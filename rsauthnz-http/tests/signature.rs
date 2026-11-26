//! The `http` mapping of the HTTP message signatures of an agent: a request that the agent signs with an absolute
//! target verifies at the server over HTTP/1.1, with `Host`, and over HTTP/2, with the authority of its target.

use core::pin::pin;
use core::task::{Context, Poll, Waker};
use core::time::Duration;

use http::{Request, Version};
use rsauthnz::cbor::Value;
use rsauthnz::cose::{Key, PublicKey, TrustedKey};
use rsauthnz::credential::{self, Claims, Draft, Serial, Subject};
use rsauthnz::crypto::Algorithm;
use rsauthnz::evidence::Method;
use rsauthnz::httpsig::{Error, LIFETIME_DEFAULT, Profile};
use rsauthnz::id::{Id, Principal};
use rsauthnz::limits::{Limits, SignatureBudget};
use rsauthnz::store::driver::{Answer, Driver, Plan};
use rsauthnz::store::{self, Store as _};
use rsauthnz::time::{Reading, ReadingSource};
use rsauthnz::transition::{Audit, OperationId, Outcome, Proposal};
use rsauthnz_conformance::memory::{Memory, Schedule};
use rsauthnz_conformance::suite::execute;
use rsauthnz_http::{add_signature, signature_draft, verify_signature};
use rscrypto::auth::{MlDsa65Ed25519, MlDsa65Ed25519SecretKey};

/// The output of `future`, which the memory binding makes ready at its first poll.
fn ready<F: Future>(future: F) -> F::Output {
    match pin!(future).poll(&mut Context::from_waker(Waker::noop())) {
        Poll::Ready(output) => Some(output),
        Poll::Pending => None,
    }
    .expect("the memory binding does no I/O")
}

/// The composite key pair of `seed`: the public key and the secret key.
fn keypair(seed: u8) -> ([u8; 1984], MlDsa65Ed25519SecretKey) {
    let (public, secret) = MlDsa65Ed25519::generate_keypair(|out| {
        let _: () = out.fill(seed);
        Ok(())
    })
    .expect("the setup of the test");
    (public.to_bytes(), secret)
}

/// The trusted key of the composite public key `public`.
fn trusted(public: &[u8; 1984]) -> TrustedKey {
    let key = Key {
        kid: None,
        alg: None,
        public: PublicKey::MlDsa65Ed25519(public),
    };
    TrustedKey::new(Algorithm::MlDsa65Ed25519, &key).expect("the setup of the test")
}

/// The credential with `claims` and the `cnf` key `holder`, which the issuer key of the seed 1 signs and a memory
/// binding commits at `now`.
fn issued(claims: &Claims, holder: &[u8; 1984], now: Reading) -> Vec<u8> {
    let (issuer, secret) = keypair(1);
    let mut memory = Memory::new(Schedule::None);
    let mut driver = Driver::new(
        store::Profile::new(memory.declaration()).expect("the setup of the test"),
        Limits::default(),
    )
    .expect("the setup of the test");
    let mut settle = |driver: &mut Driver| {
        while let Some(effect) = driver.effect() {
            let output = ready(execute(&mut memory, effect));
            driver.give(output).expect("the setup of the test");
        }
    };
    driver.start(now);
    settle(&mut driver);
    let draft = Draft::credential(&trusted(&issuer), claims, Some(PublicKey::MlDsa65Ed25519(holder)), now)
        .expect("the setup of the test");
    let signature = secret
        .sign_deterministic(&draft.to_be_signed(), &[])
        .expect("the setup of the test");
    let audit = Audit {
        actor: Principal::Workload(Id::new("acme", "issuer").expect("the setup of the test")),
        action: Id::new("acme", "credential.issue").expect("the setup of the test"),
        time: now,
    };
    let mut proposal = Proposal::new(
        OperationId::new(b"issue-1").expect("the setup of the test"),
        audit,
        &Value::Null,
        Limits::default(),
    )
    .expect("the setup of the test");
    draft.record(&mut proposal).expect("the setup of the test");
    let prepared = draft
        .finish(signature.as_bytes(), &mut SignatureBudget::new(&Limits::default()))
        .expect("the setup of the test");
    proposal.prepare(prepared).expect("the setup of the test");
    let ticket = driver.submit(proposal, Plan::default()).expect("the setup of the test");
    settle(&mut driver);
    let receipt = match driver.take(ticket) {
        Some(Answer::Outcome(Outcome::Accepted(receipt))) => Some(receipt),
        _ => None,
    };
    receipt
        .expect("the issue commits")
        .artifact()
        .expect("the credential")
        .to_vec()
}

/// The agent signs a change with an absolute target, and the server receives it with an origin-form target and `Host`
/// over HTTP/1.1, and with the authority of its target over HTTP/2. Each verifies, and a request with no authority, or
/// with two, refuses.
#[test]
fn a_request_that_the_agent_signs_verifies_at_the_server_over_each_http_version() {
    let now = Reading::new(
        Duration::from_secs(1_800_000_000),
        Some(Duration::from_secs(1)),
        ReadingSource::Caller,
    );
    let claims = Claims::new(
        Id::new("acme", "authority").unwrap(),
        Id::new("acme", "api").unwrap(),
        Subject::Workload(Id::new("acme", "runner-7").unwrap()),
        Id::new("acme", "workload").unwrap(),
        Serial(1),
        Duration::from_secs(1_800_000_900),
    );
    let (holder, agent) = keypair(2);
    let credential = issued(&claims, &holder, now);

    let body = br#"{"label":"ready"}"#.to_vec();
    let mut sent = Request::post("https://API.example/repos/repo-x/labels?ref=main")
        .header("content-type", "application/json")
        .body(body.clone())
        .unwrap();
    let draft = signature_draft(&trusted(&holder), &credential, &sent, &[9; 16], LIFETIME_DEFAULT, now).unwrap();
    let signature = agent.sign_deterministic(draft.to_be_signed(), &[]).unwrap();
    let signed = draft
        .finish(signature.as_bytes(), &mut SignatureBudget::new(&Limits::default()))
        .unwrap();
    add_signature(sent.headers_mut(), &signed);
    // An HTTP/2 encoder never indexes a sensitive field: each value changes, and the credential is longer than the
    // default table.
    assert!(sent.headers().iter().filter(|(_, value)| value.is_sensitive()).count() == 4);

    let credentials = credential::Profile::new(
        trusted(&keypair(1).0),
        claims.issuer.clone(),
        claims.audience.clone(),
        claims.purpose,
        Limits::default(),
    )
    .unwrap();
    let profile = Profile::new(credentials, &["api.example"]).unwrap();
    let received = |uri: &str, version: Version, hosts: &[&str]| {
        let mut request = Request::post(uri).version(version);
        for host in hosts {
            request = request.header("host", *host);
        }
        let mut request = request.body(body.clone()).unwrap();
        for (name, value) in sent.headers() {
            request.headers_mut().append(name, value.clone());
        }
        request
    };
    let http1 = received("/repos/repo-x/labels?ref=main", Version::HTTP_11, &["api.example"]);
    let evidence = verify_signature(&profile, &http1, now).unwrap();
    assert_eq!(evidence.method(), Method::KeyPossession);
    let http2 = received("https://api.example/repos/repo-x/labels?ref=main", Version::HTTP_2, &[]);
    verify_signature(&profile, &http2, now).unwrap();

    let no_host = received("/repos/repo-x/labels?ref=main", Version::HTTP_11, &[]);
    assert_eq!(verify_signature(&profile, &no_host, now).err(), Some(Error::Authority));
    let two_hosts = received(
        "/repos/repo-x/labels?ref=main",
        Version::HTTP_11,
        &["api.example", "api.example"],
    );
    assert_eq!(
        verify_signature(&profile, &two_hosts, now).err(),
        Some(Error::Authority)
    );
    let other_path = received("/repos/repo-x/labels?ref=dev", Version::HTTP_11, &["api.example"]);
    assert_eq!(
        verify_signature(&profile, &other_path, now).err(),
        Some(Error::Signature)
    );
}
