//! The portable consumer of rsauthnz: the cases of the A0 core and of the local authority through the public API, with
//! the entropy, the time, and the custody of a host.
//!
//! [`report`] runs each case and gives one line for each one: the CBOR vectors and limits, the COSE and CWT vectors, a
//! credential that one commit issues and its proof of possession, the refusals of the policy check, the refusals of a
//! proposal, the storage conformance suite on the memory binding, and a local authority of the host with its
//! refusals. Two bindings with a defect that a public wrapper can make are the positive control of the suite: each one
//! must fail the case that names its defect. `HostCustody` is the custody of the host: it holds each key in the
//! memory of the Worker.
//!
//! A dedicated browser Worker runs the report through the raw WebAssembly exports [`rsauthnz_portable_run`] and
//! [`rsauthnz_portable_report`]. `cargo xtask portable` compares the report of each browser with `report.txt`, and the
//! native test does the same. The mobile builds compile this crate. It is no part of a release
//! (`docs/content/portable-core.md`).

use core::cell::RefCell;
use core::num::NonZeroUsize;
use core::ops::RangeBounds;
use core::pin::pin;
use core::task::{Context, Poll, Waker};
use core::time::Duration;
use std::sync::{Arc, Mutex, PoisonError};

use rsauthnz::authz::{self, Permit, Policy, Refusal, Request, Requirements};
use rsauthnz::cbor::{self, Value};
use rsauthnz::cli::{self, Call, Challenge};
use rsauthnz::cose::{self, Key, PublicKey, Sign1, TrustedKey};
use rsauthnz::credential::{self, Claims, Draft, ProofDraft, Serial, Subject as CredentialSubject};
use rsauthnz::crypto::Algorithm;
use rsauthnz::custody::{self, Custody, Handle, Isolation, KeyId};
use rsauthnz::evidence::{Evidence, Method};
use rsauthnz::id::{Action, AuthorityVersion, Id, Principal, Resource};
use rsauthnz::limits::{Limit, Limits, SignatureBudget};
use rsauthnz::local::{self, Admitted, Authority, Bootstrap, Failure, HostGrant, Offer, Status};
use rsauthnz::store::driver::{Answer, Driver, Plan};
use rsauthnz::store::{self, Commit, Declaration, Entry, Instance, Journal, Kind, Record, Sequence, Store};
use rsauthnz::time::{Reading, ReadingSource, TimeError};
use rsauthnz::transition::{self, Audit, Change, Dependency, OperationId, Outcome, Proposal};
use rsauthnz_conformance::memory::{self, Memory, Schedule, Snapshot};
use rsauthnz_conformance::suite::{self, Case, Fault, Subject};
use rscodec::hex;
use rscrypto::ChaCha20Rng;
use rscrypto::auth::{MlDsa65Ed25519, MlDsa65Ed25519SecretKey, MlDsa65Ed25519Signature};

#[path = "../../../tests/cbor/vectors.rs"]
mod cbor_vectors;
#[path = "../../../tests/cose/vectors.rs"]
mod cose_vectors;

/// The result of one case: a short summary, or the cause of its failure.
type Verdict = Result<String, String>;

/// Runs each case with the entropy `seed` and the time `now` of the host, since the Unix epoch, and gives the report:
/// one line for each case, `<case>: ok <summary>` or `<case>: FAIL <cause>`. The cases do not depend on the seed or on
/// the time, so each host gives the same report when the core works.
#[must_use]
pub fn report(seed: [u8; 32], now: Duration) -> String {
    let now = Reading::new(now, Some(Duration::from_secs(1)), ReadingSource::Caller);
    let mut random = ChaCha20Rng::from_seed(seed);
    let journey = credential_journey(&mut random, now);
    let mut local = local_journey(&mut random, now);
    let cases: [(&str, Verdict); 15] = [
        ("cbor rfc8949 appendix-a deterministic", cbor_deterministic()),
        ("cbor rfc8949 appendix-a other encodings", cbor_other()),
        ("cbor limits", cbor_limits()),
        ("cose rfc9052 c.2.1", cose_sign1()),
        ("cwt rfc8392 a.3", cwt()),
        (
            "credential issue, verify, and possession",
            journey
                .as_ref()
                .map(|_| "ML-DSA-65 + Ed25519".to_owned())
                .map_err(Clone::clone),
        ),
        (
            "credential refusals",
            journey
                .as_ref()
                .map_err(Clone::clone)
                .and_then(|journey| credential_refusals(journey, now)),
        ),
        (
            "authz permit and refusals",
            journey
                .as_ref()
                .map_err(Clone::clone)
                .and_then(|journey| policy(&journey.evidence, now)),
        ),
        ("transition refusals", transitions(now)),
        (
            "local authority bootstrap and call",
            local
                .as_ref()
                .map(|_| "one administrator, an ML-DSA-65 + Ed25519 credential, and one admitted call".to_owned())
                .map_err(Clone::clone),
        ),
        (
            "local authority refusals",
            local.as_mut().map_err(|cause| cause.clone()).and_then(local_refusals),
        ),
        (
            "local authority missing host inputs",
            local.as_mut().map_err(|cause| cause.clone()).and_then(local_inputs),
        ),
        ("conformance memory binding", conformance()),
        (
            "conformance lost outcome reads",
            defective(Defect::LostOutcomes, Case::LostResponse),
        ),
        (
            "conformance no instance check",
            defective(Defect::NoInstanceCheck, Case::Fencing),
        ),
    ];
    let mut report = String::new();
    for (name, verdict) in cases {
        report.push_str(&match verdict {
            Ok(summary) => format!("{name}: ok {summary}\n"),
            Err(cause) => format!("{name}: FAIL {cause}\n"),
        });
    }
    report
}

/// The report of the last [`rsauthnz_portable_run`], which [`rsauthnz_portable_report`] gives to the host.
static REPORT: Mutex<String> = Mutex::new(String::new());

/// Runs [`report`] with the seed of the four words `a` to `d`, in little-endian order, and the time `now_ms` in
/// milliseconds since the Unix epoch. It keeps the report and gives its length in bytes. A browser Worker calls it with
/// `crypto.getRandomValues` and `Date.now()`.
#[expect(
    unsafe_code,
    reason = "a WebAssembly export needs an unmangled symbol; the function takes and gives only integers"
)]
#[unsafe(no_mangle)]
pub extern "C" fn rsauthnz_portable_run(a: u64, b: u64, c: u64, d: u64, now_ms: u64) -> usize {
    let mut seed = [0; 32];
    for (bytes, word) in seed.as_chunks_mut::<8>().0.iter_mut().zip([a, b, c, d]) {
        *bytes = word.to_le_bytes();
    }
    let text = report(seed, Duration::from_millis(now_ms));
    let mut kept = REPORT.lock().unwrap_or_else(PoisonError::into_inner);
    *kept = text;
    kept.len()
}

/// The address of the UTF-8 bytes of the report of the last [`rsauthnz_portable_run`]. They stay until the next run.
#[expect(
    unsafe_code,
    reason = "a WebAssembly export needs an unmangled symbol; the function gives only an address"
)]
#[unsafe(no_mangle)]
pub extern "C" fn rsauthnz_portable_report() -> *const u8 {
    REPORT.lock().unwrap_or_else(PoisonError::into_inner).as_ptr()
}

/// The output of `future`, which a future of the memory binding gives at its first poll.
fn ready<F: Future>(future: F) -> Result<F::Output, String> {
    match pin!(future).poll(&mut Context::from_waker(Waker::noop())) {
        Poll::Ready(output) => Ok(output),
        Poll::Pending => Err("a future of the memory binding is pending".to_owned()),
    }
}

/// The bytes of the lowercase hex `text`.
fn bytes(text: &str) -> Result<Vec<u8>, String> {
    let mut out = vec![0; text.len() / 2];
    hex::decode(text.as_bytes(), &mut out).map_err(|error| format!("{text}: {error}"))?;
    Ok(out)
}

/// `Ok(())` when `holds`, or the cause `cause`.
fn expect(holds: bool, cause: impl FnOnce() -> String) -> Result<(), String> {
    holds.then_some(()).ok_or_else(cause)
}

/// Each deterministic vector decodes to its value, and the value and the decoded value encode to the vector.
fn cbor_deterministic() -> Verdict {
    let vectors = cbor_vectors::deterministic();
    for (text, value) in &vectors {
        let encoded = bytes(text)?;
        let decoded = cbor::decode(&encoded, Limits::default()).map_err(|error| format!("{text}: {error}"))?;
        // A NaN is not equal to itself: the encodings check its bits.
        let nan = matches!(value, Value::Float(x) if x.is_nan());
        expect(nan || decoded == *value, || format!("{text} decodes to {decoded:?}"))?;
        for value in [&decoded, value] {
            let again = cbor::encode(value, Limits::default()).map_err(|error| format!("{text}: {error}"))?;
            expect(again == encoded, || format!("{text} encodes to {again:02x?}"))?;
        }
    }
    Ok(format!("{} vectors", vectors.len()))
}

/// Each other vector of Appendix A refuses with its typed error.
fn cbor_other() -> Verdict {
    let cases = cbor_vectors::NON_SHORTEST
        .iter()
        .map(|text| (*text, cbor::Error::NonShortest))
        .chain(
            cbor_vectors::INDEFINITE
                .iter()
                .map(|text| (*text, cbor::Error::IndefiniteLength)),
        );
    let mut count = 0;
    for (text, error) in cases {
        let refused = cbor::decode(&bytes(text)?, Limits::default()).err();
        expect(refused == Some(error), || format!("{text} gives {refused:?}"))?;
        count += 1;
    }
    Ok(format!("{count} vectors refuse"))
}

/// Each limit admits a value at it and refuses a value one past it.
fn cbor_limits() -> Verdict {
    let cases = cbor_vectors::limit_cases();
    for (limits, at, past, limit) in &cases {
        cbor::decode(&bytes(at)?, *limits).map_err(|error| format!("{at}: {error}"))?;
        let refused = cbor::decode(&bytes(past)?, *limits).err();
        expect(refused == Some(cbor::Error::Limit(*limit)), || {
            format!("{past} gives {refused:?}")
        })?;
    }
    Ok(format!("{} limits", cases.len()))
}

/// The `COSE_Sign1` of RFC 9052 C.2.1 verifies with key "11", and a changed payload refuses.
fn cose_sign1() -> Verdict {
    let key = bytes(cose_vectors::KEY_11)?;
    let key = Key::decode(&key, Limits::default()).map_err(|error| format!("key 11: {error}"))?;
    let key = TrustedKey::new(Algorithm::Es256, &key).map_err(|error| format!("key 11: {error}"))?;
    let mut message = bytes(cose_vectors::SIGN1_C_2_1)?;
    for (changed, expected) in [
        (false, Ok(&b"This is the content."[..])),
        (true, Err(cose::Error::Signature)),
    ] {
        if changed {
            // The last byte of the payload, '.', becomes '!'.
            *message.get_mut(31).ok_or("C.2.1 is too short")? = b'!';
        }
        let sign1 = Sign1::decode(&message, Limits::default()).map_err(|error| format!("C.2.1: {error}"))?;
        let verified = sign1.verify(&key, &mut SignatureBudget::new(&Limits::default()));
        expect(verified == expected, || format!("C.2.1 gives {verified:?}"))?;
    }
    Ok("verifies, and a changed payload refuses".to_owned())
}

/// The CWT of RFC 8392 A.3 verifies within its validity, and its claims are those of A.1.
fn cwt() -> Verdict {
    let (x, y) = (bytes(cose_vectors::CWT_A_3_X)?, bytes(cose_vectors::CWT_A_3_Y)?);
    let public = PublicKey::P256 {
        x: x.as_slice().try_into().map_err(|_| "x has 32 bytes")?,
        y: y.as_slice().try_into().map_err(|_| "y has 32 bytes")?,
    };
    let key = Key {
        kid: None,
        alg: None,
        public,
    };
    let profile = cose::Profile {
        key: TrustedKey::new(Algorithm::Es256, &key).map_err(|error| format!("A.2.3: {error}"))?,
        issuer: "coap://as.example.com".into(),
        audience: "coap://light.example.com".into(),
        purpose: id("credential")?,
        limits: Limits::default(),
    };
    let cwt = bytes(cose_vectors::CWT_A_3)?;
    // Between nbf (1443944944) and exp (1444064944).
    let now = Reading::new(
        Duration::from_secs(1_444_000_000),
        Some(Duration::from_secs(60)),
        ReadingSource::Caller,
    );
    let verified = profile
        .verify(&cwt, now, &mut SignatureBudget::new(&Limits::default()))
        .map_err(|error| format!("A.3: {error}"))?;
    let a1 = bytes(cose_vectors::CLAIMS_A_1)?;
    let claims = cose::Claims::decode(&a1, Limits::default()).map_err(|error| format!("A.1: {error}"))?;
    expect(claims == *verified.claims(), || {
        "the claims of A.3 are not those of A.1".to_owned()
    })?;
    expect(claims.sub == Some("erikw"), || {
        format!("the subject of A.1 is {:?}", claims.sub)
    })?;
    Ok("verifies with the claims of A.1".to_owned())
}

/// An identifier of the namespace `acme`.
fn id<K: rsauthnz::id::Kind>(value: &str) -> Result<Id<K>, String> {
    Id::new("acme", value).map_err(|error| format!("{value}: {error}"))
}

/// The custody of the host: composite ML-DSA-65 + Ed25519 keys in the memory of the Worker, which end with it. It
/// claims no hardware protection and no persistence. A browser application supplies its own custody in the same way.
#[derive(Default)]
struct HostCustody(RefCell<Vec<(Handle, MlDsa65Ed25519SecretKey)>>);

impl HostCustody {
    /// The output of `with` for the secret key of `handle`.
    fn with<T>(&self, handle: &Handle, with: impl FnOnce(&MlDsa65Ed25519SecretKey) -> T) -> Result<T, custody::Error> {
        let keys = self.0.borrow();
        let (stored, secret) = keys
            .iter()
            .find(|(stored, _)| stored.id() == handle.id())
            .ok_or(custody::Error::Unknown)?;
        (stored == handle).ok_or(custody::Error::Mismatch)?;
        Ok(with(secret))
    }

    /// A new composite key.
    fn key(&self, random: &mut ChaCha20Rng) -> Result<Handle, String> {
        let id = KeyId::random(random);
        Custody::enroll(self, id, Algorithm::MlDsa65Ed25519, random).map_err(|error| format!("an enroll: {error}"))
    }

    /// The signature of `message` by the key of `handle`.
    fn signature(&self, handle: &Handle, message: &[u8], random: &mut ChaCha20Rng) -> Result<Vec<u8>, String> {
        Custody::sign(self, handle, Algorithm::MlDsa65Ed25519, message, random)
            .map_err(|error| format!("a signature of custody: {error}"))
    }
}

impl Custody for HostCustody {
    fn report(&self) -> custody::Report {
        custody::Report {
            owner: "the Worker of the host",
            plaintext: "the life of the Worker",
            zeroization: "the drop of the key, at a delete or at the end of the Worker",
            recovery: "none: a lost key needs a new key and a new bootstrap",
            isolation: Isolation::User,
        }
    }

    fn enroll(&self, id: KeyId, algorithm: Algorithm, random: &mut ChaCha20Rng) -> Result<Handle, custody::Error> {
        (algorithm == Algorithm::MlDsa65Ed25519).ok_or(custody::Error::Algorithm)?;
        let mut keys = self.0.borrow_mut();
        keys.iter()
            .all(|(handle, _)| handle.id() != id)
            .ok_or(custody::Error::Exists)?;
        let (public, secret) = MlDsa65Ed25519::generate_keypair(|out| {
            random.fill_bytes(out);
            Ok(())
        })
        .map_err(|_| custody::Error::Crypto)?;
        let handle = Handle::new(id, algorithm, &public.to_bytes())?;
        keys.push((handle.clone(), secret));
        Ok(handle)
    }

    fn rotate(&self, from: &Handle, id: KeyId, random: &mut ChaCha20Rng) -> Result<Handle, custody::Error> {
        self.with(from, |_| ())?;
        Custody::enroll(self, id, from.algorithm(), random)
    }

    fn sign(
        &self,
        handle: &Handle,
        algorithm: Algorithm,
        message: &[u8],
        random: &mut ChaCha20Rng,
    ) -> Result<Vec<u8>, custody::Error> {
        (algorithm == handle.algorithm()).ok_or(custody::Error::Algorithm)?;
        let signature = self.with(handle, |secret| {
            secret.sign_with(message, &[], |out| {
                random.fill_bytes(out);
                Ok(())
            })
        })?;
        Ok(signature.map_err(|_| custody::Error::Crypto)?.to_bytes().to_vec())
    }

    fn delete(&self, id: KeyId) -> Result<(), custody::Error> {
        let mut keys = self.0.borrow_mut();
        let index = keys
            .iter()
            .position(|(handle, _)| handle.id() == id)
            .ok_or(custody::Error::Unknown)?;
        keys.swap_remove(index);
        Ok(())
    }
}

/// The composite public key `public`.
fn composite(public: &[u8]) -> Result<PublicKey<'_>, String> {
    Ok(PublicKey::MlDsa65Ed25519(
        public.try_into().map_err(|_| "a composite key has 1,984 bytes")?,
    ))
}

/// The trusted key of the composite key of `handle`.
fn trusted(handle: &Handle) -> Result<TrustedKey, String> {
    let public = handle.public_key();
    let key = Key {
        kid: None,
        alg: None,
        public: composite(&public)?,
    };
    TrustedKey::new(Algorithm::MlDsa65Ed25519, &key).map_err(|error| format!("a composite key: {error}"))
}

/// A new operation identity from `random`.
fn operation(random: &mut ChaCha20Rng) -> Result<OperationId, String> {
    let mut bytes = [0; 16];
    random.fill_bytes(&mut bytes);
    OperationId::new(&bytes).map_err(|error| format!("the operation: {error}"))
}

/// The result of the credential journey: the key of the issuer, the credential, its profile, and the evidence of its
/// proof of possession.
struct Journey {
    issuer: TrustedKey,
    credential: Vec<u8>,
    profile: credential::Profile,
    evidence: Evidence,
}

/// Gives each effect of `driver` to `memory`, until the driver has none.
fn settle(memory: &mut Memory, driver: &mut Driver) -> Result<(), String> {
    while let Some(effect) = driver.effect() {
        let output = ready(suite::execute(memory, effect))?;
        driver.give(output).map_err(|error| format!("the driver: {error}"))?;
    }
    Ok(())
}

/// A started commit driver on an empty memory binding.
fn started(now: Reading) -> Result<(Memory, Driver), String> {
    let mut memory = Memory::new(Schedule::None);
    let profile = store::Profile::new(memory.declaration()).map_err(|error| format!("the profile: {error}"))?;
    let mut driver = Driver::new(profile, Limits::default()).map_err(|error| format!("the driver: {error}"))?;
    driver.start(now);
    settle(&mut memory, &mut driver)?;
    Ok((memory, driver))
}

/// The outcome of the commit of `proposal`.
fn commit(memory: &mut Memory, driver: &mut Driver, (proposal, plan): (Proposal, Plan)) -> Result<Outcome, String> {
    let ticket = driver
        .submit(proposal, plan)
        .map_err(|error| format!("the submission: {error}"))?;
    settle(memory, driver)?;
    match driver.take(ticket) {
        Some(Answer::Outcome(outcome)) => Ok(outcome),
        answer => Err(format!("the commit gave {answer:?}")),
    }
}

/// The artifact that only the receipt of the accepted commit of `proposal` gives.
fn artifact(memory: &mut Memory, driver: &mut Driver, proposal: (Proposal, Plan)) -> Result<Vec<u8>, String> {
    match commit(memory, driver, proposal)? {
        Outcome::Accepted(receipt) => Ok(receipt.artifact().ok_or("the receipt has no artifact")?.to_vec()),
        outcome => Err(format!("the commit gave {outcome:?}")),
    }
}

/// An issuer commits a credential with the `cnf` key of a holder on the memory binding, and only the receipt releases
/// it. The audience verifies it, and the holder proves possession of the key.
fn credential_journey(random: &mut ChaCha20Rng, now: Reading) -> Result<Journey, String> {
    let custody = HostCustody::default();
    let (issuer, holder) = (custody.key(random)?, custody.key(random)?);
    let (issuer_key, holder_public) = (trusted(&issuer)?, holder.public_key());
    let claims = Claims::new(
        id("authority")?,
        id("build-api")?,
        CredentialSubject::Workload(id("runner-7")?),
        id("workload")?,
        Serial(1),
        now.estimate() + Duration::from_secs(3_600),
    );
    let draft = Draft::credential(&issuer_key, &claims, Some(composite(&holder_public)?), now)
        .map_err(|error| format!("the draft: {error}"))?;

    let (mut memory, mut driver) = started(now)?;
    let audit = Audit {
        actor: Principal::Human(id("u-17")?),
        action: id("credential.issue")?,
        time: now,
    };
    let mut proposal = Proposal::new(operation(random)?, audit, &Value::Null, Limits::default())
        .map_err(|error| format!("the proposal: {error}"))?;
    draft
        .record(&mut proposal)
        .map_err(|error| format!("the issuance record: {error}"))?;
    let signature = custody.signature(&issuer, &draft.to_be_signed(), random)?;
    let prepared = draft
        .finish(&signature, &mut SignatureBudget::new(&Limits::default()))
        .map_err(|error| format!("the finish: {error}"))?;
    proposal
        .prepare(prepared)
        .map_err(|error| format!("the artifact: {error}"))?;
    let credential = artifact(&mut memory, &mut driver, (proposal, Plan::default()))?;

    let profile = credential::Profile::new(
        issuer_key.clone(),
        claims.issuer.clone(),
        claims.audience.clone(),
        claims.purpose,
        Limits::default(),
    )
    .map_err(|error| format!("the profile: {error}"))?;
    let verified = profile
        .verify(&credential, now, &mut SignatureBudget::new(&Limits::default()))
        .map_err(|error| format!("the verification: {error}"))?;
    let challenge = [5; 32];
    let proof = ProofDraft::new(&trusted(&holder)?, &credential, &id("build-api")?, &challenge, now)
        .map_err(|error| format!("the proof draft: {error}"))?;
    let signature = custody.signature(&holder, &proof.to_be_signed(), random)?;
    let proof = proof
        .finish(&signature, &mut SignatureBudget::new(&Limits::default()))
        .map_err(|error| format!("the proof: {error}"))?;
    let evidence = verified
        .possession(&proof, &challenge, now, &mut SignatureBudget::new(&Limits::default()))
        .map_err(|error| format!("the possession: {error}"))?;
    let subject = Principal::Workload(id("runner-7")?);
    expect(
        *evidence.subject() == subject && evidence.method() == Method::KeyPossession,
        || format!("the evidence is {evidence:?}"),
    )?;
    Ok(Journey {
        issuer: issuer_key,
        credential,
        profile,
        evidence,
    })
}

/// A changed byte of the credential refuses, and so does the profile of another audience.
fn credential_refusals(journey: &Journey, now: Reading) -> Verdict {
    let mut changed = journey.credential.clone();
    let last = changed.last_mut().ok_or("the credential is empty")?;
    *last ^= 1;
    let refused = journey
        .profile
        .verify(&changed, now, &mut SignatureBudget::new(&Limits::default()))
        .is_err();
    expect(refused, || "a changed byte verifies".to_owned())?;
    let other = credential::Profile::new(
        journey.issuer.clone(),
        id("authority")?,
        id("other-api")?,
        id("workload")?,
        Limits::default(),
    )
    .map_err(|error| format!("the profile: {error}"))?;
    let refused = other
        .verify(&journey.credential, now, &mut SignatureBudget::new(&Limits::default()))
        .is_err();
    expect(refused, || "another audience verifies".to_owned())?;
    Ok("a changed byte and another audience refuse".to_owned())
}

/// The policy of the policy cases: one version, and the permit that it gives to each request.
struct Rules {
    version: AuthorityVersion,
    permit: Option<Permit>,
}

impl Policy for Rules {
    fn version(&self) -> &AuthorityVersion {
        &self.version
    }

    fn resolve(&self, _: &Request<'_>) -> Option<Permit> {
        self.permit.clone()
    }
}

/// The check of `evidence` permits the exact scope of a current permit, and refuses each other case with its cause.
fn policy(evidence: &Evidence, now: Reading) -> Verdict {
    let (action, resource): (Id<Action>, Id<Resource>) = (id("deploy")?, id("project-1")?);
    let version =
        |value: u8| AuthorityVersion::new(id("authority")?, &[value]).map_err(|error| format!("the version: {error}"));
    let permit = Permit {
        principal: evidence.subject().clone(),
        action: action.clone(),
        resource: resource.clone(),
        version: version(1)?,
        requires: Requirements {
            user_verified: false,
            phishing_resistant: false,
            max_age: Duration::from_secs(300),
        },
        expires: now.estimate() + Duration::from_secs(600),
    };
    let unbounded = Reading::new(now.estimate(), None, ReadingSource::Caller);
    let cases = [
        ("permit", Some(permit.clone()), now, None),
        ("no permit", None, now, Some(Refusal::Denied)),
        (
            "another resource",
            Some(Permit {
                resource: id("project-2")?,
                ..permit.clone()
            }),
            now,
            Some(Refusal::Scope),
        ),
        (
            "an old version",
            Some(Permit {
                version: version(0)?,
                ..permit.clone()
            }),
            now,
            Some(Refusal::Stale),
        ),
        (
            "phishing resistance",
            Some(Permit {
                requires: Requirements {
                    phishing_resistant: true,
                    ..permit.requires
                },
                ..permit.clone()
            }),
            now,
            Some(Refusal::Requirements),
        ),
        (
            "an ended permit",
            Some(Permit {
                expires: now.estimate(),
                ..permit.clone()
            }),
            now,
            Some(Refusal::Expired),
        ),
        (
            "a reading with no bound",
            Some(permit),
            unbounded,
            Some(Refusal::Time(TimeError::UnknownBound)),
        ),
    ];
    let count = cases.len();
    for (name, permit, reading, expected) in cases {
        let rules = Rules {
            version: version(1)?,
            permit,
        };
        let refused = authz::check(evidence, &action, &resource, &rules, reading).err();
        expect(refused == expected, || format!("{name} gives {refused:?}"))?;
    }
    Ok(format!("{} refusals and one permit", count - 1))
}

/// A change with no read that allows it refuses, and so does a read past the limit of the dependencies.
fn transitions(now: Reading) -> Verdict {
    let audit = Audit {
        actor: Principal::Human(id("u-17")?),
        action: id("change")?,
        time: now,
    };
    let operation = OperationId::new(b"change-1").map_err(|error| format!("the operation: {error}"))?;
    let mut proposal = Proposal::new(operation, audit, &Value::Null, Limits::default())
        .map_err(|error| format!("the proposal: {error}"))?;
    let key = |value: u32| {
        Kind::Grant
            .key(&value.to_be_bytes())
            .map_err(|error| format!("the key: {error}"))
    };
    let refused = proposal.change(Change::End(key(0)?)).err();
    expect(refused == Some(transition::Error::Change), || {
        format!("a change with no read gives {refused:?}")
    })?;
    let limit = u32::try_from(Limits::default().dependencies).map_err(|_| "the limit fits in 32 bits")?;
    for value in 0..limit {
        proposal
            .read(Dependency::Absent(key(value)?))
            .map_err(|error| format!("read {value}: {error}"))?;
    }
    let refused = proposal.read(Dependency::Absent(key(limit)?)).err();
    expect(refused == Some(transition::Error::Limit(Limit::Dependencies)), || {
        format!("a read past the limit gives {refused:?}")
    })?;
    Ok("a change with no read and a read past the limit refuse".to_owned())
}

/// A local authority that the host opens: the memory binding, the commit driver, the custody of the host with the issuer
/// key, the grant of the host, its generator, and its time. It has no daemon and no hosted account.
struct Local {
    memory: Memory,
    driver: Driver,
    custody: HostCustody,
    issuer: Handle,
    grant: HostGrant,
    authority: Authority,
    random: ChaCha20Rng,
    now: Reading,
}

impl Local {
    /// The ML-DSA-65 + Ed25519 public key of `key`, which a client submits with its bootstrap value.
    fn holder(key: &Handle) -> Result<[u8; 1984], String> {
        key.public_key()
            .try_into()
            .map_err(|_| "a composite key has 1,984 bytes".to_owned())
    }

    /// The bootstrap value that the commit of an issue by the local owner for `administrator` gives.
    fn issue(&mut self, administrator: &str) -> Result<Bootstrap, String> {
        let operation = operation(&mut self.random)?;
        let issue = ready(self.authority.issue(
            &mut self.memory,
            &self.grant,
            id(administrator)?,
            self.now,
            &mut self.random,
            operation,
        ))?
        .map_err(|error| format!("the issue: {error}"))?;
        let text = artifact(&mut self.memory, &mut self.driver, issue)?;
        Bootstrap::parse(&String::from_utf8(text).map_err(|_| "a value is text")?)
            .map_err(|error| format!("the value: {error}"))
    }

    /// The proposal of the bootstrap of `value` with the CLI key `key`, whose credential custody signs with the issuer
    /// key.
    fn propose(&mut self, value: &Bootstrap, key: &Handle) -> Result<(Proposal, Plan), String> {
        let serial = Serial(
            self.driver
                .allocate(Kind::Credential)
                .map_err(|error| format!("the serial: {error}"))?,
        );
        let pending = ready(
            self.authority
                .bootstrap(&mut self.memory, value, &Self::holder(key)?, serial, self.now),
        )?
        .map_err(|error| format!("the bootstrap: {error}"))?;
        let signature = self
            .custody
            .signature(&self.issuer, &pending.to_be_signed(), &mut self.random)?;
        pending
            .finish(&signature, operation(&mut self.random)?)
            .map_err(|error| format!("the finish: {error}"))
    }

    /// The challenge of the next call of `administrator`: the open one, or the one that the commit of a new one gives.
    fn challenge(&mut self, administrator: &str) -> Result<Challenge, String> {
        let operation = operation(&mut self.random)?;
        let offer = ready(self.authority.challenge(
            &mut self.memory,
            &id(administrator)?,
            self.now,
            &mut self.random,
            operation,
        ))?
        .map_err(|error| format!("the challenge: {error}"))?;
        match offer {
            Offer::Open(challenge) => Ok(challenge),
            Offer::New(proposal, plan) => {
                let bytes = artifact(&mut self.memory, &mut self.driver, (proposal, plan))?;
                Ok(Challenge::from_bytes(
                    bytes.try_into().map_err(|_| "a challenge has 32 bytes")?,
                ))
            }
        }
    }

    /// The call with the request `deploy` over `challenge`, and the proof of `key` for it with `credential`.
    fn call(&mut self, challenge: Challenge, key: &Handle, credential: &[u8]) -> Result<(Call, Vec<u8>), String> {
        let call = Call::new(
            challenge,
            operation(&mut self.random)?,
            &Value::Text("deploy"),
            Limits::default(),
        )
        .map_err(|error| format!("the call: {error}"))?;
        let proof = cli::prove(
            &self.custody,
            key,
            credential,
            &self.grant.origin,
            &call,
            self.now,
            &mut self.random,
        )
        .map_err(|error| format!("the proof: {error}"))?;
        Ok((call, proof))
    }

    /// The admission of `call` with `credential` and `proof`: the admitted call that its accepted commit gives, or the
    /// refusal of the authority.
    fn admit(
        &mut self,
        credential: &[u8],
        proof: &[u8],
        call: &Call,
    ) -> Result<Result<Admitted, local::Error>, String> {
        let admission =
            ready(
                self.authority
                    .admit(&mut self.memory, credential, proof, call, self.now, &mut self.random),
            )?;
        let (proposal, admission) = match admission {
            Ok(admission) => admission,
            Err(Failure::Refused(error)) => return Ok(Err(error)),
            Err(Failure::Store(error)) => return Err(format!("a read of the admission: {error}")),
        };
        let outcome = commit(&mut self.memory, &mut self.driver, (proposal, Plan::default()))?;
        admission
            .release(&outcome)
            .map(Ok)
            .ok_or_else(|| format!("the admission gave {outcome:?}"))
    }
}

/// The result of the journey of the local authority: the authority, the consumed value, the CLI key of the
/// administrator, its credential, and the challenge of its next call.
struct LocalJourney {
    local: Local,
    value: Bootstrap,
    key: Handle,
    credential: Vec<u8>,
    next: Challenge,
}

/// The host opens a local authority under its grant, with the issuer key in its custody, and the local owner issues a
/// bootstrap value for `alice`. The client keeps its key in the custody of the host, and only the receipt of the
/// commit of its bootstrap gives its ML-DSA-65 + Ed25519 CLI credential. The credential verifies under the profile of
/// the authority, and a call of `alice` with a proof of the key is admitted.
fn local_journey(random: &mut ChaCha20Rng, now: Reading) -> Result<LocalJourney, String> {
    let mut seed = [0; 32];
    random.fill_bytes(&mut seed);
    let mut random = ChaCha20Rng::from_seed(seed);
    let custody = HostCustody::default();
    let issuer = custody.key(&mut random)?;
    let (mut memory, driver) = started(now)?;
    let grant = HostGrant {
        owner: id("owner")?,
        origin: id("build-app")?,
    };
    let authority = ready(Authority::open(
        &mut memory,
        &grant,
        id("local")?,
        issuer.clone(),
        Limits::default(),
    ))?
    .map_err(|error| format!("the open: {error}"))?;
    let mut local = Local {
        memory,
        driver,
        custody,
        issuer,
        grant,
        authority,
        random,
        now,
    };
    let value = local.issue("alice")?;
    let key = local.custody.key(&mut local.random)?;
    let proposal = local.propose(&value, &key)?;
    let credential = artifact(&mut local.memory, &mut local.driver, proposal)?;
    let verified = local
        .authority
        .profile()
        .verify(&credential, now, &mut SignatureBudget::new(&Limits::default()))
        .map_err(|error| format!("the verification: {error}"))?;
    let alice = CredentialSubject::Human(id("alice")?);
    expect(verified.claims().subject == alice, || {
        format!("the credential names {:?}", verified.claims().subject)
    })?;
    let challenge = local.challenge("alice")?;
    let (call, proof) = local.call(challenge, &key, &credential)?;
    let admitted = local
        .admit(&credential, &proof, &call)?
        .map_err(|error| format!("the call: {error}"))?;
    expect(*admitted.subject() == id("alice")?, || {
        format!("the call of {:?} was admitted", admitted.subject())
    })?;
    Ok(LocalJourney {
        next: admitted.next(),
        local,
        value,
        key,
        credential,
    })
}

/// A grant of another origin refuses to open the authority, and a consumed value refuses a second bootstrap. A call
/// with the credential of `alice` refuses when the credential names another administrator, or when one half of its
/// composite signature is invalid. Then the same call with the credential is admitted.
fn local_refusals(journey: &mut LocalJourney) -> Verdict {
    let local = &mut journey.local;
    let other = HostGrant {
        origin: id("other-app")?,
        ..local.grant.clone()
    };
    let opened = ready(Authority::open(
        &mut local.memory,
        &other,
        id("local")?,
        local.issuer.clone(),
        Limits::default(),
    ))?
    .err();
    expect(opened == Some(Failure::Refused(local::Error::Grant)), || {
        format!("a grant of another origin gives {opened:?}")
    })?;
    let serial = Serial(
        local
            .driver
            .allocate(Kind::Credential)
            .map_err(|error| format!("the serial: {error}"))?,
    );
    let reused = ready(local.authority.bootstrap(
        &mut local.memory,
        &journey.value,
        &Local::holder(&journey.key)?,
        serial,
        local.now,
    ))?
    .err();
    expect(reused == Some(Failure::Refused(local::Error::Unknown)), || {
        format!("a consumed value gives {reused:?}")
    })?;

    let credential = &journey.credential;
    let at = credential
        .windows(5)
        .position(|bytes| bytes == b"alice")
        .ok_or("the credential does not name alice")?;
    let mut carol = credential.clone();
    carol
        .get_mut(at..at + 5)
        .ok_or("the credential ends in the name")?
        .copy_from_slice(b"carol");
    // The composite signature ends the credential, after the CBOR header of its byte string (RFC 8949 section 3): the
    // ML-DSA-65 signature, then the Ed25519 signature.
    let ml_dsa = credential
        .len()
        .checked_sub(MlDsa65Ed25519Signature::LENGTH)
        .ok_or("the credential is shorter than its signature")?;
    let [high, low] = u16::try_from(MlDsa65Ed25519Signature::LENGTH)
        .map_err(|_| "a composite signature has 3,373 bytes")?
        .to_be_bytes();
    let header = ml_dsa.checked_sub(3).and_then(|at| credential.get(at..ml_dsa));
    expect(header == Some(&[0x59, high, low][..]), || {
        format!("the signature is not the last item: {header:02x?}")
    })?;
    let (mut ml_dsa_invalid, mut ed25519_invalid) = (credential.clone(), credential.clone());
    *ml_dsa_invalid.get_mut(ml_dsa).ok_or("no ML-DSA-65 signature")? ^= 1;
    *ed25519_invalid.last_mut().ok_or("no Ed25519 signature")? ^= 1;
    let (call, proof) = local.call(journey.next, &journey.key, credential)?;
    for (name, bytes) in [
        ("another administrator", carol),
        ("an invalid ML-DSA-65 half", ml_dsa_invalid),
        ("an invalid Ed25519 half", ed25519_invalid),
    ] {
        let refused = local.admit(&bytes, &proof, &call)?.err();
        expect(matches!(refused, Some(local::Error::Credential(_))), || {
            format!("a credential with {name} gives {refused:?}")
        })?;
    }
    let admitted = local.admit(credential, &proof, &call)?;
    expect(admitted.is_ok(), || format!("the call gives {admitted:?}"))?;
    Ok("another origin, a reused value, an altered credential, and each invalid composite half refuse".to_owned())
}

/// Missing host inputs release no signed artifact and commit no state. A time with no bound refuses an issue and a
/// bootstrap. A bootstrap with no signature of custody, or with the signature of another key, refuses its finish. Then
/// the value is still valid, the administrator has no binding, and the bootstrap of the value commits.
fn local_inputs(journey: &mut LocalJourney) -> Verdict {
    let local = &mut journey.local;
    let unbounded = Reading::new(local.now.estimate(), None, ReadingSource::Caller);
    let unknown = Some(Failure::Refused(local::Error::Time(TimeError::UnknownBound)));
    let operation_id = operation(&mut local.random)?;
    let issue = ready(local.authority.issue(
        &mut local.memory,
        &local.grant,
        id("bob")?,
        unbounded,
        &mut local.random,
        operation_id,
    ))?
    .err();
    expect(issue == unknown, || format!("an issue with no bound gives {issue:?}"))?;
    let value = local.issue("bob")?;
    let key = local.custody.key(&mut local.random)?;
    let holder = Local::holder(&key)?;
    let serial = Serial(
        local
            .driver
            .allocate(Kind::Credential)
            .map_err(|error| format!("the serial: {error}"))?,
    );
    let bootstrap = ready(
        local
            .authority
            .bootstrap(&mut local.memory, &value, &holder, serial, unbounded),
    )?
    .err();
    expect(bootstrap == unknown, || {
        format!("a bootstrap with no bound gives {bootstrap:?}")
    })?;
    for signer in [None, Some(&key)] {
        let pending = ready(
            local
                .authority
                .bootstrap(&mut local.memory, &value, &holder, serial, local.now),
        )?
        .map_err(|error| format!("the bootstrap: {error}"))?;
        let signature = match signer {
            None => Vec::new(),
            Some(other) => local
                .custody
                .signature(other, &pending.to_be_signed(), &mut local.random)?,
        };
        let refused = pending.finish(&signature, operation(&mut local.random)?).err();
        expect(matches!(refused, Some(local::Error::Credential(_))), || {
            format!("a finish with {signer:?} gives {refused:?}")
        })?;
    }

    let report =
        ready(local.authority.report(&mut local.memory, local.now))?.map_err(|error| format!("the report: {error}"))?;
    let last = report.issues.last().map(|issue| (&issue.administrator, issue.status));
    expect(last == Some((&id("bob")?, Status::Valid)), || {
        format!("the last issue is {last:?}")
    })?;
    let credential = ready(
        local
            .authority
            .credential(&mut local.memory, &id("bob")?, &holder, local.now),
    )?
    .err();
    expect(credential == Some(Failure::Refused(local::Error::Unknown)), || {
        format!("the credential of bob gives {credential:?}")
    })?;
    let proposal = local.propose(&value, &key)?;
    artifact(&mut local.memory, &mut local.driver, proposal)?;
    Ok("a time with no bound, no signature, and the signature of another key commit nothing".to_owned())
}

/// The memory binding passes each case of the suite.
fn conformance() -> Verdict {
    let report = ready(suite::run(|| Memory::new(Schedule::None)))?;
    expect(report == suite::Report::default(), || format!("{report}"))?;
    Ok(format!("{} cases pass", Case::ALL.len()))
}

/// The binding with `defect` fails the case `named`.
fn defective(defect: Defect, named: Case) -> Verdict {
    let report = ready(suite::run(|| Defective::new(defect)))?;
    let failed = report.failures.iter().any(|failure| failure.case == named);
    expect(failed, || format!("the case {named} passes"))?;
    Ok(format!("fails {named}"))
}

/// A defect that a wrapper of the memory binding makes through the public primitives.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum Defect {
    /// A read of an outcome record gives none.
    LostOutcomes,
    /// The commit gives the memory binding the instance number of its last start, not the one of the caller.
    NoInstanceCheck,
}

/// The memory binding with a defect.
#[derive(Clone, Debug)]
struct Defective {
    memory: Memory,
    defect: Defect,
    /// The instance number of the last start.
    instance: Arc<Mutex<Option<Instance>>>,
}

impl Defective {
    fn new(defect: Defect) -> Self {
        Self {
            memory: Memory::new(Schedule::None),
            defect,
            instance: Arc::default(),
        }
    }
}

impl Store for Defective {
    type Error = memory::Error;

    fn declaration(&self) -> Declaration {
        self.memory.declaration()
    }

    async fn start(&mut self) -> Result<Instance, memory::Error> {
        let instance = self.memory.start().await?;
        *self.instance.lock().unwrap_or_else(PoisonError::into_inner) = Some(instance);
        Ok(instance)
    }

    async fn read(&mut self, key: &rsauthnz::transition::Key) -> Result<Option<Record>, memory::Error> {
        if self.defect == Defect::LostOutcomes && Kind::of(key) == Some(Kind::Outcome) {
            return Ok(None);
        }
        Store::read(&mut self.memory, key).await
    }

    async fn read_pair(&mut self, keys: [&rsauthnz::transition::Key; 2]) -> Result<[Option<Record>; 2], memory::Error> {
        let mut pair = self.memory.read_pair(keys).await?;
        if self.defect == Defect::LostOutcomes {
            for (key, record) in keys.into_iter().zip(&mut pair) {
                if Kind::of(key) == Some(Kind::Outcome) {
                    *record = None;
                }
            }
        }
        Ok(pair)
    }

    async fn commit(&mut self, proposal: &Proposal, instance: Instance) -> Result<Commit, memory::Error> {
        let last = *self.instance.lock().unwrap_or_else(PoisonError::into_inner);
        let instance = match (self.defect, last) {
            (Defect::NoInstanceCheck, Some(last)) => last,
            _ => instance,
        };
        self.memory.commit(proposal, instance).await
    }

    async fn expire(&mut self, kind: Kind, before: Duration, limit: NonZeroUsize) -> Result<usize, memory::Error> {
        self.memory.expire(kind, before, limit).await
    }

    async fn range(
        &mut self,
        prefix: &rsauthnz::transition::Key,
        after: Option<&rsauthnz::transition::Key>,
        limit: NonZeroUsize,
    ) -> Result<Vec<(rsauthnz::transition::Key, Record)>, memory::Error> {
        self.memory.range(prefix, after, limit).await
    }
}

impl Journal for Defective {
    type Error = memory::Error;

    async fn append(&mut self, entry: &[u8]) -> Result<Sequence, memory::Error> {
        self.memory.append(entry).await
    }

    async fn sync(&mut self) -> Result<(), memory::Error> {
        self.memory.sync().await
    }

    async fn read(&mut self, after: Sequence, limit: NonZeroUsize) -> Result<Vec<Entry>, memory::Error> {
        Journal::read(&mut self.memory, after, limit).await
    }
}

impl Subject for Defective {
    type Snapshot = Snapshot;

    fn inject(&self, fault: Fault) {
        self.memory.inject(fault);
    }

    fn restart(&self) {
        self.memory.restart();
    }

    fn snapshot(&self) -> Snapshot {
        self.memory.snapshot()
    }

    fn restore(&self, snapshot: &Snapshot) {
        self.memory.restore(snapshot);
    }

    fn lose(&self, sequences: impl RangeBounds<Sequence>) {
        self.memory.lose(sequences);
    }

    fn set_clock(&self, now: Reading) {
        self.memory.set_clock(now);
    }
}
