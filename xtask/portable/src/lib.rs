//! The portable consumer of rsauthnz: the cases of the A0 core through its public API, with the entropy and the time
//! of a host.
//!
//! [`report`] runs each case and gives one line for each one: the CBOR vectors and limits, the COSE and CWT vectors, a
//! credential that one commit issues and its proof of possession, the refusals of the policy check, the refusals of a
//! proposal, and the storage conformance suite on the memory binding. Two bindings with a defect that a public wrapper
//! can make are the positive control of the suite: each one must fail the case that names its defect.
//!
//! A dedicated browser Worker runs the report through the raw WebAssembly exports [`rsauthnz_portable_run`] and
//! [`rsauthnz_portable_report`]. `cargo xtask portable` compares the report of each browser with `report.txt`, and the
//! native test does the same. The mobile builds compile this crate. It is no part of a release
//! (`docs/content/portable-core.md`).

use core::num::NonZeroUsize;
use core::ops::RangeBounds;
use core::pin::pin;
use core::task::{Context, Poll, Waker};
use core::time::Duration;
use std::sync::{Arc, Mutex, PoisonError};

use rsauthnz::authz::{self, Permit, Policy, Refusal, Request, Requirements};
use rsauthnz::cbor::{self, Value};
use rsauthnz::cose::{self, Key, PublicKey, Sign1, TrustedKey};
use rsauthnz::credential::{self, Claims, Draft, ProofDraft, Serial, Subject as CredentialSubject};
use rsauthnz::crypto::Algorithm;
use rsauthnz::evidence::{Evidence, Method};
use rsauthnz::id::{Action, AuthorityVersion, Id, Principal, Resource};
use rsauthnz::limits::{Limit, Limits, SignatureBudget};
use rsauthnz::store::driver::{Answer, Driver, Plan};
use rsauthnz::store::{self, Commit, Declaration, Entry, Instance, Journal, Kind, Record, Sequence, Store};
use rsauthnz::time::{Reading, ReadingSource, TimeError};
use rsauthnz::transition::{self, Audit, Change, Dependency, OperationId, Outcome, Proposal};
use rsauthnz_conformance::memory::{self, Memory, Schedule, Snapshot};
use rsauthnz_conformance::suite::{self, Case, Fault, Subject};
use rscodec::hex;
use rscrypto::ChaCha20Rng;
use rscrypto::auth::{MlDsa65Ed25519, MlDsa65Ed25519SecretKey};

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
    let cases: [(&str, Verdict); 12] = [
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

/// A composite ML-DSA-65 + Ed25519 key that signs in place of custody, from the generator of the host.
struct Signer {
    public: Vec<u8>,
    secret: Box<MlDsa65Ed25519SecretKey>,
}

impl Signer {
    fn new(random: &mut ChaCha20Rng) -> Result<Self, String> {
        let (public, secret) = MlDsa65Ed25519::generate_keypair(|out| {
            random.fill_bytes(out);
            Ok(())
        })
        .map_err(|error| format!("a composite key: {error}"))?;
        Ok(Self {
            public: public.to_bytes().to_vec(),
            secret: Box::new(secret),
        })
    }

    fn public(&self) -> Result<PublicKey<'_>, String> {
        Ok(PublicKey::MlDsa65Ed25519(
            self.public
                .as_slice()
                .try_into()
                .map_err(|_| "a composite key has 1,984 bytes")?,
        ))
    }

    fn key(&self) -> Result<TrustedKey, String> {
        let key = Key {
            kid: None,
            alg: None,
            public: self.public()?,
        };
        TrustedKey::new(Algorithm::MlDsa65Ed25519, &key).map_err(|error| format!("a composite key: {error}"))
    }

    fn sign(&self, message: &[u8]) -> Result<Vec<u8>, String> {
        let signature = self
            .secret
            .sign_deterministic(message, &[])
            .map_err(|error| format!("a composite signature: {error}"))?;
        Ok(signature.to_bytes().to_vec())
    }
}

/// The result of the credential journey: the key of the issuer, the credential, its profile, and the evidence of its
/// proof of possession.
struct Journey {
    issuer: Signer,
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

/// An issuer commits a credential with the `cnf` key of a holder on the memory binding, and only the receipt releases
/// it. The audience verifies it, and the holder proves possession of the key.
fn credential_journey(random: &mut ChaCha20Rng, now: Reading) -> Result<Journey, String> {
    let (issuer, holder) = (Signer::new(random)?, Signer::new(random)?);
    let claims = Claims::new(
        id("authority")?,
        id("build-api")?,
        CredentialSubject::Workload(id("runner-7")?),
        id("workload")?,
        Serial(1),
        now.estimate() + Duration::from_secs(3_600),
    );
    let draft = Draft::credential(&issuer.key()?, &claims, Some(holder.public()?), now)
        .map_err(|error| format!("the draft: {error}"))?;

    let mut memory = Memory::new(Schedule::None);
    let profile = store::Profile::new(memory.declaration()).map_err(|error| format!("the profile: {error}"))?;
    let mut driver = Driver::new(profile, Limits::default()).map_err(|error| format!("the driver: {error}"))?;
    driver.start(now);
    settle(&mut memory, &mut driver)?;
    let audit = Audit {
        actor: Principal::Human(id("u-17")?),
        action: id("credential.issue")?,
        time: now,
    };
    let operation = OperationId::new(b"issue-1").map_err(|error| format!("the operation: {error}"))?;
    let mut proposal = Proposal::new(operation, audit, &Value::Null, Limits::default())
        .map_err(|error| format!("the proposal: {error}"))?;
    draft
        .record(&mut proposal)
        .map_err(|error| format!("the issuance record: {error}"))?;
    let signature = issuer.sign(&draft.to_be_signed())?;
    let prepared = draft
        .finish(&signature, &mut SignatureBudget::new(&Limits::default()))
        .map_err(|error| format!("the finish: {error}"))?;
    proposal
        .prepare(prepared)
        .map_err(|error| format!("the artifact: {error}"))?;
    let ticket = driver
        .submit(proposal, Plan::default())
        .map_err(|error| format!("the submission: {error}"))?;
    settle(&mut memory, &mut driver)?;
    let credential = match driver.take(ticket) {
        Some(Answer::Outcome(Outcome::Accepted(receipt))) => {
            receipt.artifact().ok_or("the receipt has no artifact")?.to_vec()
        }
        answer => return Err(format!("the issuance gave {answer:?}")),
    };

    let profile = credential::Profile::new(
        issuer.key()?,
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
    let proof = ProofDraft::new(&holder.key()?, &credential, &id("build-api")?, &challenge, now)
        .map_err(|error| format!("the proof draft: {error}"))?;
    let signature = holder.sign(&proof.to_be_signed())?;
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
        issuer,
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
        journey.issuer.key()?,
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

    fn clock(&self) -> Reading {
        self.memory.clock()
    }
}
