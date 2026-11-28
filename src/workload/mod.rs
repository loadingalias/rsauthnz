//! Workload credentials: short, audience-bound credentials that an explicit issuer gives to a registered workload,
//! with the registered proof key of the workload as their `cnf` key.
//!
//! Two records of the store hold the authority. An [`Issuer`] record holds the authority that issues, its key, its
//! audiences, and its [`Ceiling`]. The algorithm of the key is the profile that each of its audiences declares. A
//! [`Registration`] record holds a workload, its registered proof key, and its generation. The application adds the
//! first write of each record to its own transition ([`Issuer::register`], [`Registration::register`]). rsauthnz makes
//! each later write, with a version from a counter of the commit driver.
//!
//! An issuance has two steps, as each issuance of [`credential`] has. [`Pending::new`] reads the two records, checks
//! the policy and the ceiling, and makes the draft and the [`Proposal`]. Custody signs [`Pending::to_be_signed`]
//! outside the core. [`Pending::finish`] verifies the signature and puts the credential into the proposal, where it
//! stays private. The application submits the proposal to the commit driver. Only [`Awaiting::release`] of the
//! accepted commit of that proposal gives the [`Released`](credential::Released) credential. Thus the store records the credential and its audit
//! before the workload gets it. A lost response gives no credential, and the core does not try the operation again.
//!
//! The first issuance comes from a principal that the policy permits [`Mode::Issue`], such as an operator. A
//! renewal comes from the workload itself, with its current credential and a proof of possession of its registered
//! key. The policy must permit it [`Mode::Renew`]. Each renewal gives a new serial with the same `cnf` key, and the
//! earlier credential stays valid until it ends.
//!
//! A rotation replaces the registered key. The workload asks with its current credential, a proof by its current key,
//! and a proof by its new key ([`Replace`]). A recovery replaces the key of a host that is lost. A principal that the
//! policy permits [`Mode::Recover`] asks, and the new host proves its new key. Each one issues the first credential of
//! the new key. The same commit raises the generation of the registration to the serial of that credential, so each
//! earlier credential of the workload is dead. A [`Revocation`] raises the generation with no
//! new credential, and an [`IssuerRotation`] replaces the issuer key.
//!
//! A service verifies a workload credential locally, with the [`credential::Profile`] of [`Issuer::profile`]. It looks
//! up no issuer for each request. A verifier that reads the current issuer record and the current registration
//! ([`admits`]) refuses each credential that a rotation, a recovery, or a revocation ended. A verifier that reads no
//! state accepts such a credential until it ends. Thus the lifetime is the longest time that a revocation needs to
//! reach such a verifier.
//!
//! ```
//! use core::pin::pin;
//! use core::task::{Context, Poll, Waker};
//! use core::time::Duration;
//! # use rsauthnz::authz::{self, Permit, Policy, Requirements};
//! use rsauthnz::cbor::Value;
//! use rsauthnz::cose::{Key, PublicKey, TrustedKey};
//! # use rsauthnz::credential::{self, Claims, Draft, Serial, Subject};
//! use rsauthnz::credential::ProofDraft;
//! use rsauthnz::crypto::Algorithm;
//! # use rsauthnz::evidence::Evidence;
//! use rsauthnz::id::{AuthorityVersion, Id, Principal};
//! use rsauthnz::limits::{Limits, SignatureBudget};
//! use rsauthnz::store::driver::{Answer, Driver, Plan};
//! use rsauthnz::store::{self, Store};
//! use rsauthnz::time::{Reading, ReadingSource};
//! use rsauthnz::transition::{Audit, Change, Dependency, OperationId, Outcome, Proposal};
//! use rsauthnz::workload::{self, By, Ceiling, Issuer, Pending, Registration, Replace, Request};
//! use rsauthnz_conformance::memory::{Memory, Schedule};
//! use rsauthnz_conformance::suite::execute;
//! use rscrypto::auth::MlDsa65Ed25519;
//! use rscrypto::ChaCha20Rng;
//!
//! # /// The policy of the example: it permits each request of a workload action until one day after `now`.
//! # struct Workloads(AuthorityVersion, Duration);
//! # impl Policy for Workloads {
//! #     fn version(&self) -> &AuthorityVersion {
//! #         &self.0
//! #     }
//! #     fn resolve(&self, request: &authz::Request<'_>) -> Option<Permit> {
//! #         Some(Permit {
//! #             principal: request.principal.clone(),
//! #             action: request.action.clone(),
//! #             resource: request.resource.clone(),
//! #             version: self.0.clone(),
//! #             requires: Requirements { user_verified: false, phishing_resistant: false, max_age: self.1 },
//! #             expires: self.1,
//! #         })
//! #     }
//! # }
//! type Failure = Box<dyn core::error::Error>;
//!
//! /// The output of `future`. Each future of the memory binding is ready at its first poll.
//! fn ready<F: Future>(future: F) -> F::Output {
//!     let Poll::Ready(output) = pin!(future).poll(&mut Context::from_waker(Waker::noop())) else {
//!         unreachable!("the memory binding does no I/O")
//!     };
//!     output
//! }
//!
//! /// Executes each effect of `driver` on the memory binding until it has none. A production binding does the same
//! /// with its own primitives.
//! fn settle(driver: &mut Driver, memory: &mut Memory) -> Result<(), Failure> {
//!     while let Some(effect) = driver.effect() {
//!         let output = ready(execute(memory, effect));
//!         driver.give(output)?;
//!     }
//!     Ok(())
//! }
//!
//! /// Commits `proposal` with `plan`, and gives its outcome.
//! fn commit(driver: &mut Driver, memory: &mut Memory, proposal: Proposal, plan: Plan) -> Result<Outcome, Failure> {
//!     let ticket = driver.submit(proposal, plan)?;
//!     settle(driver, memory)?;
//!     match driver.take(ticket) {
//!         Some(Answer::Outcome(outcome)) => Ok(outcome),
//!         answer => Err(format!("the commit gave {answer:?}").into()),
//!     }
//! }
//!
//! fn trusted(public: PublicKey<'_>) -> Result<TrustedKey, rsauthnz::cose::Error> {
//!     TrustedKey::new(Algorithm::MlDsa65Ed25519, &Key { kid: None, alg: None, public })
//! }
//!
//! # /// The evidence of an operator: a proof by the key of a credential of the operator, which a commit released.
//! # fn operator(
//! #     driver: &mut Driver,
//! #     memory: &mut Memory,
//! #     issuer_key: &TrustedKey,
//! #     issuer_secret: &rscrypto::auth::MlDsa65Ed25519SecretKey,
//! #     now: Reading,
//! # ) -> Result<Evidence, Failure> {
//! #     let (public, secret) = MlDsa65Ed25519::generate_keypair(|out| Ok(out.fill(3)))?;
//! #     let public = public.to_bytes();
//! #     let (console, purpose) = (Id::new("acme", "console")?, Id::new("acme", "operator")?);
//! #     let expires = now.estimate() + Duration::from_secs(3_600);
//! #     let human = Id::new("acme", "operator-1")?;
//! #     let subject = Subject::Human(human.clone());
//! #     let claims = Claims::new(Id::new("acme", "issuer")?, console.clone(), subject, purpose.clone(), Serial(0), expires);
//! #     let draft = Draft::credential(issuer_key, &claims, Some(PublicKey::MlDsa65Ed25519(&public)), now)?;
//! #     let signature = issuer_secret.sign_deterministic(&draft.to_be_signed(), &[])?;
//! #     let audit = Audit { actor: Principal::Human(human), action: Id::new("acme", "operator.sign-in")?, time: now };
//! #     let mut proposal = Proposal::new(OperationId::new(b"sign-in-1")?, audit, &Value::Null, Limits::default())?;
//! #     draft.record(&mut proposal)?;
//! #     proposal.prepare(draft.finish(signature.as_bytes(), &mut SignatureBudget::new(&Limits::default()))?)?;
//! #     let Outcome::Accepted(receipt) = commit(driver, memory, proposal, Plan::default())? else {
//! #         return Err("the sign-in did not commit".into());
//! #     };
//! #     let credential = receipt.artifact().ok_or("no artifact")?;
//! #     let profile = credential::Profile::new(issuer_key.clone(), claims.issuer, console.clone(), purpose, Limits::default())?;
//! #     let verified = profile.verify(credential, now, &mut SignatureBudget::new(&Limits::default()))?;
//! #     let draft = ProofDraft::new(&trusted(PublicKey::MlDsa65Ed25519(&public))?, credential, &console, b"op", now)?;
//! #     let signature = secret.sign_deterministic(&draft.to_be_signed(), &[])?;
//! #     let proof = draft.finish(signature.as_bytes(), &mut SignatureBudget::new(&Limits::default()))?;
//! #     Ok(verified.possession(&proof, b"op", now, &mut SignatureBudget::new(&Limits::default()))?)
//! # }
//! // Custody holds the secret keys. Here rscrypto signs in place of custody. A fixed filler makes the keys
//! // reproducible. Use fresh randomness for real keys.
//! let (issuer_public, issuer_secret) = MlDsa65Ed25519::generate_keypair(|out| Ok(out.fill(1)))?;
//! let (runner_public, runner_secret) = MlDsa65Ed25519::generate_keypair(|out| Ok(out.fill(2)))?;
//! let (issuer_public, runner_public) = (issuer_public.to_bytes(), runner_public.to_bytes());
//! let now = Reading::new(Duration::from_secs(1_800_000_000), Some(Duration::from_secs(1)), ReadingSource::Caller);
//! let (authority, runner) = (Id::new("acme", "issuer")?, Id::new("acme", "runner-7")?);
//! let build = Id::new("acme", "build-api")?;
//! let mut memory = Memory::new(Schedule::None);
//! let mut driver = Driver::new(store::Profile::new(memory.declaration())?, Limits::default(), &mut ChaCha20Rng::from_seed([1; 32]))?;
//! driver.start(now);
//! settle(&mut driver, &mut memory)?;
//! # let policy = Workloads(AuthorityVersion::new(authority.clone(), &[1])?, now.estimate() + Duration::from_secs(86_400));
//! # let operator = operator(&mut driver, &mut memory, &trusted(PublicKey::MlDsa65Ed25519(&issuer_public))?, &issuer_secret, now)?;
//!
//! // 1. The application registers the issuer and the workload, and writes its policy version, in its own transition.
//! let issuer = Issuer::new(
//!     authority.clone(),
//!     PublicKey::MlDsa65Ed25519(&issuer_public),
//!     vec![build.clone()],
//!     Ceiling { lifetime_max: Duration::from_secs(3_600), not_after: now.estimate() + Duration::from_secs(86_400) },
//! )?;
//! let audit = Audit { actor: operator.subject().clone(), action: Id::new("acme", "workload.register")?, time: now };
//! let mut setup = Proposal::new(OperationId::new(b"register-1")?, audit, &Value::Null, Limits::default())?;
//! let policy_key = store::policy_key(&authority);
//! setup.read(Dependency::Absent(policy_key.clone()))?;
//! let version = AuthorityVersion::new(authority.clone(), &[1])?;
//! setup.change(Change::Write { key: policy_key, version, end: None, data: Box::from(*b"policy 1") })?;
//! issuer.register(&mut setup, &mut driver)?;
//! let runner_key = PublicKey::MlDsa65Ed25519(&runner_public);
//! Registration::register(&mut setup, runner.clone(), runner_key, &issuer, &mut driver)?;
//! assert!(matches!(commit(&mut driver, &mut memory, setup, Plan::default())?, Outcome::Accepted(_)));
//!
//! // 2. An operator asks for the first credential. `policy` permits it `Mode::Issue`, and `operator` is its evidence.
//! let issuer_record = ready(memory.read(&Issuer::store_key(&authority)))?.ok_or("no issuer")?;
//! let registration_record = ready(memory.read(&Registration::store_key(&runner)))?.ok_or("no registration")?;
//! let operation = OperationId::new(b"issue-1")?;
//! let request = Request { operation, by: By::Issue(&operator), audience: &build, lifetime: None, replace: None };
//! let pending =
//!     Pending::new(request, &issuer_record, &registration_record, &policy, &mut driver, now, Limits::default())?;
//!
//! // 3. Custody signs, and `finish` puts the credential into the proposal. Only the accepted commit releases it.
//! let budget = || SignatureBudget::new(&Limits::default());
//! let signature = issuer_secret.sign_deterministic(&pending.to_be_signed(), &[])?;
//! let (proposal, plan, awaiting) = pending.finish(signature.as_bytes(), &mut budget())?;
//! let credential = awaiting.release(commit(&mut driver, &mut memory, proposal, plan)?)?;
//!
//! // 4. The audience verifies the credential locally and checks a proof by the registered key. A verifier that reads
//! // the current registration also refuses a credential that a rotation, a recovery, or a revocation ended.
//! let runner_key = trusted(PublicKey::MlDsa65Ed25519(&runner_public))?;
//! let prove = |challenge: &[u8], now: Reading| -> Result<Vec<u8>, Failure> {
//!     let draft = ProofDraft::new(&runner_key, credential.as_bytes(), &build, challenge, now)?;
//!     let signature = runner_secret.sign_deterministic(&draft.to_be_signed(), &[])?;
//!     Ok(draft.finish(signature.as_bytes(), &mut budget())?)
//! };
//! let profile = issuer.profile(&build, Limits::default())?;
//! let verified = profile.verify(credential.as_bytes(), now, &mut budget())?;
//! let evidence = verified.possession(&prove(b"challenge-1", now)?, b"challenge-1", now, &mut budget())?;
//! assert_eq!(evidence.subject(), &Principal::Workload(runner.clone()));
//! let current = ready(memory.read(&Registration::store_key(&runner)))?;
//! workload::admits(&verified, current.as_ref(), Limits::default())?;
//!
//! // 5. At half its lifetime, the workload renews with its credential and a proof over the binding of the challenge of
//! // the issuer to its request. Each issuance writes the registration, so read it again.
//! let later = Reading::new(credential.renew_at(), Some(Duration::from_secs(1)), ReadingSource::Caller);
//! let operation = OperationId::new(b"renew-1")?;
//! let proof = prove(&workload::binding(b"challenge-2", &operation, &authority, &runner, &build, None), later)?;
//! let by = By::Renew { credential: credential.as_bytes(), proof: &proof, challenge: b"challenge-2" };
//! let request = Request { operation, by, audience: &build, lifetime: None, replace: None };
//! let registration_record = current.ok_or("no registration")?;
//! let pending =
//!     Pending::new(request, &issuer_record, &registration_record, &policy, &mut driver, later, Limits::default())?;
//! let signature = issuer_secret.sign_deterministic(&pending.to_be_signed(), &[])?;
//! let (proposal, plan, awaiting) = pending.finish(signature.as_bytes(), &mut budget())?;
//! let renewed = awaiting.release(commit(&mut driver, &mut memory, proposal, plan)?)?;
//! assert!(renewed.serial() > credential.serial());
//!
//! // 6. The host is lost. The operator recovers the workload on a new host, which proves its new key over the key
//! // binding and the binding of its challenge. One commit issues to the new host and ends each credential of the old
//! // host.
//! let (host_public, host_secret) = MlDsa65Ed25519::generate_keypair(|out| Ok(out.fill(4)))?;
//! let host_public = host_public.to_bytes();
//! let host_key = PublicKey::MlDsa65Ed25519(&host_public);
//! let operation = OperationId::new(b"recover-1")?;
//! let bound = workload::binding(b"challenge-3", &operation, &authority, &runner, &build, Some(&host_key));
//! let key_binding = workload::key_binding(&runner, &host_key);
//! let draft = ProofDraft::new(&trusted(host_key.clone())?, &key_binding, &build, &bound, later)?;
//! let signature = host_secret.sign_deterministic(&draft.to_be_signed(), &[])?;
//! let proof = draft.finish(signature.as_bytes(), &mut budget())?;
//! let replace = Replace { key: host_key, proof: &proof, challenge: b"challenge-3" };
//! let by = By::Issue(&operator);
//! let request = Request { operation, by, audience: &build, lifetime: None, replace: Some(replace) };
//! let registration_record = ready(memory.read(&Registration::store_key(&runner)))?.ok_or("no registration")?;
//! let pending =
//!     Pending::new(request, &issuer_record, &registration_record, &policy, &mut driver, later, Limits::default())?;
//! let signature = issuer_secret.sign_deterministic(&pending.to_be_signed(), &[])?;
//! let (proposal, plan, awaiting) = pending.finish(signature.as_bytes(), &mut budget())?;
//! let replacement = awaiting.release(commit(&mut driver, &mut memory, proposal, plan)?)?;
//!
//! // A verifier that reads the current registration admits the new host and refuses the old one.
//! let current = ready(memory.read(&Registration::store_key(&runner)))?;
//! let verified = profile.verify(replacement.as_bytes(), later, &mut budget())?;
//! workload::admits(&verified, current.as_ref(), Limits::default())?;
//! let verified = profile.verify(renewed.as_bytes(), later, &mut budget())?;
//! assert_eq!(workload::admits(&verified, current.as_ref(), Limits::default()), Err(workload::Error::Revoked));
//! # Ok::<(), Failure>(())
//! ```

use alloc::boxed::Box;
use alloc::string::ToString;
use alloc::vec;
use alloc::vec::Vec;
use core::cmp::Ordering;
use core::fmt;
use core::time::Duration;

use crate::authz::{self, Policy, Refusal};
use crate::cbor::{self, Value};
use crate::cose::{self, Key, PublicKey, TrustedKey};
use crate::credential::{self, Awaiting, Claims, Draft, Serial, Subject};
use crate::crypto;
use crate::evidence::Evidence;
use crate::id::{Action, Audience, Authority, AuthorityVersion, Id, Principal, Purpose, Resource, Workload};
use crate::limits::{Limits, SignatureBudget};
use crate::store::driver::{self, Driver, Plan};
use crate::store::{Kind, Record};
use crate::time::Reading;
use crate::transition::{self, Audit, Change, Dependency, OperationId, Proposal};

/// The lifetime of a credential when the request names none, unless the ceiling of the issuer is shorter. Renew a
/// credential at half its lifetime ([`Released::renew_at`](credential::Released::renew_at)).
pub const LIFETIME_DEFAULT: Duration = Duration::from_secs(3_600);

/// The most audiences of one issuer. A record with this many audiences of the longest identifiers is within the
/// default [`Limits`].
pub const AUDIENCES_MAX: usize = 16;

/// The first item of the CBOR form of an issuer record. Its number changes with the form.
const ISSUER_FORM: &str = "rsauthnz.workload.issuer.2";

/// The first item of the CBOR form of a registration record. Its number changes with the form.
const REGISTRATION_FORM: &str = "rsauthnz.workload.registration.3";

/// The first item of the CBOR form of a key binding ([`key_binding`]). Its number changes with the form.
const KEY_FORM: &str = "rsauthnz.workload.key.1";

/// The first item of the CBOR form of the binding of a proof to its request ([`binding`]). Its number changes with
/// the form.
const PROOF_FORM: &str = "rsauthnz.workload.proof.1";

/// The most credentials of one workload that a revocation of one credential ends, before they end by time. A
/// revocation of one more credential refuses: revoke all credentials ([`Target::All`]).
pub const REVOKED_MAX: usize = 16;

/// The purpose of each workload credential: `rsauthnz:workload`. A workload credential never verifies for another
/// purpose, such as an agent credential of the same issuer key.
///
/// Cost class: [`Parse`](crate::limits::Class::Parse).
#[must_use]
pub fn purpose() -> Id<Purpose> {
    Id::new("rsauthnz", "workload").expect("the purpose is a valid identifier")
}

/// The resource of the workload `workload` in the policy: an identifier with its namespace and its value. The policy
/// permits an issuance, a renewal, a rotation, a recovery, and a revocation on this resource.
///
/// Cost class: [`Parse`](crate::limits::Class::Parse).
#[must_use]
pub fn resource(workload: &Id<Workload>) -> Id<Resource> {
    Id::new(workload.namespace(), workload.value()).expect("a resource has the rules of a workload identifier")
}

/// The resource of the issuer `authority` in the policy: an identifier with its namespace and its value. The policy
/// permits a rotation of the issuer key on this resource.
///
/// Cost class: [`Parse`](crate::limits::Class::Parse).
#[must_use]
pub fn issuer_resource(authority: &Id<Authority>) -> Id<Resource> {
    Id::new(authority.namespace(), authority.value()).expect("a resource has the rules of an authority identifier")
}

/// The key binding of `workload` and its new key `key`, for a rotation or a recovery ([`Replace`]). A proof of
/// possession of the new key binds these bytes in place of a credential. They are the canonical CBOR array
/// `["rsauthnz.workload.key.1", workload, kid]`, where `kid` is the COSE Key Thumbprint of `key`
/// ([`TrustedKey::kid`]). The holder of the new key makes the proof over these bytes with
/// [`credential::ProofDraft::new`], for the audience of the request and the [`binding`] of its challenge.
///
/// Cost class: [`Parse`](crate::limits::Class::Parse).
#[must_use]
pub fn key_binding(workload: &Id<Workload>, key: &PublicKey<'_>) -> Vec<u8> {
    let kid = key.thumbprint();
    cbor::encode(
        &Value::Array(vec![Value::Text(KEY_FORM), workload.to_cbor(), Value::Bytes(&kid)]),
        Limits::FORM,
    )
    .expect("the form has no map and no simple value")
}

/// The binding of a proof to its request: the SHA-256 digest of the canonical CBOR array `["rsauthnz.workload.proof.1",
/// challenge, operation, issuer, workload, audience, kid]`. `kid` is the COSE Key Thumbprint of the new key `key` of a
/// rotation or a recovery, or `null` with no new key. Each proof of a request binds this digest in place of the bare
/// challenge ([`credential::ProofDraft::new`]): the proof by the current key of a renewal or a rotation, and the proof
/// by the new key of a rotation or a recovery. Thus a proof gives no authority for another operation, issuer,
/// workload, audience, or new key, and the current key of a rotation signs the choice of the new key.
///
/// Cost class: [`Parse`](crate::limits::Class::Parse). One SHA-256 digest of the bounded form.
#[must_use]
pub fn binding(
    challenge: &[u8],
    operation: &OperationId,
    issuer: &Id<Authority>,
    workload: &Id<Workload>,
    audience: &Id<Audience>,
    key: Option<&PublicKey<'_>>,
) -> [u8; 32] {
    let kid = key.map(PublicKey::thumbprint);
    let form = Value::Array(vec![
        Value::Text(PROOF_FORM),
        Value::Bytes(challenge),
        Value::Bytes(operation.as_bytes()),
        issuer.to_cbor(),
        workload.to_cbor(),
        audience.to_cbor(),
        kid.as_ref().map_or(Value::Null, |kid| Value::Bytes(kid)),
    ]);
    crypto::sha256(&cbor::encode(&form, Limits::FORM).expect("the form has no map and no simple value"))
}

/// The kind of an operation, and its action in the policy.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub enum Mode {
    /// A first issuance: `rsauthnz:workload.issue`.
    Issue,
    /// A renewal by the workload: `rsauthnz:workload.renew`.
    Renew,
    /// A rotation of the proof key by the workload: `rsauthnz:workload.rotate`.
    Rotate,
    /// A recovery of the workload on a replacement host: `rsauthnz:workload.recover`.
    Recover,
    /// A revocation of credentials of the workload: `rsauthnz:workload.revoke`.
    Revoke,
    /// A rotation of the issuer key: `rsauthnz:workload.issuer.rotate`.
    RotateIssuer,
}

impl Mode {
    /// The action of the mode, which the policy permits.
    ///
    /// Cost class: [`Parse`](crate::limits::Class::Parse).
    #[must_use]
    pub fn action(self) -> Id<Action> {
        let value = match self {
            Self::Issue => "workload.issue",
            Self::Renew => "workload.renew",
            Self::Rotate => "workload.rotate",
            Self::Recover => "workload.recover",
            Self::Revoke => "workload.revoke",
            Self::RotateIssuer => "workload.issuer.rotate",
        };
        Id::new("rsauthnz", value).expect("the action is a valid identifier")
    }
}

/// The ceiling of an issuer: the most authority of one credential. A request past it refuses, with no shorter
/// credential in its place.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Ceiling {
    /// The longest lifetime of a credential. The record keeps whole seconds.
    pub lifetime_max: Duration,
    /// The latest end of a credential, as the time since the Unix epoch. The record keeps whole seconds.
    pub not_after: Duration,
}

/// A public key of a record: its encoded `COSE_Key`, with its `alg`, and its trusted key.
#[derive(Clone, PartialEq, Eq)]
struct RecordKey {
    encoded: Box<[u8]>,
    trusted: TrustedKey,
}

impl RecordKey {
    /// The record key of `key`.
    fn new(key: PublicKey<'_>) -> Result<Self, Error> {
        let trusted = TrustedKey::new(
            key.algorithm(),
            &Key {
                kid: None,
                alg: None,
                public: key.clone(),
            },
        )
        .map_err(Error::Key)?;
        let encoded =
            cbor::encode(&key.to_cbor(), Limits::FORM).expect("a COSE_Key has distinct keys and no simple value");
        Ok(Self {
            encoded: encoded.into_boxed_slice(),
            trusted,
        })
    }

    /// Reads the encoded `COSE_Key` `encoded` of a record.
    fn decode(encoded: &[u8], limits: Limits) -> Result<Self, Error> {
        Self::new(Key::decode(encoded, limits).map_err(|_| Error::Record)?.public).map_err(|_| Error::Record)
    }

    /// The public key, for the `cnf` claim of a draft.
    fn public(&self, limits: Limits) -> Result<PublicKey<'_>, Error> {
        Ok(Key::decode(&self.encoded, limits).map_err(|_| Error::Record)?.public)
    }
}

/// An issuer of workload credentials: the authority that issues, its current key, the previous key during a rotation,
/// its audiences, and its ceiling. The algorithm of the keys is the profile that each audience declares. The store
/// keeps it as a [`Kind::Issuer`] record.
#[derive(Clone, PartialEq, Eq)]
pub struct Issuer {
    authority: Id<Authority>,
    /// The key that signs each new credential.
    current: RecordKey,
    /// The key that the current key replaced, and the time from which no credential that it signed is valid.
    previous: Option<(RecordKey, Duration)>,
    /// Sorted, with no two equal.
    audiences: Vec<Id<Audience>>,
    ceiling: Ceiling,
}

impl Issuer {
    /// The issuer `authority` with the public key `key`, the audiences `audiences`, and the ceiling `ceiling`. The
    /// issuer drops a second equal audience, and it keeps the whole seconds of the ceiling. The bound counts each
    /// audience of `audiences`, also a second equal one, before the issuer sorts them.
    ///
    /// Cost class: [`Verify`](crate::limits::Class::Verify). The key checks as [`TrustedKey::new`] checks it.
    ///
    /// # Errors
    ///
    /// [`Error::Audiences`] for more than [`AUDIENCES_MAX`] audiences, and [`Error::Key`] if `key` refuses as a
    /// trusted key.
    pub fn new(
        authority: Id<Authority>,
        key: PublicKey<'_>,
        audiences: Vec<Id<Audience>>,
        ceiling: Ceiling,
    ) -> Result<Self, Error> {
        Self::with(authority, RecordKey::new(key)?, None, audiences, ceiling)
    }

    /// The issuer with the record keys `current` and `previous`.
    fn with(
        authority: Id<Authority>,
        current: RecordKey,
        previous: Option<(RecordKey, Duration)>,
        mut audiences: Vec<Id<Audience>>,
        ceiling: Ceiling,
    ) -> Result<Self, Error> {
        (audiences.len() <= AUDIENCES_MAX).ok_or(Error::Audiences)?;
        audiences.sort_unstable();
        audiences.dedup();
        let whole = |time: Duration| Duration::from_secs(time.as_secs());
        Ok(Self {
            authority,
            current,
            previous,
            audiences,
            ceiling: Ceiling {
                lifetime_max: whole(ceiling.lifetime_max),
                not_after: whole(ceiling.not_after),
            },
        })
    }

    /// Reads the record form `data` of an issuer. The decode uses `limits`.
    ///
    /// Cost class: [`Verify`](crate::limits::Class::Verify).
    ///
    /// # Errors
    ///
    /// [`Error::Record`] if `data` is not the record form of an issuer.
    pub fn from_record(data: &[u8], limits: Limits) -> Result<Self, Error> {
        let value = cbor::decode(data, limits).map_err(|_| Error::Record)?;
        let Value::Array(items) = &value else {
            return Err(Error::Record);
        };
        let [
            Value::Text(ISSUER_FORM),
            authority,
            Value::Bytes(current),
            previous,
            Value::Array(audiences),
            Value::Unsigned(lifetime_max),
            Value::Unsigned(not_after),
        ] = items.as_slice()
        else {
            return Err(Error::Record);
        };
        let previous = match previous {
            Value::Null => None,
            Value::Array(previous) => match previous.as_slice() {
                [Value::Bytes(key), Value::Unsigned(until)] => {
                    Some((RecordKey::decode(key, limits)?, Duration::from_secs(*until)))
                }
                _ => return Err(Error::Record),
            },
            _ => return Err(Error::Record),
        };
        let current = RecordKey::decode(current, limits)?;
        if previous
            .as_ref()
            .is_some_and(|(previous, _)| previous.trusted.algorithm() != current.trusted.algorithm())
        {
            return Err(Error::Record);
        }
        let audiences = audiences
            .iter()
            .map(|audience| Id::from_cbor(audience).map_err(|_| Error::Record))
            .collect::<Result<_, _>>()?;
        let ceiling = Ceiling {
            lifetime_max: Duration::from_secs(*lifetime_max),
            not_after: Duration::from_secs(*not_after),
        };
        let authority = Id::from_cbor(authority).map_err(|_| Error::Record)?;
        Self::with(authority, current, previous, audiences, ceiling).map_err(|_| Error::Record)
    }

    /// The record form: the canonical CBOR array `["rsauthnz.workload.issuer.2", authority, key, previous,
    /// audiences, lifetime_max, not_after]`. `previous` is `null`, or `[key, until]` during a rotation.
    fn to_record(&self) -> Box<[u8]> {
        let audiences = self.audiences.iter().map(Id::to_cbor).collect();
        let previous = self.previous.as_ref().map_or(Value::Null, |(key, until)| {
            Value::Array(vec![Value::Bytes(&key.encoded), Value::Unsigned(until.as_secs())])
        });
        let form = Value::Array(vec![
            Value::Text(ISSUER_FORM),
            self.authority.to_cbor(),
            Value::Bytes(&self.current.encoded),
            previous,
            Value::Array(audiences),
            Value::Unsigned(self.ceiling.lifetime_max.as_secs()),
            Value::Unsigned(self.ceiling.not_after.as_secs()),
        ]);
        cbor::encode(&form, Limits::FORM)
            .expect("the form has no map and no simple value")
            .into_boxed_slice()
    }

    /// Adds the first write of the issuer record to `proposal`: the absence of the record, and its write at
    /// [`Self::store_key`]. The version is the authority of the issuer and a new value of the [`Kind::Issuer`]
    /// counter of `driver`. Thus each later write by rsauthnz has a later version, also after a restore.
    ///
    /// Cost class: [`Parse`](crate::limits::Class::Parse).
    ///
    /// # Errors
    ///
    /// [`Error::Driver`] if the driver gives no value, and [`Error::Transition`] if the proposal refuses.
    pub fn register(&self, proposal: &mut Proposal, driver: &mut Driver) -> Result<(), Error> {
        let key = Self::store_key(&self.authority);
        proposal.read(Dependency::Absent(key.clone()))?;
        proposal.change(Change::Write {
            key,
            version: version(self.authority.clone(), driver.allocate()?),
            end: None,
            data: self.to_record(),
        })?;
        Ok(())
    }

    /// The key of the record of the issuer `authority`: [`Kind::Issuer`] with the SHA-256 digest of the canonical CBOR
    /// form of the authority.
    ///
    /// Cost class: [`Parse`](crate::limits::Class::Parse).
    #[must_use]
    pub fn store_key(authority: &Id<Authority>) -> transition::Key {
        digest_key(Kind::Issuer, &authority.to_cbor())
    }

    /// The authority that issues.
    #[must_use]
    pub const fn authority(&self) -> &Id<Authority> {
        &self.authority
    }

    /// The number of its keys: the current key, and the previous key during a rotation.
    pub(crate) const fn keys(&self) -> usize {
        if self.previous.is_some() { 2 } else { 1 }
    }

    /// The audiences, sorted.
    #[must_use]
    pub fn audiences(&self) -> &[Id<Audience>] {
        &self.audiences
    }

    /// The ceiling.
    #[must_use]
    pub const fn ceiling(&self) -> Ceiling {
        self.ceiling
    }

    /// The verification profile of the workload credentials of this issuer for `audience`. It holds the current key
    /// and the previous key, and the `kid` of a credential selects one of them. The verification of the profile is
    /// local: it takes the credential, the time, and a budget, and it looks up nothing.
    ///
    /// Cost class: [`Parse`](crate::limits::Class::Parse).
    ///
    /// # Errors
    ///
    /// [`Error::Audience`] if `audience` is not an audience of the issuer, and [`Error::Credential`] if the format
    /// refuses the key of the issuer.
    pub fn profile(&self, audience: &Id<Audience>, limits: Limits) -> Result<credential::Profile, Error> {
        self.audiences.binary_search(audience).map_err(|_| Error::Audience)?;
        let profile = credential::Profile::new(
            self.current.trusted.clone(),
            self.authority.clone(),
            audience.clone(),
            purpose(),
            limits,
        )?;
        Ok(match &self.previous {
            Some((previous, until)) => profile.with_previous(previous.trusted.clone(), *until)?,
            None => profile,
        })
    }
}

impl fmt::Debug for Issuer {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("Issuer")
            .field("authority", &self.authority)
            .field("key", &self.current.trusted)
            .field(
                "previous",
                &self.previous.as_ref().map(|(key, until)| (&key.trusted, until)),
            )
            .field("audiences", &self.audiences)
            .field("ceiling", &self.ceiling)
            .finish()
    }
}

/// The registration of a workload: its identifier, its registered proof key, its generation, and its revoked
/// credentials. Each credential of the workload has this key as its `cnf` key. The store keeps it as a
/// [`Kind::Workload`] record, whose version names the issuer of the workload.
///
/// The generation is a serial: each credential of the workload with a lower serial is dead. A rotation, a recovery,
/// and a revocation of all credentials each raise it in the commit that makes the change. A revocation of one
/// credential adds its serial and its end to the revoked credentials, at most [`REVOKED_MAX`] of them. A credential
/// leaves the list when it ends. A verifier that reads the current registration refuses a dead or a revoked
/// credential ([`admits`]).
#[derive(Clone, PartialEq, Eq)]
pub struct Registration {
    workload: Id<Workload>,
    key: RecordKey,
    generation: Serial,
    /// The revoked credentials at or above the generation, with their ends, sorted by serial.
    revoked: Vec<(Serial, Duration)>,
}

impl Registration {
    /// Adds the first write of the registration of `workload` with the proof key `key` to `proposal`. It adds the
    /// absence of the record, and its write at [`Self::store_key`]. The generation is a new value of the
    /// [`Kind::Credential`] counter of `driver`. Thus a credential of an earlier registration of the same workload
    /// never verifies again. The version is the authority of `issuer` and the generation, so the registration names its
    /// issuer: an issuance of another issuer refuses, and so does a credential of another issuer at a verifier.
    ///
    /// Cost class: [`Verify`](crate::limits::Class::Verify). The key checks as [`TrustedKey::new`] checks it.
    ///
    /// # Errors
    ///
    /// [`Error::Key`] if `key` refuses as a trusted key, [`Error::Driver`] if the driver gives no value, and
    /// [`Error::Transition`] if the proposal refuses.
    pub fn register(
        proposal: &mut Proposal,
        workload: Id<Workload>,
        key: PublicKey<'_>,
        issuer: &Issuer,
        driver: &mut Driver,
    ) -> Result<Self, Error> {
        let key = RecordKey::new(key)?;
        let generation = Serial(driver.allocate()?);
        let registration = Self {
            workload,
            key,
            generation,
            revoked: Vec::new(),
        };
        let store_key = Self::store_key(&registration.workload);
        proposal.read(Dependency::Absent(store_key.clone()))?;
        proposal.change(Change::Write {
            key: store_key,
            version: version(issuer.authority.clone(), generation.0),
            end: None,
            data: registration.to_record(),
        })?;
        Ok(registration)
    }

    /// Reads the record form `data` of a registration. The decode uses `limits`.
    ///
    /// Cost class: [`Verify`](crate::limits::Class::Verify).
    ///
    /// # Errors
    ///
    /// [`Error::Record`] if `data` is not the record form of a registration.
    pub fn from_record(data: &[u8], limits: Limits) -> Result<Self, Error> {
        let (workload, key, generation, revoked) = Self::fields(data, limits)?;
        Ok(Self {
            workload,
            key: RecordKey::decode(key, limits)?,
            generation,
            revoked,
        })
    }

    /// The workload, the encoded key, the generation, and the revoked credentials of the record form `data`. The check
    /// of [`admits`] compares the thumbprint of the key, so it makes no trusted key.
    #[expect(
        clippy::type_complexity,
        reason = "the four fields of the record form, which only three callers read"
    )]
    pub(crate) fn fields(
        data: &[u8],
        limits: Limits,
    ) -> Result<(Id<Workload>, &[u8], Serial, Vec<(Serial, Duration)>), Error> {
        let value = cbor::decode(data, limits).map_err(|_| Error::Record)?;
        let Value::Array(items) = &value else {
            return Err(Error::Record);
        };
        let [
            Value::Text(REGISTRATION_FORM),
            workload,
            Value::Bytes(key),
            Value::Unsigned(generation),
            Value::Array(revoked),
        ] = items.as_slice()
        else {
            return Err(Error::Record);
        };
        (revoked.len() <= REVOKED_MAX).ok_or(Error::Record)?;
        let revoked = revoked
            .iter()
            .map(|entry| match entry {
                Value::Array(pair) => match pair.as_slice() {
                    [Value::Unsigned(serial), Value::Unsigned(expires)] => {
                        Ok((Serial(*serial), Duration::from_secs(*expires)))
                    }
                    _ => Err(Error::Record),
                },
                _ => Err(Error::Record),
            })
            .collect::<Result<Vec<_>, _>>()?;
        let workload = Id::from_cbor(workload).map_err(|_| Error::Record)?;
        Ok((workload, key, Serial(*generation), revoked))
    }

    /// The record form: the canonical CBOR array `["rsauthnz.workload.registration.3", workload, key, generation,
    /// revoked]`. `revoked` is an array of `[serial, expires]` pairs, sorted by serial, with `expires` in whole seconds.
    fn to_record(&self) -> Box<[u8]> {
        let revoked = self
            .revoked
            .iter()
            .map(|(serial, expires)| Value::Array(vec![Value::Unsigned(serial.0), Value::Unsigned(expires.as_secs())]))
            .collect();
        let form = Value::Array(vec![
            Value::Text(REGISTRATION_FORM),
            self.workload.to_cbor(),
            Value::Bytes(&self.key.encoded),
            Value::Unsigned(self.generation.0),
            Value::Array(revoked),
        ]);
        cbor::encode(&form, Limits::FORM)
            .expect("the form has no map and no simple value")
            .into_boxed_slice()
    }

    /// Adds the write of this registration to `proposal`. `record` is the current record of the registration, and
    /// `value` is a new value of the [`Kind::Credential`] counter. It adds the dependency on the version of `record`.
    /// It adds the write at the version of the owner of `record` and `value`. The write drops each revoked credential
    /// that is below the generation, or past its end at each time that `now` permits.
    fn rewrite(&mut self, proposal: &mut Proposal, record: &Record, value: u64, now: Reading) -> Result<(), Error> {
        let earliest = now.earliest().map_err(|error| Error::Refusal(Refusal::Time(error)))?;
        let generation = self.generation;
        self.revoked
            .retain(|(serial, expires)| *serial >= generation && *expires > earliest);
        let key = Self::store_key(&self.workload);
        proposal.read(Dependency::Version(key.clone(), record.version.clone()))?;
        proposal.change(Change::Write {
            key,
            version: later(&record.version, value)?,
            end: None,
            data: self.to_record(),
        })?;
        Ok(())
    }

    /// Whether the credential with the serial `serial` is dead or revoked.
    fn ended(&self, serial: Serial) -> bool {
        serial < self.generation || self.revoked.iter().any(|(revoked, _)| *revoked == serial)
    }

    /// The key of the record of `workload`: [`Kind::Workload`] with the SHA-256 digest of the canonical CBOR form of
    /// the workload.
    ///
    /// Cost class: [`Parse`](crate::limits::Class::Parse).
    #[must_use]
    pub fn store_key(workload: &Id<Workload>) -> transition::Key {
        digest_key(Kind::Workload, &workload.to_cbor())
    }

    /// The workload.
    #[must_use]
    pub const fn workload(&self) -> &Id<Workload> {
        &self.workload
    }

    /// The generation: each credential of the workload with a lower serial is dead.
    #[must_use]
    pub const fn generation(&self) -> Serial {
        self.generation
    }
}

impl fmt::Debug for Registration {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("Registration")
            .field("workload", &self.workload)
            .field("key", &self.key.trusted)
            .field("generation", &self.generation)
            .field("revoked", &self.revoked)
            .finish()
    }
}

/// Checks the verified credential `verified` against `registration`, the current registration record of its workload,
/// which the application reads with a keyed read of [`Registration::store_key`]. Give `None` when the store has no
/// record. A verifier that makes this check after [`credential::Profile::verify`] refuses each credential that a
/// rotation, a recovery, or a revocation ended. The check is local: it reads only `registration`. The decode uses
/// `limits`.
///
/// The credential must be a workload credential ([`purpose`]) of the issuer of the registration, for its workload,
/// with the registered key as its `cnf` key. Its serial must be at or above the generation, and not revoked. Thus a
/// receipt, a credential of another issuer, or a credential of another key refuses.
///
/// Cost class: [`Parse`](crate::limits::Class::Parse). The check compares the COSE Key Thumbprint of the registered
/// key with the `cnf` key, so it makes no trusted key.
///
/// # Errors
///
/// [`Error::Unregistered`] for no record, [`Error::Record`] for a record that is not the form of a registration,
/// [`Error::Possession`] if the credential is of another purpose, issuer, workload, or `cnf` key, and
/// [`Error::Revoked`] if its serial is below the generation or revoked.
pub fn admits(
    verified: &credential::Verified<'_, '_>,
    registration: Option<&Record>,
    limits: Limits,
) -> Result<(), Error> {
    let registration = registration.ok_or(Error::Unregistered)?;
    let (workload, key, generation, revoked) = Registration::fields(&registration.data, limits)?;
    let registered = Key::decode(key, limits).map_err(|_| Error::Record)?.public.thumbprint();
    let member = Admitted {
        issuer: registration.version.owner(),
        workload: &workload,
        thumbprint: &registered,
        generation,
        revoked: &revoked,
    };
    member.admits(verified)
}

/// What a verifier knows of a registration: its issuer, its workload, the COSE Key Thumbprint of its key, its
/// generation, and its revoked credentials. The current registration record gives it, or a trust snapshot
/// ([`crate::trust`]).
pub(crate) struct Admitted<'a> {
    pub(crate) issuer: &'a Id<Authority>,
    pub(crate) workload: &'a Id<Workload>,
    pub(crate) thumbprint: &'a [u8; 32],
    pub(crate) generation: Serial,
    pub(crate) revoked: &'a [(Serial, Duration)],
}

impl Admitted<'_> {
    /// The check of [`admits`].
    pub(crate) fn admits(&self, verified: &credential::Verified<'_, '_>) -> Result<(), Error> {
        let claims = verified.claims();
        let named = matches!(&claims.subject, Subject::Workload(named) if named == self.workload);
        (claims.purpose == purpose() && claims.issuer == *self.issuer && named).ok_or(Error::Possession)?;
        let ended = claims.serial < self.generation || self.revoked.iter().any(|(serial, _)| *serial == claims.serial);
        (!ended).ok_or(Error::Revoked)?;
        // Each credential at or above the generation has the registered key, so another key is no credential of the
        // registration.
        let bound = verified
            .confirmation()
            .is_some_and(|confirmation| confirmation.kid() == self.thumbprint);
        bound.ok_or(Error::Possession)
    }
}

/// A request for a workload credential.
#[derive(Clone, Debug)]
pub struct Request<'a> {
    /// The identity of the operation. After an unknown outcome, look up this identity: never submit the request as a
    /// new operation.
    pub operation: OperationId,
    /// The principal that asks, with its proof.
    pub by: By<'a>,
    /// The audience of the credential. It must be an audience of the issuer.
    pub audience: &'a Id<Audience>,
    /// The lifetime of the credential, or `None` for the lesser of [`LIFETIME_DEFAULT`] and the `lifetime_max` of the
    /// issuer.
    pub lifetime: Option<Duration>,
    /// A new proof key that replaces the registered key in the same commit, or `None` to keep the registered key.
    pub replace: Option<Replace<'a>>,
}

impl Request<'_> {
    /// The mode of the request: [`Mode::Issue`] or [`Mode::Renew`] for each kind of [`By`], or [`Mode::Recover`] or
    /// [`Mode::Rotate`] with a new key.
    #[must_use]
    pub const fn mode(&self) -> Mode {
        match (&self.by, &self.replace) {
            (By::Issue(_), None) => Mode::Issue,
            (By::Renew { .. }, None) => Mode::Renew,
            (By::Issue(_), Some(_)) => Mode::Recover,
            (By::Renew { .. }, Some(_)) => Mode::Rotate,
        }
    }
}

/// The principal that asks for a credential, with its proof.
#[derive(Clone, Copy)]
pub enum By<'a> {
    /// A first issuance, or a recovery, by the principal of the evidence, for example an operator. The policy must
    /// permit it the action of the mode on the [`resource`] of the workload.
    Issue(&'a Evidence),
    /// A renewal, or a rotation, by the workload. The policy must permit the workload the action of the mode on its
    /// [`resource`].
    Renew {
        /// The current credential of the workload from the same issuer, for the audience of the request.
        credential: &'a [u8],
        /// The proof of possession of the `cnf` key of `credential`, over `challenge` ([`credential::ProofDraft`]).
        proof: &'a [u8],
        /// The challenge of the issuer for the proof. Issue each challenge for one proof.
        challenge: &'a [u8],
    },
}

// As the output of a credential draft does, the output shows only the length of each artifact.
impl fmt::Debug for By<'_> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Issue(evidence) => f.debug_tuple("Issue").field(evidence).finish(),
            Self::Renew {
                credential,
                proof,
                challenge,
            } => f
                .debug_struct("Renew")
                .field("credential_len", &credential.len())
                .field("proof_len", &proof.len())
                .field("challenge_len", &challenge.len())
                .finish(),
        }
    }
}

/// A new proof key of a rotation or a recovery, with the proof that its holder has it. As for a certificate signing
/// request, the issuer binds no key that the workload does not hold.
#[derive(Clone)]
pub struct Replace<'a> {
    /// The new proof key. It becomes the registered key, and the `cnf` key of the credential.
    pub key: PublicKey<'a>,
    /// The proof of possession of `key` ([`credential::ProofDraft`]) over the bytes of [`key_binding`] of the
    /// workload and `key`. The proof is for the audience of the request and `challenge`.
    pub proof: &'a [u8],
    /// The challenge of the issuer for the proof. Issue each challenge for one proof.
    pub challenge: &'a [u8],
}

impl fmt::Debug for Replace<'_> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("Replace")
            .field("key", &self.key.algorithm())
            .field("proof_len", &self.proof.len())
            .field("challenge_len", &self.challenge.len())
            .finish()
    }
}

/// An issuance that custody did not sign yet: the draft of the credential, the proposal of its transition, and the
/// plan of its commit.
#[derive(Debug)]
pub struct Pending {
    draft: Draft,
    proposal: Proposal,
    plan: Plan,
    serial: Serial,
    issued: Duration,
    expires: Duration,
}

impl Pending {
    /// The issuance of `request`. `issuer` and `registration` are the current records of the issuer and of the
    /// workload, as the store holds them. `driver` gives the serial of the credential, so that a restore never gives
    /// one serial twice. The decode, the proof checks, and the proposal use `limits`.
    ///
    /// The issuance checks that the registration names this issuer, and it checks the audience and the ceiling of the
    /// issuer. For a renewal or a rotation, it verifies the current credential with [`Issuer::profile`]. The
    /// credential must name the registered workload and the registered key, and it must not be dead or revoked. Then
    /// it checks the proof of possession over the [`binding`] of its challenge. For a rotation or a recovery, it
    /// checks the proof of possession of the new key over the [`binding`] of its challenge, and the new key must not
    /// be the registered key. Then [`authz::check`] checks the evidence for the action of the mode on the
    /// [`resource`] of the workload under `policy`.
    ///
    /// The proposal reads the policy version of the permit, and the issuer record and the registration record at
    /// their versions. It writes the issuance record of the credential ([`Draft::record`]), which ends when the
    /// credential ends, and a new version of the registration record. Thus a concurrent rotation, recovery, or
    /// revocation conflicts with the issuance. A rotation and a recovery write the new key, with the serial of the
    /// credential as the generation. Thus each earlier credential of the workload is dead. The deadline of the proposal
    /// is the deadline of the checked scope ([`authz::Checked::deadline`]), so its commit refuses after the permit,
    /// the maximum age of the evidence, or the current credential ends.
    ///
    /// Cost class: [`Verify`](crate::limits::Class::Verify): a renewal verifies two signatures, of the current
    /// credential and of its proof, and a rotation three. The call of `policy` is the cost of the application.
    ///
    /// # Errors
    ///
    /// [`Error::Record`] if a record is not its form, [`Error::Issuer`] if the registration names another issuer, and
    /// [`Error::Audience`] for an audience that the issuer does not have. [`Error::Ceiling`] for a lifetime past
    /// `lifetime_max`, or an end past `not_after`. [`Error::Credential`] if the current credential or a proof refuses,
    /// if the key of the credential has another class than the key of the issuer, or with [`credential::Error::Size`]
    /// for a challenge longer than [`credential::MAX_BYTES`]. [`Error::Possession`] if the
    /// current credential names another workload or another `cnf` key than the registration, and [`Error::Revoked`]
    /// if it is dead or revoked. [`Error::Key`] if the new key refuses as a trusted key, and [`Error::Unchanged`] if it
    /// is the registered key. [`Error::Refusal`] if the policy refuses, [`Error::Driver`] if the driver gives no
    /// serial, and [`Error::Transition`] if the proposal refuses.
    pub fn new(
        request: Request<'_>,
        issuer: &Record,
        registration: &Record,
        policy: &impl Policy,
        driver: &mut Driver,
        now: Reading,
        limits: Limits,
    ) -> Result<Self, Error> {
        let mode = request.mode();
        let Request {
            operation,
            by,
            audience,
            lifetime,
            replace,
        } = request;
        // Each proof binds the digest of its challenge, so the bound comes before the digest.
        let long = |challenge: &[u8]| challenge.len() > credential::MAX_BYTES;
        if matches!(by, By::Renew { challenge, .. } if long(challenge))
            || replace.as_ref().is_some_and(|replace| long(replace.challenge))
        {
            return Err(Error::Credential(credential::Error::Size));
        }
        let (issuer_record, registration_record) = (issuer, registration);
        let issuer = Issuer::from_record(&issuer_record.data, limits)?;
        let mut registration = Registration::from_record(&registration_record.data, limits)?;
        (*registration_record.version.owner() == issuer.authority).ok_or(Error::Issuer)?;
        let profile = issuer.profile(audience, limits)?;
        let ceiling = issuer.ceiling;
        let new_key = replace
            .as_ref()
            .map(|replace| RecordKey::new(replace.key.clone()))
            .transpose()?;
        let new_kid = new_key.as_ref().map(|key| *key.trusted.kid());
        // A replacement of the registered key by itself would keep the key that the operation retires.
        (new_kid.as_ref() != Some(registration.key.trusted.kid())).ok_or(Error::Unchanged)?;
        // The request binding holds what the requester asks, so a new proposal of the same request after a lost
        // response binds the same request. The serial and the times are not part of it. It names the issuer, so the
        // same request under another issuer is another request.
        let asked = Value::Array(vec![
            issuer.authority.to_cbor(),
            registration.workload.to_cbor(),
            audience.to_cbor(),
            lifetime.map_or(Value::Null, |lifetime| Value::Unsigned(lifetime.as_secs())),
            new_kid.as_ref().map_or(Value::Null, |kid| Value::Bytes(kid)),
        ]);
        let lifetime = lifetime.unwrap_or_else(|| LIFETIME_DEFAULT.min(ceiling.lifetime_max));
        // The draft keeps the whole seconds of the times, so the check uses them too.
        let issued = Duration::from_secs(now.estimate().as_secs());
        let expires = issued
            .checked_add(lifetime)
            .map(|expires| Duration::from_secs(expires.as_secs()))
            .filter(|expires| lifetime <= ceiling.lifetime_max && *expires <= ceiling.not_after)
            .ok_or(Error::Ceiling)?;
        let replaced = replace.as_ref().map(|replace| &replace.key);
        let bound = |challenge: &[u8]| {
            binding(
                challenge,
                &operation,
                &issuer.authority,
                &registration.workload,
                audience,
                replaced,
            )
        };
        let evidence = match by {
            By::Issue(evidence) => evidence.clone(),
            By::Renew {
                credential,
                proof,
                challenge,
            } => {
                let verified = profile.verify(credential, now, &mut SignatureBudget::new(&limits))?;
                let claims = verified.claims();
                let named =
                    matches!(&claims.subject, Subject::Workload(workload) if *workload == registration.workload);
                (named && verified.confirmation() == Some(&registration.key.trusted)).ok_or(Error::Possession)?;
                (!registration.ended(claims.serial)).ok_or(Error::Revoked)?;
                verified.possession(proof, &bound(challenge), now, &mut SignatureBudget::new(&limits))?
            }
        };
        if let (Some(replace), Some(key)) = (&replace, &new_key) {
            credential::check_proof(
                &key.trusted,
                &key_binding(&registration.workload, &replace.key),
                &audience.to_string(),
                replace.proof,
                &bound(replace.challenge),
                limits,
                &mut SignatureBudget::new(&limits),
            )?;
        }
        let checked = authz::check(
            &evidence,
            &mode.action(),
            &resource(&registration.workload),
            policy,
            now,
        )?;
        let serial = Serial(driver.allocate()?);
        let claims = Claims::new(
            issuer.authority.clone(),
            audience.clone(),
            Subject::Workload(registration.workload.clone()),
            purpose(),
            serial,
            expires,
        );
        let mut plan = Plan::default();
        if let Some(key) = new_key {
            registration.key = key;
            registration.generation = serial;
            plan.replaced.push(Registration::store_key(&registration.workload));
        }
        let draft = Draft::credential(
            &issuer.current.trusted,
            &claims,
            Some(registration.key.public(limits)?),
            now,
        )?;
        let audit = Audit {
            actor: evidence.subject().clone(),
            action: mode.action(),
            time: now,
        };
        let mut proposal = Proposal::new(operation, audit, &asked, limits)?;
        proposal.read(Dependency::Policy(checked.permit().version.clone()))?;
        proposal.until(checked.deadline());
        proposal.read(Dependency::Version(
            Issuer::store_key(&issuer.authority),
            issuer_record.version.clone(),
        ))?;
        registration.rewrite(&mut proposal, registration_record, serial.0, now)?;
        draft.record(&mut proposal)?;
        Ok(Self {
            draft,
            proposal,
            plan,
            serial,
            issued,
            expires,
        })
    }

    /// The bytes that custody signs with the key of the issuer: the `Sig_structure` of the credential
    /// ([`Draft::to_be_signed`]).
    ///
    /// Cost class: [`Parse`](crate::limits::Class::Parse).
    #[must_use]
    pub fn to_be_signed(&self) -> Vec<u8> {
        self.draft.to_be_signed()
    }

    /// Verifies `signature`, the signature of custody over [`Self::to_be_signed`], with the key of the issuer, and
    /// puts the credential into the proposal. Submit the proposal to the commit driver with the [`Plan`], and give the
    /// outcome of its commit to [`Awaiting::release`]. The [`Awaiting`] keeps the SHA-256 digest of this credential,
    /// so it releases only this credential. The check charges `budget`, the budget of the credential.
    ///
    /// Cost class: [`Verify`](crate::limits::Class::Verify).
    ///
    /// # Errors
    ///
    /// [`Error::Credential`] if the signature does not verify with the key of the issuer, or if the check costs more
    /// than `budget` has.
    pub fn finish(self, signature: &[u8], budget: &mut SignatureBudget) -> Result<(Proposal, Plan, Awaiting), Error> {
        let Self {
            draft,
            mut proposal,
            plan,
            serial,
            issued,
            expires,
        } = self;
        let prepared = draft.finish(signature, budget)?;
        let awaiting = Awaiting::new(&proposal, &prepared, serial, issued, expires);
        proposal.prepare(prepared)?;
        Ok((proposal, plan, awaiting))
    }
}

/// The credentials that a revocation ends.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Target<'a> {
    /// The credential of this serial, and no other. The record is its issuance record, as the store holds it: a keyed
    /// read of [`credential::record_key`] of the serial.
    Credential(Serial, &'a Record),
    /// Each credential of the workload that a commit before the revocation released.
    All,
}

/// A revocation of credentials of a workload, in one commit. A revocation of one credential ends its issuance record
/// and adds it to the revoked credentials of the registration. A revocation of all credentials raises the generation
/// of the registration. Each verifier that reads the current registration refuses the credentials of its target. The
/// registered key stays, so the issuer can issue again.
#[derive(Clone, Debug)]
pub struct Revocation<'a> {
    /// The identity of the operation. After an unknown outcome, look up this identity.
    pub operation: OperationId,
    /// The evidence of the principal that revokes, for example an operator. The policy must permit it
    /// [`Mode::Revoke`] on the [`resource`] of the workload.
    pub by: &'a Evidence,
    /// The credentials that the revocation ends.
    pub target: Target<'a>,
}

impl Revocation<'_> {
    /// The proposal of the revocation, and the plan of its commit. `registration` is the current registration record of
    /// the workload. The proposal reads the policy version of the permit and the version of `registration`, and it
    /// writes the registration with its new generation or its new revoked credential. Thus a racing issuance
    /// conflicts. A revocation of one credential also reads its issuance record and ends it. The journal of the store
    /// records the end of the earlier version of the registration, so a restore from an older snapshot ends the
    /// registration. Submit the proposal with the plan. A revocation releases no artifact: its accepted outcome is the
    /// revocation. Its deadline is the deadline of the checked scope.
    ///
    /// Cost class: [`Verify`](crate::limits::Class::Verify): the decode of the registered key. The call of `policy` is
    /// the cost of the application.
    ///
    /// # Errors
    ///
    /// [`Error::Record`] if `registration` is not the form of a registration, [`Error::Refusal`] if the policy
    /// refuses, [`Error::Target`] if the target credential is not a live credential of the workload from the issuer
    /// of the registration, [`Error::Revocations`] if the registration holds [`REVOKED_MAX`] revoked credentials that
    /// did not end, [`Error::Driver`] if the driver gives no value, and [`Error::Transition`] if the proposal refuses.
    pub fn proposal(
        self,
        registration: &Record,
        policy: &impl Policy,
        driver: &mut Driver,
        now: Reading,
        limits: Limits,
    ) -> Result<(Proposal, Plan), Error> {
        let mut revoked = Registration::from_record(&registration.data, limits)?;
        let workload = revoked.workload.clone();
        // The request names the issuer of the registration, so the same request under another issuer is another one.
        let asked = Value::Array(vec![
            registration.version.owner().to_cbor(),
            workload.to_cbor(),
            match self.target {
                Target::Credential(serial, _) => Value::Unsigned(serial.0),
                Target::All => Value::Null,
            },
        ]);
        let checked = authz::check(self.by, &Mode::Revoke.action(), &resource(&workload), policy, now)?;
        let value = driver.allocate_after(&registration.version)?;
        let audit = Audit {
            actor: self.by.subject().clone(),
            action: Mode::Revoke.action(),
            time: now,
        };
        let mut proposal = Proposal::new(self.operation, audit, &asked, limits)?;
        proposal.read(Dependency::Policy(checked.permit().version.clone()))?;
        proposal.until(checked.deadline());
        match self.target {
            Target::Credential(serial, record) => {
                // The issuance record names the issuer, the workload, the purpose, and the end of the credential.
                let issuer = registration.version.owner();
                let issued = credential::Issued::from_record(&record.data, limits).ok_or(Error::Target)?;
                let live = now.earliest().is_ok_and(|earliest| earliest < issued.expires);
                let exact = record.version == version(issuer.clone(), serial.0)
                    && issued.issuer == *issuer
                    && issued.subject == Principal::Workload(workload.clone())
                    && issued.purpose == purpose();
                (exact && live && !revoked.ended(serial)).ok_or(Error::Target)?;
                (revoked.revoked.len() < REVOKED_MAX).ok_or(Error::Revocations)?;
                let at = revoked.revoked.partition_point(|(other, _)| *other < serial);
                revoked.revoked.insert(at, (serial, issued.expires));
                let key = credential::record_key(serial);
                proposal.read(Dependency::Version(key.clone(), record.version.clone()))?;
                proposal.change(Change::End(key))?;
            }
            Target::All => {
                revoked.generation = Serial(value);
            }
        }
        revoked.rewrite(&mut proposal, registration, value, now)?;
        let plan = Plan {
            replaced: vec![Registration::store_key(&workload)],
            ..Plan::default()
        };
        Ok((proposal, plan))
    }
}

/// What a rotation of the issuer key does with the key that it replaces.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub enum Retire {
    /// The replaced key verifies the credentials that it signed until they end: the lesser of the rotation time plus
    /// `lifetime_max` and `not_after`. A routine rotation.
    AfterLifetime,
    /// The replaced key, and an earlier previous key, refuse at once at each verifier that reads the issuer record. For
    /// a key that an attacker can have.
    Now,
}

/// A rotation of the issuer key: a new key of the same algorithm signs each new credential.
#[derive(Clone, Debug)]
pub struct IssuerRotation<'a> {
    /// The identity of the operation. After an unknown outcome, look up this identity.
    pub operation: OperationId,
    /// The evidence of the principal that rotates, for example an operator. The policy must permit it
    /// [`Mode::RotateIssuer`] on the [`issuer_resource`] of the issuer.
    pub by: &'a Evidence,
    /// The new key. Custody holds its secret key.
    pub key: PublicKey<'a>,
    /// What happens to the key that the new key replaces.
    pub retire: Retire,
}

impl IssuerRotation<'_> {
    /// The proposal of the rotation, and the plan of its commit. `issuer` is the current issuer record. The proposal
    /// reads the policy version of the permit and the version of `issuer`, and it writes the issuer record with the
    /// new key. The journal of the store records the end of the earlier version, so a restore from an older snapshot
    /// ends the issuer record. Submit the proposal with the plan. Its deadline is the deadline of the checked scope.
    ///
    /// Cost class: [`Verify`](crate::limits::Class::Verify): the check of the new key. The call of `policy` is the
    /// cost of the application.
    ///
    /// # Errors
    ///
    /// [`Error::Record`] if `issuer` is not the form of an issuer, [`Error::Key`] if the new key refuses as a trusted
    /// key, [`Error::Algorithm`] if it has another algorithm than the current key, and [`Error::Unchanged`] if it is
    /// the current or the previous key. [`Error::Overlap`] for
    /// [`Retire::AfterLifetime`] while the previous key still verifies. [`Error::Refusal`] if the policy refuses,
    /// [`Error::Driver`] if the driver gives no value, and [`Error::Transition`] if the proposal refuses.
    pub fn proposal(
        self,
        issuer: &Record,
        policy: &impl Policy,
        driver: &mut Driver,
        now: Reading,
        limits: Limits,
    ) -> Result<(Proposal, Plan), Error> {
        let record = issuer;
        let issuer = Issuer::from_record(&record.data, limits)?;
        let key = RecordKey::new(self.key)?;
        (key.trusted.algorithm() == issuer.current.trusted.algorithm()).ok_or(Error::Algorithm)?;
        // The new key must not be a key that the rotation retires or that an earlier rotation retired.
        let retired = [
            Some(&issuer.current),
            issuer.previous.as_ref().map(|(previous, _)| previous),
        ];
        (!retired
            .into_iter()
            .flatten()
            .any(|old| old.trusted.kid() == key.trusted.kid()))
        .ok_or(Error::Unchanged)?;
        let now_whole = Duration::from_secs(now.estimate().as_secs());
        let previous = match self.retire {
            Retire::AfterLifetime => {
                if let Some((_, until)) = issuer.previous
                    && now_whole < until
                {
                    return Err(Error::Overlap { until });
                }
                let until = now_whole
                    .saturating_add(issuer.ceiling.lifetime_max)
                    .min(issuer.ceiling.not_after);
                Some((issuer.current.clone(), until))
            }
            Retire::Now => None,
        };
        let asked = Value::Array(vec![
            issuer.authority.to_cbor(),
            Value::Bytes(key.trusted.kid()),
            Value::Unsigned(match self.retire {
                Retire::AfterLifetime => 0,
                Retire::Now => 1,
            }),
        ]);
        let resource = issuer_resource(&issuer.authority);
        let checked = authz::check(self.by, &Mode::RotateIssuer.action(), &resource, policy, now)?;
        let audit = Audit {
            actor: self.by.subject().clone(),
            action: Mode::RotateIssuer.action(),
            time: now,
        };
        let mut proposal = Proposal::new(self.operation, audit, &asked, limits)?;
        let rotated = Issuer {
            current: key,
            previous,
            ..issuer
        };
        let store_key = Issuer::store_key(&rotated.authority);
        proposal.read(Dependency::Policy(checked.permit().version.clone()))?;
        proposal.until(checked.deadline());
        proposal.read(Dependency::Version(store_key.clone(), record.version.clone()))?;
        proposal.change(Change::Write {
            key: store_key.clone(),
            version: later(&record.version, driver.allocate_after(&record.version)?)?,
            end: None,
            data: rotated.to_record(),
        })?;
        let plan = Plan {
            replaced: vec![store_key],
            ..Plan::default()
        };
        Ok((proposal, plan))
    }
}

/// The version of `owner` with the 8 bytes of `value`, the most significant byte first.
fn version(owner: Id<Authority>, value: u64) -> AuthorityVersion {
    AuthorityVersion::new(owner, &value.to_be_bytes()).expect("an 8-byte coordinate is valid")
}

/// The version of a write by rsauthnz of a record that a proposal read at `read`. It is the owner of `read` and
/// `value`, a new value of a counter of the driver. A new value is above each earlier value, also after a restore.
/// Thus the version is later than each version that rsauthnz wrote.
fn later(read: &AuthorityVersion, value: u64) -> Result<AuthorityVersion, Error> {
    let later = version(read.owner().clone(), value);
    // A version that rsauthnz did not write can be later. The journal fact of the write would then not hold.
    (read.compare(&later) == Ok(Ordering::Less)).ok_or(Error::Record)?;
    Ok(later)
}

/// The key of a record of `kind`: the SHA-256 digest of `form`. The digest keeps the key short, because an
/// identifier can be longer than a key.
fn digest_key(kind: Kind, form: &Value<'_>) -> transition::Key {
    let form = cbor::encode(form, Limits::FORM).expect("the form of an identifier has no map and no simple value");
    kind.key(&crypto::sha256(&form)).expect("a key of 33 bytes is valid")
}

/// The cause of a refused request or release. For a refused request, the recovery is to refuse it, unless the variant
/// names another recovery.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Error {
    /// The key refuses as a trusted key.
    Key(cose::Error),
    /// An issuer has more than [`AUDIENCES_MAX`] audiences.
    Audiences,
    /// A record is not the record form of its kind, or rsauthnz did not write its version.
    Record,
    /// The audience is not an audience of the issuer.
    Audience,
    /// The lifetime is past the `lifetime_max` of the issuer, or the end is past its `not_after`. Ask for a shorter
    /// lifetime, or ask the issuer for a new ceiling.
    Ceiling,
    /// The current credential of a renewal names another workload or another `cnf` key than the registration. Or the
    /// credential of a check names another workload.
    Possession,
    /// The serial of the credential is below the generation of the registration, or a revocation of the credential
    /// ended it. An operator issues a new credential.
    Revoked,
    /// The store has no registration of the workload. For example, a restore from a snapshot older than a rotation, a
    /// recovery, or a revocation ends the registration. An operator registers the workload again.
    Unregistered,
    /// The target of a revocation is not a live credential of the workload from the issuer of the registration: its
    /// issuance record names another issuer, workload, or purpose, or the credential ended, or a revocation ended it.
    Target,
    /// The registration holds [`REVOKED_MAX`] revoked credentials that did not end. Revoke all credentials
    /// ([`Target::All`]), or wait for one of them to end.
    Revocations,
    /// The new key is the key that the operation retires: the registered key of a rotation or a recovery, or the
    /// current or the previous key of an issuer rotation. Give a new key.
    Unchanged,
    /// The registration names another issuer than the issuer of the request.
    Issuer,
    /// The new issuer key has another algorithm than the current key. A new profile needs a new issuer, with its own
    /// authority.
    Algorithm,
    /// The previous issuer key still verifies credentials until `until`, as the time since the Unix epoch. Rotate at
    /// `until` or later, or rotate with [`Retire::Now`].
    Overlap {
        /// The time from which no credential of the previous key is valid.
        until: Duration,
    },
    /// The credential format refused: the draft, the current credential, a proof, or the signature of custody.
    Credential(credential::Error),
    /// The policy refused.
    Refusal(Refusal),
    /// The commit driver gave no value. Its error gives the recovery.
    Driver(driver::Error),
    /// The proposal refused. Its error gives the recovery.
    Transition(transition::Error),
}

impl fmt::Display for Error {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Key(error) => write!(f, "the key refuses as a trusted key: {error}"),
            Self::Audiences => write!(f, "the issuer has more than {AUDIENCES_MAX} audiences"),
            Self::Record => f.write_str("the record is not the record form of its kind"),
            Self::Audience => f.write_str("the audience is not an audience of the issuer"),
            Self::Ceiling => f.write_str("the credential is past the ceiling of the issuer"),
            Self::Possession => {
                f.write_str("the current credential names another workload or key than the registration")
            }
            Self::Revoked => f.write_str("the credential is of an earlier generation of the workload"),
            Self::Unregistered => f.write_str("the store has no registration of the workload"),
            Self::Target => f.write_str("the revocation names no live credential of the workload from its issuer"),
            Self::Revocations => write!(
                f,
                "the registration holds {REVOKED_MAX} revoked credentials that did not end"
            ),
            Self::Unchanged => f.write_str("the new key is the key that the operation retires"),
            Self::Issuer => f.write_str("the registration names another issuer"),
            Self::Algorithm => f.write_str("the new issuer key has another algorithm than the current key"),
            Self::Overlap { until } => write!(
                f,
                "the previous issuer key verifies credentials until {} s since the Unix epoch",
                until.as_secs()
            ),
            Self::Credential(error) => write!(f, "the credential format refused: {error}"),
            Self::Refusal(refusal) => write!(f, "the policy refused: {refusal}"),
            Self::Driver(error) => write!(f, "the commit driver gave no value: {error}"),
            Self::Transition(error) => write!(f, "the transition refused: {error}"),
        }
    }
}

impl core::error::Error for Error {}

impl From<credential::Error> for Error {
    fn from(error: credential::Error) -> Self {
        Self::Credential(error)
    }
}

impl From<Refusal> for Error {
    fn from(error: Refusal) -> Self {
        Self::Refusal(error)
    }
}

impl From<driver::Error> for Error {
    fn from(error: driver::Error) -> Self {
        Self::Driver(error)
    }
}

impl From<transition::Error> for Error {
    fn from(error: transition::Error) -> Self {
        Self::Transition(error)
    }
}
