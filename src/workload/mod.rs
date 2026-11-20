//! Workload credentials: short, audience-bound credentials that an explicit issuer gives to a registered workload,
//! with the registered proof key of the workload as their `cnf` key.
//!
//! Two records of the store hold the authority. An [`Issuer`] record holds the authority that issues, its public key,
//! its audiences, and its [`Ceiling`]. The algorithm of the key is the profile that each of its audiences declares. A
//! [`Registration`] record holds a workload and its registered proof key. The application writes both records with
//! its own transitions.
//!
//! An issuance has two steps, as each issuance of [`credential`] has. [`Pending::new`] reads the two records, checks
//! the policy and the ceiling, and makes the draft and the [`Proposal`]. Custody signs [`Pending::to_be_signed`]
//! outside the core. [`Pending::finish`] verifies the signature and puts the credential into the proposal, where it
//! stays private. The application submits the proposal to the commit driver. Only [`Awaiting::release`] of the
//! accepted commit of that proposal gives the [`Credential`]. Thus the store records the credential and its audit
//! before the workload gets it. A lost response gives no credential, and the core does not try the operation again.
//!
//! The first issuance comes from a principal that the policy permits [`Mode::Issue`], such as an operator. A
//! renewal comes from the workload itself, with its current credential and a proof of possession of its registered
//! key. The policy must permit it [`Mode::Renew`]. Each renewal gives a new serial with the same `cnf` key, and the
//! earlier credential stays valid until it ends.
//!
//! A service verifies a workload credential locally, with the [`credential::Profile`] of [`Issuer::profile`]. It looks
//! up no issuer for each request. A verifier reads no revocation state, so a revoked credential stays valid there until
//! it ends. Thus the lifetime is the longest time that a revocation needs to reach a verifier.
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
//! use rsauthnz::workload::{By, Ceiling, Issuer, Pending, Registration, Request};
//! use rsauthnz_conformance::memory::{Memory, Schedule};
//! use rsauthnz_conformance::suite::execute;
//! use rscrypto::auth::MlDsa65Ed25519;
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
//! /// Commits `proposal`, and gives its outcome.
//! fn commit(driver: &mut Driver, memory: &mut Memory, proposal: Proposal) -> Result<Outcome, Failure> {
//!     let ticket = driver.submit(proposal, Plan::default())?;
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
//! #     let expires = now.estimate() + Duration::from_secs(600);
//! #     let human = Id::new("acme", "operator-1")?;
//! #     let subject = Subject::Human(human.clone());
//! #     let claims = Claims::new(Id::new("acme", "issuer")?, console.clone(), subject, purpose.clone(), Serial(0), expires);
//! #     let draft = Draft::credential(issuer_key, &claims, Some(PublicKey::MlDsa65Ed25519(&public)), now)?;
//! #     let signature = issuer_secret.sign_deterministic(&draft.to_be_signed(), &[])?;
//! #     let audit = Audit { actor: Principal::Human(human), action: Id::new("acme", "operator.sign-in")?, time: now };
//! #     let mut proposal = Proposal::new(OperationId::new(b"sign-in-1")?, audit, &Value::Null, Limits::default())?;
//! #     proposal.prepare(draft.finish(signature.as_bytes(), &mut SignatureBudget::new(&Limits::default()))?);
//! #     let Outcome::Accepted(receipt) = commit(driver, memory, proposal)? else {
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
//! let mut driver = Driver::new(store::Profile::new(memory.declaration())?, Limits::default())?;
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
//! let registration = Registration::new(runner.clone(), PublicKey::MlDsa65Ed25519(&runner_public))?;
//! let audit = Audit { actor: operator.subject().clone(), action: Id::new("acme", "workload.register")?, time: now };
//! let mut setup = Proposal::new(OperationId::new(b"register-1")?, audit, &Value::Null, Limits::default())?;
//! for (key, data) in [
//!     (store::policy_key(&authority), Box::from(*b"policy 1")),
//!     (Issuer::store_key(&authority), issuer.to_record()),
//!     (Registration::store_key(&runner), registration.to_record()),
//! ] {
//!     setup.read(Dependency::Absent(key.clone()))?;
//!     setup.change(Change::Write { key, version: AuthorityVersion::new(authority.clone(), &[1])?, end: None, data })?;
//! }
//! assert!(matches!(commit(&mut driver, &mut memory, setup)?, Outcome::Accepted(_)));
//!
//! // 2. An operator asks for the first credential. `policy` permits it `Mode::Issue`, and `operator` is its evidence.
//! let issuer_record = ready(memory.read(&Issuer::store_key(&authority)))?.ok_or("no issuer")?;
//! let registration_record = ready(memory.read(&Registration::store_key(&runner)))?.ok_or("no registration")?;
//! let operation = OperationId::new(b"issue-1")?;
//! let request = Request { operation, by: By::Issue(&operator), audience: &build, lifetime: None };
//! let (issuer_record, registration_record) = (&issuer_record, &registration_record);
//! let pending = Pending::new(request, issuer_record, registration_record, &policy, &mut driver, now, Limits::default())?;
//!
//! // 3. Custody signs, and `finish` puts the credential into the proposal. Only the accepted commit releases it.
//! let budget = || SignatureBudget::new(&Limits::default());
//! let signature = issuer_secret.sign_deterministic(&pending.to_be_signed(), &[])?;
//! let (proposal, awaiting) = pending.finish(signature.as_bytes(), &mut budget())?;
//! let credential = awaiting.release(commit(&mut driver, &mut memory, proposal)?)?;
//!
//! // 4. The audience verifies the credential locally and checks a proof by the registered key.
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
//!
//! // 5. At half its lifetime, the workload renews with its credential and a proof over the challenge of the issuer.
//! let later = Reading::new(credential.renew_at(), Some(Duration::from_secs(1)), ReadingSource::Caller);
//! let proof = prove(b"challenge-2", later)?;
//! let by = By::Renew { credential: credential.as_bytes(), proof: &proof, challenge: b"challenge-2" };
//! let request = Request { operation: OperationId::new(b"renew-1")?, by, audience: &build, lifetime: None };
//! let pending =
//!     Pending::new(request, issuer_record, registration_record, &policy, &mut driver, later, Limits::default())?;
//! let signature = issuer_secret.sign_deterministic(&pending.to_be_signed(), &[])?;
//! let (proposal, awaiting) = pending.finish(signature.as_bytes(), &mut budget())?;
//! let renewed = awaiting.release(commit(&mut driver, &mut memory, proposal)?)?;
//! assert!(renewed.serial() > credential.serial());
//! # Ok::<(), Failure>(())
//! ```

use alloc::boxed::Box;
use alloc::vec;
use alloc::vec::Vec;
use core::fmt;
use core::time::Duration;

use crate::authz::{self, Policy, Refusal};
use crate::cbor::{self, Value};
use crate::cose::{self, Key, PublicKey, TrustedKey};
use crate::credential::{self, Claims, Draft, Serial, Subject};
use crate::crypto;
use crate::evidence::Evidence;
use crate::id::{Action, Audience, Authority, AuthorityVersion, Id, Purpose, Resource, Workload};
use crate::limits::{Limits, SignatureBudget};
use crate::store::driver::{self, Driver};
use crate::store::{Kind, Record};
use crate::time::Reading;
use crate::transition::{self, Audit, Change, Dependency, Operation, OperationId, Outcome, Proposal};

/// The lifetime of a credential when the request names none, unless the ceiling of the issuer is shorter. Renew a
/// credential at half its lifetime ([`Credential::renew_at`]).
pub const LIFETIME_DEFAULT: Duration = Duration::from_secs(3_600);

/// The most audiences of one issuer. A record with this many audiences of the longest identifiers is within the
/// default [`Limits`].
pub const AUDIENCES_MAX: usize = 16;

/// The first item of the CBOR form of an issuer record. Its number changes with the form.
const ISSUER_FORM: &str = "rsauthnz.workload.issuer.1";

/// The first item of the CBOR form of a registration record. Its number changes with the form.
const REGISTRATION_FORM: &str = "rsauthnz.workload.registration.1";

/// The first item of the CBOR form of a credential record. Its number changes with the form.
const CREDENTIAL_FORM: &str = "rsauthnz.workload.credential.1";

/// The purpose of each workload credential: `rsauthnz:workload`. A workload credential never verifies for another
/// purpose, such as an agent credential of the same issuer key.
///
/// Cost class: [`Parse`](crate::limits::Class::Parse).
#[must_use]
pub fn purpose() -> Id<Purpose> {
    Id::new("rsauthnz", "workload").expect("the purpose is a valid identifier")
}

/// The resource of the workload `workload` in the policy: an identifier with its namespace and its value. The policy
/// permits an issuance and a renewal on this resource.
///
/// Cost class: [`Parse`](crate::limits::Class::Parse).
#[must_use]
pub fn resource(workload: &Id<Workload>) -> Id<Resource> {
    Id::new(workload.namespace(), workload.value()).expect("a resource has the rules of a workload identifier")
}

/// The key of the record of the workload credential with the serial `serial`: [`Kind::Credential`] with the 8 bytes of
/// the serial, the most significant byte first.
///
/// Cost class: [`Parse`](crate::limits::Class::Parse).
#[must_use]
pub fn credential_key(serial: Serial) -> transition::Key {
    Kind::Credential
        .key(&serial.0.to_be_bytes())
        .expect("a key of 9 bytes is valid")
}

/// The kind of an operation, and its action in the policy.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub enum Mode {
    /// A first issuance: `rsauthnz:workload.issue`.
    Issue,
    /// A renewal by the workload: `rsauthnz:workload.renew`.
    Renew,
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

/// An issuer of workload credentials: the authority that issues, its public key, its audiences, and its ceiling.
/// The algorithm of the key is the profile that each audience declares. The store keeps it as a [`Kind::Issuer`]
/// record.
#[derive(Clone, PartialEq, Eq)]
pub struct Issuer {
    authority: Id<Authority>,
    /// The encoded `COSE_Key`, with its `alg`.
    key: Box<[u8]>,
    trusted: TrustedKey,
    /// Sorted, with no two equal.
    audiences: Vec<Id<Audience>>,
    ceiling: Ceiling,
}

impl Issuer {
    /// The issuer `authority` with the public key `key`, the audiences `audiences`, and the ceiling `ceiling`. The
    /// issuer drops a second equal audience, and it keeps the whole seconds of the ceiling.
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
        mut audiences: Vec<Id<Audience>>,
        ceiling: Ceiling,
    ) -> Result<Self, Error> {
        audiences.sort_unstable();
        audiences.dedup();
        (audiences.len() <= AUDIENCES_MAX).ok_or(Error::Audiences)?;
        let (key, trusted) = encode_key(key)?;
        let whole = |time: Duration| Duration::from_secs(time.as_secs());
        Ok(Self {
            authority,
            key,
            trusted,
            audiences,
            ceiling: Ceiling {
                lifetime_max: whole(ceiling.lifetime_max),
                not_after: whole(ceiling.not_after),
            },
        })
    }

    /// Reads the record form `data` of an issuer, which [`Self::to_record`] gives. The decode uses `limits`.
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
            Value::Bytes(key),
            Value::Array(audiences),
            Value::Unsigned(lifetime_max),
            Value::Unsigned(not_after),
        ] = items.as_slice()
        else {
            return Err(Error::Record);
        };
        let audiences = audiences
            .iter()
            .map(|audience| Id::from_cbor(audience).map_err(|_| Error::Record))
            .collect::<Result<_, _>>()?;
        let ceiling = Ceiling {
            lifetime_max: Duration::from_secs(*lifetime_max),
            not_after: Duration::from_secs(*not_after),
        };
        let key = Key::decode(key, limits).map_err(|_| Error::Record)?;
        let authority = Id::from_cbor(authority).map_err(|_| Error::Record)?;
        Self::new(authority, key.public, audiences, ceiling).map_err(|_| Error::Record)
    }

    /// The record form, which the application writes at [`Self::store_key`] of the authority: the canonical CBOR array
    /// `["rsauthnz.workload.issuer.1", authority, key, audiences, lifetime_max, not_after]`. The key is the encoded
    /// `COSE_Key`, and the times are whole seconds.
    #[must_use]
    pub fn to_record(&self) -> Box<[u8]> {
        let audiences = self.audiences.iter().map(Id::to_cbor).collect();
        let form = Value::Array(vec![
            Value::Text(ISSUER_FORM),
            self.authority.to_cbor(),
            Value::Bytes(&self.key),
            Value::Array(audiences),
            Value::Unsigned(self.ceiling.lifetime_max.as_secs()),
            Value::Unsigned(self.ceiling.not_after.as_secs()),
        ]);
        cbor::encode(&form)
            .expect("the form has no map and no simple value")
            .into_boxed_slice()
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

    /// The verification profile of the workload credentials of this issuer for `audience`. The verification of the
    /// profile is local: it takes the credential, the time, and a budget, and it looks up nothing.
    ///
    /// Cost class: [`Parse`](crate::limits::Class::Parse).
    ///
    /// # Errors
    ///
    /// [`Error::Audience`] if `audience` is not an audience of the issuer, and [`Error::Credential`] if the format
    /// refuses the key of the issuer.
    pub fn profile(&self, audience: &Id<Audience>, limits: Limits) -> Result<credential::Profile, Error> {
        self.audiences.binary_search(audience).map_err(|_| Error::Audience)?;
        Ok(credential::Profile::new(
            self.trusted.clone(),
            self.authority.clone(),
            audience.clone(),
            purpose(),
            limits,
        )?)
    }
}

impl fmt::Debug for Issuer {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("Issuer")
            .field("authority", &self.authority)
            .field("key", &self.trusted)
            .field("audiences", &self.audiences)
            .field("ceiling", &self.ceiling)
            .finish()
    }
}

/// The registration of a workload: its identifier and its registered proof key. Each credential of the workload has
/// this key as its `cnf` key. The store keeps it as a [`Kind::Workload`] record.
#[derive(Clone, PartialEq, Eq)]
pub struct Registration {
    workload: Id<Workload>,
    /// The encoded `COSE_Key`, with its `alg`.
    key: Box<[u8]>,
    trusted: TrustedKey,
}

impl Registration {
    /// The registration of `workload` with the proof key `key`.
    ///
    /// Cost class: [`Verify`](crate::limits::Class::Verify). The key checks as [`TrustedKey::new`] checks it.
    ///
    /// # Errors
    ///
    /// [`Error::Key`] if `key` refuses as a trusted key.
    pub fn new(workload: Id<Workload>, key: PublicKey<'_>) -> Result<Self, Error> {
        let (key, trusted) = encode_key(key)?;
        Ok(Self { workload, key, trusted })
    }

    /// Reads the record form `data` of a registration, which [`Self::to_record`] gives. The decode uses `limits`.
    ///
    /// Cost class: [`Verify`](crate::limits::Class::Verify).
    ///
    /// # Errors
    ///
    /// [`Error::Record`] if `data` is not the record form of a registration.
    pub fn from_record(data: &[u8], limits: Limits) -> Result<Self, Error> {
        let value = cbor::decode(data, limits).map_err(|_| Error::Record)?;
        let Value::Array(items) = &value else {
            return Err(Error::Record);
        };
        let [Value::Text(REGISTRATION_FORM), workload, Value::Bytes(key)] = items.as_slice() else {
            return Err(Error::Record);
        };
        let key = Key::decode(key, limits).map_err(|_| Error::Record)?;
        let workload = Id::from_cbor(workload).map_err(|_| Error::Record)?;
        Self::new(workload, key.public).map_err(|_| Error::Record)
    }

    /// The record form, which the application writes at [`Self::store_key`] of the workload: the canonical CBOR array
    /// `["rsauthnz.workload.registration.1", workload, key]`. The key is the encoded `COSE_Key`.
    #[must_use]
    pub fn to_record(&self) -> Box<[u8]> {
        let form = Value::Array(vec![
            Value::Text(REGISTRATION_FORM),
            self.workload.to_cbor(),
            Value::Bytes(&self.key),
        ]);
        cbor::encode(&form)
            .expect("the form has no map and no simple value")
            .into_boxed_slice()
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
}

impl fmt::Debug for Registration {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("Registration")
            .field("workload", &self.workload)
            .field("key", &self.trusted)
            .finish()
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
}

/// The principal that asks for a credential, with its proof.
#[derive(Clone, Copy)]
pub enum By<'a> {
    /// A first issuance by the principal of the evidence, for example an operator. The policy must permit it
    /// [`Mode::Issue`] on the [`resource`] of the workload.
    Issue(&'a Evidence),
    /// A renewal by the workload. The policy must permit the workload [`Mode::Renew`] on its [`resource`].
    Renew {
        /// The current credential of the workload from the same issuer, for the audience of the request.
        credential: &'a [u8],
        /// The proof of possession of the `cnf` key of `credential`, over `challenge` ([`credential::ProofDraft`]).
        proof: &'a [u8],
        /// The challenge of the issuer for the proof. Issue each challenge for one proof.
        challenge: &'a [u8],
    },
}

impl By<'_> {
    /// The mode of the request.
    #[must_use]
    pub const fn mode(&self) -> Mode {
        match self {
            Self::Issue(_) => Mode::Issue,
            Self::Renew { .. } => Mode::Renew,
        }
    }
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

/// An issuance that custody did not sign yet: the draft of the credential and the proposal of its transition.
#[derive(Debug)]
pub struct Pending {
    draft: Draft,
    proposal: Proposal,
    awaiting: Awaiting,
}

impl Pending {
    /// The issuance of `request`. `issuer` and `registration` are the current records of the issuer and of the
    /// workload, as the store holds them. `driver` gives the serial of the credential, so that a restore never gives
    /// one serial twice. The decode, the proof check, and the proposal use `limits`.
    ///
    /// The issuance checks the audience and the ceiling of the issuer. For a renewal, it verifies the current
    /// credential with [`Issuer::profile`], checks that it names the registered workload and the registered key, and
    /// checks the proof of possession. Then [`authz::check`] checks the evidence for the action of the mode on the
    /// [`resource`] of the workload under `policy`. The proposal reads the policy version of the permit, the issuer
    /// record and the registration record at their versions, and the absence of the credential record
    /// ([`credential_key`]). It writes the credential record, which ends when the credential ends.
    ///
    /// Cost class: [`Verify`](crate::limits::Class::Verify): a renewal verifies two signatures, of the current
    /// credential and of its proof. The call of `policy` is the cost of the application.
    ///
    /// # Errors
    ///
    /// [`Error::Record`] if a record is not its form, and [`Error::Audience`] for an audience that the issuer does not
    /// have. [`Error::Ceiling`] for a lifetime past `lifetime_max`, or an end past `not_after`. [`Error::Credential`]
    /// if the current credential or the proof refuses, or if the registered key has another class than the key of the
    /// issuer. [`Error::Possession`] if the current credential names another workload or another `cnf` key than the
    /// registration. [`Error::Refusal`] if the policy refuses, [`Error::Driver`] if the driver gives no serial, and
    /// [`Error::Transition`] if the proposal refuses.
    pub fn new(
        request: Request<'_>,
        issuer: &Record,
        registration: &Record,
        policy: &impl Policy,
        driver: &mut Driver,
        now: Reading,
        limits: Limits,
    ) -> Result<Self, Error> {
        let Request {
            operation,
            by,
            audience,
            lifetime,
        } = request;
        let (issuer_record, registration_record) = (issuer, registration);
        let issuer = Issuer::from_record(&issuer_record.data, limits)?;
        let registration = Registration::from_record(&registration_record.data, limits)?;
        let profile = issuer.profile(audience, limits)?;
        let ceiling = issuer.ceiling;
        // The request binding holds what the requester asks, so a new proposal of the same request after a lost
        // response binds the same request. The serial and the times are not part of it.
        let asked = Value::Array(vec![
            registration.workload.to_cbor(),
            audience.to_cbor(),
            lifetime.map_or(Value::Null, |lifetime| Value::Unsigned(lifetime.as_secs())),
        ]);
        let lifetime = lifetime.unwrap_or_else(|| LIFETIME_DEFAULT.min(ceiling.lifetime_max));
        // The draft keeps the whole seconds of the times, so the check uses them too.
        let issued = Duration::from_secs(now.estimate().as_secs());
        let expires = issued
            .checked_add(lifetime)
            .map(|expires| Duration::from_secs(expires.as_secs()))
            .filter(|expires| lifetime <= ceiling.lifetime_max && *expires <= ceiling.not_after)
            .ok_or(Error::Ceiling)?;
        let evidence = match by {
            By::Issue(evidence) => evidence.clone(),
            By::Renew {
                credential,
                proof,
                challenge,
            } => {
                let verified = profile.verify(credential, now, &mut SignatureBudget::new(&limits))?;
                let subject = &verified.claims().subject;
                let named = matches!(subject, Subject::Workload(workload) if *workload == registration.workload);
                (named && verified.confirmation() == Some(&registration.trusted)).ok_or(Error::Possession)?;
                verified.possession(proof, challenge, now, &mut SignatureBudget::new(&limits))?
            }
        };
        let mode = by.mode();
        let permit = authz::check(
            &evidence,
            &mode.action(),
            &resource(&registration.workload),
            policy,
            now,
        )?
        .permit()
        .version
        .clone();
        let serial = Serial(driver.allocate(Kind::Credential)?);
        let claims = Claims::new(
            issuer.authority.clone(),
            audience.clone(),
            Subject::Workload(registration.workload.clone()),
            purpose(),
            serial,
            expires,
        );
        let cnf = Key::decode(&registration.key, limits).map_err(|_| Error::Record)?;
        let draft = Draft::credential(&issuer.trusted, &claims, Some(cnf.public), now)?;
        let audit = Audit {
            actor: evidence.subject().clone(),
            action: mode.action(),
            time: now,
        };
        let mut proposal = Proposal::new(operation, audit, &asked, limits)?;
        let key = credential_key(serial);
        proposal.read(Dependency::Policy(permit))?;
        proposal.read(Dependency::Version(
            Issuer::store_key(&issuer.authority),
            issuer_record.version.clone(),
        ))?;
        proposal.read(Dependency::Version(
            Registration::store_key(&registration.workload),
            registration_record.version.clone(),
        ))?;
        proposal.read(Dependency::Absent(key.clone()))?;
        let record = cbor::encode(&Value::Array(vec![
            Value::Text(CREDENTIAL_FORM),
            issuer.authority.to_cbor(),
            registration.workload.to_cbor(),
            audience.to_cbor(),
            Value::Unsigned(expires.as_secs()),
        ]))
        .expect("the form has no map and no simple value");
        proposal.change(Change::Write {
            key,
            version: AuthorityVersion::new(issuer.authority, &serial.0.to_be_bytes())
                .expect("an 8-byte coordinate is valid"),
            end: Some(expires),
            data: record.into_boxed_slice(),
        })?;
        let awaiting = Awaiting {
            operation: proposal.operation().id.clone(),
            serial,
            issued,
            expires,
        };
        Ok(Self {
            draft,
            proposal,
            awaiting,
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
    /// puts the credential into the proposal. Submit the proposal to the commit driver with an empty
    /// [`Plan`](driver::Plan), and give the outcome of its commit to [`Awaiting::release`]. The check charges `budget`,
    /// the budget of the credential.
    ///
    /// Cost class: [`Verify`](crate::limits::Class::Verify).
    ///
    /// # Errors
    ///
    /// [`Error::Credential`] if the signature does not verify with the key of the issuer, or if the check costs more
    /// than `budget` has.
    pub fn finish(self, signature: &[u8], budget: &mut SignatureBudget) -> Result<(Proposal, Awaiting), Error> {
        let Self {
            draft,
            mut proposal,
            awaiting,
        } = self;
        proposal.prepare(draft.finish(signature, budget)?);
        Ok((proposal, awaiting))
    }
}

/// An issuance whose proposal waits for its commit. It holds no credential.
#[derive(Debug)]
pub struct Awaiting {
    operation: OperationId,
    serial: Serial,
    issued: Duration,
    expires: Duration,
}

impl Awaiting {
    /// The serial of the credential. The commit writes the credential record of this serial ([`credential_key`]).
    #[must_use]
    pub const fn serial(&self) -> Serial {
        self.serial
    }

    /// The credential that the accepted commit of the proposal of this issuance releases. Each other outcome gives no
    /// credential.
    ///
    /// Cost class: [`Parse`](crate::limits::Class::Parse).
    ///
    /// # Errors
    ///
    /// [`Error::Unknown`] if the commit can have occurred, [`Error::Conflict`] if a dependency changed first, and
    /// [`Error::Transition`] if the commit refused. [`Error::Committed`] if an earlier submission of the operation
    /// committed, so that this one releases nothing. [`Error::Operation`] for the outcome of another operation.
    pub fn release(self, outcome: Outcome) -> Result<Credential, Error> {
        match outcome {
            Outcome::Accepted(receipt) if *receipt.operation() == self.operation => Ok(Credential {
                bytes: receipt.artifact().ok_or(Error::Committed)?.into(),
                serial: self.serial,
                issued: self.issued,
                expires: self.expires,
            }),
            Outcome::Accepted(_) => Err(Error::Operation),
            Outcome::Conflict => Err(Error::Conflict),
            Outcome::Refused(error) => Err(Error::Transition(error)),
            Outcome::Unknown(operation) => Err(Error::Unknown(operation)),
        }
    }
}

/// A workload credential that a commit released: its encoded bytes, its serial, and its validity interval.
#[derive(Clone, PartialEq, Eq)]
pub struct Credential {
    bytes: Box<[u8]>,
    serial: Serial,
    issued: Duration,
    expires: Duration,
}

impl Credential {
    /// The encoded credential.
    #[must_use]
    pub fn as_bytes(&self) -> &[u8] {
        &self.bytes
    }

    /// The serial.
    #[must_use]
    pub const fn serial(&self) -> Serial {
        self.serial
    }

    /// The end of the credential, as the time since the Unix epoch. The credential is not valid at this time and
    /// after it.
    #[must_use]
    pub const fn expires(&self) -> Duration {
        self.expires
    }

    /// The time to renew the credential: half its lifetime after its issue time, as the time since the Unix epoch.
    #[must_use]
    pub fn renew_at(&self) -> Duration {
        self.issued.saturating_add(self.expires.saturating_sub(self.issued) / 2)
    }
}

impl fmt::Debug for Credential {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("Credential")
            .field("len", &self.bytes.len())
            .field("serial", &self.serial)
            .field("issued", &self.issued)
            .field("expires", &self.expires)
            .finish()
    }
}

/// The encoded `COSE_Key` of `key`, with its `alg`, and its trusted key.
fn encode_key(key: PublicKey<'_>) -> Result<(Box<[u8]>, TrustedKey), Error> {
    let trusted = TrustedKey::new(
        key.algorithm(),
        &Key {
            kid: None,
            alg: None,
            public: key.clone(),
        },
    )
    .map_err(Error::Key)?;
    let encoded = cbor::encode(&key.to_cbor()).expect("a COSE_Key has distinct keys and no simple value");
    Ok((encoded.into_boxed_slice(), trusted))
}

/// The key of a record of `kind`: the SHA-256 digest of `form`. The digest keeps the key short, because an
/// identifier can be longer than a key.
fn digest_key(kind: Kind, form: &Value<'_>) -> transition::Key {
    let form = cbor::encode(form).expect("the form of an identifier has no map and no simple value");
    kind.key(&crypto::sha256(&form)).expect("a key of 33 bytes is valid")
}

/// The cause of a refused issuance or release. For a refused request, the recovery is to refuse it, unless the
/// variant names another recovery.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Error {
    /// The key refuses as a trusted key.
    Key(cose::Error),
    /// An issuer has more than [`AUDIENCES_MAX`] audiences.
    Audiences,
    /// A record is not the record form of its kind.
    Record,
    /// The audience is not an audience of the issuer.
    Audience,
    /// The lifetime is past the `lifetime_max` of the issuer, or the end is past its `not_after`. Ask for a shorter
    /// lifetime, or ask the issuer for a new ceiling.
    Ceiling,
    /// The current credential of a renewal names another workload or another `cnf` key than the registration.
    Possession,
    /// The credential format refused: the draft, the current credential, its proof, or the signature of custody.
    Credential(credential::Error),
    /// The policy refused.
    Refusal(Refusal),
    /// The commit driver gave no serial. Its error gives the recovery.
    Driver(driver::Error),
    /// The proposal or the commit refused. Its error gives the recovery.
    Transition(transition::Error),
    /// A dependency changed before the commit, so nothing committed. Read the records again, and ask again as a new
    /// operation.
    Conflict,
    /// The commit can have occurred: its response was lost. Look up the operation, and never ask again as a new
    /// operation before the lookup answers. A credential whose response was lost is never released.
    Unknown(Operation),
    /// An earlier submission of the operation committed, so this one releases nothing. Ask for a renewal as a new
    /// operation.
    Committed,
    /// The outcome is of another operation.
    Operation,
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
            Self::Credential(error) => write!(f, "the credential format refused: {error}"),
            Self::Refusal(refusal) => write!(f, "the policy refused: {refusal}"),
            Self::Driver(error) => write!(f, "the commit driver gave no serial: {error}"),
            Self::Transition(error) => write!(f, "the transition refused: {error}"),
            Self::Conflict => f.write_str("a dependency changed before the commit"),
            Self::Unknown(_) => f.write_str("the outcome of the commit is unknown"),
            Self::Committed => f.write_str("an earlier submission of the operation committed"),
            Self::Operation => f.write_str("the outcome is of another operation"),
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
