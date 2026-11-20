//! CLI credentials: the possession of the key of a headless CLI on each call.
//!
//! A CLI keeps its key in custody ([`Custody`]) and holds a CLI credential whose `cnf` key is that key. The credential
//! is no secret. Each call proves the possession of the key over a one-use challenge of the authority, the operation
//! identity of the call, and its request. Thus a captured call cannot repeat, and a proof for one request refuses for
//! another.
//!
//! 1. The CLI draws a key ID, records it, and enrolls its key in custody before it submits a bootstrap value
//!    ([`local::Authority::bootstrap`]). Thus a bootstrap that commits binds a key that the CLI has, also when the
//!    CLI lost the response. It then reads its credential with [`local::Authority::credential`].
//! 2. For its first call, the CLI asks the authority for a [`Challenge`] ([`local::Authority::challenge`]). A
//!    challenge is valid for [`CHALLENGE_LIFETIME`]. A binding has at most one: a new issue replaces it.
//! 3. The CLI makes the [`Call`]: the challenge, an operation identity, and its request as a CBOR value. [`prove`]
//!    signs the proof in custody. The CLI sends its credential, the proof, the challenge, the operation, and the
//!    request.
//! 4. The authority makes the same [`Call`] from what it received, and admits the call
//!    ([`local::Authority::admit`]). The commit of the admission consumes the challenge and writes the next one, which
//!    the admitted call gives ([`local::Admitted::next`]). The CLI uses it for its next call, with no issue. After a
//!    refusal, a conflict, or a restore, the CLI asks for a new challenge.
//!
//! The example runs the journey on the memory binding of `rsauthnz-conformance`, with the key files of `FileCustody`
//! (the feature `native-custody`). It keeps the issuer key of the authority in the same custody, to stay short.
//!
//! ```
//! # #[cfg(all(feature = "native-custody", any(target_os = "linux", target_os = "macos", windows)))]
//! # fn main() -> Result<(), Box<dyn core::error::Error>> {
//! use core::pin::pin;
//! use core::task::{Context, Poll, Waker};
//! use core::time::Duration;
//!
//! use rsauthnz::cbor::Value;
//! use rsauthnz::cli::{self, Call, Challenge};
//! use rsauthnz::credential::Serial;
//! use rsauthnz::crypto::Algorithm;
//! use rsauthnz::custody::{Custody, FileCustody, Isolation, KeyId};
//! use rsauthnz::id::Id;
//! use rsauthnz::limits::Limits;
//! use rsauthnz::local::{Authority, Bootstrap, HostGrant};
//! use rsauthnz::store::driver::{Answer, Driver, Plan};
//! use rsauthnz::store::{self, Kind, Store};
//! use rsauthnz::time::{Reading, ReadingSource};
//! use rsauthnz::transition::{OperationId, Outcome, Proposal};
//! use rsauthnz_conformance::memory::{Memory, Schedule};
//! use rsauthnz_conformance::suite::execute;
//! use rscrypto::ChaCha20Rng;
//!
//! type Failure = Box<dyn core::error::Error>;
//!
//! /// The output of a future of the memory binding, which is ready at its first poll.
//! fn ready<T>(future: impl Future<Output = T>) -> T {
//!     let Poll::Ready(output) = pin!(future).poll(&mut Context::from_waker(Waker::noop())) else {
//!         unreachable!("the memory binding does no I/O");
//!     };
//!     output
//! }
//!
//! /// The outcome of the commit of `proposal` with `plan`, after the driver gives each effect to the binding.
//! fn commit(memory: &mut Memory, driver: &mut Driver, (proposal, plan): (Proposal, Plan)) -> Result<Outcome, Failure> {
//!     let ticket = driver.submit(proposal, plan)?;
//!     while let Some(effect) = driver.effect() {
//!         let output = ready(execute(memory, effect));
//!         driver.give(output)?;
//!     }
//!     match driver.take(ticket) {
//!         Some(Answer::Outcome(outcome)) => Ok(outcome),
//!         answer => Err(format!("the commit gave {answer:?}").into()),
//!     }
//! }
//!
//! /// The artifact of an accepted commit.
//! fn artifact(outcome: Outcome) -> Result<Vec<u8>, Failure> {
//!     match outcome {
//!         Outcome::Accepted(receipt) => Ok(receipt.artifact().ok_or("no artifact")?.to_vec()),
//!         outcome => Err(format!("the commit did not land: {outcome:?}").into()),
//!     }
//! }
//!
//! let now = Reading::new(Duration::from_secs(1_800_000_000), Some(Duration::from_secs(1)), ReadingSource::Caller);
//! // Only for this example: take the seed from the entropy source of the host.
//! let mut random = ChaCha20Rng::from_seed([7; 32]);
//! let dir = std::env::temp_dir().join(format!("rsauthnz-cli-example-{}", std::process::id()));
//! std::fs::create_dir(&dir)?;
//! let custody = FileCustody::open(&dir, Isolation::User)?;
//! let issuer = custody.enroll(KeyId::random(&mut random), Algorithm::MlDsa65Ed25519, &mut random)?;
//!
//! let mut memory = Memory::new(Schedule::None);
//! let mut driver = Driver::new(store::Profile::new(memory.declaration())?, Limits::default())?;
//! driver.start(now);
//! while let Some(effect) = driver.effect() {
//!     let output = ready(execute(&mut memory, effect));
//!     driver.give(output)?;
//! }
//!
//! // 1. The local owner opens the authority and issues a bootstrap value for the administrator `alice`.
//! let grant = HostGrant { owner: Id::new("acme", "owner")?, origin: Id::new("acme", "build-app")? };
//! let authority = ready(Authority::open(&mut memory, &grant, Id::new("acme", "auth")?, issuer.clone(), Limits::default()))?;
//! let alice = Id::new("acme", "alice")?;
//! let issue = ready(authority.issue(&mut memory, &grant, alice.clone(), now, &mut random, OperationId::new(b"i-1")?))?;
//! let value = Bootstrap::parse(&String::from_utf8(artifact(commit(&mut memory, &mut driver, issue)?)?)?)?;
//!
//! // 2. The CLI draws a key ID, records it with `alice`, and enrolls its key before it submits the value.
//! let key = custody.enroll(KeyId::random(&mut random), Algorithm::MlDsa65Ed25519, &mut random)?;
//! let holder: [u8; 1984] = key.public_key().as_slice().try_into()?;
//! let serial = Serial(driver.allocate(Kind::Credential)?);
//! let pending = ready(authority.bootstrap(&mut memory, &value, &holder, serial, now))?;
//! let signature = custody.sign(&issuer, Algorithm::MlDsa65Ed25519, &pending.to_be_signed(), &mut random)?;
//! let bootstrap = pending.finish(&signature, OperationId::new(b"b-1")?)?;
//! let credential = artifact(commit(&mut memory, &mut driver, bootstrap)?)?;
//!
//! // 3. The first call: the authority issues a challenge, and the CLI proves the possession of its key in custody.
//! let issued = ready(authority.challenge(&mut memory, &alice, now, &mut random, OperationId::new(b"c-1")?))?;
//! let mut challenge = Challenge::from_bytes(artifact(commit(&mut memory, &mut driver, issued)?)?.as_slice().try_into()?);
//! for (operation, target) in [(&b"call-1"[..], "status"), (b"call-2", "deploy")] {
//!     let call = Call::new(challenge, OperationId::new(operation)?, &Value::Text(target), Limits::default())?;
//!     let proof = cli::prove(&custody, &key, &credential, &grant.origin, &call, now, &mut random)?;
//!
//!     // 4. The authority makes the call again from what it received, and admits it in one commit.
//!     let (proposal, admission) = ready(authority.admit(&mut memory, &credential, &proof, &call, now, &mut random))?;
//!     let outcome = commit(&mut memory, &mut driver, (proposal, Plan::default()))?;
//!     let admitted = admission.release(&outcome).ok_or("the call was not admitted")?;
//!     assert_eq!(admitted.administrator(), &alice);
//!     // The next call uses the challenge that this commit wrote, with no issue.
//!     challenge = admitted.next();
//! }
//!
//! custody.delete(key.id())?;
//! custody.delete(issuer.id())?;
//! std::fs::remove_dir(&dir)?;
//! # Ok(())
//! # }
//! # #[cfg(not(all(feature = "native-custody", any(target_os = "linux", target_os = "macos", windows))))]
//! # fn main() {}
//! ```
//!
//! [`local::Authority::bootstrap`]: crate::local::Authority::bootstrap
//! [`local::Authority::credential`]: crate::local::Authority::credential
//! [`local::Authority::challenge`]: crate::local::Authority::challenge
//! [`local::Authority::admit`]: crate::local::Authority::admit
//! [`local::Admitted::next`]: crate::local::Admitted::next

use alloc::boxed::Box;
use alloc::vec;
use alloc::vec::Vec;
use core::fmt;
use core::time::Duration;

use rscrypto::ChaCha20Rng;

use crate::cbor::{self, Value};
use crate::credential::{self, ProofDraft};
use crate::crypto;
use crate::custody::{self, Custody, Handle};
use crate::id::{Audience, Authority, Human, Id};
use crate::limits::{Limits, SignatureBudget};
use crate::store::{Kind, Record};
use crate::time::Reading;
use crate::transition::{Key, OperationId};

/// The lifetime of a challenge: 60 seconds from its issue. A call at or after its end refuses.
pub const CHALLENGE_LIFETIME: Duration = Duration::from_secs(60);

/// The first item of each CBOR form of this module. The number changes with the form.
const CHALLENGE_FORM: &str = "rsauthnz.cli.challenge.1";
const CALL_FORM: &str = "rsauthnz.cli.call.1";

/// A one-use challenge of a call: 32 random bytes of the authority. It is no secret.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub struct Challenge([u8; 32]);

impl Challenge {
    /// The challenge with the bytes `bytes`, for a challenge that the CLI received.
    ///
    /// Cost class: [`Parse`](crate::limits::Class::Parse).
    #[must_use]
    pub const fn from_bytes(bytes: [u8; 32]) -> Self {
        Self(bytes)
    }

    /// The bytes of the challenge.
    ///
    /// Cost class: [`Parse`](crate::limits::Class::Parse).
    #[must_use]
    pub const fn to_bytes(self) -> [u8; 32] {
        self.0
    }

    /// A new challenge from `random`.
    pub(crate) fn random(random: &mut ChaCha20Rng) -> Self {
        let mut bytes = [0; 32];
        random.fill_bytes(&mut bytes);
        Self(bytes)
    }
}

/// A call of a CLI: its challenge, its operation identity, and the request binding.
#[derive(Clone, PartialEq, Eq)]
pub struct Call {
    challenge: Challenge,
    operation: OperationId,
    binding: [u8; 32],
}

impl Call {
    /// The call `operation` over `challenge`, with the request `request`: the CBOR value of the call that the
    /// application defines, such as its action, its target, and the digest of its content. The request binding is the
    /// SHA-256 digest of the canonical CBOR form `["rsauthnz.cli.call.1", challenge, operation, request]`. The CLI
    /// makes the call, and the authority makes it again from the values that it received.
    ///
    /// Cost class: [`Parse`](crate::limits::Class::Parse). One SHA-256 digest of the bounded form.
    ///
    /// # Errors
    ///
    /// [`Error::Request`] if `request` has no CBOR encoding, or the form is longer than [`Limits::bytes`] of `limits`.
    pub fn new(
        challenge: Challenge,
        operation: OperationId,
        request: &Value<'_>,
        limits: Limits,
    ) -> Result<Self, Error> {
        let form = Value::Array(vec![
            Value::Text(CALL_FORM),
            Value::Bytes(&challenge.0),
            Value::Bytes(operation.as_bytes()),
            request.clone(),
        ]);
        let form = cbor::encode(&form).map_err(|_| Error::Request)?;
        (form.len() <= limits.bytes).ok_or(Error::Request)?;
        Ok(Self {
            challenge,
            binding: crypto::sha256(&form),
            operation,
        })
    }

    /// The challenge.
    #[must_use]
    pub const fn challenge(&self) -> Challenge {
        self.challenge
    }

    /// The operation identity. After an unknown outcome, look it up: never send the call again as a new operation.
    #[must_use]
    pub const fn operation(&self) -> &OperationId {
        &self.operation
    }

    /// The request binding, which the proof binds in place of a challenge of the verifier.
    #[must_use]
    pub const fn binding(&self) -> &[u8; 32] {
        &self.binding
    }
}

// A request can hold a secret, so the output does not show the request binding.
impl fmt::Debug for Call {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("Call")
            .field("challenge", &self.challenge)
            .field("operation", &self.operation)
            .finish_non_exhaustive()
    }
}

/// The proof of `call` by the key of `handle` in `custody`: the `cnf` key of `credential`, the CLI credential of the
/// authority with the audience `audience`. The proof binds the exact bytes of `credential`, `audience`, and the request
/// binding of `call` ([`ProofDraft`]). Custody signs it with `random`, and the proof refuses unless the signature
/// verifies with the key of `handle`. Only custody holds the key.
///
/// Cost class: [`External`](crate::limits::Class::External). One custody signature and one signature check.
///
/// # Errors
///
/// [`Error::Custody`] if custody refuses to sign. [`Error::Credential`] if the proof can be longer than
/// [`credential::MAX_BYTES`], or the signature does not verify with the key of `handle`.
pub fn prove(
    custody: &dyn Custody,
    handle: &Handle,
    credential: &[u8],
    audience: &Id<Audience>,
    call: &Call,
    now: Reading,
    random: &mut ChaCha20Rng,
) -> Result<Vec<u8>, Error> {
    let draft =
        ProofDraft::new(&handle.trusted(), credential, audience, &call.binding, now).map_err(Error::Credential)?;
    let signature = custody
        .sign(handle, handle.algorithm(), &draft.to_be_signed(), random)
        .map_err(Error::Custody)?;
    // A composite signature costs two checks: the budget of the default limits.
    draft
        .finish(&signature, &mut SignatureBudget::new(&Limits::default()))
        .map_err(Error::Credential)
}

/// The key of the challenge record of the CLI credential of `subject` from `issuer`: [`Kind::SignIn`] with the SHA-256
/// digest of the canonical CBOR form `["rsauthnz.cli.challenge.1", issuer, subject]`. A restore ends each record of the
/// kind, so a challenge from before a restore refuses after it.
pub(crate) fn key(issuer: &Id<Authority>, subject: &Id<Human>) -> Key {
    let form = Value::Array(vec![Value::Text(CHALLENGE_FORM), issuer.to_cbor(), subject.to_cbor()]);
    let form = cbor::encode(&form).expect("the form has no map and no simple value");
    Kind::SignIn
        .key(&crypto::sha256(&form))
        .expect("a key of 33 bytes is valid")
}

/// The form of a challenge record: `["rsauthnz.cli.challenge.1", challenge]`. The end of the record is the end of the
/// challenge.
pub(crate) fn record(challenge: Challenge) -> Box<[u8]> {
    let form = Value::Array(vec![Value::Text(CHALLENGE_FORM), Value::Bytes(&challenge.0)]);
    cbor::encode(&form)
        .expect("the form has no map and no simple value")
        .into_boxed_slice()
}

/// The challenge of the challenge record `record`, or `None` for another form within `limits`.
pub(crate) fn challenge(record: &Record, limits: Limits) -> Option<Challenge> {
    let Value::Array(items) = cbor::decode(&record.data, limits).ok()? else {
        return None;
    };
    let [Value::Text(CHALLENGE_FORM), Value::Bytes(bytes)] = items.as_slice() else {
        return None;
    };
    Some(Challenge((*bytes).try_into().ok()?))
}

/// The cause of a refused call of a CLI. No error holds a secret.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Error {
    /// The request has no CBOR encoding, or the form of the call is longer than its bound. Give the digest of a long
    /// content in the request, not the content.
    Request,
    /// Custody refused to sign. The error gives the recovery.
    Custody(custody::Error),
    /// The proof refused: it can be longer than its bound, or the signature of custody does not verify with the key
    /// of the handle. A refused signature shows a fault of custody or another key.
    Credential(credential::Error),
}

impl fmt::Display for Error {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Request => f.write_str("the request of the call has no encoding within its bound"),
            Self::Custody(error) => write!(f, "custody refused to sign: {error}"),
            Self::Credential(error) => write!(f, "the proof refused: {error}"),
        }
    }
}

impl core::error::Error for Error {}
