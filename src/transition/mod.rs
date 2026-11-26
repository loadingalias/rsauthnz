//! Transition proposals: the change of authority that one verified request asks for, and its outcome.
//!
//! The core decides a transition with a pure function. Its inputs are a bounded request, verified evidence, the
//! current policy, and the current state that the decision reads. Its result is a [`Proposal`]: the dependencies
//! that the decision read, the state changes, the audit, the effect intents, and a prepared artifact. Only the
//! storage binding of the application accepts a proposal. It checks each dependency and commits the changes, the
//! audit, the intents, and the outcome record in one atomic commit. The [`Outcome`] is an accepted receipt, a
//! conflict, a refusal, or unknown.
//!
//! A proposal names each read of its decision with [`Proposal::read`]: a policy version, a record version, or the
//! absence of a record. A uniqueness condition is the absence of a record under a unique key. A change names a
//! record that the proposal read, so the commit refuses when a concurrent commit changed that record first.
//!
//! An operation has a stable identity, which the client chooses or which an existing ceremony or grant identity
//! supplies. Its request binding is a digest of the actor, the action, and the request. A second submission of the
//! same request under the same identity gets the outcome of the first, and a different request refuses
//! with [`Error::Reuse`]. A lost response is an [`Outcome::Unknown`]. Its recovery is a lookup of the same
//! identity, never a new operation.
//!
//! ```
//! use core::time::Duration;
//!
//! use rsauthnz::cbor::Value;
//! use rsauthnz::id::{Authority, AuthorityVersion, Human, Id, Principal};
//! use rsauthnz::limits::Limits;
//! use rsauthnz::time::{Reading, ReadingSource};
//! use rsauthnz::transition::{Audit, Change, Dependency, Key, OperationId, Proposal};
//!
//! let owner: Id<Authority> = Id::new("acme", "auth")?;
//! let version = |n: u64| AuthorityVersion::new(owner.clone(), &n.to_be_bytes());
//! let audit = Audit {
//!     actor: Principal::Human(Id::<Human>::new("acme", "u-17")?),
//!     action: Id::new("acme.auth", "credential.enroll")?,
//!     time: Reading::new(Duration::from_secs(1_000), Some(Duration::from_secs(1)), ReadingSource::Caller),
//! };
//! let invitation = Key::new(b"invitation/i-9")?;
//! let credential = Key::new(b"credential/c-4")?;
//! let request = Value::Array(vec![Value::Bytes(b"i-9"), Value::Bytes(b"c-4")]);
//!
//! // The decision consumes the invitation and creates the credential. It reads both first.
//! let mut proposal = Proposal::new(OperationId::new(b"op-1")?, audit, &request, Limits::default())?;
//! proposal.read(Dependency::Version(invitation.clone(), version(3)?))?;
//! proposal.read(Dependency::Absent(credential.clone()))?;
//! proposal.change(Change::End(invitation))?;
//! proposal.change(Change::Write {
//!     key: credential,
//!     version: version(1)?,
//!     end: None,
//!     data: Box::new(*b"the credential record"),
//! })?;
//! assert_eq!(proposal.dependencies().len(), 2);
//! # Ok::<(), Box<dyn core::error::Error>>(())
//! ```

use alloc::boxed::Box;
use alloc::vec;
use alloc::vec::Vec;
use core::cmp::Ordering;
use core::fmt;
use core::time::Duration;

use rscrypto::{ChaCha20Rng, SecretVec};

use crate::cbor::{self, Value};
use crate::crypto;
use crate::id::{Action, AuthorityVersion, Human, Id, Principal};
use crate::limits::{Limit, Limits};
use crate::store::Kind;
use crate::time::Reading;

/// The first item of the CBOR form that a request binding digests. Its number changes with the form.
const BINDING_FORM: &str = "rsauthnz.transition.binding.1";

/// The identity of one externally submitted operation: 1 to [`Self::BYTES_MAX`] opaque bytes.
///
/// The client chooses it, for example 16 random bytes, or an existing ceremony or grant identity supplies it. The
/// store keeps one outcome record for each identity.
#[derive(Clone, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct OperationId(Box<[u8]>);

impl OperationId {
    /// The most bytes in an operation identity.
    pub const BYTES_MAX: usize = 64;

    /// Makes the operation identity `bytes`.
    ///
    /// Cost class: [`Parse`](crate::limits::Class::Parse).
    ///
    /// # Errors
    ///
    /// [`Error::OperationId`] for no bytes or more than [`Self::BYTES_MAX`] bytes.
    pub fn new(bytes: &[u8]) -> Result<Self, Error> {
        (1..=Self::BYTES_MAX).contains(&bytes.len()).ok_or(Error::OperationId)?;
        Ok(Self(bytes.into()))
    }

    /// A new operation identity: 32 bytes from `random`.
    pub(crate) fn random(random: &mut ChaCha20Rng) -> Self {
        let mut id = [0; 32];
        random.fill_bytes(&mut id);
        Self(id.into())
    }

    /// The bytes of the identity.
    #[must_use]
    pub fn as_bytes(&self) -> &[u8] {
        &self.0
    }
}

impl fmt::Debug for OperationId {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "OperationId({:02x?})", self.0)
    }
}

/// An operation: its identity and its request binding. The store keeps it as the outcome record of the identity.
#[derive(Clone, PartialEq, Eq)]
pub struct Operation {
    /// The identity.
    pub id: OperationId,
    /// The request binding: the SHA-256 digest of the canonical CBOR form
    /// `["rsauthnz.transition.binding.1", actor, action, request]`. A request can hold a secret, so `Debug` does not
    /// show the binding.
    pub binding: [u8; 32],
}

impl Operation {
    /// The answer of a store that keeps `self` as the outcome record of an identity, to the submission `submitted` of
    /// that identity. The same request gets the receipt of the commit, with no artifact, and no second commit.
    ///
    /// Only the commit driver calls it, with an outcome record that it read from the store. A receipt releases
    /// authority, such as the evidence of a sign-in, so no caller can make one without a durable commit.
    #[must_use]
    pub(crate) fn answer(&self, submitted: &Self) -> Outcome {
        if self == submitted {
            Outcome::Accepted(Receipt {
                operation: self.id.clone(),
                artifact: None,
            })
        } else {
            Outcome::Refused(Error::Reuse)
        }
    }
}

impl fmt::Debug for Operation {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("Operation")
            .field("id", &self.id)
            .finish_non_exhaustive()
    }
}

/// The name of a record in the store: 1 to [`Self::BYTES_MAX`] opaque bytes. The storage contract gives the key of
/// each record kind. A key is no secret: name a record that a secret finds by a keyed digest of the secret.
#[derive(Clone, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct Key(Box<[u8]>);

impl Key {
    /// The most bytes in a key. It is the largest partition key of DynamoDB, and B-tree indexes of PostgreSQL and
    /// MySQL also hold it.
    pub const BYTES_MAX: usize = 2048;

    /// Makes the key `bytes`.
    ///
    /// Cost class: [`Parse`](crate::limits::Class::Parse).
    ///
    /// # Errors
    ///
    /// [`Error::Key`] for no bytes or more than [`Self::BYTES_MAX`] bytes.
    pub fn new(bytes: &[u8]) -> Result<Self, Error> {
        (1..=Self::BYTES_MAX).contains(&bytes.len()).ok_or(Error::Key)?;
        Ok(Self(bytes.into()))
    }

    /// The bytes of the key.
    #[must_use]
    pub fn as_bytes(&self) -> &[u8] {
        &self.0
    }
}

impl fmt::Debug for Key {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "Key({:02x?})", self.0)
    }
}

/// A read of the decision. The commit checks it again, in the same atomic step as its changes.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Dependency {
    /// The policy of the owner of the version is at this version: the policy record of the owner
    /// ([`store::policy_key`](crate::store::policy_key)) is at this version.
    Policy(AuthorityVersion),
    /// The record is at this version.
    Version(Key, AuthorityVersion),
    /// No record has this key: an absence, or the uniqueness of the key in its namespace.
    Absent(Key),
}

impl Dependency {
    /// Whether `self` and `other` read the same policy or the same record.
    fn reads_same(&self, other: &Self) -> bool {
        match (self, other) {
            (Self::Policy(a), Self::Policy(b)) => a.owner() == b.owner(),
            (Self::Version(a, _) | Self::Absent(a), Self::Version(b, _) | Self::Absent(b)) => a == b,
            _ => false,
        }
    }
}

/// A state change of a proposal.
#[derive(Clone, PartialEq, Eq)]
pub enum Change {
    /// Writes the record at `version`, with the record form `data`. The record is new when the proposal reads it as
    /// absent. Otherwise `version` is later than the version that the proposal read.
    Write {
        /// The record.
        key: Key,
        /// The new version.
        version: AuthorityVersion,
        /// The end of the record, as the time since the Unix epoch, or `None` for a record with no end. Expiry
        /// removes the record when the earliest time of a reading is past its end, so set the end past the last time
        /// that a check can accept the record.
        end: Option<Duration>,
        /// The record form. It can hold a secret, so `Debug` shows only its length.
        data: Box<[u8]>,
    },
    /// Ends the record: it consumes a one-use value, revokes, or removes. The proposal reads it at a version.
    End(Key),
}

impl Change {
    /// The key of the record that the change writes or ends.
    pub(crate) const fn key(&self) -> &Key {
        match self {
            Self::Write { key, .. } | Self::End(key) => key,
        }
    }
}

impl fmt::Debug for Change {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Write {
                key,
                version,
                end,
                data,
            } => f
                .debug_struct("Write")
                .field("key", key)
                .field("version", version)
                .field("end", end)
                .field("data", &Hidden(data))
                .finish(),
            Self::End(key) => f.debug_tuple("End").field(key).finish(),
        }
    }
}

/// The required audit of a proposal. The commit records it with the operation identity and the key of each change.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Audit {
    /// The principal that acts.
    pub actor: Principal,
    /// The action of the transition, for example `credential.enroll`.
    pub action: Id<Action>,
    /// The physical time of the decision.
    pub time: Reading,
}

/// An effect intent: a notification, signer, or provider call that the commit records, so that it survives a
/// crash. The application calls the effect after the commit, and it keeps the record until it observes the end of
/// the call.
#[derive(Clone, PartialEq, Eq)]
pub struct Intent {
    effect: Effect,
    payload: Box<[u8]>,
    state: State,
}

/// The kind of call of an intent.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub enum Effect {
    /// A notification, for example to the owner of an account.
    Notification,
    /// A signer.
    Signer,
    /// An external identity provider.
    Provider,
    /// The creation entry of the restore journal for the anchors of the commit, with the CBOR form of the anchors as
    /// its payload. The commit driver adds it to an anchor commit with no consumption, appends the entry after the
    /// commit, and then ends the intent. An application worker skips it.
    Journal,
}

/// The state of an intent.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub enum State {
    /// The application can call the effect.
    Open,
    /// The application calls the effect no more. A call can still be in progress, so the record stays.
    Cancelled,
    /// The application observed the end of the call, so it can remove the record.
    Ended(Ended),
}

/// The observed end of the call of an intent.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub enum Ended {
    /// The call completed.
    Completed,
    /// The resource of the call came back, or the call did not occur.
    Returned,
}

impl Intent {
    /// Makes an open intent of `effect` with the call parameters `payload`. The payload can hold a secret, so `Debug`
    /// shows only its length.
    ///
    /// Cost class: [`Parse`](crate::limits::Class::Parse).
    #[must_use]
    pub const fn new(effect: Effect, payload: Box<[u8]>) -> Self {
        Self {
            effect,
            payload,
            state: State::Open,
        }
    }

    /// The kind of call.
    #[must_use]
    pub const fn effect(&self) -> Effect {
        self.effect
    }

    /// The call parameters.
    #[must_use]
    pub fn payload(&self) -> &[u8] {
        &self.payload
    }

    /// The state.
    #[must_use]
    pub const fn state(&self) -> State {
        self.state
    }

    /// Stops new calls of an open intent. The record stays until the application observes the end of each call.
    ///
    /// Cost class: [`Parse`](crate::limits::Class::Parse).
    pub fn cancel(&mut self) {
        if self.state == State::Open {
            self.state = State::Cancelled;
        }
    }

    /// Records the observed end of the call. The first observed end stays.
    ///
    /// Cost class: [`Parse`](crate::limits::Class::Parse).
    pub fn observe(&mut self, ended: Ended) {
        if !matches!(self.state, State::Ended(_)) {
            self.state = State::Ended(ended);
        }
    }

    /// The version of the intent record: a later state has a later version. A commit that changes the state of a
    /// stored intent reads the record at its version and writes it at the version of the new state.
    #[must_use]
    pub fn version(&self) -> AuthorityVersion {
        let state = match self.state {
            State::Open => 1,
            State::Cancelled => 2,
            State::Ended(_) => 3,
        };
        let owner = Id::new("rsauthnz", "intent").expect("the owner of intent versions is a valid identifier");
        AuthorityVersion::new(owner, &[state]).expect("a one-byte coordinate is valid")
    }

    /// The canonical CBOR form, which the store keeps as the record form of the intent: the array `[effect, state,
    /// payload]`. The effect is 1 for a notification, 2 for a signer, and 3 for a provider. The state is 1 for open,
    /// 2 for cancelled, 3 for completed, and 4 for returned.
    #[must_use]
    pub fn to_cbor(&self) -> Value<'_> {
        let effect = match self.effect {
            Effect::Notification => 1,
            Effect::Signer => 2,
            Effect::Provider => 3,
            Effect::Journal => 4,
        };
        let state = match self.state {
            State::Open => 1,
            State::Cancelled => 2,
            State::Ended(Ended::Completed) => 3,
            State::Ended(Ended::Returned) => 4,
        };
        Value::Array(vec![
            Value::Unsigned(effect),
            Value::Unsigned(state),
            Value::Bytes(&self.payload),
        ])
    }

    /// Reads the canonical CBOR form of an intent.
    ///
    /// Cost class: [`Parse`](crate::limits::Class::Parse).
    ///
    /// # Errors
    ///
    /// [`Error::Intent`] if `value` is not the form of [`Self::to_cbor`].
    pub fn from_cbor(value: &Value<'_>) -> Result<Self, Error> {
        let Value::Array(items) = value else {
            return Err(Error::Intent);
        };
        let [Value::Unsigned(effect), Value::Unsigned(state), Value::Bytes(payload)] = items.as_slice() else {
            return Err(Error::Intent);
        };
        let effect = match effect {
            1 => Effect::Notification,
            2 => Effect::Signer,
            3 => Effect::Provider,
            4 => Effect::Journal,
            _ => return Err(Error::Intent),
        };
        let state = match state {
            1 => State::Open,
            2 => State::Cancelled,
            3 => State::Ended(Ended::Completed),
            4 => State::Ended(Ended::Returned),
            _ => return Err(Error::Intent),
        };
        Ok(Self {
            effect,
            payload: (*payload).into(),
            state,
        })
    }
}

impl fmt::Debug for Intent {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("Intent")
            .field("effect", &self.effect)
            .field("payload", &Hidden(&self.payload))
            .field("state", &self.state)
            .finish()
    }
}

/// A proposed transition: the operation, the audit, the reads of the decision, the state changes, the effect
/// intents, and a prepared artifact. Only the acceptance of the commit releases the artifact.
#[derive(Debug)]
pub struct Proposal {
    operation: Operation,
    audit: Audit,
    /// The human owner of the agent of [`Audit::actor`], which the audit record names. Only this crate sets it, from
    /// the identity record of the agent, so the caller of a proposal cannot omit or substitute the owner.
    owner: Option<Id<Human>>,
    dependencies: Vec<Dependency>,
    changes: Vec<Change>,
    intents: Vec<Intent>,
    artifact: Option<Prepared>,
    deadline: Option<Duration>,
    limits: Limits,
}

impl Proposal {
    /// Starts the proposal of the operation `id`, with the required `audit` and the request binding of its actor, its
    /// action, and `request`. The proposal holds at most [`Limits::dependencies`] dependencies and
    /// [`Limits::intents`] intents.
    ///
    /// Cost class: [`Parse`](crate::limits::Class::Parse). The binding is one SHA-256 digest of the canonical CBOR
    /// form `["rsauthnz.transition.binding.1", actor, action, request]`. `request` must encode within `limits`, and the
    /// encoder refuses it at the first bound, before more work.
    ///
    /// An agent acts only under the grant of its owner, so the actor of `audit` is a human or a workload. The proposal
    /// of an operation of an agent comes from the scope of its grant
    /// ([`Granted::propose`](crate::authz::Granted::propose)), whose audit names the owner.
    ///
    /// # Errors
    ///
    /// [`Error::Agent`] if the actor is an agent, and [`Error::Request`] if `request` has no CBOR encoding within
    /// `limits`.
    pub fn new(id: OperationId, audit: Audit, request: &Value<'_>, limits: Limits) -> Result<Self, Error> {
        (!matches!(audit.actor, Principal::Agent(_))).ok_or(Error::Agent)?;
        Self::start(id, audit, request, limits)
    }

    /// The proposal of [`Self::new`] for any actor. A proposal of an agent names its owner with [`Self::attribute`],
    /// except the enrollment request of an agent that has no owner yet.
    pub(crate) fn start(id: OperationId, audit: Audit, request: &Value<'_>, limits: Limits) -> Result<Self, Error> {
        let request = cbor::encode(request, limits).map_err(Error::Request)?;
        let prefix = cbor::prefix(&[Value::Text(BINDING_FORM), audit.actor.to_cbor(), audit.action.to_cbor()]);
        let binding = crypto::sha256_parts(&[&prefix, &request]);
        Ok(Self {
            operation: Operation { id, binding },
            audit,
            owner: None,
            dependencies: Vec::new(),
            changes: Vec::new(),
            intents: Vec::new(),
            artifact: None,
            deadline: None,
            limits,
        })
    }

    /// Adds a read of the decision to the dependencies. A second equal read adds nothing.
    ///
    /// Cost class: [`Parse`](crate::limits::Class::Parse).
    ///
    /// # Errors
    ///
    /// [`Error::Changed`] if the proposal read the same policy or record with another result, and
    /// [`Error::Limit`] with [`Limit::Dependencies`] for a dependency past [`Limits::dependencies`].
    pub fn read(&mut self, dependency: Dependency) -> Result<(), Error> {
        if let Some(earlier) = self.dependencies.iter().find(|earlier| earlier.reads_same(&dependency)) {
            return (*earlier == dependency).ok_or(Error::Changed);
        }
        (self.dependencies.len() < self.limits.dependencies).ok_or(Error::Limit(Limit::Dependencies))?;
        self.dependencies.push(dependency);
        Ok(())
    }

    /// Adds a state change. A read of the proposal must allow it: a write of a record that the proposal read as
    /// absent, a write at a later version than the version that the proposal read, or an end of a record that the
    /// proposal read at a version. Thus the changes are at most [`Limits::dependencies`]. Only the commit writes an
    /// audit or an outcome record ([`Kind::Audit`], [`Kind::Outcome`]), so no change can name one.
    ///
    /// Cost class: [`Parse`](crate::limits::Class::Parse).
    ///
    /// # Errors
    ///
    /// [`Error::Change`] if no read allows `change`, if another change names its record, or if it names an audit or an
    /// outcome record.
    pub fn change(&mut self, change: Change) -> Result<(), Error> {
        let allowed = self.dependencies.iter().any(|read| match (read, &change) {
            (Dependency::Absent(read), Change::Write { key, .. }) => read == key,
            (Dependency::Version(read, earlier), Change::Write { key, version, .. }) => {
                read == key && version.compare(earlier) == Ok(Ordering::Greater)
            }
            (Dependency::Version(read, _), Change::End(key)) => read == key,
            _ => false,
        });
        let again = self.changes.iter().any(|earlier| earlier.key() == change.key());
        let committed = matches!(Kind::of(change.key()), Some(Kind::Audit | Kind::Outcome));
        (allowed && !again && !committed).ok_or(Error::Change)?;
        self.changes.push(change);
        Ok(())
    }

    /// Adds an effect intent.
    ///
    /// Cost class: [`Parse`](crate::limits::Class::Parse).
    ///
    /// # Errors
    ///
    /// [`Error::Limit`] with [`Limit::Intents`] for an intent past [`Limits::intents`].
    pub fn intend(&mut self, intent: Intent) -> Result<(), Error> {
        (self.intents.len() < self.limits.intents).ok_or(Error::Limit(Limit::Intents))?;
        self.intents.push(intent);
        Ok(())
    }

    /// Sets the prepared artifact, for example a credential that [`Draft::finish`](crate::credential::Draft::finish)
    /// gives. The artifact names its issuance record: the record that the transition that issues it writes, such as
    /// the record of the serial of a credential ([`Draft::record`](crate::credential::Draft::record)). The proposal
    /// must already write that record at that version, so an artifact never commits with an unrelated transition. It
    /// stays private until the acceptance of this exact proposal, and only the receipt of that acceptance releases
    /// it.
    ///
    /// Cost class: [`Parse`](crate::limits::Class::Parse).
    ///
    /// # Errors
    ///
    /// [`Error::Prepared`] if the proposal has an artifact, or no change writes the issuance record of `artifact` at
    /// its version.
    pub fn prepare(&mut self, artifact: Prepared) -> Result<(), Error> {
        let issued = self.changes.iter().any(|change| {
            matches!(change, Change::Write { key, version, .. } if *key == artifact.record && *version == artifact.version)
        });
        (self.artifact.is_none() && issued).ok_or(Error::Prepared)?;
        self.artifact = Some(artifact);
        Ok(())
    }

    /// Sets the deadline of the commit, as the time since the Unix epoch: the end of the authority that the decision
    /// read, such as the end of a one-use value, of a challenge, or of a checked scope. A proposal keeps its earliest
    /// deadline. The commit driver reads a fresh clock reading just before the commit, and it refuses the commit with
    /// [`Error::Expired`] when that reading can be at or after the deadline.
    ///
    /// Cost class: [`Parse`](crate::limits::Class::Parse).
    pub fn until(&mut self, deadline: Duration) {
        self.deadline = Some(self.deadline.map_or(deadline, |earlier| earlier.min(deadline)));
    }

    /// The deadline of the commit, or `None` for a commit with no deadline.
    #[must_use]
    pub const fn deadline(&self) -> Option<Duration> {
        self.deadline
    }

    /// The operation: its identity and its request binding.
    #[must_use]
    pub const fn operation(&self) -> &Operation {
        &self.operation
    }

    /// The required audit.
    #[must_use]
    pub const fn audit(&self) -> &Audit {
        &self.audit
    }

    /// The human owner of the agent that acts, or `None` for a human, a workload, or the enrollment request of an agent
    /// that has no owner yet. The audit record names it ([`crate::store::audit_record`]).
    #[must_use]
    pub const fn owner(&self) -> Option<&Id<Human>> {
        self.owner.as_ref()
    }

    /// Names `owner` as the human owner of the agent of [`Audit::actor`]. Call it only with the owner of the current
    /// identity record of the agent.
    pub(crate) fn attribute(&mut self, owner: Id<Human>) {
        assert!(
            matches!(self.audit.actor, Principal::Agent(_)),
            "only the proposal of an agent names an owner"
        );
        self.owner = Some(owner);
    }

    /// The reads of the decision, in the order of the first read of each policy and record.
    #[must_use]
    pub fn dependencies(&self) -> &[Dependency] {
        &self.dependencies
    }

    /// The state changes.
    #[must_use]
    pub fn changes(&self) -> &[Change] {
        &self.changes
    }

    /// The effect intents.
    #[must_use]
    pub fn intents(&self) -> &[Intent] {
        &self.intents
    }

    /// The proposal that a restore commits again for an in-doubt consumption: the operation of the consumption entry,
    /// with its request binding, so that the outcome record answers the request of the first attempt.
    pub(crate) const fn again(operation: Operation, audit: Audit, limits: Limits) -> Self {
        Self {
            operation,
            audit,
            owner: None,
            dependencies: Vec::new(),
            changes: Vec::new(),
            intents: Vec::new(),
            artifact: None,
            deadline: None,
            limits,
        }
    }

    /// The receipt of the accepted proposal, which releases the prepared artifact. Only the commit of the proposal
    /// accepts it.
    pub(crate) fn accept(self) -> Receipt {
        Receipt {
            operation: self.operation.id,
            artifact: self.artifact,
        }
    }
}

/// The receipt of an accepted proposal.
#[derive(Debug)]
pub struct Receipt {
    operation: OperationId,
    artifact: Option<Prepared>,
}

impl Receipt {
    /// The identity of the operation that committed.
    #[must_use]
    pub const fn operation(&self) -> &OperationId {
        &self.operation
    }

    /// The prepared artifact, which the acceptance of the commit releases. The receipt of a lookup has none: the
    /// store never keeps the artifact.
    #[must_use]
    pub fn artifact(&self) -> Option<&[u8]> {
        self.artifact.as_ref().map(Prepared::bytes)
    }
}

/// The outcome of the commit of a proposal.
#[derive(Debug)]
pub enum Outcome {
    /// The commit accepted the proposal.
    Accepted(Receipt),
    /// A dependency changed before the commit, so nothing committed.
    Conflict,
    /// The commit refused the proposal, so nothing committed. The refusal stays true.
    Refused(Error),
    /// The commit can have occurred: its response was lost, or a restore lost its outcome record.
    Unknown(Operation),
}

impl Outcome {
    /// The recovery of the caller, or `None` for an accepted proposal.
    #[must_use]
    pub fn recovery(&self) -> Option<Recovery> {
        match self {
            Self::Accepted(_) => None,
            Self::Conflict => Some(Recovery::Restart),
            Self::Refused(error) => Some(error.recovery()),
            Self::Unknown(_) => Some(Recovery::Lookup),
        }
    }
}

/// The recovery of the caller after an outcome or an error.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub enum Recovery {
    /// Look up the outcome of the same operation identity
    /// ([`Driver::lookup`](crate::store::driver::Driver::lookup)). Only the holder of the [`Operation`], such as the
    /// server, can look it up. Never submit the request as a new operation: the first attempt can have committed.
    Lookup,
    /// Nothing committed. Read the current state again, and propose again as a new operation.
    Restart,
    /// Nothing committed. The change needs a fresh user verification of the account
    /// ([`account::Fresh`](crate::account::Fresh)): sign in with a passkey that replaces the session, then propose
    /// again as a new operation.
    Verify,
    /// Nothing committed. A removal ended the passkey of the sign-in, so the server never accepts it again
    /// ([`passkey::Error::Removed`](crate::passkey::Error::Removed)). Tell the provider of the passkey to forget it
    /// (`signalUnknownCredential` of WebAuthn Level 3), and sign in with another passkey.
    Forget,
    /// Refuse the request. The same request refuses again.
    Refuse,
}

/// The cause of a refused proposal. No error holds a secret.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Error {
    /// The operation identity has no bytes or more than [`OperationId::BYTES_MAX`] bytes.
    OperationId,
    /// The key has no bytes or more than [`Key::BYTES_MAX`] bytes.
    Key,
    /// The request has no CBOR encoding within the limits.
    Request(cbor::Error),
    /// The proposal is larger than a bound of [`Limits`].
    Limit(Limit),
    /// The decision read the same policy or record twice, with two results: the state changed between the reads.
    Changed,
    /// No read of the proposal allows the change, another change names its record, or it names an audit or an outcome
    /// record, which only the commit writes.
    Change,
    /// The operation identity has the outcome record of another request.
    Reuse,
    /// The stored form of an intent is not valid.
    Intent,
    /// The change ends the last sign-in method of an account, or the last administrator binding of the authority, that
    /// the restore journal records as live.
    LastAnchor,
    /// The proposal has an artifact, or no change writes the issuance record of the artifact at its version.
    Prepared,
    /// The clock reading just before the commit can be at or after the deadline of the proposal, or it has no bound.
    /// Nothing committed.
    Expired,
    /// The actor of the audit is an agent. An agent acts only under the grant of its owner: take the proposal from the
    /// scope of the request ([`Granted::propose`](crate::authz::Granted::propose)).
    Agent,
}

/// The recovery of a refusal: the action of its caller. Each error that a request can reach implements it, so a
/// binding maps each one to its response in one place, such as `rsauthnz_http::Problem`.
pub trait Recover {
    /// The recovery of the caller after this refusal.
    #[must_use]
    fn recovery(&self) -> Recovery;
}

impl Recover for Error {
    /// The recovery of the caller: propose again after [`Error::Changed`], and refuse each other request.
    fn recovery(&self) -> Recovery {
        match self {
            Self::Changed => Recovery::Restart,
            Self::OperationId
            | Self::Key
            | Self::Request(_)
            | Self::Limit(_)
            | Self::Change
            | Self::Reuse
            | Self::Intent
            | Self::LastAnchor
            | Self::Prepared
            | Self::Expired
            | Self::Agent => Recovery::Refuse,
        }
    }
}

impl fmt::Display for Error {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::OperationId => f.write_str("the operation identity is empty or too long"),
            Self::Key => f.write_str("the key is empty or too long"),
            Self::Request(error) => write!(f, "the request has no CBOR encoding within the limits: {error}"),
            Self::Limit(Limit::Dependencies) => f.write_str("the proposal has too many dependencies"),
            Self::Limit(Limit::Intents) => f.write_str("the proposal has too many effect intents"),
            Self::Limit(_) => f.write_str("the proposal is larger than a bound of the limits"),
            Self::Changed => f.write_str("the state changed between two reads of the decision"),
            Self::Change => f.write_str("the proposal does not allow the change"),
            Self::Reuse => f.write_str("the operation identity is in use for another request"),
            Self::Intent => f.write_str("the stored form of the intent is not valid"),
            Self::LastAnchor => f.write_str("the change ends the last sign-in method or administrator binding"),
            Self::Prepared => f.write_str("the proposal does not write the issuance record of the artifact"),
            Self::Expired => f.write_str("the commit can be at or after the deadline of the proposal"),
            Self::Agent => f.write_str("the actor is an agent, which acts only under the scope of its grant"),
        }
    }
}

impl core::error::Error for Error {}

/// A prepared artifact: a signed result, such as a credential, that gives authority only after its transition commits.
/// It names its issuance record: the key and the version of the record that its transition writes. It has no public
/// constructor and no accessor of its bytes. [`Proposal::prepare`] takes it only for a proposal that writes its
/// issuance record, and only [`Receipt::artifact`] of the accepted proposal gives its bytes. Thus no caller can
/// release it before the commit, or with another transition. An artifact can be a bearer value, such as a bootstrap
/// value, so its memory is cleared when the receipt drops.
pub struct Prepared {
    bytes: SecretVec,
    record: Key,
    version: AuthorityVersion,
}

impl Prepared {
    /// The prepared artifact with the bytes `bytes`, whose transition writes the record `record` at `version`. It
    /// keeps the allocation of `bytes`, with no copy, and clears it when it drops.
    pub(crate) const fn new(bytes: Vec<u8>, record: Key, version: AuthorityVersion) -> Self {
        Self {
            bytes: SecretVec::from_vec(bytes),
            record,
            version,
        }
    }

    /// The bytes of the artifact.
    pub(crate) fn bytes(&self) -> &[u8] {
        self.bytes.as_bytes()
    }
}

impl fmt::Debug for Prepared {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("Prepared")
            .field("bytes", &Hidden(self.bytes()))
            .field("record", &self.record)
            .field("version", &self.version)
            .finish()
    }
}

/// Bytes that can hold a secret. `Debug` shows only their length.
struct Hidden<'a>(&'a [u8]);

impl fmt::Debug for Hidden<'_> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("Hidden").field("len", &self.0.len()).finish()
    }
}

#[cfg(test)]
mod tests;
