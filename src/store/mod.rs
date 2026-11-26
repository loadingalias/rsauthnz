//! The storage contract: the primitives that a storage binding of the application implements, and its declaration.
//!
//! rsauthnz ships no storage backend. A binding implements [`Store`]: keyed reads of the current state, bounded reads
//! of one key prefix, one conditional atomic commit of a [`Proposal`], the store instance number, and incremental
//! expiry. The outcome lookup [`Store::outcome`] reads the outcome record of the commit with a keyed read. The current
//! policy version of an owner is a record too ([`policy_key`]), so the commit checks it in the same atomic step. A
//! binding that supports restore also implements [`Journal`]: a durable append, a sync, and a read of the restore
//! journal. The commit driver of the core orders the primitives. A binding executes them and decides no step of the
//! protocol.
//!
//! A [`Declaration`] states the isolation, what a crash can lose, the outcome retention, crash injection, restore
//! support, and the key and record bounds of a binding. [`Profile::new`] refuses a binding without an atomic
//! conditional commit over the complete dependency set, and the commit driver ([`driver::Driver::new`]) takes only a
//! [`Profile`].
//!
//! The commit takes a proposal, and no primitive writes state, audit, or an outcome record in another way. Thus
//! state changes cannot commit without their audit and their outcome record:
//!
//! ```
//! use rsauthnz::store::{Commit, Instance, Store};
//! use rsauthnz::transition::Proposal;
//!
//! async fn accept<S: Store>(store: &mut S, proposal: &Proposal, instance: Instance) -> Result<Commit, S::Error> {
//!     store.commit(proposal, instance).await
//! }
//! ```
//!
//! State changes alone do not make a commit:
//!
//! ```compile_fail,E0308
//! use rsauthnz::store::{Commit, Instance, Store};
//! use rsauthnz::transition::Change;
//!
//! async fn write<S: Store>(store: &mut S, changes: &[Change], instance: Instance) -> Result<Commit, S::Error> {
//!     store.commit(changes, instance).await
//! }
//! ```

use alloc::boxed::Box;
use alloc::vec;
use alloc::vec::Vec;
use core::fmt;
use core::num::NonZeroUsize;
use core::time::Duration;

use crate::cbor::{self, Value};
use crate::crypto;
use crate::id::{Authority, AuthorityVersion, Id};
use crate::limits::Limits;
use crate::time::{Reading, ReadingSource, TimeError};
use crate::transition::{self, Change, Key, Operation, OperationId, Proposal, Recover, Recovery};

pub mod driver;
pub mod journal;

/// The failure of an operation that reads the store: a refusal `R` of the module of the operation, or a failed read with
/// the error `S` of the binding. Each module names it `Failure<E>` with its own refusal.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Failure<R, S> {
    /// The operation refused.
    Refused(R),
    /// A read failed. It is a crash of the binding: start the driver again.
    Store(S),
}

impl<R: Recover, S> Recover for Failure<R, S> {
    /// The recovery of the refusal, and [`Recovery::Restart`] after a failed read: nothing committed.
    fn recovery(&self) -> Recovery {
        match self {
            Self::Refused(error) => error.recovery(),
            Self::Store(_) => Recovery::Restart,
        }
    }
}

impl<R, S> From<R> for Failure<R, S> {
    fn from(error: R) -> Self {
        Self::Refused(error)
    }
}

impl<R: fmt::Display, S: fmt::Display> fmt::Display for Failure<R, S> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Refused(error) => error.fmt(f),
            Self::Store(error) => write!(f, "a read of the store failed: {error}"),
        }
    }
}

impl<R: core::error::Error, S: core::error::Error> core::error::Error for Failure<R, S> {}

/// The first item of the CBOR form of an audit record. Its number changes with the form.
const AUDIT_FORM: &str = "rsauthnz.store.audit.2";

/// The kind of a record in the store. The first byte of the key of a record names its kind ([`Kind::key`]).
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
#[repr(u8)]
pub enum Kind {
    /// A credential: a passkey, a CLI credential, or the credential of a workload or an agent.
    Credential = 1,
    /// The link of an account to the subject of an external identity provider.
    ProviderLink = 2,
    /// A pending passkey registration ceremony. Its consumption pays for an anchor.
    Registration = 3,
    /// A pending sign-in challenge, or the challenge of the next call of a CLI ([`crate::cli`]). Its consumption pays
    /// for no anchor.
    SignIn = 4,
    /// A pending login transaction of an external identity provider. Its consumption pays for an anchor.
    Login = 5,
    /// A pending enrollment request of a CLI. Its consumption pays for an anchor.
    CliEnrollment = 6,
    /// An invitation value. Its consumption pays for an anchor.
    Invitation = 7,
    /// A session family and its current generation.
    Session = 8,
    /// A recovery value. Its consumption pays for an anchor.
    Recovery = 9,
    /// A bootstrap value of an authority. Its consumption pays for an anchor.
    Bootstrap = 10,
    /// An administrator binding of an authority. It ends with its CLI credential, so expiry removes it.
    Administrator = 11,
    /// An agent identity.
    Agent = 12,
    /// A grant and its current revision.
    Grant = 13,
    /// A one-use approval of an operation. Its consumption pays for no anchor.
    Approval = 14,
    /// The replay record of one accepted signature, or of the challenge of one passkey sign-in.
    Replay = 15,
    /// The replay floor of the store. Each replay insert reads it.
    ReplayFloor = 16,
    /// The audit record of a commit ([`audit_record`]). Its key is the operation identity.
    Audit = 17,
    /// The outcome record of a commit ([`outcome_record`]). Its key is the operation identity.
    Outcome = 18,
    /// An effect intent that the application did not end yet ([`intent_records`]).
    Intent = 19,
    /// The current policy version of an owner ([`policy_key`]). A policy change is a commit that writes it.
    Policy = 20,
    /// The journal mark of the store: the low-water mark of its state, whether a restore made the state, the number
    /// of its write, and the completions that a restore still owes. The commit driver writes it, and it has no end.
    Mark = 21,
    /// The record of a local authority ([`crate::local`]): its host grant, its issuer key, and the log of its bootstrap
    /// values. Only an issue of a bootstrap value writes it, and it has no end.
    Local = 22,
    /// An issuer of workload credentials: its authority, its current key and its previous key, its audiences, and its
    /// ceiling ([`workload::Issuer`](crate::workload::Issuer)).
    Issuer = 23,
    /// The registration of a workload: its identifier, its registered proof key, and its generation
    /// ([`workload::Registration`](crate::workload::Registration)).
    Workload = 24,
    /// The removal mark of a passkey: a removal ended it, so a sign-in with it answers
    /// [`Recovery::Forget`]. Its key holds the identifier of the credential key,
    /// and it ends after [`REMOVAL_MARK_LIFETIME`](crate::account::REMOVAL_MARK_LIFETIME).
    Removal = 25,
    /// A durable recovery or enrollment revision of an account.
    AccountState = 26,
    /// A pending enrollment request of an agent ([`crate::agent`]). Its consumption pays for no anchor.
    AgentEnrollment = 27,
}

/// What the consumption of a one-use record pays for.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub enum Pays {
    /// An anchor, such as the passkey of an enrollment. The restore journal records the consumption, and a restore
    /// completes it when it is in doubt.
    Anchor,
    /// No anchor. The consumption has no journal entry, and a restore ends each pending record of the kind.
    Nothing,
}

impl Kind {
    /// Each kind, in the order of its number.
    pub const ALL: [Self; 27] = [
        Self::Credential,
        Self::ProviderLink,
        Self::Registration,
        Self::SignIn,
        Self::Login,
        Self::CliEnrollment,
        Self::Invitation,
        Self::Session,
        Self::Recovery,
        Self::Bootstrap,
        Self::Administrator,
        Self::Agent,
        Self::Grant,
        Self::Approval,
        Self::Replay,
        Self::ReplayFloor,
        Self::Audit,
        Self::Outcome,
        Self::Intent,
        Self::Policy,
        Self::Mark,
        Self::Local,
        Self::Issuer,
        Self::Workload,
        Self::Removal,
        Self::AccountState,
        Self::AgentEnrollment,
    ];

    /// What the consumption of a record of this kind pays for, or `None` for a kind that is not one-use.
    #[must_use]
    pub const fn consumption(&self) -> Option<Pays> {
        match self {
            Self::Registration
            | Self::Login
            | Self::CliEnrollment
            | Self::Invitation
            | Self::Recovery
            | Self::Bootstrap => Some(Pays::Anchor),
            Self::SignIn | Self::Approval | Self::AgentEnrollment => Some(Pays::Nothing),
            Self::Credential
            | Self::ProviderLink
            | Self::Session
            | Self::Administrator
            | Self::Agent
            | Self::Grant
            | Self::Replay
            | Self::ReplayFloor
            | Self::Audit
            | Self::Outcome
            | Self::Intent
            | Self::Policy
            | Self::Mark
            | Self::Local
            | Self::Issuer
            | Self::Workload
            | Self::Removal
            | Self::AccountState => None,
        }
    }

    /// Whether a record of this kind can have an end, so that expiry can remove it. An expiry pass makes no call for
    /// the other kinds, and a write of a record of another kind has no end.
    #[must_use]
    pub const fn ends(&self) -> bool {
        !matches!(
            self,
            Self::ProviderLink
                | Self::Agent
                | Self::ReplayFloor
                | Self::Intent
                | Self::Policy
                | Self::Mark
                | Self::Local
                | Self::Issuer
                | Self::Workload
                | Self::AccountState
        )
    }

    /// The key of the record `id` of this kind: the number of the kind, then `id`.
    ///
    /// Cost class: [`Parse`](crate::limits::Class::Parse).
    ///
    /// # Errors
    ///
    /// [`transition::Error::Key`] if `id` is longer than [`Key::BYTES_MAX`] minus one bytes.
    pub fn key(self, id: &[u8]) -> Result<Key, transition::Error> {
        // The kind is the first byte of the key. The check comes before the copy.
        (id.len() < Key::BYTES_MAX).ok_or(transition::Error::Key)?;
        let mut bytes = Vec::with_capacity(id.len() + 1);
        bytes.push(self as u8);
        bytes.extend_from_slice(id);
        Key::new(&bytes)
    }

    /// The kind of the record `key`, or `None` for a key that [`Kind::key`] did not make.
    ///
    /// Cost class: [`Parse`](crate::limits::Class::Parse).
    #[must_use]
    pub fn of(key: &Key) -> Option<Self> {
        let tag = *key.as_bytes().first()?;
        Self::ALL.into_iter().find(|kind| *kind as u8 == tag)
    }
}

/// The store instance number. Each start writes a new one, and each commit compares it, so a commit from an earlier
/// instance refuses.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct Instance(pub u64);

/// The sequence of a journal entry. The first entry has sequence 1.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct Sequence(pub u64);

/// A durable entry of the restore journal.
#[derive(Clone, PartialEq, Eq)]
pub struct Entry {
    /// The sequence.
    pub sequence: Sequence,
    /// The bytes of the entry. They hold record forms, which can hold a credential, so `Debug` shows only their length.
    pub data: Box<[u8]>,
}

impl fmt::Debug for Entry {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("Entry")
            .field("sequence", &self.sequence)
            .field("data_len", &self.data.len())
            .finish()
    }
}

/// The current state of one record.
#[derive(Clone, PartialEq, Eq)]
pub struct Record {
    /// The version.
    pub version: AuthorityVersion,
    /// The end of the record, from [`Change::Write`].
    pub end: Option<Duration>,
    /// The record form. It can hold a secret, so `Debug` shows only its length.
    pub data: Box<[u8]>,
}

impl fmt::Debug for Record {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("Record")
            .field("version", &self.version)
            .field("end", &self.end)
            .field("data_len", &self.data.len())
            .finish()
    }
}

/// The result of a conditional commit.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Commit {
    /// Each dependency held, and the commit wrote the changes, the audit, the intents, and the outcome record.
    Accepted,
    /// A dependency or the instance number did not hold, so the commit wrote nothing.
    Conflict,
    /// The store has an outcome record of the operation identity ([`outcome_of`]), so the commit wrote nothing. The
    /// commit driver answers the proposal from the record: the receipt of the first commit for the same request, and
    /// [`Error::Reuse`](crate::transition::Error::Reuse) for another one.
    Recorded(Operation),
}

/// The primitives of a storage binding. Each one executes one bounded effect. An error of a primitive is a crash: the
/// binding stops serving, does not retry it, and serves again only after a start. The commit driver orders the
/// primitives.
///
/// A method returns a future, and the core runs no executor. A binding that does no I/O gives futures that are ready
/// at once. A binding with asynchronous I/O awaits it in its futures. A caller that is generic over `Store` and needs
/// `Send` futures names its concrete binding: return-type notation (`S: Store<commit(..): Send>`) is not stable on
/// the pinned toolchain.
pub trait Store {
    /// The cause of a failed primitive.
    type Error: core::error::Error;

    /// The declaration of the binding.
    fn declaration(&self) -> Declaration;

    /// Writes the next store instance number durably, before reconciliation, and gives it. Keep the number where a
    /// restore cannot lower it, for example in the failure domain of the journal: a restored lower number lets a
    /// delayed commit of the abandoned history land.
    fn start(&mut self) -> impl Future<Output = Result<Instance, Self::Error>>;

    /// Reads the current state of the record `key`, or `None` when no record has the key. It is a keyed read: it
    /// never scans other records. The proposal lists the result as a dependency: a version, or an absence.
    fn read(&mut self, key: &Key) -> impl Future<Output = Result<Option<Record>, Self::Error>>;

    /// Reads both keys from one store state. Each result occupies the position of its key, including an absent
    /// or repeated key. Use one indexed query or hold one read lock across both lookups.
    fn read_pair(&mut self, keys: [&Key; 2]) -> impl Future<Output = Result<[Option<Record>; 2], Self::Error>>;

    /// The conditional atomic commit of `proposal`, in one serializable step, or in one equivalent atomic step that
    /// checks the complete dependency set.
    ///
    /// The commit checks that `instance` is the current store instance number, that each dependency holds, and that
    /// no outcome record has the operation identity. A [`Dependency::Version`](transition::Dependency::Version) holds
    /// when its record is at its version, a [`Dependency::Policy`](transition::Dependency::Policy) when the policy
    /// record of its owner ([`policy_key`]) is at its version, and a
    /// [`Dependency::Absent`](transition::Dependency::Absent) when no record has its key. Then the commit writes each
    /// change, the audit record of [`audit_record`], each intent record of [`intent_records`], and the outcome record
    /// of [`outcome_record`] together. Otherwise it writes nothing. A commit is durable when it returns `Accepted`.
    /// An error is a crash, with an unknown outcome.
    ///
    /// An outcome record of the operation identity gives [`Commit::Recorded`], also when a dependency does not hold: a
    /// second submission of a commit never finds its own dependencies.
    fn commit(&mut self, proposal: &Proposal, instance: Instance) -> impl Future<Output = Result<Commit, Self::Error>>;

    /// The outcome record of the operation identity `id`, or `None` when the store has none. It reads the record of
    /// [`outcome_record`] with [`Store::read`], so a binding implements no other primitive for it. A record in another
    /// form gives `None`.
    fn outcome(&mut self, id: &OperationId) -> impl Future<Output = Result<Option<Operation>, Self::Error>> {
        async move {
            let key = Kind::Outcome
                .key(id.as_bytes())
                .expect("an operation identity of at most 64 bytes makes a valid key");
            let record = self.read(&key).await?;
            Ok(record.and_then(|record| outcome_of(id, &record)))
        }
    }

    /// Removes at most `limit` records of `kind` whose end is before `before`, and gives their number. The binding
    /// sets the end of each audit and outcome record from its retention.
    fn expire(
        &mut self,
        kind: Kind,
        before: Duration,
        limit: NonZeroUsize,
    ) -> impl Future<Output = Result<usize, Self::Error>>;

    /// Reads the first `limit` records whose key starts with `prefix` and comes after `after`, in key order. With
    /// `None`, it starts at the first key of the prefix. It gives fewer only when no more remain, and never a record of
    /// another prefix. A prefix is the key of a kind alone, such as the prefix of the intent records ([`Kind::Intent`])
    /// that a worker reads after a crash. It can also be a kind and a 32-byte digest of an owner, such as the prefix of
    /// the administrator bindings of one local authority.
    fn range(
        &mut self,
        prefix: &Key,
        after: Option<&Key>,
        limit: NonZeroUsize,
    ) -> impl Future<Output = Result<Vec<(Key, Record)>, Self::Error>>;
}

/// The restore journal of a binding that supports restore: a durable log in its own failure domain.
pub trait Journal {
    /// The cause of a failed primitive.
    type Error: core::error::Error;

    /// Appends `entry` after the last entry and gives its sequence. The entry is durable only after a later sync
    /// returns.
    fn append(&mut self, entry: &[u8]) -> impl Future<Output = Result<Sequence, Self::Error>>;

    /// Makes each earlier append durable. A failed sync is a crash: the kernel can drop the data and clear the
    /// error, so a retry that succeeds does not show that the data is durable.
    fn sync(&mut self) -> impl Future<Output = Result<(), Self::Error>>;

    /// Reads at most `limit` durable entries after `after`, in the order of their sequences.
    fn read(&mut self, after: Sequence, limit: NonZeroUsize) -> impl Future<Output = Result<Vec<Entry>, Self::Error>>;
}

/// The declaration of a storage binding.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Declaration {
    /// The isolation of the commit.
    pub isolation: Isolation,
    /// What a crash can lose.
    pub crash_loss: CrashLoss,
    /// The least time after the audit time of its proposal for which the binding keeps an audit and an outcome record.
    /// A lookup after it gives an unknown outcome.
    pub outcome_retention: Duration,
    /// Whether the binding can inject a crash at each commit point for the conformance suite.
    pub crash_injection: CrashInjection,
    /// Restore support.
    pub restore: Restore,
    /// The most bytes in a key that the binding stores. It must be at least [`Key::BYTES_MAX`].
    pub key_bytes_max: usize,
    /// The most bytes in one record that the binding stores: the record form of a write, an intent record, an audit
    /// record, or an outcome record. A proposal with a larger one refuses before the commit ([`Profile::admit`]):
    /// [`driver::Driver::submit`] refuses it, so the binding never gets it.
    ///
    /// The least bound is [`driver::record_bytes_min`] of the limits of the driver, because the driver writes records
    /// of its own. [`driver::Driver::new`] refuses a smaller bound with [`driver::Error::RecordBound`].
    pub record_bytes_max: usize,
}

/// The isolation of a commit.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub enum Isolation {
    /// Serializable isolation.
    Serializable,
    /// An atomic conditional commit that checks the complete dependency set, absences included, in one step.
    AtomicConditional,
    /// Snapshot isolation or weaker. It permits write skew on an absence, so a profile refuses it.
    Weaker,
}

/// What a crash can lose.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub enum CrashLoss {
    /// Only the writes whose commit or sync did not return.
    Unsynced,
    /// All state: the store is in the memory of the process.
    Everything,
}

/// Whether a binding can inject crashes.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub enum CrashInjection {
    /// The binding injects a crash at each commit point.
    Supported,
    /// The binding carries its own durability evidence.
    Unsupported,
}

/// Restore support.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Restore {
    /// The binding has no journal, and its restore refuses.
    Unsupported,
    /// The binding implements [`Journal`].
    Journal {
        /// Where the journal is, for example a bucket or a host.
        location: Box<str>,
        /// The failure domain of the journal, outside the failure domain of the snapshots that it protects.
        failure_domain: Box<str>,
    },
}

/// The declaration of a binding that the core accepts.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Profile(Declaration);

impl Profile {
    /// Accepts the declaration of a binding.
    ///
    /// Cost class: [`Parse`](crate::limits::Class::Parse).
    ///
    /// # Errors
    ///
    /// [`Error::Isolation`] for [`Isolation::Weaker`], and [`Error::KeyBound`] for a key bound below
    /// [`Key::BYTES_MAX`].
    pub fn new(declaration: Declaration) -> Result<Self, Error> {
        if declaration.isolation == Isolation::Weaker {
            return Err(Error::Isolation);
        }
        (declaration.key_bytes_max >= Key::BYTES_MAX).ok_or(Error::KeyBound)?;
        Ok(Self(declaration))
    }

    /// The declaration.
    #[must_use]
    pub const fn declaration(&self) -> &Declaration {
        &self.0
    }

    /// Checks that the binding stores each record that the commit of `proposal` writes, before its commit: the record
    /// form of each write, each record of [`intent_records`], and the records of [`audit_record`] and
    /// [`outcome_record`]. The audit record holds the key of each change, so it grows with the changes.
    ///
    /// Cost class: [`Parse`](crate::limits::Class::Parse).
    ///
    /// # Errors
    ///
    /// [`Error::RecordBytes`] for a record longer than [`Declaration::record_bytes_max`].
    pub fn admit(&self, proposal: &Proposal) -> Result<(), Error> {
        let fits = |data: &[u8]| data.len() <= self.0.record_bytes_max;
        let writes = proposal.changes().iter().all(|change| match change {
            Change::Write { data, .. } => fits(data),
            Change::End(_) => true,
        });
        let intents = intent_records(proposal).expect("an intent has a CBOR form and a key of at most 73 bytes");
        let records = [audit_record(proposal), outcome_record(proposal)];
        let stored = intents.iter().chain(&records).all(|(_, record)| fits(&record.data));
        (writes && stored).ok_or(Error::RecordBytes)
    }
}

/// The cause of a refused declaration or proposal.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Error {
    /// The commit of the binding is not atomic over the complete dependency set. Use a binding with serializable
    /// isolation or an atomic conditional commit.
    Isolation,
    /// The binding stores no key of [`Key::BYTES_MAX`] bytes. Use a binding with a larger key bound.
    KeyBound,
    /// A record that the commit of the proposal writes is longer than the record bound of the binding. Refuse the
    /// request.
    RecordBytes,
}

impl fmt::Display for Error {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(match self {
            Self::Isolation => "the commit of the binding is not atomic over its dependencies",
            Self::KeyBound => "the binding cannot store each key of the core",
            Self::RecordBytes => "a record is larger than the record bound of the binding",
        })
    }
}

impl core::error::Error for Error {}

/// The progress of an expiry pass.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub enum Progress {
    /// No kind has an ended record left.
    Done,
    /// A kind can have more ended records. Run another pass.
    More,
}

/// The cause of a failed expiry pass.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum ExpiryError<E> {
    /// The reading has no known bound, so no record expires.
    Time(TimeError),
    /// The binding failed.
    Store(E),
}

/// The key of the policy record of `owner`, which holds the current policy version of the owner: [`Kind::Policy`] with
/// the SHA-256 digest of the canonical CBOR form of `owner`. The digest keeps the key short, because an owner can be
/// longer than a key. A commit checks each [`Dependency::Policy`](transition::Dependency::Policy) against this record.
/// A policy change is a commit whose proposal reads this record and writes it at the new version.
///
/// Cost class: [`Parse`](crate::limits::Class::Parse).
#[must_use]
pub fn policy_key(owner: &Id<Authority>) -> Key {
    let form =
        cbor::encode(&owner.to_cbor(), Limits::FORM).expect("the form of an identifier has no map and no simple value");
    Kind::Policy
        .key(&crypto::sha256(&form))
        .expect("a key of 33 bytes is valid")
}

/// The version of each record of `owner` that only the commit writes: an audit or an outcome record. The commit
/// writes such a record one time, so its version is always the same.
fn written_once(owner: &str) -> AuthorityVersion {
    let owner = Id::new("rsauthnz", owner).expect("the owner of a record version is a valid identifier");
    AuthorityVersion::new(owner, &[1]).expect("a one-byte coordinate is valid")
}

/// The outcome record of `proposal`, which its commit writes. Its key is [`Kind::Outcome`] with the operation identity,
/// and its record form is the request binding of [`Proposal::operation`]: 32 bytes. [`Store::outcome`] reads it. The
/// record has no end: the binding sets the end from its retention.
///
/// Cost class: [`Parse`](crate::limits::Class::Parse).
#[must_use]
pub fn outcome_record(proposal: &Proposal) -> (Key, Record) {
    let operation = proposal.operation();
    let key = Kind::Outcome
        .key(operation.id.as_bytes())
        .expect("an operation identity of at most 64 bytes makes a valid key");
    let record = Record {
        version: written_once("outcome"),
        end: None,
        data: operation.binding.into(),
    };
    (key, record)
}

/// The operation of the outcome record `record` of the operation identity `id`, or `None` when `record` does not have
/// the form of [`outcome_record`]. A binding gives it in [`Commit::Recorded`].
///
/// Cost class: [`Parse`](crate::limits::Class::Parse).
#[must_use]
pub fn outcome_of(id: &OperationId, record: &Record) -> Option<Operation> {
    Some(Operation {
        id: id.clone(),
        binding: (*record.data).try_into().ok()?,
    })
}

/// The audit record of `proposal`, which its commit writes. Its key is [`Kind::Audit`] with the operation identity,
/// so [`Store::read`] finds the audit of a commit. Its record form is the CBOR array `["rsauthnz.store.audit.2",
/// actor, owner, action, time, keys]`:
///
/// - `actor` and `action` are the canonical forms of [`Audit::actor`](transition::Audit::actor) and
///   [`Audit::action`](transition::Audit::action).
/// - `owner` is the canonical form of the human owner of an agent actor ([`Proposal::owner`]), or null for a human, a
///   workload, or the enrollment request of an agent that has no owner yet.
/// - `time` is `[estimate, bound, source]` of the reading. The estimate and the bound are `[seconds, nanoseconds]`,
///   and the bound is null when it is unknown. The source is 1 for the system clock, 2 for the caller, and 0 for
///   another source.
/// - `keys` is the key of each change of the proposal, in order.
///
/// The record has no end: the binding sets the end from its retention.
///
/// Cost class: [`Parse`](crate::limits::Class::Parse).
#[must_use]
pub fn audit_record(proposal: &Proposal) -> (Key, Record) {
    let duration = |duration: Duration| {
        Value::Array(vec![
            Value::Unsigned(duration.as_secs()),
            Value::Unsigned(u64::from(duration.subsec_nanos())),
        ])
    };
    let audit = proposal.audit();
    let time = audit.time;
    let source = match time.source() {
        ReadingSource::SystemClock => 1,
        ReadingSource::Caller => 2,
        _ => 0,
    };
    let form = Value::Array(vec![
        Value::Text(AUDIT_FORM),
        audit.actor.to_cbor(),
        proposal.owner().map_or(Value::Null, Id::to_cbor),
        audit.action.to_cbor(),
        Value::Array(vec![
            duration(time.estimate()),
            time.bound().map_or(Value::Null, duration),
            Value::Unsigned(source),
        ]),
        Value::Array(
            proposal
                .changes()
                .iter()
                .map(|change| Value::Bytes(change.key().as_bytes()))
                .collect(),
        ),
    ]);
    let key = Kind::Audit
        .key(proposal.operation().id.as_bytes())
        .expect("an operation identity of at most 64 bytes makes a valid key");
    let data = cbor::encode(&form, Limits::FORM).expect("the audit form has no map and no simple value");
    (
        key,
        Record {
            version: written_once("audit"),
            end: None,
            data: data.into_boxed_slice(),
        },
    )
}

/// The intent records of `proposal`, which its commit writes: the key of each intent is its operation identity and its
/// index, and its record has the version and the CBOR form of the intent. A worker that changes the state of an
/// intent reads this key at [`Intent::version`](transition::Intent::version), and writes it at the version of the new
/// state, or ends it after it observes the end of the call.
///
/// Cost class: [`Parse`](crate::limits::Class::Parse).
///
/// # Errors
///
/// [`transition::Error::Intent`] if an intent has no CBOR encoding.
pub fn intent_records(proposal: &Proposal) -> Result<Vec<(Key, Record)>, transition::Error> {
    let id = proposal.operation().id.as_bytes();
    let mut records = Vec::with_capacity(proposal.intents().len());
    for (index, intent) in (0_u64..).zip(proposal.intents()) {
        let key = Kind::Intent.key(&[id, &index.to_be_bytes()].concat())?;
        let data = cbor::encode(&intent.to_cbor(), Limits::FORM).map_err(|_| transition::Error::Intent)?;
        records.push((
            key,
            Record {
                version: intent.version(),
                end: None,
                data: data.into_boxed_slice(),
            },
        ));
    }
    Ok(records)
}

/// One bounded expiry pass: for each kind that can end, one call of [`Store::expire`] that removes at most `limit` records whose
/// end is before the earliest time of `now`. A record that a check can still accept at `now` stays.
///
/// Cost class: [`Mutate`](crate::limits::Class::Mutate). A pass makes one call for each kind that can end, so the host bounds its
/// work with `limit`.
///
/// # Errors
///
/// [`ExpiryError::Time`] if `now` has no known bound, and [`ExpiryError::Store`] if a call fails.
///
/// ```
/// use core::num::NonZeroUsize;
///
/// use rsauthnz::store::{self, ExpiryError, Progress, Store};
/// use rsauthnz::time::Reading;
///
/// /// At most 100 records of each kind in one pass.
/// const LIMIT: NonZeroUsize = NonZeroUsize::new(100).unwrap();
///
/// /// Removes each ended record, one bounded pass after the other.
/// async fn expire_all<S: Store>(binding: &mut S, now: Reading) -> Result<(), ExpiryError<S::Error>> {
///     while store::expire(binding, now, LIMIT).await? == Progress::More {}
///     Ok(())
/// }
/// ```
pub async fn expire<S: Store>(
    store: &mut S,
    now: Reading,
    limit: NonZeroUsize,
) -> Result<Progress, ExpiryError<S::Error>> {
    let before = now.earliest().map_err(ExpiryError::Time)?;
    let mut progress = Progress::Done;
    for kind in Kind::ALL.into_iter().filter(Kind::ends) {
        let removed = store.expire(kind, before, limit).await.map_err(ExpiryError::Store)?;
        if removed >= limit.get() {
            progress = Progress::More;
        }
    }
    Ok(progress)
}

#[cfg(test)]
mod tests;
