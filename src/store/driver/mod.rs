//! The commit driver: the one sequencer of the storage protocol, as a sans-I/O state machine over the primitives of a
//! binding.
//!
//! The driver orders the journal entries, the conditional commits, the owner turns, the voids, the creation entries,
//! the acknowledgements, fencing, reconciliation, restore, and the completion of in-doubt consumptions. It does no I/O.
//! [`Driver::effect`] gives the next primitive call, an [`Effect`], and the binding executes it and gives the
//! [`Output`] to [`Driver::give`]. Thus the driver gives the binding one bounded effect at a time:
//!
//! ```
//! use rsauthnz::store::driver::{Driver, Effect, Output};
//!
//! /// Executes each effect of `driver` until it has none. `execute` stands for the primitives of a binding.
//! fn run(driver: &mut Driver, mut execute: impl FnMut(Effect<'_>) -> Output) {
//!     while let Some(effect) = driver.effect() {
//!         let output = execute(effect);
//!         driver.give(output).expect("the output answers its effect");
//!     }
//! }
//! ```
//!
//! Several application servers can each run a driver on one store. Each driver runs one operation at a time, in the
//! order of its requests. An operation is a commit ([`Driver::submit`]), a lookup ([`Driver::lookup`]), a recovery
//! ([`Driver::recover`]), a start ([`Driver::start`]), a restore ([`Driver::restore`]), or a move of the mark
//! ([`Driver::advance`]). The drivers coordinate only at the store and at the journal:
//!
//! - A start joins the open store instance with no write, so a server that starts leaves its peers serving. It
//!   activates a fresh instance only when no instance is open ([`Driver::start`]).
//! - An anchor change, such as the removal of a passkey, holds the turn of each owner of its anchors in the store
//!   from its first effect to its last ([`Kind::Turn`]). Its commit reads and advances those turns, so the anchor
//!   changes of one owner run one at a time on all servers. A peer finishes or retires the turn of a server that
//!   stopped.
//! - Each append compares the instance and the head of the journal. After a conflict, the driver reads the new entries
//!   and appends again.
//! - Each driver allocates values from its own block of the counter ([`Driver::allocate`]), which the journal reserves
//!   before any use.
//!
//! An error of a primitive ([`Output::Failed`]) is a crash: the driver stops, gives an unknown outcome to the
//! operation in progress, and serves again only after a start. That start settles the work of the operation that the
//! crash cut. The mark record ([`Kind::Mark`]) holds the low-water mark, the restore instance, and the consumptions
//! that still need completion. The replay floor names the instance only after recovery finishes. Until then, the next
//! start resumes cleanup and completion.
//!
//! After a restore of a snapshot, call [`Driver::restore`], never [`Driver::start`]: a start voids the entries that a
//! restore applies. A start refuses with [`Error::Restored`] when the journal shows a commit that the store lost: a
//! later write of the mark record, whose number a floor entry of [`Kind::Mark`] records after each write, or the
//! creation entry of an anchor with no end that the store lacks. A crash loses no commit, so it gives no refusal.
//!
//! Limit: a start cannot detect a restore of a snapshot that is newer than the last write of the mark record, when
//! only commits with no creation entry, such as an unlink or a renewal, followed the snapshot. The journal holds no
//! proof that such a commit landed, so its loss looks the same as a crash before the commit.

mod advance;
mod commit;
mod help;
pub(crate) mod record;
mod start;
mod turn;

use alloc::collections::{BTreeMap, BTreeSet, VecDeque};
use alloc::vec::Vec;
use core::fmt;
use core::num::{NonZeroU64, NonZeroUsize};
use core::time::Duration;

use rscrypto::ChaCha20Rng;

pub use super::journal::AlphaSource;
use super::journal::{self, Anchor, Body, History, Mark, Reads};
use super::{Commit, Instance, JournalWrite, Kind, Profile, Record, Restore, Sequence, outcome_of};
use crate::cbor;
use crate::id::AuthorityVersion;
use crate::limits::Limits;
use crate::time::Reading;
use crate::transition::{
    self, Change, Dependency, Intent, Key, Operation, OperationId, Outcome, Proposal, Receipt, Recover, Recovery,
};
use advance::Advance;
use commit::Submitted;
use help::{Looking, Recovering, Reserving};
use start::{Begin, Start};

/// The most journal entries after the mark that the driver reads or keeps. A start refuses a longer journal with
/// [`Error::Long`]. The driver moves the mark before it keeps more ([`ADVANCE_AT`]).
pub const JOURNAL_ENTRIES_MAX: usize = 65_536;

/// The journal entries after the last move of the mark at which the driver moves the mark again after an operation.
pub const ADVANCE_AT: usize = JOURNAL_ENTRIES_MAX / 4;

/// The most operations that wait for the driver. A request past it refuses with [`Error::Full`].
pub const QUEUE_MAX: usize = 1_024;

/// The values of the counter in one block. A driver holds one block in use and one spare block. The journal reserves
/// each block before the driver gives a value of it.
pub const FLOOR_BLOCK: NonZeroU64 = NonZeroU64::new(1_024).expect("the block is not zero");

/// The most entries, intents, or records of one read or expiry call.
pub const PAGE: NonZeroUsize = NonZeroUsize::new(256).expect("the page is not zero");

/// The time after the latest audit time of an anchor change at which a peer retires its held turn: the change runs
/// on a server that stopped, or it is slow. A retirement refuses the change, which is safe, so the time gives only
/// progress. A peer finishes a turn whose change committed, and retires the turn of a closed change, at once.
pub const TURN_PATIENCE: Duration = Duration::from_secs(30);

/// The most conflicting appends of one journal write. Each conflict reads the new entries of the peers.
const WRITE_ATTEMPTS: u32 = 64;

/// The most reservations of the owner turns of one anchor change, each after a peer released or retired a turn.
const TURN_ROUNDS: u32 = 4;

/// The kind that the floor entries of the one counter of the driver name. An earlier journal can have a floor for each
/// kind, and the counter starts above the highest of them.
const COUNTER: Kind = Kind::Credential;

/// The least record bound ([`Declaration::record_bytes_max`](super::Declaration::record_bytes_max)) of a binding for
/// a driver with `limits`: the most bytes in a record that the driver writes for itself. These are the mark record,
/// the replay floor, the turn records, the anchors of a restore and of a completion, and the audit record of each of
/// its commits. The audit record holds the key of each change, so the bound grows with [`Limits::dependencies`].
///
/// Cost class: [`Parse`](crate::limits::Class::Parse).
#[must_use]
pub fn record_bytes_min(limits: Limits) -> usize {
    record::bytes_max(limits)
}

/// The identity of an operation that the driver runs. [`Driver::take`] gives its answer.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct Ticket(u64);

/// A primitive call that the binding executes.
pub enum Effect<'a> {
    /// [`Store::start`](super::Store::start). Give [`Output::Started`].
    Start,
    /// [`Store::instance`](super::Store::instance). Give [`Output::Instance`].
    Instance,
    /// [`Store::read`](super::Store::read) of the key. Give [`Output::Read`].
    Read(&'a Key),
    /// [`Store::commit`](super::Store::commit) of the proposal with the instance number. Give [`Output::Committed`].
    Commit(&'a Proposal, Instance),
    /// [`Store::expire`](super::Store::expire). Give [`Output::Expired`].
    Expire(Kind, Duration, NonZeroUsize, Instance),
    /// [`Store::range`](super::Store::range) of the prefix after the key. Give [`Output::Range`].
    Range(&'a Key, Option<&'a Key>, NonZeroUsize),
    /// [`Journal::append`](super::Journal::append) of the entry. Give [`Output::Appended`].
    Append(&'a journal::Append, Instance),
    /// [`Journal::sync`](super::Journal::sync). Give [`Output::Synced`].
    Sync(Instance),
    /// [`Journal::read`](super::Journal::read) after the sequence. Give [`Output::Journal`].
    ReadJournal(Sequence, NonZeroUsize),
}

// A journal entry holds record forms, which can hold a credential, so the output shows only the length of an entry.
impl fmt::Debug for Effect<'_> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Start => f.write_str("Start"),
            Self::Instance => f.write_str("Instance"),
            Self::Read(key) => f.debug_tuple("Read").field(key).finish(),
            Self::Commit(proposal, instance) => f.debug_tuple("Commit").field(proposal).field(instance).finish(),
            Self::Expire(kind, now, limit, instance) => f
                .debug_tuple("Expire")
                .field(kind)
                .field(now)
                .field(limit)
                .field(instance)
                .finish(),
            Self::Range(prefix, after, limit) => {
                f.debug_tuple("Range").field(prefix).field(after).field(limit).finish()
            }
            Self::Append(append, instance) => f.debug_tuple("Append").field(append.entry()).field(instance).finish(),
            Self::Sync(instance) => f.debug_tuple("Sync").field(instance).finish(),
            Self::ReadJournal(after, limit) => f.debug_tuple("ReadJournal").field(after).field(limit).finish(),
        }
    }
}

/// The result of an [`Effect`].
#[derive(Debug)]
pub enum Output {
    /// The instance number of the start.
    Started(Instance),
    /// The installed instance number.
    Instance(Instance),
    /// The record of the read.
    Read(Option<Record>),
    /// The result of the commit.
    Committed(Commit),
    /// The deletion result for the requested instance.
    Expired(super::Expiry),
    /// The records of the range.
    Range(Vec<(Key, Record)>),
    /// The journal's conditional append result.
    Appended(JournalWrite),
    /// The journal's conditional sync result.
    Synced(JournalWrite),
    /// The journal entries.
    Journal(Vec<super::Entry>),
    /// The primitive failed. It is a crash, and the binding does not retry it.
    Failed,
}

/// What the driver needs with a proposal: the anchors of its owners, and the role of each write of the proposal.
#[derive(Clone, Debug, Default)]
pub struct Plan {
    /// Each anchor of each owner whose anchor the proposal ends, as the store holds it.
    pub held: Vec<Anchor>,
    /// The keys of the writes that replace a dead version, such as a session renewal or a grant change.
    pub replaced: Vec<Key>,
    /// The role of each anchor that the proposal creates.
    pub anchors: Vec<(Key, journal::Role)>,
}

/// The answer of an operation of the driver.
#[derive(Debug)]
pub enum Answer {
    /// The outcome of a commit. An operation in progress at a crash gets [`Outcome::Unknown`].
    Outcome(Outcome),
    /// The result of a lookup.
    Lookup(Lookup),
    /// The result of a recovery.
    Recovered(Recovered),
}

/// The result of a lookup of an operation.
#[derive(Debug)]
pub enum Lookup {
    /// The operation committed. The receipt has no artifact.
    Committed(Receipt),
    /// The store has the outcome record of another request with the identity, or recovery closed the identity
    /// ([`transition::Error::Closed`]).
    Refused(transition::Error),
    /// No retained outcome establishes the result. Keep the original operation in doubt.
    Unknown,
}

/// The result of a recovery of an operation after a lost reply ([`Driver::recover`]).
#[derive(Debug)]
pub enum Recovered {
    /// The operation committed. The receipt has no artifact: the store never keeps the artifact, so recovery releases
    /// no second copy of a secret.
    Committed(Receipt),
    /// The operation never committed, and it can never commit. Start the request again with a fresh identity.
    Fresh,
    /// The store has the outcome record of another request with the identity.
    Refused(transition::Error),
    /// The evidence cannot establish a decision: a restore or a start changed the instance, or the retention of the
    /// outcome record can have ended. Keep the original operation in doubt.
    Unknown,
}

/// The recovery handle of an operation: what a recovery needs after a lost reply ([`Driver::recover`]). Take it with
/// [`Driver::handle`] before the first effect of the operation, and keep it where a peer can read it, such as in the
/// state of the client. It holds no secret.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Handle {
    /// The operation identity and its request binding.
    pub operation: Operation,
    /// The store instance in which the driver submits the operation.
    pub instance: Instance,
    /// The estimate of the audit time of the proposal. The binding keeps the outcome record for its retention after it.
    pub time: Duration,
}

/// The state of the driver.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Status {
    /// The driver serves no operation: it has no start yet, or a crash stopped it. Call [`Driver::start`].
    Down,
    /// A start or a restore is in progress.
    Starting,
    /// The driver serves operations.
    Serving,
    /// A start or a restore refused, and the driver serves nothing. The error names the cause and its recovery.
    Refused(Error),
}

/// The cause of a refused request or a stopped driver.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Error {
    /// The binding declares no restore support, so a restore refuses.
    Unsupported,
    /// The journal refused: it does not reach back to the mark, it has a gap, or an entry changed. Restore from
    /// another snapshot, or repair the journal.
    Journal(journal::Error),
    /// The journal has more than [`JOURNAL_ENTRIES_MAX`] entries after the mark. Restore from a newer snapshot.
    Long,
    /// [`QUEUE_MAX`] operations wait. Refuse the request, and retry it later.
    Full,
    /// The proposal refuses. The error gives the recovery.
    Transition(transition::Error),
    /// The record bound of the binding is below this number of bytes, the least bound for the limits of the driver
    /// ([`record_bytes_min`]). Use a binding with a larger record bound, or smaller limits.
    RecordBound(usize),
    /// A record that the commit of the proposal writes is longer than the record bound of the binding
    /// ([`Profile::admit`]). Refuse the request.
    RecordBytes,
    /// The driver serves no operation yet. Call [`Driver::start`].
    Down,
    /// A counter is past its largest value.
    Overflow,
    /// No reserved value of the counter is left. The driver reserves another block: retry the request.
    Exhausted,
    /// A destination refused the instance or journal predecessor. Reconcile before serving more work.
    Superseded,
    /// The binding returned an unexpected output or refused an internal commit.
    Binding,
    /// A storage record has an invalid form or version.
    Record,
    /// The alpha journal and primary need operator review at `sequence`. Admission stays closed.
    /// Pass `instance` to [`Driver::resolve_alpha`] after verifying the origin of the primary.
    AlphaReview {
        /// The storage instance that fenced writes for this review.
        instance: Instance,
        /// The verified journal entry to inspect.
        sequence: Sequence,
    },
    /// The store state is older than its journal: a restore made it. Call [`Driver::restore`], not
    /// [`Driver::start`].
    Restored,
}

impl Recover for Error {
    /// The recovery of a call that commits nothing when it refuses, such as [`Driver::submit`]. A refused lookup of an
    /// operation in doubt is an [`InDoubt`], with its own recovery. The recovery of the proposal after
    /// [`Error::Transition`]. [`Recovery::Restart`] after [`Error::Full`], [`Error::Exhausted`], and [`Error::Down`]:
    /// nothing committed, and the driver serves the operation later. [`Recovery::Refuse`] after each other error: the
    /// record bound, a counter, the binding, or the state of the store refuses the request until the operator acts.
    fn recovery(&self) -> Recovery {
        match self {
            Self::Transition(error) => error.recovery(),
            Self::Full | Self::Exhausted | Self::Down => Recovery::Restart,
            Self::Unsupported
            | Self::Journal(_)
            | Self::Long
            | Self::RecordBound(_)
            | Self::RecordBytes
            | Self::Overflow
            | Self::Superseded
            | Self::Binding
            | Self::Record
            | Self::AlphaReview { .. }
            | Self::Restored => Recovery::Refuse,
        }
    }
}

/// A lookup or a recovery that the driver refused ([`Driver::lookup`], [`Driver::recover`]). The operation stays in
/// doubt: its first attempt can have committed. Look it up again when the driver serves, and never propose it again
/// as a new operation.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct InDoubt(pub Error);

impl Recover for InDoubt {
    /// [`Recovery::Lookup`], whatever the error of the driver: the first attempt can have committed.
    fn recovery(&self) -> Recovery {
        Recovery::Lookup
    }
}

impl fmt::Display for InDoubt {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "the lookup refused, and the operation stays in doubt: {}", self.0)
    }
}

impl core::error::Error for InDoubt {}

impl fmt::Display for Error {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Unsupported => f.write_str("the binding declares no restore support"),
            Self::Journal(error) => write!(f, "the journal refused: {error}"),
            Self::Long => f.write_str("the journal has too many entries after the mark"),
            Self::Full => f.write_str("too many operations wait for the driver"),
            Self::Transition(error) => write!(f, "the proposal refused: {error}"),
            Self::RecordBound(bytes) => write!(f, "the record bound of the binding is below {bytes} bytes"),
            Self::RecordBytes => f.write_str("a record of the proposal is larger than the record bound of the binding"),
            Self::Down => f.write_str("the driver serves no operation yet"),
            Self::Overflow => f.write_str("a counter is past its largest value"),
            Self::Exhausted => f.write_str("no reserved value of the counter is left, so retry the request"),
            Self::Superseded => f.write_str("the storage instance or journal head changed"),
            Self::Binding => f.write_str("the binding gave an output that the driver did not ask for"),
            Self::Record => f.write_str("a storage record has an invalid form or version"),
            Self::AlphaReview { instance, sequence } => write!(
                f,
                "review alpha journal entry {} for storage instance {} before opening admission",
                sequence.0, instance.0
            ),
            Self::Restored => f.write_str("the store state is older than its journal: call restore, not start"),
        }
    }
}

impl core::error::Error for Error {}

impl From<journal::Error> for Error {
    fn from(error: journal::Error) -> Self {
        Self::Journal(error)
    }
}

/// The reserved values of the counter of a driver: the block in use and the spare block.
#[derive(Clone, Copy, Debug)]
struct Counter {
    /// The next value of the block in use. The block is used up when it is past `last`.
    next: u64,
    /// The last value of the block in use.
    last: u64,
    /// The first and the last value of the spare block.
    spare: Option<(u64, u64)>,
}

impl Counter {
    /// No reserved value.
    const EMPTY: Self = Self {
        next: 1,
        last: 0,
        spare: None,
    };

    /// The next reserved value above `after`. Each value at or below `after` is obsolete, so it discards it.
    fn take(&mut self, after: u64) -> Option<u64> {
        let least = after.checked_add(1)?;
        loop {
            let value = self.next.max(least);
            if value <= self.last {
                self.next = value.checked_add(1)?;
                return Some(value);
            }
            let (first, last) = self.spare.take()?;
            self.next = first;
            self.last = last;
        }
    }

    /// Discards each value at or below `after`, and keeps the next value for the next call of [`Self::take`].
    fn skip(&mut self, after: u64) {
        match self.take(after) {
            Some(value) => self.next = value,
            // Each reserved value is obsolete, so the next reservation gives the block in use.
            None => self.next = self.last.saturating_add(1),
        }
    }

    /// Adds the reserved block from `first` to `last`.
    fn add(&mut self, first: u64, last: u64) {
        if self.next > self.last {
            self.next = first;
            self.last = last;
        } else {
            self.spare = Some((first, last));
        }
    }
}

/// An operation of this driver that a crash cut. The next start of the driver settles its work at once.
#[derive(Debug)]
struct Abandoned {
    operation: OperationId,
    /// The turn of the anchor change, when its reservation can have landed.
    turn: Option<turn::Turn>,
    /// Whether its end entry can be in the journal.
    end: bool,
}

/// The state of the driver that its operations share.
#[derive(Debug)]
struct Core {
    /// The binding keeps a restore journal.
    journal: bool,
    /// A crash loses all state of the store, so each start sets the replay floor.
    loses: bool,
    limits: Limits,
    /// The outcome retention of the binding.
    retention: Duration,
    status: Status,
    instance: Instance,
    record: record::State,
    /// The journal after the mark of the store state, as far as the driver read it.
    history: History,
    counter: Counter,
    /// A reservation of the counter waits or runs.
    reserving: bool,
    /// The latest time reading, which the driver's own commits record.
    now: Reading,
    /// The random identity of the driver, which its own operation identities hold.
    nonce: [u8; 16],
    /// The commits of the driver. It never restarts, so each identity of the driver is new.
    commits: u64,
    /// The key of the mark record.
    mark_key: Key,
    /// The key of the replay floor record.
    floor_key: Key,
    /// The prefix of the intent records.
    intent_prefix: Key,
    /// The journal entries after the mark at the last move of the mark.
    advanced: usize,
    /// The operations that a crash of this driver cut.
    abandoned: Vec<Abandoned>,
    /// The operation whose end entry held the mark at an earlier move of the mark, and the time of that move.
    blocked: Option<(OperationId, Duration)>,
}

impl Core {
    /// A new identity for a commit of the driver: unique, because each driver has a random identity and counts its
    /// commits.
    fn operation(&mut self) -> OperationId {
        self.commits = self.commits.saturating_add(1);
        let id = [b"rsauthnz.driver.".as_slice(), &self.nonce, &self.commits.to_be_bytes()].concat();
        OperationId::new(&id).expect("an identity of 40 bytes is valid")
    }

    /// Write the mark record. Then sync its write number to the journal so a later start can detect rollback.
    fn marking(&mut self) -> Result<Committing, Error> {
        let journaled = written(self.history.state()?);
        self.record.written = self
            .record
            .written
            .max(journaled)
            .checked_add(1)
            .ok_or(Error::Overflow)?;
        let id = self.operation();
        let record = self.record.write(id, self.now, self.limits).ok_or(Error::Record)?;
        let mut committing = Committing::new([record]);
        if self.journal {
            let floor = journal::Floor {
                kind: Kind::Mark,
                value: self.record.written,
            };
            let id = self.operation();
            committing.after = Writing::new(self, [(id, Pending::Body(Body::Floor(floor)))])?;
        }
        Ok(committing)
    }

    /// The highest value that a reservation of the counter covers: the highest floor of the journal and of the mark
    /// record, of each kind but [`Kind::Mark`].
    fn floor(&mut self) -> Result<u64, Error> {
        let journaled = self
            .history
            .state()?
            .floors()
            .filter(|floor| floor.kind != Kind::Mark)
            .map(|floor| floor.value)
            .max()
            .unwrap_or(0);
        let recorded = self.record.floors.values().copied().max().unwrap_or(0);
        Ok(journaled.max(recorded))
    }

    /// The commit of the driver that closes `operation`: it writes the closure as its outcome record.
    fn closure(&mut self, operation: &OperationId) -> Proposal {
        let id = self.operation();
        let mut proposal = record::proposal(id, record::CLOSE, self.now, self.limits);
        proposal.close(operation);
        proposal
    }
}

/// The highest write of the mark record that the floor entries of `state` show.
fn written(state: &journal::State) -> u64 {
    state
        .floors()
        .filter(|floor| floor.kind == Kind::Mark)
        .map(|floor| floor.value)
        .max()
        .unwrap_or(0)
}

/// The earliest time of `reading`, or its estimate when its bound is unknown. The driver uses it only for progress,
/// such as the patience of an owner turn, never for a decision of safety.
fn earliest(reading: Reading) -> Duration {
    reading.earliest().unwrap_or_else(|_| reading.estimate())
}

/// The latest time of `reading`, or its estimate when its bound is unknown, as for [`earliest`].
fn latest(reading: Reading) -> Duration {
    reading.latest().unwrap_or_else(|_| reading.estimate())
}

/// The key of the outcome record of `operation`.
fn outcome_key(operation: &OperationId) -> Key {
    Kind::Outcome
        .key(operation.as_bytes())
        .expect("an operation identity of at most 64 bytes makes a valid key")
}

/// The counter value of a version of a counter: its coordinate of eight bytes, or `None` for another coordinate.
fn value(version: &AuthorityVersion) -> Option<u64> {
    Some(u64::from_be_bytes(version.coordinate().try_into().ok()?))
}

/// One operation of the driver.
#[derive(Debug)]
struct Job {
    ticket: Option<Ticket>,
    cancelled: bool,
    work: Work,
}

#[derive(Debug)]
enum Work {
    Start(Box<Start>),
    Commit(Box<Submitted>),
    Lookup(Box<Looking>),
    Recover(Box<Recovering>),
    Advance(Box<Advance>),
    Reserve(Box<Reserving>),
}

/// The driver.
#[derive(Debug)]
pub struct Driver {
    core: Core,
    /// The accepted declaration of the binding. Each submitted proposal passes [`Profile::admit`].
    profile: Profile,
    queue: VecDeque<Job>,
    job: Option<Job>,
    answers: BTreeMap<Ticket, Answer>,
    tickets: u64,
}

impl Driver {
    /// A driver for a binding with the accepted declaration `profile`, so no driver exists for a binding that
    /// [`Profile::new`] refuses. Each journal entry and each proposal of the driver stays within `limits`. `random`
    /// gives the identity of the driver, so the operations of two drivers on one store have different identities. The
    /// driver is down until the first [`Driver::start`].
    ///
    /// Cost class: [`Parse`](crate::limits::Class::Parse).
    ///
    /// # Errors
    ///
    /// [`Error::RecordBound`] when the record bound of the binding is below [`record_bytes_min`] of `limits`: the
    /// binding cannot store each record that the driver writes for itself.
    pub fn new(profile: Profile, limits: Limits, random: &mut ChaCha20Rng) -> Result<Self, Error> {
        let least = record_bytes_min(limits);
        let declaration = profile.declaration();
        (declaration.record_bytes_max >= least).ok_or(Error::RecordBound(least))?;
        let mut nonce = [0; 16];
        random.fill_bytes(&mut nonce);
        Ok(Self {
            core: Core {
                journal: matches!(declaration.restore, Restore::Journal { .. }),
                loses: declaration.crash_loss == super::CrashLoss::Everything,
                limits,
                retention: declaration.outcome_retention,
                status: Status::Down,
                instance: Instance(0),
                record: record::State::default(),
                history: History::new(Mark::EMPTY),
                counter: Counter::EMPTY,
                reserving: false,
                now: Reading::new(Duration::ZERO, None, crate::time::ReadingSource::Caller),
                nonce,
                commits: 0,
                mark_key: record::mark_key(),
                floor_key: super::floor_key(),
                intent_prefix: Kind::Intent.key(&[]).expect("a key of one byte is valid"),
                advanced: 0,
                abandoned: Vec::new(),
                blocked: None,
            },
            profile,
            queue: VecDeque::new(),
            job: None,
            answers: BTreeMap::new(),
            tickets: 0,
        })
    }

    /// The state of the driver.
    #[must_use]
    pub const fn status(&self) -> Status {
        self.core.status
    }

    /// The serving instance. Capture it when scheduling an expiry pass.
    ///
    /// Cost class: [`Parse`](crate::limits::Class::Parse). One status check.
    ///
    /// # Errors
    ///
    /// [`Error::Down`] if the driver cannot serve work.
    pub fn instance(&self) -> Result<Instance, Error> {
        (self.core.status == Status::Serving)
            .then_some(self.core.instance)
            .ok_or(Error::Down)
    }

    /// Starts the driver at `now`. The driver reads the installed instance and the replay floor. When the floor names
    /// that instance, the driver joins it with no write, and its peers keep serving. Otherwise the store is new, it
    /// lost its state, or an activation stopped before it finished: the driver activates a new instance, reconciles,
    /// and resumes the recorded recovery. Then it settles the work that a crash of this driver cut, reserves its
    /// counter, and serves. Call it at first, and after each crash. Never call it after a restore of the store: call
    /// [`Driver::restore`].
    ///
    /// Cost class: [`Mutate`](crate::limits::Class::Mutate).
    pub fn start(&mut self, now: Reading) {
        self.begin(now, Begin::Start);
    }

    /// Restores the store at `now`, after the binding restored a snapshot: the driver activates a new instance, applies
    /// the journal after the mark of the snapshot, completes each in-doubt consumption, and then serves. The new
    /// instance fences the commits of each peer, which then join the restored store with a start.
    ///
    /// Cost class: [`Mutate`](crate::limits::Class::Mutate).
    ///
    /// # Errors
    ///
    /// [`Error::Unsupported`] for a binding with no journal.
    pub fn restore(&mut self, now: Reading) -> Result<(), Error> {
        self.core.journal.ok_or(Error::Unsupported)?;
        self.begin(now, Begin::Restore);
        Ok(())
    }

    /// Continue the alpha upgrade after an operator verifies the origin of this primary.
    /// Use the instance from [`Error::AlphaReview`]. The driver checks the records again in that instance.
    ///
    /// Cost class: [`Mutate`](crate::limits::Class::Mutate). One activation in the fenced instance.
    ///
    /// # Errors
    ///
    /// [`Error::Superseded`] if this review has ended or another activation is scheduled.
    /// Observe [`Driver::status`] after running the effects for the result of verification.
    pub fn resolve_alpha(&mut self, instance: Instance, source: AlphaSource, now: Reading) -> Result<(), Error> {
        let current = matches!(self.core.status, Status::Refused(Error::AlphaReview { instance: reviewed, .. }) if reviewed == instance);
        let starting = self.queue.iter().any(|job| matches!(job.work, Work::Start(_)));
        (current && !starting).ok_or(Error::Superseded)?;
        self.begin(now, Begin::Reviewed(source));
        Ok(())
    }

    fn begin(&mut self, now: Reading, begin: Begin) {
        self.core.now = now;
        self.retire_queue();
        self.queue.push_front(Job {
            ticket: None,
            cancelled: false,
            work: Work::Start(Box::new(Start::new(begin))),
        });
    }

    /// A new activation admits new submissions. Only status reads carry over from the old queue.
    fn retire_queue(&mut self) {
        let answers = &mut self.answers;
        self.queue.retain(|job| match &job.work {
            Work::Lookup(_) => true,
            Work::Commit(submitted) => {
                if let Some(ticket) = job.ticket
                    && !job.cancelled
                {
                    answers.insert(ticket, Answer::Outcome(Outcome::Unknown(submitted.operation.clone())));
                }
                false
            }
            Work::Recover(_) => {
                if let Some(ticket) = job.ticket
                    && !job.cancelled
                {
                    answers.insert(ticket, Answer::Recovered(Recovered::Unknown));
                }
                false
            }
            Work::Start(_) | Work::Advance(_) | Work::Reserve(_) => false,
        });
        self.core.reserving = false;
    }

    /// Moves the mark of the store at `now` past each journal entry that the store state reflects. The driver also
    /// moves it after a start and after [`ADVANCE_AT`] entries. An end entry of a peer that holds the mark at two moves
    /// at least [`TURN_PATIENCE`] apart belongs to a server that stopped: this move closes its operation and voids
    /// the entry, so the next move passes it.
    ///
    /// Cost class: [`Mutate`](crate::limits::Class::Mutate).
    pub fn advance(&mut self, now: Reading) {
        self.core.now = now;
        self.queue.push_back(Job {
            ticket: None,
            cancelled: false,
            work: Work::Advance(Box::new(Advance::Begin)),
        });
    }

    /// A new value of the counter, such as the version of a new record. The journal reserved it before this call, so
    /// it is above each value of each earlier instance of the store, and no other driver gives it. For the next
    /// version of a record, use [`Driver::allocate_after`].
    ///
    /// Cost class: [`Parse`](crate::limits::Class::Parse).
    ///
    /// # Errors
    ///
    /// [`Error::Down`] while the driver does not serve, [`Error::Exhausted`] when no reserved value is left, and
    /// [`Error::Overflow`] after the largest value.
    pub fn allocate(&mut self) -> Result<u64, Error> {
        self.above(0)
    }

    /// A new value of the counter for the next version of a record at `previous`: above the counter value of
    /// `previous`, its coordinate of eight bytes. Another driver can have written `previous` from a later block, so the
    /// driver discards each value at or below it. A coordinate of another length gives no bound.
    ///
    /// Cost class: [`Parse`](crate::limits::Class::Parse).
    ///
    /// # Errors
    ///
    /// As for [`Driver::allocate`].
    pub fn allocate_after(&mut self, previous: &AuthorityVersion) -> Result<u64, Error> {
        self.above(value(previous).unwrap_or(0))
    }

    fn above(&mut self, previous: u64) -> Result<u64, Error> {
        (self.core.status == Status::Serving).ok_or(Error::Down)?;
        (previous < u64::MAX).ok_or(Error::Overflow)?;
        let value = self.core.counter.take(previous);
        self.schedule();
        value.ok_or(Error::Exhausted)
    }

    /// Queues a reservation of the counter when the driver has no spare block.
    fn schedule(&mut self) {
        if self.core.status == Status::Serving && self.core.counter.spare.is_none() && !self.core.reserving {
            self.core.reserving = true;
            self.queue.push_front(Job {
                ticket: None,
                cancelled: false,
                work: Work::Reserve(Box::new(Reserving::new(1))),
            });
        }
    }

    /// The recovery handle of `proposal` ([`Handle`]), before its submission. Keep it until the answer of the commit.
    ///
    /// Cost class: [`Parse`](crate::limits::Class::Parse).
    ///
    /// # Errors
    ///
    /// [`Error::Down`] while the driver does not serve.
    pub fn handle(&self, proposal: &Proposal) -> Result<Handle, Error> {
        Ok(Handle {
            operation: proposal.operation().clone(),
            instance: self.instance()?,
            time: proposal.audit().time.estimate(),
        })
    }

    /// Submits the commit of `proposal`, with the anchors and the roles of `plan`. For an anchor change, the driver
    /// reserves the turn of each owner, checks the last anchor of each owner, writes the journal entries, commits,
    /// writes the creation entry, releases the turns, and then answers with an [`Outcome`]. A queued proposal that
    /// crosses a new start or restore returns [`Outcome::Unknown`] under its original identity.
    ///
    /// Cost class: [`Mutate`](crate::limits::Class::Mutate).
    ///
    /// # Errors
    ///
    /// [`Error::Transition`] for a proposal whose entries the journal cannot read back, or with no room for the
    /// journal intent, [`Error::Journal`] for a plan that does not fit the proposal, [`Error::RecordBytes`] for a
    /// proposal that the binding cannot store ([`Profile::admit`]), and [`Error::Full`]. A refused proposal never
    /// reaches the binding.
    pub fn submit(&mut self, proposal: Proposal, plan: Plan) -> Result<Ticket, Error> {
        (self.queue.len() < QUEUE_MAX).ok_or(Error::Full)?;
        let submitted = Submitted::new(&mut self.core, proposal, plan)?;
        self.profile
            .admit(submitted.proposal.as_ref().ok_or(Error::Binding)?)
            .map_err(|_| Error::RecordBytes)?;
        let ticket = self.ticket();
        self.queue.push_back(Job {
            ticket: Some(ticket),
            cancelled: false,
            work: Work::Commit(Box::new(submitted)),
        });
        Ok(ticket)
    }

    /// Reads the outcome of the original operation and request binding from [`Outcome::Unknown`].
    /// A missing receipt gives [`Lookup::Unknown`]. The read leaves the original operation open: it never closes it.
    ///
    /// Cost class: [`Mutate`](crate::limits::Class::Mutate). The lookup is a keyed read, a range read of the intents of
    /// the operation, and, while its creation entry is owed, a read of the new journal entries.
    ///
    /// # Errors
    ///
    /// [`InDoubt`] with [`Error::Full`]: the operation stays in doubt.
    pub fn lookup(&mut self, operation: Operation) -> Result<Ticket, InDoubt> {
        (self.queue.len() < QUEUE_MAX).ok_or(InDoubt(Error::Full))?;
        let ticket = self.ticket();
        self.queue.push_back(Job {
            ticket: Some(ticket),
            cancelled: false,
            work: Work::Lookup(Box::new(Looking::new(operation))),
        });
        Ok(ticket)
    }

    /// Recovers the operation of `handle` after a lost reply, at `now`. A retained receipt gives
    /// [`Recovered::Committed`] after the creation entry of the operation is durable. With no receipt, in the instance
    /// of the handle and within the outcome retention after its time, the driver closes the identity in one commit
    /// that competes with the commit of the original operation, voids its entries, and gives [`Recovered::Fresh`]: the
    /// original never commits. A closed identity also gives [`Recovered::Fresh`]. Other evidence gives
    /// [`Recovered::Unknown`]. The driver never starts the fresh attempt.
    ///
    /// Cost class: [`Mutate`](crate::limits::Class::Mutate). At most one read, one range read, one commit, and one
    /// journal write.
    ///
    /// # Errors
    ///
    /// [`InDoubt`] with [`Error::Full`]: the operation stays in doubt.
    pub fn recover(&mut self, handle: Handle, now: Reading) -> Result<Ticket, InDoubt> {
        (self.queue.len() < QUEUE_MAX).ok_or(InDoubt(Error::Full))?;
        let ticket = self.ticket();
        self.queue.push_back(Job {
            ticket: Some(ticket),
            cancelled: false,
            work: Work::Recover(Box::new(Recovering::new(handle, now))),
        });
        Ok(ticket)
    }

    /// Cancels the operation `ticket`. An operation that waits ends at once. The operation in progress runs to its
    /// commit or its refusal, and keeps the turn of its owners until then, but it gives no answer.
    ///
    /// Cost class: [`Parse`](crate::limits::Class::Parse).
    pub fn cancel(&mut self, ticket: Ticket) {
        self.queue.retain(|job| job.ticket != Some(ticket));
        if let Some(job) = self.job.as_mut().filter(|job| job.ticket == Some(ticket)) {
            job.cancelled = true;
        }
    }

    /// The answer of the operation `ticket`, once, after the operation ends.
    ///
    /// Cost class: [`Parse`](crate::limits::Class::Parse).
    pub fn take(&mut self, ticket: Ticket) -> Option<Answer> {
        self.answers.remove(&ticket)
    }

    /// The next effect for the binding, or `None` when the driver waits for a request.
    ///
    /// Cost class: [`Parse`](crate::limits::Class::Parse).
    pub fn effect(&mut self) -> Option<Effect<'_>> {
        self.settle();
        self.job.as_ref()?.work.effect(&self.core)
    }

    /// Gives the output of the last effect. [`Output::Failed`] is a crash: the driver stops until the next start.
    ///
    /// Cost class: [`Parse`](crate::limits::Class::Parse).
    ///
    /// # Errors
    ///
    /// [`Error::Binding`] when no effect waits for an output. A wrong output for the effect stops the driver with
    /// [`Status::Refused`].
    pub fn give(&mut self, output: Output) -> Result<(), Error> {
        let job = self.job.as_mut().ok_or(Error::Binding)?;
        if matches!(output, Output::Failed) {
            self.crash(Status::Down);
        } else if let Err(error) = job.work.give(&mut self.core, output) {
            self.crash(Status::Refused(error));
        }
        // The answer of an operation that ends with this output is ready at once.
        self.settle();
        Ok(())
    }

    fn ticket(&mut self) -> Ticket {
        self.tickets = self.tickets.saturating_add(1);
        Ticket(self.tickets)
    }

    /// Ends the operation in progress with the crash `status`: a commit gets an unknown outcome, unless its outcome
    /// was known before the crash. The next start settles the work of a commit that the crash cut.
    fn crash(&mut self, status: Status) {
        self.core.status = status;
        if let Some(job) = self.job.take() {
            let answer = match job.work {
                Work::Commit(commit) => {
                    if let Some(abandoned) = commit.abandoned() {
                        self.core.abandoned.push(abandoned);
                    }
                    Some(Answer::Outcome(
                        commit.answer.unwrap_or(Outcome::Unknown(commit.operation)),
                    ))
                }
                Work::Lookup(_) => Some(Answer::Lookup(Lookup::Unknown)),
                Work::Recover(_) => Some(Answer::Recovered(Recovered::Unknown)),
                Work::Reserve(_) => {
                    self.core.reserving = false;
                    None
                }
                Work::Start(_) | Work::Advance(_) => None,
            };
            if let (Some(ticket), false, Some(answer)) = (job.ticket, job.cancelled, answer) {
                self.answers.insert(ticket, answer);
            }
        }
        if !self.queue.iter().any(|job| matches!(job.work, Work::Start(_))) {
            self.retire_queue();
        }
    }

    /// Brings the driver to its next effect: it takes the next operation, and it ends each operation that needs no
    /// more effect.
    fn settle(&mut self) {
        loop {
            if self.job.is_none() {
                let ready = match self.core.status {
                    Status::Serving => !self.queue.is_empty(),
                    Status::Down | Status::Refused(_) => {
                        self.queue.front().is_some_and(|job| matches!(job.work, Work::Start(_)))
                    }
                    Status::Starting => false,
                };
                if !ready {
                    return;
                }
                self.job = self.queue.pop_front();
                if self.job.as_ref().is_some_and(|job| matches!(job.work, Work::Start(_))) {
                    self.core.status = Status::Starting;
                }
            }
            let Some(job) = self.job.as_mut() else {
                return;
            };
            match job.work.settle(&mut self.core) {
                Ok(None) => return,
                Ok(Some(answer)) => {
                    let ended = self.job.take().map(|job| {
                        let start = matches!(job.work, Work::Start(_));
                        if matches!(job.work, Work::Reserve(_)) {
                            self.core.reserving = false;
                        }
                        (job.ticket, job.cancelled, start)
                    });
                    if let Some((Some(ticket), false, _)) = ended
                        && let Some(answer) = answer
                    {
                        self.answers.insert(ticket, answer);
                    }
                    if ended.is_some_and(|(_, _, start)| start) && self.core.journal {
                        self.queue.push_front(Job {
                            ticket: None,
                            cancelled: false,
                            work: Work::Advance(Box::new(Advance::Begin)),
                        });
                    }
                    if self.core.status == Status::Serving
                        && self.core.journal
                        && self.core.history.entries().len() >= self.core.advanced.saturating_add(ADVANCE_AT)
                        && !self.queue.iter().any(|job| matches!(job.work, Work::Advance(_)))
                    {
                        self.queue.push_front(Job {
                            ticket: None,
                            cancelled: false,
                            work: Work::Advance(Box::new(Advance::Begin)),
                        });
                    }
                    self.schedule();
                }
                Err(error) => self.crash(Status::Refused(error)),
            }
        }
    }
}

/// The result of a settled operation: `None` while it has an effect, else its answer, which can be none.
type Settled = Result<Option<Option<Answer>>, Error>;

impl Work {
    fn effect<'a>(&'a self, core: &'a Core) -> Option<Effect<'a>> {
        match self {
            Self::Start(start) => start.effect(core),
            Self::Commit(commit) => commit.effect(core),
            Self::Lookup(lookup) => lookup.effect(core),
            Self::Recover(recover) => recover.effect(core),
            Self::Advance(advance) => advance.effect(core),
            Self::Reserve(reserve) => reserve.effect(core),
        }
    }

    fn give(&mut self, core: &mut Core, output: Output) -> Result<(), Error> {
        match self {
            Self::Start(start) => start.give(core, output),
            Self::Commit(commit) => commit.give(core, output),
            Self::Lookup(lookup) => lookup.give(core, output),
            Self::Recover(recover) => recover.give(core, output),
            Self::Advance(advance) => advance.give(core, output),
            Self::Reserve(reserve) => reserve.give(core, output),
        }
    }

    fn settle(&mut self, core: &mut Core) -> Settled {
        match self {
            Self::Start(start) => start.settle(core),
            Self::Commit(commit) => commit.settle(core),
            Self::Lookup(lookup) => lookup.settle(core),
            Self::Recover(recover) => recover.settle(core),
            Self::Advance(advance) => advance.settle(core),
            Self::Reserve(reserve) => reserve.settle(core).map(|done| done.then_some(None)),
        }
    }
}

// ---------------------------------------------------------------------------------------------------------------
// The parts of an operation: each one gives effects until it is done.

/// A journal entry that a [`Writing`] appends: a body, the void of its operation, or the reservation of this many
/// blocks of the counter. The driver computes a void and a reservation at the head of each attempt.
#[derive(Debug)]
enum Pending {
    Body(Body),
    /// The void of the first end entry of the operation that no void cancels, or its terminal void when it has none.
    Void,
    Reserve(u64),
}

/// The read of the new journal entries after a conflicting append.
#[derive(Clone, Copy, Debug)]
enum Conflict {
    /// The read of the entries after the head. `moved` when it read one, `synced` after the sync of this conflict.
    Reading { moved: bool, synced: bool },
    /// The sync that makes the accepted appends of the peers durable, so that a read gives them.
    Syncing,
    /// The read of the guard of an end entry before it appends again.
    Guarding,
}

/// The record that an end entry of a change needs before it appends again after a conflict: the owner turn of the
/// attempt at its held version, or no outcome record of a change that holds no turn. A helper that retired the turn or
/// closed the operation fenced the commit, so the end entry never lands after its void.
#[derive(Clone, Debug)]
struct Guard {
    key: Key,
    version: Option<AuthorityVersion>,
}

/// Appends entries, then syncs once. A conflicting append reads the new entries of the peers and appends again at the
/// new head. A read that gives no new entry syncs first, because a peer can have an accepted append that awaits its
/// sync. A conflict with no new entry after that sync is a change of instance.
#[derive(Debug, Default)]
struct Writing {
    bodies: VecDeque<(OperationId, Pending)>,
    /// The entry of the next append, and its stored form and mark.
    current: Option<(OperationId, Pending)>,
    next: Option<journal::Append>,
    /// An append was accepted, so the writing ends with a sync.
    sync: bool,
    conflict: Option<Conflict>,
    /// The guard of an end entry.
    guard: Option<Guard>,
    attempts: u32,
    /// The floor of the accepted reservation of the counter.
    reserved: Option<u64>,
    /// A helper fenced the change of the end entry, so the writing stopped before that entry.
    fenced: bool,
}

/// The first end entry of `operation` in `history` that no void cancels.
fn unvoided(history: &History, operation: &OperationId) -> Option<Sequence> {
    let voided: BTreeSet<Sequence> = history
        .entries()
        .iter()
        .filter_map(|entry| match entry.body {
            Body::Void(target) => Some(target),
            _ => None,
        })
        .collect();
    history
        .entries()
        .iter()
        .find(|entry| {
            entry.operation == *operation && matches!(entry.body, Body::End(_)) && !voided.contains(&entry.sequence)
        })
        .map(|entry| entry.sequence)
}

impl Writing {
    fn new(core: &mut Core, bodies: impl IntoIterator<Item = (OperationId, Pending)>) -> Result<Self, Error> {
        let mut writing = Self {
            bodies: bodies.into_iter().collect(),
            ..Self::default()
        };
        writing.encode(core)?;
        Ok(writing)
    }

    /// The writing of one end entry, which reads `guard` before each append after a conflict.
    fn guarded(core: &mut Core, operation: OperationId, end: journal::End, guard: Guard) -> Result<Self, Error> {
        let mut writing = Self {
            bodies: [(operation, Pending::Body(Body::End(end)))].into(),
            guard: Some(guard),
            ..Self::default()
        };
        writing.encode(core)?;
        Ok(writing)
    }

    /// Encodes the current entry at the head of the history, after it takes the next one.
    fn encode(&mut self, core: &mut Core) -> Result<(), Error> {
        if self.current.is_none() {
            self.current = self.bodies.pop_front();
        }
        let Some((operation, pending)) = &self.current else {
            self.next = None;
            return Ok(());
        };
        let exists = |found: &dyn Fn(&Body) -> bool| {
            core.history
                .entries()
                .iter()
                .any(|entry| entry.operation == *operation && found(&entry.body))
        };
        let once = match pending {
            Pending::Body(Body::Creation(_)) => exists(&|body| matches!(body, Body::Creation(_))),
            Pending::Body(Body::Void(target)) => {
                target.0 != 0 && exists(&|body| matches!(body, Body::Void(void) if void == target))
            }
            Pending::Body(Body::End(_) | Body::Floor(_)) | Pending::Void | Pending::Reserve(_) => false,
        };
        if once {
            // The journal holds each step of an operation once: a peer appended this one first.
            self.current = None;
            return self.encode(core);
        }
        let body = match pending {
            Pending::Body(body) => body.clone(),
            Pending::Void => Body::Void(unvoided(&core.history, operation).unwrap_or(Sequence(0))),
            Pending::Reserve(blocks) => {
                let span = FLOOR_BLOCK.get().checked_mul(*blocks).ok_or(Error::Overflow)?;
                Body::Floor(journal::Floor {
                    kind: COUNTER,
                    value: core.floor()?.checked_add(span).ok_or(Error::Overflow)?,
                })
            }
        };
        self.next = Some(core.history.head().next(operation, &body, core.limits)?);
        Ok(())
    }

    fn effect<'a>(&'a self, core: &Core) -> Option<Effect<'a>> {
        match self.conflict {
            Some(Conflict::Reading { .. }) => Some(Effect::ReadJournal(core.history.head().sequence, PAGE)),
            Some(Conflict::Syncing) => Some(Effect::Sync(core.instance)),
            Some(Conflict::Guarding) => self.guard.as_ref().map(|guard| Effect::Read(&guard.key)),
            None => match &self.next {
                Some(append) => Some(Effect::Append(append, core.instance)),
                None => self.sync.then_some(Effect::Sync(core.instance)),
            },
        }
    }

    fn give(&mut self, core: &mut Core, output: Output) -> Result<(), Error> {
        match (self.conflict, output) {
            (Some(Conflict::Reading { moved, synced }), Output::Journal(page)) => {
                if !page.is_empty() {
                    extend(core, &page)?;
                    self.conflict = Some(Conflict::Reading { moved: true, synced });
                } else if moved && self.guard.is_some() {
                    self.conflict = Some(Conflict::Guarding);
                } else if moved {
                    self.conflict = None;
                    self.encode(core)?;
                } else if !synced {
                    self.conflict = Some(Conflict::Syncing);
                } else {
                    return Err(Error::Superseded);
                }
                Ok(())
            }
            (Some(Conflict::Syncing), Output::Synced(JournalWrite::Accepted)) => {
                self.conflict = Some(Conflict::Reading {
                    moved: false,
                    synced: true,
                });
                Ok(())
            }
            (Some(Conflict::Syncing), Output::Synced(JournalWrite::Conflict)) => Err(Error::Superseded),
            (Some(Conflict::Guarding), Output::Read(record)) => {
                let guard = self.guard.as_ref().ok_or(Error::Binding)?;
                self.conflict = None;
                if record.map(|record| record.version) == guard.version {
                    self.encode(core)
                } else {
                    // A helper retired the turn or closed the operation: no end entry of this attempt lands after it.
                    self.fenced = true;
                    self.bodies.clear();
                    self.current = None;
                    self.next = None;
                    Ok(())
                }
            }
            (None, Output::Appended(JournalWrite::Accepted)) => {
                let append = self.next.take().ok_or(Error::Binding)?;
                core.history
                    .extend(core::slice::from_ref(append.entry()), core.limits)?;
                if let Some((_, Pending::Reserve(_))) = self.current.take()
                    && let Some(journal::Entry {
                        body: Body::Floor(floor),
                        ..
                    }) = core.history.entries().last()
                {
                    self.reserved = Some(floor.value);
                }
                self.sync = true;
                self.encode(core)
            }
            (None, Output::Appended(JournalWrite::Conflict)) if self.next.is_some() => {
                self.attempts = self.attempts.saturating_add(1);
                (self.attempts <= WRITE_ATTEMPTS).ok_or(Error::Superseded)?;
                self.conflict = Some(Conflict::Reading {
                    moved: false,
                    synced: false,
                });
                Ok(())
            }
            (None, Output::Synced(JournalWrite::Conflict)) if self.next.is_none() && self.sync => {
                Err(Error::Superseded)
            }
            (None, Output::Synced(JournalWrite::Accepted)) if self.next.is_none() && self.sync => {
                self.sync = false;
                Ok(())
            }
            _ => Err(Error::Binding),
        }
    }
}

/// Extends the history of `core` with a page of journal entries, within [`JOURNAL_ENTRIES_MAX`].
fn extend(core: &mut Core, page: &[super::Entry]) -> Result<(), Error> {
    core.history.extend(page, core.limits)?;
    (core.history.entries().len() <= JOURNAL_ENTRIES_MAX).ok_or(Error::Long)
}

/// Reads the journal after the head of the history of the driver, a page after the other, until no entry is left.
#[derive(Debug, Default)]
struct Refreshing {
    done: bool,
}

impl Refreshing {
    fn effect<'a>(&self, core: &Core) -> Option<Effect<'a>> {
        (!self.done).then(|| Effect::ReadJournal(core.history.head().sequence, PAGE))
    }

    fn give(&mut self, core: &mut Core, output: Output) -> Result<(), Error> {
        let Output::Journal(page) = output else {
            return Err(Error::Binding);
        };
        if page.is_empty() {
            self.done = true;
            return Ok(());
        }
        extend(core, &page)
    }
}

/// Commits the driver's own proposals, and then writes the entries of `after`. A proposal that a conflict refuses is
/// skipped when `skip` holds: a release or an end that a helper can have made first.
#[derive(Debug, Default)]
struct Committing {
    proposals: VecDeque<Proposal>,
    after: Writing,
    skip: bool,
}

impl Committing {
    fn new(proposals: impl IntoIterator<Item = Proposal>) -> Self {
        Self {
            proposals: proposals.into_iter().collect(),
            after: Writing::default(),
            skip: false,
        }
    }

    /// The commits of `proposals`, each of which a peer can have made first.
    fn skipping(proposals: impl IntoIterator<Item = Proposal>) -> Self {
        Self {
            skip: true,
            ..Self::new(proposals)
        }
    }

    fn effect<'a>(&'a self, core: &'a Core) -> Option<Effect<'a>> {
        match self.proposals.front() {
            Some(proposal) => Some(Effect::Commit(proposal, core.instance)),
            None => self.after.effect(core),
        }
    }

    fn give(&mut self, core: &mut Core, output: Output) -> Result<(), Error> {
        if self.proposals.is_empty() {
            return self.after.give(core, output);
        }
        match output {
            Output::Committed(Commit::Accepted) => {
                self.proposals.pop_front();
                Ok(())
            }
            Output::Committed(Commit::Conflict) if self.skip => {
                self.proposals.pop_front();
                Ok(())
            }
            Output::Committed(Commit::Superseded) => Err(Error::Superseded),
            _ => Err(Error::Binding),
        }
    }
}

/// Commits one proposal of the driver and keeps its result.
#[derive(Debug)]
struct Deciding {
    proposal: Proposal,
    result: Option<Commit>,
}

impl Deciding {
    const fn new(proposal: Proposal) -> Self {
        Self { proposal, result: None }
    }

    fn effect<'a>(&'a self, core: &Core) -> Option<Effect<'a>> {
        self.result
            .is_none()
            .then_some(Effect::Commit(&self.proposal, core.instance))
    }

    fn give(&mut self, output: Output) -> Result<(), Error> {
        match output {
            Output::Committed(Commit::Superseded) => Err(Error::Superseded),
            Output::Committed(result) if self.result.is_none() => {
                self.result = Some(result);
                Ok(())
            }
            _ => Err(Error::Binding),
        }
    }
}

/// Reads records and keeps them.
#[derive(Debug, Default)]
struct Gathering {
    keys: VecDeque<Key>,
    records: Vec<(Key, Option<Record>)>,
}

impl Gathering {
    fn new(keys: impl IntoIterator<Item = Key>) -> Self {
        Self {
            keys: keys.into_iter().collect(),
            records: Vec::new(),
        }
    }

    fn effect(&self) -> Option<Effect<'_>> {
        self.keys.front().map(Effect::Read)
    }

    fn give(&mut self, output: Output) -> Result<(), Error> {
        let (Some(key), Output::Read(record)) = (self.keys.pop_front(), output) else {
            return Err(Error::Binding);
        };
        self.records.push((key, record));
        Ok(())
    }

    /// The record of `key` that the reads gave.
    fn get(&self, key: &Key) -> Option<&Record> {
        self.records
            .iter()
            .find_map(|(read, record)| (read == key).then_some(record.as_ref()).flatten())
    }
}

/// Reads records and outcome records into [`Reads`].
#[derive(Debug, Default)]
struct Fetching {
    keys: VecDeque<Key>,
    operations: VecDeque<(OperationId, Key)>,
    reads: Reads,
    /// The replay floor of the reads, when they read it and the store has it.
    floor: Option<record::Floor>,
}

impl Fetching {
    fn new(keys: impl IntoIterator<Item = Key>, operations: impl IntoIterator<Item = OperationId>) -> Self {
        let keys: BTreeSet<Key> = keys.into_iter().collect();
        let operations: BTreeSet<OperationId> = operations.into_iter().collect();
        Self {
            keys: keys.into_iter().collect(),
            operations: operations
                .into_iter()
                .map(|operation| {
                    let key = outcome_key(&operation);
                    (operation, key)
                })
                .collect(),
            reads: Reads::default(),
            floor: None,
        }
    }

    fn effect(&self) -> Option<Effect<'_>> {
        match (self.keys.front(), self.operations.front()) {
            (Some(key), _) | (None, Some((_, key))) => Some(Effect::Read(key)),
            (None, None) => None,
        }
    }

    fn give(&mut self, output: Output) -> Result<(), Error> {
        let Output::Read(record) = output else {
            return Err(Error::Binding);
        };
        if let Some(key) = self.keys.pop_front() {
            if Kind::of(&key) == Some(Kind::ReplayFloor)
                && let Some(record) = &record
            {
                self.floor = Some(record::Floor::read(&record.data).ok_or(Error::Record)?);
            }
            self.reads.records.insert(key, record.map(|record| record.version));
        } else if let Some((operation, _)) = self.operations.pop_front() {
            let found = match record {
                None => false,
                Some(record) => {
                    outcome_of(&operation, &record).ok_or(Error::Record)?;
                    true
                }
            };
            self.reads.outcomes.insert(operation, found);
        } else {
            return Err(Error::Binding);
        }
        Ok(())
    }
}

/// An intent of [`Call::Journal`](transition::Effect::Journal) that the store holds: the commit owes the creation
/// entry of its anchors.
#[derive(Debug)]
struct Owed {
    operation: OperationId,
    anchors: Vec<Anchor>,
    key: Key,
    version: AuthorityVersion,
}

/// Reads the intent records of a prefix, a page after the other, and keeps each intent of
/// [`Call::Journal`](transition::Effect::Journal). The prefix is the kind of the intents, or the kind and the identity
/// of one operation, whose intents it keeps alone.
#[derive(Debug)]
struct Scanning {
    prefix: Key,
    /// The operation of a prefix of one operation.
    operation: Option<OperationId>,
    after: Option<Key>,
    owed: Vec<Owed>,
    done: bool,
}

impl Scanning {
    /// Each intent of the store.
    fn all(core: &Core) -> Self {
        Self {
            prefix: core.intent_prefix.clone(),
            operation: None,
            after: None,
            owed: Vec::new(),
            done: false,
        }
    }

    /// The intents of `operation`.
    fn of(operation: &OperationId) -> Self {
        Self {
            prefix: Kind::Intent
                .key(operation.as_bytes())
                .expect("an operation identity of at most 64 bytes makes a valid key"),
            operation: Some(operation.clone()),
            after: None,
            owed: Vec::new(),
            done: false,
        }
    }

    fn effect(&self) -> Option<Effect<'_>> {
        (!self.done).then_some(Effect::Range(&self.prefix, self.after.as_ref(), PAGE))
    }

    fn give(&mut self, limits: Limits, output: Output) -> Result<(), Error> {
        let Output::Range(page) = output else {
            return Err(Error::Binding);
        };
        let Some((last, _)) = page.last() else {
            self.done = true;
            return Ok(());
        };
        self.after = Some(last.clone());
        for (key, record) in page {
            // The key of an intent is its kind, its operation identity, and its index of eight bytes.
            let id = key
                .as_bytes()
                .get(1..key.as_bytes().len().saturating_sub(8))
                .and_then(|id| OperationId::new(id).ok());
            // The prefix of one identity also holds the intents of each longer identity that starts with it.
            if self.operation.is_some() && id != self.operation {
                continue;
            }
            let intent = cbor::decode(&record.data, limits)
                .ok()
                .and_then(|form| Intent::from_cbor(&form).ok())
                .filter(|intent| intent.effect() == transition::Effect::Journal);
            let Some(intent) = intent else {
                continue;
            };
            let anchors = journal::decode_anchors(intent.payload(), limits);
            let (Some(operation), Some(anchors)) = (id, anchors) else {
                return Err(Error::Record);
            };
            (self.owed.len() < QUEUE_MAX).ok_or(Error::Full)?;
            self.owed.push(Owed {
                operation,
                anchors,
                key,
                version: record.version,
            });
        }
        Ok(())
    }
}

/// Reads the records of a prefix, a page after the other, and keeps them, at most [`QUEUE_MAX`].
#[derive(Debug)]
struct Listing {
    prefix: Key,
    after: Option<Key>,
    records: Vec<(Key, Record)>,
    done: bool,
}

impl Listing {
    fn new(prefix: Key) -> Self {
        Self {
            prefix,
            after: None,
            records: Vec::new(),
            done: false,
        }
    }

    fn effect(&self) -> Option<Effect<'_>> {
        (!self.done).then_some(Effect::Range(&self.prefix, self.after.as_ref(), PAGE))
    }

    fn give(&mut self, output: Output) -> Result<(), Error> {
        let Output::Range(page) = output else {
            return Err(Error::Binding);
        };
        let Some((last, _)) = page.last() else {
            self.done = true;
            return Ok(());
        };
        self.after = Some(last.clone());
        (self.records.len().saturating_add(page.len()) <= QUEUE_MAX).ok_or(Error::Full)?;
        self.records.extend(page);
        Ok(())
    }
}

/// The anchors that the creation entry of `operation` holds when it is owed: those of its journal intents `owed` and
/// of its consumption entry in `history`. None when `history` has its creation entry, or when it creates no anchor.
fn owed(history: &History, operation: &OperationId, owed: &[Owed]) -> Vec<Anchor> {
    if history
        .entries()
        .iter()
        .any(|entry| entry.operation == *operation && matches!(entry.body, Body::Creation(_)))
    {
        return Vec::new();
    }
    let mut anchors: Vec<Anchor> = owed.iter().flat_map(|owed| owed.anchors.clone()).collect();
    for entry in history.entries().iter().filter(|entry| entry.operation == *operation) {
        if let Body::End(journal::End {
            consumption: Some(consumption),
            ..
        }) = &entry.body
        {
            anchors.extend(consumption.anchors.iter().cloned());
        }
    }
    anchors
}

/// The commit of the driver that ends the intent record `key` at `version`.
fn release(core: &mut Core, key: &Key, version: &AuthorityVersion) -> Result<Proposal, Error> {
    let id = core.operation();
    let mut proposal = record::proposal(id, record::INTENT, core.now, core.limits);
    proposal
        .read(Dependency::Version(key.clone(), version.clone()))
        .map_err(Error::Transition)?;
    proposal.change(Change::End(key.clone())).map_err(Error::Transition)?;
    Ok(proposal)
}

#[cfg(test)]
mod tests;
