//! The commit driver: the one sequencer of the storage protocol, as a sans-I/O state machine over the primitives of a
//! binding.
//!
//! The driver orders the journal entries, the conditional commits, the voids, the creation entries, the
//! acknowledgements, fencing, reconciliation, restore, and the completion of in-doubt consumptions. It does no I/O.
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
//! The driver runs one operation at a time, in the order of the requests, and a start first. An operation is a
//! commit ([`Driver::submit`]), a lookup ([`Driver::lookup`]), a start ([`Driver::start`]), a restore
//! ([`Driver::restore`]), or a move of the mark ([`Driver::advance`]). Thus anchor changes of one owner run one at a
//! time, and each one keeps the turn of its owner from its first effect to its last.
//!
//! An error of a primitive ([`Output::Failed`]) is a crash: the driver stops, gives an unknown outcome to the
//! operation in progress, and serves again only after a start. The driver keeps its durable state in the mark record
//! of the store ([`Kind::Mark`]): the low-water mark of the store state, whether a restore made the state, and the
//! completions that a restore still owes. So the state rolls back with a snapshot, and a start after a crash during a
//! restore completes the rest before it serves.
//!
//! After a restore of a snapshot, call [`Driver::restore`], never [`Driver::start`]: a start voids the entries that a
//! restore applies. A start refuses with [`Error::Restored`] when the journal shows a commit that the store lost: a
//! later write of the mark record, whose number a floor entry of [`Kind::Mark`] records after each write, or the
//! creation entry of an anchor with no end that the store lacks. A crash loses no commit, so it gives no refusal.
//!
//! Limit: a start cannot detect a restore of a snapshot that is newer than the last write of the mark record, when
//! only commits with no creation entry, such as an unlink or a renewal, followed the snapshot. The journal holds no
//! proof that such a commit landed, so its loss looks the same as a crash before the commit.

mod record;

use alloc::collections::{BTreeMap, BTreeSet, VecDeque};
use alloc::vec::Vec;
use core::fmt;
use core::num::{NonZeroU64, NonZeroUsize};
use core::time::Duration;

use super::journal::{self, Anchor, Body, Entries, History, Mark, Reads, Role};
use super::{Commit, Instance, Kind, Profile, Record, Restore, Sequence, intent_records, outcome_of};
use crate::cbor;
use crate::id::AuthorityVersion;
use crate::limits::Limits;
use crate::time::Reading;
use crate::transition::{
    self, Change, Dependency, Effect as Call, Intent, Key, Operation, OperationId, Outcome, Proposal, Receipt,
};

/// The most journal entries after the mark that the driver reads or keeps. A start refuses a longer journal with
/// [`Error::Long`]. The driver moves the mark before it keeps more ([`ADVANCE_AT`]).
pub const JOURNAL_ENTRIES_MAX: usize = 65_536;

/// The journal entries after the last move of the mark at which the driver moves the mark again after an operation.
pub const ADVANCE_AT: usize = JOURNAL_ENTRIES_MAX / 4;

/// The most operations that wait for the driver. A request past it refuses with [`Error::Full`].
pub const QUEUE_MAX: usize = 1_024;

/// The values of a counter that one floor entry reserves.
pub const FLOOR_BLOCK: NonZeroU64 = NonZeroU64::new(1_024).expect("the block is not zero");

/// The most entries, intents, or records of one read or expiry call.
pub const PAGE: NonZeroUsize = NonZeroUsize::new(256).expect("the page is not zero");

/// The least record bound ([`Declaration::record_bytes_max`](super::Declaration::record_bytes_max)) of a binding for
/// a driver with `limits`: the most bytes in a record that the driver writes for itself. These are the mark record,
/// the replay floor, the anchors of a restore and of a completion, and the audit record of each of its commits. The
/// audit record holds the key of each change, so the bound grows with [`Limits::dependencies`].
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
#[derive(Debug)]
pub enum Effect<'a> {
    /// [`Store::start`](super::Store::start). Give [`Output::Started`].
    Start,
    /// [`Store::read`](super::Store::read) of the key. Give [`Output::Read`].
    Read(&'a Key),
    /// [`Store::commit`](super::Store::commit) of the proposal with the instance number. Give [`Output::Committed`].
    Commit(&'a Proposal, Instance),
    /// [`Store::expire`](super::Store::expire). Give [`Output::Expired`].
    Expire(Kind, Duration, NonZeroUsize),
    /// [`Store::range`](super::Store::range) of the prefix after the key. Give [`Output::Range`].
    Range(&'a Key, Option<&'a Key>, NonZeroUsize),
    /// [`Journal::append`](super::Journal::append) of the entry. Give [`Output::Appended`].
    Append(&'a [u8]),
    /// [`Journal::sync`](super::Journal::sync). Give [`Output::Synced`].
    Sync,
    /// [`Journal::read`](super::Journal::read) after the sequence. Give [`Output::Journal`].
    ReadJournal(Sequence, NonZeroUsize),
}

/// The result of an [`Effect`].
#[derive(Debug)]
pub enum Output {
    /// The instance number of the start.
    Started(Instance),
    /// The record of the read.
    Read(Option<Record>),
    /// The result of the commit.
    Committed(Commit),
    /// The number of removed records.
    Expired(usize),
    /// The records of the range.
    Range(Vec<(Key, Record)>),
    /// The sequence of the appended entry.
    Appended(Sequence),
    /// The sync returned.
    Synced,
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
    pub anchors: Vec<(Key, Role)>,
}

/// The answer of an operation of the driver.
#[derive(Debug)]
pub enum Answer {
    /// The outcome of a commit. An operation in progress at a crash gets [`Outcome::Unknown`].
    Outcome(Outcome),
    /// The result of a lookup.
    Lookup(Lookup),
}

/// The result of a lookup of an operation.
#[derive(Debug)]
pub enum Lookup {
    /// The operation committed. The receipt has no artifact.
    Committed(Receipt),
    /// The store has the outcome record of another request with the identity.
    Refused(transition::Error),
    /// No commit has the identity: no restore made the store state, so the operation did not commit.
    Absent,
    /// The store has no outcome record, but a restore made its state, so the operation can have committed.
    Unknown,
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
    /// The binding gave an output that its effect does not ask for, or the sequence of another entry, or it refused
    /// a commit of the driver. The binding is not valid.
    Binding,
    /// The mark record of the store has no valid form.
    Record,
    /// The store state is older than its journal: a restore made it. Call [`Driver::restore`], not
    /// [`Driver::start`].
    Restored,
}

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
            Self::Binding => f.write_str("the binding gave an output that the driver did not ask for"),
            Self::Record => f.write_str("the mark record of the store has no valid form"),
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

/// The value and the durable floor of a counter.
#[derive(Clone, Copy, Debug, Default)]
struct Counter {
    /// The last allocated value.
    value: u64,
    /// The highest value that a durable floor covers.
    floor: u64,
}

/// The state of the driver that its operations share.
#[derive(Debug)]
struct Core {
    /// The binding keeps a restore journal.
    journal: bool,
    /// A crash loses all state of the store, so each start sets the replay floor.
    loses: bool,
    limits: Limits,
    status: Status,
    instance: Instance,
    record: record::State,
    /// The journal after the mark of the store state.
    history: History,
    counters: BTreeMap<Kind, Counter>,
    /// The latest time reading, which the driver's own commits record.
    now: Reading,
    /// The commits of the driver in this instance.
    commits: u64,
    /// The key of the mark record.
    mark_key: Key,
    /// The key of the replay floor record.
    floor_key: Key,
    /// The prefix of the intent records.
    intent_prefix: Key,
    /// The journal entries after the mark at the last move of the mark.
    advanced: usize,
}

impl Core {
    /// A new identity for a commit of the driver: unique, because each start has a larger instance number.
    fn operation(&mut self) -> OperationId {
        self.commits = self.commits.saturating_add(1);
        let id = [
            b"rsauthnz.driver.".as_slice(),
            &self.instance.0.to_be_bytes(),
            &self.commits.to_be_bytes(),
        ]
        .concat();
        OperationId::new(&id).expect("an identity of 32 bytes is valid")
    }

    /// The commits that write the mark record, with `others` after it, and then the floor entry of the write, which
    /// shows each later start that the store state has this write.
    fn marking(&mut self, others: impl IntoIterator<Item = Proposal>) -> Result<Committing, Error> {
        let journaled = written(self.history.state()?);
        self.record.written = self
            .record
            .written
            .max(journaled)
            .checked_add(1)
            .ok_or(Error::Overflow)?;
        let id = self.operation();
        let record = self.record.write(id, self.now, self.limits).ok_or(Error::Record)?;
        let mut committing = Committing::new([record].into_iter().chain(others));
        if self.journal {
            let floor = journal::Floor {
                kind: Kind::Mark,
                value: self.record.written,
            };
            let id = self.operation();
            committing.after = Writing::new(self, [(id, Body::Floor(floor))])?;
        }
        Ok(committing)
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
    Lookup(Looking),
    Advance(Advance),
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
    /// [`Profile::new`] refuses. Each journal entry and each proposal of the driver stays within `limits`. The driver
    /// is down until the first [`Driver::start`].
    ///
    /// Cost class: [`Parse`](crate::limits::Class::Parse).
    ///
    /// # Errors
    ///
    /// [`Error::RecordBound`] when the record bound of the binding is below [`record_bytes_min`] of `limits`: the
    /// binding cannot store each record that the driver writes for itself.
    pub fn new(profile: Profile, limits: Limits) -> Result<Self, Error> {
        let least = record_bytes_min(limits);
        let declaration = profile.declaration();
        (declaration.record_bytes_max >= least).ok_or(Error::RecordBound(least))?;
        Ok(Self {
            core: Core {
                journal: matches!(declaration.restore, Restore::Journal { .. }),
                loses: declaration.crash_loss == super::CrashLoss::Everything,
                limits,
                status: Status::Down,
                instance: Instance(0),
                record: record::State::default(),
                history: History::new(Mark::EMPTY),
                counters: BTreeMap::new(),
                now: Reading::new(Duration::ZERO, None, crate::time::ReadingSource::Caller),
                commits: 0,
                mark_key: record::mark_key(),
                floor_key: record::floor_key(),
                intent_prefix: Kind::Intent.key(&[]).expect("a key of one byte is valid"),
                advanced: 0,
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

    /// Starts the store at `now`: a new instance number, then reconciliation, then service. Call it at first, and after
    /// each crash. Never call it after a restore of the store: call [`Driver::restore`].
    ///
    /// Cost class: [`Mutate`](crate::limits::Class::Mutate).
    pub fn start(&mut self, now: Reading) {
        self.begin(now, Begin::Start);
    }

    /// Restores the store at `now`, after the binding restored a snapshot: the driver applies the journal after the
    /// mark of the snapshot, completes each in-doubt consumption, and then serves.
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

    fn begin(&mut self, now: Reading, begin: Begin) {
        self.core.now = now;
        self.queue
            .retain(|job| !matches!(job.work, Work::Start(_) | Work::Advance(_)));
        self.queue.push_front(Job {
            ticket: None,
            cancelled: false,
            work: Work::Start(Box::new(Start::new(begin))),
        });
    }

    /// Moves the mark of the store at `now` past each journal entry that the store state reflects. The driver also
    /// moves it after a start and after [`ADVANCE_AT`] entries.
    ///
    /// Cost class: [`Mutate`](crate::limits::Class::Mutate).
    pub fn advance(&mut self, now: Reading) {
        self.core.now = now;
        self.queue.push_back(Job {
            ticket: None,
            cancelled: false,
            work: Work::Advance(Advance::Begin),
        });
    }

    /// A new value of the counter of `kind`, such as a session generation. A commit that writes it waits for a
    /// durable floor that covers it.
    ///
    /// Cost class: [`Parse`](crate::limits::Class::Parse).
    ///
    /// # Errors
    ///
    /// [`Error::Down`] before the first start, and [`Error::Overflow`] after the largest value.
    pub fn allocate(&mut self, kind: Kind) -> Result<u64, Error> {
        (self.core.status == Status::Serving).ok_or(Error::Down)?;
        let counter = self.core.counters.entry(kind).or_default();
        counter.value = counter.value.checked_add(1).ok_or(Error::Overflow)?;
        Ok(counter.value)
    }

    /// Submits the commit of `proposal`, with the anchors and the roles of `plan`. The driver checks the last
    /// anchor of each owner, writes the journal entries, commits, writes the creation entry, and then answers with
    /// an [`Outcome`].
    ///
    /// Cost class: [`Mutate`](crate::limits::Class::Mutate).
    ///
    /// # Errors
    ///
    /// [`Error::Transition`] for a proposal whose entries the journal cannot read back, or with no room for the
    /// journal intent, [`Error::Journal`] for a plan that does not fit the proposal, [`Error::RecordBytes`] for a
    /// proposal that the binding cannot store ([`Profile::admit`]), and [`Error::Full`]. A refused proposal never
    /// reaches the binding.
    pub fn submit(&mut self, mut proposal: Proposal, plan: Plan) -> Result<Ticket, Error> {
        (self.queue.len() < QUEUE_MAX).ok_or(Error::Full)?;
        let entries = journal::entries(&proposal, &plan.replaced, &plan.anchors)?;
        let writes = entries.end.is_some() || !entries.creation.is_empty();
        (!(self.core.journal && writes) || self.core.history.entries().len() < JOURNAL_ENTRIES_MAX)
            .ok_or(Error::Long)?;
        let mut intent = None;
        if self.core.journal {
            if let Some(end) = &entries.end {
                // The widest sequence gives the longest form, so each later append fits too.
                let widest = Mark {
                    sequence: Sequence(u64::MAX - 1),
                    link: Mark::EMPTY.link,
                };
                widest
                    .next(&proposal.operation().id, &Body::End(end.clone()), self.core.limits)
                    .map_err(|_| Error::Transition(transition::Error::Limit(crate::limits::Limit::Bytes)))?;
            }
            let consumes = entries.end.as_ref().is_some_and(|end| end.consumption.is_some());
            if !entries.creation.is_empty() && !consumes {
                let payload = journal::encode_anchors(&entries.creation).into_boxed_slice();
                proposal
                    .intend(Intent::new(Call::Journal, payload))
                    .map_err(Error::Transition)?;
                let records = intent_records(&proposal).map_err(Error::Transition)?;
                intent = records
                    .last()
                    .map(|(key, record)| (key.clone(), record.version.clone()));
            }
        }
        // The check comes after the journal intent, because the binding stores the intent too.
        self.profile.admit(&proposal).map_err(|_| Error::RecordBytes)?;
        let ticket = self.ticket();
        self.queue.push_back(Job {
            ticket: Some(ticket),
            cancelled: false,
            work: Work::Commit(Box::new(Submitted {
                operation: proposal.operation().clone(),
                proposal: Some(proposal),
                held: plan.held,
                entries,
                intent,
                end: None,
                outcome: None,
                answer: None,
                phase: CommitPhase::Check,
            })),
        });
        Ok(ticket)
    }

    /// Looks up the outcome of `operation`: its identity and its request binding, as [`Outcome::Unknown`] gave them.
    ///
    /// Cost class: [`Mutate`](crate::limits::Class::Mutate). The lookup is a keyed read.
    ///
    /// # Errors
    ///
    /// [`Error::Full`].
    pub fn lookup(&mut self, operation: Operation) -> Result<Ticket, Error> {
        (self.queue.len() < QUEUE_MAX).ok_or(Error::Full)?;
        let ticket = self.ticket();
        let key = Kind::Outcome
            .key(operation.id.as_bytes())
            .expect("an operation identity of at most 64 bytes makes a valid key");
        self.queue.push_back(Job {
            ticket: Some(ticket),
            cancelled: false,
            work: Work::Lookup(Looking {
                operation,
                key,
                answer: None,
            }),
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
    /// was known before the crash.
    fn crash(&mut self, status: Status) {
        self.core.status = status;
        if let Some(job) = self.job.take() {
            let answer = match job.work {
                Work::Commit(commit) => Some(Answer::Outcome(
                    commit.answer.unwrap_or(Outcome::Unknown(commit.operation)),
                )),
                Work::Lookup(_) => Some(Answer::Lookup(Lookup::Unknown)),
                Work::Start(_) | Work::Advance(_) => None,
            };
            if let (Some(ticket), false, Some(answer)) = (job.ticket, job.cancelled, answer) {
                self.answers.insert(ticket, answer);
            }
        }
        self.queue.retain(|job| !matches!(job.work, Work::Advance(_)));
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
                    let ended = self
                        .job
                        .take()
                        .map(|job| (job.ticket, job.cancelled, matches!(job.work, Work::Start(_))));
                    if let Some((Some(ticket), false)) = ended.map(|(ticket, cancelled, _)| (ticket, cancelled))
                        && let Some(answer) = answer
                    {
                        self.answers.insert(ticket, answer);
                    }
                    if ended.is_some_and(|(_, _, start)| start) && self.core.journal {
                        self.queue.push_front(Job {
                            ticket: None,
                            cancelled: false,
                            work: Work::Advance(Advance::Begin),
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
                            work: Work::Advance(Advance::Begin),
                        });
                    }
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
            Self::Lookup(lookup) => lookup.answer.is_none().then_some(Effect::Read(&lookup.key)),
            Self::Advance(advance) => advance.effect(core),
        }
    }

    fn give(&mut self, core: &mut Core, output: Output) -> Result<(), Error> {
        match self {
            Self::Start(start) => start.give(core, output),
            Self::Commit(commit) => commit.give(core, output),
            Self::Lookup(lookup) => {
                let Output::Read(record) = output else {
                    return Err(Error::Binding);
                };
                lookup.answer = Some(record);
                Ok(())
            }
            Self::Advance(advance) => advance.give(core, output),
        }
    }

    fn settle(&mut self, core: &mut Core) -> Settled {
        match self {
            Self::Start(start) => start.settle(core),
            Self::Commit(commit) => commit.settle(core),
            Self::Lookup(lookup) => Ok(lookup.answer.as_ref().map(|record| {
                let found = record
                    .as_ref()
                    .and_then(|record| outcome_of(&lookup.operation.id, record));
                Some(Answer::Lookup(match found {
                    Some(stored) => match stored.answer(&lookup.operation) {
                        Outcome::Accepted(receipt) => Lookup::Committed(receipt),
                        _ => Lookup::Refused(transition::Error::Reuse),
                    },
                    None if core.record.restored => Lookup::Unknown,
                    None => Lookup::Absent,
                }))
            })),
            Self::Advance(advance) => advance.settle(core),
        }
    }
}

/// A lookup: the operation, the key of its outcome record, and the record once read.
#[derive(Debug)]
struct Looking {
    operation: Operation,
    key: Key,
    answer: Option<Option<Record>>,
}

// ---------------------------------------------------------------------------------------------------------------
// The parts of an operation: each one gives effects until it is done.

/// Appends entries, then syncs once.
#[derive(Debug, Default)]
struct Writing {
    bodies: VecDeque<(OperationId, Body)>,
    /// The stored form of the next append, and its mark.
    next: Option<(super::Entry, Mark)>,
    sync: bool,
}

impl Writing {
    fn new(core: &Core, bodies: impl IntoIterator<Item = (OperationId, Body)>) -> Result<Self, Error> {
        let mut writing = Self {
            bodies: bodies.into_iter().collect(),
            next: None,
            sync: false,
        };
        writing.encode(core)?;
        Ok(writing)
    }

    fn encode(&mut self, core: &Core) -> Result<(), Error> {
        if let Some((operation, body)) = self.bodies.pop_front() {
            let (data, mark) = core.history.head().next(&operation, &body, core.limits)?;
            self.next = Some((
                super::Entry {
                    sequence: mark.sequence,
                    data,
                },
                mark,
            ));
        }
        Ok(())
    }

    fn effect(&self) -> Option<Effect<'_>> {
        match &self.next {
            Some((entry, _)) => Some(Effect::Append(&entry.data)),
            None => self.sync.then_some(Effect::Sync),
        }
    }

    fn give(&mut self, core: &mut Core, output: Output) -> Result<(), Error> {
        match (self.next.take(), output) {
            (Some((entry, mark)), Output::Appended(sequence)) if sequence == mark.sequence => {
                core.history.extend(&[entry], core.limits)?;
                self.sync = true;
                self.encode(core)
            }
            (None, Output::Synced) if self.sync => {
                self.sync = false;
                Ok(())
            }
            _ => Err(Error::Binding),
        }
    }
}

/// Commits the driver's own proposals, each one accepted, and then writes the entries of `after`.
#[derive(Debug, Default)]
struct Committing {
    proposals: VecDeque<Proposal>,
    after: Writing,
}

impl Committing {
    fn new(proposals: impl IntoIterator<Item = Proposal>) -> Self {
        Self {
            proposals: proposals.into_iter().collect(),
            after: Writing::default(),
        }
    }

    fn effect<'a>(&'a self, core: &Core) -> Option<Effect<'a>> {
        match self.proposals.front() {
            Some(proposal) => Some(Effect::Commit(proposal, core.instance)),
            None => self.after.effect(),
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
            _ => Err(Error::Binding),
        }
    }
}

/// Reads records and outcome records into [`Reads`].
#[derive(Debug, Default)]
struct Fetching {
    keys: VecDeque<Key>,
    operations: VecDeque<(OperationId, Key)>,
    reads: Reads,
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
                    let key = Kind::Outcome
                        .key(operation.as_bytes())
                        .expect("an operation identity of at most 64 bytes makes a valid key");
                    (operation, key)
                })
                .collect(),
            reads: Reads::default(),
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
            self.reads.records.insert(key, record.map(|record| record.version));
        } else if let Some((operation, _)) = self.operations.pop_front() {
            let found = record.is_some_and(|record| outcome_of(&operation, &record).is_some());
            self.reads.outcomes.insert(operation, found);
        } else {
            return Err(Error::Binding);
        }
        Ok(())
    }
}

/// Reads the journal after the head of a history, a page after the other.
#[derive(Debug)]
struct Paging {
    history: History,
    done: bool,
}

impl Paging {
    fn effect(&self) -> Option<Effect<'_>> {
        (!self.done).then(|| Effect::ReadJournal(self.history.head().sequence, PAGE))
    }

    fn give(&mut self, limits: Limits, output: Output) -> Result<(), Error> {
        let Output::Journal(page) = output else {
            return Err(Error::Binding);
        };
        if page.is_empty() {
            self.done = true;
            return Ok(());
        }
        self.history.extend(&page, limits)?;
        (self.history.entries().len() <= JOURNAL_ENTRIES_MAX).ok_or(Error::Long)
    }
}

/// An intent of [`Call::Journal`] that the store holds: the commit owes the creation entry of its anchors.
#[derive(Debug)]
struct Owed {
    operation: OperationId,
    anchors: Vec<Anchor>,
    key: Key,
    version: AuthorityVersion,
}

/// Reads the intent records, a page after the other, and keeps each intent of [`Call::Journal`].
#[derive(Debug, Default)]
struct Scanning {
    after: Option<Key>,
    owed: Vec<Owed>,
    done: bool,
}

impl Scanning {
    fn effect<'a>(&'a self, core: &'a Core) -> Option<Effect<'a>> {
        (!self.done).then_some(Effect::Range(&core.intent_prefix, self.after.as_ref(), PAGE))
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
            let intent = cbor::decode(&record.data, limits)
                .ok()
                .and_then(|form| Intent::from_cbor(&form).ok())
                .filter(|intent| intent.effect() == Call::Journal);
            let Some(intent) = intent else {
                continue;
            };
            // The key of an intent is its kind, its operation identity, and its index of eight bytes.
            let id = key
                .as_bytes()
                .get(1..key.as_bytes().len().saturating_sub(8))
                .and_then(|id| OperationId::new(id).ok());
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

// ---------------------------------------------------------------------------------------------------------------
// A commit.

#[derive(Debug)]
struct Submitted {
    operation: Operation,
    /// The proposal, until its acceptance gives the receipt.
    proposal: Option<Proposal>,
    held: Vec<Anchor>,
    entries: Entries,
    /// The key and the version of the journal intent of the commit.
    intent: Option<(Key, AuthorityVersion)>,
    /// The sequence of the end entry once appended.
    end: Option<Sequence>,
    /// The outcome once known, before the entries that its answer waits for are durable.
    outcome: Option<Outcome>,
    /// The answer: the outcome after the creation entry or the void is durable. A crash before it gives an unknown
    /// outcome.
    answer: Option<Outcome>,
    phase: CommitPhase,
}

#[derive(Debug)]
enum CommitPhase {
    /// The last-anchor check, then the floors and the end entry.
    Check,
    /// The floor of a binding with no journal, in the mark record.
    Floor(Committing),
    /// The floor entries and the end entry, then a sync.
    Entries(Writing),
    /// The conditional commit.
    Commit,
    /// The result of the commit.
    Result(Commit),
    /// The creation entry, then a sync.
    Creation(Writing),
    /// The end of the journal intent.
    Release(Committing),
    /// The void of the end entry, then a sync.
    Void(Writing),
    Done,
}

impl Submitted {
    fn effect<'a>(&'a self, core: &'a Core) -> Option<Effect<'a>> {
        match &self.phase {
            CommitPhase::Floor(committing) | CommitPhase::Release(committing) => committing.effect(core),
            CommitPhase::Entries(writing) | CommitPhase::Creation(writing) | CommitPhase::Void(writing) => {
                writing.effect()
            }
            CommitPhase::Commit => self
                .proposal
                .as_ref()
                .map(|proposal| Effect::Commit(proposal, core.instance)),
            CommitPhase::Check | CommitPhase::Result(_) | CommitPhase::Done => None,
        }
    }

    fn give(&mut self, core: &mut Core, output: Output) -> Result<(), Error> {
        match &mut self.phase {
            CommitPhase::Floor(committing) | CommitPhase::Release(committing) => committing.give(core, output),
            CommitPhase::Entries(writing) | CommitPhase::Creation(writing) | CommitPhase::Void(writing) => {
                writing.give(core, output)
            }
            CommitPhase::Commit => {
                let Output::Committed(result) = output else {
                    return Err(Error::Binding);
                };
                self.phase = CommitPhase::Result(result);
                Ok(())
            }
            CommitPhase::Check | CommitPhase::Result(_) | CommitPhase::Done => Err(Error::Binding),
        }
    }

    fn settle(&mut self, core: &mut Core) -> Settled {
        loop {
            if self.effect(core).is_some() {
                return Ok(None);
            }
            let operation = self.operation.id.clone();
            self.phase = match core::mem::replace(&mut self.phase, CommitPhase::Done) {
                CommitPhase::Check => {
                    let state = core.history.state()?;
                    if !journal::keeps_anchor(&self.entries, &self.held, state)? {
                        return Ok(Some(Some(Answer::Outcome(Outcome::Refused(
                            transition::Error::LastAnchor,
                        )))));
                    }
                    // The floor of each counter covers each allocated value before the commit.
                    let mut floors = Vec::new();
                    for (kind, counter) in &mut core.counters {
                        if counter.value > counter.floor {
                            let floor = journal::Floor::reserve(*kind, counter.floor, counter.value, FLOOR_BLOCK)?
                                .ok_or(Error::Overflow)?;
                            counter.floor = floor.value;
                            floors.push(floor);
                        }
                    }
                    if core.journal {
                        let mut bodies: Vec<(OperationId, Body)> = floors
                            .into_iter()
                            .map(|floor| (operation.clone(), Body::Floor(floor)))
                            .collect();
                        if let Some(end) = &self.entries.end {
                            bodies.push((operation, Body::End(end.clone())));
                        }
                        CommitPhase::Entries(Writing::new(core, bodies)?)
                    } else if floors.is_empty() {
                        CommitPhase::Commit
                    } else {
                        core.record
                            .floors
                            .extend(floors.iter().map(|floor| (floor.kind, floor.value)));
                        CommitPhase::Floor(core.marking([])?)
                    }
                }
                CommitPhase::Floor(_) => CommitPhase::Commit,
                CommitPhase::Entries(_) => {
                    if self.entries.end.is_some() {
                        self.end = Some(core.history.head().sequence);
                    }
                    CommitPhase::Commit
                }
                CommitPhase::Commit => CommitPhase::Commit,
                CommitPhase::Result(Commit::Accepted) => {
                    self.outcome = self
                        .proposal
                        .take()
                        .map(|proposal| Outcome::Accepted(proposal.accept()));
                    if core.journal && !self.entries.creation.is_empty() {
                        // The acknowledgement waits for the creation entry.
                        let body = Body::Creation(self.entries.creation.clone());
                        CommitPhase::Creation(Writing::new(core, [(operation, body)])?)
                    } else {
                        return Ok(Some(self.outcome.take().map(Answer::Outcome)));
                    }
                }
                CommitPhase::Creation(_) => {
                    self.answer = self.outcome.take();
                    match &self.intent {
                        Some((key, version)) => CommitPhase::Release(Committing::new([release(core, key, version)?])),
                        None => return Ok(Some(self.answer.take().map(Answer::Outcome))),
                    }
                }
                CommitPhase::Void(_) => return Ok(Some(self.outcome.take().map(Answer::Outcome))),
                CommitPhase::Release(_) | CommitPhase::Done => {
                    return Ok(Some(self.answer.take().map(Answer::Outcome)));
                }
                CommitPhase::Result(result) => {
                    self.outcome = Some(match result {
                        Commit::Recorded(stored) => stored.answer(&self.operation),
                        Commit::Conflict | Commit::Accepted => Outcome::Conflict,
                    });
                    match self.end {
                        // The commit wrote nothing, so the void of the end entry comes before the answer.
                        Some(end) => CommitPhase::Void(Writing::new(core, [(operation, Body::Void(end))])?),
                        None => return Ok(Some(self.outcome.take().map(Answer::Outcome))),
                    }
                }
            };
        }
    }
}

// ---------------------------------------------------------------------------------------------------------------
// A start or a restore.

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum Begin {
    Start,
    Restore,
}

#[derive(Debug)]
struct Start {
    begin: Begin,
    phase: StartPhase,
    /// The journal intents that the store holds.
    owed: Vec<Owed>,
    /// The reads of the store state.
    reads: Reads,
    /// The restore decision, for a restore.
    activation: Option<journal::Activation>,
}

#[derive(Debug)]
enum StartPhase {
    /// The new instance number.
    Instance,
    /// The read of the mark record.
    Mark,
    /// The journal after the mark.
    Journal(Paging),
    /// The journal intents.
    Intents(Scanning),
    /// The reads of the store state.
    Reads(Fetching),
    /// The mark record with the completions that the restore owes, before the restore applies anything.
    Record(Committing),
    /// The facts, the anchors, and the replay floor of a restore.
    Apply(Committing),
    /// The end of the pending records of the kinds that pay for no anchor.
    Ends(VecDeque<Kind>),
    /// The completions that the restore owes.
    Complete(VecDeque<Proposal>),
    /// The reads for reconciliation after a restore.
    Recheck(Fetching),
    /// The missing creation entries and the voids.
    Reconcile(Writing),
    /// The end of the journal intents.
    Release(Committing),
    /// The mark record with no completion owed, and the replay floor of a binding that loses its state.
    Close(Committing),
    Done,
}

impl Start {
    fn new(begin: Begin) -> Self {
        Self {
            begin,
            phase: StartPhase::Instance,
            owed: Vec::new(),
            reads: Reads::default(),
            activation: None,
        }
    }

    fn effect<'a>(&'a self, core: &'a Core) -> Option<Effect<'a>> {
        match &self.phase {
            StartPhase::Instance => Some(Effect::Start),
            StartPhase::Mark => Some(Effect::Read(&core.mark_key)),
            StartPhase::Journal(paging) => paging.effect(),
            StartPhase::Intents(scanning) => scanning.effect(core),
            StartPhase::Reads(reading) | StartPhase::Recheck(reading) => reading.effect(),
            StartPhase::Record(committing)
            | StartPhase::Apply(committing)
            | StartPhase::Release(committing)
            | StartPhase::Close(committing) => committing.effect(core),
            StartPhase::Ends(kinds) => kinds.front().map(|kind| Effect::Expire(*kind, Duration::MAX, PAGE)),
            StartPhase::Complete(proposals) => proposals
                .front()
                .map(|proposal| Effect::Commit(proposal, core.instance)),
            StartPhase::Reconcile(writing) => writing.effect(),
            StartPhase::Done => None,
        }
    }

    fn give(&mut self, core: &mut Core, output: Output) -> Result<(), Error> {
        match &mut self.phase {
            StartPhase::Instance => {
                let Output::Started(instance) = output else {
                    return Err(Error::Binding);
                };
                core.instance = instance;
                core.commits = 0;
                self.phase = StartPhase::Mark;
                Ok(())
            }
            StartPhase::Mark => {
                let Output::Read(record) = output else {
                    return Err(Error::Binding);
                };
                core.record = match record {
                    None => record::State::default(),
                    Some(record) => record::State::read(&record, core.limits).ok_or(Error::Record)?,
                };
                self.phase = if core.journal {
                    StartPhase::Journal(Paging {
                        history: History::new(core.record.mark),
                        done: false,
                    })
                } else {
                    StartPhase::Reads(Fetching::new(core.loses.then(|| core.floor_key.clone()), []))
                };
                Ok(())
            }
            StartPhase::Journal(paging) => paging.give(core.limits, output),
            StartPhase::Intents(scanning) => scanning.give(core.limits, output),
            StartPhase::Reads(reading) | StartPhase::Recheck(reading) => reading.give(output),
            StartPhase::Record(committing)
            | StartPhase::Apply(committing)
            | StartPhase::Release(committing)
            | StartPhase::Close(committing) => committing.give(core, output),
            StartPhase::Ends(kinds) => {
                let Output::Expired(removed) = output else {
                    return Err(Error::Binding);
                };
                if removed < PAGE.get() {
                    kinds.pop_front();
                }
                Ok(())
            }
            StartPhase::Complete(proposals) => {
                // A completion that does not commit leaves its value consumed. One that the store recorded
                // completed before a crash.
                let Output::Committed(_) = output else {
                    return Err(Error::Binding);
                };
                proposals.pop_front();
                Ok(())
            }
            StartPhase::Reconcile(writing) => writing.give(core, output),
            StartPhase::Done => Err(Error::Binding),
        }
    }

    fn settle(&mut self, core: &mut Core) -> Settled {
        loop {
            if self.effect(core).is_some() {
                return Ok(None);
            }
            self.phase = match core::mem::replace(&mut self.phase, StartPhase::Done) {
                StartPhase::Journal(paging) => {
                    core.history = paging.history;
                    StartPhase::Intents(Scanning::default())
                }
                StartPhase::Intents(scanning) => {
                    self.owed = scanning.owed;
                    StartPhase::Reads(self.reading(core))
                }
                StartPhase::Reads(reading) => {
                    self.reads = reading.reads;
                    if !core.journal {
                        self.close(core)?
                    } else if self.begin == Begin::Restore {
                        let activation = journal::restore(&core.history, &self.reads)?;
                        core.record.restored = true;
                        core.record.owed = activation
                            .completions
                            .iter()
                            .map(|completion| completion.sequence)
                            .collect();
                        self.activation = Some(activation);
                        StartPhase::Record(core.marking([])?)
                    } else {
                        self.check(core)?;
                        if core.record.owed.is_empty() {
                            self.reconcile(core)?
                        } else {
                            // A crash stopped a restore: apply it again, and complete what it still owes.
                            self.activation = Some(journal::restore(&core.history, &self.reads)?);
                            StartPhase::Apply(Committing::new(self.apply(core)?))
                        }
                    }
                }
                StartPhase::Record(_) => StartPhase::Apply(Committing::new(self.apply(core)?)),
                StartPhase::Apply(_) => StartPhase::Ends(
                    self.activation
                        .as_ref()
                        .map(|activation| activation.ends.iter().copied().collect())
                        .unwrap_or_default(),
                ),
                StartPhase::Ends(_) => StartPhase::Complete(self.completions(core)?),
                StartPhase::Complete(_) => StartPhase::Recheck(self.reading(core)),
                StartPhase::Recheck(reading) => {
                    self.reads = reading.reads;
                    self.reconcile(core)?
                }
                StartPhase::Reconcile(_) => {
                    // A copy, because each release changes the driver. Each start runs this once.
                    let state = core.history.state()?.clone();
                    let mut releases = VecDeque::new();
                    for owed in &self.owed {
                        if state.acknowledges([&owed.operation]) {
                            releases.push_back(release(core, &owed.key, &owed.version)?);
                        }
                    }
                    StartPhase::Release(Committing::new(releases))
                }
                StartPhase::Release(_) => self.close(core)?,
                StartPhase::Close(_) => {
                    let state = core.history.state()?;
                    core.counters.clear();
                    let journaled = state.floors().map(|floor| (floor.kind, floor.value));
                    let counters = journaled
                        .chain(core.record.floors.clone())
                        .filter(|(kind, _)| *kind != Kind::Mark);
                    for (kind, value) in counters {
                        let counter = core.counters.entry(kind).or_default();
                        counter.value = counter.value.max(value);
                        counter.floor = counter.value;
                    }
                    core.status = Status::Serving;
                    return Ok(Some(None));
                }
                StartPhase::Instance | StartPhase::Mark | StartPhase::Done => return Ok(Some(None)),
            };
        }
    }

    /// The reads of each key and outcome record that the rules read: those of the journal after the mark, those of
    /// the journal intents, and the replay floor.
    fn reading(&self, core: &Core) -> Fetching {
        let keys: Vec<Key> = core
            .history
            .keys()
            .into_iter()
            .cloned()
            .chain([core.floor_key.clone()])
            .collect();
        let operations: Vec<OperationId> = core
            .history
            .operations()
            .into_iter()
            .cloned()
            .chain(self.owed.iter().map(|owed| owed.operation.clone()))
            .collect();
        Fetching::new(keys, operations)
    }

    /// The commits of a restore: the end of each record at or below the version of its fact, the anchors that a
    /// creation entry made, and the replay floor. Each one reads the store first, so a second run after a crash
    /// commits only what the first did not.
    fn apply(&self, core: &mut Core) -> Result<VecDeque<Proposal>, Error> {
        let activation = self.activation.as_ref().ok_or(Error::Record)?;
        let records = &self.reads.records;
        let mut ended = BTreeSet::new();
        let mut facts = Vec::new();
        for fact in &activation.facts {
            if let Some(Some(version)) = records.get(&fact.key)
                && version.compare(&fact.version).map_err(|_| Error::Record)? != core::cmp::Ordering::Greater
            {
                ended.insert(&fact.key);
                facts.push((
                    Dependency::Version(fact.key.clone(), version.clone()),
                    Change::End(fact.key.clone()),
                ));
            }
        }
        let mut anchors = Vec::new();
        for anchor in &activation.anchors {
            let read = match records.get(&anchor.key) {
                _ if ended.contains(&anchor.key) => Dependency::Absent(anchor.key.clone()),
                Some(None) => Dependency::Absent(anchor.key.clone()),
                Some(Some(version))
                    if version.compare(&anchor.version).map_err(|_| Error::Record)? == core::cmp::Ordering::Less =>
                {
                    Dependency::Version(anchor.key.clone(), version.clone())
                }
                _ => continue,
            };
            let write = Change::Write {
                key: anchor.key.clone(),
                version: anchor.version.clone(),
                end: anchor.end,
                data: anchor.data.clone(),
            };
            anchors.push((read, write));
        }
        let mut proposals = VecDeque::new();
        for changes in [facts, anchors] {
            for chunk in changes.chunks(core.limits.dependencies.max(1)) {
                let mut proposal = record::proposal(core.operation(), record::RESTORE, core.now, core.limits);
                for (read, change) in chunk {
                    proposal.read(read.clone()).map_err(Error::Transition)?;
                    proposal.change(change.clone()).map_err(Error::Transition)?;
                }
                proposals.push_back(proposal);
            }
        }
        let floor = records.get(&core.floor_key).cloned().flatten();
        let id = core.operation();
        proposals.push_back(record::replay_floor(id, core.now, core.limits, floor.as_ref()).ok_or(Error::Record)?);
        Ok(proposals)
    }

    /// The completions that the mark record owes: each in-doubt consumption, under its operation identity and its
    /// request binding, with no outcome record yet. Each one depends on the absence of the anchors that it creates.
    fn completions(&self, core: &Core) -> Result<VecDeque<Proposal>, Error> {
        let mut proposals = VecDeque::new();
        for sequence in &core.record.owed {
            let entry = core
                .history
                .entries()
                .iter()
                .find(|entry| entry.sequence == *sequence)
                .ok_or(Error::Record)?;
            let Body::End(journal::End {
                consumption: Some(consumption),
                ..
            }) = &entry.body
            else {
                return Err(Error::Record);
            };
            if self.reads.outcomes.get(&entry.operation) == Some(&true) {
                continue;
            }
            let operation = Operation {
                id: entry.operation.clone(),
                binding: consumption.binding,
            };
            let mut proposal = Proposal::again(operation, record::audit(record::RESTORE, core.now), core.limits);
            for anchor in &consumption.anchors {
                proposal
                    .read(Dependency::Absent(anchor.key.clone()))
                    .map_err(Error::Transition)?;
                proposal
                    .change(Change::Write {
                        key: anchor.key.clone(),
                        version: anchor.version.clone(),
                        end: anchor.end,
                        data: anchor.data.clone(),
                    })
                    .map_err(Error::Transition)?;
            }
            proposals.push_back(proposal);
        }
        Ok(proposals)
    }

    /// The missing creation entries and the voids of reconciliation.
    fn reconcile(&self, core: &Core) -> Result<StartPhase, Error> {
        let candidates: Vec<(OperationId, Vec<Anchor>)> = self
            .owed
            .iter()
            .map(|owed| (owed.operation.clone(), owed.anchors.clone()))
            .collect();
        let decision = journal::reconcile(&core.history, &self.reads, &candidates)?;
        let creations = decision
            .creations
            .into_iter()
            .map(|(operation, anchors)| (operation, Body::Creation(anchors)));
        let voids = decision
            .voids
            .into_iter()
            .map(|(operation, sequence)| (operation, Body::Void(sequence)));
        Ok(StartPhase::Reconcile(Writing::new(core, creations.chain(voids))?))
    }

    /// Refuses a start on a store state that a restore made: a later write of the mark record than the store holds,
    /// or a creation entry of an anchor with no end that the store lacks, shows a commit that the store lost. A crash
    /// loses no commit, so a start after a crash passes.
    fn check(&self, core: &mut Core) -> Result<(), Error> {
        let state = core.history.state()?;
        (written(state) <= core.record.written).ok_or(Error::Restored)?;
        if core.record.owed.is_empty() {
            for anchor in state.anchors().filter(|anchor| anchor.end.is_none()) {
                let held = self.reads.records.get(&anchor.key).is_some_and(Option::is_some);
                (held || state.ends(&anchor.key, &anchor.version)?).ok_or(Error::Restored)?;
            }
        }
        Ok(())
    }

    /// The last commits of a start: the mark record, with no completion owed, then the floor entry of its write, and
    /// the replay floor of a binding that loses its state.
    fn close(&self, core: &mut Core) -> Result<StartPhase, Error> {
        core.record.owed.clear();
        let mut floor = None;
        if core.loses && self.begin == Begin::Start {
            let version = self.reads.records.get(&core.floor_key).cloned().flatten();
            let id = core.operation();
            floor = Some(record::replay_floor(id, core.now, core.limits, version.as_ref()).ok_or(Error::Record)?);
        }
        Ok(StartPhase::Close(core.marking(floor)?))
    }
}

// ---------------------------------------------------------------------------------------------------------------
// A move of the mark.

#[derive(Debug)]
enum Advance {
    Begin,
    Reads(Fetching),
    /// A floor entry of each counter, with its value again, after the floor entries that hold the mark, and the reads.
    Restate(Writing, Reads),
    /// The mark record with the new mark.
    Write(Committing, Mark),
    Done,
}

impl Advance {
    fn effect<'a>(&'a self, core: &'a Core) -> Option<Effect<'a>> {
        match self {
            Self::Reads(reading) => reading.effect(),
            Self::Restate(writing, _) => writing.effect(),
            Self::Write(committing, _) => committing.effect(core),
            Self::Begin | Self::Done => None,
        }
    }

    fn give(&mut self, core: &mut Core, output: Output) -> Result<(), Error> {
        match self {
            Self::Reads(reading) => reading.give(output),
            Self::Restate(writing, _) => writing.give(core, output),
            Self::Write(committing, _) => committing.give(core, output),
            Self::Begin | Self::Done => Err(Error::Binding),
        }
    }

    fn settle(&mut self, core: &mut Core) -> Settled {
        loop {
            if self.effect(core).is_some() {
                return Ok(None);
            }
            *self = match core::mem::replace(self, Self::Done) {
                Self::Begin if core.journal => Self::Reads(Fetching::new(
                    core.history.keys().into_iter().cloned().collect::<Vec<_>>(),
                    [],
                )),
                Self::Reads(reading) => {
                    let mark = journal::low_water(&core.history, &reading.reads)?;
                    let held = core
                        .history
                        .entries()
                        .iter()
                        .find(|entry| entry.sequence > mark.sequence);
                    if held.is_some_and(|entry| matches!(entry.body, Body::Floor(_))) {
                        // The newest floor of a counter holds the mark: a floor entry of each counter, with its
                        // value again, lets the mark pass the earlier floor entries.
                        let id = core.operation();
                        let state = core.history.state()?;
                        let bodies: Vec<(OperationId, Body)> =
                            state.floors().map(|floor| (id.clone(), Body::Floor(floor))).collect();
                        Self::Restate(Writing::new(core, bodies)?, reading.reads)
                    } else {
                        Self::write(core, mark)?
                    }
                }
                Self::Restate(_, reads) => Self::write(core, journal::low_water(&core.history, &reads)?)?,
                Self::Write(_, mark) => {
                    core.history = core.history.after(mark);
                    core.advanced = core.history.entries().len();
                    return Ok(Some(None));
                }
                Self::Begin | Self::Done => return Ok(Some(None)),
            };
        }
    }

    /// The mark record with `mark`, or the end of the move when the mark stays.
    fn write(core: &mut Core, mark: Mark) -> Result<Self, Error> {
        if mark == core.record.mark {
            core.advanced = core.history.entries().len();
            return Ok(Self::Done);
        }
        core.record.mark = mark;
        Ok(Self::Write(core.marking([])?, mark))
    }
}

#[cfg(test)]
mod tests;
