//! The memory binding: the reference of the storage contract for tests and examples. Never use it as a production
//! store.
//!
//! [`Memory`] implements [`Store`] and [`Journal`] in the memory of the process. One mutex holds all its state, so
//! each primitive is one atomic step and each commit is serializable. The clones of a [`Memory`] share one binding:
//! give each concurrent caller, such as each driver of a server, its own clone.
//!
//! The binding simulates a durable store, and a restore journal in a separate failure domain. [`Subject::inject`] gives
//! a [`Fault`] of the suite to the next call of its primitive. A [`Schedule`] injects crashes at the primitives: each
//! fault, and two crashes of its own ([`Error::CrashAfterCommit`] and [`Error::DelayedCommit`]). The same faults and
//! the same calls give the same results. A crash keeps each commit of the simulated store that landed, and each entry
//! of the journal whose sync returned. A crash at a commit or an append stops only the clone that made the call: the
//! journal keeps an accepted append, and the next sync covers it. A failed sync crashes the whole binding: each clone
//! stops, and the appends after the last sync are lost. A stopped clone gives the [`Error`] of its crash until it calls
//! [`Store::start`] or [`Store::instance`].
//!
//! The binding implements [`Subject`], the controls of the conformance [suite](crate::suite), and passes each case.
//! [`Subject::restart`] is the loss of the process: the store loses all its state, and the journal keeps its synced
//! entries. The declaration states it with [`CrashLoss::Everything`]. [`Subject::snapshot`] and [`Subject::restore`]
//! copy the state of the store, whose mark record holds its low-water mark. A restore writes a fresh instance number,
//! so the store refuses each commit of an earlier start at once. [`Subject::lose`] removes entries of the journal.
//!
//! Each future of the binding is ready at its first poll. A commit whose response is lost gives an error, and a lookup
//! after the next start shows that it landed:
//!
//! ```
//! use core::pin::pin;
//! use core::task::{Context, Poll, Waker};
//! use core::time::Duration;
//!
//! use rsauthnz::cbor::Value;
//! use rsauthnz::id::{AuthorityVersion, Human, Id, Principal};
//! use rsauthnz::limits::Limits;
//! use rsauthnz::store::{Kind, Store};
//! use rsauthnz::time::{Reading, ReadingSource};
//! use rsauthnz::transition::{Audit, Change, Dependency, OperationId, Proposal};
//! use rsauthnz_conformance::memory::{Error, Memory, Schedule};
//! use rsauthnz_conformance::suite::{Fault, Subject};
//!
//! /// The output of a future of the memory binding.
//! fn ready<F: Future>(future: F) -> F::Output {
//!     match pin!(future).poll(&mut Context::from_waker(Waker::noop())) {
//!         Poll::Ready(output) => output,
//!         Poll::Pending => unreachable!("the memory binding does no I/O"),
//!     }
//! }
//!
//! let mut memory = Memory::new(Schedule::None);
//! let instance = ready(memory.start())?;
//!
//! // The proposal creates a credential.
//! let audit = Audit {
//!     actor: Principal::Human(Id::<Human>::new("acme", "u-17")?),
//!     action: Id::new("acme.auth", "credential.enroll")?,
//!     time: Reading::new(Duration::from_secs(1_000), Some(Duration::from_secs(1)), ReadingSource::Caller),
//! };
//! let credential = Kind::Credential.key(b"c-4")?;
//! let mut proposal = Proposal::new(OperationId::new(b"op-1")?, audit, &Value::Null, Limits::default())?;
//! proposal.read(Dependency::Absent(credential.clone()))?;
//! proposal.change(Change::Write {
//!     key: credential,
//!     version: AuthorityVersion::new(Id::new("acme", "auth")?, &[1])?,
//!     end: None,
//!     data: Box::new(*b"the credential record"),
//! })?;
//!
//! // The commit lands, and its response is lost. The binding stops until the next start.
//! memory.inject(Fault::LostResponse);
//! assert_eq!(ready(memory.commit(&proposal, instance)), Err(Error::Crash(Fault::LostResponse)));
//! ready(memory.start())?;
//! let outcome = ready(memory.outcome(&proposal.operation().id))?;
//! assert_eq!(outcome.as_ref(), Some(proposal.operation()));
//! # Ok::<(), Box<dyn core::error::Error>>(())
//! ```

use core::fmt;
use core::mem;
use core::num::NonZeroUsize;
use core::ops::{Bound, RangeBounds};
use core::time::Duration;
use std::collections::BTreeMap;
use std::sync::{Arc, Mutex, MutexGuard, PoisonError};

use rsauthnz::id::{AuthorityVersion, Id, Principal};
use rsauthnz::store::journal::{Append, Mark};
use rsauthnz::store::{
    self, Capacity, Commit, CrashInjection, CrashLoss, Declaration, Entry, Expiry, Insert, Inserted, Instance,
    Isolation, Journal, JournalWrite, Kind, Record, Restore, Sequence, Store,
};
use rsauthnz::time::{Reading, ReadingSource};
use rsauthnz::transition::{Change, Dependency, Key, OperationId, Proposal};
use rscrypto::RapidHash64;

use crate::suite::{Fault, Subject};

/// A crash that the binding injects at one primitive: a fault of the suite, or a crash that only a seeded
/// [`Schedule`] gives.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum Crash {
    Fault(Fault),
    /// [`Error::CrashAfterCommit`].
    AfterCommit,
    /// [`Error::DelayedCommit`].
    Delayed,
}

impl Crash {
    /// Each crash that a seeded schedule can give.
    const ALL: [Self; 6] = [
        Self::Fault(Fault::CrashBeforeCommit),
        Self::Fault(Fault::LostResponse),
        Self::AfterCommit,
        Self::Delayed,
        Self::Fault(Fault::CrashAfterAppend),
        Self::Fault(Fault::FailedSync),
    ];

    /// The primitive that takes the crash.
    const fn primitive(self) -> Primitive {
        match self {
            Self::Fault(Fault::CrashBeforeCommit | Fault::LostResponse) | Self::AfterCommit | Self::Delayed => {
                Primitive::Commit
            }
            Self::Fault(Fault::CrashAfterAppend) => Primitive::Append,
            Self::Fault(Fault::FailedSync) => Primitive::Sync,
        }
    }

    /// The error of each primitive after the crash.
    const fn error(self) -> Error {
        match self {
            Self::Fault(fault) => Error::Crash(fault),
            Self::AfterCommit => Error::CrashAfterCommit,
            Self::Delayed => Error::DelayedCommit,
        }
    }
}

/// A primitive that can take a fault.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum Primitive {
    Commit,
    Append,
    Sync,
}

/// The faults that a binding injects.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Schedule {
    /// No fault.
    None,
    /// Faults from this seed. Each commit, append, and sync takes a crash with a chance of one in 8, and each crash
    /// of its primitive has the same chance: each [`Fault`], [`Error::CrashAfterCommit`], and
    /// [`Error::DelayedCommit`]. The draw of a call is the RapidHash of its primitive and its number, with the seed,
    /// so a seed gives the same faults at each run.
    Seeded(u64),
}

/// A call gets a fault from a seeded schedule when its draw is a multiple of this number.
const SEEDED_ONE_IN: u8 = 8;

/// The cause of a failed primitive. Each error is a crash with an unknown outcome: call [`Store::start`].
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Error {
    /// The binding is new, or it had a restart, and it did not start after it.
    Stopped,
    /// The binding exhausted its store instance numbers. It cannot fence another activation.
    Instance,
    /// The fault crashed the binding at this primitive or at an earlier one.
    Crash(Fault),
    /// A seeded schedule crashed the binding after a commit gave its result. The commit landed when its result was
    /// [`Commit::Accepted`].
    CrashAfterCommit,
    /// A seeded schedule crashed the binding while a commit was in flight. The commit arrives after the next start,
    /// with the instance number of the earlier start, so it refuses and writes nothing.
    DelayedCommit,
}

impl fmt::Display for Error {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Stopped => f.write_str("the memory binding did not start"),
            Self::Instance => f.write_str("the memory binding exhausted its store instances"),
            Self::Crash(fault) => write!(f, "the memory binding crashed with the fault {fault:?}"),
            Self::CrashAfterCommit => f.write_str("the memory binding crashed after a commit"),
            Self::DelayedCommit => f.write_str("the memory binding crashed with a commit in flight"),
        }
    }
}

impl core::error::Error for Error {}

/// A snapshot of the store. The mark record of the store state holds its low-water mark. A restore gives back its
/// state, and the journal keeps its own entries.
#[derive(Clone, Debug)]
pub struct Snapshot(State);

/// The state of the simulated store. A crash keeps it, and a restart loses it.
#[derive(Clone, Debug, Default)]
struct State {
    /// The records, the policy, audit, outcome, and intent records included.
    records: BTreeMap<Key, Record>,
}

/// The outcome retention of a new binding. Each audit and outcome record ends at the estimate of the audit time of its
/// proposal plus the retention, which saturates at `Duration::MAX`. [`Memory::with_retention`] sets another one.
const RETENTION: Duration = Duration::MAX;

/// The capacity of the replay records of signatures of a new binding. [`Memory::with_capacity`] sets another one.
const CAPACITY: Capacity = Capacity {
    records_max: 4_096,
    share_max: 256,
};

impl State {
    /// Whether a new record at `key` fits `capacity`. A key of another kind than [`Kind::Signature`], and a key that a
    /// record has, need no room.
    fn room(&self, key: &Key, capacity: Capacity) -> bool {
        let Some(share) = store::share(key) else {
            return true;
        };
        // The keys of a prefix are adjacent in the order of the map, so each count reads only the keys of its prefix.
        let count = |prefix: &[u8]| {
            let start = Kind::Signature
                .key(prefix.get(1..).unwrap_or_default())
                .expect("a prefix of a key is a valid key");
            self.records
                .range(start..)
                .take_while(|(key, _)| key.as_bytes().starts_with(prefix))
                .count()
        };
        self.records.contains_key(key) || capacity.admits(count(&[Kind::Signature as u8]), count(share))
    }

    /// Whether `dependency` holds in the current state.
    fn holds(&self, dependency: &Dependency) -> bool {
        let at = |key: &Key, version: &AuthorityVersion| {
            self.records.get(key).is_some_and(|record| record.version == *version)
        };
        match dependency {
            Dependency::Policy(version) => at(&store::policy_key(version.owner()), version),
            Dependency::Version(key, version) => at(key, version),
            Dependency::Absent(key) => !self.records.contains_key(key),
        }
    }

    /// The records whose key starts with `prefix` and comes after `after`, in key order. The keys of one prefix are one
    /// range of the key order, which starts at the prefix.
    fn range<'a>(&'a self, prefix: &'a Key, after: Option<&Key>) -> impl Iterator<Item = (&'a Key, &'a Record)> {
        let lower = match after {
            Some(after) if after >= prefix => Bound::Excluded(after.clone()),
            _ => Bound::Included(prefix.clone()),
        };
        self.records
            .range((lower, Bound::Unbounded))
            .take_while(move |(key, _)| key.as_bytes().starts_with(prefix.as_bytes()))
    }
}

/// A commit in flight: the parts of its proposal that it checks and writes.
#[derive(Debug)]
struct Request {
    id: OperationId,
    /// The key of the outcome record.
    outcome: Key,
    dependencies: Vec<Dependency>,
    changes: Vec<Change>,
    /// The intent records, the audit record, and the outcome record.
    records: Vec<(Key, Record)>,
    /// The deadline of the proposal, which the clock of the binding checks when the commit applies.
    deadline: Option<Duration>,
    /// The proposal is a commit of the driver itself, such as the reservation of an owner turn.
    driver: bool,
}

impl Request {
    /// The request of `proposal`, whose audit and outcome records end after `retention`.
    fn new(proposal: &Proposal, retention: Duration) -> Self {
        let mut records = store::intent_records(proposal)
            .expect("an intent record has a key of at most 73 bytes and an encodable CBOR form");
        let outcome = store::outcome_record(proposal);
        let key = outcome.0.clone();
        let end = Some(proposal.audit().time.estimate().saturating_add(retention));
        records.extend([store::audit_record(proposal), outcome].map(|(key, record)| (key, Record { end, ..record })));
        Self {
            id: proposal.operation().id.clone(),
            outcome: key,
            dependencies: proposal.dependencies().to_vec(),
            changes: proposal.changes().to_vec(),
            records,
            deadline: proposal.deadline(),
            driver: proposal.audit().actor
                == Principal::Workload(Id::new("rsauthnz", "driver").expect("the driver identifier is valid")),
        }
    }
}

/// The clock of a binding: the reading of [`Memory::set_clock`], or the clock of the host of [`Memory::with_clock`].
#[derive(Clone)]
struct Clock(Arc<dyn Fn() -> Reading + Send + Sync>);

impl fmt::Debug for Clock {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("Clock")
    }
}

/// The state of a binding, which its clones share.
#[derive(Debug)]
struct Binding {
    store: State,
    /// The durable entries of the journal. A crash, a restart, and a restore keep them.
    journal: BTreeMap<Sequence, Box<[u8]>>,
    /// The last durable head. Journal retention keeps this mark.
    synced: Mark,
    /// The head including entries that await sync.
    head: Mark,
    /// The appends after the last sync. A crash loses them, so the next append gets the first sequence of them.
    unsynced: Vec<Entry>,
    /// The instance number of the last start or restore. A start and a restore each write the next number, so it
    /// increases for the life of the binding, and a commit from each earlier start refuses.
    instance: Instance,
    /// Whether a handle started or joined the binding since it was new or since its last restart.
    started: bool,
    /// The number of crashes of the whole binding: a failed sync or a restart. A handle of an earlier number gives
    /// [`Error::Stopped`] until it starts or joins again.
    epoch: u64,
    /// A commit of [`Error::DelayedCommit`] and its instance number. It lands at the next start or join.
    delayed: Option<(Request, Instance)>,
    schedule: Schedule,
    /// The fault of [`Subject::inject`] for the next call of its primitive.
    injected: Option<Fault>,
    /// The fault of [`Memory::inject_application`] for the next commit of a proposal of the application.
    application: Option<Fault>,
    /// The number of calls of each primitive that can take a fault, in the order of [`Primitive`].
    calls: [u64; 3],
    /// The clock of [`Memory::set_clock`] or [`Memory::with_clock`], which each commit with a deadline reads.
    clock: Clock,
    /// The outcome retention of the declaration.
    retention: Duration,
    /// The capacity of the replay records of signatures of the declaration.
    capacity: Capacity,
}

impl Binding {
    /// Crashes the whole binding: each handle stops until it starts or joins again, and the appends after the last
    /// sync are lost.
    fn crash_all(&mut self) {
        self.epoch = self.epoch.strict_add(1);
        self.discard_unsynced();
    }

    fn discard_unsynced(&mut self) {
        self.unsynced.clear();
        self.head = self.synced;
    }

    fn next_instance(&mut self) -> Result<(), Error> {
        let next = self.instance.0.checked_add(1).ok_or(Error::Instance)?;
        self.discard_unsynced();
        self.instance = Instance(next);
        Ok(())
    }

    /// Lands the delayed commit with the instance number that it carries, at a start or a join.
    fn deliver(&mut self) {
        if let Some((request, instance)) = self.delayed.take() {
            self.apply(request, instance);
        }
    }

    /// Counts a call of `primitive`, and gives the crash that [`Subject::inject`] or the schedule injects at it.
    fn crash(&mut self, primitive: Primitive) -> Option<Crash> {
        let count = &mut self.calls[primitive as usize];
        let call = *count;
        *count = call.strict_add(1);
        if let Some(fault) = self
            .injected
            .take_if(|fault| Crash::Fault(*fault).primitive() == primitive)
        {
            return Some(Crash::Fault(fault));
        }
        match self.schedule {
            Schedule::None => None,
            Schedule::Seeded(seed) => {
                let mut data = [primitive as u8; 9];
                data[1..].copy_from_slice(&call.to_le_bytes());
                let [rate, pick, ..] = RapidHash64::hash_with_seed(seed, &data).to_le_bytes();
                if rate % SEEDED_ONE_IN != 0 {
                    return None;
                }
                let mut crashes = Crash::ALL.into_iter().filter(|crash| crash.primitive() == primitive);
                let count = crashes.clone().count();
                crashes.nth(usize::from(pick) % count)
            }
        }
    }

    /// The commit of `request` with the instance number `instance`, and the crash of the handle after it, if any.
    fn commit(&mut self, request: Request, instance: Instance) -> (Result<Commit, Error>, Option<Error>) {
        let crash = match self.application.take_if(|_| !request.driver) {
            Some(fault) => {
                self.calls[Primitive::Commit as usize] = self.calls[Primitive::Commit as usize].strict_add(1);
                Some(Crash::Fault(fault))
            }
            None => self.crash(Primitive::Commit),
        };
        match crash {
            Some(crash @ Crash::Fault(Fault::CrashBeforeCommit)) => (Err(crash.error()), Some(crash.error())),
            Some(crash @ Crash::Fault(Fault::LostResponse)) => {
                self.apply(request, instance);
                (Err(crash.error()), Some(crash.error()))
            }
            Some(crash @ Crash::AfterCommit) => (Ok(self.apply(request, instance)), Some(crash.error())),
            Some(crash @ Crash::Delayed) => {
                self.delayed = Some((request, instance));
                (Err(crash.error()), Some(crash.error()))
            }
            // A commit takes only the crashes of a commit.
            Some(Crash::Fault(Fault::CrashAfterAppend | Fault::FailedSync)) | None => {
                (Ok(self.apply(request, instance)), None)
            }
        }
    }

    /// The conditional atomic commit of `request` with the instance number `instance`.
    fn apply(&mut self, request: Request, instance: Instance) -> Commit {
        let state = &mut self.store;
        if instance != self.instance {
            return Commit::Superseded;
        }
        if let Some(operation) = state
            .records
            .get(&request.outcome)
            .and_then(|record| store::outcome_of(&request.id, record))
        {
            return Commit::Recorded(operation);
        }
        if !request.dependencies.iter().all(|dependency| state.holds(dependency)) {
            return Commit::Conflict;
        }
        if store::expired(request.deadline, (self.clock.0)()) {
            return Commit::Expired;
        }
        let capacity = self.capacity;
        let fits = request.changes.iter().all(|change| match change {
            Change::Write { key, .. } => state.room(key, capacity),
            Change::End(_) => true,
        });
        if !fits {
            return Commit::Full;
        }
        for change in request.changes {
            match change {
                Change::Write {
                    key,
                    version,
                    end,
                    data,
                } => state.records.insert(key, Record { version, end, data }),
                Change::End(key) => state.records.remove(&key),
            };
        }
        state.records.extend(request.records);
        Commit::Accepted
    }

    /// The atomic replay insert of `insert` ([`Store::insert_replay`]).
    fn insert(&mut self, insert: &Insert) -> Inserted {
        let state = &mut self.store;
        if !insert.admits(state.records.get(&store::floor_key()), self.instance) {
            return Inserted::Floor;
        }
        if state.records.contains_key(insert.key()) {
            return Inserted::Present;
        }
        if !state.room(insert.key(), self.capacity) {
            return Inserted::Full;
        }
        if store::expired(Some(insert.deadline()), (self.clock.0)()) {
            return Inserted::Expired;
        }
        state.records.insert(insert.key().clone(), insert.record());
        Inserted::Accepted
    }
}

/// The clock that gives `now` at each reading.
fn fixed(now: Reading) -> Clock {
    Clock(Arc::new(move || now))
}

/// A handle of one memory binding. Its clones share the binding. Each handle is one connection: a crash at a
/// primitive of a handle stops that handle, and the other handles serve. A failed sync and a restart crash the whole
/// binding, so each handle stops.
#[derive(Clone, Debug)]
pub struct Memory {
    binding: Arc<Mutex<Binding>>,
    /// The crash of this handle, until it starts or joins again.
    crashed: Option<Error>,
    /// The crash number of the binding at the last start or join of this handle.
    epoch: u64,
}

impl Memory {
    /// Makes a binding with an empty store and an empty journal, which injects the faults of `schedule`. It serves
    /// after its first start.
    #[must_use]
    pub fn new(schedule: Schedule) -> Self {
        let binding = Arc::new(Mutex::new(Binding {
            store: State::default(),
            journal: BTreeMap::new(),
            synced: Mark::EMPTY,
            head: Mark::EMPTY,
            unsynced: Vec::new(),
            instance: Instance(0),
            started: false,
            epoch: 0,
            delayed: None,
            schedule,
            injected: None,
            application: None,
            calls: [0; 3],
            clock: fixed(Reading::new(
                Duration::ZERO,
                Some(Duration::ZERO),
                ReadingSource::Caller,
            )),
            retention: RETENTION,
            capacity: CAPACITY,
        }));
        Self {
            binding,
            crashed: None,
            epoch: 0,
        }
    }

    /// The binding with the outcome retention `retention`: each audit and outcome record of a later commit ends that
    /// long after the audit time of its proposal, and an expiry pass after that end removes it. A new binding keeps
    /// each one with no end. Set the retention before the first commit, so that the declaration holds for each record.
    #[must_use]
    pub fn with_retention(self, retention: Duration) -> Self {
        self.lock().retention = retention;
        self
    }

    /// The binding with the capacity `capacity` of the replay records of signatures. Set it before the first insert, so
    /// that the declaration holds for each record.
    #[must_use]
    pub fn with_capacity(self, capacity: Capacity) -> Self {
        self.lock().capacity = capacity;
        self
    }

    /// Gives `fault`, a fault of a commit, to the next commit of a proposal of the application: not to a commit of the
    /// driver itself, such as the reservation of an owner turn before an anchor change.
    ///
    /// # Panics
    ///
    /// If `fault` is not a fault of a commit.
    pub fn inject_application(&self, fault: Fault) {
        assert!(
            matches!(fault, Fault::CrashBeforeCommit | Fault::LostResponse),
            "a fault of a commit"
        );
        self.lock().application = Some(fault);
    }

    /// Sets the reading of the clock of the binding, which each commit with a deadline reads: the controlled clock of a
    /// test. The first reading is the start of the Unix epoch, before each deadline of a test at a fixed time.
    pub fn set_clock(&self, now: Reading) {
        self.lock().clock = fixed(now);
    }

    /// The binding whose clock is `clock`, the clock of the host, such as a reading of the system clock with its bound.
    /// Each commit with a deadline reads it in its atomic step.
    #[must_use]
    pub fn with_clock(self, clock: Arc<dyn Fn() -> Reading + Send + Sync>) -> Self {
        self.lock().clock = Clock(clock);
        self
    }

    /// The shared state. No step of the binding panics while it holds the lock, so a poisoned lock holds a
    /// consistent state.
    fn lock(&self) -> MutexGuard<'_, Binding> {
        self.binding.lock().unwrap_or_else(PoisonError::into_inner)
    }

    /// The shared state of a handle that serves, or the error of its crash.
    fn serving(&self) -> Result<MutexGuard<'_, Binding>, Error> {
        let binding = self.lock();
        match self.crashed {
            Some(error) => Err(error),
            None if !binding.started || binding.epoch != self.epoch => Err(Error::Stopped),
            None => Ok(binding),
        }
    }

    /// The commit of `request` with the instance number `instance`. A crash at it stops this handle.
    fn request(&mut self, request: Request, instance: Instance) -> Result<Commit, Error> {
        let mut binding = self.serving()?;
        let (commit, crash) = binding.commit(request, instance);
        drop(binding);
        if crash.is_some() {
            self.crashed = crash;
        }
        commit
    }

    /// Serves this handle again after a crash: a start or a join.
    fn join(&mut self, binding: &mut Binding) {
        binding.started = true;
        self.crashed = None;
        self.epoch = binding.epoch;
        binding.deliver();
    }
}

impl Subject for Memory {
    type Snapshot = Snapshot;

    fn inject(&self, fault: Fault) {
        self.lock().injected = Some(fault);
    }

    /// The loss of the process: the store loses all its state, and the journal keeps its durable entries. The appends
    /// after the last sync are lost.
    fn restart(&self) {
        let mut binding = self.lock();
        binding.crash_all();
        binding.started = false;
        binding.store = State::default();
    }

    fn snapshot(&self) -> Snapshot {
        Snapshot(self.lock().store.clone())
    }

    /// Installs `snapshot` and the next instance under one lock. The store takes commits
    /// at once, and refuses each commit of an earlier start. The journal keeps its entries, and the appends after the
    /// last sync are lost.
    fn restore(&self, snapshot: &Snapshot) {
        let mut binding = self.lock();
        if binding.next_instance().is_ok() {
            binding.store = snapshot.0.clone();
        }
    }

    fn lose(&self, sequences: impl RangeBounds<Sequence>) {
        self.lock().journal.retain(|sequence, _| !sequences.contains(sequence));
    }

    fn set_clock(&self, now: Reading) {
        Self::set_clock(self, now);
    }
}

impl Store for Memory {
    type Error = Error;

    fn declaration(&self) -> Declaration {
        let binding = self.lock();
        Declaration {
            isolation: Isolation::Serializable,
            crash_loss: CrashLoss::Everything,
            outcome_retention: binding.retention,
            crash_injection: CrashInjection::Supported,
            restore: Restore::Journal {
                location: "the memory of the process".into(),
                failure_domain: "a simulated domain apart from the store and from its snapshots".into(),
            },
            key_bytes_max: Key::BYTES_MAX,
            signatures: binding.capacity,
            record_bytes_max: usize::MAX,
        }
    }

    async fn start(&mut self) -> Result<Instance, Error> {
        let binding = Arc::clone(&self.binding);
        let mut binding = binding.lock().unwrap_or_else(PoisonError::into_inner);
        binding.next_instance()?;
        // A delayed commit lands now, with the instance number of an earlier start, so it refuses.
        self.join(&mut binding);
        Ok(binding.instance)
    }

    async fn instance(&mut self) -> Result<Instance, Error> {
        let binding = Arc::clone(&self.binding);
        let mut binding = binding.lock().unwrap_or_else(PoisonError::into_inner);
        // A delayed commit lands now, in the instance that it carries.
        self.join(&mut binding);
        Ok(binding.instance)
    }

    async fn read(&mut self, key: &Key) -> Result<Option<Record>, Error> {
        let binding = self.serving()?;
        Ok(binding.store.records.get(key).cloned())
    }

    async fn read_pair(&mut self, keys: [&Key; 2]) -> Result<[Option<Record>; 2], Error> {
        let binding = self.serving()?;
        Ok(keys.map(|key| binding.store.records.get(key).cloned()))
    }

    async fn commit(&mut self, proposal: &Proposal, instance: Instance) -> Result<Commit, Error> {
        let retention = self.serving()?.retention;
        self.request(Request::new(proposal, retention), instance)
    }

    async fn insert_replay(&mut self, insert: &Insert) -> Result<Inserted, Error> {
        let mut binding = self.serving()?;
        Ok(binding.insert(insert))
    }

    async fn expire(
        &mut self,
        kind: Kind,
        before: Duration,
        limit: NonZeroUsize,
        instance: Instance,
    ) -> Result<Expiry, Error> {
        let mut binding = self.serving()?;
        if instance != binding.instance {
            return Ok(Expiry::Superseded);
        }
        let prefix = kind.key(&[]).expect("a key of one byte is valid");
        let ended: Vec<Key> = binding
            .store
            .range(&prefix, None)
            .filter(|(_, record)| record.end.is_some_and(|end| end < before))
            .map(|(key, _)| key.clone())
            .take(limit.get())
            .collect();
        for key in &ended {
            binding.store.records.remove(key);
        }
        Ok(Expiry::Removed(ended.len()))
    }

    async fn range(
        &mut self,
        prefix: &Key,
        after: Option<&Key>,
        limit: NonZeroUsize,
    ) -> Result<Vec<(Key, Record)>, Error> {
        let binding = self.serving()?;
        Ok(binding
            .store
            .range(prefix, after)
            .take(limit.get())
            .map(|(key, record)| (key.clone(), record.clone()))
            .collect())
    }
}

impl Journal for Memory {
    type Error = Error;

    async fn append(&mut self, append: &Append, instance: Instance) -> Result<JournalWrite, Error> {
        let mut binding = self.serving()?;
        if binding.instance != instance || binding.head != append.after() {
            return Ok(JournalWrite::Conflict);
        }
        binding.unsynced.push(append.entry().clone());
        binding.head = append.head();
        // The journal keeps the accepted append. The handle crashes after it, and the next sync covers the append.
        let crash = binding.crash(Primitive::Append);
        drop(binding);
        if let Some(crash) = crash {
            self.crashed = Some(crash.error());
        }
        Ok(JournalWrite::Accepted)
    }

    async fn sync(&mut self, instance: Instance) -> Result<JournalWrite, Error> {
        let mut binding = self.serving()?;
        if binding.instance != instance {
            return Ok(JournalWrite::Conflict);
        }
        if let Some(crash) = binding.crash(Primitive::Sync) {
            // The journal failed, so each handle stops, and the appends after the last sync are lost.
            binding.crash_all();
            drop(binding);
            self.crashed = Some(crash.error());
            return Err(crash.error());
        }
        let entries = mem::take(&mut binding.unsynced);
        binding.synced = binding.head;
        binding
            .journal
            .extend(entries.into_iter().map(|entry| (entry.sequence, entry.data)));
        Ok(JournalWrite::Accepted)
    }

    async fn read(&mut self, after: Sequence, limit: NonZeroUsize) -> Result<Vec<Entry>, Error> {
        let binding = self.serving()?;
        Ok(binding
            .journal
            .range((Bound::Excluded(after), Bound::Unbounded))
            .take(limit.get())
            .map(|(&sequence, data)| Entry {
                sequence,
                data: data.clone(),
            })
            .collect())
    }
}

#[cfg(test)]
mod tests;
