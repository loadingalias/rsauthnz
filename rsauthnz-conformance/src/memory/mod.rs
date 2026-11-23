//! The memory binding: the reference of the storage contract for tests and examples. Never use it as a production
//! store.
//!
//! [`Memory`] implements [`Store`] and [`Journal`] in the memory of the process. One mutex holds all its state, so
//! each primitive is one atomic step and each commit is serializable. The clones of a [`Memory`] share one binding:
//! give each concurrent caller its own clone.
//!
//! The binding simulates a durable store, and a restore journal in a separate failure domain. [`Subject::inject`] gives
//! a [`Fault`] of the suite to the next call of its primitive. A [`Schedule`] injects crashes at the primitives: each
//! fault, and two crashes of its own ([`Error::CrashAfterCommit`] and [`Error::DelayedCommit`]). The same faults and
//! the same calls give the same results. A crash keeps each commit of the simulated store that landed, and each entry
//! of the journal whose sync returned. It loses the appends after the last sync. After a crash, each primitive except
//! [`Store::start`] gives the [`Error`] of the crash.
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

use rsauthnz::id::AuthorityVersion;
use rsauthnz::store::{
    self, Commit, CrashInjection, CrashLoss, Declaration, Entry, Instance, Isolation, Journal, Kind, Record, Restore,
    Sequence, Store,
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

/// The outcome retention of the declaration. Each audit and outcome record ends at the estimate of the audit time of
/// its proposal plus the retention, which saturates at `Duration::MAX`.
const RETENTION: Duration = Duration::MAX;

impl State {
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
}

impl Request {
    fn new(proposal: &Proposal) -> Self {
        let mut records = store::intent_records(proposal)
            .expect("an intent record has a key of at most 73 bytes and an encodable CBOR form");
        let outcome = store::outcome_record(proposal);
        let key = outcome.0.clone();
        let end = Some(proposal.audit().time.estimate().saturating_add(RETENTION));
        records.extend([store::audit_record(proposal), outcome].map(|(key, record)| (key, Record { end, ..record })));
        Self {
            id: proposal.operation().id.clone(),
            outcome: key,
            dependencies: proposal.dependencies().to_vec(),
            changes: proposal.changes().to_vec(),
            records,
        }
    }
}

/// The state of a binding, which its clones share.
#[derive(Debug)]
struct Binding {
    store: State,
    /// The durable entries of the journal. A crash, a restart, and a restore keep them.
    journal: BTreeMap<Sequence, Box<[u8]>>,
    /// The sequence of the last entry that a sync made durable. A loss of entries does not lower it, so no later
    /// append gets the sequence of a lost entry.
    synced: Sequence,
    /// The appends after the last sync. A crash loses them, so the next append gets the first sequence of them.
    unsynced: Vec<Entry>,
    /// The instance number of the last start or restore. A start and a restore each write the next number, so it
    /// increases for the life of the binding, and a commit from each earlier start refuses.
    instance: Instance,
    /// The error of each primitive until the next start, or `None` while the binding serves.
    stopped: Option<Error>,
    /// A commit of [`Error::DelayedCommit`] and its instance number. It lands after the next start.
    delayed: Option<(Request, Instance)>,
    schedule: Schedule,
    /// The fault of [`Subject::inject`] for the next call of its primitive.
    injected: Option<Fault>,
    /// The number of calls of each primitive that can take a fault, in the order of [`Primitive`].
    calls: [u64; 3],
    /// The reading of [`Subject::clock`].
    clock: Reading,
}

impl Binding {
    /// Gives the error of a stopped binding.
    fn serving(&self) -> Result<(), Error> {
        self.stopped.map_or(Ok(()), Err)
    }

    /// Stops the binding with `error` until the next start. The appends after the last sync are lost.
    fn stop(&mut self, error: Error) -> Error {
        self.stopped = Some(error);
        self.unsynced.clear();
        error
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

    /// The commit of `request` with the instance number `instance`, after the crash that it takes.
    fn commit(&mut self, request: Request, instance: Instance) -> Result<Commit, Error> {
        self.serving()?;
        match self.crash(Primitive::Commit) {
            Some(crash @ Crash::Fault(Fault::CrashBeforeCommit)) => Err(self.stop(crash.error())),
            Some(crash @ Crash::Fault(Fault::LostResponse)) => {
                self.apply(request, instance);
                Err(self.stop(crash.error()))
            }
            Some(crash @ Crash::AfterCommit) => {
                let commit = self.apply(request, instance);
                self.stop(crash.error());
                Ok(commit)
            }
            Some(crash @ Crash::Delayed) => {
                self.delayed = Some((request, instance));
                Err(self.stop(crash.error()))
            }
            // A commit takes only the crashes of a commit.
            Some(Crash::Fault(Fault::CrashAfterAppend | Fault::FailedSync)) | None => Ok(self.apply(request, instance)),
        }
    }

    /// The conditional atomic commit of `request` with the instance number `instance`.
    fn apply(&mut self, request: Request, instance: Instance) -> Commit {
        let state = &mut self.store;
        if instance != self.instance {
            return Commit::Conflict;
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
}

/// A handle of one memory binding. Its clones share the binding.
#[derive(Clone, Debug)]
pub struct Memory(Arc<Mutex<Binding>>);

impl Memory {
    /// Makes a binding with an empty store and an empty journal, which injects the faults of `schedule`. It serves
    /// after its first start.
    #[must_use]
    pub fn new(schedule: Schedule) -> Self {
        Self(Arc::new(Mutex::new(Binding {
            store: State::default(),
            journal: BTreeMap::new(),
            synced: Sequence(0),
            unsynced: Vec::new(),
            instance: Instance(0),
            stopped: Some(Error::Stopped),
            delayed: None,
            schedule,
            injected: None,
            calls: [0; 3],
            clock: Reading::new(Duration::ZERO, Some(Duration::ZERO), ReadingSource::Caller),
        })))
    }

    /// Sets the reading of the clock that the binding gives for [`Effect::Clock`](rsauthnz::store::driver::Effect):
    /// the controlled clock of a test. The first reading is the start of the Unix epoch, before each deadline of a
    /// test at a fixed time.
    pub fn set_clock(&self, now: Reading) {
        self.lock().clock = now;
    }

    /// The shared state. No step of the binding panics while it holds the lock, so a poisoned lock holds a
    /// consistent state.
    fn lock(&self) -> MutexGuard<'_, Binding> {
        self.0.lock().unwrap_or_else(PoisonError::into_inner)
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
        binding.stop(Error::Stopped);
        binding.store = State::default();
    }

    fn snapshot(&self) -> Snapshot {
        Snapshot(self.lock().store.clone())
    }

    /// Restores the state of the store from `snapshot`, then writes the next instance number. The store takes commits
    /// at once, and refuses each commit of an earlier start. The journal keeps its entries, and the appends after the
    /// last sync are lost.
    fn restore(&self, snapshot: &Snapshot) {
        let mut binding = self.lock();
        binding.unsynced.clear();
        binding.store = snapshot.0.clone();
        binding.instance = Instance(binding.instance.0.strict_add(1));
    }

    fn lose(&self, sequences: impl RangeBounds<Sequence>) {
        self.lock().journal.retain(|sequence, _| !sequences.contains(sequence));
    }

    /// The reading of [`Memory::set_clock`].
    fn clock(&self) -> Reading {
        self.lock().clock
    }
}

impl Store for Memory {
    type Error = Error;

    fn declaration(&self) -> Declaration {
        Declaration {
            isolation: Isolation::Serializable,
            crash_loss: CrashLoss::Everything,
            outcome_retention: RETENTION,
            crash_injection: CrashInjection::Supported,
            restore: Restore::Journal {
                location: "the memory of the process".into(),
                failure_domain: "a simulated domain apart from the store and from its snapshots".into(),
            },
            key_bytes_max: Key::BYTES_MAX,
            record_bytes_max: usize::MAX,
        }
    }

    async fn start(&mut self) -> Result<Instance, Error> {
        let mut binding = self.lock();
        binding.instance = Instance(binding.instance.0.strict_add(1));
        binding.stopped = None;
        if let Some((request, instance)) = binding.delayed.take() {
            // The delayed commit lands now, with the instance number of an earlier start, so it refuses.
            binding.apply(request, instance);
        }
        Ok(binding.instance)
    }

    async fn read(&mut self, key: &Key) -> Result<Option<Record>, Error> {
        let binding = self.lock();
        binding.serving()?;
        Ok(binding.store.records.get(key).cloned())
    }

    async fn read_pair(&mut self, keys: [&Key; 2]) -> Result<[Option<Record>; 2], Error> {
        let binding = self.lock();
        binding.serving()?;
        Ok(keys.map(|key| binding.store.records.get(key).cloned()))
    }

    async fn commit(&mut self, proposal: &Proposal, instance: Instance) -> Result<Commit, Error> {
        let request = Request::new(proposal);
        self.lock().commit(request, instance)
    }

    async fn expire(&mut self, kind: Kind, before: Duration, limit: NonZeroUsize) -> Result<usize, Error> {
        let mut binding = self.lock();
        binding.serving()?;
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
        Ok(ended.len())
    }

    async fn range(
        &mut self,
        prefix: &Key,
        after: Option<&Key>,
        limit: NonZeroUsize,
    ) -> Result<Vec<(Key, Record)>, Error> {
        let binding = self.lock();
        binding.serving()?;
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

    async fn append(&mut self, entry: &[u8]) -> Result<Sequence, Error> {
        let mut binding = self.lock();
        binding.serving()?;
        let last = binding.unsynced.last().map_or(binding.synced, |entry| entry.sequence);
        let sequence = Sequence(last.0.strict_add(1));
        binding.unsynced.push(Entry {
            sequence,
            data: entry.into(),
        });
        if let Some(crash) = binding.crash(Primitive::Append) {
            binding.stop(crash.error());
        }
        Ok(sequence)
    }

    async fn sync(&mut self) -> Result<(), Error> {
        let mut binding = self.lock();
        binding.serving()?;
        if let Some(crash) = binding.crash(Primitive::Sync) {
            return Err(binding.stop(crash.error()));
        }
        let entries = mem::take(&mut binding.unsynced);
        if let Some(last) = entries.last() {
            binding.synced = last.sequence;
        }
        binding
            .journal
            .extend(entries.into_iter().map(|entry| (entry.sequence, entry.data)));
        Ok(())
    }

    async fn read(&mut self, after: Sequence, limit: NonZeroUsize) -> Result<Vec<Entry>, Error> {
        let binding = self.lock();
        binding.serving()?;
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
