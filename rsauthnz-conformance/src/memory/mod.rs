//! The memory binding: the reference of the storage contract for tests and examples. Never use it as a production
//! store.
//!
//! [`Memory`] implements [`Store`] and [`Journal`] in the memory of the process. One mutex holds all its state, so
//! each primitive is one atomic step and each commit is serializable. The clones of a [`Memory`] share one binding:
//! give each concurrent caller its own clone.
//!
//! The binding simulates a durable store, and a restore journal in a separate failure domain. A [`Schedule`] injects
//! each [`Fault`] at a primitive. The same schedule and the same calls give the same results. A fault is a crash of
//! the simulated store: the store keeps each commit that landed, and the journal keeps each entry whose sync returned.
//! The crash loses the appends after the last sync. After a crash, each primitive except [`Store::start`] gives the
//! [`Error`] of the crash.
//!
//! [`Memory::restart`] is the loss of the process: the store loses all its state, and the journal keeps its synced
//! entries. The declaration states it with [`CrashLoss::Everything`]. [`Memory::snapshot`] and [`Memory::restore`]
//! copy the state of the store with a low-water mark, and [`Memory::lose`] removes entries of the journal.
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
//! use rsauthnz_conformance::memory::{Error, Fault, Memory, Schedule};
//!
//! /// The output of a future of the memory binding.
//! fn ready<F: Future>(future: F) -> F::Output {
//!     match pin!(future).poll(&mut Context::from_waker(Waker::noop())) {
//!         Poll::Ready(output) => output,
//!         Poll::Pending => unreachable!("the memory binding does no I/O"),
//!     }
//! }
//!
//! // The first commit loses its response.
//! let mut memory = Memory::new(Schedule::At(0, Fault::LostResponse));
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
use rsauthnz::limits::Limits;
use rsauthnz::store::journal::Mark;
use rsauthnz::store::{
    self, Commit, CrashInjection, CrashLoss, Declaration, Entry, Instance, Isolation, Journal, Kind, Record, Restore,
    Sequence, Store,
};
use rsauthnz::transition::{Change, Dependency, Key, OperationId, Proposal};
use rscrypto::RapidHash64;

/// A fault that a [`Schedule`] injects at one primitive. Each fault crashes the binding.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub enum Fault {
    /// The binding crashes before a commit, so the commit writes nothing.
    CrashBeforeCommit,
    /// A commit writes everything, but its response is lost: the commit gives the error.
    LostResponse,
    /// The binding crashes after a commit gives its result.
    CrashAfterCommit,
    /// The binding crashes while a commit is in flight. The commit arrives after the next start, with the instance
    /// number of the earlier start, so it refuses.
    DelayedCommit,
    /// The binding crashes after an append gives its sequence, before a sync. The crash loses the append.
    CrashAfterAppend,
    /// A sync fails, and no append since the last sync becomes durable.
    FailedSync,
}

impl Fault {
    /// Each fault.
    const ALL: [Self; 6] = [
        Self::CrashBeforeCommit,
        Self::LostResponse,
        Self::CrashAfterCommit,
        Self::DelayedCommit,
        Self::CrashAfterAppend,
        Self::FailedSync,
    ];

    /// The primitive that takes the fault.
    const fn primitive(self) -> Primitive {
        match self {
            Self::CrashBeforeCommit | Self::LostResponse | Self::CrashAfterCommit | Self::DelayedCommit => {
                Primitive::Commit
            }
            Self::CrashAfterAppend => Primitive::Append,
            Self::FailedSync => Primitive::Sync,
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
    /// The fault at the call of its primitive with this number. The count starts at 0 when the binding is made, and
    /// a call to a stopped binding does not count. A commit fault counts the commits, [`Fault::CrashAfterAppend`]
    /// counts the appends, and [`Fault::FailedSync`] counts the syncs.
    At(u64, Fault),
    /// Faults from this seed. Each commit, append, and sync takes a fault with a chance of one in 8, and each fault
    /// of its primitive has the same chance. The draw of a call is the RapidHash of its primitive and its number,
    /// with the seed, so a seed gives the same faults at each run.
    Seeded(u64),
}

/// A call gets a fault from a seeded schedule when its draw is a multiple of this number.
const SEEDED_ONE_IN: u8 = 8;

/// The cause of a failed primitive. Each error is a crash with an unknown outcome: call [`Store::start`].
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Error {
    /// The binding is new, or it had a restart or a restore, and it did not start after it.
    Stopped,
    /// The fault crashed the binding at this primitive or at an earlier one.
    Crash(Fault),
}

impl fmt::Display for Error {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Stopped => f.write_str("the memory binding did not start"),
            Self::Crash(fault) => write!(f, "the memory binding crashed with the fault {fault:?}"),
        }
    }
}

impl core::error::Error for Error {}

/// A snapshot of the store with its low-water mark, which keeps the link of its entry. A restore gives back its state,
/// and the journal keeps its own entries.
#[derive(Clone, Debug)]
pub struct Snapshot {
    state: State,
    mark: Mark,
}

/// The state of the simulated store. A crash keeps it, and a restart loses it.
#[derive(Clone, Debug, Default)]
struct State {
    /// The records, the policy, audit, outcome, and intent records included. The audit and outcome records have no
    /// end ([`Declaration::outcome_retention`]).
    records: BTreeMap<Key, Record>,
}

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

    /// The records of `kind` with a key after `after`, in key order. The first byte of a key names its kind, so the
    /// keys of one kind are one range, which starts at the key of the kind byte alone.
    fn of_kind(&self, kind: Kind, after: Option<&Key>) -> impl Iterator<Item = (&Key, &Record)> {
        let first = kind.key(&[]).expect("a key of one byte is valid");
        let lower = match after {
            Some(after) if *after >= first => Bound::Excluded(after.clone()),
            _ => Bound::Included(first),
        };
        self.records
            .range((lower, Bound::Unbounded))
            .take_while(move |(key, _)| Kind::of(key) == Some(kind))
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
        records.extend([store::audit_record(proposal), outcome]);
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
    /// The instance number of the last start. It increases for the life of the binding, also across a restart and a
    /// restore, so a commit from each earlier start refuses.
    instance: Instance,
    /// The error of each primitive until the next start, or `None` while the binding serves.
    stopped: Option<Error>,
    /// A commit of [`Fault::DelayedCommit`] and its instance number. It lands after the next start.
    delayed: Option<(Request, Instance)>,
    schedule: Schedule,
    /// The number of calls of each primitive that can take a fault, in the order of [`Primitive`].
    calls: [u64; 3],
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

    /// Counts a call of `primitive`, and gives the fault that the schedule injects at it.
    fn fault(&mut self, primitive: Primitive) -> Option<Fault> {
        let count = &mut self.calls[primitive as usize];
        let call = *count;
        *count = call.strict_add(1);
        match self.schedule {
            Schedule::None => None,
            Schedule::At(at, fault) => (fault.primitive() == primitive && at == call).then_some(fault),
            Schedule::Seeded(seed) => {
                let mut data = [primitive as u8; 9];
                data[1..].copy_from_slice(&call.to_le_bytes());
                let [rate, pick, ..] = RapidHash64::hash_with_seed(seed, &data).to_le_bytes();
                if rate % SEEDED_ONE_IN != 0 {
                    return None;
                }
                let mut faults = Fault::ALL.into_iter().filter(|fault| fault.primitive() == primitive);
                let count = faults.clone().count();
                faults.nth(usize::from(pick) % count)
            }
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
            calls: [0; 3],
        })))
    }

    /// The shared state. No step of the binding panics while it holds the lock, so a poisoned lock holds a
    /// consistent state.
    fn lock(&self) -> MutexGuard<'_, Binding> {
        self.0.lock().unwrap_or_else(PoisonError::into_inner)
    }

    /// A snapshot of the current state of the store, with the low-water mark `mark`: the caller states the mark of the
    /// journal entry at or below which the state reflects each entry, as `journal::low_water` gives it.
    #[must_use]
    pub fn snapshot(&self, mark: Mark) -> Snapshot {
        Snapshot {
            state: self.lock().store.clone(),
            mark,
        }
    }

    /// Restores the state of the store from `snapshot` and gives its low-water mark. The journal keeps its entries.
    /// The binding stops: the appends after the last sync are lost, and it serves again after a start.
    pub fn restore(&self, snapshot: &Snapshot) -> Mark {
        let mut binding = self.lock();
        binding.stop(Error::Stopped);
        binding.store = snapshot.state.clone();
        snapshot.mark
    }

    /// The loss of the process: the store loses all its state, and the journal keeps its durable entries. The binding
    /// stops, and it serves again after a start.
    pub fn restart(&self) {
        let mut binding = self.lock();
        binding.stop(Error::Stopped);
        binding.store = State::default();
    }

    /// Removes the durable entries of the journal with a sequence in `sequences`. `lose(..)` is the loss of the
    /// journal, and a smaller range is a gap. A later append does not get the sequence of a removed entry.
    pub fn lose(&self, sequences: impl RangeBounds<Sequence>) {
        self.lock().journal.retain(|sequence, _| !sequences.contains(sequence));
    }
}

impl Store for Memory {
    type Error = Error;

    fn declaration(&self) -> Declaration {
        Declaration {
            isolation: Isolation::Serializable,
            crash_loss: CrashLoss::Everything,
            outcome_retention: Duration::MAX,
            crash_injection: CrashInjection::Supported,
            restore: Restore::Journal {
                location: "the memory of the process".into(),
                failure_domain: "a simulated domain apart from the store and from its snapshots".into(),
            },
            key_bytes_max: Key::BYTES_MAX,
            record_bytes_max: Limits::default().bytes,
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

    async fn commit(&mut self, proposal: &Proposal, instance: Instance) -> Result<Commit, Error> {
        let request = Request::new(proposal);
        let mut binding = self.lock();
        binding.serving()?;
        match binding.fault(Primitive::Commit) {
            Some(fault @ Fault::CrashBeforeCommit) => Err(binding.stop(Error::Crash(fault))),
            Some(fault @ Fault::LostResponse) => {
                binding.apply(request, instance);
                Err(binding.stop(Error::Crash(fault)))
            }
            Some(fault @ Fault::CrashAfterCommit) => {
                let commit = binding.apply(request, instance);
                binding.stop(Error::Crash(fault));
                Ok(commit)
            }
            Some(fault @ Fault::DelayedCommit) => {
                binding.delayed = Some((request, instance));
                Err(binding.stop(Error::Crash(fault)))
            }
            // A commit takes only the faults of a commit.
            Some(Fault::CrashAfterAppend | Fault::FailedSync) | None => Ok(binding.apply(request, instance)),
        }
    }

    async fn expire(&mut self, kind: Kind, before: Duration, limit: NonZeroUsize) -> Result<usize, Error> {
        let mut binding = self.lock();
        binding.serving()?;
        let ended: Vec<Key> = binding
            .store
            .of_kind(kind, None)
            .filter(|(_, record)| record.end.is_some_and(|end| end < before))
            .map(|(key, _)| key.clone())
            .take(limit.get())
            .collect();
        for key in &ended {
            binding.store.records.remove(key);
        }
        Ok(ended.len())
    }

    async fn intents(&mut self, after: Option<&Key>, limit: NonZeroUsize) -> Result<Vec<(Key, Record)>, Error> {
        let binding = self.lock();
        binding.serving()?;
        Ok(binding
            .store
            .of_kind(Kind::Intent, after)
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
        if let Some(fault) = binding.fault(Primitive::Append) {
            binding.stop(Error::Crash(fault));
        }
        Ok(sequence)
    }

    async fn sync(&mut self) -> Result<(), Error> {
        let mut binding = self.lock();
        binding.serving()?;
        if let Some(fault) = binding.fault(Primitive::Sync) {
            return Err(binding.stop(Error::Crash(fault)));
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
