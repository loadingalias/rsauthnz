//! The conformance suite on the memory binding, on a form of it that measures each record of a commit, and on its
//! deliberately broken forms.
//!
//! Each broken binding is the memory binding with one defect in one primitive. It is in the test tree of the memory
//! binding, so that a defect changes the private state of the binding, and no production code holds it.

use core::mem;
use core::num::NonZeroUsize;
use core::ops::{Bound, RangeBounds};
use core::sync::atomic::{AtomicUsize, Ordering};
use core::time::Duration;
use std::collections::BTreeMap;
use std::sync::{Arc, Mutex};

use rsauthnz::limits::Limits;
use rsauthnz::store::driver;
use rsauthnz::store::journal::{Append, Mark};
use rsauthnz::store::{
    Capacity, Commit, Declaration, Entry, Expiry, Insert, Inserted, Instance, Journal, JournalWrite, Kind, Record,
    Sequence, Store,
};
use rsauthnz::time::Reading;
use rsauthnz::transition::{Change, Dependency, Key, Proposal};

use super::super::{Error, Fault, Memory, RETENTION, Request, Schedule, Snapshot};
use super::ready;
use crate::suite::{self, Case, Report, Subject};

/// A defect of a broken binding.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum Defect {
    /// The commit does not check its dependencies: only the reads of the caller checked them.
    NoAtomicCheck,
    /// A read of an outcome record gives none.
    LostOutcomes,
    /// The commit checks each version and policy, but an absence only of a key that it writes, as snapshot isolation
    /// checks only its writes.
    WriteSkew,
    /// The journal is in the failure domain of the snapshots, so a restore also restores the journal of the snapshot.
    NoJournal,
    /// A sync that fails retries, and the retry reports success.
    RetriedSync,
    /// The commit does not compare the store instance number.
    NoInstanceCheck,
    /// The commit compares a copy of the instance number in the store, and a restore gives back the copy of the
    /// snapshot. The counter keeps its number, so the next start writes a new one.
    RestoredInstance,
    /// The audit and outcome records end at the audit time, with no retention.
    NoRetention,
    /// A range read has no end at its prefix: it also gives the records of the keys after the prefix.
    OpenRange,
    /// The commit reads no clock, so it writes a proposal after its deadline.
    NoDeadline,
    /// The replay insert reads no clock, so a late insert writes the record of a signature again after expiry removed
    /// it.
    NoInsertClock,
    /// The binding counts the capacity but no share, so one agent key fills the store.
    NoShare,
}

impl Defect {
    const ALL: [Self; 12] = [
        Self::NoAtomicCheck,
        Self::LostOutcomes,
        Self::WriteSkew,
        Self::NoJournal,
        Self::RetriedSync,
        Self::NoInstanceCheck,
        Self::RestoredInstance,
        Self::NoRetention,
        Self::OpenRange,
        Self::NoDeadline,
        Self::NoInsertClock,
        Self::NoShare,
    ];

    /// The cases that name the defect. A commit with no atomic check is a check-then-write path, so two concurrent
    /// uses of one bootstrap value both commit.
    const fn cases(self) -> &'static [Case] {
        match self {
            Self::NoAtomicCheck => &[Case::ConcurrentConsumption, Case::Bootstrap],
            Self::LostOutcomes => &[Case::LostResponse],
            Self::WriteSkew => &[Case::AbsenceRace],
            Self::NoJournal => &[Case::RestoreJournal],
            Self::RetriedSync => &[Case::FailedSync],
            Self::NoInstanceCheck | Self::RestoredInstance => &[Case::Fencing],
            Self::NoRetention => &[Case::Retention],
            Self::OpenRange => &[Case::Range],
            Self::NoDeadline => &[Case::Deadline],
            Self::NoInsertClock => &[Case::ReplayInsert],
            Self::NoShare => &[Case::ReplayCapacity],
        }
    }
}

/// The memory binding with `defect`.
#[derive(Clone, Debug)]
struct Broken {
    memory: Memory,
    defect: Defect,
    /// The counter of [`Defect::RestoredInstance`] between a restore and the next start, while the instance number of
    /// the memory binding is the restored copy.
    counter: Arc<Mutex<Option<Instance>>>,
}

impl Broken {
    fn new(defect: Defect) -> Self {
        let memory = Memory::new(Schedule::None);
        let memory = match defect {
            // One share can hold each record of the capacity, and the declaration states the share of a new binding.
            Defect::NoShare => {
                let records_max = memory.declaration().signatures.records_max;
                memory.with_capacity(Capacity {
                    records_max,
                    share_max: records_max,
                })
            }
            _ => memory,
        };
        Self {
            memory,
            defect,
            counter: Arc::default(),
        }
    }
}

impl Store for Broken {
    type Error = Error;

    fn declaration(&self) -> Declaration {
        let mut declaration = self.memory.declaration();
        if self.defect == Defect::NoShare {
            declaration.signatures = Memory::new(Schedule::None).declaration().signatures;
        }
        declaration
    }

    async fn start(&mut self) -> Result<Instance, Error> {
        let counter = self.counter.lock().unwrap().take();
        if let Some(counter) = counter {
            self.memory.lock().instance = counter;
        }
        self.memory.start().await
    }

    async fn read(&mut self, key: &Key) -> Result<Option<Record>, Error> {
        if self.defect == Defect::LostOutcomes && Kind::of(key) == Some(Kind::Outcome) {
            return Ok(None);
        }
        Store::read(&mut self.memory, key).await
    }

    async fn read_pair(&mut self, keys: [&Key; 2]) -> Result<[Option<Record>; 2], Error> {
        let mut pair = self.memory.read_pair(keys).await?;
        if self.defect == Defect::LostOutcomes {
            for (key, record) in keys.into_iter().zip(&mut pair) {
                if Kind::of(key) == Some(Kind::Outcome) {
                    *record = None;
                }
            }
        }
        Ok(pair)
    }

    async fn commit(&mut self, proposal: &Proposal, instance: Instance) -> Result<Commit, Error> {
        let mut request = Request::new(proposal, RETENTION);
        match self.defect {
            Defect::NoAtomicCheck => request.dependencies.clear(),
            Defect::WriteSkew => {
                let written: Vec<Key> = request
                    .changes
                    .iter()
                    .map(|change| match change {
                        Change::Write { key, .. } | Change::End(key) => key.clone(),
                    })
                    .collect();
                request
                    .dependencies
                    .retain(|dependency| !matches!(dependency, Dependency::Absent(key) if !written.contains(key)));
            }
            Defect::NoInstanceCheck => {
                let mut binding = self.memory.lock();
                let current = binding.instance;
                return binding.commit(request, current);
            }
            Defect::NoDeadline => request.deadline = None,
            Defect::NoRetention => {
                for (key, record) in &mut request.records {
                    if matches!(Kind::of(key), Some(Kind::Audit | Kind::Outcome)) {
                        record.end = Some(proposal.audit().time.estimate());
                    }
                }
            }
            Defect::LostOutcomes
            | Defect::NoJournal
            | Defect::RetriedSync
            | Defect::RestoredInstance
            | Defect::OpenRange
            | Defect::NoInsertClock
            | Defect::NoShare => {
                return self.memory.commit(proposal, instance).await;
            }
        }
        self.memory.lock().commit(request, instance)
    }

    async fn insert_replay(&mut self, insert: &Insert) -> Result<Inserted, Error> {
        if self.defect != Defect::NoInsertClock {
            return self.memory.insert_replay(insert).await;
        }
        // The same insert with no deadline: the key of a signature is its kind, the share, and the nonce.
        let (share, nonce) = insert.key().as_bytes()[1..].split_at(32);
        let end = insert.record().end.unwrap_or(Duration::MAX);
        let timeless = Insert::new(
            share.try_into().unwrap(),
            nonce.try_into().unwrap(),
            end,
            Duration::MAX,
            insert.origin(),
        );
        self.memory.insert_replay(&timeless).await
    }

    async fn expire(
        &mut self,
        kind: Kind,
        before: Duration,
        limit: NonZeroUsize,
        instance: Instance,
    ) -> Result<Expiry, Error> {
        self.memory.expire(kind, before, limit, instance).await
    }

    async fn range(
        &mut self,
        prefix: &Key,
        after: Option<&Key>,
        limit: NonZeroUsize,
    ) -> Result<Vec<(Key, Record)>, Error> {
        if self.defect != Defect::OpenRange {
            return self.memory.range(prefix, after, limit).await;
        }
        let lower = match after {
            Some(after) if after >= prefix => Bound::Excluded(after.clone()),
            _ => Bound::Included(prefix.clone()),
        };
        let binding = self.memory.lock();
        binding.serving()?;
        Ok(binding
            .store
            .records
            .range((lower, Bound::Unbounded))
            .take(limit.get())
            .map(|(key, record)| (key.clone(), record.clone()))
            .collect())
    }
}

impl Journal for Broken {
    type Error = Error;

    async fn append(&mut self, append: &Append, instance: Instance) -> Result<JournalWrite, Error> {
        self.memory.append(append, instance).await
    }

    async fn sync(&mut self, instance: Instance) -> Result<JournalWrite, Error> {
        let synced = self.memory.sync(instance).await;
        if self.defect == Defect::RetriedSync && synced == Err(Error::Crash(Fault::FailedSync)) {
            // The retry: the binding serves again, and the appends that the failure dropped stay lost.
            self.memory.lock().stopped = None;
            return self.memory.sync(instance).await;
        }
        synced
    }

    async fn read(&mut self, after: Sequence, limit: NonZeroUsize) -> Result<Vec<Entry>, Error> {
        Journal::read(&mut self.memory, after, limit).await
    }
}

impl Subject for Broken {
    /// The snapshot of the store, the durable journal with its last sequence, and the instance number at the snapshot.
    type Snapshot = (Snapshot, BTreeMap<Sequence, Box<[u8]>>, Mark, Instance);

    fn inject(&self, fault: Fault) {
        self.memory.inject(fault);
    }

    fn restart(&self) {
        self.memory.restart();
    }

    fn snapshot(&self) -> Self::Snapshot {
        let binding = self.memory.lock();
        (
            Snapshot(binding.store.clone()),
            binding.journal.clone(),
            binding.synced,
            binding.instance,
        )
    }

    fn restore(&self, (snapshot, journal, synced, instance): &Self::Snapshot) {
        self.memory.restore(snapshot);
        let mut binding = self.memory.lock();
        match self.defect {
            Defect::NoJournal => {
                binding.journal = journal.clone();
                binding.synced = *synced;
                binding.head = *synced;
            }
            Defect::RestoredInstance => {
                let counter = mem::replace(&mut binding.instance, *instance);
                *self.counter.lock().unwrap() = Some(counter);
            }
            _ => {}
        }
    }

    fn lose(&self, sequences: impl RangeBounds<Sequence>) {
        self.memory.lose(sequences);
    }

    fn set_clock(&self, now: Reading) {
        self.memory.set_clock(now);
    }
}

/// The memory binding, which keeps the length of the longest record that a commit gives it.
#[derive(Clone, Debug)]
struct Measured {
    memory: Memory,
    longest: Arc<AtomicUsize>,
}

impl Store for Measured {
    type Error = Error;

    fn declaration(&self) -> Declaration {
        self.memory.declaration()
    }

    async fn start(&mut self) -> Result<Instance, Error> {
        self.memory.start().await
    }

    async fn read(&mut self, key: &Key) -> Result<Option<Record>, Error> {
        Store::read(&mut self.memory, key).await
    }

    async fn read_pair(&mut self, keys: [&Key; 2]) -> Result<[Option<Record>; 2], Error> {
        self.memory.read_pair(keys).await
    }

    /// Measures each record that the commit stores: the record form of each write, and each intent, audit, and
    /// outcome record.
    async fn commit(&mut self, proposal: &Proposal, instance: Instance) -> Result<Commit, Error> {
        let request = Request::new(proposal, RETENTION);
        let writes = request.changes.iter().filter_map(|change| match change {
            Change::Write { data, .. } => Some(data.len()),
            Change::End(_) => None,
        });
        let records = request.records.iter().map(|(_, record)| record.data.len());
        let longest = writes.chain(records).max().unwrap_or(0);
        self.longest.fetch_max(longest, Ordering::Relaxed);
        self.memory.commit(proposal, instance).await
    }

    async fn insert_replay(&mut self, insert: &Insert) -> Result<Inserted, Error> {
        self.memory.insert_replay(insert).await
    }

    async fn expire(
        &mut self,
        kind: Kind,
        before: Duration,
        limit: NonZeroUsize,
        instance: Instance,
    ) -> Result<Expiry, Error> {
        self.memory.expire(kind, before, limit, instance).await
    }

    async fn range(
        &mut self,
        prefix: &Key,
        after: Option<&Key>,
        limit: NonZeroUsize,
    ) -> Result<Vec<(Key, Record)>, Error> {
        self.memory.range(prefix, after, limit).await
    }
}

impl Journal for Measured {
    type Error = Error;

    async fn append(&mut self, append: &Append, instance: Instance) -> Result<JournalWrite, Error> {
        self.memory.append(append, instance).await
    }

    async fn sync(&mut self, instance: Instance) -> Result<JournalWrite, Error> {
        self.memory.sync(instance).await
    }

    async fn read(&mut self, after: Sequence, limit: NonZeroUsize) -> Result<Vec<Entry>, Error> {
        Journal::read(&mut self.memory, after, limit).await
    }
}

impl Subject for Measured {
    type Snapshot = Snapshot;

    fn inject(&self, fault: Fault) {
        self.memory.inject(fault);
    }

    fn restart(&self) {
        self.memory.restart();
    }

    fn snapshot(&self) -> Snapshot {
        self.memory.snapshot()
    }

    fn restore(&self, snapshot: &Snapshot) {
        self.memory.restore(snapshot);
    }

    fn lose(&self, sequences: impl RangeBounds<Sequence>) {
        self.memory.lose(sequences);
    }

    fn set_clock(&self, now: Reading) {
        self.memory.set_clock(now);
    }
}

/// The driver refuses a binding whose record bound is below its own records ([`driver::record_bytes_min`]). The
/// longest record that a commit of the suite gives the memory binding, a record of the driver's own commits included,
/// is at most that bound. The commits of each case reach the binding, so the measure is not empty.
#[test]
fn no_commit_of_the_suite_gives_a_record_longer_than_the_least_record_bound() {
    let longest = Arc::new(AtomicUsize::new(0));
    let report = ready(suite::run(|| Measured {
        memory: Memory::new(Schedule::None),
        longest: Arc::clone(&longest),
    }));
    assert_eq!(report, Report::default(), "{report}");
    let longest = longest.load(Ordering::Relaxed);
    assert!(longest > 0, "no commit reached the binding");
    assert!(longest <= driver::record_bytes_min(Limits::default()), "{longest}");
}

/// The memory binding passes each case of the suite, and its declaration selects each case.
#[test]
fn the_memory_binding_passes_every_case() {
    let report = ready(suite::run(|| Memory::new(Schedule::None)));
    assert_eq!(report, Report::default(), "{report}");
}

/// Each broken binding fails each case that names its defect. The write-skew binding passes each other case, so the
/// suite needs its absence-race case.
#[test]
fn each_broken_binding_fails_the_case_that_names_its_defect() {
    for defect in Defect::ALL {
        let report = ready(suite::run(|| Broken::new(defect)));
        let failed: Vec<Case> = report.failures.iter().map(|failure| failure.case).collect();
        let named = defect.cases().iter().all(|case| failed.contains(case));
        assert!(named, "{defect:?}:\n{report}");
        if defect == Defect::WriteSkew {
            assert_eq!(failed, [Case::AbsenceRace], "{report}");
        }
    }
}
