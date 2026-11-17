//! The conformance suite on the memory binding, and on its deliberately broken forms.
//!
//! Each broken binding is the memory binding with one defect in one primitive. It is in the test tree of the memory
//! binding, so that a defect changes the private state of the binding, and no production code holds it.

use core::num::NonZeroUsize;
use core::ops::RangeBounds;
use core::time::Duration;
use std::collections::BTreeMap;

use rsauthnz::store::{Commit, Declaration, Entry, Instance, Journal, Kind, Record, Sequence, Store};
use rsauthnz::transition::{Change, Dependency, Key, Proposal};

use super::super::{Error, Fault, Memory, Primitive, Request, Schedule, Snapshot};
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
}

impl Defect {
    const ALL: [Self; 6] = [
        Self::NoAtomicCheck,
        Self::LostOutcomes,
        Self::WriteSkew,
        Self::NoJournal,
        Self::RetriedSync,
        Self::NoInstanceCheck,
    ];

    /// The case that names the defect.
    const fn case(self) -> Case {
        match self {
            Self::NoAtomicCheck => Case::ConcurrentConsumption,
            Self::LostOutcomes => Case::LostResponse,
            Self::WriteSkew => Case::AbsenceRace,
            Self::NoJournal => Case::RestoreJournal,
            Self::RetriedSync => Case::FailedSync,
            Self::NoInstanceCheck => Case::Fencing,
        }
    }
}

/// The memory binding with `defect`.
#[derive(Clone, Debug)]
struct Broken {
    memory: Memory,
    defect: Defect,
}

impl Broken {
    /// The commit of `request` with a defect of the commit. It takes the faults as the commit of the memory binding
    /// does.
    fn apply(&self, request: Request, instance: Instance) -> Result<Commit, Error> {
        let mut binding = self.memory.lock();
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
            Some(Fault::CrashAfterAppend | Fault::FailedSync) | None => Ok(binding.apply(request, instance)),
        }
    }
}

impl Store for Broken {
    type Error = Error;

    fn declaration(&self) -> Declaration {
        self.memory.declaration()
    }

    async fn start(&mut self) -> Result<Instance, Error> {
        self.memory.start().await
    }

    async fn read(&mut self, key: &Key) -> Result<Option<Record>, Error> {
        if self.defect == Defect::LostOutcomes && Kind::of(key) == Some(Kind::Outcome) {
            return Ok(None);
        }
        Store::read(&mut self.memory, key).await
    }

    async fn commit(&mut self, proposal: &Proposal, instance: Instance) -> Result<Commit, Error> {
        let mut request = Request::new(proposal);
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
                let current = self.memory.lock().instance;
                return self.apply(request, current);
            }
            Defect::LostOutcomes | Defect::NoJournal | Defect::RetriedSync => {
                return self.memory.commit(proposal, instance).await;
            }
        }
        self.apply(request, instance)
    }

    async fn expire(&mut self, kind: Kind, before: Duration, limit: NonZeroUsize) -> Result<usize, Error> {
        self.memory.expire(kind, before, limit).await
    }

    async fn intents(&mut self, after: Option<&Key>, limit: NonZeroUsize) -> Result<Vec<(Key, Record)>, Error> {
        self.memory.intents(after, limit).await
    }
}

impl Journal for Broken {
    type Error = Error;

    async fn append(&mut self, entry: &[u8]) -> Result<Sequence, Error> {
        self.memory.append(entry).await
    }

    async fn sync(&mut self) -> Result<(), Error> {
        let synced = self.memory.sync().await;
        if self.defect == Defect::RetriedSync && synced == Err(Error::Crash(Fault::FailedSync)) {
            // The retry: the binding serves again, and the appends that the failure dropped stay lost.
            self.memory.lock().stopped = None;
            return self.memory.sync().await;
        }
        synced
    }

    async fn read(&mut self, after: Sequence, limit: NonZeroUsize) -> Result<Vec<Entry>, Error> {
        Journal::read(&mut self.memory, after, limit).await
    }
}

impl Subject for Broken {
    /// The snapshot of the store, and the durable journal with its last sequence at the snapshot.
    type Snapshot = (Snapshot, BTreeMap<Sequence, Box<[u8]>>, Sequence);

    fn inject(&self, fault: Fault) {
        self.memory.inject(fault);
    }

    fn restart(&self) {
        self.memory.restart();
    }

    fn snapshot(&self) -> Self::Snapshot {
        let binding = self.memory.lock();
        (Snapshot(binding.store.clone()), binding.journal.clone(), binding.synced)
    }

    fn restore(&self, (snapshot, journal, synced): &Self::Snapshot) {
        self.memory.restore(snapshot);
        if self.defect == Defect::NoJournal {
            let mut binding = self.memory.lock();
            binding.journal = journal.clone();
            binding.synced = *synced;
        }
    }

    fn lose(&self, sequences: impl RangeBounds<Sequence>) {
        self.memory.lose(sequences);
    }
}

/// The memory binding passes each case of the suite, and its declaration selects each case.
#[test]
fn the_memory_binding_passes_every_case() {
    let report = ready(suite::run(|| Memory::new(Schedule::None)));
    assert_eq!(report, Report::default(), "{report}");
}

/// Each broken binding fails the case that names its defect. The write-skew binding passes each other case, so the
/// suite needs its absence-race case.
#[test]
fn each_broken_binding_fails_the_case_that_names_its_defect() {
    for defect in Defect::ALL {
        let report = ready(suite::run(|| Broken {
            memory: Memory::new(Schedule::None),
            defect,
        }));
        let failed: Vec<Case> = report.failures.iter().map(|failure| failure.case).collect();
        assert!(failed.contains(&defect.case()), "{defect:?}:\n{report}");
        if defect == Defect::WriteSkew {
            assert_eq!(failed, [Case::AbsenceRace], "{report}");
        }
    }
}
