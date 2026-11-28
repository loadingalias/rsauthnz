//! A start or a restore: a join of the open instance, or the activation of a new one.

use alloc::boxed::Box;
use alloc::collections::{BTreeSet, VecDeque};
use alloc::vec::Vec;
use core::mem;
use core::time::Duration;

use super::help::{Reserving, Settling};
use super::record::{self, RestoreMark};
use super::{
    AlphaSource, Committing, Core, Counter, Effect, Error, Fetching, Gathering, Output, Owed, Pending, Refreshing,
    Scanning, Settled, Status, Writing, release, written,
};
use crate::store::journal::{self, Body, History, Reads};
use crate::store::{Commit, Expiry, Instance, Kind};
use crate::transition::{Change, Dependency, Key, Operation, OperationId, Proposal};

/// The blocks of the counter that a start reserves: one in use and one spare.
const BLOCKS: u64 = 2;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(super) enum Begin {
    Start,
    Restore,
    Reviewed(AlphaSource),
}

impl Begin {
    fn source(self) -> Option<AlphaSource> {
        match self {
            Self::Start => None,
            Self::Restore => Some(AlphaSource::Snapshot),
            Self::Reviewed(source) => Some(source),
        }
    }
}

#[derive(Debug)]
pub(super) struct Start {
    begin: Begin,
    /// The replay floor names the installed instance, so the start joins it.
    joining: bool,
    phase: StartPhase,
    /// The journal intents that the store holds.
    owed: Vec<Owed>,
    /// The reads of the store state.
    reads: Reads,
    /// The restore decision, for a restore.
    activation: Option<journal::Activation>,
    /// The replay floor that the store holds.
    floor: Option<record::Floor>,
}

#[derive(Debug)]
enum StartPhase {
    /// The installed instance number.
    Installed,
    /// The replay floor, which names the open instance.
    Admission(Gathering),
    /// The new instance number.
    Instance,
    /// The read of the mark record.
    Mark,
    /// The journal after the mark.
    Journal(Refreshing),
    /// The journal intents.
    Intents(Scanning),
    /// The reads of the store state.
    Reads(Fetching),
    /// The mark record with the completions that the restore owes, before the restore applies anything.
    Record(Committing),
    /// The facts and anchors of a restore.
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
    /// The final mark and its journal sync.
    Close(Committing),
    /// The replay floor that admits work for this instance.
    Open(Committing),
    /// The work of the operations that a crash of this driver cut.
    Settle(Box<Settling>),
    /// The blocks of the counter.
    Reserve(Box<Reserving>),
    Done,
}

impl Start {
    pub(super) fn new(begin: Begin) -> Self {
        Self {
            begin,
            joining: false,
            phase: match begin {
                Begin::Start => StartPhase::Installed,
                Begin::Restore => StartPhase::Instance,
                Begin::Reviewed(_) => StartPhase::Mark,
            },
            owed: Vec::new(),
            reads: Reads::default(),
            activation: None,
            floor: None,
        }
    }

    pub(super) fn effect<'a>(&'a self, core: &'a Core) -> Option<Effect<'a>> {
        match &self.phase {
            StartPhase::Installed => Some(Effect::Instance),
            StartPhase::Admission(gathering) => gathering.effect(),
            StartPhase::Instance => Some(Effect::Start),
            StartPhase::Mark => Some(Effect::Read(&core.mark_key)),
            StartPhase::Journal(refreshing) => refreshing.effect(core),
            StartPhase::Intents(scanning) => scanning.effect(),
            StartPhase::Reads(reading) | StartPhase::Recheck(reading) => reading.effect(),
            StartPhase::Record(committing)
            | StartPhase::Apply(committing)
            | StartPhase::Release(committing)
            | StartPhase::Close(committing)
            | StartPhase::Open(committing) => committing.effect(core),
            StartPhase::Ends(kinds) => kinds
                .front()
                .map(|kind| Effect::Expire(*kind, Duration::MAX, super::PAGE, core.instance)),
            StartPhase::Complete(proposals) => proposals
                .front()
                .map(|proposal| Effect::Commit(proposal, core.instance)),
            StartPhase::Reconcile(writing) => writing.effect(core),
            StartPhase::Settle(settling) => settling.effect(core),
            StartPhase::Reserve(reserving) => reserving.effect(core),
            StartPhase::Done => None,
        }
    }

    pub(super) fn give(&mut self, core: &mut Core, output: Output) -> Result<(), Error> {
        match &mut self.phase {
            StartPhase::Installed => {
                let Output::Instance(instance) = output else {
                    return Err(Error::Binding);
                };
                core.instance = instance;
                // No start installed an instance yet: activate the first one.
                self.phase = if instance == Instance(0) {
                    StartPhase::Instance
                } else {
                    StartPhase::Admission(Gathering::new([core.floor_key.clone()]))
                };
                Ok(())
            }
            StartPhase::Admission(gathering) => gathering.give(output),
            StartPhase::Instance => {
                let Output::Started(instance) = output else {
                    return Err(Error::Binding);
                };
                core.instance = instance;
                self.joining = false;
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
                if matches!(self.begin, Begin::Reviewed(_)) && !core.record.ambiguous() {
                    return Err(Error::Superseded);
                }
                if self.joining && core.record.restore == RestoreMark::Instance(core.instance) {
                    // The replay floor names the restore instance, so its recovery finished.
                    core.record.restore = RestoreMark::Settled;
                }
                self.phase = if self.joining && core.record.restore != RestoreMark::Settled {
                    // An unfinished recovery: activate a new instance, which resumes it.
                    self.joining = false;
                    StartPhase::Instance
                } else if core.journal {
                    core.history = History::new(core.record.mark);
                    StartPhase::Journal(Refreshing::default())
                } else if self.joining {
                    StartPhase::Settle(Box::new(Settling::new(mem::take(&mut core.abandoned))))
                } else {
                    StartPhase::Reads(Fetching::new([core.floor_key.clone()], []))
                };
                Ok(())
            }
            StartPhase::Journal(refreshing) => refreshing.give(core, output),
            StartPhase::Intents(scanning) => scanning.give(core.limits, output),
            StartPhase::Reads(reading) => {
                if core.journal
                    && core.record.ambiguous()
                    && let (Some(key), Output::Read(record)) = (reading.keys.front(), &output)
                    && let Some(sequence) = core.history.alpha_dispute(key, record.as_ref(), self.begin.source())?
                {
                    return Err(Error::AlphaReview {
                        instance: core.instance,
                        sequence,
                    });
                }
                reading.give(output)
            }
            StartPhase::Recheck(reading) => reading.give(output),
            StartPhase::Record(committing)
            | StartPhase::Apply(committing)
            | StartPhase::Release(committing)
            | StartPhase::Close(committing)
            | StartPhase::Open(committing) => committing.give(core, output),
            StartPhase::Ends(kinds) => {
                let removed = match output {
                    Output::Expired(Expiry::Removed(removed)) => removed,
                    Output::Expired(Expiry::Superseded) => return Err(Error::Superseded),
                    _ => return Err(Error::Binding),
                };
                if removed < super::PAGE.get() {
                    kinds.pop_front();
                }
                Ok(())
            }
            StartPhase::Complete(proposals) => {
                // A completion that does not commit leaves its value consumed. One that the store recorded
                // completed before a crash.
                match output {
                    Output::Committed(Commit::Superseded) => return Err(Error::Superseded),
                    Output::Committed(_) => {}
                    _ => return Err(Error::Binding),
                }
                proposals.pop_front();
                Ok(())
            }
            StartPhase::Reconcile(writing) => writing.give(core, output),
            StartPhase::Settle(settling) => settling.give(core, output),
            StartPhase::Reserve(reserving) => reserving.give(core, output),
            StartPhase::Done => Err(Error::Binding),
        }
    }

    pub(super) fn settle(&mut self, core: &mut Core) -> Settled {
        loop {
            let pending = match &mut self.phase {
                StartPhase::Settle(settling) => !settling.settle(core)?,
                StartPhase::Reserve(reserving) => !reserving.settle(core)?,
                _ => self.effect(core).is_some(),
            };
            if pending {
                return Ok(None);
            }
            self.phase = match mem::replace(&mut self.phase, StartPhase::Done) {
                StartPhase::Admission(gathering) => {
                    let floor = gathering
                        .get(&core.floor_key)
                        .map(|record| record::Floor::read(&record.data).ok_or(Error::Record))
                        .transpose()?;
                    if floor.is_some_and(|floor| floor.instance == core.instance) {
                        self.joining = true;
                        StartPhase::Mark
                    } else {
                        StartPhase::Instance
                    }
                }
                StartPhase::Journal(_) if self.joining => {
                    // The anchors with no end that the journal created, which a store state of a restore can lack.
                    let state = core.history.state()?;
                    let keys: Vec<Key> = state
                        .anchors()
                        .filter(|anchor| anchor.end.is_none())
                        .map(|anchor| anchor.key.clone())
                        .collect();
                    StartPhase::Reads(Fetching::new(keys, []))
                }
                StartPhase::Journal(_) => StartPhase::Intents(Scanning::all(core)),
                StartPhase::Intents(scanning) => {
                    self.owed = scanning.owed;
                    StartPhase::Reads(self.reading(core))
                }
                StartPhase::Reads(reading) if self.joining => {
                    // A crash loses no commit, so a journal that shows a commit that the store lacks shows a restore.
                    self.reads = reading.reads;
                    self.check(core)?;
                    StartPhase::Settle(Box::new(Settling::new(mem::take(&mut core.abandoned))))
                }
                StartPhase::Reads(reading) => {
                    self.reads = reading.reads;
                    self.floor = reading.floor;
                    self.prepare(core)?
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
                    self.floor = reading.floor;
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
                StartPhase::Release(_) => {
                    if self.activation.is_some() {
                        core.record.restore = RestoreMark::Instance(core.instance);
                    }
                    Self::close(core)?
                }
                StartPhase::Close(_) => self.open(core)?,
                StartPhase::Open(_) => {
                    core.record.restore = RestoreMark::Settled;
                    StartPhase::Settle(Box::new(Settling::new(mem::take(&mut core.abandoned))))
                }
                StartPhase::Settle(_) => {
                    // The blocks of an earlier instance or of a crashed driver can be in use by no one, but a new
                    // reservation is above each of them.
                    core.counter = Counter::EMPTY;
                    StartPhase::Reserve(Box::new(Reserving::new(BLOCKS)))
                }
                StartPhase::Reserve(_) => {
                    core.status = Status::Serving;
                    return Ok(Some(None));
                }
                StartPhase::Installed | StartPhase::Instance | StartPhase::Mark | StartPhase::Done => {
                    return Ok(Some(None));
                }
            };
        }
    }

    /// Select ordinary reconciliation, a recorded restore, or the one-time alpha cleanup from durable evidence.
    fn prepare(&mut self, core: &mut Core) -> Result<StartPhase, Error> {
        if self
            .floor
            .is_some_and(|floor| core.record.restore == RestoreMark::Instance(floor.instance))
        {
            core.record.restore = RestoreMark::Settled;
        }
        if !core.journal {
            (core.record.restore == RestoreMark::Settled).ok_or(Error::Unsupported)?;
            return Self::close(core);
        }
        let snapshot = self.begin.source() == Some(AlphaSource::Snapshot);
        if !snapshot {
            self.check(core)?;
            if core.record.restore == RestoreMark::Settled || self.begin == Begin::Reviewed(AlphaSource::Intact) {
                return self.reconcile(core);
            }
        }
        let activation = journal::restore(&core.history, &self.reads)?;
        let ambiguous = core.record.ambiguous();
        if ambiguous
            && !snapshot
            && let Some(first) = activation.completions.first()
        {
            return Err(Error::AlphaReview {
                instance: core.instance,
                sequence: first.sequence,
            });
        }
        if snapshot || ambiguous {
            core.record.restore = RestoreMark::Instance(core.instance);
            core.record.owed = activation
                .completions
                .iter()
                .map(|completion| completion.sequence)
                .collect();
            self.activation = Some(activation);
            Ok(StartPhase::Record(core.marking()?))
        } else {
            self.activation = Some(activation);
            Ok(StartPhase::Apply(Committing::new(self.apply(core)?)))
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
        let mut outcomes = core.history.operations();
        if self.begin == Begin::Reviewed(AlphaSource::Intact) {
            outcomes.extend(
                core.history
                    .entries()
                    .iter()
                    .filter_map(|entry| matches!(entry.body, Body::End(_)).then_some(&entry.operation)),
            );
        }
        let operations: Vec<OperationId> = outcomes
            .into_iter()
            .cloned()
            .chain(self.owed.iter().map(|owed| owed.operation.clone()))
            .collect();
        Fetching::new(keys, operations)
    }

    /// End each record at or below its fact. Restore each anchor from its creation entry.
    /// A second run reads each affected key and applies the changes that remain.
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
    fn reconcile(&self, core: &mut Core) -> Result<StartPhase, Error> {
        let candidates: Vec<(OperationId, Vec<journal::Anchor>)> = self
            .owed
            .iter()
            .map(|owed| (owed.operation.clone(), owed.anchors.clone()))
            .collect();
        let decision = journal::reconcile(&core.history, &self.reads, &candidates)?;
        if self.begin == Begin::Reviewed(AlphaSource::Intact) {
            let state = core.history.state()?;
            for (operation, sequence) in &decision.voids {
                let committed = self.reads.outcomes.get(operation).ok_or(journal::Error::Unread)?;
                if *committed || state.acknowledges([operation]) {
                    return Err(Error::AlphaReview {
                        instance: core.instance,
                        sequence: *sequence,
                    });
                }
            }
            core.record.restore = RestoreMark::Settled;
        }
        let creations = decision
            .creations
            .into_iter()
            .map(|(operation, anchors)| (operation, Pending::Body(Body::Creation(anchors))));
        let voids = decision
            .voids
            .into_iter()
            .map(|(operation, sequence)| (operation, Pending::Body(Body::Void(sequence))));
        Ok(StartPhase::Reconcile(Writing::new(core, creations.chain(voids))?))
    }

    /// Refuses a start on a store state that a restore made: a later write of the mark record than the store holds,
    /// or a creation entry of an anchor with no end that the store lacks, shows a commit that the store lost. A crash
    /// loses no commit, so a start after a crash passes.
    fn check(&self, core: &mut Core) -> Result<(), Error> {
        let state = core.history.state()?;
        (written(state) <= core.record.written).ok_or(Error::Restored)?;
        if core.record.restore == RestoreMark::Settled {
            for anchor in state.anchors().filter(|anchor| anchor.end.is_none()) {
                let held = self.reads.records.get(&anchor.key).is_some_and(Option::is_some);
                (held || state.ends(&anchor.key, &anchor.version)?).ok_or(Error::Restored)?;
            }
        }
        Ok(())
    }

    /// Keep the restore instance in the final mark until its replay floor is durable.
    fn close(core: &mut Core) -> Result<StartPhase, Error> {
        core.record.owed.clear();
        Ok(StartPhase::Close(core.marking()?))
    }

    /// Publish the replay floor after the mark and journal are durable. A durable store keeps its floor on an ordinary start.
    fn open(&self, core: &mut Core) -> Result<StartPhase, Error> {
        let (estimate, bound) = match self.floor {
            _ if self.activation.is_some() || core.loses => (core.now.estimate(), core.now.bound()),
            Some(kept) => (kept.estimate, kept.bound),
            None => (Duration::ZERO, Some(Duration::ZERO)),
        };
        let version = self.reads.records.get(&core.floor_key).and_then(Option::as_ref);
        let floor = record::Floor {
            estimate,
            bound,
            instance: core.instance,
        };
        let id = core.operation();
        let proposal = record::replay_floor(id, core.now, floor, core.limits, version).ok_or(Error::Record)?;
        Ok(StartPhase::Open(Committing::new([proposal])))
    }
}
