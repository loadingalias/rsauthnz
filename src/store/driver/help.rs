//! The operations that finish or settle the work of other operations: the help of a held owner turn, the settlement
//! of the work that a crash cut, the lookup, the recovery after a lost reply, the reservation of the counter, and the
//! write of the shared mark record.

use alloc::collections::VecDeque;
use alloc::vec::Vec;
use core::mem;
use core::time::Duration;

use super::turn::{self, Phase as TurnPhase, Turn};
use super::{
    Abandoned, Answer, COUNTER, Committing, Core, Deciding, Effect, Error, FLOOR_BLOCK, Gathering, Handle, Lookup,
    Output, Owed, Pending, Recovered, Refreshing, Scanning, Settled, TURN_PATIENCE, TURN_ROUNDS, WRITE_ATTEMPTS,
    Writing, outcome_key, owed, record, release, written,
};
use crate::id::AuthorityVersion;
use crate::store::journal::{self, Body, Mark};
use crate::store::{Commit, outcome_of};
use crate::time::Reading;
use crate::transition::{CLOSED, Key, Operation, Outcome, Receipt};

// ---------------------------------------------------------------------------------------------------------------
// The help of a held owner turn.

/// Finishes or retires the change of a turn record: a committed change gets its creation entry, and a retired change
/// gets its void, and then the turns are released. A held change is retired at once when it is closed or when the
/// helper forces it, and after [`TURN_PATIENCE`] otherwise.
#[derive(Debug)]
pub(super) struct Helping {
    turn: Turn,
    /// The earliest time of the reading of the helper.
    time: Duration,
    /// The change belongs to this driver and a crash cut it, so it needs no patience.
    force: bool,
    rounds: u32,
    /// The journal intents of a committed change.
    owed: Vec<Owed>,
    helped: bool,
    phase: HelpPhase,
}

#[derive(Debug)]
enum HelpPhase {
    Begin,
    /// The outcome record of a held change.
    Outcome(Gathering),
    Retire(Deciding),
    /// The turn again, after a conflicting retirement.
    Reread(Gathering),
    /// The journal intents of a committed change.
    Intents(Scanning),
    Refresh(Refreshing),
    /// The creation entry or the void of the change.
    Write(Writing),
    Release(Committing),
    Done,
}

impl Helping {
    pub(super) const fn new(turn: Turn, time: Duration, force: bool) -> Self {
        Self {
            turn,
            time,
            force,
            rounds: 0,
            owed: Vec::new(),
            helped: false,
            phase: HelpPhase::Begin,
        }
    }

    /// Whether the help released the turn: the change of the peer committed or refused, so a new reservation can land.
    pub(super) const fn helped(&self) -> bool {
        self.helped
    }

    pub(super) fn effect<'a>(&'a self, core: &'a Core) -> Option<Effect<'a>> {
        match &self.phase {
            HelpPhase::Outcome(gathering) | HelpPhase::Reread(gathering) => gathering.effect(),
            HelpPhase::Retire(deciding) => deciding.effect(core),
            HelpPhase::Intents(scanning) => scanning.effect(),
            HelpPhase::Refresh(refreshing) => refreshing.effect(core),
            HelpPhase::Write(writing) => writing.effect(core),
            HelpPhase::Release(committing) => committing.effect(core),
            HelpPhase::Begin | HelpPhase::Done => None,
        }
    }

    pub(super) fn give(&mut self, core: &mut Core, output: Output) -> Result<(), Error> {
        match &mut self.phase {
            HelpPhase::Outcome(gathering) | HelpPhase::Reread(gathering) => gathering.give(output),
            HelpPhase::Retire(deciding) => deciding.give(output),
            HelpPhase::Intents(scanning) => scanning.give(core.limits, output),
            HelpPhase::Refresh(refreshing) => refreshing.give(core, output),
            HelpPhase::Write(writing) => writing.give(core, output),
            HelpPhase::Release(committing) => committing.give(core, output),
            HelpPhase::Begin | HelpPhase::Done => Err(Error::Binding),
        }
    }

    /// Settles the help: `true` when it has no effect left.
    pub(super) fn settle(&mut self, core: &mut Core) -> Result<bool, Error> {
        loop {
            if self.effect(core).is_some() {
                return Ok(false);
            }
            let operation = self.turn.operation.clone();
            self.phase = match mem::replace(&mut self.phase, HelpPhase::Done) {
                HelpPhase::Begin => match self.turn.phase {
                    TurnPhase::Held => HelpPhase::Outcome(Gathering::new([outcome_key(&operation)])),
                    TurnPhase::Made => HelpPhase::Intents(Scanning::of(&operation)),
                    TurnPhase::Retired => self.refreshing(core)?,
                },
                HelpPhase::Outcome(gathering) => {
                    let closed = gathering
                        .get(&outcome_key(&operation))
                        .and_then(|record| outcome_of(&operation, record))
                        .is_some_and(|stored| stored.binding == CLOSED);
                    let stale = self.time > self.turn.time.saturating_add(TURN_PATIENCE);
                    if !(self.force || closed || stale) {
                        return Ok(true);
                    }
                    let id = core.operation();
                    let proposal = turn::retire(id, &self.turn, core.now, core.limits).ok_or(Error::Record)?;
                    HelpPhase::Retire(Deciding::new(proposal))
                }
                HelpPhase::Retire(deciding) => match deciding.result.ok_or(Error::Binding)? {
                    Commit::Accepted => {
                        self.turn = self.turn.with(TurnPhase::Retired);
                        self.refreshing(core)?
                    }
                    Commit::Conflict => {
                        let key = self.turn.keys.first().cloned().ok_or(Error::Record)?;
                        HelpPhase::Reread(Gathering::new([key]))
                    }
                    _ => return Err(Error::Binding),
                },
                HelpPhase::Reread(gathering) => {
                    let key = self.turn.keys.first().ok_or(Error::Record)?;
                    let turn = match gathering.get(key) {
                        None => None,
                        Some(record) => Some(Turn::read(record, core.limits).ok_or(Error::Record)?),
                    };
                    match turn {
                        Some(turn) if turn.attempt == self.turn.attempt => {
                            // The change committed, or another helper retired it, before this retirement. After
                            // `TURN_ROUNDS` of them, the help ends with no release, and the caller conflicts.
                            self.rounds = self.rounds.saturating_add(1);
                            if self.rounds > TURN_ROUNDS {
                                return Ok(true);
                            }
                            self.turn = turn;
                            HelpPhase::Begin
                        }
                        // The turn was released, so a reservation can land.
                        _ => {
                            self.helped = true;
                            HelpPhase::Done
                        }
                    }
                }
                HelpPhase::Intents(scanning) => {
                    self.owed = scanning.owed;
                    self.refreshing(core)?
                }
                HelpPhase::Refresh(_) => self.write(core)?,
                HelpPhase::Write(_) => self.releasing(core)?,
                HelpPhase::Release(_) => {
                    self.helped = true;
                    HelpPhase::Done
                }
                HelpPhase::Done => return Ok(true),
            };
        }
    }

    fn refreshing(&mut self, core: &mut Core) -> Result<HelpPhase, Error> {
        if core.journal {
            Ok(HelpPhase::Refresh(Refreshing::default()))
        } else {
            self.write(core)
        }
    }

    /// The creation entry of a committed change, or the void of a retired one, when the journal lacks it.
    fn write(&mut self, core: &mut Core) -> Result<HelpPhase, Error> {
        let operation = self.turn.operation.clone();
        if !core.journal {
            return self.releasing(core);
        }
        let body = match self.turn.phase {
            TurnPhase::Made => {
                let anchors = owed(&core.history, &operation, &self.owed);
                if anchors.is_empty() {
                    return self.releasing(core);
                }
                Body::Creation(anchors)
            }
            // The void of the end entry of the attempt, or the terminal void that fences its append.
            TurnPhase::Retired => return Ok(HelpPhase::Write(Writing::new(core, [(operation, Pending::Void)])?)),
            TurnPhase::Held => return Err(Error::Binding),
        };
        Ok(HelpPhase::Write(Writing::new(
            core,
            [(operation, Pending::Body(body))],
        )?))
    }

    /// The release of the turns, and of the journal intents of a committed change.
    fn releasing(&mut self, core: &mut Core) -> Result<HelpPhase, Error> {
        let intents: Vec<(Key, AuthorityVersion)> = self
            .owed
            .iter()
            .map(|owed| (owed.key.clone(), owed.version.clone()))
            .collect();
        let id = core.operation();
        let proposal = turn::release(id, &self.turn, &intents, core.now, core.limits).ok_or(Error::Record)?;
        Ok(HelpPhase::Release(Committing::skipping([proposal])))
    }
}

// ---------------------------------------------------------------------------------------------------------------
// The settlement of the work that a crash cut.

/// Settles each operation of `queue`: a cut anchor change gets the help of its turn, with no patience, and a cut
/// change of authority with an end entry is closed and voided when it did not commit.
#[derive(Debug)]
pub(super) struct Settling {
    queue: VecDeque<Abandoned>,
    current: Option<Abandoned>,
    phase: SettlePhase,
}

#[derive(Debug)]
enum SettlePhase {
    Next,
    Turn(Gathering),
    Help(Box<Helping>),
    Outcome(Gathering),
    Close(Deciding),
    Refresh(Refreshing),
    Void(Writing),
    Done,
}

impl Settling {
    pub(super) fn new(queue: impl IntoIterator<Item = Abandoned>) -> Self {
        Self {
            queue: queue.into_iter().collect(),
            current: None,
            phase: SettlePhase::Next,
        }
    }

    pub(super) fn effect<'a>(&'a self, core: &'a Core) -> Option<Effect<'a>> {
        match &self.phase {
            SettlePhase::Turn(gathering) | SettlePhase::Outcome(gathering) => gathering.effect(),
            SettlePhase::Help(helping) => helping.effect(core),
            SettlePhase::Close(deciding) => deciding.effect(core),
            SettlePhase::Refresh(refreshing) => refreshing.effect(core),
            SettlePhase::Void(writing) => writing.effect(core),
            SettlePhase::Next | SettlePhase::Done => None,
        }
    }

    pub(super) fn give(&mut self, core: &mut Core, output: Output) -> Result<(), Error> {
        match &mut self.phase {
            SettlePhase::Turn(gathering) | SettlePhase::Outcome(gathering) => gathering.give(output),
            SettlePhase::Help(helping) => helping.give(core, output),
            SettlePhase::Close(deciding) => deciding.give(output),
            SettlePhase::Refresh(refreshing) => refreshing.give(core, output),
            SettlePhase::Void(writing) => writing.give(core, output),
            SettlePhase::Next | SettlePhase::Done => Err(Error::Binding),
        }
    }

    /// Settles the queue: `true` when it has no effect left.
    pub(super) fn settle(&mut self, core: &mut Core) -> Result<bool, Error> {
        loop {
            if let SettlePhase::Help(helping) = &mut self.phase
                && !helping.settle(core)?
            {
                return Ok(false);
            }
            if self.effect(core).is_some() {
                return Ok(false);
            }
            self.phase = match mem::replace(&mut self.phase, SettlePhase::Done) {
                SettlePhase::Next | SettlePhase::Help(_) | SettlePhase::Void(_) => match self.queue.pop_front() {
                    None => return Ok(true),
                    Some(abandoned) => {
                        let phase = match &abandoned.turn {
                            Some(turn) => SettlePhase::Turn(Gathering::new(turn.keys.first().cloned())),
                            None if abandoned.end => {
                                SettlePhase::Outcome(Gathering::new([outcome_key(&abandoned.operation)]))
                            }
                            None => SettlePhase::Next,
                        };
                        self.current = Some(abandoned);
                        phase
                    }
                },
                SettlePhase::Turn(gathering) => {
                    let attempt = self
                        .current
                        .as_ref()
                        .and_then(|current| current.turn.as_ref())
                        .map(|turn| turn.attempt.clone())
                        .ok_or(Error::Binding)?;
                    match gathering.records.first().and_then(|(_, record)| record.as_ref()) {
                        Some(record) => {
                            let turn = Turn::read(record, core.limits).ok_or(Error::Record)?;
                            if turn.attempt == attempt {
                                SettlePhase::Help(Box::new(Helping::new(turn, Duration::ZERO, true)))
                            } else {
                                SettlePhase::Next
                            }
                        }
                        None => SettlePhase::Next,
                    }
                }
                SettlePhase::Outcome(gathering) => {
                    let current = self
                        .current
                        .as_ref()
                        .map(|current| current.operation.clone())
                        .ok_or(Error::Binding)?;
                    if gathering.get(&outcome_key(&current)).is_some() {
                        SettlePhase::Next
                    } else {
                        SettlePhase::Close(Deciding::new(core.closure(&current)))
                    }
                }
                SettlePhase::Close(deciding) => match deciding.result.ok_or(Error::Binding)? {
                    Commit::Accepted if core.journal => SettlePhase::Refresh(Refreshing::default()),
                    // The operation committed, or a peer closed it, before this closure.
                    Commit::Accepted | Commit::Conflict => SettlePhase::Next,
                    _ => return Err(Error::Binding),
                },
                SettlePhase::Refresh(_) => {
                    let current = self
                        .current
                        .as_ref()
                        .map(|current| current.operation.clone())
                        .ok_or(Error::Binding)?;
                    SettlePhase::Void(Writing::new(core, [(current, Pending::Void)])?)
                }
                SettlePhase::Done => return Ok(true),
            };
        }
    }
}

// ---------------------------------------------------------------------------------------------------------------
// The lookup.

/// A lookup: the outcome record of the operation, and, while its creation entry is owed, the journal.
#[derive(Debug)]
pub(super) struct Looking {
    operation: Operation,
    receipt: Option<Receipt>,
    owed: Vec<Owed>,
    phase: LookPhase,
}

#[derive(Debug)]
enum LookPhase {
    Outcome(Gathering),
    Intents(Scanning),
    Refresh(Refreshing),
    Done(Option<Lookup>),
}

impl Looking {
    pub(super) fn new(operation: Operation) -> Self {
        let key = outcome_key(&operation.id);
        Self {
            operation,
            receipt: None,
            owed: Vec::new(),
            phase: LookPhase::Outcome(Gathering::new([key])),
        }
    }

    pub(super) fn effect<'a>(&'a self, core: &'a Core) -> Option<Effect<'a>> {
        match &self.phase {
            LookPhase::Outcome(gathering) => gathering.effect(),
            LookPhase::Intents(scanning) => scanning.effect(),
            LookPhase::Refresh(refreshing) => refreshing.effect(core),
            LookPhase::Done(_) => None,
        }
    }

    pub(super) fn give(&mut self, core: &mut Core, output: Output) -> Result<(), Error> {
        match &mut self.phase {
            LookPhase::Outcome(gathering) => gathering.give(output),
            LookPhase::Intents(scanning) => scanning.give(core.limits, output),
            LookPhase::Refresh(refreshing) => refreshing.give(core, output),
            LookPhase::Done(_) => Err(Error::Binding),
        }
    }

    pub(super) fn settle(&mut self, core: &mut Core) -> Settled {
        loop {
            if self.effect(core).is_some() {
                return Ok(None);
            }
            let id = self.operation.id.clone();
            self.phase = match mem::replace(&mut self.phase, LookPhase::Done(None)) {
                LookPhase::Outcome(gathering) => match gathering.get(&outcome_key(&id)) {
                    None => LookPhase::Done(Some(Lookup::Unknown)),
                    Some(record) => match outcome_of(&id, record).ok_or(Error::Record)?.answer(&self.operation) {
                        Outcome::Accepted(receipt) => {
                            self.receipt = Some(receipt);
                            LookPhase::Intents(Scanning::of(&id))
                        }
                        Outcome::Refused(error) => LookPhase::Done(Some(Lookup::Refused(error))),
                        Outcome::Conflict | Outcome::Unknown(_) => LookPhase::Done(Some(Lookup::Unknown)),
                    },
                },
                // The acknowledgement waits for the creation entry of an anchor commit.
                LookPhase::Intents(scanning) if core.journal => {
                    self.owed = scanning.owed;
                    LookPhase::Refresh(Refreshing::default())
                }
                LookPhase::Intents(_) => self.committed(),
                LookPhase::Refresh(_) if owed(&core.history, &id, &self.owed).is_empty() => self.committed(),
                LookPhase::Refresh(_) => LookPhase::Done(Some(Lookup::Unknown)),
                LookPhase::Done(lookup) => return Ok(Some(lookup.map(Answer::Lookup))),
            };
        }
    }

    fn committed(&mut self) -> LookPhase {
        LookPhase::Done(Some(self.receipt.take().map_or(Lookup::Unknown, Lookup::Committed)))
    }
}

// ---------------------------------------------------------------------------------------------------------------
// The recovery after a lost reply.

/// A recovery: the receipt after its creation entry, the closure of a missing operation in its instance and retention,
/// or an unknown result.
#[derive(Debug)]
pub(super) struct Recovering {
    handle: Handle,
    now: Reading,
    receipt: Option<Receipt>,
    owed: Vec<Owed>,
    /// A closure conflicted once, so the outcome record is read again.
    again: bool,
    phase: RecoverPhase,
}

#[derive(Debug)]
enum RecoverPhase {
    Outcome(Gathering),
    Intents(Scanning),
    Refresh(Refreshing),
    Creation(Writing),
    Release(Committing),
    Close(Deciding),
    Closing(Refreshing),
    Void(Writing),
    Done(Option<Recovered>),
}

impl Recovering {
    pub(super) fn new(handle: Handle, now: Reading) -> Self {
        let key = outcome_key(&handle.operation.id);
        Self {
            handle,
            now,
            receipt: None,
            owed: Vec::new(),
            again: false,
            phase: RecoverPhase::Outcome(Gathering::new([key])),
        }
    }

    pub(super) fn effect<'a>(&'a self, core: &'a Core) -> Option<Effect<'a>> {
        match &self.phase {
            RecoverPhase::Outcome(gathering) => gathering.effect(),
            RecoverPhase::Intents(scanning) => scanning.effect(),
            RecoverPhase::Refresh(refreshing) | RecoverPhase::Closing(refreshing) => refreshing.effect(core),
            RecoverPhase::Creation(writing) | RecoverPhase::Void(writing) => writing.effect(core),
            RecoverPhase::Release(committing) => committing.effect(core),
            RecoverPhase::Close(deciding) => deciding.effect(core),
            RecoverPhase::Done(_) => None,
        }
    }

    pub(super) fn give(&mut self, core: &mut Core, output: Output) -> Result<(), Error> {
        match &mut self.phase {
            RecoverPhase::Outcome(gathering) => gathering.give(output),
            RecoverPhase::Intents(scanning) => scanning.give(core.limits, output),
            RecoverPhase::Refresh(refreshing) | RecoverPhase::Closing(refreshing) => refreshing.give(core, output),
            RecoverPhase::Creation(writing) | RecoverPhase::Void(writing) => writing.give(core, output),
            RecoverPhase::Release(committing) => committing.give(core, output),
            RecoverPhase::Close(deciding) => deciding.give(output),
            RecoverPhase::Done(_) => Err(Error::Binding),
        }
    }

    pub(super) fn settle(&mut self, core: &mut Core) -> Settled {
        loop {
            if self.effect(core).is_some() {
                return Ok(None);
            }
            let id = self.handle.operation.id.clone();
            self.phase = match mem::replace(&mut self.phase, RecoverPhase::Done(None)) {
                RecoverPhase::Outcome(gathering) => match gathering.get(&outcome_key(&id)) {
                    Some(record) => {
                        let stored = outcome_of(&id, record).ok_or(Error::Record)?;
                        match stored.answer(&self.handle.operation) {
                            Outcome::Accepted(receipt) => {
                                self.receipt = Some(receipt);
                                RecoverPhase::Intents(Scanning::of(&id))
                            }
                            Outcome::Refused(crate::transition::Error::Closed) => {
                                RecoverPhase::Done(Some(Recovered::Fresh))
                            }
                            Outcome::Refused(error) => RecoverPhase::Done(Some(Recovered::Refused(error))),
                            Outcome::Conflict | Outcome::Unknown(_) => RecoverPhase::Done(Some(Recovered::Unknown)),
                        }
                    }
                    None => {
                        let covered = self
                            .now
                            .latest()
                            .is_ok_and(|latest| latest < self.handle.time.saturating_add(core.retention));
                        if self.handle.instance == core.instance && covered && !self.again {
                            RecoverPhase::Close(Deciding::new(core.closure(&id)))
                        } else {
                            RecoverPhase::Done(Some(Recovered::Unknown))
                        }
                    }
                },
                RecoverPhase::Intents(scanning) => {
                    self.owed = scanning.owed;
                    if core.journal {
                        RecoverPhase::Refresh(Refreshing::default())
                    } else {
                        self.releasing(core)?
                    }
                }
                RecoverPhase::Refresh(_) => {
                    let anchors = owed(&core.history, &id, &self.owed);
                    if anchors.is_empty() {
                        self.releasing(core)?
                    } else {
                        RecoverPhase::Creation(Writing::new(core, [(id, Pending::Body(Body::Creation(anchors)))])?)
                    }
                }
                RecoverPhase::Creation(_) => self.releasing(core)?,
                RecoverPhase::Release(_) => self.committed(),
                RecoverPhase::Close(deciding) => match deciding.result.ok_or(Error::Binding)? {
                    Commit::Accepted if core.journal => RecoverPhase::Closing(Refreshing::default()),
                    Commit::Accepted => RecoverPhase::Done(Some(Recovered::Fresh)),
                    Commit::Conflict => {
                        // The original committed, or a peer closed it, before the closure: read its outcome again.
                        self.again = true;
                        RecoverPhase::Outcome(Gathering::new([outcome_key(&id)]))
                    }
                    _ => return Err(Error::Binding),
                },
                RecoverPhase::Closing(_) => RecoverPhase::Void(Writing::new(core, [(id, Pending::Void)])?),
                RecoverPhase::Void(_) => RecoverPhase::Done(Some(Recovered::Fresh)),
                RecoverPhase::Done(recovered) => return Ok(Some(recovered.map(Answer::Recovered))),
            };
        }
    }

    fn committed(&mut self) -> RecoverPhase {
        RecoverPhase::Done(Some(
            self.receipt.take().map_or(Recovered::Unknown, Recovered::Committed),
        ))
    }

    /// The end of each journal intent of the committed operation, after its creation entry.
    fn releasing(&mut self, core: &mut Core) -> Result<RecoverPhase, Error> {
        let proposals = self
            .owed
            .iter()
            .map(|owed| release(core, &owed.key, &owed.version))
            .collect::<Result<Vec<_>, _>>()?;
        Ok(RecoverPhase::Release(Committing::skipping(proposals)))
    }
}

// ---------------------------------------------------------------------------------------------------------------
// The reservation of the counter.

/// Reserves blocks of the counter: one floor entry above the highest floor of the journal, or one write of the mark
/// record for a binding with no journal. Each conflict reads the floors of the peers, so the blocks of two drivers are
/// disjoint.
#[derive(Debug)]
pub(super) struct Reserving {
    blocks: u64,
    phase: ReservePhase,
}

#[derive(Debug)]
enum ReservePhase {
    Begin,
    Refresh(Refreshing),
    Append(Writing),
    Mark(MarkWrite),
    Done,
}

impl Reserving {
    pub(super) const fn new(blocks: u64) -> Self {
        Self {
            blocks,
            phase: ReservePhase::Begin,
        }
    }

    pub(super) fn effect<'a>(&'a self, core: &'a Core) -> Option<Effect<'a>> {
        match &self.phase {
            ReservePhase::Refresh(refreshing) => refreshing.effect(core),
            ReservePhase::Append(writing) => writing.effect(core),
            ReservePhase::Mark(write) => write.effect(core),
            ReservePhase::Begin | ReservePhase::Done => None,
        }
    }

    pub(super) fn give(&mut self, core: &mut Core, output: Output) -> Result<(), Error> {
        match &mut self.phase {
            ReservePhase::Refresh(refreshing) => refreshing.give(core, output),
            ReservePhase::Append(writing) => writing.give(core, output),
            ReservePhase::Mark(write) => write.give(core, output),
            ReservePhase::Begin | ReservePhase::Done => Err(Error::Binding),
        }
    }

    /// Settles the reservation: `true` when the blocks are reserved.
    pub(super) fn settle(&mut self, core: &mut Core) -> Result<bool, Error> {
        loop {
            if let ReservePhase::Mark(write) = &mut self.phase
                && !write.settle(core)?
            {
                return Ok(false);
            }
            if self.effect(core).is_some() {
                return Ok(false);
            }
            self.phase = match mem::replace(&mut self.phase, ReservePhase::Done) {
                ReservePhase::Begin if core.journal => ReservePhase::Refresh(Refreshing::default()),
                ReservePhase::Begin => ReservePhase::Mark(MarkWrite::new(MarkChange::Reserve(self.blocks))),
                ReservePhase::Refresh(_) => {
                    let id = core.operation();
                    ReservePhase::Append(Writing::new(core, [(id, Pending::Reserve(self.blocks))])?)
                }
                ReservePhase::Append(writing) => {
                    self.add(core, writing.reserved.ok_or(Error::Binding)?)?;
                    ReservePhase::Done
                }
                ReservePhase::Mark(write) => {
                    self.add(core, write.reserved.ok_or(Error::Binding)?)?;
                    ReservePhase::Done
                }
                ReservePhase::Done => return Ok(true),
            };
        }
    }

    /// Adds the blocks below the reserved floor `floor` to the counter.
    fn add(&self, core: &mut Core, floor: u64) -> Result<(), Error> {
        let block = FLOOR_BLOCK.get();
        let span = block.checked_mul(self.blocks).ok_or(Error::Overflow)?;
        let first = floor
            .checked_sub(span)
            .ok_or(Error::Record)?
            .checked_add(1)
            .ok_or(Error::Overflow)?;
        for index in 0..self.blocks {
            let start = first
                .checked_add(index.checked_mul(block).ok_or(Error::Overflow)?)
                .ok_or(Error::Overflow)?;
            core.counter
                .add(start, start.checked_add(block - 1).ok_or(Error::Overflow)?);
        }
        Ok(())
    }
}

// ---------------------------------------------------------------------------------------------------------------
// The write of the shared mark record.

/// A change of the mark record that several drivers write.
#[derive(Clone, Copy, Debug)]
pub(super) enum MarkChange {
    /// Move the mark forward to this mark.
    Advance(Mark),
    /// Reserve this many blocks of the counter, for a binding with no journal.
    Reserve(u64),
}

/// Writes a change of the mark record at its version. A conflict reads the record that a peer wrote and applies the
/// change to it again. After the write, the floor entry of its number follows in the journal.
#[derive(Debug)]
pub(super) struct MarkWrite {
    change: MarkChange,
    attempts: u32,
    /// The floor of the accepted reservation.
    pub(super) reserved: Option<u64>,
    phase: MarkPhase,
}

#[derive(Debug)]
enum MarkPhase {
    Begin,
    Write(Deciding),
    Read(Gathering),
    Floor(Writing),
    Done,
}

impl MarkWrite {
    pub(super) const fn new(change: MarkChange) -> Self {
        Self {
            change,
            attempts: 0,
            reserved: None,
            phase: MarkPhase::Begin,
        }
    }

    pub(super) fn effect<'a>(&'a self, core: &'a Core) -> Option<Effect<'a>> {
        match &self.phase {
            MarkPhase::Write(deciding) => deciding.effect(core),
            MarkPhase::Read(gathering) => gathering.effect(),
            MarkPhase::Floor(writing) => writing.effect(core),
            MarkPhase::Begin | MarkPhase::Done => None,
        }
    }

    pub(super) fn give(&mut self, core: &mut Core, output: Output) -> Result<(), Error> {
        match &mut self.phase {
            MarkPhase::Write(deciding) => deciding.give(output),
            MarkPhase::Read(gathering) => gathering.give(output),
            MarkPhase::Floor(writing) => writing.give(core, output),
            MarkPhase::Begin | MarkPhase::Done => Err(Error::Binding),
        }
    }

    /// Settles the write: `true` when it has no effect left.
    pub(super) fn settle(&mut self, core: &mut Core) -> Result<bool, Error> {
        loop {
            if self.effect(core).is_some() {
                return Ok(false);
            }
            self.phase = match mem::replace(&mut self.phase, MarkPhase::Done) {
                MarkPhase::Begin => self.write(core)?,
                MarkPhase::Write(deciding) => match deciding.result.ok_or(Error::Binding)? {
                    Commit::Accepted if core.journal => {
                        let floor = journal::Floor {
                            kind: crate::store::Kind::Mark,
                            value: core.record.written,
                        };
                        let id = core.operation();
                        MarkPhase::Floor(Writing::new(core, [(id, Pending::Body(Body::Floor(floor)))])?)
                    }
                    Commit::Accepted => MarkPhase::Done,
                    Commit::Conflict => {
                        self.attempts = self.attempts.saturating_add(1);
                        (self.attempts <= WRITE_ATTEMPTS).ok_or(Error::Superseded)?;
                        MarkPhase::Read(Gathering::new([core.mark_key.clone()]))
                    }
                    _ => return Err(Error::Binding),
                },
                MarkPhase::Read(gathering) => {
                    core.record = match gathering.get(&core.mark_key) {
                        None => record::State::default(),
                        Some(record) => record::State::read(record, core.limits).ok_or(Error::Record)?,
                    };
                    MarkPhase::Begin
                }
                MarkPhase::Floor(_) => MarkPhase::Done,
                MarkPhase::Done => return Ok(true),
            };
        }
    }

    /// Applies the change to the record of the driver, and gives its write, or the end when the record already holds
    /// the change.
    fn write(&mut self, core: &mut Core) -> Result<MarkPhase, Error> {
        match self.change {
            MarkChange::Advance(mark) => {
                if mark.sequence <= core.record.mark.sequence {
                    return Ok(MarkPhase::Done);
                }
                core.record.mark = mark;
            }
            MarkChange::Reserve(blocks) => {
                let span = FLOOR_BLOCK.get().checked_mul(blocks).ok_or(Error::Overflow)?;
                let floor = core.floor()?.checked_add(span).ok_or(Error::Overflow)?;
                core.record.floors.insert(COUNTER, floor);
                self.reserved = Some(floor);
            }
        }
        let journaled = written(core.history.state()?);
        core.record.written = core
            .record
            .written
            .max(journaled)
            .checked_add(1)
            .ok_or(Error::Overflow)?;
        let id = core.operation();
        let proposal = core.record.write(id, core.now, core.limits).ok_or(Error::Record)?;
        Ok(MarkPhase::Write(Deciding::new(proposal)))
    }
}
