//! A move of the mark: past each journal entry that the store state reflects, for the entries of all drivers.

use alloc::boxed::Box;
use alloc::collections::BTreeMap;
use alloc::vec::Vec;
use core::mem;

use super::help::{Helping, MarkChange, MarkWrite, Settling};
use super::turn::Turn;
use super::{
    Abandoned, Core, Effect, Error, Fetching, Listing, Output, Pending, Refreshing, Settled, TURN_PATIENCE, Writing,
    earliest, latest,
};
use crate::store::Kind;
use crate::store::journal::{self, Body, Mark, Reads};
use crate::transition::OperationId;

#[derive(Debug)]
pub(super) enum Advance {
    Begin,
    /// The journal entries of the peers.
    Refresh(Refreshing),
    /// The turn records. An entry of an operation that holds a turn is not settled, so the mark stays before it.
    Turns(Listing),
    Reads(Fetching, BTreeMap<OperationId, Turn>),
    /// The help of a turn whose operation holds the mark, and the mark before it.
    Help(Box<Helping>, Mark),
    /// The closure and the void of an operation whose end entry held the mark at two moves.
    Settle(Box<Settling>),
    /// A floor entry of each counter, with its value again, after the floor entries that hold the mark, the reads, and
    /// the turns.
    Restate(Box<Writing>, Reads, BTreeMap<OperationId, Turn>),
    /// The mark record with the new mark.
    Write(Box<MarkWrite>),
    Done,
}

impl Advance {
    pub(super) fn effect<'a>(&'a self, core: &'a Core) -> Option<Effect<'a>> {
        match self {
            Self::Refresh(refreshing) => refreshing.effect(core),
            Self::Turns(listing) => listing.effect(),
            Self::Reads(reading, _) => reading.effect(),
            Self::Help(helping, _) => helping.effect(core),
            Self::Settle(settling) => settling.effect(core),
            Self::Restate(writing, ..) => writing.effect(core),
            Self::Write(write) => write.effect(core),
            Self::Begin | Self::Done => None,
        }
    }

    pub(super) fn give(&mut self, core: &mut Core, output: Output) -> Result<(), Error> {
        match self {
            Self::Refresh(refreshing) => refreshing.give(core, output),
            Self::Turns(listing) => listing.give(output),
            Self::Reads(reading, _) => reading.give(output),
            Self::Help(helping, _) => helping.give(core, output),
            Self::Settle(settling) => settling.give(core, output),
            Self::Restate(writing, ..) => writing.give(core, output),
            Self::Write(write) => write.give(core, output),
            Self::Begin | Self::Done => Err(Error::Binding),
        }
    }

    pub(super) fn settle(&mut self, core: &mut Core) -> Settled {
        loop {
            let pending = match self {
                Self::Help(helping, _) => !helping.settle(core)?,
                Self::Settle(settling) => !settling.settle(core)?,
                Self::Write(write) => !write.settle(core)?,
                _ => self.effect(core).is_some(),
            };
            if pending {
                return Ok(None);
            }
            *self = match mem::replace(self, Self::Done) {
                Self::Begin if core.journal => Self::Refresh(Refreshing::default()),
                Self::Refresh(_) => Self::Turns(Listing::new(Kind::Turn.key(&[]).expect("a key of one byte is valid"))),
                Self::Turns(listing) => {
                    let mut turns = BTreeMap::new();
                    for (_, record) in &listing.records {
                        let turn = Turn::read(record, core.limits).ok_or(Error::Record)?;
                        turns.insert(turn.operation.clone(), turn);
                    }
                    Self::Reads(
                        Fetching::new(core.history.keys().into_iter().cloned().collect::<Vec<_>>(), []),
                        turns,
                    )
                }
                Self::Reads(reading, turns) => {
                    let mark = settled(core, &reading.reads, &turns)?;
                    let held = core
                        .history
                        .entries()
                        .iter()
                        .find(|entry| entry.sequence > mark.sequence)
                        .map(|entry| {
                            (
                                entry.operation.clone(),
                                matches!(entry.body, Body::Floor(_)),
                                matches!(entry.body, Body::End(_)),
                            )
                        });
                    if let Some(turn) = held.as_ref().and_then(|(operation, ..)| turns.get(operation)) {
                        return self.help(core, turn.clone(), earliest(core.now), mark);
                    }
                    match held {
                        Some((_, true, _)) => {
                            // The newest floor of a counter holds the mark: a floor entry of each counter, with its
                            // value again, lets the mark pass the earlier floor entries.
                            let id = core.operation();
                            let state = core.history.state()?;
                            let bodies: Vec<(OperationId, Pending)> = state
                                .floors()
                                .map(|floor| (id.clone(), Pending::Body(Body::Floor(floor))))
                                .collect();
                            Self::Restate(Box::new(Writing::new(core, bodies)?), reading.reads, turns)
                        }
                        Some((operation, false, true)) if self.stopped(core, &operation) => {
                            core.blocked = None;
                            Self::Settle(Box::new(Settling::new([Abandoned {
                                operation,
                                turn: None,
                                end: true,
                            }])))
                        }
                        Some((operation, ..)) => {
                            let at = latest(core.now);
                            if core.blocked.as_ref().is_none_or(|(blocked, _)| *blocked != operation) {
                                core.blocked = Some((operation, at));
                            }
                            Self::write(core, mark)
                        }
                        None => {
                            core.blocked = None;
                            Self::write(core, mark)
                        }
                    }
                }
                Self::Help(_, mark) => Self::write(core, mark),
                Self::Restate(_, reads, turns) => {
                    let mark = settled(core, &reads, &turns)?;
                    Self::write(core, mark)
                }
                Self::Write(_) => {
                    let mark = core.record.mark;
                    if mark.sequence <= core.history.head().sequence {
                        core.history = core.history.after(mark);
                    }
                    core.advanced = core.history.entries().len();
                    return Ok(Some(None));
                }
                Self::Settle(_) | Self::Begin | Self::Done => return Ok(Some(None)),
            };
        }
    }

    /// The help of the turn whose operation holds the mark, then the move to `mark`.
    fn help(&mut self, core: &mut Core, turn: Turn, now: core::time::Duration, mark: Mark) -> Settled {
        *self = Self::Help(Box::new(Helping::new(turn, now, false)), mark);
        self.settle(core)
    }

    /// Whether the end entry of `operation` held the mark at an earlier move at least [`TURN_PATIENCE`] before this
    /// one: its server stopped, or it is slow, and its closure is safe.
    fn stopped(&self, core: &Core, operation: &OperationId) -> bool {
        let now = earliest(core.now);
        core.blocked
            .as_ref()
            .is_some_and(|(blocked, at)| blocked == operation && now > at.saturating_add(TURN_PATIENCE))
    }

    /// The mark record with `mark`, or the end of the move when the mark stays.
    fn write(core: &mut Core, mark: Mark) -> Self {
        if mark == core.record.mark {
            core.advanced = core.history.entries().len();
            return Self::Done;
        }
        Self::Write(Box::new(MarkWrite::new(MarkChange::Advance(mark))))
    }
}

/// The low-water mark of the reads, before the first entry of an operation that holds a turn: that operation did not
/// finish, and its creation entry can still be owed.
fn settled(core: &Core, reads: &Reads, turns: &BTreeMap<OperationId, Turn>) -> Result<Mark, Error> {
    let mark = journal::low_water(&core.history, reads)?;
    let first = core
        .history
        .entries()
        .iter()
        .position(|entry| turns.contains_key(&entry.operation) && entry.sequence <= mark.sequence);
    Ok(first.map_or(mark, |index| core.history.before(index)))
}
