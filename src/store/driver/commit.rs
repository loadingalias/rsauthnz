//! A commit: the phases of a submitted proposal.

use alloc::boxed::Box;
use alloc::vec::Vec;
use core::mem;
use core::time::Duration;

use super::help::Helping;
use super::turn::{self, Phase as TurnPhase, Turn};
use super::{
    Abandoned, Answer, Committing, Core, Deciding, Effect, Error, Gathering, Guard, JOURNAL_ENTRIES_MAX, Output,
    Pending, Plan, Refreshing, Settled, TURN_ROUNDS, Writing, earliest, latest, outcome_key, release, value,
};
use crate::id::AuthorityVersion;
use crate::store::journal::{self, Anchor, Body, Entries, Mark};
use crate::store::{Commit, Kind, Sequence, intent_records, outcome_of};
use crate::transition::{self, Change, Dependency, Effect as Call, Intent, Key, Operation, Outcome, Proposal};

/// A submitted commit.
#[derive(Debug)]
pub(super) struct Submitted {
    pub(super) operation: Operation,
    /// The proposal, until its acceptance gives the receipt.
    pub(super) proposal: Option<Proposal>,
    held: Vec<Anchor>,
    entries: Entries,
    /// The key and the version of the journal intent of the commit.
    intent: Option<(Key, AuthorityVersion)>,
    /// The turn of the owners of the anchor change, or `None` for a commit that changes no anchor.
    turn: Option<Turn>,
    /// The reservation of the turns can have landed.
    reserving: bool,
    /// The reservation landed: the commit holds the turns.
    owned: bool,
    /// The end entry can be in the journal.
    ending: bool,
    /// The commit creates a record of a kind whose keys repeat, so its check reads a fresh journal.
    fresh: bool,
    /// The earliest time of the audit reading, which the patience of a held turn of a peer compares.
    time: Duration,
    rounds: u32,
    /// The sequence of the end entry once appended.
    end: Option<Sequence>,
    /// The outcome once known, before the entries that its answer waits for are durable.
    outcome: Option<Outcome>,
    /// The answer: the outcome after the creation entry or the void is durable. A crash before it gives an unknown
    /// outcome.
    pub(super) answer: Option<Outcome>,
    phase: CommitPhase,
}

#[derive(Debug)]
enum CommitPhase {
    Begin,
    /// The reservation of the owner turns.
    Reserve(Deciding),
    /// The turns and the outcome record of the commit, after a conflicting reservation.
    Contend(Gathering),
    /// The help of the change of a peer that holds a turn.
    Help(Box<Helping>),
    /// The journal entries of the peers, before the check.
    Refresh(Refreshing),
    /// The last-anchor check and the check of the repeated keys.
    Check,
    /// The end entry, then a sync.
    Entries(Writing),
    /// The conditional commit.
    Commit,
    /// The result of the commit.
    Result(Commit),
    /// The creation entry, then a sync.
    Creation(Writing),
    /// The void of the end entry, then a sync.
    Void(Writing),
    /// The release of the turns and of the journal intent.
    Release(Committing),
    Done,
}

impl Submitted {
    /// The commit of `proposal` with `plan`. The journal intent and the guards of the owner turns join the proposal.
    pub(super) fn new(core: &mut Core, mut proposal: Proposal, plan: Plan) -> Result<Self, Error> {
        let entries = journal::entries(&proposal, &plan.replaced, &plan.anchors)?;
        let writes = entries.end.is_some() || !entries.creation.is_empty();
        (!(core.journal && writes) || core.history.entries().len() < JOURNAL_ENTRIES_MAX).ok_or(Error::Long)?;
        let mut intent = None;
        if core.journal {
            if let Some(end) = &entries.end {
                // The widest sequence gives the longest form, so each later append fits too.
                let widest = Mark {
                    sequence: Sequence(u64::MAX - 1),
                    link: Mark::EMPTY.link,
                };
                widest
                    .next(&proposal.operation().id, &Body::End(end.clone()), core.limits)
                    .map_err(|_| Error::Transition(transition::Error::Limit(crate::limits::Limit::Bytes)))?;
            }
            let consumes = entries.end.as_ref().is_some_and(|end| end.consumption.is_some());
            if !entries.creation.is_empty() && !consumes {
                let payload = journal::encode_anchors(&entries.creation, core.limits)
                    .map_err(|_| Error::Transition(transition::Error::Limit(crate::limits::Limit::Bytes)))?
                    .into_boxed_slice();
                proposal
                    .intend(Intent::new(Call::Journal, payload))
                    .map_err(Error::Transition)?;
                let records = intent_records(&proposal).map_err(Error::Transition)?;
                intent = records
                    .last()
                    .map(|(key, record)| (key.clone(), record.version.clone()));
            }
        }
        // The owner of each anchor that the change ends or creates.
        let ends = |key: &Key| {
            entries
                .end
                .as_ref()
                .is_some_and(|end| end.facts.iter().any(|fact| fact.key == *key))
        };
        let mut keys: Vec<Key> = plan
            .held
            .iter()
            .filter(|anchor| ends(&anchor.key))
            .map(|anchor| anchor.role.turn())
            .chain(plan.anchors.iter().map(|(_, role)| role.turn()))
            .collect();
        keys.sort();
        keys.dedup();
        let audit = proposal.audit().time;
        let turn = (!keys.is_empty()).then(|| Turn {
            operation: proposal.operation().id.clone(),
            attempt: core.operation(),
            phase: TurnPhase::Held,
            time: latest(audit),
            keys,
        });
        if let Some(turn) = &turn {
            turn.guard(&mut proposal);
        }
        let fresh = core.journal
            && proposal.changes().iter().any(|change| match change {
                Change::Write { key, .. } => {
                    Kind::of(key).is_some_and(|kind| kind.repeats())
                        && proposal.dependencies().contains(&Dependency::Absent(key.clone()))
                }
                Change::End(_) => false,
            });
        Ok(Self {
            operation: proposal.operation().clone(),
            proposal: Some(proposal),
            held: plan.held,
            entries,
            intent,
            turn,
            reserving: false,
            owned: false,
            ending: false,
            fresh,
            time: earliest(audit),
            rounds: 0,
            end: None,
            outcome: None,
            answer: None,
            phase: CommitPhase::Begin,
        })
    }

    /// The work of the commit that the next start settles after a crash, or `None` when it left none.
    pub(super) fn abandoned(&self) -> Option<Abandoned> {
        let turn = self.turn.clone().filter(|_| self.reserving);
        let end = self.ending && self.answer.is_none() && turn.is_none();
        (turn.is_some() || end).then(|| Abandoned {
            operation: self.operation.id.clone(),
            turn,
            end,
        })
    }

    pub(super) fn effect<'a>(&'a self, core: &'a Core) -> Option<Effect<'a>> {
        match &self.phase {
            CommitPhase::Reserve(deciding) => deciding.effect(core),
            CommitPhase::Contend(gathering) => gathering.effect(),
            CommitPhase::Help(helping) => helping.effect(core),
            CommitPhase::Refresh(refreshing) => refreshing.effect(core),
            CommitPhase::Entries(writing) | CommitPhase::Creation(writing) | CommitPhase::Void(writing) => {
                writing.effect(core)
            }
            CommitPhase::Commit => self
                .proposal
                .as_ref()
                .map(|proposal| Effect::Commit(proposal, core.instance)),
            CommitPhase::Release(committing) => committing.effect(core),
            CommitPhase::Begin | CommitPhase::Check | CommitPhase::Result(_) | CommitPhase::Done => None,
        }
    }

    pub(super) fn give(&mut self, core: &mut Core, output: Output) -> Result<(), Error> {
        match &mut self.phase {
            CommitPhase::Reserve(deciding) => deciding.give(output),
            CommitPhase::Contend(gathering) => gathering.give(output),
            CommitPhase::Help(helping) => helping.give(core, output),
            CommitPhase::Refresh(refreshing) => refreshing.give(core, output),
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
            CommitPhase::Release(committing) => committing.give(core, output),
            CommitPhase::Begin | CommitPhase::Check | CommitPhase::Result(_) | CommitPhase::Done => Err(Error::Binding),
        }
    }

    pub(super) fn settle(&mut self, core: &mut Core) -> Settled {
        loop {
            let pending = match &mut self.phase {
                CommitPhase::Help(helping) => !helping.settle(core)?,
                _ => self.effect(core).is_some(),
            };
            if pending {
                return Ok(None);
            }
            let operation = self.operation.id.clone();
            self.phase = match mem::replace(&mut self.phase, CommitPhase::Done) {
                CommitPhase::Begin => self.reserve(core)?,
                CommitPhase::Reserve(deciding) => match deciding.result.ok_or(Error::Binding)? {
                    Commit::Accepted => {
                        self.owned = true;
                        self.checking(core)
                    }
                    Commit::Conflict => {
                        let turn = self.turn.as_ref().ok_or(Error::Binding)?;
                        let keys = turn.keys.iter().cloned().chain([outcome_key(&operation)]);
                        CommitPhase::Contend(Gathering::new(keys))
                    }
                    _ => return Err(Error::Binding),
                },
                CommitPhase::Contend(gathering) => {
                    if let Some(record) = gathering.get(&outcome_key(&operation)) {
                        // The store has the outcome of the identity: a second submission, or a closure.
                        let stored = outcome_of(&operation, record).ok_or(Error::Record)?;
                        return Ok(Some(Some(Answer::Outcome(stored.answer(&self.operation)))));
                    }
                    let turn = self.turn.as_ref().ok_or(Error::Binding)?;
                    match turn.keys.iter().find_map(|key| gathering.get(key)) {
                        None => self.again(core)?,
                        Some(record) => {
                            let held = Turn::read(record, core.limits).ok_or(Error::Record)?;
                            if Some(&held.attempt) == self.turn.as_ref().map(|turn| &turn.attempt) {
                                // A reservation of this commit landed before its reply was lost.
                                self.owned = true;
                                self.checking(core)
                            } else {
                                CommitPhase::Help(Box::new(Helping::new(held, self.time, false)))
                            }
                        }
                    }
                }
                CommitPhase::Help(helping) => {
                    if helping.helped() {
                        self.again(core)?
                    } else {
                        return Ok(Some(Some(Answer::Outcome(Outcome::Conflict))));
                    }
                }
                CommitPhase::Refresh(_) => CommitPhase::Check,
                CommitPhase::Check => self.check(core)?,
                CommitPhase::Entries(writing) => {
                    if writing.fenced {
                        // A helper retired the turn of the change and voided it.
                        self.outcome = Some(Outcome::Refused(transition::Error::Closed));
                        self.answer = self.outcome.take();
                        self.releasing(core)?
                    } else {
                        self.end = core
                            .history
                            .entries()
                            .iter()
                            .rev()
                            .find(|entry| entry.operation == operation && matches!(entry.body, Body::End(_)))
                            .map(|entry| entry.sequence);
                        CommitPhase::Commit
                    }
                }
                CommitPhase::Commit => CommitPhase::Commit,
                CommitPhase::Result(Commit::Accepted) => {
                    self.outcome = self
                        .proposal
                        .take()
                        .map(|proposal| Outcome::Accepted(proposal.accept()));
                    self.turn = self.turn.take().map(|turn| turn.with(TurnPhase::Made));
                    if core.journal && !self.entries.creation.is_empty() {
                        // The acknowledgement waits for the creation entry.
                        let body = Body::Creation(self.entries.creation.clone());
                        CommitPhase::Creation(Writing::new(core, [(operation, Pending::Body(body))])?)
                    } else {
                        self.answer = self.outcome.take();
                        self.releasing(core)?
                    }
                }
                CommitPhase::Creation(_) | CommitPhase::Void(_) => {
                    self.answer = self.outcome.take();
                    self.releasing(core)?
                }
                CommitPhase::Result(result) => {
                    self.outcome = Some(match result {
                        Commit::Recorded(stored) => stored.answer(&self.operation),
                        Commit::Superseded => return Err(Error::Superseded),
                        Commit::Expired => Outcome::Refused(transition::Error::Expired),
                        Commit::Full => Outcome::Refused(transition::Error::Full),
                        Commit::Conflict | Commit::Accepted => Outcome::Conflict,
                    });
                    match self.end {
                        // The commit wrote nothing, so the void of the end entry comes before the answer.
                        Some(end) => {
                            CommitPhase::Void(Writing::new(core, [(operation, Pending::Body(Body::Void(end)))])?)
                        }
                        None => {
                            self.answer = self.outcome.take();
                            self.releasing(core)?
                        }
                    }
                }
                CommitPhase::Release(_) | CommitPhase::Done => {
                    return Ok(Some(self.answer.take().map(Answer::Outcome)));
                }
            };
        }
    }

    /// The reservation of the owner turns of an anchor change, or the check of another commit.
    fn reserve(&mut self, core: &mut Core) -> Result<CommitPhase, Error> {
        let Some(turn) = &self.turn else {
            return Ok(self.checking(core));
        };
        let proposal = turn::reserve(turn, core.now, core.limits).ok_or(Error::Record)?;
        self.reserving = true;
        Ok(CommitPhase::Reserve(Deciding::new(proposal)))
    }

    /// The next reservation after a peer released or retired a turn, or a conflict after [`TURN_ROUNDS`] of them.
    fn again(&mut self, core: &mut Core) -> Result<CommitPhase, Error> {
        self.rounds = self.rounds.saturating_add(1);
        if self.rounds > TURN_ROUNDS {
            self.answer = Some(Outcome::Conflict);
            return Ok(CommitPhase::Done);
        }
        self.reserve(core)
    }

    /// The check, after the journal entries of the peers when the check reads the journal.
    fn checking(&self, core: &Core) -> CommitPhase {
        if core.journal && (self.owned || self.fresh) {
            CommitPhase::Refresh(Refreshing::default())
        } else {
            CommitPhase::Check
        }
    }

    /// The last-anchor check, and the check of each new record of a kind whose keys repeat against the facts of the
    /// journal. Then the end entry, or the commit.
    fn check(&mut self, core: &mut Core) -> Result<CommitPhase, Error> {
        let empty = journal::State::default();
        let state = if core.journal { core.history.state()? } else { &empty };
        if !journal::keeps_anchor(&self.entries, &self.held, state)? {
            self.answer = Some(Outcome::Refused(transition::Error::LastAnchor));
            return self.releasing(core);
        }
        if self.fresh {
            let proposal = self.proposal.as_ref().ok_or(Error::Binding)?;
            let mut obsolete = None;
            for change in proposal.changes() {
                if let Change::Write { key, version, .. } = change
                    && Kind::of(key).is_some_and(|kind| kind.repeats())
                    && proposal.dependencies().contains(&Dependency::Absent(key.clone()))
                    && state.ends(key, version)?
                {
                    let dead = state
                        .facts()
                        .find(|fact| fact.key == *key)
                        .and_then(|fact| value(&fact.version));
                    obsolete = Some(dead.unwrap_or(0).max(obsolete.unwrap_or(0)));
                }
            }
            if let Some(dead) = obsolete {
                // A peer gave the key a later version before its end: a new allocation goes above it.
                core.counter.skip(dead);
                self.answer = Some(Outcome::Conflict);
                return self.releasing(core);
            }
        }
        match &self.entries.end {
            Some(end) if core.journal => {
                self.ending = true;
                let operation = self.operation.id.clone();
                let guard = match &self.turn {
                    Some(turn) => Guard {
                        key: turn.keys.first().cloned().ok_or(Error::Record)?,
                        version: Some(turn.version()),
                    },
                    None => Guard {
                        key: outcome_key(&operation),
                        version: None,
                    },
                };
                Ok(CommitPhase::Entries(Writing::guarded(
                    core,
                    operation,
                    end.clone(),
                    guard,
                )?))
            }
            _ => Ok(CommitPhase::Commit),
        }
    }

    /// The release of the owner turns and of the journal intent, or the end when the commit holds neither.
    fn releasing(&mut self, core: &mut Core) -> Result<CommitPhase, Error> {
        let made = self.turn.as_ref().is_some_and(|turn| turn.phase == TurnPhase::Made);
        let intents: Vec<(Key, AuthorityVersion)> = self.intent.iter().filter(|_| made).cloned().collect();
        match &self.turn {
            Some(turn) if self.owned => {
                let id = core.operation();
                let proposal = turn::release(id, turn, &intents, core.now, core.limits).ok_or(Error::Record)?;
                Ok(CommitPhase::Release(Committing::skipping([proposal])))
            }
            _ => match intents.first() {
                Some((key, version)) => Ok(CommitPhase::Release(Committing::skipping([release(
                    core, key, version,
                )?]))),
                None => Ok(CommitPhase::Done),
            },
        }
    }
}
