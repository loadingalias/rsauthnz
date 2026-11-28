//! Owner turns: the record of each owner of anchors that an anchor change holds ([`Kind::Turn`]).
//!
//! A reservation writes the held turn of each owner in one commit. The commit of the anchor change reads each turn at
//! its held version and writes it at its made version, so a helper that retires the held turn fences that commit.
//! Each phase of each attempt has its own version, also for two attempts of one operation, so no later turn takes the
//! version of an earlier one, and a delayed commit that read a released turn refuses.

use alloc::boxed::Box;
use alloc::vec;
use alloc::vec::Vec;
use core::time::Duration;

use super::record;
use crate::cbor::{self, Value};
use crate::crypto;
use crate::id::{AuthorityVersion, Id};
use crate::limits::Limits;
use crate::store::{Kind, Record};
use crate::time::Reading;
use crate::transition::{Change, Dependency, Key, OperationId, Proposal};

/// The first item of the CBOR form of a turn record. Its number changes with the form.
const FORM: &str = "rsauthnz.store.turn.1";

/// The phase of the anchor change that holds a turn.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(super) enum Phase {
    /// The change holds the turn, and its commit can still land.
    Held = 0,
    /// The change committed. Its creation entry and the release of the turn follow.
    Made = 1,
    /// A helper fenced the commit. The void of the change and the release of the turn follow.
    Retired = 2,
}

/// The turn record of the anchor change `operation`.
#[derive(Clone, Debug, PartialEq, Eq)]
pub(super) struct Turn {
    pub(super) operation: OperationId,
    /// The identity of this attempt of the change: the identity of its reservation. A change that a conflict
    /// refused can submit its operation again.
    pub(super) attempt: OperationId,
    pub(super) phase: Phase,
    /// The latest time of the audit reading of the change. A peer helps a held turn only after it and
    /// [`TURN_PATIENCE`](super::TURN_PATIENCE).
    pub(super) time: Duration,
    /// The turn key of each owner of the change, in key order.
    pub(super) keys: Vec<Key>,
}

/// The version of the turn records of the attempt `attempt` in `phase`: the phase, then the SHA-256 digest of the
/// identity of the attempt. A later phase of one attempt has a greater version.
pub(super) fn version(attempt: &OperationId, phase: Phase) -> AuthorityVersion {
    let mut coordinate = [0; 33];
    coordinate[0] = phase as u8;
    coordinate[1..].copy_from_slice(&crypto::sha256(attempt.as_bytes()));
    AuthorityVersion::new(owner(), &coordinate).expect("a coordinate of 33 bytes is valid")
}

/// The owner of the versions of turn records.
fn owner() -> Id<crate::id::Authority> {
    Id::new("rsauthnz", "turn").expect("the turn identifier is valid")
}

impl Turn {
    /// The same turn in `phase`.
    pub(super) fn with(&self, phase: Phase) -> Self {
        Self { phase, ..self.clone() }
    }

    /// The version of the record of this turn.
    pub(super) fn version(&self) -> AuthorityVersion {
        version(&self.attempt, self.phase)
    }

    /// The record form: the CBOR array `[form, operation, attempt, phase, [seconds, nanoseconds], keys]`.
    pub(super) fn form(&self) -> Box<[u8]> {
        let form = Value::Array(vec![
            Value::Text(FORM),
            Value::Bytes(self.operation.as_bytes()),
            Value::Bytes(self.attempt.as_bytes()),
            Value::Unsigned(self.phase as u64),
            Value::Array(vec![
                Value::Unsigned(self.time.as_secs()),
                Value::Unsigned(u64::from(self.time.subsec_nanos())),
            ]),
            Value::Array(self.keys.iter().map(|key| Value::Bytes(key.as_bytes())).collect()),
        ]);
        cbor::encode(&form, Limits::FORM)
            .expect("the turn form has no map and no simple value")
            .into_boxed_slice()
    }

    /// The turn of the stored record `record`, or `None` for another form, or for a version that is not the version of
    /// its phase.
    pub(super) fn read(record: &Record, limits: Limits) -> Option<Self> {
        let Value::Array(items) = cbor::decode(&record.data, limits).ok()? else {
            return None;
        };
        let [
            Value::Text(FORM),
            Value::Bytes(operation),
            Value::Bytes(attempt),
            Value::Unsigned(phase),
            Value::Array(time),
            Value::Array(keys),
        ] = items.as_slice()
        else {
            return None;
        };
        let phase = match phase {
            0 => Phase::Held,
            1 => Phase::Made,
            2 => Phase::Retired,
            _ => return None,
        };
        let [Value::Unsigned(seconds), Value::Unsigned(nanos)] = time.as_slice() else {
            return None;
        };
        let nanos = u32::try_from(*nanos).ok().filter(|&nanos| nanos < 1_000_000_000)?;
        let keys = keys
            .iter()
            .map(|key| match key {
                Value::Bytes(bytes) => Key::new(bytes).ok(),
                _ => None,
            })
            .collect::<Option<Vec<_>>>()?;
        let turn = Self {
            operation: OperationId::new(operation).ok()?,
            attempt: OperationId::new(attempt).ok()?,
            phase,
            time: Duration::new(*seconds, nanos),
            keys,
        };
        (record.version == turn.version()).then_some(turn)
    }

    /// The guard of each owner of the commit of the change: the read of its held turn and the write of its made turn.
    pub(super) fn guard(&self, proposal: &mut Proposal) {
        let made = self.with(Phase::Made);
        for key in &self.keys {
            proposal.guard(key.clone(), self.version(), made.version(), made.form());
        }
    }
}

/// The reservation at `now`, whose identity is the attempt: one commit that writes the held turn of each owner. It
/// reads the absence of each turn and of the outcome record of the change, so a closure of the change fences it too.
pub(super) fn reserve(turn: &Turn, now: Reading, limits: Limits) -> Option<Proposal> {
    let mut proposal = record::proposal(turn.attempt.clone(), record::TURN, now, limits);
    let outcome = Kind::Outcome.key(turn.operation.as_bytes()).ok()?;
    proposal.read(Dependency::Absent(outcome)).ok()?;
    for key in &turn.keys {
        proposal.read(Dependency::Absent(key.clone())).ok()?;
        proposal
            .change(Change::Write {
                key: key.clone(),
                version: turn.version(),
                end: None,
                data: turn.form(),
            })
            .ok()?;
    }
    Some(proposal)
}

/// The retirement `id` at `now` of the held `turn`: each owner turn goes from held to retired, so the commit of the
/// change refuses.
pub(super) fn retire(id: OperationId, turn: &Turn, now: Reading, limits: Limits) -> Option<Proposal> {
    let retired = turn.with(Phase::Retired);
    let mut proposal = record::proposal(id, record::TURN, now, limits);
    for key in &turn.keys {
        proposal.read(Dependency::Version(key.clone(), turn.version())).ok()?;
        proposal
            .change(Change::Write {
                key: key.clone(),
                version: retired.version(),
                end: None,
                data: retired.form(),
            })
            .ok()?;
    }
    Some(proposal)
}

/// The release `id` at `now` of `turn` in its phase, with the end of each journal intent of `intents` at its version.
pub(super) fn release(
    id: OperationId,
    turn: &Turn,
    intents: &[(Key, AuthorityVersion)],
    now: Reading,
    limits: Limits,
) -> Option<Proposal> {
    let mut proposal = record::proposal(id, record::TURN, now, limits);
    let held = turn.keys.iter().map(|key| (key, turn.version()));
    for (key, version) in held.chain(intents.iter().map(|(key, version)| (key, version.clone()))) {
        proposal.read(Dependency::Version(key.clone(), version)).ok()?;
        proposal.change(Change::End(key.clone())).ok()?;
    }
    Some(proposal)
}
