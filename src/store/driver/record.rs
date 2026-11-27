//! The records that the driver writes: the mark record ([`Kind::Mark`]) and the replay floor ([`Kind::ReplayFloor`]),
//! and the proposals of the driver's own commits.

use alloc::boxed::Box;
use alloc::collections::BTreeMap;
use alloc::vec;
use alloc::vec::Vec;
use core::time::Duration;

use crate::cbor::{self, Value};
use crate::id::{AuthorityVersion, Id, Principal};
use crate::limits::Limits;
use crate::store::journal::{Link, Mark};
use crate::store::{Instance, Kind, Record, Sequence, audit_record, floor_key};
use crate::time::{Reading, ReadingSource};
use crate::transition::{Audit, Change, Dependency, Key, OperationId, Proposal};

/// The first item of the CBOR form of the mark record. Its number changes with the form.
const FORM: &str = "rsauthnz.store.mark.1";

/// The action of the commit that writes the mark record.
pub(super) const MARK: &str = "store.mark";
/// The action of the commit that writes the replay floor record.
pub(super) const REPLAY_FLOOR: &str = "store.replay-floor";
/// The action of the commit that ends a journal intent.
pub(super) const INTENT: &str = "store.intent";
/// The action of a commit of a restore, and of a completion.
pub(super) const RESTORE: &str = "store.restore";

/// The most bytes in a record that the driver writes for itself within `limits`. The driver reads its mark record
/// back within `limits`, and the anchors of a restore and of a completion come from journal entries within `limits`,
/// so each of them is at most `limits.bytes`. The replay floor and each outcome record are shorter than any audit
/// record. The audit record of a commit of the driver holds the key of each of at most `limits.dependencies`
/// changes: each key adds at most its bytes and a header of 3 bytes, and the header of the array grows by at most 8.
pub(super) fn bytes_max(limits: Limits) -> usize {
    let id = OperationId::new(&[0; 32]).expect("an identity of 32 bytes is valid");
    // The longest time form: each part of each duration takes its widest CBOR head.
    let now = Reading::new(Duration::MAX, Some(Duration::MAX), ReadingSource::Caller);
    let base = [MARK, REPLAY_FLOOR, INTENT, RESTORE]
        .map(|action| {
            audit_record(&proposal(id.clone(), action, now, Limits::default()))
                .1
                .data
                .len()
        })
        .into_iter()
        .max()
        .unwrap_or(0);
    let keys = limits.dependencies.saturating_mul(Key::BYTES_MAX.saturating_add(3));
    limits.bytes.max(base.saturating_add(8).saturating_add(keys))
}

/// The state of the mark record.
#[derive(Clone, Debug, PartialEq, Eq)]
pub(super) struct State {
    /// The version of the record, or `None` before its first write.
    pub(super) version: Option<AuthorityVersion>,
    /// The low-water mark of the store state.
    pub(super) mark: Mark,
    /// A restore made the store state, so a missing outcome record is unknown.
    pub(super) restored: bool,
    /// The number of this write of the record. After each write, the driver appends a floor entry of
    /// [`Kind::Mark`] with it, so a journal with a higher number shows a store state older than its journal.
    pub(super) written: u64,
    /// The sequences of the consumption entries that a restore still completes.
    pub(super) owed: Vec<Sequence>,
    /// The floor of each counter, for a binding with no journal.
    pub(super) floors: BTreeMap<Kind, u64>,
}

impl Default for State {
    fn default() -> Self {
        Self {
            version: None,
            mark: Mark::EMPTY,
            restored: false,
            written: 0,
            owed: Vec::new(),
            floors: BTreeMap::new(),
        }
    }
}

/// The key of the mark record.
pub(super) fn mark_key() -> Key {
    Kind::Mark.key(&[]).expect("a key of one byte is valid")
}

impl State {
    /// The state of the stored mark record, or `None` for another form within `limits`.
    pub(super) fn read(record: &Record, limits: Limits) -> Option<Self> {
        let Value::Array(items) = cbor::decode(&record.data, limits).ok()? else {
            return None;
        };
        let [
            Value::Text(FORM),
            Value::Unsigned(sequence),
            Value::Bytes(link),
            Value::Bool(restored),
            Value::Unsigned(written),
            Value::Array(owed),
            Value::Array(floors),
        ] = items.as_slice()
        else {
            return None;
        };
        let owed = owed
            .iter()
            .map(|item| match item {
                Value::Unsigned(sequence) => Some(Sequence(*sequence)),
                _ => None,
            })
            .collect::<Option<_>>()?;
        let floors = floors
            .iter()
            .map(|item| match item {
                Value::Array(pair) => match pair.as_slice() {
                    [Value::Unsigned(kind), Value::Unsigned(value)] => {
                        let kind = Kind::ALL
                            .into_iter()
                            .find(|candidate| u64::from(*candidate as u8) == *kind)?;
                        Some((kind, *value))
                    }
                    _ => None,
                },
                _ => None,
            })
            .collect::<Option<_>>()?;
        Some(Self {
            version: Some(record.version.clone()),
            mark: Mark {
                sequence: Sequence(*sequence),
                link: Link(<[u8; 32]>::try_from(*link).ok()?),
            },
            restored: *restored,
            written: *written,
            owed,
            floors,
        })
    }

    /// The commit that writes `self` as the next version of the mark record, with the operation `id` at `now`, or
    /// `None` when `limits` admit no dependency, when the form is longer than `limits.bytes`, or when the stored
    /// version is not a version of the driver. `self` takes the new version, so the next write follows this one.
    pub(super) fn write(&mut self, id: OperationId, now: Reading, limits: Limits) -> Option<Proposal> {
        let form = Value::Array(vec![
            Value::Text(FORM),
            Value::Unsigned(self.mark.sequence.0),
            Value::Bytes(&self.mark.link.0),
            Value::Bool(self.restored),
            Value::Unsigned(self.written),
            Value::Array(self.owed.iter().map(|sequence| Value::Unsigned(sequence.0)).collect()),
            Value::Array(
                self.floors
                    .iter()
                    .map(|(kind, value)| {
                        Value::Array(vec![Value::Unsigned(u64::from(*kind as u8)), Value::Unsigned(*value)])
                    })
                    .collect(),
            ),
        ]);
        // The driver reads the record back within `limits`, and `bytes_max` counts on it.
        let data = cbor::encode(&form, limits).ok()?;
        let (proposal, version) = replace(
            id,
            MARK,
            now,
            limits,
            &mark_key(),
            self.version.as_ref(),
            data.into_boxed_slice(),
        )?;
        self.version = Some(version);
        Some(proposal)
    }
}

/// A replay floor: the reading of the start or the restore that set it, and the store instance number of the start
/// that wrote it. A replay insert of another instance refuses ([`Insert::admits`](crate::store::Insert::admits)), so
/// no insert lands between a start and the write of its floor.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) struct Floor {
    /// The estimate of the reading.
    pub(crate) estimate: Duration,
    /// The bound of the reading, or `None` when it is unknown.
    pub(crate) bound: Option<Duration>,
    /// The store instance number of the start that wrote the floor.
    pub(crate) instance: Instance,
}

impl Floor {
    /// The floor of the record form `data`, or `None` for another form.
    pub(crate) fn read(data: &[u8]) -> Option<Self> {
        let duration = |value: &Value<'_>| match value {
            Value::Array(parts) => match parts.as_slice() {
                [Value::Unsigned(seconds), Value::Unsigned(nanos)] => Some(Duration::new(
                    *seconds,
                    u32::try_from(*nanos).ok().filter(|&nanos| nanos < 1_000_000_000)?,
                )),
                _ => None,
            },
            _ => None,
        };
        let Ok(Value::Array(items)) = cbor::decode(data, Limits::default()) else {
            return None;
        };
        let [estimate, bound, Value::Unsigned(instance)] = items.as_slice() else {
            return None;
        };
        let bound = match bound {
            Value::Null => None,
            bound => Some(duration(bound)?),
        };
        Some(Self {
            estimate: duration(estimate)?,
            bound,
            instance: Instance(*instance),
        })
    }

    /// The time after which a value that the floor admits was created: the estimate plus twice the bound. `None` for
    /// an unknown bound, which admits no value.
    pub(crate) fn end(&self) -> Option<Duration> {
        self.estimate.checked_add(self.bound?.checked_mul(2)?)
    }

    /// The record form: the CBOR array `[estimate, bound, instance]`, each time as `[seconds, nanoseconds]` and the bound
    /// `null` when it is unknown.
    fn form(&self) -> Vec<u8> {
        let duration = |duration: Duration| {
            Value::Array(vec![
                Value::Unsigned(duration.as_secs()),
                Value::Unsigned(u64::from(duration.subsec_nanos())),
            ])
        };
        let form = Value::Array(vec![
            duration(self.estimate),
            self.bound.map_or(Value::Null, duration),
            Value::Unsigned(self.instance.0),
        ]);
        cbor::encode(&form, Limits::FORM).expect("the floor form has no map and no simple value")
    }
}

/// The time after which a value that the replay floor record `data` admits was created ([`Floor::end`]). `None` if the
/// floor has an unknown bound, which admits no value, or no valid form.
pub(crate) fn floor_end(data: &[u8]) -> Option<Duration> {
    Floor::read(data)?.end()
}

/// The commit at `now` that writes the replay floor record `floor` in place of the record at `version`. A replay
/// insert refuses each signature whose `created` is not later than the reading of the floor plus the skew and twice the
/// bound. `None` as for [`State::write`].
pub(super) fn replay_floor(
    id: OperationId,
    now: Reading,
    floor: Floor,
    limits: Limits,
    version: Option<&AuthorityVersion>,
) -> Option<Proposal> {
    replace(
        id,
        REPLAY_FLOOR,
        now,
        limits,
        &floor_key(),
        version,
        floor.form().into_boxed_slice(),
    )
    .map(|(proposal, _)| proposal)
}

/// The audit of the driver's own commit of the action `action` at `now`.
pub(super) fn audit(action: &str, now: Reading) -> Audit {
    Audit {
        actor: Principal::Workload(Id::new("rsauthnz", "driver").expect("the driver identifier is valid")),
        action: Id::new("rsauthnz", action).expect("each action of the driver is a valid identifier"),
        time: now,
    }
}

/// The proposal of the driver's own commit `id` of the action `action` at `now`, with no change yet.
pub(super) fn proposal(id: OperationId, action: &str, now: Reading, limits: Limits) -> Proposal {
    Proposal::new(id, audit(action, now), &Value::Null, limits).expect("a null request has a CBOR encoding")
}

/// The driver's commit that writes `data` at the version after `version` of the record `key` of the driver, and that
/// version. The coordinate of a version of the driver is a counter of eight bytes.
fn replace(
    id: OperationId,
    action: &str,
    now: Reading,
    limits: Limits,
    key: &Key,
    version: Option<&AuthorityVersion>,
    data: Box<[u8]>,
) -> Option<(Proposal, AuthorityVersion)> {
    let counter = match version {
        None => 0,
        Some(version) => u64::from_be_bytes(version.coordinate().try_into().ok()?),
    };
    let next = AuthorityVersion::new(owner(), &counter.checked_add(1)?.to_be_bytes()).ok()?;
    let mut proposal = proposal(id, action, now, limits);
    let read = match version {
        Some(version) => Dependency::Version(key.clone(), version.clone()),
        None => Dependency::Absent(key.clone()),
    };
    proposal.read(read).ok()?;
    proposal
        .change(Change::Write {
            key: key.clone(),
            version: next.clone(),
            end: None,
            data,
        })
        .ok()?;
    Some((proposal, next))
}

/// The owner of the versions of the driver's records.
fn owner() -> Id<crate::id::Authority> {
    Id::new("rsauthnz", "driver").expect("the driver identifier is valid")
}
