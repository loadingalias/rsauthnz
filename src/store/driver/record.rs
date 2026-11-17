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
use crate::store::{Kind, Record, Sequence};
use crate::time::Reading;
use crate::transition::{Audit, Change, Dependency, Key, OperationId, Proposal};

/// The first item of the CBOR form of the mark record. Its number changes with the form.
const FORM: &str = "rsauthnz.store.mark.1";

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

/// The key of the replay floor record.
pub(super) fn floor_key() -> Key {
    Kind::ReplayFloor.key(&[]).expect("a key of one byte is valid")
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
    /// `None` when `limits` admit no dependency or the stored version is not a version of the driver. `self` takes
    /// the new version, so the next write follows this one.
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
        let data = cbor::encode(&form).expect("the mark form has no map and no simple value");
        let (proposal, version) = replace(
            id,
            "store.mark",
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

/// The commit that writes the replay floor record: the reading `now` of a start or a restore, as the CBOR array
/// `[estimate, bound]`, each as `[seconds, nanoseconds]` and the bound `null` when it is unknown. A replay insert
/// refuses each signature whose `created` is not later than this reading plus the skew and twice the bound. `None` as
/// for [`State::write`].
pub(super) fn replay_floor(
    id: OperationId,
    now: Reading,
    limits: Limits,
    version: Option<&AuthorityVersion>,
) -> Option<Proposal> {
    let duration = |duration: Duration| {
        Value::Array(vec![
            Value::Unsigned(duration.as_secs()),
            Value::Unsigned(u64::from(duration.subsec_nanos())),
        ])
    };
    let form = Value::Array(vec![
        duration(now.estimate()),
        now.bound().map_or(Value::Null, duration),
    ]);
    let data = cbor::encode(&form).expect("the floor form has no map and no simple value");
    replace(
        id,
        "store.replay-floor",
        now,
        limits,
        &floor_key(),
        version,
        data.into_boxed_slice(),
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
