use alloc::collections::BTreeMap;
use alloc::vec;
use alloc::vec::Vec;
use core::assert_matches;
use core::num::NonZeroUsize;
use core::pin::pin;
use core::task::{Context, Poll, Waker};
use core::time::Duration;

use super::{
    Capacity, Commit, CrashInjection, CrashLoss, Declaration, Error, ExpiryError, Insert, Inserted, Instance,
    Isolation, Kind, Profile, Progress, Record, Restore, Store, audit_record, expire, intent_records, outcome_record,
};
use crate::cbor::{self, Value};
use crate::id::{AuthorityVersion, Human, Id, Principal};
use crate::limits::Limits;
use crate::time::{Reading, ReadingSource, TimeError};
use crate::transition::{Audit, Change, Dependency, Effect, Intent, Key, OperationId, Proposal};

/// The output of a future that is ready at once, as each future of the harness binding is.
fn ready<F: Future>(future: F) -> F::Output {
    match pin!(future).poll(&mut Context::from_waker(Waker::noop())) {
        Poll::Ready(output) => output,
        Poll::Pending => panic!("the harness binding does no I/O"),
    }
}

fn reading(seconds: u64) -> Reading {
    Reading::new(
        Duration::from_secs(seconds),
        Some(Duration::from_secs(1)),
        ReadingSource::Caller,
    )
}

fn declaration() -> Declaration {
    Declaration {
        isolation: Isolation::Serializable,
        crash_loss: CrashLoss::Unsynced,
        outcome_retention: Duration::from_secs(86_400),
        crash_injection: CrashInjection::Unsupported,
        restore: Restore::Unsupported,
        key_bytes_max: Key::BYTES_MAX,
        signatures: Capacity {
            records_max: 2,
            share_max: 1,
        },
        record_bytes_max: 4,
    }
}

/// A binding with snapshot isolation permits write skew on an absence, one with a smaller key bound cannot store each
/// key of the core, and one whose share of signature records is empty or larger than its capacity refuses each
/// signature or lets one agent fill the store. The profile refuses each at its construction.
#[test]
fn a_declaration_without_an_atomic_commit_refuses_its_profile() {
    for isolation in [Isolation::Serializable, Isolation::AtomicConditional] {
        Profile::new(Declaration {
            isolation,
            ..declaration()
        })
        .unwrap();
    }
    assert_eq!(
        Profile::new(Declaration {
            isolation: Isolation::Weaker,
            ..declaration()
        }),
        Err(Error::Isolation)
    );
    assert_eq!(
        Profile::new(Declaration {
            key_bytes_max: Key::BYTES_MAX - 1,
            ..declaration()
        }),
        Err(Error::KeyBound)
    );
    for (records_max, share_max) in [(2, 0), (2, 3)] {
        assert_eq!(
            Profile::new(Declaration {
                signatures: Capacity { records_max, share_max },
                ..declaration()
            }),
            Err(Error::Capacity),
            "{share_max} of {records_max}"
        );
    }
}

/// The bound of the binding applies to each record that the commit writes, before the commit: the record form of a
/// write, an intent record, and the audit record, which holds the key of each change. A proposal admits at the bound
/// of its longest stored record, and refuses one byte below it.
#[test]
fn a_record_over_the_bound_of_the_binding_refuses_before_the_commit() {
    let profile = |bytes| {
        Profile::new(Declaration {
            record_bytes_max: bytes,
            ..declaration()
        })
        .unwrap()
    };
    let audit = Audit {
        actor: Principal::Human(Id::<Human>::new("acme", "u-17").unwrap()),
        action: Id::new("acme.auth", "credential.enroll").unwrap(),
        time: reading(1_000),
    };
    let version = AuthorityVersion::new(Id::new("acme", "auth").unwrap(), &[1]).unwrap();
    // Each proposal writes one record of `data`, one more key for each of `keys`, and one intent of `payload`.
    let proposal = |data: usize, keys: u8, payload: usize| {
        let mut proposal = Proposal::new(
            OperationId::new(b"op-1").unwrap(),
            audit.clone(),
            &Value::Null,
            Limits::default(),
        )
        .unwrap();
        for index in 0..=keys {
            let id = [index; 1_000];
            let key = Kind::Credential.key(if index == 0 { b"c-4" } else { &id[..] }).unwrap();
            proposal.read(Dependency::Absent(key.clone())).unwrap();
            let data = if index == 0 { vec![0; data] } else { Vec::new() };
            proposal
                .change(Change::Write {
                    key,
                    version: version.clone(),
                    end: None,
                    data: data.into(),
                })
                .unwrap();
        }
        proposal
            .intend(Intent::new(Effect::Notification, vec![0; payload].into()))
            .unwrap();
        proposal
    };
    // The longest record is the write, the intent record, and the audit record, in this order.
    for (proposal, longest) in [
        (proposal(4_000, 0, 10), Kind::Credential),
        (proposal(10, 0, 4_000), Kind::Intent),
        (proposal(10, 3, 10), Kind::Audit),
    ] {
        let mut stored: Vec<(Key, usize)> = [audit_record(&proposal), outcome_record(&proposal)]
            .into_iter()
            .chain(intent_records(&proposal).unwrap())
            .map(|(key, record)| (key, record.data.len()))
            .collect();
        for change in proposal.changes() {
            if let Change::Write { key, data, .. } = change {
                stored.push((key.clone(), data.len()));
            }
        }
        let (key, bytes) = stored.into_iter().max_by_key(|(_, bytes)| *bytes).unwrap();
        assert_eq!(Kind::of(&key), Some(longest));
        assert_eq!(profile(bytes).admit(&proposal), Ok(()), "{longest:?}");
        assert_eq!(
            profile(bytes - 1).admit(&proposal),
            Err(Error::RecordBytes),
            "{longest:?}"
        );
    }
}

/// A key names its kind, so the records of two kinds with the same identifier never meet.
#[test]
fn the_keys_of_two_kinds_with_the_same_id_differ() {
    let keys: Vec<Key> = Kind::ALL.into_iter().map(|kind| kind.key(b"u-17").unwrap()).collect();
    for (kind, key) in Kind::ALL.into_iter().zip(&keys) {
        assert_eq!(Kind::of(key), Some(kind));
        assert_eq!(keys.iter().filter(|other| *other == key).count(), 1, "{kind:?}");
    }
    assert_eq!(Kind::of(&Key::new(b"\0u-17").unwrap()), None);
    assert_eq!(
        Kind::Session.key(&[0; Key::BYTES_MAX]),
        Err(crate::transition::Error::Key)
    );
}

/// The records of a binding with their ends, and the expiry calls that it received.
struct Ended {
    records: Vec<(Kind, Duration)>,
    calls: Vec<(Kind, Duration, usize)>,
}

impl Store for Ended {
    type Error = !;

    fn declaration(&self) -> Declaration {
        declaration()
    }

    async fn start(&mut self) -> Result<Instance, !> {
        Ok(Instance(1))
    }

    async fn read(&mut self, _: &Key) -> Result<Option<Record>, !> {
        Ok(None)
    }

    async fn read_pair(&mut self, _: [&Key; 2]) -> Result<[Option<Record>; 2], !> {
        Ok([None, None])
    }

    async fn commit(&mut self, _: &Proposal, _: Instance) -> Result<Commit, !> {
        Ok(Commit::Conflict)
    }

    async fn insert_replay(&mut self, _: &Insert) -> Result<Inserted, !> {
        Ok(Inserted::Floor)
    }

    async fn range(&mut self, _: &Key, _: Option<&Key>, _: NonZeroUsize) -> Result<Vec<(Key, Record)>, !> {
        Ok(Vec::new())
    }

    async fn expire(&mut self, kind: Kind, before: Duration, limit: NonZeroUsize) -> Result<usize, !> {
        self.calls.push((kind, before, limit.get()));
        let mut removed = 0;
        self.records.retain(|&(record, end)| {
            let remove = record == kind && end < before && removed < limit.get();
            removed += usize::from(remove);
            !remove
        });
        Ok(removed)
    }
}

/// Each pass makes one call for each kind that can end, and each call removes at most its limit. Five ended sessions need three
/// passes of two. A session that ends at 999.5 seconds stays at a reading of 1,000 ± 1 seconds, because a check can
/// still accept it. A reading with no known bound expires nothing.
#[test]
fn expiry_runs_in_bounded_steps_that_keep_each_record_that_a_check_can_accept() {
    let ended = Duration::from_secs(900);
    let late = Duration::from_millis(999_500);
    let mut store = Ended {
        records: vec![(Kind::Session, ended); 5],
        calls: Vec::new(),
    };
    store.records.push((Kind::Session, late));
    store.records.push((Kind::Credential, ended));
    let limit = NonZeroUsize::new(2).unwrap();

    let mut passes = Vec::new();
    loop {
        let progress = ready(expire(&mut store, reading(1_000), limit)).unwrap();
        passes.push(progress);
        if progress == Progress::Done {
            break;
        }
    }
    assert_eq!(passes, [Progress::More, Progress::More, Progress::Done]);
    let ending = Kind::ALL.into_iter().filter(Kind::ends).count();
    assert_eq!(store.calls.len(), 3 * ending);
    assert!(store.calls.iter().all(|&(kind, ..)| kind.ends()));
    assert!(
        store
            .calls
            .iter()
            .all(|&(_, before, limit)| before == Duration::from_secs(999) && limit == 2)
    );
    assert_eq!(store.records, [(Kind::Session, late)]);

    let unknown = Reading::new(Duration::from_secs(1_000), None, ReadingSource::SystemClock);
    let calls = store.calls.len();
    assert_matches!(
        ready(expire(&mut store, unknown, limit)),
        Err(ExpiryError::Time(TimeError::UnknownBound))
    );
    assert_eq!(store.calls.len(), calls);
}

/// A binding that keeps the intent, audit, and outcome records that its commit writes.
#[derive(Default)]
struct Records(BTreeMap<Key, Record>);

impl Store for Records {
    type Error = !;

    fn declaration(&self) -> Declaration {
        declaration()
    }

    async fn start(&mut self) -> Result<Instance, !> {
        Ok(Instance(1))
    }

    async fn read(&mut self, key: &Key) -> Result<Option<Record>, !> {
        Ok(self.0.get(key).cloned())
    }

    async fn read_pair(&mut self, keys: [&Key; 2]) -> Result<[Option<Record>; 2], !> {
        Ok(keys.map(|key| self.0.get(key).cloned()))
    }

    async fn commit(&mut self, proposal: &Proposal, _: Instance) -> Result<Commit, !> {
        self.0.extend(intent_records(proposal).unwrap());
        self.0.extend([audit_record(proposal), outcome_record(proposal)]);
        Ok(Commit::Accepted)
    }

    async fn insert_replay(&mut self, _: &Insert) -> Result<Inserted, !> {
        Ok(Inserted::Floor)
    }

    async fn range(&mut self, prefix: &Key, after: Option<&Key>, limit: NonZeroUsize) -> Result<Vec<(Key, Record)>, !> {
        let records = self
            .0
            .iter()
            .filter(|(key, _)| key.as_bytes().starts_with(prefix.as_bytes()) && after.is_none_or(|after| *key > after));
        Ok(records
            .take(limit.get())
            .map(|(key, record)| (key.clone(), record.clone()))
            .collect())
    }

    async fn expire(&mut self, _: Kind, _: Duration, _: NonZeroUsize) -> Result<usize, !> {
        Ok(0)
    }
}

/// After a crash, a worker finds the intents of a commit in bounded reads, one after the other. Each record holds the
/// intent, and a commit can change its state: the cancelled intent has a later version than the open one.
#[test]
fn a_worker_reads_the_intents_of_a_commit_in_bounded_passes() {
    let notify = Intent::new(Effect::Notification, Box::new(*b"owner"));
    let sign = Intent::new(Effect::Signer, Box::new(*b"grant"));
    let mut proposal = Proposal::new(
        OperationId::new(b"op-1").unwrap(),
        Audit {
            actor: Principal::Human(Id::<Human>::new("acme", "u-17").unwrap()),
            action: Id::new("acme.auth", "grant.issue").unwrap(),
            time: reading(1_000),
        },
        &Value::Null,
        Limits::default(),
    )
    .unwrap();
    proposal.intend(notify.clone()).unwrap();
    proposal.intend(sign.clone()).unwrap();
    let mut store = Records::default();
    assert_eq!(ready(store.commit(&proposal, Instance(1))), Ok(Commit::Accepted));

    let (intents, limit) = (Kind::Intent.key(&[]).unwrap(), NonZeroUsize::new(1).unwrap());
    let mut found = Vec::new();
    let mut after = None;
    loop {
        let read = ready(store.range(&intents, after.as_ref(), limit)).unwrap();
        assert!(read.len() <= 1);
        let Some((key, record)) = read.into_iter().next() else {
            break;
        };
        let intent = Intent::from_cbor(&cbor::decode(&record.data, Limits::default()).unwrap()).unwrap();
        assert_eq!(record.version, intent.version());
        found.push(intent);
        after = Some(key);
    }
    assert_eq!(found, [notify, sign]);

    let (key, record) = ready(store.range(&intents, None, limit)).unwrap().remove(0);
    let mut cancelled = found.remove(0);
    cancelled.cancel();
    let mut change = Proposal::new(
        OperationId::new(b"op-2").unwrap(),
        proposal.audit().clone(),
        &Value::Null,
        Limits::default(),
    )
    .unwrap();
    change.read(Dependency::Version(key.clone(), record.version)).unwrap();
    change
        .change(Change::Write {
            key,
            version: cancelled.version(),
            end: None,
            data: cbor::encode(&cancelled.to_cbor(), Limits::default()).unwrap().into(),
        })
        .unwrap();
}

/// The commit writes the audit and the outcome as records that `Store::read` finds by the operation identity. The
/// audit form names the actor, the action, the time with its bound and source, and the key of each change, so the
/// application and the conformance suite read the same audit from each binding. A reading with no known bound has a
/// null bound. `Store::outcome` reads the outcome record, and no proposal can change an audit or an outcome record.
#[test]
fn the_commit_writes_the_audit_and_the_outcome_as_records_that_a_keyed_read_finds() {
    let actor = Principal::Human(Id::<Human>::new("acme", "u-17").unwrap());
    let action = Id::new("acme.auth", "credential.enroll").unwrap();
    let version = AuthorityVersion::new(Id::new("acme", "auth").unwrap(), &[1]).unwrap();
    let [credential, invitation] = [Kind::Credential.key(b"c-4"), Kind::Invitation.key(b"i-9")].map(Result::unwrap);
    let readings = [
        Reading::new(
            Duration::new(1_000, 5),
            Some(Duration::from_millis(1_500)),
            ReadingSource::Caller,
        ),
        Reading::new(Duration::new(1_000, 5), None, ReadingSource::SystemClock),
    ];
    let bounds = [
        Value::Array(vec![Value::Unsigned(1), Value::Unsigned(500_000_000)]),
        Value::Null,
    ];
    for ((time, bound), source) in readings.into_iter().zip(bounds).zip([2, 1]) {
        let audit = Audit {
            actor: actor.clone(),
            action: action.clone(),
            time,
        };
        let mut proposal = Proposal::new(
            OperationId::new(b"op-1").unwrap(),
            audit,
            &Value::Null,
            Limits::default(),
        )
        .unwrap();
        proposal
            .read(Dependency::Version(invitation.clone(), version.clone()))
            .unwrap();
        proposal.read(Dependency::Absent(credential.clone())).unwrap();
        proposal.change(Change::End(invitation.clone())).unwrap();
        proposal
            .change(Change::Write {
                key: credential.clone(),
                version: version.clone(),
                end: None,
                data: Box::new(*b"credential"),
            })
            .unwrap();
        let mut store = Records::default();
        assert_eq!(ready(store.commit(&proposal, Instance(1))), Ok(Commit::Accepted));

        let record = ready(store.read(&Kind::Audit.key(b"op-1").unwrap())).unwrap().unwrap();
        assert_eq!(record.end, None);
        let expected = Value::Array(vec![
            Value::Text("rsauthnz.store.audit.2"),
            actor.to_cbor(),
            Value::Null,
            action.to_cbor(),
            Value::Array(vec![
                Value::Array(vec![Value::Unsigned(1_000), Value::Unsigned(5)]),
                bound,
                Value::Unsigned(source),
            ]),
            Value::Array(vec![
                Value::Bytes(invitation.as_bytes()),
                Value::Bytes(credential.as_bytes()),
            ]),
        ]);
        assert_eq!(cbor::decode(&record.data, Limits::default()).unwrap(), expected);
        assert_eq!(
            ready(store.outcome(&proposal.operation().id)),
            Ok(Some(proposal.operation().clone()))
        );
        assert_eq!(ready(store.outcome(&OperationId::new(b"op-2").unwrap())), Ok(None));
    }

    let mut forged = Proposal::new(
        OperationId::new(b"op-3").unwrap(),
        Audit {
            actor,
            action,
            time: reading(1_000),
        },
        &Value::Null,
        Limits::default(),
    )
    .unwrap();
    for kind in [Kind::Audit, Kind::Outcome] {
        let key = kind.key(b"op-2").unwrap();
        forged.read(Dependency::Absent(key.clone())).unwrap();
        let write = Change::Write {
            key,
            version: version.clone(),
            end: None,
            data: Box::new([0; 32]),
        };
        assert_eq!(forged.change(write), Err(crate::transition::Error::Change));
    }
}
