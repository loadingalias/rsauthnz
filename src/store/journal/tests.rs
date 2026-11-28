use alloc::boxed::Box;
use alloc::collections::{BTreeMap, BTreeSet};
use alloc::vec;
use alloc::vec::Vec;
use core::assert_matches;
use core::num::NonZeroU64;
use core::time::Duration;

use super::{
    Anchor, Body, Entries, Error, Fact, Floor, History, Link, Mark, Reads, Role, State, entries, keeps_anchor,
    low_water, reconcile, replay, restore,
};
use crate::cbor::Value;
use crate::crypto;
use crate::id::{Authority, AuthorityVersion, Human, Id, Principal};
use crate::limits::Limits;
use crate::store::{self, Kind, Sequence};
use crate::time::{Reading, ReadingSource};
use crate::transition::{Audit, Change, Dependency, Key, OperationId, Proposal};

fn op(name: &str) -> OperationId {
    OperationId::new(name.as_bytes()).unwrap()
}

fn key(kind: Kind, id: &str) -> Key {
    kind.key(id.as_bytes()).unwrap()
}

fn version(n: u8) -> AuthorityVersion {
    AuthorityVersion::new(authority(), &[n]).unwrap()
}

fn account(name: &str) -> Id<Human> {
    Id::new("acme", name).unwrap()
}

fn authority() -> Id<Authority> {
    Id::new("acme", "auth").unwrap()
}

/// The anchor that [`write`] gives at version 1.
fn anchor(key: &Key, role: Role) -> Anchor {
    Anchor {
        key: key.clone(),
        role,
        version: version(1),
        end: None,
        data: Box::new(*b"record"),
    }
}

fn write(key: &Key, n: u8) -> Change {
    Change::Write {
        key: key.clone(),
        version: version(n),
        end: None,
        data: Box::new(*b"record"),
    }
}

fn proposal(name: &str, reads: Vec<Dependency>, changes: Vec<Change>) -> Proposal {
    let audit = Audit {
        actor: Principal::Human(account("u-1")),
        action: Id::new("acme.auth", "test").unwrap(),
        time: Reading::new(Duration::from_secs(1), None, ReadingSource::Caller),
    };
    let mut proposal = Proposal::new(op(name), audit, &Value::Text(name), Limits::default()).unwrap();
    for read in reads {
        proposal.read(read).unwrap();
    }
    for change in changes {
        proposal.change(change).unwrap();
    }
    proposal
}

/// The entries of an end of `record`, which the proposal read at version `at`: an unlink, a removal, or a revocation.
fn unlink(name: &str, record: &Key, at: u8) -> Entries {
    let proposal = proposal(
        name,
        vec![Dependency::Version(record.clone(), version(at))],
        vec![Change::End(record.clone())],
    );
    entries(&proposal, &[], &[]).unwrap()
}

/// The entries of a grant change from revision `from` to revision `to`.
fn renew(name: &str, grant: &Key, from: u8, to: u8) -> Entries {
    let proposal = proposal(
        name,
        vec![Dependency::Version(grant.clone(), version(from))],
        vec![write(grant, to)],
    );
    entries(&proposal, core::slice::from_ref(grant), &[]).unwrap()
}

/// The entries of a consumption of `value` at version `at` that ends `retired` and creates `anchors`, and that also
/// read `read`. Each retired and read record is at version 1, and each anchor is new.
fn consume(name: &str, value: &Key, at: u8, retired: &[&Key], anchors: &[(Key, Role)], read: &[&Key]) -> Entries {
    let mut reads = vec![Dependency::Version(value.clone(), version(at))];
    let mut changes = vec![Change::End(value.clone())];
    for record in retired {
        reads.push(Dependency::Version((*record).clone(), version(1)));
        changes.push(Change::End((*record).clone()));
    }
    for (record, _) in anchors {
        reads.push(Dependency::Absent(record.clone()));
        changes.push(write(record, 1));
    }
    reads.extend(
        read.iter()
            .map(|record| Dependency::Version((*record).clone(), version(1))),
    );
    entries(&proposal(name, reads, changes), &[], anchors).unwrap()
}

fn end(entries: Entries) -> Body {
    Body::End(entries.end.unwrap())
}

fn creation(entries: Entries) -> Body {
    Body::Creation(entries.creation)
}

/// The stored form of `bodies`: a chain from the first sequence.
fn journal(bodies: &[(OperationId, Body)]) -> Vec<store::Entry> {
    let mut head = Mark::EMPTY;
    bodies
        .iter()
        .map(|(operation, body)| {
            let append = head.next(operation, body, Limits::default()).unwrap();
            head = append.head();
            append.entry().clone()
        })
        .collect()
}

/// The mark of the entry with the sequence `sequence` of `stored`, or the empty mark for 0.
fn mark(stored: &[store::Entry], sequence: u64) -> Mark {
    match sequence.checked_sub(1) {
        None => Mark::EMPTY,
        Some(index) => Mark {
            sequence: Sequence(sequence),
            link: Link(crypto::sha256(&stored[usize::try_from(index).unwrap()].data)),
        },
    }
}

/// The history of `bodies` after the mark of the entry with the sequence `after`.
fn history(after: u64, bodies: &[(OperationId, Body)]) -> History {
    let stored = journal(bodies);
    let mut history = History::new(mark(&stored, after));
    history
        .extend(&stored[usize::try_from(after).unwrap()..], Limits::default())
        .unwrap();
    history
}

/// The store reads of `history` and of `present`: each key of `present` at its version, each other key with no
/// record, and an outcome record for each operation of `committed`.
fn reads(history: &History, present: &[(&Key, u8)], committed: &[&OperationId]) -> Reads {
    let mut keys = history.keys();
    keys.extend(present.iter().map(|(key, _)| *key));
    let mut operations = history.operations();
    operations.extend(committed);
    Reads {
        records: keys
            .into_iter()
            .map(|key| {
                let found = present.iter().find(|(record, _)| *record == key);
                (key.clone(), found.map(|(_, n)| version(*n)))
            })
            .collect(),
        outcomes: operations
            .into_iter()
            .map(|operation| (operation.clone(), committed.contains(&operation)))
            .collect(),
    }
}

/// Calls `check` with each order of `items`, by Heap's algorithm.
fn for_each_order<T>(items: &mut [T], mut check: impl FnMut(&[T])) {
    let mut counters = vec![0; items.len()];
    check(items);
    let mut i = 1;
    while i < items.len() {
        if counters[i] < i {
            items.swap(if i % 2 == 0 { 0 } else { counters[i] }, i);
            check(items);
            counters[i] += 1;
            i = 1;
        } else {
            counters[i] = 0;
            i += 1;
        }
    }
}

/// A grant change is the death of the revision that it replaces, never the new revision, so the facts give one state
/// in each order of the entries, and when each entry comes twice. A voided entry adds nothing, and the floor of a
/// counter is its highest.
#[test]
fn replay_in_every_order_and_twice_gives_one_state() {
    let grant = key(Kind::Grant, "g-1");
    let session = key(Kind::Session, "s-1");
    let passkey = key(Kind::Credential, "a1p");
    let bodies = [
        (op("g-1"), end(renew("g-1", &grant, 1, 2))),
        (op("g-2"), end(renew("g-2", &grant, 2, 3))),
        (op("s-1"), end(unlink("s-1", &session, 5))),
        (op("u-1"), end(unlink("u-1", &passkey, 1))),
        (op("u-1"), Body::Void(Sequence(4))),
        (
            op("s-2"),
            Body::Floor(Floor {
                kind: Kind::Session,
                value: 64,
            }),
        ),
        (
            op("s-3"),
            Body::Floor(Floor {
                kind: Kind::Session,
                value: 32,
            }),
        ),
    ];
    let expected = State {
        dead: BTreeMap::from([(grant, version(2)), (session, version(5))]),
        anchors: BTreeMap::new(),
        created: BTreeSet::new(),
        floors: BTreeMap::from([(Kind::Session, 64)]),
    };
    let mut order = history(0, &bodies).entries().to_vec();
    for_each_order(&mut order, |order| {
        assert_eq!(replay(order).as_ref(), Ok(&expected));
        assert_eq!(replay(&[order, order].concat()).as_ref(), Ok(&expected));
    });
}

/// The driver reads the state of its history before each commit, and the history keeps it between reads. So each read
/// must hold each entry since the last one: else the last-anchor check counts an unlinked passkey as a sign-in
/// method, and accepts the unlink of the last one. A void after a read cancels an entry that the state already holds:
/// the unlink of a passkey that did not commit, and the creation of an anchor whose commit did not land.
#[test]
fn the_state_after_each_extension_equals_a_replay() {
    let passkey = key(Kind::Credential, "a1p");
    let created = key(Kind::Credential, "a1q");
    let bodies = [
        (op("u-1"), end(unlink("u-1", &passkey, 1))),
        (
            op("c-1"),
            creation(consume(
                "c-1",
                &key(Kind::Registration, "reg-1"),
                1,
                &[],
                &[(created, Role::SignIn(account("a1")))],
                &[],
            )),
        ),
        (op("u-1"), Body::Void(Sequence(1))),
        (op("c-1"), Body::Void(Sequence(2))),
    ];
    let stored = journal(&bodies);
    let mut history = History::new(Mark::EMPTY);
    // Each read: the entries up to it, whether the unlinked passkey is dead, and the number of anchors.
    for (end, dead, anchors) in [(1, true, 0), (2, true, 1), (4, false, 0)] {
        let from = history.entries().len();
        history.extend(&stored[from..end], Limits::default()).unwrap();
        let state = history.state().unwrap().clone();
        assert_eq!(state.ends(&passkey, &version(1)), Ok(dead), "after {end} entries");
        assert_eq!(state.anchors().count(), anchors, "after {end} entries");
        assert_eq!(replay(history.entries()), Ok(state), "after {end} entries");
    }
}

/// Each entry holds the link of the entry before it, and the first entry after the mark holds the link of the mark.
/// So the history finds a changed entry at the entry after it, a removed entry at its sequence, and a journal of
/// another history at its first entry.
#[test]
fn a_changed_removed_or_foreign_entry_fails_verification() {
    let passkey = key(Kind::Credential, "a1p");
    let bodies: Vec<_> = (1..=4).map(|n| (op("u-1"), end(unlink("u-1", &passkey, n)))).collect();
    let stored = journal(&bodies);
    History::new(Mark::EMPTY).extend(&stored, Limits::default()).unwrap();

    let other = mark(&stored, 1)
        .next(&op("u-1"), &end(unlink("u-1", &passkey, 9)), Limits::default())
        .unwrap();
    let mut changed = stored.clone();
    changed[1] = other.entry().clone();
    assert_eq!(
        History::new(Mark::EMPTY).extend(&changed, Limits::default()),
        Err(Error::Changed(Sequence(3)))
    );

    let removed = [stored[0].clone(), stored[2].clone(), stored[3].clone()];
    assert_eq!(
        History::new(Mark::EMPTY).extend(&removed, Limits::default()),
        Err(Error::Missing(Sequence(2)))
    );

    let foreign = journal(&bodies.iter().rev().cloned().collect::<Vec<_>>());
    assert_eq!(
        History::new(mark(&stored, 2)).extend(&foreign[2..], Limits::default()),
        Err(Error::Changed(Sequence(3)))
    );
}

/// A journal whose retained history starts after the mark refuses, and the rules read only the entries after the mark.
#[test]
fn a_journal_that_starts_after_the_mark_refuses() {
    let passkey = key(Kind::Credential, "a1p");
    let bodies: Vec<_> = (1..=4).map(|n| (op("u-1"), end(unlink("u-1", &passkey, n)))).collect();
    let stored = journal(&bodies);
    assert_eq!(
        History::new(mark(&stored, 2)).extend(&stored[3..], Limits::default()),
        Err(Error::Missing(Sequence(3)))
    );
    let after = history(2, &bodies);
    let sequences: Vec<_> = after.entries().iter().map(|entry| entry.sequence.0).collect();
    assert_eq!(sequences, [3, 4]);
}

/// An entry that a history with the same limits cannot read back refuses before its append, so no restore depends on
/// it.
#[test]
fn an_entry_that_the_history_cannot_read_back_refuses() {
    let limits = Limits {
        bytes: 64,
        ..Limits::default()
    };
    let body = end(unlink("u-1", &key(Kind::Credential, "a1p"), 1));
    assert_matches!(Mark::EMPTY.next(&op("u-1"), &body, limits), Err(Error::Cbor(_)));
}

/// Each end of a record gives a fact, and a write gives one only when it replaces a dead version. A sign-in challenge
/// pays for no anchor, and a signature counter write kills no version, so a sign-in writes no entry. A new provider
/// link is always an anchor, so a transition that gives it no role refuses before its commit, as one that consumes two
/// values that pay for an anchor does.
#[test]
fn the_entries_of_a_proposal_follow_the_kinds_of_its_changes() {
    let challenge = key(Kind::SignIn, "ch-1");
    let passkey = key(Kind::Credential, "a1p");
    let grant = key(Kind::Grant, "g-1");
    let link = key(Kind::ProviderLink, "l-1");
    let invitation = key(Kind::Invitation, "i-1");
    let registration = key(Kind::Registration, "reg-1");
    let new = key(Kind::Credential, "a1s");
    let at = |record: &Key, n: u8| Dependency::Version(record.clone(), version(n));
    let rows = [
        (
            "a sign-in challenge pays for no anchor",
            proposal("s-1", vec![at(&challenge, 1)], vec![Change::End(challenge.clone())]),
            vec![],
            vec![],
            Ok(None),
        ),
        (
            "a signature counter write replaces no dead version",
            proposal("s-2", vec![at(&passkey, 1)], vec![write(&passkey, 2)]),
            vec![],
            vec![],
            Ok(None),
        ),
        (
            "the removal of a passkey ends the version that it read",
            proposal("u-1", vec![at(&passkey, 1)], vec![Change::End(passkey.clone())]),
            vec![],
            vec![],
            Ok(Some(vec![Fact {
                key: passkey.clone(),
                version: version(1),
            }])),
        ),
        (
            "a grant change ends the revision that it replaces",
            proposal("g-1", vec![at(&grant, 1)], vec![write(&grant, 2)]),
            vec![grant.clone()],
            vec![],
            Ok(Some(vec![Fact {
                key: grant.clone(),
                version: version(1),
            }])),
        ),
        (
            "a new provider link with no role",
            proposal("l-1", vec![Dependency::Absent(link.clone())], vec![write(&link, 1)]),
            vec![],
            vec![],
            Err(Error::Proposal),
        ),
        (
            "a commit that consumes two values that pay for an anchor",
            proposal(
                "i-1",
                vec![
                    at(&invitation, 1),
                    at(&registration, 1),
                    Dependency::Absent(new.clone()),
                ],
                vec![Change::End(invitation), Change::End(registration), write(&new, 1)],
            ),
            vec![],
            vec![(new, Role::SignIn(account("a1")))],
            Err(Error::Proposal),
        ),
    ];
    for (name, proposal, replaced, anchors, expected) in rows {
        let facts = entries(&proposal, &replaced, &anchors).map(|entries| entries.end.map(|end| end.facts));
        assert_eq!(facts, expected, "{name}");
    }
}

/// The operations of the completions of `bodies`, from the mark 0, with the snapshot reads `present` and `committed`.
fn completions(bodies: &[(OperationId, Body)], present: &[(&Key, u8)], committed: &[&OperationId]) -> Vec<OperationId> {
    let history = history(0, bodies);
    let decision = restore(&history, &reads(&history, present, committed)).unwrap();
    decision
        .completions
        .into_iter()
        .map(|completion| completion.operation)
        .collect()
}

/// A restore keeps an anchor that a creation entry made after the snapshot, ignores a voided entry, ends each pending
/// sign-in challenge, and lists the in-doubt consumptions in journal order.
#[test]
fn the_restore_decision_keeps_new_anchors_and_lists_doubts_in_journal_order() {
    let registration = key(Kind::Registration, "reg-1");
    let a1s = key(Kind::Credential, "a1s");
    let a1p = key(Kind::Credential, "a1p");
    let a2c = key(Kind::Recovery, "a2c");
    let a2n = key(Kind::Credential, "a2n");
    let boot = key(Kind::Bootstrap, "b-1");
    let adm1 = key(Kind::Administrator, "adm1");
    let enrolled = consume(
        "e-1",
        &registration,
        1,
        &[],
        &[(a1s.clone(), Role::SignIn(account("a1")))],
        &[],
    );
    let recovered = consume("r-1", &a2c, 1, &[], &[(a2n, Role::SignIn(account("a2")))], &[]);
    let booted = consume("b-1", &boot, 1, &[], &[(adm1, Role::Administrator(authority()))], &[]);
    let bodies = [
        (
            op("f-1"),
            Body::Floor(Floor {
                kind: Kind::Session,
                value: 8,
            }),
        ),
        (op("e-1"), end(enrolled.clone())),
        (op("u-1"), end(unlink("u-1", &a1p, 1))),
        (op("e-1"), creation(enrolled)),
        (op("u-1"), Body::Void(Sequence(3))),
        (op("r-1"), end(recovered)),
        (op("b-1"), end(booted)),
    ];
    let history = history(1, &bodies);
    let decision = restore(&history, &reads(&history, &[(&a1p, 1), (&a2c, 1), (&boot, 1)], &[])).unwrap();
    assert_eq!(decision.anchors, [anchor(&a1s, Role::SignIn(account("a1")))]);
    assert!(decision.facts.iter().all(|fact| fact.key != a1p));
    assert!(decision.ends.contains(&Kind::SignIn));
    let operations: Vec<_> = decision
        .completions
        .into_iter()
        .map(|completion| completion.operation)
        .collect();
    assert_eq!(operations, [op("r-1"), op("b-1")]);
}

/// Each condition of a completion, true and false: the model's `AgainOK`, the known commits, and the journal order of
/// `First`. A completion spends the value of its own entry, and it does not compare the versions that the first
/// attempt read.
#[test]
fn a_completion_needs_each_condition_of_the_model() {
    let boot = key(Kind::Bootstrap, "b-1");
    let adm1 = key(Kind::Administrator, "adm1");
    let adm2 = key(Kind::Administrator, "adm2");
    let admin = |record: &Key| [(record.clone(), Role::Administrator(authority()))];
    let booted = consume("b-1", &boot, 1, &[], &admin(&adm1), &[]);
    let other = consume("b-2", &boot, 1, &[], &admin(&adm2), &[]);
    let earlier = consume("b-0", &boot, 1, &[], &admin(&adm2), &[]);
    let next = key(Kind::Bootstrap, "b-2");
    let reboot = proposal(
        "i-1",
        vec![
            Dependency::Version(boot.clone(), version(1)),
            Dependency::Absent(next.clone()),
        ],
        vec![Change::End(boot.clone()), write(&next, 1)],
    );
    let reboot = entries(&reboot, &[], &[]).unwrap();
    let b = || (op("b-1"), end(booted.clone()));
    let rows = [
        (
            "the snapshot holds the value",
            vec![b()],
            vec![(&boot, 1)],
            vec![],
            vec![op("b-1")],
        ),
        (
            "the snapshot has its outcome record",
            vec![b()],
            vec![(&boot, 1)],
            vec![op("b-1")],
            vec![],
        ),
        (
            "the journal has its creation entry",
            vec![b(), (op("b-1"), creation(booted.clone()))],
            vec![(&boot, 1)],
            vec![],
            vec![],
        ),
        (
            "an outcome record shows another commit of the value",
            vec![(op("b-2"), end(other.clone())), b()],
            vec![(&boot, 1)],
            vec![op("b-2")],
            vec![],
        ),
        (
            "a creation entry shows another commit of the value",
            vec![(op("b-2"), end(other.clone())), (op("b-2"), creation(other)), b()],
            vec![(&boot, 1)],
            vec![],
            vec![],
        ),
        (
            "an earlier consumption of the value completes first",
            vec![(op("b-0"), end(earlier.clone())), b()],
            vec![(&boot, 1)],
            vec![],
            vec![op("b-0")],
        ),
        (
            "an earlier consumption that cannot complete leaves the value",
            vec![(op("b-0"), end(earlier)), b()],
            vec![(&boot, 1), (&adm2, 1)],
            vec![],
            vec![op("b-1")],
        ),
        (
            "the snapshot has the anchor",
            vec![b()],
            vec![(&boot, 1), (&adm1, 1)],
            vec![],
            vec![],
        ),
        (
            "a creation entry made the anchor",
            vec![
                (
                    op("x-1"),
                    Body::Creation(vec![anchor(&adm1, Role::Administrator(authority()))]),
                ),
                b(),
            ],
            vec![(&boot, 1)],
            vec![],
            vec![],
        ),
        (
            "a fact ended the anchor",
            vec![(op("u-1"), end(unlink("u-1", &adm1, 1))), b()],
            vec![(&boot, 1)],
            vec![],
            vec![],
        ),
        ("the snapshot has no bootstrap value", vec![b()], vec![], vec![], vec![]),
        (
            "the snapshot has another bootstrap value",
            vec![b()],
            vec![(&boot, 2)],
            vec![],
            vec![],
        ),
        (
            "a re-bootstrap ended the value",
            vec![(op("i-1"), end(reboot.clone())), b()],
            vec![(&boot, 1)],
            vec![],
            vec![],
        ),
        (
            "a void cancels the end of the re-bootstrap",
            vec![(op("i-1"), end(reboot)), (op("i-1"), Body::Void(Sequence(1))), b()],
            vec![(&boot, 1)],
            vec![],
            vec![op("b-1")],
        ),
    ];
    for (name, bodies, present, committed, expected) in rows {
        let committed: Vec<_> = committed.iter().collect();
        assert_eq!(completions(&bodies, &present, &committed), expected, "{name}");
    }

    let a2c = key(Kind::Recovery, "a2c");
    let device = key(Kind::Credential, "a2d");
    let recovery = consume(
        "r-1",
        &a2c,
        1,
        &[],
        &[(key(Kind::Credential, "a2n"), Role::SignIn(account("a2")))],
        &[&device],
    );
    let r = [(op("r-1"), end(recovery))];
    let rows: [(&str, Vec<(&Key, u8)>); 3] = [
        ("its own entry is no spend of the value", vec![(&a2c, 1)]),
        (
            "a later version of a record that it read",
            vec![(&a2c, 1), (&device, 9)],
        ),
        ("a recovery value needs no hold in the snapshot", vec![]),
    ];
    for (name, present) in rows {
        assert_eq!(completions(&r, &present, &[]), [op("r-1")], "{name}");
    }
}

/// One floor entry covers each block of values, not each value.
#[test]
fn one_floor_entry_reserves_each_block() {
    let block = NonZeroU64::new(4).unwrap();
    let mut durable = 0;
    let mut floors = Vec::new();
    for value in 1..=10 {
        if let Some(floor) = Floor::reserve(Kind::Session, durable, value, block).unwrap() {
            durable = floor.value;
            floors.push(floor.value);
        }
    }
    assert_eq!(floors, [4, 8, 12]);
}

/// Reconciliation reads only the entries after the mark. It voids an entry whose fact does not hold, never one whose
/// outcome record is missing, and it writes the creation entry of each committed anchor commit that has none.
#[test]
fn reconciliation_reads_after_the_mark_and_voids_no_missing_outcome() {
    let a1p = key(Kind::Credential, "a1p");
    let a1q = key(Kind::Credential, "a1q");
    let a1r = key(Kind::Credential, "a1r");
    let registration = key(Kind::Registration, "reg-1");
    let a1s = key(Kind::Credential, "a1s");
    let a1c = key(Kind::Recovery, "a1c");
    let enrolled = consume(
        "e-1",
        &registration,
        1,
        &[],
        &[(a1s.clone(), Role::SignIn(account("a1")))],
        &[],
    );
    let bodies = [
        (op("x-1"), end(unlink("x-1", &a1q, 1))),
        (op("u-1"), end(unlink("u-1", &a1p, 1))),
        (op("u-2"), end(unlink("u-2", &a1r, 1))),
        (op("e-1"), end(enrolled)),
    ];
    let history = history(1, &bodies);
    let candidates = [(op("c-1"), vec![anchor(&a1c, Role::Recovery(account("a1")))])];
    let store = reads(&history, &[(&a1q, 1), (&a1r, 1), (&a1s, 1)], &[&op("e-1"), &op("c-1")]);
    let decision = reconcile(&history, &store, &candidates).unwrap();
    assert_eq!(decision.voids, [(op("u-2"), Sequence(3))]);
    assert_eq!(
        decision.creations,
        [
            (op("e-1"), vec![anchor(&a1s, Role::SignIn(account("a1")))]),
            (op("c-1"), vec![anchor(&a1c, Role::Recovery(account("a1")))]),
        ]
    );
}

/// The mark covers the entries of every owner: an end entry of `a2` that the captured state does not reflect holds
/// the mark below it, though each entry of `a1` is reflected. The newest floor of a counter also holds the mark, so a
/// restore reads it. The mark keeps the link that the next entry holds, so a restore from it reads the rest.
#[test]
fn the_mark_stays_below_an_unreflected_entry_of_any_owner() {
    let a1p = key(Kind::Credential, "a1p");
    let a2p = key(Kind::Credential, "a2p");
    let registration = key(Kind::Registration, "reg-1");
    let a1s = key(Kind::Credential, "a1s");
    let enrolled = consume(
        "e-1",
        &registration,
        1,
        &[],
        &[(a1s.clone(), Role::SignIn(account("a1")))],
        &[],
    );
    let floor = |value| {
        Body::Floor(Floor {
            kind: Kind::Session,
            value,
        })
    };
    let rows = [
        (
            "an end entry of a2 that the state does not reflect",
            vec![
                (op("u-1"), end(unlink("u-1", &a1p, 1))),
                (op("u-2"), end(unlink("u-2", &a2p, 1))),
                (op("e-1"), end(enrolled.clone())),
                (op("e-1"), creation(enrolled)),
            ],
            vec![(&a2p, 1), (&a1s, 1)],
            1,
        ),
        (
            "the newest floor of a counter",
            vec![
                (op("f-1"), floor(8)),
                (op("u-1"), end(unlink("u-1", &a1p, 1))),
                (op("f-2"), floor(16)),
            ],
            vec![],
            2,
        ),
        (
            "an anchor with an end that expiry removed",
            vec![(
                op("e-1"),
                Body::Creation(vec![Anchor {
                    end: Some(Duration::from_secs(10)),
                    ..anchor(&a1s, Role::SignIn(account("a1")))
                }]),
            )],
            vec![],
            1,
        ),
        (
            "each entry is reflected or voided",
            vec![
                (op("u-1"), end(unlink("u-1", &a1p, 1))),
                (op("u-2"), end(unlink("u-2", &a2p, 1))),
                (op("u-2"), Body::Void(Sequence(2))),
            ],
            vec![(&a2p, 1)],
            3,
        ),
    ];
    for (name, bodies, present, expected) in rows {
        let all = history(0, &bodies);
        let mark = low_water(&all, &reads(&all, &present, &[])).unwrap();
        assert_eq!(mark.sequence, Sequence(expected), "{name}");
        let stored = journal(&bodies);
        let rest = &stored[usize::try_from(expected).unwrap()..];
        assert_eq!(History::new(mark).extend(rest, Limits::default()), Ok(()), "{name}");
    }
}

/// An anchor change of an owner, or a lookup of it, waits while another commit of that owner that created an anchor
/// has no creation entry.
#[test]
fn an_acknowledgement_waits_for_each_creation_entry_of_the_owner() {
    let a1s = key(Kind::Credential, "a1s");
    let bodies = [(
        op("e-1"),
        Body::Creation(vec![anchor(&a1s, Role::SignIn(account("a1")))]),
    )];
    let state = replay(history(0, &bodies).entries()).unwrap();
    assert!(state.acknowledges([&op("e-1")]));
    assert!(!state.acknowledges([&op("e-1"), &op("e-2")]));
}

/// The last-anchor check counts the anchors that the journal records as live, and each sign-in method that the same
/// consuming commit creates. A recovery value and a CLI credential do not count.
#[test]
fn the_last_anchor_check_counts_journaled_sign_in_methods() {
    let a1 = || account("a1");
    let a1p = key(Kind::Credential, "a1p");
    let a1q = key(Kind::Credential, "a1q");
    let a1c = key(Kind::Recovery, "a1c");
    let a1k = key(Kind::Credential, "a1k");
    let a1n = key(Kind::Credential, "a1n");
    let adm1 = key(Kind::Administrator, "adm1");
    let adm2 = key(Kind::Administrator, "adm2");
    let p = anchor(&a1p, Role::SignIn(a1()));
    let q = anchor(&a1q, Role::SignIn(a1()));
    let c = anchor(&a1c, Role::Recovery(a1()));
    let k = anchor(&a1k, Role::Cli(a1()));
    let admin = |record: &Key| anchor(record, Role::Administrator(authority()));
    let unlink_q = (op("u-0"), end(unlink("u-0", &a1q, 1)));
    let replace = proposal(
        "x-1",
        vec![
            Dependency::Version(a1p.clone(), version(1)),
            Dependency::Absent(a1n.clone()),
        ],
        vec![Change::End(a1p.clone()), write(&a1n, 1)],
    );
    let replace = entries(&replace, &[], &[(a1n.clone(), Role::SignIn(a1()))]).unwrap();
    let recover = consume("r-1", &a1c, 1, &[&a1p], &[(a1n, Role::SignIn(a1()))], &[]);
    let rows = [
        (
            "another sign-in method",
            vec![p.clone(), q.clone()],
            vec![],
            unlink("u-1", &a1p, 1),
            true,
        ),
        (
            "a recovery value",
            vec![p.clone(), c.clone()],
            vec![],
            unlink("u-1", &a1p, 1),
            false,
        ),
        (
            "a CLI credential",
            vec![p.clone(), k],
            vec![],
            unlink("u-1", &a1p, 1),
            false,
        ),
        (
            "an unlink that the journal records",
            vec![p.clone(), q.clone()],
            vec![unlink_q.clone()],
            unlink("u-1", &a1p, 1),
            false,
        ),
        (
            "an unlink that a void cancels",
            vec![p.clone(), q.clone()],
            vec![unlink_q, (op("u-0"), Body::Void(Sequence(1)))],
            unlink("u-1", &a1p, 1),
            true,
        ),
        (
            "a creation entry",
            vec![p.clone()],
            vec![(op("e-1"), Body::Creation(vec![q]))],
            unlink("u-1", &a1p, 1),
            true,
        ),
        (
            "the method that the same consuming commit creates",
            vec![p.clone(), c],
            vec![],
            recover,
            true,
        ),
        (
            "a method that a commit with no consumption creates",
            vec![p],
            vec![],
            replace,
            false,
        ),
        (
            "the last administrator",
            vec![admin(&adm1)],
            vec![],
            unlink("u-1", &adm1, 1),
            false,
        ),
        (
            "another administrator",
            vec![admin(&adm1), admin(&adm2)],
            vec![],
            unlink("u-1", &adm1, 1),
            true,
        ),
    ];
    for (name, held, bodies, change, expected) in rows {
        let state = replay(history(0, &bodies).entries()).unwrap();
        assert_eq!(keeps_anchor(&change, &held, &state), Ok(expected), "{name}");
    }
}
