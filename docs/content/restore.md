# Restore journal

A snapshot of a store cannot show that it is current. A restore from an old snapshot can bring back a revoked
credential, or lose the last sign-in method of an account. A binding that supports restore therefore keeps a
restore journal outside the failure domain of its snapshots. The journal records each fact that removes authority,
the creation of each authority anchor, the voids of refused operations, and the allocation floors. Before the
restored store serves, it applies the journal entries after the snapshot.

The binding implements the primitives of `rsauthnz::store::Journal` ([Storage contract](storage.md)). The module
`rsauthnz::store::journal` gives the record format, the check of the hash chain, and the rules. The rules are pure
functions: they do no I/O and order no write. The commit driver of the core, `rsauthnz::store::driver`, calls the
rules and orders each effect ([The commit driver](#the-commit-driver)). A binding implements only primitives.

## What the binding keeps

1. Keep the journal in its own failure domain, and declare it in `Restore::Journal { location, failure_domain }`.
2. Snapshot the complete store state. The mark record of the store (`Kind::Mark`) holds its low-water mark, a
   `journal::Mark`: the sequence and the link of an entry. The state reflects each entry at or below that sequence,
   and the driver writes the record, so each snapshot holds its mark.
3. Keep each entry after the low-water mark of the oldest snapshot that a restore can still use.
4. Treat a failed sync as a crash. Do not retry it.

The journal cannot detect the loss of its own newest entries, and its chain cannot detect a change of its newest
entry. Thus the protection holds only for the events that the declared failure domain survives.

## Entries

Each entry has its sequence, the identity of the operation that wrote it, and a body (`journal::Body`):

| Body | Written | What it records |
| --- | --- | --- |
| `End(End)` | Before the commit | Each fact that the commit makes true. A consumption that pays for an anchor also records its transition (`Consumption`): the request binding, the consumed value, the dependency keys, and the anchors that it creates |
| `Creation(anchors)` | After the commit, before the acknowledgement | Each anchor that the commit created: its key, its role and owner, and the record that the commit wrote |
| `Void(sequence)` | Before a refusal returns, or at reconciliation | The end or creation entry with that sequence did not commit. No rule reads it |
| `Floor(Floor)` | Before the commit of a value above the earlier floor | The highest value of the counter of a record kind that a commit can allocate |

A fact (`journal::Fact`) states that each version of a record at or below a version is dead. An end of a record
gives a fact at the version that the proposal read. A write gives a fact only for a version that it replaces, such as
a session renewal or a grant change. A rotation, a recovery, and a revocation of a
[workload](workload.md#after-a-restore) are such writes too. A fact only removes authority, so a replay of the
entries in any order, or more than once, gives the same state.

An anchor has a `journal::Role`: a sign-in method, a CLI credential, or a recovery value of an account
(`Id<Human>`), or an administrator binding of the authority (`Id<Authority>`).

## Stored form and chain

The stored form of an entry is the canonical CBOR array
`["rsauthnz.journal.1", sequence, link, operation, body]`. The link is the SHA-256 digest of the stored form of the
entry before it. The first entry holds 32 zero bytes (`Mark::EMPTY`). `head.next(&operation, &body, limits)` gives
the stored form of the entry after the mark `head`, and the mark of the new entry. It refuses an entry that a history
with the same limits cannot read back (`Error::Cbor`).

A `History` reads the journal after a low-water mark:

1. Start it with `History::new(mark)`.
2. Read pages with `Journal::read(history.head().sequence, limit)`, and add each one with
   `history.extend(&page, limits)`.
3. Stop at an empty page. `history.head()` gives the mark after which the next entry follows.

The first entry after the mark must hold the link of the mark. Thus a journal of another history refuses, also when
its sequences are the same.

| Refusal | Cause | Recovery |
| --- | --- | --- |
| `Error::Missing(sequence)` | The journal has no entry with this sequence: it does not reach back to the mark, or it has a gap | Refuse the activation. Restore from another snapshot, or repair the journal |
| `Error::Changed(sequence)` | The entry does not hold the link of the entry before it, or of the mark: the retained history changed, or the journal is of another history | Refuse the activation. Restore with the journal of the snapshot's history |
| `Error::Form(sequence)` | The entry has no valid form within the limits | Refuse the activation |

This example is also the example of the `rsauthnz::store::journal` module documentation, and `cargo xtask test`
runs it. The removal of a passkey gives one fact, and a restore from the empty mark reads it back:

```rust
use rsauthnz::cbor::Value;
use rsauthnz::id::{AuthorityVersion, Human, Id, Principal};
use rsauthnz::limits::Limits;
use rsauthnz::store::journal::{self, Body, History, Mark};
use rsauthnz::store::{Entry, Kind};
use rsauthnz::time::{Reading, ReadingSource};
use rsauthnz::transition::{Audit, Change, Dependency, OperationId, Proposal};

let owner = Id::new("acme", "auth")?;
let audit = Audit {
    actor: Principal::Human(Id::<Human>::new("acme", "u-17")?),
    action: Id::new("acme.auth", "credential.remove")?,
    time: Reading::new(core::time::Duration::from_secs(1_000), None, ReadingSource::Caller),
};
let passkey = Kind::Credential.key(b"c-4")?;
let mut proposal = Proposal::new(OperationId::new(b"op-1")?, audit, &Value::Null, Limits::default())?;
proposal.read(Dependency::Version(passkey.clone(), AuthorityVersion::new(owner, &[3])?))?;
proposal.change(Change::End(passkey))?;

// The removal of the passkey is a fact: each version of the record at or below 3 is dead.
let entries = journal::entries(&proposal, &[], &[])?;
let end = entries.end.ok_or("an end entry")?;
let (bytes, head) = Mark::EMPTY.next(&proposal.operation().id, &Body::End(end), Limits::default())?;

// A restore from a snapshot with the empty mark reads the journal from its first entry.
let mut history = History::new(Mark::EMPTY);
history.extend(&[Entry { sequence: head.sequence, data: bytes }], Limits::default())?;
assert_eq!(history.head(), head);
assert_eq!(journal::replay(history.entries())?.facts().count(), 1);
```

## Rules

A rule that reads the store takes a `journal::Reads`: the version of each record, or `None` for no record, and
whether each operation has an outcome record. Read each key of `history.keys()` and each operation of
`history.operations()`. A rule that needs a read that `Reads` does not have gives `Error::Unread`.

| Rule | Inputs | Result |
| --- | --- | --- |
| `journal::entries(&proposal, replaced, anchors)` | The proposal, the keys of the writes that replace a dead version, and the role of each anchor that it creates | `Entries`: the end entry, or `None`, and the anchors of the creation entry. `Error::Proposal` for a declaration that names no write, a new provider link, recovery value, or administrator binding with no role, or a commit that consumes two values that pay for an anchor |
| `Floor::reserve(kind, durable, value, block)` | The durable floor of a counter, the value that a commit allocates, and the block size | The floor entry that must be durable before the commit, or `None` when the floor covers the value. One floor entry covers each block |
| `journal::keeps_anchor(&change, held, &state)` | The entries of an anchor change, the anchors of its owners that the store holds, and the state of the journal | `true` when each owner keeps a sign-in method, or the authority an administrator binding. It counts the anchors that no fact of the journal ends, and the sign-in methods that the same consuming commit creates. A recovery value and a CLI credential do not count |
| `state.acknowledges(anchor_commits)` | Each commit of the owner that created an anchor | `true` when each one has its creation entry. Only then is an anchor change of the owner, or a lookup that reports it, acknowledged |
| `journal::reconcile(&history, &reads, candidates)` | The history after the mark of the current store, its reads, and each anchor commit that has no end entry | `Reconciliation`: the missing creation entries, and a void for each end entry whose fact does not hold. A missing outcome record gives no void |
| `journal::low_water(&history, &reads)` | The history after an earlier mark, and the reads of the captured state | The low-water mark of the snapshot, across all owners, with its link. The newest floor of each counter stays after the mark |
| `journal::restore(&history, &reads)` | The history after the mark of the snapshot, and the reads of the snapshot's state | `Activation`, below |
| `journal::replay(entries)` | Entries in any order | `State`: the highest dead version of each record, the anchors, the creation entries, and the highest floor of each counter |
| `history.state()` | A history, which can have new entries since the last call | The same `State` as `journal::replay(history.entries())`. It applies only the new entries, so its cost follows them. After a new void, it replays each entry again. The commit driver reads it before each commit |

## Restore decision

`journal::restore(&history, &reads)` gives an `Activation`. `reads` has the snapshot's state before the restore
applies an entry. The activation states what the restored store applies before it serves:

1. End each record whose version is at or below the version of its fact (`facts`).
2. Write each anchor that a creation entry made after the snapshot, and that no fact ends (`anchors`).
3. Raise the counter of each floor past its value (`floors`).
4. End each pending record of a kind whose consumption pays for no anchor: a sign-in challenge, the challenge of a
   CLI call, or an operation approval (`ends`). Then set the replay floor as a start does.
5. Commit each in-doubt consumption again under its operation identity, in journal order (`completions`). Keep
   the list until each one commits, so that a crash before that does not end the restore. The driver keeps it in
   the mark record.

A consumption entry is in doubt when the snapshot has no outcome record of its operation, and the history has no
creation entry of it. A known commit of the same value excludes it. A candidate completes when no earlier completion
spent its value, and each anchor that it creates is absent. A bootstrap value must also be in the snapshot, and no
re-bootstrap entry may end it. Otherwise the value stays consumed. A completion does not compare the versions or
the policy that the first attempt read. The known commits are the outcome records of the snapshot and the creation
entries after the mark. Thus the expiry of an outcome record is outside the checked rules: the design model does not
check it. After a restore, an outcome lookup that finds no record gives an unknown outcome.

The history holds each entry after the mark in memory, so the cost of a restore is linear in those entries.

## The commit driver

`rsauthnz::store::driver::Driver` is the one sequencer of the protocol. It gives the binding one effect at a time,
and the binding executes the primitive and gives its output back. This example is also the example of the
`rsauthnz::store::driver` module documentation, and `cargo xtask test` compiles it:

```rust
use rsauthnz::store::driver::{Driver, Effect, Output};

/// Executes each effect of `driver` until it has none. `execute` stands for the primitives of a binding.
fn run(driver: &mut Driver, mut execute: impl FnMut(Effect<'_>) -> Output) {
    while let Some(effect) = driver.effect() {
        let output = execute(effect);
        driver.give(output).expect("the output answers its effect");
    }
}
```

| `Effect` | Primitive | `Output` |
| --- | --- | --- |
| `Start` | `Store::start` | `Started(instance)` |
| `Read(key)` | `Store::read` | `Read(record)` |
| `Commit(proposal, instance)` | `Store::commit` | `Committed(commit)` |
| `Expire(kind, before, limit)` | `Store::expire` | `Expired(count)` |
| `Range(prefix, after, limit)` | `Store::range` | `Range(records)` |
| `Append(entry)` | `Journal::append` | `Appended(sequence)` |
| `Sync` | `Journal::sync` | `Synced` |
| `ReadJournal(after, limit)` | `Journal::read` | `Journal(entries)` |
| `Clock` | A fresh reading of the clock of the host, with the bound of its time source | `Clock(reading)` |

`Debug` of an effect and of an output shows the length of a journal entry (`Append`, `store::Entry`) and of record
data, and never their bytes, because they hold record forms such as the claims of a CLI credential. Thus an executor
can log each effect.

`Effect::Clock` comes just before the commit of a proposal with a deadline (`proposal.until`). A production executor
reads the system clock. A test gives a controlled clock: the memory binding gives the reading of
`memory.set_clock(reading)` through `Subject::clock`.

Give `Output::Failed` when a primitive fails. It is a crash: the driver stops (`Status::Down`), gives an unknown
outcome to the operation in progress, and serves again only after `driver.start(now)`. Do not retry the primitive.

1. Call `driver.start(now)` at first, and after each crash. It writes a new store instance number, reads the mark
   record and the journal after its mark, writes the missing creation entries and the voids of reconciliation, and
   then serves.
2. After a restore of a snapshot, call `driver.restore(now)`, never `start`: a start voids the entries that a restore
   applies. The restore of the store writes a fresh store instance number as its last step, so a delayed commit of
   an earlier start refuses also before `driver.restore`. A binding with no journal gets `Error::Unsupported`. The driver records the completions in the mark record before it changes the store, then
   applies the activation and completes each in-doubt consumption. A start after a crash during the restore
   completes the rest before it serves.
3. Submit a commit with `driver.submit(proposal, plan)`. The `Plan` gives the anchors of the owners that the store
   holds, the writes that replace a dead version, and the role of each new anchor. Take the answer with
   `driver.take(ticket)`. A proposal with a record longer than `record_bytes_max` refuses with
   `Error::RecordBytes`, and the binding never gets it.
4. Look up a lost outcome with `driver.lookup(operation)`. The result is `Lookup::Committed`, `Refused`, `Absent`,
   or `Unknown`. `Unknown` is for a missing outcome record after a restore.

The driver runs one operation at a time, a start first. A commit goes through these effects:

1. The last-anchor check, with no effect. A refusal gives `Outcome::Refused(Error::LastAnchor)`.
2. A floor entry for each counter whose allocated value passes its durable floor (`driver.allocate(kind)`), the end
   entry, and one sync. A binding with no journal keeps the floors in the mark record, in a commit before this one.
3. For a proposal with a deadline: the clock effect. A reading that can be at or after the deadline gives
   `Outcome::Refused(Error::Expired)` with no commit, and the void of the end entry and a sync come first.
4. The conditional commit, with the instance number of the latest start.
5. After an accepted commit: the creation entry and a sync, then the answer. An anchor commit with no consumption
   also carries an intent of `Effect::Journal`, and a commit of the driver ends it after the creation entry.
6. After a conflict, or the outcome record of another request: the void of the end entry and a sync, then the
   answer.

A start refuses with `Error::Restored` (`Status::Refused`) when the journal shows a commit that the store lost: a
later write of the mark record, or the creation entry of an anchor with no end that the store lacks. After each write
of the mark record, the driver appends a floor entry of `Kind::Mark` with the number of the write. A crash loses no
commit, so a start after a crash serves. Then call `driver.restore(now)`.

Limit: a start cannot detect a restore of a snapshot that is newer than the last write of the mark record, when only
commits with no creation entry, such as an unlink or a renewal, followed the snapshot. The journal holds no proof that
such a commit landed, so its loss looks the same as a crash before the commit.

`driver.cancel(ticket)` ends an operation that waits. The operation in progress runs to its commit or its refusal,
and it gives no answer. The driver moves the mark of the mark record after each start, on `driver.advance(now)`, and
after `ADVANCE_AT` entries, so the journal after the mark stays under `JOURNAL_ENTRIES_MAX` entries. A start that
finds a longer journal refuses with `Error::Long`.
