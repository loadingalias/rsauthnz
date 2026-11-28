# Write a storage binding

This guide takes a backend author from an empty store to a binding that passes the [conformance suite]. A binding
connects rsauthnz to the store that the application chooses, for example a transactional database or a store with a
single writer. rsauthnz ships no storage backend, so a binding that passes the suite is the supported way to keep its
state.

You implement only primitives: one bounded effect for each call. The commit driver of the core ([`Driver`]) orders
every write: the journal entries, the commits, the voids, the creation entries, and the acknowledgements. No step of
this guide asks you to order two writes. Each step names the public items that it implements. The
[memory binding] is the reference implementation of each primitive.

[conformance suite]: crate::suite
[memory binding]: crate::memory
[`Driver`]: rsauthnz::store::driver::Driver

## Prerequisites

- A store with one atomic conditional commit over a set of keys: a serializable transaction, or one atomic write
  that checks each condition first. A store with snapshot isolation or weaker cannot keep the contract.
- For restore support, a place for the restore journal outside the failure domain of the snapshots of the store.
  For example, use another host, disk, or bucket.
- An executor for the futures of the binding. The core runs no executor.

## Steps

1. [Declare the guarantees](#1-declare-the-guarantees).
2. [Keep the store instance number](#2-keep-the-store-instance-number).
3. [Read one record](#3-read-one-record).
4. [Commit a proposal](#4-commit-a-proposal).
5. [Keep audit and outcome records for their retention](#5-keep-audit-and-outcome-records-for-their-retention).
6. [Expire ended records](#6-expire-ended-records).
7. [Read one key prefix](#7-read-one-key-prefix).
8. [Keep the restore journal](#8-keep-the-restore-journal).
9. [Stop at each error](#9-stop-at-each-error).
10. [Run the commit driver](#10-run-the-commit-driver).
11. [Implement the test controls](#11-implement-the-test-controls).
12. [Run the suite](#12-run-the-suite).

## 1. Declare the guarantees

Give the guarantees of the binding in [`Store::declaration`], as a [`Declaration`]. [`Profile::new`] refuses a
declaration that cannot keep the contract, and the driver takes only a [`Profile`] that it accepted
([step 10](#10-run-the-commit-driver)). The suite calls it before the cases.

| Field | Set it to |
| --- | --- |
| `isolation` | [`Isolation::Serializable`] for a serializable transaction. [`Isolation::AtomicConditional`] for one atomic write that checks each dependency, absences included. Never claim either one for snapshot isolation |
| `crash_loss` | [`CrashLoss::Unsynced`] when a crash loses only the writes whose commit or sync did not return. [`CrashLoss::Everything`] when the store is in the memory of the process |
| `outcome_retention` | The least time after the audit time of its proposal for which the binding keeps an outcome record ([step 5](#5-keep-audit-and-outcome-records-for-their-retention)) |
| `crash_injection` | [`CrashInjection::Supported`] when the binding implements [`Subject::inject`] ([step 11](#11-implement-the-test-controls)) |
| `restore` | [`Restore::Journal`] with the location and the failure domain of the journal, or [`Restore::Unsupported`] |
| `key_bytes_max` | At least [`Key::BYTES_MAX`] |
| `signatures` | The [`Capacity`] of the replay records of HTTP signatures: the most records, and the most records of one share ([step 4](#the-replay-insert)). Declare a small capacity for the suite, which fills it |
| `record_bytes_max` | The most bytes in one record that the store keeps: the record form of a write, an intent record, an audit record, or an outcome record. Give at least [`record_bytes_min`] of the [`Limits`] of the driver, which grows with the changes of one proposal. [`Driver::new`] refuses a smaller bound with [`driver::Error::RecordBound`]. [`Driver::submit`] refuses a proposal with a larger record, so the binding never gets it |

The declaration selects the suite cases. A binding without crash injection skips the crash cases, and a binding
without a journal skips the restore cases. [`Report::skipped`] names each case that the binding skips.

[`Store::declaration`]: rsauthnz::store::Store::declaration
[`Declaration`]: rsauthnz::store::Declaration
[`Profile::new`]: rsauthnz::store::Profile::new
[`Profile`]: rsauthnz::store::Profile
[`record_bytes_min`]: rsauthnz::store::driver::record_bytes_min
[`Limits`]: rsauthnz::limits::Limits
[`driver::Error::RecordBound`]: rsauthnz::store::driver::Error::RecordBound
[`Isolation::Serializable`]: rsauthnz::store::Isolation::Serializable
[`Isolation::AtomicConditional`]: rsauthnz::store::Isolation::AtomicConditional
[`CrashLoss::Unsynced`]: rsauthnz::store::CrashLoss::Unsynced
[`CrashLoss::Everything`]: rsauthnz::store::CrashLoss::Everything
[`CrashInjection::Supported`]: rsauthnz::store::CrashInjection::Supported
[`Restore::Journal`]: rsauthnz::store::Restore::Journal
[`Restore::Unsupported`]: rsauthnz::store::Restore::Unsupported
[`Key::BYTES_MAX`]: rsauthnz::transition::Key::BYTES_MAX
[`Report::skipped`]: crate::suite::Report::skipped
[`Subject::inject`]: crate::suite::Subject::inject

## 2. Keep the store instance number

Implement [`Store::start`]. It gives a new [`Instance`], and each commit compares its instance with the number of
the latest start ([step 4](#4-commit-a-proposal)). Thus a commit from an earlier start refuses, also when it arrives
late over the network.

1. Give a number that is larger than each number that an earlier start gave. This applies also after a restart and
   after a restore.
2. Keep the counter of the numbers where a restore cannot lower it: in the failure domain of the journal. A
   restored lower number lets a delayed commit of the abandoned history land. A binding without a journal keeps the
   counter where a restart does not lower it.
3. Install the new number durably at the primary and the journal before `start` returns.
   Each destination checks its own number at the write.
4. Exclude earlier writers at both destinations before installing a snapshot.
   Keep the fresh number outside the snapshot. A single-writer binding can hold both directory locks through installation.

The number of the latest start before the restore is not enough, also when the restore keeps it. A delayed commit of
that start, for example from an old process that connects again, lands on the restored state. The design model
permits a restore only after a crash, and no commit of the run before the restore lands after it.

One driver serves each store at a time. A start fences each commit of an earlier start, so a second driver on the
same store makes the commits of the first one refuse.

[`Store::start`]: rsauthnz::store::Store::start
[`Instance`]: rsauthnz::store::Instance

## 3. Read one record

Implement [`Store::read`]. It gives the current [`Record`] of a [`Key`]: its version, its end, and its record form.
It gives `None` when no record has the key. It is a keyed read, and it never scans other records.

Implement [`Store::read_pair`] when you upgrade an existing binding. Read both keys under one lock or in one database snapshot.
One indexed database query can return both rows in one round trip. Map the rows back to the two requested positions.
Return `None` at each missing position. If both keys match, return the same result twice.

Store each key and each record form as opaque bytes. The first byte of a key names the [`Kind`] of its record, and
[`Kind::of`] gives it. The binding stores the records of every kind in the same way. These include the records that
the driver writes for itself: the mark record ([`Kind::Mark`]) and the replay floor ([`Kind::ReplayFloor`]).

[`Store::read`]: rsauthnz::store::Store::read
[`Store::read_pair`]: rsauthnz::store::Store::read_pair
[`Record`]: rsauthnz::store::Record
[`Key`]: rsauthnz::transition::Key
[`Kind`]: rsauthnz::store::Kind
[`Kind::of`]: rsauthnz::store::Kind::of
[`Kind::Mark`]: rsauthnz::store::Kind::Mark
[`Kind::ReplayFloor`]: rsauthnz::store::Kind::ReplayFloor

## 4. Commit a proposal

Implement [`Store::commit`]. It is the only primitive that writes audit or an outcome record. Do all of this in one
atomic step:

1. Compare the instance number of the call with the number of the latest start. When they differ, give
   [`Commit::Conflict`].
2. Read the outcome record of the operation identity: the key of [`outcome_record`]. When it exists, give
   [`Commit::Recorded`] with the operation of [`outcome_of`]. Give it also when a dependency no longer holds: a
   second submission of a commit never finds its own dependencies.
3. Check each [`Dependency`] of [`Proposal::dependencies`]. `Version(key, version)` holds when the record of `key`
   has that version. `Policy(version)` holds when the record of [`policy_key`] of its owner has that version.
   `Absent(key)` holds when no record has `key`. When one does not hold, give [`Commit::Conflict`].
4. When the proposal has a deadline ([`Proposal::deadline`]), read the clock of the binding, with the bound of its
   time source. When [`store::expired`] holds for the reading, give [`Commit::Expired`]. Read the clock in the step,
   after the checks of the dependencies. A reading before the step is not sufficient: the time from that reading to
   the write has no bound.
5. For each write of a new record of [`Kind::Signature`], count the records of the kind and the records of its share
   ([`store::share`]). When [`Capacity::admits`] does not hold for the counts, give [`Commit::Full`].
6. Write each [`Change`] of [`Proposal::changes`], the record of [`audit_record`], each record of
   [`intent_records`], and the record of [`outcome_record`]. `Change::End` removes its record.
7. Make the writes durable, then give [`Commit::Accepted`].

A conflict, an expiry, and a full capacity write nothing. Give an error only when the outcome is unknown, for example
after a lost connection or a timeout. An error is a crash ([step 9](#9-stop-at-each-error)).

Map the commit to the store:

- **Transactional database.** Run steps 1 to 7 in one transaction at serializable isolation. Read the clock in the
  transaction, after the reads of the dependencies: the clock of the database, or the clock of the binding while the
  transaction is open. A transaction that the database aborts, for example at a serialization failure, wrote
  nothing: give [`Commit::Conflict`].
- **Store with a single writer.** Hold the writer for the checks, the reading of the clock, and the writes. Write all
  records in one batch, and make the batch durable before you give the result.
- **Atomic conditional write.** Put a condition for the instance number, for the absence of the outcome record, for
  each dependency, and for a deadline in the write. The condition of a deadline compares it with the time of the
  store server. When a condition fails, read the instance number and the outcome record. Give the result of the
  first check above that fails. A store whose conditions cannot read the time of the server cannot read a clock in the
  step, so it cannot commit a proposal with a deadline.

### The replay insert

Implement [`Store::insert_replay`]. It accepts the signature of one HTTP request once, with no audit record and no
outcome record. Do all of this in one atomic step, as for a commit:

1. Read the replay floor record ([`floor_key`]). When [`Insert::admits`] does not hold for it and the current
   instance number, give [`Inserted::Floor`].
2. When a record has [`Insert::key`], give [`Inserted::Present`].
3. Count the records of [`Kind::Signature`] and the records of [`Insert::share`]. When [`Capacity::admits`] does not
   hold for the counts, give [`Inserted::Full`]. Keep the keys in order, so that each count reads only the keys of
   its prefix, or keep a count of each share in the same step.
4. Read the clock of the binding. When [`store::expired`] holds for [`Insert::deadline`] and the reading, give
   [`Inserted::Expired`].
5. Write [`Insert::record`] at [`Insert::key`], make it durable, and give [`Inserted::Accepted`].

Return [`Inserted::Conflict`] when contention aborts the transaction and the store confirms that this attempt wrote nothing.
For example, PostgreSQL can report [a serialization failure] with SQLSTATE `40001`. The binding can serve the next request.
Return a primitive error after a lost reply. Stop the binding as required by [step 9](#9-stop-at-each-error).
The insert can already be durable. A later read of the key cannot identify which attempt wrote it.

[a serialization failure]: https://www.postgresql.org/docs/current/mvcc-serialization-failure-handling.html
[`Inserted::Conflict`]: rsauthnz::store::Inserted::Conflict

[`Store::commit`]: rsauthnz::store::Store::commit
[`Store::insert_replay`]: rsauthnz::store::Store::insert_replay
[`floor_key`]: rsauthnz::store::floor_key
[`Insert::admits`]: rsauthnz::store::Insert::admits
[`Insert::key`]: rsauthnz::store::Insert::key
[`Insert::share`]: rsauthnz::store::Insert::share
[`Insert::deadline`]: rsauthnz::store::Insert::deadline
[`Insert::record`]: rsauthnz::store::Insert::record
[`Inserted::Floor`]: rsauthnz::store::Inserted::Floor
[`Inserted::Present`]: rsauthnz::store::Inserted::Present
[`Inserted::Full`]: rsauthnz::store::Inserted::Full
[`Inserted::Expired`]: rsauthnz::store::Inserted::Expired
[`Inserted::Accepted`]: rsauthnz::store::Inserted::Accepted
[`Kind::Signature`]: rsauthnz::store::Kind::Signature
[`Capacity`]: rsauthnz::store::Capacity
[`Capacity::admits`]: rsauthnz::store::Capacity::admits
[`store::share`]: rsauthnz::store::share
[`Commit::Full`]: rsauthnz::store::Commit::Full
[`Commit::Conflict`]: rsauthnz::store::Commit::Conflict
[`Commit::Expired`]: rsauthnz::store::Commit::Expired
[`Proposal::deadline`]: rsauthnz::transition::Proposal::deadline
[`store::expired`]: rsauthnz::store::expired
[`Commit::Recorded`]: rsauthnz::store::Commit::Recorded
[`Commit::Accepted`]: rsauthnz::store::Commit::Accepted
[`outcome_record`]: rsauthnz::store::outcome_record
[`outcome_of`]: rsauthnz::store::outcome_of
[`audit_record`]: rsauthnz::store::audit_record
[`intent_records`]: rsauthnz::store::intent_records
[`policy_key`]: rsauthnz::store::policy_key
[`Dependency`]: rsauthnz::transition::Dependency
[`Change`]: rsauthnz::transition::Change
[`Proposal::dependencies`]: rsauthnz::transition::Proposal::dependencies
[`Proposal::changes`]: rsauthnz::transition::Proposal::changes

## 5. Keep audit and outcome records for their retention

The records of [`audit_record`] and [`outcome_record`] have no end. When you write them, set their end to the
estimate of the audit time of the proposal ([`Audit::time`], [`Reading::estimate`]) plus
[`Declaration::outcome_retention`]. When the sum is past the largest `Duration`, set the end to `Duration::MAX`. A
store that keeps coarser times rounds the end up to its precision, by at most one second. The audit time is a
[`Reading`] of the clock of the application, so [`store::expire`] compares like times, and the suite can check the
end (selected on 2026-11-18).

The retention starts at the decision, not at the commit, so the binding keeps the records for the retention minus the
time from the decision to the commit (selected on 2026-11-18). Declare a retention that includes this time.

[`Store::outcome`] is a provided method. It reads the outcome record with [`Store::read`], so you implement nothing
for it. A lookup after the retention gives an unknown outcome.

[`Declaration::outcome_retention`]: rsauthnz::store::Declaration::outcome_retention
[`Audit::time`]: rsauthnz::transition::Audit::time
[`Reading`]: rsauthnz::time::Reading
[`Reading::estimate`]: rsauthnz::time::Reading::estimate
[`Store::outcome`]: rsauthnz::store::Store::outcome

## 6. Expire ended records

Implement [`Store::expire`]. It removes at most `limit` records of one kind whose end is before `before`, and it
gives their number. It removes no record of another kind, no record with no end, and no record whose end is at
`before` or later. Keep an index of the ends of each kind, so that the cost of a call follows `limit`, not the size
of the store.

The application runs [`store::expire`] in bounded passes. It calls [`Store::expire`] only for each kind that
[`Kind::ends`] names.

[`Store::expire`]: rsauthnz::store::Store::expire
[`store::expire`]: rsauthnz::store::expire
[`Kind::ends`]: rsauthnz::store::Kind::ends

## 7. Read one key prefix

Implement [`Store::range`]. It gives the first `limit` records whose key starts with `prefix` and comes after `after`,
in the byte order of the keys. With `None`, it starts at the prefix. It gives fewer records only when no more remain,
and never a record of another prefix. The keys of one prefix are one range of the key order, so an ordered index
reads them without a scan of other records.

The core reads two prefixes. [`Kind::key`] of an empty identifier is the prefix of a kind: the driver reads its
intents ([`Kind::Intent`]) at each start, and a worker of the application reads them after a crash. A local authority
reads its administrator bindings under a prefix of 33 bytes: the kind and the digest of the authority. A store that
partitions its keys can use those 33 bytes as the partition key.

[`Store::range`]: rsauthnz::store::Store::range
[`Kind::Intent`]: rsauthnz::store::Kind::Intent
[`Kind::key`]: rsauthnz::store::Kind::key

## 8. Keep the restore journal

A binding that supports restore implements [`Journal`]. The driver writes the record format, checks the hash chain,
and applies the rules ([`journal`]). The binding stores bytes.

1. Keep the journal outside the failure domain of the snapshots, and declare it in [`Restore::Journal`].
2. Implement [`Journal::append`]. Compare the request instance and `append.after()` at the journal in the same atomic write.
   Compare both the sequence and the link. Include entries that await sync.
   Store `append.entry()` and install `append.head()` together.
3. Implement [`Journal::sync`]. Check the request instance at the journal before confirming durability.
   Return `JournalWrite::Accepted` on success. A failed comparison in either primitive gives `JournalWrite::Conflict` without a write.
   An I/O failure stops the binding. A later sync cannot establish that an earlier failed sync preserved the bytes.
4. Implement [`Journal::read`]. It gives at most `limit` durable entries ([`Entry`]) after the sequence `after`, in
   the order of their sequences. Give no append whose sync did not return. Do not fill or renumber a gap.
5. After a crash or a failed sync, drop each append after the last sync that returned. The next append gets the
   sequence after the last durable entry.
6. Frame each entry, for example with its length and a checksum. Then a start after a crash finds a torn last
   append, which no sync made durable, and drops it.

When upgrading a raw-byte journal, stop the old writers and exclude pending raw appends before opening the conditional interface.
Derive the initial head from the last retained entry with `Mark::of(sequence, data)`.
Use `Mark::EMPTY` for a new, empty journal. Preserve the head separately if retention can remove its entry.
Keep the instance and head at the journal destination. A conditional update or the journal writer's lock can protect both comparisons.
One conditional append checks both fields. One sync can cover several accepted entries.
Run the conformance suite with restore enabled and check the result of `JournalFence`.

A binding with no journal declares [`Restore::Unsupported`]. It implements [`Journal`] with methods that give an
error, because the driver and the suite never call them.

[`Journal`]: rsauthnz::store::Journal
[`journal`]: rsauthnz::store::journal
[`Journal::append`]: rsauthnz::store::Journal::append
[`Journal::sync`]: rsauthnz::store::Journal::sync
[`Journal::read`]: rsauthnz::store::Journal::read
[`Entry`]: rsauthnz::store::Entry

## 9. Stop at each error

An error of a primitive ([`Store::Error`] or [`Journal::Error`]) is a crash. Keep one state for the binding and
all its handles:

1. After an error of any primitive, give an error from each primitive except [`Store::start`].
2. Serve again only after the next [`Store::start`].
3. Do not retry a primitive inside the binding.

A failed sync stops commits too. A confirmed transaction conflict returns [`Commit::Conflict`] or [`Inserted::Conflict`], according to the primitive.

[`Store::Error`]: rsauthnz::store::Store::Error
[`Journal::Error`]: rsauthnz::store::Journal::Error

## 10. Run the commit driver

The application drives the binding with [`Driver`]. [`Driver::effect`] gives the next primitive call, an [`Effect`].
Execute it on the binding, and give the [`Output`] to [`Driver::give`]. Give [`Output::Failed`] for an error. Do not
retry the primitive. This function is the same for each binding, and `cargo xtask test` compiles it:

```rust
use rsauthnz::store::driver::{self, Driver, Effect, Output};
use rsauthnz::store::{Journal, Store};

/// The output of the primitive call `effect` on `binding`. A failed primitive gives `Output::Failed`.
async fn execute<B: Store + Journal>(binding: &mut B, effect: Effect<'_>) -> Output {
    match effect {
        Effect::Start => binding.start().await.map_or(Output::Failed, Output::Started),
        Effect::Read(key) => Store::read(binding, key).await.map_or(Output::Failed, Output::Read),
        Effect::Commit(proposal, instance) => binding
            .commit(proposal, instance)
            .await
            .map_or(Output::Failed, Output::Committed),
        Effect::Expire(kind, before, limit) => binding
            .expire(kind, before, limit)
            .await
            .map_or(Output::Failed, Output::Expired),
        Effect::Range(prefix, after, limit) => binding
            .range(prefix, after, limit)
            .await
            .map_or(Output::Failed, Output::Range),
        Effect::Append(append, instance) => binding
            .append(append, instance)
            .await
            .map_or(Output::Failed, Output::Appended),
        Effect::Sync(instance) => binding.sync(instance).await.map_or(Output::Failed, Output::Synced),
        Effect::ReadJournal(after, limit) => Journal::read(binding, after, limit)
            .await
            .map_or(Output::Failed, Output::Journal),
    }
}

/// Executes the effects of `driver` on `binding` until the driver waits for a request.
async fn settle<B: Store + Journal>(driver: &mut Driver, binding: &mut B) -> Result<(), driver::Error> {
    while let Some(effect) = driver.effect() {
        let output = execute(binding, effect).await;
        driver.give(output)?;
    }
    Ok(())
}
```

1. Make the driver with [`Driver::new`], from the [`Profile`] of the declaration of the binding and the [`Limits`].
   It refuses a record bound below [`record_bytes_min`] ([step 1](#1-declare-the-guarantees)).
2. Call [`Driver::start`] at first and after each crash, then settle. [`Driver::status`] gives
   [`Status::Serving`] when the store serves.
3. After a restore of a snapshot, call [`Driver::restore`], never [`Driver::start`].
4. Submit each proposal with [`Driver::submit`] and its [`Plan`], settle, and take the answer with
   [`Driver::take`].
5. Look up a lost outcome with [`Driver::lookup`].

The documentation of the [`driver`] module gives each operation of the driver and its refusals.

[`driver`]: rsauthnz::store::driver
[`Driver::effect`]: rsauthnz::store::driver::Driver::effect
[`Driver::give`]: rsauthnz::store::driver::Driver::give
[`Driver::new`]: rsauthnz::store::driver::Driver::new
[`Driver::start`]: rsauthnz::store::driver::Driver::start
[`Driver::status`]: rsauthnz::store::driver::Driver::status
[`Driver::restore`]: rsauthnz::store::driver::Driver::restore
[`Driver::submit`]: rsauthnz::store::driver::Driver::submit
[`Driver::take`]: rsauthnz::store::driver::Driver::take
[`Driver::lookup`]: rsauthnz::store::driver::Driver::lookup
[`Status::Serving`]: rsauthnz::store::driver::Status::Serving
[`Plan`]: rsauthnz::store::driver::Plan
[`Effect`]: rsauthnz::store::driver::Effect
[`Output`]: rsauthnz::store::driver::Output
[`Output::Failed`]: rsauthnz::store::driver::Output::Failed

## 11. Implement the test controls

Implement [`Subject`] for the binding. It adds the controls of a test to the primitives. The clones of a subject are
handles of one binding, and each control acts on all of them. Two cases commit from two clones at the same time.

| Control | Implement it so that |
| --- | --- |
| [`Subject::inject`] | The next call of the primitive of the [`Fault`] takes the fault ([below](#faults)) |
| [`Subject::restart`] | The process is lost. The store loses what `crash_loss` states. The journal keeps each entry whose sync returned, and loses each later append. The counter of instance numbers stays. The binding serves again after a start |
| [`Subject::snapshot`] | It gives a consistent copy of the complete state of the store, the mark record included. The copy holds no journal entry |
| [`Subject::restore`] | The state of the store is the copy again, with a fresh instance number ([step 2](#2-keep-the-store-instance-number)). The restore does not stop the binding: the store takes commits at once, as a restored database does, and refuses each commit of an earlier start. The journal keeps its durable entries, and loses each append after the last sync |
| [`Subject::lose`] | The durable entries with a sequence in the range are gone. The next append still gets the sequence after the last durable entry before the loss, so no entry gets a lost sequence again |
| [`Subject::set_clock`] | Each commit reads the reading in place of the clock of the binding ([step 4](#4-commit-a-proposal)), until the next call. The suite sets the fixed time of each case |

### Faults

The suite gives these faults to [`Subject::inject`]. Each one is a crash of the binding: after it, the binding stops
as [step 9](#9-stop-at-each-error) states.

| [`Fault`] | The next call of | The binding writes | The call gives |
| --- | --- | --- | --- |
| [`Fault::CrashBeforeCommit`] | [`Store::commit`] | Nothing | An error |
| [`Fault::LostResponse`] | [`Store::commit`] | The commit, as a commit with no fault | An error |
| [`Fault::CrashAfterAppend`] | [`Journal::append`] | No durable entry: the crash loses the append | `JournalWrite::Accepted`. The next primitive gives an error |
| [`Fault::FailedSync`] | [`Journal::sync`] | No durable entry since the last sync | An error |

Most bindings can inject these faults in their own code, before or after the call to the store. A binding that
cannot inject them declares [`CrashInjection::Unsupported`], and carries its own evidence
([Crash evidence without crash injection](#crash-evidence-without-crash-injection)).

[`Subject`]: crate::suite::Subject
[`Subject::restart`]: crate::suite::Subject::restart
[`Subject::set_clock`]: crate::suite::Subject::set_clock
[`Subject::snapshot`]: crate::suite::Subject::snapshot
[`Subject::restore`]: crate::suite::Subject::restore
[`Subject::lose`]: crate::suite::Subject::lose
[`Fault`]: crate::suite::Fault
[`Fault::CrashBeforeCommit`]: crate::suite::Fault::CrashBeforeCommit
[`Fault::LostResponse`]: crate::suite::Fault::LostResponse
[`Fault::CrashAfterAppend`]: crate::suite::Fault::CrashAfterAppend
[`Fault::FailedSync`]: crate::suite::Fault::FailedSync
[`CrashInjection::Unsupported`]: rsauthnz::store::CrashInjection::Unsupported

## 12. Run the suite

Call [`suite::run`] in a test, in the executor of the binding. Give it a function that makes a new binding for each
case: an empty store and an empty journal that no other caller uses, for example in a new temporary directory or a
new database schema. The binding conforms when [`Report::failures`] is empty. Each [`Failure`] names its [`Case`]
and the check that failed. The documentation of the [conformance suite] gives a complete example.

[`suite::run`]: crate::suite::run
[`Report::failures`]: crate::suite::Report::failures
[`Failure`]: crate::suite::Failure
[`Case`]: crate::suite::Case

## Read a failed case

The suite runs the driver on the primitives of the binding. A failed case shows a primitive that does not keep its
step. This table gives the step that each case checks first:

| [`Case`] | Step |
| --- | --- |
| `Commit` | [4](#4-commit-a-proposal), [3](#3-read-one-record) |
| `DependencyConflict` | [4](#4-commit-a-proposal) |
| `Deadline` | [4](#4-commit-a-proposal), [11](#11-implement-the-test-controls) |
| `ReplayInsert` | [4](#the-replay-insert), [6](#6-expire-ended-records), [11](#11-implement-the-test-controls) |
| `ReplayCapacity` | [4](#the-replay-insert), [1](#1-declare-the-guarantees) |
| `ConcurrentConsumption` | [4](#4-commit-a-proposal), [1](#1-declare-the-guarantees), [11](#11-implement-the-test-controls) |
| `AbsenceRace` | [4](#4-commit-a-proposal), [1](#1-declare-the-guarantees), [11](#11-implement-the-test-controls) |
| `Expiry` | [6](#6-expire-ended-records) |
| `Range` | [7](#7-read-one-key-prefix) |
| `Fencing` | [2](#2-keep-the-store-instance-number), [4](#4-commit-a-proposal), [11](#11-implement-the-test-controls) |
| `Retention` | [5](#5-keep-audit-and-outcome-records-for-their-retention), [6](#6-expire-ended-records) |
| `LostResponse` | [4](#4-commit-a-proposal), [5](#5-keep-audit-and-outcome-records-for-their-retention), [9](#9-stop-at-each-error), [11](#11-implement-the-test-controls) |
| `FailedSync` | [8](#8-keep-the-restore-journal), [9](#9-stop-at-each-error), [11](#11-implement-the-test-controls) |
| `Restart` | [1](#1-declare-the-guarantees), [11](#11-implement-the-test-controls) |
| `CrashPoints` | [8](#8-keep-the-restore-journal), [9](#9-stop-at-each-error), [7](#7-read-one-key-prefix), [11](#11-implement-the-test-controls) |
| `RefusalVoid` | [8](#8-keep-the-restore-journal), [11](#11-implement-the-test-controls) |
| `RestoreJournal` | [8](#8-keep-the-restore-journal), [3](#3-read-one-record), [11](#11-implement-the-test-controls) |
| `RestoreFloors` | [8](#8-keep-the-restore-journal), [11](#11-implement-the-test-controls) |
| `RestoreRefusal` | [8](#8-keep-the-restore-journal), [11](#11-implement-the-test-controls) |
| `RestoreAnchors` | [8](#8-keep-the-restore-journal), [11](#11-implement-the-test-controls) |
| `RestoreCompletions` | [4](#4-commit-a-proposal), [8](#8-keep-the-restore-journal), [11](#11-implement-the-test-controls) |
| `RestoreEnds` | [8](#8-keep-the-restore-journal), [11](#11-implement-the-test-controls) |
| `StartAfterRestore` | [8](#8-keep-the-restore-journal), [11](#11-implement-the-test-controls) |
| `Bootstrap` | [4](#4-commit-a-proposal), [3](#3-read-one-record), [7](#7-read-one-key-prefix) |
| `Rebootstrap` | [4](#4-commit-a-proposal), [7](#7-read-one-key-prefix), [8](#8-keep-the-restore-journal), [11](#11-implement-the-test-controls) |

The failure messages of the cases name these effects of the driver on the primitives:

- **The floor before a commit.** A commit can write a counter value, such as a session generation, from
  [`Driver::allocate`]. When the value passes the durable floor, the driver appends a floor entry ([`Floor`]) and
  syncs before the commit. Thus a restore never gives a released value again.
- **The end entry before a commit.** Before a commit that removes authority, the driver appends an end entry and
  syncs. A restore applies it, so a snapshot cannot make an unlinked passkey or a revoked session valid again.
- **The creation entry before the answer.** After an accepted commit that creates an anchor, such as a passkey, the
  driver appends its creation entry and syncs. Only then does it answer. A lookup reports the commit only after the
  entry is durable.
- **The void of a refusal.** After a conflict, or the outcome record of another request, the driver appends a void
  of the end entry and syncs. Only then does it give the refusal. A restore ignores a voided entry, so the refusal stays true.
- **Reconciliation at each start.** After [`Store::start`], the driver reads the mark record and the journal after
  its mark. It writes the missing creation entry of each anchor commit that landed, and a void of each end entry
  whose commit did not land.
- **Restore.** [`Driver::restore`] applies each entry after the mark of the snapshot before the store serves. It
  ends each record that a fact ends, writes each anchor that a creation entry made, raises each floor, and ends each
  pending sign-in challenge and approval. Then it sets the replay floor.
- **The completion of in-doubt consumptions.** A consumption that pays for an anchor, such as an enrollment, is in
  doubt after a restore when the snapshot has no outcome record of it. The driver commits it again under its
  operation identity before the store serves.

The documentation of the [`journal`] module gives the entries and the rules.

[`Driver::allocate`]: rsauthnz::store::driver::Driver::allocate
[`Floor`]: rsauthnz::store::journal::Floor

## Crash evidence without crash injection

The suite skips each crash case of a binding that declares [`CrashInjection::Unsupported`]: `LostResponse`,
`FailedSync`, `CrashPoints`, and `RestoreCompletions`. It also skips the crash parts of `RefusalVoid`,
`RestoreAnchors`, and `Rebootstrap`. The author of such a binding gives evidence of the same outcomes:

1. A commit whose response is lost landed. After the next start, a lookup finds its outcome record and its audit.
2. A commit that crashed before it landed wrote nothing.
3. A failed sync stops the binding. After the next start, the journal holds only the entries whose sync returned.
4. After a crash at each effect of the driver, the next start gives the outcome of the case `CrashPoints`.

One method is to run the driver in a child process, and stop the process at random effects. Then start again, and
check each outcome.

## Disk durability

The suite runs in one process, so it cannot show that a durable commit or a sync survives the loss of power. That
evidence is about the backend, and its author owns it. Record the settings of the store that make a commit and a
sync durable when they return, and the evidence that the device keeps them.
