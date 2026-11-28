# Run the conformance suite

The conformance suite checks that a storage binding keeps the [storage contract](storage.md). It checks the
primitives of the binding, then runs the commit driver of the core on them. A binding that passes each case that its
declaration selects conforms, and its author can state that it conforms.

The suite is `rsauthnz_conformance::suite`, in the workspace member `rsauthnz-conformance`. The crate is not published
yet.

## Run the suite

[Write a storage binding](storage-binding.md) gives each step of a new binding in detail.

1. Implement `rsauthnz::store::Store` for the binding. Also implement `rsauthnz::store::Journal`. A binding with no
   journal declares `Restore::Unsupported`, and its `Journal` methods can give an error: the suite and the driver do
   not call them.
2. Implement `suite::Subject`: the controls of a test ([Implement the test controls](#implement-the-test-controls)).
3. In a test, call `suite::run(make)` in the executor of the binding. `make` gives a new binding for each case, with
   an empty store and an empty journal that no other caller uses.
4. Check the `Report`. The binding conforms when `report.failures` is empty. `report.skipped` lists each case that the
   declaration does not select.

`suite::run` is an `async` function, and the core runs no executor. The futures of the
[memory binding](memory-binding.md) are ready at their first poll, so one poll runs the suite on it. This example is
the rustdoc example of `rsauthnz_conformance::suite`, and `cargo xtask test` runs it:

```rust
use core::pin::pin;
use core::task::{Context, Poll, Waker};

use rsauthnz_conformance::memory::{Memory, Schedule};
use rsauthnz_conformance::suite;

let mut suite = pin!(suite::run(|| Memory::new(Schedule::None)));
let Poll::Ready(report) = suite.as_mut().poll(&mut Context::from_waker(Waker::noop())) else {
    unreachable!("the memory binding does no I/O");
};
assert!(report.failures.is_empty(), "{report}");
assert!(report.skipped.is_empty(), "{report}");
```

A failure names its case and the check that failed in it. For example, a binding whose commit checks an absence only
of a key that it writes gives:

```text
the case AbsenceRace failed: a grant change and a revocation that read the absence of each other's write both committed, or neither did
```

Before the cases, `Profile::new` checks the declaration. When the profile refuses it, each selected case fails with
the refusal.

## Implement the test controls

`Subject` extends `Store`, `Journal`, and `Clone`. The clones of a subject are handles of one binding. Concurrent cases
commit with two clones at the same time. Each control acts on the binding of all its clones.

| `Subject` item | Effect | The suite calls it |
| --- | --- | --- |
| `type Snapshot` | The state of the store that a snapshot keeps | — |
| `inject(fault)` | The next call of the primitive of `fault` takes the fault | Only when the declaration states `CrashInjection::Supported` |
| `restart()` | The loss of the process. The store loses what `Declaration::crash_loss` states, and the journal keeps each entry whose sync returned. The binding serves again after a start | For each binding |
| `snapshot()` | Gives a snapshot of the state of the store | Only when the declaration states `Restore::Journal` |
| `restore(&snapshot)` | Restores the state of the store under a fresh instance. The restore does not stop the binding: the store takes commits at once, as a restored database does, and refuses each commit of an earlier start. The journal keeps its durable entries, and loses each append after the last sync | Only when the declaration states `Restore::Journal` |
| `lose(sequences)` | Removes the durable journal entries with a sequence in the range. A later append does not get the sequence of a removed entry | Only when the declaration states `Restore::Journal` |
| `set_clock(now)` | Each commit reads `now` in place of the clock of the binding, until the next call. A binding for production reads the system clock with its bound | For each case: the suite sets the fixed time of the case |

The fault is a `rsauthnz_conformance::suite::Fault`, one of four:

| `Fault` | Primitive | The binding gives | Durable state after it |
| --- | --- | --- | --- |
| `CrashBeforeCommit` | `Store::commit` | An error | The commit wrote nothing |
| `LostResponse` | `Store::commit` | An error | The commit landed |
| `CrashAfterAppend` | `Journal::append` | `JournalWrite::Accepted`. The next primitive gives an error | The append is lost |
| `FailedSync` | `Journal::sync` | An error | No append since the last sync is durable |

A fault is a crash. After it, each primitive except `Store::start` gives an error until the next start.

## Cases

The declaration selects the cases. A case that injects a fault needs `CrashInjection::Supported`, and a case that uses
the journal needs `Restore::Journal`. Each property names the rule exercised by that case. [Design models](design-models.md)

| `Case` | Contract | Needs | Properties |
| --- | --- | --- | --- |
| `Commit` | A commit writes its changes, its intents, its audit record, and its outcome record together. A read of the `Kind::Audit` record of the operation gives the audit, and a second submission gets the outcome record | — | — |
| `DependencyConflict` | A commit conflicts and writes nothing when a policy version, a record version, or an absence does not hold. A commit whose dependencies hold commits | — | — |
| `ReplayInsert` | A replay insert writes its record with its end once, and a second insert of the key finds it. After expiry removed the record, an insert whose deadline the clock of the binding passed refuses, so a late insert never accepts a signature twice. After a start, an insert refuses until the replay floor of the new instance exists | — | `NoDoubleAccept` |
| `ReplayCapacity` | A replay insert refuses with `Inserted::Full` past the share of its key and past the capacity, while another share still has room | — | — |
| `Deadline` | A commit with a deadline reads the clock of the binding in its atomic step. A deadline after the latest time of the reading commits. A deadline at that latest time, or a reading with no bound, gives `Commit::Expired` and writes nothing. A second submission of a commit that landed gets its outcome record, also after its deadline | — | — |
| `ConcurrentConsumption` | Two consumptions of one value at the same time give one commit and one conflict | — | `OneUse`, `PendExact` |
| `AbsenceRace` | A grant change and a revocation race. The revocation writes its record, and the change reads its absence. Only one commits | — | — |
| `Expiry` | A stale expiry pass stops. Current expiry removes at most its limit of eligible records of its kind | — | `NoLiveRemoved` |
| `Range` | A range read gives the records of its prefix after its key, in key order, up to its limit. It gives no record of another prefix, such as the administrator binding of another authority | — | — |
| `Fencing` | An earlier instance cannot commit across a start, restart, or restore. A replaced driver preserves the original identities of in-flight and queued requests. A fresh writer can commit | — | `NoStaleCommit`, `PrimaryFence` |
| `JournalFence` | Two requests for one head produce one successor. A different link at the same sequence refuses. An earlier instance cannot append or confirm durability | Journal | — |
| `Retention` | A status read leaves the original request open. Audit and outcome records last through their declared end, rounded up by at most one second. After expiry removes the receipt, the issued credential still exists and lookup reports `Unknown` | — | `PassiveStatus` |
| `LostResponse` | A commit whose response is lost landed: after the next start, its outcome record and its audit are readable. A commit that crashed before it landed wrote nothing | Crash | `MissingOutcomeUnknown` |
| `FailedSync` | A failed sync gives its failure and stops the binding. No retried sync serves before a start, and no append since the last sync is durable | Crash, journal | — |
| `Restart` | After the loss of the process, the store keeps what its declaration states, and the driver serves again. A store that loses everything gets its anchors back from the journal | — | `Recovers` |
| `CrashPoints` | A crash at each commit point gives the outcome of the model after the next start: no entry, a void, or the creation entry. A lookup or an anchor change of the owner gets its answer only after the creation entry is durable | Crash, journal | `Recovers`, `AnchorKept` |
| `RefusalVoid` | A commit that gave its refusal leaves no entry that applies at a restore. After a crash between the refusal and its void, the outcome is unknown | Journal | `AnchorKept`, `RefusalHolds` |
| `RestoreJournal` | A restore from an old snapshot applies the journal: no unlinked passkey, revoked session, replaced grant revision, or revoked invitation is valid again. A signed request waits through the final journal sync. A replacement opens admission, and a missing outcome remains unknown | Journal | `NothingEndedValid`, `MissingOutcomeUnknown` |
| `RestoreFloors` | A restore raises each allocation floor above each released value, also from a snapshot of an abandoned history | Journal | `NoCounterReuse` |
| `RestoreRefusal` | A restore refuses a journal that has a gap, or that does not reach back to the mark of the snapshot | Journal | — |
| `RestoreAnchors` | A restore keeps each anchor that an acknowledged commit saw, so an account keeps a sign-in method. It adds no anchor whose commit did not land | Journal | `AnchorKept`, `AccountKeepsAnchorP`, `NoUncommittedAnchor` |
| `RestoreCompletions` | A restore completes an in-doubt bootstrap, recovery, invitation activation, and enrollment once, before it serves, also after a crash during the completions | Crash, journal | `AccountKeepsAnchorP`, `AdminKeptP`, `NoDoubtServing`, `OneUse` |
| `RestoreEnds` | An ordinary start finishes interrupted cleanup with zero consumptions to complete. Old challenges and approvals refuse. A fresh challenge survives delayed cleanup and the next start | Journal | `PrimaryFence` |
| `StartAfterRestore` | A normal start after a restore voids no entry that the restore applied | Journal | `NothingEndedValid` |
| `Bootstrap` | The [local authority](local-authority.md) on the binding: a bootstrap value of one authority refuses at another, and after its end. Two concurrent uses of one value give one commit and one conflict or refusal, and a used value refuses. A remote call is admitted only for a live administrator binding, with a proof over the pending challenge of the binding. An owner re-bootstrap gives a new administrator, which ends the earlier binding with an unlink. Two concurrent unlinks of the last two administrators give one commit, also when the mark of the journal passes the first one, and the last binding stays. The report gives each issue and each consumption | — | `OneUse`, `OneBootValid`, `AdminKeptP` |
| `Rebootstrap` | An owner re-bootstrap of the local authority ends the earlier value. A restore from a snapshot before it does not make the ended value valid again, and loses the new value. After a restore, the report gives the live binding of an issue after the snapshot, and that administrator unlinks an earlier one. The unlink of the last administrator still refuses. A lookup of a lost re-bootstrap shows its commit and no value, and the next issue ends that value. A restore completes an in-doubt bootstrap only when the snapshot holds its value and no re-bootstrap ended it, and its client then proves the possession of its key | Journal; the lost responses and the in-doubt bootstraps need crash | `OneBootValid`, `NothingEndedValid`, `AdminKeptP` |

## Limits

- `ConcurrentConsumption` and `AbsenceRace` decide two commits from one state, then run them at the same time. A
  binding that does not check the dependencies in its commit fails each run. A check that is not atomic with its
  write fails only when the two commits overlap in the store. Thus a pass does not prove the isolation of the store:
  the store owns that evidence, and the declaration states it.
- A binding without crash injection runs no crash case. It carries its own durability evidence.
- The journal cannot detect the loss of its own newest entries. `RestoreRefusal` removes entries that a later entry
  follows.
- The suite has no case of entries that commit out of their sequence order. The driver runs one operation at a time,
  so each commit follows the order of its journal entries. The replay of the entries gives one state in each order,
  and the permutation test of the journal rules checks it.
- `ReplayCapacity` inserts each record of the declared capacity. Declare a small capacity for the suite, such as the
  256 records of the file example binding.
