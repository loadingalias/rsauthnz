# Test with the memory binding

The memory binding is the reference of the [storage contract](storage.md) for tests and examples. It implements
`rsauthnz::store::Store` and `rsauthnz::store::Journal` in the memory of the process, and it injects faults at the
primitives. The same faults and the same calls give the same results at each run.

Use it only for tests and for conformance. Never use it as a production store:

- A loss of the process loses all its state.
- Its state grows with the commits and the appends of the caller. It has no limit of its own, other than the memory
  of the process.
- Expiry scans the records of one kind for ended records, because the binding keeps no index of ends. A production
  binding keeps such an index.

The binding is `rsauthnz_conformance::memory::Memory`, in the workspace member `rsauthnz-conformance`. The crate is
not published yet.

## Run a test with a fault

This example is the rustdoc example of `rsauthnz_conformance::memory`, and `cargo xtask test` runs it. The first
commit loses its response. The commit lands, the binding gives an error and stops, and a lookup after the next start
shows the commit:

```rust
use core::pin::pin;
use core::task::{Context, Poll, Waker};
use core::time::Duration;

use rsauthnz::cbor::Value;
use rsauthnz::id::{AuthorityVersion, Human, Id, Principal};
use rsauthnz::limits::Limits;
use rsauthnz::store::{Kind, Store};
use rsauthnz::time::{Reading, ReadingSource};
use rsauthnz::transition::{Audit, Change, Dependency, OperationId, Proposal};
use rsauthnz_conformance::memory::{Error, Fault, Memory, Schedule};

/// The output of a future of the memory binding.
fn ready<F: Future>(future: F) -> F::Output {
    match pin!(future).poll(&mut Context::from_waker(Waker::noop())) {
        Poll::Ready(output) => output,
        Poll::Pending => unreachable!("the memory binding does no I/O"),
    }
}

// The first commit loses its response.
let mut memory = Memory::new(Schedule::At(0, Fault::LostResponse));
let instance = ready(memory.start())?;

// The proposal creates a credential.
let audit = Audit {
    actor: Principal::Human(Id::<Human>::new("acme", "u-17")?),
    action: Id::new("acme.auth", "credential.enroll")?,
    time: Reading::new(Duration::from_secs(1_000), Some(Duration::from_secs(1)), ReadingSource::Caller),
};
let credential = Kind::Credential.key(b"c-4")?;
let mut proposal = Proposal::new(OperationId::new(b"op-1")?, audit, &Value::Null, Limits::default())?;
proposal.read(Dependency::Absent(credential.clone()))?;
proposal.change(Change::Write {
    key: credential,
    version: AuthorityVersion::new(Id::new("acme", "auth")?, &[1])?,
    end: None,
    data: Box::new(*b"the credential record"),
})?;

// The commit lands, and its response is lost. The binding stops until the next start.
assert_eq!(ready(memory.commit(&proposal, instance)), Err(Error::Crash(Fault::LostResponse)));
ready(memory.start())?;
let outcome = ready(memory.outcome(&proposal.operation().id))?;
assert_eq!(outcome.as_ref(), Some(proposal.operation()));
```

Each future of the binding is ready at its first poll, so a test needs no executor. A test that waits for the
futures in an executor gets the same results.

1. Make the binding with `Memory::new(schedule)`. A new binding is stopped.
2. Call `Store::start` to get the store instance number (`Instance`). Give it to each commit.
3. Call the primitives. After an error, call `Store::start` again, then check the state.

## Schedule faults

`Schedule` selects the faults:

| `Schedule` | Faults |
| --- | --- |
| `Schedule::None` | No fault |
| `Schedule::At(n, fault)` | `fault` at the call `n` of its primitive. The count starts at 0 when the binding is made, and a call to a stopped binding does not count |
| `Schedule::Seeded(seed)` | Each commit, append, and sync takes a fault with a chance of one in 8. Each fault of the primitive has the same chance. The draw of each call is the RapidHash of the call with the seed, so a seed gives the same faults at each run |

Each fault is a crash of the simulated store:

| `Fault` | Primitive | Result | Durable state after the crash |
| --- | --- | --- | --- |
| `CrashBeforeCommit` | `Store::commit` | `Err(Error::Crash(fault))` | The commit wrote nothing |
| `LostResponse` | `Store::commit` | `Err(Error::Crash(fault))` | The commit landed |
| `CrashAfterCommit` | `Store::commit` | The result of the commit. The next primitive gives the error | The commit landed when its result is `Accepted` |
| `DelayedCommit` | `Store::commit` | `Err(Error::Crash(fault))` | The commit arrives after the next start, with the earlier instance number, so it refuses and writes nothing |
| `CrashAfterAppend` | `Journal::append` | The sequence of the append. The next primitive gives the error | The append is lost |
| `FailedSync` | `Journal::sync` | `Err(Error::Crash(fault))` | No append since the last sync is durable |

After a crash, the store keeps each commit that landed, and the journal keeps each entry whose sync returned. The
crash loses each append after the last sync, and the next append gets the first sequence of the lost appends. Each
primitive except `Store::start` gives `Error::Crash(fault)` until the next start.

## Restart, restore, and the journal

The journal is in a simulated failure domain apart from the store and its snapshots. Thus a restart and a restore
do not change the durable entries of the journal.

| Operation | Effect |
| --- | --- |
| `memory.restart()` | The loss of the process. The store loses all its records: the policy, audit, outcome, and intent records too. The binding stops |
| `memory.snapshot(mark)` | Gives a `Snapshot` of the state of the store with the low-water mark `mark`, a `journal::Mark`: the sequence and the link of an entry. The caller states the mark, as `journal::low_water` gives it ([Restore journal](restore.md)) |
| `memory.restore(&snapshot)` | Restores the state of the store from the snapshot, and gives its low-water mark. The binding stops. A `History` from that mark refuses a journal of another history |
| `memory.lose(sequences)` | Removes the durable journal entries in the range `sequences`. `lose(..)` is the loss of the journal, and a smaller range is a gap. No later append gets the sequence of a removed entry |

A stopped binding gives `Error::Stopped` until the next `Store::start`. Each start gives a larger instance number for
the life of the binding, also after a restart and a restore. Thus a commit from each earlier start refuses.

## Share the binding between callers

`Memory` is a handle. Its clones share one binding, so give each concurrent caller its own clone. One mutex holds all
the state, so each primitive is one atomic step, and each commit is serializable. Two commits that read the absence
of one key give one commit and one conflict.

## Declaration

`Store::declaration` gives:

| Field | Value |
| --- | --- |
| `isolation` | `Isolation::Serializable` |
| `crash_loss` | `CrashLoss::Everything`: the store is in the memory of the process |
| `outcome_retention` | `Duration::MAX`: the binding has no clock, so outcome and audit records have no end |
| `crash_injection` | `CrashInjection::Supported` |
| `restore` | `Restore::Journal`, in the memory of the process, in a simulated domain apart from the store and its snapshots |
| `key_bytes_max` | 2048 (`transition::Key::BYTES_MAX`) |
| `record_bytes_max` | 65,536 (`Limits::default().bytes`). `Profile::admit` refuses a larger record before the commit |
