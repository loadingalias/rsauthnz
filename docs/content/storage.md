# Storage contract

rsauthnz stores nothing itself and ships no storage backend. The application chooses a store and implements a
storage binding: the primitives of `rsauthnz::store::Store`, and of `rsauthnz::store::Journal` when it supports
restore. The commit driver of the core orders the primitives. A binding executes each primitive and decides no step
of the protocol. [Propose a transition](transitions.md) gives the proposal that a commit takes.

This release has the contract, but no commit driver, memory binding, or conformance suite yet. Thus nothing in
rsauthnz calls a binding except the expiry pass `store::expire`.

## Declare the binding

A binding states its guarantees in a `Declaration`. `Profile::new(declaration)` accepts it or refuses it.

| `Declaration` field | Meaning | Refusal |
| --- | --- | --- |
| `isolation` | `Isolation::Serializable`, `Isolation::AtomicConditional` (one atomic step that checks the complete dependency set, absences included), or `Isolation::Weaker` (snapshot isolation or weaker) | `Error::Isolation` for `Weaker`: it permits write skew on an absence |
| `crash_loss` | `CrashLoss::Unsynced`: a crash loses only the writes whose commit or sync did not return. `CrashLoss::Everything`: the store is in the memory of the process | — |
| `outcome_retention` | The least time for which the binding keeps an outcome record. A lookup after it gives an unknown outcome | — |
| `crash_injection` | `CrashInjection::Supported` when the binding injects a crash at each commit point, or `Unsupported` | — |
| `restore` | `Restore::Unsupported`, or `Restore::Journal { location, failure_domain }` for a binding that implements `Journal`. The failure domain of the journal is outside that of the snapshots that it protects | — |
| `key_bytes_max` | The most bytes in a key that the binding stores | `Error::KeyBound` below 2048 (`transition::Key::BYTES_MAX`), the longest key of the core |
| `record_bytes_max` | The most bytes in the record form of a write and in the payload of an intent | `profile.admit(&proposal)` gives `Error::RecordBytes` for a longer one, before the commit |

## Primitives

Each method of `Store` and `Journal` returns a future, and the core runs no executor. A binding that does no I/O
gives futures that are ready at once. A binding with asynchronous I/O awaits it in its futures.

An error of a primitive is a crash. The binding stops serving and does not retry the primitive. It serves again
only after a start. The binding gives its own error type, `Store::Error` or `Journal::Error`.

| Primitive | Effect |
| --- | --- |
| `Store::declaration()` | Gives the `Declaration` |
| `Store::start()` | Writes the next store instance number (`Instance`) durably, before reconciliation, and gives it |
| `Store::read(&key)` | Gives the current `Record` of the key (`version`, `end`, and `data`), or `None`. It is a keyed read: it never scans other records |
| `Store::commit(&proposal, instance)` | The conditional atomic commit. See [Commit](#commit) |
| `Store::outcome(&id)` | Gives the outcome record (`transition::Operation`) of the operation identity, or `None` |
| `Store::expire(kind, before, limit)` | Removes at most `limit` records of `kind` whose end is before `before`, and gives their number |
| `Store::intents(after, limit)` | Gives at most `limit` intent records with a key after `after`, in key order, or from the first key for `None` |
| `Journal::append(&entry)` | Appends the entry after the last entry and gives its `Sequence`. The entry is durable only after a later sync returns |
| `Journal::sync()` | Makes each earlier append durable. A failed sync is a crash: a retry that succeeds does not show that the data is durable |
| `Journal::read(after, limit)` | Gives at most `limit` durable entries (`Entry`) after the sequence `after`, in sequence order |

## Commit

`Store::commit(&proposal, instance)` is the only primitive that writes state, audit, or an outcome record. In one
serializable step, or in one equivalent atomic step, it checks that:

1. `instance` is the current store instance number. Thus a commit from an earlier instance refuses after a start.
2. Each dependency of `proposal.dependencies()` holds: `Policy(version)`, `Version(key, version)`, and `Absent(key)`.
3. No outcome record has the operation identity of the proposal.

Then it writes each change of `proposal.changes()`, the audit, each intent record of `store::intent_records(&proposal)`,
and the outcome record `proposal.operation()` together. Otherwise it writes nothing.

| `Commit` | Meaning |
| --- | --- |
| `Accepted` | The commit wrote everything. It is durable when it returns |
| `Conflict` | A dependency or the instance number did not hold |
| `Recorded(record)` | The store has an outcome record of the operation identity. `record.answer(proposal.operation())` gives the outcome |

An error of the commit is a crash with an unknown outcome. The commit takes a proposal, so state changes cannot
commit without their audit and their outcome record. The rustdoc of `rsauthnz::store` shows it with a compiled
example and an example that does not compile.

## Record kinds

The first byte of a key names the kind of its record: `Kind::key(id)` makes the key, and `Kind::of(&key)` gives the
kind back. The records of two kinds with the same identifier have two keys.

| `Kind` | Record | `consumption()` |
| --- | --- | --- |
| `Credential` | A passkey, a CLI credential, or the credential of a workload or an agent | `None` |
| `ProviderLink` | The link of an account to the subject of an external identity provider | `None` |
| `Registration` | A pending passkey registration ceremony | `Pays::Anchor` |
| `SignIn` | A pending sign-in challenge | `Pays::Nothing` |
| `Login` | A pending login transaction of an external identity provider | `Pays::Anchor` |
| `CliEnrollment` | A pending enrollment request of a CLI | `Pays::Anchor` |
| `Invitation` | An invitation value | `Pays::Anchor` |
| `Session` | A session family and its current generation | `None` |
| `Recovery` | A recovery value | `Pays::Anchor` |
| `Bootstrap` | A bootstrap value of an authority | `Pays::Anchor` |
| `Administrator` | An administrator binding of an authority | `None` |
| `Agent` | An agent identity | `None` |
| `Grant` | A grant and its current revision | `None` |
| `Approval` | A one-use approval of an operation | `Pays::Nothing` |
| `Replay` | The replay record of one accepted signature | `None` |
| `ReplayFloor` | The replay floor of the store. Each replay insert reads it as a dependency | `None` |
| `Audit` | An audit record | `None` |
| `Outcome` | An outcome record | `None` |
| `Intent` | An effect intent that the application did not end yet | `None` |

`consumption()` states what the consumption of a one-use record pays for. The restore journal records a
consumption that pays for an anchor, and a restore completes it when it is in doubt. A consumption that pays for
nothing has no journal entry, and a restore ends each pending record of its kind.

## Effect intents

The commit writes each intent of a proposal as a record of `Kind::Intent`. `store::intent_records(&proposal)` gives
them: the key of each one is its operation identity and its index, and its record holds `intent.version()` and the
CBOR form `intent.to_cbor()`.

After a crash, a worker finds each intent with bounded reads of `Store::intents(after, limit)`, a read after the
other, and reads each one back with `Intent::from_cbor`. A change of the state of an intent is a commit: the
proposal reads the record at its version, and writes the intent at the version of its new state, which is later. After
the worker observes the end of the call, a commit ends the record (`Change::End`).

## Expiry

A record expires after the `end` of its write (`transition::Change::Write`). The binding sets the end of each audit
and outcome record from its retention. Expiry goes forward in bounded passes. This example is also the example of
`rsauthnz::store::expire`, and `cargo xtask test` compiles it:

```rust
use core::num::NonZeroUsize;

use rsauthnz::store::{self, ExpiryError, Progress, Store};
use rsauthnz::time::Reading;

/// At most 100 records of each kind in one pass.
const LIMIT: NonZeroUsize = NonZeroUsize::new(100).unwrap();

/// Removes each ended record, one bounded pass after the other.
async fn expire_all<S: Store>(binding: &mut S, now: Reading) -> Result<(), ExpiryError<S::Error>> {
    while store::expire(binding, now, LIMIT).await? == Progress::More {}
    Ok(())
}
```

One pass of `store::expire(binding, now, limit)` makes one `Store::expire` call for each kind that can end
(`kind.ends()`). No call goes to the provider links, administrator bindings, agent identities, the replay floor, or
the intents, because their records have no end. Each call removes
at most `limit` records whose end is before the earliest time of `now`, so a record that a check can still accept
stays. The pass gives `Progress::More` while a kind can have more ended records. A reading with no known bound
gives `ExpiryError::Time` and removes nothing. The host chooses when to run each pass, and its cost class is
`Mutate` ([Admit rsauthnz work](admission.md)).
