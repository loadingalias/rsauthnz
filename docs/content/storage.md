# Storage contract

rsauthnz stores nothing itself and ships no storage backend. The application chooses a store and implements a
storage binding: the primitives of `rsauthnz::store::Store`, and of `rsauthnz::store::Journal` when it supports
restore. The commit driver of the core orders the primitives. A binding executes each primitive and decides no step
of the protocol. [Propose a transition](transitions.md) gives the proposal that a commit takes.

This release has the contract, its reference binding (the [memory binding](memory-binding.md)), and the commit driver
`rsauthnz::store::driver`, which gives the binding each primitive call ([The commit driver](restore.md#the-commit-driver)).
The [conformance suite](conformance.md) checks a binding against the contract. [Write a storage
binding](storage-binding.md) gives the steps from the primitives to a binding that passes the suite.

## Declare the binding

A binding states its guarantees in a `Declaration`. `Profile::new(declaration)` accepts it or refuses it. The commit
driver takes only an accepted `Profile` (`Driver::new(profile, limits)`), so no driver exists for a refused binding.

| `Declaration` field | Meaning | Refusal |
| --- | --- | --- |
| `isolation` | `Isolation::Serializable`, `Isolation::AtomicConditional` (one atomic step that checks the complete dependency set, absences included), or `Isolation::Weaker` (snapshot isolation or weaker) | `Error::Isolation` for `Weaker`: it permits write skew on an absence |
| `crash_loss` | `CrashLoss::Unsynced`: a crash loses only the writes whose commit or sync did not return. `CrashLoss::Everything`: the store is in the memory of the process | — |
| `outcome_retention` | The least time after the audit time of its proposal for which the binding keeps an audit and an outcome record. A lookup after it gives an unknown outcome | — |
| `crash_injection` | `CrashInjection::Supported` when the binding injects a crash at each commit point, or `Unsupported` | — |
| `restore` | `Restore::Unsupported`, or `Restore::Journal { location, failure_domain }` for a binding that implements `Journal`. The failure domain of the journal is outside that of the snapshots that it protects. [Restore journal](restore.md) gives what the journal keeps | — |
| `key_bytes_max` | The most bytes in a key that the binding stores | `Error::KeyBound` below 2048 (`transition::Key::BYTES_MAX`), the longest key of the core |
| `signatures` | The `Capacity` of the replay records of HTTP signatures (`Kind::Signature`): `records_max`, the most records, and `share_max`, the most records of one agent key in one audience | `Error::Capacity` for a `share_max` of 0 or above `records_max` |
| `record_bytes_max` | The most bytes in one record that the binding stores: the record form of a write, an intent record, an audit record, or an outcome record. The audit record holds the key of each change | `Driver::new(profile, limits)` gives `driver::Error::RecordBound(least)` below `driver::record_bytes_min(limits)`, the longest record that the driver writes for itself. `profile.admit(&proposal)` gives `Error::RecordBytes` for a longer record. `driver.submit` calls it and refuses with `driver::Error::RecordBytes`, so the binding never gets the proposal |

## Primitives

Each method of `Store` and `Journal` returns a future, and the core runs no executor. A binding that does no I/O
gives futures that are ready at once. A binding with asynchronous I/O awaits it in its futures.

An error of a primitive is a crash. The binding stops serving and does not retry the primitive. It serves again
only after a start. The binding gives its own error type, `Store::Error` or `Journal::Error`.

| Primitive | Effect |
| --- | --- |
| `Store::declaration()` | Gives the `Declaration` |
| `Store::start()` | Writes the next store instance number (`Instance`) durably, before reconciliation, and gives it. Keep the number where a restore cannot lower it, for example in the failure domain of the journal. A restored lower number lets a delayed commit of the abandoned history land |
| `Store::read(&key)` | Gives the current `Record` of the key (`version`, `end`, and `data`), or `None`. It is a keyed read: it never scans other records |
| `Store::read_pair([&first, &second])` | Looks up both keys in one store state. Returns two results in request order. Each absent key gives `None`. A repeated key gives the same result twice |
| `Store::commit(&proposal, instance)` | The conditional atomic commit. See [Commit](#commit) |
| `Store::insert_replay(&insert)` | The atomic insert of the replay record of one HTTP signature, with no audit record. See [The replay insert](#the-replay-insert) |
| `Store::expire(kind, before, limit)` | Removes at most `limit` records of `kind` whose end is before `before`, and gives their number |
| `Store::outcome(&id)` | A provided method, so a binding does not implement it. It reads the outcome record of the operation identity with `Store::read`, and gives its `transition::Operation`, or `None`. See [Audit and outcome records](#audit-and-outcome-records) |
| `Store::range(&prefix, after, limit)` | Gives the first `limit` records whose key starts with `prefix` and comes after `after`, in key order, or from the prefix for `None`. It gives fewer only when no more remain, and never a record of another prefix. See [Range reads](#range-reads) |
| `Journal::append(&append, instance)` | Compares the instance and the full head at the journal. Stores the entry and its new head in one write. A failed comparison gives `JournalWrite::Conflict` |
| `Journal::sync(instance)` | Confirms durability of earlier appends in the same instance. An old instance gives `JournalWrite::Conflict`. An I/O error stops the binding |
| `Journal::read(after, limit)` | Gives at most `limit` durable entries (`Entry`) after the sequence `after`, in sequence order |

The entries of the journal have the record format of `rsauthnz::store::journal`. [Restore journal](restore.md) gives
the format, the chain check, and the rules of a restore.

## Commit

`Store::commit(&proposal, instance)` is the only primitive that writes state, audit, or an outcome record. In one
serializable step, or in one equivalent atomic step, it checks that:

1. `instance` is the current store instance number. Thus a commit from an earlier instance refuses after a start.
2. Each dependency of `proposal.dependencies()` holds. `Version(key, version)` holds when the record `key` is at
   `version`. `Policy(version)` holds when the policy record of its owner is at `version` ([Policy
   records](#policy-records)). `Absent(key)` holds when no record has the key.
3. No outcome record has the operation identity of the proposal: no record has the key of
   `store::outcome_record(&proposal)`.
4. For a proposal with a deadline (`proposal.deadline()`), the clock of the binding is before it. The binding reads
   its clock in the step, after the checks of the dependencies, and gives `Commit::Expired` when
   `store::expired(proposal.deadline(), reading)` holds. A reading before the step is not sufficient: the time from
   that reading to the write has no bound.
5. Each write of a new record of `Kind::Signature` fits the capacity: `signatures.admits(records, share)` holds for
   the count of these records and the count of its share (`store::share(&key)`). Otherwise the commit gives
   `Commit::Full`.

Then it writes each change of `proposal.changes()`, the audit record of `store::audit_record(&proposal)`, each intent
record of `store::intent_records(&proposal)`, and the outcome record of `store::outcome_record(&proposal)` together.
Otherwise it writes nothing.

| `Commit` | Meaning |
| --- | --- |
| `Accepted` | The commit wrote everything. It is durable when it returns |
| `Conflict` | A dependency or the instance number did not hold |
| `Expired` | The proposal has a deadline, and the clock of the binding can be at or after it, or has no bound. The driver gives `Refused(Error::Expired)` |
| `Full` | A new replay record of a signature does not fit the capacity. The driver gives `Refused(Error::Full)`, with the recovery `Restart` |
| `Recorded(record)` | The store has an outcome record of the operation identity, and `record` is its `transition::Operation` (`store::outcome_of`). The commit driver gives the outcome from it: the receipt of the first commit for the same request, or `Error::Reuse` |

An error of the commit is a crash with an unknown outcome. The commit takes a proposal, so state changes cannot
commit without their audit and their outcome record. The rustdoc of `rsauthnz::store` shows it with a compiled
example and an example that does not compile.

## Record kinds

The first byte of a key names the kind of its record: `Kind::key(id)` makes the key, and `Kind::of(&key)` gives the
kind back. The records of two kinds with the same identifier have two keys.

| `Kind` | Record | `consumption()` |
| --- | --- | --- |
| `Credential` | A passkey, or the issuance record of a credential or a receipt of the format: the record of its serial ([Issue a credential](credential-format.md#issue-a-credential)) | `None` |
| `ProviderLink` | The link of an account to the subject of an external identity provider | `None` |
| `Registration` | A pending passkey registration ceremony | `Pays::Anchor` |
| `SignIn` | A pending sign-in challenge, or the challenge of the next call of a [CLI](cli.md) | `Pays::Nothing` |
| `Login` | A pending login transaction of an external identity provider ([Sign in with an identity provider](provider-sign-in.md)) | `Pays::Anchor` |
| `CliEnrollment` | A pending enrollment request of a CLI, which a human approves in a browser ([Enroll the CLI from a browser](cli.md#enroll-the-cli-from-a-browser)) | `Pays::Anchor` |
| `Invitation` | An invitation value | `Pays::Anchor` |
| `Session` | A session family and its current generation ([Keep a browser session](sessions.md)) | `None` |
| `Recovery` | A recovery value | `Pays::Anchor` |
| `Bootstrap` | A bootstrap value of an authority | `Pays::Anchor` |
| `Administrator` | An administrator binding of an authority. It ends with its CLI credential, so expiry removes it | `None` |
| `Agent` | An agent identity: its owner, its public key, its name, and the verified workload of a hosted agent ([Enroll an agent](agent-enrollment.md)) | `None` |
| `Grant` | The grant of an agent at its current revision: its owner, audiences, permissions, deadline, and policy version. The last use of the grant is at the key of the grant with one more byte, 0: its revision and the start of its window ([Grant an agent access](grants.md#record-last-use)) | `None` |
| `Approval` | A one-use approval of an operation | `Pays::Nothing` |
| `Replay` | The replay record of the challenge of one passkey sign-in | `None` |
| `ReplayFloor` | The replay floor of the store: the reading of the start or restore that set it, and the instance number of the start that wrote it. The driver writes it at each start and each restore. A sign-in reads it as a dependency, and a replay insert reads it in its step | `None` |
| `Audit` | The audit record of a commit. Its key is the operation identity ([Audit and outcome records](#audit-and-outcome-records)) | `None` |
| `Outcome` | The outcome record of a commit. Its key is the operation identity ([Audit and outcome records](#audit-and-outcome-records)) | `None` |
| `Intent` | An effect intent that the application did not end yet | `None` |
| `Policy` | The current policy version of an owner ([Policy records](#policy-records)) | `None` |
| `Mark` | The journal mark of the store: the low-water mark of its state, whether a restore made the state, the number of its write, and the completions that a restore still owes. The commit driver writes it ([Restore journal](restore.md)) | `None` |
| `Local` | The record of a [local authority](local-authority.md): its host grant, its issuer key, and the log of its bootstrap values | `None` |
| `Issuer` | An issuer of workload credentials: its authority, its current key and its previous key, its audiences, and its ceiling ([Issue and manage workload credentials](workload.md)) | `None` |
| `Workload` | The registration of a workload: the workload, its registered proof key, and its generation | `None` |
| `Removal` | The removal mark of a passkey, at the identifier of its credential key. It ends after 400 days, and a restore can lose it: a sign-in then refuses, which is safe ([Remove a passkey](accounts.md#remove-a-passkey)) | `None` |
| `AccountState` | The newest recovery revision or enrollment revision of an account | `None` |
| `AgentEnrollment` | A pending enrollment request of an agent, which its owner approves in a browser ([Enroll an agent](agent-enrollment.md)) | `Pays::Nothing` |
| `Signature` | The replay record of one accepted HTTP signature of an agent: the share of the agent key in its audience, then the digest of the nonce ([Sign the requests of an agent](http-signatures.md#the-replay-store)) | `None` |

`consumption()` states what the consumption of a one-use record pays for. The restore journal records a
consumption that pays for an anchor, and a restore completes it when it is in doubt. A consumption that pays for
nothing has no journal entry, and a restore ends each pending record of its kind.

## Policy records

The current policy version of an owner is a record in the store, so the commit checks a policy dependency in the
same atomic step as each other dependency. `store::policy_key(&owner)` gives the key of the policy record of the
owner: `Kind::Policy` with the SHA-256 digest of the canonical CBOR form of the owner. The digest keeps the key short,
because an owner identifier can be longer than a key.

A policy change is a commit like each other transition. Its proposal reads the policy record at its current version,
or as absent for the first policy of the owner. Then it writes the record at the new version, which is later. After
that commit, each proposal that read the earlier policy version conflicts.

## Audit and outcome records

The commit writes the audit and the outcome record of its proposal as records. Their keys are `Kind::Audit` and
`Kind::Outcome` with the operation identity, so `Store::read` finds both records of each commit. Only the commit
writes them: `proposal.change` gives `transition::Error::Change` for a change of an audit or an outcome record.

`store::outcome_record(&proposal)` gives the key and the record of the outcome. The record form is the request
binding of `proposal.operation()`: 32 bytes. `Store::outcome(&id)` reads this record, and
`store::outcome_of(&id, &record)` gives its `transition::Operation`. A record in another form gives `None`.

`store::audit_record(&proposal)` gives the key and the record of the audit. The record form is the CBOR array
`["rsauthnz.store.audit.2", actor, owner, action, time, keys]`:

- `actor` and `action` are the canonical CBOR forms of `audit.actor` and `audit.action`.
- `owner` is the canonical CBOR form of the human owner of an agent actor (`proposal.owner()`). It is null for a
  human, a workload, and the enrollment request of an agent, which has no owner yet. Only rsauthnz sets it, from the
  identity record of the agent ([Check the request of an agent](authorization.md#check-the-request-of-an-agent)).
- `time` is `[estimate, bound, source]` of the reading `audit.time`. The estimate and the bound are
  `[seconds, nanoseconds]`, and the bound is null when it is unknown. The source is 1 for the system clock, 2 for the
  caller, and 0 for another source.
- `keys` is the key of each change of the proposal, in order.

The two records have no end. The binding sets the end of each one to the estimate of `audit.time` plus
`outcome_retention`, or to `Duration::MAX` when the sum is past it. A store that keeps coarser times rounds the end
up, by at most one second.

## Effect intents

The commit writes each intent of a proposal as a record of `Kind::Intent`. `store::intent_records(&proposal)` gives
them: the key of each one is its operation identity and its index, and its record holds `intent.version()` and the
CBOR form `intent.to_cbor()`.

After a crash, a worker finds each intent with bounded range reads of the prefix `Kind::Intent.key(&[])`
(`Store::range(&prefix, after, limit)`), a read after the other, and reads each one back with `Intent::from_cbor`. A change of the state of an intent is a commit: the
proposal reads the record at its version, and writes the intent at the version of its new state, which is later. After
the worker observes the end of the call, a commit ends the record (`Change::End`).

An intent of `Effect::Journal` belongs to the commit driver: it names the anchors whose creation entry the journal
still owes. A worker skips it.

## Range reads

A range read gives the records of one key prefix in key order. It reads only the keys of the prefix, so an ordered
index serves it without a scan of other records. The core reads these prefixes:

| Prefix | Records | Reader |
| --- | --- | --- |
| `Kind::Intent.key(&[])`: the kind byte | The effect intents | The driver at each start, and a worker after a crash |
| The kind byte of `Kind::Administrator` and the SHA-256 digest of a local authority: 33 bytes | The administrator bindings of the authority | The report, the issue, and the unlink of a [local authority](local-authority.md), and its open after a restore lost its record |
| That prefix and the SHA-256 digest of the authority and an administrator: 65 bytes | The bindings of the administrator | The bootstrap, the challenge, and the recovery of a credential of a [local authority](local-authority.md) |
| `Kind::Credential` and the current passkey prefix (33 bytes) | Current passkeys of one account and passkey site | [Manage passkeys](accounts.md) |
| `Kind::Credential` and the device prefix for the issuer, account, and recovery number (33 bytes) | Connected account CLIs | [List and disconnect a CLI](cli.md#list-and-disconnect-a-cli) |
| `Kind::AccountState` and the 32-byte scope | Newest account recovery revision or newest passkey or CLI enrollment revision | [Recover](recovery.md#recover) and [enroll a CLI](cli.md) |
| `Kind::Session` and the 16-byte locator | Browser sessions of the current account revision | [List sessions](sessions.md#sign-out-list-and-revoke) |

Recovery keys end with the bitwise complement of the big-endian revision number. A range of one record gives the newest revision.
The first recovery also writes a permanent marker for revision zero. Each later recovery replaces the previous revision with a new key.
Restore can therefore complete a second recovery from a snapshot before either one. Old session and CLI records keep their expiry.
Full recovery selects a new passkey prefix. Stored public keys under an earlier prefix cannot authenticate.

A store that partitions its keys can use the first 33 bytes of a key as its partition key. A shorter key is its own
partition key. Then each range read of the core reads one partition, except the read of the sessions of an account:
its prefix has 17 bytes, and each session key has 33, so it reads the partitions of each session of the account.

## The replay insert

`Store::insert_replay(&insert)` accepts the signature of one HTTP request once ([Sign the requests of an
agent](http-signatures.md#the-replay-store)). It is one atomic step, with no audit record, no outcome record, and no
commit driver, so the requests of many agents insert at the same time. In that step, in this order, the binding:

1. Reads the replay floor record (`store::floor_key()`). When `insert.admits(floor, instance)` does not hold for it and
   the current instance number, it gives `Inserted::Floor`. Thus no insert lands between a start or a restore and the
   write of its floor.
2. Gives `Inserted::Present` when a record has `insert.key()`: the signature is a repetition.
3. Counts the records of `Kind::Signature` and the records of `insert.share()`. When `signatures.admits(records,
   share)` does not hold, it gives `Inserted::Full`.
4. Reads its clock. When `store::expired(Some(insert.deadline()), reading)` holds, it gives `Inserted::Expired`.
5. Writes `insert.record()` at `insert.key()`, makes it durable, and gives `Inserted::Accepted`.

When contention aborts the transaction, return `Inserted::Conflict` only after the store confirms that this attempt wrote nothing.
The binding can keep serving. If the reply was lost, return a primitive error and stop the binding.
The insert outcome is unknown. The verifier refuses the request and releases no evidence.

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
(`kind.ends()`). No call goes to the provider links, administrator bindings, agent identities, the replay floor, the
intents, the policy records, the mark record, the records of local authorities, the issuers, or the workload
registrations, because their records have no end. Each call removes
at most `limit` records whose end is before the earliest time of `now`, so a record that a check can still accept
stays. The pass gives `Progress::More` while a kind can have more ended records. A reading with no known bound
gives `ExpiryError::Time` and removes nothing. The host chooses when to run each pass, and its cost class is
`Mutate` ([Admit rsauthnz work](admission.md)).
