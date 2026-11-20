# Propose a transition

A transition changes authority: it enrolls a credential, renews a session, issues a grant, or revokes one.
rsauthnz decides a transition with a pure function and gives a `rsauthnz::transition::Proposal`. Only the storage
binding of the application accepts a proposal. It checks each dependency of the proposal again and commits the
state changes, the audit, the effect intents, and the outcome record in one atomic commit. A proposal is not a
commit and grants no authority.

The commit driver commits a proposal: `driver.submit(proposal, plan)` gives a ticket, and `driver.take(ticket)`
gives the `Outcome` ([The commit driver](restore.md#the-commit-driver)). [Storage contract](storage.md) gives the
commit that a storage binding implements.

## Build a proposal

1. Start the proposal with `Proposal::new(id, audit, &request, limits)`. `id` is the `OperationId` of the
   operation. `audit` is the required `Audit`: the actor, the action of the transition, and the time of the
   decision. `request` is the canonical CBOR value of the bounded request.
2. Add each read of the decision with `proposal.read(dependency)`. Add the policy version, each record version,
   and each absence that the decision used, also when the transition does not change that record.
3. Add each state change with `proposal.change(change)`. A read of the proposal must allow it.
4. Add each notification, signer, or provider call that must survive a crash with `proposal.intend(intent)`.
5. Set a prepared artifact, for example the credential that `credential::Draft::finish` gives, with
   `proposal.prepare(prepared)?`. A `Prepared` value names its issuance record, and the proposal must already write
   that record at its version, for example with `draft.record(&mut proposal)`. A `Prepared` value has no accessor of
   its bytes. Only the receipt of the accepted commit gives them, with `receipt.artifact()`.
6. Set the deadline of the authority that the decision read, if it has one: `proposal.until(deadline)`. The
   proposal keeps its earliest deadline ([Deadlines](#deadlines)).

This example is also the example of the `rsauthnz::transition` module documentation, and `cargo xtask test` runs
it. The decision consumes an invitation and creates a credential:

```rust
use core::time::Duration;

use rsauthnz::cbor::Value;
use rsauthnz::id::{Authority, AuthorityVersion, Human, Id, Principal};
use rsauthnz::limits::Limits;
use rsauthnz::time::{Reading, ReadingSource};
use rsauthnz::transition::{Audit, Change, Dependency, Key, OperationId, Proposal};

let owner: Id<Authority> = Id::new("acme", "auth")?;
let version = |n: u64| AuthorityVersion::new(owner.clone(), &n.to_be_bytes());
let audit = Audit {
    actor: Principal::Human(Id::<Human>::new("acme", "u-17")?),
    action: Id::new("acme.auth", "credential.enroll")?,
    time: Reading::new(Duration::from_secs(1_000), Some(Duration::from_secs(1)), ReadingSource::Caller),
};
let invitation = Key::new(b"invitation/i-9")?;
let credential = Key::new(b"credential/c-4")?;
let request = Value::Array(vec![Value::Bytes(b"i-9"), Value::Bytes(b"c-4")]);

// The decision consumes the invitation and creates the credential. It reads both first.
let mut proposal = Proposal::new(OperationId::new(b"op-1")?, audit, &request, Limits::default())?;
proposal.read(Dependency::Version(invitation.clone(), version(3)?))?;
proposal.read(Dependency::Absent(credential.clone()))?;
proposal.change(Change::End(invitation))?;
proposal.change(Change::Write {
    key: credential,
    version: version(1)?,
    end: None,
    data: Box::new(*b"the credential record"),
})?;
assert_eq!(proposal.dependencies().len(), 2);
```

## Dependencies

A `Dependency` is one read of the decision. The commit checks each one in the same atomic step as the changes, so
a concurrent change between the decision and the commit gives a conflict.

| `Dependency` | The commit checks that |
| --- | --- |
| `Policy(version)` | The policy of the owner of `version` is at `version`: its [policy record](storage.md#policy-records) is at `version` |
| `Version(key, version)` | The record `key` is at `version` |
| `Absent(key)` | No record has the key `key`. A uniqueness condition is the absence of a record under a unique key, for example the provider link of one issuer and subject |

A `Key` names a record: 1 to 2048 opaque bytes (`Key::BYTES_MAX`), the largest partition key of DynamoDB. A key is
not a secret. A record that a secret finds has a keyed digest of the secret as its key.

`proposal.read` adds a second equal read only one time. A second read of the same policy or record with another
result gives `Error::Changed`: the state changed between the two reads, so the decision starts again.
`proposal.dependencies()` gives the reads in the order of the first read of each policy and record.

## State changes

A `Change` writes or ends one record. A read of the proposal must allow it, or `proposal.change` gives
`Error::Change`:

| `Change` | The read that allows it |
| --- | --- |
| `Write { key, version, end, data }` of a new record | `Absent(key)` |
| `Write { key, version, end, data }` of a record that exists | `Version(key, earlier)`, with `version` later than `earlier` and of the same owner |
| `End(key)`: a consumption of a one-use value, a revocation, or a removal | `Version(key, current)` |

The `end` of a write is the time since the Unix epoch after which expiry can remove the record, or `None`. Set it
past the last time that a check can accept the record.

One proposal changes each record one time. Thus two consumptions of one value cannot both commit: the second one
reads a version that the first one ended. A write cannot make an earlier version current again. The changes of a
proposal are at most `Limits::dependencies`.

## Operation identity and request binding

Each externally submitted transition has an `OperationId` of 1 to 64 bytes (`OperationId::BYTES_MAX`). The client
chooses it, for example 16 random bytes, or an existing ceremony or grant identity supplies it. The store keeps
one outcome record for each identity.

`proposal.operation()` gives the `Operation`: the identity and the request binding. The binding is the SHA-256
digest of the canonical CBOR form `["rsauthnz.transition.binding.1", actor, action, request]`. The same actor,
action, and request give the same binding in each process and each release that keeps this form. The binding
holds no request bytes, so the outcome record holds no secret of the request. `Debug` does not show the binding.
`Proposal::new` encodes `request` within the `limits` that you give it, and it refuses a request past them with
`Error::Request` before more work ([Parser limits](parser-limits.md#cbor)).

Put each fact that selects the effect of the request into `request`, such as the authority or the issuer. Then the
same identity under another authority or issuer is another request, and it refuses with `Error::Reuse`. The
operations of rsauthnz do this: each local operation binds its authority, and each workload operation binds its
issuer.

The outcome record is the `Operation` of the commit. When the store has an outcome record for the identity of a
submission, `record.answer(&submitted)` gives the answer:

- The same request gets `Outcome::Accepted` with the receipt of the first commit, and nothing commits again.
- Another actor, action, or request gets `Outcome::Refused(Error::Reuse)`.

## Outcomes and recovery

The commit of a proposal has one of four outcomes. `outcome.recovery()` gives the `Recovery` of the caller:

| `Outcome` | Meaning | `Recovery` |
| --- | --- | --- |
| `Accepted(receipt)` | The commit accepted the proposal | `None` |
| `Conflict` | A dependency changed before the commit. Nothing committed | `Restart`: read the current state again, and propose again as a new operation |
| `Refused(error)` | The commit refused the proposal. Nothing committed, and the refusal stays true | `error.recovery()` |
| `Unknown(operation)` | The commit can have occurred: its response was lost, or a restore lost its outcome record | `Lookup`: look up the outcome of the same operation identity |

Never submit the request of an unknown outcome as a new operation. The first attempt can have committed, so a
new operation can, for example, issue a second grant. A lookup of the same identity gives the first commit.

`receipt.artifact()` gives the prepared artifact. Only the acceptance of the exact proposal releases it: a
proposal has no accessor for it, and only a proposal that writes its issuance record takes it. The store never keeps
the artifact, so the receipt of a lookup has none. An artifact can be a bearer value, such as a bootstrap value, so
the memory of the artifact is cleared when the receipt drops. Read it in place, and clear each copy that you make.

## Deadlines

A decision can read authority with an end: a one-use value, a challenge, the credential of evidence, or a checked
scope (`authz::Checked::deadline`). `proposal.until(deadline)` gives the proposal that end. The commit driver asks
the executor for a fresh reading of the clock just before the commit (`Effect::Clock`, [The commit driver](restore.md#the-commit-driver)).
When the reading can be at or after the deadline, or has no bound, the commit does not run: the outcome is
`Refused(Error::Expired)`, and the driver voids the end entry of the proposal before the answer. A proposal with no
deadline gets no clock effect.

## Effect intents

Notification, signer, and provider calls are not part of the commit. An `Intent` records such a call in the
commit, so that the call survives a crash. The application calls the effect after the commit. [Storage
contract](storage.md#effect-intents) gives how a worker finds the stored intents and changes their state. An intent of
`Effect::Journal` belongs to the commit driver, and a worker skips it.

| `State` | Meaning |
| --- | --- |
| `Open` | The application can call the effect |
| `Cancelled` | `intent.cancel()` stopped new calls. A call can still be in progress, so the record stays |
| `Ended(Ended::Completed)` or `Ended(Ended::Returned)` | `intent.observe(ended)` recorded that the call completed, or that its resource came back or the call did not occur. The application can remove the record |

The first observed end stays. A cancel after an observed end changes nothing. A proposal holds at most
`Limits::intents` intents.

## Errors

Each `rsauthnz::transition::Error` is a small `Copy` value with no secret. `error.recovery()` gives its recovery.

| `Error` | Cause | `Recovery` |
| --- | --- | --- |
| `OperationId` | The operation identity has no bytes or more than 64 bytes | `Refuse` |
| `Key` | The key has no bytes or more than 2048 bytes | `Refuse` |
| `Request(error)` | The request has no CBOR encoding | `Refuse` |
| `Limit(Limit::Dependencies)` | A read past `Limits::dependencies` | `Refuse` |
| `Limit(Limit::Intents)` | An intent past `Limits::intents` | `Refuse` |
| `Changed` | The decision read the same policy or record twice, with two results | `Restart` |
| `Change` | No read of the proposal allows the change, or another change names its record | `Refuse` |
| `Reuse` | The operation identity has the outcome record of another request | `Refuse` |
| `LastAnchor` | The change ends the last sign-in method of an account, or the last administrator binding, that the restore journal records as live | `Refuse` |
| `Prepared` | The proposal has an artifact, or no change writes the issuance record of the artifact at its version | `Refuse` |
| `Expired` | The clock reading just before the commit can be at or after the deadline of the proposal, or it has no bound. Nothing committed | `Refuse` |

## Limits

| `Limits` field | Default | Bound |
| --- | --- | --- |
| `dependencies` | 64 | The reads of one proposal, and so its changes |
| `intents` | 8 | The effect intents of one proposal |

Each operation of `rsauthnz::transition` is in the cost class `Parse`. `Proposal::new` does one SHA-256 digest of
the bounded request. [Admit rsauthnz work](admission.md) gives the classes.

`Debug` of a proposal, a receipt, and an outcome shows the length of record data, intent payloads, and the
prepared artifact, and never their bytes. A version shows its coordinate, so no coordinate holds a secret or a
challenge: the version of a challenge record holds the SHA-256 digest of the challenge.
