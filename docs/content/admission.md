# Admit rsauthnz work

rsauthnz puts each public operation in one cost class. The host admits each class separately, with its own bound
on concurrent and pending work. Then a flood of cheap refusals cannot delay verification, and slow provider work
cannot delay durable commits. rsauthnz does no admission itself. The host owns admission.

## Cost classes

`rsauthnz::limits::Class` has four classes:

| Class | Work | Example |
| --- | --- | --- |
| `Parse` | A cheap parse or refusal. The work is linear in input that the limit set bounds. It does no signature, KDF, storage, or network work | `cbor::decode`, `cose::Sign1::decode`, `id::Id::new`, `transition::Proposal::new` |
| `Verify` | Signature or KDF work on input that the parse admitted | `cose::Profile::verify`, `cose::Sign1::verify`, `cose::TrustedKey::new`, `custody::Handle::verify` |
| `Mutate` | One atomic commit or bounded expiry pass in the storage binding of the application | `store::expire` ([Storage contract](storage.md)) |
| `External` | Slow custody or provider work, such as a hardware key or an external identity provider | The operations of `custody::Custody` and `custody::FileCustody::open` ([Hold keys in custody](custody.md)) |

The documentation of each public operation names its class, in the form "Cost class: `Parse`". A method that
takes only `&self` and returns no `Result` reads a value that is already bounded. It names no class, unless it
does signature, KDF, or storage work.

## Admit each class

1. Give each class its own bound on concurrent work and its own bounded queue. Refuse new work when the queue is
   full.
2. Run `Parse` work on the request path. It is linear in bounded input.
3. Run `Verify` work in a pool that the host sizes for its CPU. A verifying operation such as
   `cose::Profile::verify` does its cheap checks first. An input over a bound refuses before a signature check.
4. Run `Mutate` and `External` work in their own pools, so that slow work in one cannot hold the other.

A passkey operation, such as `rp.sign_in`, takes the store and the commit driver for its whole call. A host with one
driver thus runs the verification and the commit of a sign-in in one queue. [Run the web example](web-example.md#limits)
shows such a host: one bounded queue, a share for each credential, a commit budget, and an expiry pass.

## The limit set

`rsauthnz::limits::Limits` is the one limit set of the crate. Each parser, each verifier, and each transition
proposal checks its input against it before expensive work. A refusal names the bound with
`rsauthnz::limits::Limit`. The fields of the codecs, their defaults, and their refusals are in [Parser
limits](parser-limits.md). A `cose::Profile` holds the limits of its artifacts. The fields `dependencies` and
`intents` bound a proposal, as [Propose a transition](transitions.md#limits) gives. The field `signature_checks`
bounds the signature checks of one artifact, as [Bound the signature
checks](verification.md#bound-the-signature-checks) gives.

A new bound joins `Limits` in the change that adds its first consumer. The bounds that come next are grants,
resource scopes, and the keys of a key set.

## Keyed reads

An ordinary operation reads current state only by key: the identifier of one principal, session, credential, or
record. It never scans all principals, sessions, audit records, or expiry records. Expiry and retention go forward
in bounded batches.
