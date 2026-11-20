# Issue and renew workload credentials

`rsauthnz::workload` gives a service or a host a short credential for one audience. The credential has the
registered proof key of the workload as its `cnf` key, so it is not a bearer token. An explicit issuer record
holds the authority that issues, and its ceiling limits each credential. The store records each credential and
its audit before the workload gets it. The audience verifies the credential locally, with no lookup at the
issuer.

## Before you start

You need these parts:

- A storage binding and the commit driver on it ([Storage contract](storage.md),
  [The commit driver](restore.md#the-commit-driver)).
- A custody that holds the issuer key ([Hold keys in custody](custody.md)).
- The policy of the application ([Authorize an operation](authorization.md)). It permits the first issuance and the
  renewal, as [The policy](#the-policy) gives.
- The public key of the workload. The workload makes its key in its own custody, and it keeps the private key.

## Register the issuer and the workload

Two records hold the authority. The application writes both with its own transitions, for example after an
administrator approves them. It also writes the [policy record](storage.md#policy-records) of the issuer authority.

| Record | Make it with | Key | Holds |
| --- | --- | --- | --- |
| Issuer | `Issuer::new(authority, key, audiences, ceiling)` | `Issuer::store_key(&authority)`: `Kind::Issuer` | The authority, its public key, its audiences, and its ceiling |
| Registration | `Registration::new(workload, key)` | `Registration::store_key(&workload)`: `Kind::Workload` | The workload and its registered proof key |

`to_record()` gives the record form of each, and `from_record(data, limits)` reads it back.

- The algorithm of the issuer key is the profile that each audience of the issuer declares
  ([Declare the profile of an audience](credential-format.md#declare-the-profile-of-an-audience)). The registered key
  must have the authentication of the issuer key. An audience of another profile needs another issuer record, with
  its own authority.
- An issuer has at most 16 audiences (`workload::AUDIENCES_MAX`). `Issuer::new` sorts them and drops a second equal
  audience.
- The `Ceiling` has two fields. `lifetime_max` is the longest lifetime of one credential. `not_after` is the latest
  end of any credential, as the time since the Unix epoch. The record keeps whole seconds.

## Issue the first credential

1. Read the issuer record and the registration record of the workload with `Store::read`.
2. Make the `Request`: the `OperationId` of the operation, `By::Issue(&evidence)` with the evidence of the
   principal that asks, the audience, and the lifetime. A `None` lifetime is one hour (`workload::LIFETIME_DEFAULT`),
   or `lifetime_max` when it is shorter.
3. Call `Pending::new(request, &issuer_record, &registration_record, &policy, &mut driver, now, limits)`.
4. Give the bytes of `pending.to_be_signed()` to custody. Custody signs them with the issuer key.
5. Call `pending.finish(&signature, &mut budget)`. It verifies the signature with the issuer key, and it puts the
   credential into the proposal. It gives the `Proposal` and an `Awaiting` value, which holds no credential.
6. Submit the proposal with `driver.submit(proposal, Plan::default())`, and run the driver.
7. Give the outcome of the commit to `awaiting.release(outcome)`. Only an accepted commit of this operation gives the
   `Credential`. Send `credential.as_bytes()` to the workload.

`Pending::new` does these checks before custody signs. It refuses at the first check that fails:

1. The audience must be an audience of the issuer.
2. The lifetime must be at most `lifetime_max`, and the end must be at most `not_after`. A request past the ceiling
   refuses. rsauthnz does not give a shorter credential in its place.
3. For a renewal, it checks the current credential and the proof ([Renew a credential](#renew-a-credential)).
4. `authz::check` checks the evidence for the action of the request on the resource of the workload.
5. The driver gives the serial: the next value of the `Kind::Credential` counter. Thus a restore from an older
   snapshot never gives one serial twice.

The proposal reads these dependencies, so a concurrent change between the decision and the commit gives a conflict:

| Dependency | Why |
| --- | --- |
| `Policy(version)` of the permit | A policy change refuses the issuance |
| `Version` of the issuer record | A change of the issuer key, its audiences, or its ceiling refuses the issuance |
| `Version` of the registration record | A change of the registered key refuses the issuance |
| `Absent` of the credential record | A serial commits once |

The commit writes the credential record (`workload::credential_key(serial)`), the audit record, and the outcome record
together. The credential record holds the issuer, the workload, the audience, and the end, but not the credential.
It ends when the credential ends, so expiry removes it.

## Renew a credential

The workload renews its credential at `credential.renew_at()`: half its lifetime after its issue time.

1. The issuer service gives the workload a challenge for one proof.
2. The workload signs a proof of possession of its key over the challenge, for its credential and its audience
   (`credential::ProofDraft`, [Prove possession](credential-format.md#prove-possession)).
3. The issuer service makes the `Request` with `By::Renew { credential, proof, challenge }` and the same audience.
   Then it follows the steps of [Issue the first credential](#issue-the-first-credential) from step 3.

For a renewal, `Pending::new` verifies the current credential with the profile of the issuer for the audience. The
credential must name the registered workload, and its `cnf` key must be the registered key. Then it checks the proof
of possession, and the evidence of the proof is the evidence of the policy check. A credential that ended refuses,
so an operator issues the first credential again.

A renewal gives a new serial with the same `cnf` key. The earlier credential stays valid until it ends.

rsauthnz does not store challenges. To consume the challenge in the same commit, add the read of its record and its
end to the proposal before you submit it: `proposal.read(...)` and `proposal.change(Change::End(key))`. A proof
that an attacker replays gives a credential for the registered key only, which the attacker cannot use.

## The policy

`Pending::new` calls `authz::check` with the action of the mode and the resource of the workload. The policy of the
application permits each one:

| Mode | Action | Principal of the evidence |
| --- | --- | --- |
| `Mode::Issue` (`By::Issue`) | `rsauthnz:workload.issue` (`Mode::Issue.action()`) | The principal that asks, for example an operator |
| `Mode::Renew` (`By::Renew`) | `rsauthnz:workload.renew` (`Mode::Renew.action()`) | The workload, from its proof |

The resource is `workload::resource(&workload)`: an `Id<Resource>` with the namespace and the value of the workload.
The proposal reads the policy version of the permit.

## Verify a credential at the audience

1. Make the profile with `issuer.profile(&audience, limits)`. The verifier makes the `Issuer` from its
   configuration. It does not read the store.
2. Call `profile.verify(credential, now, &mut budget)`. It takes no fetch input and looks up nothing.
3. Check a proof of possession with `verified.possession(&proof, &challenge, now, &mut budget)`. The evidence names
   `Principal::Workload`.

The profile fixes the purpose `rsauthnz:workload` (`workload::purpose()`). An artifact of another purpose of the
same issuer key refuses. [Verify a credential](credential-format.md#verify-a-credential) gives each check.

A verifier reads no revocation state. A revoked credential stays valid at a verifier until it ends. Thus the
lifetime of a credential is the longest time that a revocation needs to reach a verifier. Choose it with that cost.

## After a lost response

`awaiting.release` gives `Error::Unknown(operation)` when the commit can have occurred. The workload gets no
credential. rsauthnz does not try the operation again.

1. Look up the operation with `driver.lookup(operation)`.
2. For `Lookup::Absent`, nothing committed. Ask again, with the same operation identity or a new one.
3. For `Lookup::Committed` or `Lookup::Unknown`, the credential of that operation did not reach the workload, and no
   one has its bytes. Ask for a credential as a new operation, with a new `OperationId`.

A new proposal of the same request under the same identity, after its first commit, commits nothing. Its release
gives `Error::Committed`.

## Example

This example registers an issuer and a workload, issues the first credential, verifies it at its audience, and
renews it. rscrypto signs in place of custody. `operator` is the evidence of an operator, and `policy` permits each
request. The example is also the example of the `rsauthnz::workload` module documentation, and `cargo xtask test`
runs it:

```rust
use core::pin::pin;
use core::task::{Context, Poll, Waker};
use core::time::Duration;
use rsauthnz::cbor::Value;
use rsauthnz::cose::{Key, PublicKey, TrustedKey};
use rsauthnz::credential::ProofDraft;
use rsauthnz::crypto::Algorithm;
use rsauthnz::id::{AuthorityVersion, Id, Principal};
use rsauthnz::limits::{Limits, SignatureBudget};
use rsauthnz::store::driver::{Answer, Driver, Plan};
use rsauthnz::store::{self, Store};
use rsauthnz::time::{Reading, ReadingSource};
use rsauthnz::transition::{Audit, Change, Dependency, OperationId, Outcome, Proposal};
use rsauthnz::workload::{By, Ceiling, Issuer, Pending, Registration, Request};
use rsauthnz_conformance::memory::{Memory, Schedule};
use rsauthnz_conformance::suite::execute;
use rscrypto::auth::MlDsa65Ed25519;

type Failure = Box<dyn core::error::Error>;

/// The output of `future`. Each future of the memory binding is ready at its first poll.
fn ready<F: Future>(future: F) -> F::Output {
    let Poll::Ready(output) = pin!(future).poll(&mut Context::from_waker(Waker::noop())) else {
        unreachable!("the memory binding does no I/O")
    };
    output
}

/// Executes each effect of `driver` on the memory binding until it has none. A production binding does the same
/// with its own primitives.
fn settle(driver: &mut Driver, memory: &mut Memory) -> Result<(), Failure> {
    while let Some(effect) = driver.effect() {
        let output = ready(execute(memory, effect));
        driver.give(output)?;
    }
    Ok(())
}

/// Commits `proposal`, and gives its outcome.
fn commit(driver: &mut Driver, memory: &mut Memory, proposal: Proposal) -> Result<Outcome, Failure> {
    let ticket = driver.submit(proposal, Plan::default())?;
    settle(driver, memory)?;
    match driver.take(ticket) {
        Some(Answer::Outcome(outcome)) => Ok(outcome),
        answer => Err(format!("the commit gave {answer:?}").into()),
    }
}

fn trusted(public: PublicKey<'_>) -> Result<TrustedKey, rsauthnz::cose::Error> {
    TrustedKey::new(Algorithm::MlDsa65Ed25519, &Key { kid: None, alg: None, public })
}

// Custody holds the secret keys. Here rscrypto signs in place of custody. A fixed filler makes the keys
// reproducible. Use fresh randomness for real keys.
let (issuer_public, issuer_secret) = MlDsa65Ed25519::generate_keypair(|out| Ok(out.fill(1)))?;
let (runner_public, runner_secret) = MlDsa65Ed25519::generate_keypair(|out| Ok(out.fill(2)))?;
let (issuer_public, runner_public) = (issuer_public.to_bytes(), runner_public.to_bytes());
let now = Reading::new(Duration::from_secs(1_800_000_000), Some(Duration::from_secs(1)), ReadingSource::Caller);
let (authority, runner) = (Id::new("acme", "issuer")?, Id::new("acme", "runner-7")?);
let build = Id::new("acme", "build-api")?;
let mut memory = Memory::new(Schedule::None);
let mut driver = Driver::new(store::Profile::new(memory.declaration())?, Limits::default())?;
driver.start(now);
settle(&mut driver, &mut memory)?;

// 1. The application registers the issuer and the workload, and writes its policy version, in its own transition.
let issuer = Issuer::new(
    authority.clone(),
    PublicKey::MlDsa65Ed25519(&issuer_public),
    vec![build.clone()],
    Ceiling { lifetime_max: Duration::from_secs(3_600), not_after: now.estimate() + Duration::from_secs(86_400) },
)?;
let registration = Registration::new(runner.clone(), PublicKey::MlDsa65Ed25519(&runner_public))?;
let audit = Audit { actor: operator.subject().clone(), action: Id::new("acme", "workload.register")?, time: now };
let mut setup = Proposal::new(OperationId::new(b"register-1")?, audit, &Value::Null, Limits::default())?;
for (key, data) in [
    (store::policy_key(&authority), Box::from(*b"policy 1")),
    (Issuer::store_key(&authority), issuer.to_record()),
    (Registration::store_key(&runner), registration.to_record()),
] {
    setup.read(Dependency::Absent(key.clone()))?;
    setup.change(Change::Write { key, version: AuthorityVersion::new(authority.clone(), &[1])?, end: None, data })?;
}
assert!(matches!(commit(&mut driver, &mut memory, setup)?, Outcome::Accepted(_)));

// 2. An operator asks for the first credential. `policy` permits it `Mode::Issue`, and `operator` is its evidence.
let issuer_record = ready(memory.read(&Issuer::store_key(&authority)))?.ok_or("no issuer")?;
let registration_record = ready(memory.read(&Registration::store_key(&runner)))?.ok_or("no registration")?;
let operation = OperationId::new(b"issue-1")?;
let request = Request { operation, by: By::Issue(&operator), audience: &build, lifetime: None };
let (issuer_record, registration_record) = (&issuer_record, &registration_record);
let pending = Pending::new(request, issuer_record, registration_record, &policy, &mut driver, now, Limits::default())?;

// 3. Custody signs, and `finish` puts the credential into the proposal. Only the accepted commit releases it.
let budget = || SignatureBudget::new(&Limits::default());
let signature = issuer_secret.sign_deterministic(&pending.to_be_signed(), &[])?;
let (proposal, awaiting) = pending.finish(signature.as_bytes(), &mut budget())?;
let credential = awaiting.release(commit(&mut driver, &mut memory, proposal)?)?;

// 4. The audience verifies the credential locally and checks a proof by the registered key.
let runner_key = trusted(PublicKey::MlDsa65Ed25519(&runner_public))?;
let prove = |challenge: &[u8], now: Reading| -> Result<Vec<u8>, Failure> {
    let draft = ProofDraft::new(&runner_key, credential.as_bytes(), &build, challenge, now)?;
    let signature = runner_secret.sign_deterministic(&draft.to_be_signed(), &[])?;
    Ok(draft.finish(signature.as_bytes(), &mut budget())?)
};
let profile = issuer.profile(&build, Limits::default())?;
let verified = profile.verify(credential.as_bytes(), now, &mut budget())?;
let evidence = verified.possession(&prove(b"challenge-1", now)?, b"challenge-1", now, &mut budget())?;
assert_eq!(evidence.subject(), &Principal::Workload(runner.clone()));

// 5. At half its lifetime, the workload renews with its credential and a proof over the challenge of the issuer.
let later = Reading::new(credential.renew_at(), Some(Duration::from_secs(1)), ReadingSource::Caller);
let proof = prove(b"challenge-2", later)?;
let by = By::Renew { credential: credential.as_bytes(), proof: &proof, challenge: b"challenge-2" };
let request = Request { operation: OperationId::new(b"renew-1")?, by, audience: &build, lifetime: None };
let pending =
    Pending::new(request, issuer_record, registration_record, &policy, &mut driver, later, Limits::default())?;
let signature = issuer_secret.sign_deterministic(&pending.to_be_signed(), &[])?;
let (proposal, awaiting) = pending.finish(signature.as_bytes(), &mut budget())?;
let renewed = awaiting.release(commit(&mut driver, &mut memory, proposal)?)?;
assert!(renewed.serial() > credential.serial());
```

## Errors

Each refusal is a `workload::Error`. Refuse the request unless the table gives another recovery.

| Error | Cause | Recovery |
| --- | --- | --- |
| `Key(cose::Error)` | `Issuer::new` or `Registration::new` refused the key as a trusted key | Correct the key |
| `Audiences` | The issuer has more than 16 audiences | Use another issuer record |
| `Record` | A record is not the record form of its kind | Repair the record |
| `Audience` | The audience is not an audience of the issuer | Refuse |
| `Ceiling` | The lifetime is past `lifetime_max`, or the end is past `not_after` | Ask for a shorter lifetime, or give the issuer a new ceiling |
| `Possession` | The current credential of a renewal names another workload or another `cnf` key than the registration | Refuse |
| `Credential(credential::Error)` | The format refused the draft, the current credential, the proof, or the signature of custody | Refuse |
| `Refusal(authz::Refusal)` | The policy refused | Refuse |
| `Driver(driver::Error)` | The driver gave no serial | As the driver error gives |
| `Transition(transition::Error)` | The proposal or the commit refused | As `error.recovery()` gives |
| `Conflict` | A dependency changed before the commit, so nothing committed | Read the records again, and ask as a new operation |
| `Unknown(operation)` | The commit can have occurred | [After a lost response](#after-a-lost-response) |
| `Committed` | An earlier submission of the operation committed, so this one released nothing | Ask as a new operation |
| `Operation` | The outcome is of another operation | Give the outcome of this operation |

## Record forms

Each form is canonical CBOR ([Parser limits](parser-limits.md)). The first item names the form and its number.

| Record | Key | Form |
| --- | --- | --- |
| Issuer | `Kind::Issuer`, then the SHA-256 digest of the CBOR form of the authority | `["rsauthnz.workload.issuer.1", authority, key, audiences, lifetime_max, not_after]` |
| Registration | `Kind::Workload`, then the SHA-256 digest of the CBOR form of the workload | `["rsauthnz.workload.registration.1", workload, key]` |
| Credential | `Kind::Credential`, then the 8 bytes of the serial, the most significant byte first | `["rsauthnz.workload.credential.1", issuer, workload, audience, expires]` |

Each identifier has its CBOR form of [Vocabulary](vocabulary.md#cbor-forms). A key is the byte string of an encoded
`COSE_Key` with its `alg`. The times are whole seconds since the Unix epoch, and the lifetime is whole seconds. The
request binding of an operation holds `[workload, audience, lifetime]`, with `null` for no lifetime. The serial and
the times are not part of it.

## Limits

- A verifier reads no revocation state, so a credential stays valid until it ends.
- An issuer record holds one key. The credential has no `kid`.
