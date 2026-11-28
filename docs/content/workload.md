# Issue and manage workload credentials

`rsauthnz::workload` gives a service or a host a short credential for one audience. The credential has the
registered proof key of the workload as its `cnf` key, so it is not a bearer token. An explicit issuer record
holds the authority that issues, and its ceiling limits each credential. The store records each credential and
its audit before the workload gets it. The audience verifies the credential locally, with no lookup at the
issuer. A rotation, a recovery on a replacement host, and a revocation each end the earlier credentials of the
workload in one commit.

## Before you start

You need these parts:

- A storage binding and the commit driver on it ([Storage contract](storage.md),
  [The commit driver](restore.md#the-commit-driver)).
- A custody that holds the issuer key ([Hold keys in custody](custody.md)).
- The policy of the application ([Authorize an operation](authorization.md)). It permits each operation, as
  [The policy](#the-policy) gives.
- The public key of the workload. The workload makes its key in its own custody, and it keeps the private key.

## Register the issuer and the workload

Two records hold the authority. The application adds their first writes to its own transition, for example after
an administrator approves them. It also writes the [policy record](storage.md#policy-records) of the issuer
authority. rsauthnz makes each later write of the two records, with a version from a counter of the commit driver.
Thus each later version is greater than the version before it, also after a restore.

| Record | Add its first write with | Key | Holds |
| --- | --- | --- | --- |
| Issuer | `Issuer::new(authority, key, audiences, ceiling)?.register(&mut proposal, &mut driver)` | `Issuer::store_key(&authority)`: `Kind::Issuer` | The authority, its current key and its previous key, its audiences, and its ceiling |
| Registration | `Registration::register(&mut proposal, workload, key, &issuer, &mut driver)` | `Registration::store_key(&workload)`: `Kind::Workload` | The workload, its registered proof key, its generation, and its revoked credentials |

Each `register` adds the absence of the record and its write to the proposal. `from_record(data, limits)` reads a
record. The authority of `issuer` owns the versions of the registration record, so the registration names its
issuer. An issuance of another issuer refuses with `Error::Issuer`, and a credential of another issuer refuses at a
verifier.

- The algorithm of the issuer key is the profile that each audience of the issuer declares
  ([Declare the profile of an audience](credential-format.md#declare-the-profile-of-an-audience)). The registered key
  must have the authentication of the issuer key. An audience of another profile needs another issuer record, with
  its own authority.
- An issuer has at most 16 audiences (`workload::AUDIENCES_MAX`). `Issuer::new` counts each audience that you give,
  also a second equal one, before it sorts them and drops a second equal audience.
- The `Ceiling` has two fields. `lifetime_max` is the longest lifetime of one credential. `not_after` is the latest
  end of any credential, as the time since the Unix epoch. The record keeps whole seconds.
- The generation is a serial. Each credential of the workload with a lower serial is dead. A new registration takes
  a new value of the `Kind::Credential` counter, so a credential of an earlier registration of the same workload
  never verifies again.

## Issue the first credential

1. Read the issuer record and the registration record of the workload with `Store::read`.
2. Make the `Request`: the `OperationId` of the operation, `By::Issue(&evidence)` with the evidence of the
   principal that asks, the audience, the lifetime, and `replace: None`. A `None` lifetime is one hour
   (`workload::LIFETIME_DEFAULT`), or `lifetime_max` when it is shorter.
3. Call `Pending::new(request, &issuer_record, &registration_record, &policy, &mut driver, now, limits)`.
4. Give the bytes of `pending.to_be_signed()` to custody. Custody signs them with the current issuer key.
5. Call `pending.finish(&signature, &mut budget)`. It verifies the signature with the issuer key, and it puts the
   credential into the proposal. It gives the `Proposal`, its `Plan`, and a `credential::Awaiting` value, which holds
   no credential.
6. Submit the proposal with `driver.submit(proposal, plan)`, and run the driver.
7. Give the outcome of the commit to `awaiting.release(outcome)`. Only an accepted commit of this operation gives the
   `credential::Released` credential. Send `credential.as_bytes()` to the workload. `Awaiting` keeps the SHA-256
   digest of its own credential, so the receipt of another issuance under the same operation refuses with
   `Release::Operation`. Thus the serial and the end of the released credential are always those of its bytes.
   [Release a credential](credential-format.md#release-a-credential) gives each refusal of the release.

`Pending::new` does these checks before custody signs. It refuses at the first check that fails:

1. Each challenge of the request has at most 8,192 bytes (`credential::MAX_BYTES`), or the request refuses with
   `Error::Credential(credential::Error::Size)` before more work.
2. The audience must be an audience of the issuer.
3. The lifetime must be at most `lifetime_max`, and the end must be at most `not_after`. A request past the ceiling
   refuses. rsauthnz does not give a shorter credential in its place.
4. For a renewal or a rotation, it checks the current credential and its proof ([Renew a
   credential](#renew-a-credential)).
5. For a rotation or a recovery, it checks the proof of the new key ([Rotate the proof key](#rotate-the-proof-key)).
6. `authz::check` checks the evidence for the action of the request on the resource of the workload.
7. The driver gives the serial: the next value of the `Kind::Credential` counter. Thus a restore from an older
   snapshot never gives one serial twice.

The proposal reads these dependencies, so a concurrent change between the decision and the commit gives a conflict:

| Dependency | Why |
| --- | --- |
| `Policy(version)` of the permit | A policy change refuses the issuance |
| `Version` of the issuer record | A rotation of the issuer key, or a change of its audiences or its ceiling, refuses the issuance |
| `Version` of the registration record | A rotation, a recovery, a revocation, or another issuance of the workload refuses the issuance |
| `Absent` of the issuance record | A serial commits once |

The commit writes the issuance record of the credential (`credential::record_key(serial)`,
[Issue a credential](credential-format.md#issue-a-credential)), a new version of the registration record, the audit
record, and the outcome record together. The issuance record holds the issuer, the workload, the audience, the
purpose, and the end, but not the credential. It ends when the credential ends, so expiry removes it. The proposal
has the deadline of its checked scope: the earliest end of the permit, of the maximum age of the evidence, and of the
credential of the evidence. A commit after it refuses, and the release gives
`Release::Refused(transition::Error::Expired)`.

Each issuance writes the registration record, so that an issuance and a revocation that race cannot both commit.
Two issuances of one workload at the same time conflict too. The release of the second one gives
`Release::Conflict`, and the workload asks again as a new operation. Read the registration record again before each request.

## Renew a credential

The workload renews its credential at `credential.renew_at()`: half its lifetime after its issue time.

1. The issuer service gives the workload a challenge for one proof.
2. The workload makes the binding of the challenge to its request:
   `workload::binding(challenge, &operation, &issuer_authority, &workload, &audience, None)`.
3. The workload signs a proof of possession of its key over that binding, for its credential and its audience
   (`credential::ProofDraft`, [Prove possession](credential-format.md#prove-possession)).
4. The issuer service makes the `Request` with `By::Renew { credential, proof, challenge }`, the same operation, and
   the same audience. Then it follows the steps of [Issue the first credential](#issue-the-first-credential) from
   step 3.

The binding is the SHA-256 digest of `["rsauthnz.workload.proof.1", challenge, operation, issuer, workload, audience,
kid]`, where `kid` is the COSE Key Thumbprint of the new key of a rotation or a recovery, or `null`. Each proof of a
request binds it, so a proof gives no authority for another operation, issuer, workload, audience, or new key.

For a renewal, `Pending::new` verifies the current credential with the profile of the issuer for the audience. The
credential must name the registered workload, and its `cnf` key must be the registered key. Its serial must not be
below the generation or revoked, so a revoked credential cannot renew. Then it checks the proof of possession, and the evidence
of the proof is the evidence of the policy check. A credential that ended refuses, so an operator issues the first
credential again.

A renewal gives a new serial with the same `cnf` key. The earlier credential stays valid until it ends.

rsauthnz does not store the challenges of a workload. To consume the challenge in the same commit, add the read of its record and its
end to the proposal before you submit it: `proposal.read(...)` and `proposal.change(Change::End(key))`. A proof
that an attacker replays gives a credential for the registered key only, which the attacker cannot use.

## Rotate the proof key

The workload replaces its registered key with a new key that it holds.

1. The workload makes the new key in its custody.
2. The issuer service gives the workload two challenges, one for each proof.
3. The workload signs a proof by its current key over its credential, as for a renewal, over
   `workload::binding(challenge, &operation, &issuer_authority, &workload, &audience, Some(&new_key))`. Thus the current
   key signs the choice of the new key.
4. The workload makes the key binding: `let key_binding = workload::key_binding(&workload, &new_key)`.
5. The workload signs a proof by its new key over the key binding and the binding of the second challenge, for the
   audience of the request: `ProofDraft::new(&new_key, &key_binding, &audience, &bound, now)`, where `bound` is
   `workload::binding(new_challenge, &operation, &issuer_authority, &workload, &audience, Some(&new_key))`.
6. The issuer service makes the `Request` with `By::Renew { .. }` and
   `replace: Some(Replace { key: new_key, proof, challenge: new_challenge })`.
7. The issuer service follows the steps of [Issue the first credential](#issue-the-first-credential) from step 3.

The key binding is the canonical CBOR array `["rsauthnz.workload.key.1", workload, kid]`, where `kid` is the COSE Key
Thumbprint of the new key. The proof binds its SHA-256 digest, the audience, and the binding of the challenge. Thus,
as for a certificate signing request, the issuer binds no key that the workload does not hold. A new key that is the
registered key refuses with `Error::Unchanged`.

The commit writes the new key to the registration, and it raises the generation to the serial of the new
credential. Thus each earlier credential of the workload is dead. A renewal with the old key refuses. A verifier
that reads the current registration refuses the credentials of the old key.

## Recover a workload on a replacement host

When a host is lost, an operator moves the workload to a new host under the authority of the issuer.

1. The new host makes its key in its custody.
2. The issuer service gives the new host a challenge.
3. The new host signs a proof by its key over the key binding and the binding of the challenge, as in steps 4 and 5
   of [Rotate the proof key](#rotate-the-proof-key).
   The new key must not be the registered key: the recovery ends the key of the old host, so that key refuses with
   `Error::Unchanged`.
4. The operator asks with `By::Issue(&evidence)` and `replace: Some(Replace { key, proof, challenge })`.
5. The operator follows the steps of [Issue the first credential](#issue-the-first-credential) from step 3.

The policy must permit the operator `Mode::Recover` on the resource of the workload. One commit issues the first
credential of the new host and raises the generation. Thus each credential of the old host is dead in the same
commit. A recovery that cannot revoke refuses, and it releases nothing. For example, a renewal of the old host
after the read changes the registration, so the commit gives `Error::Conflict`. Read the records again, and
recover as a new operation.

## Revoke credentials

`Revocation { operation, by: &evidence, target }` ends credentials of a workload with no new credential. The
policy must permit the principal `Mode::Revoke` on the resource of the workload.

| `Target` | Ends |
| --- | --- |
| `Target::Credential(serial, &record)` | The credential of this serial, and no other. `record` is its issuance record, from a keyed read of `credential::record_key(serial)` |
| `Target::All` | Each credential of the workload that a commit before the revocation released |

1. Read the registration record of the workload, and for one credential its issuance record.
2. Call `revocation.proposal(&registration_record, &policy, &mut driver, now, limits)`. It gives the `Proposal` and
   its `Plan`.
3. Submit the proposal with the plan, and run the driver. An accepted outcome is the revocation.

A revocation of one credential checks that its issuance record names the issuer of the registration, the workload,
and the workload purpose, and that the credential did not end. Otherwise it refuses with `Error::Target`. Its commit
ends the issuance record and adds the serial and the end of the credential to the registration. The registration
holds at most `workload::REVOKED_MAX` (16) revoked credentials that did not end, and a credential leaves the list when
it ends. One more refuses with `Error::Revocations`: revoke all credentials. A revocation of all credentials raises
the generation. The registered key stays, so an operator can issue a new credential after the revocation.

## Rotate the issuer key

`IssuerRotation { operation, by: &evidence, key, retire }` gives the issuer a new current key. The new key has the
algorithm of the current key. The policy must permit the principal `Mode::RotateIssuer` on
`workload::issuer_resource(&authority)`.

1. Enroll the new key in custody. Keep the old key until the rotation commits.
2. Read the issuer record, and call `rotation.proposal(&issuer_record, &policy, &mut driver, now, limits)`.
3. Submit the proposal with its plan, and run the driver. After the commit, custody signs each new credential with
   the new key. Then delete the old key from custody: a verification needs only its public key, which the issuer
   record keeps.

| `Retire` | The old key |
| --- | --- |
| `Retire::AfterLifetime` | Becomes the previous key until its end: the lesser of the rotation time plus `lifetime_max` and `not_after`. After its end, it verifies nothing. Use it for a routine rotation |
| `Retire::Now` | Refuses at once, and so does an earlier previous key. Use it for a key that an attacker can have |

The new key must not be the current key or the previous key: such a key refuses with `Error::Unchanged`.

Each credential names its issuer key with its `kid` ([The format](credential-format.md#the-format)), and the
profile of the issuer holds the current key and the previous key. A credential that names no key of the profile
refuses with `cose::Error::KeyId`. A routine rotation while the previous key still verifies refuses with
`Error::Overlap { until }`. Rotate at `until` or later, or with `Retire::Now`.

## The policy

Each operation calls `authz::check` with the action of its mode. The policy of the application permits each one:

| Mode | Action | Request | Principal of the evidence | Resource |
| --- | --- | --- | --- | --- |
| `Mode::Issue` | `rsauthnz:workload.issue` | `By::Issue`, no `replace` | The principal that asks, for example an operator | The workload |
| `Mode::Renew` | `rsauthnz:workload.renew` | `By::Renew`, no `replace` | The workload, from its proof | The workload |
| `Mode::Rotate` | `rsauthnz:workload.rotate` | `By::Renew` with `replace` | The workload, from its proof | The workload |
| `Mode::Recover` | `rsauthnz:workload.recover` | `By::Issue` with `replace` | The operator | The workload |
| `Mode::Revoke` | `rsauthnz:workload.revoke` | `Revocation` | The principal that revokes | The workload |
| `Mode::RotateIssuer` | `rsauthnz:workload.issuer.rotate` | `IssuerRotation` | The principal that rotates | The issuer |

`mode.action()` gives each action, and `request.mode()` gives the mode of a `Request`. The resource of a workload is
`workload::resource(&workload)`. The resource of an issuer is `workload::issuer_resource(&authority)`. Each is an
`Id<Resource>` with the namespace and the value of the identifier. The proposal reads the policy version of the
permit.

## Verify a credential at the audience

1. Make the profile with `issuer.profile(&audience, limits)`. It holds the current key and the previous key of the
   issuer, and the `kid` of the credential selects one of them.
2. Call `profile.verify(credential, now, &mut budget)`. It takes no fetch input and looks up nothing.
3. Check a proof of possession with `verified.possession(&proof, &challenge, now, &mut budget)`. The evidence names
   `Principal::Workload`.

The profile fixes the purpose `rsauthnz:workload` (`workload::purpose()`). An artifact of another purpose of the
same issuer key refuses. [Verify a credential](credential-format.md#verify-a-credential) gives each check.

A verifier chooses what it reads:

| Verifier | Reads | Refuses a credential that a rotation, a recovery, or a revocation ended |
| --- | --- | --- |
| Reads the current state | The issuer record, to make `Issuer`, and the registration record of the workload of the credential | At once |
| Reads a trust snapshot | The issuers and the registrations of a signed snapshot of the authority ([Refresh trust with snapshots](trust-snapshots.md)) | After the refresh that installs a snapshot issued after the change |
| Reads nothing | Its configuration, to make `Issuer` with `Issuer::new`. During a routine issuer rotation, it adds the previous key with `profile.with_previous(previous_key, until)` | When the credential ends |

A verifier that reads the current state makes two keyed reads, and then calls
`workload::admits(&verified, registration_record.as_ref(), limits)`. The credential must be a workload credential of
the issuer of the registration, for its workload, with the registered key as its `cnf` key. It gives
`Error::Possession` for another purpose, issuer, workload, or `cnf` key, such as a signed receipt with no `cnf` key.
It gives `Error::Revoked` for a serial below the generation or revoked, and `Error::Unregistered` for no record. The
check is local, and it makes no other read. For a verifier that reads nothing, the lifetime of a credential is the
longest time that a revocation needs to reach it. Choose the lifetime with that cost.

## After a lost response

`awaiting.release` gives `Release::Unknown(operation)` when the commit can have occurred. The workload gets no
credential. rsauthnz does not try the operation again.

1. Keep the original operation and look it up with `driver.lookup(operation)`.
2. For `Lookup::Committed`, record that the operation succeeded. A receipt contains no credential bytes.
3. For `Lookup::Unknown`, keep the operation unresolved. A missing receipt can mean an unfinished write, expiry, or restore.
4. For `Lookup::Refused`, follow the error. A request binding mismatch means that another request owns the identity.

If a confirmed issuance lost its credential bytes, the operator can request a replacement as a new operation.
If a confirmed workload recovery lost its credential bytes, a new recovery also ends the credential from the earlier recovery.
Use the same lookup for a revocation or an issuer rotation. A missing receipt gives no instruction to repeat either change.

## After a restore

The restore journal records the end of each version that a rotation, a recovery, a revocation, or an issuer
rotation replaced ([Restore](restore.md)). A restore from a snapshot older than such a change ends that registration
or issuer record, because the snapshot holds only its earlier version. No credential of the workload then verifies
at a verifier that reads the current state (`Error::Unregistered`), and the issuer cannot issue. An operator
registers the workload or the issuer again. The new registration has a new generation, so a revoked credential stays
refused. This is the safe direction: a restore never makes an ended credential valid again.

## Example

This example registers an issuer and a workload, and it issues the first credential. Then it verifies the credential
at its audience, renews it, and recovers the workload on a replacement host. rscrypto signs in place of custody. `operator` is the evidence
of an operator, and `policy` permits each request. The example is also the example of the `rsauthnz::workload`
module documentation, and `cargo xtask test` runs it:

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
use rsauthnz::workload::{self, By, Ceiling, Issuer, Pending, Registration, Replace, Request};
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

/// Commits `proposal` with `plan`, and gives its outcome.
fn commit(driver: &mut Driver, memory: &mut Memory, proposal: Proposal, plan: Plan) -> Result<Outcome, Failure> {
    let ticket = driver.submit(proposal, plan)?;
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
let audit = Audit { actor: operator.subject().clone(), action: Id::new("acme", "workload.register")?, time: now };
let mut setup = Proposal::new(OperationId::new(b"register-1")?, audit, &Value::Null, Limits::default())?;
let policy_key = store::policy_key(&authority);
setup.read(Dependency::Absent(policy_key.clone()))?;
let version = AuthorityVersion::new(authority.clone(), &[1])?;
setup.change(Change::Write { key: policy_key, version, end: None, data: Box::from(*b"policy 1") })?;
issuer.register(&mut setup, &mut driver)?;
let runner_key = PublicKey::MlDsa65Ed25519(&runner_public);
Registration::register(&mut setup, runner.clone(), runner_key, &issuer, &mut driver)?;
assert!(matches!(commit(&mut driver, &mut memory, setup, Plan::default())?, Outcome::Accepted(_)));

// 2. An operator asks for the first credential. `policy` permits it `Mode::Issue`, and `operator` is its evidence.
let issuer_record = ready(memory.read(&Issuer::store_key(&authority)))?.ok_or("no issuer")?;
let registration_record = ready(memory.read(&Registration::store_key(&runner)))?.ok_or("no registration")?;
let operation = OperationId::new(b"issue-1")?;
let request = Request { operation, by: By::Issue(&operator), audience: &build, lifetime: None, replace: None };
let pending =
    Pending::new(request, &issuer_record, &registration_record, &policy, &mut driver, now, Limits::default())?;

// 3. Custody signs, and `finish` puts the credential into the proposal. Only the accepted commit releases it.
let budget = || SignatureBudget::new(&Limits::default());
let signature = issuer_secret.sign_deterministic(&pending.to_be_signed(), &[])?;
let (proposal, plan, awaiting) = pending.finish(signature.as_bytes(), &mut budget())?;
let credential = awaiting.release(commit(&mut driver, &mut memory, proposal, plan)?)?;

// 4. The audience verifies the credential locally and checks a proof by the registered key. A verifier that reads
// the current registration also refuses a credential that a rotation, a recovery, or a revocation ended.
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
let current = ready(memory.read(&Registration::store_key(&runner)))?;
workload::admits(&verified, current.as_ref(), Limits::default())?;

// 5. At half its lifetime, the workload renews with its credential and a proof over the binding of the challenge of
// the issuer to its request. Each issuance writes the registration, so read it again.
let later = Reading::new(credential.renew_at(), Some(Duration::from_secs(1)), ReadingSource::Caller);
let operation = OperationId::new(b"renew-1")?;
let proof = prove(&workload::binding(b"challenge-2", &operation, &authority, &runner, &build, None), later)?;
let by = By::Renew { credential: credential.as_bytes(), proof: &proof, challenge: b"challenge-2" };
let request = Request { operation, by, audience: &build, lifetime: None, replace: None };
let registration_record = current.ok_or("no registration")?;
let pending =
    Pending::new(request, &issuer_record, &registration_record, &policy, &mut driver, later, Limits::default())?;
let signature = issuer_secret.sign_deterministic(&pending.to_be_signed(), &[])?;
let (proposal, plan, awaiting) = pending.finish(signature.as_bytes(), &mut budget())?;
let renewed = awaiting.release(commit(&mut driver, &mut memory, proposal, plan)?)?;
assert!(renewed.serial() > credential.serial());

// 6. The host is lost. The operator recovers the workload on a new host, which proves its new key over the key
// binding and the binding of its challenge. One commit issues to the new host and ends each credential of the old
// host.
let (host_public, host_secret) = MlDsa65Ed25519::generate_keypair(|out| Ok(out.fill(4)))?;
let host_public = host_public.to_bytes();
let host_key = PublicKey::MlDsa65Ed25519(&host_public);
let operation = OperationId::new(b"recover-1")?;
let bound = workload::binding(b"challenge-3", &operation, &authority, &runner, &build, Some(&host_key));
let key_binding = workload::key_binding(&runner, &host_key);
let draft = ProofDraft::new(&trusted(host_key.clone())?, &key_binding, &build, &bound, later)?;
let signature = host_secret.sign_deterministic(&draft.to_be_signed(), &[])?;
let proof = draft.finish(signature.as_bytes(), &mut budget())?;
let replace = Replace { key: host_key, proof: &proof, challenge: b"challenge-3" };
let by = By::Issue(&operator);
let request = Request { operation, by, audience: &build, lifetime: None, replace: Some(replace) };
let registration_record = ready(memory.read(&Registration::store_key(&runner)))?.ok_or("no registration")?;
let pending =
    Pending::new(request, &issuer_record, &registration_record, &policy, &mut driver, later, Limits::default())?;
let signature = issuer_secret.sign_deterministic(&pending.to_be_signed(), &[])?;
let (proposal, plan, awaiting) = pending.finish(signature.as_bytes(), &mut budget())?;
let replacement = awaiting.release(commit(&mut driver, &mut memory, proposal, plan)?)?;

// A verifier that reads the current registration admits the new host and refuses the old one.
let current = ready(memory.read(&Registration::store_key(&runner)))?;
let verified = profile.verify(replacement.as_bytes(), later, &mut budget())?;
workload::admits(&verified, current.as_ref(), Limits::default())?;
let verified = profile.verify(renewed.as_bytes(), later, &mut budget())?;
assert_eq!(workload::admits(&verified, current.as_ref(), Limits::default()), Err(workload::Error::Revoked));
```

## Errors

Each refusal of an operation is a `workload::Error`. Refuse the request unless the table gives another recovery. The
release of a credential refuses with a `credential::Release` ([Release a credential](credential-format.md#release-a-credential)).

| Error | Cause | Recovery |
| --- | --- | --- |
| `Key(cose::Error)` | `Issuer::new`, `Registration::register`, a rotation, or a recovery refused the key as a trusted key | Correct the key |
| `Audiences` | The issuer has more than 16 audiences | Use another issuer record |
| `Record` | A record is not the record form of its kind, or rsauthnz did not write its version | Register the issuer or the workload with `register` |
| `Audience` | The audience is not an audience of the issuer | Refuse |
| `Ceiling` | The lifetime is past `lifetime_max`, or the end is past `not_after` | Ask for a shorter lifetime, or give the issuer a new ceiling |
| `Possession` | The current credential of a renewal names another workload or another `cnf` key than the registration, or `admits` got a credential of another purpose, issuer, workload, or `cnf` key | Refuse |
| `Revoked` | The serial of the credential is below the generation or revoked: a rotation, a recovery, or a revocation ended it | An operator issues a new credential |
| `Unregistered` | `admits` got no registration record | An operator registers the workload again ([After a restore](#after-a-restore)) |
| `Target` | The issuance record of a revocation of one credential names another issuer, workload, or purpose, the credential ended, or a revocation ended it | Name a live credential of the workload, or `Target::All` |
| `Revocations` | The registration holds `REVOKED_MAX` revoked credentials that did not end | Revoke all credentials, or wait for one of them to end |
| `Unchanged` | The new key is the key that the operation retires: the registered key, or the current or previous issuer key | Give a new key |
| `Issuer` | The registration names another issuer than the issuer record of the request | Use the issuer of the registration |
| `Algorithm` | The new issuer key has another algorithm than the current key | Use a key of the declared profile, or a new issuer with its own authority |
| `Overlap { until }` | A routine issuer rotation while the previous key still verifies | Rotate at `until` or later, or with `Retire::Now` |
| `Credential(credential::Error)` | The format refused the draft, the current credential, a proof, or the signature of custody, or a challenge is longer than `credential::MAX_BYTES` | Refuse |
| `Refusal(authz::Refusal)` | The policy refused | Refuse |
| `Driver(driver::Error)` | The driver gave no value | As the driver error gives |
| `Transition(transition::Error)` | The proposal refused | As `error.recovery()` gives |

## Record forms

Each form is canonical CBOR ([Parser limits](parser-limits.md)). The first item names the form and its number.

| Record | Key | Form |
| --- | --- | --- |
| Issuer | `Kind::Issuer`, then the SHA-256 digest of the CBOR form of the authority | `["rsauthnz.workload.issuer.2", authority, key, previous, audiences, lifetime_max, not_after]`. `previous` is `null`, or `[key, until]` during a rotation |
| Registration | `Kind::Workload`, then the SHA-256 digest of the CBOR form of the workload | `["rsauthnz.workload.registration.3", workload, key, generation, revoked]`. `revoked` is an array of `[serial, expires]`, sorted by serial |
| Credential | `Kind::Credential`, then the 8 bytes of the serial, the most significant byte first | The issuance record of [Issue a credential](credential-format.md#issue-a-credential): `["rsauthnz.credential.record.1", issuer, subject, audience, purpose, expires]` |

Each identifier has its CBOR form of [Vocabulary](vocabulary.md#cbor-forms). A key is the byte string of an encoded
`COSE_Key` with its `alg`. The times are whole seconds since the Unix epoch, and the lifetime is whole seconds.

| Record | Version |
| --- | --- |
| Issuer | The owner of its first version, and 8 bytes of a value of the `Kind::Issuer` counter |
| Registration | The issuer authority, and 8 bytes of a value of the `Kind::Credential` counter |
| Credential | The issuer authority, and the 8 bytes of the serial |

The request binding of an issuance holds `[issuer, workload, audience, lifetime, kid]`. `lifetime` is `null` for no
lifetime, and `kid` is the thumbprint of the new key, or `null` with no `replace`. A revocation binds
`[issuer, workload, serial]`, with `null` for `Target::All`; its issuer is the issuer of the registration. Thus the
same request under another issuer is another request, and it refuses with `transition::Error::Reuse`. An issuer rotation binds `[authority, kid, retire]`, with 0 for `Retire::AfterLifetime` and 1 for
`Retire::Now`. The serial and the times are not part of a binding.

## Limits

- A verifier that reads nothing accepts a credential that a rotation, a recovery, or a revocation ended until it
  ends.
- A profile holds at most two issuer keys: the current key and the previous key.
- Each issuance writes the registration record, so two issuances of one workload at the same time conflict.
- A registration holds at most `workload::REVOKED_MAX` (16) revoked credentials that did not end. With more, revoke
  all credentials of the workload.
