# Call with a CLI credential

`rsauthnz::cli` gives a headless CLI the calls of an administrator of a [local authority](local-authority.md). The CLI
keeps its key in [custody](custody.md). Its CLI credential is no bearer secret: each call proves the possession of the
key over a one-use challenge of the authority and over the request of the call. Thus a captured call cannot repeat,
and a proof for one request refuses for another.

## The model

- The **CLI key** is an ML-DSA-65 + Ed25519 key in custody. The CLI keeps only its handle: the key ID, the algorithm,
  and the public key.
- The **CLI credential** is the credential of the administrator binding that a bootstrap value paid for. Its `cnf` key
  is the CLI key. It is valid for `local::CLI_LIFETIME` (365 days).
- A **challenge** (`Challenge`) is 32 random bytes of the authority, valid for `CHALLENGE_LIFETIME` (60 seconds). Each
  administrator binding has at most one pending challenge. A new issue replaces it.
- A **call** (`Call`) is a challenge, an operation identity, and a request: the CBOR value of the call that the
  application defines, such as its action, its target, and the digest of its content. Its request binding is the
  SHA-256 digest of `["rsauthnz.cli.call.1", challenge, operation, request]`. The proof binds it in place of a
  challenge of the verifier.
- An **admission** (`Admission`) is the proposal of a call before its commit. The commit consumes the challenge and
  writes the next one. Only the accepted commit gives the admitted call (`Admitted`), with the challenge of the next
  call.

## Enroll the CLI

1. The local owner issues a bootstrap value for the administrator, and gives the CLI the value and the name of the
   administrator by a local path ([Open a local authority](local-authority.md)).
2. The CLI draws a key ID with `KeyId::random`, records it with the name of the administrator, and enrolls its key
   with `custody.enroll(id, Algorithm::MlDsa65Ed25519, random)`.
3. The CLI submits the value and its public key of 1,984 bytes. The authority calls `authority.bootstrap`, and the
   artifact of the accepted commit is the CLI credential.
4. The CLI stores its credential with the handle of its key. Neither is a secret.

The CLI enrolls its key before it submits the value. Thus a bootstrap that commits binds a key that the CLI has, also
when the CLI lost the response, or when a restore completed the bootstrap.

## Make a call

1. For its first call, the CLI asks for a challenge. The authority calls
   `authority.challenge(store, &administrator, now, random, operation)`. The artifact of the accepted commit is the
   32 bytes of the challenge: `Challenge::from_bytes`.
2. The CLI makes the call with `Call::new(challenge, operation, &request, limits)`. Draw a new operation identity for
   each call, and keep it until the call has an outcome.
3. The CLI signs the proof in custody with `cli::prove(custody, &handle, &credential, &audience, &call, now, random)`.
   The audience is the origin of the authority. The CLI sends the credential, the proof, the challenge, the
   operation identity, and the request.
4. The authority makes the same call from the values that it received, with `Call::new`. Then
   `authority.admit(store, &credential, &proof, &call, now, random)` gives the proposal and the admission.
5. The authority adds the reads and the changes of the call to the proposal, and submits it with an empty `Plan`. The
   proposal has the end of the challenge or of the credential as its deadline, so a commit after either one refuses
   with `transition::Error::Expired`.
6. `admission.release(&outcome)` gives `Admitted` only for the accepted commit of this proposal. Then the authority
   does the call, and gives the CLI `admitted.next()` in the response.
7. For its next call, the CLI uses that challenge, with no issue. In steady state, a call costs one round trip, one
   commit, one custody signature, and the checks of the credential and the proof.

An unlink of an administrator binding is a call of its own: the CLI proves `local::Unlink::new(challenge, operation,
administrator, limits).call()`, and the authority calls `authority.unlink`. The proof of another call refuses for it
([Remove an administrator](local-authority.md#remove-an-administrator)).

This example is the rustdoc example of `rsauthnz::cli`, and `cargo xtask test` runs it. It needs the feature
`native-custody`, on Linux, macOS, or Windows. It runs the journey on the [memory binding](memory-binding.md), with the
key files of `FileCustody`. To stay short, it keeps the issuer key of the authority in the same custody. A host uses
its own storage binding, and its CLI and its authority are two processes. [Run the native CLI
example](native-cli-example.md) runs the same journey as a program, with two failures and the cleanup.

```rust
use core::pin::pin;
use core::task::{Context, Poll, Waker};
use core::time::Duration;

use rsauthnz::cbor::Value;
use rsauthnz::cli::{self, Call, Challenge};
use rsauthnz::credential::Serial;
use rsauthnz::crypto::Algorithm;
use rsauthnz::custody::{Custody, FileCustody, Isolation, KeyId};
use rsauthnz::id::Id;
use rsauthnz::limits::Limits;
use rsauthnz::local::{Authority, Bootstrap, HostGrant};
use rsauthnz::store::driver::{Answer, Driver, Plan};
use rsauthnz::store::{self, Kind, Store};
use rsauthnz::time::{Reading, ReadingSource};
use rsauthnz::transition::{OperationId, Outcome, Proposal};
use rsauthnz_conformance::memory::{Memory, Schedule};
use rsauthnz_conformance::suite::execute;
use rscrypto::ChaCha20Rng;

type Failure = Box<dyn core::error::Error>;

/// The output of a future of the memory binding, which is ready at its first poll.
fn ready<T>(future: impl Future<Output = T>) -> T {
    let Poll::Ready(output) = pin!(future).poll(&mut Context::from_waker(Waker::noop())) else {
        unreachable!("the memory binding does no I/O");
    };
    output
}

/// The outcome of the commit of `proposal` with `plan`, after the driver gives each effect to the binding.
fn commit(memory: &mut Memory, driver: &mut Driver, (proposal, plan): (Proposal, Plan)) -> Result<Outcome, Failure> {
    let ticket = driver.submit(proposal, plan)?;
    while let Some(effect) = driver.effect() {
        let output = ready(execute(memory, effect));
        driver.give(output)?;
    }
    match driver.take(ticket) {
        Some(Answer::Outcome(outcome)) => Ok(outcome),
        answer => Err(format!("the commit gave {answer:?}").into()),
    }
}

/// The artifact of an accepted commit.
fn artifact(outcome: Outcome) -> Result<Vec<u8>, Failure> {
    match outcome {
        Outcome::Accepted(receipt) => Ok(receipt.artifact().ok_or("no artifact")?.to_vec()),
        outcome => Err(format!("the commit did not land: {outcome:?}").into()),
    }
}

let now = Reading::new(Duration::from_secs(1_800_000_000), Some(Duration::from_secs(1)), ReadingSource::Caller);
// Only for this example: take the seed from the entropy source of the host.
let mut random = ChaCha20Rng::from_seed([7; 32]);
let dir = std::env::temp_dir().join(format!("rsauthnz-cli-example-{}", std::process::id()));
std::fs::create_dir(&dir)?;
let custody = FileCustody::open(&dir, Isolation::User)?;
let issuer = custody.enroll(KeyId::random(&mut random), Algorithm::MlDsa65Ed25519, &mut random)?;

let mut memory = Memory::new(Schedule::None);
let mut driver = Driver::new(store::Profile::new(memory.declaration())?, Limits::default())?;
driver.start(now);
while let Some(effect) = driver.effect() {
    let output = ready(execute(&mut memory, effect));
    driver.give(output)?;
}

// 1. The local owner opens the authority and issues a bootstrap value for the administrator `alice`.
let grant = HostGrant { owner: Id::new("acme", "owner")?, origin: Id::new("acme", "build-app")? };
let authority = ready(Authority::open(&mut memory, &grant, Id::new("acme", "auth")?, issuer.clone(), Limits::default()))?;
let alice = Id::new("acme", "alice")?;
let issue = ready(authority.issue(&mut memory, &grant, alice.clone(), now, &mut random, OperationId::new(b"i-1")?))?;
let value = Bootstrap::parse(&String::from_utf8(artifact(commit(&mut memory, &mut driver, issue)?)?)?)?;

// 2. The CLI draws a key ID, records it with `alice`, and enrolls its key before it submits the value.
let key = custody.enroll(KeyId::random(&mut random), Algorithm::MlDsa65Ed25519, &mut random)?;
let holder: [u8; 1984] = key.public_key().as_slice().try_into()?;
let serial = Serial(driver.allocate(Kind::Credential)?);
let pending = ready(authority.bootstrap(&mut memory, &value, &holder, serial, now))?;
let signature = custody.sign(&issuer, Algorithm::MlDsa65Ed25519, &pending.to_be_signed(), &mut random)?;
let bootstrap = pending.finish(&signature, OperationId::new(b"b-1")?)?;
let credential = artifact(commit(&mut memory, &mut driver, bootstrap)?)?;

// 3. The first call: the authority issues a challenge, and the CLI proves the possession of its key in custody.
let issued = ready(authority.challenge(&mut memory, &alice, now, &mut random, OperationId::new(b"c-1")?))?;
let mut challenge = Challenge::from_bytes(artifact(commit(&mut memory, &mut driver, issued)?)?.as_slice().try_into()?);
for (operation, target) in [(&b"call-1"[..], "status"), (b"call-2", "deploy")] {
    let call = Call::new(challenge, OperationId::new(operation)?, &Value::Text(target), Limits::default())?;
    let proof = cli::prove(&custody, &key, &credential, &grant.origin, &call, now, &mut random)?;

    // 4. The authority makes the call again from what it received, and admits it in one commit.
    let (proposal, admission) = ready(authority.admit(&mut memory, &credential, &proof, &call, now, &mut random))?;
    let outcome = commit(&mut memory, &mut driver, (proposal, Plan::default()))?;
    let admitted = admission.release(&outcome).ok_or("the call was not admitted")?;
    assert_eq!(admitted.administrator(), &alice);
    // The next call uses the challenge that this commit wrote, with no issue.
    challenge = admitted.next();
}

custody.delete(key.id())?;
custody.delete(issuer.id())?;
std::fs::remove_dir(&dir)?;
```

A replay of a proof refuses with `local::Error::Challenge`, because the commit of its call replaced the challenge. A
proof with another request, another operation, or no proof refuses with `local::Error::Credential`.

## Select the custody of the CLI key

`cli::prove` takes a `&dyn Custody` and a handle. The core has no default custody. The CLI selects it:

- On macOS, use `KeychainCustody`, unless the CLI runs with no user session ([Select a custody](custody.md#select-a-custody)).
- On Linux and Windows, use `FileCustody`, in a directory that only the account of the CLI uses.

The key never leaves custody. The CLI gives `cli::prove` the handle only, and custody signs the bytes of the proof.
[The custody report](custody.md#the-custody-report) states the owner of the key, its plaintext lifetime, its
zeroization, its recovery, and the isolation that the OS enforces.

## Lost responses and restore

- **A lost response of a bootstrap.** The CLI keeps no secret for the recovery. It asks the authority, with the name
  of its administrator and its public key. The authority calls `authority.credential(store, &administrator, &holder,
  now)`, has custody sign `reissue.to_be_signed()` with the issuer key, and gives the CLI `reissue.finish(signature)`:
  the credential of the binding whose `cnf` key is that key. The binding keeps no signed credential, so each recovery
  costs one issuer signature. `local::Error::Unknown` shows that the bootstrap did not commit. A bootstrap that a
  restore completed gives its credential in the same way.
- **A lost response of an issue of a challenge.** Ask for a challenge again. The new issue replaces the challenge of
  the lost one.
- **A lost response of a call.** The outcome is unknown, and the call can have committed. The authority looks up the
  operation that `Outcome::Unknown` gives, with `driver.lookup(operation)`. Never send the call again as a new
  operation. After the lookup, the CLI asks for a new challenge, because it did not get the next one.
- **A restore.** A restore ends each pending challenge, also a challenge that the snapshot holds. A call over it
  refuses with `local::Error::Challenge`, and the CLI asks for a new challenge.

## Operations

| Operation | Side | Result |
| --- | --- | --- |
| `authority.challenge(store, &administrator, now, random, operation)` | Authority | `(Proposal, Plan)`. The receipt gives the 32 bytes of the challenge |
| `Challenge::from_bytes(bytes)`, `challenge.to_bytes()` | Both | The challenge, and its bytes |
| `Call::new(challenge, operation, &request, limits)` | Both | `Call` |
| `cli::prove(custody, &handle, &credential, &audience, &call, now, random)` | CLI | The bytes of the proof |
| `authority.admit(store, &credential, &proof, &call, now, random)` | Authority | `(Proposal, Admission)` |
| `admission.release(&outcome)` | Authority | `Some(Admitted)` for the accepted commit of the proposal, else `None` |
| `admitted.administrator()`, `admitted.evidence()`, `admitted.next()` | Authority | The administrator, the evidence of the possession, and the challenge of the next call |
| `authority.credential(store, &administrator, &holder, now)`, then `reissue.finish(signature)` | Authority | The CLI credential whose `cnf` key is `holder`, which custody signs again |
| `local::Unlink::new(challenge, operation, administrator, limits)`, `unlink.call()` | Both | The unlink, and the call that the CLI proves |

`authority.admit` reads the administrator binding of the serial of the credential and its challenge record, with keyed
reads. `authority.challenge` reads the bindings of the administrator with one range read, and the challenge record
with a keyed read.

## Errors

| Error | Cause | Recovery |
| --- | --- | --- |
| `cli::Error::Request` | The request has no CBOR encoding, or the form of the call is longer than `Limits::bytes` | Give the digest of a long content in the request, not the content |
| `cli::Error::Custody` | Custody refused to sign | Follow the recovery of the `custody::Error` |
| `cli::Error::Credential` | The proof can be longer than its bound, or the signature of custody does not verify with the key of the handle | A refused signature shows a fault of custody or another key |
| `local::Error::Challenge` | The binding holds no pending challenge, another one, or one whose end passed | Refuse the call. The CLI asks for a new challenge, and makes a new call |
| `local::Error::NotEnrolled` | No administrator binding with a valid CLI credential holds the credential or the administrator, or the binding of its serial holds another credential | Refuse the call |
| `local::Error::Credential` | The credential or the proof refuses: another request or operation, another key, or a credential after its end or of another authority | Refuse the call |

[Open a local authority](local-authority.md#errors) gives each other `local::Error`.

## Limits

- The issue of a challenge authenticates no caller, and its audit names the administrator. A caller that reaches the
  issue can replace the pending challenge, and the call of the CLI then refuses. Give the issue only to the clients
  of the authority.
- The recovery of a credential authenticates no caller either, and each recovery costs one signature of the issuer
  key. The credential gives nothing without the CLI key. Limit the rate of recoveries of one administrator.
- A binding has one pending challenge. Two calls of one CLI at the same time conflict: one commits, and the other
  refuses with `local::Error::Challenge` or a conflict. Make the calls of one CLI one at a time.
- The proposal of an admission carries the next challenge as its prepared artifact. Thus a call that releases its
  own artifact commits it in a second transition.
- The scope of a CLI credential is its issuer, its audience, its purpose `rsauthnz:cli`, and its validity. It names no
  resource action.

## Support

| Target | `FileCustody` | `KeychainCustody` |
| --- | --- | --- |
| macOS aarch64 | The tests pass | The tests pass, in the session of a user with an unlocked login keychain |
| Linux x86_64 and aarch64, glibc and musl | The test runs are pending | Not available |
| Windows x86_64 | The test run is pending | Not available |
