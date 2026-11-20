# Open a local authority

`rsauthnz::local` gives an application owner an authority on one host, with no hosted account and no daemon. The
owner issues a one-use bootstrap value. A client, such as a headless CLI, submits the value with its own public key,
and becomes the first administrator, with a CLI credential. A remote call is admitted only for the credential of a
live administrator. If the owner loses the administrator, the owner issues a new value: an owner re-bootstrap.

## The model

- The **host grant** (`HostGrant`) holds the local owner (`Id<Human>`) and the origin of the application
  (`Id<Audience>`). Only the host builds it, at its trusted boundary, for example for a call of its own user
  interface. A request cannot assert a grant. A remote caller, a session, or an agent grant gives evidence, never a
  grant, so it cannot issue a value.
- The **issuer key** is a composite key in [custody](custody.md). It signs each CLI credential of the authority.
- A **bootstrap value** (`Bootstrap`) is 32 random bytes. Its text is `rsauthnz-bootstrap-1-` and 64 lowercase
  hexadecimal digits. It names one administrator, it is valid for `LIFETIME` (15 minutes), and one bootstrap consumes
  it. At most one value of an authority is valid: each issue ends the earlier value that is not consumed.
- An **administrator binding** is the record of one administrator. It holds the CLI credential that the bootstrap
  issued. It is an authority anchor: a restore keeps it, and the unlink of the last one refuses.
- The **CLI credential** is a [credential](credential-format.md) of the purpose `rsauthnz:cli`, valid for
  `CLI_LIFETIME` (365 days). The issuer is the authority, the audience is the origin of the grant, the subject is the
  administrator, and the `cnf` key is the key of the client.
- The **report** gives each issue in the log of the authority, with the state of its value.

The store keeps no secret. The key of a value record is the SHA-256 digest of the authority, the issuer public key,
and the secret. Thus a value of another authority, or of another issuer key, finds no record and refuses.

## Bootstrap the first administrator

Each operation reads the store with `Store::read` and gives a proposal and its plan. Submit them to the commit
[driver](restore.md), and take the outcome of the ticket. Only the receipt of the accepted commit gives the value or
the credential.

1. Open the authority with `Authority::open(store, &grant, id, issuer, limits)`. Give the handle of the issuer key and
   the limits of the driver. An authority that its record binds to another owner, origin, or issuer key refuses.
2. Issue a value with `authority.issue(store, &grant, administrator, now, random, operation)`. Draw the operation
   identity from `random`, and keep it. The artifact of the receipt is the text of the value.
3. Give the text to the client by a local path. Do not put it in a URL, a log, or an argument.
4. The client generates its key in its custody and stores it before it submits the value. A completion that the
   client never heard about then binds a key that the client has.
5. Take the text and the public key of the client, an ML-DSA-65 + Ed25519 key of 1,984 bytes. Allocate a serial with
   `driver.allocate(Kind::Credential)`, and call `authority.bootstrap(store, &value, holder, serial, now)`.
6. Sign the bytes of `pending.to_be_signed()` with the issuer key in custody. `pending.finish(signature, operation)`
   verifies the signature and gives the proposal. Its commit consumes the value and binds the administrator. The
   artifact of the receipt is the CLI credential.
7. On each remote call, the client signs a proof of possession with `credential::ProofDraft`, over a challenge that
   the host chose for that call. `authority.admit(store, credential, proof, challenge, now)` gives `Admitted`, with
   the evidence of the possession.

This example is the rustdoc example of `rsauthnz::local`, and `cargo xtask test` runs it. It runs the journey on the
[memory binding](memory-binding.md), and rscrypto signs in place of custody, so that the example holds its keys. A
host uses its own storage binding and its custody. The `Bootstrap` and `Rebootstrap` cases of the
[conformance suite](conformance.md) run the same steps with faults and restores.

```rust
use core::pin::pin;
use core::task::{Context, Poll, Waker};
use core::time::Duration;

use rsauthnz::cose::{Key, PublicKey, TrustedKey};
use rsauthnz::credential::{ProofDraft, Serial};
use rsauthnz::crypto::Algorithm;
use rsauthnz::custody::{Handle, KeyId};
use rsauthnz::id::Id;
use rsauthnz::limits::{Limits, SignatureBudget};
use rsauthnz::local::{self, Authority, Bootstrap, HostGrant};
use rsauthnz::store::driver::{Answer, Driver, Plan};
use rsauthnz::store::{self, Kind, Store};
use rsauthnz::time::{Reading, ReadingSource};
use rsauthnz::transition::{OperationId, Outcome, Proposal};
use rsauthnz_conformance::memory::{Memory, Schedule};
use rsauthnz_conformance::suite::execute;
use rscrypto::ChaCha20Rng;
use rscrypto::auth::MlDsa65Ed25519;

type Failure = Box<dyn core::error::Error>;

/// The output of a future of the memory binding, which is ready at its first poll.
fn ready<T>(future: impl Future<Output = T>) -> T {
    let Poll::Ready(output) = pin!(future).poll(&mut Context::from_waker(Waker::noop())) else {
        unreachable!("the memory binding does no I/O");
    };
    output
}

/// Gives each effect of the driver to the binding, until the driver waits.
fn settle(memory: &mut Memory, driver: &mut Driver) -> Result<(), Failure> {
    while let Some(effect) = driver.effect() {
        let output = ready(execute(memory, effect));
        driver.give(output)?;
    }
    Ok(())
}

/// The artifact that the receipt of the accepted commit of `proposal` gives.
fn commit(memory: &mut Memory, driver: &mut Driver, (proposal, plan): (Proposal, Plan)) -> Result<Vec<u8>, Failure> {
    let ticket = driver.submit(proposal, plan)?;
    settle(memory, driver)?;
    match driver.take(ticket) {
        Some(Answer::Outcome(Outcome::Accepted(receipt))) => Ok(receipt.artifact().ok_or("no artifact")?.to_vec()),
        answer => Err(format!("the commit did not land: {answer:?}").into()),
    }
}

let now = Reading::new(Duration::from_secs(1_800_000_000), Some(Duration::from_secs(1)), ReadingSource::Caller);
// Only for this example: take the seed from the entropy source of the host, and keep each key in custody.
let mut random = ChaCha20Rng::from_seed([7; 32]);
let (issuer_public, issuer_secret) = MlDsa65Ed25519::generate_keypair(|out| Ok(out.fill(1)))?;
let (holder_public, holder_secret) = MlDsa65Ed25519::generate_keypair(|out| Ok(out.fill(2)))?;
let (issuer_public, holder_public) = (issuer_public.to_bytes(), holder_public.to_bytes());
let issuer = Handle::new(KeyId::random(&mut random), Algorithm::MlDsa65Ed25519, &issuer_public)?;

let mut memory = Memory::new(Schedule::None);
let mut driver = Driver::new(store::Profile::new(memory.declaration())?, Limits::default())?;
driver.start(now);
settle(&mut memory, &mut driver)?;

// 1. The local owner opens the authority and issues a bootstrap value for the administrator `alice`.
let grant = HostGrant { owner: Id::new("acme", "owner")?, origin: Id::new("acme", "build-app")? };
let authority = ready(Authority::open(&mut memory, &grant, Id::new("acme", "auth")?, issuer, Limits::default()))?;
let alice = Id::new("acme", "alice")?;
let issue = ready(authority.issue(&mut memory, &grant, alice.clone(), now, &mut random, OperationId::new(b"i-1")?))?;
let text = String::from_utf8(commit(&mut memory, &mut driver, issue)?)?;

// 2. The client stores its key, then submits the value and its public key. Custody signs the CLI credential.
let value = Bootstrap::parse(&text)?;
let serial = Serial(driver.allocate(Kind::Credential)?);
let pending = ready(authority.bootstrap(&mut memory, &value, &holder_public, serial, now))?;
let signature = issuer_secret.sign_deterministic(&pending.to_be_signed(), &[])?;
let bootstrap = pending.finish(signature.as_bytes(), OperationId::new(b"b-1")?)?;
let credential = commit(&mut memory, &mut driver, bootstrap)?;

// 3. On a remote call, the administrator proves the possession of its key over the challenge of the call.
let holder = TrustedKey::new(Algorithm::MlDsa65Ed25519, &Key {
    kid: None,
    alg: None,
    public: PublicKey::MlDsa65Ed25519(&holder_public),
})?;
let challenge = [9; 32];
let draft = ProofDraft::new(&holder, &credential, &grant.origin, &challenge, now)?;
let signature = holder_secret.sign_deterministic(&draft.to_be_signed(), &[])?;
let proof = draft.finish(signature.as_bytes(), &mut SignatureBudget::new(&Limits::default()))?;
let admitted = ready(authority.admit(&mut memory, &credential, &proof, &challenge, now))?;
assert_eq!(admitted.administrator(), &alice);

// The value is one-use.
let again = ready(authority.bootstrap(&mut memory, &value, &holder_public, serial, now));
assert!(matches!(again, Err(local::Failure::Refused(local::Error::Unknown))));
```

A second bootstrap of the same value refuses with `Error::Unknown`. Two uses at the same time give one commit, and the
other gets a conflict or a refusal.

## Issue a value again

The owner issues a new value in each of these cases: the value expired, the administrator lost its key, or the
response of an issue was lost. Call `authority.issue` again under the same grant. The commit ends the earlier value
that is not consumed, with an end entry in the restore journal, so a restore cannot make that value valid again. It
writes no creation entry. A new value cannot name an administrator whose binding is live: name another one, or
unlink the binding first.

A re-bootstrap does not change the existing bindings. The new administrator ends a lost or compromised binding with an
unlink.

## Lost responses and restore

- **A lost response of an issue.** Look up the operation identity. The lookup shows the commit and gives no value.
  Issue again: that issue ends the value of the lost commit.
- **A lost response of a bootstrap.** Look up the operation identity of the bootstrap. When it committed, read the
  credential from the binding with `authority.credential(store, &value, &administrator)`. The credential is no secret:
  a call needs the possession of its key too.
- **A restore from an old snapshot.** A value that a later issue ended stays ended. A value issued after the snapshot
  is lost, and the owner issues again. A bootstrap that a crash left in doubt completes at the restore when the
  snapshot holds its value and no issue ended it. Then the client reads its credential from the binding and proves
  possession with its stored key. Otherwise the value stays consumed, and the owner issues a new value.

## Remove an administrator

`authority.unlink(store, &actor, &administrator, now, operation)` ends the binding of `administrator`. The actor is an
`Admitted` administrator of the same authority. The plan holds each live binding, so the driver refuses the unlink of
the last one with `transition::Error::LastAnchor`. An administrator can unlink its own binding while another one is
live. After the unlink, `admit` refuses its credential.

## Read the report

`authority.report(store, now)` gives each issue of the log, oldest first: the administrator, the time of the issue,
the end of the value, and its `Status`.

| `Status` | Meaning |
| --- | --- |
| `Valid` | Not consumed, and a bootstrap can consume it until its end |
| `Expired` | Not consumed, and its end passed. The next issue ends it |
| `Ended` | A later issue ended it before a consumption |
| `Consumed { bound }` | Spent. `bound` is true while the administrator binding of the consumption is live, and false after an unlink. After a restore, a value whose end the restore applied also shows here, with `bound` false |

The log holds at most `ISSUES_MAX` (64) issues. A full log drops the oldest issue whose value bound no live
administrator. When each issue has a live binding, an issue refuses with `Error::Full`: unlink an administrator first.

## Operations

| Operation | Reads | Result |
| --- | --- | --- |
| `Authority::open(store, &grant, id, issuer, limits)` | The record of the authority | `Authority` |
| `authority.issue(store, &grant, administrator, now, random, operation)` | The record of the authority, the current value, and the binding of `administrator` | `(Proposal, Plan)`. The receipt gives the text of the value |
| `authority.bootstrap(store, &value, holder, serial, now)` | The value record | `Pending` |
| `pending.to_be_signed()` | — | The bytes that custody signs |
| `pending.finish(signature, operation)` | — | `(Proposal, Plan)`. The receipt gives the CLI credential |
| `authority.credential(store, &value, &administrator)` | The binding of `administrator` | The CLI credential |
| `authority.admit(store, credential, proof, challenge, now)` | The binding of the subject of the credential | `Admitted` |
| `authority.unlink(store, &actor, &administrator, now, operation)` | The binding of `administrator`, and each binding of the log | `(Proposal, Plan)` |
| `authority.report(store, now)` | The record of the authority, and the records of its issues | `Report` |
| `authority.profile()` | — | The credential profile that verifies a CLI credential of the authority |

Each read is a keyed read. An operation that reads gives `Failure::Refused(error)` for a refusal, or
`Failure::Store(error)` for a failed read. A failed read is a crash of the binding: start the driver again.

## Errors

| `Error` | Cause | Recovery |
| --- | --- | --- |
| `Form` | The text is not `rsauthnz-bootstrap-1-` and 64 lowercase hexadecimal digits | Refuse it |
| `Grant` | The host grant has another owner or origin than the authority | Open the authority with its grant |
| `Issuer` | The custody key is not the issuer key of the authority, or not a composite key | Open the authority with its issuer key |
| `Unknown` | No valid record of the value: it is consumed or ended, or it is a value of another authority or issuer key | Ask the owner to issue a new value |
| `Expired` | The end of the value passed | Ask the owner to issue a new value |
| `Bound` | The administrator has a live binding | Name another administrator, or unlink the binding |
| `Full` | Each issue of the full log bound a live administrator | Unlink an administrator, then issue again |
| `NotEnrolled` | No live administrator binding holds the credential or the administrator | Refuse the call |
| `Record` | A record of the authority has no valid form | Restore the store from a snapshot |
| `Time` | The reading has no bound, or a time overflows | Use a reading with a bound |
| `Credential` | The credential, its signature, or the proof refuses | Refuse the call. A refused signature shows a fault of custody or another key |
| `Transition` | The proposal refuses | Follow the recovery of the `transition::Error` |

## Records

| `Kind` | Key | Record |
| --- | --- | --- |
| `Local` | SHA-256 of the authority | The owner, the origin, the issuer key ID and public key, and the issue log. Only an issue writes it |
| `Bootstrap` | SHA-256 of the authority, the issuer public key, and the secret | The administrator and the end of the value. It has no store end: an issue or a bootstrap ends it, each with a journal entry |
| `Administrator` | SHA-256 of the authority and the administrator | The identity of the consumed value and the CLI credential. Its version is the serial of the credential |

## Limits

- The core cannot see where a call comes from. The host builds a grant only for a call of the local owner, and calls
  `admit` for each remote call.
- The challenge of `admit` must be fresh for each call. The host chooses it and refuses its reuse.
- The text of a value is a bearer secret in memory until the owner hands it over. The core does not clear it from
  memory.
