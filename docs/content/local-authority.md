# Open a local authority

`rsauthnz::local` gives an application owner an authority on one host, with no hosted account and no daemon. The
owner issues a one-use bootstrap value. A client, such as a headless CLI, submits the value with its own public key,
and becomes the first administrator, with a CLI credential. A remote call is admitted only for the credential of a
live administrator, with a proof of possession of its key over a one-use challenge ([CLI credential](cli.md)). If the
owner loses the administrator, the owner issues a new value: an owner re-bootstrap.

## The model

- The **host grant** (`HostGrant`) holds the local owner (`Id<Human>`) and the origin of the application
  (`Id<Audience>`). Only the host builds it, at its trusted boundary, for example for a call of its own user
  interface. A request cannot assert a grant. A remote caller, a session, or an agent grant gives evidence, never a
  grant, so it cannot issue a value.
- The **issuer key** is a composite key in [custody](custody.md). It signs each CLI credential of the authority.
- A **bootstrap value** (`Bootstrap`) is 32 random bytes. Its text is `rsauthnz-bootstrap-1-` and 64 lowercase
  hexadecimal digits. It names one administrator, it is valid for `LIFETIME` (15 minutes), and one bootstrap consumes
  it. At most one value of an authority is valid: each issue ends the earlier value that is not consumed.
- An **administrator binding** is the record of one administrator. It holds the issue of the value that the bootstrap
  consumed, the owner, the origin, and the issuer key that bound it, and the CLI credential without its signature. It
  is an authority anchor: a restore keeps it, and the unlink of the last one refuses. It ends with its CLI credential,
  and expiry removes it. A binding whose credential ended is no administrator. The store holds at most
  `ADMINISTRATORS_MAX` (64) bindings of an authority.
- The **CLI credential** is a [credential](credential-format.md) of the purpose `rsauthnz:cli`, valid for
  `CLI_LIFETIME` (365 days). The issuer is the authority, the audience is the origin of the grant, the subject is the
  administrator, and the `cnf` key is the key of the client.
- The **report** gives each issue in the log of the authority and each live administrator binding, with the state of
  its value.

The store keeps no secret and no signed credential. The key of a value record is the SHA-256 digest of the authority, the issuer public key,
and the secret. Thus a value of another authority, or of another issuer key, finds no record and refuses.

## Bootstrap the first administrator

Each operation reads the store with keyed reads (`Store::read`) and range reads (`Store::range`), and gives a proposal
and its plan. Submit them to the commit
[driver](restore.md), and take the outcome of the ticket. Only the receipt of the accepted commit gives the value or
the credential.

1. Open the authority with `Authority::open(store, &grant, id, issuer, limits)`. Give the handle of the issuer key and
   the limits of the driver. An authority that its record binds to another owner, origin, or issuer key refuses. When
   a restore lost the record of the authority, its administrator bindings name the owner, the origin, and the issuer
   key, so another grant or issuer key refuses too.
2. Issue a value with `authority.issue(store, &grant, administrator, now, random, operation)`. Draw the operation
   identity from `random`, and keep it. The artifact of the receipt is the text of the value.
3. Give the text to the client by a local path. Do not put it in a URL, a log, or an argument.
4. The client generates its key in its custody and stores it before it submits the value. A completion that the
   client never heard about then binds a key that the client has.
5. Take the text and the public key of the client, an ML-DSA-65 + Ed25519 key of 1,984 bytes. Allocate a serial with
   `driver.allocate(Kind::Credential)`, and call `authority.bootstrap(store, &value, holder, serial, now)`.
6. Sign the bytes of `pending.to_be_signed()` with the issuer key in custody. `pending.finish(signature, operation)`
   verifies the signature and gives the proposal. Its commit consumes the value, writes the issuance record of the
   credential, and binds the administrator. The artifact of the receipt is the CLI credential. The proposal has the end
   of the value as its deadline, so a commit after the end refuses with `transition::Error::Expired`.
7. On each remote call, the client proves the possession of its key over a one-use challenge of its binding and over
   the request of the call. [CLI credential](cli.md) gives the calls: `authority.challenge`, `authority.admit`, and
   `admission.release`.

This example is the rustdoc example of `rsauthnz::local`, and `cargo xtask test` runs it. It runs the journey on the
[memory binding](memory-binding.md), and rscrypto signs in place of custody, so that the example holds its keys. A
host uses its own storage binding and its custody. The `Bootstrap` and `Rebootstrap` cases of the
[conformance suite](conformance.md) run the same steps with faults and restores. [Run the native CLI
example](native-cli-example.md) runs the journey as a program, with the key files of `FileCustody` and the calls of
the CLI.

```rust
use core::pin::pin;
use core::task::{Context, Poll, Waker};
use core::time::Duration;

use rsauthnz::credential::Serial;
use rsauthnz::crypto::Algorithm;
use rsauthnz::custody::{Handle, KeyId};
use rsauthnz::id::Id;
use rsauthnz::limits::Limits;
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
let (holder_public, _) = MlDsa65Ed25519::generate_keypair(|out| Ok(out.fill(2)))?;
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

// After a lost response, the client gives its administrator and its public key, and custody signs the credential
// of the binding again.
let reissue = ready(authority.credential(&mut memory, &alice, &holder_public, now))?;
let signature = issuer_secret.sign_deterministic(&reissue.to_be_signed(), &[])?;
assert_eq!(reissue.finish(signature.as_bytes())?, credential);

// The value is one-use. Each remote call of the administrator proves the possession of its key: see `rsauthnz::cli`.
let again = ready(authority.bootstrap(&mut memory, &value, &holder_public, serial, now));
assert!(matches!(again, Err(local::Failure::Refused(local::Error::Unknown))));
```

A second bootstrap of the same value refuses with `Error::Unknown`. Two uses at the same time give one commit, and the
other gets a conflict or a refusal.

## Issue a value again

The owner issues a new value in each of these cases: the value expired, the administrator lost its key, or the
response of an issue was lost. Call `authority.issue` again under the same grant. The commit ends the earlier value
that is not consumed, with an end entry in the restore journal, so a restore cannot make that value valid again. It
writes no creation entry. A new value cannot name an administrator whose binding has a valid CLI credential: name
another one, or unlink the binding first. A value can name an administrator whose credential ended: its bootstrap
binds a new credential, and expiry removes the ended binding.

A re-bootstrap does not change the existing bindings. The new administrator ends a lost or compromised binding with an
unlink.

## Lost responses and restore

- **A lost response of an issue.** Look up the operation identity. The lookup shows the commit and gives no value.
  Issue again: that issue ends the value of the lost commit.
- **A lost response of a bootstrap.** The client keeps no secret for the recovery. It gives the administrator that the
  owner named and the public key of its key in custody. `authority.credential(store, &administrator, &holder, now)`
  gives a `Reissue` of the binding whose `cnf` key is that key. Custody signs `reissue.to_be_signed()` with the issuer
  key, and `reissue.finish(signature)` gives the credential: the same claims, serial, and `cnf` key. Each recovery
  costs one signature of the issuer key, so limit the rate of recoveries of one administrator. `Error::Unknown` shows
  that the bootstrap did not commit, that its credential ended, or that the binding holds another key. The credential
  is no secret: a call needs the possession of its key too.
- **A restore from an old snapshot.** A value that a later issue ended stays ended. A value issued after the snapshot
  is lost, and the owner issues again. A bootstrap that a crash left in doubt completes at the restore when the
  snapshot holds its value and no issue ended it. Then the client recovers its credential from the binding and proves
  possession with its stored key. Otherwise the value stays consumed, and the owner issues a new value. A binding that
  a client made after the snapshot stays live. The report gives it with the issue of its value, and that administrator
  can unlink a lost or compromised one.

## Remove an administrator

An unlink is a call of the CLI of an administrator, with its own proof:

1. The CLI asks for a challenge (`authority.challenge`), as for each call ([CLI credential](cli.md)).
2. The CLI makes `Unlink::new(challenge, operation, administrator, limits)`, and proves `unlink.call()` with
   `cli::prove`. The proof binds the challenge, the operation, and the administrator whose binding ends.
3. The authority makes the same `Unlink` from what it received, and calls
   `authority.unlink(store, credential, proof, &unlink, now, random)`. It gives `(Proposal, Plan, Admission)`.
4. Submit the proposal with the plan. One commit consumes the challenge and ends the binding.
   `admission.release(&outcome)` gives the next challenge.

A proof of another call, such as a status call, refuses with `Error::Credential(credential::Error::Proof)`, and so
does a proof of the unlink of another administrator. A replayed proof refuses with `Error::Challenge`. The plan holds
each binding of the authority, from one range read, so the driver refuses the unlink of the last one with
`transition::Error::LastAnchor`. The unlink also keeps an administrator whose CLI credential is valid: the caller, or
another one when the caller unlinks its own binding. The proposal reads that binding at its version, so two concurrent
unlinks of the last two administrators give one commit. With no such binding, an unlink of its own binding refuses
with `Error::Transition(transition::Error::LastAnchor)`. After the unlink, `admit` refuses its credential.

## Read the report

`authority.report(store, now)` gives each issue of the log, and each administrator binding with a valid CLI credential
that the log does not name. It gives them oldest first, with the administrator, the time of the issue, the end of the value, and the
`Status`. A binding holds
the issue of its value. Thus after a restore from an older snapshot, the report still gives each live administrator,
also one whose issue came after the snapshot. It does not give an issue after the snapshot that left no live binding:
the restore lost its value, or an unlink ended its binding.

| `Status` | Meaning |
| --- | --- |
| `Valid` | Not consumed, and a bootstrap can consume it until its end |
| `Expired` | Not consumed, and its end passed. The next issue ends it |
| `Ended` | A later issue ended it before a consumption |
| `Consumed { bound }` | Spent. `bound` is true while the administrator binding of the consumption has a valid CLI credential, and false after an unlink or the end of the credential. After a restore, a value whose end the restore applied also shows here, with `bound` false |

The log holds at most `ISSUES_MAX` (64) issues. A full log drops the oldest issue whose value bound no administrator
with a valid CLI credential. When the store holds `ADMINISTRATORS_MAX` (64) bindings of the authority, or each issue
of the full log bound such an administrator, an issue refuses with `Error::Full`. Run an expiry pass
(`store::expire`): it removes each binding whose credential ended. Then issue again, or unlink an administrator first.

## Operations

| Operation | Reads | Result |
| --- | --- | --- |
| `Authority::open(store, &grant, id, issuer, limits)` | The record of the authority | `Authority` |
| `authority.issue(store, &grant, administrator, now, random, operation)` | The record of the authority, the current value, and the bindings of the authority | `(Proposal, Plan)`. The receipt gives the text of the value |
| `authority.bootstrap(store, &value, holder, serial, now)` | The value record, and the bindings of the administrator | `Pending` |
| `pending.to_be_signed()` | — | The bytes that custody signs |
| `pending.finish(signature, operation)` | — | `(Proposal, Plan)`. The receipt gives the CLI credential |
| `authority.credential(store, &administrator, &holder, now)` | The bindings of `administrator` | `Reissue` of the CLI credential whose `cnf` key is `holder` |
| `reissue.to_be_signed()` | — | The bytes that custody signs |
| `reissue.finish(signature)` | — | The CLI credential |
| `authority.challenge(store, &administrator, now, random, operation)` | The bindings of `administrator`, and its challenge record | `(Proposal, Plan)`. The receipt gives the 32 bytes of the challenge ([CLI credential](cli.md)) |
| `authority.admit(store, credential, proof, &call, now, random)` | The binding of the subject and the serial of the credential, and its challenge record | `(Proposal, Admission)`. `admission.release(&outcome)` gives `Admitted` ([CLI credential](cli.md)) |
| `Unlink::new(challenge, operation, administrator, limits)` | — | The unlink, whose `call()` the CLI proves |
| `authority.unlink(store, credential, proof, &unlink, now, random)` | The reads of `admit`, and the bindings of the authority | `(Proposal, Plan, Admission)` |
| `authority.report(store, now)` | The record of the authority, the bindings of the authority, and the newest value | `Report` |
| `authority.profile()` | — | The credential profile that verifies a CLI credential of the authority |

Each read is a keyed read, except the reads of the bindings. A read of the bindings of the authority or of one
administrator is one range read of its prefix, and it gives at most `ADMINISTRATORS_MAX` bindings. An operation that reads gives
`Failure::Refused(error)` for a refusal, or
`Failure::Store(error)` for a failed read. A failed read is a crash of the binding: start the driver again.

## Errors

| `Error` | Cause | Recovery |
| --- | --- | --- |
| `Form` | The text is not `rsauthnz-bootstrap-1-` and 64 lowercase hexadecimal digits | Refuse it |
| `Grant` | The host grant has another owner or origin than the authority or its bindings | Open the authority with its grant |
| `Issuer` | The custody key is not the issuer key of the authority or of its bindings | Open the authority with its issuer key |
| `Unknown` | No valid record of the value: it is consumed or ended, or it is a value of another authority or issuer key | Ask the owner to issue a new value |
| `Expired` | The end of the value passed | Ask the owner to issue a new value |
| `Bound` | The administrator has a binding with a valid CLI credential | Name another administrator, or unlink the binding |
| `Full` | The store holds `ADMINISTRATORS_MAX` bindings of the authority, or each issue of the full log bound an administrator with a valid CLI credential | Run an expiry pass, or unlink an administrator, then issue again |
| `NotEnrolled` | No administrator binding with a valid CLI credential holds the credential or the administrator, or the credential is not the credential of its binding | Refuse the call |
| `Challenge` | The binding holds no pending challenge, another one, or one whose end passed: a call consumed it, a later issue replaced it, or a restore ended it | Refuse the call. The client asks for a new challenge, and makes a new call |
| `Record` | A record of the authority has no valid form | Restore the store from a snapshot |
| `Time` | The reading has no bound, or a time overflows | Use a reading with a bound |
| `Credential` | The credential, its signature, or the proof refuses | Refuse the call. A refused signature shows a fault of custody or another key |
| `Transition` | The proposal refuses. `transition::Error::LastAnchor` for the unlink of the last administrator with a valid CLI credential | Follow the recovery of the `transition::Error` |

## Records

| `Kind` | Key | Record |
| --- | --- | --- |
| `Local` | SHA-256 of the authority | The owner, the origin, the issuer key ID and public key, and the issue log. Only an issue writes it |
| `Bootstrap` | SHA-256 of the authority, the issuer public key, and the secret | The administrator, the time of the issue, and the end of the value. It has no store end: an issue or a bootstrap ends it, each with a journal entry |
| `Administrator` | SHA-256 of the authority, then SHA-256 of the authority and the administrator, then the 8 bytes of the serial of the credential. The kind and the first digest are the prefix of the authority, and the second digest ends the prefix of the administrator | The issue of the consumed value (its identity, the administrator, the time of the issue, and the end), the owner, the origin, the issuer key ID and thumbprint, the end of the CLI credential, the SHA-256 of its `cnf` key, and the credential without its signature. Its version is the serial of the credential, and its store end is the end of the credential |
| `Credential` | The 8 bytes of the serial | The issuance record of the CLI credential: its issuer, subject, audience, purpose, and end, with no signature. Its store end is the end of the credential |
| `SignIn` | SHA-256 of `rsauthnz.cli.challenge.1`, the authority, and the administrator | The pending challenge of the next call of the binding ([CLI credential](cli.md)). Its store end is the end of the challenge |

## Limits

- The core cannot see where a call comes from. The host builds a grant only for a call of the local owner, and calls
  `admit` for each remote call.
- The text of a value is a bearer secret in memory until the owner hands it over. The core does not clear it from
  memory.
