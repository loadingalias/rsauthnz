# Recover an account

`rsauthnz::recovery` gives each account one recovery code. A user who lost each passkey gives the name of the account
and the code, and registers a new passkey. One commit consumes the code and opens a session with the new passkey.
It ends all previous sessions, connected account CLIs, and unfinished approvals for this account at this passkey site. A recovery is weaker evidence than a passkey sign-in: it is never phishing
resistant.

Each operation proposes one commit, and the storage binding of the application accepts it ([Propose a
transition](transitions.md)). The registration of the new passkey is a [passkey registration](passkeys.md#register),
and the new session is a [browser session](sessions.md).

## The model

- A **recovery code** (`Code`) is `CODE_BYTES` (16) random bytes from the generator of the caller: 128 bits. Its text
  has `CODE_CHARS` (39) characters: 32 hexadecimal digits in eight groups of four, such as
  `3f9a-08c1-7d2e-55b0-c4a9-1e63-f087-2b5d`. `Code::parse` takes the digits in either case, with or without the
  hyphens and spaces, in a text of at most 64 bytes. A code is a bearer secret: `Debug` shows nothing of it, and its
  memory is cleared when it drops.
- The **recovery key** is 32 random bytes that the host keeps in its custody, as it keeps the key of the challenges.
  Give it with `RelyingParty::with_recovery(key)`. Keep it for the life of the codes: a new key ends each code, because
  no stored digest verifies under it. A relying party with no recovery key refuses each recovery operation with
  `Error::RecoveryKey`.
- The **record of the code** has the kind `Kind::Recovery`. Each account has at most one. Its key is the SHA-256 digest
  of the CBOR form `["rsauthnz.recovery.1", authority, relying party ID, user handle]`, so one keyed read finds it,
  also in a large store. The record holds the account, the user handle, and the keyed BLAKE3 digest of the code under
  the recovery key. It holds no code, so a dump of the store and of the restore journal gives no code. The code has 128
  random bits, so a memory-hard KDF would add no protection: it would only make each attempt cost more.
- The record is an **authority anchor** of the account: a restore keeps it ([Restore](restore.md)). It is no sign-in
  method, so the account keeps a passkey also when it has a code ([Remove a passkey](accounts.md#remove-a-passkey)).
- The **recovery challenge** is 112 bytes: 32 random bytes, the time of its creation, the digest in the key of the
  record, the version of the record, and an HMAC-SHA256 tag of the four under the key of the relying party. It serves
  for `REGISTRATION_LIFETIME` (300 seconds). A recovery or a new code changes the record, so each earlier challenge
  refuses.

## Make a recovery code

A new code is a sensitive change.

1. Get a fresh user verification of the signed-in account (`Fresh`, [Fresh user
   verification](accounts.md#fresh-user-verification)).
2. Call `rp.recovery_code(&mut store, &fresh, &handle, now, &mut random, &mut driver)`. `handle` is the user handle of
   the account. The call reads the passkeys of the account and the record of its code.
3. Submit the proposal with its plan. Only the accepted commit releases the text of the code: `receipt.artifact()`,
   39 ASCII bytes. Show it to the user once, for example to print or to keep in a password manager.
4. After a lost response, propose again. The receipt of a lookup has no artifact, and the new code ends the code of
   the lost response.

The commit reads the session of the verification at its version, and its deadline is the end of the verification. It
reads a passkey of the account at its version, writes the record of the new code, and ends the earlier code in the same
commit. The restore journal records the end of the earlier version, so a restore never makes the earlier code valid
again.

## Recover

1. The user gives the name of the account, such as an email address, and the code. The application finds the account
   and its user handle by the name. The name only finds the account: the code is the proof, so a match of an email
   address cannot start a recovery.
2. Read the code with `Code::parse(text)`, and call `rp.recovery_options(&mut store, &user, &code, now, &mut random)`.
   `user` is a `User`: the account, its user handle, and the names that the authenticator shows. The call computes one
   keyed hash and makes one keyed read. It refuses with `Error::Code` for each code that is not the code of the
   account, also for an account with no code. It writes nothing. Send the options with `rsauthnz_http::json`. The
   page runs `register({ options, finish, body })` of the [browser adapter](browser-adapter.md#register), with the
   name and the code in `body`.
3. The browser sends `credential.toJSON()`. Check the request with `site.json_change`, and read the body with
   `Response::parse`.
4. Call `rp.recover(&mut store, &response, &sessions, passkeys, now, &mut random, &mut driver)`.
   Use `Passkeys::End` to replace all previous passkeys. Use `Passkeys::Keep` to retain them.
   With 32 current passkeys, `Keep` returns `Error::Full`. Both policies end earlier sessions, account CLIs, and approvals.
5. Call `attempt.propose(&reads)` with the dependencies of the application decision. Submit the proposal and its plan together.
6. Call `opening.release(&outcome)` and send the accepted session identifier in the cookie.
   Show the user the new passkey. After full recovery, use `signalAccepted` to hide retired passkeys in a synchronized provider.
7. Make a new recovery code from the new session.

Recovery advances a durable number for this account and passkey site. A renewal, CLI call, or enrollment finish prepared
under the old number conflicts if recovery commits first. A stream stops at its next confirmation. Other accounts keep their access.

After a lost response, keep the opening, and look up the operation of the proposal (`proposal.operation()`) when the
driver serves again. Give the receipt of the lookup to `opening.release` as `Outcome::Accepted`. Never send the
recovery again ([Outcomes and recovery](transitions.md#outcomes-and-recovery)).

The plan names the new passkey as a sign-in method of the account. So a restore from a snapshot before the commit
completes a recovery that a crash left in doubt, once, before the store serves. The restored store holds the new
passkey, the code is consumed, and the sessions and passkeys that the commit ended stay ended. The new session is not
restored: the user signs in with the new passkey ([Restore](restore.md)).

## The evidence of a recovery

The evidence of the new session has `Method::Recovery`. It is never phishing resistant, and it has no authentication
of a signature, because no signature of the account proved it. It records the user verification of the registration
of the new passkey: the passkey profile requires it. Thus a permit that requires phishing resistance refuses a
recovery session ([Authorize an operation](authorization.md)), and the session is a fresh user verification for
`FRESH_MAX` (300 seconds).

## Example

This example is also the example of the `rsauthnz::recovery` module documentation, and `cargo xtask test` runs it. It
checks codes on the memory binding of `rsauthnz-conformance`. An email address is no code, and a code that the store
does not hold refuses after one keyed read. A recovery needs a browser and an authenticator.

```rust
use core::pin::pin;
use core::task::{Context, Poll, Waker};
use core::time::Duration;

use rsauthnz::id::Id;
use rsauthnz::limits::Limits;
use rsauthnz::passkey::{Error, Failure, RelyingParty, User, UserHandle};
use rsauthnz::recovery::Code;
use rsauthnz::store::driver::Driver;
use rsauthnz::store::{Profile, Store};
use rsauthnz::time::{Reading, ReadingSource};
use rsauthnz_conformance::memory::{Memory, Schedule};
use rsauthnz_conformance::suite::execute;
use rscrypto::ChaCha20Rng;

/// The output of a future of the memory binding, which is ready at its first poll.
fn ready<T>(future: impl Future<Output = T>) -> T {
    let Poll::Ready(output) = pin!(future).poll(&mut Context::from_waker(Waker::noop())) else {
        unreachable!("the memory binding does no I/O");
    };
    output
}

let now = Reading::new(Duration::from_secs(1_800_000_000), Some(Duration::from_secs(1)), ReadingSource::Caller);
let mut memory = Memory::new(Schedule::None);
let mut driver = Driver::new(Profile::new(memory.declaration())?, Limits::default())?;
driver.start(now);
while let Some(effect) = driver.effect() {
    let output = ready(execute(&mut memory, effect));
    driver.give(output)?;
}
let mut random = ChaCha20Rng::from_seed([7; 32]);
// The host keeps both keys in its custody. A new recovery key ends each recovery code.
let rp = RelyingParty::new(Id::new("acme", "auth")?, "app.example", "https://app.example", "Acme", [3; 32], Limits::default())?
    .with_recovery([4; 32]);

// An email address is no recovery code.
assert_eq!(Code::parse(b"alice@app.example").err(), Some(Error::Code));

// Alice gives the name of her account and a code. The application found her account and its user handle by the name.
let alice = Id::new("acme", "alice")?;
let user = User { account: &alice, handle: UserHandle::from_bytes([9; 32]), name: "alice@app.example", display_name: "Alice" };
let code = Code::parse(b"3F9A 08C1 7D2E 55B0 C4A9 1E63 F087 2B5D")?;
let refused = ready(rp.recovery_options(&mut memory, &user, &code, now, &mut random));
assert!(matches!(refused, Err(Failure::Refused(Error::Code))));
```

## Errors

The recovery operations of `RelyingParty` refuse with `passkey::Error` ([Errors](passkeys.md#errors)). The operations
that read the store return `passkey::Failure`.

| `Error` | Cause | Recovery |
| --- | --- | --- |
| `RecoveryKey` | The relying party has no recovery key | `Refuse` |
| `Code` | The text is not a code, or the account has no code with the value: a recovery or a new code ended it, or it is the code of another account | `Refuse`: the user types the code again |
| `Dit` | This build on this CPU cannot handle a code with data-independent timing, as on Windows aarch64 without `-C target-feature=+dit` | `Refuse` |
| `Challenge` | The challenge of the response is not a recovery challenge of the key, or it ended | `Restart`: check the code again |
| `Credential` | The account of the verification has no passkey under the user handle of `recovery_code` | `Refuse` |
| `Full` | `Passkeys::Keep` for an account that has `CREDENTIALS_MAX` (32) passkeys | `Refuse` |
| `Transition(error)` | The proposal refuses, also for a decision with more reads than the limits permit | `error.recovery()` |
| `Session(error)` | The new session refuses ([Keep a browser session](sessions.md#errors)) | `error.recovery()` |

The cost class of `Code::parse` and `Attempt::propose` is `Parse`. The cost class of `recovery_options` is `Verify`
([Admit rsauthnz work](admission.md)): one keyed hash and one keyed read, which a flood of guesses pays for each
attempt. Full recovery reads the code and the newest account revision. Its commit has fixed size for any number of sessions or CLIs.
Keeping previous passkeys also reads their enrollment revision and one page of at most `CREDENTIALS_MAX` records. Issuing a code reads the current passkeys and the code record. The commit checks the revision of the fresh session.

## Upgrade existing accounts

Keep the passkey authority, relying party ID, challenge key, and recovery key. Existing passkeys and recovery codes still work.
Clear an old session cookie on the next request and ask the user to sign in once. Ask each account CLI to enroll again.
Restart pending registration and enrollment requests. Their earlier records did not bind the request to an account recovery number.

## Support

The tests on this Mac (macOS aarch64) run on the memory binding with the test authenticator of the passkey tests. They
cover one recovery for each code, two concurrent recoveries with one code, the end of the sessions and of the named
passkeys, the evidence, an account with more sessions than one commit holds, a recovery in doubt at a restore, a lost
response, a new code that ends the earlier code and its challenges also after a restore, and a dump of the store and
of the journal with no code. A counting store shows one keyed read and no range read for each check of a code, with 10
and with 1,000 other records. The fuzz target `recovery` reads hostile text with `Code::parse` ([Fuzz the
parsers](fuzzing.md)), and no campaign has run it yet. No real browser or authenticator has run a recovery yet.
