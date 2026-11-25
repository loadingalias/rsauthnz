# Keep a browser session

`rsauthnz::session` keeps the session of a signed-in browser. The browser holds an opaque identifier in a `__Host-`
cookie. The store holds one record for each session family. A [passkey sign-in](passkeys.md#sign-in) or a
[recovery](recovery.md#recover) opens a family.
Each request checks the family and the account recovery number in one store call. A renewal rotates the identifier within its family.

The core proposes each change, and the storage binding of the application commits it ([Propose a
transition](transitions.md)). The HTTP binding writes and reads the cookie ([Mount the HTTP binding](http-binding.md)).

## The model

- A **session family** is one sign-in of one browser. Its record has the kind `Kind::Session`. The record holds the
  account, the evidence of the sign-in, and the time of the sign-in. It also holds the start of the current generation
  and two tags.
- A **generation** is one identifier of the family. A renewal consumes the current generation and writes the next
  one. The family keeps its sign-in and its evidence.
- The **identifier** holds 104 bytes. It carries a 16-byte locator, a 16-byte random family number, a 32-byte account scope,
  an eight-byte recovery number, and a 32-byte random secret. The cookie encodes these as 139 base64url characters.
- The **key** starts with `Kind::Session` and the locator. It ends with the first 16 bytes of SHA-256 over the namespace and family number.
  The namespace is the SHA-256 digest of the CBOR array `["rsauthnz.session.2", authority, audience]`.
  The locator takes the first 16 bytes of SHA-256 over the namespace, account scope, and big-endian recovery number.
- The **tag** of a generation is the HMAC-SHA256 tag of `"rsauthnz.session.2"` and the key, under the secret. The
  record holds the tag of the current generation and of the generation that the last renewal replaced. It holds no
  secret and no identifier, so a read or a dump of the store gives no usable session. The check compares the tag in
  constant time.
- The **audience** (`Id<Audience>`) is the service that accepts the sessions, such as `acme:app`. A session of one
  audience never serves another audience of the same store.

The record form is the canonical CBOR array `["rsauthnz.session.2", evidence, epoch, started, issued, tag,
previous tag or null]`. `started` and `issued` are nanoseconds since the Unix epoch. The evidence is the form of
`Evidence::to_cbor`. `epoch` records the account scope, recovery number, record version, and passkey generation. [Vocabulary](vocabulary.md)

## Choose the times

`Policy` gives three times. rsauthnz has no default: the application states each one.

| Field | Meaning |
| --- | --- |
| `lifetime` | The time from the sign-in to the end of the family. No renewal extends it |
| `idle` | The time from the start of a generation to its end. A session with no renewal in this time ends. A renewal is due after half of it |
| `grace` | The time after a renewal in which the replaced identifier serves its requests and cannot renew. After it, a use of that identifier ends the family |

`Sessions::new` refuses with `Error::Policy` when `idle` is zero or longer than `lifetime`, or when `grace` is not
shorter than `idle`. For example, take a lifetime of 30 days, an idle time of 2 days, and a grace time of 30 seconds.
An active user then stays signed in for 30 days. A browser that sends no request for 2 days is signed out.

The grace time is the window of a race. Two tabs of one browser can send requests with the same identifier while one
of them renews it. The request that lost the race still serves, and the browser gets the new cookie from the response
of the renewal. A use of the replaced identifier after the grace time shows that two holders have it: the identifier
can be stolen. The check then gives the commit that ends the family, so the holder that renewed first loses the
session too.

## Before you start

- Mount the HTTP binding, and register a passkey for the account ([Register a passkey and sign in](passkeys.md)).
- Build one `Sessions` at startup: `Sessions::new(authority, audience, policy, limits)`. On Windows aarch64, it
  refuses with `Error::Dit` unless the build sets `-C target-feature=+dit`. There, rscodec cannot detect at run time
  that the CPU has data-independent timing.
- Give each check a time reading with a known bound. A reading with no bound refuses with
  `Error::Time(TimeError::UnknownBound)`.

## Sign in

1. Check the assertion with `rp.sign_in_read(&mut store, assertion, now)` and then `records.verify()` ([Sign
   in](passkeys.md#sign-in)). It gives a `passkey::SignIn`, which has no proposal yet.
2. Call `sign_in.open(&sessions, replaces, &mut random, &mut driver)`. `replaces` is the `Access` of the current
   session of the browser, if the request has one, and `None` otherwise. It gives the proposal, its plan, and an
   `Opening`.
3. Submit the proposal with its plan. Give the outcome to `opening.release(&outcome)`. Only the accepted commit gives
   `Opened`: the `evidence` of the sign-in and the `session`.
4. Write the cookie with `site.set_session(headers, SESSION, opened.session.identifier(),
   opened.session.max_age(now))`.

The commit writes the family with the replay record of the challenge. Thus the store holds the session and its audit
before the browser gets the identifier. A sign-in that presents the current session ends that family in the same
commit. Thus each sign-in, also a fresh user verification of a signed-in account, gives a new identifier, and the old
one refuses.

After a lost response (`Outcome::Unknown`), keep the opening. Look up the operation of the proposal
(`proposal.operation()`) when the driver serves again, and give a commit to
`opening.release(&Outcome::Accepted(receipt))`. The opening keeps the identifier, so the same request gets its
session ([Lost responses](http-binding.md#lost-responses)).

## Check each request

1. Read the cookie with `SESSION.session(request.headers())`. It gives `None` when the request has no session
   cookie.
2. Call `sessions.check(&mut store, &identifier, now)`. It reads the record of the family by its key.
3. On `Check::Active(access)`, serve the request as `access.session().account()`.
4. On `Check::Reused(proposal, plan)`, submit the proposal: it ends the family. Then clear the cookie with
   `site.clear_cookie`, and refuse the request.
5. On `Error::Unknown` or `Error::Ended`, or a refusal of the cookie read, clear the cookie and treat the request as
   signed out. The browser cannot change an `HttpOnly` cookie, so only the server can clear it.

`access.generation()` is `Generation::Current`, or `Generation::Replaced` within the grace time after a renewal. Both
serve the request.

## Renew

1. After a check, call `access.renewal_due(now)`. It is true for the current generation after half of the idle time.
2. Call `sessions.renew(&access, now, &mut random, &mut driver)`. It gives the proposal, its plan, and a `Renewal`.
3. Submit the proposal with its plan, and give the outcome to `renewal.release(&outcome)`. On `Some(issued)`, write
   the new cookie with `site.set_session` on the response.

The commit reads the family at its version, writes the next generation, and its plan names the key as replaced
(`Plan::replaced`). Thus two renewals of one generation commit once. The other one conflicts, and its identifier is
then the replaced one: serve its request with no renewal. A renewal of a replaced identifier refuses with
`Error::Replaced`. A renewal at or after the end of the family refuses with `Error::Ended`. The end of each
generation is at most the end of the family.

After a lost response, keep the renewal, look up its operation, and give a commit to
`renewal.release(&Outcome::Accepted(receipt))`. If the browser gets no new cookie, its identifier is the replaced one:
it serves for the grace time, and a later use ends the family. The user then signs in again.

The restore journal records each renewal as the end of the version that it replaced ([Restore journal](restore.md)).
Thus a restore from a snapshot before a renewal ends that family, and no generation serves twice.

## Sign out, list, and revoke

- **Sign out:** call `sessions.revoke(access.session(), Revoker::Own(&access), &[], now, &mut random)`, submit the
  proposal, and clear the cookie. A sign-out needs no fresh user verification.
- **List:** `sessions.list(&mut store, &access, after, now)` confirms the session, then reads one `Page` of at most
  `PAGE_MAX` (64) records: each session of the account that did not end. `page.next` is the key after which the next
  page starts, or `None`. Each `Session` gives its `key()`, its `evidence()`, `started()`, `issued()`, `end()`, and
  `expires()`.
- **Revoke:** give a listed session to `sessions.revoke` with its `Revoker`. The end of another session of the
  account, such as the session of a lost laptop, is a sensitive change: give `Revoker::Fresh(&fresh)`, a fresh user
  verification of the account ([Manage accounts](accounts.md#fresh-user-verification)). The commit reads the session
  of the verification at its version, and it refuses after the end of the verification. `Revoker::Other(principal)`
  is another principal, such as an administrator, and never the account of the session. `decision` holds the reads of
  the decision of the application that the revoker can end the session, and the commit reads each one. A revocation
  of a session that renewed after its read conflicts: list again.

For an application change that uses this session, call `access.gate(&mut proposal)?` before submission.
The same commit checks the family version, the account revision, and the identifier deadline.

## Streams and queued output

Before each part of a stream, and before queued output, call `sessions.confirm(&mut store, access.session(), now)`. It
reads the family and account revision together. Either recovery policy ends the stream. A renewal keeps the family, so a stream continues after it. A revocation, a sign-in
that replaced the family, the idle time, and the lifetime each end it: `confirm` refuses with `Error::Ended`, and the
stream stops.

## Example

This example is also the example of the `rsauthnz::session` module documentation, and `cargo xtask test` runs it. A
sign-in needs a browser and an authenticator, so the example shows only the refusals of a check:

```rust
use core::pin::pin;
use core::task::{Context, Poll, Waker};
use core::time::Duration;

use rsauthnz::id::Id;
use rsauthnz::limits::Limits;
use rsauthnz::session::{Error, Failure, Identifier, Policy, Sessions};
use rsauthnz::store::driver::Driver;
use rsauthnz::store::{Profile, Store};
use rsauthnz::time::{Reading, ReadingSource};
use rsauthnz_conformance::memory::{Memory, Schedule};
use rsauthnz_conformance::suite::execute;

/// The output of a future of the memory binding, which is ready at its first poll.
fn ready<T>(future: impl Future<Output = T>) -> T {
    let Poll::Ready(output) = pin!(future).poll(&mut Context::from_waker(Waker::noop())) else {
        unreachable!("the memory binding does no I/O");
    };
    output
}

// A family ends 30 days after its sign-in, and a session with no request for 2 days ends.
let policy = Policy {
    lifetime: Duration::from_secs(30 * 24 * 60 * 60),
    idle: Duration::from_secs(2 * 24 * 60 * 60),
    grace: Duration::from_secs(30),
};
let sessions = Sessions::new(Id::new("acme", "auth")?, Id::new("acme", "app")?, policy, Limits::default())?;

// A cookie that is not an identifier refuses before a read.
assert_eq!(Identifier::parse(b"c2Vzc2lvbg").err(), Some(Error::Identifier));

// The store serves after the start of its commit driver.
let now = Reading::new(Duration::from_secs(1_800_000_000), Some(Duration::from_secs(1)), ReadingSource::Caller);
let mut memory = Memory::new(Schedule::None);
let mut driver = Driver::new(Profile::new(memory.declaration())?, Limits::default())?;
driver.start(now);
while let Some(effect) = driver.effect() {
    let output = ready(execute(&mut memory, effect));
    driver.give(output)?;
}

// An identifier of no session refuses after one paired read.
let stranger = Identifier::parse(&[b'A'; rsauthnz::session::IDENTIFIER_CHARS])?;
let refused = ready(sessions.check(&mut memory, &stranger, now)).unwrap_err();
assert_eq!(refused, Failure::Refused(Error::Unknown));
```

## Errors

Each `session::Error` is a small `Copy` value with no secret. `error.recovery()` of the trait `transition::Recover`
gives `Refuse`, `Verify` for `Fresh`, or the recovery of the proposal for `Transition`.

| `Error` | Cause | Response |
| --- | --- | --- |
| `Policy` | The times of the policy are not valid | Correct the configuration |
| `Dit` | This build on this CPU cannot encode or decode with data-independent timing | Build with `-C target-feature=+dit` on Windows aarch64 |
| `Identifier` | The cookie value is not the base64url text of 64 bytes | Clear the cookie, and treat the request as signed out |
| `Unknown` | No session of this audience has the identifier, also after a revocation or a sign-in that replaced the family | Clear the cookie, and treat the request as signed out |
| `Ended` | Account recovery, idle expiry, or lifetime expiry. `confirm` also detects revocation and replacement at sign-in | Clear the cookie, and treat the request as signed out |
| `Replaced` | A renewal of a replaced identifier | Serve the request with no renewal |
| `Principal` | The subject of the evidence of a sign-in is not a human | Refuse |
| `Record` | A record has no valid form | Refuse |
| `Time` | The reading has no bound, or a time overflows | Give a reading with a known bound |
| `Driver` | The commit driver does not serve | Refuse |
| `Transition(error)` | The proposal refuses | `error.recovery()` |
| `Fresh` | A `Revoker::Own` of another session, a `Revoker::Fresh` of another account, or a `Revoker::Other` that is the account of the session | `Recovery::Verify`: verify the user again, and end the session with `Revoker::Fresh` |

`check`, `list`, and `confirm` read the store, so they return `session::Failure`: `Refused(error)`, or
`Store(error)` for a failed read, which is a crash of the binding. A sign-in gives a refusal of its session as
`passkey::Error::Session(error)`.

The cost class of `check`, `list`, and `confirm` is `Verify` ([Admit rsauthnz work](admission.md)). `check` makes two keyed lookups in one round trip and writes nothing for a valid session.
`confirm` uses the same paired read. `list` also reads one page of up to 64 families.
The cost class of `renew`, `revoke`, `Identifier::parse`, and `Identifier::encode` is `Parse`.

## Support

The tests on this Mac (macOS aarch64) run on the memory binding. They cover the sign-in, the check, two concurrent
renewals, the grace time, and the reuse. They also cover the lifetime, the listing, the revocation of a session with an
open stream, and a lost renewal response. A restore from a snapshot before a renewal and a dump of the store have tests
too. No real browser has run a session of rsauthnz yet.
