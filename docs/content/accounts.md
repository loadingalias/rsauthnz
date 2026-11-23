# Manage accounts

`rsauthnz::account` adds the account journeys to [passkeys](passkeys.md) and [sessions](sessions.md): an invitation
that activates a new account, an additional passkey, the list, the rename, and the removal of passkeys, and the
fresh user verification that each sensitive change needs. Each operation proposes one commit, and the storage binding
of the application accepts it ([Propose a transition](transitions.md)). The rename of an account is a change of the
records of the application ([Rename an account](#rename-an-account)).

## The model

- An **invitation** lets one recipient activate one account. Its record (`Kind::Invitation`) holds the recipient
  account, its user handle, the issuer, and the action and the resource of the issuer. Its key is the SHA-256 digest
  of the CBOR form `["rsauthnz.invitation.1", authority, relying party ID, value]`. The **invitation value** is
  `INVITATION_BYTES` (32) random bytes, such as in the link that the issuer sends. The store keeps only the digest,
  so a read of the store gives no usable invitation. An invitation ends after its lifetime, at most
  `INVITATION_LIFETIME_MAX` (7 days).
- An **activation** registers the first passkey of the recipient and consumes the invitation in one commit. The
  invitation is the registration ceremony of the activation, so the activation writes no pending registration. Its
  challenge is 104 bytes: 32 random bytes, the time of its creation, the digest in the invitation key, and an
  HMAC-SHA256 tag of the three under the key of the relying party. It serves for `REGISTRATION_LIFETIME` (300
  seconds).
- A **fresh user verification** (`Fresh`) is a session whose evidence has user verification and is at most
  `FRESH_MAX` (300 seconds) old. A **sensitive change** needs one: an additional passkey, the removal of a passkey,
  a new recovery code ([Recover an account](recovery.md#make-a-recovery-code)), the approval of a CLI ([Enroll the CLI
  from a browser](cli.md#enroll-the-cli-from-a-browser)), and the end of another session of the account. A new account
  name that finds the account also needs one ([Rename an account](#rename-an-account)). The rename of a passkey, a new
  display name, and a sign-out need none.

## Issue an invitation

1. The issuer signs in, for example with a passkey, and the application has the `Evidence` of the sign-in.
2. Draw a user handle for the new account (`UserHandle::random`).
3. Call `rp.invite(&evidence, &policy, &invite, now, &mut random, &mut driver)`. `invite` is an `Invite`: the
   `recipient` account, its `handle`, the `action` and the `resource` of the issuer, such as `acme:team.invite` on
   `acme:team-1`, and the `lifetime`. `authz::check` checks that `policy` permits the action on the resource for the
   subject of the evidence ([Authorize an operation](authorization.md)). The proposal reads the policy version, and its
   deadline is the deadline of the checked scope.
4. Submit the proposal with its plan. Only the accepted commit releases the invitation value:
   `receipt.artifact()`. Encode it with base64url, and send the link to the recipient.
5. After a lost response, issue again. The receipt of a lookup has no artifact, and the earlier invitation ends
   unused.

## Activate an invitation

1. The recipient opens the link. The page posts the invitation value to the options path of the server, for example
   with the `register` function of the [browser adapter](browser-adapter.md#register).
2. Call `rp.activation_options(&mut store, &value, &invitee, now, &mut random)`. `invitee` is an `Invitee`: the
   account that activates and the names that the authenticator shows. The call reads the invitation and checks its
   recipient. It refuses with `Error::Activated` when the account has a passkey: an authenticator would replace that
   passkey. It writes nothing. Send the options with `rsauthnz_http::json`.
3. The browser sends `credential.toJSON()`. Check the request with `site.json_change`, and read the body with
   `Response::parse`.
4. Call `rp.activate(&mut store, &response, &recipient, &policy, now, &mut driver)`. It checks the tag and the
   lifetime of the challenge before any read. Then it reads the invitation of the challenge, checks the recipient,
   checks that the recipient has no passkey, and checks the response as a registration does. The policy must still
   permit the action of the issuer on its resource: an issuer that lost the authority refuses with `Error::Issuer`.
   It gives an `Activation`: `account()`, `credential()`, `action()`, and `resource()`.
5. Call `activation.propose(&reads)` with the reads of the decision of the application, and submit the proposal with
   its plan. The commit reads the invitation at its version and the policy version, ends the invitation, and writes
   the credential record. Its deadline is the earliest end of the challenge, of the invitation, and of the permit of
   the issuer.

The operation identity is a digest of the invitation key and the credential key. Thus the same response again gets
the receipt of the first commit. Two passkeys for one invitation are two operations: one commits, and the read of the
invitation makes the other conflict. After the commit, each activation and each new options of the value refuse with
`Error::Invitation`. After a lost response, look up the operation of the proposal (`proposal.operation()`).

The plan names the passkey as a sign-in method of the account. So a restore from a snapshot before the commit
completes an activation that a crash left in doubt, once, before the store serves, and the account has its sign-in
method ([Restore](restore.md)). The account signs in with that passkey as each account does ([Sign
in](passkeys.md#sign-in)).

## Fresh user verification

1. The account signs in with a passkey that replaces the current session of the browser:
   `sign_in.open(&sessions, Some(&access), &mut random, &mut driver)` ([Sign in](passkeys.md#sign-in)). The new
   session holds the evidence of the assertion, with its time and its user verification.
2. On the request of the change, check the session (`sessions.check`), and call
   `Fresh::check(&access, max_age, now)`. `max_age` is at most `FRESH_MAX`: an application can make the window
   shorter, never longer. The check refuses with `account::Error::Stale` when the evidence has no user verification,
   or when its earliest time is `max_age` or more before the latest time of `now`.
3. Give the `Fresh` to the sensitive change. The commit reads the session at its version, so a revocation or a
   renewal of the session makes it conflict. Its deadline is `fresh.deadline()`: the time of the verification plus
   `max_age`, or the end of the session when that is earlier. A commit after the deadline refuses with
   `transition::Error::Expired`.

After `Error::Stale`, `passkey::Error::Fresh`, or `session::Error::Fresh`, the recovery is `Recovery::Verify`. The
HTTP binding answers `403 Forbidden` with `{"recovery":"verify"}`, and the page signs in again and starts the change
again ([HTTP binding](http-binding.md)).

## Add a passkey

Run the registration of [Register](passkeys.md#register) with `Decision::Add(&fresh, &reads)` at the start and at
the finish. A `Decision::SignUp` of an account that has a passkey refuses with `Error::Fresh`, at the start and at the
finish. The finish reads the passkeys of the account again, so a passkey that another ceremony added in the meantime
also needs the verification. The verification must hold at the commit of the finish: after `Error::Fresh` or an
expired commit, verify the user again and finish again. The pending registration stays until its end.

## List and rename passkeys

- **List:** `rp.passkeys(&mut store, &handle)` gives each `account::Passkey` of the account, from one range read of
  at most `CREDENTIALS_MAX` (32) records. Each one gives its `key()`, its `account()`, and its `credential()`: the
  ID, the algorithm, the signature counter, the backup state, and the `name()`.
- **Rename:** `rp.rename(&access, &passkey, name, now, &mut random, &mut driver)` proposes the name `name` (1 to 256
  bytes) of a listed passkey of the account of `access`. It needs no fresh user verification. The commit reads the
  session and the credential record at their versions, so a sign-in that advanced the counter makes it conflict: list
  again. A passkey of another account refuses with `Error::Credential`.

## Remove a passkey

Call `rp.remove(&mut store, &fresh, &passkey, now, &mut random, &mut driver)` with a listed `passkey`, and submit
the proposal with its plan. The commit ends the credential record of the passkey. It reads another passkey of the
account at its version, so two removals of the last two passkeys cannot both commit. The plan holds each passkey of
the account, and the commit driver refuses the removal of the last sign-in method that the restore journal records as
live.

The commit also writes the **removal mark** of the passkey (`Kind::Removal`), which ends after
`REMOVAL_MARK_LIFETIME` (400 days). A provider that no Signals call reached still offers the passkey. Until the mark
ends, a sign-in with it refuses with `Error::Removed`, whose recovery is `Forget`, so the provider can forget it. A
passkey that the store never held refuses with `Error::Credential`: its registration finish can come late, so the
provider keeps it. Each commit that writes a passkey reads its removal mark as absent, so a removed passkey never
registers again. A recovery ends passkeys with no mark ([Recover](recovery.md#recover)).

The removal of the last passkey refuses with `Error::Transition(transition::Error::LastAnchor)`, also when the
account has a [recovery code](recovery.md): a recovery code is no sign-in method. A removal ends no session. To end the sessions of
a lost device, list them and end each one with `Revoker::Fresh` ([Sign out, list, and
revoke](sessions.md#sign-out-list-and-revoke)).

Add the reads of the decision of the application to a removal or a rename with `proposal.read` before the submission.

## Rename an account

The application owns the name and the display name of an account. No record of rsauthnz holds them. Give them in
the `User` or the `Invitee` of each ceremony, so the next options give the new names to the authenticator. Thus a
rename changes only the records of the application:

1. Check each new name: 1 to `passkey::NAME_BYTES_MAX` (256) bytes. A longer name makes the next start refuse with
   `Error::Name`, so refuse it at the rename.
2. Check the session of the request (`sessions.check`). A new display name needs only the session.
3. When the name finds the account, such as at a [recovery](recovery.md#recover), also call `Fresh::check`. Without
   it, a stolen session can rename the account and hide it from the recovery of its owner.
4. Refuse a name that another account holds. Write the new names in one change of the records of the application.
5. On the page, call `signalRenamed({ rpId, userId, name, displayName })` of the [browser
   adapter](browser-adapter.md#keep-the-password-manager-in-step). `userId` is the user handle as base64url. Also call
   it at each sign-in, so a provider on another device learns the new names.

## Example

This example is also the example of the `rsauthnz::account` module documentation, and `cargo xtask test` runs it. It
asks for the options of an activation on the memory binding of `rsauthnz-conformance`. A value that is not an open
invitation refuses after one keyed read. An issue needs the evidence of a signed-in issuer, and a finish needs a
browser and an authenticator.

```rust
use core::pin::pin;
use core::task::{Context, Poll, Waker};
use core::time::Duration;

use rsauthnz::account::{INVITATION_BYTES, Invitee};
use rsauthnz::id::Id;
use rsauthnz::limits::Limits;
use rsauthnz::passkey::{Error, Failure, RelyingParty};
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
let rp = RelyingParty::new(Id::new("acme", "auth")?, "app.example", "https://app.example", "Acme", [3; 32], Limits::default())?;

// Bob opens the link of an invitation with a value that the store does not hold.
let bob = Id::new("acme", "bob")?;
let invitee = Invitee { account: &bob, name: "bob@app.example", display_name: "Bob" };
let refused = ready(rp.activation_options(&mut memory, &[1; INVITATION_BYTES], &invitee, now, &mut random));
assert!(matches!(refused, Err(Failure::Refused(Error::Invitation))));
```

## Errors

The account operations of `RelyingParty` refuse with `passkey::Error` ([Errors](passkeys.md#errors)): `Fresh`,
`Invitation`, `Recipient`, `Activated`, `Issuer`, `Lifetime`, `Authorization`, and `Credential`. The operations that
read the store return `passkey::Failure`. `Fresh::check` refuses with an `account::Error`:

| `account::Error` | Cause | Recovery |
| --- | --- | --- |
| `Stale` | The evidence of the session has no user verification, or it is older than the maximum age | `Verify`: sign in again with a passkey that replaces the session |
| `Replaced` | The identifier holds the replaced generation of its session | `Restart`: the next request holds the current identifier |
| `Window` | The maximum age is longer than `FRESH_MAX` | `Refuse` |
| `Time` | A reading has no bound, or a time overflows | `Refuse`: give a reading with a known bound |

The cost class of `invite`, `rename`, `Fresh::check`, and `Activation::propose` is `Parse`. The cost class of
`activation_options`, `activate`, `passkeys`, and `remove` is `Verify` ([Admit rsauthnz work](admission.md)): one
keyed read and one range read for the activation, and one range read for the list and the removal. The call of the
policy is the cost of the application.

## Support

The tests on this Mac (macOS aarch64) run on the memory binding with the test authenticator of the passkey tests. They
cover one activation of an invitation, two concurrent activations, another recipient, a policy that no longer permits
the issuer, an activation in doubt at a restore, and a dump of the store with no invitation value. They also cover
an old and an unverified assertion, the deadline of a verification, the last passkey with a recovery value, two
concurrent removals, a rename, a sign-in with a removed passkey and its second registration, and the end of another
session. The [web example](web-example.md) tests the rename of an account and a sign-in with a removed passkey through
its HTTP API. No real browser or authenticator has run an activation or a Signals call yet.
