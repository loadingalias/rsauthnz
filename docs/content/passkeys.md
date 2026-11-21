# Register a passkey and sign in

`rsauthnz::passkey` runs the registration and the sign-in of [WebAuthn Level 3](https://www.w3.org/TR/webauthn-3/).
A passkey is a key pair that an authenticator keeps for one account at one site. A registration binds a new passkey
to an account as a sign-in method. A sign-in proves the account with an assertion: a signature of the passkey over a
challenge of the site.

The core checks the response and proposes each commit. The storage binding of the application accepts the commit
([Propose a transition](transitions.md)). The HTTP binding checks each browser request and writes its response
([Mount the HTTP binding](http-binding.md)).

## The model

- The **relying party** (`RelyingParty`) is the site: its relying party ID, such as `app.example`, its origin, such
  as `https://app.example`, the name that an authenticator shows, the authority that owns its records, and the key of
  its sign-in challenges. The origin
  is the origin of the relying party ID or of a subdomain of it, in the form that a browser writes: no default port and
  no final `/`. For development, the relying party ID `localhost` takes `http://localhost` with an optional port.
- The **user handle** (`UserHandle`) is 32 random bytes with no personal data. Each passkey of an account has the
  same handle, so an authenticator keeps one passkey for each account. Draw it once for a new account
  (`UserHandle::random`), and keep it with the account.
- The **pending registration** is a record of the kind `Kind::Registration`. Its key is the SHA-256 digest of a
  challenge of 32 random bytes, and it holds the account and the user handle. It ends after `REGISTRATION_LIFETIME`
  (300 seconds). The record keeps the digest and never the challenge. The response is not signed, so the challenge is
  the only proof that the response comes from the ceremony of the account.
- The **credential record** is a record of the kind `Kind::Credential` at `passkey::credential_key(id)`: the SHA-256
  digest of the credential ID. It holds the account, the user handle, the credential ID, the `COSE_Key` of the
  passkey, its algorithm, its signature counter, and its backup flags. It has no end.
- A **sign-in challenge** is 72 bytes: 32 random bytes, the time of its creation, and an HMAC-SHA256 tag of both
  under the key of the relying party. No record holds it until it serves a sign-in. Then the commit writes its
  **replay record** (`Kind::Replay`), which ends after `SIGN_IN_LIFETIME` (300 seconds) and a margin of twice the
  bound of the reading.

## Register

1. At startup, build one `RelyingParty::new(authority, id, origin, name, key, limits)`. `key` is 32 random bytes
   that the host keeps secret, the same on each node of the site. A new key ends each open sign-in challenge.
   `limits` bound the CBOR of each response ([Parser limits](parser-limits.md)).
2. The application decides that the account can register, for example a new account of an open sign-up. Call
   `rp.start(&user, operation, now, &mut random, &mut driver)`. `user` names the account, its user handle, and the
   name and the display name that the authenticator shows. The options hold the names, and no record does. Add the
   reads of the decision of the application to the proposal, and submit it with its plan.
3. Only the accepted commit releases the options: `receipt.artifact()`. Send them to the browser with
   `rsauthnz_http::json`. After a lost response, start again with a new operation identity. The receipt of a lookup
   has no artifact.
4. The browser gives the options to `PublicKeyCredential.parseCreationOptionsFromJSON()`, calls
   `navigator.credentials.create()`, and sends `credential.toJSON()` as the JSON body of a state change.
5. Check the request with `site.json_change`, then read the body with `Response::parse`.
6. Call `rp.finish(&mut store, &response, now, &mut driver)`. It reads the pending record of the ceremony. With no
   record, the ceremony ended or never started, and it refuses with `Error::Challenge` (`Recovery::Restart`). Submit
   the proposal with its plan. The commit consumes the pending record and writes the credential record. The plan
   names the passkey as a sign-in method of the account, so a restore completes a registration that a crash left in
   doubt.
7. Return the response of the outcome. The operation identity is the key of the pending record, so a second finish
   of the ceremony refuses: with `transition::Error::Reuse` when both run at once, and with `Error::Challenge` after the
   commit. After a lost response, look up the operation of the proposal (`proposal.operation()`).

## Sign in

1. For each view of the login page, call `rp.sign_in_options(now, &mut random)` and send the options with
   `rsauthnz_http::json`. The call writes no record and no audit record, so a view costs no write. The options name no
   credential, so the browser offers each passkey of the site, also in the autofill of conditional mediation. They
   ask for user verification when the authenticator can do it.
2. The browser gives the options to `PublicKeyCredential.parseRequestOptionsFromJSON()`, calls
   `navigator.credentials.get()`, and sends `credential.toJSON()` as the JSON body of a state change.
3. Check the request with `site.json_change`, then read the body with `Assertion::parse`.
4. Call `rp.sign_in(&mut store, &assertion, now, &mut random, &mut driver)`. It checks the tag and the lifetime of
   the challenge before any read. Then it reads the credential record, the replay floor, and the replay record of the
   challenge, and it checks the assertion and its signature.
5. Submit the proposal with its plan, and give the outcome to `sign_in.release(&outcome)`. Only the accepted commit
   gives the `Evidence`. After a lost response, the user signs in again: the same assertion is a new operation, and
   its challenge refuses.

The commit inserts the replay record of the challenge, so each challenge serves one sign-in. The commit reads the
replay floor of the store. A restore raises the floor, so a challenge from before a restore refuses after it.

The signature counter follows these rules:

| Stored counter | Received counter | Stored after the commit | `evidence.possible_clone()` |
| --- | --- | --- | --- |
| 0 | 0 | 0 | `false` |
| Any | Greater than the stored counter | The received counter | `false` |
| Not 0 | Equal or less, also 0 | Unchanged | `true` |

The stored counter never decreases. A counter that did not advance can come from a cloned credential, a faulty
authenticator, or two sign-ins that committed out of order. The signal locks nothing out: the policy of the
application decides the response. The audit action of such a sign-in is `rsauthnz:passkey.sign-in.possible-clone`,
and of each other sign-in `rsauthnz:passkey.sign-in`. A counter update reads the credential record at its version, so
two concurrent sign-ins conflict, and the second one runs again from the stored counter. A passkey with no counter
writes no credential record at a sign-in.

The evidence records the account, `Method::Passkey`, the time, whether the authenticator verified the user, phishing
resistance, `Binding::Device` for a passkey that cannot be backed up, and the authentication of the algorithm:
`PostQuantum` for ML-DSA-65, and `Classical` for the others.

## Example

This example is also the example of the `rsauthnz::passkey` module documentation, and `cargo xtask test` runs it. It
runs on the memory binding of `rsauthnz-conformance`. The finish of a real response needs a browser and an
authenticator, so the example sends a body that is not a response, which refuses before a read.

```rust
use core::pin::pin;
use core::task::{Context, Poll, Waker};
use core::time::Duration;

use rsauthnz::id::Id;
use rsauthnz::limits::Limits;
use rsauthnz::passkey::{Error, RelyingParty, Response, User, UserHandle};
use rsauthnz::store::driver::{Answer, Driver, Plan};
use rsauthnz::store::{Profile, Store};
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

/// Gives each effect of the driver to the binding, until the driver has none.
fn run(memory: &mut Memory, driver: &mut Driver) -> Result<(), Failure> {
    while let Some(effect) = driver.effect() {
        let output = ready(execute(memory, effect));
        driver.give(output)?;
    }
    Ok(())
}

/// The outcome of the commit of `proposal` with `plan`.
fn commit(memory: &mut Memory, driver: &mut Driver, proposal: Proposal, plan: Plan) -> Result<Outcome, Failure> {
    let ticket = driver.submit(proposal, plan)?;
    run(memory, driver)?;
    match driver.take(ticket) {
        Some(Answer::Outcome(outcome)) => Ok(outcome),
        answer => Err(format!("the commit gave {answer:?}").into()),
    }
}

/// The outcome of the finish of `body`: the JSON that the browser sent.
fn finish(rp: &RelyingParty, memory: &mut Memory, driver: &mut Driver, body: &[u8], now: Reading) -> Result<Outcome, Failure> {
    let response = Response::parse(body)?;
    let (proposal, plan, _credential) = ready(rp.finish(memory, &response, now, driver))?;
    commit(memory, driver, proposal, plan)
}

let now = Reading::new(Duration::from_secs(1_800_000_000), Some(Duration::from_secs(1)), ReadingSource::Caller);
let mut memory = Memory::new(Schedule::None);
let mut driver = Driver::new(Profile::new(memory.declaration())?, Limits::default())?;
driver.start(now);
run(&mut memory, &mut driver)?;
// Seed the generator from the entropy of the host. The key of the sign-in challenges is a secret of the host too.
let mut random = ChaCha20Rng::from_seed([7; 32]);
let key = [3; 32];
let rp = RelyingParty::new(Id::new("acme", "auth")?, "app.example", "https://app.example", "Acme", key, Limits::default())?;

// 1. A new account draws its user handle, and keeps it for each later passkey.
let account = Id::new("acme", "alice")?;
let user = User {
    account: &account,
    handle: UserHandle::random(&mut random),
    name: "alice@app.example",
    display_name: "Alice",
};
let (proposal, plan) = rp.start(&user, OperationId::new(b"start-1")?, now, &mut random, &mut driver)?;
let Outcome::Accepted(receipt) = commit(&mut memory, &mut driver, proposal, plan)? else {
    return Err("the start did not commit".into());
};

// 2. Only the accepted commit releases the options, for `PublicKeyCredential.parseCreationOptionsFromJSON()`.
let options = receipt.artifact().ok_or("no options")?;
assert!(options.starts_with(br#"{"rp":{"id":"app.example","name":"Acme"}"#));

// 3. The browser sends `credential.toJSON()`. A body that is not a response refuses before a store read.
let error = finish(&rp, &mut memory, &mut driver, b"{}", now).unwrap_err();
assert_eq!(error.downcast_ref::<Error>(), Some(&Error::Malformed));

// 4. A sign-in starts with options for `PublicKeyCredential.parseRequestOptionsFromJSON()`, and writes nothing.
let options = rp.sign_in_options(now, &mut random)?;
assert!(options.starts_with(br#"{"challenge":""#));
```

## The options

The options are `PublicKeyCredentialCreationOptionsJSON`:

| Member | Value |
| --- | --- |
| `pubKeyCredParams` | ML-DSA-65 (-49), EdDSA (-8), ES256 (-7), and RS256 (-257), in this order |
| `timeout` | 300,000 milliseconds |
| `attestation` | `none` |
| `authenticatorSelection` | `residentKey: required`, `requireResidentKey: true`, `userVerification: required` |
| `extensions` | `credProps: true` |

The check also takes Ed25519 (-19) and ESP256 (-9), the fully specified identifiers of EdDSA and ES256. An RS256 key
has a modulus of 2,048 to 4,096 bits and the exponent 65,537 ([Signature profiles](profiles.md)). A composite key
refuses: no passkey profile offers one.

## What the check proves

`RelyingParty::verify` checks a response against its challenge, and `finish` calls it:

- `clientDataJSON` has the type `webauthn.create`, the challenge of the ceremony, and the origin of the site. A
  ceremony in a frame of another origin (`crossOrigin` true, or a `topOrigin`) refuses.
- The authenticator data has the SHA-256 digest of the relying party ID, and the flags of user presence and of user
  verification. A backup state with no backup eligibility refuses.
- The credential ID has at most 1,023 bytes, and it is the ID of the response.
- The credential public key has an algorithm of the profile, and it is a valid key of that algorithm.
- A `credProps` result of `rk: false` refuses: the profile requires a discoverable credential. A browser that gives no
  `credProps` registers.

The check takes each attestation format, and it reads no attestation statement. Thus the credential is one with no
attestation: nothing proves the model of the authenticator, as [WebAuthn Level 3, section
7.1](https://www.w3.org/TR/webauthn-3/#sctn-registering-a-new-credential) permits. rsauthnz uses no attestation
service and trusts no AAGUID. The check ignores an authenticator extension output that nobody asked for, and it
refuses extension data that is not a CBOR map.

`Credential` gives what the authenticator reported. `backup_eligible` is the BE flag: a synchronized passkey.
`backup_state` is the BS flag. `binding()` is `Binding::Device` for a passkey that the authenticator cannot back up,
and `None` for a synchronized one. No registration gives `Binding::Hardware`, because only an attestation can prove it.

## Errors

Each `passkey::Error` is a small `Copy` value with no secret. `error.recovery()` gives its recovery, and
`rsauthnz_http::problem` gives its response.

| `Error` | Cause | Recovery |
| --- | --- | --- |
| `Malformed` | The response is not in the forms of WebAuthn Level 3 | `Refuse` |
| `Challenge` | The challenge is not the challenge of the ceremony or of the key, the ceremony ended, or the challenge is not later than the replay floor or served a sign-in already | `Restart`: start a new ceremony |
| `Origin` | The origin of `clientDataJSON` is not the origin of the site | `Refuse` |
| `CrossOrigin` | The ceremony ran in a frame of another origin | `Refuse` |
| `RelyingParty` | The authenticator data has the hash of another relying party ID, or `RelyingParty::new` has no valid ID and origin | `Refuse` |
| `UserPresence` | The UP flag is not set | `Refuse` |
| `UserVerification` | The UV flag is not set | `Refuse` |
| `Algorithm` | The key has an algorithm outside the profile | `Refuse` |
| `Key` | The key is not a valid key of its algorithm | `Refuse` |
| `CredentialId` | The ID has more than 1,023 bytes, or the response and the authenticator data have two IDs | `Refuse` |
| `NotDiscoverable` | `credProps` reports a credential that is not discoverable | `Refuse` |
| `Credential` | The store has no record of the credential of an assertion, or the assertion names another user handle | `Refuse` |
| `Signature` | The signature of an assertion does not verify with the stored key | `Refuse` |
| `Name` | A name is empty or has more than 256 bytes | `Refuse` |
| `Record` | A record has no valid form | `Refuse` |
| `Time` | The reading has no bound, or a time overflows | `Refuse` |
| `Driver` | The commit driver does not serve | `Refuse` |
| `Transition(error)` | The proposal refuses | `error.recovery()` |

`finish` and `sign_in` read the store, so they return `passkey::Failure`: `Refused(error)`, or `Store(error)` for a
failed read, which is a crash of the binding.

The cost class of `Response::parse`, `Assertion::parse`, and `sign_in_options` is `Parse`. The cost class of `verify`,
`finish`, and `sign_in` is `Verify` ([Admit rsauthnz work](admission.md)): `sign_in` makes one signature check and
three keyed reads. A response has at most 64 KiB of JSON.

## Support

The checks above have test evidence on this Mac: the published registration cases and the published assertions of
ES256, EdDSA, and RS256 of WebAuthn Level 3, and the cases of a test authenticator, which signs ML-DSA-65 assertions
with rscrypto. No real browser or authenticator has run a registration or a sign-in of rsauthnz yet.
