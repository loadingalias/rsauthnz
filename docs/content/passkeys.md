# Register a passkey

`rsauthnz::passkey` runs the registration ceremony of [WebAuthn Level 3](https://www.w3.org/TR/webauthn-3/). A
passkey is a key pair that an authenticator keeps for one account at one site. A registration binds a new passkey to
an account as a sign-in method.

The core checks the response and proposes each commit. The storage binding of the application accepts the commit
([Propose a transition](transitions.md)). The HTTP binding checks each browser request and writes its response
([Mount the HTTP binding](http-binding.md)).

## The model

- The **relying party** (`RelyingParty`) is the site: its relying party ID, such as `app.example`, its origin, such
  as `https://app.example`, the name that an authenticator shows, and the authority that owns its records. The origin
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

## Register

1. At startup, build one `RelyingParty::new(authority, id, origin, name, limits)`. `limits` bound the CBOR of each
   response ([Parser limits](parser-limits.md)).
2. The application decides that the account can register, for example a new account of an open sign-up. Call
   `rp.start(&user, operation, now, &mut random, &mut driver)`. `user` names the account, its user handle, and the
   name and the display name that the authenticator shows. The options hold the names, and no record does. Add the
   reads of the decision of the application to the proposal, and submit it with its plan.
3. Only the accepted commit releases the options: `receipt.artifact()`. Send them to the browser with
   `rsauthnz_http::json`. After a lost response, start again with a new operation identity. The receipt of a lookup
   has no artifact.
4. The browser gives the options to `PublicKeyCredential.parseCreationOptionsFromJSON()`, calls
   `navigator.credentials.create()`, and sends `credential.toJSON()` as the JSON body of a state change.
5. Check the request with `site.json_change`, then read the body with `Response::parse`. Read the pending record at
   `response.ceremony()`. If the store has no record, the ceremony ended or never started: return the response of
   `Recovery::Restart`.
6. Call `rp.finish(&response, &pending, now, &mut driver)`, and submit the proposal with its plan. The commit consumes
   the pending record and writes the credential record. The plan names the passkey as a sign-in method of the account,
   so a restore completes a registration that a crash left in doubt.
7. Return the response of the outcome. After a lost response, the browser sends the same response again. Its
   operation identity is the key of the pending record, so the commit driver gives the first outcome and commits
   nothing again. A second finish of the ceremony with another response refuses with `transition::Error::Reuse`.

This example is also the example of the `rsauthnz::passkey` module documentation, and `cargo xtask test` runs it. It
runs on the memory binding of `rsauthnz-conformance`. The finish of a real response needs a browser and an
authenticator, so the example sends a body that is not a response, which refuses.

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
    // No pending record: the ceremony ended, or it never started. The browser starts again.
    let pending = ready(memory.read(&response.ceremony()))?.ok_or(Error::Challenge)?;
    let (proposal, plan, _credential) = rp.finish(&response, &pending, now, driver)?;
    commit(memory, driver, proposal, plan)
}

let now = Reading::new(Duration::from_secs(1_800_000_000), Some(Duration::from_secs(1)), ReadingSource::Caller);
let mut memory = Memory::new(Schedule::None);
let mut driver = Driver::new(Profile::new(memory.declaration())?, Limits::default())?;
driver.start(now);
run(&mut memory, &mut driver)?;
// Seed the generator from the entropy of the host.
let mut random = ChaCha20Rng::from_seed([7; 32]);
let rp = RelyingParty::new(Id::new("acme", "auth")?, "app.example", "https://app.example", "Acme", Limits::default())?;

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
| `Challenge` | Another challenge, or the pending record ended | `Restart`: start a new ceremony |
| `Origin` | The origin of `clientDataJSON` is not the origin of the site | `Refuse` |
| `CrossOrigin` | The ceremony ran in a frame of another origin | `Refuse` |
| `RelyingParty` | The authenticator data has the hash of another relying party ID, or `RelyingParty::new` has no valid ID and origin | `Refuse` |
| `UserPresence` | The UP flag is not set | `Refuse` |
| `UserVerification` | The UV flag is not set | `Refuse` |
| `Algorithm` | The key has an algorithm outside the profile | `Refuse` |
| `Key` | The key is not a valid key of its algorithm | `Refuse` |
| `CredentialId` | The ID has more than 1,023 bytes, or the response and the authenticator data have two IDs | `Refuse` |
| `NotDiscoverable` | `credProps` reports a credential that is not discoverable | `Refuse` |
| `Name` | A name is empty or has more than 256 bytes | `Refuse` |
| `Record` | A record has no valid form | `Refuse` |
| `Time` | The reading has no bound, or a time overflows | `Refuse` |
| `Driver` | The commit driver does not serve | `Refuse` |
| `Transition(error)` | The proposal refuses | `error.recovery()` |

The cost class of `Response::parse` is `Parse`, and the cost class of `verify` and `finish` is `Verify` ([Admit
rsauthnz work](admission.md)). A response has at most 64 KiB of JSON.

## Support

The checks above have test evidence on this Mac: the published registration cases of WebAuthn Level 3 and the cases
of a test authenticator. No real browser or authenticator has run a registration of rsauthnz yet.
