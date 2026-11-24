# Register a passkey and sign in

`rsauthnz::passkey` runs the registration and the sign-in of [WebAuthn Level 3](https://www.w3.org/TR/webauthn-3/).
A passkey is a key pair that an authenticator keeps for one account at one site. A registration binds a new passkey
to an account as a sign-in method. A sign-in proves the account with an assertion: a signature of the passkey over a
challenge of the site.

The core checks the response and proposes each commit. The storage binding of the application accepts the commit
([Propose a transition](transitions.md)). The HTTP binding checks each browser request and writes its response
([Mount the HTTP binding](http-binding.md)). [Manage accounts](accounts.md) gives the invitation of a new account, an
additional passkey, the rename and the removal of a passkey, and the fresh user verification of a sensitive change.
[Recover an account](recovery.md) gives the recovery code of an account and the recovery with a new passkey.

## The model

- The **relying party** (`RelyingParty`) is the site: its relying party ID, such as `app.example`, its origin, such
  as `https://app.example`, the name that an authenticator shows, the authority that owns its records, and the key of
  its sign-in challenges. The origin
  is the origin of the relying party ID or of a subdomain of it, in the form that a browser writes: no default port and
  no final `/`. For development, the relying party ID `localhost` takes `http://localhost` with an optional port. An
  application on several domains adds its other origins with `with_related` ([Serve several
  domains](browser-adapter.md#serve-several-domains)).
- The **user handle** (`UserHandle`) is 32 random bytes with no personal data. Each passkey of an account has the
  same handle, so an authenticator keeps one passkey for each account. Draw it once for a new account
  (`UserHandle::random`), and keep it with the account.
- The **pending registration** is a record of the kind `Kind::Registration`. It holds the account and the user
  handle and the account revision at the start. Its key is the SHA-256 digest of the CBOR form `["rsauthnz.passkey.registration.2", authority, relying
  party ID, challenge]`, with a challenge of 32 random bytes. It ends after `REGISTRATION_LIFETIME` (300 seconds). The
  record never holds the challenge. The response is not signed, so the challenge is the only proof that the response
  comes from the ceremony of the account.
- The **credential record** is a record of the kind `Kind::Credential` at `rp.credential_key(&mut store, &handle, id).await?`.
  Its key combines the kind, the current passkey prefix, and the SHA-256 digest of the credential ID.
  The initial prefix is the digest of `["rsauthnz.passkey.credential.2", authority, relying party ID, user handle]`.
  Full recovery changes this prefix. The record holds the account, the user handle, the credential
  ID, the public key of the passkey, its algorithm, its signature counter, its backup flags, its transports, and its
  name. A new passkey has the empty name ([Rename a passkey](accounts.md#list-and-rename-passkeys)). It has no end. The
  public key is the deterministic CBOR of a `COSE_Key` with only `kty`, `alg`, and the checked public parameters: no
  other member of the key of the response enters the store.
- Each key names the authority and the relying party ID. Thus two relying parties can share one store: neither one
  finds a pending registration or a credential of the other. The first 33 bytes of a credential key are the same for
  each passkey of an account, so one range read gives them all. An account has at most `CREDENTIALS_MAX` (32)
  passkeys. A registration claims its place in the commit. If account recovery or another enrollment wins the race, registration conflicts.
- A **sign-in challenge** is 72 bytes: 32 random bytes, the time of its creation, and an HMAC-SHA256 tag of both
  under the key of the relying party. The time of creation is the earliest time of the reading, so it is never later
  than the true time. No record holds the challenge until it serves a sign-in. Then the commit writes its **replay
  record** (`Kind::Replay`), which ends after `SIGN_IN_LIFETIME` (300 seconds) and a margin of twice the bound of the
  reading.

## Register

1. At startup, build one `RelyingParty::new(authority, id, origin, name, key, limits)`. `key` is 32 random bytes
   that the host keeps secret, the same on each node of the site. A new key ends each open sign-in challenge.
   `limits` bound the CBOR of each response ([Parser limits](parser-limits.md)).
2. The application decides that the account can register, for example a new account of an open sign-up, or a
   signed-in account that adds a passkey. Call
   `rp.start(&mut store, &user, decision, now, &mut random, &mut driver).await`. `user` names the account, its user
   handle, and the name and the display name that the authenticator shows. The options hold the names, and no record
   does ([Rename an account](accounts.md#rename-an-account)). `decision` is a `passkey::Decision`.
   `Decision::SignUp(&reads)` is the first passkey of an account, and it refuses with `Error::Fresh` for an account
   that has a passkey. `Decision::Add(&fresh, &reads)` adds a passkey with a fresh user verification of the account
   ([Add a passkey](accounts.md#add-a-passkey)). `reads` is a slice of
   `transition::Dependency`: each record and policy that the decision read, such as the state of the sign-up and the
   policy version. The proposal reads each one. The start reads each passkey of the account and lists it in
   `excludeCredentials`. Thus an authenticator that holds one of them makes no second passkey, which would
   replace the first one on the authenticator while the store still counts it as a sign-in method. A start for an
   account with `CREDENTIALS_MAX` passkeys refuses with `Error::Full`. Submit the proposal with its plan.
3. Only the accepted commit releases the options: `receipt.artifact()`. Send them to the browser with
   `rsauthnz_http::json`. Each start has a new operation identity. After a lost response, start again: the receipt
   of a lookup has no artifact.
4. The browser gives the options to `PublicKeyCredential.parseCreationOptionsFromJSON()`, calls
   `navigator.credentials.create()`, and sends `credential.toJSON()` as the JSON body of a state change.
5. Check the request with `site.json_change`, then read the body with `Response::parse`.
6. Call `rp.finish(&mut store, &response, now, &mut driver)`. It reads the pending record of the ceremony and checks
   the response. With no record, the ceremony ended or never started, and it refuses with `Error::Challenge`
   (`Recovery::Restart`). One range read tells whether the account has a passkey. It gives a `Registration`:
   `account()` and `credential()`.
7. Decide again, with the current state, that `registration.account()` can register this passkey. Do not reuse the
   decision of the start: a session or a permission can end during the ceremony. Call
   `registration.propose(decision)` with `Decision::SignUp` or `Decision::Add` as in step 2, and submit the proposal
   with its plan. The commit reads each read of the
   decision, consumes the pending record, and writes the credential record. Thus a decision that changed after its
   read makes the commit conflict, and no credential is written. The plan names the passkey as a sign-in method of the
   account, so a restore completes a registration that a crash left in doubt.
8. Return the response of the outcome. The operation identity is the key of the pending record, and the request
   binds the credential record: the public key, the algorithm, the counter, and the flags. Thus the same response
   again gets the receipt of the commit. Another response of the ceremony refuses: with `transition::Error::Reuse`
   when both run at once, also with the same credential ID and another key, and with `Error::Challenge` after the
   commit. After a lost response, look up the operation of the proposal (`proposal.operation()`) when the driver
   serves again, and answer with its result ([HTTP binding](http-binding.md)). After a conflict, the pending record
   stays: finish again with a new decision, or start a new ceremony.

## Sign in

After the store starts or restores, read `rp.sign_in_not_before(&mut store)` once. It returns the earliest creation time the replay floor accepts.
Before issuing options, wait until `now.earliest()` reaches that time. Each subsequent sign-in still starts without a storage read.

1. For each view of the login page, call `rp.sign_in_options(now, &mut random)` and send the options with
   `rsauthnz_http::json`. `now` needs a known bound: a reading with no bound refuses with
   `Error::Time(TimeError::UnknownBound)`. The call writes no record and no audit record, so a view costs no write.
   The options name no credential, so the browser offers each passkey of the site, also in the autofill of
   conditional mediation. They ask for user verification when the authenticator can do it.
2. The browser gives the options to `PublicKeyCredential.parseRequestOptionsFromJSON()`, calls
   `navigator.credentials.get()`, and sends `credential.toJSON()` as the JSON body of a state change. The `signIn`
   function of the [browser adapter](browser-adapter.md) does this step.
3. Check the request with `site.json_change`, then read the body with `Assertion::parse`.
4. Call `rp.sign_in(&mut store, &assertion, now, &mut random, &mut driver)`. It checks the tag and the lifetime of
   the challenge before any read. Then it reads the credential record, the replay floor, and the replay record of the
   challenge, and it checks the assertion and its signature. It gives a `SignIn`. A passkey that a
   [removal](accounts.md#remove-a-passkey) ended refuses with `Error::Removed`, whose recovery is `Forget`: the
   `signIn` function of the browser adapter then tells the provider to forget the passkey.
5. Call `sign_in.open(&sessions, replaces, &mut random, &mut driver)`. It adds a new [session](sessions.md) to the
   commit, and ends the family of `replaces`, the current session of the browser, if it has one. It gives the
   proposal, its plan, and a `session::Opening`.
6. Submit the proposal with its plan, and give the outcome to `opening.release(&outcome)`. Only the accepted commit
   gives `Opened`: the `Evidence` and the session. Only the commit driver makes an accepted receipt, from a durable
   commit or its outcome record. Thus no evidence and no session leave before the store holds the replay record, the
   session, and the audit.
7. After a lost response (`Outcome::Unknown`), keep the opening. When the driver serves again, look up the operation
   of the proposal with `driver.lookup`. Give a commit to `opening.release(&Outcome::Accepted(receipt))`, and answer
   the same request with its session. Answer each other result of the lookup as [Lost
   responses](http-binding.md#lost-responses) shows: the user signs in again with a new challenge. The same assertion
   again is a new operation, and its challenge refuses after a commit.

The commit inserts the replay record of the challenge, so each challenge serves one sign-in. The commit reads the
replay floor of the store. A restore raises the floor, so a challenge from before a restore refuses after it. The
challenge holds the earliest time of its reading, so this holds also for a clock that runs fast within its bound. The
challenge serves for `SIGN_IN_LIFETIME` from that earliest time.

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
two concurrent sign-ins conflict, and the second one runs again from the stored counter. A sign-in writes the
credential record only when the counter advances or the backup state (BS) changes, as [WebAuthn Level 3, section
7.2](https://www.w3.org/TR/webauthn-3/#sctn-verifying-assertion) asks. Thus a synchronized passkey with no counter
writes no record until its provider backs it up.

The evidence records the account, `Method::Passkey`, the time, whether the authenticator verified the user, phishing
resistance, the backup state that the authenticator reports (`evidence.backup()`), and the authentication of the
algorithm: `PostQuantum` for ML-DSA-65, and `Classical` for the others. Its `binding()` is `None`: no attestation
proves where the key of a passkey lives.

## Example

This example is also the example of the `rsauthnz::passkey` module documentation, and `cargo xtask test` runs it. It
runs on the memory binding of `rsauthnz-conformance`. The decision of the application is an open sign-up. The finish
of a real response needs a browser and an authenticator, so the example sends a body that is not a response, which
refuses before a read.

```rust
use core::pin::pin;
use core::task::{Context, Poll, Waker};
use core::time::Duration;

use rsauthnz::id::{Human, Id};
use rsauthnz::limits::Limits;
use rsauthnz::passkey::{Decision, Error, RelyingParty, Response, User, UserHandle};
use rsauthnz::store::driver::{Answer, Driver, Plan};
use rsauthnz::store::{Profile, Store};
use rsauthnz::time::{Reading, ReadingSource};
use rsauthnz::transition::{Dependency, Key, Outcome, Proposal};
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

/// The reads of the decision of the application that `account` can register its first passkey: an open sign-up. The
/// sign-up is open while no record has the key `sign-up/closed`, so the decision reads that absence.
fn can_register(_account: &Id<Human>) -> Result<[Dependency; 1], Failure> {
    Ok([Dependency::Absent(Key::new(b"sign-up/closed")?)])
}

/// The outcome of the finish of `body`: the JSON that the browser sent.
fn finish(rp: &RelyingParty, memory: &mut Memory, driver: &mut Driver, body: &[u8], now: Reading) -> Result<Outcome, Failure> {
    let response = Response::parse(body)?;
    let registration = ready(rp.finish(memory, &response, now, driver))?;
    // Decide again with the current state: the decision of the start can have changed.
    let decision = can_register(registration.account())?;
    let (proposal, plan) = registration.propose(Decision::SignUp(&decision))?;
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
let decision = can_register(&account)?;
let (proposal, plan) = ready(rp.start(&mut memory, &user, Decision::SignUp(&decision), now, &mut random, &mut driver))?;
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
| `excludeCredentials` | Each passkey of the account: its ID and its transports, in the order `usb`, `nfc`, `ble`, `smart-card`, `hybrid`, `internal`. `[]` for an account with no passkey |
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
- The credential public key has an algorithm of the profile, and it is a valid key of that algorithm. A key with a
  private parameter refuses, such as `d` of an EC2 or OKP key, `priv` of an AKP key, and each of `d` to `t_i` of an
  RSA key.
- A `credProps` result of `rk: false` refuses: the profile requires a discoverable credential. A browser that gives no
  `credProps` registers.

The check takes each attestation format, and it reads no attestation statement. Thus the credential is one with no
attestation: nothing proves the model of the authenticator, as [WebAuthn Level 3, section
7.1](https://www.w3.org/TR/webauthn-3/#sctn-registering-a-new-credential) permits. rsauthnz uses no attestation
service and trusts no AAGUID. The check ignores an authenticator extension output that nobody asked for, and it
refuses extension data that is not a CBOR map.

`Credential` gives what the authenticator reported. `backup()` gives the BE and BS flags as an `evidence::Backup`:

| `Backup` | Flags | Meaning |
| --- | --- | --- |
| `SingleDevice` | BE is 0 | The authenticator reports that it cannot back up the credential |
| `Eligible` | BE is 1, BS is 0 | The authenticator can back up the credential, and reports no backup |
| `BackedUp` | BE and BS are 1 | The authenticator reports a backup, as a synchronized passkey has |

The flags are a report, not a proof. No attestation signs them, and a software authenticator can set BE to 0 for a key
that it can copy. Thus no registration and no sign-in gives a `Binding`. Use the backup state as a signal, for example
to offer a second passkey to an account whose only passkey is on one device.

## Errors

Each `passkey::Error` is a small `Copy` value with no secret. `error.recovery()` of the trait `transition::Recover`
gives its recovery, and `?` in a handler gives the `rsauthnz_http::Problem` of its response
([Return a problem](http-binding.md#return-a-problem)).

| `Error` | Cause | Recovery |
| --- | --- | --- |
| `Malformed` | The response is not in the forms of WebAuthn Level 3 | `Refuse` |
| `Challenge` | The challenge is not the challenge of a ceremony of this relying party or of its key, the ceremony ended, or the challenge is not later than the replay floor or served a sign-in already | `Restart`: start a new ceremony |
| `Origin` | The origin of `clientDataJSON` is not the origin of the site or one of its related origins | `Refuse` |
| `CrossOrigin` | The ceremony ran in a frame of another origin | `Refuse` |
| `RelyingParty` | The authenticator data has the hash of another relying party ID, or `RelyingParty::new` has no valid ID and origin | `Refuse` |
| `UserPresence` | The UP flag is not set | `Refuse` |
| `UserVerification` | The UV flag is not set | `Refuse` |
| `Algorithm` | The key has an algorithm outside the profile | `Refuse` |
| `Key` | The key is not a valid key of its algorithm | `Refuse` |
| `CredentialId` | The ID has more than 1,023 bytes, or the response and the authenticator data have two IDs | `Refuse` |
| `NotDiscoverable` | `credProps` reports a credential that is not discoverable | `Refuse` |
| `Full` | The account has `CREDENTIALS_MAX` (32) passkeys | `Refuse` |
| `Credential` | The assertion has no user handle of 32 bytes, or the store has no record of its credential under this relying party and that handle, and no removal mark | `Refuse`. A registration finish that comes late can still commit the passkey, so the provider keeps it |
| `Removed` | The store has no record of the credential, and has its removal mark: a removal ended the passkey, and no registration writes it again | `Forget`: tell the provider to forget the passkey, and sign in with another one |
| `Signature` | The signature of an assertion does not verify with the stored key | `Refuse` |
| `Name` | A name is empty or has more than 256 bytes | `Refuse` |
| `Record` | A record has no valid form | `Refuse` |
| `Time` | The reading has no bound, or a time overflows | `Refuse`: give a reading with a known bound |
| `Driver` | The commit driver does not serve | `Refuse` |
| `Transition(error)` | The proposal refuses, also for a decision with more reads than the limits permit | `error.recovery()` |
| `Session(error)` | The session of a sign-in refuses ([Keep a browser session](sessions.md#errors)) | `error.recovery()` |
| `Fresh` | A `Decision::SignUp` of an account that has a passkey, or a fresh user verification of another account | `Verify`: verify the user again ([Manage accounts](accounts.md#fresh-user-verification)) |
| `Invitation` | No open invitation has the value or the challenge: it ended, or an activation consumed it | `Refuse` |
| `Recipient` | The invitation names another recipient | `Refuse` |
| `Activated` | The recipient of the invitation has a passkey | `Refuse` |
| `Issuer` | The current policy does not permit the action of the issuer of the invitation | `Refuse` |
| `Lifetime` | The lifetime of an invitation is zero or longer than `INVITATION_LIFETIME_MAX` (7 days) | `Refuse` |
| `Authorization(refusal)` | The policy refuses the issue of an invitation ([Authorize an operation](authorization.md)) | `Refuse` |
| `RecoveryKey` | The relying party has no recovery key ([Recover an account](recovery.md)) | `Refuse` |
| `Code` | The text is not a recovery code, or the account has no recovery code with the value | `Refuse` |
| `Dit` | This build on this CPU cannot handle a recovery code with data-independent timing | `Refuse` |

`finish` and `sign_in` read the store, so they return `passkey::Failure`: `Refused(error)`, or `Store(error)` for a
failed read, which is a crash of the binding.

The cost class of `Response::parse`, `Assertion::parse`, `sign_in_options`, and `Registration::propose` is `Parse`.
The cost class of `verify`, `finish`, and `sign_in` is `Verify` ([Admit rsauthnz work](admission.md)): `finish` makes
one pending-record read, the recovery and enrollment revisions, and one passkey page. A valid `sign_in` reads the account revision,
checks one signature, and makes three further keyed lookups in two store calls.
It reads the credential first, then reads the replay floor and challenge record together.
For an absent credential, it checks the removal mark and refuses. The cost class of
`start` is `Mutate`. It looks up the account revision and reads one page of at most
`CREDENTIALS_MAX` records, and its commit. A response has at most 64 KiB of JSON.

## Support

The checks above have test evidence on this Mac: the published registration cases of ES256 and RS256 and the
published assertions of ES256, EdDSA, and RS256 of WebAuthn Level 3, and the cases of a test authenticator, which
makes ML-DSA-65, EdDSA, and ES256 passkeys with rscrypto. The published EdDSA registration case has no UV flag, so the
profile refuses it. With only the UV bit set, it passes each other check. That is a derived case: the UV bit changes
the authenticator data, so its attestation signature no longer verifies. rscodec's JSON reader reads each response,
and its fuzz campaign is not complete. No real browser or authenticator has run a registration or a sign-in of
rsauthnz yet.
