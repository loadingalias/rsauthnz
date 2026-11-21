//! Passkeys ([WebAuthn Level 3]): registration and sign-in.
//!
//! A [`RelyingParty`] holds the relying party ID, the origin of the site, the authority that owns the records, and the
//! key of the sign-in challenges. A registration has two commits:
//!
//! 1. [`RelyingParty::start`] proposes the pending registration of an account: a record of the account and its user
//!    handle, whose key is a digest of the relying party and a new challenge of 32 bytes. The proposal reads each
//!    record of the decision of the application that the account can register. The record ends after
//!    [`REGISTRATION_LIFETIME`]. The options list each passkey of the account in `excludeCredentials`. Only the
//!    accepted commit releases them, as the artifact of the receipt. Give them to
//!    `PublicKeyCredential.parseCreationOptionsFromJSON()` in the browser.
//! 2. The browser gives the response of `navigator.credentials.create()` as `credential.toJSON()`. [`Response::parse`]
//!    reads it. [`RelyingParty::finish`] reads its pending record, checks the response against it, and gives a
//!    [`Registration`]: the account and the credential. The application decides again, with the current state, and
//!    [`Registration::propose`] gives one commit with the reads of that decision: it consumes the pending record and
//!    writes the credential record. Its plan names the passkey as a sign-in method of the account, so a restore
//!    completes a registration that a crash left in doubt.
//!
//! Each record key names the authority and the relying party ID, so a relying party finds no record of another
//! relying party of the same store. The key of a credential record starts with a digest of the user handle, so one
//! range read gives each passkey of an account.
//!
//! A sign-in has one commit. [`RelyingParty::sign_in_options`] gives the options with a challenge that holds the
//! earliest time of its reading under an HMAC-SHA256 tag, and it writes nothing. [`Assertion::parse`] reads the
//! response of `navigator.credentials.get()`, and [`RelyingParty::sign_in`] checks it. [`SignIn::open`] then proposes
//! the commit: the replay record of the challenge, the counter of the credential when it advances, the new session,
//! and the audit. Only the accepted commit releases the [`Evidence`] and the session
//! ([`Opening::release`](crate::session::Opening::release)).
//!
//! The options offer ML-DSA-65 (-49), EdDSA (-8), ES256 (-7), and RS256 (-257), in this order, and the check also
//! takes Ed25519 (-19) and ESP256 (-9). They require a discoverable credential and user verification, and they ask for
//! no attestation. The check takes each attestation format and reads no attestation statement, so the credential is
//! one with no attestation: no attestation proves the model of an authenticator, and this crate trusts none
//! ([WebAuthn Level 3, section 7.1]). It checks `clientDataJSON` (the type, the challenge, the origin, and no
//! cross-origin frame), the relying party ID hash, the flags, and the credential public key. Thus the backup flags are
//! what the authenticator reports: they prove no binding of the key ([`Backup`]).
//!
//! The pending record never holds the challenge, and its key is a digest of it. The response is not signed, so the
//! challenge is the only proof that the response comes from the ceremony of the account.
//!
//! The example runs a start on the memory binding of `rsauthnz-conformance`. The decision of the application is an
//! open sign-up. The finish of a real response needs a browser and an authenticator, so the example sends a body that
//! is not a response, which refuses before a read.
//!
//! ```
//! use core::pin::pin;
//! use core::task::{Context, Poll, Waker};
//! use core::time::Duration;
//!
//! use rsauthnz::id::{Human, Id};
//! use rsauthnz::limits::Limits;
//! use rsauthnz::passkey::{Decision, Error, RelyingParty, Response, User, UserHandle};
//! use rsauthnz::store::driver::{Answer, Driver, Plan};
//! use rsauthnz::store::{Profile, Store};
//! use rsauthnz::time::{Reading, ReadingSource};
//! use rsauthnz::transition::{Dependency, Key, Outcome, Proposal};
//! use rsauthnz_conformance::memory::{Memory, Schedule};
//! use rsauthnz_conformance::suite::execute;
//! use rscrypto::ChaCha20Rng;
//!
//! type Failure = Box<dyn core::error::Error>;
//!
//! /// The output of a future of the memory binding, which is ready at its first poll.
//! fn ready<T>(future: impl Future<Output = T>) -> T {
//!     let Poll::Ready(output) = pin!(future).poll(&mut Context::from_waker(Waker::noop())) else {
//!         unreachable!("the memory binding does no I/O");
//!     };
//!     output
//! }
//!
//! /// Gives each effect of the driver to the binding, until the driver has none.
//! fn run(memory: &mut Memory, driver: &mut Driver) -> Result<(), Failure> {
//!     while let Some(effect) = driver.effect() {
//!         let output = ready(execute(memory, effect));
//!         driver.give(output)?;
//!     }
//!     Ok(())
//! }
//!
//! /// The outcome of the commit of `proposal` with `plan`.
//! fn commit(memory: &mut Memory, driver: &mut Driver, proposal: Proposal, plan: Plan) -> Result<Outcome, Failure> {
//!     let ticket = driver.submit(proposal, plan)?;
//!     run(memory, driver)?;
//!     match driver.take(ticket) {
//!         Some(Answer::Outcome(outcome)) => Ok(outcome),
//!         answer => Err(format!("the commit gave {answer:?}").into()),
//!     }
//! }
//!
//! /// The reads of the decision of the application that `account` can register its first passkey: an open sign-up. The
//! /// sign-up is open while no record has the key `sign-up/closed`, so the decision reads that absence.
//! fn can_register(_account: &Id<Human>) -> Result<[Dependency; 1], Failure> {
//!     Ok([Dependency::Absent(Key::new(b"sign-up/closed")?)])
//! }
//!
//! /// The outcome of the finish of `body`: the JSON that the browser sent.
//! fn finish(rp: &RelyingParty, memory: &mut Memory, driver: &mut Driver, body: &[u8], now: Reading) -> Result<Outcome, Failure> {
//!     let response = Response::parse(body)?;
//!     let registration = ready(rp.finish(memory, &response, now, driver))?;
//!     // Decide again with the current state: the decision of the start can have changed.
//!     let decision = can_register(registration.account())?;
//!     let (proposal, plan) = registration.propose(Decision::SignUp(&decision))?;
//!     commit(memory, driver, proposal, plan)
//! }
//!
//! let now = Reading::new(Duration::from_secs(1_800_000_000), Some(Duration::from_secs(1)), ReadingSource::Caller);
//! let mut memory = Memory::new(Schedule::None);
//! let mut driver = Driver::new(Profile::new(memory.declaration())?, Limits::default())?;
//! driver.start(now);
//! run(&mut memory, &mut driver)?;
//! // Seed the generator from the entropy of the host. The key of the sign-in challenges is a secret of the host too.
//! let mut random = ChaCha20Rng::from_seed([7; 32]);
//! let key = [3; 32];
//! let rp = RelyingParty::new(Id::new("acme", "auth")?, "app.example", "https://app.example", "Acme", key, Limits::default())?;
//!
//! // 1. A new account draws its user handle, and keeps it for each later passkey.
//! let account = Id::new("acme", "alice")?;
//! let user = User {
//!     account: &account,
//!     handle: UserHandle::random(&mut random),
//!     name: "alice@app.example",
//!     display_name: "Alice",
//! };
//! let decision = can_register(&account)?;
//! let (proposal, plan) = ready(rp.start(&mut memory, &user, Decision::SignUp(&decision), now, &mut random, &mut driver))?;
//! let Outcome::Accepted(receipt) = commit(&mut memory, &mut driver, proposal, plan)? else {
//!     return Err("the start did not commit".into());
//! };
//!
//! // 2. Only the accepted commit releases the options, for `PublicKeyCredential.parseCreationOptionsFromJSON()`.
//! let options = receipt.artifact().ok_or("no options")?;
//! assert!(options.starts_with(br#"{"rp":{"id":"app.example","name":"Acme"}"#));
//!
//! // 3. The browser sends `credential.toJSON()`. A body that is not a response refuses before a store read.
//! let error = finish(&rp, &mut memory, &mut driver, b"{}", now).unwrap_err();
//! assert_eq!(error.downcast_ref::<Error>(), Some(&Error::Malformed));
//!
//! // 4. A sign-in starts with options for `PublicKeyCredential.parseRequestOptionsFromJSON()`, and writes nothing.
//! let options = rp.sign_in_options(now, &mut random)?;
//! assert!(options.starts_with(br#"{"challenge":""#));
//! # Ok::<(), Failure>(())
//! ```
//!
//! [WebAuthn Level 3]: https://www.w3.org/TR/webauthn-3/
//! [WebAuthn Level 3, section 7.1]: https://www.w3.org/TR/webauthn-3/#sctn-registering-a-new-credential

use alloc::boxed::Box;
use alloc::string::String;
use alloc::vec;
use alloc::vec::Vec;
use core::fmt;
use core::num::NonZeroUsize;
use core::time::Duration;

use rscodec::base64::Profile::Url;
use rscodec::json::{self, Profile::Rfc8259, Slot, Str};
use rscrypto::{ChaCha20Rng, SecretBytes};

use crate::account::Fresh;
use crate::authz;
use crate::cbor::{self, Value};
use crate::cose::{self, Key, TrustedKey};
use crate::crypto::{self, Algorithm};
use crate::evidence::{Backup, Evidence, Method};
use crate::id::{Action, Authority, AuthorityVersion, Human, Id, Principal};
use crate::limits::{Limits, SignatureBudget};
use crate::session::{self, Access, Opening, Sessions};
use crate::store::driver::{self, Driver, Plan, record};
use crate::store::journal::Role;
use crate::store::{Kind, Record, Store};
use crate::time::{Reading, TimeError};
use crate::transition::{self, Audit, Change, Dependency, OperationId, Prepared, Proposal, Recovery};

/// The time from the start of a registration to the end of its pending record: 300 seconds, the timeout of the
/// options. WebAuthn Level 3 recommends 300 to 600 seconds when the ceremony requires user verification.
pub const REGISTRATION_LIFETIME: Duration = Duration::from_secs(300);

/// The time from the options of a sign-in to the end of its challenge: 300 seconds, the timeout of the options.
pub const SIGN_IN_LIFETIME: Duration = Duration::from_secs(300);

/// The bytes of a sign-in challenge: 32 random bytes, the time of its creation in nanoseconds since the Unix epoch,
/// and the HMAC-SHA256 tag of both under the key of the relying party.
const SIGN_IN_CHALLENGE_BYTES: usize = 72;

/// The bytes of an activation challenge: 32 random bytes, the time of its creation in nanoseconds since the Unix epoch,
/// the digest in the key of its invitation, and the HMAC-SHA256 tag of the three under the key of the relying party.
pub(crate) const ACTIVATION_CHALLENGE_BYTES: usize = 104;

/// The most bytes of a credential ID. WebAuthn Level 3 asks a relying party to refuse a longer one.
pub const CREDENTIAL_ID_BYTES_MAX: usize = 1023;

/// The most bytes of the relying party name and of the name and the display name of a user.
pub const NAME_BYTES_MAX: usize = 256;

/// The most related origins of a relying party ([`RelyingParty::with_related`]). A browser takes the related origins of
/// at least five registrable domains, and WebAuthn Level 3 lets it ignore the others.
pub const RELATED_MAX: usize = 32;

/// The most passkeys of one account at one relying party. The options of a registration list each one, so a start at
/// this bound refuses. Concurrent registrations can pass it by their number, and the next start refuses then too.
pub const CREDENTIALS_MAX: usize = 32;

/// The records of one range read of the passkeys of an account.
pub(crate) const CREDENTIALS: NonZeroUsize = NonZeroUsize::new(CREDENTIALS_MAX).expect("the bound is not zero");

/// The transports that this crate knows, in the order of their bits.
const TRANSPORTS: [&str; 6] = ["usb", "nfc", "ble", "smart-card", "hybrid", "internal"];

/// The algorithms that the options offer, in the order of preference.
pub const ALGORITHMS: [Algorithm; 4] = [
    Algorithm::MlDsa65,
    Algorithm::Ed25519,
    Algorithm::Es256,
    Algorithm::Rs256,
];

/// The COSE identifiers of [`ALGORITHMS`] in the options: EdDSA (-8) for Ed25519, as WebAuthn Level 3 asks.
const OFFERED: [i64; 4] = [-49, -8, -7, -257];

/// The most bytes of the JSON text of a response.
const RESPONSE_BYTES_MAX: u32 = 64 * 1024;

/// The limits of a response. The strings are base64url; the attestation object is the longest.
const RESPONSE: json::Limits = json::Limits {
    input_bytes_max: RESPONSE_BYTES_MAX,
    depth_max: 4,
    string_bytes_max: 32 * 1024,
    members_max: 16,
    elements_max: 8,
    number_digits_max: 32,
};

/// The limits of a `clientDataJSON`. A browser can add members, so the check reads only its own.
const CLIENT_DATA: json::Limits = json::Limits {
    input_bytes_max: 8 * 1024,
    depth_max: 4,
    string_bytes_max: 4096,
    members_max: 16,
    elements_max: 16,
    number_digits_max: 32,
};

/// The slots of the reader: each open container, and each key of each open object.
const SLOTS: usize = 4 * (16 + 1);

/// The flags of the authenticator data.
const USER_PRESENT: u8 = 0x01;
const USER_VERIFIED: u8 = 0x04;
const BACKUP_ELIGIBLE: u8 = 0x08;
const BACKUP_STATE: u8 = 0x10;
const ATTESTED: u8 = 0x40;
const EXTENSIONS: u8 = 0x80;

/// The record forms.
const PENDING_FORM: &str = "rsauthnz.passkey.registration.1";
const SIGN_IN_FORM: &str = "rsauthnz.passkey.sign-in.1";
const CREDENTIAL_FORM: &str = "rsauthnz.passkey.credential.2";

/// The audit actions.
const START: &str = "passkey.start";
const REGISTER: &str = "passkey.register";
const SIGN_IN: &str = "passkey.sign-in";
const SIGN_IN_CLONE: &str = "passkey.sign-in.possible-clone";

/// The relying party of a site.
#[derive(Debug)]
pub struct RelyingParty {
    pub(crate) authority: Id<Authority>,
    pub(crate) id: String,
    origin: String,
    /// The other origins of the application that use the relying party ID ([`Self::with_related`]).
    related: Vec<String>,
    name: String,
    /// The HMAC-SHA256 key of the sign-in and activation challenges.
    pub(crate) key: SecretBytes<32>,
    pub(crate) limits: Limits,
}

impl RelyingParty {
    /// The relying party `id` of the site at `origin`, whose records `authority` owns. `name` is the name that an
    /// authenticator shows. `key` signs the sign-in challenges: 32 random bytes that the host keeps secret, the same on
    /// each node that serves the relying party. A new key ends each open sign-in challenge. `limits` bound the CBOR of
    /// each response.
    ///
    /// `id` is a domain name in lowercase, such as `example.com`. `origin` is the origin in the form that a browser
    /// writes in `clientDataJSON`: `https://` and a host that is `id` or a subdomain of it, with a port only when it
    /// is not 443, or `http://localhost` with an optional port when `id` is `localhost`.
    ///
    /// Cost class: [`Parse`](crate::limits::Class::Parse).
    ///
    /// # Errors
    ///
    /// [`Error::RelyingParty`] if `id` or `origin` is not in this form, and [`Error::Name`] if `name` is empty or
    /// longer than [`NAME_BYTES_MAX`].
    pub fn new(
        authority: Id<Authority>,
        id: &str,
        origin: &str,
        name: &str,
        key: [u8; 32],
        limits: Limits,
    ) -> Result<Self, Error> {
        domain(id).ok_or(Error::RelyingParty)?;
        let host = origin_host(origin, id == "localhost").ok_or(Error::RelyingParty)?;
        let within = host == id
            || host
                .strip_suffix(id)
                .and_then(|sub| sub.strip_suffix('.'))
                .is_some_and(domain);
        within.ok_or(Error::RelyingParty)?;
        name_valid(name)?;
        Ok(Self {
            authority,
            id: id.into(),
            origin: origin.into(),
            related: Vec::new(),
            name: name.into(),
            key: SecretBytes::new(key),
            limits,
        })
    }

    /// The relying party with the related origins `origins` ([WebAuthn Level 3, section 5.11]): other origins of the
    /// application that use the relying party ID, such as `https://app.example.de` for the ID `app.example`. A response
    /// from a related origin verifies as one from the origin of the site. Each one is `https://` and a domain name in
    /// lowercase, with a port only when it is not 443. The browser of a related origin accepts the relying party ID only
    /// when the document of related origins at `https://{id}/.well-known/webauthn` lists the origin, so serve it there
    /// from this list (`rsauthnz_http::related_origins`).
    ///
    /// Cost class: [`Parse`](crate::limits::Class::Parse).
    ///
    /// # Errors
    ///
    /// [`Error::RelyingParty`] for an origin that is not in this form, the origin of the site, an origin that is in
    /// `origins` twice, and more than [`RELATED_MAX`] origins.
    ///
    /// [WebAuthn Level 3, section 5.11]: https://www.w3.org/TR/webauthn-3/#sctn-related-origins
    pub fn with_related(mut self, origins: &[&str]) -> Result<Self, Error> {
        (origins.len() <= RELATED_MAX).ok_or(Error::RelyingParty)?;
        let mut related = Vec::with_capacity(origins.len());
        for (at, origin) in origins.iter().enumerate() {
            let fresh = *origin != self.origin && !origins[..at].contains(origin);
            (fresh && origin_host(origin, false).is_some()).ok_or(Error::RelyingParty)?;
            related.push(String::from(*origin));
        }
        self.related = related;
        Ok(self)
    }

    /// The related origins, in the order of [`Self::with_related`].
    #[must_use]
    pub fn related(&self) -> &[String] {
        &self.related
    }

    /// Proposes the start of the registration of a passkey for the account of `user`, with its user handle. The options
    /// hold the name and the display name of `user`, and no record does. The proposal writes the pending record, and
    /// its commit releases the options as the artifact of the receipt. Submit it with the plan. Its operation identity
    /// is new: after a lost response, start again, because the receipt of a lookup has no artifact.
    ///
    /// The options list each passkey of the account in `excludeCredentials`, from one range read of `store`. An
    /// authenticator that holds one of them refuses to make another passkey for the account, so it cannot replace a
    /// passkey that the store counts as a sign-in method.
    ///
    /// `decision` is the decision of the application that the account can register: [`Decision::SignUp`] for an account
    /// with no passkey, such as an open sign-up, and [`Decision::Add`] with a fresh user verification of the account
    /// for an additional passkey. The proposal reads each read of the decision, so the start commits only while the
    /// decision holds. The finish does not keep it: decide again there ([`Registration::propose`]).
    ///
    /// Cost class: [`Mutate`](crate::limits::Class::Mutate). One range read of at most [`CREDENTIALS_MAX`] credential
    /// records.
    ///
    /// # Errors
    ///
    /// [`Error::Name`] if a name of `user` is empty or longer than [`NAME_BYTES_MAX`]. [`Error::Full`] if the account
    /// has [`CREDENTIALS_MAX`] passkeys, and [`Error::Record`] if one of them has no valid form. [`Error::Fresh`] for a
    /// [`Decision::SignUp`] of an account with a passkey, or a [`Decision::Add`] whose verification is of another
    /// account. [`Error::Time`] if the end of the record overflows. [`Error::Driver`] if the driver does not serve, and
    /// [`Error::Transition`] for the proposal, also for a `decision` that reads more records than the limits permit.
    /// [`Failure::Store`] if the read fails.
    pub async fn start<S: Store>(
        &self,
        store: &mut S,
        user: &User<'_>,
        decision: Decision<'_>,
        now: Reading,
        random: &mut ChaCha20Rng,
        driver: &mut Driver,
    ) -> Result<(Proposal, Plan), Failure<S::Error>> {
        let (account, handle) = (user.account, &user.handle);
        name_valid(user.name)?;
        name_valid(user.display_name)?;
        let records = store
            .range(&self.account_prefix(handle), None, CREDENTIALS)
            .await
            .map_err(Failure::Store)?;
        (records.len() < CREDENTIALS_MAX).ok_or(Error::Full)?;
        let mut excluded = Vec::with_capacity(records.len());
        for (_, record) in &records {
            let (_, _, credential) = credential_form(&record.data, self.limits)?;
            excluded.push(credential);
        }
        let mut challenge = [0; 32];
        random.fill_bytes(&mut challenge);
        let key = self.pending_key(&challenge);
        let end = now
            .estimate()
            .checked_add(REGISTRATION_LIFETIME)
            .ok_or(Error::Time(TimeError::Overflow))?;
        let request = Value::Array(vec![account.to_cbor(), Value::Bytes(&handle.0)]);
        let mut proposal = self.proposal(operation(random), account, START, &request, now)?;
        proposal.read(Dependency::Absent(key.clone())).map_err(Error::from)?;
        decision.apply(&mut proposal, account, !records.is_empty())?;
        let version = self.version(driver.allocate(Kind::Registration).map_err(Error::from)?);
        let form = Value::Array(vec![
            Value::Text(PENDING_FORM),
            account.to_cbor(),
            Value::Bytes(&handle.0),
        ]);
        proposal
            .change(Change::Write {
                key: key.clone(),
                version: version.clone(),
                end: Some(end),
                data: encode(&form),
            })
            .map_err(Error::from)?;
        let options = self.options(user, &challenge, &excluded);
        proposal
            .prepare(Prepared::new(options, key, version))
            .map_err(Error::from)?;
        Ok((proposal, Plan::default()))
    }

    /// The options of `PublicKeyCredentialCreationOptionsJSON` for the challenge `challenge`, with the passkeys
    /// `excluded` of the account.
    pub(crate) fn options(&self, user: &User<'_>, challenge: &[u8], excluded: &[Credential]) -> Vec<u8> {
        // Each name can grow six times by its escapes, and base64url makes each ID and the challenge less than twice as
        // long. Each passkey has less than 128 more bytes, and the rest is less than 1 KiB.
        let names = self.id.len() + self.name.len() + user.name.len() + user.display_name.len();
        let ids: usize = excluded.iter().map(|credential| 2 * credential.id.len() + 128).sum();
        let mut out = vec![0; 1024 + 6 * names + ids + 2 * challenge.len()];
        let len = json::write(&mut out, |options| {
            options.object(|options| {
                options.member("rp").object(|rp| {
                    rp.member("id").str(&self.id)?;
                    rp.member("name").str(&self.name)
                })?;
                options.member("user").object(|entity| {
                    entity.member("id").base64url(&user.handle.0)?;
                    entity.member("name").str(user.name)?;
                    entity.member("displayName").str(user.display_name)
                })?;
                options.member("challenge").base64url(challenge)?;
                options.member("pubKeyCredParams").array(|params| {
                    for alg in OFFERED {
                        params.item().object(|param| {
                            param.member("type").str("public-key")?;
                            param.member("alg").i64(alg)
                        })?;
                    }
                    Ok(())
                })?;
                options.member("timeout").u64(1000 * REGISTRATION_LIFETIME.as_secs())?;
                options.member("excludeCredentials").array(|list| {
                    for credential in excluded {
                        list.item().object(|descriptor| {
                            descriptor.member("type").str("public-key")?;
                            descriptor.member("id").base64url(&credential.id)?;
                            descriptor.member("transports").array(|transports| {
                                for (at, name) in TRANSPORTS.iter().enumerate() {
                                    if credential.transports & (1 << at) != 0 {
                                        transports.item().str(name)?;
                                    }
                                }
                                Ok(())
                            })
                        })?;
                    }
                    Ok(())
                })?;
                options.member("attestation").str("none")?;
                options.member("authenticatorSelection").object(|selection| {
                    selection.member("residentKey").str("required")?;
                    selection.member("requireResidentKey").bool(true)?;
                    selection.member("userVerification").str("required")
                })?;
                options
                    .member("extensions")
                    .object(|extensions| extensions.member("credProps").bool(true))
            })
        })
        .expect("the options fit their buffer");
        out.truncate(len);
        out
    }

    /// Checks the registration `response` of the ceremony whose challenge is `challenge`, and gives the credential.
    /// It checks no store: [`Self::finish`] calls it, and it gives the commit.
    ///
    /// Cost class: [`Verify`](crate::limits::Class::Verify). A P-256 key checks its point, and an RSA key its modulus.
    ///
    /// # Errors
    ///
    /// - [`Error::Challenge`] if `clientDataJSON` has another challenge.
    /// - [`Error::Origin`] if it has another origin, and [`Error::CrossOrigin`] if the ceremony ran in a frame of
    ///   another origin.
    /// - [`Error::RelyingParty`] if the authenticator data has the hash of another relying party ID.
    /// - [`Error::UserPresence`] and [`Error::UserVerification`] if a flag is not set.
    /// - [`Error::Algorithm`] if the key has an algorithm outside the profile, and [`Error::Key`] if it is not a
    ///   valid key of its algorithm.
    /// - [`Error::CredentialId`] if the credential ID is longer than [`CREDENTIAL_ID_BYTES_MAX`] or differs between
    ///   the response and the authenticator data.
    /// - [`Error::NotDiscoverable`] if the `credProps` extension reports a credential that is not discoverable.
    /// - [`Error::Malformed`] for each other difference from the forms of WebAuthn Level 3.
    pub fn verify(&self, response: &Response, challenge: &[u8]) -> Result<Credential, Error> {
        (*response.client_data.challenge == *challenge).ok_or(Error::Challenge)?;
        response.client_data.check(self)?;
        let attestation = cbor::decode(&response.attestation, self.limits).map_err(|_| Error::Malformed)?;
        let Value::Map(entries) = &attestation else {
            return Err(Error::Malformed);
        };
        let member = |name: &str| {
            entries
                .iter()
                .find(|(key, _)| *key == Value::Text(name))
                .map(|(_, value)| value)
        };
        let (Some(Value::Text(_)), Some(Value::Map(_)), Some(Value::Bytes(data))) =
            (member("fmt"), member("attStmt"), member("authData"))
        else {
            return Err(Error::Malformed);
        };
        let (flags, backup, sign_count, rest) = self.authenticator_data(data)?;
        (flags & USER_VERIFIED != 0).ok_or(Error::UserVerification)?;
        (flags & ATTESTED != 0).ok_or(Error::Malformed)?;
        let (_aaguid, rest) = rest.split_first_chunk::<16>().ok_or(Error::Malformed)?;
        let (length, rest) = rest.split_first_chunk::<2>().ok_or(Error::Malformed)?;
        let (id, rest) = rest
            .split_at_checked(usize::from(u16::from_be_bytes(*length)))
            .ok_or(Error::Malformed)?;
        (id.len() <= CREDENTIAL_ID_BYTES_MAX && *id == *response.id).ok_or(Error::CredentialId)?;
        let (key, extensions) = cbor::decode_prefix(rest, self.limits).map_err(|_| Error::Malformed)?;
        self.extensions(flags, extensions)?;
        let key = Key::from_value(&key).map_err(|error| match error {
            cose::Error::Unsupported | cose::Error::KeyAlgorithm => Error::Algorithm,
            _ => Error::Key,
        })?;
        let algorithm = key.alg.ok_or(Error::Algorithm)?;
        ALGORITHMS.contains(&algorithm).ok_or(Error::Algorithm)?;
        TrustedKey::new(algorithm, &key).map_err(|_| Error::Key)?;
        // The record keeps only the checked public parameters, never another member of the key of the response.
        let public_key = cbor::encode(&key.public.to_cbor(), Limits::FORM)
            .expect("a COSE_Key has distinct labels and no simple value");
        (response.discoverable != Some(false)).ok_or(Error::NotDiscoverable)?;
        Ok(Credential {
            id: id.into(),
            algorithm,
            public_key: public_key.into_boxed_slice(),
            sign_count,
            backup,
            transports: response.transports,
            name: Box::default(),
        })
    }

    /// The flags, the backup state, and the signature counter of the authenticator data `data`, and the bytes after the
    /// counter. It checks the hash of the relying party ID, the presence of the user, and a backup state only with
    /// backup eligibility.
    fn authenticator_data<'d>(&self, data: &'d [u8]) -> Result<(u8, Backup, u32, &'d [u8]), Error> {
        let (rp_id_hash, rest) = data.split_first_chunk::<32>().ok_or(Error::Malformed)?;
        (*rp_id_hash == crypto::sha256(self.id.as_bytes())).ok_or(Error::RelyingParty)?;
        let (&[flags], rest) = rest.split_first_chunk::<1>().ok_or(Error::Malformed)?;
        (flags & USER_PRESENT != 0).ok_or(Error::UserPresence)?;
        let backup = backup(flags & BACKUP_ELIGIBLE != 0, flags & BACKUP_STATE != 0).ok_or(Error::Malformed)?;
        let (count, rest) = rest.split_first_chunk::<4>().ok_or(Error::Malformed)?;
        Ok((flags, backup, u32::from_be_bytes(*count), rest))
    }

    /// Checks the extension outputs `extensions` of the authenticator data with `flags`: none without the ED flag, and
    /// a CBOR map with it. The check reads no output, so an output that nobody asked for has no effect.
    fn extensions(&self, flags: u8, extensions: &[u8]) -> Result<(), Error> {
        if flags & EXTENSIONS == 0 {
            extensions.is_empty().ok_or(Error::Malformed)
        } else {
            matches!(cbor::decode(extensions, self.limits), Ok(Value::Map(_))).ok_or(Error::Malformed)
        }
    }

    /// Checks the registration `response` against its pending record in `store`, and gives the [`Registration`]: the
    /// account of the ceremony, the credential, and the commit, which waits for the decision of the application
    /// ([`Registration::propose`]). The commit consumes the pending record and writes the credential record, at the
    /// key of [`Self::credential_key`]. Its plan names the passkey as a sign-in method of the account. One range read
    /// tells whether the account has a passkey, so that only a [`Decision::Add`] can add another one.
    ///
    /// The operation identity is the key of the pending record, so two concurrent finishes of one ceremony are one
    /// operation. Its request binds the credential record: the key, the algorithm, the counter, and the flags. Thus the
    /// same response again gets the receipt of the first commit, and each other response refuses with
    /// [`transition::Error::Reuse`], also one with the same credential ID and another key. After a lost response, look
    /// up the operation of the proposal. A finish after the commit refuses with [`Error::Challenge`]: the commit
    /// consumed the pending record. The deadline of the proposal is the end of the pending record.
    ///
    /// Cost class: [`Verify`](crate::limits::Class::Verify). The checks of [`Self::verify`], and one range read of at
    /// most [`CREDENTIALS_MAX`] credential records.
    ///
    /// # Errors
    ///
    /// The errors of [`Self::verify`]. [`Error::Challenge`] if the store has no pending record of the ceremony under
    /// this relying party, or the record ended at `now`. [`Error::Record`] if the record has no valid form,
    /// [`Error::Time`] if `now` has no bound, [`Error::Driver`] if the driver does not serve, and
    /// [`Error::Transition`] for the proposal. [`Failure::Store`] if a read fails.
    pub async fn finish<S: Store>(
        &self,
        store: &mut S,
        response: &Response,
        now: Reading,
        driver: &mut Driver,
    ) -> Result<Registration, Failure<S::Error>> {
        let ceremony = self.pending_key(&response.client_data.challenge);
        let pending = read(store, &ceremony).await?.ok_or(Error::Challenge)?;
        let end = pending.end.ok_or(Error::Record)?;
        (now.latest().map_err(Error::Time)? < end).ok_or(Error::Challenge)?;
        let (account, handle) = pending_form(&pending.data, self.limits)?;
        let credential = self.verify(response, &response.client_data.challenge)?;
        let existing = !store
            .range(&self.account_prefix(&handle), None, CREDENTIALS)
            .await
            .map_err(Failure::Store)?
            .is_empty();
        let key = self.credential_key(&handle, &credential.id);
        let data = credential.record(&account, &handle);
        let request = Value::Array(vec![Value::Bytes(ceremony.as_bytes()), Value::Bytes(&data)]);
        let operation = OperationId::new(ceremony.as_bytes()).map_err(Error::from)?;
        let mut proposal = self.proposal(operation, &account, REGISTER, &request, now)?;
        proposal
            .read(Dependency::Version(ceremony.clone(), pending.version))
            .map_err(Error::from)?;
        proposal.change(Change::End(ceremony)).map_err(Error::from)?;
        proposal.read(Dependency::Absent(key.clone())).map_err(Error::from)?;
        let version = self.version(driver.allocate(Kind::Credential).map_err(Error::from)?);
        proposal
            .change(Change::Write {
                key: key.clone(),
                version,
                end: None,
                data,
            })
            .map_err(Error::from)?;
        proposal.until(end);
        let plan = Plan {
            anchors: vec![(key, Role::SignIn(account.clone()))],
            ..Plan::default()
        };
        Ok(Registration {
            account,
            credential,
            existing,
            proposal,
            plan,
        })
    }

    /// The options of a sign-in: `PublicKeyCredentialRequestOptionsJSON` with a new challenge, for
    /// `PublicKeyCredential.parseRequestOptionsFromJSON()`. They ask for user verification when the authenticator can do
    /// it, and they name no credential, so the browser offers each passkey of the site, also in the autofill of
    /// conditional mediation. The start writes nothing: the challenge holds the time of its creation under an
    /// HMAC-SHA256 tag of the key. Thus a view of a login page costs no write and no audit record, and each node with the
    /// key and the store can finish the sign-in.
    ///
    /// The time of creation is the earliest time of `now`, which is never after the true time. Thus a challenge from
    /// before a restore is never later than the replay floor of the restore, also from a clock that runs fast within its
    /// bound. The challenge serves for [`SIGN_IN_LIFETIME`] from that time.
    ///
    /// Cost class: [`Parse`](crate::limits::Class::Parse).
    ///
    /// # Errors
    ///
    /// [`Error::Time`] if `now` has no bound, or its earliest time is after the year 2554.
    pub fn sign_in_options(&self, now: Reading, random: &mut ChaCha20Rng) -> Result<Vec<u8>, Error> {
        let mut challenge = [0; SIGN_IN_CHALLENGE_BYTES];
        random.fill_bytes(&mut challenge[..32]);
        let earliest = now.earliest().map_err(Error::Time)?;
        let created = u64::try_from(earliest.as_nanos()).map_err(|_| Error::Time(TimeError::Overflow))?;
        challenge[32..40].copy_from_slice(&created.to_be_bytes());
        let tag = crypto::hmac_sha256(self.key.as_bytes(), &self.signed(SIGN_IN_FORM, &challenge[..40]));
        challenge[40..].copy_from_slice(&tag);
        // The ID can grow six times by its escapes. The rest is less than 512 bytes.
        let mut out = vec![0; 512 + 6 * self.id.len()];
        let len = json::write(&mut out, |options| {
            options.object(|options| {
                options.member("challenge").base64url(&challenge)?;
                options.member("timeout").u64(1000 * SIGN_IN_LIFETIME.as_secs())?;
                options.member("rpId").str(&self.id)?;
                options.member("userVerification").str("preferred")
            })
        })
        .expect("the options fit their buffer");
        out.truncate(len);
        Ok(out)
    }

    /// Proposes the sign-in of `assertion`, after keyed reads of `store`: the credential record, the replay floor, and
    /// the replay record of the challenge. The check refuses a challenge that the key did not make or that is older than
    /// [`SIGN_IN_LIFETIME`] before any read, and a challenge that is not later than the replay floor after its read. A
    /// restore raises the floor, so a challenge from before a restore refuses after it.
    ///
    /// The proposal reads the credential record at its version, and it writes the record only when the signature
    /// counter advances or the backup state changes. A counter that does not advance, with a nonzero counter on either
    /// side, is a possible clone: the stored value stays, and the evidence and the audit action record the signal. The
    /// proposal inserts the replay record of the challenge, so the challenge serves once. Its operation identity is
    /// new, so the same assertion again is a new operation that finds the replay record. [`SignIn::open`] adds the
    /// session and gives the proposal: only its accepted commit releases the evidence and the session.
    ///
    /// Cost class: [`Verify`](crate::limits::Class::Verify). One signature check, and three keyed reads.
    ///
    /// # Errors
    ///
    /// - [`Error::Challenge`] if the challenge is not one of the key, has ended, is not later than the replay floor,
    ///   or served a sign-in already: start a new ceremony.
    /// - [`Error::Origin`] and [`Error::CrossOrigin`] as for a registration, and [`Error::RelyingParty`] and
    ///   [`Error::UserPresence`] for the authenticator data.
    /// - [`Error::Credential`] if the assertion has no user handle of 32 bytes, or the store has no record of the
    ///   credential under this relying party and that handle. [`Error::Signature`] if the signature does not verify
    ///   with the stored key.
    /// - [`Error::Malformed`] if the backup eligibility differs from the registration, and for each other difference
    ///   from the forms of WebAuthn Level 3.
    /// - [`Error::Record`] if a record has no valid form, [`Error::Time`] if `now` has no bound, [`Error::Driver`] if
    ///   the driver does not serve, and [`Error::Transition`] for the proposal. [`Failure::Store`] if a read fails.
    pub async fn sign_in<S: Store>(
        &self,
        store: &mut S,
        assertion: &Assertion,
        now: Reading,
        random: &mut ChaCha20Rng,
        driver: &mut Driver,
    ) -> Result<SignIn, Failure<S::Error>> {
        let challenge = &assertion.client_data.challenge;
        let created = self.created(challenge)?;
        let expires = created
            .checked_add(SIGN_IN_LIFETIME)
            .ok_or(Error::Time(TimeError::Overflow))?;
        let latest = now.latest().map_err(Error::Time)?;
        (created <= latest && latest < expires).ok_or(Error::Challenge)?;
        assertion.client_data.check(self)?;

        let handle = assertion.user_handle.as_deref().ok_or(Error::Credential)?;
        let handle = UserHandle(<[u8; 32]>::try_from(handle).map_err(|_| Error::Credential)?);
        let key = self.credential_key(&handle, &assertion.id);
        let record = read(store, &key).await?.ok_or(Error::Credential)?;
        let floor_key = record::floor_key();
        let floor = read(store, &floor_key).await?;
        if let Some(floor) = &floor {
            (created > record::floor_end(&floor.data, self.limits).ok_or(Error::Record)?).ok_or(Error::Challenge)?;
        }
        let replay = Kind::Replay
            .key(&crypto::sha256(&[SIGN_IN_FORM.as_bytes(), challenge].concat()))
            .expect("a key of 33 bytes is valid");
        read(store, &replay).await?.is_none().ok_or(Error::Challenge)?;

        // The key binds the user handle, so the record is of the account of the assertion.
        let (account, _, stored) = credential_form(&record.data, self.limits)?;
        let (flags, reported, count, rest) = self.authenticator_data(&assertion.authenticator_data)?;
        let single = |backup| backup == Backup::SingleDevice;
        (single(reported) == single(stored.backup) && flags & ATTESTED == 0).ok_or(Error::Malformed)?;
        self.extensions(flags, rest)?;
        let message = [
            &assertion.authenticator_data[..],
            &crypto::sha256(&assertion.client_data_json),
        ]
        .concat();
        let public = Key::decode(&stored.public_key, self.limits).map_err(|_| Error::Record)?;
        TrustedKey::new(stored.algorithm, &public)
            .map_err(|_| Error::Record)?
            .verify_assertion(&message, &assertion.signature, &mut SignatureBudget::new(&self.limits))
            .map_err(|_| Error::Signature)?;

        let advances = count > stored.sign_count;
        let possible_clone = !advances && (count | stored.sign_count) != 0;
        let request = Value::Array(vec![Value::Bytes(&assertion.id), Value::Bytes(challenge)]);
        let action = if possible_clone { SIGN_IN_CLONE } else { SIGN_IN };
        let mut proposal = self.proposal(operation(random), &account, action, &request, now)?;
        proposal
            .read(Dependency::Version(key.clone(), record.version))
            .map_err(Error::from)?;
        // No attestation proves where the key lives, so the evidence has no binding, and only the reported flags.
        let mut evidence = Evidence::new(
            Principal::Human(account.clone()),
            Method::Passkey,
            now,
            flags & USER_VERIFIED != 0,
            true,
            None,
            Some(stored.algorithm.report().authentication),
        );
        evidence.backup = Some(reported);
        evidence.possible_clone = possible_clone;
        // The record keeps the counter that advanced and the backup state of this assertion (WebAuthn Level 3, section
        // 7.2, step 24). The counter never decreases.
        if advances || reported != stored.backup {
            let credential = Credential {
                sign_count: count.max(stored.sign_count),
                backup: reported,
                ..stored
            };
            let version = self.version(driver.allocate(Kind::Credential).map_err(Error::from)?);
            let data = credential.record(&account, &handle);
            proposal
                .change(Change::Write {
                    key,
                    version,
                    end: None,
                    data,
                })
                .map_err(Error::from)?;
        }
        let floor = match floor {
            Some(floor) => Dependency::Version(floor_key, floor.version),
            None => Dependency::Absent(floor_key),
        };
        proposal.read(floor).map_err(Error::from)?;
        proposal.read(Dependency::Absent(replay.clone())).map_err(Error::from)?;
        // The record stays past the end of the challenge by twice the bound of the reading, as the replay contract
        // requires.
        let bound = now.bound().ok_or(Error::Time(TimeError::UnknownBound))?;
        let end = bound
            .checked_mul(2)
            .and_then(|margin| expires.checked_add(margin))
            .ok_or(Error::Time(TimeError::Overflow))?;
        let version = self.version(driver.allocate(Kind::Replay).map_err(Error::from)?);
        let data = encode(&Value::Text(SIGN_IN_FORM));
        proposal
            .change(Change::Write {
                key: replay,
                version,
                end: Some(end),
                data,
            })
            .map_err(Error::from)?;
        proposal.until(expires);
        Ok(SignIn { proposal, evidence })
    }

    /// The bytes that the tag of a challenge covers: the form of its ceremony, the relying party ID, and `body`: the
    /// random bytes, the time of the challenge, and the invitation of an activation. The body of each form has a fixed
    /// length, so the bytes have one reading.
    pub(crate) fn signed(&self, form: &str, body: &[u8]) -> Vec<u8> {
        [form.as_bytes(), self.id.as_bytes(), body].concat()
    }

    /// The time of creation of the sign-in challenge `challenge`, if the key made it.
    fn created(&self, challenge: &[u8]) -> Result<Duration, Error> {
        let (body, tag) = challenge.split_at_checked(40).ok_or(Error::Challenge)?;
        let tag = <&[u8; 32]>::try_from(tag).map_err(|_| Error::Challenge)?;
        crypto::hmac_sha256_verify(self.key.as_bytes(), &self.signed(SIGN_IN_FORM, body), tag)
            .ok_or(Error::Challenge)?;
        let time = body.last_chunk::<8>().ok_or(Error::Challenge)?;
        Ok(Duration::from_nanos(u64::from_be_bytes(*time)))
    }

    /// A proposal of `account` for `action` on `request`. Its request is `[authority, relying party ID, request]`, so
    /// one operation identity under two relying parties of one store binds two requests.
    pub(crate) fn proposal(
        &self,
        operation: OperationId,
        account: &Id<Human>,
        action: &str,
        request: &Value<'_>,
        now: Reading,
    ) -> Result<Proposal, Error> {
        self.proposal_by(operation, Principal::Human(account.clone()), action, request, now)
    }

    /// A proposal of `actor` for `action` on `request`, as [`Self::proposal`] makes it.
    pub(crate) fn proposal_by(
        &self,
        operation: OperationId,
        actor: Principal,
        action: &str,
        request: &Value<'_>,
        now: Reading,
    ) -> Result<Proposal, Error> {
        let audit = Audit {
            actor,
            action: Id::<Action>::new("rsauthnz", action).expect("each action of this module is a valid identifier"),
            time: now,
        };
        let request = Value::Array(vec![self.authority.to_cbor(), Value::Text(&self.id), request.clone()]);
        Ok(Proposal::new(operation, audit, &request, self.limits)?)
    }

    /// The version of a write: the authority and `value`, a new value of a counter of the driver.
    pub(crate) fn version(&self, value: u64) -> AuthorityVersion {
        AuthorityVersion::new(self.authority.clone(), &value.to_be_bytes()).expect("an 8-byte coordinate is valid")
    }

    /// The key of the record of the credential `id` of the account with the user handle `handle`: [`Kind::Credential`],
    /// the SHA-256 digest of the CBOR form `["rsauthnz.passkey.credential.2", authority, relying party ID, user
    /// handle]`, and the SHA-256 digest of `id`. Thus each relying party of a store has its own credentials, and the
    /// first 33 bytes are the prefix of each passkey of the account. No key of a credential of this crate (an 8-byte
    /// serial) has this length.
    ///
    /// Cost class: [`Parse`](crate::limits::Class::Parse).
    #[must_use]
    pub fn credential_key(&self, handle: &UserHandle, id: &[u8]) -> transition::Key {
        let account = self.digest(CREDENTIAL_FORM, &handle.0);
        Kind::Credential
            .key(&[account, crypto::sha256(id)].concat())
            .expect("a key of 65 bytes is valid")
    }

    /// The prefix of the keys of the passkeys of the account with the user handle `handle` ([`Self::credential_key`]).
    pub(crate) fn account_prefix(&self, handle: &UserHandle) -> transition::Key {
        Kind::Credential
            .key(&self.digest(CREDENTIAL_FORM, &handle.0))
            .expect("a key of 33 bytes is valid")
    }

    /// The key of the pending record of the registration challenge `challenge`: [`Kind::Registration`] with the
    /// SHA-256 digest of the CBOR form `["rsauthnz.passkey.registration.1", authority, relying party ID, challenge]`.
    fn pending_key(&self, challenge: &[u8]) -> transition::Key {
        Kind::Registration
            .key(&self.digest(PENDING_FORM, challenge))
            .expect("a key of 33 bytes is valid")
    }

    /// The SHA-256 digest of the CBOR form `[form, authority, relying party ID, value]`.
    pub(crate) fn digest(&self, form: &str, value: &[u8]) -> [u8; 32] {
        crypto::sha256(&encode(&Value::Array(vec![
            Value::Text(form),
            self.authority.to_cbor(),
            Value::Text(&self.id),
            Value::Bytes(value),
        ])))
    }
}

/// The user of a registration: the account, its user handle, and the name and the display name that the
/// authenticator shows. Each name has 1 to [`NAME_BYTES_MAX`] bytes.
#[derive(Clone, Copy, Debug)]
pub struct User<'a> {
    /// The account.
    pub account: &'a Id<Human>,
    /// The user handle of the account.
    pub handle: UserHandle,
    /// The name, such as an email address or a username.
    pub name: &'a str,
    /// The display name, such as a full name.
    pub display_name: &'a str,
}

/// The user handle of an account: 32 random bytes, with no personal data. Each passkey of an account has the same
/// handle, so the authenticator keeps one passkey for each account. Draw one for a new account, and keep it with the
/// account.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub struct UserHandle([u8; 32]);

impl UserHandle {
    /// A new user handle from `random`.
    ///
    /// Cost class: [`Parse`](crate::limits::Class::Parse).
    #[must_use]
    pub fn random(random: &mut ChaCha20Rng) -> Self {
        let mut bytes = [0; 32];
        random.fill_bytes(&mut bytes);
        Self(bytes)
    }

    /// The user handle with the bytes `bytes`.
    ///
    /// Cost class: [`Parse`](crate::limits::Class::Parse).
    #[must_use]
    pub const fn from_bytes(bytes: [u8; 32]) -> Self {
        Self(bytes)
    }

    /// The bytes of the user handle.
    ///
    /// Cost class: [`Parse`](crate::limits::Class::Parse).
    #[must_use]
    pub const fn to_bytes(self) -> [u8; 32] {
        self.0
    }
}

/// A registration response of a browser: `RegistrationResponseJSON`, the result of `credential.toJSON()`.
pub struct Response {
    id: Box<[u8]>,
    client_data: ClientData,
    attestation: Box<[u8]>,
    transports: u8,
    /// The `rk` of the `credProps` extension, if the browser gave it.
    discoverable: Option<bool>,
}

impl Response {
    /// The challenge of `clientDataJSON`.
    pub(crate) fn challenge(&self) -> &[u8] {
        &self.client_data.challenge
    }

    /// Reads the JSON text `json`. It reads `id`, `rawId`, `type`, `response.clientDataJSON`,
    /// `response.attestationObject`, `response.transports`, and `clientExtensionResults.credProps.rk`, and it skips
    /// each other member.
    ///
    /// Cost class: [`Parse`](crate::limits::Class::Parse). The work is linear in `json`, which has at most 64 KiB.
    ///
    /// # Errors
    ///
    /// [`Error::CredentialId`] if `id` and `rawId` differ, and [`Error::Malformed`] for each other difference from
    /// the form, such as a `type` other than `public-key`, a member that is not base64url, or a `clientDataJSON` that is
    /// not JSON of the type `webauthn.create` with the challenge of a registration (32 bytes) or of an activation
    /// ([`RelyingParty::activate`]).
    pub fn parse(json: &[u8]) -> Result<Self, Error> {
        let fields = Fields::read(json)?;
        let (id, client_data) = fields.credential("webauthn.create")?;
        [32, ACTIVATION_CHALLENGE_BYTES]
            .contains(&client_data.challenge.len())
            .ok_or(Error::Malformed)?;
        Ok(Self {
            id,
            client_data,
            attestation: base64url(fields.attestation.ok_or(Error::Malformed)?)?.into(),
            transports: fields.transports,
            discoverable: fields.discoverable,
        })
    }
}

// The challenge of `clientDataJSON` can complete the registration of its ceremony, so the output shows only lengths.
impl fmt::Debug for Response {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("Response")
            .field("id", &self.id.len())
            .field("attestation", &self.attestation.len())
            .finish_non_exhaustive()
    }
}

/// A sign-in response of a browser: `AuthenticationResponseJSON`, the result of `credential.toJSON()`.
pub struct Assertion {
    id: Box<[u8]>,
    client_data: ClientData,
    /// The exact bytes of `clientDataJSON`, which the signature covers through their digest.
    client_data_json: Box<[u8]>,
    authenticator_data: Box<[u8]>,
    signature: Box<[u8]>,
    user_handle: Option<Box<[u8]>>,
}

impl Assertion {
    /// Reads the JSON text `json`. It reads `id`, `rawId`, `type`, `response.clientDataJSON`,
    /// `response.authenticatorData`, `response.signature`, and `response.userHandle`, and it skips each other member.
    ///
    /// Cost class: [`Parse`](crate::limits::Class::Parse). The work is linear in `json`, which has at most 64 KiB.
    ///
    /// # Errors
    ///
    /// [`Error::CredentialId`] if `id` and `rawId` differ, and [`Error::Malformed`] for each other difference from
    /// the form, such as a `clientDataJSON` that is not JSON of the type `webauthn.get`.
    pub fn parse(json: &[u8]) -> Result<Self, Error> {
        let fields = Fields::read(json)?;
        let (id, client_data) = fields.credential("webauthn.get")?;
        Ok(Self {
            id,
            client_data,
            client_data_json: base64url(fields.client_data.ok_or(Error::Malformed)?)?.into(),
            authenticator_data: base64url(fields.authenticator_data.ok_or(Error::Malformed)?)?.into(),
            signature: base64url(fields.signature.ok_or(Error::Malformed)?)?.into(),
            user_handle: fields
                .user_handle
                .map(base64url)
                .transpose()?
                .map(Vec::into_boxed_slice),
        })
    }
}

// The challenge and the signature can repeat the sign-in while the challenge is open, so the output shows only lengths.
impl fmt::Debug for Assertion {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("Assertion")
            .field("id", &self.id.len())
            .field("signature", &self.signature.len())
            .finish_non_exhaustive()
    }
}

/// The members of a response that a check reads, as the reader gives them.
#[derive(Default)]
struct Fields<'a> {
    id: Option<Str<'a>>,
    raw_id: Option<Str<'a>>,
    kind: Option<Str<'a>>,
    client_data: Option<Str<'a>>,
    attestation: Option<Str<'a>>,
    authenticator_data: Option<Str<'a>>,
    signature: Option<Str<'a>>,
    user_handle: Option<Str<'a>>,
    transports: u8,
    discoverable: Option<bool>,
}

impl<'a> Fields<'a> {
    /// Reads the members of the response `json` of either ceremony.
    fn read(json: &'a [u8]) -> Result<Self, Error> {
        let mut scratch = [Slot::EMPTY; SLOTS];
        json::read(json, &RESPONSE, Rfc8259, &mut scratch, |reader| {
            let mut fields = Self::default();
            let mut members = reader.value().members()?;
            while let Some((name, value)) = members.next()? {
                if name == "id" {
                    fields.id = Some(value.str()?);
                } else if name == "rawId" {
                    fields.raw_id = Some(value.str()?);
                } else if name == "type" {
                    fields.kind = Some(value.str()?);
                } else if name == "response" {
                    let mut members = value.members()?;
                    while let Some((name, mut value)) = members.next()? {
                        if name == "clientDataJSON" {
                            fields.client_data = Some(value.str()?);
                        } else if name == "attestationObject" {
                            fields.attestation = Some(value.str()?);
                        } else if name == "authenticatorData" {
                            fields.authenticator_data = Some(value.str()?);
                        } else if name == "signature" {
                            fields.signature = Some(value.str()?);
                        } else if name == "userHandle" && value.kind()? != json::Kind::Null {
                            fields.user_handle = Some(value.str()?);
                        } else if name == "transports" {
                            let mut items = value.elements()?;
                            while let Some(item) = items.next()? {
                                fields.transports |= transport(item.str()?);
                            }
                        }
                    }
                } else if name == "clientExtensionResults" {
                    let mut members = value.members()?;
                    while let Some((name, value)) = members.next()? {
                        if name == "credProps" {
                            let mut members = value.members()?;
                            while let Some((name, value)) = members.next()? {
                                if name == "rk" {
                                    fields.discoverable = Some(value.bool()?);
                                }
                            }
                        }
                    }
                }
            }
            Ok(fields)
        })
        .map_err(|_| Error::Malformed)
    }

    /// The credential ID and the `clientDataJSON` of the type `kind`, after the checks of the type of the response and
    /// of its two IDs.
    fn credential(&self, kind: &str) -> Result<(Box<[u8]>, ClientData), Error> {
        let (Some(id), Some(raw_id), Some(response), Some(client_data)) =
            (self.id, self.raw_id, self.kind, self.client_data)
        else {
            return Err(Error::Malformed);
        };
        (response == "public-key").ok_or(Error::Malformed)?;
        let id = base64url(id)?;
        (id == base64url(raw_id)?).ok_or(Error::CredentialId)?;
        Ok((id.into(), ClientData::parse(&base64url(client_data)?, kind)?))
    }
}

/// The members of `clientDataJSON` that a check reads.
struct ClientData {
    challenge: Box<[u8]>,
    origin: String,
    /// Whether the ceremony ran in a frame of another origin: `crossOrigin` is true, or `topOrigin` is present.
    cross_origin: bool,
}

impl ClientData {
    /// Reads the `clientDataJSON` text `json` of the type `kind`.
    fn parse(json: &[u8], kind: &str) -> Result<Self, Error> {
        let mut scratch = [Slot::EMPTY; SLOTS];
        let (found, challenge, origin, cross_origin) =
            json::read(json, &CLIENT_DATA, Rfc8259, &mut scratch, |reader| {
                let (mut found, mut challenge, mut origin, mut cross_origin) = (None, None, None, false);
                let mut members = reader.value().members()?;
                while let Some((name, value)) = members.next()? {
                    if name == "type" {
                        found = Some(value.str()?);
                    } else if name == "challenge" {
                        challenge = Some(value.str()?);
                    } else if name == "origin" {
                        origin = Some(value.str()?);
                    } else if name == "crossOrigin" {
                        cross_origin |= value.bool()?;
                    } else if name == "topOrigin" {
                        value.skip()?;
                        cross_origin = true;
                    }
                }
                Ok((found, challenge, origin, cross_origin))
            })
            .map_err(|_| Error::Malformed)?;
        let (Some(found), Some(challenge), Some(origin)) = (found, challenge, origin) else {
            return Err(Error::Malformed);
        };
        (found == kind).ok_or(Error::Malformed)?;
        let mut text = vec![0; origin.len()];
        Ok(Self {
            challenge: base64url(challenge)?.into(),
            origin: origin.decode(&mut text).map_err(|_| Error::Malformed)?.into(),
            cross_origin,
        })
    }

    /// Checks the origin and the frame.
    /// Checks the origin of the site of `rp`, or one of its related origins, and no frame of another origin.
    fn check(&self, rp: &RelyingParty) -> Result<(), Error> {
        let origin = self.origin.as_str();
        (rp.origin == origin || rp.related.iter().any(|related| related == origin)).ok_or(Error::Origin)?;
        (!self.cross_origin).ok_or(Error::CrossOrigin)
    }
}

/// A registered passkey: what the check of a registration proved, and the record of the credential.
#[derive(Clone, PartialEq, Eq)]
pub struct Credential {
    id: Box<[u8]>,
    algorithm: Algorithm,
    /// The checked public key, as the deterministic CBOR of its `COSE_Key` with only `kty`, `alg`, and the public
    /// parameters.
    public_key: Box<[u8]>,
    sign_count: u32,
    backup: Backup,
    /// The transports of the response, one bit for each one that [`transport`] knows.
    transports: u8,
    /// The name that the user gave the passkey, or the empty name of a new one
    /// ([`RelyingParty::rename`]).
    pub(crate) name: Box<str>,
}

impl Credential {
    /// The credential ID.
    #[must_use]
    pub fn id(&self) -> &[u8] {
        &self.id
    }

    /// The algorithm of the credential key.
    #[must_use]
    pub const fn algorithm(&self) -> Algorithm {
        self.algorithm
    }

    /// The signature counter of the registration. Zero when the authenticator has no counter, as a synchronized
    /// passkey has none.
    #[must_use]
    pub const fn sign_count(&self) -> u32 {
        self.sign_count
    }

    /// The backup state that the authenticator reports: the BE and BS flags. It proves no binding of the key.
    #[must_use]
    pub const fn backup(&self) -> Backup {
        self.backup
    }

    /// The name that the user gave the passkey, such as "Work laptop". A new passkey has the empty name.
    #[must_use]
    pub fn name(&self) -> &str {
        &self.name
    }

    /// The record form: `["rsauthnz.passkey.credential.2", account, user handle, credential ID, COSE key, COSE
    /// algorithm, signature counter, backup eligible, backup state, transports, name]`.
    pub(crate) fn record(&self, account: &Id<Human>, handle: &UserHandle) -> Box<[u8]> {
        let algorithm = self
            .algorithm
            .report()
            .cose
            .expect("each algorithm of the profile has a COSE identifier");
        encode(&Value::Array(vec![
            Value::Text(CREDENTIAL_FORM),
            account.to_cbor(),
            Value::Bytes(&handle.0),
            Value::Bytes(&self.id),
            Value::Bytes(&self.public_key),
            int(algorithm),
            Value::Unsigned(u64::from(self.sign_count)),
            Value::Bool(self.backup != Backup::SingleDevice),
            Value::Bool(self.backup == Backup::BackedUp),
            Value::Unsigned(u64::from(self.transports)),
            Value::Text(&self.name),
        ]))
    }
}

impl fmt::Debug for Credential {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("Credential")
            .field("id", &self.id.len())
            .field("algorithm", &self.algorithm)
            .field("sign_count", &self.sign_count)
            .field("backup", &self.backup)
            .field("name", &self.name)
            .finish_non_exhaustive()
    }
}

/// A checked registration that waits for the decision of the application: the account of its ceremony, the
/// credential, and the commit that [`RelyingParty::finish`] made.
pub struct Registration {
    account: Id<Human>,
    credential: Credential,
    /// Whether the account had a passkey at the finish.
    existing: bool,
    proposal: Proposal,
    plan: Plan,
}

impl Registration {
    /// The account of the ceremony, from its pending record.
    #[must_use]
    pub const fn account(&self) -> &Id<Human> {
        &self.account
    }

    /// The credential that the check proved.
    #[must_use]
    pub const fn credential(&self) -> &Credential {
        &self.credential
    }

    /// The commit of the registration, with `decision`. Submit the proposal with the plan, and give the browser the
    /// response of the outcome.
    ///
    /// `decision` is the decision of the application that [`Self::account`] can register this passkey now:
    /// [`Decision::SignUp`] when the account has no passkey, and [`Decision::Add`] when it has one. Decide again with
    /// the current state, not with the decision of the start: a session or a permission can end during the ceremony.
    /// The commit that writes the credential reads each read of the decision, so a change after the decision makes it
    /// conflict. A conflict commits nothing, and the pending record stays: finish again with a new decision, or start
    /// a new ceremony. The fresh user verification of an addition must hold at the commit: after [`Error::Fresh`] or
    /// an expired commit, verify the user again and finish again.
    ///
    /// Cost class: [`Parse`](crate::limits::Class::Parse).
    ///
    /// # Errors
    ///
    /// [`Error::Fresh`] for a [`Decision::SignUp`] of an account that has a passkey, and for a [`Decision::Add`] whose
    /// verification is of another account. [`Error::Transition`] if `decision` reads a record of the registration with
    /// another result, or reads more records than the limits permit.
    pub fn propose(mut self, decision: Decision<'_>) -> Result<(Proposal, Plan), Error> {
        decision.apply(&mut self.proposal, &self.account, self.existing)?;
        Ok((self.proposal, self.plan))
    }
}

impl fmt::Debug for Registration {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("Registration")
            .field("account", &self.account)
            .field("credential", &self.credential)
            .finish_non_exhaustive()
    }
}

/// The decision of the application that an account can register a passkey: the reads of the decision, which the
/// commit reads. An additional passkey of an account is a sensitive change, so it needs a fresh user verification.
#[derive(Clone, Copy, Debug)]
pub enum Decision<'a> {
    /// The first passkey of an account, such as at an open sign-up. It refuses for an account that has a passkey.
    SignUp(&'a [Dependency]),
    /// An additional passkey of the signed-in account of the fresh user verification. The commit reads its session at
    /// its version, and its deadline is the end of the verification.
    Add(&'a Fresh, &'a [Dependency]),
}

impl Decision<'_> {
    /// Adds the decision for `account` to `proposal`. `existing` tells whether the account has a passkey.
    fn apply(self, proposal: &mut Proposal, account: &Id<Human>, existing: bool) -> Result<(), Error> {
        let reads = match self {
            Self::SignUp(reads) => {
                (!existing).ok_or(Error::Fresh)?;
                reads
            }
            Self::Add(fresh, reads) => {
                (fresh.account() == account).ok_or(Error::Fresh)?;
                fresh.gate(proposal)?;
                reads
            }
        };
        decide(proposal, reads)?;
        Ok(())
    }
}

/// A checked sign-in that waits for its session: the evidence, and the commit that [`RelyingParty::sign_in`] made.
#[derive(Debug)]
pub struct SignIn {
    proposal: Proposal,
    evidence: Evidence,
}

impl SignIn {
    /// The commit of the sign-in with a new session of `sessions`, and the [`Opening`] that only its accepted commit
    /// releases. `replaces` is the current session of the browser, if it has one: the commit ends that family, so a
    /// sign-in, also a fresh user verification of a signed-in account, always gives a new identifier and the old one
    /// refuses. Submit the proposal with the plan, and give its outcome to [`Opening::release`].
    ///
    /// After a lost response, keep the opening, and look up the operation of the proposal when the driver serves again.
    /// Give the receipt of the lookup as [`Outcome::Accepted`](crate::transition::Outcome::Accepted). No second sign-in
    /// runs by itself.
    ///
    /// Cost class: [`Parse`](crate::limits::Class::Parse). One SHA-256 digest and one HMAC-SHA256 tag.
    ///
    /// # Errors
    ///
    /// [`Error::Session`] if `replaces` is a session of another audience, and for the errors of the session: the time
    /// of the proposal has no bound, the driver does not serve, or the proposal refuses.
    pub fn open(
        mut self,
        sessions: &Sessions,
        replaces: Option<&Access>,
        random: &mut ChaCha20Rng,
        driver: &mut Driver,
    ) -> Result<(Proposal, Plan, Opening), Error> {
        let opening = sessions
            .open(&mut self.proposal, self.evidence, replaces, random, driver)
            .map_err(Error::Session)?;
        Ok((self.proposal, Plan::default(), opening))
    }
}

/// The account, the user handle, and the credential of the credential record form `data`.
pub(crate) fn credential_form(data: &[u8], limits: Limits) -> Result<(Id<Human>, UserHandle, Credential), Error> {
    let form = cbor::decode(data, limits).map_err(|_| Error::Record)?;
    let Value::Array(items) = &form else {
        return Err(Error::Record);
    };
    let [
        Value::Text(CREDENTIAL_FORM),
        account,
        Value::Bytes(handle),
        Value::Bytes(id),
        Value::Bytes(public_key),
        alg,
        Value::Unsigned(count),
        Value::Bool(backup_eligible),
        Value::Bool(backup_state),
        Value::Unsigned(transports),
        Value::Text(name),
    ] = items.as_slice()
    else {
        return Err(Error::Record);
    };
    name_length(name)?;
    let algorithm = ALGORITHMS
        .into_iter()
        .find(|algorithm| algorithm.report().cose.map(int).as_ref() == Some(alg))
        .ok_or(Error::Record)?;
    let credential = Credential {
        id: (*id).into(),
        algorithm,
        public_key: (*public_key).into(),
        sign_count: u32::try_from(*count).map_err(|_| Error::Record)?,
        backup: backup(*backup_eligible, *backup_state).ok_or(Error::Record)?,
        transports: u8::try_from(*transports).map_err(|_| Error::Record)?,
        name: (*name).into(),
    };
    let account = Id::from_cbor(account).map_err(|_| Error::Record)?;
    let handle = <[u8; 32]>::try_from(*handle).map_err(|_| Error::Record)?;
    Ok((account, UserHandle(handle), credential))
}

/// The record at `key`.
pub(crate) async fn read<S: Store>(store: &mut S, key: &transition::Key) -> Result<Option<Record>, Failure<S::Error>> {
    store.read(key).await.map_err(Failure::Store)
}

/// The account and the user handle of the pending record form `data`.
fn pending_form(data: &[u8], limits: Limits) -> Result<(Id<Human>, UserHandle), Error> {
    let form = cbor::decode(data, limits).map_err(|_| Error::Record)?;
    let Value::Array(items) = &form else {
        return Err(Error::Record);
    };
    let [Value::Text(PENDING_FORM), account, Value::Bytes(handle)] = items.as_slice() else {
        return Err(Error::Record);
    };
    let account = Id::from_cbor(account).map_err(|_| Error::Record)?;
    let handle = <[u8; 32]>::try_from(*handle).map_err(|_| Error::Record)?;
    Ok((account, UserHandle(handle)))
}

/// A new operation identity: 32 bytes from `random`.
pub(crate) fn operation(random: &mut ChaCha20Rng) -> OperationId {
    let mut id = [0; 32];
    random.fill_bytes(&mut id);
    OperationId::new(&id).expect("32 bytes are a valid operation identity")
}

/// The reads of `decision`, the decision of the application, in `proposal`.
pub(crate) fn decide(proposal: &mut Proposal, decision: &[Dependency]) -> Result<(), transition::Error> {
    decision.iter().try_for_each(|read| proposal.read(read.clone()))
}

/// The backup state of the flags BE (`eligible`) and BS (`state`), or `None` for a backup state with no backup
/// eligibility.
const fn backup(eligible: bool, state: bool) -> Option<Backup> {
    match (eligible, state) {
        (false, false) => Some(Backup::SingleDevice),
        (true, false) => Some(Backup::Eligible),
        (true, true) => Some(Backup::BackedUp),
        (false, true) => None,
    }
}

/// The bit of the transport `name`, or zero for a transport that this crate does not know.
fn transport(name: Str<'_>) -> u8 {
    TRANSPORTS
        .iter()
        .position(|known| name == *known)
        .map_or(0, |at| 1 << at)
}

/// The bytes of the base64url text `text`, with no padding.
fn base64url(text: Str<'_>) -> Result<Vec<u8>, Error> {
    let mut unescaped = Vec::new();
    let text = match text.borrowed() {
        Some(text) => text.as_bytes(),
        None => {
            unescaped.resize(text.len(), 0);
            text.decode(&mut unescaped).map_err(|_| Error::Malformed)?.as_bytes()
        }
    };
    let mut out = vec![0; Url.decoded_len(text).map_err(|_| Error::Malformed)?];
    Url.decode(text, &mut out).map_err(|_| Error::Malformed)?;
    Ok(out)
}

/// The host of `origin` in the form that a browser writes in `clientDataJSON`: `https://` and a domain name in lowercase,
/// with a port only when it is not 443, or, when `localhost` is true, `http://` and a domain name with an optional port.
/// A browser writes a port with no leading zero, and no default port.
fn origin_host(origin: &str, localhost: bool) -> Option<&str> {
    let (rest, default) = match origin.strip_prefix("https://") {
        Some(rest) => (rest, 443),
        None if localhost => (origin.strip_prefix("http://")?, 80),
        None => return None,
    };
    let (host, port) = rest
        .split_once(':')
        .map_or((rest, None), |(host, port)| (host, Some(port)));
    let port_valid = port.is_none_or(|port| {
        port.bytes().all(|byte| byte.is_ascii_digit())
            && !port.starts_with('0')
            && port.parse::<u16>().is_ok_and(|port| port != default)
    });
    (port_valid && domain(host)).then_some(host)
}

/// Whether `text` is a domain name in lowercase ASCII: labels of 1 to 63 letters, digits, and hyphens, with no hyphen
/// at an end, and at most 253 bytes.
fn domain(text: &str) -> bool {
    text.len() <= 253
        && text.split('.').all(|label| {
            (1..=63).contains(&label.len())
                && label
                    .bytes()
                    .all(|byte| byte.is_ascii_lowercase() || byte.is_ascii_digit() || byte == b'-')
                && !label.starts_with('-')
                && !label.ends_with('-')
        })
}

/// Refuses a name that is empty or longer than [`NAME_BYTES_MAX`].
pub(crate) fn name_valid(name: &str) -> Result<(), Error> {
    (1..=NAME_BYTES_MAX).contains(&name.len()).ok_or(Error::Name)
}

/// Refuses the stored name of a passkey that is longer than [`NAME_BYTES_MAX`]. A new passkey has the empty name.
fn name_length(name: &str) -> Result<(), Error> {
    (name.len() <= NAME_BYTES_MAX).ok_or(Error::Record)
}

/// The CBOR value of the integer `value`.
const fn int(value: i64) -> Value<'static> {
    if value >= 0 {
        Value::Unsigned(value.unsigned_abs())
    } else {
        Value::Negative(value.unsigned_abs() - 1)
    }
}

/// The deterministic CBOR of the record form `form`.
pub(crate) fn encode(form: &Value<'_>) -> Box<[u8]> {
    cbor::encode(form, Limits::FORM)
        .expect("a record form has no map and no simple value")
        .into_boxed_slice()
}

/// The cause of a refusal.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Error {
    /// The relying party ID or the origin of [`RelyingParty::new`] is not valid, or the authenticator data has the
    /// hash of another relying party ID.
    RelyingParty,
    /// A name is empty or longer than [`NAME_BYTES_MAX`].
    Name,
    /// The response is not in the forms of WebAuthn Level 3.
    Malformed,
    /// The challenge is not the challenge of the ceremony, or the pending record ended.
    Challenge,
    /// The origin of `clientDataJSON` is not the origin of the site or one of its related origins.
    Origin,
    /// The ceremony ran in a frame of another origin.
    CrossOrigin,
    /// The authenticator did not report the presence of the user.
    UserPresence,
    /// The authenticator did not verify the user.
    UserVerification,
    /// The credential key has an algorithm outside the profile ([`ALGORITHMS`], Ed25519, and ESP256).
    Algorithm,
    /// The credential key is not a valid key of its algorithm.
    Key,
    /// The credential ID is too long, or the response and the authenticator data have two IDs.
    CredentialId,
    /// The `credProps` extension reports a credential that is not discoverable.
    NotDiscoverable,
    /// The account has [`CREDENTIALS_MAX`] passkeys.
    Full,
    /// The store has no record of the credential of an assertion, or the assertion names another user handle.
    Credential,
    /// The signature of an assertion does not verify with the key of its credential.
    Signature,
    /// A record has no valid form.
    Record,
    /// The time reading has no bound, or a time overflows.
    Time(TimeError),
    /// The commit driver gave no value.
    Driver(driver::Error),
    /// The proposal refuses.
    Transition(transition::Error),
    /// The session of the sign-in refuses.
    Session(session::Error),
    /// The change needs a fresh user verification of the account ([`Fresh`]): a [`Decision::SignUp`] of an account
    /// that has a passkey, or a verification of another account.
    Fresh,
    /// No open invitation has the value or the challenge: the invitation ended, or an activation consumed it.
    Invitation,
    /// The invitation names another recipient.
    Recipient,
    /// The recipient of the invitation has a passkey, so the invitation activates nothing.
    Activated,
    /// The current policy does not permit the action of the issuer of the invitation.
    Issuer,
    /// The lifetime of an invitation is zero or longer than
    /// [`INVITATION_LIFETIME_MAX`](crate::account::INVITATION_LIFETIME_MAX).
    Lifetime,
    /// The policy refuses the issue of an invitation.
    Authorization(authz::Refusal),
}

impl Error {
    /// The recovery of the caller: start a new ceremony after [`Error::Challenge`], verify the user again after
    /// [`Error::Fresh`], and the recovery of the proposal after [`Error::Transition`] and [`Error::Session`]. Refuse each
    /// other request.
    #[must_use]
    pub const fn recovery(&self) -> Recovery {
        match self {
            Self::Challenge => Recovery::Restart,
            Self::Fresh => Recovery::Verify,
            Self::Transition(error) => error.recovery(),
            Self::Session(error) => error.recovery(),
            _ => Recovery::Refuse,
        }
    }
}

impl fmt::Display for Error {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::RelyingParty => f.write_str("the relying party ID or the origin is not valid"),
            Self::Name => f.write_str("a name is empty or too long"),
            Self::Malformed => f.write_str("the response is not in the forms of WebAuthn Level 3"),
            Self::Challenge => f.write_str("the challenge is not the challenge of a pending ceremony"),
            Self::Origin => f.write_str("the origin of the response is not an origin of the site"),
            Self::CrossOrigin => f.write_str("the ceremony ran in a frame of another origin"),
            Self::UserPresence => f.write_str("the authenticator did not report the presence of the user"),
            Self::UserVerification => f.write_str("the authenticator did not verify the user"),
            Self::Algorithm => f.write_str("the credential key has an algorithm outside the profile"),
            Self::Key => f.write_str("the credential key is not valid"),
            Self::CredentialId => f.write_str("the credential ID is too long or not consistent"),
            Self::NotDiscoverable => f.write_str("the credential is not discoverable"),
            Self::Full => f.write_str("the account has the most passkeys"),
            Self::Credential => f.write_str("the credential is not a passkey of the account"),
            Self::Signature => f.write_str("the signature of the assertion does not verify"),
            Self::Record => f.write_str("a record has no valid form"),
            Self::Time(error) => write!(f, "the time reading gave no value: {error}"),
            Self::Driver(error) => write!(f, "the commit driver gave no value: {error}"),
            Self::Transition(error) => write!(f, "the proposal refuses: {error}"),
            Self::Session(error) => write!(f, "the session refuses: {error}"),
            Self::Fresh => f.write_str("the change needs a fresh user verification of the account"),
            Self::Invitation => f.write_str("no open invitation has the value"),
            Self::Recipient => f.write_str("the invitation names another recipient"),
            Self::Activated => f.write_str("the recipient of the invitation has a passkey"),
            Self::Issuer => f.write_str("the policy does not permit the action of the issuer of the invitation"),
            Self::Lifetime => f.write_str("the lifetime of the invitation is not valid"),
            Self::Authorization(refusal) => write!(f, "the policy refuses the invitation: {refusal}"),
        }
    }
}

impl core::error::Error for Error {}

impl From<transition::Error> for Error {
    fn from(error: transition::Error) -> Self {
        Self::Transition(error)
    }
}

impl From<driver::Error> for Error {
    fn from(error: driver::Error) -> Self {
        Self::Driver(error)
    }
}

/// The failure of an operation that reads the store: a refusal, or a failed read.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Failure<E> {
    /// The operation refused.
    Refused(Error),
    /// A read failed. It is a crash of the binding: start the driver again.
    Store(E),
}

impl<E> From<Error> for Failure<E> {
    fn from(error: Error) -> Self {
        Self::Refused(error)
    }
}

impl<E: fmt::Display> fmt::Display for Failure<E> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Refused(error) => error.fmt(f),
            Self::Store(error) => write!(f, "a read of the store failed: {error}"),
        }
    }
}

impl<E: core::error::Error> core::error::Error for Failure<E> {}

#[cfg(test)]
mod tests;
