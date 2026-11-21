//! Passkeys ([WebAuthn Level 3]): the registration ceremony.
//!
//! A [`RelyingParty`] holds the relying party ID, the origin of the site, and the authority that owns the records.
//! A registration has two commits:
//!
//! 1. [`RelyingParty::start`] proposes the pending registration of an account: a record whose key is the SHA-256
//!    digest of a new challenge of 32 bytes, with the account and its user handle. The record ends after
//!    [`REGISTRATION_LIFETIME`]. Only the accepted commit releases the options, as the artifact of the receipt. Give
//!    them to `PublicKeyCredential.parseCreationOptionsFromJSON()` in the browser.
//! 2. The browser gives the response of `navigator.credentials.create()` as `credential.toJSON()`. [`Response::parse`]
//!    reads it, and [`Response::ceremony`] gives the key of its pending record. [`RelyingParty::finish`] checks the
//!    response against the record and proposes one commit: it consumes the pending record and writes the credential
//!    record. Its plan names the passkey as a sign-in method of the account, so a restore completes a registration
//!    that a crash left in doubt.
//!
//! The options offer ML-DSA-65 (-49), EdDSA (-8), ES256 (-7), and RS256 (-257), in this order, and the check also
//! takes Ed25519 (-19) and ESP256 (-9). They require a discoverable credential and user verification, and they ask for
//! no attestation. The check takes each attestation format and reads no attestation statement, so the credential is
//! one with no attestation: no attestation proves the model of an authenticator, and this crate trusts none
//! ([WebAuthn Level 3, section 7.1]). It checks `clientDataJSON` (the type, the challenge, the origin, and no
//! cross-origin frame), the relying party ID hash, the flags, and the credential public key.
//!
//! The pending record holds the digest of the challenge, never the challenge: the response is not signed, so the
//! challenge is the only proof that the response comes from the ceremony of the account.
//!
//! The example runs a start on the memory binding of `rsauthnz-conformance`. The finish of a real response needs a
//! browser and an authenticator, so the example sends a body that is not a response, which refuses.
//!
//! ```
//! use core::pin::pin;
//! use core::task::{Context, Poll, Waker};
//! use core::time::Duration;
//!
//! use rsauthnz::id::Id;
//! use rsauthnz::limits::Limits;
//! use rsauthnz::passkey::{Error, RelyingParty, Response, User, UserHandle};
//! use rsauthnz::store::driver::{Answer, Driver, Plan};
//! use rsauthnz::store::{Profile, Store};
//! use rsauthnz::time::{Reading, ReadingSource};
//! use rsauthnz::transition::{OperationId, Outcome, Proposal};
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
//! /// The outcome of the finish of `body`: the JSON that the browser sent.
//! fn finish(rp: &RelyingParty, memory: &mut Memory, driver: &mut Driver, body: &[u8], now: Reading) -> Result<Outcome, Failure> {
//!     let response = Response::parse(body)?;
//!     // No pending record: the ceremony ended, or it never started. The browser starts again.
//!     let pending = ready(memory.read(&response.ceremony()))?.ok_or(Error::Challenge)?;
//!     let (proposal, plan, _credential) = rp.finish(&response, &pending, now, driver)?;
//!     commit(memory, driver, proposal, plan)
//! }
//!
//! let now = Reading::new(Duration::from_secs(1_800_000_000), Some(Duration::from_secs(1)), ReadingSource::Caller);
//! let mut memory = Memory::new(Schedule::None);
//! let mut driver = Driver::new(Profile::new(memory.declaration())?, Limits::default())?;
//! driver.start(now);
//! run(&mut memory, &mut driver)?;
//! // Seed the generator from the entropy of the host.
//! let mut random = ChaCha20Rng::from_seed([7; 32]);
//! let rp = RelyingParty::new(Id::new("acme", "auth")?, "app.example", "https://app.example", "Acme", Limits::default())?;
//!
//! // 1. A new account draws its user handle, and keeps it for each later passkey.
//! let account = Id::new("acme", "alice")?;
//! let user = User {
//!     account: &account,
//!     handle: UserHandle::random(&mut random),
//!     name: "alice@app.example",
//!     display_name: "Alice",
//! };
//! let (proposal, plan) = rp.start(&user, OperationId::new(b"start-1")?, now, &mut random, &mut driver)?;
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
use core::time::Duration;

use rscodec::base64::Profile::Url;
use rscodec::json::{self, Profile::Rfc8259, Slot, Str};
use rscrypto::ChaCha20Rng;

use crate::cbor::{self, Value};
use crate::cose::{self, Key, TrustedKey};
use crate::crypto::{self, Algorithm};
use crate::evidence::Binding;
use crate::id::{Action, Authority, AuthorityVersion, Human, Id, Principal};
use crate::limits::Limits;
use crate::store::driver::{self, Driver, Plan};
use crate::store::journal::Role;
use crate::store::{Kind, Record};
use crate::time::{Reading, TimeError};
use crate::transition::{self, Audit, Change, Dependency, OperationId, Prepared, Proposal, Recovery};

/// The time from the start of a registration to the end of its pending record: 300 seconds, the timeout of the
/// options. WebAuthn Level 3 recommends 300 to 600 seconds when the ceremony requires user verification.
pub const REGISTRATION_LIFETIME: Duration = Duration::from_secs(300);

/// The most bytes of a credential ID. WebAuthn Level 3 asks a relying party to refuse a longer one.
pub const CREDENTIAL_ID_BYTES_MAX: usize = 1023;

/// The most bytes of the relying party name and of the name and the display name of a user.
pub const NAME_BYTES_MAX: usize = 256;

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
const CREDENTIAL_FORM: &str = "rsauthnz.passkey.credential.1";

/// The audit actions.
const START: &str = "passkey.start";
const REGISTER: &str = "passkey.register";

/// The relying party of a site.
#[derive(Clone, Debug)]
pub struct RelyingParty {
    authority: Id<Authority>,
    id: String,
    origin: String,
    name: String,
    limits: Limits,
}

impl RelyingParty {
    /// The relying party `id` of the site at `origin`, whose records `authority` owns. `name` is the name that an
    /// authenticator shows. `limits` bound the CBOR of each response.
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
    pub fn new(authority: Id<Authority>, id: &str, origin: &str, name: &str, limits: Limits) -> Result<Self, Error> {
        domain(id).ok_or(Error::RelyingParty)?;
        let host = match origin.strip_prefix("https://") {
            Some(rest) => rest,
            None if id == "localhost" => origin.strip_prefix("http://").ok_or(Error::RelyingParty)?,
            None => return Err(Error::RelyingParty),
        };
        let default = if origin.starts_with("https://") { 443 } else { 80 };
        let (host, port) = host
            .split_once(':')
            .map_or((host, None), |(host, port)| (host, Some(port)));
        // A browser writes a port with no leading zero, and no default port.
        let port_valid = port.is_none_or(|port| {
            port.bytes().all(|byte| byte.is_ascii_digit())
                && !port.starts_with('0')
                && port.parse::<u16>().is_ok_and(|port| port != default)
        });
        let within = host == id
            || host
                .strip_suffix(id)
                .and_then(|sub| sub.strip_suffix('.'))
                .is_some_and(domain);
        (port_valid && domain(host) && within).ok_or(Error::RelyingParty)?;
        name_valid(name)?;
        Ok(Self {
            authority,
            id: id.into(),
            origin: origin.into(),
            name: name.into(),
            limits,
        })
    }

    /// Proposes the start of the registration of a passkey for the account of `user`, with its user handle. The options
    /// hold the name and the display name of `user`, and no record does. The proposal writes the pending record, and its commit releases the options as
    /// the artifact of the receipt. Submit it with the plan. After a lost response, start again with a new operation:
    /// the receipt of a lookup has no artifact.
    ///
    /// The application decides that the account can register: for example, a new account of an open sign-up. Add the
    /// reads of that decision to the proposal before you submit it.
    ///
    /// Cost class: [`Parse`](crate::limits::Class::Parse).
    ///
    /// # Errors
    ///
    /// [`Error::Name`] if a name of `user` is empty or longer than [`NAME_BYTES_MAX`]. [`Error::Time`] if the end of
    /// the record overflows. [`Error::Driver`] if the driver does not serve, and [`Error::Transition`] for the
    /// proposal.
    pub fn start(
        &self,
        user: &User<'_>,
        operation: OperationId,
        now: Reading,
        random: &mut ChaCha20Rng,
        driver: &mut Driver,
    ) -> Result<(Proposal, Plan), Error> {
        let (account, handle) = (user.account, &user.handle);
        name_valid(user.name)?;
        name_valid(user.display_name)?;
        let mut challenge = [0; 32];
        random.fill_bytes(&mut challenge);
        let key = pending_key(&challenge);
        let end = now
            .estimate()
            .checked_add(REGISTRATION_LIFETIME)
            .ok_or(Error::Time(TimeError::Overflow))?;
        let request = Value::Array(vec![Value::Text(&self.id), account.to_cbor(), Value::Bytes(&handle.0)]);
        let mut proposal = self.proposal(operation, account, START, &request, now)?;
        proposal.read(Dependency::Absent(key.clone()))?;
        let version = self.version(driver.allocate(Kind::Registration)?);
        let form = Value::Array(vec![
            Value::Text(PENDING_FORM),
            account.to_cbor(),
            Value::Bytes(&handle.0),
        ]);
        proposal.change(Change::Write {
            key: key.clone(),
            version: version.clone(),
            end: Some(end),
            data: encode(&form),
        })?;
        proposal.prepare(Prepared::new(self.options(user, &challenge), key, version))?;
        Ok((proposal, Plan::default()))
    }

    /// The options of `PublicKeyCredentialCreationOptionsJSON` for the challenge `challenge`.
    fn options(&self, user: &User<'_>, challenge: &[u8; 32]) -> Vec<u8> {
        // Each name can grow six times by its escapes. The rest is less than 1 KiB.
        let mut out = vec![0; 1024 + 6 * (self.id.len() + self.name.len() + user.name.len() + user.display_name.len())];
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
    pub fn verify(&self, response: &Response, challenge: &[u8; 32]) -> Result<Credential, Error> {
        response.client_data.check(challenge, &self.origin)?;
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
        let (rp_id_hash, rest) = data.split_first_chunk::<32>().ok_or(Error::Malformed)?;
        (*rp_id_hash == crypto::sha256(self.id.as_bytes())).ok_or(Error::RelyingParty)?;
        let (&[flags], rest) = rest.split_first_chunk::<1>().ok_or(Error::Malformed)?;
        (flags & USER_PRESENT != 0).ok_or(Error::UserPresence)?;
        (flags & USER_VERIFIED != 0).ok_or(Error::UserVerification)?;
        let backup_eligible = flags & BACKUP_ELIGIBLE != 0;
        let backup_state = flags & BACKUP_STATE != 0;
        ((backup_eligible || !backup_state) && flags & ATTESTED != 0).ok_or(Error::Malformed)?;
        let (count, rest) = rest.split_first_chunk::<4>().ok_or(Error::Malformed)?;
        let (_aaguid, rest) = rest.split_first_chunk::<16>().ok_or(Error::Malformed)?;
        let (length, rest) = rest.split_first_chunk::<2>().ok_or(Error::Malformed)?;
        let (id, rest) = rest
            .split_at_checked(usize::from(u16::from_be_bytes(*length)))
            .ok_or(Error::Malformed)?;
        (id.len() <= CREDENTIAL_ID_BYTES_MAX && *id == *response.id).ok_or(Error::CredentialId)?;
        let (key, extensions) = cbor::decode_prefix(rest, self.limits).map_err(|_| Error::Malformed)?;
        let public_key = &rest[..rest.len() - extensions.len()];
        if flags & EXTENSIONS == 0 {
            extensions.is_empty().ok_or(Error::Malformed)?;
        } else if !matches!(cbor::decode(extensions, self.limits), Ok(Value::Map(_))) {
            return Err(Error::Malformed);
        }
        let key = Key::from_value(&key).map_err(|error| match error {
            cose::Error::Unsupported | cose::Error::KeyAlgorithm => Error::Algorithm,
            _ => Error::Key,
        })?;
        let algorithm = key.alg.ok_or(Error::Algorithm)?;
        ALGORITHMS.contains(&algorithm).ok_or(Error::Algorithm)?;
        TrustedKey::new(algorithm, &key).map_err(|_| Error::Key)?;
        (response.discoverable != Some(false)).ok_or(Error::NotDiscoverable)?;
        Ok(Credential {
            id: id.into(),
            algorithm,
            public_key: public_key.into(),
            sign_count: u32::from_be_bytes(*count),
            backup_eligible,
            backup_state,
            transports: response.transports,
        })
    }

    /// Proposes the finish of the registration `response`, whose pending record is `pending`: the record at the key of
    /// [`Response::ceremony`]. The proposal consumes the pending record and writes the credential record, at the key
    /// of [`credential_key`]. Its plan names the passkey as a sign-in method of the account. Submit them, and give the
    /// browser the response of the outcome.
    ///
    /// The operation identity is the key of the pending record, so the same response under the same ceremony is the
    /// same operation: after a lost response, the browser sends it again, and the commit driver gives the first
    /// outcome. A second finish of the ceremony with another response refuses, and two concurrent finishes commit
    /// once. The deadline of the proposal is the end of the pending record.
    ///
    /// Cost class: [`Verify`](crate::limits::Class::Verify). The checks of [`Self::verify`].
    ///
    /// # Errors
    ///
    /// The errors of [`Self::verify`]. [`Error::Challenge`] if the pending record ended at `now`. [`Error::Record`]
    /// if `pending` has no valid form, [`Error::Time`] if `now` has no bound, [`Error::Driver`] if the driver does
    /// not serve, and [`Error::Transition`] for the proposal.
    pub fn finish(
        &self,
        response: &Response,
        pending: &Record,
        now: Reading,
        driver: &mut Driver,
    ) -> Result<(Proposal, Plan, Credential), Error> {
        let end = pending.end.ok_or(Error::Record)?;
        (now.latest().map_err(Error::Time)? < end).ok_or(Error::Challenge)?;
        let (account, handle) = pending_form(&pending.data, self.limits)?;
        let credential = self.verify(response, &response.client_data.challenge)?;
        let ceremony = response.ceremony();
        let key = credential_key(&credential.id);
        let request = Value::Array(vec![Value::Bytes(ceremony.as_bytes()), Value::Bytes(&credential.id)]);
        let operation = OperationId::new(ceremony.as_bytes())?;
        let mut proposal = self.proposal(operation, &account, REGISTER, &request, now)?;
        proposal.read(Dependency::Version(ceremony.clone(), pending.version.clone()))?;
        proposal.change(Change::End(ceremony))?;
        proposal.read(Dependency::Absent(key.clone()))?;
        proposal.change(Change::Write {
            key: key.clone(),
            version: self.version(driver.allocate(Kind::Credential)?),
            end: None,
            data: credential.record(&account, &handle),
        })?;
        proposal.until(end);
        let plan = Plan {
            anchors: vec![(key, Role::SignIn(account))],
            ..Plan::default()
        };
        Ok((proposal, plan, credential))
    }

    /// A proposal of `account` for `action` on `request`. Its request is `[relying party ID, request]`, so one
    /// operation identity under two relying parties of one store binds two requests.
    fn proposal(
        &self,
        operation: OperationId,
        account: &Id<Human>,
        action: &str,
        request: &Value<'_>,
        now: Reading,
    ) -> Result<Proposal, Error> {
        let audit = Audit {
            actor: Principal::Human(account.clone()),
            action: Id::<Action>::new("rsauthnz", action).expect("each action of this module is a valid identifier"),
            time: now,
        };
        let request = Value::Array(vec![Value::Text(&self.id), request.clone()]);
        Ok(Proposal::new(operation, audit, &request, self.limits)?)
    }

    /// The version of a write: the authority and `value`, a new value of a counter of the driver.
    fn version(&self, value: u64) -> AuthorityVersion {
        AuthorityVersion::new(self.authority.clone(), &value.to_be_bytes()).expect("an 8-byte coordinate is valid")
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
    /// not JSON of the type `webauthn.create` with a challenge of 32 bytes.
    pub fn parse(json: &[u8]) -> Result<Self, Error> {
        let mut scratch = [Slot::EMPTY; SLOTS];
        let fields = json::read(json, &RESPONSE, Rfc8259, &mut scratch, |reader| {
            let mut fields = Fields::default();
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
                    while let Some((name, value)) = members.next()? {
                        if name == "clientDataJSON" {
                            fields.client_data = Some(value.str()?);
                        } else if name == "attestationObject" {
                            fields.attestation = Some(value.str()?);
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
        .map_err(|_| Error::Malformed)?;
        let (Some(id), Some(raw_id), Some(kind), Some(client_data), Some(attestation)) = (
            fields.id,
            fields.raw_id,
            fields.kind,
            fields.client_data,
            fields.attestation,
        ) else {
            return Err(Error::Malformed);
        };
        (kind == "public-key").ok_or(Error::Malformed)?;
        let id = base64url(id)?;
        (id == base64url(raw_id)?).ok_or(Error::CredentialId)?;
        Ok(Self {
            id: id.into(),
            client_data: ClientData::parse(&base64url(client_data)?)?,
            attestation: base64url(attestation)?.into(),
            transports: fields.transports,
            discoverable: fields.discoverable,
        })
    }

    /// The key of the pending record of the ceremony of the response: [`Kind::Registration`] with the SHA-256 digest
    /// of its challenge. Read the record at this key, and give it to [`RelyingParty::finish`].
    ///
    /// Cost class: [`Parse`](crate::limits::Class::Parse).
    #[must_use]
    pub fn ceremony(&self) -> transition::Key {
        pending_key(&self.client_data.challenge)
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

/// The members of a response that the check reads, as the reader gives them.
#[derive(Default)]
struct Fields<'a> {
    id: Option<Str<'a>>,
    raw_id: Option<Str<'a>>,
    kind: Option<Str<'a>>,
    client_data: Option<Str<'a>>,
    attestation: Option<Str<'a>>,
    transports: u8,
    discoverable: Option<bool>,
}

/// The members of `clientDataJSON` that the check reads.
struct ClientData {
    challenge: [u8; 32],
    origin: String,
    /// Whether the ceremony ran in a frame of another origin: `crossOrigin` is true, or `topOrigin` is present.
    cross_origin: bool,
}

impl ClientData {
    /// Reads the `clientDataJSON` text `json` of a registration.
    fn parse(json: &[u8]) -> Result<Self, Error> {
        let mut scratch = [Slot::EMPTY; SLOTS];
        let (kind, challenge, origin, cross_origin) = json::read(json, &CLIENT_DATA, Rfc8259, &mut scratch, |reader| {
            let (mut kind, mut challenge, mut origin, mut cross_origin) = (None, None, None, false);
            let mut members = reader.value().members()?;
            while let Some((name, value)) = members.next()? {
                if name == "type" {
                    kind = Some(value.str()?);
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
            Ok((kind, challenge, origin, cross_origin))
        })
        .map_err(|_| Error::Malformed)?;
        let (Some(kind), Some(challenge), Some(origin)) = (kind, challenge, origin) else {
            return Err(Error::Malformed);
        };
        (kind == "webauthn.create").ok_or(Error::Malformed)?;
        let challenge = <[u8; 32]>::try_from(base64url(challenge)?).map_err(|_| Error::Malformed)?;
        let mut text = vec![0; origin.len()];
        let origin = origin.decode(&mut text).map_err(|_| Error::Malformed)?.into();
        Ok(Self {
            challenge,
            origin,
            cross_origin,
        })
    }

    /// Checks the challenge, the origin, and the frame.
    fn check(&self, challenge: &[u8; 32], origin: &str) -> Result<(), Error> {
        (self.challenge == *challenge).ok_or(Error::Challenge)?;
        (self.origin == origin).ok_or(Error::Origin)?;
        (!self.cross_origin).ok_or(Error::CrossOrigin)
    }
}

/// A registered passkey: what the check of a registration proved, and the record of the credential.
#[derive(Clone, PartialEq, Eq)]
pub struct Credential {
    id: Box<[u8]>,
    algorithm: Algorithm,
    /// The `COSE_Key` of the authenticator data, in its exact bytes.
    public_key: Box<[u8]>,
    sign_count: u32,
    backup_eligible: bool,
    backup_state: bool,
    /// The transports of the response, one bit for each one that [`transport`] knows.
    transports: u8,
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

    /// Whether the authenticator can back up the credential (the BE flag): a synchronized passkey.
    #[must_use]
    pub const fn backup_eligible(&self) -> bool {
        self.backup_eligible
    }

    /// Whether the authenticator has backed up the credential (the BS flag).
    #[must_use]
    pub const fn backup_state(&self) -> bool {
        self.backup_state
    }

    /// The binding of the key that the authenticator reports: [`Binding::Device`] for a credential that it cannot
    /// back up, and `None` for a synchronized one. No credential reports [`Binding::Hardware`]: only an attestation
    /// could prove it, and the profile asks for none.
    #[must_use]
    pub const fn binding(&self) -> Option<Binding> {
        if self.backup_eligible {
            None
        } else {
            Some(Binding::Device)
        }
    }

    /// The record form: `["rsauthnz.passkey.credential.1", account, user handle, credential ID, COSE key, COSE
    /// algorithm, signature counter, backup eligible, backup state, transports]`.
    fn record(&self, account: &Id<Human>, handle: &UserHandle) -> Box<[u8]> {
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
            Value::Bool(self.backup_eligible),
            Value::Bool(self.backup_state),
            Value::Unsigned(u64::from(self.transports)),
        ]))
    }
}

impl fmt::Debug for Credential {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("Credential")
            .field("id", &self.id.len())
            .field("algorithm", &self.algorithm)
            .field("sign_count", &self.sign_count)
            .field("backup_eligible", &self.backup_eligible)
            .field("backup_state", &self.backup_state)
            .finish_non_exhaustive()
    }
}

/// The key of the record of the credential `id`: [`Kind::Credential`] with the SHA-256 digest of the ID. The digest
/// has 32 bytes, so no key of a credential of this crate (an 8-byte serial) is equal to it.
///
/// Cost class: [`Parse`](crate::limits::Class::Parse).
#[must_use]
pub fn credential_key(id: &[u8]) -> transition::Key {
    Kind::Credential
        .key(&crypto::sha256(id))
        .expect("a key of 33 bytes is valid")
}

/// The key of the pending record of the challenge `challenge`.
fn pending_key(challenge: &[u8; 32]) -> transition::Key {
    Kind::Registration
        .key(&crypto::sha256(challenge))
        .expect("a key of 33 bytes is valid")
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

/// The bit of the transport `name`, or zero for a transport that this crate does not know.
fn transport(name: Str<'_>) -> u8 {
    ["usb", "nfc", "ble", "smart-card", "hybrid", "internal"]
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
fn name_valid(name: &str) -> Result<(), Error> {
    (1..=NAME_BYTES_MAX).contains(&name.len()).ok_or(Error::Name)
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
fn encode(form: &Value<'_>) -> Box<[u8]> {
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
    /// The origin of `clientDataJSON` is not the origin of the site.
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
    /// A record has no valid form.
    Record,
    /// The time reading has no bound, or a time overflows.
    Time(TimeError),
    /// The commit driver gave no value.
    Driver(driver::Error),
    /// The proposal refuses.
    Transition(transition::Error),
}

impl Error {
    /// The recovery of the caller: start a new ceremony after [`Error::Challenge`], and the recovery of the proposal
    /// after [`Error::Transition`]. Refuse each other request.
    #[must_use]
    pub const fn recovery(&self) -> Recovery {
        match self {
            Self::Challenge => Recovery::Restart,
            Self::Transition(error) => error.recovery(),
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
            Self::Origin => f.write_str("the origin of the response is not the origin of the site"),
            Self::CrossOrigin => f.write_str("the ceremony ran in a frame of another origin"),
            Self::UserPresence => f.write_str("the authenticator did not report the presence of the user"),
            Self::UserVerification => f.write_str("the authenticator did not verify the user"),
            Self::Algorithm => f.write_str("the credential key has an algorithm outside the profile"),
            Self::Key => f.write_str("the credential key is not valid"),
            Self::CredentialId => f.write_str("the credential ID is too long or not consistent"),
            Self::NotDiscoverable => f.write_str("the credential is not discoverable"),
            Self::Record => f.write_str("a record has no valid form"),
            Self::Time(error) => write!(f, "the time reading gave no value: {error}"),
            Self::Driver(error) => write!(f, "the commit driver gave no value: {error}"),
            Self::Transition(error) => write!(f, "the proposal refuses: {error}"),
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
