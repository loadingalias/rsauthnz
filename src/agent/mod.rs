//! Agent identities: an agent enrolls its own key, and its human owner approves the enrollment in a browser, in the
//! shape of OAuth device authorization ([RFC 8628](https://www.rfc-editor.org/rfc/rfc8628)).
//!
//! An agent keeps its key in custody, and it never receives the session or a credential of its owner. Each step is a
//! call of [`Agents`]:
//!
//! 1. The agent stores its key in custody, then asks for an enrollment with its public key and a name
//!    ([`Agents::enroll`]). The commit writes the request. The agent gets its agent identifier and a [`UserCode`] at
//!    once, and its [`DeviceCode`] from the artifact of the accepted commit. A local agent also gives a
//!    [`Loopback`] address, and it opens the approval page in a browser.
//! 2. The human signs in with a passkey and gives the user code. The approval page shows the name and the key
//!    fingerprint of the agent ([`Agents::request`]). The human approves with a fresh user verification
//!    ([`Agents::approve`]). The commit writes the request as approved by the account of the human. For a loopback
//!    request, the browser then goes to the loopback address with a one-use [`RedirectCode`]. Each of the two steps is
//!    a check of the user code: commit its proposal, then take its answer from the outcome ([`Checked::release`]).
//! 3. The agent asks for its finish with its device code, and for a loopback request also with the redirect code
//!    ([`Agents::finish`]). Until the approval, the answer is [`Status::Waiting`]. Then one commit consumes the request
//!    and writes the agent identity, bound to the account of the approval.
//!
//! The owner comes only from the approval: no field of a request names it. A user code finds its request by its first
//! 4 letters and checks the last 4. Each check is a commit at the version of the request, and a wrong check counts.
//! Thus of the checks that read one version, only one gives an answer, and [`ATTEMPTS_MAX`] wrong checks lock the
//! request. A loopback request finishes only with the redirect code, which goes only to the browser of the
//! human that approved. So a human who approves the request of a remote agent by mistake binds no key: the remote
//! agent never gets the redirect code.
//!
//! A hosted agent can ask with the identity of its workload in place of a pasted secret: a JWT workload identity token
//! of a configured [`Platform`], such as a JWT-SVID, or a workload credential of this library ([`Workload`]). The
//! request keeps the verified workload, and the approval page shows it. The workload names no owner: the human still
//! approves, and the owner comes only from the approval.
//!
//! An agent rotates its key with signatures by its current key and by its new key ([`Agents::rotate`]). The owner
//! revokes the agent from a session ([`Agents::revoke`]), and the commit ends the identity. No operation changes the
//! owner of an identity: the owner revokes it, and a new enrollment gives a new agent identifier. The audit of each
//! earlier commit keeps the earlier owner.
//!
//! An agent identity is not an authority anchor. A restore ends each pending request, and a restore from a snapshot
//! before an enrollment loses the identity: the agent enrolls again. The restore journal keeps each rotation and each
//! revocation, so no restore gives a revoked identity or an earlier key again. [`Agents::identity`] gives the current
//! identity of an agent, with its owner and its key.

use alloc::boxed::Box;
use alloc::string::String;
use alloc::vec;
use alloc::vec::Vec;
use core::fmt;
use core::time::Duration;

use rscodec::base64::Profile::Url;
use rscodec::json::{self, Profile::Rfc8259, Slot, Str};
use rscrypto::{ChaCha20Rng, SecretBytes};

use crate::account::{Fresh, generation::Epoch};
use crate::cbor::{self, Value};
use crate::crypto;
use crate::id::{Agent, Authority, AuthorityVersion, Human, Id, Principal};
use crate::limits::{Limits, SignatureBudget};
use crate::session::Access;
use crate::store::driver::Plan;
use crate::store::{Kind, Record, Store};
use crate::time::{Reading, TimeError};
use crate::transition::{
    self, Audit, Change, Dependency, Key, OperationId, Outcome, Prepared, Proposal, Recover, Recovery,
};
use crate::{credential, grant, jose, trust};

mod hosted;

pub use hosted::{Binding, Bootstrap, Platform, WORKLOAD_BYTES_MAX, Workload};

/// The lifetime of an enrollment request: 10 minutes. An approval gives the agent the same time again to finish.
pub const ENROLLMENT_LIFETIME: Duration = Duration::from_secs(10 * 60);

/// The time from one finish of a waiting request to the next one.
pub const POLL_INTERVAL: Duration = Duration::from_secs(5);

/// The most bytes of the name of an agent, which the approval page shows.
pub const NAME_BYTES_MAX: usize = 64;

/// The most bytes of a loopback address.
pub const LOOPBACK_BYTES_MAX: usize = 128;

/// The number of wrong checks of a user code that locks its request.
pub const ATTEMPTS_MAX: u64 = 5;

/// The bytes of the public key of an agent: a composite ML-DSA-65 + Ed25519 key.
pub const KEY_BYTES: usize = 1984;

/// The most bytes of a JSON body of an agent. The base64url of its key is 2,646 bytes, of a workload credential and of
/// its proof at most 10,923 bytes each, and a token has at most [`jose::TOKEN_BYTES_MAX`] bytes.
pub const BODY_BYTES_MAX: usize = BODY.input_bytes_max as usize;

/// The limits of a JSON body of an agent.
const BODY: json::Limits = json::Limits {
    input_bytes_max: 32 * 1024,
    depth_max: 1,
    // A token has at most `jose::TOKEN_BYTES_MAX` bytes.
    string_bytes_max: 16 * 1024,
    members_max: 8,
    elements_max: 0,
    number_digits_max: 0,
};

/// The slots of the reader: one object, and each of its keys.
const SLOTS: usize = 1 + 8;

/// The first item of each CBOR form of this module. The number changes with the form.
const REQUEST_FORM: &str = "rsauthnz.agent.enrollment.2";
const AGENT_FORM: &str = "rsauthnz.agent.2";
const ROTATION_FORM: &str = "rsauthnz.agent.rotation.1";

/// The actions of the audit records.
const REQUEST: &str = "agent.request";
const CHECK: &str = "agent.code";
const APPROVE: &str = "agent.approve";
const ENROLL: &str = "agent.enroll";
const ROTATE: &str = "agent.rotate";
const REVOKE: &str = "agent.revoke";

/// The letters of a user code: the base20 alphabet of RFC 8628, section 6.1, with no vowel, so no code spells a word.
const LETTERS: &[u8; 20] = b"BCDFGHJKLMNPQRSTVWXZ";

/// The user code of an enrollment request of an agent or of a CLI ([`crate::local::enroll`]): 8 letters of the base20
/// alphabet of RFC 8628. The agent shows it as `WDJB-MJHT`, and the human gives it to the approval page. The first 4
/// letters find the request, and the last 4 check it: a wrong check counts against [`ATTEMPTS_MAX`]. `Debug` does not
/// show it.
#[derive(Clone, Copy, PartialEq, Eq)]
pub struct UserCode([u8; 8]);

impl UserCode {
    /// Reads a user code: 8 letters of the alphabet in either case, with each `-` and space ignored.
    ///
    /// Cost class: [`Parse`](crate::limits::Class::Parse).
    ///
    /// # Errors
    ///
    /// [`Error::Request`] for another text: no request has it.
    pub fn parse(text: &str) -> Result<Self, Error> {
        let mut code = [0; 8];
        let mut letters = text.bytes().filter(|byte| !matches!(byte, b'-' | b' '));
        for slot in &mut code {
            let letter = letters.next().ok_or(Error::Request)?.to_ascii_uppercase();
            LETTERS.contains(&letter).ok_or(Error::Request)?;
            *slot = letter;
        }
        letters.next().is_none().ok_or(Error::Request)?;
        Ok(Self(code))
    }

    /// The text of the code: two groups of 4 letters, such as `WDJB-MJHT`.
    #[must_use]
    pub fn text(&self) -> String {
        let (head, tail) = self.0.split_at(4);
        [head, b"-", tail].concat().into_iter().map(char::from).collect()
    }

    /// A new code from `random`. A byte at or past 240 is drawn again, so each letter has the same chance.
    pub(crate) fn random(random: &mut ChaCha20Rng) -> Self {
        let mut code = [0; 8];
        for slot in &mut code {
            *slot = loop {
                let mut byte = [0];
                random.fill_bytes(&mut byte);
                if byte[0] < 240 {
                    break LETTERS[usize::from(byte[0] % 20)];
                }
            };
        }
        Self(code)
    }

    /// The letters that find the request.
    pub(crate) fn locator(&self) -> &[u8; 4] {
        self.0.first_chunk().expect("a code has 8 letters")
    }

    /// The letters that check the request.
    pub(crate) fn check(&self) -> &[u8; 4] {
        self.0.last_chunk().expect("a code has 8 letters")
    }
}

impl fmt::Debug for UserCode {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("UserCode(..)")
    }
}

/// A one-use secret of 32 random bytes. `Debug` does not show it, and its memory is cleared when it drops. The store
/// keeps only its SHA-256 digest.
macro_rules! secret {
    ($(#[$doc:meta])* $name:ident) => {
        $(#[$doc])*
        pub struct $name(SecretBytes<32>);

        impl $name {
            /// The code of `bytes`, such as the artifact of an accepted commit.
            ///
            /// Cost class: [`Parse`](crate::limits::Class::Parse).
            #[must_use]
            pub fn from_bytes(bytes: [u8; 32]) -> Self {
                let Ok(secret) = SecretBytes::try_fill_with(|secret| {
                    secret.copy_from_slice(&bytes);
                    Ok::<_, !>(())
                });
                Self(secret)
            }

            /// The bytes of the code.
            #[must_use]
            pub fn as_bytes(&self) -> &[u8; 32] {
                self.0.as_bytes()
            }

            /// The SHA-256 digest of the code, which the request record keeps.
            pub(crate) fn digest(&self) -> [u8; 32] {
                crypto::sha256(self.0.as_bytes())
            }
        }

        impl fmt::Debug for $name {
            fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
                f.write_str(concat!(stringify!($name), "(..)"))
            }
        }
    };
}

secret! {
    /// The device code of an enrollment request of an agent or of a CLI: only the agent or the CLI holds it, and it
    /// gives it with each poll and finish.
    DeviceCode
}

secret! {
    /// The redirect code of an approved loopback request. The browser of the human that approved takes it to the
    /// loopback address, and the agent gives it with its finish. Alone it admits nothing: the finish also needs the
    /// device code.
    RedirectCode
}

/// The loopback address of a local agent ([RFC 8252, section 7.3](https://www.rfc-editor.org/rfc/rfc8252#section-7.3)):
/// `http://127.0.0.1:<port>/<path>` or `http://[::1]:<port>/<path>`, with at most [`LOOPBACK_BYTES_MAX`] bytes. The
/// path has only letters, digits, `-`, `.`, `_`, `~`, and `/`, so it has no query and no fragment. The name
/// `localhost` is not valid: a resolver can give another address.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Loopback(Box<str>);

impl Loopback {
    /// Reads a loopback address.
    ///
    /// Cost class: [`Parse`](crate::limits::Class::Parse).
    ///
    /// # Errors
    ///
    /// [`Error::Loopback`] for another text.
    pub fn parse(text: &str) -> Result<Self, Error> {
        (text.len() <= LOOPBACK_BYTES_MAX).ok_or(Error::Loopback)?;
        let rest = text
            .strip_prefix("http://127.0.0.1:")
            .or_else(|| text.strip_prefix("http://[::1]:"))
            .ok_or(Error::Loopback)?;
        let (port, path) = rest.split_once('/').ok_or(Error::Loopback)?;
        let port_valid = (1..=5).contains(&port.len())
            && !port.starts_with('0')
            && port.bytes().all(|byte| byte.is_ascii_digit())
            && port.parse::<u16>().is_ok();
        let path_valid = path
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || b"-._~/".contains(&byte));
        (port_valid && path_valid).ok_or(Error::Loopback)?;
        Ok(Self(text.into()))
    }

    /// The text of the address.
    #[must_use]
    pub fn as_str(&self) -> &str {
        &self.0
    }

    /// The address that the browser goes to after the approval: the loopback address with the query `code=` and the
    /// base64url of `code`.
    ///
    /// Cost class: [`Parse`](crate::limits::Class::Parse).
    #[must_use]
    pub fn redirect(&self, code: &RedirectCode) -> String {
        let mut out = [0; 43];
        let encoded = Url
            .encode(code.as_bytes(), &mut out)
            .expect("32 bytes have 43 base64url characters");
        let encoded = core::str::from_utf8(encoded).expect("base64url is ASCII");
        [&*self.0, "?code=", encoded].concat()
    }
}

/// The enrollment of agents under one authority: its requests, approvals, and agent identities. The authority
/// separates the records of two sites in one store, and its namespace is the namespace of each agent identifier.
#[derive(Clone, Debug)]
pub struct Agents {
    authority: Id<Authority>,
    limits: Limits,
}

/// A new enrollment request, as the agent gets it at once ([`Agents::enroll`]).
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Started {
    /// The user code. The agent shows it, and for a loopback request it also puts it into the address of the approval
    /// page that it opens.
    pub code: UserCode,
    /// The identifier of the agent after its finish. Keep it: [`Agents::identity`] reads the agent by it.
    pub agent: Id<Agent>,
}

impl Started {
    /// The JSON body of the answer to the agent, in the shape of a device authorization response (RFC 8628, section
    /// 3.2): `{"agent","user_code","device_code","verification_uri","verification_uri_complete","expires_in",
    /// "interval"}`. `verification` is the address of the approval page, with no query: the complete address adds the
    /// query `code=` and the user code. The device code is base64url.
    ///
    /// Cost class: [`Parse`](crate::limits::Class::Parse).
    #[must_use]
    pub fn json(&self, device: &DeviceCode, verification: &str) -> Vec<u8> {
        let code = self.code.text();
        let complete = [verification, "?code=", &code].concat();
        // Each string can grow six times by its escapes. The rest is less than 512 bytes.
        let mut out = vec![0; 512 + 6 * (verification.len() + complete.len())];
        let len = json::write(&mut out, |place| {
            place.object(|body| {
                body.member("agent").str(&self.agent.to_string())?;
                body.member("user_code").str(&code)?;
                body.member("device_code").base64url(device.as_bytes())?;
                body.member("verification_uri").str(verification)?;
                body.member("verification_uri_complete").str(&complete)?;
                body.member("expires_in").u64(ENROLLMENT_LIFETIME.as_secs())?;
                body.member("interval").u64(POLL_INTERVAL.as_secs())
            })
        })
        .expect("the body fits its buffer");
        out.truncate(len);
        out
    }
}

/// The JSON body of an enrollment request of an agent: `{"name","key","loopback","token","credential","proof"}`, with
/// the base64url of the key, an optional loopback address, and for a hosted agent either a token, or the base64url of a
/// workload credential and of its proof. The reader ignores each other member, so a member that names an owner names
/// none.
#[derive(Debug)]
pub struct Enrollment {
    /// The public key of the agent.
    pub key: Box<[u8; KEY_BYTES]>,
    /// The name of the agent. [`Agents::enroll`] checks it.
    pub name: String,
    /// The loopback address of a local agent.
    pub loopback: Option<Loopback>,
    /// The workload identity of a hosted agent, which the host checks before [`Agents::enroll`].
    pub bootstrap: Option<Bootstrap>,
}

impl Enrollment {
    /// Reads the body `json`, of at most [`BODY_BYTES_MAX`] bytes.
    ///
    /// Cost class: [`Parse`](crate::limits::Class::Parse).
    ///
    /// # Errors
    ///
    /// [`Error::Malformed`] if `json` is not a JSON object with a name and a key of [`KEY_BYTES`] bytes, or is longer
    /// than its bound, or has a token with a credential or a proof, or a credential with no proof or a proof with no
    /// credential. [`Error::Loopback`] if the loopback address is not valid.
    pub fn parse(json: &[u8]) -> Result<Self, Error> {
        let [name, key, loopback, token, credential, proof] =
            members(json, ["name", "key", "loopback", "token", "credential", "proof"])?;
        let key = base64url(&key.ok_or(Error::Malformed)?)?;
        let bootstrap = match (token, credential, proof) {
            (None, None, None) => None,
            (Some(token), None, None) => Some(Bootstrap::Token(token)),
            (None, Some(credential), Some(proof)) => Some(Bootstrap::Credential {
                credential: base64url(&credential)?,
                proof: base64url(&proof)?,
            }),
            _ => return Err(Error::Malformed),
        };
        Ok(Self {
            key: Box::new(key.as_slice().try_into().map_err(|_| Error::Malformed)?),
            name: name.ok_or(Error::Malformed)?,
            loopback: loopback.as_deref().map(Loopback::parse).transpose()?,
            bootstrap,
        })
    }
}

/// The JSON body of a finish of an agent: `{"user_code","device_code","redirect_code"}`, with the base64url of each
/// code, and the redirect code only for a loopback request. `Debug` shows no code.
#[derive(Debug)]
pub struct Finish {
    /// The user code of the request.
    pub code: UserCode,
    /// The device code of the request.
    pub device: DeviceCode,
    /// The redirect code that the browser brought to the loopback address.
    pub redirect: Option<RedirectCode>,
}

impl Finish {
    /// Reads the body `json`, of at most [`BODY_BYTES_MAX`] bytes.
    ///
    /// Cost class: [`Parse`](crate::limits::Class::Parse).
    ///
    /// # Errors
    ///
    /// [`Error::Malformed`] if `json` is not a JSON object with a user code and a device code, or a code is not 32
    /// bytes. [`Error::Request`] if the user code is not one of the alphabet.
    pub fn parse(json: &[u8]) -> Result<Self, Error> {
        let [code, device, redirect] = members(json, ["user_code", "device_code", "redirect_code"])?;
        let secret = |text: &str| -> Result<[u8; 32], Error> {
            base64url(text)?.as_slice().try_into().map_err(|_| Error::Malformed)
        };
        Ok(Self {
            code: UserCode::parse(&code.ok_or(Error::Malformed)?)?,
            device: DeviceCode::from_bytes(secret(&device.ok_or(Error::Malformed)?)?),
            redirect: redirect
                .as_deref()
                .map(secret)
                .transpose()?
                .map(RedirectCode::from_bytes),
        })
    }
}

/// The JSON body of a rotation of the key of an agent: `{"agent","key","old_signature","new_signature"}`, with the text
/// form of the agent identifier, the base64url of the new public key, and the base64url of the signatures of the
/// rotation statement ([`Rotation::statement`]) by the current key and by the new key. The reader ignores each other
/// member, so a member that names an owner names none.
#[derive(Debug)]
pub struct Rotation {
    /// The agent.
    pub agent: Id<Agent>,
    /// The new public key of the agent.
    pub key: Box<[u8; KEY_BYTES]>,
    /// The signature of the statement by the current key.
    pub old_signature: Vec<u8>,
    /// The signature of the statement by the new key.
    pub new_signature: Vec<u8>,
}

impl Rotation {
    /// Reads the body `json`, of at most [`BODY_BYTES_MAX`] bytes.
    ///
    /// Cost class: [`Parse`](crate::limits::Class::Parse).
    ///
    /// # Errors
    ///
    /// [`Error::Malformed`] if `json` is not a JSON object with an agent identifier, a key of [`KEY_BYTES`] bytes, and
    /// two signatures, or is longer than its bound.
    pub fn parse(json: &[u8]) -> Result<Self, Error> {
        let [agent, key, old, new] = members(json, ["agent", "key", "old_signature", "new_signature"])?;
        let agent = agent.ok_or(Error::Malformed)?;
        let (namespace, value) = agent.split_once(':').ok_or(Error::Malformed)?;
        let key = base64url(&key.ok_or(Error::Malformed)?)?;
        Ok(Self {
            agent: Id::new(namespace, value).map_err(|_| Error::Malformed)?,
            key: Box::new(key.as_slice().try_into().map_err(|_| Error::Malformed)?),
            old_signature: base64url(&old.ok_or(Error::Malformed)?)?,
            new_signature: base64url(&new.ok_or(Error::Malformed)?)?,
        })
    }

    /// The statement that the current key `old` and the new key `new` of `agent` each sign for the rotation from the
    /// key generation `generation` ([`Identity::generation`]): the canonical CBOR form `["rsauthnz.agent.rotation.1",
    /// agent, old, new, generation]`, with the SHA-256 digest of each key. Each rotation raises the generation, so a
    /// statement of an earlier generation never matches again, also after a rotation back to an earlier key.
    ///
    /// Cost class: [`Parse`](crate::limits::Class::Parse).
    #[must_use]
    pub fn statement(agent: &Id<Agent>, old: &[u8; KEY_BYTES], new: &[u8; KEY_BYTES], generation: u64) -> Vec<u8> {
        encode(&[
            Value::Text(ROTATION_FORM),
            agent.to_cbor(),
            Value::Bytes(&crypto::sha256(old)),
            Value::Bytes(&crypto::sha256(new)),
            Value::Unsigned(generation),
        ])
    }
}

/// The string members `names` of the JSON object `json`, in order. The reader ignores each other member.
fn members<const N: usize>(json: &[u8], names: [&str; N]) -> Result<[Option<String>; N], Error> {
    let mut scratch = [Slot::EMPTY; SLOTS];
    json::read(json, &BODY, Rfc8259, &mut scratch, |reader| {
        let mut found = [const { None }; N];
        let mut members = reader.value().members()?;
        while let Some((name, value)) = members.next()? {
            if let Some(at) = names.iter().position(|known| name == *known) {
                found[at] = Some(text(value.str()?)?);
            }
        }
        Ok(found)
    })
    .map_err(|_| Error::Malformed)
}

/// The text of a JSON string, with its escapes read.
fn text(value: Str<'_>) -> Result<String, json::Error> {
    let mut out = vec![0; value.len()];
    Ok(value.decode(&mut out)?.into())
}

/// The bytes of the base64url text `text`, with no padding.
fn base64url(text: &str) -> Result<Vec<u8>, Error> {
    let mut out = vec![0; Url.decoded_len(text.as_bytes()).map_err(|_| Error::Malformed)?];
    Url.decode(text.as_bytes(), &mut out).map_err(|_| Error::Malformed)?;
    Ok(out)
}

/// An enrollment request, as the approval page shows it to a signed-in human ([`Agents::request`]).
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Request {
    /// The name that the agent gave, such as `build-agent`. Show it as text, never as markup.
    pub name: String,
    /// The SHA-256 digest of the public key of the agent. The agent shows the same digest, so the human can compare
    /// them.
    pub fingerprint: [u8; 32],
    /// The loopback address of a local agent, or `None` for an agent that finishes with its device code alone.
    pub loopback: Option<Loopback>,
    /// The verified workload of a hosted agent, or `None` for an agent that gave none. Show it as text.
    pub workload: Option<Workload>,
    /// The time of the request, as the time since the Unix epoch.
    pub created: Duration,
    /// The end of the request, as the time since the Unix epoch.
    pub ends: Duration,
    /// Whether an account approved the request.
    pub approved: bool,
}

/// The answer of a check of a user code, which the commit of its proposal releases ([`Self::release`]). The proposal
/// reads the request at its version and writes its next version, and for a wrong code it counts the wrong check. Thus
/// of the checks that read one version, one commits and each other conflicts, so each answer costs one commit, also
/// for checks at the same time.
#[derive(Debug)]
pub struct Checked<T> {
    operation: OperationId,
    answer: Option<T>,
}

impl<T> Checked<T> {
    /// The check of `proposal`, with `answer` for a right code, or `None` for a wrong one.
    pub(crate) fn new(proposal: &Proposal, answer: Option<T>) -> Self {
        Self {
            operation: proposal.operation().id.clone(),
            answer,
        }
    }

    /// The answer of a right code, if `outcome` is the accepted commit of the proposal of this check, also the receipt
    /// of a lookup of its operation after a lost response. `None` for a wrong code, and for each other outcome: show
    /// nothing of the request, and tell the human to give the code again.
    ///
    /// Cost class: [`Parse`](crate::limits::Class::Parse).
    #[must_use]
    pub fn release(self, outcome: &Outcome) -> Option<T> {
        let Outcome::Accepted(receipt) = outcome else {
            return None;
        };
        (*receipt.operation() == self.operation)
            .then_some(self.answer)
            .flatten()
    }
}

/// The state of an enrollment request for its agent ([`Agents::finish`]).
#[derive(Debug)]
#[expect(
    clippy::large_enum_variant,
    reason = "the caller matches the status at once, as it takes `(Proposal, Plan)` from each other operation; a box adds an allocation to each finish"
)]
pub enum Status {
    /// No account approved the request yet. Ask again after [`POLL_INTERVAL`].
    Waiting,
    /// An account approved the request. The commit of the proposal consumes the request and writes the agent identity.
    Approved(Proposal, Plan),
}

/// A current agent identity ([`Agents::identity`]).
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Identity {
    /// The identifier of the agent.
    pub agent: Id<Agent>,
    /// The human owner: the account of the approval.
    pub owner: Id<Human>,
    /// The public key of the agent: a composite ML-DSA-65 + Ed25519 key.
    pub key: Box<[u8; KEY_BYTES]>,
    /// The name that the agent gave at its request.
    pub name: String,
    /// The verified workload of the request of a hosted agent, or `None`.
    pub workload: Option<Workload>,
    /// The time of the finish, as the time since the Unix epoch.
    pub created: Duration,
    /// The generation of the key: 1 at the enrollment, and 1 more for each rotation. The next rotation statement names
    /// it ([`Rotation::statement`]).
    pub generation: u64,
    /// The version of the identity record. A rotation writes a new one, and a revocation ends the record.
    pub version: AuthorityVersion,
}

impl Identity {
    /// The JSON body of the answer to the finish or to a rotation of the agent: `{"agent","owner","generation"}`, the
    /// text form of each identifier and the generation of the key.
    ///
    /// Cost class: [`Parse`](crate::limits::Class::Parse).
    #[must_use]
    pub fn json(&self) -> Vec<u8> {
        let (agent, owner) = (self.agent.to_string(), self.owner.to_string());
        let mut out = vec![0; 96 + 6 * (agent.len() + owner.len())];
        let len = json::write(&mut out, |place| {
            place.object(|body| {
                body.member("agent").str(&agent)?;
                body.member("owner").str(&owner)?;
                body.member("generation").u64(self.generation)
            })
        })
        .expect("the body fits its buffer");
        out.truncate(len);
        out
    }

    /// The record form: `["rsauthnz.agent.2", owner, key, name, created, workload]`, with `created` in whole seconds
    /// and `workload` its issuer and its subject, or null.
    fn form(&self) -> Box<[u8]> {
        encode(&[
            Value::Text(AGENT_FORM),
            self.owner.to_cbor(),
            Value::Bytes(&*self.key),
            Value::Text(&self.name),
            Value::Unsigned(self.created.as_secs()),
            workload_form(self.workload.as_ref()),
        ])
        .into_boxed_slice()
    }

    /// The identity of `agent` in the record `record`, or `None` for another form within `limits`. The generation is
    /// the count of the version.
    fn parse(agent: &Id<Agent>, record: &Record, limits: Limits) -> Option<Self> {
        let value = cbor::decode(&record.data, limits).ok()?;
        let Value::Array(items) = &value else {
            return None;
        };
        let [
            Value::Text(AGENT_FORM),
            owner,
            Value::Bytes(key),
            Value::Text(name),
            Value::Unsigned(created),
            workload,
        ] = items.as_slice()
        else {
            return None;
        };
        Some(Self {
            agent: agent.clone(),
            owner: Id::from_cbor(owner).ok()?,
            key: Box::new((*key).try_into().ok()?),
            name: (*name).into(),
            workload: workload_parse(workload)?,
            created: Duration::from_secs(*created),
            generation: u64::from_be_bytes(*record.version.coordinate().first_chunk::<8>()?),
            version: record.version.clone(),
        })
    }
}

/// An enrollment request record: `["rsauthnz.agent.enrollment.2", check, device, agent, key, name, created, loopback,
/// attempts, approved, workload]`. `check` is the last 4 letters of the user code, `device` the SHA-256 digest of the
/// device code, `created` the time of the request in whole seconds, `loopback` the loopback address or null,
/// `attempts` the number of wrong checks, `approved` the account, its revision, and the digest of the redirect code
/// (or null), or null, and `workload` its issuer and its subject, or null.
struct Pending {
    check: [u8; 4],
    device: [u8; 32],
    agent: Id<Agent>,
    key: Box<[u8; KEY_BYTES]>,
    name: String,
    created: u64,
    loopback: Option<Loopback>,
    attempts: u64,
    approved: Option<(Id<Human>, Epoch, Option<[u8; 32]>)>,
    workload: Option<Workload>,
}

impl Pending {
    /// The record form.
    fn form(&self) -> Box<[u8]> {
        let approved = self.approved.as_ref().map_or(Value::Null, |(owner, epoch, redirect)| {
            Value::Array(vec![
                owner.to_cbor(),
                epoch.form(),
                redirect.as_ref().map_or(Value::Null, |digest| Value::Bytes(digest)),
            ])
        });
        encode(&[
            Value::Text(REQUEST_FORM),
            Value::Bytes(&self.check),
            Value::Bytes(&self.device),
            self.agent.to_cbor(),
            Value::Bytes(&*self.key),
            Value::Text(&self.name),
            Value::Unsigned(self.created),
            self.loopback
                .as_ref()
                .map_or(Value::Null, |loopback| Value::Text(loopback.as_str())),
            Value::Unsigned(self.attempts),
            approved,
            workload_form(self.workload.as_ref()),
        ])
        .into_boxed_slice()
    }

    /// The request of the record `record`, or `None` for another form within `limits`.
    fn parse(record: &Record, limits: Limits) -> Option<Self> {
        let value = cbor::decode(&record.data, limits).ok()?;
        let Value::Array(items) = &value else {
            return None;
        };
        let [
            Value::Text(REQUEST_FORM),
            Value::Bytes(check),
            Value::Bytes(device),
            agent,
            Value::Bytes(key),
            Value::Text(name),
            Value::Unsigned(created),
            loopback,
            Value::Unsigned(attempts),
            approved,
            workload,
        ] = items.as_slice()
        else {
            return None;
        };
        let loopback = match loopback {
            Value::Null => None,
            Value::Text(text) => Some(Loopback::parse(text).ok()?),
            _ => return None,
        };
        let approved = match approved {
            Value::Null => None,
            Value::Array(items) => {
                let [owner, epoch, redirect] = items.as_slice() else {
                    return None;
                };
                let redirect = match redirect {
                    Value::Null => None,
                    Value::Bytes(digest) => Some((*digest).try_into().ok()?),
                    _ => return None,
                };
                Some((Id::from_cbor(owner).ok()?, Epoch::parse(epoch)?, redirect))
            }
            _ => return None,
        };
        Some(Self {
            check: (*check).try_into().ok()?,
            device: (*device).try_into().ok()?,
            agent: Id::from_cbor(agent).ok()?,
            key: Box::new((*key).try_into().ok()?),
            name: (*name).into(),
            created: *created,
            loopback,
            attempts: *attempts,
            approved,
            workload: workload_parse(workload)?,
        })
    }
}

/// The form of the workload `workload` of a record: `[issuer, subject]`, or null.
fn workload_form(workload: Option<&Workload>) -> Value<'_> {
    workload.map_or(Value::Null, |workload| {
        Value::Array(vec![Value::Text(workload.issuer()), Value::Text(workload.subject())])
    })
}

/// The workload of the form `value` of a record, or `None` in it for null. `None` for another form.
fn workload_parse(value: &Value<'_>) -> Option<Option<Workload>> {
    match value {
        Value::Null => Some(None),
        Value::Array(items) => match items.as_slice() {
            [Value::Text(issuer), Value::Text(subject)] => Workload::new(issuer, subject).ok().map(Some),
            _ => None,
        },
        _ => None,
    }
}

impl Agents {
    /// The enrollment of agents under `authority`, whose records and forms are within `limits`.
    ///
    /// Cost class: [`Parse`](crate::limits::Class::Parse).
    #[must_use]
    pub const fn new(authority: Id<Authority>, limits: Limits) -> Self {
        Self { authority, limits }
    }

    /// Proposes an enrollment request of an agent with the public key `key` and the name `name`, for a local agent with
    /// the address `loopback`, and for a hosted agent with its verified workload `workload`, which the request keeps
    /// for the approval page. The agent stores the private part of `key` in custody before the request. The
    /// commit writes the request, which ends after [`ENROLLMENT_LIFETIME`]. Give the agent the [`Started`] value at
    /// once, and the device code from the artifact of the accepted commit: [`DeviceCode::from_bytes`]. A request
    /// authenticates no caller, so its audit names the agent, and no field names an owner. The operation identity is
    /// new: after a lost response, the agent asks again, and the earlier request ends unused. Two open requests with
    /// the first 4 letters of one user code conflict: ask again.
    ///
    /// Cost class: [`Parse`](crate::limits::Class::Parse), and its commit. Limit the rate of requests of one client.
    ///
    /// # Errors
    ///
    /// [`Error::Name`] if `name` is empty, longer than [`NAME_BYTES_MAX`], or holds a control character.
    /// [`Error::Time`] if `now` has no bound or the end overflows, and [`Error::Transition`] for the proposal.
    pub fn enroll(
        &self,
        key: &[u8; KEY_BYTES],
        name: &str,
        loopback: Option<&Loopback>,
        workload: Option<&Workload>,
        now: Reading,
        random: &mut ChaCha20Rng,
    ) -> Result<(Proposal, Plan, Started), Error> {
        let valid = (1..=NAME_BYTES_MAX).contains(&name.len()) && !name.chars().any(char::is_control);
        valid.ok_or(Error::Name)?;
        now.latest().map_err(Error::Time)?;
        let end = now
            .estimate()
            .checked_add(ENROLLMENT_LIFETIME)
            .ok_or(Error::Time(TimeError::Overflow))?;
        let code = UserCode::random(random);
        let device = DeviceCode::from_bytes(draw(random));
        let mut value = [0; 22];
        let value = Url
            .encode(&draw::<16>(random), &mut value)
            .expect("16 bytes have 22 base64url characters");
        let value = core::str::from_utf8(value).expect("base64url is ASCII");
        let agent = Id::new(self.authority.namespace(), value).expect("base64url text is a valid value");
        let request = self.request_key(&code);
        let pending = Pending {
            check: *code.check(),
            device: device.digest(),
            agent: agent.clone(),
            key: Box::new(*key),
            name: name.into(),
            created: now.estimate().as_secs(),
            loopback: loopback.cloned(),
            attempts: 0,
            approved: None,
            workload: workload.cloned(),
        };
        let actor = Principal::Agent(agent.clone());
        let mut proposal = self.proposal(
            OperationId::random(random),
            actor,
            REQUEST,
            Value::Bytes(request.as_bytes()),
            now,
        )?;
        proposal
            .read(Dependency::Absent(request.clone()))
            .map_err(Error::Transition)?;
        let version = self.version(1, &device.digest());
        proposal
            .change(Change::Write {
                key: request.clone(),
                version: version.clone(),
                end: Some(end),
                data: pending.form(),
            })
            .map_err(Error::Transition)?;
        proposal
            .prepare(Prepared::new(device.as_bytes().to_vec(), request, version))
            .map_err(Error::Transition)?;
        Ok((proposal, Plan::default(), Started { code, agent }))
    }

    /// Proposes the check of the user code `code` by the signed-in human of `access`, for the approval page. Commit the
    /// proposal: [`Checked::release`] of its outcome gives the request for a right code. Show its fingerprint as the
    /// agent shows it, so that the human approves only the agent on their own screen.
    ///
    /// Cost class: [`Verify`](crate::limits::Class::Verify). One request lookup, and its commit.
    ///
    /// # Errors
    ///
    /// [`Error::Request`] if no request has the first 4 letters of `code`: it ended, or a finish consumed it.
    /// [`Error::Locked`] after [`ATTEMPTS_MAX`] wrong checks, and [`Error::Expired`] after its end. [`Error::Time`] if
    /// `now` has no bound. [`Error::Record`] if the record has no valid form, and [`Failure::Store`] if the read fails.
    /// [`Error::Transition`] for the proposal.
    pub async fn request<S: Store>(
        &self,
        store: &mut S,
        access: &Access,
        code: &UserCode,
        now: Reading,
        random: &mut ChaCha20Rng,
    ) -> Result<(Proposal, Plan, Checked<Request>), Failure<S::Error>> {
        let (key, record, pending) = self.open(store, code, now).await?;
        let right = pending.check == *code.check();
        let ends = record.end.ok_or(Error::Record)?;
        let request = right.then(|| Request {
            fingerprint: crypto::sha256(&*pending.key),
            name: pending.name.clone(),
            loopback: pending.loopback.clone(),
            workload: pending.workload.clone(),
            created: Duration::from_secs(pending.created),
            ends,
            approved: pending.approved.is_some(),
        });
        let proposal = self.check(key, &record, pending, access.session().account(), right, now, random)?;
        let checked = Checked::new(&proposal, request);
        Ok((proposal, Plan::default(), checked))
    }

    /// Proposes the approval of the request of `code` by the account of `fresh`, a fresh user verification of a
    /// passkey session. Thus an approval comes only from a signed-in human, and the owner comes only from the approval.
    /// The agent then has [`ENROLLMENT_LIFETIME`] to finish. The proposal reads the session and the request at their
    /// versions, so a second approval conflicts. Its deadline is the earliest of the end of the verification and of the
    /// request.
    ///
    /// The approval is also a check of `code`: for a wrong code, the proposal counts the wrong check and approves
    /// nothing. [`Checked::release`] of the accepted commit gives the loopback address of a loopback request, or `None`
    /// in it for another request. Only the receipt of that commit gives the redirect code: [`RedirectCode::from_bytes`]
    /// of its artifact. Then send the browser to [`Loopback::redirect`].
    ///
    /// Cost class: [`Verify`](crate::limits::Class::Verify). One request lookup, and its commit.
    ///
    /// # Errors
    ///
    /// The errors of [`Self::request`]. [`Error::Approved`] if an account approved the request already. [`Error::Time`]
    /// if the end overflows.
    pub async fn approve<S: Store>(
        &self,
        store: &mut S,
        fresh: &Fresh,
        code: &UserCode,
        now: Reading,
        random: &mut ChaCha20Rng,
    ) -> Result<(Proposal, Plan, Checked<Option<Loopback>>), Failure<S::Error>> {
        let owner = fresh.account();
        let (key, record, mut pending) = self.open(store, code, now).await?;
        if pending.check != *code.check() {
            let proposal = self.check(key, &record, pending, owner, false, now, random)?;
            let checked = Checked::new(&proposal, None);
            return Ok((proposal, Plan::default(), checked));
        }
        pending.approved.is_none().ok_or(Error::Approved)?;
        let actor = Principal::Human(owner.clone());
        let mut proposal = self.proposal(
            OperationId::random(random),
            actor,
            APPROVE,
            Value::Bytes(key.as_bytes()),
            now,
        )?;
        fresh.gate(&mut proposal).map_err(Error::Transition)?;
        proposal.until(record.end.ok_or(Error::Record)?);
        let end = now
            .estimate()
            .checked_add(ENROLLMENT_LIFETIME)
            .ok_or(Error::Time(TimeError::Overflow))?;
        let redirect = pending
            .loopback
            .is_some()
            .then(|| RedirectCode::from_bytes(draw(random)));
        pending.approved = Some((
            owner.clone(),
            fresh.epoch.clone(),
            redirect.as_ref().map(RedirectCode::digest),
        ));
        let version = self.rewrite(&mut proposal, key.clone(), &record, &pending, Some(end))?;
        if let Some(redirect) = redirect {
            proposal
                .prepare(Prepared::new(redirect.as_bytes().to_vec(), key, version))
                .map_err(Error::Transition)?;
        }
        let checked = Checked::new(&proposal, Some(pending.loopback));
        Ok((proposal, Plan::default(), checked))
    }

    /// The finish of the request of `code` by its agent, which proves itself with its device code `device`, and for a
    /// loopback request also with the redirect code `redirect` that the browser brought to its loopback address. Until
    /// an account approves the request, the finish gives [`Status::Waiting`] and writes nothing. Then it proposes the
    /// commit that consumes the request and writes the agent identity of [`Started::agent`], with the account of the
    /// approval as its owner and the key of the request. The proposal reads the account revision of the approval, so a
    /// recovery of the account between the approval and the finish stops it. Its deadline is the end of the request.
    /// Choose `operation`, and keep it for a lookup: after a lost response, read the identity
    /// ([`Self::identity`]).
    ///
    /// The request pays for no anchor: the consumption writes no journal entry, and a restore ends each pending
    /// request.
    ///
    /// Cost class: [`Verify`](crate::limits::Class::Verify). One request lookup, and for an approved request one
    /// account revision lookup.
    ///
    /// # Errors
    ///
    /// [`Error::Request`] if no open request has `code` and `device`, or a recovery of the account of the approval ended
    /// the approval. [`Error::Redirect`] if a loopback request has no redirect code or another one, or a request of no
    /// loopback address has one. [`Error::Locked`], [`Error::Expired`], [`Error::Time`], [`Error::Record`], and
    /// [`Failure::Store`] as for [`Self::request`]. [`Error::Transition`] for the proposal.
    pub async fn finish<S: Store>(
        &self,
        store: &mut S,
        code: &UserCode,
        device: &DeviceCode,
        redirect: Option<&RedirectCode>,
        now: Reading,
        operation: OperationId,
    ) -> Result<Status, Failure<S::Error>> {
        let (key, record, pending) = self.open(store, code, now).await?;
        (pending.check == *code.check() && pending.device == device.digest()).ok_or(Error::Request)?;
        (pending.loopback.is_some() == redirect.is_some()).ok_or(Error::Redirect)?;
        let Some((owner, epoch, expected)) = &pending.approved else {
            return Ok(Status::Waiting);
        };
        (expected.as_ref() == redirect.map(RedirectCode::digest).as_ref()).ok_or(Error::Redirect)?;
        epoch
            .holds(read(store, &epoch.key()).await?.as_ref())
            .ok_or(Error::Request)?;
        let identity = self.agent_key(&pending.agent);
        let request = Value::Array(vec![Value::Bytes(key.as_bytes()), pending.agent.to_cbor()]);
        let mut proposal = self.proposal(operation, Principal::Human(owner.clone()), ENROLL, request, now)?;
        proposal.read(epoch.dependency()).map_err(Error::Transition)?;
        proposal
            .read(Dependency::Version(key.clone(), record.version))
            .map_err(Error::Transition)?;
        proposal.change(Change::End(key)).map_err(Error::Transition)?;
        proposal.until(record.end.ok_or(Error::Record)?);
        proposal
            .read(Dependency::Absent(identity.clone()))
            .map_err(Error::Transition)?;
        let enrolled = Identity {
            agent: pending.agent.clone(),
            owner: owner.clone(),
            key: pending.key.clone(),
            name: pending.name.clone(),
            workload: pending.workload.clone(),
            created: Duration::from_secs(now.estimate().as_secs()),
            generation: 1,
            version: self.version(1, &crypto::sha256(&*pending.key)),
        };
        proposal
            .change(Change::Write {
                key: identity,
                version: enrolled.version.clone(),
                end: None,
                data: enrolled.form(),
            })
            .map_err(Error::Transition)?;
        Ok(Status::Approved(proposal, Plan::default()))
    }

    /// Proposes the rotation of the key of the agent of `rotation` to its new key. The current key and the new key
    /// each sign the statement of the current generation ([`Rotation::statement`]), so a rotation needs both keys, and
    /// a statement of an earlier generation never matches again. The commit writes the identity with the new key at
    /// the next generation, and keeps its owner, its name, its workload, and its time of creation. The plan names the
    /// identity as replaced, so the restore journal ends the earlier version: no restore gives the earlier key again.
    /// Choose `operation`, and keep it for a lookup. Then answer with the [`Identity::json`] of [`Self::identity`].
    ///
    /// Cost class: [`Verify`](crate::limits::Class::Verify). One identity lookup, and the signature checks of the two
    /// composite signatures, each within the limits.
    ///
    /// # Errors
    ///
    /// [`Error::NotEnrolled`] if the store holds no identity of the agent, and [`Error::Record`] if its record has no
    /// valid form. [`Error::Rotated`] if the new key is the current key: a rotation to it committed, for example
    /// before a lost response. [`Error::Signature`] if a signature does not verify with its key over the statement,
    /// also for a statement of another generation, or if the checks pass the limits. [`Error::Transition`] for the
    /// proposal, and [`Failure::Store`] if the read fails.
    pub async fn rotate<S: Store>(
        &self,
        store: &mut S,
        rotation: &Rotation,
        now: Reading,
        operation: OperationId,
    ) -> Result<(Proposal, Plan), Failure<S::Error>> {
        let key = self.agent_key(&rotation.agent);
        let record = read(store, &key).await?.ok_or(Error::NotEnrolled)?;
        let mut identity = Identity::parse(&rotation.agent, &record, self.limits).ok_or(Error::Record)?;
        (identity.key != rotation.key).ok_or(Error::Rotated)?;
        let statement = Rotation::statement(&rotation.agent, &identity.key, &rotation.key, identity.generation);
        for (public, signature) in [
            (&*identity.key, &rotation.old_signature),
            (&*rotation.key, &rotation.new_signature),
        ] {
            let verifier = crypto::Verifier::ml_dsa_65_ed25519(public).ok_or(Error::Signature)?;
            let verified = verifier.verify(&statement, signature, &mut SignatureBudget::new(&self.limits));
            verified.is_ok_and(|verified| verified).ok_or(Error::Signature)?;
        }
        let digest = crypto::sha256(&statement);
        let request = Value::Array(vec![Value::Bytes(key.as_bytes()), Value::Bytes(&digest)]);
        let actor = Principal::Agent(rotation.agent.clone());
        let mut proposal = self.proposal(operation, actor, ROTATE, request, now)?;
        proposal
            .read(Dependency::Version(key.clone(), record.version.clone()))
            .map_err(Error::Transition)?;
        identity.version = self.next(&record.version, &crypto::sha256(&*rotation.key))?;
        identity.key = rotation.key.clone();
        proposal
            .change(Change::Write {
                key: key.clone(),
                version: identity.version.clone(),
                end: None,
                data: identity.form(),
            })
            .map_err(Error::Transition)?;
        let plan = Plan {
            replaced: vec![key],
            ..Plan::default()
        };
        Ok((proposal, plan))
    }

    /// Proposes the revocation of `agent` by the signed-in human of `access`, who must be its owner. The commit ends
    /// the identity and its grant ([`crate::grant`]) at the versions that the proposal read, so the restore journal
    /// keeps both ends, and each later check of the agent refuses with [`Error::NotEnrolled`]. The proposal reads the
    /// session, so a revocation from a session that ended refuses. To change the owner, revoke the agent, and enroll it
    /// again: the new enrollment gives a new agent identifier.
    ///
    /// Cost class: [`Verify`](crate::limits::Class::Verify). Two keyed lookups, and the commit.
    ///
    /// # Errors
    ///
    /// [`Error::NotEnrolled`] if the store holds no identity of `agent`, also for an agent of another owner, so the
    /// answer tells no other human that the agent exists. [`Error::Record`] if its record has no valid form.
    /// [`Error::Transition`] for the proposal, and [`Failure::Store`] if the read fails.
    pub async fn revoke<S: Store>(
        &self,
        store: &mut S,
        access: &Access,
        agent: &Id<Agent>,
        now: Reading,
        random: &mut ChaCha20Rng,
    ) -> Result<(Proposal, Plan), Failure<S::Error>> {
        let key = self.agent_key(agent);
        let record = read(store, &key).await?.ok_or(Error::NotEnrolled)?;
        let identity = Identity::parse(agent, &record, self.limits).ok_or(Error::Record)?;
        let owner = access.session().account();
        (identity.owner == *owner).ok_or(Error::NotEnrolled)?;
        let actor = Principal::Human(owner.clone());
        let request = Value::Bytes(key.as_bytes());
        let mut proposal = self.proposal(OperationId::random(random), actor, REVOKE, request, now)?;
        access.gate(&mut proposal).map_err(Error::Transition)?;
        proposal
            .read(Dependency::Version(key.clone(), record.version))
            .map_err(Error::Transition)?;
        proposal.change(Change::End(key)).map_err(Error::Transition)?;
        let grant = grant::key(&self.authority, owner, agent);
        if let Some(record) = read(store, &grant).await? {
            proposal
                .read(Dependency::Version(grant.clone(), record.version))
                .map_err(Error::Transition)?;
            proposal.change(Change::End(grant)).map_err(Error::Transition)?;
        }
        Ok((proposal, Plan::default()))
    }

    /// The key of the identity record of `agent`, which a grant check reads.
    pub(crate) fn identity_key(&self, agent: &Id<Agent>) -> Key {
        self.agent_key(agent)
    }

    /// The current identity of `agent`: its owner, its key, and the generation of its key. Each check of a request of
    /// the agent reads it, so a key that no enrollment bound, that a rotation replaced, or that a revocation or a
    /// restore ended refuses.
    ///
    /// Cost class: [`Verify`](crate::limits::Class::Verify). One keyed lookup.
    ///
    /// # Errors
    ///
    /// [`Error::NotEnrolled`] if the store holds no identity of `agent`, [`Error::Record`] if its record has no valid
    /// form, and [`Failure::Store`] if the read fails.
    pub async fn identity<S: Store>(&self, store: &mut S, agent: &Id<Agent>) -> Result<Identity, Failure<S::Error>> {
        let record = read(store, &self.agent_key(agent)).await?.ok_or(Error::NotEnrolled)?;
        Ok(Identity::parse(agent, &record, self.limits).ok_or(Error::Record)?)
    }

    /// The key, the record, and the request of `code`, while it is open at `now` and not locked. Only the first 4
    /// letters of `code` find it: the caller checks the rest.
    async fn open<S: Store>(
        &self,
        store: &mut S,
        code: &UserCode,
        now: Reading,
    ) -> Result<(Key, Record, Pending), Failure<S::Error>> {
        let latest = now.latest().map_err(Error::Time)?;
        let key = self.request_key(code);
        let record = read(store, &key).await?.ok_or(Error::Request)?;
        (latest < record.end.ok_or(Error::Record)?).ok_or(Error::Expired)?;
        let pending = Pending::parse(&record, self.limits).ok_or(Error::Record)?;
        (pending.attempts < ATTEMPTS_MAX).ok_or(Error::Locked)?;
        Ok((key, record, pending))
    }

    /// The proposal of a check of the user code of the open request `pending` at `key` by the human `actor`, with one
    /// more wrong check if the code is not `right`.
    #[expect(
        clippy::too_many_arguments,
        reason = "the request, its record, its state, the actor, the result, the time, and the random source are each one input of one check"
    )]
    fn check(
        &self,
        key: Key,
        record: &Record,
        mut pending: Pending,
        actor: &Id<Human>,
        right: bool,
        now: Reading,
        random: &mut ChaCha20Rng,
    ) -> Result<Proposal, Error> {
        if !right {
            pending.attempts = pending.attempts.checked_add(1).ok_or(Error::Record)?;
        }
        let actor = Principal::Human(actor.clone());
        let request = Value::Bytes(key.as_bytes());
        let mut proposal = self.proposal(OperationId::random(random), actor, CHECK, request, now)?;
        self.rewrite(&mut proposal, key, record, &pending, record.end)?;
        Ok(proposal)
    }

    /// Adds to `proposal` the read of the request `key` at the version of `record`, and the write of `pending` at the
    /// next version, which ends at `end`. The identity of the version is the digest of the form. Thus of two proposals
    /// that read one version, one commits and the other conflicts.
    fn rewrite(
        &self,
        proposal: &mut Proposal,
        key: Key,
        record: &Record,
        pending: &Pending,
        end: Option<Duration>,
    ) -> Result<AuthorityVersion, Error> {
        let data = pending.form();
        let version = self.next(&record.version, &crypto::sha256(&data))?;
        proposal
            .read(Dependency::Version(key.clone(), record.version.clone()))
            .map_err(Error::Transition)?;
        proposal
            .change(Change::Write {
                key,
                version: version.clone(),
                end,
                data,
            })
            .map_err(Error::Transition)?;
        Ok(version)
    }

    /// The key of the request of `code`: [`Kind::AgentEnrollment`] with the SHA-256 digest of the canonical CBOR form
    /// `["rsauthnz.agent.enrollment.2", authority, locator]`, where `locator` is the first 4 letters of the code.
    fn request_key(&self, code: &UserCode) -> Key {
        let digest = crypto::sha256(&encode(&[
            Value::Text(REQUEST_FORM),
            self.authority.to_cbor(),
            Value::Bytes(code.locator()),
        ]));
        Kind::AgentEnrollment.key(&digest).expect("a key of 33 bytes is valid")
    }

    /// The key of the identity record of `agent`: [`Kind::Agent`] with the SHA-256 digest of the canonical CBOR form
    /// `["rsauthnz.agent.2", authority, agent]`.
    fn agent_key(&self, agent: &Id<Agent>) -> Key {
        let digest = crypto::sha256(&encode(&[
            Value::Text(AGENT_FORM),
            self.authority.to_cbor(),
            agent.to_cbor(),
        ]));
        Kind::Agent.key(&digest).expect("a key of 33 bytes is valid")
    }

    /// The version of a record of the authority: a counter, then the identity of the new state. The identity makes each
    /// version unique, so a proposal from before a restore never finds an equal version of another state.
    fn version(&self, count: u64, identity: &[u8; 32]) -> AuthorityVersion {
        AuthorityVersion::new(
            self.authority.clone(),
            &[count.to_be_bytes().as_slice(), identity].concat(),
        )
        .expect("a coordinate of 40 bytes is valid")
    }

    /// The version after `read`, with the identity `identity`.
    fn next(&self, read: &AuthorityVersion, identity: &[u8; 32]) -> Result<AuthorityVersion, Error> {
        let count = read.coordinate().first_chunk::<8>().ok_or(Error::Record)?;
        let count = u64::from_be_bytes(*count).checked_add(1).ok_or(Error::Record)?;
        Ok(self.version(count, identity))
    }

    /// A proposal of `actor` for `action` on `request`. Its request is `[authority, request]`, so one operation identity
    /// under two authorities of one store binds two requests.
    fn proposal(
        &self,
        operation: OperationId,
        actor: Principal,
        action: &str,
        request: Value<'_>,
        now: Reading,
    ) -> Result<Proposal, Error> {
        let audit = Audit {
            actor,
            action: Id::new("rsauthnz", action).expect("each action of this module is a valid identifier"),
            time: now,
        };
        let request = Value::Array(vec![self.authority.to_cbor(), request]);
        Proposal::new(operation, audit, &request, self.limits).map_err(Error::Transition)
    }
}

/// `N` random bytes from `random`.
fn draw<const N: usize>(random: &mut ChaCha20Rng) -> [u8; N] {
    let mut bytes = [0; N];
    random.fill_bytes(&mut bytes);
    bytes
}

/// The canonical CBOR form of the array `items`.
fn encode(items: &[Value<'_>]) -> Vec<u8> {
    cbor::encode(&Value::Array(items.to_vec()), Limits::FORM)
        .expect("the forms of this module have no map and no simple value")
}

/// The keyed read of `key`.
async fn read<S: Store>(store: &mut S, key: &Key) -> Result<Option<Record>, Failure<S::Error>> {
    store.read(key).await.map_err(Failure::Store)
}

/// The cause of a refused operation of agent enrollment. No error holds a secret.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Error {
    /// A JSON body of an agent is not of its form, or is longer than [`BODY_BYTES_MAX`].
    Malformed,
    /// The name of an agent is empty, longer than [`NAME_BYTES_MAX`], or holds a control character.
    Name,
    /// The text is not a loopback address ([`Loopback`]).
    Loopback,
    /// No open enrollment request has the user code and the device code: the request ended, a finish consumed it, or
    /// a recovery of the account of the approval ended the approval. The agent makes a new request.
    Request,
    /// The end of the enrollment request passed. The agent makes a new request.
    Expired,
    /// The request had [`ATTEMPTS_MAX`] wrong checks of its user code. The agent makes a new request.
    Locked,
    /// An account approved the enrollment request already.
    Approved,
    /// A loopback request has no redirect code or another one, or a request of no loopback address has one.
    Redirect,
    /// The store holds no identity of the agent: no enrollment bound it, its owner revoked it, or a restore lost it.
    /// The agent enrolls again.
    NotEnrolled,
    /// The new key of a rotation is the current key of the agent: a rotation to it committed.
    Rotated,
    /// A signature of a rotation does not verify with its key over the statement of the current generation.
    Signature,
    /// A record has no valid form. Restore the store from a snapshot.
    Record,
    /// The reading of the time has no bound, or a time overflows. Use a reading with a bound.
    Time(TimeError),
    /// The proposal refuses. The error gives the recovery.
    Transition(transition::Error),
    /// The key set of the platform is missing or stale, or the reading refuses. Refresh the key set.
    Trust(trust::Error),
    /// The workload identity token refuses. The agent gets a new token.
    Token(jose::Error),
    /// The workload credential or its proof refuses.
    Credential(credential::Error),
    /// The trust snapshot does not admit the workload credential: it has no registration of the workload, or a
    /// rotation, a recovery, or a revocation ended the credential. The workload gets a new credential.
    Admission,
    /// The issuer or the subject of the workload is longer than [`WORKLOAD_BYTES_MAX`] or holds a control character.
    Workload,
}

impl Recover for Error {
    /// Make a new request, or read the current state again, when the enrollment request changes.
    fn recovery(&self) -> Recovery {
        match self {
            Self::Request | Self::Expired | Self::Locked | Self::Approved => Recovery::Restart,
            Self::Transition(error) => error.recovery(),
            Self::Malformed
            | Self::Name
            | Self::Loopback
            | Self::Redirect
            | Self::NotEnrolled
            | Self::Rotated
            | Self::Signature
            | Self::Record
            | Self::Time(_)
            | Self::Trust(_)
            | Self::Token(_)
            | Self::Credential(_)
            | Self::Admission
            | Self::Workload => Recovery::Refuse,
        }
    }
}

impl fmt::Display for Error {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Malformed => f.write_str("the body is not of its form"),
            Self::Name => f.write_str("the name of the agent is not valid"),
            Self::Loopback => f.write_str("the text is not a loopback address"),
            Self::Request => f.write_str("no open enrollment request has the codes"),
            Self::Expired => f.write_str("the enrollment request expired"),
            Self::Locked => f.write_str("the enrollment request had too many wrong checks of its user code"),
            Self::Approved => f.write_str("an account approved the enrollment request already"),
            Self::Redirect => f.write_str("the redirect code is missing, wrong, or not expected"),
            Self::NotEnrolled => f.write_str("the store holds no identity of the agent"),
            Self::Rotated => f.write_str("the new key is the current key of the agent"),
            Self::Signature => f.write_str("a signature of the rotation does not verify"),
            Self::Record => f.write_str("a record of agent enrollment has no valid form"),
            Self::Time(error) => write!(f, "the time refused: {error}"),
            Self::Transition(error) => write!(f, "the proposal refused: {error}"),
            Self::Trust(error) => write!(f, "the key set of the platform refused: {error}"),
            Self::Token(error) => write!(f, "the workload identity token refused: {error}"),
            Self::Credential(error) => write!(f, "the workload credential refused: {error}"),
            Self::Admission => f.write_str("the trust snapshot does not admit the workload credential"),
            Self::Workload => f.write_str("the issuer or the subject of the workload is not valid"),
        }
    }
}

impl core::error::Error for Error {}

/// The failure of an operation that reads the store: a refusal, or a failed read.
pub type Failure<E> = crate::store::Failure<Error, E>;
