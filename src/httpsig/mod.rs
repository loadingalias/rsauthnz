//! HTTP message signatures of an agent ([RFC 9421]). Each request carries the agent credential and a signature by its
//! `cnf` key, so no bearer secret exists. The verifier keeps no state, and it gives the same [`Evidence`] as a proof of
//! possession ([`credential::Verified::possession`]). Thus [`authz::check_agent`] checks the grant of each request.
//!
//! The signature covers these components, in any order, each once:
//!
//! - `@method`, `@path`, and `@query` (RFC 9421 section 2.2). `@query` is `?` for a request with no query.
//! - `content-digest`: the SHA-256 digest of the body ([RFC 9530]), also of an empty body.
//! - `content-type`, when the request has it. A changed media type can change how the server reads the same body.
//! - `agent-credential` ([`CREDENTIAL`]): the agent credential, a byte sequence ([RFC 8941]). It is the grant
//!   reference: it names the agent, its owner, the grant revision, and the audience.
//!
//! The signature covers no authority. The audience of the credential is the recipient: the credential profile of the
//! verifier refuses a credential of another audience. Thus a proxy can change `Host` or `:authority`, and the verifier
//! never reads them. The WIMSE HTTP-signature draft binds its recipient in the same way, with a signed audience.
//!
//! The parameters are `created`, `expires`, `nonce`, and `tag`, in any order, each once. The tag is [`TAG`], and the
//! nonce is the base64url of 16 to 32 random bytes of the agent. A verifier takes the one signature with the tag, so a
//! request can also carry the signature of a proxy. A signature with `alg`, `keyid`, or another parameter refuses: the
//! `cnf` key of the credential gives the key and its algorithm, so the request never selects an algorithm.
//!
//! Signing has two steps, so the agent key stays in custody. [`Draft::new`] gives the signature base, and custody
//! signs [`Draft::to_be_signed`]. [`Draft::finish`] verifies the signature with the agent key, and gives the four
//! fields of the request ([`Signed`]).
//!
//! Verification has two steps too. [`Profile::verify`] checks a request with no state, and gives a [`Checked`]
//! signature. The replay store of the audience then accepts each signature once. For a request that commits nothing,
//! [`Checked::accept`] inserts its replay record and gives the [`Evidence`]. For a request that commits a transition,
//! [`Checked::check_agent`] checks the grant and gives a [`Pending`] scope, whose proposal carries the insert. The
//! replay identity is the audience of the verifier, the `cnf` key of the agent, and the nonce, so one agent cannot use
//! the nonce or the share of another.
//!
//! Each request carries one composite signature of 3,373 bytes and one credential of about 5.5 KB, in base64. A
//! binding marks these fields sensitive, so an HTTP/2 or HTTP/3 encoder never indexes them, and each request sends
//! them again. A proxy between the agent and the verifier must keep the method, the path, the query, the body,
//! `Content-Type`, and the four fields of the signature.
//!
//! [RFC 9421]: https://www.rfc-editor.org/rfc/rfc9421
//! [RFC 9530]: https://www.rfc-editor.org/rfc/rfc9530
//! [RFC 8941]: https://www.rfc-editor.org/rfc/rfc8941

use alloc::borrow::Cow;
use alloc::string::String;
use alloc::vec;
use alloc::vec::Vec;
use core::fmt::{self, Write as _};
use core::time::Duration;

use rscodec::base64::Profile::{Standard, Url};

use self::sf::{Bare, Item, Member, Parameters};
use crate::authz::{self, Granted, Policy};
use crate::cbor::Value;
use crate::cose::{self, TrustedKey};
use crate::credential::{self, SIGNATURE_BYTES_MAX};
use crate::crypto;
use crate::evidence::Evidence;
use crate::grant::{self, Grants};
use crate::id::{Action, AuthorityVersion, Id, Resource};
use crate::limits::{Limit, Limits, SignatureBudget};
use crate::store::{self, Insert, Inserted, Store};
use crate::time::{Reading, TimeError};
use crate::transition::{self, Change, Dependency, OperationId, Proposal, Recover, Recovery};

mod sf;
#[cfg(test)]
mod tests;

/// The `tag` parameter of each signature of the profile.
pub const TAG: &str = "rsauthnz-agent";

/// The name of the field that carries the agent credential.
pub const CREDENTIAL: &str = "agent-credential";

/// The label of the signature that [`Draft`] writes. A verifier selects a signature by its tag, not by its label.
const LABEL: &str = "agent";

/// The bytes of the nonce of [`Draft::new`]: 128 bits.
pub const NONCE_BYTES: usize = 16;

/// The most bytes of a nonce that a verifier takes. A nonce has at least [`NONCE_BYTES`] bytes.
pub const NONCE_BYTES_MAX: usize = 32;

/// The lifetime of a signature that an agent gives [`Draft::new`] when it has no other need.
pub const LIFETIME_DEFAULT: Duration = Duration::from_secs(60);

/// The longest window of a signature that a verifier takes by default: from `created` to `expires`.
pub const WINDOW_MAX_DEFAULT: Duration = Duration::from_secs(300);

/// The clock skew of an agent that a verifier takes by default: `created` can be this much after its reading.
pub const SKEW_DEFAULT: Duration = Duration::from_secs(30);

/// The name of the form of the share of a replay identity: the audience of the verifier and the `cnf` key of the agent.
const SHARE_FORM: &str = "rsauthnz.httpsig.share.1";

/// The largest integer of a structured field (RFC 8941 section 3.3.1).
const INTEGER_MAX: u64 = 999_999_999_999_999;

const SIGNATURE_INPUT: &str = "signature-input";
const SIGNATURE: &str = "signature";
const CONTENT_DIGEST: &str = "content-digest";
const CONTENT_TYPE: &str = "content-type";

/// The parts of one HTTP request that a signature covers or carries. A binding, such as `rsauthnz-http`, gives them.
#[derive(Clone, Copy)]
pub struct Request<'a> {
    /// The method, such as `POST`, in its case.
    pub method: &'a str,
    /// The path of the target, with each percent-encoded byte as the request has it. An empty path is `/`.
    pub path: &'a str,
    /// The query of the target, with no `?`, or `None` for a target with no query.
    pub query: Option<&'a str>,
    /// Each header field of the request in its order: its name and its value. Two fields of one name join with `, `
    /// (RFC 9421 section 2.1).
    pub fields: &'a [(&'a str, &'a [u8])],
    /// The body.
    pub body: &'a [u8],
}

// The path, the query, a field, and the body can hold a secret. Thus the output shows only the method and lengths.
impl fmt::Debug for Request<'_> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("Request")
            .field("method", &self.method)
            .field("fields", &self.fields.len())
            .field("body_len", &self.body.len())
            .finish_non_exhaustive()
    }
}

/// The four fields that a signature adds to its request ([`Draft::finish`]).
#[derive(Clone, PartialEq, Eq)]
pub struct Signed {
    content_digest: String,
    credential: String,
    input: String,
    signature: String,
}

impl Signed {
    /// Each field: its name and its value. Add each one in place of each field of the same name.
    #[must_use]
    pub fn fields(&self) -> [(&'static str, &str); 4] {
        [
            (CONTENT_DIGEST, &self.content_digest),
            (CREDENTIAL, &self.credential),
            (SIGNATURE_INPUT, &self.input),
            (SIGNATURE, &self.signature),
        ]
    }
}

// The credential and the signature are long. Thus the output shows their lengths.
impl fmt::Debug for Signed {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("Signed")
            .field("input", &self.input)
            .field("credential_len", &self.credential.len())
            .field("signature_len", &self.signature.len())
            .finish_non_exhaustive()
    }
}

/// A signature of a request that the agent key did not sign yet. [`Draft::finish`] consumes the draft, so one draft
/// gives at most one signature.
pub struct Draft {
    key: TrustedKey,
    base: Vec<u8>,
    signed: Signed,
}

impl Draft {
    /// The draft of the signature of `request` by the agent key `key`, the `cnf` key of `credential`. The signature has
    /// the nonce `nonce`, `created` at the whole seconds of `now.estimate()`, and `expires` `lifetime` later, in whole
    /// seconds. Make each nonce from fresh randomness of the agent, such as `rscrypto::ChaCha20Rng`. The draft
    /// computes the content digest of the body, and it covers `content-type` when `request` has it.
    ///
    /// Cost class: [`Parse`](crate::limits::Class::Parse). One SHA-256 digest of the body.
    ///
    /// # Errors
    ///
    /// [`Error::Field`] with [`Field::Credential`] if `credential` is longer than [`credential::MAX_BYTES`].
    /// [`Error::Window`] if `lifetime` is under one second, or `expires` is past the largest integer of a structured
    /// field. [`Error::Value`] if a component of `request` cannot go into the signature base: a byte that is not
    /// visible ASCII, or a field longer than [`Limits::bytes`] of the default limits.
    pub fn new(
        key: &TrustedKey,
        credential: &[u8],
        request: &Request<'_>,
        nonce: &[u8; NONCE_BYTES],
        lifetime: Duration,
        now: Reading,
    ) -> Result<Self, Error> {
        (credential.len() <= credential::MAX_BYTES).ok_or(Error::Field(Field::Credential))?;
        let created = now.estimate().as_secs();
        let expires = created
            .checked_add(lifetime.as_secs())
            .filter(|&expires| expires > created && expires <= INTEGER_MAX)
            .ok_or(Error::Window)?;
        let content_digest = format!("sha-256=:{}:", base64(&crypto::sha256(request.body)));
        let credential = format!(":{}:", base64(credential));
        let content_type = combined(request.fields, CONTENT_TYPE);
        let mut input = format!(r#"{LABEL}=("@method" "@path" "@query" "{CONTENT_DIGEST}""#);
        if content_type.is_some() {
            input.push_str(r#" "content-type""#);
        }
        let mut nonce_text = [0; 22];
        Url.encode(nonce, &mut nonce_text)
            .expect("16 bytes have 22 base64url characters");
        let nonce_text = core::str::from_utf8(&nonce_text).expect("base64url is ASCII");
        write!(
            input,
            r#" "{CREDENTIAL}");created={created};expires={expires};nonce="{nonce_text}";tag="{TAG}""#
        )
        .expect("a string takes each write");
        let mut fields = vec![
            (CONTENT_DIGEST, content_digest.as_bytes()),
            (CREDENTIAL, credential.as_bytes()),
        ];
        fields.extend(content_type.as_deref().map(|value| (CONTENT_TYPE, value)));
        let signer = Request {
            fields: &fields,
            ..*request
        };
        // The verifier parses the same text, so the base of the draft is the base of its verification.
        let members = sf::dictionary(input.as_bytes(), &Limits::default()).expect("the draft writes a dictionary");
        let Some((_, Member::List(components, parameters))) = members.first() else {
            return Err(Error::Components);
        };
        let base = base(&signer, components, parameters, &Limits::default())?;
        Ok(Self {
            key: key.clone(),
            base,
            signed: Signed {
                content_digest,
                credential,
                input,
                signature: String::new(),
            },
        })
    }

    /// The signature base: the bytes that custody signs with the agent key. ML-DSA-65 and the composites sign it with
    /// the empty context.
    #[must_use]
    pub fn to_be_signed(&self) -> &[u8] {
        &self.base
    }

    /// Verifies `signature`, the signature of custody over [`Self::to_be_signed`], with the agent key. Then it gives the
    /// fields of the request. The check charges `budget`. A refusal gives no field.
    ///
    /// Cost class: [`Verify`](crate::limits::Class::Verify).
    ///
    /// # Errors
    ///
    /// [`Error::Signature`] if the signature does not verify with the agent key. [`Error::Limit`] if the check costs
    /// more than `budget` has.
    pub fn finish(mut self, signature: &[u8], budget: &mut SignatureBudget) -> Result<Signed, Error> {
        check(&self.key, &self.base, signature, budget)?;
        self.signed.signature = format!("{LABEL}=:{}:", base64(signature));
        Ok(self.signed)
    }
}

// The base holds the path, the query, and the media type, which can hold a secret. Thus the output shows its length.
impl fmt::Debug for Draft {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("Draft")
            .field("key", &self.key)
            .field("base_len", &self.base.len())
            .field("signed", &self.signed)
            .finish()
    }
}

/// A trusted verification profile of HTTP message signatures: the profile of the credentials, the longest window of a
/// signature, and the clock skew of an agent.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Profile {
    credential: credential::Profile,
    window_max: Duration,
    skew: Duration,
}

impl Profile {
    /// The profile that verifies the requests of the holders of the credentials that `credential` verifies, such as the
    /// profile of [`Grants::profile`](crate::grant::Grants::profile). The audience of `credential` is the recipient,
    /// so a request with a credential of another audience refuses. The window is [`WINDOW_MAX_DEFAULT`], and the skew
    /// is [`SKEW_DEFAULT`].
    ///
    /// Cost class: [`Parse`](crate::limits::Class::Parse).
    #[must_use]
    pub const fn new(credential: credential::Profile) -> Self {
        Self {
            credential,
            window_max: WINDOW_MAX_DEFAULT,
            skew: SKEW_DEFAULT,
        }
    }

    /// The profile that takes a window of at most `window_max` and a clock skew of `skew`, each in whole seconds.
    ///
    /// Cost class: [`Parse`](crate::limits::Class::Parse).
    #[must_use]
    pub const fn with_window(mut self, window_max: Duration, skew: Duration) -> Self {
        self.window_max = window_max;
        self.skew = skew;
        self
    }

    /// Verifies the signature of `request` at the physical time `now`, and gives the [`Checked`] signature. Its
    /// evidence is that of [`credential::Verified::possession`]: the subject of the credential,
    /// [`Method::KeyPossession`], and the credential with its claims. Only its replay insert gives it
    /// ([`Checked::accept`], [`Checked::check_agent`]).
    ///
    /// The checks come in this order, and each signature check comes after each other check:
    ///
    /// 1. `Signature-Input` has exactly one signature with the tag [`TAG`]. It covers the components of the profile,
    ///    and it has the parameters of the profile.
    /// 2. The window: `expires` is after `created` by at most the longest window, `created` is not later than the
    ///    earliest time of `now` plus the skew, and the latest time of `now` is before `expires`.
    /// 3. `Signature` has a byte sequence with the label of that signature.
    /// 4. The `sha-256` member of `Content-Digest` is the SHA-256 digest of the body.
    /// 5. The credential verifies with the credential profile at `now` ([`credential::Profile::verify`]): its issuer,
    ///    its audience, its purpose, and its validity.
    /// 6. The `cnf` key of the credential signed the signature base.
    ///
    /// A replayed signature verifies again until its `expires`. Its replay insert refuses it.
    ///
    /// Cost class: [`Verify`](crate::limits::Class::Verify). One SHA-256 digest of the body, and two signature checks:
    /// the credential and the request, each with its own budget of [`Limits::signature_checks`].
    ///
    /// [`Method::KeyPossession`]: crate::evidence::Method::KeyPossession
    ///
    /// # Errors
    ///
    /// [`Error::Tag`], [`Error::Components`], [`Error::Parameters`], [`Error::Nonce`],
    /// [`Error::Window`], [`Error::Early`], [`Error::Expired`], [`Error::Digest`], [`Error::Signature`], and
    /// [`Error::Limit`] for each check. [`Error::Field`] for a field of the profile that is missing, longer than
    /// [`Limits::bytes`], or not valid. [`Error::Value`] for a covered value that cannot go into the signature base.
    /// [`Error::Credential`] for a refused credential, and [`Error::Time`] for a reading with no bound.
    pub fn verify(&self, request: &Request<'_>, now: Reading) -> Result<Checked, Error> {
        let limits = self.credential.limits();
        let inputs = field(request, SIGNATURE_INPUT, Field::SignatureInput)?;
        let inputs = sf::dictionary(&inputs, &limits).map_err(|_| Error::Field(Field::SignatureInput))?;
        let tag = (&b"tag"[..], Bare::String(TAG.as_bytes()));
        let mut tagged = inputs.iter().filter_map(|(label, member)| match member {
            Member::List(components, parameters) if parameters.contains(&tag) => Some((label, components, parameters)),
            Member::List(..) | Member::Item(_) => None,
        });
        let (label, components, parameters) = tagged.next().ok_or(Error::Tag)?;
        tagged.next().is_none().ok_or(Error::Tag)?;
        let (created, expires, nonce) = profile_parameters(parameters)?;
        covered(components, combined(request.fields, CONTENT_TYPE).is_some())?;
        self.window(created, expires, now)?;
        let signatures = field(request, SIGNATURE, Field::Signature)?;
        let signatures = sf::dictionary(&signatures, &limits).map_err(|_| Error::Field(Field::Signature))?;
        let signature = signatures
            .iter()
            .find(|(key, _)| key == label)
            .ok_or(sf::Malformed)
            .and_then(|(_, member)| bytes(member, SIGNATURE_BYTES_MAX))
            .map_err(|_| Error::Field(Field::Signature))?;
        digest(request, &limits)?;
        let credential = field(request, CREDENTIAL, Field::Credential)?;
        let credential = sf::item(&credential, &limits)
            .and_then(|item| bytes(&Member::Item(item), credential::MAX_BYTES))
            .map_err(|_| Error::Field(Field::Credential))?;
        let base = base(request, components, parameters, &limits)?;
        let verified = self
            .credential
            .verify(&credential, now, &mut SignatureBudget::new(&limits))?;
        let evidence = verified.proved(now, |key| {
            check(key, &base, &signature, &mut SignatureBudget::new(&limits))
        })?;
        let insert = self.insert(&evidence, nonce, created, expires, now)?;
        Ok(Checked { evidence, insert })
    }

    /// The replay insert of the signature of `evidence` with `nonce`, from `created` to `expires`, at `now`. Its record
    /// ends at `expires` plus the skew and twice the bound of `now`, and it inserts only before `expires` plus the skew.
    fn insert(
        &self,
        evidence: &Evidence,
        nonce: &[u8],
        created: u64,
        expires: u64,
        now: Reading,
    ) -> Result<Insert, Error> {
        let audience = self.credential.audience().to_string();
        let audience_len = u32::try_from(audience.len()).map_err(|_| Error::Value)?;
        let confirmation = evidence.artifact().ok_or(Error::Signature)?.confirmation;
        let share = crypto::sha256(
            &[
                SHARE_FORM.as_bytes(),
                &audience_len.to_be_bytes(),
                audience.as_bytes(),
                &confirmation,
            ]
            .concat(),
        );
        let deadline = Duration::from_secs(expires)
            .checked_add(self.skew)
            .ok_or(Error::Window)?;
        let margin = now
            .bound()
            .ok_or(Error::Time(TimeError::UnknownBound))?
            .saturating_mul(2);
        let end = deadline.checked_add(margin).ok_or(Error::Window)?;
        let origin = Duration::from_secs(created).saturating_sub(self.skew);
        Ok(Insert::new(&share, &crypto::sha256(nonce), end, deadline, origin))
    }

    /// Checks that a signature from `created` to `expires` is in the window of the profile at `now`.
    fn window(&self, created: u64, expires: u64, now: Reading) -> Result<(), Error> {
        let (earliest, latest) = (now.earliest().map_err(Error::Time)?, now.latest().map_err(Error::Time)?);
        expires
            .checked_sub(created)
            .filter(|&window| window > 0 && window <= self.window_max.as_secs())
            .ok_or(Error::Window)?;
        (Duration::from_secs(created) <= earliest.saturating_add(self.skew)).ok_or(Error::Early)?;
        (latest < Duration::from_secs(expires)).ok_or(Error::Expired)
    }
}

/// The `created`, the `expires`, and the nonce text of the parameters of a signature of the profile, after the checks
/// of each parameter.
fn profile_parameters<'a>(parameters: &Parameters<'a>) -> Result<(u64, u64, &'a [u8]), Error> {
    let (mut created, mut expires, mut nonce) = (None, None, None);
    // The parse refused a key twice, so each parameter has one value.
    for (key, value) in parameters {
        match (*key, *value) {
            (b"created", Bare::Integer(time)) => created = Some(time),
            (b"expires", Bare::Integer(time)) => expires = Some(time),
            (b"nonce", Bare::String(text)) => nonce = Some(text),
            // The selection of the signature checked the tag.
            (b"tag", _) => {}
            _ => return Err(Error::Parameters),
        }
    }
    let (Some(created), Some(expires), Some(nonce)) = (created, expires, nonce) else {
        return Err(Error::Parameters);
    };
    let time = |time: i64| u64::try_from(time).map_err(|_| Error::Parameters);
    let nonce_bytes = Url.decoded_len(nonce).map_err(|_| Error::Nonce)?;
    (NONCE_BYTES..=NONCE_BYTES_MAX)
        .contains(&nonce_bytes)
        .ok_or(Error::Nonce)?;
    Url.decode(nonce, &mut [0; NONCE_BYTES_MAX]).map_err(|_| Error::Nonce)?;
    Ok((time(created)?, time(expires)?, nonce))
}

/// Checks that `components` are the components of the profile, with `content-type` when the request has it.
fn covered(components: &[Item<'_>], content_type: bool) -> Result<(), Error> {
    let required: [&[u8]; 6] = [
        b"@method",
        b"@path",
        b"@query",
        CONTENT_DIGEST.as_bytes(),
        CREDENTIAL.as_bytes(),
        CONTENT_TYPE.as_bytes(),
    ];
    let required = &required[..if content_type { 6 } else { 5 }];
    // With equal counts, each required name once makes each component a required name.
    let each = required.iter().all(|name| {
        components
            .iter()
            .any(|item| item.bare == Bare::String(name) && item.parameters.is_empty())
    });
    (components.len() == required.len() && each).ok_or(Error::Components)
}

/// Checks that the `sha-256` member of `Content-Digest` is the SHA-256 digest of the body of `request`.
fn digest(request: &Request<'_>, limits: &Limits) -> Result<(), Error> {
    let malformed = |_| Error::Field(Field::ContentDigest);
    let digests = field(request, CONTENT_DIGEST, Field::ContentDigest)?;
    let digests = sf::dictionary(&digests, limits).map_err(malformed)?;
    let (_, member) = digests
        .iter()
        .find(|(key, _)| *key == b"sha-256")
        .ok_or(Error::Digest)?;
    let digest = bytes(member, 32).map_err(malformed)?;
    (*digest == crypto::sha256(request.body)).ok_or(Error::Digest)
}

/// The bytes of `member`, a byte sequence with no parameter, if it has at most `bytes_max` bytes.
fn bytes(member: &Member<'_>, bytes_max: usize) -> Result<Vec<u8>, sf::Malformed> {
    match member {
        Member::Item(Item {
            bare: Bare::Bytes(text),
            parameters,
        }) if parameters.is_empty() => sf::decode(text, bytes_max),
        Member::Item(_) | Member::List(..) => Err(sf::Malformed),
    }
}

/// The value of the field `name` of the profile in `request`, or [`Error::Field`] with `which` if it has none.
fn field<'a>(request: &Request<'a>, name: &str, which: Field) -> Result<Cow<'a, [u8]>, Error> {
    combined(request.fields, name).ok_or(Error::Field(which))
}

/// The value of the field `name` in `fields`: the value of each field of that name, with no leading or trailing
/// whitespace, joined with `, ` (RFC 9421 section 2.1). `None` if no field has the name.
fn combined<'a>(fields: &[(&str, &'a [u8])], name: &str) -> Option<Cow<'a, [u8]>> {
    let mut values = fields
        .iter()
        .filter(|(field, _)| field.eq_ignore_ascii_case(name))
        .map(|(_, value)| value.trim_ascii());
    let first = values.next()?;
    let Some(second) = values.next() else {
        return Some(Cow::Borrowed(first));
    };
    let mut value = [first, second].join(&b", "[..]);
    for next in values {
        value.extend_from_slice(b", ");
        value.extend_from_slice(next);
    }
    Some(Cow::Owned(value))
}

/// The signature base (RFC 9421 section 2.5) of `request` for the covered `components`, with the signature parameters
/// `parameters`. A component is a derived component of the profile or a field, with no parameter, each once. A field
/// value has at most [`Limits::bytes`] of `limits`.
fn base(
    request: &Request<'_>,
    components: &[Item<'_>],
    parameters: &Parameters<'_>,
    limits: &Limits,
) -> Result<Vec<u8>, Error> {
    let mut base = Vec::new();
    for (at, component) in components.iter().enumerate() {
        let (Bare::String(name), true) = (component.bare, component.parameters.is_empty()) else {
            return Err(Error::Components);
        };
        components[..at]
            .iter()
            .all(|seen| seen.bare != component.bare)
            .ok_or(Error::Components)?;
        let value: Cow<'_, [u8]> = match name {
            b"@method" => derived(request.method.as_bytes())?,
            b"@path" if request.path.is_empty() => Cow::Borrowed(b"/"),
            b"@path" => derived(request.path.as_bytes())?,
            b"@query" => {
                let query = [b"?", request.query.unwrap_or_default().as_bytes()].concat();
                derived(&query)?.into_owned().into()
            }
            _ if name.first() == Some(&b'@') || name.iter().any(u8::is_ascii_uppercase) => {
                return Err(Error::Components);
            }
            _ => {
                let name = core::str::from_utf8(name).map_err(|_| Error::Components)?;
                let value = combined(request.fields, name).ok_or(Error::Components)?;
                let visible = value.iter().all(|&byte| byte == b'\t' || (b' '..=b'~').contains(&byte));
                (visible && value.len() <= limits.bytes).ok_or(Error::Value)?;
                value
            }
        };
        base.push(b'"');
        base.extend_from_slice(name);
        base.extend_from_slice(b"\": ");
        base.extend_from_slice(&value);
        base.push(b'\n');
    }
    base.extend_from_slice(b"\"@signature-params\": ");
    sf::inner_list(components, parameters, &mut base).map_err(|_| Error::Parameters)?;
    Ok(base)
}

/// The value of a derived component: visible ASCII and spaces, with no leading or trailing space (RFC 9421 section
/// 2.2).
fn derived(value: &[u8]) -> Result<Cow<'_, [u8]>, Error> {
    let visible = !value.is_empty()
        && value.iter().all(|&byte| (b' '..=b'~').contains(&byte))
        && value.first() != Some(&b' ')
        && value.last() != Some(&b' ');
    visible.then_some(Cow::Borrowed(value)).ok_or(Error::Value)
}

/// Checks that `key` signed `base` with `signature`, after it charges `budget`.
fn check(key: &TrustedKey, base: &[u8], signature: &[u8], budget: &mut SignatureBudget) -> Result<(), Error> {
    key.verify(base, signature, budget).map_err(|error| match error {
        cose::Error::Limit(limit) => Error::Limit(limit),
        _ => Error::Signature,
    })
}

/// The base64 text of `bytes`, with padding: the text of a byte sequence (RFC 8941 section 3.3.5).
fn base64(bytes: &[u8]) -> String {
    let mut text = vec![
        0;
        Standard
            .encoded_len(bytes.len())
            .expect("the bytes of a signature and a credential are bounded")
    ];
    Standard.encode(bytes, &mut text).expect("the text has its length");
    String::from_utf8(text).expect("base64 is ASCII")
}

/// A signature that [`Profile::verify`] checked, before its replay insert. The replay store of the audience of the
/// verifier accepts it once: [`Checked::accept`] for a request that commits nothing, or [`Checked::check_agent`] for a
/// request that commits a transition. Neither path gives the evidence of the agent without the insert.
#[derive(Debug)]
#[must_use = "a signature gives its evidence only from its replay insert"]
pub struct Checked {
    evidence: Evidence,
    insert: Insert,
}

/// A refusal or a failed store read during [`Checked::check_agent`].
pub type Failure<E> = store::Failure<Error, E>;

/// The failure of a standalone replay insert in [`Checked::accept`].
#[derive(Clone, Copy, PartialEq, Eq)]
pub enum AcceptError<E> {
    /// The store confirmed that this attempt wrote nothing.
    Refused(Error),
    /// The binding failed. It may have written the replay record.
    Unknown(E),
}

impl<E> Recover for AcceptError<E> {
    fn recovery(&self) -> Recovery {
        match self {
            Self::Refused(error) => error.recovery(),
            Self::Unknown(_) => Recovery::Refuse,
        }
    }
}

impl<E> fmt::Display for AcceptError<E> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Refused(error) => error.fmt(f),
            Self::Unknown(_) => f.write_str("the outcome of the replay insert is unknown"),
        }
    }
}

// A backend error can contain request data. Both formats give only the public diagnosis.
impl<E> fmt::Debug for AcceptError<E> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        fmt::Display::fmt(self, f)
    }
}

impl<E: core::error::Error> core::error::Error for AcceptError<E> {}

impl Checked {
    /// Inserts the replay record of the signature into `store`, the replay store of the audience
    /// ([`Store::insert_replay`]), and gives the evidence of the agent. Give it to [`authz::check_agent`]. The insert
    /// is one atomic step with no audit record and no commit driver, so the requests of many agents insert
    /// concurrently.
    ///
    /// Cost class: [`Mutate`](crate::limits::Class::Mutate). One replay insert.
    ///
    /// # Errors
    ///
    /// [`Error::Conflict`] for a confirmed transaction abort, [`Error::Replayed`] for a repetition,
    /// [`Error::Floor`] for a signature before the replay floor, or [`Error::Full`] for a full store or share.
    /// [`Error::Expired`] when the store cannot establish that its reading is before the deadline.
    /// [`AcceptError::Unknown`] after a failed insert. Refuse the request. A standalone insert has no outcome record.
    pub async fn accept<S: Store>(self, store: &mut S) -> Result<Evidence, AcceptError<S::Error>> {
        let refusal = match store.insert_replay(&self.insert).await.map_err(AcceptError::Unknown)? {
            Inserted::Accepted => return Ok(self.evidence),
            Inserted::Conflict => Error::Conflict,
            Inserted::Present => Error::Replayed,
            Inserted::Floor => Error::Floor,
            Inserted::Full => Error::Full,
            Inserted::Expired => Error::Expired,
        };
        Err(AcceptError::Refused(refusal))
    }

    /// Checks the grant of a request that commits a transition, as [`authz::check_agent`] does, and gives the scope with
    /// the replay insert of the signature. The request takes its proposal from that scope ([`Pending::propose`]), so
    /// its commit accepts the signature once. The check first reads the replay floor of `store`, the replay store of
    /// the audience. Do each effect of the operation in that commit: for an effect outside the store, such as a call to
    /// another service, call [`Checked::accept`] before the effect.
    ///
    /// Cost class: [`Verify`](crate::limits::Class::Verify). One keyed read, then the cost of [`authz::check_agent`].
    ///
    /// # Errors
    ///
    /// [`Error::Floor`] if the store has no replay floor, or the signature was created before it. [`Error::Grant`] if
    /// the grant check refuses. [`Failure::Store`] for a failed read.
    pub async fn check_agent<S: Store>(
        self,
        grants: &Grants,
        store: &mut S,
        action: &Id<Action>,
        resource: &Id<Resource>,
        policy: &impl Policy,
        now: Reading,
    ) -> Result<Pending, Failure<S::Error>> {
        let floor = store
            .read(&store::floor_key())
            .await
            .map_err(Failure::Store)?
            .ok_or(Error::Floor)?;
        let end = store::driver::record::floor_end(&floor.data).ok_or(Error::Floor)?;
        (self.insert.origin() > end).ok_or(Error::Floor)?;
        let scope = authz::check_agent(grants, store, &self.evidence, action, resource, policy, now)
            .await
            .map_err(|failure| match failure {
                store::Failure::Refused(error) => Failure::Refused(Error::Grant(error)),
                store::Failure::Store(error) => Failure::Store(error),
            })?;
        Ok(Pending {
            scope,
            insert: self.insert,
            floor: floor.version,
        })
    }
}

/// The scope of a signed request that commits a transition, with the replay insert of its signature
/// ([`Checked::check_agent`]). The request takes its proposal from it.
#[derive(Debug)]
#[must_use = "a signed request that commits takes its proposal from its pending scope"]
pub struct Pending {
    scope: Granted,
    insert: Insert,
    /// The version of the replay floor record that the check read.
    floor: AuthorityVersion,
}

impl Pending {
    /// The scope of the request, and the proposal of [`Granted::propose`] with the replay insert of the signature. The
    /// commit reads the replay floor at the version that the check read and the absence of the replay record, writes
    /// the record, and ends at `expires` plus the skew. Thus a repetition conflicts, a full store refuses with
    /// [`transition::Error::Full`], and a commit at or after that time refuses with [`transition::Error::Expired`]. Add
    /// the changes of the operation to the proposal, and enforce the scope at each use ([`Granted::enforce`]).
    ///
    /// Cost class: [`Parse`](crate::limits::Class::Parse).
    ///
    /// # Errors
    ///
    /// The errors of [`Granted::propose`], and a [`transition::Error`] if the proposal cannot take the replay insert.
    pub fn propose(
        self,
        operation: OperationId,
        request: Value<'_>,
        now: Reading,
    ) -> Result<(Granted, Proposal), transition::Error> {
        let mut proposal = self.scope.propose(operation, request, now)?;
        // The read of the floor at its version fences a commit of another instance: each start writes the floor again.
        proposal.read(Dependency::Version(store::floor_key(), self.floor))?;
        proposal.read(Dependency::Absent(self.insert.key().clone()))?;
        let record = self.insert.record();
        proposal.change(Change::Write {
            key: self.insert.key().clone(),
            version: record.version,
            end: record.end,
            data: record.data,
        })?;
        proposal.until(self.insert.deadline());
        Ok((self.scope, proposal))
    }
}

/// A field of the profile.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Field {
    /// `Signature-Input`: the components and the parameters of each signature.
    SignatureInput,
    /// `Signature`: the bytes of each signature.
    Signature,
    /// `Content-Digest`: the digest of the body.
    ContentDigest,
    /// `Agent-Credential` ([`CREDENTIAL`]): the agent credential.
    Credential,
}

/// The cause of a refused request or draft. [`Recover::recovery`] gives the caller's next action.
/// No error holds a byte of the request.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Error {
    /// A field of the profile is missing, longer than [`Limits::bytes`], or not valid. Each signature field is a
    /// dictionary, `Content-Digest` is a dictionary, and the credential is one byte sequence.
    Field(Field),
    /// No signature has the tag [`TAG`], or more than one has it.
    Tag,
    /// The covered components are not the components of the profile: another component, a component twice, a
    /// component with a parameter, or no `content-type` for a request that has it.
    Components,
    /// The parameters are not `created`, `expires`, `nonce`, and `tag`, each once, or a time is not a whole number of
    /// seconds since the Unix epoch.
    Parameters,
    /// The nonce is not the base64url of [`NONCE_BYTES`] to [`NONCE_BYTES_MAX`] bytes.
    Nonce,
    /// `expires` is not after `created`, or the window is longer than the longest window of the profile. For a draft,
    /// the lifetime is under one second.
    Window,
    /// `created` is later than the time of the verifier plus the skew. Check the clock of the agent.
    Early,
    /// The time of the verifier can be at or after `expires`, or the time of the replay store at the insert can be at
    /// or after `expires` plus the skew. Sign the request again.
    Expired,
    /// The `Content-Digest` has no `sha-256` member, or it is not the digest of the body.
    Digest,
    /// A covered value cannot go into the signature base: an empty or not visible derived value, or a field value with a
    /// byte that is not visible ASCII.
    Value,
    /// The credential refused.
    Credential(credential::Error),
    /// The signature does not verify with the `cnf` key of the credential.
    Signature,
    /// A signature check costs more than its budget.
    Limit(Limit),
    /// The reading of the time has no bound. Use a reading with a bound.
    Time(TimeError),
    /// The replay store holds the replay record of the signature: the request is a repetition. The repetition does not
    /// show whether the first request committed: the operation identity of the transition shows that.
    Replayed,
    /// The replay store confirmed that contention aborted this insert with no write. The caller can try again.
    Conflict,
    /// The replay store has no replay floor of its current start, or the signature was created before the floor. A start
    /// or a restore sets the floor, so a captured request cannot repeat after it. Sign the request again.
    Floor,
    /// The replay store has no room: its capacity, or the share of the agent key, is full. Sign the request again later.
    Full,
    /// The grant check of a request that commits refused ([`Checked::check_agent`]).
    Grant(grant::Error),
}

impl Recover for Error {
    /// The caller can start again after a confirmed replay conflict or a full store.
    fn recovery(&self) -> Recovery {
        match self {
            Self::Full | Self::Conflict => Recovery::Restart,
            Self::Grant(error) => error.recovery(),
            _ => Recovery::Refuse,
        }
    }
}

impl fmt::Display for Error {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Field(field) => {
                let name = match field {
                    Field::SignatureInput => "Signature-Input",
                    Field::Signature => "Signature",
                    Field::ContentDigest => "Content-Digest",
                    Field::Credential => "Agent-Credential",
                };
                write!(f, "the {name} field of the request is missing or not valid")
            }
            Self::Tag => f.write_str("the request does not have exactly one signature of the profile"),
            Self::Components => f.write_str("the signature does not cover the components of the profile"),
            Self::Parameters => f.write_str("the signature does not have the parameters of the profile"),
            Self::Nonce => f.write_str("the nonce of the signature does not have 128 to 256 bits"),
            Self::Window => f.write_str("the window of the signature is empty or too long"),
            Self::Early => f.write_str("the signature was created after the time of the verifier"),
            Self::Expired => f.write_str("the signature expired"),
            Self::Digest => f.write_str("the content digest is not the digest of the body"),
            Self::Value => f.write_str("a covered value cannot go into the signature base"),
            Self::Credential(error) => write!(f, "the credential refused: {error}"),
            Self::Signature => f.write_str("the signature does not verify with the key of the credential"),
            Self::Limit(limit) => write!(f, "the signature check exceeds {limit:?}"),
            Self::Time(error) => write!(f, "the time refused: {error}"),
            Self::Replayed => f.write_str("the replay store holds the signature: the request is a repetition"),
            Self::Conflict => f.write_str("the replay store aborted the insert because of contention"),
            Self::Floor => f.write_str("the signature was created before the replay floor of the store"),
            Self::Full => f.write_str("the replay store has no room for the signature"),
            Self::Grant(error) => write!(f, "the grant check refused: {error}"),
        }
    }
}

impl core::error::Error for Error {}

impl From<credential::Error> for Error {
    fn from(error: credential::Error) -> Self {
        Self::Credential(error)
    }
}
