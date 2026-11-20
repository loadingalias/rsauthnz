//! CWT claims (RFC 8392), the `cnf` claim (RFC 8747), and verification with a trusted profile.

use alloc::string::String;
use alloc::vec::Vec;
use core::fmt;
use core::time::Duration;

use super::{Error, Key, Sign1, TrustedKey};
use crate::cbor::{self, Value};
use crate::id::{Id, Purpose};
use crate::limits::{Limits, SignatureBudget};
use crate::time::Reading;

/// The CWT tag (RFC 8392 section 6). It can enclose the tagged `COSE_Sign1`.
const CWT_TAG: u64 = 61;

/// The claims of a CWT. Each value is untrusted until [`Profile::verify`] succeeds.
#[derive(Clone, Debug, PartialEq)]
#[non_exhaustive]
pub struct Claims<'a> {
    /// `iss` (1).
    pub iss: Option<&'a str>,
    /// `sub` (2).
    pub sub: Option<&'a str>,
    /// `aud` (3): one audience, or each audience of an array. It is empty when the claim is missing.
    pub aud: Vec<&'a str>,
    /// `exp` (4), as the time since the Unix epoch.
    pub exp: Option<Duration>,
    /// `nbf` (5), as the time since the Unix epoch.
    pub nbf: Option<Duration>,
    /// `iat` (6), as the time since the Unix epoch.
    pub iat: Option<Duration>,
    /// `cti` (7).
    pub cti: Option<&'a [u8]>,
    /// `cnf` (8).
    pub cnf: Option<Confirmation<'a>>,
    /// Each other claim, in the order of the decoder. Verification does not read them.
    pub other: Vec<(Value<'a>, Value<'a>)>,
}

/// The proof-of-possession key of the `cnf` claim (RFC 8747).
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Confirmation<'a> {
    /// The `COSE_Key` (1) member: the public key.
    Key(Key<'a>),
    /// The `kid` (3) member: the identifier of a key that the recipient knows.
    KeyId(&'a [u8]),
}

impl<'a> Claims<'a> {
    /// Decodes the claims map that fills `input`, such as the payload of a CWT.
    ///
    /// Cost class: [`Parse`](crate::limits::Class::Parse).
    ///
    /// # Errors
    ///
    /// [`Error::Cbor`] if the CBOR decoder refuses `input`. [`Error::Unsupported`] for an encrypted `cnf` key and a
    /// `cnf` key that [`Key::from_value`] does not support. [`Error::Malformed`] if `input` is not a map, a claim of
    /// RFC 8392 or RFC 8747 has the wrong type, a time is negative, or `cnf` holds no key or two keys.
    pub fn decode(input: &'a [u8], limits: Limits) -> Result<Self, Error> {
        let Value::Map(entries) = cbor::decode(input, limits)? else {
            return Err(Error::Malformed);
        };
        let mut claims = Self {
            iss: None,
            sub: None,
            aud: Vec::new(),
            exp: None,
            nbf: None,
            iat: None,
            cti: None,
            cnf: None,
            other: Vec::new(),
        };
        // The decoder refuses equal keys, so each claim has one value.
        for (key, value) in entries {
            match key {
                Value::Unsigned(1) => claims.iss = Some(text(&value)?),
                Value::Unsigned(2) => claims.sub = Some(text(&value)?),
                Value::Unsigned(3) => {
                    claims.aud = match &value {
                        Value::Array(audiences) if !audiences.is_empty() => {
                            audiences.iter().map(text).collect::<Result<_, _>>()?
                        }
                        value => alloc::vec![text(value)?],
                    }
                }
                Value::Unsigned(4) => claims.exp = Some(time(&value)?),
                Value::Unsigned(5) => claims.nbf = Some(time(&value)?),
                Value::Unsigned(6) => claims.iat = Some(time(&value)?),
                Value::Unsigned(7) => match value {
                    Value::Bytes(cti) => claims.cti = Some(cti),
                    _ => return Err(Error::Malformed),
                },
                Value::Unsigned(8) => claims.cnf = Some(Confirmation::from_value(&value)?),
                key => claims.other.push((key, value)),
            }
        }
        Ok(claims)
    }
}

impl<'a> Confirmation<'a> {
    /// Reads a `cnf` map. It ignores the members that it does not know, as RFC 8747 section 3.1 requires.
    fn from_value(value: &Value<'a>) -> Result<Self, Error> {
        let Value::Map(entries) = value else {
            return Err(Error::Malformed);
        };
        let get = |member: u64| {
            entries
                .iter()
                .find(|(key, _)| *key == Value::Unsigned(member))
                .map(|(_, value)| value)
        };
        match (get(1), get(2), get(3)) {
            (Some(key), None, None) => Ok(Self::Key(Key::from_value(key)?)),
            (None, None, Some(Value::Bytes(kid))) => Ok(Self::KeyId(kid)),
            (None, Some(_), None) => Err(Error::Unsupported),
            _ => Err(Error::Malformed),
        }
    }
}

fn text<'a>(value: &Value<'a>) -> Result<&'a str, Error> {
    match value {
        Value::Text(text) => Ok(text),
        _ => Err(Error::Malformed),
    }
}

/// A `NumericDate`: the seconds since the Unix epoch, as an integer or a float.
fn time(value: &Value<'_>) -> Result<Duration, Error> {
    match value {
        Value::Unsigned(seconds) => Ok(Duration::from_secs(*seconds)),
        Value::Float(seconds) => Duration::try_from_secs_f64(*seconds).map_err(|_| Error::Malformed),
        _ => Err(Error::Malformed),
    }
}

/// A trusted verification profile: the facts that the application fixes before it reads an artifact. One profile
/// serves one purpose. Give each purpose its own key, so an artifact of one purpose never verifies for another.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Profile {
    /// The key and its algorithm.
    pub key: TrustedKey,
    /// The issuer: the `iss` claim must be equal, byte for byte.
    pub issuer: String,
    /// The audience: the `aud` claim must name it, byte for byte.
    pub audience: String,
    /// The purpose of the artifacts that the profile accepts.
    pub purpose: Id<Purpose>,
    /// The bounds of the decode of the artifact and of its claims.
    pub limits: Limits,
}

impl Profile {
    /// Verifies the signed CWT `artifact` at the physical time `now`. `artifact` is a `COSE_Sign1` with the tag 18 or
    /// no tag, and the CWT tag (61) can enclose it. The signature check charges `budget`, the budget of the artifact.
    ///
    /// Cost class: [`Verify`](crate::limits::Class::Verify).
    ///
    /// The checks of the claims come first, because they are cheap. The signature check comes last. Thus
    /// [`Error::Issuer`], [`Error::Audience`], [`Error::NoExpiry`], [`Error::Expired`], and [`Error::NotYetValid`] can
    /// come before the signature check, and such a refusal does not show that the artifact is authentic. The artifact
    /// is valid while `nbf <= t < exp` for each time `t` that `now` permits.
    ///
    /// # Errors
    ///
    /// The errors of [`Sign1::decode`], [`Claims::decode`], and [`Sign1::verify`]. [`Error::Issuer`],
    /// [`Error::Audience`], [`Error::NoExpiry`], [`Error::Expired`], and [`Error::NotYetValid`] for the claims, and
    /// [`Error::Time`] if `now` has no known bound.
    pub fn verify<'a>(
        &self,
        artifact: &'a [u8],
        now: Reading,
        budget: &mut SignatureBudget,
    ) -> Result<Verified<'a, '_>, Error> {
        let value = match cbor::decode(artifact, self.limits)? {
            Value::Tag(CWT_TAG, item) => *item,
            value => value,
        };
        let sign1 = Sign1::from_value(value, self.limits)?;
        let claims = Claims::decode(sign1.payload(), self.limits)?;
        if claims.iss != Some(self.issuer.as_str()) {
            return Err(Error::Issuer);
        }
        if !claims.aud.contains(&self.audience.as_str()) {
            return Err(Error::Audience);
        }
        let expires = claims.exp.ok_or(Error::NoExpiry)?;
        if now.latest()? >= expires {
            return Err(Error::Expired);
        }
        // `now.latest()` proved a known bound. An earliest time before the Unix epoch is before each `nbf`.
        if claims
            .nbf
            .is_some_and(|nbf| nbf > now.earliest().unwrap_or(Duration::ZERO))
        {
            return Err(Error::NotYetValid);
        }
        sign1.verify(&self.key, budget)?;
        Ok(Verified {
            artifact,
            profile: self,
            claims,
            expires,
        })
    }
}

/// The evidence of one verified CWT. It holds the exact bytes of the artifact and the profile that verified it: the
/// issuer, the audience, the key, the algorithm, and the purpose. Two values are equal only for equal artifact bytes
/// and equal profiles. A valid signature alone does not give current permission.
#[derive(Clone, PartialEq)]
pub struct Verified<'a, 'p> {
    artifact: &'a [u8],
    profile: &'p Profile,
    claims: Claims<'a>,
    expires: Duration,
}

impl<'a, 'p> Verified<'a, 'p> {
    /// The exact bytes of the artifact.
    #[must_use]
    pub const fn artifact(&self) -> &'a [u8] {
        self.artifact
    }

    /// The profile that verified the artifact.
    #[must_use]
    pub const fn profile(&self) -> &'p Profile {
        self.profile
    }

    /// The verified claims.
    #[must_use]
    pub const fn claims(&self) -> &Claims<'a> {
        &self.claims
    }

    /// The start of the validity interval: `nbf`, or `None` when the claims have no `nbf`.
    #[must_use]
    pub const fn not_before(&self) -> Option<Duration> {
        self.claims.nbf
    }

    /// The end of the validity interval: `exp`. The artifact is not valid at this time and after it.
    #[must_use]
    pub const fn expires(&self) -> Duration {
        self.expires
    }
}

// The artifact can be a bearer credential. Thus the output shows only its length.
impl fmt::Debug for Verified<'_, '_> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("Verified")
            .field("artifact_len", &self.artifact.len())
            .field("profile", &self.profile)
            .field("claims", &self.claims)
            .finish()
    }
}
