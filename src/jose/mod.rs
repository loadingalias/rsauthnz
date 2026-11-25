//! JOSE: the JWS compact serialization ([RFC 7515]) and the claims of a JWT ([RFC 7519]) and of a JWT access token
//! ([RFC 9068]), under trusted profiles.
//!
//! A [`Profile`] fixes the algorithm and the keys of the tokens that it accepts, and the issuer, the audience, and the
//! kind of each JWT. A header can only match the profile: an `alg` that names another algorithm refuses, also `none`
//! and each HMAC algorithm, and a `kid` selects only among the keys of the profile. A header that names a key URL or
//! carries a key (`jku`, `jwk`, `x5u`, `x5c`, `x5t`, `x5t#S256`) refuses, and so do `crit` and `b64`.
//!
//! The JOSE names are `Ed25519` ([RFC 9864], which also takes the `EdDSA` of [RFC 8037]), `ES256`, `RS256`, `PS256`,
//! `ML-DSA-65` ([RFC 9964]), [`ML_DSA_65_ED25519`], and [`ML_DSA_65_ES256`]. RS256 and PS256 only verify.
//!
//! [`Profile::verify`] checks a JWS and gives its payload. [`Profile::verify_jwt`] also checks the claims at a time
//! reading with its bound: the issuer, the audience, `exp`, and `nbf`. [`signing_input`] and [`compact`] make a JWS:
//! sign the bytes of the signing input with the key, such as in custody, then join the signature.
//!
//! ```
//! use rsauthnz::crypto::Algorithm;
//! use rsauthnz::jose::{Error, Kind, Profile};
//! use rsauthnz::limits::Limits;
//!
//! // The Ed25519 key and the JWS of RFC 8037, appendix A.
//! let set = br#"{"keys":[{"kty":"OKP","crv":"Ed25519","x":"11qYAYKxCrfVS_7TyWQHOg7hcvPapiMlrwIaaPcHURo"}]}"#;
//! let profile = Profile::new(Algorithm::Ed25519, Kind::Jwt, "https://issuer.example", "https://api.example", Limits::default())?
//!     .with_key_set(set)?;
//! let token = "eyJhbGciOiJFZERTQSJ9.RXhhbXBsZSBvZiBFZDI1NTE5IHNpZ25pbmc.hgyY0il_MGCjP0JzlnLWG1PPOt7-09PGcvMg3AIbQR6dWbhijcNR4ki4iylGjg5BhVsPt9g7sVvpAr_MuM0KAg";
//! assert_eq!(profile.verify(token)?.payload(), b"Example of Ed25519 signing");
//!
//! // The header `{"alg":"none"}` refuses: the profile fixes the algorithm.
//! let forged = token.replacen("eyJhbGciOiJFZERTQSJ9", "eyJhbGciOiJub25lIn0", 1);
//! assert_eq!(profile.verify(&forged).err(), Some(Error::Algorithm));
//! # Ok::<(), Box<dyn core::error::Error>>(())
//! ```
//!
//! [RFC 7515]: https://www.rfc-editor.org/rfc/rfc7515
//! [RFC 7519]: https://www.rfc-editor.org/rfc/rfc7519
//! [RFC 8037]: https://www.rfc-editor.org/rfc/rfc8037
//! [RFC 9068]: https://www.rfc-editor.org/rfc/rfc9068
//! [RFC 9864]: https://www.rfc-editor.org/rfc/rfc9864
//! [RFC 9964]: https://www.rfc-editor.org/rfc/rfc9964

use alloc::boxed::Box;
use alloc::string::String;
use alloc::vec;
use alloc::vec::Vec;
use core::fmt;
use core::time::Duration;

use rscodec::base64::Profile::Url;
use rscodec::json::{self, Profile::IJson, Slot, Str};

use crate::cose::{Key, PublicKey, TrustedKey};
use crate::crypto::Algorithm;
use crate::limits::{Limits, SignatureBudget};
use crate::time::{Reading, TimeError};

/// The most bytes of a token. A composite signature is 3,373 bytes, 4,498 in base64url.
pub const TOKEN_BYTES_MAX: usize = 16 * 1024;

/// The most keys of a profile, also from a key set.
pub const KEYS_MAX: usize = 16;

/// Draft 06 names ML-DSA-65 + Ed25519. Draft 07 omits this profile. IANA lists no assignment.
pub const ML_DSA_65_ED25519: &str = "ML-DSA-65-Ed25519";

/// Drafts 06 and 07 name ML-DSA-65 + ECDSA P-256. IANA lists no assignment.
pub const ML_DSA_65_ES256: &str = "ML-DSA-65-ES256";

/// The limits of a header.
const HEADER: json::Limits = json::Limits {
    input_bytes_max: 4096,
    depth_max: 2,
    string_bytes_max: 1024,
    members_max: 16,
    elements_max: 16,
    number_digits_max: 32,
};

/// The limits of the claims of a JWT.
const CLAIMS: json::Limits = json::Limits {
    input_bytes_max: 12 * 1024,
    depth_max: 8,
    string_bytes_max: 4096,
    members_max: 64,
    elements_max: 64,
    number_digits_max: 32,
};

/// The limits of a key set. The longest key is a composite ML-DSA-65 + ECDSA P-256 key: 2,690 characters.
const KEY_SET: json::Limits = json::Limits {
    input_bytes_max: 128 * 1024,
    depth_max: 4,
    string_bytes_max: 4096,
    members_max: 32,
    // `KEYS_MAX`: a set with more keys refuses at its limit.
    elements_max: 16,
    number_digits_max: 32,
};

/// The header members that name a key URL or carry a key, `crit`, and `b64`: each one refuses the token. RFC 7797
/// requires `crit` with `b64`, so no `b64` is valid here.
const REFUSED: [&str; 8] = ["jku", "jwk", "x5u", "x5c", "x5t", "x5t#S256", "crit", "b64"];

/// The members of a private JWK. A key set is public, so each one refuses the set.
const PRIVATE: [&str; 9] = ["d", "p", "q", "dp", "dq", "qi", "oth", "k", "priv"];

/// The slots of the reader: each open container, and each key of each open object.
const SLOTS: usize = 8 * (64 + 1);

/// The JOSE `alg` of `algorithm`, which a signature writes, or `None` for SLH-DSA, which has no JOSE name, and for
/// ES384, which this crate verifies only in X.509.
///
/// Cost class: [`Parse`](crate::limits::Class::Parse).
#[must_use]
pub const fn alg(algorithm: Algorithm) -> Option<&'static str> {
    match algorithm {
        Algorithm::Ed25519 => Some("Ed25519"),
        Algorithm::Es256 => Some("ES256"),
        Algorithm::Rs256 => Some("RS256"),
        Algorithm::Ps256 => Some("PS256"),
        Algorithm::MlDsa65 => Some("ML-DSA-65"),
        Algorithm::MlDsa65Ed25519 => Some(ML_DSA_65_ED25519),
        Algorithm::MlDsa65EcdsaP256 => Some(ML_DSA_65_ES256),
        Algorithm::Es384 | Algorithm::SlhDsaSha2_128s => None,
    }
}

/// Whether `name` names `algorithm`: its JOSE name, and also `EdDSA` for Ed25519.
fn names(algorithm: Algorithm, name: Str<'_>) -> bool {
    alg(algorithm).is_some_and(|alg| name == alg) || (algorithm == Algorithm::Ed25519 && name == "EdDSA")
}

/// The kind of the JWTs of a profile.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub enum Kind {
    /// A JWT with any `typ`, or none.
    Jwt,
    /// A JWT access token of RFC 9068: `typ` is `at+jwt`, and the claims hold `sub`, `client_id`, `iat`, and `jti`.
    Access,
}

/// A trusted verification profile: the algorithm and the keys of the tokens that it accepts, and the kind, the issuer,
/// and the audience of each JWT.
#[derive(Clone, Debug)]
pub struct Profile {
    algorithm: Algorithm,
    kind: Kind,
    issuer: Box<str>,
    audience: Box<str>,
    keys: Vec<Entry>,
    limits: Limits,
}

impl Profile {
    /// The profile of `algorithm` for the JWTs of `kind` from `issuer` to `audience`, with no key yet. `limits` bound
    /// the signature checks of each token.
    ///
    /// Cost class: [`Parse`](crate::limits::Class::Parse).
    ///
    /// # Errors
    ///
    /// [`Error::Algorithm`] if `algorithm` has no JOSE name.
    pub fn new(algorithm: Algorithm, kind: Kind, issuer: &str, audience: &str, limits: Limits) -> Result<Self, Error> {
        alg(algorithm).ok_or(Error::Algorithm)?;
        Ok(Self {
            algorithm,
            kind,
            issuer: issuer.into(),
            audience: audience.into(),
            keys: Vec::new(),
            limits,
        })
    }

    /// The profile with the trusted key `key`, which a header selects with the key ID `kid`. A header with no `kid`
    /// selects the key of a profile that has one key.
    ///
    /// Cost class: [`Parse`](crate::limits::Class::Parse).
    ///
    /// # Errors
    ///
    /// [`Error::Key`] if `key` has another algorithm, and [`Error::Limit`] if the profile has [`KEYS_MAX`] keys.
    pub fn with_key(mut self, kid: Option<&str>, key: TrustedKey) -> Result<Self, Error> {
        (key.algorithm() == self.algorithm).ok_or(Error::Key)?;
        (self.keys.len() < KEYS_MAX).ok_or(Error::Limit)?;
        self.keys.push((kid.map(Into::into), key));
        Ok(self)
    }

    /// The profile with each key of the JWK set `set` ([RFC 7517]) whose type fits the algorithm of the profile. A key
    /// whose `alg` names another algorithm, whose `use` is not `sig`, or whose `key_ops` has no `verify` does not join.
    /// A key whose `alg`, `use`, or `key_ops` the reader cannot read does not join either: a `key_ops` is an array of
    /// distinct strings (RFC 7517 section 4.3). A set is public, so a private member of any key refuses the set.
    ///
    /// Cost class: [`Verify`](crate::limits::Class::Verify). A P-256 key checks its point, and an RSA key its modulus.
    ///
    /// # Errors
    ///
    /// [`Error::Key`] if a key has a private member or a key of the type of the profile is not valid. [`Error::Limit`]
    /// if the profile would have more than [`KEYS_MAX`] keys, and [`Error::Malformed`] if `set` is not a JWK set.
    ///
    /// [RFC 7517]: https://www.rfc-editor.org/rfc/rfc7517
    pub fn with_key_set(mut self, set: &[u8]) -> Result<Self, Error> {
        let mut scratch = [Slot::EMPTY; SLOTS];
        let jwks = json::read(set, &KEY_SET, IJson, &mut scratch, |reader| {
            let mut jwks = Vec::new();
            let mut members = reader.value().members()?;
            while let Some((name, value)) = members.next()? {
                if name != "keys" {
                    continue;
                }
                let mut keys = value.elements()?;
                while let Some(key) = keys.next()? {
                    let mut jwk = Jwk::default();
                    let mut members = key.members()?;
                    while let Some((name, mut value)) = members.next()? {
                        if PRIVATE.iter().any(|private| name == *private) {
                            jwk.private = true;
                            continue;
                        }
                        if name == "key_ops" {
                            let mut ops: Vec<Str<'_>> = Vec::new();
                            let mut valid = value.kind()? == json::Kind::Array;
                            if valid {
                                let mut items = value.elements()?;
                                while let Some(mut item) = items.next()? {
                                    if item.kind()? == json::Kind::String {
                                        let op = item.str()?;
                                        valid &= !ops.contains(&op);
                                        ops.push(op);
                                    } else {
                                        valid = false;
                                    }
                                }
                            }
                            jwk.verify = Some(valid && ops.iter().any(|op| *op == "verify"));
                            continue;
                        }
                        let text = (value.kind()? == json::Kind::String).then(|| value.str()).transpose()?;
                        // A restriction that the reader cannot read keeps the key out (RFC 7517 section 5).
                        jwk.unreadable |= text.is_none() && (name == "alg" || name == "use");
                        let slot = [
                            ("kty", &mut jwk.kty),
                            ("crv", &mut jwk.crv),
                            ("alg", &mut jwk.alg),
                            ("use", &mut jwk.usage),
                            ("kid", &mut jwk.kid),
                            ("x", &mut jwk.x),
                            ("y", &mut jwk.y),
                            ("n", &mut jwk.n),
                            ("e", &mut jwk.e),
                            ("pub", &mut jwk.public),
                        ]
                        .into_iter()
                        .find(|(known, _)| name == *known);
                        if let Some((_, slot)) = slot {
                            *slot = text;
                        }
                    }
                    jwks.push(jwk);
                }
            }
            Ok(jwks)
        })
        .map_err(|_| Error::Malformed)?;
        for jwk in jwks {
            if let Some(key) = jwk.key(self.algorithm)? {
                (self.keys.len() < KEYS_MAX).ok_or(Error::Limit)?;
                self.keys.push(key);
            }
        }
        Ok(self)
    }

    /// Whether the profile has a key.
    pub(crate) fn has_keys(&self) -> bool {
        !self.keys.is_empty()
    }

    /// Checks the JWS `token` in the compact serialization, and gives its header and its payload. The token has at
    /// most [`TOKEN_BYTES_MAX`] bytes.
    ///
    /// Cost class: [`Verify`](crate::limits::Class::Verify). One signature check, after the checks of the header.
    ///
    /// # Errors
    ///
    /// - [`Error::Limit`] if the token is longer than [`TOKEN_BYTES_MAX`], or the signature checks pass the limits.
    /// - [`Error::Algorithm`] if `alg` does not name the algorithm of the profile, such as `none` or `HS256`.
    /// - [`Error::Header`] if the header names a key URL or carries a key, or has `crit` or `b64`.
    /// - [`Error::Key`] if no key of the profile has the `kid` of the header, or the header has no `kid` and the
    ///   profile has more than one key.
    /// - [`Error::Signature`] if the signature does not verify, and [`Error::Malformed`] for each other difference from
    ///   the compact serialization.
    pub fn verify(&self, token: &str) -> Result<Jws, Error> {
        (token.len() <= TOKEN_BYTES_MAX).ok_or(Error::Limit)?;
        let (input, signature) = token.rsplit_once('.').ok_or(Error::Malformed)?;
        let (header, payload) = input.split_once('.').ok_or(Error::Malformed)?;
        (!payload.contains('.')).ok_or(Error::Malformed)?;
        let header_json = base64url(header.as_bytes())?;
        let mut scratch = [Slot::EMPTY; SLOTS];
        let (algorithm, kid, typ) = json::read(&header_json, &HEADER, IJson, &mut scratch, |reader| {
            let (mut algorithm, mut kid, mut typ, mut refused) = (None, None, None, false);
            let mut members = reader.value().members()?;
            while let Some((name, value)) = members.next()? {
                // `==` compares after unescape, so a name with an escape is the same name.
                if name == "alg" {
                    algorithm = Some(value.str()?);
                } else if name == "kid" {
                    kid = Some(value.str()?);
                } else if name == "typ" {
                    typ = Some(value.str()?);
                } else if REFUSED.iter().any(|refused| name == *refused) {
                    value.skip()?;
                    refused = true;
                }
            }
            Ok((algorithm.filter(|_| !refused).ok_or(refused), kid, typ))
        })
        .map_err(|_| Error::Malformed)?;
        let algorithm = algorithm.map_err(|refused| if refused { Error::Header } else { Error::Malformed })?;
        names(self.algorithm, algorithm).ok_or(Error::Algorithm)?;
        let kid = kid.map(text).transpose()?;
        let key = match &kid {
            Some(kid) => self.keys.iter().find(|(id, _)| id.as_deref() == Some(kid.as_str())),
            None => self.keys.first().filter(|_| self.keys.len() == 1),
        };
        let (_, key) = key.ok_or(Error::Key)?;
        let signature = base64url(signature.as_bytes())?;
        key.verify(input.as_bytes(), &signature, &mut SignatureBudget::new(&self.limits))
            .map_err(|error| match error {
                crate::cose::Error::Limit(_) => Error::Limit,
                _ => Error::Signature,
            })?;
        Ok(Jws {
            kid: kid.map(String::into_boxed_str),
            typ: typ.map(text).transpose()?.map(String::into_boxed_str),
            payload: base64url(payload.as_bytes())?.into(),
        })
    }

    /// Checks the JWT `token` ([`Self::verify`]) and its claims at `now`: the issuer and the audience of the profile,
    /// `exp` after the latest time of `now`, and `nbf`, if present, at or before its earliest time. A profile of
    /// [`Kind::Access`] also checks `typ` and the claims of RFC 9068. Each time is a whole number of seconds since the
    /// Unix epoch.
    ///
    /// Cost class: [`Verify`](crate::limits::Class::Verify). The checks of [`Self::verify`].
    ///
    /// # Errors
    ///
    /// The errors of [`Self::verify`]. [`Error::Type`] if `typ` is not `at+jwt` for [`Kind::Access`].
    /// [`Error::Issuer`], [`Error::Audience`], [`Error::Expired`], and [`Error::NotYet`] for the claims, and
    /// [`Error::Claims`] if a required claim is missing or has another type. [`Error::Time`] if `now` has no bound.
    pub fn verify_jwt(&self, token: &str, now: Reading) -> Result<Jwt, Error> {
        let jws = self.verify(token)?;
        if self.kind == Kind::Access {
            jws.typ
                .as_deref()
                .is_some_and(|typ| {
                    let typ = typ.to_ascii_lowercase();
                    typ.strip_prefix("application/").unwrap_or(&typ) == "at+jwt"
                })
                .ok_or(Error::Type)?;
        }
        let claims = Claims::parse(&jws.payload)?;
        (claims.iss.as_deref() == Some(&*self.issuer)).ok_or(Error::Issuer)?;
        claims
            .aud
            .iter()
            .any(|aud| **aud == *self.audience)
            .ok_or(Error::Audience)?;
        let exp = claims.exp.ok_or(Error::Claims)?;
        (now.latest().map_err(Error::Time)? < Duration::from_secs(exp)).ok_or(Error::Expired)?;
        if let Some(nbf) = claims.nbf {
            (now.earliest().map_err(Error::Time)? >= Duration::from_secs(nbf)).ok_or(Error::NotYet)?;
        }
        if self.kind == Kind::Access {
            (claims.sub.is_some() && claims.client_id.is_some() && claims.iat.is_some() && claims.jti.is_some())
                .ok_or(Error::Claims)?;
        }
        Ok(Jwt { jws, claims })
    }
}

/// A key of a profile: its key ID, and the trusted key.
type Entry = (Option<Box<str>>, TrustedKey);

/// The members of a JWK that a key set reads.
#[derive(Default)]
struct Jwk<'a> {
    kty: Option<Str<'a>>,
    crv: Option<Str<'a>>,
    alg: Option<Str<'a>>,
    usage: Option<Str<'a>>,
    kid: Option<Str<'a>>,
    x: Option<Str<'a>>,
    y: Option<Str<'a>>,
    n: Option<Str<'a>>,
    e: Option<Str<'a>>,
    public: Option<Str<'a>>,
    /// Whether `key_ops` permits a signature check, or `None` with no `key_ops`.
    verify: Option<bool>,
    /// Whether the reader could not read the `alg` or the `use` of the key.
    unreadable: bool,
    private: bool,
}

impl Jwk<'_> {
    /// The key ID and the trusted key of the JWK for `algorithm`, or `None` if its type, its `alg`, its `use`, or its
    /// `key_ops` does not fit.
    fn key(&self, algorithm: Algorithm) -> Result<Option<Entry>, Error> {
        (!self.private).ok_or(Error::Key)?;
        let fits = self.kty.is_some_and(|kty| match algorithm {
            Algorithm::Ed25519 => kty == "OKP" && self.crv.is_some_and(|crv| crv == "Ed25519"),
            Algorithm::Es256 => kty == "EC" && self.crv.is_some_and(|crv| crv == "P-256"),
            Algorithm::Rs256 | Algorithm::Ps256 => kty == "RSA",
            Algorithm::MlDsa65 | Algorithm::MlDsa65Ed25519 | Algorithm::MlDsa65EcdsaP256 => {
                kty == "AKP" && self.alg.is_some_and(|alg| names(algorithm, alg))
            }
            Algorithm::Es384 | Algorithm::SlhDsaSha2_128s => false,
        });
        let restricted = self.unreadable
            || self.verify == Some(false)
            || self.alg.is_some_and(|alg| !names(algorithm, alg))
            || self.usage.is_some_and(|usage| usage != "sig");
        if !fits || restricted {
            return Ok(None);
        }
        let member = |member: Option<Str<'_>>| base64url(text(member.ok_or(Error::Key)?)?.as_bytes());
        let (first, second) = match algorithm {
            Algorithm::Ed25519 => (member(self.x)?, Vec::new()),
            Algorithm::Es256 => (member(self.x)?, member(self.y)?),
            Algorithm::Rs256 | Algorithm::Ps256 => (member(self.n)?, member(self.e)?),
            _ => (member(self.public)?, Vec::new()),
        };
        let fixed = <[u8]>::as_ref;
        let public = match algorithm {
            Algorithm::Ed25519 => fixed(&first).try_into().map(PublicKey::Ed25519),
            Algorithm::Es256 => fixed(&first)
                .try_into()
                .and_then(|x| fixed(&second).try_into().map(|y| PublicKey::P256 { x, y })),
            Algorithm::MlDsa65 => fixed(&first).try_into().map(PublicKey::MlDsa65),
            Algorithm::MlDsa65Ed25519 => fixed(&first).try_into().map(PublicKey::MlDsa65Ed25519),
            Algorithm::MlDsa65EcdsaP256 => fixed(&first).try_into().map(PublicKey::MlDsa65EcdsaP256),
            _ => Ok(PublicKey::Rsa { n: &first, e: &second }),
        }
        .map_err(|_| Error::Key)?;
        let key = Key {
            kid: None,
            alg: None,
            public,
        };
        let trusted = TrustedKey::new(algorithm, &key).map_err(|_| Error::Key)?;
        Ok(Some((
            self.kid.map(text).transpose()?.map(String::into_boxed_str),
            trusted,
        )))
    }
}

/// A checked JWS: the `kid` and the `typ` of its header, and its payload.
#[derive(Clone, PartialEq, Eq)]
pub struct Jws {
    kid: Option<Box<str>>,
    typ: Option<Box<str>>,
    payload: Box<[u8]>,
}

impl Jws {
    /// The `kid` of the header.
    #[must_use]
    pub fn kid(&self) -> Option<&str> {
        self.kid.as_deref()
    }

    /// The `typ` of the header.
    #[must_use]
    pub fn typ(&self) -> Option<&str> {
        self.typ.as_deref()
    }

    /// The payload.
    #[must_use]
    pub fn payload(&self) -> &[u8] {
        &self.payload
    }
}

// A payload can hold claims of a bearer token, so the output shows only its length.
impl fmt::Debug for Jws {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("Jws")
            .field("kid", &self.kid)
            .field("typ", &self.typ)
            .field("payload", &self.payload.len())
            .finish()
    }
}

/// A checked JWT: its JWS, and the claims that the check read.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Jwt {
    jws: Jws,
    claims: Claims,
}

impl Jwt {
    /// The JWS, with the payload: read each other claim from it.
    #[must_use]
    pub const fn jws(&self) -> &Jws {
        &self.jws
    }

    /// The claims that the check read.
    #[must_use]
    pub const fn claims(&self) -> &Claims {
        &self.claims
    }
}

/// The registered claims of a JWT that the check reads ([RFC 7519], [RFC 9068]). Each time is in seconds since the Unix
/// epoch.
///
/// [RFC 7519]: https://www.rfc-editor.org/rfc/rfc7519
/// [RFC 9068]: https://www.rfc-editor.org/rfc/rfc9068
#[derive(Clone, Debug, Default, PartialEq, Eq)]
#[non_exhaustive]
pub struct Claims {
    /// `iss`.
    pub iss: Option<Box<str>>,
    /// `sub`.
    pub sub: Option<Box<str>>,
    /// `aud`: one audience, or each of an array.
    pub aud: Vec<Box<str>>,
    /// `exp`.
    pub exp: Option<u64>,
    /// `nbf`.
    pub nbf: Option<u64>,
    /// `iat`.
    pub iat: Option<u64>,
    /// `jti`.
    pub jti: Option<Box<str>>,
    /// `client_id` (RFC 9068).
    pub client_id: Option<Box<str>>,
    /// `scope` (RFC 9068): the scopes, separated by spaces.
    pub scope: Option<Box<str>>,
}

impl Claims {
    /// Reads the claims of the payload `payload`.
    fn parse(payload: &[u8]) -> Result<Self, Error> {
        let mut scratch = [Slot::EMPTY; SLOTS];
        let claims = json::read(payload, &CLAIMS, IJson, &mut scratch, |reader| {
            let mut claims = RawClaims::default();
            let mut members = reader.value().members()?;
            while let Some((name, mut value)) = members.next()? {
                if name == "aud" && value.kind()? == json::Kind::Array {
                    let mut items = value.elements()?;
                    while let Some(item) = items.next()? {
                        claims.aud.push(item.str()?);
                    }
                } else if name == "aud" {
                    claims.aud.push(value.str()?);
                } else if let Some((_, time)) = [
                    ("exp", &mut claims.exp),
                    ("nbf", &mut claims.nbf),
                    ("iat", &mut claims.iat),
                ]
                .into_iter()
                .find(|(known, _)| name == *known)
                {
                    *time = Some(value.number()?.to_u64()?);
                } else if let Some((_, slot)) = [
                    ("iss", &mut claims.iss),
                    ("sub", &mut claims.sub),
                    ("jti", &mut claims.jti),
                    ("client_id", &mut claims.client_id),
                    ("scope", &mut claims.scope),
                ]
                .into_iter()
                .find(|(known, _)| name == *known)
                {
                    *slot = Some(value.str()?);
                }
            }
            Ok(claims)
        })
        .map_err(|_| Error::Claims)?;
        let text = |claim: Option<Str<'_>>| {
            claim
                .map(text)
                .transpose()
                .map(|claim| claim.map(String::into_boxed_str))
        };
        Ok(Self {
            iss: text(claims.iss)?,
            sub: text(claims.sub)?,
            aud: claims
                .aud
                .into_iter()
                .map(|aud| text(Some(aud)).map(Option::unwrap_or_default))
                .collect::<Result<_, _>>()?,
            exp: claims.exp,
            nbf: claims.nbf,
            iat: claims.iat,
            jti: text(claims.jti)?,
            client_id: text(claims.client_id)?,
            scope: text(claims.scope)?,
        })
    }
}

/// The claims as the reader gives them.
#[derive(Default)]
struct RawClaims<'a> {
    iss: Option<Str<'a>>,
    sub: Option<Str<'a>>,
    aud: Vec<Str<'a>>,
    exp: Option<u64>,
    nbf: Option<u64>,
    iat: Option<u64>,
    jti: Option<Str<'a>>,
    client_id: Option<Str<'a>>,
    scope: Option<Str<'a>>,
}

/// The JWS signing input of `payload` with the header `{"alg":…,"kid":…,"typ":…}`: `BASE64URL(header) '.'
/// BASE64URL(payload)`. Sign its bytes with the key of `algorithm`, such as in custody, then call [`compact`]. The
/// token then passes each limit of [`Profile::verify`].
///
/// Cost class: [`Parse`](crate::limits::Class::Parse).
///
/// # Errors
///
/// [`Error::Algorithm`] if `algorithm` has no JOSE name. [`Error::Limit`] if the header passes a limit of the header
/// of the verifier, or if the token with the longest signature of `algorithm` would be longer than
/// [`TOKEN_BYTES_MAX`].
pub fn signing_input(
    algorithm: Algorithm,
    kid: Option<&str>,
    typ: Option<&str>,
    payload: &[u8],
) -> Result<String, Error> {
    let name = alg(algorithm).ok_or(Error::Algorithm)?;
    // A header longer than the buffer, or with a longer string, refuses here as it would at the verifier.
    let mut header = [0; HEADER.input_bytes_max as usize];
    let len = json::write(&mut header, |place| {
        place.object(|header| {
            header.member("alg").str(name)?;
            if let Some(kid) = kid {
                header.member("kid").str(kid)?;
            }
            match typ {
                Some(typ) => header.member("typ").str(typ),
                None => Ok(()),
            }
        })
    })
    .map_err(|_| Error::Limit)?;
    let header = &header[..len];
    json::read(header, &HEADER, IJson, &mut [Slot::EMPTY; SLOTS], |reader| {
        reader.value().skip()
    })
    .map_err(|_| Error::Limit)?;
    // The base64url of the header, the payload, and the signature, and two dots.
    let token = [header.len(), payload.len(), algorithm.signature_bytes_max()]
        .into_iter()
        .try_fold(2, |len: usize, bytes| len.checked_add(Url.encoded_len(bytes)?));
    token.is_some_and(|len| len <= TOKEN_BYTES_MAX).ok_or(Error::Limit)?;
    let mut input = encode(header);
    input.push('.');
    input.push_str(&encode(payload));
    Ok(input)
}

/// The JWS compact serialization of the signing input `input` and the signature `signature`.
///
/// Cost class: [`Parse`](crate::limits::Class::Parse).
#[must_use]
pub fn compact(input: &str, signature: &[u8]) -> String {
    let mut token = String::from(input);
    token.push('.');
    token.push_str(&encode(signature));
    token
}

/// The base64url text of `bytes`, with no padding.
fn encode(bytes: &[u8]) -> String {
    let mut out = vec![0; Url.encoded_len(bytes.len()).expect("a length of a token encodes")];
    let len = Url
        .encode(bytes, &mut out)
        .expect("the buffer has the encoded length")
        .len();
    out.truncate(len);
    String::from_utf8(out).expect("base64url is ASCII")
}

/// The bytes of the base64url text `text`, with no padding.
fn base64url(text: &[u8]) -> Result<Vec<u8>, Error> {
    let mut out = vec![0; Url.decoded_len(text).map_err(|_| Error::Malformed)?];
    Url.decode(text, &mut out).map_err(|_| Error::Malformed)?;
    Ok(out)
}

/// The text of a JSON string, with its escapes read.
fn text(value: Str<'_>) -> Result<String, Error> {
    let mut buf = vec![0; value.len()];
    Ok(value.decode(&mut buf).map_err(|_| Error::Malformed)?.into())
}

/// The cause of a refused token. For each refusal, the recovery is to refuse the token.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Error {
    /// The token is not in the compact serialization, or a part is not JSON or base64url.
    Malformed,
    /// The token, the key set, or the signature checks pass a bound.
    Limit,
    /// The `alg` of the header does not name the algorithm of the profile, or the algorithm has no JOSE name.
    Algorithm,
    /// The header names a key URL, carries a key, or has `crit` or `b64`.
    Header,
    /// No key of the profile fits the header, or a key is not valid or has a private member.
    Key,
    /// The signature does not verify.
    Signature,
    /// The `typ` of the header is not the type of the profile.
    Type,
    /// The issuer is not the issuer of the profile.
    Issuer,
    /// The audience does not name the audience of the profile.
    Audience,
    /// `exp` can be at or before the reading.
    Expired,
    /// `nbf` can be after the reading.
    NotYet,
    /// A required claim is missing, or a claim has another type.
    Claims,
    /// The reading has no bound.
    Time(TimeError),
}

impl fmt::Display for Error {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Malformed => f.write_str("the token is not a JWS in the compact serialization"),
            Self::Limit => f.write_str("the token is larger than a bound"),
            Self::Algorithm => f.write_str("the alg of the token is not the algorithm of the profile"),
            Self::Header => f.write_str("the header names a key URL, carries a key, or has crit or b64"),
            Self::Key => f.write_str("no key of the profile fits the token"),
            Self::Signature => f.write_str("the signature of the token does not verify"),
            Self::Type => f.write_str("the typ of the token is not the type of the profile"),
            Self::Issuer => f.write_str("the issuer of the token is not the issuer of the profile"),
            Self::Audience => f.write_str("the token is for another audience"),
            Self::Expired => f.write_str("the token can have expired"),
            Self::NotYet => f.write_str("the token can be not valid yet"),
            Self::Claims => f.write_str("a claim of the token is missing or has another type"),
            Self::Time(error) => write!(f, "the time reading gave no value: {error}"),
        }
    }
}

impl core::error::Error for Error {}
