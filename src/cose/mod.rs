//! COSE signatures ([RFC 9052]), CWT claims ([RFC 8392]), and proof-of-possession confirmation ([RFC 8747]).
//!
//! Parsing gives untrusted values: [`Sign1::decode`], [`Key::decode`], and [`Claims::decode`]. Verification takes
//! a trusted [`Profile`], which fixes the algorithm, the key, the issuer, the audience, and the purpose. A header
//! can only match the algorithm of the profile. It never selects an algorithm or a key. [`Profile::verify`] gives
//! [`Verified`] evidence, which holds the exact bytes of the artifact.
//!
//! The profiles are Ed25519 (COSE -19), ES256 (-7), and ML-DSA-65 (-49). [rscrypto] does each signature check.
//!
//! ```
//! use core::time::Duration;
//! use rsauthnz::cbor::Limits;
//! use rsauthnz::cose::{Algorithm, Key, Profile, PublicKey, TrustedKey};
//! use rsauthnz::id::Id;
//! use rsauthnz::time::{Reading, ReadingSource};
//!
//! # fn hex(digits: &str) -> Vec<u8> {
//! #     (0..digits.len()).step_by(2).map(|i| u8::from_str_radix(&digits[i..i + 2], 16).unwrap()).collect()
//! # }
//! // The signed CWT of RFC 8392, Appendix A.3, and the public part of its key (Appendix A.2.3).
//! let cwt = hex(concat!(
//!     "d28443a10126a104524173796d6d657472696345434453413235365850a70175636f61703a2f2f61732e6578616d706c652e",
//!     "636f6d02656572696b77037818636f61703a2f2f6c696768742e6578616d706c652e636f6d041a5612aeb0051a5610d9f006",
//!     "1a5610d9f007420b7158405427c1ff28d23fbad1f29c4c7c6a555e601d6fa29f9179bc3d7438bacaca5acd08c8d4d4f96131",
//!     "680c429a01f85951ecee743a52b9b63632c57209120e1c9e30",
//! ));
//! let x = hex("143329cce7868e416927599cf65a34f3ce2ffda55a7eca69ed8919a394d42f0f");
//! let y = hex("60f7f1a780d8a783bfb7a2dd6b2796e8128dbbcef9d3d168db9529971a36e7b9");
//! let public = PublicKey::P256 { x: x.as_slice().try_into()?, y: y.as_slice().try_into()? };
//! let key = Key { kid: None, alg: None, public };
//!
//! let profile = Profile {
//!     key: TrustedKey::new(Algorithm::Es256, &key)?,
//!     issuer: "coap://as.example.com".into(),
//!     audience: "coap://light.example.com".into(),
//!     purpose: Id::new("example", "light.access")?,
//!     limits: Limits::default(),
//! };
//! // The physical time of the check, with its uncertainty bound. The CWT is valid in October 2015.
//! let now = Reading::new(Duration::from_secs(1_444_000_000), Some(Duration::from_secs(1)), ReadingSource::Caller);
//!
//! let verified = profile.verify(&cwt, now)?;
//! assert_eq!(verified.claims().sub, Some("erikw"));
//! assert_eq!(verified.expires(), Duration::from_secs(1_444_064_944));
//! # Ok::<(), Box<dyn core::error::Error>>(())
//! ```
//!
//! [RFC 9052]: https://www.rfc-editor.org/rfc/rfc9052
//! [RFC 8392]: https://www.rfc-editor.org/rfc/rfc8392
//! [RFC 8747]: https://www.rfc-editor.org/rfc/rfc8747
//! [rscrypto]: https://crates.io/crates/rscrypto

mod cwt;
mod key;
mod sign1;

use core::fmt;

pub use cwt::{Claims, Confirmation, Profile, Verified};
pub use key::{Key, PublicKey, TrustedKey};
pub use sign1::{Header, Sign1};

use crate::cbor::{self, Value};
use crate::time::TimeError;

/// A signature algorithm of a trusted profile.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub enum Algorithm {
    /// Ed25519 (COSE algorithm -19, [RFC 9864](https://www.rfc-editor.org/rfc/rfc9864)). A classical profile.
    Ed25519,
    /// ECDSA with P-256 and SHA-256 (COSE algorithm -7). A classical profile.
    Es256,
    /// ML-DSA-65 (COSE algorithm -49, [RFC 9964](https://www.rfc-editor.org/rfc/rfc9964)).
    MlDsa65,
}

impl Algorithm {
    /// The COSE algorithm identifier, in its CBOR form.
    const fn value(self) -> Value<'static> {
        match self {
            Self::Ed25519 => Value::Negative(18),
            Self::Es256 => Value::Negative(6),
            Self::MlDsa65 => Value::Negative(48),
        }
    }

    /// The algorithm with the COSE identifier `value`, if this crate has it.
    fn from_value(value: &Value<'_>) -> Option<Self> {
        [Self::Ed25519, Self::Es256, Self::MlDsa65]
            .into_iter()
            .find(|algorithm| algorithm.value() == *value)
    }
}

/// The CBOR form of the integer label `label`.
const fn label(label: i64) -> Value<'static> {
    if label >= 0 {
        Value::Unsigned(label.unsigned_abs())
    } else {
        // `label` is negative, so its magnitude is 1 or more.
        Value::Negative(label.unsigned_abs() - 1)
    }
}

/// The cause of a refusal. For each refusal, the recovery is to refuse the artifact.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Error {
    /// The CBOR decoder refused the input.
    Cbor(cbor::Error),
    /// The CBOR item is not the COSE or CWT structure, or a field has the wrong type.
    Malformed,
    /// The `crit` header names a header that this crate does not process. This crate processes `alg` (1), `content
    /// type` (3), and `kid` (4).
    UnknownCritical,
    /// The artifact or the key has a feature that this crate does not support: a key type, a curve, an algorithm, a
    /// detached payload, or an encrypted confirmation key. A key that holds private material also refuses.
    Unsupported,
    /// The key does not fit the algorithm.
    KeyAlgorithm,
    /// The protected header has no `alg`, or its `alg` is not the algorithm of the profile.
    AlgorithmMismatch,
    /// The signature does not verify with the key of the profile.
    Signature,
    /// The `iss` claim is missing, or it is not the issuer of the profile.
    Issuer,
    /// The `aud` claim is missing, or it does not name the audience of the profile.
    Audience,
    /// The claims have no `exp`. Each artifact of a profile has a finite validity.
    NoExpiry,
    /// The latest time that the reading permits is at or after `exp`.
    Expired,
    /// The earliest time that the reading permits is before `nbf`.
    NotYetValid,
    /// The reading cannot give a bound for the validity check, for example because its bound is unknown.
    Time(TimeError),
}

impl fmt::Display for Error {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Cbor(error) => write!(f, "the COSE input is not valid CBOR: {error}"),
            Self::Malformed => f.write_str("the input is not a valid COSE or CWT structure"),
            Self::UnknownCritical => f.write_str("a critical COSE header is not known"),
            Self::Unsupported => f.write_str("the COSE input has a feature that is not supported"),
            Self::KeyAlgorithm => f.write_str("the key does not fit the algorithm"),
            Self::AlgorithmMismatch => f.write_str("the COSE algorithm is not the algorithm of the profile"),
            Self::Signature => f.write_str("the signature does not verify"),
            Self::Issuer => f.write_str("the issuer is not the issuer of the profile"),
            Self::Audience => f.write_str("the audience does not include the audience of the profile"),
            Self::NoExpiry => f.write_str("the claims have no expiry"),
            Self::Expired => f.write_str("the artifact has expired"),
            Self::NotYetValid => f.write_str("the artifact is not valid yet"),
            Self::Time(error) => write!(f, "the time reading cannot bound the validity check: {error}"),
        }
    }
}

impl core::error::Error for Error {}

impl From<cbor::Error> for Error {
    fn from(error: cbor::Error) -> Self {
        Self::Cbor(error)
    }
}

impl From<TimeError> for Error {
    fn from(error: TimeError) -> Self {
        Self::Time(error)
    }
}
