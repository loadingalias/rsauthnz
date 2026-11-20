//! `COSE_Key` (RFC 9052 section 7) and the trusted verification key of a profile.

use core::fmt;

use super::{Error, algorithm, label};
use crate::cbor::{self, Value};
use crate::crypto::{Algorithm, Verifier};
use crate::limits::{Limits, SignatureBudget};

/// A public key from a `COSE_Key`. It is an untrusted value until the application makes a [`TrustedKey`] from it.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Key<'a> {
    /// The `kid` (2) parameter.
    pub kid: Option<&'a [u8]>,
    /// The `alg` (3) parameter. It fits the key type when it is present.
    pub alg: Option<Algorithm>,
    /// The public key.
    pub public: PublicKey<'a>,
}

/// The public part of a key of a supported type. Each variant borrows the bytes of the encoded key.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum PublicKey<'a> {
    /// An `OKP` (1) key on the `Ed25519` (6) curve: the 32 bytes of `x` (-2).
    Ed25519(&'a [u8; 32]),
    /// An `EC2` (2) key on the `P-256` (1) curve: the coordinates `x` (-2) and `y` (-3), 32 bytes each.
    P256 {
        /// The x coordinate.
        x: &'a [u8; 32],
        /// The y coordinate.
        y: &'a [u8; 32],
    },
    /// An `AKP` (7) key with the algorithm ML-DSA-65: the 1,952 bytes of `pub` (-1).
    MlDsa65(&'a [u8; 1952]),
    /// An `AKP` (7) key with the algorithm ML-DSA-65 + Ed25519: the 1,984 bytes of `pub` (-1). They are the ML-DSA-65
    /// key, then the Ed25519 key.
    MlDsa65Ed25519(&'a [u8; 1984]),
    /// An `AKP` (7) key with the algorithm ML-DSA-65 + ECDSA P-256: the 2,017 bytes of `pub` (-1). They are the
    /// ML-DSA-65 key, then the uncompressed P-256 point.
    MlDsa65EcdsaP256(&'a [u8; 2017]),
}

impl<'a> Key<'a> {
    /// Decodes the `COSE_Key` that fills `input`.
    ///
    /// Cost class: [`Parse`](crate::limits::Class::Parse).
    ///
    /// # Errors
    ///
    /// The errors of [`Self::from_value`], and [`Error::Cbor`] if the CBOR decoder refuses `input`.
    pub fn decode(input: &'a [u8], limits: Limits) -> Result<Self, Error> {
        Self::from_value(&cbor::decode(input, limits)?)
    }

    /// Reads a `COSE_Key` from its decoded CBOR value. It ignores the parameters that it does not read.
    ///
    /// Cost class: [`Parse`](crate::limits::Class::Parse).
    ///
    /// # Errors
    ///
    /// [`Error::Unsupported`] for a key type, a curve, or an `alg` that this crate does not support, a compressed
    /// P-256 point, and a key with private material. [`Error::KeyAlgorithm`] if `alg` does not fit the key type.
    /// [`Error::Malformed`] for each other difference from the structure.
    pub fn from_value(value: &Value<'a>) -> Result<Self, Error> {
        let Value::Map(entries) = value else {
            return Err(Error::Malformed);
        };
        let get = |key: i64| {
            let key = label(key);
            entries.iter().find(|(entry, _)| *entry == key).map(|(_, value)| value)
        };
        let kid = match get(2) {
            None => None,
            Some(Value::Bytes(kid)) => Some(*kid),
            Some(_) => return Err(Error::Malformed),
        };
        let alg = get(3).map(|alg| algorithm(alg).ok_or(Error::Unsupported)).transpose()?;
        let bytes = |key: i64| match get(key) {
            Some(Value::Bytes(bytes)) => Ok(*bytes),
            _ => Err(Error::Malformed),
        };
        let (public, fits) = match get(1) {
            Some(Value::Unsigned(1)) => {
                curve(get(-1), 6)?;
                private(get(-4))?;
                (PublicKey::Ed25519(fixed(bytes(-2)?)?), Algorithm::Ed25519)
            }
            Some(Value::Unsigned(2)) => {
                curve(get(-1), 1)?;
                private(get(-4))?;
                if matches!(get(-3), Some(Value::Bool(_))) {
                    return Err(Error::Unsupported);
                }
                let (x, y) = (fixed(bytes(-2)?)?, fixed(bytes(-3)?)?);
                (PublicKey::P256 { x, y }, Algorithm::Es256)
            }
            Some(Value::Unsigned(7)) => {
                // RFC 9964 requires `alg` in an `AKP` key, because the form of the key depends on it.
                let alg = alg.ok_or(Error::Malformed)?;
                private(get(-2))?;
                let public = match alg {
                    Algorithm::MlDsa65 => PublicKey::MlDsa65(fixed(bytes(-1)?)?),
                    Algorithm::MlDsa65Ed25519 => PublicKey::MlDsa65Ed25519(fixed(bytes(-1)?)?),
                    Algorithm::MlDsa65EcdsaP256 => PublicKey::MlDsa65EcdsaP256(fixed(bytes(-1)?)?),
                    Algorithm::Ed25519 | Algorithm::Es256 => return Err(Error::KeyAlgorithm),
                };
                (public, alg)
            }
            Some(Value::Unsigned(_) | Value::Negative(_) | Value::Text(_)) => return Err(Error::Unsupported),
            _ => return Err(Error::Malformed),
        };
        if alg.is_some_and(|alg| alg != fits) {
            return Err(Error::KeyAlgorithm);
        }
        Ok(Self { kid, alg, public })
    }
}

/// Refuses a curve other than `expected`.
fn curve(crv: Option<&Value<'_>>, expected: u64) -> Result<(), Error> {
    match crv {
        Some(Value::Unsigned(crv)) if *crv == expected => Ok(()),
        Some(Value::Unsigned(_) | Value::Negative(_) | Value::Text(_)) => Err(Error::Unsupported),
        _ => Err(Error::Malformed),
    }
}

/// Refuses private key material. A verification key never needs it.
fn private(parameter: Option<&Value<'_>>) -> Result<(), Error> {
    parameter.map_or(Ok(()), |_| Err(Error::Unsupported))
}

/// The bytes of a parameter that has the length `N`.
fn fixed<const N: usize>(bytes: &[u8]) -> Result<&[u8; N], Error> {
    bytes.try_into().map_err(|_| Error::Malformed)
}

/// A verification key that the application trusts for one algorithm. A [`super::Profile`] holds it, so a header of an
/// artifact never selects a key or an algorithm.
#[derive(Clone, PartialEq, Eq)]
pub struct TrustedKey(Verifier);

impl TrustedKey {
    /// Makes the trusted key of `algorithm` from `key`.
    ///
    /// Cost class: [`Verify`](crate::limits::Class::Verify). A P-256 key checks its point and prepares its tables.
    ///
    /// # Errors
    ///
    /// [`Error::KeyAlgorithm`] if `key` does not fit `algorithm`, or its `alg` is a different algorithm.
    /// [`Error::Malformed`] if a P-256 point, alone or in a composite key, is not on the curve.
    pub fn new(algorithm: Algorithm, key: &Key<'_>) -> Result<Self, Error> {
        if key.alg.is_some_and(|alg| alg != algorithm) {
            return Err(Error::KeyAlgorithm);
        }
        Ok(Self(match (algorithm, &key.public) {
            (Algorithm::Ed25519, PublicKey::Ed25519(x)) => Verifier::ed25519(x),
            (Algorithm::Es256, PublicKey::P256 { x, y }) => Verifier::es256(x, y).ok_or(Error::Malformed)?,
            (Algorithm::MlDsa65, PublicKey::MlDsa65(public)) => Verifier::ml_dsa_65(public),
            (Algorithm::MlDsa65Ed25519, PublicKey::MlDsa65Ed25519(public)) => {
                Verifier::ml_dsa_65_ed25519(public).ok_or(Error::Malformed)?
            }
            (Algorithm::MlDsa65EcdsaP256, PublicKey::MlDsa65EcdsaP256(public)) => {
                Verifier::ml_dsa_65_ecdsa_p256(public).ok_or(Error::Malformed)?
            }
            _ => return Err(Error::KeyAlgorithm),
        }))
    }

    /// The algorithm of the key.
    #[must_use]
    pub const fn algorithm(&self) -> Algorithm {
        self.0.algorithm()
    }

    /// Verifies `signature` over `message` with the algorithm of the key, after it charges `budget`.
    pub(crate) fn verify(&self, message: &[u8], signature: &[u8], budget: &mut SignatureBudget) -> Result<(), Error> {
        self.0
            .verify(message, signature, budget)
            .map_err(Error::Limit)?
            .ok_or(Error::Signature)
    }
}

impl fmt::Debug for TrustedKey {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_tuple("TrustedKey").field(&self.algorithm()).finish()
    }
}
