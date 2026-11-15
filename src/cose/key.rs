//! `COSE_Key` (RFC 9052 section 7) and the trusted verification key of a profile.

use alloc::boxed::Box;
use core::fmt;

use rscrypto::auth::{
    EcdsaP256PublicKey, EcdsaP256Signature, Ed25519PublicKey, Ed25519Signature, MlDsa65PublicKey, MlDsa65Signature,
};

use super::{Algorithm, Error, label};
use crate::cbor::{self, Limits, Value};

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
}

impl<'a> Key<'a> {
    /// Decodes the `COSE_Key` that fills `input`.
    ///
    /// # Errors
    ///
    /// The errors of [`Self::from_value`], and [`Error::Cbor`] if the CBOR decoder refuses `input`.
    pub fn decode(input: &'a [u8], limits: Limits) -> Result<Self, Error> {
        Self::from_value(&cbor::decode(input, limits)?)
    }

    /// Reads a `COSE_Key` from its decoded CBOR value. It ignores the parameters that it does not read.
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
        let alg = get(3)
            .map(|alg| Algorithm::from_value(alg).ok_or(Error::Unsupported))
            .transpose()?;
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
                if alg.is_none() {
                    return Err(Error::Malformed);
                }
                private(get(-2))?;
                (PublicKey::MlDsa65(fixed(bytes(-1)?)?), Algorithm::MlDsa65)
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
#[derive(Clone)]
pub struct TrustedKey(Verifier);

#[derive(Clone)]
enum Verifier {
    Ed25519(Ed25519PublicKey),
    Es256(Box<EcdsaP256PublicKey>),
    MlDsa65(Box<MlDsa65PublicKey>),
}

impl TrustedKey {
    /// Makes the trusted key of `algorithm` from `key`.
    ///
    /// # Errors
    ///
    /// [`Error::KeyAlgorithm`] if `key` does not fit `algorithm`, or its `alg` is a different algorithm.
    /// [`Error::Malformed`] if the P-256 point is not on the curve.
    pub fn new(algorithm: Algorithm, key: &Key<'_>) -> Result<Self, Error> {
        if key.alg.is_some_and(|alg| alg != algorithm) {
            return Err(Error::KeyAlgorithm);
        }
        Ok(Self(match (algorithm, &key.public) {
            (Algorithm::Ed25519, PublicKey::Ed25519(x)) => Verifier::Ed25519(Ed25519PublicKey::from_bytes(**x)),
            (Algorithm::Es256, PublicKey::P256 { x, y }) => {
                let mut sec1 = [0x04; EcdsaP256PublicKey::SEC1_LENGTH];
                sec1[1..33].copy_from_slice(*x);
                sec1[33..].copy_from_slice(*y);
                let key = EcdsaP256PublicKey::from_sec1_bytes(&sec1).map_err(|_| Error::Malformed)?;
                Verifier::Es256(Box::new(key))
            }
            (Algorithm::MlDsa65, PublicKey::MlDsa65(public)) => {
                Verifier::MlDsa65(Box::new(MlDsa65PublicKey::from_bytes(**public)))
            }
            _ => return Err(Error::KeyAlgorithm),
        }))
    }

    /// The algorithm of the key.
    #[must_use]
    pub const fn algorithm(&self) -> Algorithm {
        match self.0 {
            Verifier::Ed25519(_) => Algorithm::Ed25519,
            Verifier::Es256(_) => Algorithm::Es256,
            Verifier::MlDsa65(_) => Algorithm::MlDsa65,
        }
    }

    /// Verifies `signature` over `message` with the algorithm of the key.
    pub(super) fn verify(&self, message: &[u8], signature: &[u8]) -> Result<(), Error> {
        let verified = match &self.0 {
            Verifier::Ed25519(key) => <[u8; 64]>::try_from(signature)
                .is_ok_and(|signature| key.verify(message, &Ed25519Signature::from_bytes(signature)).is_ok()),
            Verifier::Es256(key) => <[u8; 64]>::try_from(signature)
                .ok()
                .and_then(|signature| EcdsaP256Signature::from_bytes(signature).ok())
                .is_some_and(|signature| key.verify(message, &signature).is_ok()),
            Verifier::MlDsa65(key) => MlDsa65Signature::try_from_slice(signature)
                .is_ok_and(|signature| key.verify(message, &signature).is_ok()),
        };
        if verified { Ok(()) } else { Err(Error::Signature) }
    }
}

/// Two trusted keys are equal when their algorithms and their public keys are equal.
impl PartialEq for TrustedKey {
    fn eq(&self, other: &Self) -> bool {
        match (&self.0, &other.0) {
            (Verifier::Ed25519(a), Verifier::Ed25519(b)) => a.as_bytes() == b.as_bytes(),
            (Verifier::Es256(a), Verifier::Es256(b)) => a.to_sec1_bytes() == b.to_sec1_bytes(),
            (Verifier::MlDsa65(a), Verifier::MlDsa65(b)) => a == b,
            _ => false,
        }
    }
}

impl Eq for TrustedKey {}

impl fmt::Debug for TrustedKey {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_tuple("TrustedKey").field(&self.algorithm()).finish()
    }
}
