//! `COSE_Key` (RFC 9052 section 7) and the trusted verification key of a profile.

use core::fmt;

use alloc::vec;
use alloc::vec::Vec;

use super::{Error, alg, algorithm, label};
use crate::cbor::{self, Value};
use crate::crypto::{self, Algorithm, Verifier};
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
    /// An `RSA` (3) key with the algorithm RS256: the modulus `n` (-1) and the exponent `e` (-2), each an unsigned
    /// big-endian integer.
    Rsa {
        /// The modulus.
        n: &'a [u8],
        /// The exponent.
        e: &'a [u8],
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
        let alg = get(3)
            .map(|alg| key_algorithm(alg).ok_or(Error::Unsupported))
            .transpose()?;
        let bytes = |key: i64| match get(key) {
            Some(Value::Bytes(bytes)) => Ok(*bytes),
            _ => Err(Error::Malformed),
        };
        let public = match get(1) {
            Some(Value::Unsigned(1)) => {
                curve(get(-1), 6)?;
                private(get(-4))?;
                PublicKey::Ed25519(fixed(bytes(-2)?)?)
            }
            Some(Value::Unsigned(2)) => {
                curve(get(-1), 1)?;
                private(get(-4))?;
                if matches!(get(-3), Some(Value::Bool(_))) {
                    return Err(Error::Unsupported);
                }
                let (x, y) = (fixed(bytes(-2)?)?, fixed(bytes(-3)?)?);
                PublicKey::P256 { x, y }
            }
            Some(Value::Unsigned(3)) => {
                // An RSA key serves more than one algorithm, so this crate requires `alg`: only RS256 is supported.
                if alg.ok_or(Error::Malformed)? != Algorithm::Rs256 {
                    return Err(Error::KeyAlgorithm);
                }
                private(get(-3))?;
                PublicKey::Rsa {
                    n: bytes(-1)?,
                    e: bytes(-2)?,
                }
            }
            Some(Value::Unsigned(7)) => {
                // RFC 9964 requires `alg` in an `AKP` key, because the form of the key depends on it.
                let alg = alg.ok_or(Error::Malformed)?;
                private(get(-2))?;
                match alg {
                    Algorithm::MlDsa65 => PublicKey::MlDsa65(fixed(bytes(-1)?)?),
                    Algorithm::MlDsa65Ed25519 => PublicKey::MlDsa65Ed25519(fixed(bytes(-1)?)?),
                    Algorithm::MlDsa65EcdsaP256 => PublicKey::MlDsa65EcdsaP256(fixed(bytes(-1)?)?),
                    Algorithm::Ed25519 | Algorithm::Es256 | Algorithm::Rs256 => return Err(Error::KeyAlgorithm),
                    // SLH-DSA has no COSE identifier yet, so no `alg` names it.
                    Algorithm::SlhDsaSha2_128s => return Err(Error::Unsupported),
                }
            }
            Some(Value::Unsigned(_) | Value::Negative(_) | Value::Text(_)) => return Err(Error::Unsupported),
            _ => return Err(Error::Malformed),
        };
        if alg.is_some_and(|alg| alg != public.algorithm()) {
            return Err(Error::KeyAlgorithm);
        }
        Ok(Self { kid, alg, public })
    }
}

impl<'a> PublicKey<'a> {
    /// The algorithm that the key type fixes.
    pub(crate) const fn algorithm(&self) -> Algorithm {
        match self {
            Self::Ed25519(_) => Algorithm::Ed25519,
            Self::P256 { .. } => Algorithm::Es256,
            Self::Rsa { .. } => Algorithm::Rs256,
            Self::MlDsa65(_) => Algorithm::MlDsa65,
            Self::MlDsa65Ed25519(_) => Algorithm::MlDsa65Ed25519,
            Self::MlDsa65EcdsaP256(_) => Algorithm::MlDsa65EcdsaP256,
        }
    }

    /// The `COSE_Key` of the key, with its `alg` (3): an `OKP` (1) key with `crv` (-1) `Ed25519` (6) and `x` (-2), an
    /// `EC2` (2) key with `crv` `P-256` (1), `x`, and `y` (-3), an `RSA` (3) key with `n` (-1) and `e` (-2), or an
    /// `AKP` (7) key with `pub` (-1).
    pub(crate) fn to_cbor(&self) -> Value<'a> {
        let (kty, mut entries) = self.members();
        let alg = alg(self.algorithm()).expect("each key type of this crate has a COSE algorithm");
        entries.extend([(label(1), Value::Unsigned(kty)), (label(3), alg)]);
        Value::Map(entries)
    }

    /// The COSE Key Thumbprint of the key ([RFC 9679]): the SHA-256 digest of the deterministic CBOR of its required
    /// parameters. An `OKP` or `EC2` key has `kty`, `crv`, and its coordinates, and an `RSA` key has `kty`, `n`, and `e`
    /// (RFC 9679 section 4). An `AKP` key has `kty`, `alg`, and `pub` (RFC 9964 section 6).
    ///
    /// [RFC 9679]: https://www.rfc-editor.org/rfc/rfc9679
    pub(crate) fn thumbprint(&self) -> [u8; 32] {
        let (kty, mut entries) = self.members();
        entries.push((label(1), Value::Unsigned(kty)));
        if kty == AKP {
            entries.push((
                label(3),
                alg(self.algorithm()).expect("each key type of this crate has a COSE algorithm"),
            ));
        }
        let form = cbor::encode(&Value::Map(entries), Limits::FORM)
            .expect("a COSE_Key has distinct labels and no simple value");
        crypto::sha256(&form)
    }

    /// The `kty` of the key, and its parameters other than `kty` and `alg`.
    fn members(&self) -> (u64, Vec<(Value<'a>, Value<'a>)>) {
        match *self {
            Self::Ed25519(x) => (1, vec![(label(-1), Value::Unsigned(6)), (label(-2), Value::Bytes(x))]),
            Self::P256 { x, y } => (
                2,
                vec![
                    (label(-1), Value::Unsigned(1)),
                    (label(-2), Value::Bytes(x)),
                    (label(-3), Value::Bytes(y)),
                ],
            ),
            Self::Rsa { n, e } => (3, vec![(label(-1), Value::Bytes(n)), (label(-2), Value::Bytes(e))]),
            Self::MlDsa65(public) => (AKP, vec![(label(-1), Value::Bytes(public))]),
            Self::MlDsa65Ed25519(public) => (AKP, vec![(label(-1), Value::Bytes(public))]),
            Self::MlDsa65EcdsaP256(public) => (AKP, vec![(label(-1), Value::Bytes(public))]),
        }
    }
}

/// The `kty` of an `AKP` key (RFC 9964): ML-DSA-65 and the composites.
const AKP: u64 = 7;

/// The algorithm of the `alg` (3) of a key. A key also takes the polymorphic EdDSA (-8) as Ed25519 and ESP256 (-9) as
/// ES256 ([RFC 9864]): the type of the key fixes the curve, so each one names one algorithm of this crate. WebAuthn
/// authenticators write -8.
///
/// [RFC 9864]: https://www.rfc-editor.org/rfc/rfc9864
fn key_algorithm(value: &Value<'_>) -> Option<Algorithm> {
    match value {
        Value::Negative(7) => Some(Algorithm::Ed25519),
        Value::Negative(8) => Some(Algorithm::Es256),
        _ => algorithm(value),
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

/// A verification key that the application trusts for one algorithm. A profile holds it, so a header of an artifact
/// never selects an algorithm. A `kid` selects only among the trusted keys of the profile, and each of them has the
/// algorithm of the profile.
#[derive(Clone, PartialEq, Eq)]
pub struct TrustedKey {
    verifier: Verifier,
    /// The COSE Key Thumbprint of the key.
    kid: [u8; 32],
}

impl TrustedKey {
    /// Makes the trusted key of `algorithm` from `key`. The `kid` of `key` has no effect: the key ID of a trusted key is
    /// its thumbprint ([`Self::kid`]).
    ///
    /// Cost class: [`Verify`](crate::limits::Class::Verify). A P-256 key checks its point and prepares its tables, and
    /// the thumbprint is one SHA-256 digest of the key.
    ///
    /// # Errors
    ///
    /// [`Error::KeyAlgorithm`] if `key` does not fit `algorithm`, or its `alg` is a different algorithm.
    /// [`Error::Malformed`] if a P-256 point, alone or in a composite key, is not on the curve, or if an RSA key does not
    /// have a modulus of 2,048 to 4,096 bits and the exponent 65,537.
    pub fn new(algorithm: Algorithm, key: &Key<'_>) -> Result<Self, Error> {
        if key.alg.is_some_and(|alg| alg != algorithm) {
            return Err(Error::KeyAlgorithm);
        }
        let verifier = match (algorithm, &key.public) {
            (Algorithm::Ed25519, PublicKey::Ed25519(x)) => Verifier::ed25519(x),
            (Algorithm::Es256, PublicKey::P256 { x, y }) => Verifier::es256(x, y).ok_or(Error::Malformed)?,
            (Algorithm::Rs256, PublicKey::Rsa { n, e }) => Verifier::rs256(n, e).ok_or(Error::Malformed)?,
            (Algorithm::MlDsa65, PublicKey::MlDsa65(public)) => Verifier::ml_dsa_65(public),
            (Algorithm::MlDsa65Ed25519, PublicKey::MlDsa65Ed25519(public)) => {
                Verifier::ml_dsa_65_ed25519(public).ok_or(Error::Malformed)?
            }
            (Algorithm::MlDsa65EcdsaP256, PublicKey::MlDsa65EcdsaP256(public)) => {
                Verifier::ml_dsa_65_ecdsa_p256(public).ok_or(Error::Malformed)?
            }
            _ => return Err(Error::KeyAlgorithm),
        };
        Ok(Self {
            verifier,
            kid: key.public.thumbprint(),
        })
    }

    /// The algorithm of the key.
    #[must_use]
    pub const fn algorithm(&self) -> Algorithm {
        self.verifier.algorithm()
    }

    /// The key ID of the key: its COSE Key Thumbprint ([RFC 9679]), with SHA-256. The `kid` of an artifact names its
    /// issuer key with it.
    ///
    /// [RFC 9679]: https://www.rfc-editor.org/rfc/rfc9679
    #[must_use]
    pub const fn kid(&self) -> &[u8; 32] {
        &self.kid
    }

    /// Verifies `signature` over `message` with the algorithm of the key, after it charges `budget`.
    pub(crate) fn verify(&self, message: &[u8], signature: &[u8], budget: &mut SignatureBudget) -> Result<(), Error> {
        self.verifier
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
