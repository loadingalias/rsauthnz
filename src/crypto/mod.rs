//! Signature profiles, and the facade of [rscrypto]: the only module of the core that calls its signatures,
//! digests, and secret keys. Other modules use only its random generator.
//!
//! [`Algorithm`] is the registry of the trusted signature profiles, and [`Algorithm::report`] gives the guarantee of
//! each profile. The default profile is composite ML-DSA-65 + Ed25519. SLH-DSA-SHA2-128s is the trust-root profile.
//! Each signature check of the crate goes through one function, which charges a [`SignatureBudget`] before its work.
//! Each digest goes through one SHA-256 function.
//!
//! The composite profiles are those of the [LAMPS composite signatures] (draft 19, which becomes RFC 10073). Both
//! components sign the same message, and a composite signature verifies only if both components verify. rscrypto
//! does the construction, and this crate adds no combiner. COSE uses the empty context of the construction, as the
//! [JOSE and COSE composite draft] requires.
//!
//! ```
//! use rsauthnz::crypto::{Algorithm, Authentication, Registration};
//!
//! let report = Algorithm::default().report();
//! assert_eq!(report.authentication, Authentication::Hybrid);
//! // IANA has not assigned the composite COSE identifiers yet.
//! assert_eq!(report.registration, Registration::Draft);
//! // A classical profile is never reported as post-quantum.
//! assert_eq!(Algorithm::Ed25519.report().authentication, Authentication::Classical);
//! // The trust-root profile has no COSE identifier yet.
//! assert_eq!(Algorithm::SlhDsaSha2_128s.report().cose, None);
//! ```
//!
//! [rscrypto]: https://crates.io/crates/rscrypto
//! [LAMPS composite signatures]: https://datatracker.ietf.org/doc/draft-ietf-lamps-pq-composite-sigs/
//! [JOSE and COSE composite draft]: https://datatracker.ietf.org/doc/draft-ietf-jose-pq-composite-sigs/

#[cfg(all(feature = "native-custody", any(target_os = "linux", target_os = "macos", windows)))]
pub(crate) mod secret;

use alloc::boxed::Box;
use alloc::vec::Vec;

use rscrypto::auth::{
    EcdsaP256PublicKey, EcdsaP256Signature, Ed25519PublicKey, Ed25519Signature, MlDsa65EcdsaP256PublicKey,
    MlDsa65EcdsaP256Signature, MlDsa65Ed25519PublicKey, MlDsa65Ed25519Signature, MlDsa65PublicKey, MlDsa65Signature,
};
use rscrypto::{RsaPkcs1v15Profile, RsaPublicKey, RsaPublicKeyPolicy};

use crate::limits::{Limit, SignatureBudget};

/// The COSE identifier of composite ML-DSA-65 + Ed25519. DRAFT: draft-ietf-jose-pq-composite-sigs-06 (section
/// 7.2.6) requests -59, and IANA has not assigned it. A change of the draft changes only this constant.
const ML_DSA_65_ED25519_DRAFT: i64 = -59;

/// The COSE identifier of composite ML-DSA-65 + ECDSA P-256. DRAFT: draft-ietf-jose-pq-composite-sigs-06 (section
/// 7.2.2) requests -55, and IANA has not assigned it. A change of the draft changes only this constant.
const ML_DSA_65_ECDSA_P256_DRAFT: i64 = -55;

/// A trusted signature profile: the algorithm of a trusted key. A trusted profile fixes the algorithm, so input never
/// selects one.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq, Hash)]
pub enum Algorithm {
    /// Ed25519 (COSE algorithm -19, [RFC 9864](https://www.rfc-editor.org/rfc/rfc9864)). A classical profile.
    Ed25519,
    /// ECDSA with P-256 and SHA-256 (COSE algorithm -7). A classical profile. IANA marks -7 deprecated since
    /// [RFC 9864](https://www.rfc-editor.org/rfc/rfc9864), which assigns ESP256 (-9). This profile keeps -7, because it
    /// serves a verifier that supports nothing else.
    Es256,
    /// RSASSA-PKCS1-v1_5 with SHA-256 (COSE algorithm -257), with a modulus of 2,048 to 4,096 bits and the exponent
    /// 65,537. A classical profile that only verifies: the passkeys of some authenticators, such as Windows Hello, use
    /// it. No credential of this crate and no custody key has it.
    Rs256,
    /// ML-DSA-65 (COSE algorithm -49, [RFC 9964](https://www.rfc-editor.org/rfc/rfc9964)), for a verifier that
    /// supports ML-DSA but not the composite.
    MlDsa65,
    /// Composite ML-DSA-65 + Ed25519 (`id-MLDSA65-Ed25519-SHA512`, X.509 OID 1.3.6.1.5.5.7.6.48): the default
    /// profile.
    #[default]
    MlDsa65Ed25519,
    /// Composite ML-DSA-65 + ECDSA P-256 (`id-MLDSA65-ECDSA-P256-SHA512`, X.509 OID 1.3.6.1.5.5.7.6.45): the
    /// hardware-bound profile, for a key whose P-256 half is in a Secure Enclave, a TPM, or StrongBox.
    MlDsa65EcdsaP256,
    /// SLH-DSA-SHA2-128s ([FIPS 205](https://csrc.nist.gov/pubs/fips/205/final)), pure, with the empty context: the
    /// trust-root profile. A root signs issuer keys, not credentials. Its security rests only on SHA-256. It is in NIST
    /// security category 1, below the category 3 of ML-DSA-65. The profile has no COSE identifier yet. The crate does
    /// not verify it yet: the operations of the trust root bring its verifier.
    SlhDsaSha2_128s,
}

impl Algorithm {
    /// Each algorithm of the registry.
    pub(crate) const ALL: [Self; 7] = [
        Self::Ed25519,
        Self::Es256,
        Self::Rs256,
        Self::MlDsa65,
        Self::MlDsa65Ed25519,
        Self::MlDsa65EcdsaP256,
        Self::SlhDsaSha2_128s,
    ];

    /// The report of the profile.
    #[must_use]
    pub const fn report(&self) -> Report {
        let (cose, registration, authentication) = match self {
            Self::Ed25519 => (Some(-19), Registration::Assigned, Authentication::Classical),
            Self::Es256 => (Some(-7), Registration::Assigned, Authentication::Classical),
            Self::Rs256 => (Some(-257), Registration::Assigned, Authentication::Classical),
            Self::MlDsa65 => (Some(-49), Registration::Assigned, Authentication::PostQuantum),
            Self::MlDsa65Ed25519 => (
                Some(ML_DSA_65_ED25519_DRAFT),
                Registration::Draft,
                Authentication::Hybrid,
            ),
            Self::MlDsa65EcdsaP256 => (
                Some(ML_DSA_65_ECDSA_P256_DRAFT),
                Registration::Draft,
                Authentication::Hybrid,
            ),
            // draft-ietf-cose-sphincs-plus-11 requests -51, but IANA assigned -51 to ESP384 (RFC 9864). Thus this crate
            // uses no value until IANA assigns one.
            Self::SlhDsaSha2_128s => (None, Registration::Draft, Authentication::PostQuantum),
        };
        Report {
            cose,
            registration,
            authentication,
        }
    }

    /// The signature checks of one signature: one for each component.
    const fn checks(self) -> usize {
        match self {
            Self::Ed25519 | Self::Es256 | Self::Rs256 | Self::MlDsa65 | Self::SlhDsaSha2_128s => 1,
            Self::MlDsa65Ed25519 | Self::MlDsa65EcdsaP256 => 2,
        }
    }
}

/// The facts of a signature profile, for evidence, audit, and diagnostics.
///
/// The report gives only the authentication of a signature. It says nothing about key exchange. The evidence of the
/// transport gives the key exchange as a separate guarantee, so a post-quantum signature over a classical key
/// exchange is not post-quantum end to end.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
#[non_exhaustive]
pub struct Report {
    /// The COSE algorithm identifier, or `None` if this crate uses no COSE identifier for the profile yet.
    pub cose: Option<i64>,
    /// The registration of a COSE identifier for the profile.
    pub registration: Registration,
    /// The authentication that a valid signature gives.
    pub authentication: Authentication,
}

/// The registration of a COSE algorithm identifier.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Registration {
    /// IANA assigned the identifier.
    Assigned,
    /// A draft requests the identifier, and IANA has not assigned it. A later draft can change it, and another
    /// implementation can use another value.
    Draft,
}

/// The authentication that a valid signature of a profile gives.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Authentication {
    /// A post-quantum signature and a classical signature over the same message. The signature verifies only if both
    /// components verify, so a forgery must break both algorithms.
    Hybrid,
    /// A post-quantum signature only: ML-DSA-65 or SLH-DSA.
    PostQuantum,
    /// A classical signature only. It gives no post-quantum authentication.
    Classical,
}

/// A public key that verifies the signatures of one algorithm.
#[derive(Clone)]
pub(crate) enum Verifier {
    Ed25519(Ed25519PublicKey),
    Es256(Box<EcdsaP256PublicKey>),
    Rs256(Box<RsaPublicKey>),
    MlDsa65(Box<MlDsa65PublicKey>),
    MlDsa65Ed25519(Box<MlDsa65Ed25519PublicKey>),
    MlDsa65EcdsaP256(Box<MlDsa65EcdsaP256PublicKey>),
}

impl Verifier {
    /// The Ed25519 key with the encoded point `x`.
    pub(crate) fn ed25519(x: &[u8; 32]) -> Self {
        Self::Ed25519(Ed25519PublicKey::from_bytes(*x))
    }

    /// The P-256 key with the coordinates `x` and `y`, or `None` if the point is not on the curve.
    pub(crate) fn es256(x: &[u8; 32], y: &[u8; 32]) -> Option<Self> {
        let mut sec1 = [0x04; EcdsaP256PublicKey::SEC1_LENGTH];
        sec1[1..33].copy_from_slice(x);
        sec1[33..].copy_from_slice(y);
        let key = EcdsaP256PublicKey::from_sec1_bytes(&sec1).ok()?;
        Some(Self::Es256(Box::new(key)))
    }

    /// The RSA key with the modulus `n` and the exponent `e`, each as an unsigned big-endian integer, or `None` if the
    /// modulus does not have 2,048 to 4,096 bits or the exponent is not 65,537 in its shortest form.
    pub(crate) fn rs256(n: &[u8], e: &[u8]) -> Option<Self> {
        (e == [1, 0, 1]).then_some(())?;
        let policy = RsaPublicKeyPolicy::MODULUS_2048_TO_8192.with_max_modulus_bits(4096);
        let key = RsaPublicKey::from_modulus_exponent_with_policy(n, 65_537, &policy).ok()?;
        Some(Self::Rs256(Box::new(key)))
    }

    /// The ML-DSA-65 key with the encoding `public`.
    pub(crate) fn ml_dsa_65(public: &[u8; 1952]) -> Self {
        Self::MlDsa65(Box::new(MlDsa65PublicKey::from_bytes(*public)))
    }

    /// The ML-DSA-65 + Ed25519 key with the encoding `public`. rscrypto accepts each encoding of this length.
    pub(crate) fn ml_dsa_65_ed25519(public: &[u8; 1984]) -> Option<Self> {
        let key = MlDsa65Ed25519PublicKey::from_bytes(public).ok()?;
        Some(Self::MlDsa65Ed25519(Box::new(key)))
    }

    /// The ML-DSA-65 + ECDSA P-256 key with the encoding `public`, or `None` if the P-256 point is not on the curve.
    pub(crate) fn ml_dsa_65_ecdsa_p256(public: &[u8; 2017]) -> Option<Self> {
        let key = MlDsa65EcdsaP256PublicKey::from_bytes(public).ok()?;
        Some(Self::MlDsa65EcdsaP256(Box::new(key)))
    }

    /// The encoding of the key: the 32 bytes of an Ed25519 key, the uncompressed SEC1 point of a P-256 key, the
    /// `RSAPublicKey` DER of an RSA key, and the encoding of FIPS 204 or of the LAMPS draft for an ML-DSA-65 or
    /// composite key.
    pub(crate) fn to_bytes(&self) -> Vec<u8> {
        match self {
            Self::Ed25519(key) => key.as_bytes().to_vec(),
            Self::Es256(key) => key.to_sec1_bytes().to_vec(),
            Self::Rs256(key) => key.to_pkcs1_der(),
            Self::MlDsa65(key) => key.as_bytes().to_vec(),
            Self::MlDsa65Ed25519(key) => key.to_bytes().to_vec(),
            Self::MlDsa65EcdsaP256(key) => key.to_bytes().to_vec(),
        }
    }

    /// The algorithm of the key.
    pub(crate) const fn algorithm(&self) -> Algorithm {
        match self {
            Self::Ed25519(_) => Algorithm::Ed25519,
            Self::Es256(_) => Algorithm::Es256,
            Self::Rs256(_) => Algorithm::Rs256,
            Self::MlDsa65(_) => Algorithm::MlDsa65,
            Self::MlDsa65Ed25519(_) => Algorithm::MlDsa65Ed25519,
            Self::MlDsa65EcdsaP256(_) => Algorithm::MlDsa65EcdsaP256,
        }
    }

    /// Whether `signature` is a valid signature over `message`. ML-DSA-65 and the composites use the empty context.
    ///
    /// The check first charges `budget` with its cost: one check for each component. If the budget has less, the
    /// check refuses with [`Limit::SignatureChecks`] and does no signature work.
    pub(crate) fn verify(&self, message: &[u8], signature: &[u8], budget: &mut SignatureBudget) -> Result<bool, Limit> {
        budget.charge(self.algorithm().checks())?;
        Ok(match self {
            Self::Ed25519(key) => <[u8; 64]>::try_from(signature)
                .is_ok_and(|signature| key.verify(message, &Ed25519Signature::from_bytes(signature)).is_ok()),
            Self::Es256(key) => <[u8; 64]>::try_from(signature)
                .ok()
                .and_then(|signature| EcdsaP256Signature::from_bytes(signature).ok())
                .is_some_and(|signature| key.verify(message, &signature).is_ok()),
            Self::Rs256(key) => key
                .verify_pkcs1v15(RsaPkcs1v15Profile::Sha256, message, signature)
                .is_ok(),
            Self::MlDsa65(key) => MlDsa65Signature::try_from_slice(signature)
                .is_ok_and(|signature| key.verify(message, &signature).is_ok()),
            Self::MlDsa65Ed25519(key) => MlDsa65Ed25519Signature::try_from_slice(signature)
                .is_ok_and(|signature| key.verify(message, &signature).is_ok()),
            Self::MlDsa65EcdsaP256(key) => MlDsa65EcdsaP256Signature::try_from_slice(signature)
                .is_ok_and(|signature| key.verify(message, &signature).is_ok()),
        })
    }
}

/// The SHA-256 digest of `message`.
pub(crate) fn sha256(message: &[u8]) -> [u8; 32] {
    rscrypto::Sha256::digest(message)
}

/// The SHA-256 digest of the concatenation of `parts`, with no buffer that holds it. Thus a part can be a secret: the
/// hasher clears its state when it drops.
pub(crate) fn sha256_parts(parts: &[&[u8]]) -> [u8; 32] {
    let mut hasher = rscrypto::Sha256::new();
    for part in parts {
        hasher.update(part);
    }
    hasher.finalize()
}

/// Two keys are equal when their algorithms and their public keys are equal.
impl PartialEq for Verifier {
    fn eq(&self, other: &Self) -> bool {
        match (self, other) {
            (Self::Ed25519(a), Self::Ed25519(b)) => a.as_bytes() == b.as_bytes(),
            (Self::Es256(a), Self::Es256(b)) => a.to_sec1_bytes() == b.to_sec1_bytes(),
            (Self::Rs256(a), Self::Rs256(b)) => a.modulus() == b.modulus(),
            (Self::MlDsa65(a), Self::MlDsa65(b)) => a == b,
            (Self::MlDsa65Ed25519(a), Self::MlDsa65Ed25519(b)) => a == b,
            (Self::MlDsa65EcdsaP256(a), Self::MlDsa65EcdsaP256(b)) => a == b,
            _ => false,
        }
    }
}

impl Eq for Verifier {}

#[cfg(test)]
mod tests;
