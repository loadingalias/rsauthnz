//! The secret keys of the native custody binding: the only secret keys of the core.
//!
//! rscrypto builds each key in place in its allocation, and it clears the key when the key drops. Signing reads the
//! key in place. An import reads the PKCS #8 encoding in place, and an export writes it into memory that clears itself
//! when it drops. Thus each copy of a key is in an owner that clears it, and an import or an export holds the encoding
//! and the key together for that one call. This module has no by-value key form, because a by-value key leaves moved
//! copies that nothing clears.

use alloc::alloc::Global;
use alloc::boxed::Box;
use alloc::vec;
use alloc::vec::Vec;
use std::io::{self, ErrorKind};

use rscrypto::auth::{
    MlDsa65EcdsaP256, MlDsa65EcdsaP256SecretKey, MlDsa65Ed25519, MlDsa65Ed25519SecretKey, SlhDsaSha2_128s,
    SlhDsaSha2_128sSecretKey,
};
use rscrypto::{ChaCha20Rng, SecretVec, SecretVecConstructionError};

use super::{Algorithm, Verifier};
use crate::custody::Error;

/// A secret key in custody memory: a composite key, or an SLH-DSA trust-root key.
pub(crate) enum SecretKey {
    MlDsa65Ed25519(Box<MlDsa65Ed25519SecretKey>),
    MlDsa65EcdsaP256(Box<MlDsa65EcdsaP256SecretKey>),
    SlhDsaSha2_128s(Box<SlhDsaSha2_128sSecretKey>),
}

impl SecretKey {
    /// A new key of `algorithm` from the randomness of `random`, with its public key.
    ///
    /// # Errors
    ///
    /// [`Error::Algorithm`] if `algorithm` is not a composite or SLH-DSA. [`Error::Crypto`] if rscrypto refuses.
    pub(crate) fn generate(algorithm: Algorithm, random: &mut ChaCha20Rng) -> Result<(Self, Verifier), Error> {
        let mut fill = |out: &mut [u8]| random.fill_bytes(out);
        match algorithm {
            Algorithm::MlDsa65Ed25519 => MlDsa65Ed25519::generate_keypair_in(
                |out| {
                    let _: () = fill(out);
                    Ok(())
                },
                Global,
            )
            .map(|(public, key)| (Self::MlDsa65Ed25519(key), Verifier::MlDsa65Ed25519(Box::new(public))))
            .map_err(|_| Error::Crypto),
            Algorithm::MlDsa65EcdsaP256 => MlDsa65EcdsaP256::generate_keypair_in(
                |out| {
                    let _: () = fill(out);
                    Ok(())
                },
                Global,
            )
            .map(|(public, key)| {
                (
                    Self::MlDsa65EcdsaP256(key),
                    Verifier::MlDsa65EcdsaP256(Box::new(public)),
                )
            })
            .map_err(|_| Error::Crypto),
            Algorithm::SlhDsaSha2_128s => SlhDsaSha2_128s::generate_keypair_in(
                |out| {
                    let _: () = fill(out);
                    Ok(())
                },
                Global,
            )
            .map(|(public, key)| (Self::SlhDsaSha2_128s(key), Verifier::SlhDsaSha2_128s(public)))
            .map_err(|_| Error::Crypto),
            Algorithm::Ed25519 | Algorithm::Es256 | Algorithm::Rs256 | Algorithm::Ps256 | Algorithm::MlDsa65 => {
                Err(Error::Algorithm)
            }
        }
    }

    /// The length of the PKCS #8 encoding of a key of `algorithm`, or `None` if custody holds no key of `algorithm`.
    /// An SLH-DSA key has the form of RFC 9909: 84 bytes.
    pub(crate) const fn pkcs8_len(algorithm: Algorithm) -> Option<usize> {
        match algorithm {
            Algorithm::MlDsa65Ed25519 => Some(MlDsa65Ed25519SecretKey::PKCS8_DER_LENGTH),
            Algorithm::MlDsa65EcdsaP256 => Some(MlDsa65EcdsaP256SecretKey::PKCS8_DER_LENGTH),
            Algorithm::SlhDsaSha2_128s => Some(SlhDsaSha2_128sSecretKey::PKCS8_DER_LENGTH),
            Algorithm::Ed25519 | Algorithm::Es256 | Algorithm::Rs256 | Algorithm::Ps256 | Algorithm::MlDsa65 => None,
        }
    }

    /// The key of `algorithm` whose PKCS #8 encoding `read` writes into a buffer of [`Self::pkcs8_len`] bytes. The
    /// buffer is memory that rscrypto clears when it drops.
    ///
    /// # Errors
    ///
    /// [`Error::Storage`] if the allocator or `read` refuses, and the errors of [`Self::from_pkcs8`].
    pub(crate) fn read(algorithm: Algorithm, read: impl FnOnce(&mut [u8]) -> io::Result<()>) -> Result<Self, Error> {
        let len = Self::pkcs8_len(algorithm).ok_or(Error::Algorithm)?;
        let der = SecretVec::try_fill_with(len, read).map_err(|error| match error {
            SecretVecConstructionError::Allocation(_) => Error::Storage(ErrorKind::OutOfMemory),
            SecretVecConstructionError::Fill(error) => error.into(),
        })?;
        Self::from_pkcs8(algorithm, &der)
    }

    /// The key of `algorithm` with the PKCS #8 encoding `der`, which it reads in place. The encoding must name
    /// `algorithm`, so a stored key never selects an algorithm.
    ///
    /// # Errors
    ///
    /// [`Error::Algorithm`] if custody holds no key of `algorithm`. [`Error::Mismatch`] if `der` is not a key of
    /// `algorithm`.
    pub(crate) fn from_pkcs8(algorithm: Algorithm, der: &[u8]) -> Result<Self, Error> {
        let key = match algorithm {
            Algorithm::MlDsa65Ed25519 => MlDsa65Ed25519SecretKey::from_pkcs8_der_in(der, Global)
                .map(Self::MlDsa65Ed25519)
                .ok(),
            Algorithm::MlDsa65EcdsaP256 => MlDsa65EcdsaP256SecretKey::from_pkcs8_der_in(der, Global)
                .map(Self::MlDsa65EcdsaP256)
                .ok(),
            Algorithm::SlhDsaSha2_128s => SlhDsaSha2_128sSecretKey::from_pkcs8_der_in(der, Global)
                .map(Self::SlhDsaSha2_128s)
                .ok(),
            Algorithm::Ed25519 | Algorithm::Es256 | Algorithm::Rs256 | Algorithm::Ps256 | Algorithm::MlDsa65 => {
                return Err(Error::Algorithm);
            }
        };
        key.ok_or(Error::Mismatch)
    }

    /// Writes the PKCS #8 encoding of the key into `out`, which has the [`Self::pkcs8_len`] of its algorithm.
    ///
    /// # Errors
    ///
    /// [`Error::Mismatch`] if `out` has another length.
    pub(crate) fn write_pkcs8(&self, out: &mut [u8]) -> Result<(), Error> {
        match self {
            Self::MlDsa65Ed25519(key) => key.to_pkcs8_der_into(out.try_into().map_err(|_| Error::Mismatch)?),
            Self::MlDsa65EcdsaP256(key) => key.to_pkcs8_der_into(out.try_into().map_err(|_| Error::Mismatch)?),
            Self::SlhDsaSha2_128s(key) => key.to_pkcs8_der_into(out.try_into().map_err(|_| Error::Mismatch)?),
        }
        Ok(())
    }

    /// The length of the PKCS #8 encoding of the key.
    pub(crate) const fn len(&self) -> usize {
        match self {
            Self::MlDsa65Ed25519(_) => MlDsa65Ed25519SecretKey::PKCS8_DER_LENGTH,
            Self::MlDsa65EcdsaP256(_) => MlDsa65EcdsaP256SecretKey::PKCS8_DER_LENGTH,
            Self::SlhDsaSha2_128s(_) => SlhDsaSha2_128sSecretKey::PKCS8_DER_LENGTH,
        }
    }

    /// The PKCS #8 encoding of the key, in memory that rscrypto clears when it drops.
    ///
    /// # Errors
    ///
    /// [`Error::Storage`] with [`ErrorKind::OutOfMemory`] if the allocator refuses the memory.
    pub(crate) fn to_pkcs8(&self) -> Result<SecretVec, Error> {
        SecretVec::try_fill_with(self.len(), |out| self.write_pkcs8(out)).map_err(|error| match error {
            SecretVecConstructionError::Allocation(_) => Error::Storage(ErrorKind::OutOfMemory),
            SecretVecConstructionError::Fill(error) => error,
        })
    }

    /// Whether `public` is the public key of this key.
    pub(crate) fn matches(&self, public: &Verifier) -> bool {
        match (self, public) {
            (Self::MlDsa65Ed25519(key), Verifier::MlDsa65Ed25519(public)) => key.public_key() == **public,
            (Self::MlDsa65EcdsaP256(key), Verifier::MlDsa65EcdsaP256(public)) => key.public_key() == **public,
            (Self::SlhDsaSha2_128s(key), Verifier::SlhDsaSha2_128s(public)) => key.public_key() == public,
            _ => false,
        }
    }

    /// The signature of `message`. The signing is hedged with the randomness of `random`, and it uses the empty
    /// context, as COSE requires. An SLH-DSA signature is about 2.5 million SHA-256 compressions: a root signs rarely.
    ///
    /// # Errors
    ///
    /// [`Error::Crypto`] if rscrypto refuses.
    pub(crate) fn sign(&self, message: &[u8], random: &mut ChaCha20Rng) -> Result<Vec<u8>, Error> {
        let mut fill = |out: &mut [u8]| random.fill_bytes(out);
        match self {
            Self::MlDsa65Ed25519(key) => key
                .sign_with(message, &[], |out| {
                    let _: () = fill(out);
                    Ok(())
                })
                .map(|signature| signature.as_bytes().to_vec())
                .map_err(|_| Error::Crypto),
            Self::MlDsa65EcdsaP256(key) => key
                .sign_with(message, &[], |out| {
                    let _: () = fill(out);
                    Ok(())
                })
                .map(|signature| signature.as_bytes().to_vec())
                .map_err(|_| Error::Crypto),
            Self::SlhDsaSha2_128s(key) => {
                let mut signature = vec![0; SlhDsaSha2_128s::SIGNATURE_LENGTH];
                let out = signature.as_mut_slice().try_into().map_err(|_| Error::Crypto)?;
                key.sign_with(
                    message,
                    &[],
                    |out| {
                        let _: () = fill(out);
                        Ok(())
                    },
                    out,
                )
                .map_err(|_| Error::Crypto)?;
                Ok(signature)
            }
        }
    }
}
