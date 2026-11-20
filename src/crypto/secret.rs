//! The secret keys of the native custody binding: the only secret keys of the core.
//!
//! rscrypto builds each key in place in its allocation, and it clears the key when the key drops. Thus a key has one
//! copy in memory, and signing reads it in place. This module has no by-value key form, because a by-value key
//! leaves moved copies that nothing clears.

use alloc::alloc::Global;
use alloc::boxed::Box;
use alloc::vec::Vec;
use std::io::{self, ErrorKind};

use rscrypto::auth::{MlDsa65EcdsaP256, MlDsa65EcdsaP256SecretKey, MlDsa65Ed25519, MlDsa65Ed25519SecretKey};
use rscrypto::{ChaCha20Rng, SecretVec, SecretVecConstructionError};

use super::{Algorithm, Verifier};
use crate::custody::Error;

/// A composite secret key in custody memory.
pub(crate) enum SecretKey {
    MlDsa65Ed25519(Box<MlDsa65Ed25519SecretKey>),
    MlDsa65EcdsaP256(Box<MlDsa65EcdsaP256SecretKey>),
}

impl SecretKey {
    /// A new key of `algorithm` from the randomness of `random`, with its public key.
    ///
    /// # Errors
    ///
    /// [`Error::Algorithm`] if `algorithm` is not a composite. [`Error::Crypto`] if rscrypto refuses.
    pub(crate) fn generate(algorithm: Algorithm, random: &mut ChaCha20Rng) -> Result<(Self, Verifier), Error> {
        let fill = |out: &mut [u8]| {
            random.fill_bytes(out);
            Ok(())
        };
        let pair = match algorithm {
            Algorithm::MlDsa65Ed25519 => MlDsa65Ed25519::generate_keypair_in(fill, Global)
                .map(|(public, key)| (Self::MlDsa65Ed25519(key), Verifier::MlDsa65Ed25519(Box::new(public)))),
            Algorithm::MlDsa65EcdsaP256 => MlDsa65EcdsaP256::generate_keypair_in(fill, Global).map(|(public, key)| {
                (
                    Self::MlDsa65EcdsaP256(key),
                    Verifier::MlDsa65EcdsaP256(Box::new(public)),
                )
            }),
            Algorithm::Ed25519 | Algorithm::Es256 | Algorithm::MlDsa65 => return Err(Error::Algorithm),
        };
        pair.map_err(|_| Error::Crypto)
    }

    /// The length of the PKCS #8 encoding of a key of `algorithm`, or `None` if `algorithm` is not a composite.
    pub(crate) const fn pkcs8_len(algorithm: Algorithm) -> Option<usize> {
        match algorithm {
            Algorithm::MlDsa65Ed25519 => Some(MlDsa65Ed25519SecretKey::PKCS8_DER_LENGTH),
            Algorithm::MlDsa65EcdsaP256 => Some(MlDsa65EcdsaP256SecretKey::PKCS8_DER_LENGTH),
            Algorithm::Ed25519 | Algorithm::Es256 | Algorithm::MlDsa65 => None,
        }
    }

    /// The key of `algorithm` whose PKCS #8 encoding `read` writes into a buffer of [`Self::pkcs8_len`] bytes. The
    /// buffer is memory that rscrypto clears when it drops. The encoding must name `algorithm`, so a stored key never
    /// selects an algorithm.
    ///
    /// # Errors
    ///
    /// [`Error::Algorithm`] if `algorithm` is not a composite. [`Error::Storage`] if the allocator or `read` refuses.
    /// [`Error::Mismatch`] if the encoding is not a key of `algorithm`.
    pub(crate) fn read(algorithm: Algorithm, read: impl FnOnce(&mut [u8]) -> io::Result<()>) -> Result<Self, Error> {
        let len = Self::pkcs8_len(algorithm).ok_or(Error::Algorithm)?;
        let der = SecretVec::try_fill_with(len, read).map_err(|error| match error {
            SecretVecConstructionError::Allocation(_) => Error::Storage(ErrorKind::OutOfMemory),
            SecretVecConstructionError::Fill(error) => error.into(),
        })?;
        match algorithm {
            Algorithm::MlDsa65Ed25519 => {
                MlDsa65Ed25519SecretKey::from_pkcs8_der_in(&der, Global).map(Self::MlDsa65Ed25519)
            }
            Algorithm::MlDsa65EcdsaP256 => {
                MlDsa65EcdsaP256SecretKey::from_pkcs8_der_in(&der, Global).map(Self::MlDsa65EcdsaP256)
            }
            Algorithm::Ed25519 | Algorithm::Es256 | Algorithm::MlDsa65 => return Err(Error::Algorithm),
        }
        .map_err(|_| Error::Mismatch)
    }

    /// The PKCS #8 encoding of the key, in memory that rscrypto clears when it drops.
    ///
    /// # Errors
    ///
    /// [`Error::Storage`] with [`ErrorKind::OutOfMemory`] if the allocator refuses the memory.
    pub(crate) fn to_pkcs8(&self) -> Result<SecretVec, Error> {
        /// Encodes into a zeroed buffer of `N` bytes. The buffer has `N` bytes, so the only error is a refused
        /// allocation.
        fn encode<const N: usize>(write: impl FnOnce(&mut [u8; N])) -> Result<SecretVec, Error> {
            SecretVec::try_fill_with(N, |out| out.try_into().map(write))
                .map_err(|_| Error::Storage(ErrorKind::OutOfMemory))
        }
        match self {
            Self::MlDsa65Ed25519(key) => encode(|out| key.to_pkcs8_der_into(out)),
            Self::MlDsa65EcdsaP256(key) => encode(|out| key.to_pkcs8_der_into(out)),
        }
    }

    /// Whether `public` is the public key of this key.
    pub(crate) fn matches(&self, public: &Verifier) -> bool {
        match (self, public) {
            (Self::MlDsa65Ed25519(key), Verifier::MlDsa65Ed25519(public)) => key.public_key() == **public,
            (Self::MlDsa65EcdsaP256(key), Verifier::MlDsa65EcdsaP256(public)) => key.public_key() == **public,
            _ => false,
        }
    }

    /// The signature of `message`. The signing is hedged with the randomness of `random`, and it uses the empty
    /// context, as COSE requires.
    ///
    /// # Errors
    ///
    /// [`Error::Crypto`] if rscrypto refuses.
    pub(crate) fn sign(&self, message: &[u8], random: &mut ChaCha20Rng) -> Result<Vec<u8>, Error> {
        let fill = |out: &mut [u8]| {
            random.fill_bytes(out);
            Ok(())
        };
        match self {
            Self::MlDsa65Ed25519(key) => key
                .sign_with(message, &[], fill)
                .map(|signature| signature.as_bytes().to_vec()),
            Self::MlDsa65EcdsaP256(key) => key
                .sign_with(message, &[], fill)
                .map(|signature| signature.as_bytes().to_vec()),
        }
        .map_err(|_| Error::Crypto)
    }
}
