//! Custody: narrow enroll, sign, verify, rotate, and delete operations over keys that the application never holds.
//!
//! The application keeps a [`Handle`]: the ID, the algorithm, and the public key of one key. A handle holds no
//! secret, and it is not a permission. A [`Custody`] holds the secret key and signs with it. Its [`Report`] states
//! the owner of the key, the lifetime of the plaintext key, the zeroization, the recovery path, and the
//! [`Isolation`] that the OS enforces. A custody refuses a caller that requires more isolation than it gives.
//!
//! The contract is portable, so a host, such as a browser application, can supply its own custody. With the feature
//! `native-custody`, on Linux, macOS, and Windows, `FileCustody` keeps each key in a key file under OS file
//! permissions. On macOS, `KeychainCustody` keeps each key in the login keychain. A custody holds the composite keys,
//! [`Algorithm::MlDsa65Ed25519`] and [`Algorithm::MlDsa65EcdsaP256`], and the trust-root keys of
//! [`Algorithm::SlhDsaSha2_128s`], which sign issuer keys.
//!
//! Each random value comes from the seeded [`ChaCha20Rng`] of the caller: the key ID, each key, and the randomness
//! of each signature. The signing is hedged: rscrypto takes fresh randomness from the generator for each signature.
//!
//! [`ChaCha20Rng`]: rscrypto::ChaCha20Rng

#[cfg(all(feature = "native-custody", any(target_os = "linux", target_os = "macos", windows)))]
mod file;
#[cfg(all(feature = "native-custody", target_os = "macos"))]
mod keychain;

use alloc::vec::Vec;
use core::fmt;
use std::io;

use rscrypto::ChaCha20Rng;

#[cfg(all(feature = "native-custody", any(target_os = "linux", target_os = "macos", windows)))]
pub use file::FileCustody;
#[cfg(all(feature = "native-custody", target_os = "macos"))]
pub use keychain::KeychainCustody;

use crate::cose::{Key, PublicKey, TrustedKey};
use crate::crypto::{Algorithm, Verifier};
use crate::limits::{Limit, SignatureBudget};

/// The operations of a custody. The trait is object safe, so a host can supply its custody as `&dyn Custody`.
///
/// A lost response is an unknown outcome. Thus the caller draws each [`KeyId`] and records it before it enrolls the
/// key. After a lost response, it deletes that ID and enrolls again. A custody never retries an operation.
pub trait Custody {
    /// The guarantees of the custody.
    fn report(&self) -> Report;

    /// Makes a key of `algorithm` with the ID `id`, and gives its handle. The key is durable before the handle
    /// returns.
    ///
    /// Cost class: [`External`](crate::limits::Class::External).
    ///
    /// # Errors
    ///
    /// [`Error::Algorithm`] if the custody holds no keys of `algorithm`. [`Error::Exists`] if a key has the ID
    /// already. [`Error::Storage`], [`Error::Vault`], and [`Error::Crypto`] if the storage, the OS vault, or rscrypto
    /// refuses.
    fn enroll(&self, id: KeyId, algorithm: Algorithm, random: &mut ChaCha20Rng) -> Result<Handle, Error>;

    /// Makes the successor of the key of `from`: a key of the same algorithm with the ID `id`. The key of `from`
    /// stays until the caller deletes it, after the authority commits the successor.
    ///
    /// Cost class: [`External`](crate::limits::Class::External).
    ///
    /// # Errors
    ///
    /// [`Error::Unknown`], [`Error::Mismatch`], [`Error::Permissions`], [`Error::Storage`], and [`Error::Vault`] for
    /// the key of `from`, as [`Self::sign`] gives them. Then the errors of [`Self::enroll`].
    fn rotate(&self, from: &Handle, id: KeyId, random: &mut ChaCha20Rng) -> Result<Handle, Error>;

    /// The signature of `message` by the key of `handle`, with the algorithm `algorithm`.
    ///
    /// Cost class: [`External`](crate::limits::Class::External).
    ///
    /// # Errors
    ///
    /// [`Error::Algorithm`] if `algorithm` is not the algorithm of `handle`. [`Error::Unknown`] if the custody has
    /// no key with the ID of `handle`. [`Error::Mismatch`] if the key with that ID does not match `handle`.
    /// [`Error::Permissions`] if another account can read the key. [`Error::Storage`], [`Error::Vault`], and
    /// [`Error::Crypto`] if the storage, the OS vault, or rscrypto refuses.
    fn sign(
        &self,
        handle: &Handle,
        algorithm: Algorithm,
        message: &[u8],
        random: &mut ChaCha20Rng,
    ) -> Result<Vec<u8>, Error>;

    /// Deletes the key with the ID `id`. Then each handle of the key refuses.
    ///
    /// Cost class: [`External`](crate::limits::Class::External).
    ///
    /// # Errors
    ///
    /// [`Error::Unknown`] if the custody has no key with the ID. [`Error::Storage`] or [`Error::Vault`] if the storage
    /// or the OS vault refuses.
    fn delete(&self, id: KeyId) -> Result<(), Error>;
}

/// The ID of a key in a custody: 16 random bytes. Its text form is 32 lowercase hexadecimal digits.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub struct KeyId([u8; 16]);

impl KeyId {
    /// A new ID from `random`.
    ///
    /// Cost class: [`Parse`](crate::limits::Class::Parse).
    #[must_use]
    pub fn random(random: &mut ChaCha20Rng) -> Self {
        let mut id = [0; 16];
        random.fill_bytes(&mut id);
        Self(id)
    }

    /// The ID with the bytes `bytes`, for an ID that the application stored.
    ///
    /// Cost class: [`Parse`](crate::limits::Class::Parse).
    #[must_use]
    pub const fn from_bytes(bytes: [u8; 16]) -> Self {
        Self(bytes)
    }

    /// The bytes of the ID.
    ///
    /// Cost class: [`Parse`](crate::limits::Class::Parse).
    #[must_use]
    pub const fn to_bytes(self) -> [u8; 16] {
        self.0
    }
}

impl fmt::Display for KeyId {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        self.0.iter().try_for_each(|byte| write!(f, "{byte:02x}"))
    }
}

/// The handle of a key in a custody: its ID, its algorithm, and its public key. It holds no secret.
#[derive(Clone, PartialEq, Eq)]
pub struct Handle {
    id: KeyId,
    key: Verifier,
}

impl Handle {
    /// The handle of the key `id` of `algorithm` with the public key `public`. An application uses it for a
    /// handle that it stored, and a host custody uses it for each key that it makes.
    ///
    /// Cost class: [`Verify`](crate::limits::Class::Verify). A P-256 key checks its point.
    ///
    /// # Errors
    ///
    /// [`Error::Algorithm`] if `algorithm` is not a composite or SLH-DSA. [`Error::Mismatch`] if `public` is not a
    /// public key of `algorithm`.
    pub fn new(id: KeyId, algorithm: Algorithm, public: &[u8]) -> Result<Self, Error> {
        let held = matches!(
            algorithm,
            Algorithm::MlDsa65Ed25519 | Algorithm::MlDsa65EcdsaP256 | Algorithm::SlhDsaSha2_128s
        );
        held.ok_or(Error::Algorithm)?;
        Ok(Self {
            id,
            key: Verifier::from_bytes(algorithm, public).ok_or(Error::Mismatch)?,
        })
    }

    /// The ID of the key.
    #[must_use]
    pub const fn id(&self) -> KeyId {
        self.id
    }

    /// The algorithm of the key.
    #[must_use]
    pub const fn algorithm(&self) -> Algorithm {
        self.key.algorithm()
    }

    /// The public key: the encoding of the LAMPS draft for a composite key (the `pub` of its `COSE_Key`), and PK.seed
    /// then PK.root for an SLH-DSA key.
    #[must_use]
    pub fn public_key(&self) -> Vec<u8> {
        self.key.to_bytes()
    }

    /// Whether `signature` is a valid signature of `message` by the key, with the empty context. The check first
    /// charges `budget` with one check for each component: two for a composite key, and one for an SLH-DSA key.
    ///
    /// Cost class: [`Verify`](crate::limits::Class::Verify).
    ///
    /// # Errors
    ///
    /// [`Limit::SignatureChecks`] if `budget` has less than the checks of the key. Then the check does no signature
    /// work.
    pub fn verify(&self, message: &[u8], signature: &[u8], budget: &mut SignatureBudget) -> Result<bool, Limit> {
        self.key.verify(message, signature, budget)
    }

    /// The trusted key of the public key, which checks the artifacts that the key signs, or `None` for an SLH-DSA
    /// key, which has no COSE identifier and signs no artifact of this crate.
    pub(crate) fn trusted(&self) -> Option<TrustedKey> {
        let bytes = self.key.to_bytes();
        let public = match self.algorithm() {
            Algorithm::MlDsa65Ed25519 => bytes.as_slice().try_into().map(PublicKey::MlDsa65Ed25519).ok(),
            Algorithm::MlDsa65EcdsaP256 => bytes.as_slice().try_into().map(PublicKey::MlDsa65EcdsaP256).ok(),
            _ => None,
        };
        let key = public.map(|public| Key {
            kid: None,
            alg: None,
            public,
        });
        // `Handle::new` made the same verifier from the same bytes, so a composite key gives its trusted key.
        key.and_then(|key| TrustedKey::new(self.algorithm(), &key).ok())
    }
}

impl fmt::Debug for Handle {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("Handle")
            .field("id", &self.id)
            .field("algorithm", &self.algorithm())
            .finish()
    }
}

/// The isolation of a key: the boundary that the OS enforces around it. A later variant is stronger.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum Isolation {
    /// The OS user account. Another account cannot read the key. Each process of the same account can, and so can
    /// an administrator or root.
    User,
    /// The process. A hostile process of the same account cannot read the key or sign with it.
    Process,
}

/// The guarantees of a custody. A custody that the host supplies states its own values.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Report {
    /// The owner of the key at rest.
    pub owner: &'static str,
    /// The lifetime of the plaintext key in memory.
    pub plaintext: &'static str,
    /// What clears the key from memory and from storage.
    pub zeroization: &'static str,
    /// The recovery path after the loss of a key.
    pub recovery: &'static str,
    /// The boundary that the OS enforces.
    pub isolation: Isolation,
}

impl Report {
    /// Refuses a caller that requires more isolation than the custody gives.
    ///
    /// Cost class: [`Parse`](crate::limits::Class::Parse).
    ///
    /// # Errors
    ///
    /// [`Error::Isolation`] if `required` is stronger than [`Self::isolation`].
    pub fn require(&self, required: Isolation) -> Result<(), Error> {
        (required <= self.isolation).ok_or(Error::Isolation)
    }
}

/// The refusal of a custody operation. It holds no key byte and no path.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
#[non_exhaustive]
pub enum Error {
    /// The custody cannot give the isolation that the caller requires. Use a custody whose report gives it.
    Isolation,
    /// The custody holds no keys of the algorithm, or the algorithm is not that of the handle.
    Algorithm,
    /// The custody has no key with the ID: the key was deleted, or another custody holds it.
    Unknown,
    /// A key with the ID exists. Delete it, or draw another ID.
    Exists,
    /// The stored key does not match the handle: it has another public key, or it is damaged. Delete it, and enroll
    /// a new key.
    Mismatch,
    /// Another account can read or change the stored key, or the custody cannot read its permissions. Delete the key,
    /// and enroll a new key.
    Permissions,
    /// The storage refused the operation, with the kind of the OS error.
    Storage(io::ErrorKind),
    /// The OS vault refused the operation, with its status code: an `OSStatus` of the macOS keychain.
    Vault(i32),
    /// rscrypto refused to make the key or the signature.
    Crypto,
}

impl fmt::Display for Error {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Isolation => f.write_str("the custody cannot give the required isolation"),
            Self::Algorithm => f.write_str("the custody holds no key of this algorithm"),
            Self::Unknown => f.write_str("the custody has no key with this ID"),
            Self::Exists => f.write_str("a key with this ID exists"),
            Self::Mismatch => f.write_str("the stored key does not match the handle"),
            Self::Permissions => f.write_str("another account can read or change the stored key"),
            Self::Storage(kind) => write!(f, "the storage refused the operation: {kind}"),
            Self::Vault(code) => write!(f, "the OS vault refused the operation: status {code}"),
            Self::Crypto => f.write_str("rscrypto refused the operation"),
        }
    }
}

impl core::error::Error for Error {}

impl From<io::Error> for Error {
    fn from(error: io::Error) -> Self {
        Self::Storage(error.kind())
    }
}
