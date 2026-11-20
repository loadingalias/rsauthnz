//! The OS-vault custody of macOS: one item of the login keychain for each key.

mod sys;

use alloc::format;
use alloc::string::String;
use alloc::vec::Vec;

use rscrypto::ChaCha20Rng;

use super::{Custody, Error, Handle, Isolation, KeyId, Report};
use crate::crypto::Algorithm;
use crate::crypto::secret::SecretKey;

/// The custody of keys in the login keychain of macOS. Available with the feature `native-custody`, on macOS.
///
/// Each key is one generic-password item of the login keychain of the OS user account that runs the process. Its
/// service is the service of the custody, its account is the key ID, and its data is the PKCS #8 encoding of the
/// composite key. The item does not synchronize through iCloud. macOS encrypts the keychain with a key from the login
/// password of the user. No hardware keeps the key: the custody reads the key into process memory to sign.
///
/// macOS gives an item without a dialog only to the program that made it. Another program, or a build of the program
/// with another code signature, gets the item only after the user allows it in a dialog. Thus sign the program with a
/// stable identity, so that an update keeps its access. A locked keychain also shows a dialog. In a session that
/// cannot show a dialog, such as an SSH session, the operation refuses with [`Error::Vault`].
///
/// The custody holds no key between operations. Each operation reads the item, checks that it holds the key of the
/// handle, signs, and then clears the key. macOS gives the item in memory of its own. The custody releases that memory
/// before it signs, but it cannot clear it.
///
/// ```
/// use rsauthnz::crypto::Algorithm;
/// use rsauthnz::custody::{Custody, Handle, Isolation, KeyId, KeychainCustody};
/// use rsauthnz::limits::{Limits, SignatureBudget};
/// use rscrypto::ChaCha20Rng;
///
/// // Name the keys of the application with a service, such as its bundle ID. Only for this example: the process ID
/// // keeps the items of each run apart.
/// let service = format!("com.example.rsauthnz-example.{}", std::process::id());
/// // Only for this example: take the seed from the entropy source of the host.
/// let mut random = ChaCha20Rng::from_seed([7; 32]);
///
/// let custody = KeychainCustody::open(service, Isolation::User)?;
/// // Draw the key ID, and record it before the enroll. After a lost response, delete the ID and enroll again.
/// let id = KeyId::random(&mut random);
/// let enrolled = custody.enroll(id, Algorithm::MlDsa65Ed25519, &mut random)?;
/// // Store the ID, the algorithm, and the public key. They make the handle again after a restart.
/// let handle = Handle::new(enrolled.id(), enrolled.algorithm(), &enrolled.public_key())?;
///
/// let signature = custody.sign(&handle, Algorithm::MlDsa65Ed25519, b"message", &mut random)?;
/// let mut budget = SignatureBudget::new(&Limits::default());
/// assert_eq!(handle.verify(b"message", &signature, &mut budget), Ok(true));
///
/// custody.delete(id)?;
/// # Ok::<(), Box<dyn std::error::Error>>(())
/// ```
#[derive(Debug)]
pub struct KeychainCustody {
    service: String,
}

impl KeychainCustody {
    /// The report of each Keychain custody.
    pub const REPORT: Report = Report {
        owner: "An item of the login keychain of the OS user account that runs the process. macOS gives it to another \
                program, or to a build of the program with another code signature, only after the user allows it in \
                a dialog.",
        plaintext: "macOS decrypts the item and gives it to the process for one operation. In process memory during \
                    that operation only. Swap space and a core dump can hold it.",
        zeroization: "rscrypto clears its copy of the key after each operation. macOS frees its copy of the item, \
                      which the custody cannot clear. Delete removes the item. A backup of the login keychain keeps \
                      the item, encrypted.",
        recovery: "None. Enroll a new key, and register it with the authority.",
        isolation: Isolation::User,
    };

    /// Opens the custody of the keychain items of `service`, which the caller selects.
    ///
    /// Cost class: [`Parse`](crate::limits::Class::Parse). The custody does no keychain work until an operation.
    ///
    /// # Errors
    ///
    /// [`Error::Isolation`] if `required` is stronger than [`Isolation::User`].
    pub fn open(service: impl Into<String>, required: Isolation) -> Result<Self, Error> {
        Self::REPORT.require(required)?;
        Ok(Self {
            service: service.into(),
        })
    }

    /// The key of `handle`, after the checks of its item: the length, the algorithm, and the public key.
    fn load(&self, handle: &Handle) -> Result<SecretKey, Error> {
        let len = SecretKey::pkcs8_len(handle.algorithm()).ok_or(Error::Algorithm)?;
        // The item releases its data at the end of the block, before the signature work.
        let key = {
            let item = sys::copy(&self.service, &account(handle.id()))?;
            let der = item.bytes();
            (der.len() == len).ok_or(Error::Mismatch)?;
            SecretKey::read(handle.algorithm(), |out| {
                out.copy_from_slice(der);
                Ok(())
            })?
        };
        key.matches(&handle.key).ok_or(Error::Mismatch)?;
        Ok(key)
    }
}

impl Custody for KeychainCustody {
    fn report(&self) -> Report {
        Self::REPORT
    }

    fn enroll(&self, id: KeyId, algorithm: Algorithm, random: &mut ChaCha20Rng) -> Result<Handle, Error> {
        let (key, public) = SecretKey::generate(algorithm, random)?;
        let der = key.to_pkcs8()?;
        drop(key);
        sys::add(&self.service, &account(id), &der)?;
        Ok(Handle { id, key: public })
    }

    fn rotate(&self, from: &Handle, id: KeyId, random: &mut ChaCha20Rng) -> Result<Handle, Error> {
        self.load(from)?;
        self.enroll(id, from.algorithm(), random)
    }

    fn sign(
        &self,
        handle: &Handle,
        algorithm: Algorithm,
        message: &[u8],
        random: &mut ChaCha20Rng,
    ) -> Result<Vec<u8>, Error> {
        (algorithm == handle.algorithm()).ok_or(Error::Algorithm)?;
        self.load(handle)?.sign(message, random)
    }

    fn delete(&self, id: KeyId) -> Result<(), Error> {
        sys::delete(&self.service, &account(id))
    }
}

/// The account of the item of `id`: the text form of the key ID.
fn account(id: KeyId) -> String {
    format!("{id}")
}

#[cfg(test)]
mod tests;
