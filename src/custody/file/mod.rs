//! The native software custody: one key file for each key, under OS file permissions.

#[cfg_attr(unix, path = "unix.rs")]
#[cfg_attr(windows, path = "windows.rs")]
mod os;

use alloc::vec::Vec;
use std::fs;
use std::io::{ErrorKind, Read, Write};
use std::path::PathBuf;

use rscrypto::ChaCha20Rng;

use super::{Custody, Error, Handle, Isolation, KeyId, Report};
use crate::crypto::Algorithm;
use crate::crypto::secret::SecretKey;

/// The software custody of the key files in one directory. Available with the feature `native-custody`, on Linux,
/// macOS, and Windows.
///
/// Each key is one file in the directory: the PKCS #8 encoding of the composite key, named by the key ID and
/// `.key`. Only the OS user account that runs the process can read it. On Linux and macOS, the file has the mode
/// `0600` and no extended ACL entry. On Windows, the user is its owner, and its DACL is protected and allows only
/// the user. Each operation checks these permissions, and it refuses a key file that another account can read. It
/// also refuses a link at the path, and a file of another owner. On Linux and macOS it refuses a FIFO or a device at
/// the path with no wait, and on Windows each other reparse point, such as the placeholder of a sync service.
///
/// The custody holds no key between operations. Each operation reads the key file into memory, checks that it holds
/// the key of the handle, signs, and then clears the key. Thus a key that one custody deletes refuses in each
/// custody.
///
/// ```
/// use rsauthnz::crypto::Algorithm;
/// use rsauthnz::custody::{Custody, FileCustody, Handle, Isolation, KeyId};
/// use rsauthnz::limits::{Limits, SignatureBudget};
/// use rscrypto::ChaCha20Rng;
///
/// let dir = std::env::temp_dir().join(format!("rsauthnz-custody-example-{}", std::process::id()));
/// std::fs::create_dir(&dir)?;
/// // Only for this example: take the seed from the entropy source of the host.
/// let mut random = ChaCha20Rng::from_seed([7; 32]);
///
/// let custody = FileCustody::open(&dir, Isolation::User)?;
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
/// std::fs::remove_dir(&dir)?;
/// # Ok::<(), Box<dyn std::error::Error>>(())
/// ```
#[derive(Debug)]
pub struct FileCustody {
    dir: PathBuf,
}

impl FileCustody {
    /// The report of each file custody.
    pub const REPORT: Report = Report {
        owner: "A key file of the OS user account that runs the process. Only that account can read it.",
        plaintext: "In process memory during one operation only. Swap space and a core dump can hold it.",
        zeroization: "rscrypto clears the key in memory after each operation. Delete removes the key file, \
                      but the storage device can keep its blocks.",
        recovery: "None. Enroll a new key, and register it with the authority.",
        isolation: Isolation::User,
    };

    /// Opens the custody of the key files in `dir`, which the caller selects.
    ///
    /// Cost class: [`External`](crate::limits::Class::External).
    ///
    /// # Errors
    ///
    /// [`Error::Isolation`] if `required` is stronger than [`Isolation::User`], before the custody reads the
    /// storage. [`Error::Storage`] if `dir` is not a directory.
    pub fn open(dir: impl Into<PathBuf>, required: Isolation) -> Result<Self, Error> {
        Self::REPORT.require(required)?;
        let dir = dir.into();
        if !fs::metadata(&dir)?.is_dir() {
            return Err(Error::Storage(ErrorKind::NotADirectory));
        }
        Ok(Self { dir })
    }

    /// The path of the key file of `id`.
    fn path(&self, id: KeyId) -> PathBuf {
        self.dir.join(alloc::format!("{id}.key"))
    }

    /// The key of `handle`, after the checks of its file: the permissions, the length, the algorithm, and the
    /// public key.
    fn load(&self, handle: &Handle) -> Result<SecretKey, Error> {
        let path = self.path(handle.id());
        let mut file = os::open(&path).map_err(|error| match fs::symlink_metadata(&path) {
            // The open follows no link, and a link at the path is no key file of the user.
            Ok(metadata) if metadata.file_type().is_symlink() => Error::Permissions,
            _ => unknown(error),
        })?;
        os::check(&file)?;
        let len = SecretKey::pkcs8_len(handle.algorithm()).ok_or(Error::Algorithm)?;
        (usize::try_from(file.metadata()?.len()) == Ok(len)).ok_or(Error::Mismatch)?;
        let key = SecretKey::read(handle.algorithm(), |out| file.read_exact(out))?;
        key.matches(&handle.key).ok_or(Error::Mismatch)?;
        Ok(key)
    }
}

impl Custody for FileCustody {
    fn report(&self) -> Report {
        Self::REPORT
    }

    fn enroll(&self, id: KeyId, algorithm: Algorithm, random: &mut ChaCha20Rng) -> Result<Handle, Error> {
        let (key, public) = SecretKey::generate(algorithm, random)?;
        let der = key.to_pkcs8()?;
        drop(key);
        let path = self.path(id);
        let mut file = os::create(&path).map_err(|error| match error.kind() {
            ErrorKind::AlreadyExists => Error::Exists,
            kind => Error::Storage(kind),
        })?;
        if let Err(error) = os::check(&file) {
            fs::remove_file(&path)?;
            return Err(error);
        }
        file.write_all(&der)?;
        file.sync_all()?;
        os::sync_dir(&self.dir)?;
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
        fs::remove_file(self.path(id)).map_err(unknown)?;
        os::sync_dir(&self.dir)
    }
}

/// The refusal of an operation on a key file: [`Error::Unknown`] if the file does not exist.
fn unknown(error: std::io::Error) -> Error {
    match error.kind() {
        ErrorKind::NotFound => Error::Unknown,
        kind => Error::Storage(kind),
    }
}

#[cfg(test)]
mod tests;
