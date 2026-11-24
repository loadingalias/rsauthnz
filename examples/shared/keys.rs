//! File custody for one example identity. The directory holds its private key and its public handle.

use std::fs::{self, File};
use std::io::{self, Read, Write};
use std::path::Path;

use rsauthnz::crypto::Algorithm;
use rsauthnz::custody::{Custody, FileCustody, Handle, Isolation, KeyId};
use rscrypto::ChaCha20Rng;

type Error = Box<dyn core::error::Error>;

/// An example identity with its private key in file custody.
#[derive(Debug)]
pub(crate) struct Keys {
    /// The custody of the private key.
    pub(crate) custody: FileCustody,
    /// The public key and its custody identifier.
    pub(crate) handle: Handle,
}

impl Keys {
    /// Creates an identity in a new directory, or reads the existing identity from disk.
    ///
    /// # Errors
    ///
    /// Returns the file or custody error. An incomplete enrollment requires a new directory.
    pub(crate) fn open(directory: &Path, record: &str, random: &mut ChaCha20Rng) -> Result<Self, Error> {
        let mut builder = fs::DirBuilder::new();
        #[cfg(unix)]
        std::os::unix::fs::DirBuilderExt::mode(&mut builder, 0o700);
        let created = match builder.create(directory) {
            Ok(()) => true,
            Err(error) if error.kind() == io::ErrorKind::AlreadyExists => false,
            Err(error) => return Err(error.into()),
        };
        let custody = FileCustody::open(directory, Isolation::User)?;
        let path = directory.join(record);
        let algorithm = Algorithm::MlDsa65Ed25519;
        let handle = if created {
            let id = KeyId::random(random);
            let mut file = File::create_new(path)?;
            let handle = custody.enroll(id, algorithm, random)?;
            file.write_all(&id.to_bytes())?;
            file.write_all(&handle.public_key())?;
            file.sync_all()?;
            #[cfg(unix)]
            File::open(directory)?.sync_all()?;
            handle
        } else {
            let mut file = File::open(path)?;
            let mut id = [0; 16];
            let mut public = [0; 1984];
            file.read_exact(&mut id)?;
            file.read_exact(&mut public)?;
            if file.read(&mut [0])? != 0 {
                return Err("the identity file has trailing bytes".into());
            }
            Handle::new(KeyId::from_bytes(id), algorithm, &public)?
        };
        Ok(Self { custody, handle })
    }
}
