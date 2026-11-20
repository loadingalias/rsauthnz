//! The contracts of the software custody: delete, the key ID, rotation, the isolation, the permissions and the
//! match of a key file, and the absence of key bytes in each value that the application sees.

use alloc::format;
use alloc::string::String;
use alloc::vec::Vec;
use core::assert_matches;
use core::mem::DropGuard;
use std::fs;
use std::path::{Path, PathBuf};

use rscrypto::ChaCha20Rng;
use rscrypto::auth::MlDsa65Ed25519SecretKey;

use super::FileCustody;
use crate::crypto::Algorithm;
use crate::custody::{Custody, Error, Handle, Isolation, KeyId};
use crate::limits::{Limits, SignatureBudget};

/// A new directory for the test `name`. The guard removes it.
fn scratch(name: &str) -> DropGuard<PathBuf, impl FnOnce(PathBuf)> {
    let dir = std::env::temp_dir().join(format!("rsauthnz-custody-{}-{name}", std::process::id()));
    fs::create_dir(&dir).unwrap();
    DropGuard::new(dir, |dir| fs::remove_dir_all(dir).unwrap_or_default())
}

/// The path of the key file of `id` in `dir`: the key ID and `.key`, as the custody page gives.
fn key_file(dir: &Path, id: KeyId) -> PathBuf {
    dir.join(format!("{id}.key"))
}

/// Whether `signature` is a signature of `message` by the key of `handle`.
fn verifies(handle: &Handle, message: &[u8], signature: &[u8]) -> bool {
    handle.verify(message, signature, &mut SignatureBudget::new(&Limits::default())) == Ok(true)
}

#[test]
fn delete_removes_the_key_file_and_each_handle_refuses() {
    let dir = scratch("delete");
    let custody = FileCustody::open(&*dir, Isolation::User).unwrap();
    let mut random = ChaCha20Rng::from_seed([1; 32]);
    let id = KeyId::random(&mut random);
    let handle = custody.enroll(id, Algorithm::MlDsa65Ed25519, &mut random).unwrap();
    // The application stores the parts of a handle, and it makes the handle again after a restart.
    let stored = Handle::new(id, handle.algorithm(), &handle.public_key()).unwrap();
    let signature = custody
        .sign(&stored, Algorithm::MlDsa65Ed25519, b"message", &mut random)
        .unwrap();
    assert!(verifies(&handle, b"message", &signature));

    custody.delete(id).unwrap();
    assert!(!key_file(&dir, id).exists());
    assert_eq!(
        custody.sign(&handle, Algorithm::MlDsa65Ed25519, b"message", &mut random),
        Err(Error::Unknown)
    );
    // The custody keeps no key between operations, so the delete also holds for another custody of the directory.
    let other = FileCustody::open(&*dir, Isolation::User).unwrap();
    assert_eq!(
        other.sign(&handle, Algorithm::MlDsa65Ed25519, b"message", &mut random),
        Err(Error::Unknown)
    );
    assert_eq!(custody.delete(id), Err(Error::Unknown));
}

#[test]
fn enroll_refuses_an_existing_id_and_rotate_keeps_the_predecessor() {
    let dir = scratch("rotate");
    let custody = FileCustody::open(&*dir, Isolation::User).unwrap();
    let mut random = ChaCha20Rng::from_seed([2; 32]);
    let first_id = KeyId::random(&mut random);
    let first = custody
        .enroll(first_id, Algorithm::MlDsa65EcdsaP256, &mut random)
        .unwrap();
    assert_eq!(
        custody.enroll(first_id, Algorithm::MlDsa65EcdsaP256, &mut random),
        Err(Error::Exists)
    );

    let second = custody.rotate(&first, KeyId::random(&mut random), &mut random).unwrap();
    assert_eq!(second.algorithm(), Algorithm::MlDsa65EcdsaP256);
    for handle in [&first, &second] {
        let signature = custody
            .sign(handle, Algorithm::MlDsa65EcdsaP256, b"message", &mut random)
            .unwrap();
        assert!(verifies(handle, b"message", &signature));
    }
    custody.delete(first_id).unwrap();
    let signature = custody
        .sign(&second, Algorithm::MlDsa65EcdsaP256, b"message", &mut random)
        .unwrap();
    assert!(verifies(&second, b"message", &signature));
}

#[test]
fn a_request_for_process_isolation_refuses_before_storage_work() {
    let missing = std::env::temp_dir().join(format!("rsauthnz-custody-{}-missing", std::process::id()));
    assert_matches!(FileCustody::open(missing, Isolation::Process), Err(Error::Isolation));
}

#[test]
fn a_key_file_that_another_account_can_read_refuses() {
    let dir = scratch("permissions");
    let custody = FileCustody::open(&*dir, Isolation::User).unwrap();
    let mut random = ChaCha20Rng::from_seed([3; 32]);
    let mut readable = |grant: fn(&Path)| {
        let id = KeyId::random(&mut random);
        let handle = custody.enroll(id, Algorithm::MlDsa65Ed25519, &mut random).unwrap();
        grant(&key_file(&dir, id));
        custody.sign(&handle, Algorithm::MlDsa65Ed25519, b"message", &mut random)
    };
    #[cfg(unix)]
    assert_eq!(
        readable(|path| {
            use std::os::unix::fs::PermissionsExt;
            fs::set_permissions(path, fs::Permissions::from_mode(0o640)).unwrap();
        }),
        Err(Error::Permissions)
    );
    // A macOS ACL entry gives access that the mode bits do not show.
    #[cfg(target_os = "macos")]
    assert_eq!(
        readable(|path| {
            let mut chmod = std::process::Command::new("/bin/chmod");
            assert!(
                chmod
                    .arg("+a")
                    .arg("everyone allow read")
                    .arg(path)
                    .status()
                    .unwrap()
                    .success()
            );
        }),
        Err(Error::Permissions)
    );
    // An ACE that lets BUILTIN\Users read the file.
    #[cfg(windows)]
    assert_eq!(
        readable(|path| {
            let mut icacls = std::process::Command::new("icacls");
            assert!(
                icacls
                    .arg(path)
                    .args(["/grant", "*S-1-5-32-545:(R)"])
                    .status()
                    .unwrap()
                    .success()
            );
        }),
        Err(Error::Permissions)
    );
}

#[test]
fn a_key_file_with_another_key_or_a_request_for_another_algorithm_refuses() {
    let dir = scratch("mismatch");
    let custody = FileCustody::open(&*dir, Isolation::User).unwrap();
    let mut random = ChaCha20Rng::from_seed([4; 32]);
    let ids = [KeyId::random(&mut random), KeyId::random(&mut random)];
    let first = custody.enroll(ids[0], Algorithm::MlDsa65Ed25519, &mut random).unwrap();
    custody.enroll(ids[1], Algorithm::MlDsa65Ed25519, &mut random).unwrap();
    assert_eq!(
        custody.sign(&first, Algorithm::MlDsa65EcdsaP256, b"message", &mut random),
        Err(Error::Algorithm)
    );
    // The file of the second key replaces the file of the first key.
    fs::rename(key_file(&dir, ids[1]), key_file(&dir, ids[0])).unwrap();
    assert_eq!(
        custody.sign(&first, Algorithm::MlDsa65Ed25519, b"message", &mut random),
        Err(Error::Mismatch)
    );
}

#[test]
fn handles_reports_and_errors_show_no_key_bytes() {
    let dir = scratch("debug");
    let custody = FileCustody::open(&*dir, Isolation::User).unwrap();
    let mut random = ChaCha20Rng::from_seed([5; 32]);
    let id = KeyId::random(&mut random);
    let handle = custody.enroll(id, Algorithm::MlDsa65Ed25519, &mut random).unwrap();
    let key = MlDsa65Ed25519SecretKey::from_pkcs8_der(&fs::read(key_file(&dir, id)).unwrap()).unwrap();
    let errors = [
        custody.enroll(id, Algorithm::MlDsa65Ed25519, &mut random),
        custody
            .sign(&handle, Algorithm::MlDsa65EcdsaP256, b"message", &mut random)
            .map(|_| handle.clone()),
    ];
    let mut shown = format!("{handle:?} {custody:?} {:?}", custody.report());
    for error in errors {
        let error = error.unwrap_err();
        shown.push_str(&format!(" {error:?} {error}"));
    }
    // Each part of 16 bytes of the key, in the decimal form of `Debug` and in hexadecimal.
    for part in key.expose_secret().as_bytes().windows(16) {
        let decimal = part.iter().map(u8::to_string).collect::<Vec<_>>().join(", ");
        let hex: String = part.iter().map(|byte| format!("{byte:02x}")).collect();
        assert!(!shown.contains(&decimal) && !shown.contains(&hex), "{shown}");
    }
}

/// A link at the path of a key file refuses on each OS, and a FIFO refuses on Linux and macOS without blocking. On
/// Windows, the host makes the link only for an elevated administrator or in Developer Mode.
#[test]
fn a_key_file_that_is_a_link_or_a_fifo_refuses_at_once() {
    let dir = scratch("special");
    let custody = FileCustody::open(&*dir, Isolation::User).unwrap();
    let mut random = ChaCha20Rng::from_seed([5; 32]);
    let id = KeyId::random(&mut random);
    let handle = custody.enroll(id, Algorithm::MlDsa65Ed25519, &mut random).unwrap();
    custody
        .sign(&handle, Algorithm::MlDsa65Ed25519, b"message", &mut random)
        .unwrap();
    // A link to the key file of the user, with its mode and its key: the open follows no link.
    let (path, kept) = (key_file(&dir, id), dir.join("kept.key"));
    fs::rename(&path, &kept).unwrap();
    cfg_select! {
        unix => std::os::unix::fs::symlink(&kept, &path).unwrap(),
        windows => std::os::windows::fs::symlink_file(&kept, &path)
            .expect("the host makes a link: an elevated administrator, or Developer Mode"),
    }
    assert_eq!(
        custody.sign(&handle, Algorithm::MlDsa65Ed25519, b"message", &mut random),
        Err(Error::Permissions)
    );
    // A FIFO at the path refuses, and the open does not wait for a writer.
    #[cfg(unix)]
    {
        fs::remove_file(&path).unwrap();
        let mkfifo = std::process::Command::new("mkfifo").arg(&path).status().unwrap();
        assert!(mkfifo.success());
        let (sent, received) = std::sync::mpsc::channel();
        std::thread::spawn(move || {
            let signed = custody.sign(&handle, Algorithm::MlDsa65Ed25519, b"message", &mut random);
            sent.send(signed).unwrap_or_default();
        });
        assert_eq!(
            received.recv_timeout(core::time::Duration::from_secs(10)),
            Ok(Err(Error::Permissions)),
            "the open of a FIFO blocked, or it did not refuse"
        );
    }
}

/// A DACL with one entry that allows only the user, but not protected: a later change of a parent passes its entries
/// on to the key file.
#[cfg(windows)]
#[test]
fn a_key_file_whose_dacl_is_not_protected_refuses() {
    use std::process::Command;

    let dir = scratch("unprotected");
    let whoami = Command::new("whoami")
        .args(["/user", "/fo", "csv", "/nh"])
        .output()
        .unwrap();
    let user = String::from_utf8(whoami.stdout).unwrap();
    let sid = user.trim().rsplit(',').next().unwrap().trim_matches('"').to_owned();
    // The directory passes no entry on, so the key file keeps its one entry when it takes the entries of its parent.
    let grant = format!("*{sid}:(F)");
    let icacls = Command::new("icacls")
        .arg(&*dir)
        .args(["/inheritance:r", "/grant:r", &grant])
        .status()
        .unwrap();
    assert!(icacls.success());
    let custody = FileCustody::open(&*dir, Isolation::User).unwrap();
    let mut random = ChaCha20Rng::from_seed([6; 32]);
    let id = KeyId::random(&mut random);
    let handle = custody.enroll(id, Algorithm::MlDsa65Ed25519, &mut random).unwrap();
    custody
        .sign(&handle, Algorithm::MlDsa65Ed25519, b"message", &mut random)
        .unwrap();
    let icacls = Command::new("icacls")
        .arg(key_file(&dir, id))
        .arg("/inheritance:e")
        .status()
        .unwrap();
    assert!(icacls.success());
    assert_eq!(
        custody.sign(&handle, Algorithm::MlDsa65Ed25519, b"message", &mut random),
        Err(Error::Permissions)
    );
}
