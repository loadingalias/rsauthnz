//! The contracts of the Keychain custody: sign, rotate, and delete through the login keychain, the absence of a deleted
//! key from the vault, the match of an item, and the isolation.
//!
//! Each test has a service of its own, and it deletes each of its keys at its end, so a test leaves no item in the
//! keychain.

use alloc::format;
use core::assert_matches;
use std::process::Command;

use rscrypto::ChaCha20Rng;

use super::KeychainCustody;
use crate::crypto::Algorithm;
use crate::custody::{Custody, Error, Handle, Isolation, KeyId};
use crate::limits::{Limits, SignatureBudget};

/// A custody with the service of one test, and the IDs of its keys. It deletes each key that remains when it drops.
struct Scratch<const N: usize> {
    custody: KeychainCustody,
    ids: [KeyId; N],
}

impl<const N: usize> Scratch<N> {
    /// The custody of the test `name`, and `N` key IDs from `random`.
    fn new(name: &str, random: &mut ChaCha20Rng) -> Self {
        let service = format!("rsauthnz-test-{}-{name}", std::process::id());
        Self {
            custody: KeychainCustody::open(service, Isolation::User).unwrap(),
            ids: core::array::from_fn(|_| KeyId::random(random)),
        }
    }
}

impl<const N: usize> Drop for Scratch<N> {
    fn drop(&mut self) {
        for id in self.ids {
            self.custody.delete(id).unwrap_or_default();
        }
    }
}

/// Whether the login keychain has the item of `id`, as the `security` tool of macOS reads it. The tool reads only the
/// attributes of the item, so it shows no dialog.
fn in_vault(custody: &KeychainCustody, id: KeyId) -> bool {
    let account = format!("{id}");
    let found = Command::new("/usr/bin/security")
        .args(["find-generic-password", "-s", &custody.service, "-a", &account])
        .output()
        .unwrap();
    // The tool exits with 44 if the item does not exist.
    assert_matches!(found.status.code(), Some(0 | 44));
    found.status.success()
}

/// Whether `signature` is a signature of `message` by the key of `handle`.
fn verifies(handle: &Handle, message: &[u8], signature: &[u8]) -> bool {
    handle.verify(message, signature, &mut SignatureBudget::new(&Limits::default())) == Ok(true)
}

#[test]
fn sign_rotate_and_delete_work_through_the_keychain() {
    let mut random = ChaCha20Rng::from_seed([1; 32]);
    let scratch = Scratch::<2>::new("lifecycle", &mut random);
    let (custody, [first_id, second_id]) = (&scratch.custody, scratch.ids);
    let first = custody
        .enroll(first_id, Algorithm::MlDsa65Ed25519, &mut random)
        .unwrap();
    assert!(in_vault(custody, first_id));
    assert_eq!(
        custody.enroll(first_id, Algorithm::MlDsa65Ed25519, &mut random),
        Err(Error::Exists)
    );
    // The application stores the parts of a handle, and it makes the handle again after a restart.
    let stored = Handle::new(first_id, first.algorithm(), &first.public_key()).unwrap();
    let second = custody.rotate(&stored, second_id, &mut random).unwrap();
    assert_eq!(second.algorithm(), Algorithm::MlDsa65Ed25519);
    for handle in [&stored, &second] {
        let signature = custody
            .sign(handle, Algorithm::MlDsa65Ed25519, b"message", &mut random)
            .unwrap();
        assert!(verifies(handle, b"message", &signature));
    }

    custody.delete(first_id).unwrap();
    assert!(!in_vault(custody, first_id));
    assert_eq!(
        custody.sign(&stored, Algorithm::MlDsa65Ed25519, b"message", &mut random),
        Err(Error::Unknown)
    );
    assert_eq!(custody.delete(first_id), Err(Error::Unknown));
    // The successor stays until its own delete.
    let signature = custody
        .sign(&second, Algorithm::MlDsa65Ed25519, b"message", &mut random)
        .unwrap();
    assert!(verifies(&second, b"message", &signature));
}

#[test]
fn a_keychain_item_that_does_not_match_the_handle_refuses() {
    let mut random = ChaCha20Rng::from_seed([2; 32]);
    let scratch = Scratch::<2>::new("mismatch", &mut random);
    let (custody, ids) = (&scratch.custody, scratch.ids);
    let first = custody
        .enroll(ids[0], Algorithm::MlDsa65EcdsaP256, &mut random)
        .unwrap();
    let second = custody
        .enroll(ids[1], Algorithm::MlDsa65EcdsaP256, &mut random)
        .unwrap();
    assert_eq!(
        custody.sign(&first, Algorithm::MlDsa65Ed25519, b"message", &mut random),
        Err(Error::Algorithm)
    );
    // A stored handle with the ID of the first key and the public key of the second.
    let crossed = Handle::new(ids[0], Algorithm::MlDsa65EcdsaP256, &second.public_key()).unwrap();
    assert_eq!(
        custody.sign(&crossed, Algorithm::MlDsa65EcdsaP256, b"message", &mut random),
        Err(Error::Mismatch)
    );
}

#[test]
fn a_request_for_process_isolation_refuses_the_keychain_custody() {
    assert_matches!(
        KeychainCustody::open("rsauthnz-test-isolation", Isolation::Process),
        Err(Error::Isolation)
    );
}
