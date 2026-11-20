//! The contract of the Keychain custody: after its handles drop, the process holds no copy of the key outside the
//! keychain.
//!
//! The test copies each region of this process that the process can write, through the OS, and it looks for each part
//! of the key in it. It holds the parts only masked, so the scan does not find its own copy. Threads of their own derive
//! the key and do the custody work, so the scan sees no stack frame of that work.
#![cfg(all(feature = "native-custody", target_os = "macos"))]

use core::hint::black_box;
use core::mem::DropGuard;
use std::thread;

use rsauthnz::crypto::Algorithm;
use rsauthnz::custody::{Custody, Isolation, KeyId, KeychainCustody};
use rscrypto::ChaCha20Rng;
use rscrypto::auth::MlDsa65Ed25519;

/// The bytes of a part of the key: the scan reads each word of 8 bytes at an address that is a multiple of 8. Each copy
/// of 16 or more bytes of the key holds such a word.
const PART: usize = 8;
/// The mask of each part that the test holds. No byte of the mask is zero, so no masked part equals its part.
const MASK: u64 = u64::from_ne_bytes([0xa5; PART]);
/// The seed of the generator of the custody, and of its twin in the test.
const SEED: [u8; 32] = [8; 32];
/// The IDs of the key and of its successor.
const IDS: [KeyId; 2] = [KeyId::from_bytes([1; 16]), KeyId::from_bytes([2; 16])];
/// The most bytes that one copy through the OS reads: a multiple of `PART`.
const CHUNK: usize = 1 << 16;

#[test]
fn keychain_custody_leaves_no_key_bytes_in_the_process() {
    // A twin generator draws what enroll draws. Thus the test knows the key, and it reads no custody memory.
    let (needle, public) = thread::spawn(|| {
        let mut twin = ChaCha20Rng::from_seed(SEED);
        let (public, key) = MlDsa65Ed25519::generate_keypair(|out| {
            twin.fill_bytes(out);
            Ok(())
        })
        .unwrap();
        // The raw key: the ML-DSA-65 seed, then the Ed25519 key.
        (
            Needle::new(key.expose_secret().as_bytes()),
            Vec::from(public.to_bytes()),
        )
    })
    .join()
    .unwrap();
    let mut chunk = vec![0; CHUNK];
    assert_eq!(scan(&needle, &mut chunk), [], "the derivation of the key left a copy");

    let service = format!("rsauthnz-test-{}-keychain-cache", std::process::id());
    let enrolled = thread::spawn(move || {
        let custody = KeychainCustody::open(service, Isolation::User).unwrap();
        // The guard deletes each key if a step fails, so the test leaves no item in the keychain.
        let custody = DropGuard::new(custody, |custody| {
            for id in IDS {
                custody.delete(id).unwrap_or_default();
            }
        });
        let mut random = ChaCha20Rng::from_seed(SEED);
        let handle = custody.enroll(IDS[0], Algorithm::MlDsa65Ed25519, &mut random).unwrap();
        custody
            .sign(&handle, Algorithm::MlDsa65Ed25519, b"message", &mut random)
            .unwrap();
        custody.rotate(&handle, IDS[1], &mut random).unwrap();
        for id in IDS {
            custody.delete(id).unwrap();
        }
        handle.public_key()
    })
    .join()
    .unwrap();
    assert_eq!(enrolled, public, "enroll made the key of the twin");
    assert_eq!(scan(&needle, &mut chunk), [], "the custody left a copy of the key");

    // The positive control: a planted copy of one part of the key.
    let plant = black_box(Box::new((needle.parts[0] ^ MASK).to_ne_bytes()));
    assert_ne!(scan(&needle, &mut chunk), [], "the scan missed the planted copy");
    drop(plant);
}

/// The parts of a key, masked: each window of `PART` bytes of the key.
struct Needle {
    /// The masked parts, in order.
    parts: Vec<u64>,
    /// Whether a masked part has the first two bytes of the index: a filter that makes most words cost one test.
    filter: Vec<bool>,
}

impl Needle {
    fn new(key: &[u8]) -> Self {
        let mut parts: Vec<u64> = key
            .array_windows::<PART>()
            .map(|part| u64::from_ne_bytes(*part) ^ MASK)
            .collect();
        parts.sort_unstable();
        let mut filter = vec![false; 1 << 16];
        for &part in &parts {
            filter[head(part)] = true;
        }
        Self { parts, filter }
    }

    /// Whether `word` is a part of the key.
    fn holds(&self, word: [u8; PART]) -> bool {
        let masked = u64::from_ne_bytes(word) ^ MASK;
        self.filter[head(masked)] && self.parts.binary_search(&masked).is_ok()
    }
}

/// The index of the filter for the masked part `masked`: its first two bytes.
fn head(masked: u64) -> usize {
    let [first, second, ..] = masked.to_ne_bytes();
    usize::from(u16::from_ne_bytes([first, second]))
}

/// The regions of this process that hold a part of the key: their addresses, sizes, and tags. `chunk` receives each
/// copy through the OS.
fn scan(needle: &Needle, chunk: &mut [u8]) -> Vec<(u64, u64, u32)> {
    let mut found = Vec::new();
    os::regions(|address, size, tag| {
        let mut at = 0;
        while at < size {
            let len = (size - at).min(chunk.len() as u64);
            let copy = &mut chunk[..usize::try_from(len).unwrap()];
            assert!(
                os::copy(address + at, copy),
                "the OS cannot copy the region at {address:#x}"
            );
            if copy.as_chunks::<PART>().0.iter().any(|word| needle.holds(*word)) {
                found.push((address, size, tag));
                return;
            }
            at += len;
        }
    });
    found
}

/// The regions and the copy of memory of this task, through Mach.
mod os {
    /// `VM_PROT_READ | VM_PROT_WRITE`.
    const READ_WRITE: u32 = 3;
    /// The words of a `vm_region_submap_info_64`: `VM_REGION_SUBMAP_INFO_V3_COUNT_64`.
    const INFO_WORDS: u32 = 21;
    /// The word of each field of a `vm_region_submap_info_64` that the walk reads. The structure has a packing of 4.
    const PROTECTION: usize = 0;
    const USER_TAG: usize = 5;
    const PAGES_RESIDENT: usize = 6;
    const PAGES_SWAPPED_OUT: usize = 8;
    const IS_SUBMAP: usize = 12;

    #[expect(unsafe_code, reason = "the system ABI of the Mach memory calls")]
    unsafe extern "C" {
        safe static mach_task_self_: u32;
        fn mach_vm_region_recurse(
            task: u32,
            address: *mut u64,
            size: *mut u64,
            depth: *mut u32,
            info: *mut u32,
            count: *mut u32,
        ) -> i32;
        fn mach_vm_read_overwrite(task: u32, address: u64, size: u64, data: u64, copied: *mut u64) -> i32;
    }

    /// Calls `scan` with the address, the size, and the tag of each region that this process can read and write and
    /// that holds a page. The walk enters each submap, such as the shared region of the system libraries.
    #[expect(
        unsafe_code,
        reason = "mach_vm_region_recurse writes the information of a region into `info`"
    )]
    pub(crate) fn regions(mut scan: impl FnMut(u64, u64, u32)) {
        let mut address = 0;
        let mut depth = 0;
        loop {
            let mut size = 0;
            let mut info = [0; INFO_WORDS as usize];
            let mut count = INFO_WORDS;
            // SAFETY: `info` has room for `count` words, and each other argument is a valid place for its result.
            let status = unsafe {
                mach_vm_region_recurse(
                    mach_task_self_,
                    &raw mut address,
                    &raw mut size,
                    &raw mut depth,
                    info.as_mut_ptr(),
                    &raw mut count,
                )
            };
            if status != 0 {
                return;
            }
            if info[IS_SUBMAP] != 0 {
                depth += 1;
                continue;
            }
            if info[PROTECTION] & READ_WRITE == READ_WRITE && info[PAGES_RESIDENT] | info[PAGES_SWAPPED_OUT] != 0 {
                scan(address, size, info[USER_TAG]);
            }
            let Some(next) = address.checked_add(size) else { return };
            address = next;
        }
    }

    /// Copies the bytes at `address` into `out`, or gives false if the OS cannot read them.
    #[expect(unsafe_code, reason = "mach_vm_read_overwrite copies memory of this task into `out`")]
    pub(crate) fn copy(address: u64, out: &mut [u8]) -> bool {
        let mut copied = 0;
        // SAFETY: the kernel reads memory of this task, and it writes at most `out.len()` bytes into `out`.
        let status = unsafe {
            mach_vm_read_overwrite(
                mach_task_self_,
                address,
                out.len() as u64,
                out.as_mut_ptr().addr() as u64,
                &raw mut copied,
            )
        };
        status == 0 && copied == out.len() as u64
    }
}
