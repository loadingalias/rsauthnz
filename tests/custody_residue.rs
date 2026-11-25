//! The contract of zeroization: the software custody frees no heap block that holds key bytes, and a bootstrap value of
//! a local authority leaves no heap block that holds its secret.
//!
//! This test binary has its own global allocator. While a thread arms it, the allocator copies each block that the
//! thread frees through the OS, before it releases the block, and it counts each block that holds a part of the key.
//! Then it clears the block. The system allocator can give a freed block to a later allocation with its bytes, as
//! glibc does. Thus the count of a later free never holds the bytes of an earlier one. The OS copy reads the bytes as the hardware holds them, so no Rust load reads memory that is not initialized,
//! such as the padding of a structure.
#![cfg(all(feature = "native-custody", any(target_os = "linux", target_os = "macos", windows)))]

use core::alloc::{GlobalAlloc, Layout};
use core::cell::Cell;
use core::hint::black_box;
use std::alloc::System;
use std::sync::OnceLock;

use rsauthnz::crypto::Algorithm;
use rsauthnz::custody::{Custody, FileCustody, Isolation, KeyId};
use rscrypto::ChaCha20Rng;
use rscrypto::auth::{MlDsa65Ed25519, SlhDsaSha2_128s};

/// The bytes of a part of the secret that the scan looks for.
const PART: usize = 16;
/// The most bytes that one copy through the OS reads.
const CHUNK: usize = 4096;

/// The secret that the scan looks for: the raw key (the ML-DSA-65 seed, then the Ed25519 key), or the secret of a
/// bootstrap value and its text.
static KEY: OnceLock<Vec<u8>> = OnceLock::new();

thread_local! {
    static ARMED: Cell<bool> = const { Cell::new(false) };
    static FOUND: Cell<usize> = const { Cell::new(0) };
    static FAILED: Cell<usize> = const { Cell::new(0) };
}

/// The allocator of the test binary: the system allocator, with a scan of each block that an armed thread frees.
struct Scan;

#[global_allocator]
static ALLOCATOR: Scan = Scan;

#[expect(
    unsafe_code,
    reason = "a global allocator that scans and clears each freed block before the system frees it"
)]
// SAFETY: each call goes to `System` with the same arguments. `dealloc` reads the block through the OS and clears it
// before it releases it, and the scan allocates nothing.
unsafe impl GlobalAlloc for Scan {
    unsafe fn alloc(&self, layout: Layout) -> *mut u8 {
        // SAFETY: the caller keeps the contract of `GlobalAlloc::alloc`.
        unsafe { System.alloc(layout) }
    }

    unsafe fn dealloc(&self, block: *mut u8, layout: Layout) {
        if ARMED.get() {
            ARMED.set(false);
            scan(block.addr(), layout.size());
            for at in 0..layout.size() {
                // SAFETY: the block has `layout.size()` bytes, and the caller does not use it after this call. The
                // write is volatile, so the compiler keeps it before the free.
                unsafe { block.add(at).write_volatile(0) };
            }
            ARMED.set(true);
        }
        // SAFETY: the caller keeps the contract of `GlobalAlloc::dealloc`.
        unsafe { System.dealloc(block, layout) }
    }
}

/// Counts the block of `size` bytes at `address` in `FOUND` if it holds a part of the key, and in `FAILED` if the OS
/// cannot copy it.
fn scan(address: usize, size: usize) {
    let Some(key) = KEY.get() else { return };
    let mut chunk = [0; CHUNK];
    let mut at = 0;
    while at < size {
        let len = (size - at).min(CHUNK);
        if !os::copy(address + at, &mut chunk[..len]) {
            FAILED.set(FAILED.get() + 1);
            return;
        }
        if chunk[..len]
            .windows(PART)
            .any(|bytes| key.windows(PART).any(|part| part == bytes))
        {
            FOUND.set(FOUND.get() + 1);
            return;
        }
        if at + len == size {
            return;
        }
        // The chunks overlap, so the scan also finds a part that crosses the end of a chunk.
        at += len - (PART - 1);
    }
}

/// The blocks that hold a part of the key, of those that this thread frees in `work`.
fn freed_with_key(work: impl FnOnce()) -> usize {
    FOUND.set(0);
    ARMED.set(true);
    work();
    ARMED.set(false);
    assert_eq!(FAILED.get(), 0, "the OS cannot copy a freed block");
    FOUND.get()
}

#[test]
fn custody_frees_no_heap_block_that_holds_key_bytes() {
    os::open();
    let dir = std::env::temp_dir().join(format!("rsauthnz-custody-residue-{}", std::process::id()));
    std::fs::create_dir(&dir).unwrap();
    let custody = FileCustody::open(&dir, Isolation::User).unwrap();
    let seed = [6; 32];
    let mut random = ChaCha20Rng::from_seed(seed);
    let id = KeyId::random(&mut random);
    // A twin generator draws what enroll draws. Thus the test knows the key, and it reads no custody memory.
    let mut twin = ChaCha20Rng::from_seed(seed);
    assert_eq!(KeyId::random(&mut twin), id);
    let (public, key) = MlDsa65Ed25519::generate_keypair(|out| {
        twin.fill_bytes(out);
        Ok(())
    })
    .unwrap();
    KEY.set(key.expose_secret().as_bytes().to_vec()).unwrap();
    drop(key);

    // The positive control: a copy of the key in a `Vec` that drops with no zeroization.
    assert_eq!(freed_with_key(|| drop(black_box(KEY.get().unwrap().to_vec()))), 1);

    let found = freed_with_key(|| {
        let handle = custody.enroll(id, Algorithm::MlDsa65Ed25519, &mut random).unwrap();
        assert_eq!(
            handle.public_key(),
            public.to_bytes(),
            "enroll made the key of the twin"
        );
        custody
            .sign(&handle, Algorithm::MlDsa65Ed25519, b"message", &mut random)
            .unwrap();
        custody
            .rotate(&handle, KeyId::random(&mut random), &mut random)
            .unwrap();
        custody.delete(id).unwrap();
    });
    std::fs::remove_dir_all(&dir).unwrap();
    assert_eq!(found, 0);
}

#[test]
fn custody_frees_no_heap_block_that_holds_root_key_bytes() {
    os::open();
    let dir = std::env::temp_dir().join(format!("rsauthnz-custody-root-residue-{}", std::process::id()));
    std::fs::create_dir(&dir).unwrap();
    let custody = FileCustody::open(&dir, Isolation::User).unwrap();
    let seed = [7; 32];
    let mut random = ChaCha20Rng::from_seed(seed);
    let id = KeyId::random(&mut random);
    let mut twin = ChaCha20Rng::from_seed(seed);
    assert_eq!(KeyId::random(&mut twin), id);
    let (public, key) = SlhDsaSha2_128s::generate_keypair(|out| {
        twin.fill_bytes(out);
        Ok(())
    })
    .unwrap();
    // The needle is SK.seed || SK.prf: the handle holds the public half of the key.
    KEY.set(key.expose_secret().as_bytes()[..32].to_vec()).unwrap();
    drop(key);

    // The positive control: a copy of the key in a `Vec` that drops with no zeroization.
    assert_eq!(freed_with_key(|| drop(black_box(KEY.get().unwrap().to_vec()))), 1);

    let found = freed_with_key(|| {
        let handle = custody.enroll(id, Algorithm::SlhDsaSha2_128s, &mut random).unwrap();
        assert_eq!(
            handle.public_key(),
            public.as_bytes(),
            "enroll made the key of the twin"
        );
        custody
            .sign(&handle, Algorithm::SlhDsaSha2_128s, b"issuer key", &mut random)
            .unwrap();
        custody
            .rotate(&handle, KeyId::random(&mut random), &mut random)
            .unwrap();
        custody.delete(id).unwrap();
    });
    std::fs::remove_dir_all(&dir).unwrap();
    assert_eq!(found, 0);
}

/// The copy of memory of this process through the OS.
#[cfg(target_os = "linux")]
mod os {
    use std::fs::File;
    use std::os::unix::fs::FileExt;
    use std::sync::OnceLock;

    static MEMORY: OnceLock<File> = OnceLock::new();

    /// Opens the memory of the process before a scan, because a scan allocates nothing.
    pub(crate) fn open() {
        MEMORY.get_or_init(|| File::open("/proc/self/mem").unwrap());
    }

    /// Copies the bytes at `address` into `out`, or gives false if the OS cannot read them.
    pub(crate) fn copy(address: usize, out: &mut [u8]) -> bool {
        MEMORY
            .get()
            .is_some_and(|memory| memory.read_exact_at(out, address as u64).is_ok())
    }
}

/// The copy of memory of this process through the OS.
#[cfg(target_os = "macos")]
mod os {
    /// The task port needs no setup.
    pub(crate) const fn open() {}

    /// Copies the bytes at `address` into `out`, or gives false if the OS cannot read them.
    #[expect(unsafe_code, reason = "mach_vm_read_overwrite copies memory of this task into `out`")]
    pub(crate) fn copy(address: usize, out: &mut [u8]) -> bool {
        unsafe extern "C" {
            static mach_task_self_: u32;
            fn mach_vm_read_overwrite(task: u32, address: u64, size: u64, data: u64, copied: *mut u64) -> i32;
        }
        let mut copied = 0;
        // SAFETY: the kernel reads memory of this task, and it writes at most `out.len()` bytes into `out`.
        let status = unsafe {
            mach_vm_read_overwrite(
                mach_task_self_,
                address as u64,
                out.len() as u64,
                out.as_mut_ptr().addr() as u64,
                &raw mut copied,
            )
        };
        status == 0 && copied == out.len() as u64
    }
}

/// The copy of memory of this process through the OS.
#[cfg(windows)]
mod os {
    use core::ffi::c_void;

    /// The process handle needs no setup.
    pub(crate) const fn open() {}

    /// Copies the bytes at `address` into `out`, or gives false if the OS cannot read them.
    #[expect(unsafe_code, reason = "ReadProcessMemory copies memory of this process into `out`")]
    pub(crate) fn copy(address: usize, out: &mut [u8]) -> bool {
        #[link(name = "kernel32", kind = "raw-dylib")]
        unsafe extern "system" {
            fn GetCurrentProcess() -> *mut c_void;
            fn ReadProcessMemory(
                process: *mut c_void,
                base: *const c_void,
                buffer: *mut c_void,
                size: usize,
                copied: *mut usize,
            ) -> i32;
        }
        let mut copied = 0;
        // SAFETY: the pseudo-handle of this process needs no close. The kernel reads memory of this process, and it
        // writes at most `out.len()` bytes into `out`.
        let done = unsafe {
            ReadProcessMemory(
                GetCurrentProcess(),
                core::ptr::without_provenance(address),
                out.as_mut_ptr().cast(),
                out.len(),
                &raw mut copied,
            )
        };
        done != 0 && copied == out.len()
    }
}

#[test]
fn a_bootstrap_value_leaves_no_secret_in_freed_memory() {
    use core::pin::pin;
    use core::task::{Context, Poll, Waker};
    use core::time::Duration;

    use rsauthnz::credential::Serial;
    use rsauthnz::custody::Handle;
    use rsauthnz::id::Id;
    use rsauthnz::limits::Limits;
    use rsauthnz::local::{Authority, Bootstrap, HostGrant};
    use rsauthnz::store::driver::{Answer, Driver, Plan};
    use rsauthnz::store::{self, Kind, Store};
    use rsauthnz::time::{Reading, ReadingSource};
    use rsauthnz::transition::{OperationId, Outcome, Proposal};
    use rsauthnz_conformance::memory::{Memory, Schedule};
    use rsauthnz_conformance::suite::execute;

    fn ready<T>(future: impl Future<Output = T>) -> T {
        let Poll::Ready(output) = pin!(future).poll(&mut Context::from_waker(Waker::noop())) else {
            panic!("the memory binding does no I/O");
        };
        output
    }
    fn settle(memory: &mut Memory, driver: &mut Driver) {
        while let Some(effect) = driver.effect() {
            let output = ready(execute(memory, effect));
            driver.give(output).unwrap();
        }
    }
    fn commit(memory: &mut Memory, driver: &mut Driver, (proposal, plan): (Proposal, Plan)) -> Outcome {
        let ticket = driver.submit(proposal, plan).unwrap();
        settle(memory, driver);
        let Some(Answer::Outcome(outcome)) = driver.take(ticket) else {
            panic!("the commit gave no outcome");
        };
        outcome
    }

    os::open();
    let seed = [8; 32];
    // A twin generator draws what the issue draws first: the secret of the value. Thus the test knows the secret and
    // its text, and it reads no memory of the authority.
    let mut twin = ChaCha20Rng::from_seed(seed);
    let mut secret = [0; 32];
    twin.fill_bytes(&mut secret);
    let hex: String = secret.iter().map(|byte| format!("{byte:02x}")).collect();
    KEY.set([secret.as_slice(), hex.as_bytes()].concat()).unwrap();
    // The positive control: a copy of the text in a `Vec` that drops with no zeroization.
    assert_eq!(freed_with_key(|| drop(black_box(hex.clone().into_bytes()))), 1);

    let now = Reading::new(
        Duration::from_secs(1_800_000_000),
        Some(Duration::from_secs(1)),
        ReadingSource::Caller,
    );
    let (issuer, _) = MlDsa65Ed25519::generate_keypair(|out| {
        let _: () = out.fill(1);
        Ok(())
    })
    .unwrap();
    let (holder, _) = MlDsa65Ed25519::generate_keypair(|out| {
        let _: () = out.fill(2);
        Ok(())
    })
    .unwrap();
    let issuer = Handle::new(
        KeyId::from_bytes([3; 16]),
        Algorithm::MlDsa65Ed25519,
        &issuer.to_bytes(),
    )
    .unwrap();
    let mut memory = Memory::new(Schedule::None);
    let mut driver = Driver::new(store::Profile::new(memory.declaration()).unwrap(), Limits::default()).unwrap();
    driver.start(now);
    settle(&mut memory, &mut driver);
    let grant = HostGrant {
        owner: Id::new("acme", "owner").unwrap(),
        origin: Id::new("acme", "build-app").unwrap(),
    };
    let authority = ready(Authority::open(
        &mut memory,
        &grant,
        Id::new("acme", "auth").unwrap(),
        issuer,
        Limits::default(),
    ))
    .unwrap();
    let (alice, operation) = (Id::new("acme", "alice").unwrap(), OperationId::new(b"issue-1").unwrap());
    let mut random = ChaCha20Rng::from_seed(seed);

    // The issue, the delivery of the value through the receipt, and the bootstrap of the client.
    let found = freed_with_key(|| {
        let issue = ready(authority.issue(&mut memory, &grant, alice, now, &mut random, operation)).unwrap();
        let Outcome::Accepted(receipt) = commit(&mut memory, &mut driver, issue) else {
            panic!("the issue did not commit");
        };
        let value = Bootstrap::parse(core::str::from_utf8(receipt.artifact().unwrap()).unwrap()).unwrap();
        drop(receipt);
        let serial = Serial(driver.allocate(Kind::Credential).unwrap());
        let pending = ready(authority.bootstrap(&mut memory, &value, &holder.to_bytes(), serial, now)).unwrap();
        drop((pending, value));
    });
    assert_eq!(found, 0);
}
