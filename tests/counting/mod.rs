//! The counting allocator of the allocation tests. Each test binary that includes this module counts the
//! allocations of each thread. A binary has one global allocator, so each binary that counts includes this module,
//! and no other.

use core::alloc::{GlobalAlloc, Layout};
use core::cell::Cell;
use std::alloc::System;

thread_local! {
    /// The allocations of this thread. Each test runs on its own thread, so a test counts only its own allocations.
    static ALLOCATIONS: Cell<usize> = const { Cell::new(0) };
}

/// Counts each allocation of the thread, then gives it to the system allocator.
struct Counting;

#[expect(
    unsafe_code,
    reason = "a global allocator implements an unsafe trait; each method forwards to `System` unchanged"
)]
// SAFETY: each method gives its arguments, and the contract of its caller, to `System` with no change.
unsafe impl GlobalAlloc for Counting {
    unsafe fn alloc(&self, layout: Layout) -> *mut u8 {
        ALLOCATIONS.set(ALLOCATIONS.get() + 1);
        // SAFETY: the caller keeps the contract of `GlobalAlloc::alloc`, which is also the contract of `System`.
        unsafe { System.alloc(layout) }
    }

    unsafe fn dealloc(&self, ptr: *mut u8, layout: Layout) {
        // SAFETY: `ptr` came from `System.alloc` with `layout`, through `Counting::alloc`.
        unsafe { System.dealloc(ptr, layout) }
    }
}

#[global_allocator]
static ALLOCATOR: Counting = Counting;

/// Runs `work`, and gives its result and the number of allocations that it made on this thread.
///
/// First, it counts one known allocation. Thus a count of zero cannot come from a counter that does not count.
pub(crate) fn allocations<T>(work: impl FnOnce() -> T) -> (T, usize) {
    let control = ALLOCATIONS.get();
    drop(core::hint::black_box(Vec::<u8>::with_capacity(1)));
    assert!(ALLOCATIONS.get() > control, "the counter counted no allocation");
    let before = ALLOCATIONS.get();
    let result = work();
    (result, ALLOCATIONS.get() - before)
}
