//! The storage conformance of rsauthnz: the conformance [`suite`] of the storage contract ([`rsauthnz::store`]), and the
//! [`memory`] binding, which is the reference of the contract for tests and examples. The [`guide`] takes a backend
//! author from the primitives to a binding that passes the suite. This crate is in development, and its API can change
//! in each release.

pub mod memory;
pub mod suite;

// The guide is in the package, so that `cargo package` builds it. Rustdoc checks each link of it to a public item,
// and the doctests compile its examples.
#[doc = include_str!("guide.md")]
pub mod guide {}
