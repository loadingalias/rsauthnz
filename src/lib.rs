//! Authentication and authorization. This crate is in development, and its API can change in each release.

extern crate alloc;

pub mod account;
pub mod agent;
pub mod authz;
pub mod cbor;
pub mod cli;
pub mod cose;
pub mod credential;
pub mod crypto;
pub mod custody;
pub mod evidence;
pub mod grant;
pub mod id;
pub mod jose;
pub mod limits;
pub mod local;
pub mod oidc;
pub mod passkey;
pub mod recovery;
pub mod session;
pub mod store;
pub mod transition;
pub mod trust;
pub mod workload;
pub mod x509;

/// Physical time: the reading of the family's shared types, which evidence times, expiry, and
/// retention use. A reading has an estimate, an uncertainty bound or "unknown", and its source.
pub mod time {
    pub use rstypes::time::{Reading, ReadingSource, TimeError};
}
