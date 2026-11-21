//! The shared setup of the fuzz targets of rsauthnz: the trusted key of the seeds, the time of each check, and the
//! check that no signature work ran.

use core::time::Duration;

use rsauthnz::cose::{Key, PublicKey, TrustedKey};
use rsauthnz::crypto::Algorithm;
use rsauthnz::limits::{Limits, SignatureBudget};
use rsauthnz::time::{Reading, ReadingSource};

/// The Ed25519 public key of the secret key `[1; 32]`, which signed the credential and the JWT of `seeds/`.
pub const ISSUER: [u8; 32] = [
    0x8a, 0x88, 0xe3, 0xdd, 0x74, 0x09, 0xf1, 0x95, 0xfd, 0x52, 0xdb, 0x2d, 0x3c, 0xba, 0x5d, 0x72, 0xca, 0x67, 0x09,
    0xbf, 0x1d, 0x94, 0x12, 0x1b, 0xf3, 0x74, 0x88, 0x01, 0xb4, 0x0f, 0x6f, 0x5c,
];

/// The trusted key [`ISSUER`].
#[must_use]
pub fn issuer() -> TrustedKey {
    let key = Key {
        kid: None,
        alg: None,
        public: PublicKey::Ed25519(&ISSUER),
    };
    TrustedKey::new(Algorithm::Ed25519, &key).expect("an Ed25519 key")
}

/// A reading within the validity of the seeds: 100 seconds after their issue, with a bound of one second.
#[must_use]
pub fn now() -> Reading {
    Reading::new(
        Duration::from_secs(1_800_000_100),
        Some(Duration::from_secs(1)),
        ReadingSource::Caller,
    )
}

/// Whether `budget` still has each signature check of `limits`: no signature work ran.
#[must_use]
pub fn untouched(budget: &SignatureBudget, limits: &Limits) -> bool {
    budget.remaining() == limits.signature_checks
}
