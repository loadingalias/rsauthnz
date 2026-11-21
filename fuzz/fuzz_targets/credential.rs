//! Credentials: `credential::Profile::verify` of an untrusted artifact, with the default limits. An artifact over
//! `MAX_BYTES`, or one that does not decode, refuses with no signature work.
#![no_main]

use libfuzzer_sys::fuzz_target;
use rsauthnz::cose;
use rsauthnz::credential::{self, Error, MAX_BYTES};
use rsauthnz::id::Id;
use rsauthnz::limits::{Limits, SignatureBudget};
use rsauthnz_fuzz::{issuer, now, untouched};

fuzz_target!(|input: &[u8]| {
    let limits = Limits::default();
    let profile = credential::Profile::new(
        issuer(),
        Id::new("acme", "auth").expect("an identifier"),
        Id::new("acme", "app").expect("an identifier"),
        Id::new("acme", "deploy").expect("an identifier"),
        limits,
    )
    .expect("a profile");
    let mut budget = SignatureBudget::new(&limits);
    let checked = profile.verify(input, now(), &mut budget);
    if input.len() > MAX_BYTES {
        assert!(
            matches!(checked, Err(Error::Size)),
            "an artifact over the bound passed its check"
        );
    }
    if matches!(
        checked,
        Err(Error::Size | Error::Cose(cose::Error::Cbor(_) | cose::Error::Malformed | cose::Error::Limit(_)))
    ) {
        assert!(untouched(&budget, &limits), "a refused decode did signature work");
    }
});
