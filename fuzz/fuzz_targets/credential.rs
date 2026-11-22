//! Credentials: `credential::Profile::verify` of an untrusted artifact, with the limits that the input draws
//! (`rsauthnz_fuzz::drawn`). An artifact over `MAX_BYTES` or over the byte bound, or one that does not decode, refuses
//! with no signature work.
#![no_main]

use libfuzzer_sys::fuzz_target;
use rsauthnz::cose;
use rsauthnz::credential::{self, Error, MAX_BYTES};
use rsauthnz::id::Id;
use rsauthnz::limits::SignatureBudget;
use rsauthnz_fuzz::{drawn, issuer, now, untouched};

fuzz_target!(|data: &[u8]| {
    let Some((input, limits)) = drawn(data) else {
        return;
    };
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
    let refused = matches!(
        checked,
        Err(Error::Size | Error::Cose(cose::Error::Cbor(_) | cose::Error::Malformed | cose::Error::Limit(_)))
    );
    if input.len() > limits.bytes {
        assert!(refused, "an artifact over the byte bound passed its decode");
    }
    if refused {
        assert!(untouched(&budget, &limits), "a refused decode did signature work");
    }
});
