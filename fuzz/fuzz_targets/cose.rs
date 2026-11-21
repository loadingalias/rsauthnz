//! COSE and CWT: `cose::Key::decode`, `cose::Sign1::decode` and its signature check, and the CWT check of
//! `cose::Profile::verify`, with the default limits. A decode that refuses does no signature work.
#![no_main]

use libfuzzer_sys::fuzz_target;
use rsauthnz::cose::{self, Error};
use rsauthnz::id::{Audience, Authority, Id};
use rsauthnz::limits::{Limits, SignatureBudget};
use rsauthnz_fuzz::{issuer, now, untouched};

fuzz_target!(|input: &[u8]| {
    let limits = Limits::default();
    let _ = cose::Key::decode(input, limits);
    if let Ok(sign1) = cose::Sign1::decode(input, limits) {
        let mut budget = SignatureBudget::new(&limits);
        let checked = sign1.verify(&issuer(), &mut budget);
        assert!(untouched(&budget, &limits) || matches!(checked, Ok(_) | Err(Error::Signature)));
    }
    let profile = cose::Profile {
        key: issuer(),
        issuer: Id::<Authority>::new("acme", "auth").expect("an identifier").to_string(),
        audience: Id::<Audience>::new("acme", "app").expect("an identifier").to_string(),
        purpose: Id::new("acme", "deploy").expect("an identifier"),
        limits,
    };
    let mut budget = SignatureBudget::new(&limits);
    let checked = profile.verify(input, now(), &mut budget);
    if matches!(checked, Err(Error::Cbor(_) | Error::Malformed | Error::Limit(_))) {
        assert!(untouched(&budget, &limits), "a refused decode did signature work");
    }
});
