//! COSE and CWT: `cose::Key::decode`, `cose::Sign1::decode` and its signature check, and the CWT check of
//! `cose::Profile::verify`, with the limits that the input draws (`rsauthnz_fuzz::drawn`). An input over the byte bound
//! refuses, and a decode that refuses does no signature work.
#![no_main]

use libfuzzer_sys::fuzz_target;
use rsauthnz::cose::{self, Error};
use rsauthnz::id::{Audience, Authority, Id};
use rsauthnz::limits::SignatureBudget;
use rsauthnz_fuzz::{drawn, issuer, now, untouched};

fuzz_target!(|data: &[u8]| {
    let Some((input, limits)) = drawn(data) else {
        return;
    };
    let over = input.len() > limits.bytes;
    let key = cose::Key::decode(input, limits);
    assert!(!over || key.is_err(), "a key over the byte bound decodes");
    if let Ok(sign1) = cose::Sign1::decode(input, limits) {
        assert!(!over, "a COSE_Sign1 over the byte bound decodes");
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
    if over {
        assert!(
            matches!(checked, Err(Error::Cbor(_) | Error::Limit(_))),
            "a CWT over the byte bound passed its decode"
        );
    }
    if matches!(checked, Err(Error::Cbor(_) | Error::Malformed | Error::Limit(_))) {
        assert!(untouched(&budget, &limits), "a refused decode did signature work");
    }
});
