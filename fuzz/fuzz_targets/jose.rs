//! JOSE: `jose::Profile::verify_jwt` of an untrusted compact token, and `jose::Profile::with_key_set` of an untrusted
//! key set, with the default limits. A token over `TOKEN_BYTES_MAX` refuses at its limit.
#![no_main]

use libfuzzer_sys::fuzz_target;
use rsauthnz::crypto::Algorithm;
use rsauthnz::jose::{self, Error, Kind, TOKEN_BYTES_MAX};
use rsauthnz::limits::Limits;
use rsauthnz_fuzz::{issuer, now};

fuzz_target!(|input: &[u8]| {
    let profile = jose::Profile::new(
        Algorithm::Ed25519,
        Kind::Jwt,
        "https://issuer.example",
        "app",
        Limits::default(),
    )
    .expect("a profile");
    if let Ok(token) = str::from_utf8(input) {
        let keyed = profile.clone().with_key(Some("k1"), issuer()).expect("a key");
        let checked = keyed.verify_jwt(token, now());
        if token.len() > TOKEN_BYTES_MAX {
            assert!(
                matches!(checked, Err(Error::Limit)),
                "a token over the bound passed its limit"
            );
        }
    }
    let _ = profile.with_key_set(input);
});
