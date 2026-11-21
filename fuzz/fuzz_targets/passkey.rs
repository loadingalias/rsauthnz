//! Passkeys: `Response::parse` and `RelyingParty::verify` of a registration, and `Assertion::parse`, with the default
//! limits. The relying party and the challenge are those of the ES256 registration case of WebAuthn Level 3, section
//! 16.2, which is a seed.
#![no_main]

use libfuzzer_sys::fuzz_target;
use rsauthnz::id::Id;
use rsauthnz::limits::Limits;
use rsauthnz::passkey::{Assertion, RelyingParty, Response};

/// The challenge of the ES256 case.
const CHALLENGE: [u8; 32] = [
    0x00, 0xc3, 0x0f, 0xb7, 0x85, 0x31, 0xc4, 0x64, 0xd2, 0xb6, 0x77, 0x1d, 0xab, 0x8d, 0x7b, 0x60, 0x3c, 0x01, 0x16,
    0x2f, 0x2f, 0xa4, 0x86, 0xbe, 0xa7, 0x0f, 0x28, 0x3a, 0xe5, 0x56, 0xe1, 0x30,
];

/// The most bytes of the JSON text of a response.
const RESPONSE_BYTES_MAX: usize = 64 * 1024;

fuzz_target!(|input: &[u8]| {
    let rp = RelyingParty::new(
        Id::new("acme", "auth").expect("an identifier"),
        "example.org",
        "https://example.org",
        "Example",
        [3; 32],
        Limits::default(),
    )
    .expect("a relying party");
    let response = Response::parse(input);
    if input.len() > RESPONSE_BYTES_MAX {
        assert!(response.is_err(), "a response over the bound parses");
    }
    if let Ok(response) = response {
        let _ = rp.verify(&response, &CHALLENGE);
    }
    let assertion = Assertion::parse(input);
    if input.len() > RESPONSE_BYTES_MAX {
        assert!(assertion.is_err(), "an assertion over the bound parses");
    }
});
