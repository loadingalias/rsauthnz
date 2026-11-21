//! Sessions: `Identifier::parse` of an untrusted cookie value, the base64url text of 64 bytes.
#![no_main]

use libfuzzer_sys::fuzz_target;
use rsauthnz::session::{IDENTIFIER_CHARS, Identifier};

fuzz_target!(|input: &[u8]| {
    let parsed = Identifier::parse(input);
    if input.len() != IDENTIFIER_CHARS {
        assert!(parsed.is_err(), "a cookie value of another length parses");
    }
});
