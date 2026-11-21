//! Bootstrap values: `local::Bootstrap::parse` of untrusted text.
#![no_main]

use libfuzzer_sys::fuzz_target;
use rsauthnz::local::Bootstrap;

fuzz_target!(|input: &[u8]| {
    if let Ok(text) = str::from_utf8(input) {
        let _ = Bootstrap::parse(text);
    }
});
