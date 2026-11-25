//! The bodies of an agent: `agent::Enrollment::parse` and `agent::Finish::parse` of untrusted JSON, and
//! `agent::Loopback::parse` of untrusted text.
#![no_main]

use libfuzzer_sys::fuzz_target;
use rsauthnz::agent::{BODY_BYTES_MAX, Enrollment, Finish, LOOPBACK_BYTES_MAX, Loopback};

fuzz_target!(|input: &[u8]| {
    let long = input.len() > BODY_BYTES_MAX;
    assert!(!(long && Enrollment::parse(input).is_ok()));
    assert!(!(long && Finish::parse(input).is_ok()));
    if let Ok(text) = str::from_utf8(input) {
        assert!(!(text.len() > LOOPBACK_BYTES_MAX && Loopback::parse(text).is_ok()));
    }
});
