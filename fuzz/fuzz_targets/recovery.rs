//! Recovery: `Code::parse` of an untrusted recovery code, 32 hexadecimal digits with any hyphens and spaces.
#![no_main]

use libfuzzer_sys::fuzz_target;
use rsauthnz::recovery::Code;

fuzz_target!(|input: &[u8]| {
    let parsed = Code::parse(input);
    let digits = input.iter().filter(|byte| !matches!(byte, b'-' | b' ')).count();
    if input.len() > 64 || digits != 32 {
        assert!(parsed.is_err(), "a text of another form parses");
    }
});
