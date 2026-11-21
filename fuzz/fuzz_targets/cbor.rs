//! CBOR: `cbor::decode` and `cbor::decode_prefix` of untrusted bytes, with the default limits. The decoder takes only
//! the deterministic encoding, so each item that it gives encodes to the same bytes again.
#![no_main]

use libfuzzer_sys::fuzz_target;
use rsauthnz::cbor;
use rsauthnz::limits::Limits;

fuzz_target!(|input: &[u8]| {
    let limits = Limits::default();
    let decoded = cbor::decode(input, limits);
    if input.len() > limits.bytes {
        assert!(decoded.is_err(), "an input over the byte bound decodes");
    }
    if let Ok(value) = decoded {
        assert_eq!(
            cbor::encode(&value, limits).as_deref(),
            Ok(input),
            "the item has another encoding"
        );
    }
    if let Ok((value, rest)) = cbor::decode_prefix(input, limits) {
        let item = &input[..input.len() - rest.len()];
        assert_eq!(
            cbor::encode(&value, limits).as_deref(),
            Ok(item),
            "the prefix item has another encoding"
        );
    }
});
