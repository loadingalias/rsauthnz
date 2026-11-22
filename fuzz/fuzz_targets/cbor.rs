//! CBOR: `cbor::decode` and `cbor::decode_prefix` of untrusted bytes, with the default limits and with the limits
//! that the input draws (`rsauthnz_fuzz::drawn`). The decoder takes only the deterministic encoding, so each item that
//! it gives encodes to the same bytes again. Within the drawn limits, an input over the byte bound refuses, and only a
//! bound refuses that the defaults do not: the defaults are not smaller, so an item that decodes, or a refusal that
//! names no bound, gives the same result within the defaults.
#![no_main]

use libfuzzer_sys::fuzz_target;
use rsauthnz::cbor::{self, Error};
use rsauthnz::limits::{Limit, Limits};
use rsauthnz_fuzz::drawn;

fuzz_target!(|data: &[u8]| {
    let Some((input, drawn)) = drawn(data) else {
        return;
    };
    let limits = Limits::default();
    let decoded = cbor::decode(input, limits);
    if input.len() > limits.bytes {
        assert!(decoded.is_err(), "an input over the byte bound decodes");
    }
    if let Ok(value) = &decoded {
        assert_eq!(
            cbor::encode(value, limits).as_deref(),
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

    let within = cbor::decode(input, drawn);
    if input.len() > drawn.bytes {
        assert_eq!(
            within.as_ref().err(),
            Some(&Error::Limit(Limit::Bytes)),
            "an input over the drawn byte bound decodes"
        );
    }
    match &within {
        // A float NaN is not equal to itself, so the encodings compare the values.
        Ok(value) => {
            assert!(
                decoded.is_ok(),
                "an item within the drawn limits refuses within the defaults"
            );
            assert_eq!(
                cbor::encode(value, drawn).as_deref(),
                Ok(input),
                "the item has another encoding within the drawn limits"
            );
        }
        Err(Error::Limit(_)) => {}
        Err(error) => assert_eq!(
            decoded.as_ref().err(),
            Some(error),
            "a refusal that names no bound differs within the defaults"
        ),
    }
});
