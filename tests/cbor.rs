//! The contracts of the CBOR codec: the RFC 8949 Appendix A vectors, the limits, and the typed refusals. A counting
//! allocator shows that a refusal allocates no memory.

mod counting;
#[path = "cbor/vectors.rs"]
mod vectors;

use rsauthnz::cbor::Value::{Array, Bytes, Float, Map, Negative, Null, Simple, Text, Unsigned};
use rsauthnz::cbor::{Error, decode, decode_prefix, encode};
use rsauthnz::limits::{Limit, Limits};

use counting::allocations;

/// The bytes of a string of hexadecimal digits.
fn hex(digits: &str) -> Vec<u8> {
    digits
        .as_bytes()
        .chunks(2)
        .map(|pair| u8::from_str_radix(core::str::from_utf8(pair).expect("ASCII"), 16).expect("hexadecimal"))
        .collect()
}

/// Decodes `input` and gives its refusal. A refusal must allocate no memory.
fn refusal(input: &[u8], limits: Limits) -> Option<Error> {
    let (error, allocated) = allocations(|| decode(input, limits).err());
    if error.is_some() {
        assert_eq!(allocated, 0, "the refusal of {input:02x?} allocated memory");
    }
    error
}

/// The vectors of RFC 8949 Appendix A that are in deterministic encoding, each with the value of its diagnostic
/// notation. Each one decodes to its value, the value encodes to the vector, and the decoded value encodes again
/// to the same bytes.
#[test]
fn appendix_a_deterministic_vectors_decode_and_encode_byte_for_byte() {
    for (encoded, value) in vectors::deterministic() {
        let bytes = hex(encoded);
        let decoded = decode(&bytes, Limits::default()).expect(encoded);
        // A NaN is not equal to itself. The two encodings below check its bits.
        if !matches!(value, Float(x) if x.is_nan()) {
            assert_eq!(decoded, value, "decode {encoded}");
        }
        assert_eq!(
            encode(&decoded, Limits::default()).as_deref(),
            Ok(bytes.as_slice()),
            "encode the decoded {encoded}"
        );
        assert_eq!(
            encode(&value, Limits::default()).as_deref(),
            Ok(bytes.as_slice()),
            "encode the value of {encoded}"
        );
    }
}

/// The other vectors of RFC 8949 Appendix A: floats in a longer form, and indefinite lengths.
#[test]
fn appendix_a_vectors_outside_deterministic_encoding_refuse() {
    for encoded in vectors::NON_SHORTEST {
        assert_eq!(
            refusal(&hex(encoded), Limits::default()),
            Some(Error::NonShortest),
            "{encoded}"
        );
    }
    for encoded in vectors::INDEFINITE {
        assert_eq!(
            refusal(&hex(encoded), Limits::default()),
            Some(Error::IndefiniteLength),
            "{encoded}"
        );
    }
}

#[test]
fn each_limit_admits_its_value_and_refuses_one_past_it_without_allocating() {
    for (limits, at, past, limit) in vectors::limit_cases() {
        decode(&hex(at), limits).expect(at);
        assert_eq!(refusal(&hex(past), limits), Some(Error::Limit(limit)), "{past}");
    }
}

#[test]
fn the_encoder_refuses_at_each_limit_where_the_decoder_refuses() {
    for (limits, at, past, limit) in vectors::limit_cases() {
        let (at, past) = (hex(at), hex(past));
        let value = decode(&at, Limits::default()).expect("the value at the limit");
        assert_eq!(encode(&value, limits).as_ref(), Ok(&at), "{value:?}");
        let value = decode(&past, Limits::default()).expect("the value past the limit");
        assert_eq!(encode(&value, limits), Err(Error::Limit(limit)), "{value:?}");
    }
    // A value of a caller can nest deeper than any decode admits. It refuses at the depth limit.
    let mut deep = Array(vec![]);
    for _ in 0..=Limits::default().depth {
        deep = Array(vec![deep]);
    }
    assert_eq!(encode(&deep, Limits::default()), Err(Error::Limit(Limit::Depth)));
}

/// Each class of input outside deterministic CBOR has its typed refusal.
#[test]
fn each_malformed_class_returns_its_typed_refusal_without_allocating() {
    let cases = [
        // {1: 1, 1: 2} and {"a": 1, "a": 2}
        ("a201010102", Error::DuplicateKey),
        ("a261610161610102", Error::DuplicateKey),
        // {2: 1, 1: 2}
        ("a202010102", Error::KeyOrder),
        // {-1: 0, 1: 0}: in bytewise order of the encodings, 1 (0x01) is before -1 (0x20).
        ("a220000100", Error::KeyOrder),
        // 23 with a one-byte argument, 255 with two bytes, 65,535 with four, and 2^32 - 1 with eight.
        ("1817", Error::NonShortest),
        ("1900ff", Error::NonShortest),
        ("1a0000ffff", Error::NonShortest),
        ("1b00000000ffffffff", Error::NonShortest),
        // -1 with a one-byte argument, "a" with a one-byte length, [1] with a one-byte count, and 1(0) with a
        // one-byte tag number.
        ("3800", Error::NonShortest),
        ("780161", Error::NonShortest),
        ("980101", Error::NonShortest),
        ("d80100", Error::NonShortest),
        // 1.0 as a single and as a double.
        ("fa3f800000", Error::NonShortest),
        ("fb3ff0000000000000", Error::NonShortest),
        // 0, then 0.
        ("0000", Error::TrailingBytes),
        // An argument, a string, and an array that the input ends in.
        ("1901", Error::Truncated),
        ("6261", Error::Truncated),
        ("8201", Error::Truncated),
        // A reserved additional information, a break code alone, 31 on an integer, simple value 24 in two bytes,
        // and a text string that is not UTF-8.
        ("1c", Error::Malformed),
        ("ff", Error::Malformed),
        ("1f", Error::Malformed),
        ("f818", Error::Malformed),
        ("61ff", Error::Malformed),
    ];
    for (encoded, error) in cases {
        assert_eq!(refusal(&hex(encoded), Limits::default()), Some(error), "{encoded}");
    }
}

/// WebAuthn authenticator data puts the extensions after the credential public key. Thus the decoder gives the
/// bytes after the item, and [`Limits::bytes`] bounds the item, not the bytes after it.
#[test]
fn decode_prefix_gives_the_bytes_after_the_item() {
    // {1: 2}, then 0xff and 0x00.
    let input = hex("a10102ff00");
    let item = Map(vec![(Unsigned(1), Unsigned(2))]);
    assert_eq!(
        decode_prefix(&input, vectors::limits(|limits| limits.bytes = 3)),
        Ok((item, &input[3..]))
    );
    assert_eq!(
        decode_prefix(&input, vectors::limits(|limits| limits.bytes = 2)),
        Err(Error::Limit(Limit::Bytes))
    );
}

/// The encoder sorts map keys in bytewise order of their encodings, which is also the CTAP2 canonical order of a
/// COSE key. It refuses a map with two equal keys, and a simple value with no encoding.
#[test]
fn encode_sorts_map_keys_by_their_encodings_and_refuses_values_without_an_encoding() {
    // {-3: h'01', -2: h'00', -1: 1, 3: -7, 1: 2}: an EC2 key in the reverse of its canonical order.
    let key = Map(vec![
        (Negative(2), Bytes(&[1])),
        (Negative(1), Bytes(&[0])),
        (Negative(0), Unsigned(1)),
        (Unsigned(3), Negative(6)),
        (Unsigned(1), Unsigned(2)),
    ]);
    assert_eq!(encode(&key, Limits::default()), Ok(hex("a5010203262001214100224101")));
    assert_eq!(
        encode(&Map(vec![(Text("a"), Null), (Text("a"), Null)]), Limits::default()),
        Err(Error::DuplicateKey)
    );
    for simple in [20, 22, 24, 31] {
        assert_eq!(
            encode(&Simple(simple), Limits::default()),
            Err(Error::Malformed),
            "simple({simple})"
        );
    }
}

/// A string can hold a credential or a key, so the debug output of a value shows only the length of each string.
#[test]
fn debug_output_shows_string_lengths_not_contents() {
    let value = Map(vec![(Text("d"), Bytes(b"private key"))]);
    assert_eq!(format!("{value:?}"), "{Text { len: 1 }: Bytes { len: 11 }}");
}
