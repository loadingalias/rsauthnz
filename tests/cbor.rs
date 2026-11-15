//! The contracts of the CBOR codec: the RFC 8949 Appendix A vectors, the limits, and the typed refusals. A counting
//! allocator shows that a refusal allocates no memory.

use core::alloc::{GlobalAlloc, Layout};
use core::cell::Cell;
use std::alloc::System;

use rsauthnz::cbor::Value::{Array, Bool, Bytes, Float, Map, Negative, Null, Simple, Tag, Text, Unsigned};
use rsauthnz::cbor::{Error, decode, decode_prefix, encode};
use rsauthnz::limits::{Limit, Limits};

thread_local! {
    /// The allocations of this thread. Each test runs on its own thread, so a test counts only its own allocations.
    static ALLOCATIONS: Cell<usize> = const { Cell::new(0) };
}

/// Counts each allocation of the thread, then gives it to the system allocator.
struct Counting;

#[expect(
    unsafe_code,
    reason = "a global allocator implements an unsafe trait; each method forwards to `System` unchanged"
)]
// SAFETY: each method gives its arguments, and the contract of its caller, to `System` with no change.
unsafe impl GlobalAlloc for Counting {
    unsafe fn alloc(&self, layout: Layout) -> *mut u8 {
        ALLOCATIONS.with(|count| count.set(count.get() + 1));
        // SAFETY: the caller keeps the contract of `GlobalAlloc::alloc`, which is also the contract of `System`.
        unsafe { System.alloc(layout) }
    }

    unsafe fn dealloc(&self, ptr: *mut u8, layout: Layout) {
        // SAFETY: `ptr` came from `System.alloc` with `layout`, through `Counting::alloc`.
        unsafe { System.dealloc(ptr, layout) }
    }
}

#[global_allocator]
static ALLOCATOR: Counting = Counting;

/// The bytes of a string of hexadecimal digits.
fn hex(digits: &str) -> Vec<u8> {
    digits
        .as_bytes()
        .chunks(2)
        .map(|pair| u8::from_str_radix(core::str::from_utf8(pair).expect("ASCII"), 16).expect("hexadecimal"))
        .collect()
}

/// The default limits, with the change that `set` makes.
fn limits(set: impl FnOnce(&mut Limits)) -> Limits {
    let mut limits = Limits::default();
    set(&mut limits);
    limits
}

/// Decodes `input` and gives its refusal. A refusal must allocate no memory. First, an accepted array must
/// allocate: thus a count that does not work fails, and does not hide an allocation.
fn refusal(input: &[u8], limits: Limits) -> Option<Error> {
    let counted = ALLOCATIONS.with(Cell::get);
    decode(&[0x82, 0x01, 0x02], Limits::default()).expect("[1, 2]");
    let before = ALLOCATIONS.with(Cell::get);
    assert!(before > counted, "the decode of [1, 2] counted no allocation");
    let error = decode(input, limits).err();
    if error.is_some() {
        assert_eq!(
            ALLOCATIONS.with(Cell::get),
            before,
            "the refusal of {input:02x?} allocated memory"
        );
    }
    error
}

/// The vectors of RFC 8949 Appendix A that are in deterministic encoding, each with the value of its diagnostic
/// notation. Each one decodes to its value, the value encodes to the vector, and the decoded value encodes again
/// to the same bytes.
#[test]
fn appendix_a_deterministic_vectors_decode_and_encode_byte_for_byte() {
    let nan = f64::from_bits(0x7ff8_0000_0000_0000);
    let vectors = [
        ("00", Unsigned(0)),
        ("01", Unsigned(1)),
        ("0a", Unsigned(10)),
        ("17", Unsigned(23)),
        ("1818", Unsigned(24)),
        ("1819", Unsigned(25)),
        ("1864", Unsigned(100)),
        ("1903e8", Unsigned(1000)),
        ("1a000f4240", Unsigned(1_000_000)),
        ("1b000000e8d4a51000", Unsigned(1_000_000_000_000)),
        ("1bffffffffffffffff", Unsigned(u64::MAX)),
        (
            "c249010000000000000000",
            Tag(2, Box::new(Bytes(&[1, 0, 0, 0, 0, 0, 0, 0, 0]))),
        ),
        ("3bffffffffffffffff", Negative(u64::MAX)),
        (
            "c349010000000000000000",
            Tag(3, Box::new(Bytes(&[1, 0, 0, 0, 0, 0, 0, 0, 0]))),
        ),
        ("20", Negative(0)),
        ("29", Negative(9)),
        ("3863", Negative(99)),
        ("3903e7", Negative(999)),
        ("f90000", Float(0.0)),
        ("f98000", Float(-0.0)),
        ("f93c00", Float(1.0)),
        ("fb3ff199999999999a", Float(1.1)),
        ("f93e00", Float(1.5)),
        ("f97bff", Float(65504.0)),
        ("fa47c35000", Float(100_000.0)),
        ("fa7f7fffff", Float(3.402_823_466_385_288_6e38)),
        ("fb7e37e43c8800759c", Float(1.0e300)),
        ("f90001", Float(5.960_464_477_539_063e-8)),
        ("f90400", Float(0.000_061_035_156_25)),
        ("f9c400", Float(-4.0)),
        ("fbc010666666666666", Float(-4.1)),
        ("f97c00", Float(f64::INFINITY)),
        ("f97e00", Float(nan)),
        ("f9fc00", Float(f64::NEG_INFINITY)),
        ("f4", Bool(false)),
        ("f5", Bool(true)),
        ("f6", Null),
        ("f7", Simple(23)),
        ("f0", Simple(16)),
        ("f8ff", Simple(255)),
        (
            "c074323031332d30332d32315432303a30343a30305a",
            Tag(0, Box::new(Text("2013-03-21T20:04:00Z"))),
        ),
        ("c11a514b67b0", Tag(1, Box::new(Unsigned(1_363_896_240)))),
        ("c1fb41d452d9ec200000", Tag(1, Box::new(Float(1_363_896_240.5)))),
        ("d74401020304", Tag(23, Box::new(Bytes(&[1, 2, 3, 4])))),
        ("d818456449455446", Tag(24, Box::new(Bytes(b"dIETF")))),
        (
            "d82076687474703a2f2f7777772e6578616d706c652e636f6d",
            Tag(32, Box::new(Text("http://www.example.com"))),
        ),
        ("40", Bytes(&[])),
        ("4401020304", Bytes(&[1, 2, 3, 4])),
        ("60", Text("")),
        ("6161", Text("a")),
        ("6449455446", Text("IETF")),
        ("62225c", Text("\"\\")),
        ("62c3bc", Text("\u{fc}")),
        ("63e6b0b4", Text("\u{6c34}")),
        ("64f0908591", Text("\u{10151}")),
        ("80", Array(vec![])),
        ("83010203", Array(vec![Unsigned(1), Unsigned(2), Unsigned(3)])),
        (
            "8301820203820405",
            Array(vec![
                Unsigned(1),
                Array(vec![Unsigned(2), Unsigned(3)]),
                Array(vec![Unsigned(4), Unsigned(5)]),
            ]),
        ),
        (
            "98190102030405060708090a0b0c0d0e0f101112131415161718181819",
            Array((1..=25).map(Unsigned).collect()),
        ),
        ("a0", Map(vec![])),
        (
            "a201020304",
            Map(vec![(Unsigned(1), Unsigned(2)), (Unsigned(3), Unsigned(4))]),
        ),
        (
            "a26161016162820203",
            Map(vec![
                (Text("a"), Unsigned(1)),
                (Text("b"), Array(vec![Unsigned(2), Unsigned(3)])),
            ]),
        ),
        (
            "826161a161626163",
            Array(vec![Text("a"), Map(vec![(Text("b"), Text("c"))])]),
        ),
        (
            "a56161614161626142616361436164614461656145",
            Map(vec![
                (Text("a"), Text("A")),
                (Text("b"), Text("B")),
                (Text("c"), Text("C")),
                (Text("d"), Text("D")),
                (Text("e"), Text("E")),
            ]),
        ),
    ];
    for (encoded, value) in vectors {
        let bytes = hex(encoded);
        let decoded = decode(&bytes, Limits::default()).expect(encoded);
        // A NaN is not equal to itself. The two encodings below check its bits.
        if !matches!(value, Float(x) if x.is_nan()) {
            assert_eq!(decoded, value, "decode {encoded}");
        }
        assert_eq!(
            encode(&decoded).as_deref(),
            Ok(bytes.as_slice()),
            "encode the decoded {encoded}"
        );
        assert_eq!(
            encode(&value).as_deref(),
            Ok(bytes.as_slice()),
            "encode the value of {encoded}"
        );
    }
}

/// The other vectors of RFC 8949 Appendix A: floats in a longer form, and indefinite lengths.
#[test]
fn appendix_a_vectors_outside_deterministic_encoding_refuse() {
    for encoded in [
        "fa7f800000",
        "fa7fc00000",
        "faff800000",
        "fb7ff0000000000000",
        "fb7ff8000000000000",
        "fbfff0000000000000",
    ] {
        assert_eq!(
            refusal(&hex(encoded), Limits::default()),
            Some(Error::NonShortest),
            "{encoded}"
        );
    }
    for encoded in [
        "5f42010243030405ff",
        "7f657374726561646d696e67ff",
        "9fff",
        "9f018202039f0405ffff",
        "9f01820203820405ff",
        "83018202039f0405ff",
        "83019f0203ff820405",
        "9f0102030405060708090a0b0c0d0e0f101112131415161718181819ff",
        "bf61610161629f0203ffff",
        "826161bf61626163ff",
        "bf6346756ef563416d7421ff",
    ] {
        assert_eq!(
            refusal(&hex(encoded), Limits::default()),
            Some(Error::IndefiniteLength),
            "{encoded}"
        );
    }
}

/// Each limit admits an item at the limit, and refuses an item one past it before the decoder allocates.
#[test]
fn each_limit_admits_its_value_and_refuses_one_past_it_without_allocating() {
    let cases = [
        // [1, 2] has 3 bytes, and [1, 2, 3] has 4.
        (limits(|limits| limits.bytes = 3), "820102", "83010203", Limit::Bytes),
        // [[]] has 2 levels, and [[[]]] has 3.
        (limits(|limits| limits.depth = 2), "8180", "818180", Limit::Depth),
        // 1(1(0)) has 2 levels, and 1(1(1(0))) has 3.
        (limits(|limits| limits.depth = 2), "c1c100", "c1c1c100", Limit::Depth),
        // [1, 2] has 3 items, and [1, 2, 3] has 4.
        (limits(|limits| limits.items = 3), "820102", "83010203", Limit::Items),
        // {1: 1, 2: 2} has 5 items, and [{1: 1, 2: 2}] has 6.
        (
            limits(|limits| limits.items = 5),
            "a201010202",
            "81a201010202",
            Limit::Items,
        ),
        // {1: 1, 2: 2} has 2 keys, and {1: 1, 2: 2, 3: 3} has 3.
        (
            limits(|limits| limits.map_keys = 2),
            "a201010202",
            "a3010102020303",
            Limit::MapKeys,
        ),
        // h'010203' and "abc" have 3 bytes, and h'01020304' and "abcd" have 4.
        (
            limits(|limits| limits.string_bytes = 3),
            "43010203",
            "4401020304",
            Limit::StringBytes,
        ),
        (
            limits(|limits| limits.string_bytes = 3),
            "63616263",
            "6461626364",
            Limit::StringBytes,
        ),
    ];
    for (limits, at, past, limit) in cases {
        decode(&hex(at), limits).expect(at);
        assert_eq!(refusal(&hex(past), limits), Some(Error::Limit(limit)), "{past}");
    }
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
        decode_prefix(&input, limits(|limits| limits.bytes = 3)),
        Ok((item, &input[3..]))
    );
    assert_eq!(
        decode_prefix(&input, limits(|limits| limits.bytes = 2)),
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
    assert_eq!(encode(&key), Ok(hex("a5010203262001214100224101")));
    assert_eq!(
        encode(&Map(vec![(Text("a"), Null), (Text("a"), Null)])),
        Err(Error::DuplicateKey)
    );
    for simple in [20, 22, 24, 31] {
        assert_eq!(encode(&Simple(simple)), Err(Error::Malformed), "simple({simple})");
    }
}

/// A string can hold a credential or a key, so the debug output of a value shows only the length of each string.
#[test]
fn debug_output_shows_string_lengths_not_contents() {
    let value = Map(vec![(Text("d"), Bytes(b"private key"))]);
    assert_eq!(format!("{value:?}"), "{Text { len: 1 }: Bytes { len: 11 }}");
}
