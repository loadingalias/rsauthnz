//! The vectors of RFC 8949 Appendix A and the limit cases of the CBOR codec. `tests/cbor.rs` and the portable
//! consumer (`xtask/portable`) share them, so the native tests and the browser run check the same inputs.

use rsauthnz::cbor::Value::{self, Array, Bool, Bytes, Float, Map, Negative, Null, Simple, Tag, Text, Unsigned};
use rsauthnz::limits::{Limit, Limits};

/// The 64 vectors of RFC 8949 Appendix A that are in deterministic encoding, each with the value of its diagnostic
/// notation.
pub(crate) fn deterministic() -> Vec<(&'static str, Value<'static>)> {
    let nan = f64::from_bits(0x7ff8_0000_0000_0000);
    vec![
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
    ]
}

/// The vectors of RFC 8949 Appendix A with a float in a longer form than its shortest one.
pub(crate) const NON_SHORTEST: [&str; 6] = [
    "fa7f800000",
    "fa7fc00000",
    "faff800000",
    "fb7ff0000000000000",
    "fb7ff8000000000000",
    "fbfff0000000000000",
];

/// The vectors of RFC 8949 Appendix A with an indefinite length.
pub(crate) const INDEFINITE: [&str; 11] = [
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
];

/// The default limits, with the change that `set` makes.
pub(crate) fn limits(set: impl FnOnce(&mut Limits)) -> Limits {
    let mut limits = Limits::default();
    set(&mut limits);
    limits
}

/// Each limit admits an item at the limit, and refuses an item one past it before the decoder allocates.
/// For each limit: the limits, a value at the limit, a value one past it, and the bound that refuses it.
pub(crate) fn limit_cases() -> [(Limits, &'static str, &'static str, Limit); 8] {
    [
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
    ]
}
