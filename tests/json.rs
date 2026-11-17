//! The contracts of the JSON reader: the RFC 8259 examples, the JSONTestSuite cases, the limits, the typed
//! refusals, the duplicate-member rule, and the borrowed strings. A counting allocator shows that a refusal allocates
//! no memory.

mod counting;

use std::assert_matches;
use std::borrow::Cow;
use std::fs;
use std::path::Path;

use rsauthnz::json::Value::{Array, Bool, Number, Object};
use rsauthnz::json::{Error, Value, decode};
use rsauthnz::limits::{Limit, Limits};

use counting::allocations;

/// The default limits, with the change that `set` makes.
fn limits(set: impl FnOnce(&mut Limits)) -> Limits {
    let mut limits = Limits::default();
    set(&mut limits);
    limits
}

/// The largest value of each limit. Thus only the grammar and the rules of the reader can refuse an input.
fn widest() -> Limits {
    limits(|limits| {
        limits.bytes = usize::MAX;
        limits.depth = u8::MAX;
        limits.items = usize::MAX;
        limits.map_keys = usize::MAX;
        limits.string_bytes = usize::MAX;
    })
}

/// Decodes `input` and gives its refusal. Each refusal but [`Error::DuplicateMember`] must allocate no memory.
fn refusal(input: &[u8], limits: Limits) -> Option<Error> {
    let (error, allocated) = allocations(|| decode(input, limits).err());
    if error.is_some_and(|error| error != Error::DuplicateMember) {
        assert_eq!(
            allocated,
            0,
            "the refusal of {:?} allocated memory",
            String::from_utf8_lossy(input)
        );
    }
    error
}

fn string(text: &str) -> Value<'_> {
    Value::String(text.into())
}

/// An object with these members, in the order of the list.
fn object<'a>(members: impl IntoIterator<Item = (&'a str, Value<'a>)>) -> Value<'a> {
    Object(members.into_iter().map(|(name, value)| (name.into(), value)).collect())
}

/// The examples of RFC 8259, section 13, and the three small texts of that section. The reader gives the members of
/// an object in increasing bytewise order of their names.
#[test]
fn rfc_8259_examples_decode_to_their_values() {
    let image = br#"{
      "Image": {
          "Width":  800,
          "Height": 600,
          "Title":  "View from 15th Floor",
          "Thumbnail": {
              "Url":    "http://www.example.com/image/481989943",
              "Height": 125,
              "Width":  100
          },
          "Animated" : false,
          "IDs": [116, 943, 234, 38793]
        }
    }"#;
    let expected = object([(
        "Image",
        object([
            ("Animated", Bool(false)),
            ("Height", Number("600")),
            (
                "IDs",
                Array(vec![Number("116"), Number("943"), Number("234"), Number("38793")]),
            ),
            (
                "Thumbnail",
                object([
                    ("Height", Number("125")),
                    ("Url", string("http://www.example.com/image/481989943")),
                    ("Width", Number("100")),
                ]),
            ),
            ("Title", string("View from 15th Floor")),
            ("Width", Number("800")),
        ]),
    )]);
    assert_eq!(decode(image, Limits::default()), Ok(expected));

    let places = br#"[
      {
         "precision": "zip",
         "Latitude":  37.7668,
         "Longitude": -122.3959,
         "Address":   "",
         "City":      "SAN FRANCISCO",
         "State":     "CA",
         "Zip":       "94107",
         "Country":   "US"
      },
      {
         "precision": "zip",
         "Latitude":  37.371991,
         "Longitude": -122.026020,
         "Address":   "",
         "City":      "SUNNYVALE",
         "State":     "CA",
         "Zip":       "94085",
         "Country":   "US"
      }
    ]"#;
    let place = |latitude, longitude, city, zip| {
        object([
            ("Address", string("")),
            ("City", string(city)),
            ("Country", string("US")),
            ("Latitude", Number(latitude)),
            ("Longitude", Number(longitude)),
            ("State", string("CA")),
            ("Zip", string(zip)),
            ("precision", string("zip")),
        ])
    };
    let expected = Array(vec![
        place("37.7668", "-122.3959", "SAN FRANCISCO", "94107"),
        place("37.371991", "-122.026020", "SUNNYVALE", "94085"),
    ]);
    assert_eq!(decode(places, Limits::default()), Ok(expected));

    assert_eq!(
        decode(br#""Hello world!""#, Limits::default()),
        Ok(string("Hello world!"))
    );
    assert_eq!(decode(b"42", Limits::default()), Ok(Number("42")));
    assert_eq!(decode(b"true", Limits::default()), Ok(Bool(true)));
}

/// The result of each `i_` case of JSONTestSuite, for which RFC 8259 lets a parser accept or refuse.
///
/// Each number is in the grammar, and the reader keeps its text, so it accepts. Each other case is not UTF-8, has a
/// byte order mark, has a lone surrogate, or is deeper than the greatest depth limit.
const IMPLEMENTATION_DEFINED: [(&str, Option<Error>); 35] = [
    ("i_number_double_huge_neg_exp.json", None),
    ("i_number_huge_exp.json", None),
    ("i_number_neg_int_huge_exp.json", None),
    ("i_number_pos_double_huge_exp.json", None),
    ("i_number_real_neg_overflow.json", None),
    ("i_number_real_pos_overflow.json", None),
    ("i_number_real_underflow.json", None),
    ("i_number_too_big_neg_int.json", None),
    ("i_number_too_big_pos_int.json", None),
    ("i_number_very_big_negative_int.json", None),
    ("i_object_key_lone_2nd_surrogate.json", Some(Error::LoneSurrogate)),
    (
        "i_string_1st_surrogate_but_2nd_missing.json",
        Some(Error::LoneSurrogate),
    ),
    (
        "i_string_1st_valid_surrogate_2nd_invalid.json",
        Some(Error::LoneSurrogate),
    ),
    ("i_string_UTF-16LE_with_BOM.json", Some(Error::Malformed)),
    ("i_string_UTF-8_invalid_sequence.json", Some(Error::Malformed)),
    ("i_string_UTF8_surrogate_U+D800.json", Some(Error::Malformed)),
    (
        "i_string_incomplete_surrogate_and_escape_valid.json",
        Some(Error::LoneSurrogate),
    ),
    ("i_string_incomplete_surrogate_pair.json", Some(Error::LoneSurrogate)),
    (
        "i_string_incomplete_surrogates_escape_valid.json",
        Some(Error::LoneSurrogate),
    ),
    ("i_string_invalid_lonely_surrogate.json", Some(Error::LoneSurrogate)),
    ("i_string_invalid_surrogate.json", Some(Error::LoneSurrogate)),
    ("i_string_invalid_utf-8.json", Some(Error::Malformed)),
    ("i_string_inverted_surrogates_U+1D11E.json", Some(Error::LoneSurrogate)),
    ("i_string_iso_latin_1.json", Some(Error::Malformed)),
    ("i_string_lone_second_surrogate.json", Some(Error::LoneSurrogate)),
    ("i_string_lone_utf8_continuation_byte.json", Some(Error::Malformed)),
    ("i_string_not_in_unicode_range.json", Some(Error::Malformed)),
    ("i_string_overlong_sequence_2_bytes.json", Some(Error::Malformed)),
    ("i_string_overlong_sequence_6_bytes.json", Some(Error::Malformed)),
    ("i_string_overlong_sequence_6_bytes_null.json", Some(Error::Malformed)),
    ("i_string_truncated-utf-8.json", Some(Error::Malformed)),
    ("i_string_utf16BE_no_BOM.json", Some(Error::Malformed)),
    ("i_string_utf16LE_no_BOM.json", Some(Error::Malformed)),
    ("i_structure_500_nested_arrays.json", Some(Error::Limit(Limit::Depth))),
    ("i_structure_UTF-8_BOM_empty_object.json", Some(Error::Malformed)),
];

/// The `y_` cases that the reader refuses. RFC 8259 permits two members with equal names, and I-JSON (RFC 7493)
/// does not.
const DUPLICATE_MEMBERS: [&str; 2] = ["y_object_duplicated_key.json", "y_object_duplicated_key_and_value.json"];

/// JSONTestSuite: each `y_` case accepts, except the cases with two equal member names. Each `n_` case refuses, and
/// each `i_` case gives its result in [`IMPLEMENTATION_DEFINED`]. No refusal but a duplicate member allocates.
#[test]
fn json_test_suite_cases_give_their_expected_results() {
    let dir = Path::new(env!("CARGO_MANIFEST_DIR")).join("tests/json-test-suite/test_parsing");
    let mut counts = [0; 3];
    for entry in fs::read_dir(&dir).expect("the JSONTestSuite directory") {
        let path = entry.expect("directory entry").path();
        let name = path
            .file_name()
            .and_then(|name| name.to_str())
            .expect("a UTF-8 file name");
        let input = fs::read(&path).expect("case");
        let error = refusal(&input, widest());
        if name.starts_with("y_") {
            counts[0] += 1;
            let expected = DUPLICATE_MEMBERS.contains(&name).then_some(Error::DuplicateMember);
            assert_eq!(error, expected, "{name}");
        } else if name.starts_with("n_") {
            counts[1] += 1;
            assert!(error.is_some(), "{name} accepts");
        } else {
            counts[2] += 1;
            let expected = IMPLEMENTATION_DEFINED.iter().find(|(case, _)| *case == name);
            assert_eq!(Some(error), expected.map(|&(_, result)| result), "{name}");
        }
    }
    assert_eq!(counts, [95, 188, 35], "the cases of the vendored suite");
}

/// Each limit admits a text at the limit, and refuses a text one past it before the reader allocates.
#[test]
fn each_limit_admits_its_value_and_refuses_one_past_it_without_allocating() {
    let cases: [(Limits, &str, &str, Limit); 11] = [
        (limits(|limits| limits.bytes = 7), "[1,2,3]", "[1,2,34]", Limit::Bytes),
        // [[]] has 2 levels, and [[[]]] has 3.
        (limits(|limits| limits.depth = 2), "[[]]", "[[[]]]", Limit::Depth),
        (
            limits(|limits| limits.depth = 2),
            r#"{"a":{}}"#,
            r#"{"a":{"b":{}}}"#,
            Limit::Depth,
        ),
        // [1,2] has 3 items. {"a":1} has 3: the object, the name, and the value.
        (limits(|limits| limits.items = 3), "[1,2]", "[1,2,3]", Limit::Items),
        (
            limits(|limits| limits.items = 3),
            r#"{"a":1}"#,
            r#"[{"a":1}]"#,
            Limit::Items,
        ),
        (
            limits(|limits| limits.map_keys = 2),
            r#"{"a":1,"b":2}"#,
            r#"{"a":1,"b":2,"c":3}"#,
            Limit::MapKeys,
        ),
        (
            limits(|limits| limits.string_bytes = 3),
            r#""abc""#,
            r#""abcd""#,
            Limit::StringBytes,
        ),
        (
            limits(|limits| limits.string_bytes = 3),
            r#"{"abc":1}"#,
            r#"{"abcd":1}"#,
            Limit::StringBytes,
        ),
        // The bound applies to the string after its escapes: "abcdefg\n" has 8 bytes, and "abcdefgh\n" has 9.
        (
            limits(|limits| limits.string_bytes = 8),
            r#""abcdefg\n""#,
            r#""abcdefgh\n""#,
            Limit::StringBytes,
        ),
        // Two U+00E9 have 4 bytes in UTF-8, and 12 in the input.
        (
            limits(|limits| limits.string_bytes = 4),
            r#""\u00e9\u00e9""#,
            r#""\u00e9\u00e9a""#,
            Limit::StringBytes,
        ),
        // U+1F600 has 4 bytes in UTF-8, from one surrogate pair.
        (
            limits(|limits| limits.string_bytes = 4),
            r#""\ud83d\ude00""#,
            r#""\ud83d\ude00a""#,
            Limit::StringBytes,
        ),
    ];
    for (limits, at, past, limit) in cases {
        decode(at.as_bytes(), limits).expect(at);
        assert_eq!(refusal(past.as_bytes(), limits), Some(Error::Limit(limit)), "{past}");
    }
}

/// Each class of input outside the grammar, or outside the rules of the reader, has its typed refusal.
#[test]
fn each_refusal_class_returns_its_typed_refusal_without_allocating() {
    let cases: [(&[u8], Error); 37] = [
        (b"", Error::Truncated),
        (b" \t\r\n", Error::Truncated),
        (b"[", Error::Truncated),
        (b"[1,", Error::Truncated),
        (br#"{"a""#, Error::Truncated),
        (br#"{"a":"#, Error::Truncated),
        (br#""abc"#, Error::Truncated),
        (b"tru", Error::Truncated),
        (b"-", Error::Truncated),
        (b"1.", Error::Truncated),
        (b"1e+", Error::Truncated),
        (br#""\u12"#, Error::Truncated),
        (br#""\ud800\"#, Error::Truncated),
        (b"1 2", Error::TrailingBytes),
        (b"{} x", Error::TrailingBytes),
        (b"[]]", Error::TrailingBytes),
        (b"[1,]", Error::Malformed),
        (br#"{"a":1,}"#, Error::Malformed),
        (b"[01]", Error::Malformed),
        (b"[+1]", Error::Malformed),
        (b"[.5]", Error::Malformed),
        (b"[1.e1]", Error::Malformed),
        (b"[NaN]", Error::Malformed),
        (b"[-Infinity]", Error::Malformed),
        (b"[nul]", Error::Malformed),
        (b"{a:1}", Error::Malformed),
        (br#"{"a" 1}"#, Error::Malformed),
        (b"[1 2]", Error::Malformed),
        (b"['a']", Error::Malformed),
        (br#"["\x41"]"#, Error::Malformed),
        // A tab in a string must be an escape.
        (b"[\"a\tb\"]", Error::Malformed),
        // A byte that is not UTF-8, and a UTF-8 byte order mark.
        (b"[\"\xff\"]", Error::Malformed),
        (b"\xef\xbb\xbf{}", Error::Malformed),
        (br#"["\ud800"]"#, Error::LoneSurrogate),
        (br#"["\udc00"]"#, Error::LoneSurrogate),
        (br#"["\ud800A"]"#, Error::LoneSurrogate),
        (br#"["\ud800x"]"#, Error::LoneSurrogate),
    ];
    for (input, error) in cases {
        assert_eq!(
            refusal(input, Limits::default()),
            Some(error),
            "{:?}",
            String::from_utf8_lossy(input)
        );
    }
}

/// The reader scans a string eight bytes at a time. By RFC 8259, section 7, a quote ends the string, a backslash
/// starts an escape, and a control character refuses. Each one acts at each position of a word and at the boundary
/// of two words. A space, DEL, and a two-byte UTF-8 character are plain bytes there.
#[test]
fn each_quote_backslash_and_control_byte_acts_at_each_position_of_a_word() {
    for at in 0..=24 {
        let (before, after) = ("a".repeat(at), "a".repeat(24 - at));
        // The quote ends the first string, and the bytes after it are the second string.
        let text = format!(r#"["{before}","{after}"]"#);
        assert_eq!(
            decode(text.as_bytes(), Limits::default()),
            Ok(Array(vec![string(&before), string(&after)])),
            "{text}"
        );
        for (inside, character) in [
            (r#"\""#, "\""),
            (r"\\", "\\"),
            (r"\n", "\n"),
            (" ", " "),
            ("\u{7f}", "\u{7f}"),
            ("é", "é"),
        ] {
            let text = format!(r#"["{before}{inside}{after}"]"#);
            assert_eq!(
                decode(text.as_bytes(), Limits::default()),
                Ok(Array(vec![string(&format!("{before}{character}{after}"))])),
                "{text:?}"
            );
        }
        for control in 0x00..0x20 {
            let mut text = format!(r#"["{before}?{after}"]"#).into_bytes();
            text[2 + at] = control;
            assert_eq!(
                refusal(&text, Limits::default()),
                Some(Error::Malformed),
                "{control:#04x} at {at}"
            );
        }
    }
}

/// Two member names are equal when their characters are equal after the escapes. Each object in the value is
/// checked, at each level. Names that differ in one character are not equal.
#[test]
fn members_with_names_equal_after_the_escapes_refuse() {
    for input in [
        r#"{"a":1,"a":2}"#,
        r#"{"a":1,"\u0061":2}"#,
        r#"{"\ud83d\ude00":1,"😀":2}"#,
        r#"{"b":0,"a":1,"c":2,"a":3}"#,
        r#"[{"x":{"b":1,"b":1}}]"#,
    ] {
        assert_eq!(
            refusal(input.as_bytes(), Limits::default()),
            Some(Error::DuplicateMember),
            "{input}"
        );
    }
    assert_eq!(
        decode(br#"{"a":1,"A":2,"a ":3}"#, Limits::default()),
        Ok(object([("A", Number("2")), ("a", Number("1")), ("a ", Number("3"))]))
    );
}

/// A string with no escape borrows the input. A string with an escape is a copy, with the characters of the
/// escapes.
#[test]
fn a_string_with_no_escape_borrows_the_input() {
    let input = br#"["abc", "d\u00e9f\n", {"name": "x"}]"#;
    let value = decode(input, Limits::default()).expect("the array");
    let items = match &value {
        Array(items) => Some(items),
        _ => None,
    }
    .expect("an array");
    let members = match &items[2] {
        Object(members) => Some(members),
        _ => None,
    }
    .expect("an object");
    let borrowed =
        |text: &Cow<'_, str>| matches!(text, Cow::Borrowed(text) if input.as_ptr_range().contains(&text.as_ptr()));
    assert_matches!(&items[0], Value::String(text) if borrowed(text) && text == "abc");
    assert_matches!(&items[1], Value::String(Cow::Owned(text)) if text == "d\u{e9}f\n");
    assert_matches!(&members[0].0, name if borrowed(name) && name == "name");
    assert_matches!(&members[0].1, Value::String(text) if borrowed(text) && text == "x");
}

/// At the greatest depth limit, 255 levels of arrays and of objects decode in the 1 MiB stack of a
/// `wasm32-unknown-unknown` program, and one level more refuses.
#[test]
fn the_greatest_depth_decodes_in_a_one_mebibyte_stack() {
    let thread = std::thread::Builder::new().stack_size(1 << 20).spawn(|| {
        for (open, close) in [("[", "]"), (r#"{"a":"#, "}")] {
            let text = |levels| format!("{}0{}", open.repeat(levels), close.repeat(levels));
            let deepest = text(255);
            let value = decode(deepest.as_bytes(), widest()).expect("255 levels");
            drop(value);
            assert_eq!(
                decode(text(256).as_bytes(), widest()),
                Err(Error::Limit(Limit::Depth)),
                "256 levels"
            );
        }
    });
    thread.expect("the thread").join().expect("the decode thread");
}

/// A string can hold a challenge, a token, or a key, so the debug output of a value shows only the length of each
/// string and member name.
#[test]
fn debug_output_shows_string_lengths_not_contents() {
    let value = decode(br#"{"d": "private key", "n": [1, null]}"#, Limits::default()).expect("the object");
    assert_eq!(
        format!("{value:?}"),
        r#"{String { len: 1 }: String { len: 11 }, String { len: 1 }: [Number("1"), Null]}"#
    );
}
