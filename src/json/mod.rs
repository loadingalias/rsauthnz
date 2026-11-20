//! Bounded JSON ([RFC 8259]): the one JSON reader for WebAuthn `clientDataJSON`, JOSE headers and claims, and OAuth
//! metadata documents.
//!
//! [`decode`] accepts exactly the grammar of RFC 8259, in UTF-8, with two rules of I-JSON ([RFC 7493]): no object
//! has two members with equal names, and no escape gives a lone surrogate. Thus each member name has one value, and
//! each string is a Rust `str`. Names are equal when their characters are equal after the decoder reads the escapes,
//! so `"a"` and `"\u0061"` are equal.
//!
//! The decoder works in two passes. The check pass reads the whole text against the
//! [`Limits`](crate::limits::Limits) of the caller, makes each refusal but one, and allocates no memory. Then the
//! build pass makes the value. A duplicate member refuses in the build pass, and it can allocate only within the
//! bounds that the check pass admitted. Each limit still refuses before allocation. The error value holds no input
//! text and no allocation. A string with no escape borrows the input.
//!
//! ```
//! use rsauthnz::json::{self, Value};
//! use rsauthnz::limits::Limits;
//!
//! // A JOSE header.
//! let text = br#"{"typ": "JWT", "alg": "EdDSA"}"#;
//! let value = json::decode(text, Limits::default())?;
//! assert_eq!(
//!     value,
//!     Value::Object(vec![
//!         ("alg".into(), Value::String("EdDSA".into())),
//!         ("typ".into(), Value::String("JWT".into())),
//!     ])
//! );
//! # Ok::<(), json::Error>(())
//! ```
//!
//! [RFC 8259]: https://www.rfc-editor.org/rfc/rfc8259
//! [RFC 7493]: https://www.rfc-editor.org/rfc/rfc7493

mod decode;

use alloc::borrow::Cow;
use alloc::vec::Vec;
use core::fmt;

use crate::limits::Limit;

pub use decode::decode;

/// A JSON value. A string with no escape borrows the decoded input. A string with an escape is a copy, which is not
/// longer than its text in the input.
#[derive(Clone, PartialEq, Eq)]
pub enum Value<'a> {
    /// `null`.
    Null,
    /// `false` or `true`.
    Bool(bool),
    /// A number, as its text in the input. The text matches the number grammar of RFC 8259, so `str::parse` reads it
    /// into an integer or a float type. Two numbers are equal when their texts are equal.
    Number(&'a str),
    /// A string.
    String(Cow<'a, str>),
    /// An array.
    Array(Vec<Value<'a>>),
    /// An object, as its members: each name and its value. The decoder gives them in increasing bytewise order of
    /// the UTF-8 of their names, so a binary search finds a name. It does not keep the order of the input.
    Object(Vec<(Cow<'a, str>, Value<'a>)>),
}

/// The debug output of a string: only its length.
struct Length<'a>(&'a str);

impl fmt::Debug for Length<'_> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("String").field("len", &self.0.len()).finish()
    }
}

// A string can hold a challenge, a token, or a key. Thus the output shows the structure, the numbers, and only the
// length of each string and member name.
impl fmt::Debug for Value<'_> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Null => f.write_str("Null"),
            Self::Bool(b) => f.debug_tuple("Bool").field(b).finish(),
            Self::Number(text) => f.debug_tuple("Number").field(text).finish(),
            Self::String(text) => Length(text).fmt(f),
            Self::Array(items) => f.debug_list().entries(items).finish(),
            Self::Object(members) => f
                .debug_map()
                .entries(members.iter().map(|(name, value)| (Length(name), value)))
                .finish(),
        }
    }
}

/// The cause of a refusal. For each refusal, the recovery is to refuse the message that holds the input.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Error {
    /// The text is larger than a bound of [`Limits`](crate::limits::Limits).
    Limit(Limit),
    /// The input ends in the value.
    Truncated,
    /// Bytes other than whitespace follow the value.
    TrailingBytes,
    /// The input is not in the grammar of RFC 8259, or it is not UTF-8.
    Malformed,
    /// An escape gives a lone surrogate: a high surrogate with no low surrogate after it, or a low surrogate with no
    /// high surrogate before it.
    LoneSurrogate,
    /// An object has two members with equal names.
    DuplicateMember,
}

impl fmt::Display for Error {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(match self {
            Self::Limit(Limit::Bytes) => "the JSON text has too many bytes",
            Self::Limit(Limit::Depth) => "the JSON text has too many nested levels",
            Self::Limit(Limit::Items) => "the JSON text has too many values and member names",
            Self::Limit(Limit::MapKeys) => "a JSON object has too many members",
            Self::Limit(Limit::StringBytes) => "a JSON string has too many bytes",
            Self::Limit(Limit::Dependencies | Limit::Intents | Limit::SignatureChecks) => {
                "the JSON text is larger than a bound of the limits"
            }
            Self::Truncated => "the JSON input ends in the value",
            Self::TrailingBytes => "bytes follow the JSON value",
            Self::Malformed => "the input is not RFC 8259 JSON in UTF-8",
            Self::LoneSurrogate => "a JSON escape gives a lone surrogate",
            Self::DuplicateMember => "a JSON object has two members with equal names",
        })
    }
}

impl core::error::Error for Error {}
