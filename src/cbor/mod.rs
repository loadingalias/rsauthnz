//! Bounded canonical CBOR ([RFC 8949]): the one CBOR codec for WebAuthn, COSE, and CWT.
//!
//! [`decode`] accepts only the deterministic encoding of RFC 8949 section 4.2.1. Each head argument and each float
//! has its shortest form, each length is definite, and map keys increase in bytewise order of their encodings.
//! Thus each value has one encoding, and the signed bytes of a structure have one meaning. [`encode`] writes that
//! encoding.
//!
//! The decoder checks the whole item against the [`Limits`] of the caller before it builds the value. Thus a
//! refused input allocates no memory, and the work is linear in the input. Byte and text strings borrow the input.
//!
//! ```
//! use rsauthnz::cbor::{self, Limits, Value};
//!
//! // {1: 2, 3: -7}: the key type and the algorithm of a COSE key.
//! let bytes = [0xa2, 0x01, 0x02, 0x03, 0x26];
//! let limits = Limits { string_bytes: 4096, ..Limits::default() };
//! let value = cbor::decode(&bytes, limits)?;
//! assert_eq!(
//!     value,
//!     Value::Map(vec![
//!         (Value::Unsigned(1), Value::Unsigned(2)),
//!         (Value::Unsigned(3), Value::Negative(6)),
//!     ])
//! );
//! assert_eq!(cbor::encode(&value)?, bytes);
//! # Ok::<(), cbor::Error>(())
//! ```
//!
//! [RFC 8949]: https://www.rfc-editor.org/rfc/rfc8949

mod decode;
mod encode;
mod float;

use alloc::boxed::Box;
use alloc::vec::Vec;
use core::fmt;

pub use decode::{decode, decode_prefix};
pub use encode::encode;
pub(crate) use encode::{head, head_len};

/// A CBOR data item. Byte and text strings borrow the decoded input.
///
/// Each item has one value: false, true, and null have their own variants, and [`Value::Simple`] holds only the
/// other simple values. Floats compare as `f64` values, so a NaN is not equal to itself.
#[derive(Clone, PartialEq)]
pub enum Value<'a> {
    /// An unsigned integer (major type 0).
    Unsigned(u64),
    /// The negative integer `-1 - n` (major type 1). Thus `Negative(0)` is -1.
    Negative(u64),
    /// A byte string (major type 2).
    Bytes(&'a [u8]),
    /// A text string (major type 3).
    Text(&'a str),
    /// An array (major type 4).
    Array(Vec<Value<'a>>),
    /// A map (major type 5), as its key and value pairs. The decoder gives them in increasing bytewise order of the
    /// key encodings.
    Map(Vec<(Value<'a>, Value<'a>)>),
    /// A tag number and the item that it tags (major type 6).
    Tag(u64, Box<Value<'a>>),
    /// `false` or `true`.
    Bool(bool),
    /// `null`.
    Null,
    /// A simple value other than false, true, and null: 0 to 19, 23 (undefined), or 32 to 255.
    Simple(u8),
    /// A float. The encoder writes the shortest of the half, single, and double formats that keeps its bits.
    Float(f64),
}

// A string can hold a credential, a challenge, or a key. Thus the output shows the structure, the numbers, and
// only the length of each string.
impl fmt::Debug for Value<'_> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Unsigned(n) => f.debug_tuple("Unsigned").field(n).finish(),
            Self::Negative(n) => f.debug_tuple("Negative").field(n).finish(),
            Self::Bytes(bytes) => f.debug_struct("Bytes").field("len", &bytes.len()).finish(),
            Self::Text(text) => f.debug_struct("Text").field("len", &text.len()).finish(),
            Self::Array(items) => f.debug_list().entries(items).finish(),
            Self::Map(entries) => f
                .debug_map()
                .entries(entries.iter().map(|(key, value)| (key, value)))
                .finish(),
            Self::Tag(tag, item) => f.debug_tuple("Tag").field(tag).field(item).finish(),
            Self::Bool(b) => f.debug_tuple("Bool").field(b).finish(),
            Self::Null => f.write_str("Null"),
            Self::Simple(n) => f.debug_tuple("Simple").field(n).finish(),
            Self::Float(x) => f.debug_tuple("Float").field(x).finish(),
        }
    }
}

/// The bounds of one decode. [`Error::Limit`] names the bound that refused an input.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Limits {
    /// The most bytes in the encoded item. The default is 65,536.
    pub bytes: usize,
    /// The most levels of nested arrays, maps, and tags. Each array, map, or tag adds one level. The default is 16.
    /// The type keeps the recursion of the decoder at 255 levels or fewer.
    pub depth: u8,
    /// The most data items. Each item counts: the outer item, and each array element, map key, map value, and
    /// tagged item. The default is 1,024.
    pub items: usize,
    /// The most keys in one map. The default is 64.
    pub map_keys: usize,
    /// The most bytes in one byte or text string. The default is 16,384.
    pub string_bytes: usize,
}

impl Default for Limits {
    fn default() -> Self {
        Self {
            bytes: 65_536,
            depth: 16,
            items: 1_024,
            map_keys: 64,
            string_bytes: 16_384,
        }
    }
}

/// A bound of [`Limits`].
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Limit {
    /// [`Limits::bytes`].
    Bytes,
    /// [`Limits::depth`].
    Depth,
    /// [`Limits::items`].
    Items,
    /// [`Limits::map_keys`].
    MapKeys,
    /// [`Limits::string_bytes`].
    StringBytes,
}

/// The cause of a refusal. For each decode refusal, the recovery is to refuse the message that holds the input.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Error {
    /// The item is larger than a bound of [`Limits`].
    Limit(Limit),
    /// The input ends in the item.
    Truncated,
    /// Bytes follow the item.
    TrailingBytes,
    /// The item is not well-formed CBOR, or a text string in it is not UTF-8. A head that is not well-formed has a
    /// reserved value, a break code outside an indefinite-length item, or a two-byte simple value less than 32.
    /// [`encode`] also returns it for a [`Value::Simple`] that has no encoding.
    Malformed,
    /// An item has an indefinite length.
    IndefiniteLength,
    /// A head argument or a float has a longer form than its shortest form.
    NonShortest,
    /// A map key is before the key that precedes it, in bytewise order of their encodings.
    KeyOrder,
    /// A map has two equal keys.
    DuplicateKey,
}

impl fmt::Display for Error {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(match self {
            Self::Limit(Limit::Bytes) => "the CBOR item has too many bytes",
            Self::Limit(Limit::Depth) => "the CBOR item has too many nested levels",
            Self::Limit(Limit::Items) => "the CBOR item has too many data items",
            Self::Limit(Limit::MapKeys) => "a CBOR map has too many keys",
            Self::Limit(Limit::StringBytes) => "a CBOR string has too many bytes",
            Self::Truncated => "the CBOR input ends in the item",
            Self::TrailingBytes => "bytes follow the CBOR item",
            Self::Malformed => "the CBOR item is not well-formed, or its text is not UTF-8",
            Self::IndefiniteLength => "a CBOR item has an indefinite length",
            Self::NonShortest => "a CBOR head or float is not in its shortest form",
            Self::KeyOrder => "the CBOR map keys are not in deterministic order",
            Self::DuplicateKey => "a CBOR map has two equal keys",
        })
    }
}

impl core::error::Error for Error {}
