//! Base64url with no padding ([RFC 4648, section 5]): the one base64url codec for WebAuthn, JOSE, and OAuth.
//!
//! [`decode`] accepts only the canonical text: no padding, only the 64 characters of the base64url alphabet, a
//! length that an encoding can have, and zero bits after the last decoded byte. Thus each byte string has one text,
//! and [`encode`] writes it.
//!
//! The time of each function depends only on the lengths of its input and output, not on the bytes. The functions
//! map each character and each 6-bit value with arithmetic, and they use no branch and no table on the data. Thus a
//! secret, such as a key or a session identifier, can go through them. The functions write into a slice of the
//! caller, so they allocate no memory.
//!
//! ```
//! use rsauthnz::b64;
//!
//! let text = b"-_-_";
//! let mut bytes = [0; 3];
//! assert_eq!(b64::decode(text, &mut bytes)?, [0xfb, 0xff, 0xbf]);
//! let mut encoded = [0; 4];
//! assert_eq!(b64::encode(&bytes, &mut encoded)?, text);
//! # Ok::<(), b64::Error>(())
//! ```
//!
//! [RFC 4648, section 5]: https://www.rfc-editor.org/rfc/rfc4648#section-5

use core::fmt;

/// The cause of a refusal. For a refusal of the text, the recovery is to refuse the message that holds it.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Error {
    /// The text has 4n + 1 characters, and no encoding has that length.
    Length,
    /// A byte of the text is not in the base64url alphabet. The padding character `=` is not in the alphabet.
    Malformed,
    /// The last character has bits that no decoded byte holds, and they are not zero. Thus the text is not the
    /// canonical encoding of its bytes.
    TrailingBits,
    /// The output slice of the caller is shorter than the result. The recovery is a slice of the length that
    /// [`decoded_len`] or [`encoded_len`] gives.
    ShortOutput,
}

impl fmt::Display for Error {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(match self {
            Self::Length => "the base64url text has an impossible length",
            Self::Malformed => "a byte of the base64url text is not in the alphabet",
            Self::TrailingBits => "the base64url text has nonzero bits after its last byte",
            Self::ShortOutput => "the output slice is shorter than the result",
        })
    }
}

impl core::error::Error for Error {}

/// Gives the number of bytes that `text` decodes to.
///
/// Cost class: [`Parse`](crate::limits::Class::Parse).
///
/// # Errors
///
/// Returns [`Error::Length`] if `text` has 4n + 1 bytes.
pub const fn decoded_len(text: &[u8]) -> Result<usize, Error> {
    match text.len() % 4 {
        1 => Err(Error::Length),
        rest => Ok(text.len() / 4 * 3 + rest.saturating_sub(1)),
    }
}

/// Gives the number of characters of the text of `bytes`.
///
/// Cost class: [`Parse`](crate::limits::Class::Parse).
pub const fn encoded_len(bytes: &[u8]) -> usize {
    // A slice has at most `isize::MAX` bytes, so the result cannot overflow.
    bytes.len() / 3 * 4
        + match bytes.len() % 3 {
            0 => 0,
            rest => rest + 1,
        }
}

/// Decodes the canonical base64url text `text` into the start of `out`, and gives the decoded bytes.
///
/// Cost class: [`Parse`](crate::limits::Class::Parse).
///
/// # Errors
///
/// Returns [`Error::Length`] if `text` has 4n + 1 bytes, and [`Error::ShortOutput`] if `out` is shorter than
/// [`decoded_len`]. Returns [`Error::Malformed`] if a byte of `text` is not in the base64url alphabet, and
/// [`Error::TrailingBits`] if the last character has nonzero bits after the last byte. These two refusals come after
/// the decoder reads all of `text`, so their time does not show which byte refused.
pub fn decode<'a>(text: &[u8], out: &'a mut [u8]) -> Result<&'a [u8], Error> {
    let out = out.get_mut(..decoded_len(text)?).ok_or(Error::ShortOutput)?;
    let (blocks, rest) = text.as_chunks::<4>();
    let (chunks, tail) = out.as_chunks_mut::<3>();
    // A value that is not a sextet is -1, so it sets the sign bit of `invalid`.
    let mut invalid = 0;
    for (&block, chunk) in blocks.iter().zip(chunks) {
        let values;
        (*chunk, values) = decode_block(block);
        invalid |= values;
    }
    let mut trailing = 0;
    if !rest.is_empty() {
        // The two or three last characters, then 'A', which is zero, in place of the characters that are not there.
        let mut block = [b'A'; 4];
        block[..rest.len()].copy_from_slice(rest);
        let (bytes, values) = decode_block(block);
        invalid |= values;
        tail.copy_from_slice(&bytes[..tail.len()]);
        trailing = bytes[tail.len()..].iter().fold(0, |bits, &byte| bits | byte);
    }
    if invalid < 0 {
        Err(Error::Malformed)
    } else if trailing != 0 {
        Err(Error::TrailingBits)
    } else {
        Ok(out)
    }
}

/// Encodes `bytes` into the start of `out`, and gives the base64url text. The text is ASCII, so
/// `core::str::from_utf8` cannot fail on it.
///
/// Cost class: [`Parse`](crate::limits::Class::Parse).
///
/// # Errors
///
/// Returns [`Error::ShortOutput`] if `out` is shorter than [`encoded_len`].
pub fn encode<'a>(bytes: &[u8], out: &'a mut [u8]) -> Result<&'a [u8], Error> {
    let out = out.get_mut(..encoded_len(bytes)).ok_or(Error::ShortOutput)?;
    let (blocks, rest) = bytes.as_chunks::<3>();
    let (chunks, tail) = out.as_chunks_mut::<4>();
    for (&block, chunk) in blocks.iter().zip(chunks) {
        *chunk = encode_block(block);
    }
    if !rest.is_empty() {
        let mut block = [0; 3];
        block[..rest.len()].copy_from_slice(rest);
        tail.copy_from_slice(&encode_block(block)[..tail.len()]);
    }
    Ok(out)
}

/// The sextet (6-bit value) of a base64url character, or -1 for a byte outside the alphabet. Each term is the sextet
/// plus one in the range of its characters, and zero outside it.
///
/// Each value is in -256..=255, so no operation overflows. The wrapping operations add no overflow check, which is a
/// branch on the data.
#[inline(always)]
fn sextet(byte: u8) -> i16 {
    let c = i16::from(byte);
    (-1_i16)
        .wrapping_add(in_range(c, b'A', b'Z', c.wrapping_sub(64)))
        .wrapping_add(in_range(c, b'a', b'z', c.wrapping_sub(70)))
        .wrapping_add(in_range(c, b'0', b'9', c.wrapping_add(5)))
        .wrapping_add(in_range(c, b'-', b'-', 63))
        .wrapping_add(in_range(c, b'_', b'_', 64))
}

/// `plus` if `lo <= c <= hi`, and zero if not. `(lo - 1 - c) & (c - hi - 1)` is negative only in the range, so its
/// shift right by 8 is -1 in the range and 0 outside it.
#[inline(always)]
fn in_range(c: i16, lo: u8, hi: u8, plus: i16) -> i16 {
    ((i16::from(lo) - 1).wrapping_sub(c) & c.wrapping_sub(i16::from(hi) + 1)) >> 8 & plus
}

/// The three bytes of four base64url characters, and the OR of their sextets, which is negative if a character is
/// outside the alphabet.
#[inline(always)]
fn decode_block(block: [u8; 4]) -> ([u8; 3], i16) {
    // Four calls, not `array::map`, which the compiler does not always inline.
    let [a, b, c, d] = [sextet(block[0]), sextet(block[1]), sextet(block[2]), sextet(block[3])];
    (
        [low(a << 2 | b >> 4), low(b << 4 | c >> 2), low(c << 6 | d)],
        a | b | c | d,
    )
}

/// The four base64url characters of three bytes.
#[inline(always)]
fn encode_block(block: [u8; 3]) -> [u8; 4] {
    let [a, b, c] = [i16::from(block[0]), i16::from(block[1]), i16::from(block[2])];
    [
        symbol(a >> 2),
        symbol((a << 4 | b >> 4) & 63),
        symbol((b << 2 | c >> 6) & 63),
        symbol(c & 63),
    ]
}

/// The base64url character of a sextet. Each term adds the distance to the next range of the alphabet if `value` is
/// past the last sextet of the range before it. Each value is in -128..=127, so no operation overflows, and the
/// wrapping operations add no overflow check.
#[inline(always)]
fn symbol(value: i16) -> u8 {
    let symbol = value
        .wrapping_add(i16::from(b'A'))
        .wrapping_add(past(value, 25, 6))
        .wrapping_add(past(value, 51, -75))
        .wrapping_add(past(value, 61, -13))
        .wrapping_add(past(value, 62, 49));
    low(symbol)
}

/// `plus` if `value` is past `last`, and zero if not: `(last - value) >> 8` is -1 past it and 0 up to it.
#[inline(always)]
fn past(value: i16, last: i16, plus: i16) -> i16 {
    (last.wrapping_sub(value) >> 8) & plus
}

/// The low byte of a value.
#[inline(always)]
fn low(value: i16) -> u8 {
    value.to_le_bytes()[0]
}
