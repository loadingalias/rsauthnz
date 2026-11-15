//! The encoder of the deterministic encoding (RFC 8949 section 4.2.1).

use alloc::vec::Vec;

use super::float::{self, DOUBLE, HALF, SINGLE};
use super::{Error, Value};

/// Encodes `value` in the deterministic encoding of RFC 8949 section 4.2.1. It writes each map in increasing
/// bytewise order of the key encodings, whatever the order of the entries in `value`. [`super::decode`] accepts
/// the result and gives an equal value.
///
/// # Errors
///
/// Returns [`Error::DuplicateKey`] if a map has two equal keys. Returns [`Error::Malformed`] for
/// [`Value::Simple`] with 20 to 22, which are [`Value::Bool`] and [`Value::Null`], or with 24 to 31, which have
/// no encoding.
pub fn encode(value: &Value<'_>) -> Result<Vec<u8>, Error> {
    let mut out = Vec::new();
    write(value, &mut out)?;
    Ok(out)
}

fn write(value: &Value<'_>, out: &mut Vec<u8>) -> Result<(), Error> {
    match value {
        Value::Unsigned(n) => head(out, 0, *n),
        Value::Negative(n) => head(out, 1, *n),
        Value::Bytes(bytes) => {
            head(out, 2, bytes.len() as u64);
            out.extend_from_slice(bytes);
        }
        Value::Text(text) => {
            head(out, 3, text.len() as u64);
            out.extend_from_slice(text.as_bytes());
        }
        Value::Array(items) => {
            head(out, 4, items.len() as u64);
            for item in items {
                write(item, out)?;
            }
        }
        Value::Map(entries) => map(entries, out)?,
        Value::Tag(tag, item) => {
            head(out, 6, *tag);
            write(item, out)?;
        }
        Value::Bool(false) => out.push(0xf4),
        Value::Bool(true) => out.push(0xf5),
        Value::Null => out.push(0xf6),
        Value::Simple(20..=22 | 24..=31) => return Err(Error::Malformed),
        Value::Simple(n) => head(out, 7, u64::from(*n)),
        Value::Float(x) => {
            let bits = x.to_bits();
            let (info, size, bits) = match float::narrow(bits, DOUBLE, SINGLE) {
                None => (27, 8, bits),
                Some(single) => match float::narrow(single, SINGLE, HALF) {
                    None => (26, 4, single),
                    Some(half) => (25, 2, half),
                },
            };
            put(out, 0xe0 | info, bits, size);
        }
    }
    Ok(())
}

/// Writes the head of major type `major` with the shortest form of `arg`.
pub(crate) fn head(out: &mut Vec<u8>, major: u8, arg: u64) {
    let size = head_len(arg) - 1;
    let info = match size {
        // The low byte of `arg` is its value.
        0 => arg.to_be_bytes()[7],
        1 => 24,
        2 => 25,
        4 => 26,
        _ => 27,
    };
    put(out, major << 5 | info, arg, size);
}

/// The bytes of the head with the shortest form of `arg`: the initial byte, then 0, 1, 2, 4, or 8 argument bytes.
pub(crate) const fn head_len(arg: u64) -> usize {
    match arg {
        0..=23 => 1,
        24..=0xff => 2,
        0x100..=0xffff => 3,
        0x1_0000..=0xffff_ffff => 5,
        _ => 9,
    }
}

/// Writes the initial byte, then the low `size` bytes of `arg` with the most significant byte first.
fn put(out: &mut Vec<u8>, initial: u8, arg: u64, size: usize) {
    out.push(initial);
    out.extend_from_slice(&arg.to_be_bytes()[8 - size..]);
}

/// Writes a map with its entries in increasing bytewise order of the key encodings.
fn map(entries: &[(Value<'_>, Value<'_>)], out: &mut Vec<u8>) -> Result<(), Error> {
    head(out, 5, entries.len() as u64);
    let mut encoded = Vec::new();
    // The start of each entry in `encoded`, the end of its key, and the end of its value.
    let mut spans = Vec::with_capacity(entries.len());
    for (key, value) in entries {
        let start = encoded.len();
        write(key, &mut encoded)?;
        let key_end = encoded.len();
        write(value, &mut encoded)?;
        spans.push((start, key_end, encoded.len()));
    }
    let key = |&(start, key_end, _): &(usize, usize, usize)| &encoded[start..key_end];
    spans.sort_unstable_by(|a, b| key(a).cmp(key(b)));
    if spans.windows(2).any(|pair| key(&pair[0]) == key(&pair[1])) {
        return Err(Error::DuplicateKey);
    }
    for &(start, _, end) in &spans {
        out.extend_from_slice(&encoded[start..end]);
    }
    Ok(())
}
