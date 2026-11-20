//! The encoder of the deterministic encoding (RFC 8949 section 4.2.1).

use alloc::vec::Vec;

use super::float::{self, DOUBLE, HALF, SINGLE};
use super::{Error, Value};
use crate::limits::{Limit, Limits};

/// Encodes `value` in the deterministic encoding of RFC 8949 section 4.2.1, within `limits`. It writes each map in
/// increasing bytewise order of the key encodings, whatever the order of the entries in `value`. [`super::decode`]
/// accepts the result and gives an equal value.
///
/// Cost class: [`Parse`](crate::limits::Class::Parse).
///
/// The encoder applies each bound of `limits` that [`super::decode`] applies, and it refuses at the same bound. Thus
/// a value encodes within `limits` if and only if its encoding decodes within `limits`. It checks each bound before
/// it writes the item, and its recursion is at most [`Limits::depth`] levels, so a value from a caller costs bounded
/// work and stack.
///
/// # Errors
///
/// Returns [`Error::Limit`] with the bound that refuses the value. Returns [`Error::DuplicateKey`] if a map has two
/// equal keys. Returns [`Error::Malformed`] for [`Value::Simple`] with 20 to 22, which are [`Value::Bool`] and
/// [`Value::Null`], or with 24 to 31, which have no encoding.
pub fn encode(value: &Value<'_>, limits: Limits) -> Result<Vec<u8>, Error> {
    let mut encoder = Encoder {
        limits,
        items: 0,
        bytes: 0,
    };
    encoder.admit(1)?;
    let mut out = Vec::new();
    encoder.write(value, 0, &mut out)?;
    Ok(out)
}

/// The start of the encoding of an array of `items` and one more item: the head of `items.len() + 1` items, and the
/// encoding of each item of `items`. The caller appends the encoding of the last item, for example a value of a caller
/// that [`encode`] bounded, so the array needs no copy of that value.
///
/// # Panics
///
/// If an item of `items` has no encoding: each caller gives typed values with no map and no simple value.
pub(crate) fn prefix(items: &[Value<'_>]) -> Vec<u8> {
    let mut out = Vec::new();
    head(&mut out, 4, items.len() as u64 + 1);
    for item in items {
        out.extend(encode(item, Limits::FORM).expect("each item of a prefix is a typed value with no map"));
    }
    out
}

/// The counts of one encode, which [`Limits`] bounds.
struct Encoder {
    limits: Limits,
    /// The data items that the encoder admitted. It admits the items of an array or a map at its head, as the decoder
    /// does.
    items: usize,
    /// The bytes that the encoder wrote, also into the buffer of a map.
    bytes: usize,
}

impl Encoder {
    fn admit(&mut self, items: usize) -> Result<(), Error> {
        self.items = self
            .items
            .checked_add(items)
            .filter(|&total| total <= self.limits.items)
            .ok_or(Error::Limit(Limit::Items))?;
        Ok(())
    }

    /// Charges `len` bytes before the encoder writes them.
    fn charge(&mut self, len: usize) -> Result<(), Error> {
        self.bytes = self
            .bytes
            .checked_add(len)
            .filter(|&total| total <= self.limits.bytes)
            .ok_or(Error::Limit(Limit::Bytes))?;
        Ok(())
    }

    /// Writes the head of major type `major` with the shortest form of `arg`, after it charges its bytes.
    fn head(&mut self, out: &mut Vec<u8>, major: u8, arg: u64) -> Result<(), Error> {
        self.charge(head_len(arg))?;
        head(out, major, arg);
        Ok(())
    }

    /// Writes the string `bytes` of major type `major`.
    fn string(&mut self, out: &mut Vec<u8>, major: u8, bytes: &[u8]) -> Result<(), Error> {
        (bytes.len() <= self.limits.string_bytes).ok_or(Error::Limit(Limit::StringBytes))?;
        self.head(out, major, bytes.len() as u64)?;
        self.charge(bytes.len())?;
        out.extend_from_slice(bytes);
        Ok(())
    }

    /// Writes `value`. `depth` is the number of arrays, maps, and tags around it.
    fn write(&mut self, value: &Value<'_>, depth: u8, out: &mut Vec<u8>) -> Result<(), Error> {
        if matches!(value, Value::Array(_) | Value::Map(_) | Value::Tag(..)) && depth >= self.limits.depth {
            return Err(Error::Limit(Limit::Depth));
        }
        match value {
            Value::Unsigned(n) => self.head(out, 0, *n)?,
            Value::Negative(n) => self.head(out, 1, *n)?,
            Value::Bytes(bytes) => self.string(out, 2, bytes)?,
            Value::Text(text) => self.string(out, 3, text.as_bytes())?,
            Value::Array(items) => {
                self.admit(items.len())?;
                self.head(out, 4, items.len() as u64)?;
                for item in items {
                    self.write(item, depth + 1, out)?;
                }
            }
            Value::Map(entries) => self.map(entries, depth + 1, out)?,
            Value::Tag(tag, item) => {
                self.admit(1)?;
                self.head(out, 6, *tag)?;
                self.write(item, depth + 1, out)?;
            }
            Value::Bool(false) => self.simple(out, 0xf4)?,
            Value::Bool(true) => self.simple(out, 0xf5)?,
            Value::Null => self.simple(out, 0xf6)?,
            Value::Simple(20..=22 | 24..=31) => return Err(Error::Malformed),
            Value::Simple(n) => self.head(out, 7, u64::from(*n))?,
            Value::Float(x) => {
                let bits = x.to_bits();
                let (info, size, bits) = match float::narrow(bits, DOUBLE, SINGLE) {
                    None => (27, 8, bits),
                    Some(single) => match float::narrow(single, SINGLE, HALF) {
                        None => (26, 4, single),
                        Some(half) => (25, 2, half),
                    },
                };
                self.charge(1 + size)?;
                put(out, 0xe0 | info, bits, size);
            }
        }
        Ok(())
    }

    /// Writes the one-byte simple value `byte`.
    fn simple(&mut self, out: &mut Vec<u8>, byte: u8) -> Result<(), Error> {
        self.charge(1)?;
        out.push(byte);
        Ok(())
    }

    /// Writes a map with its entries in increasing bytewise order of the key encodings. `depth` is the depth of its
    /// keys and values.
    fn map(&mut self, entries: &[(Value<'_>, Value<'_>)], depth: u8, out: &mut Vec<u8>) -> Result<(), Error> {
        (entries.len() <= self.limits.map_keys).ok_or(Error::Limit(Limit::MapKeys))?;
        self.admit(entries.len().checked_mul(2).ok_or(Error::Limit(Limit::Items))?)?;
        self.head(out, 5, entries.len() as u64)?;
        let mut encoded = Vec::new();
        // The start of each entry in `encoded`, the end of its key, and the end of its value.
        let mut spans = Vec::with_capacity(entries.len());
        for (key, value) in entries {
            let start = encoded.len();
            self.write(key, depth, &mut encoded)?;
            let key_end = encoded.len();
            self.write(value, depth, &mut encoded)?;
            spans.push((start, key_end, encoded.len()));
        }
        let key = |&(start, key_end, _): &(usize, usize, usize)| &encoded[start..key_end];
        spans.sort_unstable_by(|a, b| key(a).cmp(key(b)));
        if spans.array_windows().any(|[a, b]| key(a) == key(b)) {
            return Err(Error::DuplicateKey);
        }
        // The writes into `encoded` charged these bytes.
        for &(start, _, end) in &spans {
            out.extend_from_slice(&encoded[start..end]);
        }
        Ok(())
    }
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
