//! The decoder. A check pass reads the whole item and makes each refusal. Then a build pass makes the value, which
//! is the only step that allocates.

use alloc::boxed::Box;
use alloc::vec::Vec;
use core::cmp::Ordering;

use super::float::{self, DOUBLE, HALF, SINGLE};
use super::{Error, Limit, Limits, Value};

/// Decodes the one CBOR item that fills `input`.
///
/// # Errors
///
/// Returns [`Error::Limit`] with [`Limit::Bytes`] before it reads a byte if `input` is longer than
/// [`Limits::bytes`]. Returns [`Error::TrailingBytes`] if bytes follow the item. Returns each other refusal of
/// [`decode_prefix`]. A refusal allocates no memory.
pub fn decode(input: &[u8], limits: Limits) -> Result<Value<'_>, Error> {
    if input.len() > limits.bytes {
        return Err(Error::Limit(Limit::Bytes));
    }
    let (item, rest) = check(input, limits)?;
    if !rest.is_empty() {
        return Err(Error::TrailingBytes);
    }
    Reader::new(item).build()
}

/// Decodes the CBOR item at the start of `input`, and gives the bytes after it. Use it when other data follows the
/// item, as the extensions follow the credential public key in WebAuthn authenticator data.
///
/// # Errors
///
/// Returns [`Error::Limit`] if the item is larger than a bound of `limits`. [`Limits::bytes`] bounds the item, not
/// `input`. Returns [`Error::Truncated`] if `input` ends in the item, and [`Error::Malformed`] if the item is not
/// well-formed or has a text string that is not UTF-8. Returns [`Error::IndefiniteLength`], [`Error::NonShortest`], [`Error::KeyOrder`], or
/// [`Error::DuplicateKey`] if the item is well-formed but not in deterministic encoding. A refusal allocates no
/// memory.
pub fn decode_prefix(input: &[u8], limits: Limits) -> Result<(Value<'_>, &[u8]), Error> {
    let (item, rest) = check(input, limits)?;
    Ok((Reader::new(item).build()?, rest))
}

/// Checks the item at the start of `input`, and splits `input` after the item. It allocates nothing.
fn check(input: &[u8], limits: Limits) -> Result<(&[u8], &[u8]), Error> {
    let window = input.get(..limits.bytes).unwrap_or(input);
    let mut checker = Checker {
        reader: Reader {
            input: window,
            pos: 0,
            cut: window.len() < input.len(),
        },
        limits,
        items: 0,
    };
    checker.admit(1)?;
    checker.check(0)?;
    Ok(input.split_at(checker.reader.pos))
}

/// The initial byte of a data item, in its two fields, and the argument that follows it (RFC 8949 section 3).
struct Head {
    major: u8,
    info: u8,
    arg: u64,
}

/// A cursor in the bytes of one item.
struct Reader<'a> {
    input: &'a [u8],
    pos: usize,
    /// [`Limits::bytes`] cut `input` from a longer input.
    cut: bool,
}

impl<'a> Reader<'a> {
    const fn new(input: &'a [u8]) -> Self {
        Self {
            input,
            pos: 0,
            cut: false,
        }
    }

    /// The refusal of a read past the end of `input`.
    const fn end(&self) -> Error {
        if self.cut {
            Error::Limit(Limit::Bytes)
        } else {
            Error::Truncated
        }
    }

    const fn remaining(&self) -> usize {
        self.input.len() - self.pos
    }

    fn take(&mut self, len: usize) -> Result<&'a [u8], Error> {
        let bytes = self
            .pos
            .checked_add(len)
            .and_then(|end| self.input.get(self.pos..end))
            .ok_or_else(|| self.end())?;
        self.pos += len;
        Ok(bytes)
    }

    /// Reads a head. It refuses a head that is not well-formed, an indefinite length, and an argument that is not in
    /// its shortest form.
    fn head(&mut self) -> Result<Head, Error> {
        let initial = self.take(1)?[0];
        let (major, info) = (initial >> 5, initial & 0x1f);
        let size = match info {
            0..=23 => 0,
            24 => 1,
            25 => 2,
            26 => 4,
            27 => 8,
            31 if (2..=5).contains(&major) => return Err(Error::IndefiniteLength),
            // Reserved values, and 31 on an integer, a tag, or a break code outside an indefinite-length item.
            _ => return Err(Error::Malformed),
        };
        let arg = match size {
            0 => u64::from(info),
            _ => self.take(size)?.iter().fold(0, |arg, &byte| arg << 8 | u64::from(byte)),
        };
        if major == 7 {
            // Floats have their own check. A simple value in two bytes is 32 or more.
            if size == 1 && arg < 32 {
                return Err(Error::Malformed);
            }
        } else if (size == 1 && arg < 24) || (size > 1 && arg >> (4 * size) == 0) {
            // A shorter argument holds the value: one byte holds 24 to 255, and each other size holds the values
            // that need more than half of its bytes.
            return Err(Error::NonShortest);
        }
        Ok(Head { major, info, arg })
    }

    /// Builds the value of an item that the check pass admitted.
    fn build(&mut self) -> Result<Value<'a>, Error> {
        let head = self.head()?;
        Ok(match head.major {
            0 => Value::Unsigned(head.arg),
            1 => Value::Negative(head.arg),
            2 => Value::Bytes(self.take(length(head.arg)?)?),
            3 => Value::Text(text(self.take(length(head.arg)?)?)?),
            4 => {
                let len = length(head.arg)?;
                let mut items = Vec::with_capacity(len);
                for _ in 0..len {
                    items.push(self.build()?);
                }
                Value::Array(items)
            }
            5 => {
                let len = length(head.arg)?;
                let mut entries = Vec::with_capacity(len);
                for _ in 0..len {
                    entries.push((self.build()?, self.build()?));
                }
                Value::Map(entries)
            }
            6 => Value::Tag(head.arg, Box::new(self.build()?)),
            _ => match head.info {
                20 => Value::Bool(false),
                21 => Value::Bool(true),
                22 => Value::Null,
                25 => Value::Float(f64::from_bits(float::widen(head.arg, HALF, DOUBLE))),
                26 => Value::Float(f64::from_bits(float::widen(head.arg, SINGLE, DOUBLE))),
                27 => Value::Float(f64::from_bits(head.arg)),
                _ => Value::Simple(u8::try_from(head.arg).map_err(|_| Error::Malformed)?),
            },
        })
    }
}

/// The check pass: it reads the item and makes each refusal, and it allocates nothing.
struct Checker<'a> {
    reader: Reader<'a>,
    limits: Limits,
    /// The data items that the pass admitted. It admits the items of an array or a map at its head.
    items: usize,
}

impl Checker<'_> {
    fn admit(&mut self, items: usize) -> Result<(), Error> {
        self.items = self
            .items
            .checked_add(items)
            .filter(|&total| total <= self.limits.items)
            .ok_or(Error::Limit(Limit::Items))?;
        Ok(())
    }

    /// Admits the items in an array or a map before it reads them. Each item has at least one byte.
    fn admit_contents(&mut self, items: usize) -> Result<(), Error> {
        self.admit(items)?;
        if items > self.reader.remaining() {
            return Err(self.reader.end());
        }
        Ok(())
    }

    /// Checks one item and the items in it. `depth` is the number of arrays, maps, and tags around it.
    fn check(&mut self, depth: u8) -> Result<(), Error> {
        let head = self.reader.head()?;
        match head.major {
            2 | 3 => {
                let len = bounded(head.arg, self.limits.string_bytes, Limit::StringBytes)?;
                let bytes = self.reader.take(len)?;
                if head.major == 3 {
                    text(bytes)?;
                }
            }
            4..=6 => {
                if depth >= self.limits.depth {
                    return Err(Error::Limit(Limit::Depth));
                }
                let depth = depth + 1;
                match head.major {
                    4 => {
                        let len = bounded(head.arg, self.limits.items, Limit::Items)?;
                        self.admit_contents(len)?;
                        for _ in 0..len {
                            self.check(depth)?;
                        }
                    }
                    5 => self.check_map(head.arg, depth)?,
                    _ => {
                        self.admit(1)?;
                        self.check(depth)?;
                    }
                }
            }
            7 => match head.info {
                26 if float::narrow(head.arg, SINGLE, HALF).is_some() => return Err(Error::NonShortest),
                27 if float::narrow(head.arg, DOUBLE, SINGLE).is_some() => return Err(Error::NonShortest),
                _ => {}
            },
            _ => {}
        }
        Ok(())
    }

    /// Checks a map with `arg` entries. Its keys must increase in bytewise order of their encodings. In
    /// deterministic encoding, two keys are equal only if their encodings are equal.
    fn check_map(&mut self, arg: u64, depth: u8) -> Result<(), Error> {
        let len = bounded(arg, self.limits.map_keys, Limit::MapKeys)?;
        self.admit_contents(len.checked_mul(2).ok_or(Error::Limit(Limit::Items))?)?;
        let input = self.reader.input;
        // The empty slice is before each key, because each key has at least one byte.
        let mut previous: &[u8] = &[];
        for _ in 0..len {
            let start = self.reader.pos;
            self.check(depth)?;
            let key = &input[start..self.reader.pos];
            match previous.cmp(key) {
                Ordering::Less => previous = key,
                Ordering::Equal => return Err(Error::DuplicateKey),
                Ordering::Greater => return Err(Error::KeyOrder),
            }
            self.check(depth)?;
        }
        Ok(())
    }
}

/// Converts a declared length or count `arg` that must not be more than `limit`.
fn bounded(arg: u64, limit: usize, kind: Limit) -> Result<usize, Error> {
    usize::try_from(arg)
        .ok()
        .filter(|&len| len <= limit)
        .ok_or(Error::Limit(kind))
}

/// Converts a length that the check pass admitted.
fn length(arg: u64) -> Result<usize, Error> {
    usize::try_from(arg).map_err(|_| Error::Malformed)
}

fn text(bytes: &[u8]) -> Result<&str, Error> {
    core::str::from_utf8(bytes).map_err(|_| Error::Malformed)
}
