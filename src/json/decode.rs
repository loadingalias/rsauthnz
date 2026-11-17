//! The decoder. A check pass reads the whole text and makes each refusal but one, and it allocates nothing. Then a
//! build pass makes the value, which is the only step that allocates, and it refuses two equal member names.

use alloc::borrow::Cow;
use alloc::string::String;
use alloc::vec::Vec;

use super::{Error, Value};
use crate::limits::{Limit, Limits};

/// Decodes the one JSON value that fills `input`. Whitespace can come before and after the value.
///
/// Cost class: [`Parse`](crate::limits::Class::Parse). The work is linear in the input. To find two equal names,
/// the build pass sorts the members of each object in place, which adds a factor of at most log2 of
/// [`Limits::map_keys`].
///
/// # Errors
///
/// Returns [`Error::Limit`] with [`Limit::Bytes`] before it reads a byte if `input` is longer than
/// [`Limits::bytes`], and with another [`Limit`] if the value is larger than that bound. Returns
/// [`Error::Malformed`] if the input is not UTF-8 or not in the grammar of RFC 8259, [`Error::Truncated`] if it ends
/// in the value, and [`Error::TrailingBytes`] if bytes other than whitespace follow the value. Returns
/// [`Error::LoneSurrogate`] if an escape gives a lone surrogate. These refusals come from the check pass, so they
/// allocate no memory. Returns [`Error::DuplicateMember`] if an object has two members with equal names. That
/// refusal comes from the build pass, so it can allocate only within the bounds that the check pass admitted.
pub fn decode(input: &[u8], limits: Limits) -> Result<Value<'_>, Error> {
    if input.len() > limits.bytes {
        return Err(Error::Limit(Limit::Bytes));
    }
    // Each byte outside a string is ASCII in the grammar, so this check of the whole input is the UTF-8 check of
    // the strings. The build pass borrows each string from `text`.
    let text = core::str::from_utf8(input).map_err(|_| Error::Malformed)?;
    let mut checker = Checker {
        cursor: Cursor::new(input),
        limits,
        items: 0,
    };
    checker.value(0)?;
    if checker.cursor.skip_whitespace().is_some() {
        return Err(Error::TrailingBytes);
    }
    Builder {
        cursor: Cursor::new(input),
        text,
    }
    .value()
}

/// A position in the input. The two passes read the input with its methods.
struct Cursor<'a> {
    input: &'a [u8],
    pos: usize,
}

impl<'a> Cursor<'a> {
    const fn new(input: &'a [u8]) -> Self {
        Self { input, pos: 0 }
    }

    /// Skips whitespace, and gives the byte after it with no move past it. It gives `None` at the end of the input.
    #[inline(always)]
    fn skip_whitespace(&mut self) -> Option<u8> {
        while let Some(&byte) = self.input.get(self.pos) {
            if !matches!(byte, b' ' | b'\t' | b'\n' | b'\r') {
                return Some(byte);
            }
            self.pos += 1;
        }
        None
    }

    #[inline(always)]
    fn peek(&self) -> Option<u8> {
        self.input.get(self.pos).copied()
    }

    /// Reads one byte.
    #[inline(always)]
    fn byte(&mut self) -> Result<u8, Error> {
        let byte = self.peek().ok_or(Error::Truncated)?;
        self.pos += 1;
        Ok(byte)
    }

    /// Skips whitespace, then reads one byte.
    #[inline(always)]
    fn token(&mut self) -> Result<u8, Error> {
        self.skip_whitespace().ok_or(Error::Truncated)?;
        self.byte()
    }

    /// Reads `true`, `false`, or `null`.
    fn literal(&mut self, word: &[u8]) -> Result<(), Error> {
        let rest = self.input.get(self.pos..).unwrap_or_default();
        if rest.starts_with(word) {
            self.pos += word.len();
            Ok(())
        } else if word.starts_with(rest) {
            Err(Error::Truncated)
        } else {
            Err(Error::Malformed)
        }
    }

    /// Reads the escape after a backslash, and gives the character that it stands for. A `\u` escape of a high
    /// surrogate must have a `\u` escape of a low surrogate after it, and the two give one character.
    fn escape(&mut self) -> Result<char, Error> {
        let unit = match self.byte()? {
            b'"' => return Ok('"'),
            b'\\' => return Ok('\\'),
            b'/' => return Ok('/'),
            b'b' => return Ok('\u{8}'),
            b'f' => return Ok('\u{c}'),
            b'n' => return Ok('\n'),
            b'r' => return Ok('\r'),
            b't' => return Ok('\t'),
            b'u' => self.hex()?,
            _ => return Err(Error::Malformed),
        };
        let code = match unit {
            0xd800..=0xdbff => {
                match self.input.get(self.pos..).unwrap_or_default() {
                    [b'\\', b'u', ..] => self.pos += 2,
                    // The input can end in the escape of the low surrogate.
                    [] | [b'\\'] => return Err(Error::Truncated),
                    _ => return Err(Error::LoneSurrogate),
                }
                let low = self.hex()?;
                (0xdc00..=0xdfff).contains(&low).ok_or(Error::LoneSurrogate)?;
                0x1_0000 + ((unit - 0xd800) << 10) + (low - 0xdc00)
            }
            _ => unit,
        };
        // Only a low surrogate is not a character here.
        char::from_u32(code).ok_or(Error::LoneSurrogate)
    }

    /// Reads the four hexadecimal digits of a `\u` escape.
    fn hex(&mut self) -> Result<u32, Error> {
        let mut unit = 0;
        for _ in 0..4 {
            let digit = char::from(self.byte()?).to_digit(16).ok_or(Error::Malformed)?;
            unit = unit << 4 | digit;
        }
        Ok(unit)
    }

    /// The length of the string at the cursor, if it has no escape and its quote is in the next eight bytes. The
    /// cursor is after the opening quote. Most member names and many values are this short, so the two passes read
    /// them with no call.
    #[inline(always)]
    fn short(&self) -> Option<usize> {
        let word = *self.input.get(self.pos..)?.first_chunk::<8>()?;
        let stops = stops(u64::from_le_bytes(word));
        let len = (stops.trailing_zeros() / 8) as usize;
        (stops != 0 && word[len] == b'"').then_some(len)
    }

    /// Moves to the next quote, backslash, or control character in a string, and gives it.
    #[inline(always)]
    fn plain(&mut self) -> Result<u8, Error> {
        let rest = self.input.get(self.pos..).unwrap_or_default();
        let len = run(rest).ok_or(Error::Truncated)?;
        self.pos += len;
        Ok(rest[len])
    }

    /// Gives the position of the quote that ends the string in which the cursor is. The check pass admitted the
    /// string, and in it each backslash starts an escape.
    fn string_end(&self) -> Result<usize, Error> {
        let mut pos = self.pos;
        loop {
            match self.input.get(pos) {
                Some(b'"') => return Ok(pos),
                Some(b'\\') => pos += 2,
                Some(_) => pos += 1,
                None => return Err(Error::Truncated),
            }
        }
    }
}

/// The number of bytes before the first quote, backslash, or control character in `rest`, which a string must
/// escape. It reads eight bytes at a time.
#[inline(always)]
fn run(rest: &[u8]) -> Option<usize> {
    let (words, tail) = rest.as_chunks::<8>();
    let first = |index: usize, word: [u8; 8]| {
        let stops = stops(u64::from_le_bytes(word));
        (stops != 0).then(|| index * 8 + (stops.trailing_zeros() / 8) as usize)
    };
    words
        .iter()
        .enumerate()
        .find_map(|(index, &word)| first(index, word))
        .or_else(|| {
            // The last bytes, then plain bytes to fill a word.
            let mut word = [b'a'; 8];
            word[..tail.len()].copy_from_slice(tail);
            first(words.len(), word)
        })
}

/// The high bit of each byte of `word` that is a quote, a backslash, or a control character. Only the lowest set bit
/// is exact: no byte below the first such byte borrows, and the bits above it can be wrong. The bytes are in
/// little-endian order, so the lowest set bit is in the first such byte.
#[inline(always)]
const fn stops(word: u64) -> u64 {
    const ONES: u64 = u64::from_ne_bytes([0x01; 8]);
    const HIGH: u64 = u64::from_ne_bytes([0x80; 8]);
    // The high bit of each byte of `x` that is less than its byte of `n`, if the byte has no high bit of its own.
    const fn less(x: u64, n: u64) -> u64 {
        x.wrapping_sub(n) & !x & HIGH
    }
    less(word ^ u64::from_ne_bytes([b'"'; 8]), ONES)
        | less(word ^ u64::from_ne_bytes([b'\\'; 8]), ONES)
        | less(word, u64::from_ne_bytes([0x20; 8]))
}

/// The check pass: it reads the value and makes each refusal but [`Error::DuplicateMember`], and it allocates
/// nothing.
struct Checker<'a> {
    cursor: Cursor<'a>,
    limits: Limits,
    /// The values and member names that the pass admitted.
    items: usize,
}

impl Checker<'_> {
    /// Admits one value or member name.
    fn admit(&mut self) -> Result<(), Error> {
        (self.items < self.limits.items).ok_or(Error::Limit(Limit::Items))?;
        self.items += 1;
        Ok(())
    }

    /// Checks the value after whitespace, and the values in it. `depth` is the number of arrays and objects around
    /// it.
    fn value(&mut self, depth: u8) -> Result<(), Error> {
        self.admit()?;
        match self.cursor.skip_whitespace().ok_or(Error::Truncated)? {
            b'"' => self.string(),
            b'[' | b'{' if depth >= self.limits.depth => Err(Error::Limit(Limit::Depth)),
            b'[' => self.array(depth + 1),
            b'{' => self.object(depth + 1),
            b't' => self.cursor.literal(b"true"),
            b'f' => self.cursor.literal(b"false"),
            b'n' => self.cursor.literal(b"null"),
            b'-' | b'0'..=b'9' => self.number(),
            _ => Err(Error::Malformed),
        }
    }

    /// Checks an array. `depth` is the level of its elements.
    fn array(&mut self, depth: u8) -> Result<(), Error> {
        self.cursor.pos += 1;
        if self.cursor.skip_whitespace() == Some(b']') {
            self.cursor.pos += 1;
            return Ok(());
        }
        loop {
            self.value(depth)?;
            match self.cursor.token()? {
                b',' => {}
                b']' => return Ok(()),
                _ => return Err(Error::Malformed),
            }
        }
    }

    /// Checks an object. `depth` is the level of its member values.
    fn object(&mut self, depth: u8) -> Result<(), Error> {
        self.cursor.pos += 1;
        if self.cursor.skip_whitespace() == Some(b'}') {
            self.cursor.pos += 1;
            return Ok(());
        }
        let mut members = 0;
        loop {
            (members < self.limits.map_keys).ok_or(Error::Limit(Limit::MapKeys))?;
            members += 1;
            self.admit()?;
            (self.cursor.skip_whitespace().ok_or(Error::Truncated)? == b'"').ok_or(Error::Malformed)?;
            self.string()?;
            (self.cursor.token()? == b':').ok_or(Error::Malformed)?;
            self.value(depth)?;
            match self.cursor.token()? {
                b',' => {}
                b'}' => return Ok(()),
                _ => return Err(Error::Malformed),
            }
        }
    }

    /// Checks a string, and its length after the escapes against [`Limits::string_bytes`].
    #[inline(always)]
    fn string(&mut self) -> Result<(), Error> {
        self.cursor.pos += 1;
        let Some(len) = self.cursor.short() else {
            return self.long_string();
        };
        (len <= self.limits.string_bytes).ok_or(Error::Limit(Limit::StringBytes))?;
        self.cursor.pos += len + 1;
        Ok(())
    }

    /// Checks a string that [`Cursor::short`] does not read: a string with an escape, or with its quote past the
    /// next eight bytes. The cursor is after the opening quote.
    #[inline(never)]
    fn long_string(&mut self) -> Result<(), Error> {
        // The length cannot overflow: it is not more than the length of the input.
        let mut len = 0_usize;
        loop {
            let start = self.cursor.pos;
            let stop = self.cursor.plain()?;
            len += self.cursor.pos - start;
            self.cursor.pos += 1;
            let end = match stop {
                b'"' => true,
                b'\\' => {
                    len += self.cursor.escape()?.len_utf8();
                    false
                }
                _ => return Err(Error::Malformed),
            };
            (len <= self.limits.string_bytes).ok_or(Error::Limit(Limit::StringBytes))?;
            if end {
                return Ok(());
            }
        }
    }

    /// Checks a number: `-`, if present, then an integer part with no leading zero, a fraction, if present, and an
    /// exponent, if present.
    fn number(&mut self) -> Result<(), Error> {
        if self.cursor.peek() == Some(b'-') {
            self.cursor.pos += 1;
        }
        match self.cursor.byte()? {
            b'0' => {}
            b'1'..=b'9' => self.digits(),
            _ => return Err(Error::Malformed),
        }
        if self.cursor.peek() == Some(b'.') {
            self.cursor.pos += 1;
            self.digit()?;
            self.digits();
        }
        if matches!(self.cursor.peek(), Some(b'e' | b'E')) {
            self.cursor.pos += 1;
            if matches!(self.cursor.peek(), Some(b'+' | b'-')) {
                self.cursor.pos += 1;
            }
            self.digit()?;
            self.digits();
        }
        Ok(())
    }

    /// Reads one digit.
    fn digit(&mut self) -> Result<(), Error> {
        self.cursor.byte()?.is_ascii_digit().ok_or(Error::Malformed)
    }

    /// Skips the digits at the cursor.
    fn digits(&mut self) {
        while self.cursor.peek().is_some_and(|byte| byte.is_ascii_digit()) {
            self.cursor.pos += 1;
        }
    }
}

/// The build pass: it reads a value that the check pass admitted, and makes it.
struct Builder<'a> {
    cursor: Cursor<'a>,
    /// The input, which the decoder checked as UTF-8.
    text: &'a str,
}

impl<'a> Builder<'a> {
    /// Builds the value after whitespace.
    fn value(&mut self) -> Result<Value<'a>, Error> {
        match self.cursor.skip_whitespace().ok_or(Error::Truncated)? {
            b'"' => Ok(Value::String(self.string()?)),
            b'[' => self.array(),
            b'{' => self.object(),
            b't' => self.cursor.literal(b"true").map(|()| Value::Bool(true)),
            b'f' => self.cursor.literal(b"false").map(|()| Value::Bool(false)),
            b'n' => self.cursor.literal(b"null").map(|()| Value::Null),
            _ => {
                // The check pass admitted the number, and no byte that can follow a number can be in it.
                let start = self.cursor.pos;
                while self
                    .cursor
                    .peek()
                    .is_some_and(|byte| matches!(byte, b'0'..=b'9' | b'-' | b'+' | b'.' | b'e' | b'E'))
                {
                    self.cursor.pos += 1;
                }
                Ok(Value::Number(self.slice(start, self.cursor.pos)?))
            }
        }
    }

    fn array(&mut self) -> Result<Value<'a>, Error> {
        self.cursor.pos += 1;
        let mut items = Vec::new();
        if self.cursor.skip_whitespace() == Some(b']') {
            self.cursor.pos += 1;
            return Ok(Value::Array(items));
        }
        loop {
            items.push(self.value()?);
            match self.cursor.token()? {
                b',' => {}
                b']' => return Ok(Value::Array(items)),
                _ => return Err(Error::Malformed),
            }
        }
    }

    /// Builds an object, and refuses two members with equal names.
    fn object(&mut self) -> Result<Value<'a>, Error> {
        self.cursor.pos += 1;
        let mut members = Vec::new();
        if self.cursor.skip_whitespace() == Some(b'}') {
            self.cursor.pos += 1;
            return Ok(Value::Object(members));
        }
        loop {
            self.cursor.skip_whitespace();
            let name = self.string()?;
            self.cursor.token()?;
            members.push((name, self.value()?));
            match self.cursor.token()? {
                b',' => {}
                b'}' => break,
                _ => return Err(Error::Malformed),
            }
        }
        // The order of the members has no meaning in JSON. After the sort, two equal names are adjacent.
        members.sort_unstable_by(|(a, _), (b, _)| a.cmp(b));
        members
            .array_windows()
            .all(|[a, b]| a.0 != b.0)
            .ok_or(Error::DuplicateMember)?;
        Ok(Value::Object(members))
    }

    /// Builds a string. A string with no escape borrows the input. Each other string is one allocation of the length
    /// of its text in the input, which is not less than its length after the escapes.
    #[inline(always)]
    fn string(&mut self) -> Result<Cow<'a, str>, Error> {
        self.cursor.pos += 1;
        let start = self.cursor.pos;
        let Some(len) = self.cursor.short() else {
            return self.long_string(start);
        };
        self.cursor.pos += len + 1;
        Ok(Cow::Borrowed(self.slice(start, start + len)?))
    }

    /// Builds a string that [`Cursor::short`] does not read. `start` is the position after the opening quote.
    #[inline(never)]
    fn long_string(&mut self, start: usize) -> Result<Cow<'a, str>, Error> {
        let mut stop = self.cursor.plain()?;
        if stop == b'"' {
            let text = self.slice(start, self.cursor.pos)?;
            self.cursor.pos += 1;
            return Ok(Cow::Borrowed(text));
        }
        let mut owned = String::with_capacity(self.cursor.string_end()? - start);
        let mut run = start;
        // The check pass admitted the string, so each stop is a quote or a backslash.
        loop {
            owned.push_str(self.slice(run, self.cursor.pos)?);
            self.cursor.pos += 1;
            if stop == b'"' {
                return Ok(Cow::Owned(owned));
            }
            owned.push(self.cursor.escape()?);
            run = self.cursor.pos;
            stop = self.cursor.plain()?;
        }
    }

    /// The text from `start` to `end`. The check pass admitted the input, and each bound of a slice is next to an
    /// ASCII byte, so it is on a character boundary.
    fn slice(&self, start: usize, end: usize) -> Result<&'a str, Error> {
        self.text.get(start..end).ok_or(Error::Malformed)
    }
}
