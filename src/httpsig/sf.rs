//! Structured field values of HTTP ([RFC 8941]): the bounded parse of a Dictionary and of an Item, and the
//! serialization of an Inner List of strings, which the signature base takes.
//!
//! The parse keeps each string and token as the bytes of its text, between the quotes of a string and with its
//! escapes. The only escapes of a string are `\"` and `\\`, so a string serializes to the exact text that it parsed
//! from. A byte sequence keeps its base64 text: [`decode`] gives its bytes.
//!
//! [RFC 8941]: https://www.rfc-editor.org/rfc/rfc8941

use alloc::string::ToString;
use alloc::vec;
use alloc::vec::Vec;

use rscodec::base64::Profile::Standard;

use crate::limits::Limits;

/// A bare item (RFC 8941 section 3.3).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(super) enum Bare<'a> {
    Integer(i64),
    /// A decimal. No item of the profile is a decimal, so the parse keeps no value.
    Decimal,
    /// The text of a string between its quotes, with its escapes.
    String(&'a [u8]),
    Token(&'a [u8]),
    /// The base64 text of a byte sequence between its colons.
    Bytes(&'a [u8]),
    Boolean(bool),
}

/// The parameters of an item or of an inner list, in their order. Each key is in them once.
pub(super) type Parameters<'a> = Vec<(&'a [u8], Bare<'a>)>;

/// An item with its parameters.
#[derive(Clone, Debug, PartialEq, Eq)]
pub(super) struct Item<'a> {
    pub(super) bare: Bare<'a>,
    pub(super) parameters: Parameters<'a>,
}

/// The value of a member of a dictionary: an item, or an inner list with its parameters.
#[derive(Clone, Debug, PartialEq, Eq)]
pub(super) enum Member<'a> {
    Item(Item<'a>),
    List(Vec<Item<'a>>, Parameters<'a>),
}

/// A field value that is not a structured field of its type within its bounds.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(super) struct Malformed;

/// The members of the dictionary `input`, in their order. Each key is in them once.
///
/// # Errors
///
/// [`Malformed`] if `input` is not a dictionary, has a key twice in one dictionary or in one set of parameters, is
/// longer than [`Limits::bytes`], or has more than [`Limits::items`] members, inner-list items, and parameters.
pub(super) fn dictionary<'a>(input: &'a [u8], limits: &Limits) -> Result<Vec<(&'a [u8], Member<'a>)>, Malformed> {
    let mut parser = Parser::new(input, limits)?;
    let mut members: Vec<(&[u8], Member<'_>)> = Vec::new();
    while parser.peek().is_some() {
        parser.count()?;
        let key = parser.key()?;
        let member = if parser.eat(b'=') {
            parser.member()?
        } else {
            Member::Item(Item {
                bare: Bare::Boolean(true),
                parameters: parser.parameters()?,
            })
        };
        members.iter().all(|(seen, _)| *seen != key).ok_or(Malformed)?;
        members.push((key, member));
        parser.whitespace();
        if parser.peek().is_none() {
            break;
        }
        parser.eat(b',').ok_or(Malformed)?;
        parser.whitespace();
        // A comma after the last member.
        parser.peek().is_some().ok_or(Malformed)?;
    }
    Ok(members)
}

/// The item `input`, with its parameters.
///
/// # Errors
///
/// [`Malformed`] as for [`dictionary`].
pub(super) fn item<'a>(input: &'a [u8], limits: &Limits) -> Result<Item<'a>, Malformed> {
    let mut parser = Parser::new(input, limits)?;
    let item = parser.item()?;
    parser.spaces();
    (parser.peek().is_none()).ok_or(Malformed)?;
    Ok(item)
}

/// The bytes of the base64 text `text` of a byte sequence, if it has at most `bytes_max` bytes.
///
/// # Errors
///
/// [`Malformed`] if `text` is not canonical base64 with padding, or its bytes are more than `bytes_max`.
pub(super) fn decode(text: &[u8], bytes_max: usize) -> Result<Vec<u8>, Malformed> {
    let len = Standard.decoded_len(text).map_err(|_| Malformed)?;
    (len <= bytes_max).ok_or(Malformed)?;
    let mut bytes = vec![0; len];
    Standard.decode(text, &mut bytes).map_err(|_| Malformed)?;
    Ok(bytes)
}

/// Appends the serialization (RFC 8941 section 4.1.1.1) of the inner list of `items` with `parameters` to `out`. Each
/// item is a string with no parameter, and each parameter is a string or an integer, as each inner list of a signature
/// of the profile.
///
/// # Errors
///
/// [`Malformed`] for an item that is not a string, an item with a parameter, or a parameter of another type.
pub(super) fn inner_list(items: &[Item<'_>], parameters: &Parameters<'_>, out: &mut Vec<u8>) -> Result<(), Malformed> {
    out.push(b'(');
    for (at, item) in items.iter().enumerate() {
        let (Bare::String(text), true) = (item.bare, item.parameters.is_empty()) else {
            return Err(Malformed);
        };
        if at > 0 {
            out.push(b' ');
        }
        string(text, out);
    }
    out.push(b')');
    for (key, value) in parameters {
        out.push(b';');
        out.extend_from_slice(key);
        out.push(b'=');
        match value {
            Bare::String(text) => string(text, out),
            Bare::Integer(value) => out.extend_from_slice(value.to_string().as_bytes()),
            Bare::Decimal | Bare::Token(_) | Bare::Bytes(_) | Bare::Boolean(_) => return Err(Malformed),
        }
    }
    Ok(())
}

/// Appends the string of the text `text`, with its escapes, to `out`.
fn string(text: &[u8], out: &mut Vec<u8>) {
    out.push(b'"');
    out.extend_from_slice(text);
    out.push(b'"');
}

/// The state of one parse.
struct Parser<'a> {
    input: &'a [u8],
    at: usize,
    /// The members, inner-list items, and parameters that the parse can still take.
    items: usize,
}

impl<'a> Parser<'a> {
    /// The parse of `input`, after its leading spaces.
    fn new(input: &'a [u8], limits: &Limits) -> Result<Self, Malformed> {
        (input.len() <= limits.bytes).ok_or(Malformed)?;
        let mut parser = Self {
            input,
            at: 0,
            items: limits.items,
        };
        parser.spaces();
        Ok(parser)
    }

    fn peek(&self) -> Option<u8> {
        self.input.get(self.at).copied()
    }

    /// Takes `byte` if it is next.
    fn eat(&mut self, byte: u8) -> bool {
        let next = self.peek() == Some(byte);
        if next {
            self.at += 1;
        }
        next
    }

    /// Takes each next byte that `class` admits, and gives them.
    fn take(&mut self, class: impl Fn(u8) -> bool) -> &'a [u8] {
        let from = self.at;
        while self.peek().is_some_and(&class) {
            self.at += 1;
        }
        &self.input[from..self.at]
    }

    fn spaces(&mut self) {
        self.take(|byte| byte == b' ');
    }

    /// Takes optional whitespace: spaces and tabs.
    fn whitespace(&mut self) {
        self.take(|byte| byte == b' ' || byte == b'\t');
    }

    /// Counts one more member, inner-list item, or parameter.
    fn count(&mut self) -> Result<(), Malformed> {
        self.items = self.items.checked_sub(1).ok_or(Malformed)?;
        Ok(())
    }

    fn member(&mut self) -> Result<Member<'a>, Malformed> {
        if !self.eat(b'(') {
            return self.item().map(Member::Item);
        }
        let mut items = Vec::new();
        loop {
            self.spaces();
            if self.eat(b')') {
                return Ok(Member::List(items, self.parameters()?));
            }
            self.count()?;
            items.push(self.item()?);
            matches!(self.peek(), Some(b' ' | b')')).ok_or(Malformed)?;
        }
    }

    fn item(&mut self) -> Result<Item<'a>, Malformed> {
        Ok(Item {
            bare: self.bare()?,
            parameters: self.parameters()?,
        })
    }

    fn parameters(&mut self) -> Result<Parameters<'a>, Malformed> {
        let mut parameters: Parameters<'a> = Vec::new();
        while self.eat(b';') {
            self.spaces();
            self.count()?;
            let key = self.key()?;
            let value = if self.eat(b'=') {
                self.bare()?
            } else {
                Bare::Boolean(true)
            };
            parameters.iter().all(|(seen, _)| *seen != key).ok_or(Malformed)?;
            parameters.push((key, value));
        }
        Ok(parameters)
    }

    /// A key: a lowercase letter or `*`, then lowercase letters, digits, `_`, `-`, `.`, and `*`.
    fn key(&mut self) -> Result<&'a [u8], Malformed> {
        matches!(self.peek(), Some(b'a'..=b'z' | b'*')).ok_or(Malformed)?;
        Ok(self.take(|byte| matches!(byte, b'a'..=b'z' | b'0'..=b'9' | b'_' | b'-' | b'.' | b'*')))
    }

    fn bare(&mut self) -> Result<Bare<'a>, Malformed> {
        match self.peek().ok_or(Malformed)? {
            b'-' | b'0'..=b'9' => self.number(),
            b'"' => self.string(),
            b':' => {
                self.at += 1;
                let text = self.take(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'+' | b'/' | b'='));
                self.eat(b':').ok_or(Malformed)?;
                Ok(Bare::Bytes(text))
            }
            b'?' => {
                self.at += 1;
                let value = match self.peek() {
                    Some(b'0') => false,
                    Some(b'1') => true,
                    _ => return Err(Malformed),
                };
                self.at += 1;
                Ok(Bare::Boolean(value))
            }
            b'A'..=b'Z' | b'a'..=b'z' | b'*' => {
                Ok(Bare::Token(self.take(|byte| {
                    byte.is_ascii_alphanumeric() || b"!#$%&'*+-.^_`|~:/".contains(&byte)
                })))
            }
            _ => Err(Malformed),
        }
    }

    /// An integer of at most 15 digits, or a decimal of at most 12 digits, a point, and 1 to 3 digits
    /// (RFC 8941 section 4.2.4).
    fn number(&mut self) -> Result<Bare<'a>, Malformed> {
        let negative = self.eat(b'-');
        let whole = self.take(|byte| byte.is_ascii_digit());
        if self.eat(b'.') {
            let fraction = self.take(|byte| byte.is_ascii_digit());
            let decimal = (1..=12).contains(&whole.len()) && (1..=3).contains(&fraction.len());
            return decimal.then_some(Bare::Decimal).ok_or(Malformed);
        }
        (1..=15).contains(&whole.len()).ok_or(Malformed)?;
        // At most 15 digits: the value is less than 10^15, so it fits in an `i64` with no overflow.
        let value = whole
            .iter()
            .fold(0_i64, |value, digit| value * 10 + i64::from(digit - b'0'));
        Ok(Bare::Integer(if negative { -value } else { value }))
    }

    /// A string: visible ASCII and spaces between quotes, with the escapes `\"` and `\\`.
    fn string(&mut self) -> Result<Bare<'a>, Malformed> {
        self.at += 1;
        let from = self.at;
        loop {
            match self.peek().ok_or(Malformed)? {
                b'"' => break,
                b'\\' => {
                    self.at += 1;
                    matches!(self.peek(), Some(b'"' | b'\\')).ok_or(Malformed)?;
                }
                b' '..=b'~' => {}
                _ => return Err(Malformed),
            }
            self.at += 1;
        }
        let text = &self.input[from..self.at];
        self.at += 1;
        Ok(Bare::String(text))
    }
}
