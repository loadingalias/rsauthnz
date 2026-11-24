//! The DER of the certificates of this crate: a writer, a reader that borrows its input and allocates nothing, and the
//! times of RFC 5280.

use alloc::vec::Vec;

use super::Error;

pub(super) const BOOLEAN: u8 = 0x01;
pub(super) const INTEGER: u8 = 0x02;
pub(super) const BIT_STRING: u8 = 0x03;
pub(super) const OCTET_STRING: u8 = 0x04;
pub(super) const OBJECT: u8 = 0x06;
pub(super) const UTF8_STRING: u8 = 0x0c;
pub(super) const PRINTABLE_STRING: u8 = 0x13;
const UTC_TIME: u8 = 0x17;
const GENERALIZED_TIME: u8 = 0x18;
pub(super) const SEQUENCE: u8 = 0x30;
pub(super) const SET: u8 = 0x31;
/// The `[0]` of the version, and the `[3]` of the extensions, of a `TBSCertificate`.
pub(super) const VERSION: u8 = 0xa0;
pub(super) const EXTENSIONS: u8 = 0xa3;
/// The `dNSName` (`[2]`) and the `uniformResourceIdentifier` (`[6]`) of a `GeneralName`.
pub(super) const DNS_NAME: u8 = 0x82;
pub(super) const URI: u8 = 0x86;

/// The first second of the year 10000, which no time of RFC 5280 reaches.
const TIME_END: u64 = 253_402_300_800;

/// The element of `tag` whose content is the concatenation of `parts`.
pub(super) fn element(tag: u8, parts: &[&[u8]]) -> Vec<u8> {
    let len: usize = parts.iter().map(|part| part.len()).sum();
    let mut out = Vec::with_capacity(len + 4);
    out.push(tag);
    if len < 0x80 {
        out.push(u8::try_from(len).expect("a short length fits a byte"));
    } else {
        let bytes = len.to_be_bytes();
        let start = bytes
            .iter()
            .position(|&byte| byte != 0)
            .expect("a long length is not zero");
        out.push(0x80 | u8::try_from(bytes.len() - start).expect("a length has at most 8 bytes"));
        out.extend_from_slice(&bytes[start..]);
    }
    for part in parts {
        out.extend_from_slice(part);
    }
    out
}

/// The `UTCTime` of `seconds` since the Unix epoch, or its `GeneralizedTime` from the year 2050, as RFC 5280 section
/// 4.1.2.5 asks.
pub(super) fn time(seconds: u64) -> Result<Vec<u8>, Error> {
    (seconds < TIME_END).ok_or(Error::Validity)?;
    let (year, month, day) = civil(seconds / 86_400);
    let second = seconds % 86_400;
    let digits = [month, day, second / 3_600, second % 3_600 / 60, second % 60];
    let (tag, year) = if year < 2050 {
        (UTC_TIME, year % 100)
    } else {
        (GENERALIZED_TIME, year)
    };
    let width = if tag == UTC_TIME { 2 } else { 4 };
    let mut text = Vec::with_capacity(15);
    push_digits(&mut text, year, width);
    for value in digits {
        push_digits(&mut text, value, 2);
    }
    text.push(b'Z');
    Ok(element(tag, &[&text]))
}

/// Appends the `width` decimal digits of `value`.
fn push_digits(text: &mut Vec<u8>, value: u64, width: u32) {
    for place in (0..width).rev() {
        let digit = value / 10_u64.pow(place) % 10;
        text.push(b'0' + u8::try_from(digit).expect("a digit fits a byte"));
    }
}

/// The year, the month, and the day of the day `days` since the Unix epoch, in the proleptic Gregorian calendar
/// (H. Hinnant, "chrono-Compatible Low-Level Date Algorithms").
fn civil(days: u64) -> (u64, u64, u64) {
    let days = days + 719_468;
    let era = days / 146_097;
    let of_era = days % 146_097;
    let year_of_era = (of_era - of_era / 1_460 + of_era / 36_524 - of_era / 146_096) / 365;
    let of_year = of_era - (365 * year_of_era + year_of_era / 4 - year_of_era / 100);
    let month_index = (5 * of_year + 2) / 153;
    let day = of_year - (153 * month_index + 2) / 5 + 1;
    let month = if month_index < 10 {
        month_index + 3
    } else {
        month_index - 9
    };
    let year = year_of_era + era * 400 + u64::from(month <= 2);
    (year, month, day)
}

/// The day since the Unix epoch of `year`, `month`, and `day`, from the year 1970.
fn days(year: u64, month: u64, day: u64) -> u64 {
    let year = year - u64::from(month <= 2);
    let era = year / 400;
    let year_of_era = year % 400;
    let month_index = (month + 9) % 12;
    let of_year = (153 * month_index + 2) / 5 + day - 1;
    let of_era = year_of_era * 365 + year_of_era / 4 - year_of_era / 100 + of_year;
    era * 146_097 + of_era - 719_468
}

/// A reader of DER elements of one-byte tags, in the input that it borrows. A length has its shortest form and at
/// most two bytes, and it fits in the rest of the input, so a read allocates nothing and a declared length never passes
/// the input.
pub(super) struct Reader<'a> {
    input: &'a [u8],
}

impl<'a> Reader<'a> {
    pub(super) const fn new(input: &'a [u8]) -> Self {
        Self { input }
    }

    /// The next element with `tag`, with its tag and its length.
    pub(super) fn element(&mut self, tag: u8) -> Result<&'a [u8], Error> {
        let input = self.input;
        self.read(tag)?;
        Ok(&input[..input.len() - self.input.len()])
    }

    /// The content of the next element, which has `tag`.
    pub(super) fn read(&mut self, tag: u8) -> Result<&'a [u8], Error> {
        let (&found, rest) = self.input.split_first().ok_or(Error::Malformed)?;
        (found == tag).ok_or(Error::Malformed)?;
        let (&first, rest) = rest.split_first().ok_or(Error::Malformed)?;
        let (len, rest) = match first {
            0..=0x7f => (usize::from(first), rest),
            0x81 => {
                let (&[len], rest) = rest.split_first_chunk::<1>().ok_or(Error::Malformed)?;
                (len >= 0x80).ok_or(Error::Malformed)?;
                (usize::from(len), rest)
            }
            0x82 => {
                let (len, rest) = rest.split_first_chunk::<2>().ok_or(Error::Malformed)?;
                let len = u16::from_be_bytes(*len);
                (len >= 0x100).ok_or(Error::Malformed)?;
                (usize::from(len), rest)
            }
            _ => return Err(Error::Malformed),
        };
        let (content, rest) = rest.split_at_checked(len).ok_or(Error::Malformed)?;
        self.input = rest;
        Ok(content)
    }

    /// The content of the next element if it has `tag`.
    pub(super) fn optional(&mut self, tag: u8) -> Result<Option<&'a [u8]>, Error> {
        if self.input.first() == Some(&tag) {
            self.read(tag).map(Some)
        } else {
            Ok(None)
        }
    }

    /// The input that the reader did not read.
    pub(super) const fn rest(&self) -> &'a [u8] {
        self.input
    }

    /// Whether the reader read each element.
    pub(super) const fn is_empty(&self) -> bool {
        self.input.is_empty()
    }

    /// Refuses input after the last element.
    pub(super) fn end(&self) -> Result<(), Error> {
        self.is_empty().ok_or(Error::Malformed)
    }

    /// The seconds since the Unix epoch of the next time: a `UTCTime` before 2050, and a `GeneralizedTime` from 2050, in
    /// the forms `YYMMDDHHMMSSZ` and `YYYYMMDDHHMMSSZ` of RFC 5280. A time before 1970 refuses.
    pub(super) fn time(&mut self) -> Result<u64, Error> {
        let (text, width) = match self.optional(UTC_TIME)? {
            Some(text) => (text, 2),
            None => (self.read(GENERALIZED_TIME)?, 4),
        };
        let (zone, digits) = text.split_last().ok_or(Error::Malformed)?;
        (*zone == b'Z' && digits.len() == width + 10 && digits.iter().all(u8::is_ascii_digit))
            .ok_or(Error::Malformed)?;
        let number = |from: usize, to: usize| {
            digits[from..to]
                .iter()
                .fold(0_u64, |value, digit| value * 10 + u64::from(digit - b'0'))
        };
        let year = match width {
            2 => match number(0, 2) {
                year @ 50.. => 1900 + year,
                year => 2000 + year,
            },
            _ => number(0, 4),
        };
        // RFC 5280 writes each year before 2050 as a `UTCTime`.
        (year >= 1970 && (width == 2 || year >= 2050)).ok_or(Error::Malformed)?;
        let (month, day) = (number(width, width + 2), number(width + 2, width + 4));
        let (hour, minute, second) = (
            number(width + 4, width + 6),
            number(width + 6, width + 8),
            number(width + 8, width + 10),
        );
        let leap = year % 4 == 0 && (year % 100 != 0 || year % 400 == 0);
        let month_days = match month {
            2 if leap => 29,
            2 => 28,
            4 | 6 | 9 | 11 => 30,
            _ => 31,
        };
        let valid =
            (1..=12).contains(&month) && (1..=month_days).contains(&day) && hour < 24 && minute < 60 && second < 60;
        valid.ok_or(Error::Malformed)?;
        Ok(days(year, month, day) * 86_400 + hour * 3_600 + minute * 60 + second)
    }
}
