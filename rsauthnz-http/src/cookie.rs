//! The cookies of a site: always `__Host-`, `Secure`, `HttpOnly`, and `Path=/`, with the `SameSite` value of the site.

use core::time::Duration;

use http::header::{CACHE_CONTROL, COOKIE, HeaderMap, HeaderValue, SET_COOKIE};
use rsauthnz::session::Identifier;

use crate::response::NO_STORE;
use crate::{Error, Refusal, SameSite, Site};

/// The prefix of each cookie of a site. A browser takes a `__Host-` cookie only from a secure origin, with `Secure`,
/// `Path=/`, and no `Domain`, so another host, such as another subdomain, cannot set it.
const PREFIX: &str = "__Host-";

/// The name of a cookie of a site, with no prefix. The binding writes and reads it after the prefix `__Host-`.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub struct CookieName(&'static str);

impl CookieName {
    /// The cookie `name`, or `None` if `name` is empty or has a byte that is not a token character of RFC 9110: an
    /// ASCII letter or digit, or one of ``!#$%&'*+-.^_`|~``.
    #[must_use]
    pub const fn new(name: &'static str) -> Option<Self> {
        let mut rest = name.as_bytes();
        if rest.is_empty() {
            return None;
        }
        while let [byte, tail @ ..] = rest {
            if !token(*byte) {
                return None;
            }
            rest = tail;
        }
        Some(Self(name))
    }

    /// The value of the cookie in the `cookie` fields of `headers`, or `None` if no field has it. HTTP/2 and HTTP/3 can
    /// split the cookies of a request into several fields, so it reads each field. A cookie with another prefix, or
    /// with no prefix, is not this cookie. The work is linear in the bytes of the fields, which the server bounds.
    ///
    /// Cost class: [`Parse`](rsauthnz::limits::Class::Parse).
    ///
    /// # Errors
    ///
    /// [`Refusal::Cookie`] if the fields have the cookie twice, or if its value has a byte that a cookie value cannot
    /// have.
    pub fn find(self, headers: &HeaderMap) -> Result<Option<&[u8]>, Refusal> {
        let mut found = None;
        for field in headers.get_all(COOKIE) {
            for pair in field.as_bytes().split(|&byte| byte == b';') {
                let Some((name, value)) = pair.trim_ascii_start().split_once(|&byte| byte == b'=') else {
                    continue;
                };
                if name.strip_prefix(PREFIX.as_bytes()) != Some(self.0.as_bytes()) {
                    continue;
                }
                if found.is_some() || !value.iter().copied().all(octet) {
                    return Err(Refusal::Cookie);
                }
                found = Some(value);
            }
        }
        Ok(found)
    }

    /// The session identifier in the cookie `name` of `headers` ([`Self::find`]), or `None` if no field has the cookie.
    /// The decoder has data-independent timing. After a refusal, or when the session does not serve, clear the cookie
    /// with [`Site::clear_cookie`] and treat the request as signed out: the browser cannot change an `HttpOnly` cookie.
    ///
    /// Cost class: [`Parse`](rsauthnz::limits::Class::Parse).
    ///
    /// # Errors
    ///
    /// The refusals of [`Self::find`], and [`Refusal::Cookie`] if the value is not the base64url text of an identifier.
    pub fn session(self, headers: &HeaderMap) -> Result<Option<Identifier>, Refusal> {
        self.find(headers)?
            .map(|value| Identifier::parse(value).map_err(|_| Refusal::Cookie))
            .transpose()
    }
}

/// Whether `byte` is a token character of RFC 9110.
const fn token(byte: u8) -> bool {
    matches!(byte, b'0'..=b'9' | b'a'..=b'z' | b'A'..=b'Z' | b'!' | b'#'..=b'\'' | b'*' | b'+' | b'-' | b'.' | b'^'..=b'`' | b'|' | b'~')
}

/// Whether `byte` is a `cookie-octet` of RFC 6265: visible ASCII other than `"`, `,`, `;`, and `\`.
const fn octet(byte: u8) -> bool {
    matches!(byte, 0x21 | 0x23..=0x2b | 0x2d..=0x3a | 0x3c..=0x5b | 0x5d..=0x7e)
}

impl Site {
    /// Adds a `set-cookie` field to `headers` for the cookie `name` with `value`, which the browser keeps for
    /// `max_age`, in whole seconds. It also sets `Cache-Control: no-store`, so that no cache keeps the response and gives
    /// the cookie to another user. The field is sensitive: its debug output does not show it, and HTTP/2 and HTTP/3 do
    /// not put it in their compression tables.
    ///
    /// Cost class: [`Parse`](rsauthnz::limits::Class::Parse).
    ///
    /// # Errors
    ///
    /// [`Error::CookieValue`] if `value` has a byte that a cookie value cannot have, such as `;`, which would add an
    /// attribute.
    pub fn set_cookie(
        &self,
        headers: &mut HeaderMap,
        name: CookieName,
        value: &[u8],
        max_age: Duration,
    ) -> Result<(), Error> {
        if !value.iter().copied().all(octet) {
            return Err(Error::CookieValue);
        }
        let value = str::from_utf8(value).map_err(|_| Error::CookieValue)?;
        self.write(headers, name, value, max_age.as_secs());
        Ok(())
    }

    /// Adds a `set-cookie` field to `headers` for the cookie `name` with the session identifier `identifier`, which the
    /// browser keeps for `max_age`, such as [`Issued::max_age`](rsauthnz::session::Issued::max_age). The encoder has
    /// data-independent timing, and the field is sensitive, as in [`Self::set_cookie`].
    ///
    /// Cost class: [`Parse`](rsauthnz::limits::Class::Parse).
    ///
    /// # Errors
    ///
    /// [`Error::Dit`] if this build on this CPU cannot encode the identifier with data-independent timing.
    pub fn set_session(
        &self,
        headers: &mut HeaderMap,
        name: CookieName,
        identifier: &Identifier,
        max_age: Duration,
    ) -> Result<(), Error> {
        let text = identifier.encode().map_err(|_| Error::Dit)?;
        self.set_cookie(headers, name, text.as_bytes(), max_age)
    }

    /// Adds a `set-cookie` field to `headers` that ends the cookie `name` in the browser, and sets `Cache-Control:
    /// no-store`.
    pub fn clear_cookie(&self, headers: &mut HeaderMap, name: CookieName) {
        self.write(headers, name, "", 0);
    }

    /// Adds the `set-cookie` field of the cookie `name` with `value` and `max_age_s`.
    fn write(&self, headers: &mut HeaderMap, name: CookieName, value: &str, max_age_s: u64) {
        let same_site = match self.same_site {
            SameSite::Lax => "Lax",
            SameSite::Strict => "Strict",
        };
        let text = format!(
            "{PREFIX}{}={value}; Path=/; Max-Age={max_age_s}; Secure; HttpOnly; SameSite={same_site}",
            name.0
        );
        let mut field = HeaderValue::try_from(text).expect("a token and cookie octets are visible ASCII");
        field.set_sensitive(true);
        headers.append(SET_COOKIE, field);
        headers.insert(CACHE_CONTROL, NO_STORE);
    }
}
