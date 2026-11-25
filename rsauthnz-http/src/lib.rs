//! The HTTP binding of rsauthnz: the checks and the responses of a site that serves browsers, on `http` 1.x values. It
//! depends on no web framework, server, or runtime, so a framework that gives [`http::Request`] values mounts it with no
//! conversion. This crate is in development, and its API can change in each release.
//!
//! A [`Site`] holds the origin of the site, from the configuration of the host, and the `SameSite` value of its
//! cookies:
//!
//! - [`Site::check_change`] admits a state change only from a page of the site: an unsafe method, an `Origin` equal to
//!   the origin of the site, and `Sec-Fetch-Site: same-origin`. A browser sets both headers, and no script can set
//!   them. Thus a form or a script of another site refuses, with no token.
//! - [`Site::json_change`] also admits a JSON body within its bound, and gives its bytes to the ceremony.
//! - [`Site::set_cookie`] and [`Site::clear_cookie`] write a `__Host-` cookie with `Secure`, `HttpOnly`, `Path=/`, and
//!   the `SameSite` value of the site. [`CookieName::find`] reads it, also from the split `cookie` fields of HTTP/2 and
//!   HTTP/3.
//! - [`Site::set_session`] and [`CookieName::session`] write and read a session identifier
//!   ([`rsauthnz::session`]) in a cookie, with the base64url of data-independent timing.
//! - [`machine_json`] admits the JSON body of a client that is no browser, such as an agent
//!   ([`rsauthnz::agent`]), only with no cookie and no field that a browser sends.
//!
//! Each response of the binding has `Cache-Control: no-store`: [`json`], [`waiting`], [`redirect`] to a path of the site, the
//! problem responses of [`Refusal::response`] and [`problem`], the document of [`related_origins`], and the
//! [`browser_module`] of passkey ceremonies. A problem body holds only its recovery, never a byte of
//! the request. The HTTP version of a message changes no result.
//!
//! A handler returns `Result<Response<Vec<u8>>, Problem>`: `?` gives a [`Problem`] from each refusal of the binding and
//! from each error of rsauthnz with a recovery, and [`Problem::response`] gives its response.
//!
//! ```
//! use core::time::Duration;
//!
//! use http::Request;
//! use rsauthnz::transition::Recovery;
//! use rsauthnz_http::{CookieName, Site};
//!
//! const SESSION: CookieName = CookieName::new("session").expect("a token");
//!
//! // The origin comes from the configuration of the host, never from a request.
//! let site = Site::new("https://app.example")?;
//!
//! // A ceremony of the browser adapter, with the body that the framework read within its body limit.
//! let finish = Request::post("/passkey/finish")
//!     .header("origin", "https://app.example")
//!     .header("sec-fetch-site", "same-origin")
//!     .header("content-type", "application/json")
//!     .body(br#"{"id":"AQID"}"#.to_vec())?;
//! let body = site.json_change(&finish, 16 * 1024)?;
//! assert_eq!(body, br#"{"id":"AQID"}"#);
//!
//! // After its transition commits, the response releases the session in a cookie.
//! let mut response = rsauthnz_http::json(b"{}".to_vec());
//! site.set_cookie(response.headers_mut(), SESSION, b"c2Vzc2lvbg", Duration::from_secs(8 * 60 * 60))?;
//! assert_eq!(
//!     response.headers()["set-cookie"],
//!     "__Host-session=c2Vzc2lvbg; Path=/; Max-Age=28800; Secure; HttpOnly; SameSite=Lax"
//! );
//!
//! // A form of another site refuses before any work. The body holds only the recovery.
//! let forged = Request::post("/sign-out")
//!     .header("origin", "https://attacker.example")
//!     .header("sec-fetch-site", "cross-site")
//!     .body(())?;
//! let response = site.check_change(&forged).unwrap_err().response();
//! assert_eq!(response.status(), 403);
//! assert_eq!(response.body(), br#"{"recovery":"refuse"}"#);
//!
//! // The server looked up a commit whose response was lost, and its outcome stays unknown. The browser loads the current
//! // state, and does not send the request again.
//! assert_eq!(rsauthnz_http::problem(Recovery::Lookup).body(), br#"{"recovery":"check"}"#);
//! # Ok::<(), Box<dyn core::error::Error>>(())
//! ```

mod cookie;
mod response;

use core::fmt;

use http::Request;
use http::header::{AsHeaderName, CONTENT_TYPE, COOKIE, HeaderMap, HeaderValue, ORIGIN};

pub use cookie::CookieName;
pub use response::{Problem, RELATED_ORIGINS, browser_module, json, problem, redirect, related_origins, waiting};

/// The site that the binding serves: its origin, and the `SameSite` value of its cookies.
#[derive(Clone, Debug)]
pub struct Site {
    /// The origin, in the form that a browser writes in `Origin`.
    origin: HeaderValue,
    same_site: SameSite,
}

/// The `SameSite` value of the cookies of a site. `None` lets each other site send the cookies, so it is not a value.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq, Hash)]
pub enum SameSite {
    /// The browser sends the cookies with a navigation from another site, such as a link in an email, and not with a
    /// request that another site makes. The default.
    #[default]
    Lax,
    /// The browser sends the cookies only with the requests of the site, so a link from another site arrives with no
    /// session.
    Strict,
}

impl Site {
    /// The site of `origin`: `https://` and a domain name with an optional port, or `http://localhost` with an optional
    /// port for development. The site takes uppercase letters, the default port, and a final `/`, and it compares in
    /// the form that a browser sends. Its cookies have `SameSite=Lax`.
    ///
    /// Cost class: [`Parse`](rsauthnz::limits::Class::Parse).
    ///
    /// # Errors
    ///
    /// [`Error::Origin`] if `origin` is not in this form, for example if it has a path, a query, user information, or
    /// an IP address.
    pub fn new(origin: &str) -> Result<Self, Error> {
        let origin = serialize(origin).ok_or(Error::Origin)?;
        let origin = HeaderValue::try_from(origin).map_err(|_| Error::Origin)?;
        Ok(Self {
            origin,
            same_site: SameSite::Lax,
        })
    }

    /// The site with cookies of `same_site`.
    #[must_use]
    pub fn same_site(mut self, same_site: SameSite) -> Self {
        self.same_site = same_site;
        self
    }

    /// Checks that `request` is a state change from a page of the site. Call it before each state change that a browser
    /// sends with the cookies of the site, and before other work. The work is linear in the bytes of the two fields.
    ///
    /// Cost class: [`Parse`](rsauthnz::limits::Class::Parse).
    ///
    /// # Errors
    ///
    /// - [`Refusal::Method`] if the method is safe, such as `GET`: a link of another site can send it.
    /// - [`Refusal::Origin`] if the request has no `Origin`, more than one, or one that is not the origin of the site.
    /// - [`Refusal::FetchSite`] if the request has no `Sec-Fetch-Site`, more than one, or one other than
    ///   `same-origin`.
    pub fn check_change<B>(&self, request: &Request<B>) -> Result<(), Refusal> {
        if request.method().is_safe() {
            return Err(Refusal::Method);
        }
        let headers = request.headers();
        if one(headers, ORIGIN) != Some(&self.origin) {
            return Err(Refusal::Origin);
        }
        if one(headers, "sec-fetch-site").is_none_or(|site| site != "same-origin") {
            return Err(Refusal::FetchSite);
        }
        Ok(())
    }

    /// The JSON body of the state change `request`, after [`Site::check_change`]. The body has `Content-Type:
    /// application/json`, with no parameter or with `charset=utf-8`, and at most `bytes_max` bytes. Read the body with
    /// the body limit of the framework first: this check does not limit the memory of a body that is already read.
    ///
    /// Cost class: [`Parse`](rsauthnz::limits::Class::Parse).
    ///
    /// # Errors
    ///
    /// Each refusal of [`Site::check_change`]; [`Refusal::ContentType`] if the request has no `Content-Type`, more
    /// than one, or another type; and [`Refusal::BodyBytes`] if the body has more than `bytes_max` bytes.
    pub fn json_change<'r, B: AsRef<[u8]>>(
        &self,
        request: &'r Request<B>,
        bytes_max: usize,
    ) -> Result<&'r [u8], Refusal> {
        self.check_change(request)?;
        if one(request.headers(), CONTENT_TYPE).is_none_or(|value| !json_media(value.as_bytes())) {
            return Err(Refusal::ContentType);
        }
        let body = request.body().as_ref();
        if body.len() > bytes_max {
            return Err(Refusal::BodyBytes);
        }
        Ok(body)
    }
}

/// The JSON body of `request` from a client that is no browser, such as an agent: an unsafe method, no `Origin`, no
/// `Sec-Fetch-Site`, and no `Cookie`, a `Content-Type` of `application/json`, and at most `bytes_max` bytes. A browser
/// sends `Origin` and `Sec-Fetch-Site` with each state change, and no script can remove them, so no page of any site can
/// send this request with the cookies of a human. Thus the routes of an agent never take a session. Read the body with
/// the body limit of the framework first.
///
/// Cost class: [`Parse`](rsauthnz::limits::Class::Parse).
///
/// # Errors
///
/// [`Refusal::Method`] for a safe method. [`Refusal::Origin`], [`Refusal::FetchSite`], and [`Refusal::Cookie`] if the
/// request has that field. [`Refusal::ContentType`] and [`Refusal::BodyBytes`] as for [`Site::json_change`].
pub fn machine_json<B: AsRef<[u8]>>(request: &Request<B>, bytes_max: usize) -> Result<&[u8], Refusal> {
    if request.method().is_safe() {
        return Err(Refusal::Method);
    }
    let headers = request.headers();
    if headers.contains_key(ORIGIN) {
        return Err(Refusal::Origin);
    }
    if headers.contains_key("sec-fetch-site") {
        return Err(Refusal::FetchSite);
    }
    if headers.contains_key(COOKIE) {
        return Err(Refusal::Cookie);
    }
    if one(headers, CONTENT_TYPE).is_none_or(|value| !json_media(value.as_bytes())) {
        return Err(Refusal::ContentType);
    }
    let body = request.body().as_ref();
    if body.len() > bytes_max {
        return Err(Refusal::BodyBytes);
    }
    Ok(body)
}

/// The value of the field `name`, if `headers` has it exactly once.
fn one<K: AsHeaderName>(headers: &HeaderMap, name: K) -> Option<&HeaderValue> {
    let mut values = headers.get_all(name).iter();
    values.next().filter(|_| values.next().is_none())
}

/// Whether `value` is the media type `application/json`, with no parameter or with `charset=utf-8`.
fn json_media(value: &[u8]) -> bool {
    let (media, parameter) = match value.split_once(|&byte| byte == b';') {
        Some((media, parameter)) => (media, Some(parameter)),
        None => (value, None),
    };
    media.trim_ascii().eq_ignore_ascii_case(b"application/json")
        && parameter.is_none_or(|parameter| parameter.trim_ascii().eq_ignore_ascii_case(b"charset=utf-8"))
}

/// The origin `text` in the form that a browser sends: lowercase, with no final `/`, and with no default port. `None`
/// if it is not `https://` and a domain name, or `http://localhost`, with an optional port.
fn serialize(text: &str) -> Option<String> {
    let text = text.to_ascii_lowercase();
    let (scheme, rest) = text.split_once("://")?;
    let rest = rest.strip_suffix('/').unwrap_or(rest);
    let (host, port) = match rest.rsplit_once(':') {
        Some((host, port)) => (host, Some(port)),
        None => (rest, None),
    };
    let default = match (scheme, host) {
        ("https", _) => 443,
        ("http", "localhost") => 80,
        _ => return None,
    };
    let port = match port {
        None => default,
        Some(port) if !port.is_empty() && port.bytes().all(|byte| byte.is_ascii_digit()) => {
            port.parse::<u16>().ok().filter(|&port| port != 0)?
        }
        Some(_) => return None,
    };
    let label = |label: &str| {
        (1..=63).contains(&label.len())
            && label
                .bytes()
                .all(|byte| byte.is_ascii_lowercase() || byte.is_ascii_digit() || byte == b'-')
            && !label.starts_with('-')
            && !label.ends_with('-')
    };
    // A final label of digits is an IPv4 address, which no browser takes as the relying party of a passkey.
    let domain = host.len() <= 253
        && host.split('.').all(label)
        && host
            .rsplit('.')
            .next()
            .is_some_and(|last| !last.bytes().all(|byte| byte.is_ascii_digit()));
    domain.then(|| {
        if port == default {
            format!("{scheme}://{host}")
        } else {
            format!("{scheme}://{host}:{port}")
        }
    })
}

/// The cause of a refused request. Each refusal has a problem response ([`Refusal::response`]), and its recovery is to
/// refuse the request: the same request refuses again. No refusal holds a byte of the request.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub enum Refusal {
    /// A state change has a safe method, such as `GET`.
    Method,
    /// The `Origin` of a state change is missing, repeated, or not the origin of the site, or a request of a client that
    /// is no browser has one.
    Origin,
    /// The `Sec-Fetch-Site` of a state change is missing, repeated, or not `same-origin`, or a request of a client that
    /// is no browser has one.
    FetchSite,
    /// The body is not `application/json`.
    ContentType,
    /// The body is longer than its bound.
    BodyBytes,
    /// A cookie of the site is in the request twice, or its value has a byte that a cookie value cannot have, or a
    /// request of a client that is no browser has a cookie.
    Cookie,
    /// The target of a redirect is not a path of the site.
    Redirect,
}

impl fmt::Display for Refusal {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(match self {
            Self::Method => "a state change has a safe method",
            Self::Origin => "the Origin of the state change is not the origin of the site",
            Self::FetchSite => "the state change does not come from a page of the site",
            Self::ContentType => "the body is not JSON",
            Self::BodyBytes => "the body is longer than its bound",
            Self::Cookie => "a cookie of the site is repeated or not valid",
            Self::Redirect => "the redirect target is not a path of the site",
        })
    }
}

impl core::error::Error for Refusal {}

/// The cause of a refused value of the host.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub enum Error {
    /// The origin is not `https://` and a domain name, or `http://localhost`, with an optional port.
    Origin,
    /// The cookie value has a byte that a cookie value cannot have: a control character, a space, `"`, `,`, `;`, or
    /// `\`, or a byte that is not ASCII.
    CookieValue,
    /// This build on this CPU cannot encode a session identifier with data-independent timing. Build with
    /// `-C target-feature=+dit` on Windows aarch64.
    Dit,
}

impl fmt::Display for Error {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(match self {
            Self::Origin => "the origin is not https:// and a domain name, or http://localhost",
            Self::CookieValue => "the cookie value has a byte that a cookie value cannot have",
            Self::Dit => "this build cannot encode a session identifier with data-independent timing",
        })
    }
}

impl core::error::Error for Error {}
