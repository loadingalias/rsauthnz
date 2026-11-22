//! The responses of the binding. Each one has `Cache-Control: no-store`, and a problem body holds only its recovery.

use http::header::{CACHE_CONTROL, CONTENT_TYPE, HeaderValue, LOCATION};
use http::{Response, StatusCode};
use rsauthnz::passkey::RelyingParty;
use rsauthnz::transition::{Recover, Recovery};

use crate::{CookieName, Error, Refusal, Site};

/// The `Cache-Control` value of each response of the binding.
pub(crate) const NO_STORE: HeaderValue = HeaderValue::from_static("no-store");

/// The media type of a problem body ([RFC 9457](https://www.rfc-editor.org/rfc/rfc9457)).
const PROBLEM: HeaderValue = HeaderValue::from_static("application/problem+json");

/// A `200 OK` response with the JSON `body`, such as the options of a ceremony.
#[must_use]
pub fn json(body: Vec<u8>) -> Response<Vec<u8>> {
    response(StatusCode::OK, HeaderValue::from_static("application/json"), body)
}

/// The path of the document of related origins: `/.well-known/webauthn` ([WebAuthn Level 3, section 5.11]). Serve it
/// with [`related_origins`] at the host of the relying party ID, for a `GET` with no cookie and no redirect.
///
/// [WebAuthn Level 3, section 5.11]: https://www.w3.org/TR/webauthn-3/#sctn-related-origins
pub const RELATED_ORIGINS: &str = "/.well-known/webauthn";

/// The document of related origins of `rp`: a `200 OK` response with the JSON object `{"origins":[...]}`, which holds
/// each related origin of [`RelyingParty::with_related`] in its order. The browser of a related origin fetches it
/// before it accepts the relying party ID of `rp`.
///
/// Cost class: [`Parse`](rsauthnz::limits::Class::Parse).
#[must_use]
pub fn related_origins(rp: &RelyingParty) -> Response<Vec<u8>> {
    let mut body = br#"{"origins":["#.to_vec();
    for (at, origin) in rp.related().iter().enumerate() {
        if at > 0 {
            body.push(b',');
        }
        // A related origin is `https://`, a domain name in lowercase, and a port: it has no character to escape.
        body.extend_from_slice(&[b"\"", origin.as_bytes(), b"\""].concat());
    }
    body.extend_from_slice(b"]}");
    json(body)
}

/// The browser adapter of `browser/rsauthnz.js`: a `200 OK` response with `Content-Type: text/javascript`. Serve it at
/// a path of the site, and load it with `<script type="module">` or `import`.
#[must_use]
pub fn browser_module() -> Response<Vec<u8>> {
    let body = include_str!("../browser/rsauthnz.js").as_bytes().to_vec();
    response(
        StatusCode::OK,
        HeaderValue::from_static("text/javascript; charset=utf-8"),
        body,
    )
}

/// A `303 See Other` response to `path`, a path of the site, such as the page after a sign-in.
///
/// Cost class: [`Parse`](rsauthnz::limits::Class::Parse).
///
/// # Errors
///
/// [`Refusal::Redirect`] if `path` does not start with one `/`, or if it has a `\`, a space, or a byte that is not
/// visible ASCII. A browser reads `//host`, `/\host`, and a path with a tab or a line break in it as another host.
pub fn redirect(path: &str) -> Result<Response<Vec<u8>>, Refusal> {
    let local = match path.as_bytes() {
        [b'/', b'/' | b'\\', ..] => false,
        [b'/', ..] => path.bytes().all(|byte| matches!(byte, b'!'..=b'~') && byte != b'\\'),
        _ => false,
    };
    if !local {
        return Err(Refusal::Redirect);
    }
    let location = HeaderValue::try_from(path).map_err(|_| Refusal::Redirect)?;
    let mut response = Response::new(Vec::new());
    *response.status_mut() = StatusCode::SEE_OTHER;
    response.headers_mut().insert(CACHE_CONTROL, NO_STORE);
    response.headers_mut().insert(LOCATION, location);
    Ok(response)
}

/// The problem response of `recovery`, such as the recovery of a transition outcome
/// ([`Outcome::recovery`](rsauthnz::transition::Outcome::recovery)):
///
/// | Recovery | Status | Body |
/// | --- | --- | --- |
/// | [`Recovery::Restart`] | `409 Conflict` | `{"recovery":"restart"}` |
/// | [`Recovery::Lookup`] | `500 Internal Server Error` | `{"recovery":"check"}` |
/// | [`Recovery::Verify`] | `403 Forbidden` | `{"recovery":"verify"}` |
/// | [`Recovery::Refuse`] | `403 Forbidden` | `{"recovery":"refuse"}` |
///
/// Only the server holds the operation of an unknown outcome, so the server looks it up first. Send
/// [`Recovery::Lookup`] only when the outcome stays unknown after that lookup. The client of `check` then loads the
/// current state, such as the account page. It never sends the request again: the first attempt can have committed.
#[must_use]
pub fn problem(recovery: Recovery) -> Response<Vec<u8>> {
    let (status, body): (_, &[u8]) = match recovery {
        Recovery::Restart => (StatusCode::CONFLICT, br#"{"recovery":"restart"}"#),
        Recovery::Lookup => (StatusCode::INTERNAL_SERVER_ERROR, br#"{"recovery":"check"}"#),
        Recovery::Verify => (StatusCode::FORBIDDEN, br#"{"recovery":"verify"}"#),
        Recovery::Refuse => (StatusCode::FORBIDDEN, br#"{"recovery":"refuse"}"#),
    };
    response(status, PROBLEM, body.to_vec())
}

impl Refusal {
    /// The problem response of the refusal: its status, and the body `{"recovery":"refuse"}`.
    ///
    /// | Refusal | Status |
    /// | --- | --- |
    /// | [`Refusal::Method`], [`Refusal::Origin`], [`Refusal::FetchSite`] | `403 Forbidden` |
    /// | [`Refusal::ContentType`] | `415 Unsupported Media Type` |
    /// | [`Refusal::BodyBytes`] | `413 Content Too Large` |
    /// | [`Refusal::Cookie`], [`Refusal::Redirect`] | `400 Bad Request` |
    #[must_use]
    pub fn response(self) -> Response<Vec<u8>> {
        let status = match self {
            Self::Method | Self::Origin | Self::FetchSite => StatusCode::FORBIDDEN,
            Self::ContentType => StatusCode::UNSUPPORTED_MEDIA_TYPE,
            Self::BodyBytes => StatusCode::PAYLOAD_TOO_LARGE,
            Self::Cookie | Self::Redirect => StatusCode::BAD_REQUEST,
        };
        response(status, PROBLEM, br#"{"recovery":"refuse"}"#.to_vec())
    }
}

/// A refused request. `?` gives it from a refusal of a check of the binding, and from each error of rsauthnz with a
/// recovery ([`Recover`]), so a handler returns `Result<Response<Vec<u8>>, Problem>` and converts no error itself.
/// [`Problem::response`] gives the response. A problem holds no byte of the request.
///
/// ```
/// use http::Response;
/// use rsauthnz::{account, session};
/// use rsauthnz_http::{CookieName, Problem, Site};
///
/// const SESSION: CookieName = CookieName::new("session").expect("a token");
///
/// /// A sensitive change: `fresh` is the check of the fresh user verification of the session of the request.
/// fn remove(fresh: Result<(), account::Error>) -> Result<Response<Vec<u8>>, Problem> {
///     fresh?;
///     Ok(rsauthnz_http::json(b"{}".to_vec()))
/// }
///
/// let site = Site::new("https://app.example")?;
/// let response = remove(Err(account::Error::Stale)).unwrap_or_else(|problem| problem.response(&site));
/// assert_eq!(response.status(), 403);
/// assert_eq!(response.body(), br#"{"recovery":"verify"}"#);
///
/// // A failed read of the store committed nothing, so the client starts again.
/// let failed = Problem::from(session::Failure::Store("the store is down"));
/// assert_eq!(failed.response(&site).status(), 409);
///
/// // A session that does not serve clears its cookie.
/// let response = Problem::SignedOut(SESSION).response(&site);
/// assert_eq!(response.headers()["set-cookie"], "__Host-session=; Path=/; Max-Age=0; Secure; HttpOnly; SameSite=Lax");
/// # Ok::<(), Box<dyn core::error::Error>>(())
/// ```
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Problem {
    /// A check of the binding refused the request.
    Refusal(Refusal),
    /// An operation refused, with the recovery of the client.
    Recovery(Recovery),
    /// The session cookie of this name serves no session: its value is not valid, or its session is unknown, ended, or
    /// reused. The client is signed out, and only the server can clear an `HttpOnly` cookie.
    SignedOut(CookieName),
}

impl Problem {
    /// The response: [`Refusal::response`] of a refusal, [`problem`] of a recovery, and for [`Problem::SignedOut`] the
    /// response of [`Recovery::Refuse`] that clears the cookie ([`Site::clear_cookie`]).
    #[must_use]
    pub fn response(self, site: &Site) -> Response<Vec<u8>> {
        match self {
            Self::Refusal(refusal) => refusal.response(),
            Self::Recovery(recovery) => problem(recovery),
            Self::SignedOut(name) => {
                let mut response = problem(Recovery::Refuse);
                site.clear_cookie(response.headers_mut(), name);
                response
            }
        }
    }
}

impl From<Refusal> for Problem {
    fn from(refusal: Refusal) -> Self {
        Self::Refusal(refusal)
    }
}

impl<E: Recover> From<E> for Problem {
    fn from(error: E) -> Self {
        Self::Recovery(error.recovery())
    }
}

impl Recover for Error {
    /// [`Recovery::Refuse`]: a value of the host refuses, so the same request refuses again until the host changes it.
    fn recovery(&self) -> Recovery {
        Recovery::Refuse
    }
}

/// A response with `status`, `content_type`, and `body`.
fn response(status: StatusCode, content_type: HeaderValue, body: Vec<u8>) -> Response<Vec<u8>> {
    let mut response = Response::new(body);
    *response.status_mut() = status;
    response.headers_mut().insert(CACHE_CONTROL, NO_STORE);
    response.headers_mut().insert(CONTENT_TYPE, content_type);
    response
}
