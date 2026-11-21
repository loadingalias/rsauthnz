//! The responses of the binding. Each one has `Cache-Control: no-store`, and a problem body holds only its recovery.

use http::header::{CACHE_CONTROL, CONTENT_TYPE, HeaderValue, LOCATION};
use http::{Response, StatusCode};
use rsauthnz::passkey::RelyingParty;
use rsauthnz::transition::Recovery;

use crate::Refusal;

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

/// A response with `status`, `content_type`, and `body`.
fn response(status: StatusCode, content_type: HeaderValue, body: Vec<u8>) -> Response<Vec<u8>> {
    let mut response = Response::new(body);
    *response.status_mut() = status;
    response.headers_mut().insert(CACHE_CONTROL, NO_STORE);
    response.headers_mut().insert(CONTENT_TYPE, content_type);
    response
}
