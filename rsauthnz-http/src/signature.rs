//! The `http` mapping of the HTTP message signatures of an agent ([`rsauthnz::httpsig`]).

use core::time::Duration;

use http::Request;
use http::header::{HOST, HeaderMap, HeaderName, HeaderValue};
use rsauthnz::cose::TrustedKey;
use rsauthnz::evidence::Evidence;
use rsauthnz::httpsig::{self, Draft, Error, NONCE_BYTES, Profile, Signed};
use rsauthnz::time::Reading;

use crate::one;

/// The draft of the signature of the request `request` of an agent by its key `key`, the `cnf` key of `credential`,
/// as [`Draft::new`] gives it. The target of `request` has its authority, such as `https://api.example.com/repos/x`.
/// Custody signs `draft.to_be_signed()`, and [`Draft::finish`] gives the fields that [`add_signature`] adds.
///
/// Cost class: [`Parse`](rsauthnz::limits::Class::Parse).
///
/// # Errors
///
/// [`Error::Authority`] if the target of `request` has no authority and `request` has no one `Host`, and each error
/// of [`Draft::new`].
pub fn signature_draft<B: AsRef<[u8]>>(
    key: &TrustedKey,
    credential: &[u8],
    request: &Request<B>,
    nonce: &[u8; NONCE_BYTES],
    lifetime: Duration,
    now: Reading,
) -> Result<Draft, Error> {
    let fields = fields(request.headers());
    Draft::new(key, credential, &parts(request, &fields)?, nonce, lifetime, now)
}

/// Adds the four fields of `signed` to `headers`, each in place of each field of its name. Each one is sensitive
/// ([`HeaderValue::set_sensitive`]): each value changes from request to request, except the credential, which is
/// longer than the default table of HPACK. Thus an HTTP/2 or HTTP/3 encoder that keeps the mark never indexes them.
pub fn add_signature(headers: &mut HeaderMap, signed: &Signed) {
    for (name, value) in signed.fields() {
        let mut value = HeaderValue::try_from(value).expect("each field of a signature is visible ASCII");
        value.set_sensitive(true);
        headers.insert(HeaderName::from_static(name), value);
    }
}

/// Verifies the signature of the request `request` at the physical time `now` with `profile`
/// ([`Profile::verify`]), and gives the evidence of the agent. The authority is the authority of the target, which
/// HTTP/2 and HTTP/3 give, or else the one `Host` of HTTP/1.1. Read the body with the body limit of the framework
/// first.
///
/// Cost class: [`Verify`](rsauthnz::limits::Class::Verify).
///
/// # Errors
///
/// [`Error::Authority`] if the target of `request` has no authority and `request` has no one `Host`, and each error
/// of [`Profile::verify`].
pub fn verify_signature<B: AsRef<[u8]>>(
    profile: &Profile,
    request: &Request<B>,
    now: Reading,
) -> Result<Evidence, Error> {
    let fields = fields(request.headers());
    profile.verify(&parts(request, &fields)?, now)
}

/// Each field of `headers`: its name and its value. Two values of one name keep their order.
fn fields(headers: &HeaderMap) -> Vec<(&str, &[u8])> {
    headers
        .iter()
        .map(|(name, value)| (name.as_str(), value.as_bytes()))
        .collect()
}

/// The parts of `request` that a signature covers, with its `fields`.
fn parts<'a, B: AsRef<[u8]>>(
    request: &'a Request<B>,
    fields: &'a [(&'a str, &'a [u8])],
) -> Result<httpsig::Request<'a>, Error> {
    let uri = request.uri();
    let authority = match uri.authority() {
        Some(authority) => authority.as_str(),
        None => one(request.headers(), HOST)
            .and_then(|host| host.to_str().ok())
            .ok_or(Error::Authority)?,
    };
    Ok(httpsig::Request {
        method: request.method().as_str(),
        authority,
        path: uri.path(),
        query: uri.query(),
        fields,
        body: request.body().as_ref(),
    })
}
