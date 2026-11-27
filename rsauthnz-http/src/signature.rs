//! The `http` mapping of the HTTP message signatures of an agent ([`rsauthnz::httpsig`]).

use core::time::Duration;

use http::Request;
use http::header::{HeaderMap, HeaderName, HeaderValue};
use rsauthnz::cose::TrustedKey;
use rsauthnz::httpsig::{self, Checked, Draft, Error, NONCE_BYTES, Profile, Signed};
use rsauthnz::time::Reading;

/// The draft of the signature of the request `request` of an agent by its key `key`, the `cnf` key of `credential`,
/// as [`Draft::new`] gives it. Custody signs `draft.to_be_signed()`, and [`Draft::finish`] gives the fields that
/// [`add_signature`] adds.
///
/// Cost class: [`Parse`](rsauthnz::limits::Class::Parse).
///
/// # Errors
///
/// Each error of [`Draft::new`].
pub fn signature_draft<B: AsRef<[u8]>>(
    key: &TrustedKey,
    credential: &[u8],
    request: &Request<B>,
    nonce: &[u8; NONCE_BYTES],
    lifetime: Duration,
    now: Reading,
) -> Result<Draft, Error> {
    let fields = fields(request.headers());
    Draft::new(key, credential, &parts(request, &fields), nonce, lifetime, now)
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
/// ([`Profile::verify`]), and gives the [`Checked`] signature. Its replay insert gives the evidence of the agent
/// ([`Checked::accept`], [`Checked::check_agent`]). It reads no authority, so a proxy can change `Host` or `:authority`.
/// Read the body with the body limit of the framework first.
///
/// Cost class: [`Verify`](rsauthnz::limits::Class::Verify).
///
/// # Errors
///
/// Each error of [`Profile::verify`].
pub fn verify_signature<B: AsRef<[u8]>>(
    profile: &Profile,
    request: &Request<B>,
    now: Reading,
) -> Result<Checked, Error> {
    let fields = fields(request.headers());
    profile.verify(&parts(request, &fields), now)
}

/// Each field of `headers`: its name and its value. Two values of one name keep their order.
fn fields(headers: &HeaderMap) -> Vec<(&str, &[u8])> {
    headers
        .iter()
        .map(|(name, value)| (name.as_str(), value.as_bytes()))
        .collect()
}

/// The parts of `request` that a signature covers, with its `fields`.
fn parts<'a, B: AsRef<[u8]>>(request: &'a Request<B>, fields: &'a [(&'a str, &'a [u8])]) -> httpsig::Request<'a> {
    let uri = request.uri();
    httpsig::Request {
        method: request.method().as_str(),
        path: uri.path(),
        query: uri.query(),
        fields,
        body: request.body().as_ref(),
    }
}
