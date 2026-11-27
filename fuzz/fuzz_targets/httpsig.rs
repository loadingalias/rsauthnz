//! HTTP message signatures: `httpsig::Profile::verify` of an untrusted request, with the limits that the input draws
//! (`rsauthnz_fuzz::drawn`). The input holds the values of `Signature-Input`, `Signature`, `Content-Digest`, and
//! `Agent-Credential`, and then the body, with a zero byte after each value. A `Signature-Input` over the byte bound
//! refuses, and no request verifies: no input has a signature of the key of a credential.
#![no_main]

use libfuzzer_sys::fuzz_target;
use rsauthnz::credential;
use rsauthnz::httpsig::{Error, Field, Profile, Request};
use rsauthnz::id::Id;
use rsauthnz_fuzz::{drawn, issuer, now};

fuzz_target!(|data: &[u8]| {
    let Some((input, limits)) = drawn(data) else {
        return;
    };
    let mut values = input.splitn(5, |&byte| byte == 0);
    let mut next = || values.next().unwrap_or_default();
    let fields = [
        ("signature-input", next()),
        ("signature", next()),
        ("content-digest", next()),
        ("agent-credential", next()),
    ];
    let body = next();
    let credentials = credential::Profile::new(
        issuer(),
        Id::new("acme", "auth").expect("an identifier"),
        Id::new("acme", "app").expect("an identifier"),
        Id::new("acme", "deploy").expect("an identifier"),
        limits,
    )
    .expect("a profile");
    let profile = Profile::new(credentials);
    let request = Request {
        method: "POST",
        path: "/",
        query: None,
        fields: &fields,
        body,
    };
    let checked = profile.verify(&request, now());
    if fields[0].1.trim_ascii().len() > limits.bytes {
        assert_eq!(
            checked.as_ref().err(),
            Some(&Error::Field(Field::SignatureInput)),
            "a field over the byte bound passed its parse"
        );
    }
    assert!(checked.is_err(), "a request of the fuzzer verified");
});
