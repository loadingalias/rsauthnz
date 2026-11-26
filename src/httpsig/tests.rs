//! The vectors of RFC 9421 Appendix B for the algorithms of the profiles over a request: B.2.6 (Ed25519), B.3 (ECDSA
//! P-256 with SHA-256), and B.4 (Ed25519 over transformed messages). Each case builds the signature base from the
//! message and the `Signature-Input` of the RFC, and checks the signature of the RFC with the key of Appendix B.1.
//! B.2.1 to B.2.3 and B.2.5 use RSA-PSS and HMAC, which no profile takes, and B.2.4 signs a response.

use alloc::vec::Vec;

use rscodec::base64::Profile::Url;

use super::sf::{self, Member};
use super::{Error, Request, base, bytes, check};
use crate::cose::{Key, PublicKey, TrustedKey};
use crate::crypto::Algorithm;
use crate::limits::{Limits, SignatureBudget};

/// The base64url bytes of `text`.
fn decoded<const N: usize>(text: &str) -> [u8; N] {
    let mut out = [0; N];
    Url.decode(text.as_bytes(), &mut out).unwrap();
    out
}

/// `test-key-ed25519` of RFC 9421 Appendix B.1.4.
fn ed25519() -> TrustedKey {
    let x = decoded("JrQLj5P_89iXES9-vFgrIy29clF9CC_oPPsw3c5D0bs");
    let key = Key {
        kid: None,
        alg: None,
        public: PublicKey::Ed25519(&x),
    };
    TrustedKey::new(Algorithm::Ed25519, &key).unwrap()
}

/// `test-key-ecc-p256` of RFC 9421 Appendix B.1.3.
fn p256() -> TrustedKey {
    let x = decoded("qIVYZVLCrPZHGHjP17CTW0_-D9Lfw0EkjqF7xB4FivA");
    let y = decoded("Mc4nN9LTDOBhfoUeg8Ye9WedFRhnZXZJA12Qp0zZ6F0");
    let key = Key {
        kid: None,
        alg: None,
        public: PublicKey::P256 { x: &x, y: &y },
    };
    TrustedKey::new(Algorithm::Es256, &key).unwrap()
}

/// The signature base of `request` for its one `Signature-Input` member, and the check of its one `Signature` member
/// with `key`.
fn verify(request: &Request<'_>, input: &str, signature: &str, key: &TrustedKey) -> (Vec<u8>, Result<(), Error>) {
    let inputs = sf::dictionary(input.as_bytes(), &Limits::default()).unwrap();
    let [(_, Member::List(components, parameters))] = inputs.as_slice() else {
        panic!("one signature")
    };
    let base = base(request, components, parameters, &Limits::default()).unwrap();
    let signatures = sf::dictionary(signature.as_bytes(), &Limits::default()).unwrap();
    let signature = bytes(&signatures[0].1, 64).unwrap();
    let checked = check(key, &base, &signature, &mut SignatureBudget::new(&Limits::default()));
    (base, checked)
}

/// The `test-request` message of RFC 9421 Appendix B.2.
fn test_request<'a>(fields: &'a [(&'a str, &'a [u8])]) -> Request<'a> {
    Request {
        method: "POST",
        authority: "example.com",
        path: "/foo",
        query: Some("param=Value&Pet=dog"),
        fields,
        body: br#"{"hello": "world"}"#,
    }
}

#[test]
fn the_ed25519_request_of_b_2_6_has_its_base_and_its_signature_verifies() {
    let fields: &[(&str, &[u8])] = &[
        ("date", b"Tue, 20 Apr 2021 02:07:55 GMT"),
        ("content-type", b"application/json"),
        (
            "content-digest",
            b"sha-512=:WZDPaVn/7XgHaAy8pmojAkGWoRx2UFChF41A2svX+TaPm+AbwAgBWnrIiYllu7BNNyealdVLvRwEmTHWXvJwew==:",
        ),
        ("content-length", b"18"),
    ];
    let (base, checked) = verify(
        &test_request(fields),
        r#"sig-b26=("date" "@method" "@path" "@authority" "content-type" "content-length");created=1618884473;keyid="test-key-ed25519""#,
        "sig-b26=:wqcAqbmYJ2ji2glfAMaRy4gruYYnx2nEFN2HN6jrnDnQCK1u02Gb04v9EDgwUPiu4A0w6vuQv5lIp5WPpBKRCw==:",
        &ed25519(),
    );
    let expected = concat!(
        "\"date\": Tue, 20 Apr 2021 02:07:55 GMT\n",
        "\"@method\": POST\n",
        "\"@path\": /foo\n",
        "\"@authority\": example.com\n",
        "\"content-type\": application/json\n",
        "\"content-length\": 18\n",
        r#""@signature-params": ("date" "@method" "@path" "@authority" "content-type" "content-length");created=1618884473;keyid="test-key-ed25519""#,
    );
    assert_eq!(base, expected.as_bytes());
    assert_eq!(checked, Ok(()));
}

#[test]
fn the_p256_signature_of_the_proxy_of_b_3_has_its_base_and_verifies() {
    const CERT: &str = ":MIIBqDCCAU6gAwIBAgIBBzAKBggqhkjOPQQDAjA6MRswGQYDVQQKDBJMZXQncyBBdXRoZW50aWNhdGUxGzAZBgNVBAMMEkxBIEludGVybWVkaWF0ZSBDQTAeFw0yMDAxMTQyMjU1MzNaFw0yMTAxMjMyMjU1MzNaMA0xCzAJBgNVBAMMAkJDMFkwEwYHKoZIzj0CAQYIKoZIzj0DAQcDQgAE8YnXXfaUgmnMtOXU/IncWalRhebrXmckC8vdgJ1p5Be5F/3YC8OthxM4+k1M6aEAEFcGzkJiNy6J84y7uzo9M6NyMHAwCQYDVR0TBAIwADAfBgNVHSMEGDAWgBRm3WjLa38lbEYCuiCPct0ZaSED2DAOBgNVHQ8BAf8EBAMCBsAwEwYDVR0lBAwwCgYIKwYBBQUHAwIwHQYDVR0RAQH/BBMwEYEPYmRjQGV4YW1wbGUuY29tMAoGCCqGSM49BAMCA0gAMEUCIBHda/r1vaL6G3VliL4/Di6YK0Q6bMjeSkC3dFCOOB8TAiEAx/kHSB4urmiZ0NX5r5XarmPk0wmuydBVoU4hBVZ1yhk=:";
    let fields: &[(&str, &[u8])] = &[
        ("date", b"Tue, 20 Apr 2021 02:07:55 GMT"),
        ("content-type", b"application/json"),
        ("content-length", b"18"),
        ("client-cert", CERT.as_bytes()),
    ];
    let request = Request {
        authority: "service.internal.example",
        ..test_request(fields)
    };
    let (base, checked) = verify(
        &request,
        r#"ttrp=("@path" "@query" "@method" "@authority" "client-cert");created=1618884473;keyid="test-key-ecc-p256""#,
        "ttrp=:xVMHVpawaAC/0SbHrKRs9i8I3eOs5RtTMGCWXm/9nvZzoHsIg6Mce9315T6xoklyy0yzhD9ah4JHRwMLOgmizw==:",
        &p256(),
    );
    let expected = [
        "\"@path\": /foo\n",
        "\"@query\": ?param=Value&Pet=dog\n",
        "\"@method\": POST\n",
        "\"@authority\": service.internal.example\n",
        &format!("\"client-cert\": {CERT}\n"),
        r#""@signature-params": ("@path" "@query" "@method" "@authority" "client-cert");created=1618884473;keyid="test-key-ecc-p256""#,
    ]
    .concat();
    assert_eq!(base, expected.as_bytes());
    assert_eq!(checked, Ok(()));
}

/// The checks of the signature of RFC 9421 Appendix B.4 over each message of that section: the signed message, three
/// allowed transformations, which verify, and two changes of a covered component, which refuse.
#[test]
fn the_ed25519_signature_of_b_4_survives_each_allowed_transformation_and_no_covered_change() {
    const INPUT: &str =
        r#"transform=("@method" "@path" "@authority" "accept");created=1618884473;keyid="test-key-ed25519""#;
    const SIGNATURE: &str =
        "transform=:ZT1kooQsEHpZ0I1IjCqtQppOmIqlJPeo7DHR3SoMn0s5JZ1eRGS0A+vyYP9t/LXlh5QMFFQ6cpLt2m0pmj3NDA==:";
    let demo = |method, authority, query, fields| Request {
        method,
        authority,
        path: "/demo",
        query: Some(query),
        fields,
        body: b"",
    };
    let date = ("date", &b"Fri, 15 Jul 2022 14:24:55 GMT"[..]);
    let (json, any) = (("accept", &b"application/json"[..]), ("accept", &b"*/*"[..]));
    let signed = [date, json, any];
    let added = [date, json, any, ("accept-language", b"en-US,en;q=0.5")];
    let collapsed = [
        ("referer", &b"https://developer.example.org/demo"[..]),
        ("accept", b"application/json, */*"),
    ];
    let reordered = [json, any, date];
    let swapped = [date, any, json];
    let cases: [(Request<'_>, Result<(), Error>); 6] = [
        (demo("GET", "example.org", "name1=Value1&Name2=value2", &signed), Ok(())),
        (
            demo("GET", "example.org", "name1=Value1&Name2=value2&param=added", &added),
            Ok(()),
        ),
        (
            demo("GET", "example.org", "name1=Value1&Name2=value2", &collapsed),
            Ok(()),
        ),
        (
            demo("GET", "example.org", "name1=Value1&Name2=value2", &reordered),
            Ok(()),
        ),
        (
            demo("POST", "example.com", "name1=Value1&Name2=value2", &signed),
            Err(Error::Signature),
        ),
        (
            demo("GET", "example.org", "name1=Value1&Name2=value2", &swapped),
            Err(Error::Signature),
        ),
    ];
    for (at, (request, expected)) in cases.iter().enumerate() {
        let (base, checked) = verify(request, INPUT, SIGNATURE, &ed25519());
        assert_eq!(checked, *expected, "message {at}");
        if at == 0 {
            let expected = concat!(
                "\"@method\": GET\n",
                "\"@path\": /demo\n",
                "\"@authority\": example.org\n",
                "\"accept\": application/json, */*\n",
                r#""@signature-params": ("@method" "@path" "@authority" "accept");created=1618884473;keyid="test-key-ed25519""#,
            );
            assert_eq!(base, expected.as_bytes());
        }
    }
}
