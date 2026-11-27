//! The signatures of RFC 9421 Appendix B for the classical algorithms of the profiles: B.2.6 (Ed25519) and B.3
//! (ECDSA P-256 with SHA-256, with the 64 bytes of `r` and `s`). Each verifies over the signature base of the RFC with
//! the key of Appendix B.1. Each base of Appendix B covers `@authority`, which the profile does not cover, so the
//! tests of the profile write each base by hand from RFC 9421 section 2. B.2.1 to B.2.3 and B.2.5 use RSA-PSS and
//! HMAC, which no profile takes, and B.2.4 signs a response.

use rscodec::base64::Profile::{Standard, Url};

use super::{Error, check};
use crate::cose::{Key, PublicKey, TrustedKey};
use crate::crypto::Algorithm;
use crate::limits::{Limits, SignatureBudget};

/// The bytes of the base64 text `text` of `profile`.
fn decoded<const N: usize>(profile: rscodec::base64::Profile, text: &str) -> [u8; N] {
    let mut out = [0; N];
    profile.decode(text.as_bytes(), &mut out).unwrap();
    out
}

/// `test-key-ed25519` of RFC 9421 Appendix B.1.4.
fn ed25519() -> TrustedKey {
    let x = decoded(Url, "JrQLj5P_89iXES9-vFgrIy29clF9CC_oPPsw3c5D0bs");
    let key = Key {
        kid: None,
        alg: None,
        public: PublicKey::Ed25519(&x),
    };
    TrustedKey::new(Algorithm::Ed25519, &key).unwrap()
}

/// `test-key-ecc-p256` of RFC 9421 Appendix B.1.3.
fn p256() -> TrustedKey {
    let x = decoded(Url, "qIVYZVLCrPZHGHjP17CTW0_-D9Lfw0EkjqF7xB4FivA");
    let y = decoded(Url, "Mc4nN9LTDOBhfoUeg8Ye9WedFRhnZXZJA12Qp0zZ6F0");
    let key = Key {
        kid: None,
        alg: None,
        public: PublicKey::P256 { x: &x, y: &y },
    };
    TrustedKey::new(Algorithm::Es256, &key).unwrap()
}

/// The check of the signature `signature`, the base64 text of 64 bytes, over `base` with `key`.
fn verify(key: &TrustedKey, base: &str, signature: &str) -> Result<(), Error> {
    let signature: [u8; 64] = decoded(Standard, signature);
    check(
        key,
        base.as_bytes(),
        &signature,
        &mut SignatureBudget::new(&Limits::default()),
    )
}

#[test]
fn the_ed25519_signature_of_b_2_6_and_the_p256_signature_of_b_3_verify_over_their_bases() {
    const CERT: &str = ":MIIBqDCCAU6gAwIBAgIBBzAKBggqhkjOPQQDAjA6MRswGQYDVQQKDBJMZXQncyBBdXRoZW50aWNhdGUxGzAZBgNVBAMMEkxBIEludGVybWVkaWF0ZSBDQTAeFw0yMDAxMTQyMjU1MzNaFw0yMTAxMjMyMjU1MzNaMA0xCzAJBgNVBAMMAkJDMFkwEwYHKoZIzj0CAQYIKoZIzj0DAQcDQgAE8YnXXfaUgmnMtOXU/IncWalRhebrXmckC8vdgJ1p5Be5F/3YC8OthxM4+k1M6aEAEFcGzkJiNy6J84y7uzo9M6NyMHAwCQYDVR0TBAIwADAfBgNVHSMEGDAWgBRm3WjLa38lbEYCuiCPct0ZaSED2DAOBgNVHQ8BAf8EBAMCBsAwEwYDVR0lBAwwCgYIKwYBBQUHAwIwHQYDVR0RAQH/BBMwEYEPYmRjQGV4YW1wbGUuY29tMAoGCCqGSM49BAMCA0gAMEUCIBHda/r1vaL6G3VliL4/Di6YK0Q6bMjeSkC3dFCOOB8TAiEAx/kHSB4urmiZ0NX5r5XarmPk0wmuydBVoU4hBVZ1yhk=:";
    let b_2_6 = concat!(
        "\"date\": Tue, 20 Apr 2021 02:07:55 GMT\n",
        "\"@method\": POST\n",
        "\"@path\": /foo\n",
        "\"@authority\": example.com\n",
        "\"content-type\": application/json\n",
        "\"content-length\": 18\n",
        r#""@signature-params": ("date" "@method" "@path" "@authority" "content-type" "content-length");created=1618884473;keyid="test-key-ed25519""#,
    );
    let b_2_6_signature = "wqcAqbmYJ2ji2glfAMaRy4gruYYnx2nEFN2HN6jrnDnQCK1u02Gb04v9EDgwUPiu4A0w6vuQv5lIp5WPpBKRCw==";
    assert_eq!(verify(&ed25519(), b_2_6, b_2_6_signature), Ok(()));
    let b_3 = [
        "\"@path\": /foo\n",
        "\"@query\": ?param=Value&Pet=dog\n",
        "\"@method\": POST\n",
        "\"@authority\": service.internal.example\n",
        &format!("\"client-cert\": {CERT}\n"),
        r#""@signature-params": ("@path" "@query" "@method" "@authority" "client-cert");created=1618884473;keyid="test-key-ecc-p256""#,
    ]
    .concat();
    let b_3_signature = "xVMHVpawaAC/0SbHrKRs9i8I3eOs5RtTMGCWXm/9nvZzoHsIg6Mce9315T6xoklyy0yzhD9ah4JHRwMLOgmizw==";
    assert_eq!(verify(&p256(), &b_3, b_3_signature), Ok(()));
}
