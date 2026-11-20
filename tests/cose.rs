//! The contracts of COSE and CWT verification: the RFC 9052 and RFC 8392 vectors, the trusted profile, the critical
//! headers, the audience, the validity interval, and the evidence.

use core::time::Duration;

use rsauthnz::cbor::{Value, encode};
use rsauthnz::cose::{Claims, Confirmation, Error, Key, Profile, PublicKey, Sign1, TrustedKey, Verified};
use rsauthnz::crypto::Algorithm;
use rsauthnz::id::Id;
use rsauthnz::limits::{Limits, SignatureBudget};
use rsauthnz::time::{Reading, ReadingSource, TimeError};
use rscrypto::auth::{CompositeMlDsaError, Ed25519SecretKey, MlDsa65EcdsaP256, MlDsa65Ed25519, MlDsa65Seed};

/// The bytes of a string of hexadecimal digits.
fn hex(digits: &str) -> Vec<u8> {
    digits
        .as_bytes()
        .chunks(2)
        .map(|pair| u8::from_str_radix(core::str::from_utf8(pair).expect("ASCII"), 16).expect("hexadecimal"))
        .collect()
}

/// A reading of `seconds` since the Unix epoch, with an uncertainty bound of `bound` seconds.
fn reading(seconds: u64, bound: u64) -> Reading {
    Reading::new(
        Duration::from_secs(seconds),
        Some(Duration::from_secs(bound)),
        ReadingSource::Caller,
    )
}

fn profile(algorithm: Algorithm, public: PublicKey<'_>, issuer: &str, audience: &str) -> Profile {
    let key = Key {
        kid: None,
        alg: None,
        public,
    };
    Profile {
        key: TrustedKey::new(algorithm, &key).expect("the key fits the algorithm"),
        issuer: issuer.into(),
        audience: audience.into(),
        purpose: Id::new("test", "credential").expect("identifier"),
        limits: Limits::default(),
    }
}

/// Verifies `artifact` with `profile`, with the signature budget of the limits of the profile.
fn verify<'a, 'p>(profile: &'p Profile, artifact: &'a [u8], now: Reading) -> Result<Verified<'a, 'p>, Error> {
    profile.verify(artifact, now, &mut SignatureBudget::new(&profile.limits))
}

/// A tagged `COSE_Sign1` with an empty external AAD. `sign` signs the `Sig_structure` of RFC 9052 section 4.4.
fn sign1(protected: &Value<'_>, unprotected: Value<'_>, payload: &[u8], sign: impl Fn(&[u8]) -> Vec<u8>) -> Vec<u8> {
    let protected = encode(protected).expect("protected header");
    let to_be_signed = encode(&Value::Array(vec![
        Value::Text("Signature1"),
        Value::Bytes(&protected),
        Value::Bytes(&[]),
        Value::Bytes(payload),
    ]))
    .expect("Sig_structure");
    let signature = sign(&to_be_signed);
    encode(&Value::Tag(
        18,
        Box::new(Value::Array(vec![
            Value::Bytes(&protected),
            unprotected,
            Value::Bytes(payload),
            Value::Bytes(&signature),
        ])),
    ))
    .expect("COSE_Sign1")
}

/// The protected header `{1: alg}` with the COSE algorithm `-1 - n`.
fn alg(n: u64) -> Value<'static> {
    Value::Map(vec![(Value::Unsigned(1), Value::Negative(n))])
}

/// The claims `{iss, aud, exp, nbf}`.
fn claims(issuer: &str, audience: &str, exp: u64, nbf: u64) -> Vec<u8> {
    encode(&Value::Map(vec![
        (Value::Unsigned(1), Value::Text(issuer)),
        (Value::Unsigned(3), Value::Text(audience)),
        (Value::Unsigned(4), Value::Unsigned(exp)),
        (Value::Unsigned(5), Value::Unsigned(nbf)),
    ]))
    .expect("claims")
}

const ED25519: u64 = 18;
const ES256: u64 = 6;

fn ed25519() -> Ed25519SecretKey {
    Ed25519SecretKey::from_bytes([7; 32])
}

fn ed25519_sign(message: &[u8]) -> Vec<u8> {
    ed25519().sign(message).to_bytes().to_vec()
}

fn ed25519_profile(audience: &str) -> Profile {
    let public = ed25519().public_key().to_bytes();
    profile(
        Algorithm::Ed25519,
        PublicKey::Ed25519(&public),
        "https://issuer.example",
        audience,
    )
}

#[test]
fn rfc_9052_c_2_1_sign1_verifies_and_a_changed_payload_refuses() {
    // Key "11" of RFC 9052 C.7.1 as a COSE_Key, in deterministic order: kty 2, kid '11', crv 1, x, y.
    let key = hex(concat!(
        "a50102024231312001215820bac5b11cad8f99f9c72b05cf4b9e26d244dc189f745228255a219a86d6a09eff",
        "22582020138bf82dc1b6d562be0fa54ab7804a3a64b6d72ccfed6b6fb6ed28bbfc117e",
    ));
    let key = Key::decode(&key, Limits::default()).expect("key 11");
    assert_eq!(key.kid, Some(&b"11"[..]));
    let key = TrustedKey::new(Algorithm::Es256, &key).expect("a P-256 key");

    let mut message = hex(concat!(
        "d28443a10126a10442313154546869732069732074686520636f6e74656e742e58408eb33e4ca31d1c465ab05aac34cc6b23",
        "d58fef5c083106c4d25a91aef0b0117e2af9a291aa32e14ab834dc56ed2a223444547e01f11d3b0916e5a4c345cacb36",
    ));
    let sign1 = Sign1::decode(&message, Limits::default()).expect("C.2.1");
    assert_eq!(
        sign1.verify(&key, &mut SignatureBudget::new(&Limits::default())),
        Ok(&b"This is the content."[..])
    );

    // The last byte of the payload, '.', becomes '!'.
    message[31] = b'!';
    let sign1 = Sign1::decode(&message, Limits::default()).expect("a changed C.2.1");
    assert_eq!(
        sign1.verify(&key, &mut SignatureBudget::new(&Limits::default())),
        Err(Error::Signature)
    );
}

#[test]
fn rfc_8392_a_3_cwt_verifies_with_the_claims_of_a_1() {
    let cwt = hex(concat!(
        "d28443a10126a104524173796d6d657472696345434453413235365850a70175636f61703a2f2f61732e6578616d706c652e",
        "636f6d02656572696b77037818636f61703a2f2f6c696768742e6578616d706c652e636f6d041a5612aeb0051a5610d9f006",
        "1a5610d9f007420b7158405427c1ff28d23fbad1f29c4c7c6a555e601d6fa29f9179bc3d7438bacaca5acd08c8d4d4f96131",
        "680c429a01f85951ecee743a52b9b63632c57209120e1c9e30",
    ));
    let x = hex("143329cce7868e416927599cf65a34f3ce2ffda55a7eca69ed8919a394d42f0f");
    let y = hex("60f7f1a780d8a783bfb7a2dd6b2796e8128dbbcef9d3d168db9529971a36e7b9");
    let public = PublicKey::P256 {
        x: x[..].try_into().expect("x"),
        y: y[..].try_into().expect("y"),
    };
    let profile = profile(
        Algorithm::Es256,
        public,
        "coap://as.example.com",
        "coap://light.example.com",
    );

    // Between nbf (1443944944) and exp (1444064944).
    let verified = verify(&profile, &cwt, reading(1_444_000_000, 60)).expect("A.3");
    assert_eq!(verified.artifact(), &cwt[..]);
    assert_eq!(verified.not_before(), Some(Duration::from_secs(1_443_944_944)));
    assert_eq!(verified.expires(), Duration::from_secs(1_444_064_944));

    // The payload of A.3 is the claims set of A.1, in Figure 2. Figure 3 gives its values.
    let a1 = hex(concat!(
        "a70175636f61703a2f2f61732e6578616d706c652e636f6d02656572696b77037818636f61703a2f2f6c696768742e657861",
        "6d706c652e636f6d041a5612aeb0051a5610d9f0061a5610d9f007420b71",
    ));
    let claims = Claims::decode(&a1, Limits::default()).expect("A.1");
    assert_eq!(&claims, verified.claims());
    assert_eq!(claims.iss, Some("coap://as.example.com"));
    assert_eq!(claims.sub, Some("erikw"));
    assert_eq!(claims.aud, ["coap://light.example.com"]);
    assert_eq!(claims.exp, Some(Duration::from_secs(1_444_064_944)));
    assert_eq!(claims.nbf, Some(Duration::from_secs(1_443_944_944)));
    assert_eq!(claims.iat, Some(Duration::from_secs(1_443_944_944)));
    assert_eq!(claims.cti, Some(&[0x0b, 0x71][..]));
}

#[test]
fn a_header_alg_that_differs_from_the_profile_refuses() {
    let profile = ed25519_profile("https://rp.example");
    let payload = claims("https://issuer.example", "https://rp.example", 2_000, 0);
    let now = reading(1_000, 1);
    let empty = Value::Map(vec![]);

    // The control: the algorithm of the profile verifies.
    let valid = sign1(&alg(ED25519), empty.clone(), &payload, ed25519_sign);
    verify(&profile, &valid, now).unwrap();

    // The Ed25519 key signs, but the protected header says ES256. A verifier that dispatches on the header fails here.
    let es256 = sign1(&alg(ES256), empty.clone(), &payload, ed25519_sign);
    assert_eq!(verify(&profile, &es256, now), Err(Error::AlgorithmMismatch));

    // No `alg`, and an `alg` in the unprotected bucket, which the signature does not cover.
    let none = sign1(&Value::Map(vec![]), empty, &payload, ed25519_sign);
    assert_eq!(verify(&profile, &none, now), Err(Error::AlgorithmMismatch));
    let unprotected = sign1(&Value::Map(vec![]), alg(ED25519), &payload, ed25519_sign);
    assert_eq!(verify(&profile, &unprotected, now), Err(Error::AlgorithmMismatch));
}

#[test]
fn an_unknown_critical_header_refuses_and_an_unknown_optional_header_stays() {
    let profile = ed25519_profile("https://rp.example");
    let payload = claims("https://issuer.example", "https://rp.example", 2_000, 0);
    let now = reading(1_000, 1);
    let protected = |critical: Option<Value<'static>>| {
        let mut header = vec![
            (Value::Unsigned(1), Value::Negative(ED25519)),
            (Value::Unsigned(4), Value::Bytes(b"k1")),
            (Value::Negative(69_999), Value::Unsigned(1)),
        ];
        header.extend(critical.map(|labels| (Value::Unsigned(2), labels)));
        Value::Map(header)
    };

    // Label -70000 is not a header that this crate processes.
    let critical = Value::Array(vec![Value::Negative(69_999)]);
    let refused = sign1(&protected(Some(critical)), Value::Map(vec![]), &payload, ed25519_sign);
    assert_eq!(verify(&profile, &refused, now), Err(Error::UnknownCritical));

    // A critical `kid` is a header that this crate processes.
    let critical = Value::Array(vec![Value::Unsigned(4)]);
    let kid = sign1(&protected(Some(critical)), Value::Map(vec![]), &payload, ed25519_sign);
    verify(&profile, &kid, now).unwrap();

    // Without `crit`, the unknown header is optional: it stays in its bucket, and it has no effect.
    let optional = sign1(&protected(None), Value::Map(vec![]), &payload, ed25519_sign);
    verify(&profile, &optional, now).unwrap();
    let sign1 = Sign1::decode(&optional, Limits::default()).expect("COSE_Sign1");
    assert_eq!(sign1.protected().get(-70_000), Some(&Value::Unsigned(1)));
}

#[test]
fn a_signature_valid_under_another_audience_or_issuer_refuses() {
    let profile = ed25519_profile("https://rp-a.example");
    let now = reading(1_000, 1);
    let empty = Value::Map(vec![]);

    let other_audience = claims("https://issuer.example", "https://rp-b.example", 2_000, 0);
    let artifact = sign1(&alg(ED25519), empty.clone(), &other_audience, ed25519_sign);
    verify(&ed25519_profile("https://rp-b.example"), &artifact, now).unwrap();
    assert_eq!(verify(&profile, &artifact, now), Err(Error::Audience));

    let other_issuer = claims("https://other.example", "https://rp-a.example", 2_000, 0);
    let artifact = sign1(&alg(ED25519), empty, &other_issuer, ed25519_sign);
    assert_eq!(verify(&profile, &artifact, now), Err(Error::Issuer));
}

#[test]
fn evidence_compares_equal_only_for_the_exact_artifact_bytes() {
    let profile = ed25519_profile("https://rp.example");
    let payload = claims("https://issuer.example", "https://rp.example", 2_000, 0);
    let now = reading(1_000, 1);
    let artifact = sign1(&alg(ED25519), Value::Map(vec![]), &payload, ed25519_sign);

    let first = verify(&profile, &artifact, now).expect("artifact");
    let again = artifact.clone();
    assert_eq!(first, verify(&profile, &again, now).expect("the same bytes"));

    // The signature does not cover the unprotected bucket. A `kid` there gives other bytes with the same claims.
    let kid = Value::Map(vec![(Value::Unsigned(4), Value::Bytes(b"k1"))]);
    let other = sign1(&alg(ED25519), kid, &payload, ed25519_sign);
    let second = verify(&profile, &other, now).expect("other bytes");
    assert_eq!(first.claims(), second.claims());
    assert_ne!(first, second);
}

#[test]
fn validity_needs_exp_and_a_known_bound_over_the_whole_reading() {
    let profile = ed25519_profile("https://rp.example");
    let signed = |exp: Option<u64>| {
        let mut claims = vec![
            (Value::Unsigned(1), Value::Text("https://issuer.example")),
            (Value::Unsigned(3), Value::Text("https://rp.example")),
            (Value::Unsigned(5), Value::Unsigned(500)),
        ];
        claims.extend(exp.map(|exp| (Value::Unsigned(4), Value::Unsigned(exp))));
        sign1(
            &alg(ED25519),
            Value::Map(vec![]),
            &encode(&Value::Map(claims)).expect("claims"),
            ed25519_sign,
        )
    };
    let artifact = signed(Some(1_000));

    // Each time of the reading must be in [nbf, exp).
    verify(&profile, &artifact, reading(989, 10)).unwrap();
    assert_eq!(verify(&profile, &artifact, reading(990, 10)), Err(Error::Expired));
    verify(&profile, &artifact, reading(510, 10)).unwrap();
    assert_eq!(verify(&profile, &artifact, reading(509, 10)), Err(Error::NotYetValid));

    let unknown = Reading::new(Duration::from_secs(700), None, ReadingSource::SystemClock);
    assert_eq!(
        verify(&profile, &artifact, unknown),
        Err(Error::Time(TimeError::UnknownBound))
    );
    assert_eq!(verify(&profile, &signed(None), reading(700, 1)), Err(Error::NoExpiry));
}

#[test]
fn an_ml_dsa_65_profile_verifies_its_signature() {
    // The pure signature with the empty context, as RFC 9964 requires.
    let (public, secret) = MlDsa65Seed::from_bytes([9; 32]).keypair().expect("ML-DSA-65 key pair");
    let public = public.to_bytes();
    let profile = profile(
        Algorithm::MlDsa65,
        PublicKey::MlDsa65(&public),
        "https://issuer.example",
        "https://rp.example",
    );
    let payload = claims("https://issuer.example", "https://rp.example", 2_000, 0);
    let artifact = sign1(&alg(48), Value::Map(vec![]), &payload, |message| {
        secret
            .sign_deterministic(message, &[])
            .expect("ML-DSA-65 signature")
            .to_bytes()
            .to_vec()
    });
    verify(&profile, &artifact, reading(1_000, 1)).unwrap();
}

/// Verifies a signed CWT of the composite `algorithm` with the `AKP` key `public`. `sign` signs the `Sig_structure`.
fn verify_composite(algorithm: Algorithm, public: &[u8], sign: impl Fn(&[u8]) -> Vec<u8>) {
    // The draft identifier comes from the profile, so a change of the draft changes only its constant.
    let cose = algorithm.report().cose.expect("a composite has a COSE identifier");
    let n = u64::try_from(-1 - cose).expect("a negative identifier");
    let akp = encode(&Value::Map(vec![
        (Value::Unsigned(1), Value::Unsigned(7)),
        (Value::Unsigned(3), Value::Negative(n)),
        (Value::Negative(0), Value::Bytes(public)),
    ]))
    .expect("AKP");
    let key = Key::decode(&akp, Limits::default()).expect("a composite AKP key");
    let profile = Profile {
        key: TrustedKey::new(algorithm, &key).expect("the key fits the algorithm"),
        issuer: "https://issuer.example".into(),
        audience: "https://rp.example".into(),
        purpose: Id::new("test", "credential").expect("identifier"),
        limits: Limits::default(),
    };
    let payload = claims("https://issuer.example", "https://rp.example", 2_000, 0);
    let artifact = sign1(&alg(n), Value::Map(vec![]), &payload, sign);

    // The composite is two checks: the default budget of one artifact.
    let mut budget = SignatureBudget::new(&profile.limits);
    profile
        .verify(&artifact, reading(1_000, 1), &mut budget)
        .expect("the composite artifact");
    assert_eq!(budget.remaining(), 0, "{algorithm:?}");
}

#[test]
fn a_composite_profile_verifies_its_akp_key_and_its_signature() {
    // A fixed filler makes the keys reproducible. The signatures are the deterministic form of rscrypto.
    let fill = |out: &mut [u8]| -> Result<(), CompositeMlDsaError> {
        out.fill(7);
        Ok(())
    };
    let (public, secret) = MlDsa65Ed25519::generate_keypair(fill).expect("an ML-DSA-65 + Ed25519 key");
    verify_composite(Algorithm::MlDsa65Ed25519, &public.to_bytes(), |message| {
        secret
            .sign_deterministic(message, &[])
            .expect("signature")
            .as_bytes()
            .to_vec()
    });
    let (public, secret) = MlDsa65EcdsaP256::generate_keypair(fill).expect("an ML-DSA-65 + ECDSA P-256 key");
    verify_composite(Algorithm::MlDsa65EcdsaP256, &public.to_bytes(), |message| {
        secret
            .sign_deterministic(message, &[])
            .expect("signature")
            .as_bytes()
            .to_vec()
    });
}

#[test]
fn cose_keys_and_cnf_decode_and_a_private_key_refuses() {
    // The COSE_Key of the cnf example of RFC 8747 section 3.2.
    let x = hex("d7cc072de2205bdc1537a543d53c60a6acb62eccd890c7fa27c9e354089bbe13");
    let y = hex("f95e1d4b851a2cc80fff87d8e23f22afb725d535e515d020731e79a3b4e47120");
    let ec2 = |extra: Option<(Value<'static>, Value<'static>)>| {
        let mut key = vec![
            (Value::Unsigned(1), Value::Unsigned(2)),
            (Value::Negative(0), Value::Unsigned(1)),
            (Value::Negative(1), Value::Bytes(&x)),
            (Value::Negative(2), Value::Bytes(&y)),
        ];
        key.extend(extra);
        Value::Map(key)
    };
    let cnf = |member: u64, value: Value<'_>| {
        encode(&Value::Map(vec![
            (Value::Unsigned(1), Value::Text("coaps://server.example.com")),
            (Value::Unsigned(8), Value::Map(vec![(Value::Unsigned(member), value)])),
        ]))
        .expect("claims")
    };
    let expected = Key {
        kid: None,
        alg: None,
        public: PublicKey::P256 {
            x: x[..].try_into().expect("x"),
            y: y[..].try_into().expect("y"),
        },
    };
    let with_key = cnf(1, ec2(None));
    let claims = Claims::decode(&with_key, Limits::default()).expect("cnf with a COSE_Key");
    assert_eq!(claims.cnf, Some(Confirmation::Key(expected)));

    // The kid example of RFC 8747 section 3.4.
    let kid = hex("dfd1aa976d8d4575a0fe34b96de2bfad");
    let with_kid = cnf(3, Value::Bytes(&kid));
    let claims = Claims::decode(&with_kid, Limits::default()).expect("cnf with a kid");
    assert_eq!(claims.cnf, Some(Confirmation::KeyId(&kid)));

    // A private key `d` (-4) in a confirmation key, and an encrypted key, refuse.
    let private = cnf(1, ec2(Some((Value::Negative(3), Value::Bytes(&[1; 32])))));
    assert_eq!(Claims::decode(&private, Limits::default()), Err(Error::Unsupported));
    let encrypted = cnf(2, Value::Array(vec![]));
    assert_eq!(Claims::decode(&encrypted, Limits::default()), Err(Error::Unsupported));

    // An Ed25519 OKP key and an ML-DSA-65 AKP key decode. A key does not fit another algorithm.
    let okp = encode(&Value::Map(vec![
        (Value::Unsigned(1), Value::Unsigned(1)),
        (Value::Negative(0), Value::Unsigned(6)),
        (Value::Negative(1), Value::Bytes(&[3; 32])),
    ]))
    .expect("OKP");
    let okp = Key::decode(&okp, Limits::default()).expect("OKP key");
    assert_eq!(okp.public, PublicKey::Ed25519(&[3; 32]));
    assert_eq!(TrustedKey::new(Algorithm::Es256, &okp), Err(Error::KeyAlgorithm));
    let akp = encode(&Value::Map(vec![
        (Value::Unsigned(1), Value::Unsigned(7)),
        (Value::Unsigned(3), Value::Negative(48)),
        (Value::Negative(0), Value::Bytes(&[5; 1952])),
    ]))
    .expect("AKP");
    let akp = Key::decode(&akp, Limits::default()).expect("AKP key");
    assert_eq!(akp.public, PublicKey::MlDsa65(&[5; 1952]));
}
