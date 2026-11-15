use alloc::boxed::Box;
use alloc::vec;
use alloc::vec::Vec;
use core::time::Duration;

use rscrypto::auth::Ed25519SecretKey;

use super::{Limit, Limits};
use crate::cbor::{self, Value};
use crate::cose::{Algorithm, Error, Key, Profile, PublicKey, TrustedKey};
use crate::crypto;
use crate::id::Id;
use crate::time::{Reading, ReadingSource};

/// A tagged Ed25519 `COSE_Sign1` with an extra protected header, an unprotected bucket, and an extra claim.
fn artifact(
    protected: Option<(Value<'_>, Value<'_>)>,
    unprotected: Value<'_>,
    claim: Option<(Value<'_>, Value<'_>)>,
) -> Vec<u8> {
    let mut header = vec![(Value::Unsigned(1), Value::Negative(18))];
    header.extend(protected);
    let protected = cbor::encode(&Value::Map(header)).unwrap();
    let mut claims = vec![
        (Value::Unsigned(1), Value::Text("https://issuer.example")),
        (Value::Unsigned(3), Value::Text("https://rp.example")),
        (Value::Unsigned(4), Value::Unsigned(2_000)),
    ];
    claims.extend(claim);
    let payload = cbor::encode(&Value::Map(claims)).unwrap();
    let to_be_signed = cbor::encode(&Value::Array(vec![
        Value::Text("Signature1"),
        Value::Bytes(&protected),
        Value::Bytes(&[]),
        Value::Bytes(&payload),
    ]))
    .unwrap();
    let signature = Ed25519SecretKey::from_bytes([7; 32]).sign(&to_be_signed).to_bytes();
    let sign1 = Value::Array(vec![
        Value::Bytes(&protected),
        unprotected,
        Value::Bytes(&payload),
        Value::Bytes(&signature),
    ]);
    cbor::encode(&Value::Tag(18, Box::new(sign1))).unwrap()
}

/// Nested arrays, `levels` deep, around the integer 0.
fn nested(levels: usize) -> Value<'static> {
    (0..levels).fold(Value::Unsigned(0), |item, _| Value::Array(vec![item]))
}

#[test]
fn an_input_over_each_bound_refuses_before_a_signature_call() {
    let public = Ed25519SecretKey::from_bytes([7; 32]).public_key().to_bytes();
    let key = Key {
        kid: None,
        alg: None,
        public: PublicKey::Ed25519(&public),
    };
    let profile = Profile {
        key: TrustedKey::new(Algorithm::Ed25519, &key).unwrap(),
        issuer: "https://issuer.example".into(),
        audience: "https://rp.example".into(),
        purpose: Id::new("test", "credential").unwrap(),
        limits: Limits {
            bytes: 400,
            depth: 4,
            items: 32,
            map_keys: 8,
            string_bytes: 128,
        },
    };
    let now = Reading::new(
        Duration::from_secs(1_000),
        Some(Duration::from_secs(1)),
        ReadingSource::Caller,
    );
    let empty = || Value::Map(vec![]);
    let claim = |value| Some((Value::Unsigned(9), value));

    // The control: a valid artifact makes one signature call. Thus a count that does not work fails.
    let before = crypto::calls();
    profile.verify(&artifact(None, empty(), None), now).unwrap();
    assert_eq!(
        crypto::calls(),
        before + 1,
        "the valid artifact made no counted signature call"
    );

    let long = "x".repeat(129);
    let keys: Vec<_> = (10..19).map(|key| (Value::Unsigned(key), Value::Null)).collect();
    let over = [
        // An unprotected header makes the artifact longer than 400 bytes.
        (
            artifact(
                None,
                Value::Map(vec![(Value::Unsigned(4), Value::Bytes(&[0; 300]))]),
                None,
            ),
            Limit::Bytes,
        ),
        // The protected bucket is one level, and the arrays in it are four more.
        (
            artifact(Some((Value::Negative(69_999), nested(4))), empty(), None),
            Limit::Depth,
        ),
        (
            artifact(None, empty(), claim(Value::Array(vec![Value::Null; 30]))),
            Limit::Items,
        ),
        (artifact(None, empty(), claim(Value::Map(keys))), Limit::MapKeys),
        (artifact(None, empty(), claim(Value::Text(&long))), Limit::StringBytes),
    ];
    for (input, limit) in over {
        let before = crypto::calls();
        assert_eq!(
            profile.verify(&input, now).err(),
            Some(Error::Cbor(cbor::Error::Limit(limit))),
            "{limit:?}"
        );
        assert_eq!(
            crypto::calls(),
            before,
            "the refusal of {limit:?} made a signature call"
        );
    }
}
