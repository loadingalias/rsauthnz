use alloc::vec::Vec;

use super::{Algorithm, Verifier};
use crate::json::{self, Value};
use crate::limits::{Limit, Limits, SignatureBudget};

/// The composite cases of draft-ietf-lamps-pq-composite-sigs-19, Appendix E. `tests/composite-sigs/README.md` gives
/// the source.
const VECTORS: &str = include_str!("../../tests/composite-sigs/vectors.json");

/// The bytes of an ML-DSA-65 signature: the first component of a composite signature.
const ML_DSA_65_SIGNATURE: usize = 3_309;

/// The bytes of the standard base64 text `text`, with its padding.
fn base64(text: &str) -> Vec<u8> {
    const DIGITS: &[u8; 64] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
    let digits: Vec<u32> = text
        .bytes()
        .filter(|&byte| byte != b'=')
        .map(|byte| u32::try_from(DIGITS.iter().position(|&digit| digit == byte).unwrap()).unwrap())
        .collect();
    let mut out = Vec::new();
    for chunk in digits.chunks(4) {
        let word = chunk
            .iter()
            .enumerate()
            .fold(0, |word, (at, digit)| word | digit << (18 - 6 * at));
        out.extend_from_slice(&word.to_be_bytes()[1..chunk.len()]);
    }
    out
}

/// The member `name` of the JSON object `object`.
fn member<'v, 'a>(object: &'v Value<'a>, name: &str) -> &'v Value<'a> {
    let Value::Object(members) = object else {
        panic!("{name} is not in an object");
    };
    &members.iter().find(|(key, _)| key == name).unwrap().1
}

/// The bytes of the base64 member `name` of `object`.
fn bytes(object: &Value<'_>, name: &str) -> Vec<u8> {
    let Value::String(text) = member(object, name) else {
        panic!("{name} is not a string");
    };
    base64(text)
}

/// The verifier of the composite `algorithm` with the public key `public`.
fn verifier(algorithm: Algorithm, public: &[u8]) -> Verifier {
    match algorithm {
        Algorithm::MlDsa65Ed25519 => Verifier::ml_dsa_65_ed25519(public.try_into().unwrap()),
        Algorithm::MlDsa65EcdsaP256 => Verifier::ml_dsa_65_ecdsa_p256(public.try_into().unwrap()),
        _ => panic!("{algorithm:?} is not a composite"),
    }
    .unwrap()
}

/// A case of the vectors: its algorithm, its key, and its signature over the message with the empty context.
struct Case {
    algorithm: Algorithm,
    key: Verifier,
    signature: Vec<u8>,
}

/// The message of the vectors, and each case.
fn vectors() -> (Vec<u8>, Vec<Case>) {
    let root = json::decode(VECTORS.as_bytes(), Limits::default()).unwrap();
    let Value::Array(tests) = member(&root, "tests") else {
        panic!("the cases are not an array");
    };
    let cases = tests
        .iter()
        .map(|test| {
            let algorithm = match member(test, "tcId") {
                Value::String(id) if id == "id-MLDSA65-Ed25519-SHA512" => Algorithm::MlDsa65Ed25519,
                Value::String(id) if id == "id-MLDSA65-ECDSA-P256-SHA512" => Algorithm::MlDsa65EcdsaP256,
                id => panic!("the case {id:?} is not a composite of the crate"),
            };
            Case {
                algorithm,
                key: verifier(algorithm, &bytes(test, "pk")),
                signature: bytes(test, "s"),
            }
        })
        .collect();
    (bytes(&root, "m"), cases)
}

#[test]
fn the_lamps_vectors_verify_through_the_facade() {
    let (message, cases) = vectors();
    let algorithms: Vec<_> = cases.iter().map(|case| case.algorithm).collect();
    assert_eq!(algorithms, [Algorithm::MlDsa65EcdsaP256, Algorithm::MlDsa65Ed25519]);
    for case in &cases {
        let mut budget = SignatureBudget::new(&Limits::default());
        assert_eq!(
            case.key.verify(&message, &case.signature, &mut budget),
            Ok(true),
            "{:?}",
            case.algorithm
        );
    }
}

#[test]
fn a_composite_with_one_invalid_or_missing_component_refuses() {
    let (message, cases) = vectors();
    for case in &cases {
        let (ml_dsa, traditional) = case.signature.split_at(ML_DSA_65_SIGNATURE);
        let mut ml_dsa_invalid = case.signature.clone();
        ml_dsa_invalid[0] ^= 1;
        // The last byte is in the Ed25519 signature, or in the `s` of the ECDSA signature.
        let mut traditional_invalid = case.signature.clone();
        *traditional_invalid.last_mut().unwrap() ^= 1;
        let refused: [(&str, &[u8]); 4] = [
            ("an invalid ML-DSA-65 component", &ml_dsa_invalid),
            // A verifier that accepts when the ML-DSA-65 component verifies alone fails here.
            ("an invalid traditional component", &traditional_invalid),
            ("the ML-DSA-65 component alone", ml_dsa),
            ("the traditional component alone", traditional),
        ];
        for (signature, bytes) in refused {
            let mut budget = SignatureBudget::new(&Limits::default());
            assert_eq!(
                case.key.verify(&message, bytes, &mut budget),
                Ok(false),
                "{:?}: {signature}",
                case.algorithm
            );
        }
    }
}

#[test]
fn a_composite_costs_two_checks_of_the_budget() {
    let (message, cases) = vectors();
    for case in &cases {
        let mut budget = SignatureBudget::new(&Limits {
            signature_checks: 3,
            ..Limits::default()
        });
        assert_eq!(case.key.verify(&message, &case.signature, &mut budget), Ok(true));
        assert_eq!(budget.remaining(), 1, "{:?}", case.algorithm);
        // The second check needs two, and one remains: the check refuses, and it charges nothing.
        assert_eq!(
            case.key.verify(&message, &case.signature, &mut budget),
            Err(Limit::SignatureChecks)
        );
        assert_eq!(budget.remaining(), 1, "{:?}", case.algorithm);
    }
}
