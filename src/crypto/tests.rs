use alloc::vec::Vec;

use rscodec::base64::Profile::Standard;
use rscodec::json::{self, Profile::Rfc8259, Slot, Str};

use super::{Algorithm, Verifier};
use crate::limits::{Limit, Limits, SignatureBudget};

/// The composite cases of draft-ietf-lamps-pq-composite-sigs-19, Appendix E. `tests/composite-sigs/README.md` gives
/// the source.
const VECTORS: &str = include_str!("../../tests/composite-sigs/vectors.json");

/// The limits of `VECTORS`: 39 KiB of text, an array of objects in an object, and a certificate of 7,572 bytes as the
/// longest string.
const VECTORS_LIMITS: json::Limits = json::Limits {
    input_bytes_max: 64 * 1024,
    depth_max: 3,
    string_bytes_max: 8 * 1024,
    members_max: 8,
    elements_max: 2,
    number_digits_max: 1,
};

/// The bytes of an ML-DSA-65 signature: the first component of a composite signature.
const ML_DSA_65_SIGNATURE: usize = 3_309;

/// The bytes of the base64 string `text`.
fn base64(text: Str<'_>) -> Vec<u8> {
    let text = text.borrowed().unwrap().as_bytes();
    let mut out = alloc::vec![0; Standard.decoded_len(text).unwrap()];
    Standard.decode(text, &mut out).unwrap();
    out
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

/// The case in the object `test`. The walk skips the members that it does not read.
fn case(test: json::Value<'_, '_, '_>) -> Result<Case, json::Error> {
    let (mut algorithm, mut public, mut signature) = (None, None, None);
    let mut members = test.members()?;
    while let Some((name, value)) = members.next()? {
        if name == "tcId" {
            let id = value.str()?;
            algorithm = Some(if id == "id-MLDSA65-Ed25519-SHA512" {
                Algorithm::MlDsa65Ed25519
            } else if id == "id-MLDSA65-ECDSA-P256-SHA512" {
                Algorithm::MlDsa65EcdsaP256
            } else {
                panic!("the case {id:?} is not a composite of the crate")
            });
        } else if name == "pk" {
            public = Some(base64(value.str()?));
        } else if name == "s" {
            signature = Some(base64(value.str()?));
        }
    }
    let algorithm = algorithm.unwrap();
    Ok(Case {
        algorithm,
        key: verifier(algorithm, &public.unwrap()),
        signature: signature.unwrap(),
    })
}

/// The message of the vectors, and each case.
fn vectors() -> (Vec<u8>, Vec<Case>) {
    let mut scratch = [Slot::EMPTY; 16];
    json::read(VECTORS.as_bytes(), &VECTORS_LIMITS, Rfc8259, &mut scratch, |reader| {
        let (mut message, mut cases) = (None, Vec::new());
        let mut members = reader.value().members()?;
        while let Some((name, value)) = members.next()? {
            if name == "m" {
                message = Some(base64(value.str()?));
            } else if name == "tests" {
                let mut tests = value.elements()?;
                while let Some(test) = tests.next()? {
                    cases.push(case(test)?);
                }
            }
        }
        Ok((message.unwrap(), cases))
    })
    .unwrap()
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

/// Three NIST ACVP cases of SLH-DSA-SHA2-128s (FIPS 205) with the empty context. `tests/slh-dsa/README.md` gives the
/// source.
const SLH_DSA_VECTORS: &str = include_str!("../../tests/slh-dsa/vectors.json");

/// The limits of `SLH_DSA_VECTORS`: 50 KiB of text, and a signature of 7,856 bytes as the longest string.
const SLH_DSA_LIMITS: json::Limits = json::Limits {
    input_bytes_max: 64 * 1024,
    depth_max: 3,
    string_bytes_max: 16 * 1024,
    members_max: 8,
    elements_max: 4,
    number_digits_max: 4,
};

#[test]
fn the_fips_205_vectors_verify_through_the_facade() {
    let mut scratch = [Slot::EMPTY; 16];
    let cases = json::read(
        SLH_DSA_VECTORS.as_bytes(),
        &SLH_DSA_LIMITS,
        Rfc8259,
        &mut scratch,
        |reader| {
            let mut cases = Vec::new();
            let mut members = reader.value().members()?;
            while let Some((name, value)) = members.next()? {
                if name == "tests" {
                    let mut tests = value.elements()?;
                    while let Some(test) = tests.next()? {
                        let (mut id, mut passed, mut public, mut message, mut signature) = (0, false, None, None, None);
                        let mut fields = test.members()?;
                        while let Some((name, value)) = fields.next()? {
                            if name == "tcId" {
                                id = value.number()?.to_u64()?;
                            } else if name == "testPassed" {
                                passed = value.bool()?;
                            } else if name == "pk" {
                                public = Some(base64(value.str()?));
                            } else if name == "message" {
                                message = Some(base64(value.str()?));
                            } else if name == "signature" {
                                signature = Some(base64(value.str()?));
                            }
                        }
                        cases.push((id, passed, public.unwrap(), message.unwrap(), signature.unwrap()));
                    }
                }
            }
            Ok(cases)
        },
    )
    .unwrap();
    let ids: Vec<_> = cases.iter().map(|case| case.0).collect();
    assert_eq!(ids, [162, 474, 255]);
    for (id, passed, public, mut message, signature) in cases {
        let key = Verifier::slh_dsa_sha2_128s(public.as_slice().try_into().unwrap());
        let mut budget = SignatureBudget::new(&Limits::default());
        assert_eq!(key.verify(&message, &signature, &mut budget), Ok(passed), "{id}");
        // One SLH-DSA signature is one check.
        assert_eq!(budget.remaining(), 1);
        message[0] ^= 1;
        assert_eq!(
            key.verify(&message, &signature, &mut budget),
            Ok(false),
            "a changed message: {id}"
        );
    }
}
