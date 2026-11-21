//! The assertions of three published cases of WebAuthn Level 3, section 16: the signature check of each classical
//! algorithm of the profile, with the DER signature of ES256. `tests/passkey/README.md` gives the source. Each key is the
//! `COSE_Key` of the authenticator data of the registration of its case.

use alloc::vec::Vec;

use crate::cose::{self, Key, TrustedKey};
use crate::crypto::{self, Algorithm};
use crate::limits::{Limits, SignatureBudget};

/// A case: its name, its algorithm, its key, and its assertion, each as hexadecimal text.
struct Case {
    name: &'static str,
    algorithm: Algorithm,
    key: &'static str,
    authenticator_data: &'static str,
    client_data: &'static str,
    signature: &'static str,
}

const CASES: [Case; 3] = [
    Case {
        name: "packed-es256",
        algorithm: Algorithm::Es256,
        key: "a50102032620012158201cf27f25da591208a4239c2e324f104f585525479a29edeedd830f48e77aeae522582059e4b7da6c0106e206ce390c93ab98a15a5ec3887e57f0cc2bece803b920c423",
        authenticator_data: "bfabc37432958b063360d3ad6461c9c4735ae7f8edd46592a5e0f01452b2e4b50d00000000",
        client_data: "7b2274797065223a22776562617574686e2e676574222c226368616c6c656e6765223a2273524276704770587676463446524841565833496d4b4130453958773858306b526a44426c4d6668726255222c226f726967696e223a2268747470733a2f2f6578616d706c652e6f7267222c2263726f73734f726967696e223a66616c73652c22657874726144617461223a22636c69656e74446174614a534f4e206d617920626520657874656e6465642077697468206164646974696f6e616c206669656c647320696e20746865206675747572652c207375636820617320746869733a20415a4d77794d78496244382d756775464e7036723851227d",
        signature: "30450220694969d3ee928de6f02ef23a9c644d7d779916451734a94b432542f498a1ebe90221008b0819c824218a97152cd099c55bfb1477b29d900a49a64018314f9bfccda163",
    },
    Case {
        name: "packed-eddsa",
        algorithm: Algorithm::Ed25519,
        key: "a401010327200621582044e06ddd331c36a8dc667bab52bcae63486c916aa5e339e6acebaa84934bf832",
        authenticator_data: "bfabc37432958b063360d3ad6461c9c4735ae7f8edd46592a5e0f01452b2e4b50100000000",
        client_data: "7b2274797065223a22776562617574686e2e676574222c226368616c6c656e6765223a2269566c583442786a4f6d6d44534b4c596f7870557439736e364d48454f7943413135726947514a6e763949222c226f726967696e223a2268747470733a2f2f6578616d706c652e6f7267222c2263726f73734f726967696e223a66616c73657d",
        signature: "f5c59c7e46c34f6f8cc197101ddf9934fa2595f68eb1913a637e8419eb9ba4cfdfc48f85393bc0d40b011f0d6fecb097d6607525713223a0dc0d453993dae00b",
    },
    Case {
        name: "packed-rs256",
        algorithm: Algorithm::Rs256,
        key: "a4010303390100205901b403fffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff7ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff800000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000012143010001",
        authenticator_data: "bfabc37432958b063360d3ad6461c9c4735ae7f8edd46592a5e0f01452b2e4b51900000000",
        client_data: "7b2274797065223a22776562617574686e2e676574222c226368616c6c656e6765223a224b56395a39667150356978617970346e596d7834794e6f33617562597a5333536d75757459423462784d55222c226f726967696e223a2268747470733a2f2f6578616d706c652e6f7267222c2263726f73734f726967696e223a66616c73657d",
        signature: "01063d52d7c39b4d432fc7063c5d93e582bdcb16889cd71f888d67d880ea730a428498d3bc8e1ee11f2b1ecbe6c292b118c55ffaaddefa8cad0a54dd137c51f1eec673f1bb6c4d1789d6826a222b22d0f585fc901fdc933212e579d199b89d672aa44891333e6a1355536025e82b25590256c3538229b55737083b2f6b9377e49e2472f11952f79fdd0da180b5ffd901b4049a8f081bb40711bef76c62aed943571f2d0575304cb549d68d8892f95086a30f93716aee818f8dc06e96c0d5e0ed4cfa9fd8773d90464b68cf140f7986666ff9c9e3302acd0535d60d769f465e2ab57ef8aabc89fccfef7ba32a64154a8b3d26be2298f470b8cc5377dbe3dfd4b0b45f8f01e63bde6cfc76b62771f9b70aa27cf40152cad93aa5acd784fd4b90f676e2ea828d0bf2400aebbaae4153e5838f537f88b6228346782a93a899be66ec77de45b3efcf311da6321c92e6b0cd11bfe653bf3e98cee8e341f02d67dbb6f9c98d9e8178090cfb5b70fbc6d541599ac794ae2f1d4de1286ec8de8c2daf7b1d15c8438e90d924df5c19045220a4c8438c1b979bbe016cf3d0eeec23c3999d4882cc645b776de930756612cdc6dd398160ff02a6",
    },
];

/// The bytes of the hexadecimal text `text`.
fn hex(text: &str) -> Vec<u8> {
    text.as_bytes()
        .chunks(2)
        .map(|pair| u8::from_str_radix(str::from_utf8(pair).unwrap(), 16).unwrap())
        .collect()
}

#[test]
fn the_published_assertions_verify_with_their_credential_keys() {
    for case in &CASES {
        let key = hex(case.key);
        let trusted = TrustedKey::new(case.algorithm, &Key::decode(&key, Limits::default()).unwrap()).unwrap();
        let mut message = [
            hex(case.authenticator_data),
            crypto::sha256(&hex(case.client_data)).to_vec(),
        ]
        .concat();
        let signature = hex(case.signature);
        let mut budget = SignatureBudget::new(&Limits::default());
        assert_eq!(
            trusted.verify_assertion(&message, &signature, &mut budget),
            Ok(()),
            "{}",
            case.name
        );
        message[0] ^= 1;
        assert_eq!(
            trusted.verify_assertion(&message, &signature, &mut budget),
            Err(cose::Error::Signature),
            "{}",
            case.name
        );
    }
}
