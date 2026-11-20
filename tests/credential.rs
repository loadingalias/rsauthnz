//! The contracts of the library-issued credential format: issuance in two steps, verification for one issuer,
//! audience, purpose, and declared profile, the declared size bound, and proof of possession by the `cnf` key.

use core::time::Duration;

use rsauthnz::cbor::{self, Value};
use rsauthnz::cose::{self, Key, PublicKey, TrustedKey};
use rsauthnz::credential::{Claims, Draft, Error, Profile, Serial, Subject};
use rsauthnz::crypto::{Algorithm, Authentication};
use rsauthnz::evidence::Method;
use rsauthnz::id::{Id, Kind, Principal};
use rsauthnz::limits::{Limits, SignatureBudget};
use rsauthnz::time::{Reading, ReadingSource};
use rscrypto::auth::{
    CompositeMlDsaError, EcdsaP256SecretKey, Ed25519SecretKey, MlDsa65EcdsaP256, MlDsa65EcdsaP256SecretKey,
    MlDsa65Ed25519, MlDsa65Ed25519SecretKey, MlDsa65SecretKey, MlDsa65Seed,
};

/// Each profile of the format: the two composites, pure ML-DSA-65, and the two classical profiles.
const PROFILES: [Algorithm; 5] = [
    Algorithm::MlDsa65Ed25519,
    Algorithm::MlDsa65EcdsaP256,
    Algorithm::MlDsa65,
    Algorithm::Ed25519,
    Algorithm::Es256,
];

/// A key in custody: the encoding of its public key, and its secret key. rscrypto signs in place of custody, with
/// the deterministic form of each algorithm.
struct Custody {
    public: Vec<u8>,
    secret: Secret,
}

enum Secret {
    /// An ML-DSA-65 + Ed25519 key: the default profile.
    Default(Box<MlDsa65Ed25519SecretKey>),
    /// An ML-DSA-65 + ECDSA P-256 key: the hardware-bound profile.
    HardwareBound(Box<MlDsa65EcdsaP256SecretKey>),
    MlDsa65(Box<MlDsa65SecretKey>),
    Ed25519(Ed25519SecretKey),
    /// The public part is the uncompressed SEC1 point.
    Es256(EcdsaP256SecretKey),
}

/// A filler that makes a key reproducible: the byte `seed` in each position.
fn fill(seed: u8) -> impl FnMut(&mut [u8]) -> Result<(), CompositeMlDsaError> {
    move |out| {
        out.fill(seed);
        Ok(())
    }
}

impl Custody {
    /// The reproducible key of `algorithm` that `seed` makes.
    fn new(algorithm: Algorithm, seed: u8) -> Self {
        let (public, secret) = match algorithm {
            Algorithm::MlDsa65Ed25519 => {
                let (public, secret) = MlDsa65Ed25519::generate_keypair(fill(seed)).expect("a composite key");
                (public.to_bytes().to_vec(), Secret::Default(Box::new(secret)))
            }
            Algorithm::MlDsa65EcdsaP256 => {
                let (public, secret) = MlDsa65EcdsaP256::generate_keypair(fill(seed)).expect("a composite key");
                (public.to_bytes().to_vec(), Secret::HardwareBound(Box::new(secret)))
            }
            Algorithm::MlDsa65 => {
                let (public, secret) = MlDsa65Seed::from_bytes([seed; 32]).keypair().expect("an ML-DSA-65 key");
                (public.to_bytes().to_vec(), Secret::MlDsa65(Box::new(secret)))
            }
            Algorithm::Ed25519 => Self::ed25519(Ed25519SecretKey::from_bytes([seed; 32])),
            Algorithm::Es256 => {
                let secret = EcdsaP256SecretKey::from_bytes([seed; 32]).expect("a P-256 scalar");
                (secret.public_key().to_sec1_bytes().to_vec(), Secret::Es256(secret))
            }
            algorithm => panic!("{algorithm:?} is not a profile of the format"),
        };
        Self { public, secret }
    }

    /// The Ed25519 key `secret`, and its public key.
    fn ed25519(secret: Ed25519SecretKey) -> (Vec<u8>, Secret) {
        (secret.public_key().to_bytes().to_vec(), Secret::Ed25519(secret))
    }

    fn algorithm(&self) -> Algorithm {
        match self.secret {
            Secret::Default(_) => Algorithm::MlDsa65Ed25519,
            Secret::HardwareBound(_) => Algorithm::MlDsa65EcdsaP256,
            Secret::MlDsa65(_) => Algorithm::MlDsa65,
            Secret::Ed25519(_) => Algorithm::Ed25519,
            Secret::Es256(_) => Algorithm::Es256,
        }
    }

    fn public(&self) -> PublicKey<'_> {
        let public = self.public.as_slice();
        match self.secret {
            Secret::Default(_) => PublicKey::MlDsa65Ed25519(public.try_into().expect("1,984 bytes")),
            Secret::HardwareBound(_) => PublicKey::MlDsa65EcdsaP256(public.try_into().expect("2,017 bytes")),
            Secret::MlDsa65(_) => PublicKey::MlDsa65(public.try_into().expect("1,952 bytes")),
            Secret::Ed25519(_) => PublicKey::Ed25519(public.try_into().expect("32 bytes")),
            Secret::Es256(_) => PublicKey::P256 {
                x: public[1..33].try_into().expect("32 bytes"),
                y: public[33..].try_into().expect("32 bytes"),
            },
        }
    }

    fn key(&self) -> TrustedKey {
        let key = Key {
            kid: None,
            alg: None,
            public: self.public(),
        };
        TrustedKey::new(self.algorithm(), &key).expect("the key fits the algorithm")
    }

    /// The signature of this key over `message`, with the empty context of ML-DSA-65 and of the composites.
    fn sign(&self, message: &[u8]) -> Vec<u8> {
        match &self.secret {
            Secret::Default(secret) => secret
                .sign_deterministic(message, &[])
                .expect("signature")
                .to_bytes()
                .to_vec(),
            Secret::HardwareBound(secret) => secret
                .sign_deterministic(message, &[])
                .expect("signature")
                .as_bytes()
                .to_vec(),
            Secret::MlDsa65(secret) => secret
                .sign_deterministic(message, &[])
                .expect("signature")
                .to_bytes()
                .to_vec(),
            Secret::Ed25519(secret) => secret.sign(message).to_bytes().to_vec(),
            Secret::Es256(secret) => secret.try_sign(message).expect("signature").to_bytes().to_vec(),
        }
    }

    /// Signs `draft` with this key, and finishes it.
    fn finish(&self, draft: Draft) -> Result<Vec<u8>, Error> {
        let signature = self.sign(&draft.to_be_signed());
        draft.finish(&signature, &mut budget())
    }
}

/// The signature budget of one artifact.
fn budget() -> SignatureBudget {
    SignatureBudget::new(&Limits::default())
}

/// A reading of `seconds` since the Unix epoch, with an uncertainty bound of one second.
fn reading(seconds: u64) -> Reading {
    Reading::new(
        Duration::from_secs(seconds),
        Some(Duration::from_secs(1)),
        ReadingSource::Caller,
    )
}

/// The time of issuance and of each check.
fn now() -> Reading {
    reading(1_800_000_000)
}

fn id<K: Kind>(value: &str) -> Id<K> {
    Id::new("acme", value).expect("identifier")
}

/// The claims of a workload credential for `audience`, valid for one hour after `now()`.
fn claims(audience: &str) -> Claims {
    Claims::new(
        id("authority"),
        id(audience),
        Subject::Workload(id("runner-7")),
        id("workload"),
        Serial(1),
        Duration::from_secs(1_800_003_600),
    )
}

/// Issues `claims` with the key of `issuer`, with the `cnf` key of `holder`.
fn issue(issuer: &Custody, claims: &Claims, holder: Option<&Custody>) -> Vec<u8> {
    let draft = Draft::credential(&issuer.key(), claims, holder.map(Custody::public), now()).expect("draft");
    issuer.finish(draft).expect("credential")
}

/// The profile of the issuer, the audience, and the purpose of `claims`.
fn profile(issuer: &Custody, claims: &Claims) -> Profile {
    Profile::new(
        issuer.key(),
        claims.issuer.clone(),
        claims.audience.clone(),
        claims.purpose.clone(),
        Limits::default(),
    )
    .expect("a profile of the format")
}

/// The proof of `holder` for `credential` and `challenge`.
fn prove(holder: &Custody, credential: &[u8], challenge: &[u8]) -> Vec<u8> {
    let draft = Draft::proof(&holder.key(), credential, &id("build-api"), challenge, now()).expect("draft");
    holder.finish(draft).expect("proof")
}

#[test]
fn an_issued_credential_round_trips_and_one_changed_claim_byte_refuses() {
    for (issuer, holder) in [
        (
            Custody::new(Algorithm::MlDsa65Ed25519, 1),
            Custody::new(Algorithm::MlDsa65Ed25519, 2),
        ),
        (
            Custody::new(Algorithm::MlDsa65EcdsaP256, 1),
            Custody::new(Algorithm::MlDsa65EcdsaP256, 2),
        ),
    ] {
        let mut claims = Claims::new(
            id("authority"),
            id("build-api"),
            Subject::Agent {
                agent: id("agent-4"),
                owner: id("u-17"),
            },
            id("agent"),
            Serial(9),
            Duration::from_secs(1_800_003_600),
        );
        claims.not_before = Some(Duration::from_secs(1_799_999_000));
        let credential = issue(&issuer, &claims, Some(&holder));
        let profile = profile(&issuer, &claims);
        let verified = profile.verify(&credential, now(), &mut budget()).expect("credential");
        assert_eq!(verified.claims(), &claims, "{:?}", issuer.algorithm());
        assert_eq!(verified.issued(), Duration::from_secs(1_800_000_000));
        let evidence = verified
            .possession(&prove(&holder, &credential, &[5; 32]), &[5; 32], now(), &mut budget())
            .expect("possession");
        assert_eq!(evidence.subject(), &Principal::Agent(id("agent-4")));

        // One changed byte in the value of the owner, `u-17` to `u-18`, keeps the CBOR and the identifier valid.
        let at = credential
            .windows(4)
            .position(|window| window == b"u-17")
            .expect("the owner");
        let mut changed = credential.clone();
        changed[at + 3] = b'8';
        assert_eq!(
            profile.verify(&changed, now(), &mut budget()).unwrap_err(),
            Error::Cose(cose::Error::Signature)
        );
    }
}

#[test]
fn a_credential_for_one_audience_refuses_at_another_audience() {
    let issuer = Custody::new(Algorithm::MlDsa65Ed25519, 1);
    let credential = issue(
        &issuer,
        &claims("build-api"),
        Some(&Custody::new(Algorithm::MlDsa65Ed25519, 2)),
    );
    let other = profile(&issuer, &claims("deploy-api"));
    assert_eq!(
        other.verify(&credential, now(), &mut budget()).unwrap_err(),
        Error::Cose(cose::Error::Audience)
    );
}

#[test]
fn an_artifact_of_one_purpose_refuses_for_another_purpose_of_the_same_issuer_key() {
    let issuer = Custody::new(Algorithm::MlDsa65Ed25519, 1);
    let mut receipt = claims("build-api");
    receipt.purpose = id("enrollment-receipt");
    let artifact = issue(&issuer, &receipt, None);
    let credentials = profile(&issuer, &claims("build-api"));
    assert_eq!(
        credentials.verify(&artifact, now(), &mut budget()).unwrap_err(),
        Error::Purpose
    );
}

#[test]
fn a_proof_by_the_cnf_key_gives_possession_evidence_and_each_other_proof_refuses() {
    let issuer = Custody::new(Algorithm::MlDsa65Ed25519, 1);
    let holder = Custody::new(Algorithm::MlDsa65Ed25519, 2);
    let claims = claims("build-api");
    let credential = issue(&issuer, &claims, Some(&holder));
    let profile = profile(&issuer, &claims);
    let verified = profile.verify(&credential, now(), &mut budget()).expect("credential");
    let challenge = [5; 32];
    let proof = prove(&holder, &credential, &challenge);

    let evidence = verified
        .possession(&proof, &challenge, now(), &mut budget())
        .expect("possession");
    assert_eq!(evidence.subject(), &Principal::Workload(id("runner-7")));
    assert_eq!(evidence.method(), Method::KeyPossession);
    assert_eq!(evidence.time(), now());
    // The proof shows none of these properties.
    assert!(!evidence.user_verified());
    assert!(!evidence.phishing_resistant());
    assert_eq!(evidence.binding(), None);

    // A key other than the `cnf` key: the signature check refuses.
    let other = prove(&Custody::new(Algorithm::MlDsa65Ed25519, 3), &credential, &challenge);
    assert_eq!(
        verified
            .possession(&other, &challenge, now(), &mut budget())
            .unwrap_err(),
        Error::Cose(cose::Error::Signature)
    );
    // The proof of one challenge refuses for another challenge.
    assert_eq!(
        verified.possession(&proof, &[6; 32], now(), &mut budget()).unwrap_err(),
        Error::Proof
    );
    // The proof for another credential of the same holder refuses.
    let mut renewed = claims;
    renewed.serial = Serial(2);
    let renewed = issue(&issuer, &renewed, Some(&holder));
    assert_eq!(
        verified
            .possession(&prove(&holder, &renewed, &challenge), &challenge, now(), &mut budget())
            .unwrap_err(),
        Error::Proof
    );
    // At the expiry of the credential, a valid proof refuses.
    assert_eq!(
        verified
            .possession(&proof, &challenge, reading(1_800_003_600), &mut budget())
            .unwrap_err(),
        Error::Cose(cose::Error::Expired)
    );
}

#[test]
fn a_default_credential_is_within_the_declared_bound_and_a_longer_draft_refuses_before_signing() {
    let issuer = Custody::new(Algorithm::MlDsa65Ed25519, 1);
    let holder = Custody::new(Algorithm::MlDsa65Ed25519, 2);
    let credential = issue(&issuer, &claims("build-api"), Some(&holder));
    // The sums of the parts that the credential format page gives: 8,192 bytes or fewer.
    assert_eq!(credential.len(), 5_481);
    assert_eq!(prove(&holder, &credential, &[5; 32]).len(), 3_487);

    // Three identifiers of 2,048 bytes make the artifact longer than 8,192 bytes, so the draft refuses and custody
    // signs nothing.
    let long = "v".repeat(2_048);
    let mut claims = claims("build-api");
    claims.subject = Subject::Agent {
        agent: id(&long),
        owner: id(&long),
    };
    claims.purpose = id(&long);
    assert_eq!(
        Draft::credential(&issuer.key(), &claims, None, now()).unwrap_err(),
        Error::Size
    );
}

#[test]
fn finish_refuses_a_signature_by_another_custody_key() {
    let draft = Draft::credential(
        &Custody::new(Algorithm::MlDsa65Ed25519, 1).key(),
        &claims("build-api"),
        None,
        now(),
    )
    .expect("draft");
    assert_eq!(
        Custody::new(Algorithm::MlDsa65Ed25519, 3).finish(draft).unwrap_err(),
        Error::Cose(cose::Error::Signature)
    );
}

#[test]
fn a_credential_under_each_profile_verifies_only_for_an_audience_that_declares_that_profile() {
    let claims = claims("build-api");
    let audiences = PROFILES.map(|algorithm| Custody::new(algorithm, 1));
    for issuer in &audiences {
        let holder = Custody::new(issuer.algorithm(), 2);
        let credential = issue(issuer, &claims, Some(&holder));
        for audience in &audiences {
            let profile = profile(audience, &claims);
            let verified = profile.verify(&credential, now(), &mut budget());
            if audience.algorithm() == issuer.algorithm() {
                let challenge = [5; 32];
                let proof = prove(&holder, &credential, &challenge);
                verified
                    .expect("the declared profile")
                    .possession(&proof, &challenge, now(), &mut budget())
                    .expect("possession");
            } else {
                assert_eq!(
                    verified.unwrap_err(),
                    Error::Cose(cose::Error::AlgorithmMismatch),
                    "{:?} at an audience of {:?}",
                    issuer.algorithm(),
                    audience.algorithm()
                );
            }
        }
    }
}

/// The authentication of each profile, as the profile table of the design gives it. A classical credential and its
/// proof report no post-quantum authentication.
#[test]
fn a_credential_and_its_possession_evidence_report_the_authentication_of_the_profile() {
    let expected = [
        Authentication::Hybrid,
        Authentication::Hybrid,
        Authentication::PostQuantum,
        Authentication::Classical,
        Authentication::Classical,
    ];
    let claims = claims("build-api");
    for (algorithm, authentication) in PROFILES.into_iter().zip(expected) {
        let (issuer, holder) = (Custody::new(algorithm, 1), Custody::new(algorithm, 2));
        let credential = issue(&issuer, &claims, Some(&holder));
        let profile = profile(&issuer, &claims);
        let verified = profile.verify(&credential, now(), &mut budget()).expect("credential");
        assert_eq!(verified.report().authentication, authentication, "{algorithm:?}");
        let evidence = verified
            .possession(&prove(&holder, &credential, &[5; 32]), &[5; 32], now(), &mut budget())
            .expect("possession");
        assert_eq!(evidence.authentication(), Some(authentication), "{algorithm:?}");
    }
}

/// The issuer key of the audience joins an ML-DSA-65 key and an Ed25519 key that the test holds apart. A credential
/// that the Ed25519 half signs alone is classical, so the composite audience refuses it. A verifier that tries the
/// classical half after the composite refusal accepts it.
#[test]
fn an_audience_that_declares_composite_refuses_a_classical_credential_of_the_classical_half_of_its_key() {
    let (ml_dsa, _) = MlDsa65Seed::from_bytes([1; 32]).keypair().expect("an ML-DSA-65 key");
    let (half, secret) = Custody::ed25519(Ed25519SecretKey::from_bytes([1; 32]));
    let mut joined = ml_dsa.to_bytes().to_vec();
    joined.extend_from_slice(&half);
    let composite = Key {
        kid: None,
        alg: None,
        public: PublicKey::MlDsa65Ed25519(joined.as_slice().try_into().expect("1,984 bytes")),
    };
    let claims = claims("build-api");
    let audience = Profile::new(
        TrustedKey::new(Algorithm::MlDsa65Ed25519, &composite).expect("a composite key"),
        claims.issuer.clone(),
        claims.audience.clone(),
        claims.purpose.clone(),
        Limits::default(),
    )
    .expect("a profile of the format");

    let classical = Custody { public: half, secret };
    let credential = issue(&classical, &claims, Some(&Custody::new(Algorithm::Ed25519, 2)));
    assert_eq!(
        audience.verify(&credential, now(), &mut budget()).unwrap_err(),
        Error::Cose(cose::Error::AlgorithmMismatch)
    );
    // An audience that declares the classical profile of the same key accepts the credential.
    profile(&classical, &claims)
        .verify(&credential, now(), &mut budget())
        .expect("the classical profile");
}

#[test]
fn a_cnf_key_of_another_class_than_the_issuer_key_refuses_at_issuance_and_at_verification() {
    let claims = claims("build-api");
    let composite = Custody::new(Algorithm::MlDsa65Ed25519, 1);
    for (issuer, holder) in [
        (Algorithm::MlDsa65Ed25519, Algorithm::Ed25519),
        (Algorithm::MlDsa65EcdsaP256, Algorithm::MlDsa65),
        (Algorithm::MlDsa65, Algorithm::MlDsa65Ed25519),
        (Algorithm::Ed25519, Algorithm::MlDsa65),
        (Algorithm::Es256, Algorithm::MlDsa65EcdsaP256),
    ] {
        let holder = Custody::new(holder, 2);
        assert_eq!(
            Draft::credential(&Custody::new(issuer, 1).key(), &claims, Some(holder.public()), now()).unwrap_err(),
            Error::Profile,
            "{issuer:?} with a cnf key of {:?}",
            holder.algorithm()
        );
    }

    // Another issuer signs a composite credential with a classical `cnf` key: an `OKP` key (1) on `Ed25519` (6).
    let credential = issue(&composite, &claims, Some(&Custody::new(Algorithm::MlDsa65Ed25519, 2)));
    let Value::Tag(18, sign1) = cbor::decode(&credential, Limits::default()).expect("CBOR") else {
        panic!("a COSE_Sign1");
    };
    let Value::Array(parts) = *sign1 else {
        panic!("a COSE_Sign1 array");
    };
    let [Value::Bytes(protected), _, Value::Bytes(payload), _] = parts.as_slice() else {
        panic!("the parts of a COSE_Sign1");
    };
    let Value::Map(mut entries) = cbor::decode(payload, Limits::default()).expect("claims") else {
        panic!("a claims map");
    };
    let x = [9; 32];
    let okp = Value::Map(vec![
        (Value::Unsigned(1), Value::Unsigned(1)),
        (Value::Negative(0), Value::Unsigned(6)),
        (Value::Negative(1), Value::Bytes(&x)),
    ]);
    let cnf = entries
        .iter_mut()
        .find(|(key, _)| *key == Value::Unsigned(8))
        .expect("a cnf claim");
    cnf.1 = Value::Map(vec![(Value::Unsigned(1), okp)]);
    let payload = cbor::encode(&Value::Map(entries)).expect("claims");
    let to_be_signed = cbor::encode(&Value::Array(vec![
        Value::Text("Signature1"),
        Value::Bytes(protected),
        Value::Bytes(&[]),
        Value::Bytes(&payload),
    ]))
    .expect("Sig_structure");
    let signature = composite.sign(&to_be_signed);
    let classical_cnf = cbor::encode(&Value::Tag(
        18,
        Box::new(Value::Array(vec![
            Value::Bytes(protected),
            Value::Map(Vec::new()),
            Value::Bytes(&payload),
            Value::Bytes(&signature),
        ])),
    ))
    .expect("COSE_Sign1");
    assert_eq!(
        profile(&composite, &claims)
            .verify(&classical_cnf, now(), &mut budget())
            .unwrap_err(),
        Error::Profile
    );
}
