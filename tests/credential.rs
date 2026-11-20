//! The contracts of the library-issued credential format: issuance in two steps, verification for one issuer,
//! audience, and purpose, the declared size bound, and proof of possession by the `cnf` key.

use core::time::Duration;

use rsauthnz::cose::{self, Key, PublicKey, TrustedKey};
use rsauthnz::credential::{Claims, Draft, Error, Profile, Serial, Subject};
use rsauthnz::crypto::Algorithm;
use rsauthnz::evidence::Method;
use rsauthnz::id::{Id, Kind, Principal};
use rsauthnz::limits::{Limits, SignatureBudget};
use rsauthnz::time::{Reading, ReadingSource};
use rscrypto::auth::{
    CompositeMlDsaError, MlDsa65EcdsaP256, MlDsa65EcdsaP256SecretKey, MlDsa65Ed25519, MlDsa65Ed25519SecretKey,
};

/// A key in custody: the encoding of its public key, and its secret key. rscrypto signs in place of custody, with
/// the deterministic form of the composite.
struct Custody {
    public: Vec<u8>,
    secret: Secret,
}

enum Secret {
    /// An ML-DSA-65 + Ed25519 key: the default profile.
    Default(Box<MlDsa65Ed25519SecretKey>),
    /// An ML-DSA-65 + ECDSA P-256 key: the hardware-bound profile.
    HardwareBound(Box<MlDsa65EcdsaP256SecretKey>),
}

/// A filler that makes a key reproducible: the byte `seed` in each position.
fn fill(seed: u8) -> impl FnMut(&mut [u8]) -> Result<(), CompositeMlDsaError> {
    move |out| {
        out.fill(seed);
        Ok(())
    }
}

impl Custody {
    fn ed25519(seed: u8) -> Self {
        let (public, secret) = MlDsa65Ed25519::generate_keypair(fill(seed)).expect("a composite key");
        Self {
            public: public.to_bytes().to_vec(),
            secret: Secret::Default(Box::new(secret)),
        }
    }

    fn ecdsa_p256(seed: u8) -> Self {
        let (public, secret) = MlDsa65EcdsaP256::generate_keypair(fill(seed)).expect("a composite key");
        Self {
            public: public.to_bytes().to_vec(),
            secret: Secret::HardwareBound(Box::new(secret)),
        }
    }

    fn algorithm(&self) -> Algorithm {
        match self.secret {
            Secret::Default(_) => Algorithm::MlDsa65Ed25519,
            Secret::HardwareBound(_) => Algorithm::MlDsa65EcdsaP256,
        }
    }

    fn public(&self) -> PublicKey<'_> {
        let public = self.public.as_slice();
        match self.secret {
            Secret::Default(_) => PublicKey::MlDsa65Ed25519(public.try_into().expect("1,984 bytes")),
            Secret::HardwareBound(_) => PublicKey::MlDsa65EcdsaP256(public.try_into().expect("2,017 bytes")),
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

    /// Signs `draft` with this key, and finishes it.
    fn finish(&self, draft: Draft) -> Result<Vec<u8>, Error> {
        let message = draft.to_be_signed();
        let signature = match &self.secret {
            Secret::Default(secret) => secret
                .sign_deterministic(&message, &[])
                .expect("signature")
                .to_bytes()
                .to_vec(),
            Secret::HardwareBound(secret) => secret
                .sign_deterministic(&message, &[])
                .expect("signature")
                .as_bytes()
                .to_vec(),
        };
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
    .expect("a composite key")
}

/// The proof of `holder` for `credential` and `challenge`.
fn prove(holder: &Custody, credential: &[u8], challenge: &[u8]) -> Vec<u8> {
    let draft = Draft::proof(&holder.key(), credential, &id("build-api"), challenge, now()).expect("draft");
    holder.finish(draft).expect("proof")
}

#[test]
fn an_issued_credential_round_trips_and_one_changed_claim_byte_refuses() {
    for (issuer, holder) in [
        (Custody::ed25519(1), Custody::ed25519(2)),
        (Custody::ecdsa_p256(1), Custody::ecdsa_p256(2)),
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
    let issuer = Custody::ed25519(1);
    let credential = issue(&issuer, &claims("build-api"), Some(&Custody::ed25519(2)));
    let other = profile(&issuer, &claims("deploy-api"));
    assert_eq!(
        other.verify(&credential, now(), &mut budget()).unwrap_err(),
        Error::Cose(cose::Error::Audience)
    );
}

#[test]
fn an_artifact_of_one_purpose_refuses_for_another_purpose_of_the_same_issuer_key() {
    let issuer = Custody::ed25519(1);
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
    let issuer = Custody::ed25519(1);
    let holder = Custody::ed25519(2);
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
    let other = prove(&Custody::ed25519(3), &credential, &challenge);
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
    let issuer = Custody::ed25519(1);
    let holder = Custody::ed25519(2);
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
    let draft = Draft::credential(&Custody::ed25519(1).key(), &claims("build-api"), None, now()).expect("draft");
    assert_eq!(
        Custody::ed25519(3).finish(draft).unwrap_err(),
        Error::Cose(cose::Error::Signature)
    );
}

#[test]
fn a_classical_key_refuses_as_the_issuer_key_the_profile_key_and_the_cnf_key() {
    let x = [9; 32];
    let ed25519 = Key {
        kid: None,
        alg: None,
        public: PublicKey::Ed25519(&x),
    };
    let classical = TrustedKey::new(Algorithm::Ed25519, &ed25519).expect("an Ed25519 key");
    let claims = claims("build-api");
    assert_eq!(
        Draft::credential(&classical, &claims, None, now()).unwrap_err(),
        Error::Profile
    );
    assert_eq!(
        Profile::new(
            classical,
            claims.issuer.clone(),
            claims.audience.clone(),
            claims.purpose.clone(),
            Limits::default()
        )
        .unwrap_err(),
        Error::Profile
    );
    let issuer = Custody::ed25519(1);
    assert_eq!(
        Draft::credential(&issuer.key(), &claims, Some(PublicKey::Ed25519(&x)), now()).unwrap_err(),
        Error::Profile
    );
}
