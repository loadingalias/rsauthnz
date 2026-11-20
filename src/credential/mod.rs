//! Library-issued credentials and receipts: one format of a `COSE_Sign1` ([RFC 9052]) over CWT claims ([RFC 8392]),
//! with the proof-of-possession key of its holder ([RFC 8747]).
//!
//! The format serves workload, agent, and CLI enrollment credentials, and enrollment and approval receipts. A
//! credential has a `cnf` key: the key of its holder. A receipt has no `cnf` key. A signed purpose claim names the
//! kind of artifact. Thus one issuer key can sign each kind, and an artifact of one purpose never verifies for
//! another. The issuer key and the `cnf` key use a composite profile of [`crate::crypto`].
//!
//! Issuance has two steps, so the issuer key stays in custody. [`Draft::credential`] makes a draft, and custody signs
//! the bytes of [`Draft::to_be_signed`]. [`Draft::finish`] verifies the signature with the issuer key, and only then
//! gives the encoded artifact. [`Profile::verify`] gives [`Verified`] evidence. The holder makes a proof with
//! [`Draft::proof`] in the same two steps. [`Verified::possession`] checks the proof against the `cnf` key and gives
//! authentication [`Evidence`]. An encoded artifact or proof has at most [`MAX_BYTES`] bytes.
//!
//! ```
//! use core::time::Duration;
//! use rsauthnz::cose::{Key, PublicKey, TrustedKey};
//! use rsauthnz::credential::{Claims, Draft, Profile, Serial, Subject};
//! use rsauthnz::crypto::Algorithm;
//! use rsauthnz::evidence::Method;
//! use rsauthnz::id::Id;
//! use rsauthnz::limits::{Limits, SignatureBudget};
//! use rsauthnz::time::{Reading, ReadingSource};
//! use rscrypto::auth::MlDsa65Ed25519;
//!
//! fn trusted(public: PublicKey<'_>) -> Result<TrustedKey, rsauthnz::cose::Error> {
//!     TrustedKey::new(Algorithm::MlDsa65Ed25519, &Key { kid: None, alg: None, public })
//! }
//!
//! // Custody holds the secret keys. Here rscrypto signs in place of custody. A fixed filler makes the keys
//! // reproducible. Use fresh randomness for real keys.
//! let (issuer_public, issuer_secret) = MlDsa65Ed25519::generate_keypair(|out| Ok(out.fill(1)))?;
//! let (holder_public, holder_secret) = MlDsa65Ed25519::generate_keypair(|out| Ok(out.fill(2)))?;
//! let (issuer_public, holder_public) = (issuer_public.to_bytes(), holder_public.to_bytes());
//! let issuer_key = trusted(PublicKey::MlDsa65Ed25519(&issuer_public))?;
//! let holder_key = trusted(PublicKey::MlDsa65Ed25519(&holder_public))?;
//! let now = Reading::new(Duration::from_secs(1_800_000_000), Some(Duration::from_secs(1)), ReadingSource::Caller);
//!
//! // 1. The issuer makes a draft. Custody signs it, and `finish` verifies the signature before it gives the bytes.
//! let claims = Claims::new(
//!     Id::new("acme", "authority")?,
//!     Id::new("acme", "build-api")?,
//!     Subject::Workload(Id::new("acme", "runner-7")?),
//!     Id::new("acme", "workload")?,
//!     Serial(1),
//!     Duration::from_secs(1_800_003_600),
//! );
//! let draft = Draft::credential(&issuer_key, &claims, Some(PublicKey::MlDsa65Ed25519(&holder_public)), now)?;
//! let signature = issuer_secret.sign_deterministic(&draft.to_be_signed(), &[])?;
//! let credential = draft.finish(signature.as_bytes(), &mut SignatureBudget::new(&Limits::default()))?;
//!
//! // 2. The verifier fixes the issuer, the audience, and the purpose, and verifies the credential.
//! let (issuer, audience, purpose) = (claims.issuer.clone(), claims.audience.clone(), claims.purpose.clone());
//! let profile = Profile::new(issuer_key, issuer, audience, purpose, Limits::default())?;
//! let verified = profile.verify(&credential, now, &mut SignatureBudget::new(&Limits::default()))?;
//! assert_eq!(verified.claims(), &claims);
//!
//! // 3. The holder signs a proof over the challenge of the verifier, and the verifier checks it.
//! let challenge = [7; 32];
//! let draft = Draft::proof(&holder_key, &credential, &claims.audience, &challenge, now)?;
//! let signature = holder_secret.sign_deterministic(&draft.to_be_signed(), &[])?;
//! let proof = draft.finish(signature.as_bytes(), &mut SignatureBudget::new(&Limits::default()))?;
//! let evidence = verified.possession(&proof, &challenge, now, &mut SignatureBudget::new(&Limits::default()))?;
//! assert_eq!(evidence.method(), Method::KeyPossession);
//! # Ok::<(), Box<dyn core::error::Error>>(())
//! ```
//!
//! [RFC 9052]: https://www.rfc-editor.org/rfc/rfc9052
//! [RFC 8392]: https://www.rfc-editor.org/rfc/rfc8392
//! [RFC 8747]: https://www.rfc-editor.org/rfc/rfc8747

use alloc::boxed::Box;
use alloc::string::ToString;
use alloc::vec;
use alloc::vec::Vec;
use core::fmt;
use core::time::Duration;

use crate::cbor::{self, Value};
use crate::cose::{self, Confirmation, Key, PublicKey, Sign1, TrustedKey};
use crate::crypto::{self, Algorithm, Authentication};
use crate::evidence::{Evidence, Method};
use crate::id::{Agent, Audience, Authority, Human, Id, Principal, Purpose, Workload};
use crate::limits::{Limits, SignatureBudget};
use crate::time::Reading;

/// The most bytes of an encoded credential, receipt, or proof. A draft that can be longer refuses before custody signs
/// it, and verification refuses a longer input before it decodes it.
pub const MAX_BYTES: usize = 8_192;

/// The longest signature of a composite profile. ML-DSA-65 + ECDSA P-256 has the 3,309 bytes of ML-DSA-65 and at most
/// 72 bytes of DER ECDSA. ML-DSA-65 + Ed25519 has 3,373 bytes.
const SIGNATURE_BYTES_MAX: usize = 3_381;

/// The tag of a `COSE_Sign1` (RFC 9052 section 2).
const SIGN1_TAG: u64 = 18;

// The claim keys of this format are in the private-use range of RFC 8392 section 9.1, which is less than -65536.
// Each constant is the `n` of `Value::Negative(n)`, which is the key `-1 - n`.
/// The subject (-65537): the canonical CBOR form of a [`Principal`].
const SUBJECT: u64 = 65_536;
/// The owner of an agent (-65538): the canonical CBOR form of an `Id<Human>`.
const OWNER: u64 = 65_537;
/// The purpose (-65539): the canonical CBOR form of an `Id<Purpose>`.
const PURPOSE: u64 = 65_538;
/// The SHA-256 digest of the credential that a proof binds (-65540).
const PROOF_CREDENTIAL: u64 = 65_539;
/// The challenge of the verifier that a proof binds (-65541).
const PROOF_CHALLENGE: u64 = 65_540;

/// The claims of a credential or a receipt. Issuance writes them, and verification gives them back.
#[derive(Clone, Debug, PartialEq, Eq)]
#[non_exhaustive]
pub struct Claims {
    /// The authority that issues the artifact. `iss` holds its text form `namespace:value`.
    pub issuer: Id<Authority>,
    /// The service that accepts the artifact. `aud` holds its text form `namespace:value`.
    pub audience: Id<Audience>,
    /// The principal that the artifact names, with the owner of an agent.
    pub subject: Subject,
    /// The kind of the artifact, such as a workload credential or an approval receipt.
    pub purpose: Id<Purpose>,
    /// The serial. `cti` holds it.
    pub serial: Serial,
    /// The start of the validity interval, as the time since the Unix epoch, or `None` for no start: `nbf`. Issuance
    /// rounds it up to a whole second.
    pub not_before: Option<Duration>,
    /// The end of the validity interval, as the time since the Unix epoch: `exp`. The artifact is not valid at this
    /// time and after it. Issuance rounds it down to a whole second.
    pub expires: Duration,
}

impl Claims {
    /// The claims with no start of the validity interval. Set the other fields after this call.
    ///
    /// Cost class: [`Parse`](crate::limits::Class::Parse).
    #[must_use]
    pub const fn new(
        issuer: Id<Authority>,
        audience: Id<Audience>,
        subject: Subject,
        purpose: Id<Purpose>,
        serial: Serial,
        expires: Duration,
    ) -> Self {
        Self {
            issuer,
            audience,
            subject,
            purpose,
            serial,
            not_before: None,
            expires,
        }
    }
}

/// The principal that an artifact names. An agent always names its human owner, and a human or a workload has no
/// owner.
#[derive(Clone, Debug, PartialEq, Eq, Hash)]
pub enum Subject {
    /// A person, for example the human of a CLI credential.
    Human(Id<Human>),
    /// A service or a host that acts for itself.
    Workload(Id<Workload>),
    /// An agent and its accountable human owner. The issuer asserts the owner. An agent never asserts its own owner.
    Agent {
        /// The agent.
        agent: Id<Agent>,
        /// The human owner of the agent.
        owner: Id<Human>,
    },
}

impl Subject {
    /// The principal: the human, the workload, or the agent.
    #[must_use]
    pub fn principal(&self) -> Principal {
        match self {
            Self::Human(human) => Principal::Human(human.clone()),
            Self::Workload(workload) => Principal::Workload(workload.clone()),
            Self::Agent { agent, .. } => Principal::Agent(agent.clone()),
        }
    }

    /// The canonical CBOR form of the principal.
    fn to_cbor(&self) -> Value<'_> {
        match self {
            Self::Human(human) => human.to_cbor(),
            Self::Workload(workload) => workload.to_cbor(),
            Self::Agent { agent, .. } => agent.to_cbor(),
        }
    }
}

/// The serial of an artifact. `cti` holds it as 8 bytes, with the most significant byte first. Take it from a counter
/// of the store ([`Driver::allocate`](crate::store::driver::Driver::allocate)), so that a restore never gives one
/// serial twice.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct Serial(pub u64);

/// An artifact that custody did not sign yet: a credential, a receipt, or a proof. [`Draft::finish`] consumes it, so
/// one draft gives at most one artifact.
pub struct Draft {
    /// The public key of the signer.
    key: TrustedKey,
    /// The encoded protected bucket: `alg` only.
    protected: Vec<u8>,
    /// The encoded claims.
    payload: Vec<u8>,
}

impl Draft {
    /// The draft of a credential or a receipt that the issuer key `key` signs. `confirmation` is the public key of the
    /// holder: the `cnf` key of a credential, or `None` for a receipt. The issue time `iat` is the whole seconds of
    /// `now.estimate()`.
    ///
    /// Cost class: [`Verify`](crate::limits::Class::Verify). The draft checks `confirmation` as
    /// [`TrustedKey::new`] does.
    ///
    /// # Errors
    ///
    /// [`Error::Validity`] if `expires`, after rounding, is not after `iat` and `not_before`. [`Error::Profile`] if
    /// `key` or `confirmation` is not a composite key. [`Error::Cose`] with [`cose::Error::Malformed`] if the P-256
    /// point of `confirmation` is not on the curve. [`Error::Size`] if the artifact can be longer than
    /// [`MAX_BYTES`].
    pub fn credential(
        key: &TrustedKey,
        claims: &Claims,
        confirmation: Option<PublicKey<'_>>,
        now: Reading,
    ) -> Result<Self, Error> {
        let issued = now.estimate().as_secs();
        let expires = claims.expires.as_secs();
        let not_before = claims
            .not_before
            .map(|nbf| {
                nbf.as_secs()
                    .checked_add(u64::from(nbf.subsec_nanos() != 0))
                    .ok_or(Error::Validity)
            })
            .transpose()?;
        if expires <= issued || not_before.is_some_and(|nbf| nbf >= expires) {
            return Err(Error::Validity);
        }
        let issuer = claims.issuer.to_string();
        let audience = claims.audience.to_string();
        let serial = claims.serial.0.to_be_bytes();
        let mut entries = vec![
            (Value::Unsigned(1), Value::Text(&issuer)),
            (Value::Unsigned(3), Value::Text(&audience)),
            (Value::Unsigned(4), Value::Unsigned(expires)),
            (Value::Unsigned(6), Value::Unsigned(issued)),
            (Value::Unsigned(7), Value::Bytes(&serial)),
            (Value::Negative(SUBJECT), claims.subject.to_cbor()),
            (Value::Negative(PURPOSE), claims.purpose.to_cbor()),
        ];
        if let Some(nbf) = not_before {
            entries.push((Value::Unsigned(5), Value::Unsigned(nbf)));
        }
        if let Subject::Agent { owner, .. } = &claims.subject {
            entries.push((Value::Negative(OWNER), owner.to_cbor()));
        }
        if let Some(public) = confirmation {
            let (algorithm, bytes) = composite_key(&public)?;
            // A key whose P-256 point is not on the curve refuses here, before custody signs.
            TrustedKey::new(
                algorithm,
                &Key {
                    kid: None,
                    alg: None,
                    public,
                },
            )?;
            // The `COSE_Key` member (1) holds an `AKP` key (`kty` 7) with its `alg` (3) and `pub` (-1).
            let key = Value::Map(vec![
                (Value::Unsigned(1), Value::Unsigned(7)),
                (Value::Unsigned(3), cose::alg(algorithm)),
                (Value::Negative(0), Value::Bytes(bytes)),
            ]);
            entries.push((Value::Unsigned(8), Value::Map(vec![(Value::Unsigned(1), key)])));
        }
        let payload = cbor::encode(&Value::Map(entries)).expect("the claims have distinct keys and no simple value");
        Self::new(key, payload)
    }

    /// The draft of a proof of possession that the holder key `key`, the `cnf` key of `credential`, signs. The proof
    /// binds the SHA-256 digest of the exact bytes of `credential`, the audience `audience` of the verifier, the
    /// challenge `challenge` of the verifier, and the time `iat`: the whole seconds of `now.estimate()`.
    ///
    /// Cost class: [`Parse`](crate::limits::Class::Parse).
    ///
    /// # Errors
    ///
    /// [`Error::Profile`] if `key` is not a composite key, and [`Error::Size`] if the proof can be longer than
    /// [`MAX_BYTES`].
    pub fn proof(
        key: &TrustedKey,
        credential: &[u8],
        audience: &Id<Audience>,
        challenge: &[u8],
        now: Reading,
    ) -> Result<Self, Error> {
        let digest = crypto::sha256(credential);
        let audience = audience.to_string();
        let payload = cbor::encode(&Value::Map(vec![
            (Value::Unsigned(3), Value::Text(&audience)),
            (Value::Unsigned(6), Value::Unsigned(now.estimate().as_secs())),
            (Value::Negative(PROOF_CREDENTIAL), Value::Bytes(&digest)),
            (Value::Negative(PROOF_CHALLENGE), Value::Bytes(challenge)),
        ]))
        .expect("the claims have distinct keys and no simple value");
        Self::new(key, payload)
    }

    /// The draft of the encoded claims `payload` that `key` signs.
    fn new(key: &TrustedKey, payload: Vec<u8>) -> Result<Self, Error> {
        composite(key.algorithm())?;
        let protected = cbor::encode(&Value::Map(vec![(Value::Unsigned(1), cose::alg(key.algorithm()))]))
            .expect("the protected bucket has one key and no simple value");
        // The tag, the array head, and the empty unprotected bucket are one byte each.
        let string = |len: usize| cbor::head_len(len as u64) + len;
        if 3 + string(protected.len()) + string(payload.len()) + string(SIGNATURE_BYTES_MAX) > MAX_BYTES {
            return Err(Error::Size);
        }
        Ok(Self {
            key: key.clone(),
            protected,
            payload,
        })
    }

    /// The bytes that custody signs: the `Sig_structure` of RFC 9052 section 4.4, with an empty external AAD. Custody
    /// signs them with the empty context of the composite profile.
    ///
    /// Cost class: [`Parse`](crate::limits::Class::Parse).
    #[must_use]
    pub fn to_be_signed(&self) -> Vec<u8> {
        cose::to_be_signed(&self.protected, &self.payload)
    }

    /// Verifies `signature`, the signature of custody over [`Self::to_be_signed`], with the key of the draft. Then it
    /// gives the encoded artifact: a `COSE_Sign1` with the tag 18 and an empty unprotected bucket. The check charges
    /// `budget`, the budget of the artifact. A refusal gives no bytes.
    ///
    /// Cost class: [`Verify`](crate::limits::Class::Verify).
    ///
    /// # Errors
    ///
    /// [`Error::Cose`] with [`cose::Error::Signature`] if the signature does not verify with the key of the draft, for
    /// example because custody signed with another key. [`Error::Cose`] with [`cose::Error::Limit`] if the check
    /// costs more than `budget` has.
    pub fn finish(self, signature: &[u8], budget: &mut SignatureBudget) -> Result<Vec<u8>, Error> {
        self.key.verify(&self.to_be_signed(), signature, budget)?;
        let artifact = cbor::encode(&Value::Tag(
            SIGN1_TAG,
            Box::new(Value::Array(vec![
                Value::Bytes(&self.protected),
                Value::Map(Vec::new()),
                Value::Bytes(&self.payload),
                Value::Bytes(signature),
            ])),
        ))
        .expect("a COSE_Sign1 has no map key and no simple value");
        assert!(
            artifact.len() <= MAX_BYTES,
            "the draft bounded the length with the longest composite signature, and a valid signature is not longer"
        );
        Ok(artifact)
    }
}

// The payload can hold a bearer receipt. Thus the output shows the algorithm and only the length of each part.
impl fmt::Debug for Draft {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("Draft")
            .field("key", &self.key)
            .field("protected_len", &self.protected.len())
            .field("payload_len", &self.payload.len())
            .finish()
    }
}

/// A trusted verification profile of credentials and receipts: the issuer key, the issuer, the audience, and the
/// purpose that the application fixes before it reads an artifact.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Profile {
    /// The COSE profile, with the text forms of the issuer and the audience.
    cose: cose::Profile,
    issuer: Id<Authority>,
    audience: Id<Audience>,
}

impl Profile {
    /// The profile that accepts the artifacts of `purpose` for `audience` that `issuer` signs with `key`. The decode
    /// of an artifact and of a proof uses `limits`, and each has at most [`MAX_BYTES`] bytes.
    ///
    /// Cost class: [`Parse`](crate::limits::Class::Parse).
    ///
    /// # Errors
    ///
    /// [`Error::Profile`] if `key` is not a composite key.
    pub fn new(
        key: TrustedKey,
        issuer: Id<Authority>,
        audience: Id<Audience>,
        purpose: Id<Purpose>,
        limits: Limits,
    ) -> Result<Self, Error> {
        composite(key.algorithm())?;
        Ok(Self {
            cose: cose::Profile {
                key,
                issuer: issuer.to_string(),
                audience: audience.to_string(),
                purpose,
                limits,
            },
            issuer,
            audience,
        })
    }

    /// Verifies the credential or receipt `artifact` at the physical time `now`. The signature check charges `budget`,
    /// the budget of the artifact.
    ///
    /// Cost class: [`Verify`](crate::limits::Class::Verify).
    ///
    /// The checks are those of [`cose::Profile::verify`], with `iss` and `aud` in their text forms. Then the claims must
    /// be the claims of this format, and the purpose must be the purpose of the profile. A `cnf` key must be a
    /// composite key.
    ///
    /// # Errors
    ///
    /// [`Error::Size`] for an artifact longer than [`MAX_BYTES`], and [`Error::Cose`] for each refusal of
    /// [`cose::Profile::verify`]. [`Error::Claims`] if a claim is missing, has the wrong form, or is not a claim of
    /// this format. [`Error::Purpose`] for another purpose, and [`Error::Profile`] for a `cnf` key that is not a
    /// composite key.
    pub fn verify<'a>(
        &self,
        artifact: &'a [u8],
        now: Reading,
        budget: &mut SignatureBudget,
    ) -> Result<Verified<'a, '_>, Error> {
        if artifact.len() > MAX_BYTES {
            return Err(Error::Size);
        }
        let verified = self.cose.verify(artifact, now, budget)?;
        let cose::Claims {
            sub: None,
            nbf,
            iat: Some(issued),
            cti: Some(serial),
            cnf,
            other,
            ..
        } = verified.claims()
        else {
            return Err(Error::Claims);
        };
        let serial = Serial(u64::from_be_bytes((*serial).try_into().map_err(|_| Error::Claims)?));
        let (mut subject, mut owner, mut purpose) = (None, None, None);
        // The decoder refused equal keys, so each claim has one value.
        for (key, value) in other {
            let claim = match key {
                Value::Negative(SUBJECT) => &mut subject,
                Value::Negative(OWNER) => &mut owner,
                Value::Negative(PURPOSE) => &mut purpose,
                _ => return Err(Error::Claims),
            };
            *claim = Some(value);
        }
        let purpose = purpose
            .and_then(|purpose| Id::<Purpose>::from_cbor(purpose).ok())
            .ok_or(Error::Claims)?;
        if purpose != self.cose.purpose {
            return Err(Error::Purpose);
        }
        let principal = subject
            .and_then(|subject| Principal::from_cbor(subject).ok())
            .ok_or(Error::Claims)?;
        let owner = owner
            .map(|owner| Id::<Human>::from_cbor(owner).map_err(|_| Error::Claims))
            .transpose()?;
        let subject = match (principal, owner) {
            (Principal::Human(human), None) => Subject::Human(human),
            (Principal::Workload(workload), None) => Subject::Workload(workload),
            (Principal::Agent(agent), Some(owner)) => Subject::Agent { agent, owner },
            _ => return Err(Error::Claims),
        };
        let confirmation = match cnf {
            None => None,
            Some(Confirmation::Key(key)) => Some(TrustedKey::new(composite_key(&key.public)?.0, key)?),
            Some(Confirmation::KeyId(_)) => return Err(Error::Claims),
        };
        Ok(Verified {
            artifact,
            profile: self,
            claims: Claims {
                issuer: self.issuer.clone(),
                audience: self.audience.clone(),
                subject,
                purpose,
                serial,
                not_before: *nbf,
                expires: verified.expires(),
            },
            issued: *issued,
            confirmation,
        })
    }
}

/// The evidence of one verified credential or receipt. It holds the exact bytes of the artifact, the profile that
/// verified it, and its claims. Two values are equal only for equal artifact bytes and equal profiles. A valid
/// signature alone does not give current permission.
#[derive(Clone, PartialEq, Eq)]
pub struct Verified<'a, 'p> {
    artifact: &'a [u8],
    profile: &'p Profile,
    claims: Claims,
    issued: Duration,
    /// The `cnf` key of a credential, or `None` for a receipt.
    confirmation: Option<TrustedKey>,
}

impl<'a> Verified<'a, '_> {
    /// The exact bytes of the artifact.
    #[must_use]
    pub const fn artifact(&self) -> &'a [u8] {
        self.artifact
    }

    /// The verified claims.
    #[must_use]
    pub const fn claims(&self) -> &Claims {
        &self.claims
    }

    /// The issue time `iat`, as the time since the Unix epoch.
    #[must_use]
    pub const fn issued(&self) -> Duration {
        self.issued
    }

    /// Checks the proof `proof` of possession of the `cnf` key at the physical time `now`, and gives the evidence of
    /// the authentication. The `cnf` key must sign the proof, and the proof must bind the exact bytes of this
    /// credential, the audience of the profile, and `challenge`. The signature check charges `budget`, the budget of
    /// the proof.
    ///
    /// The challenge makes the proof fresh. Issue each challenge for one proof, and consume it in the transition that
    /// uses the evidence. The evidence records the subject, [`Method::KeyPossession`], and `now`. It records no user
    /// verification, no phishing resistance, and no device or hardware binding, because the proof does not show them.
    ///
    /// Cost class: [`Verify`](crate::limits::Class::Verify).
    ///
    /// # Errors
    ///
    /// [`Error::NoConfirmation`] if the artifact has no `cnf` key. [`Error::Cose`] with [`cose::Error::Expired`],
    /// [`cose::Error::NotYetValid`], or [`cose::Error::Time`] if the credential is not valid at each time that `now`
    /// permits. [`Error::Size`] for a proof longer than [`MAX_BYTES`], and [`Error::Cose`] for a proof that does not
    /// decode. [`Error::Proof`] if the proof does not bind the credential, the audience, and the challenge, or has
    /// another claim. [`Error::Cose`] for a refusal of [`Sign1::verify`], such as [`cose::Error::Signature`] for a
    /// proof that another key signed.
    pub fn possession(
        &self,
        proof: &[u8],
        challenge: &[u8],
        now: Reading,
        budget: &mut SignatureBudget,
    ) -> Result<Evidence, Error> {
        let key = self.confirmation.as_ref().ok_or(Error::NoConfirmation)?;
        cose::validity(self.claims.not_before, self.claims.expires, now)?;
        if proof.len() > MAX_BYTES {
            return Err(Error::Size);
        }
        let limits = self.profile.cose.limits;
        let sign1 = Sign1::decode(proof, limits)?;
        let cose::Claims {
            iss: None,
            sub: None,
            aud,
            exp: None,
            nbf: None,
            iat: Some(_),
            cti: None,
            cnf: None,
            other,
        } = cose::Claims::decode(sign1.payload(), limits)?
        else {
            return Err(Error::Proof);
        };
        let digest = crypto::sha256(self.artifact);
        let (mut credential, mut nonce) = (None, None);
        for (key, value) in &other {
            match (key, value) {
                (Value::Negative(PROOF_CREDENTIAL), Value::Bytes(bytes)) => credential = Some(*bytes),
                (Value::Negative(PROOF_CHALLENGE), Value::Bytes(bytes)) => nonce = Some(*bytes),
                _ => return Err(Error::Proof),
            }
        }
        if aud != [self.profile.cose.audience.as_str()]
            || credential != Some(digest.as_slice())
            || nonce != Some(challenge)
        {
            return Err(Error::Proof);
        }
        sign1.verify(key, budget)?;
        Ok(Evidence::new(
            self.claims.subject.principal(),
            Method::KeyPossession,
            now,
            false,
            false,
            None,
        ))
    }
}

// The artifact can be a bearer receipt. Thus the output shows only its length.
impl fmt::Debug for Verified<'_, '_> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("Verified")
            .field("artifact_len", &self.artifact.len())
            .field("profile", &self.profile)
            .field("claims", &self.claims)
            .field("issued", &self.issued)
            .field("confirmation", &self.confirmation)
            .finish()
    }
}

/// Refuses an algorithm that is not a composite profile. This format accepts only the composite profiles.
fn composite(algorithm: Algorithm) -> Result<(), Error> {
    (algorithm.report().authentication == Authentication::Hybrid).ok_or(Error::Profile)
}

/// The composite algorithm of the public key `public`, and the bytes of the key.
fn composite_key<'k>(public: &PublicKey<'k>) -> Result<(Algorithm, &'k [u8]), Error> {
    match *public {
        PublicKey::MlDsa65Ed25519(bytes) => Ok((Algorithm::MlDsa65Ed25519, bytes)),
        PublicKey::MlDsa65EcdsaP256(bytes) => Ok((Algorithm::MlDsa65EcdsaP256, bytes)),
        _ => Err(Error::Profile),
    }
}

/// The cause of a refusal. For a refused artifact or proof, the recovery is to refuse it. For a refused draft, the
/// recovery is to correct the claims or the key.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Error {
    /// The COSE layer refused: the decode, the issuer, the audience, the validity interval, the key, the signature, or
    /// the signature budget.
    Cose(cose::Error),
    /// The key is not a composite profile. This format accepts only the composite profiles.
    Profile,
    /// The encoded artifact or proof is longer than [`MAX_BYTES`], or a draft can be longer.
    Size,
    /// A claim is missing, has the wrong form, or is not a claim of this format.
    Claims,
    /// The purpose of the artifact is not the purpose of the profile.
    Purpose,
    /// The validity interval of a draft is empty: `expires` is not after `iat` and `not_before`.
    Validity,
    /// The artifact has no `cnf` key, so it cannot prove possession.
    NoConfirmation,
    /// The proof does not bind the credential, the audience of the profile, and the challenge, or it has another
    /// claim.
    Proof,
}

impl fmt::Display for Error {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Cose(error) => write!(f, "the COSE layer refused the credential: {error}"),
            Self::Profile => f.write_str("the key is not a composite profile"),
            Self::Size => write!(f, "the artifact is longer than {MAX_BYTES} bytes"),
            Self::Claims => f.write_str("the claims are not the claims of a credential"),
            Self::Purpose => f.write_str("the purpose of the credential is not the purpose of the profile"),
            Self::Validity => f.write_str("the validity interval of the credential is empty"),
            Self::NoConfirmation => f.write_str("the credential has no proof-of-possession key"),
            Self::Proof => f.write_str("the proof does not bind the credential, the audience, and the challenge"),
        }
    }
}

impl core::error::Error for Error {}

impl From<cose::Error> for Error {
    fn from(error: cose::Error) -> Self {
        Self::Cose(error)
    }
}
