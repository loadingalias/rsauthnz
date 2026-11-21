//! Library-issued credentials and receipts: one format of a `COSE_Sign1` ([RFC 9052]) over CWT claims ([RFC 8392]),
//! with the proof-of-possession key of its holder ([RFC 8747]).
//!
//! The format serves workload, agent, and CLI enrollment credentials, and enrollment and approval receipts. A
//! credential has a `cnf` key: the key of its holder. A receipt has no `cnf` key. A signed purpose claim names the
//! kind of artifact. Thus one issuer key can sign each kind, and an artifact of one purpose never verifies for
//! another.
//!
//! The algorithm of the issuer key is the profile that an audience declares. The default is the composite
//! ML-DSA-65 + Ed25519 profile of [`crate::crypto`]. Pure ML-DSA-65 and the classical profiles are explicit choices for
//! an audience that supports nothing stronger. An artifact of another profile refuses, with no fallback. The `cnf` key
//! has the [`Authentication`] class of the issuer key. The SLH-DSA trust-root profile signs issuer keys, not artifacts
//! of this format, so this format refuses it.
//!
//! Issuance has two steps, so the issuer key stays in custody. [`Draft::credential`] makes a draft, and custody signs
//! the bytes of [`Draft::to_be_signed`]. [`Draft::finish`] verifies the signature with the issuer key, and only then
//! gives the artifact, as a [`Prepared`] artifact of the transition that issues it. Only the receipt of the accepted
//! transition gives its bytes, so a credential gives no authority before its commit. [`Profile::verify`] gives
//! [`Verified`] evidence. The holder makes a proof with [`ProofDraft::new`] in the same two steps; a proof gives no
//! authority, so [`ProofDraft::finish`] gives its bytes. [`Verified::possession`] checks the proof against the `cnf` key and gives
//! authentication [`Evidence`]. An encoded artifact or proof has at most [`MAX_BYTES`] bytes.
//!
//! The protected bucket of a credential or a receipt names the issuer key with its `kid`: the COSE Key Thumbprint of
//! the key ([`TrustedKey::kid`]). A profile holds the current issuer key, and during a rotation also the previous key
//! until its end ([`Profile::with_previous`]). The `kid` selects one of them, and a missing or unknown `kid` refuses.
//! Both keys have the algorithm that the audience declares, so a header never selects an algorithm. A proof has no
//! `kid`.
//!
//! ```
//! use core::time::Duration;
//! # use core::pin::pin;
//! # use core::task::{Context, Poll, Waker};
//! # use rsauthnz::cbor::Value;
//! use rsauthnz::cose::{Key, PublicKey, TrustedKey};
//! use rsauthnz::credential::{Claims, Draft, Profile, ProofDraft, Serial, Subject};
//! use rsauthnz::crypto::Algorithm;
//! use rsauthnz::evidence::Method;
//! # use rsauthnz::id::Principal;
//! use rsauthnz::id::Id;
//! use rsauthnz::limits::{Limits, SignatureBudget};
//! # use rsauthnz::store::driver::{Answer, Driver, Plan};
//! # use rsauthnz::store::{self, Store};
//! use rsauthnz::time::{Reading, ReadingSource};
//! # use rsauthnz::transition::{Audit, OperationId, Outcome, Prepared, Proposal};
//! # use rsauthnz_conformance::memory::{Memory, Schedule};
//! # use rsauthnz_conformance::suite::execute;
//! use rscrypto::auth::MlDsa65Ed25519;
//!
//! # type Failure = Box<dyn core::error::Error>;
//! # /// Commits the issuance transition of `draft`, which carries its artifact, with the driver on a memory binding.
//! # fn issue(draft: Draft, signature: &[u8], now: Reading) -> Result<Vec<u8>, Failure> {
//! #     fn ready<F: Future>(future: F) -> F::Output {
//! #         let Poll::Ready(output) = pin!(future).poll(&mut Context::from_waker(Waker::noop())) else {
//! #             unreachable!("the memory binding does no I/O")
//! #         };
//! #         output
//! #     }
//! #     let mut memory = Memory::new(Schedule::None);
//! #     let mut driver = Driver::new(store::Profile::new(memory.declaration())?, Limits::default())?;
//! #     let mut settle = |driver: &mut Driver| -> Result<(), Failure> {
//! #         while let Some(effect) = driver.effect() {
//! #             let output = ready(execute(&mut memory, effect));
//! #             driver.give(output)?;
//! #         }
//! #         Ok(())
//! #     };
//! #     driver.start(now);
//! #     settle(&mut driver)?;
//! #     let audit = Audit {
//! #         actor: Principal::Human(Id::new("acme", "u-17")?),
//! #         action: Id::new("acme.auth", "credential.issue")?,
//! #         time: now,
//! #     };
//! #     let mut proposal = Proposal::new(OperationId::new(b"issue-1")?, audit, &Value::Null, Limits::default())?;
//! #     draft.record(&mut proposal)?;
//! #     let prepared: Prepared = draft.finish(signature, &mut SignatureBudget::new(&Limits::default()))?;
//! #     proposal.prepare(prepared)?;
//! #     let ticket = driver.submit(proposal, Plan::default())?;
//! #     settle(&mut driver)?;
//! #     match driver.take(ticket) {
//! #         Some(Answer::Outcome(Outcome::Accepted(receipt))) => Ok(receipt.artifact().ok_or("no artifact")?.to_vec()),
//! #         answer => Err(format!("the issuance did not commit: {answer:?}").into()),
//! #     }
//! # }
//! #
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
//! // 1. The issuer makes a draft. Custody signs it, and `finish` verifies the signature before it gives the
//! // prepared artifact. The issuance transition writes the issuance record of the draft and carries the artifact,
//! // and only the receipt of its commit gives the bytes.
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
//! let credential = issue(draft, signature.as_bytes(), now)?;
//!
//! // 2. The verifier fixes the issuer, the audience, and the purpose, and verifies the credential.
//! let (issuer, audience, purpose) = (claims.issuer.clone(), claims.audience.clone(), claims.purpose.clone());
//! let profile = Profile::new(issuer_key, issuer, audience, purpose, Limits::default())?;
//! let verified = profile.verify(&credential, now, &mut SignatureBudget::new(&Limits::default()))?;
//! assert_eq!(verified.claims(), &claims);
//!
//! // 3. The holder signs a proof over the challenge of the verifier, and the verifier checks it.
//! let challenge = [7; 32];
//! let draft = ProofDraft::new(&holder_key, &credential, &claims.audience, &challenge, now)?;
//! let signature = holder_secret.sign_deterministic(&draft.to_be_signed(), &[])?;
//! let proof = draft.finish(signature.as_bytes(), &mut SignatureBudget::new(&Limits::default()))?;
//! let evidence = verified.possession(&proof, &challenge, now, &mut SignatureBudget::new(&Limits::default()))?;
//! assert_eq!(evidence.method(), Method::KeyPossession);
//! # Ok::<(), Failure>(())
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
use crate::cose::{self, Confirmation, Key as CoseKey, PublicKey, Sign1, TrustedKey};
use crate::crypto::{self, Algorithm, Authentication, Report};
use crate::evidence::{Artifact, Evidence, Method};
use crate::id::{Agent, Audience, Authority, AuthorityVersion, Human, Id, Principal, Purpose, Workload};
use crate::limits::{Limits, SignatureBudget};
use crate::store::Kind;
use crate::time::Reading;
use crate::transition::{self, Change, Dependency, Key, Prepared, Proposal};

/// The most bytes of an encoded credential, receipt, or proof. A draft that can be longer refuses before custody signs
/// it, and verification refuses a longer input before it decodes it.
pub const MAX_BYTES: usize = 8_192;

/// The longest signature of a profile of this format. ML-DSA-65 + ECDSA P-256 has the 3,309 bytes of ML-DSA-65 and at
/// most 72 bytes of DER ECDSA. ML-DSA-65 + Ed25519 has 3,373 bytes, ML-DSA-65 has 3,309 bytes, and Ed25519 and ES256
/// have 64 bytes.
const SIGNATURE_BYTES_MAX: usize = 3_381;

/// The tag of a `COSE_Sign1` (RFC 9052 section 2).
const SIGN1_TAG: u64 = 18;
/// The first byte of an artifact or a proof: the head of the tag 18. The decoder accepts only the shortest head, so a
/// decoded input that starts with this byte has the tag 18 as its outer item.
const SIGN1_HEAD: u8 = 0xd2;

/// The first item of the CBOR form of an issuance record ([`Draft::record`]). Its number changes with the form.
const RECORD_FORM: &str = "rsauthnz.credential.record.1";

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
    pub(crate) fn to_cbor(&self) -> Value<'_> {
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

/// The key of the issuance record of the artifact with the serial `serial`: [`Kind::Credential`] with the 8 bytes of
/// the serial, the most significant byte first. The transition that issues an artifact writes it
/// ([`Draft::record`]), so one serial gives at most one artifact.
///
/// Cost class: [`Parse`](crate::limits::Class::Parse).
#[must_use]
pub fn record_key(serial: Serial) -> Key {
    Kind::Credential
        .key(&serial.0.to_be_bytes())
        .expect("a key of 9 bytes is valid")
}

/// The issuance record of an artifact: the record that the transition that issues it writes.
#[derive(Clone, PartialEq, Eq)]
struct Issuance {
    key: Key,
    version: AuthorityVersion,
    end: Duration,
    data: Box<[u8]>,
}

/// The fields of an issuance record that a check reads: the issuer, the subject, the audience, the purpose, and the
/// end of the artifact.
#[derive(Clone, Debug, PartialEq, Eq)]
pub(crate) struct Issued {
    pub(crate) issuer: Id<Authority>,
    pub(crate) subject: Principal,
    pub(crate) audience: Id<Audience>,
    pub(crate) purpose: Id<Purpose>,
    pub(crate) expires: Duration,
}

impl Issued {
    /// Reads the record form `data` of an issuance record ([`Draft::record`]) within `limits`, or `None` for another
    /// form.
    pub(crate) fn from_record(data: &[u8], limits: Limits) -> Option<Self> {
        let value = cbor::decode(data, limits).ok()?;
        let Value::Array(items) = &value else {
            return None;
        };
        let [
            Value::Text(RECORD_FORM),
            issuer,
            subject,
            audience,
            purpose,
            Value::Unsigned(expires),
        ] = items.as_slice()
        else {
            return None;
        };
        Some(Self {
            issuer: Id::from_cbor(issuer).ok()?,
            subject: Principal::from_cbor(subject).ok()?,
            audience: Id::from_cbor(audience).ok()?,
            purpose: Id::from_cbor(purpose).ok()?,
            expires: Duration::from_secs(*expires),
        })
    }
}

/// The bytes that a key signs, before the signature: the encoded protected bucket and the encoded claims.
#[derive(Clone)]
pub(crate) struct Unsigned {
    /// The public key of the signer.
    key: TrustedKey,
    /// The encoded protected bucket: `alg`, and the `kid` of the issuer key for a credential or a receipt.
    protected: Vec<u8>,
    /// The encoded claims.
    payload: Vec<u8>,
}

/// A credential or a receipt that custody did not sign yet. [`Draft::finish`] consumes it, so one draft gives at most
/// one artifact. [`ProofDraft`] is the draft of a proof.
pub struct Draft {
    unsigned: Unsigned,
    issuance: Issuance,
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
    /// `key` is a trust-root key, or `confirmation` has another [`Authentication`] class than `key`. [`Error::Cose`]
    /// with [`cose::Error::Malformed`] if the P-256 point of `confirmation` is not on the curve. [`Error::Size`] if
    /// the artifact can be longer than [`MAX_BYTES`].
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
        if let Some(public) = &confirmation {
            // A key whose P-256 point is not on the curve refuses here, before custody signs.
            TrustedKey::new(
                confirmation_algorithm(key.algorithm(), public)?,
                &CoseKey {
                    kid: None,
                    alg: None,
                    public: public.clone(),
                },
            )?;
        }
        let payload = payload(claims, issued, expires, not_before, confirmation.as_ref());
        let serial = claims.serial.0.to_be_bytes();
        let data = cbor::encode(
            &Value::Array(vec![
                Value::Text(RECORD_FORM),
                claims.issuer.to_cbor(),
                claims.subject.to_cbor(),
                claims.audience.to_cbor(),
                claims.purpose.to_cbor(),
                Value::Unsigned(expires),
            ]),
            Limits::FORM,
        )
        .expect("the form has no map and no simple value");
        let issuance = Issuance {
            key: record_key(claims.serial),
            version: AuthorityVersion::new(claims.issuer.clone(), &serial).expect("an 8-byte coordinate is valid"),
            end: Duration::from_secs(expires),
            data: data.into_boxed_slice(),
        };
        Ok(Self {
            unsigned: Unsigned::new(key, payload, Some(key.kid()))?,
            issuance,
        })
    }

    /// Adds the issuance record of the artifact to `proposal`: the absence of the record of its serial
    /// ([`record_key`]), and its write. The record holds no signature. Its version is the issuer of the claims and the
    /// serial, and it ends when the artifact ends. Its record form is the canonical CBOR array
    /// `["rsauthnz.credential.record.1", issuer, subject, audience, purpose, expires]`. Add it before
    /// [`Proposal::prepare`] of the artifact of [`Self::finish`]: thus one serial gives one artifact, and the artifact
    /// commits only with its own issuance.
    ///
    /// Cost class: [`Parse`](crate::limits::Class::Parse).
    ///
    /// # Errors
    ///
    /// The errors of [`Proposal::read`] and [`Proposal::change`].
    pub fn record(&self, proposal: &mut Proposal) -> Result<(), transition::Error> {
        let Issuance {
            key,
            version,
            end,
            data,
        } = self.issuance.clone();
        proposal.read(Dependency::Absent(key.clone()))?;
        proposal.change(Change::Write {
            key,
            version,
            end: Some(end),
            data,
        })
    }

    /// The bytes that custody signs: the `Sig_structure` of RFC 9052 section 4.4, with an empty external AAD. Custody
    /// signs them with the algorithm of the key. ML-DSA-65 and the composites use the empty context.
    ///
    /// Cost class: [`Parse`](crate::limits::Class::Parse).
    #[must_use]
    pub fn to_be_signed(&self) -> Vec<u8> {
        self.unsigned.to_be_signed()
    }

    /// Verifies `signature`, the signature of custody over [`Self::to_be_signed`], with the key of the draft. Then it
    /// gives the encoded artifact as a [`Prepared`] artifact: a `COSE_Sign1` with the tag 18 and an empty unprotected
    /// bucket. Give it to [`Proposal::prepare`] of the transition that writes its issuance record ([`Self::record`]).
    /// Only the receipt of the accepted transition gives its bytes, so a credential never gives authority before its
    /// commit. The check charges `budget`, the budget of the artifact. A refusal gives no artifact.
    ///
    /// Cost class: [`Verify`](crate::limits::Class::Verify).
    ///
    /// # Errors
    ///
    /// [`Error::Cose`] with [`cose::Error::Signature`] if the signature does not verify with the key of the draft, for
    /// example because custody signed with another key. [`Error::Cose`] with [`cose::Error::Limit`] if the check
    /// costs more than `budget` has.
    pub fn finish(self, signature: &[u8], budget: &mut SignatureBudget) -> Result<Prepared, Error> {
        let artifact = self.unsigned.sign(signature, budget)?;
        Ok(Prepared::new(artifact, self.issuance.key, self.issuance.version))
    }

    /// The bytes that custody signs, before the signature, for a record that keeps the artifact without its signature.
    pub(crate) const fn unsigned(&self) -> &Unsigned {
        &self.unsigned
    }
}

impl Unsigned {
    /// The unsigned bytes of the encoded claims `payload` that `key` signs. The protected bucket holds `alg`, and `kid`
    /// when `kid` is not `None`.
    fn new(key: &TrustedKey, payload: Vec<u8>, kid: Option<&[u8; 32]>) -> Result<Self, Error> {
        let protected = protected(key, kid)?;
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

    /// The unsigned bytes that a record keeps: the encoded protected bucket and the encoded claims, which `key` signs.
    /// The record that keeps them is the record of this crate, so the bytes are the bytes of an earlier draft.
    pub(crate) fn from_parts(key: TrustedKey, protected: &[u8], payload: &[u8]) -> Self {
        Self {
            key,
            protected: protected.to_vec(),
            payload: payload.to_vec(),
        }
    }

    /// The encoded protected bucket.
    pub(crate) fn protected(&self) -> &[u8] {
        &self.protected
    }

    /// The encoded claims.
    pub(crate) fn payload(&self) -> &[u8] {
        &self.payload
    }

    /// The `Sig_structure` that the key signs.
    pub(crate) fn to_be_signed(&self) -> Vec<u8> {
        cose::to_be_signed(&self.protected, &self.payload)
    }

    /// The encoded `COSE_Sign1` of the unsigned bytes and `signature`, after a check of `signature` with the key that
    /// charges `budget`.
    pub(crate) fn sign(self, signature: &[u8], budget: &mut SignatureBudget) -> Result<Vec<u8>, Error> {
        self.key.verify(&self.to_be_signed(), signature, budget)?;
        let artifact = cbor::encode(
            &Value::Tag(
                SIGN1_TAG,
                Box::new(Value::Array(vec![
                    Value::Bytes(&self.protected),
                    Value::Map(Vec::new()),
                    Value::Bytes(&self.payload),
                    Value::Bytes(signature),
                ])),
            ),
            Limits::FORM,
        )
        .expect("a COSE_Sign1 has no map key and no simple value");
        assert!(
            artifact.len() <= MAX_BYTES,
            "the draft bounded the length with the longest signature of the format, and a valid signature is not longer"
        );
        Ok(artifact)
    }
}

// The payload can hold a bearer receipt. Thus the output shows the algorithm and only the length of each part.
impl fmt::Debug for Unsigned {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("Unsigned")
            .field("key", &self.key)
            .field("protected_len", &self.protected.len())
            .field("payload_len", &self.payload.len())
            .finish()
    }
}

impl fmt::Debug for Draft {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("Draft")
            .field("unsigned", &self.unsigned)
            .field("record", &self.issuance.key)
            .finish()
    }
}

/// A proof of possession that the holder key did not sign yet. A proof gives no authority, so [`ProofDraft::finish`]
/// gives its bytes at once. [`ProofDraft::finish`] consumes the draft, so one draft gives at most one proof.
#[derive(Debug)]
pub struct ProofDraft(Unsigned);

impl ProofDraft {
    /// The draft of a proof of possession that the holder key `key`, the `cnf` key of `credential`, signs. The proof
    /// binds the SHA-256 digest of the exact bytes of `credential`, the audience `audience` of the verifier, the
    /// challenge `challenge` of the verifier, and the time `iat`: the whole seconds of `now.estimate()`.
    ///
    /// Cost class: [`Parse`](crate::limits::Class::Parse). The draft checks the lengths of `credential` and
    /// `challenge` before it reads them.
    ///
    /// # Errors
    ///
    /// [`Error::Profile`] if `key` is a trust-root key. [`Error::Size`] if `credential` or `challenge` is longer than
    /// [`MAX_BYTES`], or the proof can be longer than [`MAX_BYTES`].
    pub fn new(
        key: &TrustedKey,
        credential: &[u8],
        audience: &Id<Audience>,
        challenge: &[u8],
        now: Reading,
    ) -> Result<Self, Error> {
        (credential.len() <= MAX_BYTES && challenge.len() <= MAX_BYTES).ok_or(Error::Size)?;
        let payload = proof_payload(
            &audience.to_string(),
            now.estimate().as_secs(),
            &crypto::sha256(credential),
            challenge,
        );
        Unsigned::new(key, payload, None).map(Self)
    }

    /// The bytes that custody signs with the holder key, as [`Draft::to_be_signed`] gives them.
    ///
    /// Cost class: [`Parse`](crate::limits::Class::Parse).
    #[must_use]
    pub fn to_be_signed(&self) -> Vec<u8> {
        self.0.to_be_signed()
    }

    /// Verifies `signature`, the signature of custody over [`Self::to_be_signed`], with the holder key. Then it gives
    /// the encoded proof: a `COSE_Sign1` with the tag 18. The check charges `budget`. A refusal gives no bytes.
    ///
    /// Cost class: [`Verify`](crate::limits::Class::Verify).
    ///
    /// # Errors
    ///
    /// [`Error::Cose`] with [`cose::Error::Signature`] if the signature does not verify with the holder key.
    /// [`Error::Cose`] with [`cose::Error::Limit`] if the check costs more than `budget` has.
    pub fn finish(self, signature: &[u8], budget: &mut SignatureBudget) -> Result<Vec<u8>, Error> {
        self.0.sign(signature, budget)
    }
}

/// A trusted verification profile of credentials and receipts: the issuer key, the issuer, the audience, and the
/// purpose that the application fixes before it reads an artifact. The algorithm of the issuer key is the profile that
/// the audience declares. An artifact of another algorithm refuses, and no other key is tried.
///
/// During a rotation of the issuer key, the profile also holds the previous key ([`Profile::with_previous`]). The
/// protected `kid` of an artifact selects one of the two keys. Both have one algorithm, so the `kid` never selects an
/// algorithm, and each artifact costs one signature check.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Profile {
    /// The COSE profile, with the current issuer key and the text forms of the issuer and the audience.
    cose: cose::Profile,
    /// The issuer key that the current key replaced, with the algorithm of the current key, and the end of its trust.
    previous: Option<(TrustedKey, Duration)>,
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
    /// [`Error::Profile`] if `key` is a trust-root key.
    pub fn new(
        key: TrustedKey,
        issuer: Id<Authority>,
        audience: Id<Audience>,
        purpose: Id<Purpose>,
        limits: Limits,
    ) -> Result<Self, Error> {
        class(key.algorithm())?;
        Ok(Self {
            cose: cose::Profile {
                key,
                issuer: issuer.to_string(),
                audience: audience.to_string(),
                purpose,
                limits,
            },
            previous: None,
            issuer,
            audience,
        })
    }

    /// The profile that also verifies the artifacts of `previous`: the issuer key that the key of the profile replaced.
    /// It verifies them until `until`, the time from which no artifact that `previous` signed is valid. `until` is the
    /// time since the Unix epoch. A check whose reading can be at or after `until` refuses an artifact of `previous`.
    /// Thus a retired key that an attacker gets later signs nothing that verifies.
    ///
    /// Cost class: [`Parse`](crate::limits::Class::Parse).
    ///
    /// # Errors
    ///
    /// [`Error::Profile`] if `previous` has another algorithm than the key of the profile.
    pub fn with_previous(mut self, previous: TrustedKey, until: Duration) -> Result<Self, Error> {
        (previous.algorithm() == self.cose.key.algorithm()).ok_or(Error::Profile)?;
        self.previous = Some((previous, until));
        Ok(self)
    }

    /// Verifies the credential or receipt `artifact` at the physical time `now`. The signature check charges `budget`,
    /// the budget of the artifact.
    ///
    /// Cost class: [`Verify`](crate::limits::Class::Verify).
    ///
    /// The checks are those of [`cose::Profile::verify`], with `iss` and `aud` in their text forms, and with the key
    /// that the protected `kid` names. The artifact must be in the exact form of this format: the tag 18, the
    /// protected bucket of the issuer key, an empty unprotected bucket, and the claims in the encoding that
    /// [`Draft::credential`] writes. Thus an `aud` array, a float time, or another member of the `cnf` key refuses.
    /// Then the claims must be the claims of this format, and the purpose must be the purpose of the profile. A `cnf`
    /// key must have the [`Authentication`] class of the issuer key.
    ///
    /// # Errors
    ///
    /// [`Error::Size`] for an artifact longer than [`MAX_BYTES`], and [`Error::Cose`] for each refusal of
    /// [`cose::Profile::verify`], such as [`cose::Error::AlgorithmMismatch`] for an artifact of another profile.
    /// [`Error::Cose`] with [`cose::Error::KeyId`] if the protected bucket has no `kid`, or its `kid` names no key of
    /// the profile. It is also the error for the previous key when `now` can be at or after the end of that key.
    /// [`Error::Form`] for another tag, another protected or unprotected bucket, or another encoding of the claims.
    /// [`Error::Claims`] if a claim is missing, has the wrong form, or is not a claim of this format.
    /// [`Error::Purpose`] for another purpose, and [`Error::Profile`] for a `cnf` key of another class.
    pub fn verify<'a>(
        &self,
        artifact: &'a [u8],
        now: Reading,
        budget: &mut SignatureBudget,
    ) -> Result<Verified<'a, '_>, Error> {
        if artifact.len() > MAX_BYTES {
            return Err(Error::Size);
        }
        let (mut until, mut payload) = (None, &[][..]);
        let verified = self.cose.verify_by::<Error>(artifact, now, budget, |sign1| {
            let Some(Value::Bytes(kid)) = sign1.protected().get(4) else {
                return Err(cose::Error::KeyId.into());
            };
            let key = if self.cose.key.kid() == *kid {
                &self.cose.key
            } else {
                // The validity check came first, so the reading has a known bound.
                match &self.previous {
                    Some((previous, end)) if previous.kid() == *kid && now.latest().is_ok_and(|now| now < *end) => {
                        until = Some(*end);
                        previous
                    }
                    _ => return Err(cose::Error::KeyId.into()),
                }
            };
            envelope(artifact, sign1, key, Some(key.kid()))?;
            payload = sign1.payload();
            Ok(key)
        })?;
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
        let (public, confirmation) = match cnf {
            None => (None, None),
            Some(Confirmation::Key(key)) => (
                Some(&key.public),
                Some(TrustedKey::new(
                    confirmation_algorithm(self.cose.key.algorithm(), &key.public)?,
                    key,
                )?),
            ),
            Some(Confirmation::KeyId(_)) => return Err(Error::Claims),
        };
        let claims = Claims {
            issuer: self.issuer.clone(),
            audience: self.audience.clone(),
            subject,
            purpose,
            serial,
            not_before: *nbf,
            expires: verified.expires(),
        };
        // A time with a fraction encodes as a whole second here, so it refuses too.
        let exact = claims.not_before.map(|nbf| nbf.as_secs());
        (payload == self::payload(&claims, issued.as_secs(), claims.expires.as_secs(), exact, public))
            .ok_or(Error::Form)?;
        Ok(Verified {
            artifact,
            profile: self,
            claims,
            issued: *issued,
            confirmation,
            until,
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
    /// The end of the previous issuer key of the profile when that key verified the artifact, or `None` for the
    /// current key.
    until: Option<Duration>,
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

    /// The `cnf` key of a credential, or `None` for a receipt.
    pub(crate) const fn confirmation(&self) -> Option<&TrustedKey> {
        self.confirmation.as_ref()
    }

    /// The report of the profile of the issuer signature. Its `authentication` says if the artifact has post-quantum
    /// authentication. A `cnf` key has the same class, so the evidence of [`Self::possession`] has the same
    /// authentication.
    #[must_use]
    pub const fn report(&self) -> Report {
        self.profile.cose.key.algorithm().report()
    }

    /// Checks the proof `proof` of possession of the `cnf` key at the physical time `now`, and gives the evidence of
    /// the authentication. The `cnf` key must sign the proof, and the proof must bind the exact bytes of this
    /// credential, the audience of the profile, and `challenge`. The signature check charges `budget`, the budget of
    /// the proof.
    ///
    /// The challenge makes the proof fresh. Issue each challenge for one proof, and consume it in the transition that
    /// uses the evidence. The evidence records the subject, [`Method::KeyPossession`], `now`, and the
    /// [`Authentication`] of the `cnf` key. It also keeps the credential ([`Evidence::artifact`]): its verified claims,
    /// with the issuer, the audience, the purpose, the serial, the end, and the owner of an agent, and the SHA-256
    /// digest of its bytes. Thus a check of the evidence ends with the credential ([`authz::check`](crate::authz::check)).
    /// For a credential of the previous issuer key ([`Profile::with_previous`]), the check refuses at or after the end
    /// of that key, also for a [`Verified`] that an earlier reading gave, and the evidence ends there too.
    /// It records no user verification, no phishing resistance, and no device or hardware binding, because the proof
    /// does not show them.
    ///
    /// Cost class: [`Verify`](crate::limits::Class::Verify).
    ///
    /// # Errors
    ///
    /// [`Error::NoConfirmation`] if the artifact has no `cnf` key. [`Error::Cose`] with [`cose::Error::Expired`],
    /// [`cose::Error::NotYetValid`], or [`cose::Error::Time`] if the credential is not valid at each time that `now`
    /// permits, and with [`cose::Error::KeyId`] if `now` can be at or after the end of the previous issuer key that
    /// verified it. [`Error::Size`] for a proof longer than [`MAX_BYTES`], and [`Error::Cose`] for a proof that does
    /// not decode. [`Error::Form`] for a proof with another tag or bucket. [`Error::Proof`] if the proof does not bind
    /// the credential, the audience, and the challenge in the encoding of [`ProofDraft::new`], or has another claim.
    /// [`Error::Cose`] for a refusal of [`Sign1::verify`], such as [`cose::Error::Signature`] for a proof that another
    /// key signed.
    pub fn possession(
        &self,
        proof: &[u8],
        challenge: &[u8],
        now: Reading,
        budget: &mut SignatureBudget,
    ) -> Result<Evidence, Error> {
        let key = self.confirmation.as_ref().ok_or(Error::NoConfirmation)?;
        cose::validity(self.claims.not_before, self.claims.expires, now)?;
        // The validity check proved a known bound. An artifact of the previous issuer key ends with that key.
        if self
            .until
            .is_some_and(|until| now.latest().is_ok_and(|now| now >= until))
        {
            return Err(cose::Error::KeyId.into());
        }
        let cose = &self.profile.cose;
        check_proof(
            key,
            self.artifact,
            &cose.audience,
            proof,
            challenge,
            cose.limits,
            budget,
        )?;
        let mut evidence = Evidence::new(
            self.claims.subject.principal(),
            Method::KeyPossession,
            now,
            false,
            false,
            None,
            Some(key.algorithm().report().authentication),
        );
        evidence.artifact = Some(Artifact {
            claims: self.claims.clone(),
            digest: crypto::sha256(self.artifact),
            end: self
                .until
                .map_or(self.claims.expires, |until| until.min(self.claims.expires)),
        });
        Ok(evidence)
    }
}

/// Checks that `key` signed `proof`, a proof of possession ([`ProofDraft`]) that binds the exact bytes of `artifact`,
/// `audience` in its text form, and `challenge`. The decode uses `limits`, and the signature check charges `budget`.
///
/// Cost class: [`Verify`](crate::limits::Class::Verify).
///
/// # Errors
///
/// The errors of [`Verified::possession`] for the proof: [`Error::Size`], [`Error::Form`], [`Error::Proof`], and
/// [`Error::Cose`].
pub(crate) fn check_proof(
    key: &TrustedKey,
    artifact: &[u8],
    audience: &str,
    proof: &[u8],
    challenge: &[u8],
    limits: Limits,
    budget: &mut SignatureBudget,
) -> Result<(), Error> {
    if proof.len() > MAX_BYTES {
        return Err(Error::Size);
    }
    let sign1 = Sign1::decode(proof, limits)?;
    envelope(proof, &sign1, key, None)?;
    // A proof of at most `MAX_BYTES` bytes cannot hold a longer challenge.
    (challenge.len() <= MAX_BYTES).ok_or(Error::Proof)?;
    let issued = cose::Claims::decode(sign1.payload(), limits)?.iat.ok_or(Error::Proof)?;
    // The proof binds exactly these claims, in the encoding of the draft. A time with a fraction refuses too.
    let expected = proof_payload(audience, issued.as_secs(), &crypto::sha256(artifact), challenge);
    (sign1.payload() == expected).ok_or(Error::Proof)?;
    sign1.verify(key, budget)?;
    Ok(())
}

/// Refuses an artifact or a proof `input`, decoded as `sign1`, that is not in the envelope of this format: the tag
/// 18, the protected bucket of `key` with the `kid` `kid`, and an empty unprotected bucket.
fn envelope(input: &[u8], sign1: &Sign1<'_>, key: &TrustedKey, kid: Option<&[u8; 32]>) -> Result<(), Error> {
    // An artifact of another profile keeps the refusal of its algorithm.
    if sign1.protected().get(1) != cose::alg(key.algorithm()).as_ref() {
        return Err(cose::Error::AlgorithmMismatch.into());
    }
    let exact = input.first() == Some(&SIGN1_HEAD)
        && sign1.unprotected().entries().is_empty()
        && sign1.protected_bytes() == protected(key, kid)?.as_slice();
    exact.ok_or(Error::Form)
}

/// The encoded protected bucket of an artifact or a proof that `key` signs: `alg`, and `kid` when it is not `None`.
fn protected(key: &TrustedKey, kid: Option<&[u8; 32]>) -> Result<Vec<u8>, Error> {
    class(key.algorithm())?;
    let alg = cose::alg(key.algorithm()).ok_or(Error::Profile)?;
    let mut header = vec![(Value::Unsigned(1), alg)];
    header.extend(kid.map(|kid| (Value::Unsigned(4), Value::Bytes(kid))));
    Ok(cbor::encode(&Value::Map(header), Limits::FORM)
        .expect("the protected bucket has distinct keys and no simple value"))
}

/// The encoded claims of a credential or a receipt with `claims`, the issue time `issued`, and the `cnf` key
/// `confirmation`. `issued`, `expires`, and `not_before` are whole seconds. Issuance and verification encode them with
/// this one function, so a verified artifact has exactly the encoding of its draft.
fn payload(
    claims: &Claims,
    issued: u64,
    expires: u64,
    not_before: Option<u64>,
    confirmation: Option<&PublicKey<'_>>,
) -> Vec<u8> {
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
    entries.extend(not_before.map(|nbf| (Value::Unsigned(5), Value::Unsigned(nbf))));
    if let Subject::Agent { owner, .. } = &claims.subject {
        entries.push((Value::Negative(OWNER), owner.to_cbor()));
    }
    // The `COSE_Key` member (1) holds the key with its `alg`.
    entries.extend(confirmation.map(|public| {
        (
            Value::Unsigned(8),
            Value::Map(vec![(Value::Unsigned(1), public.to_cbor())]),
        )
    }));
    cbor::encode(&Value::Map(entries), Limits::FORM).expect("the claims have distinct keys and no simple value")
}

/// The encoded claims of a proof: `aud` (3), `iat` (6) in whole seconds, the SHA-256 `digest` of the credential, and
/// the `challenge` of the verifier. A draft and a check encode them with this one function, after each checks that
/// `challenge` has at most [`MAX_BYTES`] bytes.
fn proof_payload(audience: &str, issued: u64, digest: &[u8; 32], challenge: &[u8]) -> Vec<u8> {
    let claims = Value::Map(vec![
        (Value::Unsigned(3), Value::Text(audience)),
        (Value::Unsigned(6), Value::Unsigned(issued)),
        (Value::Negative(PROOF_CREDENTIAL), Value::Bytes(digest)),
        (Value::Negative(PROOF_CHALLENGE), Value::Bytes(challenge)),
    ]);
    cbor::encode(&claims, Limits::FORM).expect("the claims have distinct keys and no simple value")
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

/// The [`Authentication`] class of a profile of this format. The SLH-DSA trust-root profile signs issuer keys, and RS256
/// and PS256 only verify external artifacts, so this format refuses them.
const fn class(algorithm: Algorithm) -> Result<Authentication, Error> {
    match algorithm {
        Algorithm::Ed25519
        | Algorithm::Es256
        | Algorithm::MlDsa65
        | Algorithm::MlDsa65Ed25519
        | Algorithm::MlDsa65EcdsaP256 => Ok(algorithm.report().authentication),
        Algorithm::Rs256 | Algorithm::Ps256 | Algorithm::SlhDsaSha2_128s => Err(Error::Profile),
    }
}

/// The algorithm of the `cnf` key `public`. It must have the class of the issuer key algorithm `issuer`.
fn confirmation_algorithm(issuer: Algorithm, public: &PublicKey<'_>) -> Result<Algorithm, Error> {
    let algorithm = public.algorithm();
    (class(algorithm)? == class(issuer)?).ok_or(Error::Profile)?;
    Ok(algorithm)
}

/// The cause of a refusal. For a refused artifact or proof, the recovery is to refuse it. For a refused draft, the
/// recovery is to correct the claims or the key.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Error {
    /// The COSE layer refused: the decode, the issuer, the audience, the validity interval, the key, the signature, or
    /// the signature budget.
    Cose(cose::Error),
    /// The key is a trust-root key, which this format refuses, or the `cnf` key has another [`Authentication`] class
    /// than the issuer key.
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
    /// The artifact or the proof is not in the exact form of this format: another tag, another protected or
    /// unprotected bucket, or another encoding of its claims, such as an `aud` array or a float time.
    Form,
}

impl fmt::Display for Error {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Cose(error) => write!(f, "the COSE layer refused the credential: {error}"),
            Self::Profile => {
                f.write_str("the key is a trust-root key, or its class is not the class of the issuer key")
            }
            Self::Size => write!(f, "the artifact is longer than {MAX_BYTES} bytes"),
            Self::Claims => f.write_str("the claims are not the claims of a credential"),
            Self::Purpose => f.write_str("the purpose of the credential is not the purpose of the profile"),
            Self::Validity => f.write_str("the validity interval of the credential is empty"),
            Self::NoConfirmation => f.write_str("the credential has no proof-of-possession key"),
            Self::Proof => f.write_str("the proof does not bind the credential, the audience, and the challenge"),
            Self::Form => f.write_str("the artifact is not in the exact form of the credential format"),
        }
    }
}

impl core::error::Error for Error {}

impl From<cose::Error> for Error {
    fn from(error: cose::Error) -> Self {
        Self::Cose(error)
    }
}
