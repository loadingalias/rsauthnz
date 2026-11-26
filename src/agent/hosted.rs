//! Hosted bootstrap: a hosted agent asks for its enrollment with the identity of its workload, in place of a pasted
//! secret. The human owner still approves, and only the approval names the owner.

use alloc::boxed::Box;
use alloc::string::String;
use alloc::vec::Vec;
use core::fmt;

use rscodec::base64::Profile::Url;

use super::{Error, KEY_BYTES, encode};
use crate::cbor::Value;
use crate::credential::{self, Subject};
use crate::crypto;
use crate::jose;
use crate::limits::SignatureBudget;
use crate::time::Reading;
use crate::trust::{KeySet, View};

/// The most bytes of the issuer and of the subject of a [`Workload`]: the most bytes of a SPIFFE ID.
pub const WORKLOAD_BYTES_MAX: usize = 2048;

/// The first item of the challenge of a proof of a workload credential.
const CHALLENGE_FORM: &str = "rsauthnz.agent.bootstrap.1";

/// How a token of a [`Platform`] binds to the key of the agent that presents it.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub enum Binding {
    /// The audience of the token is the audience of the platform, `#`, and the base64url of the SHA-256 fingerprint of
    /// the agent key ([`Self::audience`]). So a stolen token labels only the key that it names. SPIRE, the metadata
    /// server of Google Cloud, and GitHub Actions give a token for the audience that the caller names.
    Key,
    /// The audience of the token is the audience of the platform. A stolen token labels each key until the token
    /// ends. Use it only for a platform that fixes the audience, such as a managed identity of Azure or a projected
    /// service account token of Kubernetes.
    Bearer,
}

impl Binding {
    /// The audience of a token of the agent with the key `key`, for a platform with the audience `audience`. The agent
    /// asks its platform for a token with this audience.
    ///
    /// Cost class: [`Parse`](crate::limits::Class::Parse).
    #[must_use]
    pub fn audience(self, audience: &str, key: &[u8; KEY_BYTES]) -> String {
        match self {
            Self::Key => {
                let mut fingerprint = [0; 43];
                let fingerprint = Url
                    .encode(&crypto::sha256(key), &mut fingerprint)
                    .expect("32 bytes have 43 base64url characters");
                let fingerprint = core::str::from_utf8(fingerprint).expect("base64url is ASCII");
                [audience, "#", fingerprint].concat()
            }
            Self::Bearer => audience.into(),
        }
    }
}

/// An outside issuer of workload identity tokens that the host configures, such as a SPIFFE trust domain or a cloud
/// OpenID Connect issuer: its fetched key set, and the binding of its tokens. A host with more than one platform selects
/// the platform of a request itself, for example by the address of the request.
#[derive(Debug)]
pub struct Platform {
    /// The key set of the issuer. Its profile fixes the algorithm, the kind, the issuer, and the audience of the
    /// tokens: [`jose::Kind::Svid`] with the SPIFFE ID of the trust domain for a JWT-SVID, or [`jose::Kind::Jwt`] with
    /// the `iss` of a cloud identity token. The audience names this authority.
    pub keys: KeySet,
    /// The binding of the tokens of the issuer to the agent key.
    pub binding: Binding,
}

impl Platform {
    /// The workload of the token `token` of the agent with the key `key`, at `now`. The fresh key set checks the token
    /// ([`jose::Profile::verify_jwt`]) for the audience of the binding. The workload is the issuer of the profile and
    /// the `sub` of the token. Each other claim gives nothing, also a claim that names a person, such as `email`: the
    /// owner comes only from the approval.
    ///
    /// Cost class: [`Verify`](crate::limits::Class::Verify). One signature check.
    ///
    /// # Errors
    ///
    /// [`Error::Trust`] if the key set is missing or stale, or the reading refuses. [`Error::Token`] for each refusal
    /// of the token, such as [`jose::Error::Expired`], [`jose::Error::Issuer`] for a token of another issuer or trust
    /// domain, and [`jose::Error::Audience`] for a token of another key. [`Error::Workload`] if the issuer or `sub` is
    /// longer than [`WORKLOAD_BYTES_MAX`] or holds a control character.
    pub fn verify(&self, token: &str, key: &[u8; KEY_BYTES], now: Reading) -> Result<Workload, Error> {
        let profile = self.keys.view(now).map_err(Error::Trust)?;
        let audience = self.binding.audience(profile.audience(), key);
        let jwt = profile.verify_jwt_to(token, &audience, now).map_err(Error::Token)?;
        let subject = jwt.claims().sub.as_deref().ok_or(Error::Token(jose::Error::Claims))?;
        Workload::new(profile.issuer(), subject)
    }
}

/// The verified workload of a hosted agent at its enrollment request ([`Platform::verify`],
/// [`Workload::credential`]). It names no owner.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Workload {
    issuer: Box<str>,
    subject: Box<str>,
}

impl Workload {
    /// The workload of the workload credential `credential` of this library, with the proof `proof` by its `cnf` key
    /// of the challenge of the agent key `key` ([`Self::challenge`]), at `now`. `profile` is the profile of the issuer
    /// of the fresh snapshot `view` for the audience of this authority: `view.issuer(&authority)` and
    /// [`Issuer::profile`](crate::workload::Issuer::profile). The snapshot refuses a credential that a rotation, a
    /// recovery, or a revocation ended. The workload is the issuer and the workload of the credential.
    ///
    /// Cost class: [`Verify`](crate::limits::Class::Verify). The signature checks of the credential and of the proof,
    /// each within the limits of `profile`.
    ///
    /// # Errors
    ///
    /// [`Error::Credential`] for each refusal of the credential or the proof ([`credential::Verified::possession`]),
    /// and [`Error::Admission`] if the snapshot does not admit the credential.
    pub fn credential(
        view: &View<'_>,
        profile: &credential::Profile,
        credential: &[u8],
        proof: &[u8],
        key: &[u8; KEY_BYTES],
        now: Reading,
    ) -> Result<Self, Error> {
        let limits = profile.limits();
        let verified = profile
            .verify(credential, now, &mut SignatureBudget::new(&limits))
            .map_err(Error::Credential)?;
        view.admits(&verified).map_err(|_| Error::Admission)?;
        verified
            .possession(proof, &Self::challenge(key), now, &mut SignatureBudget::new(&limits))
            .map_err(Error::Credential)?;
        let claims = verified.claims();
        let Subject::Workload(workload) = &claims.subject else {
            return Err(Error::Admission);
        };
        Self::new(&claims.issuer.to_string(), &workload.to_string())
    }

    /// The challenge that the proof of a workload credential binds for the agent key `key`
    /// ([`credential::ProofDraft::new`]): the canonical CBOR form `["rsauthnz.agent.bootstrap.1", fingerprint]`, with
    /// the SHA-256 fingerprint of the key. So the proof starts the enrollment of that key only.
    ///
    /// Cost class: [`Parse`](crate::limits::Class::Parse).
    #[must_use]
    pub fn challenge(key: &[u8; KEY_BYTES]) -> Vec<u8> {
        encode(&[Value::Text(CHALLENGE_FORM), Value::Bytes(&crypto::sha256(key))])
    }

    /// The issuer: the SPIFFE ID of a trust domain, the `iss` of a token, or the authority of a workload credential.
    #[must_use]
    pub fn issuer(&self) -> &str {
        &self.issuer
    }

    /// The subject: the SPIFFE ID of a JWT-SVID, the `sub` of a token, or the workload of a workload credential.
    #[must_use]
    pub fn subject(&self) -> &str {
        &self.subject
    }

    /// The workload of `issuer` and `subject`, each within [`WORKLOAD_BYTES_MAX`] and with no control character.
    pub(super) fn new(issuer: &str, subject: &str) -> Result<Self, Error> {
        let valid = |text: &str| (1..=WORKLOAD_BYTES_MAX).contains(&text.len()) && !text.chars().any(char::is_control);
        (valid(issuer) && valid(subject)).ok_or(Error::Workload)?;
        Ok(Self {
            issuer: issuer.into(),
            subject: subject.into(),
        })
    }
}

/// The workload identity in the enrollment request of a hosted agent ([`super::Enrollment`]). `Debug` does not show a
/// token.
pub enum Bootstrap {
    /// A JWT workload identity token: a JWT-SVID or a cloud identity token. [`Platform::verify`] checks it.
    Token(String),
    /// A workload credential of this library, and the proof of its `cnf` key. [`Workload::credential`] checks them.
    Credential {
        /// The workload credential.
        credential: Vec<u8>,
        /// The proof of possession of its `cnf` key.
        proof: Vec<u8>,
    },
}

impl fmt::Debug for Bootstrap {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Token(_) => f.write_str("Token(..)"),
            Self::Credential { credential, proof } => f
                .debug_struct("Credential")
                .field("credential_bytes", &credential.len())
                .field("proof_bytes", &proof.len())
                .finish(),
        }
    }
}
