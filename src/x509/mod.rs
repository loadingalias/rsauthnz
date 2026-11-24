//! X.509 certificates ([RFC 5280]): the issuance of certificates for TLS identities, a bounded reader, and the checks of
//! a certificate of another issuer, such as the Fulcio certificate of a Sigstore build.
//!
//! A [`Draft`] builds the DER `TBSCertificate` of [`Fields`]: the serial, the issuer and the subject names, the
//! validity, the subject key, and the [`Usage`]. The issuer key gives the signature algorithm:
//!
//! | Algorithm | X.509 identifier |
//! | --- | --- |
//! | Composite ML-DSA-65 + Ed25519, the default | `id-MLDSA65-Ed25519-SHA512`, 1.3.6.1.5.5.7.6.48 (draft) |
//! | Composite ML-DSA-65 + ECDSA P-256 | `id-MLDSA65-ECDSA-P256-SHA512`, 1.3.6.1.5.5.7.6.45 (draft) |
//! | ML-DSA-65 | `id-ml-dsa-65`, 2.16.840.1.101.3.4.3.18 ([RFC 9881]) |
//! | SLH-DSA-SHA2-128s, for issuer certificates only | `id-slh-dsa-sha2-128s`, 2.16.840.1.101.3.4.3.20 ([RFC 9909]) |
//! | Ed25519, classical | `id-Ed25519`, 1.3.101.112 ([RFC 8410]) |
//! | ECDSA P-256 with SHA-256, classical | `ecdsa-with-SHA256`, 1.2.840.10045.4.3.2 ([RFC 5758]) |
//!
//! The caller gets the signature over [`Draft::to_be_signed`] from its signer: a custody for a composite or an SLH-DSA
//! key, or another signer. [`Draft::finish`] verifies it and gives a [`Prepared`] artifact, and [`Draft::record`] adds
//! the issuance record of the serial to the transition. Thus only the accepted commit releases the certificate, and one
//! serial of an issuer gives one certificate.
//!
//! [`Certificate::parse`] reads these forms and a strict profile of other issuers, after a bound on the bytes, with no
//! allocation past the declared lengths. [`Certificate::verify`] checks the signature with the key of the issuer. The
//! profile adds ECDSA P-384 with SHA-384 (`ecdsa-with-SHA384`, 1.2.840.10045.4.3.3), which only verifies.
//!
//! [`Certificate::verify_path`] checks the path of a certificate to a trust anchor at a time that the caller gives.
//! [`Certificate::fulcio`] gives the claims of a Fulcio certificate, and [`Certificate::timestamps`] checks the
//! Certificate Transparency timestamps ([RFC 6962]) that a certificate embeds. The caller owns the policy: its anchors
//! and logs, the windows of their trust, and the claims that it accepts.
//!
//! The example drafts the certificate of a TLS identity whose Ed25519 key signs its own certificate. A custody key gives
//! its encoding with [`Handle::public_key`](crate::custody::Handle::public_key).
//!
//! ```
//! use core::time::Duration;
//!
//! use rsauthnz::crypto::Algorithm;
//! use rsauthnz::id::Id;
//! use rsauthnz::limits::{Limits, SignatureBudget};
//! use rsauthnz::x509::{AltName, Attribute, Certificate, Draft, Error, Fields, PublicKey, Purpose, Serial, Usage, Validity};
//! use rscrypto::ChaCha20Rng;
//!
//! let key = PublicKey::new(Algorithm::Ed25519, &[0x3b; 32])?;
//! let name = [(Attribute::Organization, "acme"), (Attribute::CommonName, "build")];
//! let fields = Fields {
//!     serial: Serial::random(&mut ChaCha20Rng::from_seed([7; 32])),
//!     issuer: &name,
//!     subject: &name,
//!     validity: Validity {
//!         not_before: Duration::from_secs(1_800_000_000),
//!         not_after: Duration::from_secs(1_831_536_000),
//!     },
//!     key: &key,
//!     usage: Usage::Identity {
//!         names: &[AltName::Dns("build.app.example")],
//!         purposes: &[Purpose::Server, Purpose::Client],
//!     },
//! };
//! let draft = Draft::new(&fields, &key, &Id::new("acme", "auth")?)?;
//! // The issuer signs these bytes: the DER `TBSCertificate`.
//! assert_eq!(draft.to_be_signed()[0], 0x30);
//! // A signature that the issuer key did not make gives no certificate.
//! let refused = draft.finish(&[0; 64], &mut SignatureBudget::new(&Limits::default()));
//! assert_eq!(refused.err(), Some(Error::Signature));
//! // More bytes than `CERTIFICATE_BYTES_MAX` refuse before a read.
//! assert_eq!(Certificate::parse(&[0x30; 16 * 1024 + 1]).err(), Some(Error::Bytes));
//! # Ok::<(), Box<dyn core::error::Error>>(())
//! ```
//!
//! [RFC 5280]: https://www.rfc-editor.org/rfc/rfc5280
//! [RFC 5758]: https://www.rfc-editor.org/rfc/rfc5758
//! [RFC 6962]: https://www.rfc-editor.org/rfc/rfc6962
//! [RFC 8410]: https://www.rfc-editor.org/rfc/rfc8410
//! [RFC 9881]: https://www.rfc-editor.org/rfc/rfc9881
//! [RFC 9909]: https://www.rfc-editor.org/rfc/rfc9909

mod der;

use alloc::vec;
use alloc::vec::Vec;
use core::time::Duration;
use core::{fmt, iter};

use rscrypto::ChaCha20Rng;

use self::der::{
    BIT_STRING, BOOLEAN, DNS_NAME, EXTENSIONS, INTEGER, OBJECT, OCTET_STRING, PRINTABLE_STRING, Reader, SEQUENCE, SET,
    URI, UTF8_STRING, VERSION, element,
};
use crate::cbor::{self, Value};
use crate::crypto::{self, Algorithm, Authentication, Verifier};
use crate::id::{Authority, AuthorityVersion, Id};
use crate::limits::{Limit, Limits, SignatureBudget};
use crate::store::Kind;
use crate::transition::{self, Change, Dependency, Key, Prepared, Proposal};

/// The most bytes of a certificate. An SLH-DSA signature over the key of a composite issuer is about 10.3 KB.
pub const CERTIFICATE_BYTES_MAX: usize = 16 * 1024;

/// The most attributes of a name.
pub const NAME_ATTRIBUTES_MAX: usize = 8;

/// The most bytes of the value of one attribute of a name. RFC 5280 bounds each attribute of [`Attribute`] to 64
/// characters.
pub const NAME_VALUE_BYTES_MAX: usize = 64;

/// The most subject alternative names of a certificate.
pub const ALT_NAMES_MAX: usize = 16;

/// The most bytes of a URI name. A GitHub Actions identity names the repository, the path of the workflow, and the ref.
pub const URI_BYTES_MAX: usize = 1024;

/// The most issuer certificates between a certificate and its trust anchor in [`Certificate::verify_path`].
pub const PATH_ISSUERS_MAX: usize = 4;

/// The most Certificate Transparency timestamps that [`Certificate::timestamps`] reads in one certificate.
pub const TIMESTAMPS_MAX: usize = 8;

/// The most extensions of a certificate that [`Certificate::parse`] reads. A Fulcio certificate has 27.
const EXTENSIONS_MAX: usize = 64;

/// The most bytes of a serial number: RFC 5280 section 4.1.2.2.
const SERIAL_BYTES_MAX: usize = 20;

/// The record form of an issuance, and the domain of the digest in its key.
const RECORD_FORM: &str = "rsauthnz.x509.record.1";

/// The DER `AlgorithmIdentifier` of each algorithm: of its signatures, and of its keys.
const MLDSA65_ED25519: &[u8] = &[0x30, 0x0a, 0x06, 0x08, 0x2b, 0x06, 0x01, 0x05, 0x05, 0x07, 0x06, 0x30];
const MLDSA65_ECDSA_P256: &[u8] = &[0x30, 0x0a, 0x06, 0x08, 0x2b, 0x06, 0x01, 0x05, 0x05, 0x07, 0x06, 0x2d];
const MLDSA65: &[u8] = &[
    0x30, 0x0b, 0x06, 0x09, 0x60, 0x86, 0x48, 0x01, 0x65, 0x03, 0x04, 0x03, 0x12,
];
const SLHDSA_SHA2_128S: &[u8] = &[
    0x30, 0x0b, 0x06, 0x09, 0x60, 0x86, 0x48, 0x01, 0x65, 0x03, 0x04, 0x03, 0x14,
];
const ED25519: &[u8] = &[0x30, 0x05, 0x06, 0x03, 0x2b, 0x65, 0x70];
const ECDSA_SHA256: &[u8] = &[0x30, 0x0a, 0x06, 0x08, 0x2a, 0x86, 0x48, 0xce, 0x3d, 0x04, 0x03, 0x02];
const ECDSA_SHA384: &[u8] = &[0x30, 0x0a, 0x06, 0x08, 0x2a, 0x86, 0x48, 0xce, 0x3d, 0x04, 0x03, 0x03];
/// `id-ecPublicKey` with the named curve `prime256v1`.
const EC_P256: &[u8] = &[
    0x30, 0x13, 0x06, 0x07, 0x2a, 0x86, 0x48, 0xce, 0x3d, 0x02, 0x01, 0x06, 0x08, 0x2a, 0x86, 0x48, 0xce, 0x3d, 0x03,
    0x01, 0x07,
];
/// `id-ecPublicKey` with the named curve `secp384r1`.
const EC_P384: &[u8] = &[
    0x30, 0x10, 0x06, 0x07, 0x2a, 0x86, 0x48, 0xce, 0x3d, 0x02, 0x01, 0x06, 0x05, 0x2b, 0x81, 0x04, 0x00, 0x22,
];

/// The algorithms of certificates, with the identifiers of their signatures and of their keys, and the most bytes of
/// a signature in its X.509 form.
const ALGORITHMS: [(Algorithm, &[u8], &[u8], usize); 7] = [
    (Algorithm::MlDsa65Ed25519, MLDSA65_ED25519, MLDSA65_ED25519, 3_373),
    (
        Algorithm::MlDsa65EcdsaP256,
        MLDSA65_ECDSA_P256,
        MLDSA65_ECDSA_P256,
        3_381,
    ),
    (Algorithm::MlDsa65, MLDSA65, MLDSA65, 3_309),
    (Algorithm::SlhDsaSha2_128s, SLHDSA_SHA2_128S, SLHDSA_SHA2_128S, 7_856),
    (Algorithm::Ed25519, ED25519, ED25519, 64),
    (Algorithm::Es256, ECDSA_SHA256, EC_P256, 72),
    (Algorithm::Es384, ECDSA_SHA384, EC_P384, 104),
];

/// The OIDs of the extensions, of the attributes, and of the extended key usages.
const BASIC_CONSTRAINTS: &[u8] = &[0x55, 0x1d, 0x13];
const KEY_USAGE: &[u8] = &[0x55, 0x1d, 0x0f];
const EXTENDED_KEY_USAGE: &[u8] = &[0x55, 0x1d, 0x25];
const SUBJECT_ALT_NAME: &[u8] = &[0x55, 0x1d, 0x11];
const SUBJECT_KEY_IDENTIFIER: &[u8] = &[0x55, 0x1d, 0x0e];
const AUTHORITY_KEY_IDENTIFIER: &[u8] = &[0x55, 0x1d, 0x23];
const SERVER_AUTH: &[u8] = &[0x2b, 0x06, 0x01, 0x05, 0x05, 0x07, 0x03, 0x01];
const CLIENT_AUTH: &[u8] = &[0x2b, 0x06, 0x01, 0x05, 0x05, 0x07, 0x03, 0x02];
const CODE_SIGNING: &[u8] = &[0x2b, 0x06, 0x01, 0x05, 0x05, 0x07, 0x03, 0x03];
/// 1.3.6.1.4.1.11129.2.4.2: the `SignedCertificateTimestampList` of RFC 6962 section 3.3.
const TIMESTAMP_LIST: &[u8] = &[0x2b, 0x06, 0x01, 0x04, 0x01, 0xd6, 0x79, 0x02, 0x04, 0x02];
/// 1.3.6.1.4.1.57264.1: the arc of the Fulcio claims. One more arc names each claim.
const FULCIO: &[u8] = &[0x2b, 0x06, 0x01, 0x04, 0x01, 0x83, 0xbf, 0x30, 0x01];

/// The `KeyUsage` bits of RFC 5280 section 4.2.1.3, in the first byte of the bit string: `digitalSignature` of an
/// identity, and `keyCertSign` of an issuer, which can also have `cRLSign` and `digitalSignature`.
const DIGITAL_SIGNATURE: u8 = 0x80;
const KEY_CERT_SIGN: u8 = 0x04;
const CRL_SIGN: u8 = 0x02;

/// The public key of a certificate: its algorithm and its key.
#[derive(Clone, PartialEq, Eq)]
pub struct PublicKey(Verifier);

impl PublicKey {
    /// The key of `algorithm` with the encoding `public`: the 32 bytes of an Ed25519 key, the uncompressed SEC1 point
    /// of 65 bytes of a P-256 key or of 97 bytes of a P-384 key, the encoding of FIPS 204 or of the LAMPS draft for an
    /// ML-DSA-65 or a composite key, and PK.seed then PK.root for an SLH-DSA key. A custody handle gives this encoding
    /// ([`Handle::public_key`](crate::custody::Handle::public_key)).
    ///
    /// Cost class: [`Verify`](crate::limits::Class::Verify). An ECDSA key checks its point.
    ///
    /// # Errors
    ///
    /// [`Error::Unsupported`] for RS256 and PS256, and [`Error::Key`] if `public` is not a key of `algorithm`.
    pub fn new(algorithm: Algorithm, public: &[u8]) -> Result<Self, Error> {
        identifiers(algorithm).ok_or(Error::Unsupported)?;
        Verifier::from_bytes(algorithm, public).map(Self).ok_or(Error::Key)
    }

    /// The key of `algorithm` in the DER `SubjectPublicKeyInfo` `der`, such as the key of a Certificate Transparency
    /// log in a trusted root. The caller fixes the algorithm, so the input never selects one.
    ///
    /// Cost class: [`Verify`](crate::limits::Class::Verify). An ECDSA key checks its point.
    ///
    /// # Errors
    ///
    /// [`Error::Bytes`] for more than [`CERTIFICATE_BYTES_MAX`] bytes, [`Error::Malformed`] for DER outside the form,
    /// [`Error::Unsupported`] for a key outside the profile, and [`Error::Key`] for a key of another algorithm or a key
    /// that is not valid.
    pub fn from_spki(algorithm: Algorithm, der: &[u8]) -> Result<Self, Error> {
        (der.len() <= CERTIFICATE_BYTES_MAX).ok_or(Error::Bytes)?;
        let key = read_key(der)?;
        (key.algorithm() == algorithm).ok_or(Error::Key)?;
        Ok(key)
    }

    /// The algorithm of the key.
    #[must_use]
    pub const fn algorithm(&self) -> Algorithm {
        self.0.algorithm()
    }

    /// The encoding of the key, as [`Self::new`] takes it.
    #[must_use]
    pub fn to_bytes(&self) -> Vec<u8> {
        self.0.to_bytes()
    }

    /// The DER `SubjectPublicKeyInfo` of the key.
    fn info(&self) -> Vec<u8> {
        let (_, key, _) = identifiers(self.algorithm()).expect("each key of a certificate has an identifier");
        let bits = [&[0][..], &self.to_bytes()].concat();
        element(SEQUENCE, &[key, &element(BIT_STRING, &[&bits])])
    }
}

impl fmt::Debug for PublicKey {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_tuple("PublicKey").field(&self.algorithm()).finish()
    }
}

/// The identifiers of the signatures and of the keys of `algorithm`, and the most bytes of its signature, or `None`
/// for an algorithm with no certificate profile.
fn identifiers(algorithm: Algorithm) -> Option<(&'static [u8], &'static [u8], usize)> {
    ALGORITHMS
        .iter()
        .find(|(known, ..)| *known == algorithm)
        .map(|&(_, signature, key, bytes)| (signature, key, bytes))
}

/// The serial number of a certificate: a positive DER integer of 1 to 20 bytes, in its shortest form. An issuer gives
/// each certificate its own serial.
#[derive(Clone, Copy, PartialEq, Eq, Hash)]
pub struct Serial {
    bytes: [u8; SERIAL_BYTES_MAX],
    len: u8,
}

impl Serial {
    /// A serial of 16 bytes from `random`, with 126 random bits. Its first byte is 0x40 to 0x7f, so it is positive and
    /// in its shortest form.
    ///
    /// Cost class: [`Parse`](crate::limits::Class::Parse).
    #[must_use]
    pub fn random(random: &mut ChaCha20Rng) -> Self {
        let mut bytes = [0; SERIAL_BYTES_MAX];
        random.fill_bytes(&mut bytes[..16]);
        bytes[0] = bytes[0] & 0x3f | 0x40;
        Self { bytes, len: 16 }
    }

    /// The serial with the DER integer content `bytes`.
    ///
    /// Cost class: [`Parse`](crate::limits::Class::Parse).
    ///
    /// # Errors
    ///
    /// [`Error::Serial`] if `bytes` is empty, has more than 20 bytes, is not positive, or is not in its shortest form.
    pub fn from_bytes(bytes: &[u8]) -> Result<Self, Error> {
        let (&first, rest) = bytes.split_first().ok_or(Error::Serial)?;
        let shortest = first != 0 || rest.first().is_some_and(|next| next & 0x80 != 0);
        let zero = first == 0 && rest.is_empty();
        (bytes.len() <= SERIAL_BYTES_MAX && first & 0x80 == 0 && shortest && !zero).ok_or(Error::Serial)?;
        let mut serial = [0; SERIAL_BYTES_MAX];
        serial[..bytes.len()].copy_from_slice(bytes);
        Ok(Self {
            bytes: serial,
            len: u8::try_from(bytes.len()).expect("at most 20 bytes"),
        })
    }

    /// The DER integer content of the serial.
    #[must_use]
    pub fn as_bytes(&self) -> &[u8] {
        &self.bytes[..usize::from(self.len)]
    }
}

impl fmt::Debug for Serial {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "Serial({:02x?})", self.as_bytes())
    }
}

/// An attribute of a name. Each value is a `UTF8String` of 1 to [`NAME_VALUE_BYTES_MAX`] bytes.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub enum Attribute {
    /// `commonName` (2.5.4.3).
    CommonName,
    /// `organizationName` (2.5.4.10).
    Organization,
    /// `organizationalUnitName` (2.5.4.11).
    OrganizationalUnit,
}

impl Attribute {
    const ALL: [Self; 3] = [Self::CommonName, Self::Organization, Self::OrganizationalUnit];

    /// The DER of the OID of the attribute.
    const fn object(self) -> &'static [u8] {
        match self {
            Self::CommonName => &[0x06, 0x03, 0x55, 0x04, 0x03],
            Self::Organization => &[0x06, 0x03, 0x55, 0x04, 0x0a],
            Self::OrganizationalUnit => &[0x06, 0x03, 0x55, 0x04, 0x0b],
        }
    }
}

/// A name: its attributes in order, one in each relative distinguished name, such as
/// `[(Organization, "acme"), (CommonName, "build")]`. A name has 1 to [`NAME_ATTRIBUTES_MAX`] attributes.
pub type Name<'a> = [(Attribute, &'a str)];

/// A subject alternative name.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub enum AltName<'a> {
    /// A `dNSName`: a domain name in lowercase ASCII, such as `build.app.example`.
    Dns(&'a str),
    /// A `uniformResourceIdentifier` of 1 to [`URI_BYTES_MAX`] bytes of visible ASCII with a scheme, such as
    /// `https://app.example/workload/build`.
    Uri(&'a str),
}

/// An extended key usage.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub enum Purpose {
    /// `id-kp-serverAuth`: a TLS server.
    Server,
    /// `id-kp-clientAuth`: a TLS client.
    Client,
    /// `id-kp-codeSigning`: the signer of code, such as a Sigstore build.
    CodeSigning,
}

impl Purpose {
    const ALL: [Self; 3] = [Self::Server, Self::Client, Self::CodeSigning];

    const fn object(self) -> &'static [u8] {
        match self {
            Self::Server => SERVER_AUTH,
            Self::Client => CLIENT_AUTH,
            Self::CodeSigning => CODE_SIGNING,
        }
    }
}

/// What the key of a certificate does. Each purpose is in its list at most once, and an empty list gives no
/// `extKeyUsage`.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Usage<'a> {
    /// An identity, such as a TLS server or a code signer: the critical `keyUsage` `digitalSignature`, the
    /// `extKeyUsage` of `purposes`, and the `subjectAltName` of `names`. An empty list gives no extension.
    Identity {
        /// The subject alternative names: at most [`ALT_NAMES_MAX`].
        names: &'a [AltName<'a>],
        /// The extended key usages.
        purposes: &'a [Purpose],
    },
    /// An issuer of certificates, such as an issuer key under a trust root: the critical `basicConstraints` with `cA`
    /// and the path length, the critical `keyUsage` `keyCertSign`, and the `extKeyUsage` of `purposes`.
    Issuer {
        /// The most issuer certificates under this one in a path, or `None` for no bound.
        path_length: Option<u8>,
        /// The extended key usages that each certificate under this one serves, or an empty list for no bound.
        purposes: &'a [Purpose],
    },
}

/// The claims of a Fulcio certificate: the identity that an OpenID Connect token proved to the Sigstore certificate
/// authority. Each claim is the `UTF8String` of the extension 1.3.6.1.4.1.57264.1.*n* that its field names (Fulcio
/// `docs/oid-info.md`), or `None` if the certificate does not have it. The deprecated claims 1 to 6 have no effect.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq, Hash)]
pub struct Fulcio<'a> {
    /// 8: the issuer of the token, such as `https://token.actions.githubusercontent.com`.
    pub issuer: Option<&'a str>,
    /// 9: the URI of the build signer, such as the workflow of a GitHub Actions build at its ref.
    pub build_signer_uri: Option<&'a str>,
    /// 10: the digest of the build signer, such as the commit of the workflow.
    pub build_signer_digest: Option<&'a str>,
    /// 11: the runner environment, such as `github-hosted`.
    pub runner_environment: Option<&'a str>,
    /// 12: the URI of the source repository.
    pub source_repository_uri: Option<&'a str>,
    /// 13: the digest of the source, such as a commit.
    pub source_repository_digest: Option<&'a str>,
    /// 14: the ref of the source, such as `refs/heads/main`.
    pub source_repository_ref: Option<&'a str>,
    /// 15: the stable identifier of the source repository.
    pub source_repository_identifier: Option<&'a str>,
    /// 16: the URI of the owner of the source repository.
    pub source_repository_owner_uri: Option<&'a str>,
    /// 17: the stable identifier of the owner of the source repository.
    pub source_repository_owner_identifier: Option<&'a str>,
    /// 18: the URI of the build configuration.
    pub build_config_uri: Option<&'a str>,
    /// 19: the digest of the build configuration.
    pub build_config_digest: Option<&'a str>,
    /// 20: the event that started the build, such as `push`.
    pub build_trigger: Option<&'a str>,
    /// 21: the URI of the run of the build.
    pub run_invocation_uri: Option<&'a str>,
    /// 22: the visibility of the source repository at the time of signing, such as `public`.
    pub source_repository_visibility: Option<&'a str>,
}

impl<'a> Fulcio<'a> {
    /// The field of the claim with the last arc `arc`, or `None` for another arc.
    const fn claim(&mut self, arc: u8) -> Option<&mut Option<&'a str>> {
        Some(match arc {
            8 => &mut self.issuer,
            9 => &mut self.build_signer_uri,
            10 => &mut self.build_signer_digest,
            11 => &mut self.runner_environment,
            12 => &mut self.source_repository_uri,
            13 => &mut self.source_repository_digest,
            14 => &mut self.source_repository_ref,
            15 => &mut self.source_repository_identifier,
            16 => &mut self.source_repository_owner_uri,
            17 => &mut self.source_repository_owner_identifier,
            18 => &mut self.build_config_uri,
            19 => &mut self.build_config_digest,
            20 => &mut self.build_trigger,
            21 => &mut self.run_invocation_uri,
            22 => &mut self.source_repository_visibility,
            _ => return None,
        })
    }
}

/// A Certificate Transparency timestamp that a trusted log signed for a certificate (RFC 6962 section 3.2).
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub struct Timestamp {
    /// The index of the log in the list of the check.
    pub log: usize,
    /// The time at which the log saw the certificate, since the Unix epoch, in milliseconds.
    pub time: Duration,
}

/// The validity of a certificate, as the times since the Unix epoch. Each time encodes its whole seconds.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub struct Validity {
    /// The first time at which the certificate is valid.
    pub not_before: Duration,
    /// The last time at which the certificate is valid.
    pub not_after: Duration,
}

/// The fields of a certificate that a [`Draft`] encodes.
#[derive(Clone, Copy, Debug)]
pub struct Fields<'a> {
    /// The serial number.
    pub serial: Serial,
    /// The name of the issuer: the subject of its certificate.
    pub issuer: &'a Name<'a>,
    /// The name of the subject.
    pub subject: &'a Name<'a>,
    /// The validity.
    pub validity: Validity,
    /// The key of the subject.
    pub key: &'a PublicKey,
    /// What the key of the subject does.
    pub usage: Usage<'a>,
}

/// A certificate that its issuer did not sign yet. [`Draft::finish`] consumes it, so one draft gives at most one
/// certificate.
pub struct Draft {
    tbs: Vec<u8>,
    issuer: PublicKey,
    record: Key,
    version: AuthorityVersion,
    end: Duration,
    data: Vec<u8>,
}

impl Draft {
    /// The draft of the certificate of `fields` that the key `issuer` signs, with the issuance record of `authority`.
    /// The algorithm of `issuer` is the signature algorithm, and the caller selects it: no input selects it.
    ///
    /// Cost class: [`Parse`](crate::limits::Class::Parse).
    ///
    /// # Errors
    ///
    /// - [`Error::Name`] for a name with no attribute, more than [`NAME_ATTRIBUTES_MAX`] attributes, or a value that is
    ///   empty or longer than [`NAME_VALUE_BYTES_MAX`] bytes, for more than [`ALT_NAMES_MAX`] alternative names or an
    ///   alternative name outside its form, and for a purpose that is in the list twice.
    /// - [`Error::Validity`] if `not_after` is not after `not_before`, or a time is after the year 9999.
    /// - [`Error::Profile`] if an SLH-DSA key signs or holds a certificate that is no issuer certificate, if one of
    ///   the two keys is classical and the other one is not, or if a key is ES384, which this crate only verifies.
    /// - [`Error::Bytes`] if the certificate can have more than [`CERTIFICATE_BYTES_MAX`] bytes.
    pub fn new(fields: &Fields<'_>, issuer: &PublicKey, authority: &Id<Authority>) -> Result<Self, Error> {
        let issued = issuer.algorithm();
        let held = fields.key.algorithm();
        let fits = |algorithm| match algorithm {
            Algorithm::SlhDsaSha2_128s => matches!(fields.usage, Usage::Issuer { .. }),
            Algorithm::Es384 => false,
            _ => true,
        };
        let classical = |algorithm: Algorithm| algorithm.report().authentication == Authentication::Classical;
        (fits(issued) && fits(held) && classical(issued) == classical(held)).ok_or(Error::Profile)?;
        let not_before = fields.validity.not_before.as_secs();
        let not_after = fields.validity.not_after.as_secs();
        (not_before < not_after).ok_or(Error::Validity)?;
        let (signature, _, signature_bytes) = identifiers(issued).expect("each key of a certificate has an identifier");
        let tbs = element(
            SEQUENCE,
            &[
                &element(VERSION, &[&[INTEGER, 1, 2]]),
                &element(INTEGER, &[fields.serial.as_bytes()]),
                signature,
                &name(fields.issuer)?,
                &element(SEQUENCE, &[&der::time(not_before)?, &der::time(not_after)?]),
                &name(fields.subject)?,
                &fields.key.info(),
                &element(
                    EXTENSIONS,
                    &[&element(SEQUENCE, &[&extensions(&fields.usage, fields.key, issuer)?])],
                ),
            ],
        );
        // The certificate is the TBS, the identifier, and the signature with its bit string head, in one sequence.
        (tbs.len() + signature.len() + signature_bytes + 16 <= CERTIFICATE_BYTES_MAX).ok_or(Error::Bytes)?;
        let serial = fields.serial.as_bytes();
        let record = record_key(issuer, serial);
        let data = cbor::encode(
            &Value::Array(vec![
                Value::Text(RECORD_FORM),
                Value::Bytes(serial),
                Value::Unsigned(not_after),
            ]),
            Limits::FORM,
        )
        .expect("the form has no map and no simple value");
        Ok(Self {
            tbs,
            issuer: issuer.clone(),
            record,
            version: AuthorityVersion::new(authority.clone(), serial).expect("a serial has 1 to 20 bytes"),
            end: Duration::from_secs(not_after.saturating_add(1)),
            data,
        })
    }

    /// The bytes that the issuer signs: the DER `TBSCertificate`. ML-DSA-65, the composites, and SLH-DSA sign with the
    /// empty context. The bytes start with a DER sequence (0x30), so they never read as the CBOR `Sig_structure` that the
    /// same root key signs for a trust snapshot ([`crate::trust`]), which starts with an array (0x84).
    ///
    /// Cost class: [`Parse`](crate::limits::Class::Parse).
    #[must_use]
    pub fn to_be_signed(&self) -> &[u8] {
        &self.tbs
    }

    /// Adds the issuance record of the certificate to `proposal`: the absence of the record of its serial under its
    /// issuer key, and its write. The key of the record is [`Kind::Credential`] with the SHA-256 digest of the CBOR
    /// form `["rsauthnz.x509.record.1", issuer key, serial]`. The record holds no signature, and it ends after the
    /// certificate. Its form is `["rsauthnz.x509.record.1", serial, not_after in seconds]`. Add it before
    /// [`Proposal::prepare`] of the artifact of [`Self::finish`].
    ///
    /// Cost class: [`Parse`](crate::limits::Class::Parse).
    ///
    /// # Errors
    ///
    /// The errors of [`Proposal::read`] and [`Proposal::change`].
    pub fn record(&self, proposal: &mut Proposal) -> Result<(), transition::Error> {
        proposal.read(Dependency::Absent(self.record.clone()))?;
        proposal.change(Change::Write {
            key: self.record.clone(),
            version: self.version.clone(),
            end: Some(self.end),
            data: self.data.clone().into_boxed_slice(),
        })
    }

    /// Verifies `signature`, the signature of the issuer over [`Self::to_be_signed`] in its X.509 form, and gives the
    /// DER certificate as a [`Prepared`] artifact. Give it to [`Proposal::prepare`] of the transition that writes its
    /// issuance record ([`Self::record`]): only the receipt of the accepted transition gives its bytes. An ECDSA
    /// signature is the DER `Ecdsa-Sig-Value`, and a composite signature is the form of the LAMPS draft. The check
    /// charges `budget`.
    ///
    /// Cost class: [`Verify`](crate::limits::Class::Verify).
    ///
    /// # Errors
    ///
    /// [`Error::Signature`] if the signature does not verify with the issuer key, and [`Error::Limit`] if the check
    /// costs more than `budget` has.
    pub fn finish(self, signature: &[u8], budget: &mut SignatureBudget) -> Result<Prepared, Error> {
        let (_, _, signature_bytes) = identifiers(self.issuer.algorithm()).expect("the key has an identifier");
        (signature.len() <= signature_bytes).ok_or(Error::Signature)?;
        verify(&self.issuer, &self.tbs, signature, budget)?;
        let (identifier, ..) = identifiers(self.issuer.algorithm()).expect("the key has an identifier");
        let bits = [&[0][..], signature].concat();
        let certificate = element(SEQUENCE, &[&self.tbs, identifier, &element(BIT_STRING, &[&bits])]);
        Ok(Prepared::new(certificate, self.record, self.version))
    }
}

impl fmt::Debug for Draft {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("Draft")
            .field("tbs", &self.tbs.len())
            .field("issuer", &self.issuer)
            .finish_non_exhaustive()
    }
}

/// The key of the issuance record of `serial` under the key `issuer`.
fn record_key(issuer: &PublicKey, serial: &[u8]) -> Key {
    let form = cbor::encode(
        &Value::Array(vec![
            Value::Text(RECORD_FORM),
            Value::Bytes(&issuer.to_bytes()),
            Value::Bytes(serial),
        ]),
        Limits::FORM,
    )
    .expect("the form has no map and no simple value");
    Kind::Credential
        .key(&crypto::sha256(&form))
        .expect("a key of 33 bytes is valid")
}

/// Verifies `signature` over `message` with `key`.
fn verify(key: &PublicKey, message: &[u8], signature: &[u8], budget: &mut SignatureBudget) -> Result<(), Error> {
    key.0
        .verify_der(message, signature, budget)
        .map_err(Error::Limit)?
        .ok_or(Error::Signature)
}

/// The DER `Name` of `attributes`.
fn name(attributes: &Name<'_>) -> Result<Vec<u8>, Error> {
    (1..=NAME_ATTRIBUTES_MAX)
        .contains(&attributes.len())
        .ok_or(Error::Name)?;
    let mut sets = Vec::new();
    for (attribute, value) in attributes {
        (1..=NAME_VALUE_BYTES_MAX).contains(&value.len()).ok_or(Error::Name)?;
        let pair = element(
            SEQUENCE,
            &[attribute.object(), &element(UTF8_STRING, &[value.as_bytes()])],
        );
        sets.extend_from_slice(&element(SET, &[&pair]));
    }
    Ok(element(SEQUENCE, &[&sets]))
}

/// The DER `Extension` of the OID `object` with the DER value `value`.
fn extension(object: &[u8], critical: bool, value: &[u8]) -> Vec<u8> {
    let critical: &[u8] = if critical { &[BOOLEAN, 1, 0xff] } else { &[] };
    element(
        SEQUENCE,
        &[&element(OBJECT, &[object]), critical, &element(OCTET_STRING, &[value])],
    )
}

/// The key identifier of `key`: the first 160 bits of the SHA-256 digest of the bits of its `subjectPublicKey`, the
/// first method of [RFC 7093](https://www.rfc-editor.org/rfc/rfc7093).
fn key_identifier(key: &PublicKey) -> Vec<u8> {
    element(OCTET_STRING, &[&crypto::sha256(&key.to_bytes())[..20]])
}

/// The extensions of `usage` for the subject key `subject` and the issuer key `issuer`, in the order of this crate.
/// An issuer certificate has its `subjectKeyIdentifier`, and each certificate that is not self-signed has the
/// `authorityKeyIdentifier` of its issuer, as RFC 5280 sections 4.2.1.1 and 4.2.1.2 ask.
fn extensions(usage: &Usage<'_>, subject: &PublicKey, issuer: &PublicKey) -> Result<Vec<u8>, Error> {
    let mut out = Vec::new();
    match usage {
        Usage::Identity { names, purposes } => {
            out.extend(extension(KEY_USAGE, true, &key_usage(DIGITAL_SIGNATURE)));
            out.extend(purposes_extension(purposes)?);
            if !names.is_empty() {
                (names.len() <= ALT_NAMES_MAX).ok_or(Error::Name)?;
                let mut general = Vec::new();
                for alt in *names {
                    alt_valid(alt).ok_or(Error::Name)?;
                    let (tag, text) = match alt {
                        AltName::Dns(text) => (DNS_NAME, text),
                        AltName::Uri(text) => (URI, text),
                    };
                    general.extend(element(tag, &[text.as_bytes()]));
                }
                out.extend(extension(SUBJECT_ALT_NAME, false, &element(SEQUENCE, &[&general])));
            }
        }
        Usage::Issuer { path_length, purposes } => {
            let length = path_length.map(|length| element(INTEGER, &[&integer(length)]));
            let constraints = element(SEQUENCE, &[&[BOOLEAN, 1, 0xff], length.as_deref().unwrap_or_default()]);
            out.extend(extension(BASIC_CONSTRAINTS, true, &constraints));
            out.extend(extension(KEY_USAGE, true, &key_usage(KEY_CERT_SIGN)));
            out.extend(purposes_extension(purposes)?);
            out.extend(extension(SUBJECT_KEY_IDENTIFIER, false, &key_identifier(subject)));
        }
    }
    if subject != issuer {
        // The `keyIdentifier` is `[0] IMPLICIT OCTET STRING`.
        let mut identifier = key_identifier(issuer);
        identifier[0] = 0x80;
        out.extend(extension(
            AUTHORITY_KEY_IDENTIFIER,
            false,
            &element(SEQUENCE, &[&identifier]),
        ));
    }
    Ok(out)
}

/// The DER `KeyUsage` of `bits`, in the first byte. DER drops the trailing zero bits.
fn key_usage(bits: u8) -> Vec<u8> {
    let unused = u8::try_from(bits.trailing_zeros()).expect("a byte has at most 8 zero bits");
    element(BIT_STRING, &[&[unused, bits]])
}

/// The `extKeyUsage` extension of `purposes`, or no bytes for an empty list.
fn purposes_extension(purposes: &[Purpose]) -> Result<Vec<u8>, Error> {
    if purposes.is_empty() {
        return Ok(Vec::new());
    }
    let unique = purposes
        .iter()
        .enumerate()
        .all(|(at, purpose)| !purposes[..at].contains(purpose));
    unique.ok_or(Error::Name)?;
    let objects: Vec<Vec<u8>> = purposes
        .iter()
        .map(|purpose| element(OBJECT, &[purpose.object()]))
        .collect();
    let objects: Vec<&[u8]> = objects.iter().map(Vec::as_slice).collect();
    Ok(extension(EXTENDED_KEY_USAGE, false, &element(SEQUENCE, &objects)))
}

/// The DER integer content of `value`.
fn integer(value: u8) -> Vec<u8> {
    if value & 0x80 == 0 { vec![value] } else { vec![0, value] }
}

/// Whether `alt` has its form: a domain name in lowercase ASCII of at most 253 bytes, or a URI of visible ASCII with
/// a scheme.
fn alt_valid(alt: &AltName<'_>) -> bool {
    match alt {
        AltName::Dns(name) => {
            (1..=253).contains(&name.len())
                && name.split('.').all(|label| {
                    (1..=63).contains(&label.len())
                        && label
                            .bytes()
                            .all(|byte| byte.is_ascii_lowercase() || byte.is_ascii_digit() || byte == b'-')
                        && !label.starts_with('-')
                        && !label.ends_with('-')
                })
        }
        AltName::Uri(uri) => {
            (1..=URI_BYTES_MAX).contains(&uri.len())
                && uri.bytes().all(|byte| byte.is_ascii_graphic())
                && uri.split_once(':').is_some_and(|(scheme, _)| {
                    !scheme.is_empty()
                        && scheme
                            .bytes()
                            .all(|byte| byte.is_ascii_alphanumeric() || b"+-.".contains(&byte))
                })
        }
    }
}

/// A certificate as [`Certificate::parse`] read it. It borrows the DER.
#[derive(Clone, Debug)]
pub struct Certificate<'a> {
    tbs: &'a [u8],
    algorithm: Algorithm,
    signature: &'a [u8],
    serial: Serial,
    issuer: Vec<(Attribute, &'a str)>,
    subject: Vec<(Attribute, &'a str)>,
    /// The DER contents of the names, which a path compares.
    issuer_name: &'a [u8],
    subject_name: &'a [u8],
    validity: Validity,
    key: PublicKey,
    /// The DER `SubjectPublicKeyInfo`, whose digest a Certificate Transparency log signs for the certificates under it.
    key_info: &'a [u8],
    names: Vec<AltName<'a>>,
    purposes: Vec<Purpose>,
    /// The path length of an issuer certificate, or `None` for a TLS identity.
    issuer_path: Option<Option<u8>>,
    fulcio: Option<Fulcio<'a>>,
    /// The content of the `SignedCertificateTimestampList` extension.
    timestamps: Option<&'a [u8]>,
}

impl<'a> Certificate<'a> {
    /// Reads the DER certificate `der`: version 3, a serial of 1 to 20 bytes, a signature algorithm of the profile of
    /// this module and the same one in the `TBSCertificate`, names of the attributes of [`Attribute`] in `UTF8String`
    /// or `PrintableString`, the times of RFC 5280, a key of the profile, and the extensions of a [`Usage`]. An empty
    /// subject needs a critical `subjectAltName`, as RFC 5280 section 4.1.2.6 asks. It also reads the Fulcio claims
    /// ([`Self::fulcio`]) and the Certificate Transparency timestamps ([`Self::timestamps`]). It refuses each other
    /// form: a critical extension that it does not read, a unique identifier, and bytes after the certificate. It
    /// reads no signature: [`Self::verify`] checks it.
    ///
    /// Cost class: [`Parse`](crate::limits::Class::Parse). The reader allocates nothing for the DER: each length is in
    /// its shortest form and fits in the input, which has at most [`CERTIFICATE_BYTES_MAX`] bytes. An ECDSA key checks
    /// its point.
    ///
    /// # Errors
    ///
    /// [`Error::Bytes`] for more than [`CERTIFICATE_BYTES_MAX`] bytes, before any read. [`Error::Malformed`] for DER
    /// outside these forms, [`Error::Unsupported`] for an algorithm, an attribute, or a critical extension outside the
    /// profile, [`Error::Name`], [`Error::Serial`], and [`Error::Validity`] for a field outside its form, and
    /// [`Error::Key`] for a key that is not valid.
    pub fn parse(der: &'a [u8]) -> Result<Self, Error> {
        (der.len() <= CERTIFICATE_BYTES_MAX).ok_or(Error::Bytes)?;
        let mut outer = Reader::new(der);
        let mut certificate = Reader::new(outer.read(SEQUENCE)?);
        outer.end()?;
        let tbs = certificate.element(SEQUENCE)?;
        let identifier = certificate.element(SEQUENCE)?;
        let algorithm = ALGORITHMS
            .iter()
            .find(|(_, signature, ..)| *signature == identifier)
            .map(|(algorithm, ..)| *algorithm)
            .ok_or(Error::Unsupported)?;
        let bits = certificate.read(BIT_STRING)?;
        certificate.end()?;
        let (&[0], signature) = bits.split_first_chunk::<1>().ok_or(Error::Malformed)? else {
            return Err(Error::Malformed);
        };

        let mut fields = Reader::new(Reader::new(tbs).read(SEQUENCE)?);
        (fields.read(VERSION)? == [INTEGER, 1, 2]).ok_or(Error::Malformed)?;
        let serial = Serial::from_bytes(fields.read(INTEGER)?)?;
        (fields.element(SEQUENCE)? == identifier).ok_or(Error::Malformed)?;
        let issuer_name = fields.read(SEQUENCE)?;
        let issuer = read_name(issuer_name)?;
        (!issuer.is_empty()).ok_or(Error::Name)?;
        let mut times = Reader::new(fields.read(SEQUENCE)?);
        let (not_before, not_after) = (times.time()?, times.time()?);
        times.end()?;
        (not_before < not_after).ok_or(Error::Validity)?;
        let subject_name = fields.read(SEQUENCE)?;
        let subject = read_name(subject_name)?;
        let key_info = fields.element(SEQUENCE)?;
        let key = read_key(key_info)?;
        let mut extensions = Reader::new(fields.read(EXTENSIONS)?);
        let list = extensions.read(SEQUENCE)?;
        extensions.end()?;
        fields.end()?;
        let usage = read_extensions(list)?;
        (!subject.is_empty() || usage.names_critical).ok_or(Error::Name)?;
        Ok(Self {
            tbs,
            algorithm,
            signature,
            serial,
            issuer,
            subject,
            issuer_name,
            subject_name,
            validity: Validity {
                not_before: Duration::from_secs(not_before),
                not_after: Duration::from_secs(not_after),
            },
            key,
            key_info,
            names: usage.names,
            purposes: usage.purposes,
            issuer_path: usage.issuer_path,
            fulcio: usage.fulcio,
            timestamps: usage.timestamps,
        })
    }

    /// Verifies the signature of the certificate with `issuer`, the key of its issuer, after it charges `budget`.
    ///
    /// Cost class: [`Verify`](crate::limits::Class::Verify).
    ///
    /// # Errors
    ///
    /// [`Error::Signature`] if `issuer` has another algorithm than the signature, or the signature does not verify.
    /// [`Error::Limit`] if the check costs more than `budget` has.
    pub fn verify(&self, issuer: &PublicKey, budget: &mut SignatureBudget) -> Result<(), Error> {
        (issuer.algorithm() == self.algorithm).ok_or(Error::Signature)?;
        verify(issuer, self.tbs, self.signature, budget)
    }

    /// Verifies the path of this certificate to the trust anchor `anchor` at the time `at`, for `purpose`. `issuers`
    /// holds the issuer certificates in order: the issuer of this certificate first, and the certificate that `anchor`
    /// signed last. The checks:
    ///
    /// 1. This certificate is an identity ([`Usage::Identity`]), and its purposes include `purpose`.
    /// 2. The issuer name of each certificate is the subject name of the next one, byte for byte.
    /// 3. Each next certificate is an issuer certificate. Its path length bounds the issuer certificates under it, and
    ///    its purposes, if it names some, include `purpose`.
    /// 4. `at` is in the validity of each certificate, `anchor` included, from its first second to its last second.
    /// 5. Each signature verifies with the key of the next certificate. The caller trusts `anchor`, so the check does
    ///    not verify the signature of `anchor`.
    ///
    /// The first check that fails gives its error.
    ///
    /// Cost class: [`Verify`](crate::limits::Class::Verify): one signature check for each certificate under `anchor`.
    ///
    /// # Errors
    ///
    /// [`Error::Path`] for more than [`PATH_ISSUERS_MAX`] issuers, a name that does not chain, an issuer that is no
    /// issuer certificate, or a path past the length of an issuer. [`Error::Purpose`] if a certificate does not serve
    /// `purpose`. [`Error::Time`] if `at` is outside the validity of a certificate. [`Error::Signature`] and
    /// [`Error::Limit`] as [`Self::verify`] gives them.
    ///
    /// # Example
    ///
    /// The Fulcio certificate of a GitHub Actions release, along the Sigstore chain, at the time of its log entry.
    ///
    /// ```
    /// use core::time::Duration;
    ///
    /// use rsauthnz::crypto::Algorithm;
    /// use rsauthnz::limits::{Limits, SignatureBudget};
    /// use rsauthnz::x509::{Certificate, Error, PublicKey, Purpose};
    ///
    /// # let leaf: &[u8] = include_bytes!("../../tests/x509/fulcio-leaf.der");
    /// # let intermediate: &[u8] = include_bytes!("../../tests/x509/sigstore-intermediate.der");
    /// # let root: &[u8] = include_bytes!("../../tests/x509/sigstore-root.der");
    /// # let ct_log: &[u8] = include_bytes!("../../tests/x509/ctfe-2022.der");
    /// // The path is two signature checks, and each timestamp of a trusted log is one more.
    /// let mut limits = Limits::default();
    /// limits.signature_checks = 3;
    /// let mut budget = SignatureBudget::new(&limits);
    /// // The root and the intermediate of the trusted root of the host, and the leaf of the bundle.
    /// let anchor = Certificate::parse(root)?;
    /// let issuers = [Certificate::parse(intermediate)?];
    /// let leaf = Certificate::parse(leaf)?;
    /// // The `integratedTime` of the Rekor entry of the bundle: the leaf is valid for 10 minutes.
    /// let logged = Duration::from_secs(1_710_888_076);
    /// leaf.verify_path(&issuers, &anchor, logged, Purpose::CodeSigning, &mut budget)?;
    /// // The CT log of the trusted root signed one timestamp of the leaf.
    /// let log = PublicKey::from_spki(Algorithm::Es256, ct_log)?;
    /// assert_eq!(leaf.timestamps(&issuers[0], &[log], &mut budget)?.len(), 1);
    /// // The policy of the host compares the claims.
    /// let claims = leaf.fulcio().ok_or(Error::Unsupported)?;
    /// assert_eq!(claims.source_repository_uri, Some("https://github.com/trailofbits/rfc8785.py"));
    /// assert_eq!(claims.source_repository_ref, Some("refs/tags/v0.1.2"));
    /// # Ok::<(), Error>(())
    /// ```
    pub fn verify_path(
        &self,
        issuers: &[Self],
        anchor: &Self,
        at: Duration,
        purpose: Purpose,
        budget: &mut SignatureBudget,
    ) -> Result<(), Error> {
        (issuers.len() <= PATH_ISSUERS_MAX).ok_or(Error::Path)?;
        (self.issuer_path.is_none() && self.purposes.contains(&purpose)).ok_or(Error::Purpose)?;
        let path = || iter::once(self).chain(issuers).chain(iter::once(anchor));
        // `below` counts the issuer certificates between `parent` and this certificate.
        for (below, (child, parent)) in path().zip(path().skip(1)).enumerate() {
            (child.issuer_name == parent.subject_name).ok_or(Error::Path)?;
            let length = parent.issuer_path.ok_or(Error::Path)?;
            length
                .is_none_or(|length| below <= usize::from(length))
                .ok_or(Error::Path)?;
            (parent.purposes.is_empty() || parent.purposes.contains(&purpose)).ok_or(Error::Purpose)?;
        }
        for certificate in path() {
            let Validity { not_before, not_after } = certificate.validity;
            (not_before <= at && at <= not_after).ok_or(Error::Time)?;
        }
        for (child, parent) in path().zip(path().skip(1)) {
            child.verify(&parent.key, budget)?;
        }
        Ok(())
    }

    /// The Certificate Transparency timestamps of this certificate that a log of `logs` signed (RFC 6962 sections 3.2
    /// and 3.3), in the order of the certificate. `issuer` is the certificate of the issuer: the log signs the digest
    /// of its key with the certificate. Each log key is ES256, and the ID of a log is the SHA-256 digest of its
    /// `SubjectPublicKeyInfo`. A timestamp of another log has no effect, and a certificate with no timestamp gives an
    /// empty list. The caller decides which logs it trusts at the time of each timestamp, and how many it needs.
    ///
    /// Cost class: [`Verify`](crate::limits::Class::Verify): one signature check for each timestamp of a log of
    /// `logs`.
    ///
    /// # Errors
    ///
    /// [`Error::Unsupported`] for a log key that is not ES256, or a timestamp of a version other than 1.
    /// [`Error::Malformed`] for a list outside the form of RFC 6962 or with more than [`TIMESTAMPS_MAX`] timestamps.
    /// [`Error::Timestamp`] if a timestamp of a log of `logs` does not verify. [`Error::Limit`] if the checks cost
    /// more than `budget` has.
    pub fn timestamps(
        &self,
        issuer: &Self,
        logs: &[PublicKey],
        budget: &mut SignatureBudget,
    ) -> Result<Vec<Timestamp>, Error> {
        logs.iter()
            .all(|log| log.algorithm() == Algorithm::Es256)
            .ok_or(Error::Unsupported)?;
        let Some(value) = self.timestamps else {
            return Ok(Vec::new());
        };
        let mut outer = Reader::new(value);
        let mut input = outer.read(OCTET_STRING)?;
        outer.end()?;
        let mut list = vector(&mut input)?;
        (input.is_empty() && !list.is_empty()).ok_or(Error::Malformed)?;
        let ids: Vec<[u8; 32]> = logs.iter().map(|log| crypto::sha256(&log.info())).collect();
        let (mut precertificate, mut found, mut count) = (None::<Vec<u8>>, Vec::new(), 0);
        while !list.is_empty() {
            count += 1;
            (count <= TIMESTAMPS_MAX).ok_or(Error::Malformed)?;
            let mut sct = vector(&mut list)?;
            let [version] = take(&mut sct)?;
            (version == 0).ok_or(Error::Unsupported)?;
            let id: [u8; 32] = take(&mut sct)?;
            let time: [u8; 8] = take(&mut sct)?;
            let extensions_len: [u8; 2] = take(&mut sct)?;
            let extensions = take_len(&mut sct, extensions_len)?;
            let algorithms: [u8; 2] = take(&mut sct)?;
            let signature = vector(&mut sct)?;
            sct.is_empty().ok_or(Error::Malformed)?;
            let Some(log) = ids.iter().position(|known| *known == id) else {
                continue;
            };
            // SHA-256 (4) with ECDSA (3): the algorithm of the log key.
            (algorithms == [4, 3]).ok_or(Error::Timestamp)?;
            let entry: &[u8] = match precertificate {
                Some(ref entry) => entry,
                None => precertificate.insert(self.precertificate(issuer)?),
            };
            // The `digitally-signed` struct: the version 1, the type `certificate_timestamp`, the time, the entry, and
            // the extensions of the timestamp.
            let message = [&[0, 0][..], &time, entry, &extensions_len, extensions].concat();
            verify(&logs[log], &message, signature, budget).map_err(|error| match error {
                Error::Signature => Error::Timestamp,
                other => other,
            })?;
            found.push(Timestamp {
                log,
                time: Duration::from_millis(u64::from_be_bytes(time)),
            });
        }
        Ok(found)
    }

    /// The `entry_type` `precert_entry` and the `PreCert` of RFC 6962 section 3.2 for this certificate under `issuer`:
    /// the SHA-256 digest of the key of the issuer, and the `TBSCertificate` with no timestamp list.
    fn precertificate(&self, issuer: &Self) -> Result<Vec<u8>, Error> {
        let mut fields = Reader::new(Reader::new(self.tbs).read(SEQUENCE)?);
        let all = fields.rest();
        // The version, the serial, the signature algorithm, the issuer, the validity, the subject, and the key.
        for tag in [VERSION, INTEGER, SEQUENCE, SEQUENCE, SEQUENCE, SEQUENCE, SEQUENCE] {
            fields.element(tag)?;
        }
        let head = &all[..all.len() - fields.rest().len()];
        let mut wrapper = Reader::new(fields.read(EXTENSIONS)?);
        let mut list = Reader::new(wrapper.read(SEQUENCE)?);
        let mut kept = Vec::new();
        while !list.is_empty() {
            let extension = list.element(SEQUENCE)?;
            let object = Reader::new(Reader::new(extension).read(SEQUENCE)?).read(OBJECT)?;
            if object != TIMESTAMP_LIST {
                kept.push(extension);
            }
        }
        let tbs = element(SEQUENCE, &[head, &element(EXTENSIONS, &[&element(SEQUENCE, &kept)])]);
        let len = u32::try_from(tbs.len())
            .expect("a certificate has at most 16 KiB")
            .to_be_bytes();
        Ok([&[0, 1][..], &crypto::sha256(issuer.key_info), &len[1..], &tbs].concat())
    }

    /// The signature algorithm.
    #[must_use]
    pub const fn algorithm(&self) -> Algorithm {
        self.algorithm
    }

    /// The serial number.
    #[must_use]
    pub const fn serial(&self) -> &Serial {
        &self.serial
    }

    /// The name of the issuer.
    #[must_use]
    pub fn issuer(&self) -> &Name<'a> {
        &self.issuer
    }

    /// The name of the subject.
    #[must_use]
    pub fn subject(&self) -> &Name<'a> {
        &self.subject
    }

    /// The validity, in whole seconds.
    #[must_use]
    pub const fn validity(&self) -> Validity {
        self.validity
    }

    /// The key of the subject.
    #[must_use]
    pub const fn key(&self) -> &PublicKey {
        &self.key
    }

    /// What the key of the subject does.
    #[must_use]
    pub fn usage(&self) -> Usage<'_> {
        match self.issuer_path {
            Some(path_length) => Usage::Issuer {
                path_length,
                purposes: &self.purposes,
            },
            None => Usage::Identity {
                names: &self.names,
                purposes: &self.purposes,
            },
        }
    }

    /// The claims of a Fulcio certificate, or `None` if the certificate has no Fulcio claim. The claims are evidence
    /// only after [`Self::verify_path`] to the Sigstore anchor. The caller decides which values it accepts.
    #[must_use]
    pub const fn fulcio(&self) -> Option<&Fulcio<'a>> {
        self.fulcio.as_ref()
    }
}

/// The first `N` bytes of `input`, which moves past them.
fn take<const N: usize>(input: &mut &[u8]) -> Result<[u8; N], Error> {
    let (head, rest) = input.split_first_chunk::<N>().ok_or(Error::Malformed)?;
    *input = rest;
    Ok(*head)
}

/// The `len` bytes after the big-endian length `len` in `input`, which moves past them.
fn take_len<'a>(input: &mut &'a [u8], len: [u8; 2]) -> Result<&'a [u8], Error> {
    let (head, rest) = input
        .split_at_checked(usize::from(u16::from_be_bytes(len)))
        .ok_or(Error::Malformed)?;
    *input = rest;
    Ok(head)
}

/// The TLS vector with a length of two bytes at the start of `input`, which moves past it.
fn vector<'a>(input: &mut &'a [u8]) -> Result<&'a [u8], Error> {
    let len = take(input)?;
    take_len(input, len)
}

/// The attributes of the DER `Name` content `content`, which can have no attribute. A value is a `UTF8String`, or a
/// `PrintableString` of the characters of X.680 section 41.4.
fn read_name(content: &[u8]) -> Result<Vec<(Attribute, &str)>, Error> {
    let mut reader = Reader::new(content);
    let mut attributes = Vec::new();
    while !reader.is_empty() {
        (attributes.len() < NAME_ATTRIBUTES_MAX).ok_or(Error::Name)?;
        let mut set = Reader::new(reader.read(SET)?);
        let mut pair = Reader::new(set.read(SEQUENCE)?);
        set.end()?;
        let object = pair.element(OBJECT)?;
        let attribute = Attribute::ALL
            .into_iter()
            .find(|attribute| attribute.object() == object)
            .ok_or(Error::Unsupported)?;
        let value = match pair.optional(PRINTABLE_STRING)? {
            Some(text) => {
                let printable = |byte: &u8| byte.is_ascii_alphanumeric() || b" '()+,-./:=?".contains(byte);
                text.iter().all(printable).ok_or(Error::Name)?;
                text
            }
            None => pair.read(UTF8_STRING)?,
        };
        let value = str::from_utf8(value).map_err(|_| Error::Name)?;
        pair.end()?;
        (1..=NAME_VALUE_BYTES_MAX).contains(&value.len()).ok_or(Error::Name)?;
        attributes.push((attribute, value));
    }
    Ok(attributes)
}

/// The key of the DER `SubjectPublicKeyInfo` `der`.
fn read_key(der: &[u8]) -> Result<PublicKey, Error> {
    let mut outer = Reader::new(der);
    let mut reader = Reader::new(outer.read(SEQUENCE)?);
    outer.end()?;
    let identifier = reader.element(SEQUENCE)?;
    let algorithm = ALGORITHMS
        .iter()
        .find(|(_, _, key, _)| *key == identifier)
        .map(|(algorithm, ..)| *algorithm)
        .ok_or(Error::Unsupported)?;
    let bits = reader.read(BIT_STRING)?;
    reader.end()?;
    let (&[0], public) = bits.split_first_chunk::<1>().ok_or(Error::Malformed)? else {
        return Err(Error::Malformed);
    };
    PublicKey::new(algorithm, public)
}

/// The extensions of a certificate, as [`read_extensions`] read them.
struct Extensions<'a> {
    names: Vec<AltName<'a>>,
    /// Whether the certificate has a critical `subjectAltName`.
    names_critical: bool,
    purposes: Vec<Purpose>,
    issuer_path: Option<Option<u8>>,
    fulcio: Option<Fulcio<'a>>,
    timestamps: Option<&'a [u8]>,
}

/// The extensions of the DER `Extensions` content `content`. An issuer has the critical `basicConstraints` with `cA`,
/// the critical `keyUsage` `keyCertSign` with `cRLSign` or `digitalSignature` or both or neither, and no
/// `subjectAltName`. A TLS identity has the critical `keyUsage` `digitalSignature`, and no `basicConstraints`. Each
/// can have an `extKeyUsage` of [`Purpose`] that is not critical. A `subjectAltName` of [`AltName`] can be critical.
/// The Fulcio claims and the `SignedCertificateTimestampList` are not critical. An extension that is not critical and
/// that this module does not read, such as a key identifier, has no effect.
fn read_extensions(content: &[u8]) -> Result<Extensions<'_>, Error> {
    let mut reader = Reader::new(content);
    let (mut constraints, mut usage, mut purposes, mut names, mut timestamps) = (None, None, None, None, None);
    let (mut names_critical, mut fulcio, mut count) = (false, Fulcio::default(), 0);
    while !reader.is_empty() {
        count += 1;
        (count <= EXTENSIONS_MAX).ok_or(Error::Malformed)?;
        let mut extension = Reader::new(reader.read(SEQUENCE)?);
        let object = extension.read(OBJECT)?;
        // DER omits the default: a critical flag is present only when it is true.
        let critical = match extension.optional(BOOLEAN)? {
            Some([0xff]) => true,
            Some(_) => return Err(Error::Malformed),
            None => false,
        };
        let value = extension.read(OCTET_STRING)?;
        extension.end()?;
        let slot = match object {
            BASIC_CONSTRAINTS if critical => &mut constraints,
            KEY_USAGE if critical => &mut usage,
            SUBJECT_ALT_NAME => {
                names_critical = critical;
                &mut names
            }
            BASIC_CONSTRAINTS | KEY_USAGE => return Err(Error::Unsupported),
            // Each other extension that this module reads is not critical.
            _ if critical => return Err(Error::Unsupported),
            EXTENDED_KEY_USAGE => &mut purposes,
            TIMESTAMP_LIST => &mut timestamps,
            _ => {
                let claim = match object.strip_prefix(FULCIO) {
                    Some(&[arc]) => fulcio.claim(arc),
                    _ => None,
                };
                if let Some(claim) = claim {
                    claim.replace(read_text(value)?).is_none().ok_or(Error::Malformed)?;
                }
                continue;
            }
        };
        slot.replace(value).is_none().ok_or(Error::Malformed)?;
    }
    let names = names.map(read_alt_names).transpose()?.unwrap_or_default();
    let issuer_path = match (constraints, usage.map(read_key_usage).transpose()?) {
        (Some(constraints), Some(bits))
            if bits & KEY_CERT_SIGN != 0 && bits & !(KEY_CERT_SIGN | CRL_SIGN | DIGITAL_SIGNATURE) == 0 =>
        {
            names.is_empty().ok_or(Error::Unsupported)?;
            Some(read_constraints(constraints)?)
        }
        (None, Some(DIGITAL_SIGNATURE)) => None,
        _ => return Err(Error::Unsupported),
    };
    Ok(Extensions {
        names,
        names_critical,
        purposes: purposes.map(read_purposes).transpose()?.unwrap_or_default(),
        issuer_path,
        fulcio: (fulcio != Fulcio::default()).then_some(fulcio),
        timestamps,
    })
}

/// The text of the DER `UTF8String` `value`.
fn read_text(value: &[u8]) -> Result<&str, Error> {
    let mut reader = Reader::new(value);
    let text = reader.read(UTF8_STRING)?;
    reader.end()?;
    str::from_utf8(text).map_err(|_| Error::Malformed)
}

/// The bits of the DER `KeyUsage` `value`, in its first byte. A usage in a second byte, `encipherOnly` or
/// `decipherOnly`, is outside the profile.
fn read_key_usage(value: &[u8]) -> Result<u8, Error> {
    let mut reader = Reader::new(value);
    let bits = reader.read(BIT_STRING)?;
    reader.end()?;
    match *bits {
        // DER drops the trailing zero bits: the count of unused bits is the count of trailing zeros.
        [unused, bits] if bits != 0 && u32::from(unused) == bits.trailing_zeros() => Ok(bits),
        [_, _, _] => Err(Error::Unsupported),
        _ => Err(Error::Malformed),
    }
}

/// The path length of the DER `BasicConstraints` `value` with `cA`, or `None` for no bound.
fn read_constraints(value: &[u8]) -> Result<Option<u8>, Error> {
    let mut sequence = Reader::new(value);
    let mut fields = Reader::new(sequence.read(SEQUENCE)?);
    sequence.end()?;
    (fields.read(BOOLEAN)? == [0xff]).ok_or(Error::Unsupported)?;
    let path_length = fields
        .optional(INTEGER)?
        .map(|length| match length {
            [value] if value & 0x80 == 0 => Ok(*value),
            [0, value] if value & 0x80 != 0 => Ok(*value),
            _ => Err(Error::Unsupported),
        })
        .transpose()?;
    fields.end()?;
    Ok(path_length)
}

/// The purposes of the DER `ExtKeyUsageSyntax` `value`.
fn read_purposes(value: &[u8]) -> Result<Vec<Purpose>, Error> {
    let mut outer = Reader::new(value);
    let mut reader = Reader::new(outer.read(SEQUENCE)?);
    outer.end()?;
    let mut purposes = Vec::new();
    while !reader.is_empty() {
        let object = reader.read(OBJECT)?;
        let purpose = Purpose::ALL
            .into_iter()
            .find(|purpose| purpose.object() == object)
            .ok_or(Error::Unsupported)?;
        (!purposes.contains(&purpose)).ok_or(Error::Name)?;
        purposes.push(purpose);
    }
    (!purposes.is_empty()).ok_or(Error::Malformed)?;
    Ok(purposes)
}

/// The names of the DER `GeneralNames` `value`.
fn read_alt_names(value: &[u8]) -> Result<Vec<AltName<'_>>, Error> {
    let mut outer = Reader::new(value);
    let mut reader = Reader::new(outer.read(SEQUENCE)?);
    outer.end()?;
    let mut names = Vec::new();
    while !reader.is_empty() {
        (names.len() < ALT_NAMES_MAX).ok_or(Error::Name)?;
        let name = if let Some(text) = reader.optional(DNS_NAME)? {
            AltName::Dns(str::from_utf8(text).map_err(|_| Error::Name)?)
        } else {
            AltName::Uri(str::from_utf8(reader.read(URI).map_err(|_| Error::Unsupported)?).map_err(|_| Error::Name)?)
        };
        alt_valid(&name).ok_or(Error::Name)?;
        names.push(name);
    }
    (!names.is_empty()).ok_or(Error::Malformed)?;
    Ok(names)
}

/// The cause of a refused certificate. No error holds a secret.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Error {
    /// The input has more than [`CERTIFICATE_BYTES_MAX`] bytes, or the certificate of a draft can have more.
    Bytes,
    /// The DER is not in the form of a certificate of this module.
    Malformed,
    /// An algorithm, an attribute, an extension, or a form of an extension is outside the profile of this module.
    Unsupported,
    /// A name, an alternative name, or a list of purposes is outside its form.
    Name,
    /// The serial number is not a positive DER integer of 1 to 20 bytes in its shortest form.
    Serial,
    /// The validity has no time after its start, or a time is outside the years 1970 to 9999.
    Validity,
    /// The keys do not fit the profile of issuance: an SLH-DSA key of a certificate that is no issuer certificate, a
    /// classical key with a key that is not classical, or an ES384 key.
    Profile,
    /// The public key is not a valid key of its algorithm.
    Key,
    /// The signature does not verify with the key, or the key has another algorithm than the signature.
    Signature,
    /// The certificates are not a path to the anchor: more than [`PATH_ISSUERS_MAX`] issuers, a name that does not
    /// chain, an issuer that is no issuer certificate, or a path past the length of an issuer. Give the issuers in
    /// order, from the issuer of the certificate to the certificate that the anchor signed.
    Path,
    /// A certificate of the path does not serve the purpose of the check.
    Purpose,
    /// The time of the check is outside the validity of a certificate of the path.
    Time,
    /// A Certificate Transparency timestamp of a trusted log does not verify.
    Timestamp,
    /// The signature check costs more than its budget has.
    Limit(Limit),
}

impl fmt::Display for Error {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Bytes => f.write_str("the certificate is too long"),
            Self::Malformed => f.write_str("the DER is not in the form of a certificate"),
            Self::Unsupported => f.write_str("the certificate is outside the profile"),
            Self::Name => f.write_str("a name of the certificate is not valid"),
            Self::Serial => f.write_str("the serial number is not valid"),
            Self::Validity => f.write_str("the validity is not valid"),
            Self::Profile => f.write_str("the keys do not fit the profile"),
            Self::Key => f.write_str("the public key is not valid"),
            Self::Signature => f.write_str("the signature does not verify"),
            Self::Path => f.write_str("the certificates are not a path to the anchor"),
            Self::Purpose => f.write_str("a certificate of the path does not serve the purpose"),
            Self::Time => f.write_str("the time is outside the validity of a certificate of the path"),
            Self::Timestamp => f.write_str("a timestamp of a trusted log does not verify"),
            Self::Limit(limit) => write!(f, "the signature check passes a limit: {limit:?}"),
        }
    }
}

impl core::error::Error for Error {}
