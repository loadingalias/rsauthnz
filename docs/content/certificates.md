# Issue, read, and check X.509 certificates

`rsauthnz::x509` issues the X.509 certificates of TLS identities ([RFC 5280](https://www.rfc-editor.org/rfc/rfc5280)),
and it reads the same forms. A **TLS identity** is a key that a TLS stack uses for one server or client, such as a
workload. An **issuer certificate** binds a key that signs other certificates, such as an issuer key under a trust
root. rsauthnz encodes and checks the certificate, and the TLS stack of the host uses it.

`rsauthnz::x509` also checks a certificate that another issuer made, such as the Fulcio certificate of a Sigstore
build ([Check a certificate of another issuer](#check-a-certificate-of-another-issuer)).

## The model

- A `Draft` builds the DER `TBSCertificate`: the bytes that the issuer signs. The signer is outside the draft: a
  [custody](custody.md) for a composite or an SLH-DSA key, or another signer for an ML-DSA-65 or a classical key.
- The issuer key gives the signature algorithm. No input selects it, and rsauthnz never selects a classical algorithm
  for you ([Signature profiles](profiles.md)).
- Only the accepted commit releases a certificate. `Draft::finish` verifies the signature and gives a
  `transition::Prepared`. `Draft::record` adds the issuance record of the serial to the same proposal. Thus one serial
  of an issuer gives one certificate, and a lost response gives none ([Propose a transition](transitions.md)).
- `Certificate::parse` reads the forms of this module and a strict profile of other issuers. `Certificate::verify`
  checks a signature with the key of the issuer, and `Certificate::verify_path` checks a path to a trust anchor.

| `Algorithm` | Signature and key identifier | Use |
| --- | --- | --- |
| `MlDsa65Ed25519` | `id-MLDSA65-Ed25519-SHA512`, 1.3.6.1.5.5.7.6.48 (LAMPS draft) | The default |
| `MlDsa65EcdsaP256` | `id-MLDSA65-ECDSA-P256-SHA512`, 1.3.6.1.5.5.7.6.45 (LAMPS draft) | A key whose P-256 half is in hardware |
| `MlDsa65` | `id-ml-dsa-65`, 2.16.840.1.101.3.4.3.18 ([RFC 9881](https://www.rfc-editor.org/rfc/rfc9881)) | A verifier that supports ML-DSA but not the composite |
| `SlhDsaSha2_128s` | `id-slh-dsa-sha2-128s`, 2.16.840.1.101.3.4.3.20 ([RFC 9909](https://www.rfc-editor.org/rfc/rfc9909)) | Issuer certificates of a trust root only |
| `Ed25519` | `id-Ed25519`, 1.3.101.112 ([RFC 8410](https://www.rfc-editor.org/rfc/rfc8410)) | Classical |
| `Es256` | `ecdsa-with-SHA256`, 1.2.840.10045.4.3.2, and the key `id-ecPublicKey` with `prime256v1` | Classical |
| `Es384` | `ecdsa-with-SHA384`, 1.2.840.10045.4.3.3, and the key `id-ecPublicKey` with `secp384r1` | Classical, verification only: the certificates of other issuers, such as Sigstore |

Each identifier has no parameters. The composite OIDs come from the LAMPS draft, and each one is one constant, so a
change of the draft changes only that constant. ML-DSA-65, the composites, and SLH-DSA sign with the empty context.

A draft refuses three forms with `Error::Profile`. An SLH-DSA key signs and holds only issuer certificates, because a
trust root signs issuer keys. A classical key never chains with a key that is not classical, so a classical
certificate never claims a post-quantum issuer, and a post-quantum certificate never rests on a classical one. An
`Es384` key neither signs nor holds a certificate of rsauthnz.

## The forms

`Fields` holds each field of the certificate:

| Field | Form |
| --- | --- |
| `serial` | A `Serial`: a positive DER integer of 1 to 20 bytes. `Serial::random` gives 16 bytes with 126 random bits |
| `issuer`, `subject` | A `Name`: 1 to `NAME_ATTRIBUTES_MAX` (8) attributes, `CommonName`, `Organization`, or `OrganizationalUnit`, each a `UTF8String` of 1 to `NAME_VALUE_BYTES_MAX` (64) bytes, in order |
| `validity` | `not_before` and `not_after`, in whole seconds since the Unix epoch. `UTCTime` before 2050, and `GeneralizedTime` from 2050 |
| `key` | The `PublicKey` of the subject |
| `usage` | `Usage::Identity` or `Usage::Issuer` |

`PublicKey::new(algorithm, public)` takes the encoding of `Handle::public_key`: 32 bytes for Ed25519, the
uncompressed SEC1 point of 65 bytes for P-256 or of 97 bytes for P-384, the encoding of FIPS 204 or of the LAMPS draft for ML-DSA-65 and the
composites, and PK.seed then PK.root for SLH-DSA.

The extensions follow from the usage, in this order:

| Usage | Extensions |
| --- | --- |
| `Identity { names, purposes }` | `keyUsage` `digitalSignature` (critical). `extKeyUsage` of `purposes` (`Server`, `Client`, `CodeSigning`) and `subjectAltName` of `names`: up to `ALT_NAMES_MAX` (16) `Dns` names in lowercase and `Uri` names of up to `URI_BYTES_MAX` (1,024) bytes. An empty list gives no extension |
| `Issuer { path_length, purposes }` | `basicConstraints` with `cA` and the path length (critical), `keyUsage` `keyCertSign` (critical), `extKeyUsage` of `purposes`, and `subjectKeyIdentifier`. The purposes bound the certificates under the issuer. An empty list gives no `extKeyUsage` and no bound |

Each certificate that is not self-signed also has the `authorityKeyIdentifier` of its issuer, as RFC 5280 sections
4.2.1.1 and 4.2.1.2 ask. A key identifier is the first 160 bits of the SHA-256 digest of the key ([RFC
7093](https://www.rfc-editor.org/rfc/rfc7093), method 1).

## Issue a certificate

1. Draw a serial with `Serial::random(&mut random)`, and fill `Fields`.
2. Call `Draft::new(&fields, &issuer, &authority)`. `issuer` is the `PublicKey` of the issuer, and `authority` owns
   the issuance record.
3. Sign `draft.to_be_signed()` with the issuer key. For a custody key, call
   `custody.sign(&handle, handle.algorithm(), draft.to_be_signed(), &mut random)`. An ECDSA signature is the DER
   `Ecdsa-Sig-Value`.
4. Make the proposal of your transition, and call `draft.record(&mut proposal)`. The record has the key
   `Kind::Credential` with the SHA-256 digest of `["rsauthnz.x509.record.1", issuer key, serial]`, and it ends after
   the certificate. It holds no signature.
5. Call `draft.finish(&signature, &mut budget)`, and give the result to `proposal.prepare`. A signature of another key
   refuses with `Error::Signature`, and gives no certificate.
6. Submit the proposal. Only the receipt of the accepted commit gives the DER certificate: `receipt.artifact()`. A
   second draft with the same serial of the same issuer conflicts at its record. After a lost response, issue again
   with a new serial: the receipt of a lookup has no artifact.

## Read and verify a certificate

`Certificate::parse(der)` refuses more than `CERTIFICATE_BYTES_MAX` (16,384) bytes before it reads a byte. Then it
reads the DER with no allocation for the DER itself: each length has its shortest form, has at most two bytes, and
fits in the input. It reads the forms of this module, and also these forms of other issuers:

- An `Es384` key or signature.
- A name value in `PrintableString`.
- An empty subject, with a critical `subjectAltName` (RFC 5280 section 4.1.2.6).
- An issuer certificate whose `keyUsage` adds `cRLSign` or `digitalSignature` to `keyCertSign`, and whose
  `extKeyUsage` names its purposes.
- Up to 64 extensions, with the Fulcio claims and the Certificate Transparency timestamps.

It refuses each other form, such as a version other than 3, another signature algorithm in the `TBSCertificate`, an
attribute other than `CommonName`, `Organization`, and `OrganizationalUnit`, a critical extension that it does not
read, a unique identifier, and bytes after the certificate. It skips an extension that is not critical and that it
does not read, such as a key identifier. It reads no signature.

`certificate.verify(&issuer, &mut budget)` checks the signature with the key of the issuer. A key of another algorithm
refuses before any signature work. The accessors give `algorithm()`, `serial()`, `issuer()`, `subject()`,
`validity()`, `key()`, `usage()`, and `fulcio()`.

## Check a certificate of another issuer

A host checks a certificate that another issuer made, such as the Fulcio certificate of a Sigstore build. rsauthnz
gives the evidence. The host owns the policy: its trust anchors and logs, the time windows of their trust, the count
of timestamps, and the claims that it accepts. A **trust anchor** is an issuer certificate that the host trusts
before the check, such as the root of a Sigstore trusted root. rsauthnz does not read the Sigstore bundle, the DSSE
envelope, or the Rekor entry.

1. Parse the anchor and the issuer certificates of your trusted root, and the leaf of the bundle, with
   `Certificate::parse`.
2. Call `leaf.verify_path(&issuers, &anchor, at, purpose, &mut budget)`. Give `issuers` in order: the issuer of the
   leaf first, at most `PATH_ISSUERS_MAX` (4). Give `at` as a time that a log proved, such as the `integratedTime` of
   the Rekor entry, because a Fulcio leaf is valid for 10 minutes. The checks run in this order, and the first that
   fails gives its error:
   1. The leaf is a `Usage::Identity` whose purposes include `purpose`, else `Error::Purpose`.
   2. The issuer name of each certificate equals the subject name of the next, byte for byte, else `Error::Path`.
   3. Each next certificate is an issuer certificate, else `Error::Path`. Its path length bounds the issuer
      certificates under it, else `Error::Path`. If it names purposes, they include `purpose`, else `Error::Purpose`.
   4. `at` is in the validity of each certificate, the anchor too, from its first second to its last, else
      `Error::Time`.
   5. Each signature verifies with the key of the next certificate, else `Error::Signature`. The host trusts the
      anchor, so the check does not verify the signature of the anchor.
3. Make the key of each trusted Certificate Transparency log with `PublicKey::from_spki(Algorithm::Es256, spki)`.
   The caller gives the algorithm, so the input cannot select it. Call `leaf.timestamps(&issuer, &logs, &mut budget)`,
   where `issuer` is the certificate that signed the leaf. The result has one `Timestamp { log, time }` for each
   embedded timestamp (SCT, [RFC 6962](https://www.rfc-editor.org/rfc/rfc6962) section 3.3) of a log of `logs`. `log`
   is the index in `logs`, and `time` has milliseconds. A timestamp of another log has no effect. A timestamp of a
   log of `logs` that does not verify gives `Error::Timestamp`. Check that each log was trusted at its `time`, and
   that you have the count of timestamps that your policy needs.
4. Read `leaf.fulcio()`, and compare the claims with your policy. Each field of `Fulcio` is the claim of one Fulcio
   extension (1.3.6.1.4.1.57264.1.8 to .22), or `None`. For a GitHub Actions build, compare at least `issuer`
   (`https://token.actions.githubusercontent.com`), `source_repository_uri`, `source_repository_ref`, and
   `build_signer_uri`. `usage()` gives the `subjectAltName` of the leaf. The deprecated claims 1 to 6 have no effect.

Size the budget for the work: each certificate under the anchor is one signature check, and each timestamp of a
trusted log is one more. A Fulcio chain with one timestamp is three checks, and the default budget has two.

This example is also the example of `Certificate::verify_path`, and `cargo xtask test` runs it. `root`,
`intermediate`, `leaf`, and `ct_log` are the DER bytes of the Sigstore certificates and of the CT log key in
`tests/x509/`:

```rust
use core::time::Duration;

use rsauthnz::crypto::Algorithm;
use rsauthnz::limits::{Limits, SignatureBudget};
use rsauthnz::x509::{Certificate, Error, PublicKey, Purpose};

// The path is two signature checks, and each timestamp of a trusted log is one more.
let mut limits = Limits::default();
limits.signature_checks = 3;
let mut budget = SignatureBudget::new(&limits);
// The root and the intermediate of the trusted root of the host, and the leaf of the bundle.
let anchor = Certificate::parse(root)?;
let issuers = [Certificate::parse(intermediate)?];
let leaf = Certificate::parse(leaf)?;
// The `integratedTime` of the Rekor entry of the bundle: the leaf is valid for 10 minutes.
let logged = Duration::from_secs(1_710_888_076);
leaf.verify_path(&issuers, &anchor, logged, Purpose::CodeSigning, &mut budget)?;
// The CT log of the trusted root signed one timestamp of the leaf.
let log = PublicKey::from_spki(Algorithm::Es256, ct_log)?;
assert_eq!(leaf.timestamps(&issuers[0], &[log], &mut budget)?.len(), 1);
// The policy of the host compares the claims.
let claims = leaf.fulcio().ok_or(Error::Unsupported)?;
assert_eq!(claims.source_repository_uri, Some("https://github.com/trailofbits/rfc8785.py"));
assert_eq!(claims.source_repository_ref, Some("refs/tags/v0.1.2"));
```

## Example

This example is also the example of the `rsauthnz::x509` module documentation, and `cargo xtask test` runs it. It
drafts the certificate of a TLS identity whose Ed25519 key signs its own certificate.

```rust
use core::time::Duration;

use rsauthnz::crypto::Algorithm;
use rsauthnz::id::Id;
use rsauthnz::limits::{Limits, SignatureBudget};
use rsauthnz::x509::{AltName, Attribute, Certificate, Draft, Error, Fields, PublicKey, Purpose, Serial, Usage, Validity};
use rscrypto::ChaCha20Rng;

let key = PublicKey::new(Algorithm::Ed25519, &[0x3b; 32])?;
let name = [(Attribute::Organization, "acme"), (Attribute::CommonName, "build")];
let fields = Fields {
    serial: Serial::random(&mut ChaCha20Rng::from_seed([7; 32])),
    issuer: &name,
    subject: &name,
    validity: Validity {
        not_before: Duration::from_secs(1_800_000_000),
        not_after: Duration::from_secs(1_831_536_000),
    },
    key: &key,
    usage: Usage::Identity {
        names: &[AltName::Dns("build.app.example")],
        purposes: &[Purpose::Server, Purpose::Client],
    },
};
let draft = Draft::new(&fields, &key, &Id::new("acme", "auth")?)?;
// The issuer signs these bytes: the DER `TBSCertificate`.
assert_eq!(draft.to_be_signed()[0], 0x30);
// A signature that the issuer key did not make gives no certificate.
let refused = draft.finish(&[0; 64], &mut SignatureBudget::new(&Limits::default()));
assert_eq!(refused.err(), Some(Error::Signature));
// More bytes than `CERTIFICATE_BYTES_MAX` refuse before a read.
assert_eq!(Certificate::parse(&[0x30; 16 * 1024 + 1]).err(), Some(Error::Bytes));
```

## Errors

Each `x509::Error` is a small `Copy` value with no secret. Refuse the request after each one.

| `Error` | Cause |
| --- | --- |
| `Bytes` | More than `CERTIFICATE_BYTES_MAX` bytes, or a draft whose certificate can have more |
| `Malformed` | The DER is not in the form of a certificate of this module |
| `Unsupported` | An algorithm, an attribute, an extension, or a form of an extension outside the profile |
| `Name` | A name, an alternative name, or a list of purposes outside its form |
| `Serial` | The serial is not a positive DER integer of 1 to 20 bytes in its shortest form |
| `Validity` | `not_after` is not after `not_before`, or a time is outside the years 1970 to 9999 |
| `Profile` | An SLH-DSA key of a certificate that is no issuer certificate, a classical key with a key that is not classical, or an `Es384` key in a draft |
| `Key` | The public key is not a valid key of its algorithm, or `PublicKey::from_spki` read a key of another algorithm |
| `Signature` | The signature does not verify, or the issuer key has another algorithm than the signature |
| `Path` | The certificates are not a path to the anchor: more than `PATH_ISSUERS_MAX` issuers, a name that does not chain, an issuer that is no issuer certificate, or a path past the length of an issuer. Give the issuers in order, from the issuer of the leaf |
| `Purpose` | A certificate of the path does not serve the purpose of the check |
| `Time` | The time of the check is outside the validity of a certificate of the path |
| `Timestamp` | A Certificate Transparency timestamp of a trusted log does not verify, or it names an algorithm other than ECDSA with SHA-256 |
| `Limit(limit)` | The signature checks cost more than their budget has |

`Certificate::timestamps` gives `Unsupported` for a log key that is not `Es256` and for a timestamp of a version other
than 1. It gives `Malformed` for a list outside the form of RFC 6962 or with more than `TIMESTAMPS_MAX` (8)
timestamps.

The cost class of `Draft::new`, `to_be_signed`, `record`, `Serial::random`, and `Certificate::parse` is `Parse`. The
cost class of `Draft::finish`, `Certificate::verify`, `Certificate::verify_path`, `Certificate::timestamps`,
`PublicKey::new`, and `PublicKey::from_spki` is `Verify` ([Admit rsauthnz work](admission.md)): one signature check for
each component, two for a composite.

## Support

The tests on this Mac (macOS aarch64) rebuild the two composite certificates of the LAMPS draft (draft 19, Appendix
E) byte for byte, from their fields and their signatures. They rebuild five certificates of OpenSSL 3.5.9 byte for
byte the same way: an SLH-DSA-SHA2-128s root, an ML-DSA-65 issuer under it, an ML-DSA-65 leaf under that issuer, and
self-signed Ed25519 and ES256 leaves. Each signature of these certificates verifies along its chain. OpenSSL 3.5.9, in
its strict mode, parsed certificates that this module issued with new keys, and it verified their ML-DSA-65,
Ed25519, ES256, and SLH-DSA signatures. OpenSSL verifies no composite signature, so the composite claim rests on the
LAMPS certificates. No TLS stack has used a certificate of this module yet.

The tests check the Fulcio certificate of a GitHub Actions release (`trailofbits/rfc8785.py` v0.1.2, from the
sigstore-python test assets) along the Sigstore public-good chain, at the time of its Rekor entry. Its 15 claims equal
the values that OpenSSL 3 printed, and its timestamp verifies with the key of the CT log `ctfe.sigstore.dev/2022`. The
Sigstore public-good instance is the only issuer of other certificates that has run.
