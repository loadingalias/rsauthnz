# Issue and read X.509 certificates

`rsauthnz::x509` issues the X.509 certificates of TLS identities ([RFC 5280](https://www.rfc-editor.org/rfc/rfc5280)),
and it reads the same forms. A **TLS identity** is a key that a TLS stack uses for one server or client, such as a
workload. An **issuer certificate** binds a key that signs other certificates, such as an issuer key under a trust
root. rsauthnz encodes and checks the certificate, and the TLS stack of the host uses it.

## The model

- A `Draft` builds the DER `TBSCertificate`: the bytes that the issuer signs. The signer is outside the draft: a
  [custody](custody.md) for a composite or an SLH-DSA key, or another signer for an ML-DSA-65 or a classical key.
- The issuer key gives the signature algorithm. No input selects it, and rsauthnz never selects a classical algorithm
  for you ([Signature profiles](profiles.md)).
- Only the accepted commit releases a certificate. `Draft::finish` verifies the signature and gives a
  `transition::Prepared`. `Draft::record` adds the issuance record of the serial to the same proposal. Thus one serial
  of an issuer gives one certificate, and a lost response gives none ([Propose a transition](transitions.md)).
- `Certificate::parse` reads only the forms of this module, and `Certificate::verify` checks a signature with the key
  of the issuer.

| `Algorithm` | Signature and key identifier | Use |
| --- | --- | --- |
| `MlDsa65Ed25519` | `id-MLDSA65-Ed25519-SHA512`, 1.3.6.1.5.5.7.6.48 (LAMPS draft) | The default |
| `MlDsa65EcdsaP256` | `id-MLDSA65-ECDSA-P256-SHA512`, 1.3.6.1.5.5.7.6.45 (LAMPS draft) | A key whose P-256 half is in hardware |
| `MlDsa65` | `id-ml-dsa-65`, 2.16.840.1.101.3.4.3.18 ([RFC 9881](https://www.rfc-editor.org/rfc/rfc9881)) | A verifier that supports ML-DSA but not the composite |
| `SlhDsaSha2_128s` | `id-slh-dsa-sha2-128s`, 2.16.840.1.101.3.4.3.20 ([RFC 9909](https://www.rfc-editor.org/rfc/rfc9909)) | Issuer certificates of a trust root only |
| `Ed25519` | `id-Ed25519`, 1.3.101.112 ([RFC 8410](https://www.rfc-editor.org/rfc/rfc8410)) | Classical |
| `Es256` | `ecdsa-with-SHA256`, 1.2.840.10045.4.3.2, and the key `id-ecPublicKey` with `prime256v1` | Classical |

Each identifier has no parameters. The composite OIDs come from the LAMPS draft, and each one is one constant, so a
change of the draft changes only that constant. ML-DSA-65, the composites, and SLH-DSA sign with the empty context.

A draft refuses two mixes with `Error::Profile`. An SLH-DSA key signs and holds only issuer certificates, because a
trust root signs issuer keys. A classical key never chains with a key that is not classical, so a classical
certificate never claims a post-quantum issuer, and a post-quantum certificate never rests on a classical one.

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
uncompressed SEC1 point of 65 bytes for P-256, the encoding of FIPS 204 or of the LAMPS draft for ML-DSA-65 and the
composites, and PK.seed then PK.root for SLH-DSA.

The extensions follow from the usage, in this order:

| Usage | Extensions |
| --- | --- |
| `Identity { names, purposes }` | `keyUsage` `digitalSignature` (critical). `extKeyUsage` of `purposes` (`Server`, `Client`) and `subjectAltName` of `names`: up to `ALT_NAMES_MAX` (16) `Dns` names in lowercase and `Uri` names of up to `URI_BYTES_MAX` (256) bytes. An empty list gives no extension |
| `Issuer { path_length }` | `basicConstraints` with `cA` and the path length (critical), `keyUsage` `keyCertSign` (critical), and `subjectKeyIdentifier` |

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
fits in the input. It refuses each form outside this module, such as a version other than 3, another signature
algorithm in the `TBSCertificate`, a critical extension that it does not read, a unique identifier, and bytes after
the certificate. It skips an extension that is not critical and that it does not read, such as a key identifier. It
reads no signature.

`certificate.verify(&issuer, &mut budget)` checks the signature with the key of the issuer. A key of another algorithm
refuses before any signature work. The accessors give `algorithm()`, `serial()`, `issuer()`, `subject()`,
`validity()`, `key()`, and `usage()`. A path check, such as the names of a chain and the validity at a time, is the
work of the verifier of the host.

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
| `Profile` | An SLH-DSA key of a certificate that is no issuer certificate, or a classical key with a key that is not classical |
| `Key` | The public key is not a valid key of its algorithm |
| `Signature` | The signature does not verify, or the issuer key has another algorithm than the signature |
| `Limit(limit)` | The signature check costs more than its budget has |

The cost class of `Draft::new`, `to_be_signed`, `record`, `Serial::random`, and `Certificate::parse` is `Parse`. The
cost class of `Draft::finish`, `Certificate::verify`, and `PublicKey::new` is `Verify` ([Admit rsauthnz
work](admission.md)): one signature check for each component, two for a composite.

## Support

The tests on this Mac (macOS aarch64) rebuild the two composite certificates of the LAMPS draft (draft 19, Appendix
E) byte for byte, from their fields and their signatures. They rebuild five certificates of OpenSSL 3.5.9 byte for
byte the same way: an SLH-DSA-SHA2-128s root, an ML-DSA-65 issuer under it, an ML-DSA-65 leaf under that issuer, and
self-signed Ed25519 and ES256 leaves. Each signature of these certificates verifies along its chain. OpenSSL 3.5.9, in
its strict mode, parsed certificates that this module issued with new keys, and it verified their ML-DSA-65,
Ed25519, ES256, and SLH-DSA signatures. OpenSSL verifies no composite signature, so the composite claim rests on the
LAMPS certificates. No TLS stack has used a certificate of this module yet.
