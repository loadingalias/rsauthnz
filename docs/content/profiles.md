# Signature profiles

`rsauthnz::crypto` holds the signature profiles. A profile is the algorithm of a trusted key. The application
selects it, and an artifact cannot select it. [rscrypto](https://github.com/loadingalias/rscrypto) does each
signature check. rsauthnz adds no cryptography. [Verify COSE and CWT artifacts](verification.md) gives the
verification with each profile, and [Issue, read, and check X.509 certificates](certificates.md) gives the X.509 identifier of
each profile of a certificate.

## The profiles

| `Algorithm` | COSE `alg` | Registration | Authentication | Signature checks | Public key | Signature | Use |
| --- | --- | --- | --- | --- | --- | --- | --- |
| `MlDsa65Ed25519` | -59 | Draft | `Hybrid` | 2 | 1,984 bytes | 3,373 bytes | The default profile: `Algorithm::default()` |
| `MlDsa65EcdsaP256` | -55 | Draft | `Hybrid` | 2 | 2,017 bytes | 3,381 bytes or fewer | The hardware-bound profile, for a key whose P-256 half is in a Secure Enclave, a TPM, or StrongBox |
| `MlDsa65` | -49 | Assigned | `PostQuantum` | 1 | 1,952 bytes | 3,309 bytes | A verifier that supports ML-DSA but not the composite |
| `Ed25519` | -19 | Assigned | `Classical` | 1 | 32 bytes | 64 bytes | A verifier that supports nothing else |
| `Es256` | -7 | Assigned | `Classical` | 1 | Two coordinates of 32 bytes | 64 bytes | A verifier that supports nothing else |
| `Rs256` | -257 | Assigned | `Classical` | 1 | A modulus of 2,048 to 4,096 bits, and the exponent 65,537 | The bytes of the modulus | Verification only: a [passkey](passkeys.md) of an authenticator that has no other algorithm, such as Windows Hello. No credential and no custody key of rsauthnz has it |
| `Ps256` | -37 | Assigned | `Classical` | 1 | The key of `Rs256` | The bytes of the modulus | Verification only: a JWT of an external issuer, such as an ID token ([Verify and sign JOSE tokens](jose.md)). No credential and no custody key of rsauthnz has it |
| `Es384` | None | Assigned | `Classical` | 1 | Two coordinates of 48 bytes | 96 bytes | Verification only: an X.509 certificate of another issuer, such as the Sigstore certificate authority ([Check a certificate of another issuer](certificates.md#check-a-certificate-of-another-issuer)). No credential, no custody key, and no COSE or JOSE form of rsauthnz has it |
| `SlhDsaSha2_128s` | None yet | Draft | `PostQuantum` | 1 | 32 bytes | 7,856 bytes | The trust-root profile: a root that signs issuer keys |

rsauthnz never selects a classical profile for you, and it never reports a classical profile as post-quantum.

IANA marks ES256 (-7) deprecated since [RFC 9864](https://www.rfc-editor.org/rfc/rfc9864), which assigns the
fully specified ESP256 (-9). `Es256` keeps -7, because the classical profile serves a verifier that supports nothing
else, and such a verifier knows -7.

The two composite profiles are the [LAMPS composite
signatures](https://datatracker.ietf.org/doc/draft-ietf-lamps-pq-composite-sigs/) (draft 19, which becomes RFC
10073). ML-DSA-65 and the classical algorithm sign the same message. A composite signature verifies only if both
components verify. One component alone does not verify as the composite. Thus each composite signature costs two
signature checks.

COSE uses the composite with the empty context, as the [JOSE and COSE composite
draft](https://datatracker.ietf.org/doc/draft-ietf-jose-pq-composite-sigs/) (draft 06, section 4.1) requires. A
composite `COSE_Key` is an `AKP` key (`kty` 7) with `alg` and `pub`. `pub` is the public key in the encoding of
the LAMPS draft: the ML-DSA-65 key, then the Ed25519 key or the uncompressed P-256 point. A composite signature is
the ML-DSA-65 signature, then the Ed25519 signature or the DER `Ecdsa-Sig-Value` of the ECDSA signature. The
verifier accepts only the canonical DER. An `Es256` signature is different: it is `r || s`, 64 bytes.

### Draft identifiers

IANA has not assigned the COSE identifiers of the composite profiles. Draft 06 of the JOSE and COSE composite draft
requests -59 for `MlDsa65Ed25519` and -55 for `MlDsa65EcdsaP256`, and rsauthnz uses these values. Until IANA
assigns them, another implementation can use other values. A later draft can change them. Each value is one
constant in rsauthnz, so a change of the draft changes only that constant.

## The profile of an audience

The algorithm of the issuer key is the profile that an audience declares. The audience accepts only artifacts of that
algorithm, and rsauthnz tries no other key and no other algorithm after a refusal. The `cnf` key of a credential has
the same authentication as the issuer key. [Declare the profile of an audience](credential-format.md#declare-the-profile-of-an-audience)
gives the rules.

| Authentication | Guarantee | Cost of one signature |
| --- | --- | --- |
| `Hybrid` | A forgery must break ML-DSA-65 and the classical algorithm | Two checks. 3,373 bytes, or 3,381 bytes or fewer for P-256 |
| `PostQuantum` | A forgery must break ML-DSA-65 only | One check. 3,309 bytes |
| `Classical` | A forgery must break Ed25519 or P-256. A quantum computer that can break them can forge | One check. 64 bytes |

Select pure ML-DSA-65 or a classical profile only for an audience that cannot verify the composite. Its credentials
then report `PostQuantum` or `Classical`, and so does the evidence of each proof of possession.

## The trust-root profile

`SlhDsaSha2_128s` is SLH-DSA-SHA2-128s of [FIPS 205](https://csrc.nist.gov/pubs/fips/205/final), in its pure form,
with the empty context. A trust root signs issuer keys rarely, and its signatures must stay trustworthy longest.
The security of SLH-DSA rests only on its hash function, SHA-256.

rsauthnz selects SLH-DSA-SHA2-128s for these reasons:

- rscrypto qualifies it first as the root profile of the family.
- It has the smallest signature of the FIPS 205 sets: 7,856 bytes. SLH-DSA-SHA2-192s has 16,224 bytes.
- The JOSE and COSE draft for SLH-DSA registers only the two 128s sets.

The cost: SLH-DSA-SHA2-128s is in NIST security category 1, and ML-DSA-65 is in category 3. Thus the root is in a
lower category than the credentials that it endorses. A deployment whose policy requires category 3 needs
SLH-DSA-SHA2-192s, which rsauthnz does not have.

The profile has no COSE identifier yet. [draft-ietf-cose-sphincs-plus-11](https://datatracker.ietf.org/doc/draft-ietf-cose-sphincs-plus/)
requests -51, but IANA assigned -51 to ESP384 ([RFC 9864](https://www.rfc-editor.org/rfc/rfc9864)). Thus the
`cose` field of its report is `None`, and `TrustedKey::new` refuses the algorithm. The credential format refuses it
too. The one artifact that a root signs is a [trust snapshot](trust-snapshots.md): its protected bucket has no `alg`,
and the custody handle of the trusted root names the algorithm.

Custody makes, signs with, rotates, and deletes root keys ([Hold keys in custody](custody.md)), and a custody handle
verifies their signatures. The three NIST ACVP cases of `tests/slh-dsa/` verify through the facade, with the empty
context. A root also signs X.509 issuer certificates ([Issue, read, and check X.509 certificates](certificates.md)). The other
formats of rsauthnz refuse the profile, because a root signs issuer keys and trust snapshots only.

## The profile report

`Algorithm::report()` gives a `Report` with these fields:

| Field | Type | Value |
| --- | --- | --- |
| `cose` | `Option<i64>` | The COSE algorithm identifier, or `None` if rsauthnz uses none for the profile yet |
| `registration` | `Registration` | `Assigned` if IANA assigned the identifier. `Draft` if a draft requests it |
| `authentication` | `Authentication` | `Hybrid`: a post-quantum and a classical signature, and both must verify. `PostQuantum`: ML-DSA-65 or SLH-DSA only. `Classical`: no post-quantum authentication |

The report gives the authentication of a signature only. Post-quantum key exchange is a guarantee of the transport,
and the evidence of the transport gives it separately. A composite credential over a connection with a classical key
exchange is not post-quantum end to end.

This example is also the example of the `rsauthnz::crypto` module documentation, and `cargo xtask test` runs it:

```rust
use rsauthnz::crypto::{Algorithm, Authentication, Registration};

let report = Algorithm::default().report();
assert_eq!(report.authentication, Authentication::Hybrid);
// IANA has not assigned the composite COSE identifiers yet.
assert_eq!(report.registration, Registration::Draft);
// A classical profile is never reported as post-quantum.
assert_eq!(Algorithm::Ed25519.report().authentication, Authentication::Classical);
// The trust-root profile has no COSE identifier yet.
assert_eq!(Algorithm::SlhDsaSha2_128s.report().cose, None);
```

## Cost

Each signature check charges the signature budget of its artifact before its work: one check for `MlDsa65`,
`Ed25519`, `Es256`, `Es384`, `Rs256`, `Ps256`, and `SlhDsaSha2_128s`, and two checks for a composite. [Verify COSE and CWT
artifacts](verification.md#bound-the-signature-checks) gives the budget. A signature check is in the cost class
`Verify` of [Admit rsauthnz work](admission.md).
