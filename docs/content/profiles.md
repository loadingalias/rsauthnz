# Signature profiles

`rsauthnz::crypto` holds the signature profiles. A profile is the algorithm of a trusted key. The application
selects it, and an artifact cannot select it. [rscrypto](https://github.com/loadingalias/rscrypto) does each
signature check. rsauthnz adds no cryptography. [Verify COSE and CWT artifacts](verification.md) gives the
verification with each profile.

## The profiles

| `Algorithm` | COSE `alg` | Registration | Authentication | Signature checks | Public key | Signature | Use |
| --- | --- | --- | --- | --- | --- | --- | --- |
| `MlDsa65Ed25519` | -59 | Draft | `Hybrid` | 2 | 1,984 bytes | 3,373 bytes | The default profile: `Algorithm::default()` |
| `MlDsa65EcdsaP256` | -55 | Draft | `Hybrid` | 2 | 2,017 bytes | 3,381 bytes or fewer | The hardware-bound profile, for a key whose P-256 half is in a Secure Enclave, a TPM, or StrongBox |
| `MlDsa65` | -49 | Assigned | `PostQuantum` | 1 | 1,952 bytes | 3,309 bytes | A verifier that supports ML-DSA but not the composite |
| `Ed25519` | -19 | Assigned | `Classical` | 1 | 32 bytes | 64 bytes | A verifier that supports nothing else |
| `Es256` | -7 | Assigned | `Classical` | 1 | Two coordinates of 32 bytes | 64 bytes | A verifier that supports nothing else |

rsauthnz never selects a classical profile for you, and it never reports a classical profile as post-quantum.

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

## The profile report

`Algorithm::report()` gives a `Report` with these fields:

| Field | Type | Value |
| --- | --- | --- |
| `cose` | `i64` | The COSE algorithm identifier |
| `registration` | `Registration` | `Assigned` if IANA assigned the identifier. `Draft` if a draft requests it |
| `authentication` | `Authentication` | `Hybrid`: a post-quantum and a classical signature, and both must verify. `PostQuantum`: ML-DSA-65 only. `Classical`: no post-quantum authentication |

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
```

## Cost

Each signature check charges the signature budget of its artifact before its work: one check for `MlDsa65`,
`Ed25519`, and `Es256`, and two checks for a composite. [Verify COSE and CWT
artifacts](verification.md#bound-the-signature-checks) gives the budget. A signature check is in the cost class
`Verify` of [Admit rsauthnz work](admission.md).
