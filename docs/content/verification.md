# Verify COSE and CWT artifacts

`rsauthnz::cose` verifies a signed CWT: a `COSE_Sign1` ([RFC 9052](https://www.rfc-editor.org/rfc/rfc9052)) whose
payload is a CWT claims map ([RFC 8392](https://www.rfc-editor.org/rfc/rfc8392)). The application gives a trusted
profile, and verification gives evidence. A header of the artifact can only match the profile. It never selects an
algorithm or a key.

Parsing gives untrusted values. Do not use a parsed value for a decision before verification succeeds.

## Make a trusted profile

A `Profile` holds the facts that the application fixes before it reads an artifact:

| Field | Type | Rule |
| --- | --- | --- |
| `key` | `TrustedKey` | The key and its algorithm. The signature must verify with this key |
| `issuer` | `String` | The `iss` claim must be equal, byte for byte |
| `audience` | `String` | The `aud` claim must name it, byte for byte. `aud` can be one text string or an array |
| `purpose` | `Id<Purpose>` | The purpose of the artifacts that the profile accepts. The evidence records it |
| `limits` | `limits::Limits` | The bounds of the decode of the artifact and of its claims. See [Parser limits](parser-limits.md) |

One profile serves one purpose. Give each purpose its own key, so an artifact of one purpose never verifies for
another purpose. The credentials and receipts of rsauthnz sign their purpose, so one issuer key can sign each
purpose. [Issue and verify credentials](credential-format.md) gives that format.

`TrustedKey::new(algorithm, &key)` makes the key from a `Key` and a `crypto::Algorithm`. Decode a `COSE_Key` with
`Key::decode`, or make a `Key` from the bytes of a public key that you trust. `TrustedKey::new` returns
`Error::KeyAlgorithm` if the key does not fit the algorithm. It returns `Error::Malformed` if a P-256 point, alone or
in a composite key, is not on the curve.

| `Algorithm` | COSE `alg` | `PublicKey` | `COSE_Key` |
| --- | --- | --- | --- |
| `MlDsa65Ed25519` | -59 (draft) | `MlDsa65Ed25519(&[u8; 1984])` | `kty` 7 (`AKP`), `alg` -59, `pub` |
| `MlDsa65EcdsaP256` | -55 (draft) | `MlDsa65EcdsaP256(&[u8; 2017])` | `kty` 7 (`AKP`), `alg` -55, `pub` |
| `MlDsa65` | -49 | `MlDsa65(&[u8; 1952])` | `kty` 7 (`AKP`), `alg` -49, `pub` |
| `Ed25519` | -19 | `Ed25519(&[u8; 32])` | `kty` 1 (`OKP`), `crv` 6, `x` |
| `Es256` | -7 | `P256 { x, y }`, 32 bytes each | `kty` 2 (`EC2`), `crv` 1, `x`, `y` |
| `Rs256` | -257 | `Rsa { n, e }` | `kty` 3 (`RSA`), `alg` -257, `n`, `e` |

A `COSE_Key` also takes `alg` -8 (EdDSA) for an `OKP` key and -9 (ESP256) for an `EC2` key ([RFC
9864](https://www.rfc-editor.org/rfc/rfc9864)). The key type fixes the curve, so each one names `Ed25519` or `Es256`.
WebAuthn authenticators write -8. An `RSA` key needs `alg`, because the key type serves more than one algorithm, and
only -257 is supported. `TrustedKey::new` returns `Error::Malformed` for an RSA key that does not have a modulus of
2,048 to 4,096 bits and the exponent 65,537.

[Signature profiles](profiles.md) gives the guarantee of each profile, and the state of the draft identifiers.
`MlDsa65Ed25519` is the default profile. Ed25519 and ES256 are classical profiles. Select one only for a verifier
that supports nothing else. The SLH-DSA trust-root profile has no COSE identifier yet, so `TrustedKey::new` refuses
it with `Error::KeyAlgorithm`.

## Verify a CWT

Call `Profile::verify(artifact, now, &mut budget)`. `now` is a `time::Reading`: the physical time, with its
uncertainty bound. `budget` is the signature budget of the artifact, as [Bound the signature
checks](#bound-the-signature-checks) gives. This example verifies the signed CWT of RFC 8392, Appendix A.3. It is
also the example of the `rsauthnz::cose` module documentation, and `cargo xtask test` runs it:

```rust
use core::time::Duration;
use rsauthnz::crypto::Algorithm;
use rsauthnz::limits::{Limits, SignatureBudget};
use rsauthnz::cose::{Key, Profile, PublicKey, TrustedKey};
use rsauthnz::id::Id;
use rsauthnz::time::{Reading, ReadingSource};

// The signed CWT of RFC 8392, Appendix A.3, and the public part of its key (Appendix A.2.3).
let cwt = hex(concat!(
    "d28443a10126a104524173796d6d657472696345434453413235365850a70175636f61703a2f2f61732e6578616d706c652e",
    "636f6d02656572696b77037818636f61703a2f2f6c696768742e6578616d706c652e636f6d041a5612aeb0051a5610d9f006",
    "1a5610d9f007420b7158405427c1ff28d23fbad1f29c4c7c6a555e601d6fa29f9179bc3d7438bacaca5acd08c8d4d4f96131",
    "680c429a01f85951ecee743a52b9b63632c57209120e1c9e30",
));
let x = hex("143329cce7868e416927599cf65a34f3ce2ffda55a7eca69ed8919a394d42f0f");
let y = hex("60f7f1a780d8a783bfb7a2dd6b2796e8128dbbcef9d3d168db9529971a36e7b9");
let public = PublicKey::P256 { x: x.as_slice().try_into()?, y: y.as_slice().try_into()? };
let key = Key { kid: None, alg: None, public };

let profile = Profile {
    key: TrustedKey::new(Algorithm::Es256, &key)?,
    issuer: "coap://as.example.com".into(),
    audience: "coap://light.example.com".into(),
    purpose: Id::new("example", "light.access")?,
    limits: Limits::default(),
};
// The physical time of the check, with its uncertainty bound. The CWT is valid in October 2015.
let now = Reading::new(Duration::from_secs(1_444_000_000), Some(Duration::from_secs(1)), ReadingSource::Caller);

// One budget bounds the signature checks of the artifact. An ES256 signature is one check.
let mut budget = SignatureBudget::new(&profile.limits);
let verified = profile.verify(&cwt, now, &mut budget)?;
assert_eq!(budget.remaining(), 1);
assert_eq!(verified.claims().sub, Some("erikw"));
assert_eq!(verified.expires(), Duration::from_secs(1_444_064_944));
```

The example uses a `hex` function that converts hexadecimal digits to bytes. rsauthnz does not supply it.

`Profile::verify` does these checks, in this order. It refuses at the first check that fails:

1. It decodes the artifact within `limits`. The artifact is a `COSE_Sign1` with the tag 18 or no tag. The CWT tag
   61 can enclose it. The credentials and receipts of rsauthnz accept only their exact form: the tag 18, no CWT tag,
   and an empty unprotected bucket ([Issue and verify credentials](credential-format.md#the-format)).
2. It checks the header buckets. A label must not be in both buckets. A `crit` header must be protected. It can
   name only `alg` (1), `content type` (3), and `kid` (4), and each label that it names must be in the protected
   bucket.
3. It decodes the claims within `limits`, then checks `iss` and `aud`.
4. It checks the validity interval. The claims must have `exp`. The artifact is valid while `nbf <= t < exp` for
   each time `t` from `now.earliest()` to `now.latest()`. Thus a reading with an unknown bound refuses.
5. It checks that the protected `alg` is the algorithm of the profile.
6. It charges the signature budget, then verifies the signature with the key of the profile. This is the only
   expensive check.

The checks of the claims come before the signature check because they are cheap. Thus `Error::Issuer`,
`Error::Audience`, `Error::NoExpiry`, `Error::Expired`, and `Error::NotYetValid` can come before the signature
check. Such a refusal, and each other refusal of steps 1 to 5, does not show that the artifact is authentic.

## Bound the signature checks

`limits::SignatureBudget` holds the signature checks that one artifact can still make. Make one budget for each
artifact with `SignatureBudget::new(&limits)`. It starts at `Limits::signature_checks`, and the default is 2: one
composite signature. Give the same budget to each signature check of the artifact, for example `Profile::verify`
for a credential and `Sign1::verify` for a structure in it.

Each check charges its cost before its signature work: two checks for a composite profile, and one check for each
other profile. If the budget has less, the check refuses with `Error::Limit(Limit::SignatureChecks)`. It charges
nothing, and it does no signature work. `remaining()` gives the checks that are left.

## Use the evidence

`Verified` is the evidence of one verified CWT:

| Method | Result |
| --- | --- |
| `artifact()` | The exact bytes of the artifact |
| `profile()` | The profile that verified it: the key, the algorithm, the issuer, the audience, and the purpose |
| `claims()` | The verified `Claims` |
| `not_before()` | `nbf`, or `None` when the claims have no `nbf` |
| `expires()` | `exp`. The artifact is not valid at this time and after it |

Two `Verified` values are equal only for equal artifact bytes and equal profiles. Two artifacts with the same claims
but different bytes, for example a different unprotected `kid`, give different evidence.

A valid signature does not give current permission. Keep the evidence with the claims that a later possession or
authorization check reads.

The debug output of `Verified` and `Sign1` shows only the length of the artifact, the payload, and the signature,
because an artifact can be a bearer credential.

## Read COSE structures

These functions give untrusted values:

- `Sign1::decode(input, limits)` decodes a `COSE_Sign1`. `protected()` and `unprotected()` give the header buckets.
  A header that rsauthnz does not process stays in its bucket. `Header::get(label)` and `Header::entries()` read
  it. `payload()` gives the untrusted payload.
- `Sign1::verify(&key, &mut budget)` checks the `alg` and the signature of a `COSE_Sign1` that is not a CWT, and
  gives its payload. The externally supplied data is empty.
- `Key::decode(input, limits)` decodes a `COSE_Key`. It ignores the parameters that it does not read.
- `Claims::decode(input, limits)` decodes a CWT claims map. Each claim of RFC 8392 has its own field. Each other
  claim is in `other`.

The `cnf` claim ([RFC 8747](https://www.rfc-editor.org/rfc/rfc8747)) decodes into `Confirmation::Key` for a
`COSE_Key` member, or into `Confirmation::KeyId` for a `kid` member. A `cnf` map with two keys, or with no key,
refuses.

## Errors

Each refusal is a `cose::Error`. For each refusal, the recovery is to refuse the artifact.

| Error | Cause |
| --- | --- |
| `Cbor(cbor::Error)` | The CBOR decoder refused the input. See [Parser limits](parser-limits.md) |
| `Malformed` | The input is not the COSE or CWT structure, or a field has the wrong type |
| `UnknownCritical` | `crit` names a header that rsauthnz does not process |
| `Unsupported` | A key type, curve, or algorithm that rsauthnz does not support, a detached payload, a compressed P-256 point, an encrypted `cnf` key, or a key with private material |
| `KeyAlgorithm` | The key does not fit the algorithm |
| `AlgorithmMismatch` | The protected bucket has no `alg`, or its `alg` is not the algorithm of the profile. An `alg` in the unprotected bucket does not count |
| `KeyId` | A credential or a receipt of [the credential format](credential-format.md) has no protected `kid`, or its `kid` names no key of the profile at the time of the check. A `kid` in the unprotected bucket does not count |
| `Signature` | The signature does not verify with the key of the profile |
| `Limit(Limit::SignatureChecks)` | The signature check costs more than the signature budget of the artifact has. The check did no signature work |
| `Issuer` | `iss` is missing, or it is not the issuer of the profile |
| `Audience` | `aud` is missing, or it does not name the audience of the profile |
| `NoExpiry` | The claims have no `exp` |
| `Expired` | `now.latest()` is at or after `exp` |
| `NotYetValid` | `now.earliest()` is before `nbf` |
| `Time(TimeError)` | The reading cannot bound the check, for example `TimeError::UnknownBound` |

## Limits

- The decoder accepts only deterministic CBOR (RFC 8949, section 4.2.1). An artifact or a key in another encoding
  refuses with `Error::Cbor`. For example, the `COSE_Key` hex of RFC 8392, Appendix A.2.3, has its map keys out of
  order, so it refuses.
- rsauthnz verifies only `COSE_Sign1`. It does not support `COSE_Sign`, `COSE_Mac0`, `COSE_Encrypt0`, or a nested
  CWT.
- The signature check encodes the `Sig_structure` of RFC 9052, section 4.4, into one allocation of its exact size,
  after the profile match. It holds one copy of the payload, because the rscrypto verify functions take one
  contiguous message. It is at most 10 bytes longer than the `COSE_Sign1`.
