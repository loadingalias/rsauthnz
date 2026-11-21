# Verify and sign JOSE tokens

`rsauthnz::jose` verifies and signs JWS tokens in the compact serialization ([RFC
7515](https://www.rfc-editor.org/rfc/rfc7515)), and it checks the claims of a JWT ([RFC
7519](https://www.rfc-editor.org/rfc/rfc7519)) and of a JWT access token ([RFC
9068](https://www.rfc-editor.org/rfc/rfc9068)). Use it for the tokens of an external issuer, such as an identity
provider, and for the JWT access tokens of the bearer bridge. The credentials of rsauthnz use COSE
([Verify COSE and CWT artifacts](verification.md)).

## The model

A **profile** (`jose::Profile`) is what the verifier trusts: one algorithm, its keys, and the issuer, the audience,
and the kind of each JWT. A token can only match its profile:

- The `alg` of the header must name the algorithm of the profile. `none`, each HMAC algorithm, and each other
  algorithm refuse with `Error::Algorithm`. Thus a token cannot make the verifier use a public key as an HMAC secret.
- The `kid` of the header selects among the keys of the profile only. A header with no `kid` selects the key of a
  profile with one key.
- A header that names a key URL or carries a key (`jku`, `jwk`, `x5u`, `x5c`, `x5t`, `x5t#S256`) refuses with
  `Error::Header`, and so does `crit`. A name with escapes, such as `\u006aku`, is the same name.

## Algorithms

| `Algorithm` | JOSE `alg` | Key in a key set | Use |
| --- | --- | --- | --- |
| `MlDsa65Ed25519` | `ML-DSA-65-Ed25519` (draft) | `AKP` with `alg` and `pub` | Sign and verify |
| `MlDsa65EcdsaP256` | `ML-DSA-65-ES256` (draft) | `AKP` with `alg` and `pub` | Sign and verify |
| `MlDsa65` | `ML-DSA-65` ([RFC 9964](https://www.rfc-editor.org/rfc/rfc9964)) | `AKP` with `alg` and `pub` | Sign and verify |
| `Ed25519` | `Ed25519` ([RFC 9864](https://www.rfc-editor.org/rfc/rfc9864)); verification also takes `EdDSA` | `OKP` with `crv` `Ed25519` | Sign and verify |
| `Es256` | `ES256` | `EC` with `crv` `P-256` | Sign and verify |
| `Rs256` | `RS256` | `RSA` | Verify only |
| `Ps256` | `PS256` | `RSA` | Verify only |

The composite names come from draft 06 of the [JOSE and COSE composite
draft](https://datatracker.ietf.org/doc/draft-ietf-jose-pq-composite-sigs/), each in one constant:
`jose::ML_DSA_65_ED25519` and `jose::ML_DSA_65_ES256`. IANA has not assigned them. An RSA key has a modulus of 2,048 to
4,096 bits and the exponent 65,537 ([Signature profiles](profiles.md)).

## Verify a token

1. Build the profile with `Profile::new(algorithm, kind, issuer, audience, limits)`. `kind` is `Kind::Jwt`, or
   `Kind::Access` for a JWT access token. `limits` bound the signature checks of each token.
2. Give it keys: `with_key(kid, trusted_key)` for a key that you hold, or `with_key_set(jwks)` for the JWK set
   ([RFC 7517](https://www.rfc-editor.org/rfc/rfc7517)) of the issuer. A key set gives each key whose type fits the
   algorithm. A key whose `alg` names another algorithm, or whose `use` is not `sig`, does not join. A key with a
   private member refuses the set with `Error::Key`. A profile has at most `KEYS_MAX` (16) keys.
3. Call `profile.verify(token)` for a JWS, or `profile.verify_jwt(token, now)` for a JWT. `now` is the time reading
   with its uncertainty bound.

`verify_jwt` checks the claims after the signature:

- `iss` is the issuer of the profile, and `aud`, one string or an array, names its audience.
- `exp` is after the latest time of the reading, and `nbf`, if present, is at or before the earliest time. Each time
  is a whole number of seconds since the Unix epoch.
- For `Kind::Access`, `typ` is `at+jwt` (also `application/at+jwt`, in any case), and the claims hold `sub`,
  `client_id`, `iat`, and `jti`.

`jwt.claims()` gives the registered claims: `iss`, `sub`, `aud`, `exp`, `nbf`, `iat`, `jti`, `client_id`, and `scope`.
Read each other claim from `jwt.jws().payload()`.

This example is also the example of the `rsauthnz::jose` module documentation, and `cargo xtask test` runs it:

```rust
use rsauthnz::crypto::Algorithm;
use rsauthnz::jose::{Error, Kind, Profile};
use rsauthnz::limits::Limits;

// The Ed25519 key and the JWS of RFC 8037, appendix A.
let set = br#"{"keys":[{"kty":"OKP","crv":"Ed25519","x":"11qYAYKxCrfVS_7TyWQHOg7hcvPapiMlrwIaaPcHURo"}]}"#;
let profile = Profile::new(Algorithm::Ed25519, Kind::Jwt, "https://issuer.example", "https://api.example", Limits::default())?
    .with_key_set(set)?;
let token = "eyJhbGciOiJFZERTQSJ9.RXhhbXBsZSBvZiBFZDI1NTE5IHNpZ25pbmc.hgyY0il_MGCjP0JzlnLWG1PPOt7-09PGcvMg3AIbQR6dWbhijcNR4ki4iylGjg5BhVsPt9g7sVvpAr_MuM0KAg";
assert_eq!(profile.verify(token)?.payload(), b"Example of Ed25519 signing");

// The header `{"alg":"none"}` refuses: the profile fixes the algorithm.
let forged = token.replacen("eyJhbGciOiJFZERTQSJ9", "eyJhbGciOiJub25lIn0", 1);
assert_eq!(profile.verify(&forged).err(), Some(Error::Algorithm));
```

## Sign a token

1. Write the payload: the JSON of the claims.
2. Call `jose::signing_input(algorithm, kid, typ, payload)`. It gives `BASE64URL(header) '.' BASE64URL(payload)`,
   with the header `{"alg":…,"kid":…,"typ":…}`.
3. Sign the bytes of the signing input with the key of the algorithm, such as in custody ([Hold keys in
   custody](custody.md)).
4. Call `jose::compact(&input, &signature)` for the token.

## Errors

Each `jose::Error` is a small `Copy` value with no part of the token. For each one, refuse the token.

| `Error` | Cause |
| --- | --- |
| `Malformed` | The token is not in the compact serialization, or a part is not JSON or base64url |
| `Limit` | The token has more than `TOKEN_BYTES_MAX` (16 KiB) bytes, a key set passes a bound, or the signature checks pass the limits |
| `Algorithm` | `alg` does not name the algorithm of the profile, or the algorithm has no JOSE name |
| `Header` | The header names a key URL, carries a key, or has `crit` |
| `Key` | No key of the profile fits the header, or a key of the set is not valid or has a private member |
| `Signature` | The signature does not verify |
| `Type` | `typ` is not `at+jwt` for `Kind::Access` |
| `Issuer` | `iss` is not the issuer of the profile |
| `Audience` | `aud` does not name the audience of the profile |
| `Expired` | `exp` can be at or before the reading |
| `NotYet` | `nbf` can be after the reading |
| `Claims` | A required claim is missing, or a claim has another type |
| `Time` | The reading has no bound |

The cost class of `verify` and `verify_jwt` is `Verify`: the header checks, then one signature check. The cost class
of `with_key_set` is `Verify`, and of `signing_input` and `compact` is `Parse` ([Admit rsauthnz work](admission.md)).

## Support

The JWS cases of RFC 7515 (RS256 and ES256) and RFC 8037 (Ed25519) and the key set of RFC 7517 pass on this Mac.
PS256, ML-DSA-65, and composite ML-DSA-65 + Ed25519 tokens that rscrypto signs pass too: no RFC has a PS256 JWS, and
no published JOSE case has an ML-DSA key yet.
