# Passkey test data

`vectors.rs` holds eight registration cases of
[Web Authentication Level 3](https://www.w3.org/TR/webauthn-3/), section 16 (Test Vectors), in the W3C
Recommendation of 25 August 2026.

- Source: `https://www.w3.org/TR/webauthn-3/`, read on 2026-11-20. Each case is the `challenge`,
  `credential_id`, `clientDataJSON`, and `attestationObject` of the registration part of its section, with no change.
  The SHA-256 of the 32 values in the order of the file is
  `417e20bf94a7f4a03f1a3bc636a917d2971e1fb4abe463aaa892126f83614eea`.
- The relying party ID of each case is `example.org`, and its origin is `https://example.org`.
- `src/passkey/tests.rs` holds the authentication part of `packed-es256`, `packed-eddsa`, and `packed-rs256`
  (`authenticatorData`, `clientDataJSON`, and `signature`), with the `COSE_Key` of the authenticator data of the
  registration of each case, from the same source with no change.
- W3C documents are subject to the W3C Document License. The file holds test data only.

No published case has an ML-DSA credential (w3c/webauthn issue 2393 is open on 2026-11-20). Thus the ML-DSA cases come
from `authenticator.rs`, which makes the keys and the responses with rscrypto.
