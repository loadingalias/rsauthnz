# Issue and verify credentials

`rsauthnz::credential` issues and verifies the credentials and receipts of rsauthnz. They have one format: a
`COSE_Sign1` ([RFC 9052](https://www.rfc-editor.org/rfc/rfc9052)) over CWT claims
([RFC 8392](https://www.rfc-editor.org/rfc/rfc8392)). A credential also has the proof-of-possession key of its
holder in a `cnf` claim ([RFC 8747](https://www.rfc-editor.org/rfc/rfc8747)). The issuer key stays in custody.
rsauthnz gives the bytes to sign, and it checks the signature before it gives the artifact.

## The artifacts

One format serves five kinds of artifact. The purpose claim names the kind, and the signature covers it. Thus one
issuer key can sign each kind, and an artifact of one purpose does not verify for another purpose.

| Artifact | `cnf` key | Subject |
| --- | --- | --- |
| Workload credential | The key of the workload | `Subject::Workload` |
| Agent credential | The key of the agent | `Subject::Agent`, with its human owner |
| CLI enrollment credential | The key of the CLI | `Subject::Human` |
| Enrollment receipt | None | The principal that enrolled |
| Approval receipt | None | The principal that approved |

The application chooses the purpose of each kind, as an `Id<Purpose>`, except for a workload credential. The
`rsauthnz::workload` module issues each workload credential with the purpose `rsauthnz:workload`, through its
transition ([Issue and manage workload credentials](workload.md)). A receipt has no `cnf` key, so it cannot prove
possession.

## Declare the profile of an audience

The algorithm of the issuer key is the profile that an audience declares. The issuer signs each artifact for the
audience with that key, and the `Profile` of the audience holds that key. An artifact of another algorithm refuses
with `Error::Cose(cose::Error::AlgorithmMismatch)`. rsauthnz tries no other key and no other algorithm.

Each artifact names its issuer key with the `kid` of its protected bucket. The `kid` is the COSE Key Thumbprint of
the key ([RFC 9679](https://www.rfc-editor.org/rfc/rfc9679)), with SHA-256: `TrustedKey::kid()`. During a rotation
of the issuer key, `profile.with_previous(previous_key, until)` adds the key that the current key replaced. `until` is
the time from which no artifact of the previous key is valid. The `kid` selects one of the two keys, and the
signature check uses only that key. A check whose reading can be at or after `until` refuses an artifact of the
previous key with `cose::Error::KeyId`. Thus a retired key that leaks later signs nothing that verifies.
`with_previous` refuses a key of another algorithm with `Error::Profile`, so a header never selects an algorithm.

| Issuer key `Algorithm` | Authentication | `cnf` key `Algorithm` | Use |
| --- | --- | --- | --- |
| `MlDsa65Ed25519` (the default) or `MlDsa65EcdsaP256` (the hardware-bound profile) | `Hybrid` | `MlDsa65Ed25519` or `MlDsa65EcdsaP256` | Each audience, unless it declares another profile |
| `MlDsa65` | `PostQuantum` | `MlDsa65` | An audience that supports ML-DSA-65 but not the composite |
| `Ed25519` or `Es256` | `Classical` | `Ed25519` or `Es256` | An audience that supports nothing else |

The `cnf` key has the authentication of the issuer key, so a proof of possession has the same guarantee as the
credential. A `cnf` key of another authentication refuses with `Error::Profile`, at issuance and at verification.

A classical profile is an explicit choice. rsauthnz never selects it for you, and it reports `Classical`, never
post-quantum. A quantum computer that can break Ed25519 or P-256 can forge its signatures. Use it only for an
audience that cannot verify ML-DSA-65. [Signature profiles](profiles.md) gives the guarantee and the cost of each
profile.

The SLH-DSA trust-root profile signs issuer keys, not artifacts of this format. This format refuses it with
`Error::Profile`.

## The format

The artifact is a `COSE_Sign1` with the tag 18:

- The protected bucket holds `alg` (1) and `kid` (4). `alg` is the COSE identifier of the issuer key: -59 for
  `MlDsa65Ed25519`, -55 for `MlDsa65EcdsaP256`, -49 for `MlDsa65`, -19 for `Ed25519`, or -7 for `Es256`. The two
  composite identifiers are drafts. `kid` is the 32-byte COSE Key Thumbprint of the issuer key. A proof has only
  `alg`.
- The unprotected bucket is empty.
- The payload is the claims map, in the deterministic CBOR of [Parser limits](parser-limits.md).
- The signature covers the `Sig_structure` of RFC 9052, section 4.4, with an empty external AAD. ML-DSA-65 and the
  composites sign it with the empty context.

The claims map holds these claims, and no others:

| Key | Claim | `Claims` field | Value |
| --- | --- | --- | --- |
| 1 | `iss` | `issuer` | The text `namespace:value` of an `Id<Authority>` |
| 3 | `aud` | `audience` | The text `namespace:value` of an `Id<Audience>` |
| 4 | `exp` | `expires` | Whole seconds since the Unix epoch. The artifact is not valid at this time and after it |
| 5 | `nbf` | `not_before` | Whole seconds since the Unix epoch. Only when `not_before` is set |
| 6 | `iat` | (`Verified::issued()`) | The whole seconds of the reading at issuance |
| 7 | `cti` | `serial` | The `Serial`: 8 bytes, with the most significant byte first |
| 8 | `cnf` | (the key of `Verified::possession`) | A `COSE_Key` member (1) with its `alg`: an `AKP` key (`kty` 7) with `pub` for ML-DSA-65 and the composites, an `OKP` key (`kty` 1) with `crv` 6 and `x` for Ed25519, or an `EC2` key (`kty` 2) with `crv` 1, `x`, and `y` for ES256. Only in a credential |
| -65537 | Subject | `subject` | The CBOR form of a `Principal`: `[kind, namespace, value]` |
| -65538 | Owner | `subject` | The CBOR form of the `Id<Human>` that owns an agent. Only when the subject is an agent |
| -65539 | Purpose | `purpose` | The CBOR form of an `Id<Purpose>` |

The subject, owner, and purpose keys are in the private-use range of RFC 8392: less than -65536.
[Vocabulary](vocabulary.md) gives the CBOR forms and the text form of an identifier. Take each serial from a
counter of the store (`store::driver::Driver::allocate`), so that a restore never gives one serial twice.

## Sizes

An encoded artifact or proof has at most `credential::MAX_BYTES`: 8,192 bytes. A draft that can be longer refuses
with `Error::Size` before custody signs it. Verification refuses a longer input before it decodes it.

The example credential below is 5,517 bytes. The default profile signs it, and its `cnf` key is a default key:

| Part | Bytes |
| --- | --- |
| The tag, the array head, and the empty unprotected bucket | 3 |
| The protected bucket, with its head: `alg` and the `kid` of 32 bytes | 41 |
| The claims, with their head | 2,097 |
| Of the claims: the `cnf` claim | 1,997 |
| Of the `cnf` claim: the public key of the holder | 1,984 |
| The signature, with its head | 3,376 |
| Total | 5,517 |

The composite signature and the composite key of the holder make up 5,357 bytes of the total. A credential of the
hardware-bound profile is at most 41 bytes longer: its key has 2,017 bytes, and its signature has at most 3,381
bytes. A credential of `MlDsa65`, `Ed25519`, or `Es256` is shorter than the example, because its key and its
signature are shorter. Longer identifiers make the claims longer. The example is 2,675 bytes below the limit.

A proof of possession of the example credential, with a challenge of 32 bytes, is 3,487 bytes. The holder sends one
proof for each check of possession.

## Issue a credential

1. Make the claims with `Claims::new(issuer, audience, subject, purpose, serial, expires)`. Set `not_before`
   after this call, if the credential has a start.
2. Call `Draft::credential(&issuer_key, &claims, Some(holder_public_key), now)`. Give `None` in place of the
   holder key for a receipt. `issuer_key` is the `cose::TrustedKey` of the issuer key in custody.
3. Give the bytes of `draft.to_be_signed()` to custody. Custody signs them with the issuer key.
4. Add the issuance record of the draft to the proposal of the transition that issues the credential:
   `draft.record(&mut proposal)`. It reads the absence of `credential::record_key(serial)` and writes the record:
   `["rsauthnz.credential.record.1", issuer, subject, audience, purpose, expires]`, at the version of the issuer and
   the serial, with the end of the artifact as its store end. The record holds no signature.
5. Call `draft.finish(&signature, &mut budget)`. It verifies the signature with the issuer key, and then gives the
   artifact as a `transition::Prepared` value. That value has no accessor of its bytes.
6. Give the value to `proposal.prepare(prepared)?`, and submit the proposal to the driver
   ([Make a transition](transitions.md)). Only the receipt of the accepted commit gives the bytes:
   `receipt.artifact()`. After a lost response, look up the outcome. The receipt of a lookup has no bytes.

`prepare` refuses with `transition::Error::Prepared` when the proposal does not write the issuance record of the
artifact, or already has an artifact. Thus one serial gives one artifact, and an artifact commits only with its own
issuance.

Thus a credential gives no authority before its commit. `finish` refuses a signature that does not verify, for
example a signature by another custody key. A refusal gives no artifact. It consumes the draft, so one draft gives at most one artifact. The issue time `iat` is the whole
seconds of `now.estimate()`. Issuance rounds `expires` down and `not_before` up to whole seconds, so the artifact
is never valid outside the interval that you gave.

Run the signature of custody in the `External` cost class of [Admit rsauthnz work](admission.md), apart from the
`Verify` work of `finish`.

This example issues a workload credential, verifies it, and checks a proof of possession. rscrypto signs in place
of custody. `issue` stands for the commit of the issuance transition: it writes the issuance record of the draft,
finishes the draft with the signature, submits the proposal that carries the prepared artifact, and gives the bytes of
the receipt. The example is also the example of the
`rsauthnz::credential` module documentation, where `issue` commits on the memory binding, and `cargo xtask test`
runs it:

```rust
use core::time::Duration;
use rsauthnz::cose::{Key, PublicKey, TrustedKey};
use rsauthnz::credential::{Claims, Draft, Profile, ProofDraft, Serial, Subject};
use rsauthnz::crypto::Algorithm;
use rsauthnz::evidence::Method;
use rsauthnz::id::Id;
use rsauthnz::limits::{Limits, SignatureBudget};
use rsauthnz::time::{Reading, ReadingSource};
use rscrypto::auth::MlDsa65Ed25519;

fn trusted(public: PublicKey<'_>) -> Result<TrustedKey, rsauthnz::cose::Error> {
    TrustedKey::new(Algorithm::MlDsa65Ed25519, &Key { kid: None, alg: None, public })
}

// Custody holds the secret keys. Here rscrypto signs in place of custody. A fixed filler makes the keys
// reproducible. Use fresh randomness for real keys.
let (issuer_public, issuer_secret) = MlDsa65Ed25519::generate_keypair(|out| Ok(out.fill(1)))?;
let (holder_public, holder_secret) = MlDsa65Ed25519::generate_keypair(|out| Ok(out.fill(2)))?;
let (issuer_public, holder_public) = (issuer_public.to_bytes(), holder_public.to_bytes());
let issuer_key = trusted(PublicKey::MlDsa65Ed25519(&issuer_public))?;
let holder_key = trusted(PublicKey::MlDsa65Ed25519(&holder_public))?;
let now = Reading::new(Duration::from_secs(1_800_000_000), Some(Duration::from_secs(1)), ReadingSource::Caller);

// 1. The issuer makes a draft. Custody signs it, and `finish` verifies the signature before it gives the
// prepared artifact. The issuance transition writes the issuance record of the draft and carries the artifact,
// and only the receipt of its commit gives the bytes.
let claims = Claims::new(
    Id::new("acme", "authority")?,
    Id::new("acme", "build-api")?,
    Subject::Workload(Id::new("acme", "runner-7")?),
    Id::new("acme", "workload")?,
    Serial(1),
    Duration::from_secs(1_800_003_600),
);
let draft = Draft::credential(&issuer_key, &claims, Some(PublicKey::MlDsa65Ed25519(&holder_public)), now)?;
let signature = issuer_secret.sign_deterministic(&draft.to_be_signed(), &[])?;
let credential = issue(draft, signature.as_bytes(), now)?;

// 2. The verifier fixes the issuer, the audience, and the purpose, and verifies the credential.
let (issuer, audience, purpose) = (claims.issuer.clone(), claims.audience.clone(), claims.purpose.clone());
let profile = Profile::new(issuer_key, issuer, audience, purpose, Limits::default())?;
let verified = profile.verify(&credential, now, &mut SignatureBudget::new(&Limits::default()))?;
assert_eq!(verified.claims(), &claims);

// 3. The holder signs a proof over the challenge of the verifier, and the verifier checks it.
let challenge = [7; 32];
let draft = ProofDraft::new(&holder_key, &credential, &claims.audience, &challenge, now)?;
let signature = holder_secret.sign_deterministic(&draft.to_be_signed(), &[])?;
let proof = draft.finish(signature.as_bytes(), &mut SignatureBudget::new(&Limits::default()))?;
let evidence = verified.possession(&proof, &challenge, now, &mut SignatureBudget::new(&Limits::default()))?;
assert_eq!(evidence.method(), Method::KeyPossession);
```

## Verify a credential

`Profile::new(issuer_key, issuer, audience, purpose, limits)` makes the trusted profile. The application fixes
these facts before it reads an artifact. Then call `profile.verify(artifact, now, &mut budget)`. `now` is a
`time::Reading`, and `budget` is the signature budget of the artifact, as [Bound the signature
checks](verification.md#bound-the-signature-checks) gives.

`Profile::verify` does these checks, in this order. It refuses at the first check that fails:

1. The artifact has at most 8,192 bytes.
2. It does each check of `cose::Profile::verify`, as [Verify a CWT](verification.md#verify-a-cwt) gives. `iss`
   must be the text of the issuer, and `aud` must name the text of the audience. Before the signature check, the
   protected `kid` must name a key of the profile, or the artifact refuses with `cose::Error::KeyId`. The previous
   key counts only while `now.latest()` is before its end. The signature check of the named key comes last of these
   checks.
3. The claims must be the claims of this format: `iat`, `cti`, the subject, and the purpose. An agent must have
   its owner, and a human or a workload must have none. A claim of another key, or a `sub` claim, refuses.
4. The purpose must be the purpose of the profile.
5. A `cnf` key must have the authentication of the issuer key.

`Verified` is the evidence of the artifact:

| Method | Result |
| --- | --- |
| `artifact()` | The exact bytes of the artifact |
| `claims()` | The verified `Claims` |
| `issued()` | `iat` |
| `report()` | The `crypto::Report` of the profile of the issuer key. Its `authentication` is `Classical` for a classical credential |
| `possession(proof, challenge, now, &mut budget)` | The authentication evidence of a proof by the `cnf` key |

Two `Verified` values are equal only for equal artifact bytes and equal profiles. A valid signature does not give
current permission. Keep the evidence with the claims that a later authorization check reads.

## Prove possession

A credential is not a bearer token. Its holder proves possession of the `cnf` key for each check:

1. The verifier issues a challenge for one proof.
2. The holder calls `ProofDraft::new(&holder_key, &credential, &audience, &challenge, now)`. Custody signs
   `draft.to_be_signed()` with the `cnf` key, and `draft.finish(&signature, &mut budget)` gives the proof. A proof
   gives no authority, so `finish` gives its bytes at once.
3. The verifier calls `verified.possession(&proof, &challenge, now, &mut budget)`. Give a new budget for the
   proof, because it is a separate artifact.
4. The verifier consumes the challenge in the transition that uses the evidence.

The proof is a `COSE_Sign1` with the tag 18, signed by the `cnf` key. Its claims map holds `aud` (3), `iat` (6),
the SHA-256 digest of the exact bytes of the credential (-65540), and the challenge (-65541). `possession`
refuses a proof that does not bind this credential, the audience of the profile, and the challenge. It also
refuses a proof by another key, and a check outside the validity interval of the credential.

The evidence records the subject, the method `Method::KeyPossession`, the reading `now`, and the authentication of
the `cnf` key: `Hybrid`, `PostQuantum`, or `Classical`. It also keeps the credential: `evidence.artifact()` gives its
verified claims, with the issuer, the audience, the purpose, the serial, the end, and the owner of an agent, and the
SHA-256 digest of its bytes. `evidence.expires()` gives the end of the credential, and `authz::check` ends the checked
scope there ([Authorize an operation](authorization.md)). It records no user verification, no phishing resistance,
and no device or hardware binding, because the proof does not show them.
[Vocabulary](vocabulary.md#authentication-evidence) gives the evidence.

The challenge makes the proof fresh. For a CLI credential of a local authority, rsauthnz keeps a one-use challenge
for each binding, and the proof binds the request of the call in place of the challenge
([CLI credential](cli.md)). For each other credential, the application issues each challenge for one proof, and
it refuses a challenge that it consumed.

## Errors

Each refusal is a `credential::Error`. For a refused artifact or proof, refuse it. For a refused draft, correct the
claims or the key.

| Error | Cause |
| --- | --- |
| `Cose(cose::Error)` | The COSE layer refused: the decode, the issuer, the audience, the validity interval, a key, the `kid`, the signature, or the signature budget. [Verify COSE and CWT artifacts](verification.md#errors) gives each cause |
| `Profile` | A key is the SLH-DSA trust-root key, the `cnf` key has another authentication than the issuer key, or the previous key of `with_previous` has another algorithm than the current key |
| `Size` | The artifact or proof is longer than 8,192 bytes, or a draft can be longer |
| `Claims` | A claim is missing, has the wrong form, or is not a claim of this format |
| `Purpose` | The purpose of the artifact is not the purpose of the profile |
| `Validity` | The validity interval of a draft is empty: `expires` is not after `iat` and `not_before` |
| `NoConfirmation` | The artifact has no `cnf` key, so it cannot prove possession |
| `Proof` | The proof does not bind the credential, the audience, and the challenge, or it has another claim |

## Limits

- The composite COSE identifiers are drafts. Another implementation can use other values until IANA assigns them.
- A profile holds at most two issuer keys: the current key and the previous key.
- Verification decodes the artifact and the proof within the `limits` of the profile. The default limits admit
  each artifact and proof of this format.
