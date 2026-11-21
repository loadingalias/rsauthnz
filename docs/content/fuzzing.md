# Fuzz the parsers

The fuzz targets of rsauthnz give hostile bytes to each parser that reads untrusted input, with the production limits,
and check that each one refuses before expensive work. They live in `fuzz/`, a separate Cargo workspace with its own
lock file. libFuzzer holds C++, so it stays out of each library closure.

## The targets

| Target | Entry points | What the target checks |
| --- | --- | --- |
| `cbor` | `cbor::decode`, `cbor::decode_prefix` | An input over `Limits::bytes` refuses. Each item that decodes encodes to the same bytes again, because the decoder takes only the deterministic encoding |
| `cose` | `cose::Key::decode`, `cose::Sign1::decode` and `Sign1::verify`, `cose::Profile::verify` | A decode or a limit that refuses does no signature work. A signature check runs only for a `Sign1` that decodes |
| `credential` | `credential::Profile::verify` | An artifact over `credential::MAX_BYTES` refuses with `Error::Size`. A decode or a limit that refuses does no signature work |
| `passkey` | `passkey::Response::parse`, `RelyingParty::verify`, `passkey::Assertion::parse` | A response over 64 KiB refuses |
| `jose` | `jose::Profile::verify_jwt`, `jose::Profile::with_key_set` | A token over `jose::TOKEN_BYTES_MAX` refuses with `Error::Limit` |
| `x509` | `x509::Certificate::parse`, `Certificate::verify` | An input over `CERTIFICATE_BYTES_MAX` refuses with `Error::Bytes`. A signature check runs only for a certificate that parses |
| `session` | `session::Identifier::parse` | A cookie value of another length than `IDENTIFIER_CHARS` refuses |
| `bootstrap` | `local::Bootstrap::parse` | No input panics |

A signature check charges its `SignatureBudget` before its work ([Bound the signature
checks](verification.md#bound-the-signature-checks)). Thus a budget that still has each check shows that no signature
work ran, and the targets read it from outside the crate.

Each target also fails on a panic, on a report of AddressSanitizer, and on one allocation of more than 16 MB. The
JSON reader and base64url are rscodec's, and rscodec fuzzes them. The `passkey`, `jose`, and `session` targets give
their input to the core entry points that call them.

## Before you start

- The toolchain of `rust-toolchain.toml`, a nightly. cargo-fuzz needs one.
- cargo-fuzz 0.13.2. `machine update all` installs it.
- The host target. cargo-fuzz builds for the target of its own build, which can be another one, such as
  `x86_64-apple-darwin` on an aarch64 Mac. Give the host target to each command: `rustc -vV` names it as `host`.

## Run a target

1. Build the targets:

   ```sh
   cargo fuzz build --target aarch64-apple-darwin
   ```

2. Run one target for 3 minutes, from its seeds:

   ```sh
   cargo fuzz run --target aarch64-apple-darwin x509 fuzz/corpus/x509 fuzz/seeds/x509 -- \
     -max_total_time=180 -max_len=70000 -len_control=0 -malloc_limit_mb=16 -timeout=10
   ```

   libFuzzer writes the new inputs to the first directory, `fuzz/corpus/<target>`, which Git ignores. The seeds in
   `fuzz/seeds/<target>` stay as they are. `-max_len=70000` lets an input pass each byte limit, and
   `-len_control=0` gives the inputs that length from the start, so the over-limit paths run too. With no
   `-len_control=0`, libFuzzer grows the length slowly, and a short run never passes a limit of 64 KiB.

3. A run that ends at its time with no finding prints `Done` and its statistics. A finding stops the run, and
   libFuzzer writes its input to `fuzz/artifacts/<target>/`, which Git ignores. Run the target again with that file
   to reproduce it:

   ```sh
   cargo fuzz run --target aarch64-apple-darwin x509 fuzz/artifacts/x509/crash-<digest>
   ```

A finding is a defect of the parser that it names. Fix it in the parser, and add a regression test with the input in
the main workspace, next to the tests of that parser.

The build keeps the overflow checks and the debug assertions on, as each profile of the main workspace does.
`cargo xtask check` formats and lints the targets without the libFuzzer link, so it builds no C++, and an API change
cannot break a target with no notice. A campaign is a heavy check: run one only for a named risk, and with the
approval of the owner.

## The seeds

| Directory | Seeds |
| --- | --- |
| `cbor` | Small items: integers, an array, a map, a tag, floats, strings, and nested arrays. Also the credential and the COSE key of `cose` |
| `cose`, `credential` | A credential of the credential format, from `credential::Draft` and its commit, and a `COSE_Key`. The Ed25519 key of the secret `[1; 32]` signed the credential; `fuzz/src/lib.rs` holds its public key |
| `jose` | A JWT from `jose::signing_input` and `jose::compact`, signed by the same key, and a JWK set of the key |
| `passkey` | The registration of the ES256 case of WebAuthn Level 3, section 16.2, and an assertion of the same credential |
| `x509` | The five certificates of `tests/x509/`, and the two composite certificates of the LAMPS draft |
| `session`, `bootstrap` | One identifier and one bootstrap value in their forms |

## Campaign record

The named risk is a hostile input that allocates or runs signature work before it refuses. The budget is 3 minutes for
each target, and a campaign stops at the end of the budget or at the first finding.

The campaign of 2026-11-21 ran each target for its budget on this Mac (macOS aarch64), with AddressSanitizer, on
rsauthnz `4680393` and the targets of this page. It ran the command of [Run a target](#run-a-target) with no
`-len_control=0`. No target found a crash, a leak, an assertion failure, or an allocation of more than 16 MB:

| Target | Runs | Coverage | Longest input |
| --- | --- | --- | --- |
| `cbor` | 2,500,156 | 383 | 15,423 bytes |
| `cose` | 1,851,739 | 899 | 12,407 bytes |
| `credential` | 1,354,316 | 991 | 7,379 bytes |
| `passkey` | 2,740,443 | 3,603 | 3,831 bytes |
| `jose` | 2,894,527 | 2,961 | 5,818 bytes |
| `x509` | 2,282,633 | 2,224 | 30,637 bytes |
| `session` | 3,747,303 | 65 | 37,405 bytes |
| `bootstrap` | 4,079,416 | 59 | 40,611 bytes |

The longest input is the length limit that libFuzzer reached. Only `x509`, `session`, and `bootstrap` passed their
byte limits. Thus the over-limit refusals of `cbor`, `cose`, `credential`, `passkey`, and `jose` did not run in this
campaign, and the next campaign adds `-len_control=0`.
