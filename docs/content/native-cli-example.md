# Run the native CLI example

The native CLI example is a program that runs the journey of a headless CLI on a [local authority](local-authority.md).
The local owner opens the authority and issues a one-use bootstrap value. The CLI enrolls its key in
[custody](custody.md), and submits the value with its public key. Then the CLI is the first administrator, with a CLI
credential. Each later call proves the possession of the key ([CLI credential](cli.md)). The example also shows two
failures and its cleanup.

The example is the workspace member `examples/native-cli`, in one file: `src/main.rs`. It uses only public items:
`rsauthnz`, the memory binding and the effect executor of `rsauthnz-conformance`, and the random generator of
`rscrypto`. It builds no claims and no transitions by hand.

## Run the example

You need a checkout of the repository and the toolchain that `rust-toolchain.toml` pins. The example needs the
feature `native-custody`, on Linux, macOS, or Windows. Run it from the root of the repository:

```sh
cargo run --locked -p native-cli --features native-custody
```

The program prints each step and exits with status 0:

```text
The store is the memory binding: a restart of this process loses each record.
1. The local owner opened the authority acme:auth for the origin acme:build-app.
2. The owner issued a one-use bootstrap value for acme:alice. It is valid for 15 minutes.
3. The CLI enrolled its key in custody. A key file of the OS user account that runs the process. Only that account can read it.
4. The authority bound acme:alice as the first administrator, with a CLI credential of 5508 bytes.
5. A second bootstrap with the same value refused: the authority holds no valid bootstrap value of this text.
6. Call 1 (status) proved the possession of the CLI key. The authority admitted it for acme:alice.
7. A replay of the proof of call 1 refused: the binding holds no pending challenge of the call.
8. Call 2 (deploy) used the challenge that call 1 gave, and the authority admitted it.
9. The CLI and the authority deleted their keys, and the example removed its key directory.
```

Without the feature, Cargo refuses the run and names the feature that the program needs. If a step fails, the program
stops, removes its key directory, and exits with status 1 and the error.

## The steps

| Step | Side | Operations | Guide |
| --- | --- | --- | --- |
| 1 | Local owner | `FileCustody::open`, `custody.enroll` for the issuer key, `Authority::open` with a `HostGrant` | [Open a local authority](local-authority.md#bootstrap-the-first-administrator) |
| 2 | Local owner | `authority.issue`, then the commit. The receipt gives the text of the value | [Open a local authority](local-authority.md#bootstrap-the-first-administrator) |
| 3 | CLI | `custody.enroll` for the CLI key, before the CLI submits the value | [Enroll the CLI](cli.md#enroll-the-cli) |
| 4 | Authority | `Bootstrap::parse`, `authority.bootstrap`, `custody.sign` with the issuer key, `pending.finish`, then the commit. The receipt gives the CLI credential | [Enroll the CLI](cli.md#enroll-the-cli) |
| 5 | Authority | `authority.bootstrap` with the same value refuses with `local::Error::Unknown` | [Errors](local-authority.md#errors) |
| 6 | Both | `authority.challenge`, `Call::new`, `cli::prove`, `authority.admit`, the commit, `admission.release` | [Make a call](cli.md#make-a-call) |
| 7 | Authority | `authority.admit` with the proof of call 1 refuses with `local::Error::Challenge` | [Errors](cli.md#errors) |
| 8 | Both | `Call::new` with `admitted.next()`, with no new issue | [Make a call](cli.md#make-a-call) |
| 9 | Both | `custody.delete` for each key, then the removal of the key directory | [Custody](custody.md) |

The text of the bootstrap value is a secret. The example does not print it.

## The two failures

- **A second bootstrap with the same value.** The first bootstrap consumed the value, so the authority holds no valid
  record of it. The refusal is `local::Error::Unknown`. The recovery is a new value from the local owner.
- **A replay of a proof.** The commit of call 1 consumed its challenge and wrote the challenge of the next call. Thus
  the proof of call 1 refuses with `local::Error::Challenge`. A refused replay does not change the pending challenge,
  so call 2 still uses the challenge that call 1 gave.

The example matches each refusal by its error. If an operation does not refuse with that error, the program fails.

## Cleanup

The example makes a new directory `rsauthnz-native-cli-<process ID>` under the temporary directory of the system. Its
two key files are there. At the end, the CLI and the authority delete their keys with `custody.delete`, and the
example removes the empty directory. After a failure, the example removes the directory and each key file in it.

## Test the example

The test runs the same journey, and passes only if each step completes, each failure refuses with its error, and the
directory is gone:

```sh
cargo xtask test -p native-cli
```

One test passes: `tests::the_journey_refuses_a_second_bootstrap_and_a_replay_and_leaves_no_key_file`.

## Limits of the example

- The store is the [memory binding](memory-binding.md). It keeps each record in the memory of the process, so a
  restart loses the authority, the administrator binding, and each challenge. A host uses a
  [storage binding](storage-binding.md) of its own store.
- One process is the local owner, the authority, and the CLI. In a host, the CLI and the authority are two processes,
  and the CLI sends its public key, its credential, its proofs, and its calls to the authority.
- The issuer key and the CLI key are in one `FileCustody`. A host keeps the issuer key in the custody of the authority,
  and the CLI keeps its key in its own custody ([Select the custody of the CLI key](cli.md#select-the-custody-of-the-cli-key)).
- The program takes the seed of its random generator (`rscrypto::ChaCha20Rng`) from the entropy source of the OS,
  through `ChaCha20Rng::try_generate_with` and `std::random::SystemRng`. `SystemRng` is unstable, so the program
  needs a nightly toolchain and `#![feature(random)]`. The test gives the journey a fixed seed.
- The example reads the system clock once, and gives the reading a bound of one second. A host reads its clock for
  each request, with the bound of its time source.

## Support

| Target | Result |
| --- | --- |
| macOS aarch64 | The example and its test pass |
| Linux x86_64 and aarch64, glibc and musl | The runs are pending |
| Windows x86_64 | The run is pending |
