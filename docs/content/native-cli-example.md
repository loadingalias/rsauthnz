# Run the native CLI example

The native CLI can ask a person to approve its key in a browser. It then signs a `status` call for that account.
It also runs a headless bootstrap for the first administrator.

## Connect a CLI to your account

Use the pinned Rust toolchain. Start the web example and create a passkey for your account. [Run the web example](web-example.md#run-the-example).

1. Open a second terminal at the repository root. Use a new directory outside the checkout for the CLI key.

   ```sh
   cargo run --locked -p native-cli --features native-custody -- enroll "$HOME/.rsauthnz-laptop-cli" "Laptop"
   ```

2. Open the local address printed by the CLI. Enter the **User code** and select **Review request**.
3. Sign in if the page asks. Check the account and device name. Compare the fingerprint with your terminal.
4. Select **Approve this CLI**. The terminal prints the approving account, then `Status admitted for` and its account ID.
5. Use the same directory for later calls.

   ```sh
   cargo run --locked -p native-cli --features native-custody -- status "$HOME/.rsauthnz-laptop-cli"
   ```

The user code expires after ten minutes. While the request waits, the CLI polls every five seconds.
The default loopback port is 8080. To use another port, give it after the device name. The CLI saves the port with the binding.

The directory holds the private key, the binding, and the signed credential. Keep it for later calls.
Before sending the finish, the CLI saves the account ID and credential serial. If the response is lost, the CLI looks up the credential.
Run `status` after an interruption. Account recovery or a server restart ends the binding. Enroll again in a new directory.
[CLI enrollment and recovery](cli.md#enroll-the-cli-from-a-browser).

## Run the headless example

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

## Headless bootstrap steps

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

## Headless cleanup

The example makes a new directory `rsauthnz-native-cli-<process ID>` under the temporary directory of the system. Its
two key files are there. At the end, the CLI and the authority delete their keys with `custody.delete`, and the
example removes the empty directory. After a failure, the example removes the directory and each key file in it.
If that removal also fails, for example on a file system that became read-only, the error names the directory and
both causes. Then remove the directory by hand, because key files can remain in it. After a panic, the example
removes the directory with no further error.

## Test the example

Run both journeys.

```sh
cargo xtask test -p native-cli
```

The browser journey starts the native binary and the web application on loopback. It checks fresh verification, credential recovery, and a later signed call.
The headless journey checks the second bootstrap, the repeated proof, and key cleanup.

## Limits of the headless example

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
- The example reads the system clock once for its requests, and gives the reading a bound of one second. It reads
  the clock again for each commit with a deadline (`Effect::Clock`). A host reads its clock for each request, with the
  bound of its time source.

## Support

| Target | Result |
| --- | --- |
| macOS aarch64 | Browser-approved enrollment and signed status over HTTP/2. The headless bootstrap also passes. |
| Linux x86_64 and aarch64, glibc and musl | The runs are pending |
| Windows x86_64 | The run is pending |
