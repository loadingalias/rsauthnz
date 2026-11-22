# Run the core in a browser Worker and on mobile

`rsauthnz` builds for `wasm32-unknown-unknown` with its default features, and the same production code runs in a
dedicated browser Worker. It also compiles for `aarch64-apple-ios` and `aarch64-linux-android`. The core needs no
runtime, filesystem, socket, thread, or shared memory: the host supplies each input.

## What the host supplies

| Input | What the core takes | In a browser Worker |
| --- | --- | --- |
| Entropy | A `rscrypto::ChaCha20Rng` from a seed of 32 bytes | `crypto.getRandomValues` |
| Time | A `time::Reading`: the time since the Unix epoch, and the bound of its error | `Date.now()`, with a bound that the application declares |
| Policy | An implementation of `authz::Policy` ([Authorize an operation](authorization.md)) | The policy of the application |
| Storage | A storage binding ([Write a storage binding](storage-binding.md)) | The memory binding of `rsauthnz-conformance` keeps its state in the Worker, and the state ends with the Worker ([Test with the memory binding](memory-binding.md)). Persistent browser storage belongs to the application |
| Custody | The keys that sign | The application holds them: no custody of the library builds for these targets ([Hold keys in custody](custody.md)) |
| Execution | Each operation that reads the store is a future | Poll it with the executor of the host. A future of the memory binding is ready at its first poll |

## Build the module

1. Add the target to the pinned toolchain: `rustup target add wasm32-unknown-unknown`. `machine update all` adds it,
   and also `aarch64-apple-ios` and `aarch64-linux-android`.
2. Depend on `rsauthnz` with its default features. The feature `native-custody` has no effect on these targets.
3. Build the module of the application as a `cdylib` for the target only:

   ```sh
   cargo rustc --locked --release --lib --target wasm32-unknown-unknown --crate-type cdylib
   ```

   A `cdylib` in the manifest also builds for each other target, and a target such as `x86_64-unknown-linux-musl`
   drops it with a warning.

The module of `xtask/portable` has no import, so the Worker instantiates it with an empty import object. Its exports
take and give only integers. The Worker gives the seed as four 64-bit words and the time in milliseconds, and reads
the result from the memory of the module:

```rust
/// The report of the last [`rsauthnz_portable_run`], which [`rsauthnz_portable_report`] gives to the host.
static REPORT: Mutex<String> = Mutex::new(String::new());

/// Runs [`report`] with the seed of the four words `a` to `d`, in little-endian order, and the time `now_ms` in
/// milliseconds since the Unix epoch. It keeps the report and gives its length in bytes. A browser Worker calls it with
/// `crypto.getRandomValues` and `Date.now()`.
#[expect(
    unsafe_code,
    reason = "a WebAssembly export needs an unmangled symbol; the function takes and gives only integers"
)]
#[unsafe(no_mangle)]
pub extern "C" fn rsauthnz_portable_run(a: u64, b: u64, c: u64, d: u64, now_ms: u64) -> usize {
    let mut seed = [0; 32];
    for (bytes, word) in seed.as_chunks_mut::<8>().0.iter_mut().zip([a, b, c, d]) {
        *bytes = word.to_le_bytes();
    }
    let text = report(seed, Duration::from_millis(now_ms));
    let mut kept = REPORT.lock().unwrap_or_else(PoisonError::into_inner);
    *kept = text;
    kept.len()
}

/// The address of the UTF-8 bytes of the report of the last [`rsauthnz_portable_run`]. They stay until the next run.
#[expect(
    unsafe_code,
    reason = "a WebAssembly export needs an unmangled symbol; the function gives only an address"
)]
#[unsafe(no_mangle)]
pub extern "C" fn rsauthnz_portable_report() -> *const u8 {
    REPORT.lock().unwrap_or_else(PoisonError::into_inner).as_ptr()
}
```

```js
// The dedicated Worker of `cargo xtask portable`. It instantiates the module with no imports, gives it a seed from
// `crypto.getRandomValues` and the time of `Date.now()`, and posts its report to the page. A trap posts its error.
(async () => {
  try {
    const bytes = await (await fetch('portable.wasm')).arrayBuffer();
    const { instance } = await WebAssembly.instantiate(bytes, {});
    const { memory, rsauthnz_portable_run: run, rsauthnz_portable_report: report } = instance.exports;
    const seed = crypto.getRandomValues(new BigUint64Array(4));
    const length = run(seed[0], seed[1], seed[2], seed[3], BigInt(Date.now()));
    postMessage(new TextDecoder().decode(new Uint8Array(memory.buffer, report(), length)));
  } catch (error) {
    postMessage('trap: ' + error + '\n');
  }
})();
```

## Check the portable core

`cargo xtask portable` runs each check of the portable core on this Mac (macOS aarch64). CI builds no wasm32 or
mobile target, so the command is the gate of each task that changes the portable closure.

Before the first run:

1. Install Chrome and Firefox in `/Applications`. The command starts them headless with a temporary profile, with no
   driver.
2. Run `sudo safaridriver --enable` once. Safari has no headless mode, so the command opens one session of the system
   `safaridriver`, and Safari shows one automation window.
3. Give the pinned toolchain the targets `wasm32-unknown-unknown`, `aarch64-apple-ios`, and `aarch64-linux-android`.

The command:

1. Builds `xtask/portable` for `wasm32-unknown-unknown`, and checks the module: no import, no shared memory, and only
   the exports `memory`, `rsauthnz_portable_report`, and `rsauthnz_portable_run`.
2. Checks the closure on `wasm32-unknown-unknown`: exactly the crates of the table below, and no `native-custody`.
3. Runs the native test of the consumer, and builds it for `aarch64-apple-ios` and `aarch64-linux-android`.
4. Serves the page, the Worker, and the module on a loopback port, and opens the page in Chrome, Firefox, and Safari.
   The page starts one dedicated Worker, which posts its report. The command compares the report of each browser
   with `xtask/portable/report.txt`.

A run prints each step with its time, the version of each browser, and its user agent. A browser cell passes only on
a report that equals the expected text: a build alone passes no cell. A failed cell prints each line that differs, and
the command fails. A trap in the Worker gives `trap: <error>` as the report. A browser that gives no report in 180
seconds fails its cell. The command stops each browser and `safaridriver`, and deletes each temporary profile.

## The cases

Each case uses the public API, and the native test and each browser give the same line. The cases do not depend on
the seed or the time of the host.

| Case | Expected result |
| --- | --- |
| `cbor rfc8949 appendix-a deterministic` | 64 vectors |
| `cbor rfc8949 appendix-a other encodings` | 17 vectors refuse |
| `cbor limits` | 8 limits |
| `cose rfc9052 c.2.1` | verifies, and a changed payload refuses |
| `cwt rfc8392 a.3` | verifies with the claims of A.1 |
| `credential issue, verify, and possession` | ML-DSA-65 + Ed25519 |
| `credential refusals` | a changed byte and another audience refuse |
| `authz permit and refusals` | 6 refusals and one permit |
| `transition refusals` | a change with no read and a read past the limit refuse |
| `conformance memory binding` | 22 cases pass |
| `conformance lost outcome reads` | fails LostResponse |
| `conformance no instance check` | fails Fencing |

The conformance suite runs on the memory binding. The two defects are the positive control of the suite in the
browser: a wrapper of the memory binding gives no outcome record, or gives each commit the instance number of its last
start, and each one must fail the case that names its defect. The nine broken bindings of the memory binding change
its private state, so they run only in the native tests ([Run the conformance suite](conformance.md)).

## The closure

On `wasm32-unknown-unknown`, the consumer has exactly these crates. The core has no feature.

| Crate | Features |
| --- | --- |
| `rsauthnz` | None: no `native-custody` |
| `rsauthnz-conformance` | None |
| `rsauthnz-portable` | None |
| `rscodec` | `base64`, `hex`, `json`, `std` |
| `rscrypto` | `alloc`, `blake3`, `chacha20-rng`, `ecdsa-p256`, `ed25519`, `hmac`, `ml-dsa`, `mldsa65-ecdsa-p256`, `mldsa65-ed25519`, `rapidhash`, `rsa`, `sha2`, `sha3`, `slh-dsa` |
| `rstypes` | None |

## Support

| Target | Evidence |
| --- | --- |
| `wasm32-unknown-unknown` in a dedicated Worker | The report of each case passes in Chrome 158.0.8127.37, Firefox 160.0.1, and Safari 27.2, on macOS 27.2.1 aarch64 |
| `aarch64-apple-ios`, `aarch64-linux-android` | The consumer compiles as an rlib. No device run, custody, or mobile binding is claimed |

The browser runs establish the behavior of the core, not persistent browser custody or storage, and not a real
authenticator. No WASI target, no thread, and no shared WebAssembly memory is claimed. The cases cover the A0 core:
codecs, credentials, evidence, policy, transitions, and the memory binding. The local authority, trust snapshots, and
grant checks join the cases with their stages.
