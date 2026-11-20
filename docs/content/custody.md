# Hold keys in custody

`rsauthnz::custody` holds the secret keys of the application. The application keeps a handle, which holds no secret.
A custody signs with the key of the handle and gives only the signature. Thus no key enters application state,
logs, prompts, or tool output.

A handle is not a permission. The authority of a key comes from the authority that enrolls its public key.

## The model

- A **handle** (`Handle`) names one key: its key ID, its algorithm, and its public key. The application stores
  these three parts, and `Handle::new` makes the handle again after a restart.
- A **custody** (`Custody`) holds the secret keys. Its operations are `enroll`, `rotate`, `sign`, and `delete`.
  `Handle::verify` checks a signature with the public key of the handle.
- A **report** (`Report`) states the guarantees of a custody: the owner of the key, the lifetime of the plaintext
  key, the zeroization, the recovery path, and the isolation that the OS enforces.
- The **isolation** (`Isolation`) is `User` or `Process`. `User` keeps the key from other OS accounts. `Process`
  also keeps it from a hostile process of the same account. A custody refuses a caller that requires more than it
  gives.

A custody holds composite keys only: `MlDsa65Ed25519`, the default profile, and `MlDsa65EcdsaP256`. [Signature
profiles](profiles.md) gives the profiles. Each random value comes from the seeded `rscrypto::ChaCha20Rng` of the
caller: the key ID, each key, and the randomness of each signature. The signing is hedged: rscrypto takes fresh
randomness from the generator for each signature.

## Use the file custody

`FileCustody` is the software custody. It keeps each key in a key file under OS file permissions. It needs the
feature `native-custody`:

```toml
[dependencies]
rsauthnz = { git = "https://github.com/loadingalias/rsauthnz", branch = "main", features = ["native-custody"] }
```

The feature has an effect on Linux, macOS, and Windows only. A build for another target, such as WebAssembly, iOS,
or Android, has no `FileCustody`.

1. Select a directory for the key files. Give it to `FileCustody::open` with the isolation that you require. The
   library reads no environment variable and has no default directory.
2. Draw a key ID with `KeyId::random`, and record it before you enroll the key.
3. Enroll the key. Store the ID, the algorithm, and the public key of the handle.
4. Sign with the handle. Give the algorithm that the signed artifact names. A different algorithm refuses.
5. Delete the key when you no longer use it. Then each handle of the key refuses.

This example is also the example of the `FileCustody` documentation, and `cargo xtask test` runs it:

```rust
use rsauthnz::crypto::Algorithm;
use rsauthnz::custody::{Custody, FileCustody, Handle, Isolation, KeyId};
use rsauthnz::limits::{Limits, SignatureBudget};
use rscrypto::ChaCha20Rng;

let dir = std::env::temp_dir().join(format!("rsauthnz-custody-example-{}", std::process::id()));
std::fs::create_dir(&dir)?;
// Only for this example: take the seed from the entropy source of the host.
let mut random = ChaCha20Rng::from_seed([7; 32]);

let custody = FileCustody::open(&dir, Isolation::User)?;
// Draw the key ID, and record it before the enroll. After a lost response, delete the ID and enroll again.
let id = KeyId::random(&mut random);
let enrolled = custody.enroll(id, Algorithm::MlDsa65Ed25519, &mut random)?;
// Store the ID, the algorithm, and the public key. They make the handle again after a restart.
let handle = Handle::new(enrolled.id(), enrolled.algorithm(), &enrolled.public_key())?;

let signature = custody.sign(&handle, Algorithm::MlDsa65Ed25519, b"message", &mut random)?;
let mut budget = SignatureBudget::new(&Limits::default());
assert_eq!(handle.verify(b"message", &signature, &mut budget), Ok(true));

custody.delete(id)?;
std::fs::remove_dir(&dir)?;
```

`Handle::public_key` gives the public key in the encoding of the LAMPS draft: the `pub` of a composite `COSE_Key`.

## Lost responses and rotation

A lost response is an unknown outcome, and a custody never retries an operation. Thus the caller draws each key ID
and records it before it enrolls the key. After a lost response or a crash, delete that ID and enroll again. A
delete of an ID with no key refuses with `Error::Unknown`, so the recovery is the same in each case.

`rotate` makes the successor of a key: a key of the same algorithm with a new ID. The predecessor stays until you
delete it. Delete it only after the authority commits the successor, so a lost commit leaves a key that still works.

## Key files

| Property | Value |
| --- | --- |
| Name | The key ID as 32 lowercase hexadecimal digits, then `.key`, in the directory of the custody |
| Content | The PKCS #8 (version 1) DER encoding of the composite key, as rscrypto writes it |
| Linux and macOS | Mode `0600`, set when the file is created. On macOS, also no extended ACL entry |
| Windows | The user of the process is the owner. The DACL is protected and has one entry, which allows that user. The security descriptor applies when the file is created |
| Durability | Enroll flushes the key file before the handle returns. On Linux and macOS, enroll and delete also flush the directory |

Each operation checks the permissions of the key file before it reads the key. A key file that another account can
read or change refuses with `Error::Permissions`. On Linux, a POSIX ACL is covered too, because the group bits of
the mode are the mask of the ACL. Each operation also checks that the length, the algorithm, and the public key of
the key file match the handle. A key file with another key refuses with `Error::Mismatch`.

An administrator or root can still read a key file, through file privileges. The software custody does not keep
the key from them.

## The custody report

`Custody::report` gives a `Report`. `FileCustody::REPORT` has these values:

| Field | Type | Value of `FileCustody` |
| --- | --- | --- |
| `owner` | `&'static str` | A key file of the OS user account that runs the process. Only that account can read it |
| `plaintext` | `&'static str` | In process memory during one operation only. Swap space and a core dump can hold it |
| `zeroization` | `&'static str` | rscrypto clears the key in memory after each operation. Delete removes the key file, but the storage device can keep its blocks |
| `recovery` | `&'static str` | None. Enroll a new key, and register it with the authority |
| `isolation` | `Isolation` | `User` |

`Report::require` refuses with `Error::Isolation` if a caller requires more isolation than the report gives.
`FileCustody::open` calls it before it reads the storage, so `Isolation::Process` refuses there.

The custody keeps one copy of a key in memory, and only during one operation. rscrypto builds the key in place in
its allocation, and signing reads it there. The memory that holds the encoded key file is cleared too. A test of
the library reads each heap block that the custody frees, through the OS, and it finds no key bytes.

Use full-disk encryption on the volume of the key files, because a deleted key file can stay on the storage device.

## Operations

| Operation | Cost class | Result | Refusals |
| --- | --- | --- | --- |
| `FileCustody::open(dir, required)` | `External` | The custody of the key files in `dir` | `Isolation`, `Storage` |
| `Custody::enroll(id, algorithm, random)` | `External` | The handle of a new key. The key is durable first | `Algorithm`, `Exists`, `Storage`, `Crypto` |
| `Custody::rotate(from, id, random)` | `External` | The handle of the successor of `from` | The refusals of `sign` for `from`, then those of `enroll` |
| `Custody::sign(handle, algorithm, message, random)` | `External` | The composite signature of `message` | `Algorithm`, `Unknown`, `Mismatch`, `Permissions`, `Storage`, `Crypto` |
| `Custody::delete(id)` | `External` | The key file is gone | `Unknown`, `Storage` |
| `Handle::new(id, algorithm, public)` | `Verify` | The handle of a stored key | `Algorithm`, `Mismatch` |
| `Handle::verify(message, signature, budget)` | `Verify` | Whether the signature is valid | `Limit::SignatureChecks` if the budget has less than two checks |

[Admit rsauthnz work](admission.md) explains the cost classes.

## Errors

`custody::Error` holds no key byte and no path.

| Error | Cause | Recovery |
| --- | --- | --- |
| `Isolation` | The custody cannot give the isolation that the caller requires | Use a custody whose report gives it |
| `Algorithm` | The custody holds no keys of the algorithm, or the algorithm is not that of the handle | Sign with the algorithm of the handle. Enroll a composite key |
| `Unknown` | No key has the ID: the key was deleted, or another custody holds it | Use the custody of the key. Enroll a new key |
| `Exists` | A key with the ID exists | Delete the ID, or draw another ID |
| `Mismatch` | The stored key does not match the handle: another public key, or a damaged file | Delete the key, and enroll a new key |
| `Permissions` | Another account can read or change the key file, or the custody cannot read its permissions | Delete the key, and enroll a new key |
| `Storage(kind)` | The storage refused the operation. `kind` is the kind of the OS error | Correct the cause, such as the directory or the free space |
| `Crypto` | rscrypto refused to make the key or the signature | Enroll a new key |

## Supply a custody

A host, such as a browser application, can supply its own custody. Implement the `Custody` trait, and give a
`Report` that states your own guarantees. Make each handle with `Handle::new`. The trait is object safe, so a
consumer takes `&dyn Custody`.

## Support

| Target | State |
| --- | --- |
| macOS aarch64 | The tests pass |
| Linux x86_64 and aarch64, glibc and musl | The lints pass for the musl targets. The test runs are pending |
| Windows x86_64 | The lints pass. The test run is pending |
| iOS, Android, WebAssembly | No file custody. The contract and the handle are available |

The software custody does not keep a key from a hostile process of the same OS account. No custody of the library
gives `Isolation::Process` now.
