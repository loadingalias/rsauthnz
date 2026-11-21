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

A custody holds the composite keys, `MlDsa65Ed25519`, the default profile, and `MlDsa65EcdsaP256`, and the
trust-root keys of `SlhDsaSha2_128s`. A root key signs issuer keys, and no credential or proof: as the issuer key of
a local authority or the key of a CLI, it refuses with `credential::Error::Profile`. [Signature profiles](profiles.md)
gives the profiles. Each random value comes from the seeded `rscrypto::ChaCha20Rng` of the
caller: the key ID, each key, and the randomness of each signature. The signing is hedged: rscrypto takes fresh
randomness from the generator for each signature.

## Select a custody

The feature `native-custody` gives two custodies:

- `FileCustody`, the software custody, keeps each key in a key file under OS file permissions. It is available on
  Linux, macOS, and Windows.
- `KeychainCustody`, the OS-vault custody, keeps each key in the login keychain of macOS. It is available on macOS.

Both custodies give the same operations and the same isolation. The keychain encrypts the keys at rest, and it adds
no directory for you to protect. No custody gives hardware non-exportability: each one reads the key into process
memory to sign.

On macOS, use `KeychainCustody`. Use `FileCustody` if the program runs with no user session, or if its code
signature changes with each build. In those cases, the keychain needs a person, or it refuses (see
[Keychain dialogs](#keychain-dialogs)).

## Use the file custody

`FileCustody` is the software custody. It keeps each key in a key file under OS file permissions. It needs the
feature `native-custody`:

```toml
[dependencies]
rsauthnz = { git = "https://github.com/loadingalias/rsauthnz", branch = "main", features = ["native-custody"] }
```

The feature has an effect on Linux, macOS, and Windows only. A build for another target, such as WebAssembly, iOS,
or Android, has no `FileCustody` and no `KeychainCustody`.

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

## Use the Keychain custody

`KeychainCustody` keeps each key in the login keychain of the OS user account that runs the process. It needs the
feature `native-custody`, and it is available on macOS only. The library adds no entitlement and no code-signing step.

1. Select a service name for the keys of your application, such as its bundle ID. Give it to `KeychainCustody::open`
   with the isolation that you require. The library has no default service name.
2. Draw a key ID with `KeyId::random`, and record it before you enroll the key.
3. Enroll the key. Store the ID, the algorithm, and the public key of the handle.
4. Sign with the handle. Give the algorithm that the signed artifact names. A different algorithm refuses.
5. Delete the key when you no longer use it. Then each handle of the key refuses.

This example is also the example of the `KeychainCustody` documentation, and `cargo xtask test` runs it on macOS:

```rust
use rsauthnz::crypto::Algorithm;
use rsauthnz::custody::{Custody, Handle, Isolation, KeyId, KeychainCustody};
use rsauthnz::limits::{Limits, SignatureBudget};
use rscrypto::ChaCha20Rng;

// Name the keys of the application with a service, such as its bundle ID. Only for this example: the process ID
// keeps the items of each run apart.
let service = format!("com.example.rsauthnz-example.{}", std::process::id());
// Only for this example: take the seed from the entropy source of the host.
let mut random = ChaCha20Rng::from_seed([7; 32]);

let custody = KeychainCustody::open(service, Isolation::User)?;
// Draw the key ID, and record it before the enroll. After a lost response, delete the ID and enroll again.
let id = KeyId::random(&mut random);
let enrolled = custody.enroll(id, Algorithm::MlDsa65Ed25519, &mut random)?;
// Store the ID, the algorithm, and the public key. They make the handle again after a restart.
let handle = Handle::new(enrolled.id(), enrolled.algorithm(), &enrolled.public_key())?;

let signature = custody.sign(&handle, Algorithm::MlDsa65Ed25519, b"message", &mut random)?;
let mut budget = SignatureBudget::new(&Limits::default());
assert_eq!(handle.verify(b"message", &signature, &mut budget), Ok(true));

custody.delete(id)?;
```

### Keychain items

| Property | Value |
| --- | --- |
| Keychain | The login keychain of the user: `~/Library/Keychains/login.keychain-db`. Each add, read, and delete names it, so another default keychain or another keychain of the search list takes no part. Not the data protection keychain |
| Class | Generic password |
| Service | The service name that you give to `KeychainCustody::open` |
| Account | The key ID as 32 lowercase hexadecimal digits |
| Data | The PKCS #8 (version 1) DER encoding of the composite key, as rscrypto writes it |
| Synchronization | None. The item does not synchronize through iCloud |
| Access | The default access of macOS: the program that made the item reads it without a dialog |
| Durability | macOS writes the item before enroll returns |

macOS encrypts the login keychain with a key from the login password of the user. Each operation checks that the
length, the algorithm, and the public key of the item match the handle. An item with another key refuses with
`Error::Mismatch`.

### Keychain dialogs

macOS shows a dialog that needs a person in these cases:

- Another program reads the item. The program that made the item does not get a dialog.
- A build of your program with another code signature reads the item. An ad-hoc signature changes with each build,
  for example after each `cargo install`.
- The login keychain is locked.

The operation waits until the person answers. If the person denies access, the operation refuses with
`Error::Vault`. macOS documents `errSecInteractionNotAllowed` (`-25308`) for a dialog that the session cannot show,
for example in an SSH session. No test of the library runs that path.

To keep access across updates, sign your program with a stable identity, such as a Developer ID certificate. If a
program lost its access, allow it in the dialog, or enroll a new key and register it with the authority.

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
| Content | The PKCS #8 (version 1) DER encoding of the key, as rscrypto writes it. A root key has the form of [RFC 9909](https://www.rfc-editor.org/rfc/rfc9909): 84 bytes |
| Linux and macOS | A regular file of the effective user of the process, with the mode `0600`, set when the file is created. On macOS, also no extended ACL entry |
| Windows | The user of the process is the owner. The DACL is protected and has one entry, which allows that user. The security descriptor applies when the file is created |
| Durability | Enroll flushes the key file before the handle returns. On Linux and macOS, enroll and delete also flush the directory |

Each operation checks the permissions of the key file before it reads the key. A key file that another account can
read or change refuses with `Error::Permissions`. On Linux, a POSIX ACL is covered too, because the group bits of
the mode are the mask of the ACL. The open follows no link, and the checks read the open file. A link at the path and
a file of another owner refuse with `Error::Permissions`. Thus a key file that a restore keeps with the owner of
another account refuses, also for a service that runs as root. On Linux and macOS, the open does not block, so a FIFO
or a device at the path refuses at once. On Windows, each reparse point refuses: a link, a junction, or the
placeholder of a sync service such as OneDrive, which can copy the key off the host. A DACL that is not protected
refuses too, also with one entry for the user, because a later change of a parent directory passes its entries on
to it. Each operation also checks that the length, the algorithm, and the public key of
the key file match the handle. A key file with another key refuses with `Error::Mismatch`.

An administrator or root can still read a key file, through file privileges. The software custody does not keep
the key from them.

A backup of the directory, such as a Time Machine backup, copies each key file, and the key in it is plaintext.
Exclude the directory of the key files from backups.

## The custody report

`Custody::report` gives a `Report`. `FileCustody::REPORT` and `KeychainCustody::REPORT` have these values:

| Field | Type | Value of `FileCustody` | Value of `KeychainCustody` |
| --- | --- | --- | --- |
| `owner` | `&'static str` | A key file of the OS user account that runs the process. Only that account can read it | An item of the login keychain of the OS user account that runs the process. macOS gives it to another program, or to a build of the program with another code signature, only after the user allows it in a dialog |
| `plaintext` | `&'static str` | In process memory during one operation only. Swap space and a core dump can hold it | macOS decrypts the item and gives it to the process for one operation. In process memory during that operation only. Swap space and a core dump can hold it |
| `zeroization` | `&'static str` | rscrypto clears the key in memory after each operation. Delete removes the key file, but the storage device can keep its blocks | rscrypto clears its copy of the key after each operation. macOS frees its copy of the item, which the custody cannot clear. Delete removes the item. A backup of the login keychain keeps the item, encrypted |
| `recovery` | `&'static str` | None. Enroll a new key, and register it with the authority | None. Enroll a new key, and register it with the authority |
| `isolation` | `Isolation` | `User` | `User` |

`Report::require` refuses with `Error::Isolation` if a caller requires more isolation than the report gives.
`FileCustody::open` and `KeychainCustody::open` call it before they read the storage, so `Isolation::Process`
refuses there.

A custody keeps a key in memory only during one operation, and each copy that it makes is in memory that is cleared
when it drops. rscrypto builds the key in place in its allocation, and signing reads it there. An import reads the
PKCS #8 encoding in place, and an export writes it into a buffer that is cleared. Thus an import or an export holds
the encoding and the key together for that one call. The file custody reads the key file into such a buffer. A test
of the library reads each heap block that the file custody frees, through the OS, and it finds no key bytes.

The Keychain custody also gets a copy of the item in memory of macOS, and rscrypto reads the key from it in place.
The custody releases that copy before it signs, but it cannot clear it. Enroll writes the encoding into memory that
CoreFoundation owns, and CoreFoundation gives it back to rsauthnz to clear when the item data ends. A test of the library reads each region of the process that the process can write, after the
Keychain custody and its handles drop, and it finds no key bytes. That test passes on macOS 27.2.1 on aarch64.

Use full-disk encryption on the volume of the key files, because a deleted key file can stay on the storage device.

## Operations

| Operation | Cost class | Result | Refusals |
| --- | --- | --- | --- |
| `FileCustody::open(dir, required)` | `External` | The custody of the key files in `dir` | `Isolation`, `Storage` |
| `KeychainCustody::open(service, required)` | `Parse` | The custody of the keychain items of `service`. It does no keychain work | `Isolation` |
| `Custody::enroll(id, algorithm, random)` | `External` | The handle of a new key. The key is durable first | `Algorithm`, `Exists`, `Storage`, `Vault`, `Crypto` |
| `Custody::rotate(from, id, random)` | `External` | The handle of the successor of `from` | The refusals of `sign` for `from`, then those of `enroll` |
| `Custody::sign(handle, algorithm, message, random)` | `External` | The signature of `message`: a composite signature, or an SLH-DSA signature of 7,856 bytes for a root key | `Algorithm`, `Unknown`, `Mismatch`, `Permissions`, `Storage`, `Vault`, `Crypto` |
| `Custody::delete(id)` | `External` | The key file or the keychain item is gone | `Unknown`, `Storage`, `Vault` |
| `Handle::new(id, algorithm, public)` | `Verify` | The handle of a stored key | `Algorithm`, `Mismatch` |
| `Handle::verify(message, signature, budget)` | `Verify` | Whether the signature is valid | `Limit::SignatureChecks` if the budget has less than the checks of the key: two for a composite key, and one for a root key |

[Admit rsauthnz work](admission.md) explains the cost classes. A root signature is about 2.5 million SHA-256
compressions, because SLH-DSA signs with hashes only. A root signs rarely, so the cost is named and not optimized: a
debug build takes several seconds for one signature.

## Errors

`custody::Error` holds no key byte and no path.

| Error | Cause | Recovery |
| --- | --- | --- |
| `Isolation` | The custody cannot give the isolation that the caller requires | Use a custody whose report gives it |
| `Algorithm` | The custody holds no keys of the algorithm, or the algorithm is not that of the handle | Sign with the algorithm of the handle. Enroll a composite key |
| `Unknown` | No key has the ID: the key was deleted, or another custody holds it | Use the custody of the key. Enroll a new key |
| `Exists` | A key with the ID exists | Delete the ID, or draw another ID |
| `Mismatch` | The stored key does not match the handle: another public key, or a damaged key file or item | Delete the key, and enroll a new key |
| `Permissions` | Another account can read or change the key file, or the custody cannot read its permissions | Delete the key, and enroll a new key |
| `Storage(kind)` | The storage refused the operation. `kind` is the kind of the OS error | Correct the cause, such as the directory or the free space |
| `Vault(code)` | The keychain refused the operation. `code` is the `OSStatus` of macOS | See the codes in the next table |
| `Crypto` | rscrypto refused to make the key or the signature | Enroll a new key |

These are the frequent `Vault` codes. macOS names each code in its `SecBase.h` header.

| Code | Name | Cause | Recovery |
| --- | --- | --- | --- |
| `-25308` | `errSecInteractionNotAllowed` | macOS needs a dialog, but the session cannot show one | Unlock the login keychain, or run the program in the session of the user |
| `-128` | `errSecUserCanceled` | The person canceled the dialog | Do the operation again, and allow it in the dialog |
| `-25293` | `errSecAuthFailed` | The authorization or the authentication failed, for example with a wrong keychain password | Do the operation again with the keychain password |
| `-25291` | `errSecNotAvailable` | No keychain is available | Restore or make the login keychain of the user |

## Supply a custody

A host, such as a browser application, can supply its own custody. Implement the `Custody` trait, and give a
`Report` that states your own guarantees. Make each handle with `Handle::new`. The trait is object safe, so a
consumer takes `&dyn Custody`.

## Support

| Target | `FileCustody` | `KeychainCustody` |
| --- | --- | --- |
| macOS aarch64 | The tests pass | The tests pass, in the session of a user with an unlocked login keychain |
| macOS x86_64 | No claim | No claim |
| Linux x86_64 and aarch64, glibc and musl | The lints pass for the musl targets. The test runs are pending | Not available |
| Windows x86_64 | The lints pass. The test run is pending | Not available |
| iOS, Android, WebAssembly | Not available. The contract and the handle are available | Not available |

No custody of the library keeps a key from a hostile process of the same OS account, and none gives
`Isolation::Process`. Such a process can read a key file. It can also start your program and make it sign, or load
its own code into your program, and then use the keychain item without a dialog.
