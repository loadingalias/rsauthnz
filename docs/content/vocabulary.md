# Vocabulary

rsauthnz names principals, authorities, and the objects of authorization with one set of bounded
identifiers. It records what an authentication proved as evidence. This page gives each type, its
rules, and its canonical CBOR form. The CBOR codec is the one of [Parser limits](parser-limits.md).
[Authorize an operation](authorization.md) checks an action on a resource with these identifiers.
[Propose a transition](transitions.md) uses authority versions as the dependencies of a proposal.

## Identifiers

An identifier `Id<K>` has a kind `K`, a namespace, and a value. The kind is a type, so an identifier
of one kind cannot take the place of another. The application chooses the namespace and the value,
so it adds identifiers without a change to rsauthnz.

| Kind | Type | What it names |
| --- | --- | --- |
| `Human` | `Id<Human>` | A person |
| `Workload` | `Id<Workload>` | A service or a host that acts for itself |
| `Agent` | `Id<Agent>` | An agent that acts for its human owner |
| `Authority` | `Id<Authority>` | An authority: the owner of principals, policy, and versions |
| `Tenant` | `Id<Tenant>` | A tenant of an authority |
| `Action` | `Id<Action>` | An action on a resource, such as `repo.read` |
| `Resource` | `Id<Resource>` | A resource, such as a repository |
| `Audience` | `Id<Audience>` | The service that accepts an artifact |
| `Purpose` | `Id<Purpose>` | The purpose of an artifact or a key |

`Id::new(namespace, value)` refuses a part outside its rule:

| Part | Length | Bytes | Refusal |
| --- | --- | --- | --- |
| Namespace | 1 to 64 (`MAX_NAMESPACE`) | Lowercase ASCII letters, digits, `.`, `-`, `_` | `IdError::Namespace` |
| Value | 1 to 2048 (`MAX_VALUE`) | Visible ASCII, `!` to `~`: no space and no control character | `IdError::Value` |

Thus each identifier has one form, and two identifiers are equal only when their kinds, namespaces,
and values are equal, byte for byte. Text with other characters needs an encoding first, for example
percent-encoding. An identifier allocates the bytes of its namespace and its value, and no more.

```rust
use rsauthnz::id::{Action, Id, Resource};

let action: Id<Action> = Id::new("acme.repo", "repo.read")?;
let resource: Id<Resource> = Id::new("acme.repo", "repo:x")?;
```

There is no default tenant. Each tenant is an identifier that the application chooses.

## Principals

A `Principal` is `Principal::Human`, `Principal::Workload`, or `Principal::Agent`, each with the
identifier of its kind. Principals of two kinds are never equal, also when their namespaces and
values are equal. A check that needs a human takes an `Id<Human>`, so an agent cannot pass it.

## Authority versions

An `AuthorityVersion` is a version of state that an authority owns, such as its policy or a grant:
the owner, an `Id<Authority>`, and an opaque coordinate of 1 to 64 bytes. It is no timestamp,
database epoch, or causal clock. A storage binding maps its own coordinates into it.

The comparison is declared: `compare` orders two versions of one owner by their coordinates, byte
by byte. A shorter coordinate that is a prefix of a longer one is earlier. Thus give each later
version a greater coordinate, for example a counter in big-endian bytes of a fixed width. Versions
of two owners do not compare: `compare` gives `VersionError::Owners`.

```rust
use rsauthnz::id::{AuthorityVersion, Id, VersionError};

let owner = Id::new("acme", "policy").map_err(VersionError::Owner)?;
let version = AuthorityVersion::new(owner, &7_u64.to_be_bytes())?;
```

## Authentication evidence

`Evidence` records the facts that one authentication proved, and no others:

| Fact | Getter |
| --- | --- |
| The principal | `subject()` |
| The method: a passkey, a provider sign-in, a recovery value, a bootstrap value, or the possession of an enrolled key | `method()` |
| The physical time | `time()` |
| User verification | `user_verified()` |
| Phishing resistance: the proof binds the origin | `phishing_resistant()` |
| Recovery | `recovery()` |
| A device or hardware binding of the key | `binding()` |

Evidence has no strength score. A recovery never records phishing resistance. Only the verifiers of
rsauthnz make evidence, so a caller cannot mark an unverified claim as proved. A storage binding
keeps the encoded evidence as opaque bytes and gives them back; it never rebuilds evidence itself. The verifiers come in
later releases, so this release makes no evidence yet.

The time is a `rsauthnz::time::Reading`: an estimate of the Unix time, an uncertainty bound or
"unknown", and its source.

## CBOR forms

Each type has one canonical CBOR form, which `to_cbor` gives. `from_cbor` reads the form of each
type except `Evidence`, which only rsauthnz reads:

| Type | Form |
| --- | --- |
| `Id<K>` | `[kind, namespace, value]`. The kinds are numbers: human 1, workload 2, agent 3, authority 4, tenant 5, action 6, resource 7, audience 8, purpose 9 |
| `Principal` | The form of its identifier |
| `AuthorityVersion` | `[owner, coordinate]`, with the coordinate as a byte string |
| `Evidence` | `[subject, method, time, user verified, phishing resistant, binding]` |

A form of another kind refuses: for example, the form of an `Id<Agent>` does not read as an
`Id<Human>`.
