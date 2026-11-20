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

The text form of an identifier is `namespace:value`, which `Display` gives. A namespace has no `:`, so the first
`:` ends it. The text form does not name the kind. The `iss` and `aud` claims of a credential hold it, as
[Issue and verify credentials](credential-format.md) gives.

```rust
use rsauthnz::id::{Action, Id, Resource};

let action: Id<Action> = Id::new("acme.repo", "repo.read")?;
let resource: Id<Resource> = Id::new("acme.repo", "repo:x")?;
```

There is no default tenant. Each tenant is an identifier that the application chooses.

The namespace `rsauthnz` holds the identifiers that rsauthnz fixes, such as the purpose `rsauthnz:workload` and the
actions `rsauthnz:workload.issue` and `rsauthnz:workload.revoke` ([Issue and manage workload
credentials](workload.md#the-policy)). Do not use it for identifiers of the application.

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
The [restore journal](restore.md) uses this order: a fact states that each version of a record at or below a
version is dead. rsauthnz writes the later versions of the issuer and registration records of
[workloads](workload.md) itself. Each one has a new value of a counter of the commit driver, so it is greater than
each earlier version, also after a restore.

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
| The authentication of the signature: `Hybrid`, `PostQuantum`, or `Classical` (`crypto::Authentication`), or `None` when rsauthnz verified no signature | `authentication()` |
| The credential of the authentication: its verified claims, with the issuer, the audience, the purpose, the serial, the validity interval, and the owner of an agent, and the SHA-256 digest of its bytes (`evidence::Artifact`), or `None` with no credential | `artifact()` |
| The end of the credential, after which the evidence gives no authority | `expires()` |

A `Classical` authentication gives no post-quantum guarantee. Post-quantum key exchange is a separate
guarantee of the transport, and the evidence does not record it. Evidence has no strength score. A recovery never records phishing resistance. Only the verifiers of
rsauthnz make evidence, so a caller cannot mark an unverified claim as proved. A storage binding
keeps the encoded evidence as opaque bytes and gives them back; it never rebuilds evidence itself.
`credential::Verified::possession` makes the evidence of a key possession, as [Prove
possession](credential-format.md#prove-possession) gives. The other verifiers come in later releases.

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
| `Evidence` | `[subject, method, time, user verified, phishing resistant, binding, authentication, artifact]`. The authentication is hybrid 1, post-quantum 2, classical 3, or `null`. The artifact is `null`, or `[issuer, audience, subject, owner, purpose, serial, not before, expires, digest]`, with `null` for no owner and for no start |

A form of another kind refuses: for example, the form of an `Id<Agent>` does not read as an
`Id<Human>`.
