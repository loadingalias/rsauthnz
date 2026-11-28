# Application servers on one store

Two application servers can submit changes to the same account. Restarting either server leaves the other server's pending commit eligible.
Restoring the store fences pending requests from the abandoned generation. An acknowledged revocation survives restoration of an older snapshot.

## Model boundary

Each server submits one request against the version it read. One request revokes a grant. The others update the same account.
Only the revocation writes the independent journal. A client can lose its response between the primary commit and acknowledgement.

| Action | Atomic event |
| --- | --- |
| `Join` | A process reconnects to the active store. An earlier network request can still arrive. |
| `Submit` | A server captures a store generation and account version for its request. |
| `Log` | The revocation reaches independent durable storage under the generation fence. |
| `Apply` | The primary store compares its generation and the account version, then commits the change or refuses it. |
| `Ack` | A caller receives a successful response. |
| `Crash`, `Install`, `Open` | Admission closes. Recovery fences the abandoned generation and installs the original snapshot. Replay applies the durable revocation before service resumes. |

The base profile has two servers and permits one restore. The raised profile has three servers and permits two restores.
Each profile selects any one server for an ordinary restart. A correct join leaves shared state intact, so another join has the same effect there.
The profiles impose no state constraint. Weak fairness applies only to processing a submitted append or commit.
If the store eventually stays available, each submitted request reaches a decision. The caller controls submission and receipt of a reply.

The model assumes recovery can close admission at both destinations. It represents the durable point of one journal fact and one account version.
A version conflict in this model is the primary store's answer to the driver. The owner-turn model checks when a caller can receive a refusal.
The [authority model](../authority-restore/README.md) covers anchor creation, refusal voids, and in-doubt completion under its storage-crash assumption.
Journal head changes, counter reservations, anchor creation, and recovery-worker takeover need a joint protocol check before implementation.
The current [commit driver](../../src/store/driver/mod.rs) serializes requests through one driver per store.

## Removing different sign-in methods

`OwnerTurn.tla` starts with two sign-in methods on one account. A different server tries to remove each method. The raised profile uses three methods.
Each primary write changes a different key. The shared owner turn protects the check for a remaining sign-in method.

| Action | Atomic event |
| --- | --- |
| `Take`, `Check` | Reserve the owner for the operation. Check the methods that the primary and the retained journal still protect. |
| `Log`, `Ready`, `Send` | Make the end entry durable. Record that the primary write can proceed. Send that write. Each is a separate step. |
| `Apply`, `Retire` | The write and a helper compete on the same durable operation phase. Only the write can end the method in the primary store. |
| `Void`, `Finish` | After retirement, make the journal void durable. Only then can the primary release the turn and the caller receive a refusal. |

The original write can arrive after the helper retired it and a peer acquired the turn. It must then refuse at the primary.
The check covers the live primary state and the methods an original snapshot would retain after applying journal facts.
Weak fairness applies to advancing reserved work while the store and a driver can serve it. Starting a request and retiring a write are optional.
Each server asks once. A method has one original identity. The model covers removals under an established storage generation.

## Checks

Run `cargo xtask model replica-commit`.

| Profiles | Required result |
| --- | --- |
| `ReplicaCommit` base and `Raised` | A healthy peer keeps its fence. Every commit uses its original generation and version. Restore keeps an acknowledged revocation. A responsive store decides pending requests. |
| `Peer_reach` | A submitted request commits across a peer restart. The restarted peer also commits to that account. |
| `Race_reach` | Both servers read one version. One request commits and the other conflicts. |
| `Restore_reach` | Restore retains the acknowledged revocation and fences a delayed request. |
| `Join_bad`, `Fence_bad`, `Version_bad` | Fencing peers on join, omitting the generation check, and omitting the version check each violate their own invariant. |
| `Journal_bad`, `Stall_bad` | Skipping the durable revocation violates `RevocationKept`. Stalling a healthy peer violates `Responsive`. |
| `OwnerTurn` base and `Raised` | The account keeps a sign-in method in the primary and after journal replay. A refusal stays true. Each reserved operation reaches a decision. |
| `Last_reach`, `Takeover_reach` | One request refuses to remove the last method. A retired write arrives during a peer's turn. The peer commits its removal. |
| `Local_bad`, `Late_bad`, `Hold_bad` | A process-local turn can end every method. A stale write can contradict a refusal. Holding a finished turn can prevent a decision. |

On 2026-11-27 all 17 profiles passed on macOS 27.2.1 arm64 with TLC 1.8.0 at `bc1b506bdcad` and JRE 21.0.13.1+2.
The replica searches exhausted 2,380 and 340,237 distinct states. The owner-turn searches exhausted 105 and 843.
All five witnesses reached their targets. The eight faulty designs violated their named properties.
The replica checks recorded eleven inputs with SHA-256 `ae70d1e9f54f9ce065afe5a6d0330810275ceaaafe90b64465ca552402fbebcd`.
The owner-turn checks added eight inputs. The digest of all nineteen was `7f80db25410b6e6659a64259408d1fe8f820edefdbdbdcae022825077af58446`.
