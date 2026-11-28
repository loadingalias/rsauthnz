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
The shared recovery checks below cover the writes that establish that crash boundary.
The [commit driver](../../src/store/driver/mod.rs) implements these rules for several drivers on one store.
A join reads the installed generation and writes none. Only an activation takes a fresh generation.
The driver keeps the closed-step rule of the journal itself: an end entry reads its owner turn again before each append after a conflict.
The model covers the replacement of a counter value. The driver also checks a new record of a key that can repeat against the dead version of its journal facts. No profile checks that rule yet.

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

## Shared recovery

A server can stop after the journal accepts a consumption or after the primary creates its anchor.
A peer can finish the operation from durable state. A caller that lost the reply can look up its outcome.

| Design step | Model action and atomicity |
| --- | --- |
| Reserve and decide | `SharedTurns.Reserve` acquires every affected owner in one primary transaction. `Decide` checks the turn and payment in the primary write. `Retire` competes for that same turn. |
| Finish an operation | A helper observes the durable decision and appends its creation or void. `Finish` releases the reservation in a later primary write. |
| Look up an outcome | `Lookup` reads the outcome and the affected owner turns in one primary state. It waits while any of those turns has a committed creation to settle. |
| Capture a snapshot | `Snapshot` captures the primary and a verified prefix of the journal. Every operation in that prefix has settled, including operations of other owners. |
| Restore a snapshot | `Install` loads the snapshot after both destinations have fenced old work. `Replay` applies entries after the mark. `Redrive` completes an eligible consumption under its original identity. |
| Replace a recovery worker | `RecoveryFence.Start` takes a fresh generation at the primary. The worker fences the journal before installing the snapshot. Each later write checks its destination's generation and phase. |
| Reserve revisions | `CounterBlocks.Reserve` compares and advances the independent journal floor. `Replace` checks the predecessor and the candidate revision at the primary. |

Each successful append extends one predecessor and records one immutable operation step.
A lost reply changes no durable fact. A peer can identify the step at the journal before it continues.
A delayed primary write must still own its turn and generation. A rejected packet changes neither destination.

Packets that the old journal accepts before its fence belong to the history that recovery reads.
The closed journal accepts recovery entries for its current generation. It opens for ordinary entries before the primary admits servers to that generation.

`Authority.JournalEnd`, `Commit`, `JournalCreate`, and `Resolve` correspond to the intent append, primary decision, creation append, and outcome lookup here.
An abandoned turn can remain pending while another owner advances. The model exposes the interval between a primary retirement and its durable void.
The recovery packet represents a terminal append. Creation and void compare the same generation, admission state, head, and open operation at the journal.
The authority model checks their different effects on restart and replay.

1. A successful lookup has a primary outcome and a durable creation entry. It also waits for a later commit that still owes a creation for the same owner.
2. A confirmed refusal has a terminal void. The primary decision excludes a later commit of that turn. Replay excludes its voided intent.
3. A committed spend is present in the snapshot or has an unvoided entry after its mark.
   Recovery applies that entry before admission. A known outcome or creation excludes a second operation for the same payment.

A mark can trail the journal head. Suppose one account has an unfinished consumption at sequence 1.
Another account completes its creation at sequence 3. A snapshot taken then must retain sequence 1 for replay.
Taking the greatest completed sequence would allow restore to lose the first account's spend.

The authority model supplies the rules for each kind of anchor, the last sign-in method, and competing claims on a bootstrap value.
Changes that share an owner finish their journal writes in turn. The next last-anchor check sees the same settled facts as the authority model.
Independent owners can interleave their entries at the journal head.

Here one consumption pays for one new anchor. Each operation keeps its identity and payload across a lost reply.
The binding retains the journal outside the snapshot's failure domain. Each destination supplies durable conditional writes.

Each reservation compares the old floor and raises it by the block size. Only one allocation can win that comparison.
Its entire block is above every earlier block. Losing a reply can waste values. A restore keeps the floor in the independent journal.
A server with an older block must discard any candidate at or below the revision it plans to replace.

### Bounds and progress

`SharedTurns` checks a shared owner and payment, separate owners, and a reservation that overlaps on its second owner.
The base has two operations, one snapshot at any reachable point, and one restore. Separate profiles raise the operation and restore bounds.
A second restore can interrupt recovery after its primary commit and before its creation append.

The model keeps the same snapshot for both restores. Each operation has one caller. Any healthy helper can advance a durable turn.

`RecoveryFence` checks two operation identities, two changes of generation, and one delayed packet in its base profile.
One profile permits three generation changes with one delayed packet. Another permits two delayed packets across one generation change.
Other helpers can continue to submit fresh requests.

A successful fresh write represents one atomic comparison at its destination. Only the delayed packet needs to keep its original observations.
Identical delayed packets share a slot. After one append succeeds, its copy has an old head.
A retry at a new head still checks whether the journal already holds that operation step.

The length identifies a head in this append-only history. The binding compares the authenticated head of its chain.
In the missing-fence trace, a server sends an end entry at head 0 in generation 0.
The journal opens generation 1 at head 0. A head-only check accepts the delayed entry. The generation check refuses it.

`CounterBlocks` checks one counter kind. It starts with two servers, two blocks of two values, and one restore.
Separate profiles raise each bound by one. A restore can select any earlier committed revision or the initial revision.
The set of previously assigned blocks and the set of previously issued values serve only as observers.

Progress for reserved turns and recovery assumes that crashes stop and a healthy helper eventually executes each continuously enabled local step.
Callers decide whether to submit or look up an operation. Delayed packets can remain in transit forever.
These finite searches use no state constraint. The authority induction has its own domains and its recorded [proof limit](../authority-restore/README.md#limits).

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

On 2026-11-27 the first 17 profiles passed on macOS 27.2.1 arm64 with TLC 1.8.0 at `bc1b506bdcad` and JRE 21.0.13.1+2.
The replica searches exhausted 2,380 and 340,237 distinct states. The owner-turn searches exhausted 105 and 843.
All five witnesses reached their targets. The eight faulty designs violated their named properties.
The replica checks recorded eleven inputs with SHA-256 `ae70d1e9f54f9ce065afe5a6d0330810275ceaaafe90b64465ca552402fbebcd`.
The owner-turn checks added eight inputs. The digest of all nineteen was `7f80db25410b6e6659a64259408d1fe8f820edefdbdbdcae022825077af58446`.

### Shared recovery evidence

On 2026-11-27 SANY parsed the three shared recovery modules. TLC completed their 43 profiles on the same Mac and checker versions.
Each full search exhausted its queue. Each witness reached its target. Each faulty design violated its named property.

| Module | Complete searches in distinct states | Witnesses | Faulty designs |
| --- | --- | ---: | ---: |
| `SharedTurns` | Base 17,925. Three operations 2,132,843. Two restores 32,836. | 5 | 8 |
| `RecoveryFence` | Base 70,654. Three generation changes 152,530. Two delayed packets 442,311. | 5 | 9 |
| `CounterBlocks` | Base 1,134. Three servers 7,315. Three blocks 12,790. Three values per block 2,844. Two restores 1,794. | 1 | 4 |

At ten minutes the three-operation search had found 1,260,056 states, with 344,542 queued.
The search and all four temporal checks finished in 28 minutes and 33 seconds.
The 65 input files have SHA-256 `c4a5253eb5d5d2f7f92f36626792e1b4914554e11f7668471e87a28c97c59727`.
Each of the 60 passing run records matches its current profile and module byte for byte.
Each `target/model/replica-commit/<profile>/<run>/run.txt` gives both input hashes, their combined hash, the command, the checker versions, and the verdict.
