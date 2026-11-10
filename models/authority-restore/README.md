# authority-restore: design model of tasks A000 and A016

Status (2026-11-10): the inductive invariant of `AuthorityInd.tla` now implies every authority
property, `AnchorKept`, `AccountKeepsAnchorP`, and `AdminKeptP` included, and the declared proof
passed in full at the current digest. The raise by one runs in two groups
(`AuthorityIndAnchors.tla` and `AuthorityIndProcess.tla`), and it replaces the TLC raise searches
and the reduction to one account, which are removed ([Raise by one](#raise-by-one)). The proof
work found one gap of the model and one weak property, and both are closed
([Decisions](#decisions)): a lookup promised the anchor set of the operation's latest commit, not
of the outcome record that it found; and `AnchorKept` excused an anchor that an operation planned
to end before that operation wrote its end entry. A016 closed on 2026-11-10 with three named
limits ([Limits](#limits)): the grouped raises ran only in part, the two declared TLC searches did
not run at the current digest, and the round-6 logs of the Apalache profiles are lost.

## Promise

- **Authority and restore** (`Authority.tla`). After any sequence of crashes, restarts, and
  restores, nothing that a committed transition ended is valid again. At most one bootstrap value
  is valid, and the local owner can issue a new one after the first is consumed. No counter value
  is issued twice. A missing outcome after restore is unknown. Restore adds no anchor whose commit did not
  complete. A refusal that a client received stays true. Each one-use value is spent at most once
  in the store's history. While the store serves, each account and the authority keep the anchors
  that acknowledged commits left them. A concrete failure: a restore from yesterday's snapshot
  makes a revoked passkey valid again, or removes the last sign-in method of an account.
- **Replay window** (`Replay.tla`). For every clock error within its bound, no signature is
  accepted twice, and no record is removed while a verifier can still accept its signature. A
  concrete failure: two verifiers that share one store both accept one captured request.

## Run it

```sh
cargo xtask model authority-restore/Authority.TwoOps.cfg   # one profile
cargo xtask model authority-restore/Authority.TwoOps.cfg authority-restore/Replay.Step.apalache
cargo xtask model authority-restore                        # every profile
```

`cargo xtask model authority-restore` includes the declared-bounds searches `Authority.cfg` and
`Authority.Bootstrapped.cfg` and the step checks of the proofs, which need the evidence host
([Evidence record](#evidence-record)). On the development host, run the other profiles by name.
The output and each trace go to `target/model/authority-restore/<file>/`: `checker.log`, and
`trace.json` (TLC) or `<Module>.tla/<run>/violation1.itf.json` (Apalache). [Check the design
models](../../docs/content/design-models.md) tells how to install the checkers and what a
failure means.

## Profiles

The first part of a profile's name names its module (`cargo xtask model --help`). A `_bad`
profile is a known-bad variant and a `_reach` profile is a reachability witness: each checks one
property and passes only on a violation of it. "TwoOps" is the local bound: two operations of
three, counter values up to 4, and at most one owner re-bootstrap. "Declared" is three operations,
counter values up to 5, and at most one owner re-bootstrap. The constant `Origin` is "new" (the
first bootstrap value is not consumed) or "bootstrapped" (it is consumed, and administrator `adm1`
is live), so that a re-bootstrap and its consequences fit in the operation bound. The constant
`Raise` is "none" for the declared domains, "anchors" and "process" for the two raised proofs, and
"slotsA1" (the fourth slot of `a1`) for `SlotsA1AckEarly_bad`.

| Profile | Checker | Check | Bound |
| --- | --- | --- | --- |
| `Authority.cfg` | TLC | Every authority property, `Origin = "new"` | Declared (evidence host) |
| `Authority.Bootstrapped.cfg` | TLC | Every authority property, `Origin = "bootstrapped"` | Declared (evidence host) |
| `Authority.TwoOps.cfg` | TLC | Every authority property, `Origin = "new"` | TwoOps |
| `Authority.TwoOpsBootstrapped.cfg` | TLC | Every authority property, `Origin = "bootstrapped"` | TwoOps |
| `Authority.Race.cfg` | TLC | Every authority property, with `Turn = "entry"`: each turn ends at the first journal write, so two consumptions of one value can be in doubt at one restore | TwoOps |
| `Authority.<Rule>_bad.cfg` | TLC | One known-bad variant ([Known-bad variants](#known-bad-variants)) | TwoOps; `Unserialized_bad` Declared |
| `Authority.<Target>_reach.cfg` | TLC | One reachability witness ([Reachability](#reachability)) | TwoOps; `AdminReplaced_reach` Declared |
| `AuthorityInd.Init.apalache` | Apalache | `Init => IndInv` | Declared domains |
| `AuthorityInd.Step<Part><Group>.apalache` | Apalache | `IndInv /\ Next<Part> => P'` for each part `P` of `IndInv` in the group: `Base` (the eight parts of A000), `Anchor` (`AnchorStateInv`, `PromiseInv`, `KeptNowInv`, `TurnInv`, `ServingInv`), `Restore` (`RestoreAccountInv`, `RestoreAdminInv`), or `RestoreNow` (`RestoreNowAccountInv`, `RestoreNowAdminInv`); four profiles for each of the twenty-three parts of `Next` | Declared domains, unbounded integers |
| `AuthorityInd.Safety.apalache` | Apalache | `IndInv => Safety` | Declared domains |
| `AuthorityInd.<Witness>_reach.apalache` | Apalache | `IndInit` contains a key state ([Inductive proofs](#inductive-proofs)) | — |
| `AuthorityInd.SnapshotOwnMark_bad.apalache` | Apalache | Known-bad variant `ownMark`: a snapshot step breaks `EndInv` | Declared domains |
| `AuthorityIndAnchors.<Check>.apalache` | Apalache | Each check of `AuthorityInd` with the anchor domains raised by one, and the witnesses `AccountsUsed_reach` and `AdminUsed_reach` | Three accounts, four slots in `a1`, three in `a2`, three administrator slots |
| `AuthorityIndProcess.<Check>.apalache` | Apalache | Each check of `AuthorityInd` with the process domains raised by one, and the witness `ProcessUsed_reach` | Four operations, three snapshots, four values in each set of bootstrap values |
| `Replay.Init.apalache`, `Replay.Step.apalache`, `Replay.Safety.apalache` | Apalache | The inductive invariant of the replay window, and `IndInv => Safety` | Unbounded integers and time |
| `Replay.AcceptedGone_reach.apalache` | Apalache | `IndInv` contains an acceptance whose record expired while a verifier holds a check | — |
| `Replay.<Rule>_bad.apalache` | Apalache | One known-bad variant, 10 steps | Unbounded integers and time |

The twenty-three parts of `Next` are one action each (`AuthorityInd.tla`): the eight kinds of
`Start`, `JournalEnd`, `Commit`, `Conflict`, `JournalCreate`, `Ack`, `Resolve`,
`ReconcileCreate`, `ReconcileVoid`, `Redrive`, `RedriveFail`, `Crash`, `Restart`, `Serve`,
`Snapshot`, and `Restore`. By the definitions of `Next`, `NextRun`, `NextEnd`, `NextRec`,
`NextAgain`, and `NextSys`, their disjunction is `Next`.

## Correspondence: authority and restore

Each action is one atomic design step. The source is [AUTH Storage Contract and Bindings] unless
the row names [AUTH Authority Transitions]. A later revision maps each row to its A007–A011 code
and conformance case.

| Action | Design rule | Atomicity | Crash point after it (`pc`) |
| --- | --- | --- | --- |
| `Start(o)`: `StartEnroll`, `StartUnlink`, `StartRecover`, `StartBoot`, `StartRenew`, `StartRevoke`, `StartIssue` | The core checks the request and proposes a transition of one kind. A bootstrap takes a valid bootstrap value and binds a new administrator. `StartIssue` is the owner re-bootstrap ([AUTH Authority Transitions], selected on 2026-11-08): it plans to end the valid bootstrap value, if any. An unlink of an administrator binding keeps another administrator that the journal records as live ([AUTH Authority Transitions]). An anchor change takes its owner's turn. An unlink keeps an anchor that the journal records as live ("counts the journaled anchors that the change does not end"). A recovery binds its new anchor in the commit that consumes its value | Check and turn, one step | Before a journal write (`cChecked`) |
| `JournalEnd(o)` | Write rule: the end entry is durable before its commit. A consumption entry records its transition. An unlink ends its turn here | One journal append | Between a journal write and its commit (`cJournaled`) |
| `Commit(o)` | Serializable conditional commit of every dependency, the state change, and the outcome record ([AUTH Authority Transitions]). The record keeps the anchors of the owner that the commit leaves live (`left`): what the commit promises when it is acknowledged. An owner re-bootstrap depends on the valid bootstrap values that it checked; its commit adds a value with a new identity and ends the value that it checked. The outcome record and the audit stand for the authority's report of each issue and each consumption. Allocation floors: the floor is durable before a commit allocates a value above it | One step, because the storage contract makes the commit atomic; the floor write and the commit are one step, because the state between them differs only by a higher floor | Between a commit and its creation entry, or before the acknowledgement (`cCommitted`) |
| `Conflict(o)` | A changed dependency refuses the commit. Write rule: the refusal voids each entry of its operation before it returns | One step: a crash before the void is the crash at `journaled` | — |
| `JournalCreate(o)` | The creation entry, after its commit and before its acknowledgement. It ends the turn | One journal append | Before an acknowledgement (`cCreated`) |
| `Ack(o)` | The response, after the floor covers the artifact's value. Acknowledgement order (selected on 2026-11-08): an anchor change of an owner is acknowledged only after each other commit of that owner that created an anchor has its creation entry (`CreationPending`), so a restore keeps each anchor in the state that the acknowledged commit saw. The acknowledgement adds the anchor set of its outcome record to the promises (`promised`) | One step | — |
| `Resolve(o)` | A client whose response was lost looks up its operation identity and receives the committed outcome ([AUTH Authority Transitions]: "Resolve it through the accepted receipt/current-state contract"). A lookup that reports a commit is an acknowledgement too, so it has the same `CreationPending` guard (selected on 2026-11-08). It promises the anchor set of the outcome record that it finds: after a restore, the record of the snapshot (2026-11-09) | One step | — |
| `Crash` | A crash stops each operation in flight at its point; the store and the journal keep their durable state | One step | — |
| `Restart`, `Serve` | A start reconciles before it serves; the store serves only with no missing creation entry, no entry to void, and no in-doubt consumption | One step each | — |
| `ReconcileCreate(o)`, `ReconcileVoid(o)` | Reconciliation writes the missing creation entry of each anchor whose commit has an outcome record, and a void for each end entry whose fact does not hold in the store | One journal append each | A crash during reconciliation |
| `Redrive(o)`, `RedriveFail(o)` | Restore completes each in-doubt consumption: the first in journal order for each value commits again under its operation identity when its dependencies hold; otherwise the value stays consumed. A bootstrap value must be one that the restored store holds and that no re-bootstrap entry ended | One step each, because the commit is atomic | A crash during reconciliation |
| `Snapshot` | A snapshot with its low-water mark: the highest journal sequence at or below which every entry is reflected. It holds the outcome records with their anchor sets | One step | — |
| `Restore(s)` | Restore from any retained snapshot of a store that is down: apply each entry after the low-water mark that no void cancels, keep an ended anchor ended, raise the floor, and mark each in-doubt consumption; reconciliation follows. The store holds the snapshot's bootstrap values and outcome records, so a value issued after the snapshot is lost; consumption and re-bootstrap entries apply as facts | One step before reconciliation | — |

Merged rules, each with the same journal rule in the design:

- The authority anchors are passkeys, provider links, CLI credentials, recovery values, and
  administrator bindings (CLI credentials selected on 2026-11-08). In the model, one account
  anchor kind stands for passkeys, provider links, and recovery values: the sign-in methods and
  the values that recover them, which the last-anchor check protects. A CLI credential of an
  account has the same journal rule, but it is not a sign-in method and does not count toward the
  last sign-in method, so the model does not merge it into the account kind (that would weaken
  `AccountKeepsAnchorP`). The administrator bindings (`adm1`, `adm2`) stand for the headless CLI
  credential that a bootstrap value pays for: only a bootstrap creates one, and an unlink with
  the last-anchor check ends one. A bootstrap binds the first absent slot; the slots are
  interchangeable.
- An agent identity is not an anchor: a restore can lose an agent enrollment that came after its
  snapshot, and the agent enrolls again. A ceremony or a short-lived one-use value whose
  consumption pays for no anchor (a sign-in challenge, an operation approval) has no journal
  entry, and a restore ends it. Neither is in the model (selected on 2026-11-08).
- A bootstrap value is a random secret, so no identity repeats: `bnext` gives each issued value a
  new identity, and no restore changes it.
- Enrollment and link are one action kind (`enroll`). Credential removal and unlink are one kind
  (`unlink`).
- Session generations and grant revisions are one versioned value (`cur`, `dead`). Session
  renewal and grant change are one kind (`renew`): its entry is the death of the replaced value,
  never the new value. Revocation (`revoke`) ends the session family or grant as an identity.
- One allocation counter stands for every counter whose values appear in artifacts. The
  enrollment, recovery, bootstrap, and renewal artifacts each carry a value from it.
- A bootstrap and a recovery are the consumptions that pay for an anchor. An enrollment that
  consumes its ceremony follows the same rule; the model's enrollment consumes nothing.

## Correspondence: replay window

The source is [AUTH HTTP-Signature Replay].

| Action | Design rule |
| --- | --- |
| `Check(v)` | The verifier checks `created` against its reading plus the skew, `expires`, and the maximum window |
| `Insert(v)` | Atomic acceptance: with its own reading, the store inserts the replay identity if it is absent, above the replay floor, and the reading is before `expires` plus the skew; otherwise the verifier refuses |
| `Expire` | Retention: the record stays until the store's reading passes `expires` plus the skew and twice the uncertainty bound |
| `Start` | Restart and restore floor: the store loses its records and refuses each `created` at or below its start reading plus the skew and twice the uncertainty bound. A record that a snapshot keeps can only refuse a signature, so the model uses the case with no records |
| `Tick` | True time passes by any amount |

## Physical assumptions

Each assumption names its primary source and how the model represents it.

| Assumption | Source | In the model |
| --- | --- | --- |
| A write is durable only after its sync returns. A file's data and its directory entry need separate syncs. After a failed sync, the kernel can drop the dirty pages, so a later sync can return success for data that is lost: a binding must treat a failed sync as a crash, not retry it | [fsync(2)](https://man7.org/linux/man-pages/man2/fsync.2.html); PostgreSQL, [Fsync Errors](https://wiki.postgresql.org/wiki/Fsync_Errors) | Each journal append and each commit is one action whose end state is durable. Each crash point (`pc` values `cChecked` to `cCreated`) is between two durable steps. The binding's declaration of what a crash can lose owns the evidence that its syncs hold ([AUTH Storage Contract and Bindings], "Backend declaration") |
| A crash stops every commit in flight. For a client-server store this holds only with fencing: each start writes a new store instance number before reconciliation, and the conditional check of each commit reads it, so a late commit of an earlier instance refuses. The binding drives each commit that has a journal entry to a commit or a refusal, and a commit that it cannot finish (a timeout, a lost connection) or a failed sync counts as a crash | [AUTH Storage Contract and Bindings], "Fencing" (selected on 2026-11-08) | `Crash` moves every operation in flight to its crash point, and no later step commits it except a redrive under its operation identity after a restore. A late commit of an earlier instance is not a behavior of the model, which is correct only with fencing |
| The journal is in its own failure domain, outside the domain of the snapshots that it protects. The loss of its newest entries is outside its declared domain | [AUTH Storage Contract and Bindings], "Restore journal" and "Refusal" | `Crash` and `Restore` change no journal variable. The loss of newest entries is not modeled: a limit |
| The conditional commit is atomic over its complete dependency set: serializable isolation, or an equivalent atomic conditional commit. Snapshot isolation is not enough: it permits write skew on absence | [AUTH Storage Contract and Bindings], "Contract"; Berenson et al., [A Critique of ANSI SQL Isolation Levels](https://arxiv.org/abs/cs/0701157) (write skew, A5B) | `Commit` and `Conflict` are one step each, which read every dependency. A weaker isolation would split them; the A011 broken binding "write skew on absence" owns that failure, and this model has no variant for it |
| Each clock reading is within the uncertainty bound U of true time and is not monotonic: a system clock can step and slew | [clock_gettime(2)](https://man7.org/linux/man-pages/man2/clock_gettime.2.html) (`CLOCK_REALTIME` "is affected by discontinuous jumps"); [AUTH HTTP-Signature Replay], "Window" | `Reading(r)` takes any integer within `[now - U, now + U]`, independently for each reading. No variable keeps the last reading |
| Time has no bound between two steps of one process: a verifier can stop between its window check and its insert for any time (scheduling, a stopped virtual machine) | [RFC 9421 section 7.2.2](https://www.rfc-editor.org/rfc/rfc9421.html#section-7.2.2) (a creation time limits validity; it does not prevent repetition) | `Tick` adds any positive amount, at any point. This is the cause of F2: no retention alone covers the time between `Check` and `Insert` |
| A client can lose its state and its response at any point, and can come back later to look up its outcome | [AUTH Authority Transitions] ("A lost response can mean the transition committed"); [draft-ietf-httpapi-idempotency-key-header-08](https://datatracker.ietf.org/doc/draft-ietf-httpapi-idempotency-key-header/) | `Crash` stops each operation at its point; `Resolve` is the later lookup. A client that never looks up stays at its crash point. The client rule (a client stores an anchor's private part before it submits) has no variable: the model has no keys |
| Only the local application owner can issue an owner re-bootstrap, through the host/origin grant that opens local authority | [AUTH Authority Transitions], "Owner re-bootstrap" | The model has no authentication: any operation can issue. That adds behaviors, so it also covers an attacker who holds the owner's grant |
| The attacker holds a one-use value, or raced for it and lost. It acts after a restore as any client can | [NIST SP 800-63B-4](https://pages.nist.gov/800-63-4/sp800-63b.html), sec. 4.2.1.1 (a recovery code is invalidated after use) | `Start` does not tell a user from an attacker: any operation can consume any value that its check accepts. `Turn = "entry"` lets two consumptions of one value race. `OneUse` and `RefusalHolds` are the checks |

**Fairness.** No property needs progress, so the models state no fairness: each property is an
invariant, and TLC's deadlock check stays on (a crash is always possible, so no state is
terminal). Availability is a state predicate instead: `AdminKeptP` and `AccountKeepsAnchorP`
hold while the store serves (`phase = "up"`), and `Serve` needs reconciliation and each redrive
to be complete. The model claims no "eventually serves". Reconciliation ends: each of its steps
removes one need (a missing creation entry, an entry to void, or an in-doubt consumption), a
redrive adds at most one missing creation entry, and journal order picks one first consumption
for each value. That is an argument, not a check.

## Bounds, faults, and reductions

- Authority: two accounts (three anchor slots in `a1` and two in `a2`; `a1p`, `a1q`, `a1r`, and
  `a2p` live at the start), the administrator binding, three operation identities, and at most
  two snapshots, with two administrator slots and at most one owner re-bootstrap in each run (an
  owner event with no bound in the design), from either origin. A completion that a crash stops
  before its creation entry runs again after the
  next restore and allocates a new value each time, so the counter needs a bound: values up to 5
  for the declared search (one value again after three allocations), up to 4 for the local bound.
  With two anchor slots, no second unlink can make the first one refuse, so F3 needs three. Each
  bound is a state constraint, so a TLC pass is a complete search of the bounded space only. The
  Apalache proofs have no counter, journal, or re-bootstrap bound. An operation identity starts
  once and commits through `Commit` once, and a snapshot is never removed, so the operation and
  snapshot bounds count all the operations and snapshots of a run; the proofs hold for any number
  of crashes, restarts, restores, and reconciliation steps over them.
- Faults: a crash at each point in the correspondence table, restart, restore from any retained
  snapshot, a commit conflict, a lost response, and a crash during reconciliation.
- Replay: one signature with symbolic `created` and `expires`, symbolic non-negative `Skew`, `U`,
  and `MaxWin`, and integer time with no bound.
- The reduction to one account (selected on 2026-11-08) and the TLC raise searches were removed on
  2026-11-09: the raised proof covers each bound ([Raise by one](#raise-by-one)).

Each reduction names the failure that it could hide, and a known-bad variant with that failure
still fails under it ([FP Design Models]):

| Reduction | The failure that it could hide | Known-bad variant that still fails |
| --- | --- | --- |
| Operations start in identity order (`Rank`); the identities are interchangeable | A race that needs a later identity to start first | `RefusalNoVoid_bad`, `RaceNoVoid_bad`, and `Unserialized_bad` need two or three concurrent operations |
| One account anchor kind for passkeys, provider links, and recovery values; the administrator bindings for the bootstrapped CLI credential | A journal rule that differs by kind | The design gives the kinds one rule; `IgnoreVoids_bad` (unlink) and `NoAgainAccount_bad` (recovery) fail on the one kind |
| One counter for every counter | Two counters with one floor | Each counter has its own floor with one rule; `NoFloor_bad` and `FloorAtRelease_bad` fail |
| Session generations and grant revisions as one versioned value, whose entry is the death of the replaced value | A renewal that journals the new value | `NoJournal_bad` fails on any end entry; a renewal that journals the new value is A009's wrong-implementation case |
| The floor write and the commit are one step | A value released before its floor is durable | `FloorAtRelease_bad` fails |
| A lost response leaves the store state, and the client resolves it by lookup (`Resolve`) | A release through the lookup path. The first model had no lookup, and this hid F4 | `FloorAtRelease_bad` fails only through `Resolve` |
| The model keeps every journal entry; retention reaches each retained snapshot's low-water mark | A gap in the journal | `NoJournal_bad` fails; the refusal for a gapped journal is a conformance case |
| One replay signature stands for each identity, and a restart loses every record | Interaction between records, and a kept record | Records of different identities share only the capacity bound (A409); `FloorNoSkew_bad` fails |
| A bootstrap binds the first absent administrator slot | A failure that depends on which slot a bootstrap takes | The slots are interchangeable; `NoAgainAdmin_bad` fails, and `AdminReplaced_reach` reaches a new binding in the second slot |
| At most one owner re-bootstrap in each run | A failure that needs two re-bootstraps | Each re-bootstrap ends the valid value and adds one, so a second one repeats the first one's step; `IssueNoEnd_bad` and `IssueNoJournal_bad` fail with one |

## Properties for the conformance suite (A011)

| Property | Module | Conformance case |
| --- | --- | --- |
| `NothingEndedValid` | Authority | Restore with no resurrected revocation, grant revision, or one-use material; no restore makes an ended bootstrap value valid again; restore without its journal (broken binding) |
| `NoCounterReuse` | Authority | Restore raises each allocation floor above every released value; a restore from a snapshot of an abandoned history releases no counter value twice |
| `MissingOutcomeUnknown` | Authority | Restore returns unknown for a missing outcome; lost outcome records (broken binding) |
| `NoUncommittedAnchor` | Authority | No anchor from an uncommitted creation |
| `AnchorKept` | Authority | Restore keeps each anchor created after the snapshot; a commit that returned its refusal leaves no entry that applies at restore; a lookup after a restore reports the anchor set of the outcome record that it finds |
| `AccountKeepsAnchorP` | Authority | No restore leaves a serving store with an account that has no sign-in method; restore completes an in-doubt recovery once |
| `AdminKeptP` | Authority | The serving authority has an administrator while the store holds a consumed bootstrap value that no re-bootstrap ended; restore completes an in-doubt bootstrap once |
| `OneBootValid` | Authority | An owner re-bootstrap ends the earlier bootstrap value; at most one bootstrap value is valid |
| `RefusalHolds` | Authority | A refusal that reached its client never commits later. After a crash between the refusal and its void, the outcome is unknown, and the memory binding injects that crash |
| `OneUse`, `PendExact` | Authority | Concurrent consumption; at most one commit spends each value in a store's history |
| `NoDoubtServing` | Authority | The store serves only after each in-doubt consumption completes or stays consumed |
| `NoDoubleAccept` | Replay | Replay record insert; an insert after `expires` plus the skew refuses; restart and restore floor |
| `NoLiveRemoved` | Replay | Incremental expiry |

## Decisions

The user selected each rule below on 2026-11-07, except the owner re-bootstrap, which the user
selected on 2026-11-08. The design text is in
[AUTH Storage Contract and Bindings], [AUTH Authority Transitions], and
[AUTH HTTP-Signature Replay].

- **F1, lockout after a restore: restore completes the in-doubt transition (option b').** A
  bootstrap or a recovery consumes a one-use value and creates an anchor in one commit, but the
  journal recorded the two halves with opposite presumptions: the consumption entry before the
  commit applies unless a void cancels it, and the creation entry after the commit is absent
  unless written. After a restore, the outcome is unknown, so restore applied half of one
  transaction. Now the consumption entry records its whole transition, and before the restored
  store serves, the first in-doubt consumption of each value commits again under its operation
  identity when its dependencies hold (`Redrive`). This maps a restored in-doubt state onto one
  that the store already handles: "the commit succeeded and the response was lost". The client
  stores the private part of the anchor before it submits, so that the completed anchor is usable.
- **F2, one signature accepted twice: the insert refuses once the store's reading reaches
  `expires` plus the skew.** No rule at expiry alone can work, because the time between the
  window check and the insert has no bound. `expires` plus the skew is the latest threshold that
  the retention `expires + Skew + 2U` allows (`InsertLate_bad` moves it one bound later and
  fails). The check adds no refusal where the window check promises acceptance: a refusing
  reading `r >= expires + Skew` puts true time at or past `expires - U`, where a verifier's own
  reading can already refuse.
- **F3, a refused unlink applied at restore: a refusal voids its entries before it returns.** It
  is the abort record of presumed-commit logging. It costs one write, on the refusal path only.
- **F4, a counter value released twice across two restores: the floor is durable before the
  commit,** not only before the release. Block reservation keeps it at one write for each block.
- **Reconciliation: void by fact.** Reconciliation voids an end entry only when its fact does
  not hold in the store. It needs no outcome lookup, no activation mark, and no restored flag,
  and outcome-record retention does not affect it.
- **The last-anchor check** counts the journaled anchors that the change does not end, and each
  anchor that the same commit creates when that commit consumes the value that pays for it. A
  recovery binds at least one new anchor in the commit that consumes its value.
- **Model bounds (A6):** three anchor slots in one account at the declared bounds, because F3 is
  unreachable with two. The inductive proof covers every safety property that could be made
  inductive, and each inductive check has a vacuity witness (E1: with `Gen(2)` for snapshots,
  the starting set contained no snapshot, so the step check never covered `Restore`).

- **Owner re-bootstrap** (selected on 2026-11-08). Only the local application owner, through the
  host/origin grant that opens local authority, issues a new one-use bootstrap value. Its commit
  ends each earlier value that is not consumed, with a journaled end entry, so at most one value
  is valid. The value is not an anchor and has no creation entry: a restore loses a value issued
  after its snapshot, and the owner issues again. Its consumption is as for the first bootstrap.
  The new administrator ends a lost or compromised binding through an unlink with the
  last-anchor check. In the model, availability then has a precise form: `AdminKeptP` holds while
  the store holds a consumed bootstrap value that no re-bootstrap ended. When an in-doubt
  consumption and an in-doubt re-bootstrap name the same value, a restore applies both entries,
  the completion's dependency fails (the value is ended), and the authority has no administrator
  from that value; the local owner issues a new value. The design gives that path, so it is not a
  defect.
- **Acknowledgement order of anchor changes** (selected on 2026-11-08; found by
  `Authority.RaiseOpsOne.cfg`). An unlink checked its kept anchor and committed while an
  enrollment of the same account had committed but not yet written its creation entry; the
  unlink was acknowledged with that new anchor in the state that it saw, and a restore then
  removed the new anchor, because it had no creation entry. Now the binding acknowledges an anchor
  change of an owner, and a lookup reports it, only after each other commit of that owner that
  created an anchor has its creation entry (`CreationPending` on `Ack` and `Resolve`). The
  known-bad variant `ackEarly` keeps the old order and fails `AnchorKept` under the reduction and
  on both accounts.
- **The reduction to one account** (selected on 2026-11-08) for the raise of the operations,
  with a free slot in the account. Removed on 2026-11-09 with the TLC raise searches: the raised
  proof covers the raise of the operations (below).

Selected on 2026-11-09, task A016. The user selected the approach; each finding below changed the
model, and no design rule changed.

- **The anchor set of each outcome record (finding).** `left`, the anchors of its owner that a
  commit leaves live, was a history variable of each operation identity, and `Promised` took it
  for each acknowledged identity. An identity commits twice when a restore loses its first
  commit and a redrive commits it again, and the redrive replaced `left`. A client that resolved
  the identity against a restore of a snapshot that recorded the first commit was then promised
  the anchors of the second. The proof found this: no inductive form held for the snapshot copy
  of the promise. Now the outcome record keeps the anchor set, a restore brings back the records
  of its snapshot, and the history variable `promised` collects the anchor set of each
  acknowledgement and each lookup. No completed TLC search had reached the gap, and every
  property still holds. The promise is now exact, and the TwoOps search has 601,942 distinct
  states against 602,230 before, because a restore now brings back the anchor sets with their
  records.
- **`Uncertain` needs the end entry (finding).** `AnchorKept` excuses an anchor that an
  in-doubt end entry ended (`Uncertain`). The excuse also covered an operation that crashed
  before it wrote its end entry, which cannot have ended anything. Now `Uncertain` requires the
  entry, so `AnchorKept` is stronger, and every search and proof passes with it.
- **The proof replaces the TLC raises.** `IndInv` implies every property, and the raised
  proofs check it with each domain raised by one. That is the raise of each bound that rule 4 of
  [FP Design Models] asks for, so the eight TLC raise searches and the reduction to one account,
  which existed only for the raise of the operations, are removed.
- **Two grouped raises** (selected on 2026-11-10). With every domain raised at once (four
  operations, three accounts, twelve anchors, three snapshots), five step profiles ran more than
  one hour on their first or second query, against the budget rule. Rule 4 asks for each bound
  raised by one, not all at once, so the raise runs in two groups: the anchor domains (accounts,
  slots, administrator slots) in `AuthorityIndAnchors`, and the process domains (operations,
  snapshots, bootstrap values) in `AuthorityIndProcess`. Each group covers each single raise in
  it and each pair inside it.
- **The form of the proof checks.** Four changes make each check finish in the budget, and none
  makes a check weaker: the starting set gives each function the fixed domain of its variable
  (the earlier generated domains kept the raised step parts in one solver query); a step check
  states `IndInv'` as action invariants, which Apalache checks after the transition only, since
  each state of the starting set is a state of `IndInv`; each step part is one action, and each
  has two profiles, one for the restore parts of `IndInv` and one for the others; and the
  snapshot set of the starting set is one choice, not one transition for each count of
  snapshots. [Inductive proofs](#inductive-proofs) gives the measured effects.
- **The cross-account known-bad variant `ownMark`.** A store that keeps one low-water mark for
  each account, and stamps a snapshot with the mark of one account, misses the in-flight end
  entries of the others. `Authority.OwnMark_bad.cfg` violates `NothingEndedValid` with two
  accounts, and `AuthorityInd.SnapshotOwnMark_bad.apalache` shows that the snapshot step of the
  proof breaks `EndInv` under it. With one account, the variant is the design, so the one-account
  reduction hid this failure.

Rejected options. Their files were never committed; this record replaces them.

- **(b) A retry by the client of the same operation** (rejected on 2026-11-07). The in-doubt
  consumption stays pending while the store serves, and only a retry with the same operation
  identity and request binding can spend the value. It passed every property in its checked
  form (`InDoubtRetry_proposal`, 448,356 states, and its inductive steps), with availability only
  as "or a pending retry". It needs client state and a pending marker, and the lockout stays when
  a client lost its state, for example a CLI that bootstraps. (b') needs neither.
- **(d) An out-of-band backstop as the fix** (rejected as a fix on 2026-11-07). A human procedure
  for the local owner changes nothing in the write path, and until a human acts, the lockout
  stays. The owner re-bootstrap of 2026-11-08 is now that backstop for the administrator, for
  example when a client lost the private part of its anchor.
- **Reconciliation that trusts a missing outcome at a normal start** (the first reading of the
  reconciliation item, rejected on 2026-11-07). Read as "never void after any restore", it is
  safe, but after the first restore no start voids an entry again, so an unlink that crashed
  before its commit ends its anchor at each later restore. Read as "a normal start trusts a
  missing outcome again", it is unsafe: `VoidOnMissing_bad` keeps that reading and violates
  `NothingEndedValid` (an unlink commits; a restore from a snapshot before it applies its entry
  and loses its outcome record; a normal start voids the entry; a second restore makes the ended
  anchor live).
- **(a) Restore applies the pair entry** and **(c) the consumption entry after the commit** fail
  a security property. They stay as known-bad variants: `PairApplies_bad` (an attempt that lost
  its race, or crashed before its dependency check, gets its anchor; `NoUncommittedAnchor`) and
  `AfterCommit_bad` (a used recovery code works again after a crash between the commit and its
  entry; `NothingEndedValid`).

## Known-bad variants

Each variant changes one rule through the constant `Bad` (or `Turn`), and its profile checks only
its own property. The results are those of the evidence run of the current files
([Evidence record](#evidence-record)): distinct states and depth at the violation, and the time
that the xtask printed.

| Profile | Changed rule | Must violate | Origin, bound | Result |
| --- | --- | --- | --- | --- |
| `Authority.AfterCommit_bad.cfg` | Option (c): the consumption entry comes after the commit | `NothingEndedValid` | new, TwoOps | `NothingEndedValid` violated (12), as required, 5,649 (7), 1.55 s |
| `Authority.CreateBeforeCommit_bad.cfg` | A creation entry before its commit | `NoUncommittedAnchor` | new, TwoOps | `NoUncommittedAnchor` violated (12), as required, 1,931 (6), 1.22 s |
| `Authority.FloorAtRelease_bad.cfg` | F4: the floor is durable at the release, not at the commit | `NoCounterReuse` | new, TwoOps | `NoCounterReuse` violated (12), as required, 461,992 (18), 20.27 s |
| `Authority.IgnoreVoids_bad.cfg` | Restore applies voided entries | `AnchorKept` | new, TwoOps | `AnchorKept` violated (12), as required, 17,920 (9), 2.00 s |
| `Authority.IssueNoEnd_bad.cfg` | An owner re-bootstrap that does not end the earlier value (2026-11-08) | `OneBootValid` | new, TwoOps | `OneBootValid` violated (12), as required, 444 (5), 0.71 s |
| `Authority.IssueNoJournal_bad.cfg` | An owner re-bootstrap whose end of the earlier value has no journal entry (2026-11-08) | `NothingEndedValid` | new, TwoOps | `NothingEndedValid` violated (12), as required, 5,783 (8), 1.37 s |
| `Authority.LookupAbsent_bad.cfg` | A missing outcome after restore reads as absent | `MissingOutcomeUnknown` | new, TwoOps | `MissingOutcomeUnknown` violated (12), as required, 5,201 (7), 1.38 s |
| `Authority.NoAgainAccount_bad.cfg` | F1: restore leaves an in-doubt recovery unresolved | `AccountKeepsAnchorP` | new, TwoOps | `AccountKeepsAnchorP` violated (12), as required, 9,245 (8), 1.84 s |
| `Authority.NoAgainAdmin_bad.cfg` | F1: restore leaves an in-doubt bootstrap unresolved (the design before 2026-11-07) | `AdminKeptP` | new, TwoOps | `AdminKeptP` violated (12), as required, 11,112 (9), 1.64 s |
| `Authority.NoFloor_bad.cfg` | Restore does not raise the allocation floor | `NoCounterReuse` | new, TwoOps | `NoCounterReuse` violated (12), as required, 223,428 (14), 7.38 s |
| `Authority.NoJournal_bad.cfg` | Restore without its journal | `NothingEndedValid` | new, TwoOps | `NothingEndedValid` violated (12), as required, 4,338 (7), 1.36 s |
| `Authority.OwnMark_bad.cfg` | `ownMark`: the low-water mark counts the entries of `a1` and the authority only (2026-11-09) | `NothingEndedValid` | new, TwoOps | `NothingEndedValid` violated (12), as required, 11,443 (8), 1.34 s |
| `Authority.PairApplies_bad.cfg` | Option (a): restore applies the pair and creates the anchor at once | `NoUncommittedAnchor` | new, TwoOps | `NoUncommittedAnchor` violated (12), as required, 3,327 (7), 1.48 s |
| `Authority.RaceNoVoid_bad.cfg` | F3 with `Turn = "entry"` | `RefusalHolds` | new, TwoOps | `RefusalHolds` violated (12), as required, 58,066 (11), 3.72 s |
| `Authority.RefusalNoVoid_bad.cfg` | F3: a refusal writes no void | `AnchorKept` | new, TwoOps | `AnchorKept` violated (12), as required, 29,252 (10), 2.47 s |
| `Authority.SlotsA1AckEarly_bad.cfg` | `ackEarly`: an anchor change is acknowledged before the creation entry of another anchor commit of its owner (the order before 2026-11-08), with the fourth slot of `a1` | `AnchorKept` | new, TwoOps | `AnchorKept` violated (12), as required, 62,357 (10), 4.75 s |
| `Authority.Unserialized_bad.cfg` | Anchor changes of one account take no turn | `AccountKeepsAnchorP` | new, Declared | `AccountKeepsAnchorP` violated (12), as required, 1,663,506 (11), 68.33 s |
| `Authority.VoidOnMissing_bad.cfg` | Reconciliation voids on a missing outcome at a normal start after a restore | `NothingEndedValid` | new, TwoOps | `NothingEndedValid` violated (12), as required, 148,103 (13), 7.31 s |
| `AuthorityInd.SnapshotOwnMark_bad.apalache` | `ownMark` in the snapshot step of the proof (2026-11-09) | `EndInvPost` | declared domains | `EndInvPost` violated, as required (round 6; the time is not kept) |
| `Replay.FloorNoSkew_bad.apalache` | A restart floor without the skew | `NoDoubleAccept` | — | `NoDoubleAccept` violated, as required, 6.42 s (A000 record; `Replay.tla` is unchanged) |
| `Replay.InsertLate_bad.apalache` | The insert threshold one bound later (`expires + Skew + U`) | `NoDoubleAccept` | — | `NoDoubleAccept` violated, as required, 6.89 s (A000 record; `Replay.tla` is unchanged) |
| `Replay.NoInsertCheckDouble_bad.apalache` | F2: no insert check (the design before 2026-11-07) | `NoDoubleAccept` | — | `NoDoubleAccept` violated, as required, 6.74 s (A000 record; `Replay.tla` is unchanged) |
| `Replay.NoInsertCheckLive_bad.apalache` | F2: no insert check | `NoLiveRemoved` | — | `NoLiveRemoved` violated, as required, 6.70 s (A000 record; `Replay.tla` is unchanged) |
| `Replay.RetentionOneU_bad.apalache` | Retention with one uncertainty bound | `NoLiveRemoved` | — | `NoLiveRemoved` violated, as required, 5.93 s (A000 record; `Replay.tla` is unchanged) |

The counterexample of `ackEarly`, from the search of `Authority.RaiseOpsOne.cfg` on 2026-11-08
that found it (that search is removed; `SlotsA1AckEarly_bad` keeps the failure): `StartUnlink(o1)` (an unlink in `a1` that keeps another anchor), `JournalEnd(o1)`,
`StartEnroll(o2)` (an enrollment of the free slot `a1s`), `Snapshot`, `Commit(o2)` (`a1s` is
live, and its creation entry is still to come), `Commit(o1)`, `Ack(o1)` (its commit saw `a1s`,
so `a1s` is in the anchors that the acknowledged commit left), `Crash`, `Restore`. Then `a1s` has
no creation entry, so the restore makes it absent, and `AnchorKept` fails. With `CreationPending`,
`Ack(o1)` waits for the creation entry of `o2`, and a crash before it leaves `o1` unacknowledged.

The counterexamples, as actions and the observation that breaks the property. They are the traces
of the record of 2026-11-08; the current traces differ only where the searches reach their
violation in another order:

- `Authority.AfterCommit_bad.cfg`: `Start(o1)` bootstrap of value 1 binds adm1, `Snapshot`, `Commit(o1)`, `Crash`, `Restore`. Then a consumption commits with no entry before its commit and crashes before its only entry; the restore from the snapshot before it makes the consumed value valid again.
- `Authority.CreateBeforeCommit_bad.cfg`: `Start(o1)` enroll makes a2q, `JournalEnd(o1)`, `Snapshot`, `Crash`, `Restore`. Then an enrollment writes its creation entry before its commit; a crash before the commit and a restore make the anchor live with no commit.
- `Authority.FloorAtRelease_bad.cfg`: `Start(o1)` enroll makes a2q, `Snapshot`, `Commit(o1)`, `JournalCreate(o1)`, `Snapshot`, `Crash`, `Restore`, `Serve`, `Start(o2)` renew, `JournalEnd(o2)`, `Commit(o2)`, `Ack(o2)`, `Crash`, `Restore`, `Serve`, `Resolve(o1)`. Then a commit after the first snapshot allocates value 2 with no floor write; a restore from the older snapshot lets another operation release value 2; a restore from the newer snapshot brings back the first commit, whose client then receives value 2 by lookup.
- `Authority.IgnoreVoids_bad.cfg`: `Start(o1)` unlink a1q keeps a1p, `JournalEnd(o1)`, `Snapshot`, `Crash`, `Restart`, `ReconcileVoid(o1)`, `Crash`, `Restore`. Then a normal start voids the entry of an unlink that did not commit; a restore applies the voided entry and ends an anchor that the store kept.
- `Authority.IssueNoEnd_bad.cfg`: `Start(o1)` owner re-bootstrap, `Commit(o1)`. Then the re-bootstrap commits while the first value is valid and ends nothing, so two bootstrap values are valid.
- `Authority.IssueNoJournal_bad.cfg`: `Start(o1)` owner re-bootstrap ends value 1, `Snapshot`, `Commit(o1)`, `Crash`, `Restore`. Then the re-bootstrap ends the first value with no journal entry; the restore from the snapshot before it makes the first value valid again.
- `Authority.LookupAbsent_bad.cfg`: `Start(o1)` enroll makes a2q, `Start(o2)` unlink a1r keeps a1p, `Snapshot`, `Commit(o1)`, `Crash`, `Restore`. Then a commit after the snapshot loses its outcome record at the restore, and its lookup reads absent.
- `Authority.NoAgainAccount_bad.cfg`: `Start(o1)` recover a2p makes a2q, `JournalEnd(o1)`, `Snapshot`, `Crash`, `Restore`, `Serve`. Then the recovery's end entry applies at the restore, its new anchor does not, and the serving store has no anchor for the account.
- `Authority.NoAgainAdmin_bad.cfg`: `Start(o1)` bootstrap of value 1 binds adm1, `JournalEnd(o1)`, `Snapshot`, `Crash`, `Restore`, `Serve`. Then the bootstrap's consumption entry applies at the restore, its commit does not, and the serving authority has a consumed bootstrap value and no administrator.
- `Authority.NoFloor_bad.cfg`: `Start(o1)` enroll makes a2q, `Snapshot`, `Commit(o1)`, `JournalCreate(o1)`, `Ack(o1)`, `Crash`, `Restore`, `Serve`, `Start(o2)` renew, `JournalEnd(o2)`, `Commit(o2)`, `Ack(o2)`. Then a commit releases value 2; a restore from an older snapshot keeps the counter at 1, and another operation releases value 2 again.
- `Authority.NoJournal_bad.cfg`: `Start(o1)` unlink a1r keeps a1p, `JournalEnd(o1)`, `Snapshot`, `Commit(o1)`, `Crash`, `Restore`. Then a commit after the snapshot ends a value or an anchor; a restore without the journal makes it valid again.
- `Authority.OwnMark_bad.cfg`: `Start(o1)` recover a2p makes a2q, `JournalEnd(o1)`, `Snapshot`, `Commit(o1)`, `Crash`, `Restore`. Then the snapshot's mark counts no entry of `a2`, so it is at or above the recovery's end entry; the restore skips the entry, and the used recovery value `a2p` works again.
- `Authority.PairApplies_bad.cfg`: `Start(o1)` recover a2p makes a2q, `JournalEnd(o1)`, `Snapshot`, `Crash`, `Restore`. Then a consumption that crashed before its commit gets its new anchor at the restore with no commit.
- `Authority.RaceNoVoid_bad.cfg`: `Start(o1)` recover a2p makes a2q, `JournalEnd(o1)`, `Start(o2)` enroll makes a2q, `Snapshot`, `Commit(o2)`, `Conflict(o1)`, `Crash`, `Restore`, `Redrive(o1)`. Then a consumption refuses after another commit changed its dependency; with no void, the restore puts the refused consumption in doubt, and the redrive commits it.
- `Authority.RefusalNoVoid_bad.cfg`: `Start(o1)` unlink a1q keeps a1p, `JournalEnd(o1)`, `Start(o2)` unlink a1p keeps a1r, `Snapshot`, `JournalEnd(o2)`, `Commit(o2)`, `Conflict(o1)`, `Crash`, `Restore`. Then one unlink commits, the other refuses, and the restore applies the refused unlink's entry, so the anchor that its client was told stays ends.
- `Authority.Unserialized_bad.cfg`: `Start(o1)` unlink a1r keeps a1p, `JournalEnd(o1)`, `Start(o2)` unlink a1q keeps a1p, `Start(o3)` unlink a1p keeps a1q, `JournalEnd(o2)`, `JournalEnd(o3)`, `Snapshot`, `Crash`, `Restore`, `Serve`. Then three unlinks of `a1` each keep another anchor that the journal records as live; a crash before the commits and a restore apply all three ends, and the serving store has no anchor for `a1`.
- `Authority.VoidOnMissing_bad.cfg`: `Start(o1)` unlink a1r keeps a1p, `JournalEnd(o1)`, `Snapshot`, `Commit(o1)`, `Crash`, `Restore`, `Crash`, `Restart`, `ReconcileVoid(o1)`, `Crash`, `Restore`. Then a commit loses its outcome record at a restore; a normal start voids its entry; a second restore makes what it ended valid again.
- `Replay.FloorNoSkew_bad.apalache`: a signature accepted before a start is above the floor that the start sets with no skew, and it is accepted again.
- `Replay.InsertLate_bad.apalache`: after an expiry, an insert with a store reading below the late threshold accepts the signature a second time.
- `Replay.NoInsertCheckDouble_bad.apalache`: a verifier waits between its window check and its insert while the record expires, then accepts the same signature a second time.
- `Replay.NoInsertCheckLive_bad.apalache`: expiry removes a record while a verifier that holds a check can still insert it.
- `Replay.RetentionOneU_bad.apalache`: expiry removes a record while a verifier reading at that time still passes the window.

## Reachability

Each witness passes only when the checker reaches its target: it reports the witness's
`Not<Target>` invariant as violated. The results are those of the evidence run of the current
files.

| Profile | Target | Origin, bound | Result |
| --- | --- | --- | --- |
| `Authority.AccountAfterDoubt_reach.cfg` | F1: after an in-doubt recovery and a restore, the serving store has the new anchor | new, TwoOps | `NotAccountAfterDoubt` violated (12), the target is reached, 39,202 (10), 3.13 s |
| `Authority.AdminAfterDoubt_reach.cfg` | F1: after an in-doubt bootstrap and a restore, the serving store has its administrator | new, TwoOps | `NotAdminAfterDoubt` violated (12), the target is reached, 43,463 (10), 2.56 s |
| `Authority.AdminReplaced_reach.cfg` | The administrator of a re-bootstrap ends the earlier administrator binding through an unlink (2026-11-08) | bootstrapped, Declared | `NotAdminReplaced` violated (12), the target is reached, 645,883 (10), 12.76 s |
| `Authority.CrashBeforeAck_reach.cfg` | Restore after a crash before an acknowledgement | new, TwoOps | `NotRestoreAfterCrashBeforeAck` violated (12), the target is reached, 14,506 (8), 2.25 s |
| `Authority.CrashBeforeCommit_reach.cfg` | Restore after a crash between a journal write and its commit | new, TwoOps | `NotRestoreAfterCrashBeforeCommit` violated (12), the target is reached, 4,739 (7), 1.44 s |
| `Authority.CrashBeforeCreation_reach.cfg` | Restore after a crash between a commit and its creation entry | new, TwoOps | `NotRestoreAfterCrashBeforeCreation` violated (12), the target is reached, 11,540 (8), 1.71 s |
| `Authority.CrashBeforeJournal_reach.cfg` | Restore after a crash before a journal write | new, TwoOps | `NotRestoreAfterCrashBeforeJournal` violated (12), the target is reached, 3,887 (7), 1.34 s |
| `Authority.IssueEndApplied_reach.cfg` | A restore applies the end entry of an owner re-bootstrap whose commit is not known (2026-11-08) | new, TwoOps | `NotIssueEndApplied` violated (12), the target is reached, 12,830 (9), 1.85 s |
| `Authority.Rebootstrapped_reach.cfg` | After the first bootstrap value was consumed, an owner re-bootstrap gives the authority a new administrator (2026-11-08) | bootstrapped, TwoOps | `NotRebootstrapped` violated (12), the target is reached, 9,021 (9), 1.60 s |
| `Authority.ReconciledCreate_reach.cfg` | Reconciliation writes the creation entry of a crashed commit | new, TwoOps | `NotReconciledCreate` violated (12), the target is reached, 5,591 (7), 1.62 s |
| `Authority.ReconciledVoid_reach.cfg` | Reconciliation voids the entry of a crashed operation that did not commit | new, TwoOps | `NotReconciledVoid` violated (12), the target is reached, 5,828 (7), 1.40 s |
| `Authority.RefusedKept_reach.cfg` | F3: a refused unlink voided its entry, and a restored store keeps its anchor | new, TwoOps | `NotRefusedKept` violated (12), the target is reached, 57,922 (11), 3.52 s |
| `Authority.TwoInDoubt_reach.cfg` | `Turn = "entry"`: two consumptions of one value in doubt at one restore | new, TwoOps | `NotTwoInDoubt` violated (12), the target is reached, 16,962 (9), 2.25 s |

## Inductive proofs

`AuthorityInd.tla` proves every property of `Safety` with counter values, journal sequences, and
bootstrap-value identities as unbounded integers, for both origins: `NothingEndedValid`,
`OneBootValid`, `NoCounterReuse`, `MissingOutcomeUnknown`, `NoUncommittedAnchor`,
`RefusalHolds`, `OneUse`, `PendExact`, `NoDoubtServing`, and, since 2026-11-09 (A016),
`AnchorKept`, `AccountKeepsAnchorP`, and `AdminKeptP`. Its scope is exact: an operation identity
starts once and commits through `Commit` once, and a snapshot is never removed, so the proof
covers any number of crashes, restarts, restores, redrives, and reconciliation steps over at
most three operations and two snapshots in a run, and at most three values in each set of
bootstrap values (four operations, three snapshots, and four values in `AuthorityIndProcess`). That is the domain of rule 4 of
[FP Design Models]. A proof for any number of operations would need identities that are used
again and a journal that is a set of entries; rule 4 does not ask for it.

The invariant has seventeen parts. The eight parts of A000 are `TypeInd`, `JournalInv` (the
journal and the history; since 2026-11-09 also the order of entries: each has its own sequence
number, and an operation's entries come in the order of its steps), `EndInv` (committed ends hold in the store and in each later
snapshot), `OutcomeInv` (outcome records are commits), `DoubtInv` (the in-doubt state),
`AnchorInv` (created anchors against each snapshot's low-water mark), `BootInv` (at most one
valid bootstrap value), and `CounterInv` (artifact values against the counter and the floor).
Nine parts are for the anchor properties (2026-11-09):

| Part | What it states | Why the anchor properties need it |
| --- | --- | --- |
| `AnchorStateInv` | An anchor that the journal records as made or as ended, or that an operation in flight ends, is never absent. An ended anchor was ended by a commit or by an in-doubt end entry, in the store and in each snapshot. An operation that stopped at its check wrote no entry, and each entry of an operation in flight comes after each entry of a crashed operation | A restore cannot make a promised anchor absent, and an ended anchor stays ended. The order of entries is what a crash leaves, and it ties each kept anchor to the unlinks that came before it |
| `PromiseInv` | Each promised anchor has a journaled creation. Each live anchor, and each anchor that an outcome record left, has one, or a commit in the record made it and its creation entry is still due; while the store serves, that commit is in flight | With `CreationPending`, an acknowledgement promises only journaled anchors, and a restore applies or keeps each journaled creation |
| `KeptNowInv` | Each account has a live anchor, and the authority has an administrator while it holds a consumed bootstrap value, or an in-doubt recovery or bootstrap makes one before the store serves | `AccountKeepsAnchorP` and `AdminKeptP`: while the store serves, nothing is in doubt |
| `RestoreAccountInv`, `RestoreAdminInv` | The same through a restore from each retained snapshot: what the restore gives now, from the snapshot and the entries after its low-water mark, with its in-doubt consumptions; one part for the accounts, one for the authority | A crash can come at any step, and the restore then sets the store |
| `RestoreNowAccountInv`, `RestoreNowAdminInv` | The same for the snapshot that the serving store takes now | The snapshot step keeps the two restore parts |
| `TurnInv` | The owner's turn has one holder between its check and the end of its turn. An unlink keeps an anchor that the journal records as live; that anchor's creation stays journaled, and each end entry of it that counts comes after the unlink's own, while the unlink's end entry counts. A consumption in its turn has no rival commit of its value, and its new anchor has no entry | An end entry that ends the last anchor of a restore comes with a kept anchor, or with an in-doubt consumption that makes one |
| `ServingInv` | Each snapshot is a copy of a serving store. While the store serves, the end entry of each crashed operation that no void cancels holds in the store | Reconciliation left no stale entry that a later void could turn into a lockout |

`AuthorityInd.Safety.apalache` checks that `IndInv` implies each property of `Safety`, the three anchor
properties included.

How the parts were found: each candidate clause first passed `Authority.TwoOps.cfg`,
`Authority.TwoOpsBootstrapped.cfg`, and `Authority.Race.cfg` as a TLC invariant, so it holds in
each reachable state of those bounds. Then each counterexample to induction of a step check,
first on a domain of one account, two operations, and one snapshot, gave a clause that excludes
an unreachable starting state. One counterexample was not of that kind: it showed the gap of the
outcome record's anchor set ([Decisions](#decisions)).

The starting set `IndStart(n)` gives each function the fixed domain of its variable and each
value in it a free choice. Each snapshot is one record of its own fields, and the snapshot set is
one choice among the sets of up to `NSnaps` snapshots. `n` bounds each set of bootstrap values (3,
and 4 in `AuthorityIndProcess`). Until 2026-11-09, `Gen` built each function with a domain of its own, and the
solver had to prove that domain equal to the fixed one: each raised step part stayed in one query
of its starting set. Apalache checks each part of `IndInv` after the step as an action invariant
(`<Part>Post == <Part>'`), so it does not check the starting state, which is a state of `IndInv` by
its definition. As one choice, the snapshot set gives the start one transition: as one transition
for each number of snapshots, the raised start took 15 to 20 minutes, and as one choice about 1.5
minutes. Each step part has four profiles: `Step<Part>Base` checks the eight parts of A000,
`Step<Part>Anchor` the five other parts that the anchor properties need, `Step<Part>Restore`
the two restore parts for each retained snapshot, and `Step<Part>RestoreNow` the two for a
snapshot taken now. Their conjunction is the step check. With every part in one profile, the
declared `Commit`, `Conflict`, and `End` (then one part of three actions) took more than one hour,
and with every domain raised at once, profiles ran past one hour. With the four profiles and the
order clauses of 2026-11-09, each declared profile takes 2 to 13 minutes. The times of the grouped
raise profiles are not kept ([Limits](#limits)).

Each `_reach` witness shows that `IndInit` contains a state that a step must cover; each new part
has at least one:

| Witness | The starting set contains |
| --- | --- |
| `DoubtSnapshot_reach` | A snapshot from which a restore puts a consumption in doubt |
| `Pending_reach` | An in-doubt consumption that a redrive can commit |
| `TwoReleased_reach` | Two released artifacts |
| `IssueReady_reach` | An owner re-bootstrap that can commit and end the valid value |
| `EndedValueSnapshot_reach` | A snapshot whose valid bootstrap value a later re-bootstrap entry ends at a restore |
| `MadePromise_reach` | A promise of an anchor that a commit created (`PromiseInv`) |
| `CreationDue_reach` | An outcome record that left an anchor whose creation entry is still due (`PromiseInv`) |
| `DoubtKeeps_reach` | An account that a restore keeps only through an in-doubt recovery (`RestoreAccountInv`) |
| `DoubtAdmin_reach` | An authority that a restore keeps only through an in-doubt bootstrap (`RestoreAdminInv`) |
| `UncertainEnded_reach` | An ended anchor that only an in-doubt end entry accounts for (`AnchorStateInv`) |
| `PendKeeps_reach` | During reconciliation, an account that only an in-doubt recovery keeps (`KeptNowInv`) |
| `DoubtKeepsNow_reach` | A serving store that a snapshot taken now keeps only through an in-doubt recovery (`RestoreNowAccountInv`) |
| `TurnHeld_reach` | A consumption that committed and still holds its owner's turn (`TurnInv`) |
| `CrashedHolds_reach` | A serving store with a crashed operation that did not commit and whose end entry holds (`ServingInv`) |
| `AccountsUsed_reach` | The third account's second anchor and the extra slots of `a1` and `a2` live together |
| `AdminUsed_reach` | The third administrator live |
| `ProcessUsed_reach` | Three snapshots, the fourth operation, and four bootstrap values |

Results of the proofs. Each Apalache profile ran through the xtask; a pass is the outcome
`NoError` with exit status 0, a witness or known-bad variant passes on its violation
([Evidence record](#evidence-record)):

| Module | Profiles | At the current digest (round 6) | At the digest `sha256:0dba3f3d…` (round 5) |
| --- | --- | --- | --- |
| `AuthorityInd` (declared domains) | 109 | Every profile passed with its required verdict | Every profile passed; each took 2 to 13 minutes on one core |
| `AuthorityIndAnchors` (anchor raise) | 110 | 33 profiles passed with their required verdict; 77 did not finish before the hosts stopped | — |
| `AuthorityIndProcess` (process raise) | 109 | 22 profiles passed with their required verdict; 87 did not finish before the hosts stopped | — |

Round 5 had one module that raised every domain at once; its proof checks passed where they
finished, but five step profiles ran more than one hour ([Decisions](#decisions)). The two
clauses that round 5 found (no new anchor in an initial slot, and the order of entries in a
turn) are the only change from round 5 to round 6 in the declared checks.

`Replay.tla` proves `Safety` of the replay window for every non-negative `Skew`, `U`, and `MaxWin`
and every integer time. It is unchanged since 2026-11-08, so its results are those of the A000
record (digest `sha256:5549a6d4…`); round 6 did not reach it:

| Check | Result |
| --- | --- |
| `Replay.Init.apalache` (`Init => IndInv`) | Pass, 4.90 s (A000 record) |
| `Replay.Step.apalache` (`IndInv /\ Next => IndInv'`) | Pass, 3.60 s (A000 record) |
| `Replay.Safety.apalache` (`IndInv => Safety`) | Pass, 5.39 s (A000 record) |
| `Replay.AcceptedGone_reach.apalache` (`IndInv` contains an acceptance whose record expired while a verifier holds a check) | Target reached, 5.81 s (A000 record) |

## Raise by one

Rule 4 of [FP Design Models]: a bound whose sufficiency the model argues but does not prove gets
one complete check with that bound raised by one before the evidence is final. Since 2026-11-09,
`IndInv` implies every authority property, so the two raised proofs are that check for each
domain bound (selected on 2026-11-10). Round 6 ran part of each ([Limits](#limits)). A raised element starts inert, except the first anchor of a
third account, which is live as `a2p` is.

| Bound | Declared | Raised | Check |
| --- | --- | --- | --- |
| Accounts | 2 | 3 (`a3p` live, `a3q` absent) | `AuthorityIndAnchors` |
| Anchor slots of `a1` | 3 | 4 (`a1s` absent) | `AuthorityIndAnchors` |
| Anchor slots of `a2` | 2 | 3 (`a2r` absent) | `AuthorityIndAnchors` |
| Administrator slots | 2 | 3 (`adm3`) | `AuthorityIndAnchors` |
| Operations | 3 | 4 (`o4` idle) | `AuthorityIndProcess` |
| Snapshots | 2 | 3 | `AuthorityIndProcess` |
| Values in each set of bootstrap values | 3 | 4 | `AuthorityIndProcess` |
| Counter values and journal sequences | Unbounded integers | Unbounded integers | Both proofs |
| Owner re-bootstraps | No bound in the proof's `Next` | No bound | Both proofs |

Each grouped raise covers each single raise in its group: a state of a model that raises one
bound is a state of the grouped model with the other extra elements inert, each `IndInv` clause
quantifies over the domains uniformly, and each step of the smaller model is a step of the grouped
one. So each bound is raised by one, and each pair of bounds in one group is raised together. A
raise of every domain at once (`AuthorityIndRaise`, until 2026-11-10) did not fit the budget
([Decisions](#decisions)). The witnesses `AccountsUsed_reach`, `AdminUsed_reach`, and
`ProcessUsed_reach` show that each starting set contains states that use the raised elements.
Each new anchor needs its own committed maker, so with three operations the anchor raise has two
witnesses: one for the accounts and one for the administrator.

TLC keeps its declared bounds. `Authority.cfg` and `Authority.Bootstrapped.cfg` search the
declared space completely, a check that does not depend on the invariant. Their counter bound
(values up to 5) and re-bootstrap bound (one) are state constraints of the search only.

The TLC raise searches are removed. Their last results, at the A000 digest
`sha256:5549a6d4…` on 48 vCPUs, were complete searches with no violation: `RaiseCtr` 260,779,156
distinct states, `RaiseSlotsA2` 422,601,310, `RaiseSlotsA1` 770,348,006 (92 minutes),
`RaiseAccounts` 545,513,196, `RaiseSnaps` 552,749,238, `RaiseIssues` 220,953,314, and
`RaiseIssuesBootstrapped` 67,750,337. `RaiseOpsOne`, the raise of the operations under the
reduction to one account, stopped at 6,866,941,619 distinct states with no violation. Most of
them took more than the budget of one hour on 16 vCPUs, and none was a proof.

## Evidence record

### Evidence of the current files

Round 6 was the final run of the A016 work (the user selected it as final on 2026-11-10). It ran
every profile of the current files, each with `cargo xtask model authority-restore/<profile>` from
the repository root, from 2026-11-10 04:24 UTC.

- Source: the files of this directory, not yet committed then, on top of commit `83e1bc3`. Each
  run printed `sha256:89a81c7ac67f013ad0c1bb41e42042fc12e5faf884dadc46a3a49f9100cbfb53 (378
  files)`.
- Checkers: temurin-jre 21.0.13+9 (Linux aarch64, SHA-256 checked against Adoptium), tla2tools
  1.8.0+d8fb231de4e4 (TLC2 Version 2026.11.06.222357, rev d8fb231; SHA-256
  `e1f11b75c4b5bc4478ba0ac5cb6ae28e40a01b0016bc33e0aa97da22dfdbcd7f` checked), with `-workers auto
  -lncheck final`; apalache 0.62.4 (SHA-256 of `lib/apalache.jar` checked).
- Hosts: EC2 m8g.4xlarge (16 vCPUs, 64 GiB, AWS Graviton4), image `ami-06b1a03fa3561aefb`
  (Ubuntu 26.04 arm64, 20261104.1), kernel 7.0.0-1016-aws, on demand. `i-0cbfe5a46b68b5a85`
  (us-east-1b) ran the 109 `AuthorityInd` profiles, nine at a time, and then the TLC and Replay
  profiles one at a time. `i-0cc104d10ea31d875` (us-east-1a) ran the 110 `AuthorityIndAnchors`
  profiles, eight at a time, and `i-07b2942b31bd038f9` (us-east-1c) the 109
  `AuthorityIndProcess` profiles, seven at a time.
- Result at 04:50 UTC: every one of the 109 `AuthorityInd` profiles exited 0 with its required
  verdict; 4 of the 45 TLC and Replay profiles, 33 `AuthorityIndAnchors` profiles, and 22
  `AuthorityIndProcess` profiles had finished, each with its required verdict, and no profile had
  failed. The hosts then reached their time limits and terminated before their logs were
  collected (they had no storage to write to), so this record keeps the exit statuses and counts
  only, not the time of each profile ([Limits](#limits)).

The TLC profiles other than the two declared searches ran again on the development host after
round 6, at the same digest:

- Command: `cargo xtask model` with the 34 TLC profiles other than `Authority.cfg` and
  `Authority.Bootstrapped.cfg`, from the repository root, on 2026-11-10. Exit status 0. The xtask
  printed `sha256:89a81c7ac67f013ad0c1bb41e42042fc12e5faf884dadc46a3a49f9100cbfb53 (378 files)`.
- Checkers: temurin-jre 21.0.13+9 (macOS aarch64), tla2tools 1.8.0+d8fb231de4e4 (TLC2 Version
  2026.11.06.222357, rev d8fb231), apalache 0.62.4.
- Host: Apple M1 Pro, 10 cores, macOS 27.2.1, shared with other work, so the times are
  indicative only. The tables of [Known-bad variants](#known-bad-variants) and
  [Reachability](#reachability) hold the result of each profile.

### Earlier records

- 2026-11-10, round 5, at the digest `sha256:0dba3f3d…` (267 files): every `AuthorityInd` profile
  passed, each in 2 to 13 minutes; the raise of every domain at once found two missing clauses
  and did not fit the budget.
- 2026-11-09, at the A000 digest `sha256:5549a6d4…` (111 files): every profile passed with its
  required verdict except `Authority.RaiseOpsOne.cfg` and the seventeen raised step parts (the
  two limits of A000). On a 16-vCPU host (`i-0cc104d10ea31d875`, each search alone),
  `Authority.cfg` took 56 min 14 s (218,052,725 distinct states, depth 36) and
  `Authority.Bootstrapped.cfg` 16 min 50 s (67,075,361, depth 36).
- 2026-11-08 and earlier, at the digests `904164456e72…`, `1023dd21…`, `0b6c17bd…`, and
  `7b5cf1bc…`: the rules as they were then. Their tables are in the history of this file
  (commit `83e1bc3`).

## Limits

- Three limits of the A016 evidence, from round 6, the final run (selected by the user on
  2026-11-10). The next evidence run of this model, one run of every profile on one 16-vCPU host
  of about three hours, closes them:
  - The grouped raises are partial: 33 of the 110 `AuthorityIndAnchors` profiles and 22 of the
    109 `AuthorityIndProcess` profiles finished, each with its required verdict, and none
    failed. So the raise by one of the anchor properties is not complete.
  - `Authority.cfg` and `Authority.Bootstrapped.cfg` did not run at the current digest. Their
    last complete searches are at the A000 digest, before the exact promise and the stricter
    `Uncertain`. The declared proof covers each of their properties at the current digest.
  - The round-6 logs of the Apalache profiles are lost, so the record keeps their exit statuses
    and counts, not the time of each profile.
- The proofs cover the domains of rule 4 ([Inductive proofs](#inductive-proofs)): any number of
  crashes, restarts, restores, and reconciliation steps, over at most three operations and two
  snapshots in a run (four and three raised). The TLC searches cover their bounds.
- The proofs check the design's turn (`Turn = "creation"`). The turn that ends at the first
  journal write (`Turn = "entry"`) has the TLC search `Authority.Race.cfg` at TwoOps and its
  known-bad variant `RaceNoVoid_bad`, and no proof.
- `Authority.cfg` is the longest TLC profile, and it is near the one-hour budget on 16 vCPUs
  ([Evidence record](#evidence-record)). A change that grows its state space needs a reduction
  first; because the proof covers its properties, a smaller declared search is that reduction.
- The models check the design, not code. A007–A011 add the code correspondence.
- Not modeled: the lifetime and expiry of a bootstrap value (the model has no time), the
  authentication of the local owner, and the report as a separate record (the outcome record and
  audit stand for it). Not modeled either: the journal hash chain, the refusal for a missing or gapped journal, the loss of
  the journal's newest entries (outside its declared failure domain), outcome-record expiry, the
  replay store's capacity, the passkey signature counter, anchor keys (the client rule), the
  isolation failure "write skew on absence" (an A011 broken binding), CLI credentials of accounts,
  agent identities (not anchors) and the ceremonies whose consumption pays for no anchor (no
  journal entry; restore ends them), and the transitions outside A000 (workload issuance, agent
  enrollment, operation approval, federated sign-in).
- Under the completion rule, restore checks dependencies against the restored state. A policy
  change that is not an invalidation, and that came after the snapshot, is lost at restore for
  every request, and a completion uses the older policy. This is a limit of restore in general.
- A party that can append valid entries to the journal can add an in-doubt consumption, as it can
  add a creation entry. The hash chain detects a change inside the history, not a new entry at its
  end.
- No liveness property is checked; reconciliation ends by the argument in
  [Physical assumptions](#physical-assumptions).

## Open questions

- None for the design. The question of a new administrator after the bootstrap is consumed is
  answered by the owner re-bootstrap (selected on 2026-11-08).
[AUTH Authority Transitions]: ../../docs/specs/authentication.md#authority-transitions
[AUTH Storage Contract and Bindings]: ../../docs/specs/authentication.md#storage-contract-and-bindings
[AUTH HTTP-Signature Replay]: ../../docs/specs/authentication.md#http-signature-replay
[AUTH Initial Profiles]: ../../docs/specs/authentication.md#initial-human-workload-and-agent-profiles
[FP Design Models]: ../../../rsasync/docs/specs/family-policy.md#design-models
