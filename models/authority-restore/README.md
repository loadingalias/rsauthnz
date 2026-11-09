# authority-restore: design model of task A000

Status (2026-11-08): the modules follow the design as selected on 2026-11-07 and the owner
re-bootstrap selected on 2026-11-08 ([Decisions](#decisions)). The four design defects of the
first rounds (F1 to F4) are closed in the design, and each one is now a known-bad variant that
fails. On 2026-11-08 the user also selected the acknowledgement order of anchor changes
(`CreationPending`, a defect that the raise of the operations found) and the reduction to one
account for that raise ([Decisions](#decisions), [Bounds, faults, and reductions](#bounds-faults-and-reductions)).
At the current digest
`sha256:5549a6d42d03b46fe37fd498ff38b1413a6260383f23241d4ed8165dee760454` (111 files), every
profile passed with its required verdict except two raise checks, which did not finish
([Evidence record](#evidence-record)): `Authority.RaiseOpsOne.cfg` and the seventeen step parts
of `AuthorityIndRaise`. Both are named limits ([Limits](#limits)), and the model is complete
with them (selected on 2026-11-09). Task A016 closes them before A009, the restore journal, is
built. Every other earlier row in this file is the record of earlier files.

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

`cargo xtask model authority-restore` includes `Authority.cfg` and `Authority.Bootstrapped.cfg`,
the declared-bounds searches, which need the evidence host. On the development host, run the other profiles by name. The output and
each trace go to `target/model/authority-restore/<file>/`: `checker.log`, and `trace.json` (TLC)
or `<Module>.tla/<run>/violation1.itf.json` (Apalache). [Check the design
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
`Raise` is "none" for the declared bounds; its other values raise one bound by one
([Raise by one](#raise-by-one)), and "oneAccount" and "opsOne" are the reduction to one account
(selected on 2026-11-08).

| Profile | Checker | Check | Bound |
| --- | --- | --- | --- |
| `Authority.cfg` | TLC | Every authority property, `Origin = "new"` | Declared (evidence host) |
| `Authority.Bootstrapped.cfg` | TLC | Every authority property, `Origin = "bootstrapped"` | Declared (evidence host) |
| `Authority.TwoOps.cfg` | TLC | Every authority property, `Origin = "new"` | TwoOps |
| `Authority.TwoOpsBootstrapped.cfg` | TLC | Every authority property, `Origin = "bootstrapped"` | TwoOps |
| `Authority.Race.cfg` | TLC | Every authority property, with `Turn = "entry"`: each turn ends at the first journal write, so two consumptions of one value can be in doubt at one restore | TwoOps |
| `Authority.<Rule>_bad.cfg` | TLC | One known-bad variant ([Known-bad variants](#known-bad-variants)) | TwoOps; `Unserialized_bad` Declared |
| `Authority.<Target>_reach.cfg` | TLC | One reachability witness ([Reachability](#reachability)) | TwoOps; `AdminReplaced_reach` Declared |
| `AuthorityInd.Init.apalache` | Apalache | `Init => IndInv` | Unbounded integers |
| `AuthorityInd.Step<Part>.apalache` | Apalache | `IndInv /\ Next<Part> => IndInv'` for the seventeen parts of `Next`: `Enroll`, `Unlink`, `Recover`, `Boot`, `Renew`, `Revoke`, `IssueEnd`, `IssueNone`, `Journal`, `Commit`, `Conflict`, `End`, `Rec`, `Again`, `Fail`, `Serve`, `Restore` | Unbounded integers |
| `AuthorityInd.Safety.apalache` | Apalache | `IndInv => Safety` | Unbounded integers |
| `AuthorityInd.<Witness>_reach.apalache` | Apalache | `IndInit` contains a key state: `DoubtSnapshot`, `Pending`, `TwoReleased`, `IssueReady`, `EndedValueSnapshot` | — |
| `Authority.Raise<Bound>.cfg` | TLC | Every authority property with one bound raised by one ([Raise by one](#raise-by-one)) | Declared + 1 (evidence host) |
| `Authority.RaiseOpsOne.cfg` | TLC | Every authority property with four operations, under the reduction to one account (selected on 2026-11-08) | Declared + 1 operation (evidence host) |
| `Authority.OneAccount<Rule>_bad.cfg` | TLC | A known-bad variant under the reduction to one account: it must still fail, so the reduction keeps its failure | TwoOps; `OneAccountNoAgainAccount_bad` and `OneAccountUnserialized_bad` Declared |
| `Authority.SlotsA1AckEarly_bad.cfg` | TLC | The known-bad variant `ackEarly` on both accounts with the fourth slot of `a1`, so its failure does not come from the reduction | TwoOps |
| `AuthorityIndRaise.<Check>.apalache` | Apalache | The checks of `AuthorityInd` with every domain raised by one at once | Unbounded integers |
| `Replay.Init.apalache`, `Replay.Step.apalache`, `Replay.Safety.apalache` | Apalache | The inductive invariant of the replay window, and `IndInv => Safety` | Unbounded integers and time |
| `Replay.AcceptedGone_reach.apalache` | Apalache | `IndInv` contains an acceptance whose record expired while a verifier holds a check | — |
| `Replay.<Rule>_bad.apalache` | Apalache | One known-bad variant, 10 steps | Unbounded integers and time |

`Next` of `Authority.tla` is the disjunction of `NextRun`, `NextEnd`, `NextRec`, `NextAgain`,
`NextSys`, and `NextRestore`. `AuthorityInd.tla` splits `NextRun` into eleven parts and `NextSys`
into two, by the definitions of `Start` (the disjunction of its seven kinds, with `StartIssue` as
the disjunction of `StartIssueEnd` and `StartIssueNone`), `NextRun`, and
`NextSys`, so that each Apalache run has one symbolic transition, or two for the short ones. The
seventeen parts together are the step check.

## Correspondence: authority and restore

Each action is one atomic design step. The source is [AUTH Storage Contract and Bindings] unless
the row names [AUTH Authority Transitions]. A later revision maps each row to its A007–A011 code
and conformance case.

| Action | Design rule | Atomicity | Crash point after it (`pc`) |
| --- | --- | --- | --- |
| `Start(o)`: `StartEnroll`, `StartUnlink`, `StartRecover`, `StartBoot`, `StartRenew`, `StartRevoke`, `StartIssue` | The core checks the request and proposes a transition of one kind. A bootstrap takes a valid bootstrap value and binds a new administrator. `StartIssue` is the owner re-bootstrap ([AUTH Authority Transitions], selected on 2026-11-08): it plans to end the valid bootstrap value, if any. An unlink of an administrator binding keeps another administrator that the journal records as live ([AUTH Authority Transitions]). An anchor change takes its owner's turn. An unlink keeps an anchor that the journal records as live ("counts the journaled anchors that the change does not end"). A recovery binds its new anchor in the commit that consumes its value | Check and turn, one step | Before a journal write (`cChecked`) |
| `JournalEnd(o)` | Write rule: the end entry is durable before its commit. A consumption entry records its transition. An unlink ends its turn here | One journal append | Between a journal write and its commit (`cJournaled`) |
| `Commit(o)` | Serializable conditional commit of every dependency, the state change, and the outcome record ([AUTH Authority Transitions]). An owner re-bootstrap depends on the valid bootstrap values that it checked; its commit adds a value with a new identity and ends the value that it checked. The outcome record and the audit stand for the authority's report of each issue and each consumption. Allocation floors: the floor is durable before a commit allocates a value above it | One step, because the storage contract makes the commit atomic; the floor write and the commit are one step, because the state between them differs only by a higher floor | Between a commit and its creation entry, or before the acknowledgement (`cCommitted`) |
| `Conflict(o)` | A changed dependency refuses the commit. Write rule: the refusal voids each entry of its operation before it returns | One step: a crash before the void is the crash at `journaled` | — |
| `JournalCreate(o)` | The creation entry, after its commit and before its acknowledgement. It ends the turn | One journal append | Before an acknowledgement (`cCreated`) |
| `Ack(o)` | The response, after the floor covers the artifact's value. Acknowledgement order (selected on 2026-11-08): an anchor change of an owner is acknowledged only after each other commit of that owner that created an anchor has its creation entry (`CreationPending`), so a restore keeps each anchor in the state that the acknowledged commit saw | One step | — |
| `Resolve(o)` | A client whose response was lost looks up its operation identity and receives the committed outcome ([AUTH Authority Transitions]: "Resolve it through the accepted receipt/current-state contract"). A lookup that reports a commit is an acknowledgement too, so it has the same `CreationPending` guard (selected on 2026-11-08) | One step | — |
| `Crash` | A crash stops each operation in flight at its point; the store and the journal keep their durable state | One step | — |
| `Restart`, `Serve` | A start reconciles before it serves; the store serves only with no missing creation entry, no entry to void, and no in-doubt consumption | One step each | — |
| `ReconcileCreate(o)`, `ReconcileVoid(o)` | Reconciliation writes the missing creation entry of each anchor whose commit has an outcome record, and a void for each end entry whose fact does not hold in the store | One journal append each | A crash during reconciliation |
| `Redrive(o)`, `RedriveFail(o)` | Restore completes each in-doubt consumption: the first in journal order for each value commits again under its operation identity when its dependencies hold; otherwise the value stays consumed. A bootstrap value must be one that the restored store holds and that no re-bootstrap entry ended | One step each, because the commit is atomic | A crash during reconciliation |
| `Snapshot` | A snapshot with its low-water mark: the highest journal sequence at or below which every entry is reflected | One step | — |
| `Restore(s)` | Restore from any retained snapshot of a store that is down: apply each entry after the low-water mark that no void cancels, keep an ended anchor ended, raise the floor, and mark each in-doubt consumption; reconciliation follows. The store holds the snapshot's bootstrap values, so a value issued after the snapshot is lost; consumption and re-bootstrap entries apply as facts | One step before reconciliation | — |

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
  Apalache proofs have no such bound: they hold at the declared domains for histories of any
  length.
- Faults: a crash at each point in the correspondence table, restart, restore from any retained
  snapshot, a commit conflict, a lost response, and a crash during reconciliation.
- Replay: one signature with symbolic `created` and `expires`, symbolic non-negative `Skew`, `U`,
  and `MaxWin`, and integer time with no bound.
- The reduction to one account (selected on 2026-11-08) exists for the raise of the operations,
  whose full form is an estimated 10 to 100 billion states. Its first form had no free slot (`a1`
  with its three live anchors only), and it hid F1: `OneAccountNoAgainAccount_bad` completed a
  search of 43,855,280 states with no violation, because no recovery had a free slot to create its
  new anchor into. The fourth slot `a1s`, absent at the start, gives each recovery and each
  enrollment a slot, and with it every one-account variant fails. `Authority.RaiseOps.cfg` is
  removed; `Authority.RaiseOpsOne.cfg` is the raise of the operations.

Each reduction names the failure that it could hide, and a known-bad variant with that failure
still fails under it ([FP Design Models]):

| Reduction | The failure that it could hide | Known-bad variant that still fails |
| --- | --- | --- |
| Operations start in identity order (`Rank`); the identities are interchangeable | A race that needs a later identity to start first | `RefusalNoVoid_bad`, `RaceNoVoid_bad`, and `Unserialized_bad` need two or three concurrent operations |
| One account anchor kind for passkeys, provider links, and recovery values; the administrator bindings for the bootstrapped CLI credential | A journal rule that differs by kind | The design gives the kinds one rule; `IgnoreVoids_bad` (unlink) and `NoAgainAccount_bad` (recovery) fail on the one kind |
| The reduction to one account (`Raise = "oneAccount"`; with four operations, `"opsOne"`): account `a1` with a fourth slot `a1s`, absent at the start, and the administrator bindings, at the declared bounds (selected on 2026-11-08) | An interaction between accounts through the shared low-water mark, the shared operation identities, or the counter; and, without a free slot, every failure that needs an anchor creation in the account | `OneAccountIgnoreVoids_bad`, `OneAccountNoAgainAccount_bad`, `OneAccountRefusalNoVoid_bad`, `OneAccountUnserialized_bad`, `OneAccountVoidOnMissing_bad`, and `OneAccountAckEarly_bad` fail their named properties; `SlotsA1AckEarly_bad` fails the same property on both accounts |
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
| `AnchorKept` | Authority | Restore keeps each anchor created after the snapshot; a commit that returned its refusal leaves no entry that applies at restore |
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
  with a free slot in the account ([Bounds, faults, and reductions](#bounds-faults-and-reductions)).

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
its own property. The "Current files" column is the evidence host record of 2026-11-08 and 2026-11-09
([Evidence record](#evidence-record)); the column before it is the record of earlier files.

| Profile | Changed rule | Must violate | Origin, bound | Record of earlier files: verdict, distinct states (depth), time | Current files |
| --- | --- | --- | --- | --- | --- |
| `Authority.AfterCommit_bad.cfg` | Option (c): the consumption entry comes after the commit | `NothingEndedValid` | new, TwoOps | `NothingEndedValid` violated, as required, 4120 (7), 1.68 s | `NothingEndedValid` violated, as required, 9,104 (9), 0.94 s |
| `Authority.CreateBeforeCommit_bad.cfg` | A creation entry before its commit | `NoUncommittedAnchor` | new, TwoOps | `NoUncommittedAnchor` violated, as required, 1848 (6), 1.22 s | `NoUncommittedAnchor` violated, as required, 5,291 (8), 1.09 s |
| `Authority.FloorAtRelease_bad.cfg` | F4: the floor is durable at the release, not at the commit | `NoCounterReuse` | new, TwoOps | `NoCounterReuse` violated, as required, 452699 (18), 18.29 s | `NoCounterReuse` violated, as required, 459,913 (18), 4.38 s |
| `Authority.IgnoreVoids_bad.cfg` | Restore applies voided entries | `AnchorKept` | new, TwoOps | `AnchorKept` violated, as required, 23362 (9), 2.07 s | `AnchorKept` violated, as required, 33,896 (10), 1.27 s |
| `Authority.IssueNoEnd_bad.cfg` | An owner re-bootstrap that does not end the earlier value (2026-11-08) | `OneBootValid` | new, TwoOps | `OneBootValid` violated, as required, 306 (4), 0.86 s | `OneBootValid` violated, as required, 553 (6), 0.64 s |
| `Authority.IssueNoJournal_bad.cfg` | An owner re-bootstrap whose end of the earlier value has no journal entry (2026-11-08) | `NothingEndedValid` | new, TwoOps | `NothingEndedValid` violated, as required, 6294 (8), 1.51 s | `NothingEndedValid` violated, as required, 8,890 (9), 0.95 s |
| `Authority.LookupAbsent_bad.cfg` | A missing outcome after restore reads as absent | `MissingOutcomeUnknown` | new, TwoOps | `MissingOutcomeUnknown` violated, as required, 3503 (7), 1.70 s | `MissingOutcomeUnknown` violated, as required, 6,034 (8), 1.18 s |
| `Authority.NoAgainAccount_bad.cfg` | F1: restore leaves an in-doubt recovery unresolved | `AccountKeepsAnchorP` | new, TwoOps | `AccountKeepsAnchorP` violated, as required, 7306 (8), 1.63 s | `AccountKeepsAnchorP` violated, as required, 10,039 (9), 1.38 s |
| `Authority.NoAgainAdmin_bad.cfg` | F1: restore leaves an in-doubt bootstrap unresolved (the design before 2026-11-07) | `AdminKeptP` | new, TwoOps | `AdminKeptP` violated, as required, 9569 (9), 1.92 s | `AdminKeptP` violated, as required, 15,045 (9), 1.07 s |
| `Authority.NoFloor_bad.cfg` | Restore does not raise the allocation floor | `NoCounterReuse` | new, TwoOps | `NoCounterReuse` violated, as required, 240675 (14), 8.80 s | `NoCounterReuse` violated, as required, 255,931 (15), 2.98 s |
| `Authority.OneAccountAckEarly_bad.cfg` | `ackEarly`: an anchor change is acknowledged before the creation entry of another anchor commit of its owner (the order before 2026-11-08) | `AnchorKept` | new, one account, TwoOps | not run on earlier files | `AnchorKept` violated, as required, 42,832 (11), 1.37 s |
| `Authority.OneAccountIgnoreVoids_bad.cfg` | `ignoreVoids` under the reduction to one account | `AnchorKept` | new, one account, TwoOps | not run on earlier files | `AnchorKept` violated, as required, 42,293 (11), 1.46 s |
| `Authority.OneAccountNoAgainAccount_bad.cfg` | `noAgain` under the reduction to one account | `AccountKeepsAnchorP` | new, one account, Declared | first form without `a1s`: no violation in a complete search of 43,855,280 states (the reduction hid F1) | `AccountKeepsAnchorP` violated, as required, 877,864 (11), 3.46 s |
| `Authority.OneAccountRefusalNoVoid_bad.cfg` | `refusalNoVoid` under the reduction to one account | `AnchorKept` | new, one account, TwoOps | not run on earlier files | `AnchorKept` violated, as required, 42,312 (11), 1.42 s |
| `Authority.OneAccountUnserialized_bad.cfg` | `unserialized` under the reduction to one account | `AccountKeepsAnchorP` | new, one account, Declared | not run on earlier files | `AccountKeepsAnchorP` violated, as required, 2,646,458 (11), 7.46 s |
| `Authority.OneAccountVoidOnMissing_bad.cfg` | `voidOnMissing` under the reduction to one account | `NothingEndedValid` | new, one account, TwoOps | not run on earlier files | `NothingEndedValid` violated, as required, 193,788 (14), 2.25 s |
| `Authority.SlotsA1AckEarly_bad.cfg` | `ackEarly` on both accounts with the fourth slot of `a1` | `AnchorKept` | new, raise of `a1`'s slots, TwoOps | not run on earlier files | `AnchorKept` violated, as required, 69,679 (11), 2.04 s |
| `Authority.NoJournal_bad.cfg` | Restore without its journal | `NothingEndedValid` | new, TwoOps | `NothingEndedValid` violated, as required, 3454 (7), 1.50 s | `NothingEndedValid` violated, as required, 8,904 (8), 1.05 s |
| `Authority.PairApplies_bad.cfg` | Option (a): restore applies the pair and creates the anchor at once | `NoUncommittedAnchor` | new, TwoOps | `NoUncommittedAnchor` violated, as required, 4754 (7), 1.83 s | `NoUncommittedAnchor` violated, as required, 4,811 (7), 1.00 s |
| `Authority.RaceNoVoid_bad.cfg` | F3 with `Turn = "entry"` | `RefusalHolds` | new, TwoOps | `RefusalHolds` violated, as required, 60121 (10), 3.27 s | `RefusalHolds` violated, as required, 61,049 (11), 1.69 s |
| `Authority.RefusalNoVoid_bad.cfg` | F3: a refusal writes no void | `AnchorKept` | new, TwoOps | `AnchorKept` violated, as required, 22790 (10), 2.22 s | `AnchorKept` violated, as required, 48,396 (11), 1.42 s |
| `Authority.Unserialized_bad.cfg` | Anchor changes of one account take no turn | `AccountKeepsAnchorP` | new, Declared | `AccountKeepsAnchorP` violated, as required, 1552164 (11), 29.64 s | `AccountKeepsAnchorP` violated, as required, 1,632,112 (12), 6.09 s |
| `Authority.VoidOnMissing_bad.cfg` | Reconciliation voids on a missing outcome at a normal start after a restore | `NothingEndedValid` | new, TwoOps | `NothingEndedValid` violated, as required, 154190 (13), 5.68 s | `NothingEndedValid` violated, as required, 172,765 (13), 2.27 s |
| `Replay.FloorNoSkew_bad.apalache` | A restart floor without the skew | `NoDoubleAccept` | — | not run since 2026-11-08 (`Replay.tla` is unchanged since its run of 2026-11-08, digest `904164456e72…`) | `NoDoubleAccept` violated, as required, 6.42 s |
| `Replay.InsertLate_bad.apalache` | The insert threshold one bound later (`expires + Skew + U`) | `NoDoubleAccept` | — | not run since 2026-11-08 (`Replay.tla` is unchanged since its run of 2026-11-08, digest `904164456e72…`) | `NoDoubleAccept` violated, as required, 6.89 s |
| `Replay.NoInsertCheckDouble_bad.apalache` | F2: no insert check (the design before 2026-11-07) | `NoDoubleAccept` | — | not run since 2026-11-08 (`Replay.tla` is unchanged since its run of 2026-11-08, digest `904164456e72…`) | `NoDoubleAccept` violated, as required, 6.74 s |
| `Replay.NoInsertCheckLive_bad.apalache` | F2: no insert check | `NoLiveRemoved` | — | not run since 2026-11-08 (`Replay.tla` is unchanged since its run of 2026-11-08, digest `904164456e72…`) | `NoLiveRemoved` violated, as required, 6.70 s |
| `Replay.RetentionOneU_bad.apalache` | Retention with one uncertainty bound | `NoLiveRemoved` | — | not run since 2026-11-08 (`Replay.tla` is unchanged since its run of 2026-11-08, digest `904164456e72…`) | `NoLiveRemoved` violated, as required, 5.93 s |

The counterexample of `ackEarly`, from the search of `Authority.RaiseOpsOne.cfg` on 2026-11-08
that found it: `StartUnlink(o1)` (an unlink in `a1` that keeps another anchor), `JournalEnd(o1)`,
`StartEnroll(o2)` (an enrollment of the free slot `a1s`), `Snapshot`, `Commit(o2)` (`a1s` is
live, and its creation entry is still to come), `Commit(o1)`, `Ack(o1)` (its commit saw `a1s`,
so `a1s` is in the anchors that the acknowledged commit left), `Crash`, `Restore`. Then `a1s` has
no creation entry, so the restore makes it absent, and `AnchorKept` fails. With `CreationPending`,
`Ack(o1)` waits for the creation entry of `o2`, and a crash before it leaves `o1` unacknowledged.

The counterexamples of the record of earlier files, as actions and the observation that breaks
the property:

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

In the record of earlier files, each witness reached its target: the checker reported its `Not<Target>` invariant as violated. The "Current files" column has the evidence host record.

| Profile | Target | Origin, bound | Record of earlier files: verdict, distinct states (depth), time | Current files |
| --- | --- | --- | --- | --- |
| `Authority.AccountAfterDoubt_reach.cfg` | F1: after an in-doubt recovery and a restore, the serving store has the new anchor | new, TwoOps | `NotAccountAfterDoubt` violated, as required, 41418 (10), 3.01 s | `NotAccountAfterDoubt` violated, the target is reached, 50,658 (11), 1.50 s |
| `Authority.AdminAfterDoubt_reach.cfg` | F1: after an in-doubt bootstrap and a restore, the serving store has its administrator | new, TwoOps | `NotAdminAfterDoubt` violated, as required, 35841 (10), 2.73 s | `NotAdminAfterDoubt` violated, the target is reached, 45,550 (11), 1.66 s |
| `Authority.AdminReplaced_reach.cfg` | The administrator of a re-bootstrap ends the earlier administrator binding through an unlink (2026-11-08) | bootstrapped, Declared | `NotAdminReplaced` violated, as required, 815125 (12), 16.60 s | `NotAdminReplaced` violated, the target is reached, 810,231 (12), 3.63 s |
| `Authority.CrashBeforeAck_reach.cfg` | Restore after a crash before an acknowledgement | new, TwoOps | `NotRestoreAfterCrashBeforeAck` violated, as required, 13908 (9), 2.00 s | `NotRestoreAfterCrashBeforeAck` violated, the target is reached, 16,380 (9), 1.23 s |
| `Authority.CrashBeforeCommit_reach.cfg` | Restore after a crash between a journal write and its commit | new, TwoOps | `NotRestoreAfterCrashBeforeCommit` violated, as required, 6170 (7), 1.88 s | `NotRestoreAfterCrashBeforeCommit` violated, the target is reached, 9,811 (8), 1.15 s |
| `Authority.CrashBeforeCreation_reach.cfg` | Restore after a crash between a commit and its creation entry | new, TwoOps | `NotRestoreAfterCrashBeforeCreation` violated, as required, 7400 (8), 1.88 s | `NotRestoreAfterCrashBeforeCreation` violated, the target is reached, 17,004 (9), 1.21 s |
| `Authority.CrashBeforeJournal_reach.cfg` | Restore after a crash before a journal write | new, TwoOps | `NotRestoreAfterCrashBeforeJournal` violated, as required, 2107 (6), 1.48 s | `NotRestoreAfterCrashBeforeJournal` violated, the target is reached, 9,592 (8), 1.23 s |
| `Authority.IssueEndApplied_reach.cfg` | A restore applies the end entry of an owner re-bootstrap whose commit is not known (2026-11-08) | new, TwoOps | `NotIssueEndApplied` violated, as required, 12932 (8), 1.80 s | `NotIssueEndApplied` violated, the target is reached, 17,147 (9), 1.20 s |
| `Authority.Rebootstrapped_reach.cfg` | After the first bootstrap value was consumed, an owner re-bootstrap gives the authority a new administrator (2026-11-08) | bootstrapped, TwoOps | `NotRebootstrapped` violated, as required, 5998 (7), 1.38 s | `NotRebootstrapped` violated, the target is reached, 8,434 (9), 1.01 s |
| `Authority.ReconciledCreate_reach.cfg` | Reconciliation writes the creation entry of a crashed commit | new, TwoOps | `NotReconciledCreate` violated, as required, 4703 (8), 1.63 s | `NotReconciledCreate` violated, the target is reached, 11,040 (9), 1.10 s |
| `Authority.ReconciledVoid_reach.cfg` | Reconciliation voids the entry of a crashed operation that did not commit | new, TwoOps | `NotReconciledVoid` violated, as required, 4765 (7), 1.52 s | `NotReconciledVoid` violated, the target is reached, 10,089 (8), 1.17 s |
| `Authority.RefusedKept_reach.cfg` | F3: a refused unlink voided its entry, and a restored store keeps its anchor | new, TwoOps | `NotRefusedKept` violated, as required, 79263 (11), 3.63 s | `NotRefusedKept` violated, the target is reached, 81,260 (12), 2.00 s |
| `Authority.TwoInDoubt_reach.cfg` | `Turn = "entry"`: two consumptions of one value in doubt at one restore | new, TwoOps | `NotTwoInDoubt` violated, as required, 25743 (9), 2.51 s | `NotTwoInDoubt` violated, the target is reached, 19,551 (9), 1.26 s |

## Inductive proofs

`AuthorityInd.tla` proves `Safety` for histories of any length, with counter values and journal
sequences as unbounded integers: `NothingEndedValid`, `OneBootValid`, `NoCounterReuse`,
`MissingOutcomeUnknown`, `NoUncommittedAnchor`, `RefusalHolds`, `OneUse`, `PendExact`, and
`NoDoubtServing`, for both origins. The invariant has eight parts: `TypeInd`, the journal and history clauses
(`JournalInv`), committed ends hold in the store and in each later snapshot (`EndInv`), outcome
records are commits (`OutcomeInv`), the in-doubt state (`DoubtInv`), created anchors and their
entries against each snapshot's low-water mark (`AnchorInv`), at most one valid bootstrap value
in the store and in each snapshot (`BootInv`), and the artifact values against the counter and
the durable floor (`CounterInv`). Until 2026-11-08, a part `AdminInv` was in the place of
`BootInv`, and it proved `AdminKeptP` (see below).
`IndInit` builds each of its two snapshots from generated fields: `Gen(7)` for the anchor
function (seven anchors), and `Gen(3)` for each set of bootstrap values and each outcome set.
So the proof covers stores and snapshots that hold, consumed, or ended at most three bootstrap
values; each step adds at most one, and the declared TLC bounds have at most two. With `Gen(7)`
for the whole snapshot set, the same witness took 714 s against 7.5 s, so the step checks did not
fit the development host.
`Replay.tla` proves `Safety` of the replay window for every non-negative `Skew`, `U`, and
`MaxWin` and every integer time. The acknowledgement order of 2026-11-08 (`CreationPending`) only
removes behaviors of `Ack` and `Resolve`, and the proof modules did not change for it; the step
checks ran again on the current files and passed.

Not inductive: `AnchorKept`, `AccountKeepsAnchorP`, and, since 2026-11-08, `AdminKeptP`. An
inductive form needs, for each promised anchor and each retained snapshot, the creation and end
entries of every anchor of its owner against the snapshot's low-water mark, together with the turn
of each owner and the crash point of each operation that holds it. Until 2026-11-08 no transition
ended the administrator binding, so `AdminInv` proved `AdminKeptP` without that. Now an unlink
with the last-anchor check can end an administrator binding, as it ends a sign-in method, so
`AdminKeptP` needs the same form. The TLC searches check all three at their bounds.

| Profile | Check | Record of earlier files: verdict, time | Current files |
| --- | --- | --- | --- |
| `AuthorityInd.DoubtSnapshot_reach.apalache` | `IndInit` contains `~NoDoubtSnapshot` | `NoDoubtSnapshot` violated, as required, 11.13 s | `NoDoubtSnapshot` violated, the target is reached, 19.76 s |
| `AuthorityInd.EndedValueSnapshot_reach.apalache` | `IndInit` contains `~NoEndedValueSnapshot` | `NoEndedValueSnapshot` violated, as required, 10.10 s | `NoEndedValueSnapshot` violated, the target is reached, 22.03 s |
| `AuthorityInd.Init.apalache` | `Init => IndInv` | Pass, 6.17 s; and `ok in 8.21s (exit status: 0)`, outcome NoError, on the files of digest `sha256:7b5cf1bc…` (104 files) | Pass, 13.25 s |
| `AuthorityInd.IssueReady_reach.apalache` | `IndInit` contains `~NoIssueReady` | `NoIssueReady` violated, as required, 7.71 s | `NoIssueReady` violated, the target is reached, 16.46 s |
| `AuthorityInd.Pending_reach.apalache` | `IndInit` contains `~NoPending` | `NoPending` violated, as required, 8.17 s | `NoPending` violated, the target is reached, 16.46 s |
| `AuthorityInd.Safety.apalache` | `IndInv => Safety` | Pass, 26.62 s | Pass, 57.23 s |
| `AuthorityInd.StepAgain.apalache` | `IndInv /\ NextAgain => IndInv'` | Pass, 382.12 s | Pass, 892.72 s |
| `AuthorityInd.StepBoot.apalache` | `IndInv /\ NextBoot => IndInv'` | Pass, 1200.19 s | Pass, 2365.38 s |
| `AuthorityInd.StepCommit.apalache` | `IndInv /\ NextCommit => IndInv'` | Pass, 305.43 s | Pass, 988.18 s |
| `AuthorityInd.StepConflict.apalache` | `IndInv /\ NextConflict => IndInv'` | Pass, 445.06 s | Pass, 1590.06 s |
| `AuthorityInd.StepEnd.apalache` | `IndInv /\ NextEnd => IndInv'` | Pass, 348.80 s | Pass, 1275.02 s |
| `AuthorityInd.StepEnroll.apalache` | `IndInv /\ NextEnroll => IndInv'` | Pass, 654.05 s | Pass, 2896.10 s |
| `AuthorityInd.StepFail.apalache` | `IndInv /\ NextFail => IndInv'` | Pass, 182.75 s | Pass, 700.87 s |
| `AuthorityInd.StepIssueEnd.apalache` | `IndInv /\ NextIssueEnd => IndInv'` | Pass, 905.40 s | Pass, 3052.31 s |
| `AuthorityInd.StepIssueNone.apalache` | `IndInv /\ NextIssueNone => IndInv'` | Pass, 962.45 s | Pass, 2761.80 s |
| `AuthorityInd.StepJournal.apalache` | `IndInv /\ NextJournal => IndInv'` | Pass, 617.63 s | Pass, 1446.19 s |
| `AuthorityInd.StepRec.apalache` | `IndInv /\ NextRec => IndInv'` | Pass, 1001.28 s | Pass, 1505.67 s |
| `AuthorityInd.StepRecover.apalache` | `IndInv /\ NextRecover => IndInv'` | Pass, 1387.04 s | Pass, 2640.55 s |
| `AuthorityInd.StepRenew.apalache` | `IndInv /\ NextRenew => IndInv'` | not run | Pass, 3089.98 s |
| `AuthorityInd.StepRestore.apalache` | `IndInv /\ NextRestore => IndInv'` | not run | Pass, 1853.26 s |
| `AuthorityInd.StepRevoke.apalache` | `IndInv /\ NextRevoke => IndInv'` | not run | Pass, 2566.24 s |
| `AuthorityInd.StepServe.apalache` | `IndInv /\ NextServe => IndInv'` | not run | Pass, 3184.65 s |
| `AuthorityInd.StepUnlink.apalache` | `IndInv /\ NextUnlink => IndInv'` | not run | Pass, 2227.65 s |
| `AuthorityInd.TwoReleased_reach.apalache` | `IndInit` contains `~NoTwoReleased` | not run | `NoTwoReleased` violated, the target is reached, 15.78 s |
| `Replay.AcceptedGone_reach.apalache` | `IndInv` contains `~NoAcceptedGone` | not run since 2026-11-08 | `NoAcceptedGone` violated, the target is reached, 5.81 s |
| `Replay.FloorNoSkew_bad.apalache` | `Init /\ Next => NoDoubleAccept'` | not run since 2026-11-08 | `NoDoubleAccept` violated, as required, 6.42 s |
| `Replay.Init.apalache` | `Init => IndInv` | not run since 2026-11-08 | Pass, 4.90 s |
| `Replay.InsertLate_bad.apalache` | `Init /\ Next => NoDoubleAccept'` | not run since 2026-11-08 | `NoDoubleAccept` violated, as required, 6.89 s |
| `Replay.NoInsertCheckDouble_bad.apalache` | `Init /\ Next => NoDoubleAccept'` | not run since 2026-11-08 | `NoDoubleAccept` violated, as required, 6.74 s |
| `Replay.NoInsertCheckLive_bad.apalache` | `Init /\ Next => NoLiveRemoved'` | not run since 2026-11-08 | `NoLiveRemoved` violated, as required, 6.70 s |
| `Replay.RetentionOneU_bad.apalache` | `Init /\ Next => NoLiveRemoved'` | not run since 2026-11-08 | `NoLiveRemoved` violated, as required, 5.93 s |
| `Replay.Safety.apalache` | `IndInv => Safety` | not run since 2026-11-08 | Pass, 5.39 s |
| `Replay.Step.apalache` | `IndInv /\ Next => IndInv'` | not run since 2026-11-08 | Pass, 3.60 s |

## Raise by one

Rule 4 of [FP Design Models]: a bound whose sufficiency the model argues but does not prove gets
one complete search with that bound raised by one before the evidence is final (selected on
2026-11-08 for A000). The constant `Raise` selects the raised bound; a raised element starts
inert (an idle operation, an absent slot), except the first anchor of a third account, which is
live as `a2p` is.

| Bound | Declared | Raised | Apalache proof | TLC profile |
| --- | --- | --- | --- | --- |
| Accounts | 2 | 3 (`a3p` live, `a3q` absent) | Fixed domain; `AuthorityIndRaise` | `Authority.RaiseAccounts.cfg` |
| Anchor slots of `a1` | 3 | 4 (`a1s` absent) | Fixed domain; `AuthorityIndRaise` | `Authority.RaiseSlotsA1.cfg` |
| Anchor slots of `a2` | 2 | 3 (`a2r` absent) | Fixed domain; `AuthorityIndRaise` | `Authority.RaiseSlotsA2.cfg` |
| Administrator slots | 2 | 3 (`adm3`) | Fixed domain; `AuthorityIndRaise` | In the re-bootstrap raise (below) |
| Operations | 3 | 4 (`o4` idle) | Fixed domain; `AuthorityIndRaise` | `Authority.RaiseOpsOne.cfg`, under the reduction to one account (`Authority.RaiseOps.cfg` was removed on 2026-11-08: an estimated 10 to 100 billion states) |
| Snapshots | 2 | 3 | Fixed domain; `AuthorityIndRaise` | `Authority.RaiseSnaps.cfg` |
| Counter values | up to 5 | up to 6 | Covered: unbounded integers | `Authority.RaiseCtr.cfg` |
| Owner re-bootstraps | 1 | 2, with `adm3` | The proof's `Next` has no bound; each value set in its starting set has at most three values (four in `AuthorityIndRaise`) | `Authority.RaiseIssues.cfg`, `Authority.RaiseIssuesBootstrapped.cfg` |

The journal sequence is an unbounded integer in the proofs, and it has no TLC bound. Each
bootstrap binds a new administrator slot, so the slots that a run can reach are one more than its
re-bootstraps (from a new authority) or `adm1` and its re-bootstraps (bootstrapped): with one
re-bootstrap, two slots are exactly what is reachable, and a third slot alone is never reached.
So the re-bootstrap raise brings the third slot, and a separate administrator-slot TLC search
would repeat the declared one.

`AuthorityIndRaise.tla` raises every domain at once (`Raise = "all"`). One combined raise covers
each single raise: a state of a model that raises one bound is a state of the combined model with
the other extra elements inert, each `IndInv` clause quantifies over the domains uniformly, and
each step of the smaller model is a step of the combined one. Its witness `RaiseUsed_reach` shows
that its starting set contains a state that uses each raised element.

`AnchorKept`, `AccountKeepsAnchorP`, and `AdminKeptP` have no inductive proof, so only the TLC
raises cover them. An inductive form was not found (analysis only; no checker run tried one).
The raise of the operations uses the independence argument across accounts, a reduction to one
account (selected on 2026-11-08; [Bounds, faults, and reductions](#bounds-faults-and-reductions)):

- The reduction: one account (or the authority's administrator bindings) with every operation
  free to act on it, and the global steps (crash, restart, snapshot, restore).
- Why it can hold: the turn, the last-anchor check, and the recovery binding read only the
  account's own anchors and entries. Another account's operations change only the shared journal
  sequence, the low-water mark (they can only lower it), and the counter. A lower mark makes a
  restore apply more entries, and an entry that a snapshot already reflects changes nothing,
  because facts are monotone.
- The failure that it could hide: an interaction through the shared low-water mark, the shared
  operation identities, or the counter.
- Known-bad variants that still fail under one account: the five `Authority.OneAccount*_bad`
  profiles of the earlier variants and `Authority.OneAccountAckEarly_bad.cfg`. The account has a
  fourth slot, absent at the start: the first form without it hid F1. No variant tests a
  cross-account interaction yet; one would compute the low-water mark from the account's own
  entries only.

## Evidence record

### Evidence host record of the current files

Runs of every profile on the evidence hosts from 2026-11-08 19:59 to 2026-11-09 02:56 UTC, each
with `cargo xtask model authority-restore/<profile>` from the repository root, one profile at a
time on a host (TLC) or one per core (Apalache). The xtask passes a profile only with the
checker's own completion or violation status and outcome, with no `TIMEOUT` or ignored line.

- Source: the files of this directory, not yet committed, on top of commit
  `1a6019fe46038ed534f8e084a2b6be8d2b77dd4c`. Each run printed
  `sha256:5549a6d42d03b46fe37fd498ff38b1413a6260383f23241d4ed8165dee760454 (111 files)`.
- Checkers: temurin-jre 21.0.13+9 (Linux aarch64, SHA-256 checked against Adoptium), tla2tools
  1.8.0+d8fb231de4e4 (TLC2 Version 2026.11.06.222357, rev d8fb231; SHA-256
  `e1f11b75c4b5bc4478ba0ac5cb6ae28e40a01b0016bc33e0aa97da22dfdbcd7f` checked), with `-workers auto
  -lncheck final`; apalache 0.62.4.
- Hosts: EC2 in us-east-1, image `ami-06b1a03fa3561aefb` (Ubuntu 26.04 arm64, 20261104.1),
  kernel 7.0.0-1016-aws, no other workload: c8g.12xlarge (48 vCPUs, 92 GiB) instances
  `i-05b81545f5b7a28ea` (the small TLC profiles, `Authority.cfg`, `Authority.Bootstrapped.cfg`,
  `RaiseCtr`, `RaiseSlotsA2`, `RaiseIssuesBootstrapped`), `i-0301356a189c645dc` (`RaiseSlotsA1`,
  `RaiseIssues`), `i-0a676670f8e703b3c` (`RaiseAccounts`), and `i-0df7ebb3e43d93ecb` (41 Apalache
  profiles, 40 at a time, then `RaiseSnaps`). Each instance is terminated. The host's own
  logs are not kept; the "Current files" columns above hold the figures of each profile.
- Result: every TLC profile except `Authority.RaiseOpsOne.cfg`, and every Apalache profile
  except the seventeen `AuthorityIndRaise.Step<Part>.apalache`, passed with its required
  verdict: each main and raise search complete with no violation, each known-bad variant a
  violation of its own property, and each witness its target. The searches: `Authority.cfg`
  218,052,725 distinct states (depth 36, 20 min), `Authority.Bootstrapped.cfg` 67,075,361 (36,
  6 min), `RaiseCtr` 260,779,156 (39, 24 min), `RaiseSlotsA2` 422,601,310 (36, 51 min),
  `RaiseSlotsA1` 770,348,006 (37, 92 min), `RaiseAccounts` 545,513,196 (36, 83 min),
  `RaiseSnaps` 552,749,238 (41, 55 min), `RaiseIssues` 220,953,314 (36, 25 min), and
  `RaiseIssuesBootstrapped` 67,750,337 (36, 7 min). The declared Apalache step parts took 12 to
  53 minutes each.

Two raise checks did not finish, so neither is a pass:

- `Authority.RaiseOpsOne.cfg` (four operations under the reduction to one account) ran on an
  r8g.16xlarge (64 vCPUs) from 2026-11-08 20:54 UTC. The user stopped it on 2026-11-09 at 02:55
  UTC, at 6,866,941,619 distinct states with 2,958,680,598 on the queue, depth 21, and no
  violation found; on the shape of `Authority.cfg` the whole search is about 13 to 14 billion
  states. An earlier start on a Spot host was lost to a Spot reclaim at 20:47 UTC.
- The seventeen `AuthorityIndRaise.Step<Part>.apalache` (every domain raised by one) ran on an
  m8g.8xlarge from 2026-11-09 00:10 UTC. Every step part stayed in one solver query, state
  invariant 41 of the starting state, from about 00:13 UTC to the end of the run at 02:56 UTC.
  An earlier start on a Spot host showed the same query in each step part that was read, from
  20:02 UTC, until a Spot reclaim after 21:20 UTC. That is a formulation defect of the raised
  starting set, not a resource limit. The raised `Init`, `Safety`, and the six raised witnesses
  passed.

Neither check fits the budget rule of [FP Design Models] (one hour on one 16-vCPU host). Symmetry
over the operations would not bring the operations raise into it: operations already start in
identity order (`Rank`), so symmetry removes only two to four times the states. The user
selected on 2026-11-09 to complete the model with both checks as named limits
([Limits](#limits)); task A016 closes them before A009.

Each block below is the record of earlier files: it shows the rules, and it is not the evidence
of the current files. Those runs used tla2tools 1.8.0+3ec1cc4f8c24 and apalache 0.62.4 on this Mac
(Darwin 25.6.0, aarch64, 10 cores, 16 GB), shared with other sessions' model checkers, so their
durations are indicative only. On the digest `sha256:7b5cf1bcf19c1e52e1d8850864d672d715f1078ab8a0ed3c28c3cd4715f48abf`
(104 files), `AuthorityInd.Init.apalache` passed (`ok in 8.21s (exit status: 0)`, outcome
NoError), and SANY parsed every module.

**Functional run**, record of earlier files (2026-11-08, digest `sha256:1023dd2115d4609b07d1ca77c6c9a2cf21b0e9ca1a3d40ae5c29a77c15fd25e7 (70 files)`): the owner re-bootstrap model before the `Raise` constant and the slot rule of the re-bootstrap raise. Its 50 rows are in the tables above: every TLC profile, and the Apalache profiles up to `AuthorityInd.StepRecover`. Each passed with its required verdict. The xtask before 12:06 ran the first 48; `StepRec` and `StepRecover` ran under the current xtask. These rows show the rules; they are not the evidence of the current files.

**Refactor check**, record of earlier files (digest `sha256:0b6c17bd3aba39728f0d3a5c3a431adfa8777aa757cb422de76e6bf9f585d2c2`, 81 files, current xtask): with `Raise = "none"`, `Authority.TwoOps.cfg` passed with 602,397 distinct states (51.51 s) and `Authority.TwoOpsBootstrapped.cfg` with 325,333 (23.00 s), the same counts as the functional run, so the parameterization keeps the declared behaviors.

**Raise probe**, record of earlier files (before the slot rule of the re-bootstrap raise): `AuthorityIndRaise.RaiseUsed_reach.apalache` reached its target in 151.27 s (exit status 12), against 7.5 s for the declared witness. `AuthorityIndRaise.StepCommit.apalache` ran about 516 s and was stopped with the host (exit status 143, no outcome): not a pass.

### Evidence host record

This record is for the model before the owner re-bootstrap (digest `904164456e72d62dced2890d6514f99a375675eb`, in the git object-ID form of the earlier xtask). It does not cover the current modules; `Authority.cfg` and `Authority.Bootstrapped.cfg` of the current modules wait for the evidence host.

`Authority.cfg` of that model, the declared bounds, on 2026-11-08. The estimate before the run was 0.1 to 0.4
billion distinct states; the stop condition was a complete search, a violation, or 12 hours.

- Command: `cargo xtask model authority-restore/Authority.cfg`, from the repository root, with a
  limit of 12 hours (`timeout 43200`).
- Source: the files of this directory, the same as the runs above. The digest that the xtask
  printed: `904164456e72d62dced2890d6514f99a375675eb (56 files)`.
- Checkers: temurin-jre 21.0.13+9 (Linux aarch64, SHA-256 checked against Adoptium), tla2tools
  1.8.0+3ec1cc4f8c24 (TLC2 Version 2026.11.06.005304, rev 3ec1cc4; the pinned jar, SHA-256
  `654aa501…` checked), with `-workers auto -lncheck final`.
- Host: EC2 m8g.4xlarge (16 vCPUs, 64 GiB), us-east-1a, image `ami-06b1a03fa3561aefb` (Ubuntu
  26.04 arm64, 20261104.1), kernel 7.0.0-1016-aws, instance `i-0376f74828732047c`, no other
  workload. The instance is terminated.
- Result: exit status 0, a complete search with no violation of `TypeOK`, `NothingEndedValid`,
  `NoCounterReuse`, `MissingOutcomeUnknown`, `NoUncommittedAnchor`, `AnchorKept`, `AdminKeptP`,
  `AccountKeepsAnchorP`, `RefusalHolds`, `OneUse`, `PendExact`, and `NoDoubtServing`.
  410,188,991 states generated, 176,229,386 distinct states, depth 36, 29 min 39 s
  (2026-11-08 07:18:42 to 07:48:23 UTC).
- Replay: the same command writes the checker output to
  `target/model/authority-restore/Authority.cfg/checker.log`. The host's own log is not kept.

That search was the bounded check of `AnchorKept` and `AccountKeepsAnchorP` for that model.

## Limits

- Two raise checks are not done (selected on 2026-11-09). The operations bound (three operations)
  of `AnchorKept`, `AccountKeepsAnchorP`, and `AdminKeptP` has no raise-by-one search: these three
  properties have no inductive proof, and the raise to four operations is more than 6.8 billion
  states. Each other bound of the three properties has its raise, and each other property has its
  inductive proof at the declared domains. The inductive steps with every domain raised by one
  (`AuthorityIndRaise`) do not finish: each stays in one solver query of the starting set. The
  raised `Init`, `Safety`, and witnesses pass, and the TLC raises cover each raised domain for the
  TLC bounds. Task A016 closes both limits, with an inductive proof of the three properties,
  before A009 builds the restore journal.
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
