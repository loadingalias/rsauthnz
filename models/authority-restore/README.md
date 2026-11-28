# authority-restore: design model of tasks A000 and A016

Status (2026-11-17): 117 of the 118 profiles pass at the current files.
`AuthorityIndProcess.Step.apalache`, the step of the process raise, reached its 3600-second cap
with one of its 447 clause pairs unfinished. So the raise by one of operations, snapshots, and
bootstrap identities is a named limit ([Limits](#limits)).

The [Evidence record](#evidence-record) gives the result of each of the 118 profiles at the
current digest. The proof work found one gap of the model and one weak property, and both are
closed ([Decisions](#decisions)). A lookup promised the anchor set of the operation's latest
commit, not of the outcome record that it found. `AnchorKept` excused an anchor that an operation
planned to end before that operation wrote its end entry.

The [shared recovery model](../replica-commit/README.md#shared-recovery) checks owner turns and journal writes across application servers.
It checks the separate destination fences that establish the crash boundary used here.

## Promise

- **Authority and restore** (`Authority.tla`). After any sequence of crashes, restarts, and
  restores, nothing that a committed transition ended is valid again. At most one bootstrap value
  is valid, and the local owner can issue a new one after the first is consumed. No counter value
  is issued twice. A missing outcome after restore is unknown. Restore adds no anchor whose commit did not
  complete. A refusal that a client received stays true. Each one-use value is spent at most once
  in the store's history. While the store serves, each account and the authority keep the anchors
  that acknowledged commits left them. A concrete failure: a restore from yesterday's snapshot
  makes a revoked passkey valid again, or removes the last sign-in method of an account.
- **Recovery progress** (`AuthorityRecovery.tla`, `AuthorityInd.tla`). When crashes stop and
  enabled recovery work is weakly fair, reconciliation completes and the store serves. A failure:
  every required journal write completes, but the store remains in reconciliation.
- **Store fencing** (`Fencing.tla`). A request from an earlier store instance cannot commit after
  a start installs a new instance number. A failure: a delayed request changes the store during
  reconciliation with a request from the previous instance.
- **Replay window** (`Replay.tla`). For every clock error within its bound, no signature is
  accepted twice, and no record is removed while a verifier can still accept its signature. A
  concrete failure: two verifiers that share one store both accept one captured request.

## Run it

```sh
cargo xtask model authority-restore/Authority.TwoOps.cfg   # one profile
cargo xtask model authority-restore/Authority.TwoOps.cfg authority-restore/Replay.Step.apalache
cargo xtask model authority-restore                        # every profile
cargo xtask model authority-restore/AuthorityInd.Step.apalache   # one complete inductive step
```

`cargo xtask model authority-restore` includes the declared-bounds searches `AuthorityCached.cfg` and
`AuthorityCached.Bootstrapped.cfg` and the step checks of the proofs.
Each profile has a cap of one hour. Run each Step on a Linux host with 16 cores and 96 GiB of
available memory, where it runs 16 native jobs at a time. Run selected profiles by name.
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
| `AuthorityCached.cfg` | TLC | Every authority property, `Origin = "new"` | Declared |
| `AuthorityCached.Bootstrapped.cfg` | TLC | Every authority property, `Origin = "bootstrapped"` | Declared |
| `Authority.TwoOps.cfg` | TLC | Every authority property, `Origin = "new"` | TwoOps |
| `Authority.TwoOpsBootstrapped.cfg` | TLC | Every authority property, `Origin = "bootstrapped"` | TwoOps |
| `Authority.Race.cfg` | TLC | Every authority property, with `Turn = "entry"`: each turn ends at the first journal write, so two consumptions of one value can be in doubt at one restore | TwoOps |
| `Authority.<Rule>_bad.cfg` | TLC | One known-bad variant ([Known-bad variants](#known-bad-variants)) | TwoOps; `Unserialized_bad` Declared |
| `Authority.<Target>_reach.cfg` | TLC | One reachability witness ([Reachability](#reachability)) | TwoOps; `AdminReplaced_reach` Declared |
| `AuthorityInd.Init.apalache` | Apalache | `Init => IndInv` | Declared domains |
| `AuthorityInd*.Step.apalache` | Apalache | Complete `IndInv /\ Next => IndInv'`, in 67 exhaustive groups under one budget | Declared and both raised domains |
| `AuthorityInd.Safety.apalache` | Apalache | `IndInv => Safety` | Declared domains |
| `AuthorityInd*.RecoveryRank.apalache`, `AuthorityInd*.RecoveryReady.apalache` | Apalache | Each recovery step decreases a non-negative rank, and a step is enabled whenever the store does not serve | Declared and both raised domains |
| `AuthorityInd.<Witness>_reach.apalache` | Apalache | `IndInit` contains a key state ([Inductive proofs](#inductive-proofs)) | — |
| `AuthorityIndOwnMark.SnapshotOwnMark_bad.apalache` | Apalache | Known-bad variant `ownMark`: the full `Next` breaks `SnapshotEnds`, the snapshot-entry clause of `EndInv` | Declared domains |
| `AuthorityIndAnchors.<Check>.apalache` | Apalache | Each check of `AuthorityInd` with the anchor domains raised by one, and the witnesses `AccountsUsed_reach` and `AdminUsed_reach` | Three accounts, four slots in `a1`, three in `a2`, three administrator slots |
| `AuthorityIndProcess.<Check>.apalache` | Apalache | Each check of `AuthorityInd` with the process domains raised by one, and the witness `ProcessUsed_reach` | Four operations, three snapshots, five bootstrap-value identities |
| `Authority.AllIssueValues_reach.cfg`, `Authority.RaisedIssueValues_reach.cfg` | TLC | The initial value and every issue operation produce four values, or five in the process raise | Issue operations only; no snapshots |
| `AuthorityRecovery.cfg` | TLC | `Recovers` under the recovery fairness rule | One submitted operation, at most one restore, and any number of crashes and restarts |
| `AuthorityRecovery.NoServe_bad.cfg` | TLC | A disabled `Serve` violates `Recovers` under the same fairness | No submitted operation |
| `Fencing.cfg`, `Fencing.Raised.cfg` | TLC | Each committed request belongs to the instance that accepted it | Two requests and one restart; three requests and two restarts |
| `Fencing.NoInstance_bad.cfg`, `Fencing.Crossing_reach.cfg` | TLC | The missing instance check fails; an old request refuses while a new one commits | Two requests and one restart |
| `Replay.Init.apalache`, `Replay.Step.apalache`, `Replay.Safety.apalache` | Apalache | The inductive invariant of the replay window, and `IndInv => Safety` | Unbounded integers and time |
| `Replay.AcceptedGone_reach.apalache` | Apalache | `IndInv` contains an acceptance whose record expired while a verifier holds a check | — |
| `Replay.<Rule>_bad.apalache` | Apalache | One known-bad variant, 10 steps | Unbounded integers and time |

`AuthorityCached` materializes each owner's constant anchor sets once with `TLCEval`.
Its configurations replace `Anc` and `Protected` with maps of the same sets.
Eight `Next` wrappers run the same `Start` relations behind their shared readiness guards.
The unlink and recovery wrappers use the same actions over prefiltered constant candidate pairs.

The pair sets apply only the original owner, inequality, and protected-anchor guards.
Every state-dependent guard, `Propose` call, and recovery retirement subset stays unchanged.
This removes constant-invalid candidates from TLC enumeration without removing any transition.

The shared phase, idle operation, and operation order guards run before each `Start` family expands its candidates.
These guards already hold at every `Propose` call.
TLC can give the resulting actions different labels. Check the property and state facts in each trace.
The declared unlink domain has 15 eligible pairs, or 20 for `countRecovery`, instead of 81 candidate pairs.
The recovery domain has five eligible pairs instead of ten candidate pairs.

The constant-set and candidate replacements keep every transition and property unchanged.
Arguments outside `Owners \cup {""}` return the empty set, as the original operators do.

The cached TLC profiles also rename `a1p`, `a1q`, and `a1r` to three distinct native model values.
These sign-in slots have the same owner, initial state, and recovery classification.
Their `Anchors`, `Owner`, and `InitLive` definitions contain the only executable references to those original identities.
`AnchorSymmetry` permits all permutations of the three values.
It permutes the entire state, including anchor maps, plans, snapshots, outcomes, and promises.

Every action, property, and constraint treats these slots through the same owner and set membership rules.
The operation order distinguishes operation identities, and the bootstrap priority distinguishes administrator slots. Neither rule distinguishes these three account slots.
Thus renaming maps each original behavior to a cached behavior, and permutation preserves every configured safety property.
The three model values keep the original domain cardinality.
No temporal profile uses this symmetry.

A review of each change to these definitions checks the inverse renaming against the original
definitions, the three model-value assignments, and the permutation group.

Both `CountRecovery_bad` and `Unserialized_bad` must qualify the symmetry with `AccountKeepsAnchorP` violations.
`CountRecovery_bad` must remove the last account sign-in method while keeping a recovery value.
That fault can occur on account `a2`.
The `Unserialized_bad` trace must check all three `a1` slots concurrently and resume service after restore with all three ended.
Both faults and both positive TwoOps origins pass their qualifications. Both full searches also pass.

Six plain constant aliases cache function-space expressions in `TypeOK` and `SnapOK` without enumerating those spaces.
The cached predicates equal the original predicates after alias expansion.

`AuthorityCached.CountRecovery_bad.cfg` uses all replacements and must still violate `AccountKeepsAnchorP`.
The wrapper's three profiles replace the earlier full searches and this existing fault qualification. The inventory remains 118 profiles.

The twenty-three parts of `Next` are one action each (`Authority.tla`): the eight kinds of
`Start`, `JournalEnd`, `Commit`, `Conflict`, `JournalCreate`, `Ack`, `Resolve`,
`ReconcileCreate`, `ReconcileVoid`, `Redrive`, `RedriveFail`, `Crash`, `Restart`, `Serve`,
`Snapshot`, and `Restore`. `Next` uses these definitions directly.

The runner reads `induction.matrix` and requires each domain's `Init`, `Step`, and `Safety`
profiles with their exact initializers and lengths. For `Step`, it derives the action names from `Authority.Next`
and the component names from `AuthorityInvariant.IndInv`. It requires each action/component pair exactly once
in `AuthorityPreservation`, with exact primed aliases. Each assumption is an existing invariant conjunct.
Each group starts from a set that includes every invariant state. The complete product includes `TypeInd`.

A missing pair, alias, domain profile, or completed group prevents a complete proof. The three Step
entries are logical profiles. Their 209 native jobs share three aggregate proof budgets.

## Correspondence: authority and restore

Each action is one atomic design step. The source is [AUTH Storage Contract and Bindings] unless
the row names [AUTH Authority Transitions]. The code column names the A007 code of each action in
`src/transition/mod.rs`, the A008 storage primitive in `src/store/mod.rs`, the A009 journal rule
in `src/store/journal/` (`journal::` below), and the A017 driver transition in `src/store/driver/`
(after "Driver:"), and the case of the conformance suite `rsauthnz_conformance::suite` (A011) that checks
it (after "Case:").

| Action | Design rule | Atomicity | Crash point after it (`pc`) | Code |
| --- | --- | --- | --- | --- |
| `Start(o)`: `StartEnroll`, `StartUnlink`, `StartRecover`, `StartBoot`, `StartRenew`, `StartRevoke`, `StartIssue` | The core checks the request and proposes a transition of one kind. A bootstrap takes a valid bootstrap value and binds a new administrator. `StartIssue` is the owner re-bootstrap ([AUTH Authority Transitions], selected on 2026-11-08): it plans to end the valid bootstrap value, if any. An unlink of an administrator binding keeps another administrator that the journal records as live ([AUTH Authority Transitions]). An anchor change takes its owner's turn. An unlink keeps an anchor that the journal records as live ("counts the journaled anchors that the change does not end"). A recovery binds its new anchor in the commit that consumes its value | Check and turn, one step | Before a journal write (`cChecked`) | `Proposal::new` binds the operation identity to the actor, the action, and the request. `Proposal::read` lists each read as a dependency (`Dependency`). `Proposal::change` admits a change only with a read that allows it. The check of each kind comes with its transition. `journal::keeps_anchor` is the last-anchor check (`Journaled`, `Protected`): it counts the anchors that the store holds or that a creation entry made, that no unvoided fact ends, and the sign-in methods that the same consuming commit creates. Driver: `Driver::submit` queues the operation. When it runs, it holds the turn of every owner, because the driver runs one operation at a time, and `CommitPhase::Check` runs `journal::keeps_anchor`. Local authority (A105): `local::Authority::issue` proposes `StartIssue`. It reads the record of the authority (`Kind::Local`), whose log names the one value that can be valid, and that value at its version or its absence (`DepOK`). It ends that value and writes a value with a new random identity (`bnext`). `local::Authority::bootstrap` and `Pending::finish` propose `StartBoot`: the value at its version and the absence of the administrator binding, whose key ends with the serial of its credential, so each bootstrap binds an absent slot. The plan names it as an `Administrator` anchor. `local::Authority::unlink` proposes an unlink of an administrator binding, with each binding in `Plan::held`: one range read of the bindings of the authority (`Store::range`). It also reads, at its version, a binding that stays and whose CLI credential is valid (`keep`), so a concurrent unlink of that binding conflicts on a binding with no journal too. An administrator binding ends with its CLI credential, and expiry removes it outside the model: the driver keeps no rule for it, a start skips an anchor with an end (`Restored`), and the unlink counts no binding whose credential ended. Case: `RestoreAnchors` (an unlink keeps the enrolled anchor), `Bootstrap` (two concurrent unlinks of the last two administrators), `Rebootstrap` |
| `JournalEnd(o)` | Write rule: the end entry is durable before its commit. A consumption entry records its transition. The model releases an unlink turn early, as the abstraction below explains | One journal append | Between a journal write and its commit (`cJournaled`) | `Journal::append`, then `Journal::sync`. `journal::entries` gives the end entry (`Body::End`, `PreWrite`): a fact for each end and each replaced version, and for a consumption (`Consumes`) its transition. `Mark::next` gives its stored form, with the link of the entry before it. Driver: `CommitPhase::Entries` appends the floor entries and the end entry (`Effect::Append`), then one `Effect::Sync`. Case: `CrashPoints` (`cChecked`, `cJournaled`), `RestoreJournal` |
| `Commit(o)` | Serializable conditional commit of every dependency, the state change, and the outcome record ([AUTH Authority Transitions]). The record keeps the anchors of the owner that the commit leaves live (`left`): what the commit promises when it is acknowledged. An owner re-bootstrap depends on the valid bootstrap values that it checked; its commit adds a value with a new identity and ends the value that it checked. The outcome record and the audit stand for the authority's report of each issue and each consumption. Allocation floors: the floor is durable before a commit allocates a value above it | One step, because the storage contract makes the commit atomic; the floor write and the commit are one step, because the state between them differs only by a higher floor | Between a commit and its creation entry, or before the acknowledgement (`cCommitted`) | The commit checks `Proposal::dependencies` and writes `Proposal::changes`, `Proposal::audit`, `Proposal::intents`, and the outcome record `Operation`. `Proposal::accept` gives the `Receipt`. `Store::commit` checks the instance number, each dependency, and the absence of an outcome record, and writes them together (`Commit::Accepted`). `Floor::reserve` gives the floor entry that is durable before the commit of a value above the durable floor, one for each block (`FloorAt`). Driver: `CommitPhase::Commit` gives `Effect::Commit` with the instance number of the latest start, after the floor entry of each value above the durable floor. A binding with no journal commits its floors in the mark record first. The report of the local authority is the issue log of `Kind::Local`, which the commit of each issue writes, and the administrator bindings of one range read (`local::Authority::report`). Each binding holds the issue of its value, so a restore that keeps a binding keeps its issue in the report. Case: `Commit`, `DependencyConflict`, `ConcurrentConsumption`, `AbsenceRace`, `RestoreFloors`, `Bootstrap` |
| `Conflict(o)` | A changed dependency refuses the commit. Write rule: the refusal voids each entry of its operation before it returns | One step: a crash before the void is the crash at `journaled` | — | `Outcome::Conflict`, with the recovery `Recovery::Restart`. `Store::commit` gives `Commit::Conflict` and writes nothing. `Entry::void` gives the void (`Body::Void`) of the end entry. Driver: `CommitPhase::Void` appends the void of the end entry and syncs before the answer, also for `Commit::Recorded` of another request. Case: `DependencyConflict`, `RefusalVoid` |
| `JournalCreate(o)` | The creation entry, after its commit and before its acknowledgement. It ends the turn | One journal append | Before an acknowledgement (`cCreated`) | `Journal::append`, then `Journal::sync`. `Entries::creation` gives the anchors of the creation entry (`Body::Creation`). Driver: `CommitPhase::Creation` appends the creation entry and syncs. `CommitPhase::Release` then ends the `Effect::Journal` intent of an anchor commit with no consumption. Case: `CrashPoints` (`cCommitted`, `cCreated`), `RestoreAnchors` |
| `Ack(o)` | The response, after the floor covers the artifact's value. Acknowledgement order (selected on 2026-11-08): an anchor change of an owner is acknowledged only after each other commit of that owner that created an anchor has its creation entry (`CreationPending`), so a restore keeps each anchor in the state that the acknowledged commit saw. The acknowledgement adds the anchor set of its outcome record to the promises (`promised`) | One step | — | `Outcome::Accepted`: `Receipt::artifact` releases the prepared artifact. `State::acknowledges` is the acknowledgement order (`CreationPending`). Driver: `Driver::take` gives the answer only after the creation entry is durable. One operation runs at a time, so no other anchor commit of the owner lacks its creation entry. Case: `CrashPoints` (`cCommitted`) |
| `Resolve(o)` | A client whose response was lost looks up its operation identity and receives the committed outcome ([AUTH Authority Transitions]: "Resolve it through the accepted receipt/current-state contract"). A lookup that reports a commit is an acknowledgement too, so it has the same `CreationPending` guard (selected on 2026-11-08). It promises the anchor set of the outcome record that it finds: after a restore, the record of the snapshot (2026-11-09) | One step | — | `Outcome::recovery` gives `Recovery::Lookup` for `Outcome::Unknown`. `Operation::answer` gives the receipt of the same request, with no artifact, and refuses another request (`Error::Reuse`). `Store::outcome` reads the outcome record. `Commit::Recorded` gives it to a second submission. `State::acknowledges` also holds a lookup that reports a commit. Driver: `Driver::lookup` reads the outcome record after each earlier operation and after the reconciliation of the start, and gives `Lookup::Unknown` for a missing record after a restore. Case: `LostResponse`, `CrashPoints`, `RestoreJournal` |
| `Crash` | A crash stops each operation in flight at its point; the store and the journal keep their durable state | One step | — | Driver: `Output::Failed` stops the driver (`Status::Down`). The operation in progress gets `Outcome::Unknown`, unless its creation entry or its void was durable. Case: `CrashPoints`, `LostResponse`, `FailedSync` |
| `Restart`, `Serve` | A start reconciles before it serves; the store serves only with no missing creation entry, no entry to void, and no in-doubt consumption | One step each | — | `Store::start` writes the next `Instance`. `Profile::new` refuses a binding without an atomic conditional commit. `History::extend` reads the journal after the mark and checks its chain, from the link of the mark. The store serves when `journal::reconcile` gives nothing and `Activation::completions` is done. Driver: `Driver::start` gives `Effect::Start`, reads the mark record (`Kind::Mark`), the journal after its mark, the journal intents, and the keys, refuses a store state that a restore made (`Error::Restored`, which the model does not have), then reconciles. `StartPhase::Close` writes the mark record and the floor entry of its write, and sets `Status::Serving`. Case: `Restart`, `CrashPoints` |
| `ReconcileCreate(o)`, `ReconcileVoid(o)` | Reconciliation writes the missing creation entry of each anchor whose commit has an outcome record, and a void for each end entry whose fact does not hold in the store | One journal append each | A crash during reconciliation | `journal::reconcile`: `Reconciliation::creations` (`NeedsCreate`), and `Reconciliation::voids` for each end entry whose fact does not hold (`NeedsVoid`, never for a missing outcome). Driver: `StartPhase::Reconcile` appends the creation entries and the voids of `journal::reconcile`, with the journal intents as candidates. `StartPhase::Release` then ends those intents. Case: `CrashPoints`, `StartAfterRestore` |
| `Redrive(o)`, `RedriveFail(o)` | Restore completes each in-doubt consumption: the first in journal order for each value commits again under its operation identity when its dependencies hold; otherwise the value stays consumed. A bootstrap value must be one that the restored store holds and that no re-bootstrap entry ended | One step each, because the commit is atomic | A crash during reconciliation | `journal::restore` gives `Activation::completions`: in journal order (`First`), each candidate whose `AgainOK` holds. A candidate whose `AgainOK` fails is left out (`RedriveFail`), and a completion removes the other candidates of its value. Driver: `StartPhase::Complete` commits `Proposal::again` for each completion that the mark record owes and that has no outcome record. A conflict leaves the value consumed. Case: `RestoreCompletions`, `Rebootstrap` |
| `Snapshot` | A snapshot with its low-water mark: the highest journal sequence at or below which every entry is reflected. It holds the outcome records with their anchor sets | One step | — | `journal::low_water` (`LowWater`, `Unreflected`) across all owners. A floor entry is reflected only when a later floor of its counter covers it, so a restore reads the newest floor of each counter. Driver: the mark record is store state, so each snapshot holds its mark. `Driver::advance`, also after each start and after `ADVANCE_AT` entries, moves it, and writes the floor of each counter again when a floor entry holds the mark. Case: `RestoreJournal`, `RestoreFloors`, `StartAfterRestore` |
| `Restore(s)` | Restore from any retained snapshot of a store that is down: apply each entry after the low-water mark that no void cancels, keep an ended anchor ended, raise the floor, and mark each in-doubt consumption; reconciliation follows. The store holds the snapshot's bootstrap values and outcome records, so a value issued after the snapshot is lost; consumption and re-bootstrap entries apply as facts | One step before reconciliation | — | `journal::restore`: `Activation::facts` (`endedX`), `Activation::anchors` (`madeX`), `Activation::floors` (`jfloor`), `Activation::ends` (the kinds that pay for no anchor), and the candidates (`doubt`, `known`, `taken`). `journal::replay` gives the state of the entries in any order (`Applies`). `History::extend` refuses a journal that does not reach back to the mark, or that is of another history, which the model does not have. Driver: `Driver::restore` decides from the reads of the snapshot state, writes the mark record with the completions owed and `restored` before any change (`StartPhase::Record`), then commits the facts, the anchors, and the replay floor (`StartPhase::Apply`), ends the pending records (`StartPhase::Ends`), completes, and reconciles. A start after a crash during a restore applies it again from the mark record. Case: `RestoreJournal`, `RestoreRefusal`, `RestoreAnchors`, `RestoreCompletions`, `RestoreEnds` |

The design retains an unlink's owner lock until its commit or refusal.
The model maps that retained lock to `"none"` after the durable end entry.
This abstraction permits additional starts between the entry and the commit or refusal.
The implementation's eventual lock release maps to a model step that changes no state.
The proof must cover those additional model behaviors. This abstraction does not change the design's lock rule.

Turn release points of the driver (A017). The driver runs one operation at a time, so each
operation holds the turn of every owner from its first effect to its last. An anchor creator
holds it through its durable creation entry, and through the end of its journal intent. An
unlink holds it through its commit result, and through its void when it refuses. A cancelled
operation keeps it until then. Each release of an anchor creator is at or after its durable
creation entry, as the full inductive checks select (`Turn = "creation"`). Each release of an
unlink is after the model's release at its durable end entry, so it maps to a model step that
changes no state. The driver uses no earlier release, so it does not depend on the bounded TLC
evidence of `Turn = "entry"`.

Merged rules, each with the same journal rule in the design:

- The authority anchors are passkeys, provider links, CLI credentials, recovery values, and
  administrator bindings (CLI credentials selected on 2026-11-08). `SignIns` represents passkeys
  and provider links. `Recoveries` has separate slots, with the same journal rules. `Protected`
  excludes recovery values, so one cannot justify removal of the last sign-in method. The
  `countRecovery` variant breaks this rule.
- A CLI credential of an account has the same journal rule, but it is not a sign-in method and does not count toward the
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
- `StartRecover` consumes a member of `Recoveries`, retires the displaced `SignIns` in its
  `retire` set, and creates a new sign-in method in the same commit. The design requires
  credential/session revocation with recovery ([AUTH Authority Transitions]) and retirement
  of displaced authority ([AUTH Passkey Profile]). The model checks the credential part;
  session invalidation has the separate `revoke` transition. The consumed value and displaced
  methods share one journal entry and atomic commit, and `Ends` applies both effects. The
  same-commit creation pays the last-sign-in check, so every displaced method can retire.
  `AccountAfterDoubt_reach` requires a real recovery value and a nonempty retirement set.
- The old recovery abstraction used one anchor identity for both the payment and the displaced
  sign-in method. The revised `NoAgainAccount_bad` consumes a recovery value and retires the last
  displaced method before its unresolved replacement; it fails `AccountKeepsAnchorP`.
  `NoAgainRecovery_bad` checks `NoDoubtServing` even when no method retires.
  `RestoreRetirement_bad` applies the payment's end but omits retirement; it fails
  `NothingEndedValid`. `RecoveryOnly` selects actual recovery requests;
  `RecoveryWithoutRetirement` additionally keeps every existing sign-in method in the
  unresolved-work canary, so that check cannot rely on the last-sign-in failure.

## Correspondence: store fencing

`Fencing.tla` checks the instance dependency of [AUTH Storage Contract and Bindings], "Fencing".
`Submit` retains the sender's instance number. `Crash` leaves remote requests pending. `Start`
writes the next durable instance number before it enters reconciliation. `Complete` reads that
number in the same atomic conditional transaction as its commit.

All other dependencies hold, so the check cannot rely on an unrelated conflict to refuse an old request. `Serve` ends
reconciliation. The model does not copy the authority or journal algorithm.

A request can complete after a physical crash and before the new instance write. Reconciliation
must observe that durable completion. In the atomic `Authority` abstraction, it is a completion
before `Crash`. After the new instance write, the old request must refuse, also while the store
reconciles. The companion checks this boundary at its declared and raised finite bounds. It
does not prove storage durability or the complete authority model under a weaker transaction.
The case `Fencing` of the conformance suite checks the instance dependency of a binding.

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
| A crash stops every commit in flight at the model's atomic boundary. The binding drives each journaled commit to a commit or refusal; an uncertain completion or a failed sync counts as a crash | [AUTH Storage Contract and Bindings], "Fencing" (selected on 2026-11-08) | `Authority.Crash` stops each in-flight operation. `Fencing` separately checks the instance dependency that refuses a delayed old request after the new instance write; a completion before that write belongs before the abstract crash |
| The journal is in its own failure domain, outside the domain of the snapshots that it protects. The loss of its newest entries is outside its declared domain | [AUTH Storage Contract and Bindings], "Restore journal" and "Refusal" | `Crash` and `Restore` change no journal variable. The loss of newest entries is not modeled: a limit |
| The conditional commit is atomic over its complete dependency set: serializable isolation, or an equivalent atomic conditional commit. Snapshot isolation is not enough: it permits write skew on absence | [AUTH Storage Contract and Bindings], "Contract"; Berenson et al., [A Critique of ANSI SQL Isolation Levels](https://arxiv.org/abs/cs/0701157) (write skew, A5B) | `Commit` and `Conflict` are one step each, which read every dependency. A weaker isolation would split them; the A011 broken binding "write skew on absence" owns that failure, and this model has no variant for it |
| Each clock reading is within the uncertainty bound U of true time and is not monotonic: a system clock can step and slew | [clock_gettime(2)](https://man7.org/linux/man-pages/man2/clock_gettime.2.html) (`CLOCK_REALTIME` "is affected by discontinuous jumps"); [AUTH HTTP-Signature Replay], "Window" | `Reading(r)` takes any integer within `[now - U, now + U]`, independently for each reading. No variable keeps the last reading |
| Time has no bound between two steps of one process: a verifier can stop between its window check and its insert for any time (scheduling, a stopped virtual machine) | [RFC 9421 section 7.2.2](https://www.rfc-editor.org/rfc/rfc9421.html#section-7.2.2) (a creation time limits validity; it does not prevent repetition) | `Tick` adds any positive amount, at any point. This is the cause of F2: no retention alone covers the time between `Check` and `Insert` |
| A client can lose its state and its response at any point, and can come back later to look up its outcome | [AUTH Authority Transitions] ("A lost response can mean the transition committed"); [draft-ietf-httpapi-idempotency-key-header-08](https://datatracker.ietf.org/doc/draft-ietf-httpapi-idempotency-key-header/) | `Crash` stops each operation at its point; `Resolve` is the later lookup. A client that never looks up stays at its crash point. The client rule (a client stores an anchor's private part before it submits) has no variable: the model has no keys |
| Only the local application owner can issue an owner re-bootstrap, through the host/origin grant that opens local authority | [AUTH Authority Transitions], "Owner re-bootstrap" | The model has no authentication: any operation can issue. That adds behaviors, so it also covers an attacker who holds the owner's grant |
| The attacker holds a one-use value, or raced for it and lost. It acts after a restore as any client can | [NIST SP 800-63B-4](https://pages.nist.gov/800-63-4/sp800-63b.html), sec. 4.2.1.1 (a recovery code is invalidated after use) | `Start` does not tell a user from an attacker: any operation can consume any value that its check accepts. `Turn = "entry"` lets two consumptions of one value race. `OneUse` and `RefusalHolds` are the checks |

**Fairness.** Safety needs no fairness. `RecoverySpec` adds weak fairness only for enabled
local recovery work: `Restart`, `Serve`, reconciliation, and redrive. It gives no fairness to a
client, a crash, a restore request, or an owner re-bootstrap. `Recovers` requires service after
crashes stop. There can be at most one restore after the last crash, because restore enters
reconciliation and needs a down store.

`RecoveryRank` is zero in service. With `n = Cardinality(Ops)` and `w = 2*n + 1`, its value in
reconciliation is `1 + w*Cardinality(pend)` plus the number of missing creations and needed
voids. A redrive removes at least one pending operation and adds at most `2*n` such needs.
Each other recovery step removes a need or enters service. The down-state rank is
`w*(n + 1) + 1`, above every reconciliation rank.

`RecoveryRank` profiles check the strict decrease, and `RecoveryReady` profiles check that the
guards permit work whenever the store does not serve. Together with a complete inductive safety
check, these establish progress under the stated fairness.

`AuthorityRecovery.cfg` also checks the temporal property on a finite behavior slice: one
submitted operation, at most one restore, then recovery and crashes only. It bounds neither
the counter nor the number of crashes, and it removes no recovery step. The disabled-`Serve`
canary still fails under the same fairness, even with no client work. This catches a progress
failure that `NoDoubtServing`, a safety property, cannot detect.

## Bounds, faults, and reductions

- Authority: two accounts (three sign-in slots in `a1` and two in `a2`; `a1p`, `a1q`, `a1r`, and
  `a2p` live at the start), one live recovery-value slot per account, the administrator binding,
  three operation identities, and at most
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
- Fencing: two request identities and one restart; the raised search has three requests and
  two restarts. Request completion has no fairness, because the remote store controls it.
- The reduction to one account (selected on 2026-11-08) and the TLC raise searches were removed on
  2026-11-09: the raised proof covers each bound ([Raise by one](#raise-by-one)).

Each reduction names the failure that it could hide, and a known-bad variant with that failure
still fails under it ([FP Design Models]):

| Reduction | The failure that it could hide | Known-bad variant that still fails |
| --- | --- | --- |
| Operations start in identity order (`Rank`); the identities are interchangeable | A race that needs a later identity to start first | `RefusalNoVoid_bad`, `RaceNoVoid_bad`, and `Unserialized_bad` need two or three concurrent operations |
| Passkeys and provider links share `SignIns`; recovery values have separate `Recoveries` slots | A recovery value that incorrectly counts as a sign-in method | `CountRecovery_bad` removes the only sign-in method while a recovery value remains |
| One counter for every counter | Two counters with one floor | Each counter has its own floor with one rule; `NoFloor_bad` and `FloorAtRelease_bad` fail |
| Session generations and grant revisions as one versioned value, whose entry is the death of the replaced value | A renewal that journals the new value | `NoJournal_bad` fails on any end entry; a renewal that journals the new value is A009's wrong-implementation case |
| The floor write and the commit are one step | A value released before its floor is durable | `FloorAtRelease_bad` fails |
| A lost response leaves the store state, and the client resolves it by lookup (`Resolve`) | A release through the lookup path. The first model had no lookup, and this hid F4 | `FloorAtRelease_bad` fails only through `Resolve` |
| The model keeps every journal entry; retention reaches each retained snapshot's low-water mark | A gap in the journal | `NoJournal_bad` fails; the refusal for a gapped journal is a conformance case |
| One replay signature stands for each identity, and a restart loses every record | Interaction between records, and a kept record | Records of different identities share only the capacity bound (A409); `FloorNoSkew_bad` fails |
| A bootstrap binds the first absent administrator slot | A failure that depends on which slot a bootstrap takes | The slots are interchangeable; `NoAgainAdmin_bad` fails, and `AdminReplaced_reach` reaches a new binding in the second slot |
| At most one owner re-bootstrap in each run | A failure that needs two re-bootstraps | Each re-bootstrap ends the valid value and adds one, so a second one repeats the first one's step; `IssueNoEnd_bad` and `IssueNoJournal_bad` fail with one |

## Properties for the conformance suite (A011)

| Property | Module | Conformance case | Suite case |
| --- | --- | --- | --- |
| `NothingEndedValid` | Authority | Restore with no resurrected revocation, grant revision, or one-use material; no restore makes an ended bootstrap value valid again; restore without its journal (broken binding) | `RestoreJournal`, `StartAfterRestore`, `Rebootstrap` |
| `NoCounterReuse` | Authority | Restore raises each allocation floor above every released value; a restore from a snapshot of an abandoned history releases no counter value twice | `RestoreFloors` |
| `MissingOutcomeUnknown` | Authority | Restore returns unknown for a missing outcome; lost outcome records (broken binding) | `RestoreJournal`, `LostResponse` |
| `NoUncommittedAnchor` | Authority | No anchor from an uncommitted creation | `RestoreAnchors` |
| `AnchorKept` | Authority | Restore keeps each anchor created after the snapshot; a commit that returned its refusal leaves no entry that applies at restore; a lookup after a restore reports the anchor set of the outcome record that it finds | `RestoreAnchors`, `RefusalVoid`, `CrashPoints` |
| `AccountKeepsAnchorP` | Authority | No restore leaves a serving store with an account that has no sign-in method; restore completes an in-doubt recovery once | `RestoreAnchors`, `RestoreCompletions` |
| `AdminKeptP` | Authority | The serving authority has an administrator while the store holds a consumed bootstrap value that no re-bootstrap ended; restore completes an in-doubt bootstrap once | `RestoreCompletions`, `Bootstrap`, `Rebootstrap` |
| `OneBootValid` | Authority | An owner re-bootstrap ends the earlier bootstrap value; at most one bootstrap value is valid | `Bootstrap`, `Rebootstrap` |
| `RefusalHolds` | Authority | A refusal that reached its client never commits later. After a crash between the refusal and its void, the outcome is unknown, and the memory binding injects that crash | `RefusalVoid` |
| `OneUse`, `PendExact` | Authority | Concurrent consumption; at most one commit spends each value in a store's history | `ConcurrentConsumption`, `RestoreCompletions`, `Bootstrap` |
| `NoDoubtServing` | Authority | The store serves only after each in-doubt consumption completes or stays consumed | `RestoreCompletions` |
| `Recovers` | AuthorityRecovery | After crashes stop, weakly fair recovery work returns the store to service | `Restart`, `CrashPoints` |
| `NoStaleCommit` | Fencing | A delayed commit from an earlier instance refuses after the new instance write | `Fencing` |
| `NoDoubleAccept` | Replay | Replay record insert; an insert after `expires` plus the skew refuses; restart and restore floor | `ReplayInsert`: a repetition finds its record, a late insert after expiry refuses, and no insert lands before the floor of a start. `RestoreJournal` checks that a restore sets the replay floor |
| `NoLiveRemoved` | Replay | Incremental expiry | `Expiry` |

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
- **The former proof checks (before the domain correction).** Four changes made those
  checks fit their budget: the starting set gives each function the fixed domain of its variable
  (the earlier generated domains kept the raised step parts in one solver query); a step check
  states `IndInv'` as action invariants, which Apalache checks after the transition only, since
  each state of the starting set is a state of `IndInv`; each step part is one action, and each
  has two profiles, one for the restore parts of `IndInv` and one for the others; and the
  snapshot set of the starting set is one choice, not one transition for each count of
  snapshots. [Inductive proofs](#inductive-proofs) gives the measured effects.
- **The cross-account known-bad variant `ownMark`.** A store that keeps one low-water mark for
  each account, and stamps a snapshot with the mark of one account, misses the in-flight end
  entries of the others. `Authority.OwnMark_bad.cfg` violates `NothingEndedValid` with two
  accounts.

  `AuthorityIndOwnMark.SnapshotOwnMark_bad.apalache` checks the full `Next` and the exact
  snapshot-entry clause `SnapshotEnds` of `EndInv`. It retains every invariant clause and assigns
  the complete documented reachable witness state. The positive proof keeps the full invariant
  starting set. The qualification checks only the fault postcondition. With one account, the
  variant is the design, so the one-account reduction hid this failure.

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
its own property. Each variant reports its required violation at the current files
([Evidence record](#evidence-record)). The Result column keeps the first recorded size: distinct
states and depth at the violation, and the time that the xtask printed. A row marked "Current" ran
at the current files, and a "Pre-slot" row ran before the slot representation. Each other row
is from the 2026-11-10 run at `sha256:89a81c7a…`.

| Profile | Changed rule | Must violate | Origin, bound | Result |
| --- | --- | --- | --- | --- |
| `Authority.AfterCommit_bad.cfg` | Option (c): the consumption entry comes after the commit | `NothingEndedValid` | new, TwoOps | `NothingEndedValid` violated (12), as required, 5,649 (7), 1.55 s |
| `Authority.CreateBeforeCommit_bad.cfg` | A creation entry before its commit | `NoUncommittedAnchor` | new, TwoOps | `NoUncommittedAnchor` violated (12), as required, 1,931 (6), 1.22 s |
| `Authority.FloorAtRelease_bad.cfg` | F4: the floor is durable at the release, not at the commit | `NoCounterReuse` | new, TwoOps | `NoCounterReuse` violated (12), as required, 461,992 (18), 20.27 s |
| `Authority.IgnoreVoids_bad.cfg` | Restore applies voided entries | `AnchorKept` | new, TwoOps | `AnchorKept` violated (12), as required, 17,920 (9), 2.00 s |
| `Authority.IssueNoEnd_bad.cfg` | An owner re-bootstrap that does not end the earlier value (2026-11-08) | `OneBootValid` | new, TwoOps | `OneBootValid` violated (12), as required, 444 (5), 0.71 s |
| `Authority.IssueNoJournal_bad.cfg` | An owner re-bootstrap whose end of the earlier value has no journal entry (2026-11-08) | `NothingEndedValid` | new, TwoOps | `NothingEndedValid` violated (12), as required, 5,783 (8), 1.37 s |
| `Authority.LookupAbsent_bad.cfg` | A missing outcome after restore reads as absent | `MissingOutcomeUnknown` | new, TwoOps | `MissingOutcomeUnknown` violated (12), as required, 5,201 (7), 1.38 s |
| `Authority.NoAgainAccount_bad.cfg` | F1: recovery retires the last displaced sign-in method, and the store serves before its replacement | `AccountKeepsAnchorP` | new, typed recovery only | Pre-slot result: required violation, 2.97 s |
| `Authority.NoAgainRecovery_bad.cfg` | The store serves before an in-doubt recovery completes | `NoDoubtServing` | new, typed recovery without retirement | Pre-slot result: required violation, 2.02 s |
| `Authority.RestoreRetirement_bad.cfg` | Restore omits recovery's displaced sign-in methods | `NothingEndedValid` | new, typed recovery only | Pre-slot result: required violation, 3.15 s |
| `AuthorityCached.CountRecovery_bad.cfg` | A recovery value counts toward the last sign-in method | `AccountKeepsAnchorP` | new, TwoOps | Current: required violation, 4.953 s |
| `AuthorityRecovery.NoServe_bad.cfg` | `Serve` is disabled while enabled recovery work stays weakly fair | `Recovers` | no client work | Pre-slot result: required temporal violation, 2.82 s |
| `Fencing.NoInstance_bad.cfg` | The conditional commit does not read the store instance | `NoStaleCommit` | two requests, one restart | Current: required violation, 1.12 s |
| `Authority.NoAgainAdmin_bad.cfg` | F1: restore leaves an in-doubt bootstrap unresolved (the design before 2026-11-07) | `AdminKeptP` | new, TwoOps | `AdminKeptP` violated (12), as required, 11,112 (9), 1.64 s |
| `Authority.NoFloor_bad.cfg` | Restore does not raise the allocation floor | `NoCounterReuse` | new, TwoOps | `NoCounterReuse` violated (12), as required, 223,428 (14), 7.38 s |
| `Authority.NoJournal_bad.cfg` | Restore without its journal | `NothingEndedValid` | new, TwoOps | `NothingEndedValid` violated (12), as required, 4,338 (7), 1.36 s |
| `Authority.OwnMark_bad.cfg` | `ownMark`: the low-water mark counts the entries of `a1` and the authority only (2026-11-09) | `NothingEndedValid` | new, TwoOps | Current: required violation (12), 1.83 s |
| `Authority.PairApplies_bad.cfg` | Option (a): restore applies the pair and creates the anchor at once | `NoUncommittedAnchor` | new, TwoOps | `NoUncommittedAnchor` violated (12), as required, 3,327 (7), 1.48 s |
| `Authority.RaceNoVoid_bad.cfg` | F3 with `Turn = "entry"` | `RefusalHolds` | new, TwoOps | `RefusalHolds` violated (12), as required, 58,066 (11), 3.72 s |
| `Authority.RefusalNoVoid_bad.cfg` | F3: a refusal writes no void | `AnchorKept` | new, TwoOps | `AnchorKept` violated (12), as required, 29,252 (10), 2.47 s |
| `Authority.SlotsA1AckEarly_bad.cfg` | `ackEarly`: an anchor change is acknowledged before the creation entry of another anchor commit of its owner (the order before 2026-11-08), with the fourth slot of `a1` | `AnchorKept` | new, TwoOps | `AnchorKept` violated (12), as required, 62,357 (10), 4.75 s |
| `Authority.Unserialized_bad.cfg` | Anchor changes of one account take no turn | `AccountKeepsAnchorP` | new, Declared | `AccountKeepsAnchorP` violated (12), as required, 1,663,506 (11), 68.33 s |
| `Authority.VoidOnMissing_bad.cfg` | Reconciliation voids on a missing outcome at a normal start after a restore | `NothingEndedValid` | new, TwoOps | `NothingEndedValid` violated (12), as required, 148,103 (13), 7.31 s |
| `AuthorityIndOwnMark.SnapshotOwnMark_bad.apalache` | `ownMark` under the complete `Next` of the proof | `SnapshotEnds` | declared domains | Current invariant: required violation (12), 29.154 s |
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

The following counterexamples are historical traces from 2026-11-08, before recovery values
had separate slots. Their `recover a2p` step was an abstraction of one-use replacement, not a
typed account recovery. Current checks must produce their required violation independently.

- `Authority.AfterCommit_bad.cfg`: `Start(o1)` bootstrap of value 1 binds adm1, `Snapshot`, `Commit(o1)`, `Crash`, `Restore`. Then a consumption commits with no entry before its commit and crashes before its only entry; the restore from the snapshot before it makes the consumed value valid again.
- `Authority.CreateBeforeCommit_bad.cfg`: `Start(o1)` enroll makes a2q, `JournalEnd(o1)`, `Snapshot`, `Crash`, `Restore`. Then an enrollment writes its creation entry before its commit; a crash before the commit and a restore make the anchor live with no commit.
- `Authority.FloorAtRelease_bad.cfg`: `Start(o1)` enroll makes a2q, `Snapshot`, `Commit(o1)`, `JournalCreate(o1)`, `Snapshot`, `Crash`, `Restore`, `Serve`, `Start(o2)` renew, `JournalEnd(o2)`, `Commit(o2)`, `Ack(o2)`, `Crash`, `Restore`, `Serve`, `Resolve(o1)`. Then a commit after the first snapshot allocates value 2 with no floor write; a restore from the older snapshot lets another operation release value 2; a restore from the newer snapshot brings back the first commit, whose client then receives value 2 by lookup.
- `Authority.IgnoreVoids_bad.cfg`: `Start(o1)` unlink a1q keeps a1p, `JournalEnd(o1)`, `Snapshot`, `Crash`, `Restart`, `ReconcileVoid(o1)`, `Crash`, `Restore`. Then a normal start voids the entry of an unlink that did not commit; a restore applies the voided entry and ends an anchor that the store kept.
- `Authority.IssueNoEnd_bad.cfg`: `Start(o1)` owner re-bootstrap, `Commit(o1)`. Then the re-bootstrap commits while the first value is valid and ends nothing, so two bootstrap values are valid.
- `Authority.IssueNoJournal_bad.cfg`: `Start(o1)` owner re-bootstrap ends value 1, `Snapshot`, `Commit(o1)`, `Crash`, `Restore`. Then the re-bootstrap ends the first value with no journal entry; the restore from the snapshot before it makes the first value valid again.
- `Authority.LookupAbsent_bad.cfg`: `Start(o1)` enroll makes a2q, `Start(o2)` unlink a1r keeps a1p, `Snapshot`, `Commit(o1)`, `Crash`, `Restore`. Then a commit after the snapshot loses its outcome record at the restore, and its lookup reads absent.
- `Authority.NoAgainAccount_bad.cfg`: the old trace consumed the last sign-in method `a2p`.
  That trace is replaced by the typed-recovery canary described above.
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
`Not<Target>` invariant as violated. Each witness reaches its target at the current files
([Evidence record](#evidence-record)). The Result column keeps the size of the 2026-11-10 run at
`sha256:89a81c7a…`, except for `TwoInDoubt_reach`, which ran at the current files. The current
`AccountAfterDoubt_reach` target requires consumption of a recovery value.

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
| `Authority.TwoInDoubt_reach.cfg` | `Turn = "entry"`: two consumptions of one value in doubt at one restore | new, TwoOps | `NotTwoInDoubt` violated with `SameValue(o,q)`, as required. Both pending operations recover `a2c` with `val=0`. Seven transitions, 4.20 s |

## Inductive proofs

`AuthorityInvariant.tla` defines `IndInv`. The thin `AuthorityInd`, `AuthorityIndAnchors`, and
`AuthorityIndProcess` modules set literal Apalache overrides for `Bad`, `Turn`, and `Raise`.
This removes unused fault and domain branches before symbolic construction. `Origin` still
ranges over both values through each constant initializer. The separate `AuthorityIndOwnMark`
wrapper selects that fault.

The two raised modules also expand `Raised(b)` into equalities for their fixed `Raise` value.
Each expansion equals the original predicate for every `b`. This lets native constant evaluation
resolve `BootIds` and `NSnaps` before it constructs integer ranges. The generator and its domains
stay unchanged: base and anchors permit four bootstrap identities, and process permits five.

The proof obligations cover every property of `Safety` with counter values and journal sequences
as unbounded integers, for both origins: `NothingEndedValid`,
`OneBootValid`, `NoCounterReuse`, `MissingOutcomeUnknown`, `NoUncommittedAnchor`,
`RefusalHolds`, `OneUse`, `PendExact`, `NoDoubtServing`, and, since 2026-11-09 (A016),
`AnchorKept`, `AccountKeepsAnchorP`, and `AdminKeptP`. Its scope is exact: an operation identity
starts once and commits through `Commit` once, and a snapshot is never removed, so the proof
covers any number of crashes, restarts, restores, redrives, and reconciliation steps over at
most three operations and two snapshots in a run. The bootstrap identities are exactly
`1..(1 + Cardinality(Ops))`: the initial value and at most one issue commit per operation.
Thus the declared domain has four identities and `AuthorityIndProcess` has five, with four
operations and three snapshots. That is the domain of rule 4 of
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
| `AnchorStateInv` | An anchor that the journal records as made or as ended, or that an operation in flight ends, is never absent. An ended anchor has a committed end or the complete fact of an unvoided crashed end. An operation that stopped at its check wrote no entry, and each entry of an operation in flight comes after each entry of a crashed operation | A restore cannot make a promised anchor absent, and an ended anchor stays ended. The complete end fact prevents reconciliation from voiding its sole justification. The entry order ties each kept anchor to the unlinks that came before it |
| `PromiseInv` | Each promised anchor has a journaled creation. Each live anchor, and each anchor that an outcome record left, has one, or a commit in the record made it and its creation entry is still due; while the store serves, that commit is in flight | With `CreationPending`, an acknowledgement promises only journaled anchors, and a restore applies or keeps each journaled creation |
| `KeptNowInv` | Each account has a live sign-in method, or a pending recovery replaces its displaced methods. The authority has an administrator while it holds a consumed bootstrap value, or a pending bootstrap makes one before service | During reconciliation the replacement can be pending; before service, nothing remains in doubt |
| `RestoreAccountInv`, `RestoreAdminInv` | The same through each retained snapshot and its journal entries, with a pending recovery or bootstrap when needed | A crash can come at any step, and the restore then sets the store |
| `RestoreNowAccountInv`, `RestoreNowAdminInv` | The same for the snapshot that the serving store takes now | The snapshot step keeps the two restore parts |
| `TurnInv` | The owner's turn has one holder between its check and the end of its turn. An unlink keeps an anchor that the journal records as live; that anchor's creation stays journaled, and each end entry of it that counts comes after the unlink's own, while the unlink's end entry counts. A consumption in its turn has no rival commit of its value, and its new anchor has no entry. Each noninitial anchor has a creation entry before any unvoided end entry. With `Turn = "creation"`, two consumptions of one value cannot both have unvoided end entries | An end entry that ends the last anchor of a restore comes with a kept anchor, or with an in-doubt consumption that makes one |
| `ServingInv` | Each snapshot is a copy of a serving store. While the store serves, the end entry of each crashed operation that no void cancels holds in the store | Reconciliation left no stale entry that a later void could turn into a lockout |

`AuthorityInd.Safety.apalache` checks that `IndInv` implies each property of `Safety`, the three anchor
properties included.

The inductive invariant targets `Turn = "creation"`. The entry-release race profile does not establish its current creation-history clauses.
Entry release can permit a recovery commit without its creation entry, followed by a checked unlink of the new anchor.
Earlier arbitrary-start counterexamples guided the invariant's history clauses.
One reachable counterexample exposed the outcome record's anchor-set gap ([Decisions](#decisions)).

The starting set `IndStart` gives each function its fixed domain and each value a free choice.
Every bootstrap-value set is an arbitrary subset of
`BootIds == 1..(1 + Cardinality(Ops))`. The three current sets use direct membership in
`SUBSET BootIds`. Nine independent subset binders supply the three fields of each snapshot.

`TypeInd` requires `bnext = 1 + Cardinality` of the committed issue operations, and
`committed` is a subset of `Ops`. Thus `bnext <= 1 + Cardinality(Ops)`. `TypeInd` and
`SnapTypeOK` restrict every member of these sets to `1..bnext`. Every invariant state therefore
satisfies the subset choices. Conversely, `IndStart` still includes the complete `IndInv`,
so the choices admit no state outside the invariant. Together with the other unchanged
generators and the snapshot representation below, this gives exactly every invariant state.

This replaces arbitrary integer identities that `Gen(Cardinality(BootIds))` produced and the
invariant then restricted. It changes the symbolic representation, not the admissible states.
The domain has four identities in the declared and anchor runs, and five in the process run.
`Init` satisfies the counter equality. Only an issue commit increments both sides, and an
operation commits through `Commit` once.

The issue-only reachability profiles reach all four identities, and all five in the process
raise. They expose the former `Gen(3)`/`Gen(4)` gap. Witnesses alone would not prove domain
coverage. The
[pinned subset selection](https://github.com/apalache-mc/apalache/blob/v0.62.4/tla-bmcmt/src/main/scala/at/forsyte/apalache/tla/bmcmt/rules/support/CherryPick.scala)
uses a membership choice for each possible element without enumerating the powerset.
Plan retirement sets keep their existing subset domain.

Each snapshot slot is an arbitrary record. `snaps` has the fixed domain `1..NSnaps`, and
`nSnaps` ranges from zero through `NSnaps`. The active prefix holds the retained snapshots.
`SnapTypeOK` applies to every slot, including inactive ones. All other snapshot clauses and
restore choices range over the active slot IDs.

Thus the initializer covers every state of
`IndInv`: each slot's fields have independent choices over exactly their type domains, and
`nSnaps` has every allowed value. It does not assume reachable states or distinct slot values.
Duplicate active records are allowed in the proof's starting set, so the proof also covers
these unreachable representations. The process witness requires three distinct active records.

The projection to the former snapshot set is `{snaps[i] : i \in ActiveSnaps}`. Initially the
prefix is empty. `Snapshot` compares the current snapshot, including its low-water mark, with
each active record. A duplicate leaves the slots and count unchanged. A new record goes in the
next slot and increases the count by one. Hence every reachable prefix has distinct records,
and its count equals the cardinality of the projected set.

The original capacity guard and each restore choice are unchanged under this projection. Every
original snapshot set has an enumeration in these slots, and a new capture extends that
enumeration. No history is excluded.

Inactive slots never affect a guard, a restore, or a safety property. Their type conditions
remain true as `bnext` and `jhead` only increase. No recovery action changes the slots or their
count, so recovery enabledness, rank, and fairness are unchanged. Both origins and both grouped
raises use this same representation. This removes nested record-set equality and cardinality
from the invariant. Record equality is needed only for duplicate capture.

The restore predicates use Booleans directly. This is a pointwise rewrite of the same
invariant, including states that are not reachable.

Let `E` mean that a restore ends an anchor and `M` mean that it makes the anchor live. The former
result was `IF E THEN "ended" ELSE IF M THEN "live" ELSE "absent"`. Its equality to `"live"` is
exactly `~E /\ M`. Its inequality to `"ended"` is exactly `~E`. `RestoreLive` and `RestoreEnds`
use those forms.

For bootstrap values,
`v \in (S \cup {f(o) : o \in {q \in Ops : P(q)}})` is exactly
`v \in S \/ \E o \in Ops : P(o) /\ f(o) = v`. `RestoreBootUsed` and
`RestoreBootEnded` apply this identity, including repeated values and empty sets. The old
string and set constructors have no remaining consumers and are removed.

Every shared restore predicate takes one cutoff operator `After(n)`. For a retained
snapshot `s`, the operator is `n > s.lwm`. For the current store, it is `AboveNow(n)`.
For arbitrary integers `n`, `u`, and `v`,
`n > Min(u, v) - 1` is equivalent to `u <= n \/ v <= n`.
`UnreflectedAtMost(o, n)` applies that identity to the two original conditional candidates
of `Unreflected(o)`: each selected entry is compared with `n`, and each fallback `jhead + 1`
becomes `jhead < n`. The `ownMark` ignored-owner branch keeps that same fallback.

`AboveNow` takes the disjunction over all three or four operation identities. It adds
`jhead < n` for the absent fourth identity only in the three-operation domain. The
four-operation domain has no extra sentinel. Thus `AboveNow(n)` is exactly `n > LowWater`
without any journal bound, reachability premise, or assumption about which condition holds.

The former `SnapNow` differed from `Now` only in `lwm`. All reads of that field in these
predicates were entry comparisons, now supplied by `After`. Their other fields and Boolean
structure are unchanged. Substitution of the cutoff equivalence and the identities above
therefore preserves every restore conjunct and each affected reachability predicate.

The argument does not depend on `Origin`, anchor counts, or snapshot counts. `IndStart`,
all type clauses, `Init`, `Next`, `Safety`, and the actual `LowWater` computation are unchanged.
The rewrite removes repeated numeric `Min` expansion from the shared invariant. All profiles
that import the changed invariant need new checker results despite this exact equivalence.

The Step modules use an auxiliary integer, `cutoff`.
Only these modules replace `AboveNow(n)` with `n > cutoff`.
The original invariant, actions, domains, and matrix remain unchanged.
A variable survives operator inlining, so each state uses one cutoff value across its restore predicates.
Groups that read the auxiliary require its exact `LowWater` value.
Groups that cannot read it assign zero and omit the unused `LowWater` constraints.

A group uses the exact cutoff when its actions, assumptions, or targets read `LowWater`, and the
fixed zero otherwise. 23 groups use the exact value, and 44 groups use the fixed helper. A review
of each change to `AuthorityPreservation.tla` checks this selection. The runner does not.

`UnusedCutoffInit(I)` requires `cutoff = 0` and the original initializer `I`.
`UnusedCutoffStep(A)` requires the original action `A` and `cutoff' = 0`.
Every original start and successor of an independent group has exactly one extension, even when a reduced start contains invalid journal references.
Erasing the auxiliary recovers the original query because none of its inputs reads the auxiliary.

`LiftInit(I)` first assigns an arbitrary integer to `cutoff`, then requires `I` and `cutoff = LowWater`.
The first assignment lets the checker evaluate invariant assumptions that read the auxiliary.
Each dependent group passes its original `IndStartWith(assumptions)` to this helper.
`LiftStep(A)` requires the original action and `cutoff' = LowWater'`.
Each dependent group uses that equation, except for the exact `StepSnapshotOther` frame described below.

For a full-`IndInv` state, `TypeInd` and `JournalInv` make every relevant cutoff lookup valid.
A positive creation entry names a nonempty creation target, which `PlanOK` places in `Anchors`.
A positive end entry names a nonempty target.
`EndHoldsIn` handles scalar targets by kind and uses the anchor map only for anchor targets and retirement sets.
The original `AboveNow`/`LowWater` equivalence therefore gives each original invariant state exactly one auxiliary extension.

The same argument covers each original successor without assuming that preservation has passed.
`Propose` changes only an idle plan, whose journal entries are zero.
`JournalEnd`, `JournalCreate`, and `ReconcileCreate` require their relevant nonempty targets before writing positive entries.
Other actions keep the plans and entry references unchanged.
`Commit`, `Redrive`, and `Restore` keep the anchor map's domain equal to `Anchors`.
Thus every original successor has exactly one extension through its computed cutoff.

For the exact helper, projection removes only `cutoff` and recovers the original states, actions, and checked postconditions.
The auxiliary belongs only to the one-step proof, not the original behavior or its temporal specification.
Some reduced starts omit `JournalInv` and admit extra states with invalid references.
`TypeInd` alone does not establish their lookup validity, and this projection argument makes no such claim.
Required coverage remains every full-`IndInv` state and every original successor.

The Step modules also add `heldEnds`, a set of operation identities.
It caches `EndHoldsIn(o, Now)` only when `jEnd[o] > 0` and `plan[o].kill /= ""`.
Other operations remain outside the set. The guard avoids invalid anchor lookups for idle, enrollment, and issue-without-end plans.

Two Step-only copies replace one guarded `EndHolds(o)` call each: `Unreflected(o)` and `AnchorStateInv`.
The runner reverses only that substitution and requires exact equality with each original body.
The original operators and all their other consumers remain unchanged.

`HeldInit(I)` chooses a subset of `Ops`, requires `I`, then fixes the set to `ExactHeldEnds`.
`HeldStep(A)` chooses the successor set before `A`, then requires `heldEnds' = ExactHeldEnds'`.
The early primed assignment lets the successor cutoff calculation read the cache.

One dependency walker selects both auxiliary modes, including each selected cutoff helper's complete dependencies.
Forty groups require the exact cache. The other 27 groups assign an empty set before and after their action.
Unused groups add no end-fact constraint.

Every full-`IndInv` start has the required extension. `JournalInv` gives each positive end entry a nonempty kill target.
The unchanged generator types, `TypeInd`, and `PlanOK` give the cache operands their original types and anchor domains.
Both substituted occurrences already require a positive end entry, so their cached values equal their original calls.
Reduced starts can admit positive entries with empty kills when they omit `JournalInv`.
The cache remains defined there, but this equivalence argument covers the required full-invariant starts and transitions.

The successor argument does not assume a post-state invariant.
The eight `Start` actions call `Propose`, which changes only an idle operation with zero journal entries.
`JournalEnd` writes a positive end only for a nonempty kill.
`JournalCreate` can write an end only in the disabled `afterCommit` fault mode.
The other thirteen actions retain the plan and end entries.
Store writers retain the full anchor domain and the scalar operand types.

Thus every original successor has a defined, exact cache extension.
Only `Snapshot` reads the substituted `Unreflected` in an original action, and its pre-state cache is exact.
The original `JournalInv` target remains independent of both substituted operators.
Its preservation obligation remains unchanged and does not assume the cached post-state `AnchorStateInv` result.
Removing both auxiliaries recovers every required original transition and checked property.

A change to these writers, frame aliases, types, constant modes, or initializers needs a new
review of this argument before the next run.

`StepSnapshotOther` retains its exact initializer and full `IndInv` assumptions, then frames both auxiliaries across its original snapshot action.
`Snapshot` leaves the store, plan, and journal unchanged. Thus `ExactHeldEnds` and `LowWater` retain their values.
From each exact start, the frame satisfies the former successor equations, and those equations force the same frame.

This equivalence assumes no successor invariant. All eleven original targets remain unchanged.
A review of each change to `StepSnapshotOther` checks that its frame keeps this action, these assumptions and components, and this initializer.

The cached `AnchorStateInv` names its nine original conjuncts. Their conjunction remains the complete original predicate after the reviewed cache substitution.
Only `StepCommitRecords` and `StepRestoreAnchors` check those nine conjuncts as separate exact primed targets.
`JournalInvPost` and `PromiseInvPost` remain in their respective groups. Every other group keeps its original component targets.

Priming distributes over conjunction, so all nine checks are equivalent to the former single component check.
No start, action, or assumption changes. The pinned checker can filter each unchanged conjunct separately.

The runner takes the nine targets from the conjunction in `OVERRIDE_AnchorStateInv`, and it
requires each `<clause>Post` to be exactly its clause, primed. A review checks that each clause
keeps its original body and indentation. The native arguments use the same complete target list.
The 447 clause-level pairs represent all 391 logical action/component pairs.

Let `A_i` be an action of `Next`, `C_j` an invariant component, and `G_k` a group's assumptions.
Each group's generator admits every `IndInv` state because `IndInv => G_k` and the generator domains are unchanged.
Its native checks use the selected auxiliary extension of `G_k /\ A_i => C_j'` for each pair.
Thus each checked pair implies `IndInv /\ A_i => C_j'`.
Together, all 391 pairs imply `IndInv /\ Next => IndInv'`.

They keep all 17 components, including the type predicate, and all 23 actions. `CInit`,
`CInitAnchors`, and `CInitProcess` each retain both origins. The separate `Init => IndInv` and
`IndInv => Safety` profiles complete the three obligations of each proof.

`AuthorityPreservation.tla` covers the complete action/component product in 67 groups.
Each pair occurs exactly once. The nineteen Prepare groups and six selected Restore/Snapshot groups use these assumptions:

| Group | Actions | Postconditions | Starting assumptions |
| --- | --- | --- | --- |
| `StepPrepareRestoreAdmin` | All eight `Start` actions | `RestoreAdminInv` | `TypeInd`, `JournalInv`, `OutcomeInv`, `RestoreAdminInv` |
| `StepPrepareRestoreNowAdminEnroll` | `NextEnroll` | `RestoreNowAdminInv` | `TypeInd`, `JournalInv`, `AnchorStateInv`, `RestoreNowAdminInv` |
| `StepPrepareRestoreNowAdminUnlink` | `NextUnlink` | `RestoreNowAdminInv` | `TypeInd`, `JournalInv`, `AnchorStateInv`, `RestoreNowAdminInv` |
| `StepPrepareRestoreNowAdminRecover` | `NextRecover` | `RestoreNowAdminInv` | `TypeInd`, `JournalInv`, `AnchorStateInv`, `RestoreNowAdminInv` |
| `StepPrepareRestoreNowAdminBoot` | `NextBoot` | `RestoreNowAdminInv` | `TypeInd`, `JournalInv`, `AnchorStateInv`, `RestoreNowAdminInv` |
| `StepPrepareRestoreNowAdminRenew` | `NextRenew` | `RestoreNowAdminInv` | `TypeInd`, `JournalInv`, `AnchorStateInv`, `RestoreNowAdminInv` |
| `StepPrepareRestoreNowAdminRevoke` | `NextRevoke` | `RestoreNowAdminInv` | `TypeInd`, `JournalInv`, `AnchorStateInv`, `RestoreNowAdminInv` |
| `StepPrepareRestoreNowAdminIssueEnd` | `NextIssueEnd` | `RestoreNowAdminInv` | `TypeInd`, `JournalInv`, `AnchorStateInv`, `RestoreNowAdminInv` |
| `StepPrepareRestoreNowAdminIssueNone` | `NextIssueNone` | `RestoreNowAdminInv` | `TypeInd`, `JournalInv`, `AnchorStateInv`, `RestoreNowAdminInv` |
| `StepPrepareRestoreAccount` | All eight `Start` actions | `RestoreAccountInv` | `TypeInd`, `JournalInv`, `OutcomeInv`, `RestoreAccountInv` |
| `StepPrepareRestoreNowAccountOwner` | `NextEnroll`, `NextUnlink`, `NextRecover`, `NextBoot` | `RestoreNowAccountInv` | `TypeInd`, `JournalInv`, `RestoreNowAccountInv` |
| `StepPrepareRestoreNowAccountOwnerless` | `NextRenew`, `NextRevoke`, `NextIssueEnd`, `NextIssueNone` | `RestoreNowAccountInv` | `TypeInd`, `JournalInv`, `RestoreNowAccountInv` |
| `StepPrepareRecords` | All eight `Start` actions | `JournalInv`, `AnchorStateInv` | `TypeInd`, `JournalInv`, `AnchorStateInv` |
| `StepPrepareEnd` | All eight `Start` actions | `EndInv` | `TypeInd`, `JournalInv`, `OutcomeInv`, `EndInv` |
| `StepPreparePromise` | All eight `Start` actions | `PromiseInv` | `TypeInd`, `JournalInv`, `OutcomeInv`, `PromiseInv` |
| `StepPrepareKept` | All eight `Start` actions | `KeptNowInv` | `TypeInd`, `DoubtInv`, `KeptNowInv` |
| `StepPrepareTurnAnchors` | `NextUnlink`, `NextRecover`, `NextBoot` | `TurnInv` | `TypeInd`, `JournalInv`, `EndInv`, `AnchorStateInv`, `PromiseInv`, `TurnInv`, `ServingInv` |
| `StepPrepareTurnPassive` | `NextEnroll`, `NextRenew`, `NextRevoke`, `NextIssueEnd`, `NextIssueNone` | `TurnInv` | `TypeInd`, `JournalInv`, `TurnInv` |
| `StepPrepareOther` | All eight `Start` actions | `TypeInd`, `OutcomeInv`, `DoubtInv`, `AnchorInv`, `BootInv`, `CounterInv`, `ServingInv` | `TypeInd`, `JournalInv`, `OutcomeInv`, `DoubtInv`, `AnchorInv`, `BootInv`, `CounterInv`, `ServingInv` |
| `StepSnapshotPromise` | `NextSnapshot` | `PromiseInv` | `TypeInd`, `PromiseInv` |
| `StepSnapshotRestorable` | `NextSnapshot` | `RestoreAccountInv`, `RestoreAdminInv` | `TypeInd`, `JournalInv`, `RestoreAccountInv`, `RestoreAdminInv`, `RestoreNowAccountInv`, `RestoreNowAdminInv` |
| `StepSnapshotServing` | `NextSnapshot` | `ServingInv` | `TypeInd`, `JournalInv`, `DoubtInv`, `KeptNowInv`, `ServingInv` |
| `StepRestoreAnchors` | `NextRestore` | `AnchorStateInv`, `PromiseInv` | `TypeInd`, `JournalInv`, `EndInv`, `AnchorInv`, `AnchorStateInv`, `PromiseInv` |
| `StepRestoreKept` | `NextRestore` | `KeptNowInv` | `TypeInd`, `JournalInv`, `RestoreAccountInv`, `RestoreAdminInv` |
| `StepSnapshotAnchors` | `NextSnapshot` | `EndInv`, `AnchorStateInv` | `TypeInd`, `JournalInv`, `EndInv`, `OutcomeInv`, `AnchorStateInv` |

The nineteen Commit groups cover the 102 pairs for their six actions.

| Group | Actions | Postconditions | Starting assumptions |
| --- | --- | --- | --- |
| `StepCommitNowAdminCore` | `NextCommit`, `NextConflict` | `RestoreNowAdminInv` | `TypeInd`, `JournalInv`, `EndInv`, `DoubtInv`, `AnchorInv`, `AnchorStateInv`, `KeptNowInv`, `TurnInv` |
| `StepCommitAdmin` | `NextJournal`, `NextCommit`, `NextConflict`, `NextCreate`, `NextAck`, `NextResolve` | `RestoreAdminInv` | `TypeInd`, `JournalInv`, `EndInv`, `OutcomeInv`, `AnchorInv`, `AnchorStateInv`, `TurnInv`, `ServingInv` |
| `StepCommitNowAccountCore` | `NextCommit`, `NextConflict` | `RestoreNowAccountInv` | `TypeInd`, `JournalInv`, `EndInv`, `DoubtInv`, `AnchorStateInv`, `KeptNowInv`, `TurnInv`, `ServingInv`, `RestoreNowAccountInv` |
| `StepCommitNowAdminJournal` | `NextJournal` | `RestoreNowAdminInv` | `TypeInd`, `JournalInv`, `EndInv`, `OutcomeInv`, `DoubtInv`, `AnchorStateInv`, `KeptNowInv`, `TurnInv`, `ServingInv`, `RestoreNowAdminInv` |
| `StepCommitNowAccountJournal` | `NextJournal` | `RestoreNowAccountInv` | `TypeInd`, `JournalInv`, `EndInv`, `OutcomeInv`, `AnchorStateInv`, `TurnInv`, `RestoreNowAccountInv` |
| `StepCommitNowAdminCreate` | `NextCreate` | `RestoreNowAdminInv` | `TypeInd`, `JournalInv`, `TurnInv`, `RestoreNowAdminInv` |
| `StepCommitNowAccountCreate` | `NextCreate` | `RestoreNowAccountInv` | `TypeInd`, `JournalInv`, `TurnInv`, `RestoreNowAccountInv` |
| `StepCommitNowAdminReply` | `NextAck`, `NextResolve` | `RestoreNowAdminInv` | `TypeInd`, `JournalInv`, `RestoreNowAdminInv` |
| `StepCommitNowAccountReply` | `NextAck`, `NextResolve` | `RestoreNowAccountInv` | `TypeInd`, `JournalInv`, `RestoreNowAccountInv` |
| `StepCommitValues` | `NextJournal`, `NextCommit`, `NextConflict`, `NextCreate`, `NextAck`, `NextResolve` | `TypeInd`, `OutcomeInv`, `BootInv`, `CounterInv` | `TypeInd`, `JournalInv`, `OutcomeInv`, `BootInv`, `CounterInv` |
| `StepCommitRecords` | `NextJournal`, `NextCommit`, `NextConflict`, `NextCreate`, `NextAck`, `NextResolve` | `JournalInv`, `AnchorStateInv` | `TypeInd`, `JournalInv`, `OutcomeInv`, `AnchorInv`, `AnchorStateInv` |
| `StepCommitEnds` | `NextJournal`, `NextCommit`, `NextConflict`, `NextCreate`, `NextAck`, `NextResolve` | `EndInv` | `TypeInd`, `JournalInv`, `EndInv` |
| `StepCommitDoubt` | `NextJournal`, `NextCommit`, `NextConflict`, `NextCreate`, `NextAck`, `NextResolve` | `DoubtInv` | `TypeInd`, `JournalInv`, `EndInv`, `OutcomeInv`, `DoubtInv` |
| `StepCommitAnchors` | `NextJournal`, `NextCommit`, `NextConflict`, `NextCreate`, `NextAck`, `NextResolve` | `AnchorInv` | `TypeInd`, `JournalInv`, `AnchorInv` |
| `StepCommitPromises` | `NextJournal`, `NextCommit`, `NextConflict`, `NextCreate`, `NextAck`, `NextResolve` | `PromiseInv` | `TypeInd`, `JournalInv`, `AnchorStateInv`, `PromiseInv` |
| `StepCommitKept` | `NextJournal`, `NextCommit`, `NextConflict`, `NextCreate`, `NextAck`, `NextResolve` | `KeptNowInv` | `TypeInd`, `DoubtInv`, `KeptNowInv` |
| `StepCommitTurn` | `NextJournal`, `NextCommit`, `NextConflict`, `NextCreate`, `NextAck`, `NextResolve` | `TurnInv` | `TypeInd`, `JournalInv`, `TurnInv` |
| `StepCommitServing` | `NextJournal`, `NextCommit`, `NextConflict`, `NextCreate`, `NextAck`, `NextResolve` | `ServingInv` | `TypeInd`, `JournalInv`, `ServingInv` |
| `StepCommitAccount` | `NextJournal`, `NextCommit`, `NextConflict`, `NextCreate`, `NextAck`, `NextResolve` | `RestoreAccountInv` | `TypeInd`, `JournalInv`, `EndInv`, `OutcomeInv`, `AnchorInv`, `AnchorStateInv`, `RestoreAccountInv`, `TurnInv`, `ServingInv` |

The 21 Recovery groups cover its seven actions.

| Group | Actions | Postconditions | Starting assumptions |
| --- | --- | --- | --- |
| `StepRecoveryVoidAnchorState` | `NextRecVoid` | `AnchorStateInv` | `TypeInd`, `JournalInv`, `AnchorStateInv` |
| `StepRecoveryTypes` | `NextRecCreate`, `NextRecVoid`, `NextRedriveFail`, `NextCrash`, `NextRestart`, `NextServe` | `TypeInd` | `TypeInd` |
| `StepRecoveryOutcomes` | `NextRecCreate`, `NextRecVoid`, `NextRedrive`, `NextRedriveFail`, `NextCrash`, `NextRestart`, `NextServe` | `OutcomeInv`, `DoubtInv`, `BootInv`, `ServingInv` | `TypeInd`, `JournalInv`, `OutcomeInv`, `DoubtInv`, `BootInv`, `ServingInv` |
| `StepRecoveryTurn` | `NextRecCreate`, `NextRecVoid`, `NextRedrive`, `NextRedriveFail`, `NextCrash`, `NextRestart`, `NextServe` | `TurnInv` | `TypeInd`, `TurnInv` |
| `StepRecoveryStableAnchors` | `NextRecCreate`, `NextRecVoid`, `NextRedriveFail`, `NextCrash`, `NextRestart`, `NextServe` | `AnchorInv`, `CounterInv`, `PromiseInv` | `TypeInd`, `JournalInv`, `AnchorInv`, `CounterInv`, `PromiseInv` |
| `StepRecoveryStableEnds` | `NextRecCreate`, `NextRedriveFail`, `NextCrash`, `NextRestart`, `NextServe` | `EndInv` | `TypeInd`, `JournalInv`, `EndInv` |
| `StepRecoveryStableJournal` | `NextRedriveFail`, `NextCrash`, `NextRestart`, `NextServe` | `JournalInv` | `TypeInd`, `JournalInv` |
| `StepRecoveryStableKept` | `NextRecCreate`, `NextRecVoid`, `NextCrash`, `NextRestart`, `NextServe` | `KeptNowInv` | `TypeInd`, `KeptNowInv` |
| `StepRecoveryStableAnchorState` | `NextRedriveFail`, `NextCrash`, `NextRestart`, `NextServe` | `AnchorStateInv` | `TypeInd`, `AnchorStateInv` |
| `StepRecoveryStableSnapshots` | `NextRedrive`, `NextRedriveFail`, `NextCrash`, `NextRestart`, `NextServe` | `RestoreAccountInv`, `RestoreAdminInv` | `TypeInd`, `RestoreAccountInv`, `RestoreAdminInv` |
| `StepRecoveryCreateJournal` | `NextRecCreate` | `JournalInv` | `TypeInd`, `JournalInv`, `EndInv`, `OutcomeInv` |
| `StepRecoveryVoidJournal` | `NextRecVoid` | `JournalInv`, `EndInv` | `TypeInd`, `JournalInv`, `EndInv` |
| `StepRecoveryCreateAnchorState` | `NextRecCreate` | `AnchorStateInv` | `TypeInd`, `JournalInv`, `OutcomeInv`, `AnchorInv`, `AnchorStateInv` |
| `StepRecoveryRedriveRecords` | `NextRedrive` | `TypeInd`, `JournalInv`, `EndInv` | `TypeInd`, `JournalInv`, `EndInv`, `DoubtInv`, `AnchorStateInv` |
| `StepRecoveryRedriveAnchors` | `NextRedrive` | `AnchorInv`, `CounterInv`, `AnchorStateInv`, `PromiseInv`, `KeptNowInv` | `TypeInd`, `JournalInv`, `DoubtInv`, `AnchorInv`, `CounterInv`, `AnchorStateInv`, `PromiseInv`, `KeptNowInv` |
| `StepRecoveryFailKept` | `NextRedriveFail` | `KeptNowInv` | `TypeInd`, `DoubtInv`, `KeptNowInv` |
| `StepRecoveryCreateAccount` | `NextRecCreate` | `RestoreAccountInv` | `TypeInd`, `JournalInv`, `EndInv`, `OutcomeInv`, `RestoreAccountInv`, `TurnInv` |
| `StepRecoveryAdminRestorable` | `NextRecCreate`, `NextRecVoid` | `RestoreAdminInv` | `TypeInd`, `JournalInv`, `EndInv`, `OutcomeInv`, `AnchorInv`, `AnchorStateInv`, `TurnInv`, `ServingInv` |
| `StepRecoveryVoidAccount` | `NextRecVoid` | `RestoreAccountInv` | `TypeInd`, `JournalInv`, `EndInv`, `OutcomeInv`, `AnchorInv`, `AnchorStateInv`, `RestoreAccountInv`, `TurnInv`, `ServingInv` |
| `StepRecoveryNotServing` | `NextRecCreate`, `NextRecVoid`, `NextRedrive`, `NextRedriveFail`, `NextCrash`, `NextRestart` | `RestoreNowAccountInv`, `RestoreNowAdminInv` | `TypeInd` |
| `StepRecoveryServeRestorable` | `NextServe` | `RestoreNowAccountInv`, `RestoreNowAdminInv` | `TypeInd`, `JournalInv`, `AnchorStateInv`, `KeptNowInv` |

`StepRestoreOther` checks the other 14 Restore components from the full invariant.
`StepSnapshotOther` checks the other 11 Snapshot components from the full invariant.
The nineteen Prepare groups cover all 17 components for the same eight actions.
Journal and anchor-state targets share identical assumptions. Each restore target has its own sufficient starting set.

The passive Turn group contains enrollment, renewal, revocation, and both issue cases.
Its zero journal entries and nonconsuming plans preserve history. `Propose` establishes each new owner lock.

The Commit and Recovery target lists cover their 102 and 119 pairs, respectively.
Together, the 391 pairs cover all 23 actions and 17 components.
`StepSnapshotRestorable` runs first in the declared and anchor domains, and the Process domain starts its eleven split jobs first.
Every other group retains its source order.

`Propose` changes one idle operation's plan, program counter, and owner lock.
Its journal entries are zero, and no current or snapshot outcome contains it.
These facts preserve the journal, end, promise, and restore clauses selected by the Prepare groups.
The turn clauses use the free owner lock, complete end facts, and the guards of each `Start` action.

The Commit groups separate local record/value facts from retained and current restore predicates.
Committed end facts and dependency guards exclude a second commit of the same consumed value.
Response guards convert each newly promised anchor's pending creation into a journaled creation.
The owner turn prevents another active consumption from changing its new anchor before creation completes.

The current restore groups separate framed replies, fresh journal entries, fresh creations, and commit/conflict effects.
The current administrator core follows the maximal-unlink keeper argument without assuming its target.
Each retained target uses only the existing conjuncts required by its source argument.
The current administrator journal group also assumes `DoubtInv`, `KeptNowInv`, and `ServingInv`.
Each surviving held value has a current administrator or an unreflected journaled bootstrap replacement.
The maximal-unlink keeper argument preserves an administrator through replayed ends.

`StepRecoveryVoidAnchorState` checks the complete-end correction before other preservation work.
A void cannot select the complete fact that justifies an ended anchor.
Creation can remove a hypothetical pending replacement only for that same consumption, because persistent uniqueness excludes rivals.
Its new creation then supplies that same unended replacement.

The administrator argument follows a maximal journaled unlink to its unended keeper.
The account argument follows strictly increasing keeper and creation-before-end entries.
This account argument uses the separate declared domains: base/process have one recovery value per account.
The anchor raise has three operations and two recovery values per account.
The proof claims neither a simultaneous raise nor larger domains. The declared domains remain unchanged.

The pinned `before` mode checks each affected component separately for every prepared action transition.
A group with eight actions can therefore require eight sets of component queries.
A completed set for one transition does not complete that group.

Snapshot keeps existing snapshots and copies the current store into each new snapshot.
Thus the current-store clauses of `PromiseInv` establish its new-snapshot clauses.
The two current-store restore predicates establish the new snapshot's restore predicates through the exact `AboveNow`/`LowWater` equivalence.
Snapshot requires service. `DoubtInv` then makes `pend` empty, and `KeptNowInv` supplies the live anchors required by `ServingCopy`.
`ServingInv` retains the existing snapshot clauses and the unchanged current-store clause.

`IndStartWith(assumptions)` keeps every original assignment and domain of `IndStart`.
`IndStart` calls it with `IndInv`. Each group calls it with a conjunction of existing invariant components.
Every state of `IndInv` satisfies those components, so the selected starts can only add states.
A successful check therefore proves preservation for every original invariant state.

The bootstrap domains still have four identities, or five in the process raise.
The three rows and initializer names of `induction.matrix` stay unchanged.

Before any checker starts, `xtask` reads `preservation.matrix` and the flat named lists of
`Next`, `IndInv`, and each group's `Actions`, `Assumptions`, and `Components`. It requires every
action/component pair exactly once, and `TypeInd` in each assumption list. Each assumption and each
component is an existing invariant conjunct, or `IndInv` as a whole. Each group initializer starts
from `IndStartWith(<group>Assumptions)`. Each post alias is exactly its component or clause,
primed, such as `TypeIndPost == TypeInd'`.

No module can override a group, its lists, its initializer, a post alias, `IndStartWith`, or
`PreservationNext`. Each domain wrapper extends only its original proof module and the shared
module. The runner checks only these general rules. The reviews above own the auxiliary helpers and
the frame. SANY still parses each module.

The runner generates native profile files inside the aggregate Step evidence directory.
`preservation.matrix` names each split and the start order. Base and anchors run each of their 67
groups as one native job. Process uses 75 jobs for the same 67 logical groups, 391 logical pairs,
and 447 clause pairs.

`StepSnapshotRestorable` separates its Account and Admin targets. `StepRestoreOther` separates End, Anchor, and its twelve remaining targets.
Each target job retains the complete original action relation, initializer, and auxiliary equations.

`StepCommitTurn` separates its six actions in their original order. Each generated alias is the
group's relation with `StepCommitTurnActions` replaced by one action, so it keeps
`UnusedHeldStep(UnusedCutoffStep(action))` and the original group initializer. Distribution over
the action disjunction preserves every original transition. The runner rejects a split that omits or
repeats a pair, or that changes a start or a relation.

`preservation.matrix` is a separate file so that the closures of the retained results stay byte for
byte the same: every profile closure contains `induction.matrix`. At the next full run of this model,
`preservation.matrix` joins `induction.matrix`.

No independently selectable job profiles enter the model directory.
`run.txt` retains logical coverage and actual targets. Each `job` row binds its name, group, actions, targets, initializer, next operator, module, and constant initializer.
The record also retains job results, input closures, and cumulative elapsed time.

All native jobs must complete within 3600 seconds to pass one domain's logical Step.
Earlier or partial results cannot form a later pass. The three Steps require 209 native jobs under three aggregate budgets.

Keep every model input frozen during a check. The final full-input digest guard also rejects changes outside that profile's source closure.
Use a separate validation checkout at the reviewed commit when correction work continues.

Run a complete Step with the model command:

```sh
cargo xtask model authority-restore/AuthorityInd.Step.apalache
cargo xtask model authority-restore/AuthorityIndAnchors.Step.apalache
cargo xtask model authority-restore/AuthorityIndProcess.Step.apalache
```

On Linux, a Step runs one native job for each core that has 6 GiB of available memory. Another host
runs one job at a time. The 6 GiB reservation is an admission estimate, not a hard limit. A native
failure stops dispatch and kills the remaining jobs.

The groups of a domain's `first` row in `preservation.matrix` start first, in their listed order,
and every other group keeps its source order. Base and anchors start `StepSnapshotRestorable`
first. Process starts its two SnapshotRestorable jobs, six CommitTurn jobs, and three RestoreOther
jobs first. This fixed order removes observed dispatch delays, but it gives no completion guarantee.

All jobs of a Step share one 3,600-second cap. At the cap, the command kills each running checker,
waits for it, and fails the Step. Each checker is a direct child of the command: TLC runs as java,
and `apalache-mc` replaces itself with java through `exec`. The one known remainder is the short
`java -version` probe that `apalache-mc` runs before its `exec`. A kill in that moment leaves the
probe, which ends by itself.

The first 600 seconds are a sizing point of this same run, not a separate run. Stop if the
measured progress cannot support completion in the remaining budget.

All native preservation batches use the paired options `--discard-disabled=false` and
`--no-deadlock=true`. These omit separate enabledness and deadlock queries. They do not remove
preservation queries. A batch can be disabled in some invariant states. The whole `Next` is
enabled in every `TypeInd` state: `Restart` when down, otherwise `Crash`. Recovery readiness,
rank, temporal properties, and the required witnesses remain separate obligations.

The generated batches use `--smtprof` to retain counts of SMT cells, constants, and expressions
by source location. Native logs retain query timing and indices. Intermediate JSON output is
disabled: its serialization exhausted the Java heap before the first qualification could
check a property. A native query index alone does not identify a source action or component. See the pinned
[profiling guide](https://github.com/apalache-mc/apalache/blob/v0.62.4/docs/src/apalache/profiling.md).

The separate `ownMark` qualification checks full `Next` and `SnapshotEnds`. Only its
initializer is concrete: state 3 of retained TLC run `1794443451669468844-20487`, after
`StartUnlink(o1)` and `JournalEnd(o1)`. All 27 variables, including inactive snapshot slots,
are assigned their trace values, and `IndInv` is conjoined. The state has origin `new`, no
retained snapshot, `o1` journaled to unlink live `a2c` while keeping `a2p`, `jEnd[o1] = 1`,
`jhead = 1`, no void, and the other operations idle.

The faulty snapshot ignores that unreflected end entry from the other account. A required
`SnapshotEnds` violation qualifies the named fault from a reachable precursor. It proves no
universal preservation claim.
The positive batches retain every invariant state. Run the qualification once:

```sh
cargo xtask model authority-restore/AuthorityIndOwnMark.SnapshotOwnMark_bad.apalache
```

Each `_reach` witness shows that `IndInit` contains a state that a step must cover; each new part
has at least one:

| Witness | The starting set contains |
| --- | --- |
| `DoubtSnapshot_reach` | A snapshot from which a restore puts a consumption in doubt |
| `Pending_reach` | An in-doubt consumption that a redrive can commit |
| `TwoReleased_reach` | Two released artifacts |
| `IssueReady_reach` | An owner re-bootstrap that can commit and end the valid value |
| `EndedValueSnapshot_reach` | A snapshot whose valid bootstrap value a later re-bootstrap entry ends at a restore |
| `MadePromise_reach` | A promised noninitial anchor with an unvoided journaled end and a checked end (`PromiseInv`, `TurnInv`) |
| `CreationDue_reach` | An outcome record that left an anchor whose creation entry is still due (`PromiseInv`) |
| `DoubtKeeps_reach` | A snapshot whose restore retires an account's last displaced sign-in method, so its pending recovery must create the replacement |
| `DoubtAdmin_reach` | An authority that a restore keeps only through an in-doubt bootstrap (`RestoreAdminInv`) |
| `UncertainEnded_reach` | An ended anchor that only an in-doubt end entry accounts for (`AnchorStateInv`) |
| `PendKeeps_reach` | During reconciliation, an account that needs its pending recovery to replace its last displaced sign-in method |
| `DoubtKeepsNow_reach` | A serving store whose current snapshot would need a pending recovery to replace its last displaced sign-in method |
| `TurnHeld_reach` | A consumption that committed and still holds its owner's turn (`TurnInv`) |
| `CrashedHolds_reach` | A serving store with a crashed operation that did not commit and whose end entry holds (`ServingInv`) |
| `AccountsUsed_reach` | The third account's second anchor and the extra slots of `a1` and `a2` live together |
| `AdminUsed_reach` | The third administrator live |
| `RecoverySlotsUsed_reach` | The second recovery slot of each original account live |
| `ProcessUsed_reach` | Three snapshots, the fourth operation, and all five bootstrap values |

`Replay.tla` proves `Safety` of the replay window for every non-negative `Skew`, `U`, and `MaxWin`
and every integer time. `Replay.Init.apalache` checks `Init => IndInv`, `Replay.Step.apalache`
checks `IndInv /\ Next => IndInv'`, and `Replay.Safety.apalache` checks `IndInv => Safety`.
`Replay.AcceptedGone_reach.apalache` shows that `IndInv` contains an acceptance whose record
expired while a verifier holds a check.

## Raise by one

Rule 4 of [FP Design Models]: a bound whose sufficiency the model argues but does not prove gets
one complete check with that bound raised by one before the evidence is final. Since 2026-11-09,
`IndInv` implies every authority property, so the two raised proofs are that check for each
domain bound (selected on 2026-11-10). A raised element starts inert, except the first anchor of
a third account, which is live as `a2p` is.

| Bound | Declared | Raised | Check |
| --- | --- | --- | --- |
| Accounts | 2 | 3 (`a3p` live, `a3q` absent) | `AuthorityIndAnchors` |
| Anchor slots of `a1` | 3 | 4 (`a1s` absent) | `AuthorityIndAnchors` |
| Anchor slots of `a2` | 2 | 3 (`a2r` absent) | `AuthorityIndAnchors` |
| Recovery-value slots of each original account | 1 | 2 (`a1d` and `a2d` absent) | `AuthorityIndAnchors` |
| Administrator slots | 2 | 3 (`adm3`) | `AuthorityIndAnchors` |
| Operations | 3 | 4 (`o4` idle) | `AuthorityIndProcess` |
| Snapshots | 2 | 3 | `AuthorityIndProcess` |
| Bootstrap-value identities | 4 (initial value plus three issue commits) | 5 (initial value plus four issue commits) | `AuthorityIndProcess` |
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

TLC keeps its declared bounds. `AuthorityCached.cfg` and `AuthorityCached.Bootstrapped.cfg` search the
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

117 of the 118 profiles have accepted evidence for the current files. The step of the process
raise is incomplete ([Limits](#limits)).
For this directory, the model command prints
`sha256:09a2c67063ca3fc271aa597bca45a166633ffd2c31647552c9f7e61afee6d04d (134 files)`.

Each result checks the closure of its profile: the profile file, its module and each module that
the module extends, and `induction.matrix`. A Step aggregate also reads `preservation.matrix`.
The results ran at earlier digests of this directory, the last at
`sha256:97f96687c6eb…` (133 files, before `preservation.matrix`). The closure of each profile is
byte-identical to the current files. Reviews of each retained source copy on 2026-11-16 and of each
regenerated Step job on 2026-11-17 confirm this.

So each result applies to the current files under the budget rule of [FP Design Models] (selected on
2026-11-17). A change of a model's files needs a run of each profile whose checked files changed.
A retained closure proves that a profile's files did not change.

- Checkers: temurin-jre 21.0.13+9 (Linux aarch64, and macOS aarch64 for the local profiles),
  tla2tools 1.8.0+d8fb231de4e4 (TLC2 Version 2026.11.06.222357, rev d8fb231), and apalache 0.62.4.
  Each run record names the SHA-256 of each checker tree and of the runner.
- Command: `python3 xtask/model-run.py authority-restore/<profile>`, the supervisor of that time,
  under a cap of 3600 seconds, or 600 seconds for six known-bad Apalache variants. The Step profiles
  ran 16 jobs at a time. The current `cargo xtask model` replaces that supervisor. On 2026-11-17, it
  generated each native job file, job row, and child closure of the three Steps byte for byte as
  those runs used them. Each other profile closure is also unchanged.
- Retention: each result has a native archive and an independent lead review in the retained A016
  evidence. Its `profile-inventory.json` names the archive and the review of each profile.

| Profiles | Count | Host | Result |
| --- | --- | --- | --- |
| `Authority.*.cfg`, `AuthorityRecovery.cfg`, `AuthorityRecovery.NoServe_bad.cfg`, `AuthorityCached.CountRecovery_bad.cfg` | 41 | Apple M1 Pro, macOS aarch64 | Each known-bad variant reports a violation of its one property, each witness reaches its target, and each other search completes with an empty queue |
| `AuthorityCached.cfg`, `AuthorityCached.Bootstrapped.cfg` | 2 | EC2 c8g.4xlarge (16 vCPUs, 32 GiB) | Complete searches with empty queues: 199,512,487 distinct states in 2162.140 seconds, and 61,475,683 in 611.016 seconds |
| `Init`, `Safety`, `RecoveryRank`, and `RecoveryReady` of `AuthorityInd`, `AuthorityIndAnchors`, and `AuthorityIndProcess` | 12 | EC2 Graviton, Linux aarch64 | `NoError` |
| The 46 `_reach` witnesses of the three proof modules, and `AuthorityIndOwnMark.SnapshotOwnMark_bad.apalache` | 47 | EC2 Graviton, Linux aarch64 | Each witness reaches its target, and `ownMark` violates `SnapshotEnds` |
| `AuthorityIndAnchors.Step.apalache` | 1 | EC2 r8g.4xlarge (16 vCPUs, 128 GiB) | All 67 jobs report `NoError` for 391 action/component pairs and 447 clause pairs, in 2813.315 seconds |
| `AuthorityInd.Step.apalache` | 1 | EC2 r8g.4xlarge | All 67 jobs report `NoError` for 391 action/component pairs and 447 clause pairs, in 648.837 seconds |
| `AuthorityIndProcess.Step.apalache` | 1 | EC2 r8g.4xlarge | Incomplete at the 3600-second cap, so not a pass: 74 of 75 jobs report `NoError`, and `StepSnapshotRestorableAdmin` had no answer after 58.8 minutes |
| `Fencing*.cfg` and `Replay*.apalache` | 13 | A000 evidence of 2026-11-12, Linux aarch64 | The required verdict of each profile |

The tables of [Known-bad variants](#known-bad-variants) and [Reachability](#reachability) keep the
first recorded size of each search. They show its scale, not the current result.

### Earlier records

Each record below is superseded. Its archives and reviews stay in the retained evidence of the
task, and the task entries give each run.

- 2026-11-15, `sha256:a1240ae5…`: the guarded end-fact cache. The anchor raise completed 64 of 67
  groups before its cap. The clause targets and the snapshot frame replaced it.
- 2026-11-15, `sha256:f9331be8…`: the selective low-water cutoff. The anchor raise completed 62 of
  67 groups before its cap. The end-fact cache replaced it.
- 2026-11-14, `sha256:8e5917bb…`: the anchor symmetry of the full TLC searches. Both searches and
  the base Step completed, and the anchor raise completed 53 of 67 groups. The selective cutoff in
  `AuthorityPreservation.tla` reopened the three Step profiles. The TLC results still apply.
- 2026-11-13 to 2026-11-14, fourteen digests from `sha256:2313ab40…` to `sha256:809d52ae…`: the
  invariant corrections and the preservation partitions. Arbitrary-start counterexamples made
  `AnchorStateInv`, `TurnInv`, and `RestoreAccountInv` stronger. No Step profile completed. The
  other results whose closures did not change still apply.
- 2026-11-10, round 6, `sha256:89a81c7a…` (378 files): every `AuthorityInd` profile passed, and the
  raised profiles ran in part. The corrected recovery and bootstrap domains replaced the model.
- 2026-11-10, round 5, `sha256:0dba3f3d…` (267 files): every `AuthorityInd` profile passed. The
  raise of every domain at once found two missing clauses and did not fit the budget.
- 2026-11-09, the A000 digest `sha256:5549a6d4…` (111 files): every profile passed except
  `Authority.RaiseOpsOne.cfg` and the seventeen raised step parts.
- 2026-11-08 and earlier, `904164456e72…`, `1023dd21…`, `0b6c17bd…`, and `7b5cf1bc…`: the rules as
  they were then.

## Limits

- The process raise (operations 3 to 4, snapshots 2 to 3, bootstrap identities 4 to 5) has one
  clause pair with no result. From `CInitProcess`, the pair "`NextSnapshot` preserves
  `RestoreAdminInvPost`" has no result. Its job, `StepSnapshotRestorableAdmin`, ran z3 for 58.8
  minutes with no answer, and the 3600-second cap stopped it. The other 446 of 447 clause pairs
  (390 of 391 logical pairs) hold at the raised domains.

  The same pair holds at the declared domains (`AuthorityInd.Step.apalache`) and in the anchor
  raise. No checker found a violation in any profile. The run is `20261117T025323Z-50576`, and its
  archive `AuthorityIndProcess.Step.apalache-1.native.tar.gz` has the SHA-256
  `2dc7e8fe6be39cea98a7e248a3752640ea6b4dcbc17fe7a4dd32819ef67e857c`. This is a named limit (user
  decision of 2026-11-17).
- The proof obligations cover the domains of rule 4 ([Inductive proofs](#inductive-proofs)): any number of
  crashes, restarts, restores, and reconciliation steps, over at most three operations and two
  snapshots in a run (four and three raised). The TLC searches cover their bounds.
- The proofs check the design's turn (`Turn = "creation"`). The turn that ends at the first
  journal write (`Turn = "entry"`) has the TLC search `Authority.Race.cfg` at TwoOps and its
  known-bad variant `RaceNoVoid_bad`, and no proof.
- The full TLC searches use the exact constant-set cache and the anchor symmetry of
  `AuthorityCached`. `CountRecovery_bad` and the three-anchor `Unserialized_bad` trace show that
  the symmetry keeps a violation of `AccountKeepsAnchorP` visible.
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
- Recovery progress needs crashes to stop and enabled local recovery work to be weakly fair.
  No liveness claim applies while crashes continue or the store cannot complete durable work.

## Open questions

- None for the design. The question of a new administrator after the bootstrap is consumed is
  answered by the owner re-bootstrap (selected on 2026-11-08).
[AUTH Authority Transitions]: ../../docs/specs/authentication.md#authority-transitions
[AUTH Storage Contract and Bindings]: ../../docs/specs/authentication.md#storage-contract-and-bindings
[AUTH HTTP-Signature Replay]: ../../docs/specs/authentication.md#http-signature-replay
[AUTH Initial Profiles]: ../../docs/specs/authentication.md#initial-human-workload-and-agent-profiles
[AUTH Passkey Profile]: ../../docs/specs/authentication.md#passkey-profile
[FP Design Models]: ../../../rsasync/docs/specs/family-policy.md#design-models
