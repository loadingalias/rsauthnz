# grant-approval: design model of task A400

These models check the authority of agent grants, revocation, and one-use operation approval with
the operation commit. They gate agent revocation and the grant checks (A404–A406), and then
operation approval (A501–A503). They check the design, not the Rust code.

| Module | Concern |
| --- | --- |
| `GrantAccess.tla` | Owner authority, policy changes, agent revocation, grant issuance, change, and revocation, the deadline, and the request check and commit |
| `Approval.tla` | Approval instances, the passkey approval, atomic consumption with the operation commit, cancellation, lost responses and requests, and restore |
| `ApprovalSnapshotNumber.tla` | A known-bad variant of `Approval.tla`: a restore raises the store instance number of its snapshot ([Bounds](#bounds), restores) |

## Promise

- **Access** (`GrantAccess.tla`). An operation commits only while its agent is live, within its
  grant and before the grant deadline, and within the current authority of the human owner under
  the policy version that the grant binds. A concrete failure: an agent revocation lands between
  the request check and the commit, and the operation still commits.
- **Approval** (`Approval.tla`). One human assertion pays for at most one effect: of the exact
  approved request, through the approved instance, under the current grant revision. A lost
  response, a lost request, a retry, or a restore gives no second effect, and a restore leaves no
  old approval pending. A concrete failure: one passkey assertion approves two operations.

## Run it

```sh
cargo xtask model grant-approval/GrantAccess.cfg grant-approval/Approval.cfg   # the declared profiles
cargo xtask model grant-approval                                               # every profile
```

The output and each trace go to `target/model/grant-approval/<file>/`. [Check the design
models](../../docs/content/design-models.md) tells how to install the checkers and what a failure
means.

## Split by concern

Each model treats the other concern as an environment that can do each thing that the other
concern can do. This over-approximation keeps a pass sound: each behavior of the design is a
behavior of the model, and a property of the model holds for the design.

- `GrantAccess.tla` has no approval, no lost request, and no restore. An approval adds a check to
  a commit and so removes commits. A lost request or a restore makes the commit refuse, or it
  ends a request. None of these adds a commit, and each access property is a fact of each commit.
- `Approval.tla` takes the access check as an environment choice. Each approval and each commit
  can pass the check, and the environment can refuse each one (`CancelOp`, `EndInst`). The grant
  revision is an input that can change at each step (`GrantChange`). A submission names an
  approved instance, or no instance when its permission needs no approval. Agent revocation, the
  policy version, and the owner's authority have no variable, because they change only the result
  of the check.
- A property that needs both concerns, "an approval applies only to the current grant", is in
  `Approval.tla`, with the grant revision as its input.

## Properties

| Module | Property | Acceptance item of A400 |
| --- | --- | --- |
| `GrantAccess` | `RevokedNoAccess` | A revoked agent has no access: at each commit, the agent is active |
| `GrantAccess` | `EffectiveAccess` | At each commit, the owner holds the permission now, and the grant binds the current policy version |
| `GrantAccess` | `WithinGrant` | At each commit, the grant is active for the agent and before its deadline, and it names the audience, resource, and action |
| `Approval` | `ApprovalBinding` | Each consumed approval has the assertion of its own instance (identity, nonce, and request), its own request (agent and digest), and the current grant revision |
| `Approval` | `ApprovalOnce` | Consumption and the operation commit together, at most once: one assertion pays for at most one effect |
| `Approval` | `RestoreRejects` | Restore rejects old pending approvals: no instance of an earlier store instance is pending or approved |
| `Approval` | `OutcomeOnce` | A lost response permits an outcome lookup without a second effect: each identity has at most one effect, and an `ok` answer has one |

Each property of an effect reads the history variable `held`. Each commit records there whether
the property held, from the facts of the current state. The commit's own check uses what the
request check read. A known-bad variant changes the check, not the recorded facts. In
`Approval.tla`, `done` (the identities that have an effect) and `paid` (the assertions that paid
for an effect) are the history of `OutcomeOnce` and `ApprovalOnce`. A restore does not change
them.

## Correspondence

| Model action | Design transition ([AUTH Authority Transitions], [AUTH Grants], [AUTH Operation Approval]) | Task |
| --- | --- | --- |
| `GrantAccess!OwnerChange` | A change of the owner's resource authority (an application input) | A405, A406 |
| `GrantAccess!PolicyChange` | A relevant new policy version (an application input) | A405, A406 |
| `GrantAccess!AgentRevoke` | Revocation of an agent | A404 |
| `GrantAccess!GrantIssue`, `GrantChange` | Agent grant issuance or change: a new revision within the owner's current authority, with a finite deadline and the current policy version | A405 |
| `GrantAccess!GrantRevoke` | Revocation of a grant | A405 |
| `GrantAccess!Deadline` | Time passes the grant deadline | A405, A406 |
| `GrantAccess!Submit` | The agent request check, which reads its dependencies | A406 |
| `GrantAccess!Commit` | The operation's transition: the atomic comparison of each dependency that the check read, and the deadline | A406 |
| `Approval!GrantChange` | A human-approved grant change (environment) | A405 |
| `Approval!Request` | The approval request: a pending instance with a fresh nonce | A501 |
| `Approval!Sign` | The human's passkey assertion with user verification over the instance's challenge | A502 |
| `Approval!Approve` | The approval transition: it consumes the pending instance and records the one-use approval under the current revision | A502 |
| `Approval!EndInst` | Cancellation, the short expiry of an instance, or a refused approval | A501, A502 |
| `Approval!Submit` | A submission under a new stable identity, with its approval | A503 |
| `Approval!Commit` | The operation's transition: the identity check and the approval consumption in one commit | A503 |
| `Approval!Retry` | A second submission of the same identity, answered from its outcome record | A503 |
| `Approval!CancelOp` | The agent withdraws a checked operation, or the access check refuses it | A503 |
| `Approval!LoseRequest` | A crash of the store process or a failed connection loses a checked request and its response | A503 |
| `Approval!Restore` | The storage binding: a restore with the restore journal | A007 (model: `authority-restore`) |

## Assumptions

- Cryptographic verification is correct. A challenge is the tuple of the instance identity, the
  nonce, and the request, so two different tuples never collide. A description stands for its
  digest. An assertion verifies only for the challenge that the human signed.
- A nonce is fresh: no two instances in the history get the same nonce. A restore does not undo
  this, because the nonce comes from rscrypto randomness, not from the store.
- An attacker can replay each assertion that the human made.
- The human owner is authenticated with fresh user verification at each grant transition and each
  approval. The models do not model that ceremony.
- The restore journal keeps agent revocations and dead grant revisions, as `authority-restore`
  checks for each ending. Restore ends each pending instance and each unconsumed approval of its
  snapshot ([AUTH Storage Contract and Bindings], restore). After a restore, a missing outcome
  record of an identity from an earlier store instance is unknown, as `authority-restore` checks
  with `MissingOutcomeUnknown`.
- The policy version and the owner's authority are application inputs. A restore of the auth store
  does not change them.

## Bounds

| Module | Constant | Declared | Kind | Evidence |
| --- | --- | --- | --- | --- |
| `GrantAccess` | `Agents` | 2 | Symbols | Raise: `GrantAccess.Agents3.cfg` |
| `GrantAccess` | `Ops` | 2 | Count | Raise: `GrantAccess.Ops3.cfg` |
| `GrantAccess` | `Auds`, `Ress`, `Acts` | 2 each | Symbols | Raises: `GrantAccess.Auds3.cfg`, `GrantAccess.Ress3.cfg`, `GrantAccess.Acts3.cfg` |
| `GrantAccess` | `NPol` | 2 (one relevant change) | Count | Raise: `GrantAccess.Pol3.cfg` |
| `GrantAccess` | `MaxRev` | 2 (issuance and one change) | Count | Raise: `GrantAccess.Rev3.cfg` |
| `GrantAccess` | `MaxPerms` | 1 | Count | Raise: `GrantAccess.Perms2.cfg` |
| `GrantAccess` | `MaxOwn` | 1 | Count | Raise: `GrantAccess.Own2.cfg` |
| `Approval` | `Agents`, `Descs` | 2 each | Symbols | Data independence, below |
| `Approval` | `Insts` | 2 | Symbols | Proved in writing (lead review 2026-11-15): projection, below |
| `Approval` | `Ops` | 2 | Count | Proved in writing (lead review 2026-11-15): projection, below |
| `Approval` | `Nonces` | 4 | Count | Proved: one for each request, below |
| `Approval` | `MaxRev` | 2 (one change) | Count | Data independence, below; raise: `Approval.Rev3.cfg` |
| `Approval` | `MaxRestore` | 1 | Count | Proved in writing (lead review 2026-11-15): restores, below; `ApprovalSnapshotNumber.Restore2_bad` breaks its premise and fails |

`GrantAccess.tla` is small, so each of its bounds gets a raise by one, also the symbol bounds. A
data-independence argument there has a gap: `OwnerChange` removes one pair from a set, and a
renaming that merges two pairs does not keep that step.

**Nonces.** An instance slot is free again only after a restore. So each slot takes at most one
request in each store instance, and a behavior has at most `|Insts| * (MaxRestore + 1)` requests.
That many nonces let each request take a fresh nonce, so the bound blocks no request.

**Data independence of the request symbols (`Approval`).** The model compares an agent or a
description only for equality, as a part of a request or a challenge. No action makes a new
value from them, and each choice ranges over the whole set. Take a behavior that violates a
property at one commit. Its violation is an inequality between at most two requests (the
operation's and the instance's), in its agent or in its description. Rename each value of each
set to `v1` when it is the value of the operation's request, and to `v2` otherwise. Each
equality in a guard stays true. A step whose guard was false and becomes true is a refusal of a
commit, and `CancelOp` makes the same state. A `Sign` whose challenge is already in `signed`
becomes a stutter. So the renamed behavior is a behavior of the two-value model, and it keeps the
violating inequality. Two values for each set are therefore enough.

**Data independence of the grant revision (`Approval`).** A revision is compared only for
equality (`inst.rev = grev`), and each change makes a value that no earlier step had. Rename each
revision to 1 when it is the revision of the violating approval, and to 2 otherwise. A
`GrantChange` from 2 to 2 becomes a stutter, and a refusal that becomes a pass is `CancelOp` as
above. So one change is enough for the declared profile.

**Projection of instances and operations (`Approval`).** A violation involves at most two
instances (the consumed instance and the instance whose assertion it carries) and at most two
operations (two effects of one assertion, or one identity twice). The guard of a step of an
instance or an operation reads no other instance and no other operation, except `Submit`, which
reads only the instance that it names, and `Request`, which needs a nonce outside `used`. Remove
every step of every other instance and operation. A step that is left keeps its guard, and fewer
requests leave more nonces free. So the projection is a behavior of the model with two instances
and two operations, and it keeps the violation.

**Restores (`Approval`).** One restore shows each violation that two restores show, if a store
instance number never repeats. The argument is about the correct model (`Bad = "none"`), and it
uses each read of the number:

- `Commit`, `Retry`, and `RestoreRejects` compare a stored number with the current number `ep`,
  for equality only.
- `Request` and `Submit` write the current number. `LoseRequest`, the lost branch of `Commit`,
  and a `Retry` that checks again keep the stored number.
- `FreeInst`, `IdleOp`, and `Final` write 0 as a placeholder. No comparison reads it: each one
  reads a pending or approved instance, or a checked or lost operation.
- `Restore` counts the restores with `ep < MaxRestore`, and it writes `ep + 1`. So the new number
  differs from each stored number. `TypeOK` checks only the range.

Two facts follow. An operation is submitted once, it keeps the number of its submission, and only
a commit under the current number has an effect. So each effect of an operation is in the store
instance of its submission. A restore ends each pending and approved instance (`Earlier`), and
each request takes a fresh nonce. So each approval is requested, approved, and consumed in one
store instance, and its nonce names its request.

Take a behavior with two restores that violates a property. If the violation comes before the
second restore, the behavior to it has at most one restore. Its at most four requests can take
the four nonces of the declared profile. Otherwise, change the behavior in four steps:

1. Give a new instance identity to each request of an instance that a restore freed. Each
   challenge holds its nonce, so it gets the identity of its request. After the submission, only
   `Commit` reads the instance that an operation names. A restore between the submission and the
   commit makes the commit refuse, whatever the instance holds. So no step relates two requests of
   one instance. Until step 4, the behavior has more instance identities than the declared profile.
2. Remove the first restore. In its place, `EndInst` ends each pending and approved instance. Then
   each requested instance of the first store instance is ended or consumed, and the removed
   restore left it free, ended, or consumed. Step 1 gives it no later request, so no guard or
   property tells these states apart. The second restore can install the same state from each.
   The second restore also removes the outcome records that the first restore removed, which are
   of operations of the first store instance (the first fact).
3. Give the number 0 to the first two store instances, and 1 to the third. Each comparison keeps
   its result, except for an operation of the first store instance between the two restores. Its
   refused commit becomes `CancelOp`. Its retry that answered `unknown` becomes a `Retry` that
   answers `ok` from a record that step 2 keeps, or a `Retry` and a `CancelOp`. No guard or
   property tells `unknown` from `no`. An `ok` keeps `OutcomeOnce`, because each identity with a
   record has an effect.
4. Project the behavior onto the instances and the operations of the violation, as above. A
   restore keeps its choices for these instances and operations. Each instance has one request,
   so two of the four nonces are enough.

The commits do not change, and each reads the same facts, so `held`, `done`, and `paid` do not
change. After the second restore, the instances, the outcome records, and each comparison are as
before. So the result is a behavior of the declared profile, and it violates the same property.
The same steps remove each further restore.

The premise is that a number never repeats, as Decision 3 requires. `ApprovalSnapshotNumber.tla`
breaks it: the store keeps the number in its snapshot, so a restore raises the number of the
snapshot. With two restores, a number repeats, and `ApprovalSnapshotNumber.Restore2_bad` fails
`OutcomeOnce`. With one restore, the same variant passes (`ApprovalSnapshotNumber.cfg`). So no
declared profile can show this defect, and only the premise excludes it.

## Reductions

Each reduction names the failure that it could hide. Each known-bad variant still fails under
every reduction, because each profile uses all of them.

- **Symmetry.** `Symmetry` permutes each set of model values, in every profile. `Init`, `Next`,
  each property, and each witness target treat the members of each set alike: the owner's first
  authority is all of `Ress \X Acts`, each choice ranges over a whole set, and no property or
  target names a model value (`NotRevocationRace` quantifies over all of `Ops`, `NotNarrowGrant`
  compares only `grant`, `auth`, and the views, and `NotApprovedWork` tests `paid = {}`). An
  approval instance has its role (an equal or a different request) in its state, not in its
  identity, and `Init` gives each instance the same state. Symmetry could hide a failure that only
  one named value shows. No such value exists.
- **A refused submission changes no state** (`GrantAccess`). A refusal reads the current state and
  writes nothing. It could hide a failure that follows a refusal. None exists, because a refusal
  leaves nothing that a later step reads.
- **A submission names only an approved instance** (`Approval`). `Approve` writes only its
  instance, and a submission reads no instance. So a submission before an approval has the same
  outcome as the same submission after it. It could hide an operation that names a pending
  instance and commits after the approval. The commit reads the instance at the commit, so that
  behavior is in the search.
- **Freshness flags in place of the values that a check read** (`GrantAccess`). The agent
  lifecycle, the grant (state and revision), the policy version, and the owner's authority each
  change in one direction only. So a value equals the value that a check read exactly when no
  change came between, and the commit compares one flag for each group. It could hide a change
  that returns a value to the value that the check read. No action makes such a change.
- **An agent without the grant is revoked only while no grant exists** (`GrantAccess`). Only
  `GrantIssue` reads the lifecycle of an agent that does not hold the grant: each check needs the
  grant's agent. So such a revocation commutes with each other action, and it can wait until the
  grant state is `none`. It could hide a failure that needs that revocation while a grant exists.
  No property reads it.
- **Request loss for each operation, with no bound** (`Approval`). A crash loses each checked
  request at once. A sequence of `LoseRequest` steps makes the same state, so the model has more
  behaviors than one with a bounded number of crashes.
- **A lost response of a committed operation keeps only the store instance of its identity**
  (`Approval`). In the correct model, a retry of such an identity finds its outcome record, or it
  finds a later store instance and answers `unknown`. It never reads the request again.
  `NoIdentity_bad` and `Separate_bad` keep the request and the instance, because their retry or
  their late consumption reads them.
- **Restore chooses an earlier state of each part on its own** (`Approval`). The model keeps no
  snapshot. A restore installs, for each instance, its free state, an earlier pending or approved
  state (which restore ends), or its consumed or ended state, and a subset of the outcome
  records. Each real snapshot gives one such choice, so the model has every behavior of a real
  restore, and more. It could show a failure that no real snapshot gives. Each such trace would be
  read against the design before any change.
- **The history keeps no commit order.** `held`, `done`, and `paid` keep what the properties
  read, and no property reads the order of the effects. No variable can leave the state through a
  `VIEW`, because a property or an action reads each history variable (`signed` by `Approve`,
  `used` by `Request`). It could hide a second effect of one identity or one assertion.
  `held.outcome` and `held.once` record each such effect at its commit.

- **The approval-required mark is a check of one step** (`GrantAccess`, `Approval`). No module
  has the mark. Four facts of the design and the guards reduce the rule "a commit of a marked
  permission names an approval" to the request check:
  1. The design puts the marks in the grant ([AUTH Grants]: "A grant binds ... optional
     approval-required marks on permissions"). A grant changes only through a new human-approved
     transition, which ends the revision that it replaces (decision 4). So a change of a mark
     advances the grant revision. `GrantAccess!Commit` commits only when the grant did not
     change after the request check: each grant change and each revocation clears the `gr` flag
     of each checked operation (`Stale("gr", None)`), and `Same` reads that flag. So when a
     change sets a mark after a check that passed with no approval, the commit refuses.
     `NoRevision_bad` removes that comparison and fails `WithinGrant`: its commit lands after a
     grant change that its check did not see, which is the state of this race.
  2. `Approval!Commit` with a named approval needs `ApprovalOK`, so the approval is of the current
     grant revision. `StaleApproval_bad` removes that rule, and it fails `ApprovalBinding`.
  3. `Approval!Submit` can name no instance for each request. So the model has each behavior in
     which only a submission that names an approval passes the check of a marked permission, and
     more. Each approval property holds for those behaviors.
  4. `Restore` keeps `grev`, and the restore journal keeps each ended revision dead (decision 4).
     So no restore brings back a revision without the mark.

  The rest is the predicate of the check: a marked permission with no named approval refuses.
  It reads the grant revision and the submission in one step, and by facts 1 and 4 no other step
  changes them before the commit. So a test of that one check finds each defect of the rule, and
  no interleaving adds one. A405 (the marks of each revision) and A503 (the consumption check)
  own that test. The failure that this reduction could hide is a check that ignores the mark, and
  only that test shows it.

Faults: the loss of a checked request (a crash or a failed connection), a restore, a lost
response, the cancellation or expiry of an instance, and the withdrawal or refusal of a checked
operation. An attacker can replay each assertion. The models check safety only, so they have no
fairness, and a terminal state is no failure (`CHECK_DEADLOCK FALSE`).

Time is symbolic. `Deadline` marks the grant deadline as passed, and a grant change sets a new
deadline. `EndInst` stands for the short expiry of an instance.

The policy version counts only relevant policy changes. A policy change that is not relevant
raises no version, so it is outside the model. A relevant change ends the access of each grant
that binds an earlier version, until a human-approved grant change binds the new version.

## Decisions

These readings of the design are recorded for the design owner.

1. A grant binds the policy version of its issuance or last change. Access needs that version to
   equal the current version (the lead's ruling of 2026-11-14). The owner's authority is a separate
   input, read at the time of each check, so a change of it needs no new policy version.
2. An approval binds the grant revision of its approval. The commit consumes it only under that
   revision. A grant change therefore needs a new approval.
3. After a restore, a missing outcome record of an identity from an earlier store instance is
   unknown. The store instance number is outside the snapshot. This is the `MissingOutcomeUnknown`
   rule of `authority-restore`. `ApprovalSnapshotNumber.Restore2_bad` keeps the number in the
   snapshot, and it fails `OutcomeOnce`.
4. The restore journal keeps each grant revision that a later change or revocation ended dead
   ([AUTH Storage Contract and Bindings]: "A grant change is recorded as the death of the revision
   that it replaces").
5. Whether a permission needs approval is a grant fact: each grant revision binds its
   approval-required marks. The rule that a commit of a marked permission names an approval is a
   check of one step ([Reductions](#reductions), the approval-required mark).

## Known-bad variants

Each variant changes one rule of the correct model and must violate its one property.

| Profile | Change | Property |
| --- | --- | --- |
| `GrantAccess.IssuedAuth_bad` | The check uses the owner authority of issuance, not the current one | `EffectiveAccess` |
| `GrantAccess.IssuedPolicy_bad` | The check uses the policy version of issuance, not the current one | `EffectiveAccess` |
| `GrantAccess.NoRestrict_bad` | The check ignores the grant's permission restriction | `WithinGrant` |
| `GrantAccess.NoLifecycle_bad` | The commit does not compare the agent lifecycle | `RevokedNoAccess` |
| `GrantAccess.NoRevision_bad` | The commit does not compare the grant revision | `WithinGrant` |
| `Approval.OtherInst_bad` | The approval accepts another instance's assertion for an equal request | `ApprovalBinding` |
| `Approval.StaleApproval_bad` | The commit does not compare the approval's grant revision | `ApprovalBinding` |
| `Approval.Separate_bad` | A second commit, after the operation commit, consumes the approval | `ApprovalOnce` |
| `Approval.RestoreKeeps_bad` | Restore keeps the pending instances and approvals of its snapshot | `RestoreRejects` |
| `Approval.NoIdentity_bad` | The commit does not check the outcome record of the operation identity | `OutcomeOnce` |
| `ApprovalSnapshotNumber.Restore2_bad` | A restore raises the store instance number of its snapshot, not the current number, with two restores | `OutcomeOnce` |

The module `ApprovalSnapshotNumber.tla` replaces `Restore` with `SnapshotRestore`, and each of
its profiles names that replacement. `ApprovalSnapshotNumber.cfg` checks the same variant at the
constants of `Approval.cfg`, and it must pass with the state count of `Approval.cfg`. One restore
cannot repeat a number, so that profile shows that only the restore argument of
[Bounds](#bounds) excludes the defect.

## Reachability

| Profile | Witness state |
| --- | --- |
| `GrantAccess.RevocationRace_reach` | A revocation of the agent or the grant lands between the check and the commit, and the commit refuses |
| `GrantAccess.NarrowGrant_reach` | An operation commits under an active grant that is narrower than the owner's authority |
| `Approval.ApprovedWork_reach` | An operation commits with the human's approval |

## Evidence record

One run checked each of the 27 profiles one time, one at a time, with
`cargo xtask model grant-approval/<profile>` from the repository root. It ran from 2026-11-17
03:41:54 UTC to 04:04:43 UTC, and each profile had a cap of 3,600 seconds.

- Source: the current 30 model files. Each profile printed
  `sha256:f1521b02fb7a7ac450bdcbbf3960873f95b9e5f3f93109549335ab49dd65f92f (30 files)`. An earlier
  source also had the raises `Approval.Ops3.cfg` and `Approval.Restore2.cfg`, which did not finish
  within one hour. The arguments of [Bounds](#bounds) replace them, so they are removed.
- Checkers: temurin-jre 21.0.13+9 (Linux aarch64; the SHA-256 of
  `OpenJDK21U-jre_aarch64_linux_hotspot_21.0.13_9.tar.gz` matched the value that Adoptium
  publishes before the unpack), tla2tools 1.8.0+bc1b506bdcad (TLC2 Version 2026.11.15.002146, rev
  bc1b506), and apalache 0.62.4 (not used by these profiles). TLC ran with `-workers auto
  -lncheck final`: 16 workers and a heap of 7004 MB.
- Host: EC2 c8g.4xlarge (16 vCPUs, AWS Graviton4), on demand, image `ami-06bcda7571e75165c`
  (Debian 12 arm64), kernel 6.1.0-54-cloud-arm64. It was created for dev-machine run
  `20261117T033658Z-62452` and deleted after it. The run reported exit, collection, and teardown
  0, and `dev-machine status rsauthnz aws-linux-arm64-debian12` then showed no AWS instance or EBS
  volume.

| Profile | Result | Distinct states | Depth | Time |
| --- | --- | --- | --- | --- |
| `GrantAccess.cfg` | ok | 50,952 | 13 | 1.03 s |
| `GrantAccess.Ops3.cfg` | ok | 203,212 | 15 | 2.48 s |
| `GrantAccess.Rev3.cfg` | ok | 107,752 | 14 | 1.36 s |
| `GrantAccess.Perms2.cfg` | ok | 177,708 | 13 | 1.66 s |
| `GrantAccess.Own2.cfg` | ok | 105,570 | 14 | 1.29 s |
| `GrantAccess.Pol3.cfg` | ok | 96,222 | 14 | 1.22 s |
| `GrantAccess.Agents3.cfg` | ok | 76,426 | 14 | 1.31 s |
| `GrantAccess.Auds3.cfg` | ok | 85,486 | 13 | 1.42 s |
| `GrantAccess.Ress3.cfg` | ok | 59,672 | 13 | 1.35 s |
| `GrantAccess.Acts3.cfg` | ok | 59,672 | 13 | 1.39 s |
| `GrantAccess.IssuedAuth_bad.cfg` | `EffectiveAccess` violated | 1,549 | 8 | 0.52 s |
| `GrantAccess.IssuedPolicy_bad.cfg` | `EffectiveAccess` violated | 2,179 | 9 | 0.56 s |
| `GrantAccess.NoRestrict_bad.cfg` | `WithinGrant` violated | 1,033 | 8 | 0.56 s |
| `GrantAccess.NoLifecycle_bad.cfg` | `RevokedNoAccess` violated | 2,195 | 9 | 0.61 s |
| `GrantAccess.NoRevision_bad.cfg` | `WithinGrant` violated | 1,575 | 9 | 0.53 s |
| `GrantAccess.RevocationRace_reach.cfg` | target reached | 1,549 | 9 | 0.53 s |
| `GrantAccess.NarrowGrant_reach.cfg` | target reached | 681 | 8 | 0.58 s |
| `Approval.OtherInst_bad.cfg` | `ApprovalBinding` violated | 4,536 | 9 | 0.70 s |
| `Approval.StaleApproval_bad.cfg` | `ApprovalBinding` violated | 6,024 | 10 | 0.76 s |
| `Approval.Separate_bad.cfg` | `ApprovalOnce` violated | 18,212 | 10 | 0.95 s |
| `Approval.RestoreKeeps_bad.cfg` | `RestoreRejects` violated | 183 | 8 | 0.58 s |
| `Approval.NoIdentity_bad.cfg` | `OutcomeOnce` violated | 12,489 | 10 | 0.88 s |
| `Approval.ApprovedWork_reach.cfg` | target reached | 1,781 | 9 | 0.67 s |
| `Approval.cfg` | ok | 11,210,056 | 23 | 318.50 s |
| `Approval.Rev3.cfg` | ok | 23,402,439 | 24 | 697.45 s |
| `ApprovalSnapshotNumber.cfg` | ok | 11,210,056 | 23 | 323.73 s |
| `ApprovalSnapshotNumber.Restore2_bad.cfg` | `OutcomeOnce` violated | 376,594 | 12 | 6.22 s |

Each positive search completed with 0 states left on the queue. The state count of a violation
depends on the order of the workers, so it can differ between runs. The archive
`~/.local/state/model-evidence/rsauthnz/A400/20261117-grant-approval-evidence.tar.gz` (SHA-256
`ab9e0307ebfbbf49cd18b973f340117e191e3724c6f9a1fe50cda1c1d719a893`) keeps the output, the traces,
and the remote run record.

Each trace of a known-bad variant or a witness was read against the task text. Each shows its
named failure or target. For example, `StaleApproval_bad` approves under revision 1, changes the
grant, and then commits with the stale approval. `IssuedAuth_bad` issues the grant, removes the
granted permission from the owner, and commits. In the trace of
`ApprovalSnapshotNumber.Restore2_bad`, a restore gives the number 1, and an operation of that
store instance commits with a lost response. A second restore from a snapshot of the first store
instance gives the number 1 again and removes the outcome record. The retry finds no record under
the current number, so the operation commits a second time. The three steps before the first
restore do not take part in the failure, because the operation names no approval.
