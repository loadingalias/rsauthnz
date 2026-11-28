# Check the design models

rsauthnz has TLA+ models of its authority and restore rules, in
[`models/authority-restore/`](../../models/authority-restore/README.md), and of agent grants and
operation approval, in [`models/grant-approval/`](../../models/grant-approval/README.md).

The [account recovery model](../../models/account-recovery/README.md) covers online operations that cross a
recovery commit and generation checks after restore.

The [replica commit model](../../models/replica-commit/README.md) checks the design for several application servers on one store.
It covers peer restarts, competing passkey removals, and an acknowledged revocation after restore.
Its [shared recovery checks](../../models/replica-commit/README.md#shared-recovery) cover abandoned commits, delayed journal writes, snapshot marks, and counter reservations.
The current Rust driver serves one process per store.

The authority models check that after crashes, restarts, and restores from an older snapshot,
nothing that a committed change ended is valid again: no revoked passkey, no consumed one-use value,
and no reused counter value. They check that a restore adds no anchor whose commit did not complete,
and that each account and the authority keep their anchors. A recovery value cannot justify the
removal of the last sign-in method. They also check recovery progress, the refusal of requests
from an earlier store instance, and the replay window. The models check the design, not the Rust code. Change the model when you change one of these rules.

| Module | Checker | Check |
| --- | --- | --- |
| `Authority.tla`, `AuthorityCached.tla` | TLC | A complete search of authority and restore at declared bounds |
| `AuthorityInd.tla`, `AuthorityIndAnchors.tla`, `AuthorityIndProcess.tla` | Apalache | An inductive proof of every authority property, at the declared domains and with each domain raised by one (the anchor domains and the process domains in two groups): for any number of crashes, restarts, and restores over the operations and snapshots of those domains |
| `AuthorityRecovery.tla` | TLC | Recovery returns to service after crashes stop, with weak fairness for local recovery work, for one operation and at most one restore |
| `Fencing.tla` | TLC | The instance check refuses delayed old requests: two requests and one restart, then the raised bounds of three requests and two restarts |
| `Replay.tla` | Apalache | An inductive proof of the replay window, for each clock error in its bound |

Status (2026-11-17): 117 of the 118 authority profiles pass at the current model files. In the
process raise, one clause pair, `NextSnapshot` preserves `RestoreAdminInvPost`, has no result within
the one-hour cap and is a named limit. The model README's
[evidence record](../../models/authority-restore/README.md#evidence-record) gives each result, and
its [Limits](../../models/authority-restore/README.md#limits) name the open pair.

The grant models check that an agent acts only within its grant, within its owner's current
authority under the current policy version, and before the grant deadline, and that a revoked
agent has no access. They check that one passkey assertion pays for at most one effect of the
exact approved operation, also after a lost response, a lost request, a retry, or a restore.

| Module | Checker | Check |
| --- | --- | --- |
| `GrantAccess.tla` | TLC | A complete search of grant authority and the request check and commit, at the declared bounds and with each bound raised by one |
| `Approval.tla` | TLC | A complete search of one-use approval with the operation commit, request loss, and restore, at the declared bounds |
| `ApprovalSnapshotNumber.tla` | TLC | A known-bad variant of `Approval.tla`: a restore raises the store instance number of its snapshot. It must fail with two restores and pass with one |

The grant models assume that cryptographic verification is correct: two different challenges or
descriptions never give the same digest, and a nonce never repeats. Each grant model takes the
other model's concern as an environment that can do each thing that the concern can do. In
`Approval.tla`, a restore installs any earlier state of each part of the store, so it covers each
real snapshot, and more. The declared profile has one restore. A written argument shows that one
restore is enough while a store instance number never repeats. The `grant-approval` README gives
that argument, and it names each bound, reduction, and decision.

## Install the checkers

The model command uses the Rust toolchain that `rust-toolchain.toml` pins and three checkers. Put
one version of each checker under `~/.local/opt/<name>/<version>/`:

| Name | Version of the recorded evidence | Source | Path that the command uses |
| --- | --- | --- | --- |
| `temurin-jre` | 21.0.13+9 | [Eclipse Temurin](https://adoptium.net/temurin/releases/?version=21) JRE 21 | `bin/java` (on macOS, `Contents/Home/bin/java`) |
| `tla2tools` | 1.8.0: rev d8fb231 (TLC2 Version 2026.11.06.222357) for authority-restore, and rev bc1b506 (TLC2 Version 2026.11.15.002146) for grant-approval | [TLA+ release v1.8.0](https://github.com/tlaplus/tlaplus/releases/tag/v1.8.0) | `tla2tools.jar` |
| `apalache` | 0.62.4 | [Apalache release v0.62.4](https://github.com/apalache-mc/apalache/releases/tag/v0.62.4), `apalache-0.62.4.tgz` without its top directory | `bin/apalache-mc` |

Compare each download with the SHA-256 that its release publishes. The TLA+ project builds the
v1.8.0 release again from its main branch, so its `tla2tools.jar` changes in place. A newer build
can give other state counts, but it must give the same verdicts. Each evidence record names the
`TLC2 Version` line of its build.

`machine update all` now installs the build of rev bc1b506 (2026-11-15) as
`tla2tools/1.8.0+bc1b506bdcad`. The grant-approval results used that build. The authority-restore
TLC results used rev d8fb231, and its Apalache profiles do not use TLC.

The command does not install anything. If a checker is missing, or two versions of one are
present, it stops and names the directory.

## Run the model

From the repository root:

```sh
cargo xtask model authority-restore/Authority.TwoOps.cfg         # one profile; TwoOps is the edit-loop bound
cargo xtask model authority-restore                              # every authority profile
cargo xtask model grant-approval                                 # every grant profile
cargo xtask model account-recovery                               # five recovery profiles
cargo xtask model replica-commit                                 # application server restart and store restore
cargo xtask model replica-commit/SharedTurns.cfg                 # owner turns, outcome lookup, and journal replay
cargo xtask model authority-restore/AuthorityCached.cfg          # a full TLC search
cargo xtask model authority-restore/AuthorityInd.Step.apalache   # a complete inductive step
```

One model run at a time holds the host lock; another run waits for it.

The command prints the digest of the model files, then one result for each profile:

```text
files of .../target/model/inputs/<run>/authority-restore: sha256:<digest> (<count> files)
── tlc authority-restore/Authority.SlotsA1AckEarly_bad.cfg
   `AnchorKept` is violated: as the known-bad variant requires, in 2.50s (exit status: 12)
```

- A main profile passes with `ok` and exit status 0: a complete search or proof with no
  violation. The command reads the checker's own summary: TLC must report 0 states left on the
  queue, and Apalache the outcome `NoError` with no timed-out query. A search that stopped early
  fails as inconclusive, also when the checker exits with 0. Each checker runs with a cleared
  environment, and Apalache uses an explicit empty JSON configuration.
- A `_bad` profile is a known-bad variant. It passes only when the checker reports a violation
  of its one property.
- A `_reach` profile is a reachability witness. It passes only when the checker reaches its
  target.
- A profile that runs longer than one hour fails. At that cap, the command kills the checker and
  waits for it. Each checker is a direct child of the command: TLC runs as java, and
  `apalache-mc` replaces itself with java through `exec`.

The command checks a retained copy of the model under `target/model/inputs/<run>/`. An edit
during a batch cannot change its inputs. The command exits 0 when every selected profile passes.
Each run has its own directory under `target/model/authority-restore/<profile>/`. It keeps the
command, the checker identities, the checked source closure, the verdict, `checker.log`, and a
trace for a violation. A new run never replaces an earlier one.

Each `AuthorityInd*.Step.apalache` profile expands into 67 native jobs, or 75 for the process
raise. Together, the jobs check each action/component pair of the inductive step one time. The
model README's [Inductive proofs](../../models/authority-restore/README.md#inductive-proofs) gives
the argument, and its `preservation.matrix` names the native jobs. All jobs of a Step share its
one-hour cap, and a partial or interrupted Step never passes.

On Linux, a Step runs one job for each core that has 6 GiB of available memory. On another host,
it runs one job at a time. Run each Step on a Linux host with 16 cores and 96 GiB of available
memory. The evidence host EC2 r8g.4xlarge is such a host. No setting changes the job count.

## Large profiles

Most profiles take seconds to minutes. `Authority.TwoOps.cfg` is the local bound for an edit loop.
Each `GrantAccess` profile and each known-bad variant of the grant models finishes in seconds.
These profiles need a large host (16 vCPUs). Each Apalache job uses one core.

| Profile | Size | Time |
| --- | --- | --- |
| `AuthorityCached.cfg` | 199,512,487 distinct states | 36 minutes on c8g.4xlarge (32 GiB) |
| `AuthorityCached.Bootstrapped.cfg` | 61,475,683 distinct states | 10 minutes on c8g.4xlarge |
| `AuthorityInd.Step.apalache` | 67 jobs | 11 minutes on r8g.4xlarge (128 GiB), 16 jobs at a time |
| `AuthorityIndAnchors.Step.apalache` | 67 jobs | 47 minutes on r8g.4xlarge, 16 jobs at a time |
| `AuthorityIndProcess.Step.apalache` | 75 jobs | Incomplete at the 60-minute cap on r8g.4xlarge, with 74 of 75 jobs complete |
| `Approval.cfg` | 11.2 million distinct states | 5 minutes (measured at the A400 files) |
| `Approval.Rev3.cfg` | 23.4 million distinct states | 12 minutes (measured at the A400 files) |
| `ApprovalSnapshotNumber.cfg` | 11.2 million distinct states, as `Approval.cfg` | 5 minutes (measured at the A400 files) |

A large TLC search writes its state queue under `target/model/`, so it also needs free disk.
Each profile must finish within one hour on a 16-vCPU host, so that a run of every profile after a
change stays short. Before you run a new large profile in full, run it for 10 minutes, and estimate
its full size from the growth of the distinct states and the queue. A profile that does not finish
in that time gives no result, and a larger host does not change the limit.

Make the model smaller
only in a way that keeps the result sound: symmetry over identical processes, a bound that the
model proves, or an inductive proof. Each such change needs a known-bad variant that still fails
under it. A smaller bound must still reach each failure that the model names, and it needs a
profile with that bound raised by one.

On a smaller host, select the profiles that your change touches, and run every profile before you
record evidence.

## When a profile fails

- A main TLC profile, or a main Apalache profile that starts at `Init`, reports a violation. The
  trace starts at an initial state. Compare each step with the design's transitions. If the model
  follows the design, the trace is a counterexample to a design rule: the design changes first,
  and then the model. If the model does not follow the design, correct the model.
- A `Step` or `Safety` profile of a proof (`AuthorityInd*.Step.apalache`,
  `AuthorityInd*.Safety.apalache`, `Replay.Step.apalache`, `Replay.Safety.apalache`) reports a
  violation. Its trace starts at a state of the invariant, not at an initial state, and that state
  can be one that no run reaches. Then the invariant is too weak, not the design. Add a clause that
  excludes that state and holds in each reachable state, and run every profile again. To check a
  new clause against the reachable states of a small bound, add it first as an invariant of
  `Authority.TwoOps.cfg`. The trace shows a design defect only when a run from an initial state
  reaches the same violation.
- A `_bad` profile reports "no violation". The variant no longer breaks its property, so the
  property or the module changed. Find which one changed before you change the profile.
- A profile reports a violation of a property other than its own. The variant fails for another
  reason, so it shows nothing about its own property.

After a change, run every profile and update the evidence record in the model's README with the
digest that the command prints.
