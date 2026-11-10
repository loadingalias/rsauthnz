# Check the design models

rsauthnz has TLA+ models of its authority and restore rules:
[`models/authority-restore/`](../../models/authority-restore/README.md). They check that after
crashes, restarts, and restores from an older snapshot, nothing that a committed change ended is
valid again: no revoked passkey, no consumed one-use value, and no reused counter value. They check
that a restore adds no anchor whose commit did not complete, that each account and the authority
keep their anchors, and that the replay window accepts no signature twice for each clock error in
its bound. The models check the design, not the Rust code. Change the model when you change one of
these rules.

| Module | Checker | Check |
| --- | --- | --- |
| `Authority.tla` | TLC | A complete search of authority and restore at declared bounds |
| `AuthorityInd.tla`, `AuthorityIndAnchors.tla`, `AuthorityIndProcess.tla` | Apalache | An inductive proof of every authority property, at the declared domains and with each domain raised by one (the anchor domains and the process domains in two groups): for any number of crashes, restarts, and restores over the operations and snapshots of those domains |
| `Replay.tla` | Apalache | An inductive proof of the replay window, for each clock error in its bound |

## Install the checkers

The model command uses the Rust toolchain that `rust-toolchain.toml` pins and three checkers. Put
one version of each checker under `~/.local/opt/<name>/<version>/`:

| Name | Version of the recorded evidence | Source | Path that the command uses |
| --- | --- | --- | --- |
| `temurin-jre` | 21.0.13+9 | [Eclipse Temurin](https://adoptium.net/temurin/releases/?version=21) JRE 21 | `bin/java` (on macOS, `Contents/Home/bin/java`) |
| `tla2tools` | 1.8.0 (TLC2 Version 2026.11.06.222357, rev d8fb231) | [TLA+ release v1.8.0](https://github.com/tlaplus/tlaplus/releases/tag/v1.8.0) | `tla2tools.jar` |
| `apalache` | 0.62.4 | [Apalache release v0.62.4](https://github.com/apalache-mc/apalache/releases/tag/v0.62.4), `apalache-0.62.4.tgz` without its top directory | `bin/apalache-mc` |

Compare each download with the SHA-256 that its release publishes. The TLA+ project builds the
v1.8.0 release again from its main branch, so its `tla2tools.jar` changes in place. A newer build
can give other state counts, but it must give the same verdicts. Each evidence record names the
`TLC2 Version` line of its build.

The command does not install anything. If a checker is missing, or two versions of one are
present, it stops and names the directory.

## Run the model

From the repository root:

```sh
cargo xtask model authority-restore/Authority.TwoOps.cfg                 # one profile
cargo xtask model authority-restore/Authority.TwoOps.cfg authority-restore/Replay.Step.apalache
cargo xtask model authority-restore                                      # every profile
```

One model run at a time holds the host lock; another run waits for it.

The command prints the digest of the model files, then one result for each profile:

```text
files of .../models/authority-restore: sha256:<digest> (<count> files)
── tlc authority-restore/Authority.SlotsA1AckEarly_bad.cfg
   `AnchorKept` is violated: as the known-bad variant requires, in 2.50s (exit status: 12)
```

- A main profile passes with `ok` and exit status 0: a complete search or proof with no
  violation. The command reads the checker's own summary: TLC must report 0 states left on the
  queue, and Apalache the outcome `NoError` with no timed-out query. A search that stopped early
  fails as inconclusive, also when the checker exits with 0. The command removes the JVM option
  variables (`JAVA_TOOL_OPTIONS`, `JDK_JAVA_OPTIONS`, `_JAVA_OPTIONS`, `JVM_ARGS`) from each
  checker run.
- A `_bad` profile is a known-bad variant. It passes only when the checker reports a violation
  of its one property.
- A `_reach` profile is a reachability witness. It passes only when the checker reaches its
  target.

The command exits 0 when every selected profile passes. The output of each profile goes to
`target/model/authority-restore/<profile>/`: `checker.log`, and a trace for a violation
(`trace.json` from TLC, `<Module>.tla/<run>/violation1.itf.json` from Apalache).

## Large profiles

Most profiles take seconds to minutes. `Authority.TwoOps.cfg` is the local bound for an edit loop.
These profiles need a large host (16 vCPUs, 64 GiB; each Apalache profile uses one core):

| Profile | Size | Time |
| --- | --- | --- |
| `Authority.cfg` | 218.1 million distinct states | 56 minutes (measured at the A000 files) |
| `Authority.Bootstrapped.cfg` | 67.1 million distinct states | 17 minutes (measured at the A000 files) |
| `AuthorityInd.Step<Part><Group>.apalache` (92 profiles) | — | 2 to 13 minutes each |
| `AuthorityIndAnchors.Step<Part><Group>.apalache`, `AuthorityIndProcess.Step<Part><Group>.apalache` (92 profiles each) | — | Not measured in full; the model README, "Limits" |

A large TLC search writes its state queue under `target/model/`, so it also needs free disk.
Each profile must finish within one hour on a 16-vCPU host. Before you run a new large profile in
full, run it for 10 minutes, and estimate its full size from the growth of the distinct states and
the queue. A profile that cannot finish in that time needs a smaller model, not a larger host.

On a smaller host, select the profiles that your change touches, and run every profile before you
record evidence.

## When a profile fails

- A main profile reports a violation. The trace is a counterexample to a design rule. The design
  changes first, and then the model.
- A `_bad` profile reports "no violation". The variant no longer breaks its property, so the
  property or the module changed. Find which one changed before you change the profile.
- A profile reports a violation of a property other than its own. The variant fails for another
  reason, so it shows nothing about its own property.

After a change, run every profile and update the evidence record in the model's README with the
digest that the command prints.
