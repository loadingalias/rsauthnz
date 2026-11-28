# Recover an operation after a lost reply

A server sends a credential request and loses the reply. A second server looks for its receipt before the write arrives.
If the second server tells the caller to start again, both requests can issue a credential.

The recovery action takes the original operation identity and request binding. Its answer tells the caller what to do.

| Evidence at the primary store | Recovery action | Answer |
| --- | --- | --- |
| A retained receipt | Read the receipt after any required journal work settles. | Committed. Return the original receipt. |
| A durable request that can still commit | Help that request reach its decision. | Read the resulting decision under the same identity. |
| No decision, with complete history for this request | Atomically record that this identity is closed. A concurrent commit or reservation uses the same comparison. | If closure wins, a fresh attempt is safe. If another write wins, read its decision. |
| No decision, with missing history | Keep the outcome unresolved. | Unknown. |

A status read only observes. Recovery never repeats a one-use operation or issues a second copy of a private credential.

## Primary store decisions

Each copy of the original request carries the same operation identity, binding, generation, and retention window.
The window identifies the period for which the store can establish the full history of this operation.

| Action | Corresponding store operation |
| --- | --- |
| `Prepare`, `Deliver` | Check the original generation, window, and decision in the same write as reservation or commit. A closed identity refuses either write. |
| `Inspect` | Read the decision. An empty row can occur while the original request is in flight. |
| `Resolve` | Help a reserved request or close an eligible empty row. Read its decision in a separate step. A helper can lose the reply between these steps. |
| `RetireWindow`, `Prune` | Stop admitting writes for the original window before removing its receipts or closures. Retained decisions still answer recovery. |
| `Restore` | Install a snapshot from before the operation and change the generation. Old requests can arrive after restore. |

`FreshIsFinal` excludes a commit before or after a fresh-attempt answer. `AtMostOnce` counts commits across restore.
`ReceiptBacked` requires an actual commit for each reported receipt. `PassiveStatus` prevents a status read from closing a live request.
`Returns` checks that recovery reaches an answer if the store keeps giving the helper a turn.

## Bounds

The model follows one operation, its delayed copies, one optional reservation, one retirement, and one optional restore.
It treats a primary write as atomic. It assumes a binding has a durable test for retention coverage.
It does not measure time or the length of a client's wait. The model counts durable effects even when a snapshot loses their records.
The production driver implements the recovery action (`Driver::recover`). A closure is the outcome record of the identity, so the commit check of the original compares it.
The separate model checks settlement of an owner's journal work and fencing at both destinations. [Shared recovery](../replica-commit/README.md#shared-recovery)

## Evidence

On 2026-11-27 SANY parsed the module on macOS 27.2.1 arm64.
TLC 1.8.0 at `bc1b506bdcad` ran all 14 profiles with JRE 21.0.13.1+2.
The checker runs took 6.7 seconds in total.

| Profiles | Result |
| --- | --- |
| Two delayed copies, then three | TLC exhausted 529 and 731 distinct states and completed the temporal check at each bound. |
| Four witnesses | A packet arrived after closure. A helper committed a reserved request. Recovery reported unknown after pruning and after restore. |
| Four false assurances | Reading absence as final, ignoring closure, and trusting missing history after expiry or restore violated `FreshIsFinal`. |
| Three duplicate commits | Accepting a retired window or old generation, and pruning a live decision, violated `AtMostOnce`. |
| One destructive status read | A status read that closed a request violated `PassiveStatus`. |

Run the focused checks with `cargo xtask model outcome-resolution`.
The 15 input files have SHA-256 `f47faa44012fa94760105f84e2daabd879e64638e675687edfd8baab7c60ea53`.
Each `target/model/outcome-resolution/<profile>/<run>/run.txt` records the module and profile hashes, tool versions, command, and verdict.
