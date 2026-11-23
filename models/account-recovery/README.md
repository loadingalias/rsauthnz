# Account recovery generations

A full account recovery takes effect at the store commit. This model checks which evidence an online operation can
use when recovery or restore occurs between verification and commit. It also checks that a restored account can use
the passkey of its latest recovery.

## Protocol

| Action | Contract |
| --- | --- |
| `WriteIntent` | The restore journal durably records a recovery that consumes a code. |
| `Recover` | The conditional store commit consumes the code and installs the new generation and passkey together. |
| `Record` | The journal records the result before the caller can receive confirmation or the restored store can serve. |
| `Restore` | The store stops serving and installs a saved generation and passkey. The journal survives. |
| `Replay` | Restore applies the recorded generation and passkey or completes the eligible recovery. |
| `Obtain` | A caller obtains evidence or an approval in the current generation. |
| `Prepare` | A verifier checks the generation of that evidence and includes it in a proposal. |
| `Commit` | The store compares that generation in the same transaction as the effect. |

The profiles cover one account, a retained request, and two successive full recoveries. The initial generation is
one. A restore can select any earlier committed snapshot. Another crash can interrupt replay before its result
becomes durable. The source of a request can survive each recovery and restore.

The model assumes a single eligible recovery for each code. The authority-restore model owns selection between
competing consumers, voids, and store instance numbers. This model assumes that the journal retains the generation
with the new passkey of the selected recovery. The Rust restore journey must show that its stored forms implement
that assumption. Ordinary online checks, account isolation, and the keep-passkeys policy also need Rust evidence.

The current journal checks that each new anchor key is absent before it completes a consumption in doubt.
A snapshot after a first recovery can already contain the generation record at a fixed account key. A second
recovery must preserve both its generation and its passkey in that case. See [restore](../../src/store/journal/rules.rs).

## Profiles

| Profile | Required result |
| --- | --- |
| `AccountRecovery.cfg` | Every accepted request uses current evidence. Each serving state has the latest accepted generation and its passkey. |
| `AccountRecovery.Commit_bad.cfg` | A commit that omits the generation comparison violates `CurrentAtCommit`. |
| `AccountRecovery.Approval_bad.cfg` | Relabeling earlier evidence with the current generation violates `CurrentAtCommit`. |
| `AccountRecovery.Restore_bad.cfg` | Keeping the snapshot generation during replay violates `CurrentAfterRestore`. |
| `AccountRecovery.RestoredUse_reach.cfg` | A request succeeds after two recoveries and a restore from an earlier generation. |

Run the five profiles with `cargo xtask model account-recovery`.

On 2026-11-23, all five profiles passed on macOS arm64 with TLC 1.8.0 at `bc1b506bdcad` and JRE 21.0.13+9.
The main search found 224 distinct states, reached depth 13, and exhausted its queue. Each faulty profile violated
its named invariant. The witness reached successful use after restore. The six model input files had SHA-256
`cdb7502ff49f99a4277566d27efdf96738c589a6700416fd53e03fdd19f61e88`.
