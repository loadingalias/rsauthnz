------------------------ MODULE ApprovalSnapshotNumber ------------------------
(***************************************************************************)
(* Known-bad variant of Approval.tla for the restore bound: the store      *)
(* keeps its instance number in the snapshot. So a restore raises the      *)
(* number of its snapshot, not the current number, and two store           *)
(* instances can get the same number. Decision 3 of the README forbids     *)
(* this.                                                                   *)
(*                                                                         *)
(* With one restore, each snapshot has the number 0, so the state graph    *)
(* is the graph of Approval.tla. With two restores, a missing outcome      *)
(* record can look current, and a retry gives a second effect.             *)
(*                                                                         *)
(* Each profile replaces Restore with SnapshotRestore.                     *)
(***************************************************************************)
EXTENDS Approval

\* Restore of Approval.tla, except the new store instance number: it is one
\* more than the number s of the snapshot, from this or an earlier store
\* instance.
SnapshotRestore ==
  /\ ep < MaxRestore
  /\ \E f \in [Insts -> UNION {Earlier(i) : i \in Insts}] :
       /\ \A i \in Insts : f[i] \in Earlier(i)
       /\ inst' = f
  /\ \E R \in SUBSET rec : rec' = R
  /\ \E s \in 0..ep : ep' = s + 1
  /\ UNCHANGED <<grev, op, signed, used, done, paid, held>>

=============================================================================
