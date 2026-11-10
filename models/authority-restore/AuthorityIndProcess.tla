------------------------ MODULE AuthorityIndProcess ------------------------
(***************************************************************************)
(* The raise by one of the process domains ([FP Design Models], rule 4):   *)
(* IndInv of AuthorityInd.tla with four operations, three snapshots, and   *)
(* sets of up to four bootstrap values (Raise = "process"). The raise of   *)
(* the anchor domains is AuthorityIndAnchors.tla; the two together raise   *)
(* each bound of the model by one (selected on 2026-11-10). The counter    *)
(* and the journal sequence are unbounded integers, so they need no raise. *)
(*                                                                         *)
(* One grouped raise covers each single raise of its group: a state of a   *)
(* model that raises one bound is a state of this model with the other     *)
(* extra elements inert (an idle operation, fewer snapshots, fewer         *)
(* values), each IndInv clause quantifies over the domains uniformly, and  *)
(* each step of the smaller model is a step of this one.                   *)
(*                                                                         *)
(* The profiles are those of AuthorityInd.tla with CInitProcess and        *)
(* IndInitProcess, and one more witness: the starting set contains a state *)
(* that uses each raised element (NoProcessUsed).                          *)
(***************************************************************************)
EXTENDS AuthorityInd

CInitProcess == Bad = "none" /\ Turn = "creation" /\ Origin \in {"new", "bootstrapped"} /\ Raise = "process"

IndInitProcess == IndStart(4)

\* Vacuity witness: the starting set contains a state that uses each raised
\* element: three snapshots, the fourth operation, and four bootstrap values.
NoProcessUsed ==
  ~(Cardinality(snaps) = 3 /\ pc["o4"] /= "idle" /\ Cardinality(bvals) = 4)
=============================================================================
