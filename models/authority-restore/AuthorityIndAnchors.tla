------------------------ MODULE AuthorityIndAnchors ------------------------
(***************************************************************************)
(* The raise by one of the anchor domains ([FP Design Models], rule 4):    *)
(* IndInv of AuthorityInd.tla with three accounts, four slots in a1,       *)
(* three in a2, and three administrator slots (Raise = "anchors"). The     *)
(* raise of the process domains is AuthorityIndProcess.tla; the two        *)
(* together raise each bound of the model by one (selected on 2026-11-10). *)
(*                                                                         *)
(* One grouped raise covers each single raise of its group: a state of a   *)
(* model that raises one bound is a state of this model with the other     *)
(* extra elements inert (absent anchors), each IndInv clause quantifies    *)
(* over the domains uniformly, and each step of the smaller model is a     *)
(* step of this one.                                                       *)
(*                                                                         *)
(* The profiles are those of AuthorityInd.tla with CInitAnchors and        *)
(* IndInitAnchors, and two more witnesses: the starting set contains      *)
(* states that use the raised elements (NoAccountsUsed, NoAdminUsed).     *)
(***************************************************************************)
EXTENDS AuthorityInd

CInitAnchors == Bad = "none" /\ Turn = "creation" /\ Origin \in {"new", "bootstrapped"} /\ Raise = "anchors"

IndInitAnchors == IndStart(3)

\* Vacuity witnesses: the starting set contains states that use the raised
\* elements. Each new anchor needs its own committed maker, and the raise
\* keeps three operations, so the accounts and the administrators have one
\* witness each: the third account's second anchor and the extra slots of a1
\* and a2 live together, and the third administrator live.
NoAccountsUsed == ~(anc["a3q"] = "live" /\ anc["a1s"] = "live" /\ anc["a2r"] = "live")
NoAdminUsed == ~(anc["adm3"] = "live")
=============================================================================
