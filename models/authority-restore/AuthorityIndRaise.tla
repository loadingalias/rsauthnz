------------------------- MODULE AuthorityIndRaise -------------------------
(***************************************************************************)
(* The raise-by-one check of the inductive invariant ([FP Design Models],  *)
(* rule 4): IndInv of AuthorityInd.tla at every domain raised by one at    *)
(* once (Raise = "all"): three accounts, four slots in a1, three in a2,    *)
(* three administrator slots, four operations, three snapshots, and sets   *)
(* of up to four bootstrap values. The counter and the journal sequence    *)
(* are unbounded integers already, so they need no raise.                  *)
(*                                                                         *)
(* One combined raise covers each single raise: a state of a model that    *)
(* raises one bound is a state of this model with the other extra elements *)
(* inert (an idle operation, absent anchors, fewer snapshots, fewer        *)
(* values), each IndInv clause quantifies over the domains uniformly, and  *)
(* each step of the smaller model is a step of this one.                   *)
(*                                                                         *)
(* The profiles are those of AuthorityInd.tla with CInitRaise and          *)
(* IndInitRaise, and one more witness: IndInitRaise contains a state that  *)
(* uses each raised element (NoRaiseUsed).                                 *)
(***************************************************************************)
EXTENDS AuthorityInd

CInitRaise == Bad = "none" /\ Turn = "creation" /\ Origin \in {"new", "bootstrapped"} /\ Raise = "all"

\* Twelve anchors: the seven of the declared bounds, a1s, a2r, a3p, a3q, and
\* adm3. Each snapshot is one record built from its own generated fields.
\* @type: Str -> Str;
RAncA == Gen(12)
\* @type: Str -> Str;
RAncB == Gen(12)
\* @type: Str -> Str;
RAncC == Gen(12)
\* @type: Set(Int);
RBvalsA == Gen(4)
\* @type: Set(Int);
RBvalsB == Gen(4)
\* @type: Set(Int);
RBvalsC == Gen(4)
\* @type: Set(Int);
RBusedA == Gen(4)
\* @type: Set(Int);
RBusedB == Gen(4)
\* @type: Set(Int);
RBusedC == Gen(4)
\* @type: Set(Int);
RBendedA == Gen(4)
\* @type: Set(Int);
RBendedB == Gen(4)
\* @type: Set(Int);
RBendedC == Gen(4)
\* @type: Set(Str);
ROutA == Gen(4)
\* @type: Set(Str);
ROutB == Gen(4)
\* @type: Set(Str);
ROutC == Gen(4)
\* @type: $snapshot;
RSnapA == [anc |-> RAncA, bvals |-> RBvalsA, bused |-> RBusedA, bended |-> RBendedA,
           cur |-> Gen(1), dead |-> Gen(1), revoked |-> Gen(1), ctr |-> Gen(1),
           out |-> ROutA, lwm |-> Gen(1)]
\* @type: $snapshot;
RSnapB == [anc |-> RAncB, bvals |-> RBvalsB, bused |-> RBusedB, bended |-> RBendedB,
           cur |-> Gen(1), dead |-> Gen(1), revoked |-> Gen(1), ctr |-> Gen(1),
           out |-> ROutB, lwm |-> Gen(1)]
\* @type: $snapshot;
RSnapC == [anc |-> RAncC, bvals |-> RBvalsC, bused |-> RBusedC, bended |-> RBendedC,
           cur |-> Gen(1), dead |-> Gen(1), revoked |-> Gen(1), ctr |-> Gen(1),
           out |-> ROutC, lwm |-> Gen(1)]
\* @type: Str -> $plan;
RPlanGen == Gen(4)
\* @type: Str -> Int;
RArtGen == Gen(4)
\* @type: Str -> Int;
RJEndGen == Gen(4)
\* @type: Str -> Int;
RJCreGen == Gen(4)
\* @type: Str -> Int;
RJVoidGen == Gen(4)
\* @type: Set(Int);
RBvalsGen == Gen(4)
\* @type: Set(Int);
RBusedGen == Gen(4)
\* @type: Set(Int);
RBendedGen == Gen(4)

IndInitRaise ==
  /\ \/ snaps = {}
     \/ snaps = {RSnapA}
     \/ snaps = {RSnapA, RSnapB}
     \/ snaps = {RSnapA, RSnapB, RSnapC}
  /\ plan = RPlanGen
  /\ art = RArtGen
  /\ jEnd = RJEndGen
  /\ jCre = RJCreGen
  /\ jVoid = RJVoidGen
  /\ bvals = RBvalsGen
  /\ bused = RBusedGen
  /\ bended = RBendedGen
  /\ \E n \in Int : cur = n
  /\ \E n \in Int : dead = n
  /\ \E n \in Int : ctr = n
  /\ \E n \in Int : jhead = n
  /\ \E n \in Int : jfloor = n
  /\ \E n \in Int : bnext = n
  /\ IndInv

\* Vacuity witness: IndInitRaise contains a state that uses each raised
\* element: three snapshots, the fourth operation, the third account, the
\* extra slots, the third administrator, and four bootstrap values.
NoRaiseUsed ==
  ~/\ Cardinality(snaps) = 3
   /\ pc["o4"] /= "idle"
   /\ anc["a3q"] = "live" /\ anc["a1s"] = "live" /\ anc["a2r"] = "live" /\ anc["adm3"] = "live"
   /\ Cardinality(bvals) = 4
=============================================================================
