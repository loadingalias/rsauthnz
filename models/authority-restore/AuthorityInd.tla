---------------------------- MODULE AuthorityInd ----------------------------
(***************************************************************************)
(* The inductive invariant of Authority.tla. It proves the safety          *)
(* properties in Safety for histories of any length, at the declared       *)
(* domains, for both origins, with counter values, journal sequences, and  *)
(* bootstrap-value identities as unbounded integers. Apalache checks       *)
(* (README.md, Profiles):                                                  *)
(*   Init => IndInv                          (AuthorityInd.Init)           *)
(*   IndInv /\ N => IndInv' for each part N  (AuthorityInd.Step<N>)        *)
(*   IndInv => Safety                        (AuthorityInd.Safety)         *)
(* Next is the disjunction of the parts, so the parts together are the     *)
(* step check. The `_reach` witnesses show that IndInit contains the       *)
(* states that the Restore, Redrive, and re-bootstrap steps must cover.    *)
(*                                                                         *)
(* AnchorKept, AccountKeepsAnchorP, and AdminKeptP are not in Safety:      *)
(* README.md, Inductive proofs, gives the reason. TLC checks them in the   *)
(* bounded search.                                                         *)
(***************************************************************************)
EXTENDS Authority, Apalache

CInit == Bad = "none" /\ Turn = "creation" /\ Origin \in {"new", "bootstrapped"} /\ Raise = "none"

AncStates == {"absent", "live", "ended"}
PcValues == {"idle", "acked", "refused"} \cup InFlight \cup Crashed

\* A bootstrap-value identity that the history has issued.
\* @type: (Int) => Bool;
IsVal(v) == 1 <= v /\ v <= bnext

\* A plan that Start can propose.
\* @type: ($plan) => Bool;
PlanOK(p) ==
  CASE p.kind = "" -> p = NoPlan
    [] p.kind = "enroll" ->
         p.make \in Anchors \ Adms /\ p.own = Owner(p.make) /\ p.kill = "" /\ p.keep = ""
         /\ p.val = 0
    [] p.kind = "unlink" ->
         /\ p.kill \in Anchors /\ p.keep \in Anchors /\ p.kill /= p.keep /\ p.make = ""
         /\ p.own = Owner(p.kill) /\ Owner(p.keep) = p.own /\ p.val = 0
    [] p.kind = "recover" ->
         /\ p.kill \in Anchors \ Adms /\ p.make \in Anchors \ Adms /\ p.keep = ""
         /\ p.kill /= p.make /\ p.own = Owner(p.kill) /\ Owner(p.make) = p.own /\ p.val = 0
    [] p.kind = "boot" ->
         /\ p.own = "auth" /\ p.kill = "boot" /\ p.keep = "" /\ p.make \in Adms /\ IsVal(p.val)
    [] p.kind = "issue" ->
         /\ p.own = "" /\ p.keep = "" /\ p.make = ""
         /\ \/ p.kill = "boot" /\ IsVal(p.val)
            \/ p.kill = "" /\ p.val = 0
    [] p.kind = "renew" -> p.own = "" /\ p.kill = "L" /\ p.keep = "" /\ p.make = ""
    [] p.kind = "revoke" -> p = Plan("revoke", "", "L", "", "", 0)
    [] OTHER -> FALSE

\* @type: ($snapshot) => Bool;
SnapTypeOK(s) ==
  /\ s.anc \in [Anchors -> AncStates]
  /\ s.revoked \in BOOLEAN
  /\ s.out \subseteq Ops
  /\ \A v \in s.bvals \cup s.bused \cup s.bended : IsVal(v)
  /\ 0 <= s.lwm /\ s.lwm <= jhead

\* Symbolic values for IndInit. Gen(n) bounds each nested collection by n.
\* A snapshot's anchor function has seven anchors, so it needs Gen(7); with
\* a smaller bound, IndInit contains no snapshot, and the step check never
\* covers Restore. Each set of bootstrap values has at most three values,
\* and each outcome set at most three operations (README.md, Inductive
\* proofs). The two snapshots are two records, each built from its own
\* generated fields, so that Gen(7) bounds only the anchor functions.
\* @type: Str -> Str;
AncA == Gen(7)
\* @type: Str -> Str;
AncB == Gen(7)
\* @type: Set(Int);
BvalsA == Gen(3)
\* @type: Set(Int);
BvalsB == Gen(3)
\* @type: Set(Int);
BusedA == Gen(3)
\* @type: Set(Int);
BusedB == Gen(3)
\* @type: Set(Int);
BendedA == Gen(3)
\* @type: Set(Int);
BendedB == Gen(3)
\* @type: Set(Str);
OutA == Gen(3)
\* @type: Set(Str);
OutB == Gen(3)
\* @type: $snapshot;
SnapA == [anc |-> AncA, bvals |-> BvalsA, bused |-> BusedA, bended |-> BendedA,
          cur |-> Gen(1), dead |-> Gen(1), revoked |-> Gen(1), ctr |-> Gen(1),
          out |-> OutA, lwm |-> Gen(1)]
\* @type: $snapshot;
SnapB == [anc |-> AncB, bvals |-> BvalsB, bused |-> BusedB, bended |-> BendedB,
          cur |-> Gen(1), dead |-> Gen(1), revoked |-> Gen(1), ctr |-> Gen(1),
          out |-> OutB, lwm |-> Gen(1)]
\* @type: Str -> $plan;
PlanGen == Gen(3)
\* @type: Str -> Int;
ArtGen == Gen(3)
\* @type: Str -> Int;
JEndGen == Gen(3)
\* @type: Str -> Int;
JCreGen == Gen(3)
\* @type: Str -> Int;
JVoidGen == Gen(3)
\* @type: Set(Int);
BvalsGen == Gen(3)
\* @type: Set(Int);
BusedGen == Gen(3)
\* @type: Set(Int);
BendedGen == Gen(3)

TypeInd ==
  /\ phase \in {"up", "down", "rec"}
  /\ restored \in BOOLEAN
  /\ anc \in [Anchors -> AncStates]
  /\ revoked \in BOOLEAN
  /\ out \in SUBSET Ops
  /\ pend \in SUBSET Ops
  /\ pc \in [Ops -> PcValues]
  /\ DOMAIN plan = Ops /\ DOMAIN art = Ops
  /\ lock \in [Owners -> Ops \cup {"none"}]
  /\ DOMAIN jEnd = Ops /\ DOMAIN jCre = Ops /\ DOMAIN jVoid = Ops
  /\ jhead >= 0
  /\ bnext >= 1
  /\ \A v \in bvals \cup bused \cup bended : IsVal(v)
  /\ Cardinality(snaps) <= NSnaps
  /\ committed \in SUBSET Ops
  /\ left \in [Ops -> SUBSET Anchors]
  /\ \A o \in Ops : PlanOK(plan[o])
  /\ \A o \in Ops :
       /\ 0 <= jEnd[o] /\ jEnd[o] <= jhead /\ 0 <= jCre[o] /\ jCre[o] <= jhead
       /\ 0 <= jVoid[o]
  /\ \A s \in snaps : SnapTypeOK(s)

\* The journal and the history: what each point of an operation implies.
JournalInv ==
  /\ \A o \in Ops :
       /\ pc[o] = "idle" <=> plan[o].kind = ""
       /\ pc[o] = "idle" =>
            /\ jEnd[o] = 0 /\ jCre[o] = 0 /\ jVoid[o] = 0 /\ art[o] = 0
            /\ o \notin committed /\ o \notin out
       /\ jEnd[o] > 0 => plan[o].kill /= ""
       /\ jCre[o] > 0 => plan[o].make /= "" /\ o \in committed
  /\ \A o \in Ops : pc[o] \in InFlight => phase = "up" /\ jVoid[o] = 0
  /\ \A o \in Ops : pc[o] = "journaled" /\ plan[o].kill /= "" => jEnd[o] > 0
  /\ \A o \in Ops : pc[o] \in {"checked", "journaled"} => o \notin committed
  /\ \A o \in Ops : pc[o] \in {"committed", "created", "cCommitted", "cCreated"} => o \in committed
  /\ \A o \in Ops : pc[o] \in {"created", "cCreated"} => jCre[o] > 0
  /\ \A o \in Ops : pc[o] = "acked" /\ plan[o].make /= "" => jCre[o] > 0
  \* A refusal voided its entry, and the refused operation never committed.
  /\ \A o \in Ops : pc[o] = "refused" => o \notin committed /\ (jEnd[o] > 0 => jVoid[o] > 0)

\* NothingEndedValid: each committed end holds in the store, and in each
\* snapshot unless the snapshot comes before the entry.
EndInv ==
  /\ \A o \in committed :
       /\ jVoid[o] = 0
       /\ plan[o].kill /= "" => jEnd[o] > 0 /\ EndHolds(o)
  /\ \A s \in snaps : \A o \in Ops :
       0 < jEnd[o] /\ jEnd[o] <= s.lwm => EndHoldsIn(o, s) \/ jVoid[o] > 0
  /\ \A s \in snaps : \A o \in s.out : plan[o].kill /= "" => EndHoldsIn(o, s)

\* MissingOutcomeUnknown: an outcome record, in the store or in a snapshot,
\* is a commit, and before the first restore each commit has its record.
OutcomeInv ==
  /\ ~restored => committed \subseteq out
  /\ out \subseteq committed
  /\ \A s \in snaps : s.out \subseteq committed

\* OneUse and PendExact: an in-doubt consumption has an entry that no void
\* cancels, its fact holds, its client has stopped, and no commit in the
\* current history spent its value. No in-doubt state remains while the
\* store serves.
DoubtInv ==
  /\ \A o \in pend :
       /\ Consumes(o) /\ jEnd[o] > 0 /\ jVoid[o] = 0 /\ EndHolds(o)
       /\ pc[o] \in Crashed /\ o \notin out
       /\ ~\E q \in out : Consumes(q) /\ SameValue(q, o)
  /\ phase = "up" => pend = {}
  /\ OneUse
  /\ \A s \in snaps :
       \A o, q \in s.out : o /= q /\ Consumes(o) /\ Consumes(q) => ~SameValue(o, q)

\* NoUncommittedAnchor, and the anchors that commits created: an anchor of
\* an outcome record is never absent, and a creation entry at or below a
\* snapshot's low-water mark is reflected in that snapshot.
AnchorInv ==
  /\ NoUncommittedAnchor
  /\ \A o \in out : plan[o].make /= "" => anc[plan[o].make] /= "absent"
  /\ \A s \in snaps :
       /\ \A x \in Anchors :
            s.anc[x] = "live" => x \in InitLive \/ \E o \in committed : plan[o].make = x
       /\ \A o \in s.out : plan[o].make /= "" => s.anc[plan[o].make] /= "absent"
       /\ \A o \in Ops :
            0 < jCre[o] /\ jCre[o] <= s.lwm /\ jVoid[o] = 0 => s.anc[plan[o].make] /= "absent"

\* OneBootValid: at most one bootstrap value is valid, in the store and in
\* each snapshot. A restore keeps only the values of its snapshot.
BootInv ==
  /\ OneBootValid
  /\ \A s \in snaps :
       \A v, w \in s.bvals :
         v \notin s.bused /\ v \notin s.bended /\ w \notin s.bused /\ w \notin s.bended => v = w

\* NoCounterReuse: each artifact value is above the initial value, at or
\* below the counter and the durable floor, and unique.
CounterInv ==
  /\ ctr >= 1
  /\ \A s \in snaps : s.ctr >= 1
  /\ \A o \in Ops : art[o] = 0 \/ (2 <= art[o] /\ art[o] <= ctr /\ art[o] <= jfloor)
  /\ \A o, q \in Ops : o /= q /\ art[o] > 0 /\ art[q] > 0 => art[o] /= art[q]

IndInv ==
  /\ TypeInd
  /\ JournalInv
  /\ EndInv
  /\ OutcomeInv
  /\ DoubtInv
  /\ AnchorInv
  /\ BootInv
  /\ CounterInv

\* The properties that the inductive invariant proves.
Safety ==
  /\ NothingEndedValid
  /\ OneBootValid
  /\ NoCounterReuse
  /\ MissingOutcomeUnknown
  /\ NoUncommittedAnchor
  /\ RefusalHolds
  /\ OneUse
  /\ PendExact
  /\ NoDoubtServing

IndInit ==
  /\ \/ snaps = {}
     \/ snaps = {SnapA}
     \/ snaps = {SnapA, SnapB}
  /\ plan = PlanGen
  /\ art = ArtGen
  /\ jEnd = JEndGen
  /\ jCre = JCreGen
  /\ jVoid = JVoidGen
  /\ bvals = BvalsGen
  /\ bused = BusedGen
  /\ bended = BendedGen
  /\ \E n \in Int : cur = n
  /\ \E n \in Int : dead = n
  /\ \E n \in Int : ctr = n
  /\ \E n \in Int : jhead = n
  /\ \E n \in Int : jfloor = n
  /\ \E n \in Int : bnext = n
  /\ IndInv

\* The parts of the step check. Each part has one symbolic transition, or
\* two for the short ones, so that each Apalache run stays within the time
\* budget of the development host. By the definitions of Start, NextRun,
\* and NextSys:
\*   NextRun = NextEnroll \/ NextUnlink \/ NextRecover \/ NextBoot
\*             \/ NextRenew \/ NextRevoke \/ NextIssueEnd \/ NextIssueNone
\*             \/ NextJournal \/ NextCommit \/ NextConflict
\*   NextSys = NextFail \/ NextServe
\* so these parts, NextEnd, NextRec, NextAgain, and NextRestore together are
\* Next.
NextEnroll == \E o \in Ops : StartEnroll(o)
NextUnlink == \E o \in Ops : StartUnlink(o)
NextRecover == \E o \in Ops : StartRecover(o)
NextBoot == \E o \in Ops : StartBoot(o)
NextRenew == \E o \in Ops : StartRenew(o)
NextRevoke == \E o \in Ops : StartRevoke(o)
NextIssueEnd == \E o \in Ops : StartIssueEnd(o)
NextIssueNone == \E o \in Ops : StartIssueNone(o)
NextJournal == \E o \in Ops : JournalEnd(o)
NextCommit == \E o \in Ops : Commit(o)
NextConflict == \E o \in Ops : Conflict(o)
NextFail == Crash \/ Restart
NextServe == Serve \/ Snapshot

\* Vacuity witnesses. Each `_reach` profile checks one of these at length 0,
\* so the checker shows an IndInit state with the key state.
\* A snapshot from which a restore puts a consumption in doubt.
NoDoubtSnapshot ==
  ~\E s \in snaps : \E o \in Ops :
     /\ phase = "down" /\ Consumes(o) /\ jEnd[o] > s.lwm /\ jVoid[o] = 0
     /\ o \notin s.out /\ jCre[o] = 0
\* An in-doubt consumption that a redrive can commit.
NoPending == ~\E o \in pend : First(o) /\ AgainOK(o)
\* Two released artifacts.
NoTwoReleased ==
  ~\E o, q \in Ops : o /= q /\ pc[o] = "acked" /\ pc[q] = "acked" /\ art[o] > 0 /\ art[q] > 0
\* An owner re-bootstrap that can commit and end the valid value.
NoIssueReady ==
  ~\E o \in Ops :
     /\ phase = "up" /\ pc[o] = "journaled" /\ plan[o].kind = "issue" /\ plan[o].kill = "boot"
     /\ ValidBoot = {plan[o].val}
\* A snapshot whose valid bootstrap value a later re-bootstrap entry ends at
\* a restore.
NoEndedValueSnapshot ==
  ~\E s \in snaps : \E o \in Ops :
     /\ phase = "down" /\ plan[o].kind = "issue" /\ plan[o].kill = "boot"
     /\ jEnd[o] > s.lwm /\ jVoid[o] = 0
     /\ plan[o].val \in s.bvals /\ plan[o].val \notin s.bused /\ plan[o].val \notin s.bended
=============================================================================
