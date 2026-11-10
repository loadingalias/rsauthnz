---------------------------- MODULE AuthorityInd ----------------------------
(***************************************************************************)
(* The inductive invariant of Authority.tla. It proves every property in   *)
(* Safety, the anchor properties AnchorKept, AccountKeepsAnchorP, and      *)
(* AdminKeptP included, for histories of any length at the declared        *)
(* domains, for both origins, with counter values, journal sequences, and  *)
(* bootstrap-value identities as unbounded integers. An operation identity *)
(* commits through Commit once, and a snapshot is never removed, so "any   *)
(* length" means any number of crashes, restarts, restores, and            *)
(* reconciliation steps over the domains of the run (README.md, Inductive  *)
(* proofs). Apalache checks (README.md, Profiles):                         *)
(*   Init => IndInv                          (AuthorityInd.Init)           *)
(*   IndInv /\ N => IndInv' for each part N  (AuthorityInd.Step<N>)        *)
(*   IndInv => Safety                        (AuthorityInd.Safety)         *)
(* Next is the disjunction of the parts, so the parts together are the     *)
(* step check. A step check states IndInv' as action invariants, one for   *)
(* each part of IndInv, which Apalache checks after the transition only:   *)
(* IndInit is a subset of IndInv, so a check of its states proves nothing. *)
(* The `_reach` witnesses show that IndInit contains the states that the   *)
(* steps must cover.                                                       *)
(***************************************************************************)
EXTENDS Authority, Apalache

CInit == Bad = "none" /\ Turn = "creation" /\ Origin \in {"new", "bootstrapped"} /\ Raise = "none"
\* The known-bad variant "ownMark" of the shared low-water mark.
CInitOwnMark == Bad = "ownMark" /\ Turn = "creation" /\ Origin \in {"new", "bootstrapped"} /\ Raise = "none"

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
  /\ DOMAIN s.anc = Anchors /\ \A x \in Anchors : s.anc[x] \in AncStates
  /\ s.revoked \in BOOLEAN
  /\ s.out \subseteq Ops
  /\ DOMAIN s.left = Ops /\ \A o \in Ops : s.left[o] \subseteq Anchors
  /\ \A v \in s.bvals \cup s.bused \cup s.bended : IsVal(v)
  /\ 0 <= s.lwm /\ s.lwm <= jhead

TypeInd ==
  /\ phase \in {"up", "down", "rec"}
  /\ restored \in BOOLEAN
  /\ DOMAIN anc = Anchors /\ \A x \in Anchors : anc[x] \in AncStates
  /\ revoked \in BOOLEAN
  /\ out \subseteq Ops
  /\ pend \subseteq Ops
  /\ DOMAIN pc = Ops /\ \A o \in Ops : pc[o] \in PcValues
  /\ DOMAIN plan = Ops /\ DOMAIN art = Ops
  /\ DOMAIN lock = Owners /\ \A a \in Owners : lock[a] \in Ops \cup {"none"}
  /\ DOMAIN jEnd = Ops /\ DOMAIN jCre = Ops /\ DOMAIN jVoid = Ops
  /\ jhead >= 0
  /\ bnext >= 1
  /\ \A v \in bvals \cup bused \cup bended : IsVal(v)
  /\ Cardinality(snaps) <= NSnaps
  /\ committed \subseteq Ops
  /\ DOMAIN left = Ops /\ \A o \in Ops : left[o] \subseteq Anchors
  /\ promised \subseteq Anchors
  /\ \A o \in Ops : PlanOK(plan[o])
  /\ \A o \in Ops :
       /\ 0 <= jEnd[o] /\ jEnd[o] <= jhead /\ 0 <= jCre[o] /\ jCre[o] <= jhead
       /\ 0 <= jVoid[o] /\ jVoid[o] <= jhead
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
  \* Only a redrive commits a crashed operation: a consumption with its entry.
  \* A new anchor goes in a slot that is absent, so never in an initial one.
  /\ \A o \in Ops : plan[o].make \notin InitLive
  /\ \A o \in Ops :
       pc[o] \in {"cChecked", "cJournaled"} /\ o \in committed => Consumes(o) /\ pc[o] = "cJournaled"
  /\ \A o \in Ops : pc[o] \in {"committed", "created", "cCommitted", "cCreated"} => o \in committed
  /\ \A o \in Ops : pc[o] \in {"created", "cCreated"} => jCre[o] > 0
  /\ \A o \in Ops : pc[o] = "acked" /\ plan[o].make /= "" => jCre[o] > 0
  \* Each entry has its own sequence number, and the entries of an operation
  \* come in the order of its steps.
  /\ \A o \in Ops :
       /\ jEnd[o] > 0 /\ jCre[o] > 0 => jEnd[o] < jCre[o]
       /\ jVoid[o] > 0 => jEnd[o] > 0 /\ jVoid[o] > jEnd[o] /\ jCre[o] = 0
  /\ \A o, q \in Ops :
       o /= q => \A e \in {jEnd[o], jCre[o], jVoid[o]} \ {0} : e \notin {jEnd[q], jCre[q], jVoid[q]}
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

\* The anchor properties. A restore from a snapshot s makes each anchor what
\* the snapshot holds, with each entry after its low-water mark that no void
\* cancels; RestoredAnc is that state. A restore keeps an anchor that the
\* journal records as made and as not ended (Journaled), so each promise and
\* each account's last anchor rest on the journal (README.md, Inductive
\* proofs).
\* An anchor that the journal records as made: live at the start, or with a
\* creation entry. Creation entries are never voided.
JournalMade(x) == x \in InitLive \/ \E o \in Ops : plan[o].make = x /\ jCre[o] > 0
\* An end entry of x that no void cancels.
JournalEnded(x) == \E o \in Ops : plan[o].kill = x /\ jEnd[o] > 0 /\ jVoid[o] = 0
\* A commit of q made x, and its creation entry is still to come.
CreationDue(q, x) == plan[q].make = x /\ jCre[q] = 0

\* What a restore from s gives now.
\* @type: ($snapshot, Str) => Bool;
RestoreEnds(s, x) == s.anc[x] = "ended" \/ \E o \in Ops : plan[o].kill = x /\ jEnd[o] > s.lwm /\ jVoid[o] = 0
\* @type: ($snapshot, Str) => Bool;
RestoreMakes(s, x) == s.anc[x] = "live" \/ \E o \in Ops : plan[o].make = x /\ jCre[o] > s.lwm /\ jVoid[o] = 0
\* @type: ($snapshot, Str) => Str;
RestoredAnc(s, x) == IF RestoreEnds(s, x) THEN "ended" ELSE IF RestoreMakes(s, x) THEN "live" ELSE "absent"
\* @type: ($snapshot, Str) => Bool;
KnownAt(s, o) == o \in s.out \/ jCre[o] > 0
\* @type: ($snapshot, Str) => Bool;
TakenAt(s, o) == \E q \in Ops : q /= o /\ Consumes(q) /\ SameValue(q, o) /\ KnownAt(s, q)
\* @type: ($snapshot, Str) => Bool;
DoubtAt(s, o) ==
  Consumes(o) /\ jEnd[o] > s.lwm /\ jVoid[o] = 0 /\ ~KnownAt(s, o) /\ ~TakenAt(s, o)
\* @type: ($snapshot) => Set(Int);
RestoredBused(s) == s.bused \cup {plan[o].val : o \in {q \in Ops : plan[q].kind = "boot" /\ jEnd[q] > s.lwm /\ jVoid[q] = 0}}
\* @type: ($snapshot) => Set(Int);
RestoredBended(s) == s.bended \cup {plan[o].val : o \in {q \in Ops : plan[q].kind = "issue" /\ jEnd[q] > s.lwm /\ jVoid[q] = 0}}
\* @type: ($snapshot) => Bool;
RestoredBootHeld(s) == \E v \in s.bvals : v \in RestoredBused(s) /\ v \notin RestoredBended(s)

\* Account a keeps a sign-in method through a restore from s and the
\* reconciliation after it: an anchor is live in the restored store, or an
\* in-doubt recovery of a whose new anchor a restore does not end.
\* @type: ($snapshot, Str) => Bool;
AccountRestorable(s, a) ==
  \/ \E x \in Anc(a) : RestoredAnc(s, x) = "live"
  \/ \E o \in Ops :
       /\ DoubtAt(s, o) /\ plan[o].kind = "recover" /\ plan[o].own = a
       /\ RestoredAnc(s, plan[o].make) /= "ended"
\* @type: ($snapshot) => Bool;
AdminRestorable(s) ==
  RestoredBootHeld(s) =>
    \/ \E x \in Adms : RestoredAnc(s, x) = "live"
    \/ \E o \in Ops :
         /\ DoubtAt(s, o) /\ plan[o].kind = "boot"
         /\ plan[o].val \in s.bvals /\ plan[o].val \notin RestoredBended(s)
         /\ RestoredAnc(s, plan[o].make) /= "ended"
\* Only an unlink ends an administrator binding, and it keeps one that the
\* journal records as live: a restore that makes an administrator keeps one.
\* @type: ($snapshot) => Bool;
AdminChain(s) ==
  (\E x \in Adms : RestoreMakes(s, x)) => \E x \in Adms : RestoredAnc(s, x) = "live"
\* @type: ($snapshot) => Bool;
Restorable(s) == AdminRestorable(s) /\ AdminChain(s) /\ \A a \in Accounts : AccountRestorable(s, a)

\* The same for the current store and its in-doubt consumptions.
AccountKeptNow(a) ==
  \/ \E x \in Anc(a) : anc[x] = "live"
  \/ \E o \in pend : plan[o].kind = "recover" /\ plan[o].own = a /\ anc[plan[o].make] /= "ended"
AdminKeptNow ==
  BootHeld =>
    \/ AdminLive
    \/ \E o \in pend :
         /\ plan[o].kind = "boot" /\ plan[o].val \in bvals /\ plan[o].val \notin bended
         /\ anc[plan[o].make] /= "ended"

\* A snapshot that the serving store could take now.
SnapNow == [Now EXCEPT !.lwm = LowWater]

\* The owner's turn (Turn = "creation"): the holder is the one operation of
\* its owner between its check and the end of its turn, and the turn
\* protects what its check read.
TurnInv ==
  /\ \A a \in Owners : lock[a] /= "none" =>
       /\ phase = "up" /\ plan[lock[a]].own = a
       /\ \/ pc[lock[a]] = "checked"
          \/ plan[lock[a]].make /= "" /\ pc[lock[a]] \in {"journaled", "committed"}
  /\ \A o \in Ops : plan[o].own /= "" /\ pc[o] = "checked" => lock[plan[o].own] = o
  \* Each other operation of the owner ended its turn before the holder's
  \* check, so each of its entries comes before the holder's end entry.
  /\ \A o, q \in Ops :
       /\ plan[o].own /= "" /\ lock[plan[o].own] = o /\ jEnd[o] > 0
       /\ q /= o /\ plan[q].own = plan[o].own
       => jEnd[q] < jEnd[o] /\ jCre[q] < jEnd[o]
  /\ \A o \in Ops :
       Turn = "creation" /\ plan[o].own /= "" /\ plan[o].make /= ""
       /\ pc[o] \in {"journaled", "committed"} => lock[plan[o].own] = o
  \* An unlink keeps an anchor that the journal records as live, and its
  \* creation stays journaled while the unlink's end entry counts.
  /\ \A o \in Ops : plan[o].kind = "unlink" /\ pc[o] = "checked" => Journaled(plan[o].keep)
  /\ \A o, q \in Ops :
       /\ plan[o].kind = "unlink" /\ jEnd[o] > 0 /\ jVoid[o] = 0
       /\ plan[q].kill = plan[o].keep /\ jEnd[q] > 0 /\ jVoid[q] = 0
       => jEnd[q] > jEnd[o]
  /\ \A o \in Ops :
       plan[o].kind = "unlink" /\ jEnd[o] > 0 /\ jVoid[o] = 0 => JournalMade(plan[o].keep)
  \* A consumption in its turn: no other consumption of its value counts, and
  \* its new anchor has no entry and is live exactly after its commit.
  /\ \A o \in Ops :
       Turn = "creation" /\ Consumes(o) /\ pc[o] \in {"checked", "journaled", "committed"} =>
         /\ \A q \in Ops \ {o} : SameValue(q, o) => q \notin committed /\ (jEnd[q] = 0 \/ jVoid[q] > 0)
         /\ ~JournalMade(plan[o].make) /\ ~JournalEnded(plan[o].make)
         /\ anc[plan[o].make] = IF pc[o] = "committed" THEN "live" ELSE "absent"

\* Anchor states. An anchor that the journal records as made or as ended,
\* or that an operation in flight ends, is never absent. An ended anchor was
\* ended by a commit or by an in-doubt entry, in the store and in each
\* snapshot. Each acknowledgement, and each commit in flight, has its outcome
\* record.
AnchorStateInv ==
  /\ \A x \in InitLive : anc[x] /= "absent" /\ \A s \in snaps : s.anc[x] /= "absent"
  /\ \A x \in Anchors : JournalMade(x) \/ JournalEnded(x) => anc[x] /= "absent"
  /\ \A o \in Ops : pc[o] \in InFlight /\ plan[o].kill \in Anchors => anc[plan[o].kill] /= "absent"
  /\ \A x \in Anchors : anc[x] = "ended" => x \in EndedAnchors \/ Uncertain(x)
  /\ \A s \in snaps : \A x \in Anchors : s.anc[x] = "ended" => anc[x] = "ended"
  /\ \A o \in Ops : pc[o] = "acked" => o \in committed
  /\ \A o \in Ops : pc[o] \in {"committed", "created"} => o \in out
  \* An operation that stopped at its check wrote no entry, and each entry of
  \* an operation in flight comes after each entry of a crashed operation.
  /\ \A o \in Ops : pc[o] \in {"checked", "cChecked"} => jEnd[o] = 0 /\ jCre[o] = 0 /\ jVoid[o] = 0
  /\ \A o, q \in Ops :
       pc[o] \in InFlight /\ pc[q] \in Crashed =>
         \A e \in {jEnd[o], jCre[o]} : e > 0 => e > jEnd[q] /\ e > jCre[q] /\ e > jVoid[q]

\* Promises. Each promised anchor has a journaled creation. Each live
\* anchor, and each anchor that an outcome record left, has one, or a
\* recorded commit made it and its creation entry is still due; while the
\* store serves, that commit is in flight. An operation with no outcome
\* record left no anchor.
PromiseInv ==
  /\ \A o \in Ops : left[o] \subseteq Anc(plan[o].own)
  /\ \A x \in Promised : JournalMade(x)
  /\ \A x \in Anchors : anc[x] = "live" => JournalMade(x) \/ \E q \in out : CreationDue(q, x)
  /\ \A s \in snaps : \A x \in Anchors :
       s.anc[x] = "live" => JournalMade(x) \/ \E q \in s.out : CreationDue(q, x)
  /\ phase = "up" => \A q \in out : plan[q].make /= "" /\ jCre[q] = 0 => pc[q] = "committed"
  /\ \A o \in out : \A x \in left[o] : JournalMade(x) \/ \E q \in out : CreationDue(q, x)
  /\ \A s \in snaps : \A o \in s.out : \A x \in s.left[o] :
       JournalMade(x) \/ \E q \in s.out : CreationDue(q, x)
  /\ \A o \in Ops : o \notin out => left[o] = {}
  /\ \A s \in snaps : \A o \in Ops :
       /\ s.left[o] \subseteq Anc(plan[o].own)
       /\ o \notin s.out => s.left[o] = {}

KeptNowInv == AdminKeptNow /\ \A a \in Accounts : AccountKeptNow(a)

\* A snapshot is a copy of a serving store: each account has a live anchor,
\* and the authority an administrator while it holds a consumed value.
\* @type: ($snapshot) => Bool;
ServingCopy(s) ==
  /\ \A a \in Accounts : \E x \in Anc(a) : s.anc[x] = "live"
  /\ (\E v \in s.bvals : v \in s.bused /\ v \notin s.bended) => \E x \in Adms : s.anc[x] = "live"
\* While the store serves, reconciliation has voided each entry of a crashed
\* operation whose fact did not hold, and facts only grow.
ServingInv ==
  /\ \A s \in snaps : ServingCopy(s)
  /\ phase = "up" => \A o \in Ops : pc[o] \in Crashed /\ jEnd[o] > 0 /\ jVoid[o] = 0 => EndHolds(o)
RestoreAccountInv == \A s \in snaps : \A a \in Accounts : AccountRestorable(s, a)
RestoreAdminInv == \A s \in snaps : AdminRestorable(s) /\ AdminChain(s)
RestoreNowAccountInv == phase = "up" => \A a \in Accounts : AccountRestorable(SnapNow, a)
RestoreNowAdminInv == phase = "up" => AdminRestorable(SnapNow) /\ AdminChain(SnapNow)

IndInv ==
  /\ TypeInd
  /\ JournalInv
  /\ EndInv
  /\ OutcomeInv
  /\ DoubtInv
  /\ AnchorInv
  /\ BootInv
  /\ CounterInv
  /\ AnchorStateInv
  /\ PromiseInv
  /\ KeptNowInv
  /\ RestoreAccountInv
  /\ RestoreAdminInv
  /\ RestoreNowAccountInv
  /\ RestoreNowAdminInv
  /\ TurnInv
  /\ ServingInv

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
  /\ AnchorKept
  /\ AccountKeepsAnchorP
  /\ AdminKeptP

\* The starting set of the step checks: every state of IndInv at the domains
\* of the run. Each function has the fixed domain of its variable, each value
\* in it is free, and each snapshot is one record of its own fields; n bounds
\* each set of bootstrap values (README.md, Inductive proofs). The snapshot
\* set is one choice, so that the start has one transition.
IndStart(n) ==
  /\ \E fa, fb, fc \in [Anchors -> AncStates], la, lb, lc \in [Ops -> SUBSET Anchors],
        oa, ob, oc \in SUBSET Ops, ia, ib, ic \in [{"cur", "dead", "ctr", "lwm"} -> Int],
        ra, rb, rc \in BOOLEAN :
       LET \* @type: $snapshot;
           SA == [anc |-> fa, bvals |-> Gen(n), bused |-> Gen(n), bended |-> Gen(n),
                  cur |-> ia["cur"], dead |-> ia["dead"], revoked |-> ra, ctr |-> ia["ctr"],
                  out |-> oa, left |-> la, lwm |-> ia["lwm"]]
           \* @type: $snapshot;
           SB == [anc |-> fb, bvals |-> Gen(n), bused |-> Gen(n), bended |-> Gen(n),
                  cur |-> ib["cur"], dead |-> ib["dead"], revoked |-> rb, ctr |-> ib["ctr"],
                  out |-> ob, left |-> lb, lwm |-> ib["lwm"]]
           \* @type: $snapshot;
           SC == [anc |-> fc, bvals |-> Gen(n), bused |-> Gen(n), bended |-> Gen(n),
                  cur |-> ic["cur"], dead |-> ic["dead"], revoked |-> rc, ctr |-> ic["ctr"],
                  out |-> oc, left |-> lc, lwm |-> ic["lwm"]]
       IN snaps \in {{}, {SA}, {SA, SB}} \cup (IF NSnaps = 3 THEN {{SA, SB, SC}} ELSE {})
  /\ \E pk \in [Ops -> Kinds], po \in [Ops -> Owners \cup {""}], pi \in [Ops -> Items],
        pe \in [Ops -> Anchors \cup {""}], pm \in [Ops -> Anchors \cup {""}], pv \in [Ops -> Int] :
       plan = [o \in Ops |-> [kind |-> pk[o], own |-> po[o], kill |-> pi[o], keep |-> pe[o],
                              make |-> pm[o], val |-> pv[o]]]
  /\ \E g \in [Ops -> Int] : art = g
  /\ \E g \in [Ops -> Int] : jEnd = g
  /\ \E g \in [Ops -> Int] : jCre = g
  /\ \E g \in [Ops -> Int] : jVoid = g
  /\ bvals = Gen(n)
  /\ bused = Gen(n)
  /\ bended = Gen(n)
  /\ \E v \in Int : cur = v
  /\ \E v \in Int : dead = v
  /\ \E v \in Int : ctr = v
  /\ \E v \in Int : jhead = v
  /\ \E v \in Int : jfloor = v
  /\ \E v \in Int : bnext = v
  /\ phase \in {"up", "down", "rec"}
  /\ restored \in BOOLEAN
  /\ revoked \in BOOLEAN
  /\ \E g \in [Anchors -> AncStates] : anc = g
  /\ \E g \in [Ops -> PcValues] : pc = g
  /\ \E g \in [Owners -> Ops \cup {"none"}] : lock = g
  /\ \E g \in [Ops -> SUBSET Anchors] : left = g
  /\ \E so, sp, sc \in SUBSET Ops, pr \in SUBSET Anchors :
       out = so /\ pend = sp /\ committed = sc /\ promised = pr
  /\ IndInv

IndInit == IndStart(3)

\* The parts of the step check: one action each, so that each Apalache run
\* has one transition, or two for the two outcomes of Conflict. By the
\* definitions of Start, NextRun, NextEnd, NextRec, NextAgain, and NextSys,
\* these twenty-three parts together are Next:
\*   NextRun = NextEnroll \/ NextUnlink \/ NextRecover \/ NextBoot
\*             \/ NextRenew \/ NextRevoke \/ NextIssueEnd \/ NextIssueNone
\*             \/ NextJournal \/ NextCommit \/ NextConflict
\*   NextEnd = NextCreate \/ NextAck \/ NextResolve
\*   NextRec = NextRecCreate \/ NextRecVoid
\*   NextAgain = NextRedrive \/ NextRedriveFail
\*   NextSys = NextCrash \/ NextRestart \/ NextServe \/ NextSnapshot
\* and NextRestore.
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
NextCreate == \E o \in Ops : JournalCreate(o)
NextAck == \E o \in Ops : Ack(o)
NextResolve == \E o \in Ops : Resolve(o)
NextRecCreate == \E o \in Ops : ReconcileCreate(o)
NextRecVoid == \E o \in Ops : ReconcileVoid(o)
NextRedrive == \E o \in Ops : Redrive(o)
NextRedriveFail == \E o \in Ops : RedriveFail(o)
NextCrash == Crash
NextRestart == Restart
NextServe == Serve
NextSnapshot == Snapshot

\* The step check: each part of IndInv after one step, as an action
\* invariant. Each step part has four profiles, so that each run fits the time
\* budget (README.md, Inductive proofs): `Step<Part>Base` checks the eight
\* parts of A000, `Step<Part>Anchor` the five other parts of the anchor
\* properties, `Step<Part>Restore` the two restore parts for each retained
\* snapshot, and `Step<Part>RestoreNow` the two for a snapshot taken now.
TypeIndPost == TypeInd'
JournalInvPost == JournalInv'
EndInvPost == EndInv'
OutcomeInvPost == OutcomeInv'
DoubtInvPost == DoubtInv'
AnchorInvPost == AnchorInv'
BootInvPost == BootInv'
CounterInvPost == CounterInv'
AnchorStateInvPost == AnchorStateInv'
PromiseInvPost == PromiseInv'
KeptNowInvPost == KeptNowInv'
RestoreAccountInvPost == RestoreAccountInv'
RestoreAdminInvPost == RestoreAdminInv'
RestoreNowAccountInvPost == RestoreNowAccountInv'
RestoreNowAdminInvPost == RestoreNowAdminInv'
TurnInvPost == TurnInv'
ServingInvPost == ServingInv'

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

\* Vacuity witnesses of the anchor clauses. Each `_reach` profile checks one
\* of these at length 0, so the checker shows an IndInit state with the case.
\* A promise of an anchor that a commit created.
NoMadePromise == ~\E x \in Promised : x \notin InitLive
\* A recorded outcome that left an anchor whose creation entry is still due.
NoCreationDue == ~\E o, q \in out : o /= q /\ \E x \in left[o] : CreationDue(q, x)
\* An account that a restore from a snapshot keeps only through an in-doubt
\* recovery.
NoDoubtKeeps == ~\E s \in snaps : \E a \in Accounts : \A x \in Anc(a) : RestoredAnc(s, x) /= "live"
\* An authority that a restore keeps only through an in-doubt bootstrap.
NoDoubtAdmin == ~\E s \in snaps : RestoredBootHeld(s) /\ \A x \in Adms : RestoredAnc(s, x) /= "live"
\* An ended anchor that only an in-doubt end entry accounts for.
NoUncertainEnded == ~\E x \in Anchors : anc[x] = "ended" /\ x \notin EndedAnchors
\* During reconciliation, an account that only an in-doubt recovery keeps.
NoPendKeeps == ~\E a \in Accounts : \A x \in Anc(a) : anc[x] /= "live"
\* A serving store that a snapshot taken now keeps only through an in-doubt
\* recovery.
NoDoubtKeepsNow ==
  ~(phase = "up" /\ \E a \in Accounts : \A x \in Anc(a) : RestoredAnc(SnapNow, x) /= "live")
\* A consumption that committed and still holds its owner's turn.
NoTurnHeld ==
  ~\E o \in Ops : Consumes(o) /\ pc[o] = "committed" /\ lock[plan[o].own] = o
\* A serving store with a crashed operation that did not commit and whose end
\* entry holds.
NoCrashedHolds ==
  ~(phase = "up" /\ \E o \in Ops :
      pc[o] \in Crashed /\ o \notin committed /\ jEnd[o] > 0 /\ jVoid[o] = 0)
=============================================================================
