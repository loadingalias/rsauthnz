------------------------- MODULE AuthorityInvariant -------------------------
(***************************************************************************)
(* The inductive invariant of Authority.tla. It proves every property in   *)
(* Safety, the anchor properties AnchorKept, AccountKeepsAnchorP, and      *)
(* AdminKeptP included, for histories of any length at the declared        *)
(* domains, for both origins, with counter values, journal sequences, and  *)
(* bootstrap values in the proved finite issue domain. An operation identity *)
(* commits through Commit once, and a snapshot is never removed, so "any   *)
(* length" means any number of crashes, restarts, restores, and            *)
(* reconciliation steps over the domains of the run (README.md, Inductive  *)
(* proofs). Apalache checks (README.md, Profiles):                         *)
(*   Init => IndInv                          (AuthorityInd.Init)           *)
(*   IndInv /\ Next => IndInv'              (AuthorityInd.Step)           *)
(*   IndInv => Safety                        (AuthorityInd.Safety)         *)
(* The length-one checks cover every Next action and IndInv component.   *)
(* IndInit is exactly IndInv in its domains. Selected conjuncts broaden   *)
(* some preservation starts, so they still include every invariant state. *)
(* The `_reach` witnesses show that IndInit contains representative states the   *)
(* steps must cover.                                                       *)
(***************************************************************************)
EXTENDS Authority

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
  /\ p.retire \subseteq SignIns
  /\ p.kind /= "recover" => p.retire = {}
  /\ CASE p.kind = "" -> p = NoPlan
    [] p.kind = "enroll" ->
         p.make \in Anchors \ Adms /\ p.own = Owner(p.make) /\ p.kill = "" /\ p.keep = ""
         /\ p.val = 0
    [] p.kind = "unlink" ->
         /\ p.kill \in Anchors /\ p.keep \in Anchors \ Recoveries /\ p.kill /= p.keep /\ p.make = ""
         /\ p.own = Owner(p.kill) /\ Owner(p.keep) = p.own /\ p.val = 0
    [] p.kind = "recover" ->
         /\ p.kill \in Recoveries /\ p.make \in SignIns /\ p.keep = ""
         /\ p.kill /= p.make /\ p.own = Owner(p.kill) /\ Owner(p.make) = p.own /\ p.val = 0
         /\ p.retire \subseteq Anc(p.own) /\ p.make \notin p.retire
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
  /\ bnext = 1 + Cardinality({o \in committed : plan[o].kind = "issue"})
  /\ \A v \in bvals \cup bused \cup bended : IsVal(v)
  /\ DOMAIN snaps = SnapIds /\ nSnaps \in 0..NSnaps
  /\ committed \subseteq Ops
  /\ DOMAIN left = Ops /\ \A o \in Ops : left[o] \subseteq Anchors
  /\ promised \subseteq Anchors
  /\ \A o \in Ops : PlanOK(plan[o])
  /\ \A o \in Ops :
       /\ 0 <= jEnd[o] /\ jEnd[o] <= jhead /\ 0 <= jCre[o] /\ jCre[o] <= jhead
       /\ 0 <= jVoid[o] /\ jVoid[o] <= jhead
  /\ \A i \in SnapIds : SnapTypeOK(snaps[i])

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
SnapshotEnds ==
  \A i \in ActiveSnaps : LET s == snaps[i] IN \A o \in Ops :
    0 < jEnd[o] /\ jEnd[o] <= s.lwm => EndHoldsIn(o, s) \/ jVoid[o] > 0

EndInv ==
  /\ \A o \in committed :
       /\ jVoid[o] = 0
       /\ plan[o].kill /= "" => jEnd[o] > 0 /\ EndHolds(o)
  /\ SnapshotEnds
  /\ \A i \in ActiveSnaps : LET s == snaps[i] IN \A o \in s.out : plan[o].kill /= "" => EndHoldsIn(o, s)

\* MissingOutcomeUnknown: an outcome record, in the store or in a snapshot,
\* is a commit, and before the first restore each commit has its record.
OutcomeInv ==
  /\ ~restored => committed \subseteq out
  /\ out \subseteq committed
  /\ \A i \in ActiveSnaps : LET s == snaps[i] IN s.out \subseteq committed

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
  /\ \A i \in ActiveSnaps : LET s == snaps[i] IN
       \A o, q \in s.out : o /= q /\ Consumes(o) /\ Consumes(q) => ~SameValue(o, q)

\* NoUncommittedAnchor, and the anchors that commits created: an anchor of
\* an outcome record is never absent, and a creation entry at or below a
\* snapshot's low-water mark is reflected in that snapshot.
AnchorInv ==
  /\ NoUncommittedAnchor
  /\ \A o \in out : plan[o].make /= "" => anc[plan[o].make] /= "absent"
  /\ \A i \in ActiveSnaps : LET s == snaps[i] IN
       /\ \A x \in Anchors :
            s.anc[x] = "live" => x \in InitLive \/ \E o \in committed : plan[o].make = x
       /\ \A o \in s.out : plan[o].make /= "" => s.anc[plan[o].make] /= "absent"
       /\ \A o \in Ops :
            0 < jCre[o] /\ jCre[o] <= s.lwm /\ jVoid[o] = 0 => s.anc[plan[o].make] /= "absent"

\* OneBootValid: at most one bootstrap value is valid, in the store and in
\* each snapshot. A restore keeps only the values of its snapshot.
BootInv ==
  /\ OneBootValid
  /\ \A i \in ActiveSnaps : LET s == snaps[i] IN
       \A v, w \in s.bvals :
         v \notin s.bused /\ v \notin s.bended /\ w \notin s.bused /\ w \notin s.bended => v = w

\* NoCounterReuse: each artifact value is above the initial value, at or
\* below the counter and the durable floor, and unique.
CounterInv ==
  /\ ctr >= 1
  /\ \A i \in ActiveSnaps : LET s == snaps[i] IN s.ctr >= 1
  /\ \A o \in Ops : art[o] = 0 \/ (2 <= art[o] /\ art[o] <= ctr /\ art[o] <= jfloor)
  /\ \A o, q \in Ops : o /= q /\ art[o] > 0 /\ art[q] > 0 => art[o] /= art[q]

\* The anchor properties. A restore from a snapshot s makes each anchor what
\* the snapshot holds, with each entry after its low-water mark that no void
\* cancels; the restore predicates describe that state. A restore keeps an
\* anchor that the journal records as made and as not ended (Journaled), so each promise and
\* each account's last anchor rest on the journal (README.md, Inductive
\* proofs).
\* An anchor that the journal records as made: live at the start, or with a
\* creation entry. Creation entries are never voided.
JournalMade(x) == x \in InitLive \/ \E o \in Ops : plan[o].make = x /\ jCre[o] > 0
\* An end entry of x that no void cancels.
JournalEnded(x) == \E o \in Ops : Ends(plan[o], x) /\ jEnd[o] > 0 /\ jVoid[o] = 0
\* A commit of q made x, and its creation entry is still to come.
CreationDue(q, x) == plan[q].make = x /\ jCre[q] = 0

\* Compare with each conditional candidate of Unreflected, without its
\* numeric Min. No bound on n or on a journal sequence is used here.
\* @type: (Str, Int) => Bool;
UnreflectedAtMost(o, n) ==
  IF Bad = "ownMark" /\ plan[o].own \in Accounts \ {"a1"}
  THEN jhead < n
  ELSE
    \/ IF jEnd[o] > 0 /\ ~EndHolds(o) /\ jVoid[o] = 0
       THEN jEnd[o] <= n ELSE jhead < n
    \/ IF jCre[o] > 0 /\ jVoid[o] = 0 /\ anc[plan[o].make] = "absent"
       THEN jCre[o] <= n ELSE jhead < n

\* n > LowWater iff at least one of the original integer candidates is at
\* most n. The fourth, absent operation contributes jhead + 1 only when
\* o4 is absent. Both initial origins and each declared or raised domain
\* use exactly these three or four operation identities.
\* @type: (Int) => Bool;
AboveNow(n) ==
  \/ \E o \in Ops : UnreflectedAtMost(o, n)
  \/ "o4" \notin Ops /\ jhead < n

\* What a restore from s gives. After selects entries after its cutoff:
\* n > s.lwm for a retained snapshot, or AboveNow(n) for the current store.
\* One Boolean algorithm covers both; it constructs no restored value sets
\* or anchor-state strings only to test membership or equality afterward.
\* @type: ($snapshot, (Int) => Bool, Str) => Bool;
RestoreEnds(s, After(_), x) ==
  s.anc[x] = "ended" \/ \E o \in Ops : Ends(plan[o], x) /\ After(jEnd[o]) /\ jVoid[o] = 0
\* @type: ($snapshot, (Int) => Bool, Str) => Bool;
RestoreMakes(s, After(_), x) ==
  s.anc[x] = "live" \/ \E o \in Ops : plan[o].make = x /\ After(jCre[o]) /\ jVoid[o] = 0
\* @type: ($snapshot, (Int) => Bool, Str) => Bool;
RestoreLive(s, After(_), x) == ~RestoreEnds(s, After, x) /\ RestoreMakes(s, After, x)
\* @type: ($snapshot, Str) => Bool;
KnownAt(s, o) == o \in s.out \/ jCre[o] > 0
\* @type: ($snapshot, Str) => Bool;
TakenAt(s, o) == \E q \in Ops : q /= o /\ Consumes(q) /\ SameValue(q, o) /\ KnownAt(s, q)
\* @type: ($snapshot, (Int) => Bool, Str) => Bool;
DoubtAt(s, After(_), o) ==
  Consumes(o) /\ After(jEnd[o]) /\ jVoid[o] = 0 /\ ~KnownAt(s, o) /\ ~TakenAt(s, o)
\* @type: ($snapshot, (Int) => Bool, Int) => Bool;
RestoreBootUsed(s, After(_), v) ==
  v \in s.bused \/ \E o \in Ops :
    plan[o].kind = "boot" /\ After(jEnd[o]) /\ jVoid[o] = 0 /\ plan[o].val = v
\* @type: ($snapshot, (Int) => Bool, Int) => Bool;
RestoreBootEnded(s, After(_), v) ==
  v \in s.bended \/ \E o \in Ops :
    plan[o].kind = "issue" /\ After(jEnd[o]) /\ jVoid[o] = 0 /\ plan[o].val = v
\* @type: ($snapshot, (Int) => Bool) => Bool;
RestoredBootHeld(s, After(_)) ==
  \E v \in s.bvals : RestoreBootUsed(s, After, v) /\ ~RestoreBootEnded(s, After, v)

\* Account a keeps a sign-in method through a restore from s and its
\* reconciliation: one remains live, or a pending recovery replaces the
\* displaced methods that its end entry retired.
\* @type: ($snapshot, (Int) => Bool, Str) => Bool;
AccountRestorable(s, After(_), a) ==
  \/ \E x \in Protected(a) : RestoreLive(s, After, x)
  \/ \E o \in Ops :
       /\ DoubtAt(s, After, o) /\ plan[o].kind = "recover" /\ plan[o].own = a
       /\ ~RestoreEnds(s, After, plan[o].make)
\* @type: ($snapshot, (Int) => Bool) => Bool;
AdminRestorable(s, After(_)) ==
  RestoredBootHeld(s, After) =>
    \/ \E x \in Adms : RestoreLive(s, After, x)
    \/ \E o \in Ops :
         /\ DoubtAt(s, After, o) /\ plan[o].kind = "boot"
         /\ plan[o].val \in s.bvals /\ ~RestoreBootEnded(s, After, plan[o].val)
         /\ ~RestoreEnds(s, After, plan[o].make)
\* Only an unlink ends an administrator binding, and it keeps one that the
\* journal records as live: a restore that makes an administrator keeps one.
\* @type: ($snapshot, (Int) => Bool) => Bool;
AdminChain(s, After(_)) ==
  (\E x \in Adms : RestoreMakes(s, After, x)) => \E x \in Adms : RestoreLive(s, After, x)

\* The same for the current store and its in-doubt consumptions.
AccountKeptNow(a) ==
  \/ \E x \in Protected(a) : anc[x] = "live"
  \/ \E o \in pend : plan[o].kind = "recover" /\ plan[o].own = a /\ anc[plan[o].make] /= "ended"
AdminKeptNow ==
  BootHeld =>
    \/ AdminLive
    \/ \E o \in pend :
         /\ plan[o].kind = "boot" /\ plan[o].val \in bvals /\ plan[o].val \notin bended
         /\ anc[plan[o].make] /= "ended"

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
       /\ Ends(plan[q], plan[o].keep) /\ jEnd[q] > 0 /\ jVoid[q] = 0
       => jEnd[q] > jEnd[o]
  /\ \A o \in Ops :
       plan[o].kind = "unlink" /\ jEnd[o] > 0 /\ jVoid[o] = 0 => JournalMade(plan[o].keep)
  \* An anchor's creation precedes each journaled end of that anchor.
  /\ \A o \in Ops : pc[o] = "checked" =>
       \A x \in Anchors : Ends(plan[o], x) => JournalMade(x)
  /\ \A o \in Ops : jEnd[o] > 0 /\ jVoid[o] = 0 =>
       \A x \in Anchors : Ends(plan[o], x) =>
         \/ x \in InitLive
         \/ \E q \in Ops : plan[q].make = x /\ 0 < jCre[q] /\ jCre[q] < jEnd[o]
  \* Serialization keeps one unvoided end entry for each consumed value.
  /\ Turn = "creation" =>
       \A o, q \in Ops :
         /\ o /= q /\ Consumes(o) /\ Consumes(q) /\ SameValue(o, q)
         /\ jEnd[o] > 0 /\ jEnd[q] > 0
         => jVoid[o] > 0 \/ jVoid[q] > 0
  \* A consumption in its turn: no other consumption of its value counts, and
  \* its new anchor has no entry and is live exactly after its commit.
  /\ \A o \in Ops :
       Turn = "creation" /\ Consumes(o) /\ pc[o] \in {"checked", "journaled", "committed"} =>
         /\ \A q \in Ops \ {o} : SameValue(q, o) => q \notin committed /\ (jEnd[q] = 0 \/ jVoid[q] > 0)
         /\ ~JournalMade(plan[o].make) /\ ~JournalEnded(plan[o].make)
         /\ anc[plan[o].make] = IF pc[o] = "committed" THEN "live" ELSE "absent"

\* Anchor states. An anchor that the journal records as made or as ended,
\* or that an operation in flight ends, is never absent. An ended anchor has
\* a committed end or the complete fact of an unvoided crashed end.
\* Each acknowledgement, and each commit in flight, has its outcome
\* record.
AnchorStateInv ==
  /\ \A x \in InitLive : anc[x] /= "absent" /\ \A i \in ActiveSnaps : LET s == snaps[i] IN s.anc[x] /= "absent"
  /\ \A x \in Anchors : JournalMade(x) \/ JournalEnded(x) => anc[x] /= "absent"
  /\ \A o \in Ops : pc[o] \in InFlight =>
       \A x \in Anchors : Ends(plan[o], x) => anc[x] /= "absent"
  \* A crashed end justifies an ended anchor only while its complete fact holds.
  /\ \A x \in Anchors : anc[x] = "ended" =>
       \/ x \in EndedAnchors
       \/ \E o \in Ops :
            /\ Ends(plan[o], x) /\ jEnd[o] > 0 /\ jVoid[o] = 0
            /\ pc[o] \in Crashed /\ o \notin committed /\ EndHolds(o)
  /\ \A i \in ActiveSnaps : LET s == snaps[i] IN \A x \in Anchors : s.anc[x] = "ended" => anc[x] = "ended"
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
  /\ \A i \in ActiveSnaps : LET s == snaps[i] IN \A x \in Anchors :
       s.anc[x] = "live" => JournalMade(x) \/ \E q \in s.out : CreationDue(q, x)
  /\ phase = "up" => \A q \in out : plan[q].make /= "" /\ jCre[q] = 0 => pc[q] = "committed"
  /\ \A o \in out : \A x \in left[o] : JournalMade(x) \/ \E q \in out : CreationDue(q, x)
  /\ \A i \in ActiveSnaps : LET s == snaps[i] IN \A o \in s.out : \A x \in s.left[o] :
       JournalMade(x) \/ \E q \in s.out : CreationDue(q, x)
  /\ \A o \in Ops : o \notin out => left[o] = {}
  /\ \A i \in ActiveSnaps : LET s == snaps[i] IN \A o \in Ops :
       /\ s.left[o] \subseteq Anc(plan[o].own)
       /\ o \notin s.out => s.left[o] = {}

KeptNowInv == AdminKeptNow /\ \A a \in Accounts : AccountKeptNow(a)

\* A snapshot is a copy of a serving store: each account has a live anchor,
\* and the authority an administrator while it holds a consumed value.
\* @type: ($snapshot) => Bool;
ServingCopy(s) ==
  /\ \A a \in Accounts : \E x \in Protected(a) : s.anc[x] = "live"
  /\ (\E v \in s.bvals : v \in s.bused /\ v \notin s.bended) => \E x \in Adms : s.anc[x] = "live"
\* While the store serves, reconciliation has voided each entry of a crashed
\* operation whose fact did not hold, and facts only grow.
ServingInv ==
  /\ \A i \in ActiveSnaps : LET s == snaps[i] IN ServingCopy(s)
  /\ phase = "up" => \A o \in Ops : pc[o] \in Crashed /\ jEnd[o] > 0 /\ jVoid[o] = 0 => EndHolds(o)
RestoreAccountInv ==
  \A i \in ActiveSnaps :
    LET s == snaps[i]
        \* @type: (Int) => Bool;
        After(n) == n > s.lwm
    IN \A a \in Accounts : AccountRestorable(s, After, a)
RestoreAdminInv ==
  \A i \in ActiveSnaps :
    LET s == snaps[i]
        \* @type: (Int) => Bool;
        After(n) == n > s.lwm
    IN AdminRestorable(s, After) /\ AdminChain(s, After)
RestoreNowAccountInv == phase = "up" => \A a \in Accounts : AccountRestorable(Now, AboveNow, a)
RestoreNowAdminInv == phase = "up" => AdminRestorable(Now, AboveNow) /\ AdminChain(Now, AboveNow)

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
\* in it is free, and each snapshot is one record of its own fields.
\* TypeInd bounds bnext by one plus the issue commits, so BootIds contains
\* every bootstrap value of IndInv. Each set is an arbitrary subset of that
\* domain; TypeInd and SnapTypeOK constrain its members to 1..bnext.
\* Each fixed snapshot slot is an arbitrary record, and nSnaps selects the
\* retained prefix. Every set of at most NSnaps snapshots has such an
\* enumeration. Duplicate slots are permitted in the invariant starting set;
\* reachable states have none because Snapshot coalesces duplicate captures.
\* The inactive slots have only SnapTypeOK and do not affect any transition.
BootIds == 1..(1 + Cardinality(Ops))

\* @type: (Bool) => Bool;
IndStartWith(assumptions) ==
  /\ \E fa, fb, fc \in [Anchors -> AncStates], la, lb, lc \in [Ops -> SUBSET Anchors],
        oa, ob, oc \in SUBSET Ops, ia, ib, ic \in [{"cur", "dead", "ctr", "lwm"} -> Int],
        ra, rb, rc \in BOOLEAN,
        va, ua, ea, vb, ub, eb, vc, uc, ec \in SUBSET BootIds :
       LET \* @type: $snapshot;
           SA == [anc |-> fa, bvals |-> va, bused |-> ua, bended |-> ea,
                  cur |-> ia["cur"], dead |-> ia["dead"], revoked |-> ra, ctr |-> ia["ctr"],
                  out |-> oa, left |-> la, lwm |-> ia["lwm"]]
           \* @type: $snapshot;
           SB == [anc |-> fb, bvals |-> vb, bused |-> ub, bended |-> eb,
                  cur |-> ib["cur"], dead |-> ib["dead"], revoked |-> rb, ctr |-> ib["ctr"],
                  out |-> ob, left |-> lb, lwm |-> ib["lwm"]]
           \* @type: $snapshot;
           SC == [anc |-> fc, bvals |-> vc, bused |-> uc, bended |-> ec,
                  cur |-> ic["cur"], dead |-> ic["dead"], revoked |-> rc, ctr |-> ic["ctr"],
                  out |-> oc, left |-> lc, lwm |-> ic["lwm"]]
       IN snaps = [i \in SnapIds |-> CASE i = 1 -> SA [] i = 2 -> SB [] OTHER -> SC]
  /\ nSnaps \in 0..NSnaps
  /\ \E pk \in [Ops -> Kinds], po \in [Ops -> Owners \cup {""}], pi \in [Ops -> Items],
        pe \in [Ops -> Anchors \cup {""}], pm \in [Ops -> Anchors \cup {""}], pv \in [Ops -> Int],
        pd \in [Ops -> SUBSET SignIns] :
       plan = [o \in Ops |-> [kind |-> pk[o], own |-> po[o], kill |-> pi[o], keep |-> pe[o],
                              make |-> pm[o], val |-> pv[o], retire |-> pd[o]]]
  /\ \E g \in [Ops -> Int] : art = g
  /\ \E g \in [Ops -> Int] : jEnd = g
  /\ \E g \in [Ops -> Int] : jCre = g
  /\ \E g \in [Ops -> Int] : jVoid = g
  /\ bvals \in SUBSET BootIds
  /\ bused \in SUBSET BootIds
  /\ bended \in SUBSET BootIds
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
  /\ assumptions

IndStart == IndStartWith(IndInv)

IndInit == IndStart

\* A redrive removes one pending consumption and can add at most 2*|Ops|
\* reconciliation needs. Each other recovery step removes a need or serves.
RecoveryWeight == 2 * Cardinality(Ops) + 1
RecoveryRank ==
  IF phase = "up" THEN 0
  ELSE IF phase = "down" THEN RecoveryWeight * (Cardinality(Ops) + 1) + 1
  ELSE 1 + RecoveryWeight * Cardinality(pend)
         + Cardinality({o \in Ops : NeedsCreate(o)})
         + Cardinality({o \in Ops : NeedsVoid(o)})
\* These are exactly the guards of Restart, Serve, and the four recovery actions.
RecoveryReady ==
  phase /= "up" =>
    \/ phase = "down"
    \/ /\ phase = "rec"
       /\ (\E o \in Ops : NeedsCreate(o) \/ NeedsVoid(o))
           \/ (\E q \in pend : First(q)) \/ pend = {}
RecoveryDecreases == RecoveryRank' < RecoveryRank

\* Vacuity witnesses. Each `_reach` profile checks one of these at length 0,
\* so the checker shows an IndInit state with the key state.
\* A snapshot from which a restore puts a consumption in doubt.
NoDoubtSnapshot ==
  ~\E i \in ActiveSnaps : LET s == snaps[i] IN \E o \in Ops :
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
  ~\E i \in ActiveSnaps : LET s == snaps[i] IN \E o \in Ops :
     /\ phase = "down" /\ plan[o].kind = "issue" /\ plan[o].kill = "boot"
     /\ jEnd[o] > s.lwm /\ jVoid[o] = 0
     /\ plan[o].val \in s.bvals /\ plan[o].val \notin s.bused /\ plan[o].val \notin s.bended

\* Vacuity witnesses of the anchor clauses. Each `_reach` profile checks one
\* of these at length 0, so the checker shows an IndInit state with the case.
\* A promised noninitial anchor has a journaled end and a checked end.
\* The same witness exercises creation-before-end history at both stages.
NoMadePromise ==
  ~\E x \in Promised :
     /\ x \notin InitLive
     /\ \E o \in Ops : Ends(plan[o], x) /\ jEnd[o] > 0 /\ jVoid[o] = 0
     /\ \E q \in Ops : pc[q] = "checked" /\ Ends(plan[q], x)
\* A recorded outcome that left an anchor whose creation entry is still due.
NoCreationDue == ~\E o, q \in out : o /= q /\ \E x \in left[o] : CreationDue(q, x)
\* A restore consumes a recovery value and retires the last displaced
\* sign-in method. The account needs the pending recovery's new method.
NoDoubtKeeps ==
  ~\E i \in ActiveSnaps :
    LET s == snaps[i]
        \* @type: (Int) => Bool;
        After(n) == n > s.lwm
    IN \E a \in Accounts : \A x \in Protected(a) : ~RestoreLive(s, After, x)
\* An authority that a restore keeps only through an in-doubt bootstrap.
NoDoubtAdmin ==
  ~\E i \in ActiveSnaps :
    LET s == snaps[i]
        \* @type: (Int) => Bool;
        After(n) == n > s.lwm
    IN RestoredBootHeld(s, After) /\ \A x \in Adms : ~RestoreLive(s, After, x)
\* An ended anchor that only an in-doubt end entry accounts for.
NoUncertainEnded == ~\E x \in Anchors : anc[x] = "ended" /\ x \notin EndedAnchors
\* During reconciliation, an account that only a pending recovery keeps.
NoPendKeeps == ~\E a \in Accounts : \A x \in Protected(a) : anc[x] /= "live"
\* A serving store whose current snapshot would need a pending recovery to
\* replace its last displaced sign-in method.
NoDoubtKeepsNow ==
  ~(phase = "up" /\ \E a \in Accounts : \A x \in Protected(a) : ~RestoreLive(Now, AboveNow, x))
\* A consumption that committed and still holds its owner's turn.
NoTurnHeld ==
  ~\E o \in Ops : Consumes(o) /\ pc[o] = "committed" /\ lock[plan[o].own] = o
\* A serving store with a crashed operation that did not commit and whose end
\* entry holds.
NoCrashedHolds ==
  ~(phase = "up" /\ \E o \in Ops :
      pc[o] \in Crashed /\ o \notin committed /\ jEnd[o] > 0 /\ jVoid[o] = 0)
=============================================================================
