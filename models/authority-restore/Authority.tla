------------------------------ MODULE Authority ------------------------------
(***************************************************************************)
(* Authority transitions, the storage commit, the restore journal, and     *)
(* restore ([AUTH Authority Transitions], [AUTH Storage Contract and       *)
(* Bindings]). README.md maps each action to its design rule.              *)
(*                                                                         *)
(* Promise: after any sequence of crashes, restarts, and restores, nothing *)
(* that a committed transition ended is valid again, at most one bootstrap *)
(* value is valid, no counter value is issued twice, a missing outcome     *)
(* after restore is unknown, restore adds no uncommitted anchor, a refusal *)
(* stays true, and each account and the authority keep the anchors that    *)
(* acknowledged commits left them.                                         *)
(*                                                                         *)
(* The rules that were selected on 2026-11-07 (README.md, Decisions):      *)
(* - Restore completes each in-doubt consumption: a bootstrap or a         *)
(*   recovery whose consumption entry applies and whose commit is not      *)
(*   known. Before the store serves, the first in-doubt consumption of     *)
(*   each value commits again when its dependencies hold (Redrive).        *)
(* - A refusal voids the entries of its operation before it returns.       *)
(* - Reconciliation voids an entry only when its fact does not hold in the *)
(*   store.                                                                *)
(* - The allocation floor is durable before the commit that allocates a    *)
(*   value above it.                                                       *)
(* The rule that was selected on 2026-11-08: the local owner issues a new  *)
(* one-use bootstrap value (StartIssue). Its commit ends each earlier      *)
(* bootstrap value that is not consumed, with a journaled end entry. The   *)
(* value is not an anchor and has no creation entry.                       *)
(***************************************************************************)
EXTENDS Integers, FiniteSets

CONSTANTS
  \* "none" for the design, or the name of one known-bad variant.
  \* @type: Str;
  Bad,
  \* "creation" is the design's turn: an anchor creation ends its owner's
  \* turn at its creation entry. "entry" ends every turn at the first
  \* journal write, so two consumptions of one value can race.
  \* @type: Str;
  Turn,
  \* "new": the first bootstrap value is not consumed, and the authority has
  \* no administrator. "bootstrapped": the first bootstrap value is
  \* consumed, and administrator adm1 is live, so a re-bootstrap fits in the
  \* operation bound.
  \* @type: Str;
  Origin,
  \* "none" for the declared bounds, or the one bound that a raise-by-one
  \* search raises ([FP Design Models], rule 4): "accounts", "slotsA1",
  \* "slotsA2", "ops", "snaps", "ctr", or "issues" (which also adds the
  \* administrator slot that a second re-bootstrap needs); "adms" adds only
  \* that slot; "all" raises every one of them. "oneAccount" is the reduction
  \* to one account, a1, with a fourth anchor slot (a1s, absent at the start,
  \* so that a recovery or an enrollment has a slot to create into), and the
  \* administrator bindings, at the declared bounds; its known-bad variants
  \* show that it keeps their failures. Without a1s it hides the lockout F1.
  \* "opsOne" raises the operations under that reduction (README,
  \* "Reductions"; selected on 2026-11-08). A raised element starts inert: an extra operation is
  \* idle, and an extra anchor slot is absent, except the first anchor of a
  \* third account, which is live as a2p is.
  \* @type: Str;
  Raise

(* @typeAlias: plan = { kind: Str, own: Str, kill: Str, keep: Str, make: Str, val: Int }; *)
(* @typeAlias: snapshot = { anc: Str -> Str, bvals: Set(Int), bused: Set(Int), bended: Set(Int), cur: Int, dead: Int, revoked: Bool, ctr: Int, out: Set(Str), lwm: Int }; *)
Aliases == TRUE

\* The bound that this run raises by one.
Raised(b) == Raise \in {b, "all"}

\* Three operation identities (four in a raise). Each is one externally
\* submitted transition.
Ops == {"o1", "o2", "o3"} \cup (IF Raised("ops") \/ Raise = "opsOne" THEN {"o4"} ELSE {})
Rank == [o \in Ops |-> CASE o = "o1" -> 1 [] o = "o2" -> 2 [] o = "o3" -> 3 [] OTHER -> 4]

\* Two accounts and two administrator slots of the authority. Account a1
\* has three anchor slots, so that a second unlink can make the first one
\* refuse; a2 has two. Passkeys, provider links, and recovery values have
\* the same journal rules, so one anchor kind stands for all three. A raise
\* adds a third account, a fourth slot to a1, a third slot to a2, or a third
\* administrator slot.
\* The reduction to one account keeps only a1.
OneAccount == Raise \in {"oneAccount", "opsOne"}
Accounts ==
  IF OneAccount THEN {"a1"}
  ELSE {"a1", "a2"} \cup (IF Raised("accounts") THEN {"a3"} ELSE {})
Owners == Accounts \cup {"auth"}
\* Each bootstrap binds a new administrator slot, so the slots that a run can
\* reach are one more than its re-bootstraps from a new authority, and as
\* many from a bootstrapped one plus adm1. The re-bootstrap raise therefore
\* brings the third slot; a third slot alone is never reached.
Adms == {"adm1", "adm2"} \cup (IF Raised("adms") \/ Raised("issues") THEN {"adm3"} ELSE {})
Anchors ==
  {"a1p", "a1q", "a1r"} \cup (IF OneAccount THEN {} ELSE {"a2p", "a2q"}) \cup Adms
  \cup (IF Raised("slotsA1") \/ OneAccount THEN {"a1s"} ELSE {})
  \cup (IF Raised("slotsA2") THEN {"a2r"} ELSE {})
  \cup (IF Raised("accounts") THEN {"a3p", "a3q"} ELSE {})
Owner(x) ==
  IF x \in {"a1p", "a1q", "a1r", "a1s"} THEN "a1"
  ELSE IF x \in {"a2p", "a2q", "a2r"} THEN "a2"
  ELSE IF x \in {"a3p", "a3q"} THEN "a3"
  ELSE "auth"
Anc(a) == {x \in Anchors : Owner(x) = a}
InitLive ==
  {"a1p", "a1q", "a1r"}
  \cup (IF OneAccount THEN {} ELSE {"a2p"})
  \cup (IF Raised("accounts") THEN {"a3p"} ELSE {})
  \cup (IF Origin = "bootstrapped" THEN {"adm1"} ELSE {})
\* The snapshot bound, the counter bound, and the re-bootstrap bound.
NSnaps == IF Raised("snaps") THEN 3 ELSE 2
CtrMax == IF Raised("ctr") THEN 6 ELSE 5
MaxIssues == IF Raised("issues") THEN 2 ELSE 1

\* The points where an operation can stop, and the point after a crash.
InFlight == {"checked", "journaled", "committed", "created"}
Crashed == {"cChecked", "cJournaled", "cCommitted", "cCreated"}
CrashOf(s) ==
  IF s = "checked" THEN "cChecked"
  ELSE IF s = "journaled" THEN "cJournaled"
  ELSE IF s = "committed" THEN "cCommitted"
  ELSE "cCreated"

NoPlan == [kind |-> "", own |-> "", kill |-> "", keep |-> "", make |-> "", val |-> 0]

VARIABLES
  \* The store. "up" serves; "down" after a crash; "rec" reconciles.
  \* @type: Str;
  phase,
  \* A restore made the current store, so a missing outcome is unknown.
  \* @type: Bool;
  restored,
  \* Each anchor: "absent", "live", or "ended".
  \* @type: Str -> Str;
  anc,
  \* The bootstrap values that the store holds (issued in its history), the
  \* values consumed, and the values that an owner re-bootstrap ended.
  \* @type: Set(Int);
  bvals,
  \* @type: Set(Int);
  bused,
  \* @type: Set(Int);
  bended,
  \* The session line: its current generation, the highest dead generation,
  \* and its revocation.
  \* @type: Int;
  cur,
  \* @type: Int;
  dead,
  \* @type: Bool;
  revoked,
  \* The allocation counter: the highest value that the store allocated.
  \* @type: Int;
  ctr,
  \* The outcome records.
  \* @type: Set(Str);
  out,
  \* In-doubt consumptions: operations whose consumption entry restore
  \* applied with no known commit. Store state.
  \* @type: Set(Str);
  pend,
  \* Each operation's point, its plan, and the value of its artifact.
  \* @type: Str -> Str;
  pc,
  \* @type: Str -> $plan;
  plan,
  \* @type: Str -> Int;
  art,
  \* The turn of each owner: the operation that holds it, or "none".
  \* @type: Str -> Str;
  lock,
  \* The journal: the sequence of each operation's end, creation, and void
  \* entry (0 for none), the last sequence, and the allocation floor.
  \* @type: Str -> Int;
  jEnd,
  \* @type: Str -> Int;
  jCre,
  \* @type: Str -> Int;
  jVoid,
  \* @type: Int;
  jhead,
  \* @type: Int;
  jfloor,
  \* The retained snapshots.
  \* @type: Set($snapshot);
  snaps,
  \* History, for the properties only: each operation that committed in any
  \* history, and the anchors of its owner that its commit left live.
  \* @type: Set(Str);
  committed,
  \* @type: Str -> Set(Str);
  left,
  \* The identity of the last bootstrap value issued in any history. A value
  \* is a random secret, so no identity repeats; no restore changes this.
  \* @type: Int;
  bnext

store == <<phase, restored, anc, bvals, bused, bended, cur, dead, revoked, ctr, out, pend>>
journal == <<jEnd, jCre, jVoid, jhead, jfloor>>
hist == <<committed, left, bnext>>
vars == <<store, pc, plan, art, lock, journal, snaps, hist>>

-----------------------------------------------------------------------------
Max(a, b) == IF a >= b THEN a ELSE b
Min(a, b) == IF a <= b THEN a ELSE b

\* The valid bootstrap values: held by the store, not consumed, not ended.
ValidBoot == {v \in bvals : v \notin bused /\ v \notin bended}

\* An anchor that the journal records as live: live at the start, or with a
\* creation entry, and with no end entry that no void cancels.
Journaled(x) ==
  /\ \/ x \in InitLive
     \/ \E o \in Ops : plan[o].make = x /\ jCre[o] > 0 /\ jVoid[o] = 0
  /\ ~\E o \in Ops : plan[o].kill = x /\ jEnd[o] > 0 /\ jVoid[o] = 0

\* Outcome lookup. After a restore, a missing record is unknown. Known-bad
\* "lookupAbsent" reads it as absent.
Lookup(o) ==
  IF o \in out THEN "committed"
  ELSE IF restored /\ Bad /= "lookupAbsent" THEN "unknown"
  ELSE "absent"

\* A consumption of a one-use value that pays for an anchor.
Consumes(o) == plan[o].kind \in {"boot", "recover"}
\* Two such consumptions spend the same value.
SameValue(o, q) ==
  plan[o].kind = plan[q].kind /\ plan[o].kill = plan[q].kill /\ plan[o].val = plan[q].val

\* The operation writes an entry before its commit. Known-bad "afterCommit"
\* (option c): a consumption writes no entry before its commit, and one
\* entry after the commit records it with the creation. Known-bad
\* "createBeforeCommit": the creation entry comes before the commit.
\* Known-bad "issueNoJournal": an owner re-bootstrap ends the earlier value
\* with no journal entry.
PreWrite(o) ==
  \/ /\ plan[o].kill /= ""
     /\ ~(Bad = "afterCommit" /\ Consumes(o))
     /\ ~(Bad = "issueNoJournal" /\ plan[o].kind = "issue")
  \/ Bad = "createBeforeCommit" /\ plan[o].make /= ""

\* @type: ($plan) => Bool;
Issues(p) == p.kind \in {"enroll", "recover", "boot", "renew"}

\* The dependencies that the conditional commit checks. An owner
\* re-bootstrap depends on the valid bootstrap values that it checked:
\* the one that it ends, or none. Known-bad "issueNoEnd" checks none.
\* @type: ($plan) => Bool;
DepOK(p) ==
  CASE p.kind = "enroll" -> anc[p.make] = "absent"
    [] p.kind = "unlink" -> anc[p.kill] = "live" /\ anc[p.keep] = "live"
    [] p.kind = "recover" -> anc[p.kill] = "live" /\ anc[p.make] = "absent"
    [] p.kind = "boot" -> p.val \in ValidBoot /\ anc[p.make] = "absent"
    [] p.kind = "issue" ->
         Bad = "issueNoEnd" \/ ValidBoot = (IF p.kill = "boot" THEN {p.val} ELSE {})
    [] p.kind = "renew" -> cur = p.val /\ cur > dead /\ ~revoked
    [] OTHER -> ~revoked

\* The dependencies of an in-doubt consumption after restore applied its own
\* entry: its value is consumed for every other request, and the anchor that
\* it pays for is absent. A bootstrap value must also be one that the
\* restored store holds and that no re-bootstrap ended.
AgainOK(o) ==
  IF plan[o].kind = "boot"
  THEN plan[o].val \in bvals /\ plan[o].val \notin bended /\ anc[plan[o].make] = "absent"
  ELSE anc[plan[o].kill] = "ended" /\ anc[plan[o].make] = "absent"

\* Journal order among the in-doubt consumptions of one value.
First(o) == \A q \in pend : SameValue(q, o) => jEnd[o] <= jEnd[q]

Now == [anc |-> anc, bvals |-> bvals, bused |-> bused, bended |-> bended, cur |-> cur,
        dead |-> dead, revoked |-> revoked, ctr |-> ctr, out |-> out, lwm |-> 0]

\* The fact of an operation's end entry holds in t.
\* @type: (Str, $snapshot) => Bool;
EndHoldsIn(o, t) ==
  CASE plan[o].kind = "renew" -> t.dead >= plan[o].val
    [] plan[o].kind = "revoke" -> t.revoked
    [] plan[o].kind = "boot" -> plan[o].val \in t.bused
    [] plan[o].kind = "issue" -> plan[o].val \in t.bended
    [] OTHER -> t.anc[plan[o].kill] = "ended"
EndHolds(o) == EndHoldsIn(o, Now)

\* The low-water mark: one below the first entry that the store does not
\* reflect yet.
Unreflected(o) ==
  Min(IF jEnd[o] > 0 /\ ~EndHolds(o) /\ jVoid[o] = 0 THEN jEnd[o] ELSE jhead + 1,
      IF jCre[o] > 0 /\ jVoid[o] = 0 /\ anc[plan[o].make] = "absent" THEN jCre[o] ELSE jhead + 1)

\* The fourth operation counts only in a raise.
LowWater ==
  Min(Unreflected("o1"), Min(Unreflected("o2"), Min(Unreflected("o3"),
      IF "o4" \in Ops THEN Unreflected("o4") ELSE jhead + 1))) - 1

Unlock(o) == [a \in Owners |-> IF lock[a] = o THEN "none" ELSE lock[a]]

\* The floor is durable before a commit allocates a value above it. The
\* floor write and the commit are one step: a crash between them leaves only
\* a higher floor. Known-bad "floorAtRelease": the floor waits for the
\* release (Ack, Resolve).
\* @type: ($plan) => Int;
FloorAt(p) == IF Issues(p) /\ Bad /= "floorAtRelease" THEN Max(jfloor, ctr + 1) ELSE jfloor

\* The anchors after a commit of plan p.
\* @type: ($plan) => Str -> Str;
AncAfter(p) == [x \in Anchors |-> IF x = p.kill THEN "ended"
                                  ELSE IF x = p.make THEN "live" ELSE anc[x]]

-----------------------------------------------------------------------------
\* The core checks the request and proposes a transition. An anchor change
\* takes its owner's turn. Operations start in identity order: the
\* identities are interchangeable, so the order loses no behavior.
\* Known-bad "unserialized": anchor changes take no turn.
\* @type: (Str, $plan) => Bool;
Propose(o, p) ==
  /\ phase = "up"
  /\ pc[o] = "idle"
  /\ \A q \in Ops : Rank[q] < Rank[o] => pc[q] /= "idle"
  /\ IF p.own = "" \/ Bad = "unserialized" THEN TRUE ELSE lock[p.own] = "none"
  /\ pc' = [pc EXCEPT ![o] = "checked"]
  /\ plan' = [plan EXCEPT ![o] = p]
  /\ lock' = IF p.own = "" \/ Bad = "unserialized" THEN lock
             ELSE [lock EXCEPT ![p.own] = o]
  /\ UNCHANGED <<store, art, journal, snaps, hist>>

\* @type: (Str, Str, Str, Str, Str, Int) => $plan;
Plan(kind, own, kill, keep, make, val) ==
  [kind |-> kind, own |-> own, kill |-> kill, keep |-> keep, make |-> make, val |-> val]

\* The seven transition kinds. Each one is the check and the proposal of one
\* kind; Start is their disjunction.
\* Enrollment and link of an account anchor.
StartEnroll(o) ==
  \E x \in Anchors \ Adms :
    anc[x] = "absent" /\ Propose(o, Plan("enroll", Owner(x), "", "", x, 0))
\* Unlink and credential removal, for an account anchor or an administrator
\* binding: the last-anchor check keeps an anchor of the same owner that the
\* journal records as live.
StartUnlink(o) ==
  \E x, y \in Anchors :
    /\ x /= y /\ Owner(x) = Owner(y)
    /\ anc[x] = "live" /\ anc[y] = "live" /\ Journaled(y)
    /\ Propose(o, Plan("unlink", Owner(x), x, y, "", 0))
\* Recovery: it binds a new anchor in the commit that consumes its value.
StartRecover(o) ==
  \E x, y \in Anchors \ Adms :
    /\ x /= y /\ Owner(x) = Owner(y)
    /\ anc[x] = "live" /\ anc[y] = "absent"
    /\ Propose(o, Plan("recover", Owner(x), x, "", y, 0))
\* Bootstrap: it consumes a valid bootstrap value and binds a new
\* administrator in the first absent slot. The slots are interchangeable.
StartBoot(o) ==
  LET x == IF anc["adm1"] = "absent" THEN "adm1"
           ELSE IF anc["adm2"] = "absent" \/ "adm3" \notin Adms THEN "adm2"
           ELSE "adm3" IN
  \E v \in ValidBoot :
    anc[x] = "absent" /\ Propose(o, Plan("boot", "auth", "boot", "", x, v))
\* Session renewal and grant change.
StartRenew(o) ==
  cur > dead /\ ~revoked /\ Propose(o, Plan("renew", "", "L", "", "", cur))
\* Revocation of the session family or grant.
StartRevoke(o) ==
  ~revoked /\ Propose(o, Plan("revoke", "", "L", "", "", 0))
\* Owner re-bootstrap, by the local application owner only: it issues a new
\* bootstrap value and ends the valid one, if any. An owner event: it has no
\* fairness. Known-bad "issueNoEnd" ends no earlier value.
\* A re-bootstrap while a bootstrap value is valid: it plans to end it.
StartIssueEnd(o) ==
  \E v \in ValidBoot :
    Bad /= "issueNoEnd" /\ Propose(o, Plan("issue", "", "boot", "", "", v))
\* A re-bootstrap while no bootstrap value is valid: it ends none.
StartIssueNone(o) ==
  (ValidBoot = {} \/ Bad = "issueNoEnd") /\ Propose(o, Plan("issue", "", "", "", "", 0))
StartIssue(o) == StartIssueEnd(o) \/ StartIssueNone(o)

Start(o) ==
  \/ StartEnroll(o) \/ StartUnlink(o) \/ StartRecover(o) \/ StartBoot(o)
  \/ StartRenew(o) \/ StartRevoke(o) \/ StartIssue(o)

\* Write rule: the end entry is durable before its commit. An unlink ends its
\* turn here. With Turn = "entry", every turn ends here.
JournalEnd(o) ==
  /\ phase = "up"
  /\ pc[o] = "checked"
  /\ PreWrite(o)
  /\ jEnd' = IF plan[o].kill /= "" THEN [jEnd EXCEPT ![o] = jhead + 1] ELSE jEnd
  /\ jCre' = IF Bad = "createBeforeCommit" /\ plan[o].make /= ""
             THEN [jCre EXCEPT ![o] = jhead + 2] ELSE jCre
  /\ jhead' = jhead + (IF Bad = "createBeforeCommit" /\ plan[o].make /= "" THEN 2 ELSE 1)
  /\ lock' = IF plan[o].make = "" \/ Turn = "entry" THEN Unlock(o) ELSE lock
  /\ pc' = [pc EXCEPT ![o] = "journaled"]
  /\ UNCHANGED <<store, plan, art, jVoid, jfloor, snaps, hist>>

Committable(o) ==
  /\ phase = "up"
  /\ \/ pc[o] = "journaled"
     \/ pc[o] = "checked" /\ ~PreWrite(o)

\* Serializable conditional commit of the dependencies, the state change,
\* and the outcome record. An owner re-bootstrap adds a value with a new
\* identity and ends the value that it checked.
Commit(o) ==
  LET p == plan[o] IN
  /\ Committable(o)
  /\ DepOK(p)
  /\ anc' = AncAfter(p)
  /\ bvals' = IF p.kind = "issue" THEN bvals \cup {bnext + 1} ELSE bvals
  /\ bused' = IF p.kind = "boot" THEN bused \cup {p.val} ELSE bused
  /\ bended' = IF p.kind = "issue" /\ p.kill = "boot" THEN bended \cup {p.val} ELSE bended
  /\ bnext' = IF p.kind = "issue" THEN bnext + 1 ELSE bnext
  /\ dead' = IF p.kind = "renew" THEN p.val ELSE dead
  /\ revoked' = (revoked \/ p.kind = "revoke")
  /\ cur' = IF p.kind = "renew" THEN ctr + 1 ELSE cur
  /\ ctr' = IF Issues(p) THEN ctr + 1 ELSE ctr
  /\ art' = IF Issues(p) THEN [art EXCEPT ![o] = ctr + 1] ELSE art
  /\ out' = out \cup {o}
  /\ committed' = committed \cup {o}
  /\ left' = [left EXCEPT ![o] = {x \in Anc(p.own) : anc'[x] = "live"}]
  /\ pc' = [pc EXCEPT ![o] = "committed"]
  /\ jfloor' = FloorAt(p)
  /\ UNCHANGED <<phase, restored, pend, plan, lock, jEnd, jCre, jVoid, jhead, snaps>>

\* A dependency changed: the commit refuses and changes no store state. The
\* binding voids each entry of the operation before the refusal returns. A
\* crash before the void stops the operation before its response, which is
\* the state of a crash at "journaled". Known-bad "refusalNoVoid": no void.
Conflict(o) ==
  /\ Committable(o)
  /\ ~DepOK(plan[o])
  /\ pc' = [pc EXCEPT ![o] = "refused"]
  /\ lock' = Unlock(o)
  /\ IF Bad = "refusalNoVoid" \/ (jEnd[o] = 0 /\ jCre[o] = 0)
     THEN UNCHANGED <<jVoid, jhead>>
     ELSE /\ jVoid' = [jVoid EXCEPT ![o] = jhead + 1]
          /\ jhead' = jhead + 1
  /\ UNCHANGED <<store, plan, art, jEnd, jCre, jfloor, snaps, hist>>

\* The creation entry, after the commit and before the acknowledgement. It
\* ends the turn. With "afterCommit" (option c), the same entry records the
\* consumption.
JournalCreate(o) ==
  /\ phase = "up"
  /\ pc[o] = "committed"
  /\ plan[o].make /= ""
  /\ jCre[o] = 0
  /\ jCre' = [jCre EXCEPT ![o] = jhead + 1]
  /\ jEnd' = IF Bad = "afterCommit" /\ Consumes(o) THEN [jEnd EXCEPT ![o] = jhead + 1] ELSE jEnd
  /\ jhead' = jhead + 1
  /\ lock' = Unlock(o)
  /\ pc' = [pc EXCEPT ![o] = "created"]
  /\ UNCHANGED <<store, plan, art, jVoid, jfloor, snaps, hist>>

\* The response, after the floor covers the artifact's value.
\* Another operation of o's owner committed an anchor creation, and its
\* creation entry is still to come. An acknowledgement of o waits for that
\* entry, so each anchor in the state that an acknowledged commit saw has its
\* creation entry, and a restore keeps it (selected on 2026-11-08). The
\* known-bad variant "ackEarly" does not wait.
CreationPending(o) ==
  /\ Bad /= "ackEarly"
  /\ plan[o].own /= ""
  /\ \E q \in Ops \ {o} :
       /\ plan[q].own = plan[o].own
       /\ plan[q].make /= ""
       /\ pc[q] \in {"committed", "cCommitted"}
       /\ jCre[q] = 0

Ack(o) ==
  /\ phase = "up"
  /\ \/ pc[o] = "created"
     \/ pc[o] = "committed" /\ (plan[o].make = "" \/ jCre[o] > 0)
  /\ ~CreationPending(o)
  /\ jfloor' = Max(jfloor, art[o])
  /\ lock' = Unlock(o)
  /\ pc' = [pc EXCEPT ![o] = "acked"]
  /\ UNCHANGED <<store, plan, art, jEnd, jCre, jVoid, jhead, snaps, hist>>

\* A client whose response was lost looks up its operation identity, finds
\* the committed outcome, and receives its artifact.
Resolve(o) ==
  /\ phase = "up"
  /\ pc[o] \in Crashed
  /\ o \in out
  /\ plan[o].make = "" \/ jCre[o] > 0
  /\ ~CreationPending(o)
  /\ jfloor' = Max(jfloor, art[o])
  /\ pc' = [pc EXCEPT ![o] = "acked"]
  /\ UNCHANGED <<store, plan, art, lock, jEnd, jCre, jVoid, jhead, snaps, hist>>

\* Restore completes an in-doubt consumption: the first in-doubt
\* consumption of a value commits again against the restored state, under
\* its operation identity, when its dependencies hold. Its creation entry
\* follows as the missing creation entry of a committed anchor.
Redrive(o) ==
  LET p == plan[o] IN
  /\ phase = "rec"
  /\ o \in pend /\ First(o) /\ AgainOK(o)
  /\ anc' = AncAfter(p)
  /\ bused' = IF p.kind = "boot" THEN bused \cup {p.val} ELSE bused
  /\ ctr' = ctr + 1
  /\ art' = [art EXCEPT ![o] = ctr + 1]
  /\ out' = out \cup {o}
  /\ pend' = {q \in pend : ~SameValue(q, o)}
  /\ committed' = committed \cup {o}
  /\ left' = [left EXCEPT ![o] = {x \in Anc(p.own) : anc'[x] = "live"}]
  /\ jfloor' = FloorAt(p)
  /\ UNCHANGED <<phase, restored, bvals, bended, cur, dead, revoked, pc, plan, lock, jEnd, jCre,
                 jVoid, jhead, snaps, bnext>>

\* The dependencies do not hold: the value stays consumed.
RedriveFail(o) ==
  /\ phase = "rec"
  /\ o \in pend /\ First(o) /\ ~AgainOK(o)
  /\ pend' = pend \ {o}
  /\ UNCHANGED <<phase, restored, anc, bvals, bused, bended, cur, dead, revoked, ctr, out, pc, plan,
                 art, lock, journal, snaps, hist>>

-----------------------------------------------------------------------------
\* A crash stops each operation in flight at its point. The store and the
\* journal keep their durable state.
Crash ==
  /\ phase /= "down"
  /\ phase' = "down"
  /\ pc' = [o \in Ops |-> IF pc[o] \in InFlight THEN CrashOf(pc[o]) ELSE pc[o]]
  /\ lock' = [a \in Owners |-> "none"]
  /\ UNCHANGED <<restored, anc, bvals, bused, bended, cur, dead, revoked, ctr, out, pend, plan, art,
                 journal, snaps, hist>>

\* A start reconciles before it serves. Known-bad "voidOnMissing": a normal
\* start reads a missing outcome as absent again after an earlier restore.
Restart ==
  /\ phase = "down"
  /\ phase' = "rec"
  /\ restored' = IF Bad = "voidOnMissing" THEN FALSE ELSE restored
  /\ UNCHANGED <<anc, bvals, bused, bended, cur, dead, revoked, ctr, out, pend, pc, plan, art, lock,
                 journal, snaps, hist>>

NeedsCreate(o) == o \in out /\ plan[o].make /= "" /\ jCre[o] = 0
\* Reconciliation voids an end entry whose fact does not hold in the store.
\* Facts are monotone, a commit makes its fact hold, and restore applies each
\* entry that no void cancels, so the fact fails only for an operation that
\* did not commit since its entry was written. A creation entry follows its
\* commit, so reconciliation never voids one. Known-bad "voidOnMissing" and
\* "lookupAbsent" void each entry whose outcome lookup is absent.
NeedsVoid(o) ==
  /\ jVoid[o] = 0
  /\ IF Bad \in {"voidOnMissing", "lookupAbsent"}
     THEN Lookup(o) = "absent" /\ (jEnd[o] > 0 \/ jCre[o] > 0)
     ELSE jEnd[o] > 0 /\ ~EndHolds(o)

ReconcileCreate(o) ==
  /\ phase = "rec"
  /\ NeedsCreate(o)
  /\ jCre' = [jCre EXCEPT ![o] = jhead + 1]
  /\ jhead' = jhead + 1
  /\ UNCHANGED <<store, pc, plan, art, lock, jEnd, jVoid, jfloor, snaps, hist>>

ReconcileVoid(o) ==
  /\ phase = "rec"
  /\ NeedsVoid(o)
  /\ jVoid' = [jVoid EXCEPT ![o] = jhead + 1]
  /\ jhead' = jhead + 1
  /\ UNCHANGED <<store, pc, plan, art, lock, jEnd, jCre, jfloor, snaps, hist>>

\* The store serves when reconciliation is complete and no in-doubt
\* consumption remains.
Serve ==
  /\ phase = "rec"
  /\ \A o \in Ops : ~NeedsCreate(o) /\ ~NeedsVoid(o)
  /\ pend = {}
  /\ phase' = "up"
  /\ UNCHANGED <<restored, anc, bvals, bused, bended, cur, dead, revoked, ctr, out, pend, pc, plan,
                 art, lock, journal, snaps, hist>>

\* A snapshot with its low-water mark. A serving store has no in-doubt
\* consumption, so a snapshot keeps none.
Snapshot ==
  /\ phase = "up"
  /\ Cardinality(snaps) < NSnaps
  /\ snaps' = snaps \cup {[Now EXCEPT !.lwm = LowWater]}
  /\ UNCHANGED <<store, pc, plan, art, lock, journal, hist>>

\* An entry applies at a restore from s. Known-bad "ignoreVoids" applies a
\* voided entry; "noJournal" restores without the journal.
\* @type: (Int, Str, $snapshot) => Bool;
Applies(seq, o, s) ==
  /\ seq > s.lwm
  /\ jVoid[o] = 0 \/ Bad = "ignoreVoids"
  /\ Bad /= "noJournal"

\* Restore from a retained snapshot of a store that is down: apply each entry
\* after the low-water mark that no void cancels, keep an ended anchor ended,
\* raise the floor, and find the in-doubt consumptions. A bootstrap value
\* that was issued after the snapshot is lost: the store holds the
\* snapshot's values. Reconciliation follows. Known-bad "pairApplies"
\* (option a) creates the anchors of the in-doubt consumptions at once;
\* "noAgain" (the design before 2026-11-07) leaves them unresolved.
\* @type: ($snapshot) => Bool;
Restore(s) ==
  LET ends == {o \in Ops : Applies(jEnd[o], o, s)}
      makes == {o \in Ops : Applies(jCre[o], o, s)}
      known(o) == o \in s.out \/ (jCre[o] > 0 /\ Bad /= "noJournal")
      taken(o) == \E q \in Ops : q /= o /\ Consumes(q) /\ SameValue(q, o) /\ known(q)
      doubt == {o \in ends : Consumes(o) /\ ~known(o) /\ ~taken(o)}
      endedX(x) == s.anc[x] = "ended" \/ \E o \in ends : plan[o].kill = x
      madeX(x) ==
        \/ s.anc[x] = "live"
        \/ \E o \in makes : plan[o].make = x
        \/ Bad = "pairApplies" /\ \E o \in doubt : plan[o].make = x
      deadOf(o) == IF o \in ends /\ plan[o].kind = "renew" THEN plan[o].val ELSE 0
  IN
  /\ phase = "down"
  /\ anc' = [x \in Anchors |-> IF endedX(x) THEN "ended"
                               ELSE IF madeX(x) THEN "live" ELSE "absent"]
  /\ bvals' = s.bvals
  /\ bused' = s.bused \cup {plan[o].val : o \in {q \in ends : plan[q].kind = "boot"}}
  /\ bended' = s.bended \cup {plan[o].val : o \in {q \in ends : plan[q].kind = "issue"}}
  /\ dead' = Max(s.dead, Max(deadOf("o1"), Max(deadOf("o2"), Max(deadOf("o3"),
                IF "o4" \in Ops THEN deadOf("o4") ELSE 0))))
  /\ revoked' = (s.revoked \/ \E o \in ends : plan[o].kind = "revoke")
  /\ cur' = s.cur
  /\ ctr' = IF Bad \in {"noFloor", "noJournal"} THEN s.ctr ELSE Max(s.ctr, jfloor)
  /\ out' = s.out
  /\ pend' = IF Bad \in {"pairApplies", "noAgain"} THEN {} ELSE doubt
  /\ restored' = TRUE
  /\ phase' = "rec"
  /\ UNCHANGED <<pc, plan, art, lock, journal, snaps, hist>>

-----------------------------------------------------------------------------
Init ==
  /\ phase = "up"
  /\ restored = FALSE
  /\ anc = [x \in Anchors |-> IF x \in InitLive THEN "live" ELSE "absent"]
  /\ bvals = {1}
  /\ bused = IF Origin = "bootstrapped" THEN {1} ELSE {}
  /\ bended = {}
  /\ cur = 1
  /\ dead = 0
  /\ revoked = FALSE
  /\ ctr = 1
  /\ out = {}
  /\ pend = {}
  /\ pc = [o \in Ops |-> "idle"]
  /\ plan = [o \in Ops |-> NoPlan]
  /\ art = [o \in Ops |-> 0]
  /\ lock = [a \in Owners |-> "none"]
  /\ jEnd = [o \in Ops |-> 0]
  /\ jCre = [o \in Ops |-> 0]
  /\ jVoid = [o \in Ops |-> 0]
  /\ jhead = 0
  /\ jfloor = 1
  /\ snaps = {}
  /\ committed = {}
  /\ left = [o \in Ops |-> {}]
  /\ bnext = 1

\* The parts of Next. AuthorityInd.tla splits them further for its step
\* checks. Next is their disjunction.
NextRun == \E o \in Ops : Start(o) \/ JournalEnd(o) \/ Commit(o) \/ Conflict(o)
NextEnd == \E o \in Ops : JournalCreate(o) \/ Ack(o) \/ Resolve(o)
NextRec == \E o \in Ops : ReconcileCreate(o) \/ ReconcileVoid(o)
NextAgain == \E o \in Ops : Redrive(o) \/ RedriveFail(o)
NextSys == Crash \/ Restart \/ Serve \/ Snapshot
NextRestore == \E s \in snaps : Restore(s)

Next == NextRun \/ NextEnd \/ NextRec \/ NextAgain \/ NextSys \/ NextRestore

Spec == Init /\ [][Next]_vars

-----------------------------------------------------------------------------
Kinds == {"", "enroll", "unlink", "recover", "boot", "renew", "revoke", "issue"}
Items == Anchors \cup {"", "boot", "L"}
Seqs == 0..jhead
Vals == 1..bnext
Plans == [kind : Kinds, own : Owners \cup {""}, kill : Items, keep : Anchors \cup {""},
          make : Anchors \cup {""}, val : Nat]
\* @type: ($snapshot) => Bool;
SnapOK(s) ==
  /\ s.anc \in [Anchors -> {"absent", "live", "ended"}]
  /\ s.bvals \subseteq Vals /\ s.bused \subseteq Vals /\ s.bended \subseteq Vals
  /\ s.cur \in Nat /\ s.dead \in Nat /\ s.revoked \in BOOLEAN /\ s.ctr \in Nat
  /\ s.out \subseteq Ops /\ s.lwm \in Seqs

TypeOK ==
  /\ phase \in {"up", "down", "rec"}
  /\ restored \in BOOLEAN
  /\ anc \in [Anchors -> {"absent", "live", "ended"}]
  /\ bvals \subseteq Vals /\ bused \subseteq Vals /\ bended \subseteq Vals
  /\ cur \in Nat /\ dead \in Nat /\ revoked \in BOOLEAN /\ ctr \in Nat
  /\ out \subseteq Ops /\ pend \subseteq Ops
  /\ pc \in [Ops -> {"idle", "acked", "refused"} \cup InFlight \cup Crashed]
  /\ plan \in [Ops -> Plans]
  /\ art \in [Ops -> Nat]
  /\ lock \in [Owners -> Ops \cup {"none"}]
  /\ jEnd \in [Ops -> Seqs] /\ jCre \in [Ops -> Seqs] /\ jVoid \in [Ops -> Seqs]
  /\ jhead \in Nat /\ jfloor \in Nat
  /\ Cardinality(snaps) <= NSnaps /\ \A s \in snaps : SnapOK(s)
  /\ committed \subseteq Ops
  /\ left \in [Ops -> SUBSET Anchors]
  /\ bnext \in Nat \ {0}

-----------------------------------------------------------------------------
\* Properties. A011 gives each one its conformance case (README.md).

EndedAnchors == {plan[o].kill : o \in {q \in committed : plan[q].kind \in {"unlink", "recover"}}}
\* The bootstrap values that a committed consumption or a committed owner
\* re-bootstrap ended.
EndedBoot ==
  {plan[o].val : o \in {q \in committed :
     plan[q].kind = "boot" \/ (plan[q].kind = "issue" /\ plan[q].kill = "boot")}}
LineEnded(v) ==
  \E o \in committed :
    \/ plan[o].kind = "revoke"
    \/ plan[o].kind = "renew" /\ v <= plan[o].val

\* Nothing that a committed transition ended is valid again.
NothingEndedValid ==
  /\ \A x \in EndedAnchors : anc[x] /= "live"
  /\ \A v \in EndedBoot : v \notin ValidBoot
  /\ cur > dead /\ ~revoked => ~LineEnded(cur)

\* At most one bootstrap value is valid.
OneBootValid == \A v, w \in ValidBoot : v = w

\* No counter value is released twice, and none is the initial value.
NoCounterReuse ==
  \A o \in Ops :
    pc[o] = "acked" /\ art[o] > 0 =>
      /\ art[o] /= 1
      /\ \A q \in Ops \ {o} : pc[q] = "acked" => art[q] /= art[o]

\* A committed operation is never reported as absent.
MissingOutcomeUnknown == \A o \in committed : Lookup(o) /= "absent"

\* Each live anchor was live at the start or has a commit that created it.
NoUncommittedAnchor ==
  \A x \in Anchors : anc[x] = "live" => x \in InitLive \/ \E o \in committed : plan[o].make = x

\* Each anchor that an acknowledged commit left is live, ended by a commit,
\* or ended by an entry of a crashed operation whose outcome is unknown.
Uncertain(x) ==
  \E o \in Ops : plan[o].kill = x /\ pc[o] \in Crashed /\ o \notin committed /\ jVoid[o] = 0
Promised == InitLive \cup UNION {left[o] : o \in {q \in Ops : pc[q] = "acked"}}
AnchorKept == \A x \in Promised : anc[x] = "live" \/ x \in EndedAnchors \/ Uncertain(x)

AccountKeepsAnchor == \A a \in Accounts : \E x \in Anc(a) : anc[x] = "live"
\* The authority has an administrator when the store holds a consumed
\* bootstrap value that no owner re-bootstrap ended. Otherwise the local
\* owner issues a new value.
AdminLive == \E x \in Adms : anc[x] = "live"
BootHeld == \E v \in bvals : v \in bused /\ v \notin bended
AdminKept == BootHeld => AdminLive

\* While the store serves, the authority keeps its administrator and each
\* account keeps an anchor. During reconciliation after a restore, an
\* in-doubt bootstrap or recovery has not completed yet.
AdminKeptP == phase = "up" => AdminKept
AccountKeepsAnchorP == phase = "up" => AccountKeepsAnchor

\* A delivered refusal stays true: no refused operation commits later.
RefusalHolds == \A o \in Ops : pc[o] = "refused" => o \notin committed

\* In the store's current history, at most one commit spends each value.
OneUse ==
  \A o, q \in out : o /= q /\ Consumes(o) /\ Consumes(q) => ~SameValue(o, q)

\* An in-doubt consumption is a journaled consumption that no void cancels,
\* with no outcome in the store's current history, whose value no commit in
\* that history spent. Only it can spend the value again.
PendExact ==
  \A o \in pend :
    /\ Consumes(o) /\ jEnd[o] > 0 /\ jVoid[o] = 0 /\ o \notin out
    /\ ~\E q \in out : Consumes(q) /\ SameValue(q, o)

\* No in-doubt state remains while the store serves.
NoDoubtServing == phase = "up" => pend = {}

-----------------------------------------------------------------------------
\* Reachability targets. Each `_reach` profile checks the negation of one.

RestoredUp == restored /\ phase = "up"
\* Restore after each crash point.
RestoreAfterCrashBeforeJournal ==
  RestoredUp /\ \E o \in Ops : pc[o] = "cChecked" /\ PreWrite(o)
RestoreAfterCrashBeforeCommit ==
  RestoredUp /\ \E o \in Ops : pc[o] = "cJournaled"
RestoreAfterCrashBeforeCreation ==
  RestoredUp /\ \E o \in Ops : pc[o] = "cCommitted" /\ plan[o].make /= ""
RestoreAfterCrashBeforeAck ==
  RestoredUp /\ \E o \in Ops : pc[o] = "cCreated"
\* Reconciliation wrote the creation entry of a crashed commit, and voided the
\* entry of a crashed operation that did not commit.
ReconciledCreate ==
  phase = "up" /\ \E o \in Ops : pc[o] = "cCommitted" /\ plan[o].make /= "" /\ jCre[o] > 0
ReconciledVoid ==
  phase = "up" /\ \E o \in Ops : pc[o] = "cJournaled" /\ jVoid[o] > 0
\* A bootstrap crashed between its consumption entry and its commit, a
\* restore followed, and the serving store has its administrator.
AdminAfterDoubt ==
  /\ RestoredUp
  /\ \E o \in Ops : plan[o].kind = "boot" /\ pc[o] = "cJournaled" /\ anc[plan[o].make] = "live"
\* The same for a recovery and its new anchor.
AccountAfterDoubt ==
  /\ RestoredUp
  /\ \E o \in Ops : plan[o].kind = "recover" /\ pc[o] = "cJournaled" /\ anc[plan[o].make] = "live"
\* A refused unlink voided its entry, and a restored store serves with the
\* anchor that the unlink would end.
RefusedKept ==
  /\ RestoredUp
  /\ \E o \in Ops : plan[o].kind = "unlink" /\ pc[o] = "refused" /\ jVoid[o] > 0 /\ anc[plan[o].kill] = "live"
\* Two consumptions of one value were in doubt at one restore (Turn = "entry").
TwoInDoubt == \E o, q \in pend : o /= q
\* After the first bootstrap value was consumed, the authority gains an
\* administrator through an owner re-bootstrap.
Rebootstrapped ==
  /\ phase = "up" /\ 1 \in bused
  /\ \E o \in out : plan[o].kind = "boot" /\ plan[o].val > 1 /\ anc[plan[o].make] = "live"
\* The administrator of a re-bootstrap ended the earlier administrator
\* binding through an unlink.
AdminReplaced == phase = "up" /\ anc["adm1"] = "ended" /\ anc["adm2"] = "live"
\* A restore applied the end entry of an owner re-bootstrap whose commit is
\* not known.
IssueEndApplied ==
  /\ RestoredUp
  /\ \E o \in Ops :
       plan[o].kind = "issue" /\ plan[o].kill = "boot" /\ pc[o] = "cJournaled" /\ plan[o].val \in bended

NotRestoreAfterCrashBeforeJournal == ~RestoreAfterCrashBeforeJournal
NotRestoreAfterCrashBeforeCommit == ~RestoreAfterCrashBeforeCommit
NotRestoreAfterCrashBeforeCreation == ~RestoreAfterCrashBeforeCreation
NotRestoreAfterCrashBeforeAck == ~RestoreAfterCrashBeforeAck
NotReconciledCreate == ~ReconciledCreate
NotReconciledVoid == ~ReconciledVoid
NotAdminAfterDoubt == ~AdminAfterDoubt
NotAccountAfterDoubt == ~AccountAfterDoubt
NotRefusedKept == ~RefusedKept
NotTwoInDoubt == ~TwoInDoubt
NotRebootstrapped == ~Rebootstrapped
NotAdminReplaced == ~AdminReplaced
NotIssueEndApplied == ~IssueEndApplied

-----------------------------------------------------------------------------
\* Search bounds. Each is a state constraint, so a search is complete only
\* for the bounded space. A completion that a crash stops before its
\* creation entry runs again after the next restore and allocates a new
\* value each time, so the counter needs a bound. The owner re-bootstrap is
\* an owner event with no bound in the design, so its number needs one: at
\* most one in each run (two in its raise).
IssueBound == Cardinality({o \in Ops : plan[o].kind = "issue"}) <= MaxIssues
\* The declared bound: counter values up to 5 (6 in its raise), which allows
\* one value again after three operations allocate theirs, and the
\* re-bootstrap bound.
Declared == ctr <= CtrMax /\ IssueBound
\* The local bound: two operations, counter values up to 4, and at most one
\* re-bootstrap.
TwoOps == Cardinality({o \in Ops : pc[o] /= "idle"}) <= 2 /\ ctr <= 4 /\ IssueBound
=============================================================================
