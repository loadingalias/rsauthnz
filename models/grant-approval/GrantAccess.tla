----------------------------- MODULE GrantAccess -----------------------------
(***************************************************************************)
(* Design model of task A400, part 1: the current authority of an agent    *)
(* grant.                                                                  *)
(*                                                                         *)
(* Promise: an operation commits only while its agent is live, within its  *)
(* grant and before the grant deadline, and within the current authority   *)
(* of the human owner under the policy version that the grant binds.       *)
(*                                                                         *)
(* Failure: a revocation or an authority change lands between the request  *)
(* check and the commit, and the operation still commits.                  *)
(*                                                                         *)
(* Approval, request loss, and restore are in Approval.tla.                *)
(***************************************************************************)
EXTENDS Naturals, FiniteSets, TLC

CONSTANTS
  Agents,      \* agent identities, enrolled and bound to the one human owner
  Ops,         \* operations of the agents
  Auds,        \* audience symbols
  Ress,        \* resource symbols
  Acts,        \* action symbols
  NPol,        \* policy versions 1..NPol; a relevant policy change raises it
  MaxRev,      \* grant revisions 1..MaxRev; issuance and each change take one
  MaxPerms,    \* resource permissions in one grant revision
  MaxOwn,      \* changes of the owner's authority
  Bad,         \* the known-bad variant, or "none"
  None         \* a model value that differs from every other value

Pairs == Ress \X Acts                                   \* resource permissions
Req   == [ag : Agents, aud : Auds, res : Ress, act : Acts]

GrantSt == {"none", "active", "revoked"}
Grants  == [st : GrantSt, ag : Agents \cup {None}, auds : SUBSET Auds,
            perms : SUBSET Pairs, late : BOOLEAN, rev : 0..MaxRev,
            pol : 0..NPol]

\* For each group of dependencies that a request check reads, whether it is
\* unchanged since the check: the agent lifecycle, the grant (its state and
\* revision), and the policy version with the owner's authority. Each of these
\* changes only in one direction, so "unchanged" equals "equal to the value
\* that the check read" (design: atomic dependency comparison and commit).
Fresh    == [ag : BOOLEAN, gr : BOOLEAN, pol : BOOLEAN]
AllFresh == [ag |-> TRUE, gr |-> TRUE, pol |-> TRUE]

OpSt  == {"idle", "checked", "closed"}
Views == {"none", "ok", "no", "conflict", "revoked"}
OpRec == [st : OpSt, req : Req \cup {None}, fresh : Fresh \cup {None},
          view : Views]

\* For each property, whether it held at every commit so far.
Facts == [live : BOOLEAN, owner : BOOLEAN, inGrant : BOOLEAN]

VARIABLES
  pol,     \* the current policy version (an application input)
  auth,    \* the current resource authority of the owner (an application input)
  ownN,    \* owner authority changes so far
  agent,   \* agent lifecycle
  grant,   \* the one grant
  op,      \* each operation
  held     \* the facts of Facts, over every commit so far (history)

vars == <<pol, auth, ownN, agent, grant, op, held>>

NoGrant == [st |-> "none", ag |-> None, auds |-> {}, perms |-> {},
            late |-> FALSE, rev |-> 0, pol |-> 0]
IdleOp  == [st |-> "idle", req |-> None, fresh |-> None, view |-> "none"]
Final(v) == [IdleOp EXCEPT !.st = "closed", !.view = v]

TypeOK ==
  /\ pol \in 1..NPol
  /\ auth \in SUBSET Pairs
  /\ ownN \in 0..MaxOwn
  /\ agent \in [Agents -> {"active", "revoked"}]
  /\ grant \in Grants
  /\ op \in [Ops -> OpRec]
  /\ held \in Facts

\* Both agents are enrolled. The owner holds every resource permission under
\* the first policy version, and no grant exists yet.
Init ==
  /\ pol = 1
  /\ auth = Pairs
  /\ ownN = 0
  /\ agent = [g \in Agents |-> "active"]
  /\ grant = NoGrant
  /\ op = [o \in Ops |-> IdleOp]
  /\ held = [live |-> TRUE, owner |-> TRUE, inGrant |-> TRUE]

-----------------------------------------------------------------------------
(* Checks of the design.                                                   *)

Pair(r) == <<r.res, r.act>>

\* The request check of the resource (A406): a live agent, its own active grant
\* before the deadline, the audience, and the permission in both the grant and
\* the owner's current authority, under the policy version that the grant
\* binds. Known-bad variants weaken it.
Check(r) ==
  /\ agent[r.ag] = "active"
  /\ grant.st = "active" /\ grant.ag = r.ag /\ ~grant.late
  /\ r.aud \in grant.auds
  /\ Bad = "noRestrict" \/ Pair(r) \in grant.perms
  /\ Bad = "issuedAuth" \/ Pair(r) \in auth
  /\ Bad = "issuedPolicy" \/ grant.pol = pol

\* The atomic dependency comparison of the commit.
Same(fr) ==
  /\ Bad = "noLifecycle" \/ fr.ag
  /\ Bad = "noRevision" \/ fr.gr
  /\ fr.pol

\* The operations after a change of dependency group f: each checked operation
\* of agent g (of every agent when g is None) is no longer fresh in f.
Stale(f, g) ==
  [o \in Ops |-> IF op[o].st = "checked" /\ (g = None \/ op[o].req.ag = g)
                 THEN [op[o] EXCEPT !.fresh[f] = FALSE]
                 ELSE op[o]]

\* The facts that a property compares at a commit, from the current state.
InGrantNow(r) ==
  /\ grant.st = "active" /\ grant.ag = r.ag /\ ~grant.late
  /\ r.aud \in grant.auds /\ Pair(r) \in grant.perms
OwnerNow(r) == Pair(r) \in auth /\ grant.pol = pol

-----------------------------------------------------------------------------
(* Owner, policy, and agent lifecycle.                                     *)

\* The owner loses one resource permission, for example through a role change.
OwnerChange ==
  /\ ownN < MaxOwn
  /\ \E p \in auth : auth' = auth \ {p}
  /\ ownN' = ownN + 1
  /\ op' = Stale("pol", None)
  /\ UNCHANGED <<pol, agent, grant, held>>

\* A relevant policy change. A change that is not relevant raises no version.
PolicyChange ==
  /\ pol < NPol
  /\ pol' = pol + 1
  /\ op' = Stale("pol", None)
  /\ UNCHANGED <<auth, ownN, agent, grant, held>>

\* Only GrantIssue reads the lifecycle of an agent that does not hold the grant,
\* so its revocation waits until no grant exists.
AgentRevoke(g) ==
  /\ agent[g] = "active"
  /\ grant.st = "none" \/ grant.ag = g
  /\ agent' = [agent EXCEPT ![g] = "revoked"]
  /\ op' = Stale("ag", g)
  /\ UNCHANGED <<pol, auth, ownN, grant, held>>

-----------------------------------------------------------------------------
(* Grants. The authenticated owner approves each transition. A change kills *)
(* the revision that it replaces.                                          *)

\* A new revision for agent g: audiences, permissions within the owner's
\* current authority, a new finite deadline, and the current policy version.
NewRevision(g) ==
  /\ grant.rev < MaxRev
  /\ agent[g] = "active"
  /\ \E A \in (SUBSET Auds) \ {{}},
        P \in {Q \in SUBSET auth : Q # {} /\ Cardinality(Q) <= MaxPerms} :
       grant' = [st |-> "active", ag |-> g, auds |-> A, perms |-> P,
                 late |-> FALSE, rev |-> grant.rev + 1, pol |-> pol]
  /\ op' = Stale("gr", None)
  /\ UNCHANGED <<pol, auth, ownN, agent, held>>

GrantIssue == grant.st = "none" /\ \E g \in Agents : NewRevision(g)

GrantChange == grant.st = "active" /\ NewRevision(grant.ag)

GrantRevoke ==
  /\ grant.st = "active"
  /\ grant' = [grant EXCEPT !.st = "revoked"]
  /\ op' = Stale("gr", None)
  /\ UNCHANGED <<pol, auth, ownN, agent, held>>

\* Time passes the grant deadline. Time is symbolic: only this order matters.
Deadline ==
  /\ grant.st = "active" /\ ~grant.late
  /\ grant' = [grant EXCEPT !.late = TRUE]
  /\ UNCHANGED <<pol, auth, ownN, agent, op, held>>

-----------------------------------------------------------------------------
(* Operations.                                                             *)

\* The agent submits an operation, and the resource checks it. A refused
\* submission changes no state.
Submit(o) ==
  /\ op[o].st = "idle"
  /\ \E r \in Req :
       /\ Check(r)
       /\ op' = [op EXCEPT ![o] = [st |-> "checked", req |-> r,
                                   fresh |-> AllFresh, view |-> "none"]]
  /\ UNCHANGED <<pol, auth, ownN, agent, grant, held>>

\* The operation's own transition: one commit compares every dependency that
\* the check read and checks the deadline.
Commit(o) ==
  /\ op[o].st = "checked"
  /\ LET r == op[o].req IN
       IF Same(op[o].fresh) /\ ~grant.late
       THEN /\ held' = [live    |-> held.live /\ agent[r.ag] = "active",
                        owner   |-> held.owner /\ OwnerNow(r),
                        inGrant |-> held.inGrant /\ InGrantNow(r)]
            /\ op' = [op EXCEPT ![o] = Final("ok")]
       ELSE /\ op' = [op EXCEPT ![o] =
                        IF ~op[o].fresh.ag \/ grant.st = "revoked"
                        THEN Final("revoked")
                        ELSE IF ~Same(op[o].fresh) THEN Final("conflict")
                        ELSE Final("no")]
            /\ UNCHANGED held
  /\ UNCHANGED <<pol, auth, ownN, agent, grant>>

-----------------------------------------------------------------------------

Next ==
  \/ OwnerChange \/ PolicyChange \/ \E g \in Agents : AgentRevoke(g)
  \/ GrantIssue \/ GrantChange \/ GrantRevoke \/ Deadline
  \/ \E o \in Ops : Submit(o) \/ Commit(o)

Spec == Init /\ [][Next]_vars

\* Each set of identical symbols. Init, Next, each property, and each witness
\* target treat the members of each set alike.
Symmetry ==
  Permutations(Agents) \cup Permutations(Ops) \cup Permutations(Auds)
  \cup Permutations(Ress) \cup Permutations(Acts)

-----------------------------------------------------------------------------
(* Properties. Each reads `held`: each commit records there whether the    *)
(* property held, from the facts of the current state.                     *)

\* A revoked agent has no access.
RevokedNoAccess == held.live

\* Effective access is the grant intersected with the owner's current
\* authority, under the current policy version.
EffectiveAccess == held.owner

\* Each accepted operation is within the grant's audiences, resources,
\* actions, and deadline.
WithinGrant == held.inGrant

-----------------------------------------------------------------------------
(* Reachability witnesses. A `_reach` profile passes when the checker      *)
(* reaches a state that violates one of these.                             *)

\* A revocation of the agent or the grant lands between the check and the
\* commit, and the commit refuses.
NotRevocationRace == ~\E o \in Ops : op[o].view = "revoked"

\* An operation commits under an active grant that is narrower than the
\* owner's authority.
NotNarrowGrant ==
  ~(/\ grant.st = "active" /\ grant.perms # auth /\ grant.perms \subseteq auth
    /\ \E o \in Ops : op[o].view = "ok")

=============================================================================
