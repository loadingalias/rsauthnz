------------------------------- MODULE Approval -------------------------------
(***************************************************************************)
(* Design model of task A400, part 2: one-use operation approval with the  *)
(* operation commit.                                                       *)
(*                                                                         *)
(* Promise: one human assertion pays for at most one effect, of the exact  *)
(* approved request, by the approved instance, under the current grant     *)
(* revision. A lost response, a lost request, a retry, or a restore gives  *)
(* no second effect, and a restore leaves no old approval pending.         *)
(*                                                                         *)
(* Failure: one passkey assertion approves two operations.                 *)
(*                                                                         *)
(* The access check of GrantAccess.tla is an environment choice here: each *)
(* check can pass or refuse, and the grant revision can change at any      *)
(* step. That holds every behavior of the grant side, and more.            *)
(*                                                                         *)
(* Cryptographic verification is an assumption. A challenge is the tuple   *)
(* of the instance identity, the nonce, and the request, so two different  *)
(* tuples never collide. A description stands for its digest. A nonce is   *)
(* fresh: no two instances in the history get the same nonce.              *)
(***************************************************************************)
EXTENDS Naturals, FiniteSets, TLC

CONSTANTS
  Agents,      \* agent identities
  Descs,       \* canonical operation descriptions; each stands for its digest
  Insts,       \* approval instance identities
  Nonces,      \* nonce values; each instance request takes a fresh one
  Ops,         \* stable operation identities of agent submissions
  MaxRev,      \* grant revisions 1..MaxRev
  MaxRestore,  \* restores
  Bad,         \* the known-bad variant, or "none"
  None         \* a model value that differs from every other value

Req   == [ag : Agents, desc : Descs]       \* the request that a digest covers
Chals == Insts \X Nonces \X Req            \* WebAuthn challenges

InstSt  == {"free", "pending", "approved", "consumed", "ended"}
InstRec == [st : InstSt, req : Req \cup {None}, nonce : Nonces \cup {None},
            rev : 0..MaxRev, asr : Chals \cup {None}, ep : 0..MaxRestore]

OpSt  == {"idle", "checked", "closed"}
Views == {"none", "ok", "no", "lost", "unknown"}
OpRec == [st : OpSt, req : Req \cup {None}, ap : Insts \cup {None},
          ep : 0..MaxRestore, view : Views]

\* For each property of an effect, whether it held at every commit so far.
Facts == [bound : BOOLEAN, once : BOOLEAN, outcome : BOOLEAN]

VARIABLES
  grev,    \* the current grant revision (an environment input)
  inst,    \* approval instances (store)
  rec,     \* identities with a committed outcome record (store)
  ep,      \* the store instance number; each restore raises it
  op,      \* each submitted operation
  signed,  \* challenges that the human signed; an attacker can replay each
  used,    \* nonces in use; fresh randomness never repeats one (history)
  done,    \* identities that have an effect (history)
  paid,    \* assertions that paid for an effect (history)
  held     \* the facts of Facts, over every commit so far (history)

vars == <<grev, inst, rec, ep, op, signed, used, done, paid, held>>

FreeInst == [st |-> "free", req |-> None, nonce |-> None, rev |-> 0,
             asr |-> None, ep |-> 0]
IdleOp   == [st |-> "idle", req |-> None, ap |-> None, ep |-> 0, view |-> "none"]
Final(v) == [IdleOp EXCEPT !.st = "closed", !.view = v]

TypeOK ==
  /\ grev \in 1..MaxRev
  /\ inst \in [Insts -> InstRec]
  /\ rec \in SUBSET Ops
  /\ ep \in 0..MaxRestore
  /\ op \in [Ops -> OpRec]
  /\ signed \in SUBSET Chals
  /\ used \in SUBSET Nonces
  /\ done \in SUBSET Ops
  /\ paid \in SUBSET Chals
  /\ held \in Facts

Init ==
  /\ grev = 1
  /\ inst = [i \in Insts |-> FreeInst]
  /\ rec = {}
  /\ ep = 0
  /\ op = [o \in Ops |-> IdleOp]
  /\ signed = {}
  /\ used = {}
  /\ done = {}
  /\ paid = {}
  /\ held = [bound |-> TRUE, once |-> TRUE, outcome |-> TRUE]

-----------------------------------------------------------------------------
(* Checks of the design.                                                   *)

Chal(i) == <<i, inst[i].nonce, inst[i].req>>

\* An unconsumed approval of this exact request under the current grant
\* revision.
ApprovalOK(r, a) ==
  /\ inst[a].st = "approved"
  /\ inst[a].req = r
  /\ Bad = "staleApproval" \/ inst[a].rev = grev

\* The facts that ApprovalBinding compares at a commit: the human signed the
\* challenge of this instance, for this request, under the current revision.
BoundNow(r, a) ==
  /\ inst[a].asr = Chal(a)
  /\ inst[a].req = r
  /\ inst[a].rev = grev

-----------------------------------------------------------------------------
(* The grant side, as an environment.                                      *)

\* A human-approved grant change.
GrantChange ==
  /\ grev < MaxRev
  /\ grev' = grev + 1
  /\ UNCHANGED <<inst, rec, ep, op, signed, used, done, paid, held>>

-----------------------------------------------------------------------------
(* Approval instances.                                                     *)

\* The agent asks for approval of one request. The library records a pending
\* instance with a fresh nonce.
Request(i) ==
  /\ inst[i].st = "free"
  /\ \E n \in Nonces \ used, r \in Req :
       /\ inst' = [inst EXCEPT ![i] = [st |-> "pending", req |-> r, nonce |-> n,
                                       rev |-> 0, asr |-> None, ep |-> ep]]
       /\ used' = used \cup {n}
  /\ UNCHANGED <<grev, rec, ep, op, signed, done, paid, held>>

\* The human signs the challenge of a pending instance with a passkey
\* assertion with user verification.
Sign(i) ==
  /\ inst[i].st = "pending"
  /\ Chal(i) \notin signed
  /\ signed' = signed \cup {Chal(i)}
  /\ UNCHANGED <<grev, inst, rec, ep, op, used, done, paid, held>>

\* The approval transition checks the assertion against the challenge of this
\* instance, and the access check passes. One commit consumes the pending
\* instance and records the one-use approval under the current revision.
Approve(i) ==
  /\ inst[i].st = "pending"
  /\ \E c \in signed :
       /\ IF Bad = "otherInst" THEN c[3] = inst[i].req ELSE c = Chal(i)
       /\ inst' = [inst EXCEPT ![i].st = "approved", ![i].asr = c,
                               ![i].rev = grev]
  /\ UNCHANGED <<grev, rec, ep, op, signed, used, done, paid, held>>

\* Cancellation, the short expiry of the request, or a refused approval.
EndInst(i) ==
  /\ inst[i].st \in {"pending", "approved"}
  /\ inst' = [inst EXCEPT ![i].st = "ended"]
  /\ UNCHANGED <<grev, rec, ep, op, signed, used, done, paid, held>>

-----------------------------------------------------------------------------
(* Operations.                                                             *)

\* The agent submits an operation under a new stable identity. It names an
\* approved instance, or no instance when its permission needs no approval
\* (an environment input). Approve writes nothing that a submission reads, so
\* an earlier submission gives no other outcome.
Submit(o) ==
  /\ op[o].st = "idle"
  /\ \E r \in Req, a \in {None} \cup {i \in Insts : inst[i].st = "approved"} :
       op' = [op EXCEPT ![o] = [st |-> "checked", req |-> r, ap |-> a,
                                ep |-> ep, view |-> "none"]]
  /\ UNCHANGED <<grev, inst, rec, ep, signed, used, done, paid, held>>

\* The operation's own transition: one commit checks the absence of an outcome
\* record of the identity, consumes the approval, and records the outcome. The
\* access check passes; a refusal is CancelOp. The response can be lost.
Commit(o) ==
  /\ op[o].st = "checked"
  /\ LET r  == op[o].req
         a  == op[o].ap
         ok == /\ Bad = "noIdentity" \/ o \notin rec
               /\ op[o].ep = ep
               /\ a = None \/ ApprovalOK(r, a)
     IN IF ok
        THEN /\ LET c == IF a = None THEN None ELSE inst[a].asr IN
                  /\ held' = [bound   |-> held.bound /\ (a # None => BoundNow(r, a)),
                              once    |-> held.once /\ c \notin paid,
                              outcome |-> held.outcome /\ o \notin done]
                  /\ paid' = IF a = None THEN paid ELSE paid \cup {c}
             /\ done' = done \cup {o}
             /\ rec' = rec \cup {o}
             /\ inst' = IF a # None /\ Bad # "separate"
                        THEN [inst EXCEPT ![a].st = "consumed"] ELSE inst
             /\ op' = [op EXCEPT ![o] =
                        IF Bad = "separate" /\ a # None
                        THEN [@ EXCEPT !.st = "closed", !.view = "ok"]
                        ELSE Final("ok")]
                \/ op' = [op EXCEPT ![o] =
                          IF Bad \in {"noIdentity", "separate"}
                          THEN [@ EXCEPT !.st = "closed", !.view = "lost"]
                          ELSE [Final("lost") EXCEPT !.ep = op[o].ep]]
        ELSE /\ op' = [op EXCEPT ![o] =
                         IF o \notin rec /\ op[o].ep # ep THEN Final("unknown")
                         ELSE Final("no")]
             /\ UNCHANGED <<done, paid, held, rec, inst>>
  /\ UNCHANGED <<grev, ep, signed, used>>

\* After a lost response, the agent submits the same identity again. The store
\* answers from the outcome record of the identity. After a restore, a missing
\* record of an earlier store instance is unknown (the A000 rule).
Retry(o) ==
  /\ op[o].st = "closed" /\ op[o].view = "lost"
  /\ op' = [op EXCEPT ![o] =
             IF o \in rec /\ Bad # "noIdentity" THEN Final("ok")
             ELSE IF op[o].ep # ep THEN Final("unknown")
             ELSE [@ EXCEPT !.st = "checked", !.view = "none"]]
  /\ UNCHANGED <<grev, inst, rec, ep, signed, used, done, paid, held>>

\* The agent withdraws a checked operation, or the access check refuses it.
CancelOp(o) ==
  /\ op[o].st = "checked"
  /\ op' = [op EXCEPT ![o] = Final("no")]
  /\ UNCHANGED <<grev, inst, rec, ep, signed, used, done, paid, held>>

\* A crash of the store process or a failed connection: a checked operation
\* loses its request and its response. Durable state stays. A crash loses each
\* checked request at once, which a sequence of these steps covers.
LoseRequest(o) ==
  /\ op[o].st = "checked"
  /\ op' = [op EXCEPT ![o].st = "closed", ![o].view = "lost"]
  /\ UNCHANGED <<grev, inst, rec, ep, signed, used, done, paid, held>>

\* Known-bad variant "separate": a second commit consumes the approval.
ConsumeLate(o) ==
  /\ Bad = "separate"
  /\ o \in rec
  /\ op[o].ap # None
  /\ inst[op[o].ap].st = "approved"
  /\ inst' = [inst EXCEPT ![op[o].ap].st = "consumed"]
  /\ op' = [op EXCEPT ![o].ap = None]
  /\ UNCHANGED <<grev, rec, ep, signed, used, done, paid, held>>

-----------------------------------------------------------------------------
(* Restore.                                                                *)

\* The earlier states of instance i that a restore can install: the free
\* state, each earlier pending or approved state, and a consumed or ended
\* state. Restore ends a pending or approved instance; the known-bad variant
\* "restoreKeeps" keeps it.
Earlier(i) ==
  {FreeInst}
  \cup (IF inst[i].st = "free" THEN {}
        ELSE IF Bad = "restoreKeeps"
        THEN {[inst[i] EXCEPT !.st = "pending", !.asr = None]}
             \cup (IF inst[i].asr = None THEN {}
                   ELSE {[inst[i] EXCEPT !.st = "approved"]})
        ELSE {[inst[i] EXCEPT !.st = "ended"]})
  \cup (IF inst[i].st \in {"consumed", "ended"} THEN {inst[i]} ELSE {})

\* Restore installs an earlier state of the store. It chooses the earlier state
\* of each part on its own, so the model holds every snapshot that a store can
\* have, and more. It raises the store instance number. The grant revision is
\* an environment input, which the restore journal keeps.
Restore ==
  /\ ep < MaxRestore
  /\ \E f \in [Insts -> UNION {Earlier(i) : i \in Insts}] :
       /\ \A i \in Insts : f[i] \in Earlier(i)
       /\ inst' = f
  /\ \E R \in SUBSET rec : rec' = R
  /\ ep' = ep + 1
  /\ UNCHANGED <<grev, op, signed, used, done, paid, held>>

-----------------------------------------------------------------------------

Next ==
  \/ GrantChange
  \/ \E i \in Insts : Request(i) \/ Sign(i) \/ Approve(i) \/ EndInst(i)
  \/ \E o \in Ops : \/ Submit(o) \/ Commit(o) \/ Retry(o) \/ CancelOp(o)
                    \/ LoseRequest(o) \/ ConsumeLate(o)
  \/ Restore

Spec == Init /\ [][Next]_vars

\* Each set of identical symbols. Init, Next, each property, and the witness
\* target treat the members of each set alike.
Symmetry ==
  Permutations(Agents) \cup Permutations(Descs) \cup Permutations(Insts)
  \cup Permutations(Nonces) \cup Permutations(Ops)

-----------------------------------------------------------------------------
(* Properties.                                                             *)

\* An approval applies only to its agent, instance, nonce, digest, and the
\* current grant revision.
ApprovalBinding == held.bound

\* Consumption and the operation commit together, at most once: one human
\* assertion pays for at most one effect, across request loss and restore.
ApprovalOnce == held.once

\* Restore rejects old pending approvals: no instance of an earlier store
\* instance is pending or approved.
RestoreRejects ==
  \A i \in Insts : inst[i].st \in {"pending", "approved"} => inst[i].ep = ep

\* A lost response permits an outcome lookup without a second effect: each
\* identity has at most one effect, and an agent that learned "ok" has one.
OutcomeOnce ==
  /\ held.outcome
  /\ \A o \in Ops : op[o].view = "ok" => o \in done

-----------------------------------------------------------------------------
(* Reachability witness.                                                   *)

\* An operation commits with the human's approval.
NotApprovedWork == paid = {}

=============================================================================
