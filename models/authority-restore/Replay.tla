------------------------------- MODULE Replay -------------------------------
(***************************************************************************)
(* The HTTP-signature replay window ([AUTH HTTP-Signature Replay]): two    *)
(* verifiers that share one replay store, with symbolic integer time.      *)
(*                                                                         *)
(* Promise: for every clock error within its bound, no signature is        *)
(* accepted twice, and no record is removed while a verifier can still     *)
(* accept its signature.                                                   *)
(*                                                                         *)
(* The atomic insert reads the store's clock and refuses once that reading *)
(* reaches expires plus the skew (selected on 2026-11-07). Without that    *)
(* check (known-bad "noInsertCheck"), no finite retention covers the time  *)
(* between a verifier's window check and its insert.                       *)
(*                                                                         *)
(* One signature stands for each: records of different replay identities  *)
(* do not interact (the capacity bound is not modeled).                    *)
(***************************************************************************)
EXTENDS Integers

CONSTANTS
  \* @type: Int;
  Skew,     \* allowed agent clock skew
  \* @type: Int;
  U,        \* uncertainty bound of each physical-time reading
  \* @type: Int;
  MaxWin,   \* maximum window, expires minus created
  \* "none" for the design, or the name of one known-bad variant.
  \* @type: Str;
  Bad

Verifiers == {"v1", "v2"}

VARIABLES
  \* @type: Int;
  now,      \* true physical time; no process reads it
  \* @type: Int;
  created,  \* the signature's created parameter, which the agent chose
  \* @type: Int;
  expires,  \* the signature's expires parameter
  \* @type: Bool;
  rec,      \* the shared store holds the signature's replay record
  \* @type: Int;
  floor,    \* replay floor: the store refuses created at or below it
  \* @type: Str -> Bool;
  checked,  \* the verifier verified signature and window, before its insert
  \* History, for the properties only.
  \* @type: Int;
  accepts,  \* acceptances of the signature
  \* @type: Bool;
  liveGone  \* expiry removed a record that a verifier could still accept

vars == <<now, created, expires, rec, floor, checked, accepts, liveGone>>

\* A physical-time reading: within the uncertainty bound of true time. Each
\* reading of each process is independent; none is monotonic.
Reading(r) == now - U <= r /\ r <= now + U

\* The floor that a start sets from its reading. Known-bad "floorNoSkew"
\* leaves out the skew.
FloorAt(r) == r + (IF Bad = "floorNoSkew" THEN 0 ELSE Skew) + 2 * U

\* The latest store reading at which the insert accepts, exclusive. Known-bad
\* "insertLate" moves it one bound later; "noInsertCheck" has no limit.
InsertBefore(r) ==
  CASE Bad = "noInsertCheck" -> TRUE
    [] Bad = "insertLate" -> r < expires + Skew + U
    [] OTHER -> r < expires + Skew

\* The retention margin. Known-bad "retentionOneU" keeps one bound.
Margin == IF Bad = "retentionOneU" THEN U ELSE 2 * U

\* The verifier window check with its own reading.
WindowOK(r) ==
  /\ created <= r + Skew
  /\ r < expires
  /\ expires - created <= MaxWin

\* Some verifier can still accept the signature now or later: it is above
\* the floor, and a verifier has verified it and some store reading can
\* still pass the insert check, or a reading within the bound at a present
\* or future time passes the window.
Live ==
  /\ created > floor
  /\ \/ \E v \in Verifiers :
          checked[v] /\ (Bad = "noInsertCheck" \/ now - U < expires + Skew)
     \/ /\ expires - created <= MaxWin
        /\ now - U < expires
        /\ created - Skew < expires

-----------------------------------------------------------------------------
Init ==
  /\ now \in Int
  /\ created \in Int
  /\ expires \in Int
  /\ rec = FALSE
  /\ \E r \in Int : Reading(r) /\ floor = FloorAt(r)
  /\ checked = [v \in Verifiers |-> FALSE]
  /\ accepts = 0
  /\ liveGone = FALSE

\* Time passes.
Tick ==
  /\ \E d \in Int : d > 0 /\ now' = now + d
  /\ UNCHANGED <<created, expires, rec, floor, checked, accepts, liveGone>>

\* A verifier verifies the signature and its window with its own reading.
Check(v) ==
  /\ ~checked[v]
  /\ \E r \in Int : Reading(r) /\ WindowOK(r)
  /\ checked' = [checked EXCEPT ![v] = TRUE]
  /\ UNCHANGED <<now, created, expires, rec, floor, accepts, liveGone>>

\* Atomic acceptance: with its own reading r, the store inserts the replay
\* identity if it is absent, the signature is above the floor, and r is
\* before expires plus the skew. The operation then runs. Otherwise the
\* verifier refuses.
Insert(v) ==
  /\ checked[v]
  /\ checked' = [checked EXCEPT ![v] = FALSE]
  /\ \E r \in Int :
       /\ Reading(r)
       /\ IF ~rec /\ created > floor /\ InsertBefore(r)
          THEN rec' = TRUE /\ accepts' = accepts + 1
          ELSE UNCHANGED <<rec, accepts>>
  /\ UNCHANGED <<now, created, expires, floor, liveGone>>

\* Incremental expiry: the store removes a record when its own reading passes
\* expires plus the skew and twice the uncertainty bound.
Expire ==
  /\ rec
  /\ \E r \in Int : Reading(r) /\ r > expires + Skew + Margin
  /\ rec' = FALSE
  /\ liveGone' = (liveGone \/ Live)
  /\ UNCHANGED <<now, created, expires, floor, checked, accepts>>

\* A start after a restart, or the activation of a restore: the store loses
\* its records, and sets the floor from its start reading. A record that a
\* snapshot keeps can only refuse a signature, so losing every record is the
\* case that the floor must cover.
Start ==
  /\ rec' = FALSE
  /\ \E r \in Int : Reading(r) /\ floor' = FloorAt(r)
  /\ UNCHANGED <<now, created, expires, checked, accepts, liveGone>>

Next ==
  \/ Tick \/ Expire \/ Start
  \/ \E v \in Verifiers : Check(v) \/ Insert(v)

Spec == Init /\ [][Next]_vars

-----------------------------------------------------------------------------
\* No signature is accepted twice.
NoDoubleAccept == accepts <= 1

\* No live record is removed.
NoLiveRemoved == ~liveGone

Safety == NoDoubleAccept /\ NoLiveRemoved

\* The inductive invariant: it holds for every non-negative Skew, U, and
\* MaxWin and every integer time, so Safety holds for behaviors of any
\* length.
IndInv ==
  /\ now \in Int /\ created \in Int /\ expires \in Int /\ floor \in Int
  /\ rec \in BOOLEAN /\ checked \in [Verifiers -> BOOLEAN]
  /\ accepts \in {0, 1} /\ liveGone = FALSE
  \* A verified signature, and an accepted one, has created at most true
  \* time plus the bound and the skew.
  /\ \A v \in Verifiers : checked[v] => created <= now + U + Skew
  /\ accepts = 1 => created <= now + U + Skew
  \* After the acceptance, the record is present, or the floor or the store
  \* clock refuses every later insert.
  /\ accepts = 1 /\ ~rec => created <= floor \/ now - U >= expires + Skew

\* Vacuity witness: IndInv contains the state that the insert check exists
\* for: an accepted signature whose record expiry removed, with a verifier
\* that has verified it and not inserted yet.
NoAcceptedGone == ~(accepts = 1 /\ ~rec /\ created > floor /\ \E v \in Verifiers : checked[v])

\* The constants: the declared bounds are any non-negative values.
Bounds == Skew \in Nat /\ U \in Nat /\ MaxWin \in Nat
ConstInit == Bounds /\ Bad = "none"
NoInsertCheckInit == Bounds /\ Bad = "noInsertCheck"
InsertLateInit == Bounds /\ Bad = "insertLate"
RetentionOneUInit == Bounds /\ Bad = "retentionOneU"
FloorNoSkewInit == Bounds /\ Bad = "floorNoSkew"
=============================================================================
