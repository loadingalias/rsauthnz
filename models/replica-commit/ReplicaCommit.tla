--------------------------- MODULE ReplicaCommit ---------------------------
EXTENDS Naturals

\* One changing account record. Server 1 revokes a grant. Each other server
\* changes the same account version. Each server submits one request.
CONSTANTS Servers, Restores, Bad
Peers == 1..Servers
VARIABLES phase, generation, restarted, version, revoked, journal, requests
vars == <<phase, generation, restarted, version, revoked, journal, requests>>
Serving == phase = "up"
States == {"idle", "journal", "sent", "committed", "ack", "conflict", "fenced"}
Done == {"committed", "ack", "conflict", "fenced"}
Fence == <<generation, IF Bad = "join" THEN restarted ELSE 0>>

Init ==
  /\ phase = "up" /\ generation = 0 /\ restarted = 0
  /\ version = 0 /\ revoked = FALSE /\ journal = FALSE
  /\ requests = [p \in Peers |-> [pc |-> "idle", fence |-> <<0, 0>>,
       read |-> 0, written |-> 0, joined |-> 0, replied |-> 0, at |-> 0]]

\* A process reconnects to the active store. Previously sent effects can
\* still arrive. The faulty join changes the fence of every healthy peer.
Join(p) ==
  /\ Serving /\ restarted = 0 /\ restarted' = p
  /\ UNCHANGED <<phase, generation, version, revoked, journal, requests>>

Submit(p) ==
  /\ Serving /\ requests[p].pc = "idle"
  /\ requests' = [requests EXCEPT ![p].fence = Fence, ![p].read = version,
       ![p].joined = restarted,
       ![p].pc = IF p = 1 /\ Bad /= "skipJournal" THEN "journal" ELSE "sent"]
  /\ UNCHANGED <<phase, generation, restarted, version, revoked, journal>>

\* The single revocation fact reaches the separate durability domain. The
\* model can pause on either side of this point and of the primary commit.
Log ==
  /\ Serving /\ requests[1].pc = "journal"
  /\ LET valid == requests[1].fence = Fence IN
     /\ journal' = (journal \/ valid)
     /\ requests' = [requests EXCEPT ![1].pc = IF valid THEN "sent" ELSE "fenced",
          ![1].at = generation, ![1].replied = restarted]
  /\ UNCHANGED <<phase, generation, restarted, version, revoked>>

\* The destination compares its fence and the account version in the write.
\* The reply records the generation and version actually seen at that point.
Apply(p) ==
  /\ Serving /\ requests[p].pc = "sent"
  /\ Bad /= "stall" \/ restarted = 0 \/ restarted = p
  /\ LET r == requests[p]
         result == IF r.fence /= Fence /\ Bad /= "noFence" THEN "fenced"
                   ELSE IF r.read /= version /\ Bad /= "noVersion" THEN "conflict"
                   ELSE "committed"
     IN /\ requests' = [requests EXCEPT ![p].pc = result, ![p].at = generation,
                ![p].written = version, ![p].replied = restarted]
        /\ version' = IF result = "committed" THEN version + 1 ELSE version
        /\ revoked' = (revoked \/ (p = 1 /\ result = "committed"))
  /\ UNCHANGED <<phase, generation, restarted, journal>>

Ack(p) ==
  /\ Serving /\ requests[p].pc = "committed" /\ requests[p].at = generation
  /\ requests' = [requests EXCEPT ![p].pc = "ack"]
  /\ UNCHANGED <<phase, generation, restarted, version, revoked, journal>>

\* Normal admission is closed before installation. An old request can be
\* delivered again as soon as the recovered store serves.
Crash ==
  /\ Serving /\ generation < Restores /\ phase' = "closed"
  /\ UNCHANGED <<generation, restarted, version, revoked, journal, requests>>
Install ==
  /\ phase = "closed" /\ phase' = "replay" /\ generation' = generation + 1
  /\ version' = 0 /\ revoked' = FALSE
  /\ UNCHANGED <<restarted, journal, requests>>
Open ==
  /\ phase = "replay" /\ phase' = "up"
  /\ revoked' = journal
  /\ UNCHANGED <<generation, restarted, version, journal, requests>>

Next == Crash \/ Install \/ Open \/ Log
        \/ \E p \in Peers : Join(p) \/ Submit(p) \/ Apply(p) \/ Ack(p)
Spec == Init /\ [][Next]_vars /\ WF_vars(Log) /\ \A p \in Peers : WF_vars(Apply(p))

TypeOK ==
  /\ phase \in {"up", "closed", "replay"} /\ generation \in 0..Restores
  /\ restarted \in 0..Servers /\ version \in 0..Servers
  /\ revoked \in BOOLEAN /\ journal \in BOOLEAN
  /\ requests \in [Peers -> [pc : States, fence : (0..Restores) \X (0..Servers),
       read : 0..Servers, written : 0..Servers, joined : 0..Servers,
       replied : 0..Servers, at : 0..Restores]]

PeerKeepsFence == \A p \in Peers : LET r == requests[p] IN
  r.pc = "fenced" /\ r.joined /= r.replied /\ p /= r.replied => r.fence[1] /= r.at
CurrentGeneration == \A p \in Peers : LET r == requests[p] IN
  r.pc \in {"committed", "ack"} => r.fence[1] = r.at
CurrentVersion == \A p \in Peers : LET r == requests[p] IN
  r.pc \in {"committed", "ack"} => r.read = r.written
RevocationKept == Serving /\ requests[1].pc = "ack" => revoked
Responsive == (<>[]Serving) =>
  \A p \in Peers : (requests[p].pc \in {"journal", "sent"}) ~> (requests[p].pc \in Done)

\* A peer's already submitted operation commits across a restart. The
\* restarted server also commits on the same account in that generation.
NoPeerCommit == ~\E p \in Peers : LET r == requests[p] IN
  /\ restarted \in Peers /\ restarted /= p /\ r.joined = 0 /\ r.replied = restarted
  /\ r.pc = "ack" /\ requests[restarted].pc = "ack"
  /\ requests[restarted].joined = restarted /\ requests[restarted].at = r.at
NoRecoveredRefusal == ~(Serving /\ revoked /\ requests[1].pc = "ack"
  /\ requests[1].at < generation /\ \E p \in Peers :
      requests[p].pc = "fenced" /\ requests[p].at = generation)
NoRace == ~\E p, q \in Peers :
  /\ requests[p].pc = "ack" /\ requests[q].pc = "conflict"
  /\ requests[p].at = requests[q].at /\ requests[p].read = requests[q].read
=============================================================================
