------------------------------ MODULE Fencing ------------------------------
EXTENDS Naturals

\* The store instance is durable before reconciliation starts. A delayed
\* request retains the instance of its sender. Its other dependencies still
\* hold, so only the instance check can refuse a stale request.
CONSTANTS MaxInstance, NRequests, Bad

Requests == 1..NRequests
Results == {"idle", "pending", "committed", "refused"}

VARIABLES instance, phase, requestAt, result, committedAt
vars == <<instance, phase, requestAt, result, committedAt>>

Init ==
  /\ instance = 1
  /\ phase = "up"
  /\ requestAt = [o \in Requests |-> 0]
  /\ result = [o \in Requests |-> "idle"]
  /\ committedAt = [o \in Requests |-> 0]

\* A submitted request can remain at the remote store across a crash.
Submit(o) ==
  /\ phase = "up"
  /\ result[o] = "idle"
  /\ requestAt' = [requestAt EXCEPT ![o] = instance]
  /\ result' = [result EXCEPT ![o] = "pending"]
  /\ UNCHANGED <<instance, phase, committedAt>>

Crash ==
  /\ phase /= "down"
  /\ phase' = "down"
  /\ UNCHANGED <<instance, requestAt, result, committedAt>>

\* This atomic durable write comes before any reconciliation or new work.
Start ==
  /\ phase = "down"
  /\ instance < MaxInstance
  /\ instance' = instance + 1
  /\ phase' = "rec"
  /\ UNCHANGED <<requestAt, result, committedAt>>

Serve ==
  /\ phase = "rec"
  /\ phase' = "up"
  /\ UNCHANGED <<instance, requestAt, result, committedAt>>

\* The remote store can complete a request in any phase, also after a
\* physical crash but before Start. The instance read and commit are one
\* conditional transaction. The faulty binding omits that dependency.
Complete(o) ==
  /\ result[o] = "pending"
  /\ IF requestAt[o] = instance \/ Bad = "noInstance"
     THEN /\ result' = [result EXCEPT ![o] = "committed"]
          /\ committedAt' = [committedAt EXCEPT ![o] = instance]
     ELSE /\ result' = [result EXCEPT ![o] = "refused"]
          /\ UNCHANGED committedAt
  /\ UNCHANGED <<instance, phase, requestAt>>

Next == Crash \/ Start \/ Serve \/ \E o \in Requests : Submit(o) \/ Complete(o)
Spec == Init /\ [][Next]_vars

TypeOK ==
  /\ instance \in 1..MaxInstance
  /\ phase \in {"up", "down", "rec"}
  /\ requestAt \in [Requests -> 0..MaxInstance]
  /\ result \in [Requests -> Results]
  /\ committedAt \in [Requests -> 0..MaxInstance]

NoStaleCommit ==
  \A o \in Requests : result[o] = "committed" => committedAt[o] = requestAt[o]

\* One old request refuses after Start, and a new request commits. This
\* witness requires both the delayed-request path and continued service.
NoCrossing ==
  ~\E o, q \in Requests :
    /\ result[o] = "refused" /\ requestAt[o] < instance
    /\ result[q] = "committed" /\ requestAt[q] = instance
=============================================================================
