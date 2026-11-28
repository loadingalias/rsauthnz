----------------------------- MODULE OwnerTurn -----------------------------
EXTENDS Naturals, FiniteSets

\* One account begins with all its sign-in methods. A different server
\* asks to remove each method. The primary writes affect different keys.
CONSTANTS Methods, Bad
Keys == 1..Methods
Active == {"check", "checked", "ready", "committed", "aborting"}
Terminal == {"ack", "refused"}
VARIABLES pc, live, ends, voids, flight, delayed
vars == <<pc, live, ends, voids, flight, delayed>>

Init ==
  /\ pc = [k \in Keys |-> "idle"] /\ live = Keys
  /\ ends = {} /\ voids = {} /\ flight = {} /\ delayed = {}

\* The shared reservation and its operation phase survive the process.
\* A local turn permits a second server to enter the same owner.
Take(k) ==
  /\ pc[k] = "idle"
  /\ Bad = "local" \/ ~\E q \in Keys : pc[q] \in Active
  /\ pc' = [pc EXCEPT ![k] = "check"]
  /\ UNCHANGED <<live, ends, voids, flight, delayed>>
Check(k) ==
  /\ pc[k] = "check"
  /\ pc' = [pc EXCEPT ![k] =
       IF (live \ (ends \ voids)) \ {k} = {} THEN "refused" ELSE "checked"]
  /\ UNCHANGED <<live, ends, voids, flight, delayed>>
Log(k) ==
  /\ pc[k] = "checked" /\ k \notin ends /\ ends' = ends \cup {k}
  /\ UNCHANGED <<pc, live, voids, flight, delayed>>
Ready(k) ==
  /\ pc[k] = "checked" /\ k \in ends /\ pc' = [pc EXCEPT ![k] = "ready"]
  /\ UNCHANGED <<live, ends, voids, flight, delayed>>
Send(k) ==
  /\ pc[k] = "ready" /\ k \notin flight /\ flight' = flight \cup {k}
  /\ UNCHANGED <<pc, live, ends, voids, delayed>>

\* A helper can retire the pending primary write. Its conditional update
\* competes with Apply on the same operation phase. The packet survives.
Retire(k) ==
  /\ pc[k] = "ready" /\ pc' = [pc EXCEPT ![k] = "aborting"]
  /\ UNCHANGED <<live, ends, voids, flight, delayed>>
Apply(k) ==
  /\ k \in flight /\ flight' = flight \ {k}
  /\ IF pc[k] = "ready"
     THEN /\ live' = live \ {k} /\ pc' = [pc EXCEPT ![k] = "committed"]
          /\ UNCHANGED delayed
     ELSE /\ delayed' = IF pc[k] = "refused" /\ \E q \in Keys : pc[q] \in Active
                        THEN delayed \cup {k} ELSE delayed
          /\ live' = IF Bad = "late" THEN live \ {k} ELSE live
          /\ UNCHANGED pc
  /\ UNCHANGED <<ends, voids>>
Void(k) ==
  /\ pc[k] = "aborting" /\ k \notin voids /\ voids' = voids \cup {k}
  /\ UNCHANGED <<pc, live, ends, flight, delayed>>
Finish(k) ==
  /\ pc[k] = "committed" \/ (pc[k] = "aborting" /\ k \in voids)
  /\ Bad /= "hold"
  /\ pc' = [pc EXCEPT ![k] = IF @ = "committed" THEN "ack" ELSE "refused"]
  /\ UNCHANGED <<live, ends, voids, flight, delayed>>

Advance(k) == Check(k) \/ Log(k) \/ Ready(k) \/ Send(k) \/ Apply(k) \/ Void(k) \/ Finish(k)
Next == \E k \in Keys : Take(k) \/ Retire(k) \/ Advance(k)
Spec == Init /\ [][Next]_vars /\ \A k \in Keys : WF_vars(Advance(k))

TypeOK ==
  /\ pc \in [Keys -> Active \cup Terminal \cup {"idle"}]
  /\ live \subseteq Keys /\ ends \subseteq Keys /\ voids \subseteq ends
  /\ flight \subseteq Keys /\ delayed \subseteq Keys
KeepsSignIn == live /= {} /\ Keys \ (ends \ voids) /= {}
RefusalHolds == \A k \in Keys : pc[k] = "refused" => k \in live /\ k \notin (ends \ voids)
Settles == \A k \in Keys : (pc[k] \in Active) ~> (pc[k] \in Terminal)

NoLastRefusal == ~(Cardinality(live) = 1 /\ \E k \in live : pc[k] = "refused" /\ k \notin ends)
NoTakeover == ~\E k, q \in Keys :
  k \in delayed /\ k \in voids /\ pc[k] = "refused" /\ pc[q] = "ack"
=============================================================================
