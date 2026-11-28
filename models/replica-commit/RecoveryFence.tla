--------------------------- MODULE RecoveryFence ---------------------------
EXTENDS Naturals, Sequences, FiniteSets

\* The two destinations compare their own generation. A recovery worker can
\* lose its response or stop after any write. A peer can take over.
CONSTANTS Generations, Packets, Bad
Ops == {1, 2}
Steps == {"end", "create", "void"}
Appends == Steps \cup {"recoverCreate"}
Control == {"fence", "install", "ready", "enable", "activate"}
VARIABLES gen, phase, jgen, jopen, log, flight, event
vars == <<gen, phase, jgen, jopen, log, flight, event>>
Init == /\ gen = 0 /\ phase = "up" /\ jgen = 0 /\ jopen = TRUE
        /\ log = <<>> /\ flight = {} /\ event = "none"

Start ==
  /\ gen < Generations /\ gen' = gen + 1 /\ phase' = "closed"
  /\ UNCHANGED <<jgen, jopen, log, flight, event>>
Packet(k, o) == [kind |-> k, op |-> o, token |-> gen, head |-> IF k \in Appends THEN Len(log) ELSE 0]
Requests ==
  CASE phase = "up" -> {Packet(k, o) : k \in Steps, o \in Ops} \cup {Packet("primary", 0)}
    [] phase = "closed" -> IF jgen = gen /\ ~jopen THEN {Packet("install", 0)} ELSE {Packet("fence", 0)}
    [] phase = "replay" -> {Packet("ready", 0)} \cup {Packet("recoverCreate", o) : o \in Ops}
    [] OTHER -> IF jgen = gen /\ jopen THEN {Packet("activate", 0)} ELSE {Packet("enable", 0)}

Has(o, k) == \E i \in 1..Len(log) : log[i] = <<o, k>>
Stored(k) == IF k = "recoverCreate" THEN "create" ELSE k
Closed(o) == Has(o, "create") \/ Has(o, "void")
Admission(r) == IF r.kind = "recoverCreate" THEN ~jopen ELSE jopen
\* A terminal void can close a retired operation while an earlier append
\* is uncertain. Normal requests can refresh their head after contention.
Accept(r) ==
  CASE r.kind \in Appends ->
         /\ Admission(r) \/ Bad = "journalMode"
         /\ r.token = jgen \/ IF r.kind = "recoverCreate" THEN Bad = "recoveryFence" ELSE Bad = "journalFence"
         /\ (r.head = Len(log) \/ Bad = "head")
         /\ (~Has(r.op, Stored(r.kind)) \/ Bad = "repeat")
         /\ (~Closed(r.op) \/ Bad = "terminal")
    [] r.kind = "primary" -> phase = "up" /\ (r.token = gen \/ Bad = "primaryFence")
    [] r.kind = "fence" -> r.token > jgen
    [] r.kind = "install" -> r.token = gen /\ phase = "closed"
    [] r.kind = "ready" -> r.token = gen /\ phase = "replay" /\ Bad /= "stall"
    [] r.kind = "enable" -> r.token = jgen /\ ~jopen
    [] OTHER -> phase = "ready" /\ (r.token = gen \/ Bad = "activation")

\* Observe the destination and the request at delivery. These observations
\* do not participate in either destination's decision.
Event(r, ok) ==
  CASE r.kind \in Appends /\ ok /\ r.token /= jgen ->
         IF r.kind = "recoverCreate" THEN "oldRecoveryAppend" ELSE "oldJournal"
    [] r.kind \in Appends /\ ok /\ ~Admission(r) -> "wrongMode"
    [] r.kind \in Appends /\ ok /\ r.head /= Len(log) -> "fork"
    [] r.kind \in Appends /\ Admission(r) /\ ~Closed(r.op) /\ ~Has(r.op, Stored(r.kind)) ->
         CASE r.token /= jgen /\ r.head = Len(log) ->
                IF r.kind = "recoverCreate" THEN "fencedRecoveryAppend" ELSE "fencedAppend"
           [] r.token = jgen /\ r.head /= Len(log) -> "headConflict"
           [] OTHER -> "none"
    [] r.kind = "primary" /\ r.token /= gen /\ phase = "up" ->
         IF ok THEN "oldPrimary" ELSE "fencedPrimary"
    [] r.kind = "activate" /\ r.token /= gen /\ phase = "ready" ->
         IF ok THEN "oldWorker" ELSE "fencedWorker"
    [] OTHER -> "none"
Arrive(r) ==
  LET ok == Accept(r) IN
  /\ event' = Event(r, ok)
  /\ IF ~ok THEN UNCHANGED <<phase, jgen, jopen, log>>
     ELSE CASE r.kind \in Appends -> /\ log' = Append(log, <<r.op, Stored(r.kind)>>)
                                     /\ UNCHANGED <<phase, jgen, jopen>>
            [] r.kind = "fence" -> /\ jgen' = r.token /\ jopen' = FALSE /\ UNCHANGED <<phase, log>>
            [] r.kind = "enable" -> /\ jopen' = TRUE /\ UNCHANGED <<phase, jgen, log>>
            [] OTHER -> /\ phase' = CASE r.kind = "install" -> "replay" [] r.kind = "ready" -> "ready"
                                      [] OTHER -> "up"
                        /\ UNCHANGED <<jgen, jopen, log>>
  /\ UNCHANGED gen
Fresh == \E r \in Requests : Arrive(r) /\ UNCHANGED flight
Advance == \E r \in Requests : r.kind \in Control /\ Arrive(r) /\ UNCHANGED flight
Send == \E r \in Requests : /\ Cardinality(flight) < Packets /\ r \notin flight
                            /\ flight' = flight \cup {r}
                            /\ UNCHANGED <<gen, phase, jgen, jopen, log, event>>
Deliver == \E r \in flight : Arrive(r) /\ flight' = flight \ {r}
Next == Start \/ Fresh \/ Send \/ Deliver
Spec == Init /\ [][Next]_vars /\ WF_vars(Advance)

TypeOK ==
  /\ gen \in 0..Generations /\ jgen \in 0..gen /\ jopen \in BOOLEAN
  /\ phase \in {"up", "closed", "replay", "ready"} /\ log \in Seq(Ops \X Steps)
  /\ flight \subseteq [kind : Appends \cup Control \cup {"primary"}, op : 0..2,
                       token : 0..Generations, head : 0..(2 * Cardinality(Ops))]
  /\ Cardinality(flight) <= Packets
  /\ event \in {"none","oldJournal","fencedAppend","fork","headConflict","oldPrimary",
                "fencedPrimary","oldWorker","fencedWorker","oldRecoveryAppend","fencedRecoveryAppend","wrongMode"}
JournalFence == event /= "oldJournal"
RecoveryAppendFence == event /= "oldRecoveryAppend"
JournalAdmission == event /= "wrongMode"
PrimaryFence == event /= "oldPrimary"
CurrentWorker == event /= "oldWorker"
OneSuccessor == event /= "fork"
Once == \A i, j \in 1..Len(log) : log[i] = log[j] => i = j
ClosedStep == \A i \in 1..Len(log) : log[i][2] \in {"create", "void"} =>
                ~\E j \in (i+1)..Len(log) : log[j][1] = log[i][1]
Admitted == phase = "up" => gen = jgen /\ jopen
Returns == (phase /= "up") ~> (phase = "up")
NoDelayedAppend == event /= "fencedAppend"
NoDelayedRecoveryAppend == event /= "fencedRecoveryAppend"
NoDelayedPrimary == event /= "fencedPrimary"
NoDelayedWorker == event /= "fencedWorker"
NoHeadRace == event /= "headConflict"
=============================================================================
