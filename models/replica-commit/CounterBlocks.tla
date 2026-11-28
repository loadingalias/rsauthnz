--------------------------- MODULE CounterBlocks ---------------------------
EXTENDS Integers
CONSTANTS Servers, Blocks, Width, Restores, Bad
Peers == 1..Servers
Limit == Blocks * Width
Values == 1..Limit
None == [read |-> 0, value |-> 0]
VARIABLES floor, readFloor, unused, pending, current, round, grants, used, event
vars == <<floor, readFloor, unused, pending, current, round, grants, used, event>>
Init ==
  /\ floor = 0 /\ readFloor = [p \in Peers |-> -1] /\ unused = [p \in Peers |-> {}]
  /\ pending = [p \in Peers |-> None] /\ current = 0 /\ round = 0
  /\ grants = [p \in Peers |-> {}] /\ used = {} /\ event = "none"

Read(p) ==
  /\ readFloor[p] = -1 /\ unused[p] = {} /\ floor < Limit
  /\ readFloor' = [readFloor EXCEPT ![p] = floor]
  /\ UNCHANGED <<floor, unused, pending, current, round, grants, used, event>>
\* The independent journal compares and raises its floor in one durable
\* write. A lost reply can abandon the whole block.
Reserve(p) ==
  LET base == readFloor[p]
      block == (base+1)..(base+Width)
      previous == UNION {grants[q] : q \in Peers}
  IN
  /\ base >= 0 /\ readFloor' = [readFloor EXCEPT ![p] = -1]
  /\ IF base = floor \/ Bad = "overlap"
     THEN /\ floor' = base + Width /\ unused' = [unused EXCEPT ![p] = block]
          /\ grants' = [grants EXCEPT ![p] = @ \cup block]
          /\ event' = IF block \cap previous /= {} THEN "overlap" ELSE "none"
     ELSE UNCHANGED <<floor, unused, grants, event>>
  /\ UNCHANGED <<pending, current, round, used>>

Prepare(p) ==
  /\ pending[p] = None /\ unused[p] /= {}
  /\ LET v == CHOOSE n \in unused[p] : \A w \in unused[p] : n <= w
     IN /\ unused' = [unused EXCEPT ![p] = @ \ {v}]
        /\ pending' = [pending EXCEPT ![p] = [read |-> current, value |-> v]]
  /\ UNCHANGED <<floor, readFloor, current, round, grants, used, event>>
Replace(p) ==
  LET r == pending[p] IN
  /\ r /= None /\ pending' = [pending EXCEPT ![p] = None]
  /\ IF (r.read = current \/ Bad = "predecessor") /\ (r.value > r.read \/ Bad = "older")
     THEN /\ current' = r.value /\ used' = used \cup {r.value}
          /\ event' = CASE r.value \in used -> "reused" [] r.read /= current -> "stale"
                        [] r.value <= current -> "older" [] OTHER -> "none"
     ELSE /\ UNCHANGED <<current, used>>
          /\ event' = IF r.read = current /\ r.value < current THEN "discarded" ELSE "none"
  /\ UNCHANGED <<floor, readFloor, unused, round, grants>>
Leave(p) ==
  /\ readFloor' = [readFloor EXCEPT ![p] = -1] /\ unused' = [unused EXCEPT ![p] = {}]
  /\ pending' = [pending EXCEPT ![p] = None]
  /\ UNCHANGED <<floor, current, round, grants, used, event>>
Restore ==
  /\ round < Restores /\ round' = round + 1 /\ current' \in used \cup {0}
  /\ floor' = IF Bad = "floorRestore" THEN 0 ELSE floor
  /\ readFloor' = [p \in Peers |-> -1] /\ unused' = [p \in Peers |-> {}]
  /\ pending' = [p \in Peers |-> None]
  /\ UNCHANGED <<grants, used, event>>
Next == Restore \/ \E p \in Peers : Read(p) \/ Reserve(p) \/ Prepare(p) \/ Replace(p) \/ Leave(p)
Spec == Init /\ [][Next]_vars
TypeOK ==
  /\ floor \in 0..Limit /\ readFloor \in [Peers -> (-1)..Limit] /\ round \in 0..Restores
  /\ unused \in [Peers -> SUBSET Values] /\ grants \in [Peers -> SUBSET Values]
  /\ pending \in [Peers -> [read : 0..Limit, value : 0..Limit]]
  /\ current \in 0..Limit /\ used \subseteq Values
  /\ event \in {"none","overlap","reused","stale","older","discarded"}
Disjoint == event /= "overlap" /\ \A p, q \in Peers : p /= q => grants[p] \cap grants[q] = {}
FreshValue == event /= "reused"
CurrentPredecessor == event /= "stale"
Increasing == event /= "older"
NoOlderBlock == ~(event = "discarded" /\ \E p, q \in Peers :
                  p /= q /\ current \in grants[q] /\ \E n \in grants[p] : n < current)
=============================================================================
