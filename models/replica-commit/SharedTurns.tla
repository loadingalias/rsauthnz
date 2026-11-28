---------------------------- MODULE SharedTurns ----------------------------
EXTENDS Integers, Sequences

\* Each operation spends one value to create one anchor. The operation ID
\* also names its new anchor. Each caller submits once and can look up a
\* lost response. RecoveryFence checks the destination checks on packets.
CONSTANTS Operations, Restores, Bad
Ops == 1..Operations
Layouts == {"shared", "apart", "overlap"}
Held == {"held", "made", "retired"}
Terminal == {"done", "refused"}
Kinds == {"end", "create", "void"}
VARIABLES layout, pc, asked, log, spent, anchors, out, snap, round, mode,
          ever, lookedUp, missingAtLookup, refused, interrupted, orphan
primary == <<spent, anchors, out>>
receipts == <<lookedUp, missingAtLookup>>
history == <<ever, receipts, refused, interrupted>>
vars == <<layout, pc, asked, log, primary, snap, round, mode, history, orphan>>

Value(o) == IF layout = "shared" THEN 1 ELSE o
Owners(o) == IF layout = "overlap" /\ o = 1 THEN {1, 2} ELSE {Value(o)}
Positions == 1..Len(log)
At(o, k) == {i \in Positions : log[i] = <<o, k>>}
Has(o, k) == At(o, k) /= {}
After(o, k) == \E i \in At(o, k) : i > snap.mark
Created == {o \in Ops : Has(o, "create")}
Image(mark) == [mark |-> mark, spent |-> spent, anchors |-> anchors, out |-> out]

Init ==
  /\ layout \in Layouts /\ pc = [o \in Ops |-> "idle"] /\ asked = {}
  /\ log = <<>> /\ spent = {} /\ anchors = {} /\ out = {}
  /\ snap = Image(-1) /\ round = 0 /\ mode = "up"
  /\ ever = {} /\ lookedUp = {} /\ missingAtLookup = {} /\ refused = {} /\ interrupted = {} /\ orphan = 0

\* Reserve all owners and the operation phase in one primary transaction.
Reserve(o) ==
  /\ mode = "up" /\ o \notin asked
  /\ \A q \in Ops : pc[q] \in Held =>
       (IF Bad = "oneOwner" THEN {Value(o)} \cap {Value(q)} ELSE Owners(o) \cap Owners(q)) = {}
  /\ pc' = [pc EXCEPT ![o] = "held"] /\ asked' = asked \cup {o}
  /\ UNCHANGED <<layout, log, primary, snap, round, mode, history, orphan>>

\* A conditional append is a durable journal step. Reading a stale head
\* gives no append in this projection. RecoveryFence checks that refinement.
AppendStep(o, k) ==
  /\ ~Has(o, k) /\ o \notin Created /\ ~Has(o, "void")
  /\ log' = Append(log, <<o, k>>)
  /\ UNCHANGED <<layout, pc, asked, primary, snap, round, mode, history, orphan>>

\* The primary decision also checks the reservation. Retiring it prevents
\* a delayed primary commit. A second helper can finish either decision.
Decide(o) ==
  /\ pc[o] = "held" /\ Has(o, "end")
  /\ IF Value(o) \notin spent \/ Bad = "spendTwice"
     THEN /\ pc' = [pc EXCEPT ![o] = "made"]
          /\ spent' = spent \cup {Value(o)} /\ anchors' = anchors \cup {o}
          /\ out' = out \cup {o} /\ ever' = ever \cup {o}
     ELSE /\ pc' = [pc EXCEPT ![o] = "retired"] /\ UNCHANGED <<primary, ever>>
  /\ UNCHANGED <<layout, asked, log, snap, round, mode, receipts, refused, interrupted, orphan>>
Retire(o) ==
  /\ mode = "up" /\ pc[o] = "held" /\ Has(o, "end")
  /\ pc' = [pc EXCEPT ![o] = "retired"]
  /\ UNCHANGED <<layout, asked, log, primary, snap, round, mode, history, orphan>>
Finish(o) ==
  /\ (pc[o] = "made" /\ o \in Created)
     \/ (pc[o] = "retired" /\ (Has(o, "void") \/ Bad = "earlyNo"))
  /\ pc' = [pc EXCEPT ![o] = IF @ = "made" THEN "done" ELSE "refused"]
  /\ refused' = IF pc[o] = "retired" THEN refused \cup {o} ELSE refused
  /\ UNCHANGED <<layout, asked, log, primary, snap, round, mode, ever, receipts, interrupted, orphan>>
Help(o) ==
  /\ mode = "up" /\ (Bad /= "ignoreOrphan" \/ orphan /= o)
  /\ \/ pc[o] = "held" /\ AppendStep(o, "end")
     \/ Decide(o)
     \/ pc[o] = "made" /\ AppendStep(o, "create")
     \/ pc[o] = "retired" /\ AppendStep(o, "void")
     \/ Finish(o)
Leave(o) ==
  /\ mode = "up" /\ orphan = 0 /\ pc[o] = "held" /\ Has(o, "end")
  /\ orphan' = o
  /\ UNCHANGED <<layout, pc, asked, log, primary, snap, round, mode, history>>

\* Lookup reads the outcome and the current owner turns in one primary
\* state. Finish releases each committed turn only after its creation.
Related(o) == {q \in Ops \ {o} : Owners(q) \cap Owners(o) /= {}}
Lookup(o) ==
  /\ mode = "up" /\ o \in out /\ (pc[o] /= "made" \/ Bad = "earlyLookup")
  /\ Bad = "peerLookup" \/ \A q \in Related(o) : pc[q] /= "made"
  /\ lookedUp' = lookedUp \cup {o}
  /\ missingAtLookup' = missingAtLookup \cup ((out \ Created) \cap Related(o))
  /\ UNCHANGED <<layout, pc, asked, log, primary, snap, round, mode, ever, refused, interrupted, orphan>>

\* The prefix is immutable. Settlement in this generation is durable.
\* The primary can capture a smaller verified mark while other owners work.
Marks == {n \in 0..Len(log) : \A i \in 1..n : pc[log[i][1]] \in Terminal}
Snapshot ==
  /\ mode = "up" /\ snap.mark = -1
  /\ \E n \in IF Bad = "ownMark" THEN {0} \cup {i \in Positions : pc[log[i][1]] \in Terminal}
               ELSE Marks : snap' = Image(n)
  /\ UNCHANGED <<layout, pc, asked, log, primary, round, mode, history, orphan>>

\* Both destinations have fenced old work before this step. A replacement
\* worker can install the same snapshot after any completed recovery step.
Install ==
  /\ snap.mark >= 0 /\ round < Restores
  /\ round' = round + 1 /\ mode' = "recover" /\ pc' = [o \in Ops |-> "idle"]
  /\ spent' = snap.spent /\ anchors' = snap.anchors /\ out' = snap.out
  /\ interrupted' = IF mode = "recover" THEN interrupted \cup (out \ (snap.out \cup Created)) ELSE interrupted
  /\ UNCHANGED <<layout, asked, log, snap, ever, receipts, refused, orphan>>

Ends == {o \in Ops : After(o, "end") /\ ~Has(o, "void")}
Makes == IF Bad = "skipCreateReplay" THEN {} ELSE {o \in Created : After(o, "create")}
Replayed == {Value(o) : o \in Ends} \subseteq spent /\ Makes \subseteq anchors
Replay(o) ==
  /\ (o \in Ends /\ Value(o) \notin spent) \/ (o \in Makes /\ o \notin anchors)
  /\ spent' = IF o \in Ends THEN spent \cup {Value(o)} ELSE spent
  /\ anchors' = IF o \in Makes THEN anchors \cup {o} ELSE anchors
  /\ UNCHANGED <<layout, pc, asked, log, out, snap, round, mode, history, orphan>>

\* A recorded outcome or creation rules out a different spender. Otherwise
\* the first unvoided intent for this value can complete under its own ID.
Owed(o) ==
  /\ o \in Ends /\ o \notin anchors
  /\ ~\E q \in out \cup Created : Value(q) = Value(o)
  /\ ~\E q \in Ends : Value(q) = Value(o) /\ \E i \in At(q, "end"), j \in At(o, "end") : i < j
Redrive(o) ==
  /\ Replayed /\ Owed(o)
  /\ out' = out \cup {o} /\ anchors' = anchors \cup {o} /\ ever' = ever \cup {o}
  /\ UNCHANGED <<layout, pc, asked, log, spent, snap, round, mode, receipts, refused, interrupted, orphan>>
Open ==
  /\ Replayed /\ out \subseteq Created /\ ~\E o \in Ops : Owed(o)
  /\ mode' = "up"
  /\ UNCHANGED <<layout, pc, asked, log, primary, snap, round, history, orphan>>
Recover ==
  /\ mode = "recover"
  /\ \/ \E o \in Ops : Replay(o) \/ Redrive(o) \/ (o \in out /\ AppendStep(o, "create"))
     \/ Open
Next == Snapshot \/ Install \/ Recover
        \/ \E o \in Ops : Reserve(o) \/ Help(o) \/ Leave(o) \/ Retire(o) \/ Lookup(o)
Spec == Init /\ [][Next]_vars /\ WF_vars(Recover) /\ \A o \in Ops : WF_vars(Help(o))

TypeOK ==
  /\ layout \in Layouts /\ pc \in [Ops -> Held \cup Terminal \cup {"idle"}]
  /\ asked \subseteq Ops /\ log \in Seq(Ops \X Kinds) /\ Len(log) <= 2 * Operations
  /\ spent \subseteq Ops /\ anchors \subseteq Ops /\ out \subseteq Ops
  /\ snap \in [mark : (-1)..(2 * Operations), spent : SUBSET Ops, anchors : SUBSET Ops, out : SUBSET Ops]
  /\ round \in 0..Restores /\ mode \in {"up", "recover"} /\ orphan \in 0..Operations
  /\ ever \subseteq Ops /\ lookedUp \subseteq Ops /\ missingAtLookup \subseteq Ops
  /\ refused \subseteq Ops /\ interrupted \subseteq Ops
Exclusive == \A o, q \in Ops : o /= q /\ pc[o] \in Held /\ pc[q] \in Held => Owners(o) \cap Owners(q) = {}
LookupBacked == lookedUp \subseteq Created
PeerLookupBacked == missingAtLookup = {}
RefusalStaysVoid == \A o \in refused : Has(o, "void") /\ o \notin ever
OneSpender == \A o, q \in ever : Value(o) = Value(q) => o = q
SpentStaysSpent == mode = "up" => {Value(o) : o \in ever} \subseteq spent
AcknowledgedAnchors == mode = "up" => lookedUp \subseteq anchors
Progress == /\ (mode = "recover") ~> (mode = "up")
            /\ \A o \in Ops : (pc[o] \in Held) ~> (pc[o] \notin Held)

NoPeerCompletion == ~(layout = "shared" /\ orphan \in lookedUp /\ round = 0 /\ \E q \in Ops \ {orphan} : q \in refused)
NoWaitingLookup == ~(mode = "up" /\ \E o \in out \cap Created : (out \ Created) \cap Related(o) /= {})
NoMarkGap == ~(snap.mark = 0 /\ Len(log) >= 3 /\ pc[log[1][1]] = "held"
               /\ \E i \in 2..Len(log) : pc[log[i][1]] = "done")
NoRestoredSpend == ~(round > 0 /\ mode = "up" /\ \E o \in lookedUp :
                     o \notin snap.out /\ Value(o) \in spent /\ o \in anchors /\ o \in out)
NoInterruptedRecovery == ~(mode = "up" /\ \E o \in interrupted \cap lookedUp :
                          o \in anchors /\ Value(o) \in spent /\ o \in Created)
=============================================================================
