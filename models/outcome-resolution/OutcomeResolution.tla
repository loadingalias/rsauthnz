------------------------- MODULE OutcomeResolution -------------------------
EXTENDS Naturals
CONSTANTS Copies, Bad

\* All copies carry one original operation, binding, generation and retention
\* window. The primary owns the row and the admission test at each write.
VARIABLES generation, window, row, packets, commits, resolution, seen, helped, late
vars == <<generation, window, row, packets, commits, resolution, seen, helped, late>>
rows == {"empty", "held", "done", "closed"}
answers == {"committed", "fresh", "unknown"}
Init ==
    /\ generation = 0 /\ window = "open" /\ row = "empty" /\ packets = Copies
    /\ commits = 0 /\ resolution = "idle" /\ seen = "none" /\ helped = FALSE /\ late = FALSE

Admits == (generation = 0 \/ Bad = "oldGeneration") /\ (window = "open" \/ Bad = "oldWindow")
Covered == (generation = 0 \/ Bad = "restoreProof") /\ (window = "open" \/ Bad = "expiryProof")

\* Optional durable preparation. A plain write can arrive before this step.
Prepare ==
    /\ Admits /\ row = "empty" /\ packets > 0 /\ row' = "held"
    /\ UNCHANGED <<generation, window, packets, commits, resolution, seen, helped, late>>

\* One original packet arrives. A receipt, a closure, or a retired scope
\* prevents the write, even if the caller lost all previous replies.
Deliver ==
    /\ packets > 0 /\ packets' = packets - 1
    /\ late' = (late \/ (resolution = "fresh" /\ generation = 0 /\ window = "open"))
    /\ IF Admits /\ (row \in {"empty", "held"} \/ (row = "closed" /\ Bad = "ignoreClose"))
       THEN /\ row' = "done" /\ commits' = commits + 1
       ELSE UNCHANGED <<row, commits>>
    /\ UNCHANGED <<generation, window, resolution, seen, helped>>

\* A status read can observe a retained decision. It never decides the request.
Inspect ==
    /\ seen' = IF row = "empty" THEN "unknown" ELSE row
    /\ row' = IF Bad = "statusCloses" /\ row = "empty" THEN "closed" ELSE row
    /\ UNCHANGED <<generation, window, packets, commits, resolution, helped, late>>

Begin ==
    /\ resolution = "idle" /\ resolution' = "waiting"
    /\ UNCHANGED <<generation, window, row, packets, commits, seen, helped, late>>

\* Help and seal each compare the row at the primary. Learning the decision
\* is a separate step, so a crash or lost reply can intervene.
Resolve ==
    /\ resolution = "waiting"
    /\ CASE row = "done" ->
              /\ resolution' = "committed" /\ UNCHANGED <<row, commits, helped>>
         [] row = "closed" ->
              /\ resolution' = "fresh" /\ UNCHANGED <<row, commits, helped>>
         [] row = "held" /\ Admits ->
              /\ row' = "done" /\ commits' = commits + 1 /\ helped' = TRUE /\ UNCHANGED resolution
         [] (row = "held" /\ ~Admits) \/ (row = "empty" /\ Covered) ->
              /\ IF Bad = "readEmpty" /\ row = "empty"
                 THEN /\ resolution' = "fresh" /\ UNCHANGED row
                 ELSE /\ row' = "closed" /\ UNCHANGED resolution
              /\ UNCHANGED <<commits, helped>>
         [] OTHER ->
              /\ resolution' = "unknown" /\ UNCHANGED <<row, commits, helped>>
    /\ UNCHANGED <<generation, window, packets, seen, late>>

\* Close admission for this attempt before retention can remove its decision.
RetireWindow ==
    /\ window = "open" /\ window' = "retired"
    /\ UNCHANGED <<generation, row, packets, commits, resolution, seen, helped, late>>
Prune ==
    /\ window = "retired" \/ Bad = "earlyPrune"
    /\ row \in {"done", "closed"} /\ row' = "empty"
    /\ UNCHANGED <<generation, window, packets, commits, resolution, seen, helped, late>>

\* Install a snapshot from before this operation. The generation is outside
\* its failure domain. The old packets can still reach the primary.
Restore ==
    /\ generation = 0 /\ generation' = 1 /\ row' = "empty"
    /\ UNCHANGED <<window, packets, commits, resolution, seen, helped, late>>

Next == Prepare \/ Deliver \/ Inspect \/ Begin \/ Resolve \/ RetireWindow \/ Prune \/ Restore
Spec == Init /\ [][Next]_vars /\ WF_vars(Resolve)

TypeOK ==
    /\ generation \in 0..1 /\ window \in {"open", "retired"} /\ row \in rows
    /\ packets \in 0..Copies /\ commits \in 0..(Copies+1)
    /\ resolution \in answers \cup {"idle", "waiting"}
    /\ seen \in {"none", "unknown", "held", "done", "closed"} /\ helped \in BOOLEAN /\ late \in BOOLEAN
FreshIsFinal == resolution = "fresh" => commits = 0
AtMostOnce == commits <= 1
ReceiptBacked == (resolution = "committed" \/ seen = "done") => commits > 0
PassiveStatus == resolution = "idle" => row /= "closed"
Returns == (resolution = "waiting") ~> (resolution \in answers)

NoLateRefusal == ~late
NoHelpedReceipt == ~(helped /\ resolution = "committed")
NoExpiredUnknown == ~(generation = 0 /\ window = "retired" /\ commits > 0 /\ resolution = "unknown")
NoRestoredUnknown == ~(generation = 1 /\ window = "open" /\ commits > 0 /\ resolution = "unknown")
=============================================================================
