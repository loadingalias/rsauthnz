-------------------------- MODULE AccountRecovery --------------------------
EXTENDS Naturals

\* One account, successive full recoveries, and one holder of a session,
\* CLI approval, or credential. See README.md for the journal assumptions.
CONSTANTS MaxGeneration, Bad
VARIABLES phase, generation, passkey, accepted, journal, intent,
          evidence, prepared, usedStale, restored, lastUse
state == <<phase, generation, passkey, accepted, journal, intent,
           evidence, prepared, usedStale, restored, lastUse>>

Serving == phase \in {"up", "intent", "committed"}
Generations == 1..MaxGeneration

Init ==
    /\ phase = "up"
    /\ generation = 1 /\ passkey = 1 /\ accepted = 1 /\ journal = 1
    /\ intent = 0 /\ evidence = 0 /\ prepared = 0
    /\ usedStale = FALSE /\ restored = FALSE /\ lastUse = 0

\* The recovery code is valid in this generation. The driver makes its
\* consumption intent durable before it submits the conditional commit.
WriteIntent ==
    /\ phase = "up" /\ generation < MaxGeneration
    /\ intent' = generation + 1 /\ phase' = "intent"
    /\ UNCHANGED <<generation, passkey, accepted, journal, evidence,
                   prepared, usedStale, restored, lastUse>>

\* The store consumes the code, moves the generation, and installs the new
\* passkey in one commit. Accepted is an observer of committed recoveries.
Recover ==
    /\ phase = "intent"
    /\ generation' = intent /\ passkey' = intent
    /\ accepted' = IF intent > accepted THEN intent ELSE accepted
    /\ phase' = "committed"
    /\ UNCHANGED <<journal, intent, evidence, prepared, usedStale, restored, lastUse>>

\* The creation entry becomes durable before the recovery is acknowledged
\* or a restored store starts serving. It covers the passkey and generation.
Record ==
    /\ phase \in {"committed", "replayed"}
    /\ journal' = passkey /\ intent' = 0 /\ phase' = "up"
    /\ UNCHANGED <<generation, passkey, accepted, evidence, prepared,
                   usedStale, restored, lastUse>>

\* Install any earlier committed snapshot. A second crash can interrupt
\* restore, including after replay and before its creation entry is durable.
Restore ==
    /\ \E saved \in 1..accepted : generation' = saved /\ passkey' = saved
    /\ phase' = "down" /\ restored' = FALSE /\ lastUse' = 0
    /\ UNCHANGED <<accepted, journal, intent, evidence, prepared, usedStale>>

\* There is one eligible consumption per generation in this model. Replay
\* completes it under its original identity, or installs the recorded state.
Replay ==
    /\ phase = "down"
    /\ LET selected == IF intent = 0 THEN journal ELSE intent IN
        /\ passkey' = selected
        /\ accepted' = IF selected > accepted THEN selected ELSE accepted
        /\ restored' = (generation < selected /\ selected = MaxGeneration)
        /\ generation' = IF Bad = "snapshot" THEN generation ELSE selected
    /\ phase' = "replayed"
    /\ UNCHANGED <<journal, intent, evidence, prepared, usedStale, lastUse>>

\* A successful verification or CLI approval belongs to the generation of
\* its authority. The holder can keep it while one or more recoveries run.
Obtain ==
    /\ Serving /\ prepared = 0
    /\ evidence' = passkey
    /\ UNCHANGED <<phase, generation, passkey, accepted, journal, intent,
                   prepared, usedStale, restored, lastUse>>

Prepare ==
    /\ Serving /\ evidence # 0 /\ prepared = 0
    /\ evidence = generation \/ Bad = "retag"
    /\ prepared' = generation
    /\ UNCHANGED <<phase, generation, passkey, accepted, journal, intent,
                   evidence, usedStale, restored, lastUse>>

\* The accepted effect and its comparison share the store transaction.
Commit ==
    /\ Serving /\ prepared # 0
    /\ IF prepared = generation \/ Bad = "skipCommitCheck"
       THEN /\ usedStale' = (usedStale \/ evidence # generation)
            /\ lastUse' = evidence
       ELSE UNCHANGED <<usedStale, lastUse>>
    /\ prepared' = 0 /\ evidence' = 0
    /\ UNCHANGED <<phase, generation, passkey, accepted, journal, intent, restored>>

Next == WriteIntent \/ Recover \/ Record \/ Restore \/ Replay \/ Obtain \/ Prepare \/ Commit
Spec == Init /\ [][Next]_state

TypeOK ==
    /\ phase \in {"up", "intent", "committed", "down", "replayed"}
    /\ {generation, passkey, accepted, journal} \subseteq Generations
    /\ {intent, evidence, prepared, lastUse} \subseteq 0..MaxGeneration
    /\ usedStale \in BOOLEAN /\ restored \in BOOLEAN

CurrentAfterRestore == Serving => generation = accepted /\ passkey = generation
CurrentAtCommit == ~usedStale

\* A new use after restore can succeed even after two recoveries. Restore
\* clears lastUse, so an earlier success cannot supply the witness.
NoRestoredUse == ~(restored /\ lastUse = MaxGeneration /\ journal = MaxGeneration)
=============================================================================
