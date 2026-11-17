------------------------- MODULE AuthorityRecovery -------------------------
EXTENDS Authority

\* Before the first restore, submit at most one operation. After it, keep
\* every recovery step and crash, but submit no new work and restore no
\* second snapshot. Each redrive then runs at most once, so this slice is
\* finite without a counter constraint. Fairness is unchanged.
OneRestoreNext ==
  /\ IF restored THEN RecoveryStep \/ Crash ELSE Next
  /\ \A o \in Ops \ {"o1"} : pc'[o] = "idle"
OneRestoreSpec == Init /\ [][OneRestoreNext]_vars /\ WF_vars(RecoveryStep)

\* A client may submit no work. This slice keeps exactly that behavior of
\* RecoverySpec. The NoServe fault then has a three-state fair counterexample.
\* No constraint removes a recovery step or changes its fairness.
IdleRecovery == Init /\ [][Crash \/ Restart \/ Serve]_vars /\ WF_vars(Restart \/ Serve)
=============================================================================
