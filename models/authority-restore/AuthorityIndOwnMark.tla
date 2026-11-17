------------------------ MODULE AuthorityIndOwnMark ------------------------
EXTENDS AuthorityInvariant

\* Keep the low-water-mark fault separate from the statically sound proof.
OVERRIDE_Bad == "ownMark"
OVERRIDE_Turn == "creation"
OVERRIDE_Raise == "none"
\* State 3 of the retained TLC OwnMark trace: after StartUnlink(o1) and
\* JournalEnd(o1), before the first Snapshot. Assign every variable, including
\* inactive snapshot slots. IndInv checks membership in the positive starting
\* set; this concrete seed is used only to qualify the wrong implementation.
OwnMarkInit ==
  /\ Origin = "new"
  /\ phase = "up"
  /\ restored = FALSE
  /\ anc = [x \in Anchors |-> IF x \in InitLive THEN "live" ELSE "absent"]
  /\ bvals = {1}
  /\ bused = {}
  /\ bended = {}
  /\ cur = 1
  /\ dead = 0
  /\ revoked = FALSE
  /\ ctr = 1
  /\ out = {}
  /\ pend = {}
  /\ pc = [o \in Ops |-> IF o = "o1" THEN "journaled" ELSE "idle"]
  /\ plan = [o \in Ops |-> IF o = "o1" THEN Plan("unlink", "a2", "a2c", "a2p", "", 0) ELSE NoPlan]
  /\ art = [o \in Ops |-> 0]
  /\ lock = [a \in Owners |-> "none"]
  /\ jEnd = [o \in Ops |-> IF o = "o1" THEN 1 ELSE 0]
  /\ jCre = [o \in Ops |-> 0]
  /\ jVoid = [o \in Ops |-> 0]
  /\ jhead = 1
  /\ jfloor = 1
  /\ committed = {}
  /\ left = [o \in Ops |-> {}]
  /\ promised = InitLive
  /\ bnext = 1
  /\ snaps = [i \in SnapIds |-> Now]
  /\ nSnaps = 0
  /\ IndInv
=============================================================================
