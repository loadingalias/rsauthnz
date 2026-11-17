----------------------- MODULE AuthorityPreservation -----------------------
EXTENDS AuthorityInvariant

\* Each group retains every invariant state through its auxiliary extension.
VARIABLE
  \* @type: Int;
  cutoff

\* A variable survives the checker's operator inlining.
\* @type: (Int) => Bool;
OVERRIDE_AboveNow(n) == n > cutoff

\* Choose the auxiliary before I reads it, then require its exact value.
\* @type: (Bool) => Bool;
LiftInit(I) ==
  /\ \E c \in Int : cutoff = c
  /\ I
  /\ cutoff = LowWater

\* Each branch keeps the original successor and assigns its exact cutoff.
\* @type: (Bool) => Bool;
LiftStep(A) == A /\ cutoff' = LowWater'

\* A group that cannot read AboveNow needs no LowWater constraints.
\* @type: (Bool) => Bool;
UnusedCutoffInit(I) == cutoff = 0 /\ I

\* @type: (Bool) => Bool;
UnusedCutoffStep(A) == A /\ cutoff' = 0

\* Cache only recorded ends with a defined plan operand.
VARIABLE
  \* @type: Set(Str);
  heldEnds

ExactHeldEnds ==
  {o \in Ops :
    IF jEnd[o] > 0 /\ plan[o].kill /= ""
    THEN EndHoldsIn(o, Now)
    ELSE FALSE}

\* @type: (Str) => Bool;
HeldEnd(o) == o \in heldEnds

\* Choose the cache before assumptions or cutoff expressions read it.
\* @type: (Bool) => Bool;
HeldInit(I) ==
  /\ \E h \in SUBSET Ops : heldEnds = h
  /\ I
  /\ heldEnds = ExactHeldEnds

\* The primed choice also precedes a successor cutoff calculation.
\* @type: (Bool) => Bool;
HeldStep(A) ==
  /\ \E h \in SUBSET Ops : heldEnds' = h
  /\ A
  /\ heldEnds' = ExactHeldEnds'

\* A group without a cached consumer imposes no end-fact constraint.
\* @type: (Bool) => Bool;
UnusedHeldInit(I) == heldEnds = {} /\ I

\* @type: (Bool) => Bool;
UnusedHeldStep(A) == A /\ heldEnds' = {}

\* Each copied occurrence is guarded by a positive end entry.
\* The runner pins the original premises and checks the inverse substitution.
\* @type: (Str) => Int;
OVERRIDE_Unreflected(o) ==
  IF Bad = "ownMark" /\ plan[o].own \in Accounts \ {"a1"} THEN jhead + 1
  ELSE Min(IF jEnd[o] > 0 /\ ~HeldEnd(o) /\ jVoid[o] = 0 THEN jEnd[o] ELSE jhead + 1,
           IF jCre[o] > 0 /\ jVoid[o] = 0 /\ anc[plan[o].make] = "absent" THEN jCre[o] ELSE jhead + 1)

\* Separate targets expose each original conjunct's unchanged variables.
AnchorStateInitial ==
  \A x \in InitLive : anc[x] /= "absent" /\ \A i \in ActiveSnaps : LET s == snaps[i] IN s.anc[x] /= "absent"
AnchorStateRecorded ==
  \A x \in Anchors : JournalMade(x) \/ JournalEnded(x) => anc[x] /= "absent"
AnchorStateInFlight ==
  \A o \in Ops : pc[o] \in InFlight =>
       \A x \in Anchors : Ends(plan[o], x) => anc[x] /= "absent"
AnchorStateEnded ==
  \A x \in Anchors : anc[x] = "ended" =>
       \/ x \in EndedAnchors
       \/ \E o \in Ops :
            /\ Ends(plan[o], x) /\ jEnd[o] > 0 /\ jVoid[o] = 0
            /\ pc[o] \in Crashed /\ o \notin committed /\ HeldEnd(o)
AnchorStateSnapshots ==
  \A i \in ActiveSnaps : LET s == snaps[i] IN \A x \in Anchors : s.anc[x] = "ended" => anc[x] = "ended"
AnchorStateAcknowledged ==
  \A o \in Ops : pc[o] = "acked" => o \in committed
AnchorStateOutcomes ==
  \A o \in Ops : pc[o] \in {"committed", "created"} => o \in out
AnchorStateChecked ==
  \A o \in Ops : pc[o] \in {"checked", "cChecked"} => jEnd[o] = 0 /\ jCre[o] = 0 /\ jVoid[o] = 0
AnchorStateOrder ==
  \A o, q \in Ops :
       pc[o] \in InFlight /\ pc[q] \in Crashed =>
         \A e \in {jEnd[o], jCre[o]} : e > 0 => e > jEnd[q] /\ e > jCre[q] /\ e > jVoid[q]

OVERRIDE_AnchorStateInv ==
  /\ AnchorStateInitial
  /\ AnchorStateRecorded
  /\ AnchorStateInFlight
  /\ AnchorStateEnded
  /\ AnchorStateSnapshots
  /\ AnchorStateAcknowledged
  /\ AnchorStateOutcomes
  /\ AnchorStateChecked
  /\ AnchorStateOrder

\* Each action/component pair occurs once. The runner checks this product.
\* Assumptions use only invariant conjuncts, so every invariant state remains.
\* All 67 groups share one 3600-second preservation budget per domain.
StepPrepareRestoreNowAdminEnrollActions ==
  \/ NextEnroll

StepPrepareRestoreNowAdminEnroll == HeldStep(LiftStep(StepPrepareRestoreNowAdminEnrollActions))

StepPrepareRestoreNowAdminEnrollAssumptions ==
  /\ TypeInd
  /\ JournalInv
  /\ AnchorStateInv
  /\ RestoreNowAdminInv

StepPrepareRestoreNowAdminEnrollComponents ==
  /\ RestoreNowAdminInv

StepPrepareRestoreNowAdminEnrollInit == HeldInit(LiftInit(IndStartWith(StepPrepareRestoreNowAdminEnrollAssumptions)))

StepPrepareRestoreNowAdminUnlinkActions ==
  \/ NextUnlink

StepPrepareRestoreNowAdminUnlink == HeldStep(LiftStep(StepPrepareRestoreNowAdminUnlinkActions))

StepPrepareRestoreNowAdminUnlinkAssumptions ==
  /\ TypeInd
  /\ JournalInv
  /\ AnchorStateInv
  /\ RestoreNowAdminInv

StepPrepareRestoreNowAdminUnlinkComponents ==
  /\ RestoreNowAdminInv

StepPrepareRestoreNowAdminUnlinkInit == HeldInit(LiftInit(IndStartWith(StepPrepareRestoreNowAdminUnlinkAssumptions)))

StepPrepareRestoreNowAdminRecoverActions ==
  \/ NextRecover

StepPrepareRestoreNowAdminRecover == HeldStep(LiftStep(StepPrepareRestoreNowAdminRecoverActions))

StepPrepareRestoreNowAdminRecoverAssumptions ==
  /\ TypeInd
  /\ JournalInv
  /\ AnchorStateInv
  /\ RestoreNowAdminInv

StepPrepareRestoreNowAdminRecoverComponents ==
  /\ RestoreNowAdminInv

StepPrepareRestoreNowAdminRecoverInit == HeldInit(LiftInit(IndStartWith(StepPrepareRestoreNowAdminRecoverAssumptions)))

StepPrepareRestoreNowAdminBootActions ==
  \/ NextBoot

StepPrepareRestoreNowAdminBoot == HeldStep(LiftStep(StepPrepareRestoreNowAdminBootActions))

StepPrepareRestoreNowAdminBootAssumptions ==
  /\ TypeInd
  /\ JournalInv
  /\ AnchorStateInv
  /\ RestoreNowAdminInv

StepPrepareRestoreNowAdminBootComponents ==
  /\ RestoreNowAdminInv

StepPrepareRestoreNowAdminBootInit == HeldInit(LiftInit(IndStartWith(StepPrepareRestoreNowAdminBootAssumptions)))

StepPrepareRestoreNowAdminRenewActions ==
  \/ NextRenew

StepPrepareRestoreNowAdminRenew == HeldStep(LiftStep(StepPrepareRestoreNowAdminRenewActions))

StepPrepareRestoreNowAdminRenewAssumptions ==
  /\ TypeInd
  /\ JournalInv
  /\ AnchorStateInv
  /\ RestoreNowAdminInv

StepPrepareRestoreNowAdminRenewComponents ==
  /\ RestoreNowAdminInv

StepPrepareRestoreNowAdminRenewInit == HeldInit(LiftInit(IndStartWith(StepPrepareRestoreNowAdminRenewAssumptions)))

StepPrepareRestoreNowAdminRevokeActions ==
  \/ NextRevoke

StepPrepareRestoreNowAdminRevoke == HeldStep(LiftStep(StepPrepareRestoreNowAdminRevokeActions))

StepPrepareRestoreNowAdminRevokeAssumptions ==
  /\ TypeInd
  /\ JournalInv
  /\ AnchorStateInv
  /\ RestoreNowAdminInv

StepPrepareRestoreNowAdminRevokeComponents ==
  /\ RestoreNowAdminInv

StepPrepareRestoreNowAdminRevokeInit == HeldInit(LiftInit(IndStartWith(StepPrepareRestoreNowAdminRevokeAssumptions)))

StepPrepareRestoreNowAdminIssueEndActions ==
  \/ NextIssueEnd

StepPrepareRestoreNowAdminIssueEnd == HeldStep(LiftStep(StepPrepareRestoreNowAdminIssueEndActions))

StepPrepareRestoreNowAdminIssueEndAssumptions ==
  /\ TypeInd
  /\ JournalInv
  /\ AnchorStateInv
  /\ RestoreNowAdminInv

StepPrepareRestoreNowAdminIssueEndComponents ==
  /\ RestoreNowAdminInv

StepPrepareRestoreNowAdminIssueEndInit == HeldInit(LiftInit(IndStartWith(StepPrepareRestoreNowAdminIssueEndAssumptions)))

StepPrepareRestoreNowAdminIssueNoneActions ==
  \/ NextIssueNone

StepPrepareRestoreNowAdminIssueNone == HeldStep(LiftStep(StepPrepareRestoreNowAdminIssueNoneActions))

StepPrepareRestoreNowAdminIssueNoneAssumptions ==
  /\ TypeInd
  /\ JournalInv
  /\ AnchorStateInv
  /\ RestoreNowAdminInv

StepPrepareRestoreNowAdminIssueNoneComponents ==
  /\ RestoreNowAdminInv

StepPrepareRestoreNowAdminIssueNoneInit == HeldInit(LiftInit(IndStartWith(StepPrepareRestoreNowAdminIssueNoneAssumptions)))

StepRecoveryVoidAnchorStateActions ==
  \/ NextRecVoid

StepRecoveryVoidAnchorState == HeldStep(UnusedCutoffStep(StepRecoveryVoidAnchorStateActions))

StepRecoveryVoidAnchorStateAssumptions ==
  /\ TypeInd
  /\ JournalInv
  /\ AnchorStateInv

StepRecoveryVoidAnchorStateComponents ==
  /\ AnchorStateInv

StepRecoveryVoidAnchorStateInit == HeldInit(UnusedCutoffInit(IndStartWith(StepRecoveryVoidAnchorStateAssumptions)))

StepCommitNowAdminCoreActions ==
  \/ NextCommit
  \/ NextConflict

StepCommitNowAdminCore == HeldStep(LiftStep(StepCommitNowAdminCoreActions))

StepCommitNowAdminCoreAssumptions ==
  /\ TypeInd
  /\ JournalInv
  /\ EndInv
  /\ DoubtInv
  /\ AnchorInv
  /\ AnchorStateInv
  /\ KeptNowInv
  /\ TurnInv

StepCommitNowAdminCoreComponents ==
  /\ RestoreNowAdminInv

StepCommitNowAdminCoreInit == HeldInit(LiftInit(IndStartWith(StepCommitNowAdminCoreAssumptions)))

StepCommitAdminActions ==
  \/ NextJournal
  \/ NextCommit
  \/ NextConflict
  \/ NextCreate
  \/ NextAck
  \/ NextResolve

StepCommitAdmin == HeldStep(UnusedCutoffStep(StepCommitAdminActions))

StepCommitAdminAssumptions ==
  /\ TypeInd
  /\ JournalInv
  /\ EndInv
  /\ OutcomeInv
  /\ AnchorInv
  /\ AnchorStateInv
  /\ TurnInv
  /\ ServingInv

StepCommitAdminComponents ==
  /\ RestoreAdminInv

StepCommitAdminInit == HeldInit(UnusedCutoffInit(IndStartWith(StepCommitAdminAssumptions)))

StepRecoveryAdminRestorableActions ==
  \/ NextRecCreate
  \/ NextRecVoid

StepRecoveryAdminRestorable == HeldStep(UnusedCutoffStep(StepRecoveryAdminRestorableActions))

StepRecoveryAdminRestorableAssumptions ==
  /\ TypeInd
  /\ JournalInv
  /\ EndInv
  /\ OutcomeInv
  /\ AnchorInv
  /\ AnchorStateInv
  /\ TurnInv
  /\ ServingInv

StepRecoveryAdminRestorableComponents ==
  /\ RestoreAdminInv

StepRecoveryAdminRestorableInit == HeldInit(UnusedCutoffInit(IndStartWith(StepRecoveryAdminRestorableAssumptions)))

StepCommitNowAccountCoreActions ==
  \/ NextCommit
  \/ NextConflict

StepCommitNowAccountCore == HeldStep(LiftStep(StepCommitNowAccountCoreActions))

StepCommitNowAccountCoreAssumptions ==
  /\ TypeInd
  /\ JournalInv
  /\ EndInv
  /\ DoubtInv
  /\ AnchorStateInv
  /\ KeptNowInv
  /\ TurnInv
  /\ ServingInv
  /\ RestoreNowAccountInv

StepCommitNowAccountCoreComponents ==
  /\ RestoreNowAccountInv

StepCommitNowAccountCoreInit == HeldInit(LiftInit(IndStartWith(StepCommitNowAccountCoreAssumptions)))

StepPrepareRestoreAdminActions ==
  \/ NextEnroll
  \/ NextUnlink
  \/ NextRecover
  \/ NextBoot
  \/ NextRenew
  \/ NextRevoke
  \/ NextIssueEnd
  \/ NextIssueNone

StepPrepareRestoreAdmin == UnusedHeldStep(UnusedCutoffStep(StepPrepareRestoreAdminActions))

StepPrepareRestoreAdminAssumptions ==
  /\ TypeInd
  /\ JournalInv
  /\ OutcomeInv
  /\ RestoreAdminInv

StepPrepareRestoreAdminComponents ==
  /\ RestoreAdminInv

StepPrepareRestoreAdminInit == UnusedHeldInit(UnusedCutoffInit(IndStartWith(StepPrepareRestoreAdminAssumptions)))

StepCommitNowAdminJournalActions ==
  \/ NextJournal

StepCommitNowAdminJournal == HeldStep(LiftStep(StepCommitNowAdminJournalActions))

StepCommitNowAdminJournalAssumptions ==
  /\ TypeInd
  /\ JournalInv
  /\ EndInv
  /\ OutcomeInv
  /\ DoubtInv
  /\ AnchorStateInv
  /\ KeptNowInv
  /\ TurnInv
  /\ ServingInv
  /\ RestoreNowAdminInv

StepCommitNowAdminJournalComponents ==
  /\ RestoreNowAdminInv

StepCommitNowAdminJournalInit == HeldInit(LiftInit(IndStartWith(StepCommitNowAdminJournalAssumptions)))

StepCommitNowAccountJournalActions ==
  \/ NextJournal

StepCommitNowAccountJournal == HeldStep(LiftStep(StepCommitNowAccountJournalActions))

StepCommitNowAccountJournalAssumptions ==
  /\ TypeInd
  /\ JournalInv
  /\ EndInv
  /\ OutcomeInv
  /\ AnchorStateInv
  /\ TurnInv
  /\ RestoreNowAccountInv

StepCommitNowAccountJournalComponents ==
  /\ RestoreNowAccountInv

StepCommitNowAccountJournalInit == HeldInit(LiftInit(IndStartWith(StepCommitNowAccountJournalAssumptions)))

StepPrepareRestoreAccountActions ==
  \/ NextEnroll
  \/ NextUnlink
  \/ NextRecover
  \/ NextBoot
  \/ NextRenew
  \/ NextRevoke
  \/ NextIssueEnd
  \/ NextIssueNone

StepPrepareRestoreAccount == UnusedHeldStep(UnusedCutoffStep(StepPrepareRestoreAccountActions))

StepPrepareRestoreAccountAssumptions ==
  /\ TypeInd
  /\ JournalInv
  /\ OutcomeInv
  /\ RestoreAccountInv

StepPrepareRestoreAccountComponents ==
  /\ RestoreAccountInv

StepPrepareRestoreAccountInit == UnusedHeldInit(UnusedCutoffInit(IndStartWith(StepPrepareRestoreAccountAssumptions)))

StepPrepareRestoreNowAccountOwnerActions ==
  \/ NextEnroll
  \/ NextUnlink
  \/ NextRecover
  \/ NextBoot

StepPrepareRestoreNowAccountOwner == HeldStep(LiftStep(StepPrepareRestoreNowAccountOwnerActions))

StepPrepareRestoreNowAccountOwnerAssumptions ==
  /\ TypeInd
  /\ JournalInv
  /\ RestoreNowAccountInv

StepPrepareRestoreNowAccountOwnerComponents ==
  /\ RestoreNowAccountInv

StepPrepareRestoreNowAccountOwnerInit == HeldInit(LiftInit(IndStartWith(StepPrepareRestoreNowAccountOwnerAssumptions)))

StepPrepareRestoreNowAccountOwnerlessActions ==
  \/ NextRenew
  \/ NextRevoke
  \/ NextIssueEnd
  \/ NextIssueNone

StepPrepareRestoreNowAccountOwnerless == HeldStep(LiftStep(StepPrepareRestoreNowAccountOwnerlessActions))

StepPrepareRestoreNowAccountOwnerlessAssumptions ==
  /\ TypeInd
  /\ JournalInv
  /\ RestoreNowAccountInv

StepPrepareRestoreNowAccountOwnerlessComponents ==
  /\ RestoreNowAccountInv

StepPrepareRestoreNowAccountOwnerlessInit == HeldInit(LiftInit(IndStartWith(StepPrepareRestoreNowAccountOwnerlessAssumptions)))

StepPrepareRecordsActions ==
  \/ NextEnroll
  \/ NextUnlink
  \/ NextRecover
  \/ NextBoot
  \/ NextRenew
  \/ NextRevoke
  \/ NextIssueEnd
  \/ NextIssueNone

StepPrepareRecords == HeldStep(UnusedCutoffStep(StepPrepareRecordsActions))

StepPrepareRecordsAssumptions ==
  /\ TypeInd
  /\ JournalInv
  /\ AnchorStateInv

StepPrepareRecordsComponents ==
  /\ JournalInv
  /\ AnchorStateInv

StepPrepareRecordsInit == HeldInit(UnusedCutoffInit(IndStartWith(StepPrepareRecordsAssumptions)))

StepPrepareEndActions ==
  \/ NextEnroll
  \/ NextUnlink
  \/ NextRecover
  \/ NextBoot
  \/ NextRenew
  \/ NextRevoke
  \/ NextIssueEnd
  \/ NextIssueNone

StepPrepareEnd == UnusedHeldStep(UnusedCutoffStep(StepPrepareEndActions))

StepPrepareEndAssumptions ==
  /\ TypeInd
  /\ JournalInv
  /\ OutcomeInv
  /\ EndInv

StepPrepareEndComponents ==
  /\ EndInv

StepPrepareEndInit == UnusedHeldInit(UnusedCutoffInit(IndStartWith(StepPrepareEndAssumptions)))

StepPreparePromiseActions ==
  \/ NextEnroll
  \/ NextUnlink
  \/ NextRecover
  \/ NextBoot
  \/ NextRenew
  \/ NextRevoke
  \/ NextIssueEnd
  \/ NextIssueNone

StepPreparePromise == UnusedHeldStep(UnusedCutoffStep(StepPreparePromiseActions))

StepPreparePromiseAssumptions ==
  /\ TypeInd
  /\ JournalInv
  /\ OutcomeInv
  /\ PromiseInv

StepPreparePromiseComponents ==
  /\ PromiseInv

StepPreparePromiseInit == UnusedHeldInit(UnusedCutoffInit(IndStartWith(StepPreparePromiseAssumptions)))

StepPrepareKeptActions ==
  \/ NextEnroll
  \/ NextUnlink
  \/ NextRecover
  \/ NextBoot
  \/ NextRenew
  \/ NextRevoke
  \/ NextIssueEnd
  \/ NextIssueNone

StepPrepareKept == UnusedHeldStep(UnusedCutoffStep(StepPrepareKeptActions))

StepPrepareKeptAssumptions ==
  /\ TypeInd
  /\ DoubtInv
  /\ KeptNowInv

StepPrepareKeptComponents ==
  /\ KeptNowInv

StepPrepareKeptInit == UnusedHeldInit(UnusedCutoffInit(IndStartWith(StepPrepareKeptAssumptions)))

StepPrepareTurnAnchorsActions ==
  \/ NextUnlink
  \/ NextRecover
  \/ NextBoot

StepPrepareTurnAnchors == HeldStep(UnusedCutoffStep(StepPrepareTurnAnchorsActions))

StepPrepareTurnAnchorsAssumptions ==
  /\ TypeInd
  /\ JournalInv
  /\ EndInv
  /\ AnchorStateInv
  /\ PromiseInv
  /\ TurnInv
  /\ ServingInv

StepPrepareTurnAnchorsComponents ==
  /\ TurnInv

StepPrepareTurnAnchorsInit == HeldInit(UnusedCutoffInit(IndStartWith(StepPrepareTurnAnchorsAssumptions)))

StepPrepareTurnPassiveActions ==
  \/ NextEnroll
  \/ NextRenew
  \/ NextRevoke
  \/ NextIssueEnd
  \/ NextIssueNone

StepPrepareTurnPassive == UnusedHeldStep(UnusedCutoffStep(StepPrepareTurnPassiveActions))

StepPrepareTurnPassiveAssumptions ==
  /\ TypeInd
  /\ JournalInv
  /\ TurnInv

StepPrepareTurnPassiveComponents ==
  /\ TurnInv

StepPrepareTurnPassiveInit == UnusedHeldInit(UnusedCutoffInit(IndStartWith(StepPrepareTurnPassiveAssumptions)))

StepPrepareOtherActions ==
  \/ NextEnroll
  \/ NextUnlink
  \/ NextRecover
  \/ NextBoot
  \/ NextRenew
  \/ NextRevoke
  \/ NextIssueEnd
  \/ NextIssueNone

StepPrepareOther == UnusedHeldStep(UnusedCutoffStep(StepPrepareOtherActions))

StepPrepareOtherAssumptions ==
  /\ TypeInd
  /\ JournalInv
  /\ OutcomeInv
  /\ DoubtInv
  /\ AnchorInv
  /\ BootInv
  /\ CounterInv
  /\ ServingInv

StepPrepareOtherComponents ==
  /\ TypeInd
  /\ OutcomeInv
  /\ DoubtInv
  /\ AnchorInv
  /\ BootInv
  /\ CounterInv
  /\ ServingInv

StepPrepareOtherInit == UnusedHeldInit(UnusedCutoffInit(IndStartWith(StepPrepareOtherAssumptions)))

StepCommitNowAdminCreateActions ==
  \/ NextCreate

StepCommitNowAdminCreate == HeldStep(LiftStep(StepCommitNowAdminCreateActions))

StepCommitNowAdminCreateAssumptions ==
  /\ TypeInd
  /\ JournalInv
  /\ TurnInv
  /\ RestoreNowAdminInv

StepCommitNowAdminCreateComponents ==
  /\ RestoreNowAdminInv

StepCommitNowAdminCreateInit == HeldInit(LiftInit(IndStartWith(StepCommitNowAdminCreateAssumptions)))

StepCommitNowAccountCreateActions ==
  \/ NextCreate

StepCommitNowAccountCreate == HeldStep(LiftStep(StepCommitNowAccountCreateActions))

StepCommitNowAccountCreateAssumptions ==
  /\ TypeInd
  /\ JournalInv
  /\ TurnInv
  /\ RestoreNowAccountInv

StepCommitNowAccountCreateComponents ==
  /\ RestoreNowAccountInv

StepCommitNowAccountCreateInit == HeldInit(LiftInit(IndStartWith(StepCommitNowAccountCreateAssumptions)))

StepCommitNowAdminReplyActions ==
  \/ NextAck
  \/ NextResolve

StepCommitNowAdminReply == HeldStep(LiftStep(StepCommitNowAdminReplyActions))

StepCommitNowAdminReplyAssumptions ==
  /\ TypeInd
  /\ JournalInv
  /\ RestoreNowAdminInv

StepCommitNowAdminReplyComponents ==
  /\ RestoreNowAdminInv

StepCommitNowAdminReplyInit == HeldInit(LiftInit(IndStartWith(StepCommitNowAdminReplyAssumptions)))

StepCommitNowAccountReplyActions ==
  \/ NextAck
  \/ NextResolve

StepCommitNowAccountReply == HeldStep(LiftStep(StepCommitNowAccountReplyActions))

StepCommitNowAccountReplyAssumptions ==
  /\ TypeInd
  /\ JournalInv
  /\ RestoreNowAccountInv

StepCommitNowAccountReplyComponents ==
  /\ RestoreNowAccountInv

StepCommitNowAccountReplyInit == HeldInit(LiftInit(IndStartWith(StepCommitNowAccountReplyAssumptions)))

StepCommitValuesActions ==
  \/ NextJournal
  \/ NextCommit
  \/ NextConflict
  \/ NextCreate
  \/ NextAck
  \/ NextResolve

StepCommitValues == UnusedHeldStep(UnusedCutoffStep(StepCommitValuesActions))

StepCommitValuesAssumptions ==
  /\ TypeInd
  /\ JournalInv
  /\ OutcomeInv
  /\ BootInv
  /\ CounterInv

StepCommitValuesComponents ==
  /\ TypeInd
  /\ OutcomeInv
  /\ BootInv
  /\ CounterInv

StepCommitValuesInit == UnusedHeldInit(UnusedCutoffInit(IndStartWith(StepCommitValuesAssumptions)))

StepCommitRecordsActions ==
  \/ NextJournal
  \/ NextCommit
  \/ NextConflict
  \/ NextCreate
  \/ NextAck
  \/ NextResolve

StepCommitRecords == HeldStep(UnusedCutoffStep(StepCommitRecordsActions))

StepCommitRecordsAssumptions ==
  /\ TypeInd
  /\ JournalInv
  /\ OutcomeInv
  /\ AnchorInv
  /\ AnchorStateInv

StepCommitRecordsComponents ==
  /\ JournalInv
  /\ AnchorStateInv

StepCommitRecordsInit == HeldInit(UnusedCutoffInit(IndStartWith(StepCommitRecordsAssumptions)))

StepCommitEndsActions ==
  \/ NextJournal
  \/ NextCommit
  \/ NextConflict
  \/ NextCreate
  \/ NextAck
  \/ NextResolve

StepCommitEnds == UnusedHeldStep(UnusedCutoffStep(StepCommitEndsActions))

StepCommitEndsAssumptions ==
  /\ TypeInd
  /\ JournalInv
  /\ EndInv

StepCommitEndsComponents ==
  /\ EndInv

StepCommitEndsInit == UnusedHeldInit(UnusedCutoffInit(IndStartWith(StepCommitEndsAssumptions)))

StepCommitDoubtActions ==
  \/ NextJournal
  \/ NextCommit
  \/ NextConflict
  \/ NextCreate
  \/ NextAck
  \/ NextResolve

StepCommitDoubt == UnusedHeldStep(UnusedCutoffStep(StepCommitDoubtActions))

StepCommitDoubtAssumptions ==
  /\ TypeInd
  /\ JournalInv
  /\ EndInv
  /\ OutcomeInv
  /\ DoubtInv

StepCommitDoubtComponents ==
  /\ DoubtInv

StepCommitDoubtInit == UnusedHeldInit(UnusedCutoffInit(IndStartWith(StepCommitDoubtAssumptions)))

StepCommitAnchorsActions ==
  \/ NextJournal
  \/ NextCommit
  \/ NextConflict
  \/ NextCreate
  \/ NextAck
  \/ NextResolve

StepCommitAnchors == UnusedHeldStep(UnusedCutoffStep(StepCommitAnchorsActions))

StepCommitAnchorsAssumptions ==
  /\ TypeInd
  /\ JournalInv
  /\ AnchorInv

StepCommitAnchorsComponents ==
  /\ AnchorInv

StepCommitAnchorsInit == UnusedHeldInit(UnusedCutoffInit(IndStartWith(StepCommitAnchorsAssumptions)))

StepCommitPromisesActions ==
  \/ NextJournal
  \/ NextCommit
  \/ NextConflict
  \/ NextCreate
  \/ NextAck
  \/ NextResolve

StepCommitPromises == HeldStep(UnusedCutoffStep(StepCommitPromisesActions))

StepCommitPromisesAssumptions ==
  /\ TypeInd
  /\ JournalInv
  /\ AnchorStateInv
  /\ PromiseInv

StepCommitPromisesComponents ==
  /\ PromiseInv

StepCommitPromisesInit == HeldInit(UnusedCutoffInit(IndStartWith(StepCommitPromisesAssumptions)))

StepCommitKeptActions ==
  \/ NextJournal
  \/ NextCommit
  \/ NextConflict
  \/ NextCreate
  \/ NextAck
  \/ NextResolve

StepCommitKept == UnusedHeldStep(UnusedCutoffStep(StepCommitKeptActions))

StepCommitKeptAssumptions ==
  /\ TypeInd
  /\ DoubtInv
  /\ KeptNowInv

StepCommitKeptComponents ==
  /\ KeptNowInv

StepCommitKeptInit == UnusedHeldInit(UnusedCutoffInit(IndStartWith(StepCommitKeptAssumptions)))

StepCommitTurnActions ==
  \/ NextJournal
  \/ NextCommit
  \/ NextConflict
  \/ NextCreate
  \/ NextAck
  \/ NextResolve

StepCommitTurn == UnusedHeldStep(UnusedCutoffStep(StepCommitTurnActions))

StepCommitTurnAssumptions ==
  /\ TypeInd
  /\ JournalInv
  /\ TurnInv

StepCommitTurnComponents ==
  /\ TurnInv

StepCommitTurnInit == UnusedHeldInit(UnusedCutoffInit(IndStartWith(StepCommitTurnAssumptions)))

StepCommitServingActions ==
  \/ NextJournal
  \/ NextCommit
  \/ NextConflict
  \/ NextCreate
  \/ NextAck
  \/ NextResolve

StepCommitServing == UnusedHeldStep(UnusedCutoffStep(StepCommitServingActions))

StepCommitServingAssumptions ==
  /\ TypeInd
  /\ JournalInv
  /\ ServingInv

StepCommitServingComponents ==
  /\ ServingInv

StepCommitServingInit == UnusedHeldInit(UnusedCutoffInit(IndStartWith(StepCommitServingAssumptions)))

StepCommitAccountActions ==
  \/ NextJournal
  \/ NextCommit
  \/ NextConflict
  \/ NextCreate
  \/ NextAck
  \/ NextResolve

StepCommitAccount == HeldStep(UnusedCutoffStep(StepCommitAccountActions))

StepCommitAccountAssumptions ==
  /\ TypeInd
  /\ JournalInv
  /\ EndInv
  /\ OutcomeInv
  /\ AnchorInv
  /\ AnchorStateInv
  /\ RestoreAccountInv
  /\ TurnInv
  /\ ServingInv

StepCommitAccountComponents ==
  /\ RestoreAccountInv

StepCommitAccountInit == HeldInit(UnusedCutoffInit(IndStartWith(StepCommitAccountAssumptions)))

StepRecoveryTypesActions ==
  \/ NextRecCreate
  \/ NextRecVoid
  \/ NextRedriveFail
  \/ NextCrash
  \/ NextRestart
  \/ NextServe

StepRecoveryTypes == UnusedHeldStep(UnusedCutoffStep(StepRecoveryTypesActions))

StepRecoveryTypesAssumptions ==
  /\ TypeInd

StepRecoveryTypesComponents ==
  /\ TypeInd

StepRecoveryTypesInit == UnusedHeldInit(UnusedCutoffInit(IndStartWith(StepRecoveryTypesAssumptions)))

StepRecoveryOutcomesActions ==
  \/ NextRecCreate
  \/ NextRecVoid
  \/ NextRedrive
  \/ NextRedriveFail
  \/ NextCrash
  \/ NextRestart
  \/ NextServe

StepRecoveryOutcomes == UnusedHeldStep(UnusedCutoffStep(StepRecoveryOutcomesActions))

StepRecoveryOutcomesAssumptions ==
  /\ TypeInd
  /\ JournalInv
  /\ OutcomeInv
  /\ DoubtInv
  /\ BootInv
  /\ ServingInv

StepRecoveryOutcomesComponents ==
  /\ OutcomeInv
  /\ DoubtInv
  /\ BootInv
  /\ ServingInv

StepRecoveryOutcomesInit == UnusedHeldInit(UnusedCutoffInit(IndStartWith(StepRecoveryOutcomesAssumptions)))

StepRecoveryTurnActions ==
  \/ NextRecCreate
  \/ NextRecVoid
  \/ NextRedrive
  \/ NextRedriveFail
  \/ NextCrash
  \/ NextRestart
  \/ NextServe

StepRecoveryTurn == UnusedHeldStep(UnusedCutoffStep(StepRecoveryTurnActions))

StepRecoveryTurnAssumptions ==
  /\ TypeInd
  /\ TurnInv

StepRecoveryTurnComponents ==
  /\ TurnInv

StepRecoveryTurnInit == UnusedHeldInit(UnusedCutoffInit(IndStartWith(StepRecoveryTurnAssumptions)))

StepRecoveryStableAnchorsActions ==
  \/ NextRecCreate
  \/ NextRecVoid
  \/ NextRedriveFail
  \/ NextCrash
  \/ NextRestart
  \/ NextServe

StepRecoveryStableAnchors == UnusedHeldStep(UnusedCutoffStep(StepRecoveryStableAnchorsActions))

StepRecoveryStableAnchorsAssumptions ==
  /\ TypeInd
  /\ JournalInv
  /\ AnchorInv
  /\ CounterInv
  /\ PromiseInv

StepRecoveryStableAnchorsComponents ==
  /\ AnchorInv
  /\ CounterInv
  /\ PromiseInv

StepRecoveryStableAnchorsInit == UnusedHeldInit(UnusedCutoffInit(IndStartWith(StepRecoveryStableAnchorsAssumptions)))

StepRecoveryStableEndsActions ==
  \/ NextRecCreate
  \/ NextRedriveFail
  \/ NextCrash
  \/ NextRestart
  \/ NextServe

StepRecoveryStableEnds == UnusedHeldStep(UnusedCutoffStep(StepRecoveryStableEndsActions))

StepRecoveryStableEndsAssumptions ==
  /\ TypeInd
  /\ JournalInv
  /\ EndInv

StepRecoveryStableEndsComponents ==
  /\ EndInv

StepRecoveryStableEndsInit == UnusedHeldInit(UnusedCutoffInit(IndStartWith(StepRecoveryStableEndsAssumptions)))

StepRecoveryStableJournalActions ==
  \/ NextRedriveFail
  \/ NextCrash
  \/ NextRestart
  \/ NextServe

StepRecoveryStableJournal == UnusedHeldStep(UnusedCutoffStep(StepRecoveryStableJournalActions))

StepRecoveryStableJournalAssumptions ==
  /\ TypeInd
  /\ JournalInv

StepRecoveryStableJournalComponents ==
  /\ JournalInv

StepRecoveryStableJournalInit == UnusedHeldInit(UnusedCutoffInit(IndStartWith(StepRecoveryStableJournalAssumptions)))

StepRecoveryStableKeptActions ==
  \/ NextRecCreate
  \/ NextRecVoid
  \/ NextCrash
  \/ NextRestart
  \/ NextServe

StepRecoveryStableKept == UnusedHeldStep(UnusedCutoffStep(StepRecoveryStableKeptActions))

StepRecoveryStableKeptAssumptions ==
  /\ TypeInd
  /\ KeptNowInv

StepRecoveryStableKeptComponents ==
  /\ KeptNowInv

StepRecoveryStableKeptInit == UnusedHeldInit(UnusedCutoffInit(IndStartWith(StepRecoveryStableKeptAssumptions)))

StepRecoveryStableAnchorStateActions ==
  \/ NextRedriveFail
  \/ NextCrash
  \/ NextRestart
  \/ NextServe

StepRecoveryStableAnchorState == HeldStep(UnusedCutoffStep(StepRecoveryStableAnchorStateActions))

StepRecoveryStableAnchorStateAssumptions ==
  /\ TypeInd
  /\ AnchorStateInv

StepRecoveryStableAnchorStateComponents ==
  /\ AnchorStateInv

StepRecoveryStableAnchorStateInit == HeldInit(UnusedCutoffInit(IndStartWith(StepRecoveryStableAnchorStateAssumptions)))

StepRecoveryStableSnapshotsActions ==
  \/ NextRedrive
  \/ NextRedriveFail
  \/ NextCrash
  \/ NextRestart
  \/ NextServe

StepRecoveryStableSnapshots == UnusedHeldStep(UnusedCutoffStep(StepRecoveryStableSnapshotsActions))

StepRecoveryStableSnapshotsAssumptions ==
  /\ TypeInd
  /\ RestoreAccountInv
  /\ RestoreAdminInv

StepRecoveryStableSnapshotsComponents ==
  /\ RestoreAccountInv
  /\ RestoreAdminInv

StepRecoveryStableSnapshotsInit == UnusedHeldInit(UnusedCutoffInit(IndStartWith(StepRecoveryStableSnapshotsAssumptions)))

StepRecoveryCreateJournalActions ==
  \/ NextRecCreate

StepRecoveryCreateJournal == UnusedHeldStep(UnusedCutoffStep(StepRecoveryCreateJournalActions))

StepRecoveryCreateJournalAssumptions ==
  /\ TypeInd
  /\ JournalInv
  /\ EndInv
  /\ OutcomeInv

StepRecoveryCreateJournalComponents ==
  /\ JournalInv

StepRecoveryCreateJournalInit == UnusedHeldInit(UnusedCutoffInit(IndStartWith(StepRecoveryCreateJournalAssumptions)))

StepRecoveryVoidJournalActions ==
  \/ NextRecVoid

StepRecoveryVoidJournal == UnusedHeldStep(UnusedCutoffStep(StepRecoveryVoidJournalActions))

StepRecoveryVoidJournalAssumptions ==
  /\ TypeInd
  /\ JournalInv
  /\ EndInv

StepRecoveryVoidJournalComponents ==
  /\ JournalInv
  /\ EndInv

StepRecoveryVoidJournalInit == UnusedHeldInit(UnusedCutoffInit(IndStartWith(StepRecoveryVoidJournalAssumptions)))

StepRecoveryCreateAnchorStateActions ==
  \/ NextRecCreate

StepRecoveryCreateAnchorState == HeldStep(UnusedCutoffStep(StepRecoveryCreateAnchorStateActions))

StepRecoveryCreateAnchorStateAssumptions ==
  /\ TypeInd
  /\ JournalInv
  /\ OutcomeInv
  /\ AnchorInv
  /\ AnchorStateInv

StepRecoveryCreateAnchorStateComponents ==
  /\ AnchorStateInv

StepRecoveryCreateAnchorStateInit == HeldInit(UnusedCutoffInit(IndStartWith(StepRecoveryCreateAnchorStateAssumptions)))

StepRecoveryRedriveRecordsActions ==
  \/ NextRedrive

StepRecoveryRedriveRecords == HeldStep(UnusedCutoffStep(StepRecoveryRedriveRecordsActions))

StepRecoveryRedriveRecordsAssumptions ==
  /\ TypeInd
  /\ JournalInv
  /\ EndInv
  /\ DoubtInv
  /\ AnchorStateInv

StepRecoveryRedriveRecordsComponents ==
  /\ TypeInd
  /\ JournalInv
  /\ EndInv

StepRecoveryRedriveRecordsInit == HeldInit(UnusedCutoffInit(IndStartWith(StepRecoveryRedriveRecordsAssumptions)))

StepRecoveryRedriveAnchorsActions ==
  \/ NextRedrive

StepRecoveryRedriveAnchors == HeldStep(UnusedCutoffStep(StepRecoveryRedriveAnchorsActions))

StepRecoveryRedriveAnchorsAssumptions ==
  /\ TypeInd
  /\ JournalInv
  /\ DoubtInv
  /\ AnchorInv
  /\ CounterInv
  /\ AnchorStateInv
  /\ PromiseInv
  /\ KeptNowInv

StepRecoveryRedriveAnchorsComponents ==
  /\ AnchorInv
  /\ CounterInv
  /\ AnchorStateInv
  /\ PromiseInv
  /\ KeptNowInv

StepRecoveryRedriveAnchorsInit == HeldInit(UnusedCutoffInit(IndStartWith(StepRecoveryRedriveAnchorsAssumptions)))

StepRecoveryFailKeptActions ==
  \/ NextRedriveFail

StepRecoveryFailKept == UnusedHeldStep(UnusedCutoffStep(StepRecoveryFailKeptActions))

StepRecoveryFailKeptAssumptions ==
  /\ TypeInd
  /\ DoubtInv
  /\ KeptNowInv

StepRecoveryFailKeptComponents ==
  /\ KeptNowInv

StepRecoveryFailKeptInit == UnusedHeldInit(UnusedCutoffInit(IndStartWith(StepRecoveryFailKeptAssumptions)))

StepRecoveryCreateAccountActions ==
  \/ NextRecCreate

StepRecoveryCreateAccount == UnusedHeldStep(UnusedCutoffStep(StepRecoveryCreateAccountActions))

StepRecoveryCreateAccountAssumptions ==
  /\ TypeInd
  /\ JournalInv
  /\ EndInv
  /\ OutcomeInv
  /\ RestoreAccountInv
  /\ TurnInv

StepRecoveryCreateAccountComponents ==
  /\ RestoreAccountInv

StepRecoveryCreateAccountInit == UnusedHeldInit(UnusedCutoffInit(IndStartWith(StepRecoveryCreateAccountAssumptions)))

StepRecoveryVoidAccountActions ==
  \/ NextRecVoid

StepRecoveryVoidAccount == HeldStep(UnusedCutoffStep(StepRecoveryVoidAccountActions))

StepRecoveryVoidAccountAssumptions ==
  /\ TypeInd
  /\ JournalInv
  /\ EndInv
  /\ OutcomeInv
  /\ AnchorInv
  /\ AnchorStateInv
  /\ RestoreAccountInv
  /\ TurnInv
  /\ ServingInv

StepRecoveryVoidAccountComponents ==
  /\ RestoreAccountInv

StepRecoveryVoidAccountInit == HeldInit(UnusedCutoffInit(IndStartWith(StepRecoveryVoidAccountAssumptions)))

StepRecoveryNotServingActions ==
  \/ NextRecCreate
  \/ NextRecVoid
  \/ NextRedrive
  \/ NextRedriveFail
  \/ NextCrash
  \/ NextRestart

StepRecoveryNotServing == HeldStep(LiftStep(StepRecoveryNotServingActions))

StepRecoveryNotServingAssumptions ==
  /\ TypeInd

StepRecoveryNotServingComponents ==
  /\ RestoreNowAccountInv
  /\ RestoreNowAdminInv

StepRecoveryNotServingInit == HeldInit(LiftInit(IndStartWith(StepRecoveryNotServingAssumptions)))

StepRecoveryServeRestorableActions ==
  \/ NextServe

StepRecoveryServeRestorable == HeldStep(LiftStep(StepRecoveryServeRestorableActions))

StepRecoveryServeRestorableAssumptions ==
  /\ TypeInd
  /\ JournalInv
  /\ AnchorStateInv
  /\ KeptNowInv

StepRecoveryServeRestorableComponents ==
  /\ RestoreNowAccountInv
  /\ RestoreNowAdminInv

StepRecoveryServeRestorableInit == HeldInit(LiftInit(IndStartWith(StepRecoveryServeRestorableAssumptions)))

StepSnapshotPromiseActions ==
  \/ NextSnapshot

StepSnapshotPromise == HeldStep(UnusedCutoffStep(StepSnapshotPromiseActions))

StepSnapshotPromiseAssumptions ==
  /\ TypeInd
  /\ PromiseInv

StepSnapshotPromiseComponents ==
  /\ PromiseInv

StepSnapshotPromiseInit == HeldInit(UnusedCutoffInit(IndStartWith(StepSnapshotPromiseAssumptions)))

StepSnapshotRestorableActions ==
  \/ NextSnapshot

StepSnapshotRestorable == HeldStep(LiftStep(StepSnapshotRestorableActions))

StepSnapshotRestorableAssumptions ==
  /\ TypeInd
  /\ JournalInv
  /\ RestoreAccountInv
  /\ RestoreAdminInv
  /\ RestoreNowAccountInv
  /\ RestoreNowAdminInv

StepSnapshotRestorableComponents ==
  /\ RestoreAccountInv
  /\ RestoreAdminInv

StepSnapshotRestorableInit == HeldInit(LiftInit(IndStartWith(StepSnapshotRestorableAssumptions)))

StepSnapshotServingActions ==
  \/ NextSnapshot

StepSnapshotServing == HeldStep(UnusedCutoffStep(StepSnapshotServingActions))

StepSnapshotServingAssumptions ==
  /\ TypeInd
  /\ JournalInv
  /\ DoubtInv
  /\ KeptNowInv
  /\ ServingInv

StepSnapshotServingComponents ==
  /\ ServingInv

StepSnapshotServingInit == HeldInit(UnusedCutoffInit(IndStartWith(StepSnapshotServingAssumptions)))

StepRestoreAnchorsActions ==
  \/ NextRestore

StepRestoreAnchors == HeldStep(UnusedCutoffStep(StepRestoreAnchorsActions))

StepRestoreAnchorsAssumptions ==
  /\ TypeInd
  /\ JournalInv
  /\ EndInv
  /\ AnchorInv
  /\ AnchorStateInv
  /\ PromiseInv

StepRestoreAnchorsComponents ==
  /\ AnchorStateInv
  /\ PromiseInv

StepRestoreAnchorsInit == HeldInit(UnusedCutoffInit(IndStartWith(StepRestoreAnchorsAssumptions)))

StepRestoreKeptActions ==
  \/ NextRestore

StepRestoreKept == UnusedHeldStep(UnusedCutoffStep(StepRestoreKeptActions))

StepRestoreKeptAssumptions ==
  /\ TypeInd
  /\ JournalInv
  /\ RestoreAccountInv
  /\ RestoreAdminInv

StepRestoreKeptComponents ==
  /\ KeptNowInv

StepRestoreKeptInit == UnusedHeldInit(UnusedCutoffInit(IndStartWith(StepRestoreKeptAssumptions)))

StepSnapshotAnchorsActions ==
  \/ NextSnapshot

StepSnapshotAnchors == HeldStep(UnusedCutoffStep(StepSnapshotAnchorsActions))

StepSnapshotAnchorsAssumptions ==
  /\ TypeInd
  /\ JournalInv
  /\ EndInv
  /\ OutcomeInv
  /\ AnchorStateInv

StepSnapshotAnchorsComponents ==
  /\ EndInv
  /\ AnchorStateInv

StepSnapshotAnchorsInit == HeldInit(UnusedCutoffInit(IndStartWith(StepSnapshotAnchorsAssumptions)))

StepRestoreOtherActions ==
  \/ NextRestore

StepRestoreOther == HeldStep(LiftStep(StepRestoreOtherActions))

StepRestoreOtherAssumptions == IndInv

StepRestoreOtherComponents ==
  /\ TypeInd
  /\ JournalInv
  /\ EndInv
  /\ OutcomeInv
  /\ DoubtInv
  /\ AnchorInv
  /\ BootInv
  /\ CounterInv
  /\ RestoreAccountInv
  /\ RestoreAdminInv
  /\ RestoreNowAccountInv
  /\ RestoreNowAdminInv
  /\ TurnInv
  /\ ServingInv

StepRestoreOtherInit == HeldInit(LiftInit(IndStartWith(StepRestoreOtherAssumptions)))

StepSnapshotOtherActions ==
  \/ NextSnapshot

\* Snapshot retains every input of both exact auxiliary values.
StepSnapshotOther == StepSnapshotOtherActions /\ UNCHANGED <<cutoff, heldEnds>>

StepSnapshotOtherAssumptions == IndInv

StepSnapshotOtherComponents ==
  /\ TypeInd
  /\ JournalInv
  /\ OutcomeInv
  /\ DoubtInv
  /\ AnchorInv
  /\ BootInv
  /\ CounterInv
  /\ KeptNowInv
  /\ RestoreNowAccountInv
  /\ RestoreNowAdminInv
  /\ TurnInv

StepSnapshotOtherInit == HeldInit(LiftInit(IndStartWith(StepSnapshotOtherAssumptions)))

PreservationNext ==
  \/ StepPrepareRestoreNowAdminEnroll
  \/ StepPrepareRestoreNowAdminUnlink
  \/ StepPrepareRestoreNowAdminRecover
  \/ StepPrepareRestoreNowAdminBoot
  \/ StepPrepareRestoreNowAdminRenew
  \/ StepPrepareRestoreNowAdminRevoke
  \/ StepPrepareRestoreNowAdminIssueEnd
  \/ StepPrepareRestoreNowAdminIssueNone
  \/ StepRecoveryVoidAnchorState
  \/ StepCommitNowAdminCore
  \/ StepCommitAdmin
  \/ StepRecoveryAdminRestorable
  \/ StepCommitNowAccountCore
  \/ StepPrepareRestoreAdmin
  \/ StepCommitNowAdminJournal
  \/ StepCommitNowAccountJournal
  \/ StepPrepareRestoreAccount
  \/ StepPrepareRestoreNowAccountOwner
  \/ StepPrepareRestoreNowAccountOwnerless
  \/ StepPrepareRecords
  \/ StepPrepareEnd
  \/ StepPreparePromise
  \/ StepPrepareKept
  \/ StepPrepareTurnAnchors
  \/ StepPrepareTurnPassive
  \/ StepPrepareOther
  \/ StepCommitNowAdminCreate
  \/ StepCommitNowAccountCreate
  \/ StepCommitNowAdminReply
  \/ StepCommitNowAccountReply
  \/ StepCommitValues
  \/ StepCommitRecords
  \/ StepCommitEnds
  \/ StepCommitDoubt
  \/ StepCommitAnchors
  \/ StepCommitPromises
  \/ StepCommitKept
  \/ StepCommitTurn
  \/ StepCommitServing
  \/ StepCommitAccount
  \/ StepRecoveryTypes
  \/ StepRecoveryOutcomes
  \/ StepRecoveryTurn
  \/ StepRecoveryStableAnchors
  \/ StepRecoveryStableEnds
  \/ StepRecoveryStableJournal
  \/ StepRecoveryStableKept
  \/ StepRecoveryStableAnchorState
  \/ StepRecoveryStableSnapshots
  \/ StepRecoveryCreateJournal
  \/ StepRecoveryVoidJournal
  \/ StepRecoveryCreateAnchorState
  \/ StepRecoveryRedriveRecords
  \/ StepRecoveryRedriveAnchors
  \/ StepRecoveryFailKept
  \/ StepRecoveryCreateAccount
  \/ StepRecoveryVoidAccount
  \/ StepRecoveryNotServing
  \/ StepRecoveryServeRestorable
  \/ StepSnapshotPromise
  \/ StepSnapshotRestorable
  \/ StepSnapshotServing
  \/ StepRestoreAnchors
  \/ StepRestoreKept
  \/ StepSnapshotAnchors
  \/ StepRestoreOther
  \/ StepSnapshotOther

\* Exact primed aliases check post-states without a state-zero self-check.
TypeIndPost == TypeInd'
JournalInvPost == JournalInv'
EndInvPost == EndInv'
OutcomeInvPost == OutcomeInv'
DoubtInvPost == DoubtInv'
AnchorInvPost == AnchorInv'
BootInvPost == BootInv'
CounterInvPost == CounterInv'
AnchorStateInvPost == AnchorStateInv'
PromiseInvPost == PromiseInv'
KeptNowInvPost == KeptNowInv'
RestoreAccountInvPost == RestoreAccountInv'
RestoreAdminInvPost == RestoreAdminInv'
RestoreNowAccountInvPost == RestoreNowAccountInv'
RestoreNowAdminInvPost == RestoreNowAdminInv'
TurnInvPost == TurnInv'
ServingInvPost == ServingInv'

\* CommitRecords and RestoreAnchors check every original conjunct separately.
AnchorStateInitialPost == AnchorStateInitial'
AnchorStateRecordedPost == AnchorStateRecorded'
AnchorStateInFlightPost == AnchorStateInFlight'
AnchorStateEndedPost == AnchorStateEnded'
AnchorStateSnapshotsPost == AnchorStateSnapshots'
AnchorStateAcknowledgedPost == AnchorStateAcknowledged'
AnchorStateOutcomesPost == AnchorStateOutcomes'
AnchorStateCheckedPost == AnchorStateChecked'
AnchorStateOrderPost == AnchorStateOrder'
=============================================================================
