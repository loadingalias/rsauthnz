-------------------------- MODULE AuthorityCached --------------------------
EXTENDS Authority, TLC

CONSTANTS A1P, A1Q, A1R

\* These three sign-in slots have the same owner and initial state.
\* Keep these copies equal to Authority after the inverse identity renaming.
SymmetricAnchors ==
  {A1P, A1Q, A1R, "a2p", "a2q"} \cup Adms \cup Recoveries
  \cup (IF Raised("slotsA1") THEN {"a1s"} ELSE {})
  \cup (IF Raised("slotsA2") THEN {"a2r"} ELSE {})
  \cup (IF Raised("accounts") THEN {"a3p", "a3q"} ELSE {})

SymmetricOwner(x) ==
  IF x \in {A1P, A1Q, A1R, "a1s", "a1c", "a1d"} THEN "a1"
  ELSE IF x \in {"a2p", "a2q", "a2r", "a2c", "a2d"} THEN "a2"
  ELSE IF x \in {"a3p", "a3q", "a3c"} THEN "a3"
  ELSE "auth"

SymmetricInitLive ==
  {A1P, A1Q, A1R, "a2p"} \cup (Recoveries \ {"a1d", "a2d"})
  \cup (IF Raised("accounts") THEN {"a3p"} ELSE {})
  \cup (IF Origin = "bootstrapped" THEN {"adm1"} ELSE {})

AnchorSymmetry == Permutations({A1P, A1Q, A1R})

\* Materialize the constant anchor sets once for the full TLC searches.
\* The maps call Owner but not Anc or Protected, so overrides have no cycle.
OwnerArgs == Owners \cup {""}

AncValues ==
  TLCEval([a \in OwnerArgs |-> TLCEval({x \in Anchors : Owner(x) = a})])

ProtectedValues ==
  TLCEval([a \in OwnerArgs |-> TLCEval(AncValues[a] \ Recoveries)])

CachedAnc(a) == IF a \in OwnerArgs THEN AncValues[a] ELSE {}

CachedProtected(a) == IF a \in OwnerArgs THEN ProtectedValues[a] ELSE {}

\* Move only constant guards into the candidate domains.
UnlinkCandidates ==
  TLCEval({pair \in Anchors \X Anchors :
    /\ pair[1] /= pair[2]
    /\ Owner(pair[1]) = Owner(pair[2])
    /\ Bad = "countRecovery" \/ pair[2] \in Protected(Owner(pair[1]))})

RecoveryCandidates ==
  TLCEval({pair \in Recoveries \X SignIns :
    /\ pair[1] /= pair[2]
    /\ Owner(pair[1]) = Owner(pair[2])})

\* Propose implies these guards for every candidate plan.
CachedReady(o) ==
  /\ phase = "up"
  /\ pc[o] = "idle"
  /\ \A q \in Ops : Rank[q] < Rank[o] => pc[q] /= "idle"

\* Keep each remaining guard and proposal equal to its action in Authority.
\* A change to either action must also update its cached form.
CachedStartUnlink(o) ==
  /\ CachedReady(o)
  /\ \E <<x, y>> \in UnlinkCandidates :
       /\ anc[x] = "live" /\ anc[y] = "live" /\ Journaled(y)
       /\ Propose(o, Plan("unlink", Owner(x), x, y, "", 0))

CachedStartRecover(o) ==
  /\ CachedReady(o)
  /\ \E <<x, y>> \in RecoveryCandidates :
       /\ anc[x] = "live" /\ anc[y] = "absent"
       /\ \E retired \in SUBSET {z \in Protected(Owner(x)) : anc[z] = "live"} :
            Propose(o, [Plan("recover", Owner(x), x, "", y, 0) EXCEPT !.retire = retired])

\* The leading conjunction keeps each Start family in one TLC action.
\* Every Start action implies these shared Propose guards.
CachedStartGroup(StartAction(_)) ==
  /\ phase = "up"
  /\ \E o \in Ops :
       /\ CachedReady(o)
       /\ StartAction(o)

CachedNextEnroll == CachedStartGroup(StartEnroll)
CachedNextUnlink == CachedStartGroup(CachedStartUnlink)
CachedNextRecover == CachedStartGroup(CachedStartRecover)
CachedNextBoot == CachedStartGroup(StartBoot)
CachedNextRenew == CachedStartGroup(StartRenew)
CachedNextRevoke == CachedStartGroup(StartRevoke)
CachedNextIssueEnd == CachedStartGroup(StartIssueEnd)
CachedNextIssueNone == CachedStartGroup(StartIssueNone)

\* Plain constant operators cache these function spaces without enumerating them.
AnchorStateMaps == [Anchors -> {"absent", "live", "ended"}]
OperationPhaseMaps == [Ops -> {"idle", "acked", "refused"} \cup InFlight \cup Crashed]
OperationPlanMaps == [Ops -> Plans]
OperationNumberMaps == [Ops -> Nat]
OwnerLockMaps == [Owners -> Ops \cup {"none"}]
OperationAnchorMaps == [Ops -> SUBSET Anchors]

\* Expand only the six aliases to recover Authority's complete type predicates.
CachedSnapOK(s) ==
  /\ s.anc \in AnchorStateMaps
  /\ s.bvals \subseteq Vals /\ s.bused \subseteq Vals /\ s.bended \subseteq Vals
  /\ s.cur \in Nat /\ s.dead \in Nat /\ s.revoked \in BOOLEAN /\ s.ctr \in Nat
  /\ s.out \subseteq Ops /\ s.left \in OperationAnchorMaps /\ s.lwm \in Seqs

CachedTypeOK ==
  /\ phase \in {"up", "down", "rec"}
  /\ restored \in BOOLEAN
  /\ anc \in AnchorStateMaps
  /\ bvals \subseteq Vals /\ bused \subseteq Vals /\ bended \subseteq Vals
  /\ cur \in Nat /\ dead \in Nat /\ revoked \in BOOLEAN /\ ctr \in Nat
  /\ out \subseteq Ops /\ pend \subseteq Ops
  /\ pc \in OperationPhaseMaps
  /\ plan \in OperationPlanMaps
  /\ art \in OperationNumberMaps
  /\ lock \in OwnerLockMaps
  /\ jEnd \in [Ops -> Seqs] /\ jCre \in [Ops -> Seqs] /\ jVoid \in [Ops -> Seqs]
  /\ jhead \in Nat /\ jfloor \in Nat
  /\ DOMAIN snaps = SnapIds /\ nSnaps \in 0..NSnaps
  /\ \A i \in SnapIds : SnapOK(snaps[i])
  /\ committed \subseteq Ops
  /\ left \in OperationAnchorMaps
  /\ promised \subseteq Anchors
  /\ bnext \in Nat \ {0}
=============================================================================
