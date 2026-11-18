//! The conformance suite of the storage contract: the cases that a storage binding passes before an application uses
//! it.
//!
//! The suite is backend-neutral. It checks the primitives of a binding ([`Store`] and [`Journal`]), then runs the
//! commit driver of the core ([`Driver`]) on them. A binding author implements [`Subject`]: the primitives, and the
//! controls of a test, such as a fault at a primitive or a snapshot. [`run`] then runs each [`Case`] on a new binding,
//! and its [`Report`] names each case that failed and each case that the declaration of the binding did not select.
//! Any binding that passes conforms.
//!
//! The suite reads the declaration of each binding. A case that injects a fault runs only for a binding that declares
//! [`CrashInjection::Supported`]. A binding without crash injection carries its own durability evidence. A case that
//! needs the restore journal runs only for a binding that declares [`Restore::Journal`].
//!
//! The suite is asynchronous, so the executor of the binding runs it. The futures of the memory binding are ready at
//! their first poll, so one poll runs the suite on it:
//!
//! ```
//! use core::pin::pin;
//! use core::task::{Context, Poll, Waker};
//!
//! use rsauthnz_conformance::memory::{Memory, Schedule};
//! use rsauthnz_conformance::suite;
//!
//! let mut suite = pin!(suite::run(|| Memory::new(Schedule::None)));
//! let Poll::Ready(report) = suite.as_mut().poll(&mut Context::from_waker(Waker::noop())) else {
//!     unreachable!("the memory binding does no I/O");
//! };
//! assert!(report.failures.is_empty(), "{report}");
//! assert!(report.skipped.is_empty(), "{report}");
//! ```

mod cases;

use core::fmt;
use core::future::poll_fn;
use core::mem;
use core::num::NonZeroUsize;
use core::ops::RangeBounds;
use core::pin::pin;
use core::task::Poll;
use core::time::Duration;
use std::collections::BTreeMap;

use rsauthnz::cbor::Value;
use rsauthnz::id::{Authority, AuthorityVersion, Human, Id, Principal};
use rsauthnz::limits::Limits;
use rsauthnz::store::driver::{self, Answer, Driver, Effect, Lookup, Output, Plan, Status, Ticket};
use rsauthnz::store::journal::{Anchor, History, Mark, Role};
use rsauthnz::store::{
    CrashInjection, Declaration, Journal, Kind, Profile, Record, Restore, Sequence, Store, audit_record,
};
use rsauthnz::time::{Reading, ReadingSource};
use rsauthnz::transition::{
    Audit, Change, Dependency, Effect as Call, Intent, Key, Operation, OperationId, Outcome, Proposal,
};

/// The most effects of one run of the driver until it waits. A run of a case needs far fewer, so more effects show a
/// binding that does not end a step, for example an expiry that always reports a full page.
const EFFECTS_MAX: usize = 10_000;

/// A binding under test: the primitives of the storage contract, and the controls of a test.
///
/// The clones of a subject are handles of one binding, so each concurrent caller takes its own clone. Each control
/// acts on the binding of all its clones. A binding that declares [`Restore::Unsupported`] has no journal: its
/// [`Journal`] methods can fail, because the suite and the driver do not call them.
pub trait Subject: Store + Journal + Clone {
    /// The state of the store that a snapshot keeps.
    type Snapshot;

    /// Gives `fault` to the next call of its primitive: a commit, an append, or a sync. The suite injects a fault only
    /// into a binding that declares [`CrashInjection::Supported`].
    fn inject(&self, fault: Fault);

    /// The loss of the process. The store loses what [`Declaration::crash_loss`] states, and the journal keeps each
    /// entry whose sync returned. The binding serves again after a start.
    fn restart(&self);

    /// A snapshot of the state of the store. The suite takes snapshots only of a binding that declares
    /// [`Restore::Journal`].
    fn snapshot(&self) -> Self::Snapshot;

    /// Restores the state of the store from `snapshot`. The journal keeps its entries, and the binding serves again
    /// after a start. The suite restores only a binding that declares [`Restore::Journal`].
    fn restore(&self, snapshot: &Self::Snapshot);

    /// Removes the durable entries of the journal with a sequence in `sequences`: the loss of entries in the failure
    /// domain of the journal. A later append does not get the sequence of a removed entry. The suite removes entries
    /// only of a binding that declares [`Restore::Journal`].
    fn lose(&self, sequences: impl RangeBounds<Sequence>);
}

/// A fault that the suite gives to one primitive of a binding with [`Subject::inject`]. Each fault is a crash: after
/// it, each primitive except [`Store::start`] gives an error until the next start.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub enum Fault {
    /// The binding crashes before a commit, so the commit writes nothing and gives an error.
    CrashBeforeCommit,
    /// A commit writes everything, but its response is lost: the commit gives an error.
    LostResponse,
    /// The binding crashes after an append gives its sequence, before a sync. The crash loses the append.
    CrashAfterAppend,
    /// A sync fails and gives an error, and no append since the last sync becomes durable.
    FailedSync,
}

/// A case of the suite. Its documentation states the contract that it checks, and the properties of the
/// authority-restore design model that the contract keeps.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub enum Case {
    /// A commit writes its changes, its intents, its audit record, and its outcome record together. A read of the
    /// [`Kind::Audit`] record of the operation gives the audit, and a second submission gets the outcome record.
    Commit,
    /// A commit conflicts and writes nothing when a dependency of each kind does not hold: a policy version, a record
    /// version, or an absence. A commit whose dependencies hold commits.
    DependencyConflict,
    /// Two concurrent consumptions of one value give one commit and one conflict. Properties: `OneUse`, `PendExact`.
    ConcurrentConsumption,
    /// A grant change and a revocation of the grant race. The revocation writes the revocation record, and the change
    /// reads its absence, so only the check of that absence refuses the later one. Snapshot isolation permits this
    /// write skew.
    AbsenceRace,
    /// Expiry removes at most its limit of ended records of its kind, and no other record. Property: `NoLiveRemoved`.
    Expiry,
    /// A commit with the instance number of an earlier start refuses after a start, after a restart, and after a
    /// restore: the delayed commit of an abandoned history. Property: `NoStaleCommit`.
    Fencing,
    /// A commit whose response is lost landed: after the next start, its outcome record and its audit are readable.
    /// A commit that crashes before it lands writes nothing. Property: `MissingOutcomeUnknown`.
    LostResponse,
    /// A failed sync returns its failure and stops the binding. No retried sync serves before a start, and no append
    /// since the last sync is durable.
    FailedSync,
    /// After the loss of the process, the store keeps what its declaration states, and the driver serves again. A
    /// store that loses everything gets its anchors back from the journal. Property: `Recovers`.
    Restart,
    /// A crash at each commit point of the model gives the model's outcome after the next start: no entry, a void, or
    /// the creation entry. A lookup or an anchor change of the owner is answered only after the creation entry is
    /// durable. Properties: `Recovers`, `AnchorKept`.
    CrashPoints,
    /// A commit that returned its refusal leaves no entry that applies at a restore. After a crash between the
    /// refusal and its void, the outcome is unknown. Properties: `AnchorKept`, `RefusalHolds`.
    RefusalVoid,
    /// A restore from an old snapshot applies the journal: no unlinked passkey, revoked session, replaced grant
    /// revision, or revoked one-use value is valid again. It sets the replay floor, and a lookup of a lost outcome is
    /// unknown. Properties: `NothingEndedValid`, `MissingOutcomeUnknown`.
    RestoreJournal,
    /// A restore raises each allocation floor above each released value, also from a snapshot of an abandoned
    /// history. Property: `NoCounterReuse`.
    RestoreFloors,
    /// A restore refuses a journal that has a gap or that does not reach back to the mark of the snapshot.
    RestoreRefusal,
    /// A restore keeps each anchor created after the snapshot that an acknowledged commit saw, and adds no anchor
    /// whose commit did not land. Properties: `AnchorKept`, `AccountKeepsAnchorP`, `NoUncommittedAnchor`.
    RestoreAnchors,
    /// A restore completes an in-doubt bootstrap, recovery, invitation activation, and enrollment once, before it
    /// serves, also after a crash during the completions. Properties: `AccountKeepsAnchorP`, `AdminKeptP`,
    /// `NoDoubtServing`, `OneUse`.
    RestoreCompletions,
    /// After a restore, each pending sign-in challenge and approval refuses. Their consumptions write no journal
    /// entry, and a consumption that pays for an anchor writes one.
    RestoreEnds,
    /// A normal start after a restore voids no entry that the restore applied. Property: `NothingEndedValid`.
    StartAfterRestore,
    /// An owner re-bootstrap ends the earlier bootstrap value and adds one. No restore makes the ended value valid
    /// again, or completes a bootstrap from it. Properties: `OneBootValid`, `NothingEndedValid`, `AdminKeptP`.
    Rebootstrap,
}

impl Case {
    /// Each case, in the order of [`run`].
    pub const ALL: [Self; 19] = [
        Self::Commit,
        Self::DependencyConflict,
        Self::ConcurrentConsumption,
        Self::AbsenceRace,
        Self::Expiry,
        Self::Fencing,
        Self::LostResponse,
        Self::FailedSync,
        Self::Restart,
        Self::CrashPoints,
        Self::RefusalVoid,
        Self::RestoreJournal,
        Self::RestoreFloors,
        Self::RestoreRefusal,
        Self::RestoreAnchors,
        Self::RestoreCompletions,
        Self::RestoreEnds,
        Self::StartAfterRestore,
        Self::Rebootstrap,
    ];

    /// Whether the case runs for a binding with `declaration`.
    fn selected(self, declaration: &Declaration) -> bool {
        let (crash, journal) = (crashes(declaration), journaled(declaration));
        match self {
            Self::Commit
            | Self::DependencyConflict
            | Self::ConcurrentConsumption
            | Self::AbsenceRace
            | Self::Expiry
            | Self::Fencing
            | Self::Restart => true,
            Self::LostResponse => crash,
            Self::RefusalVoid
            | Self::RestoreJournal
            | Self::RestoreFloors
            | Self::RestoreRefusal
            | Self::RestoreAnchors
            | Self::RestoreEnds
            | Self::StartAfterRestore
            | Self::Rebootstrap => journal,
            Self::FailedSync | Self::CrashPoints | Self::RestoreCompletions => crash && journal,
        }
    }

    async fn check<S: Subject>(self, make: &mut impl FnMut() -> S) -> Checked {
        match self {
            Self::Commit => cases::commit(make()).await,
            Self::DependencyConflict => cases::dependency_conflict(make()).await,
            Self::ConcurrentConsumption => cases::concurrent_consumption(make()).await,
            Self::AbsenceRace => cases::absence_race(make()).await,
            Self::Expiry => cases::expiry(make()).await,
            Self::Fencing => cases::fencing(make()).await,
            Self::LostResponse => cases::lost_response(make()).await,
            Self::FailedSync => cases::failed_sync(make()).await,
            Self::Restart => cases::restart(make()).await,
            Self::CrashPoints => cases::crash_points(make()).await,
            Self::RefusalVoid => cases::refusal_void(make()).await,
            Self::RestoreJournal => cases::restore_journal(make()).await,
            Self::RestoreFloors => cases::restore_floors(make()).await,
            Self::RestoreRefusal => cases::restore_refusal(make).await,
            Self::RestoreAnchors => cases::restore_anchors(make()).await,
            Self::RestoreCompletions => cases::restore_completions(make()).await,
            Self::RestoreEnds => cases::restore_ends(make()).await,
            Self::StartAfterRestore => cases::start_after_restore(make()).await,
            Self::Rebootstrap => cases::rebootstrap(make()).await,
        }
    }
}

impl fmt::Display for Case {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        fmt::Debug::fmt(self, f)
    }
}

/// A case that failed, and the check that failed in it.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Failure {
    /// The case.
    pub case: Case,
    /// What the binding did that the contract does not permit.
    pub detail: String,
}

impl fmt::Display for Failure {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "the case {} failed: {}", self.case, self.detail)
    }
}

/// The result of [`run`]. The binding conforms when no case failed.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct Report {
    /// Each case that failed.
    pub failures: Vec<Failure>,
    /// Each case that the declaration of the binding did not select: a crash case of a binding without crash
    /// injection, or a restore case of a binding without a journal.
    pub skipped: Vec<Case>,
}

impl fmt::Display for Report {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        for failure in &self.failures {
            writeln!(f, "{failure}")?;
        }
        for case in &self.skipped {
            writeln!(f, "the declaration of the binding does not select the case {case}")?;
        }
        Ok(())
    }
}

/// Runs each case on a new binding from `make`, after a check of the declaration with [`Profile::new`]. `make` gives a
/// binding with an empty store and an empty journal, which no other caller uses: one for the declaration, and one for
/// each case.
pub async fn run<S: Subject>(mut make: impl FnMut() -> S) -> Report {
    let declaration = make().declaration();
    let profile = Profile::new(declaration.clone());
    let mut report = Report::default();
    for case in Case::ALL {
        if !case.selected(&declaration) {
            report.skipped.push(case);
            continue;
        }
        let checked = match &profile {
            Ok(_) => case.check(&mut make).await,
            Err(error) => Err(format!("the profile refuses the declaration: {error}")),
        };
        if let Err(detail) = checked {
            report.failures.push(Failure { case, detail });
        }
    }
    report
}

/// Whether a binding with `declaration` takes injected faults.
fn crashes(declaration: &Declaration) -> bool {
    declaration.crash_injection == CrashInjection::Supported
}

/// Whether a binding with `declaration` keeps a restore journal.
const fn journaled(declaration: &Declaration) -> bool {
    matches!(declaration.restore, Restore::Journal { .. })
}

/// The result of a check: `Err` with what failed.
type Checked = Result<(), String>;

/// `Ok` when `holds`, else `Err` with `detail`.
fn ensure(holds: bool, detail: &str) -> Checked {
    holds.ok_or_else(|| detail.to_owned())
}

/// The detail of a primitive that failed with no fault.
fn failed<E: fmt::Display>(primitive: &'static str) -> impl FnOnce(E) -> String {
    move |error| format!("{primitive} failed with no fault: {error}")
}

/// The most entries, intents, or records of one read of the suite.
const PAGE: NonZeroUsize = driver::PAGE;

/// The bytes of each record that the suite writes.
const DATA: &[u8] = b"record";

/// The end of each pending ceremony and short-lived value that the suite writes: after [`now`].
const LATER: Duration = Duration::from_secs(2_000);

/// The reading of each decision of the suite.
fn now() -> Reading {
    Reading::new(
        Duration::from_secs(1_000),
        Some(Duration::from_secs(1)),
        ReadingSource::Caller,
    )
}

/// The authority of the suite: the owner of each version.
fn authority() -> Id<Authority> {
    Id::new("acme", "auth").expect("the authority of the suite is a valid identifier")
}

fn account(name: &str) -> Id<Human> {
    Id::new("acme", name).expect("each account of the suite is a valid identifier")
}

fn sign_in(name: &str) -> Role {
    Role::SignIn(account(name))
}

/// The version `n` of the authority, which compares in the order of `n`.
fn version(n: u64) -> AuthorityVersion {
    AuthorityVersion::new(authority(), &n.to_be_bytes()).expect("a coordinate of eight bytes is valid")
}

fn key(kind: Kind, id: &str) -> Key {
    kind.key(id.as_bytes())
        .expect("each record of the suite has a short key")
}

fn op(name: &str) -> OperationId {
    OperationId::new(name.as_bytes()).expect("each operation of the suite has a short identity")
}

/// The anchor that [`Build::writes`] of `key` creates.
fn anchor(key: &Key, role: Role) -> Anchor {
    Anchor {
        key: key.clone(),
        role,
        version: version(1),
        end: None,
        data: DATA.into(),
    }
}

/// The plan of a proposal: the anchors that the store holds of its owners, the writes that replace a dead version,
/// and each anchor that it creates.
fn plan(held: &[Anchor], replaced: &[&Key], anchors: &[(&Key, Role)]) -> Plan {
    Plan {
        held: held.to_vec(),
        replaced: replaced.iter().map(|key| (*key).clone()).collect(),
        anchors: anchors
            .iter()
            .map(|(key, role)| ((*key).clone(), role.clone()))
            .collect(),
    }
}

/// Whether `stored` has the version and the record form of `expected`. The binding sets the end of an audit or an
/// outcome record from its retention, so the end can differ.
fn same(stored: Option<&Record>, expected: &Record) -> bool {
    stored.is_some_and(|stored| stored.version == expected.version && stored.data == expected.data)
}

/// The proposal of an operation of the suite, built one read and change after the other. Each version is a version of
/// [`version`].
struct Build(Proposal);

impl Build {
    fn new(name: &str) -> Self {
        let audit = Audit {
            actor: Principal::Human(account("u-1")),
            action: Id::new("acme.auth", "suite").expect("the action of the suite is a valid identifier"),
            time: now(),
        };
        Self(Proposal::new(op(name), audit, &Value::Null, Limits::default()).expect("a null request has a form"))
    }

    fn read(mut self, dependency: Dependency) -> Self {
        self.0
            .read(dependency)
            .expect("a proposal of the suite reads each record once, within the limits");
        self
    }

    fn change(mut self, change: Change) -> Self {
        self.0
            .change(change)
            .expect("a proposal of the suite changes each record once, after its read");
        self
    }

    /// Reads the policy at version `at`.
    fn policy(self, at: u64) -> Self {
        self.read(Dependency::Policy(version(at)))
    }

    /// Reads the record `key` at version `at`.
    fn reads(self, key: &Key, at: u64) -> Self {
        self.read(Dependency::Version(key.clone(), version(at)))
    }

    /// Reads the absence of the record `key`.
    fn lacks(self, key: &Key) -> Self {
        self.read(Dependency::Absent(key.clone()))
    }

    /// Reads the record `key` at version `at`, and ends it.
    fn ends(self, key: &Key, at: u64) -> Self {
        self.reads(key, at).change(Change::End(key.clone()))
    }

    /// Reads the absence of the record `key`, and writes it at version `at` with `end`.
    fn writes_until(self, key: &Key, at: u64, end: Option<Duration>) -> Self {
        self.lacks(key).change(Change::Write {
            key: key.clone(),
            version: version(at),
            end,
            data: DATA.into(),
        })
    }

    /// Reads the absence of the record `key`, and writes it at version `at` with no end.
    fn writes(self, key: &Key, at: u64) -> Self {
        self.writes_until(key, at, None)
    }

    /// Reads the record `key` at version `from`, and writes it at version `to`.
    fn replaces(self, key: &Key, from: u64, to: u64) -> Self {
        self.reads(key, from).change(Change::Write {
            key: key.clone(),
            version: version(to),
            end: None,
            data: DATA.into(),
        })
    }

    /// Adds an intent of a notification.
    fn intends(mut self) -> Self {
        self.0
            .intend(Intent::new(Call::Notification, (*b"notify").into()))
            .expect("a proposal of the suite has one intent");
        self
    }

    fn done(self) -> Proposal {
        self.0
    }
}

/// The seed of each case that runs the driver: one commit of the records that the cases read.
///
/// - Accounts `a1`, `a2`, and `a4` with the passkeys `a1p`, `a1q`, `a2p`, and `a4p`, and the recovery value `a2c` of
///   `a2`. Each one is an anchor with its creation entry.
/// - The registration ceremonies `reg-1` and `reg-4`, the invitation `inv-1`, the bootstrap value `b-1`, the sign-in
///   challenge `ch-1`, and the approval `ap-1`. The ceremonies and the invitation end at [`LATER`].
/// - The session `s-1` and the grant `g-1`.
///
/// Each record is at version 1.
fn seed() -> (Proposal, Plan) {
    let mut build = Build::new("seed");
    let mut anchors = Vec::new();
    for (id, owner) in [("a1p", "a1"), ("a1q", "a1"), ("a2p", "a2"), ("a4p", "a4")] {
        let passkey = key(Kind::Credential, id);
        build = build.writes(&passkey, 1);
        anchors.push((passkey, sign_in(owner)));
    }
    let recovery = key(Kind::Recovery, "a2c");
    build = build.writes(&recovery, 1);
    anchors.push((recovery, Role::Recovery(account("a2"))));
    for (kind, id) in [
        (Kind::Registration, "reg-1"),
        (Kind::Registration, "reg-4"),
        (Kind::Invitation, "inv-1"),
        (Kind::SignIn, "ch-1"),
        (Kind::Approval, "ap-1"),
    ] {
        build = build.writes_until(&key(kind, id), 1, Some(LATER));
    }
    for (kind, id) in [(Kind::Bootstrap, "b-1"), (Kind::Session, "s-1"), (Kind::Grant, "g-1")] {
        build = build.writes(&key(kind, id), 1);
    }
    let plan = Plan {
        anchors,
        ..Plan::default()
    };
    (build.done(), plan)
}

/// The output of the primitive call `effect` on `binding`. A failed primitive gives [`Output::Failed`].
async fn execute<S: Subject>(binding: &mut S, effect: Effect<'_>) -> Output {
    match effect {
        Effect::Start => binding.start().await.map_or(Output::Failed, Output::Started),
        Effect::Read(key) => Store::read(binding, key).await.map_or(Output::Failed, Output::Read),
        Effect::Commit(proposal, instance) => binding
            .commit(proposal, instance)
            .await
            .map_or(Output::Failed, Output::Committed),
        Effect::Expire(kind, before, limit) => binding
            .expire(kind, before, limit)
            .await
            .map_or(Output::Failed, Output::Expired),
        Effect::Intents(after, limit) => binding
            .intents(after, limit)
            .await
            .map_or(Output::Failed, Output::Intents),
        Effect::Append(entry) => binding.append(entry).await.map_or(Output::Failed, Output::Appended),
        Effect::Sync => binding.sync().await.map_or(Output::Failed, |()| Output::Synced),
        Effect::ReadJournal(after, limit) => Journal::read(binding, after, limit)
            .await
            .map_or(Output::Failed, Output::Journal),
    }
}

/// The outputs of `first` and `second`, which run at the same time: each poll polls each one that is not ready.
async fn both<A: Future, B: Future>(first: A, second: B) -> (A::Output, B::Output) {
    let (mut first, mut second) = (pin!(first), pin!(second));
    let (mut a, mut b) = (Poll::Pending, Poll::Pending);
    poll_fn(|context| {
        if a.is_pending() {
            a = first.as_mut().poll(context);
        }
        if b.is_pending() {
            b = second.as_mut().poll(context);
        }
        match (mem::replace(&mut a, Poll::Pending), mem::replace(&mut b, Poll::Pending)) {
            (Poll::Ready(a), Poll::Ready(b)) => Poll::Ready((a, b)),
            (pending_a, pending_b) => {
                a = pending_a;
                b = pending_b;
                Poll::Pending
            }
        }
    })
    .await
}

/// Whether `effect` is the commit of `operation`.
fn commit_of(effect: &Effect<'_>, operation: &OperationId) -> bool {
    matches!(effect, Effect::Commit(proposal, _) if proposal.operation().id == *operation)
}

/// A hook that gives `fault` to the first effect that `at` matches.
fn once(mut at: impl FnMut(&Effect<'_>) -> bool, fault: Fault) -> impl FnMut(&Effect<'_>) -> Option<Fault> {
    let mut done = false;
    move |effect| {
        let hit = !done && at(effect);
        done |= hit;
        hit.then_some(fault)
    }
}

/// A hook that gives `fault` to the commit of `operation`.
fn at_commit(operation: &str, fault: Fault) -> impl FnMut(&Effect<'_>) -> Option<Fault> {
    let operation = op(operation);
    once(move |effect| commit_of(effect, &operation), fault)
}

/// A hook that gives `fault` to the first effect after the commit of `operation` that `at` matches.
fn after_commit(
    operation: &str,
    mut at: impl FnMut(&Effect<'_>) -> bool,
    fault: Fault,
) -> impl FnMut(&Effect<'_>) -> Option<Fault> {
    let operation = op(operation);
    let mut seen = false;
    once(
        move |effect| {
            let hit = seen && at(effect);
            seen |= commit_of(effect, &operation);
            hit
        },
        fault,
    )
}

/// What a run does with the next effect.
enum Next {
    /// Execute it, after the fault, if any.
    Run(Option<Fault>),
    /// Stop before it.
    Stop,
}

/// A driver on a binding: the harness of each case that runs the driver.
struct Run<S> {
    binding: S,
    driver: Driver,
    /// The audit record that the commit of each submitted proposal writes.
    audits: BTreeMap<Ticket, (Key, Record)>,
}

impl<S: Subject> Run<S> {
    /// A driver that started on `binding`, and that committed the records of [`seed`].
    async fn seeded(binding: S) -> Result<Self, String> {
        let driver = Driver::new(&binding.declaration(), Limits::default());
        let mut run = Self {
            binding,
            driver,
            audits: BTreeMap::new(),
        };
        run.start().await?;
        let (proposal, plan) = seed();
        run.commit(proposal, plan, "the seed").await?;
        Ok(run)
    }

    /// Executes the next effect of the driver, after its fault, unless `next` stops before it. Gives `false` when the
    /// driver waits or `next` stops.
    async fn step(&mut self, next: &mut impl FnMut(&Effect<'_>) -> Next) -> Result<bool, String> {
        let Some(effect) = self.driver.effect() else {
            return Ok(false);
        };
        let Next::Run(fault) = next(&effect) else {
            return Ok(false);
        };
        if let Some(fault) = fault {
            self.binding.inject(fault);
        }
        let output = execute(&mut self.binding, effect).await;
        self.driver
            .give(output)
            .map_err(|error| format!("the driver refused an output of the binding: {error}"))?;
        Ok(true)
    }

    /// Executes the effects of the driver until it waits, or until `next` stops.
    async fn steps(&mut self, mut next: impl FnMut(&Effect<'_>) -> Next) -> Checked {
        for _ in 0..EFFECTS_MAX {
            if !self.step(&mut next).await? {
                return Ok(());
            }
        }
        Err(format!("the driver gave more than {EFFECTS_MAX} effects"))
    }

    /// Executes the effects until the driver waits. `hook` gives the fault of each effect.
    async fn drive(&mut self, mut hook: impl FnMut(&Effect<'_>) -> Option<Fault>) -> Checked {
        self.steps(|effect| Next::Run(hook(effect))).await
    }

    /// Executes the effects with no fault until the driver waits.
    async fn settle(&mut self) -> Checked {
        self.drive(|_| None).await
    }

    /// Executes the effects with no fault until the next one is the commit of `operation`.
    async fn until_commit(&mut self, operation: &str) -> Checked {
        let operation = op(operation);
        self.steps(|effect| {
            if commit_of(effect, &operation) {
                Next::Stop
            } else {
                Next::Run(None)
            }
        })
        .await
    }

    fn serving(&self) -> Checked {
        match self.driver.status() {
            Status::Serving => Ok(()),
            status => Err(format!("the driver does not serve: {status:?}")),
        }
    }

    /// A start of the driver, which serves after it.
    async fn start(&mut self) -> Checked {
        self.driver.start(now());
        self.settle().await?;
        self.serving()
    }

    /// The restore of the driver on the current state of the store.
    async fn activate(&mut self) -> Checked {
        self.driver
            .restore(now())
            .map_err(|error| format!("the driver refused the restore: {error}"))?;
        self.settle().await
    }

    /// The restore of `snapshot`, which serves after it.
    async fn restore(&mut self, snapshot: &S::Snapshot) -> Checked {
        self.binding.restore(snapshot);
        self.activate().await?;
        self.serving()
    }

    /// Submits `proposal` with `plan`.
    fn submit(&mut self, proposal: Proposal, plan: Plan) -> Result<Ticket, String> {
        let audit = audit_record(&proposal);
        let ticket = self
            .driver
            .submit(proposal, plan)
            .map_err(|error| format!("the driver refused a proposal of the suite: {error}"))?;
        self.audits.insert(ticket, audit);
        Ok(ticket)
    }

    /// The outcome of the commit `ticket`, which ended. An accepted commit has its audit record.
    async fn outcome(&mut self, ticket: Ticket) -> Result<Outcome, String> {
        let outcome = match self.driver.take(ticket) {
            Some(Answer::Outcome(outcome)) => outcome,
            answer => return Err(format!("a commit has no outcome: {answer:?}")),
        };
        if let (Outcome::Accepted(_), Some((key, audit))) = (&outcome, self.audits.get(&ticket)) {
            let stored = Store::read(&mut self.binding, key).await.map_err(failed("read"))?;
            ensure(same(stored.as_ref(), audit), "an accepted commit has no audit record")?;
        }
        Ok(outcome)
    }

    /// The commit of `proposal` with `plan`, which the driver accepts. `what` names the commit.
    async fn commit(&mut self, proposal: Proposal, plan: Plan, what: &str) -> Checked {
        let ticket = self.submit(proposal, plan)?;
        self.settle().await?;
        match self.outcome(ticket).await? {
            Outcome::Accepted(_) => Ok(()),
            outcome => Err(format!("{what} did not commit: {outcome:?}")),
        }
    }

    /// The lookup of `operation`, after each operation that waits.
    async fn lookup(&mut self, operation: &Operation) -> Result<Lookup, String> {
        let ticket = self
            .driver
            .lookup(operation.clone())
            .map_err(|error| format!("the driver refused a lookup: {error}"))?;
        self.settle().await?;
        match self.driver.take(ticket) {
            Some(Answer::Lookup(lookup)) => Ok(lookup),
            answer => Err(format!("a lookup has no result: {answer:?}")),
        }
    }

    async fn holds(&mut self, key: &Key) -> Result<bool, String> {
        Ok(Store::read(&mut self.binding, key)
            .await
            .map_err(failed("read"))?
            .is_some())
    }

    /// The durable journal, from its first entry.
    async fn history(&mut self) -> Result<History, String> {
        let mut history = History::new(Mark::EMPTY);
        for _ in 0..=driver::JOURNAL_ENTRIES_MAX / PAGE {
            let page = Journal::read(&mut self.binding, history.head().sequence, PAGE)
                .await
                .map_err(failed("read of the journal"))?;
            if page.is_empty() {
                return Ok(history);
            }
            history
                .extend(&page, Limits::default())
                .map_err(|error| format!("the journal refused: {error}"))?;
        }
        Err(format!(
            "the journal has more than {} entries",
            driver::JOURNAL_ENTRIES_MAX
        ))
    }
}

/// The key of the replay floor record of the driver.
fn replay_floor() -> Key {
    Kind::ReplayFloor.key(&[]).expect("a key of one byte is valid")
}
