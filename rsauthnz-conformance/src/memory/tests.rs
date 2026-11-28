use core::assert_matches;
use core::num::NonZeroUsize;
use core::pin::pin;
use core::task::{Context, Poll, Waker};
use core::time::Duration;
use std::sync::Barrier;
use std::thread;

use rsauthnz::cbor::Value;
use rsauthnz::id::{AuthorityVersion, Id, Principal};
use rsauthnz::limits::Limits;
use rsauthnz::store::journal::{Append, Body, Floor, Mark};
use rsauthnz::store::{Commit, Entry, Expiry, Instance, Journal, JournalWrite, Kind, Sequence, Store};
use rsauthnz::time::{Reading, ReadingSource};
use rsauthnz::transition::{Audit, Change, Dependency, Key, Operation, OperationId, Proposal};

use super::{Crash, Error, Fault, Memory, Schedule};
use crate::suite::Subject;

mod broken;

/// The output of a future of the binding, which is ready at its first poll.
fn ready<F: Future>(future: F) -> F::Output {
    match pin!(future).poll(&mut Context::from_waker(Waker::noop())) {
        Poll::Ready(output) => output,
        Poll::Pending => panic!("the memory binding does no I/O"),
    }
}

/// The proposal of the operation `id`, which reads the absence of `key` and writes it.
fn proposal(id: &[u8], key: &Key) -> Proposal {
    let audit = Audit {
        actor: Principal::Human(Id::new("acme", "u-17").unwrap()),
        action: Id::new("acme.auth", "credential.enroll").unwrap(),
        time: Reading::new(
            Duration::from_secs(1_000),
            Some(Duration::from_secs(1)),
            ReadingSource::Caller,
        ),
    };
    let mut proposal = Proposal::new(OperationId::new(id).unwrap(), audit, &Value::Null, Limits::default()).unwrap();
    proposal.read(Dependency::Absent(key.clone())).unwrap();
    proposal
        .change(Change::Write {
            key: key.clone(),
            version: AuthorityVersion::new(Id::new("acme", "auth").unwrap(), &[1]).unwrap(),
            end: None,
            data: Box::new(*b"credential"),
        })
        .unwrap();
    proposal
}

/// Each durable entry of the journal.
fn entries(memory: &mut Memory) -> Result<Vec<Entry>, Error> {
    ready(Journal::read(memory, Sequence(0), NonZeroUsize::MAX))
}

fn floor(after: Mark, value: u8) -> Append {
    let body = Body::Floor(Floor {
        kind: Kind::Session,
        value: u64::from(value),
    });
    after
        .next(&OperationId::new(&[value]).unwrap(), &body, Limits::default())
        .unwrap()
}

/// The seeds of the seeded run, and the steps of each run.
const SEEDS: u64 = 64;
const STEPS: u8 = 16;

/// One primitive call of a run, with its result.
#[derive(Debug, PartialEq)]
enum Call {
    Start(Instance),
    Append(Result<JournalWrite, Error>),
    Sync(Result<JournalWrite, Error>),
    Commit(Result<Commit, Error>),
}

/// A run on a binding with a seeded schedule, and what the storage contract makes durable.
struct Run {
    memory: Memory,
    instance: Instance,
    calls: Vec<Call>,
    /// The error of each crash.
    crashes: Vec<Error>,
    /// The entries whose sync returned.
    synced: Vec<Entry>,
    /// The entries whose append returned after the last sync.
    unsynced: Vec<Entry>,
    /// The operation and the key of each commit, and whether the commit landed.
    commits: Vec<(Operation, Key, bool)>,
}

impl Run {
    /// One step: an append, a sync, and the commit of a proposal that creates one key.
    fn step(&mut self, step: u8) -> Result<(), Error> {
        let head = self
            .synced
            .last()
            .map_or(Mark::EMPTY, |entry| Mark::of(entry.sequence, &entry.data));
        let append = floor(head, step);
        let appended = ready(self.memory.append(&append, self.instance));
        self.calls.push(Call::Append(appended));
        assert_eq!(appended?, JournalWrite::Accepted);
        self.unsynced.push(append.entry().clone());
        let synced = ready(self.memory.sync(self.instance));
        self.calls.push(Call::Sync(synced));
        assert_eq!(synced?, JournalWrite::Accepted);
        self.synced.append(&mut self.unsynced);

        let key = Kind::Credential.key(&[step]).unwrap();
        let proposal = proposal(&[step], &key);
        let commit = ready(self.memory.commit(&proposal, self.instance));
        self.calls.push(Call::Commit(commit.clone()));
        let landed = match &commit {
            Ok(commit) => {
                assert_eq!(*commit, Commit::Accepted);
                true
            }
            Err(Error::Crash(Fault::LostResponse)) => true,
            Err(_) => false,
        };
        self.commits.push((proposal.operation().clone(), key, landed));
        commit.map(drop)
    }

    /// Starts the binding after a crash, and checks the durable state that the storage contract gives: each entry
    /// whose sync returned and no other, and each commit that landed with its outcome and audit, and no other.
    fn recover(&mut self) {
        self.unsynced.clear();
        self.instance = ready(self.memory.start()).unwrap();
        self.calls.push(Call::Start(self.instance));
        assert_eq!(entries(&mut self.memory), Ok(self.synced.clone()));
        for (operation, key, landed) in &self.commits {
            let outcome = ready(self.memory.outcome(&operation.id)).unwrap();
            assert_eq!(outcome.as_ref(), landed.then_some(operation));
            let record = ready(Store::read(&mut self.memory, key)).unwrap();
            assert_eq!(record.is_some(), *landed);
            let audit = Kind::Audit.key(operation.id.as_bytes()).unwrap();
            assert_eq!(ready(Store::read(&mut self.memory, &audit)).unwrap().is_some(), *landed);
        }
    }
}

/// Runs the steps on a binding with the schedule `Seeded(seed)`, and recovers after each crash and at the end. It
/// gives each call with its result, and the error of each crash.
fn run(seed: u64) -> (Vec<Call>, Vec<Error>) {
    let mut memory = Memory::new(Schedule::Seeded(seed));
    let instance = ready(memory.start()).unwrap();
    let mut run = Run {
        memory,
        instance,
        calls: vec![Call::Start(instance)],
        crashes: Vec::new(),
        synced: Vec::new(),
        unsynced: Vec::new(),
        commits: Vec::new(),
    };
    for step in 0..STEPS {
        match run.step(step) {
            Ok(()) => {}
            Err(Error::Stopped) => panic!("the run starts the binding after each crash"),
            Err(crash) => {
                run.crashes.push(crash);
                run.recover();
            }
        }
    }
    run.recover();
    (run.calls, run.crashes)
}

/// Each fault of a seeded schedule gives the outcome of the storage contract: a crash before a commit and a delayed
/// commit land nothing, a commit with a lost response lands, and a crash loses each append whose sync did not
/// return. The faults of the seeds include each fault, and the same seed gives the same calls and results again.
#[test]
fn each_fault_of_a_seeded_schedule_gives_its_outcome_and_a_seed_replays_its_results() {
    let runs: Vec<_> = (0..SEEDS).map(run).collect();
    for crash in Crash::ALL {
        assert!(
            runs.iter().any(|(_, crashes)| crashes.contains(&crash.error())),
            "{crash:?}"
        );
    }
    for (seed, first) in (0..SEEDS).zip(&runs) {
        assert_eq!(&run(seed), first, "seed {seed}");
    }
    assert!(runs.windows(2).any(|pair| pair[0] != pair[1]));
}

/// Two callers commit at the same time. Each proposal reads the absence of one key and writes it, so a serializable
/// commit accepts one and refuses the other, and the refused one writes no outcome record.
#[test]
fn two_concurrent_commits_that_read_one_absence_give_one_commit_and_one_conflict() {
    const ROUNDS: u8 = 64;
    let memory = Memory::new(Schedule::None);
    let instance = ready(memory.clone().start()).unwrap();
    let barrier = Barrier::new(2);
    for round in 0..ROUNDS {
        let key = Kind::Credential.key(&[round]).unwrap();
        let proposals = [proposal(&[round, 1], &key), proposal(&[round, 2], &key)];
        let commits = thread::scope(|scope| {
            proposals
                .each_ref()
                .map(|proposal| {
                    let mut memory = memory.clone();
                    let barrier = &barrier;
                    scope.spawn(move || {
                        barrier.wait();
                        ready(memory.commit(proposal, instance)).unwrap()
                    })
                })
                .map(|commit| commit.join().unwrap())
        });
        assert_matches!(
            commits,
            [Commit::Accepted, Commit::Conflict] | [Commit::Conflict, Commit::Accepted]
        );
        let outcomes = proposals.map(|proposal| ready(memory.clone().outcome(&proposal.operation().id)).unwrap());
        assert_eq!(outcomes.iter().filter(|outcome| outcome.is_some()).count(), 1);
    }
}

/// An append is durable only after its sync returns: a read before the sync does not give it, and the crash of a
/// failed sync loses it. The next append gets the sequence of the lost append, so the journal has no gap.
/// Contract: [`Memory::with_retention`] ends the audit and outcome records of a commit at its audit time plus the
/// retention. An expiry pass removes each one only after that end.
#[test]
fn an_expiry_pass_removes_the_audit_and_outcome_records_only_after_the_finite_retention() {
    let hour = Duration::from_secs(3_600);
    let mut memory = Memory::new(Schedule::None).with_retention(hour);
    assert_eq!(memory.declaration().outcome_retention, hour);
    let instance = ready(memory.start()).unwrap();
    let key = Kind::Credential.key(b"c-1").unwrap();
    let proposal = proposal(b"op-1", &key);
    assert_eq!(ready(memory.commit(&proposal, instance)), Ok(Commit::Accepted));

    // The audit time of the proposal is 1,000 s, so each record ends at 4,600 s.
    let page = NonZeroUsize::new(16).unwrap();
    let end = Duration::from_secs(4_600);
    for kind in [Kind::Audit, Kind::Outcome] {
        assert_eq!(
            ready(memory.expire(kind, end, page, instance)),
            Ok(Expiry::Removed(0)),
            "{kind:?} at its end"
        );
    }
    assert_eq!(
        ready(memory.outcome(&proposal.operation().id)).unwrap().as_ref(),
        Some(proposal.operation())
    );
    for kind in [Kind::Audit, Kind::Outcome] {
        assert_eq!(
            ready(memory.expire(kind, end + Duration::from_nanos(1), page, instance)),
            Ok(Expiry::Removed(1)),
            "{kind:?} after its end"
        );
    }
    assert_eq!(ready(memory.outcome(&proposal.operation().id)), Ok(None));
    assert!(
        ready(Store::read(&mut memory, &key)).unwrap().is_some(),
        "the credential has no end"
    );
}

#[test]
fn an_append_is_durable_only_after_its_sync_returns() {
    let mut memory = Memory::new(Schedule::None);
    let instance = ready(memory.start()).unwrap();
    let first = floor(Mark::EMPTY, 1);
    let second = floor(first.head(), 2);
    assert_eq!(ready(memory.append(&first, instance)), Ok(JournalWrite::Accepted));
    assert_eq!(ready(memory.sync(instance)), Ok(JournalWrite::Accepted));
    assert_eq!(ready(memory.append(&second, instance)), Ok(JournalWrite::Accepted));
    let durable = vec![first.entry().clone()];
    assert_eq!(entries(&mut memory), Ok(durable.clone()));

    memory.inject(Fault::FailedSync);
    assert_eq!(ready(memory.sync(instance)), Err(Error::Crash(Fault::FailedSync)));
    let current = ready(memory.start()).unwrap();
    assert_eq!(entries(&mut memory), Ok(durable));
    assert_eq!(
        ready(memory.append(&floor(first.head(), 3), current)),
        Ok(JournalWrite::Accepted)
    );
}

/// A restart and a restore each lose the appends after the last sync, as a crash does, so a sync after the next start
/// makes none of them durable.
#[test]
fn a_restart_or_a_restore_loses_each_append_after_the_last_sync() {
    for stop in ["restart", "restore"] {
        let mut memory = Memory::new(Schedule::None);
        let snapshot = memory.snapshot();
        let instance = ready(memory.start()).unwrap();
        let first = floor(Mark::EMPTY, 1);
        assert_eq!(ready(memory.append(&first, instance)), Ok(JournalWrite::Accepted));
        assert_eq!(ready(memory.sync(instance)), Ok(JournalWrite::Accepted));
        let durable = entries(&mut memory).unwrap();
        assert_eq!(
            ready(memory.append(&floor(first.head(), 2), instance)),
            Ok(JournalWrite::Accepted)
        );
        if stop == "restart" {
            memory.restart();
        } else {
            memory.restore(&snapshot);
        }
        let current = ready(memory.start()).unwrap();
        assert_eq!(ready(memory.sync(current)), Ok(JournalWrite::Accepted));
        assert_eq!(entries(&mut memory), Ok(durable), "{stop}");
    }
}

/// The loss of journal entries leaves a gap that a read shows, and no later append fills it: the next append gets
/// the sequence after the last synced entry.
#[test]
fn a_lost_entry_leaves_a_gap_that_no_append_fills() {
    let mut memory = Memory::new(Schedule::None);
    let instance = ready(memory.start()).unwrap();
    let mut head = Mark::EMPTY;
    for value in 1..=4 {
        let append = floor(head, value);
        assert_eq!(ready(memory.append(&append, instance)), Ok(JournalWrite::Accepted));
        head = append.head();
    }
    assert_eq!(ready(memory.sync(instance)), Ok(JournalWrite::Accepted));

    memory.lose(Sequence(2)..=Sequence(3));
    let sequences = |memory: &mut Memory| {
        entries(memory)
            .unwrap()
            .iter()
            .map(|entry| entry.sequence)
            .collect::<Vec<_>>()
    };
    assert_eq!(sequences(&mut memory), [Sequence(1), Sequence(4)]);
    memory.lose(..);
    assert_eq!(sequences(&mut memory), []);
    assert_eq!(
        ready(memory.append(&floor(head, 5), instance)),
        Ok(JournalWrite::Accepted)
    );
    assert_eq!(ready(memory.sync(instance)), Ok(JournalWrite::Accepted));
    assert_eq!(sequences(&mut memory), [Sequence(5)]);
}
