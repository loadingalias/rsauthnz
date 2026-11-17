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
use rsauthnz::store::journal::{self, Body, Floor, History, Mark};
use rsauthnz::store::{Commit, CrashLoss, Entry, Instance, Journal, Kind, Sequence, Store};
use rsauthnz::time::{Reading, ReadingSource};
use rsauthnz::transition::{Audit, Change, Dependency, Key, Operation, OperationId, Proposal};

use super::{Error, Fault, Memory, Schedule};

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

/// Appends and syncs a floor entry of each value of `floors` after `head`, and gives the mark of each entry.
fn append_floors(memory: &mut Memory, mut head: Mark, floors: &[u64]) -> Vec<Mark> {
    let operation = OperationId::new(b"f-1").unwrap();
    let mut marks = Vec::new();
    for value in floors {
        let floor = Body::Floor(Floor {
            kind: Kind::Session,
            value: *value,
        });
        let (data, next) = head.next(&operation, &floor, Limits::default()).unwrap();
        assert_eq!(ready(memory.append(&data)), Ok(next.sequence));
        ready(memory.sync()).unwrap();
        marks.push(next);
        head = next;
    }
    marks
}

/// The seeds of the seeded run, and the steps of each run.
const SEEDS: u64 = 64;
const STEPS: u8 = 16;

/// One primitive call of a run, with its result.
#[derive(Debug, PartialEq)]
enum Call {
    Start(Instance),
    Append(Result<Sequence, Error>),
    Sync(Result<(), Error>),
    Commit(Result<Commit, Error>),
}

/// A run on a binding with a seeded schedule, and what the storage contract makes durable.
struct Run {
    memory: Memory,
    instance: Instance,
    calls: Vec<Call>,
    faults: Vec<Fault>,
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
        let appended = ready(self.memory.append(&[step]));
        self.calls.push(Call::Append(appended));
        self.unsynced.push(Entry {
            sequence: appended?,
            data: Box::new([step]),
        });
        let synced = ready(self.memory.sync());
        self.calls.push(Call::Sync(synced));
        synced?;
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
/// gives each call with its result, and each fault.
fn run(seed: u64) -> (Vec<Call>, Vec<Fault>) {
    let mut memory = Memory::new(Schedule::Seeded(seed));
    let instance = ready(memory.start()).unwrap();
    let mut run = Run {
        memory,
        instance,
        calls: vec![Call::Start(instance)],
        faults: Vec::new(),
        synced: Vec::new(),
        unsynced: Vec::new(),
        commits: Vec::new(),
    };
    for step in 0..STEPS {
        match run.step(step) {
            Ok(()) => {}
            Err(Error::Crash(fault)) => {
                run.faults.push(fault);
                run.recover();
            }
            Err(Error::Stopped) => panic!("the run starts the binding after each crash"),
        }
    }
    run.recover();
    (run.calls, run.faults)
}

/// Each fault of a seeded schedule gives the outcome of the storage contract: a crash before a commit and a delayed
/// commit land nothing, a commit with a lost response lands, and a crash loses each append whose sync did not
/// return. The faults of the seeds include each fault, and the same seed gives the same calls and results again.
#[test]
fn each_fault_of_a_seeded_schedule_gives_its_outcome_and_a_seed_replays_its_results() {
    let runs: Vec<_> = (0..SEEDS).map(run).collect();
    for fault in Fault::ALL {
        assert!(runs.iter().any(|(_, faults)| faults.contains(&fault)), "{fault:?}");
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

/// A commit carries the instance number of its start. After a later start, also after a restart and after a restore,
/// a commit with an earlier number refuses and writes nothing.
#[test]
fn a_commit_with_an_earlier_instance_number_refuses() {
    let mut memory = Memory::new(Schedule::None);
    let empty = memory.snapshot(Mark::EMPTY);
    let key = Kind::Credential.key(b"c-4").unwrap();
    let proposal = proposal(b"op-1", &key);

    let first = ready(memory.start()).unwrap();
    let second = ready(memory.start()).unwrap();
    assert_eq!(ready(memory.commit(&proposal, first)), Ok(Commit::Conflict));
    memory.restart();
    let third = ready(memory.start()).unwrap();
    assert_eq!(ready(memory.commit(&proposal, second)), Ok(Commit::Conflict));
    memory.restore(&empty);
    let fourth = ready(memory.start()).unwrap();
    assert_eq!(ready(memory.commit(&proposal, third)), Ok(Commit::Conflict));
    assert_eq!(ready(Store::read(&mut memory, &key)), Ok(None));
    assert_eq!(ready(memory.commit(&proposal, fourth)), Ok(Commit::Accepted));
}

/// An append is durable only after its sync returns: a read before the sync does not give it, and the crash of a
/// failed sync loses it. The next append gets the sequence of the lost append, so the journal has no gap.
#[test]
fn an_append_is_durable_only_after_its_sync_returns() {
    let mut memory = Memory::new(Schedule::At(1, Fault::FailedSync));
    ready(memory.start()).unwrap();
    let first = ready(memory.append(b"first")).unwrap();
    ready(memory.sync()).unwrap();
    let second = ready(memory.append(b"second")).unwrap();
    let durable = vec![Entry {
        sequence: first,
        data: Box::new(*b"first"),
    }];
    assert_eq!(entries(&mut memory), Ok(durable.clone()));

    assert_eq!(ready(memory.sync()), Err(Error::Crash(Fault::FailedSync)));
    ready(memory.start()).unwrap();
    assert_eq!(entries(&mut memory), Ok(durable));
    assert_eq!(ready(memory.append(b"third")), Ok(second));
}

/// A restart is the loss of the process, and the declaration says that it loses all state: the records and the
/// outcome records are gone. The journal is in another failure domain, so it keeps its synced entries.
#[test]
fn a_restart_loses_the_store_and_keeps_the_journal() {
    let mut memory = Memory::new(Schedule::None);
    assert_eq!(memory.declaration().crash_loss, CrashLoss::Everything);
    let instance = ready(memory.start()).unwrap();
    let key = Kind::Credential.key(b"c-4").unwrap();
    let proposal = proposal(b"op-1", &key);
    assert_eq!(ready(memory.commit(&proposal, instance)), Ok(Commit::Accepted));
    ready(memory.append(b"entry")).unwrap();
    ready(memory.sync()).unwrap();
    let journal = entries(&mut memory).unwrap();

    memory.restart();
    assert_eq!(ready(Store::read(&mut memory, &key)), Err(Error::Stopped));
    ready(memory.start()).unwrap();
    assert_eq!(ready(Store::read(&mut memory, &key)), Ok(None));
    assert_eq!(ready(memory.outcome(&proposal.operation().id)), Ok(None));
    assert_eq!(entries(&mut memory), Ok(journal));
}

/// A restore gives back the state and the low-water mark of its snapshot: the commit before the snapshot stays, and
/// the commit after it is gone. The journal is in another failure domain, so it keeps each entry.
#[test]
fn a_restore_gives_the_state_and_the_mark_of_its_snapshot() {
    let mut memory = Memory::new(Schedule::None);
    let instance = ready(memory.start()).unwrap();
    let keys = [b"c-1", b"c-2"].map(|id| Kind::Credential.key(id).unwrap());
    let proposals = [proposal(b"op-1", &keys[0]), proposal(b"op-2", &keys[1])];
    let mut snapshot = None;
    let mut head = Mark::EMPTY;
    for (proposal, floor) in proposals.iter().zip([8, 16]) {
        assert_eq!(ready(memory.commit(proposal, instance)), Ok(Commit::Accepted));
        let mark = append_floors(&mut memory, head, &[floor])[0];
        snapshot.get_or_insert_with(|| (mark, memory.snapshot(mark)));
        head = mark;
    }
    let journal = entries(&mut memory).unwrap();

    let (mark, snapshot) = snapshot.unwrap();
    assert_eq!(memory.restore(&snapshot), mark);
    ready(memory.start()).unwrap();
    for (proposal, (key, kept)) in proposals.iter().zip(keys.iter().zip([true, false])) {
        assert_eq!(ready(Store::read(&mut memory, key)).unwrap().is_some(), kept);
        let outcome = ready(memory.outcome(&proposal.operation().id)).unwrap();
        assert_eq!(outcome.as_ref(), kept.then_some(proposal.operation()));
    }
    assert_eq!(entries(&mut memory), Ok(journal));
}

/// A restart and a restore stop the binding as a crash does: each append after the last sync is lost, so a sync after
/// the next start makes none of them durable.
#[test]
fn a_restart_or_a_restore_loses_each_append_after_the_last_sync() {
    for stop in ["restart", "restore"] {
        let mut memory = Memory::new(Schedule::None);
        let snapshot = memory.snapshot(Mark::EMPTY);
        ready(memory.start()).unwrap();
        ready(memory.append(b"synced")).unwrap();
        ready(memory.sync()).unwrap();
        let durable = entries(&mut memory).unwrap();
        ready(memory.append(b"unsynced")).unwrap();
        if stop == "restart" {
            memory.restart();
        } else {
            memory.restore(&snapshot);
        }
        ready(memory.start()).unwrap();
        ready(memory.sync()).unwrap();
        assert_eq!(entries(&mut memory), Ok(durable), "{stop}");
    }
}

/// A snapshot keeps the link of the entry at its mark, so a restore with the journal of another history refuses at
/// its first entry after the mark, also when the sequences are the same.
#[test]
fn a_restore_with_the_journal_of_another_history_refuses() {
    let mut store = Memory::new(Schedule::None);
    ready(store.start()).unwrap();
    let marks = append_floors(&mut store, Mark::EMPTY, &[8, 16, 24]);
    let snapshot = store.snapshot(marks[1]);
    let mut other = Memory::new(Schedule::None);
    ready(other.start()).unwrap();
    append_floors(&mut other, Mark::EMPTY, &[1, 2, 3]);

    for (memory, expected) in [
        (&mut store, Ok(())),
        (&mut other, Err(journal::Error::Changed(Sequence(3)))),
    ] {
        let mark = memory.restore(&snapshot);
        ready(memory.start()).unwrap();
        let page = ready(Journal::read(memory, mark.sequence, NonZeroUsize::MAX)).unwrap();
        assert_eq!(History::new(mark).extend(&page, Limits::default()), expected);
    }
}

/// The loss of journal entries leaves a gap that a read shows, and no later append fills it: the next append gets
/// the sequence after the last synced entry.
#[test]
fn a_lost_entry_leaves_a_gap_that_no_append_fills() {
    let mut memory = Memory::new(Schedule::None);
    ready(memory.start()).unwrap();
    for entry in [b"1", b"2", b"3", b"4"] {
        ready(memory.append(entry)).unwrap();
    }
    ready(memory.sync()).unwrap();

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
    assert_eq!(ready(memory.append(b"5")), Ok(Sequence(5)));
}
