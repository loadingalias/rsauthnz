use alloc::boxed::Box;
use alloc::collections::BTreeMap;
use alloc::vec;
use alloc::vec::Vec;
use core::assert_matches;
use core::time::Duration;

use super::{
    AlphaSource, Answer, Begin, Driver, Effect, Error, Lookup, Output, Plan, Status, Ticket, record_bytes_min,
};
use crate::cbor::{self, Value};
use crate::id::{AuthorityVersion, Human, Id, Principal};
use crate::limits::Limits;
use crate::store::journal::{self, Anchor, Body, Mark, Role};
use crate::store::{
    self, Capacity, Commit, CrashInjection, CrashLoss, Declaration, Expiry, Instance, Isolation, JournalWrite, Kind,
    Profile, Record, Restore, Sequence, audit_record, intent_records, outcome_of, outcome_record,
};
use crate::time::{Reading, ReadingSource};
use crate::transition::{
    self, Audit, Change, Dependency, Key, Operation, OperationId, Outcome, Proposal, Recover as _, Recovery,
};

fn now() -> Reading {
    Reading::new(
        Duration::from_secs(1_000),
        Some(Duration::from_secs(1)),
        ReadingSource::Caller,
    )
}

fn op(name: &str) -> OperationId {
    OperationId::new(name.as_bytes()).unwrap()
}

fn key(kind: Kind, id: &str) -> Key {
    kind.key(id.as_bytes()).unwrap()
}

fn version(n: u8) -> AuthorityVersion {
    AuthorityVersion::new(Id::new("acme", "auth").unwrap(), &[n]).unwrap()
}

fn record(n: u8) -> Record {
    Record {
        version: version(n),
        end: None,
        data: Box::new(*b"record"),
    }
}

fn account(name: &str) -> Id<Human> {
    Id::new("acme", name).unwrap()
}

fn sign_in(name: &str) -> Role {
    Role::SignIn(account(name))
}

/// The anchor that a write of [`proposal`] gives.
fn anchor(key: &Key, role: Role) -> Anchor {
    Anchor {
        key: key.clone(),
        role,
        version: version(1),
        end: None,
        data: Box::new(*b"record"),
    }
}

fn declaration(journal: bool) -> Declaration {
    Declaration {
        isolation: Isolation::Serializable,
        crash_loss: CrashLoss::Unsynced,
        outcome_retention: Duration::from_secs(86_400),
        crash_injection: CrashInjection::Supported,
        restore: if journal {
            Restore::Journal {
                location: "memory".into(),
                failure_domain: "the test".into(),
            }
        } else {
            Restore::Unsupported
        },
        key_bytes_max: Key::BYTES_MAX,
        signatures: Capacity {
            records_max: 1,
            share_max: 1,
        },
        record_bytes_max: usize::MAX,
    }
}

/// The proposal of the operation `name` for the request `request`: it reads each record of `ends` at version 1 and
/// ends it, and it writes each new record of `writes` at version 1.
fn request(name: &str, request: &str, ends: &[&Key], writes: &[&Key]) -> Proposal {
    let audit = Audit {
        actor: Principal::Human(account("u-1")),
        action: Id::new("acme.auth", "test").unwrap(),
        time: now(),
    };
    let mut proposal = Proposal::new(op(name), audit, &Value::Text(request), Limits::default()).unwrap();
    for record in ends {
        proposal
            .read(Dependency::Version((*record).clone(), version(1)))
            .unwrap();
        proposal.change(Change::End((*record).clone())).unwrap();
    }
    for record in writes {
        proposal.read(Dependency::Absent((*record).clone())).unwrap();
        proposal
            .change(Change::Write {
                key: (*record).clone(),
                version: version(1),
                end: None,
                data: Box::new(*b"record"),
            })
            .unwrap();
    }
    proposal
}

/// The proposal of the operation `name` for the request `name`.
fn proposal(name: &str, ends: &[&Key], writes: &[&Key]) -> Proposal {
    request(name, name, ends, writes)
}

/// The plan of a change of the anchors `held` of their owners, which creates each anchor of `anchors`.
fn plan(held: &[Anchor], anchors: &[(Key, Role)]) -> Plan {
    Plan {
        held: held.to_vec(),
        replaced: Vec::new(),
        anchors: anchors.to_vec(),
    }
}

/// The passkeys of `a1` that the store of [`Double::new`] holds.
fn passkeys() -> Vec<Anchor> {
    ["a1p", "a1q", "a1r"]
        .map(|id| anchor(&key(Kind::Credential, id), sign_in("a1")))
        .to_vec()
}

/// The enrollment `e-1`: it consumes the registration ceremony `reg-1` and creates the passkey `a1s`.
fn enrollment() -> (Proposal, Plan) {
    let a1s = key(Kind::Credential, "a1s");
    let proposal = proposal("e-1", &[&key(Kind::Registration, "reg-1")], &[&a1s]);
    (proposal, plan(&[], &[(a1s, sign_in("a1"))]))
}

/// The issue `i-1` of a recovery value `a1d`: an anchor commit that consumes no value.
fn issue() -> (Proposal, Plan) {
    let a1d = key(Kind::Recovery, "a1d");
    let proposal = proposal("i-1", &[], &[&a1d]);
    (proposal, plan(&[], &[(a1d, Role::Recovery(account("a1")))]))
}

/// What a scripted fault does to one effect: the binding crashes, and the effect happens or not.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum Fault {
    /// The effect does not happen.
    Fail,
    /// The effect happens, and its response is lost.
    Lost,
}

/// The kind of a journal entry, read from its stored form.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum Written {
    End,
    Creation,
    Void,
    Floor,
}

/// One effect of a run, an injected crash, or an answer.
#[derive(Clone, Debug, PartialEq, Eq)]
enum Event {
    Start,
    Read(Key),
    Commit(OperationId, Instance),
    Expire(Kind),
    Range,
    Append(Written, OperationId),
    Sync,
    ReadJournal,
    Crash,
    Answer(Ticket),
}

impl Event {
    fn of(effect: &Effect<'_>) -> Self {
        match effect {
            Effect::Start => Self::Start,
            Effect::Read(key) => Self::Read((*key).clone()),
            Effect::Commit(proposal, instance) => Self::Commit(proposal.operation().id.clone(), *instance),
            Effect::Expire(kind, ..) => Self::Expire(*kind),
            Effect::Range(..) => Self::Range,
            Effect::Append(append, _) => {
                // The stored form is `[form, sequence, link, operation, [tag, ...]]`.
                let Value::Array(items) = cbor::decode(&append.entry().data, Limits::default()).unwrap() else {
                    panic!("an entry is an array");
                };
                let (Value::Bytes(id), Value::Array(body)) = (&items[3], &items[4]) else {
                    panic!("an entry has an operation and a body");
                };
                let written = match body[0] {
                    Value::Unsigned(0) => Written::End,
                    Value::Unsigned(1) => Written::Creation,
                    Value::Unsigned(2) => Written::Void,
                    _ => Written::Floor,
                };
                Self::Append(written, OperationId::new(id).unwrap())
            }
            Effect::Sync(_) => Self::Sync,
            Effect::ReadJournal(..) => Self::ReadJournal,
        }
    }
}

fn appended(written: Written, name: &str) -> Event {
    Event::Append(written, op(name))
}

/// A store and a journal in memory, which execute the effects of the driver. A crash loses each append after the last
/// sync.
#[derive(Clone, Debug, Default)]
struct Double {
    records: BTreeMap<Key, Record>,
    journal: Vec<store::Entry>,
    synced: usize,
    instance: u64,
    /// The seconds since the Unix epoch of each reading of the clock, with no uncertainty.
    clock: u64,
}

impl Double {
    /// The store of account `a1`: the passkeys `a1p`, `a1q`, and `a1r`, the registration ceremony `reg-1`, the
    /// recovery value `a1c`, and the bootstrap value `b-1`, each at version 1.
    fn new() -> Self {
        let mut double = Self::default();
        for (kind, id) in [
            (Kind::Credential, "a1p"),
            (Kind::Credential, "a1q"),
            (Kind::Credential, "a1r"),
            (Kind::Registration, "reg-1"),
            (Kind::Recovery, "a1c"),
            (Kind::Bootstrap, "b-1"),
        ] {
            double.records.insert(key(kind, id), record(1));
        }
        double
    }

    /// Appends and syncs `bodies` from the first sequence, as an earlier driver did.
    fn write(&mut self, bodies: &[(OperationId, Body)]) {
        let mut head = Mark::EMPTY;
        for (operation, body) in bodies {
            let append = head.next(operation, body, Limits::default()).unwrap();
            head = append.head();
            self.journal.push(append.entry().clone());
        }
        self.synced = self.journal.len();
    }

    fn execute(&mut self, effect: Effect<'_>, fault: Option<Fault>) -> Output {
        if fault == Some(Fault::Fail) {
            self.journal.truncate(self.synced);
            return Output::Failed;
        }
        let output = match effect {
            Effect::Start => {
                self.instance += 1;
                Output::Started(Instance(self.instance))
            }
            Effect::Read(key) => Output::Read(self.records.get(key).cloned()),
            Effect::Commit(proposal, instance) => Output::Committed(self.commit(proposal, instance)),
            Effect::Expire(kind, before, limit, instance) => {
                if instance.0 != self.instance {
                    return Output::Expired(Expiry::Superseded);
                }
                let ended: Vec<Key> = self
                    .records
                    .iter()
                    .filter(|(key, record)| Kind::of(key) == Some(kind) && record.end.is_some_and(|end| end < before))
                    .map(|(key, _)| key.clone())
                    .take(limit.get())
                    .collect();
                for key in &ended {
                    self.records.remove(key);
                }
                Output::Expired(Expiry::Removed(ended.len()))
            }
            Effect::Range(prefix, after, limit) => Output::Range(
                self.records
                    .iter()
                    .filter(|(key, _)| {
                        key.as_bytes().starts_with(prefix.as_bytes()) && after.is_none_or(|after| *key > after)
                    })
                    .take(limit.get())
                    .map(|(key, record)| (key.clone(), record.clone()))
                    .collect(),
            ),
            Effect::Append(append, instance) => {
                let head = self
                    .journal
                    .last()
                    .map_or(Mark::EMPTY, |entry| Mark::of(entry.sequence, &entry.data));
                if instance.0 != self.instance || head != append.after() {
                    return Output::Appended(JournalWrite::Conflict);
                }
                self.journal.push(append.entry().clone());
                Output::Appended(JournalWrite::Accepted)
            }
            Effect::Sync(instance) => {
                if instance.0 != self.instance {
                    return Output::Synced(JournalWrite::Conflict);
                }
                self.synced = self.journal.len();
                Output::Synced(JournalWrite::Accepted)
            }
            Effect::ReadJournal(after, limit) => Output::Journal(
                self.journal[..self.synced]
                    .iter()
                    .filter(|entry| entry.sequence > after)
                    .take(limit.get())
                    .cloned()
                    .collect(),
            ),
        };
        if fault == Some(Fault::Lost) {
            self.journal.truncate(self.synced);
            return Output::Failed;
        }
        output
    }

    fn commit(&mut self, proposal: &Proposal, instance: Instance) -> Commit {
        if instance.0 != self.instance {
            return Commit::Superseded;
        }
        let (outcome, stored) = outcome_record(proposal);
        if let Some(earlier) = self.records.get(&outcome) {
            return outcome_of(&proposal.operation().id, earlier).map_or(Commit::Conflict, Commit::Recorded);
        }
        let holds = proposal.dependencies().iter().all(|dependency| match dependency {
            Dependency::Version(key, version) => self.records.get(key).is_some_and(|record| record.version == *version),
            Dependency::Absent(key) => !self.records.contains_key(key),
            Dependency::Policy(_) => true,
        });
        if !holds {
            return Commit::Conflict;
        }
        let now = Reading::new(
            Duration::from_secs(self.clock),
            Some(Duration::ZERO),
            ReadingSource::Caller,
        );
        if store::expired(proposal.deadline(), now) {
            return Commit::Expired;
        }
        for change in proposal.changes() {
            match change {
                Change::Write {
                    key,
                    version,
                    end,
                    data,
                } => {
                    let record = Record {
                        version: version.clone(),
                        end: *end,
                        data: data.clone(),
                    };
                    self.records.insert(key.clone(), record);
                }
                Change::End(key) => {
                    self.records.remove(key);
                }
            }
        }
        let (audit, audited) = audit_record(proposal);
        self.records.insert(audit, audited);
        self.records.insert(outcome, stored);
        self.records.extend(intent_records(proposal).unwrap());
        Commit::Accepted
    }
}

/// A driver, its double, the events of its runs, and the answers.
struct Harness {
    driver: Driver,
    double: Double,
    events: Vec<Event>,
    tickets: Vec<Ticket>,
    answers: BTreeMap<Ticket, Answer>,
}

impl Harness {
    fn new(declaration: Declaration, double: Double) -> Self {
        Self {
            driver: Driver::new(Profile::new(declaration).unwrap(), Limits::default()).unwrap(),
            double,
            events: Vec::new(),
            tickets: Vec::new(),
            answers: BTreeMap::new(),
        }
    }

    /// A harness whose driver started on the store of [`Double::new`] and serves.
    fn serving(journal: bool) -> Self {
        let mut harness = Self::new(declaration(journal), Double::new());
        harness.driver.start(now());
        harness.run(|_| None);
        assert_eq!(harness.driver.status(), Status::Serving);
        harness.events.clear();
        harness
    }

    fn submit(&mut self, proposal: Proposal, plan: Plan) -> Ticket {
        let ticket = self.driver.submit(proposal, plan).unwrap();
        self.tickets.push(ticket);
        ticket
    }

    /// A lookup of the operation `name` for the request `name`.
    fn lookup(&mut self, name: &str) -> Ticket {
        let operation: Operation = proposal(name, &[], &[]).operation().clone();
        let ticket = self.driver.lookup(operation).unwrap();
        self.tickets.push(ticket);
        ticket
    }

    /// Runs the driver until it has no effect, or until `stop` holds for its next effect. `fault` chooses the fault
    /// of each effect.
    fn run_until(&mut self, mut stop: impl FnMut(&Event) -> bool, mut fault: impl FnMut(&Event) -> Option<Fault>) {
        while let Some(effect) = self.driver.effect() {
            let event = Event::of(&effect);
            if stop(&event) {
                return;
            }
            let chosen = fault(&event);
            let output = self.double.execute(effect, chosen);
            self.events.push(event);
            if chosen.is_some() {
                self.events.push(Event::Crash);
            }
            self.driver.give(output).unwrap();
            self.answers();
        }
        self.answers();
    }

    /// Takes each answer that is ready.
    fn answers(&mut self) {
        for ticket in &self.tickets {
            if let Some(answer) = self.driver.take(*ticket) {
                self.events.push(Event::Answer(*ticket));
                self.answers.insert(*ticket, answer);
            }
        }
    }

    fn run(&mut self, fault: impl FnMut(&Event) -> Option<Fault>) {
        self.run_until(|_| false, fault);
    }

    /// The position of the first event equal to `event`.
    fn at(&self, event: &Event) -> usize {
        self.events
            .iter()
            .position(|candidate| candidate == event)
            .unwrap_or_else(|| panic!("no event {event:?} in {:?}", self.events))
    }

    fn has(&self, event: &Event) -> bool {
        self.events.contains(event)
    }

    fn holds(&self, key: &Key) -> bool {
        self.double.records.contains_key(key)
    }
}

/// A fault at the first event that `at` matches.
fn once(mut at: impl FnMut(&Event) -> bool, fault: Fault) -> impl FnMut(&Event) -> Option<Fault> {
    let mut done = false;
    move |event| {
        let hit = !done && at(event);
        done |= hit;
        hit.then_some(fault)
    }
}

fn committed(name: &str) -> impl Fn(&Event) -> bool {
    let id = op(name);
    move |event| matches!(event, Event::Commit(operation, _) if *operation == id)
}

/// The effect of a crash point.
#[derive(Clone, Copy, Debug)]
enum Point {
    /// The append of the end entry.
    End,
    /// The commit of the operation.
    Commit,
    /// The first commit after the creation entry: the end of the journal intent.
    AfterCreation,
}

/// For each crash point of the model, the effects of the next start give the model's outcome: an end entry that no
/// commit followed gets a void, a commit with no creation entry gets it, and a lookup reports a commit only after its
/// creation entry.
#[test]
fn each_crash_point_gives_the_model_outcome_after_the_next_start() {
    let reg = key(Kind::Registration, "reg-1");
    let a1s = key(Kind::Credential, "a1s");
    // (crash point, operation, effect, fault, a void at the start, a creation entry at the start, commit)
    let rows = [
        ("cChecked", "e-1", Point::End, Fault::Fail, false, false, false),
        ("cJournaled", "e-1", Point::Commit, Fault::Fail, true, false, false),
        ("cCommitted", "e-1", Point::Commit, Fault::Lost, false, true, true),
        ("cCreated", "i-1", Point::AfterCreation, Fault::Fail, false, false, true),
    ];
    for (point, name, effect, fault, void, creation, commits) in rows {
        let mut harness = Harness::serving(true);
        let (proposal, plan) = if name == "e-1" { enrollment() } else { issue() };
        let ticket = harness.submit(proposal, plan);
        let mut created = false;
        let at = |event: &Event| match effect {
            Point::End => *event == appended(Written::End, name),
            Point::Commit => committed(name)(event),
            Point::AfterCreation => {
                created |= *event == appended(Written::Creation, name);
                created && matches!(event, Event::Commit(..))
            }
        };
        harness.run(once(at, fault));
        assert_eq!(harness.driver.status(), Status::Down, "{point}");
        // The client of a crash before the creation entry gets an unknown outcome.
        let answer = harness.answers.remove(&ticket);
        if matches!(effect, Point::AfterCreation) {
            assert_matches!(answer, Some(Answer::Outcome(Outcome::Accepted(_))), "{point}");
        } else {
            assert_matches!(answer, Some(Answer::Outcome(Outcome::Unknown(_))), "{point}");
        }

        harness.events.clear();
        harness.driver.start(now());
        let lookup = harness.lookup(name);
        harness.run(|_| None);
        assert_eq!(harness.has(&appended(Written::Void, name)), void, "{point}");
        assert_eq!(harness.has(&appended(Written::Creation, name)), creation, "{point}");
        let found = harness.answers.remove(&lookup);
        if commits {
            assert_matches!(found, Some(Answer::Lookup(Lookup::Committed(_))), "{point}");
        } else {
            assert_matches!(found, Some(Answer::Lookup(Lookup::Unknown)), "{point}");
        }
        if name == "e-1" {
            assert_eq!(harness.holds(&a1s), commits, "{point}");
            assert_eq!(harness.holds(&reg), !commits, "{point}");
        }
        let intents = harness
            .double
            .records
            .keys()
            .filter(|key| Kind::of(key) == Some(Kind::Intent));
        assert_eq!(intents.count(), 0, "{point}: the start ends each journal intent");
    }
}

/// A refusal writes the void of its end entry before its answer, so a refusal that the client received stays true
/// after a restore: for a conflict, and for an operation identity that another request used.
#[test]
fn a_refusal_voids_its_end_entry_before_its_answer() {
    let a1p = key(Kind::Credential, "a1p");
    for refusal in ["conflict", "reuse"] {
        let mut harness = Harness::serving(true);
        if refusal == "conflict" {
            harness.double.records.insert(a1p.clone(), record(2));
        } else {
            let (outcome, stored) = outcome_record(&request("u-1", "another request", &[], &[]));
            harness.double.records.insert(outcome, stored);
        }
        let ticket = harness.submit(proposal("u-1", &[&a1p], &[]), plan(&passkeys(), &[]));
        harness.run(|_| None);
        let void = harness.at(&appended(Written::Void, "u-1"));
        assert_eq!(harness.events[void + 1], Event::Sync, "{refusal}");
        assert!(void < harness.at(&Event::Answer(ticket)), "{refusal}");
        let answer = harness.answers.remove(&ticket);
        if refusal == "conflict" {
            assert_matches!(answer, Some(Answer::Outcome(Outcome::Conflict)));
        } else {
            assert_matches!(
                answer,
                Some(Answer::Outcome(Outcome::Refused(crate::transition::Error::Reuse)))
            );
        }
    }
}

/// A proposal with a deadline commits only when the clock of the binding, in the step of the commit, is before it. A
/// reading that can be at the deadline refuses with no write, and the void of the end entry comes before the answer,
/// so a restore does not apply the end.
#[test]
fn a_commit_at_or_after_the_deadline_of_its_proposal_refuses_with_no_write() {
    let a1p = key(Kind::Credential, "a1p");
    for (clock, commits) in [(1_059, true), (1_060, false)] {
        let mut harness = Harness::serving(true);
        harness.double.clock = clock;
        let mut proposal = proposal("u-1", &[&a1p], &[]);
        proposal.until(Duration::from_secs(1_060));
        let ticket = harness.submit(proposal, plan(&passkeys(), &[]));
        harness.run(|_| None);
        let committed = harness.at(&Event::Commit(op("u-1"), Instance(1)));
        assert!(harness.at(&appended(Written::End, "u-1")) < committed, "{clock}");
        let answer = harness.answers.remove(&ticket);
        if commits {
            assert_matches!(answer, Some(Answer::Outcome(Outcome::Accepted(_))));
            assert!(!harness.holds(&a1p));
        } else {
            let void = harness.at(&appended(Written::Void, "u-1"));
            assert!(committed < void && void < harness.at(&Event::Answer(ticket)), "{clock}");
            assert_matches!(
                answer,
                Some(Answer::Outcome(Outcome::Refused(crate::transition::Error::Expired)))
            );
            assert!(harness.holds(&a1p));
        }
    }
}

/// The floor of a counter is durable before the commit of a value above it. One floor entry covers a block of
/// values, so the next value of the block needs none.
#[test]
fn a_floor_is_durable_before_the_commit_of_a_value_above_it() {
    let mut harness = Harness::serving(true);
    assert_eq!(harness.driver.allocate(Kind::Session), Ok(1));
    let first = harness.submit(proposal("s-1", &[], &[&key(Kind::Session, "s-1")]), Plan::default());
    harness.run(|_| None);
    let floor = harness.at(&appended(Written::Floor, "s-1"));
    assert_eq!(harness.events[floor + 1], Event::Sync);
    assert!(floor < harness.at(&Event::Commit(op("s-1"), Instance(1))));
    assert_matches!(
        harness.answers.remove(&first),
        Some(Answer::Outcome(Outcome::Accepted(_)))
    );

    assert_eq!(harness.driver.allocate(Kind::Session), Ok(2));
    harness.submit(proposal("s-2", &[], &[&key(Kind::Session, "s-2")]), Plan::default());
    harness.run(|_| None);
    assert!(!harness.has(&appended(Written::Floor, "s-2")));
}

/// After a crash between a commit and its creation entry, the next start writes the creation entry before it serves.
/// So no lookup of the commit, and no anchor change of the same owner, is answered before it.
#[test]
fn no_answer_comes_before_the_creation_entry_of_an_anchor_commit_of_the_owner() {
    let mut harness = Harness::serving(true);
    let (proposal_e, plan_e) = enrollment();
    harness.submit(proposal_e, plan_e);
    harness.run(once(committed("e-1"), Fault::Lost));

    harness.events.clear();
    harness.driver.start(now());
    let lookup = harness.lookup("e-1");
    let mut held = passkeys();
    held.push(anchor(&key(Kind::Credential, "a1s"), sign_in("a1")));
    let unlink = harness.submit(proposal("u-1", &[&key(Kind::Credential, "a1p")], &[]), plan(&held, &[]));
    harness.run(|_| None);
    let creation = harness.at(&appended(Written::Creation, "e-1"));
    assert!(creation < harness.at(&Event::Answer(lookup)));
    assert!(creation < harness.at(&Event::Answer(unlink)));
    assert_matches!(
        harness.answers.remove(&lookup),
        Some(Answer::Lookup(Lookup::Committed(_)))
    );
}

/// A binding whose record bound is below the longest record that the driver writes for itself gets no driver: it
/// refuses with the least bound. At that bound, the driver serves.
#[test]
fn a_record_bound_below_the_records_of_the_driver_refuses_at_the_construction() {
    let least = record_bytes_min(Limits::default());
    let driver = |bytes| {
        let declaration = Declaration {
            record_bytes_max: bytes,
            ..declaration(true)
        };
        Driver::new(Profile::new(declaration).unwrap(), Limits::default())
    };
    assert_matches!(driver(least - 1), Err(Error::RecordBound(bytes)) if bytes == least);
    assert_matches!(driver(least), Ok(_));
}

/// A proposal with a record longer than the record bound of the binding refuses at its submission, so the binding
/// never gets its commit.
#[test]
fn a_proposal_over_the_record_bound_refuses_before_the_binding_gets_it() {
    let least = record_bytes_min(Limits::default());
    let bounded = Declaration {
        record_bytes_max: least,
        ..declaration(true)
    };
    let mut harness = Harness::new(bounded, Double::new());
    harness.driver.start(now());
    harness.run(|_| None);
    let credential = key(Kind::Credential, "c-9");
    let mut long = proposal("w-1", &[], &[]);
    long.read(Dependency::Absent(credential.clone())).unwrap();
    long.change(Change::Write {
        key: credential,
        version: version(1),
        end: None,
        data: vec![0; least + 1].into(),
    })
    .unwrap();
    assert_eq!(harness.driver.submit(long, Plan::default()), Err(Error::RecordBytes));
    harness.run(|_| None);
    assert!(
        !harness
            .events
            .iter()
            .any(|event| matches!(event, Event::Commit(id, _) if *id == op("w-1")))
    );
}

/// Each commit carries the instance number of the latest start, so the binding refuses a commit of an earlier
/// instance.
#[test]
fn a_commit_carries_the_instance_number_of_the_latest_start() {
    let mut harness = Harness::serving(true);
    harness.submit(
        proposal("u-1", &[&key(Kind::Credential, "a1p")], &[]),
        plan(&passkeys(), &[]),
    );
    harness.run(once(committed("u-1"), Fault::Fail));
    harness.driver.start(now());
    harness.run(|_| None);
    harness.events.clear();
    harness.submit(
        proposal("u-2", &[&key(Kind::Credential, "a1q")], &[]),
        plan(&passkeys(), &[]),
    );
    harness.run(|_| None);
    assert!(harness.has(&Event::Commit(op("u-2"), Instance(2))));
}

/// A journal with two in-doubt consumptions: the recovery `r-1` of `a2c`, then the bootstrap `b-1`.
fn in_doubt() -> Double {
    let mut double = Double::default();
    let a2c = key(Kind::Recovery, "a2c");
    let boot = key(Kind::Bootstrap, "b-1");
    double.records.insert(a2c.clone(), record(1));
    double.records.insert(boot.clone(), record(1));
    let a2n = key(Kind::Credential, "a2n");
    let recovered = journal::entries(&proposal("r-1", &[&a2c], &[&a2n]), &[], &[(a2n, sign_in("a2"))]).unwrap();
    let adm1 = key(Kind::Administrator, "adm1");
    let administrator = Role::Administrator(Id::new("acme", "auth").unwrap());
    let booted = journal::entries(&proposal("b-1", &[&boot], &[&adm1]), &[], &[(adm1, administrator)]).unwrap();
    double.write(&[
        (op("r-1"), Body::End(recovered.end.unwrap())),
        (op("b-1"), Body::End(booted.end.unwrap())),
    ]);
    double
}

/// The original alpha form. A restore sets its flag even when it owes zero consumptions.
fn alpha_mark(owed: Option<&[u64]>) -> Record {
    let form = Value::Array(vec![
        Value::Text("rsauthnz.store.mark.1"),
        Value::Unsigned(0),
        Value::Bytes(&[0; 32]),
        Value::Bool(owed.is_some()),
        Value::Unsigned(1),
        Value::Array(owed.unwrap_or_default().iter().copied().map(Value::Unsigned).collect()),
        Value::Array(vec![]),
    ]);
    Record {
        version: AuthorityVersion::new(Id::new("rsauthnz", "driver").unwrap(), &1u64.to_be_bytes()).unwrap(),
        end: None,
        data: cbor::encode(&form, Limits::default()).unwrap().into_boxed_slice(),
    }
}

/// An alpha mark can identify an ordinary start or list the consumptions of an unfinished restore.
#[test]
fn an_alpha_store_keeps_a_live_challenge_or_completes_its_recorded_consumptions() {
    let challenge = key(Kind::SignIn, "pending");
    for (begin, restored, owed, mut double) in [
        (Begin::Start, false, vec![], Double::new()),
        (Begin::Start, true, vec![1, 2], in_doubt()),
        (Begin::Restore, true, vec![], in_doubt()),
    ] {
        double
            .records
            .insert(key(Kind::Mark, ""), alpha_mark(restored.then_some(&owed)));
        double.records.insert(
            challenge.clone(),
            Record {
                end: Some(Duration::from_secs(2_000)),
                ..record(1)
            },
        );
        let mut harness = Harness::new(declaration(true), double);
        if begin == Begin::Restore {
            harness.driver.restore(now()).unwrap();
        } else {
            harness.driver.start(now());
        }
        harness.run(|_| None);
        assert_eq!(harness.driver.status(), Status::Serving);
        assert_eq!(harness.holds(&challenge), !restored);
        if restored {
            assert!(harness.holds(&key(Kind::Credential, "a2n")));
            assert!(harness.holds(&key(Kind::Administrator, "adm1")));
        }
    }
}

/// A consistent alpha store keeps its authority and ends pending ceremonies once, even if cleanup loses its worker.
#[test]
fn an_ambiguous_alpha_upgrade_cleans_up_once_when_authority_agrees() {
    let mut double = Double::new();
    let passkey = key(Kind::Credential, "a1p");
    let grant = key(Kind::Grant, "revised");
    let approval = key(Kind::Approval, "pending");
    let pending = Record {
        end: Some(Duration::from_secs(2_000)),
        ..record(1)
    };
    double.records.insert(key(Kind::Mark, ""), alpha_mark(Some(&[])));
    double.records.insert(approval.clone(), pending.clone());
    double.records.insert(grant.clone(), record(2));
    let cancel = proposal("cancelled", &[&passkey], &[]);
    let revision = proposal("revision", &[&grant], &[]);
    double.write(&[
        (op("enrolled"), Body::Creation(vec![anchor(&passkey, sign_in("a1"))])),
        (
            op("cancelled"),
            Body::End(journal::entries(&cancel, &[], &[]).unwrap().end.unwrap()),
        ),
        (op("cancelled"), Body::Void(Sequence(2))),
        (
            op("revision"),
            Body::End(journal::entries(&revision, &[], &[]).unwrap().end.unwrap()),
        ),
    ]);
    let mut harness = Harness::new(declaration(true), double);
    harness.driver.start(now());
    harness.run(once(|event| *event == Event::Expire(Kind::SignIn), Fault::Fail));
    assert_eq!(harness.driver.status(), Status::Down);
    harness.driver.start(now());
    harness.run(|_| None);
    assert_eq!(harness.driver.status(), Status::Serving);
    assert_eq!(harness.double.records.get(&passkey), Some(&record(1)));
    assert_eq!(harness.double.records.get(&grant), Some(&record(2)));
    assert!(!harness.holds(&approval));

    harness.double.records.insert(approval.clone(), pending);
    harness.driver.start(now());
    harness.run(|_| None);
    assert_eq!(harness.driver.status(), Status::Serving);
    assert!(harness.holds(&approval));
}

/// Begin an ordinary upgrade. The refusal identifies the entry and leaves both durable stores intact.
fn alpha_review(double: &Double, entry: u64) -> Harness {
    let mut harness = Harness::new(declaration(true), double.clone());
    harness.driver.start(now());
    harness.run(|_| None);
    assert_eq!(
        harness.driver.status(),
        Status::Refused(Error::AlphaReview {
            instance: Instance(1),
            sequence: Sequence(entry),
        })
    );
    assert_eq!(harness.double.records, double.records);
    assert_eq!(harness.double.journal, double.journal);
    harness
}

/// Give the verified source to the same driver and run its storage effects.
fn resolve_alpha(harness: &mut Harness, source: AlphaSource) -> Status {
    let Status::Refused(Error::AlphaReview { instance, .. }) = harness.driver.status() else {
        panic!("the upgrade must request review");
    };
    harness.driver.resolve_alpha(instance, source, now()).unwrap();
    harness.run(|_| None);
    harness.driver.status()
}

/// An unresolved removal has two possible histories. The operator verifies the primary before choosing one.
#[test]
fn a_reviewed_alpha_removal_follows_the_verified_source_in_its_original_instance() {
    let passkey = key(Kind::Credential, "a1p");
    let mut double = Double::new();
    double.records.insert(key(Kind::Mark, ""), alpha_mark(Some(&[])));
    let unlink = proposal("unlink", &[&passkey], &[]);
    let end = journal::entries(&unlink, &[], &[]).unwrap().end.unwrap();
    double.write(&[
        (op("enrolled"), Body::Creation(vec![anchor(&passkey, sign_in("a1"))])),
        (op("unlink"), Body::End(end)),
    ]);
    for source in [AlphaSource::Intact, AlphaSource::Snapshot] {
        let mut harness = alpha_review(&double, 2);
        assert_eq!(
            harness.driver.resolve_alpha(Instance(0), source, now()),
            Err(Error::Superseded)
        );
        assert_eq!(resolve_alpha(&mut harness, source), Status::Serving);
        assert_eq!(harness.driver.instance(), Ok(Instance(1)));
        assert_eq!(harness.holds(&passkey), source == AlphaSource::Intact);
        assert_eq!(
            harness.has(&appended(Written::Void, "unlink")),
            source == AlphaSource::Intact
        );
    }
    // A peer takes a new instance while the review is open. The old decision cannot write its void.
    let mut harness = alpha_review(&double, 2);
    assert_matches!(
        harness.double.execute(Effect::Start, None),
        Output::Started(Instance(2))
    );
    assert_eq!(
        resolve_alpha(&mut harness, AlphaSource::Intact),
        Status::Refused(Error::Superseded)
    );
    assert_eq!(harness.double.records, double.records);
    assert_eq!(harness.double.journal, double.journal);
}

/// A receipt proves a removal committed. A declaration that the primary is intact cannot cancel it.
#[test]
fn review_of_an_alpha_grant_cannot_void_a_committed_revocation() {
    let grant = key(Kind::Grant, "g-1");
    let revoked = proposal("revoke", &[&grant], &[]);
    let mut double = Double::new();
    double.records.insert(grant.clone(), record(1));
    double.records.insert(key(Kind::Mark, ""), alpha_mark(Some(&[])));
    double.records.extend([outcome_record(&revoked)]);
    double.write(&[(
        op("revoke"),
        Body::End(journal::entries(&revoked, &[], &[]).unwrap().end.unwrap()),
    )]);
    let mut harness = alpha_review(&double, 1);
    let review = harness.driver.status();
    assert_eq!(resolve_alpha(&mut harness, AlphaSource::Intact), review);
    assert_eq!(harness.double.records, double.records);
    assert_eq!(harness.double.journal, double.journal);
    assert_eq!(resolve_alpha(&mut harness, AlphaSource::Snapshot), Status::Serving);
    assert!(!harness.holds(&grant));
}

/// A missing credential needs a verified snapshot. Conflicting bytes at one version need a trustworthy store copy.
#[test]
fn an_alpha_upgrade_checks_the_record_of_a_live_credential() {
    let passkey = key(Kind::Credential, "a1p");
    for held in [
        None,
        Some(Record {
            data: Box::new(*b"different"),
            ..record(1)
        }),
    ] {
        let mut double = Double::new();
        double.records.remove(&passkey);
        double
            .records
            .extend(held.clone().map(|record| (passkey.clone(), record)));
        double.records.insert(key(Kind::Mark, ""), alpha_mark(Some(&[])));
        double.write(&[(op("enrolled"), Body::Creation(vec![anchor(&passkey, sign_in("a1"))]))]);
        let mut harness = alpha_review(&double, 1);
        let review = harness.driver.status();
        assert_eq!(resolve_alpha(&mut harness, AlphaSource::Intact), review);
        let resolved = resolve_alpha(&mut harness, AlphaSource::Snapshot);
        if held.is_some() {
            assert_eq!(resolved, review);
            assert_eq!(harness.double.records, double.records);
            assert_eq!(harness.double.journal, double.journal);
        } else {
            assert_eq!(resolved, Status::Serving);
            assert_eq!(harness.double.records.get(&passkey), Some(&record(1)));
        }
    }
}

/// A spent recovery value with a missing outcome can still create a credential during snapshot restore.
#[test]
fn an_alpha_upgrade_pauses_before_completing_an_uncertain_credential() {
    let mut double = in_doubt();
    double.records.remove(&key(Kind::Recovery, "a2c"));
    double.records.remove(&key(Kind::Bootstrap, "b-1"));
    double.records.insert(key(Kind::Mark, ""), alpha_mark(Some(&[])));
    let mut harness = alpha_review(&double, 1);
    assert_eq!(resolve_alpha(&mut harness, AlphaSource::Intact), Status::Serving);
    assert!(!harness.holds(&key(Kind::Credential, "a2n")));
}

/// The in-doubt consumptions that a restore owes stay in the mark record: after a crash during the completions, the
/// next start completes the rest before it serves. A second restore decision would find the bootstrap value ended.
#[test]
fn a_crash_during_the_completions_completes_the_rest_at_the_next_start() {
    let mut harness = Harness::new(declaration(true), in_doubt());
    harness.driver.restore(now()).unwrap();
    harness.run(once(committed("b-1"), Fault::Fail));
    assert_eq!(harness.driver.status(), Status::Down);
    assert!(harness.holds(&key(Kind::Credential, "a2n")));
    assert!(!harness.holds(&key(Kind::Administrator, "adm1")));

    harness.events.clear();
    harness.driver.start(now());
    let user = harness.submit(proposal("x-1", &[], &[&key(Kind::Credential, "x")]), Plan::default());
    harness.run(|_| None);
    assert!(harness.holds(&key(Kind::Administrator, "adm1")));
    let completion = harness.at(&Event::Commit(op("b-1"), Instance(2)));
    assert!(completion < harness.at(&Event::Commit(op("x-1"), Instance(2))));
    assert!(!harness.has(&Event::Commit(op("r-1"), Instance(2))));
    assert_matches!(
        harness.answers.remove(&user),
        Some(Answer::Outcome(Outcome::Accepted(_)))
    );
}

/// A cancelled commit with an end entry still ends in its commit: its entry gets no void, its caller gets no answer,
/// and it keeps the turn of its owner until the commit result.
#[test]
fn a_cancelled_commit_with_an_entry_ends_in_its_commit() {
    let mut harness = Harness::serving(true);
    let a1p = key(Kind::Credential, "a1p");
    let first = harness.submit(proposal("u-1", &[&a1p], &[]), plan(&passkeys(), &[]));
    harness.run_until(committed("u-1"), |_| None);
    // The anchor change of the same owner waits when the cancel comes, so a released turn would run it first.
    let a1q = key(Kind::Credential, "a1q");
    harness.submit(proposal("u-2", &[&a1q], &[]), plan(&passkeys()[1..], &[]));
    harness.driver.cancel(first);
    harness.run(|_| None);
    assert!(!harness.has(&appended(Written::Void, "u-1")));
    assert!(!harness.holds(&a1p));
    assert!(!harness.has(&Event::Answer(first)));
    assert!(harness.at(&Event::Commit(op("u-1"), Instance(1))) < harness.at(&appended(Written::End, "u-2")));
}

/// A restore applies each entry after the mark of its snapshot: it ends the passkey that an unlink ended, writes the
/// passkey that an enrollment created, ends each pending sign-in challenge, and sets the replay floor. A lookup that
/// finds no outcome record is then unknown.
#[test]
fn a_restore_applies_the_journal_after_the_mark_of_its_snapshot() {
    let mut double = Double::new();
    let a1p = key(Kind::Credential, "a1p");
    let a1s = key(Kind::Credential, "a1s");
    let challenge = key(Kind::SignIn, "ch-1");
    let pending = Record {
        end: Some(Duration::from_secs(1_100)),
        ..record(1)
    };
    double.records.insert(challenge.clone(), pending);
    let removal = journal::entries(&proposal("u-1", &[&a1p], &[]), &[], &[]).unwrap();
    double.write(&[
        (op("u-1"), Body::End(removal.end.unwrap())),
        (op("e-1"), Body::Creation(vec![anchor(&a1s, sign_in("a1"))])),
    ]);
    let mut harness = Harness::new(declaration(true), double);
    harness.driver.restore(now()).unwrap();
    let lookup = harness.lookup("u-1");
    harness.run(|_| None);
    assert_eq!(harness.driver.status(), Status::Serving);
    assert!(!harness.holds(&a1p));
    assert!(harness.holds(&a1s));
    assert!(!harness.holds(&challenge));
    assert!(harness.holds(&key(Kind::ReplayFloor, "")));
    assert_matches!(harness.answers.remove(&lookup), Some(Answer::Lookup(Lookup::Unknown)));
}

/// A binding with no journal gets the commit path with no journal effect, and its restore refuses.
#[test]
fn a_binding_without_a_journal_gets_no_journal_effect() {
    let mut harness = Harness::serving(false);
    let (proposal_e, plan_e) = enrollment();
    let enrolled = harness.submit(proposal_e, plan_e);
    harness.submit(
        proposal("u-1", &[&key(Kind::Credential, "a1p")], &[]),
        plan(&passkeys(), &[]),
    );
    harness.run(|_| None);
    let journal = |event: &Event| matches!(event, Event::Append(..) | Event::Sync | Event::ReadJournal);
    assert!(!harness.events.iter().any(journal));
    assert_matches!(
        harness.answers.remove(&enrolled),
        Some(Answer::Outcome(Outcome::Accepted(_)))
    );
    assert_eq!(harness.driver.restore(now()), Err(Error::Unsupported));
}

/// The last-anchor check refuses an unlink of the last sign-in method before any effect.
#[test]
fn the_last_sign_in_method_cannot_be_unlinked() {
    let mut harness = Harness::serving(true);
    let a1p = key(Kind::Credential, "a1p");
    let ticket = harness.submit(proposal("u-1", &[&a1p], &[]), plan(&[anchor(&a1p, sign_in("a1"))], &[]));
    harness.run(|_| None);
    assert_eq!(harness.events, [Event::Answer(ticket)]);
    assert_matches!(
        harness.answers.remove(&ticket),
        Some(Answer::Outcome(Outcome::Refused(crate::transition::Error::LastAnchor)))
    );
}

/// The driver moves the mark past each reflected entry, so a later start reads only the entries after it. The newest
/// floor of a counter holds the mark, so the driver writes the floor again first, and the counter keeps its floor.
#[test]
fn an_advance_moves_the_mark_past_the_reflected_entries() {
    let mut harness = Harness::serving(true);
    let a1p = key(Kind::Credential, "a1p");
    assert_eq!(harness.driver.allocate(Kind::Session), Ok(1));
    harness.submit(proposal("s-1", &[], &[&key(Kind::Session, "s-1")]), Plan::default());
    harness.submit(proposal("u-1", &[&a1p], &[]), plan(&passkeys(), &[]));
    harness.driver.advance(now());
    harness.run(|_| None);

    harness.events.clear();
    harness.driver.start(now());
    harness.run(|_| None);
    assert!(!harness.has(&Event::Read(a1p)));
    assert_eq!(harness.driver.allocate(Kind::Session), Ok(super::FLOOR_BLOCK.get() + 1));
}

/// How a test changes the store between two starts.
#[derive(Clone, Copy, Debug)]
enum Between {
    /// An unlink and a start, then a rollback of the store to its state before them.
    StartThenRollback,
    /// An enrollment, then a rollback of the store to its state before it.
    CreationThenRollback,
    /// A start that crashes before its write of the mark record.
    CrashBeforeMark,
    /// A start that crashes after its write of the mark record, before the floor entry of the write.
    CrashAfterMark,
}

/// A start refuses a store state that a restore made, because the journal shows a commit that the store lost: a
/// later write of the mark record, or the creation entry of an anchor that the store lacks. A start that crashed
/// lost no commit, so the next start serves.
#[test]
fn a_start_on_a_rolled_back_store_refuses_and_a_crashed_start_does_not() {
    let a1p = key(Kind::Credential, "a1p");
    let rows = [
        (Between::StartThenRollback, Status::Refused(Error::Restored)),
        (Between::CreationThenRollback, Status::Refused(Error::Restored)),
        (Between::CrashBeforeMark, Status::Serving),
        (Between::CrashAfterMark, Status::Serving),
    ];
    for (between, status) in rows {
        let mut harness = Harness::serving(true);
        let snapshot = harness.double.records.clone();
        match between {
            Between::StartThenRollback => {
                let unlink = harness.submit(proposal("u-1", &[&a1p], &[]), plan(&passkeys(), &[]));
                harness.run(|_| None);
                assert_matches!(
                    harness.answers.remove(&unlink),
                    Some(Answer::Outcome(Outcome::Accepted(_)))
                );
                harness.driver.start(now());
                harness.run(|_| None);
                harness.double.records = snapshot;
            }
            Between::CreationThenRollback => {
                let (proposal_e, plan_e) = enrollment();
                harness.submit(proposal_e, plan_e);
                harness.run(|_| None);
                harness.double.records = snapshot;
            }
            Between::CrashBeforeMark | Between::CrashAfterMark => {
                harness.driver.start(now());
                let mut commits = 0;
                let after = matches!(between, Between::CrashAfterMark);
                // The mark commit precedes its journal entry. The replay floor opens after that entry is durable.
                harness.run(once(
                    |event| {
                        commits += usize::from(matches!(event, Event::Commit(..)));
                        !after && commits == 1 && matches!(event, Event::Commit(..))
                            || after && commits >= 1 && matches!(event, Event::Append(..))
                    },
                    Fault::Fail,
                ));
                assert_eq!(harness.driver.status(), Status::Down, "{between:?}");
            }
        }
        harness.events.clear();
        harness.driver.start(now());
        harness.run(|_| None);
        assert_eq!(harness.driver.status(), status, "{between:?}");
        assert!(!harness.has(&appended(Written::Void, "u-1")), "{between:?}");
    }

    // The restore of the same store state serves, and applies the unlink.
    let mut harness = Harness::serving(true);
    let snapshot = harness.double.records.clone();
    let unlink = harness.submit(proposal("u-1", &[&a1p], &[]), plan(&passkeys(), &[]));
    harness.run(|_| None);
    assert_matches!(
        harness.answers.remove(&unlink),
        Some(Answer::Outcome(Outcome::Accepted(_)))
    );
    harness.driver.start(now());
    harness.run(|_| None);
    harness.double.records = snapshot;
    harness.driver.restore(now()).unwrap();
    harness.run(|_| None);
    assert_eq!(harness.driver.status(), Status::Serving);
    assert!(!harness.holds(&a1p));
}

/// A client starts an operation again only when the driver can serve it later: after a full queue, before a start, and
/// as the refusal of the proposal gives it. Each other refusal of the driver stays until the operator acts, so the
/// client refuses, and does not send the request again in a loop.
#[test]
fn a_driver_refusal_restarts_only_when_the_driver_can_serve_the_operation_later() {
    for (error, recovery) in [
        (Error::Full, Recovery::Restart),
        (Error::Down, Recovery::Restart),
        (Error::Transition(transition::Error::Changed), Recovery::Restart),
        (Error::Transition(transition::Error::Reuse), Recovery::Refuse),
        (Error::RecordBytes, Recovery::Refuse),
        (Error::Binding, Recovery::Refuse),
        (Error::Restored, Recovery::Refuse),
    ] {
        assert_eq!(error.recovery(), recovery, "{error:?}");
    }
}
