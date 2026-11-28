//! Measures the journal cost of each transition kind on the file binding: the journal entries and bytes of each
//! commit, and the commit latency at p50 and p99, with restore support and without it. Each measured commit runs
//! through the commit driver, after an untimed commit that writes the records that it reads. The rounds interleave
//! the kinds and the two modes.
//!
//! Run it on a quiet host with an optimized build. The optional argument is the directory for the files, on the disk
//! under test:
//!
//! ```sh
//! cargo run --locked --release -p storage-binding --example journal_cost -- "$HOME"
//! ```

use core::mem::DropGuard;
use core::pin::pin;
use core::task::{Context, Poll, Waker};
use core::time::Duration;
use std::path::Path;
use std::time::Instant;
use std::{env, fs, process};

use rsauthnz::cbor::Value;
use rsauthnz::id::{AuthorityVersion, Human, Id, Principal};
use rsauthnz::limits::Limits;
use rsauthnz::store::driver::{Answer, Driver, Effect, Output, Plan, Status};
use rsauthnz::store::journal::{Anchor, Role};
use rsauthnz::store::{Journal, Kind, Profile, Restore, Store};
use rsauthnz::time::{Reading, ReadingSource};
use rsauthnz::transition::{Audit, Change, Dependency, Key, OperationId, Outcome, Proposal};
use storage_binding::Files;

/// The measured commits of each transition kind in each mode.
const RUNS: usize = 500;

/// The record form of each write.
const DATA: &[u8] = b"record";

/// The end of each pending ceremony and one-use value: after [`now`].
const LATER: Duration = Duration::from_secs(2_000);

/// A transition kind: its name, and the untimed commit that writes its records and the measured commit, for the
/// record identifier `id`.
type Transition = (&'static str, fn(&str) -> [(Proposal, Plan); 2]);

/// The transition kinds. A sign-in and an approval pay for no anchor, so they have no journal entry. Each other kind
/// invalidates authority, and an enrollment also creates an anchor.
const TRANSITIONS: [Transition; 8] = [
    ("sign-in", |id| {
        let (challenge, session) = (key(Kind::SignIn, id), key(Kind::Session, id));
        let seed = Build::new(id, "seed").writes(&challenge, Some(LATER)).done();
        let sign_in = Build::new(id, "sign-in")
            .ends(&challenge, 1)
            .writes(&session, None)
            .done();
        [(seed, Plan::default()), (sign_in, Plan::default())]
    }),
    ("approval consumption", |id| {
        let approval = key(Kind::Approval, id);
        let seed = Build::new(id, "seed").writes(&approval, Some(LATER)).done();
        let consumption = Build::new(id, "consume").ends(&approval, 1).done();
        [(seed, Plan::default()), (consumption, Plan::default())]
    }),
    ("session revocation", |id| {
        let session = key(Kind::Session, id);
        let seed = Build::new(id, "seed").writes(&session, None).done();
        let revocation = Build::new(id, "revoke").ends(&session, 1).done();
        [(seed, Plan::default()), (revocation, Plan::default())]
    }),
    ("session renewal", |id| {
        let session = key(Kind::Session, id);
        let seed = Build::new(id, "seed").writes(&session, None).done();
        let renewal = Build::new(id, "renew").replaces(&session).done();
        [(seed, Plan::default()), (renewal, replaced(&session))]
    }),
    ("grant revocation", |id| {
        let grant = key(Kind::Grant, id);
        let seed = Build::new(id, "seed").writes(&grant, None).done();
        let revocation = Build::new(id, "revoke").ends(&grant, 1).done();
        [(seed, Plan::default()), (revocation, Plan::default())]
    }),
    ("grant change", |id| {
        let grant = key(Kind::Grant, id);
        let seed = Build::new(id, "seed").writes(&grant, None).done();
        let change = Build::new(id, "change").replaces(&grant).done();
        [(seed, Plan::default()), (change, replaced(&grant))]
    }),
    ("passkey unlink", |id| {
        let (kept, unlinked) = (
            key(Kind::Credential, &format!("{id}/p")),
            key(Kind::Credential, &format!("{id}/q")),
        );
        let seed = Build::new(id, "seed")
            .writes(&kept, None)
            .writes(&unlinked, None)
            .done();
        let role = Role::SignIn(account(id));
        let anchors = vec![(kept.clone(), role.clone()), (unlinked.clone(), role.clone())];
        let unlink = Build::new(id, "unlink").ends(&unlinked, 1).done();
        let held = vec![anchor(&kept, role.clone()), anchor(&unlinked, role)];
        let seed_plan = Plan {
            anchors,
            ..Plan::default()
        };
        [
            (seed, seed_plan),
            (
                unlink,
                Plan {
                    held,
                    ..Plan::default()
                },
            ),
        ]
    }),
    ("passkey enrollment", |id| {
        let (registration, passkey) = (key(Kind::Registration, id), key(Kind::Credential, id));
        let seed = Build::new(id, "seed").writes(&registration, Some(LATER)).done();
        let enrollment = Build::new(id, "enroll")
            .ends(&registration, 1)
            .writes(&passkey, None)
            .done();
        let plan = Plan {
            anchors: vec![(passkey, Role::SignIn(account(id)))],
            ..Plan::default()
        };
        [(seed, Plan::default()), (enrollment, plan)]
    }),
];

/// The journal appends of one commit.
#[derive(Default)]
struct Meter {
    entries: usize,
    bytes: usize,
}

/// The measurement of one transition kind in one mode.
struct Row {
    entries: (usize, usize),
    bytes: (usize, usize),
    p50: Duration,
    p99: Duration,
}

#[expect(clippy::print_stdout, reason = "the measurement prints its table")]
fn main() {
    let root = env::args_os()
        .nth(1)
        .map_or_else(env::temp_dir, Into::into)
        .join(format!("journal-cost-{}", process::id()));
    let root = DropGuard::new(root, |root| {
        fs::remove_dir_all(root).expect("the measurement can remove its files")
    });
    let journal = root.join("journal");
    let restore = Restore::Journal {
        location: journal.to_str().expect("the directory has a UTF-8 path").into(),
        failure_domain: "the disk under test".into(),
    };
    let mut modes = [
        Mode::new(&root.join("store-journal"), restore),
        Mode::new(&root.join("store-plain"), Restore::Unsupported),
    ];
    // Each round measures each kind in each mode. The first kind and the order of the modes change from round to
    // round, so a change of the disk over time affects each cell the same.
    for run in 0..RUNS {
        for offset in 0..TRANSITIONS.len() {
            let index = (offset + run) % TRANSITIONS.len();
            let id = format!("t{index}-{run}");
            let order = if run % 2 == 0 { [0, 1] } else { [1, 0] };
            for mode in order {
                modes[mode].measure(index, &id);
            }
        }
    }
    let [with, without] = modes.map(Mode::rows);
    println!("{RUNS} commits of each kind in each mode, interleaved. Latency in microseconds.");
    println!();
    println!("| Transition | Entries | Bytes | p50 journal | p99 journal | p50 no journal | p99 no journal |");
    println!("| --- | --- | --- | --- | --- | --- | --- |");
    for (((name, _), with), without) in TRANSITIONS.iter().zip(with).zip(without) {
        assert_eq!(without.entries, (0, 0), "a binding with no journal has no entry");
        println!(
            "| {name} | {} | {} | {} | {} | {} | {} |",
            span(with.entries),
            span(with.bytes),
            with.p50.as_micros(),
            with.p99.as_micros(),
            without.p50.as_micros(),
            without.p99.as_micros(),
        );
    }
}

/// A binding under measurement, its driver, and the journal appends and the latency of each measured commit of each
/// transition kind.
struct Mode {
    binding: Files,
    driver: Driver,
    samples: Vec<Vec<(Meter, Duration)>>,
}

impl Mode {
    /// A started binding with its store in `store` and `restore`.
    fn new(store: &Path, restore: Restore) -> Self {
        let mut binding = Files::new(store.into(), restore, Duration::from_secs(86_400));
        let profile = Profile::new(binding.declaration()).expect("the file binding declares a serializable commit");
        let mut driver = Driver::new(profile, Limits::default()).expect("the record bound of the binding is enough");
        driver.start(now());
        settle(&mut driver, &mut binding, &mut Meter::default());
        assert_eq!(driver.status(), Status::Serving);
        let samples = TRANSITIONS.iter().map(|_| Vec::with_capacity(RUNS)).collect();
        Self {
            binding,
            driver,
            samples,
        }
    }

    /// Commits the records of the transition kind `index` for the record identifier `id`, then measures its commit.
    fn measure(&mut self, index: usize, id: &str) {
        let [seed, measured] = TRANSITIONS[index].1(id);
        commit(&mut self.driver, &mut self.binding, seed, &mut Meter::default());
        let mut meter = Meter::default();
        let start = Instant::now();
        commit(&mut self.driver, &mut self.binding, measured, &mut meter);
        self.samples[index].push((meter, start.elapsed()));
    }

    /// The row of each transition kind.
    fn rows(self) -> Vec<Row> {
        self.samples
            .into_iter()
            .map(|samples| {
                let mut latencies: Vec<_> = samples.iter().map(|(_, latency)| *latency).collect();
                latencies.sort_unstable();
                let span = |of: fn(&Meter) -> usize| {
                    let values = samples.iter().map(|(meter, _)| of(meter));
                    (values.clone().min().unwrap_or(0), values.max().unwrap_or(0))
                };
                Row {
                    entries: span(|meter| meter.entries),
                    bytes: span(|meter| meter.bytes),
                    p50: latencies[RUNS / 2],
                    p99: latencies[(RUNS * 99).div_ceil(100) - 1],
                }
            })
            .collect()
    }
}

/// `low` alone when the span has one value, else `low–high`.
fn span((low, high): (usize, usize)) -> String {
    if low == high {
        low.to_string()
    } else {
        format!("{low}–{high}")
    }
}

/// Submits `proposal` with `plan`, executes the effects of the driver, and checks that the commit accepted it.
fn commit(driver: &mut Driver, binding: &mut Files, (proposal, plan): (Proposal, Plan), meter: &mut Meter) {
    let ticket = driver.submit(proposal, plan).expect("the driver serves");
    settle(driver, binding, meter);
    let answer = driver.take(ticket);
    assert!(
        matches!(answer, Some(Answer::Outcome(Outcome::Accepted(_)))),
        "{answer:?}"
    );
}

/// Executes the effects of `driver` on `binding` until the driver waits (guide step 10). It counts each journal append
/// in `meter`.
fn settle(driver: &mut Driver, binding: &mut Files, meter: &mut Meter) {
    while let Some(effect) = driver.effect() {
        if let Effect::Append(append, _) = &effect {
            meter.entries += 1;
            meter.bytes += append.entry().data.len();
        }
        let output = ready(execute(binding, effect));
        driver.give(output).expect("the output answers its effect");
    }
}

/// The output of the primitive call `effect` on `binding`, as in guide step 10.
async fn execute(binding: &mut Files, effect: Effect<'_>) -> Output {
    match effect {
        Effect::Start => binding.start().await.map_or(Output::Failed, Output::Started),
        Effect::Read(key) => Store::read(binding, key).await.map_or(Output::Failed, Output::Read),
        Effect::Commit(proposal, instance) => binding
            .commit(proposal, instance)
            .await
            .map_or(Output::Failed, Output::Committed),
        Effect::Expire(kind, before, limit, instance) => binding
            .expire(kind, before, limit, instance)
            .await
            .map_or(Output::Failed, Output::Expired),
        Effect::Range(prefix, after, limit) => binding
            .range(prefix, after, limit)
            .await
            .map_or(Output::Failed, Output::Range),
        Effect::Append(append, instance) => binding
            .append(append, instance)
            .await
            .map_or(Output::Failed, Output::Appended),
        Effect::Sync(instance) => binding.sync(instance).await.map_or(Output::Failed, Output::Synced),
        Effect::ReadJournal(after, limit) => Journal::read(binding, after, limit)
            .await
            .map_or(Output::Failed, Output::Journal),
    }
}

/// The output of `future`. The futures of the file binding are ready at their first poll.
fn ready<F: Future>(future: F) -> F::Output {
    match pin!(future).poll(&mut Context::from_waker(Waker::noop())) {
        Poll::Ready(output) => Some(output),
        Poll::Pending => None,
    }
    .expect("the file binding is ready at its first poll")
}

/// The reading of each decision.
fn now() -> Reading {
    Reading::new(
        Duration::from_secs(1_000),
        Some(Duration::from_secs(1)),
        ReadingSource::Caller,
    )
}

/// The version `n` of the authority.
fn version(n: u8) -> AuthorityVersion {
    let authority = Id::new("acme", "auth").expect("the authority is a valid identifier");
    AuthorityVersion::new(authority, &[n]).expect("a one-byte coordinate is valid")
}

fn account(id: &str) -> Id<Human> {
    Id::new("acme", id).expect("each account is a valid identifier")
}

fn key(kind: Kind, id: &str) -> Key {
    kind.key(id.as_bytes()).expect("each record has a short key")
}

/// The anchor that [`Build::writes`] of `key` created, with `role`.
fn anchor(key: &Key, role: Role) -> Anchor {
    Anchor {
        key: key.clone(),
        role,
        version: version(1),
        end: None,
        data: DATA.into(),
    }
}

/// The plan of a write that replaces the dead version of `key`.
fn replaced(key: &Key) -> Plan {
    Plan {
        replaced: vec![key.clone()],
        ..Plan::default()
    }
}

/// A proposal, built one read and change after the other.
struct Build(Proposal);

impl Build {
    /// The proposal of the operation `step` on the records `id`.
    fn new(id: &str, step: &str) -> Self {
        let audit = Audit {
            actor: Principal::Human(account("u-1")),
            action: Id::new("acme.auth", step).expect("each step is a valid identifier"),
            time: now(),
        };
        let operation = OperationId::new(format!("{id}/{step}").as_bytes()).expect("each operation is short");
        Self(Proposal::new(operation, audit, &Value::Null, Limits::default()).expect("a null request has a form"))
    }

    fn read(mut self, dependency: Dependency) -> Self {
        self.0.read(dependency).expect("each proposal reads each record once");
        self
    }

    fn change(mut self, change: Change) -> Self {
        self.0
            .change(change)
            .expect("each proposal changes each record once, after its read");
        self
    }

    /// Reads the record `key` at version `at`, and ends it.
    fn ends(self, key: &Key, at: u8) -> Self {
        self.read(Dependency::Version(key.clone(), version(at)))
            .change(Change::End(key.clone()))
    }

    /// Reads the absence of the record `key`, and writes it at version 1 with `end`.
    fn writes(self, key: &Key, end: Option<Duration>) -> Self {
        self.read(Dependency::Absent(key.clone())).change(Change::Write {
            key: key.clone(),
            version: version(1),
            end,
            data: DATA.into(),
        })
    }

    /// Reads the record `key` at version 1, and writes it at version 2.
    fn replaces(self, key: &Key) -> Self {
        self.read(Dependency::Version(key.clone(), version(1)))
            .change(Change::Write {
                key: key.clone(),
                version: version(2),
                end: None,
                data: DATA.into(),
            })
    }

    fn done(self) -> Proposal {
        self.0
    }
}
