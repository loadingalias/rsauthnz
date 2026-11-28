//! The file binding keeps the storage contract: it passes the conformance suite with and without a journal, and a
//! start after a torn write serves the durable state.
// The binding claims durability on a Unix file system only: its durable rename syncs the directory.
#![cfg(unix)]

use core::assert_matches;
use core::mem::DropGuard;
use core::num::NonZeroUsize;
use core::pin::pin;
use core::task::{Context, Poll, Waker};
use core::time::Duration;
use std::fs::{self, OpenOptions};
use std::io::Write as _;
use std::path::{Path, PathBuf};
use std::{env, process};

use rsauthnz::cbor::Value;
use rsauthnz::id::{AuthorityVersion, Id, Principal};
use rsauthnz::limits::Limits;
use rsauthnz::store::journal::{Append, Body, Floor, Mark};
use rsauthnz::store::{Commit, Journal, JournalWrite, Kind, Restore, Sequence, Store};
use rsauthnz::time::{Reading, ReadingSource};
use rsauthnz::transition::{Audit, Change, Dependency, Key, OperationId, Proposal};
use rsauthnz_conformance::suite::{self, Case, Report, Subject as _};
use storage_binding::{Error, Files, INSTANCE_FILE, JOURNAL_FILE, STORE_FILE};

/// The outcome retention of each binding of the tests.
const RETENTION: Duration = Duration::from_secs(86_400);

/// The output of `future`. The futures of the file binding are ready at their first poll.
fn ready<F: Future>(future: F) -> F::Output {
    match pin!(future).poll(&mut Context::from_waker(Waker::noop())) {
        Poll::Ready(output) => Some(output),
        Poll::Pending => None,
    }
    .expect("the file binding is ready at its first poll")
}

/// A new empty directory for the test `name`, which the guard removes.
fn scratch(name: &str) -> DropGuard<PathBuf, impl FnOnce(PathBuf)> {
    let dir = env::temp_dir().join(format!("storage-binding-{}-{name}", process::id()));
    if dir.exists() {
        fs::remove_dir_all(&dir).expect("the test can remove a directory of an earlier run");
    }
    fs::create_dir_all(&dir).expect("the test can make its directory");
    DropGuard::new(dir, |dir| {
        fs::remove_dir_all(dir).expect("the test can remove its directory")
    })
}

/// The journal of a binding in `dir`.
fn journal(dir: &Path) -> Restore {
    Restore::Journal {
        location: dir
            .join("journal")
            .to_str()
            .expect("the temporary directory has a UTF-8 path")
            .into(),
        failure_domain: "the scratch directory of the test".into(),
    }
}

/// Runs the suite on bindings in new directories under `root`. `restore` gives the restore support of a binding in a
/// directory.
fn run(root: &Path, restore: fn(&Path) -> Restore) -> Report {
    let mut bindings = 0_u32;
    ready(suite::run(|| {
        bindings += 1;
        let dir = root.join(bindings.to_string());
        Files::new(dir.join("store"), restore(&dir), RETENTION)
    }))
}

#[test]
fn the_binding_with_a_journal_passes_each_case_of_the_suite() {
    let root = scratch("journal");
    let report = run(&root, journal);
    assert!(report.failures.is_empty(), "{report}");
    assert!(report.skipped.is_empty(), "{report}");
}

#[test]
fn the_binding_without_a_journal_passes_each_case_that_it_selects() {
    let root = scratch("no-journal");
    let report = run(&root, |_| Restore::Unsupported);
    assert!(report.failures.is_empty(), "{report}");
    // The guide skips only the restore cases of a binding without a journal, so the commit case runs.
    assert!(!report.skipped.contains(&Case::Commit), "{report}");
}

fn floor(after: Mark, value: u64) -> Append {
    let body = Body::Floor(Floor {
        kind: Kind::Session,
        value,
    });
    let id = OperationId::new(&value.to_be_bytes()).expect("eight bytes identify the operation");
    after
        .next(&id, &body, Limits::default())
        .expect("a session floor fits the journal limits")
}

/// A crash in the middle of a write leaves a torn frame at the end of a file: here a complete length with a wrong
/// checksum. The next start drops it, and serves the commit and the synced journal entry before it.
#[test]
fn a_start_after_a_torn_write_serves_the_durable_state() {
    let root = scratch("torn");
    let make = || Files::new(root.join("store"), journal(&root), RETENTION);
    let key = Kind::Session.key(b"s-1").unwrap();
    let first = floor(Mark::EMPTY, 1);
    {
        let mut binding = make();
        let instance = ready(binding.start()).unwrap();
        assert_eq!(ready(binding.commit(&write(&key), instance)).unwrap(), Commit::Accepted);
        assert_eq!(ready(binding.append(&first, instance)).unwrap(), JournalWrite::Accepted);
        assert_eq!(ready(binding.sync(instance)).unwrap(), JournalWrite::Accepted);
    }
    let torn = [3, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1, 2, 3];
    for file in [
        root.join("store").join(STORE_FILE),
        root.join("journal").join(JOURNAL_FILE),
    ] {
        OpenOptions::new()
            .append(true)
            .open(file)
            .unwrap()
            .write_all(&torn)
            .unwrap();
    }

    let mut binding = make();
    let current = ready(binding.start()).unwrap();
    assert!(ready(Store::read(&mut binding, &key)).unwrap().is_some());
    let entries = ready(Journal::read(&mut binding, Sequence(0), NonZeroUsize::MAX)).unwrap();
    assert_eq!(entries, core::slice::from_ref(first.entry()));
    assert_eq!(
        ready(binding.append(&floor(first.head(), 2), current)).unwrap(),
        JournalWrite::Accepted
    );
}

#[test]
fn a_stopped_writer_preserves_the_commits_of_its_replacement() {
    let root = scratch("replacement");
    let make = || Files::new(root.join("store"), journal(&root), RETENTION);
    let mut old = make();
    ready(old.start()).unwrap();
    let snapshot = old.snapshot();
    old.restart();

    let mut current = make();
    let instance = ready(current.start()).unwrap();
    let key = Kind::Session.key(b"session").unwrap();
    let first = floor(Mark::EMPTY, 1);
    assert_eq!(ready(current.commit(&write(&key), instance)).unwrap(), Commit::Accepted);
    assert_eq!(ready(current.append(&first, instance)).unwrap(), JournalWrite::Accepted);
    assert_eq!(ready(current.sync(instance)).unwrap(), JournalWrite::Accepted);
    old.restore(&snapshot);
    assert_matches!(ready(Store::read(&mut old, &key)), Err(Error::Stopped));

    let mut other = Files::new(root.join("other-store"), journal(&root), RETENTION);
    assert_matches!(ready(other.start()), Err(Error::Locked));
    drop(current);
    ready(old.start()).unwrap();
    assert!(ready(Store::read(&mut old, &key)).unwrap().is_some());
    assert_eq!(
        ready(Journal::read(&mut old, Sequence(0), NonZeroUsize::MAX)).unwrap(),
        core::slice::from_ref(first.entry())
    );
}

#[test]
fn a_missing_or_empty_instance_cannot_reopen_existing_logs() {
    let root = scratch("instance");
    let mut binding = Files::new(root.join("store"), journal(&root), RETENTION);
    ready(binding.start()).unwrap();
    binding.restart();
    let instance = root.join("journal").join(INSTANCE_FILE);
    fs::remove_file(&instance).unwrap();
    assert_matches!(ready(binding.start()), Err(Error::Instance));
    fs::write(instance, []).unwrap();
    assert_matches!(ready(binding.start()), Err(Error::Instance));
}

/// A proposal that writes the new record `key`.
fn write(key: &Key) -> Proposal {
    const VALID: &str = "each identifier of the test is valid";
    let audit = Audit {
        actor: Principal::Human(Id::new("acme", "u-1").expect(VALID)),
        action: Id::new("acme.auth", "test").expect(VALID),
        time: Reading::new(
            Duration::from_secs(1_000),
            Some(Duration::from_secs(1)),
            ReadingSource::Caller,
        ),
    };
    let operation = OperationId::new(b"op-1").expect("a short operation identity is valid");
    let mut proposal =
        Proposal::new(operation, audit, &Value::Null, Limits::default()).expect("a null request has a form");
    let change = Change::Write {
        key: key.clone(),
        version: AuthorityVersion::new(Id::new("acme", "auth").expect(VALID), &[1]).expect(VALID),
        end: None,
        data: (*b"record").into(),
    };
    proposal
        .read(Dependency::Absent(key.clone()))
        .and_then(|()| proposal.change(change))
        .expect("the proposal reads the absence of its one write");
    proposal
}
