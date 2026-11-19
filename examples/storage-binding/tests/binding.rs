//! The file binding keeps the storage contract: it passes the conformance suite with and without a journal, and a
//! start after a torn write serves the durable state.

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
use rsauthnz::store::{Commit, Entry, Journal, Kind, Restore, Sequence, Store};
use rsauthnz::time::{Reading, ReadingSource};
use rsauthnz::transition::{Audit, Change, Dependency, Key, OperationId, Proposal};
use rsauthnz_conformance::suite::{self, Case, Report};
use storage_binding::{Files, JOURNAL_FILE, STORE_FILE};

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

/// A crash in the middle of a write leaves a torn frame at the end of a file: here a complete length with a wrong
/// checksum. The next start drops it, and serves the commit and the synced journal entry before it.
#[test]
fn a_start_after_a_torn_write_serves_the_durable_state() {
    let root = scratch("torn");
    let make = || Files::new(root.join("store"), journal(&root), RETENTION);
    let key = Kind::Session.key(b"s-1").unwrap();
    {
        let mut binding = make();
        let instance = ready(binding.start()).unwrap();
        assert_eq!(ready(binding.commit(&write(&key), instance)).unwrap(), Commit::Accepted);
        assert_eq!(ready(binding.append(b"entry")).unwrap(), Sequence(1));
        ready(binding.sync()).unwrap();
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
    ready(binding.start()).unwrap();
    assert!(ready(Store::read(&mut binding, &key)).unwrap().is_some());
    let entries = ready(Journal::read(&mut binding, Sequence(0), NonZeroUsize::MAX)).unwrap();
    let expected = Entry {
        sequence: Sequence(1),
        data: (*b"entry").into(),
    };
    assert_eq!(entries, [expected]);
    assert_eq!(ready(binding.append(b"next")).unwrap(), Sequence(2));
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
