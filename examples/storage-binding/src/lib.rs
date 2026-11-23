//! A storage binding of rsauthnz on files, with one writer: the example of the storage binding guide
//! ([`rsauthnz_conformance::guide`]). It implements only the primitives, and the commit driver of the core does the
//! sequencing.
//!
//! [`Files`] keeps the store as a log of writes in one directory, and the restore journal as a log of entries in
//! another one. Each commit appends its writes to the store log as one frame and syncs the file. A start reads the log
//! into memory, drops each write after the last sync that returned, and rewrites the log with the current records.
//! Each primitive holds one lock for its checks and its writes, and a lock file keeps out a second process, so the
//! binding is the one writer of its files.
//!
//! The futures do blocking file I/O and are ready at their first poll, so run them on a thread that can block. A
//! durable rename needs a sync of its directory, which needs a Unix file system.

mod form;
mod subject;

use core::fmt;
use core::num::NonZeroUsize;
use core::ops::Bound;
use core::time::Duration;
use std::collections::{BTreeMap, BTreeSet};
use std::fs::{self, File, OpenOptions, TryLockError};
use std::io::{self, Read as _, Seek as _, SeekFrom, Write as _};
use std::path::{Path, PathBuf};
use std::sync::{Arc, Mutex, MutexGuard};

use rsauthnz::id::AuthorityVersion;
use rsauthnz::store::{
    Commit, CrashInjection, CrashLoss, Declaration, Entry, Instance, Isolation, Journal, Kind, Record, Restore,
    Sequence, Store, audit_record, intent_records, outcome_of, outcome_record, policy_key,
};
use rsauthnz::transition::{Change, Dependency, Key, Proposal};
use rsauthnz_conformance::suite::Fault;

/// The most bytes in one record that the binding stores. It is above
/// [`record_bytes_min`](rsauthnz::store::driver::record_bytes_min) of the default limits.
pub const RECORD_BYTES_MAX: usize = 1 << 20;

/// The name of the store log in the store directory.
pub const STORE_FILE: &str = "store";

/// The name of the journal in the journal directory.
pub const JOURNAL_FILE: &str = "journal";

/// The name of the last store instance number: in the journal directory, or in the store directory of a binding with
/// no journal.
pub const INSTANCE_FILE: &str = "instance";

/// The name of the lock file in the store directory.
pub const LOCK_FILE: &str = "lock";

/// A handle of a file binding. The clones of a handle are handles of one binding.
#[derive(Clone, Debug)]
pub struct Files {
    store: PathBuf,
    declaration: Declaration,
    inner: Arc<Mutex<Inner>>,
}

/// The state that the handles of one binding share.
#[derive(Debug)]
struct Inner {
    state: State,
    /// The fault that the next call of its primitive takes.
    fault: Option<Fault>,
}

#[derive(Debug)]
enum State {
    /// The files are open, and the binding serves each primitive.
    Serving(Open),
    /// An error or a restart stopped the binding. It serves again after a start.
    Stopped(Durable),
}

/// The lengths of the files at the last write and sync that returned. A start drops the bytes after them: the writes
/// whose commit or sync did not return.
#[derive(Clone, Copy, Debug)]
struct Durable {
    store: u64,
    journal: u64,
}

impl Durable {
    /// No length known: the first start of the process reads each complete frame of each file.
    const UNKNOWN: Self = Self {
        store: u64::MAX,
        journal: u64::MAX,
    };
}

/// The open files and the current records.
#[derive(Debug)]
struct Open {
    instance: Instance,
    records: Records,
    store: File,
    /// The durable length of the store log. Each write syncs before it returns.
    store_len: u64,
    journal: Option<Log>,
    /// The lock of the store directory, which the binding holds while it serves.
    _lock: File,
}

/// The current records, and the key of each record with an end, by kind and end. Thus an expiry reads only the
/// records that it removes.
#[derive(Debug, Default)]
struct Records {
    by_key: BTreeMap<Key, Record>,
    ends: BTreeMap<Kind, BTreeSet<(Duration, Key)>>,
}

/// The open journal.
#[derive(Debug)]
struct Log {
    file: File,
    /// The sequence and the offset of each entry in the file, in the order of the file.
    entries: Vec<(Sequence, u64)>,
    /// The number of entries and the length of the file at the last sync that returned.
    synced: (usize, u64),
    /// The length of the file.
    len: u64,
    /// The sequence of the next append. A loss of entries does not lower it.
    next: Sequence,
}

/// The cause of a failed primitive. No error holds the bytes of a record.
#[derive(Debug)]
pub enum Error {
    /// A file operation failed. The binding stops: start it again.
    Io(io::Error),
    /// The binding stopped at an earlier error, an injected fault, or a restart. Start it again.
    Stopped,
    /// The fault that the conformance suite injected. The binding stops: start it again.
    Fault(Fault),
    /// A file has a complete frame with no valid form, or a proposal has an intent with no CBOR form. A file that
    /// changed outside the binding needs a restore.
    Form,
    /// Another binding holds the lock of the store directory. Stop it, or give each binding its own directory.
    Locked,
    /// The binding declares no restore support, so it has no journal.
    NoJournal,
}

impl fmt::Display for Error {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Io(error) => write!(f, "a file operation failed: {error}"),
            Self::Stopped => f.write_str("the binding stopped at an error or a restart, so start it again"),
            Self::Fault(fault) => write!(f, "the injected fault {fault:?} stopped the binding"),
            Self::Form => f.write_str("a file or a proposal has a record with no valid form"),
            Self::Locked => f.write_str("another binding holds the lock of the store directory"),
            Self::NoJournal => f.write_str("the binding declares no restore support, so it has no journal"),
        }
    }
}

impl core::error::Error for Error {
    fn source(&self) -> Option<&(dyn core::error::Error + 'static)> {
        match self {
            Self::Io(error) => Some(error),
            Self::Stopped | Self::Fault(_) | Self::Form | Self::Locked | Self::NoJournal => None,
        }
    }
}

impl From<io::Error> for Error {
    fn from(error: io::Error) -> Self {
        Self::Io(error)
    }
}

impl Files {
    /// A binding with its store log in the directory `store`. With [`Restore::Journal`], the journal is in the
    /// directory `location`: put it outside the failure domain of the snapshots of the store, for example on another
    /// disk. With [`Restore::Unsupported`], the binding has no journal. The binding keeps each audit and outcome
    /// record for `outcome_retention` after the audit time of its proposal.
    #[must_use]
    pub fn new(store: PathBuf, restore: Restore, outcome_retention: Duration) -> Self {
        let declaration = Declaration {
            // Each primitive holds the one lock for its checks and its writes, so the commits run one at a time.
            isolation: Isolation::Serializable,
            crash_loss: CrashLoss::Unsynced,
            outcome_retention,
            crash_injection: CrashInjection::Supported,
            restore,
            key_bytes_max: Key::BYTES_MAX,
            record_bytes_max: RECORD_BYTES_MAX,
        };
        let inner = Inner {
            state: State::Stopped(Durable::UNKNOWN),
            fault: None,
        };
        Self {
            store,
            declaration,
            inner: Arc::new(Mutex::new(inner)),
        }
    }

    /// The journal directory, or `None` for a binding with no journal.
    fn journal(&self) -> Option<&Path> {
        match &self.declaration.restore {
            Restore::Journal { location, .. } => Some(Path::new(&**location)),
            Restore::Unsupported => None,
        }
    }

    /// The shared state. A panic while a handle held it leaves the state unknown, so the binding stops.
    fn lock(&self) -> Result<MutexGuard<'_, Inner>, Error> {
        self.inner.lock().map_err(|_| Error::Stopped)
    }

    /// Opens the files for a start (guide step 2). Reads the complete frames of the store log up to its durable
    /// length, rewrites the log with the current records, drops the journal after its durable length, and writes the
    /// next instance number.
    fn open(&self, durable: Durable) -> Result<Open, Error> {
        fs::create_dir_all(&self.store)?;
        let lock = File::options()
            .write(true)
            .create(true)
            .truncate(false)
            .open(self.store.join(LOCK_FILE))?;
        lock.try_lock().map_err(|error| match error {
            TryLockError::WouldBlock => Error::Locked,
            TryLockError::Error(error) => Error::Io(error),
        })?;
        let mut log = read(&self.store.join(STORE_FILE))?;
        log.truncate(usize::try_from(durable.store).unwrap_or(usize::MAX));
        let mut records = Records::default();
        for (_, payload) in form::frames(&log).0 {
            for (key, record) in form::read_writes(payload).ok_or(Error::Form)? {
                records.apply(key, record);
            }
        }
        let compact = records.form();
        replace(&self.store, STORE_FILE, &compact)?;
        let store = OpenOptions::new().append(true).open(self.store.join(STORE_FILE))?;
        let journal = self.journal().map(|dir| Log::open(dir, durable.journal)).transpose()?;
        let instance = next_instance(self.journal().unwrap_or(&self.store))?;
        Ok(Open {
            instance,
            records,
            store,
            store_len: compact.len() as u64,
            journal,
            _lock: lock,
        })
    }
}

impl Inner {
    /// Runs `primitive` on the open files. An error stops the binding until the next start (guide step 9).
    fn serve<T>(&mut self, primitive: impl FnOnce(&mut Open) -> Result<T, Error>) -> Result<T, Error> {
        let State::Serving(open) = &mut self.state else {
            return Err(Error::Stopped);
        };
        let result = primitive(open);
        if result.is_err() {
            self.stop();
        }
        result
    }

    /// Stops the binding and closes its files. The next start drops each write after the durable lengths.
    fn stop(&mut self) {
        self.state = State::Stopped(self.state.durable());
    }
}

impl State {
    fn durable(&self) -> Durable {
        match self {
            Self::Serving(open) => Durable {
                store: open.store_len,
                journal: open.journal.as_ref().map_or(0, |log| log.synced.1),
            },
            Self::Stopped(durable) => *durable,
        }
    }
}

impl Open {
    fn log(&mut self) -> Result<&mut Log, Error> {
        self.journal.as_mut().ok_or(Error::NoJournal)
    }

    /// The commit of `proposal` (guide steps 4 and 5). Each fault gives an error. With [`Fault::LostResponse`], the
    /// commit is durable first.
    fn commit(
        &mut self,
        proposal: &Proposal,
        instance: Instance,
        retention: Duration,
        fault: Option<Fault>,
    ) -> Result<Commit, Error> {
        let answer = match self.answer(proposal, instance)? {
            Some(answer) => answer,
            None => {
                self.write(writes(proposal, retention)?, fault)?;
                Commit::Accepted
            }
        };
        fault.map_or(Ok(answer), |fault| Err(Error::Fault(fault)))
    }

    /// The answer of a commit of `proposal` that writes nothing, or `None` for a commit that writes.
    fn answer(&self, proposal: &Proposal, instance: Instance) -> Result<Option<Commit>, Error> {
        if instance != self.instance {
            return Ok(Some(Commit::Conflict));
        }
        let (key, _) = outcome_record(proposal);
        if let Some(record) = self.records.by_key.get(&key) {
            let operation = outcome_of(&proposal.operation().id, record).ok_or(Error::Form)?;
            return Ok(Some(Commit::Recorded(operation)));
        }
        let holds = proposal
            .dependencies()
            .iter()
            .all(|dependency| self.records.holds(dependency));
        Ok((!holds).then_some(Commit::Conflict))
    }

    /// Appends `writes` to the store log as one frame, syncs the file, and applies them. With
    /// [`Fault::CrashBeforeCommit`], the sync fails, so the next start drops the frame.
    fn write(&mut self, writes: Vec<(Key, Option<Record>)>, fault: Option<Fault>) -> Result<(), Error> {
        let frame = form::frame(&form::writes(writes.iter().map(|(key, record)| (key, record.as_ref()))));
        self.store.write_all(&frame)?;
        if fault == Some(Fault::CrashBeforeCommit) {
            return Err(Error::Fault(Fault::CrashBeforeCommit));
        }
        self.store.sync_data()?;
        self.store_len += frame.len() as u64;
        for (key, record) in writes {
            self.records.apply(key, record);
        }
        Ok(())
    }
}

/// The writes of the commit of `proposal`: each change, the audit record, each intent record, and the outcome record.
/// The audit and outcome records end at the audit time plus `retention` (guide step 5).
fn writes(proposal: &Proposal, retention: Duration) -> Result<Vec<(Key, Option<Record>)>, Error> {
    let end = proposal
        .audit()
        .time
        .estimate()
        .checked_add(retention)
        .unwrap_or(Duration::MAX);
    let mut writes: Vec<_> = proposal
        .changes()
        .iter()
        .map(|change| match change {
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
                (key.clone(), Some(record))
            }
            Change::End(key) => (key.clone(), None),
        })
        .collect();
    let intents = intent_records(proposal).map_err(|_| Error::Form)?;
    writes.extend(intents.into_iter().map(|(key, record)| (key, Some(record))));
    for (key, mut record) in [audit_record(proposal), outcome_record(proposal)] {
        record.end = Some(end);
        writes.push((key, Some(record)));
    }
    Ok(writes)
}

impl Records {
    /// Writes `record` at `key`, or removes the record of `key` for `None`.
    fn apply(&mut self, key: Key, record: Option<Record>) {
        if let Some(old) = self.by_key.remove(&key)
            && let (Some(end), Some(kind)) = (old.end, Kind::of(&key))
            && let Some(ends) = self.ends.get_mut(&kind)
        {
            ends.remove(&(end, key.clone()));
        }
        let Some(record) = record else { return };
        if let (Some(end), Some(kind)) = (record.end, Kind::of(&key)) {
            self.ends.entry(kind).or_default().insert((end, key.clone()));
        }
        self.by_key.insert(key, record);
    }

    /// Whether `dependency` holds (guide step 4.3).
    fn holds(&self, dependency: &Dependency) -> bool {
        let at = |key: &Key, version: &AuthorityVersion| {
            self.by_key.get(key).is_some_and(|record| record.version == *version)
        };
        match dependency {
            Dependency::Version(key, version) => at(key, version),
            Dependency::Policy(version) => at(&policy_key(version.owner()), version),
            Dependency::Absent(key) => !self.by_key.contains_key(key),
        }
    }

    /// The store log of the current records: one frame.
    fn form(&self) -> Vec<u8> {
        form::frame(&form::writes(
            self.by_key.iter().map(|(key, record)| (key, Some(record))),
        ))
    }
}

impl Log {
    /// Opens the journal in `dir` (guide step 8). Drops the bytes after `durable` and a torn last frame, and syncs the
    /// file.
    fn open(dir: &Path, durable: u64) -> Result<Self, Error> {
        fs::create_dir_all(dir)?;
        let mut file = OpenOptions::new()
            .read(true)
            .append(true)
            .create(true)
            .open(dir.join(JOURNAL_FILE))?;
        sync_dir(dir)?;
        let mut bytes = Vec::new();
        file.read_to_end(&mut bytes)?;
        bytes.truncate(usize::try_from(durable).unwrap_or(usize::MAX));
        let (payloads, end) = form::frames(&bytes);
        let entries = payloads
            .into_iter()
            .map(|(offset, payload)| Ok((form::read_entry(payload).ok_or(Error::Form)?.0, offset as u64)))
            .collect::<Result<Vec<_>, Error>>()?;
        let len = end as u64;
        file.set_len(len)?;
        file.sync_data()?;
        let next = entries
            .last()
            .map_or(Sequence(1), |(sequence, _)| Sequence(sequence.0 + 1));
        Ok(Self {
            file,
            synced: (entries.len(), len),
            entries,
            len,
            next,
        })
    }

    fn append(&mut self, entry: &[u8]) -> Result<Sequence, Error> {
        let sequence = self.next;
        let frame = form::frame(&form::entry(sequence, entry));
        self.file.write_all(&frame)?;
        self.entries.push((sequence, self.len));
        self.len += frame.len() as u64;
        self.next = Sequence(sequence.0 + 1);
        Ok(sequence)
    }

    fn sync(&mut self) -> Result<(), Error> {
        self.file.sync_data()?;
        self.synced = (self.entries.len(), self.len);
        Ok(())
    }

    /// At most `limit` durable entries after `after`, in one read of the file.
    fn read(&mut self, after: Sequence, limit: NonZeroUsize) -> Result<Vec<Entry>, Error> {
        let (count, len) = self.synced;
        let durable = &self.entries[..count];
        let first = durable.partition_point(|(sequence, _)| *sequence <= after);
        let page = &durable[first..count.min(first.saturating_add(limit.get()))];
        let Some(&(_, from)) = page.first() else {
            return Ok(Vec::new());
        };
        let to = durable.get(first + page.len()).map_or(len, |(_, offset)| *offset);
        let mut bytes = vec![0; usize::try_from(to - from).map_err(|_| Error::Form)?];
        self.file.seek(SeekFrom::Start(from))?;
        self.file.read_exact(&mut bytes)?;
        let (payloads, _) = form::frames(&bytes);
        if payloads.len() != page.len() {
            return Err(Error::Form);
        }
        payloads
            .into_iter()
            .map(|(_, payload)| {
                let (sequence, data) = form::read_entry(payload).ok_or(Error::Form)?;
                Ok(Entry {
                    sequence,
                    data: data.into(),
                })
            })
            .collect()
    }
}

impl Store for Files {
    type Error = Error;

    fn declaration(&self) -> Declaration {
        self.declaration.clone()
    }

    async fn start(&mut self) -> Result<Instance, Error> {
        let mut inner = self.lock()?;
        inner.stop();
        let open = self.open(inner.state.durable())?;
        let instance = open.instance;
        inner.state = State::Serving(open);
        Ok(instance)
    }

    async fn read(&mut self, key: &Key) -> Result<Option<Record>, Error> {
        self.lock()?.serve(|open| Ok(open.records.by_key.get(key).cloned()))
    }

    async fn read_pair(&mut self, keys: [&Key; 2]) -> Result<[Option<Record>; 2], Error> {
        self.lock()?
            .serve(|open| Ok(keys.map(|key| open.records.by_key.get(key).cloned())))
    }

    async fn commit(&mut self, proposal: &Proposal, instance: Instance) -> Result<Commit, Error> {
        let retention = self.declaration.outcome_retention;
        let mut inner = self.lock()?;
        let fault = inner
            .fault
            .take_if(|fault| matches!(fault, Fault::CrashBeforeCommit | Fault::LostResponse));
        inner.serve(|open| open.commit(proposal, instance, retention, fault))
    }

    async fn expire(&mut self, kind: Kind, before: Duration, limit: NonZeroUsize) -> Result<usize, Error> {
        self.lock()?.serve(|open| {
            let ended: Vec<_> = open
                .records
                .ends
                .get(&kind)
                .into_iter()
                .flatten()
                .take_while(|(end, _)| *end < before)
                .take(limit.get())
                .map(|(_, key)| (key.clone(), None))
                .collect();
            let removed = ended.len();
            if removed > 0 {
                open.write(ended, None)?;
            }
            Ok(removed)
        })
    }

    async fn range(
        &mut self,
        prefix: &Key,
        after: Option<&Key>,
        limit: NonZeroUsize,
    ) -> Result<Vec<(Key, Record)>, Error> {
        let from = match after {
            Some(after) if after >= prefix => Bound::Excluded(after),
            _ => Bound::Included(prefix),
        };
        self.lock()?.serve(|open| {
            Ok(open
                .records
                .by_key
                .range::<Key, _>((from, Bound::Unbounded))
                .take_while(|(key, _)| key.as_bytes().starts_with(prefix.as_bytes()))
                .take(limit.get())
                .map(|(key, record)| (key.clone(), record.clone()))
                .collect())
        })
    }
}

impl Journal for Files {
    type Error = Error;

    async fn append(&mut self, entry: &[u8]) -> Result<Sequence, Error> {
        let mut inner = self.lock()?;
        let crash = inner.fault.take_if(|fault| *fault == Fault::CrashAfterAppend).is_some();
        let sequence = inner.serve(|open| open.log()?.append(entry));
        if crash {
            // The crash after the append: the next start drops it, because no sync made it durable.
            inner.stop();
        }
        sequence
    }

    async fn sync(&mut self) -> Result<(), Error> {
        let mut inner = self.lock()?;
        let fault = inner.fault.take_if(|fault| *fault == Fault::FailedSync);
        inner.serve(|open| {
            let log = open.log()?;
            // A failed sync is never retried (guide step 8.3): the next start drops each append after the last sync.
            fault.map_or_else(|| log.sync(), |fault| Err(Error::Fault(fault)))
        })
    }

    async fn read(&mut self, after: Sequence, limit: NonZeroUsize) -> Result<Vec<Entry>, Error> {
        self.lock()?.serve(|open| open.log()?.read(after, limit))
    }
}

/// The bytes of the file `path`, or no bytes when it does not exist.
fn read(path: &Path) -> Result<Vec<u8>, Error> {
    match fs::read(path) {
        Ok(bytes) => Ok(bytes),
        Err(error) if error.kind() == io::ErrorKind::NotFound => Ok(Vec::new()),
        Err(error) => Err(error.into()),
    }
}

/// Replaces the file `name` in `dir` with `bytes` durably: a new file, its sync, a rename over `name`, and a sync of
/// `dir`.
fn replace(dir: &Path, name: &str, bytes: &[u8]) -> Result<(), Error> {
    let new = dir.join(format!("{name}.new"));
    let mut file = File::create(&new)?;
    file.write_all(bytes)?;
    file.sync_data()?;
    fs::rename(&new, dir.join(name))?;
    sync_dir(dir)
}

/// Makes the names in `dir` durable.
fn sync_dir(dir: &Path) -> Result<(), Error> {
    Ok(File::open(dir)?.sync_all()?)
}

/// Writes the instance number after the last one in `dir` durably, and gives it (guide step 2). A restore does not
/// lower it, because the counter is in the failure domain of the journal.
fn next_instance(dir: &Path) -> Result<Instance, Error> {
    fs::create_dir_all(dir)?;
    let last = match read(&dir.join(INSTANCE_FILE))?.as_slice() {
        [] => 0,
        bytes => u64::from_le_bytes(bytes.try_into().map_err(|_| Error::Form)?),
    };
    let next = last.checked_add(1).ok_or(Error::Form)?;
    replace(dir, INSTANCE_FILE, &next.to_le_bytes())?;
    Ok(Instance(next))
}
