//! The test controls of the conformance suite for [`Files`] (guide step 11). A control that fails stops the binding,
//! so the next primitive of the suite gives an error.

use core::num::NonZeroUsize;
use core::ops::RangeBounds;
use core::time::Duration;
use std::time::{SystemTime, UNIX_EPOCH};

use rsauthnz::store::Sequence;
use rsauthnz::time::{Reading, ReadingSource};
use rsauthnz_conformance::suite::{Fault, Subject};

use crate::{Durable, Error, Files, Inner, JOURNAL_FILE, Log, STORE_FILE, State, form, replace};

impl Files {
    /// The shared state for a control. A control has no error, so it takes the state after a panic too.
    fn control(&self) -> std::sync::MutexGuard<'_, Inner> {
        self.inner.lock().unwrap_or_else(std::sync::PoisonError::into_inner)
    }
}

impl Subject for Files {
    /// The store log of the current records, or `None` for a binding that does not serve.
    type Snapshot = Option<Box<[u8]>>;

    fn inject(&self, fault: Fault) {
        self.control().fault = Some(fault);
    }

    /// The loss of the process. The binding stops, and the next start drops each write after the last sync that
    /// returned, as after a crash. The instance number stays in its file.
    fn restart(&self) {
        self.control().stop();
    }

    fn snapshot(&self) -> Self::Snapshot {
        match &self.control().state {
            State::Serving(open) => Some(open.records.form().into()),
            State::Stopped(_) => None,
        }
    }

    /// Writes `snapshot` as the store log, then opens the files as a start does, with a fresh instance number (guide
    /// step 2.4). The journal keeps its durable entries.
    fn restore(&self, snapshot: &Self::Snapshot) {
        let mut inner = self.control();
        inner.stop();
        let durable = inner.state.durable();
        let Some(log) = snapshot else { return };
        let restored = replace(&self.store, STORE_FILE, log).and_then(|()| {
            self.open(Durable {
                store: log.len() as u64,
                ..durable
            })
        });
        if let Ok(open) = restored {
            inner.state = State::Serving(open);
        }
    }

    fn lose(&self, sequences: impl RangeBounds<Sequence>) {
        let Some(dir) = self.journal() else { return };
        // An error stops the binding, so the suite sees it at its next primitive.
        self.control()
            .serve(|open| {
                let log = open.log()?;
                let next = log.next;
                let mut kept = Vec::new();
                for entry in log.read(Sequence(0), NonZeroUsize::MAX)? {
                    if !sequences.contains(&entry.sequence) {
                        kept.extend(form::frame(&form::entry(entry.sequence, &entry.data)));
                    }
                }
                replace(dir, JOURNAL_FILE, &kept)?;
                *log = Log::open(dir, u64::MAX)?;
                log.next = next;
                Ok::<_, Error>(())
            })
            .unwrap_or_default();
    }

    /// A reading of the system clock with a bound of one second (guide step 10). A clock before the Unix epoch reads as
    /// the epoch with no bound, so each deadline refuses.
    fn clock(&self) -> Reading {
        match SystemTime::now().duration_since(UNIX_EPOCH) {
            Ok(since) => Reading::new(since, Some(Duration::from_secs(1)), ReadingSource::SystemClock),
            Err(_) => Reading::new(Duration::ZERO, None, ReadingSource::SystemClock),
        }
    }
}
