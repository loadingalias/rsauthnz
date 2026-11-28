//! The test controls of the conformance suite for [`Files`] (guide step 11). A control that fails stops the binding,
//! so the next primitive of the suite gives an error.

use core::num::NonZeroUsize;
use core::ops::RangeBounds;

use rsauthnz::store::Sequence;
use rsauthnz::time::Reading;
use rsauthnz_conformance::suite::{Fault, Subject};

use crate::{Error, Files, Inner, JOURNAL_FILE, Log, State, form, replace};

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

    /// Takes a fresh instance under both locks before installing the snapshot. The journal keeps its durable entries.
    fn restore(&self, snapshot: &Self::Snapshot) {
        let mut inner = self.control();
        inner.stop();
        let Some(log) = snapshot else { return };
        if let Ok(open) = self.open(inner.state.durable(), Some(log), true) {
            inner.state = State::Serving(open);
        }
    }

    fn lose(&self, sequences: impl RangeBounds<Sequence>) {
        let Some(dir) = self.journal() else { return };
        // An error stops the binding, so the suite sees it at its next primitive.
        self.control()
            .serve(|open| {
                let log = open.log()?;
                let head = log.head;
                let mut kept = Vec::new();
                for entry in log.read(Sequence(0), NonZeroUsize::MAX)? {
                    if !sequences.contains(&entry.sequence) {
                        kept.extend(form::frame(&form::entry(entry.sequence, &entry.data)));
                    }
                }
                replace(dir, JOURNAL_FILE, &kept)?;
                *log = Log::open(dir, u64::MAX)?;
                log.head = head;
                Ok::<_, Error>(())
            })
            .unwrap_or_default();
    }

    /// Each commit reads `now` in place of the system clock, until the next call.
    fn set_clock(&self, now: Reading) {
        self.control().clock = Some(now);
    }
}
