//! A store of the tests: the memory binding behind a gate. While the gate is closed, no call of the store answers.

use core::future::poll_fn;
use core::num::NonZeroUsize;
use core::ops::RangeBounds;
use core::task::{Poll, Waker};
use core::time::Duration;
use std::sync::{Arc, Mutex};

use rsauthnz::store::{Commit, Declaration, Entry, Insert, Inserted, Instance, Journal, Kind, Record, Sequence, Store};
use rsauthnz::time::Reading;
use rsauthnz::transition::{Key, Proposal};
use rsauthnz_conformance::memory::{Error, Memory, Snapshot};
use rsauthnz_conformance::suite::{Fault, Subject};

/// The memory binding behind a gate. Its clones share the binding and the gate.
#[derive(Clone)]
pub(crate) struct Gated {
    memory: Memory,
    gate: Arc<Mutex<Gate>>,
}

/// Whether the gate is closed, and the wakers of the calls that wait at it.
#[derive(Default)]
struct Gate {
    closed: bool,
    waiting: Vec<Waker>,
}

impl Gated {
    /// The binding `memory` behind an open gate.
    pub(crate) fn new(memory: Memory) -> Self {
        Self {
            memory,
            gate: Arc::default(),
        }
    }

    /// Closes the gate: each later call of the store waits.
    pub(crate) fn close(&self) {
        self.gate.lock().expect("the gate").closed = true;
    }

    /// Opens the gate, and wakes each call that waits at it.
    pub(crate) fn open(&self) {
        let waiting = {
            let mut gate = self.gate.lock().expect("the gate");
            gate.closed = false;
            core::mem::take(&mut gate.waiting)
        };
        for waker in waiting {
            waker.wake();
        }
    }

    /// Whether a call of the store waits at the gate.
    pub(crate) fn stalled(&self) -> bool {
        !self.gate.lock().expect("the gate").waiting.is_empty()
    }

    /// Waits while the gate is closed.
    async fn pass(&self) {
        poll_fn(|context| {
            let mut gate = self.gate.lock().expect("the gate");
            if gate.closed {
                gate.waiting.push(context.waker().clone());
                Poll::Pending
            } else {
                Poll::Ready(())
            }
        })
        .await;
    }
}

impl Store for Gated {
    type Error = Error;

    fn declaration(&self) -> Declaration {
        self.memory.declaration()
    }

    async fn start(&mut self) -> Result<Instance, Error> {
        self.pass().await;
        self.memory.start().await
    }

    async fn read(&mut self, key: &Key) -> Result<Option<Record>, Error> {
        self.pass().await;
        Store::read(&mut self.memory, key).await
    }

    async fn read_pair(&mut self, keys: [&Key; 2]) -> Result<[Option<Record>; 2], Error> {
        self.pass().await;
        self.memory.read_pair(keys).await
    }

    async fn commit(&mut self, proposal: &Proposal, instance: Instance) -> Result<Commit, Error> {
        self.pass().await;
        self.memory.commit(proposal, instance).await
    }

    async fn insert_replay(&mut self, insert: &Insert) -> Result<Inserted, Error> {
        self.pass().await;
        self.memory.insert_replay(insert).await
    }

    async fn expire(&mut self, kind: Kind, before: Duration, limit: NonZeroUsize) -> Result<usize, Error> {
        self.pass().await;
        self.memory.expire(kind, before, limit).await
    }

    async fn range(
        &mut self,
        prefix: &Key,
        after: Option<&Key>,
        limit: NonZeroUsize,
    ) -> Result<Vec<(Key, Record)>, Error> {
        self.pass().await;
        self.memory.range(prefix, after, limit).await
    }
}

impl Journal for Gated {
    type Error = Error;

    async fn append(&mut self, entry: &[u8]) -> Result<Sequence, Error> {
        self.pass().await;
        self.memory.append(entry).await
    }

    async fn sync(&mut self) -> Result<(), Error> {
        self.pass().await;
        self.memory.sync().await
    }

    async fn read(&mut self, after: Sequence, limit: NonZeroUsize) -> Result<Vec<Entry>, Error> {
        self.pass().await;
        Journal::read(&mut self.memory, after, limit).await
    }
}

impl Subject for Gated {
    type Snapshot = Snapshot;

    fn inject(&self, fault: Fault) {
        self.memory.inject(fault);
    }

    fn restart(&self) {
        self.memory.restart();
    }

    fn snapshot(&self) -> Snapshot {
        self.memory.snapshot()
    }

    fn restore(&self, snapshot: &Snapshot) {
        self.memory.restore(snapshot);
    }

    fn lose(&self, sequences: impl RangeBounds<Sequence>) {
        self.memory.lose(sequences);
    }

    fn set_clock(&self, now: Reading) {
        self.memory.set_clock(now);
    }
}
