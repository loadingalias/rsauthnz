//! The last use of a grant: at most one record for each revision in each window of a declared granularity, never a
//! commit for each request.

use alloc::collections::BTreeSet;
use alloc::vec;
use core::cmp::Ordering;
use core::num::NonZeroUsize;
use core::time::Duration;

use super::{Error, Failure, Grants, encode, read};
use crate::authz::Granted;
use crate::cbor::{self, Value};
use crate::crypto;
use crate::id::{Agent, AuthorityVersion, Human, Id, Principal};
use crate::limits::Limits;
use crate::store::driver::Plan;
use crate::store::{Record, Store};
use crate::time::Reading;
use crate::transition::{Audit, Change, Dependency, Key, OperationId, Proposal};

/// The granularity of last use of [`Usage::default`]: 5 minutes.
pub const GRANULARITY_DEFAULT: Duration = Duration::from_secs(300);

/// The most grant revisions that [`Usage::default`] notes in one window.
pub const USES_DEFAULT: usize = 4_096;

/// The first item of the record form of a last use, and the domain of the identity of its operation.
const FORM: &str = "rsauthnz.grant.use.1";

/// The action of the audit record of a last use.
const USE: &str = "grant.use";

/// One use of a grant that [`Usage::note`] gave: the agent, its owner, the grant revision, and the start of the window
/// of the use. [`Grants::record`] proposes its record.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct LastUse {
    pub(crate) agent: Id<Agent>,
    pub(crate) owner: Id<Human>,
    pub(crate) revision: u64,
    /// The key and the version of the grant record that the check of the use read.
    pub(crate) grant: (Key, AuthorityVersion),
    /// The grant deadline, which ends the record.
    pub(crate) ends: Duration,
    /// The start of the window of the use, as the time since the Unix epoch.
    pub(crate) window: Duration,
}

/// The grant revisions that one host noted in the current window of its granularity. It holds at most its capacity of
/// revisions, and the next window starts empty.
#[derive(Clone, Debug)]
pub struct Usage {
    /// The granularity in whole seconds, at least 1.
    granularity: u64,
    capacity: usize,
    /// The number of the current window: the time in whole seconds divided by the granularity.
    window: u64,
    /// The key of each grant that the host noted in the window, without its kind byte, with its revision.
    noted: BTreeSet<([u8; 32], u64)>,
}

impl Usage {
    /// The uses of grants in windows of `granularity`, at most `capacity` grant revisions in one window.
    ///
    /// Cost class: [`Parse`](crate::limits::Class::Parse).
    ///
    /// # Errors
    ///
    /// [`Error::Granularity`] if `granularity` is not a whole number of seconds, at least one.
    pub fn new(granularity: Duration, capacity: NonZeroUsize) -> Result<Self, Error> {
        (granularity.as_secs() > 0 && granularity.subsec_nanos() == 0).ok_or(Error::Granularity)?;
        Ok(Self {
            granularity: granularity.as_secs(),
            capacity: capacity.get(),
            window: 0,
            noted: BTreeSet::new(),
        })
    }

    /// Notes one use of the scope `scope` at `now`, at its check ([`crate::authz::check_agent`]). It gives a
    /// [`LastUse`] for the first use of the grant revision in the window of `now`, and `None` for each later use in
    /// that window. Thus repeated checks give at most one record in each window. It gives `None` for a reading before
    /// the current window, and for a new revision when the window holds its capacity: the record then waits for the
    /// next window.
    ///
    /// Cost class: [`Parse`](crate::limits::Class::Parse). One lookup in an ordered set.
    pub fn note(&mut self, scope: &Granted, now: Reading) -> Option<LastUse> {
        let window = now.estimate().as_secs() / self.granularity;
        match window.cmp(&self.window) {
            Ordering::Less => return None,
            Ordering::Greater => {
                self.noted.clear();
                self.window = window;
            }
            Ordering::Equal => {}
        }
        // The window starts no later than the reading, so the product fits.
        let last_use = scope.last_use(Duration::from_secs(window * self.granularity));
        let grant = last_use.grant.0.as_bytes()[1..]
            .try_into()
            .expect("the key of a grant has 32 bytes after its kind");
        (self.noted.len() < self.capacity && self.noted.insert((grant, last_use.revision))).then_some(last_use)
    }
}

impl Default for Usage {
    /// The uses in windows of [`GRANULARITY_DEFAULT`], at most [`USES_DEFAULT`] grant revisions in one window.
    fn default() -> Self {
        let capacity = NonZeroUsize::new(USES_DEFAULT).expect("the default capacity is not zero");
        Self::new(GRANULARITY_DEFAULT, capacity).expect("the default granularity is whole seconds")
    }
}

/// The key of the record of the last use of the grant at `grant`: the key of the grant with one more byte, 0. Thus
/// one range read of the grants of an owner gives each grant and its last use next to it.
pub(super) fn use_key(grant: &Key) -> Key {
    Key::new(&[grant.as_bytes(), &[0]].concat()).expect("a key of 34 bytes is valid")
}

/// The grant revision and the start of the window of the record `record` of a last use, or `None` for another form.
pub(super) fn parse_use(record: &Record, limits: Limits) -> Option<(u64, Duration)> {
    let value = cbor::decode(&record.data, limits).ok()?;
    let Value::Array(items) = &value else {
        return None;
    };
    let [Value::Text(FORM), Value::Unsigned(revision), Value::Unsigned(window)] = items.as_slice() else {
        return None;
    };
    Some((*revision, Duration::from_secs(*window)))
}

impl Grants {
    /// Proposes the record of `last_use` ([`Usage::note`]), or gives `None` when the store holds this use or a later
    /// one. The record holds the grant revision and the start of the window, and ends at the grant deadline. The
    /// proposal reads the grant at the version of the check, so a change or a revocation before the commit drops the
    /// record: it is a conflict, and the next use gives a new one. Its audit names the agent and its owner. Its
    /// operation identity is the SHA-256 digest of the grant, the revision, and the window, so a second host that noted
    /// the same use commits the same operation once. A lost response or a conflict needs no recovery: the next use in
    /// a later window records it.
    ///
    /// Cost class: [`Verify`](crate::limits::Class::Verify). One keyed lookup.
    ///
    /// # Errors
    ///
    /// [`Error::Record`] for a record of another authority, [`Error::Transition`] for the proposal, and
    /// [`Failure::Store`] if the read fails.
    pub async fn record<S: Store>(
        &self,
        store: &mut S,
        last_use: &LastUse,
        now: Reading,
    ) -> Result<Option<(Proposal, Plan)>, Failure<S::Error>> {
        let (grant, at) = &last_use.grant;
        let key = use_key(grant);
        let window = last_use.window.as_secs();
        let coordinate = [window.to_be_bytes(), last_use.revision.to_be_bytes()].concat();
        let version =
            AuthorityVersion::new(self.authority.clone(), &coordinate).expect("a 16-byte coordinate is valid");
        let current = read(store, &key).await?;
        let read = match &current {
            None => Dependency::Absent(key.clone()),
            Some(record) => match record.version.compare(&version) {
                Ok(Ordering::Less) => Dependency::Version(key.clone(), record.version.clone()),
                Ok(_) => return Ok(None),
                Err(_) => return Err(Error::Record.into()),
            },
        };
        let request = Value::Array(vec![
            Value::Bytes(grant.as_bytes()),
            Value::Unsigned(last_use.revision),
            Value::Unsigned(window),
        ]);
        let form = encode(&[Value::Text(FORM), request.clone()]);
        let operation = OperationId::new(&crypto::sha256(&form)).expect("a digest of 32 bytes is a valid identity");
        let audit = Audit {
            actor: Principal::Agent(last_use.agent.clone()),
            action: Id::new("rsauthnz", USE).expect("the action is a valid identifier"),
            time: now,
        };
        let mut proposal = Proposal::start(operation, audit, &request, self.limits).map_err(Error::Transition)?;
        proposal.attribute(last_use.owner.clone());
        [Dependency::Version(grant.clone(), at.clone()), read]
            .into_iter()
            .try_for_each(|read| proposal.read(read))
            .map_err(Error::Transition)?;
        let data = encode(&[
            Value::Text(FORM),
            Value::Unsigned(last_use.revision),
            Value::Unsigned(window),
        ]);
        proposal
            .change(Change::Write {
                key,
                version,
                end: Some(last_use.ends),
                data: data.into_boxed_slice(),
            })
            .map_err(Error::Transition)?;
        Ok(Some((proposal, Plan::default())))
    }
}
