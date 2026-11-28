//! Grants: the access that a human owner gives one of their agents, limited to named resource actions, audiences, and
//! a finite deadline.
//!
//! Each agent identity has at most one grant. Its owner issues it and changes it with a fresh user verification
//! ([`Grants::issue`]). Each issue or change writes a new revision, and a counter of the commit driver numbers it, so a
//! restore never gives one revision number twice. The grant keeps only the requested permissions that the owner holds
//! at the issue, and it binds the policy version of that decision.
//!
//! Effective access is the grant intersected with the current authority of the owner, under the policy version that
//! the grant binds ([`crate::authz::check_agent`]). Each check resolves the policy again: a grant holds no copy of the
//! authority of its owner. A relevant policy change raises the version, so it stops each grant of the earlier version
//! until the owner approves a new revision. A key rotation of the agent keeps its grant. A revocation of the grant
//! ([`Grants::revoke`]) or of the agent ([`crate::agent::Agents::revoke`]) ends it.
//!
//! The active-access page of an owner shows the sessions of [`crate::session::Sessions::list`] and the grants of
//! [`Grants::list`] together. Only a human gives a grant: [`Grants::issue`] takes the [`Fresh`] user verification of a
//! passkey session, and no agent has one.

use alloc::boxed::Box;
use alloc::vec;
use alloc::vec::Vec;
use core::fmt;
use core::num::NonZeroUsize;
use core::time::Duration;

use rscrypto::ChaCha20Rng;

use crate::account::Fresh;
use crate::agent::{self, Agents};
use crate::authz::{self, Policy};
use crate::cbor::{self, Value};
use crate::crypto;
use crate::id::{Action, Agent, Audience, Authority, AuthorityVersion, Human, Id, Principal, Resource};
use crate::limits::{Limit, Limits};
use crate::session::Access;
use crate::store::driver::{self, Driver, Plan};
use crate::store::{Kind, Record, Store};
use crate::time::{Reading, TimeError};
use crate::transition::{self, Audit, Change, Dependency, Key, OperationId, Proposal, Recover, Recovery};

pub use self::credential::{Body, LIFETIME_DEFAULT, LIFETIME_MAX, Pending, Request, purpose, statement};
pub use self::usage::{GRANULARITY_DEFAULT, LastUse, USES_DEFAULT, Usage};

mod credential;
mod usage;

/// The most records of one page of [`Grants::list`]: grants and their last uses.
pub const PAGE_MAX: usize = 64;

/// The bytes of the key of a grant: its kind, the locator of its owner, and 16 bytes of the digest of its agent.
const GRANT_KEY_BYTES: usize = 33;

/// The records of one range read of [`Grants::list`].
const PAGE: NonZeroUsize = NonZeroUsize::new(PAGE_MAX).expect("the bound is not zero");

/// The first item of the record form of a grant, and the domain of the key of a grant.
const FORM: &str = "rsauthnz.grant.1";

/// The domain of the locator of an owner, which starts the key of each grant of the owner.
const OWNER: &str = "rsauthnz.grant.owner.1";

/// The actions of the audit records.
const ISSUE: &str = "grant.issue";
const CHANGE: &str = "grant.change";
const REVOKE: &str = "grant.revoke";

/// Whether an operation of a permission needs a one-use approval of the owner.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub enum Approval {
    /// The grant alone admits the operation.
    NotRequired,
    /// The operation also needs a one-use approval of the owner. The check gives the mark
    /// ([`Granted::approval`](crate::authz::Granted::approval)).
    Required,
}

/// A resource permission of a grant: an action on a resource, both identifiers of the application.
#[derive(Clone, Debug, PartialEq, Eq, Hash)]
pub struct Permission {
    /// The resource, such as a repository.
    pub resource: Id<Resource>,
    /// The action, such as `repo.read`.
    pub action: Id<Action>,
    /// Whether an operation needs a one-use approval of the owner.
    pub approval: Approval,
}

/// What the owner approves for the grant of an agent ([`Grants::issue`]).
#[derive(Clone, Copy, Debug)]
pub struct Draft<'a> {
    /// The services that accept the agent under the grant: at least one, and at most [`Limits::audiences`].
    pub audiences: &'a [Id<Audience>],
    /// The resource permissions: at least one, and at most [`Limits::permissions`].
    pub permissions: &'a [Permission],
    /// The end of the grant, as the time since the Unix epoch. The issue rounds it down to a whole second.
    pub deadline: Duration,
}

/// A revision of the grant of an agent.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Grant {
    /// The agent.
    pub agent: Id<Agent>,
    /// The human owner of the agent, who approved the revision.
    pub owner: Id<Human>,
    /// The services that accept the agent under the grant.
    pub audiences: Vec<Id<Audience>>,
    /// The resource permissions that the owner held at the issue of the revision.
    pub permissions: Vec<Permission>,
    /// The end of the grant, as the time since the Unix epoch.
    pub deadline: Duration,
    /// The policy version of the decision of the issue. A check refuses under another version.
    pub policy: AuthorityVersion,
    /// The time of the issue of the revision, as the time since the Unix epoch.
    pub issued: Duration,
    /// The revision number. Each issue and change takes a new one from the counter of the commit driver.
    pub revision: u64,
    /// The version of the grant record.
    pub version: AuthorityVersion,
    /// The start of the window of the last use of this revision that a host recorded ([`Grants::record`]), as the time
    /// since the Unix epoch, or `None`. Only [`Grants::list`] gives it.
    pub last_use: Option<Duration>,
}

impl Grant {
    /// The record form: `["rsauthnz.grant.1", owner, agent, audiences, permissions, deadline, policy, issued]`. Each
    /// permission is `[resource, action, approval]`, with 1 for an approval mark and 0 for none, and each time is in
    /// whole seconds.
    fn form(&self) -> Box<[u8]> {
        let audiences = self.audiences.iter().map(Id::to_cbor).collect();
        let permissions = self
            .permissions
            .iter()
            .map(|permission| {
                let approval = match permission.approval {
                    Approval::NotRequired => 0,
                    Approval::Required => 1,
                };
                Value::Array(vec![
                    permission.resource.to_cbor(),
                    permission.action.to_cbor(),
                    Value::Unsigned(approval),
                ])
            })
            .collect();
        encode(&[
            Value::Text(FORM),
            self.owner.to_cbor(),
            self.agent.to_cbor(),
            Value::Array(audiences),
            Value::Array(permissions),
            Value::Unsigned(self.deadline.as_secs()),
            self.policy.to_cbor(),
            Value::Unsigned(self.issued.as_secs()),
        ])
        .into_boxed_slice()
    }

    /// The grant of the record `record`, or `None` for another form, or for more audiences or permissions than
    /// `limits` permit. The revision is the coordinate of the version.
    pub(crate) fn parse(record: &Record, limits: Limits) -> Option<Self> {
        let value = cbor::decode(&record.data, limits).ok()?;
        let Value::Array(items) = &value else {
            return None;
        };
        let [
            Value::Text(FORM),
            owner,
            agent,
            Value::Array(audiences),
            Value::Array(permissions),
            Value::Unsigned(deadline),
            policy,
            Value::Unsigned(issued),
        ] = items.as_slice()
        else {
            return None;
        };
        (audiences.len() <= limits.audiences && permissions.len() <= limits.permissions).then_some(())?;
        let permissions = permissions
            .iter()
            .map(|permission| {
                let Value::Array(fields) = permission else {
                    return None;
                };
                let [resource, action, Value::Unsigned(approval)] = fields.as_slice() else {
                    return None;
                };
                let approval = match approval {
                    0 => Approval::NotRequired,
                    1 => Approval::Required,
                    _ => return None,
                };
                Some(Permission {
                    resource: Id::from_cbor(resource).ok()?,
                    action: Id::from_cbor(action).ok()?,
                    approval,
                })
            })
            .collect::<Option<_>>()?;
        Some(Self {
            agent: Id::from_cbor(agent).ok()?,
            owner: Id::from_cbor(owner).ok()?,
            audiences: audiences
                .iter()
                .map(|audience| Id::from_cbor(audience).ok())
                .collect::<Option<_>>()?,
            permissions,
            deadline: Duration::from_secs(*deadline),
            policy: AuthorityVersion::from_cbor(policy).ok()?,
            issued: Duration::from_secs(*issued),
            revision: u64::from_be_bytes(*record.version.coordinate().first_chunk::<8>()?),
            version: record.version.clone(),
            last_use: None,
        })
    }
}

/// One page of the grants of an owner ([`Grants::list`]).
#[derive(Clone, Debug)]
pub struct Page {
    /// The grants that did not end.
    pub grants: Vec<Grant>,
    /// The key after which the next page starts, or `None` when no records remain.
    pub next: Option<Key>,
}

/// The grants of the agents of one authority: the authority of [`Agents`].
#[derive(Clone, Debug)]
pub struct Grants {
    pub(crate) agents: Agents,
    pub(crate) authority: Id<Authority>,
    pub(crate) limits: Limits,
}

impl Grants {
    /// The grants of the agents of `authority`, whose records and forms are within `limits`.
    ///
    /// Cost class: [`Parse`](crate::limits::Class::Parse).
    #[must_use]
    pub fn new(authority: Id<Authority>, limits: Limits) -> Self {
        Self {
            agents: Agents::new(authority.clone(), limits),
            authority,
            limits,
        }
    }

    /// Proposes the grant of `draft` to `agent` by its owner, the account of `fresh`, or a change of its grant. Each
    /// call writes a new revision with a number from `driver`. The grant keeps only the permissions of `draft` that
    /// `policy` permits the owner now, and binds the policy version. The commit reads the session of the verification,
    /// the agent identity, the policy version, and the current grant, or its absence, so two changes of one grant, or
    /// a change and a revocation, commit at most once. A change replaces the revision that it read: the restore journal
    /// ends it. Show the [`Grant`] after the accepted commit: it holds the permissions that the grant keeps.
    ///
    /// Cost class: [`Verify`](crate::limits::Class::Verify). Two keyed lookups, and one policy decision for each
    /// permission of `draft`.
    ///
    /// # Errors
    ///
    /// [`Error::Deadline`] if the deadline is not after the latest time of `now`. [`Error::Draft`] for no audience, no
    /// permission, or one named twice, and [`Error::Limit`] for more than the limits permit. [`Error::NotEnrolled`] if
    /// the store holds no identity of `agent`, also for an agent of another owner. [`Error::Authority`] if the owner
    /// holds none of the permissions now. [`Error::Record`] for a record with no valid form, [`Error::Time`] for a
    /// reading with no bound, [`Error::Driver`] if the driver does not serve, [`Error::Transition`] for the proposal,
    /// and [`Failure::Store`] if a read fails.
    #[expect(
        clippy::too_many_arguments,
        reason = "the store, the verification, the agent, the draft, the policy, the time, the random source, and the counter are each one input of one issue"
    )]
    pub async fn issue<S: Store>(
        &self,
        store: &mut S,
        fresh: &Fresh,
        agent: &Id<Agent>,
        draft: &Draft<'_>,
        policy: &impl Policy,
        now: Reading,
        random: &mut ChaCha20Rng,
        driver: &mut Driver,
    ) -> Result<(Proposal, Plan, Grant), Failure<S::Error>> {
        let latest = now.latest().map_err(Error::Time)?;
        let deadline = Duration::from_secs(draft.deadline.as_secs());
        (latest < deadline).ok_or(Error::Deadline)?;
        self.bounds(draft)?;
        let owner = fresh.account();
        let identity = self.identity(store, agent).await?;
        (identity.owner == *owner).ok_or(Error::NotEnrolled)?;
        let principal = Principal::Human(owner.clone());
        let permissions: Vec<Permission> = draft
            .permissions
            .iter()
            .filter(|permission| permit(policy, &principal, &permission.resource, &permission.action, latest).is_some())
            .cloned()
            .collect();
        (!permissions.is_empty()).ok_or(Error::Authority)?;
        let key = key(&self.authority, owner, agent);
        let record = read(store, &key).await?;
        let action = if record.is_some() { CHANGE } else { ISSUE };
        let mut proposal = self.proposal(OperationId::random(random), principal, action, &key, now)?;
        fresh.gate(&mut proposal).map_err(Error::Transition)?;
        let reads = [
            Dependency::Version(self.agents.identity_key(agent), identity.version),
            Dependency::Policy(policy.version().clone()),
            match &record {
                Some(record) => Dependency::Version(key.clone(), record.version.clone()),
                None => Dependency::Absent(key.clone()),
            },
        ];
        reads
            .into_iter()
            .try_for_each(|read| proposal.read(read))
            .map_err(Error::Transition)?;
        let revision = match &record {
            Some(record) => driver.allocate_after(&record.version),
            None => driver.allocate(),
        }
        .map_err(Error::Driver)?;
        let grant = Grant {
            agent: agent.clone(),
            owner: owner.clone(),
            audiences: draft.audiences.to_vec(),
            permissions,
            deadline,
            policy: policy.version().clone(),
            issued: Duration::from_secs(now.estimate().as_secs()),
            revision,
            version: AuthorityVersion::new(self.authority.clone(), &revision.to_be_bytes())
                .expect("an 8-byte coordinate is valid"),
            last_use: None,
        };
        proposal
            .change(Change::Write {
                key: key.clone(),
                version: grant.version.clone(),
                end: Some(deadline),
                data: grant.form(),
            })
            .map_err(Error::Transition)?;
        let plan = Plan {
            replaced: record.map(|_| key).into_iter().collect(),
            ..Plan::default()
        };
        Ok((proposal, plan, grant))
    }

    /// Proposes the revocation of the grant of `agent` by its owner, the signed-in human of `access`. The commit ends
    /// the grant at the revision that the proposal read, so the restore journal keeps the end, and a change that
    /// read the same revision conflicts. The proposal reads the session, so a revocation from a session that ended
    /// refuses.
    ///
    /// Cost class: [`Verify`](crate::limits::Class::Verify). One keyed lookup, and its commit.
    ///
    /// # Errors
    ///
    /// [`Error::NoGrant`] if `agent` has no grant of the owner, also for an agent of another owner. [`Error::Record`]
    /// for a record with no valid form, [`Error::Transition`] for the proposal, and [`Failure::Store`] if the read
    /// fails.
    pub async fn revoke<S: Store>(
        &self,
        store: &mut S,
        access: &Access,
        agent: &Id<Agent>,
        now: Reading,
        random: &mut ChaCha20Rng,
    ) -> Result<(Proposal, Plan), Failure<S::Error>> {
        let owner = access.session().account();
        let key = key(&self.authority, owner, agent);
        let record = read(store, &key).await?.ok_or(Error::NoGrant)?;
        Grant::parse(&record, self.limits)
            .filter(|grant| grant.agent == *agent && grant.owner == *owner)
            .ok_or(Error::Record)?;
        let actor = Principal::Human(owner.clone());
        let mut proposal = self.proposal(OperationId::random(random), actor, REVOKE, &key, now)?;
        access.gate(&mut proposal).map_err(Error::Transition)?;
        proposal
            .read(Dependency::Version(key.clone(), record.version))
            .map_err(Error::Transition)?;
        proposal.change(Change::End(key)).map_err(Error::Transition)?;
        Ok((proposal, Plan::default()))
    }

    /// Lists the grants of the owner, the signed-in human of `access`, that did not end at `now`, each with the last use
    /// of its revision ([`Grant::last_use`]). The page starts after `after`, or at the first key. Show it on the
    /// active-access page with the sessions of [`crate::session::Sessions::list`].
    ///
    /// Cost class: [`Verify`](crate::limits::Class::Verify). One range read of at most [`PAGE_MAX`] records: each
    /// grant, and the record of its last use next to it. A full page that ends at a grant leaves that grant to the
    /// next page, with its last use.
    ///
    /// # Errors
    ///
    /// [`Error::Record`] if a record has no valid form, [`Error::Time`] if `now` has no bound, and [`Failure::Store`]
    /// if the read fails.
    pub async fn list<S: Store>(
        &self,
        store: &mut S,
        access: &Access,
        after: Option<&Key>,
        now: Reading,
    ) -> Result<Page, Failure<S::Error>> {
        let latest = now.latest().map_err(Error::Time)?;
        let owner = access.session().account();
        let prefix = Kind::Grant
            .key(&locator(&self.authority, owner))
            .expect("a key of 17 bytes is valid");
        let records = store.range(&prefix, after, PAGE).await.map_err(Failure::Store)?;
        let full = records.len() == PAGE_MAX;
        let grant_key = |key: &Key| key.as_bytes().len() == GRANT_KEY_BYTES;
        // The last use of the last grant of a full page can be the first record of the next page.
        let records = match records.split_last() {
            Some(((key, _), rest)) if full && grant_key(key) => rest,
            _ => &records[..],
        };
        let next = full.then(|| records.last().map(|(key, _)| key.clone())).flatten();
        let mut grants = Vec::with_capacity(records.len());
        let mut records = records.iter().peekable();
        while let Some((key, record)) = records.next() {
            // A last use whose grant ended stays until its own end.
            if !grant_key(key) {
                continue;
            }
            let mut grant = Grant::parse(record, self.limits)
                .filter(|grant| grant.owner == *owner)
                .ok_or(Error::Record)?;
            if let Some((_, used)) = records.next_if(|(next, _)| *next == usage::use_key(key)) {
                let (revision, window) = usage::parse_use(used, self.limits).ok_or(Error::Record)?;
                grant.last_use = (revision == grant.revision).then_some(window);
            }
            if latest < grant.deadline {
                grants.push(grant);
            }
        }
        Ok(Page { grants, next })
    }

    /// Refuses a draft with no audience or no permission, one named twice, or more than the limits permit.
    fn bounds(&self, draft: &Draft<'_>) -> Result<(), Error> {
        let Draft {
            audiences, permissions, ..
        } = draft;
        (audiences.len() <= self.limits.audiences).ok_or(Error::Limit(Limit::Audiences))?;
        (permissions.len() <= self.limits.permissions).ok_or(Error::Limit(Limit::Permissions))?;
        let distinct = |count: usize, same: &dyn Fn(usize, usize) -> bool| {
            count > 0 && (0..count).all(|i| (i + 1..count).all(|j| !same(i, j)))
        };
        let audiences_distinct = distinct(audiences.len(), &|i, j| audiences[i] == audiences[j]);
        let permissions_distinct = distinct(permissions.len(), &|i, j| {
            permissions[i].resource == permissions[j].resource && permissions[i].action == permissions[j].action
        });
        (audiences_distinct && permissions_distinct).ok_or(Error::Draft)
    }

    /// The current identity of `agent`.
    async fn identity<S: Store>(&self, store: &mut S, agent: &Id<Agent>) -> Result<agent::Identity, Failure<S::Error>> {
        self.agents
            .identity(store, agent)
            .await
            .map_err(|failure| match failure {
                agent::Failure::Refused(agent::Error::NotEnrolled) => Failure::Refused(Error::NotEnrolled),
                agent::Failure::Refused(_) => Failure::Refused(Error::Record),
                agent::Failure::Store(error) => Failure::Store(error),
            })
    }

    /// A proposal of `actor` for `action` on the grant at `key`. Its request is `[authority, key]`.
    fn proposal(
        &self,
        operation: OperationId,
        actor: Principal,
        action: &str,
        key: &Key,
        now: Reading,
    ) -> Result<Proposal, Error> {
        let audit = Audit {
            actor,
            action: Id::new("rsauthnz", action).expect("each action of this module is a valid identifier"),
            time: now,
        };
        let request = Value::Array(vec![self.authority.to_cbor(), Value::Bytes(key.as_bytes())]);
        Proposal::new(operation, audit, &request, self.limits).map_err(Error::Transition)
    }
}

/// The key of the grant of `agent` from `owner` under `authority`: [`Kind::Grant`] with the locator of the owner, then
/// 16 bytes of the SHA-256 digest of `["rsauthnz.grant.1", authority, agent]`. The locator starts the key, so the
/// grants of one owner are one range.
pub(crate) fn key(authority: &Id<Authority>, owner: &Id<Human>, agent: &Id<Agent>) -> Key {
    let digest = crypto::sha256(&encode(&[Value::Text(FORM), authority.to_cbor(), agent.to_cbor()]));
    let mut bytes = [0; 32];
    bytes[..16].copy_from_slice(&locator(authority, owner));
    bytes[16..].copy_from_slice(&digest[..16]);
    Kind::Grant.key(&bytes).expect("a key of 33 bytes is valid")
}

/// The locator of `owner` under `authority`: 16 bytes of the SHA-256 digest of `["rsauthnz.grant.owner.1", authority,
/// owner]`.
fn locator(authority: &Id<Authority>, owner: &Id<Human>) -> [u8; 16] {
    let digest = crypto::sha256(&encode(&[Value::Text(OWNER), authority.to_cbor(), owner.to_cbor()]));
    *digest.first_chunk().expect("a digest has 32 bytes")
}

/// The end of the permit of `policy` for `principal` to do `action` on `resource`, or `None` if the policy permits it
/// at no time after `latest`, or the permit is of another request or version.
pub(crate) fn permit(
    policy: &impl Policy,
    principal: &Principal,
    resource: &Id<Resource>,
    action: &Id<Action>,
    latest: Duration,
) -> Option<Duration> {
    let request = authz::Request {
        principal,
        action,
        resource,
    };
    policy
        .resolve(&request)
        .filter(|permit| {
            permit.principal == *principal
                && permit.action == *action
                && permit.resource == *resource
                && permit.version == *policy.version()
                && latest < permit.expires
        })
        .map(|permit| permit.expires)
}

/// The canonical CBOR form of the array `items`.
fn encode(items: &[Value<'_>]) -> Vec<u8> {
    cbor::encode(&Value::Array(items.to_vec()), Limits::FORM)
        .expect("the forms of this module have no map and no simple value")
}

/// The keyed read of `key`.
async fn read<S: Store>(store: &mut S, key: &Key) -> Result<Option<Record>, Failure<S::Error>> {
    store.read(key).await.map_err(Failure::Store)
}

/// The cause of a refused grant operation. No error holds a secret.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Error {
    /// The draft has no audience or no permission, or names one twice.
    Draft,
    /// The draft has more audiences or permissions than the limits permit.
    Limit(Limit),
    /// The deadline is not after the time of the reading. A grant always ends.
    Deadline,
    /// The owner holds none of the requested permissions now, or does not hold the permission of a use now.
    Authority,
    /// The store holds no identity of the agent, or the agent has another owner. The answer is the same, so it tells
    /// no other human that the agent exists.
    NotEnrolled,
    /// The agent has no grant: its owner gave none, revoked it, or the agent was revoked.
    NoGrant,
    /// The evidence is not of the credential of an agent: a human or a workload has no grant.
    Principal,
    /// Another authority issued the credential of the agent.
    Issuer,
    /// The credential names another owner than the identity of the agent.
    Owner,
    /// The key that proved the possession of the credential is not the current key of the agent: a rotation replaced
    /// it. The agent proves its current key.
    Key,
    /// The credential names another revision than the current revision of the grant: a change replaced it. The agent
    /// gets a credential of the current revision.
    Revision,
    /// The deadline of the grant passed, or the deadline of the scope of a request: the end of the permit of the owner
    /// or of the credential of the agent. The owner can approve a new revision, or the agent gets a new credential.
    Expired,
    /// The grant does not name the audience.
    Audience,
    /// The grant does not name the action on the resource.
    Permission,
    /// The grant binds another policy version: a relevant policy change stopped it. The owner can approve a new
    /// revision.
    Policy,
    /// A record has no valid form. Restore the store from a snapshot.
    Record,
    /// The lifetime of a credential request is past [`LIFETIME_MAX`] or under one second. Ask for a shorter or a longer
    /// one, or for the default.
    Lifetime,
    /// The granularity of a [`Usage`] is not a whole number of seconds, at least one.
    Granularity,
    /// The JSON body of a credential request is not a request ([`Body::parse`]).
    Malformed,
    /// The credential format refused: the proof of a request, the draft, or the signature of custody. An issuer key of
    /// SLH-DSA refuses with [`crate::credential::Error::Profile`]: it signs no credential.
    Credential(crate::credential::Error),
    /// The reading of the time has no bound. Use a reading with a bound.
    Time(TimeError),
    /// The commit driver does not serve, or its counter has no next value.
    Driver(driver::Error),
    /// The proposal refuses. The error gives the recovery.
    Transition(transition::Error),
}

impl Recover for Error {
    /// The recovery of the proposal after [`Error::Transition`], and of the driver after [`Error::Driver`]. Refuse
    /// each other request: it refuses again until the owner or the policy changes.
    fn recovery(&self) -> Recovery {
        match self {
            Self::Transition(error) => error.recovery(),
            Self::Driver(error) => error.recovery(),
            _ => Recovery::Refuse,
        }
    }
}

impl fmt::Display for Error {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Draft => f.write_str("the draft has no audience or no permission, or names one twice"),
            Self::Limit(limit) => write!(f, "the draft passes a bound: {limit:?}"),
            Self::Deadline => f.write_str("the deadline of the grant is not after the time of the reading"),
            Self::Authority => f.write_str("the owner does not hold the permission now"),
            Self::NotEnrolled => f.write_str("the store holds no identity of the agent"),
            Self::NoGrant => f.write_str("the agent has no grant"),
            Self::Principal => f.write_str("the evidence is not of the credential of an agent"),
            Self::Issuer => f.write_str("another authority issued the credential of the agent"),
            Self::Owner => f.write_str("the credential names another owner than the identity of the agent"),
            Self::Key => f.write_str("the key of the proof is not the current key of the agent"),
            Self::Revision => f.write_str("the credential names another revision than the current grant"),
            Self::Expired => f.write_str("the deadline of the grant passed"),
            Self::Audience => f.write_str("the grant does not name the audience"),
            Self::Permission => f.write_str("the grant does not name the action on the resource"),
            Self::Policy => f.write_str("the grant binds another policy version"),
            Self::Record => f.write_str("a grant record has no valid form"),
            Self::Lifetime => f.write_str("the lifetime is past the most or under one second"),
            Self::Granularity => f.write_str("the granularity is not a whole number of seconds, at least one"),
            Self::Malformed => f.write_str("the body is not a credential request"),
            Self::Credential(error) => write!(f, "the credential format refused: {error}"),
            Self::Time(error) => write!(f, "the time refused: {error}"),
            Self::Driver(error) => write!(f, "the commit driver refused: {error}"),
            Self::Transition(error) => write!(f, "the proposal refused: {error}"),
        }
    }
}

impl core::error::Error for Error {}

/// The failure of an operation that reads the store: a refusal, or a failed read.
pub type Failure<E> = crate::store::Failure<Error, E>;
