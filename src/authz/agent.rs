//! The agent path: the check of one request of an agent under the grant of its owner, and the scope that the operation
//! enforces at each use.

use alloc::vec;
use core::time::Duration;

use super::Policy;
use crate::agent::Identity;
use crate::cbor::Value;
use crate::cose::PublicKey;
use crate::credential::Subject;
use crate::evidence::Evidence;
use crate::grant::{self, Approval, Error, Failure, Grant, Grants};
use crate::id::{Action, Agent, AuthorityVersion, Human, Id, Principal, Resource};
use crate::limits::Limits;
use crate::store::{Record, Store};
use crate::time::Reading;
use crate::transition::{self, Audit, Dependency, Key, OperationId, Proposal};

/// Checks that the grant of the agent of `evidence` permits `action` on `resource` at the physical time `now`, and
/// gives the checked scope. The evidence is the proof of possession of a credential of the agent
/// ([`credential::Verified::possession`](crate::credential::Verified::possession)), which names the agent, its owner,
/// the revision of its grant, and the audience. The check reads the identity of the agent and its grant from one store
/// state ([`Store::read_pair`]). Then the credential must be of the authority of `grants`, and must name the owner of
/// the identity and the current revision of the grant. The key that proved the possession must be the current key of
/// the agent. The grant must name the audience of the credential and the action on the resource, and `policy` must
/// permit the owner the action on the resource now, under the policy version of the grant. Thus effective access is
/// the grant intersected with the current authority of the owner, and it never exceeds either one.
///
/// The requirements of the permit of the owner do not apply: they are requirements on the evidence of the owner, and
/// the issue of the grant took a fresh user verification of the owner.
///
/// Cost class: [`Verify`](crate::limits::Class::Verify). One read of two keys, one SHA-256 digest of the key of the
/// agent, and one policy decision.
///
/// # Errors
///
/// [`Error::Principal`] if the evidence is not of the credential of an agent, and [`Error::Issuer`] for a credential
/// of another authority. [`Error::NotEnrolled`] if the store holds no identity of the agent, [`Error::Owner`] if the
/// credential names another owner, and [`Error::Key`] if a rotation replaced the key. [`Error::NoGrant`] if the agent
/// has no grant, and [`Error::Revision`] if the credential names another revision. [`Error::Expired`] at or after the
/// deadline of the grant, [`Error::Audience`] and [`Error::Permission`] for an audience or a permission that the grant
/// does not name, [`Error::Policy`] for a grant of another policy version, and [`Error::Authority`] if the owner does
/// not hold the permission now. [`Error::Record`] for a record with no valid form, [`Error::Time`] for a reading with
/// no bound, and [`Failure::Store`] if the read fails.
pub async fn check_agent<S: Store>(
    grants: &Grants,
    store: &mut S,
    evidence: &Evidence,
    action: &Id<Action>,
    resource: &Id<Resource>,
    policy: &impl Policy,
    now: Reading,
) -> Result<Granted, Failure<S::Error>> {
    let latest = now.latest().map_err(Error::Time)?;
    let artifact = evidence.artifact().ok_or(Error::Principal)?;
    let claims = artifact.claims();
    let Subject::Agent { agent, owner, revision } = &claims.subject else {
        return Err(Error::Principal.into());
    };
    (claims.issuer == grants.authority).ok_or(Error::Issuer)?;
    let identity_key = grants.agents.identity_key(agent);
    let grant_key = grant::key(&grants.authority, owner, agent);
    let [identity, record] = store
        .read_pair([&identity_key, &grant_key])
        .await
        .map_err(Failure::Store)?;
    let identity = identity.ok_or(Error::NotEnrolled)?;
    let current = Identity::parse(agent, &identity, grants.limits).ok_or(Error::Record)?;
    (current.owner == *owner).ok_or(Error::Owner)?;
    (PublicKey::MlDsa65Ed25519(&current.key).thumbprint() == artifact.confirmation).ok_or(Error::Key)?;
    let record = record.ok_or(Error::NoGrant)?;
    let grant = Grant::parse(&record, grants.limits)
        .filter(|grant| grant.agent == *agent && grant.owner == *owner)
        .ok_or(Error::Record)?;
    (grant.revision == *revision).ok_or(Error::Revision)?;
    (latest < grant.deadline).ok_or(Error::Expired)?;
    grant.audiences.contains(&claims.audience).ok_or(Error::Audience)?;
    let permission = grant
        .permissions
        .iter()
        .find(|permission| permission.resource == *resource && permission.action == *action)
        .ok_or(Error::Permission)?;
    (*policy.version() == grant.policy).ok_or(Error::Policy)?;
    let principal = Principal::Human(owner.clone());
    let expires = grant::permit(policy, &principal, resource, action, latest).ok_or(Error::Authority)?;
    Ok(Granted {
        agent: agent.clone(),
        owner: owner.clone(),
        revision: grant.revision,
        action: action.clone(),
        resource: resource.clone(),
        approval: permission.approval,
        deadline: grant.deadline.min(expires).min(artifact.end()),
        policy: grant.policy,
        identity: (identity_key, identity.version),
        grant: (grant_key, record.version),
        limits: grants.limits,
    })
}

/// The scope of one request of an agent, which [`check_agent`] gave: the agent, its human owner, the grant revision,
/// the action on the resource, and the deadline. The operation enforces it at each use ([`Self::enforce`]), and an
/// operation that commits takes its proposal from it ([`Self::propose`]).
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Granted {
    agent: Id<Agent>,
    owner: Id<Human>,
    revision: u64,
    action: Id<Action>,
    resource: Id<Resource>,
    approval: Approval,
    deadline: Duration,
    /// The policy version of the grant.
    policy: AuthorityVersion,
    /// The key and the version of the identity record of the agent that the check read.
    identity: (Key, AuthorityVersion),
    /// The key and the version of the grant record that the check read.
    grant: (Key, AuthorityVersion),
    limits: Limits,
}

impl Granted {
    /// Checks that the operation does the action on the resource of the scope, that `policy` is at the version of the
    /// grant, that `now` is before the deadline, and that the identity of the agent and its grant are still the
    /// records that the check read. Call it at each use, for example before each chunk of a streamed response: a
    /// revocation, a change of the grant, or a rotation of the key then stops the work at its next use. The scope keeps
    /// no copy of the state, so each call reads it from one store state ([`Store::read_pair`]).
    ///
    /// Cost class: [`Verify`](crate::limits::Class::Verify). One read of two keys.
    ///
    /// # Errors
    ///
    /// [`Error::Permission`] for another action or resource, [`Error::Policy`] for another policy version,
    /// [`Error::Expired`] if `now` permits a time at or after the deadline, and [`Error::Time`] if `now` has no known
    /// bound. [`Error::NotEnrolled`] if the identity ended, [`Error::Key`] if a rotation changed it,
    /// [`Error::NoGrant`] if the grant ended, and [`Error::Revision`] if a change replaced it. [`Failure::Store`] if
    /// the read fails.
    pub async fn enforce<S: Store>(
        &self,
        store: &mut S,
        action: &Id<Action>,
        resource: &Id<Resource>,
        policy: &impl Policy,
        now: Reading,
    ) -> Result<(), Failure<S::Error>> {
        (*action == self.action && *resource == self.resource).ok_or(Error::Permission)?;
        (*policy.version() == self.policy).ok_or(Error::Policy)?;
        (now.latest().map_err(Error::Time)? < self.deadline).ok_or(Error::Expired)?;
        let [identity, grant] = store
            .read_pair([&self.identity.0, &self.grant.0])
            .await
            .map_err(Failure::Store)?;
        let same = |record: Option<Record>, (_, read): &(Key, AuthorityVersion), ended, changed| {
            (record.ok_or(ended)?.version == *read).ok_or(changed)
        };
        same(identity, &self.identity, Error::NotEnrolled, Error::Key)?;
        same(grant, &self.grant, Error::NoGrant, Error::Revision)?;
        Ok(())
    }

    /// The proposal of an operation of the agent that commits, with the operation identity `operation` and the request
    /// `request` of the application. The audit names the agent as the actor, its owner as a separate field, and the
    /// action of the scope. The commit reads the identity, the grant, and the policy version of the check, so a
    /// revocation, a change, or a relevant policy change before the commit refuses it, and it refuses at or after the
    /// deadline. Add the changes of the operation to the proposal. Its request is `[resource, request]`.
    ///
    /// Cost class: [`Parse`](crate::limits::Class::Parse).
    ///
    /// # Errors
    ///
    /// [`transition::Error::Request`] if the request has no CBOR encoding within the limits of the grants.
    pub fn propose(
        &self,
        operation: OperationId,
        request: Value<'_>,
        now: Reading,
    ) -> Result<Proposal, transition::Error> {
        let audit = Audit {
            actor: Principal::Agent(self.agent.clone()),
            action: self.action.clone(),
            time: now,
        };
        let request = Value::Array(vec![self.resource.to_cbor(), request]);
        let mut proposal = Proposal::start(operation, audit, &request, self.limits)?;
        proposal.attribute(self.owner.clone());
        for read in [
            Dependency::Version(self.identity.0.clone(), self.identity.1.clone()),
            Dependency::Version(self.grant.0.clone(), self.grant.1.clone()),
            Dependency::Policy(self.policy.clone()),
        ] {
            proposal.read(read)?;
        }
        proposal.until(self.deadline);
        Ok(proposal)
    }

    /// The agent.
    #[must_use]
    pub const fn agent(&self) -> &Id<Agent> {
        &self.agent
    }

    /// The human owner of the agent.
    #[must_use]
    pub const fn owner(&self) -> &Id<Human> {
        &self.owner
    }

    /// The revision of the grant.
    #[must_use]
    pub const fn revision(&self) -> u64 {
        self.revision
    }

    /// The end of the scope: the earliest of the grant deadline, the end of the permit of the owner, and the end of the
    /// credential of the agent. The scope is not valid at this time and after it.
    #[must_use]
    pub const fn deadline(&self) -> Duration {
        self.deadline
    }

    /// Whether the operation also needs a one-use approval of the owner.
    #[must_use]
    pub const fn approval(&self) -> Approval {
        self.approval
    }
}
