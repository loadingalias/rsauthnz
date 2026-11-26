//! The grant of an agent: its owner gives named resource actions at named audiences until a deadline. Each use checks
//! the current authority of the owner, each change needs a fresh verification of the owner, and a restore releases no
//! revision twice.

use core::time::Duration;

use rsauthnz::account::{FRESH_MAX, Fresh};
use rsauthnz::authz::{Permit, Policy, Request, Requirements};
use rsauthnz::grant::{Admitted, Approval, Draft, Error, Failure, Grant, Grants, Permission, Use};
use rsauthnz::id::{Action, Audience, AuthorityVersion, Id, Principal, Resource};
use rsauthnz::limits::{Limit, Limits};
use rsauthnz::session::Access;
use rsauthnz::transition::{self, Outcome};
use rsauthnz_conformance::suite::Subject as _;

use super::agent::{Agent, World, rotation};
use super::{START, alice, at, ready};

/// The audience of the grants of the tests.
const API: &str = "api";

/// The policy of the tests: alice holds each permission of `held` under `version`, until one day after [`START`].
struct Held {
    version: AuthorityVersion,
    held: Vec<(Id<Resource>, Id<Action>)>,
}

impl Policy for Held {
    fn version(&self) -> &AuthorityVersion {
        &self.version
    }

    fn resolve(&self, request: &Request<'_>) -> Option<Permit> {
        let held = *request.principal == Principal::Human(alice())
            && self
                .held
                .iter()
                .any(|(resource, action)| resource == request.resource && action == request.action);
        held.then(|| Permit {
            principal: request.principal.clone(),
            action: request.action.clone(),
            resource: request.resource.clone(),
            version: self.version.clone(),
            requires: Requirements {
                user_verified: true,
                phishing_resistant: true,
                max_age: FRESH_MAX,
            },
            expires: START + Duration::from_secs(86_400),
        })
    }
}

fn resource(name: &str) -> Id<Resource> {
    Id::new("acme", name).expect("an identifier")
}

fn action(name: &str) -> Id<Action> {
    Id::new("acme", name).expect("an identifier")
}

fn audience(name: &str) -> Id<Audience> {
    Id::new("acme", name).expect("an identifier")
}

/// The permission of `name` on `on`, with no approval mark.
fn permission(on: &str, name: &str) -> Permission {
    Permission {
        resource: resource(on),
        action: action(name),
        approval: Approval::NotRequired,
    }
}

/// The time `seconds` past [`START`].
fn time(seconds: u64) -> Duration {
    START + Duration::from_secs(seconds)
}

/// Alice, her agent enrolled at 23, the grants of its authority, and the policy at version 1, under which she holds the
/// read of `repo-x`.
struct Grantor {
    world: World,
    agent: Agent,
    grants: Grants,
    policy: Held,
}

impl Grantor {
    fn new() -> Self {
        let mut world = World::new();
        let agent = world.enrolled(2);
        let version = world.site.node.policy(None, 1);
        Self {
            world,
            agent,
            grants: Grants::new(Id::new("acme", "agents").expect("an identifier"), Limits::default()),
            policy: Held {
                version,
                held: vec![(resource("repo-x"), action("repo.read"))],
            },
        }
    }

    /// The proposal of the grant of `permissions` at [`API`] until `deadline` by the human of `fresh` at `seconds`.
    fn propose(
        &mut self,
        fresh: &Fresh,
        permissions: &[Permission],
        deadline: Duration,
        seconds: u64,
    ) -> Result<(transition::Proposal, rsauthnz::store::driver::Plan, Grant), Error> {
        let draft = Draft {
            audiences: &[audience(API)],
            permissions,
            deadline,
        };
        self.draft(fresh, &draft, seconds)
    }

    fn draft(
        &mut self,
        fresh: &Fresh,
        draft: &Draft<'_>,
        seconds: u64,
    ) -> Result<(transition::Proposal, rsauthnz::store::driver::Plan, Grant), Error> {
        let node = &mut self.world.site.node;
        let issue = self.grants.issue(
            &mut node.memory,
            fresh,
            &self.agent.started.agent,
            draft,
            &self.policy,
            at(seconds),
            &mut self.world.site.random,
            &mut node.driver,
        );
        ready(issue).map_err(refused)
    }

    /// Commits the grant of [`Self::propose`], and gives the grant.
    fn issue(&mut self, fresh: &Fresh, permissions: &[Permission], deadline: Duration, seconds: u64) -> Grant {
        let (proposal, plan, grant) = self.propose(fresh, permissions, deadline, seconds).expect("a grant");
        assert!(matches!(self.world.commit((proposal, plan)), Outcome::Accepted(_)));
        grant
    }

    /// The check of the action `name` on `on` at `at_audience` by the agent at `seconds`.
    fn admits(&mut self, at_audience: &str, on: &str, name: &str, seconds: u64) -> Result<Admitted, Error> {
        let (audience, resource, action) = (audience(at_audience), resource(on), action(name));
        let request = Use {
            audience: &audience,
            resource: &resource,
            action: &action,
        };
        let check = self.grants.admits(
            &mut self.world.site.node.memory,
            &self.agent.started.agent,
            request,
            &self.policy,
            at(seconds),
        );
        ready(check).map_err(refused)
    }

    /// The proposal of the revocation of the grant by the human of `access` at `seconds`.
    fn revocation(
        &mut self,
        access: &Access,
        seconds: u64,
    ) -> Result<(transition::Proposal, rsauthnz::store::driver::Plan), Error> {
        let revoke = self.grants.revoke(
            &mut self.world.site.node.memory,
            access,
            &self.agent.started.agent,
            at(seconds),
            &mut self.world.site.random,
        );
        ready(revoke).map_err(refused)
    }

    /// The grants on the active-access page of the human of `access` at `seconds`.
    fn list(&mut self, access: &Access, seconds: u64) -> Vec<Grant> {
        let list = self
            .grants
            .list(&mut self.world.site.node.memory, access, None, at(seconds));
        ready(list).map_err(refused).expect("a page").grants
    }
}

/// The refusal of a failure of the memory binding, which reads with no failure.
fn refused(failure: Failure<rsauthnz_conformance::memory::Error>) -> Error {
    match failure {
        Failure::Refused(error) => error,
        Failure::Store(error) => panic!("the read failed: {error:?}"),
    }
}

/// The grant keeps only the permissions that alice holds at the issue. Each use checks her authority again, so a
/// permission that she loses after the issue refuses at the next use, and a relevant policy change stops the grant.
#[test]
fn a_grant_keeps_only_what_its_owner_holds_and_each_use_checks_her_current_authority() {
    let mut grantor = Grantor::new();
    let (_, fresh) = grantor.world.session();
    let wanted = [permission("repo-x", "repo.read"), permission("repo-y", "repo.write")];
    let grant = grantor.issue(&fresh, &wanted, time(3600), 30);
    assert_eq!(grant.permissions, [permission("repo-x", "repo.read")]);

    let admitted = grantor.admits(API, "repo-x", "repo.read", 31).expect("a use");
    assert_eq!((admitted.owner(), admitted.revision()), (&alice(), grant.revision));
    assert_eq!(admitted.deadline(), time(3600));
    assert_eq!(
        grantor.admits(API, "repo-y", "repo.write", 31).err(),
        Some(Error::Permission)
    );
    assert_eq!(
        grantor.admits(API, "repo-x", "repo.write", 31).err(),
        Some(Error::Permission)
    );
    assert_eq!(
        grantor.admits("other-api", "repo-x", "repo.read", 31).err(),
        Some(Error::Audience)
    );

    grantor.policy.held.clear();
    assert_eq!(
        grantor.admits(API, "repo-x", "repo.read", 32).err(),
        Some(Error::Authority)
    );
    assert_eq!(
        grantor.propose(&fresh, &wanted, time(3600), 33).err(),
        Some(Error::Authority)
    );

    grantor.policy.held = vec![(resource("repo-x"), action("repo.read"))];
    let earlier = grantor.policy.version.clone();
    grantor.policy.version = grantor.world.site.node.policy(Some(&earlier), 2);
    assert_eq!(
        grantor.admits(API, "repo-x", "repo.read", 34).err(),
        Some(Error::Policy)
    );
}

/// A grant needs a deadline after the reading, and each use refuses from the deadline on. A draft names at least one
/// audience and one permission, each once, within the limits.
#[test]
fn a_grant_needs_a_deadline_after_now_and_each_use_ends_at_it() {
    let mut grantor = Grantor::new();
    let (_, fresh) = grantor.world.session();
    let read = [permission("repo-x", "repo.read")];
    // The reading at 30 can be at 31.
    for deadline in [time(30), time(31)] {
        assert_eq!(
            grantor.propose(&fresh, &read, deadline, 30).err(),
            Some(Error::Deadline)
        );
    }
    grantor.issue(&fresh, &read, time(100), 30);
    grantor.admits(API, "repo-x", "repo.read", 98).unwrap();
    assert_eq!(
        grantor.admits(API, "repo-x", "repo.read", 99).err(),
        Some(Error::Expired)
    );

    let audiences: Vec<_> = (0..9).map(|n| audience(&format!("api-{n}"))).collect();
    let twice = [permission("repo-x", "repo.read"), permission("repo-x", "repo.read")];
    let drafts = [
        (&audiences[..0], &read[..], Error::Draft),
        (&audiences[..], &read[..], Error::Limit(Limit::Audiences)),
        (&audiences[..1], &[][..], Error::Draft),
        (&audiences[..1], &twice[..], Error::Draft),
    ];
    for (audiences, permissions, error) in drafts {
        let draft = Draft {
            audiences,
            permissions,
            deadline: time(3600),
        };
        assert_eq!(grantor.draft(&fresh, &draft, 40).err(), Some(error));
    }
}

/// Only the owner changes a grant, and only with a fresh verification: an extension whose verification ended before
/// its commit refuses. A change writes a new revision, and the next use names it.
#[test]
fn an_extension_needs_a_fresh_verification_of_its_owner() {
    let mut grantor = Grantor::new();
    let (_, fresh) = grantor.world.session();
    let read = [permission("repo-x", "repo.read")];
    let first = grantor.issue(&fresh, &read, time(3600), 30);

    let (_, bob) = grantor.world.bob();
    assert_eq!(
        grantor.propose(&bob, &read, time(7200), 43).err(),
        Some(Error::NotEnrolled)
    );

    let (proposal, plan, _) = grantor.propose(&fresh, &read, time(7200), 44).expect("a change");
    // The sign-in of the verification was at 11.
    grantor.world.site.node.memory.set_clock(at(12 + FRESH_MAX.as_secs()));
    assert!(matches!(
        grantor.world.commit((proposal, plan)),
        Outcome::Refused(transition::Error::Expired)
    ));
    grantor.world.site.node.memory.set_clock(at(45));
    assert_eq!(
        grantor
            .admits(API, "repo-x", "repo.read", 45)
            .expect("a use")
            .deadline(),
        time(3600)
    );

    let (_, fresh) = grantor.world.session();
    let changed = grantor.issue(&fresh, &read, time(7200), 46);
    assert!(changed.revision > first.revision);
    let admitted = grantor.admits(API, "repo-x", "repo.read", 47).expect("a use");
    assert_eq!(
        (admitted.revision(), admitted.deadline()),
        (changed.revision, time(7200))
    );
}

/// A change and a revocation that read one revision commit at most once.
#[test]
fn a_change_racing_a_revocation_commits_at_most_one() {
    let mut grantor = Grantor::new();
    let (access, fresh) = grantor.world.session();
    let read = [permission("repo-x", "repo.read")];
    grantor.issue(&fresh, &read, time(3600), 30);
    let (change, plan, _) = grantor.propose(&fresh, &read, time(7200), 31).expect("a change");
    let revocation = grantor.revocation(&access, 31).expect("a revocation");

    assert!(matches!(grantor.world.commit((change, plan)), Outcome::Accepted(_)));
    assert!(matches!(grantor.world.commit(revocation), Outcome::Conflict));
}

/// A restore from a snapshot before a change gives no revision of the grant again: the journal ends the revision that
/// the change replaced, and the next issue takes a revision after each one that the store gave.
#[test]
fn a_restore_from_an_older_snapshot_releases_no_revision_twice() {
    let mut grantor = Grantor::new();
    let (_, fresh) = grantor.world.session();
    let read = [permission("repo-x", "repo.read")];
    grantor.issue(&fresh, &read, time(3600), 30);
    let snapshot = grantor.world.site.node.memory.snapshot();
    let changed = grantor.issue(&fresh, &read, time(7200), 31);

    grantor.world.site.node.memory.restore(&snapshot);
    grantor.world.site.node.driver.restore(at(0)).expect("a restore");
    grantor.world.site.node.run();
    assert_eq!(
        grantor.admits(API, "repo-x", "repo.read", 32).err(),
        Some(Error::NoGrant)
    );

    let (_, fresh) = grantor.world.session();
    let again = grantor.issue(&fresh, &read, time(7200), 33);
    assert!(again.revision > changed.revision);
}

/// A key rotation of the agent keeps its grant. A revocation of the agent ends the grant in the same commit, so the
/// active-access page no longer lists it.
#[test]
fn a_rotation_keeps_the_grant_and_a_revocation_of_the_agent_ends_it() {
    let mut grantor = Grantor::new();
    let (access, fresh) = grantor.world.session();
    let grant = grantor.issue(&fresh, &[permission("repo-x", "repo.read")], time(3600), 30);
    let id = grantor.agent.started.agent.clone();
    let rotated = grantor.world.rotate(&rotation(&id, 2, 3, 1, [2, 3]), 31);
    assert!(matches!(rotated, Ok(Outcome::Accepted(_))));
    assert_eq!(
        grantor
            .admits(API, "repo-x", "repo.read", 32)
            .expect("a use")
            .revision(),
        grant.revision
    );

    let agent = &grantor.agent;
    let revoked = grantor.world.revoke(&access, agent, 33);
    assert!(matches!(revoked, Ok(Outcome::Accepted(_))));
    assert_eq!(
        grantor.admits(API, "repo-x", "repo.read", 34).err(),
        Some(Error::NotEnrolled)
    );
    assert!(grantor.list(&access, 34).is_empty());
}

/// The active-access page of alice lists her grant, and the page of bob does not. Bob cannot revoke it. After her
/// revocation, the page lists nothing and each use refuses.
#[test]
fn the_active_access_page_lists_the_grants_of_its_owner_and_only_she_revokes_them() {
    let mut grantor = Grantor::new();
    let (access, fresh) = grantor.world.session();
    let grant = grantor.issue(&fresh, &[permission("repo-x", "repo.read")], time(3600), 30);
    assert_eq!(grantor.list(&access, 31), [grant]);

    let (bob, _) = grantor.world.bob();
    assert!(grantor.list(&bob, 43).is_empty());
    assert_eq!(grantor.revocation(&bob, 43).err(), Some(Error::NoGrant));

    let revocation = grantor.revocation(&access, 44).expect("a revocation");
    assert!(matches!(grantor.world.commit(revocation), Outcome::Accepted(_)));
    assert!(grantor.list(&access, 45).is_empty());
    assert_eq!(
        grantor.admits(API, "repo-x", "repo.read", 45).err(),
        Some(Error::NoGrant)
    );
}
