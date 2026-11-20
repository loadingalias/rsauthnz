use alloc::vec::Vec;
use core::time::Duration;

use super::{Permit, Policy, Refusal, Request, Requirements, check};
use crate::evidence::{Evidence, Method};
use crate::id::{Action, Agent, AuthorityVersion, Human, Id, Principal, Resource};
use crate::time::{Reading, ReadingSource, TimeError};

/// A policy with a list of permits. It gives the permit with the action and the resource of the request, and it
/// does not compare the principal, so a test can show that the check does.
struct Permits {
    version: AuthorityVersion,
    permits: Vec<Permit>,
}

impl Policy for Permits {
    fn version(&self) -> &AuthorityVersion {
        &self.version
    }

    fn resolve(&self, request: &Request<'_>) -> Option<Permit> {
        self.permits
            .iter()
            .find(|permit| permit.action == *request.action && permit.resource == *request.resource)
            .cloned()
    }
}

fn version(n: u64) -> AuthorityVersion {
    AuthorityVersion::new(Id::new("acme", "policy").unwrap(), &n.to_be_bytes()).unwrap()
}

fn action(value: &str) -> Id<Action> {
    Id::new("acme.repo", value).unwrap()
}

fn resource(value: &str) -> Id<Resource> {
    Id::new("acme.repo", value).unwrap()
}

fn human() -> Principal {
    Principal::Human(Id::<Human>::new("acme", "u-17").unwrap())
}

fn reading(seconds: u64) -> Reading {
    Reading::new(
        Duration::from_secs(seconds),
        Some(Duration::from_secs(1)),
        ReadingSource::Caller,
    )
}

/// A user-verified, phishing-resistant passkey authentication of `subject` at 1,000 seconds.
fn passkey(subject: Principal) -> Evidence {
    Evidence::new(subject, Method::Passkey, reading(1_000), true, true, None, None)
}

/// The permit of `repo.read` on `repo:x` for the human, at policy version 7, until 2,000 seconds.
fn read_x(requires: Requirements) -> Permit {
    Permit {
        principal: human(),
        action: action("repo.read"),
        resource: resource("repo:x"),
        version: version(7),
        requires,
        expires: Duration::from_secs(2_000),
    }
}

const ANY: Requirements = Requirements {
    user_verified: false,
    phishing_resistant: false,
    max_age: Duration::from_secs(3_600),
};

fn policy(n: u64, permit: Permit) -> Permits {
    Permits {
        version: version(n),
        permits: alloc::vec![permit],
    }
}

#[test]
fn a_scope_for_repo_read_on_repo_x_refuses_repo_write_and_repo_y() {
    let policy = policy(7, read_x(ANY));
    let evidence = passkey(human());
    let (read, write, x, y) = (
        action("repo.read"),
        action("repo.write"),
        resource("repo:x"),
        resource("repo:y"),
    );
    let now = reading(1_100);

    // The authorized operation succeeds.
    let scope = check(&evidence, &read, &x, &policy, now).unwrap();
    assert_eq!(scope.enforce(&read, &x, &policy, now), Ok(()));
    assert_eq!(scope.evidence(), &evidence);

    assert_eq!(scope.enforce(&write, &x, &policy, now), Err(Refusal::Scope));
    assert_eq!(scope.enforce(&read, &y, &policy, now), Err(Refusal::Scope));
    assert_eq!(check(&evidence, &write, &x, &policy, now), Err(Refusal::Denied));
    assert_eq!(check(&evidence, &read, &y, &policy, now), Err(Refusal::Denied));
}

#[test]
fn a_scope_from_policy_version_n_refuses_under_version_n_plus_1() {
    let (read, x, now) = (action("repo.read"), resource("repo:x"), reading(1_100));
    let evidence = passkey(human());
    let scope = check(&evidence, &read, &x, &policy(7, read_x(ANY)), now).unwrap();

    // The policy changes to version 8 after the check.
    let changed = policy(8, read_x(ANY));
    assert_eq!(scope.enforce(&read, &x, &changed, now), Err(Refusal::Stale));
    // A policy at version 8 that gives a permit of version 7.
    assert_eq!(check(&evidence, &read, &x, &changed, now), Err(Refusal::Stale));
}

#[test]
fn the_evidence_must_meet_the_requirements_and_the_deadline() {
    let (read, x) = (action("repo.read"), resource("repo:x"));
    let strict = Requirements {
        user_verified: true,
        phishing_resistant: true,
        max_age: Duration::from_secs(300),
    };
    let policy = policy(7, read_x(strict));

    let recovery = Evidence::new(human(), Method::Recovery, reading(1_000), true, true, None, None);
    let unverified = Evidence::new(human(), Method::Passkey, reading(1_000), false, true, None, None);
    assert_eq!(
        check(&recovery, &read, &x, &policy, reading(1_100)),
        Err(Refusal::Requirements)
    );
    assert_eq!(
        check(&unverified, &read, &x, &policy, reading(1_100)),
        Err(Refusal::Requirements)
    );

    // The authentication was at 999 seconds at the earliest, so the scope ends at 1,299 seconds.
    let evidence = passkey(human());
    let scope = check(&evidence, &read, &x, &policy, reading(1_297)).unwrap();
    assert_eq!(scope.deadline(), Duration::from_secs(1_299));
    assert_eq!(
        check(&evidence, &read, &x, &policy, reading(1_298)),
        Err(Refusal::Expired)
    );
    assert_eq!(scope.enforce(&read, &x, &policy, reading(1_298)), Err(Refusal::Expired));

    // The end of the permit, 2,000 seconds, comes before the end of the maximum age.
    let lasting = self::policy(7, read_x(ANY));
    assert_eq!(
        check(&evidence, &read, &x, &lasting, reading(1_999)),
        Err(Refusal::Expired)
    );

    let unknown = Reading::new(Duration::from_secs(1_100), None, ReadingSource::SystemClock);
    assert_eq!(
        check(&evidence, &read, &x, &lasting, unknown),
        Err(Refusal::Time(TimeError::UnknownBound))
    );
}

#[test]
fn a_permit_for_another_principal_with_the_same_raw_id_refuses() {
    let policy = policy(7, read_x(ANY));
    let agent = passkey(Principal::Agent(Id::<Agent>::new("acme", "u-17").unwrap()));
    assert_eq!(
        check(
            &agent,
            &action("repo.read"),
            &resource("repo:x"),
            &policy,
            reading(1_100)
        ),
        Err(Refusal::Scope)
    );
}
