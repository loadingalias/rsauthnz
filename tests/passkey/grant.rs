//! The grant of an agent: its owner gives named resource actions at named audiences until a deadline. Each request of
//! the agent presents a credential that names its owner and the revision of its grant, and each use checks the
//! current authority of the owner. Each change needs a fresh verification of the owner, and a restore releases no
//! revision twice.

use core::time::Duration;

use rsauthnz::account::{FRESH_MAX, Fresh};
use rsauthnz::authz::{self, Granted, Permit, Policy, Request, Requirements};
use rsauthnz::cbor::{self, Value};
use rsauthnz::cose::{Key, PublicKey, TrustedKey};
use rsauthnz::credential::{Claims, Draft as CredentialDraft, Profile, ProofDraft, Serial, Subject};
use rsauthnz::crypto::Algorithm;
use rsauthnz::evidence::Evidence;
use rsauthnz::grant::{Approval, Draft, Error, Failure, Grant, Grants, Permission};
use rsauthnz::id::{Action, Audience, AuthorityVersion, Human, Id, Principal, Purpose, Resource, Workload};
use rsauthnz::limits::{Limit, Limits, SignatureBudget};
use rsauthnz::session::Access;
use rsauthnz::store::Kind;
use rsauthnz::store::driver::Plan;
use rsauthnz::transition::{self, Audit, OperationId, Outcome, Proposal};
use rsauthnz_conformance::suite::Subject as _;
use rscrypto::auth::{MlDsa65Ed25519, MlDsa65Ed25519PublicKey, MlDsa65Ed25519SecretKey};

use super::agent::{Agent, World, key, keypair, rotation};
use super::{START, alice, at, ready};

/// The audience of the grants of the tests.
const API: &str = "api";

/// The authority of the agents and of their grants, which issues the credentials of its agents.
const AUTHORITY: &str = "agents";

/// The challenge of the verifier that each proof of possession binds.
const CHALLENGE: [u8; 32] = [5; 32];

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

fn purpose() -> Id<Purpose> {
    Id::new("acme", "agent").expect("an identifier")
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

/// The composite key of an issuer of credentials. rscrypto signs in place of custody.
struct Issuer {
    public: MlDsa65Ed25519PublicKey,
    secret: MlDsa65Ed25519SecretKey,
}

impl Issuer {
    fn new(seed: u8) -> Self {
        let (public, secret) = MlDsa65Ed25519::generate_keypair(|out| {
            let _: () = out.fill(seed);
            Ok(())
        })
        .expect("a key pair");
        Self { public, secret }
    }

    fn key(&self) -> TrustedKey {
        trusted(PublicKey::MlDsa65Ed25519(&self.public.to_bytes()))
    }
}

/// The trusted key of the composite public key `public`.
fn trusted(public: PublicKey<'_>) -> TrustedKey {
    let key = Key {
        kid: None,
        alg: None,
        public,
    };
    TrustedKey::new(Algorithm::MlDsa65Ed25519, &key).expect("a composite key")
}

/// What a credential of the agent names: its issuer, the owner, the grant revision, and the audience. The agent key of
/// `holder` proves its possession.
struct Presented<'a> {
    issuer: &'a str,
    owner: Id<Human>,
    revision: u64,
    audience: &'a str,
    holder: u8,
}

/// Alice, her agent enrolled at 23 with the key of seed 2, the grants of its authority, and the policy at version 1,
/// under which she holds the read of `repo-x`. The authority issues the credentials of the agent.
struct Grantor {
    world: World,
    agent: Agent,
    grants: Grants,
    policy: Held,
    issuer: Issuer,
    /// The revision of the last grant that committed, which each credential of [`Self::check`] names.
    revision: u64,
    /// The seed of the current key of the agent.
    holder: u8,
    /// The serial of the last credential.
    serial: u64,
}

impl Grantor {
    fn new() -> Self {
        let mut world = World::new();
        let agent = world.enrolled(2);
        let version = world.site.node.policy(None, 1);
        Self {
            world,
            agent,
            grants: Grants::new(Id::new("acme", AUTHORITY).expect("an identifier"), Limits::default()),
            policy: Held {
                version,
                held: vec![(resource("repo-x"), action("repo.read"))],
            },
            issuer: Issuer::new(7),
            revision: 0,
            holder: 2,
            serial: 0,
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
        self.revision = grant.revision;
        grant
    }

    /// The credential of `presented` for the agent, which the issuer of `presented` signs at `seconds`, and which
    /// ends one day after [`START`]. Only the receipt of its issuance commit gives its bytes.
    fn credential(&mut self, presented: &Presented<'_>, seconds: u64) -> Vec<u8> {
        self.serial += 1;
        let claims = Claims::new(
            Id::new("acme", presented.issuer).expect("an identifier"),
            audience(presented.audience),
            Subject::Agent {
                agent: self.agent.started.agent.clone(),
                owner: presented.owner.clone(),
                revision: presented.revision,
            },
            purpose(),
            Serial(self.serial),
            time(86_400),
        );
        let holder = key(presented.holder);
        let draft = CredentialDraft::credential(
            &self.issuer.key(),
            &claims,
            Some(PublicKey::MlDsa65Ed25519(&holder)),
            at(seconds),
        )
        .expect("a draft");
        let signature = self
            .issuer
            .secret
            .sign_deterministic(&draft.to_be_signed(), &[])
            .expect("a signature");
        let audit = Audit {
            actor: Principal::Workload(Id::<Workload>::new("acme", presented.issuer).expect("an identifier")),
            action: Id::new("acme", "credential.issue").expect("an identifier"),
            time: at(seconds),
        };
        let operation = OperationId::new(format!("credential-{}", self.serial).as_bytes()).expect("an identity");
        let mut proposal = Proposal::new(operation, audit, &Value::Null, Limits::default()).expect("a proposal");
        draft.record(&mut proposal).expect("the issuance record");
        let prepared = draft
            .finish(signature.as_bytes(), &mut SignatureBudget::new(&Limits::default()))
            .expect("a credential");
        proposal.prepare(prepared).expect("the issuance record");
        match self.world.commit((proposal, Plan::default())) {
            Outcome::Accepted(receipt) => receipt.artifact().expect("the credential").to_vec(),
            outcome => panic!("the issuance gave {outcome:?}"),
        }
    }

    /// The evidence of the credential of `presented` at `seconds`: the profile of its issuer and audience verifies it,
    /// and the agent key of `presented` signs the proof of possession.
    fn evidence(&mut self, presented: &Presented<'_>, seconds: u64) -> Evidence {
        let credential = self.credential(presented, seconds);
        let audience = audience(presented.audience);
        let issuer = Id::new("acme", presented.issuer).expect("an identifier");
        let profile = Profile::new(
            self.issuer.key(),
            issuer,
            audience.clone(),
            purpose(),
            Limits::default(),
        )
        .expect("a profile");
        let budget = || SignatureBudget::new(&Limits::default());
        let verified = profile
            .verify(&credential, at(seconds), &mut budget())
            .expect("a credential");
        let holder = key(presented.holder);
        let draft = ProofDraft::new(
            &trusted(PublicKey::MlDsa65Ed25519(&holder)),
            &credential,
            &audience,
            &CHALLENGE,
            at(seconds),
        )
        .expect("a proof draft");
        let signature = keypair(presented.holder)
            .1
            .sign_deterministic(&draft.to_be_signed(), &[])
            .expect("a signature");
        let proof = draft.finish(signature.as_bytes(), &mut budget()).expect("a proof");
        verified
            .possession(&proof, &CHALLENGE, at(seconds), &mut budget())
            .expect("the evidence")
    }

    /// The check of the action `name` on `on` by the agent of `presented` at `seconds`.
    fn present(&mut self, presented: &Presented<'_>, on: &str, name: &str, seconds: u64) -> Result<Granted, Error> {
        let evidence = self.evidence(presented, seconds);
        let (action, resource) = (action(name), resource(on));
        let check = authz::check_agent(
            &self.grants,
            &mut self.world.site.node.memory,
            &evidence,
            &action,
            &resource,
            &self.policy,
            at(seconds),
        );
        ready(check).map_err(refused)
    }

    /// What the current credential of the agent names at `at_audience`: the authority, alice, the last revision, and the
    /// current key.
    fn current<'a>(&self, at_audience: &'a str) -> Presented<'a> {
        Presented {
            issuer: AUTHORITY,
            owner: alice(),
            revision: self.revision,
            audience: at_audience,
            holder: self.holder,
        }
    }

    /// The check of the action `name` on `on` at `at_audience` by the agent with its current credential at `seconds`.
    fn check(&mut self, at_audience: &str, on: &str, name: &str, seconds: u64) -> Result<Granted, Error> {
        let presented = self.current(at_audience);
        self.present(&presented, on, name, seconds)
    }

    /// Enforces `scope` on the read of `repo-x` at `seconds`.
    fn enforce(&mut self, scope: &Granted, seconds: u64) -> Result<(), Error> {
        let (action, resource) = (action("repo.read"), resource("repo-x"));
        let enforce = scope.enforce(
            &mut self.world.site.node.memory,
            &action,
            &resource,
            &self.policy,
            at(seconds),
        );
        ready(enforce).map_err(refused)
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

    let scope = grantor.check(API, "repo-x", "repo.read", 31).expect("a use");
    assert_eq!((scope.owner(), scope.revision()), (&alice(), grant.revision));
    assert_eq!(scope.deadline(), time(3600));
    assert_eq!(
        grantor.check(API, "repo-y", "repo.write", 31).err(),
        Some(Error::Permission)
    );
    assert_eq!(
        grantor.check(API, "repo-x", "repo.write", 31).err(),
        Some(Error::Permission)
    );
    assert_eq!(
        grantor.check("other-api", "repo-x", "repo.read", 31).err(),
        Some(Error::Audience)
    );

    grantor.policy.held.clear();
    assert_eq!(
        grantor.check(API, "repo-x", "repo.read", 32).err(),
        Some(Error::Authority)
    );
    assert_eq!(
        grantor.propose(&fresh, &wanted, time(3600), 33).err(),
        Some(Error::Authority)
    );

    grantor.policy.held = vec![(resource("repo-x"), action("repo.read"))];
    let earlier = grantor.policy.version.clone();
    grantor.policy.version = grantor.world.site.node.policy(Some(&earlier), 2);
    assert_eq!(grantor.check(API, "repo-x", "repo.read", 34).err(), Some(Error::Policy));
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
    grantor.check(API, "repo-x", "repo.read", 98).unwrap();
    assert_eq!(
        grantor.check(API, "repo-x", "repo.read", 99).err(),
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
        grantor.check(API, "repo-x", "repo.read", 45).expect("a use").deadline(),
        time(3600)
    );

    let (_, fresh) = grantor.world.session();
    let changed = grantor.issue(&fresh, &read, time(7200), 46);
    assert!(changed.revision > first.revision);
    let scope = grantor.check(API, "repo-x", "repo.read", 47).expect("a use");
    assert_eq!((scope.revision(), scope.deadline()), (changed.revision, time(7200)));
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
        grantor.check(API, "repo-x", "repo.read", 32).err(),
        Some(Error::NoGrant)
    );

    let (_, fresh) = grantor.world.session();
    let again = grantor.issue(&fresh, &read, time(7200), 33);
    assert!(again.revision > changed.revision);
}

/// A key rotation of the agent keeps its grant: a credential of the new key serves, and a credential of the old key
/// refuses. A revocation of the agent ends the grant in the same commit, so the active-access page no longer lists it.
#[test]
fn a_rotation_keeps_the_grant_and_a_revocation_of_the_agent_ends_it() {
    let mut grantor = Grantor::new();
    let (access, fresh) = grantor.world.session();
    let grant = grantor.issue(&fresh, &[permission("repo-x", "repo.read")], time(3600), 30);
    let id = grantor.agent.started.agent.clone();
    let rotated = grantor.world.rotate(&rotation(&id, 2, 3, 1, [2, 3]), 31);
    assert!(matches!(rotated, Ok(Outcome::Accepted(_))));
    assert_eq!(grantor.check(API, "repo-x", "repo.read", 32).err(), Some(Error::Key));
    grantor.holder = 3;
    assert_eq!(
        grantor.check(API, "repo-x", "repo.read", 32).expect("a use").revision(),
        grant.revision
    );

    let agent = &grantor.agent;
    let revoked = grantor.world.revoke(&access, agent, 33);
    assert!(matches!(revoked, Ok(Outcome::Accepted(_))));
    assert_eq!(
        grantor.check(API, "repo-x", "repo.read", 34).err(),
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
        grantor.check(API, "repo-x", "repo.read", 45).err(),
        Some(Error::NoGrant)
    );
}

/// The scope of a request names the agent, its owner, and the revision of its grant. The store gives the owner and
/// the revision, and the credential must name both: a credential of another authority, another owner, or an earlier
/// revision refuses.
#[test]
fn a_request_refuses_a_credential_of_another_authority_another_owner_or_an_earlier_revision() {
    let mut grantor = Grantor::new();
    let (_, fresh) = grantor.world.session();
    let read = [permission("repo-x", "repo.read")];
    let first = grantor.issue(&fresh, &read, time(3600), 30);
    let scope = grantor.check(API, "repo-x", "repo.read", 31).expect("a use");
    assert_eq!(
        (scope.agent(), scope.owner(), scope.revision()),
        (&grantor.agent.started.agent, &alice(), first.revision)
    );

    let tenant = Presented {
        issuer: "other-agents",
        ..grantor.current(API)
    };
    assert_eq!(
        grantor.present(&tenant, "repo-x", "repo.read", 32).err(),
        Some(Error::Issuer)
    );
    let substituted = Presented {
        owner: Id::new("acme", "bob").expect("an identifier"),
        ..grantor.current(API)
    };
    assert_eq!(
        grantor.present(&substituted, "repo-x", "repo.read", 32).err(),
        Some(Error::Owner)
    );

    let (_, fresh) = grantor.world.session();
    grantor.issue(&fresh, &read, time(7200), 33);
    let earlier = Presented {
        revision: first.revision,
        ..grantor.current(API)
    };
    assert_eq!(
        grantor.present(&earlier, "repo-x", "repo.read", 34).err(),
        Some(Error::Revision)
    );
}

/// An operation of an agent takes its proposal from its scope, and the audit record names the agent and, as a separate
/// field, its owner. A proposal that names an agent as its actor outside a scope refuses, so no audit of a request of
/// an agent lacks its owner.
#[test]
fn the_audit_of_an_operation_of_an_agent_names_the_agent_and_its_owner() {
    let mut grantor = Grantor::new();
    let (_, fresh) = grantor.world.session();
    grantor.issue(&fresh, &[permission("repo-x", "repo.read")], time(3600), 30);
    let scope = grantor.check(API, "repo-x", "repo.read", 31).expect("a use");
    let operation = OperationId::new(b"agent-read").expect("an operation identity");
    let proposal = scope.propose(operation, Value::Null, at(31)).expect("a proposal");
    assert!(matches!(
        grantor.world.commit((proposal, Plan::default())),
        Outcome::Accepted(_)
    ));

    let key = Kind::Audit.key(b"agent-read").expect("a key");
    let record = grantor.world.site.node.read(&key).expect("the audit record");
    let value = cbor::decode(&record.data, Limits::default()).expect("an audit form");
    let Value::Array(items) = &value else {
        panic!("an audit form");
    };
    let agent = Principal::Agent(grantor.agent.started.agent.clone());
    let read = action("repo.read");
    assert_eq!(
        items[..4],
        [
            Value::Text("rsauthnz.store.audit.2"),
            agent.to_cbor(),
            alice().to_cbor(),
            read.to_cbor()
        ]
    );

    let audit = Audit {
        actor: agent,
        action: read,
        time: at(32),
    };
    let operation = OperationId::new(b"agent-write").expect("an operation identity");
    assert_eq!(
        Proposal::new(operation, audit, &Value::Null, Limits::default()).err(),
        Some(transition::Error::Agent)
    );
}

/// Each use of a scope reads the identity and the grant again, so a revocation during a streamed response stops it at
/// its next chunk, and pending work that commits after the revocation refuses.
#[test]
fn a_revocation_during_a_streamed_response_stops_it_at_the_next_chunk() {
    let mut grantor = Grantor::new();
    let (access, fresh) = grantor.world.session();
    grantor.issue(&fresh, &[permission("repo-x", "repo.read")], time(3600), 30);
    let scope = grantor.check(API, "repo-x", "repo.read", 31).expect("a use");
    let operation = OperationId::new(b"pending").expect("an operation identity");
    let pending = scope.propose(operation, Value::Null, at(31)).expect("a proposal");

    let (mut sent, mut stopped) = (Vec::new(), None);
    for chunk in 0..4 {
        if chunk == 2 {
            let revocation = grantor.revocation(&access, 40).expect("a revocation");
            assert!(matches!(grantor.world.commit(revocation), Outcome::Accepted(_)));
        }
        if let Err(error) = grantor.enforce(&scope, 40 + chunk) {
            stopped = Some(error);
            break;
        }
        sent.push(chunk);
    }
    assert_eq!((sent, stopped), (vec![0, 1], Some(Error::NoGrant)));
    assert!(matches!(
        grantor.world.commit((pending, Plan::default())),
        Outcome::Conflict
    ));
}

/// A scope keeps no copy of the state that its check read: a relevant policy change, a rotation of the key of the
/// agent, or a change of the grant stops it at its next use.
#[test]
fn a_policy_change_a_rotation_or_a_change_of_the_grant_stops_a_scope_at_its_next_use() {
    let mut grantor = Grantor::new();
    let (_, fresh) = grantor.world.session();
    let read = [permission("repo-x", "repo.read")];
    grantor.issue(&fresh, &read, time(3600), 30);
    let scope = grantor.check(API, "repo-x", "repo.read", 31).expect("a use");
    grantor.enforce(&scope, 32).expect("a use");
    let earlier = grantor.policy.version.clone();
    grantor.policy.version = grantor.world.site.node.policy(Some(&earlier), 2);
    assert_eq!(grantor.enforce(&scope, 33).err(), Some(Error::Policy));

    let (_, fresh) = grantor.world.session();
    grantor.issue(&fresh, &read, time(3600), 34);
    let scope = grantor.check(API, "repo-x", "repo.read", 35).expect("a use");
    let id = grantor.agent.started.agent.clone();
    let rotated = grantor.world.rotate(&rotation(&id, 2, 3, 1, [2, 3]), 36);
    assert!(matches!(rotated, Ok(Outcome::Accepted(_))));
    assert_eq!(grantor.enforce(&scope, 37).err(), Some(Error::Key));

    grantor.holder = 3;
    let scope = grantor.check(API, "repo-x", "repo.read", 38).expect("a use");
    let (_, fresh) = grantor.world.session();
    grantor.issue(&fresh, &read, time(7200), 39);
    assert_eq!(grantor.enforce(&scope, 40).err(), Some(Error::Revision));
}
