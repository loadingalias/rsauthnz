//! The grant of an agent: its owner gives named resource actions at named audiences until a deadline. Each request of
//! the agent presents a credential that names its owner and the revision of its grant, and each use checks the
//! current authority of the owner. Each change needs a fresh verification of the owner, and a restore releases no
//! revision twice.

use core::num::NonZeroUsize;
use core::time::Duration;

use rsauthnz::account::{FRESH_MAX, Fresh};
use rsauthnz::authz::{self, Granted, Permit, Policy, Request, Requirements};
use rsauthnz::cbor::{self, Value};
use rsauthnz::cose::{Key, PublicKey, TrustedKey};
use rsauthnz::credential::{Claims, Draft as CredentialDraft, ProofDraft, Released, Serial, Subject};
use rsauthnz::crypto::Algorithm;
use rsauthnz::custody::{Handle, KeyId};
use rsauthnz::grant::{self, Approval, Draft, Error, Failure, Grant, Grants, LIFETIME_MAX, Permission, Usage};
use rsauthnz::id::{Action, Audience, Authority, AuthorityVersion, Human, Id, Principal, Resource, Workload};
use rsauthnz::limits::{Limit, Limits, SignatureBudget};
use rsauthnz::session::Access;
use rsauthnz::store::Kind;
use rsauthnz::store::driver::Plan;
use rsauthnz::transition::{self, Audit, OperationId, Outcome, Proposal};
use rsauthnz_conformance::suite::Subject as _;
use rscrypto::auth::{MlDsa65Ed25519, MlDsa65Ed25519PublicKey, MlDsa65Ed25519SecretKey};

use super::agent::{Agent, World, base64url, key, keypair, rotation};
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

    /// The handle of the issuer key in custody.
    fn handle(&self) -> Handle {
        Handle::new(
            KeyId::from_bytes([7; 16]),
            Algorithm::MlDsa65Ed25519,
            &self.public.to_bytes(),
        )
        .expect("a handle")
    }

    /// The signature of custody over `message`.
    fn sign(&self, message: &[u8]) -> Vec<u8> {
        let signature = self.secret.sign_deterministic(message, &[]).expect("a signature");
        signature.as_bytes().to_vec()
    }
}

/// The authority of the agents and of their grants.
fn authority() -> Id<Authority> {
    Id::new("acme", AUTHORITY).expect("an identifier")
}

/// The signature budget of one artifact.
fn budget() -> SignatureBudget {
    SignatureBudget::new(&Limits::default())
}

/// The proof of possession of the agent key of `holder` over `bytes` for `audience` and `challenge` at `seconds`.
fn prove(holder: u8, bytes: &[u8], audience: &Id<Audience>, challenge: &[u8], seconds: u64) -> Vec<u8> {
    let draft = ProofDraft::new(
        &trusted(PublicKey::MlDsa65Ed25519(&key(holder))),
        bytes,
        audience,
        challenge,
        at(seconds),
    )
    .expect("a proof draft");
    let signature = keypair(holder)
        .1
        .sign_deterministic(&draft.to_be_signed(), &[])
        .expect("a signature");
    draft.finish(signature.as_bytes(), &mut budget()).expect("a proof")
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

/// A credential of the agent that a test presents: its bytes, its issuer, its audience, and the seed of the agent key
/// that proves its possession.
struct Shown<'a> {
    bytes: Vec<u8>,
    issuer: &'a str,
    audience: &'a str,
    holder: u8,
}

/// What a forged credential of the agent names: its issuer, the owner, and the grant revision. The issuer key of the
/// tests signs it with the generic credential draft, as an issuer that does not read the grant would.
struct Forged<'a> {
    issuer: &'a str,
    owner: Id<Human>,
    revision: u64,
}

/// Alice, her agent enrolled at 23 with the key of seed 2, the grants of its authority, and the policy at version 1,
/// under which she holds the read of `repo-x`. The authority issues the credentials of the agent.
struct Grantor {
    world: World,
    agent: Agent,
    grants: Grants,
    policy: Held,
    issuer: Issuer,
    /// The seed of the current key of the agent.
    holder: u8,
    /// The number of the last credential: the nonce of an issue, or the serial of a forged credential.
    count: u64,
}

impl Grantor {
    fn new() -> Self {
        let mut world = World::new();
        let agent = world.enrolled(2);
        let version = world.site.node.policy(None, 1);
        Self {
            world,
            agent,
            grants: Grants::new(authority(), Limits::default()),
            policy: Held {
                version,
                held: vec![(resource("repo-x"), action("repo.read"))],
            },
            issuer: Issuer::new(7),
            holder: 2,
            count: 0,
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

    /// The credential of the agent for `at_audience` and `lifetime`, which the authority issues at `seconds` from the
    /// grant ([`Grants::credential`]). The key of `holder` proves the request, and custody signs with the issuer key.
    fn issued(
        &mut self,
        holder: u8,
        at_audience: &str,
        lifetime: Option<Duration>,
        seconds: u64,
    ) -> Result<Released, Error> {
        self.count += 1;
        let (agent, audience) = (self.agent.started.agent.clone(), audience(at_audience));
        let mut nonce = [0; 32];
        nonce[..8].copy_from_slice(&self.count.to_be_bytes());
        let statement = grant::statement(&authority(), &agent, &audience, lifetime);
        let proof = prove(holder, &statement, &audience, &nonce, seconds);
        // The body of the agent, with a member that names an owner, which names none.
        let lifetime = lifetime.map_or_else(String::new, |lifetime| format!(r#""lifetime":{},"#, lifetime.as_secs()));
        let body = format!(
            r#"{{"agent":"{agent}","audience":"{audience}",{lifetime}"nonce":"{}","proof":"{}","owner":"acme:bob"}}"#,
            base64url(&nonce),
            base64url(&proof),
        );
        let body = grant::Body::parse(body.as_bytes()).expect("a body");
        self.request(body.request(), seconds)
    }

    /// The credential of `request`, which the authority issues at `seconds` and its commit releases.
    fn request(&mut self, request: grant::Request<'_>, seconds: u64) -> Result<Released, Error> {
        let handle = self.issuer.handle();
        let node = &mut self.world.site.node;
        let credential = self.grants.credential(
            &mut node.memory,
            request,
            &handle,
            &self.policy,
            at(seconds),
            &mut node.driver,
        );
        let pending = ready(credential).map_err(refused)?;
        let signature = self.issuer.sign(&pending.to_be_signed());
        let (proposal, plan, awaiting) = pending.finish(&signature, &mut budget())?;
        let outcome = self.world.commit((proposal, plan));
        Ok(awaiting.release(outcome).expect("the commit releases the credential"))
    }

    /// The credential of `forged` at `at_audience` for the current key of the agent, which the issuer key signs at
    /// `seconds` with the generic credential draft, and which ends one day after [`START`].
    fn forged<'a>(&mut self, forged: &Forged<'a>, at_audience: &'a str, seconds: u64) -> Shown<'a> {
        self.count += 1;
        let claims = Claims::new(
            Id::new("acme", forged.issuer).expect("an identifier"),
            audience(at_audience),
            Subject::Agent {
                agent: self.agent.started.agent.clone(),
                owner: forged.owner.clone(),
                revision: forged.revision,
            },
            grant::purpose(),
            Serial(self.world.site.node.driver.allocate().expect("a serial")),
            time(86_400),
        );
        let holder = key(self.holder);
        let draft = CredentialDraft::credential(
            &self.issuer.key(),
            &claims,
            Some(PublicKey::MlDsa65Ed25519(&holder)),
            at(seconds),
        )
        .expect("a draft");
        let signature = self.issuer.sign(&draft.to_be_signed());
        let audit = Audit {
            actor: Principal::Workload(Id::<Workload>::new("acme", forged.issuer).expect("an identifier")),
            action: Id::new("acme", "credential.issue").expect("an identifier"),
            time: at(seconds),
        };
        let operation = OperationId::new(format!("forged-{}", self.count).as_bytes()).expect("an identity");
        let mut proposal = Proposal::new(operation, audit, &Value::Null, Limits::default()).expect("a proposal");
        draft.record(&mut proposal).expect("the issuance record");
        let prepared = draft.finish(&signature, &mut budget()).expect("a credential");
        proposal.prepare(prepared).expect("the issuance record");
        let bytes = match self.world.commit((proposal, Plan::default())) {
            Outcome::Accepted(receipt) => receipt.artifact().expect("the credential").to_vec(),
            outcome => panic!("the issuance gave {outcome:?}"),
        };
        Shown {
            bytes,
            issuer: forged.issuer,
            audience: at_audience,
            holder: self.holder,
        }
    }

    /// The check of the action `name` on `on` by the agent that presents `shown` at `seconds`: the profile of the issuer
    /// and the audience of `shown` verifies it, and the agent key of `shown` proves its possession.
    fn present(&mut self, shown: &Shown<'_>, on: &str, name: &str, seconds: u64) -> Result<Granted, Error> {
        let audience = audience(shown.audience);
        let grants = Grants::new(Id::new("acme", shown.issuer).expect("an identifier"), Limits::default());
        let profile = grants.profile(self.issuer.key(), &audience).expect("a profile");
        let verified = profile
            .verify(&shown.bytes, at(seconds), &mut budget())
            .expect("a credential");
        let proof = prove(shown.holder, &shown.bytes, &audience, &CHALLENGE, seconds);
        let evidence = verified
            .possession(&proof, &CHALLENGE, at(seconds), &mut budget())
            .expect("the evidence");
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

    /// The credential `released` of the agent at `at_audience`, as its current key shows it.
    fn shown<'a>(&self, released: &Released, at_audience: &'a str) -> Shown<'a> {
        Shown {
            bytes: released.as_bytes().to_vec(),
            issuer: AUTHORITY,
            audience: at_audience,
            holder: self.holder,
        }
    }

    /// The check of the action `name` on `on` at `at_audience` by the agent at `seconds`, with a new credential of its
    /// current key.
    fn check(&mut self, at_audience: &str, on: &str, name: &str, seconds: u64) -> Result<Granted, Error> {
        let released = self.issued(self.holder, at_audience, None, seconds)?;
        let shown = self.shown(&released, at_audience);
        self.present(&shown, on, name, seconds)
    }

    /// Notes the use of `scope` in `usage` at `seconds`. It gives `None` when `usage` gives no last use. Else it
    /// commits the record of the last use when the store holds no later one, and gives whether a record committed.
    fn note(&mut self, usage: &mut Usage, scope: &Granted, seconds: u64) -> Option<bool> {
        let last_use = usage.note(scope, at(seconds))?;
        let record = self
            .grants
            .record(&mut self.world.site.node.memory, &last_use, at(seconds));
        Some(match ready(record).map_err(refused).expect("a proposal") {
            Some(proposal) => matches!(self.world.commit(proposal), Outcome::Accepted(_)),
            None => false,
        })
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
    // The credential of the check ends first: 15 minutes after its issue.
    assert_eq!(scope.deadline(), time(31 + 900));
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
    let (access, _) = grantor.world.session();
    assert_eq!(grantor.list(&access, 45), core::slice::from_ref(&first));

    let (_, fresh) = grantor.world.session();
    let changed = grantor.issue(&fresh, &read, time(7200), 46);
    assert!(changed.revision > first.revision);
    let scope = grantor.check(API, "repo-x", "repo.read", 47).expect("a use");
    assert_eq!(scope.revision(), changed.revision);
    assert_eq!(grantor.list(&access, 47), [changed]);
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
    let before = grantor.issued(2, API, None, 30).expect("a credential");
    let id = grantor.agent.started.agent.clone();
    let rotated = grantor.world.rotate(&rotation(&id, 2, 3, 1, [2, 3]), 31);
    assert!(matches!(rotated, Ok(Outcome::Accepted(_))));
    let old = grantor.shown(&before, API);
    assert_eq!(grantor.present(&old, "repo-x", "repo.read", 32).err(), Some(Error::Key));
    // The old key cannot get a credential either.
    assert!(matches!(grantor.issued(2, API, None, 32), Err(Error::Credential(_))));
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

    let tenant = Forged {
        issuer: "other-agents",
        owner: alice(),
        revision: first.revision,
    };
    let tenant = grantor.forged(&tenant, API, 32);
    assert_eq!(
        grantor.present(&tenant, "repo-x", "repo.read", 32).err(),
        Some(Error::Issuer)
    );
    let substituted = Forged {
        issuer: AUTHORITY,
        owner: Id::new("acme", "bob").expect("an identifier"),
        revision: first.revision,
    };
    let substituted = grantor.forged(&substituted, API, 32);
    assert_eq!(
        grantor.present(&substituted, "repo-x", "repo.read", 32).err(),
        Some(Error::Owner)
    );

    let earlier = grantor.issued(2, API, None, 33).expect("a credential");
    let (_, fresh) = grantor.world.session();
    grantor.issue(&fresh, &read, time(7200), 34);
    let earlier = grantor.shown(&earlier, API);
    assert_eq!(
        grantor.present(&earlier, "repo-x", "repo.read", 35).err(),
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

/// A credential ends at the earlier of its lifetime and the grant deadline, so a refresh never extends the grant, and a
/// refresh at or after the deadline refuses. A lifetime past the most, or under one second, refuses.
#[test]
fn a_credential_ends_at_the_grant_deadline_and_a_refresh_past_it_refuses() {
    let mut grantor = Grantor::new();
    let (_, fresh) = grantor.world.session();
    grantor.issue(&fresh, &[permission("repo-x", "repo.read")], time(600), 30);
    let profile = grantor
        .grants
        .profile(grantor.issuer.key(), &audience(API))
        .expect("a profile");
    let end = |credential: &Released| {
        let verified = profile.verify(credential.as_bytes(), at(31), &mut budget());
        verified.expect("a credential").claims().expires
    };
    // The default lifetime of 15 minutes ends after the deadline.
    let first = grantor.issued(2, API, None, 30).expect("a credential");
    assert_eq!(end(&first), time(600));
    // The answer to the agent: its credential, its end, and the time to renew it, half its lifetime after 30.
    let answer = format!(
        r#"{{"credential":"{}","expires":{},"renew_at":{}}}"#,
        base64url(first.as_bytes()),
        time(600).as_secs(),
        time(315).as_secs()
    );
    assert_eq!(first.json(), answer.as_bytes());
    let short = grantor
        .issued(2, API, Some(Duration::from_secs(60)), 40)
        .expect("a credential");
    assert_eq!(end(&short), time(100));

    for lifetime in [LIFETIME_MAX + Duration::from_secs(1), Duration::from_millis(999)] {
        assert_eq!(grantor.issued(2, API, Some(lifetime), 41).err(), Some(Error::Lifetime));
    }
    // The reading at 598 can be at 599, and the reading at 599 can be at the deadline.
    let last = grantor.issued(2, API, None, 598).expect("a credential");
    assert_eq!(last.expires(), time(600));
    assert_eq!(grantor.issued(2, API, None, 599).err(), Some(Error::Expired));
}

/// A credential that names a grant or an agent that a revocation ended refuses, also before its own end.
#[test]
fn a_credential_of_a_revoked_grant_or_agent_refuses() {
    let mut grantor = Grantor::new();
    let (access, fresh) = grantor.world.session();
    let read = [permission("repo-x", "repo.read")];
    grantor.issue(&fresh, &read, time(3600), 30);
    let before = grantor.issued(2, API, None, 30).expect("a credential");
    let revocation = grantor.revocation(&access, 31).expect("a revocation");
    assert!(matches!(grantor.world.commit(revocation), Outcome::Accepted(_)));
    let shown = grantor.shown(&before, API);
    assert_eq!(
        grantor.present(&shown, "repo-x", "repo.read", 32).err(),
        Some(Error::NoGrant)
    );

    let (_, fresh) = grantor.world.session();
    grantor.issue(&fresh, &read, time(3600), 33);
    let before = grantor.issued(2, API, None, 33).expect("a credential");
    let agent = &grantor.agent;
    let revoked = grantor.world.revoke(&access, agent, 34);
    assert!(matches!(revoked, Ok(Outcome::Accepted(_))));
    let shown = grantor.shown(&before, API);
    assert_eq!(
        grantor.present(&shown, "repo-x", "repo.read", 35).err(),
        Some(Error::NotEnrolled)
    );
}

/// An issue needs a proof by the current key of the agent over the exact request. A proof by another key, or over a
/// request for another audience, refuses, so no party issues a credential in the name of an agent.
#[test]
fn an_issue_needs_a_proof_of_the_current_key_over_the_exact_request() {
    let mut grantor = Grantor::new();
    let (_, fresh) = grantor.world.session();
    grantor.issue(&fresh, &[permission("repo-x", "repo.read")], time(3600), 30);
    let (agent, api) = (grantor.agent.started.agent.clone(), audience(API));
    let nonce = [9; 32];
    let other = audience("other-api");
    let proofs = [
        (3, grant::statement(&authority(), &agent, &api, None), &api),
        (2, grant::statement(&authority(), &agent, &other, None), &other),
    ];
    for (holder, statement, proved) in proofs {
        let request = grant::Request {
            agent: &agent,
            audience: &api,
            lifetime: None,
            nonce: &nonce,
            proof: &prove(holder, &statement, proved, &nonce, 31),
        };
        assert!(matches!(grantor.request(request, 31), Err(Error::Credential(_))));
    }
}

/// Repeated checks in one window give at most one last use, and one commit records it: the page shows the start of
/// the window. A second host that notes the same use proposes nothing. A change of the grant drops the last use of
/// the earlier revision from the page. A full table notes no new revision until the next window.
#[test]
fn repeated_checks_within_one_granularity_give_at_most_one_last_use() {
    let mut grantor = Grantor::new();
    let (access, fresh) = grantor.world.session();
    let read = [permission("repo-x", "repo.read")];
    grantor.issue(&fresh, &read, time(3600), 30);
    let one = NonZeroUsize::MIN;
    let mut usage = Usage::new(Duration::from_secs(60), one).expect("a table");
    let last_use = |grantor: &mut Grantor, seconds| grantor.list(&access, seconds)[0].last_use;

    // START is a whole minute, so the checks from 31 to 59 are in the window that starts at START.
    let scope = grantor.check(API, "repo-x", "repo.read", 31).expect("a use");
    assert_eq!(grantor.note(&mut usage, &scope, 31), Some(true));
    assert_eq!(last_use(&mut grantor, 31), Some(time(0)));
    for seconds in [40, 59] {
        let scope = grantor.check(API, "repo-x", "repo.read", seconds).expect("a use");
        assert_eq!(grantor.note(&mut usage, &scope, seconds), None);
    }
    let mut other = Usage::default();
    assert_eq!(grantor.note(&mut other, &scope, 45), Some(false));

    let (_, fresh) = grantor.world.session();
    grantor.issue(&fresh, &read, time(3600), 50);
    assert_eq!(last_use(&mut grantor, 50), None);
    let scope = grantor.check(API, "repo-x", "repo.read", 55).expect("a use");
    assert_eq!(grantor.note(&mut usage, &scope, 55), None);
    let scope = grantor.check(API, "repo-x", "repo.read", 61).expect("a use");
    assert_eq!(grantor.note(&mut usage, &scope, 61), Some(true));
    assert_eq!(last_use(&mut grantor, 61), Some(time(60)));
}

/// A full page of the active-access page that ends at a grant leaves that grant to the next page, with its last use.
/// Thus each grant shows its last use once, also at the end of a page.
#[test]
fn a_page_that_ends_at_a_grant_gives_it_with_its_last_use_on_the_next_page() {
    let mut grantor = Grantor::new();
    let read = [permission("repo-x", "repo.read")];
    // 33 more agents of alice, enrolled from 24 to 56, each with a grant at 60.
    let agents: Vec<_> = (3..36)
        .map(|seed| (grantor.world.enrolled_at(seed, u64::from(seed) + 21), seed))
        .collect();
    let (access, fresh) = grantor.world.session();
    let mut agents: Vec<_> = agents
        .into_iter()
        .map(|(mut agent, seed)| {
            core::mem::swap(&mut grantor.agent, &mut agent);
            grantor.issue(&fresh, &read, time(3600), 60);
            core::mem::swap(&mut grantor.agent, &mut agent);
            (agent, seed)
        })
        .collect();
    let page = |grantor: &mut Grantor, after| {
        let list = grantor
            .grants
            .list(&mut grantor.world.site.node.memory, &access, after, at(70));
        ready(list).map_err(refused).expect("a page")
    };
    let order: Vec<_> = page(&mut grantor, None)
        .grants
        .into_iter()
        .map(|grant| grant.agent)
        .collect();
    assert_eq!(order.len(), 33);

    // Each grant in the order of the page has a last use, except the 32nd. The 31 pairs and the 32nd grant are 63
    // records, so the 64th record is the 33rd grant, and its last use is the 65th.
    let mut usage = Usage::default();
    for (index, agent) in order.iter().enumerate() {
        if index == 31 {
            continue;
        }
        let at_index = agents.iter().position(|(held, _)| held.started.agent == *agent);
        let (held, seed) = agents.swap_remove(at_index.expect("an agent of the page"));
        grantor.agent = held;
        grantor.holder = seed;
        let scope = grantor.check(API, "repo-x", "repo.read", 61).expect("a use");
        assert_eq!(grantor.note(&mut usage, &scope, 61), Some(true));
    }

    let first = page(&mut grantor, None);
    let used: Vec<_> = first.grants.iter().map(|grant| grant.last_use.is_some()).collect();
    assert_eq!(used.len(), 32);
    assert!(used[..31].iter().all(|used| *used) && !used[31]);
    let second = page(&mut grantor, first.next.as_ref());
    assert_eq!(second.grants.len(), 1);
    assert_eq!(
        (&second.grants[0].agent, second.grants[0].last_use),
        // The default window of 5 minutes that holds 61 starts at START.
        (&order[32], Some(time(0)))
    );
    assert_eq!(second.next, None);
}

#[path = "signature.rs"]
mod signature;
