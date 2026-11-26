//! The enrollment of an agent that its human owner approves in a browser: the agent asks with its own key, alice
//! approves with a fresh user verification of her passkey session, and the finish of the agent binds its key to an
//! agent identity that she owns. A hosted agent also gives the token of its workload, which names no owner. The agent
//! rotates its key with both keys, and only its owner revokes it.

use core::time::Duration;

use rsauthnz::account::{FRESH_MAX, Fresh};
use rsauthnz::agent::{
    ATTEMPTS_MAX, Agents, Binding, Bootstrap, Checked, DeviceCode, ENROLLMENT_LIFETIME, Enrollment, Error, Failure,
    Finish, Identity, KEY_BYTES, Loopback, Platform, RedirectCode, Request, Rotation, Started, Status, UserCode,
    Workload,
};
use rsauthnz::cbor::{self, Value};
use rsauthnz::crypto::Algorithm;
use rsauthnz::id::{Agent as AgentId, Authority, Id, Principal};
use rsauthnz::jose;
use rsauthnz::limits::Limits;
use rsauthnz::recovery::Passkeys;
use rsauthnz::session::{Access, Check, Revoker};
use rsauthnz::store::Kind;
use rsauthnz::store::driver::Plan;
use rsauthnz::transition::{OperationId, Outcome, Proposal};
use rsauthnz::trust::{self, Freshness, KeySet, Refresh};
use rsauthnz_conformance::suite::Subject as _;
use rscodec::base64::Profile::Url;
use rscrypto::EcdsaP256SecretKey;
use rscrypto::auth::{MlDsa65Ed25519, MlDsa65Ed25519SecretKey};

use super::authenticator::{Get, Passkey};
use super::session::BOB;
use super::{HANDLE, ORIGIN, RP_ID, START, Site, alice, at, ready, wrong};

/// The site of alice with her passkey, and the agent enrollment of the site.
pub(super) struct World {
    pub(super) site: Site,
    passkey: Passkey,
    agents: Agents,
}

/// The proposal of a check of a user code, its plan, and its answer.
type Proposed<T> = (Proposal, Plan, Checked<T>);

/// An agent that asked for an enrollment: its public key, and the values of its request.
pub(super) struct Agent {
    key: [u8; KEY_BYTES],
    pub(super) started: Started,
    device: DeviceCode,
}

impl World {
    pub(super) fn new() -> Self {
        let mut site = Site::new();
        let passkey = site.register(rsauthnz::crypto::Algorithm::Ed25519, -8, 1, 0);
        let authority: Id<Authority> = Id::new("acme", "agents").expect("an identifier");
        Self {
            site,
            passkey,
            agents: Agents::new(authority, Limits::default()),
        }
    }

    pub(super) fn commit(&mut self, (proposal, plan): (Proposal, Plan)) -> Outcome {
        self.site.node.commit(proposal, plan)
    }

    /// The artifact of the accepted commit of `proposal`.
    fn artifact(&mut self, proposal: (Proposal, Plan)) -> [u8; 32] {
        match self.commit(proposal) {
            Outcome::Accepted(receipt) => receipt.artifact().expect("an artifact").try_into().expect("32 bytes"),
            outcome => panic!("the commit gave {outcome:?}"),
        }
    }

    /// The request of an agent with the key of `seed` and the name `name` at `seconds`.
    fn request(&mut self, seed: u8, name: &str, loopback: Option<&Loopback>, seconds: u64) -> Agent {
        self.hosted(key(seed), name, loopback, None, seconds)
    }

    /// The request of an agent with the key `key`, the name `name`, and the verified workload `workload` at `seconds`.
    fn hosted(
        &mut self,
        key: [u8; KEY_BYTES],
        name: &str,
        loopback: Option<&Loopback>,
        workload: Option<&Workload>,
        seconds: u64,
    ) -> Agent {
        let (proposal, plan, started) = self
            .agents
            .enroll(&key, name, loopback, workload, at(seconds), &mut self.site.random)
            .expect("a request");
        let device = DeviceCode::from_bytes(self.artifact((proposal, plan)));
        Agent { key, started, device }
    }

    /// The session of a passkey sign-in of alice at 11, checked at 12, and its fresh user verification.
    pub(super) fn session(&mut self) -> (Access, Fresh) {
        let (access, fresh, _) = self.signed_in();
        (access, fresh)
    }

    /// The session of [`Self::session`], its fresh user verification, and the text of its identifier, which the cookie
    /// of the browser of alice holds.
    fn signed_in(&mut self) -> (Access, Fresh, Vec<u8>) {
        let options = self.site.options(at(10));
        let json = Get::new(&self.passkey, RP_ID, ORIGIN, options, HANDLE).json();
        let opened = self.site.opened(&json, at(11), None);
        let cookie = opened
            .session
            .identifier()
            .encode()
            .expect("an identifier")
            .as_bytes()
            .to_vec();
        let check = self
            .site
            .sessions
            .check(&mut self.site.node.memory, opened.session.identifier(), at(12));
        let Ok(Check::Active(access)) = ready(check) else {
            panic!("the session does not serve");
        };
        let fresh = Fresh::check(&access, FRESH_MAX, at(12)).expect("a fresh verification");
        (access, fresh, cookie)
    }

    /// The proposal of the check of `code` for the approval page of the human of `access` at `seconds`, and its answer.
    fn check(&mut self, access: &Access, code: &UserCode, seconds: u64) -> Result<Proposed<Request>, Error> {
        let request = self.agents.request(
            &mut self.site.node.memory,
            access,
            code,
            at(seconds),
            &mut self.site.random,
        );
        ready(request).map_err(refused)
    }

    /// The request of `code` as the approval page shows it to the human of `access` at `seconds`, after the commit of
    /// its check: `None` for a wrong code.
    fn show(&mut self, access: &Access, code: &UserCode, seconds: u64) -> Result<Option<Request>, Error> {
        let (proposal, plan, checked) = self.check(access, code, seconds)?;
        let outcome = self.commit((proposal, plan));
        Ok(checked.release(&outcome))
    }

    /// The approval proposal of the request of `code` with `fresh` at `seconds`, and its answer.
    fn approval(&mut self, fresh: &Fresh, code: &UserCode, seconds: u64) -> Result<Proposed<Option<Loopback>>, Error> {
        let approve = self.agents.approve(
            &mut self.site.node.memory,
            fresh,
            code,
            at(seconds),
            &mut self.site.random,
        );
        ready(approve).map_err(refused)
    }

    /// Commits the approval of the request of `agent` with `fresh` at `seconds`, and gives the outcome.
    fn approve(&mut self, agent: &Agent, fresh: &Fresh, seconds: u64) -> Outcome {
        let (proposal, plan, checked) = self.approval(fresh, &agent.started.code, seconds).expect("an approval");
        let outcome = self.commit((proposal, plan));
        if matches!(outcome, Outcome::Accepted(_)) {
            assert_eq!(checked.release(&outcome), Some(None));
        }
        outcome
    }

    /// The finish of `agent` at `seconds`, with the redirect code `redirect`.
    fn finish(&mut self, agent: &Agent, redirect: Option<&RedirectCode>, seconds: u64) -> Result<Status, Error> {
        let operation = OperationId::new(format!("finish-{seconds}").as_bytes()).expect("an operation identity");
        let finish = self.agents.finish(
            &mut self.site.node.memory,
            &agent.started.code,
            &agent.device,
            redirect,
            at(seconds),
            operation,
        );
        ready(finish).map_err(refused)
    }

    /// Commits the finish of `agent` at `seconds`, which must be ready.
    fn enroll(&mut self, agent: &Agent, redirect: Option<&RedirectCode>, seconds: u64) -> Outcome {
        let Status::Approved(proposal, plan) = self.finish(agent, redirect, seconds).expect("a finish") else {
            panic!("an approved request");
        };
        self.commit((proposal, plan))
    }

    fn identity(&mut self, agent: &Agent) -> Result<Identity, Error> {
        ready(self.agents.identity(&mut self.site.node.memory, &agent.started.agent)).map_err(refused)
    }

    /// An agent with the key of `seed` that alice enrolls: its request at 20, her approval at 22, its finish at 23.
    pub(super) fn enrolled(&mut self, seed: u8) -> Agent {
        let agent = self.request(seed, "build-agent", None, 20);
        let (_, fresh) = self.session();
        assert!(matches!(self.approve(&agent, &fresh, 22), Outcome::Accepted(_)));
        assert!(matches!(self.enroll(&agent, None, 23), Outcome::Accepted(_)));
        agent
    }

    /// Commits the rotation `rotation` at `seconds`.
    pub(super) fn rotate(&mut self, rotation: &Rotation, seconds: u64) -> Result<Outcome, Error> {
        let operation = OperationId::new(format!("rotate-{seconds}").as_bytes()).expect("an operation identity");
        let rotate = self
            .agents
            .rotate(&mut self.site.node.memory, rotation, at(seconds), operation);
        let proposal = ready(rotate).map_err(refused)?;
        Ok(self.commit(proposal))
    }

    /// Commits the revocation of `agent` by the human of `access` at `seconds`.
    pub(super) fn revoke(&mut self, access: &Access, agent: &Agent, seconds: u64) -> Result<Outcome, Error> {
        let revoke = self.agents.revoke(
            &mut self.site.node.memory,
            access,
            &agent.started.agent,
            at(seconds),
            &mut self.site.random,
        );
        let proposal = ready(revoke).map_err(refused)?;
        Ok(self.commit(proposal))
    }

    /// A session of bob, who has his own passkey, at 41, checked at 42.
    pub(super) fn bob(&mut self) -> (Access, Fresh) {
        let passkey = self.site.register_bob();
        let opened = self.site.session_of(&passkey, BOB, 41, None);
        let access = self.site.active(opened.session.identifier(), at(42));
        let fresh = Fresh::check(&access, FRESH_MAX, at(42)).expect("a fresh verification");
        (access, fresh)
    }

    /// The actor of the audit record of the operation `operation`.
    fn actor(&mut self, operation: &str) -> Principal {
        let key = Kind::Audit.key(operation.as_bytes()).expect("a key");
        let record = self.site.node.read(&key).expect("an audit record");
        let value = cbor::decode(&record.data, Limits::default()).expect("an audit form");
        let Value::Array(items) = &value else {
            panic!("an audit form");
        };
        Principal::from_cbor(&items[1]).expect("an actor")
    }
}

/// The composite key pair from `seed`.
fn keypair(seed: u8) -> ([u8; KEY_BYTES], MlDsa65Ed25519SecretKey) {
    let (public, secret) = MlDsa65Ed25519::generate_keypair(|out| {
        let _: () = out.fill(seed);
        Ok(())
    })
    .expect("a key pair");
    (public.to_bytes(), secret)
}

/// The public key of the composite profile from `seed`.
fn key(seed: u8) -> [u8; KEY_BYTES] {
    keypair(seed).0
}

/// The rotation of `agent` from the key of `old` to the key of `new`, whose statement of `generation` the keys of
/// `signers` sign: the current key first, then the new key.
pub(super) fn rotation(agent: &Id<AgentId>, old: u8, new: u8, generation: u64, signers: [u8; 2]) -> Rotation {
    let statement = Rotation::statement(agent, &key(old), &key(new), generation);
    let [old_signature, new_signature] = signers.map(|seed| {
        let signature = keypair(seed)
            .1
            .sign_deterministic(&statement, &[])
            .expect("a signature");
        signature.as_bytes().to_vec()
    });
    Rotation {
        agent: agent.clone(),
        key: Box::new(key(new)),
        old_signature,
        new_signature,
    }
}

/// The base64url text of `bytes`.
fn base64url(bytes: &[u8]) -> String {
    let mut out = vec![0; Url.encoded_len(bytes.len()).expect("a length")];
    let text = Url.encode(bytes, &mut out).expect("a buffer of the length");
    String::from_utf8(text.to_vec()).expect("ASCII")
}

/// The refusal of a failure of the memory binding, which reads with no failure.
fn refused(failure: Failure<rsauthnz_conformance::memory::Error>) -> Error {
    match failure {
        Failure::Refused(error) => error,
        Failure::Store(error) => panic!("the read failed: {error:?}"),
    }
}

#[test]
fn an_agent_that_alice_approves_gets_an_identity_that_she_owns() {
    let mut world = World::new();
    let agent = world.request(2, "build-agent", None, 20);
    let (access, fresh) = world.session();

    let shown = world.show(&access, &agent.started.code, 21).expect("a request");
    let shown = shown.expect("the code is right");
    assert_eq!(shown.name, "build-agent");
    assert_eq!(shown.fingerprint, rscrypto::Sha256::digest(&agent.key));
    assert_eq!((shown.loopback, shown.approved), (None, false));
    assert!(matches!(world.finish(&agent, None, 21), Ok(Status::Waiting)));

    assert!(matches!(world.approve(&agent, &fresh, 22), Outcome::Accepted(_)));
    assert!(matches!(world.enroll(&agent, None, 23), Outcome::Accepted(_)));
    let identity = world.identity(&agent).expect("the identity");
    assert_eq!((&identity.owner, &identity.agent), (&alice(), &agent.started.agent));
    assert_eq!(*identity.key, agent.key);
    // The finish consumed the request.
    assert_eq!(world.finish(&agent, None, 24).err(), Some(Error::Request));
}

/// The agent sends its JSON bodies and reads the JSON answers. A member that names an owner names none: the owner comes
/// only from the approval. No answer to the agent holds the session of alice or a byte of its cookie.
#[test]
fn the_messages_of_an_agent_name_no_owner_it_chose_and_hold_no_session_of_its_owner() {
    let mut world = World::new();
    let body = format!(
        r#"{{"name":"mallory","key":"{}","owner":"acme:mallory"}}"#,
        base64url(&key(2))
    );
    let enrollment = Enrollment::parse(body.as_bytes()).expect("a body");
    let (proposal, plan, started) = world
        .agents
        .enroll(
            &enrollment.key,
            &enrollment.name,
            None,
            None,
            at(20),
            &mut world.site.random,
        )
        .expect("a request");
    let device = DeviceCode::from_bytes(world.artifact((proposal, plan)));
    let answer = started.json(&device, "https://app.example/agent");
    let text = core::str::from_utf8(&answer).expect("UTF-8");
    let code = started.code.text();
    assert!(text.contains(&format!(
        r#""verification_uri_complete":"https://app.example/agent?code={code}""#
    )));
    assert!(text.contains(&format!(r#""device_code":"{}""#, base64url(device.as_bytes()))));

    let (access, fresh, cookie) = world.signed_in();
    let agent = Agent {
        key: *enrollment.key,
        started,
        device,
    };
    assert!(matches!(world.approve(&agent, &fresh, 21), Outcome::Accepted(_)));
    let finish = format!(
        r#"{{"user_code":"{code}","device_code":"{}"}}"#,
        base64url(agent.device.as_bytes())
    );
    let finish = Finish::parse(finish.as_bytes()).expect("a body");
    assert_eq!(finish.code, agent.started.code);
    assert!(matches!(
        world.enroll(&agent, finish.redirect.as_ref(), 22),
        Outcome::Accepted(_)
    ));
    let identity = world.identity(&agent).expect("the identity");
    assert_eq!(identity.owner, alice());
    let enrolled = identity.json();
    assert_eq!(
        enrolled,
        format!(
            r#"{{"agent":"{}","owner":"acme:alice","generation":1}}"#,
            agent.started.agent
        )
        .into_bytes()
    );

    let session = access.session().key().as_bytes();
    for message in [answer.as_slice(), &enrolled] {
        for secret in [cookie.as_slice(), session] {
            assert!(!message.windows(secret.len()).any(|window| window == secret));
        }
    }
}

/// An approval reads the session of its verification: after alice signs out, the approval of that session refuses.
#[test]
fn an_approval_from_a_session_that_ended_refuses() {
    let mut world = World::new();
    let agent = world.request(2, "build-agent", None, 20);
    let (access, fresh) = world.session();
    let (proposal, plan, _) = world.approval(&fresh, &agent.started.code, 21).expect("an approval");
    let sign_out = world
        .site
        .sessions
        .revoke(
            access.session(),
            Revoker::Own(&access),
            &[],
            at(21),
            &mut world.site.random,
        )
        .expect("a sign-out");
    assert!(matches!(world.commit(sign_out), Outcome::Accepted(_)));

    assert!(matches!(world.commit((proposal, plan)), Outcome::Conflict));
    assert!(matches!(world.finish(&agent, None, 22), Ok(Status::Waiting)));
}

#[test]
fn two_approvals_of_one_request_commit_once() {
    let mut world = World::new();
    let agent = world.request(2, "build-agent", None, 20);
    let (_, fresh) = world.session();
    let (first, first_plan, _) = world.approval(&fresh, &agent.started.code, 21).expect("an approval");
    let (second, second_plan, _) = world.approval(&fresh, &agent.started.code, 21).expect("an approval");
    assert!(matches!(world.commit((first, first_plan)), Outcome::Accepted(_)));
    assert!(matches!(world.commit((second, second_plan)), Outcome::Conflict));
    assert_eq!(
        world.approval(&fresh, &agent.started.code, 22).err(),
        Some(Error::Approved)
    );
}

/// Each check of a user code is a commit at the version of its request, and a wrong check counts, also in an approval.
/// So a right check that read the version before a count conflicts and shows nothing: checks at the same time get one
/// answer for each count. After `ATTEMPTS_MAX` wrong checks, the request is locked: the right code refuses too, and the
/// agent makes a new request.
#[test]
fn wrong_user_codes_past_the_bound_lock_the_request() {
    let mut world = World::new();
    let agent = world.request(2, "build-agent", None, 20);
    let (access, fresh) = world.session();
    let wrong = wrong(&agent.started.code);
    for attempt in 1..=ATTEMPTS_MAX {
        let (right, plan, shown) = world.check(&access, &agent.started.code, 21).expect("a check");
        if attempt % 2 == 0 {
            let (proposal, plan, approved) = world.approval(&fresh, &wrong, 21).expect("a check");
            let outcome = world.commit((proposal, plan));
            assert!(matches!(outcome, Outcome::Accepted(_)));
            assert_eq!(approved.release(&outcome), None);
        } else {
            assert_eq!(world.show(&access, &wrong, 21), Ok(None));
        }
        let outcome = world.commit((right, plan));
        assert!(matches!(outcome, Outcome::Conflict));
        assert_eq!(shown.release(&outcome), None);
    }
    assert_eq!(world.show(&access, &agent.started.code, 22).err(), Some(Error::Locked));
    assert_eq!(
        world.approval(&fresh, &agent.started.code, 22).err(),
        Some(Error::Locked)
    );
    assert_eq!(world.finish(&agent, None, 22).err(), Some(Error::Locked));
}

#[test]
fn an_ended_request_refuses_its_check_its_approval_and_its_finish() {
    let mut world = World::new();
    let late = ENROLLMENT_LIFETIME.as_secs();
    let agent = world.request(2, "build-agent", None, 20);
    let (access, fresh) = world.session();
    assert_eq!(
        world.show(&access, &agent.started.code, 20 + late).err(),
        Some(Error::Expired)
    );
    assert_eq!(
        world.approval(&fresh, &agent.started.code, 20 + late).err(),
        Some(Error::Expired)
    );
    assert_eq!(world.finish(&agent, None, 20 + late).err(), Some(Error::Expired));
}

/// A loopback request finishes only with the redirect code that the receipt of its approval gives to the browser.
#[test]
fn a_loopback_request_finishes_only_with_the_redirect_code_of_its_approval() {
    let mut world = World::new();
    let loopback = Loopback::parse("http://127.0.0.1:49152/agent").expect("a loopback address");
    let agent = world.request(2, "desktop-agent", Some(&loopback), 20);
    let (access, fresh) = world.session();
    let shown = world.show(&access, &agent.started.code, 21).expect("a request");
    assert_eq!(shown.expect("the code is right").loopback.as_ref(), Some(&loopback));
    let (proposal, plan, checked) = world.approval(&fresh, &agent.started.code, 21).expect("an approval");
    let outcome = world.commit((proposal, plan));
    let Outcome::Accepted(receipt) = &outcome else {
        panic!("the approval gave {outcome:?}");
    };
    let redirect = RedirectCode::from_bytes(receipt.artifact().expect("an artifact").try_into().expect("32 bytes"));
    let Some(Some(target)) = checked.release(&outcome) else {
        panic!("a loopback approval");
    };
    let address = target.redirect(&redirect);
    assert!(address.starts_with("http://127.0.0.1:49152/agent?code="));

    // The device code alone, or another redirect code, finishes nothing.
    assert_eq!(world.finish(&agent, None, 22).err(), Some(Error::Redirect));
    let other = RedirectCode::from_bytes([7; 32]);
    assert_eq!(world.finish(&agent, Some(&other), 22).err(), Some(Error::Redirect));
    assert_eq!(world.identity(&agent).err(), Some(Error::NotEnrolled));

    assert!(matches!(
        world.enroll(&agent, Some(&redirect), 22),
        Outcome::Accepted(_)
    ));
    assert_eq!(world.identity(&agent).expect("the identity").owner, alice());
}

/// A redirect goes only to an address of the loopback interface of this host, so no approval sends its code to
/// another host.
#[test]
fn a_loopback_address_is_only_a_loopback_ip_literal_with_a_port_and_a_path() {
    for valid in [
        "http://127.0.0.1:1/",
        "http://[::1]:65535/cb",
        "http://127.0.0.1:8080/a/b-c_d.e~f",
    ] {
        assert!(Loopback::parse(valid).is_ok(), "{valid}");
    }
    for invalid in [
        "http://localhost:8080/cb",
        "https://127.0.0.1:8080/cb",
        "http://127.0.0.1/cb",
        "http://127.0.0.1:0/cb",
        "http://127.0.0.1:65536/cb",
        "http://127.0.0.1:08080/cb",
        "http://127.0.0.1:8080",
        "http://127.0.0.1:8080/cb?next=https://attacker.example",
        "http://127.0.0.1:8080/cb#x",
        "http://127.0.0.1:8080@attacker.example/cb",
        "http://127.0.0.1.attacker.example:8080/cb",
        "http://[::1]:8080/%2e%2e",
    ] {
        assert_eq!(Loopback::parse(invalid), Err(Error::Loopback), "{invalid}");
    }
}

/// An agent identity is not an anchor: a restore from a snapshot before an enrollment ends each pending request and
/// loses the identity, and a new enrollment then commits.
#[test]
fn a_restore_ends_pending_requests_and_loses_a_later_identity() {
    let mut world = World::new();
    let pending = world.request(2, "pending-agent", None, 20);
    let enrolled = world.request(3, "build-agent", None, 20);
    let snapshot = world.site.node.memory.snapshot();
    let (_, fresh) = world.session();
    assert!(matches!(world.approve(&enrolled, &fresh, 21), Outcome::Accepted(_)));
    assert!(matches!(world.enroll(&enrolled, None, 22), Outcome::Accepted(_)));

    world.site.node.memory.restore(&snapshot);
    world.site.node.driver.restore(at(0)).expect("a restore");
    world.site.node.run();

    assert_eq!(world.finish(&pending, None, 30).err(), Some(Error::Request));
    assert_eq!(world.identity(&enrolled).err(), Some(Error::NotEnrolled));
    let again = world.request(3, "build-agent", None, 30);
    let (_, fresh) = world.session();
    assert!(matches!(world.approve(&again, &fresh, 31), Outcome::Accepted(_)));
    assert!(matches!(world.enroll(&again, None, 32), Outcome::Accepted(_)));
    assert_eq!(*world.identity(&again).expect("the identity").key, enrolled.key);
}

/// A recovery of the account of the owner ends each approval before it: a finish that the agent proposed before the
/// recovery conflicts, and a new finish refuses.
#[test]
fn a_recovery_of_the_owner_between_the_approval_and_the_finish_ends_the_approval() {
    let mut world = World::new();
    let agent = world.request(2, "build-agent", None, 20);
    let (_, fresh) = world.session();
    let code = world.site.new_code(&fresh, 13);
    assert!(matches!(world.approve(&agent, &fresh, 21), Outcome::Accepted(_)));
    let Status::Approved(finish, plan) = world.finish(&agent, None, 22).expect("a finish") else {
        panic!("an approved request");
    };

    let challenge = world
        .site
        .recovery_challenge(&alice(), &code, 25)
        .expect("a recovery challenge");
    let replacement = Passkey::new(rsauthnz::crypto::Algorithm::Ed25519, -8, 9);
    let attempt = world
        .site
        .attempt(&replacement, challenge, 26, Passkeys::Keep)
        .expect("a recovery attempt");
    let (recovery, recovery_plan, _) = attempt.propose(&[]).expect("a recovery proposal");
    assert!(matches!(
        world.site.node.commit(recovery, recovery_plan),
        Outcome::Accepted(_)
    ));

    assert!(matches!(world.commit((finish, plan)), Outcome::Conflict));
    assert_eq!(world.finish(&agent, None, 27).err(), Some(Error::Request));
    assert_eq!(world.identity(&agent).err(), Some(Error::NotEnrolled));
}

/// The trust domain of the hosted agents, and the audience of their tokens: the enrollment of the authority.
const DOMAIN: &str = "spiffe://prod.example";
const AUDIENCE: &str = "https://app.example/agent";

/// A key set ends 10 minutes after the start of its fetch, and a refresh is due after 5 minutes.
const FRESHNESS: Freshness = Freshness {
    max_age: Duration::from_secs(600),
    uncertainty: Duration::from_secs(1),
    propagation: Duration::from_secs(660),
    retry: Duration::from_secs(60),
};

/// A SPIFFE trust domain of the tests: the ES256 key of its JWT bundle, and the key ID of that key.
struct Domain {
    secret: EcdsaP256SecretKey,
    kid: String,
}

impl Domain {
    fn new(seed: u8) -> Self {
        Self {
            secret: EcdsaP256SecretKey::from_bytes([seed; 32]).expect("a scalar"),
            kid: format!("jwt-{seed}"),
        }
    }

    /// The JWT bundle of the trust domain, as its bundle endpoint serves it.
    fn bundle(&self) -> String {
        let point = self.secret.public_key().to_sec1_bytes();
        let (x, y) = (base64url(&point[1..33]), base64url(&point[33..]));
        format!(
            r#"{{"keys":[{{"use":"jwt-svid","kty":"EC","crv":"P-256","kid":"{}","x":"{x}","y":"{y}"}}],"spiffe_sequence":1}}"#,
            self.kid
        )
    }

    /// The JWT-SVID of `sub` for the audience `aud`, which ends `ends` seconds past [`START`], with the claims `more`.
    fn svid(&self, sub: &str, aud: &str, ends: u64, more: &str) -> String {
        let exp = START.as_secs() + ends;
        let claims = format!(r#"{{"sub":"{sub}","aud":["{aud}"],"exp":{exp}{more}}}"#);
        let input = jose::signing_input(Algorithm::Es256, Some(&self.kid), Some("JWT"), claims.as_bytes())
            .expect("a signing input");
        let signature = self.secret.try_sign(input.as_bytes()).expect("a signature");
        jose::compact(&input, &signature.to_bytes())
    }
}

/// The key set of the trust domain [`DOMAIN`], with no set.
fn keys() -> KeySet {
    let profile =
        jose::Profile::new(Algorithm::Es256, jose::Kind::Svid, DOMAIN, AUDIENCE, Limits::default()).expect("a profile");
    KeySet::new(profile, FRESHNESS).expect("a key set")
}

/// Installs `bundle` in `keys` at `seconds`, through the one fetch that the refresh gives.
fn install(keys: &mut KeySet, bundle: &str, seconds: u64) -> Result<(), trust::Error> {
    let Refresh::Fetch(ticket) = keys.refresh(at(seconds)).expect("a refresh") else {
        panic!("a refresh is due");
    };
    keys.install(ticket, bundle.as_bytes(), at(seconds))
}

/// The platform of [`DOMAIN`] with `binding`, whose key set the fetch at 0 installs from the bundle of `domain`.
fn platform(domain: &Domain, binding: Binding) -> Platform {
    let mut keys = keys();
    install(&mut keys, &domain.bundle(), 0).expect("an install");
    Platform { keys, binding }
}

/// A hosted agent gives a JWT-SVID of the configured trust domain for its own key. The request shows the workload to
/// alice, and its identity keeps it. A claim that names a person gives no owner: the request waits for an approval, and
/// the owner is the human of the approval.
#[test]
fn a_jwt_svid_of_the_configured_trust_domain_starts_an_enrollment_that_alice_approves() {
    let mut world = World::new();
    let domain = Domain::new(5);
    let platform = platform(&domain, Binding::Key);
    let (agent_key, workload) = (key(2), "spiffe://prod.example/ns/ci/sa/builder");
    let aud = Binding::Key.audience(AUDIENCE, &agent_key);
    let owner = r#","email":"mallory@example.com","owner":"acme:mallory""#;
    let token = domain.svid(workload, &aud, 300, owner);
    let body = format!(
        r#"{{"name":"builder","key":"{}","token":"{token}"}}"#,
        base64url(&agent_key)
    );
    let enrollment = Enrollment::parse(body.as_bytes()).expect("a body");
    let Some(Bootstrap::Token(token)) = &enrollment.bootstrap else {
        panic!("the body has a token");
    };
    assert!(!format!("{enrollment:?}").contains(token.as_str()));
    let verified = platform.verify(token, &enrollment.key, at(20)).expect("a workload");
    assert_eq!((verified.issuer(), verified.subject()), (DOMAIN, workload));

    let agent = world.hosted(*enrollment.key, &enrollment.name, None, Some(&verified), 20);
    assert!(matches!(world.finish(&agent, None, 21), Ok(Status::Waiting)));
    let (access, fresh) = world.session();
    let shown = world.show(&access, &agent.started.code, 21).expect("a request");
    assert_eq!(shown.expect("the code is right").workload.as_ref(), Some(&verified));
    assert!(matches!(world.approve(&agent, &fresh, 22), Outcome::Accepted(_)));
    assert!(matches!(world.enroll(&agent, None, 23), Outcome::Accepted(_)));
    let identity = world.identity(&agent).expect("the identity");
    assert_eq!(identity.owner, alice());
    assert_eq!(identity.workload, Some(verified));
}

/// A token of another trust domain refuses: one signed by another bundle key, and one that a key of the configured
/// bundle signs for a workload of another trust domain. A token past its end refuses, and so does a token for another
/// agent key. A bearer platform takes its fixed audience for each key.
#[test]
fn a_token_of_another_trust_domain_for_another_key_or_past_its_end_refuses() {
    let domain = Domain::new(5);
    let platform = platform(&domain, Binding::Key);
    let (agent_key, workload) = (key(2), "spiffe://prod.example/ns/ci/sa/builder");
    let aud = Binding::Key.audience(AUDIENCE, &agent_key);
    let verify = |token: &str, key: &[u8; KEY_BYTES], seconds: u64| platform.verify(token, key, at(seconds)).err();
    assert_eq!(verify(&domain.svid(workload, &aud, 300, ""), &agent_key, 20), None);

    let other = Domain::new(6).svid("spiffe://other.example/ns/ci/sa/builder", &aud, 300, "");
    assert_eq!(verify(&other, &agent_key, 20), Some(Error::Token(jose::Error::Key)));
    let crossed = domain.svid("spiffe://other.example/ns/ci/sa/builder", &aud, 300, "");
    assert_eq!(
        verify(&crossed, &agent_key, 20),
        Some(Error::Token(jose::Error::Issuer))
    );
    let ended = domain.svid(workload, &aud, 30, "");
    assert_eq!(verify(&ended, &agent_key, 40), Some(Error::Token(jose::Error::Expired)));
    let stolen = domain.svid(workload, &aud, 300, "");
    assert_eq!(verify(&stolen, &key(3), 20), Some(Error::Token(jose::Error::Audience)));

    let bearer = self::platform(&domain, Binding::Bearer);
    let fixed = domain.svid(workload, AUDIENCE, 300, "");
    for agent_key in [key(2), key(3)] {
        bearer.verify(&fixed, &agent_key, at(20)).unwrap();
    }
    assert_eq!(
        bearer.verify(&stolen, &agent_key, at(20)).err(),
        Some(Error::Token(jose::Error::Audience))
    );
}

/// A platform with no installed key set refuses, and so does one whose set passed its maximum age. A refresh that gives
/// no valid set, or no key of the algorithm, keeps the installed set until its end.
#[test]
fn a_missing_or_stale_key_set_refuses() {
    let domain = Domain::new(5);
    let (agent_key, workload) = (key(2), "spiffe://prod.example/ns/ci/sa/builder");
    let token = domain.svid(workload, &Binding::Key.audience(AUDIENCE, &agent_key), 900, "");
    let empty = Platform {
        keys: keys(),
        binding: Binding::Key,
    };
    assert_eq!(
        empty.verify(&token, &agent_key, at(20)).err(),
        Some(Error::Trust(trust::Error::Missing))
    );

    let mut platform = platform(&domain, Binding::Key);
    let x509 = domain.bundle().replace("jwt-svid", "x509-svid");
    assert_eq!(
        install(&mut platform.keys, "{\"keys\":", 300),
        Err(trust::Error::KeySet(jose::Error::Malformed))
    );
    assert_eq!(platform.keys.refresh(at(330)), Ok(Refresh::Pending));
    assert_eq!(
        install(&mut platform.keys, &x509, 360),
        Err(trust::Error::KeySet(jose::Error::Key))
    );
    // The fetch started at the latest time of its reading, 1, so the set ends at 601. A reading at 600 can be at 601.
    platform.verify(&token, &agent_key, at(599)).unwrap();
    assert_eq!(
        platform.verify(&token, &agent_key, at(600)).err(),
        Some(Error::Trust(trust::Error::Stale))
    );
}

/// A rotation needs a signature by the current key and by the new key over the statement of the current generation.
/// After it, the old key refuses, and a statement of an earlier generation never matches again, also after a rotation
/// back to the old key. A member of the body that names another owner changes no owner.
#[test]
fn a_rotation_needs_the_current_key_and_then_the_old_key_refuses() {
    let mut world = World::new();
    let agent = world.enrolled(2);
    let id = agent.started.agent.clone();
    assert_eq!(world.identity(&agent).expect("the identity").generation, 1);

    for signers in [[3, 3], [4, 3], [3, 2]] {
        let forged = rotation(&id, 2, 3, 1, signers);
        assert_eq!(world.rotate(&forged, 30).err(), Some(Error::Signature), "{signers:?}");
    }
    assert_eq!(
        world.rotate(&rotation(&id, 2, 3, 2, [2, 3]), 30).err(),
        Some(Error::Signature)
    );

    let first = rotation(&id, 2, 3, 1, [2, 3]);
    let body = format!(
        r#"{{"agent":"{id}","key":"{}","old_signature":"{}","new_signature":"{}","owner":"acme:bob"}}"#,
        base64url(&*first.key),
        base64url(&first.old_signature),
        base64url(&first.new_signature),
    );
    let parsed = Rotation::parse(body.as_bytes()).expect("a body");
    assert!(matches!(world.rotate(&parsed, 31), Ok(Outcome::Accepted(_))));
    let rotated = world.identity(&agent).expect("the identity");
    assert_eq!((*rotated.key, rotated.generation), (key(3), 2));
    assert_eq!((&rotated.owner, rotated.name.as_str()), (&alice(), "build-agent"));
    // A lost response: the same body again tells that the rotation committed.
    assert_eq!(world.rotate(&first, 32).err(), Some(Error::Rotated));
    // The old key alone no longer rotates.
    assert_eq!(
        world.rotate(&rotation(&id, 2, 4, 2, [2, 4]), 33).err(),
        Some(Error::Signature)
    );

    assert!(matches!(
        world.rotate(&rotation(&id, 3, 2, 2, [3, 2]), 34),
        Ok(Outcome::Accepted(_))
    ));
    assert_eq!(world.rotate(&first, 35).err(), Some(Error::Signature));
    assert_eq!(world.identity(&agent).expect("the identity").generation, 3);
}

/// Only the owner revokes an agent: a revocation by another human refuses as if the agent did not exist. After the
/// revocation, the identity, a rotation, and a second revocation refuse, and a restore from a snapshot before the
/// revocation or before a rotation gives neither the identity nor the earlier key again.
#[test]
fn after_its_owner_revokes_an_agent_its_key_refuses_and_another_human_cannot_revoke_it() {
    let mut world = World::new();
    let agent = world.enrolled(2);
    let before = world.site.node.memory.snapshot();
    let (bob, _) = world.bob();
    assert_eq!(world.revoke(&bob, &agent, 43).err(), Some(Error::NotEnrolled));
    world.identity(&agent).unwrap();

    let (alice, _) = world.session();
    assert!(matches!(world.revoke(&alice, &agent, 44), Ok(Outcome::Accepted(_))));
    assert_eq!(world.identity(&agent).err(), Some(Error::NotEnrolled));
    let id = agent.started.agent.clone();
    assert_eq!(
        world.rotate(&rotation(&id, 2, 3, 1, [2, 3]), 45).err(),
        Some(Error::NotEnrolled)
    );
    assert_eq!(world.revoke(&alice, &agent, 45).err(), Some(Error::NotEnrolled));

    world.site.node.memory.restore(&before);
    world.site.node.driver.restore(at(0)).expect("a restore");
    world.site.node.run();
    assert_eq!(world.identity(&agent).err(), Some(Error::NotEnrolled));

    let rotated = world.request(5, "deploy-agent", None, 50);
    let (_, fresh) = world.session();
    assert!(matches!(world.approve(&rotated, &fresh, 52), Outcome::Accepted(_)));
    assert!(matches!(world.enroll(&rotated, None, 53), Outcome::Accepted(_)));
    let before = world.site.node.memory.snapshot();
    let id = rotated.started.agent.clone();
    assert!(matches!(
        world.rotate(&rotation(&id, 5, 6, 1, [5, 6]), 54),
        Ok(Outcome::Accepted(_))
    ));
    world.site.node.memory.restore(&before);
    world.site.node.driver.restore(at(0)).expect("a restore");
    world.site.node.run();
    assert_eq!(world.identity(&rotated).err(), Some(Error::NotEnrolled));
}

/// No operation changes the owner of an identity. A new owner comes from a revocation and a new enrollment, which gives
/// a new agent identifier, and the audit of each earlier commit keeps the earlier owner.
#[test]
fn a_new_owner_comes_only_from_a_new_enrollment_and_the_audit_keeps_the_earlier_owner() {
    let mut world = World::new();
    let first = world.enrolled(2);
    let (alice, _) = world.session();
    assert!(matches!(world.revoke(&alice, &first, 30), Ok(Outcome::Accepted(_))));

    let (_, bob) = world.bob();
    let again = world.request(2, "build-agent", None, 43);
    assert!(matches!(world.approve(&again, &bob, 44), Outcome::Accepted(_)));
    assert!(matches!(world.enroll(&again, None, 45), Outcome::Accepted(_)));
    let identity = world.identity(&again).expect("the identity");
    assert_ne!(identity.agent, first.started.agent);
    assert_eq!(identity.owner, Id::new("acme", "bob").expect("an identifier"));
    assert_eq!(world.identity(&first).err(), Some(Error::NotEnrolled));

    assert_eq!(world.actor("finish-23"), Principal::Human(super::alice()));
    assert_eq!(world.actor("finish-45"), Principal::Human(identity.owner));
}
