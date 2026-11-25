//! The enrollment of an agent that its human owner approves in a browser: the agent asks with its own key, alice
//! approves with a fresh user verification of her passkey session, and the finish of the agent binds its key to an
//! agent identity that she owns.

use rsauthnz::account::{FRESH_MAX, Fresh};
use rsauthnz::agent::{
    ATTEMPTS_MAX, Agents, Checked, DeviceCode, ENROLLMENT_LIFETIME, Enrollment, Error, Failure, Finish, Identity,
    KEY_BYTES, Loopback, RedirectCode, Request, Started, Status, UserCode,
};
use rsauthnz::id::{Authority, Id};
use rsauthnz::limits::Limits;
use rsauthnz::recovery::Passkeys;
use rsauthnz::session::{Access, Check, Revoker};
use rsauthnz::store::driver::Plan;
use rsauthnz::transition::{OperationId, Outcome, Proposal};
use rsauthnz_conformance::suite::Subject as _;
use rscodec::base64::Profile::Url;
use rscrypto::auth::MlDsa65Ed25519;

use super::authenticator::{Get, Passkey};
use super::{HANDLE, ORIGIN, RP_ID, Site, alice, at, ready, wrong};

/// The site of alice with her passkey, and the agent enrollment of the site.
struct World {
    site: Site,
    passkey: Passkey,
    agents: Agents,
}

/// The proposal of a check of a user code, its plan, and its answer.
type Proposed<T> = (Proposal, Plan, Checked<T>);

/// An agent that asked for an enrollment: its public key, and the values of its request.
struct Agent {
    key: [u8; KEY_BYTES],
    started: Started,
    device: DeviceCode,
}

impl World {
    fn new() -> Self {
        let mut site = Site::new();
        let passkey = site.register(rsauthnz::crypto::Algorithm::Ed25519, -8, 1, 0);
        let authority: Id<Authority> = Id::new("acme", "agents").expect("an identifier");
        Self {
            site,
            passkey,
            agents: Agents::new(authority, Limits::default()),
        }
    }

    fn commit(&mut self, (proposal, plan): (Proposal, Plan)) -> Outcome {
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
        let key = key(seed);
        let (proposal, plan, started) = self
            .agents
            .enroll(&key, name, loopback, at(seconds), &mut self.site.random)
            .expect("a request");
        let device = DeviceCode::from_bytes(self.artifact((proposal, plan)));
        Agent { key, started, device }
    }

    /// The session of a passkey sign-in of alice at 11, checked at 12, and its fresh user verification.
    fn session(&mut self) -> (Access, Fresh) {
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
}

/// The public key of the composite profile from `seed`.
fn key(seed: u8) -> [u8; KEY_BYTES] {
    let (public, _) = MlDsa65Ed25519::generate_keypair(|out| {
        let _: () = out.fill(seed);
        Ok(())
    })
    .expect("a key pair");
    public.to_bytes()
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
        .enroll(&enrollment.key, &enrollment.name, None, at(20), &mut world.site.random)
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
        format!(r#"{{"agent":"{}","owner":"acme:alice"}}"#, agent.started.agent).into_bytes()
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
