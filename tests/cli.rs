//! The contracts of a headless CLI on later calls: each call proves the possession of the key of the CLI over a one-use
//! challenge of its binding and over its own request, so a call with no proof, a proof for another request, and a
//! replayed or restored proof refuse. The next call uses the challenge that the commit of a call wrote. A CLI whose
//! bootstrap response was lost reads its credential with its key alone. The key of the CLI stays in custody: in key
//! files, and in the login keychain on macOS.

#![cfg(all(feature = "native-custody", any(target_os = "linux", target_os = "macos", windows)))]

use core::pin::pin;
use core::task::{Context, Poll, Waker};
use core::time::Duration;
use std::assert_matches;
use std::path::PathBuf;

use rsauthnz::cbor::Value;
use rsauthnz::cli::{self, Call, Challenge};
use rsauthnz::credential::{self, Serial};
use rsauthnz::crypto::Algorithm;
use rsauthnz::custody::{Custody, FileCustody, Handle, Isolation, KeyId};
use rsauthnz::id::Id;
use rsauthnz::limits::Limits;
use rsauthnz::local::{self, Admission, Admitted, Authority, Bootstrap, Error, Failure, HostGrant, Offer, Unlink};
use rsauthnz::store::driver::{Answer, Driver, Plan};
use rsauthnz::store::{self, Kind, Profile, Store};
use rsauthnz::time::{Reading, ReadingSource};
use rsauthnz::transition::{self, Change, OperationId, Outcome, Proposal};
use rsauthnz_conformance::memory::{Memory, Schedule, Snapshot};
use rsauthnz_conformance::suite::{self, Fault, Subject as _};
use rscrypto::ChaCha20Rng;

/// The time of the first call.
const START: Duration = Duration::from_secs(1_800_000_000);

/// The reading at `after` past [`START`], with an uncertainty of one second.
fn at(after: Duration) -> Reading {
    Reading::new(START + after, Some(Duration::from_secs(1)), ReadingSource::Caller)
}

fn now() -> Reading {
    at(Duration::ZERO)
}

/// The output of `future`. The futures of the memory binding are ready at their first poll.
fn ready<F: Future>(future: F) -> F::Output {
    match pin!(future).poll(&mut Context::from_waker(Waker::noop())) {
        Poll::Ready(output) => output,
        Poll::Pending => panic!("the memory binding does no I/O"),
    }
}

fn op(name: &str) -> OperationId {
    OperationId::new(name.as_bytes()).unwrap()
}

/// The call `name` over `challenge` with the request `request`.
fn call(challenge: Challenge, name: &str, request: &str) -> Call {
    Call::new(challenge, op(name), &Value::Text(request), Limits::default()).unwrap()
}

/// The public key of the CLI key `key`, which the CLI submits with its bootstrap value.
fn holder(key: &Handle) -> [u8; 1984] {
    key.public_key().as_slice().try_into().unwrap()
}

/// A directory of key files of one test, which it removes when it drops.
struct Files {
    dir: PathBuf,
    custody: FileCustody,
}

impl Files {
    fn new(name: &str) -> Self {
        let dir = std::env::temp_dir().join(format!("rsauthnz-cli-{}-{name}", std::process::id()));
        std::fs::create_dir(&dir).unwrap();
        let custody = FileCustody::open(&dir, Isolation::User).unwrap();
        Self { dir, custody }
    }
}

impl Drop for Files {
    fn drop(&mut self) {
        std::fs::remove_dir_all(&self.dir).unwrap_or_default();
    }
}

/// The memory binding, the commit driver on it, a custody that holds the issuer key and each CLI key, and the host
/// grant of the local owner. It deletes each key that it enrolled when it drops.
struct World<'c> {
    memory: Memory,
    driver: Driver,
    custody: &'c dyn Custody,
    grant: HostGrant,
    issuer: Handle,
    random: ChaCha20Rng,
    keys: Vec<KeyId>,
    /// The `Debug` output of each effect and each output.
    log: String,
}

impl<'c> World<'c> {
    /// A started driver on an empty store, and the issuer key in `custody`.
    fn new(custody: &'c dyn Custody) -> Self {
        let mut random = ChaCha20Rng::from_seed([5; 32]);
        let id = KeyId::random(&mut random);
        let issuer = custody.enroll(id, Algorithm::MlDsa65Ed25519, &mut random).unwrap();
        let mut world = Self::with(custody, issuer, random);
        world.keys.push(id);
        world
    }

    /// A started driver on an empty store, with the issuer key `issuer` in `custody`, as a second store of the same
    /// authority and issuer key has.
    fn with(custody: &'c dyn Custody, issuer: Handle, random: ChaCha20Rng) -> Self {
        let memory = Memory::new(Schedule::None);
        let driver = Driver::new(Profile::new(memory.declaration()).unwrap(), Limits::default()).unwrap();
        let grant = HostGrant {
            owner: Id::new("acme", "owner").unwrap(),
            origin: Id::new("acme", "build-app").unwrap(),
        };
        let mut world = Self {
            memory,
            driver,
            custody,
            grant,
            issuer,
            random,
            keys: Vec::new(),
            log: String::new(),
        };
        world.start();
        world
    }

    /// Executes each effect of the driver until it has none, and logs the `Debug` output of each effect and output.
    fn run(&mut self) {
        while let Some(effect) = self.driver.effect() {
            self.log.push_str(&format!("{effect:?}\n"));
            let output = ready(suite::execute(&mut self.memory, effect));
            self.log.push_str(&format!("{output:?}\n"));
            self.driver.give(output).unwrap();
        }
    }

    /// A start after a crash.
    fn start(&mut self) {
        self.driver.start(now());
        self.run();
    }

    /// The restore of `snapshot`.
    fn restore(&mut self, snapshot: &Snapshot) {
        self.memory.restore(snapshot);
        self.driver.restore(now()).unwrap();
        self.run();
    }

    fn commit(&mut self, (proposal, plan): (Proposal, Plan)) -> Outcome {
        let ticket = self.driver.submit(proposal, plan).unwrap();
        self.run();
        match self.driver.take(ticket) {
            Some(Answer::Outcome(outcome)) => outcome,
            answer => panic!("the commit gave {answer:?}"),
        }
    }

    /// The artifact of the accepted commit of `proposal`.
    fn artifact(&mut self, proposal: (Proposal, Plan)) -> Vec<u8> {
        match self.commit(proposal) {
            Outcome::Accepted(receipt) => receipt.artifact().unwrap().to_vec(),
            outcome => panic!("the commit did not land: {outcome:?}"),
        }
    }

    /// The local authority `name` of the grant, with the issuer key in custody.
    fn open(&mut self, name: &str) -> Authority {
        let id = Id::new("acme", name).unwrap();
        ready(Authority::open(
            &mut self.memory,
            &self.grant,
            id,
            self.issuer.clone(),
            Limits::default(),
        ))
        .unwrap()
    }

    /// A new operation identity.
    fn operation(&mut self) -> OperationId {
        let mut id = [0; 16];
        self.random.fill_bytes(&mut id);
        OperationId::new(&id).unwrap()
    }

    /// A new key of the CLI in custody. The ID is recorded before the enroll.
    fn key(&mut self) -> Handle {
        let id = KeyId::random(&mut self.random);
        self.keys.push(id);
        self.custody
            .enroll(id, Algorithm::MlDsa65Ed25519, &mut self.random)
            .unwrap()
    }

    /// The value that the commit of an issue by the owner for `administrator` at `at` gives.
    fn issue(&mut self, auth: &Authority, administrator: &str, at: Reading) -> Result<Bootstrap, Error> {
        let administrator = Id::new("acme", administrator).unwrap();
        let operation = self.operation();
        let issue = ready(auth.issue(
            &mut self.memory,
            &self.grant,
            administrator,
            at,
            &mut self.random,
            operation,
        ));
        let issue = issue.map_err(|failure| match failure {
            Failure::Refused(error) => error,
            Failure::Store(error) => panic!("a read failed: {error}"),
        })?;
        let text = String::from_utf8(self.artifact(issue)).unwrap();
        Ok(Bootstrap::parse(&text).unwrap())
    }

    /// The signature of the issuer key in custody over `message`.
    fn sign(&mut self, message: &[u8]) -> Vec<u8> {
        self.custody
            .sign(&self.issuer, Algorithm::MlDsa65Ed25519, message, &mut self.random)
            .unwrap()
    }

    /// The proposal of the bootstrap at `at` of a value that the owner issued for `administrator` at `at`, with the CLI
    /// key `key`.
    fn propose_at(&mut self, auth: &Authority, administrator: &str, key: &Handle, at: Reading) -> (Proposal, Plan) {
        let value = self.issue(auth, administrator, at).unwrap();
        let serial = Serial(self.driver.allocate(Kind::Credential).unwrap());
        let pending = ready(auth.bootstrap(&mut self.memory, &value, &holder(key), serial, at)).unwrap();
        let signature = self.sign(&pending.to_be_signed());
        pending.finish(&signature, self.operation()).unwrap()
    }

    /// The proposal of the bootstrap of a value that the owner issued for `administrator`, with the CLI key `key`.
    fn propose(&mut self, auth: &Authority, administrator: &str, key: &Handle) -> (Proposal, Plan) {
        self.propose_at(auth, administrator, key, now())
    }

    /// The key of a new CLI in custody, and the credential that its bootstrap as `administrator` gives.
    fn enroll(&mut self, auth: &Authority, administrator: &str) -> (Handle, Vec<u8>) {
        let key = self.key();
        let bootstrap = self.propose(auth, administrator, &key);
        let credential = self.artifact(bootstrap);
        (key, credential)
    }

    /// The credential of the binding of `administrator` with the CLI key `key`, which custody signs again: the
    /// recovery of a CLI whose response was lost.
    fn recover(&mut self, auth: &Authority, administrator: &str, key: &Handle) -> Result<Vec<u8>, Error> {
        let administrator = Id::new("acme", administrator).unwrap();
        let reissue =
            ready(auth.credential(&mut self.memory, &administrator, &holder(key), now())).map_err(|failure| {
                match failure {
                    Failure::Refused(error) => error,
                    Failure::Store(error) => panic!("a read failed: {error}"),
                }
            })?;
        let signature = self.sign(&reissue.to_be_signed());
        reissue.finish(&signature)
    }

    /// The proposal of the unlink of the binding of `target` by the CLI of `administrator`, whose key `key` proves the
    /// unlink, with a challenge that the commit of an issue gives.
    fn unlink(
        &mut self,
        auth: &Authority,
        (key, credential, administrator): (&Handle, &[u8], &str),
        target: &str,
        at: Reading,
    ) -> Result<(Proposal, Plan, Admission), Error> {
        let challenge = self.challenge(auth, administrator, at);
        let unlink = Unlink::new(
            challenge,
            self.operation(),
            Id::new("acme", target).unwrap(),
            Limits::default(),
        )
        .unwrap();
        let proof = self.prove(key, credential, unlink.call());
        ready(auth.unlink(&mut self.memory, credential, &proof, &unlink, at, &mut self.random)).map_err(|failure| {
            match failure {
                Failure::Refused(error) => error,
                Failure::Store(error) => panic!("a read failed: {error}"),
            }
        })
    }

    /// The challenge of the binding of `administrator` at `at`: the open challenge, or the one that the commit of a
    /// new challenge gives.
    fn challenge(&mut self, auth: &Authority, administrator: &str, at: Reading) -> Challenge {
        let administrator = Id::new("acme", administrator).unwrap();
        let operation = self.operation();
        match ready(auth.challenge(&mut self.memory, &administrator, at, &mut self.random, operation)).unwrap() {
            Offer::Open(challenge) => challenge,
            Offer::New(proposal, plan) => {
                Challenge::from_bytes(self.artifact((proposal, plan)).as_slice().try_into().unwrap())
            }
        }
    }

    /// The proof of `call` by the CLI key `key` in custody.
    fn prove(&mut self, key: &Handle, credential: &[u8], call: &Call) -> Vec<u8> {
        cli::prove(
            self.custody,
            key,
            credential,
            &self.grant.origin,
            call,
            now(),
            &mut self.random,
        )
        .unwrap()
    }

    fn admit(
        &mut self,
        auth: &Authority,
        credential: &[u8],
        proof: &[u8],
        call: &Call,
        at: Reading,
    ) -> Result<(Proposal, Admission), Failure<<Memory as Store>::Error>> {
        ready(auth.admit(&mut self.memory, credential, proof, call, at, &mut self.random))
    }

    /// The admitted call that the commit of the admission of `call` gives.
    fn call(&mut self, auth: &Authority, credential: &[u8], proof: &[u8], call: &Call) -> Admitted {
        let (proposal, admission) = self.admit(auth, credential, proof, call, now()).unwrap();
        let outcome = self.commit((proposal, Plan::default()));
        admission.release(&outcome).unwrap()
    }
}

impl Drop for World<'_> {
    fn drop(&mut self) {
        for id in &self.keys {
            self.custody.delete(*id).unwrap_or_default();
        }
    }
}

/// The journey of a CLI whose key is in `custody`: a call with no proof and a proof for another request refuse, a call
/// is admitted once, its replay refuses, and the next call uses the challenge that the commit wrote, with no issue.
fn journey(custody: &dyn Custody) {
    let mut world = World::new(custody);
    let auth = world.open("auth");
    let (key, credential) = world.enroll(&auth, "alice");

    let first = call(world.challenge(&auth, "alice", now()), "call-1", "status");
    assert_matches!(
        world.admit(&auth, &credential, &[], &first, now()),
        Err(Failure::Refused(Error::Credential(_)))
    );
    let proof = world.prove(&key, &credential, &first);
    let other = call(first.challenge(), "call-1", "deploy");
    assert_matches!(
        world.admit(&auth, &credential, &proof, &other, now()),
        Err(Failure::Refused(Error::Credential(credential::Error::Proof)))
    );
    let admitted = world.call(&auth, &credential, &proof, &first);
    assert_eq!(admitted.subject().value(), "alice");
    assert_eq!(admitted.holder(), local::Holder::Administrator);
    assert_matches!(
        world.admit(&auth, &credential, &proof, &first, now()),
        Err(Failure::Refused(Error::Challenge))
    );

    let second = call(admitted.next(), "call-2", "deploy");
    let proof = world.prove(&key, &credential, &second);
    world.call(&auth, &credential, &proof, &second);
}

#[test]
fn a_cli_with_its_key_in_a_key_file_proves_possession_once_on_each_call() {
    let files = Files::new("journey");
    journey(&files.custody);
}

#[cfg(target_os = "macos")]
#[test]
fn a_cli_with_its_key_in_the_keychain_proves_possession_once_on_each_call() {
    let service = format!("rsauthnz-test-{}-cli-keychain", std::process::id());
    let custody = rsauthnz::custody::KeychainCustody::open(service, Isolation::User).unwrap();
    journey(&custody);
}

/// Two admissions of one call that read the challenge before either commits: one commit, and one admitted call. The
/// second submission finds the outcome record of the first, so a duplicate request runs the call once.
#[test]
fn two_admissions_of_one_call_release_one_admitted_call() {
    let files = Files::new("twice");
    let mut world = World::new(&files.custody);
    let auth = world.open("auth");
    let (key, credential) = world.enroll(&auth, "alice");
    let once = call(world.challenge(&auth, "alice", now()), "call-1", "deploy");
    let proof = world.prove(&key, &credential, &once);
    let admissions = [
        world.admit(&auth, &credential, &proof, &once, now()).unwrap(),
        world.admit(&auth, &credential, &proof, &once, now()).unwrap(),
    ];
    let released = admissions
        .into_iter()
        .filter_map(|(proposal, admission)| admission.release(&world.commit((proposal, Plan::default()))))
        .count();
    assert_eq!(released, 1);
}

#[test]
fn a_cli_whose_bootstrap_response_was_lost_reads_its_credential_and_proves_possession() {
    let files = Files::new("lost");
    let mut world = World::new(&files.custody);
    let auth = world.open("auth");
    // The CLI stores its key in custody before it submits the bootstrap, whose response is lost.
    let key = world.key();
    let bootstrap = world.propose(&auth, "alice", &key);
    world.memory.inject(Fault::LostResponse);
    assert_matches!(world.commit(bootstrap), Outcome::Unknown(_));
    world.start();

    // The CLI keeps no secret: it gives its administrator and its public key. Another key finds no credential.
    let stranger = world.key();
    assert_matches!(world.recover(&auth, "alice", &stranger), Err(Error::Unknown));
    let credential = world.recover(&auth, "alice", &key).unwrap();
    let first = call(world.challenge(&auth, "alice", now()), "call-1", "status");
    let proof = world.prove(&key, &credential, &first);
    world.call(&auth, &credential, &proof, &first);
}

/// A restore from a snapshot that holds a pending challenge ends it, so a proof over it that a call used after the
/// snapshot cannot repeat.
#[test]
fn a_challenge_from_before_a_restore_refuses_after_it() {
    let files = Files::new("restore");
    let mut world = World::new(&files.custody);
    let auth = world.open("auth");
    let (key, credential) = world.enroll(&auth, "alice");
    let first = call(world.challenge(&auth, "alice", now()), "call-1", "deploy");
    let snapshot = world.memory.snapshot();
    let proof = world.prove(&key, &credential, &first);
    world.call(&auth, &credential, &proof, &first);

    world.restore(&snapshot);
    assert_matches!(
        world.admit(&auth, &credential, &proof, &first, now()),
        Err(Failure::Refused(Error::Challenge))
    );
    // The CLI asks for a new challenge after the restore.
    let second = call(world.challenge(&auth, "alice", now()), "call-2", "deploy");
    let proof = world.prove(&key, &credential, &second);
    world.call(&auth, &credential, &proof, &second);
}

/// The scope of a CLI credential is its issuer, its audience, its purpose, and its validity. A credential after its end
/// refuses although its binding is live, and so does a credential of another authority of the same issuer key.
#[test]
fn a_cli_credential_outside_its_scope_refuses() {
    let files = Files::new("scope");
    let mut world = World::new(&files.custody);
    let auth = world.open("auth");
    let (key, credential) = world.enroll(&auth, "alice");
    let late = at(local::CLI_LIFETIME);
    let first = call(world.challenge(&auth, "alice", now()), "call-1", "status");
    let proof = world.prove(&key, &credential, &first);
    assert_matches!(
        world.admit(&auth, &credential, &proof, &first, late),
        Err(Failure::Refused(Error::Credential(_)))
    );
    // A binding whose credential ended is no administrator, so it gets no challenge.
    let alice = Id::new("acme", "alice").unwrap();
    let operation = world.operation();
    assert_matches!(
        ready(auth.challenge(&mut world.memory, &alice, late, &mut world.random, operation)),
        Err(Failure::Refused(Error::NotEnrolled))
    );

    let other = world.open("other");
    let (key, foreign) = world.enroll(&other, "alice");
    let second = call(world.challenge(&auth, "alice", now()), "call-2", "status");
    let proof = world.prove(&key, &foreign, &second);
    assert_matches!(
        world.admit(&auth, &foreign, &proof, &second, now()),
        Err(Failure::Refused(Error::Credential(_)))
    );
}

/// An unlink is a call of its own: its proof binds its challenge, its operation, and its target. A proof of another
/// call, such as a status call, refuses, and so does a proof of the unlink of another administrator. One commit
/// consumes the challenge and ends the binding, so the same proof cannot unlink twice.
#[test]
fn an_unlink_takes_only_a_proof_of_that_unlink_and_runs_once() {
    let files = Files::new("unlink");
    let mut world = World::new(&files.custody);
    let auth = world.open("auth");
    let (_, alice) = world.enroll(&auth, "alice");
    let (bob_key, bob) = world.enroll(&auth, "bob");
    let (_, carol) = world.enroll(&auth, "carol");
    let carol_id = Id::new("acme", "carol").unwrap();

    // A proof of a status call under an operation, given as the proof of an unlink under that operation.
    let challenge = world.challenge(&auth, "bob", now());
    let status = call(challenge, "op-1", "status");
    let proof = world.prove(&bob_key, &bob, &status);
    let unlink = Unlink::new(
        challenge,
        op("op-1"),
        Id::new("acme", "alice").unwrap(),
        Limits::default(),
    )
    .unwrap();
    assert_matches!(
        ready(auth.unlink(&mut world.memory, &bob, &proof, &unlink, now(), &mut world.random)),
        Err(Failure::Refused(Error::Credential(credential::Error::Proof)))
    );
    // A proof of the unlink of alice, given for the unlink of carol.
    let proof = world.prove(&bob_key, &bob, unlink.call());
    let other = Unlink::new(challenge, op("op-1"), carol_id, Limits::default()).unwrap();
    assert_matches!(
        ready(auth.unlink(&mut world.memory, &bob, &proof, &other, now(), &mut world.random)),
        Err(Failure::Refused(Error::Credential(credential::Error::Proof)))
    );

    let (proposal, plan, admission) =
        ready(auth.unlink(&mut world.memory, &bob, &proof, &unlink, now(), &mut world.random)).unwrap();
    let outcome = world.commit((proposal, plan));
    assert_matches!(outcome, Outcome::Accepted(_));
    assert!(admission.release(&outcome).is_some());
    let stranger = world.key();
    assert_matches!(world.recover(&auth, "alice", &stranger), Err(Error::Unknown));
    // The proof of the unlink is spent with its challenge.
    assert_matches!(
        ready(auth.unlink(&mut world.memory, &bob, &proof, &unlink, now(), &mut world.random)),
        Err(Failure::Refused(Error::Challenge))
    );
    let _ = (alice, carol);
}

/// The proposal of a bootstrap holds no signed CLI credential outside its prepared artifact: the binding keeps the
/// credential without its signature. Only the receipt of the commit gives the credential, and a later recovery signs
/// the binding again.
#[test]
fn the_proposal_of_a_bootstrap_holds_no_signed_credential() {
    let files = Files::new("unsigned");
    let mut world = World::new(&files.custody);
    let auth = world.open("auth");
    let key = world.key();
    let (proposal, plan) = world.propose(&auth, "alice", &key);
    let records: Vec<Vec<u8>> = proposal
        .changes()
        .iter()
        .filter_map(|change| match change {
            Change::Write { data, .. } => Some(data.to_vec()),
            Change::End(_) => None,
        })
        .collect();
    let credential = world.artifact((proposal, plan));
    // The last 64 bytes of the credential are the Ed25519 part of its composite signature.
    let signature = &credential[credential.len() - 64..];
    for data in &records {
        assert!(
            !data.windows(64).any(|window| window == signature),
            "a record holds the signature"
        );
    }
    // The control: the recovery gives a credential with the same claims and a signature of its own.
    let recovered = world.recover(&auth, "alice", &key).unwrap();
    assert_eq!(recovered.len(), credential.len());
    assert_eq!(
        recovered[..recovered.len() - 3_373],
        credential[..credential.len() - 3_373]
    );
}

/// A restore from a snapshot from before the first issue keeps the administrator binding of a later bootstrap and
/// loses the record of the authority. The binding names the grant and the issuer key that bound it, so an open with
/// another grant or another issuer key refuses, and the open of the authority still works.
#[test]
fn an_authority_whose_record_a_restore_lost_refuses_another_grant_or_issuer_key() {
    let files = Files::new("identity");
    let mut world = World::new(&files.custody);
    let snapshot = world.memory.snapshot();
    let auth = world.open("auth");
    world.enroll(&auth, "alice");
    world.restore(&snapshot);

    let id = Id::new("acme", "auth").unwrap();
    let mallory = HostGrant {
        owner: Id::new("acme", "mallory").unwrap(),
        ..world.grant.clone()
    };
    let open = |world: &mut World<'_>, grant: &HostGrant, issuer: Handle| {
        ready(Authority::open(
            &mut world.memory,
            grant,
            id.clone(),
            issuer,
            Limits::default(),
        ))
    };
    let (issuer, grant) = (world.issuer.clone(), world.grant.clone());
    assert_matches!(
        open(&mut world, &mallory, issuer.clone()),
        Err(Failure::Refused(Error::Grant))
    );
    let other = world.key();
    assert_matches!(open(&mut world, &grant, other), Err(Failure::Refused(Error::Issuer)));
    assert_matches!(open(&mut world, &grant, issuer), Ok(_));
}

/// The commit of a bootstrap and of an admission refuses after the end of the authority that the decision read: the
/// end of the value, and the end of the challenge. The clock of the commit is a fresh reading, so a proposal that was
/// made before the end does not commit after it.
#[test]
fn a_bootstrap_or_an_admission_after_its_deadline_does_not_commit() {
    let files = Files::new("deadline");
    let mut world = World::new(&files.custody);
    let auth = world.open("auth");
    let key = world.key();
    let bootstrap = world.propose(&auth, "alice", &key);
    world.memory.set_clock(at(local::LIFETIME));
    assert_matches!(world.commit(bootstrap), Outcome::Refused(transition::Error::Expired));
    world.memory.set_clock(now());
    let (key, credential) = world.enroll(&auth, "alice");

    let first = call(world.challenge(&auth, "alice", now()), "call-1", "status");
    let proof = world.prove(&key, &credential, &first);
    let (proposal, admission) = world.admit(&auth, &credential, &proof, &first, now()).unwrap();
    world.memory.set_clock(at(cli::CHALLENGE_LIFETIME));
    let outcome = world.commit((proposal, Plan::default()));
    assert_matches!(outcome, Outcome::Refused(transition::Error::Expired));
    assert!(admission.release(&outcome).is_none());
    // The control: before the end, the same call commits.
    world.memory.set_clock(now());
    let second = call(world.challenge(&auth, "alice", now()), "call-2", "status");
    let proof = world.prove(&key, &credential, &second);
    world.call(&auth, &credential, &proof, &second);
}

/// A binding whose CLI credential ended is no administrator. A sole administrator with a valid credential cannot
/// unlink itself when the other binding has ended. The owner issues a value for an administrator whose credential
/// ended, and its bootstrap binds a new credential. At the most bindings, an issue refuses until an expiry pass removes
/// each binding whose credential ended.
#[test]
fn an_ended_binding_counts_as_no_administrator_and_the_owner_rebinds_it() {
    let files = Files::new("ended");
    let mut world = World::new(&files.custody);
    let auth = world.open("auth");
    let key = world.key();
    let bootstrap = world.propose(&auth, "alice", &key);
    let alice = world.artifact(bootstrap);
    let later = Duration::from_secs(10 * 24 * 60 * 60);
    let bootstrap = world.propose_at(&auth, "bob", &key, at(later));
    let bob = world.artifact(bootstrap);
    let ended = at(local::CLI_LIFETIME + Duration::from_secs(60));
    world.memory.set_clock(ended);
    assert_matches!(
        world.unlink(&auth, (&key, &bob, "bob"), "bob", ended),
        Err(Error::Transition(transition::Error::LastAnchor))
    );

    // The owner issues a value for alice again, and the bootstrap gives alice a new credential.
    let bootstrap = world.propose_at(&auth, "alice", &key, ended);
    let rebound = world.artifact(bootstrap);
    assert_ne!(rebound, alice);
    let first = call(world.challenge(&auth, "alice", ended), "call-1", "status");
    let proof = world.prove(&key, &rebound, &first);
    let (proposal, admission) = world.admit(&auth, &rebound, &proof, &first, ended).unwrap();
    assert!(admission.release(&world.commit((proposal, Plan::default()))).is_some());

    // Other names fill the bindings of the authority. An issue refuses, and an expiry pass removes the ended binding of
    // alice, so the owner issues again.
    for n in 3..local::ADMINISTRATORS_MAX {
        let bootstrap = world.propose_at(&auth, &format!("a-{n}"), &key, ended);
        world.artifact(bootstrap);
    }
    assert_matches!(world.issue(&auth, "zoe", ended), Err(Error::Full));
    let limit = core::num::NonZeroUsize::new(16).unwrap();
    while ready(store::expire(&mut world.memory, ended, limit)).unwrap() == store::Progress::More {}
    world.issue(&auth, "zoe", ended).unwrap();
}

/// A credential of another store of the same authority and issuer key can have the serial of a binding of this one.
/// The binding keeps the credential that it bound, so the other credential refuses although it names the same
/// administrator and serial.
#[test]
fn a_credential_with_the_serial_of_a_binding_but_other_bytes_refuses() {
    let files = Files::new("serial");
    let mut world = World::new(&files.custody);
    let auth = world.open("auth");
    world.enroll(&auth, "alice");
    let mut twin = World::with(&files.custody, world.issuer.clone(), ChaCha20Rng::from_seed([6; 32]));
    let twin_authority = twin.open("auth");
    let (mallory, forged) = twin.enroll(&twin_authority, "alice");

    let first = call(world.challenge(&auth, "alice", now()), "call-1", "status");
    let proof = world.prove(&mallory, &forged, &first);
    assert_matches!(
        world.admit(&auth, &forged, &proof, &first, now()),
        Err(Failure::Refused(Error::NotEnrolled))
    );
}

/// Whether `text` shows the first 16 bytes of `bytes` as `Debug` shows a byte slice: in decimal, or in hexadecimal as
/// for a version.
fn shows(text: &str, bytes: &[u8]) -> bool {
    let window = &bytes[..16];
    [format!("{window:?}"), format!("{window:02x?}")]
        .iter()
        .any(|form| text.contains(form.trim_start_matches('[').trim_end_matches(']')))
}

#[test]
fn the_debug_output_of_a_journey_shows_no_challenge_and_no_credential() {
    let files = Files::new("debug");
    let mut world = World::new(&files.custody);
    let auth = world.open("auth");
    let (key, credential) = world.enroll(&auth, "alice");
    let challenge = world.challenge(&auth, "alice", now());
    let first = call(challenge, "call-1", "status");
    let proof = world.prove(&key, &credential, &first);
    let admitted = world.call(&auth, &credential, &proof, &first);

    // The search finds each value where `Debug` of the bytes shows it.
    let (challenge, next, public) = (challenge.to_bytes(), admitted.next().to_bytes(), holder(&key));
    assert!(shows(&format!("{public:?}"), &public) && shows(&format!("{challenge:02x?}"), &challenge));
    // The bootstrap journals the binding with the claims of the credential, and the commits of the challenge and of
    // the call write challenge records. No effect, no output, and no value of the call shows them.
    let log = format!("{}{first:?}{admitted:?}", world.log);
    assert!(log.contains("Append"), "the journey journals its bootstrap");
    assert!(!shows(&log, &challenge), "the challenge");
    assert!(!shows(&log, &next), "the next challenge");
    assert!(!shows(&log, &public), "the cnf key of the credential");
}

#[test]
fn a_call_request_past_the_limits_refuses() {
    let limits = Limits::default();
    let mut request = Value::Null;
    for _ in 0..limits.depth {
        request = Value::Array(vec![request]);
    }
    // At the depth limit the call is made. One level more refuses, as it does for the proposal of an operation.
    let challenge = Challenge::from_bytes([1; 32]);
    Call::new(challenge, op("call-1"), &request, limits).unwrap();
    let deeper = Value::Array(vec![request]);
    assert_eq!(
        Call::new(challenge, op("call-1"), &deeper, limits),
        Err(cli::Error::Request)
    );
    let audit = transition::Audit {
        actor: rsauthnz::id::Principal::Human(Id::new("acme", "alice").unwrap()),
        action: Id::new("acme", "deploy").unwrap(),
        time: now(),
    };
    assert_matches!(
        Proposal::new(op("op-1"), audit, &deeper, limits),
        Err(transition::Error::Request(rsauthnz::cbor::Error::Limit(
            rsauthnz::limits::Limit::Depth
        )))
    );
}

#[test]
fn a_challenge_request_gives_the_open_challenge_and_commits_nothing() {
    let files = Files::new("open");
    let mut world = World::new(&files.custody);
    let auth = world.open("auth");
    let (key, credential) = world.enroll(&auth, "alice");
    let alice = Id::new("acme", "alice").unwrap();
    let request = |world: &mut World<'_>, at: Reading| {
        let operation = world.operation();
        ready(auth.challenge(&mut world.memory, &alice, at, &mut world.random, operation)).unwrap()
    };
    let Offer::New(proposal, plan) = request(&mut world, now()) else {
        panic!("a binding with no challenge gets the proposal of one");
    };
    let open = Challenge::from_bytes(world.artifact((proposal, plan)).as_slice().try_into().unwrap());

    // The CLI signs a call over the open challenge. Another caller asks for a challenge before the call arrives: it
    // gets the same challenge, nothing commits, and the call is admitted.
    let first = call(open, "call-1", "status");
    let proof = world.prove(&key, &credential, &first);
    assert_matches!(request(&mut world, at(Duration::from_secs(30))), Offer::Open(challenge) if challenge == open);
    let admitted = world.call(&auth, &credential, &proof, &first);
    // The commit of the call wrote the next challenge, which a request gives until its end. At its end, a request
    // gets the proposal of a new one.
    assert_matches!(
        request(&mut world, at(Duration::from_secs(58))),
        Offer::Open(challenge) if challenge == admitted.next()
    );
    assert_matches!(request(&mut world, at(Duration::from_secs(59))), Offer::New(..));
}

#[test]
fn one_operation_under_two_authorities_binds_two_requests() {
    let files = Files::new("two");
    let mut world = World::new(&files.custody);
    let (first, second) = (world.open("auth-a"), world.open("auth-b"));
    world.enroll(&first, "alice");
    world.enroll(&second, "alice");
    let alice = Id::new("acme", "alice").unwrap();
    let offer = |world: &mut World<'_>, auth: &Authority| match ready(auth.challenge(
        &mut world.memory,
        &alice,
        now(),
        &mut world.random,
        op("challenge-1"),
    ))
    .unwrap()
    {
        Offer::New(proposal, plan) => (proposal, plan),
        Offer::Open(_) => panic!("a binding with no challenge gets the proposal of one"),
    };
    let proposal = offer(&mut world, &first);
    world.artifact(proposal);
    // The same operation identity and the same administrator under the other authority is another request.
    let proposal = offer(&mut world, &second);
    assert_matches!(world.commit(proposal), Outcome::Refused(transition::Error::Reuse));
}

/// A trust-root key signs issuer keys, and no credential or proof. As the issuer key of an authority, or as the key of
/// a CLI, it refuses.
#[test]
fn a_root_key_refuses_as_an_issuer_key_and_as_a_cli_key() {
    let files = Files::new("root");
    let root = Handle::new(KeyId::from_bytes([3; 16]), Algorithm::SlhDsaSha2_128s, &[7; 32]).unwrap();
    let mut world = World::with(&files.custody, root.clone(), ChaCha20Rng::from_seed([5; 32]));
    let id = Id::new("acme", "auth").unwrap();
    assert_matches!(
        ready(Authority::open(
            &mut world.memory,
            &world.grant,
            id,
            root.clone(),
            Limits::default()
        )),
        Err(Failure::Refused(Error::Credential(credential::Error::Profile)))
    );
    let audience = Id::new("acme", "build-app").unwrap();
    let call = call(Challenge::from_bytes([1; 32]), "call-1", "status");
    let mut random = ChaCha20Rng::from_seed([6; 32]);
    assert_matches!(
        cli::prove(&files.custody, &root, b"", &audience, &call, now(), &mut random),
        Err(cli::Error::Credential(credential::Error::Profile))
    );
}

/// A host whose clock gives no bound gets `Error::Time` from each operation, before its reads: also for an
/// administrator with no binding, and for a valid credential. Another error would send the host to the wrong recovery.
#[test]
fn a_reading_with_no_bound_refuses_each_operation_before_its_first_read() {
    let files = Files::new("bound");
    let mut world = World::new(&files.custody);
    let auth = world.open("auth");
    let value = world.issue(&auth, "alice", now()).unwrap();
    let (key, credential) = world.enroll(&auth, "bob");
    let unbounded = Reading::new(START, None, ReadingSource::Caller);
    let time = Failure::Refused(Error::Time(rsauthnz::time::TimeError::UnknownBound));
    let (alice, carol) = (Id::new("acme", "alice").unwrap(), Id::new("acme", "carol").unwrap());
    let operation = world.operation();
    let issued = ready(auth.issue(
        &mut world.memory,
        &world.grant,
        carol.clone(),
        unbounded,
        &mut world.random,
        operation,
    ));
    assert_eq!(issued.err(), Some(time));
    let pending = ready(auth.bootstrap(&mut world.memory, &value, &holder(&key), Serial(9), unbounded));
    assert_eq!(pending.err(), Some(time));
    let reissue = ready(auth.credential(&mut world.memory, &carol, &holder(&key), unbounded));
    assert_eq!(reissue.err(), Some(time), "an administrator with no binding");
    let operation = world.operation();
    let offer = ready(auth.challenge(&mut world.memory, &carol, unbounded, &mut world.random, operation));
    assert_eq!(offer.err(), Some(time), "an administrator with no binding");
    let challenge = world.challenge(&auth, "bob", now());
    let request = call(challenge, "call-1", "status");
    let proof = world.prove(&key, &credential, &request);
    let admitted = world.admit(&auth, &credential, &proof, &request, unbounded);
    assert_eq!(admitted.err(), Some(time), "a valid credential");
    let unlink = Unlink::new(challenge, world.operation(), alice, Limits::default()).unwrap();
    let proof = world.prove(&key, &credential, unlink.call());
    let unlinked = ready(auth.unlink(
        &mut world.memory,
        &credential,
        &proof,
        &unlink,
        unbounded,
        &mut world.random,
    ));
    assert_eq!(unlinked.err(), Some(time), "a valid credential");
}
