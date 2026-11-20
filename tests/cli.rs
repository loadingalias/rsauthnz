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
use rsauthnz::local::{self, Admission, Admitted, Authority, Bootstrap, Error, Failure, HostGrant};
use rsauthnz::store::driver::{Answer, Driver, Plan};
use rsauthnz::store::{Kind, Profile, Store};
use rsauthnz::time::{Reading, ReadingSource};
use rsauthnz::transition::{OperationId, Outcome, Proposal};
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
}

impl<'c> World<'c> {
    /// A started driver on an empty store, and the issuer key in `custody`.
    fn new(custody: &'c dyn Custody) -> Self {
        let memory = Memory::new(Schedule::None);
        let driver = Driver::new(Profile::new(memory.declaration()).unwrap(), Limits::default()).unwrap();
        let mut random = ChaCha20Rng::from_seed([5; 32]);
        let id = KeyId::random(&mut random);
        let issuer = custody.enroll(id, Algorithm::MlDsa65Ed25519, &mut random).unwrap();
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
            keys: vec![id],
        };
        world.start();
        world
    }

    /// Executes each effect of the driver until it has none.
    fn run(&mut self) {
        while let Some(effect) = self.driver.effect() {
            let output = ready(suite::execute(&mut self.memory, effect));
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

    /// The proposal of the bootstrap of a value that the owner issued for `administrator`, with the CLI key `key`.
    fn propose(&mut self, auth: &Authority, administrator: &str, key: &Handle) -> (Proposal, Plan) {
        let administrator = Id::new("acme", administrator).unwrap();
        let operation = self.operation();
        let issue = ready(auth.issue(
            &mut self.memory,
            &self.grant,
            administrator,
            now(),
            &mut self.random,
            operation,
        ));
        let text = String::from_utf8(self.artifact(issue.unwrap())).unwrap();
        let serial = Serial(self.driver.allocate(Kind::Credential).unwrap());
        let value = Bootstrap::parse(&text).unwrap();
        let pending = ready(auth.bootstrap(&mut self.memory, &value, &holder(key), serial, now())).unwrap();
        let signature = self
            .custody
            .sign(
                &self.issuer,
                Algorithm::MlDsa65Ed25519,
                &pending.to_be_signed(),
                &mut self.random,
            )
            .unwrap();
        pending.finish(&signature, self.operation()).unwrap()
    }

    /// The key of a new CLI in custody, and the credential that its bootstrap as `administrator` gives.
    fn enroll(&mut self, auth: &Authority, administrator: &str) -> (Handle, Vec<u8>) {
        let key = self.key();
        let bootstrap = self.propose(auth, administrator, &key);
        let credential = self.artifact(bootstrap);
        (key, credential)
    }

    /// The challenge that the commit of an issue for `administrator` at `at` gives.
    fn challenge(&mut self, auth: &Authority, administrator: &str, at: Reading) -> Challenge {
        let administrator = Id::new("acme", administrator).unwrap();
        let operation = self.operation();
        let issue = ready(auth.challenge(&mut self.memory, &administrator, at, &mut self.random, operation)).unwrap();
        Challenge::from_bytes(self.artifact(issue).as_slice().try_into().unwrap())
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
    assert_eq!(admitted.administrator().value(), "alice");
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
    let alice = Id::new("acme", "alice").unwrap();
    let stranger = holder(&world.key());
    assert_matches!(
        ready(auth.credential(&mut world.memory, &alice, &stranger, now())),
        Err(Failure::Refused(Error::Unknown))
    );
    let credential = ready(auth.credential(&mut world.memory, &alice, &holder(&key), now())).unwrap();
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
    let first = call(world.challenge(&auth, "alice", late), "call-1", "status");
    let proof = world.prove(&key, &credential, &first);
    assert_matches!(
        world.admit(&auth, &credential, &proof, &first, late),
        Err(Failure::Refused(Error::Credential(_)))
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
