//! The contracts of workload credentials: a credential is released only by the accepted commit of its own operation,
//! it verifies only for its audience and its issuer key with a proof by its registered key, a request past the ceiling
//! or outside the policy refuses, and a restore releases no serial twice. A rotation, a recovery, and a revocation end
//! the earlier credentials of the workload at each verifier that reads the current registration, also when they race
//! an issuance or a restore follows them. An issuer-key rotation keeps the credentials of the old key until they end,
//! unless it retires the old key at once.

#[path = "workload/trust.rs"]
mod trust;

use core::pin::pin;
use core::task::{Context, Poll, Waker};
use core::time::Duration;
use std::sync::LazyLock;

use rsauthnz::authz::{self, Permit, Policy, Refusal, Requirements};
use rsauthnz::cbor::Value;
use rsauthnz::cose::{self, PublicKey, TrustedKey};
use rsauthnz::credential::{self, Awaiting, Claims, Draft, ProofDraft, Release, Released, Serial, Subject};
use rsauthnz::crypto::Algorithm;
use rsauthnz::evidence::Evidence;
use rsauthnz::id::{Audience, Authority, AuthorityVersion, Human, Id, Principal, Workload};
use rsauthnz::limits::{Limits, SignatureBudget};
use rsauthnz::store::driver::{Answer, Driver, Lookup, PAGE, Plan};
use rsauthnz::store::{self, Journal, Kind, Profile, Record, Sequence, Store};
use rsauthnz::time::{Reading, ReadingSource};
use rsauthnz::transition::{Audit, Change, Dependency, Key, OperationId, Outcome, Proposal};
use rsauthnz::workload::{
    self, By, Ceiling, Error, Issuer, IssuerRotation, LIFETIME_DEFAULT, Mode, Pending, Registration, Replace, Request,
    Retire, Revocation, Target,
};
use rsauthnz_conformance::memory::{Memory, Schedule, Snapshot};
use rsauthnz_conformance::suite::{self, Fault, Subject as _};
use rscrypto::auth::{CompositeMlDsaError, Ed25519SecretKey, MlDsa65Ed25519, MlDsa65Ed25519SecretKey};

/// The time of the first request.
const START: Duration = Duration::from_secs(1_800_000_000);

fn minutes(n: u64) -> Duration {
    Duration::from_secs(n * 60)
}

/// The reading at `n` minutes past [`START`], with an uncertainty of one second.
fn at(n: u64) -> Reading {
    Reading::new(START + minutes(n), Some(Duration::from_secs(1)), ReadingSource::Caller)
}

/// The output of `future`. The futures of the memory binding are ready at their first poll.
fn ready<F: Future>(future: F) -> F::Output {
    match pin!(future).poll(&mut Context::from_waker(Waker::noop())) {
        Poll::Ready(output) => output,
        Poll::Pending => panic!("the memory binding does no I/O"),
    }
}

fn budget() -> SignatureBudget {
    SignatureBudget::new(&Limits::default())
}

/// Whether `haystack` holds `needle`.
fn holds(haystack: &[u8], needle: &[u8]) -> bool {
    haystack.windows(needle.len()).any(|window| window == needle)
}

/// A composite key in custody. rscrypto signs in place of custody.
struct Custody {
    public: Vec<u8>,
    secret: MlDsa65Ed25519SecretKey,
}

impl Custody {
    /// The reproducible key that `seed` makes.
    fn new(seed: u8) -> Self {
        let fill = move |out: &mut [u8]| -> Result<(), CompositeMlDsaError> {
            out.fill(seed);
            Ok(())
        };
        let (public, secret) = MlDsa65Ed25519::generate_keypair(fill).unwrap();
        Self {
            public: public.to_bytes().to_vec(),
            secret,
        }
    }

    fn public(&self) -> PublicKey<'_> {
        PublicKey::MlDsa65Ed25519(self.public.as_slice().try_into().unwrap())
    }

    fn trusted(&self) -> TrustedKey {
        let key = cose::Key {
            kid: None,
            alg: None,
            public: self.public(),
        };
        TrustedKey::new(Algorithm::MlDsa65Ed25519, &key).unwrap()
    }

    fn sign(&self, message: &[u8]) -> Vec<u8> {
        self.secret
            .sign_deterministic(message, &[])
            .unwrap()
            .as_bytes()
            .to_vec()
    }

    /// The proof of possession of this key for `credential` at `audience`, over `challenge`.
    fn prove(&self, credential: &[u8], audience: &Id<Audience>, challenge: &[u8], now: Reading) -> Vec<u8> {
        let draft = ProofDraft::new(&self.trusted(), credential, audience, challenge, now).unwrap();
        let signature = self.sign(&draft.to_be_signed());
        draft.finish(&signature, &mut budget()).unwrap()
    }

    /// The proof of possession of this key, signed by `signer`, as the new key of the workload `workload` for a
    /// rotation or a recovery at `build-api`, over the request binding `challenge`.
    fn prove_new(&self, signer: &Self, workload: &Id<Workload>, challenge: &[u8], now: Reading) -> Vec<u8> {
        let binding = workload::key_binding(workload, &self.public());
        let draft = ProofDraft::new(&signer.trusted(), &binding, &audience("build-api"), challenge, now).unwrap();
        let signature = signer.sign(&draft.to_be_signed());
        draft.finish(&signature, &mut budget()).unwrap()
    }

    /// The proof of this key, signed by `signer`, as the new key of the workload `workload` for the recovery of the
    /// operation `name` at `build-api`, whose challenge is `name`.
    fn prove_recovery(&self, signer: &Self, workload: &Id<Workload>, name: &str, now: Reading) -> Vec<u8> {
        let build = audience("build-api");
        let key = self.public();
        let bound = workload::binding(name.as_bytes(), &op(name), &authority(), workload, &build, Some(&key));
        self.prove_new(signer, workload, &bound, now)
    }
}

fn authority() -> Id<Authority> {
    Id::new("acme", "workload-issuer").unwrap()
}

fn operator() -> Id<Human> {
    Id::new("acme", "operator-1").unwrap()
}

fn runner_id() -> Id<Workload> {
    Id::new("acme", "runner-7").unwrap()
}

fn audience(name: &str) -> Id<Audience> {
    Id::new("acme", name).unwrap()
}

fn version(n: u8) -> AuthorityVersion {
    AuthorityVersion::new(authority(), &[n]).unwrap()
}

fn op(name: &str) -> OperationId {
    OperationId::new(name.as_bytes()).unwrap()
}

/// The ceiling of the tests: one hour for each credential, and no credential past two hours.
fn ceiling() -> Ceiling {
    Ceiling {
        lifetime_max: minutes(60),
        not_after: START + minutes(120),
    }
}

/// The policy of the tests: the operator can issue, recover, and revoke on the resource of the workload, and rotate the
/// key of the issuer. The workload can renew and rotate on its resource.
struct Permits;

impl Policy for Permits {
    fn version(&self) -> &AuthorityVersion {
        static VERSION: LazyLock<AuthorityVersion> = LazyLock::new(|| version(1));
        &VERSION
    }

    fn resolve(&self, request: &authz::Request<'_>) -> Option<Permit> {
        let modes: &[Mode] = match request.principal {
            Principal::Human(human) if *human == operator() => &[Mode::Issue, Mode::Recover, Mode::Revoke],
            Principal::Workload(workload) if *workload == runner_id() => &[Mode::Renew, Mode::Rotate],
            _ => &[],
        };
        let on_workload = *request.resource == workload::resource(&runner_id())
            && modes.iter().any(|mode| mode.action() == *request.action);
        let on_issuer = *request.resource == workload::issuer_resource(&authority())
            && *request.principal == Principal::Human(operator())
            && *request.action == Mode::RotateIssuer.action();
        (on_workload || on_issuer).then(|| Permit {
            principal: request.principal.clone(),
            action: request.action.clone(),
            resource: request.resource.clone(),
            version: self.version().clone(),
            requires: Requirements {
                user_verified: false,
                phishing_resistant: false,
                max_age: minutes(600),
            },
            expires: START + minutes(1_440),
        })
    }
}

/// A proposal of the operator that writes records of the application.
fn proposal(name: &str) -> Proposal {
    let audit = Audit {
        actor: Principal::Human(operator()),
        action: Id::new("acme", "records.write").unwrap(),
        time: at(0),
    };
    Proposal::new(op(name), audit, &Value::Null, Limits::default()).unwrap()
}

/// The memory binding and the commit driver on it.
struct Node {
    memory: Memory,
    driver: Driver,
}

impl Node {
    /// A started node with an empty store.
    fn new() -> Self {
        let memory = Memory::new(Schedule::None);
        let driver = Driver::new(Profile::new(memory.declaration()).unwrap(), Limits::default()).unwrap();
        let mut node = Self { memory, driver };
        node.start();
        node
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
        self.driver.start(at(0));
        self.run();
    }

    /// The restore of `snapshot`.
    fn restore(&mut self, snapshot: &Snapshot) {
        self.memory.restore(snapshot);
        self.driver.restore(at(0)).unwrap();
        self.run();
    }

    fn commit(&mut self, proposal: Proposal, plan: Plan) -> Outcome {
        let ticket = self.driver.submit(proposal, plan).unwrap();
        self.run();
        match self.driver.take(ticket) {
            Some(Answer::Outcome(outcome)) => outcome,
            answer => panic!("the commit gave {answer:?}"),
        }
    }

    fn read(&mut self, key: &Key) -> Option<Record> {
        ready(Store::read(&mut self.memory, key)).unwrap()
    }
}

/// A node whose store holds the records of the application, the keys, and the evidence of the operator.
struct Host {
    node: Node,
    issuer: Custody,
    runner: Custody,
    operator: Evidence,
}

impl Host {
    /// A node that holds the policy record, the issuer record of `ceiling` for the audiences `build-api` and
    /// `deploy-api`, and the registration of the workload. The commit of the records releases a credential of the
    /// operator too, and a proof by the key of the operator gives its evidence.
    fn new(ceiling: Ceiling) -> Self {
        let mut node = Node::new();
        let (issuer, runner, operator) = (Custody::new(1), Custody::new(2), Custody::new(3));
        let audiences = vec![audience("build-api"), audience("deploy-api")];
        let mut setup = proposal("setup");
        let policy = store::policy_key(&authority());
        setup.read(Dependency::Absent(policy.clone())).unwrap();
        let change = Change::Write {
            key: policy,
            version: version(1),
            end: None,
            data: Box::from(*b"the policy"),
        };
        setup.change(change).unwrap();
        let record = Issuer::new(authority(), issuer.public(), audiences, ceiling).unwrap();
        record.register(&mut setup, &mut node.driver).unwrap();
        Registration::register(&mut setup, runner_id(), runner.public(), &record, &mut node.driver).unwrap();
        let (console, purpose) = (audience("console"), Id::new("acme", "operator").unwrap());
        let claims = Claims::new(
            authority(),
            console.clone(),
            Subject::Human(self::operator()),
            purpose.clone(),
            Serial(u64::MAX),
            START + minutes(60),
        );
        let draft = Draft::credential(&issuer.trusted(), &claims, Some(operator.public()), at(0)).unwrap();
        let signature = issuer.sign(&draft.to_be_signed());
        draft.record(&mut setup).unwrap();
        setup.prepare(draft.finish(&signature, &mut budget()).unwrap()).unwrap();
        let Outcome::Accepted(receipt) = node.commit(setup, Plan::default()) else {
            panic!("the records did not commit");
        };
        let credential = receipt.artifact().unwrap();
        let profile = credential::Profile::new(
            issuer.trusted(),
            authority(),
            console.clone(),
            purpose,
            Limits::default(),
        );
        let profile = profile.unwrap();
        let verified = profile.verify(credential, at(0), &mut budget()).unwrap();
        let proof = operator.prove(credential, &console, b"challenge-op", at(0));
        let evidence = verified
            .possession(&proof, b"challenge-op", at(0), &mut budget())
            .unwrap();
        Self {
            node,
            issuer,
            runner,
            operator: evidence,
        }
    }

    /// The current issuer.
    fn issuer(&mut self) -> Issuer {
        let record = self.node.read(&Issuer::store_key(&authority())).unwrap();
        Issuer::from_record(&record.data, Limits::default()).unwrap()
    }

    /// The current registration record of the workload.
    fn registration(&mut self) -> Option<Record> {
        self.node.read(&Registration::store_key(&runner_id()))
    }

    /// The check of a verifier that reads the current state: `credential` verifies at `audience` under the profile of
    /// the current issuer record, and the current registration admits it, at `now`.
    fn admits(&mut self, credential: &Released, audience: &str, now: Reading) -> Result<(), Error> {
        let profile = self.issuer().profile(&self::audience(audience), Limits::default())?;
        let verified = profile.verify(credential.as_bytes(), now, &mut budget())?;
        let registration = self.registration();
        workload::admits(&verified, registration.as_ref(), Limits::default())
    }

    /// The pending issuance of `request` at `now`, from the current records.
    fn pending(&mut self, request: Request<'_>, now: Reading) -> Result<Pending, Error> {
        let issuer = self.node.read(&Issuer::store_key(&authority())).unwrap();
        let registration = self.registration().unwrap();
        Pending::new(
            request,
            &issuer,
            &registration,
            &Permits,
            &mut self.node.driver,
            now,
            Limits::default(),
        )
    }

    /// The pending issuance of `request` at `now` that custody signed: its proposal, its plan, its release, and the
    /// signature.
    fn signed(&mut self, request: Request<'_>, now: Reading) -> (Proposal, Plan, Awaiting, Vec<u8>) {
        let pending = self.pending(request, now).unwrap();
        let signature = self.issuer.sign(&pending.to_be_signed());
        let (proposal, plan, awaiting) = pending.finish(&signature, &mut budget()).unwrap();
        (proposal, plan, awaiting, signature)
    }

    /// The credential of `request` at `now`, which its commit releases, or the refusal of the issuance.
    fn issue(&mut self, request: Request<'_>, now: Reading) -> Result<Released, Error> {
        let pending = self.pending(request, now)?;
        let signature = self.issuer.sign(&pending.to_be_signed());
        let (proposal, plan, awaiting) = pending.finish(&signature, &mut budget())?;
        let outcome = self.node.commit(proposal, plan);
        Ok(awaiting.release(outcome).expect("the commit releases the credential"))
    }

    /// The commit of the revocation of the operation `name` of `target` by the operator at `now`.
    fn revoke(&mut self, name: &str, target: Target<'_>, now: Reading) -> Outcome {
        let operator = self.operator.clone();
        let revocation = Revocation {
            operation: op(name),
            by: &operator,
            target,
        };
        let registration = self.registration().unwrap();
        let (proposal, plan) = revocation
            .proposal(&registration, &Permits, &mut self.node.driver, now, Limits::default())
            .unwrap();
        self.node.commit(proposal, plan)
    }

    /// The issuance record of `credential`, as the store holds it.
    fn record(&mut self, credential: &Released) -> Record {
        self.node.read(&credential::record_key(credential.serial())).unwrap()
    }

    /// The commit of the rotation of the operation `name` of the issuer key to `key` by the operator at `now`, or its
    /// refusal.
    fn rotate_issuer(
        &mut self,
        name: &str,
        key: PublicKey<'_>,
        retire: Retire,
        now: Reading,
    ) -> Result<Outcome, Error> {
        let operator = self.operator.clone();
        let rotation = IssuerRotation {
            operation: op(name),
            by: &operator,
            key,
            retire,
        };
        let issuer = self.node.read(&Issuer::store_key(&authority())).unwrap();
        let (proposal, plan) = rotation.proposal(&issuer, &Permits, &mut self.node.driver, now, Limits::default())?;
        Ok(self.node.commit(proposal, plan))
    }

    /// The first issuance of the operation `name` by the operator, for `build-api` with the default lifetime.
    fn first(&mut self, name: &str) -> Released {
        let (operator, build) = (self.operator.clone(), audience("build-api"));
        self.issue(issuance(name, &operator, &build), at(0)).unwrap()
    }

    /// The renewal of `credential` of the operation `name` at `now`, for `build-api` and `lifetime`, with a proof by
    /// `key`.
    fn renew(
        &mut self,
        name: &str,
        credential: &Released,
        key: &Custody,
        lifetime: Option<Duration>,
        now: Reading,
    ) -> Result<Released, Error> {
        let build = audience("build-api");
        let bound = workload::binding(name.as_bytes(), &op(name), &authority(), &runner_id(), &build, None);
        let proof = key.prove(credential.as_bytes(), &build, &bound, now);
        let request = Request {
            operation: op(name),
            by: By::Renew {
                credential: credential.as_bytes(),
                proof: &proof,
                challenge: name.as_bytes(),
            },
            audience: &build,
            lifetime,
            replace: None,
        };
        self.issue(request, now)
    }

    /// The rotation of the operation `name` at `now` by the workload, with `credential` and a proof by `key`, to the
    /// key of `new`, whose proof `signer` signs.
    fn rotate(
        &mut self,
        name: &str,
        credential: &Released,
        key: &Custody,
        new: &Custody,
        signer: &Custody,
        now: Reading,
    ) -> Result<Released, Error> {
        let build = audience("build-api");
        let new_key = new.public();
        let bound = |challenge: &[u8]| {
            workload::binding(challenge, &op(name), &authority(), &runner_id(), &build, Some(&new_key))
        };
        let proof = key.prove(credential.as_bytes(), &build, &bound(name.as_bytes()), now);
        let challenge = [name.as_bytes(), b"-new"].concat();
        let new_proof = new.prove_new(signer, &runner_id(), &bound(&challenge), now);
        let request = Request {
            operation: op(name),
            by: By::Renew {
                credential: credential.as_bytes(),
                proof: &proof,
                challenge: name.as_bytes(),
            },
            audience: &build,
            lifetime: None,
            replace: Some(Replace {
                key: new.public(),
                proof: &new_proof,
                challenge: &challenge,
            }),
        };
        self.issue(request, now)
    }
}

/// A first issuance of the operation `name` by `evidence` for `audience`, with the default lifetime.
fn issuance<'a>(name: &str, evidence: &'a Evidence, audience: &'a Id<Audience>) -> Request<'a> {
    Request {
        operation: op(name),
        by: By::Issue(evidence),
        audience,
        lifetime: None,
        replace: None,
    }
}

/// A recovery of the operation `name` by `evidence` for `build`, to the new key `key` with its proof `proof` over
/// `challenge`.
fn recovery<'a>(
    name: &str,
    evidence: &'a Evidence,
    build: &'a Id<Audience>,
    key: PublicKey<'a>,
    proof: &'a [u8],
    challenge: &'a [u8],
) -> Request<'a> {
    Request {
        replace: Some(Replace { key, proof, challenge }),
        ..issuance(name, evidence, build)
    }
}

#[test]
fn a_workload_credential_refuses_at_a_wrong_audience_under_a_wrong_key_and_with_a_wrong_proof() {
    let mut host = Host::new(ceiling());
    let credential = host.first("i-1");
    let issuer = host.issuer();
    let (build, now) = (audience("build-api"), at(1));
    let proof = host.runner.prove(credential.as_bytes(), &build, b"challenge-1", now);

    // The control: the credential verifies at its audience, and a proof by the registered key gives the evidence of
    // the workload.
    let profile = issuer.profile(&build, Limits::default()).unwrap();
    let verified = profile.verify(credential.as_bytes(), now, &mut budget()).unwrap();
    let evidence = verified.possession(&proof, b"challenge-1", now, &mut budget()).unwrap();
    assert_eq!(evidence.subject(), &Principal::Workload(runner_id()));

    let deploy = issuer.profile(&audience("deploy-api"), Limits::default()).unwrap();
    assert_eq!(
        deploy.verify(credential.as_bytes(), now, &mut budget()).err(),
        Some(credential::Error::Cose(cose::Error::Audience))
    );
    let other = Issuer::new(
        authority(),
        Custody::new(4).public(),
        issuer.audiences().to_vec(),
        ceiling(),
    )
    .unwrap();
    // The `kid` of the credential names no key of a verifier that trusts another issuer key.
    let other = other.profile(&build, Limits::default()).unwrap();
    assert_eq!(
        other.verify(credential.as_bytes(), now, &mut budget()).err(),
        Some(credential::Error::Cose(cose::Error::KeyId))
    );
    let stolen = Custody::new(4).prove(credential.as_bytes(), &build, b"challenge-1", now);
    assert_eq!(
        verified.possession(&stolen, b"challenge-1", now, &mut budget()).err(),
        Some(credential::Error::Cose(cose::Error::Signature))
    );
}

#[test]
fn a_credential_is_released_only_by_the_accepted_commit_of_its_own_operation() {
    let mut host = Host::new(ceiling());
    let (operator, build) = (host.operator.clone(), audience("build-api"));

    // The commit lands, and its response is lost: the release gives no credential.
    let (proposal, plan, awaiting, signature) = host.signed(issuance("i-lost", &operator, &build), at(0));
    let serial = awaiting.serial();
    host.node.memory.inject(Fault::LostResponse);
    let outcome = host.node.commit(proposal, plan);
    let Err(Release::Unknown(operation)) = awaiting.release(outcome) else {
        panic!("a lost response released a credential, or gave another error than an unknown outcome");
    };
    host.node.start();
    let ticket = host.node.driver.lookup(operation).unwrap();
    host.node.run();
    let Some(Answer::Lookup(Lookup::Committed(receipt))) = host.node.driver.take(ticket) else {
        panic!("the lookup does not show the commit");
    };
    assert_eq!(receipt.artifact(), None);
    // The store recorded the issuance and its audit, and no record and no journal entry holds the credential.
    let mut records = vec![host.node.read(&credential::record_key(serial)).unwrap()];
    for kind in [Kind::Audit, Kind::Outcome] {
        records.push(host.node.read(&kind.key(b"i-lost").unwrap()).unwrap());
    }
    assert!(records.iter().all(|record| !holds(&record.data, &signature)));
    let entries = ready(Journal::read(&mut host.node.memory, Sequence(0), PAGE)).unwrap();
    assert!(entries.iter().all(|entry| !holds(&entry.data, &signature)));

    // A new proposal of the same request under the same identity commits nothing, and it releases nothing.
    let (again, plan, awaiting, _) = host.signed(issuance("i-lost", &operator, &build), at(0));
    let serial = awaiting.serial();
    assert_eq!(
        awaiting.release(host.node.commit(again, plan)).err(),
        Some(Release::Committed)
    );
    assert_eq!(host.node.read(&credential::record_key(serial)), None);

    // A crash before the commit: the release gives no credential, and nothing committed.
    let (proposal, plan, awaiting, _) = host.signed(issuance("i-crash", &operator, &build), at(0));
    let serial = awaiting.serial();
    host.node.memory.inject(Fault::CrashBeforeCommit);
    let outcome = host.node.commit(proposal, plan);
    assert!(matches!(awaiting.release(outcome), Err(Release::Unknown(_))));
    host.node.start();
    assert_eq!(host.node.read(&credential::record_key(serial)), None);

    // The control: the accepted commit releases the credential that custody signed, and it verifies.
    let (proposal, plan, awaiting, signature) = host.signed(issuance("i-accepted", &operator, &build), at(0));
    let credential = awaiting.release(host.node.commit(proposal, plan)).unwrap();
    assert!(holds(credential.as_bytes(), &signature));
    let profile = host.issuer().profile(&build, Limits::default()).unwrap();
    let verified = profile.verify(credential.as_bytes(), at(1), &mut budget()).unwrap();
    assert_eq!(verified.claims().serial, credential.serial());
}

#[test]
fn a_renewal_past_the_ceiling_of_the_issuer_refuses() {
    let mut host = Host::new(Ceiling {
        lifetime_max: minutes(60),
        not_after: START + minutes(90),
    });
    let first = host.first("i-1");
    assert_eq!(first.expires(), START + LIFETIME_DEFAULT);
    assert_eq!(first.renew_at(), START + minutes(30));
    let runner = Custody::new(2);

    // At 40 minutes, the default hour ends at 100 minutes, past `not_after`. Two hours are past `lifetime_max`.
    assert_eq!(
        host.renew("r-1", &first, &runner, None, at(40)).err(),
        Some(Error::Ceiling)
    );
    assert_eq!(
        host.renew("r-2", &first, &runner, Some(minutes(120)), at(40)).err(),
        Some(Error::Ceiling)
    );
    let (operator, other) = (host.operator.clone(), audience("other-api"));
    assert_eq!(
        host.issue(issuance("i-2", &operator, &other), at(40)).err(),
        Some(Error::Audience)
    );

    // The control: a renewal that ends at `not_after` gives a new serial with the same key, and the earlier
    // credential stays valid.
    let renewed = host.renew("r-3", &first, &runner, Some(minutes(50)), at(40)).unwrap();
    assert!(renewed.serial() > first.serial());
    assert_eq!(renewed.expires(), START + minutes(90));
    let build = audience("build-api");
    let profile = host.issuer().profile(&build, Limits::default()).unwrap();
    for credential in [&first, &renewed] {
        let verified = profile.verify(credential.as_bytes(), at(41), &mut budget()).unwrap();
        let proof = runner.prove(credential.as_bytes(), &build, b"challenge-2", at(41));
        verified
            .possession(&proof, b"challenge-2", at(41), &mut budget())
            .unwrap();
    }
}

#[test]
fn a_renewal_refuses_without_possession_of_the_registered_key() {
    let mut host = Host::new(ceiling());
    let first = host.first("i-1");
    let runner = Custody::new(2);
    host.renew("r-1", &first, &runner, None, at(30)).unwrap();

    let stolen = Custody::new(4);
    assert_eq!(
        host.renew("r-2", &first, &stolen, None, at(30)).err(),
        Some(Error::Credential(credential::Error::Cose(cose::Error::Signature)))
    );
}

#[test]
fn an_issuance_that_the_policy_does_not_permit_refuses() {
    let mut host = Host::new(ceiling());
    let first = host.first("i-1");
    let build = audience("build-api");
    let profile = host.issuer().profile(&build, Limits::default()).unwrap();
    let verified = profile.verify(first.as_bytes(), at(1), &mut budget()).unwrap();
    let proof = host.runner.prove(first.as_bytes(), &build, b"challenge-1", at(1));
    let workload = verified
        .possession(&proof, b"challenge-1", at(1), &mut budget())
        .unwrap();

    // The policy permits the workload to renew, not to issue.
    assert_eq!(
        host.issue(issuance("i-2", &workload, &build), at(1)).err(),
        Some(Error::Refusal(Refusal::Denied))
    );
}

#[test]
fn a_restore_from_an_older_snapshot_releases_no_credential_serial_twice() {
    let mut host = Host::new(ceiling());
    let older = host.node.memory.snapshot();
    let mut serials = vec![host.first("i-1").serial()];
    let newer = host.node.memory.snapshot();
    host.node.restore(&older);
    serials.push(host.first("i-2").serial());
    host.node.restore(&newer);
    serials.push(host.first("i-3").serial());
    assert!(
        serials.array_windows().all(|[earlier, later]| earlier < later),
        "{serials:?}"
    );
}

#[test]
fn after_a_rotation_the_old_proof_key_refuses() {
    let mut host = Host::new(ceiling());
    let first = host.first("i-1");
    let (runner, new) = (Custody::new(2), Custody::new(6));
    // The control: before the rotation, the current registration admits the credential.
    host.admits(&first, "build-api", at(10)).unwrap();

    // The workload proves its current key and its new key. The commit issues the first credential of the new key.
    let rotated = host.rotate("rot-1", &first, &runner, &new, &new, at(10)).unwrap();
    let build = audience("build-api");
    let profile = host.issuer().profile(&build, Limits::default()).unwrap();
    let verified = profile.verify(rotated.as_bytes(), at(11), &mut budget()).unwrap();
    let proof = new.prove(rotated.as_bytes(), &build, b"challenge-1", at(11));
    verified
        .possession(&proof, b"challenge-1", at(11), &mut budget())
        .unwrap();
    host.admits(&rotated, "build-api", at(11)).unwrap();

    // The old key refuses at the issuer, and its credential refuses at a verifier that reads the registration.
    assert_eq!(
        host.renew("r-1", &first, &runner, None, at(30)).err(),
        Some(Error::Possession)
    );
    assert_eq!(host.admits(&first, "build-api", at(11)), Err(Error::Revoked));
    assert_eq!(
        host.renew("r-2", &rotated, &runner, None, at(30)).err(),
        Some(Error::Credential(credential::Error::Cose(cose::Error::Signature)))
    );
    host.renew("r-3", &rotated, &new, None, at(30)).unwrap();
}

#[test]
fn a_rotation_and_a_recovery_refuse_a_new_key_without_its_proof_of_possession() {
    let mut host = Host::new(ceiling());
    let first = host.first("i-1");
    let (runner, new, other) = (Custody::new(2), Custody::new(6), Custody::new(7));

    // Another key signs the proof of the new key, so the issuer binds no key that the workload does not hold.
    assert_eq!(
        host.rotate("rot-1", &first, &runner, &new, &other, at(10)).err(),
        Some(Error::Credential(credential::Error::Cose(cose::Error::Signature)))
    );
    let (operator, build) = (host.operator.clone(), audience("build-api"));
    let forged = new.prove_recovery(&other, &runner_id(), "rec-1", at(10));
    assert_eq!(
        host.issue(
            recovery("rec-1", &operator, &build, new.public(), &forged, b"rec-1"),
            at(10)
        )
        .err(),
        Some(Error::Credential(credential::Error::Cose(cose::Error::Signature)))
    );
    // A proof of the new key for another workload binds other bytes.
    let elsewhere = new.prove_recovery(&new, &Id::new("acme", "runner-8").unwrap(), "rec-2", at(10));
    assert_eq!(
        host.issue(
            recovery("rec-2", &operator, &build, new.public(), &elsewhere, b"rec-2"),
            at(10)
        )
        .err(),
        Some(Error::Credential(credential::Error::Proof))
    );

    // Nothing committed: the registered key and the generation are the same.
    host.admits(&first, "build-api", at(10)).unwrap();
    host.renew("r-1", &first, &runner, None, at(30)).unwrap();
}

#[test]
fn a_revoked_credential_refuses_at_a_verifier_that_reads_the_current_registration() {
    let mut host = Host::new(ceiling());
    let (operator, deploy) = (host.operator.clone(), audience("deploy-api"));
    let build = host.first("i-1");
    let later = host.issue(issuance("i-2", &operator, &deploy), at(0)).unwrap();
    for (credential, audience) in [(&build, "build-api"), (&later, "deploy-api")] {
        host.admits(credential, audience, at(1)).unwrap();
    }

    // A revocation of one credential ends that credential and no other: an earlier one and a later one stay valid.
    let record = host.record(&later);
    assert!(matches!(
        host.revoke("rv-0", Target::Credential(later.serial(), &record), at(1)),
        Outcome::Accepted(_)
    ));
    assert_eq!(host.admits(&later, "deploy-api", at(2)), Err(Error::Revoked));
    host.admits(&build, "build-api", at(2)).unwrap();
    let after = host.issue(issuance("i-3", &operator, &deploy), at(2)).unwrap();
    let record = host.record(&build);
    assert!(matches!(
        host.revoke("rv-1", Target::Credential(build.serial(), &record), at(2)),
        Outcome::Accepted(_)
    ));
    assert_eq!(host.admits(&build, "build-api", at(3)), Err(Error::Revoked));
    host.admits(&after, "deploy-api", at(3)).unwrap();
    let runner = Custody::new(2);
    assert_eq!(
        host.renew("r-1", &build, &runner, None, at(30)).err(),
        Some(Error::Revoked)
    );

    // The revocation reads the issuance record of its serial: the record of another serial, and the record of a
    // credential that a revocation ended, refuse.
    let operator = host.operator.clone();
    let registration = host.registration().unwrap();
    let other = host.record(&after);
    for target in [
        Target::Credential(Serial(after.serial().0 + 1_000), &other),
        Target::Credential(build.serial(), &record),
    ] {
        let revocation = Revocation {
            operation: op("rv-2"),
            by: &operator,
            target,
        };
        assert_eq!(
            revocation
                .proposal(&registration, &Permits, &mut host.node.driver, at(3), Limits::default())
                .err(),
            Some(Error::Target)
        );
    }

    // A revocation of all credentials ends each one. The registration stays, so the operator issues again.
    assert!(matches!(host.revoke("rv-3", Target::All, at(3)), Outcome::Accepted(_)));
    assert_eq!(host.admits(&after, "deploy-api", at(4)), Err(Error::Revoked));
    let again = host.first("i-4");
    host.admits(&again, "build-api", at(4)).unwrap();
}

/// A registration holds at most [`workload::REVOKED_MAX`] revoked credentials that did not end. The revocation of one
/// more refuses, and a revocation of all credentials still commits.
#[test]
fn a_revocation_of_one_credential_past_the_bound_of_the_registration_refuses() {
    let mut host = Host::new(ceiling());
    let operator = host.operator.clone();
    let build = audience("build-api");
    for n in 0..=workload::REVOKED_MAX {
        let credential = host
            .issue(issuance(&format!("i-{n}"), &operator, &build), at(0))
            .unwrap();
        let record = host.record(&credential);
        let revocation = Revocation {
            operation: op(&format!("rv-{n}")),
            by: &operator,
            target: Target::Credential(credential.serial(), &record),
        };
        let registration = host.registration().unwrap();
        let proposal = revocation.proposal(&registration, &Permits, &mut host.node.driver, at(1), Limits::default());
        if n < workload::REVOKED_MAX {
            let (proposal, plan) = proposal.unwrap();
            assert!(matches!(host.node.commit(proposal, plan), Outcome::Accepted(_)));
        } else {
            assert_eq!(proposal.err(), Some(Error::Revocations));
        }
    }
    assert!(matches!(
        host.revoke("rv-all", Target::All, at(1)),
        Outcome::Accepted(_)
    ));
}

#[test]
fn a_replacement_host_gets_a_credential_and_the_old_hosts_credential_refuses() {
    let mut host = Host::new(ceiling());
    let old = host.first("i-1");
    let (old_host, new_host) = (Custody::new(2), Custody::new(5));
    let (operator, build) = (host.operator.clone(), audience("build-api"));

    // A recovery that the old host races refuses with nothing released: it cannot revoke the old host's credential
    // that it did not read.
    let proof = new_host.prove_recovery(&new_host, &runner_id(), "rec-1", at(10));
    let (proposal, plan, awaiting, _) = host.signed(
        recovery("rec-1", &operator, &build, new_host.public(), &proof, b"rec-1"),
        at(10),
    );
    let renewed = host.renew("r-1", &old, &old_host, None, at(10)).unwrap();
    assert_eq!(
        awaiting.release(host.node.commit(proposal, plan)).err(),
        Some(Release::Conflict)
    );
    host.admits(&renewed, "build-api", at(11)).unwrap();

    // The recovery under the authority of the operator issues to the new host and revokes the old host in one commit.
    let proof = new_host.prove_recovery(&new_host, &runner_id(), "rec-2", at(11));
    let replacement = host
        .issue(
            recovery("rec-2", &operator, &build, new_host.public(), &proof, b"rec-2"),
            at(11),
        )
        .unwrap();
    host.admits(&replacement, "build-api", at(12)).unwrap();
    let profile = host.issuer().profile(&build, Limits::default()).unwrap();
    let verified = profile.verify(replacement.as_bytes(), at(12), &mut budget()).unwrap();
    let possession = new_host.prove(replacement.as_bytes(), &build, b"challenge-1", at(12));
    verified
        .possession(&possession, b"challenge-1", at(12), &mut budget())
        .unwrap();
    for credential in [&old, &renewed] {
        assert_eq!(host.admits(credential, "build-api", at(12)), Err(Error::Revoked));
        assert_eq!(
            host.renew("r-2", credential, &old_host, None, at(30)).err(),
            Some(Error::Possession)
        );
    }
}

#[test]
fn an_issuance_and_a_revocation_that_race_conflict_so_no_credential_survives_its_revocation() {
    let mut host = Host::new(ceiling());
    let first = host.first("i-1");
    let runner = Custody::new(2);

    // The revocation reads the registration first. A renewal with a later serial commits before it. The revocation
    // conflicts, because a revocation that committed would leave the renewed credential valid.
    let operator = host.operator.clone();
    let revocation = Revocation {
        operation: op("rv-1"),
        by: &operator,
        target: Target::All,
    };
    let registration = host.registration().unwrap();
    let (proposal, plan) = revocation
        .proposal(
            &registration,
            &Permits,
            &mut host.node.driver,
            at(30),
            Limits::default(),
        )
        .unwrap();
    let renewed = host.renew("r-1", &first, &runner, None, at(30)).unwrap();
    assert!(matches!(host.node.commit(proposal, plan), Outcome::Conflict));

    // A renewal that read the registration before a revocation commits conflicts, and it releases nothing.
    let build = audience("build-api");
    let bound = workload::binding(b"r-2", &op("r-2"), &authority(), &runner_id(), &build, None);
    let proof = runner.prove(renewed.as_bytes(), &build, &bound, at(31));
    let request = Request {
        operation: op("r-2"),
        by: By::Renew {
            credential: renewed.as_bytes(),
            proof: &proof,
            challenge: b"r-2",
        },
        audience: &build,
        lifetime: None,
        replace: None,
    };
    let (proposal, plan, awaiting, _) = host.signed(request, at(31));
    assert!(matches!(host.revoke("rv-2", Target::All, at(31)), Outcome::Accepted(_)));
    assert_eq!(
        awaiting.release(host.node.commit(proposal, plan)).err(),
        Some(Release::Conflict)
    );
    assert_eq!(host.admits(&renewed, "build-api", at(32)), Err(Error::Revoked));
}

#[test]
fn an_issuer_rotation_keeps_the_credentials_of_the_old_key_until_they_end_and_a_retired_key_refuses() {
    let mut host = Host::new(ceiling());
    let old = host.first("i-1");
    let (second, third) = (Custody::new(8), Custody::new(9));

    // A routine rotation: the old key verifies its credentials until they can end, and the new key signs.
    let outcome = host
        .rotate_issuer("ir-1", second.public(), Retire::AfterLifetime, at(10))
        .unwrap();
    assert!(matches!(outcome, Outcome::Accepted(_)));
    host.issuer = Custody::new(8);
    let new = host.first("i-2");
    host.admits(&old, "build-api", at(11)).unwrap();
    host.admits(&new, "build-api", at(11)).unwrap();

    // A second routine rotation waits for the end of the credentials of the previous key. A key of another algorithm
    // would change the declared profile of the audiences.
    assert_eq!(
        host.rotate_issuer("ir-2", third.public(), Retire::AfterLifetime, at(20))
            .err(),
        Some(Error::Overlap {
            until: START + minutes(70)
        })
    );
    let classical = Ed25519SecretKey::from_bytes([9; 32]).public_key().to_bytes();
    assert_eq!(
        host.rotate_issuer("ir-3", PublicKey::Ed25519(&classical), Retire::Now, at(20))
            .err(),
        Some(Error::Algorithm)
    );

    // A rotation that retires the old key at once: each credential of an earlier key refuses by its `kid`.
    let outcome = host.rotate_issuer("ir-4", third.public(), Retire::Now, at(20)).unwrap();
    assert!(matches!(outcome, Outcome::Accepted(_)));
    host.issuer = Custody::new(9);
    let retired = Err(Error::Credential(credential::Error::Cose(cose::Error::KeyId)));
    assert_eq!(host.admits(&old, "build-api", at(21)), retired);
    assert_eq!(host.admits(&new, "build-api", at(21)), retired);
    let current = host.first("i-3");
    host.admits(&current, "build-api", at(21)).unwrap();
}

#[test]
fn a_restore_from_a_snapshot_older_than_a_revocation_keeps_the_revoked_credential_refused() {
    let mut host = Host::new(ceiling());
    let first = host.first("i-1");
    let older = host.node.memory.snapshot();
    assert!(matches!(host.revoke("rv-1", Target::All, at(1)), Outcome::Accepted(_)));
    host.node.restore(&older);

    // The journal ends the registration that the snapshot holds, so no verifier that reads it admits the credential.
    assert_eq!(host.registration(), None);
    assert_eq!(host.admits(&first, "build-api", at(2)), Err(Error::Unregistered));

    // A new registration of the same key starts a new generation, so the revoked credential stays refused.
    let mut setup = proposal("register-again");
    let issuer = host.issuer();
    Registration::register(
        &mut setup,
        runner_id(),
        Custody::new(2).public(),
        &issuer,
        &mut host.node.driver,
    )
    .unwrap();
    assert!(matches!(host.node.commit(setup, Plan::default()), Outcome::Accepted(_)));
    assert_eq!(host.admits(&first, "build-api", at(2)), Err(Error::Revoked));
}

/// The bytes of the artifact of `draft`, which `signer` signs, from the accepted commit of its issuance record under
/// the operation `name`.
fn released(host: &mut Host, name: &str, draft: Draft, signer: &Custody) -> Vec<u8> {
    let mut issue = proposal(name);
    draft.record(&mut issue).unwrap();
    let signature = signer.sign(&draft.to_be_signed());
    issue.prepare(draft.finish(&signature, &mut budget()).unwrap()).unwrap();
    let Outcome::Accepted(receipt) = host.node.commit(issue, Plan::default()) else {
        panic!("the artifact did not commit");
    };
    receipt.artifact().unwrap().to_vec()
}

/// Each proof of a workload request binds its operation, its issuer, its workload, its audience, and its new key. An
/// unused proof of a renewal does not prove the current key for a rotation, and a proof of the current key for one new
/// key does not choose another new key.
#[test]
fn a_rotation_takes_only_a_proof_of_the_current_key_that_names_the_new_key() {
    let mut host = Host::new(ceiling());
    let first = host.first("i-1");
    let (runner, chosen, other) = (Custody::new(2), Custody::new(6), Custody::new(7));
    let build = audience("build-api");
    let bound = |key: Option<&PublicKey<'_>>, challenge: &[u8]| {
        workload::binding(challenge, &op("rot-1"), &authority(), &runner_id(), &build, key)
    };
    let renewal = runner.prove(first.as_bytes(), &build, &bound(None, b"rot-1"), at(10));
    let for_chosen = runner.prove(
        first.as_bytes(),
        &build,
        &bound(Some(&chosen.public()), b"rot-1"),
        at(10),
    );
    let other_key = other.public();
    let new_proof = other.prove_new(&other, &runner_id(), &bound(Some(&other_key), b"rot-1-new"), at(10));
    for old_proof in [&renewal, &for_chosen] {
        let request = Request {
            operation: op("rot-1"),
            by: By::Renew {
                credential: first.as_bytes(),
                proof: old_proof,
                challenge: b"rot-1",
            },
            audience: &build,
            lifetime: None,
            replace: Some(Replace {
                key: other.public(),
                proof: &new_proof,
                challenge: b"rot-1-new",
            }),
        };
        assert_eq!(
            host.issue(request, at(10)).err(),
            Some(Error::Credential(credential::Error::Proof))
        );
    }
    // The control: the proof of the current key that names the new key rotates to it.
    host.rotate("rot-2", &first, &runner, &other, &other, at(10)).unwrap();
}

/// A rotation and a recovery refuse the registered key as the new key, so the old host cannot keep its key. An issuer
/// rotation refuses the current key and the previous key as the new key.
#[test]
fn an_operation_refuses_the_key_that_it_retires_as_the_new_key() {
    let mut host = Host::new(ceiling());
    let first = host.first("i-1");
    let runner = Custody::new(2);
    assert_eq!(
        host.rotate("rot-1", &first, &runner, &runner, &runner, at(10)).err(),
        Some(Error::Unchanged)
    );
    let (operator, build) = (host.operator.clone(), audience("build-api"));
    let proof = runner.prove_recovery(&runner, &runner_id(), "rec-1", at(10));
    assert_eq!(
        host.issue(
            recovery("rec-1", &operator, &build, runner.public(), &proof, b"rec-1"),
            at(10)
        )
        .err(),
        Some(Error::Unchanged)
    );

    let current = Custody::new(1);
    for retire in [Retire::Now, Retire::AfterLifetime] {
        assert_eq!(
            host.rotate_issuer("ir-1", current.public(), retire, at(10)).err(),
            Some(Error::Unchanged)
        );
    }
    let second = Custody::new(8);
    assert!(matches!(
        host.rotate_issuer("ir-2", second.public(), Retire::AfterLifetime, at(10)),
        Ok(Outcome::Accepted(_))
    ));
    assert_eq!(
        host.rotate_issuer("ir-3", current.public(), Retire::Now, at(20)).err(),
        Some(Error::Unchanged)
    );
}

/// A verifier admits only a workload credential of the issuer of the registration whose `cnf` key is the registered
/// key. A signed artifact of the issuer that names the workload with no `cnf` key refuses, and so does a credential of
/// another issuer with a serial at or above the generation.
#[test]
fn a_verifier_admits_only_a_credential_of_the_issuer_with_the_registered_key() {
    let mut host = Host::new(ceiling());
    let first = host.first("i-1");
    let build = audience("build-api");
    // Each artifact has its own serial at or above the generation: one serial gives one artifact in one store.
    let claims = |issuer: Id<Authority>, ahead: u64| {
        Claims::new(
            issuer,
            build.clone(),
            Subject::Workload(runner_id()),
            workload::purpose(),
            Serial(first.serial().0 + ahead),
            START + minutes(60),
        )
    };
    let issuer_key = Custody::new(1);
    let draft = Draft::credential(&issuer_key.trusted(), &claims(authority(), 100), None, at(0)).unwrap();
    let receipt = released(&mut host, "receipt", draft, &issuer_key);
    let profile = host.issuer().profile(&build, Limits::default()).unwrap();
    let verified = profile.verify(&receipt, at(1), &mut budget()).unwrap();
    let registration = host.registration();
    assert_eq!(
        workload::admits(&verified, registration.as_ref(), Limits::default()),
        Err(Error::Possession)
    );

    let (other_key, other) = (Custody::new(4), Id::new("acme", "other-issuer").unwrap());
    let draft = Draft::credential(
        &other_key.trusted(),
        &claims(other.clone(), 101),
        Some(host.runner.public()),
        at(0),
    )
    .unwrap();
    let foreign = released(&mut host, "foreign", draft, &other_key);
    let profile = credential::Profile::new(
        other_key.trusted(),
        other,
        build.clone(),
        workload::purpose(),
        Limits::default(),
    )
    .unwrap();
    let verified = profile.verify(&foreign, at(1), &mut budget()).unwrap();
    assert_eq!(
        workload::admits(&verified, registration.as_ref(), Limits::default()),
        Err(Error::Possession)
    );
    // The control: the credential of the issuer with the registered key is admitted.
    host.admits(&first, "build-api", at(1)).unwrap();
}

/// The evidence of a credential gives no authority after the credential ends, also when the policy permits an older
/// authentication. The proposal of an issuance carries the deadline of its checked scope, so its commit after the end
/// of the credential of the operator refuses.
#[test]
fn an_issuance_after_the_end_of_the_credential_of_its_evidence_refuses() {
    let mut host = Host::new(ceiling());
    let (operator, build) = (host.operator.clone(), audience("build-api"));
    assert_eq!(operator.expires(), Some(START + minutes(60)));
    assert_eq!(
        host.issue(issuance("i-1", &operator, &build), at(60)).err(),
        Some(Error::Refusal(Refusal::Expired))
    );

    let (proposal, plan, awaiting, _) = host.signed(issuance("i-2", &operator, &build), at(59));
    host.node.memory.set_clock(at(60));
    assert_eq!(
        awaiting.release(host.node.commit(proposal, plan)).err(),
        Some(Release::Refused(rsauthnz::transition::Error::Expired))
    );
    // The control: the same issuance before the end commits.
    host.node.memory.set_clock(at(59));
    host.issue(issuance("i-3", &operator, &build), at(59)).unwrap();
}

#[test]
fn the_receipt_of_another_issuance_under_the_same_operation_releases_nothing() {
    let mut host = Host::new(ceiling());
    let (operator, build) = (host.operator.clone(), audience("build-api"));
    // Two issuances of one request under one operation, as a host makes after a lost response: each has its own serial
    // and its own credential. The receipt of the first one releases nothing through the second one.
    let (proposal, plan, _, _) = host.signed(issuance("i-1", &operator, &build), at(0));
    let (_, _, second, _) = host.signed(issuance("i-1", &operator, &build), at(1));
    assert_eq!(
        second.release(host.node.commit(proposal, plan)).err(),
        Some(Release::Operation)
    );
    // The control: the receipt of an issuance releases its own credential, with its own serial.
    let (proposal, plan, awaiting, _) = host.signed(issuance("i-2", &operator, &build), at(1));
    let serial = awaiting.serial();
    let credential = awaiting.release(host.node.commit(proposal, plan)).unwrap();
    let profile = host.issuer().profile(&build, Limits::default()).unwrap();
    let verified = profile.verify(credential.as_bytes(), at(1), &mut budget()).unwrap();
    assert_eq!((verified.claims().serial, credential.serial()), (serial, serial));
}

#[test]
fn the_same_request_under_two_issuers_binds_two_requests() {
    let mut host = Host::new(ceiling());
    let (operator, build) = (host.operator.clone(), audience("build-api"));
    host.issue(issuance("i-1", &operator, &build), at(0)).unwrap();
    // A second issuer, and the registration of the same workload under it, as a restore that registered the workload
    // again leaves it.
    let other = Id::new("acme", "authority-2").unwrap();
    let mut setup = proposal("setup-2");
    let record = Issuer::new(other.clone(), host.issuer.public(), vec![build.clone()], ceiling()).unwrap();
    record.register(&mut setup, &mut host.node.driver).unwrap();
    assert!(matches!(host.node.commit(setup, Plan::default()), Outcome::Accepted(_)));
    let issuer = host.node.read(&Issuer::store_key(&other)).unwrap();
    let registration = host.registration().unwrap();
    let version = AuthorityVersion::new(other, registration.version.coordinate()).unwrap();
    let registration = Record {
        version,
        ..registration
    };
    let pending = Pending::new(
        issuance("i-1", &operator, &build),
        &issuer,
        &registration,
        &Permits,
        &mut host.node.driver,
        at(1),
        Limits::default(),
    )
    .unwrap();
    let signature = host.issuer.sign(&pending.to_be_signed());
    let (proposal, plan, awaiting) = pending.finish(&signature, &mut budget()).unwrap();
    // The same operation identity and the same request under the other issuer is another request: it does not report
    // the commit of the first issuer.
    assert_eq!(
        awaiting.release(host.node.commit(proposal, plan)).err(),
        Some(Release::Refused(rsauthnz::transition::Error::Reuse))
    );
}
