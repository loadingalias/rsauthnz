//! The contracts of workload issuance and renewal: a credential is released only by the accepted commit of its own
//! operation, it verifies only for its audience and its issuer key with a proof by its registered key, a request past
//! the ceiling or outside the policy refuses, and a restore releases no serial twice.

use core::pin::pin;
use core::task::{Context, Poll, Waker};
use core::time::Duration;
use std::sync::LazyLock;

use rsauthnz::authz::{self, Permit, Policy, Refusal, Requirements};
use rsauthnz::cbor::Value;
use rsauthnz::cose::{self, PublicKey, TrustedKey};
use rsauthnz::credential::{self, Claims, Draft, ProofDraft, Serial, Subject};
use rsauthnz::crypto::Algorithm;
use rsauthnz::evidence::Evidence;
use rsauthnz::id::{Audience, Authority, AuthorityVersion, Human, Id, Principal, Workload};
use rsauthnz::limits::{Limits, SignatureBudget};
use rsauthnz::store::driver::{Answer, Driver, Lookup, PAGE, Plan};
use rsauthnz::store::{self, Journal, Kind, Profile, Record, Sequence, Store};
use rsauthnz::time::{Reading, ReadingSource};
use rsauthnz::transition::{Audit, Change, Dependency, Key, OperationId, Outcome, Proposal};
use rsauthnz::workload::{
    self, Awaiting, By, Ceiling, Credential, Error, Issuer, LIFETIME_DEFAULT, Mode, Pending, Registration, Request,
};
use rsauthnz_conformance::memory::{Memory, Schedule, Snapshot};
use rsauthnz_conformance::suite::{self, Fault, Subject as _};
use rscrypto::auth::{CompositeMlDsaError, MlDsa65Ed25519, MlDsa65Ed25519SecretKey};

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

/// The policy of the tests: the operator can issue, and the workload can renew, on the resource of the workload.
struct Permits;

impl Policy for Permits {
    fn version(&self) -> &AuthorityVersion {
        static VERSION: LazyLock<AuthorityVersion> = LazyLock::new(|| version(1));
        &VERSION
    }

    fn resolve(&self, request: &authz::Request<'_>) -> Option<Permit> {
        let permitted = match request.principal {
            Principal::Human(human) => *human == operator() && *request.action == Mode::Issue.action(),
            Principal::Workload(workload) => *workload == runner_id() && *request.action == Mode::Renew.action(),
            Principal::Agent(_) => false,
        };
        (permitted && *request.resource == workload::resource(&runner_id())).then(|| Permit {
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

    fn commit(&mut self, proposal: Proposal) -> Outcome {
        let ticket = self.driver.submit(proposal, Plan::default()).unwrap();
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
        for (key, data) in [
            (store::policy_key(&authority()), Box::from(*b"the policy")),
            (
                Issuer::store_key(&authority()),
                Issuer::new(authority(), issuer.public(), audiences, ceiling)
                    .unwrap()
                    .to_record(),
            ),
            (
                Registration::store_key(&runner_id()),
                Registration::new(runner_id(), runner.public()).unwrap().to_record(),
            ),
        ] {
            setup.read(Dependency::Absent(key.clone())).unwrap();
            let change = Change::Write {
                key,
                version: version(1),
                end: None,
                data,
            };
            setup.change(change).unwrap();
        }
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
        setup.prepare(draft.finish(&signature, &mut budget()).unwrap());
        let Outcome::Accepted(receipt) = node.commit(setup) else {
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

    /// The pending issuance of `request` at `now`, from the current records.
    fn pending(&mut self, request: Request<'_>, now: Reading) -> Result<Pending, Error> {
        let issuer = self.node.read(&Issuer::store_key(&authority())).unwrap();
        let registration = self.node.read(&Registration::store_key(&runner_id())).unwrap();
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

    /// The pending issuance of `request` at `now` that custody signed: its proposal, its release, and the signature.
    fn signed(&mut self, request: Request<'_>, now: Reading) -> (Proposal, Awaiting, Vec<u8>) {
        let pending = self.pending(request, now).unwrap();
        let signature = self.issuer.sign(&pending.to_be_signed());
        let (proposal, awaiting) = pending.finish(&signature, &mut budget()).unwrap();
        (proposal, awaiting, signature)
    }

    /// The credential of `request` at `now`, or the refusal of the issuance or of its commit.
    fn issue(&mut self, request: Request<'_>, now: Reading) -> Result<Credential, Error> {
        let pending = self.pending(request, now)?;
        let signature = self.issuer.sign(&pending.to_be_signed());
        let (proposal, awaiting) = pending.finish(&signature, &mut budget())?;
        let outcome = self.node.commit(proposal);
        awaiting.release(outcome)
    }

    /// The first issuance of the operation `name` by the operator, for `build-api` with the default lifetime.
    fn first(&mut self, name: &str) -> Credential {
        let (operator, build) = (self.operator.clone(), audience("build-api"));
        self.issue(issuance(name, &operator, &build), at(0)).unwrap()
    }

    /// The renewal of `credential` of the operation `name` at `now`, for `build-api` and `lifetime`, with a proof by
    /// `key`.
    fn renew(
        &mut self,
        name: &str,
        credential: &Credential,
        key: &Custody,
        lifetime: Option<Duration>,
        now: Reading,
    ) -> Result<Credential, Error> {
        let build = audience("build-api");
        let proof = key.prove(credential.as_bytes(), &build, name.as_bytes(), now);
        let request = Request {
            operation: op(name),
            by: By::Renew {
                credential: credential.as_bytes(),
                proof: &proof,
                challenge: name.as_bytes(),
            },
            audience: &build,
            lifetime,
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
    let other = other.profile(&build, Limits::default()).unwrap();
    assert_eq!(
        other.verify(credential.as_bytes(), now, &mut budget()).err(),
        Some(credential::Error::Cose(cose::Error::Signature))
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
    let (proposal, awaiting, signature) = host.signed(issuance("i-lost", &operator, &build), at(0));
    let serial = awaiting.serial();
    host.node.memory.inject(Fault::LostResponse);
    let outcome = host.node.commit(proposal);
    let Err(Error::Unknown(operation)) = awaiting.release(outcome) else {
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
    let mut records = vec![host.node.read(&workload::credential_key(serial)).unwrap()];
    for kind in [Kind::Audit, Kind::Outcome] {
        records.push(host.node.read(&kind.key(b"i-lost").unwrap()).unwrap());
    }
    assert!(records.iter().all(|record| !holds(&record.data, &signature)));
    let entries = ready(Journal::read(&mut host.node.memory, Sequence(0), PAGE)).unwrap();
    assert!(entries.iter().all(|entry| !holds(&entry.data, &signature)));

    // A new proposal of the same request under the same identity commits nothing, and it releases nothing.
    let (again, awaiting, _) = host.signed(issuance("i-lost", &operator, &build), at(0));
    let serial = awaiting.serial();
    assert_eq!(awaiting.release(host.node.commit(again)).err(), Some(Error::Committed));
    assert_eq!(host.node.read(&workload::credential_key(serial)), None);

    // A crash before the commit: the release gives no credential, and nothing committed.
    let (proposal, awaiting, _) = host.signed(issuance("i-crash", &operator, &build), at(0));
    let serial = awaiting.serial();
    host.node.memory.inject(Fault::CrashBeforeCommit);
    let outcome = host.node.commit(proposal);
    assert!(matches!(awaiting.release(outcome), Err(Error::Unknown(_))));
    host.node.start();
    assert_eq!(host.node.read(&workload::credential_key(serial)), None);

    // The control: the accepted commit releases the credential that custody signed, and it verifies.
    let (proposal, awaiting, signature) = host.signed(issuance("i-accepted", &operator, &build), at(0));
    let credential = awaiting.release(host.node.commit(proposal)).unwrap();
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

    // The application registers a new key. A proof by the earlier key of a credential that is still valid refuses.
    let key = Registration::store_key(&runner_id());
    let mut change = proposal("rotate");
    change.read(Dependency::Version(key.clone(), version(1))).unwrap();
    change
        .change(Change::Write {
            key,
            version: version(2),
            end: None,
            data: Registration::new(runner_id(), stolen.public()).unwrap().to_record(),
        })
        .unwrap();
    assert!(matches!(host.node.commit(change), Outcome::Accepted(_)));
    assert_eq!(
        host.renew("r-3", &first, &runner, None, at(30)).err(),
        Some(Error::Possession)
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
