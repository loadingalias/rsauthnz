//! The passkeys of WebAuthn Level 3: the published registration cases, the options of the profile, each refusal of a
//! response, one commit for each ceremony, the decision of the application in the credential commit, the completion of
//! a registration in doubt at a restore, the records of each relying party, and the sign-in.

#[path = "passkey/authenticator.rs"]
mod authenticator;
#[path = "passkey/vectors.rs"]
mod vectors;

use core::pin::pin;
use core::task::{Context, Poll, Waker};
use core::time::Duration;

use rsauthnz::cbor::{self, Value};
use rsauthnz::crypto::Algorithm;
use rsauthnz::crypto::Authentication;
use rsauthnz::evidence::{Backup, Evidence, Method};
use rsauthnz::id::{Authority, AuthorityVersion, Human, Id, Principal};
use rsauthnz::limits::Limits;
use rsauthnz::passkey::{self, Assertion, Error, Failure, RelyingParty, Response, SignIn, User, UserHandle};
use rsauthnz::store::driver::{Answer, Driver, Lookup, Plan};
use rsauthnz::store::{self, Kind, Profile, Record, Store};
use rsauthnz::time::{Reading, ReadingSource, TimeError};
use rsauthnz::transition::{self, Audit, Change, Dependency, Key, OperationId, Outcome, Proposal};
use rsauthnz_conformance::memory::{Memory, Schedule};
use rsauthnz_conformance::suite::{self, Fault, Subject as _};
use rscodec::base64::Profile::Url;
use rscrypto::ChaCha20Rng;

use authenticator::{
    ATTESTED, BACKUP_ELIGIBLE, BACKUP_STATE, EXTENSIONS, Get, Passkey, Registration, USER_PRESENT, USER_VERIFIED,
};
use vectors::Vector;

const START: Duration = Duration::from_secs(1_800_000_000);
const RP_ID: &str = "app.example";
const ORIGIN: &str = "https://app.example";
/// The HMAC key of the sign-in challenges of the relying party.
const KEY: [u8; 32] = [3; 32];
/// The user handle of alice.
const HANDLE: [u8; 32] = [9; 32];

/// The key of the pending record of the registration challenge `challenge` of [`rp`]: the documented digest of
/// `["rsauthnz.passkey.registration.1", authority, relying party ID, challenge]`.
fn ceremony(challenge: &[u8]) -> Key {
    let authority = authority();
    let form = Value::Array(vec![
        Value::Text("rsauthnz.passkey.registration.1"),
        authority.to_cbor(),
        Value::Text(RP_ID),
        Value::Bytes(challenge),
    ]);
    let form = cbor::encode(&form, Limits::default()).expect("a form");
    Kind::Registration.key(&rscrypto::Sha256::digest(&form)).expect("a key")
}

/// The reading at `seconds` past [`START`], with an uncertainty of one second.
fn at(seconds: u64) -> Reading {
    Reading::new(
        START + Duration::from_secs(seconds),
        Some(Duration::from_secs(1)),
        ReadingSource::Caller,
    )
}

/// The output of `future`. The futures of the memory binding are ready at their first poll.
fn ready<F: Future>(future: F) -> F::Output {
    match pin!(future).poll(&mut Context::from_waker(Waker::noop())) {
        Poll::Ready(output) => output,
        Poll::Pending => panic!("the memory binding does no I/O"),
    }
}

/// The bytes of the hexadecimal text `text`.
fn hex(text: &str) -> Vec<u8> {
    text.as_bytes()
        .chunks(2)
        .map(|pair| u8::from_str_radix(str::from_utf8(pair).expect("ASCII"), 16).expect("hexadecimal"))
        .collect()
}

fn alice() -> Id<Human> {
    Id::new("acme", "alice").expect("an identifier")
}

fn authority() -> Id<Authority> {
    Id::new("acme", "auth").expect("an identifier")
}

fn rp() -> RelyingParty {
    RelyingParty::new(authority(), RP_ID, ORIGIN, "Acme", KEY, Limits::default()).expect("a relying party")
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
        let driver = Driver::new(
            Profile::new(memory.declaration()).expect("a profile"),
            Limits::default(),
        )
        .expect("a driver");
        let mut node = Self { memory, driver };
        node.start();
        node
    }

    /// Executes each effect of the driver until it has none.
    fn run(&mut self) {
        while let Some(effect) = self.driver.effect() {
            let output = ready(suite::execute(&mut self.memory, effect));
            self.driver.give(output).expect("the driver takes the output");
        }
    }

    /// A start after a crash.
    fn start(&mut self) {
        self.driver.start(at(0));
        self.run();
    }

    fn commit(&mut self, proposal: Proposal, plan: Plan) -> Outcome {
        let ticket = self.driver.submit(proposal, plan).expect("a submission");
        self.run();
        match self.driver.take(ticket) {
            Some(Answer::Outcome(outcome)) => outcome,
            answer => panic!("the commit gave {answer:?}"),
        }
    }

    fn read(&mut self, key: &Key) -> Option<Record> {
        ready(Store::read(&mut self.memory, key)).expect("a read")
    }

    /// Commits the policy record of the authority at the version `to`, after the version `from` or no record, and
    /// gives the version.
    fn policy(&mut self, from: Option<&AuthorityVersion>, to: u64) -> AuthorityVersion {
        let key = store::policy_key(&authority());
        let version = AuthorityVersion::new(authority(), &to.to_be_bytes()).expect("a version");
        let audit = Audit {
            actor: Principal::Human(Id::new("acme", "admin").expect("an identifier")),
            action: Id::new("acme", "policy.change").expect("an identifier"),
            time: at(0),
        };
        let operation = OperationId::new(format!("policy-{to}").as_bytes()).expect("an operation identity");
        let mut proposal =
            Proposal::new(operation, audit, &Value::Unsigned(to), Limits::default()).expect("a proposal");
        let read = match from {
            Some(from) => Dependency::Version(key.clone(), from.clone()),
            None => Dependency::Absent(key.clone()),
        };
        proposal.read(read).expect("a read");
        let change = Change::Write {
            key,
            version: version.clone(),
            end: None,
            data: Box::from(*b"the policy"),
        };
        proposal.change(change).expect("a change");
        assert!(matches!(self.commit(proposal, Plan::default()), Outcome::Accepted(_)));
        version
    }
}

/// A site: its node, its relying party, and its random generator.
struct Site {
    node: Node,
    rp: RelyingParty,
    random: ChaCha20Rng,
}

impl Site {
    fn new() -> Self {
        Self {
            node: Node::new(),
            rp: rp(),
            random: ChaCha20Rng::from_seed([5; 32]),
        }
    }

    /// The start of a registration of `account` with the user handle `handle`.
    fn propose_start(&mut self, account: &Id<Human>, handle: [u8; 32]) -> Result<(Proposal, Plan), Error> {
        let user = User {
            account,
            handle: UserHandle::from_bytes(handle),
            name: "user@app.example",
            display_name: "User",
        };
        let start = self.rp.start(
            &mut self.node.memory,
            &user,
            &[],
            at(0),
            &mut self.random,
            &mut self.node.driver,
        );
        ready(start).map_err(refused)
    }

    /// Commits the start of a registration of `account` with the user handle `handle`, and gives its options.
    fn options_of(&mut self, account: &Id<Human>, handle: [u8; 32]) -> Vec<u8> {
        let (proposal, plan) = self.propose_start(account, handle).expect("a start");
        let Outcome::Accepted(receipt) = self.node.commit(proposal, plan) else {
            panic!("the start does not commit");
        };
        receipt.artifact().expect("the options").to_vec()
    }

    /// Commits the start of a registration of alice, and gives the challenge of its options.
    fn start(&mut self) -> Vec<u8> {
        authenticator::challenge(&self.options_of(&alice(), HANDLE))
    }

    /// Registers a passkey of `algorithm` for alice, with `alg` in its key and the counter `count`.
    fn register(&mut self, algorithm: Algorithm, alg: i64, seed: u8, count: u32) -> Passkey {
        let challenge = self.start();
        let passkey = Passkey::new(algorithm, alg, seed);
        let mut registration = Registration::new(&passkey, RP_ID, ORIGIN, challenge);
        registration.sign_count = count;
        let (proposal, plan) = self.propose(&registration.json(), at(1));
        assert!(matches!(self.node.commit(proposal, plan), Outcome::Accepted(_)));
        passkey
    }

    /// The challenge of new sign-in options at `now`.
    fn options(&mut self, now: Reading) -> Vec<u8> {
        authenticator::challenge(&self.rp.sign_in_options(now, &mut self.random).expect("the options"))
    }

    /// Proposes the sign-in of `json` at `now`.
    fn sign_in(&mut self, json: &[u8], now: Reading) -> Result<(Proposal, Plan, SignIn), Error> {
        let assertion = Assertion::parse(json)?;
        let sign_in = self.rp.sign_in(
            &mut self.node.memory,
            &assertion,
            now,
            &mut self.random,
            &mut self.node.driver,
        );
        ready(sign_in).map_err(refused)
    }

    /// The evidence of the accepted sign-in of `json` at `now`.
    fn signed_in(&mut self, json: &[u8], now: Reading) -> Evidence {
        let (proposal, plan, sign_in) = self.sign_in(json, now).expect("a sign-in");
        let outcome = self.node.commit(proposal, plan);
        sign_in.release(&outcome).expect("the evidence of the accepted sign-in")
    }

    /// The key of the credential record of the passkey `passkey` of alice.
    fn key(&self, passkey: &Passkey) -> Key {
        self.rp.credential_key(&UserHandle::from_bytes(HANDLE), &passkey.id)
    }

    /// The stored counter and backup state (BS) of `passkey`: the seventh and the ninth item of the documented form of
    /// the credential record.
    fn stored(&mut self, passkey: &Passkey) -> (u64, bool) {
        let record = self.node.read(&self.key(passkey)).expect("the credential record");
        let Ok(Value::Array(items)) = cbor::decode(&record.data, Limits::default()) else {
            panic!("a record form");
        };
        let (Value::Unsigned(count), Value::Bool(backed_up)) = (&items[6], &items[8]) else {
            panic!("a counter and a backup state");
        };
        (*count, *backed_up)
    }

    /// The finish of `json` with the pending record that the store holds.
    fn finish(&mut self, json: &[u8], now: Reading) -> Result<passkey::Registration, Error> {
        let response = Response::parse(json)?;
        let finish = self
            .rp
            .finish(&mut self.node.memory, &response, now, &mut self.node.driver);
        ready(finish).map_err(refused)
    }

    /// The commit of the finish of `json`, with a decision of the application that reads nothing.
    fn propose(&mut self, json: &[u8], now: Reading) -> (Proposal, Plan) {
        let registration = self.finish(json, now).expect("a finish");
        registration.propose(&[]).expect("a proposal")
    }
}

/// The refusal of a failure of an operation of the memory binding, which reads with no failure.
fn refused(failure: Failure<rsauthnz_conformance::memory::Error>) -> Error {
    match failure {
        Failure::Refused(error) => error,
        Failure::Store(error) => panic!("the memory binding failed a read: {error}"),
    }
}

/// The attestation object `attestation` with the UV flag set in its authenticator data. The format of the object is
/// unchanged, and nothing signs the flags of a registration with no attestation.
fn user_verified(attestation: &[u8]) -> Vec<u8> {
    let Ok(Value::Map(entries)) = cbor::decode(attestation, Limits::default()) else {
        panic!("an attestation object");
    };
    let Some((_, Value::Bytes(data))) = entries.iter().find(|(key, _)| *key == Value::Text("authData")) else {
        panic!("authenticator data");
    };
    let mut data = data.to_vec();
    data[32] |= USER_VERIFIED;
    let entries: Vec<_> = entries
        .iter()
        .map(|(key, value)| match key {
            Value::Text("authData") => (key.clone(), Value::Bytes(&data)),
            _ => (key.clone(), value.clone()),
        })
        .collect();
    cbor::encode(&Value::Map(entries), Limits::default()).expect("an attestation object")
}

/// The check of the published case `vector` at `example.org`, with the UV flag set if `verified`.
fn verify(vector: &Vector, verified: bool) -> Result<(Algorithm, bool, usize), Error> {
    let authority: Id<Authority> = Id::new("acme", "auth").expect("an identifier");
    let rp = RelyingParty::new(
        authority,
        "example.org",
        "https://example.org",
        "Example",
        KEY,
        Limits::default(),
    )
    .expect("a relying party");
    let mut attestation = hex(vector.attestation);
    if verified {
        attestation = user_verified(&attestation);
    }
    let json = authenticator::response(&hex(vector.credential_id), &hex(vector.client_data), &attestation, None);
    let challenge = hex(vector.challenge);
    let credential = rp.verify(&Response::parse(&json)?, &challenge)?;
    Ok((
        credential.algorithm(),
        credential.backup() != Backup::SingleDevice,
        credential.id().len(),
    ))
}

#[test]
fn the_published_registration_cases_verify_under_the_profile() {
    use vectors::*;
    let cases = [
        ("packed ES256", &PACKED_ES256, Ok((Algorithm::Es256, true, 32))),
        (
            "self-attested ES256",
            &PACKED_SELF_ES256,
            Ok((Algorithm::Es256, true, 32)),
        ),
        ("packed RS256", &PACKED_RS256, Ok((Algorithm::Rs256, true, 32))),
        // The profile requires user verification, and these cases do not set the UV flag.
        ("packed EdDSA", &PACKED_EDDSA, Err(Error::UserVerification)),
        ("ES256 with no attestation", &NONE_ES256, Err(Error::UserVerification)),
        (
            "a credential ID of 1,023 bytes",
            &NONE_ES256_LONG_CREDENTIAL_ID,
            Err(Error::UserVerification),
        ),
        // The profile refuses a ceremony in a frame of another origin.
        (
            "a cross-origin frame",
            &NONE_ES256_CROSS_ORIGIN,
            Err(Error::CrossOrigin),
        ),
        ("a top origin", &NONE_ES256_TOP_ORIGIN, Err(Error::CrossOrigin)),
    ];
    for (name, vector, expected) in cases {
        assert_eq!(verify(vector, false), expected, "{name}");
    }
}

/// Derived cases, not published evidence: the UV bit changes the authenticator data, which the attestation signature of
/// packed EdDSA covers, so that signature no longer verifies. The profile reads no attestation statement.
#[test]
fn a_published_case_with_only_the_uv_bit_set_passes_each_other_check() {
    use vectors::*;
    let verified = [
        ("packed EdDSA", &PACKED_EDDSA, (Algorithm::Ed25519, false, 32)),
        ("ES256 with no attestation", &NONE_ES256, (Algorithm::Es256, true, 32)),
        (
            "a credential ID of 1,023 bytes",
            &NONE_ES256_LONG_CREDENTIAL_ID,
            (Algorithm::Es256, true, 1023),
        ),
    ];
    for (name, vector, expected) in verified {
        assert_eq!(verify(vector, true), Ok(expected), "{name}");
    }
}

#[test]
fn the_options_offer_the_profile_and_release_only_after_the_start_commits() {
    let mut site = Site::new();
    let (proposal, plan) = site.propose_start(&alice(), HANDLE).expect("a start");
    // A lost response releases no options: the browser gets no challenge whose record may not exist.
    site.node.memory.inject(Fault::LostResponse);
    assert!(matches!(site.node.commit(proposal, plan), Outcome::Unknown(_)));
    site.node.start();

    let options = &site.options_of(&alice(), HANDLE)[..];
    let mut text = [0; 43];
    let challenge = Url
        .encode(&authenticator::challenge(options), &mut text)
        .expect("base64url")
        .to_vec();
    let challenge = String::from_utf8(challenge).expect("ASCII");
    let handle = "CQkJCQkJCQkJCQkJCQkJCQkJCQkJCQkJCQkJCQkJCQk";
    let expected = format!(
        concat!(
            r#"{{"rp":{{"id":"app.example","name":"Acme"}},"#,
            r#""user":{{"id":"{handle}","name":"user@app.example","displayName":"User"}},"#,
            r#""challenge":"{challenge}","#,
            r#""pubKeyCredParams":[{{"type":"public-key","alg":-49}},{{"type":"public-key","alg":-8}},"#,
            r#"{{"type":"public-key","alg":-7}},{{"type":"public-key","alg":-257}}],"#,
            r#""timeout":300000,"excludeCredentials":[],"attestation":"none","#,
            r#""authenticatorSelection":{{"residentKey":"required","requireResidentKey":true,"userVerification":"required"}},"#,
            r#""extensions":{{"credProps":true}}}}"#
        ),
        handle = handle,
        challenge = challenge,
    );
    assert_eq!(str::from_utf8(options), Ok(expected.as_str()));
}

#[test]
fn each_algorithm_of_the_profile_registers_through_the_ceremony() {
    let mut site = Site::new();
    let cases = [
        (Algorithm::MlDsa65, -49, 1),
        (Algorithm::Ed25519, -8, 2),
        (Algorithm::Es256, -7, 3),
        // The fully specified identifiers: Ed25519 and ESP256.
        (Algorithm::Ed25519, -19, 4),
        (Algorithm::Es256, -9, 5),
    ];
    for (algorithm, alg, seed) in cases {
        let challenge = site.start();
        let passkey = Passkey::new(algorithm, alg, seed);
        let json = Registration::new(&passkey, RP_ID, ORIGIN, challenge.clone()).json();
        let registration = site.finish(&json, at(1)).expect("a finish");
        assert_eq!(registration.credential().algorithm(), algorithm, "{alg}");
        let (proposal, plan) = registration.propose(&[]).expect("a proposal");
        let ceremony = ceremony(&challenge);
        assert!(
            matches!(site.node.commit(proposal, plan), Outcome::Accepted(_)),
            "{alg}"
        );
        // One commit consumed the ceremony and wrote the credential.
        assert_eq!(site.node.read(&ceremony), None, "{alg}");
        let record = site.node.read(&site.key(&passkey)).expect("the credential record");
        assert_eq!(record.end, None, "{alg}");
    }
}

#[test]
fn a_response_that_differs_from_the_ceremony_or_the_profile_refuses() {
    let rp = rp();
    let challenge = vec![7; 32];
    let passkey = Passkey::new(Algorithm::Es256, -7, 1);
    let check = |registration: &Registration<'_>| rp.verify(&Response::parse(&registration.json())?, &challenge);
    let base = || Registration::new(&passkey, RP_ID, ORIGIN, challenge.clone());
    check(&base()).unwrap();

    let mut cases: Vec<(&str, Registration<'_>, Error)> = Vec::new();
    let mut case = |name, change: &dyn Fn(&mut Registration<'_>), error| {
        let mut registration = base();
        change(&mut registration);
        cases.push((name, registration, error));
    };
    case("another challenge", &|r| r.challenge = vec![8; 32], Error::Challenge);
    case(
        "another origin",
        &|r| r.origin = "https://attacker.example",
        Error::Origin,
    );
    case(
        "a subdomain origin",
        &|r| r.origin = "https://login.app.example",
        Error::Origin,
    );
    case("a cross-origin frame", &|r| r.cross_origin = true, Error::CrossOrigin);
    case("a sign-in", &|r| r.kind = "webauthn.get", Error::Malformed);
    case(
        "another relying party ID",
        &|r| r.rp_id = "attacker.example",
        Error::RelyingParty,
    );
    case("no user presence", &|r| r.flags &= !USER_PRESENT, Error::UserPresence);
    case(
        "no user verification",
        &|r| r.flags &= !USER_VERIFIED,
        Error::UserVerification,
    );
    case(
        "a backup state with no backup eligibility",
        &|r| r.flags &= !BACKUP_ELIGIBLE,
        Error::Malformed,
    );
    case(
        "no attested credential data",
        &|r| r.flags &= !ATTESTED,
        Error::Malformed,
    );
    case(
        "a credential that is not discoverable",
        &|r| r.discoverable = Some(false),
        Error::NotDiscoverable,
    );
    case(
        "an extension flag with no extensions",
        &|r| r.flags |= EXTENSIONS,
        Error::Malformed,
    );
    case(
        "extension outputs that are not a map",
        &|r| {
            r.flags |= EXTENSIONS;
            r.extensions = Some(vec![0x01]);
        },
        Error::Malformed,
    );
    case(
        "extensions with no extension flag",
        &|r| r.extensions = Some(vec![0xa0]),
        Error::Malformed,
    );
    for (name, registration, error) in &cases {
        assert_eq!(check(registration).err(), Some(*error), "{name}");
    }

    // An unsolicited extension output is ignored, and a browser with no `credProps` registers.
    let mut registration = base();
    registration.flags |= EXTENSIONS;
    registration.extensions = Some(
        cbor::encode(
            &Value::Map(vec![(Value::Text("credProtect"), Value::Unsigned(2))]),
            Limits::default(),
        )
        .expect("extension outputs"),
    );
    registration.discoverable = None;
    check(&registration).unwrap();

    // A credential ID longer than 1,023 bytes, and a composite key, which no passkey profile offers.
    let mut long = Passkey::new(Algorithm::Es256, -7, 1);
    long.id = vec![1; 1024];
    let registration = Registration::new(&long, RP_ID, ORIGIN, challenge.clone());
    assert_eq!(check(&registration).err(), Some(Error::CredentialId));
    let mut composite = Passkey::new(Algorithm::MlDsa65, -49, 1);
    let Ok(Value::Map(mut members)) = cbor::decode(&composite.cose_key, Limits::default()) else {
        panic!("a COSE_Key");
    };
    let public = vec![0; 1984];
    for (key, value) in &mut members {
        if *key == authenticator::int(3) {
            *value = authenticator::int(-51_000);
        } else if *key == authenticator::int(-1) {
            *value = Value::Bytes(&public);
        }
    }
    composite.cose_key = cbor::encode(&Value::Map(members), Limits::default()).expect("a COSE_Key");
    let registration = Registration::new(&composite, RP_ID, ORIGIN, challenge.clone());
    assert_eq!(check(&registration).err(), Some(Error::Algorithm));
}

#[test]
fn a_passkey_reports_its_backup_flags_and_no_binding() {
    let rp = rp();
    let passkey = Passkey::new(Algorithm::Ed25519, -8, 1);
    let mut registration = Registration::new(&passkey, RP_ID, ORIGIN, vec![7; 32]);
    let check = |registration: &Registration<'_>| {
        let credential = rp.verify(&Response::parse(&registration.json())?, &[7; 32])?;
        Ok::<_, Error>(credential.backup())
    };
    assert_eq!(check(&registration), Ok(Backup::BackedUp));
    registration.flags &= !BACKUP_STATE;
    assert_eq!(check(&registration), Ok(Backup::Eligible));
    registration.flags &= !BACKUP_ELIGIBLE;
    assert_eq!(check(&registration), Ok(Backup::SingleDevice));

    // An authenticator that reports BE=0 proves no binding: nothing attests where its key lives.
    let mut site = Site::new();
    registration.challenge = site.start();
    let (proposal, plan) = site.propose(&registration.json(), at(1));
    assert!(matches!(site.node.commit(proposal, plan), Outcome::Accepted(_)));
    let mut get = Get::new(&passkey, RP_ID, ORIGIN, site.options(at(10)), HANDLE);
    get.flags &= !(BACKUP_ELIGIBLE | BACKUP_STATE);
    let evidence = site.signed_in(&get.json(), at(11));
    assert_eq!(
        (evidence.backup(), evidence.binding()),
        (Some(Backup::SingleDevice), None)
    );
}

#[test]
fn a_ceremony_commits_once_and_its_challenge_refuses_after_it() {
    let mut site = Site::new();
    let challenge = site.start();
    let (first, second) = (
        Passkey::new(Algorithm::Es256, -7, 1),
        Passkey::new(Algorithm::Es256, -7, 2),
    );
    // A twin of the first passkey: the same credential ID, and another key.
    let mut twin = Passkey::new(Algorithm::Es256, -7, 3);
    twin.id.clone_from(&first.id);
    let json = |passkey| Registration::new(passkey, RP_ID, ORIGIN, challenge.clone()).json();
    let (first_json, second_json, twin_json) = (json(&first), json(&second), json(&twin));
    // Four finishes of one ceremony read its pending record before any one commits: the first response, another
    // passkey, the twin, and the first response again.
    let ceremony = ceremony(&challenge);
    let tickets = [&first_json, &second_json, &twin_json, &first_json].map(|json| {
        let (proposal, plan) = site.propose(json, at(1));
        site.node.driver.submit(proposal, plan).expect("a submission")
    });
    site.node.run();
    let outcomes = tickets.map(|ticket| match site.node.driver.take(ticket) {
        Some(Answer::Outcome(outcome)) => outcome,
        answer => panic!("the commit gave {answer:?}"),
    });
    // Only the same response gets the receipt of the commit. The twin refuses, because its key was not stored.
    assert!(matches!(outcomes[0], Outcome::Accepted(_)));
    for outcome in &outcomes[1..3] {
        assert!(
            matches!(outcome, Outcome::Refused(transition::Error::Reuse)),
            "{outcome:?}"
        );
    }
    assert!(matches!(outcomes[3], Outcome::Accepted(_)));
    assert!(site.node.read(&site.key(&first)).is_some());
    assert_eq!(site.node.read(&site.key(&second)), None);
    // The commit consumed the challenge, so no later finish finds its ceremony.
    assert_eq!(site.node.read(&ceremony), None);
    assert_eq!(site.finish(&second_json, at(2)).err(), Some(Error::Challenge));
    assert_eq!(site.finish(&first_json, at(2)).err(), Some(Error::Challenge));
}

#[test]
fn a_pending_registration_ends_after_its_lifetime() {
    let mut site = Site::new();
    let challenge = site.start();
    let passkey = Passkey::new(Algorithm::Ed25519, -8, 1);
    let json = Registration::new(&passkey, RP_ID, ORIGIN, challenge).json();
    let late = at(passkey::REGISTRATION_LIFETIME.as_secs());
    assert_eq!(site.finish(&json, late).err(), Some(Error::Challenge));
    assert_eq!(Error::Challenge.recovery(), transition::Recovery::Restart);
}

#[test]
fn a_registration_in_doubt_completes_once_at_restore() {
    let mut site = Site::new();
    let challenge = site.start();
    let snapshot = site.node.memory.snapshot();
    let passkey = Passkey::new(Algorithm::MlDsa65, -49, 1);
    let json = Registration::new(&passkey, RP_ID, ORIGIN, challenge.clone()).json();
    let (proposal, plan) = site.propose(&json, at(1));
    let operation = proposal.operation().clone();
    // The commit lands, and its response is lost. Then the store comes back from the snapshot before the commit.
    site.node.memory.inject(Fault::LostResponse);
    assert!(matches!(site.node.commit(proposal, plan), Outcome::Unknown(_)));
    site.node.memory.restore(&snapshot);
    site.node.driver.restore(at(0)).expect("a restore");
    site.node.run();

    // The restored store holds the passkey of alice, and the ceremony is consumed.
    assert!(site.node.read(&site.key(&passkey)).is_some());
    let ceremony = ceremony(&challenge);
    assert_eq!(site.node.read(&ceremony), None);
    let ticket = site.node.driver.lookup(operation).expect("a lookup");
    site.node.run();
    assert!(matches!(
        site.node.driver.take(ticket),
        Some(Answer::Lookup(Lookup::Committed(_)))
    ));
    // The same response again commits nothing: its ceremony is consumed.
    assert_eq!(site.finish(&json, at(2)).err(), Some(Error::Challenge));
}

#[test]
fn a_decision_read_that_changes_before_the_credential_commit_stops_it() {
    let mut site = Site::new();
    // The policy of the authority permits the registration at its first version.
    let permitted = site.node.policy(None, 1);
    let challenge = site.start();
    let passkey = Passkey::new(Algorithm::Es256, -7, 1);
    let json = Registration::new(&passkey, RP_ID, ORIGIN, challenge).json();
    let registration = site.finish(&json, at(1)).expect("a finish");
    assert_eq!(registration.account(), &alice());
    let (proposal, plan) = registration
        .propose(&[Dependency::Policy(permitted.clone())])
        .expect("a proposal");
    // A policy change after the decision ends the permission before the commit.
    let changed = site.node.policy(Some(&permitted), 2);
    assert!(matches!(site.node.commit(proposal, plan), Outcome::Conflict));
    let key = site.key(&passkey);
    assert_eq!(site.node.read(&key), None);
    // The control: a decision at the current policy commits the same response.
    let (proposal, plan) = site
        .finish(&json, at(2))
        .expect("a finish")
        .propose(&[Dependency::Policy(changed)])
        .expect("a proposal");
    assert!(matches!(site.node.commit(proposal, plan), Outcome::Accepted(_)));
    assert!(site.node.read(&key).is_some());
}

#[test]
fn records_of_one_relying_party_serve_no_other_relying_party_of_the_store() {
    let mut site = Site::new();
    let new = |authority, id, origin| {
        RelyingParty::new(authority, id, origin, "Other", KEY, Limits::default()).expect("a relying party")
    };
    let globex = Id::new("globex", "auth").expect("an identifier");
    let others = [
        (
            new(authority(), "other.example", "https://other.example"),
            "other.example",
            "https://other.example",
        ),
        (new(globex, RP_ID, ORIGIN), RP_ID, ORIGIN),
    ];
    let challenge = site.start();
    let passkey = Passkey::new(Algorithm::Es256, -7, 1);
    for (other, id, origin) in &others {
        // A response of the other relying party with the challenge of this one finds no pending record.
        let response =
            Response::parse(&Registration::new(&passkey, id, origin, challenge.clone()).json()).expect("a response");
        let finish = other.finish(&mut site.node.memory, &response, at(1), &mut site.node.driver);
        assert_eq!(ready(finish).map_err(refused).err(), Some(Error::Challenge), "{id}");
    }
    // The control: this relying party finishes its ceremony.
    let (proposal, plan) = site.propose(&Registration::new(&passkey, RP_ID, ORIGIN, challenge).json(), at(1));
    assert!(matches!(site.node.commit(proposal, plan), Outcome::Accepted(_)));

    for (other, id, origin) in &others {
        // An assertion of the passkey for the other relying party finds no credential record there.
        let options = other.sign_in_options(at(10), &mut site.random).expect("the options");
        let get = Get::new(&passkey, id, origin, authenticator::challenge(&options), HANDLE);
        let assertion = Assertion::parse(&get.json()).expect("an assertion");
        let sign_in = other.sign_in(
            &mut site.node.memory,
            &assertion,
            at(11),
            &mut site.random,
            &mut site.node.driver,
        );
        assert_eq!(ready(sign_in).map_err(refused).err(), Some(Error::Credential), "{id}");
    }
    // The control: the passkey signs in at this relying party.
    let get = Get::new(&passkey, RP_ID, ORIGIN, site.options(at(10)), HANDLE);
    site.signed_in(&get.json(), at(11));
}

#[test]
fn the_options_exclude_each_passkey_of_the_account() {
    let mut site = Site::new();
    let first = site.register(Algorithm::Es256, -7, 1, 0);
    let second = site.register(Algorithm::Ed25519, -8, 2, 0);
    // A passkey of bob, another account of the store.
    let bob = Id::new("acme", "bob").expect("an identifier");
    let challenge = authenticator::challenge(&site.options_of(&bob, [8; 32]));
    let other = Passkey::new(Algorithm::Es256, -7, 3);
    let (proposal, plan) = site.propose(&Registration::new(&other, RP_ID, ORIGIN, challenge).json(), at(1));
    assert!(matches!(site.node.commit(proposal, plan), Outcome::Accepted(_)));

    // The options of alice list each of her passkeys with the transports of its registration, and no passkey of bob.
    let options = String::from_utf8(site.options_of(&alice(), HANDLE)).expect("UTF-8");
    let descriptor = |passkey: &Passkey| {
        let mut text = [0; 32];
        let id = Url.encode(&passkey.id, &mut text).expect("base64url");
        let id = str::from_utf8(id).expect("ASCII");
        format!(r#"{{"type":"public-key","id":"{id}","transports":["hybrid","internal"]}}"#)
    };
    for passkey in [&first, &second] {
        assert!(options.contains(&descriptor(passkey)), "{options}");
    }
    assert!(!options.contains(&descriptor(&other)), "{options}");
    assert_eq!(options.matches(r#"{"type":"public-key","id""#).count(), 2);

    // An account holds at most `CREDENTIALS_MAX` passkeys, so the options always list each one.
    for seed in 4..=u8::try_from(passkey::CREDENTIALS_MAX + 1).expect("a small bound") {
        site.register(Algorithm::Es256, -7, seed, 0);
    }
    assert_eq!(site.propose_start(&alice(), HANDLE).err(), Some(Error::Full));
    site.propose_start(&bob, [8; 32]).unwrap();
}

#[test]
fn the_credential_record_holds_only_the_checked_public_key() {
    let mut site = Site::new();
    let challenge = site.start();
    let mut passkey = Passkey::new(Algorithm::Es256, -7, 1);
    let original = passkey.cose_key.clone();
    let Ok(Value::Map(members)) = cbor::decode(&original, Limits::default()) else {
        panic!("a COSE_Key");
    };
    let member = |label: i64| {
        let found = members.iter().find(|(key, _)| *key == authenticator::int(label));
        found.map(|(_, value)| value.clone()).expect("a member")
    };
    // The public parameters of an EC2 key of RFC 9053: `kty`, `alg`, `crv`, `x`, and `y`.
    let public = Value::Map(vec![
        (authenticator::int(1), Value::Unsigned(2)),
        (authenticator::int(3), authenticator::int(-7)),
        (authenticator::int(-1), Value::Unsigned(1)),
        (authenticator::int(-2), member(-2)),
        (authenticator::int(-3), member(-3)),
    ]);
    let expected = cbor::encode(&public, Limits::default()).expect("a COSE_Key");
    // The authenticator adds a key ID and a member that no check reads.
    let mut extended = members.clone();
    extended.push((authenticator::int(2), Value::Bytes(b"kid")));
    extended.push((authenticator::int(-70), Value::Bytes(b"not read")));
    passkey.cose_key = cbor::encode(&Value::Map(extended), Limits::default()).expect("a COSE_Key");
    let (proposal, plan) = site.propose(&Registration::new(&passkey, RP_ID, ORIGIN, challenge).json(), at(1));
    assert!(matches!(site.node.commit(proposal, plan), Outcome::Accepted(_)));

    let record = site.node.read(&site.key(&passkey)).expect("the credential record");
    let Ok(Value::Array(items)) = cbor::decode(&record.data, Limits::default()) else {
        panic!("a record form");
    };
    assert_eq!(items[4], Value::Bytes(&expected));
    // The passkey signs in with the stored key.
    let get = Get::new(&passkey, RP_ID, ORIGIN, site.options(at(10)), HANDLE);
    site.signed_in(&get.json(), at(11));
}

#[test]
fn a_sign_in_stores_a_new_backup_state() {
    let mut site = Site::new();
    // A passkey that can be backed up, with no backup yet and no counter.
    let challenge = site.start();
    let passkey = Passkey::new(Algorithm::Ed25519, -8, 1);
    let mut registration = Registration::new(&passkey, RP_ID, ORIGIN, challenge);
    registration.flags &= !BACKUP_STATE;
    let (proposal, plan) = site.propose(&registration.json(), at(1));
    assert!(matches!(site.node.commit(proposal, plan), Outcome::Accepted(_)));
    assert_eq!(site.stored(&passkey), (0, false));
    // The provider backs it up: the next assertion sets BS, and the counter stays 0.
    let get = Get::new(&passkey, RP_ID, ORIGIN, site.options(at(10)), HANDLE);
    assert_eq!(site.signed_in(&get.json(), at(11)).backup(), Some(Backup::BackedUp));
    assert_eq!(site.stored(&passkey), (0, true));
}

#[test]
fn a_relying_party_takes_only_an_origin_of_its_id() {
    let authority: Id<Authority> = Id::new("acme", "auth").expect("an identifier");
    let new = |id: &str, origin: &str| {
        RelyingParty::new(authority.clone(), id, origin, "Acme", KEY, Limits::default()).map(drop)
    };
    for (id, origin) in [
        ("app.example", "https://app.example"),
        ("app.example", "https://login.app.example"),
        ("app.example", "https://app.example:8443"),
        ("localhost", "http://localhost:8080"),
        ("localhost", "https://localhost"),
    ] {
        assert_eq!(new(id, origin), Ok(()), "{id} {origin}");
    }
    for (id, origin) in [
        ("app.example", "https://attackerapp.example"),
        ("app.example", "https://example"),
        ("app.example", "http://app.example"),
        ("app.example", "https://app.example:443"),
        ("app.example", "https://app.example/"),
        ("app.example", "https://App.example"),
        ("App.example", "https://App.example"),
        ("localhost", "http://localhost:80"),
        ("example.com", "https://login.app.example"),
    ] {
        assert_eq!(new(id, origin), Err(Error::RelyingParty), "{id} {origin}");
    }
}

#[test]
fn each_counter_case_gives_its_stored_value_and_signal() {
    let mut site = Site::new();
    // The stored counter, the received counter, the stored counter after the sign-in, and the possible-clone signal.
    let cases = [
        (0, 0, 0, false),
        (0, 5, 5, false),
        (3, 5, 5, false),
        (5, 5, 5, true),
        (5, 3, 5, true),
        (5, 0, 5, true),
    ];
    for (seed, (stored, received, after, signal)) in (1..).zip(cases) {
        let passkey = site.register(Algorithm::Es256, -7, seed, stored);
        let mut get = Get::new(&passkey, RP_ID, ORIGIN, site.options(at(10)), HANDLE);
        get.sign_count = received;
        let evidence = site.signed_in(&get.json(), at(11));
        assert_eq!(
            (site.stored(&passkey).0, evidence.possible_clone()),
            (after, signal),
            "{stored}, then {received}"
        );
    }
}

#[test]
fn two_concurrent_sign_ins_with_counters_5_and_4_store_5_and_signal_on_4() {
    let mut site = Site::new();
    let passkey = site.register(Algorithm::Es256, -7, 1, 1);
    let mut five = Get::new(&passkey, RP_ID, ORIGIN, site.options(at(10)), HANDLE);
    five.sign_count = 5;
    let mut four = Get::new(&passkey, RP_ID, ORIGIN, site.options(at(10)), HANDLE);
    four.sign_count = 4;
    let (five, four) = (five.json(), four.json());
    // Both sign-ins read the credential record before either one commits.
    let (one, one_plan, first) = site.sign_in(&five, at(11)).expect("a sign-in");
    let (two, two_plan, _) = site.sign_in(&four, at(11)).expect("a sign-in");
    let outcome = site.node.commit(one, one_plan);
    assert!(
        first
            .release(&outcome)
            .is_some_and(|evidence| !evidence.possible_clone())
    );
    assert!(matches!(site.node.commit(two, two_plan), Outcome::Conflict));
    // The conflict restarts the sign-in: it reads the record again, and its challenge is still open.
    assert!(site.signed_in(&four, at(12)).possible_clone());
    assert_eq!(site.stored(&passkey).0, 5);
}

#[test]
fn a_lost_sign_in_response_resolves_by_a_lookup_of_the_server() {
    let mut site = Site::new();
    let passkey = site.register(Algorithm::Ed25519, -8, 1, 0);
    // The commit lands and its response is lost: the unknown outcome releases nothing.
    let json = Get::new(&passkey, RP_ID, ORIGIN, site.options(at(10)), HANDLE).json();
    let (proposal, plan, sign_in) = site.sign_in(&json, at(11)).expect("a sign-in");
    site.node.memory.inject(Fault::LostResponse);
    let outcome = site.node.commit(proposal, plan);
    assert!(matches!(outcome, Outcome::Unknown(_)));
    assert_eq!(sign_in.release(&outcome), None);
    site.node.start();
    // The browser holds no operation of a sign-in. The server keeps the sign-in, looks up its operation when the driver
    // serves again, and gives the evidence to the same request.
    let json = Get::new(&passkey, RP_ID, ORIGIN, site.options(at(20)), HANDLE).json();
    let (proposal, plan, sign_in) = site.sign_in(&json, at(21)).expect("a sign-in");
    let operation = proposal.operation().clone();
    site.node.memory.inject(Fault::LostResponse);
    assert!(matches!(site.node.commit(proposal, plan), Outcome::Unknown(_)));
    site.node.start();
    let ticket = site.node.driver.lookup(operation).expect("a lookup");
    site.node.run();
    let Some(Answer::Lookup(Lookup::Committed(receipt))) = site.node.driver.take(ticket) else {
        panic!("the lookup shows the commit");
    };
    let evidence = sign_in
        .release(&Outcome::Accepted(receipt))
        .expect("the evidence of the commit");
    assert_eq!(evidence.subject(), &Principal::Human(alice()));
    // The same assertion again refuses, because its challenge served the commit.
    assert_eq!(site.sign_in(&json, at(22)).err(), Some(Error::Challenge));
}

#[test]
fn each_algorithm_of_the_profile_signs_in_and_reports_its_authentication() {
    let mut site = Site::new();
    let cases = [
        (Algorithm::MlDsa65, -49, Authentication::PostQuantum),
        (Algorithm::Ed25519, -8, Authentication::Classical),
        (Algorithm::Es256, -7, Authentication::Classical),
    ];
    for (seed, (algorithm, alg, authentication)) in (1..).zip(cases) {
        let passkey = site.register(algorithm, alg, seed, 0);
        // A signature of another key of the same algorithm refuses.
        let mut stranger = Passkey::new(algorithm, alg, seed + 100);
        stranger.id.clone_from(&passkey.id);
        let forged = Get::new(&stranger, RP_ID, ORIGIN, site.options(at(10)), HANDLE).json();
        assert_eq!(
            site.sign_in(&forged, at(11)).err(),
            Some(Error::Signature),
            "{algorithm:?}"
        );
        let challenge = site.options(at(10));
        let evidence = site.signed_in(&Get::new(&passkey, RP_ID, ORIGIN, challenge, HANDLE).json(), at(11));
        assert_eq!(evidence.subject(), &Principal::Human(alice()), "{algorithm:?}");
        assert_eq!(
            (
                evidence.method(),
                evidence.user_verified(),
                evidence.phishing_resistant()
            ),
            (Method::Passkey, true, true)
        );
        // A synchronized passkey reports its backup, and no binding.
        assert_eq!(
            (evidence.backup(), evidence.binding(), evidence.authentication()),
            (Some(Backup::BackedUp), None, Some(authentication))
        );
    }
}

#[test]
fn a_sign_in_challenge_from_before_a_restore_refuses_after_it() {
    let mut site = Site::new();
    let passkey = site.register(Algorithm::Ed25519, -8, 1, 0);
    let snapshot = site.node.memory.snapshot();
    let before = Get::new(&passkey, RP_ID, ORIGIN, site.options(at(10)), HANDLE).json();
    // At the true time 15, a clock that runs 10 seconds fast within its bound of 11 seconds reads 25.
    let fast = Reading::new(
        START + Duration::from_secs(25),
        Some(Duration::from_secs(11)),
        ReadingSource::Caller,
    );
    let fast = Get::new(&passkey, RP_ID, ORIGIN, site.options(fast), HANDLE).json();
    site.node.memory.restore(&snapshot);
    site.node.driver.restore(at(20)).expect("a restore");
    site.node.run();
    assert_eq!(site.sign_in(&before, at(21)).err(), Some(Error::Challenge));
    // The estimate 25 is later than the floor of the restore (20 and twice its bound), but the challenge is older.
    assert_eq!(site.sign_in(&fast, at(30)).err(), Some(Error::Challenge));
    // A reading with no bound cannot show that a challenge is later than a restore, so it gives none.
    let unbounded = Reading::new(START + Duration::from_secs(30), None, ReadingSource::Caller);
    assert_eq!(
        site.rp.sign_in_options(unbounded, &mut site.random).err(),
        Some(Error::Time(TimeError::UnknownBound))
    );
    // The control: a challenge after the restore signs in.
    let after = Get::new(&passkey, RP_ID, ORIGIN, site.options(at(30)), HANDLE).json();
    site.signed_in(&after, at(31));
}

#[test]
fn a_challenge_serves_one_sign_in_and_each_other_difference_refuses() {
    let mut site = Site::new();
    let passkey = site.register(Algorithm::Es256, -7, 1, 0);
    let json = Get::new(&passkey, RP_ID, ORIGIN, site.options(at(10)), HANDLE).json();
    site.signed_in(&json, at(11));
    assert_eq!(site.sign_in(&json, at(12)).err(), Some(Error::Challenge));

    // A challenge of another key, a changed challenge, and a challenge past its lifetime.
    let authority: Id<Authority> = Id::new("acme", "auth").expect("an identifier");
    let other =
        RelyingParty::new(authority, RP_ID, ORIGIN, "Acme", [4; 32], Limits::default()).expect("a relying party");
    let foreign = authenticator::challenge(&other.sign_in_options(at(10), &mut site.random).expect("the options"));
    let mut changed = site.options(at(10));
    changed[0] ^= 1;
    let unregistered = Passkey::new(Algorithm::Es256, -7, 2);
    let mut cases: Vec<(&str, Get<'_>, Reading, Error)> = vec![
        (
            "another key",
            Get::new(&passkey, RP_ID, ORIGIN, foreign, HANDLE),
            at(11),
            Error::Challenge,
        ),
        (
            "a changed challenge",
            Get::new(&passkey, RP_ID, ORIGIN, changed, HANDLE),
            at(11),
            Error::Challenge,
        ),
        (
            "an unregistered credential",
            Get::new(&unregistered, RP_ID, ORIGIN, site.options(at(10)), HANDLE),
            at(11),
            Error::Credential,
        ),
        (
            "another user handle",
            Get::new(&passkey, RP_ID, ORIGIN, site.options(at(10)), [8; 32]),
            at(11),
            Error::Credential,
        ),
        (
            "another origin",
            Get::new(
                &passkey,
                RP_ID,
                "https://attacker.example",
                site.options(at(10)),
                HANDLE,
            ),
            at(11),
            Error::Origin,
        ),
        (
            "another relying party ID",
            Get::new(&passkey, "attacker.example", ORIGIN, site.options(at(10)), HANDLE),
            at(11),
            Error::RelyingParty,
        ),
    ];
    let late = passkey::SIGN_IN_LIFETIME.as_secs();
    cases.push((
        "an ended challenge",
        Get::new(&passkey, RP_ID, ORIGIN, site.options(at(10)), HANDLE),
        at(10 + late),
        Error::Challenge,
    ));
    let mut no_handle = Get::new(&passkey, RP_ID, ORIGIN, site.options(at(10)), HANDLE);
    no_handle.user_handle = None;
    cases.push(("no user handle", no_handle, at(11), Error::Credential));
    let mut absent = Get::new(&passkey, RP_ID, ORIGIN, site.options(at(10)), HANDLE);
    absent.flags &= !USER_PRESENT;
    cases.push(("no user presence", absent, at(11), Error::UserPresence));
    let mut bound = Get::new(&passkey, RP_ID, ORIGIN, site.options(at(10)), HANDLE);
    bound.flags &= !(BACKUP_ELIGIBLE | BACKUP_STATE);
    cases.push((
        "a backup eligibility that differs from the registration",
        bound,
        at(11),
        Error::Malformed,
    ));
    for (name, get, now, error) in cases {
        assert_eq!(site.sign_in(&get.json(), now).err(), Some(error), "{name}");
    }

    // An authenticator that did not verify its user signs in, and the evidence says so.
    let mut unverified = Get::new(&passkey, RP_ID, ORIGIN, site.options(at(10)), HANDLE);
    unverified.flags &= !USER_VERIFIED;
    assert!(!site.signed_in(&unverified.json(), at(11)).user_verified());
}
