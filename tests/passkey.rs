//! The passkey registration of WebAuthn Level 3: the published registration cases, the options of the profile, each
//! refusal of a response, one commit for each ceremony, and the completion of a registration in doubt at a restore.

#[path = "passkey/authenticator.rs"]
mod authenticator;
#[path = "passkey/vectors.rs"]
mod vectors;

use core::pin::pin;
use core::task::{Context, Poll, Waker};
use core::time::Duration;

use rsauthnz::cbor::{self, Value};
use rsauthnz::crypto::Algorithm;
use rsauthnz::evidence::Binding;
use rsauthnz::id::{Authority, Human, Id};
use rsauthnz::limits::Limits;
use rsauthnz::passkey::{self, Credential, Error, RelyingParty, Response, User, UserHandle};
use rsauthnz::store::driver::{Answer, Driver, Lookup, Plan};
use rsauthnz::store::{Profile, Record, Store};
use rsauthnz::time::{Reading, ReadingSource};
use rsauthnz::transition::{self, Key, OperationId, Outcome, Proposal};
use rsauthnz_conformance::memory::{Memory, Schedule};
use rsauthnz_conformance::suite::{self, Fault, Subject as _};
use rscodec::base64::Profile::Url;
use rscrypto::ChaCha20Rng;

use authenticator::{
    ATTESTED, BACKUP_ELIGIBLE, BACKUP_STATE, EXTENSIONS, Passkey, Registration, USER_PRESENT, USER_VERIFIED,
};
use vectors::Vector;

const START: Duration = Duration::from_secs(1_800_000_000);
const RP_ID: &str = "app.example";
const ORIGIN: &str = "https://app.example";

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

fn rp() -> RelyingParty {
    let authority: Id<Authority> = Id::new("acme", "auth").expect("an identifier");
    RelyingParty::new(authority, RP_ID, ORIGIN, "Acme", Limits::default()).expect("a relying party")
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

    /// Commits the start of a registration of alice, and gives the challenge of its options.
    fn start(&mut self, operation: &str) -> [u8; 32] {
        let account = alice();
        let user = User {
            account: &account,
            handle: UserHandle::from_bytes([9; 32]),
            name: "alice@app.example",
            display_name: "Alice",
        };
        let operation = OperationId::new(operation.as_bytes()).expect("an operation identity");
        let (proposal, plan) = self
            .rp
            .start(&user, operation, at(0), &mut self.random, &mut self.node.driver)
            .expect("a start");
        let Outcome::Accepted(receipt) = self.node.commit(proposal, plan) else {
            panic!("the start does not commit");
        };
        authenticator::challenge(receipt.artifact().expect("the options"))
    }

    /// Proposes the finish of `json` with the pending record that the store holds.
    fn finish(&mut self, json: &[u8], now: Reading) -> Result<(Proposal, Plan, Credential), Error> {
        let response = Response::parse(json)?;
        let pending = self.node.read(&response.ceremony()).ok_or(Error::Challenge)?;
        self.rp.finish(&response, &pending, now, &mut self.node.driver)
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
        Limits::default(),
    )
    .expect("a relying party");
    let mut attestation = hex(vector.attestation);
    if verified {
        attestation = user_verified(&attestation);
    }
    let json = authenticator::response(&hex(vector.credential_id), &hex(vector.client_data), &attestation, None);
    let challenge = <[u8; 32]>::try_from(hex(vector.challenge)).expect("a challenge of 32 bytes");
    let credential = rp.verify(&Response::parse(&json)?, &challenge)?;
    Ok((
        credential.algorithm(),
        credential.backup_eligible(),
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
    // With only the UV flag set, each other check of these cases passes: the EdDSA key, and the longest ID.
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
    let account = alice();
    let user = User {
        account: &account,
        handle: UserHandle::from_bytes([9; 32]),
        name: "alice@app.example",
        display_name: "Alice",
    };
    let operation = OperationId::new(b"start-1").expect("an operation identity");
    let (proposal, plan) = site
        .rp
        .start(&user, operation, at(0), &mut site.random, &mut site.node.driver)
        .expect("a start");
    // A lost response releases no options: the browser gets no challenge whose record may not exist.
    site.node.memory.inject(Fault::LostResponse);
    assert!(matches!(site.node.commit(proposal, plan), Outcome::Unknown(_)));
    site.node.start();

    let (proposal, plan) = site
        .rp
        .start(
            &user,
            OperationId::new(b"start-2").expect("an operation identity"),
            at(0),
            &mut site.random,
            &mut site.node.driver,
        )
        .expect("a start");
    let Outcome::Accepted(receipt) = site.node.commit(proposal, plan) else {
        panic!("the start does not commit");
    };
    let options = receipt.artifact().expect("the options");
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
            r#""user":{{"id":"{handle}","name":"alice@app.example","displayName":"Alice"}},"#,
            r#""challenge":"{challenge}","#,
            r#""pubKeyCredParams":[{{"type":"public-key","alg":-49}},{{"type":"public-key","alg":-8}},"#,
            r#"{{"type":"public-key","alg":-7}},{{"type":"public-key","alg":-257}}],"#,
            r#""timeout":300000,"attestation":"none","#,
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
        let challenge = site.start(&format!("start-{seed}"));
        let passkey = Passkey::new(algorithm, alg, seed);
        let json = Registration::new(&passkey, RP_ID, ORIGIN, challenge).json();
        let (proposal, plan, credential) = site.finish(&json, at(1)).expect("a finish");
        assert_eq!(credential.algorithm(), algorithm, "{alg}");
        let ceremony = Response::parse(&json).expect("a response").ceremony();
        assert!(
            matches!(site.node.commit(proposal, plan), Outcome::Accepted(_)),
            "{alg}"
        );
        // One commit consumed the ceremony and wrote the credential.
        assert_eq!(site.node.read(&ceremony), None, "{alg}");
        let record = site
            .node
            .read(&passkey::credential_key(&passkey.id))
            .expect("the credential record");
        assert_eq!(record.end, None, "{alg}");
    }
}

#[test]
fn a_response_that_differs_from_the_ceremony_or_the_profile_refuses() {
    let rp = rp();
    let challenge = [7; 32];
    let passkey = Passkey::new(Algorithm::Es256, -7, 1);
    let check = |registration: &Registration<'_>| rp.verify(&Response::parse(&registration.json())?, &challenge);
    let base = || Registration::new(&passkey, RP_ID, ORIGIN, challenge);
    check(&base()).unwrap();

    let mut cases: Vec<(&str, Registration<'_>, Error)> = Vec::new();
    let mut case = |name, change: &dyn Fn(&mut Registration<'_>), error| {
        let mut registration = base();
        change(&mut registration);
        cases.push((name, registration, error));
    };
    case("another challenge", &|r| r.challenge = [8; 32], Error::Challenge);
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
    let registration = Registration::new(&long, RP_ID, ORIGIN, challenge);
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
    let registration = Registration::new(&composite, RP_ID, ORIGIN, challenge);
    assert_eq!(check(&registration).err(), Some(Error::Algorithm));
}

#[test]
fn a_synchronized_passkey_reports_no_hardware_binding() {
    let rp = rp();
    let passkey = Passkey::new(Algorithm::Ed25519, -8, 1);
    let mut registration = Registration::new(&passkey, RP_ID, ORIGIN, [7; 32]);
    let check = |registration: &Registration<'_>| {
        let credential = rp.verify(&Response::parse(&registration.json())?, &[7; 32])?;
        Ok::<_, Error>((
            credential.backup_eligible(),
            credential.backup_state(),
            credential.binding(),
        ))
    };
    assert_eq!(check(&registration), Ok((true, true, None)));
    registration.flags &= !BACKUP_STATE;
    assert_eq!(check(&registration), Ok((true, false, None)));
    // A credential that cannot leave its device reports the device. No registration proves hardware.
    registration.flags &= !BACKUP_ELIGIBLE;
    assert_eq!(check(&registration), Ok((false, false, Some(Binding::Device))));
}

#[test]
fn a_ceremony_commits_once_and_its_challenge_refuses_after_it() {
    let mut site = Site::new();
    let challenge = site.start("start-1");
    let (first, second) = (
        Passkey::new(Algorithm::Es256, -7, 1),
        Passkey::new(Algorithm::Es256, -7, 2),
    );
    let first_json = Registration::new(&first, RP_ID, ORIGIN, challenge).json();
    let second_json = Registration::new(&second, RP_ID, ORIGIN, challenge).json();
    // Two finishes of one ceremony read its pending record before either one commits.
    let ceremony = Response::parse(&first_json).expect("a response").ceremony();
    let stale = site.node.read(&ceremony).expect("the pending record");
    let (one, one_plan, _) = site.finish(&first_json, at(1)).expect("a finish");
    let (two, two_plan, _) = site.finish(&second_json, at(1)).expect("a finish");
    let tickets = [
        site.node.driver.submit(one, one_plan).expect("a submission"),
        site.node.driver.submit(two, two_plan).expect("a submission"),
    ];
    site.node.run();
    let outcomes = tickets.map(|ticket| match site.node.driver.take(ticket) {
        Some(Answer::Outcome(outcome)) => outcome,
        answer => panic!("the commit gave {answer:?}"),
    });
    assert!(matches!(outcomes[0], Outcome::Accepted(_)));
    assert!(
        matches!(outcomes[1], Outcome::Refused(transition::Error::Reuse)),
        "{:?}",
        outcomes[1]
    );
    assert!(site.node.read(&passkey::credential_key(&first.id)).is_some());
    assert_eq!(site.node.read(&passkey::credential_key(&second.id)), None);
    // The commit consumed the challenge, so no later finish finds its ceremony.
    assert_eq!(site.node.read(&ceremony), None);
    assert_eq!(site.finish(&second_json, at(2)).err(), Some(Error::Challenge));
    // The same response with the record that it read before the commit is the same operation: the driver gives the
    // receipt of the first commit, and commits nothing.
    let response = Response::parse(&first_json).expect("a response");
    let (again, plan, _) = site
        .rp
        .finish(&response, &stale, at(2), &mut site.node.driver)
        .expect("a finish");
    assert!(matches!(site.node.commit(again, plan), Outcome::Accepted(receipt) if receipt.artifact().is_none()));
}

#[test]
fn a_pending_registration_ends_after_its_lifetime() {
    let mut site = Site::new();
    let challenge = site.start("start-1");
    let passkey = Passkey::new(Algorithm::Ed25519, -8, 1);
    let json = Registration::new(&passkey, RP_ID, ORIGIN, challenge).json();
    let late = at(passkey::REGISTRATION_LIFETIME.as_secs());
    assert_eq!(site.finish(&json, late).err(), Some(Error::Challenge));
    assert_eq!(Error::Challenge.recovery(), transition::Recovery::Restart);
}

#[test]
fn a_registration_in_doubt_completes_once_at_restore() {
    let mut site = Site::new();
    let challenge = site.start("start-1");
    let snapshot = site.node.memory.snapshot();
    let passkey = Passkey::new(Algorithm::MlDsa65, -49, 1);
    let json = Registration::new(&passkey, RP_ID, ORIGIN, challenge).json();
    let (proposal, plan, _) = site.finish(&json, at(1)).expect("a finish");
    let operation = proposal.operation().clone();
    // The commit lands, and its response is lost. Then the store comes back from the snapshot before the commit.
    site.node.memory.inject(Fault::LostResponse);
    assert!(matches!(site.node.commit(proposal, plan), Outcome::Unknown(_)));
    site.node.memory.restore(&snapshot);
    site.node.driver.restore(at(0)).expect("a restore");
    site.node.run();

    // The restored store holds the passkey of alice, and the ceremony is consumed.
    assert!(site.node.read(&passkey::credential_key(&passkey.id)).is_some());
    let ceremony = Response::parse(&json).expect("a response").ceremony();
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
fn a_relying_party_takes_only_an_origin_of_its_id() {
    let authority: Id<Authority> = Id::new("acme", "auth").expect("an identifier");
    let new =
        |id: &str, origin: &str| RelyingParty::new(authority.clone(), id, origin, "Acme", Limits::default()).map(drop);
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
