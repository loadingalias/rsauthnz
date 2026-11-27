//! The HTTP message signatures of an agent (RFC 9421). Each request carries the agent credential and a signature by its
//! key over the method, the target, the body, and the credential, which is the grant reference and names the audience.
//! The replay store of the audience accepts each signature once, and its insert gives the evidence that the grant check
//! takes. A change of each covered part refuses, and so does a verifier of another audience.

use core::time::Duration;

use core::num::NonZeroUsize;

use rsauthnz::authz;
use rsauthnz::cbor::Value;
use rsauthnz::cose::{self, PublicKey};
use rsauthnz::credential::{self, Released};
use rsauthnz::evidence::Evidence;
use rsauthnz::httpsig::{Checked, Draft, Error, Failure, Field, LIFETIME_DEFAULT, Profile, Request, Signed};
use rsauthnz::store::driver::Plan;
use rsauthnz::store::{self, Capacity, Progress};
use rsauthnz::time::{Reading, ReadingSource};
use rsauthnz::transition::{self, OperationId, Outcome};
use rsauthnz_conformance::memory::Memory;
use rsauthnz_conformance::suite::Subject as _;
use rscodec::base64::Profile::Standard;

use super::{API, Grantor, action, at, audience, budget, key, keypair, permission, resource, time, trusted};

/// The nonce of each signature of the tests that needs no other one.
const NONCE: [u8; 16] = [9; 16];

/// The parts of a request that the agent sends: its fields own their values.
#[derive(Clone)]
struct Sent {
    method: &'static str,
    path: &'static str,
    query: Option<&'static str>,
    fields: Vec<(&'static str, Vec<u8>)>,
    body: Vec<u8>,
}

impl Sent {
    /// The read of `repo-x`, with no body.
    fn read() -> Self {
        Self {
            method: "GET",
            path: "/repos/repo-x",
            query: None,
            fields: vec![("accept", b"application/json".to_vec())],
            body: Vec::new(),
        }
    }

    /// A change of `repo-x`, with a JSON body and a query.
    fn change() -> Self {
        Self {
            method: "POST",
            path: "/repos/repo-x/labels",
            query: Some("ref=main"),
            fields: vec![("content-type", b"application/json".to_vec())],
            body: br#"{"label":"ready"}"#.to_vec(),
        }
    }

    /// The request with the fields `fields`.
    fn with<'a>(&'a self, fields: &'a [(&'a str, &'a [u8])]) -> Request<'a> {
        Request {
            method: self.method,
            path: self.path,
            query: self.query,
            fields,
            body: &self.body,
        }
    }

    /// Adds each field of `signed`, in place of each field of its name.
    fn add(&mut self, fields: &[(&'static str, String)]) {
        for (name, value) in fields {
            self.fields.retain(|(field, _)| field != name);
            self.fields.push((name, value.clone().into_bytes()));
        }
    }

    /// The field of `name`.
    fn field(&mut self, name: &str) -> &mut Vec<u8> {
        let (_, value) = self
            .fields
            .iter_mut()
            .find(|(field, _)| *field == name)
            .expect("the field");
        value
    }
}

/// A change of a signed request, which can take the body of the case.
type Change = fn(&mut Sent, &[u8]);

/// The view of `fields`.
fn view<'a>(fields: &'a [(&'static str, Vec<u8>)]) -> Vec<(&'static str, &'a [u8])> {
    fields.iter().map(|(name, value)| (*name, value.as_slice())).collect()
}

/// The owned fields of `signed`.
fn owned(signed: &Signed) -> Vec<(&'static str, String)> {
    signed.fields().map(|(name, value)| (name, value.to_owned())).to_vec()
}

/// The base64 text of `bytes`, with padding.
fn standard(bytes: &[u8]) -> String {
    let mut out = vec![0; Standard.encoded_len(bytes.len()).expect("a length")];
    let text = Standard.encode(bytes, &mut out).expect("a buffer of the length");
    String::from_utf8(text.to_vec()).expect("ASCII")
}

/// Alice and her agent with a grant of the read of `repo-x` at [`API`] until one hour after `START`, a credential of
/// the agent from 30, and the verifier of [`API`].
fn granted() -> (Grantor, Released, Profile) {
    let mut grantor = Grantor::new();
    let (_, fresh) = grantor.world.session();
    grantor.issue(&fresh, &[permission("repo-x", "repo.read")], time(3600), 30);
    let credential = grantor.issued(2, API, None, 30).expect("a credential");
    let profile = grantor
        .grants
        .profile(grantor.issuer.key(), &audience(API))
        .expect("a profile");
    let profile = Profile::new(profile);
    (grantor, credential, profile)
}

/// `sent` signed by the key of `holder` with `credential`, `lifetime`, and the nonce [`NONCE`] at `seconds`.
fn signed(sent: &Sent, holder: u8, credential: &[u8], lifetime: Duration, seconds: u64) -> Sent {
    signed_with(sent, holder, credential, &NONCE, lifetime, seconds)
}

/// `sent` signed by the key of `holder` with `credential`, `nonce`, and `lifetime` at `seconds`.
fn signed_with(sent: &Sent, holder: u8, credential: &[u8], nonce: &[u8; 16], lifetime: Duration, seconds: u64) -> Sent {
    let fields = view(&sent.fields);
    let key = trusted(PublicKey::MlDsa65Ed25519(&key(holder)));
    let draft = Draft::new(&key, credential, &sent.with(&fields), nonce, lifetime, at(seconds)).expect("a draft");
    let signature = keypair(holder)
        .1
        .sign_deterministic(draft.to_be_signed(), &[])
        .expect("a signature");
    let signed = draft.finish(signature.as_bytes(), &mut budget()).expect("the fields");
    let mut sent = sent.clone();
    sent.add(&owned(&signed));
    sent
}

/// The verification of `sent` by `profile` at `seconds`.
fn verify(profile: &Profile, sent: &Sent, seconds: u64) -> Result<Checked, Error> {
    profile.verify(&sent.with(&view(&sent.fields)), at(seconds))
}

/// The refusal of a failure of the memory binding, which fails no primitive.
fn refused(failure: Failure<rsauthnz_conformance::memory::Error>) -> Error {
    match failure {
        Failure::Refused(error) => error,
        Failure::Store(error) => panic!("the insert failed: {error:?}"),
    }
}

/// The verification of `sent` by `profile` at `seconds`, then its replay insert into `memory`.
fn accept(profile: &Profile, memory: &mut Memory, sent: &Sent, seconds: u64) -> Result<Evidence, Error> {
    super::ready(verify(profile, sent, seconds)?.accept(memory)).map_err(refused)
}

/// A signed read gives the evidence of the agent, and the grant check of that evidence gives the scope of alice. A
/// change with a body, a query, and a media type verifies too. So does a request that a proxy also signs, with another
/// field, its fields in another order, their names in uppercase, and space around their values.
#[test]
fn a_signed_request_gives_the_evidence_that_the_grant_check_takes() {
    let (mut grantor, credential, profile) = granted();
    let read = signed(&Sent::read(), 2, credential.as_bytes(), LIFETIME_DEFAULT, 40);
    let evidence = accept(&profile, &mut grantor.world.site.node.memory, &read, 41).expect("the evidence");
    let (action, resource) = (action("repo.read"), resource("repo-x"));
    let check = authz::check_agent(
        &grantor.grants,
        &mut grantor.world.site.node.memory,
        &evidence,
        &action,
        &resource,
        &grantor.policy,
        at(41),
    );
    let scope = super::ready(check).map_err(super::refused).expect("the scope");
    assert_eq!(*scope.owner(), super::alice());
    assert_eq!(scope.agent(), &grantor.agent.started.agent);

    let change = signed(&Sent::change(), 2, credential.as_bytes(), LIFETIME_DEFAULT, 40);
    let _checked = verify(&profile, &change, 41).expect("a check");
    // The signature of a proxy, with no tag of the profile, is in the same two fields.
    let mut proxied = change;
    proxied
        .field("signature-input")
        .extend_from_slice(br#", proxy=("@method");created=1"#);
    proxied.field("signature").extend_from_slice(b", proxy=:AAAA:");
    proxied.fields.push(("x-forwarded-for", b"203.0.113.7".to_vec()));
    proxied.fields.reverse();
    let upper: Vec<(String, Vec<u8>)> = proxied
        .fields
        .iter()
        .map(|(name, value)| (name.to_ascii_uppercase(), [b"  ", value.as_slice(), b" "].concat()))
        .collect();
    let fields: Vec<(&str, &[u8])> = upper
        .iter()
        .map(|(name, value)| (name.as_str(), value.as_slice()))
        .collect();
    let _checked = profile.verify(&proxied.with(&fields), at(41)).expect("a check");
}

/// Each change of a covered part of a signed request refuses: the method, the path, the query, the body, the media type,
/// and the credential, which is the grant reference. A signature by another key refuses too, and a verifier of another
/// audience refuses the request: the audience of the credential binds its recipient.
#[test]
fn a_changed_method_target_body_or_grant_reference_or_another_audience_refuses() {
    let (mut grantor, credential, profile) = granted();
    let sent = signed(&Sent::change(), 2, credential.as_bytes(), LIFETIME_DEFAULT, 40);
    let _checked = verify(&profile, &sent, 41).expect("a check");
    // A second credential of the same agent and grant: another serial, so other bytes.
    let other = grantor.issued(2, API, None, 35).expect("a credential");
    let body = br#"{"label":"merged"}"#;
    let cases: [(&str, Change, Error); 8] = [
        ("method", |sent, _| sent.method = "PUT", Error::Signature),
        ("path", |sent, _| sent.path = "/repos/repo-y/labels", Error::Signature),
        ("query", |sent, _| sent.query = Some("ref=dev"), Error::Signature),
        ("no query", |sent, _| sent.query = None, Error::Signature),
        ("body", |sent, body| sent.body = body.to_vec(), Error::Digest),
        (
            "body and digest",
            |sent, body| {
                sent.body = body.to_vec();
                let digest = format!("sha-256=:{}:", standard(&rscrypto::Sha256::digest(body)));
                *sent.field("content-digest") = digest.into_bytes();
            },
            Error::Signature,
        ),
        (
            "media type",
            |sent, _| *sent.field("content-type") = b"text/plain".to_vec(),
            Error::Signature,
        ),
        (
            "no media type",
            |sent, _| sent.fields.retain(|(name, _)| *name != "content-type"),
            Error::Components,
        ),
    ];
    for (name, change, expected) in cases {
        let mut changed = sent.clone();
        change(&mut changed, body);
        assert_eq!(verify(&profile, &changed, 41).err(), Some(expected), "{name}");
    }
    let billing = grantor
        .grants
        .profile(grantor.issuer.key(), &audience("billing"))
        .expect("a profile");
    assert_eq!(
        verify(&Profile::new(billing), &sent, 41).err(),
        Some(Error::Credential(credential::Error::Cose(cose::Error::Audience))),
        "another audience"
    );
    let mut swapped = sent;
    *swapped.field("agent-credential") = format!(":{}:", standard(other.as_bytes())).into_bytes();
    assert_eq!(
        verify(&profile, &swapped, 41).err(),
        Some(Error::Signature),
        "grant reference"
    );
    // The key of seed 3 signs, and the credential names the key of seed 2.
    let other_key = signed(&Sent::change(), 3, credential.as_bytes(), LIFETIME_DEFAULT, 40);
    assert_eq!(
        verify(&profile, &other_key, 41).err(),
        Some(Error::Signature),
        "another key"
    );
}

/// A signature verifies from its creation, with the skew of an agent, until its expiry, and only with a window of at
/// most 5 minutes. A reading with no bound refuses.
#[test]
fn a_signature_outside_its_window_refuses() {
    let (_, credential, profile) = granted();
    let credential = credential.as_bytes();
    let sent = signed(&Sent::read(), 2, credential, LIFETIME_DEFAULT, 40);
    // Expires at 100: the reading at 98 is at 99 at the latest, and the reading at 99 can be at 100.
    let _checked = verify(&profile, &sent, 98).expect("a check");
    assert_eq!(verify(&profile, &sent, 99).err(), Some(Error::Expired));
    // The clock of the agent is ahead. The reading at 41 is at 40 at the earliest, and the skew is 30 seconds.
    let ahead = signed(&Sent::read(), 2, credential, LIFETIME_DEFAULT, 70);
    let _checked = verify(&profile, &ahead, 41).expect("a check");
    let early = signed(&Sent::read(), 2, credential, LIFETIME_DEFAULT, 71);
    assert_eq!(verify(&profile, &early, 41).err(), Some(Error::Early));
    let longest = signed(&Sent::read(), 2, credential, Duration::from_secs(300), 40);
    let _checked = verify(&profile, &longest, 41).expect("a check");
    let long = signed(&Sent::read(), 2, credential, Duration::from_secs(301), 40);
    assert_eq!(verify(&profile, &long, 41).err(), Some(Error::Window));
    let unbounded = Reading::new(time(41), None, ReadingSource::Caller);
    let fields = view(&sent.fields);
    assert!(matches!(
        profile.verify(&sent.with(&fields), unbounded),
        Err(Error::Time(_))
    ));
    let key = trusted(PublicKey::MlDsa65Ed25519(&key(2)));
    let draft = Draft::new(
        &key,
        credential,
        &sent.with(&fields),
        &NONCE,
        Duration::from_millis(999),
        at(40),
    );
    assert_eq!(draft.err(), Some(Error::Window));
}

/// `sent` signed by the agent key over the signature base that this test writes for `params`, the components of the
/// profile with the parameters of `params`, and the label `agent`.
fn by_hand(sent: &Sent, credential: &[u8], params: &str) -> Sent {
    let digest = format!("sha-256=:{}:", standard(&rscrypto::Sha256::digest(&sent.body)));
    let credential = format!(":{}:", standard(credential));
    let inner = format!(r#"("@method" "@path" "@query" "content-digest" "agent-credential"){params}"#);
    let base = format!(
        "\"@method\": {}\n\"@path\": {}\n\"@query\": ?{}\n\"content-digest\": {digest}\n\
         \"agent-credential\": {credential}\n\"@signature-params\": {inner}",
        sent.method,
        sent.path,
        sent.query.unwrap_or_default(),
    );
    let signature = keypair(2)
        .1
        .sign_deterministic(base.as_bytes(), &[])
        .expect("a signature");
    let mut sent = sent.clone();
    sent.add(&[
        ("content-digest", digest),
        ("agent-credential", credential),
        ("signature-input", format!("agent={inner}")),
        ("signature", format!("agent=:{}:", standard(signature.as_bytes()))),
    ]);
    sent
}

/// The base64url text of `bytes` bytes of the nonce.
fn nonce(bytes: usize) -> String {
    super::base64url(&vec![9; bytes])
}

/// A signature verifies only with a nonce of 128 to 256 bits and with exactly the parameters of the profile. The
/// agent key signs each case, so each refusal comes from its parameters.
#[test]
fn a_signature_with_a_nonce_under_128_bits_or_another_parameter_refuses() {
    let (_, credential, profile) = granted();
    let created = time(40).as_secs();
    let expires = created + 60;
    let tag = r#"tag="rsauthnz-agent""#;
    let window = format!(";created={created};expires={expires}");
    let cases = [
        (valid(created, expires), None),
        (
            format!(r#";{tag};expires={expires};nonce="{}";created={created}"#, nonce(32)),
            None,
        ),
        (format!(r#"{window};nonce="{}";{tag}"#, nonce(15)), Some(Error::Nonce)),
        (format!(r#"{window};nonce="{}";{tag}"#, nonce(33)), Some(Error::Nonce)),
        (format!(r#"{window};nonce="{}=";{tag}"#, nonce(16)), Some(Error::Nonce)),
        (
            format!(r#"{window};nonce="{}";{tag};alg="ed25519""#, nonce(16)),
            Some(Error::Parameters),
        ),
        (
            format!(r#"{window};nonce="{}";{tag};keyid="agent""#, nonce(16)),
            Some(Error::Parameters),
        ),
        (
            format!(r#";created={created};nonce="{}";{tag}"#, nonce(16)),
            Some(Error::Parameters),
        ),
        (format!(r#"{window};{tag}"#), Some(Error::Parameters)),
        (format!(r#"{window};nonce="{}""#, nonce(16)), Some(Error::Tag)),
    ];
    for (params, expected) in cases {
        let sent = by_hand(&Sent::read(), credential.as_bytes(), &params);
        assert_eq!(verify(&profile, &sent, 41).err(), expected, "{params}");
    }
    // A second signature of the profile under another label.
    let mut twice = by_hand(&Sent::read(), credential.as_bytes(), &valid(created, expires));
    let input = String::from_utf8(twice.field("signature-input").clone()).expect("ASCII");
    let copy = format!(", copy={}", input.trim_start_matches("agent="));
    twice.field("signature-input").extend_from_slice(copy.as_bytes());
    assert_eq!(verify(&profile, &twice, 41).err(), Some(Error::Tag));
    // A request with no signature.
    let mut unsigned = by_hand(&Sent::read(), credential.as_bytes(), &valid(created, expires));
    unsigned.fields.retain(|(name, _)| *name != "signature-input");
    assert_eq!(
        verify(&profile, &unsigned, 41).err(),
        Some(Error::Field(Field::SignatureInput))
    );
}

/// The parameters of a valid signature from `created` to `expires`.
fn valid(created: u64, expires: u64) -> String {
    format!(
        r#";created={created};expires={expires};nonce="{}";tag="rsauthnz-agent""#,
        nonce(16)
    )
}

/// A second agent of alice, with the key of seed 3, a grant of the read of `repo-x` at [`API`] from 32, and its
/// credential from 33.
fn second(grantor: &mut Grantor) -> Released {
    let (_, fresh) = grantor.world.session();
    let mut agent = grantor.world.enrolled_at(3, 31);
    core::mem::swap(&mut grantor.agent, &mut agent);
    grantor.issue(&fresh, &[permission("repo-x", "repo.read")], time(3600), 32);
    let credential = grantor.issued(3, API, None, 33).expect("a credential");
    core::mem::swap(&mut grantor.agent, &mut agent);
    credential
}

/// The replay store accepts a signature once in its audience: a repetition refuses at the same verifier and at a
/// second verifier of the audience. Another agent can use the same nonce, because the replay identity names the key of
/// the agent.
#[test]
fn a_repeated_signature_refuses_also_at_a_second_verifier_and_another_agent_keeps_its_nonce() {
    let (mut grantor, credential, profile) = granted();
    let other = second(&mut grantor);
    let again = grantor
        .grants
        .profile(grantor.issuer.key(), &audience(API))
        .expect("a profile");
    let again = Profile::new(again);
    let memory = &mut grantor.world.site.node.memory;
    let read = signed(&Sent::read(), 2, credential.as_bytes(), LIFETIME_DEFAULT, 40);
    accept(&profile, memory, &read, 41).unwrap();
    assert_eq!(accept(&profile, memory, &read, 42).err(), Some(Error::Replayed));
    assert_eq!(accept(&again, memory, &read, 42).err(), Some(Error::Replayed));
    let theirs = signed(&Sent::read(), 3, other.as_bytes(), LIFETIME_DEFAULT, 40);
    assert!(
        accept(&profile, memory, &theirs, 41).is_ok(),
        "the nonce of another agent"
    );
}

/// A captured signature cannot repeat after a restart of a memory store, which loses its records, or after a restore
/// from a snapshot before its insert. Each start and each restore sets the replay floor, and between a restore and its
/// floor no insert lands. A signature created later than the floor plus the skew of an agent verifies.
#[test]
fn a_captured_signature_refuses_after_a_restart_and_after_a_restore() {
    let (mut grantor, credential, profile) = granted();
    let ours = credential.as_bytes();
    let read = signed(&Sent::read(), 2, ours, LIFETIME_DEFAULT, 40);
    let node = &mut grantor.world.site.node;
    accept(&profile, &mut node.memory, &read, 41).unwrap();
    // The store loses its records, so its start refuses, and a restore from its journal activates it. The floor of the
    // restore at 50 ends at 52, and the skew is 30 seconds: `created` at 82 refuses, and at 83 verifies.
    node.memory.restart();
    node.driver.start(at(50));
    node.run();
    node.driver.restore(at(50)).expect("a restore");
    node.run();
    assert_eq!(accept(&profile, &mut node.memory, &read, 51).err(), Some(Error::Floor));
    let early = signed_with(&Sent::read(), 2, ours, &[1; 16], LIFETIME_DEFAULT, 82);
    assert_eq!(accept(&profile, &mut node.memory, &early, 83).err(), Some(Error::Floor));
    let late = signed_with(&Sent::read(), 2, ours, &[2; 16], LIFETIME_DEFAULT, 83);
    accept(&profile, &mut node.memory, &late, 84).unwrap();

    let (mut grantor, credential, profile) = granted();
    let ours = credential.as_bytes();
    let read = signed(&Sent::read(), 2, ours, LIFETIME_DEFAULT, 40);
    let node = &mut grantor.world.site.node;
    let snapshot = node.memory.snapshot();
    accept(&profile, &mut node.memory, &read, 41).unwrap();
    node.memory.restore(&snapshot);
    let between = signed_with(&Sent::read(), 2, ours, &[3; 16], LIFETIME_DEFAULT, 45);
    assert_eq!(
        accept(&profile, &mut node.memory, &between, 46).err(),
        Some(Error::Floor),
        "an insert before the floor of the restore"
    );
    node.driver.restore(at(60)).expect("a restore");
    node.run();
    assert_eq!(accept(&profile, &mut node.memory, &read, 61).err(), Some(Error::Floor));
    let after = signed_with(&Sent::read(), 2, ours, &[4; 16], LIFETIME_DEFAULT, 93);
    accept(&profile, &mut node.memory, &after, 94).unwrap();
}

/// A verifier that waits past the retention of a replay record, between its check and its insert, cannot accept the
/// signature twice: the store refuses the insert once its own clock reaches `expires` plus the skew.
#[test]
fn an_insert_at_or_after_the_expiry_and_skew_of_its_signature_refuses() {
    let (mut grantor, credential, profile) = granted();
    // Expires at 100: the insert ends at 130, and the record at 132.
    let read = signed(&Sent::read(), 2, credential.as_bytes(), LIFETIME_DEFAULT, 40);
    let memory = &mut grantor.world.site.node.memory;
    accept(&profile, memory, &read, 41).unwrap();
    let waiting = verify(&profile, &read, 98).expect("a check in the window");
    memory.set_clock(at(140));
    while super::ready(store::expire(memory, at(140), NonZeroUsize::MIN)).expect("an expiry pass") == Progress::More {}
    // The record is gone, so only the clock of the store refuses the insert.
    assert_eq!(
        super::ready(waiting.accept(memory)).map_err(refused).err(),
        Some(Error::Expired)
    );
}

/// The store admits records within its capacity and the share of each agent key. A full share or a full store refuses
/// with a retryable overload, and writes no record. A forged request with the credential of an agent takes no room in
/// its share, because a request that fails its check inserts nothing.
#[test]
fn a_full_share_or_store_refuses_and_a_forged_request_takes_no_room() {
    let (mut grantor, credential, profile) = granted();
    let other = second(&mut grantor);
    let capacity = Capacity {
        records_max: 3,
        share_max: 2,
    };
    let mut memory = grantor.world.site.node.memory.clone().with_capacity(capacity);
    let ours = credential.as_bytes();
    for nonce in [[1; 16], [2; 16]] {
        // The key of seed 3 signs with the credential of the key of seed 2.
        let forged = signed_with(&Sent::read(), 3, ours, &nonce, LIFETIME_DEFAULT, 40);
        assert_eq!(accept(&profile, &mut memory, &forged, 41).err(), Some(Error::Signature));
    }
    for nonce in [[1; 16], [2; 16]] {
        let read = signed_with(&Sent::read(), 2, ours, &nonce, LIFETIME_DEFAULT, 40);
        assert!(accept(&profile, &mut memory, &read, 41).is_ok(), "{nonce:?}");
    }
    let third = signed_with(&Sent::read(), 2, ours, &[3; 16], LIFETIME_DEFAULT, 40);
    assert_eq!(accept(&profile, &mut memory, &third, 41).err(), Some(Error::Full));
    // A refusal wrote no record, so the same signature is not a repetition.
    assert_eq!(accept(&profile, &mut memory, &third, 41).err(), Some(Error::Full));
    let theirs = |nonce| signed_with(&Sent::read(), 3, other.as_bytes(), &nonce, LIFETIME_DEFAULT, 40);
    assert!(
        accept(&profile, &mut memory, &theirs([1; 16]), 41).is_ok(),
        "another share"
    );
    assert_eq!(
        accept(&profile, &mut memory, &theirs([2; 16]), 41).err(),
        Some(Error::Full),
        "the capacity"
    );
}

/// The commit of the operation `id` of the agent of `checked`, with its replay insert.
fn commit(grantor: &mut Grantor, checked: Checked, id: &str) -> Result<Outcome, Error> {
    let (action, resource) = (action("repo.read"), resource("repo-x"));
    let check = authz::check_agent(
        &grantor.grants,
        &mut grantor.world.site.node.memory,
        checked.evidence(),
        &action,
        &resource,
        &grantor.policy,
        at(41),
    );
    let scope = super::ready(check).map_err(super::refused).expect("the scope");
    let operation = OperationId::new(id.as_bytes()).expect("an identity");
    let mut proposal = scope.propose(operation, Value::Null, at(41)).expect("a proposal");
    super::ready(checked.include(&mut grantor.world.site.node.memory, &mut proposal)).map_err(refused)?;
    Ok(grantor.world.commit((proposal, Plan::default())))
}

/// A request that commits a transition puts its replay insert in its own commit. The commit refuses a repetition, the
/// replay store refuses it without a commit too, and a commit into a full share refuses with nothing written.
#[test]
fn a_request_that_commits_puts_its_replay_insert_in_its_commit() {
    let (mut grantor, credential, profile) = granted();
    let change = signed(&Sent::change(), 2, credential.as_bytes(), LIFETIME_DEFAULT, 40);
    let first = verify(&profile, &change, 41).expect("a check");
    assert!(matches!(commit(&mut grantor, first, "op-1"), Ok(Outcome::Accepted(_))));
    let again = verify(&profile, &change, 42).expect("a check");
    assert!(matches!(commit(&mut grantor, again, "op-2"), Ok(Outcome::Conflict)));
    let memory = &mut grantor.world.site.node.memory;
    assert_eq!(accept(&profile, memory, &change, 42).err(), Some(Error::Replayed));
    let _full = memory.clone().with_capacity(Capacity {
        records_max: 1,
        share_max: 1,
    });
    let next = signed_with(
        &Sent::change(),
        2,
        credential.as_bytes(),
        &[1; 16],
        LIFETIME_DEFAULT,
        40,
    );
    let checked = verify(&profile, &next, 41).expect("a check");
    assert!(matches!(
        commit(&mut grantor, checked, "op-3"),
        Ok(Outcome::Refused(transition::Error::Full))
    ));
}
