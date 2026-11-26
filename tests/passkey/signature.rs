//! The HTTP message signatures of an agent (RFC 9421). Each request carries the agent credential and a signature by its
//! key over the method, the target, the authority, the body, and the credential, which is the grant reference. The
//! verifier gives the evidence that the grant check takes, and a change of each covered part refuses.

use core::time::Duration;

use rsauthnz::authz;
use rsauthnz::cose::PublicKey;
use rsauthnz::credential::Released;
use rsauthnz::httpsig::{Draft, Error, Field, LIFETIME_DEFAULT, Profile, Request, Signed};
use rsauthnz::time::{Reading, ReadingSource};
use rscodec::base64::Profile::Standard;

use super::{API, Grantor, action, at, audience, budget, key, keypair, permission, refused, resource, time, trusted};

/// The authorities of the verifier: two hosts of one service.
const AUTHORITIES: [&str; 2] = ["api.example", "api-eu.example"];

/// The nonce of each signature of the tests that needs no other one.
const NONCE: [u8; 16] = [9; 16];

/// The parts of a request that the agent sends: its fields own their values.
#[derive(Clone)]
struct Sent {
    method: &'static str,
    authority: &'static str,
    path: &'static str,
    query: Option<&'static str>,
    fields: Vec<(&'static str, Vec<u8>)>,
    body: Vec<u8>,
}

impl Sent {
    /// The read of `repo-x` at `api.example`, with no body.
    fn read() -> Self {
        Self {
            method: "GET",
            authority: "api.example",
            path: "/repos/repo-x",
            query: None,
            fields: vec![("accept", b"application/json".to_vec())],
            body: Vec::new(),
        }
    }

    /// A change of `repo-x` at `api.example`, with a JSON body and a query.
    fn change() -> Self {
        Self {
            method: "POST",
            authority: "api.example",
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
            authority: self.authority,
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
/// the agent from 30, and the verifier of [`AUTHORITIES`].
fn granted() -> (Grantor, Released, Profile) {
    let mut grantor = Grantor::new();
    let (_, fresh) = grantor.world.session();
    grantor.issue(&fresh, &[permission("repo-x", "repo.read")], time(3600), 30);
    let credential = grantor.issued(2, API, None, 30).expect("a credential");
    let profile = grantor
        .grants
        .profile(grantor.issuer.key(), &audience(API))
        .expect("a profile");
    let profile = Profile::new(profile, &AUTHORITIES).expect("a verifier");
    (grantor, credential, profile)
}

/// `sent` signed by the key of `holder` with `credential`, `lifetime`, and the nonce [`NONCE`] at `seconds`.
fn signed(sent: &Sent, holder: u8, credential: &[u8], lifetime: Duration, seconds: u64) -> Sent {
    let fields = view(&sent.fields);
    let key = trusted(PublicKey::MlDsa65Ed25519(&key(holder)));
    let draft = Draft::new(&key, credential, &sent.with(&fields), &NONCE, lifetime, at(seconds)).expect("a draft");
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
fn verify(profile: &Profile, sent: &Sent, seconds: u64) -> Result<rsauthnz::evidence::Evidence, Error> {
    profile.verify(&sent.with(&view(&sent.fields)), at(seconds))
}

/// A signed read gives the evidence of the agent, and the grant check of that evidence gives the scope of alice. A
/// change with a body, a query, and a media type verifies too, and so does a request that a proxy also signs.
#[test]
fn a_signed_request_gives_the_evidence_that_the_grant_check_takes() {
    let (mut grantor, credential, profile) = granted();
    let read = signed(&Sent::read(), 2, credential.as_bytes(), LIFETIME_DEFAULT, 40);
    let evidence = verify(&profile, &read, 41).expect("the evidence");
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
    let scope = super::ready(check).map_err(refused).expect("the scope");
    assert_eq!(*scope.owner(), super::alice());
    assert_eq!(scope.agent(), &grantor.agent.started.agent);

    let change = signed(&Sent::change(), 2, credential.as_bytes(), LIFETIME_DEFAULT, 40);
    verify(&profile, &change, 41).unwrap();
    // The signature of a proxy, with no tag of the profile, is in the same two fields.
    let mut proxied = change;
    proxied
        .field("signature-input")
        .extend_from_slice(br#", proxy=("@method");created=1"#);
    proxied.field("signature").extend_from_slice(b", proxy=:AAAA:");
    verify(&profile, &proxied, 41).unwrap();
}

/// Each change of a covered part of a signed request refuses: the method, the path, the query, the authority, the
/// body, the media type, and the credential, which is the grant reference. A signature by another key refuses too.
#[test]
fn a_changed_method_target_authority_body_or_grant_reference_refuses() {
    let (mut grantor, credential, profile) = granted();
    let sent = signed(&Sent::change(), 2, credential.as_bytes(), LIFETIME_DEFAULT, 40);
    verify(&profile, &sent, 41).unwrap();
    // A second credential of the same agent and grant: another serial, so other bytes.
    let other = grantor.issued(2, API, None, 35).expect("a credential");
    let body = br#"{"label":"merged"}"#;
    let cases: [(&str, Change, Error); 10] = [
        ("method", |sent, _| sent.method = "PUT", Error::Signature),
        ("path", |sent, _| sent.path = "/repos/repo-y/labels", Error::Signature),
        ("query", |sent, _| sent.query = Some("ref=dev"), Error::Signature),
        ("no query", |sent, _| sent.query = None, Error::Signature),
        (
            "authority",
            |sent, _| sent.authority = "api-eu.example",
            Error::Signature,
        ),
        (
            "authority of another verifier",
            |sent, _| sent.authority = "api.other.example",
            Error::Authority,
        ),
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
    verify(&profile, &sent, 98).unwrap();
    assert_eq!(verify(&profile, &sent, 99).err(), Some(Error::Expired));
    // The clock of the agent is ahead. The reading at 41 is at 40 at the earliest, and the skew is 30 seconds.
    verify(
        &profile,
        &signed(&Sent::read(), 2, credential, LIFETIME_DEFAULT, 70),
        41,
    )
    .unwrap();
    let early = signed(&Sent::read(), 2, credential, LIFETIME_DEFAULT, 71);
    assert_eq!(verify(&profile, &early, 41).err(), Some(Error::Early));
    let longest = signed(&Sent::read(), 2, credential, Duration::from_secs(300), 40);
    verify(&profile, &longest, 41).unwrap();
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
    let inner = format!(r#"("@method" "@authority" "@path" "@query" "content-digest" "agent-credential"){params}"#);
    let base = format!(
        "\"@method\": {}\n\"@authority\": {}\n\"@path\": {}\n\"@query\": ?{}\n\"content-digest\": {digest}\n\
         \"agent-credential\": {credential}\n\"@signature-params\": {inner}",
        sent.method,
        sent.authority,
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
