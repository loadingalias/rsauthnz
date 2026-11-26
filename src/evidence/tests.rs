use core::time::Duration;

use super::{Artifact, Backup, Binding, Evidence, EvidenceError, Method};
use crate::cbor;
use crate::credential::{Claims, Serial, Subject};
use crate::crypto::Authentication;
use crate::id::{Agent, Human, Id, Principal, Workload};
use crate::limits::Limits;
use crate::time::{Reading, ReadingSource};

fn human() -> Principal {
    Principal::Human(Id::<Human>::new("acme", "u-17").unwrap())
}

fn time(bound: Option<Duration>) -> Reading {
    Reading::new(Duration::new(1_800_000_000, 250), bound, ReadingSource::Caller)
}

/// A verifier that claims phishing resistance for a recovery gets evidence without it, and a stored
/// form of a recovery with phishing resistance does not read. A passkey keeps the property.
#[test]
fn a_recovery_never_reports_phishing_resistance() {
    let recovery = Evidence::new(human(), Method::Recovery, time(None), true, true, None, None);
    assert!(recovery.recovery());
    assert!(!recovery.phishing_resistant());
    let passkey = Evidence::new(human(), Method::Passkey, time(None), true, true, None, None);
    assert!(passkey.phishing_resistant() && !passkey.recovery());

    let cbor::Value::Array(mut items) = recovery.to_cbor() else {
        panic!("evidence is an array");
    };
    items[5] = cbor::Value::Bool(true);
    assert_eq!(
        Evidence::from_cbor(&cbor::Value::Array(items)),
        Err(EvidenceError::Form)
    );
}

/// The evidence of a proof of possession of the credential of `subject`, whose claims start before
/// the proof and end after it.
fn possession(principal: Principal, subject: Subject) -> Evidence {
    let mut evidence = Evidence::new(
        principal,
        Method::KeyPossession,
        time(Some(Duration::from_secs(1))),
        false,
        false,
        None,
        Some(Authentication::Hybrid),
    );
    let mut claims = Claims::new(
        Id::new("acme", "agents").unwrap(),
        Id::new("acme", "api").unwrap(),
        subject,
        Id::new("acme", "agent").unwrap(),
        Serial(9),
        Duration::from_secs(1_800_003_600),
    );
    claims.not_before = Some(Duration::from_secs(1_799_999_000));
    evidence.artifact = Some(Artifact {
        claims,
        confirmation: [3; 32],
        digest: [4; 32],
        end: Duration::from_secs(1_800_001_800),
    });
    evidence
}

/// Evidence reads back from its encoded CBOR form with each fact: the kind of its subject, the time
/// with a known or an unknown bound, each binding, each authentication of a signature, each backup
/// state of a passkey, and the credential of a proof of possession with the owner and the grant
/// revision of an agent and the key that proved it.
#[test]
fn evidence_reads_back_from_its_cbor_form() {
    let agent = Principal::Agent(Id::<Agent>::new("acme", "u-17").unwrap());
    let passkey = |backup| {
        let mut evidence = Evidence::new(
            human(),
            Method::Passkey,
            time(Some(Duration::from_millis(20))),
            true,
            true,
            None,
            Some(Authentication::PostQuantum),
        );
        evidence.backup = Some(backup);
        evidence
    };
    let cases = [
        passkey(Backup::SingleDevice),
        passkey(Backup::Eligible),
        passkey(Backup::BackedUp),
        Evidence::new(
            human(),
            Method::KeyPossession,
            time(None),
            false,
            false,
            Some(Binding::Device),
            Some(Authentication::Classical),
        ),
        Evidence::new(
            agent.clone(),
            Method::KeyPossession,
            time(None),
            false,
            false,
            Some(Binding::Hardware),
            Some(Authentication::Hybrid),
        ),
        Evidence::new(
            human(),
            Method::KeyPossession,
            time(None),
            false,
            false,
            None,
            Some(Authentication::Classical),
        ),
        Evidence::new(human(), Method::Provider, time(None), false, false, None, None),
        possession(
            agent,
            Subject::Agent {
                agent: Id::new("acme", "u-17").unwrap(),
                owner: Id::new("acme", "alice").unwrap(),
                revision: 7,
            },
        ),
        possession(
            Principal::Workload(Id::<Workload>::new("acme", "runner-7").unwrap()),
            Subject::Workload(Id::new("acme", "runner-7").unwrap()),
        ),
    ];
    for evidence in cases {
        let encoded = cbor::encode(&evidence.to_cbor(), Limits::default()).unwrap();
        let value = cbor::decode(&encoded, crate::limits::Limits::default()).unwrap();
        assert_eq!(Evidence::from_cbor(&value), Ok(evidence));
    }
}

/// A form that another version wrote does not read as this one: the form of A216 with no name, and a form of another
/// name with the same items, such as the first form, which had no grant revision and no key thumbprint.
#[test]
fn a_stored_form_of_another_version_refuses() {
    let evidence = Evidence::new(human(), Method::Passkey, time(None), true, true, None, None);
    let cbor::Value::Array(items) = evidence.to_cbor() else {
        panic!("evidence is an array");
    };
    assert_eq!(items[0], cbor::Value::Text("rsauthnz.evidence.2"));
    let unnamed = cbor::Value::Array(items[1..].to_vec());
    assert_eq!(Evidence::from_cbor(&unnamed), Err(EvidenceError::Form));
    let mut renamed = items;
    renamed[0] = cbor::Value::Text("rsauthnz.evidence.1");
    assert_eq!(
        Evidence::from_cbor(&cbor::Value::Array(renamed)),
        Err(EvidenceError::Form)
    );
}
