use core::time::Duration;

use super::{Binding, Evidence, EvidenceError, Method};
use crate::cbor;
use crate::id::{Agent, Human, Id, Principal};
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
    let recovery = Evidence::new(human(), Method::Recovery, time(None), true, true, None);
    assert!(recovery.recovery());
    assert!(!recovery.phishing_resistant());
    let passkey = Evidence::new(human(), Method::Passkey, time(None), true, true, None);
    assert!(passkey.phishing_resistant() && !passkey.recovery());

    let cbor::Value::Array(mut items) = recovery.to_cbor() else {
        panic!("evidence is an array");
    };
    items[4] = cbor::Value::Bool(true);
    assert_eq!(
        Evidence::from_cbor(&cbor::Value::Array(items)),
        Err(EvidenceError::Form)
    );
}

/// Evidence reads back from its encoded CBOR form with each fact: the kind of its subject, the time
/// with a known or an unknown bound, and each binding.
#[test]
fn evidence_reads_back_from_its_cbor_form() {
    let agent = Principal::Agent(Id::<Agent>::new("acme", "u-17").unwrap());
    let cases = [
        Evidence::new(
            human(),
            Method::Passkey,
            time(Some(Duration::from_millis(20))),
            true,
            true,
            Some(Binding::Device),
        ),
        Evidence::new(
            agent,
            Method::KeyPossession,
            time(None),
            false,
            false,
            Some(Binding::Hardware),
        ),
        Evidence::new(human(), Method::Provider, time(None), false, false, None),
    ];
    for evidence in cases {
        let encoded = cbor::encode(&evidence.to_cbor()).unwrap();
        let value = cbor::decode(&encoded, cbor::Limits::default()).unwrap();
        assert_eq!(Evidence::from_cbor(&value), Ok(evidence));
    }
}
