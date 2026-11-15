use core::cmp::Ordering;

use super::{
    Action, Agent, Authority, AuthorityVersion, Human, Id, IdError, MAX_NAMESPACE, MAX_VALUE, Principal, Resource,
    VersionError, Workload,
};
use crate::cbor;

/// A human and an agent with the same raw identifier are different principals: they are not
/// equal, the CBOR form of the agent does not read as a human, and a principal keeps its kind
/// through its CBOR form.
#[test]
fn a_human_and_an_agent_with_the_same_raw_id_stay_distinct() {
    let human = Id::<Human>::new("acme", "u-17").unwrap();
    let agent = Id::<Agent>::new("acme", "u-17").unwrap();
    assert_ne!(Principal::Human(human.clone()), Principal::Agent(agent.clone()));
    assert_ne!(
        Principal::Workload(Id::<Workload>::new("acme", "u-17").unwrap()),
        Principal::Agent(agent.clone())
    );

    let encoded = cbor::encode(&agent.to_cbor()).unwrap();
    let value = cbor::decode(&encoded, crate::limits::Limits::default()).unwrap();
    assert_eq!(Id::<Human>::from_cbor(&value), Err(IdError::Kind));
    assert_eq!(Principal::from_cbor(&value), Ok(Principal::Agent(agent)));
    assert_eq!(
        Principal::from_cbor(&Principal::Human(human.clone()).to_cbor()),
        Ok(Principal::Human(human))
    );
    let resource = Id::<Resource>::new("acme", "u-17").unwrap();
    assert_eq!(Principal::from_cbor(&resource.to_cbor()), Err(IdError::Kind));
}

/// Each part admits its longest length and refuses one byte more, and an empty part or a byte
/// outside its rule refuses.
#[test]
fn an_identifier_over_its_bound_refuses() {
    let namespace = "n".repeat(MAX_NAMESPACE);
    let value = "v".repeat(MAX_VALUE);
    let id = Id::<Action>::new(&namespace, &value).unwrap();
    assert_eq!((id.namespace(), id.value()), (namespace.as_str(), value.as_str()));
    assert_eq!(
        Id::<Action>::new(&"n".repeat(MAX_NAMESPACE + 1), "v"),
        Err(IdError::Namespace)
    );
    assert_eq!(Id::<Action>::new("n", &"v".repeat(MAX_VALUE + 1)), Err(IdError::Value));
    for namespace in ["", "Acme", "acme:repo", "acme repo"] {
        assert_eq!(
            Id::<Action>::new(namespace, "v"),
            Err(IdError::Namespace),
            "{namespace:?}"
        );
    }
    for value in ["", "repo read", "repo\u{e9}", "repo\n"] {
        assert_eq!(Id::<Action>::new("acme", value), Err(IdError::Value), "{value:?}");
    }
}

/// The canonical CBOR form is `[kind, namespace, value]`: here kind 6 (action) and two text strings
/// of 9 bytes each.
#[test]
fn an_identifier_has_one_canonical_cbor_form() {
    let id = Id::<Action>::new("acme.repo", "repo.read").unwrap();
    let mut expected = vec![0x83, 0x06, 0x69];
    expected.extend_from_slice(b"acme.repo");
    expected.push(0x69);
    expected.extend_from_slice(b"repo.read");
    assert_eq!(cbor::encode(&id.to_cbor()), Ok(expected.clone()));
    let value = cbor::decode(&expected, crate::limits::Limits::default()).unwrap();
    assert_eq!(Id::<Action>::from_cbor(&value), Ok(id));
}

/// Versions of one owner compare by their coordinates. Versions of two owners refuse comparison,
/// also when their coordinates are equal.
#[test]
fn versions_of_two_owners_refuse_comparison() {
    let acme = Id::<Authority>::new("acme", "policy").unwrap();
    let globex = Id::<Authority>::new("globex", "policy").unwrap();
    let version =
        |owner: &Id<Authority>, counter: u64| AuthorityVersion::new(owner.clone(), &counter.to_be_bytes()).unwrap();
    assert_eq!(version(&acme, 255).compare(&version(&acme, 256)), Ok(Ordering::Less));
    assert_eq!(version(&acme, 9).compare(&version(&acme, 9)), Ok(Ordering::Equal));
    assert_eq!(
        version(&acme, 9).compare(&version(&globex, 9)),
        Err(VersionError::Owners)
    );
    assert_ne!(version(&acme, 9), version(&globex, 9));

    let coordinate = [7; AuthorityVersion::MAX_COORDINATE];
    let longest = AuthorityVersion::new(acme.clone(), &coordinate).unwrap();
    assert_eq!(AuthorityVersion::from_cbor(&longest.to_cbor()), Ok(longest));
    let refused = [7; AuthorityVersion::MAX_COORDINATE + 1];
    assert_eq!(
        AuthorityVersion::new(acme.clone(), &refused),
        Err(VersionError::Coordinate)
    );
    assert_eq!(AuthorityVersion::new(acme, &[]), Err(VersionError::Coordinate));
}
