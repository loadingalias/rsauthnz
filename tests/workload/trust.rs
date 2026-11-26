//! The trust snapshots of a remote verifier: one signed snapshot of the issuers and the workload generations, installed
//! monotonically, and fresh only from its signed time of issue.

use core::time::Duration;

use rsauthnz::agent::{self, KEY_BYTES};
use rsauthnz::credential::{self, Released};
use rsauthnz::crypto::Algorithm;
use rsauthnz::custody::{Handle, KeyId};
use rsauthnz::id::{Authority, Id};
use rsauthnz::limits::Limits;
use rsauthnz::time::{Reading, ReadingSource, TimeError};
use rsauthnz::transition::Outcome;
use rsauthnz::trust::{Draft, Error, Freshness, Profile, Refresh, Trust};
use rsauthnz::workload::{self, Target};
use rscrypto::auth::SlhDsaSha2_128s;

use super::{Custody, Host, START, at, audience, authority, budget, ceiling, issuance, minutes, ready, runner_id};

/// A snapshot ends 10 minutes after its issue, and a refresh is due after 5 minutes.
const FRESHNESS: Freshness = Freshness {
    max_age: Duration::from_secs(600),
    uncertainty: Duration::from_secs(2),
    propagation: Duration::from_secs(660),
    retry: Duration::from_secs(60),
};

/// The authority of the snapshots.
fn domain() -> Id<Authority> {
    Id::new("acme", "trust").unwrap()
}

/// The handle of the composite key `key` as a trust root.
fn handle(key: &Custody) -> Handle {
    Handle::new(KeyId::from_bytes([20; 16]), Algorithm::MlDsa65Ed25519, &key.public).unwrap()
}

/// A verifier that trusts the root `key`, with no snapshot.
fn verifier(key: &Custody) -> Trust {
    Trust::new(Profile::new(domain(), handle(key), FRESHNESS, Limits::default()).unwrap())
}

impl Host {
    /// The snapshot of the store at `now` that `root` signs.
    fn snapshot(&mut self, root: &Custody, now: Reading) -> Vec<u8> {
        let (domain, handle) = (domain(), handle(root));
        let draft = ready(Draft::read(
            &mut self.node.memory,
            &domain,
            &handle,
            now,
            Limits::default(),
        ))
        .unwrap();
        let signature = root.sign(&draft.to_be_signed());
        draft.finish(&signature, &mut budget()).unwrap()
    }
}

/// Installs `snapshot` in `trust` at `now`, through the one fetch that the refresh gives.
fn install(trust: &mut Trust, snapshot: &[u8], now: Reading) -> Result<(), Error> {
    let Refresh::Fetch(ticket) = trust.refresh(now).unwrap() else {
        panic!("a refresh is due");
    };
    trust.install(ticket, snapshot, now)
}

/// The check of a remote verifier: `credential` verifies at `audience` under the issuer of the snapshot, and the
/// snapshot admits it, at `now`.
fn admits(trust: &Trust, credential: &Released, audience: &str, now: Reading) -> Result<(), workload::Error> {
    let view = trust.view(now).unwrap();
    let issuer = view.issuer(&authority()).unwrap();
    let profile = issuer.profile(&self::audience(audience), Limits::default())?;
    let verified = profile.verify(credential.as_bytes(), now, &mut budget())?;
    view.admits(&verified)
}

#[test]
fn a_remote_verifier_refuses_a_credential_that_a_revocation_before_its_snapshot_ended() {
    let (mut host, root) = (Host::new(ceiling()), Custody::new(20));
    let operator = host.operator.clone();
    let build = host.first("i-1");
    let deploy = host
        .issue(issuance("i-2", &operator, &audience("deploy-api")), at(0))
        .unwrap();
    let mut trust = verifier(&root);
    install(&mut trust, &host.snapshot(&root, at(0)), at(0)).unwrap();
    admits(&trust, &build, "build-api", at(1)).unwrap();
    admits(&trust, &deploy, "deploy-api", at(1)).unwrap();

    let record = host.record(&deploy);
    let revoked = host.revoke("rv-0", Target::Credential(deploy.serial(), &record), at(1));
    assert!(matches!(revoked, Outcome::Accepted(_)));
    // The residual window: the snapshot from before the revocation still admits the credential until a refresh.
    admits(&trust, &deploy, "deploy-api", at(2)).unwrap();
    assert_eq!(trust.refresh(at(2)), Ok(Refresh::Fresh));
    install(&mut trust, &host.snapshot(&root, at(5)), at(5)).unwrap();
    assert_eq!(
        admits(&trust, &deploy, "deploy-api", at(6)),
        Err(workload::Error::Revoked)
    );
    admits(&trust, &build, "build-api", at(6)).unwrap();
}

#[test]
fn an_older_snapshot_after_a_newer_one_refuses_and_so_does_another_one_of_the_same_issue() {
    let (mut host, root) = (Host::new(ceiling()), Custody::new(20));
    let old = host.snapshot(&root, at(0));
    let new = host.snapshot(&root, at(5));
    let mut trust = verifier(&root);
    install(&mut trust, &new, at(5)).unwrap();
    // The refresh at 10 gets the older snapshot, for example from a stale cache.
    assert_eq!(install(&mut trust, &old, at(10)), Err(Error::Rollback));
    assert_eq!(
        trust.view(at(10)).unwrap().issued(),
        (START + minutes(5)).checked_sub(Duration::from_secs(1)).unwrap()
    );

    // The same issue again changes nothing. Another snapshot with the same time of issue refuses.
    assert_eq!(install(&mut trust, &new, at(11)), Ok(()));
    let deploy = host
        .issue(issuance("i-2", &host.operator.clone(), &audience("deploy-api")), at(5))
        .unwrap();
    let record = host.record(&deploy);
    host.revoke("rv-0", Target::Credential(deploy.serial(), &record), at(5));
    let other = host.snapshot(&root, at(5));
    assert_ne!(other, new);
    assert_eq!(install(&mut trust, &other, at(12)), Err(Error::Inconsistent));
}

#[test]
fn a_snapshot_past_its_maximum_age_refuses() {
    let (mut host, root) = (Host::new(ceiling()), Custody::new(20));
    let snapshot = host.snapshot(&root, at(0));
    let mut trust = verifier(&root);
    install(&mut trust, &snapshot, at(0)).unwrap();
    // The snapshot was issued at 1 second before minute 0, so it ends 10 minutes later.
    let before = Reading::new(
        (START + minutes(10)).checked_sub(Duration::from_secs(4)).unwrap(),
        Some(Duration::from_secs(1)),
        ReadingSource::Caller,
    );
    let end = trust.view(before).unwrap().end();
    assert_eq!(end, (START + minutes(10)).checked_sub(Duration::from_secs(1)).unwrap());
    assert_eq!(trust.view(at(10)).err(), Some(Error::Stale));
}

#[test]
fn a_rollback_of_the_injected_time_or_a_replayed_old_snapshot_extends_no_reuse() {
    let (mut host, root) = (Host::new(ceiling()), Custody::new(20));
    let snapshot = host.snapshot(&root, at(0));
    let mut trust = verifier(&root);
    install(&mut trust, &snapshot, at(0)).unwrap();
    assert_eq!(trust.view(at(10)).err(), Some(Error::Stale));
    // The wall clock moves back 6 minutes. The trust keeps the latest time that it saw.
    assert_eq!(trust.view(at(4)).err(), Some(Error::Stale));
    // A new verifier gets the old snapshot at minute 10: its freshness comes from its issue, not from the fetch.
    let mut replayed = verifier(&root);
    assert_eq!(install(&mut replayed, &snapshot, at(10)), Err(Error::Stale));
    // The control: the same snapshot installs within its maximum age.
    let mut fresh = verifier(&root);
    install(&mut fresh, &snapshot, at(9)).unwrap();
}

#[test]
fn a_snapshot_with_a_changed_signature_or_payload_or_of_another_root_refuses() {
    let (mut host, root) = (Host::new(ceiling()), Custody::new(20));
    let snapshot = host.snapshot(&root, at(0));
    let mut signature = snapshot.clone();
    *signature.last_mut().unwrap() ^= 1;
    // The payload holds the authority of the snapshot as text: `acme` becomes `acmf`.
    let at_name = snapshot.windows(4).position(|window| window == b"acme").unwrap();
    let mut payload = snapshot.clone();
    payload[at_name + 3] = b'f';
    let other = host.snapshot(&Custody::new(21), at(0));
    for changed in [signature, payload, other] {
        let mut trust = verifier(&root);
        assert_eq!(install(&mut trust, &changed, at(0)), Err(Error::Signature));
        assert_eq!(trust.view(at(0)).err(), Some(Error::Missing));
    }
    // The control: the snapshot as the root signed it installs.
    install(&mut verifier(&root), &snapshot, at(0)).unwrap();
}

#[test]
fn a_reading_with_no_bound_or_a_larger_bound_than_the_declared_uncertainty_refuses() {
    let (mut host, root) = (Host::new(ceiling()), Custody::new(20));
    let mut trust = verifier(&root);
    install(&mut trust, &host.snapshot(&root, at(0)), at(0)).unwrap();
    let reading = |bound| Reading::new(START + minutes(1), bound, ReadingSource::Caller);
    assert_eq!(
        trust.view(reading(None)).err(),
        Some(Error::Time(TimeError::UnknownBound))
    );
    assert_eq!(
        trust.view(reading(Some(Duration::from_secs(3)))).err(),
        Some(Error::Uncertain)
    );
    assert_eq!(trust.refresh(reading(None)), Err(Error::Time(TimeError::UnknownBound)));
    trust.view(reading(Some(Duration::from_secs(2)))).unwrap();
    // Declared times that cannot meet the propagation objective refuse.
    let slow = Freshness {
        propagation: Duration::from_secs(601),
        ..FRESHNESS
    };
    let profile = Profile::new(domain(), handle(&root), slow, Limits::default());
    assert_eq!(profile.err(), Some(Error::Freshness));
}

#[test]
fn ten_concurrent_refresh_requests_make_one_fetch() {
    // A server shares one trust between its threads.
    const fn shared<T: Send + Sync>() {}
    shared::<Trust>();
    let (mut host, root) = (Host::new(ceiling()), Custody::new(20));
    let mut trust = verifier(&root);
    let refreshes: Vec<_> = (0..10).map(|_| trust.refresh(at(0)).unwrap()).collect();
    let fetches: Vec<_> = refreshes
        .iter()
        .filter_map(|refresh| match refresh {
            Refresh::Fetch(ticket) => Some(*ticket),
            _ => None,
        })
        .collect();
    assert_eq!(fetches.len(), 1);
    assert!(refreshes[1..].iter().all(|refresh| *refresh == Refresh::Pending));
    // The fetch fails. The next one waits for the retry time after its start.
    trust.fail(fetches[0]);
    assert_eq!(trust.refresh(at(0)), Ok(Refresh::Pending));
    let Ok(Refresh::Fetch(ticket)) = trust.refresh(at(1)) else {
        panic!("a fetch after the retry time");
    };
    // An earlier ticket installs nothing.
    let snapshot = host.snapshot(&root, at(1));
    assert_eq!(trust.install(fetches[0], &snapshot, at(1)), Err(Error::Ticket));
    trust.install(ticket, &snapshot, at(1)).unwrap();
    assert_eq!(trust.refresh(at(2)), Ok(Refresh::Fresh));
}

#[test]
fn a_snapshot_that_an_slh_dsa_root_signs_installs() {
    let mut host = Host::new(ceiling());
    let (public, key) = SlhDsaSha2_128s::generate_keypair(|out| {
        out.fill(9);
        Ok(())
    })
    .unwrap();
    let root = Handle::new(
        KeyId::from_bytes([9; 16]),
        Algorithm::SlhDsaSha2_128s,
        public.as_bytes(),
    )
    .unwrap();
    let draft = ready(Draft::read(
        &mut host.node.memory,
        &domain(),
        &root,
        at(0),
        Limits::default(),
    ))
    .unwrap();
    let mut signature = [0; SlhDsaSha2_128s::SIGNATURE_LENGTH];
    key.sign_deterministic(&draft.to_be_signed(), &[], &mut signature)
        .unwrap();
    let snapshot = draft.finish(&signature, &mut budget()).unwrap();
    let mut trust = Trust::new(Profile::new(domain(), root, FRESHNESS, Limits::default()).unwrap());
    install(&mut trust, &snapshot, at(0)).unwrap();
    // A credential of the registration in the snapshot passes the check.
    let build = host.first("i-1");
    admits(&trust, &build, "build-api", at(1)).unwrap();
}

/// A hosted agent gives the credential of its workload and a proof by the registered key over the agent key, and the
/// snapshot gives the workload. A proof over another agent key refuses, and so does a credential that a revocation
/// before the snapshot ended.
#[test]
fn a_workload_credential_with_a_proof_over_the_agent_key_gives_its_workload() {
    let (mut host, root) = (Host::new(ceiling()), Custody::new(20));
    let build = audience("build-api");
    let credential = host.first("i-1");
    let mut trust = verifier(&root);
    install(&mut trust, &host.snapshot(&root, at(0)), at(0)).unwrap();
    let agent_key = [7; KEY_BYTES];
    let challenge = agent::Workload::challenge(&agent_key);
    let proof = host.runner.prove(credential.as_bytes(), &build, &challenge, at(1));
    let hosted = |trust: &Trust, key: &[u8; KEY_BYTES], now: Reading| {
        let view = trust.view(now).unwrap();
        let profile = view
            .issuer(&authority())
            .unwrap()
            .profile(&build, Limits::default())
            .unwrap();
        agent::Workload::credential(&view, &profile, credential.as_bytes(), &proof, key, now)
    };
    let workload = hosted(&trust, &agent_key, at(1)).unwrap();
    assert_eq!(workload.issuer(), authority().to_string());
    assert_eq!(workload.subject(), runner_id().to_string());
    assert_eq!(
        hosted(&trust, &[8; KEY_BYTES], at(1)).err(),
        Some(agent::Error::Credential(credential::Error::Proof))
    );

    let record = host.record(&credential);
    let revoked = host.revoke("rv-0", Target::Credential(credential.serial(), &record), at(1));
    assert!(matches!(revoked, Outcome::Accepted(_)));
    install(&mut trust, &host.snapshot(&root, at(5)), at(5)).unwrap();
    assert_eq!(hosted(&trust, &agent_key, at(6)).err(), Some(agent::Error::Admission));
}
