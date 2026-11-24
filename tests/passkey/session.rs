//! The browser sessions of a passkey sign-in: renewal, inspection, revocation, and restore.

use core::num::NonZeroUsize;

use rsauthnz::account::{FRESH_MAX, Fresh};
use rsauthnz::crypto::Algorithm;
use rsauthnz::id::{Human, Id};
use rsauthnz::limits::Limits;
use rsauthnz::session::{
    self, Access, Check, Error, Generation, Identifier, Issued, Opened, Renewal, Revoker, Sessions,
};
use rsauthnz::store::driver::{Answer, Lookup, Plan};
use rsauthnz::store::{Kind, Store};
use rsauthnz::time::{Reading, ReadingSource, TimeError};
use rsauthnz::transition::{Outcome, Proposal};
use rsauthnz_conformance::memory;
use rsauthnz_conformance::suite::{Fault, Subject as _};
use rscodec::base64::Profile::Url;

use super::authenticator::{self, Get, Passkey, Registration};
use super::{HANDLE, ORIGIN, POLICY, RP_ID, START, Site, at, authority, ready};
use std::assert_matches;

/// The user handle of bob.
pub(super) const BOB: [u8; 32] = [8; 32];

/// The refusal of a failure of an operation of the memory binding, which reads with no failure.
fn refused(failure: session::Failure<memory::Error>) -> Error {
    match failure {
        session::Failure::Refused(error) => error,
        session::Failure::Store(error) => panic!("the memory binding failed a read: {error}"),
    }
}

/// The time `seconds` after [`START`].
const fn time(seconds: u64) -> core::time::Duration {
    START.saturating_add(core::time::Duration::from_secs(seconds))
}

impl Site {
    /// The session of the sign-in of `passkey` of the account with the user handle `handle` at `seconds`, which ends
    /// the family of `replaces`.
    pub(super) fn session_of(
        &mut self,
        passkey: &Passkey,
        handle: [u8; 32],
        seconds: u64,
        replaces: Option<&Access>,
    ) -> Opened {
        let json = Get::new(passkey, RP_ID, ORIGIN, self.options(at(seconds - 1)), handle).json();
        self.opened(&json, at(seconds), replaces)
    }

    fn check(&mut self, identifier: &Identifier, now: Reading) -> Result<Check, Error> {
        ready(self.sessions.check(&mut self.node.memory, identifier, now)).map_err(refused)
    }

    /// The session of `identifier` at `now`, which must serve.
    pub(super) fn active(&mut self, identifier: &Identifier, now: Reading) -> Access {
        match self.check(identifier, now) {
            Ok(Check::Active(access)) => access,
            other => panic!("the session does not serve: {other:?}"),
        }
    }

    fn renew(&mut self, access: &Access, now: Reading) -> Result<(Proposal, Plan, Renewal), Error> {
        self.sessions
            .renew(access, now, &mut self.random, &mut self.node.driver)
    }

    /// The next generation of the accepted renewal of `access` at `now`.
    fn renewed(&mut self, access: &Access, now: Reading) -> Issued {
        let (proposal, plan, renewal) = self.renew(access, now).expect("a renewal");
        let outcome = self.node.commit(proposal, plan);
        renewal.release(&outcome).expect("the next generation")
    }

    /// Registers a passkey for bob, with the user handle [`BOB`].
    pub(super) fn register_bob(&mut self) -> Passkey {
        let bob = Id::<Human>::new("acme", "bob").expect("an identifier");
        let challenge = authenticator::challenge(&self.options_of(&bob, BOB));
        let passkey = Passkey::new(Algorithm::Ed25519, -8, 7);
        let (proposal, plan) = self.propose(&Registration::new(&passkey, RP_ID, ORIGIN, challenge).json(), at(1));
        assert!(matches!(self.node.commit(proposal, plan), Outcome::Accepted(_)));
        passkey
    }
}

/// The bytes of an identifier, from its cookie value.
fn bytes(identifier: &Identifier) -> [u8; session::IDENTIFIER_BYTES] {
    let text = identifier.encode().expect("the cookie value");
    let mut bytes = [0; session::IDENTIFIER_BYTES];
    Url.decode(text.as_bytes(), &mut bytes).expect("base64url");
    bytes
}

#[test]
fn two_concurrent_renewals_of_one_generation_commit_once_and_the_loser_holds_the_replaced_one() {
    let mut site = Site::new();
    let passkey = site.register(Algorithm::Ed25519, -8, 1, 0);
    let first = site.session_of(&passkey, HANDLE, 11, None).session;
    // The sign-in at 11 starts the generation at 10, so its renewal is due at 60.
    let access = site.active(first.identifier(), at(70));
    assert!(access.renewal_due(at(70)));
    let (one, one_plan, winner) = site.renew(&access, at(70)).expect("a renewal");
    let (two, two_plan, loser) = site.renew(&access, at(70)).expect("a renewal");
    let won = site.node.commit(one, one_plan);
    let lost = site.node.commit(two, two_plan);
    assert!(matches!(lost, Outcome::Conflict));
    assert!(loser.release(&lost).is_none());
    let current = winner.release(&won).expect("the next generation");

    // Within the grace time, the replaced identifier serves its request and cannot renew.
    let replaced = site.active(first.identifier(), at(77));
    assert_eq!(replaced.generation(), Generation::Replaced);
    assert!(!replaced.renewal_due(at(77)));
    assert_eq!(site.renew(&replaced, at(77)).err(), Some(Error::Replaced));
    assert_eq!(
        site.active(current.identifier(), at(77)).generation(),
        Generation::Current
    );

    // The renewal started the generation at 69, so the grace ends at 79. A use after it ends the family.
    let Ok(Check::Reused(proposal, plan)) = site.check(first.identifier(), at(80)) else {
        panic!("a use after the grace time is a reuse");
    };
    assert!(matches!(site.node.commit(proposal, plan), Outcome::Accepted(_)));
    assert_eq!(site.check(current.identifier(), at(81)).err(), Some(Error::Unknown));
}

#[test]
fn a_revoked_session_refuses_at_its_next_use_also_in_an_open_stream() {
    let mut site = Site::new();
    let passkey = site.register(Algorithm::Ed25519, -8, 1, 0);
    let first = site.session_of(&passkey, HANDLE, 11, None).session;
    let stream = site.active(first.identifier(), at(20));
    let confirm = |site: &mut Site, now| ready(site.sessions.confirm(&mut site.node.memory, stream.session(), now));
    assert_eq!(confirm(&mut site, at(21)), Ok(()));
    // A renewal keeps the family, so the stream continues.
    let access = site.active(first.identifier(), at(70));
    let current = site.renewed(&access, at(70));
    assert_eq!(confirm(&mut site, at(71)), Ok(()));

    // The account signs out.
    let access = site.active(current.identifier(), at(72));
    let (proposal, plan) = site
        .sessions
        .revoke(access.session(), Revoker::Own(&access), &[], at(72), &mut site.random)
        .expect("a revocation");
    assert!(matches!(site.node.commit(proposal, plan), Outcome::Accepted(_)));
    assert_eq!(confirm(&mut site, at(73)), Err(session::Failure::Refused(Error::Ended)));
    assert_eq!(site.check(current.identifier(), at(73)).err(), Some(Error::Unknown));
}

#[test]
fn a_fresh_user_verification_changes_the_identifier_and_the_old_one_refuses() {
    let mut site = Site::new();
    let passkey = site.register(Algorithm::Ed25519, -8, 1, 0);
    let old = site.session_of(&passkey, HANDLE, 11, None).session;
    let access = site.active(old.identifier(), at(20));
    let fresh = site.session_of(&passkey, HANDLE, 31, Some(&access));
    assert_ne!(bytes(fresh.session.identifier()), bytes(old.identifier()));
    assert_eq!(site.check(old.identifier(), at(32)).err(), Some(Error::Unknown));
    let access = site.active(fresh.session.identifier(), at(32));
    assert_eq!(access.session().evidence().time(), fresh.evidence.time());
    assert!(access.session().evidence().user_verified());
}

#[test]
fn a_dump_of_the_store_holds_no_usable_session_identifier() {
    let mut site = Site::new();
    let passkey = site.register(Algorithm::Ed25519, -8, 1, 0);
    let first = site.session_of(&passkey, HANDLE, 11, None).session;
    let access = site.active(first.identifier(), at(70));
    // The renewal keeps the tag of the replaced generation in the record too.
    let current = site.renewed(&access, at(70));

    let mut dump = Vec::new();
    for kind in Kind::ALL {
        let prefix = kind.key(&[]).expect("a key of one byte");
        let records = ready(site.node.memory.range(&prefix, None, NonZeroUsize::MAX)).expect("a read");
        dump.extend(
            records
                .into_iter()
                .map(|(key, record)| [key.as_bytes(), &record.data].concat()),
        );
    }
    let holds = |needle: &[u8]| {
        dump.iter()
            .any(|bytes| bytes.windows(needle.len()).any(|window| window == needle))
    };
    for identifier in [first.identifier(), current.identifier()] {
        let bytes = bytes(identifier);
        let text = identifier.encode().expect("the cookie value");
        // The positive control: the search reads the keys, which start with the locator.
        assert!(holds(&bytes[..16]));
        for needle in [&bytes[..], &bytes[16..32], &bytes[72..], text.as_bytes()] {
            assert!(!holds(needle));
        }
    }
    // The positive control of the records: they hold the account.
    assert!(holds(b"alice"));
}

#[test]
fn a_family_ends_at_its_idle_time_and_no_renewal_passes_its_lifetime() {
    let mut site = Site::new();
    let passkey = site.register(Algorithm::Ed25519, -8, 1, 0);
    // With no renewal, the generation of the sign-in at 11 ends at 110.
    let idle = site.session_of(&passkey, HANDLE, 11, None).session;
    assert_eq!(idle.end(), time(110));
    site.active(idle.identifier(), at(108));
    assert_eq!(site.check(idle.identifier(), at(109)).err(), Some(Error::Ended));

    // The family of the sign-in at 21 ends at 1,020, its sign-in at 20 plus the lifetime.
    let mut current = site.session_of(&passkey, HANDLE, 21, None).session;
    for seconds in (80..1_000).step_by(60) {
        let access = site.active(current.identifier(), at(seconds));
        current = site.renewed(&access, at(seconds));
    }
    // The last renewal at 980 starts a generation at 979, which ends at the end of the family, not at 1,079.
    assert_eq!(current.end(), time(1_020));
    let access = site.active(current.identifier(), at(1_000));
    assert_eq!(access.session().expires(), time(1_020));
    assert_eq!(site.renew(&access, at(1_019)).err(), Some(Error::Ended));
    assert_eq!(site.check(current.identifier(), at(1_019)).err(), Some(Error::Ended));
}

#[test]
fn a_restore_from_an_older_snapshot_releases_no_session_generation_twice() {
    let mut site = Site::new();
    let passkey = site.register(Algorithm::Ed25519, -8, 1, 0);
    let first = site.session_of(&passkey, HANDLE, 11, None).session;
    let snapshot = site.node.memory.snapshot();
    let access = site.active(first.identifier(), at(70));
    let second = site.renewed(&access, at(70));
    // The store comes back from the snapshot, which holds the first generation as current.
    site.node.memory.restore(&snapshot);
    site.node.driver.restore(at(80)).expect("a restore");
    site.node.run();
    // The journal records that the renewal consumed the first generation, so it does not serve again.
    assert_eq!(site.check(first.identifier(), at(81)).err(), Some(Error::Unknown));
    assert_eq!(site.check(second.identifier(), at(81)).err(), Some(Error::Unknown));
}

#[test]
fn a_lost_renewal_response_releases_the_next_generation_after_a_lookup_of_the_server() {
    let mut site = Site::new();
    let passkey = site.register(Algorithm::Ed25519, -8, 1, 0);
    let first = site.session_of(&passkey, HANDLE, 11, None).session;
    let access = site.active(first.identifier(), at(70));
    let (proposal, plan, renewal) = site.renew(&access, at(70)).expect("a renewal");
    let operation = proposal.operation().clone();
    site.node.memory.inject(Fault::LostResponse);
    assert!(matches!(site.node.commit(proposal, plan), Outcome::Unknown(_)));
    site.node.start();
    let ticket = site.node.driver.lookup(operation).expect("a lookup");
    site.node.run();
    let Some(Answer::Lookup(Lookup::Committed(receipt))) = site.node.driver.take(ticket) else {
        panic!("the lookup shows the commit");
    };
    // The server answers the same request with the cookie of the next generation.
    let next = renewal
        .release(&Outcome::Accepted(receipt))
        .expect("the next generation");
    assert_eq!(site.active(next.identifier(), at(71)).generation(), Generation::Current);
}

#[test]
fn the_listing_gives_each_session_of_the_account_that_did_not_end() {
    let mut site = Site::new();
    let passkey = site.register(Algorithm::Ed25519, -8, 1, 0);
    let bob = site.register_bob();
    let laptop = site.session_of(&passkey, HANDLE, 11, None).session;
    let phone = site.session_of(&passkey, HANDLE, 31, None).session;
    site.session_of(&bob, BOB, 41, None);
    let list = |site: &mut Site, access: &Access, now| {
        let page = ready(site.sessions.list(&mut site.node.memory, access, None, now));
        let page = page.map_err(refused).expect("a page");
        assert_eq!(page.next, None);
        let mut keys: Vec<_> = page.sessions.iter().map(|session| session.key().clone()).collect();
        keys.sort();
        keys
    };
    let laptop = site.active(laptop.identifier(), at(50));
    let phone = site.active(phone.identifier(), at(50));
    let mut both = vec![laptop.session().key().clone(), phone.session().key().clone()];
    both.sort();
    assert_eq!(list(&mut site, &phone, at(50)), both);

    // The account ends the session of the laptop from the listing on the phone, with the fresh verification of its
    // sign-in at 31.
    let fresh = Fresh::check(&phone, FRESH_MAX, at(51)).expect("a fresh verification");
    let (proposal, plan) = site
        .sessions
        .revoke(laptop.session(), Revoker::Fresh(&fresh), &[], at(51), &mut site.random)
        .expect("a revocation");
    assert!(matches!(site.node.commit(proposal, plan), Outcome::Accepted(_)));
    assert_eq!(list(&mut site, &phone, at(52)), vec![phone.session().key().clone()]);
    // The session of the phone, from the sign-in at 31, ends at 130 with no renewal.
    assert_matches!(
        ready(site.sessions.list(&mut site.node.memory, &phone, None, at(130))),
        Err(session::Failure::Refused(Error::Ended))
    );
}

#[test]
fn an_identifier_refuses_at_another_audience_and_under_a_reading_with_no_bound() {
    let mut site = Site::new();
    let passkey = site.register(Algorithm::Ed25519, -8, 1, 0);
    let session = site.session_of(&passkey, HANDLE, 11, None).session;
    let admin = Sessions::new(
        authority(),
        Id::new("acme", "admin").expect("an identifier"),
        POLICY,
        Limits::default(),
    )
    .expect("the sessions");
    let check = admin.check(&mut site.node.memory, session.identifier(), at(20));
    assert_eq!(ready(check).map_err(refused).err(), Some(Error::Unknown));
    let unbounded = Reading::new(time(20), None, ReadingSource::Caller);
    assert_eq!(
        site.check(session.identifier(), unbounded).err(),
        Some(Error::Time(TimeError::UnknownBound))
    );
    // The control: the audience of the sign-in serves it.
    site.active(session.identifier(), at(20));
}
