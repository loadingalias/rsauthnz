//! Two application servers, each with its own commit driver, on one store.

use rsauthnz::account::{FRESH_MAX, Fresh};
use rsauthnz::crypto::Algorithm;
use rsauthnz::limits::Limits;
use rsauthnz::passkey::Error;
use rsauthnz::session::{Check, Issued, Revoker};
use rsauthnz::store::driver::{Answer, Driver, Effect, Plan, Status, Ticket};
use rsauthnz::store::{Profile, Store as _};
use rsauthnz::transition::{self, Outcome, Proposal};
use rsauthnz_conformance::suite::{self, Subject as _};
use rscrypto::ChaCha20Rng;

use super::authenticator::{Get, Passkey};
use super::{HANDLE, Node, ORIGIN, RP_ID, Site, at, ready};

impl Node {
    /// A second server on the store of this node: a driver with its own identity, which joins the open instance.
    fn peer(&self, seed: u8) -> Self {
        let memory = self.memory.clone();
        let profile = Profile::new(memory.declaration()).expect("a profile");
        let driver =
            Driver::new(profile, Limits::default(), &mut ChaCha20Rng::from_seed([seed; 32])).expect("a driver");
        let mut node = Self { memory, driver };
        node.join();
        node
    }

    /// A start that joins the open instance: it installs no new instance, so the peers keep serving.
    fn join(&mut self) {
        self.driver.start(at(0));
        assert!(
            !matches!(self.driver.effect(), Some(Effect::Start)),
            "a join installs no instance"
        );
        self.run();
        assert_eq!(self.driver.status(), Status::Serving);
    }

    /// The restart of this server: a new driver, as after the loss of the process, which joins the store.
    fn restart(&mut self, seed: u8) {
        *self = self.peer(seed);
    }

    /// Submits `proposal`, and runs the driver until the next effect is the commit of the proposal itself.
    fn hold(&mut self, proposal: Proposal, plan: Plan) -> Ticket {
        let operation = proposal.operation().id.clone();
        let ticket = self.driver.submit(proposal, plan).expect("a submission");
        while let Some(effect) = self.driver.effect() {
            if matches!(&effect, Effect::Commit(held, _) if held.operation().id == operation) {
                return ticket;
            }
            let output = ready(suite::execute(&mut self.memory, effect));
            self.driver.give(output).expect("the driver takes the output");
        }
        panic!("the driver gave no commit of the proposal");
    }

    /// Runs the driver, and gives the outcome of `ticket`.
    fn outcome(&mut self, ticket: Ticket) -> Outcome {
        self.run();
        match self.driver.take(ticket) {
            Some(Answer::Outcome(outcome)) => outcome,
            answer => panic!("the commit gave {answer:?}"),
        }
    }
}

/// Runs `operation` on `site` through the server `server`: its relying party and sessions are those of the site.
fn through<T>(site: &mut Site, server: &mut Node, operation: impl FnOnce(&mut Site) -> T) -> T {
    core::mem::swap(&mut site.node, server);
    let result = operation(site);
    core::mem::swap(&mut site.node, server);
    result
}

/// A passkey sign-in of alice with `passkey` through `site`, whose session serves: the sign-in at `seconds` and the
/// check at `seconds` + 1.
fn session(site: &mut Site, passkey: &Passkey, seconds: u64) -> Issued {
    let json = Get::new(passkey, RP_ID, ORIGIN, site.options(at(seconds - 1)), HANDLE).json();
    let issued = site.opened(&json, at(seconds), None).session;
    let check = ready(
        site.sessions
            .check(&mut site.node.memory, issued.identifier(), at(seconds + 1)),
    );
    assert!(matches!(check, Ok(Check::Active(_))), "{check:?}");
    issued
}

#[test]
fn two_servers_on_one_store_each_complete_a_passkey_sign_in_and_start_a_session() {
    let mut site = Site::new();
    let passkey = site.register(Algorithm::Ed25519, -8, 1, 0);
    let mut second = site.node.peer(31);
    let first = session(&mut site, &passkey, 11);
    let other = through(&mut site, &mut second, |site| session(site, &passkey, 21));
    // Each server reads each session of the store.
    for issued in [&first, &other] {
        let check = through(&mut site, &mut second, |site| {
            ready(site.sessions.check(&mut site.node.memory, issued.identifier(), at(30)))
        });
        assert!(matches!(check, Ok(Check::Active(_))));
    }
}

#[test]
fn a_restart_of_either_server_leaves_the_other_one_committing() {
    let mut site = Site::new();
    let passkey = site.register(Algorithm::Ed25519, -8, 1, 0);
    let mut second = site.node.peer(32);
    for (round, restarted) in [(0_u64, "second"), (1, "first")] {
        // A sign-in of one server waits at its commit while the other server restarts and joins.
        let seconds = 40 + 20 * round;
        let json = Get::new(&passkey, RP_ID, ORIGIN, site.options(at(seconds - 1)), HANDLE).json();
        if restarted == "first" {
            core::mem::swap(&mut site.node, &mut second);
        }
        let (proposal, plan, opening) = site.sign_in(&json, at(seconds)).expect("a sign-in");
        let ticket = site.node.hold(proposal, plan);
        second.restart(33 + u8::try_from(round).expect("a small round"));
        let outcome = site.node.outcome(ticket);
        assert!(matches!(outcome, Outcome::Accepted(_)), "{restarted}: {outcome:?}");
        let opened = opening.release(&outcome).expect("the session");
        let check = ready(
            site.sessions
                .check(&mut site.node.memory, opened.session.identifier(), at(seconds + 1)),
        );
        assert!(matches!(check, Ok(Check::Active(_))), "{restarted}");
        if restarted == "first" {
            core::mem::swap(&mut site.node, &mut second);
        }
    }
}

#[test]
fn two_servers_that_race_to_remove_the_two_passkeys_of_an_account_leave_one() {
    let mut site = Site::new();
    let first = site.register(Algorithm::Ed25519, -8, 1, 0);
    let added = site.add(&first, Algorithm::Es256, -7, 2);
    let mut second = site.node.peer(35);
    let fresh: Fresh = site.fresh(&added);
    let (proposal, plan) = site.remove(&fresh, &first, at(13)).expect("a removal");
    // The first server holds the turn of alice at the commit of its removal.
    let held = site.node.hold(proposal, plan);
    let other = through(&mut site, &mut second, |site| {
        let fresh = site.fresh(&first);
        let (proposal, plan) = site.remove(&fresh, &added, at(13)).expect("a removal");
        site.node.commit(proposal, plan)
    });
    assert!(matches!(other, Outcome::Conflict), "{other:?}");
    assert!(matches!(site.node.outcome(held), Outcome::Accepted(_)));
    // The second server proposes again from the current store: its passkey is the last one, so it refuses.
    let again = through(&mut site, &mut second, |site| {
        let (access, _) = site.verified(&added);
        let fresh = Fresh::check(&access, FRESH_MAX, at(12)).expect("a fresh verification");
        site.remove(&fresh, &added, at(13))
            .map(|(proposal, plan)| site.node.commit(proposal, plan))
    });
    assert!(
        matches!(
            again,
            Ok(Outcome::Refused(transition::Error::LastAnchor)) | Err(Error::Transition(transition::Error::LastAnchor))
        ),
        "{again:?}"
    );
    assert!(site.credential(&first).is_none());
    assert!(site.credential(&added).is_some());
}

#[test]
fn a_restore_keeps_an_acknowledged_revocation_and_an_acknowledged_passkey_of_either_server() {
    let mut site = Site::new();
    let first = site.register(Algorithm::Ed25519, -8, 1, 0);
    let mut second = site.node.peer(36);
    let issued = session(&mut site, &first, 11);
    let snapshot = site.node.memory.snapshot();

    // The second server adds a passkey, and the first one revokes the session. Each commit is acknowledged.
    let added = through(&mut site, &mut second, |site| site.add(&first, Algorithm::Es256, -7, 2));
    let access = match ready(site.sessions.check(&mut site.node.memory, issued.identifier(), at(20))) {
        Ok(Check::Active(access)) => access,
        other => panic!("the session does not serve: {other:?}"),
    };
    let (proposal, plan) = site
        .sessions
        .revoke(access.session(), Revoker::Own(&access), &[], at(20), &mut site.random)
        .expect("a revocation");
    assert!(matches!(site.node.commit(proposal, plan), Outcome::Accepted(_)));

    // The store comes back from the snapshot before both commits, and the first server restores it.
    site.node.memory.restore(&snapshot);
    site.node.driver.restore(at(0)).expect("a restore");
    site.node.run();
    assert_eq!(site.node.driver.status(), Status::Serving);
    assert!(
        site.credential(&added).is_some(),
        "the restore lost an acknowledged passkey"
    );
    let check = ready(site.sessions.check(&mut site.node.memory, issued.identifier(), at(21)));
    assert!(
        !matches!(check, Ok(Check::Active(_))),
        "the restore lost an acknowledged revocation"
    );

    // The new instance fences the second server. It joins the restored store with a start, and serves.
    let json = Get::new(&added, RP_ID, ORIGIN, site.options(at(29)), HANDLE).json();
    let fenced = through(&mut site, &mut second, |site| {
        let (proposal, plan, _) = site.sign_in(&json, at(30)).expect("a sign-in");
        site.node.commit(proposal, plan)
    });
    assert!(matches!(fenced, Outcome::Unknown(_)), "{fenced:?}");
    assert_eq!(
        second.driver.status(),
        Status::Refused(rsauthnz::store::driver::Error::Superseded)
    );
    second.join();
    through(&mut site, &mut second, |site| session(site, &added, 41));
}
