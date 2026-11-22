//! Invitations, the passkeys of an account, and the gate of a fresh user verification.

use core::num::NonZeroUsize;
use core::time::Duration;

use rsauthnz::account::{self, Activation, Fresh, INVITATION_BYTES, Invite, Invitee};
use rsauthnz::authz::{Permit, Policy, Request, Requirements};
use rsauthnz::crypto::Algorithm;
use rsauthnz::evidence::Evidence;
use rsauthnz::id::{Action, AuthorityVersion, Human, Id, Principal, Resource};
use rsauthnz::passkey::{Error, Response, UserHandle};
use rsauthnz::session::{Access, Revoker};
use rsauthnz::store::driver::{Answer, Lookup, Plan};
use rsauthnz::store::{Kind, Store};
use rsauthnz::time::Reading;
use rsauthnz::transition::{self, Outcome, Proposal};
use rsauthnz_conformance::suite::{Fault, Subject as _};

use super::authenticator::{
    self, BACKUP_ELIGIBLE, BACKUP_STATE, Get, Passkey, Registration, USER_PRESENT, USER_VERIFIED,
};
use super::{HANDLE, ORIGIN, RP_ID, START, Site, alice, at, ready, refused};

/// The user handle of the administrator, and of carol, the recipient of the invitations.
const ADMIN: [u8; 32] = [7; 32];
const CAROL: [u8; 32] = [6; 32];

fn carol() -> Id<Human> {
    Id::new("acme", "carol").expect("an identifier")
}

fn admin() -> Id<Human> {
    Id::new("acme", "admin").expect("an identifier")
}

fn invite_action() -> Id<Action> {
    Id::new("acme", "team.invite").expect("an identifier")
}

fn team() -> Id<Resource> {
    Id::new("acme", "team-1").expect("an identifier")
}

/// The policy of the site: `issuer` can invite a member of the team, until one day after [`START`].
struct Invitations {
    version: AuthorityVersion,
    issuer: Principal,
}

impl Policy for Invitations {
    fn version(&self) -> &AuthorityVersion {
        &self.version
    }

    fn resolve(&self, request: &Request<'_>) -> Option<Permit> {
        let permitted =
            *request.principal == self.issuer && *request.action == invite_action() && *request.resource == team();
        permitted.then(|| Permit {
            principal: request.principal.clone(),
            action: request.action.clone(),
            resource: request.resource.clone(),
            version: self.version.clone(),
            requires: Requirements {
                user_verified: true,
                phishing_resistant: true,
                max_age: Duration::from_secs(300),
            },
            expires: START + Duration::from_secs(24 * 60 * 60),
        })
    }
}

/// A site with a signed-in administrator, and the policy that lets the administrator invite.
struct Invited {
    site: Site,
    evidence: Evidence,
    policy: Invitations,
}

impl Invited {
    /// The administrator registers at 1 and signs in at 11. The policy is at its first version.
    fn new() -> Self {
        let mut site = Site::new();
        let challenge = authenticator::challenge(&site.options_of(&admin(), ADMIN));
        let passkey = Passkey::new(Algorithm::Ed25519, -8, 50);
        let (proposal, plan) = site.propose(&Registration::new(&passkey, RP_ID, ORIGIN, challenge).json(), at(1));
        assert!(matches!(site.node.commit(proposal, plan), Outcome::Accepted(_)));
        let json = Get::new(&passkey, RP_ID, ORIGIN, site.options(at(10)), ADMIN).json();
        let evidence = site.signed_in(&json, at(11));
        let version = site.node.policy(None, 1);
        Self {
            site,
            evidence,
            policy: Invitations {
                version,
                issuer: Principal::Human(admin()),
            },
        }
    }

    /// The value of an accepted invitation of carol at 12, for one day.
    fn invite(&mut self) -> Vec<u8> {
        let invite = Invite {
            recipient: &carol(),
            handle: UserHandle::from_bytes(CAROL),
            action: &invite_action(),
            resource: &team(),
            lifetime: Duration::from_secs(24 * 60 * 60),
        };
        let site = &mut self.site;
        let (proposal, plan) = site
            .rp
            .invite(
                &self.evidence,
                &self.policy,
                &invite,
                at(12),
                &mut site.random,
                &mut site.node.driver,
            )
            .expect("an invitation");
        let Outcome::Accepted(receipt) = site.node.commit(proposal, plan) else {
            panic!("the invitation does not commit");
        };
        receipt.artifact().expect("the invitation value").to_vec()
    }

    /// The challenge of the options of the activation of `value` by `account` at `now`.
    fn options(&mut self, value: &[u8], account: &Id<Human>, now: Reading) -> Result<Vec<u8>, Error> {
        let invitee = Invitee {
            account,
            name: "carol@app.example",
            display_name: "Carol",
        };
        let site = &mut self.site;
        let options = ready(
            site.rp
                .activation_options(&mut site.node.memory, value, &invitee, now, &mut site.random),
        );
        Ok(authenticator::challenge(&options.map_err(refused)?))
    }

    /// The activation of the response `json` for `recipient` at `now`.
    fn activate(&mut self, json: &[u8], recipient: &Id<Human>, now: Reading) -> Result<Activation, Error> {
        let response = Response::parse(json)?;
        let site = &mut self.site;
        let activation = site.rp.activate(
            &mut site.node.memory,
            &response,
            recipient,
            &self.policy,
            now,
            &mut site.node.driver,
        );
        ready(activation).map_err(refused)
    }

    /// The commit of the activation of `json` for carol at 21.
    fn propose(&mut self, json: &[u8]) -> (Proposal, Plan) {
        let activation = self.activate(json, &carol(), at(21)).expect("an activation");
        assert_eq!(
            (activation.account(), activation.action(), activation.resource()),
            (&carol(), &invite_action(), &team())
        );
        activation.propose(&[]).expect("a proposal")
    }

    /// The registration response of `passkey` for the activation challenge `challenge`.
    fn response(passkey: &Passkey, challenge: Vec<u8>) -> Vec<u8> {
        Registration::new(passkey, RP_ID, ORIGIN, challenge).json()
    }

    /// Whether carol has the passkey `passkey`.
    fn holds(&mut self, passkey: &Passkey) -> bool {
        let key = self.site.rp.credential_key(&UserHandle::from_bytes(CAROL), &passkey.id);
        self.site.node.read(&key).is_some()
    }
}

#[test]
fn an_invitation_activates_once_and_a_second_activation_refuses() {
    let mut invited = Invited::new();
    let value = invited.invite();
    assert_eq!(value.len(), INVITATION_BYTES);
    let challenge = invited.options(&value, &carol(), at(20)).expect("the options");
    let (first, second) = (
        Passkey::new(Algorithm::MlDsa65, -49, 1),
        Passkey::new(Algorithm::Ed25519, -8, 2),
    );
    let (proposal, plan) = invited.propose(&Invited::response(&first, challenge.clone()));
    assert!(matches!(invited.site.node.commit(proposal, plan), Outcome::Accepted(_)));
    assert!(invited.holds(&first));

    // The commit consumed the invitation: no second activation finds it, with the open challenge or with new options.
    let again = Invited::response(&second, challenge);
    assert_eq!(
        invited.activate(&again, &carol(), at(22)).err(),
        Some(Error::Invitation)
    );
    assert_eq!(invited.options(&value, &carol(), at(22)).err(), Some(Error::Invitation));
    assert!(!invited.holds(&second));

    // The invited account signs in with its first passkey.
    let json = Get::new(&first, RP_ID, ORIGIN, invited.site.options(at(30)), CAROL).json();
    let evidence = invited.site.signed_in(&json, at(31));
    assert_eq!(evidence.subject(), &Principal::Human(carol()));
}

/// Two activations of one invitation read it before either one commits. Only the read of the invitation in the commit
/// orders them, so one commits and the other conflicts.
#[test]
fn two_concurrent_activations_of_one_invitation_commit_once() {
    let mut invited = Invited::new();
    let value = invited.invite();
    let passkeys = [
        Passkey::new(Algorithm::Ed25519, -8, 1),
        Passkey::new(Algorithm::Es256, -7, 2),
    ];
    let tickets = passkeys.each_ref().map(|passkey| {
        let challenge = invited.options(&value, &carol(), at(20)).expect("the options");
        let (proposal, plan) = invited.propose(&Invited::response(passkey, challenge));
        invited.site.node.driver.submit(proposal, plan).expect("a submission")
    });
    invited.site.node.run();
    let outcomes = tickets.map(|ticket| match invited.site.node.driver.take(ticket) {
        Some(Answer::Outcome(outcome)) => outcome,
        answer => panic!("the commit gave {answer:?}"),
    });
    assert!(
        matches!(outcomes, [Outcome::Accepted(_), Outcome::Conflict]),
        "{outcomes:?}"
    );
    assert!(invited.holds(&passkeys[0]));
    assert!(!invited.holds(&passkeys[1]));
}

#[test]
fn an_invitation_for_one_recipient_refuses_another() {
    let mut invited = Invited::new();
    let value = invited.invite();
    let dave = Id::new("acme", "dave").expect("an identifier");
    assert_eq!(invited.options(&value, &dave, at(20)).err(), Some(Error::Recipient));
    // A response to the options of carol refuses for dave too.
    let challenge = invited.options(&value, &carol(), at(20)).expect("the options");
    let json = Invited::response(&Passkey::new(Algorithm::Ed25519, -8, 1), challenge);
    assert_eq!(invited.activate(&json, &dave, at(21)).err(), Some(Error::Recipient));
    // The control: carol activates it.
    let (proposal, plan) = invited.propose(&json);
    assert!(matches!(invited.site.node.commit(proposal, plan), Outcome::Accepted(_)));
}

/// The activation needs the current authority of the issuer: a policy that no longer permits the issuer refuses it,
/// and a policy change between the activation and its commit stops the commit.
#[test]
fn an_activation_needs_the_current_authority_of_the_issuer() {
    let mut invited = Invited::new();
    let value = invited.invite();
    let challenge = invited.options(&value, &carol(), at(20)).expect("the options");
    let json = Invited::response(&Passkey::new(Algorithm::Ed25519, -8, 1), challenge);
    let (proposal, plan) = invited.propose(&json);
    let first = invited.policy.version.clone();
    let second = invited.site.node.policy(Some(&first), 2);
    assert!(matches!(invited.site.node.commit(proposal, plan), Outcome::Conflict));

    // At the second version, the policy no longer permits the administrator.
    invited.policy = Invitations {
        version: second,
        issuer: Principal::Human(alice()),
    };
    assert_eq!(invited.activate(&json, &carol(), at(22)).err(), Some(Error::Issuer));
    // The control: the policy permits the administrator again.
    invited.policy.issuer = Principal::Human(admin());
    let (proposal, plan) = invited.propose(&json);
    assert!(matches!(invited.site.node.commit(proposal, plan), Outcome::Accepted(_)));
}

#[test]
fn an_activation_in_doubt_completes_once_at_restore() {
    let mut invited = Invited::new();
    let value = invited.invite();
    let snapshot = invited.site.node.memory.snapshot();
    let challenge = invited.options(&value, &carol(), at(20)).expect("the options");
    let passkey = Passkey::new(Algorithm::MlDsa65, -49, 1);
    let json = Invited::response(&passkey, challenge);
    let (proposal, plan) = invited.propose(&json);
    let operation = proposal.operation().clone();
    // The commit lands, and its response is lost. Then the store comes back from the snapshot before the commit.
    invited.site.node.memory.inject(Fault::LostResponse);
    assert!(matches!(invited.site.node.commit(proposal, plan), Outcome::Unknown(_)));
    invited.site.node.memory.restore(&snapshot);
    invited.site.node.driver.restore(at(0)).expect("a restore");
    invited.site.node.run();

    // The restored store holds the passkey of carol, and the invitation is consumed.
    assert!(invited.holds(&passkey));
    assert_eq!(invited.options(&value, &carol(), at(22)).err(), Some(Error::Invitation));
    let ticket = invited.site.node.driver.lookup(operation).expect("a lookup");
    invited.site.node.run();
    assert!(matches!(
        invited.site.node.driver.take(ticket),
        Some(Answer::Lookup(Lookup::Committed(_)))
    ));
    // The account has its sign-in method.
    let json = Get::new(&passkey, RP_ID, ORIGIN, invited.site.options(at(30)), CAROL).json();
    assert_eq!(
        invited.site.signed_in(&json, at(31)).subject(),
        &Principal::Human(carol())
    );
}

#[test]
fn a_dump_of_the_store_holds_no_invitation_value() {
    let mut invited = Invited::new();
    let value = invited.invite();
    let mut dump = Vec::new();
    for kind in Kind::ALL {
        let prefix = kind.key(&[]).expect("a key of one byte");
        let records = ready(invited.site.node.memory.range(&prefix, None, NonZeroUsize::MAX)).expect("a read");
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
    // The positive control: the invitation record holds the user handle of carol.
    assert!(holds(&CAROL));
    assert!(!holds(&value));
    assert!(!holds(&value[..16]));
}

impl Site {
    /// The session of the sign-in of the passkey `passkey` of alice at `seconds`, which ends the family of `replaces`,
    /// at `seconds` + 1. `flags` are the flags of the assertion.
    fn signed_in_at(&mut self, passkey: &Passkey, seconds: u64, replaces: Option<&Access>, flags: u8) -> Access {
        let mut get = Get::new(passkey, RP_ID, ORIGIN, self.options(at(seconds - 1)), HANDLE);
        get.flags = flags;
        let opened = self.opened(&get.json(), at(seconds), replaces);
        match ready(
            self.sessions
                .check(&mut self.node.memory, opened.session.identifier(), at(seconds + 1)),
        ) {
            Ok(rsauthnz::session::Check::Active(access)) => access,
            other => panic!("the session does not serve: {other:?}"),
        }
    }

    /// The proposal of the removal of `passkey` of alice with `fresh` at `now`.
    fn remove(&mut self, fresh: &Fresh, passkey: &Passkey, now: Reading) -> Result<(Proposal, Plan), Error> {
        let handle = UserHandle::from_bytes(HANDLE);
        let remove = self.rp.remove(
            &mut self.node.memory,
            fresh,
            &handle,
            &passkey.id,
            now,
            &mut self.random,
        );
        ready(remove).map_err(refused)
    }
}

/// The flags of an assertion of a synchronized passkey, with and with no user verification.
const VERIFIED: u8 = USER_PRESENT | USER_VERIFIED | BACKUP_ELIGIBLE | BACKUP_STATE;
const UNVERIFIED: u8 = USER_PRESENT | BACKUP_ELIGIBLE | BACKUP_STATE;

#[test]
fn a_sensitive_change_with_an_old_or_unverified_assertion_refuses_and_with_a_fresh_one_commits() {
    let mut site = Site::new();
    let first = site.register(Algorithm::Ed25519, -8, 1, 0);
    let second = site.add(&first, Algorithm::Es256, -7, 2);

    // A sign-in at 21 with no user verification gives no fresh verification.
    let unverified = site.signed_in_at(&first, 21, None, UNVERIFIED);
    assert_eq!(
        Fresh::check(&unverified, account::FRESH_MAX, at(22)).err(),
        Some(account::Error::Stale)
    );
    // A verification at 31 is older than a window of 30 seconds at 62. No window is longer than `FRESH_MAX`.
    let verified = site.signed_in_at(&first, 31, Some(&unverified), VERIFIED);
    assert_eq!(
        Fresh::check(&verified, Duration::from_secs(30), at(62)).err(),
        Some(account::Error::Stale)
    );
    let longer = account::FRESH_MAX + Duration::from_secs(1);
    assert_eq!(
        Fresh::check(&verified, longer, at(32)).err(),
        Some(account::Error::Window)
    );

    // The removal of a fresh verification at 32 commits only before its deadline.
    let fresh = Fresh::check(&verified, account::FRESH_MAX, at(32)).expect("a fresh verification");
    let (proposal, plan) = site.remove(&fresh, &second, at(32)).expect("a removal");
    site.node.memory.set_clock(at(32 + account::FRESH_MAX.as_secs()));
    assert!(matches!(
        site.node.commit(proposal, plan),
        Outcome::Refused(transition::Error::Expired)
    ));
    site.node.memory.set_clock(at(33));
    let (proposal, plan) = site.remove(&fresh, &second, at(33)).expect("a removal");
    assert!(matches!(site.node.commit(proposal, plan), Outcome::Accepted(_)));
    assert_eq!(site.node.read(&site.key(&second)), None);
}

/// A recovery value is no sign-in method, so the account keeps its last passkey also when it has one.
#[test]
fn the_removal_of_the_last_passkey_refuses_also_when_a_recovery_value_is_set() {
    let mut site = Site::new();
    let passkey = site.register(Algorithm::Ed25519, -8, 1, 0);
    let access = site.signed_in_at(&passkey, 21, None, VERIFIED);
    let fresh = Fresh::check(&access, account::FRESH_MAX, at(22)).expect("a fresh verification");
    // A recovery code of alice is an anchor and no sign-in method.
    let code = site.new_code(&fresh, 22);
    assert_eq!(
        site.remove(&fresh, &passkey, at(23)).err(),
        Some(Error::Transition(transition::Error::LastAnchor))
    );
    assert!(site.node.read(&site.key(&passkey)).is_some());
    site.recovery_challenge(&alice(), &code, 24).unwrap();
}

/// Two removals of the last two passkeys each read the other one as the passkey that stays. One commits, and the read
/// of the other one stops the second.
#[test]
fn two_concurrent_removals_keep_one_passkey() {
    let mut site = Site::new();
    let first = site.register(Algorithm::Ed25519, -8, 1, 0);
    let second = site.add(&first, Algorithm::Es256, -7, 2);
    let access = site.signed_in_at(&first, 21, None, VERIFIED);
    let fresh = Fresh::check(&access, account::FRESH_MAX, at(22)).expect("a fresh verification");
    let tickets = [&first, &second].map(|passkey| {
        let (proposal, plan) = site.remove(&fresh, passkey, at(22)).expect("a removal");
        site.node.driver.submit(proposal, plan).expect("a submission")
    });
    site.node.run();
    let outcomes = tickets.map(|ticket| match site.node.driver.take(ticket) {
        Some(Answer::Outcome(outcome)) => outcome,
        answer => panic!("the commit gave {answer:?}"),
    });
    // The second one conflicts at its read, or the last-anchor check of the driver refuses it first.
    assert!(
        matches!(
            outcomes,
            [
                Outcome::Accepted(_),
                Outcome::Conflict | Outcome::Refused(transition::Error::LastAnchor)
            ]
        ),
        "{outcomes:?}"
    );
    assert_eq!(site.node.read(&site.key(&first)), None);
    assert!(site.node.read(&site.key(&second)).is_some());
}

#[test]
fn a_rename_keeps_the_passkey_and_refuses_a_passkey_of_another_account() {
    let mut site = Site::new();
    let passkey = site.register(Algorithm::Ed25519, -8, 1, 7);
    let bob = site.register_bob();
    let access = site.signed_in_at(&passkey, 21, None, VERIFIED);
    let list = |site: &mut Site, handle: [u8; 32]| {
        let handle = UserHandle::from_bytes(handle);
        let passkeys = ready(site.rp.passkeys(&mut site.node.memory, &handle));
        passkeys.map_err(refused).expect("the passkeys")
    };
    let [stored] = list(&mut site, HANDLE).try_into().expect("one passkey");
    assert_eq!(stored.credential().name(), "");
    let (proposal, plan) = site
        .rp
        .rename(
            &access,
            &stored,
            "Work laptop",
            at(22),
            &mut site.random,
            &mut site.node.driver,
        )
        .expect("a rename");
    assert!(matches!(site.node.commit(proposal, plan), Outcome::Accepted(_)));
    let [renamed] = list(&mut site, HANDLE).try_into().expect("one passkey");
    assert_eq!(renamed.credential().name(), "Work laptop");
    // The rename keeps the rest of the credential, such as its counter, and the passkey signs in.
    assert_eq!(renamed.credential().sign_count(), stored.credential().sign_count());
    assert_eq!(renamed.credential().id(), &passkey.id[..]);
    site.signed_in_at(&passkey, 31, Some(&access), VERIFIED);

    // A passkey of bob refuses in a session of alice.
    let [of_bob] = list(&mut site, super::session::BOB).try_into().expect("one passkey");
    assert_eq!(of_bob.credential().id(), &bob.id[..]);
    assert_eq!(
        site.rp
            .rename(
                &access,
                &of_bob,
                "Mine",
                at(32),
                &mut site.random,
                &mut site.node.driver
            )
            .err(),
        Some(Error::Credential)
    );
}

/// A sign-out ends the own session with no fresh verification. The end of another session of the account needs one,
/// and no revoker of another kind ends it.
#[test]
fn the_end_of_another_session_of_the_account_needs_a_fresh_verification() {
    let mut site = Site::new();
    let passkey = site.register(Algorithm::Ed25519, -8, 1, 0);
    let laptop = site.signed_in_at(&passkey, 21, None, VERIFIED);
    let phone = site.signed_in_at(&passkey, 31, None, VERIFIED);
    let sessions = site.sessions.clone();
    let revoke = |site: &mut Site, by: Revoker<'_>| {
        sessions
            .revoke(laptop.session(), by, &[], at(40), &mut site.random)
            .map(|_| ())
            .err()
    };
    let stale = site.signed_in_at(&passkey, 11, None, UNVERIFIED);
    assert_eq!(
        Fresh::check(&stale, account::FRESH_MAX, at(40)).err(),
        Some(account::Error::Stale)
    );
    assert_eq!(
        revoke(&mut site, Revoker::Own(&phone)),
        Some(rsauthnz::session::Error::Fresh)
    );
    assert_eq!(
        revoke(&mut site, Revoker::Other(Principal::Human(alice()))),
        Some(rsauthnz::session::Error::Fresh)
    );
    // A fresh verification of bob ends no session of alice.
    let bob = site.register_bob();
    let mut get = Get::new(&bob, RP_ID, ORIGIN, site.options(at(34)), super::session::BOB);
    get.flags = VERIFIED;
    let opened = site.opened(&get.json(), at(35), None);
    let of_bob = match ready(
        site.sessions
            .check(&mut site.node.memory, opened.session.identifier(), at(36)),
    ) {
        Ok(rsauthnz::session::Check::Active(access)) => access,
        other => panic!("the session does not serve: {other:?}"),
    };
    let fresh_bob = Fresh::check(&of_bob, account::FRESH_MAX, at(40)).expect("a fresh verification");
    assert_eq!(
        revoke(&mut site, Revoker::Fresh(&fresh_bob)),
        Some(rsauthnz::session::Error::Fresh)
    );

    // The controls: the phone ends the laptop with a fresh verification, and the laptop signs itself out.
    let fresh = Fresh::check(&phone, account::FRESH_MAX, at(40)).expect("a fresh verification");
    let (proposal, plan) = sessions
        .revoke(laptop.session(), Revoker::Fresh(&fresh), &[], at(40), &mut site.random)
        .expect("a revocation");
    assert!(matches!(site.node.commit(proposal, plan), Outcome::Accepted(_)));
    let (proposal, plan) = sessions
        .revoke(phone.session(), Revoker::Own(&phone), &[], at(41), &mut site.random)
        .expect("a sign-out");
    assert!(matches!(site.node.commit(proposal, plan), Outcome::Accepted(_)));
}
