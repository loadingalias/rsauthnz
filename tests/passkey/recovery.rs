//! Recovery codes: one recovery for each code, the end of the displaced authority, the evidence of a recovery, the
//! completion of a recovery in doubt, a new code, and the cost and the secrecy of a code.

use core::num::NonZeroUsize;
use core::time::Duration;

use rsauthnz::account::{FRESH_MAX, Fresh};
use rsauthnz::cbor::Value;
use rsauthnz::crypto::Algorithm;
use rsauthnz::evidence::Method;
use rsauthnz::id::{AuthorityVersion, Human, Id, Principal};
use rsauthnz::limits::Limits;
use rsauthnz::passkey::{Error, RelyingParty, Response, User, UserHandle};
use rsauthnz::recovery::{Attempt, CODE_CHARS, Code, Ended, Passkeys};
use rsauthnz::session::{self, Check, Identifier, Opened, Revoker};
use rsauthnz::store::driver::{Answer, Lookup, Plan};
use rsauthnz::store::{Commit, Declaration, Instance, Journal, Kind, Record, Sequence, Store};
use rsauthnz::transition::{Audit, Change, Dependency, Key, OperationId, Outcome, Proposal};
use rsauthnz_conformance::memory::{self, Memory};
use rsauthnz_conformance::suite::{Fault, Subject as _};

use super::authenticator::{self, Get, Passkey, Registration};
use super::{HANDLE, KEY, Node, ORIGIN, RECOVERY_KEY, RP_ID, Site, alice, at, authority, hex, ready, refused};

impl Site {
    /// The session of the sign-in of alice with `passkey` at `seconds`.
    fn signed_in_with(&mut self, passkey: &Passkey, seconds: u64) -> Opened {
        let json = Get::new(passkey, RP_ID, ORIGIN, self.options(at(seconds - 1)), HANDLE).json();
        self.opened(&json, at(seconds), None)
    }

    /// The check of the session `identifier` at `seconds`.
    fn session(&mut self, identifier: &Identifier, seconds: u64) -> Result<Check, session::Error> {
        match ready(self.sessions.check(&mut self.node.memory, identifier, at(seconds))) {
            Ok(check) => Ok(check),
            Err(session::Failure::Refused(error)) => Err(error),
            Err(session::Failure::Store(error)) => panic!("the memory binding reads with no failure: {error}"),
        }
    }

    /// The fresh user verification of the session `opened` at `seconds`.
    fn fresh_of(&mut self, opened: &Opened, seconds: u64) -> Fresh {
        let Ok(Check::Active(access)) = self.session(opened.session.identifier(), seconds) else {
            panic!("the session does not serve");
        };
        Fresh::check(&access, FRESH_MAX, at(seconds)).expect("a fresh verification")
    }

    /// The proposal of a new recovery code of alice with `fresh` at `seconds`.
    fn propose_code(&mut self, fresh: &Fresh, seconds: u64) -> (Proposal, Plan) {
        let handle = UserHandle::from_bytes(HANDLE);
        let code = self.rp.recovery_code(
            &mut self.node.memory,
            fresh,
            &handle,
            at(seconds),
            &mut self.random,
            &mut self.node.driver,
        );
        ready(code).map_err(refused).expect("a new code")
    }

    /// Commits a new recovery code of alice with `fresh` at `seconds`, and gives its text.
    pub(super) fn new_code(&mut self, fresh: &Fresh, seconds: u64) -> Vec<u8> {
        let (proposal, plan) = self.propose_code(fresh, seconds);
        let Outcome::Accepted(receipt) = self.node.commit(proposal, plan) else {
            panic!("the new code does not commit");
        };
        receipt.artifact().expect("the text of the code").to_vec()
    }

    /// The challenge of the recovery options of `account`, with the user handle of alice, after a check of the code
    /// `text` at `seconds`.
    pub(super) fn recovery_challenge(
        &mut self,
        account: &Id<Human>,
        text: &[u8],
        seconds: u64,
    ) -> Result<Vec<u8>, Error> {
        let code = Code::parse(text)?;
        let user = User {
            account,
            handle: UserHandle::from_bytes(HANDLE),
            name: "alice@app.example",
            display_name: "Alice",
        };
        let options = self
            .rp
            .recovery_options(&mut self.node.memory, &user, &code, at(seconds), &mut self.random);
        Ok(authenticator::challenge(&ready(options).map_err(refused)?))
    }

    /// The recovery attempt of the registration of `passkey` for the challenge `challenge` at `seconds`.
    fn attempt(&mut self, passkey: &Passkey, challenge: Vec<u8>, seconds: u64) -> Result<Attempt, Error> {
        let response = Response::parse(&Registration::new(passkey, RP_ID, ORIGIN, challenge).json())?;
        let recover = self.rp.recover(
            &mut self.node.memory,
            &response,
            &self.sessions,
            at(seconds),
            &mut self.random,
            &mut self.node.driver,
        );
        ready(recover).map_err(refused)
    }
}

impl Node {
    /// Commits `count` records of no account, so the store grows.
    fn fill(&mut self, count: u32) {
        for batch in 0..count.div_ceil(32) {
            let audit = Audit {
                actor: Principal::Human(Id::new("acme", "filler").expect("an identifier")),
                action: Id::new("acme", "fill").expect("an identifier"),
                time: at(0),
            };
            let operation =
                OperationId::new(format!("fill-{count}-{batch}").as_bytes()).expect("an operation identity");
            let mut proposal =
                Proposal::new(operation, audit, &Value::Unsigned(batch.into()), Limits::default()).expect("a proposal");
            for record in batch * 32..count.min((batch + 1) * 32) {
                let key = Kind::Invitation
                    .key(&[&count.to_be_bytes()[..], &record.to_be_bytes(), &[0; 25]].concat())
                    .expect("a key of 33 bytes");
                proposal.read(Dependency::Absent(key.clone())).expect("a read");
                let version = AuthorityVersion::new(authority(), &u64::from(record).to_be_bytes()).expect("a version");
                let data = Box::from(*b"a record of no account");
                proposal
                    .change(Change::Write {
                        key,
                        version,
                        end: None,
                        data,
                    })
                    .expect("a change");
            }
            assert!(matches!(self.commit(proposal, Plan::default()), Outcome::Accepted(_)));
        }
    }
}

/// A site where alice registered the passkey `lost` at 1, signed in with it at 11 (`opened`), and made the recovery
/// code `text` at 13. Then she lost the passkey.
struct Lost {
    site: Site,
    lost: Passkey,
    opened: Opened,
    text: Vec<u8>,
}

impl Lost {
    fn new() -> Self {
        let mut site = Site::new();
        let lost = site.register(Algorithm::Ed25519, -8, 1, 0);
        let opened = site.signed_in_with(&lost, 11);
        let fresh = site.fresh_of(&opened, 12);
        let text = site.new_code(&fresh, 13);
        Self {
            site,
            lost,
            opened,
            text,
        }
    }

    /// The proposal of the recovery of alice with her code and the new passkey `passkey`, with `passkeys`: the check of
    /// the code at 20 and the recovery at 21.
    fn propose(&mut self, passkey: &Passkey, passkeys: Passkeys) -> (Proposal, Plan, session::Opening, Ended) {
        let challenge = self
            .site
            .recovery_challenge(&alice(), &self.text, 20)
            .expect("the options");
        let attempt = self.site.attempt(passkey, challenge, 21).expect("a recovery");
        assert_eq!(attempt.account(), &alice());
        attempt.propose(passkeys, &[]).expect("a proposal")
    }
}

/// The memory binding, with a count of its keyed reads and its range reads.
struct Counting<'m> {
    memory: &'m mut Memory,
    reads: usize,
    ranges: usize,
}

impl Store for Counting<'_> {
    type Error = memory::Error;

    fn declaration(&self) -> Declaration {
        self.memory.declaration()
    }

    async fn start(&mut self) -> Result<Instance, memory::Error> {
        self.memory.start().await
    }

    async fn read(&mut self, key: &Key) -> Result<Option<Record>, memory::Error> {
        self.reads += 1;
        Store::read(self.memory, key).await
    }

    async fn commit(&mut self, proposal: &Proposal, instance: Instance) -> Result<Commit, memory::Error> {
        self.memory.commit(proposal, instance).await
    }

    async fn expire(&mut self, kind: Kind, before: Duration, limit: NonZeroUsize) -> Result<usize, memory::Error> {
        self.memory.expire(kind, before, limit).await
    }

    async fn range(
        &mut self,
        prefix: &Key,
        after: Option<&Key>,
        limit: NonZeroUsize,
    ) -> Result<Vec<(Key, Record)>, memory::Error> {
        self.ranges += 1;
        self.memory.range(prefix, after, limit).await
    }
}

#[test]
fn a_code_serves_one_recovery_and_each_other_use_refuses() {
    let Lost { mut site, text, .. } = Lost::new();
    assert_eq!(text.len(), CODE_CHARS);
    // Two browsers check the code before either one commits. The read of the code orders the two commits.
    let first = site.recovery_challenge(&alice(), &text, 20).expect("the options");
    let second = site.recovery_challenge(&alice(), &text, 20).expect("the options");
    let one = site
        .attempt(&Passkey::new(Algorithm::Ed25519, -8, 2), first, 21)
        .expect("a recovery");
    let two = site
        .attempt(&Passkey::new(Algorithm::Ed25519, -8, 3), second, 21)
        .expect("a recovery");
    let (proposal, plan, opening, _) = one.propose(Passkeys::Keep, &[]).expect("a proposal");
    let won = site.node.commit(proposal, plan);
    assert!(opening.release(&won).is_some());
    let (proposal, plan, opening, _) = two.propose(Passkeys::Keep, &[]).expect("a proposal");
    let lost = site.node.commit(proposal, plan);
    assert!(matches!(lost, Outcome::Conflict));
    assert!(opening.release(&lost).is_none());
    // A third use refuses at the check of the code.
    assert_eq!(site.recovery_challenge(&alice(), &text, 22).err(), Some(Error::Code));
}

#[test]
fn a_recovery_ends_the_sessions_and_the_named_passkeys_and_its_evidence_is_a_recovery() {
    for passkeys in [Passkeys::End, Passkeys::Keep] {
        let mut lost = Lost::new();
        let new = Passkey::new(Algorithm::MlDsa65, -49, 2);
        let (proposal, plan, opening, ended) = lost.propose(&new, passkeys);
        assert_eq!(ended, Ended::All);
        let outcome = lost.site.node.commit(proposal, plan);
        let recovered = opening.release(&outcome).expect("the session of the recovery");
        let site = &mut lost.site;

        // The evidence has no phishing resistance and no authentication of a signature. It has the user verification
        // of the registration of the new passkey, so the new session makes a new code at once.
        let evidence = &recovered.evidence;
        assert_eq!(
            (
                evidence.method(),
                evidence.phishing_resistant(),
                evidence.user_verified(),
                evidence.authentication()
            ),
            (Method::Recovery, false, true, None)
        );
        let fresh = site.fresh_of(&recovered, 22);
        let next = site.new_code(&fresh, 23);
        site.recovery_challenge(&alice(), &next, 24).unwrap();

        // The commit ended the session of the lost passkey. The lost passkey stays only with `Keep`.
        assert_eq!(
            site.session(lost.opened.session.identifier(), 22).err(),
            Some(session::Error::Unknown)
        );
        assert_eq!(
            site.node.read(&site.key(&lost.lost)).is_some(),
            passkeys == Passkeys::Keep
        );
        // The new passkey signs in.
        assert_eq!(site.signed_in_with(&new, 31).evidence.method(), Method::Passkey);
    }
}

#[test]
fn a_recovery_in_doubt_completes_once_at_restore() {
    let mut lost = Lost::new();
    let snapshot = lost.site.node.memory.snapshot();
    let new = Passkey::new(Algorithm::Ed25519, -8, 2);
    let (proposal, plan, _, _) = lost.propose(&new, Passkeys::End);
    let operation = proposal.operation().clone();
    // The commit lands, and its response is lost. Then the store comes back from the snapshot before the commit.
    let site = &mut lost.site;
    site.node.memory.inject(Fault::LostResponse);
    assert!(matches!(site.node.commit(proposal, plan), Outcome::Unknown(_)));
    site.node.memory.restore(&snapshot);
    site.node.driver.restore(at(0)).expect("a restore");
    site.node.run();

    // The restored store holds the new passkey and no lost passkey, the code is consumed, and the session of the lost
    // passkey ended.
    assert!(site.node.read(&site.key(&new)).is_some());
    assert!(site.node.read(&site.key(&lost.lost)).is_none());
    assert_eq!(
        site.recovery_challenge(&alice(), &lost.text, 22).err(),
        Some(Error::Code)
    );
    assert_eq!(
        site.session(lost.opened.session.identifier(), 22).err(),
        Some(session::Error::Unknown)
    );
    let ticket = site.node.driver.lookup(operation).expect("a lookup");
    site.node.run();
    assert!(matches!(
        site.node.driver.take(ticket),
        Some(Answer::Lookup(Lookup::Committed(_)))
    ));
    // The account has its sign-in method.
    assert_eq!(
        site.signed_in_with(&new, 31).evidence.subject(),
        &Principal::Human(alice())
    );
}

#[test]
fn a_lost_recovery_response_releases_the_session_only_from_the_commit_that_consumed_the_code() {
    let mut lost = Lost::new();
    // With `Keep`, the commit ends no sign-in method, so only the consumption of the code stops a second use.
    let (proposal, plan, opening, _) = lost.propose(&Passkey::new(Algorithm::Ed25519, -8, 2), Passkeys::Keep);
    let operation = proposal.operation().clone();
    let site = &mut lost.site;
    site.node.memory.inject(Fault::LostResponse);
    assert!(matches!(site.node.commit(proposal, plan), Outcome::Unknown(_)));

    // The binding stopped as at a crash. After its start, the code refuses a second use, and the lookup of the operation
    // finds the commit, which releases the session.
    site.node.start();
    assert_eq!(
        site.recovery_challenge(&alice(), &lost.text, 22).err(),
        Some(Error::Code)
    );
    let ticket = site.node.driver.lookup(operation).expect("a lookup");
    site.node.run();
    let Some(Answer::Lookup(Lookup::Committed(receipt))) = site.node.driver.take(ticket) else {
        panic!("the lookup finds no commit");
    };
    let recovered = opening
        .release(&Outcome::Accepted(receipt))
        .expect("the session of the recovery");
    assert!(matches!(
        site.session(recovered.session.identifier(), 23),
        Ok(Check::Active(_))
    ));
}

#[test]
fn a_new_code_ends_the_earlier_code_and_its_challenges_also_after_a_restore() {
    let Lost {
        mut site,
        lost,
        text: earlier,
        ..
    } = Lost::new();
    let snapshot = site.node.memory.snapshot();
    let challenge = site.recovery_challenge(&alice(), &earlier, 30).expect("the options");
    let opened = site.signed_in_with(&lost, 31);
    let fresh = site.fresh_of(&opened, 32);
    let later = site.new_code(&fresh, 33);
    assert_ne!(earlier, later);

    // The earlier code and a challenge that it gave before the new code refuse.
    assert_eq!(site.recovery_challenge(&alice(), &earlier, 34).err(), Some(Error::Code));
    assert_eq!(
        site.attempt(&Passkey::new(Algorithm::Ed25519, -8, 2), challenge, 34)
            .err(),
        Some(Error::Code)
    );
    // A restore from the snapshot before the new code keeps the new code and the end of the earlier one.
    site.node.memory.restore(&snapshot);
    site.node.driver.restore(at(0)).expect("a restore");
    site.node.run();
    assert_eq!(site.recovery_challenge(&alice(), &earlier, 35).err(), Some(Error::Code));
    site.recovery_challenge(&alice(), &later, 35).unwrap();
}

#[test]
fn the_store_the_journal_and_debug_hold_no_recovery_code() {
    let mut site = Site::new();
    let passkey = site.register(Algorithm::Ed25519, -8, 1, 0);
    let opened = site.signed_in_with(&passkey, 11);
    let fresh = site.fresh_of(&opened, 12);
    let (proposal, plan) = site.propose_code(&fresh, 13);
    let mut shown = format!("{proposal:?} {plan:?}");
    let Outcome::Accepted(receipt) = site.node.commit(proposal, plan) else {
        panic!("the new code does not commit");
    };
    let text = receipt.artifact().expect("the text of the code").to_vec();
    let code = Code::parse(&text).expect("a code");
    shown.push_str(&format!("{receipt:?} {code:?}"));
    let digits: Vec<u8> = text.iter().copied().filter(|byte| *byte != b'-').collect();
    let bytes = hex(str::from_utf8(&digits).expect("ASCII"));

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
    let entries = ready(Journal::read(&mut site.node.memory, Sequence(0), NonZeroUsize::MAX)).expect("a read");
    dump.extend(entries.into_iter().map(|entry| entry.data.into_vec()));
    let holds = |needle: &[u8]| {
        dump.iter()
            .any(|bytes| bytes.windows(needle.len()).any(|window| window == needle))
    };
    // The positive control: the record of the code holds the user handle of alice.
    assert!(holds(&HANDLE));
    for needle in [&text[..], &digits, &bytes] {
        assert!(!holds(needle));
    }
    let first = str::from_utf8(&digits[..8]).expect("ASCII");
    assert!(!shown.contains(first));
}

#[test]
fn each_check_of_a_code_costs_one_keyed_read_when_the_store_grows_100_times() {
    let Lost { mut site, text, .. } = Lost::new();
    let alice = alice();
    let user = User {
        account: &alice,
        handle: UserHandle::from_bytes(HANDLE),
        name: "alice@app.example",
        display_name: "Alice",
    };
    let wrong = Code::parse(&[b'0'; 32]).expect("a code");
    let right = Code::parse(&text).expect("a code");
    for records in [10, 1_000] {
        site.node.fill(records);
        let mut counting = Counting {
            memory: &mut site.node.memory,
            reads: 0,
            ranges: 0,
        };
        let mut refused = 0;
        for code in [&wrong, &wrong, &right] {
            let options = site
                .rp
                .recovery_options(&mut counting, &user, code, at(20), &mut site.random);
            refused += usize::from(ready(options).is_err());
        }
        assert_eq!((refused, counting.reads, counting.ranges), (2, 3, 0));
    }
}

#[test]
fn a_code_is_its_32_digits_in_either_case_and_proves_only_its_own_account() {
    let Lost { mut site, text, .. } = Lost::new();
    // A user types the code in capitals, with no hyphens.
    let typed: Vec<u8> = text
        .iter()
        .filter(|byte| **byte != b'-')
        .map(u8::to_ascii_uppercase)
        .collect();
    site.recovery_challenge(&alice(), &typed, 20).unwrap();
    // An email address, a digit too few or too many, a letter that is no digit, and a text of 65 bytes are no code.
    for text in [
        b"alice@app.example".to_vec(),
        typed[..31].to_vec(),
        [&typed[..], b"0"].concat(),
        [&typed[..31], b"G"].concat(),
        [&typed[..], &[b' '; 33]].concat(),
    ] {
        assert_eq!(Code::parse(&text).err(), Some(Error::Code));
    }
    // The code of alice proves no other account, also with her user handle.
    let bob = Id::new("acme", "bob").expect("an identifier");
    assert_eq!(site.recovery_challenge(&bob, &text, 20).err(), Some(Error::Code));
}

#[test]
fn a_recovery_ends_the_sessions_that_fit_and_its_new_session_ends_the_others() {
    let mut site = Site::new();
    // A relying party whose proposals hold ten reads: a recovery with no decision has room for six sessions.
    let mut limits = Limits::default();
    limits.dependencies = 10;
    site.rp = RelyingParty::new(authority(), RP_ID, ORIGIN, "Acme", KEY, limits)
        .expect("a relying party")
        .with_recovery(RECOVERY_KEY);
    let lost = site.register(Algorithm::Ed25519, -8, 1, 0);
    let opened = site.signed_in_with(&lost, 11);
    let fresh = site.fresh_of(&opened, 12);
    let text = site.new_code(&fresh, 13);
    for seconds in 14..21 {
        site.signed_in_with(&lost, seconds);
    }
    let challenge = site.recovery_challenge(&alice(), &text, 30).expect("the options");
    let attempt = site
        .attempt(&Passkey::new(Algorithm::Ed25519, -8, 2), challenge, 31)
        .expect("a recovery");
    let (proposal, plan, opening, ended) = attempt.propose(Passkeys::Keep, &[]).expect("a proposal");
    assert_eq!(ended, Ended::Part);
    let outcome = site.node.commit(proposal, plan);
    let recovered = opening.release(&outcome).expect("the session of the recovery");

    // Two sessions of the lost passkey stay. The new session ends them with its fresh verification.
    let sessions = site.sessions.clone();
    let page = ready(sessions.list(&mut site.node.memory, &alice(), None, at(32))).expect("a list");
    let Ok(Check::Active(access)) = site.session(recovered.session.identifier(), 32) else {
        panic!("the session of the recovery does not serve");
    };
    let others: Vec<_> = page
        .sessions
        .iter()
        .filter(|session| session.key() != access.session().key())
        .collect();
    assert_eq!((page.sessions.len(), others.len()), (3, 2));
    let fresh = Fresh::check(&access, FRESH_MAX, at(32)).expect("a fresh verification");
    for other in others {
        let (proposal, plan) = sessions
            .revoke(other, Revoker::Fresh(&fresh), &[], at(32), &mut site.random)
            .expect("a revocation");
        assert!(matches!(site.node.commit(proposal, plan), Outcome::Accepted(_)));
    }
    let page = ready(sessions.list(&mut site.node.memory, &alice(), None, at(33))).expect("a list");
    assert_eq!(page.sessions.len(), 1);
}
