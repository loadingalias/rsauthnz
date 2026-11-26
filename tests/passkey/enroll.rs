//! The enrollment of a CLI that a human approves in a browser: the CLI asks with its key, alice approves with a fresh
//! user verification of her passkey session, and the finish of the CLI binds its key to a CLI credential of her
//! account. rscrypto signs in place of custody, so that the tests hold the keys.

use core::time::Duration;

use rsauthnz::account::Fresh;
use rsauthnz::agent::{ATTEMPTS_MAX, Checked, DeviceCode, Loopback, RedirectCode, UserCode};
use rsauthnz::cbor::Value;
use rsauthnz::cli::{Call, Challenge};
use rsauthnz::cose::{Key as CoseKey, PublicKey, TrustedKey};
use rsauthnz::credential::{ProofDraft, Serial};
use rsauthnz::crypto::Algorithm;
use rsauthnz::custody::{Handle, KeyId};
use rsauthnz::id::{Human, Id};
use rsauthnz::limits::{Limits, SignatureBudget};
use rsauthnz::local::enroll::{CliId, ENROLLMENT_LIFETIME, Request, Status};
use rsauthnz::local::{self, Admission, Admitted, Authority, Bootstrap, Holder, HostGrant, Offer, Unlink};
use rsauthnz::recovery::Passkeys;
use rsauthnz::session::Access;
use rsauthnz::store::Kind;
use rsauthnz::store::driver::{Answer, Lookup, Plan};
use rsauthnz::transition::{OperationId, Outcome, Proposal};
use rsauthnz_conformance::suite::{Fault, Subject as _};
use rscrypto::auth::{MlDsa65Ed25519, MlDsa65Ed25519SecretKey};

use super::authenticator::Passkey;
use super::{START, Site, alice, at, ready, wrong};

/// A key of the composite profile, as a CLI or the issuer holds it.
struct Pair {
    public: [u8; 1984],
    secret: MlDsa65Ed25519SecretKey,
}

impl Pair {
    fn new(seed: u8) -> Self {
        let (public, secret) = MlDsa65Ed25519::generate_keypair(|out| {
            let _: () = out.fill(seed);
            Ok(())
        })
        .expect("a key pair");
        Self {
            public: public.to_bytes(),
            secret,
        }
    }

    fn sign(&self, message: &[u8]) -> Vec<u8> {
        let signature = self.secret.sign_deterministic(message, &[]).expect("a signature");
        signature.as_bytes().to_vec()
    }
}

/// The site of alice with her passkey, and the local authority of the site with its issuer key.
struct World {
    site: Site,
    passkey: Passkey,
    authority: Authority,
    grant: HostGrant,
    issuer: Pair,
}

/// A CLI that asked for an enrollment: its key, and the codes of its request.
struct Cli {
    serial: Serial,
    key: Pair,
    code: UserCode,
    device: DeviceCode,
}

impl World {
    fn new() -> Self {
        let mut site = Site::new();
        let passkey = site.register(Algorithm::Ed25519, -8, 1, 0);
        let issuer = Pair::new(1);
        let handle =
            Handle::new(KeyId::from_bytes([1; 16]), Algorithm::MlDsa65Ed25519, &issuer.public).expect("a handle");
        let grant = HostGrant {
            owner: Id::new("acme", "owner").expect("an identifier"),
            origin: Id::new("acme", "app").expect("an identifier"),
        };
        let open = Authority::open(
            &mut site.node.memory,
            &grant,
            Id::new("acme", "cli").expect("an identifier"),
            handle,
            Limits::default(),
        );
        let authority = ready(open).expect("the authority");
        Self {
            site,
            passkey,
            authority,
            grant,
            issuer,
        }
    }

    /// The artifact of the accepted commit of `proposal`.
    fn artifact(&mut self, (proposal, plan): (Proposal, Plan)) -> Vec<u8> {
        match self.site.node.commit(proposal, plan) {
            Outcome::Accepted(receipt) => receipt.artifact().expect("an artifact").to_vec(),
            outcome => panic!("the commit gave {outcome:?}"),
        }
    }

    /// The request of a CLI with the key of `seed` at `seconds`.
    fn request(&mut self, seed: u8, seconds: u64) -> Cli {
        self.request_at(seed, None, seconds)
    }

    /// The request of a CLI with the key of `seed` and the loopback address `loopback` at `seconds`.
    fn request_at(&mut self, seed: u8, loopback: Option<&Loopback>, seconds: u64) -> Cli {
        let key = Pair::new(seed);
        let (proposal, plan, code) = self
            .authority
            .enroll(
                &key.public,
                "alice-laptop",
                loopback,
                at(seconds),
                &mut self.site.random,
            )
            .expect("a request");
        let device = self.artifact((proposal, plan));
        let device = DeviceCode::from_bytes(device.try_into().expect("32 bytes"));
        let serial = Serial(self.site.node.driver.allocate(Kind::Credential).expect("a serial"));
        Cli {
            key,
            code,
            device,
            serial,
        }
    }

    /// A fresh user verification of alice: a passkey sign-in at 11, checked at 12.
    fn fresh(&mut self) -> Fresh {
        self.site.fresh(&self.passkey)
    }

    /// The session of a passkey sign-in of alice at 11, checked at 12, and its fresh user verification.
    fn session(&mut self) -> (Access, Fresh) {
        self.site.verified(&self.passkey)
    }

    /// The proposal of the check of `code` for the approval page of the human of `access` at `seconds`, and its answer.
    fn check(
        &mut self,
        access: &Access,
        code: &UserCode,
        seconds: u64,
    ) -> Result<(Proposal, Plan, Checked<Request>), local::Error> {
        let request = self.authority.request(
            &mut self.site.node.memory,
            access,
            code,
            at(seconds),
            &mut self.site.random,
        );
        ready(request).map_err(refused_local)
    }

    /// The request of `code` as the approval page shows it to the human of `access` at `seconds`, after the commit of
    /// its check: `None` for a wrong code.
    fn show(&mut self, access: &Access, code: &UserCode, seconds: u64) -> Result<Option<Request>, local::Error> {
        let (proposal, plan, checked) = self.check(access, code, seconds)?;
        let outcome = self.site.node.commit(proposal, plan);
        Ok(checked.release(&outcome))
    }

    /// The approval of the request of `cli` with the code `code` and `fresh` at `seconds`, which commits: whether it
    /// approved the request.
    fn approval(&mut self, cli: &Cli, code: &UserCode, fresh: &Fresh, seconds: u64) -> Result<bool, local::Error> {
        let approve = self.authority.approve(
            &mut self.site.node.memory,
            fresh,
            code,
            cli.serial,
            at(seconds),
            &mut self.site.random,
        );
        let (proposal, plan, checked) = ready(approve).map_err(refused_local)?;
        let outcome = self.site.node.commit(proposal, plan);
        assert!(matches!(outcome, Outcome::Accepted(_)));
        Ok(checked.release(&outcome).is_some())
    }

    /// The approval of the request of `cli` with `fresh` at `seconds`.
    fn approve(&mut self, cli: &Cli, fresh: &Fresh, seconds: u64) -> Result<(), local::Error> {
        assert!(self.approval(cli, &cli.code, fresh, seconds)?);
        Ok(())
    }

    /// The proposal of the finish of the request of `cli` for `account` at `seconds`, which the issuer key signs.
    fn finish(&mut self, cli: &Cli, account: &Id<Human>, seconds: u64) -> Result<(Proposal, Plan), local::Error> {
        self.finish_with(cli, None, account, seconds)
    }

    /// The proposal of the finish of [`Self::finish`], with the redirect code `redirect`.
    fn finish_with(
        &mut self,
        cli: &Cli,
        redirect: Option<&RedirectCode>,
        account: &Id<Human>,
        seconds: u64,
    ) -> Result<(Proposal, Plan), local::Error> {
        let finish = self.authority.finish(
            &mut self.site.node.memory,
            &cli.code,
            &cli.device,
            redirect,
            account,
            at(seconds),
        );
        let finish = ready(finish).map_err(refused_local)?;
        let signature = self.issuer.sign(&finish.to_be_signed());
        finish.finish(
            &signature,
            OperationId::new(&cli.code.text().into_bytes()).expect("an operation"),
        )
    }

    /// The admitted call `status` of the CLI with the key `key` and the credential `credential` of alice at `seconds`,
    /// after a challenge of its binding.
    fn call(&mut self, cli: &Cli, credential: &[u8], seconds: u64) -> Result<Admitted, local::Error> {
        let (proposal, admission) = self.prepare_call(cli, credential, seconds)?;
        let outcome = self.site.node.commit(proposal, Plan::default());
        Ok(admission.release(&outcome).expect("the admitted call"))
    }

    fn prepare_call(
        &mut self,
        cli: &Cli,
        credential: &[u8],
        seconds: u64,
    ) -> Result<(Proposal, Admission), local::Error> {
        let key = &cli.key;
        let offer = ready(
            self.authority.account_challenge(
                &mut self.site.node.memory,
                &CliId {
                    account: alice(),
                    serial: cli.serial,
                },
                &key.public,
                at(seconds),
                &mut self.site.random,
                OperationId::new(
                    &[
                        b"challenge".as_slice(),
                        &cli.serial.0.to_be_bytes(),
                        &seconds.to_be_bytes(),
                    ]
                    .concat(),
                )
                .expect("an operation"),
            ),
        );
        let challenge = match offer.map_err(refused_local)? {
            Offer::Open(challenge) => challenge,
            Offer::New(proposal, plan) => {
                Challenge::from_bytes(self.artifact((proposal, plan)).try_into().expect("32 bytes"))
            }
        };
        let call = Call::new(
            challenge,
            OperationId::new(
                &[
                    b"status".as_slice(),
                    &cli.serial.0.to_be_bytes(),
                    &seconds.to_be_bytes(),
                ]
                .concat(),
            )
            .expect("an operation"),
            &Value::Text("status"),
            Limits::default(),
        )
        .expect("a call");
        let proof = self.prove(key, credential, &call, seconds);
        let admit = self.authority.admit(
            &mut self.site.node.memory,
            credential,
            &proof,
            &call,
            at(seconds),
            &mut self.site.random,
        );
        ready(admit).map_err(refused_local)
    }

    /// The proof of `call` with `key` over `credential`.
    fn prove(&self, key: &Pair, credential: &[u8], call: &Call, seconds: u64) -> Vec<u8> {
        let public = CoseKey {
            kid: None,
            alg: None,
            public: PublicKey::MlDsa65Ed25519(&key.public),
        };
        let trusted = TrustedKey::new(Algorithm::MlDsa65Ed25519, &public).expect("a trusted key");
        let draft =
            ProofDraft::new(&trusted, credential, &self.grant.origin, call.binding(), at(seconds)).expect("a draft");
        let signature = key.sign(&draft.to_be_signed());
        draft
            .finish(&signature, &mut SignatureBudget::new(&Limits::default()))
            .expect("a proof")
    }

    /// The credential of the binding of alice with the key `key`, which the issuer key signs again.
    fn reissue(&mut self, cli: &Cli, seconds: u64) -> Result<Vec<u8>, local::Error> {
        let reissue = ready(self.authority.account_credential(
            &mut self.site.node.memory,
            &CliId {
                account: alice(),
                serial: cli.serial,
            },
            &cli.key.public,
            at(seconds),
        ));
        let reissue = reissue.map_err(refused_local)?;
        let signature = self.issuer.sign(&reissue.to_be_signed());
        reissue.finish(&signature)
    }

    fn poll(&mut self, cli: &Cli, seconds: u64) -> Result<Status, local::Error> {
        self.poll_with(cli, None, seconds)
    }

    /// The poll of [`Self::poll`], with the redirect code `redirect`.
    fn poll_with(&mut self, cli: &Cli, redirect: Option<&RedirectCode>, seconds: u64) -> Result<Status, local::Error> {
        let poll = self.authority.poll(
            &mut self.site.node.memory,
            &cli.code,
            &cli.device,
            redirect,
            at(seconds),
        );
        ready(poll).map_err(refused_local)
    }
}

#[test]
fn either_recovery_cuts_off_a_connected_cli_and_its_unfinished_approvals() {
    for policy in [Passkeys::Keep, Passkeys::End] {
        let mut world = World::new();
        let other_rp = super::RelyingParty::new(
            Id::new("acme", "other-site").unwrap(),
            super::RP_ID,
            super::ORIGIN,
            "Other",
            super::KEY,
            Limits::default(),
        )
        .unwrap();
        let first_rp = core::mem::replace(&mut world.site.rp, other_rp);
        let other_key = world.site.register(Algorithm::Ed25519, -8, 10, 0);
        let other_session = world.site.signed_in_with(&other_key, 14);
        let other_fresh = world.site.fresh(&other_key);
        let other_cli = world.request(4, 20);
        world.approve(&other_cli, &other_fresh, 21).unwrap();
        let finish = world.finish(&other_cli, &alice(), 22).unwrap();
        let other_credential = world.artifact(finish);
        world.site.rp = first_rp;
        let connected = world.request(2, 20);
        let waiting = world.request(3, 20);
        let fresh = world.fresh();
        let code = world.site.new_code(&fresh, 13);
        world.approve(&connected, &fresh, 21).unwrap();
        world.approve(&waiting, &fresh, 21).unwrap();
        let finished = world.finish(&connected, &alice(), 22).unwrap();
        let credential = world.artifact(finished);
        let (call, admission) = world.prepare_call(&connected, &credential, 24).unwrap();
        let (finish, plan) = world.finish(&waiting, &alice(), 24).unwrap();
        let challenge = world.site.recovery_challenge(&alice(), &code, 25).unwrap();
        let new = Passkey::new(Algorithm::Ed25519, -8, 9);
        let attempt = world.site.attempt(&new, challenge, 26, policy).unwrap();
        let (recovery, recovery_plan, opening) = attempt.propose(&[]).unwrap();
        let opened = opening
            .release(&world.site.node.commit(recovery, recovery_plan))
            .unwrap();
        let access = world.site.active(opened.session.identifier(), at(27));
        assert!(
            ready(
                world
                    .authority
                    .account_clis(&mut world.site.node.memory, &access, at(27))
            )
            .unwrap()
            .is_empty()
        );
        let outcome = world.site.node.commit(call, Plan::default());
        assert!(matches!(outcome, Outcome::Conflict));
        assert!(admission.release(&outcome).is_none());
        assert!(matches!(world.site.node.commit(finish, plan), Outcome::Conflict));
        assert_eq!(world.poll(&waiting, 27).err(), Some(local::Error::NotEnrolled));
        assert_eq!(
            world.finish(&waiting, &alice(), 27).err(),
            Some(local::Error::NotEnrolled)
        );
        assert_eq!(world.reissue(&connected, 27).err(), Some(local::Error::NotEnrolled));
        assert_eq!(
            world.call(&connected, &credential, 27).err(),
            Some(local::Error::NotEnrolled)
        );
        let access = world.site.active(other_session.session.identifier(), at(28));
        let other_devices = ready(
            world
                .authority
                .account_clis(&mut world.site.node.memory, &access, at(28)),
        )
        .unwrap();
        assert_eq!(
            other_devices.iter().map(|device| device.serial).collect::<Vec<_>>(),
            [other_cli.serial]
        );
        assert_eq!(
            world.call(&other_cli, &other_credential, 28).unwrap().holder(),
            Holder::Account
        );
    }
}

#[test]
fn full_recovery_reads_one_code_and_one_revision_at_any_cli_count() {
    let mut size = None;
    for count in [0, local::enroll::ACCOUNT_CLIS_MAX] {
        let mut world = World::new();
        let fresh = world.fresh();
        let code = world.site.new_code(&fresh, 13);
        for index in 0..count {
            let cli = world.request(u8::try_from(10 + index).unwrap(), 20);
            world.approve(&cli, &fresh, 21).unwrap();
            let finish = world.finish(&cli, &alice(), 22).unwrap();
            world.artifact(finish);
        }
        let site = &mut world.site;
        let challenge = site.recovery_challenge(&alice(), &code, 24).unwrap();
        let new = Passkey::new(Algorithm::Ed25519, -8, 9);
        let registration = super::Registration::new(&new, super::RP_ID, super::ORIGIN, challenge);
        let response = super::Response::parse(&registration.json()).unwrap();
        let mut store = super::recovery::Counting::new(&mut site.node.memory);
        let attempt = ready(site.rp.recover(
            &mut store,
            &response,
            &site.sessions,
            Passkeys::End,
            at(25),
            &mut site.random,
            &mut site.node.driver,
        ))
        .unwrap();
        assert_eq!((store.reads, store.ranges), (1, 1));
        let (proposal, plan, opening) = attempt.propose(&[]).unwrap();
        let work = (proposal.dependencies().len(), proposal.changes().len());
        assert_eq!(*size.get_or_insert(work), work);
        let recovered = opening.release(&site.node.commit(proposal, plan)).unwrap();
        let access = site.active(recovered.session.identifier(), at(26));
        assert!(
            ready(world.authority.account_clis(&mut site.node.memory, &access, at(26)))
                .unwrap()
                .is_empty()
        );
    }
}

#[test]
fn disconnect_needs_fresh_verification_and_ends_only_the_selected_cli() {
    let mut world = World::new();
    let first = world.request(2, 20);
    let other = world.request(3, 20);
    let fresh = world.fresh();
    world.approve(&first, &fresh, 21).unwrap();
    world.approve(&other, &fresh, 21).unwrap();
    let finish = world.finish(&first, &alice(), 22).unwrap();
    let credential = world.artifact(finish);
    let finish = world.finish(&other, &alice(), 22).unwrap();
    let kept = world.artifact(finish);
    let opened = world.site.signed_in_with(&world.passkey, 24);
    let access = world.site.active(opened.session.identifier(), at(25));
    let mut store = super::recovery::Counting::new(&mut world.site.node.memory);
    let devices = ready(world.authority.account_clis(&mut store, &access, at(25))).unwrap();
    assert_eq!((store.reads, store.ranges), (2, 1));
    assert_eq!(devices.len(), 2);
    let listed = devices.iter().find(|device| device.serial == first.serial).unwrap();
    assert_eq!(listed.name, "alice-laptop");
    assert_eq!(listed.fingerprint, rscrypto::Sha256::digest(&first.key.public));
    assert_eq!(listed.expires, at(22).estimate() + local::CLI_LIFETIME);
    let op = OperationId::new(b"disconnect").unwrap();
    assert_eq!(
        ready(
            world
                .authority
                .disconnect(&mut world.site.node.memory, &fresh, first.serial, at(400), op.clone())
        )
        .map_err(refused_local)
        .err(),
        Some(local::Error::Expired)
    );
    let (call, _) = world.prepare_call(&first, &credential, 25).unwrap();
    let (proposal, plan) =
        ready(
            world
                .authority
                .disconnect(&mut world.site.node.memory, &fresh, first.serial, at(26), op),
        )
        .unwrap();
    assert!(matches!(world.site.node.commit(proposal, plan), Outcome::Accepted(_)));
    assert!(matches!(
        world.site.node.commit(call, Plan::default()),
        Outcome::Conflict
    ));
    assert_eq!(
        world.call(&first, &credential, 27).err(),
        Some(local::Error::NotEnrolled)
    );
    assert_eq!(world.reissue(&first, 27).err(), Some(local::Error::NotEnrolled));
    assert_eq!(
        ready(
            world
                .authority
                .account_clis(&mut world.site.node.memory, &access, at(27))
        )
        .unwrap()
        .iter()
        .map(|device| device.serial)
        .collect::<Vec<_>>(),
        [other.serial]
    );
    assert_eq!(world.call(&other, &kept, 27).unwrap().holder(), Holder::Account);
}

#[test]
fn two_finishes_cannot_claim_the_last_place_and_a_disconnect_frees_it() {
    let mut world = World::new();
    let fresh = world.fresh();
    let early = world.request(30, 20);
    world.approve(&early, &fresh, 21).unwrap();
    let early_finish = world.finish(&early, &alice(), 22).unwrap();
    for seed in 2..17 {
        let cli = world.request(seed, 20);
        world.approve(&cli, &fresh, 21).unwrap();
        let finish = world.finish(&cli, &alice(), 22).unwrap();
        world.artifact(finish);
    }
    let last = world.request(31, 24);
    let other = world.request(32, 24);
    world.approve(&last, &fresh, 25).unwrap();
    world.approve(&other, &fresh, 25).unwrap();
    let one = world.finish(&last, &alice(), 26).unwrap();
    let (two, plan) = world.finish(&other, &alice(), 26).unwrap();
    world.artifact(one);
    assert!(matches!(world.site.node.commit(two, plan), Outcome::Conflict));
    assert!(matches!(
        world.site.node.commit(early_finish.0, early_finish.1),
        Outcome::Conflict
    ));
    assert_eq!(world.finish(&other, &alice(), 27).err(), Some(local::Error::Full));
    let (proposal, plan) = ready(world.authority.disconnect(
        &mut world.site.node.memory,
        &fresh,
        last.serial,
        at(27),
        OperationId::new(b"free").unwrap(),
    ))
    .unwrap();
    assert!(matches!(world.site.node.commit(proposal, plan), Outcome::Accepted(_)));
    let next = world.finish(&other, &alice(), 28).unwrap();
    world.artifact(next);
}

/// The refusal of a local authority, from a store that does not fail.
fn refused_local(failure: local::Failure<rsauthnz_conformance::memory::Error>) -> local::Error {
    match failure {
        local::Failure::Refused(error) => error,
        local::Failure::Store(error) => panic!("the memory binding failed a read: {error}"),
    }
}

#[test]
fn a_cli_that_alice_approves_calls_for_her_account_and_makes_no_administrator_call() {
    let mut world = World::new();
    let cli = world.request(2, 20);
    let (access, fresh) = world.session();
    assert_eq!(
        world.show(&access, &cli.code, 21),
        Ok(Some(Request {
            name: "alice-laptop".into(),
            fingerprint: rscrypto::Sha256::digest(&cli.key.public),
            loopback: None,
            created: START + Duration::from_secs(20),
            ends: START + Duration::from_secs(20) + ENROLLMENT_LIFETIME,
            approved: false,
        }))
    );
    assert_eq!(world.poll(&cli, 22), Ok(Status::Waiting));
    assert_eq!(world.finish(&cli, &alice(), 22).err(), Some(local::Error::Waiting));

    assert_eq!(world.approve(&cli, &fresh, 23), Ok(()));
    assert_eq!(world.approve(&cli, &fresh, 24).err(), Some(local::Error::Approved));
    assert_eq!(
        world.poll(&cli, 25),
        Ok(Status::Approved(CliId {
            account: alice(),
            serial: cli.serial
        }))
    );
    let finish = world.finish(&cli, &alice(), 26).expect("a finish");
    let credential = world.artifact(finish);
    assert_eq!(world.poll(&cli, 27).err(), Some(local::Error::Request));

    let admitted = world.call(&cli, &credential, 28).expect("an admitted call");
    assert_eq!((admitted.subject(), admitted.holder()), (&alice(), Holder::Account));

    // The CLI of an account makes no administrator call, also when the authority has an administrator.
    let bob = Id::new("acme", "bob").expect("an identifier");
    let issue = ready(world.authority.issue(
        &mut world.site.node.memory,
        &world.grant,
        bob.clone(),
        at(29),
        &mut world.site.random,
        OperationId::new(b"issue").expect("an operation"),
    ));
    let text = world.artifact(issue.map_err(refused_local).expect("an issue"));
    let value = Bootstrap::parse(core::str::from_utf8(&text).expect("text")).expect("a value");
    let serial = Serial(world.site.node.driver.allocate(Kind::Credential).expect("a serial"));
    let administrator = Pair::new(3);
    let bootstrap = world.authority.bootstrap(
        &mut world.site.node.memory,
        &value,
        &administrator.public,
        serial,
        at(30),
    );
    let pending = ready(bootstrap).map_err(refused_local).expect("a bootstrap");
    let signature = world.issuer.sign(&pending.to_be_signed());
    let bound = pending
        .finish(&signature, OperationId::new(b"bootstrap").expect("an operation"))
        .expect("a proposal");
    world.artifact(bound);
    let challenge = admitted.next();
    let unlink = Unlink::new(
        challenge,
        OperationId::new(b"unlink").expect("an operation"),
        bob,
        Limits::default(),
    )
    .expect("an unlink");
    let proof = world.prove(&cli.key, &credential, unlink.call(), 31);
    let refused = world.authority.unlink(
        &mut world.site.node.memory,
        &credential,
        &proof,
        &unlink,
        at(31),
        &mut world.site.random,
    );
    assert_eq!(
        ready(refused).map_err(refused_local).err(),
        Some(local::Error::NotEnrolled)
    );
}

/// An approval names one request, so it binds only the key of that request, and only for the approving account.
#[test]
fn an_approval_binds_only_the_key_of_its_request_for_its_account() {
    let mut world = World::new();
    let approved = world.request(2, 20);
    let other = world.request(3, 20);
    let fresh = world.fresh();
    world.approve(&approved, &fresh, 21).expect("an approval");

    // The other request has no approval, and its device code finishes no other request.
    assert_eq!(world.finish(&other, &alice(), 22).err(), Some(local::Error::Waiting));
    let crossed = Cli {
        serial: approved.serial,
        key: Pair::new(3),
        code: approved.code,
        device: DeviceCode::from_bytes(*other.device.as_bytes()),
    };
    assert_eq!(world.finish(&crossed, &alice(), 22).err(), Some(local::Error::Request));
    let bob = Id::new("acme", "bob").expect("an identifier");
    assert_eq!(world.finish(&approved, &bob, 22).err(), Some(local::Error::Account));

    let finish = world.finish(&approved, &alice(), 23).expect("a finish");
    let credential = world.artifact(finish);
    world.call(&approved, &credential, 24).unwrap();
    assert_eq!(world.reissue(&other, 25).err(), Some(local::Error::NotEnrolled));
}

#[test]
fn an_ended_request_refuses_its_approval_and_its_finish() {
    let mut world = World::new();
    let fresh = world.fresh();
    let late = ENROLLMENT_LIFETIME.as_secs();
    let unapproved = world.request(2, 20);
    assert_eq!(
        world.approve(&unapproved, &fresh, 20 + late).err(),
        Some(local::Error::Expired)
    );
    // An approval gives the CLI `ENROLLMENT_LIFETIME` from the approval to finish.
    let approved = world.request(3, 20);
    world.approve(&approved, &fresh, 30).expect("an approval");
    assert_eq!(
        world.finish(&approved, &alice(), 30 + late).err(),
        Some(local::Error::Expired)
    );
}

/// The CLI stored its key before its request, so after a lost finish response it gives its account and its key, and
/// custody signs the credential of its binding again.
#[test]
fn a_cli_whose_finish_response_was_lost_reads_its_credential_and_proves_possession() {
    let mut world = World::new();
    let cli = world.request(2, 20);
    let fresh = world.fresh();
    world.approve(&cli, &fresh, 21).expect("an approval");
    let (proposal, plan) = world.finish(&cli, &alice(), 22).expect("a finish");
    world.site.node.memory.inject(Fault::LostResponse);
    assert!(matches!(world.site.node.commit(proposal, plan), Outcome::Unknown(_)));
    world.site.node.start();

    assert_eq!(world.poll(&cli, 23).err(), Some(local::Error::Request));
    let credential = world.reissue(&cli, 24).expect("the credential");
    let admitted = world.call(&cli, &credential, 25).expect("an admitted call");
    assert_eq!(admitted.holder(), Holder::Account);
}

/// The finish pays for its CLI anchor with the request, so a restore completes a finish in doubt once, and keeps the
/// binding of an acknowledged finish.
#[test]
fn a_restore_completes_a_finish_in_doubt_once_and_keeps_an_acknowledged_one() {
    let mut world = World::new();
    let doubt = world.request(2, 20);
    let kept = world.request(3, 20);
    let fresh = world.fresh();
    world.approve(&doubt, &fresh, 21).expect("an approval");
    world.approve(&kept, &fresh, 21).expect("an approval");
    let snapshot = world.site.node.memory.snapshot();

    let finish = world.finish(&kept, &alice(), 22).expect("a finish");
    let acknowledged = world.artifact(finish);
    let (proposal, plan) = world.finish(&doubt, &alice(), 22).expect("a finish");
    let operation = proposal.operation().clone();
    world.site.node.memory.inject(Fault::LostResponse);
    assert!(matches!(world.site.node.commit(proposal, plan), Outcome::Unknown(_)));
    world.site.node.memory.restore(&snapshot);
    world.site.node.driver.restore(at(0)).expect("a restore");
    world.site.node.run();

    assert_eq!(world.reissue(&kept, 30), Ok(acknowledged));
    assert_eq!(world.poll(&doubt, 30).err(), Some(local::Error::Request));
    let credential = world.reissue(&doubt, 30).expect("the credential");
    world.call(&doubt, &credential, 31).unwrap();
    let ticket = world.site.node.driver.lookup(operation).expect("a lookup");
    world.site.node.run();
    assert!(matches!(
        world.site.node.driver.take(ticket),
        Some(Answer::Lookup(Lookup::Committed(_)))
    ));
}

/// A pending request of the A208 form, as a store holds it at an upgrade: `["rsauthnz.local.enrollment.2", device,
/// holder, name, created, null]` at the key of the SHA-256 digest of `["rsauthnz.local.enrollment.2", authority,
/// code]`, with all 8 letters of `code`.
fn earlier_request(world: &mut World, code: &str, device: &DeviceCode, holder: &[u8; 1984], seconds: u64) {
    const FORM: &str = "rsauthnz.local.enrollment.2";
    let authority: Id<rsauthnz::id::Authority> = Id::new("acme", "cli").expect("an identifier");
    let encode =
        |items: Vec<Value<'_>>| rsauthnz::cbor::encode(&Value::Array(items), Limits::default()).expect("a form");
    let letters = code.replace('-', "");
    let digest = rscrypto::Sha256::digest(&encode(vec![
        Value::Text(FORM),
        authority.to_cbor(),
        Value::Bytes(letters.as_bytes()),
    ]));
    let key = Kind::CliEnrollment.key(&digest).expect("a key");
    let device = rscrypto::Sha256::digest(device.as_bytes());
    let created = at(seconds).estimate();
    let data = encode(vec![
        Value::Text(FORM),
        Value::Bytes(&device),
        Value::Bytes(holder),
        Value::Text("alice-laptop"),
        Value::Unsigned(created.as_secs()),
        Value::Null,
    ]);
    let audit = rsauthnz::transition::Audit {
        actor: rsauthnz::id::Principal::Human(world.grant.owner.clone()),
        action: Id::new("rsauthnz", "cli.enroll").expect("an identifier"),
        time: at(seconds),
    };
    let mut proposal = Proposal::new(
        OperationId::new(b"earlier").expect("an operation"),
        audit,
        &Value::Null,
        Limits::default(),
    )
    .expect("a proposal");
    proposal
        .read(rsauthnz::transition::Dependency::Absent(key.clone()))
        .expect("a read");
    let version = [1_u64.to_be_bytes().as_slice(), &device].concat();
    proposal
        .change(rsauthnz::transition::Change::Write {
            key,
            version: rsauthnz::id::AuthorityVersion::new(authority, &version).expect("a version"),
            end: Some(created + ENROLLMENT_LIFETIME),
            data: data.into_boxed_slice(),
        })
        .expect("a write");
    assert!(matches!(
        world.site.node.commit(proposal, Plan::default()),
        Outcome::Accepted(_)
    ));
}

/// Each check of a user code is a commit at the version of its request, and a wrong check counts, also in an approval.
/// So a right check that read the version before a count conflicts and shows nothing: checks at the same time get one
/// answer for each count. After `ATTEMPTS_MAX` wrong checks, the request is locked: its right code refuses, and the CLI
/// makes a new request.
#[test]
fn wrong_user_codes_past_the_bound_lock_a_cli_request() {
    let mut world = World::new();
    let cli = world.request(2, 20);
    let (access, fresh) = world.session();
    let wrong = wrong(&cli.code);
    for attempt in 1..=ATTEMPTS_MAX {
        let (right, plan, shown) = world.check(&access, &cli.code, 21).unwrap();
        if attempt % 2 == 0 {
            assert_eq!(world.approval(&cli, &wrong, &fresh, 21), Ok(false));
        } else {
            assert_eq!(world.show(&access, &wrong, 21), Ok(None));
        }
        let outcome = world.site.node.commit(right, plan);
        assert!(matches!(outcome, Outcome::Conflict));
        assert_eq!(shown.release(&outcome), None);
    }
    assert_eq!(world.show(&access, &cli.code, 22), Err(local::Error::Locked));
    assert_eq!(world.approve(&cli, &fresh, 22), Err(local::Error::Locked));
    assert_eq!(world.poll(&cli, 22), Err(local::Error::Locked));
    assert_eq!(world.finish(&cli, &alice(), 22).err(), Some(local::Error::Locked));
}

/// The key of a request covers its form, so after an upgrade from the form of A208, a pending request of that form
/// refuses for the human and for the CLI. The CLI makes a new request.
#[test]
fn a_pending_request_of_the_earlier_form_refuses() {
    let mut world = World::new();
    let key = Pair::new(2);
    let device = DeviceCode::from_bytes([5; 32]);
    earlier_request(&mut world, "WDJB-MJHT", &device, &key.public, 20);
    let code = UserCode::parse("WDJB-MJHT").unwrap();
    let (access, _) = world.session();
    assert_eq!(world.show(&access, &code, 21), Err(local::Error::Request));
    let poll = world
        .authority
        .poll(&mut world.site.node.memory, &code, &device, None, at(21));
    assert_eq!(ready(poll).map_err(refused_local), Err(local::Error::Request));
}

/// A loopback request finishes only with the redirect code that the receipt of its approval gives to the browser. So a
/// human who approves the request of a remote CLI by mistake binds no key: the device code alone finishes nothing, and
/// tells nothing of the approval. A request with no loopback address takes no redirect code.
#[test]
fn a_loopback_cli_request_finishes_only_with_the_redirect_code_of_its_approval() {
    let mut world = World::new();
    let loopback = Loopback::parse("http://127.0.0.1:49152/approved").unwrap();
    let cli = world.request_at(2, Some(&loopback), 20);
    let plain = world.request(3, 20);
    let (access, fresh) = world.session();
    let shown = world.show(&access, &cli.code, 21).unwrap().expect("the code is right");
    assert_eq!(shown.loopback.as_ref(), Some(&loopback));
    let approve = world.authority.approve(
        &mut world.site.node.memory,
        &fresh,
        &cli.code,
        cli.serial,
        at(21),
        &mut world.site.random,
    );
    let (proposal, plan, checked) = ready(approve).map_err(refused_local).unwrap();
    let outcome = world.site.node.commit(proposal, plan);
    let Outcome::Accepted(receipt) = &outcome else {
        panic!("the approval gave {outcome:?}");
    };
    let redirect = RedirectCode::from_bytes(receipt.artifact().unwrap().try_into().unwrap());
    assert_eq!(checked.release(&outcome), Some(Some(loopback)));

    let other = RedirectCode::from_bytes([7; 32]);
    for wrong in [None, Some(&other)] {
        assert_eq!(world.poll_with(&cli, wrong, 22), Err(local::Error::Redirect));
        assert_eq!(
            world.finish_with(&cli, wrong, &alice(), 22).err(),
            Some(local::Error::Redirect)
        );
    }
    world.approve(&plain, &fresh, 22).unwrap();
    assert_eq!(
        world.poll_with(&plain, Some(&redirect), 22),
        Err(local::Error::Redirect)
    );
    assert_eq!(
        world.finish_with(&plain, Some(&redirect), &alice(), 22).err(),
        Some(local::Error::Redirect)
    );

    let approved = Status::Approved(CliId {
        account: alice(),
        serial: cli.serial,
    });
    assert_eq!(world.poll_with(&cli, Some(&redirect), 23), Ok(approved));
    let finish = world.finish_with(&cli, Some(&redirect), &alice(), 23).unwrap();
    let credential = world.artifact(finish);
    assert_eq!(world.call(&cli, &credential, 24).unwrap().holder(), Holder::Account);
}
