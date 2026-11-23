//! The enrollment of a CLI that a human approves in a browser: the CLI asks with its key, alice approves with a fresh
//! user verification of her passkey session, and the finish of the CLI binds its key to a CLI credential of her
//! account. rscrypto signs in place of custody, so that the tests hold the keys.

use core::time::Duration;

use rsauthnz::account::Fresh;
use rsauthnz::cbor::Value;
use rsauthnz::cli::{Call, Challenge};
use rsauthnz::cose::{Key as CoseKey, PublicKey, TrustedKey};
use rsauthnz::credential::{ProofDraft, Serial};
use rsauthnz::crypto::Algorithm;
use rsauthnz::custody::{Handle, KeyId};
use rsauthnz::id::{Human, Id};
use rsauthnz::limits::{Limits, SignatureBudget};
use rsauthnz::local::enroll::{DeviceCode, ENROLLMENT_LIFETIME, Request, Status, UserCode};
use rsauthnz::local::{self, Admitted, Authority, Bootstrap, Holder, HostGrant, Offer, Unlink};
use rsauthnz::store::Kind;
use rsauthnz::store::driver::{Answer, Lookup, Plan};
use rsauthnz::transition::{OperationId, Outcome, Proposal};
use rsauthnz_conformance::suite::{Fault, Subject as _};
use rscrypto::auth::{MlDsa65Ed25519, MlDsa65Ed25519SecretKey};

use super::authenticator::Passkey;
use super::{START, Site, alice, at, ready};

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
        let key = Pair::new(seed);
        let (proposal, plan, code) = self
            .authority
            .enroll(&key.public, "alice-laptop", at(seconds), &mut self.site.random)
            .expect("a request");
        let device = self.artifact((proposal, plan));
        let device = DeviceCode::from_bytes(device.try_into().expect("32 bytes"));
        Cli { key, code, device }
    }

    /// A fresh user verification of alice: a passkey sign-in at 11, checked at 12.
    fn fresh(&mut self) -> Fresh {
        self.site.fresh(&self.passkey)
    }

    /// The approval of the request of `cli` with `fresh` at `seconds`.
    fn approve(&mut self, cli: &Cli, fresh: &Fresh, seconds: u64) -> Result<(), local::Error> {
        let approve = self.authority.approve(
            &mut self.site.node.memory,
            fresh,
            &cli.code,
            at(seconds),
            &mut self.site.random,
        );
        let (proposal, plan) = ready(approve).map_err(refused_local)?;
        assert!(matches!(self.site.node.commit(proposal, plan), Outcome::Accepted(_)));
        Ok(())
    }

    /// The proposal of the finish of the request of `cli` for `account` at `seconds`, which the issuer key signs.
    fn finish(&mut self, cli: &Cli, account: &Id<Human>, seconds: u64) -> Result<(Proposal, Plan), local::Error> {
        let serial = Serial(self.site.node.driver.allocate(Kind::Credential).expect("a serial"));
        let finish = self.authority.finish(
            &mut self.site.node.memory,
            &cli.code,
            &cli.device,
            account,
            serial,
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
    fn call(&mut self, key: &Pair, credential: &[u8], seconds: u64) -> Result<Admitted, local::Error> {
        let offer = ready(self.authority.account_challenge(
            &mut self.site.node.memory,
            &alice(),
            &key.public,
            at(seconds),
            &mut self.site.random,
            OperationId::new(b"challenge").expect("an operation"),
        ));
        let challenge = match offer.map_err(refused_local)? {
            Offer::Open(challenge) => challenge,
            Offer::New(proposal, plan) => {
                Challenge::from_bytes(self.artifact((proposal, plan)).try_into().expect("32 bytes"))
            }
        };
        let call = Call::new(
            challenge,
            OperationId::new(b"status").expect("an operation"),
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
        let (proposal, admission) = ready(admit).map_err(refused_local)?;
        let outcome = self.site.node.commit(proposal, Plan::default());
        Ok(admission.release(&outcome).expect("the admitted call"))
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
    fn reissue(&mut self, key: &Pair, seconds: u64) -> Result<Vec<u8>, local::Error> {
        let reissue =
            ready(
                self.authority
                    .account_credential(&mut self.site.node.memory, &alice(), &key.public, at(seconds)),
            );
        let reissue = reissue.map_err(refused_local)?;
        let signature = self.issuer.sign(&reissue.to_be_signed());
        reissue.finish(&signature)
    }

    fn poll(&mut self, cli: &Cli, seconds: u64) -> Result<Status, local::Error> {
        let poll = self
            .authority
            .poll(&mut self.site.node.memory, &cli.code, &cli.device, at(seconds));
        ready(poll).map_err(refused_local)
    }
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
    let shown = ready(world.authority.request(&mut world.site.node.memory, &cli.code, at(21))).map_err(refused_local);
    assert_eq!(
        shown,
        Ok(Request {
            name: "alice-laptop".into(),
            fingerprint: rscrypto::Sha256::digest(&cli.key.public),
            created: START + Duration::from_secs(20),
            ends: START + Duration::from_secs(20) + ENROLLMENT_LIFETIME,
            approved: false,
        })
    );
    assert_eq!(world.poll(&cli, 22), Ok(Status::Waiting));
    assert_eq!(world.finish(&cli, &alice(), 22).err(), Some(local::Error::Waiting));

    let fresh = world.fresh();
    assert_eq!(world.approve(&cli, &fresh, 23), Ok(()));
    assert_eq!(world.approve(&cli, &fresh, 24).err(), Some(local::Error::Approved));
    assert_eq!(world.poll(&cli, 25), Ok(Status::Approved(alice())));
    let finish = world.finish(&cli, &alice(), 26).expect("a finish");
    let credential = world.artifact(finish);
    assert_eq!(world.poll(&cli, 27).err(), Some(local::Error::Request));

    let admitted = world.call(&cli.key, &credential, 28).expect("an admitted call");
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
        key: Pair::new(3),
        code: approved.code,
        device: DeviceCode::from_bytes(*other.device.as_bytes()),
    };
    assert_eq!(world.finish(&crossed, &alice(), 22).err(), Some(local::Error::Request));
    let bob = Id::new("acme", "bob").expect("an identifier");
    assert_eq!(world.finish(&approved, &bob, 22).err(), Some(local::Error::Account));

    let finish = world.finish(&approved, &alice(), 23).expect("a finish");
    let credential = world.artifact(finish);
    world.call(&approved.key, &credential, 24).unwrap();
    assert_eq!(world.reissue(&other.key, 25).err(), Some(local::Error::NotEnrolled));
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
    let credential = world.reissue(&cli.key, 24).expect("the credential");
    let admitted = world.call(&cli.key, &credential, 25).expect("an admitted call");
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

    assert_eq!(world.reissue(&kept.key, 30), Ok(acknowledged));
    assert_eq!(world.poll(&doubt, 30).err(), Some(local::Error::Request));
    let credential = world.reissue(&doubt.key, 30).expect("the credential");
    world.call(&doubt.key, &credential, 31).unwrap();
    let ticket = world.site.node.driver.lookup(operation).expect("a lookup");
    world.site.node.run();
    assert!(matches!(
        world.site.node.driver.take(ticket),
        Some(Answer::Lookup(Lookup::Committed(_)))
    ));
}
