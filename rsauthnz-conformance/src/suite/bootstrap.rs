//! The cases of the local authority ([`rsauthnz::local`]): the bootstrap, the owner re-bootstrap, and their restore.
//! Each case runs the transitions of the core through the commit driver on the binding.

use core::time::Duration;

use rsauthnz::cbor::Value;
use rsauthnz::cli::{Call, Challenge};
use rsauthnz::cose::{Key as CoseKey, PublicKey, TrustedKey};
use rsauthnz::credential::{ProofDraft, Serial};
use rsauthnz::crypto::Algorithm;
use rsauthnz::custody::{Handle, KeyId};
use rsauthnz::id::Id;
use rsauthnz::limits::{Limits, SignatureBudget};
use rsauthnz::local::{self, Admitted, Authority, Bootstrap, Failure, HostGrant, Issue, Status, Unlink};
use rsauthnz::time::{Reading, ReadingSource};
use rsauthnz::transition::{self, OperationId};
use rscrypto::ChaCha20Rng;
use rscrypto::auth::{MlDsa65Ed25519, MlDsa65Ed25519SecretKey};

use super::{
    Checked, Fault, Kind, Lookup, Outcome, Plan, Proposal, Run, Subject, account, at_commit, authority, crashes,
    ensure, now, op,
};

/// A composite key pair. rscrypto signs in place of custody. A fixed filler makes the key reproducible.
struct Keys {
    public: [u8; 1984],
    secret: MlDsa65Ed25519SecretKey,
}

impl Keys {
    fn new(filler: u8) -> Self {
        let (public, secret) = MlDsa65Ed25519::generate_keypair(|out| {
            out.fill(filler);
            Ok(())
        })
        .expect("a fixed filler makes a key pair");
        Self {
            public: public.to_bytes(),
            secret,
        }
    }

    fn sign(&self, message: &[u8]) -> Vec<u8> {
        self.secret
            .sign_deterministic(message, &[])
            .expect("a composite key signs a message with an empty context")
            .as_bytes()
            .to_vec()
    }

    /// The custody handle of the key, as the issuer key of an authority.
    fn handle(&self) -> Handle {
        Handle::new(KeyId::from_bytes([7; 16]), Algorithm::MlDsa65Ed25519, &self.public)
            .expect("the public key of a composite key pair makes a handle")
    }

    /// The proof of possession of the key, the `cnf` key of `credential`, over the request binding `binding` of a call.
    fn proof(&self, credential: &[u8], binding: &[u8]) -> Vec<u8> {
        let key = TrustedKey::new(
            Algorithm::MlDsa65Ed25519,
            &CoseKey {
                kid: None,
                alg: None,
                public: PublicKey::MlDsa65Ed25519(&self.public),
            },
        )
        .expect("a composite public key is a trusted key");
        let draft = ProofDraft::new(&key, credential, &grant().origin, binding, now()).expect("a proof fits its bound");
        let signature = self.sign(&draft.to_be_signed());
        draft
            .finish(&signature, &mut SignatureBudget::new(&Limits::default()))
            .expect("the holder key signs its proof")
    }
}

/// The host grant of the cases.
fn grant() -> HostGrant {
    HostGrant {
        owner: account("owner"),
        origin: Id::new("acme", "app").expect("the origin of the cases is a valid identifier"),
    }
}

/// A reading at the end of a value that the cases issue at [`now`].
fn later() -> Reading {
    Reading::new(
        now().estimate().saturating_add(local::LIFETIME),
        Some(Duration::from_secs(1)),
        ReadingSource::Caller,
    )
}

/// The detail of a refused operation of the local authority.
fn refused<E: core::fmt::Display>(what: &'static str) -> impl FnOnce(E) -> String {
    move |error| format!("{what} refused: {error}")
}

/// Opens the authority `name` of the cases under [`grant`], with the issuer key `issuer`.
async fn open<S: Subject>(run: &mut Run<S>, issuer: &Keys, name: &str) -> Result<Authority, String> {
    let id = Id::new("acme", name).expect("each authority of the cases is a valid identifier");
    Authority::open(&mut run.binding, &grant(), id, issuer.handle(), Limits::default())
        .await
        .map_err(refused("an open"))
}

/// The proposal `proposal` with `plan`, after the driver ends it: its outcome.
async fn submitted<S: Subject>(run: &mut Run<S>, proposal: Proposal, plan: Plan) -> Result<Outcome, String> {
    let ticket = run.submit(proposal, plan)?;
    run.settle().await?;
    run.outcome(ticket).await
}

/// The artifact of an accepted commit, or `Err` with `what`.
fn artifact(outcome: Outcome, what: &str) -> Result<Vec<u8>, String> {
    match outcome {
        Outcome::Accepted(receipt) => receipt
            .artifact()
            .map(<[u8]>::to_vec)
            .ok_or_else(|| format!("{what} released no artifact")),
        outcome => Err(format!("{what} did not commit: {outcome:?}")),
    }
}

/// The value that the commit of an issue for `administrator`, under the operation `name`, gives.
async fn issue<S: Subject>(
    run: &mut Run<S>,
    auth: &Authority,
    random: &mut ChaCha20Rng,
    administrator: &str,
    name: &str,
) -> Result<Bootstrap, String> {
    let (proposal, plan) = auth
        .issue(
            &mut run.binding,
            &grant(),
            account(administrator),
            now(),
            random,
            op(name),
        )
        .await
        .map_err(refused("an issue"))?;
    let text = artifact(submitted(run, proposal, plan).await?, "an issue")?;
    let text = core::str::from_utf8(&text).map_err(|_| "the value of an issue is not text".to_owned())?;
    Bootstrap::parse(text).map_err(refused("the text of an issued value"))
}

/// The proposal of the bootstrap of `value` by the client with the key `client`, under the operation `name`.
async fn propose<S: Subject>(
    run: &mut Run<S>,
    auth: &Authority,
    issuer: &Keys,
    value: &Bootstrap,
    client: &Keys,
    name: &str,
) -> Result<(Proposal, Plan), String> {
    let serial = run
        .driver
        .allocate(Kind::Credential)
        .map_err(refused("an allocation"))?;
    let pending = auth
        .bootstrap(&mut run.binding, value, &client.public, Serial(serial), now())
        .await
        .map_err(refused("a bootstrap"))?;
    let signature = issuer.sign(&pending.to_be_signed());
    pending.finish(&signature, op(name)).map_err(refused("a bootstrap"))
}

/// The credential that the commit of the bootstrap of `value` by `client` gives.
async fn enroll<S: Subject>(
    run: &mut Run<S>,
    auth: &Authority,
    issuer: &Keys,
    value: &Bootstrap,
    client: &Keys,
    name: &str,
) -> Result<Vec<u8>, String> {
    let (proposal, plan) = propose(run, auth, issuer, value, client, name).await?;
    artifact(submitted(run, proposal, plan).await?, "a bootstrap")
}

/// The refusal of a bootstrap of `value` at `at`, or `None` when the bootstrap does not refuse.
async fn refusal<S: Subject>(
    run: &mut Run<S>,
    auth: &Authority,
    value: &Bootstrap,
    client: &Keys,
    at: Reading,
) -> Result<Option<local::Error>, String> {
    match auth
        .bootstrap(&mut run.binding, value, &client.public, Serial(0), at)
        .await
    {
        Err(Failure::Refused(error)) => Ok(Some(error)),
        Err(Failure::Store(error)) => Err(format!("a read failed with no fault: {error}")),
        Ok(_) => Ok(None),
    }
}

/// An operation identity of 16 bytes from `random`.
fn drawn(random: &mut ChaCha20Rng) -> OperationId {
    let mut id = [0; 16];
    random.fill_bytes(&mut id);
    OperationId::new(&id).expect("an identity of 16 bytes is valid")
}

/// The challenge that the commit of an issue for the administrator `administrator` gives.
async fn challenge<S: Subject>(
    run: &mut Run<S>,
    auth: &Authority,
    administrator: &str,
    random: &mut ChaCha20Rng,
) -> Result<Result<Challenge, local::Error>, String> {
    let operation = drawn(random);
    let issued = match auth
        .challenge(&mut run.binding, &account(administrator), now(), random, operation)
        .await
    {
        Ok((proposal, plan)) => artifact(submitted(run, proposal, plan).await?, "the issue of a challenge")?,
        Err(failure) => return refusal_of(failure),
    };
    let challenge = <[u8; 32]>::try_from(issued.as_slice())
        .map_err(|_| "the artifact of an issue is not a challenge".to_owned())?;
    Ok(Ok(Challenge::from_bytes(challenge)))
}

/// The refusal of an operation of the local authority, or `Err` for a failed read.
fn refusal_of<E: core::fmt::Display, T>(failure: Failure<E>) -> Result<Result<T, local::Error>, String> {
    match failure {
        Failure::Refused(error) => Ok(Err(error)),
        Failure::Store(error) => Err(format!("a read failed with no fault: {error}")),
    }
}

/// The admission of one remote call of the administrator `administrator` with `credential` and a proof by `client`:
/// the issue of a challenge, the proof over the call, and the commit of the admission.
async fn admit<S: Subject>(
    run: &mut Run<S>,
    auth: &Authority,
    credential: &[u8],
    client: &Keys,
    administrator: &str,
    random: &mut ChaCha20Rng,
) -> Result<Result<Admitted, local::Error>, String> {
    let challenge = match challenge(run, auth, administrator, random).await? {
        Ok(challenge) => challenge,
        Err(error) => return Ok(Err(error)),
    };
    let call =
        Call::new(challenge, drawn(random), &Value::Text("status"), Limits::default()).map_err(refused("a call"))?;
    let proof = client.proof(credential, call.binding());
    let (proposal, admission) = match auth
        .admit(&mut run.binding, credential, &proof, &call, now(), random)
        .await
    {
        Ok(admission) => admission,
        Err(failure) => return refusal_of(failure),
    };
    let outcome = submitted(run, proposal, Plan::default()).await?;
    admission
        .release(&outcome)
        .map(Ok)
        .ok_or_else(|| format!("the commit of an admission did not land: {outcome:?}"))
}

/// The proposal of the unlink of the binding of `target` by the administrator `administrator` with `credential` and
/// a proof by `client`: the issue of a challenge, and the proof over the unlink.
async fn propose_unlink<S: Subject>(
    run: &mut Run<S>,
    auth: &Authority,
    (credential, client, administrator): (&[u8], &Keys, &str),
    target: &str,
    random: &mut ChaCha20Rng,
) -> Result<Result<(Proposal, Plan), local::Error>, String> {
    let challenge = match challenge(run, auth, administrator, random).await? {
        Ok(challenge) => challenge,
        Err(error) => return Ok(Err(error)),
    };
    let unlink =
        Unlink::new(challenge, drawn(random), account(target), Limits::default()).map_err(refused("an unlink"))?;
    let proof = client.proof(credential, unlink.call().binding());
    match auth
        .unlink(&mut run.binding, credential, &proof, &unlink, now(), random)
        .await
    {
        Ok((proposal, plan, _)) => Ok(Ok((proposal, plan))),
        Err(failure) => refusal_of(failure),
    }
}

/// The outcome of the unlink of the binding of `target` by an administrator ([`propose_unlink`]), or its refusal.
async fn unlink<S: Subject>(
    run: &mut Run<S>,
    auth: &Authority,
    caller: (&[u8], &Keys, &str),
    target: &str,
    random: &mut ChaCha20Rng,
) -> Result<Result<Outcome, local::Error>, String> {
    match propose_unlink(run, auth, caller, target, random).await? {
        Ok((proposal, plan)) => Ok(Ok(submitted(run, proposal, plan).await?)),
        Err(error) => Ok(Err(error)),
    }
}

/// The credential of the binding of `administrator` with the key `client`, which `issuer` signs again: the recovery of
/// a client whose response was lost.
async fn recover<S: Subject>(
    run: &mut Run<S>,
    auth: &Authority,
    issuer: &Keys,
    client: &Keys,
    administrator: &str,
) -> Result<Vec<u8>, String> {
    let reissue = auth
        .credential(&mut run.binding, &account(administrator), &client.public, now())
        .await
        .map_err(refused("a recovery"))?;
    let signature = issuer.sign(&reissue.to_be_signed());
    reissue.finish(&signature).map_err(refused("a recovery"))
}

/// The refusal of the last administrator binding: the core keeps an administrator whose credential is valid.
const LAST: local::Error = local::Error::Transition(transition::Error::LastAnchor);

/// The administrator and the state of each issue of the report at `at`.
async fn report<S: Subject>(run: &mut Run<S>, auth: &Authority, at: Reading) -> Result<Vec<(String, Status)>, String> {
    let report = auth.report(&mut run.binding, at).await.map_err(refused("a report"))?;
    Ok(report
        .issues
        .into_iter()
        .map(
            |Issue {
                 administrator, status, ..
             }| (administrator.value().to_owned(), status),
        )
        .collect())
}

fn statuses(rows: &[(&str, Status)]) -> Vec<(String, Status)> {
    rows.iter()
        .map(|(name, status)| ((*name).to_owned(), *status))
        .collect()
}

const BOUND: Status = Status::Consumed { bound: true };

pub(super) async fn bootstrap<S: Subject>(mut make: impl FnMut() -> S) -> Checked {
    let (issuer, alice, bob, carol) = (Keys::new(1), Keys::new(2), Keys::new(3), Keys::new(4));
    let mut random = ChaCha20Rng::from_seed([1; 32]);
    let mut run = Run::seeded(make()).await?;
    let auth = open(&mut run, &issuer, authority().value()).await?;
    let first = issue(&mut run, &auth, &mut random, "alice", "i-1").await?;
    ensure(
        refusal(&mut run, &auth, &first, &alice, later()).await? == Some(local::Error::Expired),
        "an expired first value did not refuse",
    )?;
    let other = open(&mut run, &issuer, "other").await?;
    ensure(
        refusal(&mut run, &other, &first, &alice, now()).await? == Some(local::Error::Unknown),
        "a value of one authority did not refuse at another",
    )?;
    let foreign = Authority::open(
        &mut run.binding,
        &grant(),
        authority(),
        Keys::new(9).handle(),
        Limits::default(),
    )
    .await;
    ensure(
        matches!(foreign, Err(Failure::Refused(local::Error::Issuer))),
        "an authority opened with another issuer key",
    )?;
    let stranger = HostGrant {
        owner: account("mallory"),
        ..grant()
    };
    let reissue = auth
        .issue(
            &mut run.binding,
            &stranger,
            account("mallory"),
            now(),
            &mut random,
            op("i-x"),
        )
        .await;
    ensure(
        matches!(reissue, Err(Failure::Refused(local::Error::Grant))),
        "an issue under the grant of another owner did not refuse",
    )?;
    // A credential of a twin authority in another store, before an administrator enrolls in this one.
    let mut twin = Run::seeded(make()).await?;
    let twin_authority = open(&mut twin, &issuer, authority().value()).await?;
    let value = issue(&mut twin, &twin_authority, &mut random, "alice", "t-1").await?;
    let credential = enroll(&mut twin, &twin_authority, &issuer, &value, &alice, "t-2").await?;
    ensure(
        matches!(
            admit(&mut run, &auth, &credential, &alice, "alice", &mut random).await?,
            Err(local::Error::NotEnrolled)
        ),
        "a remote call was admitted before an administrator enrolled",
    )?;

    // Two concurrent uses of the first value: each one reads it before either commits.
    let uses = [
        propose(&mut run, &auth, &issuer, &first, &alice, "u-1").await?,
        propose(&mut run, &auth, &issuer, &first, &bob, "u-2").await?,
    ];
    let tickets = uses
        .map(|(proposal, plan)| run.submit(proposal, plan))
        .into_iter()
        .collect::<Result<Vec<_>, _>>()?;
    run.settle().await?;
    let mut credentials = Vec::new();
    let mut others = 0;
    for ticket in tickets {
        match run.outcome(ticket).await? {
            Outcome::Accepted(receipt) => credentials.extend(receipt.artifact().map(<[u8]>::to_vec)),
            Outcome::Conflict | Outcome::Refused(_) => others += 1,
            Outcome::Unknown(_) => return Err("a use of a value has an unknown outcome with no fault".to_owned()),
        }
    }
    ensure(
        credentials.len() == 1 && others == 1,
        "two concurrent uses of one value did not give one commit and one conflict or refusal",
    )?;
    let credential = credentials.remove(0);
    ensure(
        refusal(&mut run, &auth, &first, &alice, now()).await? == Some(local::Error::Unknown),
        "a consumed value did not refuse",
    )?;
    ensure(
        recover(&mut run, &auth, &issuer, &alice, "alice").await? == credential,
        "the binding does not give the credential of the consumption",
    )?;
    ensure(
        admit(&mut run, &auth, &credential, &alice, "alice", &mut random)
            .await?
            .is_ok(),
        "the remote call of the administrator was not admitted",
    )?;

    // An owner re-bootstrap after the consumption gives a new administrator.
    let second = issue(&mut run, &auth, &mut random, "bob", "i-2").await?;
    let credential_b = enroll(&mut run, &auth, &issuer, &second, &bob, "u-3").await?;
    let third = issue(&mut run, &auth, &mut random, "carol", "i-3").await?;
    ensure(
        refusal(&mut run, &auth, &third, &carol, later()).await? == Some(local::Error::Expired),
        "an expired value of a re-bootstrap did not refuse",
    )?;
    ensure(
        report(&mut run, &auth, now()).await?
            == statuses(&[("alice", BOUND), ("bob", BOUND), ("carol", Status::Valid)]),
        "the report does not give each issue and each consumption",
    )?;

    // The administrator ends the earlier binding with an unlink.
    let fourth = issue(&mut run, &auth, &mut random, "dora", "i-4").await?;
    let dora = Keys::new(10);
    let credential_d = enroll(&mut run, &auth, &issuer, &fourth, &dora, "u-4").await?;
    let (bob_call, dora_call) = (
        (credential_b.as_slice(), &bob, "bob"),
        (credential_d.as_slice(), &dora, "dora"),
    );
    ensure(
        matches!(
            unlink(&mut run, &auth, bob_call, "alice", &mut random).await?,
            Ok(Outcome::Accepted(_))
        ),
        "the unlink of an earlier administrator did not commit",
    )?;
    ensure(
        matches!(
            admit(&mut run, &auth, &credential, &alice, "alice", &mut random).await?,
            Err(local::Error::NotEnrolled)
        ),
        "an unlinked administrator was admitted",
    )?;

    // The last two administrators each unlink their own binding, and each one reads the bindings before either
    // commits. Only the first commits, also when the mark of the journal passes it, so the authority keeps an
    // administrator. The unlink of the last binding refuses.
    let first = propose_unlink(&mut run, &auth, bob_call, "bob", &mut random)
        .await?
        .map_err(refused("an unlink"))?;
    let second = propose_unlink(&mut run, &auth, dora_call, "dora", &mut random)
        .await?
        .map_err(refused("an unlink"))?;
    ensure(
        matches!(submitted(&mut run, first.0, first.1).await?, Outcome::Accepted(_)),
        "the unlink of an administrator by itself did not commit",
    )?;
    run.driver.advance(now());
    run.settle().await?;
    ensure(
        !matches!(submitted(&mut run, second.0, second.1).await?, Outcome::Accepted(_)),
        "two concurrent unlinks of the last two administrators both committed",
    )?;
    ensure(
        matches!(
            unlink(&mut run, &auth, dora_call, "dora", &mut random).await?,
            Err(LAST)
        ),
        "the unlink of the last administrator did not refuse",
    )?;
    ensure(
        report(&mut run, &auth, later()).await?
            == statuses(&[
                ("alice", Status::Consumed { bound: false }),
                ("bob", Status::Consumed { bound: false }),
                ("carol", Status::Ended),
                ("dora", BOUND),
            ]),
        "the report does not give the unlinks and the end of a value",
    )?;

    // A full log drops the oldest issues whose value bound no live administrator, and keeps the live binding of dora.
    for n in 0..local::ISSUES_MAX {
        issue(&mut run, &auth, &mut random, &format!("a-{n}"), &format!("l-{n}")).await?;
    }
    let log = report(&mut run, &auth, now()).await?;
    ensure(
        log.len() == local::ISSUES_MAX && log.first() == Some(&("dora".to_owned(), BOUND)),
        "a full log did not keep the live binding and drop the oldest other issues",
    )
}

pub(super) async fn rebootstrap<S: Subject>(binding: S) -> Checked {
    let crash = crashes(&binding.declaration());
    let (issuer, alice, erin, gina) = (Keys::new(1), Keys::new(2), Keys::new(5), Keys::new(7));
    let mut random = ChaCha20Rng::from_seed([2; 32]);
    let mut run = Run::seeded(binding).await?;
    let auth = open(&mut run, &issuer, authority().value()).await?;
    let first = issue(&mut run, &auth, &mut random, "alice", "r-1").await?;
    let snapshot = run.binding.snapshot();
    let second = issue(&mut run, &auth, &mut random, "bob", "r-2").await?;
    ensure(
        refusal(&mut run, &auth, &first, &alice, now()).await?.is_some(),
        "an owner re-bootstrap did not end the earlier value",
    )?;
    ensure(
        report(&mut run, &auth, now()).await? == statuses(&[("alice", Status::Ended), ("bob", Status::Valid)]),
        "the report does not give the end of the earlier value",
    )?;
    run.restore(&snapshot).await?;
    ensure(
        refusal(&mut run, &auth, &first, &alice, now()).await? == Some(local::Error::Unknown),
        "a restore made a value that a re-bootstrap ended valid again",
    )?;
    ensure(
        refusal(&mut run, &auth, &second, &alice, now()).await? == Some(local::Error::Unknown),
        "a restore kept a value issued after its snapshot",
    )?;
    let third = issue(&mut run, &auth, &mut random, "carol", "r-3").await?;
    enroll(&mut run, &auth, &issuer, &third, &alice, "r-4").await?;

    // A restore keeps the binding of a bootstrap whose issue came after its snapshot, and the log of the snapshot does
    // not name the issue. After the mark passes its creation entry, the report gives the issue with its live binding,
    // and that administrator unlinks the earlier one. The unlink of the last binding still refuses.
    let fresh = open(&mut run, &issuer, "fresh").await?;
    let (yves, zoe) = (Keys::new(8), Keys::new(6));
    let value = issue(&mut run, &fresh, &mut random, "yves", "f-1").await?;
    enroll(&mut run, &fresh, &issuer, &value, &yves, "f-2").await?;
    let snapshot = run.binding.snapshot();
    let value = issue(&mut run, &fresh, &mut random, "zoe", "f-3").await?;
    let credential = enroll(&mut run, &fresh, &issuer, &value, &zoe, "f-4").await?;
    run.restore(&snapshot).await?;
    run.driver.advance(now());
    run.settle().await?;
    let issued = Duration::from_secs(now().estimate().as_secs());
    let row = |name: &str| Issue {
        administrator: account(name),
        issued,
        expires: issued.saturating_add(local::LIFETIME),
        status: BOUND,
    };
    let rows = fresh
        .report(&mut run.binding, now())
        .await
        .map_err(refused("a report"))?
        .issues;
    ensure(
        rows == [row("yves"), row("zoe")],
        "after a restore, the report does not give an issue after the snapshot whose value a client consumed",
    )?;
    let zoe_call = (credential.as_slice(), &zoe, "zoe");
    ensure(
        matches!(
            unlink(&mut run, &fresh, zoe_call, "yves", &mut random).await?,
            Ok(Outcome::Accepted(_))
        ),
        "after a restore, the administrator of an issue after the snapshot did not unlink an earlier one",
    )?;
    ensure(
        report(&mut run, &fresh, now()).await?
            == statuses(&[("yves", Status::Consumed { bound: false }), ("zoe", BOUND)]),
        "the report does not give the unlink after a restore",
    )?;
    ensure(
        matches!(unlink(&mut run, &fresh, zoe_call, "zoe", &mut random).await?, Err(LAST)),
        "after a restore, the unlink of the last administrator did not refuse",
    )?;
    if !crash {
        return Ok(());
    }

    // A re-bootstrap whose response is lost: a lookup shows its commit and no value, and the next issue ends it.
    let (proposal, plan) = auth
        .issue(
            &mut run.binding,
            &grant(),
            account("dave"),
            now(),
            &mut random,
            op("r-5"),
        )
        .await
        .map_err(refused("an issue"))?;
    let operation = proposal.operation().clone();
    let ticket = run.submit(proposal, plan)?;
    run.drive(at_commit("r-5", Fault::LostResponse)).await?;
    ensure(
        matches!(run.outcome(ticket).await?, Outcome::Unknown(_)),
        "a lost response gave an outcome",
    )?;
    run.start().await?;
    ensure(
        matches!(run.lookup(&operation).await?, Lookup::Committed(receipt) if receipt.artifact().is_none()),
        "the lookup of a lost re-bootstrap did not show its commit with no value",
    )?;
    let fifth = issue(&mut run, &auth, &mut random, "erin", "r-6").await?;
    ensure(
        report(&mut run, &auth, now()).await?.ends_with(&statuses(&[
            ("carol", BOUND),
            ("dave", Status::Ended),
            ("erin", Status::Valid),
        ])),
        "the next issue did not end the value of a lost re-bootstrap",
    )?;

    // A bootstrap that read the value before a re-bootstrap ended it crashes before its commit. Its fact holds, so
    // the start keeps its entry, and the restore does not complete it.
    let snapshot = run.binding.snapshot();
    let (proposal, plan) = propose(&mut run, &auth, &issuer, &fifth, &erin, "r-7").await?;
    issue(&mut run, &auth, &mut random, "frank", "r-8").await?;
    run.submit(proposal, plan)?;
    run.drive(at_commit("r-7", Fault::CrashBeforeCommit)).await?;
    run.start().await?;
    run.restore(&snapshot).await?;
    ensure(
        refusal(&mut run, &auth, &fifth, &erin, now()).await? == Some(local::Error::Unknown),
        "a restore made a value that a re-bootstrap ended valid again",
    )?;
    // The owner issues a new value for the same administrator, which an issue refuses while a binding is live.
    issue(&mut run, &auth, &mut random, "erin", "r-9").await?;

    // A bootstrap of a value that the snapshot does not hold lands, and its response is lost.
    let snapshot = run.binding.snapshot();
    let seventh = issue(&mut run, &auth, &mut random, "gina", "r-10").await?;
    let (proposal, plan) = propose(&mut run, &auth, &issuer, &seventh, &gina, "r-11").await?;
    run.submit(proposal, plan)?;
    run.drive(at_commit("r-11", Fault::LostResponse)).await?;
    run.restore(&snapshot).await?;
    // The restore completed nothing: an issue refuses an administrator with a live binding.
    let eighth = issue(&mut run, &auth, &mut random, "gina", "r-12").await?;

    // A bootstrap of a value that the snapshot holds lands, and its response is lost. The restore completes it, and the
    // client proves the possession of its stored key with the credential of the binding.
    let snapshot = run.binding.snapshot();
    let (proposal, plan) = propose(&mut run, &auth, &issuer, &eighth, &gina, "r-13").await?;
    let operation = proposal.operation().clone();
    run.submit(proposal, plan)?;
    run.drive(at_commit("r-13", Fault::LostResponse)).await?;
    run.restore(&snapshot).await?;
    let credential = recover(&mut run, &auth, &issuer, &gina, "gina").await?;
    ensure(
        admit(&mut run, &auth, &credential, &gina, "gina", &mut random)
            .await?
            .is_ok(),
        "the client of a completed bootstrap did not prove the possession of its key",
    )?;
    ensure(
        matches!(run.lookup(&operation).await?, Lookup::Committed(_)),
        "a lookup did not report the completed bootstrap",
    )?;
    ensure(
        report(&mut run, &auth, now()).await?.last() == Some(&("gina".to_owned(), BOUND)),
        "the report does not give the completed bootstrap",
    )
}
