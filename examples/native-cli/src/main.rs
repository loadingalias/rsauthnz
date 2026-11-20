//! A headless CLI on a local authority of rsauthnz. The local owner opens the authority and issues a one-use
//! bootstrap value. The CLI enrolls its key in custody and submits the value with its public key. The CLI then is the
//! first administrator, with a CLI credential. Each later call proves the possession of the key over a one-use
//! challenge. The example also shows two failures: a second bootstrap with the same value, and a replayed proof.
//!
//! One process is the local owner, the authority, and the CLI. The store is the memory binding of
//! `rsauthnz-conformance`, so a restart loses each record. The keys are key files of `FileCustody` in a new directory
//! under the temporary directory. The example deletes the keys and removes the directory at its end.
//!
//! ```sh
//! cargo run --locked -p native-cli --features native-custody
//! ```

// std's OS generator. Review this gate at each move of the pinned nightly (AGENTS.md toolchain review).
#![feature(random)]

use core::mem::DropGuard;
use core::pin::pin;
use core::random::Rng as _;
use core::task::{Context, Poll, Waker};
use core::time::Duration;
use std::path::PathBuf;
use std::random::SystemRng;
use std::time::{SystemTime, UNIX_EPOCH};
use std::{env, fs, process};

use rsauthnz::cbor::Value;
use rsauthnz::cli::{self, Call, Challenge};
use rsauthnz::credential::Serial;
use rsauthnz::crypto::Algorithm;
use rsauthnz::custody::{Custody, FileCustody, Isolation, KeyId};
use rsauthnz::id::Id;
use rsauthnz::limits::Limits;
use rsauthnz::local::{self, Authority, Bootstrap, HostGrant, Offer};
use rsauthnz::store::driver::{Answer, Driver, Effect, Output, Plan};
use rsauthnz::store::{Kind, Profile, Store as _};
use rsauthnz::time::{Reading, ReadingSource};
use rsauthnz::transition::{OperationId, Outcome, Proposal};
use rsauthnz_conformance::memory::{Memory, Schedule};
use rsauthnz_conformance::suite::execute;
use rscrypto::ChaCha20Rng;

type Failure = Box<dyn core::error::Error>;

fn main() -> Result<(), Failure> {
    // The seed of the generator comes from the entropy source of the OS.
    let Ok(random) = ChaCha20Rng::try_generate_with(|seed| {
        SystemRng.fill_bytes(seed);
        Ok::<_, !>(())
    });
    let dir = env::temp_dir().join(format!("rsauthnz-native-cli-{}", process::id()));
    journey(dir, random)
}

/// The output of `future`. The futures of the memory binding are ready at their first poll.
fn ready<F: Future>(future: F) -> F::Output {
    match pin!(future).poll(&mut Context::from_waker(Waker::noop())) {
        Poll::Ready(output) => Some(output),
        Poll::Pending => None,
    }
    .expect("the memory binding does no I/O")
}

/// Gives each effect of the driver to the memory binding, until the driver waits. The clock of a commit is a fresh
/// reading of the system clock.
fn settle(memory: &mut Memory, driver: &mut Driver) -> Result<(), Failure> {
    while let Some(effect) = driver.effect() {
        let output = match effect {
            Effect::Clock => Output::Clock(clock()?),
            effect => ready(execute(memory, effect)),
        };
        driver.give(output)?;
    }
    Ok(())
}

/// A reading of the system clock, with the bound of its time source: here one second.
fn clock() -> Result<Reading, Failure> {
    let since_epoch = SystemTime::now().duration_since(UNIX_EPOCH)?;
    Ok(Reading::new(
        since_epoch,
        Some(Duration::from_secs(1)),
        ReadingSource::SystemClock,
    ))
}

/// The outcome of the commit of `proposal` with `plan`.
fn commit(memory: &mut Memory, driver: &mut Driver, (proposal, plan): (Proposal, Plan)) -> Result<Outcome, Failure> {
    let ticket = driver.submit(proposal, plan)?;
    settle(memory, driver)?;
    match driver.take(ticket) {
        Some(Answer::Outcome(outcome)) => Ok(outcome),
        answer => Err(format!("the commit gave {answer:?}").into()),
    }
}

/// The artifact that the receipt of an accepted commit gives.
fn artifact(outcome: Outcome) -> Result<Vec<u8>, Failure> {
    match outcome {
        Outcome::Accepted(receipt) => Ok(receipt.artifact().ok_or("the receipt has no artifact")?.to_vec()),
        outcome => Err(format!("the commit did not land: {outcome:?}").into()),
    }
}

/// The journey, with its key files in the new directory `dir`, and the random values of `random`. It removes the
/// directory at its end, also after a failure.
#[expect(clippy::print_stdout, reason = "the example prints each step of its journey")]
fn journey(dir: PathBuf, mut random: ChaCha20Rng) -> Result<(), Failure> {
    // A host reads its clock for each request, with the bound of its time source. This journey takes one reading for
    // its requests, and a fresh one for each commit.
    let now = clock()?;
    let limits = Limits::default();

    fs::create_dir(&dir)?;
    let dir = DropGuard::new(dir, |dir| {
        fs::remove_dir_all(dir).expect("the example can remove its key directory")
    });
    let custody = FileCustody::open(&*dir, Isolation::User)?;
    let mut memory = Memory::new(Schedule::None);
    let mut driver = Driver::new(Profile::new(memory.declaration())?, limits)?;
    driver.start(now);
    settle(&mut memory, &mut driver)?;
    println!("The store is the memory binding: a restart of this process loses each record.");

    // 1. The local owner opens the authority, with its issuer key in custody. Only the host builds the grant.
    let issuer = custody.enroll(KeyId::random(&mut random), Algorithm::MlDsa65Ed25519, &mut random)?;
    let grant = HostGrant {
        owner: Id::new("acme", "owner")?,
        origin: Id::new("acme", "build-app")?,
    };
    let id = Id::new("acme", "auth")?;
    let authority = ready(Authority::open(&mut memory, &grant, id.clone(), issuer.clone(), limits))?;
    let origin = &grant.origin;
    println!("1. The local owner opened the authority {id} for the origin {origin}.");

    // 2. The owner issues a value for the administrator `alice`, and gives its text to the CLI by a local path. The
    // text is a secret: do not print it, log it, or put it in an argument.
    let alice = Id::new("acme", "alice")?;
    let operation = OperationId::new(b"issue-1")?;
    let issue = ready(authority.issue(&mut memory, &grant, alice.clone(), now, &mut random, operation))?;
    let text = String::from_utf8(artifact(commit(&mut memory, &mut driver, issue)?)?)?;
    let minutes = local::LIFETIME.as_secs() / 60;
    println!("2. The owner issued a one-use bootstrap value for {alice}. It is valid for {minutes} minutes.");

    // 3. The CLI enrolls its key in custody before it submits the value. Thus a bootstrap that commits binds a key
    // that the CLI has, also if the CLI does not get the response.
    let key = custody.enroll(KeyId::random(&mut random), Algorithm::MlDsa65Ed25519, &mut random)?;
    let holder: [u8; 1984] = key.public_key().as_slice().try_into()?;
    println!("3. The CLI enrolled its key in custody. {}", custody.report().owner);

    // 4. The CLI submits the text and its public key. The authority signs the CLI credential with the issuer key.
    let value = Bootstrap::parse(&text)?;
    let serial = Serial(driver.allocate(Kind::Credential)?);
    let pending = ready(authority.bootstrap(&mut memory, &value, &holder, serial, now))?;
    let signature = custody.sign(&issuer, Algorithm::MlDsa65Ed25519, &pending.to_be_signed(), &mut random)?;
    let bootstrap = pending.finish(&signature, OperationId::new(b"bootstrap-1")?)?;
    let credential = artifact(commit(&mut memory, &mut driver, bootstrap)?)?;
    let bytes = credential.len();
    println!("4. The authority bound {alice} as the first administrator, with a CLI credential of {bytes} bytes.");

    // 5. The value is one-use, so a second bootstrap with it refuses.
    let serial = Serial(driver.allocate(Kind::Credential)?);
    match ready(authority.bootstrap(&mut memory, &value, &holder, serial, now)) {
        Err(local::Failure::Refused(error @ local::Error::Unknown)) => {
            println!("5. A second bootstrap with the same value refused: {error}.");
        }
        Err(error) => return Err(error.into()),
        Ok(_) => return Err("a second bootstrap with the same value did not refuse".into()),
    }

    // 6. The first call. The authority issues a challenge. The CLI proves the possession of its key over the
    // challenge, the operation, and the request. It sends the credential, the proof, and the call.
    let operation = OperationId::new(b"challenge-1")?;
    // A binding with an open challenge offers it, and nothing commits. This binding has none, so the authority
    // offers the proposal of a new one.
    let challenge = match ready(authority.challenge(&mut memory, &alice, now, &mut random, operation))? {
        Offer::Open(challenge) => challenge,
        Offer::New(proposal, plan) => {
            let challenge = artifact(commit(&mut memory, &mut driver, (proposal, plan))?)?;
            Challenge::from_bytes(challenge.as_slice().try_into()?)
        }
    };
    let first = Call::new(challenge, OperationId::new(b"call-1")?, &Value::Text("status"), limits)?;
    let proof = cli::prove(&custody, &key, &credential, origin, &first, now, &mut random)?;
    // The authority makes the call again from what it received. One commit admits it and consumes the challenge.
    let (proposal, admission) = ready(authority.admit(&mut memory, &credential, &proof, &first, now, &mut random))?;
    let outcome = commit(&mut memory, &mut driver, (proposal, Plan::default()))?;
    let admitted = admission.release(&outcome).ok_or("call 1 was not admitted")?;
    let administrator = admitted.administrator();
    println!("6. Call 1 (status) proved the possession of the CLI key. The authority admitted it for {administrator}.");

    // 7. A replay of the proof refuses, because the commit of call 1 consumed its challenge.
    match ready(authority.admit(&mut memory, &credential, &proof, &first, now, &mut random)) {
        Err(local::Failure::Refused(error @ local::Error::Challenge)) => {
            println!("7. A replay of the proof of call 1 refused: {error}.");
        }
        Err(error) => return Err(error.into()),
        Ok(_) => return Err("a replay of the proof of call 1 did not refuse".into()),
    }

    // 8. The next call uses the challenge that the commit of call 1 wrote, with no new issue.
    let challenge = admitted.next();
    let second = Call::new(challenge, OperationId::new(b"call-2")?, &Value::Text("deploy"), limits)?;
    let proof = cli::prove(&custody, &key, &credential, origin, &second, now, &mut random)?;
    let (proposal, admission) = ready(authority.admit(&mut memory, &credential, &proof, &second, now, &mut random))?;
    let outcome = commit(&mut memory, &mut driver, (proposal, Plan::default()))?;
    admission.release(&outcome).ok_or("call 2 was not admitted")?;
    println!("8. Call 2 (deploy) used the challenge that call 1 gave, and the authority admitted it.");

    // 9. Cleanup: delete each key from custody, then remove the empty directory.
    custody.delete(key.id())?;
    custody.delete(issuer.id())?;
    fs::remove_dir(DropGuard::dismiss(dir))?;
    println!("9. The CLI and the authority deleted their keys, and the example removed its key directory.");
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    /// The journey runs to its end on this host. A second bootstrap with the same value refuses with
    /// `local::Error::Unknown`, a replayed proof refuses with `local::Error::Challenge`, and no key file stays.
    #[test]
    fn the_journey_refuses_a_second_bootstrap_and_a_replay_and_leaves_no_key_file() {
        let dir = env::temp_dir().join(format!("rsauthnz-native-cli-test-{}", process::id()));
        journey(dir.clone(), ChaCha20Rng::from_seed([7; 32])).unwrap();
        assert!(!dir.exists());
    }
}
