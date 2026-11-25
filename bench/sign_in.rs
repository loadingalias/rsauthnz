//! The ES256 sign-in verification beside the rscrypto verification of the same signature.
//!
//! `primitive` builds the P-256 key from its SEC1 bytes, reads the DER signature, and verifies it. `verify` verifies a
//! parsed assertion against the records of its read (`SignInRecords::verify`), with no store and no driver. Both sides
//! start from stored bytes, so neither one holds a prepared key. `parse` reads the `AuthenticationResponseJSON`, and
//! `read` reads the records from the memory binding after the check of the challenge tag. These two cells have no bar.
//! Nothing commits, so each iteration verifies the same assertion.
//!
//! `overhead` runs `primitive` and `verify` in each sample and gives the difference of their times. A change of the
//! speed of the host during the run then changes both sides of a sample. The records of a sample are read before its
//! timers start, and each sign-in drops after them, because a host gives it to `SignIn::open`.
//!
//! Each interval has a confidence level of 97.5%. An interval of `overhead / primitive` from the bounds of both
//! intervals thus has a level of at least 95%.

#[path = "../tests/passkey/authenticator.rs"]
#[expect(
    dead_code,
    reason = "the benchmark uses a part of the test authenticator of the core"
)]
#[expect(
    clippy::panic,
    reason = "the test authenticator stops on a fixture that it cannot make"
)]
mod authenticator;

use core::hint::black_box;
use core::pin::pin;
use core::task::{Context, Poll, Waker};
use core::time::Duration;
use std::time::Instant;

use criterion::{BatchSize, Criterion};
use rsauthnz::crypto::Algorithm;
use rsauthnz::id::Id;
use rsauthnz::limits::Limits;
use rsauthnz::passkey::{Assertion, Decision, RelyingParty, Response, User, UserHandle};
use rsauthnz::store::driver::{Answer, Driver, Plan};
use rsauthnz::store::{Profile, Store as _};
use rsauthnz::time::{Reading, ReadingSource};
use rsauthnz::transition::{Outcome, Proposal, Receipt};
use rsauthnz_conformance::memory::{Memory, Schedule};
use rsauthnz_conformance::suite;
use rscrypto::auth::{EcdsaP256PublicKey, EcdsaP256SecretKey, EcdsaP256Signature};
use rscrypto::{ChaCha20Rng, Sha256};

use authenticator::{Get, Passkey, Registration};

const RP_ID: &str = "app.example";
const ORIGIN: &str = "https://app.example";
const HANDLE: [u8; 32] = [9; 32];
/// The seed of the key of the passkey.
const SEED: u8 = 1;

/// The reading at `seconds` past a fixed start, with an uncertainty of one second.
fn at(seconds: u64) -> Reading {
    Reading::new(
        Duration::from_secs(1_800_000_000 + seconds),
        Some(Duration::from_secs(1)),
        ReadingSource::Caller,
    )
}

/// The output of `future`. The futures of the memory binding are ready at their first poll.
fn ready<F: Future>(future: F) -> F::Output {
    match pin!(future).poll(&mut Context::from_waker(Waker::noop())) {
        Poll::Ready(output) => Some(output),
        Poll::Pending => None,
    }
    .expect("the memory binding does no I/O")
}

/// Executes each effect of `driver` on `memory` until it has none.
fn run(memory: &mut Memory, driver: &mut Driver) {
    while let Some(effect) = driver.effect() {
        let output = ready(suite::execute(memory, effect));
        driver.give(output).expect("the driver takes the output");
    }
}

/// The receipt of the accepted commit of `proposal`.
fn commit(memory: &mut Memory, driver: &mut Driver, (proposal, plan): (Proposal, Plan)) -> Receipt {
    let ticket = driver.submit(proposal, plan).expect("a submission");
    run(memory, driver);
    match driver.take(ticket) {
        Some(Answer::Outcome(Outcome::Accepted(receipt))) => Some(receipt),
        _ => None,
    }
    .expect("an accepted commit")
}

fn main() {
    let mut memory = Memory::new(Schedule::None);
    let profile = Profile::new(memory.declaration()).expect("a profile");
    let mut driver = Driver::new(profile, Limits::default()).expect("a driver");
    driver.start(at(0));
    run(&mut memory, &mut driver);
    let authority = Id::new("acme", "auth").expect("an identifier");
    let rp = RelyingParty::new(authority, RP_ID, ORIGIN, "Acme", [3; 32], Limits::default()).expect("a relying party");
    let mut random = ChaCha20Rng::from_seed([5; 32]);

    // One ES256 passkey of one account, as a synchronized passkey registers it: the counter stays zero.
    let account = Id::new("acme", "alice").expect("an identifier");
    let user = User {
        account: &account,
        handle: UserHandle::from_bytes(HANDLE),
        name: "user@app.example",
        display_name: "User",
    };
    let start = ready(rp.start(
        &mut memory,
        &user,
        Decision::SignUp(&[]),
        at(0),
        &mut random,
        &mut driver,
    ))
    .expect("a start");
    let options = commit(&mut memory, &mut driver, start);
    let challenge = authenticator::challenge(options.artifact().expect("the options"));
    let passkey = Passkey::new(Algorithm::Es256, -7, SEED);
    let response = Response::parse(&Registration::new(&passkey, RP_ID, ORIGIN, challenge).json()).expect("a response");
    let registration = ready(rp.finish(&mut memory, &response, at(1), &mut driver)).expect("a finish");
    commit(
        &mut memory,
        &mut driver,
        registration.propose(Decision::SignUp(&[])).expect("a proposal"),
    );

    // One assertion for a challenge that is later than the replay floor of the start.
    let challenge = authenticator::challenge(&rp.sign_in_options(at(10), &mut random).expect("the options"));
    let get = Get::new(&passkey, RP_ID, ORIGIN, challenge, HANDLE);
    let json = get.json();
    let (client_data, data, signature) = get.parts();
    let message = [&data[..], &Sha256::digest(&client_data)].concat();
    let sec1 = EcdsaP256SecretKey::from_bytes([SEED; 32])
        .expect("a P-256 scalar")
        .public_key()
        .to_sec1_bytes();

    let mut primitive = || {
        let key = EcdsaP256PublicKey::from_sec1_bytes(black_box(&sec1)).expect("a P-256 point");
        let signature = EcdsaP256Signature::from_der(black_box(&signature)).expect("a DER signature");
        key.verify(black_box(&message), &signature)
            .expect("the signature verifies");
    };
    let assertion = Assertion::parse(&json).expect("an assertion");
    let read = |memory: &mut Memory, assertion: Assertion| {
        ready(rp.sign_in_read(memory, assertion, at(11))).expect("the records")
    };

    let mut criterion = Criterion::default().confidence_level(0.975).configure_from_args();
    let mut group = criterion.benchmark_group("sign_in_es256");
    group.bench_function("primitive", |bencher| bencher.iter(&mut primitive));
    group.bench_function("parse", |bencher| {
        bencher.iter(|| Assertion::parse(black_box(&json)).expect("an assertion"));
    });
    group.bench_function("read", |bencher| {
        bencher.iter_batched(
            || assertion.clone(),
            |assertion| read(&mut memory, black_box(assertion)),
            BatchSize::SmallInput,
        );
    });
    group.bench_function("verify", |bencher| {
        bencher.iter_batched(
            || read(&mut memory, assertion.clone()),
            |records| black_box(records).verify().expect("a verified sign-in"),
            BatchSize::SmallInput,
        );
    });
    group.bench_function("overhead", |bencher| {
        bencher.iter_custom(|iterations| {
            let count = usize::try_from(iterations).expect("a count that this host can hold");
            let records: Vec<_> = (0..count).map(|_| read(&mut memory, assertion.clone())).collect();
            let mut verified = Vec::with_capacity(count);
            let started = Instant::now();
            for _ in 0..iterations {
                primitive();
            }
            let primitive = started.elapsed();
            let started = Instant::now();
            for each in records {
                verified.push(black_box(each).verify().expect("a verified sign-in"));
            }
            let verify = started.elapsed();
            drop(verified);
            verify.saturating_sub(primitive)
        });
    });
    group.finish();
    criterion.final_summary();
}
