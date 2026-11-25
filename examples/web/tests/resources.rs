//! The resource runs of the web example on the memory binding, at the declared limits of the host: a flood of
//! malformed input, a flood of sign-in verifications, the latency of a legitimate sign-in during that flood, and the
//! retained records at the commit budget. `tests/limits.rs` holds the two other items: the store that does not answer,
//! and the shutdown with a request in flight.
//!
//! A run measures, so it does not run with the other tests. Run each one alone, in a release build, on a quiet host:
//!
//! ```sh
//! cargo xtask test --release -p web --run-ignored only --no-capture -E 'test(<name>)'
//! ```
//!
//! Each run first prints its risk, its budget, its bounds, and its stop condition. Then it prints its results.

// `cfg(test)` marks the shared test authenticator as test code for Clippy.
#[cfg(test)]
#[path = "../../../tests/passkey/authenticator.rs"]
#[expect(dead_code, reason = "the runs use a part of the test authenticator of the core")]
mod authenticator;
#[path = "support/load.rs"]
mod load;
#[expect(dead_code, reason = "the runs use a part of the support of the journeys")]
mod support;

use core::net::SocketAddr;
use core::time::Duration;
use std::sync::Arc;

use authenticator::{Get, Passkey, Registration};
use axum::body::Bytes;
use http::StatusCode;
use load::{Client, Host, ORIGIN, Sample, ending, percentile, records, times};
use rsauthnz::crypto::Algorithm;
use rsauthnz_conformance::memory::{Memory, Schedule};
use support::{Browser, Site};

/// The most time of the 99th percentile of a refusal, and of a legitimate sign-in during a flood. Each run declares
/// its bound before it starts.
const P99_MAX: Duration = Duration::from_millis(50);

/// The offered rate of a flood of sign-in verifications, in requests in each second. One thread verifies fewer.
const FLOOD_RATE: u32 = 40_000;

/// A new ES256 passkey of the test authenticator.
fn passkey(seed: u8) -> Arc<Passkey> {
    Arc::new(Passkey::new(Algorithm::Es256, -7, seed))
}

/// Signs up the account `name` with `passkey`, and gives its user handle.
async fn sign_up(client: &Client, name: &str, passkey: &Passkey) -> [u8; 32] {
    let body = format!(r#"{{"name":"{name}"}}"#);
    let (status, options) = client.post("/sign-up/options", ORIGIN, body.into()).await;
    assert_eq!(status, StatusCode::OK);
    let json = Registration::new(passkey, "localhost", ORIGIN, authenticator::challenge(&options)).json();
    assert_eq!(
        client.post("/sign-up/finish", ORIGIN, json.into()).await.0,
        StatusCode::OK
    );
    support::user_id(&options)
}

/// The body of a sign-in of `passkey` of the account `handle`, for new options of the site.
async fn assertion(client: &Client, passkey: &Passkey, handle: [u8; 32]) -> Bytes {
    let (status, options) = client.post("/sign-in/options", ORIGIN, Bytes::from_static(b"{}")).await;
    assert_eq!(status, StatusCode::OK);
    Get::new(passkey, "localhost", ORIGIN, authenticator::challenge(&options), handle)
        .json()
        .into()
}

/// One complete sign-in of `passkey` of the account `handle`: the status of its finish.
async fn sign_in(client: &Client, passkey: &Passkey, handle: [u8; 32]) -> StatusCode {
    let body = assertion(client, passkey, handle).await;
    client.post("/sign-in/finish", ORIGIN, body).await.0
}

/// The body of a sign-in with the credential of `passkey` and a signature of another key. The site verifies the
/// signature, and then refuses it.
async fn forged(client: &Client, passkey: &Passkey, handle: [u8; 32]) -> Bytes {
    let mut forger = Passkey::new(Algorithm::Es256, -7, 200);
    forger.id.clone_from(&passkey.id);
    assertion(client, &forger, handle).await
}

/// A load of 2,000 requests of one kind of malformed input in each second, for 3 seconds.
fn malformed(
    client: &Client,
    path: &'static str,
    origin: &'static str,
    body: &Bytes,
) -> impl Future<Output = Vec<Sample>> {
    let (client, body) = (client.clone(), body.clone());
    load::load(2_000, Duration::from_secs(3), move |_| {
        let (client, body) = (client.clone(), body.clone());
        async move { client.post(path, origin, body).await.0 }
    })
}

/// A flood on its own thread and connection: `FLOOD_RATE` sign-ins with `body` in each second for `time`.
fn flood(address: SocketAddr, time: Duration, body: Bytes) -> std::thread::JoinHandle<Vec<Sample>> {
    std::thread::spawn(move || {
        let runtime = tokio::runtime::Builder::new_current_thread()
            .enable_io()
            .enable_time()
            .build()
            .expect("a runtime");
        runtime.block_on(async move {
            let client = Client::connect(address).await;
            load::load(FLOOD_RATE, time, |_| {
                let (client, body) = (client.clone(), body.clone());
                async move { client.post("/sign-in/finish", ORIGIN, body).await.0 }
            })
            .await
        })
    })
}

/// Contract: malformed input and input over a limit get their refusals within the declared time, and they leave no
/// record.
#[tokio::test]
#[ignore = "a resource run: run it alone, in a release build, on a quiet host"]
async fn a_flood_of_malformed_input_gets_its_refusals_and_keeps_no_state() {
    println!("risk: malformed input costs work of the application, or leaves state");
    println!("budget: 4 kinds of input, 2,000 requests of each kind in each second, for 3 seconds");
    println!(
        "bounds: each request gets its refusal; the 99th percentile of each kind is at most {P99_MAX:?}; no new record"
    );
    println!("stop: one result");
    let memory = Memory::new(Schedule::None).with_retention(web::RETENTION);
    let host = Host::start(memory.clone());
    let client = Client::connect(host.address).await;
    let before = records(&memory).await;

    let large = Bytes::from(vec![b' '; web::BODY_BYTES_MAX + 1024]);
    let kinds: [(&str, &'static str, &'static str, Bytes, &[u16]); 4] = [
        ("a body over 16 KiB", "/sign-up/options", ORIGIN, large, &[413]),
        (
            "a request of another site",
            "/sign-in/finish",
            "https://attacker.example",
            Bytes::from_static(b"{}"),
            &[403],
        ),
        (
            "a sign-in that is no assertion",
            "/sign-in/finish",
            ORIGIN,
            Bytes::from_static(br#"{"id":"#),
            &[403],
        ),
        // This one waits for the application thread, which refuses it before it reads the store.
        (
            "a sign-up that is no JSON",
            "/sign-up/options",
            ORIGIN,
            Bytes::from_static(b"{"),
            &[403, 503],
        ),
    ];
    let run = |kind: usize| malformed(&client, kinds[kind].1, kinds[kind].2, &kinds[kind].3);
    let (a, b, c, d) = tokio::join!(run(0), run(1), run(2), run(3));
    for ((name, _, _, _, expected), samples) in kinds.iter().zip([a, b, c, d]) {
        assert_eq!(samples.len(), 6_000, "{name}");
        let other: Vec<_> = samples
            .iter()
            .filter(|(status, _)| !expected.contains(&status.as_u16()))
            .collect();
        assert!(
            other.is_empty(),
            "{name}: {} other responses, first {:?}",
            other.len(),
            other[0]
        );
        let times = times(&samples, |_| true);
        let (p50, p99) = (percentile(&times, 50), percentile(&times, 99));
        println!("result: {name}: {} refusals, p50 {p50:?}, p99 {p99:?}", samples.len());
        assert!(p99 <= P99_MAX, "{name}: p99 {p99:?}");
    }
    assert_eq!(records(&memory).await, before, "the flood left a record");
    println!("result: {before} records before and after the flood");
    host.stop().await.expect("a joined shutdown");
}

/// Contract: a flood of sign-in verifications with one credential holds at most its share of the queue. Each sign-in
/// over the share gets `503` within the declared time. The flood leaves no record, and the credential signs in after
/// it.
#[tokio::test]
#[ignore = "a resource run: run it alone, in a release build, on a quiet host"]
async fn a_flood_of_sign_in_verifications_stays_in_its_share_and_keeps_no_state() {
    println!("risk: a flood of signature checks with one credential fills the queue, or leaves state");
    println!("budget: {FLOOD_RATE} sign-ins with a wrong signature in each second, for 3 seconds");
    println!("bounds: each response is 403 or 503; the 99th percentile of a 503 is at most {P99_MAX:?}; no new record");
    println!("stop: one result");
    let memory = Memory::new(Schedule::None).with_retention(web::RETENTION);
    let host = Host::start(memory.clone());
    let client = Client::connect(host.address).await;
    let attacker = passkey(1);
    let handle = sign_up(&client, "attacker", &attacker).await;
    assert_eq!(sign_in(&client, &attacker, handle).await, StatusCode::OK);
    let body = forged(&client, &attacker, handle).await;
    let before = records(&memory).await;

    let samples = flood(host.address, Duration::from_secs(3), body)
        .join()
        .expect("the flood");
    let (verified, over) = (
        times(&samples, |status| status == StatusCode::FORBIDDEN),
        times(&samples, |status| status == StatusCode::SERVICE_UNAVAILABLE),
    );
    assert_eq!(
        verified.len() + over.len(),
        samples.len(),
        "a response that is not 403 or 503"
    );
    println!(
        "result: {} sign-ins verified and refused (403), p50 {:?}, p99 {:?}",
        verified.len(),
        percentile(&verified, 50),
        percentile(&verified, 99)
    );
    println!(
        "result: {} sign-ins over the share (503), p50 {:?}, p99 {:?}",
        over.len(),
        percentile(&over, 50),
        percentile(&over, 99)
    );
    assert!(
        !verified.is_empty() && !over.is_empty(),
        "the flood did not reach the share"
    );
    assert!(percentile(&over, 99) <= P99_MAX);
    assert_eq!(records(&memory).await, before, "the flood left a record");
    println!("result: {before} records before and after the flood");
    // Each place of the credential is free again.
    assert_eq!(sign_in(&client, &attacker, handle).await, StatusCode::OK);
    host.stop().await.expect("a joined shutdown");
}

/// Contract: during a flood of sign-in verifications with one credential, each sign-in of another account gets its
/// session, within the declared time.
#[tokio::test]
#[ignore = "a resource run: run it alone, in a release build, on a quiet host"]
async fn a_legitimate_sign_in_keeps_its_latency_during_a_flood_of_verifications() {
    println!("risk: a flood of signature checks with one credential delays the sign-in of another account");
    println!(
        "budget: the flood of {FLOOD_RATE} sign-ins in each second for 12 seconds; 10 legitimate sign-ins in each second for 10 seconds"
    );
    println!(
        "bounds: each legitimate sign-in gets 200; its 99th percentile, from the planned start to the session, is at most {P99_MAX:?}"
    );
    println!("stop: one result");
    let host = Host::start(Memory::new(Schedule::None).with_retention(web::RETENTION));
    let client = Client::connect(host.address).await;
    let (attacker, tenant) = (passkey(1), passkey(2));
    let attacker_handle = sign_up(&client, "attacker", &attacker).await;
    let tenant_handle = sign_up(&client, "tenant", &tenant).await;
    assert_eq!(sign_in(&client, &tenant, tenant_handle).await, StatusCode::OK);
    let body = forged(&client, &attacker, attacker_handle).await;

    let flood = flood(host.address, Duration::from_secs(12), body);
    tokio::time::sleep(Duration::from_secs(1)).await;
    let samples = load::load(10, Duration::from_secs(10), |_| {
        let (client, tenant) = (client.clone(), Arc::clone(&tenant));
        async move { sign_in(&client, &tenant, tenant_handle).await }
    })
    .await;
    let flood = flood.join().expect("the flood");

    let over = times(&flood, |status| status == StatusCode::SERVICE_UNAVAILABLE).len();
    println!(
        "result: the flood: {} sign-ins, {over} of them over the share (503)",
        flood.len()
    );
    assert!(over > 0, "the flood did not reach the share");
    let signed_in = times(&samples, |status| status == StatusCode::OK);
    let (p50, p99) = (percentile(&signed_in, 50), percentile(&signed_in, 99));
    println!(
        "result: {} of {} legitimate sign-ins got a session, p50 {p50:?}, p99 {p99:?}, most {:?}",
        signed_in.len(),
        samples.len(),
        percentile(&signed_in, 100)
    );
    assert_eq!((signed_in.len(), samples.len()), (100, 100));
    assert!(p99 <= P99_MAX, "p99 {p99:?}");
    host.stop().await.expect("a joined shutdown");
}

/// Contract: at the commit budget, the records with an end stay within their limit, and each one leaves after its
/// end.
#[tokio::test]
#[ignore = "a resource run: run it alone, in a release build, on a quiet host"]
async fn the_records_with_an_end_stay_within_their_limit_at_the_commit_budget() {
    // A sign-in keeps a replay record for 302 s, a session for 30 minutes, and an audit and an outcome record for the
    // retention of 1 hour. A pass removes a record at most 5 s after its end. The start and the burst add 100.
    const SIGN_INS: usize = 20;
    const LIMIT: usize = SIGN_INS * (302 + 1_800 + 2 * 3_600) + SIGN_INS * 4 * 5 + 100;
    println!("risk: records with an end stay in the store after their end");
    println!(
        "budget: {SIGN_INS} sign-ins in each second of the host clock for 5,400 seconds, then 2 hours with no sign-in"
    );
    println!("bounds: at most {LIMIT} records with an end at each time; none of them 2 hours after the last sign-in");
    println!("stop: one result");
    let memory = Memory::new(Schedule::None).with_retention(web::RETENTION);
    let (site, _app) = Site::on(ORIGIN, 1_800_000_000, memory.clone(), memory.clone());
    site.advance(10);
    let passkey = Passkey::new(Algorithm::Ed25519, -8, 1);
    let handle = site
        .register(
            &mut Browser::default(),
            ("/sign-up/options", "/sign-up/finish"),
            br#"{"name":"alice"}"#,
            &passkey,
        )
        .await;

    let mut most = 0;
    for second in 1..=5_400 {
        site.advance(1);
        for _ in 0..SIGN_INS {
            site.sign_in(&mut Browser::default(), &passkey, handle).await;
        }
        if second % 300 == 0 {
            let retained = ending(&memory).await;
            most = most.max(retained);
            println!("result: after {second} s: {retained} records with an end");
            assert!(retained <= LIMIT, "{retained} records after {second} s");
        }
    }
    // Each request with no session comes after the pass of its second.
    site.advance(7_200);
    let mut passes = 0;
    while ending(&memory).await > 0 {
        passes += 1;
        // The largest kind has 72,060 records, and 282 passes of 256 records remove them.
        assert!(passes <= 20, "records with an end stay after {} passes", passes * 20);
        for _ in 0..20 {
            site.advance(1);
            assert_eq!(
                site.send(&mut Browser::default(), "GET", "/account", b"").await.status,
                StatusCode::FORBIDDEN
            );
        }
    }
    println!("result: the most records with an end: {most} of {LIMIT}");
    println!("result: no record with an end after {} passes", passes * 20);
}
