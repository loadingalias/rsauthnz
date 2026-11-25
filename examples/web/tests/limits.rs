//! The limits of the host of the web example: the queue of the application thread, the share of a credential, the
//! commit budget, the account bound, the expiry pass, and the joined shutdown.

// `cfg(test)` marks the shared test authenticator as test code for Clippy.
#[cfg(test)]
#[path = "../../../tests/passkey/authenticator.rs"]
#[expect(dead_code, reason = "the limits use a part of the test authenticator of the core")]
mod authenticator;
#[path = "support/gate.rs"]
mod gate;
#[expect(dead_code, reason = "the limits use a part of the support of the journeys")]
mod support;

use core::num::NonZeroUsize;
use core::pin::Pin;
use core::task::{Context, Poll, Waker};
use core::time::Duration;
use std::io::{Read as _, Write as _};
use std::sync::Arc;

use authenticator::{Get, Passkey};
use axum::body::Body;
use gate::Gated;
use http::{Request, StatusCode};
use rsauthnz::crypto::Algorithm;
use rsauthnz::store::{Kind, Store};
use rsauthnz_conformance::memory::{Memory, Schedule};
use support::{Browser, Site};
use tower::ServiceExt as _;

const ORIGIN: &str = "http://localhost:8080";
const START: u64 = 1_800_000_000;
const SIGN_UP: (&str, &str) = ("/sign-up/options", "/sign-up/finish");

/// A request that a test holds while the application does not answer it.
type Waiting = Pin<Box<dyn Future<Output = StatusCode>>>;

/// The status of the request `method` `path` with `body` from a page of `site`, with no cookie. The future borrows
/// nothing, so a test can hold many of them.
fn status(site: &Site, method: &str, path: &str, body: &[u8]) -> Waiting {
    let request = Request::builder()
        .method(method)
        .uri(path)
        .header("origin", &site.origin)
        .header("sec-fetch-site", "same-origin")
        .header("content-type", "application/json")
        .body(Body::from(body.to_vec()))
        .expect("a request");
    let router = site.router.clone();
    Box::pin(async move { router.oneshot(request).await.expect("a response").status() })
}

/// The status of the sign-up options of the account `name`: one commit of a request with no session.
fn sign_up(site: &Site, name: &str) -> Waiting {
    status(
        site,
        "POST",
        "/sign-up/options",
        format!(r#"{{"name":"{name}"}}"#).as_bytes(),
    )
}

/// One poll of `request`: its status, or `None` while it waits for the application.
fn poll(request: &mut Waiting) -> Option<StatusCode> {
    match request.as_mut().poll(&mut Context::from_waker(Waker::noop())) {
        Poll::Ready(status) => Some(status),
        Poll::Pending => None,
    }
}

/// Waits until the application thread waits for `store`.
async fn stalled(store: &Gated) {
    for _ in 0..10_000 {
        if store.stalled() {
            return;
        }
        tokio::time::sleep(Duration::from_millis(1)).await;
    }
    assert!(store.stalled(), "the application thread did not reach the store");
}

/// A site on a gated store, 10 seconds after its start.
fn gated() -> (Site, Arc<web::App<Gated>>, Gated) {
    let memory = Memory::new(Schedule::None);
    let store = Gated::new(memory.clone());
    let (site, app) = Site::on(ORIGIN, START, store.clone(), memory);
    site.advance(10);
    (site, app, store)
}

/// The body of a sign-in of `passkey` of the account `handle`, for new options of `site`.
async fn assertion(site: &Site, passkey: &Passkey, handle: [u8; 32]) -> Vec<u8> {
    let options = site.post(&mut Browser::default(), "/sign-in/options", b"{}").await;
    Get::new(passkey, "localhost", ORIGIN, authenticator::challenge(&options), handle).json()
}

/// Contract: at most 64 requests wait for the application thread. The next one gets `503` at once, and a
/// request that needs no state of the application still gets its answer.
#[tokio::test]
async fn the_request_after_the_last_waiting_place_gets_503_and_a_page_still_serves() {
    let (site, _app, store) = gated();
    store.close();
    // The application thread takes the first request and waits for the store.
    let mut waiting = vec![sign_up(&site, "first")];
    assert_eq!(poll(&mut waiting[0]), None);
    stalled(&store).await;
    for place in 0..64 {
        let mut request = sign_up(&site, &format!("user-{place}"));
        assert_eq!(poll(&mut request), None, "the place {place} of the queue");
        waiting.push(request);
    }
    assert_eq!(poll(&mut sign_up(&site, "late")), Some(StatusCode::SERVICE_UNAVAILABLE));
    assert_eq!(status(&site, "GET", "/", b"").await, StatusCode::OK);
    assert_eq!(status(&site, "POST", "/sign-in/options", b"{}").await, StatusCode::OK);

    store.open();
    for request in waiting {
        assert_eq!(request.await, StatusCode::OK);
    }
    // Each place is free again.
    assert_eq!(sign_up(&site, "late").await, StatusCode::OK);
}

/// Contract: one credential holds at most 8 places. The next sign-in of that credential gets `503` at once.
/// A sign-in of another credential waits for its turn, and each place is free again after its sign-in.
#[tokio::test]
async fn the_sign_in_after_the_share_of_a_credential_gets_503_and_another_credential_waits() {
    let (site, _app, store) = gated();
    let (alice, bob) = (
        Passkey::new(Algorithm::Ed25519, -8, 1),
        Passkey::new(Algorithm::Ed25519, -8, 2),
    );
    let mut browser = Browser::default();
    let alice_handle = site
        .register(&mut browser, SIGN_UP, br#"{"name":"alice"}"#, &alice)
        .await;
    let bob_handle = site.register(&mut browser, SIGN_UP, br#"{"name":"bob"}"#, &bob).await;
    let flood = assertion(&site, &alice, alice_handle).await;
    let other = assertion(&site, &bob, bob_handle).await;

    store.close();
    let mut waiting: Vec<Waiting> = (0..8)
        .map(|_| status(&site, "POST", "/sign-in/finish", &flood))
        .collect();
    for request in &mut waiting {
        assert_eq!(poll(request), None);
    }
    let mut ninth = status(&site, "POST", "/sign-in/finish", &flood);
    assert_eq!(poll(&mut ninth), Some(StatusCode::SERVICE_UNAVAILABLE));
    let mut other = status(&site, "POST", "/sign-in/finish", &other);
    assert_eq!(poll(&mut other), None);

    store.open();
    // The first sign-in of the flood uses its challenge. Each later one has the same challenge, so it refuses.
    let mut flood = waiting.into_iter();
    assert_eq!(flood.next().expect("the first sign-in").await, StatusCode::OK);
    for request in flood {
        assert_eq!(request.await, StatusCode::CONFLICT);
    }
    assert_eq!(other.await, StatusCode::OK);
    site.sign_in(&mut browser, &alice, alice_handle).await;
}

/// Contract: the application takes at most 100 commits at one time, and 20 more in each second. A commit over the
/// budget gets `503` and commits nothing.
#[tokio::test]
async fn a_commit_over_the_budget_gets_503_and_the_same_request_commits_after_the_budget_fills() {
    let site = Site::at(ORIGIN, START);
    // After 10 seconds, the budget is full again after the policy commit of the start.
    site.advance(10);
    for commit in 0..100 {
        assert_eq!(sign_up(&site, &format!("burst-{commit}")).await, StatusCode::OK);
    }
    assert_eq!(sign_up(&site, "late").await, StatusCode::SERVICE_UNAVAILABLE);

    // One second gives 20 commits. The refused request committed nothing, so its name is free.
    site.advance(1);
    assert_eq!(sign_up(&site, "late").await, StatusCode::OK);
    for commit in 1..20 {
        assert_eq!(sign_up(&site, &format!("second-{commit}")).await, StatusCode::OK);
    }
    assert_eq!(sign_up(&site, "later").await, StatusCode::SERVICE_UNAVAILABLE);
}

/// Contract: the directory holds at most 1,024 accounts. The next sign-up gets `503`.
#[tokio::test]
async fn the_sign_up_after_the_last_account_gets_503() {
    let site = Site::at(ORIGIN, START);
    let passkey = Passkey::new(Algorithm::Ed25519, -8, 1);
    for account in 0..1_024 {
        // One sign-up is two commits, and one second gives 20 commits.
        if account % 10 == 0 {
            site.advance(1);
        }
        let body = format!(r#"{{"name":"user-{account}"}}"#);
        site.register(&mut Browser::default(), SIGN_UP, body.as_bytes(), &passkey)
            .await;
    }
    site.advance(1);
    assert_eq!(sign_up(&site, "late").await, StatusCode::SERVICE_UNAVAILABLE);
}

/// The audit records of `memory`.
async fn audits(memory: &Memory) -> usize {
    let prefix = Kind::Audit.key(&[]).expect("a prefix");
    memory
        .clone()
        .range(&prefix, None, NonZeroUsize::MAX)
        .await
        .expect("a range")
        .len()
}

/// Contract: after the clock passes the end of a record, the next expiry pass removes the record. One pass removes
/// at most 256 records of a kind, and the next pass continues.
#[tokio::test]
async fn an_expiry_pass_removes_ended_records_in_bounded_steps() {
    let memory = Memory::new(Schedule::None).with_retention(Duration::from_secs(600));
    let (site, _app) = Site::on(ORIGIN, START, memory.clone(), memory.clone());
    site.advance(10);
    let passkey = Passkey::new(Algorithm::Ed25519, -8, 1);
    let mut browser = Browser::default();
    let handle = site
        .register(&mut browser, SIGN_UP, br#"{"name":"alice"}"#, &passkey)
        .await;
    for sign_in in 0..300 {
        if sign_in % 20 == 0 {
            site.advance(1);
        }
        site.sign_in(&mut browser, &passkey, handle).await;
    }
    // Each commit made one audit record: the 300 sign-ins, the sign-up, and the start of the application.
    let ended = audits(&memory).await;
    assert!((300..=512).contains(&ended), "{ended} audit records");

    // Each audit record ended. A request with no session reads no record, and a pass comes before it.
    site.advance(3_600);
    assert_eq!(status(&site, "GET", "/account", b"").await, StatusCode::FORBIDDEN);
    assert_eq!(audits(&memory).await, ended - 256);
    site.advance(1);
    assert_eq!(status(&site, "GET", "/account", b"").await, StatusCode::FORBIDDEN);
    assert_eq!(audits(&memory).await, 0);
}

/// The HTTP/1.1 response to a sign-up of `name` at `address`.
fn http1_sign_up(address: core::net::SocketAddr, name: &str) -> String {
    let body = format!(r#"{{"name":"{name}"}}"#);
    let request = format!(
        "POST /sign-up/options HTTP/1.1\r\nhost: localhost:8080\r\norigin: {ORIGIN}\r\nsec-fetch-site: \
         same-origin\r\ncontent-type: application/json\r\ncontent-length: {}\r\nconnection: close\r\n\r\n{body}",
        body.len()
    );
    let mut stream = std::net::TcpStream::connect(address).expect("a connection");
    stream.write_all(request.as_bytes()).expect("a request");
    let mut response = String::new();
    stream.read_to_string(&mut response).expect("a response");
    response
}

/// Contract: a shutdown returns the response of each request that the server took, and then joins the application
/// thread. It does not return while a request waits for the store.
#[tokio::test]
async fn a_shutdown_returns_the_response_of_a_request_in_flight_and_then_joins_the_application_thread() {
    let (site, app, store) = gated();
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.expect("a listener");
    let address = listener.local_addr().expect("an address");
    let (stop, stopped) = tokio::sync::oneshot::channel::<()>();
    let router = site.router.clone();
    let server = tokio::spawn(async move {
        let shutdown = async {
            stopped.await.expect("the test stops the server");
        };
        web::serve(listener, router, &app, shutdown).await
    });

    store.close();
    let request = tokio::task::spawn_blocking(move || http1_sign_up(address, "alice"));
    stalled(&store).await;
    stop.send(()).expect("the server runs");
    tokio::time::sleep(Duration::from_millis(100)).await;
    assert!(
        !server.is_finished(),
        "the shutdown returned before the request in flight"
    );

    store.open();
    let response = request.await.expect("the request");
    assert!(response.starts_with("HTTP/1.1 200 OK\r\n"), "{response}");
    server.await.expect("the server").expect("a joined shutdown");
    // The queue is closed, so a later request gets the overload response.
    assert_eq!(sign_up(&site, "bob").await, StatusCode::SERVICE_UNAVAILABLE);
}
