//! The journeys of the web example through its HTTP API, with the responses of the A202 test authenticator: a sign-up,
//! a sign-in, the rename, the addition, and the removal of a passkey, a second session and its end, an invitation and
//! its activation, a recovery with a code, and a sign-out. Also the rename of an account, a lost response, a request
//! of another site, a stale verification, and the same API over HTTP/1.1 and HTTP/2.

// `cfg(test)` marks the shared test authenticator as test code for Clippy.
#[cfg(test)]
#[path = "../../../tests/passkey/authenticator.rs"]
#[expect(dead_code, reason = "the journeys use a part of the test authenticator of the core")]
mod authenticator;

mod support;

use std::io::{Read as _, Write as _};

use authenticator::{Get, Passkey, Registration};
use axum::body::{Body, Bytes};
use http::{Request, StatusCode};
use rsauthnz::crypto::Algorithm;
use rsauthnz_conformance::suite::{Fault, Subject as _};
use rscodec::base64::Profile::Url;
use support::{Browser, Reply, Site, member};
use tower::ServiceExt as _;

const ORIGIN: &str = "http://localhost:8080";
const RP_ID: &str = "localhost";

impl Site {
    fn new() -> Self {
        let site = Self::at(ORIGIN, 1_800_000_000);
        site.advance(10);
        site
    }

    /// The account page of `browser`.
    async fn account(&self, browser: &mut Browser) -> Reply {
        self.send(browser, "GET", "/account", b"").await
    }
}

/// The base64url text of `bytes`, as the JSON of the site writes an ID.
fn base64url(bytes: &[u8]) -> String {
    let mut out = vec![0; Url.encoded_len(bytes.len()).expect("a short ID")];
    Url.encode(bytes, &mut out).expect("an encode");
    String::from_utf8(out).expect("base64url text")
}

#[tokio::test]
async fn an_unfinished_sign_up_leaves_the_name_available_and_only_one_finish_claims_it() {
    let site = Site::new();
    let mut first = Browser::default();
    let mut second = Browser::default();
    let name = br#"{"name":"alice"}"#;
    let ceremony = ("/sign-up/options", "/sign-up/finish");
    let options = site.post(&mut first, ceremony.0, name).await;
    assert_eq!(site.account(&mut first).await.status, StatusCode::FORBIDDEN);

    let accepted = Passkey::new(Algorithm::Ed25519, -8, 1);
    let handle = site.register(&mut second, ceremony, name, &accepted).await;
    let late = Passkey::new(Algorithm::Ed25519, -8, 2);
    let answer = Registration::new(&late, RP_ID, ORIGIN, authenticator::challenge(&options)).json();
    assert_eq!(
        site.send(&mut first, "POST", ceremony.1, &answer).await.status,
        StatusCode::FORBIDDEN
    );
    assert!(first.cookie.is_none());

    site.sign_in(&mut second, &accepted, handle).await;
    let account = site.account(&mut second).await;
    assert!(account.body.contains(&base64url(&accepted.id)));
    assert!(!account.body.contains(&base64url(&late.id)));
}

#[tokio::test]
async fn the_first_sign_in_after_start_issues_a_challenge_the_store_accepts() {
    let site = Site::at(ORIGIN, 1_800_000_000);
    let mut browser = Browser::default();
    let passkey = Passkey::new(Algorithm::Ed25519, -8, 1);
    let handle = site
        .register(
            &mut browser,
            ("/sign-up/options", "/sign-up/finish"),
            br#"{"name":"alice"}"#,
            &passkey,
        )
        .await;
    // At three seconds, the earliest challenge time equals the replay floor. The first admissible time is one nanosecond later.
    site.advance(3);
    let options = {
        let mut start = core::pin::pin!(site.post(&mut browser, "/sign-in/options", b"{}"));
        assert!(
            start
                .as_mut()
                .poll(&mut core::task::Context::from_waker(core::task::Waker::noop()))
                .is_pending()
        );
        site.advance(1);
        start.await
    };
    let response = Get::new(&passkey, RP_ID, ORIGIN, authenticator::challenge(&options), handle).json();
    site.post(&mut browser, "/sign-in/finish", &response).await;
    assert_eq!(site.account(&mut browser).await.status, StatusCode::OK);
}

#[tokio::test]
async fn a_person_runs_each_step_of_the_journey_through_the_http_api() {
    let site = Site::new();
    let (mut laptop, mut phone, mut bob_browser, mut new_laptop) = (
        Browser::default(),
        Browser::default(),
        Browser::default(),
        Browser::default(),
    );

    // Sign-up and sign-in.
    let first = Passkey::new(Algorithm::Ed25519, -8, 1);
    let ceremony = ("/sign-up/options", "/sign-up/finish");
    let handle = site
        .register(&mut laptop, ceremony, br#"{"name":"alice"}"#, &first)
        .await;
    assert!(laptop.cookie.is_none(), "a sign-up opens no session");
    // An upgrade clears the earlier cookie. The user signs in once with the passkey already registered.
    laptop.cookie = include_str!("../../../tests/passkey/upgrade.txt")
        .lines()
        .last()
        .map(str::to_owned);
    assert_eq!(site.account(&mut laptop).await.status, StatusCode::FORBIDDEN);
    assert!(laptop.cookie.is_none());
    site.sign_in(&mut laptop, &first, handle).await;
    // The account page gives the data of `signalRenamed` and `signalAccepted`.
    let account = site.account(&mut laptop).await;
    assert_eq!(account.status, StatusCode::OK);
    let expected = format!(
        r#"{{"rpId":"localhost","userId":"{}","name":"alice","displayName":"alice","passkeys":[{{"id":"{}""#,
        base64url(&handle),
        base64url(&first.id)
    );
    assert!(account.body.starts_with(&expected), "{}", account.body);

    // The renewal rotates the cookie even when the server must look up the accepted commit.
    let previous = laptop.cookie.clone();
    site.memory.inject(Fault::LostResponse);
    site.post(&mut laptop, "/sessions/renew", b"{}").await;
    assert!(laptop.cookie.is_some() && laptop.cookie != previous);
    let account = site.account(&mut laptop).await;
    assert_eq!(account.status, StatusCode::OK);
    assert!(account.body.starts_with(&expected));
    // The lookup restarts the driver. The next sign-in must start after its replay floor.
    site.advance(4);

    // A rename needs no verification.
    let rename = format!(r#"{{"id":"{}","name":"laptop"}}"#, base64url(&first.id));
    site.post(&mut laptop, "/passkeys/rename", rename.as_bytes()).await;
    assert!(site.account(&mut laptop).await.body.contains(r#""name":"laptop""#));

    // An added passkey, with the fresh verification of the sign-in, then its removal. The account page then gives only
    // the first passkey to `signalAccepted`.
    let second = Passkey::new(Algorithm::Es256, -7, 2);
    let ceremony = ("/passkeys/add/options", "/passkeys/add/finish");
    site.register(&mut laptop, ceremony, b"{}", &second).await;
    assert_eq!(site.account(&mut laptop).await.body.matches(r#"{"id":"#).count(), 2);
    let remove = format!(r#"{{"id":"{}"}}"#, base64url(&second.id));
    site.post(&mut laptop, "/passkeys/remove", remove.as_bytes()).await;
    let account = site.account(&mut laptop).await.body;
    assert_eq!(account.matches(r#"{"id":"#).count(), 1);
    assert!(account.contains(&base64url(&first.id)), "{account}");

    // A provider that no Signals call reached still offers the removed passkey. Its sign-in answers `forget`, and
    // the browser module then tells the provider to forget it.
    let mut stale = Browser::default();
    let options = site.post(&mut stale, "/sign-in/options", b"{}").await;
    let json = Get::new(&second, RP_ID, ORIGIN, authenticator::challenge(&options), handle).json();
    let reply = site.send(&mut stale, "POST", "/sign-in/finish", &json).await;
    assert_eq!(
        (reply.status, reply.body.as_str()),
        (StatusCode::GONE, r#"{"recovery":"forget"}"#)
    );
    assert!(stale.cookie.is_none());

    // A second session, which the first one ends with a fresh verification.
    site.sign_in(&mut phone, &first, handle).await;
    let sessions = site.account(&mut laptop).await.body;
    assert_eq!(sessions.matches(r#""current":"#).count(), 2);
    let other = sessions
        .split(r#"{"key":""#)
        .find(|part| part.contains(r#""current":false"#))
        .and_then(|part| part.split_once('"'))
        .map(|(key, _)| key.to_owned())
        .expect("the other session");
    site.post(
        &mut laptop,
        "/sessions/revoke",
        format!(r#"{{"key":"{other}"}}"#).as_bytes(),
    )
    .await;
    assert_eq!(site.account(&mut phone).await.status, StatusCode::FORBIDDEN);

    // A recovery code, shown once, and an invitation of bob, who activates it and signs in.
    let code = member(&site.post(&mut laptop, "/recovery-code", b"{}").await, "code");
    let invitation = member(
        &site.post(&mut laptop, "/invitations", br#"{"name":"bob"}"#).await,
        "invitation",
    );
    let bob = Passkey::new(Algorithm::Ed25519, -8, 3);
    let body = format!(r#"{{"invitation":"{invitation}","name":"bob"}}"#);
    let ceremony = ("/invitation/options", "/invitation/finish/bob");
    let bob_handle = site.register(&mut bob_browser, ceremony, body.as_bytes(), &bob).await;
    site.sign_in(&mut bob_browser, &bob, bob_handle).await;
    assert!(
        site.account(&mut bob_browser)
            .await
            .body
            .contains(r#""name":"bob","displayName":"bob""#)
    );

    // Alice loses her passkey and recovers with the code: the recovery ends her other passkey and her sessions.
    let recovered = Passkey::new(Algorithm::MlDsa65, -49, 4);
    let body = format!(r#"{{"name":"alice","code":"{code}"}}"#);
    let options = site.post(&mut new_laptop, "/recover/options", body.as_bytes()).await;
    let json = Registration::new(&recovered, RP_ID, ORIGIN, authenticator::challenge(&options)).json();
    site.post(&mut new_laptop, "/recover/finish", &json).await;
    assert_eq!(site.account(&mut laptop).await.status, StatusCode::FORBIDDEN);
    let account = site.account(&mut new_laptop).await.body;
    assert!(account.contains(&base64url(&recovered.id)) && !account.contains(&base64url(&first.id)));
    let again = site
        .send(&mut new_laptop, "POST", "/recover/options", body.as_bytes())
        .await;
    assert_eq!(again.status, StatusCode::FORBIDDEN, "a spent code refuses");

    // The sign-out clears the cookie, and the account page refuses.
    site.post(&mut new_laptop, "/sign-out", b"{}").await;
    assert!(new_laptop.cookie.is_none());
    assert_eq!(site.account(&mut new_laptop).await.status, StatusCode::FORBIDDEN);
}

#[tokio::test]
async fn a_sign_in_whose_commit_response_is_lost_gets_its_session_from_the_lookup_of_the_server() {
    let site = Site::new();
    let mut browser = Browser::default();
    let passkey = Passkey::new(Algorithm::Ed25519, -8, 1);
    let ceremony = ("/sign-up/options", "/sign-up/finish");
    let handle = site
        .register(&mut browser, ceremony, br#"{"name":"alice"}"#, &passkey)
        .await;
    let options = site.post(&mut browser, "/sign-in/options", b"{}").await;
    let json = Get::new(&passkey, RP_ID, ORIGIN, authenticator::challenge(&options), handle).json();
    site.memory.inject(Fault::LostResponse);
    site.post(&mut browser, "/sign-in/finish", &json).await;
    assert_eq!(site.account(&mut browser).await.status, StatusCode::OK);
}

#[tokio::test]
async fn a_request_of_another_site_refuses_before_any_work() {
    let site = Site::new();
    let request = Request::post("/sign-up/options")
        .header("origin", "https://attacker.example")
        .header("sec-fetch-site", "cross-site")
        .header("content-type", "application/json")
        .body(Body::from(r#"{"name":"alice"}"#))
        .expect("a request");
    let response = site.router.clone().oneshot(request).await.expect("a response");
    assert_eq!(response.status(), StatusCode::FORBIDDEN);
    let body = axum::body::to_bytes(response.into_body(), usize::MAX)
        .await
        .expect("a body");
    assert_eq!(&body[..], br#"{"recovery":"refuse"}"#);
    // No account was made: the same name signs up from the site.
    let passkey = Passkey::new(Algorithm::Ed25519, -8, 1);
    site.register(
        &mut Browser::default(),
        ("/sign-up/options", "/sign-up/finish"),
        br#"{"name":"alice"}"#,
        &passkey,
    )
    .await;
}

#[tokio::test]
async fn a_sensitive_change_after_the_verification_window_asks_for_a_new_sign_in() {
    let site = Site::new();
    let mut browser = Browser::default();
    let passkey = Passkey::new(Algorithm::Ed25519, -8, 1);
    let ceremony = ("/sign-up/options", "/sign-up/finish");
    let handle = site
        .register(&mut browser, ceremony, br#"{"name":"alice"}"#, &passkey)
        .await;
    site.sign_in(&mut browser, &passkey, handle).await;
    site.advance(301);
    let reply = site.send(&mut browser, "POST", "/recovery-code", b"{}").await;
    assert_eq!(
        (reply.status, reply.body.as_str()),
        (StatusCode::FORBIDDEN, r#"{"recovery":"verify"}"#)
    );
    // A new sign-in replaces the session, and the change runs.
    site.sign_in(&mut browser, &passkey, handle).await;
    site.post(&mut browser, "/recovery-code", b"{}").await;
}

#[tokio::test]
async fn a_new_account_name_needs_a_fresh_verification_and_the_next_options_give_the_new_names() {
    let site = Site::new();
    let mut browser = Browser::default();
    let passkey = Passkey::new(Algorithm::Ed25519, -8, 1);
    let ceremony = ("/sign-up/options", "/sign-up/finish");
    let handle = site
        .register(&mut browser, ceremony, br#"{"name":"alice"}"#, &passkey)
        .await;
    let bob = Passkey::new(Algorithm::Ed25519, -8, 2);
    site.register(&mut Browser::default(), ceremony, br#"{"name":"bob"}"#, &bob)
        .await;
    site.sign_in(&mut browser, &passkey, handle).await;
    let code = member(&site.post(&mut browser, "/recovery-code", b"{}").await, "code");
    let rename = async |browser: &mut Browser, body: &[u8]| {
        let reply = site.send(browser, "POST", "/account/rename", body).await;
        (reply.status, reply.body)
    };
    let refused = |recovery: &str| (StatusCode::FORBIDDEN, format!(r#"{{"recovery":"{recovery}"}}"#));

    // After the verification window, a new display name needs only the session, and a new name asks for a new sign-in.
    site.advance(301);
    let body = br#"{"name":"alice","displayName":"Alice Liddell"}"#;
    assert_eq!(rename(&mut browser, body).await, (StatusCode::OK, "{}".to_owned()));
    assert!(
        site.account(&mut browser)
            .await
            .body
            .contains(r#""displayName":"Alice Liddell""#)
    );
    let body = br#"{"name":"ally","displayName":"Ally"}"#;
    assert_eq!(rename(&mut browser, body).await, refused("verify"));

    // With a fresh verification, a name of another account and a display name over its bound refuse.
    site.sign_in(&mut browser, &passkey, handle).await;
    let long = format!(r#"{{"name":"ally","displayName":"{}"}}"#, "x".repeat(257));
    for wrong in [br#"{"name":"bob","displayName":"Ally"}"#.as_slice(), long.as_bytes()] {
        assert_eq!(rename(&mut browser, wrong).await, refused("refuse"));
    }
    assert_eq!(rename(&mut browser, body).await, (StatusCode::OK, "{}".to_owned()));

    // The account page gives the new names to `signalRenamed`, and the recovery options of the new name give them to
    // the authenticator. The old name finds no account.
    let account = site.account(&mut browser).await.body;
    let expected = format!(
        r#"{{"rpId":"localhost","userId":"{}","name":"ally","displayName":"Ally","#,
        base64url(&handle)
    );
    assert!(account.starts_with(&expected), "{account}");
    let old = format!(r#"{{"name":"alice","code":"{code}"}}"#);
    let reply = site
        .send(&mut Browser::default(), "POST", "/recover/options", old.as_bytes())
        .await;
    assert_eq!((reply.status, reply.body), refused("refuse"));
    let new = format!(r#"{{"name":"ally","code":"{code}"}}"#);
    let options = site
        .post(&mut Browser::default(), "/recover/options", new.as_bytes())
        .await;
    let options = String::from_utf8(options).expect("text");
    assert!(options.contains(r#""name":"ally","displayName":"Ally""#), "{options}");
}

#[test]
fn the_page_calls_the_signals_api_at_each_load_and_after_the_removal_of_a_passkey() {
    let page = include_str!("../www/app.js");
    let (_, load) = page.split_once("async function load()").expect("the load");
    let (load, _) = load.split_once("\n}\n").expect("the end of the load");
    let (_, after) = load.split_once(r#"change("/passkeys/remove""#).expect("the removal");
    let (handler, _) = after.split_once("item.append").expect("the end of the handler");
    assert!(handler.contains("signalDeleted("), "{handler}");
    let (_, tail) = load.rsplit_once("}));").expect("the lists of the account");
    assert!(
        tail.contains("signalRenamed(account)") && tail.contains("signalAccepted("),
        "{tail}"
    );
}

/// A request for sign-in options over HTTP/1.1 with std I/O.
fn http1(address: core::net::SocketAddr) -> String {
    let mut stream = std::net::TcpStream::connect(address).expect("a connection");
    let request = format!(
        "POST /sign-in/options HTTP/1.1\r\nhost: localhost\r\norigin: {ORIGIN}\r\nsec-fetch-site: same-origin\r\n\
         content-length: 2\r\nconnection: close\r\n\r\n{{}}"
    );
    stream.write_all(request.as_bytes()).expect("a write");
    let mut response = String::new();
    stream.read_to_string(&mut response).expect("a response");
    response
}

#[tokio::test]
async fn the_api_serves_the_same_response_over_http_1_1_and_http_2() {
    let site = Site::new();
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.expect("a listener");
    let address = listener.local_addr().expect("an address");
    let router = site.router.clone();
    tokio::spawn(async move { axum::serve(listener, router).await });

    let response = tokio::task::spawn_blocking(move || http1(address))
        .await
        .expect("the HTTP/1.1 client");
    assert!(response.starts_with("HTTP/1.1 200 OK\r\n"), "{response}");
    assert!(response.contains(r#""challenge":""#), "{response}");

    let tcp = tokio::net::TcpStream::connect(address).await.expect("a connection");
    let (client, connection) = h2::client::handshake(tcp).await.expect("an HTTP/2 connection");
    tokio::spawn(connection);
    let mut client = client.ready().await.expect("a ready client");
    let request = Request::post("http://localhost/sign-in/options")
        .header("origin", ORIGIN)
        .header("sec-fetch-site", "same-origin")
        .body(())
        .expect("a request");
    let (response, mut stream) = client.send_request(request, false).expect("a stream");
    stream.send_data(Bytes::from_static(b"{}"), true).expect("the body");
    let response = response.await.expect("a response");
    assert_eq!(response.status(), StatusCode::OK);
    assert_eq!(response.version(), http::Version::HTTP_2);
    let mut body = response.into_body();
    let mut text = Vec::new();
    while let Some(chunk) = body.data().await {
        let chunk = chunk.expect("a chunk");
        body.flow_control().release_capacity(chunk.len()).expect("capacity");
        text.extend_from_slice(&chunk);
    }
    assert!(String::from_utf8(text).expect("text").contains(r#""challenge":""#));
}
