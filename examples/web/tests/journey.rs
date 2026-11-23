//! The journeys of the web example through its HTTP API, with the responses of the A202 test authenticator: a sign-up,
//! a sign-in, the rename, the addition, and the removal of a passkey, a second session and its end, an invitation and
//! its activation, a recovery with a code, and a sign-out. Also the rename of an account, a lost response, a request
//! of another site, a stale verification, and the same API over HTTP/1.1 and HTTP/2.

// `cfg(test)` marks the shared test authenticator as test code for Clippy.
#[cfg(test)]
#[path = "../../../tests/passkey/authenticator.rs"]
#[expect(dead_code, reason = "the journeys use a part of the test authenticator of the core")]
mod authenticator;

use core::sync::atomic::{AtomicU64, Ordering};
use core::time::Duration;
use std::io::{Read as _, Write as _};
use std::sync::Arc;

use authenticator::{Get, Passkey, Registration};
use axum::Router;
use axum::body::{Body, Bytes};
use http::{Request, StatusCode};
use rsauthnz::crypto::Algorithm;
use rsauthnz::time::{Reading, ReadingSource};
use rsauthnz_conformance::memory::{Memory, Schedule};
use rsauthnz_conformance::suite::{Fault, Subject as _};
use rscodec::base64::Profile::Url;
use rscodec::json::{self, Slot};
use rscrypto::ChaCha20Rng;
use tower::ServiceExt as _;

const ORIGIN: &str = "http://localhost:8080";
const RP_ID: &str = "localhost";

/// The site: its router, its store, and the clock of the host in whole seconds.
struct Site {
    router: Router,
    memory: Memory,
    seconds: Arc<AtomicU64>,
}

/// A browser: the session cookie that the site gave it.
#[derive(Default)]
struct Browser {
    cookie: Option<String>,
}

/// A response: its status and its body.
struct Reply {
    status: StatusCode,
    body: String,
}

impl Site {
    /// A new site at a fixed time. Its first requests come 10 seconds after its start, after the replay floor of the
    /// start.
    fn new() -> Self {
        let memory = Memory::new(Schedule::None);
        let seconds = Arc::new(AtomicU64::new(1_800_000_000));
        let clock = Arc::clone(&seconds);
        let clock = Box::new(move || {
            Reading::new(
                Duration::from_secs(clock.load(Ordering::SeqCst)),
                Some(Duration::from_secs(1)),
                ReadingSource::Caller,
            )
        });
        let app = web::App::new(ORIGIN, memory.clone(), clock, ChaCha20Rng::from_seed([5; 32])).expect("the app");
        let site = Self {
            router: web::router(Arc::new(app)),
            memory,
            seconds,
        };
        site.advance(10);
        site
    }

    fn advance(&self, seconds: u64) {
        self.seconds.fetch_add(seconds, Ordering::SeqCst);
    }

    /// The response to `browser` of a request with `method`, `path`, and `body`, from a page of the site. The browser
    /// keeps the session cookie of the response.
    async fn send(&self, browser: &mut Browser, method: &str, path: &str, body: &[u8]) -> Reply {
        let mut request = Request::builder()
            .method(method)
            .uri(path)
            .header("origin", ORIGIN)
            .header("sec-fetch-site", "same-origin")
            .header("content-type", "application/json");
        if let Some(cookie) = &browser.cookie {
            request = request.header("cookie", format!("__Host-session={cookie}"));
        }
        let request = request.body(Body::from(body.to_vec())).expect("a request");
        let response = self.router.clone().oneshot(request).await.expect("a response");
        if let Some(set) = response.headers().get("set-cookie") {
            let set = set.to_str().expect("a cookie");
            let value = set
                .strip_prefix("__Host-session=")
                .and_then(|rest| rest.split_once(';'))
                .map(|(value, _)| value.to_owned());
            browser.cookie = value.filter(|_| !set.contains("Max-Age=0"));
        }
        let status = response.status();
        let body = axum::body::to_bytes(response.into_body(), usize::MAX)
            .await
            .expect("a body");
        Reply {
            status,
            body: String::from_utf8(body.to_vec()).expect("a text body"),
        }
    }

    /// The body of the accepted request `path` with `body`.
    async fn post(&self, browser: &mut Browser, path: &str, body: &[u8]) -> Vec<u8> {
        let reply = self.send(browser, "POST", path, body).await;
        assert_eq!(reply.status, StatusCode::OK, "{path} gives {}", reply.body);
        reply.body.into_bytes()
    }

    /// Registers `passkey` through the options and the finish of a ceremony, and gives the user handle of the options.
    async fn register(
        &self,
        browser: &mut Browser,
        (options, finish): (&str, &str),
        body: &[u8],
        passkey: &Passkey,
    ) -> [u8; 32] {
        let options = self.post(browser, options, body).await;
        let json = Registration::new(passkey, RP_ID, ORIGIN, authenticator::challenge(&options)).json();
        self.post(browser, finish, &json).await;
        user_id(&options)
    }

    /// A sign-in of `browser` with `passkey` of the account `handle`.
    async fn sign_in(&self, browser: &mut Browser, passkey: &Passkey, handle: [u8; 32]) {
        let options = self.post(browser, "/sign-in/options", b"{}").await;
        let json = Get::new(passkey, RP_ID, ORIGIN, authenticator::challenge(&options), handle).json();
        self.post(browser, "/sign-in/finish", &json).await;
        assert!(browser.cookie.is_some(), "the sign-in gives a session cookie");
    }

    /// The account page of `browser`.
    async fn account(&self, browser: &mut Browser) -> Reply {
        self.send(browser, "GET", "/account", b"").await
    }
}

/// The user handle of the creation options `options`: the `id` of its `user`.
fn user_id(options: &[u8]) -> [u8; 32] {
    let limits = json::Limits {
        input_bytes_max: 64 * 1024,
        depth_max: 4,
        string_bytes_max: 1024,
        members_max: 16,
        elements_max: 64,
        number_digits_max: 16,
    };
    let mut scratch = [Slot::EMPTY; 80];
    let text = json::read(options, &limits, json::Profile::IJson, &mut scratch, |reader| {
        let mut id = None;
        let mut members = reader.value().members()?;
        while let Some((name, value)) = members.next()? {
            if name == "user" {
                let mut user = value.members()?;
                while let Some((name, value)) = user.next()? {
                    if name == "id" {
                        id = value.str()?.borrowed();
                    }
                }
            }
        }
        Ok(id)
    })
    .expect("options in JSON")
    .expect("a user id");
    let mut handle = [0; 32];
    Url.decode(text.as_bytes(), &mut handle)
        .expect("a user handle of 32 bytes");
    handle
}

/// The base64url text of `bytes`, as the JSON of the site writes an ID.
fn base64url(bytes: &[u8]) -> String {
    let mut out = vec![0; Url.encoded_len(bytes.len()).expect("a short ID")];
    Url.encode(bytes, &mut out).expect("an encode");
    String::from_utf8(out).expect("base64url text")
}

/// The string member `name` of the JSON object `body`.
fn member(body: &[u8], name: &str) -> String {
    let limits = json::Limits {
        input_bytes_max: 4 * 1024,
        depth_max: 2,
        string_bytes_max: 1024,
        members_max: 8,
        elements_max: 32,
        number_digits_max: 1,
    };
    let mut scratch = [Slot::EMPTY; 8];
    json::read(body, &limits, json::Profile::Rfc8259, &mut scratch, |reader| {
        let mut found = None;
        let mut members = reader.value().members()?;
        while let Some((key, value)) = members.next()? {
            if key == name {
                found = value.str()?.borrowed().map(str::to_owned);
            }
        }
        Ok(found)
    })
    .expect("a JSON object")
    .expect("the member")
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
