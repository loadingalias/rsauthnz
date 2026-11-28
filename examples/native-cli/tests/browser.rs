//! A person approves the real native CLI. With its device code, a committed finish loses its response, and the CLI
//! recovers and proves possession. On the loopback interface, the browser brings the redirect code to the CLI.
#![cfg(feature = "native-custody")]

#[cfg(test)]
#[path = "../../../tests/passkey/authenticator.rs"]
#[expect(
    dead_code,
    reason = "the journey uses the registration and sign-in of the core test authenticator"
)]
mod authenticator;
#[path = "../../web/tests/support/mod.rs"]
mod support;

use core::mem::DropGuard;
use core::time::Duration;
use std::io::{BufRead as _, BufReader, Read as _};

use std::process::{Command, Stdio};
use std::sync::{Arc, Mutex};
use std::time::{SystemTime, UNIX_EPOCH};
use tokio::io::{AsyncReadExt as _, AsyncWriteExt as _};

use authenticator::Passkey;
use http::StatusCode;
use rsauthnz::account::FRESH_MAX;
use rsauthnz::agent::{ATTEMPTS_MAX, UserCode};
use rsauthnz::crypto::Algorithm;
use rsauthnz_conformance::suite::Fault;
use support::{Browser, Site, member};

#[tokio::test]
async fn browser_approval_requires_fresh_verification_and_the_native_cli_recovers_a_lost_finish() {
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0")
        .await
        .expect("loopback listener");
    let port = listener.local_addr().expect("port").port();
    let origin = format!("http://localhost:{port}");
    let now = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .expect("system clock")
        .as_secs();
    let age = FRESH_MAX.as_secs() + 1;
    let site = Site::at(&origin, now - age - 10);
    site.advance(10);
    let directory = site.issuer_dir.join("laptop");
    let binding = directory.join("binding");
    let requests = Arc::new(Mutex::new(Vec::new()));
    let observed = Arc::clone(&requests);
    let router = site.router.clone().layer(axum::middleware::from_fn(
        move |request: axum::extract::Request, next: axum::middleware::Next| {
            match request.uri().path() {
                "/cli/finish" => observed.lock().expect("requests").push(("finish", binding.is_file())),
                "/cli/credential" => observed
                    .lock()
                    .expect("requests")
                    .push(("credential", binding.is_file())),
                _ => {}
            }
            next.run(request)
        },
    ));
    tokio::spawn(async move { axum::serve(listener, router).await });

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
    site.sign_in(&mut browser, &passkey, handle).await;
    site.advance(age);
    let cli = env!("CARGO_BIN_EXE_native-cli");
    let child = Command::new(cli)
        .arg("enroll")
        .arg(&directory)
        .arg("Alice laptop")
        .arg(port.to_string())
        .arg("--device-code")
        .stdout(Stdio::piped())
        .spawn()
        .expect("start the native CLI");
    let mut child = DropGuard::new(child, |mut child| {
        drop(child.kill());
        drop(child.wait());
    });
    let stdout = child.stdout.take().expect("the CLI output");
    let (mut stdout, code, fingerprint) = tokio::task::spawn_blocking(move || {
        let mut reader = BufReader::new(stdout);
        let mut lines = (&mut reader).lines();
        let mut line = || lines.next().expect("CLI output").expect("a line");
        assert_eq!(line(), format!("Open {origin}/cli"));
        let code = line().strip_prefix("User code ").expect("the code").to_owned();
        let fingerprint = line()
            .strip_prefix("Key fingerprint ")
            .expect("the fingerprint")
            .to_owned();
        (reader, code, fingerprint)
    })
    .await
    .expect("the CLI prompt");
    UserCode::parse(&code).expect("the displayed user code");
    let review = format!(r#"{{"code":"{code}"}}"#);
    let (locator, check) = code.split_once('-').expect("two groups");
    let other = if check.starts_with('B') { "CCCC" } else { "BBBB" };
    let wrong = format!(r#"{{"code":"{locator}-{other}"}}"#);
    // A human who is not signed in checks no code, so no wrong code of theirs counts against the bound.
    for body in core::iter::repeat_n(&wrong, usize::try_from(ATTEMPTS_MAX).expect("a count")).chain([&review]) {
        let no_session = site
            .send(&mut Browser::default(), "POST", "/cli/request", body.as_bytes())
            .await;
        assert_eq!(no_session.body, r#"{"recovery":"verify"}"#);
    }
    // A wrong code of a signed-in human counts, and the page shows nothing of the request.
    let counted = site.send(&mut browser, "POST", "/cli/request", wrong.as_bytes()).await;
    assert_eq!(counted.body, r#"{"recovery":"restart"}"#);
    let shown = site.post(&mut browser, "/cli/request", review.as_bytes()).await;
    assert_eq!(member(&shown, "name"), "Alice laptop");
    assert_eq!(member(&shown, "account"), "alice");
    assert_eq!(member(&shown, "fingerprint"), fingerprint);
    let id = member(&shown, "accountId");
    let approve = format!(r#"{{"code":"{code}","accountId":"{id}"}}"#);
    let stale = site
        .send(&mut browser, "POST", "/cli/approve", approve.as_bytes())
        .await;
    assert_eq!(stale.status, StatusCode::FORBIDDEN);
    assert_eq!(stale.body, r#"{"recovery":"verify"}"#);
    let other = Passkey::new(Algorithm::Ed25519, -8, 2);
    let other_handle = site
        .register(
            &mut browser,
            ("/sign-up/options", "/sign-up/finish"),
            br#"{"name":"bob"}"#,
            &other,
        )
        .await;
    site.sign_in(&mut browser, &other, other_handle).await;
    let switched = site
        .send(&mut browser, "POST", "/cli/approve", approve.as_bytes())
        .await;
    assert_eq!(switched.body, r#"{"recovery":"restart"}"#);
    site.sign_in(&mut browser, &passkey, handle).await;
    site.post(&mut browser, "/cli/approve", approve.as_bytes()).await;
    site.memory.inject_application(Fault::LostResponse);

    let status = exit(&mut child).await;
    let mut tail = String::new();
    stdout.read_to_string(&mut tail).expect("the CLI result");
    assert!(status.success(), "{status} {tail}");
    assert_eq!(
        tail,
        format!("Approved account alice ({id})\nStatus admitted for {id}\n")
    );

    let output = tokio::task::spawn_blocking(move || Command::new(cli).arg("status").arg(directory).output())
        .await
        .expect("the second process")
        .expect("run status");
    assert!(output.status.success(), "{}", String::from_utf8_lossy(&output.stderr));
    assert_eq!(
        *requests.lock().expect("requests"),
        [("finish", true), ("credential", true)]
    );
    assert_eq!(
        String::from_utf8_lossy(&output.stdout),
        format!("Status admitted for {id}\n")
    );
}

/// A CLI on this computer listens on the loopback interface and opens the approval page with its code. The approval
/// sends the browser to the listener with the one-use redirect code, and the CLI then finishes and signs a status call.
#[tokio::test]
async fn a_loopback_cli_finishes_with_the_redirect_that_the_browser_brings() {
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0")
        .await
        .expect("loopback listener");
    let port = listener.local_addr().expect("port").port();
    let origin = format!("http://localhost:{port}");
    let now = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .expect("system clock")
        .as_secs();
    let site = Site::at(&origin, now - 10);
    site.advance(10);
    let router = site.router.clone();
    tokio::spawn(async move { axum::serve(listener, router).await });
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
    site.sign_in(&mut browser, &passkey, handle).await;

    // The output of the CLI is no terminal, so it prints the address and opens no browser.
    let child = Command::new(env!("CARGO_BIN_EXE_native-cli"))
        .arg("enroll")
        .arg(site.issuer_dir.join("desktop"))
        .arg("Desktop")
        .arg(port.to_string())
        .stdout(Stdio::piped())
        .spawn()
        .expect("start the native CLI");
    let mut child = DropGuard::new(child, |mut child| {
        drop(child.kill());
        drop(child.wait());
    });
    let stdout = child.stdout.take().expect("the CLI output");
    let (mut stdout, opened, code) = tokio::task::spawn_blocking(move || {
        let mut reader = BufReader::new(stdout);
        let mut lines = (&mut reader).lines();
        let mut line = || lines.next().expect("CLI output").expect("a line");
        let opened = line();
        let code = line().strip_prefix("User code ").expect("the code").to_owned();
        line();
        (reader, opened, code)
    })
    .await
    .expect("the CLI prompt");
    assert_eq!(opened, format!("Open {origin}/cli?code={code}"));
    let review = format!(r#"{{"code":"{code}"}}"#);
    let shown = site.post(&mut browser, "/cli/request", review.as_bytes()).await;
    assert!(String::from_utf8_lossy(&shown).contains(r#""loopback":true"#));
    let id = member(&shown, "accountId");
    let approve = format!(r#"{{"code":"{code}","accountId":"{id}"}}"#);
    let approved = site.post(&mut browser, "/cli/approve", approve.as_bytes()).await;
    let redirect = member(&approved, "redirect");
    let (host, target) = redirect
        .strip_prefix("http://")
        .and_then(|address| address.split_once('/'))
        .expect("a loopback address");
    let mut stream = tokio::net::TcpStream::connect(host)
        .await
        .expect("the listener of the CLI");
    let request = format!("GET /{target} HTTP/1.1\r\nHost: {host}\r\n\r\n");
    stream.write_all(request.as_bytes()).await.expect("the redirect");
    let mut answer = String::new();
    stream.read_to_string(&mut answer).await.expect("the answer of the CLI");
    assert!(answer.starts_with("HTTP/1.1 200 OK\r\n"), "{answer}");

    let status = exit(&mut child).await;
    let mut tail = String::new();
    stdout.read_to_string(&mut tail).expect("the CLI result");
    assert!(status.success(), "{status} {tail}");
    assert_eq!(
        tail,
        format!("Approved account alice ({id})\nStatus admitted for {id}\n")
    );
}

/// The exit status of the CLI `child`, which finishes soon after the approval.
async fn exit(child: &mut std::process::Child) -> std::process::ExitStatus {
    tokio::time::timeout(Duration::from_secs(25), async {
        loop {
            if let Some(status) = child.try_wait().expect("the CLI process") {
                break status;
            }
            tokio::time::sleep(Duration::from_millis(50)).await;
        }
    })
    .await
    .expect("the CLI finishes after the approval")
}
