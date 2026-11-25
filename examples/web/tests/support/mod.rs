//! The HTTP site, passkey ceremonies, and session cookie for the example journeys.

use core::sync::atomic::{AtomicU64, Ordering};
use core::time::Duration;
use std::sync::Arc;

use axum::Router;
use axum::body::Body;
use http::{Request, StatusCode};
use rsauthnz::time::{Reading, ReadingSource};
use rsauthnz_conformance::memory::{Memory, Schedule};
use rsauthnz_conformance::suite::Subject;
use rscodec::base64::Profile::Url;
use rscodec::json::{self, Slot};
use rscrypto::ChaCha20Rng;
use tower::ServiceExt as _;

use crate::authenticator::{self, Get, Passkey, Registration};

/// The site: its router, its store, and the clock of the host in whole seconds.
pub(crate) struct Site {
    pub(crate) origin: String,
    pub(crate) router: Router,
    pub(crate) memory: Memory,
    seconds: Arc<AtomicU64>,
    pub(crate) issuer_dir: std::path::PathBuf,
}

/// A browser: the session cookie that the site gave it.
#[derive(Default)]
pub(crate) struct Browser {
    pub(crate) cookie: Option<String>,
}

/// A response: its status and its body.
pub(crate) struct Reply {
    pub(crate) status: StatusCode,
    pub(crate) body: String,
}

impl Drop for Site {
    fn drop(&mut self) {
        std::fs::remove_dir_all(&self.issuer_dir).expect("remove the test issuer directory");
    }
}

impl Site {
    /// A new site at the start time of its memory store.
    pub(crate) fn at(origin: &str, start: u64) -> Self {
        let memory = Memory::new(Schedule::None);
        Self::on(origin, start, memory.clone(), memory).0
    }

    /// A new site on `store`, which keeps its records in `memory`, at the start time `start`. Also the application
    /// of the site.
    pub(crate) fn on<S: Subject + Send + 'static>(
        origin: &str,
        start: u64,
        store: S,
        memory: Memory,
    ) -> (Self, Arc<web::App<S>>) {
        let seconds = Arc::new(AtomicU64::new(start));
        let clock = Arc::clone(&seconds);
        let clock = Box::new(move || {
            Reading::new(
                Duration::from_secs(clock.load(Ordering::SeqCst)),
                Some(Duration::from_secs(1)),
                ReadingSource::Caller,
            )
        });
        static NEXT: AtomicU64 = AtomicU64::new(0);
        let issuer_dir = std::env::temp_dir().join(format!(
            "rsauthnz-web-test-{}-{}",
            std::process::id(),
            NEXT.fetch_add(1, Ordering::Relaxed)
        ));
        let app = web::App::new(origin, store, clock, ChaCha20Rng::from_seed([5; 32]), &issuer_dir).expect("the app");
        let app = Arc::new(app);
        let site = Self {
            origin: origin.to_owned(),
            router: web::router(Arc::clone(&app)),
            memory,
            seconds,
            issuer_dir,
        };
        (site, app)
    }

    pub(crate) fn advance(&self, seconds: u64) {
        self.seconds.fetch_add(seconds, Ordering::SeqCst);
    }

    /// The response to `browser` of a request with `method`, `path`, and `body`, from a page of the site. The browser
    /// keeps the session cookie of the response.
    pub(crate) async fn send(&self, browser: &mut Browser, method: &str, path: &str, body: &[u8]) -> Reply {
        let mut request = Request::builder()
            .method(method)
            .uri(path)
            .header("origin", &self.origin)
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
    pub(crate) async fn post(&self, browser: &mut Browser, path: &str, body: &[u8]) -> Vec<u8> {
        let reply = self.send(browser, "POST", path, body).await;
        assert_eq!(reply.status, StatusCode::OK, "{path} gives {}", reply.body);
        reply.body.into_bytes()
    }

    /// Registers `passkey` through the options and the finish of a ceremony, and gives the user handle of the options.
    pub(crate) async fn register(
        &self,
        browser: &mut Browser,
        (options, finish): (&str, &str),
        body: &[u8],
        passkey: &Passkey,
    ) -> [u8; 32] {
        let options = self.post(browser, options, body).await;
        let json = Registration::new(passkey, "localhost", &self.origin, authenticator::challenge(&options)).json();
        self.post(browser, finish, &json).await;
        user_id(&options)
    }

    /// A sign-in of `browser` with `passkey` of the account `handle`.
    pub(crate) async fn sign_in(&self, browser: &mut Browser, passkey: &Passkey, handle: [u8; 32]) {
        let options = self.post(browser, "/sign-in/options", b"{}").await;
        let json = Get::new(
            passkey,
            "localhost",
            &self.origin,
            authenticator::challenge(&options),
            handle,
        )
        .json();
        self.post(browser, "/sign-in/finish", &json).await;
        assert!(browser.cookie.is_some(), "the sign-in gives a session cookie");
    }
}

/// The user handle of the creation options `options`: the `id` of its `user`.
pub(crate) fn user_id(options: &[u8]) -> [u8; 32] {
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

/// The string member `name` of the JSON object `body`.
pub(crate) fn member(body: &[u8], name: &str) -> String {
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
