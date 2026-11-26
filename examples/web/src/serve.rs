//! The loopback server used by both web example binaries.

use core::random::Rng as _;
use core::time::Duration;
use std::path::{Path, PathBuf};
use std::random::SystemRng;
use std::sync::Arc;
use std::time::{SystemTime, UNIX_EPOCH};

use axum::{Router, extract::Request, http, middleware, response::IntoResponse as _};
use rsauthnz::time::{Reading, ReadingSource};
use rsauthnz_conformance::memory::{Memory, Schedule};
use rscrypto::ChaCha20Rng;

#[derive(Clone, Copy)]
pub(crate) enum Transport {
    Http,
    Https,
}

pub(crate) fn arguments() -> Result<(Transport, Option<PathBuf>), &'static str> {
    let mut args = std::env::args_os().skip(1).peekable();
    let transport = match args.next_if(|arg| arg == "--https") {
        Some(_) => Transport::Https,
        None => Transport::Http,
    };
    let directory = args.next().map(PathBuf::from);
    args.next()
        .is_none()
        .then_some((transport, directory))
        .ok_or("Use [--https] [ISSUER_DIRECTORY].")
}

impl Transport {
    pub(crate) const fn origin(self) -> &'static str {
        match self {
            Self::Http => "http://localhost:8080",
            Self::Https => "https://localhost:8443",
        }
    }
}

fn clock() -> Reading {
    match SystemTime::now().duration_since(UNIX_EPOCH) {
        Ok(time) => Reading::new(time, Some(Duration::from_secs(1)), ReadingSource::SystemClock),
        Err(_) => Reading::new(Duration::ZERO, None, ReadingSource::SystemClock),
    }
}

#[expect(clippy::print_stdout, reason = "the example prints the local page for the operator")]
pub(crate) fn run(
    transport: Transport,
    directory: &Path,
    page: &str,
    routes: Router,
) -> Result<(), Box<dyn core::error::Error>> {
    let Ok(random) = ChaCha20Rng::try_generate_with(|seed| {
        SystemRng.fill_bytes(seed);
        Ok::<_, !>(())
    });
    let origin = transport.origin();
    let store = Memory::new(Schedule::None).with_retention(web::RETENTION);
    let app = Arc::new(web::App::new(origin, store, Box::new(clock), random, directory)?);
    let router = web::router(Arc::clone(&app)).merge(routes);
    let (port, router) = match transport {
        Transport::Http => (8080, router),
        Transport::Https => (8081, router.layer(middleware::from_fn(cli_address))),
    };
    tokio::runtime::Builder::new_current_thread()
        .enable_io()
        .enable_time()
        .build()?
        .block_on(async {
            let listener = tokio::net::TcpListener::bind((core::net::Ipv4Addr::LOCALHOST, port)).await?;
            println!("Serving {origin}{page}. The store is in memory: a restart of this process loses each account.");
            println!("Stop the server with Ctrl-C. It first completes each request that it took.");
            web::serve(listener, router, &app, async {
                // With no signal handler, the server serves until the process ends.
                if tokio::signal::ctrl_c().await.is_err() {
                    core::future::pending::<()>().await;
                }
            })
            .await
        })?;
    Ok(())
}

/// The native CLI prints its loopback address. Send its browser navigation to the configured HTTPS site, with the
/// query that holds the user code.
async fn cli_address(request: Request, next: middleware::Next) -> axum::response::Response {
    if request.method() == http::Method::GET
        && request.uri().path() == "/cli"
        && request
            .headers()
            .get(http::header::HOST)
            .is_some_and(|host| host == "localhost:8081")
    {
        let query = request.uri().query().map_or(String::new(), |query| format!("?{query}"));
        return axum::response::Redirect::temporary(&format!("https://localhost:8443/cli{query}")).into_response();
    }
    next.run(request).await
}
