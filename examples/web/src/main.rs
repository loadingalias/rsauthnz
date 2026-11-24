//! The web example on `http://localhost:8080`. The store is the memory binding, so a restart loses each account.
//!
//! ```sh
//! cargo run --locked -p web
//! ```

// std's OS generator. Review this gate at each move of the pinned nightly (AGENTS.md toolchain review).
#![feature(random)]

use core::random::Rng as _;
use core::time::Duration;
use std::random::SystemRng;
use std::sync::Arc;
use std::time::{SystemTime, UNIX_EPOCH};

use rsauthnz::time::{Reading, ReadingSource};
use rsauthnz_conformance::memory::{Memory, Schedule};
use rscrypto::ChaCha20Rng;

/// The origin of the site. A browser keeps its `Secure` session cookie only when `localhost` is a secure context.
const ORIGIN: &str = "http://localhost:8080";

/// The address that serves the origin.
const ADDRESS: &str = "127.0.0.1:8080";

/// A reading of the system clock with a bound of one second. A clock before the Unix epoch gives no bound, so each
/// operation refuses.
fn clock() -> Reading {
    match SystemTime::now().duration_since(UNIX_EPOCH) {
        Ok(since_epoch) => Reading::new(since_epoch, Some(Duration::from_secs(1)), ReadingSource::SystemClock),
        Err(_) => Reading::new(Duration::ZERO, None, ReadingSource::SystemClock),
    }
}

#[expect(clippy::print_stdout, reason = "the example prints its address and its limit once")]
fn main() -> Result<(), Box<dyn core::error::Error>> {
    // The seed of the generator comes from the entropy source of the OS.
    let Ok(random) = ChaCha20Rng::try_generate_with(|seed| {
        SystemRng.fill_bytes(seed);
        Ok::<_, !>(())
    });
    let mut args = std::env::args_os().skip(1);
    let directory = match args.next() {
        Some(directory) => std::path::PathBuf::from(directory),
        None => std::env::home_dir()
            .ok_or("no home directory for the web issuer")?
            .join(".rsauthnz-web-example"),
    };
    if args.next().is_some() {
        return Err("Use web [ISSUER_DIRECTORY].".into());
    }
    let app = web::App::new(ORIGIN, Memory::new(Schedule::None), Box::new(clock), random, &directory)?;
    let runtime = tokio::runtime::Builder::new_current_thread()
        .enable_io()
        .enable_time()
        .build()?;
    runtime.block_on(async {
        let listener = tokio::net::TcpListener::bind(ADDRESS).await?;
        println!("Serving {ORIGIN}. The store is in memory: a restart of this process loses each account.");
        axum::serve(listener, web::router(Arc::new(app))).await
    })?;
    Ok(())
}
