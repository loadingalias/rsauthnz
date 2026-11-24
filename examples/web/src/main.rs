//! The web example on `http://localhost:8080`. The store is the memory binding, so a restart loses each account.
//!
//! ```sh
//! cargo run --locked -p web
//! ```

// std's OS generator. Review this gate at each move of the pinned nightly (AGENTS.md toolchain review).
#![feature(random)]

mod serve;

fn main() -> Result<(), Box<dyn core::error::Error>> {
    let (transport, directory) = serve::arguments()?;
    let directory = match directory {
        Some(directory) => directory,
        None => std::env::home_dir()
            .ok_or("no home directory for the web issuer")?
            .join(".rsauthnz-web-example"),
    };
    serve::run(transport, &directory, "", axum::Router::new())
}
