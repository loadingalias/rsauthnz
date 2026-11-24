//! Runs the web example with an observation page for real browser passkey providers.

#![feature(random)]

#[path = "../src/serve.rs"]
mod serve;

use axum::extract::DefaultBodyLimit;
use axum::http::{HeaderMap, StatusCode, header};
use axum::response::Html;
use axum::routing::{get, post};

/// Accept only named observations and public WebAuthn metadata from the local page.
#[expect(
    clippy::print_stdout,
    reason = "the operator records these observations for the provider run"
)]
async fn observe(origin: &str, headers: HeaderMap, body: String) -> StatusCode {
    if headers.get(header::ORIGIN).and_then(|v| v.to_str().ok()) != Some(origin) {
        return StatusCode::FORBIDDEN;
    }
    let Some((event, values)) = body.split_once(' ') else {
        return StatusCode::BAD_REQUEST;
    };
    if !matches!(
        event,
        "page"
            | "conditional-get"
            | "conditional-create"
            | "signup-offer"
            | "add-offer"
            | "invite-offer"
            | "recover-offer"
            | "signup"
            | "add"
            | "activate"
            | "recover"
            | "signin"
            | "account"
            | "renew"
            | "revoke"
            | "signout"
            | "remove"
            | "rename"
            | "unknown-credential"
            | "accepted-credentials"
            | "user-details"
            | "provider-create"
            | "provider-get"
            | "conditional-result"
            | "consent"
    ) {
        return StatusCode::BAD_REQUEST;
    }
    if values.is_empty()
        || !values.split(' ').all(|value| {
            matches!(
                value,
                "ready"
                    | "yes"
                    | "no"
                    | "missing"
                    | "ok"
                    | "refused"
                    | "unsupported"
                    | "canceled"
                    | "not-allowed"
                    | "stopped"
                    | "platform"
                    | "cross-platform"
                    | "unknown"
                    | "verify"
                    | "restart"
                    | "forget"
                    | "check"
                    | "refuse"
                    | "uv"
                    | "no-uv"
                    | "backup-eligible"
                    | "device-bound"
                    | "backed-up"
                    | "not-backed-up"
            ) || value.parse::<i16>().is_ok_and(|number| number.to_string() == value)
        })
    {
        return StatusCode::BAD_REQUEST;
    }
    let agent = headers
        .get(header::USER_AGENT)
        .and_then(|v| v.to_str().ok())
        .unwrap_or("");
    let browser = if agent.contains("Firefox/") {
        "Firefox"
    } else if agent.contains("Chrome/") {
        "Chrome"
    } else if agent.contains("Safari/") {
        "Safari"
    } else {
        "Other"
    };
    println!("{browser} {event} {values}");
    StatusCode::NO_CONTENT
}

fn main() -> Result<(), Box<dyn core::error::Error>> {
    let (transport, directory) = serve::arguments()?;
    let directory = directory.ok_or("Use providers [--https] ISSUER_DIRECTORY.")?;
    let (before, after) = include_str!("../www/index.html")
        .split_once(r#"<script type="module" src="/app.js"></script>"#)
        .ok_or("The account page needs its app.js module.")?;
    let page = Html(format!("{before}{}{after}", include_str!("providers/page.html")));
    let routes = axum::Router::new()
        .route("/run", get(move || async move { page }))
        .route(
            "/run/observe.js",
            get(|| async {
                (
                    [(header::CONTENT_TYPE, "text/javascript; charset=utf-8")],
                    include_str!("providers/observe.js"),
                )
            }),
        )
        .route(
            "/run/observation",
            post(move |headers, body| observe(transport.origin(), headers, body)).layer(DefaultBodyLimit::max(192)),
        );
    serve::run(transport, &directory, "/run", routes)
}
