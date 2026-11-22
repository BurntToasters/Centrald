//! HTTP routes.

mod account;
mod agent;
mod devices;
mod join;
mod misc;
mod runs;

pub use account::SETUP_CODE_KEY;

use axum::Router;
use axum::extract::{DefaultBodyLimit, Request, State};
use axum::http::header::{
    ALLOW, CACHE_CONTROL, CONTENT_SECURITY_POLICY, CONTENT_TYPE, HOST, REFERRER_POLICY,
    RETRY_AFTER, X_CONTENT_TYPE_OPTIONS, X_FRAME_OPTIONS,
};
use axum::http::{HeaderName, HeaderValue, StatusCode};
use axum::middleware::{self, Next};
use axum::response::{IntoResponse, Response};
use axum::routing::{get, post};

use crate::error::ApiError;
use crate::session;
use crate::state::Shared;

const CSP: &str = "default-src 'self'; script-src 'self'; style-src 'self' 'unsafe-inline'; \
    img-src 'self' data:; connect-src 'self'; font-src 'self'; object-src 'none'; \
    base-uri 'none'; form-action 'self'; frame-ancestors 'none'";

pub fn router(state: Shared) -> Router {
    // Browser routes: session auth plus the same-origin guard.
    let browser = Router::new()
        .route("/state", get(account::get_state))
        .route("/setup", post(account::setup))
        .route("/login", post(account::login))
        .route("/logout", post(account::logout))
        .route("/account/password", post(account::change_password))
        .route("/account/totp/setup", post(account::totp_setup))
        .route("/account/totp/enable", post(account::totp_enable))
        .route("/account/totp/disable", post(account::totp_disable))
        .route(
            "/users",
            get(account::list_users).post(account::create_user),
        )
        .route("/users/{id}", axum::routing::delete(account::delete_user))
        .route("/devices", get(devices::list))
        .route(
            "/devices/{id}",
            get(devices::get)
                .patch(devices::update)
                .delete(devices::remove),
        )
        .route("/devices/{id}/metrics", get(devices::metrics))
        .route(
            "/devices/{id}/terminal",
            get(devices::terminal).connect(devices::terminal),
        )
        .route("/join-tokens", get(join::list).post(join::create))
        .route("/join-tokens/{id}", axum::routing::delete(join::revoke))
        .route("/runs", get(runs::list).post(runs::create))
        .route("/runs/{id}", get(runs::get))
        .route("/runs/{id}/cancel", post(runs::cancel))
        .route("/audit", get(misc::audit))
        .route("/server", get(misc::server))
        .route("/server/ca.crt", get(misc::ca_certificate))
        .route("/events", get(misc::events).connect(misc::events))
        .layer(middleware::from_fn_with_state(
            state.clone(),
            session::same_origin,
        ));

    // Agent routes authenticate with join secrets or device credentials and
    // never carry cookies, so the origin guard does not apply.
    let agents = Router::new()
        .route("/enroll", post(agent::enroll))
        .route("/connect", get(agent::connect).connect(agent::connect));

    let api = Router::new()
        .merge(browser)
        .nest("/agent", agents)
        .fallback(|| async { ApiError::not_found("No such API endpoint.") })
        .layer(middleware::from_fn(json_errors))
        .layer(middleware::from_fn(no_store));

    Router::new()
        .nest("/api", api)
        .route("/install.sh", get(join::install_sh))
        .route("/install.ps1", get(join::install_ps1))
        .route("/download/agent/{os}/{arch}", get(join::agent_binary))
        .fallback(crate::ui::serve)
        .layer(DefaultBodyLimit::max(64 * 1024))
        .layer(middleware::from_fn_with_state(state.clone(), host_guard))
        .layer(middleware::from_fn(security_headers))
        .with_state(state)
}

/// Answers 421 to a `Host` or `:authority` that does not name this server,
/// which defeats DNS rebinding. Agent paths are exempt: agents pin the CA
/// and dial whatever address their join code holds.
async fn host_guard(State(state): State<Shared>, request: Request, next: Next) -> Response {
    let path = request.uri().path();
    let exempt = path.starts_with("/api/agent/") || path.starts_with("/download/agent/");
    let header = request
        .headers()
        .get(HOST)
        .map(|v| v.to_str().ok().is_some_and(|h| state.tls.allows_host(h)));
    let authority = request
        .uri()
        .authority()
        .map(|a| state.tls.allows_host(a.as_str()));
    if exempt || (header != Some(false) && authority != Some(false)) {
        return next.run(request).await;
    }
    ApiError::new(
        StatusCode::MISDIRECTED_REQUEST,
        "This server does not answer to that name. Use its IP address, or add the name to CENTRALD_HOSTNAMES on the server.",
    )
    .into_response()
}

/// Gives every API error a JSON body, including axum's own rejections
/// (bad JSON, wrong method), which are plain text by default.
async fn json_errors(request: Request, next: Next) -> Response {
    let response = next.run(request).await;
    let status = response.status();
    let is_json = response
        .headers()
        .get(CONTENT_TYPE)
        .and_then(|v| v.to_str().ok())
        .is_some_and(|v| v.starts_with("application/json"));
    if !(status.is_client_error() || status.is_server_error()) || is_json {
        return response;
    }
    let (parts, body) = response.into_parts();
    let text = axum::body::to_bytes(body, 4096)
        .await
        .map(|bytes| String::from_utf8_lossy(&bytes).trim().to_owned())
        .unwrap_or_default();
    let message = if text.is_empty() {
        status
            .canonical_reason()
            .unwrap_or("Request failed")
            .to_owned()
    } else {
        text
    };
    let mut fixed = ApiError::new(status, message).into_response();
    for name in [ALLOW, RETRY_AFTER] {
        if let Some(value) = parts.headers.get(&name) {
            fixed.headers_mut().insert(name, value.clone());
        }
    }
    fixed
}

async fn no_store(request: Request, next: Next) -> Response {
    let mut response = next.run(request).await;
    response
        .headers_mut()
        .insert(CACHE_CONTROL, HeaderValue::from_static("no-store"));
    response
}

async fn security_headers(request: Request, next: Next) -> Response {
    let mut response = next.run(request).await.into_response();
    let headers = response.headers_mut();
    headers.insert(CONTENT_SECURITY_POLICY, HeaderValue::from_static(CSP));
    headers.insert(X_CONTENT_TYPE_OPTIONS, HeaderValue::from_static("nosniff"));
    headers.insert(X_FRAME_OPTIONS, HeaderValue::from_static("DENY"));
    headers.insert(REFERRER_POLICY, HeaderValue::from_static("no-referrer"));
    headers.insert(
        HeaderName::from_static("cross-origin-opener-policy"),
        HeaderValue::from_static("same-origin"),
    );
    headers.insert(
        HeaderName::from_static("permissions-policy"),
        HeaderValue::from_static("camera=(), microphone=(), geolocation=()"),
    );
    response
}

/// Close frame for a failed browser socket read: 1009 when the peer sent
/// more than the size limit, 1002 for other protocol errors.
fn read_error_close(error: &axum::Error) -> axum::extract::ws::CloseFrame {
    // axum hides the tungstenite error type; its message names the limit.
    let text = error.to_string();
    let code = if text.contains("too long") || text.contains("Space limit") {
        1009
    } else {
        1002
    };
    axum::extract::ws::CloseFrame {
        code,
        reason: "".into(),
    }
}
