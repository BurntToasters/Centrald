//! Browser sessions: the signed-in user extractor, cookies, and the
//! same-origin guard for state-changing requests.

use axum::extract::{ConnectInfo, FromRequestParts, Request, State};
use axum::http::header::{COOKIE, HOST, ORIGIN, SET_COOKIE, USER_AGENT};
use axum::http::request::Parts;
use axum::http::{HeaderMap, HeaderValue, Method, Uri};
use axum::middleware::Next;
use axum::response::{IntoResponse, Response};
use rusqlite::OptionalExtension;

use crate::auth::{SESSION_COOKIE, SESSION_IDLE_SECONDS, SESSION_MAX_SECONDS, session_hash};
use crate::db::now;
use crate::error::ApiError;
use crate::net::ClientAddr;
use crate::state::Shared;

/// The signed-in operator behind a request.
#[derive(Debug, Clone)]
pub struct CurrentUser {
    pub id: String,
    pub username: String,
    pub totp_enabled: bool,
    pub session_hash: [u8; 32],
    pub address: String,
}

impl FromRequestParts<Shared> for CurrentUser {
    type Rejection = ApiError;

    async fn from_request_parts(parts: &mut Parts, state: &Shared) -> Result<Self, ApiError> {
        let address = client_address(parts);
        let token = session_cookie(&parts.headers)
            .ok_or_else(|| ApiError::unauthorized("Sign in to continue."))?;
        let hash = session_hash(&token);
        let user = load_session(state, hash).await?;
        let (id, username, totp_enabled) =
            user.ok_or_else(|| ApiError::unauthorized("Your session has ended. Sign in again."))?;
        Ok(Self {
            id,
            username,
            totp_enabled,
            session_hash: hash,
            address,
        })
    }
}

/// Validates a session and slides its idle window forward.
pub async fn load_session(
    state: &Shared,
    hash: [u8; 32],
) -> Result<Option<(String, String, bool)>, ApiError> {
    Ok(state
        .db
        .call(move |c| {
            let time = now();
            let row = c
                .query_row(
                    "SELECT u.id, u.username, u.totp_enabled, s.last_seen_at
                     FROM sessions s JOIN users u ON u.id = s.user_id
                     WHERE s.token_hash = ?1 AND s.expires_at > ?2 AND s.last_seen_at > ?3",
                    rusqlite::params![hash, time, time - SESSION_IDLE_SECONDS],
                    |row| {
                        Ok((
                            row.get::<_, String>(0)?,
                            row.get::<_, String>(1)?,
                            row.get::<_, bool>(2)?,
                            row.get::<_, i64>(3)?,
                        ))
                    },
                )
                .optional()?;
            let Some((id, username, totp, last_seen)) = row else {
                return Ok(None);
            };
            // Avoid a write per request; a minute of precision is plenty.
            if time - last_seen > 60 {
                c.execute(
                    "UPDATE sessions SET last_seen_at = ?2 WHERE token_hash = ?1",
                    rusqlite::params![hash, time],
                )?;
            }
            Ok(Some((id, username, totp)))
        })
        .await?)
}

/// Creates a session row and returns the `Set-Cookie` header for it.
pub async fn start_session(
    state: &Shared,
    user_id: String,
    headers: &HeaderMap,
    address: String,
) -> Result<HeaderValue, ApiError> {
    let (token, hash) = crate::auth::new_session_token();
    let user_agent: String = headers
        .get(USER_AGENT)
        .and_then(|v| v.to_str().ok())
        .unwrap_or("")
        .chars()
        .take(200)
        .collect();
    state
        .db
        .call(move |c| {
            let time = now();
            // Expired rows are cleaned up opportunistically.
            c.execute(
                "DELETE FROM sessions WHERE expires_at <= ?1 OR last_seen_at <= ?2",
                rusqlite::params![time, time - SESSION_IDLE_SECONDS],
            )?;
            c.execute(
                "INSERT INTO sessions
                     (token_hash, user_id, created_at, last_seen_at, expires_at, address, user_agent)
                 VALUES (?1, ?2, ?3, ?3, ?4, ?5, ?6)",
                rusqlite::params![
                    hash,
                    user_id,
                    time,
                    time + SESSION_MAX_SECONDS,
                    address,
                    user_agent
                ],
            )?;
            Ok(())
        })
        .await?;
    let cookie = format!(
        "{SESSION_COOKIE}={token}; Path=/; Secure; HttpOnly; SameSite=Strict; Max-Age={SESSION_MAX_SECONDS}"
    );
    HeaderValue::from_str(&cookie).map_err(|e| anyhow::anyhow!("cookie: {e}").into())
}

pub fn clear_cookie() -> (axum::http::HeaderName, HeaderValue) {
    (
        SET_COOKIE,
        HeaderValue::from_static(
            "__Host-centrald=; Path=/; Secure; HttpOnly; SameSite=Strict; Max-Age=0",
        ),
    )
}

pub fn session_cookie(headers: &HeaderMap) -> Option<String> {
    headers
        .get_all(COOKIE)
        .iter()
        .filter_map(|value| value.to_str().ok())
        .flat_map(|value| value.split(';'))
        .find_map(|pair| {
            let (name, value) = pair.trim().split_once('=')?;
            (name == SESSION_COOKIE && !value.is_empty()).then(|| value.to_owned())
        })
}

/// `Host` for HTTP/1.1, or the URI authority HTTP/2 carries instead.
pub fn request_host<'a>(headers: &'a HeaderMap, uri: &'a Uri) -> Option<&'a str> {
    headers
        .get(HOST)
        .and_then(|v| v.to_str().ok())
        .or_else(|| uri.authority().map(axum::http::uri::Authority::as_str))
}

pub fn client_address(parts: &Parts) -> String {
    parts
        .extensions
        .get::<ConnectInfo<ClientAddr>>()
        .map(|info| info.0.0.ip().to_string())
        .unwrap_or_default()
}

/// Rejects cross-site state changes and cross-site WebSocket upgrades.
///
/// The session cookie is already `SameSite=Strict`; this is the second
/// layer. Browsers always send `Origin` on these requests.
pub async fn same_origin(State(_): State<Shared>, request: Request, next: Next) -> Response {
    let is_upgrade = request.headers().contains_key(axum::http::header::UPGRADE);
    let safe = matches!(*request.method(), Method::GET | Method::HEAD) && !is_upgrade;
    if !safe && !origin_matches(request.headers(), request.uri()) {
        return ApiError::forbidden("This request did not come from the CentralD web app.")
            .into_response();
    }
    next.run(request).await
}

fn origin_matches(headers: &HeaderMap, uri: &Uri) -> bool {
    let Some(origin) = headers.get(ORIGIN).and_then(|v| v.to_str().ok()) else {
        return false;
    };
    let Some(host) = request_host(headers, uri) else {
        return false;
    };
    origin
        .strip_prefix("https://")
        .is_some_and(|rest| rest.eq_ignore_ascii_case(host))
}

/// The peer's IP address as text; empty if unknown.
#[derive(Debug, Clone)]
pub struct Peer(pub String);

impl<S: Send + Sync> FromRequestParts<S> for Peer {
    type Rejection = std::convert::Infallible;

    async fn from_request_parts(parts: &mut Parts, _state: &S) -> Result<Self, Self::Rejection> {
        Ok(Self(client_address(parts)))
    }
}
