//! Join codes for adding devices, the install scripts, and agent downloads.

use axum::Json;
use axum::extract::{Path, State};
use axum::http::header::{CACHE_CONTROL, CONTENT_DISPOSITION, CONTENT_LENGTH, CONTENT_TYPE};
use axum::http::{HeaderMap, StatusCode, Uri};
use axum::response::{IntoResponse, Response};
use centrald_proto::join::{JoinCode, validate_server_address};
use serde::{Deserialize, Serialize};
use serde_json::json;

use crate::db::{self, now};
use crate::downloads;
use crate::error::{ApiError, ApiResult};
use crate::hub::Event;
use crate::model::{self, JoinTokenView};
use crate::session::{CurrentUser, request_host};
use crate::state::Shared;

const DEFAULT_EXPIRY_HOURS: u32 = 24;
const MAX_EXPIRY_HOURS: u32 = 7 * 24;

#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct CreateRequest {
    /// Optional display name for the device that uses this code.
    #[serde(default)]
    name: String,
    /// `host:port` devices should dial; the web app pre-fills the address the
    /// browser used.
    server_address: String,
    #[serde(default)]
    expires_in_hours: Option<u32>,
    /// Install commands enroll the device as monitor-only.
    #[serde(default)]
    monitor_only: bool,
}

#[derive(Debug, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct CreatedToken {
    id: String,
    code: String,
    expires_at: i64,
    servers: Vec<String>,
    linux_command: String,
    windows_command: String,
}

/// Other addresses of this host, so a device can still reach the server if
/// the address the browser used (say `localhost`) means nothing to it.
fn fallback_addresses(port: u16, preferred: &str) -> Vec<String> {
    let mut found = Vec::new();
    if let Ok(interfaces) = if_addrs::get_if_addrs() {
        for interface in interfaces {
            let ip = interface.ip();
            if ip.is_loopback() || !ip.is_ipv4() {
                continue;
            }
            let address = format!("{ip}:{port}");
            if address != preferred && !found.contains(&address) {
                found.push(address);
            }
        }
    }
    found
}

fn is_loopback_host(address: &str) -> bool {
    let host = address.rsplit_once(':').map_or(address, |(h, _)| h);
    host.eq_ignore_ascii_case("localhost") || host.starts_with("127.") || host == "[::1]"
}

pub async fn create(
    State(state): State<Shared>,
    user: CurrentUser,
    Json(body): Json<CreateRequest>,
) -> ApiResult<(StatusCode, Json<CreatedToken>)> {
    let preferred = body.server_address.trim().to_ascii_lowercase();
    validate_server_address(&preferred).map_err(|_| {
        ApiError::bad_request(
            "Enter the server address as host:port, for example 192.168.1.10:7443.",
        )
    })?;
    let name = if body.name.trim().is_empty() {
        String::new()
    } else {
        super::devices::clean_name(&body.name)?
    };
    let hours = body
        .expires_in_hours
        .unwrap_or(DEFAULT_EXPIRY_HOURS)
        .clamp(1, MAX_EXPIRY_HOURS);

    let port = preferred
        .rsplit_once(':')
        .and_then(|(_, p)| p.parse().ok())
        .unwrap_or(state.config.listen.port());
    let mut servers = vec![preferred.clone()];
    for address in fallback_addresses(port, &preferred) {
        if servers.len() >= 4 {
            break;
        }
        servers.push(address);
    }
    // Agents on other machines should try a LAN address first; the install
    // command still uses exactly what the operator typed.
    if is_loopback_host(&preferred) && servers.len() > 1 {
        servers.rotate_left(1);
    }

    let code = JoinCode::generate(servers.clone(), state.tls.ca_fingerprint)
        .map_err(|e| ApiError::bad_request(e.to_string()))?;
    let encoded = code.encode();
    let secret_hash = code.secret_hash();
    let id = uuid::Uuid::new_v4().to_string();
    let expires_at = now() + i64::from(hours) * 3600;
    let token_id = id.clone();
    let token_name = name.clone();
    state
        .db
        .call(move |c| {
            c.execute(
                "INSERT INTO join_tokens (id, name, secret_hash, created_by, created_at, expires_at)
                 VALUES (?1, ?2, ?3, ?4, ?5, ?6)",
                rusqlite::params![token_id, token_name, secret_hash, user.username, now(), expires_at],
            )?;
            let label = if token_name.is_empty() { "unnamed device" } else { &token_name };
            db::audit(c, &user.username, "join_code.created", label, &format!("valid {hours} h"), &user.address)?;
            Ok(())
        })
        .await?;
    state.hub.emit(&Event::JoinTokens);

    let (pin, leaf) = state.tls.browser_pins();
    let (linux_command, windows_command) =
        downloads::install_commands(&preferred, &pin, &leaf, &encoded, body.monitor_only);
    Ok((
        StatusCode::CREATED,
        Json(CreatedToken {
            id,
            code: encoded,
            expires_at,
            servers,
            linux_command,
            windows_command,
        }),
    ))
}

pub async fn list(
    State(state): State<Shared>,
    _user: CurrentUser,
) -> ApiResult<Json<Vec<JoinTokenView>>> {
    Ok(Json(
        state.db.call(|c| model::list_join_tokens(c, now())).await?,
    ))
}

pub async fn revoke(
    State(state): State<Shared>,
    user: CurrentUser,
    Path(id): Path<String>,
) -> ApiResult<Json<serde_json::Value>> {
    let removed = state
        .db
        .call(move |c| {
            let changed = c.execute(
                "DELETE FROM join_tokens WHERE id = ?1 AND used_at IS NULL",
                [&id],
            )?;
            if changed == 1 {
                db::audit(
                    c,
                    &user.username,
                    "join_code.revoked",
                    &id,
                    "",
                    &user.address,
                )?;
            }
            Ok(changed == 1)
        })
        .await?;
    if !removed {
        return Err(ApiError::not_found(
            "That join code was already used or removed.",
        ));
    }
    state.hub.emit(&Event::JoinTokens);
    Ok(Json(json!({ "ok": true })))
}

fn script_host(state: &Shared, headers: &HeaderMap, uri: &Uri) -> ApiResult<String> {
    let host = request_host(headers, uri)
        .unwrap_or_default()
        .to_ascii_lowercase();
    let host = if host.contains(':') && !host.ends_with(']') {
        host
    } else {
        format!("{host}:{}", state.config.listen.port())
    };
    validate_server_address(&host).map_err(|_| ApiError::bad_request("Invalid Host header."))?;
    Ok(host)
}

fn text(content_type: &'static str, body: String) -> Response {
    (
        [(CONTENT_TYPE, content_type), (CACHE_CONTROL, "no-store")],
        body,
    )
        .into_response()
}

pub async fn install_sh(
    State(state): State<Shared>,
    headers: HeaderMap,
    uri: Uri,
) -> ApiResult<Response> {
    let host = script_host(&state, &headers, &uri)?;
    let (pin, _) = state.tls.browser_pins();
    Ok(text(
        "text/x-shellscript; charset=utf-8",
        downloads::install_sh(&host, &pin),
    ))
}

pub async fn install_ps1(
    State(state): State<Shared>,
    headers: HeaderMap,
    uri: Uri,
) -> ApiResult<Response> {
    let host = script_host(&state, &headers, &uri)?;
    let (_, leaf) = state.tls.browser_pins();
    Ok(text(
        "text/plain; charset=utf-8",
        downloads::install_ps1(&host, &leaf),
    ))
}

/// `/download/agent/{os}/{arch}` and `…/{arch}.sha256`.
pub async fn agent_binary(
    State(state): State<Shared>,
    Path((os, arch)): Path<(String, String)>,
) -> ApiResult<Response> {
    let (arch, checksum) = match arch.strip_suffix(".sha256") {
        Some(arch) => (arch.to_owned(), true),
        None => (arch, false),
    };
    let build = state.builds.find(&os, &arch).ok_or_else(|| {
        ApiError::not_found(format!(
            "This server has no {os} {arch} agent. Install the agent package for that platform on the server."
        ))
    })?;
    if checksum {
        return Ok(text("text/plain; charset=utf-8", build.sha256));
    }
    let (length, body) = downloads::stream_file(&build.path).await?;
    let disposition = format!(
        "attachment; filename=\"{}\"",
        if os == "windows" {
            "centrald-agent.exe"
        } else {
            "centrald-agent"
        }
    );
    Ok((
        [
            (CONTENT_TYPE, "application/octet-stream".to_owned()),
            (CONTENT_DISPOSITION, disposition),
            (CACHE_CONTROL, "no-store".to_owned()),
            (CONTENT_LENGTH, length.to_string()),
        ],
        body,
    )
        .into_response())
}
