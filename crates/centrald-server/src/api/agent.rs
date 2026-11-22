//! The agent side of the API: enrollment and the long-lived connection.

use std::time::Duration;

use axum::Json;
use axum::extract::State;
use axum::extract::ws::{Message, WebSocket, WebSocketUpgrade};
use axum::http::HeaderMap;
use axum::http::header::AUTHORIZATION;
use axum::response::Response;
use base64::Engine;
use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use centrald_proto::limits::{MAX_ID_BYTES, MAX_MESSAGE_BYTES, STATUS_INTERVAL_SECONDS};
use centrald_proto::wire::{
    AgentMessage, EnrollRequest, EnrollResponse, Hello, ServerMessage, Status, Welcome,
};
use centrald_proto::{PROTOCOL_VERSION, sha256};
use rand::RngCore;
use rusqlite::OptionalExtension;

use crate::auth::constant_time_eq;
use crate::db::{self, now};
use crate::error::{ApiError, ApiResult};
use crate::hub::{AgentLink, Event, SOCKET_SEND_TIMEOUT};
use crate::session::Peer;
use crate::state::Shared;

const HELLO_TIMEOUT: Duration = Duration::from_secs(10);
const PING_INTERVAL: Duration = Duration::from_secs(30);
/// An agent that sends nothing (not even a pong) for this long is gone.
const SILENCE_LIMIT: Duration = Duration::from_secs(90);
/// Time allowed to deliver queued messages to a connection being closed.
const CLOSE_FLUSH: Duration = Duration::from_secs(2);

/// Exchanges a one-time join secret for a device credential.
#[allow(clippy::too_many_lines)]
pub async fn enroll(
    State(state): State<Shared>,
    Peer(address): Peer,
    Json(mut body): Json<EnrollRequest>,
) -> ApiResult<Json<EnrollResponse>> {
    let key = format!("enroll:{address}");
    state
        .agent_limiter
        .check(&key)
        .map_err(ApiError::too_many)?;
    if body.protocol != PROTOCOL_VERSION {
        return Err(ApiError::bad_request(format!(
            "This agent speaks protocol {} but the server speaks {PROTOCOL_VERSION}. Install the agent offered by this server.",
            body.protocol
        )));
    }
    let secret = hex::decode(body.secret.trim())
        .ok()
        .filter(|s| s.len() == centrald_proto::join::SECRET_BYTES)
        .ok_or_else(|| {
            state.agent_limiter.record_failure(&key);
            ApiError::bad_request("The join code is malformed.")
        })?;
    let mut hello = Hello {
        protocol: body.protocol,
        agent_version: std::mem::take(&mut body.agent_version),
        hostname: std::mem::take(&mut body.hostname),
        os: std::mem::take(&mut body.os),
        allow_commands: body.allow_commands,
        package_managed: body.package_managed,
    };
    hello.sanitize();

    let secret_hash = sha256(&secret);
    let mut token_bytes = [0_u8; 32];
    rand::rng().fill_bytes(&mut token_bytes);
    let token = URL_SAFE_NO_PAD.encode(token_bytes);
    let token_hash = sha256(token.as_bytes());
    let device_id = uuid::Uuid::new_v4().to_string();

    let new_id = device_id.clone();
    let audit_address = address.clone();
    let outcome = state
        .db
        .call(move |c| {
            let tx = c.transaction()?;
            let row: Option<(String, String, String, i64, Option<i64>)> = tx
                .query_row(
                    "SELECT id, name, created_by, expires_at, used_at FROM join_tokens
                     WHERE secret_hash = ?1",
                    [secret_hash],
                    |r| Ok((r.get(0)?, r.get(1)?, r.get(2)?, r.get(3)?, r.get(4)?)),
                )
                .optional()?;
            let Some((token_id, name, created_by, expires_at, used_at)) = row else {
                return Ok(Err(
                    "This join code is not valid. Create a new one in the web app.",
                ));
            };
            if used_at.is_some() {
                return Ok(Err(
                    "This join code was already used. Create a new one in the web app.",
                ));
            }
            if expires_at <= now() {
                return Ok(Err(
                    "This join code has expired. Create a new one in the web app.",
                ));
            }
            let name = if name.is_empty() {
                hello.hostname.clone()
            } else {
                name
            };
            let name = if name.is_empty() {
                "New device".to_owned()
            } else {
                name
            };
            tx.execute(
                "UPDATE join_tokens SET used_at = ?2, device_id = ?3 WHERE id = ?1",
                rusqlite::params![token_id, now(), new_id],
            )?;
            tx.execute(
                "INSERT INTO devices (id, name, token_hash, hostname, os_json, agent_version,
                     allow_commands, package_managed, enrolled_at, last_address)
                 VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, ?10)",
                rusqlite::params![
                    new_id,
                    name,
                    token_hash,
                    hello.hostname,
                    serde_json::to_string(&hello.os)?,
                    hello.agent_version,
                    hello.allow_commands,
                    hello.package_managed,
                    now(),
                    audit_address
                ],
            )?;
            let mode = if hello.allow_commands {
                "full control"
            } else {
                "monitor-only"
            };
            db::audit(
                &tx,
                &created_by,
                "device.enrolled",
                &name,
                &format!("{} ({mode})", hello.os.name),
                &audit_address,
            )?;
            tx.commit()?;
            Ok(Ok(name))
        })
        .await?;
    match outcome {
        Ok(name) => {
            state.agent_limiter.record_success(&key);
            state.hub.emit_device(&device_id).await;
            state.hub.emit(&Event::JoinTokens);
            tracing::info!(device = %name, %address, "device enrolled");
            Ok(Json(EnrollResponse {
                device_id,
                token,
                name,
            }))
        }
        Err(message) => {
            state.agent_limiter.record_failure(&key);
            Err(ApiError::forbidden(message))
        }
    }
}

/// Authenticates an agent by its bearer credential, then upgrades.
///
/// A credential that verifies always gets through: failures are counted per
/// address and device id, so nobody sharing the agent's address can lock it
/// out. Malformed requests are counted per address.
pub async fn connect(
    State(state): State<Shared>,
    Peer(address): Peer,
    headers: HeaderMap,
    upgrade: WebSocketUpgrade,
) -> ApiResult<Response> {
    let credential = headers
        .get(AUTHORIZATION)
        .and_then(|v| v.to_str().ok())
        .and_then(|v| v.strip_prefix("Bearer "))
        .and_then(|v| v.split_once('.'))
        .filter(|(id, token)| id.len() <= MAX_ID_BYTES && token.len() <= 128)
        .map(|(id, token)| (id.to_owned(), token.to_owned()));
    let Some((device_id, token)) = credential else {
        let key = format!("agent:{address}");
        state
            .agent_limiter
            .check(&key)
            .map_err(ApiError::too_many)?;
        state.agent_limiter.record_failure(&key);
        return Err(ApiError::unauthorized("Missing device credential."));
    };
    let key = format!("agent:{address}:{device_id}");
    let lookup = device_id.clone();
    let stored: Option<(Vec<u8>, bool)> = state
        .db
        .call(move |c| {
            Ok(c.query_row(
                "SELECT token_hash, allow_commands FROM devices WHERE id = ?1",
                [lookup],
                |r| Ok((r.get(0)?, r.get(1)?)),
            )
            .optional()?)
        })
        .await?;
    let presented = sha256(token.as_bytes());
    let Some((hash, _)) = stored.filter(|(hash, _)| constant_time_eq(hash, &presented)) else {
        state
            .agent_limiter
            .check(&key)
            .map_err(ApiError::too_many)?;
        state.agent_limiter.record_failure(&key);
        // Agents stop retrying quickly on this exact status.
        return Err(ApiError::unauthorized(
            "This device is not enrolled with this server. Enroll it again.",
        ));
    };
    drop(hash);
    state.agent_limiter.record_success(&key);
    Ok(upgrade
        .max_message_size(MAX_MESSAGE_BYTES)
        .max_frame_size(MAX_MESSAGE_BYTES)
        .on_upgrade(move |socket| agent_session(state, device_id, socket, address)))
}

/// Sends one message; a device that does not take it in time is dropped.
async fn send(socket: &mut WebSocket, message: &ServerMessage) -> bool {
    let Ok(text) = serde_json::to_string(message) else {
        return false;
    };
    matches!(
        tokio::time::timeout(SOCKET_SEND_TIMEOUT, socket.send(Message::Text(text.into()))).await,
        Ok(Ok(()))
    )
}

async fn agent_session(state: Shared, device_id: String, mut socket: WebSocket, address: String) {
    let hello = match tokio::time::timeout(HELLO_TIMEOUT, socket.recv()).await {
        Ok(Some(Ok(Message::Text(text)))) => match serde_json::from_str::<AgentMessage>(&text) {
            Ok(AgentMessage::Hello(hello)) => hello,
            _ => return,
        },
        _ => return,
    };
    let mut hello = hello;
    if hello.protocol != PROTOCOL_VERSION {
        tracing::warn!(device = %device_id, protocol = hello.protocol, "agent protocol mismatch");
        return;
    }
    hello.sanitize();
    let allow_commands = hello.allow_commands;
    let id = device_id.clone();
    let seen_address = address.clone();
    let stored = state
        .db
        .call(move |c| {
            Ok(c.execute(
                "UPDATE devices SET hostname = ?2, os_json = ?3, agent_version = ?4,
                     allow_commands = ?5, package_managed = ?6, last_seen_at = ?7,
                     last_address = ?8
                 WHERE id = ?1",
                rusqlite::params![
                    id,
                    hello.hostname,
                    serde_json::to_string(&hello.os)?,
                    hello.agent_version,
                    hello.allow_commands,
                    hello.package_managed,
                    now(),
                    seen_address
                ],
            )?)
        })
        .await;
    if !matches!(stored, Ok(1)) {
        return;
    }

    let mut link = state.hub.register_agent(&device_id, allow_commands);
    let connection = link.connection;
    tracing::info!(device = %device_id, %address, "agent connected");
    let welcome = ServerMessage::Welcome(Welcome {
        server_version: centrald_proto::VERSION.to_owned(),
        status_interval_seconds: STATUS_INTERVAL_SECONDS,
    });
    if send(&mut socket, &welcome).await {
        state.hub.emit_device(&device_id).await;
        run_session(&state, &device_id, &mut socket, &mut link).await;
    }
    state.hub.unregister_agent(&device_id, connection).await;
    let id = device_id.clone();
    let _ = state
        .db
        .call(move |c| {
            c.execute(
                "UPDATE devices SET last_seen_at = ?2 WHERE id = ?1",
                rusqlite::params![id, now()],
            )?;
            Ok(())
        })
        .await;
    tracing::info!(device = %device_id, "agent disconnected");
}

async fn run_session(
    state: &Shared,
    device_id: &str,
    socket: &mut WebSocket,
    link: &mut AgentLink,
) {
    let mut ping = tokio::time::interval(PING_INTERVAL);
    ping.tick().await;
    let mut last_heard = tokio::time::Instant::now();
    loop {
        tokio::select! {
            message = link.outgoing.recv() => match message {
                Some(message) => {
                    if !send(socket, &message).await {
                        return;
                    }
                }
                // Removed or replaced; no sender is left.
                None => return close_gracefully(socket, &mut link.outgoing).await,
            },
            // Removed or replaced: deliver what was queued (cancels), then close.
            () = closed(&mut link.closed) => {
                return close_gracefully(socket, &mut link.outgoing).await;
            },
            incoming = socket.recv() => {
                last_heard = tokio::time::Instant::now();
                match incoming {
                    Some(Ok(Message::Text(text))) => {
                        match serde_json::from_str::<AgentMessage>(&text) {
                            Ok(message) => handle(state, device_id, link.connection, message).await,
                            Err(error) => {
                                tracing::warn!(device = %device_id, %error, "bad agent message");
                                return;
                            }
                        }
                    }
                    Some(Ok(Message::Close(_)) | Err(_)) | None => return,
                    Some(Ok(_)) => {}
                }
            },
            _ = ping.tick() => {
                if last_heard.elapsed() > SILENCE_LIMIT {
                    return;
                }
                let ping = socket.send(Message::Ping(Vec::new().into()));
                if !matches!(tokio::time::timeout(SOCKET_SEND_TIMEOUT, ping).await, Ok(Ok(()))) {
                    return;
                }
            }
        }
    }
}

/// Sends what is still queued, then closes and waits for the agent's
/// answer. Dropping a socket with unread input resets the connection, and
/// the agent would lose the queued cancels.
async fn close_gracefully(
    socket: &mut WebSocket,
    outgoing: &mut tokio::sync::mpsc::Receiver<ServerMessage>,
) {
    let deadline = tokio::time::Instant::now() + CLOSE_FLUSH;
    while let Ok(message) = outgoing.try_recv() {
        if tokio::time::Instant::now() > deadline || !send(socket, &message).await {
            break;
        }
    }
    let _ = tokio::time::timeout(CLOSE_FLUSH, socket.send(Message::Close(None))).await;
    let _ = tokio::time::timeout(CLOSE_FLUSH, async {
        while let Some(Ok(message)) = socket.recv().await {
            if matches!(message, Message::Close(_)) {
                break;
            }
        }
    })
    .await;
}

/// Resolves once the hub drops this connection.
async fn closed(receiver: &mut tokio::sync::watch::Receiver<bool>) {
    let _ = receiver.wait_for(|closed| *closed).await;
}

async fn handle(state: &Shared, device_id: &str, connection: u64, message: AgentMessage) {
    let id_too_long = match &message {
        AgentMessage::ExecOutput { id, .. }
        | AgentMessage::ExecExit { id, .. }
        | AgentMessage::TermOutput { id, .. }
        | AgentMessage::TermExit { id, .. } => id.len() > MAX_ID_BYTES,
        AgentMessage::Hello(_) | AgentMessage::Status(_) => false,
    };
    if id_too_long {
        tracing::warn!(device = %device_id, "ignoring a message with an oversized id");
        return;
    }
    match message {
        AgentMessage::Hello(_) => {}
        AgentMessage::Status(status) => record_status(state, device_id, connection, *status).await,
        AgentMessage::ExecOutput { id, data } => state.hub.exec_output(device_id, &id, &data),
        AgentMessage::ExecExit { id, outcome } => {
            state.hub.exec_exit(device_id, &id, outcome).await;
        }
        AgentMessage::TermOutput { id, data } => {
            state
                .hub
                .term_output(device_id, connection, &id, data)
                .await;
        }
        AgentMessage::TermExit { id, message } => {
            let message = centrald_proto::text::clean(&message, 256);
            state.hub.term_exit(device_id, &id, message).await;
        }
    }
}

/// Keeps the newest status in memory; writes it to disk only now and then.
async fn record_status(state: &Shared, device_id: &str, connection: u64, mut status: Status) {
    status.sanitize();
    let Some(due) = state
        .hub
        .accept_status(device_id, connection, status.clone())
    else {
        return;
    };
    if due {
        state.hub.persist_status(device_id, &status, now()).await;
    }
    state.hub.emit_device(device_id).await;
}
