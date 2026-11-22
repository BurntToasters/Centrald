//! Devices: inventory, renaming, removal, metrics history, and terminals.

use std::time::Duration;

use axum::Json;
use axum::extract::ws::{CloseFrame, Message, WebSocket, WebSocketUpgrade};
use axum::extract::{Path, Query, State};
use axum::response::Response;
use centrald_proto::limits::{MAX_CHUNK_BYTES, MAX_TERMINAL_COLUMNS, MAX_TERMINAL_ROWS};
use serde::{Deserialize, Serialize};
use serde_json::json;

use crate::db::{self, now};
use crate::error::{ApiError, ApiResult};
use crate::hub::{Event, SOCKET_SEND_TIMEOUT, TermEvent};
use crate::model::{self, DeviceView};
use crate::session::CurrentUser;
use crate::state::Shared;

const MAX_NAME_CHARS: usize = 64;
/// Terminals close after this long without keyboard input.
const TERMINAL_IDLE: Duration = Duration::from_secs(30 * 60);
/// How often an open terminal checks for idleness.
const IDLE_CHECK: Duration = Duration::from_secs(30);

pub async fn list(
    State(state): State<Shared>,
    _user: CurrentUser,
) -> ApiResult<Json<Vec<DeviceView>>> {
    let mut devices = state.db.call(|c| model::list_devices(c)).await?;
    for device in &mut devices {
        state.hub.decorate(device);
    }
    Ok(Json(devices))
}

pub async fn get(
    State(state): State<Shared>,
    _user: CurrentUser,
    Path(id): Path<String>,
) -> ApiResult<Json<DeviceView>> {
    let mut device = state
        .db
        .call(move |c| model::get_device(c, &id))
        .await?
        .ok_or_else(|| ApiError::not_found("That device no longer exists."))?;
    state.hub.decorate(&mut device);
    Ok(Json(device))
}

#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct UpdateRequest {
    name: String,
}

pub fn clean_name(name: &str) -> Result<String, ApiError> {
    let name: String = name
        .trim()
        .chars()
        .filter(|c| !centrald_proto::text::is_hidden(*c))
        .collect();
    let name = name.trim().to_owned();
    if name.is_empty() || name.chars().count() > MAX_NAME_CHARS {
        return Err(ApiError::bad_request(
            "Use a name between 1 and 64 characters.",
        ));
    }
    Ok(name)
}

pub async fn update(
    State(state): State<Shared>,
    user: CurrentUser,
    Path(id): Path<String>,
    Json(body): Json<UpdateRequest>,
) -> ApiResult<Json<serde_json::Value>> {
    let name = clean_name(&body.name)?;
    let device_id = id.clone();
    let changed = state
        .db
        .call(move |c| {
            let old: Option<String> = rusqlite::OptionalExtension::optional(c.query_row(
                "SELECT name FROM devices WHERE id = ?1",
                [&device_id],
                |r| r.get(0),
            ))?;
            let Some(old) = old else { return Ok(false) };
            c.execute(
                "UPDATE devices SET name = ?2 WHERE id = ?1",
                rusqlite::params![device_id, name],
            )?;
            db::audit(
                c,
                &user.username,
                "device.renamed",
                &name,
                &format!("was {old}"),
                &user.address,
            )?;
            Ok(true)
        })
        .await?;
    if !changed {
        return Err(ApiError::not_found("That device no longer exists."));
    }
    state.hub.emit_device(&id).await;
    Ok(Json(json!({ "ok": true })))
}

/// Forgets a device and revokes its credential immediately.
pub async fn remove(
    State(state): State<Shared>,
    user: CurrentUser,
    Path(id): Path<String>,
) -> ApiResult<Json<serde_json::Value>> {
    let device_id = id.clone();
    let removed = state
        .db
        .call(move |c| {
            let tx = c.transaction()?;
            let name: Option<String> = rusqlite::OptionalExtension::optional(tx.query_row(
                "SELECT name FROM devices WHERE id = ?1",
                [&device_id],
                |r| r.get(0),
            ))?;
            let Some(name) = name else { return Ok(false) };
            tx.execute("DELETE FROM devices WHERE id = ?1", [&device_id])?;
            db::audit(
                &tx,
                &user.username,
                "device.removed",
                &name,
                "",
                &user.address,
            )?;
            tx.commit()?;
            Ok(true)
        })
        .await?;
    if !removed {
        return Err(ApiError::not_found("That device no longer exists."));
    }
    state.hub.disconnect(&id).await;
    state.hub.emit(&Event::DeviceRemoved { id });
    Ok(Json(json!({ "ok": true })))
}

#[derive(Debug, Deserialize)]
pub struct MetricsQuery {
    hours: Option<u32>,
}

#[derive(Debug, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct MetricPoint {
    at: i64,
    cpu: f64,
    memory: f64,
    load: Option<f64>,
}

pub async fn metrics(
    State(state): State<Shared>,
    _user: CurrentUser,
    Path(id): Path<String>,
    Query(query): Query<MetricsQuery>,
) -> ApiResult<Json<Vec<MetricPoint>>> {
    let hours = i64::from(query.hours.unwrap_or(24).clamp(1, 24 * 7));
    let points = state
        .db
        .call(move |c| {
            let mut statement = c.prepare(
                "SELECT at, cpu, memory, load FROM metrics
                 WHERE device_id = ?1 AND at >= ?2 ORDER BY at",
            )?;
            let rows = statement
                .query_map(rusqlite::params![id, now() - hours * 3600], |r| {
                    Ok(MetricPoint {
                        at: r.get(0)?,
                        cpu: r.get(1)?,
                        memory: r.get(2)?,
                        load: r.get(3)?,
                    })
                })?
                .collect::<rusqlite::Result<Vec<_>>>()?;
            Ok(rows)
        })
        .await?;
    Ok(Json(points))
}

#[derive(Debug, Deserialize)]
pub struct TerminalQuery {
    columns: Option<u16>,
    rows: Option<u16>,
}

#[derive(Debug, Deserialize)]
#[serde(tag = "type", rename_all = "snake_case")]
enum TerminalControl {
    Resize { columns: u16, rows: u16 },
}

/// Opens an interactive root shell on a device over a WebSocket.
///
/// Binary frames carry terminal bytes both ways. Text frames carry JSON
/// control messages: `resize` from the browser; `exit` and `error` from us.
pub async fn terminal(
    State(state): State<Shared>,
    user: CurrentUser,
    Path(id): Path<String>,
    Query(query): Query<TerminalQuery>,
    upgrade: WebSocketUpgrade,
) -> ApiResult<Response> {
    let device_id = id.clone();
    let name: String = state
        .db
        .call(move |c| {
            Ok(rusqlite::OptionalExtension::optional(c.query_row(
                "SELECT name FROM devices WHERE id = ?1",
                [&device_id],
                |r| r.get(0),
            ))?)
        })
        .await?
        .ok_or_else(|| ApiError::not_found("That device no longer exists."))?;
    let columns = query.columns.unwrap_or(80).clamp(10, MAX_TERMINAL_COLUMNS);
    let rows = query.rows.unwrap_or(24).clamp(4, MAX_TERMINAL_ROWS);
    let (guard, events) = state
        .hub
        .open_terminal(&id, columns, rows)
        .map_err(ApiError::conflict)?;

    Ok(upgrade
        .max_message_size(MAX_CHUNK_BYTES * 2)
        .on_upgrade(move |socket| async move {
            // Logged only once the socket exists, so every "opened" has a "closed".
            let actor = user.username.clone();
            let address = user.address.clone();
            let audit_name = name.clone();
            let _ = state
                .db
                .call(move |c| db::audit(c, &actor, "terminal.opened", &audit_name, "", &address))
                .await;
            let started = std::time::Instant::now();
            relay(&state, &user, socket, &guard.id, events).await;
            drop(guard);
            let detail = format!("{} seconds", started.elapsed().as_secs());
            let CurrentUser {
                username, address, ..
            } = user;
            let _ = state
                .db
                .call(move |c| db::audit(c, &username, "terminal.closed", &name, &detail, &address))
                .await;
        }))
}

/// Sends one frame to the browser; false if it fails or takes too long.
async fn send_frame(socket: &mut WebSocket, message: Message) -> bool {
    matches!(
        tokio::time::timeout(SOCKET_SEND_TIMEOUT, socket.send(message)).await,
        Ok(Ok(()))
    )
}

async fn relay(
    state: &Shared,
    user: &CurrentUser,
    mut socket: WebSocket,
    id: &str,
    mut events: tokio::sync::mpsc::Receiver<TermEvent>,
) {
    let mut session = state.hub.watch_session(user.session_hash, &user.id);
    let mut idle_check = tokio::time::interval(IDLE_CHECK);
    idle_check.tick().await;
    let mut last_input = tokio::time::Instant::now();
    let reason = loop {
        tokio::select! {
            event = events.recv() => match event {
                Some(TermEvent::Output(data)) => {
                    if !send_frame(&mut socket, Message::Binary(data.into())).await {
                        break None;
                    }
                }
                Some(TermEvent::Exit(message)) => {
                    let text = json!({ "type": "exit", "message": message }).to_string();
                    let _ = send_frame(&mut socket, Message::Text(text.into())).await;
                    break Some("closed");
                }
                None => break Some("closed"),
            },
            () = session.ended() => {
                break Some("Your session ended, so the terminal was closed.");
            },
            incoming = socket.recv() => match incoming {
                Some(Ok(Message::Binary(data))) => {
                    last_input = tokio::time::Instant::now();
                    let mut delivered = true;
                    for chunk in data.chunks(MAX_CHUNK_BYTES) {
                        if !state.hub.term_input(id, chunk.to_vec()).await {
                            delivered = false;
                            break;
                        }
                    }
                    if !delivered {
                        break Some("The device stopped responding, so the terminal was closed.");
                    }
                }
                Some(Ok(Message::Text(text))) => {
                    if let Ok(TerminalControl::Resize { columns, rows }) = serde_json::from_str(&text) {
                        state.hub.term_resize(
                            id,
                            columns.clamp(10, MAX_TERMINAL_COLUMNS),
                            rows.clamp(4, MAX_TERMINAL_ROWS),
                        );
                    }
                }
                Some(Err(error)) => {
                    let close = Message::Close(Some(super::read_error_close(&error)));
                    let _ = send_frame(&mut socket, close).await;
                    return;
                }
                Some(Ok(Message::Close(_))) | None => break None,
                Some(Ok(_)) => {}
            },
            _ = idle_check.tick() => {
                if last_input.elapsed() > TERMINAL_IDLE {
                    break Some("The terminal closed after 30 minutes without input.");
                }
            }
        }
    };
    if let Some(reason) = reason.filter(|r| *r != "closed") {
        let text = json!({ "type": "error", "message": reason }).to_string();
        let _ = send_frame(&mut socket, Message::Text(text.into())).await;
    }
    let _ = send_frame(
        &mut socket,
        Message::Close(Some(CloseFrame {
            code: 1000,
            reason: "".into(),
        })),
    )
    .await;
}
