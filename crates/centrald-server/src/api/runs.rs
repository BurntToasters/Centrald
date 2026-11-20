//! Running commands and built-in actions on one or more devices.

use std::collections::BTreeSet;

use axum::Json;
use axum::extract::{Path, Query, State};
use axum::http::StatusCode;
use base64::Engine;
use base64::engine::general_purpose::STANDARD;
use centrald_proto::limits::{
    DEFAULT_TIMEOUT_SECONDS, MAX_COMMAND_BYTES, MAX_TIMEOUT_SECONDS, MIN_TIMEOUT_SECONDS,
};
use centrald_proto::wire::{Action, ExecSpec};
use rusqlite::OptionalExtension;
use serde::Deserialize;
use serde_json::json;

use crate::db::{self, now};
use crate::error::{ApiError, ApiResult};
use crate::hub::StartError;
use crate::model::{self, RunView};
use crate::session::CurrentUser;
use crate::state::Shared;

const MAX_TARGETS: usize = 500;

#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct CreateRequest {
    device_ids: Vec<String>,
    #[serde(default)]
    command: Option<String>,
    #[serde(default)]
    action: Option<String>,
    #[serde(default)]
    timeout_seconds: Option<u32>,
}

#[allow(clippy::too_many_lines)]
pub async fn create(
    State(state): State<Shared>,
    user: CurrentUser,
    Json(body): Json<CreateRequest>,
) -> ApiResult<(StatusCode, Json<RunView>)> {
    let (kind, text, spec) = match (body.command, body.action) {
        (Some(command), None) => {
            let command = command.trim().to_owned();
            if command.is_empty() {
                return Err(ApiError::bad_request("Type a command to run."));
            }
            if command.len() > MAX_COMMAND_BYTES {
                return Err(ApiError::bad_request(
                    "That command is too long (16 KiB at most).",
                ));
            }
            if command.contains('\0') {
                return Err(ApiError::bad_request(
                    "Commands cannot contain NUL characters.",
                ));
            }
            ("command", command.clone(), ExecSpec::Shell { command })
        }
        (None, Some(action)) => {
            let action =
                Action::parse(&action).ok_or_else(|| ApiError::bad_request("Unknown action."))?;
            (
                "action",
                action.as_str().to_owned(),
                ExecSpec::Action { action },
            )
        }
        _ => {
            return Err(ApiError::bad_request(
                "Send either a command or an action, not both.",
            ));
        }
    };
    let timeout = body
        .timeout_seconds
        .unwrap_or(DEFAULT_TIMEOUT_SECONDS)
        .clamp(MIN_TIMEOUT_SECONDS, MAX_TIMEOUT_SECONDS);
    let device_ids: BTreeSet<String> = body.device_ids.into_iter().collect();
    if device_ids.is_empty() {
        return Err(ApiError::bad_request("Pick at least one device."));
    }
    if device_ids.len() > MAX_TARGETS {
        return Err(ApiError::bad_request("Too many devices in one run."));
    }

    // Decide each target's starting state before anything is sent.
    let run_id = uuid::Uuid::new_v4().to_string();
    let mut plan = Vec::new();
    {
        let ids: Vec<String> = device_ids.into_iter().collect();
        let names = state
            .db
            .call(move |c| {
                let mut found = Vec::new();
                for id in ids {
                    let name: Option<String> = c
                        .query_row("SELECT name FROM devices WHERE id = ?1", [&id], |r| {
                            r.get(0)
                        })
                        .optional()?;
                    if let Some(name) = name {
                        found.push((id, name));
                    }
                }
                Ok(found)
            })
            .await?;
        if names.is_empty() {
            return Err(ApiError::not_found("None of those devices exist any more."));
        }
        for (id, name) in names {
            plan.push((id, name));
        }
    }

    let record_id = run_id.clone();
    let targets = plan.clone();
    let audit_text = text.clone();
    let actor = user.username.clone();
    let address = user.address.clone();
    state
        .db
        .call(move |c| {
            let tx = c.transaction()?;
            let time = now();
            tx.execute(
                "INSERT INTO runs (id, kind, command, created_by, created_at, timeout_seconds)
                 VALUES (?1, ?2, ?3, ?4, ?5, ?6)",
                rusqlite::params![record_id, kind, audit_text, actor, time, timeout],
            )?;
            for (device_id, name) in &targets {
                tx.execute(
                    "INSERT INTO run_targets (run_id, device_id, device_name, state, started_at)
                     VALUES (?1, ?2, ?3, 'running', ?4)",
                    rusqlite::params![record_id, device_id, name, time],
                )?;
            }
            let devices = targets
                .iter()
                .map(|(_, n)| n.as_str())
                .collect::<Vec<_>>()
                .join(", ");
            let action = if kind == "command" {
                "run.command"
            } else {
                "run.action"
            };
            let detail: String = audit_text.chars().take(500).collect();
            db::audit(&tx, &actor, action, &devices, &detail, &address)?;
            tx.commit()?;
            Ok(())
        })
        .await?;

    let mut immediate = Vec::new();
    for (device_id, _) in &plan {
        match state
            .hub
            .start_exec(&run_id, device_id, spec.clone(), timeout)
        {
            Ok(()) => {}
            Err(StartError::Offline) => {
                immediate.push((device_id.clone(), "unreachable", "The device is offline."));
            }
            Err(StartError::MonitorOnly) => immediate.push((
                device_id.clone(),
                "refused",
                "This device is monitor-only and does not accept commands.",
            )),
        }
    }
    if !immediate.is_empty() {
        let record_id = run_id.clone();
        state
            .db
            .call(move |c| {
                for (device_id, target_state, error) in immediate {
                    c.execute(
                        "UPDATE run_targets SET state = ?3, error = ?4, finished_at = ?5
                         WHERE run_id = ?1 AND device_id = ?2",
                        rusqlite::params![record_id, device_id, target_state, error, now()],
                    )?;
                }
                Ok(())
            })
            .await?;
    }

    let id = run_id.clone();
    let run = state
        .db
        .call(move |c| model::get_run(c, &id, false))
        .await?
        .ok_or_else(|| anyhow::anyhow!("run vanished"))?;
    state.hub.emit_run(&run_id).await;
    Ok((StatusCode::CREATED, Json(run)))
}

#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct ListQuery {
    limit: Option<u32>,
    before: Option<i64>,
    device_id: Option<String>,
}

pub async fn list(
    State(state): State<Shared>,
    _user: CurrentUser,
    Query(query): Query<ListQuery>,
) -> ApiResult<Json<Vec<RunView>>> {
    let limit = query.limit.unwrap_or(50).clamp(1, 200);
    let runs = state
        .db
        .call(move |c| model::list_runs(c, limit, query.before, query.device_id.as_deref()))
        .await?;
    Ok(Json(runs))
}

pub async fn get(
    State(state): State<Shared>,
    _user: CurrentUser,
    Path(id): Path<String>,
) -> ApiResult<Json<RunView>> {
    let mut run = state
        .db
        .call(move |c| model::get_run(c, &id, true))
        .await?
        .ok_or_else(|| ApiError::not_found("That run no longer exists."))?;
    for target in &mut run.targets {
        if target.state == "running"
            && let Some((output, truncated)) = state.hub.live_output(&run.id, &target.device_id)
        {
            target.output_bytes = i64::try_from(output.len()).unwrap_or(i64::MAX);
            target.output = Some(STANDARD.encode(&output));
            target.truncated = truncated;
        }
    }
    Ok(Json(run))
}

pub async fn cancel(
    State(state): State<Shared>,
    user: CurrentUser,
    Path(id): Path<String>,
) -> ApiResult<Json<serde_json::Value>> {
    let sent = state.hub.cancel_run(&id);
    if sent > 0 {
        state
            .db
            .call(move |c| db::audit(c, &user.username, "run.canceled", &id, "", &user.address))
            .await?;
    }
    Ok(Json(json!({ "canceled": sent })))
}
