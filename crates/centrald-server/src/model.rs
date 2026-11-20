//! JSON shapes shared by the browser API and live events, plus the queries
//! that build them.

use anyhow::Result;
use base64::Engine;
use base64::engine::general_purpose::STANDARD;
use centrald_proto::wire::{OsInfo, Status};
use rusqlite::{Connection, OptionalExtension, Row};
use serde::Serialize;

#[derive(Debug, Clone, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct DeviceView {
    pub id: String,
    pub name: String,
    pub hostname: String,
    pub os: OsInfo,
    pub agent_version: String,
    pub allow_commands: bool,
    pub package_managed: bool,
    pub enrolled_at: i64,
    pub last_seen_at: Option<i64>,
    pub last_address: Option<String>,
    pub online: bool,
    pub status: Option<Status>,
    pub status_at: Option<i64>,
}

const DEVICE_COLUMNS: &str = "id, name, hostname, os_json, agent_version, allow_commands, \
     package_managed, enrolled_at, last_seen_at, last_address, status_json, status_at";

fn device_from_row(row: &Row<'_>) -> rusqlite::Result<DeviceView> {
    let os_json: String = row.get(3)?;
    let status_json: Option<String> = row.get(10)?;
    Ok(DeviceView {
        id: row.get(0)?,
        name: row.get(1)?,
        hostname: row.get(2)?,
        os: serde_json::from_str(&os_json).unwrap_or_default(),
        agent_version: row.get(4)?,
        allow_commands: row.get(5)?,
        package_managed: row.get(6)?,
        enrolled_at: row.get(7)?,
        last_seen_at: row.get(8)?,
        last_address: row.get(9)?,
        online: false,
        status: status_json.and_then(|json| serde_json::from_str(&json).ok()),
        status_at: row.get(11)?,
    })
}

pub fn list_devices(connection: &Connection) -> Result<Vec<DeviceView>> {
    let mut statement = connection.prepare(&format!(
        "SELECT {DEVICE_COLUMNS} FROM devices ORDER BY name COLLATE NOCASE, id"
    ))?;
    let devices = statement
        .query_map([], device_from_row)?
        .collect::<rusqlite::Result<Vec<_>>>()?;
    Ok(devices)
}

pub fn get_device(connection: &Connection, id: &str) -> Result<Option<DeviceView>> {
    Ok(connection
        .query_row(
            &format!("SELECT {DEVICE_COLUMNS} FROM devices WHERE id = ?1"),
            [id],
            device_from_row,
        )
        .optional()?)
}

#[derive(Debug, Clone, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct RunView {
    pub id: String,
    /// `command` or `action`.
    pub kind: String,
    /// The command line, or the action identifier.
    pub command: String,
    pub created_by: String,
    pub created_at: i64,
    pub timeout_seconds: i64,
    pub targets: Vec<TargetView>,
}

#[derive(Debug, Clone, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct TargetView {
    pub device_id: String,
    pub device_name: String,
    pub state: String,
    pub exit_code: Option<i64>,
    pub error: Option<String>,
    pub started_at: i64,
    pub finished_at: Option<i64>,
    /// Base64 output; omitted from list responses.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub output: Option<String>,
    pub output_bytes: i64,
    pub truncated: bool,
}

fn run_from_row(row: &Row<'_>) -> rusqlite::Result<RunView> {
    Ok(RunView {
        id: row.get(0)?,
        kind: row.get(1)?,
        command: row.get(2)?,
        created_by: row.get(3)?,
        created_at: row.get(4)?,
        timeout_seconds: row.get(5)?,
        targets: Vec::new(),
    })
}

fn targets_for(
    connection: &Connection,
    run_id: &str,
    with_output: bool,
) -> rusqlite::Result<Vec<TargetView>> {
    let mut statement = connection.prepare_cached(
        "SELECT device_id, device_name, state, exit_code, error, started_at, finished_at,
                output, truncated
         FROM run_targets WHERE run_id = ?1 ORDER BY device_name COLLATE NOCASE",
    )?;
    statement
        .query_map([run_id], |row| {
            let output: Vec<u8> = row.get(7)?;
            Ok(TargetView {
                device_id: row.get(0)?,
                device_name: row.get(1)?,
                state: row.get(2)?,
                exit_code: row.get(3)?,
                error: row.get(4)?,
                started_at: row.get(5)?,
                finished_at: row.get(6)?,
                output_bytes: i64::try_from(output.len()).unwrap_or(i64::MAX),
                output: with_output.then(|| STANDARD.encode(&output)),
                truncated: row.get(8)?,
            })
        })?
        .collect()
}

pub fn get_run(connection: &Connection, id: &str, with_output: bool) -> Result<Option<RunView>> {
    let run = connection
        .query_row(
            "SELECT id, kind, command, created_by, created_at, timeout_seconds
             FROM runs WHERE id = ?1",
            [id],
            run_from_row,
        )
        .optional()?;
    let Some(mut run) = run else {
        return Ok(None);
    };
    run.targets = targets_for(connection, id, with_output)?;
    Ok(Some(run))
}

/// Newest first. `device_id` narrows to runs that targeted one device.
pub fn list_runs(
    connection: &Connection,
    limit: u32,
    before: Option<i64>,
    device_id: Option<&str>,
) -> Result<Vec<RunView>> {
    let before = before.unwrap_or(i64::MAX);
    let mut statement = connection.prepare(
        "SELECT id, kind, command, created_by, created_at, timeout_seconds FROM runs
         WHERE created_at < ?1
           AND (?2 IS NULL OR id IN (SELECT run_id FROM run_targets WHERE device_id = ?2))
         ORDER BY created_at DESC, id DESC LIMIT ?3",
    )?;
    let mut runs = statement
        .query_map(rusqlite::params![before, device_id, limit], run_from_row)?
        .collect::<rusqlite::Result<Vec<_>>>()?;
    for run in &mut runs {
        run.targets = targets_for(connection, &run.id, false)?;
    }
    Ok(runs)
}

#[derive(Debug, Clone, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct JoinTokenView {
    pub id: String,
    pub name: String,
    pub created_by: String,
    pub created_at: i64,
    pub expires_at: i64,
    pub used_at: Option<i64>,
    pub device_id: Option<String>,
}

pub fn list_join_tokens(connection: &Connection, now: i64) -> Result<Vec<JoinTokenView>> {
    // Recently used or expired codes stay visible for a day for context.
    let mut statement = connection.prepare(
        "SELECT id, name, created_by, created_at, expires_at, used_at, device_id
         FROM join_tokens
         WHERE (used_at IS NULL AND expires_at > ?1 - 86400) OR used_at > ?1 - 86400
         ORDER BY created_at DESC LIMIT 100",
    )?;
    let tokens = statement
        .query_map([now], |row| {
            Ok(JoinTokenView {
                id: row.get(0)?,
                name: row.get(1)?,
                created_by: row.get(2)?,
                created_at: row.get(3)?,
                expires_at: row.get(4)?,
                used_at: row.get(5)?,
                device_id: row.get(6)?,
            })
        })?
        .collect::<rusqlite::Result<Vec<_>>>()?;
    Ok(tokens)
}

#[derive(Debug, Clone, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct AuditView {
    pub id: i64,
    pub at: i64,
    pub actor: String,
    pub action: String,
    pub target: String,
    pub detail: String,
    pub address: String,
}

pub fn list_audit(
    connection: &Connection,
    limit: u32,
    before: Option<i64>,
) -> Result<Vec<AuditView>> {
    let mut statement = connection.prepare(
        "SELECT id, at, actor, action, target, detail, address FROM audit
         WHERE id < ?1 ORDER BY id DESC LIMIT ?2",
    )?;
    let entries = statement
        .query_map(
            rusqlite::params![before.unwrap_or(i64::MAX), limit],
            |row| {
                Ok(AuditView {
                    id: row.get(0)?,
                    at: row.get(1)?,
                    actor: row.get(2)?,
                    action: row.get(3)?,
                    target: row.get(4)?,
                    detail: row.get(5)?,
                    address: row.get(6)?,
                })
            },
        )?
        .collect::<rusqlite::Result<Vec<_>>>()?;
    Ok(entries)
}
