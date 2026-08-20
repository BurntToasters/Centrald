//! Admin shell session commands: elevation challenges, terminal streams, and
//! session input/resize/close over the Tauri IPC channel.

use std::collections::HashMap;
use std::sync::{Arc, Mutex};

use anyhow::{Context, Result};
use base64::Engine as _;
use base64::engine::general_purpose::STANDARD;
use centrald_protocol::v1::{
    AdminShellFrame, BeginElevationRequest, ShellClose, ShellData, ShellFrame, ShellOpen,
    ShellPrivilege,
};
use ed25519_dalek::Signer;
use ed25519_dalek::pkcs8::DecodePrivateKey;
use serde::Serialize;
use tauri::{AppHandle, Manager, State};
use tokio::sync::mpsc;
use tokio_stream::wrappers::ReceiverStream;
use uuid::Uuid;

use crate::profiles::{admin_client, load_profile_from_dir, profiles_dir};

const ELEVATION_DOMAIN: &[u8] = b"centrald-elevation-v1\0";
/// Upper bound on base64 input per keystroke-batch frame (64 KiB of payload).
const MAX_INPUT_BASE64_CHARS: usize = 96 * 1024;

/// Tauri-managed registry of active shell sessions.
#[derive(Debug, Default)]
pub struct ShellSessions {
    sessions: Mutex<HashMap<String, ShellClient>>,
}

#[derive(Debug)]
struct ShellClient {
    tx: mpsc::Sender<AdminShellFrame>,
    session_id: Arc<Mutex<Option<String>>>,
}

#[derive(Debug, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct ElevationChallengeView {
    id: String,
    nonce: String,
    context_hash: String,
    expires_at: String,
    challenge_signature: String,
}

#[derive(Debug, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct ShellOpenView {
    handle: String,
}

/// Events forwarded to the frontend terminal component.
#[derive(Debug, Serialize)]
#[serde(tag = "type", rename_all = "snake_case")]
pub enum ShellEvent {
    Data {
        session_id: String,
        data: String,
    },
    Close {
        session_id: String,
        reason: String,
        exit_code: i32,
    },
    Error {
        message: String,
    },
}

#[tauri::command]
#[allow(clippy::needless_pass_by_value)]
pub async fn begin_elevation(
    app: AppHandle,
    profile_id: String,
    target_id: String,
    operation: String,
    reason: String,
) -> Result<ElevationChallengeView, String> {
    begin_elevation_inner(&app, &profile_id, target_id, operation, reason)
        .await
        .map_err(display_error)
}

#[tauri::command]
#[allow(clippy::needless_pass_by_value)]
#[allow(clippy::too_many_arguments)]
pub async fn open_shell(
    app: AppHandle,
    state: State<'_, ShellSessions>,
    profile_id: String,
    target_id: String,
    privilege: String,
    columns: u32,
    rows: u32,
    reason: String,
    account_user: String,
    account_password: String,
    save_credentials: bool,
    challenge_id: String,
    challenge_signature: String,
    channel: tauri::ipc::Channel<ShellEvent>,
) -> Result<ShellOpenView, String> {
    open_shell_inner(
        &app,
        &state,
        &profile_id,
        target_id,
        &privilege,
        columns,
        rows,
        reason,
        account_user,
        account_password,
        save_credentials,
        &challenge_id,
        &challenge_signature,
        channel,
    )
    .await
    .map_err(display_error)
}

#[tauri::command]
#[allow(clippy::needless_pass_by_value)]
pub async fn shell_input(
    state: State<'_, ShellSessions>,
    handle: String,
    data: String,
) -> Result<(), String> {
    shell_input_inner(&state, &handle, &data).map_err(display_error)
}

#[tauri::command]
#[allow(clippy::needless_pass_by_value)]
pub async fn shell_resize(
    state: State<'_, ShellSessions>,
    handle: String,
    columns: u32,
    rows: u32,
) -> Result<(), String> {
    shell_resize_inner(&state, &handle, columns, rows).map_err(display_error)
}

#[tauri::command]
#[allow(clippy::needless_pass_by_value)]
pub async fn shell_close(state: State<'_, ShellSessions>, handle: String) -> Result<(), String> {
    shell_close_inner(&state, &handle).map_err(display_error)
}

async fn begin_elevation_inner(
    app: &AppHandle,
    profile_id: &str,
    target_id: String,
    operation: String,
    reason: String,
) -> Result<ElevationChallengeView> {
    if !centrald_common::TERMINAL_SESSIONS_ENABLED {
        anyhow::bail!("interactive terminal is unavailable in this alpha release");
    }
    let response = admin_client(app, profile_id)
        .await?
        .begin_elevation(BeginElevationRequest {
            target_id,
            operation,
            reason,
        })
        .await?
        .into_inner();
    let signature = sign_elevation_challenge(app, profile_id, &response)?;
    Ok(ElevationChallengeView {
        id: response.id,
        nonce: STANDARD.encode(&response.nonce),
        context_hash: STANDARD.encode(&response.context_hash),
        expires_at: timestamp_text(response.expires_at),
        challenge_signature: STANDARD.encode(signature),
    })
}

#[allow(clippy::too_many_arguments)]
#[allow(clippy::too_many_lines)]
async fn open_shell_inner(
    app: &AppHandle,
    state: &State<'_, ShellSessions>,
    profile_id: &str,
    target_id: String,
    privilege: &str,
    columns: u32,
    rows: u32,
    reason: String,
    account_user: String,
    account_password: String,
    save_credentials: bool,
    challenge_id: &str,
    challenge_signature: &str,
    channel: tauri::ipc::Channel<ShellEvent>,
) -> Result<ShellOpenView> {
    if !centrald_common::TERMINAL_SESSIONS_ENABLED {
        anyhow::bail!("interactive terminal is unavailable in this alpha release");
    }
    let privilege_enum = match privilege {
        "low" => ShellPrivilege::Low,
        "elevated" => ShellPrivilege::Elevated,
        _ => anyhow::bail!("unsupported shell privilege"),
    };
    if !(2..=500).contains(&columns) || !(2..=500).contains(&rows) {
        anyhow::bail!("terminal size must be 2-500 columns and rows");
    }
    let (tx, rx) = mpsc::channel(64);
    let mut client = admin_client(app, profile_id).await?;
    let response = client
        .open_shell(ReceiverStream::new(rx))
        .await
        .context("open the remote shell stream")?;
    let mut inbound = response.into_inner();

    let session_id = Arc::new(Mutex::new(None::<String>));
    let handle = Uuid::now_v7().to_string();
    state
        .sessions
        .lock()
        .map_err(|_| anyhow::anyhow!("shell session registry lock was poisoned"))?
        .insert(
            handle.clone(),
            ShellClient {
                tx: tx.clone(),
                session_id: Arc::clone(&session_id),
            },
        );

    // Keep the only writable copy of the password in zeroizing storage; the
    // frame's byte copy is the ephemeral wire value and the wrapper's clone
    // semantics clear this source before it drops.
    let account_password = secrecy::zeroize::Zeroizing::new(account_password.into_bytes());
    let open = AdminShellFrame {
        shell: Some(ShellFrame {
            payload: Some(centrald_protocol::v1::shell_frame::Payload::Open(
                ShellOpen {
                    session_id: String::new(),
                    target_id,
                    privilege: privilege_enum as i32,
                    reason,
                    challenge_id: challenge_id.to_owned(),
                    challenge_signature: decode_b64(challenge_signature)?,
                    columns,
                    rows,
                    account_user,
                    account_password: account_password.to_vec(),
                    save_credentials,
                    parameters_json: Vec::new(),
                },
            )),
        }),
    };
    tx.send(open)
        .await
        .map_err(|_| anyhow::anyhow!("shell stream closed before open"))?;

    let app_handle = app.clone();
    let session_handle = handle.clone();
    tokio::spawn(async move {
        let remove_session = || {
            app_handle
                .state::<ShellSessions>()
                .sessions
                .lock()
                .ok()
                .map(|mut sessions| sessions.remove(&session_handle));
        };
        loop {
            match inbound.message().await {
                Ok(Some(frame)) => {
                    let Some(shell) = frame.shell else { continue };
                    match shell.payload {
                        Some(centrald_protocol::v1::shell_frame::Payload::Open(open)) => {
                            if let Ok(mut slot) = session_id.lock() {
                                *slot = Some(open.session_id.clone());
                            }
                        }
                        Some(centrald_protocol::v1::shell_frame::Payload::Data(data)) => {
                            let _ = channel.send(ShellEvent::Data {
                                session_id: data.session_id,
                                data: STANDARD.encode(&data.data),
                            });
                        }
                        Some(centrald_protocol::v1::shell_frame::Payload::Close(close)) => {
                            let _ = channel.send(ShellEvent::Close {
                                session_id: close.session_id,
                                reason: close.reason,
                                exit_code: close.exit_code,
                            });
                            break;
                        }
                        _ => {}
                    }
                }
                Ok(None) => break,
                Err(error) => {
                    let _ = channel.send(ShellEvent::Error {
                        message: error.to_string(),
                    });
                    break;
                }
            }
        }
        // Every exit path (close, stream end, or error) must release the
        // registry entry so sessions cannot leak across the GUI session.
        remove_session();
    });
    Ok(ShellOpenView { handle })
}

fn shell_input_inner(
    state: &State<'_, ShellSessions>,
    handle: &str,
    data_base64: &str,
) -> Result<()> {
    if !centrald_common::TERMINAL_SESSIONS_ENABLED {
        anyhow::bail!("interactive terminal is unavailable in this alpha release");
    }
    if data_base64.len() > MAX_INPUT_BASE64_CHARS {
        anyhow::bail!("shell input exceeds the per-frame limit");
    }
    let data = decode_b64(data_base64)?;
    let (tx, session_id) = session_client(state, handle)?;
    // Never block on a stalled stream from the async RPC path; fail fast so
    // the frontend can retry after backpressure clears.
    tx.try_send(AdminShellFrame {
        shell: Some(ShellFrame {
            payload: Some(centrald_protocol::v1::shell_frame::Payload::Data(
                ShellData {
                    session_id,
                    sequence: 0,
                    data,
                },
            )),
        }),
    })
    .map_err(|_| anyhow::anyhow!("shell input stream is backed up; retry shortly"))?;
    Ok(())
}

fn shell_resize_inner(
    state: &State<'_, ShellSessions>,
    handle: &str,
    columns: u32,
    rows: u32,
) -> Result<()> {
    if !centrald_common::TERMINAL_SESSIONS_ENABLED {
        anyhow::bail!("interactive terminal is unavailable in this alpha release");
    }
    if !(2..=500).contains(&columns) || !(2..=500).contains(&rows) {
        anyhow::bail!("terminal size must be 2-500 columns and rows");
    }
    let (tx, session_id) = session_client(state, handle)?;
    tx.try_send(AdminShellFrame {
        shell: Some(ShellFrame {
            payload: Some(centrald_protocol::v1::shell_frame::Payload::Resize(
                centrald_protocol::v1::ShellResize {
                    session_id,
                    columns,
                    rows,
                },
            )),
        }),
    })
    .map_err(|_| anyhow::anyhow!("shell stream is backed up; retry shortly"))?;
    Ok(())
}

fn shell_close_inner(state: &State<'_, ShellSessions>, handle: &str) -> Result<()> {
    if !centrald_common::TERMINAL_SESSIONS_ENABLED {
        anyhow::bail!("interactive terminal is unavailable in this alpha release");
    }
    let client = state
        .sessions
        .lock()
        .map_err(|_| anyhow::anyhow!("shell session registry lock was poisoned"))?
        .remove(handle)
        .ok_or_else(|| anyhow::anyhow!("shell session does not exist"))?;
    if let Ok(guard) = client.session_id.lock()
        && let Some(session_id) = guard.clone()
    {
        // Close is best-effort: a full stream still closes once the
        // server-side deadline fires, so never block on the send.
        let _ = client.tx.try_send(AdminShellFrame {
            shell: Some(ShellFrame {
                payload: Some(centrald_protocol::v1::shell_frame::Payload::Close(
                    ShellClose {
                        session_id,
                        reason: "operator closed the terminal".to_owned(),
                        exit_code: 0,
                    },
                )),
            }),
        });
    }
    Ok(())
}

fn session_client(
    state: &State<'_, ShellSessions>,
    handle: &str,
) -> Result<(mpsc::Sender<AdminShellFrame>, String)> {
    let sessions = state
        .sessions
        .lock()
        .map_err(|_| anyhow::anyhow!("shell session registry lock was poisoned"))?;
    let client = sessions
        .get(handle)
        .ok_or_else(|| anyhow::anyhow!("shell session does not exist"))?;
    let session_id = client
        .session_id
        .lock()
        .map_err(|_| anyhow::anyhow!("shell session lock was poisoned"))?
        .clone()
        .ok_or_else(|| anyhow::anyhow!("shell session is not open yet"))?;
    Ok((client.tx.clone(), session_id))
}

fn sign_elevation_challenge(
    app: &AppHandle,
    profile_id: &str,
    challenge: &centrald_protocol::v1::ElevationChallenge,
) -> Result<Vec<u8>> {
    let id: Uuid = profile_id.parse()?;
    let profile_dir = profiles_dir(app)?.join(id.to_string());
    let profile = load_profile_from_dir(&profile_dir)?;
    let key_path = profile.elevation_private_key().ok_or_else(|| {
        anyhow::anyhow!(
            "this Admin profile has no elevation key; re-enroll to enable elevated shells"
        )
    })?;
    let pem = std::fs::read_to_string(key_path)
        .with_context(|| format!("read Admin elevation key {}", key_path.display()))?;
    let signing_key =
        ed25519_dalek::SigningKey::from_pkcs8_pem(&pem).context("parse the Admin elevation key")?;
    let mut payload = Vec::new();
    payload.extend_from_slice(ELEVATION_DOMAIN);
    payload.extend_from_slice(&challenge.nonce);
    payload.extend_from_slice(&challenge.context_hash);
    let signature = signing_key.sign(&payload);
    Ok(signature.to_bytes().to_vec())
}

fn decode_b64(value: &str) -> Result<Vec<u8>> {
    if value.is_empty() {
        return Ok(Vec::new());
    }
    STANDARD.decode(value).context("invalid base64 input")
}

fn timestamp_text(value: Option<prost_types::Timestamp>) -> String {
    value
        .and_then(|timestamp| {
            u32::try_from(timestamp.nanos)
                .ok()
                .and_then(|nanos| chrono::DateTime::from_timestamp(timestamp.seconds, nanos))
        })
        .map_or_else(String::new, |timestamp| timestamp.to_rfc3339())
}

fn display_error(error: impl std::fmt::Display) -> String {
    error.to_string()
}
