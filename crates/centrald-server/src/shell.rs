//! Server-side shell session relay and elevation challenges.
//!
//! The Admin's `OpenShell` bidi stream is relayed to the target client's
//! control stream. Each session is owned by one relay task that validates
//! every frame in both directions, enforces frame/byte/timeout bounds, and
//! ends the session durably (`shell_sessions` row, audit, close frames to both
//! sides). Elevated sessions additionally require a consumed elevation
//! challenge signed by the Admin's elevation key.
//!
//! Passwords ride inside the mTLS relay only; they are hashed for grant
//! binding, never stored, and never logged.

use std::sync::Arc;
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::time::Duration;

use centrald_common::grant::{GrantOperation, PrivilegedGrant};
use centrald_protocol::v1::server_frame;
use centrald_protocol::v1::{
    AdminShellFrame, BeginElevationRequest, ElevationChallenge, ServerFrame, ShellClose, ShellData,
    ShellFrame, ShellOpen, ShellPrivilege,
};
use chrono::{DateTime, Utc};
use ed25519_dalek::{Verifier, VerifyingKey};
use rand::RngCore;
use serde::Serialize;
use sha2::{Digest, Sha256};
use sqlx::PgPool;
use tokio::sync::mpsc;
use tonic::{Status, Streaming};
use uuid::Uuid;

use crate::services::RuntimeState;

/// Hard absolute session cap regardless of activity.
pub const SHELL_ABSOLUTE_TIMEOUT_SECONDS: u32 = 28_800;
/// How long an elevation challenge stays valid.
const ELEVATION_CHALLENGE_TTL_SECONDS: i64 = 300;
/// Signature domain for Admin elevation proofs.
const ELEVATION_DOMAIN: &[u8] = b"centrald-elevation-v1\0";
const MAX_SHELL_REASON_BYTES: usize = 512;
const MAX_SHELL_ACCOUNT_BYTES: usize = 128;
const MAX_SHELL_ACCOUNT_PASSWORD_BYTES: usize = 4096;
/// Bounded totals per session; exceeding either closes the session.
const MAX_SHELL_INPUT_BYTES: u64 = 256 * 1024 * 1024;
const MAX_SHELL_OUTPUT_BYTES: u64 = 1024 * 1024 * 1024;

/// Per-session relay state shared between the client stream task and the
/// relay task.
#[derive(Debug)]
pub struct ShellSessionHandle {
    pub session_id: Uuid,
    /// Frames from the client (terminal output) are pushed here for the
    /// Admin's response stream.
    pub admin_in_tx: mpsc::Sender<Result<AdminShellFrame, Status>>,
    pub target_id: Uuid,
    pub actor_id: Uuid,
    pub privilege: String,
    pub max_frame_bytes: usize,
    pub started_at: std::sync::Mutex<std::time::Instant>,
    pub last_activity: std::sync::Mutex<std::time::Instant>,
    pub admin_sequence: AtomicU64,
    pub client_sequence: AtomicU64,
    pub input_bytes: AtomicU64,
    pub output_bytes: AtomicU64,
    pub closed: AtomicBool,
}

impl ShellSessionHandle {
    fn touch(&self) {
        if let Ok(mut last) = self.last_activity.lock() {
            *last = std::time::Instant::now();
        }
    }

    fn closed(&self) -> bool {
        self.closed.load(Ordering::Relaxed)
    }
}

/// The validated open request, converted into broker-bound session
/// parameters.
#[derive(Debug)]
pub struct ShellOpenPlan {
    pub session_id: Uuid,
    pub target_id: Uuid,
    pub privilege: String,
    pub parameters_json: Vec<u8>,
    pub operation: GrantOperation,
}

/// Validates a `ShellOpen` against the Admin, target, and settings, and
/// verifies the elevation challenge for elevated sessions.
///
/// # Errors
///
/// Returns a gRPC status describing the rejected request.
pub async fn validate_shell_open(
    pool: &PgPool,
    state: &RuntimeState,
    actor: Uuid,
    open: &ShellOpen,
) -> Result<ShellOpenPlan, Status> {
    let target_id = parse_uuid(&open.target_id, "target_id")?;
    let privilege = match ShellPrivilege::try_from(open.privilege) {
        Ok(ShellPrivilege::Low) => "low",
        Ok(ShellPrivilege::Elevated) => "elevated",
        _ => return Err(Status::invalid_argument("unsupported shell privilege")),
    };
    if !(2..=500).contains(&open.columns) || !(2..=500).contains(&open.rows) {
        return Err(Status::invalid_argument(
            "shell size must be 2-500 columns and rows",
        ));
    }
    if open.reason.is_empty()
        || open.reason.len() > MAX_SHELL_REASON_BYTES
        || open.reason.chars().any(char::is_control)
    {
        return Err(Status::invalid_argument("shell reason is invalid"));
    }
    if open.account_user.len() > MAX_SHELL_ACCOUNT_BYTES
        || open.account_user.chars().any(char::is_control)
    {
        return Err(Status::invalid_argument("shell OS account is invalid"));
    }
    if open.account_password.len() > MAX_SHELL_ACCOUNT_PASSWORD_BYTES {
        return Err(Status::invalid_argument(
            "shell OS account password is too large",
        ));
    }
    if open.save_credentials && open.account_password.is_empty() {
        return Err(Status::invalid_argument(
            "credential saving requires a password to save",
        ));
    }
    if privilege == "elevated" && open.account_user.trim().is_empty() {
        return Err(Status::invalid_argument(
            "elevated shells require an OS account",
        ));
    }
    if privilege == "low" && open.account_user == "root" {
        return Err(Status::invalid_argument("a low shell must not run as root"));
    }

    let row = sqlx::query_as::<_, (String, bool)>(
        "SELECT COALESCE(os, ''), COALESCE(capabilities ? 'typed_jobs', FALSE) \
         FROM clients WHERE identity_id = $1",
    )
    .bind(target_id)
    .fetch_optional(pool)
    .await
    .map_err(crate::services::internal)?
    .ok_or_else(|| Status::not_found("target client does not exist"))?;
    if !row.1 {
        return Err(Status::failed_precondition(
            "target client does not support typed operations",
        ));
    }
    if !state.client_online(target_id) {
        return Err(Status::failed_precondition("target client is offline"));
    }

    let user = if open.account_user.trim().is_empty() {
        "centrald".to_owned()
    } else {
        open.account_user.clone()
    };
    let credentials_sha256 = if open.account_password.is_empty() {
        String::new()
    } else {
        hex::encode(Sha256::digest(&open.account_password))
    };
    if privilege == "elevated" {
        verify_elevation_challenge(pool, actor, target_id, open, privilege).await?;
    }
    let parameters = SessionParameters {
        privilege,
        user: &user,
        shell: "",
        max_frame_bytes: state.shell_max_frame_bytes(),
        idle_timeout_seconds: state.shell_idle_timeout_seconds(),
        absolute_timeout_seconds: SHELL_ABSOLUTE_TIMEOUT_SECONDS,
        credentials_sha256: &credentials_sha256,
    };
    let parameters_json = serde_json::to_vec(&parameters).map_err(crate::services::internal)?;
    Ok(ShellOpenPlan {
        session_id: Uuid::now_v7(),
        target_id,
        privilege: privilege.to_owned(),
        parameters_json,
        operation: if privilege == "low" {
            GrantOperation::OpenLowShell
        } else {
            GrantOperation::OpenElevatedShell
        },
    })
}

#[derive(Serialize)]
#[serde(rename_all = "snake_case")]
struct SessionParameters<'a> {
    privilege: &'a str,
    user: &'a str,
    shell: &'a str,
    max_frame_bytes: u32,
    idle_timeout_seconds: u32,
    absolute_timeout_seconds: u32,
    credentials_sha256: &'a str,
}

/// Verifies and consumes an elevation challenge presented for an elevated
/// shell.
///
/// # Errors
///
/// Returns a status when the challenge is unknown, expired, already consumed,
/// or not signed by the requesting Admin's elevation key.
pub async fn verify_elevation_challenge(
    pool: &PgPool,
    actor: Uuid,
    target_id: Uuid,
    open: &ShellOpen,
    _privilege: &str,
) -> Result<(), Status> {
    let challenge_id = parse_uuid(&open.challenge_id, "challenge_id")?;
    if open.challenge_signature.is_empty() {
        return Err(Status::invalid_argument(
            "elevation challenge signature is missing",
        ));
    }
    let row = sqlx::query_as::<_, (Uuid, Uuid, Vec<u8>, Vec<u8>, DateTime<Utc>, Option<Vec<u8>>)>(
        "SELECT c.admin_id, c.target_id, c.nonce, c.context_hash, c.expires_at, i.elevation_public_key \
         FROM elevation_challenges c LEFT JOIN identities i ON i.id = c.admin_id \
         WHERE c.id = $1",
    )
    .bind(challenge_id)
    .fetch_optional(pool)
    .await
    .map_err(crate::services::internal)?
    .ok_or_else(|| Status::not_found("elevation challenge does not exist"))?;
    let (admin_id, bound_target, nonce, context_hash, expires_at, elevation_key) = row;
    if admin_id != actor || bound_target != target_id {
        return Err(Status::permission_denied(
            "elevation challenge is not for this target",
        ));
    }
    if expires_at <= Utc::now() {
        return Err(Status::failed_precondition(
            "elevation challenge has expired",
        ));
    }
    let Some(elevation_key) = elevation_key else {
        return Err(Status::failed_precondition(
            "the requesting Admin has no elevation key; re-enroll to enable elevated shells",
        ));
    };
    if elevation_key.len() != 32 {
        return Err(Status::failed_precondition(
            "the Admin elevation key is invalid",
        ));
    }
    let mut payload = Vec::with_capacity(ELEVATION_DOMAIN.len() + nonce.len() + context_hash.len());
    payload.extend_from_slice(ELEVATION_DOMAIN);
    payload.extend_from_slice(&nonce);
    payload.extend_from_slice(&context_hash);
    let signature = ed25519_dalek::Signature::from_slice(&open.challenge_signature)
        .map_err(|_| Status::invalid_argument("elevation challenge signature is invalid"))?;
    let verifying_key = VerifyingKey::from_bytes(
        <&[u8; 32]>::try_from(elevation_key.as_slice())
            .map_err(|_| Status::failed_precondition("the Admin elevation key is invalid"))?,
    )
    .map_err(|_| Status::failed_precondition("the Admin elevation key is invalid"))?;
    if verifying_key.verify(&payload, &signature).is_err() {
        return Err(Status::permission_denied(
            "elevation challenge signature does not verify",
        ));
    }
    let consumed = sqlx::query(
        "UPDATE elevation_challenges SET consumed_at = NOW() \
         WHERE id = $1 AND consumed_at IS NULL AND expires_at > NOW()",
    )
    .bind(challenge_id)
    .execute(pool)
    .await
    .map_err(crate::services::internal)?
    .rows_affected();
    if consumed != 1 {
        return Err(Status::failed_precondition(
            "elevation challenge was already consumed",
        ));
    }
    Ok(())
}

/// Creates the shell session row and the signed grant, and returns the
/// frames to deliver to the client.
///
/// # Errors
///
/// Returns a status when the database write fails.
pub async fn create_shell_session(
    pool: &PgPool,
    state: &RuntimeState,
    actor: Uuid,
    open: &ShellOpen,
    plan: &ShellOpenPlan,
) -> Result<(ShellFrame, Vec<u8>), Status> {
    sqlx::query(
        "INSERT INTO shell_sessions (id, target_id, actor_id, privilege, reason) \
         VALUES ($1, $2, $3, $4, $5)",
    )
    .bind(plan.session_id)
    .bind(plan.target_id)
    .bind(actor)
    .bind(&plan.privilege)
    .bind(&open.reason)
    .execute(pool)
    .await
    .map_err(crate::services::internal)?;
    crate::services::audit(
        pool,
        Some(actor),
        "admin",
        "shell.session.open",
        Some(plan.target_id),
        "opened",
        serde_json::json!({
            "session_id": plan.session_id,
            "privilege": plan.privilege,
        }),
    )
    .await?;
    let grant = PrivilegedGrant {
        id: Uuid::now_v7(),
        device_id: plan.target_id,
        job_or_session_id: plan.session_id,
        admin_id: actor,
        operation: plan.operation.clone(),
        parameters_sha256: hex::encode(Sha256::digest(&plan.parameters_json)),
        issued_at: Utc::now() - chrono::Duration::seconds(5),
        expires_at: Utc::now() + chrono::Duration::seconds(960),
        nonce: plan.session_id.to_string(),
    }
    .sign(state.grant_signing_key())
    .map_err(crate::services::internal)?;
    let signed_grant = serde_json::to_vec(&grant).map_err(crate::services::internal)?;
    let frame = ShellFrame {
        payload: Some(centrald_protocol::v1::shell_frame::Payload::Open(
            ShellOpen {
                session_id: plan.session_id.to_string(),
                target_id: plan.target_id.to_string(),
                privilege: open.privilege,
                reason: open.reason.clone(),
                challenge_id: open.challenge_id.clone(),
                challenge_signature: open.challenge_signature.clone(),
                columns: open.columns,
                rows: open.rows,
                account_user: open.account_user.clone(),
                account_password: open.account_password.clone(),
                save_credentials: open.save_credentials,
                parameters_json: plan.parameters_json.clone(),
            },
        )),
    };
    Ok((frame, signed_grant))
}

/// Creates an elevation challenge for an elevated shell request.
///
/// # Errors
///
/// Returns a status when the target is invalid or the database write fails.
pub async fn begin_elevation(
    pool: &PgPool,
    actor: Uuid,
    request: BeginElevationRequest,
) -> Result<ElevationChallenge, Status> {
    let target_id = parse_uuid(&request.target_id, "target_id")?;
    if request.operation != "open_shell" {
        return Err(Status::invalid_argument("unsupported elevation operation"));
    }
    if request.reason.is_empty()
        || request.reason.len() > MAX_SHELL_REASON_BYTES
        || request.reason.chars().any(char::is_control)
    {
        return Err(Status::invalid_argument("elevation reason is invalid"));
    }
    let supports: bool = sqlx::query_scalar(
        "SELECT COALESCE(capabilities ? 'typed_jobs', FALSE) FROM clients WHERE identity_id = $1",
    )
    .bind(target_id)
    .fetch_optional(pool)
    .await
    .map_err(crate::services::internal)?
    .unwrap_or(false);
    if !supports {
        return Err(Status::failed_precondition(
            "target client does not support typed operations",
        ));
    }
    let mut nonce = vec![0_u8; 32];
    rand::rng().fill_bytes(&mut nonce);
    let mut context = Vec::new();
    context.extend_from_slice(target_id.as_bytes());
    context.extend_from_slice(request.operation.as_bytes());
    context.extend_from_slice(request.reason.as_bytes());
    let context_hash = Sha256::digest(&context).to_vec();
    let challenge_id = Uuid::now_v7();
    let expires_at = Utc::now() + chrono::Duration::seconds(ELEVATION_CHALLENGE_TTL_SECONDS);
    sqlx::query(
        "INSERT INTO elevation_challenges \
         (id, admin_id, target_id, operation, nonce, context_hash, expires_at) \
         VALUES ($1, $2, $3, $4, $5, $6, $7)",
    )
    .bind(challenge_id)
    .bind(actor)
    .bind(target_id)
    .bind(&request.operation)
    .bind(&nonce)
    .bind(&context_hash)
    .bind(expires_at)
    .execute(pool)
    .await
    .map_err(crate::services::internal)?;
    crate::services::audit(
        pool,
        Some(actor),
        "admin",
        "shell.elevation.begin",
        Some(target_id),
        "challenge_issued",
        serde_json::json!({
            "challenge_id": challenge_id,
            "operation": &request.operation,
        }),
    )
    .await?;
    Ok(ElevationChallenge {
        id: challenge_id.to_string(),
        nonce,
        context_hash,
        expires_at: Some(prost_types::Timestamp {
            seconds: expires_at.timestamp(),
            nanos: i32::try_from(expires_at.timestamp_subsec_nanos()).unwrap_or(0),
        }),
    })
}

/// Ends a shell session durably and best-effort notifies both sides.
pub async fn end_shell_session(
    pool: &PgPool,
    session_id: Uuid,
    outcome: &str,
    client_tx: &Option<mpsc::Sender<Result<ServerFrame, Status>>>,
    admin_tx: &Option<mpsc::Sender<Result<AdminShellFrame, Status>>>,
    target_id: Option<Uuid>,
) {
    if let Err(error) = sqlx::query(
        "UPDATE shell_sessions SET ended_at = NOW(), outcome = $2 \
         WHERE id = $1 AND ended_at IS NULL",
    )
    .bind(session_id)
    .bind(outcome)
    .execute(pool)
    .await
    {
        tracing::error!(%session_id, %error, "could not close shell session row");
    }
    if let Some(target_id) = target_id
        && let Err(error) = crate::services::audit(
            pool,
            None,
            "server",
            "shell.session.end",
            Some(target_id),
            "closed",
            serde_json::json!({
                "session_id": session_id,
                "outcome": outcome,
            }),
        )
        .await
    {
        tracing::error!(%session_id, %error, "could not audit shell session end");
    }
    let close = ShellFrame {
        payload: Some(centrald_protocol::v1::shell_frame::Payload::Close(
            ShellClose {
                session_id: session_id.to_string(),
                reason: outcome.to_owned(),
                exit_code: 0,
            },
        )),
    };
    if let Some(client_tx) = client_tx {
        let _ = client_tx
            .send(Ok(ServerFrame {
                payload: Some(server_frame::Payload::Shell(close.clone())),
            }))
            .await;
    }
    if let Some(admin_tx) = admin_tx {
        let _ = admin_tx
            .send(Ok(AdminShellFrame { shell: Some(close) }))
            .await;
    }
}

/// Validates one frame on the Admin → client leg and forwards it.
///
/// # Errors
///
/// Returns a status that terminates the session on violation.
pub async fn relay_admin_frame(
    handle: &Arc<ShellSessionHandle>,
    frame: AdminShellFrame,
    client_tx: &mpsc::Sender<Result<ServerFrame, Status>>,
) -> Result<(), Status> {
    if handle.closed() {
        return Err(Status::failed_precondition("shell session is closed"));
    }
    let Some(shell) = frame.shell else {
        return Err(Status::invalid_argument("empty Admin shell frame"));
    };
    let Some(payload) = shell.payload else {
        return Err(Status::invalid_argument("empty Admin shell frame"));
    };
    match payload {
        centrald_protocol::v1::shell_frame::Payload::Data(data) => {
            validate_shell_data(&data, handle)?;
            let sequence = handle.admin_sequence.fetch_add(1, Ordering::Relaxed) + 1;
            let added = u64::try_from(data.data.len()).unwrap_or(u64::MAX);
            if handle.input_bytes.fetch_add(added, Ordering::Relaxed) + added
                > MAX_SHELL_INPUT_BYTES
            {
                return Err(Status::resource_exhausted("shell input bound reached"));
            }
            let data = ShellData {
                session_id: data.session_id,
                sequence,
                data: data.data,
            };
            let frame = ShellFrame {
                payload: Some(centrald_protocol::v1::shell_frame::Payload::Data(data)),
            };
            client_tx
                .send(Ok(ServerFrame {
                    payload: Some(server_frame::Payload::Shell(frame)),
                }))
                .await
                .map_err(|_| Status::cancelled("target client stream closed"))?;
            handle.touch();
        }
        centrald_protocol::v1::shell_frame::Payload::Resize(resize) => {
            if resize.columns < 2 || resize.rows < 2 || resize.columns > 500 || resize.rows > 500 {
                return Err(Status::invalid_argument("invalid shell resize"));
            }
            let resize_session = parse_uuid(&resize.session_id, "session_id")?;
            if resize_session != handle.session_id {
                return Err(Status::permission_denied(
                    "shell frame session ID does not match this session",
                ));
            }
            client_tx
                .send(Ok(ServerFrame {
                    payload: Some(server_frame::Payload::Shell(ShellFrame {
                        payload: Some(centrald_protocol::v1::shell_frame::Payload::Resize(resize)),
                    })),
                }))
                .await
                .map_err(|_| Status::cancelled("target client stream closed"))?;
            handle.touch();
        }
        centrald_protocol::v1::shell_frame::Payload::Close(_) => {
            return Err(Status::failed_precondition(
                "the Admin may not close a session; end the stream instead",
            ));
        }
        centrald_protocol::v1::shell_frame::Payload::Open(_) => {
            return Err(Status::failed_precondition(
                "a session is already open; open frames are server-generated",
            ));
        }
    }
    Ok(())
}

/// Validates and forwards one client → Admin data frame.
///
/// # Errors
///
/// Returns a status terminating the session on protocol violations; data on a
/// closed session is dropped without error so racing in-flight output cannot
/// kill the client's control stream.
pub fn relay_client_data(
    handle: &Arc<ShellSessionHandle>,
    data: &ShellData,
) -> Result<Option<AdminShellFrame>, Status> {
    if handle.closed() {
        return Ok(None);
    }
    validate_shell_data(data, handle)?;
    let sequence = handle.client_sequence.fetch_add(1, Ordering::Relaxed) + 1;
    let added = u64::try_from(data.data.len()).unwrap_or(u64::MAX);
    if handle.output_bytes.fetch_add(added, Ordering::Relaxed) + added > MAX_SHELL_OUTPUT_BYTES {
        return Err(Status::resource_exhausted("shell output bound reached"));
    }
    handle.touch();
    let data = ShellData {
        session_id: data.session_id.clone(),
        sequence,
        data: data.data.clone(),
    };
    Ok(Some(AdminShellFrame {
        shell: Some(ShellFrame {
            payload: Some(centrald_protocol::v1::shell_frame::Payload::Data(data)),
        }),
    }))
}

fn validate_shell_data(data: &ShellData, handle: &Arc<ShellSessionHandle>) -> Result<(), Status> {
    let session_id = parse_uuid(&data.session_id, "session_id")?;
    if session_id != handle.session_id {
        return Err(Status::permission_denied(
            "shell frame session ID does not match this session",
        ));
    }
    if data.data.len() > handle.max_frame_bytes {
        return Err(Status::resource_exhausted(
            "shell data frame exceeds the limit",
        ));
    }
    Ok(())
}

fn parse_uuid(value: &str, field: &str) -> Result<Uuid, Status> {
    value
        .parse::<Uuid>()
        .map_err(|_| Status::invalid_argument(format!("{field} is invalid")))
}

/// Checks idle and absolute timeouts for a session using a monotonic clock.
pub fn shell_deadline_exceeded(
    handle: &ShellSessionHandle,
    idle_timeout_seconds: u32,
    absolute_timeout_seconds: u32,
) -> bool {
    let started = handle
        .started_at
        .lock()
        .map_or_else(|_| std::time::Instant::now(), |value| *value);
    let last = handle
        .last_activity
        .lock()
        .map_or_else(|_| std::time::Instant::now(), |value| *value);
    let now = std::time::Instant::now();
    now.saturating_duration_since(last) > Duration::from_secs(u64::from(idle_timeout_seconds))
        || now.saturating_duration_since(started)
            > Duration::from_secs(u64::from(absolute_timeout_seconds))
}

/// Waits for one inbound Admin frame with a deadline-checking heartbeat.
///
/// # Errors
///
/// Returns a status when the session deadline is exceeded or the frame cannot
/// be decoded; `Ok(None)` means the Admin closed the stream.
pub async fn next_admin_frame(
    inbound: &mut Streaming<AdminShellFrame>,
    handle: &Arc<ShellSessionHandle>,
    idle_timeout_seconds: u32,
    absolute_timeout_seconds: u32,
) -> Result<Option<AdminShellFrame>, Status> {
    loop {
        if shell_deadline_exceeded(handle, idle_timeout_seconds, absolute_timeout_seconds) {
            return Err(Status::deadline_exceeded("shell session timeout reached"));
        }
        match tokio::time::timeout(Duration::from_secs(5), inbound.message()).await {
            Ok(Ok(Some(frame))) => return Ok(Some(frame)),
            Ok(Ok(None)) => return Ok(None),
            Ok(Err(_)) => {
                return Err(Status::invalid_argument(
                    "could not decode Admin shell frame",
                ));
            }
            Err(_) => {}
        }
    }
}

/// Opens the shell session and delivers the grant + open frame to the client.
///
/// # Errors
///
/// Returns a status when the client stream cannot be reached.
pub async fn deliver_shell_open_to_client(
    state: &RuntimeState,
    target_id: Uuid,
    frame: &ShellFrame,
    signed_grant: &[u8],
) -> Result<mpsc::Sender<Result<ServerFrame, Status>>, Status> {
    let client_tx = state
        .client_stream(target_id)
        .ok_or_else(|| Status::failed_precondition("target client stream is unavailable"))?;
    client_tx
        .send(Ok(ServerFrame {
            payload: Some(server_frame::Payload::SignedGrant(signed_grant.to_vec())),
        }))
        .await
        .map_err(|_| Status::cancelled("target client stream closed"))?;
    client_tx
        .send(Ok(ServerFrame {
            payload: Some(server_frame::Payload::Shell(frame.clone())),
        }))
        .await
        .map_err(|_| Status::cancelled("target client stream closed"))?;
    Ok(client_tx)
}

/// Registers the session so client frames route to the Admin stream.
///
/// # Errors
///
/// Returns a status when the session registry is unavailable or the active
/// session limit is reached.
pub fn register_shell_session(
    state: &RuntimeState,
    session_id: Uuid,
    handle: Arc<ShellSessionHandle>,
) -> Result<(), Status> {
    state
        .insert_shell_session(session_id, handle)
        .map_err(Status::resource_exhausted)
}

/// Removes the session from the registry.
pub fn unregister_shell_session(state: &RuntimeState, session_id: Uuid) {
    state.remove_shell_session(session_id);
}

/// Looks up the session for a client frame.
#[must_use]
pub fn shell_session_for_client(
    state: &RuntimeState,
    session_id: Uuid,
    client_id: Uuid,
) -> Option<Arc<ShellSessionHandle>> {
    let handle = state.get_shell_session(session_id)?;
    (handle.target_id == client_id).then_some(handle)
}

#[cfg(test)]
#[allow(clippy::unwrap_used)]
mod tests {
    use super::*;

    fn handle(seconds_since_activity: u64) -> Arc<ShellSessionHandle> {
        handle_since(seconds_since_activity, 30)
    }

    fn handle_since(
        seconds_since_activity: u64,
        seconds_since_start: u64,
    ) -> Arc<ShellSessionHandle> {
        let now = std::time::Instant::now();
        let age = std::time::Duration::from_secs(seconds_since_start);
        let idle = std::time::Duration::from_secs(seconds_since_activity);
        let handle = ShellSessionHandle {
            session_id: Uuid::now_v7(),
            admin_in_tx: mpsc::channel(1).0,
            target_id: Uuid::now_v7(),
            actor_id: Uuid::now_v7(),
            privilege: "low".to_owned(),
            max_frame_bytes: 65_536,
            started_at: std::sync::Mutex::new(now.checked_sub(age).unwrap()),
            last_activity: std::sync::Mutex::new(now.checked_sub(idle).unwrap()),
            admin_sequence: AtomicU64::new(0),
            client_sequence: AtomicU64::new(0),
            input_bytes: AtomicU64::new(0),
            output_bytes: AtomicU64::new(0),
            closed: AtomicBool::new(false),
        };
        Arc::new(handle)
    }

    #[test]
    fn session_parameters_serialize_with_broker_field_names() {
        let params = SessionParameters {
            privilege: "low",
            user: "centrald",
            shell: "",
            max_frame_bytes: 65_536,
            idle_timeout_seconds: 900,
            absolute_timeout_seconds: SHELL_ABSOLUTE_TIMEOUT_SECONDS,
            credentials_sha256: "",
        };
        let value: serde_json::Value = serde_json::to_value(&params).unwrap();
        let object = value.as_object().unwrap();
        for key in [
            "privilege",
            "user",
            "shell",
            "max_frame_bytes",
            "idle_timeout_seconds",
            "absolute_timeout_seconds",
            "credentials_sha256",
        ] {
            assert!(object.contains_key(key), "missing broker parameter {key}");
        }
    }

    #[test]
    fn deadlines_track_idle_and_absolute_bounds() {
        assert!(!shell_deadline_exceeded(&handle(5), 900, 28_800));
        assert!(shell_deadline_exceeded(&handle(1000), 900, 28_800));
        assert!(shell_deadline_exceeded(
            &handle_since(5, u64::from(SHELL_ABSOLUTE_TIMEOUT_SECONDS) + 60),
            900,
            SHELL_ABSOLUTE_TIMEOUT_SECONDS,
        ));
    }

    #[test]
    fn parse_uuid_rejects_malformed_values() {
        assert!(parse_uuid(&Uuid::now_v7().to_string(), "id").is_ok());
        assert!(parse_uuid("not-a-uuid", "id").is_err());
        assert!(parse_uuid("", "id").is_err());
    }
}
