//! Broker-side PTY session transport.
//!
//! Shell sessions use a separate connection on the broker channel with
//! length-prefixed JSON frames. The first frame opens the session (signed
//! grant + parameters + OS account), then frames flow in both directions
//! until either side closes. The broker enforces per-frame bounds, byte
//! totals, idle and absolute timeouts, and a concurrent-session limit.
//!
//! Passwords are held only in zeroizing buffers and never logged.

use std::io::{Read, Write};
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

use anyhow::{Context, Result, bail};
use base64::Engine as _;
use base64::engine::general_purpose::STANDARD;
use centrald_common::grant::SignedGrant;
use centrald_platform::broker::GrantVerifier;
use chrono::Utc;
use secrecy::{ExposeSecret, SecretString};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use uuid::Uuid;

use crate::ptys::{PtyController, PtyParts, PtySession, PtySessionSpec, SessionPrivilege};

/// Upper bound for one session wire frame. The server permits data frames up
/// to 1 MiB; base64 encoding expands them by 4/3, so the bound must cover the
/// encoded frame plus JSON envelope overhead.
pub const MAX_SESSION_WIRE_FRAME_BYTES: usize = 1_500_000;
/// Maximum number of concurrent PTY sessions on one machine.
pub const MAX_CONCURRENT_SESSIONS: usize = 8;
/// Bounded totals per session; exceeding either closes the session.
const MAX_SESSION_INPUT_BYTES: u64 = 256 * 1024 * 1024;
const MAX_SESSION_OUTPUT_BYTES: u64 = 1024 * 1024 * 1024;

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(tag = "kind", rename_all = "snake_case", deny_unknown_fields)]
// The open frame carries a full signed grant; everything else is small.
#[allow(clippy::large_enum_variant)]
pub enum SessionWireFrame {
    Open {
        grant: SignedGrant,
        parameters_base64: String,
        columns: u32,
        rows: u32,
        account_user: String,
        account_password_base64: String,
        save_credentials: bool,
    },
    Opened {
        session_id: Uuid,
        warning: String,
    },
    Error {
        message: String,
    },
    Data {
        data_base64: String,
    },
    Resize {
        columns: u32,
        rows: u32,
    },
    Close {
        reason: String,
        exit_code: i32,
    },
}

/// Parameters bound to the shell grant by the server.
#[derive(Debug, Clone, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct SessionParameters {
    pub privilege: String,
    pub user: String,
    pub shell: String,
    pub max_frame_bytes: u32,
    pub idle_timeout_seconds: u32,
    pub absolute_timeout_seconds: u32,
    pub credentials_sha256: String,
}

impl SessionParameters {
    /// Validates every parameter against the broker's hard bounds.
    ///
    /// # Errors
    ///
    /// Returns an error when a parameter is missing or out of range.
    pub fn validate(&self) -> Result<()> {
        if !matches!(self.privilege.as_str(), "low" | "elevated") {
            bail!("session privilege must be 'low' or 'elevated'");
        }
        if !(1024..=1024 * 1024).contains(&self.max_frame_bytes) {
            bail!("session max_frame_bytes must be between 1024 and 1048576");
        }
        if !(30..=86_400).contains(&self.idle_timeout_seconds) {
            bail!("session idle timeout must be between 30 and 86400 seconds");
        }
        if !(300..=86_400).contains(&self.absolute_timeout_seconds) {
            bail!("session absolute timeout must be between 300 and 86400 seconds");
        }
        if !self.credentials_sha256.is_empty() && !is_sha256_hex(&self.credentials_sha256) {
            bail!("session credentials_sha256 must be a SHA-256 hex digest or empty");
        }
        if self.user.len() > 128 {
            bail!("session user must be at most 128 characters");
        }
        if self.shell.len() > 256 {
            bail!("session shell must be at most 256 characters");
        }
        Ok(())
    }
}

fn is_sha256_hex(value: &str) -> bool {
    value.len() == 64 && value.bytes().all(|byte| byte.is_ascii_hexdigit())
}

/// A duplex stream that can be duplicated into concurrent read/write halves.
pub trait DuplexStream: Read + Write + Send {
    /// Duplicates the stream for an independent half.
    ///
    /// # Errors
    ///
    /// Returns an error when the underlying handle cannot be duplicated.
    fn try_duplicate(&self) -> std::io::Result<Self>
    where
        Self: Sized;
}

#[cfg(unix)]
impl DuplexStream for std::os::unix::net::UnixStream {
    fn try_duplicate(&self) -> std::io::Result<Self>
    where
        Self: Sized,
    {
        self.try_clone()
    }
}

/// State shared by a session's input/output/watchdog threads.
struct SessionShared {
    stop: AtomicBool,
    last_activity: Mutex<Instant>,
    input_bytes: std::sync::atomic::AtomicU64,
    output_bytes: std::sync::atomic::AtomicU64,
}

/// The running session registry, bounding concurrent PTY execution.
#[derive(Debug)]
pub struct SessionManager {
    sessions: Mutex<Vec<Uuid>>,
}

impl SessionManager {
    #[must_use]
    pub fn new() -> Self {
        Self {
            sessions: Mutex::new(Vec::new()),
        }
    }

    fn reserve(&self, session_id: Uuid) -> Result<SessionReservation<'_>> {
        let mut sessions = self
            .sessions
            .lock()
            .map_err(|_| anyhow::anyhow!("session registry lock was poisoned"))?;
        if sessions.len() >= MAX_CONCURRENT_SESSIONS {
            bail!("the machine session limit was reached; close another terminal first");
        }
        sessions.push(session_id);
        Ok(SessionReservation {
            manager: self,
            session_id,
        })
    }

    fn release(&self, session_id: Uuid) {
        if let Ok(mut sessions) = self.sessions.lock() {
            sessions.retain(|existing| *existing != session_id);
        }
    }

    #[must_use]
    pub fn active_count(&self) -> usize {
        self.sessions.lock().map_or(0, |sessions| sessions.len())
    }
}

/// RAII reservation of a broker session slot; the slot is released on drop so
/// no error path can leak it.
struct SessionReservation<'a> {
    manager: &'a SessionManager,
    session_id: Uuid,
}

impl Drop for SessionReservation<'_> {
    fn drop(&mut self) {
        self.manager.release(self.session_id);
    }
}

impl Default for SessionManager {
    fn default() -> Self {
        Self::new()
    }
}

/// Runs one session connection to completion: validates the open frame,
/// starts the PTY, then relays frames until either side closes.
///
/// # Errors
///
/// Returns an error only for protocol violations that must terminate the
/// connection; session-level failures are reported as frames.
pub fn serve_session(
    open_bytes: &[u8],
    reader: Box<dyn Read + Send>,
    mut writer: Box<dyn Write + Send>,
    verifier: &Mutex<GrantVerifier>,
    manager: &SessionManager,
) -> Result<()> {
    let open = serde_json::from_slice::<SessionWireFrame>(open_bytes)
        .context("decode session open frame")?;
    let SessionWireFrame::Open {
        grant,
        parameters_base64,
        columns,
        rows,
        account_user,
        account_password_base64,
        save_credentials,
    } = open
    else {
        return Err(anyhow::anyhow!(
            "the first session frame must be an open frame"
        ));
    };
    let parameters_json = STANDARD
        .decode(&parameters_base64)
        .context("decode session parameters")?;
    let params: SessionParameters =
        serde_json::from_slice(&parameters_json).context("decode session parameters")?;
    params.validate()?;
    let digest = hex::encode(Sha256::digest(&parameters_json));
    if digest != grant.grant.parameters_sha256 {
        return Err(anyhow::anyhow!(
            "session parameters do not match the signed grant"
        ));
    }
    verifier
        .lock()
        .map_err(|_| anyhow::anyhow!("broker verifier lock was poisoned"))?
        .verify_and_consume(&grant, Utc::now())?;

    let session_id = grant.grant.job_or_session_id;
    let reservation = manager.reserve(session_id)?;

    let credentials = match resolve_credentials(
        &params,
        &account_user,
        &account_password_base64,
        save_credentials,
    ) {
        Ok(credentials) => credentials,
        Err(error) => {
            drop(reservation);
            let frame = SessionWireFrame::Error {
                message: error.to_string(),
            };
            write_frame(&mut writer, &encode_frame(&frame))?;
            return Ok(());
        }
    };
    if params.privilege == "elevated" && credentials.is_none() {
        drop(reservation);
        let frame = SessionWireFrame::Error {
            message: "elevated shells require OS account credentials".to_owned(),
        };
        write_frame(&mut writer, &encode_frame(&frame))?;
        return Ok(());
    }
    let privilege = match params.privilege.as_str() {
        "low" => SessionPrivilege::Low,
        "elevated" => SessionPrivilege::Elevated,
        _ => unreachable!("validated by SessionParameters::validate"),
    };
    let spec = PtySessionSpec {
        privilege,
        user: params.user.clone(),
        shell: params.shell.clone(),
        columns,
        rows,
    };
    let pty = match PtySession::open(&spec) {
        Ok(pty) => pty,
        Err(error) => {
            drop(reservation);
            let frame = SessionWireFrame::Error {
                message: error.to_string(),
            };
            write_frame(&mut writer, &encode_frame(&frame))?;
            return Ok(());
        }
    };
    let opened = SessionWireFrame::Opened {
        session_id,
        warning: String::new(),
    };
    if let Err(error) = write_frame(&mut writer, &encode_frame(&opened)) {
        drop(reservation);
        return Err(error);
    }

    let result = run_session(pty, reader, writer, &params, session_id, manager);
    drop(reservation);
    result
}

fn resolve_credentials(
    params: &SessionParameters,
    account_user: &str,
    account_password_base64: &str,
    save_credentials: bool,
) -> Result<Option<SecretString>> {
    if save_credentials {
        bail!("saved terminal credentials are unavailable in this alpha release");
    }
    let user = if account_user.is_empty() {
        params.user.clone()
    } else {
        account_user.to_owned()
    };
    if user.is_empty() {
        return Ok(None);
    }
    let Some(password) = decode_password(account_password_base64)? else {
        return Ok(None);
    };
    if !params.credentials_sha256.is_empty() {
        let actual = hex::encode(Sha256::digest(password.expose_secret().as_bytes()));
        if actual != params.credentials_sha256 {
            bail!("account password does not match the signed session parameters");
        }
    }
    crate::auth::validate_account_credentials(&user, &password).map_err(anyhow::Error::msg)?;
    Ok(Some(password))
}

fn decode_password(account_password_base64: &str) -> Result<Option<SecretString>> {
    if account_password_base64.is_empty() {
        return Ok(None);
    }
    let decoded = zeroize::Zeroizing::new(
        STANDARD
            .decode(account_password_base64)
            .context("decode account password")?,
    );
    let password = zeroize::Zeroizing::new(
        String::from_utf8(decoded.to_vec()).context("account password is not valid text")?,
    );
    Ok(Some(SecretString::from(password.as_str())))
}

fn run_session(
    parts: PtyParts,
    reader: Box<dyn Read + Send>,
    writer: Box<dyn Write + Send>,
    params: &SessionParameters,
    session_id: Uuid,
    manager: &SessionManager,
) -> Result<()> {
    let shared = Arc::new(SessionShared {
        stop: AtomicBool::new(false),
        last_activity: Mutex::new(Instant::now()),
        input_bytes: std::sync::atomic::AtomicU64::new(0),
        output_bytes: std::sync::atomic::AtomicU64::new(0),
    });
    let controller = parts.controller;
    let max_frame_bytes = usize::try_from(params.max_frame_bytes).unwrap_or(1024 * 1024);
    let idle_timeout = Duration::from_secs(u64::from(params.idle_timeout_seconds));
    let absolute_timeout = Duration::from_secs(u64::from(params.absolute_timeout_seconds));

    let input_shared = shared.clone();
    let input_controller = controller.clone();
    let input_thread = std::thread::spawn(move || -> Result<()> {
        let outcome = input_loop(
            parts.writer,
            reader,
            &input_controller,
            &input_shared,
            max_frame_bytes,
        );
        input_shared.stop.store(true, Ordering::Relaxed);
        outcome
    });

    let output_shared = shared.clone();
    let output_thread = std::thread::spawn(move || -> Result<()> {
        output_loop(parts.reader, writer, &output_shared, max_frame_bytes)
    });

    let started = Instant::now();
    let mut final_reason: &str = "session ended";
    loop {
        if shared.stop.load(Ordering::Relaxed) {
            break;
        }
        if started.elapsed() > absolute_timeout {
            final_reason = "session absolute timeout reached";
            break;
        }
        let last_activity = *shared
            .last_activity
            .lock()
            .map_err(|_| anyhow::anyhow!("session activity lock was poisoned"))?;
        if last_activity.elapsed() > idle_timeout {
            final_reason = "session idle timeout reached";
            break;
        }
        std::thread::sleep(Duration::from_millis(500));
    }
    shared.stop.store(true, Ordering::Relaxed);
    let mut guard = controller
        .lock()
        .map_err(|_| anyhow::anyhow!("session pty lock was poisoned"))?;
    if let Some(pty) = guard.as_mut() {
        // Kill the child and its whole process group; on Windows the master is
        // dropped below, which closes the pseudoconsole and EOFs the output
        // pipe so the reader thread unblocks.
        pty.kill();
    }
    *guard = None;
    drop(guard);
    let input_result = input_thread.join();
    let output_result = output_thread.join();
    let _ = manager.active_count();
    tracing::info!(%session_id, %final_reason, "shell session ended");
    // Surface an internal thread failure so the connection reports it rather
    // than silently wedging.
    let input_error = match input_result {
        Ok(Ok(())) | Err(_) => None,
        Ok(Err(error)) => Some(error),
    };
    let output_error = match output_result {
        Ok(Ok(())) | Err(_) => None,
        Ok(Err(error)) => Some(error),
    };
    if let Some(error) = output_error {
        return Err(error.context("terminal output thread failed"));
    }
    if let Some(error) = input_error {
        return Err(error.context("terminal input thread failed"));
    }
    Ok(())
}

fn touch_activity(shared: &SessionShared) {
    if let Ok(mut last) = shared.last_activity.lock() {
        *last = Instant::now();
    }
}

fn input_loop(
    mut master_writer: Box<dyn Write + Send>,
    mut socket_reader: Box<dyn Read + Send>,
    controller: &Mutex<Option<PtyController>>,
    shared: &SessionShared,
    max_frame_bytes: usize,
) -> Result<()> {
    loop {
        if shared.stop.load(Ordering::Relaxed) {
            return Ok(());
        }
        let frame_bytes = read_frame(socket_reader.as_mut(), MAX_SESSION_WIRE_FRAME_BYTES)?;
        let frame = serde_json::from_slice::<SessionWireFrame>(&frame_bytes)
            .context("decode session frame")?;
        match frame {
            SessionWireFrame::Data { data_base64 } => {
                let data = STANDARD
                    .decode(&data_base64)
                    .context("decode session data frame")?;
                if data.len() > max_frame_bytes {
                    bail!("session data frame exceeds the configured limit");
                }
                let added = u64::try_from(data.len()).unwrap_or(u64::MAX);
                let total = shared.input_bytes.fetch_add(added, Ordering::Relaxed) + added;
                if total > MAX_SESSION_INPUT_BYTES {
                    bail!("session input bound reached");
                }
                master_writer
                    .write_all(&data)
                    .context("write terminal input")?;
                touch_activity(shared);
            }
            SessionWireFrame::Resize { columns, rows } => {
                controller
                    .lock()
                    .map_err(|_| anyhow::anyhow!("session pty lock was poisoned"))?
                    .as_mut()
                    .context("session is closed")?
                    .resize(columns, rows)?;
                touch_activity(shared);
            }
            SessionWireFrame::Close { .. } | SessionWireFrame::Error { .. } => {
                shared.stop.store(true, Ordering::Relaxed);
                return Ok(());
            }
            SessionWireFrame::Open { .. } | SessionWireFrame::Opened { .. } => {
                bail!("unexpected session frame kind");
            }
        }
    }
}

fn output_loop(
    mut master_reader: Box<dyn Read + Send>,
    mut writer: Box<dyn Write + Send>,
    shared: &SessionShared,
    max_frame_bytes: usize,
) -> Result<()> {
    let mut buffer = vec![0_u8; max_frame_bytes];
    loop {
        if shared.stop.load(Ordering::Relaxed) {
            return Ok(());
        }
        let read = match master_reader.read(&mut buffer) {
            Ok(0) => {
                shared.stop.store(true, Ordering::Relaxed);
                let close = SessionWireFrame::Close {
                    reason: "shell exited".to_owned(),
                    exit_code: 0,
                };
                write_frame(writer.as_mut(), &encode_frame(&close))?;
                return Ok(());
            }
            Ok(read) => read,
            Err(error)
                if matches!(
                    error.kind(),
                    std::io::ErrorKind::Interrupted | std::io::ErrorKind::WouldBlock
                ) =>
            {
                continue;
            }
            Err(error) => {
                shared.stop.store(true, Ordering::Relaxed);
                return Err(error).context("read terminal output");
            }
        };
        let added = u64::try_from(read).unwrap_or(u64::MAX);
        if shared.output_bytes.fetch_add(added, Ordering::Relaxed) + added
            > MAX_SESSION_OUTPUT_BYTES
        {
            shared.stop.store(true, Ordering::Relaxed);
            let close = SessionWireFrame::Close {
                reason: "session output bound reached".to_owned(),
                exit_code: 1,
            };
            write_frame(writer.as_mut(), &encode_frame(&close))?;
            return Ok(());
        }
        let frame = SessionWireFrame::Data {
            data_base64: STANDARD.encode(&buffer[..read]),
        };
        write_frame(writer.as_mut(), &encode_frame(&frame))?;
        touch_activity(shared);
    }
}

fn encode_frame(frame: &SessionWireFrame) -> Vec<u8> {
    serde_json::to_vec(frame).unwrap_or_else(|_| {
        serde_json::to_vec(&SessionWireFrame::Error {
            message: "session frame encoding failed".to_owned(),
        })
        .unwrap_or_default()
    })
}

/// Reads one length-prefixed frame (4-byte big-endian length + JSON body).
///
/// # Errors
///
/// Returns an error on EOF, an invalid or oversized length, or a short body.
pub fn read_frame(reader: &mut dyn Read, max_bytes: usize) -> Result<Vec<u8>> {
    let mut length = [0_u8; 4];
    reader
        .read_exact(&mut length)
        .context("read frame length")?;
    let size = usize::try_from(u32::from_be_bytes(length)).context("frame length is invalid")?;
    if size == 0 || size > max_bytes {
        bail!("session frame exceeds the bound or is empty");
    }
    let mut body = vec![0_u8; size];
    reader.read_exact(&mut body).context("read frame body")?;
    Ok(body)
}

/// Writes one length-prefixed frame.
///
/// # Errors
///
/// Returns an error when the body is too large or the write fails.
pub fn write_frame(writer: &mut dyn Write, body: &[u8]) -> Result<()> {
    let size = u32::try_from(body.len()).context("frame body is too large")?;
    writer.write_all(&size.to_be_bytes())?;
    writer.write_all(body)?;
    writer.flush()?;
    Ok(())
}

/// Strips the length prefix from a single complete wire message (used by the
/// message-mode Windows pipe transport, where each message holds one frame).
///
/// # Errors
///
/// Returns an error for a truncated, empty, or oversized message.
pub fn unframe_message(framed: &[u8], max_body: usize) -> Result<&[u8]> {
    if framed.len() < 4 {
        bail!("broker message is truncated");
    }
    let size = usize::try_from(u32::from_be_bytes([
        framed[0], framed[1], framed[2], framed[3],
    ]))
    .context("broker message length is invalid")?;
    if size == 0 || size > max_body || 4 + size != framed.len() {
        bail!("broker message exceeds the bound or has trailing bytes");
    }
    Ok(&framed[4..4 + size])
}

#[cfg(test)]
#[allow(clippy::unwrap_used)]
mod tests {
    use super::*;

    #[test]
    fn session_parameters_validate_bounds() {
        let mut params = SessionParameters {
            privilege: "low".into(),
            user: "centrald".into(),
            shell: "/bin/bash".into(),
            max_frame_bytes: 65_536,
            idle_timeout_seconds: 900,
            absolute_timeout_seconds: 28_800,
            credentials_sha256: String::new(),
        };
        assert!(params.validate().is_ok());
        params.privilege = "root".into();
        assert!(params.validate().is_err());
        params.privilege = "low".into();
        params.max_frame_bytes = 10;
        assert!(params.validate().is_err());
        params.max_frame_bytes = 65_536;
        params.credentials_sha256 = "zz".repeat(32);
        assert!(params.validate().is_err());
    }

    #[test]
    fn frames_round_trip_with_bounds() {
        let payload = encode_frame(&SessionWireFrame::Data {
            data_base64: STANDARD.encode(b"hello"),
        });
        let mut framed = Vec::new();
        framed.extend_from_slice(&u32::try_from(payload.len()).unwrap().to_be_bytes());
        framed.extend_from_slice(&payload);
        let mut cursor = std::io::Cursor::new(framed.clone());
        let decoded = read_frame(&mut cursor, MAX_SESSION_WIRE_FRAME_BYTES).unwrap();
        assert_eq!(decoded, payload);
        assert!(read_frame(&mut std::io::Cursor::new(Vec::new()), 1024).is_err());
        let mut oversized = Vec::new();
        oversized.extend_from_slice(&(u32::MAX).to_be_bytes());
        assert!(read_frame(&mut std::io::Cursor::new(oversized), 1024).is_err());
    }

    #[test]
    fn saved_credentials_are_release_gated() {
        let params = SessionParameters {
            privilege: "low".into(),
            user: "centrald".into(),
            shell: "/bin/bash".into(),
            max_frame_bytes: 65_536,
            idle_timeout_seconds: 900,
            absolute_timeout_seconds: 28_800,
            credentials_sha256: String::new(),
        };
        let error = resolve_credentials(&params, "centrald", "", true).unwrap_err();
        assert!(error.to_string().contains("unavailable"));
        assert!(
            resolve_credentials(&params, "centrald", "", false)
                .unwrap()
                .is_none()
        );
    }
}
