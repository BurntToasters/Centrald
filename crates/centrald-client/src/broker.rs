//! Privileged broker: the root-side half of the job execution path.
//!
//! The client daemon is unprivileged. Typed, short-lived, server-signed
//! grants are forwarded over an ACL-restricted local channel to this broker,
//! which verifies the grant, executes the allowlisted operation, and reports
//! the bounded result back to the daemon for delivery as a job event.
//!
//! Exactly-once semantics are provided by a durable ledger: each job is marked
//! `Executing` before its operation runs and `Completed` after. A re-dispatched
//! job replays the recorded result instead of running twice, and an
//! interrupted marker fails closed with an explicit "outcome unknown" error.
//!
//! The broker performs blocking operations (apt, systemctl) inline; it is a
//! dedicated process whose only job is serialized execution, so a running
//! operation simply queues later connections.

use std::path::PathBuf;
use std::sync::{Arc, Mutex};
use std::time::Duration;

use anyhow::{Context, Result, bail};
pub use centrald_platform::broker::BrokerRequest;
use centrald_platform::broker::{
    BrokerResponse, GrantVerifier, MAX_WIRE_REQUEST_BYTES, MAX_WIRE_RESPONSE_BYTES, OperationRunner,
};
use chrono::{DateTime, Utc};
use ed25519_dalek::VerifyingKey;
use ed25519_dalek::pkcs8::DecodePublicKey;
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
#[cfg(unix)]
use std::path::Path;
#[cfg(unix)]
use tokio::net::UnixStream;
#[cfg(unix)]
use tracing::warn;
use tracing::{error, info};

use crate::ledger::{BrokerLedger, LedgerLookup};
use crate::runners::SystemOperationRunner;

/// The one supported Unix broker socket. Daemon and broker both hard-code it;
/// a client daemon never learns the path from configuration.
pub const BROKER_SOCKET_PATH: &str = "/run/centrald/broker.sock";
/// The Linux daemon runs as the packaged `centrald` service account.
#[cfg(unix)]
const DAEMON_USER: &str = "centrald";
#[cfg(unix)]
const MAX_PASSWD_BYTES: u64 = 1024 * 1024;
/// How long the daemon waits for a broker round trip before giving up.
pub const BROKER_ROUND_TRIP_TIMEOUT: Duration = Duration::from_secs(1200);

/// Tagged wire result so a rejected/errored request round-trips as a typed
/// failure instead of a parse error.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(tag = "result", rename_all = "snake_case", deny_unknown_fields)]
pub enum WireResult {
    Ok { response: BrokerResponse },
    Error { message: String },
}

/// Runs the privileged broker until the platform channel terminates.
///
/// # Errors
///
/// Returns when the client identity cannot be loaded or the local channel
/// fails; systemd/SCM restart the service on failure.
pub async fn run() -> Result<()> {
    let (_shutdown_sender, shutdown_receiver) = tokio::sync::watch::channel(false);
    run_with_shutdown(shutdown_receiver).await
}

/// Runs the privileged broker until the supplied shutdown signal becomes true.
///
/// On Windows the SCM stop handler additionally terminates the process after a
/// short grace period because the blocking pipe accept cannot be interrupted.
///
/// # Errors
///
/// Returns when the client identity cannot be loaded or the local channel
/// fails; systemd/SCM restart the service on failure.
#[cfg_attr(windows, allow(unused_mut))]
pub async fn run_with_shutdown(mut shutdown: tokio::sync::watch::Receiver<bool>) -> Result<()> {
    let executor = Arc::new(build_executor()?);
    info!("privileged broker started");
    #[cfg(unix)]
    {
        serve_unix(executor, &mut shutdown).await
    }
    #[cfg(windows)]
    {
        let _ = shutdown;
        serve_windows(executor).await
    }
    #[cfg(not(any(unix, windows)))]
    {
        let _ = executor;
        bail!("privileged broker is unsupported on this operating system")
    }
}

fn build_executor() -> Result<BrokerExecutor<SystemOperationRunner>> {
    let (_path, config) = crate::enrollment::load_latest_config()?;
    let grant_pem = std::fs::read_to_string(&config.grant_signing_public_key)
        .with_context(|| format!("read {}", config.grant_signing_public_key.display()))?;
    let verifying_key = VerifyingKey::from_public_key_pem(&grant_pem)
        .context("parse the server grant verification key")?;
    let ledger = BrokerLedger::open(&broker_state_dir()?)?;
    Ok(BrokerExecutor::new(
        GrantVerifier::new(config.identity_id, verifying_key),
        ledger,
        SystemOperationRunner,
    ))
}

/// Returns the fixed root-owned broker state directory.
///
/// # Errors
///
/// Returns an error when the fixed Windows state root cannot be resolved.
pub fn broker_state_dir() -> Result<PathBuf> {
    #[cfg(unix)]
    {
        Ok(PathBuf::from("/var/lib/centrald-broker"))
    }
    #[cfg(windows)]
    {
        let data_dir = centrald_common::config::client_data_dir()
            .context("resolve the fixed CentralD state root")?;
        Ok(data_dir.join("Broker"))
    }
    #[cfg(not(any(unix, windows)))]
    {
        bail!("broker state is unsupported on this operating system")
    }
}

/// Forwards one verified job to the broker and returns the wire result.
///
/// # Errors
///
/// Returns an error when the broker channel is unavailable, the exchange
/// exceeds its timeout, or the response is malformed or oversized.
pub async fn submit_request(request: &BrokerRequest) -> Result<WireResult> {
    let bytes = serde_json::to_vec(request).context("serialize broker request")?;
    if bytes.len() > MAX_WIRE_REQUEST_BYTES {
        bail!("broker request exceeds the wire bound");
    }
    #[cfg(unix)]
    {
        let response = tokio::time::timeout(
            BROKER_ROUND_TRIP_TIMEOUT,
            unix_round_trip(BROKER_SOCKET_PATH, &bytes),
        )
        .await
        .context("broker round trip timed out")??;
        decode_wire_result(&response)
    }
    #[cfg(windows)]
    {
        let response = tokio::time::timeout(
            BROKER_ROUND_TRIP_TIMEOUT,
            tokio::task::spawn_blocking(move || crate::windows_ffi::pipe_request(&bytes)),
        )
        .await
        .context("broker round trip timed out")?
        .context("broker pipe worker failed")??;
        decode_wire_result(&response)
    }
    #[cfg(not(any(unix, windows)))]
    {
        let _ = bytes;
        bail!("broker transport is unsupported on this operating system")
    }
}

#[cfg(unix)]
async fn unix_round_trip(socket_path: &str, request: &[u8]) -> Result<Vec<u8>> {
    use tokio::io::{AsyncReadExt, AsyncWriteExt};

    let mut stream = UnixStream::connect(socket_path)
        .await
        .with_context(|| format!("connect to {socket_path}; is the privileged broker running?"))?;
    let framed = frame_bytes(request)?;
    stream
        .write_all(&framed)
        .await
        .context("send broker request")?;
    stream.shutdown().await.context("finish broker request")?;
    let mut response = Vec::new();
    stream
        .take(MAX_WIRE_RESPONSE_BYTES + 8)
        .read_to_end(&mut response)
        .await
        .context("read broker response")?;
    let (body, _) = unframe_bytes(&response, MAX_WIRE_RESPONSE_BYTES)?;
    Ok(body.to_vec())
}

/// Length-prefixes a request body for the broker wire.
#[cfg(unix)]
fn frame_bytes(body: &[u8]) -> Result<Vec<u8>> {
    let size = u32::try_from(body.len()).context("broker request is too large")?;
    let mut framed = Vec::with_capacity(body.len() + 4);
    framed.extend_from_slice(&size.to_be_bytes());
    framed.extend_from_slice(body);
    Ok(framed)
}

/// Strips the length prefix from a broker wire message.
#[cfg(unix)]
fn unframe_bytes(framed: &[u8], max_body: usize) -> Result<(&[u8], usize)> {
    if framed.len() < 4 {
        bail!("broker response is truncated");
    }
    let size = usize::try_from(u32::from_be_bytes([
        framed[0], framed[1], framed[2], framed[3],
    ]))
    .context("broker response length is invalid")?;
    if size == 0 || size > max_body {
        bail!("broker response exceeds the wire bound");
    }
    let total = 4_usize.saturating_add(size);
    if total > framed.len() {
        bail!("broker response is truncated");
    }
    Ok((&framed[4..total], total))
}

fn decode_wire_result(bytes: &[u8]) -> Result<WireResult> {
    let result: WireResult = serde_json::from_slice(bytes).context("decode broker response")?;
    Ok(result)
}

#[cfg(unix)]
async fn serve_unix(
    executor: Arc<BrokerExecutor<SystemOperationRunner>>,
    shutdown: &mut tokio::sync::watch::Receiver<bool>,
) -> Result<()> {
    use std::os::unix::fs::PermissionsExt;

    use tokio::net::UnixListener;

    let socket_path = Path::new(BROKER_SOCKET_PATH);
    validate_socket_path(socket_path)?;
    let parent = socket_path
        .parent()
        .context("broker socket has no parent")?;
    let parent_metadata = parent
        .symlink_metadata()
        .with_context(|| format!("inspect broker socket directory {}", parent.display()))?;
    if parent_metadata.file_type().is_symlink() || !parent_metadata.is_dir() {
        bail!("broker socket directory is not a real directory");
    }
    if let Ok(metadata) = socket_path.symlink_metadata() {
        if !metadata.file_type().is_socket() {
            bail!("refusing to replace a non-socket broker path");
        }
        if UnixStream::connect(socket_path).await.is_ok() {
            bail!("another privileged broker is already using the socket");
        }
        std::fs::remove_file(socket_path).context("remove stale broker socket")?;
    }
    let listener = UnixListener::bind(socket_path)
        .with_context(|| format!("bind broker socket {}", socket_path.display()))?;
    std::fs::set_permissions(socket_path, std::fs::Permissions::from_mode(0o660))
        .context("set broker socket permissions")?;
    let expected_uid = resolve_daemon_account().map(|(uid, _)| uid)?;
    let expected_gid = resolve_daemon_account().map(|(_, gid)| gid)?;
    // The unprivileged daemon connects as the `centrald` service account, so
    // the socket must be owned by that account (mode 0660 with a root owner
    // would still deny the connect).
    rustix::fs::chown(socket_path, Some(expected_uid), Some(expected_gid))
        .context("chown broker socket to the centrald service account")?;
    let sessions = Arc::new(crate::broker_session::SessionManager::new());
    loop {
        tokio::select! {
            changed = shutdown.changed() => {
                if changed.is_ok() && *shutdown.borrow() {
                    return Ok(());
                }
            }
            accepted = listener.accept() => {
                let (stream, _) = accepted.context("accept broker connection")?;
                let credentials = stream
                    .peer_cred()
                    .context("read broker peer credentials")?;
                if credentials.uid() != expected_uid {
                    warn!(
                        uid = credentials.uid(),
                        "rejected broker peer outside the centrald service account"
                    );
                    continue;
                }
                let std_stream = stream
                    .into_std()
                    .context("convert broker connection to blocking I/O")?;
                let executor = executor.clone();
                let sessions = sessions.clone();
                tokio::task::spawn_blocking(move || {
                    if let Err(error) = handle_unix_connection_sync(std_stream, &executor, &sessions)
                    {
                        warn!(%error, "broker request failed");
                    }
                });
            }
        }
    }
}

/// Handles one Unix broker connection (one-shot request or session) with
/// blocking I/O on a dedicated worker.
#[cfg(unix)]
fn handle_unix_connection_sync(
    stream: std::os::unix::net::UnixStream,
    executor: &BrokerExecutor<SystemOperationRunner>,
    sessions: &crate::broker_session::SessionManager,
) -> Result<()> {
    use std::io::{Read, Write};

    let read_half = stream.try_clone().context("clone broker connection")?;
    let mut reader: Box<dyn Read + Send> = Box::new(read_half);
    let writer: Box<dyn Write + Send> = Box::new(stream);
    let first = crate::broker_session::read_frame(&mut reader, MAX_FIRST_FRAME_BYTES)
        .context("read first broker frame")?;
    dispatch_connection(first, reader, writer, executor, sessions)
}

#[cfg(windows)]
async fn serve_windows(executor: Arc<BrokerExecutor<SystemOperationRunner>>) -> Result<()> {
    let sessions = Arc::new(crate::broker_session::SessionManager::new());
    tokio::task::spawn_blocking(move || -> Result<()> {
        loop {
            let pipe = crate::windows_ffi::accept_pipe_connection()?;
            let stream = crate::windows_ffi::PipeStream::new(pipe);
            let (read_half, write_half) = stream.split()?;
            let mut reader: Box<dyn std::io::Read + Send> = Box::new(read_half);
            let writer: Box<dyn std::io::Write + Send> = Box::new(write_half);
            let first = match crate::broker_session::read_frame(&mut reader, MAX_FIRST_FRAME_BYTES)
            {
                Ok(first) => first,
                Err(error) => {
                    tracing::warn!(%error, "broker request failed before dispatch");
                    continue;
                }
            };
            // Each connection runs on its own thread so a long operation or a
            // shell session cannot block the accept loop (which must keep
            // serving new pipe instances).
            let executor = executor.clone();
            let sessions = sessions.clone();
            std::thread::spawn(move || {
                if let Err(error) =
                    dispatch_connection(&first, reader, writer, &executor, &sessions)
                {
                    tracing::warn!(%error, "broker request failed");
                }
            });
        }
    })
    .await
    .context("broker pipe server worker failed")??;
    Ok(())
}

/// First-frame bound: the larger of the one-shot request and the session
/// open frame.
const MAX_FIRST_FRAME_BYTES: usize = 128 * 1024;

/// Dispatches a broker connection after its first frame has been read.
fn dispatch_connection(
    first_frame: &[u8],
    reader: Box<dyn std::io::Read + Send>,
    mut writer: Box<dyn std::io::Write + Send>,
    executor: &BrokerExecutor<SystemOperationRunner>,
    sessions: &crate::broker_session::SessionManager,
) -> Result<()> {
    let is_session_open = serde_json::from_slice::<serde_json::Value>(first_frame)
        .ok()
        .and_then(|value| {
            value
                .get("kind")
                .and_then(serde_json::Value::as_str)
                .map(|kind| kind == "open")
        })
        .unwrap_or(false);
    if is_session_open {
        return crate::broker_session::serve_session(
            first_frame,
            reader,
            writer,
            executor.grant_verifier(),
            sessions,
        );
    }
    let response = if first_frame.len() > MAX_WIRE_REQUEST_BYTES {
        encode_wire_error("broker request exceeds the wire bound")
    } else {
        match execute_request(executor, first_frame) {
            Ok(response) => response,
            Err(error) => encode_wire_error(&error.to_string()),
        }
    };
    if response.len() > MAX_WIRE_RESPONSE_BYTES {
        error!(
            bytes = response.len(),
            "broker response exceeded the wire bound"
        );
        let error_frame = encode_wire_error("broker response exceeded the wire bound");
        crate::broker_session::write_frame(writer.as_mut(), &error_frame)?;
        return Ok(());
    }
    crate::broker_session::write_frame(writer.as_mut(), &response)?;
    Ok(())
}

fn execute_request(
    executor: &BrokerExecutor<SystemOperationRunner>,
    request_bytes: &[u8],
) -> Result<Vec<u8>> {
    let request: BrokerRequest =
        serde_json::from_slice(request_bytes).context("decode broker request")?;
    let response = executor.execute(&request, Utc::now())?;
    serde_json::to_vec(&WireResult::Ok { response }).context("encode broker response")
}

fn encode_wire_error(message: &str) -> Vec<u8> {
    serde_json::to_vec(&WireResult::Error {
        message: message.to_owned(),
    })
    .unwrap_or_else(|_| {
        b"{\"result\":\"error\",\"message\":\"broker error encoding failed\"}".to_vec()
    })
}

#[cfg(unix)]
fn validate_socket_path(path: &Path) -> Result<()> {
    if path != Path::new(BROKER_SOCKET_PATH) {
        bail!("broker socket must be exactly {}", BROKER_SOCKET_PATH);
    }
    Ok(())
}

/// Resolves the packaged client daemon account's UID and primary GID from the
/// fixed `/etc/passwd`. The broker fails closed when the account is missing.
#[cfg(unix)]
fn resolve_daemon_account() -> Result<(u32, u32)> {
    use std::io::Read;

    let mut file = std::fs::File::open("/etc/passwd").context("open /etc/passwd")?;
    let metadata = file.metadata().context("inspect /etc/passwd")?;
    if metadata.file_type().is_symlink() || !metadata.is_file() {
        bail!("/etc/passwd is not a regular file");
    }
    let mut content = Vec::new();
    file.take(MAX_PASSWD_BYTES + 1)
        .read_to_end(&mut content)
        .context("read /etc/passwd")?;
    if content.len() > MAX_PASSWD_BYTES as usize {
        bail!("/etc/passwd exceeds the bounded read size");
    }
    let text = String::from_utf8(content).context("/etc/passwd is not valid UTF-8")?;
    for line in text.lines() {
        let fields: Vec<&str> = line.split(':').collect();
        if fields.len() >= 4 && fields[0] == DAEMON_USER {
            let uid: u32 = fields[2]
                .parse()
                .with_context(|| format!("{DAEMON_USER} UID is invalid in /etc/passwd"))?;
            if uid == 0 {
                bail!("the centrald service account must not be UID 0");
            }
            let gid: u32 = fields[3]
                .parse()
                .with_context(|| format!("{DAEMON_USER} GID is invalid in /etc/passwd"))?;
            return Ok((uid, gid));
        }
    }
    bail!("the centrald service account is missing from /etc/passwd")
}

#[cfg(unix)]
fn resolve_daemon_uid() -> Result<u32> {
    resolve_daemon_account().map(|(uid, _)| uid)
}

/// Executes one verified request with exactly-once ledger semantics.
#[derive(Debug)]
pub struct BrokerExecutor<R: OperationRunner> {
    verifier: Mutex<GrantVerifier>,
    ledger: Mutex<BrokerLedger>,
    /// Serializes operation execution so a re-dispatched request for an
    /// in-flight job waits for the original execution to finish and then
    /// replays its recorded result.
    execution: Mutex<()>,
    runner: Mutex<R>,
}

impl<R: OperationRunner> BrokerExecutor<R> {
    #[must_use]
    pub fn new(verifier: GrantVerifier, ledger: BrokerLedger, runner: R) -> Self {
        Self {
            verifier: Mutex::new(verifier),
            ledger: Mutex::new(ledger),
            execution: Mutex::new(()),
            runner: Mutex::new(runner),
        }
    }

    /// Exposes the shared grant verifier so shell sessions consume grants from
    /// the same replay set as one-shot job operations.
    #[must_use]
    pub fn grant_verifier(&self) -> &Mutex<GrantVerifier> {
        &self.verifier
    }

    /// Verifies and consumes the grant, then executes the operation once.
    ///
    /// # Errors
    ///
    /// Returns an error for invalid/replayed grants, interrupted or already
    /// completed ledger state, ledger failures, or runner failures.
    pub fn execute(&self, request: &BrokerRequest, now: DateTime<Utc>) -> Result<BrokerResponse> {
        self.verifier
            .lock()
            .map_err(|_| anyhow::anyhow!("broker verifier lock was poisoned"))?
            .verify_and_consume(&request.signed_grant, now)?;
        let digest = hex::encode(Sha256::digest(&request.parameters_json));
        if digest != request.signed_grant.grant.parameters_sha256 {
            bail!("operation parameters do not match the signed grant");
        }
        let job_id = request.signed_grant.grant.job_or_session_id;
        if let Some(completed) = self
            .ledger
            .lock()
            .map_err(|_| anyhow::anyhow!("broker ledger lock was poisoned"))?
            .lookup(job_id, now)?
        {
            match completed {
                LedgerLookup::Completed(response) => return Ok(response),
                LedgerLookup::Executing { interrupted: false } => {
                    // An in-flight execution completes before the serialized
                    // request below; nothing can still be running here except
                    // a marker left by a crashed broker process.
                    bail!("job execution is already recorded as in progress; outcome unknown");
                }
                LedgerLookup::Executing { interrupted: true } => {
                    bail!(
                        "job execution was interrupted and its outcome is unknown; verify the machine and resubmit if needed"
                    );
                }
            }
        }
        let _execution = self
            .execution
            .lock()
            .map_err(|_| anyhow::anyhow!("broker execution lock was poisoned"))?;
        if let Some(completed) = self
            .ledger
            .lock()
            .map_err(|_| anyhow::anyhow!("broker ledger lock was poisoned"))?
            .lookup(job_id, now)?
        {
            if let LedgerLookup::Completed(response) = completed {
                return Ok(response);
            }
            bail!(
                "job execution was interrupted and its outcome is unknown; verify the machine and resubmit if needed"
            );
        }
        let operation = request.signed_grant.grant.operation.clone();
        self.ledger
            .lock()
            .map_err(|_| anyhow::anyhow!("broker ledger lock was poisoned"))?
            .mark_executing(job_id, operation.clone(), now)?;
        let response = self
            .runner
            .lock()
            .map_err(|_| anyhow::anyhow!("broker runner lock was poisoned"))?
            .run(&operation, &request.parameters_json)
            .map_err(|error| anyhow::anyhow!("{error}"))?;
        self.ledger
            .lock()
            .map_err(|_| anyhow::anyhow!("broker ledger lock was poisoned"))?
            .record_completed(job_id, &response, now)?;
        Ok(response)
    }
}

#[cfg(test)]
#[allow(clippy::unwrap_used)]
mod tests {
    use chrono::Duration as ChronoDuration;
    use ed25519_dalek::SigningKey;
    use sha2::{Digest, Sha256};
    use uuid::Uuid;

    use centrald_common::grant::GrantOperation;

    use super::*;

    #[derive(Debug, Default)]
    struct FakeRunner {
        calls: std::sync::atomic::AtomicUsize,
    }

    #[derive(Debug)]
    struct FakeError;

    impl std::fmt::Display for FakeError {
        fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
            formatter.write_str("fake runner failure")
        }
    }

    impl std::error::Error for FakeError {}

    impl OperationRunner for FakeRunner {
        type Error = FakeError;

        fn run(
            &mut self,
            _operation: &GrantOperation,
            _parameters_json: &[u8],
        ) -> Result<BrokerResponse, Self::Error> {
            self.calls.fetch_add(1, std::sync::atomic::Ordering::SeqCst);
            Ok(BrokerResponse {
                success: true,
                output: b"ok".to_vec(),
                exit_code: 0,
            })
        }
    }

    fn fixture(seed: u8) -> (Uuid, SigningKey, BrokerExecutor<FakeRunner>) {
        let device_id = Uuid::now_v7();
        let key = SigningKey::from_bytes(&[seed; 32]);
        let root = std::env::temp_dir().join(format!("centrald-broker-exec-{}", Uuid::now_v7()));
        let ledger = BrokerLedger::open(&root).unwrap();
        let executor = BrokerExecutor::new(
            GrantVerifier::new(device_id, key.verifying_key()),
            ledger,
            FakeRunner::default(),
        );
        (device_id, key, executor)
    }

    fn request(
        device_id: Uuid,
        key: &SigningKey,
        job_id: Uuid,
        parameters: &[u8],
    ) -> BrokerRequest {
        let now = Utc::now();
        let grant = centrald_common::grant::PrivilegedGrant {
            id: Uuid::now_v7(),
            device_id,
            job_or_session_id: job_id,
            admin_id: Uuid::now_v7(),
            operation: GrantOperation::RestartClientService,
            parameters_sha256: hex::encode(Sha256::digest(parameters)),
            issued_at: now - ChronoDuration::seconds(1),
            expires_at: now + ChronoDuration::seconds(60),
            nonce: Uuid::now_v7().to_string(),
        };
        BrokerRequest {
            signed_grant: grant.sign(key).unwrap(),
            parameters_json: parameters.to_vec(),
        }
    }

    #[test]
    fn executes_once_and_replays_for_redispatched_jobs() {
        let (device, key, executor) = fixture(3);
        let job = Uuid::now_v7();
        let first = request(device, &key, job, b"{}");
        let response = executor.execute(&first, Utc::now()).unwrap();
        assert_eq!(response.output, b"ok");
        // A re-dispatched job with a fresh grant replays the recorded result
        // instead of executing again.
        let redispatched = request(device, &key, job, b"{}");
        let replay = executor.execute(&redispatched, Utc::now()).unwrap();
        assert_eq!(replay.output, b"ok");
        let calls = executor
            .runner
            .lock()
            .unwrap()
            .calls
            .load(std::sync::atomic::Ordering::SeqCst);
        assert_eq!(calls, 1);
    }

    #[test]
    fn rejects_replayed_grants_wrong_devices_and_wrong_keys() {
        let (device, key, executor) = fixture(3);
        let (other_device, other_key, _other_executor) = fixture(9);
        let job = Uuid::now_v7();
        let first = request(device, &key, job, b"{}");
        assert!(executor.execute(&first, Utc::now()).is_ok());
        assert!(executor.execute(&first, Utc::now()).is_err());

        // A grant for another device, validly signed, must be rejected.
        let wrong_device = request(other_device, &other_key, job, b"{}");
        assert!(executor.execute(&wrong_device, Utc::now()).is_err());

        // A grant for this device signed by the wrong key must be rejected.
        let wrong_key = request(device, &other_key, job, b"{}");
        assert!(executor.execute(&wrong_key, Utc::now()).is_err());
    }

    #[test]
    fn rejects_tampered_parameters() {
        let (device, key, executor) = fixture(3);
        let job = Uuid::now_v7();
        let mut tampered = request(device, &key, job, b"{\"delay\":1}");
        tampered.parameters_json = b"{\"delay\":2}".to_vec();
        assert!(executor.execute(&tampered, Utc::now()).is_err());
    }
}
