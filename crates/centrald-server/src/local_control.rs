#[cfg(any(unix, test))]
use std::path::Path;
use std::path::PathBuf;
use std::sync::Arc;
use std::time::Duration;

#[cfg(any(unix, test))]
use anyhow::Context;
use anyhow::{Result, bail};
use centrald_common::config::ServerConfig;
use chrono::{DateTime, Utc};
use secrecy::SecretString;
use serde::{Deserialize, Serialize};
use sqlx::PgPool;
use tokio::sync::Semaphore;
use uuid::Uuid;

use crate::manage::{CreatedEnrollmentKey, DiagnosticsSummary, IdentitySummary};
#[cfg(unix)]
use crate::manage::{
    create_enrollment_key_bounded, diagnostic_summary, list_identity_records,
    revoke_identity_record,
};

#[cfg(unix)]
const MAX_REQUEST_BYTES: u64 = 16 * 1024;
#[cfg(unix)]
const MAX_RESPONSE_BYTES: u64 = 256 * 1024;

#[derive(Debug, Serialize, Deserialize)]
#[serde(tag = "operation", rename_all = "snake_case", deny_unknown_fields)]
enum LocalRequest {
    CreateEnrollment {
        role: String,
        name: String,
        expires_in_seconds: u64,
    },
    ListIdentities {
        role: String,
    },
    RevokeIdentity {
        role: String,
        identity_id: Uuid,
        reason: String,
    },
    Diagnostics,
}

#[derive(Serialize, Deserialize)]
#[serde(tag = "result", rename_all = "snake_case", deny_unknown_fields)]
enum LocalResponse {
    Enrollment {
        id: Uuid,
        role: String,
        name: String,
        expires_at: DateTime<Utc>,
        key: String,
    },
    Identities {
        identities: Vec<IdentitySummary>,
    },
    Diagnostics {
        summary: DiagnosticsSummary,
    },
    Success {
        message: String,
    },
    Error {
        message: String,
    },
}

impl std::fmt::Debug for LocalResponse {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Enrollment {
                id,
                role,
                name,
                expires_at,
                ..
            } => formatter
                .debug_struct("Enrollment")
                .field("id", id)
                .field("role", role)
                .field("name", name)
                .field("expires_at", expires_at)
                .field("key", &"[REDACTED]")
                .finish(),
            Self::Identities { identities } => formatter
                .debug_struct("Identities")
                .field("identities", identities)
                .finish(),
            Self::Diagnostics { summary } => formatter
                .debug_struct("Diagnostics")
                .field("summary", summary)
                .finish(),
            Self::Success { message } => formatter
                .debug_struct("Success")
                .field("message", message)
                .finish(),
            Self::Error { message } => formatter
                .debug_struct("Error")
                .field("message", message)
                .finish(),
        }
    }
}

#[derive(Debug, Clone)]
pub struct LocalControlClient {
    #[cfg_attr(not(unix), allow(dead_code))]
    socket_path: PathBuf,
}

impl LocalControlClient {
    #[must_use]
    pub fn new(socket_path: PathBuf) -> Self {
        Self { socket_path }
    }

    /// Requests a single-use enrollment invitation from the running server.
    ///
    /// # Errors
    ///
    /// Returns an error when local transport, validation, or server processing
    /// fails.
    pub async fn create_enrollment(
        &self,
        role: &str,
        name: &str,
        ttl: Duration,
    ) -> Result<CreatedEnrollmentKey> {
        let expires_in_seconds = ttl.as_secs();
        match self
            .request(LocalRequest::CreateEnrollment {
                role: role.to_owned(),
                name: name.to_owned(),
                expires_in_seconds,
            })
            .await?
        {
            LocalResponse::Enrollment {
                id,
                role,
                name,
                expires_at,
                key,
            } => Ok(CreatedEnrollmentKey {
                id,
                role,
                name,
                expires_at,
                key: SecretString::from(key),
            }),
            response => unexpected_response(&response),
        }
    }

    /// Lists identities through the authenticated local server channel.
    ///
    /// # Errors
    ///
    /// Returns an error for transport failure, server rejection, or malformed
    /// response data.
    pub async fn list_identities(&self, role: &str) -> Result<Vec<IdentitySummary>> {
        match self
            .request(LocalRequest::ListIdentities {
                role: role.to_owned(),
            })
            .await?
        {
            LocalResponse::Identities { identities } => Ok(identities),
            response => unexpected_response(&response),
        }
    }

    /// Revokes one identity through the authenticated local server channel.
    ///
    /// # Errors
    ///
    /// Returns an error for transport failure, server rejection, or malformed
    /// response data.
    pub async fn revoke_identity(&self, role: &str, identity_id: Uuid, reason: &str) -> Result<()> {
        match self
            .request(LocalRequest::RevokeIdentity {
                role: role.to_owned(),
                identity_id,
                reason: reason.to_owned(),
            })
            .await?
        {
            LocalResponse::Success { .. } => Ok(()),
            response => unexpected_response(&response),
        }
    }

    /// Reads non-secret health counts from the running server.
    ///
    /// # Errors
    ///
    /// Returns an error for transport failure, server rejection, or malformed
    /// response data.
    pub async fn diagnostics(&self) -> Result<DiagnosticsSummary> {
        match self.request(LocalRequest::Diagnostics).await? {
            LocalResponse::Diagnostics { summary } => Ok(summary),
            response => unexpected_response(&response),
        }
    }

    #[cfg(unix)]
    async fn request(&self, request: LocalRequest) -> Result<LocalResponse> {
        use tokio::io::{AsyncReadExt, AsyncWriteExt};
        use tokio::net::UnixStream;

        let mut stream = UnixStream::connect(&self.socket_path)
            .await
            .with_context(|| {
                format!(
                    "connect to {}; is centrald-server running?",
                    self.socket_path.display()
                )
            })?;
        let request = serde_json::to_vec(&request)?;
        if request.len() > usize::try_from(MAX_REQUEST_BYTES).unwrap_or(usize::MAX) {
            bail!("local management request is too large");
        }
        stream.write_all(&request).await?;
        stream.shutdown().await?;
        let mut response = Vec::new();
        stream
            .take(MAX_RESPONSE_BYTES + 1)
            .read_to_end(&mut response)
            .await?;
        if response.len() > usize::try_from(MAX_RESPONSE_BYTES).unwrap_or(usize::MAX) {
            bail!("local management response is too large");
        }
        decode_response(&response)
    }

    #[cfg(not(unix))]
    #[allow(clippy::unused_async)]
    async fn request(&self, _request: LocalRequest) -> Result<LocalResponse> {
        bail!("centrald-server local management is supported on Debian/Ubuntu hosts")
    }
}

/// Serves authenticated, bounded, typed local management requests.
///
/// # Errors
///
/// Returns an error if socket validation/binding fails or the accept loop
/// terminates.
#[cfg(unix)]
#[derive(Debug)]
pub struct ServerLock {
    _file: std::fs::File,
}

/// Acquires the same exclusive lock used by the running server.
///
/// The lock parent must be a root-owned, non-symlink directory. Holding the
/// returned guard proves no correctly configured CentralD daemon can start or
/// continue running through the destructive-reset window.
///
/// # Errors
///
/// Returns an error for an unsafe runtime path or when another process holds
/// the server lock.
#[cfg(unix)]
pub fn acquire_server_lock(socket_path: &Path) -> Result<ServerLock> {
    use std::fs::OpenOptions;
    use std::os::unix::fs::{MetadataExt, OpenOptionsExt, PermissionsExt};

    use fs2::FileExt;

    validate_socket_path(socket_path)?;
    let parent = socket_path
        .parent()
        .context("local control socket path has no parent")?;
    if parent.exists() {
        let metadata = parent.symlink_metadata()?;
        if metadata.file_type().is_symlink() || !metadata.is_dir() || metadata.uid() != 0 {
            bail!("local control socket parent must be a root-owned real directory");
        }
    } else {
        std::fs::create_dir(parent)
            .with_context(|| format!("create local socket directory {}", parent.display()))?;
        std::fs::set_permissions(parent, std::fs::Permissions::from_mode(0o700))?;
    }
    std::fs::set_permissions(parent, std::fs::Permissions::from_mode(0o700))?;

    let lock_path = parent.join("server.lock");
    if lock_path
        .symlink_metadata()
        .is_ok_and(|metadata| metadata.file_type().is_symlink())
    {
        bail!("refusing symbolic-link local server lock");
    }
    let lock_file = OpenOptions::new()
        .read(true)
        .write(true)
        .create(true)
        .truncate(false)
        .custom_flags({
            const O_NOFOLLOW: i32 = 0o400000;
            const O_CLOEXEC: i32 = 0o2000000;
            O_NOFOLLOW | O_CLOEXEC
        })
        .open(&lock_path)
        .with_context(|| format!("open local server lock {}", lock_path.display()))?;
    std::fs::set_permissions(&lock_path, std::fs::Permissions::from_mode(0o600))?;
    FileExt::try_lock_exclusive(&lock_file)
        .with_context(|| format!("another CentralD server holds {}", lock_path.display()))?;
    Ok(ServerLock { _file: lock_file })
}

#[cfg(not(unix))]
#[derive(Debug)]
pub struct ServerLock;

#[cfg(not(unix))]
/// Rejects server-lock acquisition on unsupported server platforms.
///
/// # Errors
///
/// Always returns an unsupported-platform error.
pub fn acquire_server_lock(_socket_path: &std::path::Path) -> Result<ServerLock> {
    bail!("centrald-server runtime locking is supported only on Ubuntu Server hosts")
}

#[cfg(unix)]
pub async fn serve(
    path: PathBuf,
    pool: PgPool,
    config: ServerConfig,
    enrollment_crypto_limit: Arc<Semaphore>,
    _server_lock: ServerLock,
) -> Result<()> {
    use std::os::unix::fs::{FileTypeExt, PermissionsExt};

    use tokio::net::{UnixListener, UnixStream};
    use tracing::{error, warn};

    if let Ok(metadata) = path.symlink_metadata() {
        if !metadata.file_type().is_socket() {
            bail!(
                "refusing to replace non-socket local control path {}",
                path.display()
            );
        }
        if UnixStream::connect(&path).await.is_ok() {
            bail!(
                "another CentralD server is already using {}",
                path.display()
            );
        }
        std::fs::remove_file(&path)
            .with_context(|| format!("remove locked stale socket {}", path.display()))?;
    }

    let listener = UnixListener::bind(&path)
        .with_context(|| format!("bind local control socket {}", path.display()))?;
    std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o600))?;
    loop {
        let (stream, _) = listener.accept().await?;
        let credentials = stream.peer_cred()?;
        if credentials.uid() != 0 {
            warn!(uid = credentials.uid(), "rejected local management peer");
            continue;
        }
        let pool = pool.clone();
        let config = config.clone();
        let enrollment_crypto_limit = enrollment_crypto_limit.clone();
        tokio::spawn(async move {
            if let Err(error) =
                handle_connection(stream, &pool, &config, enrollment_crypto_limit).await
            {
                error!(error = %error, "local management request failed");
            }
        });
    }
}

#[cfg(not(unix))]
/// Rejects local management on unsupported server platforms.
///
/// # Errors
///
/// Always returns an unsupported-platform error.
#[allow(clippy::unused_async)]
pub async fn serve(
    _path: PathBuf,
    _pool: PgPool,
    _config: ServerConfig,
    _enrollment_crypto_limit: Arc<Semaphore>,
    _server_lock: ServerLock,
) -> Result<()> {
    bail!("centrald-server local management is supported on Debian/Ubuntu hosts")
}

#[cfg(unix)]
async fn handle_connection(
    stream: tokio::net::UnixStream,
    pool: &PgPool,
    config: &ServerConfig,
    enrollment_crypto_limit: Arc<Semaphore>,
) -> Result<()> {
    use tokio::io::{AsyncReadExt, AsyncWriteExt};

    let (read_half, mut write_half) = stream.into_split();
    let mut request_bytes = Vec::new();
    read_half
        .take(MAX_REQUEST_BYTES + 1)
        .read_to_end(&mut request_bytes)
        .await?;
    let response = if request_bytes.len() > usize::try_from(MAX_REQUEST_BYTES).unwrap_or(usize::MAX)
    {
        LocalResponse::Error {
            message: "local management request is too large".to_owned(),
        }
    } else {
        match decode_request(&request_bytes) {
            Ok(request) => match dispatch(pool, config, enrollment_crypto_limit, request).await {
                Ok(response) => response,
                Err(error) => {
                    tracing::error!(error = %error, "local management operation rejected");
                    LocalResponse::Error {
                        message: error.to_string(),
                    }
                }
            },
            Err(_) => LocalResponse::Error {
                message: "malformed local management request".to_owned(),
            },
        }
    };
    let response = serde_json::to_vec(&response)?;
    if response.len() > usize::try_from(MAX_RESPONSE_BYTES).unwrap_or(usize::MAX) {
        bail!("local management response exceeds bound");
    }
    write_half.write_all(&response).await?;
    write_half.shutdown().await?;
    Ok(())
}

#[cfg(any(unix, test))]
fn decode_request(bytes: &[u8]) -> Result<LocalRequest> {
    let value: serde_json::Value =
        serde_json::from_slice(bytes).context("decode local management request")?;
    let object = value
        .as_object()
        .context("local management request must be an object")?;
    let operation = object
        .get("operation")
        .and_then(serde_json::Value::as_str)
        .context("local management request operation is required")?;
    let allowed: &[&str] = match operation {
        "create_enrollment" => &["operation", "role", "name", "expires_in_seconds"],
        "list_identities" => &["operation", "role"],
        "revoke_identity" => &["operation", "role", "identity_id", "reason"],
        "diagnostics" => &["operation"],
        _ => bail!("unknown local management operation"),
    };
    if object.keys().any(|key| !allowed.contains(&key.as_str())) {
        bail!("local management request contains unknown fields");
    }
    serde_json::from_value(value).context("validate local management request")
}

#[cfg(unix)]
async fn dispatch(
    pool: &PgPool,
    config: &ServerConfig,
    enrollment_crypto_limit: Arc<Semaphore>,
    request: LocalRequest,
) -> Result<LocalResponse> {
    match request {
        LocalRequest::CreateEnrollment {
            role,
            name,
            expires_in_seconds,
        } => {
            let created = create_enrollment_key_bounded(
                pool,
                config,
                &role,
                &name,
                Duration::from_secs(expires_in_seconds),
                Some(enrollment_crypto_limit),
            )
            .await?;
            Ok(LocalResponse::Enrollment {
                id: created.id,
                role: created.role,
                name: created.name,
                expires_at: created.expires_at,
                key: secrecy::ExposeSecret::expose_secret(&created.key).to_owned(),
            })
        }
        LocalRequest::ListIdentities { role } => Ok(LocalResponse::Identities {
            identities: list_identity_records(pool, &role).await?,
        }),
        LocalRequest::RevokeIdentity {
            role,
            identity_id,
            reason,
        } => {
            revoke_identity_record(pool, &role, identity_id, &reason).await?;
            Ok(LocalResponse::Success {
                message: "identity revoked".to_owned(),
            })
        }
        LocalRequest::Diagnostics => Ok(LocalResponse::Diagnostics {
            summary: diagnostic_summary(pool).await?,
        }),
    }
}

#[cfg(any(unix, test))]
fn decode_response(bytes: &[u8]) -> Result<LocalResponse> {
    let response: LocalResponse = serde_json::from_slice(bytes)
        .map_err(|error| anyhow::anyhow!("decode local management response: {error}"))?;
    if let LocalResponse::Error { message } = response {
        bail!("{message}");
    }
    Ok(response)
}

fn unexpected_response<T>(response: &LocalResponse) -> Result<T> {
    bail!("unexpected local management response: {response:?}")
}

#[cfg(any(unix, test))]
fn validate_socket_path(path: &Path) -> Result<()> {
    if path != Path::new(crate::DEFAULT_LOCAL_SOCKET) {
        bail!(
            "local control socket must be exactly {}",
            crate::DEFAULT_LOCAL_SOCKET
        );
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn rejects_relative_socket_and_unknown_request_fields() {
        assert!(validate_socket_path(Path::new("server.sock")).is_err());
        let malformed = br#"{"operation":"diagnostics","unexpected":true}"#;
        assert!(decode_request(malformed).is_err());
    }

    #[test]
    fn decodes_server_error_without_accepting_wrong_variant() {
        let response = br#"{"result":"error","message":"denied"}"#;
        assert!(decode_response(response).is_err());
    }
}
