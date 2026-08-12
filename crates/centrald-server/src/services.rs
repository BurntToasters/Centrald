use std::fmt;
use std::fs;
use std::path::PathBuf;
use std::pin::Pin;
use std::sync::Arc;
use std::time::Duration;

use centrald_common::config::ServerConfig;
use centrald_common::enrollment::{
    EnrollmentInvitationClaims, EnrollmentRole, generate_enrollment_invitation,
    parse_enrollment_invitation, hash_enrollment_key, verify_enrollment_key,
};
use centrald_common::grant::{GrantOperation, PrivilegedGrant};
use centrald_common::release::ReleaseManifestV1;
use centrald_common::secure_fs::replace_file_atomically;
use centrald_pki::{
    IdentityCertificateKind, IssuedCertificate, certificate_sha256, issue_identity_csr,
};
use centrald_protocol::v1::admin_service_server::AdminService;
use centrald_protocol::v1::client_service_server::ClientService;
use centrald_protocol::v1::enrollment_service_server::EnrollmentService;
use centrald_protocol::v1::{
    ActivateIdentityRequest, AdminShellFrame, BeginElevationRequest, ClientFrame,
    CreateEnrollmentKeyRequest, CreateEnrollmentKeyResponse, ElevationChallenge,
    EnrollAdminRequest, EnrollClientRequest,
    EnrollmentKeySummary, EnrollmentResponse, GetServerSettingsRequest, HeartbeatAck, IdentityRole,
    Job, JobDeliveryAck, JobEvent, JobKind, JobState, ListEnrollmentKeysRequest,
    ListEnrollmentKeysResponse,
    ListTargetsRequest, ListTargetsResponse, OperationResult, RenewCertificateRequest,
    RenewCertificateResponse, ReplaceIdentityRequest, RevokeEnrollmentKeyRequest,
    RevokeIdentityRequest, ServerFrame,
    ServerSettings, StartJobRequest, StreamJobRequest, TargetSummary, UpdateServerSettingsRequest,
};
use chrono::{DateTime, Utc};
use ed25519_dalek::SigningKey;
use ed25519_dalek::pkcs8::DecodePrivateKey;
use secrecy::{ExposeSecret, SecretString};
use sqlx::{PgPool, Postgres, Transaction};
use tokio::sync::{Mutex, Semaphore, mpsc};
use tokio_stream::Stream;
use tokio_stream::wrappers::ReceiverStream;
use tonic::{Request, Response, Status, Streaming};
use tracing::{error, warn};
use uuid::Uuid;

use crate::config_lock::{
    ConfigFileLock, SettingsUpdateTransaction, recover_interrupted_database_update_locked,
    recover_interrupted_settings_update_locked,
};
use crate::db::{connect_and_migrate, resolve_database_url};
use crate::file_security::{read_root_private_text, read_root_public_text};
use crate::manage::{
    recover_interrupted_online_issuer_rotation_locked,
    recover_interrupted_tls_rotation_locked,
};

const MAX_CSR_BYTES: usize = 16 * 1024;
const MAX_PARAMETERS_BYTES: usize = 64 * 1024;
const MAX_JOB_EVENT_OUTPUT_BYTES: usize = 64 * 1024;
const MAX_JOB_RETAINED_OUTPUT_BYTES: i64 = 1024 * 1024;
const MAX_JOB_EVENTS: i64 = 4096;
const MAX_HELLO_HOSTNAME_BYTES: usize = 253;
const MAX_HELLO_TEXT_BYTES: usize = 128;
const MAX_HELLO_CAPABILITIES: usize = 64;
const MAX_HELLO_CAPABILITY_BYTES: usize = 64;
const IDENTITY_ACTIVATION_TTL_HOURS: i64 = 24;
const JOB_DELIVERY_LEASE_SECONDS: i64 = 60;
const JOB_EXECUTION_START_LEASE_SECONDS: i64 = 60;
const MAX_CONCURRENT_JOB_STREAMS: usize = 128;
const MAX_CONCURRENT_ENROLLMENT_CRYPTO: usize = 2;
const ADMIN_STREAM_REAUTH_SECONDS: u64 = 5;
const MAX_RELEASE_MANIFEST_BYTES: usize = 1024 * 1024;
const MAX_RELEASE_MANIFEST_BYTES_U64: u64 = 1024 * 1024;

type RpcStream<T> = Pin<Box<dyn Stream<Item = Result<T, Status>> + Send + 'static>>;

#[derive(Clone)]
pub struct RuntimeState {
    pub pool: PgPool,
    config: Arc<ServerConfig>,
    root_certificate_pem: Arc<String>,
    client_issuer_certificate_pem: Arc<String>,
    client_issuer_private_key_pem: Arc<SecretString>,
    admin_issuer_certificate_pem: Arc<String>,
    admin_issuer_private_key_pem: Arc<SecretString>,
    grant_signing_public_key_pem: Arc<String>,
    grant_signing_key: Arc<SigningKey>,
    config_path: Arc<PathBuf>,
    loaded_config_revision: Arc<String>,
    settings_lock: Arc<Mutex<()>>,
    job_stream_limit: Arc<Semaphore>,
    pub enrollment_crypto_limit: Arc<Semaphore>,
}

impl fmt::Debug for RuntimeState {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("RuntimeState")
            .field("server_instance", &self.config.server.instance_id)
            .field("config_path", &self.config_path)
            .field("pki_and_signing_material", &"[REDACTED]")
            .finish_non_exhaustive()
    }
}

impl RuntimeState {
    /// Loads runtime configuration, opens `PostgreSQL`, and reads PKI material.
    ///
    /// # Errors
    ///
    /// Returns an error when the database URL is absent, migrations fail, or
    /// any configured certificate/key file cannot be read.
    pub async fn load(config: ServerConfig, config_path: PathBuf) -> anyhow::Result<Self> {
        let loaded_config_revision = settings_revision(&std::fs::read(&config_path)?);
        let database_url = resolve_database_url(&config)?;
        let pool = connect_and_migrate(
            database_url.expose_secret(),
            config.database.max_connections,
            config.server.instance_id,
        )
        .await?;
        let root_certificate_pem = read_root_public_text(
            &config.pki.root_cert,
            256 * 1024,
            "root CA certificate",
        )?;
        let client_issuer_certificate_pem = read_root_public_text(
            &config.pki.client_issuer_cert,
            256 * 1024,
            "client issuer certificate",
        )?;
        let client_issuer_private_key_pem = SecretString::from(read_root_private_text(
            &config.pki.client_issuer_key,
            256 * 1024,
            "client issuer private key",
        )?);
        let admin_issuer_certificate_pem = read_root_public_text(
            &config.pki.admin_issuer_cert,
            256 * 1024,
            "Admin issuer certificate",
        )?;
        let admin_issuer_private_key_pem = SecretString::from(read_root_private_text(
            &config.pki.admin_issuer_key,
            256 * 1024,
            "Admin issuer private key",
        )?);
        let grant_signing_public_key_pem = read_root_public_text(
            &config.pki.grant_signing_public_key,
            128 * 1024,
            "grant-signing public key",
        )?;
        let grant_signing_key_pem = SecretString::from(read_root_private_text(
            &config.pki.grant_signing_key,
            128 * 1024,
            "grant-signing private key",
        )?);
        let grant_signing_key =
            SigningKey::from_pkcs8_pem(grant_signing_key_pem.expose_secret())?;
        Ok(Self {
            pool,
            config: Arc::new(config),
            root_certificate_pem: Arc::new(root_certificate_pem),
            client_issuer_certificate_pem: Arc::new(client_issuer_certificate_pem),
            client_issuer_private_key_pem: Arc::new(client_issuer_private_key_pem),
            admin_issuer_certificate_pem: Arc::new(admin_issuer_certificate_pem),
            admin_issuer_private_key_pem: Arc::new(admin_issuer_private_key_pem),
            grant_signing_public_key_pem: Arc::new(grant_signing_public_key_pem),
            grant_signing_key: Arc::new(grant_signing_key),
            config_path: Arc::new(config_path),
            loaded_config_revision: Arc::new(loaded_config_revision),
            settings_lock: Arc::new(Mutex::new(())),
            job_stream_limit: Arc::new(Semaphore::new(MAX_CONCURRENT_JOB_STREAMS)),
            enrollment_crypto_limit: Arc::new(Semaphore::new(MAX_CONCURRENT_ENROLLMENT_CRYPTO)),
        })
    }
}

/// Runs bounded cleanup and repair for expiring identities and jobs.
pub async fn run_maintenance(state: RuntimeState) {
    let mut interval = tokio::time::interval(Duration::from_secs(30));
    interval.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Delay);
    loop {
        interval.tick().await;
        if let Err(error) = maintenance_once(&state.pool).await {
            error!(%error, "CentralD maintenance pass failed");
        }
    }
}

/// Checks the configured release feed without installing anything.
///
/// The shared `.yml` feed is emitted as JSON-compatible YAML 1.2 so runtime
/// parsing stays strict and bounded. Artifacts remain operator-approved and are
/// verified again at installation time by the future package broker.
pub async fn run_update_checks(state: RuntimeState) {
    if !state.config.updates.enabled {
        return;
    }
    let delay = Duration::from_secs(u64::from(
        state.config.updates.check_interval_seconds,
    ));
    loop {
        if let Err(error) = check_release_manifest(&state).await {
            warn!(%error, "CentralD release-manifest check failed");
        }
        tokio::time::sleep(delay).await;
    }
}

async fn check_release_manifest(state: &RuntimeState) -> anyhow::Result<()> {
    let client = reqwest::Client::builder()
        .timeout(Duration::from_secs(20))
        .redirect(reqwest::redirect::Policy::none())
        .build()?;
    let mut response = client
        .get(&state.config.updates.manifest_url)
        .header(reqwest::header::ACCEPT_ENCODING, "identity")
        .send()
        .await?
        .error_for_status()?;
    if response
        .content_length()
        .is_some_and(|length| length > MAX_RELEASE_MANIFEST_BYTES_U64)
    {
        anyhow::bail!("release manifest exceeds the size limit");
    }
    if response
        .headers()
        .get(reqwest::header::CONTENT_ENCODING)
        .and_then(|value| value.to_str().ok())
        .is_some_and(|value| !value.eq_ignore_ascii_case("identity"))
    {
        anyhow::bail!("release manifest must not use content encoding");
    }
    if let Some(content_type) = response
        .headers()
        .get(reqwest::header::CONTENT_TYPE)
        .and_then(|value| value.to_str().ok())
    {
        let media_type = content_type.split(';').next().unwrap_or("").trim();
        if !matches!(
            media_type,
            "application/json"
                | "application/yaml"
                | "application/x-yaml"
                | "application/octet-stream"
                | "text/plain"
                | "text/yaml"
        ) {
            anyhow::bail!("release manifest returned unsupported content type {media_type}");
        }
    }
    let mut body = Vec::with_capacity(16 * 1024);
    while let Some(chunk) = response.chunk().await? {
        if body.len().saturating_add(chunk.len()) > MAX_RELEASE_MANIFEST_BYTES {
            anyhow::bail!("release manifest exceeds the size limit");
        }
        body.extend_from_slice(&chunk);
    }
    let manifest: ReleaseManifestV1 = serde_json::from_slice(&body)?;
    manifest.validate()?;
    if manifest.channel != state.config.updates.channel {
        anyhow::bail!(
            "release feed channel {} does not match configured channel {}",
            manifest.channel,
            state.config.updates.channel
        );
    }
    if manifest.protocol_major != centrald_protocol::PROTOCOL_MAJOR {
        anyhow::bail!("release feed protocol major is incompatible");
    }
    if !state.config.updates.allow_prerelease && !manifest.version.pre.is_empty() {
        anyhow::bail!("release feed returned a prerelease while prereleases are disabled");
    }
    let current = semver::Version::parse(env!("CARGO_PKG_VERSION"))?;
    let available = manifest.version > current;
    let snapshot = serde_json::json!({
        "available": available,
        "current_version": current.to_string(),
        "version": manifest.version.to_string(),
        "channel": manifest.channel,
        "generated_at": manifest.generated_at,
        "repository": manifest.repository,
        "artifact_count": manifest.artifacts.len(),
    });
    let expires_at = Utc::now()
        + chrono::Duration::seconds(i64::from(
            state.config.updates.check_interval_seconds,
        ).saturating_mul(2));
    let mut transaction = state.pool.begin().await?;
    sqlx::query(
        "INSERT INTO update_snapshots (id, target_id, scope, updates, expires_at) \
         VALUES ($1, NULL, 'server_release_manifest', $2, $3)",
    )
    .bind(Uuid::now_v7())
    .bind(snapshot)
    .bind(expires_at)
    .execute(&mut *transaction)
    .await?;
    sqlx::query(
        "DELETE FROM update_snapshots WHERE id IN ( \
             SELECT id FROM update_snapshots \
             WHERE scope = 'server_release_manifest' \
             ORDER BY created_at DESC OFFSET 20 \
         ) OR expires_at < NOW() - INTERVAL '7 days'",
    )
    .execute(&mut *transaction)
    .await?;
    transaction.commit().await?;
    Ok(())
}

async fn maintenance_once(pool: &PgPool) -> Result<(), Status> {
    let mut transaction = pool.begin().await.map_err(internal)?;
    sqlx::query(
        "UPDATE jobs SET state = 'queued', delivery_id = NULL, \
         delivery_lease_expires_at = NULL, updated_at = NOW() \
         WHERE state = 'dispatched' AND delivery_lease_expires_at <= NOW() \
         AND expires_at > NOW()",
    )
    .execute(&mut *transaction)
    .await
    .map_err(internal)?;
    sqlx::query(
        "UPDATE jobs SET state = 'queued', execution_start_expires_at = NULL, \
         updated_at = NOW() WHERE state = 'acknowledged' \
         AND execution_start_expires_at <= NOW() AND expires_at > NOW()",
    )
    .execute(&mut *transaction)
    .await
    .map_err(internal)?;
    sqlx::query(
        "WITH expired AS ( \
             UPDATE jobs SET state = 'timed_out', delivery_id = NULL, \
                    delivery_lease_expires_at = NULL, execution_start_expires_at = NULL, \
                    updated_at = NOW() \
             WHERE state IN ('queued', 'dispatched', 'acknowledged', 'running') \
             AND expires_at <= NOW() RETURNING id \
         ) \
         INSERT INTO job_events (job_id, sequence, state, terminal) \
         SELECT expired.id, COALESCE((SELECT MAX(sequence) + 1 FROM job_events \
                                      WHERE job_id = expired.id), 0), \
                'timed_out', TRUE FROM expired",
    )
    .execute(&mut *transaction)
    .await
    .map_err(internal)?;
    sqlx::query(
        "DELETE FROM identities WHERE activated_at IS NULL \
         AND activation_expires_at <= NOW()",
    )
    .execute(&mut *transaction)
    .await
    .map_err(internal)?;
    sqlx::query(
        "DELETE FROM identity_certificates WHERE state = 'pending' \
         AND activation_expires_at <= NOW()",
    )
    .execute(&mut *transaction)
    .await
    .map_err(internal)?;
    transaction.commit().await.map_err(internal)?;
    Ok(())
}

#[derive(Debug, Clone)]
pub struct EnrollmentRpc {
    state: RuntimeState,
}

impl EnrollmentRpc {
    #[must_use]
    pub fn new(state: RuntimeState) -> Self {
        Self { state }
    }
}

#[derive(Debug, Clone)]
pub struct ClientRpc {
    state: RuntimeState,
}

impl ClientRpc {
    #[must_use]
    pub fn new(state: RuntimeState) -> Self {
        Self { state }
    }
}

#[derive(Debug, Clone)]
pub struct AdminRpc {
    state: RuntimeState,
}

impl AdminRpc {
    #[must_use]
    pub fn new(state: RuntimeState) -> Self {
        Self { state }
    }
}

#[tonic::async_trait]
impl EnrollmentService for EnrollmentRpc {
    async fn enroll_client(
        &self,
        request: Request<EnrollClientRequest>,
    ) -> Result<Response<EnrollmentResponse>, Status> {
        let request = request.into_inner();
        validate_protocol(request.protocol.as_ref())?;
        validate_client_claims(&request)?;
        let response = enroll(
            &self.state,
            IdentityRole::Client,
            request.enrollment_key,
            request.csr_pem,
            request.hostname,
            None,
            Some((request.os, request.architecture)),
        )
        .await?;
        Ok(Response::new(response))
    }

    async fn enroll_admin(
        &self,
        request: Request<EnrollAdminRequest>,
    ) -> Result<Response<EnrollmentResponse>, Status> {
        let request = request.into_inner();
        validate_protocol(request.protocol.as_ref())?;
        validate_name(&request.name, 128)?;
        if !request.elevation_public_key.is_empty() && request.elevation_public_key.len() != 32 {
            return Err(Status::invalid_argument(
                "elevation public key must be empty or 32-byte Ed25519",
            ));
        }
        let elevation_public_key = (!request.elevation_public_key.is_empty())
            .then_some(request.elevation_public_key);
        let response = enroll(
            &self.state,
            IdentityRole::Admin,
            request.enrollment_key,
            request.csr_pem,
            request.name,
            elevation_public_key,
            None,
        )
        .await?;
        Ok(Response::new(response))
    }
}

#[tonic::async_trait]
impl ClientService for ClientRpc {
    type ControlStreamStream = RpcStream<ServerFrame>;

    async fn control_stream(
        &self,
        request: Request<Streaming<ClientFrame>>,
    ) -> Result<Response<Self::ControlStreamStream>, Status> {
        let presented_fingerprint = peer_certificate_fingerprint(&request)?;
        let identity = authenticate(&self.state.pool, &request, "client").await?;
        let mut inbound = request.into_inner();
        let first = tokio::time::timeout(Duration::from_secs(10), inbound.message())
            .await
            .map_err(|_| Status::deadline_exceeded("client Hello was not received in time"))?
            .map_err(|_| Status::invalid_argument("could not decode client Hello"))?
            .ok_or_else(|| Status::invalid_argument("client stream closed before Hello"))?;
        let hello = match first.payload {
            Some(centrald_protocol::v1::client_frame::Payload::Hello(hello)) => hello,
            _ => return Err(Status::failed_precondition("the first client frame must be Hello")),
        };
        handle_client_hello(&self.state, identity, hello).await?;

        let state = self.state.clone();
        let (sender, receiver) = mpsc::channel(32);
        tokio::spawn(async move {
            let mut authorization = tokio::time::interval(Duration::from_secs(5));
            authorization.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Delay);
            loop {
                tokio::select! {
                    _ = authorization.tick() => {
                        if let Err(status) = authorize_existing_identity(
                            &state.pool,
                            identity,
                            &presented_fingerprint,
                            "client",
                        ).await {
                            let _ = sender.send(Err(status)).await;
                            break;
                        }
                    }
                    message = inbound.message() => {
                        let frame = match message {
                            Ok(Some(frame)) => frame,
                            Ok(None) => break,
                            Err(_) => {
                                let _ = sender.send(Err(Status::invalid_argument(
                                    "could not decode client frame",
                                ))).await;
                                break;
                            }
                        };
                        if matches!(
                            frame.payload,
                            Some(centrald_protocol::v1::client_frame::Payload::Hello(_))
                        ) {
                            let _ = sender.send(Err(Status::failed_precondition(
                                "client Hello may be sent only once",
                            ))).await;
                            break;
                        }
                        if let Err(status) = handle_client_frame(&state, identity, frame, &sender).await {
                            let _ = sender.send(Err(status)).await;
                            break;
                        }
                    }
                }
            }
        });
        Ok(Response::new(Box::pin(ReceiverStream::new(receiver))))
    }

    async fn activate_identity(
        &self,
        request: Request<ActivateIdentityRequest>,
    ) -> Result<Response<OperationResult>, Status> {
        let fingerprint = peer_certificate_fingerprint(&request)?;
        let request = request.into_inner();
        validate_protocol(request.protocol.as_ref())?;
        let identity = parse_uuid(&request.identity_id, "identity_id")?;
        activate_identity_certificate(&self.state.pool, identity, &fingerprint, "client").await?;
        Ok(Response::new(OperationResult {
            success: true,
            message: "client identity activated".to_owned(),
        }))
    }

    async fn renew_certificate(
        &self,
        request: Request<RenewCertificateRequest>,
    ) -> Result<Response<RenewCertificateResponse>, Status> {
        let presented_fingerprint = peer_certificate_fingerprint(&request)?;
        let identity = authenticate(&self.state.pool, &request, "client").await?;
        let response = renew_identity_certificate(
            &self.state,
            identity,
            &presented_fingerprint,
            request.into_inner(),
            IdentityCertificateKind::Client,
        )
        .await?;
        Ok(Response::new(response))
    }

    async fn replace_identity(
        &self,
        request: Request<ReplaceIdentityRequest>,
    ) -> Result<Response<OperationResult>, Status> {
        let current_identity = authenticate(&self.state.pool, &request, "client").await?;
        let request = request.into_inner();
        validate_protocol(request.protocol.as_ref())?;
        validate_name(&request.reason, 512)?;
        let replacement = parse_uuid(&request.replacement_identity_id, "replacement_identity_id")?;
        replace_client_identity(
            &self.state.pool,
            current_identity,
            replacement,
            &request.reason,
        )
        .await?;
        Ok(Response::new(OperationResult {
            success: true,
            message: "previous client identity revoked after replacement".to_owned(),
        }))
    }
}

#[tonic::async_trait]
impl AdminService for AdminRpc {
    type StreamJobStream = RpcStream<JobEvent>;
    type OpenShellStream = RpcStream<AdminShellFrame>;

    async fn list_targets(
        &self,
        request: Request<ListTargetsRequest>,
    ) -> Result<Response<ListTargetsResponse>, Status> {
        let _actor = authenticate(&self.state.pool, &request, "admin").await?;
        let rows =
            sqlx::query_as::<_, (Uuid, String, String, String, String, Option<DateTime<Utc>>)>(
                "SELECT i.id, i.name, c.os, c.architecture, c.client_version, c.last_seen \
             FROM identities i JOIN clients c ON c.identity_id = i.id \
             WHERE i.activated_at IS NOT NULL AND i.revoked_at IS NULL ORDER BY i.name",
            )
            .fetch_all(&self.state.pool)
            .await
            .map_err(internal)?;
        let now = Utc::now();
        let targets = rows
            .into_iter()
            .map(
                |(id, name, os, architecture, version, last_seen)| TargetSummary {
                    id: id.to_string(),
                    name,
                    os,
                    architecture,
                    version,
                    last_seen: last_seen.map(chrono_timestamp),
                    online: last_seen.is_some_and(|seen| {
                        now - seen
                            < chrono::Duration::seconds(i64::from(
                                self.state.config.runtime.offline_after_seconds,
                            ))
                    }),
                    server: false,
                },
            )
            .collect();
        Ok(Response::new(ListTargetsResponse { targets }))
    }

    async fn create_enrollment_key(
        &self,
        request: Request<CreateEnrollmentKeyRequest>,
    ) -> Result<Response<CreateEnrollmentKeyResponse>, Status> {
        let actor = authenticate(&self.state.pool, &request, "admin").await?;
        let request = request.into_inner();
        let role = IdentityRole::try_from(request.role)
            .map_err(|_| Status::invalid_argument("invalid identity role"))?;
        if role != IdentityRole::Client {
            return Err(Status::permission_denied(
                "Admin access keys can be created only with centrald-server",
            ));
        }
        let role_name = "client";
        validate_name(&request.name, 128)?;
        if !(60..=86_400).contains(&request.expires_in_seconds) {
            return Err(Status::invalid_argument(
                "expiry must be between 60 seconds and 24 hours",
            ));
        }
        let id = Uuid::now_v7();
        let expires_at =
            Utc::now() + chrono::Duration::seconds(i64::from(request.expires_in_seconds));
        let claims = EnrollmentInvitationClaims::new(
            id,
            self.state.config.server.instance_id,
            EnrollmentRole::Client,
            request.name.clone(),
            self.state.config.server.public_host.clone(),
            self.state.config.server.enrollment_listen.port(),
            self.state.config.server.client_listen.port(),
            self.state.config.server.admin_listen.port(),
            self.state.root_certificate_pem.as_ref().clone(),
            expires_at,
        );
        let key = generate_enrollment_invitation(&claims).map_err(invalid_key)?;
        let (key, hash) = hash_enrollment_key_bounded(&self.state, key).await?;
        let mut transaction = self.state.pool.begin().await.map_err(internal)?;
        sqlx::query(
            "INSERT INTO enrollment_keys (id, role, name, secret_hash, expires_at) \
             VALUES ($1, $2, $3, $4, $5)",
        )
        .bind(id)
        .bind(role_name)
        .bind(&request.name)
        .bind(hash)
        .bind(expires_at)
        .execute(&mut *transaction)
        .await
        .map_err(internal)?;
        append_audit(
            &mut transaction,
            Some(actor),
            "admin",
            "enrollment_key.create",
            None,
            "succeeded",
            serde_json::json!({"key_id": id, "role": role_name}),
        )
        .await?;
        transaction.commit().await.map_err(internal)?;
        Ok(Response::new(CreateEnrollmentKeyResponse {
            id: id.to_string(),
            enrollment_key: key.expose_secret().to_owned(),
            expires_at: Some(chrono_timestamp(expires_at)),
        }))
    }

    async fn list_enrollment_keys(
        &self,
        request: Request<ListEnrollmentKeysRequest>,
    ) -> Result<Response<ListEnrollmentKeysResponse>, Status> {
        let _actor = authenticate(&self.state.pool, &request, "admin").await?;
        let request = request.into_inner();
        let role = IdentityRole::try_from(request.role)
            .map_err(|_| Status::invalid_argument("invalid identity role"))?;
        if role != IdentityRole::Client {
            return Err(Status::permission_denied(
                "Admin access keys are visible only in centrald-server config",
            ));
        }
        let rows = if request.include_inactive {
            sqlx::query_as::<
                _,
                (
                    Uuid,
                    String,
                    DateTime<Utc>,
                    DateTime<Utc>,
                    Option<DateTime<Utc>>,
                    Option<DateTime<Utc>>,
                    Option<String>,
                ),
            >(
                "SELECT id, name, expires_at, created_at, consumed_at, revoked_at, revoked_reason \
                 FROM enrollment_keys WHERE role = 'client' \
                 ORDER BY created_at DESC LIMIT 500",
            )
            .fetch_all(&self.state.pool)
            .await
            .map_err(internal)?
        } else {
            sqlx::query_as::<
                _,
                (
                    Uuid,
                    String,
                    DateTime<Utc>,
                    DateTime<Utc>,
                    Option<DateTime<Utc>>,
                    Option<DateTime<Utc>>,
                    Option<String>,
                ),
            >(
                "SELECT id, name, expires_at, created_at, consumed_at, revoked_at, revoked_reason \
                 FROM enrollment_keys WHERE role = 'client' AND consumed_at IS NULL \
                 AND revoked_at IS NULL AND expires_at > NOW() \
                 ORDER BY created_at DESC LIMIT 500",
            )
            .fetch_all(&self.state.pool)
            .await
            .map_err(internal)?
        };
        let keys = rows
            .into_iter()
            .map(
                |(id, name, expires_at, created_at, consumed_at, revoked_at, revoked_reason)| {
                    EnrollmentKeySummary {
                        id: id.to_string(),
                        role: IdentityRole::Client as i32,
                        name,
                        expires_at: Some(chrono_timestamp(expires_at)),
                        created_at: Some(chrono_timestamp(created_at)),
                        consumed_at: consumed_at.map(chrono_timestamp),
                        revoked_at: revoked_at.map(chrono_timestamp),
                        revoked_reason: revoked_reason.unwrap_or_default(),
                    }
                },
            )
            .collect();
        Ok(Response::new(ListEnrollmentKeysResponse { keys }))
    }

    async fn revoke_enrollment_key(
        &self,
        request: Request<RevokeEnrollmentKeyRequest>,
    ) -> Result<Response<OperationResult>, Status> {
        let actor = authenticate(&self.state.pool, &request, "admin").await?;
        let request = request.into_inner();
        validate_name(&request.reason, 512)?;
        let key_id = parse_uuid(&request.enrollment_key_id, "enrollment_key_id")?;
        let mut transaction = self.state.pool.begin().await.map_err(internal)?;
        let affected = sqlx::query(
            "UPDATE enrollment_keys SET revoked_at = NOW(), revoked_by = $2, revoked_reason = $3 \
             WHERE id = $1 AND role = 'client' AND consumed_at IS NULL \
             AND revoked_at IS NULL AND expires_at > NOW()",
        )
        .bind(key_id)
        .bind(actor)
        .bind(&request.reason)
        .execute(&mut *transaction)
        .await
        .map_err(internal)?
        .rows_affected();
        if affected != 1 {
            return Err(Status::failed_precondition(
                "invitation is missing, expired, consumed, or already revoked",
            ));
        }
        append_audit(
            &mut transaction,
            Some(actor),
            "admin",
            "enrollment_key.revoke",
            None,
            "succeeded",
            serde_json::json!({"key_id": key_id, "role": "client", "reason": request.reason}),
        )
        .await?;
        transaction.commit().await.map_err(internal)?;
        Ok(Response::new(OperationResult {
            success: true,
            message: "client invitation revoked".to_owned(),
        }))
    }

    async fn activate_admin_identity(
        &self,
        request: Request<ActivateIdentityRequest>,
    ) -> Result<Response<OperationResult>, Status> {
        let fingerprint = peer_certificate_fingerprint(&request)?;
        let request = request.into_inner();
        validate_protocol(request.protocol.as_ref())?;
        let identity = parse_uuid(&request.identity_id, "identity_id")?;
        activate_identity_certificate(&self.state.pool, identity, &fingerprint, "admin").await?;
        Ok(Response::new(OperationResult {
            success: true,
            message: "Admin identity activated".to_owned(),
        }))
    }

    async fn renew_admin_certificate(
        &self,
        request: Request<RenewCertificateRequest>,
    ) -> Result<Response<RenewCertificateResponse>, Status> {
        let presented_fingerprint = peer_certificate_fingerprint(&request)?;
        let identity = authenticate(&self.state.pool, &request, "admin").await?;
        let response = renew_identity_certificate(
            &self.state,
            identity,
            &presented_fingerprint,
            request.into_inner(),
            IdentityCertificateKind::Admin,
        )
        .await?;
        Ok(Response::new(response))
    }

    async fn revoke_identity(
        &self,
        request: Request<RevokeIdentityRequest>,
    ) -> Result<Response<OperationResult>, Status> {
        let actor = authenticate(&self.state.pool, &request, "admin").await?;
        let request = request.into_inner();
        validate_name(&request.reason, 512)?;
        let identity_id = parse_uuid(&request.identity_id, "identity_id")?;
        let mut transaction = self.state.pool.begin().await.map_err(internal)?;
        let identity: Option<(String, Option<DateTime<Utc>>)> = sqlx::query_as(
            "SELECT role, revoked_at FROM identities WHERE id = $1 FOR UPDATE",
        )
        .bind(identity_id)
        .fetch_optional(&mut *transaction)
        .await
        .map_err(internal)?;
        let Some((role, revoked_at)) = identity else {
            return Err(Status::not_found("identity not found"));
        };
        if role != "client" {
            return Err(Status::permission_denied(
                "Admin identities can be revoked only with centrald-server",
            ));
        }
        if revoked_at.is_some() {
            return Err(Status::failed_precondition("identity is already revoked"));
        }
        let affected = sqlx::query(
            "UPDATE identities SET revoked_at = NOW(), revoked_reason = $2, updated_at = NOW() \
             WHERE id = $1 AND role = 'client' AND revoked_at IS NULL",
        )
        .bind(identity_id)
        .bind(&request.reason)
        .execute(&mut *transaction)
        .await
        .map_err(internal)?
        .rows_affected();
        if affected != 1 {
            return Err(Status::aborted(
                "identity changed before revocation; refresh and try again",
            ));
        }
        append_audit(
            &mut transaction,
            Some(actor),
            "admin",
            "identity.revoke",
            Some(identity_id),
            "succeeded",
            serde_json::json!({"reason": request.reason}),
        )
        .await?;
        transaction.commit().await.map_err(internal)?;
        Ok(Response::new(OperationResult {
            success: true,
            message: "identity revoked".into(),
        }))
    }

    async fn start_job(&self, request: Request<StartJobRequest>) -> Result<Response<Job>, Status> {
        let actor = authenticate(&self.state.pool, &request, "admin").await?;
        let request = request.into_inner();
        let request_id = parse_uuid(&request.request_id, "request_id")?;
        let target_id = parse_uuid(&request.target_id, "target_id")?;
        let kind = JobKind::try_from(request.kind)
            .map_err(|_| Status::invalid_argument("invalid job kind"))?;
        let kind_name = job_kind_name(kind)?;
        validate_name(&request.reason, 512)?;
        if request.parameters_json.len() > MAX_PARAMETERS_BYTES {
            return Err(Status::invalid_argument("job parameters are too large"));
        }
        let parameters: serde_json::Value = if request.parameters_json.is_empty() {
            serde_json::json!({})
        } else {
            serde_json::from_slice(&request.parameters_json)
                .map_err(|_| Status::invalid_argument("parameters_json is invalid JSON"))?
        };
        let id = Uuid::now_v7();
        let idempotency_key = request_id;
        let expires_at = Utc::now()
            + chrono::Duration::seconds(i64::from(
                self.state.config.runtime.job_ttl_seconds,
            ));
        let mut transaction = self.state.pool.begin().await.map_err(internal)?;
        let active_target: bool = sqlx::query_scalar(
            "SELECT EXISTS (SELECT 1 FROM identities \
             WHERE id = $1 AND role = 'client' AND activated_at IS NOT NULL AND revoked_at IS NULL)",
        )
        .bind(target_id)
        .fetch_one(&mut *transaction)
        .await
        .map_err(internal)?;
        if !active_target {
            return Err(Status::not_found("active client target not found"));
        }
        let supports_typed_jobs: bool = sqlx::query_scalar(
            "SELECT COALESCE((SELECT capabilities ? 'typed_jobs' FROM clients WHERE identity_id = $1), FALSE)",
        )
        .bind(target_id)
        .fetch_one(&mut *transaction)
        .await
        .map_err(internal)?;
        if !supports_typed_jobs {
            return Err(Status::failed_precondition(
                "client privileged job execution is unavailable until the broker is enabled",
            ));
        }
        let row = sqlx::query_as::<
            _,
            (
                Uuid,
                Uuid,
                String,
                String,
                serde_json::Value,
                String,
                Uuid,
                DateTime<Utc>,
            ),
        >(
            "INSERT INTO jobs \
             (id, request_id, target_id, actor_id, kind, state, parameters, reason, \
              idempotency_key, expires_at) \
             VALUES ($1, $2, $3, $4, $5, 'queued', $6, $7, $8, $9) \
             ON CONFLICT (actor_id, request_id) DO UPDATE SET request_id = EXCLUDED.request_id \
             RETURNING id, target_id, kind, state, parameters, reason, idempotency_key, expires_at",
        )
        .bind(id)
        .bind(request_id)
        .bind(target_id)
        .bind(actor)
        .bind(kind_name)
        .bind(&parameters)
        .bind(&request.reason)
        .bind(idempotency_key)
        .bind(expires_at)
        .fetch_one(&mut *transaction)
        .await
        .map_err(internal)?;
        if row.1 != target_id
            || row.2 != kind_name
            || row.4 != parameters
            || row.5 != request.reason
            || row.6 != idempotency_key
        {
            return Err(Status::already_exists(
                "request_id was already used for a different job",
            ));
        }
        append_audit(
            &mut transaction,
            Some(actor),
            "admin",
            "job.start",
            Some(target_id),
            "succeeded",
            serde_json::json!({"job_id": row.0, "kind": kind_name}),
        )
        .await?;
        transaction.commit().await.map_err(internal)?;
        let parameters_json = serde_json::to_vec(&row.4).map_err(internal)?;
        Ok(Response::new(Job {
            id: row.0.to_string(),
            target_id: target_id.to_string(),
            kind: kind as i32,
            state: job_state_from_name(&row.3) as i32,
            parameters_json,
            idempotency_key: idempotency_key.to_string(),
            expires_at: Some(chrono_timestamp(row.7)),
            delivery_id: String::new(),
        }))
    }

    async fn stream_job(
        &self,
        request: Request<StreamJobRequest>,
    ) -> Result<Response<Self::StreamJobStream>, Status> {
        let presented_fingerprint = peer_certificate_fingerprint(&request)?;
        let actor = authenticate(&self.state.pool, &request, "admin").await?;
        let stream_permit = self
            .state
            .job_stream_limit
            .clone()
            .try_acquire_owned()
            .map_err(|_| Status::resource_exhausted("too many concurrent Admin job streams"))?;
        let request = request.into_inner();
        let job_id = parse_uuid(&request.job_id, "job_id")?;
        let mut next = i64::try_from(request.from_sequence)
            .map_err(|_| Status::invalid_argument("from_sequence is too large"))?;
        let expires_at: DateTime<Utc> = sqlx::query_scalar(
            "SELECT expires_at FROM jobs WHERE id = $1",
        )
        .bind(job_id)
        .fetch_optional(&self.state.pool)
        .await
        .map_err(internal)?
        .ok_or_else(|| Status::not_found("job does not exist"))?;
        let stream_deadline = expires_at + chrono::Duration::minutes(5);
        let pool = self.state.pool.clone();
        let follow = request.follow;
        let (sender, receiver) = mpsc::channel(64);
        tokio::spawn(async move {
            let _stream_permit = stream_permit;
            let mut next_authorization = tokio::time::Instant::now()
                + Duration::from_secs(ADMIN_STREAM_REAUTH_SECONDS);
            loop {
                if Utc::now() > stream_deadline {
                    let _ = sender
                        .send(Err(Status::deadline_exceeded("job stream lifetime ended")))
                        .await;
                    break;
                }
                if tokio::time::Instant::now() >= next_authorization {
                    if let Err(status) = authorize_existing_identity(
                        &pool,
                        actor,
                        &presented_fingerprint,
                        "admin",
                    )
                    .await
                    {
                        let _ = sender.send(Err(status)).await;
                        break;
                    }
                    next_authorization = tokio::time::Instant::now()
                        + Duration::from_secs(ADMIN_STREAM_REAUTH_SECONDS);
                }
                let rows = sqlx::query_as::<_, (i64, String, Vec<u8>, bool, Option<i32>, bool)>(
                    "SELECT sequence, state, output, stderr, exit_code, terminal \
                     FROM job_events WHERE job_id = $1 AND sequence >= $2 \
                     ORDER BY sequence LIMIT 128",
                )
                .bind(job_id)
                .bind(next)
                .fetch_all(&pool)
                .await;
                let rows = match rows {
                    Ok(rows) => rows,
                    Err(error) => {
                        error!(%error, %job_id, "stream job query failed");
                        let _ = sender.send(Err(Status::internal("job stream failed"))).await;
                        break;
                    }
                };
                let mut terminal = false;
                for (sequence, state, output, stderr, exit_code, is_terminal) in rows {
                    next = sequence.saturating_add(1);
                    terminal |= is_terminal;
                    let event = JobEvent {
                        job_id: job_id.to_string(),
                        sequence: u64::try_from(sequence).unwrap_or_default(),
                        state: job_state_from_name(&state) as i32,
                        output,
                        stderr,
                        exit_code: exit_code.unwrap_or_default(),
                        terminal: is_terminal,
                    };
                    if sender.send(Ok(event)).await.is_err() {
                        return;
                    }
                }
                if terminal || !follow {
                    break;
                }
                tokio::select! {
                    () = sender.closed() => break,
                    () = tokio::time::sleep(Duration::from_millis(250)) => {}
                }
            }
        });
        Ok(Response::new(Box::pin(ReceiverStream::new(receiver))))
    }

    async fn begin_elevation(
        &self,
        request: Request<BeginElevationRequest>,
    ) -> Result<Response<ElevationChallenge>, Status> {
        let _actor = authenticate(&self.state.pool, &request, "admin").await?;
        Err(Status::unimplemented(
            "elevated shell challenge transport is not enabled yet",
        ))
    }

    async fn open_shell(
        &self,
        request: Request<Streaming<AdminShellFrame>>,
    ) -> Result<Response<Self::OpenShellStream>, Status> {
        let _actor = authenticate(&self.state.pool, &request, "admin").await?;
        Err(Status::unimplemented(
            "remote shell relay is disabled until broker PTY isolation is complete",
        ))
    }

    async fn get_server_settings(
        &self,
        request: Request<GetServerSettingsRequest>,
    ) -> Result<Response<ServerSettings>, Status> {
        let _actor = authenticate(&self.state.pool, &request, "admin").await?;
        let _guard = self.state.settings_lock.lock().await;
        let _file_lock = acquire_config_lock_nonblocking(&self.state.config_path).await?;
        recover_server_transactions_locked(&self.state.config_path)?;
        let (config, revision) = load_server_settings(&self.state.config_path)?;
        let restart_required = revision != self.state.loaded_config_revision.as_str();
        Ok(Response::new(server_settings(&config, revision, restart_required)))
    }

    async fn update_server_settings(
        &self,
        request: Request<UpdateServerSettingsRequest>,
    ) -> Result<Response<ServerSettings>, Status> {
        let actor = authenticate(&self.state.pool, &request, "admin").await?;
        let request = request.into_inner();
        if request.expected_revision.is_empty() {
            return Err(Status::invalid_argument("expected_revision is required"));
        }
        let requested = request
            .settings
            .ok_or_else(|| Status::invalid_argument("settings are required"))?;
        let _guard = self.state.settings_lock.lock().await;
        let _file_lock = acquire_config_lock_nonblocking(&self.state.config_path).await?;
        recover_server_transactions_locked(&self.state.config_path)?;
        let original = fs::read(&*self.state.config_path).map_err(internal)?;
        let (mut config, revision) = load_server_settings(&self.state.config_path)?;
        if request.expected_revision != revision {
            return Err(Status::aborted(
                "server settings changed; reload before saving",
            ));
        }
        validate_read_only_settings(&config, &requested)?;
        config.server.enrollment_listen = parse_listener(
            &requested.enrollment_listen,
            "enrollment_listen",
        )?;
        config.server.client_listen =
            parse_listener(&requested.client_listen, "client_listen")?;
        config.server.admin_listen =
            parse_listener(&requested.admin_listen, "admin_listen")?;
        config.database.max_connections = requested.database_max_connections;
        config.runtime.heartbeat_interval_seconds = requested.heartbeat_interval_seconds;
        config.runtime.offline_after_seconds = requested.offline_after_seconds;
        config.runtime.job_ttl_seconds = requested.job_ttl_seconds;
        config.runtime.shell_idle_timeout_seconds = requested.shell_idle_timeout_seconds;
        config.runtime.max_shell_frame_bytes = requested.max_shell_frame_bytes;
        config.updates.enabled = requested.updates_enabled;
        config.updates.check_interval_seconds = requested.update_check_interval_seconds;
        config.updates.allow_prerelease = requested.update_allow_prerelease;
        config
            .validate()
            .map_err(|error| Status::invalid_argument(error.to_string()))?;
        let serialized = toml::to_string_pretty(&config).map_err(internal)?;
        let new_revision = settings_revision(serialized.as_bytes());
        audit(
            &self.state.pool,
            Some(actor),
            "admin",
            "server_settings.update.prepare",
            None,
            "pending",
            serde_json::json!({
                "previous_revision": &revision,
                "intended_revision": &new_revision,
            }),
        )
        .await?;
        let transaction = SettingsUpdateTransaction::begin_locked(
            &self.state.config_path,
            &original,
            &new_revision,
        )
        .map_err(internal)?;
        if let Err(error) = replace_file_atomically(
            &self.state.config_path,
            serialized.as_bytes(),
            true,
        ) {
            let rollback = transaction.rollback();
            return Err(settings_update_failure("publish configuration", error, rollback));
        }
        if let Err(error) = transaction.mark_published() {
            let rollback = transaction.rollback();
            return Err(settings_update_failure("mark configuration published", error, rollback));
        }
        if let Err(error) = audit(
            &self.state.pool,
            Some(actor),
            "admin",
            "server_settings.update",
            None,
            "succeeded",
            serde_json::json!({"revision": &new_revision}),
        )
        .await
        {
            let rollback = transaction.rollback();
            return Err(settings_update_failure("append final audit entry", error, rollback));
        }
        if let Err(error) = transaction.complete() {
            warn!(%error, "server settings committed but recovery transaction cleanup was incomplete");
            recover_interrupted_settings_update_locked(&self.state.config_path).map_err(
                |recovery_error| {
                    Status::internal(format!(
                        "server settings were committed, but recovery cleanup failed: {error:#}; reconciliation also failed: {recovery_error:#}"
                    ))
                },
            )?;
        }
        Ok(Response::new(server_settings(&config, new_revision, true)))
    }
}

fn settings_update_failure(
    operation: &str,
    error: impl std::fmt::Display,
    rollback: anyhow::Result<()>,
) -> Status {
    match rollback {
        Ok(()) => Status::internal(format!(
            "server settings update failed during {operation} and was rolled back: {error}"
        )),
        Err(rollback_error) => Status::internal(format!(
            "server settings update failed during {operation}; rollback also failed: {error}; {rollback_error:#}"
        )),
    }
}

fn recover_server_transactions_locked(path: &std::path::Path) -> Result<(), Status> {
    recover_interrupted_database_update_locked(path).map_err(internal)?;
    recover_interrupted_settings_update_locked(path).map_err(internal)?;
    recover_interrupted_online_issuer_rotation_locked(path).map_err(internal)?;
    recover_interrupted_tls_rotation_locked(path).map_err(internal)?;
    Ok(())
}

fn load_server_settings(path: &std::path::Path) -> Result<(ServerConfig, String), Status> {
    let raw = std::fs::read(path).map_err(internal)?;
    let config = ServerConfig::load(path)
        .map_err(|error| Status::failed_precondition(error.to_string()))?;
    Ok((config, settings_revision(&raw)))
}

fn settings_revision(raw: &[u8]) -> String {
    hex::encode(sha256(raw))
}

fn server_settings(
    config: &ServerConfig,
    revision: String,
    restart_required: bool,
) -> ServerSettings {
    ServerSettings {
        revision,
        instance_id: config.server.instance_id.to_string(),
        public_host: config.server.public_host.clone(),
        enrollment_listen: config.server.enrollment_listen.to_string(),
        client_listen: config.server.client_listen.to_string(),
        admin_listen: config.server.admin_listen.to_string(),
        database_max_connections: config.database.max_connections,
        heartbeat_interval_seconds: config.runtime.heartbeat_interval_seconds,
        offline_after_seconds: config.runtime.offline_after_seconds,
        job_ttl_seconds: config.runtime.job_ttl_seconds,
        shell_idle_timeout_seconds: config.runtime.shell_idle_timeout_seconds,
        max_shell_frame_bytes: config.runtime.max_shell_frame_bytes,
        updates_enabled: config.updates.enabled,
        update_channel: config.updates.channel.clone(),
        update_manifest_url: config.updates.manifest_url.clone(),
        update_check_interval_seconds: config.updates.check_interval_seconds,
        update_allow_prerelease: config.updates.allow_prerelease,
        data_dir: config.server.data_dir.display().to_string(),
        local_socket: config.server.local_socket.display().to_string(),
        database_url_env: config.database.url_env.clone(),
        database_environment_file: config.database.environment_file.display().to_string(),
        root_cert_path: config.pki.root_cert.display().to_string(),
        local_only_fields: vec![
            "instanceId".into(),
            "publicHost".into(),
            "dataDir".into(),
            "localSocket".into(),
            "databaseUrlEnv".into(),
            "databaseEnvironmentFile".into(),
            "rootCertPath".into(),
            "updateChannel".into(),
            "updateManifestUrl".into(),
            "pki".into(),
            "adminAccess".into(),
            "nuke".into(),
        ],
        restart_required,
    }
}

fn validate_read_only_settings(
    config: &ServerConfig,
    requested: &ServerSettings,
) -> Result<(), Status> {
    let unchanged = requested.instance_id == config.server.instance_id.to_string()
        && requested.public_host == config.server.public_host
        && requested.data_dir == config.server.data_dir.display().to_string()
        && requested.local_socket == config.server.local_socket.display().to_string()
        && requested.database_url_env == config.database.url_env
        && requested.database_environment_file
            == config.database.environment_file.display().to_string()
        && requested.root_cert_path == config.pki.root_cert.display().to_string()
        && requested.update_channel == config.updates.channel
        && requested.update_manifest_url == config.updates.manifest_url;
    if !unchanged {
        return Err(Status::permission_denied(
            "one or more server-local settings were modified",
        ));
    }
    Ok(())
}

fn parse_listener(value: &str, field: &str) -> Result<std::net::SocketAddr, Status> {
    value
        .parse()
        .map_err(|_| Status::invalid_argument(format!("{field} is not a socket address")))
}

async fn renew_identity_certificate(
    state: &RuntimeState,
    identity: Uuid,
    presented_fingerprint: &str,
    request: RenewCertificateRequest,
    kind: IdentityCertificateKind,
) -> Result<RenewCertificateResponse, Status> {
    validate_protocol(request.protocol.as_ref())?;
    let csr = decode_csr(&request.csr_pem)?;
    let name: String = sqlx::query_scalar(
        "SELECT name FROM identities WHERE id = $1 AND activated_at IS NOT NULL AND revoked_at IS NULL",
    )
    .bind(identity)
    .fetch_optional(&state.pool)
    .await
    .map_err(internal)?
    .ok_or_else(|| Status::permission_denied("identity is revoked, inactive, or missing"))?;
    let (issuer_certificate, issuer_key) = match kind {
        IdentityCertificateKind::Client => (
            state.client_issuer_certificate_pem.as_str(),
            state.client_issuer_private_key_pem.expose_secret(),
        ),
        IdentityCertificateKind::Admin => (
            state.admin_issuer_certificate_pem.as_str(),
            state.admin_issuer_private_key_pem.expose_secret(),
        ),
    };
    let issued = issue_identity_csr(
        csr,
        &name,
        identity,
        kind,
        issuer_certificate,
        issuer_key,
        &state.root_certificate_pem,
    )
    .map_err(|_| Status::invalid_argument("invalid certificate request"))?;
    let expires_at = issued_expiration(&issued)?;
    let activation_expires_at = Utc::now()
        + chrono::Duration::hours(IDENTITY_ACTIVATION_TTL_HOURS);
    let mut transaction = state.pool.begin().await.map_err(internal)?;
    let presented_is_active: bool = sqlx::query_scalar(
        "SELECT EXISTS (SELECT 1 FROM identity_certificates \
         WHERE identity_id = $1 AND certificate_fingerprint = $2 \
         AND state = 'active' AND revoked_at IS NULL AND expires_at > NOW() \
         AND (retire_at IS NULL OR retire_at > NOW()))",
    )
    .bind(identity)
    .bind(presented_fingerprint)
    .fetch_one(&mut *transaction)
    .await
    .map_err(internal)?;
    if !presented_is_active {
        return Err(Status::unauthenticated("certificate is no longer active"));
    }
    sqlx::query(
        "INSERT INTO identity_certificates \
         (certificate_fingerprint, identity_id, certificate_serial, state, \
          activation_expires_at, expires_at) \
         VALUES ($1, $2, $3, 'pending', $4, $5)",
    )
    .bind(&issued.fingerprint_sha256)
    .bind(identity)
    .bind(&issued.serial_hex)
    .bind(activation_expires_at)
    .bind(expires_at)
    .execute(&mut *transaction)
    .await
    .map_err(internal)?;
    append_audit(
        &mut transaction,
        Some(identity),
        match kind {
            IdentityCertificateKind::Client => "client",
            IdentityCertificateKind::Admin => "admin",
        },
        "identity.certificate_renew_pending",
        Some(identity),
        "succeeded",
        serde_json::json!({
            "previous_fingerprint": presented_fingerprint,
            "pending_fingerprint": issued.fingerprint_sha256,
            "activation_expires_at": activation_expires_at,
        }),
    )
    .await?;
    transaction.commit().await.map_err(internal)?;
    Ok(RenewCertificateResponse {
        certificate_chain_pem: issued.certificate_chain_pem.into_bytes(),
        expires_at: Some(offset_timestamp(issued.expires_at)),
    })
}

async fn enroll(
    state: &RuntimeState,
    role: IdentityRole,
    enrollment_key: String,
    csr_pem: Vec<u8>,
    presented_name: String,
    elevation_public_key: Option<Vec<u8>>,
    client_platform: Option<(String, String)>,
) -> Result<EnrollmentResponse, Status> {
    let secret = SecretString::from(enrollment_key);
    let claims = parse_enrollment_invitation(&secret).map_err(invalid_key)?;
    if claims.server_instance_id != state.config.server.instance_id {
        return Err(Status::unauthenticated(
            "invitation belongs to a different CentralD server",
        ));
    }
    let role_name = role_name(role)?;
    if claims.role.as_str() != role_name || claims.expires_at <= Utc::now() {
        return Err(Status::unauthenticated("invalid enrollment key"));
    }
    if role == IdentityRole::Admin && presented_name != claims.name {
        return Err(Status::invalid_argument(
            "Admin name does not match the access key",
        ));
    }
    let csr = decode_csr(&csr_pem)?;
    let key_id = claims.id;

    // Argon2id verification is intentionally performed outside a database
    // transaction and on Tokio's blocking pool. Each verification uses 64 MiB
    // of memory, so a small semaphore bounds concurrent work on homelab hosts.
    let candidate = sqlx::query_as::<
        _,
        (
            String,
            String,
            String,
            DateTime<Utc>,
            Option<DateTime<Utc>>,
            Option<DateTime<Utc>>,
        ),
    >(
        "SELECT role, name, secret_hash, expires_at, consumed_at, revoked_at FROM enrollment_keys \
         WHERE id = $1",
    )
    .bind(key_id)
    .fetch_optional(&state.pool)
    .await
    .map_err(internal)?
    .ok_or_else(|| Status::unauthenticated("invalid enrollment key"))?;
    if candidate.0 != role_name
        || candidate.1 != claims.name
        || candidate.3 <= Utc::now()
        || candidate.4.is_some()
        || candidate.5.is_some()
    {
        return Err(Status::unauthenticated("invalid enrollment key"));
    }
    let expected_hash = candidate.2.clone();
    if !verify_enrollment_key_bounded(state, secret, expected_hash.clone()).await? {
        return Err(Status::unauthenticated("invalid enrollment key"));
    }

    // Lock and re-check the invitation after the expensive verification. This
    // keeps single-use consumption transactional without holding a row lock
    // while Argon2id is running.
    let mut transaction = state.pool.begin().await.map_err(internal)?;
    let row = sqlx::query_as::<
        _,
        (
            String,
            String,
            String,
            DateTime<Utc>,
            Option<DateTime<Utc>>,
            Option<DateTime<Utc>>,
        ),
    >(
        "SELECT role, name, secret_hash, expires_at, consumed_at, revoked_at FROM enrollment_keys \
         WHERE id = $1 FOR UPDATE",
    )
    .bind(key_id)
    .fetch_optional(&mut *transaction)
    .await
    .map_err(internal)?
    .ok_or_else(|| Status::unauthenticated("invalid enrollment key"))?;
    if row.0 != role_name
        || row.1 != claims.name
        || row.2 != expected_hash
        || row.3 <= Utc::now()
        || row.4.is_some()
        || row.5.is_some()
    {
        return Err(Status::unauthenticated("invalid enrollment key"));
    }

    let identity_id = Uuid::now_v7();
    let (kind, issuer_cert, issuer_key) = match role {
        IdentityRole::Client => (
            IdentityCertificateKind::Client,
            state.client_issuer_certificate_pem.as_str(),
            state.client_issuer_private_key_pem.expose_secret(),
        ),
        IdentityRole::Admin => (
            IdentityCertificateKind::Admin,
            state.admin_issuer_certificate_pem.as_str(),
            state.admin_issuer_private_key_pem.expose_secret(),
        ),
        IdentityRole::Unspecified => {
            return Err(Status::invalid_argument("invalid identity role"));
        }
    };
    let issued = issue_identity_csr(
        csr,
        &claims.name,
        identity_id,
        kind,
        issuer_cert,
        issuer_key,
        &state.root_certificate_pem,
    )
    .map_err(|_| Status::invalid_argument("invalid certificate request"))?;
    let activation_expires_at = Utc::now()
        + chrono::Duration::hours(IDENTITY_ACTIVATION_TTL_HOURS);
    sqlx::query(
        "INSERT INTO identities \
         (id, role, name, certificate_serial, certificate_fingerprint, elevation_public_key, \
          activation_expires_at) \
         VALUES ($1, $2, $3, $4, $5, $6, $7)",
    )
    .bind(identity_id)
    .bind(role_name)
    .bind(&claims.name)
    .bind(&issued.serial_hex)
    .bind(&issued.fingerprint_sha256)
    .bind(elevation_public_key)
    .bind(activation_expires_at)
    .execute(&mut *transaction)
    .await
    .map_err(internal)?;
    sqlx::query(
        "INSERT INTO identity_certificates \
         (certificate_fingerprint, identity_id, certificate_serial, state, \
          activation_expires_at, expires_at) \
         VALUES ($1, $2, $3, 'pending', $4, $5)",
    )
    .bind(&issued.fingerprint_sha256)
    .bind(identity_id)
    .bind(&issued.serial_hex)
    .bind(activation_expires_at)
    .bind(issued_expiration(&issued)?)
    .execute(&mut *transaction)
    .await
    .map_err(internal)?;
    if let Some((os, architecture)) = client_platform {
        sqlx::query(
            "INSERT INTO clients \
             (identity_id, hostname, os, architecture, client_version, protocol_major, protocol_minor) \
             VALUES ($1, $2, $3, $4, $5, $6, $7)",
        )
        .bind(identity_id)
        .bind(&presented_name)
        .bind(os)
        .bind(architecture)
        .bind(env!("CARGO_PKG_VERSION"))
        .bind(i32::try_from(centrald_protocol::PROTOCOL_MAJOR).unwrap_or(i32::MAX))
        .bind(i32::try_from(centrald_protocol::PROTOCOL_MINOR).unwrap_or(i32::MAX))
        .execute(&mut *transaction)
        .await
        .map_err(internal)?;
    }
    let consumed = sqlx::query(
        "UPDATE enrollment_keys SET consumed_at = NOW(), consumed_by = $2 \
         WHERE id = $1 AND consumed_at IS NULL AND revoked_at IS NULL AND expires_at > NOW()",
    )
    .bind(key_id)
    .bind(identity_id)
    .execute(&mut *transaction)
    .await
    .map_err(internal)?
    .rows_affected();
    if consumed != 1 {
        return Err(Status::unauthenticated("invalid enrollment key"));
    }
    append_audit(
        &mut transaction,
        Some(identity_id),
        role_name,
        "identity.enroll_pending",
        Some(identity_id),
        "succeeded",
        serde_json::json!({
            "key_id": key_id,
            "role": role_name,
            "activation_expires_at": activation_expires_at,
        }),
    )
    .await?;
    transaction.commit().await.map_err(internal)?;

    Ok(enrollment_response(state, identity_id, role, issued))
}

fn enrollment_response(
    state: &RuntimeState,
    identity_id: Uuid,
    role: IdentityRole,
    issued: IssuedCertificate,
) -> EnrollmentResponse {
    EnrollmentResponse {
        identity_id: identity_id.to_string(),
        role: role as i32,
        certificate_chain_pem: issued.certificate_chain_pem.into_bytes(),
        client_endpoint: endpoint(
            &state.config.server.public_host,
            state.config.server.client_listen.port(),
        ),
        admin_endpoint: endpoint(
            &state.config.server.public_host,
            state.config.server.admin_listen.port(),
        ),
        grant_signing_public_key: state.grant_signing_public_key_pem.as_bytes().to_vec(),
        expires_at: Some(offset_timestamp(issued.expires_at)),
    }
}

fn peer_certificate_fingerprint<T>(request: &Request<T>) -> Result<String, Status> {
    let certificates = request
        .peer_certs()
        .ok_or_else(|| Status::unauthenticated("client certificate required"))?;
    let leaf = certificates
        .first()
        .ok_or_else(|| Status::unauthenticated("client certificate required"))?;
    Ok(certificate_sha256(leaf.as_ref()))
}

fn issued_expiration(issued: &IssuedCertificate) -> Result<DateTime<Utc>, Status> {
    DateTime::from_timestamp(issued.expires_at.unix_timestamp(), issued.expires_at.nanosecond())
        .ok_or_else(|| Status::internal("issued certificate expiration is outside the supported range"))
}

async fn activate_identity_certificate(
    pool: &PgPool,
    identity: Uuid,
    fingerprint: &str,
    expected_role: &str,
) -> Result<(), Status> {
    let mut transaction = pool.begin().await.map_err(internal)?;
    let row = sqlx::query_as::<
        _,
        (
            String,
            Option<DateTime<Utc>>,
            Option<DateTime<Utc>>,
            Option<DateTime<Utc>>,
            String,
            String,
            Option<DateTime<Utc>>,
            DateTime<Utc>,
            Option<DateTime<Utc>>,
        ),
    >(
        "SELECT i.role, i.revoked_at, i.activated_at, i.activation_expires_at, \
                c.certificate_serial, c.state, c.activation_expires_at, c.expires_at, c.revoked_at \
         FROM identities i JOIN identity_certificates c ON c.identity_id = i.id \
         WHERE i.id = $1 AND c.certificate_fingerprint = $2 \
         FOR UPDATE OF i, c",
    )
    .bind(identity)
    .bind(fingerprint)
    .fetch_optional(&mut *transaction)
    .await
    .map_err(internal)?
    .ok_or_else(|| Status::unauthenticated("unknown identity certificate"))?;
    if row.0 != expected_role || row.1.is_some() || row.8.is_some() || row.7 <= Utc::now() {
        return Err(Status::permission_denied("identity certificate is not authorized"));
    }
    if row.5 == "active" {
        transaction.commit().await.map_err(internal)?;
        return Ok(());
    }
    if row.5 != "pending" {
        return Err(Status::unauthenticated("identity certificate has an invalid state"));
    }
    if row.6.is_none_or(|deadline| deadline <= Utc::now())
        || (row.2.is_none() && row.3.is_none_or(|deadline| deadline <= Utc::now()))
    {
        return Err(Status::unauthenticated("identity activation window expired"));
    }

    sqlx::query(
        "UPDATE identity_certificates \
         SET retire_at = LEAST(COALESCE(retire_at, expires_at), NOW() + INTERVAL '1 hour') \
         WHERE identity_id = $1 AND certificate_fingerprint <> $2 \
         AND state = 'active' AND revoked_at IS NULL AND expires_at > NOW()",
    )
    .bind(identity)
    .bind(fingerprint)
    .execute(&mut *transaction)
    .await
    .map_err(internal)?;
    sqlx::query(
        "UPDATE identity_certificates \
         SET state = 'active', activation_expires_at = NULL, retire_at = NULL \
         WHERE identity_id = $1 AND certificate_fingerprint = $2",
    )
    .bind(identity)
    .bind(fingerprint)
    .execute(&mut *transaction)
    .await
    .map_err(internal)?;
    sqlx::query(
        "UPDATE identities SET activated_at = COALESCE(activated_at, NOW()), \
         activation_expires_at = NULL, certificate_serial = $3, certificate_fingerprint = $2, \
         updated_at = NOW() WHERE id = $1",
    )
    .bind(identity)
    .bind(fingerprint)
    .bind(&row.4)
    .execute(&mut *transaction)
    .await
    .map_err(internal)?;
    append_audit(
        &mut transaction,
        Some(identity),
        expected_role,
        "identity.activate",
        Some(identity),
        "succeeded",
        serde_json::json!({"certificate_fingerprint": fingerprint}),
    )
    .await?;
    transaction.commit().await.map_err(internal)?;
    Ok(())
}

async fn replace_client_identity(
    pool: &PgPool,
    current_identity: Uuid,
    replacement_identity: Uuid,
    reason: &str,
) -> Result<(), Status> {
    if current_identity == replacement_identity {
        return Err(Status::invalid_argument("replacement identity must be different"));
    }
    let mut transaction = pool.begin().await.map_err(internal)?;
    let replacement_is_active: bool = sqlx::query_scalar(
        "SELECT EXISTS (SELECT 1 FROM identities \
         WHERE id = $1 AND role = 'client' AND activated_at IS NOT NULL AND revoked_at IS NULL)",
    )
    .bind(replacement_identity)
    .fetch_one(&mut *transaction)
    .await
    .map_err(internal)?;
    if !replacement_is_active {
        return Err(Status::failed_precondition(
            "replacement client identity is not active",
        ));
    }
    let affected = sqlx::query(
        "UPDATE identities SET revoked_at = NOW(), revoked_reason = $2, updated_at = NOW() \
         WHERE id = $1 AND role = 'client' AND revoked_at IS NULL",
    )
    .bind(current_identity)
    .bind(reason)
    .execute(&mut *transaction)
    .await
    .map_err(internal)?
    .rows_affected();
    if affected != 1 {
        return Err(Status::aborted("current client identity changed before replacement"));
    }
    sqlx::query(
        "UPDATE identity_certificates SET revoked_at = NOW() \
         WHERE identity_id = $1 AND revoked_at IS NULL",
    )
    .bind(current_identity)
    .execute(&mut *transaction)
    .await
    .map_err(internal)?;
    append_audit(
        &mut transaction,
        Some(current_identity),
        "client",
        "identity.replace",
        Some(replacement_identity),
        "succeeded",
        serde_json::json!({"reason": reason}),
    )
    .await?;
    transaction.commit().await.map_err(internal)?;
    Ok(())
}

async fn authenticate<T>(
    pool: &PgPool,
    request: &Request<T>,
    expected_role: &str,
) -> Result<Uuid, Status> {
    let fingerprint = peer_certificate_fingerprint(request)?;
    let identity: Uuid = sqlx::query_scalar(
        "SELECT identities.id FROM identity_certificates \
         JOIN identities ON identities.id = identity_certificates.identity_id \
         WHERE identity_certificates.certificate_fingerprint = $1 \
         AND identity_certificates.state = 'active' \
         AND identity_certificates.revoked_at IS NULL \
         AND identity_certificates.expires_at > NOW() \
         AND (identity_certificates.retire_at IS NULL OR identity_certificates.retire_at > NOW()) \
         AND identities.role = $2 AND identities.activated_at IS NOT NULL \
         AND identities.revoked_at IS NULL",
    )
    .bind(&fingerprint)
    .bind(expected_role)
    .fetch_optional(pool)
    .await
    .map_err(internal)?
    .ok_or_else(|| Status::unauthenticated("unknown or inactive identity"))?;
    Ok(identity)
}

async fn authorize_existing_identity(
    pool: &PgPool,
    identity: Uuid,
    fingerprint: &str,
    expected_role: &str,
) -> Result<(), Status> {
    let authorized: bool = sqlx::query_scalar(
        "SELECT EXISTS (SELECT 1 FROM identity_certificates c \
         JOIN identities i ON i.id = c.identity_id \
         WHERE i.id = $1 AND c.certificate_fingerprint = $2 \
         AND c.state = 'active' AND c.revoked_at IS NULL AND c.expires_at > NOW() \
         AND (c.retire_at IS NULL OR c.retire_at > NOW()) \
         AND i.role = $3 AND i.activated_at IS NOT NULL AND i.revoked_at IS NULL)",
    )
    .bind(identity)
    .bind(fingerprint)
    .bind(expected_role)
    .fetch_one(pool)
    .await
    .map_err(internal)?;
    if !authorized {
        return Err(Status::permission_denied("identity was revoked or expired"));
    }
    Ok(())
}

async fn handle_client_hello(
    state: &RuntimeState,
    identity: Uuid,
    hello: centrald_protocol::v1::ClientHello,
) -> Result<(), Status> {
    if parse_uuid(&hello.identity_id, "identity_id")? != identity {
        return Err(Status::permission_denied(
            "hello identity does not match certificate",
        ));
    }
    validate_protocol(hello.protocol.as_ref())?;
    validate_hello_text(&hello.hostname, MAX_HELLO_HOSTNAME_BYTES, "hostname")?;
    validate_hello_text(&hello.os_version, MAX_HELLO_TEXT_BYTES, "os_version")?;
    validate_hello_text(&hello.client_version, MAX_HELLO_TEXT_BYTES, "client_version")?;
    validate_hello_text(&hello.boot_id, MAX_HELLO_TEXT_BYTES, "boot_id")?;
    if !matches!(hello.os.as_str(), "linux" | "windows") {
        return Err(Status::invalid_argument("unsupported client OS"));
    }
    if !matches!(hello.architecture.as_str(), "x86_64" | "aarch64") {
        return Err(Status::invalid_argument("unsupported client architecture"));
    }
    if hello.capabilities.len() > MAX_HELLO_CAPABILITIES {
        return Err(Status::resource_exhausted("too many client capabilities"));
    }
    let mut capabilities = std::collections::BTreeSet::new();
    for capability in hello.capabilities {
        validate_hello_text(
            &capability,
            MAX_HELLO_CAPABILITY_BYTES,
            "capability",
        )?;
        if !capabilities.insert(capability) {
            return Err(Status::invalid_argument("duplicate client capability"));
        }
    }
    let capabilities: Vec<String> = capabilities.into_iter().collect();
    sqlx::query(
        "UPDATE clients SET hostname = $2, os = $3, os_version = $4, architecture = $5, \
         client_version = $6, protocol_major = $7, protocol_minor = $8, \
         capabilities = $9, boot_id = $10, last_seen = NOW() WHERE identity_id = $1",
    )
    .bind(identity)
    .bind(hello.hostname)
    .bind(hello.os)
    .bind(hello.os_version)
    .bind(hello.architecture)
    .bind(hello.client_version)
    .bind(i32::try_from(centrald_protocol::PROTOCOL_MAJOR).unwrap_or(i32::MAX))
    .bind(i32::try_from(centrald_protocol::PROTOCOL_MINOR).unwrap_or(i32::MAX))
    .bind(serde_json::json!(capabilities))
    .bind(hello.boot_id)
    .execute(&state.pool)
    .await
    .map_err(internal)?;
    Ok(())
}

fn validate_hello_text(value: &str, maximum: usize, field: &str) -> Result<(), Status> {
    if value.is_empty()
        || value.len() > maximum
        || value.chars().any(char::is_control)
    {
        return Err(Status::invalid_argument(format!("{field} is invalid")));
    }
    Ok(())
}

async fn handle_client_frame(
    state: &RuntimeState,
    identity: Uuid,
    frame: ClientFrame,
    sender: &mpsc::Sender<Result<ServerFrame, Status>>,
) -> Result<(), Status> {
    use centrald_protocol::v1::client_frame::Payload;
    match frame.payload {
        Some(Payload::Heartbeat(_)) => {
            sqlx::query("UPDATE clients SET last_seen = NOW() WHERE identity_id = $1")
                .bind(identity)
                .execute(&state.pool)
                .await
                .map_err(internal)?;
            sender
                .send(Ok(ServerFrame {
                    payload: Some(centrald_protocol::v1::server_frame::Payload::HeartbeatAck(
                        HeartbeatAck {
                            server_time: Some(chrono_timestamp(Utc::now())),
                            next_interval_seconds: state.config.runtime.heartbeat_interval_seconds,
                        },
                    )),
                }))
                .await
                .map_err(|_| Status::cancelled("control stream closed"))?;
            if let Some((job, signed_grant)) = claim_next_job(state, identity).await? {
                sender
                    .send(Ok(ServerFrame {
                        payload: Some(centrald_protocol::v1::server_frame::Payload::SignedGrant(
                            signed_grant,
                        )),
                    }))
                    .await
                    .map_err(|_| Status::cancelled("control stream closed"))?;
                sender
                    .send(Ok(ServerFrame {
                        payload: Some(centrald_protocol::v1::server_frame::Payload::Job(job)),
                    }))
                    .await
                    .map_err(|_| Status::cancelled("control stream closed"))?;
            }
        }
        Some(Payload::JobDeliveryAck(ack)) => acknowledge_job_delivery(&state.pool, identity, ack).await?,
        Some(Payload::JobEvent(event)) => persist_job_event(&state.pool, identity, event).await?,
        Some(Payload::Shell(_)) => {
            return Err(Status::failed_precondition(
                "shell frame received without an active session",
            ));
        }
        Some(Payload::Hello(_)) => {
            return Err(Status::failed_precondition("client Hello may be sent only once"));
        }
        None => return Err(Status::invalid_argument("empty client frame")),
    }
    Ok(())
}

async fn claim_next_job(
    state: &RuntimeState,
    identity: Uuid,
) -> Result<Option<(Job, Vec<u8>)>, Status> {
    let supports_typed_jobs: bool = sqlx::query_scalar(
        "SELECT COALESCE(capabilities ? 'typed_jobs', FALSE) FROM clients WHERE identity_id = $1",
    )
    .bind(identity)
    .fetch_optional(&state.pool)
    .await
    .map_err(internal)?
    .unwrap_or(false);
    if !supports_typed_jobs {
        return Ok(None);
    }
    let mut transaction = state.pool.begin().await.map_err(internal)?;
    let row = sqlx::query_as::<_, (Uuid, String, serde_json::Value, Uuid, DateTime<Utc>, Uuid)>(
        "SELECT id, kind, parameters, idempotency_key, expires_at, actor_id FROM jobs \
         WHERE target_id = $1 AND state = 'queued' AND expires_at > NOW() \
         ORDER BY created_at FOR UPDATE SKIP LOCKED LIMIT 1",
    )
    .bind(identity)
    .fetch_optional(&mut *transaction)
    .await
    .map_err(internal)?;
    let Some((id, kind, parameters, idempotency_key, expires_at, actor_id)) = row else {
        transaction.commit().await.map_err(internal)?;
        return Ok(None);
    };
    let delivery_id = Uuid::now_v7();
    let delivery_lease_expires_at =
        Utc::now() + chrono::Duration::seconds(JOB_DELIVERY_LEASE_SECONDS);
    sqlx::query(
        "UPDATE jobs SET state = 'dispatched', delivery_id = $2, \
         delivery_lease_expires_at = $3, updated_at = NOW() WHERE id = $1",
    )
    .bind(id)
    .bind(delivery_id)
    .bind(delivery_lease_expires_at)
    .execute(&mut *transaction)
    .await
    .map_err(internal)?;
    sqlx::query(
        "INSERT INTO job_events (job_id, sequence, state) VALUES ($1, 0, 'dispatched') \
         ON CONFLICT DO NOTHING",
    )
    .bind(id)
    .execute(&mut *transaction)
    .await
    .map_err(internal)?;
    transaction.commit().await.map_err(internal)?;
    let parameters_bytes = serde_json::to_vec(&parameters).map_err(internal)?;
    let job = Job {
        id: id.to_string(),
        target_id: identity.to_string(),
        kind: job_kind_from_name(&kind) as i32,
        state: JobState::Dispatched as i32,
        parameters_json: parameters_bytes.clone(),
        idempotency_key: idempotency_key.to_string(),
        expires_at: Some(chrono_timestamp(expires_at)),
        delivery_id: delivery_id.to_string(),
    };
    let now = Utc::now();
    let grant = PrivilegedGrant {
        id: Uuid::now_v7(),
        device_id: identity,
        job_or_session_id: id,
        admin_id: actor_id,
        operation: grant_operation(&kind)?,
        parameters_sha256: hex::encode(sha256(&parameters_bytes)),
        issued_at: now - chrono::Duration::seconds(5),
        expires_at: now + chrono::Duration::seconds(JOB_DELIVERY_LEASE_SECONDS),
        nonce: delivery_id.to_string(),
    }
    .sign(&state.grant_signing_key)
    .map_err(internal)?;
    let signed_grant = serde_json::to_vec(&grant).map_err(internal)?;
    Ok(Some((job, signed_grant)))
}

async fn acknowledge_job_delivery(
    pool: &PgPool,
    identity: Uuid,
    acknowledgement: JobDeliveryAck,
) -> Result<(), Status> {
    let job_id = parse_uuid(&acknowledgement.job_id, "job_id")?;
    let delivery_id = parse_uuid(&acknowledgement.delivery_id, "delivery_id")?;
    let mut transaction = pool.begin().await.map_err(internal)?;
    let row = sqlx::query_as::<_, (Uuid, String, Option<Uuid>, Option<DateTime<Utc>>, DateTime<Utc>)>(
        "SELECT target_id, state, delivery_id, delivery_lease_expires_at, expires_at \
         FROM jobs WHERE id = $1 FOR UPDATE",
    )
    .bind(job_id)
    .fetch_optional(&mut *transaction)
    .await
    .map_err(internal)?
    .ok_or_else(|| Status::not_found("job does not exist"))?;
    if row.0 != identity {
        return Err(Status::permission_denied("job does not belong to client"));
    }
    if row.1 != "dispatched"
        || row.2 != Some(delivery_id)
        || row.3.is_none_or(|deadline| deadline <= Utc::now())
        || row.4 <= Utc::now()
    {
        return Err(Status::failed_precondition("job delivery lease is not active"));
    }
    let execution_start_expires_at =
        Utc::now() + chrono::Duration::seconds(JOB_EXECUTION_START_LEASE_SECONDS);
    sqlx::query(
        "UPDATE jobs SET state = 'acknowledged', delivery_id = NULL, \
         delivery_lease_expires_at = NULL, execution_start_expires_at = $2, \
         updated_at = NOW() WHERE id = $1",
    )
    .bind(job_id)
    .bind(execution_start_expires_at)
    .execute(&mut *transaction)
    .await
    .map_err(internal)?;
    transaction.commit().await.map_err(internal)?;
    Ok(())
}

async fn persist_job_event(pool: &PgPool, identity: Uuid, event: JobEvent) -> Result<(), Status> {
    let job_id = parse_uuid(&event.job_id, "job_id")?;
    let sequence = i64::try_from(event.sequence)
        .map_err(|_| Status::invalid_argument("sequence too large"))?;
    if event.output.len() > MAX_JOB_EVENT_OUTPUT_BYTES {
        return Err(Status::resource_exhausted(
            "job event output exceeds the per-event limit",
        ));
    }
    let next_state = JobState::try_from(event.state)
        .map_err(|_| Status::invalid_argument("invalid job state"))?;
    let state = job_state_name(next_state)?;
    validate_job_event_shape(next_state, event.terminal, event.exit_code)?;

    let mut transaction = pool.begin().await.map_err(internal)?;
    let row = sqlx::query_as::<_, (Uuid, String, DateTime<Utc>, Option<DateTime<Utc>>)>(
        "SELECT target_id, state, expires_at, execution_start_expires_at \
         FROM jobs WHERE id = $1 FOR UPDATE",
    )
    .bind(job_id)
    .fetch_optional(&mut *transaction)
    .await
    .map_err(internal)?;
    let Some((target, current_state_name, expires_at, execution_start_expires_at)) = row else {
        return Err(Status::not_found("job does not exist"));
    };
    if target != identity {
        return Err(Status::permission_denied("job does not belong to client"));
    }
    if expires_at <= Utc::now() {
        return Err(Status::failed_precondition("job has expired"));
    }
    let current_state = job_state_from_name(&current_state_name);
    if current_state == JobState::Acknowledged
        && execution_start_expires_at.is_none_or(|deadline| deadline <= Utc::now())
    {
        return Err(Status::failed_precondition(
            "job execution-start lease expired before the first event",
        ));
    }
    validate_job_transition(current_state, next_state)?;

    let (last_sequence, retained_bytes, event_count, terminal_seen) =
        sqlx::query_as::<_, (Option<i64>, i64, i64, bool)>(
            "SELECT MAX(sequence), \
                    COALESCE(SUM(octet_length(output)), 0)::BIGINT, \
                    COUNT(*)::BIGINT, \
                    COALESCE(bool_or(terminal), FALSE) \
             FROM job_events WHERE job_id = $1",
        )
        .bind(job_id)
        .fetch_one(&mut *transaction)
        .await
        .map_err(internal)?;
    if terminal_seen || is_terminal_job_state(current_state) {
        return Err(Status::failed_precondition("job is already terminal"));
    }
    let expected_sequence = last_sequence.unwrap_or(-1) + 1;
    if sequence != expected_sequence {
        return Err(Status::failed_precondition(format!(
            "job event sequence must be {expected_sequence}"
        )));
    }
    if event_count >= MAX_JOB_EVENTS {
        return Err(Status::resource_exhausted("job event count limit reached"));
    }
    let output_length = i64::try_from(event.output.len())
        .map_err(|_| Status::resource_exhausted("job output is too large"))?;
    if retained_bytes.saturating_add(output_length) > MAX_JOB_RETAINED_OUTPUT_BYTES {
        return Err(Status::resource_exhausted(
            "job retained output limit reached",
        ));
    }

    let inserted = sqlx::query(
        "INSERT INTO job_events \
         (job_id, sequence, state, output, stderr, exit_code, terminal) \
         VALUES ($1, $2, $3, $4, $5, $6, $7)",
    )
    .bind(job_id)
    .bind(sequence)
    .bind(state)
    .bind(event.output)
    .bind(event.stderr)
    .bind(event.exit_code)
    .bind(event.terminal)
    .execute(&mut *transaction)
    .await
    .map_err(internal)?;
    if inserted.rows_affected() != 1 {
        return Err(Status::aborted("job event was not inserted"));
    }
    sqlx::query(
        "UPDATE jobs SET state = $2, execution_start_expires_at = NULL, \
         updated_at = NOW() WHERE id = $1",
    )
        .bind(job_id)
        .bind(state)
        .execute(&mut *transaction)
        .await
        .map_err(internal)?;
    transaction.commit().await.map_err(internal)?;
    Ok(())
}

fn validate_job_event_shape(
    state: JobState,
    terminal: bool,
    exit_code: i32,
) -> Result<(), Status> {
    let terminal_state = is_terminal_job_state(state);
    if terminal != terminal_state {
        return Err(Status::invalid_argument(
            "terminal flag must exactly match a terminal job state",
        ));
    }
    if terminal_state {
        if state == JobState::Succeeded && exit_code != 0 {
            return Err(Status::invalid_argument(
                "a succeeded job must report exit code zero",
            ));
        }
    } else if exit_code != 0 {
        return Err(Status::invalid_argument(
            "non-terminal job events must not report an exit code",
        ));
    }
    Ok(())
}

fn validate_job_transition(current: JobState, next: JobState) -> Result<(), Status> {
    let allowed = matches!(
        (current, next),
        (JobState::Acknowledged, JobState::Running)
            | (JobState::Acknowledged, JobState::Succeeded)
            | (JobState::Acknowledged, JobState::Failed)
            | (JobState::Running, JobState::Running)
            | (JobState::Running, JobState::Succeeded)
            | (JobState::Running, JobState::Failed)
    );
    if !allowed {
        return Err(Status::failed_precondition(format!(
            "invalid job state transition from {} to {}",
            job_state_name(current).unwrap_or("unknown"),
            job_state_name(next).unwrap_or("unknown")
        )));
    }
    Ok(())
}

fn is_terminal_job_state(state: JobState) -> bool {
    matches!(
        state,
        JobState::Succeeded | JobState::Failed | JobState::Canceled | JobState::TimedOut
    )
}

async fn audit(
    pool: &PgPool,
    actor_id: Option<Uuid>,
    actor_label: &str,
    action: &str,
    target_id: Option<Uuid>,
    outcome: &str,
    metadata: serde_json::Value,
) -> Result<(), Status> {
    let mut transaction = pool.begin().await.map_err(internal)?;
    append_audit(
        &mut transaction,
        actor_id,
        actor_label,
        action,
        target_id,
        outcome,
        metadata,
    )
    .await?;
    transaction.commit().await.map_err(internal)?;
    Ok(())
}

async fn append_audit(
    transaction: &mut Transaction<'_, Postgres>,
    actor_id: Option<Uuid>,
    actor_label: &str,
    action: &str,
    target_id: Option<Uuid>,
    outcome: &str,
    metadata: serde_json::Value,
) -> Result<(), Status> {
    let id = Uuid::now_v7();
    let created_at = Utc::now();
    // Serialize all audit appends behind a transaction-scoped advisory lock so
    // concurrent RPCs cannot fork the hash chain.
    sqlx::query("SELECT pg_advisory_xact_lock(1129601348)")
        .execute(&mut **transaction)
        .await
        .map_err(internal)?;
    let previous_hash: Option<Vec<u8>> = sqlx::query_scalar(
        "SELECT entry_hash FROM audit_entries ORDER BY sequence DESC LIMIT 1",
    )
    .fetch_optional(&mut **transaction)
    .await
    .map_err(internal)?;
    let canonical = serde_json::to_vec(&serde_json::json!({
        "id": id,
        "actorId": actor_id,
        "actorLabel": actor_label,
        "action": action,
        "targetId": target_id,
        "outcome": outcome,
        "metadata": &metadata,
        "previousHash": previous_hash.as_ref().map(hex::encode),
        "createdAt": created_at,
    }))
    .map_err(|_| Status::internal("audit serialization failed"))?;
    let hash = sha256(&canonical);
    sqlx::query(
        "INSERT INTO audit_entries \
         (id, actor_id, actor_label, action, target_id, outcome, metadata, \
          previous_hash, entry_hash, created_at) \
         VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10)",
    )
    .bind(id)
    .bind(actor_id)
    .bind(actor_label)
    .bind(action)
    .bind(target_id)
    .bind(outcome)
    .bind(metadata)
    .bind(previous_hash)
    .bind(hash)
    .bind(created_at)
    .execute(&mut **transaction)
    .await
    .map_err(internal)?;
    Ok(())
}

fn validate_protocol(
    protocol: Option<&centrald_protocol::v1::ProtocolVersion>,
) -> Result<(), Status> {
    let protocol = protocol.ok_or_else(|| Status::invalid_argument("protocol version required"))?;
    if protocol.major != centrald_protocol::PROTOCOL_MAJOR {
        return Err(Status::failed_precondition("incompatible protocol major"));
    }
    Ok(())
}

fn validate_client_claims(request: &EnrollClientRequest) -> Result<(), Status> {
    validate_name(&request.hostname, 253)?;
    if !matches!(request.os.as_str(), "linux" | "windows") {
        return Err(Status::invalid_argument("unsupported client OS"));
    }
    if !matches!(request.architecture.as_str(), "x86_64" | "aarch64") {
        return Err(Status::invalid_argument("unsupported client architecture"));
    }
    Ok(())
}

fn validate_name(value: &str, max: usize) -> Result<(), Status> {
    let value = value.trim();
    if value.is_empty() || value.len() > max || value.chars().any(char::is_control) {
        return Err(Status::invalid_argument("name is empty or invalid"));
    }
    Ok(())
}

fn decode_csr(bytes: &[u8]) -> Result<&str, Status> {
    if bytes.is_empty() || bytes.len() > MAX_CSR_BYTES {
        return Err(Status::invalid_argument(
            "certificate request size is invalid",
        ));
    }
    std::str::from_utf8(bytes)
        .map_err(|_| Status::invalid_argument("certificate request is not UTF-8 PEM"))
}

fn endpoint(host: &str, port: u16) -> String {
    if host.contains(':') && !host.starts_with('[') {
        format!("https://[{host}]:{port}")
    } else {
        format!("https://{host}:{port}")
    }
}

fn role_name(role: IdentityRole) -> Result<&'static str, Status> {
    match role {
        IdentityRole::Client => Ok("client"),
        IdentityRole::Admin => Ok("admin"),
        IdentityRole::Unspecified => Err(Status::invalid_argument(
            "identity role must be client or admin",
        )),
    }
}

fn job_kind_name(kind: JobKind) -> Result<&'static str, Status> {
    match kind {
        JobKind::RestartClientService => Ok("restart_client_service"),
        JobKind::RestartMachine => Ok("restart_machine"),
        JobKind::CheckOsUpdates => Ok("check_os_updates"),
        JobKind::ApplyOsUpdates => Ok("apply_os_updates"),
        JobKind::UpdateClient => Ok("update_client"),
        JobKind::Unspecified => Err(Status::invalid_argument("job kind is unsupported")),
    }
}

fn job_kind_from_name(kind: &str) -> JobKind {
    match kind {
        "restart_client_service" => JobKind::RestartClientService,
        "restart_machine" => JobKind::RestartMachine,
        "check_os_updates" => JobKind::CheckOsUpdates,
        "apply_os_updates" => JobKind::ApplyOsUpdates,
        "update_client" => JobKind::UpdateClient,
        _ => JobKind::Unspecified,
    }
}

fn grant_operation(kind: &str) -> Result<GrantOperation, Status> {
    match kind {
        "restart_client_service" => Ok(GrantOperation::RestartClientService),
        "restart_machine" => Ok(GrantOperation::RestartMachine),
        "check_os_updates" => Ok(GrantOperation::CheckOsUpdates),
        "apply_os_updates" => Ok(GrantOperation::ApplyOsUpdates),
        "update_client" => Ok(GrantOperation::UpdateClient),
        _ => Err(Status::invalid_argument("job cannot be authorized")),
    }
}

fn job_state_name(state: JobState) -> Result<&'static str, Status> {
    match state {
        JobState::Queued => Ok("queued"),
        JobState::Dispatched => Ok("dispatched"),
        JobState::Acknowledged => Ok("acknowledged"),
        JobState::Running => Ok("running"),
        JobState::Succeeded => Ok("succeeded"),
        JobState::Failed => Ok("failed"),
        JobState::Canceled => Ok("canceled"),
        JobState::TimedOut => Ok("timed_out"),
        JobState::Unspecified => Err(Status::invalid_argument("job state is unsupported")),
    }
}

fn job_state_from_name(state: &str) -> JobState {
    match state {
        "queued" => JobState::Queued,
        "dispatched" => JobState::Dispatched,
        "acknowledged" => JobState::Acknowledged,
        "running" => JobState::Running,
        "succeeded" => JobState::Succeeded,
        "failed" => JobState::Failed,
        "canceled" => JobState::Canceled,
        "timed_out" => JobState::TimedOut,
        _ => JobState::Unspecified,
    }
}

fn parse_uuid(value: &str, field: &str) -> Result<Uuid, Status> {
    value
        .parse()
        .map_err(|_| Status::invalid_argument(format!("{field} is not a UUID")))
}

fn chrono_timestamp(value: DateTime<Utc>) -> prost_types::Timestamp {
    prost_types::Timestamp {
        seconds: value.timestamp(),
        nanos: i32::try_from(value.timestamp_subsec_nanos()).unwrap_or_default(),
    }
}

fn offset_timestamp(value: time::OffsetDateTime) -> prost_types::Timestamp {
    prost_types::Timestamp {
        seconds: value.unix_timestamp(),
        nanos: i32::try_from(value.nanosecond()).unwrap_or_default(),
    }
}

async fn acquire_config_lock_nonblocking(
    config_path: &std::path::Path,
) -> Result<ConfigFileLock, Status> {
    let path = config_path.to_path_buf();
    tokio::task::spawn_blocking(move || ConfigFileLock::try_acquire(&path))
        .await
        .map_err(|_| Status::internal("configuration lock worker failed"))?
        .map_err(internal)?
        .ok_or_else(|| Status::unavailable("configuration is busy; retry shortly"))
}

async fn hash_enrollment_key_bounded(
    state: &RuntimeState,
    key: SecretString,
) -> Result<(SecretString, String), Status> {
    let _permit = state
        .enrollment_crypto_limit
        .clone()
        .try_acquire_owned()
        .map_err(|_| Status::resource_exhausted("enrollment cryptography is busy; retry shortly"))?;
    let (key, result) = tokio::task::spawn_blocking(move || {
        let result = hash_enrollment_key(&key);
        (key, result)
    })
    .await
    .map_err(|_| Status::internal("enrollment hashing worker failed"))?;
    let hash = result.map_err(invalid_key)?;
    Ok((key, hash))
}

async fn verify_enrollment_key_bounded(
    state: &RuntimeState,
    key: SecretString,
    encoded_hash: String,
) -> Result<bool, Status> {
    let _permit = state
        .enrollment_crypto_limit
        .clone()
        .try_acquire_owned()
        .map_err(|_| Status::resource_exhausted("enrollment cryptography is busy; retry shortly"))?;
    tokio::task::spawn_blocking(move || verify_enrollment_key(&key, &encoded_hash))
        .await
        .map_err(|_| Status::internal("enrollment verification worker failed"))?
        .map_err(invalid_key)
}

fn invalid_key(error: impl std::fmt::Display) -> Status {
    warn!(%error, "invalid enrollment key material");
    Status::unauthenticated("invalid enrollment key")
}

fn internal(error: impl std::fmt::Display) -> Status {
    error!(%error, "internal RPC failure");
    Status::internal("internal server error")
}

fn sha256(bytes: &[u8]) -> Vec<u8> {
    use sha2::{Digest, Sha256};
    Sha256::digest(bytes).to_vec()
}
