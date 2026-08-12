use std::collections::HashMap;
use std::time::Duration;

use anyhow::{Context, Result, bail};
use centrald_common::config::ClientConfig;
use centrald_common::grant::{GrantOperation, SignedGrant};
use centrald_common::secure_fs::write_new_file;
use centrald_protocol::v1::client_frame;
use centrald_protocol::v1::client_service_client::ClientServiceClient;
use centrald_protocol::v1::server_frame;
use centrald_protocol::v1::{
    ActivateIdentityRequest, ClientFrame, ClientHello, Heartbeat, Job, JobDeliveryAck,
    JobEvent, JobState, ProtocolVersion, RenewCertificateRequest, ReplaceIdentityRequest,
};
use chrono::{Duration as ChronoDuration, Utc};
use ed25519_dalek::VerifyingKey;
use ed25519_dalek::pkcs8::DecodePublicKey;
use rcgen::{
    CertificateParams, DistinguishedName, DnType, ExtendedKeyUsagePurpose, KeyPair,
    KeyUsagePurpose,
};
use sha2::{Digest, Sha256};
use tokio::sync::{mpsc, watch};
use tokio_stream::wrappers::ReceiverStream;
use tonic::transport::{Certificate, Channel, ClientTlsConfig, Endpoint, Identity};
use tracing::{info, warn};
use uuid::Uuid;

use crate::state_lock::ClientStateLock;

/// Validates the active configuration and credential files before a service
/// manager is told that the daemon is running.
pub fn validate_startup_state() -> Result<()> {
    let _state_lock = ClientStateLock::acquire()
        .context("wait for CentralD client state publication to finish")?;
    let (_path, config) = crate::enrollment::load_latest_config()?;
    config.validate()?;
    for path in [
        &config.identity_cert,
        &config.identity_key,
        &config.root_ca,
        &config.grant_signing_public_key,
    ] {
        let metadata = path
            .symlink_metadata()
            .with_context(|| format!("inspect client credential {}", path.display()))?;
        if metadata.file_type().is_symlink() || !metadata.is_file() {
            bail!("client credential is not a regular file: {}", path.display());
        }
        if std::fs::metadata(path)?.len() == 0 {
            bail!("client credential is empty: {}", path.display());
        }
    }
    Ok(())
}

/// Runs the outbound-only managed client control loop with bounded reconnect
/// backoff.
///
/// # Errors
///
/// Returns only when no enrolled configuration can be loaded. Connection and
/// stream failures are retried indefinitely with bounded backoff.
pub async fn run() -> Result<()> {
    let (_shutdown_sender, shutdown_receiver) = watch::channel(false);
    run_with_shutdown(shutdown_receiver).await
}

/// Runs the client daemon until the supplied shutdown signal becomes true.
/// This is used by both foreground diagnostics and the Windows SCM host.
///
/// # Errors
///
/// Returns when the active identity is unusable or configuration cannot be
/// loaded. Transient network failures continue to use bounded reconnects.
pub async fn run_with_shutdown(mut shutdown: watch::Receiver<bool>) -> Result<()> {
    let mut backoff = Duration::from_secs(1);
    loop {
        if *shutdown.borrow() {
            return Ok(());
        }
        let Some(state_lock) = ClientStateLock::try_acquire()? else {
            tokio::select! {
                () = tokio::time::sleep(Duration::from_millis(250)) => {}
                changed = shutdown.changed() => {
                    if changed.is_ok() && *shutdown.borrow() {
                        return Ok(());
                    }
                }
            }
            continue;
        };
        let (config_path, config) = crate::enrollment::load_latest_config()?;
        info!(
            path = %config_path.display(),
            identity = %config.identity_id,
            expires_at = %config.certificate_expires_at,
            "loaded client identity"
        );
        if let Err(error) = finalize_active_publication(&config).await {
            warn!(%error, "active client credential publication is incomplete; retrying");
            tokio::select! {
                () = tokio::time::sleep(backoff) => {}
                changed = shutdown.changed() => {
                    if changed.is_ok() && *shutdown.borrow() {
                        return Ok(());
                    }
                }
            }
            backoff = (backoff * 2).min(Duration::from_secs(60));
            continue;
        }
        match renew_certificate_if_needed(&config).await {
            Ok(true) => {
                info!(identity = %config.identity_id, "client certificate renewed; loading the new generation");
                backoff = Duration::from_secs(1);
                continue;
            }
            Ok(false) => {}
            Err(error) if config.certificate_expires_at > Utc::now() => {
                warn!(%error, "certificate renewal is due but failed; continuing with the current certificate");
            }
            Err(error) => {
                return Err(error.context(
                    "client certificate is expired and renewal failed; run centrald-client reenroll",
                ));
            }
        }
        // Credential and pointer mutation is complete. The long-lived network
        // stream must not prevent a local reenrollment or repair operation.
        drop(state_lock);
        let mut healthy_stream = false;
        match connect_once(&config, &mut shutdown, &mut healthy_stream).await {
            Ok(()) if *shutdown.borrow() => return Ok(()),
            Ok(()) => warn!("control stream ended; reconnecting"),
            Err(error) => warn!(%error, "control stream failed; reconnecting"),
        }
        if healthy_stream {
            backoff = Duration::from_secs(1);
        }
        tokio::select! {
            () = tokio::time::sleep(backoff) => {}
            changed = shutdown.changed() => {
                if changed.is_ok() && *shutdown.borrow() {
                    return Ok(());
                }
            }
        }
        if !healthy_stream {
            backoff = (backoff * 2).min(Duration::from_secs(60));
        }
    }
}

async fn finalize_active_publication(config: &ClientConfig) -> Result<()> {
    if let Err(error) = ensure_identity_active(config).await {
        if crate::enrollment::rollback_active_config_if_previous(&config.data_dir)? {
            return Err(error.context(
                "activate the persisted client identity; restored the previous active credential",
            ));
        }
        return Err(error.context("activate the persisted client identity"));
    }
    if let Some((_path, previous)) = crate::enrollment::previous_active_config(&config.data_dir)? {
        if previous.identity_id != config.identity_id {
            replace_previous_identity(&previous, config.identity_id)
                .await
                .context("complete authenticated reenrollment replacement")?;
        }
    }
    crate::enrollment::commit_active_config(&config.data_dir)
        .context("finalize recovered client credential pointer")
}

async fn connect_once(
    config: &ClientConfig,
    shutdown: &mut watch::Receiver<bool>,
    healthy_stream: &mut bool,
) -> Result<()> {
    let channel = client_channel(config).await?;
    let mut client = ClientServiceClient::new(channel);
    let (sender, receiver) = mpsc::channel(64);
    sender
        .send(ClientFrame {
            payload: Some(client_frame::Payload::Hello(client_hello(config))),
        })
        .await
        .context("queue client hello")?;
    let response = client
        .control_stream(ReceiverStream::new(receiver))
        .await
        .context("open mTLS control stream")?;
    let mut inbound = response.into_inner();
    let mut heartbeat_seconds = 30_u32;
    let mut interval = tokio::time::interval(Duration::from_secs(u64::from(heartbeat_seconds)));
    interval.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Delay);
    let grant_verification_pem = std::fs::read_to_string(&config.grant_signing_public_key)
        .with_context(|| format!("read {}", config.grant_signing_public_key.display()))?;
    let grant_verification_key = VerifyingKey::from_public_key_pem(&grant_verification_pem)
        .context("parse server grant verification key")?;
    let mut grants = HashMap::<Uuid, SignedGrant>::new();
    let renewal_delay = (config.certificate_expires_at
        - ChronoDuration::days(CERTIFICATE_RENEWAL_WINDOW_DAYS)
        - Utc::now())
    .to_std()
    .unwrap_or(Duration::ZERO);
    let renewal_deadline = tokio::time::sleep(renewal_delay);
    tokio::pin!(renewal_deadline);

    loop {
        tokio::select! {
            () = &mut renewal_deadline => {
                info!(identity = %config.identity_id, "certificate renewal window reached; reconnecting");
                return Ok(());
            }
            changed = shutdown.changed() => {
                if changed.is_ok() && *shutdown.borrow() {
                    return Ok(());
                }
            }
            _ = interval.tick() => {
                let (memory_total_bytes, memory_used_bytes) = memory_bytes();
                sender.send(ClientFrame {
                    payload: Some(client_frame::Payload::Heartbeat(Heartbeat {
                        sent_at: Some(now_timestamp()),
                        uptime_seconds: system_uptime_seconds(),
                        memory_total_bytes,
                        memory_used_bytes,
                    })),
                }).await.context("send heartbeat")?;
            }
            frame = inbound.message() => {
                let Some(frame) = frame.context("receive server frame")? else {
                    bail!("server closed control stream");
                };
                match frame.payload {
                    Some(server_frame::Payload::HeartbeatAck(ack)) => {
                        if !(5..=3600).contains(&ack.next_interval_seconds) {
                            bail!("server returned an invalid heartbeat interval");
                        }
                        *healthy_stream = true;
                        if ack.next_interval_seconds != heartbeat_seconds {
                            heartbeat_seconds = ack.next_interval_seconds;
                            interval.reset_after(Duration::from_secs(u64::from(heartbeat_seconds)));
                        }
                    }
                    Some(server_frame::Payload::SignedGrant(bytes)) => {
                        let grant: SignedGrant = serde_json::from_slice(&bytes)
                            .context("server sent malformed signed grant")?;
                        grant
                            .verify(&grant_verification_key, config.identity_id, Utc::now())
                            .context("server sent an invalid signed grant")?;
                        let now = Utc::now();
                        grants.retain(|_, existing| existing.grant.expires_at > now);
                        let id = grant.grant.job_or_session_id;
                        if !grants.contains_key(&id) && grants.len() >= MAX_PENDING_GRANTS {
                            bail!("server exceeded the bounded pending signed-grant set");
                        }
                        grants.insert(id, grant);
                    }
                    Some(server_frame::Payload::Job(job)) => {
                        handle_job(&sender, job, &mut grants).await?;
                    }
                    Some(server_frame::Payload::Shell(_)) => {
                        bail!("server sent shell data without a negotiated shell session");
                    }
                    None => bail!("server sent an empty control frame"),
                }
            }
        }
    }
}

const CERTIFICATE_RENEWAL_WINDOW_DAYS: i64 = 30;
const MAX_PENDING_GRANTS: usize = 128;

async fn renew_certificate_if_needed(config: &ClientConfig) -> Result<bool> {
    if config.certificate_expires_at
        > Utc::now() + ChronoDuration::days(CERTIFICATE_RENEWAL_WINDOW_DAYS)
    {
        return Ok(false);
    }

    let identity_key = KeyPair::generate().context("generate renewed client identity key")?;
    let mut parameters = CertificateParams::default();
    let mut distinguished_name = DistinguishedName::new();
    distinguished_name.push(DnType::CommonName, config.identity_name.clone());
    parameters.distinguished_name = distinguished_name;
    parameters.key_usages = vec![KeyUsagePurpose::DigitalSignature];
    parameters.extended_key_usages = vec![ExtendedKeyUsagePurpose::ClientAuth];
    let csr = parameters
        .serialize_request(&identity_key)
        .context("generate renewed certificate signing request")?
        .pem()
        .context("encode renewed certificate signing request")?;

    let channel = client_channel(config).await?;
    let response = ClientServiceClient::new(channel)
        .renew_certificate(RenewCertificateRequest {
            csr_pem: csr.into_bytes(),
            protocol: Some(ProtocolVersion {
                major: centrald_protocol::PROTOCOL_MAJOR,
                minor: centrald_protocol::PROTOCOL_MINOR,
            }),
        })
        .await
        .context("request client certificate renewal")?
        .into_inner();
    if response.certificate_chain_pem.is_empty() {
        bail!("server returned an empty renewed certificate chain");
    }
    let expires_at = crate::enrollment::timestamp_to_datetime(response.expires_at)
        .context("server returned an invalid renewed certificate expiration")?;
    if expires_at <= Utc::now() + ChronoDuration::days(1) {
        bail!("server returned a renewed certificate with an unsafe expiration");
    }

    let generation_id = Uuid::now_v7();
    let identity_dir = config
        .data_dir
        .join("identities")
        .join(config.identity_id.to_string())
        .join("generations")
        .join(generation_id.to_string());
    let mut replacement = config.clone();
    replacement.identity_cert = identity_dir.join("identity-chain.pem");
    replacement.identity_key = identity_dir.join("identity-key.pem");
    replacement.root_ca = identity_dir.join("root-ca.pem");
    replacement.grant_signing_public_key = identity_dir.join("grant-signing-public.pem");
    replacement.certificate_expires_at = expires_at;
    let config_path = config
        .data_dir
        .join("configurations")
        .join(format!(
            "client-{}-{generation_id}.toml",
            config.identity_id
        ));
    replacement.validate()?;
    replacement.validate_storage_path(&config_path)?;
    let serialized = toml::to_string_pretty(&replacement)
        .context("serialize renewed client configuration")?;

    let root_ca = std::fs::read(&config.root_ca)
        .with_context(|| format!("read {}", config.root_ca.display()))?;
    let grant_signing_public_key = std::fs::read(&config.grant_signing_public_key)
        .with_context(|| format!("read {}", config.grant_signing_public_key.display()))?;

    let persistence = (|| {
        crate::enrollment::prepare_identity_generation(&replacement.data_dir, &identity_dir)?;
        write_new_file(
            &replacement.identity_cert,
            &response.certificate_chain_pem,
            false,
        )?;
        write_new_file(
            &replacement.identity_key,
            identity_key.serialize_pem().as_bytes(),
            true,
        )?;
        write_new_file(&replacement.root_ca, &root_ca, false)?;
        write_new_file(
            &replacement.grant_signing_public_key,
            &grant_signing_public_key,
            false,
        )?;
        crate::enrollment::secure_renewed_generation(
            &replacement.data_dir,
            &identity_dir,
        )?;
        write_new_file(&config_path, serialized.as_bytes(), true)?;
        crate::enrollment::secure_renewed_configuration(
            &replacement.data_dir,
            &config_path,
        )?;
        Ok::<(), anyhow::Error>(())
    })();
    if let Err(error) = persistence {
        crate::enrollment::cleanup_failed_generation(&identity_dir, &config_path);
        return Err(error.context("persist renewed client identity generation"));
    }
    let publication = match crate::enrollment::publish_active_config(
        &replacement.data_dir,
        &config_path,
    ) {
        Ok(publication) => publication,
        Err(error) => {
            crate::enrollment::cleanup_failed_generation(&identity_dir, &config_path);
            return Err(error.context("publish renewed client credential generation"));
        }
    };
    if let Err(error) = ensure_identity_active(&replacement).await {
        if let Err(rollback_error) = publication.rollback() {
            return Err(error.context(format!(
                "renewed certificate activation failed and pointer rollback also failed; the published generation was retained for recovery: {rollback_error}"
            )));
        }
        crate::enrollment::cleanup_failed_generation(&identity_dir, &config_path);
        return Err(error.context("activate renewed client certificate after durable publication"));
    }
    publication
        .commit()
        .context("finalize renewed client credential pointer")?;
    Ok(true)
}

async fn handle_job(
    sender: &mpsc::Sender<ClientFrame>,
    job: Job,
    grants: &mut HashMap<Uuid, SignedGrant>,
) -> Result<()> {
    let job_id: Uuid = job.id.parse().context("server sent an invalid job ID")?;
    if job.delivery_id.is_empty() {
        bail!("server sent a job without a delivery lease");
    }
    let grant = grants
        .remove(&job_id)
        .context("server did not provide a verified privileged-operation grant")?;
    let job_kind = centrald_protocol::v1::JobKind::try_from(job.kind)
        .context("server sent an invalid job kind")?;
    let expected_operation = match job_kind {
        centrald_protocol::v1::JobKind::RestartClientService => GrantOperation::RestartClientService,
        centrald_protocol::v1::JobKind::RestartMachine => GrantOperation::RestartMachine,
        centrald_protocol::v1::JobKind::CheckOsUpdates => GrantOperation::CheckOsUpdates,
        centrald_protocol::v1::JobKind::ApplyOsUpdates => GrantOperation::ApplyOsUpdates,
        centrald_protocol::v1::JobKind::UpdateClient => GrantOperation::UpdateClient,
        centrald_protocol::v1::JobKind::Unspecified => bail!("server sent an unspecified job kind"),
    };
    if grant.grant.job_or_session_id != job_id
        || grant.grant.operation != expected_operation
        || grant.grant.nonce != job.delivery_id
        || grant.grant.parameters_sha256 != hex::encode(Sha256::digest(&job.parameters_json))
    {
        bail!("signed grant does not match the delivered job");
    }
    sender
        .send(ClientFrame {
            payload: Some(client_frame::Payload::JobDeliveryAck(JobDeliveryAck {
                job_id: job.id.clone(),
                delivery_id: job.delivery_id.clone(),
            })),
        })
        .await
        .context("acknowledge verified job delivery")?;
    // Sequence zero is the server-created dispatch marker. Client-originated
    // execution events start at one so the first terminal broker-disabled
    // result satisfies the server's strictly increasing event contract.
    send_job_event(
        sender,
        &job.id,
        1,
        JobState::Failed,
        b"privileged broker handoff is not enabled in this build",
        true,
    )
    .await
}

async fn send_job_event(
    sender: &mpsc::Sender<ClientFrame>,
    job_id: &str,
    sequence: u64,
    state: JobState,
    output: &[u8],
    terminal: bool,
) -> Result<()> {
    sender
        .send(ClientFrame {
            payload: Some(client_frame::Payload::JobEvent(JobEvent {
                job_id: job_id.to_owned(),
                sequence,
                state: state as i32,
                output: output.to_vec(),
                stderr: state == JobState::Failed,
                exit_code: i32::from(terminal && state == JobState::Failed),
                terminal,
            })),
        })
        .await
        .context("send job event")
}

pub(crate) async fn client_channel(config: &ClientConfig) -> Result<Channel> {
    let certificate = std::fs::read(&config.identity_cert)
        .with_context(|| format!("read {}", config.identity_cert.display()))?;
    let private_key = std::fs::read(&config.identity_key)
        .with_context(|| format!("read {}", config.identity_key.display()))?;
    let root = std::fs::read(&config.root_ca)
        .with_context(|| format!("read {}", config.root_ca.display()))?;
    Endpoint::from_shared(config.endpoint.clone())
        .context("invalid client endpoint")?
        .connect_timeout(Duration::from_secs(10))
        .timeout(Duration::from_secs(60))
        .tls_config(
            ClientTlsConfig::new()
                .domain_name(config.server_name.clone())
                .ca_certificate(Certificate::from_pem(root))
                .identity(Identity::from_pem(certificate, private_key)),
        )
        .context("configure client mTLS")?
        .connect()
        .await
        .context("connect to client endpoint")
}

/// Verifies that the active identity can establish a pinned mTLS connection to
/// the configured client listener without starting the long-running daemon.
///
/// # Errors
///
/// Returns an error when identity material cannot be read, TLS validation
/// fails, DNS/network connectivity is unavailable, or the endpoint is invalid.
pub async fn probe_connection(config: &ClientConfig) -> Result<()> {
    let _channel = client_channel(config).await?;
    Ok(())
}

fn client_hello(config: &ClientConfig) -> ClientHello {
    ClientHello {
        identity_id: config.identity_id.to_string(),
        hostname: hostname::get()
            .ok()
            .and_then(|value| value.into_string().ok())
            .unwrap_or_else(|| "unknown".into()),
        os: std::env::consts::OS.into(),
        os_version: os_version(),
        architecture: std::env::consts::ARCH.into(),
        client_version: env!("CARGO_PKG_VERSION").into(),
        protocol: Some(ProtocolVersion {
            major: centrald_protocol::PROTOCOL_MAJOR,
            minor: centrald_protocol::PROTOCOL_MINOR,
        }),
        capabilities: vec!["heartbeat".into()],
        boot_id: boot_id(),
    }
}

/// Proves possession of the persisted client private key and activates a
/// pending enrollment or renewed certificate. The operation is idempotent.
pub(crate) async fn ensure_identity_active(config: &ClientConfig) -> Result<()> {
    let channel = client_channel(config).await?;
    let response = ClientServiceClient::new(channel)
        .activate_identity(ActivateIdentityRequest {
            identity_id: config.identity_id.to_string(),
            protocol: Some(ProtocolVersion {
                major: centrald_protocol::PROTOCOL_MAJOR,
                minor: centrald_protocol::PROTOCOL_MINOR,
            }),
        })
        .await
        .context("activate client identity")?
        .into_inner();
    if !response.success {
        bail!("server rejected client identity activation: {}", response.message);
    }
    Ok(())
}

/// Uses the previously active identity to prove an authenticated replacement
/// and revoke it only after the new identity has been durably published and
/// activated.
pub(crate) async fn replace_previous_identity(
    previous: &ClientConfig,
    replacement_identity_id: Uuid,
) -> Result<()> {
    if previous.identity_id == replacement_identity_id {
        return Ok(());
    }
    let channel = client_channel(previous).await?;
    let response = ClientServiceClient::new(channel)
        .replace_identity(ReplaceIdentityRequest {
            replacement_identity_id: replacement_identity_id.to_string(),
            reason: "client completed authenticated reenrollment".to_owned(),
            protocol: Some(ProtocolVersion {
                major: centrald_protocol::PROTOCOL_MAJOR,
                minor: centrald_protocol::PROTOCOL_MINOR,
            }),
        })
        .await
        .context("replace previous client identity")?
        .into_inner();
    if !response.success {
        bail!("server rejected previous-identity replacement: {}", response.message);
    }
    Ok(())
}

fn boot_id() -> String {
    #[cfg(target_os = "linux")]
    if let Ok(value) = std::fs::read_to_string("/proc/sys/kernel/random/boot_id") {
        let value = value.trim();
        if Uuid::parse_str(value).is_ok() {
            return value.to_owned();
        }
    }
    #[cfg(windows)]
    {
        let uptime = system_uptime_seconds();
        if uptime > 0 {
            let now = std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .map_or(0, |duration| duration.as_secs());
            // GetTickCount64 is monotonic since Windows boot. Rounding the
            // derived boot epoch to a minute keeps the identifier stable across
            // process/service restarts while avoiding machine-specific data.
            let boot_epoch = now.saturating_sub(uptime);
            return format!("windows-boot-{}", boot_epoch / 60 * 60);
        }
    }
    static PROCESS_BOOT_ID: std::sync::OnceLock<String> = std::sync::OnceLock::new();
    PROCESS_BOOT_ID
        .get_or_init(|| Uuid::now_v7().to_string())
        .clone()
}

fn os_version() -> String {
    #[cfg(target_os = "linux")]
    if let Ok(contents) = std::fs::read_to_string("/etc/os-release") {
        for line in contents.lines() {
            if let Some(value) = line.strip_prefix("PRETTY_NAME=") {
                return value.trim_matches('"').chars().take(128).collect();
            }
        }
    }
    std::env::var("OS").unwrap_or_else(|_| std::env::consts::OS.to_owned())
}

fn system_uptime_seconds() -> u64 {
    #[cfg(target_os = "linux")]
    if let Ok(contents) = std::fs::read_to_string("/proc/uptime") {
        if let Some(value) = contents.split_whitespace().next() {
            let whole_seconds = value.split_once('.').map_or(value, |(whole, _)| whole);
            if let Ok(seconds) = whole_seconds.parse::<u64>() {
                return seconds;
            }
        }
    }
    #[cfg(windows)]
    return windows_uptime_seconds();
    #[cfg(not(any(target_os = "linux", windows)))]
    return 0;
    #[cfg(target_os = "linux")]
    0
}

#[cfg(windows)]
#[allow(unsafe_code)]
fn windows_uptime_seconds() -> u64 {
    // SAFETY: GetTickCount64 has no parameters and returns a process-independent
    // monotonic millisecond counter maintained by the operating system.
    unsafe { windows_sys::Win32::System::SystemInformation::GetTickCount64() / 1_000 }
}

fn memory_bytes() -> (u64, u64) {
    #[cfg(target_os = "linux")]
    if let Ok(contents) = std::fs::read_to_string("/proc/meminfo") {
        let mut total_kib = None;
        let mut available_kib = None;
        for line in contents.lines() {
            let mut fields = line.split_whitespace();
            match fields.next() {
                Some("MemTotal:") => total_kib = fields.next().and_then(|value| value.parse().ok()),
                Some("MemAvailable:") => {
                    available_kib = fields.next().and_then(|value| value.parse().ok())
                }
                _ => {}
            }
        }
        if let (Some(total), Some(available)) = (total_kib, available_kib) {
            let total = total.saturating_mul(1024);
            let available = available.saturating_mul(1024);
            return (total, total.saturating_sub(available));
        }
    }
    (0, 0)
}

fn now_timestamp() -> prost_types::Timestamp {
    let now = Utc::now();
    prost_types::Timestamp {
        seconds: now.timestamp(),
        nanos: i32::try_from(now.timestamp_subsec_nanos()).unwrap_or_default(),
    }
}
