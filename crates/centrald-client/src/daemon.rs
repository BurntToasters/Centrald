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
    ActivateIdentityRequest, ClientFrame, ClientHello, Heartbeat, Job, JobDeliveryAck, JobEvent,
    JobState, ProtocolVersion, RenewCertificateRequest, ReplaceIdentityRequest,
};
use chrono::{Duration as ChronoDuration, Utc};
use ed25519_dalek::VerifyingKey;
use ed25519_dalek::pkcs8::DecodePublicKey;
use rcgen::{
    CertificateParams, DistinguishedName, DnType, ExtendedKeyUsagePurpose, KeyPair, KeyUsagePurpose,
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
///
/// # Errors
///
/// Returns an error when no enrolled configuration can be loaded, the
/// configuration fails validation, or a client credential is not a regular,
/// non-empty file.
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
            bail!(
                "client credential is not a regular file: {}",
                path.display()
            );
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
    let mut consecutive_failures: u32 = 0;
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
            consecutive_failures = 0;
        } else {
            consecutive_failures = consecutive_failures.saturating_add(1);
            if consecutive_failures == 5 || consecutive_failures.is_multiple_of(20) {
                warn!(
                    failures = consecutive_failures,
                    "client still offline after repeated reconnects; confirm NTP/network, then run centrald-client rescue"
                );
            }
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
    if let Some((_path, previous)) = crate::enrollment::previous_active_config(&config.data_dir)?
        && previous.identity_id != config.identity_id
    {
        replace_previous_identity(&previous, config.identity_id)
            .await
            .context("complete authenticated reenrollment replacement")?;
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
    let mut shells = HashMap::<Uuid, ShellRelay>::new();
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
                    Some(server_frame::Payload::Shell(frame)) => {
                        handle_shell_frame(&sender, frame, &mut grants, &mut shells).await?;
                    }
                    None => bail!("server sent an empty control frame"),
                }
            }
        }
    }
}

const CERTIFICATE_RENEWAL_WINDOW_DAYS: i64 = 30;
const MAX_PENDING_GRANTS: usize = 128;

#[allow(clippy::too_many_lines)]
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
    let config_path = config.data_dir.join("configurations").join(format!(
        "client-{}-{generation_id}.toml",
        config.identity_id
    ));
    replacement.validate()?;
    replacement.validate_storage_path(&config_path)?;
    let serialized =
        toml::to_string_pretty(&replacement).context("serialize renewed client configuration")?;

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
        // The serialized key is written to its root-owned file, then the
        // in-memory PEM is wiped rather than left as plaintext after renewal.
        let serialized_key = zeroize::Zeroizing::new(identity_key.serialize_pem());
        write_new_file(&replacement.identity_key, serialized_key.as_bytes(), true)?;
        write_new_file(&replacement.root_ca, &root_ca, false)?;
        write_new_file(
            &replacement.grant_signing_public_key,
            &grant_signing_public_key,
            false,
        )?;
        crate::enrollment::secure_renewed_generation(&replacement.data_dir, &identity_dir)?;
        write_new_file(&config_path, serialized.as_bytes(), true)?;
        crate::enrollment::secure_renewed_configuration(&replacement.data_dir, &config_path)?;
        Ok::<(), anyhow::Error>(())
    })();
    if let Err(error) = persistence {
        crate::enrollment::cleanup_failed_generation(&identity_dir, &config_path);
        return Err(error.context("persist renewed client identity generation"));
    }
    let publication =
        match crate::enrollment::publish_active_config(&replacement.data_dir, &config_path) {
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
        centrald_protocol::v1::JobKind::RestartClientService => {
            GrantOperation::RestartClientService
        }
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
    // The first event must arrive before the server's execution-start lease
    // expires, so report that execution is starting before the (possibly long)
    // broker round trip.
    //
    // Sequence zero is the server-created dispatch marker. Client-originated
    // execution events start at one so the first running/terminal result
    // satisfies the server's strictly increasing event contract.
    send_job_event(
        sender,
        &job.id,
        1,
        JobState::Running,
        b"executing via the privileged broker",
        false,
    )
    .await?;
    let request = crate::broker::BrokerRequest {
        signed_grant: grant,
        parameters_json: job.parameters_json,
    };
    let result = crate::broker::submit_request(&request).await;
    match result {
        Ok(crate::broker::WireResult::Ok { response }) if response.success => {
            send_job_event(
                sender,
                &job.id,
                2,
                JobState::Succeeded,
                &response.output,
                true,
            )
            .await?;
        }
        Ok(crate::broker::WireResult::Ok { response }) => {
            send_job_event(sender, &job.id, 2, JobState::Failed, &response.output, true).await?;
        }
        Ok(crate::broker::WireResult::Error { message }) => {
            send_job_event(
                sender,
                &job.id,
                2,
                JobState::Failed,
                message.as_bytes(),
                true,
            )
            .await?;
        }
        Err(error) => {
            send_job_event(
                sender,
                &job.id,
                2,
                JobState::Failed,
                error.to_string().as_bytes(),
                true,
            )
            .await?;
        }
    }
    Ok(())
}

/// One active shell session relay on the client: a bounded channel into the
/// broker connection task plus a completion flag for stale-session pruning.
struct ShellRelay {
    to_broker: mpsc::Sender<crate::broker_session::SessionWireFrame>,
    ended: std::sync::Arc<std::sync::atomic::AtomicBool>,
}

/// Maximum concurrent shell sessions relayed by one daemon connection.
const MAX_SHELL_SESSIONS: usize = 8;

/// Handles one server shell frame: opens, relays, or closes a broker session.
///
/// # Errors
///
/// Returns an error only for protocol violations that must terminate the
/// control stream; session-level failures are reported to the server as
/// shell close frames.
async fn handle_shell_frame(
    sender: &mpsc::Sender<ClientFrame>,
    frame: centrald_protocol::v1::ShellFrame,
    grants: &mut HashMap<Uuid, SignedGrant>,
    shells: &mut HashMap<Uuid, ShellRelay>,
) -> Result<()> {
    let Some(payload) = frame.payload else {
        bail!("server sent an empty shell frame");
    };
    match payload {
        centrald_protocol::v1::shell_frame::Payload::Open(open) => {
            open_shell_session(sender, open, grants, shells).await
        }
        centrald_protocol::v1::shell_frame::Payload::Data(data) => {
            relay_shell_data(shells, &data).await
        }
        centrald_protocol::v1::shell_frame::Payload::Resize(resize) => {
            relay_shell_resize(shells, resize).await
        }
        centrald_protocol::v1::shell_frame::Payload::Close(close) => {
            relay_shell_close(shells, close).await
        }
    }
}

async fn open_shell_session(
    sender: &mpsc::Sender<ClientFrame>,
    open: centrald_protocol::v1::ShellOpen,
    grants: &mut HashMap<Uuid, SignedGrant>,
    shells: &mut HashMap<Uuid, ShellRelay>,
) -> Result<()> {
    let session_id: Uuid = open
        .session_id
        .parse()
        .context("server sent an invalid shell session ID")?;
    if open.columns == 0 || open.rows == 0 || open.columns > 500 || open.rows > 500 {
        bail!("server sent an invalid shell size");
    }
    let Some(grant) = grants.remove(&session_id) else {
        send_shell_close(
            sender,
            session_id,
            "server did not provide a shell-operation grant",
        )
        .await?;
        return Ok(());
    };
    let expected_operation = match centrald_protocol::v1::ShellPrivilege::try_from(open.privilege) {
        Ok(centrald_protocol::v1::ShellPrivilege::Low) => GrantOperation::OpenLowShell,
        Ok(centrald_protocol::v1::ShellPrivilege::Elevated) => GrantOperation::OpenElevatedShell,
        _ => {
            send_shell_close(
                sender,
                session_id,
                "server requested an invalid shell privilege",
            )
            .await?;
            return Ok(());
        }
    };
    if grant.grant.job_or_session_id != session_id
        || grant.grant.operation != expected_operation
        || grant.grant.nonce != session_id.to_string()
    {
        send_shell_close(
            sender,
            session_id,
            "shell grant does not match the requested session",
        )
        .await?;
        return Ok(());
    }
    if !shells.contains_key(&session_id) && shells.len() >= MAX_SHELL_SESSIONS {
        // Prune relays whose broker connection already ended before enforcing
        // the cap, so ended sessions do not leak capacity.
        shells.retain(|_, relay| !relay.ended.load(std::sync::atomic::Ordering::Relaxed));
        if shells.len() >= MAX_SHELL_SESSIONS {
            send_shell_close(
                sender,
                session_id,
                "the client shell-session limit was reached",
            )
            .await?;
            return Ok(());
        }
    }
    let (to_broker, from_daemon) = mpsc::channel::<crate::broker_session::SessionWireFrame>(16);
    let ended = std::sync::Arc::new(std::sync::atomic::AtomicBool::new(false));
    shells.insert(
        session_id,
        ShellRelay {
            to_broker: to_broker.clone(),
            ended: ended.clone(),
        },
    );
    if let Err(error) =
        spawn_broker_session(sender, session_id, &open, grant, from_daemon, ended).await
    {
        shells.remove(&session_id);
        send_shell_close(
            sender,
            session_id,
            &format!("broker session failed: {error}"),
        )
        .await?;
    }
    Ok(())
}

async fn spawn_broker_session(
    sender: &mpsc::Sender<ClientFrame>,
    session_id: Uuid,
    open: &centrald_protocol::v1::ShellOpen,
    grant: SignedGrant,
    from_daemon: mpsc::Receiver<crate::broker_session::SessionWireFrame>,
    ended: std::sync::Arc<std::sync::atomic::AtomicBool>,
) -> Result<()> {
    use base64::Engine as _;
    use base64::engine::general_purpose::STANDARD;

    let open_frame = crate::broker_session::SessionWireFrame::Open {
        grant,
        parameters_base64: STANDARD.encode(&open.parameters_json),
        columns: open.columns,
        rows: open.rows,
        account_user: open.account_user.clone(),
        account_password_base64: STANDARD.encode(&open.account_password),
        save_credentials: open.save_credentials,
    };
    #[cfg(unix)]
    let connection = {
        let stream = tokio::net::UnixStream::connect(crate::broker::BROKER_SOCKET_PATH)
            .await
            .with_context(|| {
                format!(
                    "connect to {}; is the privileged broker running?",
                    crate::broker::BROKER_SOCKET_PATH
                )
            })?;
        stream.into_std().context("convert broker connection")?
    };
    #[cfg(windows)]
    let connection = {
        let stream = tokio::task::spawn_blocking(crate::windows_ffi::connect_pipe_client)
            .await
            .context("broker pipe worker failed")??;
        crate::windows_ffi::PipeStream::new(stream)
    };
    let sender_for_task = sender.clone();
    tokio::task::spawn_blocking(move || {
        let outcome = crate::daemon::shell_relay_loop(
            connection,
            &sender_for_task,
            from_daemon,
            &open_frame,
            session_id,
        );
        ended.store(true, std::sync::atomic::Ordering::Relaxed);
        if let Err(error) = outcome {
            tracing::warn!(%session_id, %error, "shell session relay failed");
        }
    });
    Ok(())
}

/// Runs the blocking broker-connection relay for one shell session: forwards
/// daemon frames to the broker and broker frames to the control stream.
fn shell_relay_loop<S>(
    connection: S,
    sender: &mpsc::Sender<ClientFrame>,
    mut from_daemon: mpsc::Receiver<crate::broker_session::SessionWireFrame>,
    open_frame: &crate::broker_session::SessionWireFrame,
    session_id: Uuid,
) -> Result<()>
where
    S: crate::broker_session::DuplexStream + 'static,
{
    use base64::Engine as _;
    use base64::engine::general_purpose::STANDARD;

    let mut writer = connection
        .try_duplicate()
        .map_err(|_| anyhow::anyhow!("could not duplicate the broker session connection"))?;
    let mut reader = connection;
    let open_bytes = serde_json::to_vec(&open_frame)?;
    crate::broker_session::write_frame(&mut writer, &open_bytes)?;
    let send_thread = std::thread::spawn(move || {
        while let Some(frame) = from_daemon.blocking_recv() {
            let Ok(bytes) = serde_json::to_vec(&frame) else {
                break;
            };
            if crate::broker_session::write_frame(&mut writer, &bytes).is_err() {
                break;
            }
        }
    });
    loop {
        let frame_bytes = match crate::broker_session::read_frame(
            &mut reader,
            crate::broker_session::MAX_SESSION_WIRE_FRAME_BYTES,
        ) {
            Ok(bytes) => bytes,
            Err(error) => {
                let _ = send_shell_close_blocking(
                    sender,
                    session_id,
                    &format!("broker session ended: {error}"),
                );
                break;
            }
        };
        let frame =
            match serde_json::from_slice::<crate::broker_session::SessionWireFrame>(&frame_bytes) {
                Ok(frame) => frame,
                Err(error) => {
                    let _ = send_shell_close_blocking(
                        sender,
                        session_id,
                        &format!("broker sent a malformed frame: {error}"),
                    );
                    break;
                }
            };
        let terminal = match frame {
            crate::broker_session::SessionWireFrame::Data { data_base64 } => {
                let Ok(data) = STANDARD.decode(&data_base64) else {
                    let _ = send_shell_close_blocking(
                        sender,
                        session_id,
                        "broker sent invalid session data",
                    );
                    break;
                };
                let frame = centrald_protocol::v1::ShellFrame {
                    payload: Some(centrald_protocol::v1::shell_frame::Payload::Data(
                        centrald_protocol::v1::ShellData {
                            session_id: session_id.to_string(),
                            sequence: 0,
                            data,
                        },
                    )),
                };
                if sender
                    .blocking_send(ClientFrame {
                        payload: Some(client_frame::Payload::Shell(frame)),
                    })
                    .is_err()
                {
                    break;
                }
                false
            }
            crate::broker_session::SessionWireFrame::Close { reason, .. } => {
                let _ = send_shell_close_blocking(sender, session_id, &reason);
                true
            }
            crate::broker_session::SessionWireFrame::Error { message } => {
                let _ = send_shell_close_blocking(sender, session_id, &message);
                true
            }
            crate::broker_session::SessionWireFrame::Opened { .. }
            | crate::broker_session::SessionWireFrame::Open { .. }
            | crate::broker_session::SessionWireFrame::Resize { .. } => false,
        };
        if terminal {
            break;
        }
    }
    let _ = send_thread.join();
    Ok(())
}

fn send_shell_close_blocking(
    sender: &mpsc::Sender<ClientFrame>,
    session_id: Uuid,
    reason: &str,
) -> Result<()> {
    let frame = centrald_protocol::v1::ShellFrame {
        payload: Some(centrald_protocol::v1::shell_frame::Payload::Close(
            centrald_protocol::v1::ShellClose {
                session_id: session_id.to_string(),
                reason: reason.to_owned(),
                exit_code: 1,
            },
        )),
    };
    sender
        .blocking_send(ClientFrame {
            payload: Some(client_frame::Payload::Shell(frame)),
        })
        .context("send shell close to the control stream")
}

async fn send_shell_close(
    sender: &mpsc::Sender<ClientFrame>,
    session_id: Uuid,
    reason: &str,
) -> Result<()> {
    let frame = centrald_protocol::v1::ShellFrame {
        payload: Some(centrald_protocol::v1::shell_frame::Payload::Close(
            centrald_protocol::v1::ShellClose {
                session_id: session_id.to_string(),
                reason: reason.to_owned(),
                exit_code: 1,
            },
        )),
    };
    sender
        .send(ClientFrame {
            payload: Some(client_frame::Payload::Shell(frame)),
        })
        .await
        .context("send shell close to the control stream")
}

async fn relay_shell_data(
    shells: &mut HashMap<Uuid, ShellRelay>,
    data: &centrald_protocol::v1::ShellData,
) -> Result<()> {
    let session_id: Uuid = data
        .session_id
        .parse()
        .context("server sent an invalid shell session ID")?;
    let Some(relay) = shells.get(&session_id) else {
        // A frame for a session the client already closed races with the
        // server's relay; dropping it must not kill the control stream.
        tracing::warn!(%session_id, "ignored shell data for an unknown session");
        return Ok(());
    };
    if data.data.len() > crate::broker_session::MAX_SESSION_WIRE_FRAME_BYTES {
        bail!("server sent an oversized shell data frame");
    }
    let frame = crate::broker_session::SessionWireFrame::Data {
        data_base64: {
            use base64::Engine as _;
            use base64::engine::general_purpose::STANDARD;
            STANDARD.encode(&data.data)
        },
    };
    if relay.to_broker.send(frame).await.is_err() {
        bail!("shell session relay ended");
    }
    Ok(())
}

async fn relay_shell_close(
    shells: &mut HashMap<Uuid, ShellRelay>,
    close: centrald_protocol::v1::ShellClose,
) -> Result<()> {
    let session_id: Uuid = close
        .session_id
        .parse()
        .context("server sent an invalid shell session ID")?;
    let Some(relay) = shells.remove(&session_id) else {
        return Ok(());
    };
    let _ = relay
        .to_broker
        .send(crate::broker_session::SessionWireFrame::Close {
            reason: if close.reason.is_empty() {
                "operator closed the terminal".to_owned()
            } else {
                close.reason
            },
            exit_code: close.exit_code,
        })
        .await;
    Ok(())
}

async fn relay_shell_resize(
    shells: &mut HashMap<Uuid, ShellRelay>,
    resize: centrald_protocol::v1::ShellResize,
) -> Result<()> {
    let session_id: Uuid = resize
        .session_id
        .parse()
        .context("server sent an invalid shell session ID")?;
    if resize.columns == 0 || resize.rows == 0 || resize.columns > 500 || resize.rows > 500 {
        bail!("server sent an invalid shell size");
    }
    let Some(relay) = shells.get(&session_id) else {
        tracing::warn!(%session_id, "ignored shell resize for an unknown session");
        return Ok(());
    };
    if relay
        .to_broker
        .send(crate::broker_session::SessionWireFrame::Resize {
            columns: resize.columns,
            rows: resize.rows,
        })
        .await
        .is_err()
    {
        bail!("shell session relay ended");
    }
    Ok(())
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
    // tonic copies the PEM bytes into its TLS identity, so our intermediate
    // buffers are wiped on drop rather than left as plaintext key material.
    let certificate = zeroize::Zeroizing::new(
        std::fs::read(&config.identity_cert)
            .with_context(|| format!("read {}", config.identity_cert.display()))?,
    );
    let private_key = zeroize::Zeroizing::new(
        std::fs::read(&config.identity_key)
            .with_context(|| format!("read {}", config.identity_key.display()))?,
    );
    let root = zeroize::Zeroizing::new(
        std::fs::read(&config.root_ca)
            .with_context(|| format!("read {}", config.root_ca.display()))?,
    );
    Endpoint::from_shared(config.endpoint.clone())
        .context("invalid client endpoint")?
        .connect_timeout(Duration::from_secs(10))
        .tls_config(
            ClientTlsConfig::new()
                .domain_name(config.server_name.clone())
                .ca_certificate(Certificate::from_pem(&*root))
                .identity(Identity::from_pem(&*certificate, &*private_key)),
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
        bail!(
            "server rejected client identity activation: {}",
            response.message
        );
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
        bail!(
            "server rejected previous-identity replacement: {}",
            response.message
        );
    }
    Ok(())
}

#[allow(clippy::items_after_statements)]
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
    return crate::windows_ffi::uptime_seconds();
    #[cfg(not(any(target_os = "linux", windows)))]
    return 0;
    #[cfg(target_os = "linux")]
    0
}

fn memory_bytes() -> (u64, u64) {
    #[cfg(target_os = "linux")]
    if let Ok(contents) = std::fs::read_to_string("/proc/meminfo") {
        let mut total_kib: Option<u64> = None;
        let mut available_kib: Option<u64> = None;
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
