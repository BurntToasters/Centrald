#[cfg(unix)]
use std::fs::File;
use std::io::{self, IsTerminal, Read, Write};
use std::path::{Path, PathBuf};
#[cfg(windows)]
use std::process::Command;

use anyhow::{Context, Result, bail};
use centrald_common::active_pointer::{ActivePointer, ActivePointerError, PointerPublication};
#[cfg(windows)]
use centrald_common::config::windows_system_executable;
use centrald_common::config::{ClientConfig, client_data_dir};
use centrald_common::enrollment::{EnrollmentRole, parse_enrollment_invitation};
use centrald_common::host::https_endpoint;
#[cfg(not(unix))]
use centrald_common::secure_fs::write_new_file;
use centrald_protocol::v1::enrollment_service_client::EnrollmentServiceClient;
use centrald_protocol::v1::{EnrollClientRequest, IdentityRole, ProtocolVersion};
use chrono::Utc;
use rcgen::{
    CertificateParams, DistinguishedName, DnType, ExtendedKeyUsagePurpose, KeyPair, KeyUsagePurpose,
};
use secrecy::{ExposeSecret, SecretString};
use tonic::transport::{Certificate, Channel, ClientTlsConfig, Endpoint};
use uuid::Uuid;

use crate::cli::EnrollmentArgs;
use crate::state_lock::{ClientStateLock, state_lock_path};

const MAX_INVITATION_BYTES: usize = 128 * 1024;

/// Runs the one-paste client enrollment wizard and persists a new identity.
///
/// The invitation itself supplies the server TLS name, ports, and root CA. A
/// server address override changes only where the TCP connection is made; TLS
/// still verifies the name embedded in the invitation.
///
/// # Errors
///
/// Returns an error for invalid input, expired/wrong-role invitations, TLS/RPC
/// failures, rejected enrollment, certificate generation, or safe persistence
/// failures.
#[allow(clippy::too_many_lines)]
pub async fn run(args: EnrollmentArgs, reenroll: bool) -> Result<PathBuf> {
    println!("CentralD client enrollment");
    println!("Paste the one-time invitation created by your CentralD administrator.");
    let automated_input = args.key_file.is_some() || args.key_stdin;
    let secret = secret_or_prompt(args.key_file.as_deref(), args.key_stdin, "Access key")?;
    let claims = parse_enrollment_invitation(&secret).context("invalid CentralD access key")?;
    if claims.role != EnrollmentRole::Client {
        bail!("this access key is for an Admin, not a managed client");
    }
    if claims.expires_at <= Utc::now() {
        bail!("this client invitation has expired");
    }
    // Key-file/stdin enrollment is intended for unattended provisioning. When
    // no destination override is supplied, use the invitation endpoint without
    // consuming stdin for a second prompt.
    let server = if automated_input && args.server.is_none() {
        claims.server_name.clone()
    } else {
        server_or_prompt(args.server, &claims.server_name)?
    };
    let enrollment_endpoint = service_endpoint(&server, claims.enrollment_port)?;
    let client_endpoint = service_endpoint(&server, claims.client_port)?;
    let hostname = local_hostname()?;
    let data_dir = client_data_dir().context("resolve fixed CentralD client state root")?;
    // Coordinate the complete credential publication with the running daemon.
    // On Unix, the lock lives directly under root-owned /var/lib so the managed
    // service account cannot unlink it and split the lock domain.
    let state_lock = ClientStateLock::acquire()
        .context("wait for another CentralD client state mutation to finish")?;
    prepare_base_state(&data_dir)
        .context("prepare protected client state before consuming the one-time invitation")?;
    let pointer = client_active_pointer(&data_dir)?;
    if pointer.previous()?.is_some() {
        bail!(
            "a prior credential publication still needs activation; start the client service or run rescue before enrolling again"
        );
    }
    let active = active_config_path(&data_dir)?;
    let previous_identity = match (reenroll, active) {
        (true, Some(path)) => Some(
            ClientConfig::load(&path)
                .context("reenroll requires an existing usable client identity")?,
        ),
        (true, None) => bail!("reenroll requires an existing enrolled client identity"),
        (false, Some(_)) => bail!("client is already enrolled; use centrald-client reenroll"),
        (false, None) => None,
    };

    let identity_key = KeyPair::generate().context("generate client identity key")?;
    let mut parameters = CertificateParams::default();
    let mut distinguished_name = DistinguishedName::new();
    distinguished_name.push(DnType::CommonName, claims.name.clone());
    parameters.distinguished_name = distinguished_name;
    parameters.key_usages = vec![KeyUsagePurpose::DigitalSignature];
    parameters.extended_key_usages = vec![ExtendedKeyUsagePurpose::ClientAuth];
    let csr = parameters
        .serialize_request(&identity_key)
        .context("generate certificate signing request")?
        .pem()
        .context("encode certificate signing request")?;

    let channel = enrollment_channel(
        &enrollment_endpoint,
        &claims.server_name,
        &claims.root_ca_pem,
    )
    .await?;
    let mut client = EnrollmentServiceClient::new(channel);
    let response = client
        .enroll_client(EnrollClientRequest {
            enrollment_key: secret.expose_secret().to_owned(),
            csr_pem: csr.into_bytes(),
            hostname,
            os: normalized_os()?.into(),
            architecture: normalized_architecture()?.into(),
            protocol: Some(ProtocolVersion {
                major: centrald_protocol::PROTOCOL_MAJOR,
                minor: centrald_protocol::PROTOCOL_MINOR,
            }),
        })
        .await
        .context("server rejected client enrollment")?
        .into_inner();
    let identity_id: Uuid = response
        .identity_id
        .parse()
        .context("server returned an invalid identity ID")?;
    if response.role != IdentityRole::Client as i32
        || response.certificate_chain_pem.is_empty()
        || response.grant_signing_public_key.is_empty()
    {
        bail!("server returned incomplete or mismatched enrollment material");
    }

    let certificate_expires_at = timestamp_to_datetime(response.expires_at)
        .context("server returned an invalid certificate expiration")?;
    let generation_id = Uuid::now_v7();
    let identity_dir = data_dir
        .join("identities")
        .join(identity_id.to_string())
        .join("generations")
        .join(generation_id.to_string());
    let certificate_path = identity_dir.join("identity-chain.pem");
    let private_key_path = identity_dir.join("identity-key.pem");
    let root_path = identity_dir.join("root-ca.pem");
    let grant_key_path = identity_dir.join("grant-signing-public.pem");
    let config_path = data_dir
        .join("configurations")
        .join(format!("client-{identity_id}-{generation_id}.toml"));
    let config = ClientConfig {
        identity_id,
        identity_name: claims.name.clone(),
        endpoint: client_endpoint,
        server_name: claims.server_name,
        data_dir: data_dir.clone(),
        identity_cert: certificate_path.clone(),
        identity_key: private_key_path.clone(),
        root_ca: root_path.clone(),
        grant_signing_public_key: grant_key_path.clone(),
        certificate_expires_at,
    };
    config.validate()?;
    config.validate_storage_path(&config_path)?;
    let config_toml = toml::to_string_pretty(&config).context("serialize client config")?;

    let persistence = persist_identity_generation(
        &config,
        &config_path,
        &identity_dir,
        generation_id,
        &response.certificate_chain_pem,
        identity_key.serialize_pem().as_bytes(),
        claims.root_ca_pem.as_bytes(),
        &response.grant_signing_public_key,
        config_toml.as_bytes(),
    );
    if let Err(error) = persistence {
        cleanup_failed_enrollment_generation(
            &data_dir,
            identity_id,
            generation_id,
            &identity_dir,
            &config_path,
        );
        return Err(error.context(
            "server accepted a pending enrollment, but local identity persistence failed; the pending identity will expire automatically",
        ));
    }
    let publication = match publish_active_config(&data_dir, &config_path) {
        Ok(publication) => publication,
        Err(error) => {
            cleanup_failed_enrollment_generation(
                &data_dir,
                identity_id,
                generation_id,
                &identity_dir,
                &config_path,
            );
            return Err(error.context("publish the enrolled client credential generation"));
        }
    };
    if let Err(error) = crate::daemon::ensure_identity_active(&config).await {
        if let Err(rollback_error) = publication.rollback() {
            return Err(error.context(format!(
                "client identity activation failed and pointer rollback also failed; the published generation was retained for recovery: {rollback_error}"
            )));
        }
        cleanup_failed_enrollment_generation(
            &data_dir,
            identity_id,
            generation_id,
            &identity_dir,
            &config_path,
        );
        return Err(error.context(
            "durable client identity was not activated; local publication was rolled back and the pending server identity will expire",
        ));
    }

    if let Some(previous) = previous_identity {
        if let Err(error) = crate::daemon::replace_previous_identity(&previous, identity_id).await {
            return Err(error.context(format!(
                "new client identity {identity_id} is active, but previous identity {} could not be revoked; the client service will retry before finalizing the credential pointer",
                previous.identity_id
            )));
        }
        eprintln!(
            "reenrollment activated identity {identity_id} and revoked previous identity {}",
            previous.identity_id
        );
    }
    publication
        .commit()
        .context("finalize the active client credential pointer")?;
    secure_active_pointer_files(&data_dir)?;
    // The service startup path also observes the state lock. Release it before
    // asking the service manager to synchronously start the daemon.
    drop(state_lock);
    #[cfg(target_os = "linux")]
    if let Err(error) = enable_linux_service_after_enrollment() {
        eprintln!(
            "warning: enrollment succeeded but the Linux client service could not be enabled and started automatically: {error:#}"
        );
    }
    #[cfg(windows)]
    if let Err(error) = enable_windows_service_after_enrollment() {
        eprintln!(
            "warning: enrollment succeeded but Windows service startup could not be enabled automatically: {error:#}"
        );
    }
    Ok(config_path)
}

#[allow(clippy::too_many_arguments)]
fn persist_identity_generation(
    config: &ClientConfig,
    config_path: &Path,
    identity_dir: &Path,
    generation_id: Uuid,
    certificate: &[u8],
    private_key: &[u8],
    root_ca: &[u8],
    grant_key: &[u8],
    config_toml: &[u8],
) -> Result<()> {
    #[cfg(unix)]
    {
        let _ = identity_dir;
        let service_ids = service_account_ids()?.context(
            "the centrald service account does not exist; install the Linux package before enrollment",
        )?;
        let configuration_name = config_path
            .file_name()
            .and_then(|value| value.to_str())
            .context("client configuration filename is invalid")?;
        crate::unix_state::persist_enrollment_generation(
            &config.data_dir,
            config.identity_id,
            generation_id,
            configuration_name,
            certificate,
            private_key,
            root_ca,
            grant_key,
            config_toml,
            service_ids,
        )?;
        crate::broker::publish_grant_verifying_key(grant_key)
    }

    #[cfg(not(unix))]
    {
        let _ = generation_id;
        prepare_identity_generation(&config.data_dir, identity_dir)?;
        write_new_file(&config.identity_cert, certificate, false)?;
        write_new_file(&config.identity_key, private_key, true)?;
        write_new_file(&config.root_ca, root_ca, false)?;
        write_new_file(&config.grant_signing_public_key, grant_key, false)?;
        secure_identity_directory(&config.data_dir, identity_dir)?;
        // The configuration is the publication point: the daemon cannot discover
        // this generation until every referenced file is durable and protected.
        write_new_file(config_path, config_toml, true)?;
        secure_configuration_file(&config.data_dir, config_path)?;
        crate::broker::publish_grant_verifying_key(grant_key)
    }
}

fn cleanup_failed_enrollment_generation(
    data_dir: &Path,
    identity_id: Uuid,
    generation_id: Uuid,
    identity_dir: &Path,
    config_path: &Path,
) {
    #[cfg(unix)]
    {
        let _ = identity_dir;
        let result = (|| {
            let service_ids = service_account_ids()?.context(
                "the centrald service account does not exist; cannot safely clean failed enrollment",
            )?;
            let configuration_name = config_path
                .file_name()
                .and_then(|value| value.to_str())
                .context("client configuration filename is invalid")?;
            crate::unix_state::cleanup_enrollment_generation(
                data_dir,
                identity_id,
                generation_id,
                configuration_name,
                service_ids,
            )
        })();
        if let Err(error) = result {
            eprintln!(
                "warning: failed enrollment generation could not be cleaned safely: {error:#}"
            );
        }
    }
    #[cfg(not(unix))]
    {
        let _ = (data_dir, identity_id, generation_id);
        cleanup_failed_generation(identity_dir, config_path);
    }
}

fn prepare_base_state(data_dir: &Path) -> Result<()> {
    #[cfg(windows)]
    validate_windows_protected_root(data_dir)?;
    ensure_real_directory(data_dir)?;
    ensure_real_directory(&data_dir.join("identities"))?;
    ensure_real_directory(&data_dir.join("configurations"))?;
    #[cfg(unix)]
    {
        let service_ids = service_account_ids()?.context(
            "the centrald service account does not exist; install the Linux package before enrollment",
        )?;
        crate::unix_state::secure_base_state(data_dir, &state_lock_path()?, service_ids)?;
    }
    #[cfg(windows)]
    {
        validate_windows_inherited_state(data_dir, &data_dir.join("identities"))?;
        validate_windows_inherited_state(data_dir, &data_dir.join("configurations"))?;
    }
    Ok(())
}

pub(crate) fn prepare_identity_generation(data_dir: &Path, identity_dir: &Path) -> Result<()> {
    if !identity_dir.starts_with(data_dir) {
        bail!("client identity generation escaped the protected data directory");
    }
    ensure_real_directory(identity_dir)
}

fn ensure_real_directory(path: &Path) -> Result<()> {
    if path.as_os_str().is_empty() {
        bail!("client state directory must not be empty");
    }
    match path.symlink_metadata() {
        Ok(metadata) => {
            if metadata.file_type().is_symlink() || !metadata.is_dir() {
                bail!("refusing unsafe client state directory {}", path.display());
            }
            return Ok(());
        }
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => {}
        Err(error) => return Err(error).with_context(|| format!("inspect {}", path.display())),
    }
    let parent = path
        .parent()
        .filter(|parent| !parent.as_os_str().is_empty())
        .context("client state directory has no parent")?;
    ensure_real_directory(parent)?;
    match std::fs::create_dir(path) {
        Ok(()) => {}
        Err(error) if error.kind() == std::io::ErrorKind::AlreadyExists => {}
        Err(error) => return Err(error).with_context(|| format!("create {}", path.display())),
    }
    let metadata = path
        .symlink_metadata()
        .with_context(|| format!("inspect newly created {}", path.display()))?;
    if metadata.file_type().is_symlink() || !metadata.is_dir() {
        bail!("refusing unsafe client state directory {}", path.display());
    }
    Ok(())
}

pub(crate) fn cleanup_failed_generation(identity_dir: &Path, config_path: &Path) {
    if config_path
        .symlink_metadata()
        .is_ok_and(|metadata| metadata.is_file() && !metadata.file_type().is_symlink())
    {
        let _ = std::fs::remove_file(config_path);
    }
    if identity_dir
        .symlink_metadata()
        .is_ok_and(|metadata| metadata.is_dir() && !metadata.file_type().is_symlink())
    {
        let _ = std::fs::remove_dir_all(identity_dir);
    }
}

#[cfg(unix)]
pub(crate) fn secure_renewed_generation(data_dir: &Path, identity_dir: &Path) -> Result<()> {
    secure_identity_directory(data_dir, identity_dir)
}

#[cfg(unix)]
pub(crate) fn secure_renewed_configuration(data_dir: &Path, config_path: &Path) -> Result<()> {
    secure_configuration_file(data_dir, config_path)
}

#[cfg(windows)]
pub(crate) fn secure_renewed_generation(data_dir: &Path, identity_dir: &Path) -> Result<()> {
    validate_windows_inherited_state(data_dir, identity_dir)
}

#[cfg(windows)]
pub(crate) fn secure_renewed_configuration(data_dir: &Path, config_path: &Path) -> Result<()> {
    validate_windows_inherited_state(data_dir, config_path)
}

#[cfg(windows)]
fn validate_windows_protected_root(data_dir: &Path) -> Result<()> {
    let expected_data_dir =
        client_data_dir().context("resolve installer-owned Windows CentralD data directory")?;
    if data_dir != expected_data_dir {
        bail!(
            "Windows CentralD client state must use the installer-owned fixed data directory {}",
            expected_data_dir.display()
        );
    }
    let metadata = data_dir
        .symlink_metadata()
        .with_context(|| {
            format!(
                "inspect installer-owned CentralD data root {}; run the signed installer before enrollment",
                data_dir.display()
            )
        })?;
    require_windows_real_component(data_dir, &metadata)?;
    if !metadata.is_dir() {
        bail!("CentralD client data root is not a directory");
    }
    Ok(())
}

#[cfg(windows)]
fn validate_windows_inherited_state(data_dir: &Path, path: &Path) -> Result<()> {
    validate_windows_protected_root(data_dir)?;
    let relative = path
        .strip_prefix(data_dir)
        .map_err(|_| anyhow::anyhow!("client state escaped the protected data directory"))?;
    let mut current = data_dir.to_path_buf();
    for component in relative.components() {
        use std::path::Component;
        let Component::Normal(component) = component else {
            bail!("client state contains a non-canonical Windows path component");
        };
        current.push(component);
        let metadata = current
            .symlink_metadata()
            .with_context(|| format!("inspect protected client state {}", current.display()))?;
        require_windows_real_component(&current, &metadata)?;
    }
    Ok(())
}

#[cfg(windows)]
fn require_windows_real_component(path: &Path, metadata: &std::fs::Metadata) -> Result<()> {
    use std::os::windows::fs::MetadataExt;

    const FILE_ATTRIBUTE_REPARSE_POINT: u32 = 0x0400;
    if metadata.file_type().is_symlink()
        || metadata.file_attributes() & FILE_ATTRIBUTE_REPARSE_POINT != 0
    {
        bail!(
            "refusing Windows reparse point in client state: {}",
            path.display()
        );
    }
    Ok(())
}

#[cfg(not(any(unix, windows)))]
pub(crate) fn secure_renewed_generation(_data_dir: &Path, _identity_dir: &Path) -> Result<()> {
    bail!("unsupported client operating system")
}

#[cfg(not(any(unix, windows)))]
pub(crate) fn secure_renewed_configuration(_data_dir: &Path, _config_path: &Path) -> Result<()> {
    bail!("unsupported client operating system")
}

pub(crate) fn timestamp_to_datetime(
    value: Option<prost_types::Timestamp>,
) -> Result<chrono::DateTime<Utc>> {
    let value = value.context("timestamp is missing")?;
    let nanos = u32::try_from(value.nanos).context("timestamp nanoseconds are invalid")?;
    chrono::DateTime::from_timestamp(value.seconds, nanos)
        .context("timestamp is outside the supported range")
}

/// Finds and validates the fixed active client configuration pointer.
///
/// # Errors
///
/// Returns an error when the pointer or target is missing, malformed, unsafe,
/// or the referenced configuration is invalid.
pub fn load_latest_config() -> Result<(PathBuf, ClientConfig)> {
    let data_dir = client_data_dir().context("resolve fixed CentralD client state root")?;
    let path = active_config_path(&data_dir)?.context("client is not enrolled")?;
    let config = ClientConfig::load(&path)?;
    Ok((path, config))
}

pub(crate) fn previous_active_config(data_dir: &Path) -> Result<Option<(PathBuf, ClientConfig)>> {
    let pointer = client_active_pointer(data_dir)?;
    let Some(filename) = pointer.previous()? else {
        return Ok(None);
    };
    let path = validate_active_config_target(data_dir, &filename)?;
    let config = ClientConfig::load(&path)?;
    Ok(Some((path, config)))
}

pub(crate) fn publish_active_config(
    data_dir: &Path,
    config_path: &Path,
) -> Result<PointerPublication> {
    let directory = data_dir.join("configurations");
    if config_path.parent() != Some(directory.as_path()) {
        bail!("client configuration escaped the protected configurations directory");
    }
    let filename = config_path
        .file_name()
        .and_then(|value| value.to_str())
        .context("client configuration filename is invalid")?;
    validate_active_config_target(data_dir, filename)?;
    let pointer = client_active_pointer(data_dir)?;
    let publication = pointer.publish(filename)?;
    if let Err(error) = secure_active_pointer_files(data_dir) {
        let rollback = publication.rollback();
        if let Err(rollback_error) = rollback {
            return Err(error.context(format!(
                "secure active pointer files failed and rollback also failed: {rollback_error}"
            )));
        }
        return Err(error);
    }
    Ok(publication)
}

pub(crate) fn commit_active_config(data_dir: &Path) -> Result<()> {
    let pointer = client_active_pointer(data_dir)?;
    pointer.commit_recovered()?;
    secure_active_pointer_files(data_dir)
}

pub(crate) fn rollback_active_config_if_previous(data_dir: &Path) -> Result<bool> {
    let pointer = client_active_pointer(data_dir)?;
    let rolled_back = pointer.rollback_recovered_if_previous()?;
    secure_active_pointer_files(data_dir)?;
    Ok(rolled_back)
}

fn active_config_path(data_dir: &Path) -> Result<Option<PathBuf>> {
    let pointer = client_active_pointer(data_dir)?;
    match pointer.read() {
        Ok(filename) => Ok(Some(validate_active_config_target(data_dir, &filename)?)),
        Err(ActivePointerError::Missing) => Ok(None),
        Err(error) => Err(error.into()),
    }
}

#[allow(clippy::case_sensitive_file_extension_comparisons)]
fn validate_active_config_target(data_dir: &Path, filename: &str) -> Result<PathBuf> {
    let candidate = Path::new(filename);
    if filename.is_empty()
        || candidate.is_absolute()
        || candidate.components().count() != 1
        || !filename.starts_with("client-")
        || !filename.ends_with(".toml")
    {
        bail!("active client configuration pointer is invalid");
    }
    let path = data_dir.join("configurations").join(candidate);
    let metadata = path
        .symlink_metadata()
        .with_context(|| format!("inspect active client configuration {}", path.display()))?;
    if metadata.file_type().is_symlink() || !metadata.is_file() {
        bail!(
            "active client configuration is not a regular file: {}",
            path.display()
        );
    }
    Ok(path)
}

fn client_active_pointer(data_dir: &Path) -> Result<ActivePointer> {
    ActivePointer::new(data_dir.join("configurations")).map_err(Into::into)
}

fn secure_active_pointer_files(data_dir: &Path) -> Result<()> {
    let pointer = client_active_pointer(data_dir)?;
    let state_lock = state_lock_path()?;
    for path in pointer
        .managed_paths()
        .into_iter()
        .chain(std::iter::once(state_lock))
    {
        match path.symlink_metadata() {
            Ok(metadata) => {
                if metadata.file_type().is_symlink() || !metadata.is_file() {
                    bail!("refusing unsafe active pointer file {}", path.display());
                }
                secure_configuration_file(data_dir, &path)?;
            }
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => {}
            Err(error) => return Err(error).with_context(|| format!("inspect {}", path.display())),
        }
    }
    Ok(())
}

async fn enrollment_channel(endpoint: &str, server_name: &str, root_pem: &str) -> Result<Channel> {
    let endpoint = Endpoint::from_shared(endpoint.to_owned())
        .context("invalid enrollment endpoint")?
        .connect_timeout(std::time::Duration::from_secs(10))
        .timeout(std::time::Duration::from_secs(30))
        .tls_config(
            ClientTlsConfig::new()
                .domain_name(server_name.to_owned())
                .ca_certificate(Certificate::from_pem(root_pem.as_bytes())),
        )
        .context("configure enrollment TLS")?;
    endpoint
        .connect()
        .await
        .context("connect to enrollment endpoint")
}

fn service_endpoint(server: &str, port: u16) -> Result<String> {
    https_endpoint(server, port).context(
        "server must be a canonical ASCII IP or FQDN without credentials, port, path, query, or fragment",
    )
}

fn secret_or_prompt(key_file: Option<&Path>, key_stdin: bool, label: &str) -> Result<SecretString> {
    if let Some(path) = key_file {
        return read_access_key_file(path, label);
    }
    if key_stdin {
        if io::stdin().is_terminal() {
            bail!(
                "--key-stdin requires piped input; run without key flags for the interactive wizard"
            );
        }
        let stdin = io::stdin();
        let mut input = Vec::new();
        stdin
            .lock()
            .take((MAX_INVITATION_BYTES + 1) as u64)
            .read_to_end(&mut input)
            .context("read the CentralD access key from standard input")?;
        if input.len() > MAX_INVITATION_BYTES {
            bail!("{label} exceeds the maximum supported invitation size");
        }
        let value =
            String::from_utf8(input).context("access key from standard input is not UTF-8")?;
        return normalize_access_key(value, label);
    }
    let value = rpassword::prompt_password(format!("{label}: "))?;
    normalize_access_key(value, label)
}

fn read_access_key_file(path: &Path, label: &str) -> Result<SecretString> {
    #[cfg(windows)]
    {
        let _ = (path, label);
        bail!(
            "--key-file is disabled on Windows because CentralD cannot prove an arbitrary file's ACL; use the interactive wizard or pipe one token to --key-stdin"
        );
    }

    #[cfg(unix)]
    {
        use rustix::fs::{Mode, OFlags, open};
        use std::os::unix::fs::MetadataExt;

        if !path.is_absolute() {
            bail!("access-key file path must be absolute");
        }
        let inspected = path
            .symlink_metadata()
            .with_context(|| format!("inspect access-key file {}", path.display()))?;
        if inspected.file_type().is_symlink() || !inspected.is_file() {
            bail!("access-key path must be a regular, non-symbolic-link file");
        }
        if inspected.len() > MAX_INVITATION_BYTES as u64 {
            bail!("{label} file exceeds the maximum supported invitation size");
        }
        if inspected.uid() != 0 || inspected.mode() & 0o077 != 0 || inspected.nlink() != 1 {
            bail!(
                "access-key file must be root-owned, private (no group/other permissions), and single-linked: {}",
                path.display()
            );
        }
        validate_access_key_ancestors(path)?;

        // Open the file after validation and compare the descriptor metadata to
        // the inspected inode. A rename between inspection and open therefore
        // fails instead of silently changing which invitation root reads.
        let descriptor = open(
            path,
            OFlags::RDONLY | OFlags::CLOEXEC | OFlags::NOFOLLOW,
            Mode::empty(),
        )
        .with_context(|| {
            format!(
                "open access-key file {} without following symbolic links",
                path.display()
            )
        })?;
        let file = File::from(descriptor);
        let opened = file
            .metadata()
            .with_context(|| format!("inspect opened access-key file {}", path.display()))?;
        if opened.dev() != inspected.dev()
            || opened.ino() != inspected.ino()
            || !opened.is_file()
            || opened.uid() != 0
            || opened.nlink() != 1
            || opened.mode() & 0o077 != 0
        {
            bail!("access-key file changed while it was being opened");
        }

        let mut input = Vec::new();
        file.take((MAX_INVITATION_BYTES + 1) as u64)
            .read_to_end(&mut input)
            .with_context(|| format!("read access-key file {}", path.display()))?;
        if input.len() > MAX_INVITATION_BYTES {
            bail!("{label} file exceeds the maximum supported invitation size");
        }
        let value = String::from_utf8(input).context("access-key file is not UTF-8")?;
        return normalize_access_key(value, label);
    }

    #[cfg(not(any(unix, windows)))]
    {
        let _ = (path, label);
        bail!("--key-file is unsupported on this operating system");
    }
}

#[cfg(unix)]
fn validate_access_key_ancestors(path: &Path) -> Result<()> {
    use std::os::unix::fs::MetadataExt;

    let parent = path
        .parent()
        .context("access-key file has no parent directory")?;
    for ancestor in parent.ancestors() {
        let metadata = ancestor
            .symlink_metadata()
            .with_context(|| format!("inspect access-key ancestor {}", ancestor.display()))?;
        if metadata.file_type().is_symlink() || !metadata.is_dir() {
            bail!(
                "access-key ancestor must be a real directory: {}",
                ancestor.display()
            );
        }
        if metadata.mode() & 0o022 != 0 {
            bail!(
                "access-key ancestor must not be group/world writable: {}",
                ancestor.display()
            );
        }
        if metadata.uid() != 0 {
            bail!(
                "access-key ancestor must be root-owned: {}",
                ancestor.display()
            );
        }
    }
    Ok(())
}

fn normalize_access_key(mut value: String, label: &str) -> Result<SecretString> {
    let end = value.trim_end().len();
    value.truncate(end);
    let leading = value.len() - value.trim_start().len();
    if leading > 0 {
        value.drain(..leading);
    }
    if value.is_empty() {
        bail!("{label} must not be empty");
    }
    if value.chars().any(char::is_whitespace) {
        bail!("{label} must be one invitation token without whitespace");
    }
    Ok(SecretString::from(value))
}

fn server_or_prompt(value: Option<String>, default: &str) -> Result<String> {
    if let Some(value) = value {
        if value.trim().is_empty() {
            bail!("server must not be empty");
        }
        return Ok(value.trim().to_owned());
    }
    print!("Server IP or FQDN [{default}]: ");
    io::stdout().flush()?;
    let mut value = String::new();
    io::stdin().read_line(&mut value)?;
    let value = value.trim();
    if value.is_empty() {
        Ok(default.to_owned())
    } else {
        Ok(value.to_owned())
    }
}

fn local_hostname() -> Result<String> {
    let hostname = hostname::get().context("read local hostname")?;
    let hostname = hostname
        .to_str()
        .context("local hostname is not valid UTF-8")?
        .trim()
        .to_owned();
    if hostname.is_empty() || hostname.len() > 253 || hostname.chars().any(char::is_control) {
        bail!("local hostname is invalid");
    }
    Ok(hostname)
}

fn normalized_os() -> Result<&'static str> {
    match std::env::consts::OS {
        "linux" => Ok("linux"),
        "windows" => Ok("windows"),
        other => bail!("unsupported client operating system: {other}"),
    }
}

fn normalized_architecture() -> Result<&'static str> {
    match std::env::consts::ARCH {
        "x86_64" => Ok("x86_64"),
        "aarch64" => Ok("aarch64"),
        other => bail!("unsupported client architecture: {other}"),
    }
}

/// Reapplies the operating-system ownership and access policy to the active
/// client configuration and its current identity generation.
///
/// # Errors
///
/// Returns an error when the configuration points outside the protected data
/// root, a path is not a regular file/directory, or the platform ACL operation
/// fails.
pub fn repair_active_state_permissions() -> Result<(PathBuf, ClientConfig)> {
    #[cfg(windows)]
    {
        bail!(
            "Windows client ACL repair is installer-owned; rerun the signed CentralD client installer as Administrator"
        );
    }

    #[cfg(unix)]
    {
        let data_dir = client_data_dir().context("resolve fixed CentralD client state root")?;
        let state_lock = ClientStateLock::acquire().context(
            "client state is busy; stop the CentralD client service and retry the repair",
        )?;
        let service_ids = service_account_ids()?.context(
            "the centrald service account does not exist; install the Linux package before repair",
        )?;
        let (config_path, config) =
            crate::unix_state::load_active_configuration(&data_dir, service_ids)
                .context("load active client state through fixed-root descriptors")?;
        let layout = validate_repair_layout(&config_path, &config)?;
        secure_unix_repair_state(&layout, state_lock.path())?;
        return Ok((config_path, config));
    }

    #[cfg(not(any(unix, windows)))]
    {
        bail!("unsupported client operating system");
    }
}

#[allow(dead_code)]
#[derive(Debug, Clone, Copy)]
struct RepairLayout {
    identity_id: Uuid,
    generation_id: Uuid,
}

#[allow(dead_code)]
fn validate_repair_layout(config_path: &Path, config: &ClientConfig) -> Result<RepairLayout> {
    let data_dir = client_data_dir().context("resolve fixed CentralD client state root")?;
    if config.data_dir != data_dir {
        bail!(
            "client configuration data root must be {}",
            data_dir.display()
        );
    }
    let configurations = data_dir.join("configurations");
    if config_path.parent() != Some(configurations.as_path()) {
        bail!("active configuration is outside the fixed CentralD configurations directory");
    }
    let filename = config_path
        .file_name()
        .and_then(|value| value.to_str())
        .context("active configuration filename is invalid")?;
    let prefix = format!("client-{}-", config.identity_id);
    let generation_text = filename
        .strip_prefix(&prefix)
        .and_then(|value| value.strip_suffix(".toml"))
        .context("active configuration filename does not match its identity")?;
    let generation_id: Uuid = generation_text
        .parse()
        .context("active configuration generation UUID is invalid")?;
    let identity_dir = data_dir
        .join("identities")
        .join(config.identity_id.to_string())
        .join("generations")
        .join(generation_id.to_string());
    let expected = [
        (
            &config.identity_cert,
            identity_dir.join("identity-chain.pem"),
        ),
        (&config.identity_key, identity_dir.join("identity-key.pem")),
        (&config.root_ca, identity_dir.join("root-ca.pem")),
        (
            &config.grant_signing_public_key,
            identity_dir.join("grant-signing-public.pem"),
        ),
    ];
    for (actual, expected) in expected {
        if actual != &expected {
            bail!(
                "client configuration contains a nonstandard repair target {}; expected {}",
                actual.display(),
                expected.display()
            );
        }
    }
    Ok(RepairLayout {
        identity_id: config.identity_id,
        generation_id,
    })
}

#[cfg(unix)]
fn secure_unix_repair_state(layout: &RepairLayout, lock_path: &Path) -> Result<()> {
    let service_ids = service_account_ids()?.context(
        "the centrald service account does not exist; install the Linux package before repair",
    )?;
    let data_dir = client_data_dir().context("resolve fixed CentralD client state root")?;
    crate::unix_state::secure_generation(
        &data_dir,
        layout.identity_id,
        layout.generation_id,
        service_ids,
    )?;
    let configuration_name = format!(
        "client-{}-{}.toml",
        layout.identity_id, layout.generation_id
    );
    crate::unix_state::secure_configuration(&data_dir, &configuration_name, service_ids)?;
    // The descriptor-opened active configuration proves that the current
    // pointer exists. Repair the fixed pointer files through the same no-follow
    // descriptor walk rather than re-resolving their paths.
    crate::unix_state::secure_configuration(&data_dir, "current.pointer", service_ids)?;
    crate::unix_state::secure_configuration(&data_dir, ".current.pointer.lock", service_ids)?;
    crate::unix_state::secure_lock(lock_path, service_ids)?;
    let grant_path = data_dir
        .join("identities")
        .join(layout.identity_id.to_string())
        .join("generations")
        .join(layout.generation_id.to_string())
        .join("grant-signing-public.pem");
    let grant_key = std::fs::read(&grant_path)
        .with_context(|| format!("read grant verifying key {}", grant_path.display()))?;
    crate::broker::publish_grant_verifying_key(&grant_key)
}

#[cfg(unix)]
pub(crate) fn secure_identity_directory(data_dir: &Path, identity_dir: &Path) -> Result<()> {
    let (identity_id, generation_id) = parse_generation_path(data_dir, identity_dir)?;
    let service_ids = service_account_ids()?.context(
        "the centrald service account does not exist; install the Linux package before enrollment",
    )?;
    crate::unix_state::secure_generation(data_dir, identity_id, generation_id, service_ids)
}

#[cfg(unix)]
pub(crate) fn secure_configuration_file(data_dir: &Path, config_path: &Path) -> Result<()> {
    let service_ids = service_account_ids()?.context(
        "the centrald service account does not exist; install the Linux package before enrollment",
    )?;
    if config_path == state_lock_path()? {
        return crate::unix_state::secure_lock(config_path, service_ids);
    }
    let expected_directory = data_dir.join("configurations");
    if config_path.parent() != Some(expected_directory.as_path()) {
        bail!("client configuration escaped the protected configurations directory");
    }
    let filename = config_path
        .file_name()
        .and_then(|value| value.to_str())
        .context("client configuration filename is invalid")?;
    crate::unix_state::secure_configuration(data_dir, filename, service_ids)
}

#[cfg(unix)]
fn parse_generation_path(data_dir: &Path, identity_dir: &Path) -> Result<(Uuid, Uuid)> {
    let relative = identity_dir
        .strip_prefix(data_dir)
        .context("client identity generation escaped the fixed data root")?;
    let components = relative
        .components()
        .map(|component| component.as_os_str())
        .collect::<Vec<_>>();
    if components.len() != 4 || components[0] != "identities" || components[2] != "generations" {
        bail!("client identity generation path has an invalid shape");
    }
    let identity_id = components[1]
        .to_str()
        .context("client identity path is not UTF-8")?
        .parse::<Uuid>()
        .context("client identity path is not a UUID")?;
    let generation_id = components[3]
        .to_str()
        .context("client generation path is not UTF-8")?
        .parse::<Uuid>()
        .context("client generation path is not a UUID")?;
    Ok((identity_id, generation_id))
}

#[cfg(unix)]
fn service_account_ids() -> Result<Option<(u32, u32)>> {
    let passwd = std::fs::read_to_string("/etc/passwd").context("read /etc/passwd")?;
    let mut match_ids = None;
    for line in passwd.lines() {
        let mut fields = line.split(':');
        if fields.next() != Some("centrald") {
            continue;
        }
        let _password = fields.next();
        let uid = fields
            .next()
            .context("centrald account has no UID")?
            .parse::<u32>()
            .context("centrald account UID is invalid")?;
        let gid = fields
            .next()
            .context("centrald account has no primary GID")?
            .parse::<u32>()
            .context("centrald account GID is invalid")?;
        if match_ids.replace((uid, gid)).is_some() {
            bail!("/etc/passwd contains more than one centrald account");
        }
    }
    Ok(match_ids)
}

#[cfg(windows)]
fn secure_identity_directory(data_dir: &Path, identity_dir: &Path) -> Result<()> {
    validate_windows_inherited_state(data_dir, identity_dir)
}

#[cfg(windows)]
pub(crate) fn secure_configuration_file(data_dir: &Path, config_path: &Path) -> Result<()> {
    validate_windows_inherited_state(data_dir, config_path)
}

#[cfg(target_os = "linux")]
fn enable_linux_service_after_enrollment() -> Result<()> {
    let output = std::process::Command::new("/usr/bin/systemctl")
        .args(["enable", "--now", "centrald-client.service"])
        .output()
        .context("enable and start centrald-client.service")?;
    if !output.status.success() {
        bail!(
            "systemctl enable --now centrald-client.service failed: {}",
            String::from_utf8_lossy(&output.stderr).trim()
        );
    }
    Ok(())
}

#[cfg(windows)]
fn enable_windows_service_after_enrollment() -> Result<()> {
    let manual_start_marker = centrald_common::config::client_manual_start_marker()
        .context("resolve administrator-owned Windows startup policy path")?;
    if manual_start_marker.exists() {
        return Ok(());
    }
    let sc = windows_system_executable("sc.exe")
        .context("Windows did not return its trusted system directory")?;
    let output = Command::new(&sc)
        .args(["config", "CentralDClient", "start=", "delayed-auto"])
        .output()
        .context("configure CentralDClient delayed automatic start")?;
    if !output.status.success() {
        bail!(
            "sc.exe could not configure delayed automatic start: {}",
            String::from_utf8_lossy(&output.stderr).trim()
        );
    }
    // Starting is best-effort because reenrollment may run while the service is
    // already active. Startup mode is the durable invariant.
    let _ = Command::new(&sc).args(["start", "CentralDClient"]).output();
    Ok(())
}

#[cfg(not(any(unix, windows)))]
fn secure_identity_directory(_data_dir: &Path, _identity_dir: &Path) -> Result<()> {
    bail!("unsupported client operating system")
}

#[cfg(not(any(unix, windows)))]
pub(crate) fn secure_configuration_file(_data_dir: &Path, _config_path: &Path) -> Result<()> {
    bail!("unsupported client operating system")
}

#[cfg(test)]
#[allow(clippy::expect_used)]
mod tests {
    use super::*;

    #[test]
    fn endpoint_normalization_uses_invitation_port() {
        assert_eq!(
            service_endpoint("centrald.home.arpa", 7443).expect("endpoint should parse"),
            "https://centrald.home.arpa:7443"
        );
        assert_eq!(
            service_endpoint("192.0.2.10", 7444).expect("IP should parse"),
            "https://192.0.2.10:7444"
        );
        assert_eq!(
            service_endpoint("2001:db8::10", 7443).expect("raw IPv6 should parse"),
            "https://[2001:db8::10]:7443"
        );
        assert_eq!(
            service_endpoint("[2001:db8::10]", 7443).expect("bracketed IPv6 should parse"),
            "https://[2001:db8::10]:7443"
        );
        assert!(service_endpoint("http://centrald.home.arpa", 7443).is_err());
        assert!(service_endpoint("https://user@centrald.home.arpa", 7443).is_err());
    }
}
