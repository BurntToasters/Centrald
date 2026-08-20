use std::fs::{File, OpenOptions};
use std::io::ErrorKind;
use std::path::{Path, PathBuf};
use std::time::{Duration, Instant};

use anyhow::Context;
use centrald_common::active_pointer::{ActivePointer, ActivePointerError, PointerPublication};
#[cfg(windows)]
use centrald_common::config::windows_powershell_executable;
use centrald_common::enrollment::{EnrollmentRole, parse_enrollment_invitation};
use centrald_common::host::https_endpoint;
use centrald_common::secure_fs::write_new_file;
use centrald_protocol::v1::admin_service_client::AdminServiceClient;
use centrald_protocol::v1::enrollment_service_client::EnrollmentServiceClient;
use centrald_protocol::v1::{
    ActivateIdentityRequest, CreateEnrollmentKeyRequest, EnrollAdminRequest,
    EnrollmentKeySummary as ProtocolEnrollmentKey, GetServerSettingsRequest, IdentityRole, JobKind,
    ListEnrollmentKeysRequest, ListTargetsRequest, ProtocolVersion, RenewCertificateRequest,
    RevokeEnrollmentKeyRequest, RevokeIdentityRequest, ServerSettings, StartJobRequest,
    TargetSummary, UpdateServerSettingsRequest,
};
use chrono::{DateTime, Duration as ChronoDuration, Utc};
use fs2::FileExt;
use rcgen::{
    CertificateParams, DistinguishedName, DnType, ExtendedKeyUsagePurpose, KeyPair, KeyUsagePurpose,
};
use secrecy::{ExposeSecret, SecretString};
use serde::{Deserialize, Serialize};
use tauri::{AppHandle, Manager};
use tonic::transport::{Certificate, Channel, ClientTlsConfig, Endpoint, Identity};
use uuid::Uuid;

const PROFILE_STATE_LOCK_NAME: &str = ".centrald-profile-state.lock";
const PROFILE_STATE_LOCK_TIMEOUT: Duration = Duration::from_secs(15);

#[derive(Debug)]
struct AdminProfileLock {
    file: File,
    path: PathBuf,
}

impl AdminProfileLock {
    async fn acquire(profile_dir: &Path) -> anyhow::Result<Self> {
        let directory = profile_dir.symlink_metadata().with_context(|| {
            format!("inspect Admin profile directory {}", profile_dir.display())
        })?;
        if directory.file_type().is_symlink() || !directory.is_dir() {
            anyhow::bail!(
                "Admin profile path is not a real directory: {}",
                profile_dir.display()
            );
        }
        let path = profile_dir.join(PROFILE_STATE_LOCK_NAME);
        if let Ok(metadata) = path.symlink_metadata()
            && (metadata.file_type().is_symlink() || !metadata.is_file())
        {
            anyhow::bail!(
                "refusing unsafe Admin profile state lock {}",
                path.display()
            );
        }
        let mut options = OpenOptions::new();
        options.read(true).write(true).create(true);
        #[cfg(unix)]
        {
            use std::os::unix::fs::OpenOptionsExt;
            options.mode(0o600);
        }
        let file = options
            .open(&path)
            .with_context(|| format!("open Admin profile state lock {}", path.display()))?;
        let metadata = file
            .metadata()
            .with_context(|| format!("inspect Admin profile state lock {}", path.display()))?;
        if !metadata.is_file() {
            anyhow::bail!(
                "Admin profile state lock is not a regular file: {}",
                path.display()
            );
        }
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            file.set_permissions(std::fs::Permissions::from_mode(0o600))?;
        }

        let deadline = Instant::now() + PROFILE_STATE_LOCK_TIMEOUT;
        loop {
            match FileExt::try_lock_exclusive(&file) {
                Ok(()) => break,
                Err(error) if error.kind() == ErrorKind::WouldBlock => {
                    if Instant::now() >= deadline {
                        anyhow::bail!(
                            "Admin profile state remained busy for {} seconds: {}",
                            PROFILE_STATE_LOCK_TIMEOUT.as_secs(),
                            profile_dir.display()
                        );
                    }
                    tokio::time::sleep(Duration::from_millis(25)).await;
                }
                Err(error) => {
                    return Err(error)
                        .with_context(|| format!("lock Admin profile state {}", path.display()));
                }
            }
        }
        Ok(Self { file, path })
    }
}

impl Drop for AdminProfileLock {
    fn drop(&mut self) {
        if let Err(error) = FileExt::unlock(&self.file) {
            eprintln!(
                "warning: could not release Admin profile state lock {}: {error}",
                self.path.display()
            );
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct AdminProfile {
    id: Uuid,
    identity_id: Uuid,
    name: String,
    endpoint: String,
    server_name: String,
    root_ca: PathBuf,
    identity_certificate: PathBuf,
    identity_private_key: PathBuf,
    certificate_expires_at: DateTime<Utc>,
    /// Ed25519 elevation key used to sign shell-elevation challenges. Older
    /// profiles have no key and cannot request elevated shells until they are
    /// re-enrolled.
    #[serde(default)]
    elevation_private_key: Option<PathBuf>,
}

/// IPC view of an Admin profile. Private-key and certificate paths stay
/// process-local and are never sent to the `WebView`.
#[derive(Debug, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct AdminProfileView {
    id: Uuid,
    identity_id: Uuid,
    name: String,
    endpoint: String,
    server_name: String,
    certificate_expires_at: DateTime<Utc>,
}

impl AdminProfile {
    /// The stored elevation private key path, if this profile has one.
    #[must_use]
    pub fn elevation_private_key(&self) -> Option<&Path> {
        self.elevation_private_key.as_deref()
    }

    fn view(&self) -> AdminProfileView {
        AdminProfileView {
            id: self.id,
            identity_id: self.identity_id,
            name: self.name.clone(),
            endpoint: self.endpoint.clone(),
            server_name: self.server_name.clone(),
            certificate_expires_at: self.certificate_expires_at,
        }
    }
}

#[derive(Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct EnrollAdminInput {
    access_key: String,
    connection_override: Option<String>,
}

impl std::fmt::Debug for EnrollAdminInput {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter
            .debug_struct("EnrollAdminInput")
            .field("access_key", &"[REDACTED]")
            .field("connection_override", &self.connection_override)
            .finish()
    }
}

#[derive(Debug, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct TargetView {
    id: String,
    name: String,
    os: String,
    architecture: String,
    version: String,
    last_seen: String,
    online: bool,
    server: bool,
}

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
pub struct InvitationView {
    id: String,
    access_key: String,
    expires_at: String,
}

impl std::fmt::Debug for InvitationView {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter
            .debug_struct("InvitationView")
            .field("id", &self.id)
            .field("access_key", &"[REDACTED]")
            .field("expires_at", &self.expires_at)
            .finish()
    }
}

#[derive(Debug, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct EnrollmentKeyView {
    id: String,
    name: String,
    role: String,
    created_at: String,
    expires_at: String,
    consumed_at: String,
    revoked_at: String,
    revoked_reason: String,
    status: String,
}

#[derive(Debug, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct JobView {
    id: String,
    target_id: String,
    kind: String,
    state: i32,
    expires_at: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
#[allow(clippy::struct_excessive_bools)]
pub struct ServerSettingsView {
    revision: String,
    instance_id: String,
    public_host: String,
    enrollment_listen: String,
    client_listen: String,
    admin_listen: String,
    database_max_connections: u32,
    heartbeat_interval_seconds: u32,
    offline_after_seconds: u32,
    job_ttl_seconds: u32,
    shell_idle_timeout_seconds: u32,
    max_shell_frame_bytes: u32,
    updates_enabled: bool,
    update_channel: String,
    update_manifest_url: String,
    update_check_interval_seconds: u32,
    update_allow_prerelease: bool,
    data_dir: String,
    local_socket: String,
    database_url_env: String,
    database_environment_file: String,
    root_cert_path: String,
    local_only_fields: Vec<String>,
    restart_required: bool,
    update_latest_version: String,
    update_available: bool,
    update_last_check_error: String,
}

#[derive(Debug, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct ProfileWarning {
    directory: String,
    message: String,
}

#[derive(Debug, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct ProfileListView {
    profiles: Vec<AdminProfileView>,
    warnings: Vec<ProfileWarning>,
}

#[tauri::command]
#[allow(clippy::needless_pass_by_value)]
pub fn list_profiles(app: AppHandle) -> Result<ProfileListView, String> {
    list_profiles_inner(&app).map_err(display_error)
}

#[tauri::command]
#[allow(clippy::needless_pass_by_value)]
pub async fn enroll_admin(
    app: AppHandle,
    input: EnrollAdminInput,
) -> Result<AdminProfileView, String> {
    enroll_admin_inner(&app, input).await.map_err(display_error)
}

#[tauri::command]
#[allow(clippy::needless_pass_by_value)]
pub async fn list_targets(app: AppHandle, profile_id: String) -> Result<Vec<TargetView>, String> {
    list_targets_inner(&app, &profile_id)
        .await
        .map_err(display_error)
}

#[tauri::command]
#[allow(clippy::needless_pass_by_value)]
pub async fn create_client_invitation(
    app: AppHandle,
    profile_id: String,
    name: String,
    expires_in_seconds: u32,
) -> Result<InvitationView, String> {
    create_client_invitation_inner(&app, &profile_id, name, expires_in_seconds)
        .await
        .map_err(display_error)
}

#[tauri::command]
#[allow(clippy::needless_pass_by_value)]
pub async fn list_client_invitations(
    app: AppHandle,
    profile_id: String,
    include_inactive: bool,
) -> Result<Vec<EnrollmentKeyView>, String> {
    list_client_invitations_inner(&app, &profile_id, include_inactive)
        .await
        .map_err(display_error)
}

#[tauri::command]
#[allow(clippy::needless_pass_by_value)]
pub async fn revoke_client_invitation(
    app: AppHandle,
    profile_id: String,
    invitation_id: String,
    reason: String,
) -> Result<String, String> {
    revoke_client_invitation_inner(&app, &profile_id, invitation_id, reason)
        .await
        .map_err(display_error)
}

#[tauri::command]
#[allow(clippy::needless_pass_by_value)]
pub async fn revoke_client(
    app: AppHandle,
    profile_id: String,
    client_id: String,
    reason: String,
) -> Result<String, String> {
    revoke_client_inner(&app, &profile_id, client_id, reason)
        .await
        .map_err(display_error)
}

#[tauri::command]
#[allow(clippy::needless_pass_by_value)]
pub async fn start_job(
    app: AppHandle,
    profile_id: String,
    target_id: String,
    kind: String,
    reason: String,
    parameters_json: String,
) -> Result<JobView, String> {
    start_job_inner(&app, &profile_id, target_id, &kind, reason, parameters_json)
        .await
        .map_err(display_error)
}

#[tauri::command]
#[allow(clippy::needless_pass_by_value)]
pub async fn get_server_settings(
    app: AppHandle,
    profile_id: String,
) -> Result<ServerSettingsView, String> {
    get_server_settings_inner(&app, &profile_id)
        .await
        .map_err(display_error)
}

#[tauri::command]
#[allow(clippy::needless_pass_by_value)]
pub async fn update_server_settings(
    app: AppHandle,
    profile_id: String,
    settings: ServerSettingsView,
) -> Result<ServerSettingsView, String> {
    update_server_settings_inner(&app, &profile_id, settings)
        .await
        .map_err(display_error)
}

#[allow(clippy::too_many_lines)]
async fn enroll_admin_inner(
    app: &AppHandle,
    input: EnrollAdminInput,
) -> anyhow::Result<AdminProfileView> {
    validate_enrollment_input(&input)?;
    let access_key = SecretString::from(input.access_key);
    let claims = parse_enrollment_invitation(&access_key)?;
    if claims.role != EnrollmentRole::Admin {
        anyhow::bail!("this access key is not for an Admin identity");
    }
    if claims.expires_at <= chrono::Utc::now() {
        anyhow::bail!(
            "this Admin access key has expired (or this machine's clock is skewed); check NTP, then create a new access key from centrald-server config"
        );
    }
    let connection_host = input
        .connection_override
        .as_deref()
        .filter(|value| !value.trim().is_empty())
        .unwrap_or(&claims.server_name);
    let enrollment_endpoint = service_endpoint(connection_host, claims.enrollment_port)?;
    let admin_endpoint = service_endpoint(connection_host, claims.admin_port)?;

    let identity_key = KeyPair::generate()?;
    let mut parameters = CertificateParams::default();
    let mut name = DistinguishedName::new();
    name.push(DnType::CommonName, claims.name.clone());
    parameters.distinguished_name = name;
    parameters.key_usages = vec![KeyUsagePurpose::DigitalSignature];
    parameters.extended_key_usages = vec![ExtendedKeyUsagePurpose::ClientAuth];
    let csr = parameters.serialize_request(&identity_key)?.pem()?;

    // The elevation key proves the operator's intent for elevated shells. It
    // is generated locally, kept with the profile, and only its public half
    // is sent to the server.
    let elevation_signing_key = ed25519_dalek::SigningKey::generate(&mut rand_core_06::OsRng);
    let elevation_public_key = elevation_signing_key.verifying_key().to_bytes().to_vec();

    let profile_id = Uuid::now_v7();
    let generation_id = Uuid::now_v7();
    let profile_dir = profiles_dir(app)?.join(profile_id.to_string());
    let credential_dir = profile_dir
        .join("credentials")
        .join(generation_id.to_string());
    let identity_private_key = credential_dir.join("identity-key.pem");
    let elevation_private_key = profile_dir.join("elevation-key.pem");
    std::fs::create_dir_all(&profile_dir)
        .with_context(|| format!("create Admin profile directory {}", profile_dir.display()))?;
    let cleanup = |profile_dir: &Path| {
        if profile_dir.is_dir() {
            let _ = std::fs::remove_dir_all(profile_dir);
        }
    };
    let _profile_lock = match AdminProfileLock::acquire(&profile_dir).await {
        Ok(lock) => lock,
        Err(error) => {
            cleanup(&profile_dir);
            return Err(error.context("lock the new Admin profile directory"));
        }
    };
    if let Err(error) = prepare_profile_directories(&profile_dir, &credential_dir) {
        cleanup(&profile_dir);
        return Err(error.context("prepare Admin profile directories"));
    }
    if let Err(error) = write_new_file(
        &identity_private_key,
        identity_key.serialize_pem().as_bytes(),
        true,
    ) {
        cleanup(&profile_dir);
        return Err(anyhow::Error::from(error)
            .context("persist the Admin identity private key before enrollment"));
    }
    if let Err(error) =
        persist_elevation_key(&profile_dir, &elevation_private_key, &elevation_signing_key)
    {
        cleanup(&profile_dir);
        return Err(error.context("persist the Admin elevation key before enrollment"));
    }

    let channel = match tls_channel(
        &enrollment_endpoint,
        &claims.server_name,
        &claims.root_ca_pem,
        None,
    )
    .await
    {
        Ok(channel) => channel,
        Err(error) => {
            cleanup(&profile_dir);
            return Err(error);
        }
    };
    let response = match EnrollmentServiceClient::new(channel)
        .enroll_admin(EnrollAdminRequest {
            enrollment_key: access_key.expose_secret().to_owned(),
            csr_pem: csr.into_bytes(),
            name: claims.name.clone(),
            elevation_public_key,
            protocol: Some(ProtocolVersion {
                major: centrald_protocol::PROTOCOL_MAJOR,
                minor: centrald_protocol::PROTOCOL_MINOR,
            }),
        })
        .await
    {
        Ok(response) => response.into_inner(),
        Err(error) => {
            cleanup(&profile_dir);
            return Err(error.into());
        }
    };
    let identity_id: Uuid = match response.identity_id.parse() {
        Ok(identity_id) => identity_id,
        Err(error) => {
            cleanup(&profile_dir);
            return Err(error.into());
        }
    };
    if response.role != IdentityRole::Admin as i32 || response.certificate_chain_pem.is_empty() {
        cleanup(&profile_dir);
        anyhow::bail!("server returned incomplete Admin enrollment material");
    }

    let Some(certificate_expires_at) = timestamp_datetime(response.expires_at) else {
        cleanup(&profile_dir);
        anyhow::bail!("server returned an invalid Admin certificate expiration");
    };
    let profile = AdminProfile {
        id: profile_id,
        identity_id,
        name: claims.name,
        endpoint: admin_endpoint,
        server_name: claims.server_name,
        root_ca: credential_dir.join("root-ca.pem"),
        identity_certificate: credential_dir.join("identity-chain.pem"),
        identity_private_key,
        certificate_expires_at,
        elevation_private_key: Some(elevation_private_key),
    };
    if let Err(error) = persist_profile_generation(
        &profile_dir,
        generation_id,
        &profile,
        claims.root_ca_pem.as_bytes(),
        &response.certificate_chain_pem,
        None,
    ) {
        cleanup(&profile_dir);
        return Err(error.context(
            "server accepted a pending Admin enrollment, but local profile persistence failed; the pending identity will expire automatically",
        ));
    }
    let publication = match publish_active_profile(&profile_dir, generation_id) {
        Ok(publication) => publication,
        Err(error) => {
            cleanup(&profile_dir);
            return Err(error.context("publish the enrolled Admin credential generation"));
        }
    };
    if let Err(error) = activate_admin_profile(&profile).await {
        if let Err(rollback_error) = publication.rollback() {
            return Err(error.context(format!(
                "Admin identity activation failed and pointer rollback also failed; the published generation was retained for recovery: {rollback_error}"
            )));
        }
        cleanup(&profile_dir);
        return Err(error.context(
            "durable Admin identity was not activated; local publication was rolled back and the pending server identity will expire",
        ));
    }
    publication
        .commit()
        .context("finalize the active Admin credential pointer")?;
    secure_profile_tree(&profile_dir)?;
    Ok(profile.view())
}

fn persist_profile_generation(
    profile_dir: &Path,
    generation_id: Uuid,
    profile: &AdminProfile,
    root_ca: &[u8],
    identity_certificate: &[u8],
    identity_private_key: Option<&[u8]>,
) -> anyhow::Result<()> {
    let metadata_path = profile_dir.join(format!("profile-{generation_id}.json"));
    let credential_dir = profile
        .identity_private_key
        .parent()
        .ok_or_else(|| anyhow::anyhow!("Admin credential path has no parent"))?;
    let result = (|| {
        prepare_profile_directories(profile_dir, credential_dir)?;
        write_new_file(&profile.root_ca, root_ca, false)?;
        write_new_file(&profile.identity_certificate, identity_certificate, false)?;
        if let Some(identity_private_key) = identity_private_key {
            write_new_file(&profile.identity_private_key, identity_private_key, true)?;
        }
        secure_profile_tree(profile_dir)?;
        let metadata = serde_json::to_vec_pretty(profile)?;
        // The uniquely named profile document is the publication point. A
        // failed write never replaces the previously active credential set.
        write_new_file(&metadata_path, &metadata, true)?;
        secure_profile_tree(profile_dir)?;
        Ok::<(), anyhow::Error>(())
    })();
    if result.is_err() {
        if metadata_path.is_file() {
            let _ = std::fs::remove_file(&metadata_path);
        }
        if credential_dir.is_dir() {
            let _ = std::fs::remove_dir_all(credential_dir);
        }
    }
    result
}

fn persist_elevation_key(
    profile_dir: &Path,
    path: &Path,
    key: &ed25519_dalek::SigningKey,
) -> anyhow::Result<()> {
    use ed25519_dalek::pkcs8::EncodePrivateKey;

    let bytes = key
        .to_pkcs8_pem(pkcs8::LineEnding::LF)
        .context("encode the Admin elevation private key")?;
    write_new_file(path, bytes.as_bytes(), true)
        .with_context(|| format!("write Admin elevation key {}", path.display()))?;
    secure_profile_tree(profile_dir)
}

fn prepare_profile_directories(profile_dir: &Path, credential_dir: &Path) -> anyhow::Result<()> {
    std::fs::create_dir_all(credential_dir)?;
    secure_profile_tree(profile_dir)
}

#[cfg(unix)]
fn secure_profile_tree(profile_dir: &Path) -> anyhow::Result<()> {
    use std::os::unix::fs::PermissionsExt;

    for directory in [profile_dir.to_path_buf(), profile_dir.join("credentials")] {
        if directory.is_dir() {
            std::fs::set_permissions(&directory, std::fs::Permissions::from_mode(0o700))?;
        }
    }
    if profile_dir.join("credentials").is_dir() {
        for entry in std::fs::read_dir(profile_dir.join("credentials"))? {
            let entry = entry?;
            if entry.file_type()?.is_dir() {
                std::fs::set_permissions(entry.path(), std::fs::Permissions::from_mode(0o700))?;
            }
        }
    }
    Ok(())
}

#[cfg(windows)]
fn secure_profile_tree(profile_dir: &Path) -> anyhow::Result<()> {
    use std::process::Command;

    const SCRIPT: &str = r#"
$ErrorActionPreference = 'Stop'
$Path = $env:CENTRALD_ACL_PATH
if ([string]::IsNullOrWhiteSpace($Path)) { throw 'CENTRALD_ACL_PATH is missing' }
$current = [System.Security.Principal.WindowsIdentity]::GetCurrent().User
$system = [System.Security.Principal.SecurityIdentifier]::new('S-1-5-18')
function Set-CentralDAcl([System.IO.FileSystemInfo]$Item) {
  if (($Item.Attributes -band [System.IO.FileAttributes]::ReparsePoint) -ne 0) {
    throw "Refusing reparse point: $($Item.FullName)"
  }
  if ($Item.PSIsContainer) {
    $acl = [System.Security.AccessControl.DirectorySecurity]::new()
    $inherit = [System.Security.AccessControl.InheritanceFlags]'ContainerInherit, ObjectInherit'
  } else {
    $acl = [System.Security.AccessControl.FileSecurity]::new()
    $inherit = [System.Security.AccessControl.InheritanceFlags]::None
  }
  $acl.SetAccessRuleProtection($true, $false)
  $acl.SetOwner($current)
  $propagation = [System.Security.AccessControl.PropagationFlags]::None
  $allow = [System.Security.AccessControl.AccessControlType]::Allow
  $acl.AddAccessRule([System.Security.AccessControl.FileSystemAccessRule]::new($current, 'FullControl', $inherit, $propagation, $allow))
  $acl.AddAccessRule([System.Security.AccessControl.FileSystemAccessRule]::new($system, 'FullControl', $inherit, $propagation, $allow))
  Set-Acl -LiteralPath $Item.FullName -AclObject $acl
}
$root = Get-Item -LiteralPath $Path -Force
$maximumItems = 4096
$items = [System.Collections.Generic.List[System.IO.FileSystemInfo]]::new()
$items.Add($root)
Get-ChildItem -LiteralPath $Path -Force -Recurse | ForEach-Object {
  if ($items.Count -ge $maximumItems) {
    throw "CentralD Admin profile contains more than $maximumItems entries; refusing recursive ACL replacement"
  }
  if (($_.Attributes -band [System.IO.FileAttributes]::ReparsePoint) -ne 0) {
    throw "Refusing reparse point: $($_.FullName)"
  }
  $items.Add($_)
}
foreach ($item in $items) { Set-CentralDAcl $item }
"#;
    let powershell = windows_powershell_executable()
        .context("Windows did not return its trusted system directory")?;
    let status = Command::new(powershell)
        .args([
            "-NoLogo",
            "-NoProfile",
            "-NonInteractive",
            "-Command",
            SCRIPT,
        ])
        .env("CENTRALD_ACL_PATH", profile_dir)
        .status()
        .context("apply owner-only ACL to CentralD Admin profile")?;
    if !status.success() {
        anyhow::bail!("could not protect CentralD Admin profile with an owner/SYSTEM-only ACL");
    }
    Ok(())
}

#[cfg(not(any(unix, windows)))]
fn secure_profile_tree(_profile_dir: &Path) -> anyhow::Result<()> {
    anyhow::bail!("unsupported Admin operating system")
}

async fn list_targets_inner(app: &AppHandle, profile_id: &str) -> anyhow::Result<Vec<TargetView>> {
    let mut client = admin_client(app, profile_id).await?;
    let response = client
        .list_targets(ListTargetsRequest {})
        .await?
        .into_inner();
    Ok(response.targets.into_iter().map(target_view).collect())
}

async fn create_client_invitation_inner(
    app: &AppHandle,
    profile_id: &str,
    name: String,
    expires_in_seconds: u32,
) -> anyhow::Result<InvitationView> {
    if name.trim().is_empty() || name.len() > 128 {
        anyhow::bail!("client name must be 1-128 characters");
    }
    if !(60..=86_400).contains(&expires_in_seconds) {
        anyhow::bail!("expiry must be between 60 seconds and 24 hours");
    }
    let response = admin_client(app, profile_id)
        .await?
        .create_enrollment_key(CreateEnrollmentKeyRequest {
            role: IdentityRole::Client as i32,
            name,
            expires_in_seconds,
        })
        .await?
        .into_inner();
    Ok(InvitationView {
        id: response.id,
        access_key: response.enrollment_key,
        expires_at: timestamp_text(response.expires_at),
    })
}

async fn list_client_invitations_inner(
    app: &AppHandle,
    profile_id: &str,
    include_inactive: bool,
) -> anyhow::Result<Vec<EnrollmentKeyView>> {
    let response = admin_client(app, profile_id)
        .await?
        .list_enrollment_keys(ListEnrollmentKeysRequest {
            role: IdentityRole::Client as i32,
            include_inactive,
        })
        .await?
        .into_inner();
    Ok(response.keys.into_iter().map(enrollment_key_view).collect())
}

async fn revoke_client_invitation_inner(
    app: &AppHandle,
    profile_id: &str,
    invitation_id: String,
    reason: String,
) -> anyhow::Result<String> {
    let _: Uuid = invitation_id.parse()?;
    if reason.trim().is_empty() || reason.len() > 512 || reason.chars().any(char::is_control) {
        anyhow::bail!("revocation reason must be 1-512 printable characters");
    }
    let response = admin_client(app, profile_id)
        .await?
        .revoke_enrollment_key(RevokeEnrollmentKeyRequest {
            enrollment_key_id: invitation_id,
            reason,
        })
        .await?
        .into_inner();
    if !response.success {
        anyhow::bail!(response.message);
    }
    Ok(response.message)
}

async fn revoke_client_inner(
    app: &AppHandle,
    profile_id: &str,
    client_id: String,
    reason: String,
) -> anyhow::Result<String> {
    let response = admin_client(app, profile_id)
        .await?
        .revoke_identity(RevokeIdentityRequest {
            identity_id: client_id,
            reason,
            force_last_admin: false,
        })
        .await?
        .into_inner();
    if !response.success {
        anyhow::bail!(response.message);
    }
    Ok(response.message)
}

async fn start_job_inner(
    app: &AppHandle,
    profile_id: &str,
    target_id: String,
    kind: &str,
    reason: String,
    parameters_json: String,
) -> anyhow::Result<JobView> {
    if !centrald_common::PRIVILEGED_OPERATIONS_ENABLED {
        anyhow::bail!("privileged client jobs are unavailable in this alpha release");
    }
    let (job_kind, kind_name) = parse_job_kind(kind)?;
    let parameters_json = parameters_json.trim();
    let parameters: serde_json::Value =
        serde_json::from_str(parameters_json).context("job parameters must be a JSON object")?;
    if !parameters.is_object() {
        anyhow::bail!("job parameters must be a JSON object");
    }
    let response = admin_client(app, profile_id)
        .await?
        .start_job(StartJobRequest {
            request_id: Uuid::now_v7().to_string(),
            target_id,
            kind: job_kind as i32,
            parameters_json: serde_json::to_vec(&parameters)?,
            reason,
        })
        .await?
        .into_inner();
    Ok(JobView {
        id: response.id,
        target_id: response.target_id,
        kind: kind_name.into(),
        state: response.state,
        expires_at: timestamp_text(response.expires_at),
    })
}

async fn get_server_settings_inner(
    app: &AppHandle,
    profile_id: &str,
) -> anyhow::Result<ServerSettingsView> {
    let response = admin_client(app, profile_id)
        .await?
        .get_server_settings(GetServerSettingsRequest {})
        .await?
        .into_inner();
    Ok(settings_view(response))
}

async fn update_server_settings_inner(
    app: &AppHandle,
    profile_id: &str,
    settings: ServerSettingsView,
) -> anyhow::Result<ServerSettingsView> {
    let expected_revision = settings.revision.clone();
    let response = admin_client(app, profile_id)
        .await?
        .update_server_settings(UpdateServerSettingsRequest {
            expected_revision,
            settings: Some(settings_proto(settings)),
        })
        .await?
        .into_inner();
    Ok(settings_view(response))
}

const ADMIN_CERTIFICATE_RENEWAL_WINDOW_DAYS: i64 = 30;

pub(crate) async fn admin_client(
    app: &AppHandle,
    profile_id: &str,
) -> anyhow::Result<AdminServiceClient<Channel>> {
    let id: Uuid = profile_id.parse()?;
    let profile_dir = profiles_dir(app)?.join(id.to_string());
    let _profile_lock = AdminProfileLock::acquire(&profile_dir)
        .await
        .context("wait for another Admin credential state transition")?;
    let mut profile = load_profile_from_dir(&profile_dir)?;
    if profile.id != id {
        anyhow::bail!("Admin profile identity does not match its protected directory");
    }
    if let Err(error) = activate_admin_profile(&profile).await {
        if rollback_active_profile_if_previous(&profile_dir)? {
            return Err(error.context(
                "activate Admin credential generation; restored the previous active credential",
            ));
        }
        return Err(error);
    }
    commit_active_profile(&profile_dir).context("finalize recovered Admin credential pointer")?;
    if profile.certificate_expires_at
        <= Utc::now() + ChronoDuration::days(ADMIN_CERTIFICATE_RENEWAL_WINDOW_DAYS)
    {
        match renew_admin_profile(&profile_dir, &profile).await {
            Ok(replacement) => profile = replacement,
            Err(error) if profile.certificate_expires_at > Utc::now() => {
                eprintln!(
                    "CentralD Admin certificate renewal is due but failed; retrying with the current unexpired identity: {error:#}"
                );
            }
            Err(error) => return Err(error),
        }
    }
    admin_client_for_profile(&profile).await
}

async fn renew_admin_profile(
    profile_dir: &Path,
    profile: &AdminProfile,
) -> anyhow::Result<AdminProfile> {
    if profile.certificate_expires_at <= Utc::now() {
        anyhow::bail!(
            "Admin certificate expired; revoke this Admin on the server and enroll a new access key"
        );
    }
    let identity_key = KeyPair::generate()?;
    let mut parameters = CertificateParams::default();
    let mut name = DistinguishedName::new();
    name.push(DnType::CommonName, profile.name.clone());
    parameters.distinguished_name = name;
    parameters.key_usages = vec![KeyUsagePurpose::DigitalSignature];
    parameters.extended_key_usages = vec![ExtendedKeyUsagePurpose::ClientAuth];
    let csr = parameters.serialize_request(&identity_key)?.pem()?;
    let response = admin_client_for_profile(profile)
        .await?
        .renew_admin_certificate(RenewCertificateRequest {
            csr_pem: csr.into_bytes(),
            protocol: Some(ProtocolVersion {
                major: centrald_protocol::PROTOCOL_MAJOR,
                minor: centrald_protocol::PROTOCOL_MINOR,
            }),
        })
        .await?
        .into_inner();
    if response.certificate_chain_pem.is_empty() {
        anyhow::bail!("server returned an empty renewed Admin certificate chain");
    }
    let certificate_expires_at = timestamp_datetime(response.expires_at).ok_or_else(|| {
        anyhow::anyhow!("server returned an invalid renewed certificate expiration")
    })?;
    if certificate_expires_at <= Utc::now() + ChronoDuration::days(1) {
        anyhow::bail!("server returned a renewed Admin certificate with an unsafe expiration");
    }

    let generation_id = Uuid::now_v7();
    let credential_dir = profile_dir
        .join("credentials")
        .join(generation_id.to_string());
    let mut replacement = profile.clone();
    replacement.root_ca = credential_dir.join("root-ca.pem");
    replacement.identity_certificate = credential_dir.join("identity-chain.pem");
    replacement.identity_private_key = credential_dir.join("identity-key.pem");
    replacement.certificate_expires_at = certificate_expires_at;
    let root_ca = std::fs::read(&profile.root_ca)?;
    persist_profile_generation(
        profile_dir,
        generation_id,
        &replacement,
        &root_ca,
        &response.certificate_chain_pem,
        Some(identity_key.serialize_pem().as_bytes()),
    )?;
    let publication = match publish_active_profile(profile_dir, generation_id) {
        Ok(publication) => publication,
        Err(error) => {
            cleanup_profile_generation(profile_dir, generation_id, &replacement);
            return Err(error.context("publish renewed Admin credential generation"));
        }
    };
    if let Err(error) = activate_admin_profile(&replacement).await {
        if let Err(rollback_error) = publication.rollback() {
            return Err(error.context(format!(
                "renewed Admin activation failed and pointer rollback also failed; the published generation was retained for recovery: {rollback_error}"
            )));
        }
        cleanup_profile_generation(profile_dir, generation_id, &replacement);
        return Err(error.context("activate renewed Admin certificate after durable publication"));
    }
    publication
        .commit()
        .context("finalize renewed Admin credential pointer")?;
    secure_profile_tree(profile_dir)?;
    Ok(replacement)
}

async fn activate_admin_profile(profile: &AdminProfile) -> anyhow::Result<()> {
    let response = admin_client_for_profile(profile)
        .await?
        .activate_admin_identity(ActivateIdentityRequest {
            identity_id: profile.identity_id.to_string(),
            protocol: Some(ProtocolVersion {
                major: centrald_protocol::PROTOCOL_MAJOR,
                minor: centrald_protocol::PROTOCOL_MINOR,
            }),
        })
        .await
        .context("activate Admin identity")?
        .into_inner();
    if !response.success {
        anyhow::bail!(
            "server rejected Admin identity activation: {}",
            response.message
        );
    }
    Ok(())
}

fn cleanup_profile_generation(profile_dir: &Path, generation_id: Uuid, profile: &AdminProfile) {
    let metadata_path = profile_dir.join(format!("profile-{generation_id}.json"));
    let _ = std::fs::remove_file(metadata_path);
    if let Some(credential_dir) = profile.identity_private_key.parent() {
        let _ = std::fs::remove_dir_all(credential_dir);
    }
}

async fn admin_client_for_profile(
    profile: &AdminProfile,
) -> anyhow::Result<AdminServiceClient<Channel>> {
    let root = std::fs::read(&profile.root_ca)?;
    let certificate = std::fs::read(&profile.identity_certificate)?;
    let private_key = std::fs::read(&profile.identity_private_key)?;
    let channel = tls_channel(
        &profile.endpoint,
        &profile.server_name,
        std::str::from_utf8(&root)?,
        Some(Identity::from_pem(certificate, private_key)),
    )
    .await?;
    Ok(AdminServiceClient::new(channel))
}

pub(crate) fn load_profile_from_dir(profile_dir: &Path) -> anyhow::Result<AdminProfile> {
    let path = latest_profile_path(profile_dir)?;
    Ok(serde_json::from_slice(&std::fs::read(path)?)?)
}

fn latest_profile_path(profile_dir: &Path) -> anyhow::Result<PathBuf> {
    let pointer = profile_pointer(profile_dir)?;
    let filename = match pointer.read() {
        Ok(filename) => filename,
        Err(ActivePointerError::Missing) => {
            anyhow::bail!("Admin profile has no activated credential generation")
        }
        Err(error) => return Err(error.into()),
    };
    validate_profile_target(profile_dir, &filename)
}

fn publish_active_profile(
    profile_dir: &Path,
    generation_id: Uuid,
) -> anyhow::Result<PointerPublication> {
    let filename = format!("profile-{generation_id}.json");
    validate_profile_target(profile_dir, &filename)?;
    let pointer = profile_pointer(profile_dir)?;
    let publication = pointer.publish(&filename)?;
    if let Err(error) = secure_profile_tree(profile_dir) {
        if let Err(rollback_error) = publication.rollback() {
            return Err(error.context(format!(
                "secure Admin pointer files failed and rollback also failed: {rollback_error}"
            )));
        }
        return Err(error);
    }
    Ok(publication)
}

fn commit_active_profile(profile_dir: &Path) -> anyhow::Result<()> {
    profile_pointer(profile_dir)?.commit_recovered()?;
    secure_profile_tree(profile_dir)
}

fn rollback_active_profile_if_previous(profile_dir: &Path) -> anyhow::Result<bool> {
    let rolled_back = profile_pointer(profile_dir)?.rollback_recovered_if_previous()?;
    secure_profile_tree(profile_dir)?;
    Ok(rolled_back)
}

fn profile_pointer(profile_dir: &Path) -> anyhow::Result<ActivePointer> {
    ActivePointer::new(profile_dir.to_path_buf()).map_err(Into::into)
}

fn validate_profile_target(profile_dir: &Path, filename: &str) -> anyhow::Result<PathBuf> {
    let candidate = Path::new(filename);
    if filename.is_empty()
        || candidate.is_absolute()
        || candidate.components().count() != 1
        || !filename.starts_with("profile-")
        || !filename.to_ascii_lowercase().ends_with(".json")
    {
        anyhow::bail!("active Admin profile pointer is invalid");
    }
    let path = profile_dir.join(candidate);
    let metadata = path
        .symlink_metadata()
        .with_context(|| format!("inspect active Admin profile {}", path.display()))?;
    if metadata.file_type().is_symlink() || !metadata.is_file() {
        anyhow::bail!(
            "active Admin profile is not a regular file: {}",
            path.display()
        );
    }
    Ok(path)
}

fn list_profiles_inner(app: &AppHandle) -> anyhow::Result<ProfileListView> {
    let directory = profiles_dir(app)?;
    if !directory.exists() {
        return Ok(ProfileListView {
            profiles: Vec::new(),
            warnings: Vec::new(),
        });
    }
    let mut profiles = Vec::new();
    let mut warnings = Vec::new();
    for entry_result in std::fs::read_dir(directory)? {
        let entry = match entry_result {
            Ok(entry) => entry,
            Err(error) => {
                warnings.push(ProfileWarning {
                    directory: "<unreadable-entry>".into(),
                    message: error.to_string(),
                });
                continue;
            }
        };
        let is_directory = match entry.file_type() {
            Ok(file_type) => file_type.is_dir(),
            Err(error) => {
                warnings.push(ProfileWarning {
                    directory: entry.file_name().to_string_lossy().into_owned(),
                    message: format!("could not inspect profile directory: {error}"),
                });
                continue;
            }
        };
        if !is_directory {
            continue;
        }
        let profile_result = latest_profile_path(&entry.path()).and_then(|metadata| {
            let raw = std::fs::read(&metadata)?;
            Ok(serde_json::from_slice::<AdminProfile>(&raw)?)
        });
        match profile_result {
            Ok(profile) => profiles.push(profile.view()),
            Err(error) => warnings.push(ProfileWarning {
                directory: entry.file_name().to_string_lossy().into_owned(),
                message: error.to_string(),
            }),
        }
    }
    profiles.sort_by(|left: &AdminProfileView, right| left.name.cmp(&right.name));
    warnings.sort_by(|left, right| left.directory.cmp(&right.directory));
    Ok(ProfileListView { profiles, warnings })
}

async fn tls_channel(
    endpoint: &str,
    server_name: &str,
    root_pem: &str,
    identity: Option<Identity>,
) -> anyhow::Result<Channel> {
    let mut tls = ClientTlsConfig::new()
        .domain_name(server_name.to_owned())
        .ca_certificate(Certificate::from_pem(root_pem));
    if let Some(identity) = identity {
        tls = tls.identity(identity);
    }
    Ok(Endpoint::from_shared(endpoint.to_owned())?
        .connect_timeout(std::time::Duration::from_secs(10))
        .timeout(std::time::Duration::from_secs(30))
        .tls_config(tls)?
        .connect()
        .await?)
}

fn service_endpoint(input: &str, port: u16) -> anyhow::Result<String> {
    https_endpoint(input, port).map_err(anyhow::Error::from)
}

fn validate_enrollment_input(input: &EnrollAdminInput) -> anyhow::Result<()> {
    if input.access_key.len() < 80 {
        anyhow::bail!("Admin access key is invalid");
    }
    Ok(())
}

fn parse_job_kind(value: &str) -> anyhow::Result<(JobKind, &'static str)> {
    match value {
        "restart-client-service" => Ok((JobKind::RestartClientService, "restart-client-service")),
        "restart-machine" => Ok((JobKind::RestartMachine, "restart-machine")),
        "check-os-updates" => Ok((JobKind::CheckOsUpdates, "check-os-updates")),
        "apply-os-updates" => Ok((JobKind::ApplyOsUpdates, "apply-os-updates")),
        "update-client" => Ok((JobKind::UpdateClient, "update-client")),
        _ => anyhow::bail!("unsupported job kind"),
    }
}

fn settings_view(settings: ServerSettings) -> ServerSettingsView {
    ServerSettingsView {
        revision: settings.revision,
        instance_id: settings.instance_id,
        public_host: settings.public_host,
        enrollment_listen: settings.enrollment_listen,
        client_listen: settings.client_listen,
        admin_listen: settings.admin_listen,
        database_max_connections: settings.database_max_connections,
        heartbeat_interval_seconds: settings.heartbeat_interval_seconds,
        offline_after_seconds: settings.offline_after_seconds,
        job_ttl_seconds: settings.job_ttl_seconds,
        shell_idle_timeout_seconds: settings.shell_idle_timeout_seconds,
        max_shell_frame_bytes: settings.max_shell_frame_bytes,
        updates_enabled: settings.updates_enabled,
        update_channel: settings.update_channel,
        update_manifest_url: settings.update_manifest_url,
        update_check_interval_seconds: settings.update_check_interval_seconds,
        update_allow_prerelease: settings.update_allow_prerelease,
        data_dir: settings.data_dir,
        local_socket: settings.local_socket,
        database_url_env: settings.database_url_env,
        database_environment_file: settings.database_environment_file,
        root_cert_path: settings.root_cert_path,
        local_only_fields: settings.local_only_fields,
        restart_required: settings.restart_required,
        update_latest_version: settings.update_latest_version,
        update_available: settings.update_available,
        update_last_check_error: settings.update_last_check_error,
    }
}

fn settings_proto(settings: ServerSettingsView) -> ServerSettings {
    ServerSettings {
        revision: settings.revision,
        instance_id: settings.instance_id,
        public_host: settings.public_host,
        enrollment_listen: settings.enrollment_listen,
        client_listen: settings.client_listen,
        admin_listen: settings.admin_listen,
        database_max_connections: settings.database_max_connections,
        heartbeat_interval_seconds: settings.heartbeat_interval_seconds,
        offline_after_seconds: settings.offline_after_seconds,
        job_ttl_seconds: settings.job_ttl_seconds,
        shell_idle_timeout_seconds: settings.shell_idle_timeout_seconds,
        max_shell_frame_bytes: settings.max_shell_frame_bytes,
        updates_enabled: settings.updates_enabled,
        update_channel: settings.update_channel,
        update_manifest_url: settings.update_manifest_url,
        update_check_interval_seconds: settings.update_check_interval_seconds,
        update_allow_prerelease: settings.update_allow_prerelease,
        data_dir: settings.data_dir,
        local_socket: settings.local_socket,
        database_url_env: settings.database_url_env,
        database_environment_file: settings.database_environment_file,
        root_cert_path: settings.root_cert_path,
        local_only_fields: settings.local_only_fields,
        restart_required: settings.restart_required,
        update_latest_version: settings.update_latest_version,
        update_available: settings.update_available,
        update_last_check_error: settings.update_last_check_error,
    }
}

pub(crate) fn profiles_dir(app: &AppHandle) -> anyhow::Result<PathBuf> {
    Ok(app.path().app_data_dir()?.join("profiles"))
}

fn target_view(target: TargetSummary) -> TargetView {
    TargetView {
        id: target.id,
        name: target.name,
        os: target.os,
        architecture: target.architecture,
        version: target.version,
        last_seen: timestamp_text(target.last_seen),
        online: target.online,
        server: target.server,
    }
}

fn enrollment_key_view(key: ProtocolEnrollmentKey) -> EnrollmentKeyView {
    let expires_at_value = timestamp_datetime(key.expires_at);
    let status = if key.revoked_at.is_some() {
        "revoked"
    } else if key.consumed_at.is_some() {
        "consumed"
    } else if expires_at_value.is_some_and(|expires_at| expires_at <= Utc::now()) {
        "expired"
    } else {
        "pending"
    };
    let role = IdentityRole::try_from(key.role).map_or_else(
        |_| "unknown".to_owned(),
        |role| match role {
            IdentityRole::Client => "client".to_owned(),
            IdentityRole::Admin => "admin".to_owned(),
            IdentityRole::Unspecified => "unspecified".to_owned(),
        },
    );
    EnrollmentKeyView {
        id: key.id,
        name: key.name,
        role,
        created_at: timestamp_text(key.created_at),
        expires_at: timestamp_text(key.expires_at),
        consumed_at: timestamp_text(key.consumed_at),
        revoked_at: timestamp_text(key.revoked_at),
        revoked_reason: key.revoked_reason,
        status: status.to_owned(),
    }
}

fn timestamp_datetime(value: Option<prost_types::Timestamp>) -> Option<DateTime<Utc>> {
    value.and_then(|timestamp| {
        u32::try_from(timestamp.nanos)
            .ok()
            .and_then(|nanos| DateTime::from_timestamp(timestamp.seconds, nanos))
    })
}

fn timestamp_text(value: Option<prost_types::Timestamp>) -> String {
    timestamp_datetime(value).map_or_else(String::new, |timestamp| timestamp.to_rfc3339())
}

fn display_error(error: impl std::fmt::Display) -> String {
    error.to_string()
}

#[cfg(test)]
#[allow(clippy::unwrap_used)]
mod tests {
    use super::*;

    #[test]
    fn connection_override_uses_strict_host_and_invitation_port() {
        assert_eq!(
            service_endpoint("192.0.2.5", 7445).unwrap(),
            "https://192.0.2.5:7445"
        );
        assert_eq!(
            service_endpoint("2001:db8::5", 7445).unwrap(),
            "https://[2001:db8::5]:7445"
        );
        assert!(service_endpoint("192.0.2.5:1234", 7445).is_err());
    }
}
