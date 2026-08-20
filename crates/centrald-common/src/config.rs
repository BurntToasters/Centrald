use std::net::SocketAddr;
use std::path::{Path, PathBuf};

use serde::{Deserialize, Serialize};
use thiserror::Error;
use url::Url;

use crate::host::canonical_host;
use crate::secure_fs::validate_no_symlink_ancestors;
use uuid::Uuid;

pub const SERVER_CONFIG_SCHEMA_VERSION: u32 = 1;
pub const SERVER_DATABASE_URL_ENV: &str = "CENTRALD_DATABASE_URL";
pub const SERVER_DATA_DIR: &str = "/var/lib/centrald";
pub const SERVER_LOCAL_SOCKET: &str = "/run/centrald/server.sock";
pub const SERVER_DATABASE_ENV_FILE: &str = "/etc/centrald/server.env";

/// Returns the one supported client state root for the current platform.
///
/// This location is intentionally not configurable. Privileged repair and
/// service ACL operations must never take their target root from daemon-writable
/// configuration or process environment variables.
///
/// # Errors
///
/// Returns a `ConfigError` when the Windows known-folder lookup fails.
#[cfg(windows)]
pub fn client_data_dir() -> Result<PathBuf, ConfigError> {
    crate::windows_paths::program_data_dir()
        .map(|directory| directory.join("CentralD"))
        .ok_or(ConfigError::PlatformPath(
            "Windows did not return FOLDERID_ProgramData; refusing to guess a machine state path",
        ))
}

/// Returns the one supported client state root on Unix platforms.
///
/// # Errors
///
/// Returns a `ConfigError` when the Unix state root cannot be constructed.
#[cfg(not(windows))]
pub fn client_data_dir() -> Result<PathBuf, ConfigError> {
    Ok(PathBuf::from("/var/lib/centrald-client"))
}

/// Returns the administrator-owned Windows service-start policy marker.
///
/// The managed client account has read/execute access to the installation
/// directory but must not be able to change this operator policy.
///
/// # Errors
///
/// Returns a `ConfigError` when the Windows known-folder lookup fails.
#[cfg(windows)]
pub fn client_manual_start_marker() -> Result<PathBuf, ConfigError> {
    Ok(client_install_dir()?.join("manual-start.optout"))
}

/// Returns the package-managed Windows installation directory without trusting
/// `ProgramFiles` from the process environment or guessing a drive on failure.
///
/// # Errors
///
/// Returns a `ConfigError` when the Windows known-folder lookup fails.
#[cfg(windows)]
pub fn client_install_dir() -> Result<PathBuf, ConfigError> {
    crate::windows_paths::program_files_dir()
        .map(|directory| directory.join("CentralD"))
        .ok_or(ConfigError::PlatformPath(
            "Windows did not return FOLDERID_ProgramFiles; refusing to guess an installation path",
        ))
}

/// Returns an executable in the native Windows system directory without PATH
/// or environment-variable lookup.
#[cfg(windows)]
#[must_use]
pub fn windows_system_executable(name: &str) -> Option<PathBuf> {
    crate::windows_paths::system_directory().map(|directory| directory.join(name))
}

/// Returns the in-box Windows PowerShell executable without PATH lookup.
/// Failure to query the system directory is propagated by callers rather than
/// falling back to a potentially attacker-controlled hard-coded drive.
#[cfg(windows)]
#[must_use]
pub fn windows_powershell_executable() -> Option<PathBuf> {
    crate::windows_paths::system_directory().map(|directory| {
        directory
            .join("WindowsPowerShell")
            .join("v1.0")
            .join("powershell.exe")
    })
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ServerConfig {
    pub schema_version: u32,
    pub server: ServerSection,
    pub database: DatabaseSection,
    pub pki: ServerPkiSection,
    pub runtime: RuntimeSection,
    pub updates: UpdateSection,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ServerSection {
    pub instance_id: Uuid,
    pub public_host: String,
    pub enrollment_listen: SocketAddr,
    pub client_listen: SocketAddr,
    pub admin_listen: SocketAddr,
    pub data_dir: PathBuf,
    pub local_socket: PathBuf,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct DatabaseSection {
    pub url_env: String,
    pub environment_file: PathBuf,
    pub max_connections: u32,
    /// Dedicated local `PostgreSQL` role created by the guided setup, when used.
    pub managed_local_role: Option<String>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ServerPkiSection {
    pub root_cert: PathBuf,
    pub server_chain: PathBuf,
    pub server_key: PathBuf,
    pub server_issuer_cert: PathBuf,
    pub server_issuer_key: PathBuf,
    pub client_issuer_cert: PathBuf,
    pub client_issuer_key: PathBuf,
    pub admin_issuer_cert: PathBuf,
    pub admin_issuer_key: PathBuf,
    pub grant_signing_key: PathBuf,
    pub grant_signing_public_key: PathBuf,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct RuntimeSection {
    pub heartbeat_interval_seconds: u32,
    pub offline_after_seconds: u32,
    pub job_ttl_seconds: u32,
    pub shell_idle_timeout_seconds: u32,
    pub max_shell_frame_bytes: u32,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct UpdateSection {
    pub enabled: bool,
    pub channel: String,
    pub manifest_url: String,
    pub check_interval_seconds: u32,
    pub allow_prerelease: bool,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ClientConfig {
    pub identity_id: Uuid,
    pub identity_name: String,
    pub endpoint: String,
    pub server_name: String,
    pub data_dir: PathBuf,
    pub identity_cert: PathBuf,
    pub identity_key: PathBuf,
    pub root_ca: PathBuf,
    pub grant_signing_public_key: PathBuf,
    pub certificate_expires_at: chrono::DateTime<chrono::Utc>,
}

#[derive(Debug, Error)]
pub enum ConfigError {
    #[error("could not read config {path}: {source}")]
    Read {
        path: PathBuf,
        source: std::io::Error,
    },
    #[error("invalid TOML in {path}: {source}")]
    Parse {
        path: PathBuf,
        source: toml::de::Error,
    },
    #[error("invalid configuration: {0}")]
    Validation(String),
    #[error("required platform path is unavailable: {0}")]
    PlatformPath(&'static str),
}

impl ServerConfig {
    /// Loads and validates a server configuration from a TOML file.
    ///
    /// # Errors
    ///
    /// Returns an error when the file cannot be read, TOML parsing fails, or
    /// a required security or listener invariant is violated.
    pub fn load(path: &Path) -> Result<Self, ConfigError> {
        let raw = std::fs::read_to_string(path).map_err(|source| ConfigError::Read {
            path: path.to_path_buf(),
            source,
        })?;
        let config: Self = toml::from_str(&raw).map_err(|source| ConfigError::Parse {
            path: path.to_path_buf(),
            source,
        })?;
        config.validate()?;
        Ok(config)
    }

    /// Validates every persisted server setting.
    ///
    /// # Errors
    ///
    /// Returns [`ConfigError::Validation`] when an invariant is violated.
    pub fn validate(&self) -> Result<(), ConfigError> {
        if self.schema_version != SERVER_CONFIG_SCHEMA_VERSION {
            return invalid(format!(
                "unsupported schema_version {}; expected {}",
                self.schema_version, SERVER_CONFIG_SCHEMA_VERSION
            ));
        }
        if self.server.instance_id.is_nil() {
            return invalid("server.instance_id must not be nil");
        }
        validate_host(&self.server.public_host, "server.public_host")?;
        if self.database.url_env != SERVER_DATABASE_URL_ENV {
            return invalid(format!(
                "database.url_env must be {SERVER_DATABASE_URL_ENV}"
            ));
        }
        if !(1..=100).contains(&self.database.max_connections) {
            return invalid("database.max_connections must be between 1 and 100");
        }
        if let Some(role) = &self.database.managed_local_role
            && (role.len() < 10
                || role.len() > 63
                || !role.starts_with("centrald_")
                || !role.chars().all(|character| {
                    character.is_ascii_lowercase() || character.is_ascii_digit() || character == '_'
                }))
        {
            return invalid(
                "database.managed_local_role is not a valid CentralD-managed PostgreSQL role",
            );
        }
        let ports = [
            self.server.enrollment_listen.port(),
            self.server.client_listen.port(),
            self.server.admin_listen.port(),
        ];
        if ports[0] == ports[1] || ports[0] == ports[2] || ports[1] == ports[2] {
            return invalid("enrollment, client, and admin listeners must use distinct ports");
        }
        if ports.iter().any(|port| *port < 1024) {
            return invalid(
                "listener ports must be between 1024 and 65535 because the packaged server runs without privileged bind capabilities",
            );
        }
        validate_server_fixed_paths(self)?;
        for (label, path) in server_paths(self) {
            if path.as_os_str().is_empty() {
                return invalid(format!("{label} must not be empty"));
            }
            if !path.is_absolute() {
                return invalid(format!("{label} must be an absolute path"));
            }
            validate_no_symlink_ancestors(path).map_err(|error| {
                ConfigError::Validation(format!(
                    "{label} has an unsafe filesystem ancestor: {error}"
                ))
            })?;
            if path
                .symlink_metadata()
                .is_ok_and(|metadata| metadata.file_type().is_symlink())
            {
                return invalid(format!("{label} must not be a symbolic link"));
            }
            validate_server_path_parent_security(path, label)?;
        }
        validate_runtime(&self.runtime)?;
        validate_updates(&self.updates)?;
        Ok(())
    }
}

impl ClientConfig {
    /// Loads and validates a client configuration from a TOML file.
    ///
    /// # Errors
    ///
    /// Returns an error when the file cannot be read, TOML parsing fails, or
    /// a required endpoint or identity path is invalid.
    pub fn load(path: &Path) -> Result<Self, ConfigError> {
        let raw = std::fs::read_to_string(path).map_err(|source| ConfigError::Read {
            path: path.to_path_buf(),
            source,
        })?;
        Self::parse_at(&raw, path)
    }

    /// Parses and validates client configuration bytes already obtained from a
    /// trusted file descriptor.
    ///
    /// # Errors
    ///
    /// Returns an error when the TOML or canonical storage layout is invalid.
    pub fn parse_at(raw: &str, path: &Path) -> Result<Self, ConfigError> {
        let config: Self = toml::from_str(raw).map_err(|source| ConfigError::Parse {
            path: path.to_path_buf(),
            source,
        })?;
        config.validate()?;
        config.validate_storage_path(path)?;
        Ok(config)
    }

    /// Validates the secure client endpoint and required identity paths.
    ///
    /// # Errors
    ///
    /// Returns [`ConfigError::Validation`] when an endpoint or path invariant
    /// is violated.
    pub fn validate(&self) -> Result<(), ConfigError> {
        validate_https_url(&self.endpoint, "client endpoint", false)?;
        validate_host(&self.server_name, "client server_name")?;
        if self.identity_name.trim().is_empty()
            || self.identity_name.len() > 128
            || self.identity_name.chars().any(char::is_control)
        {
            return invalid("client identity_name must be 1-128 printable characters");
        }
        let expected_data_dir = client_data_dir()?;
        if self.data_dir != expected_data_dir {
            return invalid(format!(
                "client data_dir must be the platform-managed state root {}",
                expected_data_dir.display()
            ));
        }
        for path in [
            &self.identity_cert,
            &self.identity_key,
            &self.root_ca,
            &self.grant_signing_public_key,
        ] {
            if path.as_os_str().is_empty() || !path.is_absolute() {
                return invalid("client identity paths must be absolute and non-empty");
            }
        }
        self.identity_generation_id()?;
        Ok(())
    }

    /// Verifies that the configuration filename and all credential paths name
    /// one canonical identity generation under the fixed client state root.
    ///
    /// # Errors
    ///
    /// Returns [`ConfigError::Validation`] when the file is outside the fixed
    /// configurations directory or its identity/generation does not match the
    /// credential paths.
    pub fn validate_storage_path(&self, path: &Path) -> Result<(), ConfigError> {
        let generation = self.identity_generation_id()?;
        let expected = self
            .data_dir
            .join("configurations")
            .join(format!("client-{}-{generation}.toml", self.identity_id));
        if path != expected {
            return invalid(format!(
                "client configuration path must be {}; got {}",
                expected.display(),
                path.display()
            ));
        }
        Ok(())
    }

    fn identity_generation_id(&self) -> Result<Uuid, ConfigError> {
        let generation_dir = self.identity_key.parent().ok_or_else(|| {
            ConfigError::Validation("client identity key has no generation directory".into())
        })?;
        let generation_text = generation_dir
            .file_name()
            .and_then(|value| value.to_str())
            .ok_or_else(|| {
                ConfigError::Validation("client identity generation name is invalid".into())
            })?;
        let generation = generation_text.parse::<Uuid>().map_err(|_| {
            ConfigError::Validation("client identity generation is not a UUID".into())
        })?;
        let expected_dir = self
            .data_dir
            .join("identities")
            .join(self.identity_id.to_string())
            .join("generations")
            .join(generation.to_string());
        let expected = [
            (&self.identity_cert, expected_dir.join("identity-chain.pem")),
            (&self.identity_key, expected_dir.join("identity-key.pem")),
            (&self.root_ca, expected_dir.join("root-ca.pem")),
            (
                &self.grant_signing_public_key,
                expected_dir.join("grant-signing-public.pem"),
            ),
        ];
        for (actual, expected) in expected {
            if actual != &expected {
                return invalid(format!(
                    "client credential path must be {}; got {}",
                    expected.display(),
                    actual.display()
                ));
            }
        }
        Ok(generation)
    }
}

fn validate_runtime(runtime: &RuntimeSection) -> Result<(), ConfigError> {
    if !(5..=3600).contains(&runtime.heartbeat_interval_seconds) {
        return invalid("runtime.heartbeat_interval_seconds must be between 5 and 3600");
    }
    if runtime.offline_after_seconds <= runtime.heartbeat_interval_seconds
        || runtime.offline_after_seconds > 86_400
    {
        return invalid(
            "runtime.offline_after_seconds must exceed the heartbeat interval and be no more than 86400",
        );
    }
    if !(1800..=604_800).contains(&runtime.job_ttl_seconds) {
        return invalid(
            "runtime.job_ttl_seconds must be at least 1800 seconds so long broker operations can report their terminal event",
        );
    }
    if !(30..=86_400).contains(&runtime.shell_idle_timeout_seconds) {
        return invalid("runtime.shell_idle_timeout_seconds must be between 30 and 86400");
    }
    if !(1024..=1_048_576).contains(&runtime.max_shell_frame_bytes) {
        return invalid("runtime.max_shell_frame_bytes must be between 1024 and 1048576");
    }
    Ok(())
}

fn validate_updates(updates: &UpdateSection) -> Result<(), ConfigError> {
    if !valid_channel(&updates.channel) {
        return invalid("updates.channel must be stable, alpha, or beta");
    }
    if updates.enabled || !updates.manifest_url.is_empty() {
        validate_https_url(&updates.manifest_url, "updates.manifest_url", true)?;
    }
    if updates.enabled && !(300..=2_592_000).contains(&updates.check_interval_seconds) {
        return invalid("updates.check_interval_seconds must be between 300 and 2592000");
    }
    Ok(())
}

#[must_use]
pub fn valid_channel(value: &str) -> bool {
    crate::build_info::is_supported_channel(value)
}

fn validate_https_url(value: &str, label: &str, allow_path: bool) -> Result<(), ConfigError> {
    let parsed = Url::parse(value)
        .map_err(|_| ConfigError::Validation(format!("{label} must be an absolute HTTPS URL")))?;
    if parsed.scheme() != "https"
        || parsed.host_str().is_none()
        || !parsed.username().is_empty()
        || parsed.password().is_some()
        || parsed.query().is_some()
        || parsed.fragment().is_some()
        || (!allow_path && !matches!(parsed.path(), "" | "/"))
    {
        return invalid(format!(
            "{label} must be HTTPS without credentials, a query, or a fragment"
        ));
    }
    Ok(())
}

fn validate_host(value: &str, label: &str) -> Result<(), ConfigError> {
    let canonical = canonical_host(value).map_err(|_| {
        ConfigError::Validation(format!(
            "{label} must be a canonical ASCII DNS name or IP without scheme, port, path, or whitespace"
        ))
    })?;
    if canonical != value {
        return invalid(format!("{label} must use its canonical form: {canonical}"));
    }
    Ok(())
}

#[cfg(unix)]
fn validate_server_path_parent_security(path: &Path, label: &str) -> Result<(), ConfigError> {
    use std::os::unix::fs::MetadataExt;

    let mut current = match path.symlink_metadata() {
        Ok(metadata) if metadata.is_dir() => Some(path),
        _ => path.parent(),
    };
    let mut found_existing = false;
    while let Some(ancestor) = current {
        if ancestor.as_os_str().is_empty() {
            break;
        }
        match ancestor.symlink_metadata() {
            Ok(metadata) => {
                found_existing = true;
                if metadata.file_type().is_symlink() || !metadata.is_dir() {
                    return invalid(format!(
                        "{label} ancestor {} must be a real directory",
                        ancestor.display()
                    ));
                }
                if metadata.uid() != 0 || metadata.mode() & 0o022 != 0 {
                    return invalid(format!(
                        "{label} ancestor {} must be root-owned and not group/world writable",
                        ancestor.display()
                    ));
                }
            }
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => {}
            Err(error) => {
                return invalid(format!(
                    "could not inspect {label} ancestor {}: {error}",
                    ancestor.display()
                ));
            }
        }
        current = ancestor.parent();
    }
    if found_existing {
        Ok(())
    } else {
        invalid(format!("{label} has no existing filesystem ancestor"))
    }
}

#[cfg(not(unix))]
#[allow(clippy::unnecessary_wraps)]
fn validate_server_path_parent_security(_path: &Path, _label: &str) -> Result<(), ConfigError> {
    Ok(())
}

fn validate_server_fixed_paths(config: &ServerConfig) -> Result<(), ConfigError> {
    let pki = Path::new(SERVER_DATA_DIR).join("pki");
    let expected: [(&str, &Path, PathBuf); 14] = [
        (
            "server.data_dir",
            &config.server.data_dir,
            PathBuf::from(SERVER_DATA_DIR),
        ),
        (
            "server.local_socket",
            &config.server.local_socket,
            PathBuf::from(SERVER_LOCAL_SOCKET),
        ),
        (
            "database.environment_file",
            &config.database.environment_file,
            PathBuf::from(SERVER_DATABASE_ENV_FILE),
        ),
        (
            "pki.root_cert",
            &config.pki.root_cert,
            pki.join("root-ca.pem"),
        ),
        (
            "pki.server_chain",
            &config.pki.server_chain,
            pki.join("server-chain.pem"),
        ),
        (
            "pki.server_key",
            &config.pki.server_key,
            pki.join("server-key.pem"),
        ),
        (
            "pki.server_issuer_cert",
            &config.pki.server_issuer_cert,
            pki.join("server-issuer.pem"),
        ),
        (
            "pki.server_issuer_key",
            &config.pki.server_issuer_key,
            pki.join("server-issuer-key.pem"),
        ),
        (
            "pki.client_issuer_cert",
            &config.pki.client_issuer_cert,
            pki.join("client-issuer.pem"),
        ),
        (
            "pki.client_issuer_key",
            &config.pki.client_issuer_key,
            pki.join("client-issuer-key.pem"),
        ),
        (
            "pki.admin_issuer_cert",
            &config.pki.admin_issuer_cert,
            pki.join("admin-issuer.pem"),
        ),
        (
            "pki.admin_issuer_key",
            &config.pki.admin_issuer_key,
            pki.join("admin-issuer-key.pem"),
        ),
        (
            "pki.grant_signing_key",
            &config.pki.grant_signing_key,
            pki.join("grant-signing-key.pem"),
        ),
        (
            "pki.grant_signing_public_key",
            &config.pki.grant_signing_public_key,
            pki.join("grant-signing-public.pem"),
        ),
    ];
    for (label, actual, expected) in expected {
        if actual != expected.as_path() {
            return invalid(format!(
                "{label} is package-managed and must be {}",
                expected.display()
            ));
        }
    }
    Ok(())
}

fn server_paths(config: &ServerConfig) -> [(&'static str, &Path); 14] {
    [
        ("server.data_dir", &config.server.data_dir),
        ("server.local_socket", &config.server.local_socket),
        (
            "database.environment_file",
            &config.database.environment_file,
        ),
        ("pki.root_cert", &config.pki.root_cert),
        ("pki.server_chain", &config.pki.server_chain),
        ("pki.server_key", &config.pki.server_key),
        ("pki.server_issuer_cert", &config.pki.server_issuer_cert),
        ("pki.server_issuer_key", &config.pki.server_issuer_key),
        ("pki.client_issuer_cert", &config.pki.client_issuer_cert),
        ("pki.client_issuer_key", &config.pki.client_issuer_key),
        ("pki.admin_issuer_cert", &config.pki.admin_issuer_cert),
        ("pki.admin_issuer_key", &config.pki.admin_issuer_key),
        ("pki.grant_signing_key", &config.pki.grant_signing_key),
        (
            "pki.grant_signing_public_key",
            &config.pki.grant_signing_public_key,
        ),
    ]
}

fn invalid<T>(message: impl Into<String>) -> Result<T, ConfigError> {
    Err(ConfigError::Validation(message.into()))
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used)]
mod tests {
    use super::*;

    fn valid_config() -> ServerConfig {
        ServerConfig {
            schema_version: SERVER_CONFIG_SCHEMA_VERSION,
            server: ServerSection {
                instance_id: Uuid::now_v7(),
                public_host: "centrald.home.arpa".into(),
                enrollment_listen: "0.0.0.0:7443".parse().unwrap(),
                client_listen: "0.0.0.0:7444".parse().unwrap(),
                admin_listen: "0.0.0.0:7445".parse().unwrap(),
                data_dir: "/var/lib/centrald".into(),
                local_socket: "/run/centrald/server.sock".into(),
            },
            database: DatabaseSection {
                url_env: "CENTRALD_DATABASE_URL".into(),
                environment_file: "/etc/centrald/server.env".into(),
                max_connections: 10,
                managed_local_role: None,
            },
            pki: ServerPkiSection {
                root_cert: "/var/lib/centrald/pki/root-ca.pem".into(),
                server_chain: "/var/lib/centrald/pki/server-chain.pem".into(),
                server_key: "/var/lib/centrald/pki/server-key.pem".into(),
                server_issuer_cert: "/var/lib/centrald/pki/server-issuer.pem".into(),
                server_issuer_key: "/var/lib/centrald/pki/server-issuer-key.pem".into(),
                client_issuer_cert: "/var/lib/centrald/pki/client-issuer.pem".into(),
                client_issuer_key: "/var/lib/centrald/pki/client-issuer-key.pem".into(),
                admin_issuer_cert: "/var/lib/centrald/pki/admin-issuer.pem".into(),
                admin_issuer_key: "/var/lib/centrald/pki/admin-issuer-key.pem".into(),
                grant_signing_key: "/var/lib/centrald/pki/grant-signing-key.pem".into(),
                grant_signing_public_key: "/var/lib/centrald/pki/grant-signing-public.pem".into(),
            },
            runtime: RuntimeSection {
                heartbeat_interval_seconds: 30,
                offline_after_seconds: 90,
                job_ttl_seconds: 1_800,
                shell_idle_timeout_seconds: 900,
                max_shell_frame_bytes: 65_536,
            },
            updates: UpdateSection {
                enabled: true,
                channel: "stable".into(),
                manifest_url: "https://example.test/centrald-release.yml".into(),
                check_interval_seconds: 21_600,
                allow_prerelease: false,
            },
        }
    }

    #[cfg(unix)]
    #[test]
    fn valid_config_is_accepted() {
        assert!(valid_config().validate().is_ok());
    }

    #[test]
    fn job_ttl_meets_the_broker_reporting_floor() {
        assert!((1800..=604_800).contains(&valid_config().runtime.job_ttl_seconds));
    }

    #[test]
    fn rejects_shared_listener_port() {
        let mut config = valid_config();
        config.server.admin_listen = config.server.client_listen;
        let error = config.validate().expect_err("shared ports must fail");
        assert!(error.to_string().contains("distinct ports"));
    }

    #[test]
    fn rejects_privileged_listener_port_without_bind_capability() {
        let mut config = valid_config();
        config.server.enrollment_listen.set_port(443);
        let error = config.validate().expect_err("port 443 must fail");
        assert!(error.to_string().contains("1024 and 65535"));
    }

    #[test]
    fn rejects_insecure_update_manifest() {
        let mut config = valid_config();
        config.updates.manifest_url = "http://example.test/manifest.yml".into();
        assert!(config.validate().is_err());
    }

    fn valid_client_config() -> (ClientConfig, PathBuf) {
        let identity_id = Uuid::now_v7();
        let generation_id = Uuid::now_v7();
        let data_dir = client_data_dir().unwrap();
        let identity_dir = data_dir
            .join("identities")
            .join(identity_id.to_string())
            .join("generations")
            .join(generation_id.to_string());
        let path = data_dir
            .join("configurations")
            .join(format!("client-{identity_id}-{generation_id}.toml"));
        (
            ClientConfig {
                identity_id,
                identity_name: "test-client".into(),
                endpoint: "https://centrald.home.arpa:7444".into(),
                server_name: "centrald.home.arpa".into(),
                data_dir,
                identity_cert: identity_dir.join("identity-chain.pem"),
                identity_key: identity_dir.join("identity-key.pem"),
                root_ca: identity_dir.join("root-ca.pem"),
                grant_signing_public_key: identity_dir.join("grant-signing-public.pem"),
                certificate_expires_at: chrono::Utc::now() + chrono::Duration::days(90),
            },
            path,
        )
    }

    #[test]
    fn accepts_canonical_client_generation_paths() {
        let (config, path) = valid_client_config();
        assert!(config.validate().is_ok());
        assert!(config.validate_storage_path(&path).is_ok());
    }

    #[test]
    fn rejects_client_path_outside_identity_generation() {
        let (mut config, path) = valid_client_config();
        config.identity_key = config.data_dir.join("identity-key.pem");
        assert!(config.validate().is_err());
        assert!(config.validate_storage_path(&path).is_err());
    }

    #[test]
    fn rejects_client_configuration_filename_mismatch() {
        let (config, _path) = valid_client_config();
        let wrong_path = config.data_dir.join("configurations").join(format!(
            "client-{}-{}.toml",
            config.identity_id,
            Uuid::now_v7()
        ));
        assert!(config.validate_storage_path(&wrong_path).is_err());
    }
}
