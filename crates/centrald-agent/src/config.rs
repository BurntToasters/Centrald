//! The agent's single configuration file. It holds the device credential, so
//! it is readable by root/SYSTEM only.

use std::path::PathBuf;

use anyhow::{Context, Result, bail};
use serde::{Deserialize, Serialize};

#[derive(Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct AgentConfig {
    /// `host:port` addresses tried in order.
    pub servers: Vec<String>,
    /// Hex SHA-256 of the server's certificate authority.
    pub ca_fingerprint: String,
    pub device_id: String,
    pub token: String,
    /// False for monitor-only devices: commands and terminals are refused
    /// here, whatever the server asks.
    pub allow_commands: bool,
}

impl std::fmt::Debug for AgentConfig {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter
            .debug_struct("AgentConfig")
            .field("servers", &self.servers)
            .field("device_id", &self.device_id)
            .field("token", &"<redacted>")
            .field("allow_commands", &self.allow_commands)
            .finish_non_exhaustive()
    }
}

/// `CENTRALD_AGENT_CONFIG` overrides the location (tests, unusual layouts).
#[allow(clippy::unnecessary_wraps)] // Fallible on Windows only.
pub fn path() -> Result<PathBuf> {
    if let Some(path) = std::env::var_os("CENTRALD_AGENT_CONFIG").filter(|p| !p.is_empty()) {
        return Ok(PathBuf::from(path));
    }
    #[cfg(windows)]
    {
        let base = std::env::var_os("ProgramData")
            .filter(|p| !p.is_empty())
            .context("ProgramData is not set")?;
        Ok(PathBuf::from(base).join("CentralD").join("agent.toml"))
    }
    #[cfg(not(windows))]
    {
        Ok(PathBuf::from("/etc/centrald/agent.toml"))
    }
}

impl AgentConfig {
    pub fn fingerprint(&self) -> Result<[u8; 32]> {
        hex::decode(&self.ca_fingerprint)
            .ok()
            .and_then(|bytes| bytes.try_into().ok())
            .context("the CA fingerprint in the agent configuration is corrupt")
    }

    pub fn load() -> Result<Option<Self>> {
        let path = path()?;
        let text = match std::fs::read_to_string(&path) {
            Ok(text) => text,
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => return Ok(None),
            Err(error) => {
                return Err(error).with_context(|| format!("cannot read {}", path.display()));
            }
        };
        let config: Self = toml::from_str(&text)
            .with_context(|| format!("invalid agent configuration in {}", path.display()))?;
        if config.servers.is_empty() || config.device_id.is_empty() || config.token.is_empty() {
            bail!("{} is incomplete; enroll this device again", path.display());
        }
        config.fingerprint()?;
        Ok(Some(config))
    }

    pub fn save(&self) -> Result<()> {
        let path = path()?;
        let directory = path.parent().context("configuration path has no parent")?;
        std::fs::create_dir_all(directory)
            .with_context(|| format!("cannot create {}", directory.display()))?;
        restrict_directory(directory)?;
        let text = format!(
            "# CentralD agent configuration. Written by `centrald-agent enroll`.\n\
             # Contains this device's credential: keep it private.\n{}",
            toml::to_string(self)?
        );
        let mut temporary = path.as_os_str().to_owned();
        temporary.push(".tmp");
        let temporary = PathBuf::from(temporary);
        write_private(&temporary, text.as_bytes())?;
        std::fs::rename(&temporary, &path)
            .with_context(|| format!("cannot replace {}", path.display()))?;
        Ok(())
    }

    pub fn remove() -> Result<bool> {
        let path = path()?;
        match std::fs::remove_file(&path) {
            Ok(()) => Ok(true),
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => Ok(false),
            Err(error) => Err(error).with_context(|| format!("cannot remove {}", path.display())),
        }
    }
}

fn write_private(path: &std::path::Path, bytes: &[u8]) -> Result<()> {
    use std::io::Write;
    let mut options = std::fs::OpenOptions::new();
    options.write(true).create(true).truncate(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        options.mode(0o600);
    }
    let mut file = options
        .open(path)
        .with_context(|| format!("cannot write {}", path.display()))?;
    #[cfg(unix)]
    {
        // `mode` only applies to new files.
        use std::os::unix::fs::PermissionsExt;
        file.set_permissions(std::fs::Permissions::from_mode(0o600))?;
    }
    file.write_all(bytes)?;
    file.sync_all()?;
    Ok(())
}

#[cfg(unix)]
fn restrict_directory(directory: &std::path::Path) -> Result<()> {
    use std::os::unix::fs::PermissionsExt;
    // Only tighten directories we own outright; never chmod /etc itself.
    if directory.ends_with("centrald") {
        std::fs::set_permissions(directory, std::fs::Permissions::from_mode(0o700))
            .with_context(|| format!("cannot restrict {}", directory.display()))?;
    }
    Ok(())
}

/// `ProgramData` is readable by every user, so the directory gets an ACL of
/// SYSTEM and Administrators only (inherited by the files inside).
#[cfg(windows)]
fn restrict_directory(directory: &std::path::Path) -> Result<()> {
    let system_root = std::env::var_os("SystemRoot").context("SystemRoot is not set")?;
    let icacls = PathBuf::from(system_root)
        .join("System32")
        .join("icacls.exe");
    let status = std::process::Command::new(icacls)
        .arg(directory)
        .args([
            "/inheritance:r",
            "/grant:r",
            "*S-1-5-18:(OI)(CI)F",
            "*S-1-5-32-544:(OI)(CI)F",
            "/q",
        ])
        .status()
        .context("run icacls")?;
    if !status.success() {
        bail!("icacls could not restrict {}", directory.display());
    }
    Ok(())
}
