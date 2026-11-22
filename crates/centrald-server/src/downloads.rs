//! Agent binaries the server offers to new devices, and the install scripts
//! that fetch them.

use std::path::{Path, PathBuf};
use std::sync::{Mutex, PoisonError};
use std::time::SystemTime;

use serde::Serialize;

pub const OPERATING_SYSTEMS: [&str; 2] = ["linux", "windows"];
pub const ARCHITECTURES: [&str; 2] = ["x86_64", "aarch64"];

#[derive(Debug, Clone, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct AgentBuild {
    pub os: &'static str,
    pub arch: &'static str,
    pub sha256: String,
    pub size: u64,
    #[serde(skip)]
    pub path: PathBuf,
    #[serde(skip)]
    modified: Option<SystemTime>,
}

/// Scans `agent_dir` for `centrald-agent-<os>-<arch>[.exe]`, caching hashes
/// until a file changes.
#[derive(Debug)]
pub struct AgentBuilds {
    directory: PathBuf,
    cache: Mutex<Vec<AgentBuild>>,
}

pub fn file_name(os: &str, arch: &str) -> String {
    let extension = if os == "windows" { ".exe" } else { "" };
    format!("centrald-agent-{os}-{arch}{extension}")
}

/// The release Minisign signature shipped next to an agent build.
pub fn signature_path(build: &Path) -> PathBuf {
    let mut path = build.as_os_str().to_owned();
    path.push(".minisig");
    PathBuf::from(path)
}

impl AgentBuilds {
    pub fn new(directory: PathBuf) -> Self {
        Self {
            directory,
            cache: Mutex::new(Vec::new()),
        }
    }

    /// Current builds. Hashing is skipped for files that did not change.
    pub fn list(&self) -> Vec<AgentBuild> {
        let mut found = Vec::new();
        for os in OPERATING_SYSTEMS {
            for arch in ARCHITECTURES {
                let path = self.directory.join(file_name(os, arch));
                if let Some(build) = self.describe(os, arch, &path) {
                    found.push(build);
                }
            }
        }
        found
    }

    pub fn find(&self, os: &str, arch: &str) -> Option<AgentBuild> {
        let os = OPERATING_SYSTEMS.into_iter().find(|v| *v == os)?;
        let arch = ARCHITECTURES.into_iter().find(|v| *v == arch)?;
        let path = self.directory.join(file_name(os, arch));
        self.describe(os, arch, &path)
    }

    fn describe(&self, os: &'static str, arch: &'static str, path: &Path) -> Option<AgentBuild> {
        let metadata = std::fs::metadata(path)
            .ok()
            .filter(std::fs::Metadata::is_file)?;
        let modified = metadata.modified().ok();
        let size = metadata.len();
        let mut cache = self.cache.lock().unwrap_or_else(PoisonError::into_inner);
        if let Some(hit) = cache
            .iter()
            .find(|b| b.path == path && b.size == size && b.modified == modified)
        {
            return Some(hit.clone());
        }
        let bytes = std::fs::read(path).ok()?;
        let build = AgentBuild {
            os,
            arch,
            sha256: hex::encode(centrald_proto::sha256(&bytes)),
            size,
            path: path.to_owned(),
            modified,
        };
        cache.retain(|b| b.path != path);
        cache.push(build.clone());
        Some(build)
    }
}

const INSTALL_SH: &str = include_str!("../assets/install.sh");
const INSTALL_PS1: &str = include_str!("../assets/install.ps1");

/// Linux installer with this server's address and key pin filled in.
///
/// `server` must already have passed `validate_server_address`; the pin is
/// base64, so neither can break out of the single-quoted shell strings.
pub fn install_sh(server: &str, pin: &str) -> String {
    INSTALL_SH
        .replace("__CENTRALD_SERVER__", server)
        .replace("__CENTRALD_PIN__", pin)
}

/// Windows installer; `leaf_sha256` is uppercase hex.
pub fn install_ps1(server: &str, leaf_sha256: &str) -> String {
    INSTALL_PS1
        .replace("__CENTRALD_SERVER__", server)
        .replace("__CENTRALD_CERT_SHA256__", leaf_sha256)
}

/// One-line commands shown in the web app.
pub fn install_commands(
    server: &str,
    pin: &str,
    leaf_sha256: &str,
    code: &str,
    monitor_only: bool,
) -> (String, String) {
    let (sh_flag, ps_flag) = if monitor_only {
        (
            " CENTRALD_MONITOR_ONLY=1",
            "$env:CENTRALD_MONITOR_ONLY='1'; ",
        )
    } else {
        ("", "")
    };
    let linux = format!(
        "curl -fsSk --pinnedpubkey '{pin}' https://{server}/install.sh | CENTRALD_JOIN='{code}'{sh_flag} sh"
    );
    let windows = format!(
        "$env:CENTRALD_JOIN='{code}'; {ps_flag}[Net.ServicePointManager]::SecurityProtocol='Tls12'; \
         [Net.ServicePointManager]::ServerCertificateValidationCallback={{param($s,$c) \
         ([BitConverter]::ToString([Security.Cryptography.SHA256]::Create().ComputeHash($c.GetRawCertData())) -replace '-') -eq '{leaf_sha256}'}}; \
         iex (New-Object Net.WebClient).DownloadString('https://{server}/install.ps1')"
    );
    (linux, windows)
}
