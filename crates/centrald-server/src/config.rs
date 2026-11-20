//! Server configuration: built-in defaults, an optional TOML file, then
//! environment overrides. Every value has a working default, so a fresh
//! install needs no configuration at all.

use std::net::SocketAddr;
use std::path::{Path, PathBuf};

use anyhow::{Context, Result, bail};
use serde::Deserialize;

pub const DEFAULT_CONFIG_PATH: &str = "/etc/centrald/server.toml";
pub const DEFAULT_DATA_DIR: &str = "/var/lib/centrald";
pub const DEFAULT_AGENT_DIR: &str = "/usr/share/centrald/agents";

#[derive(Debug, Clone)]
pub struct ServerConfig {
    /// Address of the single HTTPS listener.
    pub listen: SocketAddr,
    /// Database, TLS material, and nothing else.
    pub data_dir: PathBuf,
    /// Extra DNS names or IPs to put in the server certificate.
    pub hostnames: Vec<String>,
    /// Optional operator-supplied certificate for browsers.
    pub tls_cert: Option<PathBuf>,
    pub tls_key: Option<PathBuf>,
    /// Directory of agent binaries offered to new devices.
    pub agent_dir: PathBuf,
}

/// On-disk shape. Unknown keys are rejected so typos never pass silently.
#[derive(Debug, Default, Deserialize)]
#[serde(deny_unknown_fields)]
struct FileConfig {
    listen: Option<String>,
    data_dir: Option<PathBuf>,
    hostnames: Option<Vec<String>>,
    tls_cert: Option<PathBuf>,
    tls_key: Option<PathBuf>,
    agent_dir: Option<PathBuf>,
}

impl ServerConfig {
    /// Loads configuration. A missing default file is fine; a missing file
    /// the operator named explicitly is an error.
    pub fn load(explicit_path: Option<&Path>) -> Result<Self> {
        let path = explicit_path.unwrap_or(Path::new(DEFAULT_CONFIG_PATH));
        let file = match std::fs::read_to_string(path) {
            Ok(text) => toml::from_str::<FileConfig>(&text)
                .with_context(|| format!("invalid configuration in {}", path.display()))?,
            Err(error)
                if error.kind() == std::io::ErrorKind::NotFound && explicit_path.is_none() =>
            {
                FileConfig::default()
            }
            Err(error) => {
                return Err(error).with_context(|| format!("cannot read {}", path.display()));
            }
        };

        let listen = env("CENTRALD_LISTEN")
            .or(file.listen)
            .unwrap_or_else(|| format!("0.0.0.0:{}", centrald_proto::DEFAULT_PORT));
        let listen: SocketAddr = listen
            .parse()
            .with_context(|| format!("invalid listen address `{listen}`; expected ip:port"))?;
        if listen.port() == 0 {
            bail!("the listen port cannot be 0");
        }

        let hostnames = match env("CENTRALD_HOSTNAMES") {
            Some(value) => value
                .split(',')
                .map(|name| name.trim().to_owned())
                .filter(|name| !name.is_empty())
                .collect(),
            None => file.hostnames.unwrap_or_default(),
        };

        let tls_cert = env("CENTRALD_TLS_CERT")
            .map(PathBuf::from)
            .or(file.tls_cert);
        let tls_key = env("CENTRALD_TLS_KEY").map(PathBuf::from).or(file.tls_key);
        if tls_cert.is_some() != tls_key.is_some() {
            bail!("tls_cert and tls_key must be set together");
        }

        Ok(Self {
            listen,
            data_dir: env("CENTRALD_DATA_DIR")
                .map(PathBuf::from)
                .or(file.data_dir)
                .unwrap_or_else(|| PathBuf::from(DEFAULT_DATA_DIR)),
            hostnames,
            tls_cert,
            tls_key,
            agent_dir: env("CENTRALD_AGENT_DIR")
                .map(PathBuf::from)
                .or(file.agent_dir)
                .unwrap_or_else(|| PathBuf::from(DEFAULT_AGENT_DIR)),
        })
    }

    pub fn database_path(&self) -> PathBuf {
        self.data_dir.join("centrald.db")
    }

    pub fn tls_dir(&self) -> PathBuf {
        self.data_dir.join("tls")
    }
}

fn env(name: &str) -> Option<String> {
    std::env::var(name).ok().filter(|value| !value.is_empty())
}
