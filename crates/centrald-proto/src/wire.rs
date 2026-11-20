//! Messages exchanged over the agent WebSocket, as JSON text frames.

use serde::{Deserialize, Serialize};

use crate::limits::{MAX_ADDRESSES, MAX_DISKS, MAX_FAILED_UNITS, MAX_TEXT_BYTES};

/// Agent to server.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(
    tag = "type",
    rename_all = "snake_case",
    rename_all_fields = "camelCase"
)]
pub enum AgentMessage {
    /// First message on every connection.
    Hello(Hello),
    Status(Box<Status>),
    ExecOutput {
        id: String,
        #[serde(with = "b64")]
        data: Vec<u8>,
    },
    ExecExit {
        id: String,
        outcome: ExecOutcome,
    },
    TermOutput {
        id: String,
        #[serde(with = "b64")]
        data: Vec<u8>,
    },
    TermExit {
        id: String,
        message: String,
    },
}

/// Server to agent.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(
    tag = "type",
    rename_all = "snake_case",
    rename_all_fields = "camelCase"
)]
pub enum ServerMessage {
    /// Reply to `Hello`.
    Welcome(Welcome),
    ExecStart {
        id: String,
        spec: ExecSpec,
        timeout_seconds: u32,
    },
    ExecCancel {
        id: String,
    },
    TermOpen {
        id: String,
        columns: u16,
        rows: u16,
    },
    TermInput {
        id: String,
        #[serde(with = "b64")]
        data: Vec<u8>,
    },
    TermResize {
        id: String,
        columns: u16,
        rows: u16,
    },
    TermClose {
        id: String,
    },
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct Hello {
    pub protocol: u32,
    pub agent_version: String,
    pub hostname: String,
    pub os: OsInfo,
    /// False when the device was enrolled as monitor-only.
    pub allow_commands: bool,
    /// True when the agent binary is owned by a system package manager.
    pub package_managed: bool,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct Welcome {
    pub server_version: String,
    pub status_interval_seconds: u32,
}

#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct OsInfo {
    /// `linux`, `windows`, or `macos`.
    pub family: String,
    /// Distribution identifier such as `debian`, `ubuntu`, `fedora`, `arch`.
    pub id: String,
    /// Human name, for example `Debian GNU/Linux 12 (bookworm)`.
    pub name: String,
    pub version: String,
    pub kernel: String,
    pub arch: String,
}

#[derive(Debug, Clone, Default, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct Status {
    pub uptime_seconds: u64,
    pub cpu_percent: f32,
    pub cpu_count: u32,
    /// 1, 5 and 15 minute load averages; absent on Windows.
    pub load: Option<[f32; 3]>,
    pub memory: Usage,
    pub swap: Usage,
    pub disks: Vec<Disk>,
    pub addresses: Vec<String>,
    pub updates: Option<Updates>,
    /// Failed systemd units; `None` where systemd is not in use.
    pub failed_units: Option<Vec<String>>,
}

#[derive(Debug, Clone, Copy, Default, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct Usage {
    pub total_bytes: u64,
    pub used_bytes: u64,
}

#[derive(Debug, Clone, Default, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct Disk {
    pub mount: String,
    pub filesystem: String,
    pub total_bytes: u64,
    pub used_bytes: u64,
}

#[derive(Debug, Clone, Default, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct Updates {
    /// Package manager that produced the numbers: `apt`, `dnf`, `pacman`.
    pub manager: String,
    pub pending: u32,
    pub reboot_required: bool,
    /// Unix seconds of the last check.
    pub checked_at: u64,
}

/// What an operator asked the agent to run.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(tag = "kind", rename_all = "snake_case")]
pub enum ExecSpec {
    /// A command line for the platform shell.
    Shell { command: String },
    /// A built-in action the agent maps to fixed platform commands.
    Action { action: Action },
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Action {
    Reboot,
    UpdatesCheck,
    UpdatesApply,
}

impl Action {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Reboot => "reboot",
            Self::UpdatesCheck => "updates_check",
            Self::UpdatesApply => "updates_apply",
        }
    }

    pub fn parse(value: &str) -> Option<Self> {
        match value {
            "reboot" => Some(Self::Reboot),
            "updates_check" => Some(Self::UpdatesCheck),
            "updates_apply" => Some(Self::UpdatesApply),
            _ => None,
        }
    }

    pub fn label(self) -> &'static str {
        match self {
            Self::Reboot => "Reboot",
            Self::UpdatesCheck => "Check for updates",
            Self::UpdatesApply => "Install updates",
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ExecState {
    Succeeded,
    Failed,
    TimedOut,
    Canceled,
    /// The agent declined to run it (monitor-only, busy, unsupported).
    Refused,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct ExecOutcome {
    pub state: ExecState,
    pub exit_code: Option<i32>,
    pub error: Option<String>,
}

impl Hello {
    /// Clamps every agent-supplied string before the server stores it.
    pub fn sanitize(&mut self) {
        clamp(&mut self.agent_version);
        clamp(&mut self.hostname);
        clamp(&mut self.os.family);
        clamp(&mut self.os.id);
        clamp(&mut self.os.name);
        clamp(&mut self.os.version);
        clamp(&mut self.os.kernel);
        clamp(&mut self.os.arch);
    }
}

impl Status {
    /// Clamps every agent-supplied collection, string, and number.
    pub fn sanitize(&mut self) {
        if !self.cpu_percent.is_finite() {
            self.cpu_percent = 0.0;
        }
        self.cpu_percent = self.cpu_percent.clamp(0.0, 100.0);
        if let Some(load) = &mut self.load {
            for value in load {
                if !value.is_finite() || *value < 0.0 {
                    *value = 0.0;
                }
            }
        }
        self.disks.truncate(MAX_DISKS);
        for disk in &mut self.disks {
            clamp(&mut disk.mount);
            clamp(&mut disk.filesystem);
        }
        self.addresses.truncate(MAX_ADDRESSES);
        for address in &mut self.addresses {
            clamp(address);
        }
        if let Some(updates) = &mut self.updates {
            clamp(&mut updates.manager);
        }
        if let Some(units) = &mut self.failed_units {
            units.truncate(MAX_FAILED_UNITS);
            for unit in units {
                clamp(unit);
            }
        }
    }
}

/// Truncates to the shared text bound and drops control characters.
fn clamp(value: &mut String) {
    if value.chars().any(char::is_control) {
        *value = value.chars().filter(|c| !c.is_control()).collect();
    }
    if value.len() > MAX_TEXT_BYTES {
        let mut end = MAX_TEXT_BYTES;
        while !value.is_char_boundary(end) {
            end -= 1;
        }
        value.truncate(end);
    }
}

/// Base64 for byte payloads inside JSON.
mod b64 {
    use base64::Engine;
    use base64::engine::general_purpose::STANDARD;
    use serde::{Deserialize, Deserializer, Serializer};

    pub fn serialize<S: Serializer>(bytes: &[u8], serializer: S) -> Result<S::Ok, S::Error> {
        serializer.serialize_str(&STANDARD.encode(bytes))
    }

    pub fn deserialize<'de, D: Deserializer<'de>>(deserializer: D) -> Result<Vec<u8>, D::Error> {
        let text = String::deserialize(deserializer)?;
        STANDARD.decode(text).map_err(serde::de::Error::custom)
    }
}

/// Body of `POST /api/agent/enroll`.
#[derive(Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct EnrollRequest {
    pub protocol: u32,
    /// Lowercase hexadecimal join secret.
    pub secret: String,
    pub hostname: String,
    pub os: OsInfo,
    pub agent_version: String,
    pub allow_commands: bool,
    pub package_managed: bool,
}

impl std::fmt::Debug for EnrollRequest {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter
            .debug_struct("EnrollRequest")
            .field("hostname", &self.hostname)
            .field("secret", &"<redacted>")
            .finish_non_exhaustive()
    }
}

#[derive(Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct EnrollResponse {
    pub device_id: String,
    /// Long-lived device credential; the server keeps only its hash.
    pub token: String,
    pub name: String,
}

impl std::fmt::Debug for EnrollResponse {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter
            .debug_struct("EnrollResponse")
            .field("device_id", &self.device_id)
            .field("token", &"<redacted>")
            .finish_non_exhaustive()
    }
}
