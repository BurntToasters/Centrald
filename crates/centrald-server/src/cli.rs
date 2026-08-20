use std::path::PathBuf;

use clap::{Args, Parser, Subcommand, ValueEnum};

#[derive(Debug, Parser)]
#[command(
    name = "centrald-server",
    version,
    about = "CentralD management server"
)]
#[allow(clippy::struct_excessive_bools)]
pub struct ServerCli {
    #[arg(long = "config", global = true, default_value = crate::DEFAULT_CONFIG_PATH)]
    pub config_path: PathBuf,
    #[arg(long, global = true)]
    pub json: bool,
    #[arg(long, global = true)]
    pub no_color: bool,
    /// Permanently drop the `CentralD` database and remove this server install.
    #[arg(long, requires = "yes_i_want_to_do_this")]
    pub nuke: bool,
    /// Required literal acknowledgement for --nuke.
    #[arg(long)]
    pub yes_i_want_to_do_this: bool,
    #[command(subcommand)]
    pub command: Option<ServerCommand>,
}

#[derive(Debug, Subcommand)]
pub enum ServerCommand {
    /// Start the three secure network listeners.
    Run,
    /// Create a new server, database, PKI, and first Admin invitation.
    #[command(name = "initial-setup")]
    InitialSetup(SetupArgs),
    /// Open the guided local configuration and administration console.
    Config,
    /// Switch the release channel this server follows for client updates.
    Channel(ChannelArgs),
    #[command(hide = true)]
    Status(TargetArgs),
    #[command(hide = true)]
    Restart,
    #[command(hide = true)]
    ExportTrust(OutputArgs),
    #[command(hide = true)]
    EnrollClient(EnrollArgs),
    #[command(hide = true)]
    EnrollAdmin(EnrollArgs),
    #[command(hide = true)]
    ListClients,
    #[command(hide = true)]
    ListAdmins,
    #[command(hide = true)]
    RevokeClient(IdentityArgs),
    #[command(hide = true)]
    RevokeAdmin(RevokeAdminArgs),
    #[command(hide = true)]
    RestartClient(ClientArgs),
    #[command(hide = true)]
    RestartMachine(RestartMachineArgs),
    #[command(hide = true)]
    Shell(ShellArgs),
    #[command(hide = true)]
    CheckUpdates(UpdateArgs),
    #[command(hide = true)]
    ApplyUpdates(ApplyUpdateArgs),
    #[command(hide = true)]
    Audit(AuditArgs),
    #[command(hide = true)]
    PkiRotate,
    #[command(hide = true)]
    PkiRecover(PkiRecoverArgs),
    #[command(hide = true)]
    MaintenanceBroker,
}

#[derive(Debug, Args)]
pub struct SetupArgs {
    #[arg(long)]
    pub public_host: Option<String>,
    #[arg(long)]
    pub database_url_env: Option<String>,
    #[arg(long)]
    pub data_dir: Option<PathBuf>,
    #[arg(long)]
    pub recovery_key_output: Option<PathBuf>,
    #[arg(long)]
    pub admin_name: Option<String>,
    #[arg(long)]
    pub non_interactive: bool,
}

#[derive(Debug, Args)]
pub struct TargetArgs {
    #[arg(long)]
    pub client: Option<String>,
}

#[derive(Debug, Args)]
pub struct OutputArgs {
    #[arg(long)]
    pub output: PathBuf,
}

#[derive(Debug, Args)]
pub struct EnrollArgs {
    #[arg(long)]
    pub name: Option<String>,
    #[arg(long, default_value = "15m")]
    pub expires: String,
}

#[derive(Debug, Args)]
pub struct IdentityArgs {
    #[arg(long)]
    pub client: String,
    #[arg(long)]
    pub reason: String,
}

#[derive(Debug, Args)]
pub struct RevokeAdminArgs {
    #[arg(long)]
    pub admin: String,
    #[arg(long)]
    pub reason: String,
    #[arg(long)]
    pub force_last: bool,
}

#[derive(Debug, Args)]
pub struct ClientArgs {
    #[arg(long)]
    pub client: String,
}

#[derive(Debug, Clone, Copy, ValueEnum)]
pub enum TargetKind {
    Server,
    Client,
}

#[derive(Debug, Args)]
pub struct RestartMachineArgs {
    #[arg(long, value_enum)]
    pub target: TargetKind,
    #[arg(long)]
    pub client: Option<String>,
    #[arg(long, default_value_t = 0)]
    pub delay: u32,
}

#[derive(Debug, Args)]
pub struct ShellArgs {
    #[arg(long)]
    pub client: String,
    #[arg(long)]
    pub elevated: bool,
    #[arg(long)]
    pub reason: String,
}

#[derive(Debug, Clone, Copy, ValueEnum)]
pub enum UpdateScope {
    Centrald,
    Os,
}

#[derive(Debug, Clone, Copy, ValueEnum)]
pub enum ReleaseChannel {
    Stable,
    Alpha,
    Beta,
}

impl ReleaseChannel {
    #[must_use]
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Stable => "stable",
            Self::Alpha => "alpha",
            Self::Beta => "beta",
        }
    }
}

#[derive(Debug, Args)]
pub struct ChannelArgs {
    /// Channel to follow: stable, alpha, or beta.
    #[arg(value_enum)]
    pub channel: ReleaseChannel,
}

#[derive(Debug, Args)]
pub struct UpdateArgs {
    #[arg(long, value_enum)]
    pub scope: UpdateScope,
    #[arg(long, value_enum)]
    pub target: TargetKind,
    #[arg(long)]
    pub client: Option<String>,
}

#[derive(Debug, Args)]
pub struct ApplyUpdateArgs {
    #[command(flatten)]
    pub update: UpdateArgs,
    #[arg(long = "update")]
    pub update_ids: Vec<String>,
    #[arg(long, conflicts_with = "update_ids")]
    pub all_preselected: bool,
}

#[derive(Debug, Args)]
pub struct AuditArgs {
    #[arg(long)]
    pub client: Option<String>,
    #[arg(long)]
    pub since: Option<String>,
    #[arg(long, default_value_t = 100)]
    pub limit: u32,
}

#[derive(Debug, Args)]
pub struct PkiRecoverArgs {
    #[arg(long)]
    pub bundle: PathBuf,
}
