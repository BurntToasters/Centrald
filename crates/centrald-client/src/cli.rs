use std::path::PathBuf;

use clap::{Args, Parser, Subcommand};

#[derive(Debug, Parser)]
#[command(name = "centrald-client", version, about = "CentralD managed client")]
pub struct ClientCli {
    #[command(subcommand)]
    pub command: ClientCommand,
}

#[derive(Debug, Subcommand)]
pub enum ClientCommand {
    Enroll(EnrollmentArgs),
    /// Restart the installed CentralD client service.
    Restart,
    Reenroll(EnrollmentArgs),
    Rescue(RescueArgs),
    #[command(hide = true)]
    Daemon,
    #[command(hide = true)]
    PrivilegedBroker,
    #[cfg(windows)]
    #[command(hide = true)]
    WindowsService,
}

#[derive(Debug, Args)]
pub struct EnrollmentArgs {
    /// Server IP or FQDN override. The access key supplies ports and TLS trust.
    #[arg(long)]
    pub server: Option<String>,
    /// Read the one-time invitation from a protected file instead of prompting.
    #[arg(long, value_name = "PATH", conflicts_with = "key_stdin")]
    pub key_file: Option<PathBuf>,
    /// Read the one-time invitation from piped standard input.
    #[arg(long, conflicts_with = "key_file")]
    pub key_stdin: bool,
}

#[derive(Debug, Args)]
pub struct RescueArgs {
    /// Reapply permissions to the fixed CentralD client state layout.
    #[arg(long)]
    pub repair: bool,
    /// Restart the installed client service after diagnostics/repair.
    #[arg(long)]
    pub restart_service: bool,
    #[arg(long)]
    pub bundle: Option<PathBuf>,
}
