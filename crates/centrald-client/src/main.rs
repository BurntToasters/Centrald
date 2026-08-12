#![forbid(unsafe_code)]

use anyhow::{Result, bail};
use centrald_client::cli::{ClientCli, ClientCommand};
use clap::Parser;
use tracing_subscriber::EnvFilter;

#[tokio::main]
async fn main() -> Result<()> {
    tracing_subscriber::fmt()
        .with_env_filter(
            EnvFilter::try_from_default_env().unwrap_or_else(|_| EnvFilter::new("info")),
        )
        .try_init()
        .map_err(|error| anyhow::anyhow!(error.to_string()))?;
    let cli = ClientCli::parse();
    match cli.command {
        ClientCommand::Enroll(args) => {
            let path = centrald_client::enrollment::run(args, false).await?;
            println!("client enrolled; configuration: {}", path.display());
            Ok(())
        }
        ClientCommand::Reenroll(args) => {
            let path = centrald_client::enrollment::run(args, true).await?;
            println!("client reenrolled; configuration: {}", path.display());
            Ok(())
        }
        ClientCommand::Restart => centrald_client::rescue::restart_client_service(),
        ClientCommand::Rescue(args) => centrald_client::rescue::run(args).await,
        ClientCommand::Daemon => centrald_client::daemon::run().await,
        ClientCommand::PrivilegedBroker => bail!("privileged broker transport is not initialized"),
        #[cfg(windows)]
        ClientCommand::WindowsService => centrald_client::windows_service::run_dispatcher(),
    }
}
