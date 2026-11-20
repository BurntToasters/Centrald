//! `CentralD` agent: reports this machine's status to a `CentralD` server and
//! runs the commands and terminals operators open from the web app.

mod config;
mod connection;
mod exec;
mod net;
mod process;
mod service;
mod status;
mod terminal;
mod update;
#[cfg(windows)]
mod winservice;

use std::io::{BufRead, IsTerminal, Read, Write};
use std::path::PathBuf;

use anyhow::{Context, Result, bail};
use centrald_proto::join::{JoinCode, validate_server_address};
use centrald_proto::wire::{EnrollRequest, EnrollResponse};
use clap::{Parser, Subcommand};

use crate::config::AgentConfig;

#[derive(Debug, Parser)]
#[command(
    name = "centrald-agent",
    version,
    about = "CentralD agent for homelab remote management"
)]
struct Cli {
    #[command(subcommand)]
    command: Command,
}

#[derive(Debug, Subcommand)]
#[allow(clippy::doc_markdown)] // These comments are --help text.
enum Command {
    /// Connect this machine to a CentralD server using a join code.
    Enroll {
        /// Read the join code from this file.
        #[arg(long, value_name = "PATH", conflicts_with = "key_stdin")]
        key_file: Option<PathBuf>,
        /// Read the join code from standard input.
        #[arg(long)]
        key_stdin: bool,
        /// Try this server address (host:port) before the ones in the code.
        #[arg(long, value_name = "HOST:PORT")]
        server: Option<String>,
        /// Report status only; refuse commands and terminals on this machine.
        #[arg(long)]
        monitor_only: bool,
    },
    /// Show enrollment and connection status.
    Status,
    /// Disconnect from the server and remove the agent service.
    Leave,
    /// Replace this agent with the version your server offers.
    Update,
    /// Run the agent in the foreground (what the service does).
    #[command(hide = true)]
    Run,
    /// Windows service entry point.
    #[cfg(windows)]
    #[command(hide = true)]
    Service,
}

fn main() -> std::process::ExitCode {
    let cli = Cli::parse();
    let result = match cli.command {
        Command::Enroll {
            key_file,
            key_stdin,
            server,
            monitor_only,
        } => enroll(key_file, key_stdin, server, monitor_only),
        Command::Status => status(),
        Command::Leave => leave(),
        Command::Update => require_admin().and_then(|()| update::run()),
        Command::Run => run(),
        #[cfg(windows)]
        Command::Service => winservice::start(),
    };
    match result {
        Ok(()) => std::process::ExitCode::SUCCESS,
        Err(error) => {
            eprintln!("centrald-agent: {error:#}");
            std::process::ExitCode::FAILURE
        }
    }
}

fn init_logging() {
    let filter = tracing_subscriber::EnvFilter::try_from_env("CENTRALD_LOG")
        .unwrap_or_else(|_| tracing_subscriber::EnvFilter::new("info"));
    tracing_subscriber::fmt()
        .with_env_filter(filter)
        .with_target(false)
        // No color codes in journald or redirected logs.
        .with_ansi(std::io::IsTerminal::is_terminal(&std::io::stdout()))
        .init();
}

pub(crate) fn runtime() -> Result<tokio::runtime::Runtime> {
    tokio::runtime::Builder::new_multi_thread()
        .enable_all()
        .build()
        .context("start runtime")
}

fn run() -> Result<()> {
    init_logging();
    let config = AgentConfig::load()?.context(
        "this machine is not enrolled yet; run `sudo centrald-agent enroll` with a join code from the web app",
    )?;
    runtime()?.block_on(async move {
        tokio::select! {
            result = connection::run(config) => result,
            () = shutdown_signal() => {
                tracing::info!("stopping");
                Ok(())
            }
        }
    })
}

async fn shutdown_signal() {
    #[cfg(unix)]
    {
        use tokio::signal::unix::{SignalKind, signal};
        if let Ok(mut terminate) = signal(SignalKind::terminate()) {
            tokio::select! {
                _ = terminate.recv() => {}
                _ = tokio::signal::ctrl_c() => {}
            }
            return;
        }
    }
    let _ = tokio::signal::ctrl_c().await;
}

// Windows relies on the service manager and ACL calls failing without
// elevation, each with its own clear error.
#[cfg_attr(windows, allow(clippy::unnecessary_wraps))]
fn require_admin() -> Result<()> {
    #[cfg(unix)]
    {
        if std::env::var_os("CENTRALD_AGENT_CONFIG").is_none()
            && !nix::unistd::Uid::effective().is_root()
        {
            bail!(
                "run this with sudo (the agent stores its credential where only root can read it)"
            );
        }
    }
    Ok(())
}

fn read_join_code(key_file: Option<PathBuf>, key_stdin: bool) -> Result<String> {
    if let Some(path) = key_file {
        let text = std::fs::read_to_string(&path)
            .with_context(|| format!("cannot read {}", path.display()))?;
        return Ok(text.trim().to_owned());
    }
    if key_stdin {
        let mut text = String::new();
        std::io::stdin()
            .take(4096)
            .read_to_string(&mut text)
            .context("read the join code from standard input")?;
        return Ok(text.trim().to_owned());
    }
    if !std::io::stdin().is_terminal() {
        bail!("no join code given; use --key-stdin or --key-file, or run interactively");
    }
    print!("Paste the join code from the CentralD web app (Devices → Add device): ");
    std::io::stdout().flush()?;
    let mut line = String::new();
    std::io::stdin()
        .lock()
        .take(4096)
        .read_line(&mut line)
        .context("read the join code")?;
    Ok(line.trim().to_owned())
}

fn enroll(
    key_file: Option<PathBuf>,
    key_stdin: bool,
    server: Option<String>,
    monitor_only: bool,
) -> Result<()> {
    require_admin()?;
    let text = read_join_code(key_file, key_stdin)?;
    let code = JoinCode::parse(&text)?;
    let mut servers = code.servers.clone();
    if let Some(server) = server {
        let server = server.trim().to_owned();
        validate_server_address(&server)?;
        servers.retain(|s| *s != server);
        servers.insert(0, server);
    }
    if let Ok(Some(existing)) = AgentConfig::load() {
        println!(
            "This machine was enrolled before (device {}); enrolling again replaces that.",
            existing.device_id
        );
    }

    let request = EnrollRequest {
        protocol: centrald_proto::PROTOCOL_VERSION,
        secret: hex::encode(code.secret),
        hostname: status::hostname(),
        os: status::os_info(),
        agent_version: centrald_proto::VERSION.to_owned(),
        allow_commands: !monitor_only,
        package_managed: std::env::current_exe().is_ok_and(|p| p.starts_with("/usr/bin")),
    };
    let body = serde_json::to_vec(&request)?;
    let fingerprint = code.ca_fingerprint;
    let response = runtime()?.block_on(async {
        let mut failures = Vec::new();
        for server in &servers {
            println!("Contacting {server} ...");
            match net::post_json(server, fingerprint, "/api/agent/enroll", body.clone()).await {
                Ok((200, body)) => {
                    return serde_json::from_slice::<EnrollResponse>(&body)
                        .context("the server sent an unexpected reply");
                }
                // The server answered: its verdict is final.
                Ok((_, body)) => bail!("{}", net::error_message(&body)),
                Err(error) => failures.push(format!("  {server}: {error:#}")),
            }
        }
        bail!(
            "could not reach the server at any address in the join code:\n{}\n\
             Check that this machine can reach the server, or pass --server HOST:PORT.",
            failures.join("\n")
        )
    })?;

    let config = AgentConfig {
        servers,
        ca_fingerprint: hex::encode(fingerprint),
        device_id: response.device_id,
        token: response.token,
        allow_commands: !monitor_only,
    };
    config.save()?;
    println!("Enrolled as \"{}\".", response.name);
    if monitor_only {
        println!("Monitor-only: this machine reports status but refuses commands and terminals.");
    }
    match service::install_and_start() {
        Ok(service::Installed::Started) => {
            println!(
                "The CentralD agent service is running. The device appears online in the web app within a few seconds."
            );
        }
        Ok(service::Installed::Manual(note)) => println!("{note}"),
        Err(error) => {
            println!("Enrolled, but the service could not be started: {error:#}");
            println!(
                "Start it with `sudo systemctl enable --now centrald-agent` or run `centrald-agent run`."
            );
        }
    }
    Ok(())
}

fn status() -> Result<()> {
    let Some(config) = AgentConfig::load()? else {
        println!(
            "Not enrolled. Run `sudo centrald-agent enroll` with a join code from the web app."
        );
        return Ok(());
    };
    println!("CentralD agent {}", centrald_proto::VERSION);
    println!("Device ID:  {}", config.device_id);
    println!(
        "Mode:       {}",
        if config.allow_commands {
            "full control (commands and terminals allowed)"
        } else {
            "monitor-only (commands and terminals refused)"
        }
    );
    println!("Service:    {}", service::state());
    let fingerprint = config.fingerprint()?;
    let reachable = runtime()?.block_on(async {
        let mut lines = Vec::new();
        for server in &config.servers {
            let line = match net::connect(server, fingerprint).await {
                Ok(_) => format!("  {server}: reachable, certificate matches"),
                Err(error) => format!("  {server}: {error:#}"),
            };
            lines.push(line);
        }
        lines
    });
    println!("Servers:");
    for line in reachable {
        println!("{line}");
    }
    Ok(())
}

fn leave() -> Result<()> {
    require_admin()?;
    service::stop_and_remove()?;
    let removed = AgentConfig::remove()?;
    if removed {
        println!("This machine left CentralD. Remove it from the Devices page in the web app too.");
    } else {
        println!("This machine was not enrolled.");
    }
    Ok(())
}
