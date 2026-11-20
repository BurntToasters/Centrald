//! `CentralD` server: the web app, its API, and the hub agents connect to.

mod api;
mod auth;
mod config;
mod db;
mod downloads;
mod error;
mod hub;
mod model;
mod net;
mod session;
mod state;
mod tls;
mod ui;

use std::io::{IsTerminal, Read};
use std::path::{Path, PathBuf};
use std::sync::Arc;
use std::time::Duration;

use anyhow::{Context, Result, bail};
use clap::{Parser, Subcommand};
use rusqlite::OptionalExtension;

use crate::config::ServerConfig;
use crate::db::Db;
use crate::state::AppState;

#[derive(Debug, Parser)]
#[command(
    name = "centrald-server",
    version,
    about = "CentralD server for homelab remote management"
)]
struct Cli {
    /// Configuration file (default /etc/centrald/server.toml; optional).
    #[arg(long, global = true, value_name = "PATH")]
    config: Option<PathBuf>,
    #[command(subcommand)]
    command: Option<Command>,
}

#[derive(Debug, Subcommand)]
enum Command {
    /// Run the server (what the system service does).
    Run,
    /// Show the web address, setup code, and health of this server.
    Status,
    /// Set a new password for an operator and turn off their two-factor sign-in.
    ResetPassword {
        /// The operator's username.
        username: String,
        /// Read the new password from standard input instead of prompting.
        #[arg(long)]
        password_stdin: bool,
    },
}

fn main() -> std::process::ExitCode {
    let cli = Cli::parse();
    let result = (|| -> Result<()> {
        let config = ServerConfig::load(cli.config.as_deref())?;
        match cli.command.unwrap_or(Command::Run) {
            Command::Run => run(config),
            Command::Status => status(&config),
            Command::ResetPassword {
                username,
                password_stdin,
            } => reset_password(&config, &username, password_stdin),
        }
    })();
    match result {
        Ok(()) => std::process::ExitCode::SUCCESS,
        Err(error) => {
            eprintln!("centrald-server: {error:#}");
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

fn prepare_data_dir(path: &Path) -> Result<()> {
    std::fs::create_dir_all(path).with_context(|| format!("cannot create {}", path.display()))?;
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        std::fs::set_permissions(path, std::fs::Permissions::from_mode(0o700))
            .with_context(|| format!("cannot restrict {}", path.display()))?;
    }
    Ok(())
}

/// Local tools run as root but must not create root-owned files the
/// service account then cannot read, so they become the data owner first.
#[cfg(unix)]
fn become_data_owner(data_dir: &Path) -> Result<()> {
    use nix::unistd::{Gid, Uid, setgid, setgroups, setuid};
    use std::os::unix::fs::MetadataExt;
    if !Uid::effective().is_root() {
        return Ok(());
    }
    let Ok(metadata) = std::fs::metadata(data_dir) else {
        return Ok(());
    };
    if metadata.uid() == 0 {
        return Ok(());
    }
    setgroups(&[]).context("drop supplementary groups")?;
    setgid(Gid::from_raw(metadata.gid())).context("switch group")?;
    setuid(Uid::from_raw(metadata.uid())).context("switch user")?;
    Ok(())
}

#[cfg(not(unix))]
fn become_data_owner(_data_dir: &Path) -> Result<()> {
    Ok(())
}

fn open_existing_db(config: &ServerConfig) -> Result<Db> {
    let path = config.database_path();
    if !path.exists() {
        bail!(
            "no CentralD data in {}; start the server first (sudo systemctl start centrald-server)",
            config.data_dir.display()
        );
    }
    become_data_owner(&config.data_dir)?;
    Db::open(&path)
}

/// Web addresses for this host, most useful first.
fn web_urls(listen: std::net::SocketAddr) -> Vec<String> {
    let port = listen.port();
    if !listen.ip().is_unspecified() {
        return vec![format!("https://{listen}")];
    }
    let mut urls = Vec::new();
    if let Ok(interfaces) = if_addrs::get_if_addrs() {
        for interface in interfaces {
            let ip = interface.ip();
            if ip.is_ipv4() && !ip.is_loopback() {
                urls.push(format!("https://{ip}:{port}"));
            }
        }
    }
    if let Some(host) = sysinfo::System::host_name() {
        urls.push(format!("https://{}:{port}", host.to_ascii_lowercase()));
    }
    urls.dedup();
    urls
}

fn run(config: ServerConfig) -> Result<()> {
    init_logging();
    prepare_data_dir(&config.data_dir)?;
    let db = Db::open(&config.database_path())?;
    hub::Hub::recover_on_start(&db)?;

    let setup_code = db.call_blocking(|c| {
        let users: i64 = c.query_row("SELECT COUNT(*) FROM users", [], |r| r.get(0))?;
        if users > 0 {
            db::delete_setting(c, api::SETUP_CODE_KEY)?;
            return Ok(None);
        }
        if let Some(code) = db::get_setting(c, api::SETUP_CODE_KEY)? {
            return Ok(Some(code));
        }
        let code = auth::new_setup_code();
        db::set_setting(c, api::SETUP_CODE_KEY, &code)?;
        Ok(Some(code))
    })?;

    let tls = tls::TlsState::load_or_create(&config)?;
    let runtime = tokio::runtime::Builder::new_multi_thread()
        .enable_all()
        .build()
        .context("start runtime")?;
    runtime.block_on(async move {
        let listener = net::TlsListener::bind(config.listen, tls.config.clone()).await?;
        let state = Arc::new(AppState {
            hub: hub::Hub::new(db.clone()),
            builds: downloads::AgentBuilds::new(config.agent_dir.clone()),
            config,
            db,
            tls,
            login_limiter: auth::RateLimiter::default(),
            agent_limiter: auth::RateLimiter::default(),
            hash_permits: tokio::sync::Semaphore::new(2),
        });

        tracing::info!(version = centrald_proto::VERSION, listen = %state.config.listen, "CentralD server started");
        for url in web_urls(state.config.listen) {
            tracing::info!("web app: {url}");
        }
        if let Some(code) = setup_code {
            tracing::info!("first-run setup code: {code} (enter it in the web app to create the first account)");
        }
        tracing::info!(
            "CA fingerprint: {}",
            centrald_proto::format_fingerprint(&state.tls.ca_fingerprint)
        );

        tokio::spawn(maintenance(state.clone()));
        let app = api::router(state).into_make_service_with_connect_info::<net::ClientAddr>();
        axum::serve(listener, app)
            .with_graceful_shutdown(shutdown_signal())
            .await
            .context("server stopped")?;
        tracing::info!("CentralD server stopped");
        Ok(())
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

/// Hourly upkeep: certificate refresh and retention.
async fn maintenance(state: state::Shared) {
    let mut tick = tokio::time::interval(Duration::from_secs(3600));
    loop {
        tick.tick().await;
        match state.tls.refresh() {
            Ok(true) => {
                tracing::info!(
                    "issued a new server certificate (addresses changed or renewal due)"
                );
            }
            Ok(false) => {}
            Err(error) => {
                tracing::error!(error = %format!("{error:#}"), "certificate refresh failed");
            }
        }
        let pruned = state
            .db
            .call(|c| {
                let time = db::now();
                c.execute("DELETE FROM metrics WHERE at < ?1", [time - 8 * 86_400])?;
                c.execute(
                    "DELETE FROM runs WHERE created_at < ?1
                     AND id NOT IN (SELECT run_id FROM run_targets WHERE state = 'running')",
                    [time - 90 * 86_400],
                )?;
                c.execute("DELETE FROM audit WHERE at < ?1", [time - 365 * 86_400])?;
                c.execute(
                    "DELETE FROM join_tokens WHERE expires_at < ?1",
                    [time - 30 * 86_400],
                )?;
                c.execute("DELETE FROM sessions WHERE expires_at < ?1", [time])?;
                Ok(())
            })
            .await;
        if let Err(error) = pruned {
            tracing::error!(%error, "retention cleanup failed");
        }
    }
}

fn status(config: &ServerConfig) -> Result<()> {
    let db = open_existing_db(config)?;
    let (users, setup_code, devices, online_recent) = db.call_blocking(|c| {
        let users: i64 = c.query_row("SELECT COUNT(*) FROM users", [], |r| r.get(0))?;
        let code = db::get_setting(c, api::SETUP_CODE_KEY)?;
        let devices: i64 = c.query_row("SELECT COUNT(*) FROM devices", [], |r| r.get(0))?;
        let recent: i64 = c.query_row(
            "SELECT COUNT(*) FROM devices WHERE last_seen_at > ?1",
            [db::now() - 120],
            |r| r.get(0),
        )?;
        Ok((users, code, devices, recent))
    })?;
    let ca_path = config.tls_dir().join("ca.crt");
    let fingerprint = std::fs::read_to_string(&ca_path).ok().and_then(|pem| {
        use rustls::pki_types::CertificateDer;
        use rustls::pki_types::pem::PemObject;
        CertificateDer::from_pem_slice(pem.as_bytes())
            .ok()
            .map(|der| centrald_proto::format_fingerprint(&centrald_proto::sha256(der.as_ref())))
    });

    println!("CentralD server {}", centrald_proto::VERSION);
    println!();
    println!("Open the web app at:");
    for url in web_urls(config.listen) {
        println!("  {url}");
    }
    println!();
    if users == 0 {
        match setup_code {
            Some(code) => {
                println!("Setup code: {code}");
                println!("Enter it in the web app to create the first account.");
            }
            None => println!("Setup code: not created yet (start the server first)."),
        }
    } else {
        println!("Accounts: {users}");
    }
    println!("Devices: {devices} enrolled, {online_recent} seen in the last two minutes");
    if let Some(fingerprint) = fingerprint {
        println!();
        println!("Certificate authority fingerprint (SHA-256):");
        println!("  {fingerprint}");
        println!("Your browser will warn about the certificate on first visit; compare");
        println!("this fingerprint, or install the CA from Settings in the web app.");
    }
    println!();
    println!("Data: {}", config.data_dir.display());
    Ok(())
}

fn reset_password(config: &ServerConfig, username: &str, from_stdin: bool) -> Result<()> {
    let db = open_existing_db(config)?;
    let name = username.to_owned();
    let found: Option<(String, String)> = db.call_blocking(move |c| {
        Ok(c.query_row(
            "SELECT id, username FROM users WHERE username = ?1",
            [name],
            |r| Ok((r.get(0)?, r.get(1)?)),
        )
        .optional()?)
    })?;
    let Some((id, canonical)) = found else {
        bail!("there is no operator named `{username}`");
    };
    let password = if from_stdin {
        let mut text = String::new();
        std::io::stdin()
            .take(1024)
            .read_to_string(&mut text)
            .context("read password")?;
        text.trim_end_matches(['\r', '\n']).to_owned()
    } else {
        if !std::io::stdin().is_terminal() {
            bail!("no terminal to prompt on; pass --password-stdin");
        }
        let first = rpassword::prompt_password(format!("New password for {canonical}: "))?;
        let second = rpassword::prompt_password("Repeat it: ")?;
        if first != second {
            bail!("the passwords do not match");
        }
        first
    };
    auth::validate_password(&password, &canonical).map_err(anyhow::Error::msg)?;
    let hash = auth::hash_password(&password)?;
    db.call_blocking(move |c| {
        let tx = c.transaction()?;
        tx.execute(
            "UPDATE users SET password_hash = ?2, totp_enabled = 0, totp_secret = NULL WHERE id = ?1",
            rusqlite::params![id, hash],
        )?;
        tx.execute("DELETE FROM sessions WHERE user_id = ?1", [&id])?;
        db::audit(&tx, "local console", "account.password_reset", &canonical, "two-factor turned off", "")?;
        tx.commit()?;
        Ok(())
    })?;
    println!("Password updated. Two-factor sign-in is off and all sessions were signed out.");
    Ok(())
}
