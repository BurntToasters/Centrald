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

/// Name of the lock file the running server holds in the data directory.
const LOCK_FILE: &str = "lock";

/// Checks the data directory and reports whether it is brand new (empty
/// apart from the lock file). It is never created here: a missing directory
/// (say, an unmounted volume) must not turn into a first run. systemd's
/// `StateDirectory=` creates it for the packaged service.
fn prepare_data_dir(path: &Path) -> Result<bool> {
    let metadata = std::fs::metadata(path).with_context(|| {
        format!(
            "the data directory {} does not exist; create it (owned by the service user, mode 0700) or fix CENTRALD_DATA_DIR",
            path.display()
        )
    })?;
    if !metadata.is_dir() {
        bail!("{} is not a directory", path.display());
    }
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        std::fs::set_permissions(path, std::fs::Permissions::from_mode(0o700))
            .with_context(|| format!("cannot restrict {}", path.display()))?;
    }
    let mut entries =
        std::fs::read_dir(path).with_context(|| format!("cannot read {}", path.display()))?;
    Ok(!entries.any(|entry| entry.is_ok_and(|e| e.file_name() != LOCK_FILE)))
}

/// Holds an exclusive lock on `<data_dir>/lock` for the life of the server,
/// so a second instance stops before it touches any state.
#[cfg(unix)]
fn lock_data_dir(data_dir: &Path) -> Result<nix::fcntl::Flock<std::fs::File>> {
    use nix::errno::Errno;
    use nix::fcntl::{Flock, FlockArg};
    let path = data_dir.join(LOCK_FILE);
    let mut file = std::fs::OpenOptions::new()
        .read(true)
        .write(true)
        .create(true)
        .truncate(false)
        .open(&path)
        .with_context(|| format!("cannot open {}", path.display()))?;
    // `status` takes a brief shared lock; retry so it never blocks a start.
    for _ in 0..30 {
        match Flock::lock(file, FlockArg::LockExclusiveNonblock) {
            Ok(lock) => return Ok(lock),
            Err((returned, Errno::EWOULDBLOCK)) => {
                file = returned;
                std::thread::sleep(Duration::from_millis(100));
            }
            Err((_, errno)) => {
                return Err(anyhow::Error::from(errno))
                    .with_context(|| format!("cannot lock {}", path.display()));
            }
        }
    }
    bail!(
        "another CentralD server is already running with {}; stop it first (sudo systemctl stop centrald-server)",
        data_dir.display()
    )
}

/// Whether a server holds the data-directory lock right now.
#[cfg(unix)]
fn server_running(data_dir: &Path) -> Option<bool> {
    use nix::errno::Errno;
    use nix::fcntl::{Flock, FlockArg};
    let file = std::fs::File::open(data_dir.join(LOCK_FILE)).ok()?;
    match Flock::lock(file, FlockArg::LockSharedNonblock) {
        Ok(_) => Some(false),
        Err((_, Errno::EWOULDBLOCK)) => Some(true),
        Err(_) => None,
    }
}

#[cfg(not(unix))]
fn server_running(_data_dir: &Path) -> Option<bool> {
    None
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

/// Opens the database for a local tool. Never creates or migrates it, so
/// it is safe next to a running server.
fn open_existing_db(config: &ServerConfig) -> Result<Db> {
    open_tool_db(config, db::OpenMode::Tool)
}

fn open_tool_db(config: &ServerConfig, mode: db::OpenMode) -> Result<Db> {
    let path = config.database_path();
    if !path.exists() {
        bail!(
            "no CentralD data in {}; start the server first (sudo systemctl start centrald-server)",
            config.data_dir.display()
        );
    }
    become_data_owner(&config.data_dir)?;
    Db::open(&path, mode)
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
    // Order matters: lock, then bind, then read or write any state, so a
    // second instance fails before it can disturb the first.
    let fresh = prepare_data_dir(&config.data_dir)?;
    #[cfg(unix)]
    let _lock = lock_data_dir(&config.data_dir)?;
    let listener = net::bind(config.listen)?;

    if fresh {
        tracing::info!(data = %config.data_dir.display(), "empty data directory: creating a new certificate authority and database");
    }
    // A brand-new directory gets its CA first and its database last; any
    // other directory must already hold both.
    let tls = tls::TlsState::load_or_create(&config, fresh)?;
    let mode = if fresh {
        db::OpenMode::Create
    } else {
        db::OpenMode::Server
    };
    let db = Db::open(&config.database_path(), mode)?;
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

    let runtime = tokio::runtime::Builder::new_multi_thread()
        .enable_all()
        .build()
        .context("start runtime")?;
    runtime.block_on(async move {
        let (hash_permits, hash_queue) = AppState::new_hash_limits();
        let tls_config = tls.config.clone();
        let state = Arc::new(AppState {
            hub: hub::Hub::new(db.clone()),
            builds: downloads::AgentBuilds::new(config.agent_dir.clone()),
            config,
            db,
            tls,
            login_limiter: auth::RateLimiter::default(),
            agent_limiter: auth::RateLimiter::default(),
            hash_permits,
            hash_queue,
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
        let app = api::router(state);
        net::serve(listener, tls_config, app, shutdown_signal())
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
    use std::fmt::Write as _;
    let db = open_tool_db(config, db::OpenMode::ReadOnly)?;
    let running = server_running(&config.data_dir);
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

    let mut out = String::new();
    writeln!(out, "CentralD server {}", centrald_proto::VERSION)?;
    match running {
        Some(true) => writeln!(out, "Server: running")?,
        Some(false) => writeln!(out, "Server: not running")?,
        None => {}
    }
    out.push('\n');
    writeln!(out, "Open the web app at:")?;
    for url in web_urls(config.listen) {
        writeln!(out, "  {url}")?;
    }
    out.push('\n');
    if users == 0 {
        match setup_code {
            Some(code) => {
                writeln!(out, "Setup code: {code}")?;
                writeln!(out, "Enter it in the web app to create the first account.")?;
            }
            None => writeln!(out, "Setup code: not created yet (start the server first).")?,
        }
    } else {
        writeln!(out, "Accounts: {users}")?;
    }
    writeln!(
        out,
        "Devices: {devices} enrolled, {online_recent} seen in the last two minutes"
    )?;
    if let Some(fingerprint) = fingerprint {
        out.push('\n');
        writeln!(out, "Certificate authority fingerprint (SHA-256):")?;
        writeln!(out, "  {fingerprint}")?;
        writeln!(
            out,
            "Your browser will warn about the certificate on first visit; compare"
        )?;
        writeln!(
            out,
            "this fingerprint, or install the CA from Settings in the web app."
        )?;
    }
    out.push('\n');
    writeln!(out, "Data: {}", config.data_dir.display())?;
    print_all(&out)
}

/// Prints to stdout; a reader that went away (`status | head -1`) is not
/// an error.
fn print_all(text: &str) -> Result<()> {
    use std::io::Write;
    let mut stdout = std::io::stdout().lock();
    match stdout
        .write_all(text.as_bytes())
        .and_then(|()| stdout.flush())
    {
        Err(error) if error.kind() != std::io::ErrorKind::BrokenPipe => {
            Err(error).context("write status")
        }
        _ => Ok(()),
    }
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
