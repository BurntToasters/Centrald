#![forbid(unsafe_code)]

use std::net::{IpAddr, SocketAddr};
use std::path::{Path, PathBuf};
use std::process::Command;
use std::time::Duration;

use anyhow::{Context, Result, bail};
use centrald_common::config::ServerConfig;
use centrald_protocol::v1::admin_service_server::AdminServiceServer;
use centrald_protocol::v1::client_service_server::ClientServiceServer;
use centrald_protocol::v1::enrollment_service_server::EnrollmentServiceServer;
use centrald_server::cli::{EnrollArgs, ServerCli, ServerCommand, SetupArgs};
use centrald_server::db::{
    connect_and_migrate, ensure_database_and_migrate, migrate_precreated_database,
    resolve_database_url,
};
use centrald_server::local_postgres;
use centrald_server::manage::{create_enrollment_key as create_key, require_root};
use centrald_server::services::{
    AdminRpc, ClientRpc, EnrollmentRpc, RuntimeState, run_maintenance, run_update_checks,
};
use centrald_server::setup::{SetupOptions, initialize, preflight, prepare_directories};
use centrald_server::setup_recovery;
use centrald_server::wizard::{collect as collect_setup, print_completion};
use clap::Parser;
use secrecy::ExposeSecret;
use tonic::transport::{Certificate, ClientTlsConfig, Endpoint, Identity, Server, ServerTlsConfig};
use tracing::info;
use tracing_subscriber::EnvFilter;

const ENROLLMENT_MAX_MESSAGE_BYTES: usize = 512 * 1024;
const CLIENT_MAX_MESSAGE_BYTES: usize = 256 * 1024;
const ADMIN_MAX_MESSAGE_BYTES: usize = 512 * 1024;

#[tokio::main]
#[allow(clippy::large_futures)]
async fn main() -> Result<()> {
    let cli = ServerCli::parse();
    if cli.no_color {
        console::set_colors_enabled(false);
        console::set_colors_enabled_stderr(false);
    }
    init_tracing(cli.json)?;
    if cli.yes_i_want_to_do_this && !cli.nuke {
        bail!("--yes-i-want-to-do-this is valid only with --nuke");
    }
    let is_initial_setup = matches!(cli.command.as_ref(), Some(ServerCommand::InitialSetup(_)));
    if !is_initial_setup && !cli.nuke {
        setup_recovery::prepare_for_normal_command(&cli.config_path).await?;
    }

    let _setup_mutation_lock = if cli.nuke {
        if cli.command.is_some() {
            bail!("--nuke cannot be combined with a subcommand");
        }
        require_root()?;
        Some(setup_recovery::acquire_setup_mutation_lock()?)
    } else {
        None
    };

    if cli.nuke && setup_recovery::reset_interrupted_setup_for_nuke(&cli.config_path).await? {
        println!("Interrupted CentralD setup permanently reset.");
        println!("  Removed the generated PostgreSQL role/database and partial setup files.");
        println!("No published CentralD installation remained.");
        return Ok(());
    }

    if cli.config_path.exists() {
        centrald_server::config_lock::recover_interrupted_database_update(&cli.config_path)
            .context("recover interrupted database settings update")?;
        centrald_server::config_lock::recover_interrupted_settings_update(&cli.config_path)
            .context("recover interrupted audited settings update")?;
        centrald_server::manage::recover_interrupted_online_issuer_rotation(&cli.config_path)
            .context("recover interrupted online issuer rotation")?;
        centrald_server::manage::recover_interrupted_root_replacement(&cli.config_path)
            .context("recover interrupted offline root replacement")?;
        centrald_server::manage::recover_interrupted_tls_rotation(&cli.config_path)
            .context("recover interrupted server TLS rotation")?;
    }

    if cli.nuke {
        let summary = centrald_server::nuke::nuke(&cli.config_path).await?;
        println!("CentralD installation permanently reset.");
        println!("  Dropped PostgreSQL database: {}", summary.database_name);
        println!("  Removed data: {}", summary.data_dir.display());
        println!("  Removed config: {}", summary.config_path.display());
        println!(
            "  Removed database environment file: {}",
            summary.environment_file.display()
        );
        println!("The offline root recovery bundle was intentionally preserved.");
        return Ok(());
    }
    let command = cli.command.context(
        "a subcommand is required (use initial-setup, config, run, or --nuke --yes-i-want-to-do-this)",
    )?;
    match command {
        ServerCommand::Run => run(&cli.config_path).await,
        ServerCommand::Status(_) => {
            let config = ServerConfig::load(&cli.config_path)?;
            println!("server instance: {}", config.server.instance_id);
            println!("TLS name: {}", config.server.public_host);
            println!(
                "listeners: enrollment={} client={} admin={}",
                config.server.enrollment_listen,
                config.server.client_listen,
                config.server.admin_listen
            );
            Ok(())
        }
        ServerCommand::InitialSetup(args) => initial_setup(&cli.config_path, args).await,
        ServerCommand::Config => centrald_server::manage::run(&cli.config_path).await,
        ServerCommand::Channel(args) => {
            centrald_server::manage::set_channel(&cli.config_path, args.channel.as_str())
        }
        ServerCommand::EnrollClient(args) => {
            create_enrollment_key(&cli.config_path, args, "client", cli.json).await
        }
        ServerCommand::EnrollAdmin(args) => {
            create_enrollment_key(&cli.config_path, args, "admin", cli.json).await
        }
        ServerCommand::MaintenanceBroker => {
            bail!("maintenance broker transport is not initialized")
        }
        command => bail!("command {command:?} is scaffolded but not initialized"),
    }
}

#[allow(clippy::too_many_lines)]
async fn run(config_path: &Path) -> Result<()> {
    require_root()?;
    let mut config = ServerConfig::load(config_path)?;
    let local_socket = config.server.local_socket.clone();
    let server_lock = centrald_server::local_control::acquire_server_lock(&local_socket)
        .context("acquire exclusive CentralD server runtime lock")?;
    centrald_server::manage::check_pki_expiry(&config)?;
    if centrald_server::manage::renew_server_identity_if_needed(config_path)? {
        config = ServerConfig::load(config_path)?;
        centrald_server::manage::check_pki_expiry(&config)?;
        info!("server TLS leaf renewed during startup");
    }
    let enrollment_address = config.server.enrollment_listen;
    let client_address = config.server.client_listen;
    let admin_address = config.server.admin_listen;
    let server_chain = centrald_server::file_security::read_root_public_text(
        &config.pki.server_chain,
        256 * 1024,
        "server TLS certificate chain",
    )?
    .into_bytes();
    let server_key = centrald_server::file_security::read_root_private_text(
        &config.pki.server_key,
        256 * 1024,
        "server TLS private key",
    )?
    .into_bytes();
    let root_certificate = centrald_server::file_security::read_root_public_text(
        &config.pki.root_cert,
        256 * 1024,
        "root CA certificate",
    )?
    .into_bytes();
    let state = RuntimeState::load(config.clone(), config_path.to_path_buf()).await?;
    let reconciled = centrald_server::local_audit::reconcile(&state.pool, config_path).await?;
    if reconciled > 0 {
        info!(reconciled, "reconciled server-local audit journal");
    }
    let local_pool = state.pool.clone();
    let enrollment_crypto_limit = state.enrollment_crypto_limit.clone();
    tokio::spawn(run_maintenance(state.clone()));
    tokio::spawn(run_update_checks(state.clone()));
    let identity = Identity::from_pem(server_chain, server_key);
    let client_ca = Certificate::from_pem(root_certificate);

    info!(%enrollment_address, "enrollment TLS listener ready");
    info!(%client_address, "client mTLS listener ready");
    info!(%admin_address, "admin mTLS listener ready");

    let enrollment = Server::builder()
        .tls_config(ServerTlsConfig::new().identity(identity.clone()))?
        .add_service(
            EnrollmentServiceServer::new(EnrollmentRpc::new(state.clone()))
                .max_decoding_message_size(ENROLLMENT_MAX_MESSAGE_BYTES)
                .max_encoding_message_size(ENROLLMENT_MAX_MESSAGE_BYTES),
        )
        .serve(enrollment_address);
    let clients = Server::builder()
        .tls_config(
            ServerTlsConfig::new()
                .identity(identity.clone())
                .client_ca_root(client_ca.clone()),
        )?
        .add_service(
            ClientServiceServer::new(ClientRpc::new(state.clone()))
                .max_decoding_message_size(CLIENT_MAX_MESSAGE_BYTES)
                .max_encoding_message_size(CLIENT_MAX_MESSAGE_BYTES),
        )
        .serve(client_address);
    let admins = Server::builder()
        .tls_config(
            ServerTlsConfig::new()
                .identity(identity)
                .client_ca_root(client_ca),
        )?
        .add_service(
            AdminServiceServer::new(AdminRpc::new(state))
                .max_decoding_message_size(ADMIN_MAX_MESSAGE_BYTES)
                .max_encoding_message_size(ADMIN_MAX_MESSAGE_BYTES),
        )
        .serve(admin_address);
    let local_control = centrald_server::local_control::serve(
        local_socket,
        local_pool,
        config.clone(),
        enrollment_crypto_limit,
        server_lock,
    );

    if centrald_server::manage::tls_retirement_pending(config_path)? {
        let retirement_config = config_path.to_path_buf();
        let retirement_probe_config = config.clone();
        tokio::spawn(async move {
            match verify_tls_listeners_before_retirement(&retirement_probe_config).await {
                Ok(()) => {
                    match centrald_server::manage::retire_completed_tls_rotation(&retirement_config)
                    {
                        Ok(true) => info!(
                            "retired previous server TLS rollback material after all listener TLS probes succeeded"
                        ),
                        Ok(false) => {}
                        Err(error) => {
                            tracing::warn!(%error, "could not retire previous server TLS rollback material");
                        }
                    }
                }
                Err(error) => {
                    tracing::warn!(%error, "keeping server TLS/PKI rollback material because listener health probes did not all succeed");
                }
            }
        });
    }

    let enrollment = async { enrollment.await.context("enrollment listener stopped") };
    let clients = async { clients.await.context("client listener stopped") };
    let admins = async { admins.await.context("Admin listener stopped") };
    let tls_renewal = monitor_server_tls_renewal(config_path.to_path_buf());
    tokio::try_join!(enrollment, clients, admins, local_control, tls_renewal)?;
    Ok(())
}

async fn monitor_server_tls_renewal(config_path: PathBuf) -> Result<()> {
    let mut interval = tokio::time::interval(Duration::from_secs(6 * 60 * 60));
    interval.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Delay);
    // Startup already performed the first renewal check. Consume the immediate
    // tick so the long-lived daemon checks again on the bounded schedule.
    interval.tick().await;
    loop {
        interval.tick().await;
        if centrald_server::manage::renew_server_identity_if_needed(&config_path)? {
            bail!(
                "server TLS leaf renewed; exiting so the service manager can activate the replacement identity"
            );
        }
    }
}

async fn verify_tls_listeners_before_retirement(config: &ServerConfig) -> Result<()> {
    let root = centrald_server::file_security::read_root_public_text(
        &config.pki.root_cert,
        256 * 1024,
        "root CA certificate",
    )?;
    let client_issuer = centrald_server::file_security::read_root_public_text(
        &config.pki.client_issuer_cert,
        256 * 1024,
        "client issuer certificate",
    )?;
    let client_key = centrald_server::file_security::read_root_private_text(
        &config.pki.client_issuer_key,
        256 * 1024,
        "client issuer private key",
    )?;
    let admin_issuer = centrald_server::file_security::read_root_public_text(
        &config.pki.admin_issuer_cert,
        256 * 1024,
        "Admin issuer certificate",
    )?;
    let admin_key = centrald_server::file_security::read_root_private_text(
        &config.pki.admin_issuer_key,
        256 * 1024,
        "Admin issuer private key",
    )?;
    let client_probe = centrald_pki::issue_ephemeral_identity(
        "centrald-client-tls-probe",
        centrald_pki::IdentityCertificateKind::Client,
        &client_issuer,
        &client_key,
        &root,
    )?;
    let admin_probe = centrald_pki::issue_ephemeral_identity(
        "centrald-admin-tls-probe",
        centrald_pki::IdentityCertificateKind::Admin,
        &admin_issuer,
        &admin_key,
        &root,
    )?;

    for attempt in 1..=30_u32 {
        let result = async {
            probe_tls_listener(
                config.server.enrollment_listen,
                &config.server.public_host,
                &root,
                None,
            )
            .await
            .context("enrollment TLS probe")?;
            probe_tls_listener(
                config.server.client_listen,
                &config.server.public_host,
                &root,
                Some(&client_probe),
            )
            .await
            .context("client-mTLS probe")?;
            probe_tls_listener(
                config.server.admin_listen,
                &config.server.public_host,
                &root,
                Some(&admin_probe),
            )
            .await
            .context("Admin-mTLS probe")?;
            Ok::<(), anyhow::Error>(())
        }
        .await;
        match result {
            Ok(()) => return Ok(()),
            Err(error) if attempt < 30 => {
                tracing::debug!(attempt, %error, "listener TLS health probe not ready yet");
                tokio::time::sleep(std::time::Duration::from_secs(1)).await;
            }
            Err(error) => return Err(error),
        }
    }
    bail!("listener TLS health probes exhausted retries")
}

async fn probe_tls_listener(
    address: SocketAddr,
    server_name: &str,
    root_pem: &str,
    identity: Option<&centrald_pki::PemIdentity>,
) -> Result<()> {
    let destination = probe_destination(address);
    let mut tls = ClientTlsConfig::new()
        .domain_name(server_name.to_owned())
        .ca_certificate(Certificate::from_pem(root_pem));
    if let Some(identity) = identity {
        tls = tls.identity(Identity::from_pem(
            identity.certificate_chain_pem.as_bytes(),
            identity.private_key_pem.as_bytes(),
        ));
    }
    let channel = Endpoint::from_shared(destination)?
        .connect_timeout(std::time::Duration::from_secs(3))
        .timeout(std::time::Duration::from_secs(3))
        .tls_config(tls)?
        .connect()
        .await?;
    drop(channel);
    Ok(())
}

fn probe_destination(address: SocketAddr) -> String {
    let ip = if address.ip().is_unspecified() {
        match address.ip() {
            IpAddr::V4(_) => IpAddr::V4(std::net::Ipv4Addr::LOCALHOST),
            IpAddr::V6(_) => IpAddr::V6(std::net::Ipv6Addr::LOCALHOST),
        }
    } else {
        address.ip()
    };
    match ip {
        IpAddr::V4(ip) => format!("https://{ip}:{}", address.port()),
        IpAddr::V6(ip) => format!("https://[{ip}]:{}", address.port()),
    }
}

#[allow(clippy::too_many_lines)]
async fn initial_setup(config_path: &Path, args: SetupArgs) -> Result<()> {
    require_root()?;
    let _setup_mutation_lock = setup_recovery::acquire_setup_mutation_lock()?;
    let recovered_committed = setup_recovery::recover_before_initial_setup(config_path).await?;
    if config_path.exists() {
        if recovered_committed {
            bail!(
                "CentralD setup already committed before the previous process stopped. Use `sudo centrald-server config` to create a new Admin access key or inspect health; use the explicit --nuke command only when you intend to erase the installation."
            );
        }
        bail!(
            "CentralD is already configured at {}. Use `sudo centrald-server config` for guided administration.",
            config_path.display()
        );
    }

    let options = collect_setup(config_path, args)?;
    // Prove every output is absent and every ancestor is safe before creating
    // the managed PostgreSQL role. Recovery may remove only these preflighted
    // targets after an interrupted setup.
    preflight(&options).context("validate every setup output before changing PostgreSQL")?;
    prepare_directories(&options)
        .context("create private server setup directories before changing PostgreSQL")?;
    let managed_role = options.managed_local_role.clone();
    setup_recovery::begin_setup(&options)
        .context("create crash-recovery state before PostgreSQL provisioning")?;
    if let Some(role) = managed_role.as_deref() {
        if let Err(error) =
            local_postgres::provision_role(role, &options.database_url, options.instance_id)
        {
            return Err(setup_failure(
                &options,
                error.context("provision the generated local PostgreSQL role"),
            )
            .await);
        }
        if let Err(error) =
            local_postgres::provision_database(role, &options.database_url, options.instance_id)
        {
            return Err(setup_failure(
                &options,
                error.context("provision the generated local PostgreSQL database"),
            )
            .await);
        }
    }

    let summary = match initialize(&options) {
        Ok(summary) => summary,
        Err(error) => {
            return Err(setup_failure(&options, error).await);
        }
    };
    let config = match ServerConfig::load(config_path) {
        Ok(config) => config,
        Err(error) => {
            let error =
                anyhow::Error::new(error).context("load newly generated server configuration");
            return Err(setup_failure(&options, error).await);
        }
    };
    let database_result = if managed_role.is_some() {
        migrate_precreated_database(
            options.database_url.expose_secret(),
            config.database.max_connections,
            config.server.instance_id,
        )
        .await
    } else {
        ensure_database_and_migrate(
            options.database_url.expose_secret(),
            config.database.max_connections,
            config.server.instance_id,
        )
        .await
    };
    let database = match database_result {
        Ok(database) => database,
        Err(error) => {
            let error =
                anyhow::Error::new(error).context("create and migrate the CentralD database");
            return Err(setup_failure(&options, error).await);
        }
    };
    if let Some(role) = managed_role.as_deref()
        && let Err(error) = local_postgres::harden_role(role, options.instance_id)
    {
        database.pool.close().await;
        return Err(setup_failure(
            &options,
            error.context("secure the generated local PostgreSQL role"),
        )
        .await);
    }
    let admin = match create_key(
        &database.pool,
        &config,
        "admin",
        &options.admin_name,
        std::time::Duration::from_secs(24 * 60 * 60),
    )
    .await
    {
        Ok(admin) => admin,
        Err(error) => {
            database.pool.close().await;
            return Err(setup_failure(
                &options,
                error.context("create the initial Admin access key"),
            )
            .await);
        }
    };
    database.pool.close().await;

    if let Err(error) = setup_recovery::mark_committed(config_path) {
        return Err(
            setup_failure(&options, error.context("mark PostgreSQL setup committed")).await,
        );
    }
    if let Err(error) = setup_recovery::retire_committed(config_path) {
        tracing::warn!(
            %error,
            "setup committed successfully but its recovery journal could not be retired; the next server command will retry safe retirement"
        );
    }

    let service = try_start_packaged_service(config_path).await;
    print_completion(&summary, &admin, &service);
    Ok(())
}

async fn setup_failure(options: &SetupOptions, error: anyhow::Error) -> anyhow::Error {
    match setup_recovery::rollback_current_setup(&options.config_path).await {
        Ok(()) => error,
        Err(cleanup_error) => error.context(format!(
            "automatic setup rollback was incomplete; rerun `sudo centrald-server initial-setup` to retry recovery: {cleanup_error:#}"
        )),
    }
}

#[allow(clippy::unused_async)]
async fn packaged_local_socket_reachable() -> bool {
    #[cfg(unix)]
    {
        tokio::net::UnixStream::connect(centrald_server::DEFAULT_LOCAL_SOCKET)
            .await
            .is_ok()
    }
    #[cfg(not(unix))]
    {
        let _ = centrald_server::DEFAULT_LOCAL_SOCKET;
        false
    }
}

async fn try_start_packaged_service(config_path: &Path) -> String {
    if std::env::var_os("CENTRALD_SKIP_SERVICE_START").is_some() {
        return "Automatic service start skipped by CENTRALD_SKIP_SERVICE_START; run sudo systemctl enable --now centrald-server when ready.".into();
    }
    if config_path != Path::new(centrald_server::DEFAULT_CONFIG_PATH) {
        return "Custom configuration path detected; start CentralD with your own service definition or centrald-server run.".into();
    }
    if std::env::current_exe().ok().as_deref() != Some(Path::new("/usr/bin/centrald-server")) {
        return "Source/custom server binary detected; start it with centrald-server run or install the server package for automatic systemd activation.".into();
    }
    if !Path::new("/run/systemd/system").is_dir() {
        return "systemd is not active; start CentralD with centrald-server run or your service manager.".into();
    }
    let unit_installed = [
        "/etc/systemd/system/centrald-server.service",
        "/usr/lib/systemd/system/centrald-server.service",
        "/lib/systemd/system/centrald-server.service",
    ]
    .iter()
    .any(|path| Path::new(path).is_file());
    if !unit_installed {
        return "Packaged systemd unit was not found; start CentralD with centrald-server run or install the server package.".into();
    }
    let systemctl = Path::new("/usr/bin/systemctl");
    let timeout = Path::new("/usr/bin/timeout");
    if !systemctl.is_file() || !timeout.is_file() {
        return "systemctl/timeout was not found at the packaged paths; enable and start centrald-server.service with your service manager.".into();
    }
    match Command::new(timeout)
        .args([
            "--kill-after=5s",
            "45s",
            "/usr/bin/systemctl",
            "--no-ask-password",
            "enable",
            "--now",
            "centrald-server.service",
        ])
        .status()
    {
        Ok(status) if status.success() => {
            let ready = tokio::time::timeout(Duration::from_secs(15), async {
                loop {
                    if packaged_local_socket_reachable().await {
                        break;
                    }
                    tokio::time::sleep(Duration::from_millis(250)).await;
                }
            })
            .await
            .is_ok();
            if ready {
                "READY: centrald-server.service is enabled, running, and accepting local health connections. It will start automatically after reboot.".into()
            } else {
                "INCOMPLETE: setup committed and the service is enabled, but the daemon did not become healthy within 15 seconds. Run: sudo systemctl status centrald-server --no-pager; then sudo centrald-server config and choose Health, status, and next steps.".into()
            }
        }
        Ok(status) => format!(
            "INCOMPLETE: setup committed, but systemd could not start CentralD (exit status {status}). Run: sudo systemctl enable --now centrald-server"
        ),
        Err(error) => format!(
            "INCOMPLETE: setup committed, but systemd startup failed ({error}). Run: sudo systemctl enable --now centrald-server"
        ),
    }
}

async fn create_enrollment_key(
    config_path: &Path,
    args: EnrollArgs,
    role: &str,
    json: bool,
) -> Result<()> {
    require_root()?;
    let config = ServerConfig::load(config_path)?;
    let ttl = humantime::parse_duration(&args.expires).context("invalid --expires duration")?;
    if ttl.is_zero() || ttl > std::time::Duration::from_secs(24 * 60 * 60) {
        bail!("enrollment-key lifetime must be greater than zero and no more than 24 hours");
    }
    let name = args.name.unwrap_or_else(|| format!("{role} enrollment"));
    let database_url = resolve_database_url(&config)?;
    let pool = connect_and_migrate(
        database_url.expose_secret(),
        config.database.max_connections,
        config.server.instance_id,
    )
    .await?;
    let created = create_key(&pool, &config, role, &name, ttl).await?;
    pool.close().await;

    if json {
        println!(
            "{}",
            serde_json::json!({
                "id": created.id,
                "role": created.role,
                "name": created.name,
                "expiresAt": created.expires_at,
                "accessKey": created.key.expose_secret(),
            })
        );
    } else {
        println!("one-time {role} access key (shown once):");
        println!("{}", created.key.expose_secret());
        println!("expires: {}", created.expires_at);
    }
    Ok(())
}

fn init_tracing(json: bool) -> Result<()> {
    let filter = EnvFilter::try_from_default_env().unwrap_or_else(|_| EnvFilter::new("info"));
    if json {
        tracing_subscriber::fmt()
            .with_env_filter(filter)
            .json()
            .try_init()
            .map_err(|error| anyhow::anyhow!(error.to_string()))?;
    } else {
        tracing_subscriber::fmt()
            .with_env_filter(filter)
            .try_init()
            .map_err(|error| anyhow::anyhow!(error.to_string()))?;
    }
    Ok(())
}
