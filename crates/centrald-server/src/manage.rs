use std::fs;
use std::io::{IsTerminal, stdin, stdout};
use std::net::SocketAddr;
use std::path::{Path, PathBuf};
use std::sync::Arc;
use std::time::Duration;

use anyhow::{Context, Result, bail};
use centrald_common::config::ServerConfig;
use centrald_common::enrollment::{
    EnrollmentInvitationClaims, EnrollmentRole, generate_enrollment_invitation, hash_enrollment_key,
};
use centrald_common::host::canonical_host;
use centrald_common::secure_fs::{prune_file_backups, replace_file_with_backup, write_new_file};
use centrald_pki::{certificate_not_after, issue_server_identity, rotate_online_issuers};
use chrono::{DateTime, Utc};
use console::style;
use dialoguer::{Confirm, Input, Password, Select, theme::ColorfulTheme};
use secrecy::{ExposeSecret, SecretString};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use sqlx::{PgPool, Postgres, Transaction};
use tokio::sync::Semaphore;
use tracing::warn;
use uuid::Uuid;

use crate::config_lock::{
    ConfigFileLock, DatabaseUpdateTransaction, recover_interrupted_database_update_locked,
    recover_interrupted_settings_update_locked,
};
use crate::db::{
    connect_and_migrate, database_environment_contents, resolve_database_url,
    validate_database_url_policy, verify_owned_database,
};
use crate::file_security::{read_root_private_text, read_root_public_text};
use crate::local_audit;
use crate::local_control::LocalControlClient;

const MAX_ENROLLMENT_TTL: Duration = Duration::from_secs(24 * 60 * 60);
const AUDIT_LOCK_ID: i64 = 1_129_601_348;
const TLS_ROTATION_JOURNAL_NAME: &str = ".centrald-tls-rotation.json";
const ISSUER_ROTATION_JOURNAL_NAME: &str = ".centrald-issuer-rotation.json";
const ROOT_REPLACEMENT_JOURNAL_NAME: &str = ".centrald-root-replacement.json";
const TLS_RETIREMENT_JOURNAL_NAME: &str = ".centrald-tls-retirement.json";
const SERVER_RENEW_BEFORE_DAYS: i64 = 30;
const CONFIG_BACKUP_RETENTION: usize = 10;

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct TlsRotationJournal {
    version: u32,
    nonce: Uuid,
    config_path: PathBuf,
    server_chain: PathBuf,
    server_key: PathBuf,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct IssuerRotationJournal {
    version: u32,
    nonce: Uuid,
    config_path: PathBuf,
    targets: Vec<IssuerRotationTarget>,
}

/// Crash-recovery journal for the offline-root replacement ceremony: the root
/// certificate plus the three issuer certificates/keys and the server leaf.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct RootReplacementJournal {
    version: u32,
    nonce: Uuid,
    config_path: PathBuf,
    targets: Vec<IssuerRotationTarget>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct IssuerRotationTarget {
    path: PathBuf,
    private: bool,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct TlsRetirementJournal {
    version: u32,
    config_path: PathBuf,
    backups: Vec<PathBuf>,
}

type IdentityListRow = (Uuid, String, DateTime<Utc>, Option<DateTime<Utc>>);
type EnrollmentListRow = (
    Uuid,
    String,
    String,
    DateTime<Utc>,
    DateTime<Utc>,
    Option<DateTime<Utc>>,
    Option<DateTime<Utc>>,
    Option<String>,
);

#[derive(Debug)]
pub struct CreatedEnrollmentKey {
    pub id: Uuid,
    pub role: String,
    pub name: String,
    pub expires_at: DateTime<Utc>,
    pub key: SecretString,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct IdentitySummary {
    pub id: Uuid,
    pub name: String,
    pub created_at: DateTime<Utc>,
    pub revoked_at: Option<DateTime<Utc>>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct EnrollmentKeySummary {
    pub id: Uuid,
    pub role: String,
    pub name: String,
    pub expires_at: DateTime<Utc>,
    pub created_at: DateTime<Utc>,
    pub consumed_at: Option<DateTime<Utc>>,
    pub revoked_at: Option<DateTime<Utc>>,
    pub revoked_reason: Option<String>,
}

impl EnrollmentKeySummary {
    #[must_use]
    pub fn is_pending(&self, now: &DateTime<Utc>) -> bool {
        self.consumed_at.is_none() && self.revoked_at.is_none() && self.expires_at > *now
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct DiagnosticsSummary {
    pub active_clients: i64,
    pub active_admins: i64,
    pub pending_enrollments: i64,
}

#[derive(Debug, Clone, Copy)]
enum MenuAction {
    EnrollClient,
    EnrollAdmin,
    ListClients,
    ListAdmins,
    ManageClientInvitations,
    ManageAdminInvitations,
    RevokeClient,
    RevokeAdmin,
    Configure,
    RotateIssuers,
    ReplaceRoot,
    ExportTrust,
    ExportAudit,
    Diagnostics,
    Exit,
}

/// Runs the local, guided server configuration and administration console.
///
/// The console reads `PostgreSQL` credentials only in the root-owned process and
/// does not require the network daemon to be running.
///
/// # Errors
///
/// Returns an error when the process is not an interactive root session, the
/// configuration cannot be loaded, or terminal interaction fails.
pub async fn run(config_path: &Path) -> Result<()> {
    require_interactive_root()?;
    let mut config = ServerConfig::load(config_path)?;
    let theme = ColorfulTheme::default();

    println!();
    println!("{}", style("CentralD Server Configuration").cyan().bold());
    println!(
        "Routine tasks are first. Advanced server, database, and PKI controls remain available below."
    );

    loop {
        println!();
        let action = select_action(&theme)?;
        if matches!(action, MenuAction::Exit) {
            println!("{}", style("Goodbye.").dim());
            return Ok(());
        }
        let result = match action {
            MenuAction::EnrollClient => guided_enrollment(&config, "client", &theme).await,
            MenuAction::EnrollAdmin => guided_enrollment(&config, "admin", &theme).await,
            MenuAction::ListClients => guided_list(&config, "client").await,
            MenuAction::ListAdmins => guided_list(&config, "admin").await,
            MenuAction::ManageClientInvitations => {
                guided_manage_invitations(&config, "client", &theme).await
            }
            MenuAction::ManageAdminInvitations => {
                guided_manage_invitations(&config, "admin", &theme).await
            }
            MenuAction::RevokeClient => guided_revoke(&config, "client", &theme).await,
            MenuAction::RevokeAdmin => guided_revoke(&config, "admin", &theme).await,
            MenuAction::Configure => configure(config_path, &mut config, &theme).await,
            MenuAction::RotateIssuers => {
                rotate_online_issuers_guided(config_path, &mut config, &theme)
            }
            MenuAction::ReplaceRoot => replace_root_guided(config_path, &mut config, &theme),
            MenuAction::ExportTrust => export_trust(&config, &theme),
            MenuAction::ExportAudit => export_audit_guided(config_path).await,
            MenuAction::Diagnostics => diagnostics(config_path, &config).await,
            MenuAction::Exit => unreachable!(),
        };
        if let Err(error) = result {
            eprintln!(
                "{} {error:#}",
                style("Could not complete action:").red().bold()
            );
        }
    }
}

/// Creates and stores a single-use, self-contained enrollment invitation.
///
/// # Errors
///
/// Returns an error for invalid input, unreadable trust material, hashing
/// failure, or database/audit failure.
pub async fn create_enrollment_key(
    pool: &PgPool,
    config: &ServerConfig,
    role: &str,
    name: &str,
    ttl: Duration,
) -> Result<CreatedEnrollmentKey> {
    create_enrollment_key_bounded(pool, config, role, name, ttl, None).await
}

/// Creates an enrollment invitation while optionally sharing the daemon Argon2
/// concurrency limit used by the network enrollment path.
///
/// # Errors
///
/// Returns an error for invalid input, unreadable trust material, hashing
/// failure, or database/audit failure.
pub async fn create_enrollment_key_bounded(
    pool: &PgPool,
    config: &ServerConfig,
    role: &str,
    name: &str,
    ttl: Duration,
    enrollment_crypto_limit: Option<Arc<Semaphore>>,
) -> Result<CreatedEnrollmentKey> {
    let invitation_role = parse_role(role)?;
    validate_name(name, 128, "enrollment name")?;
    if ttl.is_zero() || ttl > MAX_ENROLLMENT_TTL {
        bail!("enrollment-key lifetime must be greater than zero and no more than 24 hours");
    }

    let id = Uuid::now_v7();
    let expires_at = Utc::now()
        + chrono::Duration::from_std(ttl).context("enrollment-key lifetime is too large")?;
    let root_ca_pem =
        read_root_public_text(&config.pki.root_cert, 256 * 1024, "root CA certificate")?;
    let claims = EnrollmentInvitationClaims::new(
        id,
        config.server.instance_id,
        invitation_role,
        name.to_owned(),
        config.server.public_host.clone(),
        config.server.enrollment_listen.port(),
        config.server.client_listen.port(),
        config.server.admin_listen.port(),
        root_ca_pem,
        expires_at,
    );
    let key = generate_enrollment_invitation(&claims)?;
    let _crypto_permit = match enrollment_crypto_limit {
        Some(limit) => Some(
            limit
                .acquire_owned()
                .await
                .context("enrollment cryptography limit closed")?,
        ),
        None => None,
    };
    let secret_hash = tokio::task::spawn_blocking({
        let key = SecretString::from(key.expose_secret().to_owned());
        move || hash_enrollment_key(&key)
    })
    .await
    .context("enrollment hashing worker failed")?
    .context("hash enrollment invitation")?;
    let mut transaction = pool.begin().await?;
    sqlx::query(
        "INSERT INTO enrollment_keys (id, role, name, secret_hash, expires_at) \
         VALUES ($1, $2, $3, $4, $5)",
    )
    .bind(id)
    .bind(role)
    .bind(name)
    .bind(secret_hash)
    .bind(expires_at)
    .execute(&mut *transaction)
    .await
    .context("store one-time enrollment key")?;
    append_local_audit(
        &mut transaction,
        "enrollment_key.create",
        None,
        serde_json::json!({"key_id": id, "role": role}),
    )
    .await?;
    transaction.commit().await?;

    Ok(CreatedEnrollmentKey {
        id,
        role: role.to_owned(),
        name: name.to_owned(),
        expires_at,
        key,
    })
}

fn select_action(theme: &ColorfulTheme) -> Result<MenuAction> {
    let labels = [
        "Add a client (guided)",
        "Client invitations (list or revoke)",
        "Health, status, and next steps",
        "Create an Admin access key",
        "List clients",
        "List Admins",
        "Admin access keys (list or revoke)",
        "Revoke a client",
        "Revoke an Admin",
        "Server settings (advanced)",
        "Rotate online PKI issuers (advanced; offline root required)",
        "Replace the offline root CA (advanced; current offline root required)",
        "Export the root trust certificate",
        "Export the verified audit chain (advanced)",
        "Exit",
    ];
    let actions = [
        MenuAction::EnrollClient,
        MenuAction::ManageClientInvitations,
        MenuAction::Diagnostics,
        MenuAction::EnrollAdmin,
        MenuAction::ListClients,
        MenuAction::ListAdmins,
        MenuAction::ManageAdminInvitations,
        MenuAction::RevokeClient,
        MenuAction::RevokeAdmin,
        MenuAction::Configure,
        MenuAction::RotateIssuers,
        MenuAction::ReplaceRoot,
        MenuAction::ExportTrust,
        MenuAction::ExportAudit,
        MenuAction::Exit,
    ];
    let selected = Select::with_theme(theme)
        .with_prompt("What would you like to do?")
        .items(labels)
        .default(0)
        .interact()?;
    actions
        .get(selected)
        .copied()
        .context("invalid menu selection")
}

async fn guided_enrollment(config: &ServerConfig, role: &str, theme: &ColorfulTheme) -> Result<()> {
    println!();
    println!("{}", style(format!("Create {role} access")).cyan().bold());
    println!("The resulting bearer invitation is single-use and shown once.");
    let name = Input::<String>::with_theme(theme)
        .with_prompt(if role == "client" {
            "Friendly client name"
        } else {
            "Admin name"
        })
        .validate_with(|value: &String| validate_prompt_name(value))
        .interact_text()?;
    let expiries = ["15 minutes", "1 hour", "4 hours", "24 hours"];
    let durations = [
        Duration::from_secs(15 * 60),
        Duration::from_secs(60 * 60),
        Duration::from_secs(4 * 60 * 60),
        Duration::from_secs(24 * 60 * 60),
    ];
    let selected = Select::with_theme(theme)
        .with_prompt("Invitation lifetime")
        .items(expiries)
        .default(0)
        .interact()?;
    if !Confirm::with_theme(theme)
        .with_prompt(format!("Create one {role} invitation for {name}?"))
        .default(true)
        .interact()?
    {
        println!("No invitation created.");
        return Ok(());
    }
    let duration = *durations
        .get(selected)
        .context("invalid invitation lifetime selection")?;
    let pool = open_pool(config).await?;
    let created = create_enrollment_key(&pool, config, role, &name, duration).await?;
    pool.close().await;

    println!();
    println!("{}", style("Access key (shown once)").yellow().bold());
    println!("{}", created.key.expose_secret());
    println!("Expires: {}", created.expires_at);
    println!();
    if role == "client" {
        println!("On the target machine run: centrald-client enroll");
        println!("Paste the key when prompted. A server IP/FQDN override is optional.");
    } else {
        println!("Paste this single key into CentralD Admin.");
    }
    Ok(())
}

async fn guided_list(config: &ServerConfig, role: &str) -> Result<()> {
    let pool = open_pool(config).await?;
    let rows = list_identity_records(&pool, role).await?;
    pool.close().await;
    println!();
    println!(
        "{}",
        style(format!("{}s", display_role(role))).cyan().bold()
    );
    if rows.is_empty() {
        println!("None enrolled yet.");
        return Ok(());
    }
    for identity in rows {
        let state = identity
            .revoked_at
            .map_or("active".to_owned(), |at| format!("revoked {at}"));
        println!(
            "- {}  [{state}]\n  ID: {}\n  Created: {}",
            identity.name, identity.id, identity.created_at
        );
    }
    Ok(())
}

async fn guided_manage_invitations(
    config: &ServerConfig,
    role: &str,
    theme: &ColorfulTheme,
) -> Result<()> {
    let pool = open_pool(config).await?;
    let rows = list_enrollment_key_records(&pool, role, true).await?;
    println!();
    println!(
        "{}",
        style(format!("{} invitations", display_role(role)))
            .cyan()
            .bold()
    );
    if rows.is_empty() {
        println!("No invitations have been created.");
        pool.close().await;
        return Ok(());
    }
    let now = Utc::now();
    for key in &rows {
        let state = if let Some(at) = key.consumed_at {
            format!("consumed {at}")
        } else if let Some(at) = key.revoked_at {
            format!("revoked {at}")
        } else if key.expires_at <= now {
            format!("expired {}", key.expires_at)
        } else {
            format!("pending until {}", key.expires_at)
        };
        println!("- {} ({}) [{state}]", key.name, key.id);
    }

    let pending: Vec<&EnrollmentKeySummary> =
        rows.iter().filter(|key| key.is_pending(&now)).collect();
    if pending.is_empty()
        || !Confirm::with_theme(theme)
            .with_prompt("Revoke one pending invitation?")
            .default(false)
            .interact()?
    {
        pool.close().await;
        return Ok(());
    }
    let labels: Vec<String> = pending
        .iter()
        .map(|key| format!("{} ({}) expires {}", key.name, key.id, key.expires_at))
        .collect();
    let selected = Select::with_theme(theme)
        .with_prompt("Invitation to revoke")
        .items(&labels)
        .interact()?;
    let key = pending
        .get(selected)
        .copied()
        .context("invalid invitation selection")?;
    let reason = Input::<String>::with_theme(theme)
        .with_prompt("Reason (stored in audit history)")
        .validate_with(|value: &String| validate_prompt_reason(value))
        .interact_text()?;
    if Confirm::with_theme(theme)
        .with_prompt(format!("Revoke invitation {} for {}?", key.id, key.name))
        .default(false)
        .interact()?
    {
        revoke_enrollment_key_record(&pool, role, key.id, &reason).await?;
        println!("{} Invitation revoked.", style("✓").green());
    }
    pool.close().await;
    Ok(())
}

/// Returns at most 500 enrollment invitation summaries for a validated role.
/// The bearer secret is never stored or returned.
///
/// # Errors
///
/// Returns an error for invalid roles or database query failure.
pub async fn list_enrollment_key_records(
    pool: &PgPool,
    role: &str,
    include_inactive: bool,
) -> Result<Vec<EnrollmentKeySummary>> {
    parse_role(role)?;
    let rows: Vec<EnrollmentListRow> = if include_inactive {
        sqlx::query_as(
            "SELECT id, role, name, expires_at, created_at, consumed_at, revoked_at, revoked_reason \
             FROM enrollment_keys WHERE role = $1 ORDER BY created_at DESC LIMIT 500",
        )
        .bind(role)
        .fetch_all(pool)
        .await?
    } else {
        sqlx::query_as(
            "SELECT id, role, name, expires_at, created_at, consumed_at, revoked_at, revoked_reason \
             FROM enrollment_keys WHERE role = $1 AND consumed_at IS NULL \
             AND revoked_at IS NULL AND expires_at > NOW() \
             ORDER BY created_at DESC LIMIT 500",
        )
        .bind(role)
        .fetch_all(pool)
        .await?
    };
    Ok(rows
        .into_iter()
        .map(
            |(id, role, name, expires_at, created_at, consumed_at, revoked_at, revoked_reason)| {
                EnrollmentKeySummary {
                    id,
                    role,
                    name,
                    expires_at,
                    created_at,
                    consumed_at,
                    revoked_at,
                    revoked_reason,
                }
            },
        )
        .collect())
}

/// Transactionally revokes one pending invitation and appends local audit
/// metadata. Consumed, expired, or already-revoked invitations cannot be
/// changed.
///
/// # Errors
///
/// Returns an error for invalid input, stale state, or database/audit failure.
pub async fn revoke_enrollment_key_record(
    pool: &PgPool,
    role: &str,
    key_id: Uuid,
    reason: &str,
) -> Result<()> {
    parse_role(role)?;
    validate_name(reason, 512, "revocation reason")?;
    let mut transaction = pool.begin().await?;
    let affected = sqlx::query(
        "UPDATE enrollment_keys SET revoked_at = NOW(), revoked_reason = $3 \
         WHERE id = $1 AND role = $2 AND consumed_at IS NULL \
         AND revoked_at IS NULL AND expires_at > NOW()",
    )
    .bind(key_id)
    .bind(role)
    .bind(reason)
    .execute(&mut *transaction)
    .await?
    .rows_affected();
    if affected != 1 {
        bail!("invitation is missing, expired, consumed, or already revoked");
    }
    append_local_audit(
        &mut transaction,
        "enrollment_key.revoke",
        None,
        serde_json::json!({"key_id": key_id, "role": role, "reason": reason}),
    )
    .await?;
    transaction.commit().await?;
    Ok(())
}

async fn guided_revoke(config: &ServerConfig, role: &str, theme: &ColorfulTheme) -> Result<()> {
    let pool = open_pool(config).await?;
    let rows: Vec<IdentitySummary> = list_identity_records(&pool, role)
        .await?
        .into_iter()
        .filter(|identity| identity.revoked_at.is_none())
        .collect();
    if rows.is_empty() {
        println!("No active {}s to revoke.", display_role(role));
        pool.close().await;
        return Ok(());
    }
    let labels: Vec<String> = rows
        .iter()
        .map(|identity| format!("{} ({})", identity.name, identity.id))
        .collect();
    let selected = Select::with_theme(theme)
        .with_prompt(format!("Which {} should be revoked?", display_role(role)))
        .items(&labels)
        .interact()?;
    let identity = rows.get(selected).context("invalid identity selection")?;
    let reason = Input::<String>::with_theme(theme)
        .with_prompt("Reason (stored in audit history)")
        .validate_with(|value: &String| validate_prompt_reason(value))
        .interact_text()?;
    if !Confirm::with_theme(theme)
        .with_prompt(format!(
            "Revoke {}? Existing credentials will stop working.",
            identity.name
        ))
        .default(false)
        .interact()?
    {
        println!("No changes made.");
        pool.close().await;
        return Ok(());
    }
    revoke_identity_record(&pool, role, identity.id, &reason).await?;
    pool.close().await;
    println!("{} {} revoked.", style("✓").green(), identity.name);
    Ok(())
}

/// Returns at most 500 identity summaries for a validated role.
///
/// # Errors
///
/// Returns an error for invalid roles or database query failure.
pub async fn list_identity_records(pool: &PgPool, role: &str) -> Result<Vec<IdentitySummary>> {
    parse_role(role)?;
    let rows: Vec<IdentityListRow> = sqlx::query_as(
        "SELECT id, name, created_at, revoked_at FROM identities \
         WHERE role = $1 ORDER BY name, id LIMIT 500",
    )
    .bind(role)
    .fetch_all(pool)
    .await?;
    Ok(rows
        .into_iter()
        .map(|(id, name, created_at, revoked_at)| IdentitySummary {
            id,
            name,
            created_at,
            revoked_at,
        })
        .collect())
}

/// Transactionally revokes one identity and appends local audit metadata.
///
/// # Errors
///
/// Returns an error for invalid input, missing/already-revoked identity, last
/// Admin protection, or database/audit failure.
pub async fn revoke_identity_record(
    pool: &PgPool,
    role: &str,
    identity_id: Uuid,
    reason: &str,
) -> Result<()> {
    parse_role(role)?;
    validate_name(reason, 512, "revocation reason")?;
    let mut transaction = pool.begin().await?;
    sqlx::query("SELECT pg_advisory_xact_lock($1)")
        .bind(AUDIT_LOCK_ID + 1)
        .execute(&mut *transaction)
        .await?;
    if role == "admin" {
        let active_admins: i64 = sqlx::query_scalar(
            "SELECT COUNT(*) FROM identities WHERE role = 'admin' AND revoked_at IS NULL",
        )
        .fetch_one(&mut *transaction)
        .await?;
        if active_admins <= 1 {
            bail!("refusing to revoke the last active Admin; create a replacement first");
        }
    }
    let affected = sqlx::query(
        "UPDATE identities SET revoked_at = NOW(), revoked_reason = $2, updated_at = NOW() \
         WHERE id = $1 AND role = $3 AND revoked_at IS NULL",
    )
    .bind(identity_id)
    .bind(reason)
    .bind(role)
    .execute(&mut *transaction)
    .await?
    .rows_affected();
    if affected != 1 {
        bail!("identity changed before revocation; refresh and try again");
    }
    append_local_audit(
        &mut transaction,
        "identity.revoke",
        Some(identity_id),
        serde_json::json!({"reason": reason, "role": role}),
    )
    .await?;
    transaction.commit().await?;
    Ok(())
}

async fn configure(
    config_path: &Path,
    config: &mut ServerConfig,
    theme: &ColorfulTheme,
) -> Result<()> {
    loop {
        println!();
        println!("{}", style("Server settings (advanced)").cyan().bold());
        println!("Normal enrollment and health tasks are available from the previous menu.");
        let options = [
            "Network listeners and TLS name (advanced)",
            "Client, job, and shell runtime policy (advanced)",
            "Update policy",
            "PostgreSQL settings (advanced)",
            "Paths and storage (advanced)",
            "View complete non-secret TOML",
            "Back",
        ];
        match Select::with_theme(theme)
            .with_prompt("Configuration area")
            .items(options)
            .default(0)
            .interact()?
        {
            0 => configure_network(config_path, config, theme)?,
            1 => configure_runtime(config_path, config, theme)?,
            2 => configure_updates(config_path, config, theme)?,
            3 => configure_database(config_path, config, theme).await?,
            4 => configure_paths(config_path, config, theme)?,
            5 => println!("{}", toml::to_string_pretty(config)?),
            _ => return Ok(()),
        }
    }
}

fn configure_network(
    config_path: &Path,
    config: &mut ServerConfig,
    theme: &ColorfulTheme,
) -> Result<()> {
    let mut replacement = config.clone();
    replacement.server.public_host = Input::<String>::with_theme(theme)
        .with_prompt("TLS name clients verify")
        .default(config.server.public_host.clone())
        .validate_with(|value: &String| validate_prompt_host(value))
        .interact_text()?;
    replacement.server.public_host =
        canonical_host(&replacement.server.public_host).context("canonicalize public TLS host")?;
    replacement.server.enrollment_listen = socket_prompt(
        theme,
        "Enrollment listener",
        config.server.enrollment_listen,
    )?;
    replacement.server.client_listen =
        socket_prompt(theme, "Client mTLS listener", config.server.client_listen)?;
    replacement.server.admin_listen =
        socket_prompt(theme, "Admin mTLS listener", config.server.admin_listen)?;
    replacement.validate()?;
    if replacement.server.public_host == config.server.public_host
        && replacement.server.enrollment_listen == config.server.enrollment_listen
        && replacement.server.client_listen == config.server.client_listen
        && replacement.server.admin_listen == config.server.admin_listen
    {
        println!("No changes made.");
        return Ok(());
    }
    if !Confirm::with_theme(theme)
        .with_prompt("Save network settings? Server restart required.")
        .default(true)
        .interact()?
    {
        return Ok(());
    }
    if replacement.server.public_host == config.server.public_host {
        save_config(config_path, config, replacement)?;
    } else {
        rotate_server_identity_and_save(config_path, config, replacement)?;
    }
    Ok(())
}

fn configure_runtime(
    config_path: &Path,
    config: &mut ServerConfig,
    theme: &ColorfulTheme,
) -> Result<()> {
    let mut replacement = config.clone();
    replacement.runtime.heartbeat_interval_seconds = u32_prompt(
        theme,
        "Heartbeat interval seconds (5-3600)",
        config.runtime.heartbeat_interval_seconds,
        5,
        3600,
    )?;
    replacement.runtime.offline_after_seconds = u32_prompt(
        theme,
        "Mark client offline after seconds",
        config.runtime.offline_after_seconds,
        6,
        86_400,
    )?;
    replacement.runtime.job_ttl_seconds = u32_prompt(
        theme,
        "Job lifetime seconds",
        config.runtime.job_ttl_seconds,
        // The TTL must exceed the longest broker round trip (up to 15 minutes
        // for package operations) or terminal job events can be rejected as
        // expired after the operation already ran.
        1800,
        604_800,
    )?;
    replacement.runtime.shell_idle_timeout_seconds = u32_prompt(
        theme,
        "Shell idle timeout seconds",
        config.runtime.shell_idle_timeout_seconds,
        30,
        86_400,
    )?;
    replacement.runtime.max_shell_frame_bytes = u32_prompt(
        theme,
        "Maximum shell frame bytes",
        config.runtime.max_shell_frame_bytes,
        1024,
        1_048_576,
    )?;
    replacement.validate()?;
    confirm_and_save(config_path, config, replacement, theme)
}

fn configure_updates(
    config_path: &Path,
    config: &mut ServerConfig,
    theme: &ColorfulTheme,
) -> Result<()> {
    let mut replacement = config.clone();
    replacement.updates.enabled = Confirm::with_theme(theme)
        .with_prompt("Enable update checks?")
        .default(config.updates.enabled)
        .interact()?;
    replacement.updates.channel = Input::<String>::with_theme(theme)
        .with_prompt("Release channel")
        .default(config.updates.channel.clone())
        .validate_with(|value: &String| validate_short_text(value, 32))
        .interact_text()?;
    replacement.updates.manifest_url = Input::<String>::with_theme(theme)
        .with_prompt("Release manifest HTTPS URL")
        .default(config.updates.manifest_url.clone())
        .validate_with(|value: &String| validate_manifest_url(value))
        .interact_text()?;
    replacement.updates.check_interval_seconds = u32_prompt(
        theme,
        "Update check interval seconds",
        config.updates.check_interval_seconds,
        300,
        2_592_000,
    )?;
    replacement.updates.allow_prerelease = Confirm::with_theme(theme)
        .with_prompt("Allow prerelease versions?")
        .default(config.updates.allow_prerelease)
        .interact()?;
    replacement.validate()?;
    confirm_and_save(config_path, config, replacement, theme)
}

#[allow(clippy::too_many_lines)]
async fn configure_database(
    config_path: &Path,
    config: &mut ServerConfig,
    theme: &ColorfulTheme,
) -> Result<()> {
    let new_url = Password::with_theme(theme)
        .with_prompt("PostgreSQL URL (leave blank to keep current)")
        .allow_empty_password(true)
        .validate_with(|value: &String| {
            if value.is_empty() {
                Ok(())
            } else {
                validate_database_url(value)
            }
        })
        .interact()?;
    let mut replacement = config.clone();
    println!(
        "Database environment variable and secret-file path are package-managed: {} in {}",
        replacement.database.url_env,
        replacement.database.environment_file.display()
    );
    replacement.database.max_connections = u32_prompt(
        theme,
        "Maximum PostgreSQL connections",
        config.database.max_connections,
        1,
        100,
    )?;
    replacement.validate()?;
    if !Confirm::with_theme(theme)
        .with_prompt("Save database settings? Server restart required.")
        .default(true)
        .interact()?
    {
        return Ok(());
    }
    let serialized = toml::to_string_pretty(&replacement)?;
    let intended_revision = hex::encode(Sha256::digest(serialized.as_bytes()));

    let _lock = ConfigFileLock::acquire(config_path)?;
    recover_interrupted_database_update_locked(config_path)?;
    recover_interrupted_settings_update_locked(config_path)?;
    recover_interrupted_online_issuer_rotation_locked(config_path)?;
    recover_interrupted_tls_rotation_locked(config_path)?;
    let current = ServerConfig::load(config_path)?;
    if current != *config {
        bail!(
            "server configuration changed in another process; reopen centrald-server config and retry"
        );
    }
    let current_url = resolve_database_url(&current)?;
    let database_url = if new_url.is_empty() {
        current_url
    } else {
        if current.database.managed_local_role.is_some() && new_url != current_url.expose_secret() {
            bail!(
                "the recommended managed-local PostgreSQL location is lifecycle-bound to this installation; use the existing URL or perform an explicit backup/reset/restore instead of silently relocating it"
            );
        }
        tokio::time::timeout(
            Duration::from_secs(15),
            verify_owned_database(&new_url, current.server.instance_id),
        )
        .await
        .context("timed out verifying replacement PostgreSQL URL")??;
        SecretString::from(new_url)
    };
    let contents = database_environment_contents(
        replacement.server.instance_id,
        &replacement.database.url_env,
        database_url.expose_secret(),
    );
    local_audit::record(
        config_path,
        "database_settings.local_update",
        "pending",
        serde_json::json!({
            "intended_revision": &intended_revision,
            "max_connections": replacement.database.max_connections,
        }),
    )?;
    let transaction = DatabaseUpdateTransaction::begin_locked(
        config_path,
        &replacement.database.environment_file,
        contents.as_bytes(),
        serialized.as_bytes(),
    )?;
    if let Err(error) = transaction.commit() {
        match recover_interrupted_database_update_locked(config_path) {
            Ok(()) => {
                warn!(%error, "database settings publication was interrupted but recovery completed it");
            }
            Err(recovery) => {
                return Err(error.context(format!(
                    "database settings publication failed and recovery also failed: {recovery:#}"
                )));
            }
        }
    }
    *config = ServerConfig::load(config_path)?;
    if let Err(error) = local_audit::record(
        config_path,
        "database_settings.local_update",
        "succeeded",
        serde_json::json!({"new_revision": &intended_revision}),
    ) {
        warn!(%error, "database settings were committed; final local audit append is pending reconciliation");
    }
    println!(
        "{} Database settings committed atomically.",
        style("✓").green()
    );
    println!("Restart centrald-server to apply runtime changes.");
    Ok(())
}

#[allow(clippy::unnecessary_wraps)]
fn configure_paths(
    _config_path: &Path,
    config: &mut ServerConfig,
    _theme: &ColorfulTheme,
) -> Result<()> {
    println!(
        "CentralD package paths are fixed so the systemd sandbox and privileged recovery boundary cannot drift."
    );
    println!("  Data directory: {}", config.server.data_dir.display());
    println!("  Local socket: {}", config.server.local_socket.display());
    println!(
        "  Database secret file: {}",
        config.database.environment_file.display()
    );
    println!("  PKI root: {}", config.pki.root_cert.display());
    println!(
        "  Server certificate: {}",
        config.pki.server_chain.display()
    );
    println!(
        "  Server issuer: {}",
        config.pki.server_issuer_cert.display()
    );
    println!(
        "  Client issuer: {}",
        config.pki.client_issuer_cert.display()
    );
    println!("  Admin issuer: {}", config.pki.admin_issuer_cert.display());
    println!(
        "Use the guided online-issuer rotation action for PKI key rotation; paths themselves are not configurable."
    );
    Ok(())
}

fn rotate_online_issuers_guided(
    config_path: &Path,
    config: &mut ServerConfig,
    theme: &ColorfulTheme,
) -> Result<()> {
    println!();
    println!("{}", style("Rotate online PKI issuers").cyan().bold());
    println!(
        "This maintenance ceremony requires the offline root recovery PEM. The root itself is not changed."
    );
    println!(
        "Existing client/Admin certificates continue to chain to the same root while new certificates use the replacement issuers."
    );
    let recovery_path = PathBuf::from(
        Input::<String>::with_theme(theme)
            .with_prompt("Offline root recovery PEM path")
            .validate_with(|value: &String| validate_nonempty(value, "path"))
            .interact_text()?,
    );
    if !recovery_path.is_absolute() {
        bail!("offline root recovery path must be absolute");
    }
    let bundle = SecretString::from(read_root_private_text(
        &recovery_path,
        256 * 1024,
        "offline root recovery bundle",
    )?);
    let (recovery_root, recovery_key) = parse_root_recovery_bundle(bundle.expose_secret())?;
    let configured_root =
        read_root_public_text(&config.pki.root_cert, 256 * 1024, "root CA certificate")?;
    if recovery_root.trim() != configured_root.trim() {
        bail!("offline recovery certificate does not match this server's configured root CA");
    }
    let rotated = rotate_online_issuers(&recovery_root, recovery_key.expose_secret())
        .context("generate replacement online issuers from offline root")?;
    let server_identity = issue_server_identity(
        &config.server.public_host,
        &rotated.server_certificate_pem,
        &rotated.server_private_key_pem,
        &configured_root,
    )?;
    if !Confirm::with_theme(theme)
        .with_prompt("Replace all three online issuers and the server TLS leaf? Restart required.")
        .default(false)
        .interact()?
    {
        println!("Issuer rotation cancelled.");
        return Ok(());
    }

    commit_online_issuer_rotation(config_path, config, rotated, server_identity)?;
    println!(
        "{} Online issuers and server TLS leaf rotated.",
        style("✓").green()
    );
    println!(
        "Restart centrald-server. Rollback keys are retired only after all TLS listeners pass health probes."
    );
    Ok(())
}

fn parse_root_recovery_bundle(bundle: &str) -> Result<(String, SecretString)> {
    fn extract(bundle: &str, begin: &str, end: &str) -> Result<String> {
        let start = bundle
            .find(begin)
            .context("recovery bundle is missing required PEM material")?;
        let suffix = &bundle[start..];
        let finish = suffix
            .find(end)
            .map(|index| index + end.len())
            .context("recovery bundle contains truncated PEM material")?;
        Ok(format!("{}\n", &suffix[..finish]))
    }
    let certificate = extract(
        bundle,
        "-----BEGIN CERTIFICATE-----",
        "-----END CERTIFICATE-----",
    )?;
    let private_key = extract(
        bundle,
        "-----BEGIN PRIVATE KEY-----",
        "-----END PRIVATE KEY-----",
    )?;
    Ok((certificate, SecretString::from(private_key)))
}

#[allow(clippy::too_many_lines)]
fn commit_online_issuer_rotation(
    config_path: &Path,
    config: &mut ServerConfig,
    rotated: centrald_pki::OnlineIssuerRotation,
    server_identity: centrald_pki::PemIdentity,
) -> Result<()> {
    let _lock = ConfigFileLock::acquire(config_path)?;
    recover_interrupted_database_update_locked(config_path)?;
    recover_interrupted_settings_update_locked(config_path)?;
    recover_interrupted_online_issuer_rotation_locked(config_path)?;
    recover_interrupted_tls_rotation_locked(config_path)?;
    let retirement_path = tls_retirement_journal_path(config_path)?;
    if retirement_path.exists() {
        bail!(
            "previous PKI/TLS rollback material is awaiting a healthy server restart; restart centrald-server before rotating issuers again"
        );
    }
    let current = ServerConfig::load(config_path)?;
    if current != *config {
        bail!(
            "server configuration changed in another process; reopen centrald-server config and retry"
        );
    }

    let replacements: Vec<(PathBuf, bool, Vec<u8>)> = vec![
        (
            config.pki.server_issuer_cert.clone(),
            false,
            rotated.server_certificate_pem.into_bytes(),
        ),
        (
            config.pki.server_issuer_key.clone(),
            true,
            rotated.server_private_key_pem.into_bytes(),
        ),
        (
            config.pki.client_issuer_cert.clone(),
            false,
            rotated.client_certificate_pem.into_bytes(),
        ),
        (
            config.pki.client_issuer_key.clone(),
            true,
            rotated.client_private_key_pem.into_bytes(),
        ),
        (
            config.pki.admin_issuer_cert.clone(),
            false,
            rotated.admin_certificate_pem.into_bytes(),
        ),
        (
            config.pki.admin_issuer_key.clone(),
            true,
            rotated.admin_private_key_pem.into_bytes(),
        ),
        (
            config.pki.server_chain.clone(),
            false,
            server_identity.certificate_chain_pem.into_bytes(),
        ),
        (
            config.pki.server_key.clone(),
            true,
            server_identity.private_key_pem.into_bytes(),
        ),
    ];
    let nonce = Uuid::now_v7();
    let targets: Vec<IssuerRotationTarget> = replacements
        .iter()
        .map(|(path, private, _)| IssuerRotationTarget {
            path: path.clone(),
            private: *private,
        })
        .collect();
    let journal = IssuerRotationJournal {
        version: 1,
        nonce,
        config_path: config_path.to_path_buf(),
        targets,
    };
    let journal_path = issuer_rotation_journal_path(config_path)?;
    let artifact_paths: Vec<RotationArtifactPaths> = replacements
        .iter()
        .map(|(path, _, _)| rotation_artifact_paths(path, nonce))
        .collect::<Result<_>>()?;
    let retirement = TlsRetirementJournal {
        version: 1,
        config_path: config_path.to_path_buf(),
        backups: artifact_paths
            .iter()
            .map(|paths| paths.backup.clone())
            .collect(),
    };

    local_audit::record(
        config_path,
        "pki.online_issuers.rotate",
        "pending",
        serde_json::json!({"issuer_count": 3}),
    )?;
    let staging = (|| {
        for ((path, private, bytes), paths) in replacements.iter().zip(&artifact_paths) {
            stage_rotation_artifact(path, paths, bytes, *private)?;
        }
        write_new_file(&journal_path, &serde_json::to_vec_pretty(&journal)?, true)?;
        write_new_file(
            &retirement_path,
            &serde_json::to_vec_pretty(&retirement)?,
            true,
        )?;
        sync_parent(&journal_path)?;
        Ok::<(), anyhow::Error>(())
    })();
    if let Err(error) = staging {
        let _ = local_audit::record(
            config_path,
            "pki.online_issuers.rotate",
            "failed",
            serde_json::json!({"phase": "stage"}),
        );
        if journal_path.exists() {
            let _ = recover_interrupted_online_issuer_rotation_locked(config_path);
        } else {
            cleanup_uncommitted_rotation_artifacts(&artifact_paths);
            let _ = fs::remove_file(&retirement_path);
        }
        return Err(error.context("stage online issuer rotation"));
    }

    let commit = (|| {
        for ((path, _, _), paths) in replacements.iter().zip(&artifact_paths) {
            atomic_replace_from_stage(&paths.stage, path)?;
            sync_parent(path)?;
        }
        fs::remove_file(&journal_path).with_context(|| {
            format!("remove issuer rotation journal {}", journal_path.display())
        })?;
        if let Err(error) = sync_parent(&journal_path) {
            warn!(%error, "online issuer rotation committed but journal-directory sync could not be confirmed");
        }
        Ok::<(), anyhow::Error>(())
    })();
    if let Err(error) = commit {
        let _ = local_audit::record(
            config_path,
            "pki.online_issuers.rotate",
            "failed",
            serde_json::json!({"phase": "commit"}),
        );
        return match recover_interrupted_online_issuer_rotation_locked(config_path) {
            Ok(()) => Err(error.context("online issuer rotation failed and was rolled back")),
            Err(rollback) => Err(error.context(format!(
                "online issuer rotation failed and rollback also failed: {rollback:#}"
            ))),
        };
    }
    if let Err(error) = local_audit::record(
        config_path,
        "pki.online_issuers.rotate",
        "succeeded",
        serde_json::json!({"issuer_count": 3}),
    ) {
        warn!(%error, "online issuer rotation committed; final local audit append is pending reconciliation");
    }
    Ok(())
}

/// Guided ceremony that replaces the offline root CA, all online issuers, and
/// the server TLS leaf. Authorized only by the current offline root recovery
/// key; every enrolled client/Admin must re-enroll afterwards.
fn replace_root_guided(
    config_path: &Path,
    config: &mut ServerConfig,
    theme: &ColorfulTheme,
) -> Result<()> {
    println!();
    println!("{}", style("Replace the offline root CA").cyan().bold());
    println!(
        "WARNING: every enrolled client and Admin chains to the current root and will be unable to connect after this ceremony. All devices must re-enroll."
    );
    println!(
        "This ceremony requires the CURRENT offline root recovery PEM and writes the replacement recovery material to a new root-only file."
    );
    let recovery_path = PathBuf::from(
        Input::<String>::with_theme(theme)
            .with_prompt("Current offline root recovery PEM path")
            .validate_with(|value: &String| validate_nonempty(value, "path"))
            .interact_text()?,
    );
    if !recovery_path.is_absolute() {
        bail!("offline root recovery path must be absolute");
    }
    let output_path = PathBuf::from(
        Input::<String>::with_theme(theme)
            .with_prompt("New offline root recovery PEM output path")
            .validate_with(|value: &String| validate_nonempty(value, "path"))
            .interact_text()?,
    );
    if !output_path.is_absolute() {
        bail!("new offline root recovery path must be absolute");
    }
    if output_path == recovery_path {
        bail!("the new recovery output must not overwrite the current recovery bundle");
    }
    if output_path.exists() {
        bail!("the new recovery output path already exists; refusing to overwrite it");
    }
    let bundle = SecretString::from(read_root_private_text(
        &recovery_path,
        256 * 1024,
        "current offline root recovery bundle",
    )?);
    let (recovery_root, recovery_key) = parse_root_recovery_bundle(bundle.expose_secret())?;
    let configured_root =
        read_root_public_text(&config.pki.root_cert, 256 * 1024, "root CA certificate")?;
    if recovery_root.trim() != configured_root.trim() {
        bail!("offline recovery certificate does not match this server's configured root CA");
    }
    let replacement = centrald_pki::replace_root(
        &recovery_root,
        recovery_key.expose_secret(),
        &config.server.public_host,
    )
    .context("generate a replacement root hierarchy authorized by the current offline root")?;
    if !Confirm::with_theme(theme)
        .with_prompt("Replace the offline root, all issuers, and the server TLS leaf? Every enrolled device must re-enroll.")
        .default(false)
        .interact()?
    {
        println!("Root replacement cancelled.");
        return Ok(());
    }
    commit_root_replacement(config_path, config, replacement, &output_path)?;
    println!("{} Offline root CA replaced.", style("✓").green());
    println!("Replacement recovery material: {}", output_path.display());
    println!(
        "Restart centrald-server. Rollback keys are retired only after all TLS listeners pass health probes. Re-enroll every client and Admin with the new trust anchor."
    );
    Ok(())
}

#[allow(clippy::too_many_lines)]
fn commit_root_replacement(
    config_path: &Path,
    config: &mut ServerConfig,
    replacement: centrald_pki::RootReplacement,
    output_path: &Path,
) -> Result<()> {
    let _lock = ConfigFileLock::acquire(config_path)?;
    recover_interrupted_database_update_locked(config_path)?;
    recover_interrupted_settings_update_locked(config_path)?;
    recover_interrupted_online_issuer_rotation_locked(config_path)?;
    recover_interrupted_root_replacement_locked(config_path)?;
    recover_interrupted_tls_rotation_locked(config_path)?;
    let retirement_path = tls_retirement_journal_path(config_path)?;
    if retirement_path.exists() {
        bail!(
            "previous PKI/TLS rollback material is awaiting a healthy server restart; restart centrald-server before replacing the root"
        );
    }
    let current = ServerConfig::load(config_path)?;
    if current != *config {
        bail!(
            "server configuration changed in another process; reopen centrald-server config and retry"
        );
    }

    let replacements: Vec<(PathBuf, bool, Vec<u8>)> = vec![
        (
            config.pki.root_cert.clone(),
            false,
            replacement.root_certificate_pem.clone().into_bytes(),
        ),
        (
            config.pki.server_issuer_cert.clone(),
            false,
            replacement.server_certificate_pem.into_bytes(),
        ),
        (
            config.pki.server_issuer_key.clone(),
            true,
            replacement.server_private_key_pem.into_bytes(),
        ),
        (
            config.pki.client_issuer_cert.clone(),
            false,
            replacement.client_certificate_pem.into_bytes(),
        ),
        (
            config.pki.client_issuer_key.clone(),
            true,
            replacement.client_private_key_pem.into_bytes(),
        ),
        (
            config.pki.admin_issuer_cert.clone(),
            false,
            replacement.admin_certificate_pem.into_bytes(),
        ),
        (
            config.pki.admin_issuer_key.clone(),
            true,
            replacement.admin_private_key_pem.into_bytes(),
        ),
        (
            config.pki.server_chain.clone(),
            false,
            replacement
                .server_identity
                .certificate_chain_pem
                .into_bytes(),
        ),
        (
            config.pki.server_key.clone(),
            true,
            replacement.server_identity.private_key_pem.into_bytes(),
        ),
    ];
    let nonce = Uuid::now_v7();
    let targets: Vec<IssuerRotationTarget> = replacements
        .iter()
        .map(|(path, private, _)| IssuerRotationTarget {
            path: path.clone(),
            private: *private,
        })
        .collect();
    let journal = RootReplacementJournal {
        version: 1,
        nonce,
        config_path: config_path.to_path_buf(),
        targets,
    };
    let journal_path = root_replacement_journal_path(config_path)?;
    let artifact_paths: Vec<RotationArtifactPaths> = replacements
        .iter()
        .map(|(path, _, _)| rotation_artifact_paths(path, nonce))
        .collect::<Result<_>>()?;
    let retirement = TlsRetirementJournal {
        version: 1,
        config_path: config_path.to_path_buf(),
        backups: artifact_paths
            .iter()
            .map(|paths| paths.backup.clone())
            .collect(),
    };
    // The replacement recovery bundle is written before the rotation journal
    // so an interrupted commit never loses the new offline root key.
    let bundle = format!(
        "{}{}",
        replacement.root_certificate_pem, replacement.root_private_key_pem
    );
    write_new_file(output_path, bundle.as_bytes(), true).with_context(|| {
        format!(
            "write replacement recovery bundle {}",
            output_path.display()
        )
    })?;

    local_audit::record(
        config_path,
        "pki.root.replace",
        "pending",
        serde_json::json!({"target_count": 9}),
    )?;
    let staging = (|| {
        for ((path, private, bytes), paths) in replacements.iter().zip(&artifact_paths) {
            stage_rotation_artifact(path, paths, bytes, *private)?;
        }
        write_new_file(&journal_path, &serde_json::to_vec_pretty(&journal)?, true)?;
        write_new_file(
            &retirement_path,
            &serde_json::to_vec_pretty(&retirement)?,
            true,
        )?;
        sync_parent(&journal_path)?;
        Ok::<(), anyhow::Error>(())
    })();
    if let Err(error) = staging {
        let _ = local_audit::record(
            config_path,
            "pki.root.replace",
            "failed",
            serde_json::json!({"phase": "stage"}),
        );
        if journal_path.exists() {
            let _ = recover_interrupted_root_replacement_locked(config_path);
        } else {
            cleanup_uncommitted_rotation_artifacts(&artifact_paths);
            let _ = fs::remove_file(&retirement_path);
        }
        return Err(error.context("stage offline root replacement"));
    }

    let commit = (|| {
        for ((path, _, _), paths) in replacements.iter().zip(&artifact_paths) {
            atomic_replace_from_stage(&paths.stage, path)?;
            sync_parent(path)?;
        }
        fs::remove_file(&journal_path).with_context(|| {
            format!("remove root replacement journal {}", journal_path.display())
        })?;
        if let Err(error) = sync_parent(&journal_path) {
            warn!(%error, "offline root replacement committed but journal-directory sync could not be confirmed");
        }
        Ok::<(), anyhow::Error>(())
    })();
    if let Err(error) = commit {
        let _ = local_audit::record(
            config_path,
            "pki.root.replace",
            "failed",
            serde_json::json!({"phase": "commit"}),
        );
        return match recover_interrupted_root_replacement_locked(config_path) {
            Ok(()) => Err(error.context("offline root replacement failed and was rolled back")),
            Err(rollback) => Err(error.context(format!(
                "offline root replacement failed and rollback also failed: {rollback:#}"
            ))),
        };
    }
    if let Err(error) = local_audit::record(
        config_path,
        "pki.root.replace",
        "succeeded",
        serde_json::json!({"target_count": 9}),
    ) {
        warn!(%error, "offline root replacement committed; final local audit append is pending reconciliation");
    }
    Ok(())
}

fn root_replacement_journal_path(config_path: &Path) -> Result<PathBuf> {
    let parent = config_path
        .parent()
        .filter(|parent| !parent.as_os_str().is_empty())
        .context("server configuration path has no parent")?;
    Ok(parent.join(ROOT_REPLACEMENT_JOURNAL_NAME))
}

/// Restores all pre-replacement files if the process stopped after publishing
/// a root-replacement journal but before completing the multi-file commit.
///
/// # Errors
///
/// Returns an error when the journal is malformed, rollback backups are
/// missing, or a file cannot be restored durably.
pub fn recover_interrupted_root_replacement(config_path: &Path) -> Result<()> {
    let journal_path = root_replacement_journal_path(config_path)?;
    if !journal_path.exists() {
        return Ok(());
    }
    let _lock = ConfigFileLock::acquire(config_path)?;
    recover_interrupted_root_replacement_locked(config_path)
}

pub(crate) fn recover_interrupted_root_replacement_locked(config_path: &Path) -> Result<()> {
    let journal_path = root_replacement_journal_path(config_path)?;
    if !journal_path.exists() {
        return Ok(());
    }
    let journal: RootReplacementJournal = serde_json::from_slice(
        &read_root_private_text(
            &journal_path,
            256 * 1024,
            "offline root replacement recovery journal",
        )?
        .into_bytes(),
    )
    .context("parse offline root replacement recovery journal")?;
    if journal.version != 1 || journal.config_path != config_path || journal.targets.len() != 9 {
        bail!("offline root replacement journal does not belong to this server configuration");
    }
    for target in &journal.targets {
        let paths = rotation_artifact_paths(&target.path, journal.nonce)?;
        validate_regular_file(&paths.backup)?;
        let original = if target.private {
            read_root_private_text(&paths.backup, 256 * 1024, "root replacement private backup")?
                .into_bytes()
        } else {
            read_root_public_text(&paths.backup, 256 * 1024, "root replacement backup")?
                .into_bytes()
        };
        if paths.stage.exists() {
            validate_regular_file(&paths.stage)?;
            fs::remove_file(&paths.stage)?;
        }
        write_new_file(&paths.stage, &original, target.private)?;
        atomic_replace_from_stage(&paths.stage, &target.path)?;
        sync_parent(&target.path)?;
    }
    fs::remove_file(&journal_path)?;
    let retirement_path = tls_retirement_journal_path(config_path)?;
    if retirement_path.exists() {
        validate_regular_file(&retirement_path)?;
        fs::remove_file(&retirement_path)?;
    }
    sync_parent(&journal_path)?;
    Ok(())
}

fn issuer_rotation_journal_path(config_path: &Path) -> Result<PathBuf> {
    let parent = config_path
        .parent()
        .filter(|parent| !parent.as_os_str().is_empty())
        .context("server configuration path has no parent")?;
    Ok(parent.join(ISSUER_ROTATION_JOURNAL_NAME))
}
/// Rolls back an interrupted online-issuer rotation journal before startup.
///
/// # Errors
///
/// Returns an error when the journal is unsafe, unreadable, or the rotation
/// artifacts cannot be restored.
pub fn recover_interrupted_online_issuer_rotation(config_path: &Path) -> Result<()> {
    let journal_path = issuer_rotation_journal_path(config_path)?;
    if !journal_path.exists() {
        return Ok(());
    }
    let _lock = ConfigFileLock::acquire(config_path)?;
    recover_interrupted_online_issuer_rotation_locked(config_path)
}

pub(crate) fn recover_interrupted_online_issuer_rotation_locked(config_path: &Path) -> Result<()> {
    let journal_path = issuer_rotation_journal_path(config_path)?;
    if !journal_path.exists() {
        return Ok(());
    }
    let journal: IssuerRotationJournal = serde_json::from_slice(
        &read_root_private_text(
            &journal_path,
            256 * 1024,
            "online issuer rotation recovery journal",
        )?
        .into_bytes(),
    )
    .context("parse online issuer rotation recovery journal")?;
    if journal.version != 1 || journal.config_path != config_path || journal.targets.len() != 8 {
        bail!("online issuer rotation journal does not belong to this server configuration");
    }
    for target in &journal.targets {
        let paths = rotation_artifact_paths(&target.path, journal.nonce)?;
        validate_regular_file(&paths.backup)?;
        let original = if target.private {
            read_root_private_text(&paths.backup, 256 * 1024, "issuer rotation private backup")?
                .into_bytes()
        } else {
            read_root_public_text(&paths.backup, 256 * 1024, "issuer rotation backup")?.into_bytes()
        };
        if paths.stage.exists() {
            validate_regular_file(&paths.stage)?;
            fs::remove_file(&paths.stage)?;
        }
        write_new_file(&paths.stage, &original, target.private)?;
        atomic_replace_from_stage(&paths.stage, &target.path)?;
        sync_parent(&target.path)?;
    }
    fs::remove_file(&journal_path)?;
    let retirement_path = tls_retirement_journal_path(config_path)?;
    if retirement_path.exists() {
        validate_regular_file(&retirement_path)?;
        fs::remove_file(&retirement_path)?;
    }
    sync_parent(&journal_path)?;
    Ok(())
}

#[allow(clippy::too_many_lines)]
fn rotate_server_identity_and_save(
    config_path: &Path,
    config: &mut ServerConfig,
    replacement: ServerConfig,
) -> Result<()> {
    replacement.validate()?;
    let _lock = ConfigFileLock::acquire(config_path)?;
    recover_interrupted_database_update_locked(config_path)?;
    recover_interrupted_settings_update_locked(config_path)?;
    recover_interrupted_online_issuer_rotation_locked(config_path)?;
    recover_interrupted_tls_rotation_locked(config_path)?;
    let retirement_path = tls_retirement_journal_path(config_path)?;
    if retirement_path.exists() {
        bail!(
            "a previous TLS rotation is awaiting a successful server restart; restart centrald-server before rotating again"
        );
    }
    let current = ServerConfig::load(config_path)?;
    if current != *config {
        bail!(
            "server configuration changed in another process; reopen centrald-server config and retry"
        );
    }

    let issuer_certificate = read_root_public_text(
        &replacement.pki.server_issuer_cert,
        256 * 1024,
        "server issuer certificate",
    )?;
    let issuer_key = read_root_private_text(
        &replacement.pki.server_issuer_key,
        256 * 1024,
        "server issuer private key",
    )?;
    let root = read_root_public_text(
        &replacement.pki.root_cert,
        256 * 1024,
        "root CA certificate",
    )?;
    let identity = issue_server_identity(
        &replacement.server.public_host,
        &issuer_certificate,
        &issuer_key,
        &root,
    )?;
    let serialized = toml::to_string_pretty(&replacement)?;

    let nonce = Uuid::now_v7();
    let journal = TlsRotationJournal {
        version: 1,
        nonce,
        config_path: config_path.to_path_buf(),
        server_chain: replacement.pki.server_chain.clone(),
        server_key: replacement.pki.server_key.clone(),
    };
    let config_paths = rotation_artifact_paths(config_path, nonce)?;
    let chain_paths = rotation_artifact_paths(&replacement.pki.server_chain, nonce)?;
    let key_paths = rotation_artifact_paths(&replacement.pki.server_key, nonce)?;
    let journal_path = tls_rotation_journal_path(config_path)?;
    let retirement = TlsRetirementJournal {
        version: 1,
        config_path: config_path.to_path_buf(),
        backups: vec![
            chain_paths.backup.clone(),
            key_paths.backup.clone(),
            config_paths.backup.clone(),
        ],
    };
    let retirement_path = tls_retirement_journal_path(config_path)?;
    let previous_revision = hex::encode(Sha256::digest(fs::read(config_path)?));
    let new_revision = hex::encode(Sha256::digest(serialized.as_bytes()));
    local_audit::record(
        config_path,
        "server_tls.rotate",
        "pending",
        serde_json::json!({
            "previous_revision": &previous_revision,
            "intended_revision": &new_revision,
            "previous_host": &current.server.public_host,
            "new_host": &replacement.server.public_host,
        }),
    )?;

    let staging = (|| {
        stage_rotation_artifact(config_path, &config_paths, serialized.as_bytes(), true)?;
        stage_rotation_artifact(
            &replacement.pki.server_chain,
            &chain_paths,
            identity.certificate_chain_pem.as_bytes(),
            false,
        )?;
        stage_rotation_artifact(
            &replacement.pki.server_key,
            &key_paths,
            identity.private_key_pem.as_bytes(),
            true,
        )?;
        write_new_file(&journal_path, &serde_json::to_vec_pretty(&journal)?, true)?;
        write_new_file(
            &retirement_path,
            &serde_json::to_vec_pretty(&retirement)?,
            true,
        )?;
        sync_parent(&journal_path)?;
        Ok::<(), anyhow::Error>(())
    })();
    if let Err(error) = staging {
        let _ = local_audit::record(
            config_path,
            "server_tls.rotate",
            "failed",
            serde_json::json!({"intended_revision": &new_revision, "phase": "stage"}),
        );
        if journal_path.exists() {
            let _ = recover_interrupted_tls_rotation_locked(config_path);
        } else {
            cleanup_uncommitted_rotation_artifacts(&[config_paths, chain_paths, key_paths]);
            let _ = fs::remove_file(&retirement_path);
        }
        return Err(error.context("stage server TLS rotation"));
    }

    let commit = (|| {
        atomic_replace_from_stage(&chain_paths.stage, &replacement.pki.server_chain)?;
        atomic_replace_from_stage(&key_paths.stage, &replacement.pki.server_key)?;
        atomic_replace_from_stage(&config_paths.stage, config_path)?;
        for path in [
            &replacement.pki.server_chain,
            &replacement.pki.server_key,
            config_path,
        ] {
            sync_parent(path)?;
        }
        fs::remove_file(&journal_path).with_context(|| {
            format!(
                "remove completed TLS rotation journal {}",
                journal_path.display()
            )
        })?;
        if let Err(error) = sync_parent(&journal_path) {
            warn!(%error, "server TLS rotation committed but journal-directory sync could not be confirmed");
        }
        Ok::<(), anyhow::Error>(())
    })();
    if let Err(error) = commit {
        let _ = local_audit::record(
            config_path,
            "server_tls.rotate",
            "failed",
            serde_json::json!({"intended_revision": &new_revision, "phase": "commit"}),
        );
        return match recover_interrupted_tls_rotation_locked(config_path) {
            Ok(()) => Err(error.context("TLS identity rotation failed and was rolled back")),
            Err(rollback) => Err(error.context(format!(
                "TLS identity rotation failed and rollback also failed: {rollback:#}"
            ))),
        };
    }

    if let Err(error) = local_audit::record(
        config_path,
        "server_tls.rotate",
        "succeeded",
        serde_json::json!({
            "previous_revision": &previous_revision,
            "new_revision": &new_revision,
            "new_host": &replacement.server.public_host,
        }),
    ) {
        warn!(%error, "server TLS rotation committed; final local audit append is pending reconciliation");
    }

    *config = replacement;
    println!(
        "{} Server TLS identity and configuration committed together.",
        style("✓").green()
    );
    println!(
        "Rollback material will be removed automatically after the restarted server remains healthy."
    );
    println!("Restart centrald-server to apply runtime changes.");
    Ok(())
}

#[derive(Debug)]
struct RotationArtifactPaths {
    backup: PathBuf,
    stage: PathBuf,
}

fn rotation_artifact_paths(path: &Path, nonce: Uuid) -> Result<RotationArtifactPaths> {
    let parent = path
        .parent()
        .filter(|parent| !parent.as_os_str().is_empty())
        .context("rotation target has no parent")?;
    let name = path
        .file_name()
        .context("rotation target has no file name")?
        .to_string_lossy();
    Ok(RotationArtifactPaths {
        backup: parent.join(format!(".{name}.centrald-rotation-backup-{nonce}")),
        stage: parent.join(format!(".{name}.centrald-rotation-stage-{nonce}")),
    })
}

fn stage_rotation_artifact(
    final_path: &Path,
    paths: &RotationArtifactPaths,
    replacement: &[u8],
    private: bool,
) -> Result<()> {
    validate_regular_file(final_path)?;
    let original = fs::read(final_path)
        .with_context(|| format!("read rotation target {}", final_path.display()))?;
    write_new_file(&paths.backup, &original, true)?;
    write_new_file(&paths.stage, replacement, private)?;
    Ok(())
}

fn cleanup_uncommitted_rotation_artifacts(paths: &[RotationArtifactPaths]) {
    for path in paths {
        for artifact in [&path.stage, &path.backup] {
            match fs::remove_file(artifact) {
                Ok(()) => {}
                Err(error) if error.kind() == std::io::ErrorKind::NotFound => {}
                Err(error) => {
                    warn!(path = %artifact.display(), %error, "could not remove uncommitted rotation artifact");
                }
            }
        }
    }
}

fn validate_regular_file(path: &Path) -> Result<()> {
    let metadata = path
        .symlink_metadata()
        .with_context(|| format!("inspect {}", path.display()))?;
    if metadata.file_type().is_symlink() || !metadata.is_file() {
        bail!(
            "refusing non-regular or symbolic-link rotation target {}",
            path.display()
        );
    }
    Ok(())
}

#[cfg(unix)]
fn atomic_replace_from_stage(stage: &Path, destination: &Path) -> Result<()> {
    validate_regular_file(stage)?;
    validate_regular_file(destination)?;
    // Revalidate the destination's ancestors at the point of use so a
    // directory swapped for a symlink since staging cannot redirect the
    // rename outside the intended PKI tree.
    centrald_common::secure_fs::validate_no_symlink_ancestors(destination).map_err(|error| {
        anyhow::anyhow!(
            "validate rotation destination ancestors {}: {error}",
            destination.display()
        )
    })?;
    fs::rename(stage, destination).with_context(|| {
        format!(
            "atomically replace {} from {}",
            destination.display(),
            stage.display()
        )
    })
}

#[cfg(not(unix))]
fn atomic_replace_from_stage(_stage: &Path, _destination: &Path) -> Result<()> {
    bail!("server TLS rotation is supported only on Ubuntu Server")
}

fn sync_parent(path: &Path) -> Result<()> {
    let parent = path
        .parent()
        .filter(|parent| !parent.as_os_str().is_empty())
        .context("path has no parent to synchronize")?;
    fs::File::open(parent)
        .and_then(|directory| directory.sync_all())
        .with_context(|| format!("synchronize directory {}", parent.display()))
}

fn tls_rotation_journal_path(config_path: &Path) -> Result<PathBuf> {
    let parent = config_path
        .parent()
        .filter(|parent| !parent.as_os_str().is_empty())
        .context("server configuration path has no parent")?;
    Ok(parent.join(TLS_ROTATION_JOURNAL_NAME))
}

/// Restores all pre-rotation files if the process stopped after publishing a
/// TLS-rotation journal but before completing the multi-file commit.
///
/// # Errors
///
/// Returns an error when the journal is unsafe, unreadable, or the
/// pre-rotation files cannot be restored.
pub fn recover_interrupted_tls_rotation(config_path: &Path) -> Result<()> {
    let journal_path = tls_rotation_journal_path(config_path)?;
    if !journal_path.exists() {
        return Ok(());
    }
    let _lock = ConfigFileLock::acquire(config_path)?;
    recover_interrupted_tls_rotation_locked(config_path)
}

pub(crate) fn recover_interrupted_tls_rotation_locked(config_path: &Path) -> Result<()> {
    let journal_path = tls_rotation_journal_path(config_path)?;
    if !journal_path.exists() {
        return Ok(());
    }
    validate_regular_file(&journal_path)?;
    let journal: TlsRotationJournal = serde_json::from_slice(
        &read_root_private_text(&journal_path, 256 * 1024, "TLS rotation recovery journal")?
            .into_bytes(),
    )
    .context("parse TLS rotation recovery journal")?;
    if journal.version != 1 || journal.config_path != config_path {
        bail!("TLS rotation journal does not belong to this server configuration");
    }
    let config_paths = rotation_artifact_paths(config_path, journal.nonce)?;
    let chain_paths = rotation_artifact_paths(&journal.server_chain, journal.nonce)?;
    let key_paths = rotation_artifact_paths(&journal.server_key, journal.nonce)?;

    for (final_path, paths, private) in [
        (journal.server_chain.as_path(), &chain_paths, false),
        (journal.server_key.as_path(), &key_paths, true),
        (config_path, &config_paths, true),
    ] {
        validate_regular_file(&paths.backup)?;
        let original = if private {
            read_root_private_text(&paths.backup, 256 * 1024, "TLS rotation private backup")?
                .into_bytes()
        } else {
            read_root_public_text(&paths.backup, 256 * 1024, "TLS rotation backup")?.into_bytes()
        };
        if paths.stage.exists() {
            validate_regular_file(&paths.stage)?;
            fs::remove_file(&paths.stage)
                .with_context(|| format!("remove abandoned TLS stage {}", paths.stage.display()))?;
        }
        write_new_file(&paths.stage, &original, private)?;
        atomic_replace_from_stage(&paths.stage, final_path)?;
        sync_parent(final_path)?;
    }
    fs::remove_file(&journal_path).with_context(|| {
        format!(
            "remove recovered TLS rotation journal {}",
            journal_path.display()
        )
    })?;
    let retirement_path = tls_retirement_journal_path(config_path)?;
    if retirement_path.exists() {
        validate_regular_file(&retirement_path)?;
        fs::remove_file(&retirement_path).with_context(|| {
            format!(
                "remove rolled-back TLS retirement journal {}",
                retirement_path.display()
            )
        })?;
    }
    sync_parent(&journal_path)?;
    Ok(())
}

fn tls_retirement_journal_path(config_path: &Path) -> Result<PathBuf> {
    let parent = config_path
        .parent()
        .filter(|parent| !parent.as_os_str().is_empty())
        .context("server configuration path has no parent")?;
    Ok(parent.join(TLS_RETIREMENT_JOURNAL_NAME))
}

/// Returns whether a completed PKI/TLS rotation is waiting for post-restart
/// listener health verification before rollback material can be retired.
///
/// # Errors
///
/// Returns an error when the retirement journal path is unsafe.
pub fn tls_retirement_pending(config_path: &Path) -> Result<bool> {
    let path = tls_retirement_journal_path(config_path)?;
    if !path.exists() {
        return Ok(false);
    }
    validate_regular_file(&path)?;
    Ok(true)
}

/// Removes private rollback material only after the restarted daemon has
/// completed explicit TLS handshakes on enrollment, client-mTLS, and Admin-mTLS
/// listeners.
///
/// # Errors
///
/// Returns an error when the retirement journal is unsafe, unreadable, or
/// rollback material cannot be removed.
pub fn retire_completed_tls_rotation(config_path: &Path) -> Result<bool> {
    let retirement_path = tls_retirement_journal_path(config_path)?;
    if !retirement_path.exists() {
        return Ok(false);
    }
    let _lock = ConfigFileLock::acquire(config_path)?;
    validate_regular_file(&retirement_path)?;
    let journal: TlsRetirementJournal = serde_json::from_slice(
        &read_root_private_text(&retirement_path, 256 * 1024, "TLS retirement journal")?
            .into_bytes(),
    )?;
    if journal.version != 1 || journal.config_path != config_path {
        bail!("TLS retirement journal does not belong to this server configuration");
    }
    for backup in &journal.backups {
        if !backup.exists() {
            continue;
        }
        validate_regular_file(backup)?;
        fs::remove_file(backup).with_context(|| {
            format!("remove retired TLS rollback material {}", backup.display())
        })?;
        sync_parent(backup)?;
    }
    fs::remove_file(&retirement_path).with_context(|| {
        format!(
            "remove TLS retirement journal {}",
            retirement_path.display()
        )
    })?;
    sync_parent(&retirement_path)?;
    Ok(true)
}

/// Renews the server TLS leaf when it is expired or within the renewal
/// window. Startup and the long-lived daemon both call this function. The
/// persisted online server issuer is used; the offline root key remains offline.
///
/// # Errors
///
/// Returns an error when the configuration or trust material cannot be read
/// or the renewal rotation fails.
pub fn renew_server_identity_if_needed(config_path: &Path) -> Result<bool> {
    let mut config = ServerConfig::load(config_path)?;
    let chain = read_root_public_text(
        &config.pki.server_chain,
        256 * 1024,
        "server TLS certificate chain",
    )?;
    let expires_at = certificate_not_after(&chain)?;
    if expires_at > time::OffsetDateTime::now_utc() + time::Duration::days(SERVER_RENEW_BEFORE_DAYS)
    {
        return Ok(false);
    }
    let replacement = config.clone();
    rotate_server_identity_and_save(config_path, &mut config, replacement)?;
    Ok(true)
}

/// Rejects expired trust material and warns when issuer/root rotation planning
/// is due. Leaf renewal is handled separately at startup and while running.
///
/// # Errors
///
/// Returns an error when trust material cannot be read or is already expired.
pub fn check_pki_expiry(config: &ServerConfig) -> Result<()> {
    let now = time::OffsetDateTime::now_utc();
    for (label, path, warn_days) in [
        ("offline root", &config.pki.root_cert, 365_i64),
        ("server issuer", &config.pki.server_issuer_cert, 180_i64),
        ("client issuer", &config.pki.client_issuer_cert, 180_i64),
        ("Admin issuer", &config.pki.admin_issuer_cert, 180_i64),
    ] {
        let pem = read_root_public_text(path, 256 * 1024, &format!("{label} certificate"))?;
        let expires_at = certificate_not_after(&pem)?;
        if expires_at <= now {
            bail!(
                "{label} certificate expired at {expires_at}; rotate PKI before starting CentralD"
            );
        }
        if expires_at <= now + time::Duration::days(warn_days) {
            warn!(%expires_at, %label, "CentralD PKI certificate is approaching expiration; schedule server-local rotation");
        }
    }
    Ok(())
}

fn confirm_and_save(
    config_path: &Path,
    config: &mut ServerConfig,
    replacement: ServerConfig,
    theme: &ColorfulTheme,
) -> Result<()> {
    if !Confirm::with_theme(theme)
        .with_prompt("Save these settings? Server restart required.")
        .default(true)
        .interact()?
    {
        return Ok(());
    }
    save_config(config_path, config, replacement)
}

fn save_config(
    config_path: &Path,
    config: &mut ServerConfig,
    replacement: ServerConfig,
) -> Result<()> {
    replacement.validate()?;
    let _lock = ConfigFileLock::acquire(config_path)?;
    recover_interrupted_database_update_locked(config_path)?;
    recover_interrupted_settings_update_locked(config_path)?;
    recover_interrupted_online_issuer_rotation_locked(config_path)?;
    recover_interrupted_root_replacement_locked(config_path)?;
    recover_interrupted_tls_rotation_locked(config_path)?;
    let current = ServerConfig::load(config_path)?;
    if current != *config {
        bail!(
            "server configuration changed in another process; reopen centrald-server config and retry"
        );
    }
    let original_raw = fs::read(config_path)?;
    let serialized = toml::to_string_pretty(&replacement)?;
    let previous_revision = hex::encode(Sha256::digest(&original_raw));
    let new_revision = hex::encode(Sha256::digest(serialized.as_bytes()));
    let changed_fields = changed_config_fields(&current, &replacement);
    local_audit::record(
        config_path,
        "server_settings.local_update",
        "pending",
        serde_json::json!({
            "previous_revision": &previous_revision,
            "intended_revision": &new_revision,
            "changed_fields": &changed_fields,
        }),
    )?;
    prune_file_backups(config_path, CONFIG_BACKUP_RETENTION.saturating_sub(1))
        .context("prune old server configuration backups before saving")?;
    let backup = match replace_file_with_backup(config_path, serialized.as_bytes(), true) {
        Ok(backup) => backup,
        Err(error) => {
            let _ = local_audit::record(
                config_path,
                "server_settings.local_update",
                "failed",
                serde_json::json!({"intended_revision": &new_revision, "changed_fields": &changed_fields}),
            );
            return Err(error.into());
        }
    };
    *config = replacement;
    if let Err(error) = local_audit::record(
        config_path,
        "server_settings.local_update",
        "succeeded",
        serde_json::json!({
            "previous_revision": &previous_revision,
            "new_revision": &new_revision,
            "changed_fields": &changed_fields,
        }),
    ) {
        warn!(%error, "server configuration was committed; final local audit append is pending reconciliation");
    }
    if let Err(error) = prune_file_backups(config_path, CONFIG_BACKUP_RETENTION) {
        warn!(%error, "server configuration was committed, but old backup pruning failed");
    }
    println!(
        "{} Configuration saved. Backup: {}",
        style("✓").green(),
        backup.display()
    );
    println!("Restart centrald-server to apply runtime changes.");
    Ok(())
}

#[allow(clippy::too_many_lines)]
fn changed_config_fields(before: &ServerConfig, after: &ServerConfig) -> Vec<&'static str> {
    let mut fields = Vec::new();
    macro_rules! changed {
        ($name:literal, $left:expr, $right:expr) => {
            if &$left != &$right {
                fields.push($name);
            }
        };
    }
    changed!(
        "server.public_host",
        before.server.public_host,
        after.server.public_host
    );
    changed!(
        "server.enrollment_listen",
        before.server.enrollment_listen,
        after.server.enrollment_listen
    );
    changed!(
        "server.client_listen",
        before.server.client_listen,
        after.server.client_listen
    );
    changed!(
        "server.admin_listen",
        before.server.admin_listen,
        after.server.admin_listen
    );
    changed!(
        "server.data_dir",
        before.server.data_dir,
        after.server.data_dir
    );
    changed!(
        "database.environment_file",
        before.database.environment_file,
        after.database.environment_file
    );
    changed!(
        "database.max_connections",
        before.database.max_connections,
        after.database.max_connections
    );
    changed!("pki.root_cert", before.pki.root_cert, after.pki.root_cert);
    changed!(
        "pki.server_chain",
        before.pki.server_chain,
        after.pki.server_chain
    );
    changed!(
        "pki.server_key",
        before.pki.server_key,
        after.pki.server_key
    );
    changed!(
        "pki.server_issuer_cert",
        before.pki.server_issuer_cert,
        after.pki.server_issuer_cert
    );
    changed!(
        "pki.server_issuer_key",
        before.pki.server_issuer_key,
        after.pki.server_issuer_key
    );
    changed!(
        "pki.client_issuer_cert",
        before.pki.client_issuer_cert,
        after.pki.client_issuer_cert
    );
    changed!(
        "pki.client_issuer_key",
        before.pki.client_issuer_key,
        after.pki.client_issuer_key
    );
    changed!(
        "pki.admin_issuer_cert",
        before.pki.admin_issuer_cert,
        after.pki.admin_issuer_cert
    );
    changed!(
        "pki.admin_issuer_key",
        before.pki.admin_issuer_key,
        after.pki.admin_issuer_key
    );
    changed!(
        "runtime.heartbeat_interval_seconds",
        before.runtime.heartbeat_interval_seconds,
        after.runtime.heartbeat_interval_seconds
    );
    changed!(
        "runtime.offline_after_seconds",
        before.runtime.offline_after_seconds,
        after.runtime.offline_after_seconds
    );
    changed!(
        "runtime.job_ttl_seconds",
        before.runtime.job_ttl_seconds,
        after.runtime.job_ttl_seconds
    );
    changed!(
        "runtime.shell_idle_timeout_seconds",
        before.runtime.shell_idle_timeout_seconds,
        after.runtime.shell_idle_timeout_seconds
    );
    changed!(
        "runtime.max_shell_frame_bytes",
        before.runtime.max_shell_frame_bytes,
        after.runtime.max_shell_frame_bytes
    );
    changed!(
        "updates.enabled",
        before.updates.enabled,
        after.updates.enabled
    );
    changed!(
        "updates.channel",
        before.updates.channel,
        after.updates.channel
    );
    changed!(
        "updates.manifest_url",
        before.updates.manifest_url,
        after.updates.manifest_url
    );
    changed!(
        "updates.check_interval_seconds",
        before.updates.check_interval_seconds,
        after.updates.check_interval_seconds
    );
    changed!(
        "updates.allow_prerelease",
        before.updates.allow_prerelease,
        after.updates.allow_prerelease
    );
    fields
}

fn export_trust(config: &ServerConfig, theme: &ColorfulTheme) -> Result<()> {
    let current_directory = std::env::current_dir().context("resolve current directory")?;
    let default_destination = current_directory.join("centrald-root-ca.pem");
    let destination = Input::<String>::with_theme(theme)
        .with_prompt("New destination for root trust certificate")
        .default(default_destination.display().to_string())
        .validate_with(|value: &String| validate_nonempty(value, "path"))
        .interact_text()?;
    let destination = PathBuf::from(destination);
    let destination = if destination.is_absolute() {
        destination
    } else {
        current_directory.join(destination)
    };
    let certificate =
        read_root_public_text(&config.pki.root_cert, 256 * 1024, "root CA certificate")?;
    write_new_file(&destination, certificate.as_bytes(), false)?;
    println!(
        "{} Trust certificate exported to {}",
        style("✓").green(),
        destination.display()
    );
    Ok(())
}

/// Guides a verified, append-only export of the audit hash chain into a
/// root-owned directory as `centrald-audit-<from>-<to>.jsonl` files.
async fn export_audit_guided(config_path: &Path) -> Result<()> {
    println!();
    println!("{}", style("Export the verified audit chain").cyan().bold());
    println!(
        "Each batch is verified against the PostgreSQL hash chain and the previous export file before it is written. Files are never rewritten."
    );
    let config = ServerConfig::load(config_path)?;
    let current_directory = std::env::current_dir().context("resolve current directory")?;
    let default_directory = current_directory.join("centrald-audit-export");
    let directory = Input::<String>::with_theme(&ColorfulTheme::default())
        .with_prompt("Audit export directory")
        .default(default_directory.display().to_string())
        .validate_with(|value: &String| validate_nonempty(value, "directory"))
        .interact_text()?;
    let directory = PathBuf::from(directory);
    let directory = if directory.is_absolute() {
        directory
    } else {
        current_directory.join(directory)
    };
    let limit = Input::<usize>::with_theme(&ColorfulTheme::default())
        .with_prompt("Maximum entries in this batch")
        .default(5_000)
        .validate_with(|value: &usize| {
            if *value < 1 || *value > 50_000 {
                bail!("batch size must be between 1 and 50000")
            }
            Ok(())
        })
        .interact_text()?;
    let pool = open_pool(&config).await.context("connect to PostgreSQL")?;
    let summary = crate::audit_export::export_audit_chain(&pool, &directory, limit).await?;
    if summary.exported_count == 0 {
        println!(
            "Audit chain is fully exported through sequence {}.",
            summary.exported_to
        );
    } else {
        println!(
            "{} Exported {} audit records (sequences {} through {}) to {}",
            style("✓").green(),
            summary.exported_count,
            summary.exported_from + 1,
            summary.exported_to,
            directory.display()
        );
        println!(
            "Next batch continues from sequence {}.",
            summary.exported_to
        );
    }
    println!("Chain tail entry hash: {}", summary.tail_hash);
    Ok(())
}

async fn diagnostics(config_path: &Path, config: &ServerConfig) -> Result<()> {
    println!();
    println!("{}", style("Health, status, and next steps").cyan().bold());
    println!(
        "{} Configuration valid: {}",
        style("✓").green(),
        config_path.display()
    );

    let pool = open_pool(config).await;
    match pool {
        Ok(pool) => {
            let summary = diagnostic_summary(&pool).await?;
            pool.close().await;
            println!(
                "{} PostgreSQL connected and migrations current",
                style("✓").green()
            );
            println!("  Active clients: {}", summary.active_clients);
            println!("  Active Admins: {}", summary.active_admins);
            println!("  Pending invitations: {}", summary.pending_enrollments);
        }
        Err(error) => println!("{} PostgreSQL unavailable: {error:#}", style("!").yellow()),
    }

    let client = LocalControlClient::new(config.server.local_socket.clone());
    match client.diagnostics().await {
        Ok(_) => println!(
            "{} centrald-server daemon accepted an authenticated local health request",
            style("✓").green()
        ),
        Err(error) => println!(
            "{} centrald-server daemon is not reachable: {error}",
            style("!").yellow()
        ),
    }

    if Path::new("/run/systemd/system").is_dir() && Path::new("/usr/bin/systemctl").is_file() {
        let active = std::process::Command::new("/usr/bin/systemctl")
            .args(["is-active", "--quiet", "centrald-server.service"])
            .status()
            .is_ok_and(|status| status.success());
        let enabled = std::process::Command::new("/usr/bin/systemctl")
            .args(["is-enabled", "--quiet", "centrald-server.service"])
            .status()
            .is_ok_and(|status| status.success());
        println!(
            "systemd: {} / {}",
            if active { "active" } else { "not active" },
            if enabled {
                "enabled at boot"
            } else {
                "not enabled"
            }
        );
        if !active || !enabled {
            println!("Next step: sudo systemctl enable --now centrald-server.service");
        }
    }

    let raw = std::fs::read(config_path)?;
    let persisted_revision = hex::encode(Sha256::digest(&raw));
    println!(
        "Persisted configuration revision: {}",
        &persisted_revision[..12]
    );
    println!("TLS name: {}", config.server.public_host);
    println!(
        "{} Root trust certificate: {}",
        style("✓").green(),
        config.pki.root_cert.display()
    );
    Ok(())
}

/// Returns bounded, non-secret server health counts.
///
/// # Errors
///
/// Returns an error when `PostgreSQL` health queries fail.
pub async fn diagnostic_summary(pool: &PgPool) -> Result<DiagnosticsSummary> {
    let clients: i64 = sqlx::query_scalar(
        "SELECT COUNT(*) FROM identities WHERE role = 'client' AND revoked_at IS NULL",
    )
    .fetch_one(pool)
    .await?;
    let admins: i64 = sqlx::query_scalar(
        "SELECT COUNT(*) FROM identities WHERE role = 'admin' AND revoked_at IS NULL",
    )
    .fetch_one(pool)
    .await?;
    let pending: i64 = sqlx::query_scalar(
        "SELECT COUNT(*) FROM enrollment_keys WHERE consumed_at IS NULL \
         AND revoked_at IS NULL AND expires_at > NOW()",
    )
    .fetch_one(pool)
    .await?;
    Ok(DiagnosticsSummary {
        active_clients: clients,
        active_admins: admins,
        pending_enrollments: pending,
    })
}

async fn open_pool(config: &ServerConfig) -> Result<PgPool> {
    let url = resolve_database_url(config)?;
    connect_and_migrate(
        url.expose_secret(),
        config.database.max_connections,
        config.server.instance_id,
    )
    .await
    .context("connect to CentralD PostgreSQL database")
}

async fn append_local_audit(
    transaction: &mut Transaction<'_, Postgres>,
    action: &str,
    target_id: Option<Uuid>,
    metadata: serde_json::Value,
) -> Result<()> {
    sqlx::query("SELECT pg_advisory_xact_lock($1)")
        .bind(AUDIT_LOCK_ID)
        .execute(&mut **transaction)
        .await?;
    let previous_hash: Option<Vec<u8>> =
        sqlx::query_scalar("SELECT entry_hash FROM audit_entries ORDER BY sequence DESC LIMIT 1")
            .fetch_optional(&mut **transaction)
            .await?;
    let id = Uuid::now_v7();
    // Normalize to microsecond precision exactly like the RPC audit path so
    // exported canonical-record verification reproduces the stored hash.
    let created_at = crate::services::normalized_audit_timestamp(Utc::now());
    let canonical = serde_json::to_vec(&serde_json::json!({
        "id": id,
        "actorId": null,
        "actorLabel": "server-local-root",
        "action": action,
        "targetId": target_id,
        "outcome": "succeeded",
        "metadata": &metadata,
        "previousHash": previous_hash.as_ref().map(hex::encode),
        "createdAt": created_at,
    }))?;
    let entry_hash = Sha256::digest(&canonical).to_vec();
    sqlx::query(
        "INSERT INTO audit_entries \
         (id, actor_id, actor_label, action, target_id, outcome, metadata, previous_hash, \
          entry_hash, created_at) VALUES ($1, NULL, $2, $3, $4, 'succeeded', $5, $6, $7, $8)",
    )
    .bind(id)
    .bind("server-local-root")
    .bind(action)
    .bind(target_id)
    .bind(metadata)
    .bind(previous_hash)
    .bind(entry_hash)
    .bind(created_at)
    .execute(&mut **transaction)
    .await?;
    Ok(())
}

fn require_interactive_root() -> Result<()> {
    if !stdin().is_terminal() || !stdout().is_terminal() {
        bail!("config requires an interactive terminal; use direct commands for automation");
    }
    require_root()
}

#[cfg(unix)]
/// Verifies the process is running as root.
///
/// # Errors
///
/// Returns an error when the effective user ID cannot be determined or is
/// not root.
pub fn require_root() -> Result<()> {
    let status = std::fs::read_to_string("/proc/self/status")
        .context("read effective user ID from /proc/self/status")?;
    let effective_uid = status
        .lines()
        .find_map(|line| line.strip_prefix("Uid:"))
        .and_then(|ids| ids.split_whitespace().nth(1))
        .and_then(|id| id.parse::<u32>().ok())
        .context("parse effective user ID from /proc/self/status")?;
    if effective_uid != 0 {
        bail!("centrald-server local administration must run as root");
    }
    Ok(())
}

#[cfg(not(unix))]
/// Verifies the process is running as root.
///
/// # Errors
///
/// Returns an error on this platform because local administration is
/// supported only on Ubuntu Server hosts.
pub fn require_root() -> Result<()> {
    bail!("centrald-server local administration is supported on Ubuntu Server hosts")
}

fn parse_role(role: &str) -> Result<EnrollmentRole> {
    match role {
        "client" => Ok(EnrollmentRole::Client),
        "admin" => Ok(EnrollmentRole::Admin),
        _ => bail!("invalid identity role"),
    }
}

fn validate_name(value: &str, maximum: usize, label: &str) -> Result<()> {
    let trimmed = value.trim();
    if trimmed.is_empty() || trimmed.len() > maximum || trimmed.chars().any(char::is_control) {
        bail!("{label} must be 1-{maximum} printable characters");
    }
    Ok(())
}

fn validate_prompt_name(value: &str) -> Result<(), &'static str> {
    if value.trim().is_empty() || value.len() > 128 || value.chars().any(char::is_control) {
        Err("enter 1-128 printable characters")
    } else {
        Ok(())
    }
}

fn validate_prompt_reason(value: &str) -> Result<(), &'static str> {
    if value.trim().is_empty() || value.len() > 512 || value.chars().any(char::is_control) {
        Err("enter 1-512 printable characters")
    } else {
        Ok(())
    }
}

fn validate_prompt_host(value: &str) -> Result<(), &'static str> {
    canonical_host(value).map(|_| ()).map_err(
        |_| "enter a canonical ASCII DNS name or IP without scheme, port, path, or whitespace",
    )
}

fn validate_nonempty(value: &str, label: &str) -> Result<(), String> {
    if value.trim().is_empty() || value.chars().any(char::is_control) {
        Err(format!(
            "{label} must not be empty or contain control characters"
        ))
    } else {
        Ok(())
    }
}

fn validate_short_text(value: &str, maximum: usize) -> Result<(), &'static str> {
    if value.trim().is_empty() || value.len() > maximum || value.chars().any(char::is_control) {
        Err("enter a short printable value")
    } else {
        Ok(())
    }
}

fn validate_manifest_url(value: &str) -> Result<(), &'static str> {
    if value.starts_with("https://") && !value.contains(char::is_whitespace) {
        Ok(())
    } else {
        Err("enter an HTTPS URL without whitespace")
    }
}

#[allow(dead_code)]
fn validate_env_name(value: &str) -> Result<(), &'static str> {
    let mut characters = value.chars();
    let first = characters
        .next()
        .ok_or("enter an environment variable name")?;
    if !(first.is_ascii_alphabetic() || first == '_')
        || !characters.all(|character| character.is_ascii_alphanumeric() || character == '_')
    {
        Err("use letters, digits, and underscores; do not start with a digit")
    } else {
        Ok(())
    }
}

fn validate_database_url(value: &str) -> Result<(), String> {
    validate_database_url_policy(value).map_err(|error| format!(
        "{error}; use postgresql://user:password@host:5432/database and require sslmode=verify-full for non-loopback hosts"
    ))
}

fn socket_prompt(theme: &ColorfulTheme, prompt: &str, default: SocketAddr) -> Result<SocketAddr> {
    let value = Input::<String>::with_theme(theme)
        .with_prompt(prompt)
        .default(default.to_string())
        .validate_with(|value: &String| {
            let socket = value
                .parse::<SocketAddr>()
                .map_err(|_| "enter an IP:port socket address")?;
            if socket.port() < 1024 {
                return Err("use an unprivileged listener port from 1024 to 65535");
            }
            Ok(())
        })
        .interact_text()?;
    value.parse().context("parse listener socket")
}

fn u32_prompt(
    theme: &ColorfulTheme,
    prompt: &str,
    default: u32,
    minimum: u32,
    maximum: u32,
) -> Result<u32> {
    Ok(Input::<u32>::with_theme(theme)
        .with_prompt(prompt)
        .default(default)
        .validate_with(move |value: &u32| {
            if (minimum..=maximum).contains(value) {
                Ok(())
            } else {
                Err(format!("enter a value from {minimum} through {maximum}"))
            }
        })
        .interact_text()?)
}

fn display_role(role: &str) -> &'static str {
    if role == "admin" { "Admin" } else { "client" }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn rejects_invalid_guided_input() {
        assert!(validate_prompt_name("").is_err());
        assert!(validate_prompt_name("valid host").is_ok());
        assert!(validate_prompt_reason("\n").is_err());
        assert!(validate_database_url("https://example.test").is_err());
        assert!(
            validate_database_url("postgresql://centrald:secret@127.0.0.1:5432/centrald").is_ok()
        );
        assert!(validate_env_name("CENTRALD_DATABASE_URL").is_ok());
    }

    #[test]
    fn rejects_unsupported_enrollment_role_and_name() {
        assert!(parse_role("operator").is_err());
        assert!(parse_role("client").is_ok());
        assert!(validate_name("", 128, "name").is_err());
    }
}
