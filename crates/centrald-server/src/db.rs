use centrald_common::config::ServerConfig;
use secrecy::SecretString;
use sqlx::postgres::PgPoolOptions;
use sqlx::{Connection, PgConnection, PgPool, migrate::MigrateError};
use thiserror::Error;
use tracing::warn;
use url::Url;
use uuid::Uuid;

use crate::file_security::read_root_private_text;

const DATABASE_COMMENT_PREFIX: &str = "centrald-instance:";
const DATABASE_ENV_MARKER_PREFIX: &str = "# centrald-instance:";

#[derive(Debug, Error)]
pub enum DatabaseError {
    #[error("database connection failed: {0}")]
    Connect(#[from] sqlx::Error),
    #[error("database migration failed: {0}")]
    Migrate(#[from] MigrateError),
    #[error("database is not owned by this CentralD server instance: {0}")]
    Ownership(String),
}

#[derive(Debug, Error)]
pub enum DatabaseAdminError {
    #[error("database URL is invalid or does not identify a dedicated PostgreSQL database")]
    InvalidUrl,
    #[error(
        "ambient PostgreSQL environment variables are not allowed because they can override connection options: {0}"
    )]
    UnsafeEnvironment(String),
    #[error("refusing destructive operation on PostgreSQL maintenance or template database")]
    ProtectedDatabase,
    #[error(
        "the configured PostgreSQL database already exists; initial-setup requires a new dedicated database"
    )]
    AlreadyExists,
    #[error("the configured PostgreSQL database is missing: {0}")]
    MissingDatabase(String),
    #[error("could not connect to the PostgreSQL maintenance database: {0}")]
    Maintenance(#[source] sqlx::Error),
    #[error("could not create the CentralD database: {0}")]
    Create(#[source] sqlx::Error),
    #[error("could not drop the CentralD database: {0}")]
    Drop(#[source] sqlx::Error),
    #[error("database migration failed: {0}")]
    Migrate(#[from] MigrateError),
    #[error("database connection failed: {0}")]
    Connect(#[source] sqlx::Error),
    #[error("database ownership validation failed: {0}")]
    Ownership(String),
}

#[derive(Debug, Error)]
pub enum DatabaseConfigError {
    #[error("database URL is unavailable from the configured instance-bound environment file")]
    Missing,
    #[error("could not read database environment file: {0}")]
    Read(#[from] std::io::Error),
    #[error("database environment file is unsafe: {0}")]
    UnsafeFile(String),
    #[error("database environment file has an invalid format")]
    Invalid,
}

/// Result of provisioning the database during first-time setup.
#[derive(Debug)]
pub struct InitializedDatabase {
    pub pool: PgPool,
}

/// Resolves the database URL from the instance-bound, root-protected environment file.
///
/// Process environment variables are intentionally ignored after setup. This keeps
/// an exported `CENTRALD_DATABASE_URL` from silently redirecting a running daemon
/// or a root TUI session to another database. Non-interactive initial setup reads
/// its bootstrap variable before a server configuration exists.
///
/// # Errors
///
/// Returns an error when the protected environment file is missing, malformed,
/// or bound to another server instance. Error text never includes the URL.
pub fn resolve_database_url(config: &ServerConfig) -> Result<SecretString, DatabaseConfigError> {
    resolve_database_url_from_file(config)
}

/// Resolves the database URL only from the instance-bound, root-protected
/// environment file. Destructive operations use this path so a caller's process
/// environment cannot redirect them to another otherwise valid `CentralD` clone.
///
/// # Errors
///
/// Returns an error when the file is missing, malformed, or bound to another
/// server instance.
pub fn resolve_database_url_from_file(
    config: &ServerConfig,
) -> Result<SecretString, DatabaseConfigError> {
    let raw = read_root_private_text(
        &config.database.environment_file,
        128 * 1024,
        "database environment file",
    )
    .map_err(|error| DatabaseConfigError::UnsafeFile(error.to_string()))?;
    parse_database_environment(config, &raw)
}

fn parse_database_environment(
    config: &ServerConfig,
    raw: &str,
) -> Result<SecretString, DatabaseConfigError> {
    let normalized = raw.replace("\r\n", "\n");
    if normalized.contains('\r') {
        return Err(DatabaseConfigError::Invalid);
    }
    let mut lines = normalized.lines();
    let marker = lines.next().ok_or(DatabaseConfigError::Invalid)?;
    let assignment = lines.next().ok_or(DatabaseConfigError::Invalid)?;
    if lines.next().is_some() || marker != database_environment_marker(config.server.instance_id) {
        return Err(DatabaseConfigError::Invalid);
    }
    let (name, value) = assignment
        .split_once('=')
        .ok_or(DatabaseConfigError::Invalid)?;
    if name != config.database.url_env || value.is_empty() || value.contains(char::is_whitespace) {
        return Err(DatabaseConfigError::Invalid);
    }
    Ok(SecretString::from(value.to_owned()))
}

/// Serializes the root-only `PostgreSQL` environment file with an instance-bound
/// ownership marker. The URL must already have been validated and is never
/// logged by this helper.
#[must_use]
pub fn database_environment_contents(instance_id: Uuid, name: &str, value: &str) -> String {
    format!(
        "{}\n{name}={value}\n",
        database_environment_marker(instance_id)
    )
}

fn database_environment_marker(instance_id: Uuid) -> String {
    format!("{DATABASE_ENV_MARKER_PREFIX}{instance_id}")
}

/// Connects to the dedicated `CentralD` database, validates ownership, and
/// applies embedded schema migrations.
///
/// Ownership is bound twice: a `PostgreSQL` database comment and the singleton
/// `centrald_installation` row must both match the configured server instance.
/// This prevents a mistyped URL from migrating or later deleting another
/// application's database.
///
/// # Errors
///
/// Returns an error when the pool cannot connect, ownership does not match, or
/// any migration fails.
pub async fn connect_and_migrate(
    url: &str,
    max_connections: u32,
    instance_id: Uuid,
) -> Result<PgPool, DatabaseError> {
    let target = parse_target(url).map_err(|error| DatabaseError::Ownership(error.to_string()))?;
    verify_database_comment(&target, instance_id)
        .await
        .map_err(|error| DatabaseError::Ownership(error.to_string()))?;
    let pool = PgPoolOptions::new()
        .max_connections(max_connections)
        .connect(url)
        .await?;
    verify_installation_row(&pool, instance_id)
        .await
        .map_err(DatabaseError::Ownership)?;
    sqlx::migrate!("./migrations").run(&pool).await?;
    Ok(pool)
}

/// Creates a brand-new dedicated database, migrates it, and binds it to one
/// `CentralD` server instance.
///
/// Existing databases are never adopted, even when empty. The operator must
/// choose a new database name, which keeps `--nuke` from ever treating an
/// unrelated database as CentralD-owned.
///
/// # Errors
///
/// Returns an error for unsafe URLs, an existing target database, insufficient
/// `PostgreSQL` privileges, connection failures, or migration failures.
pub async fn ensure_database_and_migrate(
    url: &str,
    max_connections: u32,
    instance_id: Uuid,
) -> Result<InitializedDatabase, DatabaseAdminError> {
    let target = parse_target(url)?;
    reject_protected_database(&target.database_name)?;
    let mut maintenance = PgConnection::connect(target.maintenance_url.as_str())
        .await
        .map_err(DatabaseAdminError::Maintenance)?;
    let exists: bool =
        sqlx::query_scalar("SELECT EXISTS (SELECT 1 FROM pg_database WHERE datname = $1)")
            .bind(&target.database_name)
            .fetch_one(&mut maintenance)
            .await
            .map_err(DatabaseAdminError::Maintenance)?;
    if exists {
        return Err(DatabaseAdminError::AlreadyExists);
    }

    let create = format!(
        "CREATE DATABASE {}",
        quote_identifier(&target.database_name)
    );
    sqlx::query(&create)
        .execute(&mut maintenance)
        .await
        .map_err(DatabaseAdminError::Create)?;
    let comment = database_comment(instance_id);
    let set_comment = format!(
        "COMMENT ON DATABASE {} IS {}",
        quote_identifier(&target.database_name),
        quote_literal(&comment)
    );
    if let Err(error) = sqlx::query(&set_comment).execute(&mut maintenance).await {
        let _ = maintenance.close().await;
        cleanup_new_database(url, instance_id).await;
        return Err(DatabaseAdminError::Create(error));
    }
    if let Err(error) = maintenance.close().await {
        cleanup_new_database(url, instance_id).await;
        return Err(DatabaseAdminError::Maintenance(error));
    }

    let pool = match PgPoolOptions::new()
        .max_connections(max_connections)
        .connect(url)
        .await
    {
        Ok(pool) => pool,
        Err(error) => {
            cleanup_new_database(url, instance_id).await;
            return Err(DatabaseAdminError::Connect(error));
        }
    };
    if let Err(error) = sqlx::migrate!("./migrations").run(&pool).await {
        pool.close().await;
        cleanup_new_database(url, instance_id).await;
        return Err(DatabaseAdminError::Migrate(error));
    }
    if let Err(error) =
        sqlx::query("INSERT INTO centrald_installation (singleton, instance_id) VALUES (TRUE, $1)")
            .bind(instance_id)
            .execute(&pool)
            .await
    {
        pool.close().await;
        cleanup_new_database(url, instance_id).await;
        return Err(DatabaseAdminError::Ownership(format!(
            "write installation marker: {error}"
        )));
    }
    Ok(InitializedDatabase { pool })
}

async fn cleanup_new_database(url: &str, _instance_id: Uuid) {
    // This helper is reachable only after `ensure_database_and_migrate` has
    // confirmed the name was absent and created it in this call. It deliberately
    // does not require the ownership comment because COMMENT itself may be the
    // step that failed. Public destructive paths still require both ownership
    // markers.
    let result = async {
        let target = parse_target(url)?;
        reject_protected_database(&target.database_name)?;
        let mut maintenance = PgConnection::connect(target.maintenance_url.as_str())
            .await
            .map_err(DatabaseAdminError::Maintenance)?;
        let statement = format!(
            "DROP DATABASE {} WITH (FORCE)",
            quote_identifier(&target.database_name)
        );
        sqlx::query(&statement)
            .execute(&mut maintenance)
            .await
            .map_err(DatabaseAdminError::Drop)?;
        maintenance
            .close()
            .await
            .map_err(DatabaseAdminError::Maintenance)?;
        Ok::<(), DatabaseAdminError>(())
    }
    .await;
    if let Err(error) = result {
        warn!(%error, "automatic cleanup of newly created database failed");
    }
}

/// Migrates a freshly provisioned managed-local database and writes its
/// internal installation marker. The database itself must already have been
/// created and commented by the pinned local postgres administrator.
///
/// # Errors
///
/// Returns an error when ownership does not match, the service login cannot
/// connect, migrations fail, or the installation marker cannot be written.
pub async fn migrate_precreated_database(
    url: &str,
    max_connections: u32,
    instance_id: Uuid,
) -> Result<InitializedDatabase, DatabaseAdminError> {
    let target = parse_target(url)?;
    reject_protected_database(&target.database_name)?;
    verify_database_comment(&target, instance_id).await?;
    let pool = PgPoolOptions::new()
        .max_connections(max_connections)
        .connect(url)
        .await
        .map_err(DatabaseAdminError::Connect)?;
    if let Err(error) = sqlx::migrate!("./migrations").run(&pool).await {
        pool.close().await;
        return Err(DatabaseAdminError::Migrate(error));
    }
    if let Err(error) =
        sqlx::query("INSERT INTO centrald_installation (singleton, instance_id) VALUES (TRUE, $1)")
            .bind(instance_id)
            .execute(&pool)
            .await
    {
        pool.close().await;
        return Err(DatabaseAdminError::Ownership(format!(
            "write installation marker: {error}"
        )));
    }
    Ok(InitializedDatabase { pool })
}

/// Verifies both `CentralD` database ownership markers without changing the database.
///
/// # Errors
///
/// Returns an error when the database is missing, its comment does not match,
/// the installation row does not match, or `PostgreSQL` cannot be reached.
pub async fn verify_owned_database(
    url: &str,
    instance_id: Uuid,
) -> Result<String, DatabaseAdminError> {
    let target = parse_target(url)?;
    reject_protected_database(&target.database_name)?;
    verify_database_comment(&target, instance_id).await?;
    let pool = PgPoolOptions::new()
        .max_connections(1)
        .connect(url)
        .await
        .map_err(DatabaseAdminError::Connect)?;
    let row_result = verify_installation_row(&pool, instance_id).await;
    pool.close().await;
    row_result.map_err(DatabaseAdminError::Ownership)?;
    Ok(target.database_name)
}

/// Returns the validated database name from a `PostgreSQL` URL without exposing
/// credentials.
///
/// # Errors
///
/// Returns an error when the URL is unsafe or the database name is protected.
pub fn database_name_from_url(url: &str) -> Result<String, DatabaseAdminError> {
    let target = parse_target(url)?;
    reject_protected_database(&target.database_name)?;
    Ok(target.database_name)
}

/// Drops a database only after both `CentralD` ownership markers match.
///
/// # Errors
///
/// Returns an error for unsafe names, a missing/mismatched ownership marker,
/// connection failures, or when `PostgreSQL` refuses the destructive operation.
pub async fn drop_owned_database(
    url: &str,
    instance_id: Uuid,
) -> Result<String, DatabaseAdminError> {
    let database_name = verify_owned_database(url, instance_id).await?;
    drop_verified_database(url).await?;
    Ok(database_name)
}

/// Removes a database created by the current setup attempt. This is used only
/// for rollback after the database comment has been written but before setup is
/// committed. It still requires the comment to match the instance ID.
///
/// # Errors
///
/// Returns an error when the database is missing, its comment does not match,
/// or the database cannot be dropped.
pub async fn rollback_setup_database(
    url: &str,
    instance_id: Uuid,
) -> Result<String, DatabaseAdminError> {
    drop_database_with_comment(url, instance_id, false).await
}

async fn drop_verified_database(url: &str) -> Result<(), DatabaseAdminError> {
    let target = parse_target(url)?;
    reject_protected_database(&target.database_name)?;
    let mut maintenance = PgConnection::connect(target.maintenance_url.as_str())
        .await
        .map_err(DatabaseAdminError::Maintenance)?;
    let statement = format!(
        "DROP DATABASE {} WITH (FORCE)",
        quote_identifier(&target.database_name)
    );
    sqlx::query(&statement)
        .execute(&mut maintenance)
        .await
        .map_err(DatabaseAdminError::Drop)?;
    maintenance
        .close()
        .await
        .map_err(DatabaseAdminError::Maintenance)?;
    Ok(())
}

async fn drop_database_with_comment(
    url: &str,
    instance_id: Uuid,
    require_installation_row: bool,
) -> Result<String, DatabaseAdminError> {
    let target = parse_target(url)?;
    reject_protected_database(&target.database_name)?;
    verify_database_comment(&target, instance_id).await?;
    if require_installation_row {
        let pool = PgPoolOptions::new()
            .max_connections(1)
            .connect(url)
            .await
            .map_err(DatabaseAdminError::Connect)?;
        let row_result = verify_installation_row(&pool, instance_id).await;
        pool.close().await;
        row_result.map_err(DatabaseAdminError::Ownership)?;
    }

    let mut maintenance = PgConnection::connect(target.maintenance_url.as_str())
        .await
        .map_err(DatabaseAdminError::Maintenance)?;
    let statement = format!(
        "DROP DATABASE {} WITH (FORCE)",
        quote_identifier(&target.database_name)
    );
    sqlx::query(&statement)
        .execute(&mut maintenance)
        .await
        .map_err(DatabaseAdminError::Drop)?;
    maintenance
        .close()
        .await
        .map_err(DatabaseAdminError::Maintenance)?;
    Ok(target.database_name)
}

async fn verify_database_comment(
    target: &DatabaseTarget,
    instance_id: Uuid,
) -> Result<(), DatabaseAdminError> {
    let mut maintenance = PgConnection::connect(target.maintenance_url.as_str())
        .await
        .map_err(DatabaseAdminError::Maintenance)?;
    let row: Option<Option<String>> = sqlx::query_scalar(
        "SELECT shobj_description(oid, 'pg_database') FROM pg_database WHERE datname = $1",
    )
    .bind(&target.database_name)
    .fetch_optional(&mut maintenance)
    .await
    .map_err(DatabaseAdminError::Maintenance)?;
    maintenance
        .close()
        .await
        .map_err(DatabaseAdminError::Maintenance)?;
    let expected = database_comment(instance_id);
    match row {
        None => Err(DatabaseAdminError::MissingDatabase(
            target.database_name.clone(),
        )),
        Some(Some(value)) if value == expected => Ok(()),
        Some(Some(_)) => Err(DatabaseAdminError::Ownership(
            "PostgreSQL database comment belongs to another server instance".to_owned(),
        )),
        Some(None) => Err(DatabaseAdminError::Ownership(
            "PostgreSQL database has no CentralD ownership comment".to_owned(),
        )),
    }
}

async fn verify_installation_row(pool: &PgPool, instance_id: Uuid) -> Result<(), String> {
    let stored: Option<Uuid> =
        sqlx::query_scalar("SELECT instance_id FROM centrald_installation WHERE singleton = TRUE")
            .fetch_optional(pool)
            .await
            .map_err(|error| format!("read centrald_installation marker: {error}"))?;
    match stored {
        Some(value) if value == instance_id => Ok(()),
        Some(_) => Err("centrald_installation belongs to another server instance".to_owned()),
        None => Err("centrald_installation marker is missing".to_owned()),
    }
}

#[derive(Debug)]
struct DatabaseTarget {
    database_name: String,
    maintenance_url: Url,
}

/// Validates the structural and transport-security policy for a `PostgreSQL` URL.
///
/// Connection identity is taken only from the authority/path portion of the URL.
/// Query parameters that can override host, user, password, or database are
/// rejected because SQLx/libpq otherwise permit them to disagree with the fields
/// `CentralD` uses for ownership and destructive-operation checks. Remote TCP
/// databases must use `sslmode=verify-full`; loopback development connections may
/// use another explicit or default mode.
///
/// # Errors
///
/// Returns an error when the URL is structurally invalid, uses an unsafe query
/// parameter, or violates the transport-security policy.
pub fn validate_database_url_policy(value: &str) -> Result<(), DatabaseAdminError> {
    if value.contains(char::is_whitespace) {
        return Err(DatabaseAdminError::InvalidUrl);
    }
    let parsed = Url::parse(value).map_err(|_| DatabaseAdminError::InvalidUrl)?;
    if !matches!(parsed.scheme(), "postgres" | "postgresql")
        || parsed.host_str().is_none()
        || parsed.port().is_none()
        || parsed.username().is_empty()
        || parsed.fragment().is_some()
    {
        return Err(DatabaseAdminError::InvalidUrl);
    }
    let database_name = parsed.path().trim_start_matches('/');
    if database_name.is_empty()
        || database_name.len() > 63
        || database_name.contains('/')
        || !database_name
            .chars()
            .all(|character| character.is_ascii_alphanumeric() || matches!(character, '_' | '-'))
    {
        return Err(DatabaseAdminError::InvalidUrl);
    }

    let mut seen = std::collections::BTreeSet::new();
    let mut sslmode = None;
    for (key, value) in parsed.query_pairs() {
        if !seen.insert(key.to_string()) {
            return Err(DatabaseAdminError::InvalidUrl);
        }
        #[allow(clippy::match_same_arms)]
        match key.as_ref() {
            "sslmode" => sslmode = Some(value.to_string()),
            "sslrootcert"
            | "sslcert"
            | "sslkey"
            | "application_name"
            | "statement-cache-capacity" => {}
            // SQLx/libpq accept these as query parameters and they can override
            // the authority/path fields CentralD validates above. The explicit
            // deny list stays on contiguous lines so it reads as one policy.
            #[rustfmt::skip]
            "user" | "password" | "passfile" | "host" | "hostaddr" | "port" | "dbname" | "options" => return Err(DatabaseAdminError::InvalidUrl),
            _ => return Err(DatabaseAdminError::InvalidUrl),
        }
    }

    reject_ambient_postgres_environment()?;

    let host = parsed.host_str().ok_or(DatabaseAdminError::InvalidUrl)?;
    let loopback = host.eq_ignore_ascii_case("localhost")
        || host
            .parse::<std::net::IpAddr>()
            .is_ok_and(|address| address.is_loopback());
    if !loopback && sslmode.as_deref() != Some("verify-full") {
        return Err(DatabaseAdminError::InvalidUrl);
    }
    Ok(())
}

fn reject_ambient_postgres_environment() -> Result<(), DatabaseAdminError> {
    const VARIABLES: &[&str] = &[
        "PGUSER",
        "PGPASSWORD",
        "PGPASSFILE",
        "PGHOST",
        "PGHOSTADDR",
        "PGPORT",
        "PGDATABASE",
        "PGSSLMODE",
        "PGSSLROOTCERT",
        "PGSSLCERT",
        "PGSSLKEY",
        "PGOPTIONS",
        "PGAPPNAME",
        "PGSERVICE",
        "PGSERVICEFILE",
    ];
    let present: Vec<&str> = VARIABLES
        .iter()
        .copied()
        .filter(|name| std::env::var_os(name).is_some())
        .collect();
    if present.is_empty() {
        Ok(())
    } else {
        Err(DatabaseAdminError::UnsafeEnvironment(present.join(", ")))
    }
}

fn parse_target(value: &str) -> Result<DatabaseTarget, DatabaseAdminError> {
    validate_database_url_policy(value)?;
    let mut parsed = Url::parse(value).map_err(|_| DatabaseAdminError::InvalidUrl)?;
    let database_name = parsed.path().trim_start_matches('/').to_owned();
    parsed.set_path("/postgres");
    parsed.set_fragment(None);
    Ok(DatabaseTarget {
        database_name,
        maintenance_url: parsed,
    })
}

fn database_comment(instance_id: Uuid) -> String {
    format!("{DATABASE_COMMENT_PREFIX}{instance_id}")
}

fn quote_identifier(value: &str) -> String {
    format!("\"{}\"", value.replace('"', "\"\""))
}

fn quote_literal(value: &str) -> String {
    format!("'{}'", value.replace('\'', "''"))
}

fn reject_protected_database(database_name: &str) -> Result<(), DatabaseAdminError> {
    if matches!(database_name, "postgres" | "template0" | "template1") {
        Err(DatabaseAdminError::ProtectedDatabase)
    } else {
        Ok(())
    }
}

#[cfg(test)]
#[allow(clippy::unwrap_used)]
mod tests {
    use super::*;

    #[test]
    fn database_target_rejects_protected_or_complex_paths() {
        assert!(parse_target("https://db/centrald").is_err());
        assert!(parse_target("postgresql://user:secret@127.0.0.1:5432/").is_err());
        assert!(parse_target("postgresql://user:secret@127.0.0.1:5432/centrald%2Fother").is_err());
        let target = parse_target("postgresql://user:secret@127.0.0.1:5432/centrald").unwrap();
        assert_eq!(target.database_name, "centrald");
        assert_eq!(target.maintenance_url.path(), "/postgres");
        assert!(reject_protected_database("postgres").is_err());
        assert!(reject_protected_database("template0").is_err());
    }

    #[test]
    fn remote_database_urls_require_verify_full_sslmode() {
        assert!(
            validate_database_url_policy("postgresql://user:secret@db.example:5432/centrald")
                .is_err()
        );
        assert!(
            validate_database_url_policy(
                "postgresql://user:secret@db.example:5432/centrald?sslmode=require"
            )
            .is_err()
        );
        assert!(
            validate_database_url_policy(
                "postgresql://user:secret@db.example:5432/centrald?sslmode=verify-full"
            )
            .is_ok()
        );
        assert!(
            validate_database_url_policy("postgresql://user:secret@127.0.0.1:5432/centrald")
                .is_ok()
        );
        assert!(
            validate_database_url_policy("postgresql://user:secret@localhost:5432/centrald")
                .is_ok()
        );
    }

    #[test]
    fn database_urls_reject_target_changing_or_unknown_query_options() {
        assert!(
            validate_database_url_policy(
                "postgresql://user:secret@127.0.0.1:5432/centrald?host=evil.example"
            )
            .is_err()
        );
        assert!(
            validate_database_url_policy(
                "postgresql://user:secret@127.0.0.1:5432/centrald?dbname=other"
            )
            .is_err()
        );
        assert!(
            validate_database_url_policy(
                "postgresql://user:secret@127.0.0.1:5432/centrald?application_name=centrald&application_name=dup"
            )
            .is_err()
        );
        assert!(
            validate_database_url_policy(
                "postgresql://user:secret@127.0.0.1:5432/centrald?unexpected=1"
            )
            .is_err()
        );
        assert!(validate_database_url_policy("postgresql://user:secret@db/centrald").is_err());
    }

    #[test]
    fn ownership_comment_is_instance_bound() {
        let id = Uuid::nil();
        assert_eq!(
            database_comment(id),
            "centrald-instance:00000000-0000-0000-0000-000000000000"
        );
    }
}
