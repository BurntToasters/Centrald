use std::io::Write;
use std::path::Path;
use std::process::{Command, Stdio};

use anyhow::{Context, Result, bail};
use secrecy::{ExposeSecret, SecretString};
use url::Url;
use uuid::Uuid;

const ENV: &str = "/usr/bin/env";
const PSQL: &str = "/usr/bin/psql";
const RUNUSER: &str = "/usr/sbin/runuser";
const SYSTEMCTL: &str = "/usr/bin/systemctl";
const TIMEOUT: &str = "/usr/bin/timeout";
const LOCAL_POSTGRES_SOCKET: &str = "/var/run/postgresql";
const LOCAL_POSTGRES_PORT: &str = "5432";
const SAFE_PATH: &str = "/usr/sbin:/usr/bin:/sbin:/bin";
const ROLE_COMMENT_PREFIX: &str = "centrald-instance:";
const NULL_SENTINEL: &str = "__centrald_null__";
const MAX_DIAGNOSTIC_BYTES: usize = 4096;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum RoleOwnership {
    Missing,
    Owned,
    Other,
}

/// Provisions the dedicated `PostgreSQL` login used by the recommended local setup.
///
/// SQL is delivered on stdin, so the generated password never appears in
/// process arguments. Role creation and its instance-bound ownership marker are
/// one `PostgreSQL` transaction. The login never receives database-creation or
/// role-management authority; the pinned local postgres administrator creates
/// its one database separately.
///
/// # Errors
///
/// Returns an error when the generated URL is inconsistent or the role cannot
/// be created.
pub fn provision_role(role: &str, database_url: &SecretString, instance_id: Uuid) -> Result<()> {
    let _database = managed_database_name(role, database_url)?;
    let parsed =
        Url::parse(database_url.expose_secret()).context("parse generated local PostgreSQL URL")?;
    let password = parsed
        .password()
        .context("generated local PostgreSQL URL has no password")?;
    let statement = format!(
        "BEGIN;\nCREATE ROLE {} LOGIN NOCREATEDB NOSUPERUSER NOCREATEROLE NOREPLICATION PASSWORD {};\nCOMMENT ON ROLE {} IS {};\nCOMMIT;\n",
        quote_identifier(role),
        quote_literal(password),
        quote_identifier(role),
        quote_literal(&role_comment(instance_id)),
    );
    run_psql(&statement, true).context("create the dedicated CentralD PostgreSQL role")
}

/// Creates the one instance-bound database owned by the restricted managed login.
///
/// The operation runs through the pinned local postgres administrator. The
/// service login therefore never needs `CREATEDB`, even temporarily. A durable
/// setup-recovery journal must already exist before this function is called.
///
/// # Errors
///
/// Returns an error when the role marker does not match, the generated URL is
/// inconsistent, or `PostgreSQL` rejects database creation/commenting.
pub fn provision_database(
    role: &str,
    database_url: &SecretString,
    instance_id: Uuid,
) -> Result<()> {
    let database = managed_database_name(role, database_url)?;
    require_owned_role(role, instance_id)?;
    let statement = format!(
        "CREATE DATABASE {} OWNER {};\nCOMMENT ON DATABASE {} IS {};\n",
        quote_identifier(&database),
        quote_identifier(role),
        quote_identifier(&database),
        quote_literal(&role_comment(instance_id)),
    );
    run_psql(&statement, false).context("create the dedicated CentralD PostgreSQL database")
}

/// Returns the generated database name after validating the complete local URL.
/// This helper intentionally never returns the password.
///
/// # Errors
///
/// Returns an error when the role name is invalid or the URL does not match
/// the generated local role/database pair.
pub fn managed_database_name(role: &str, database_url: &SecretString) -> Result<String> {
    validate_managed_name(role)?;
    let parsed =
        Url::parse(database_url.expose_secret()).context("parse generated local PostgreSQL URL")?;
    let database = parsed.path().trim_start_matches('/');
    if parsed.scheme() != "postgresql"
        || parsed.username() != role
        || parsed.password().is_none()
        || parsed.host_str() != Some("127.0.0.1")
        || parsed.port_or_known_default() != Some(5432)
        || parsed.query().is_some()
        || parsed.fragment().is_some()
        || database != role
    {
        bail!("managed PostgreSQL URL does not match the generated local role/database");
    }
    Ok(database.to_owned())
}

/// Reasserts the restricted privilege set on the managed service login.
///
/// # Errors
///
/// Returns an error when the role is missing, is not owned by this server
/// instance, or the privileges cannot be reset.
pub fn harden_role(role: &str, instance_id: Uuid) -> Result<()> {
    require_owned_role(role, instance_id)?;
    run_psql(
        &format!(
            "ALTER ROLE {} NOCREATEDB NOSUPERUSER NOCREATEROLE NOREPLICATION;\n",
            quote_identifier(role)
        ),
        false,
    )
    .context("remove PostgreSQL database-creation privilege from the CentralD role")
}

/// Cleans an interrupted recommended local setup without trusting a generated-
/// looking name alone.
///
/// The role must carry this setup's exact instance marker. A same-named database
/// is removed only when that role owns it and its comment is either the expected
/// marker or absent in the narrow crash window before the database comment was
/// committed. Foreign collisions are left untouched; the recovery journal may
/// then retire so a fresh setup can generate a different full-width UUID name.
///
/// # Errors
///
/// Returns an error when the role/database names are invalid, ownership checks
/// fail, or the managed objects cannot be removed.
pub fn cleanup_managed_resources(role: &str, database: &str, instance_id: Uuid) -> Result<()> {
    validate_managed_name(role)?;
    validate_managed_name(database)?;
    if role != database {
        bail!("managed PostgreSQL cleanup requires the generated role/database pair to match");
    }

    match role_ownership(role, instance_id)? {
        // A pre-existing colliding role/database was never created by this
        // setup attempt. Preserve it and allow the journal to retire so the
        // next guided run can generate a different 128-bit name.
        RoleOwnership::Missing | RoleOwnership::Other => return Ok(()),
        RoleOwnership::Owned => {}
    }

    if let Some(owner) = database_owner(database)? {
        if owner != role {
            // The same-name database is foreign. Remove only our instance-
            // bound role; PostgreSQL will refuse if unexpected dependencies
            // make even that cleanup unsafe.
            return drop_owned_role(role, instance_id);
        }
        if let Some(comment) = database_comment_value(database)?
            && comment != role_comment(instance_id)
        {
            bail!(
                "refusing to remove PostgreSQL database {database}: its ownership comment belongs to another installation"
            );
        }
        run_psql(
            &format!(
                "DROP DATABASE IF EXISTS {} WITH (FORCE);\n",
                quote_identifier(database)
            ),
            false,
        )
        .context("remove interrupted CentralD-managed PostgreSQL database")?;
    }
    drop_owned_role(role, instance_id)
}

/// Verifies that a managed role exists and belongs to the expected server.
///
/// # Errors
///
/// Returns an error when the role name is invalid, the role is missing, or the
/// role is not owned by this server instance.
pub fn require_owned_role(role: &str, instance_id: Uuid) -> Result<()> {
    validate_managed_name(role)?;
    match role_ownership(role, instance_id)? {
        RoleOwnership::Owned => Ok(()),
        RoleOwnership::Missing => bail!("CentralD-managed PostgreSQL role {role} is missing"),
        RoleOwnership::Other => {
            bail!("PostgreSQL role {role} is not owned by this CentralD server instance")
        }
    }
}

/// Removes the dedicated role only after its instance-bound marker matches.
///
/// # Errors
///
/// Returns an error when the role name is invalid, the role is owned by
/// another server instance, or the role cannot be removed.
pub fn drop_owned_role(role: &str, instance_id: Uuid) -> Result<()> {
    validate_managed_name(role)?;
    match role_ownership(role, instance_id)? {
        RoleOwnership::Missing => return Ok(()),
        RoleOwnership::Owned => {}
        RoleOwnership::Other => bail!(
            "refusing to remove PostgreSQL role {role}: its CentralD ownership marker does not match"
        ),
    }
    run_psql(&format!("DROP ROLE {};\n", quote_identifier(role)), false)
        .context("remove the dedicated CentralD PostgreSQL role")
}

fn role_ownership(role: &str, instance_id: Uuid) -> Result<RoleOwnership> {
    validate_managed_name(role)?;
    let value = query_optional_scalar(&format!(
        "SELECT COALESCE(shobj_description(oid, 'pg_authid'), {}) FROM pg_roles WHERE rolname = {};",
        quote_literal(NULL_SENTINEL),
        quote_literal(role),
    ))?;
    Ok(match value {
        None => RoleOwnership::Missing,
        Some(comment) if comment == role_comment(instance_id) => RoleOwnership::Owned,
        Some(_) => RoleOwnership::Other,
    })
}

fn database_owner(database: &str) -> Result<Option<String>> {
    validate_managed_name(database)?;
    query_optional_scalar(&format!(
        "SELECT owner.rolname FROM pg_database AS database_entry JOIN pg_roles AS owner ON owner.oid = database_entry.datdba WHERE database_entry.datname = {};",
        quote_literal(database),
    ))
}

fn database_comment_value(database: &str) -> Result<Option<String>> {
    validate_managed_name(database)?;
    let value = query_optional_scalar(&format!(
        "SELECT COALESCE(shobj_description(oid, 'pg_database'), {}) FROM pg_database WHERE datname = {};",
        quote_literal(NULL_SENTINEL),
        quote_literal(database),
    ))?;
    match value.as_deref() {
        Some(NULL_SENTINEL) | None => Ok(None),
        Some(_) => Ok(value),
    }
}

fn role_comment(instance_id: Uuid) -> String {
    format!("{ROLE_COMMENT_PREFIX}{instance_id}")
}

fn ensure_tools() -> Result<()> {
    if !Path::new(PSQL).is_file()
        || !Path::new(RUNUSER).is_file()
        || !Path::new(ENV).is_file()
        || !Path::new(TIMEOUT).is_file()
    {
        bail!(
            "recommended local PostgreSQL setup requires the Ubuntu postgresql and coreutils packages; install them with: sudo apt install postgresql coreutils"
        );
    }
    Ok(())
}

fn ensure_postgresql_started() -> Result<()> {
    if !Path::new("/run/systemd/system").is_dir() || !Path::new(SYSTEMCTL).is_file() {
        return Ok(());
    }
    let output = Command::new(TIMEOUT)
        .env_clear()
        .env("PATH", SAFE_PATH)
        .env("LANG", "C")
        .env("LC_ALL", "C")
        .args([
            "--signal=TERM",
            "--kill-after=5s",
            "45s",
            SYSTEMCTL,
            "--no-ask-password",
            "enable",
            "--now",
            "postgresql.service",
        ])
        .output()
        .context("start the local PostgreSQL service")?;
    if output.status.success() {
        return Ok(());
    }
    let detail = bounded_diagnostic(&output.stderr);
    bail!(
        "could not enable and start postgresql.service{}; run `sudo systemctl status postgresql.service --no-pager` for details",
        diagnostic_suffix(&detail)
    )
}

fn pinned_psql_command() -> Command {
    // runuser preserves most of the caller environment and PAM may add more.
    // Execute `env -i` after the identity transition and specify every target
    // parameter so inherited libpq settings cannot redirect this local path.
    let mut command = Command::new(RUNUSER);
    command
        .env_clear()
        .env("PATH", SAFE_PATH)
        .env("LANG", "C")
        .env("LC_ALL", "C")
        .args([
            "-u",
            "postgres",
            "--",
            ENV,
            "-i",
            "HOME=/var/lib/postgresql",
            "USER=postgres",
            "LOGNAME=postgres",
            "PATH=/usr/sbin:/usr/bin:/sbin:/bin",
            "LANG=C",
            "LC_ALL=C",
            TIMEOUT,
            "--signal=TERM",
            "--kill-after=5s",
            "30s",
            PSQL,
            "--no-psqlrc",
            "--host",
            LOCAL_POSTGRES_SOCKET,
            "--port",
            LOCAL_POSTGRES_PORT,
            "--username",
            "postgres",
            "--dbname",
            "postgres",
        ]);
    command
}

fn run_psql(sql: &str, contains_secret: bool) -> Result<()> {
    ensure_tools()?;
    ensure_postgresql_started()?;
    let mut command = pinned_psql_command();
    let mut child = command
        .args([
            "--quiet",
            "--set",
            "ON_ERROR_STOP=1",
            "--set",
            "VERBOSITY=terse",
        ])
        .stdin(Stdio::piped())
        .stdout(Stdio::null())
        .stderr(Stdio::piped())
        .spawn()
        .context("start pinned local PostgreSQL administration command")?;
    let mut stdin = child
        .stdin
        .take()
        .context("open PostgreSQL administration stdin")?;
    stdin
        .write_all(sql.as_bytes())
        .context("write PostgreSQL administration request")?;
    drop(stdin);
    let output = child
        .wait_with_output()
        .context("wait for PostgreSQL administration command")?;
    if !output.status.success() {
        let detail = if contains_secret {
            String::new()
        } else {
            bounded_diagnostic(&output.stderr)
        };
        bail!(
            "PostgreSQL rejected the pinned local CentralD administration operation{}; check `sudo systemctl status postgresql.service --no-pager`",
            diagnostic_suffix(&detail)
        );
    }
    Ok(())
}

fn query_optional_scalar(sql: &str) -> Result<Option<String>> {
    ensure_tools()?;
    ensure_postgresql_started()?;
    let mut command = pinned_psql_command();
    let mut child = command
        .args([
            "--tuples-only",
            "--no-align",
            "--set",
            "ON_ERROR_STOP=1",
            "--set",
            "VERBOSITY=terse",
        ])
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .context("start pinned local PostgreSQL ownership query")?;
    let mut stdin = child
        .stdin
        .take()
        .context("open PostgreSQL ownership-query stdin")?;
    stdin
        .write_all(sql.as_bytes())
        .context("write PostgreSQL ownership query")?;
    drop(stdin);
    let output = child
        .wait_with_output()
        .context("wait for PostgreSQL ownership query")?;
    if !output.status.success() {
        let detail = bounded_diagnostic(&output.stderr);
        bail!(
            "could not query pinned local PostgreSQL ownership metadata{}",
            diagnostic_suffix(&detail)
        );
    }
    let text =
        String::from_utf8(output.stdout).context("PostgreSQL returned non-UTF-8 metadata")?;
    let mut rows = text.lines().map(str::trim).filter(|line| !line.is_empty());
    let first = rows.next().map(ToOwned::to_owned);
    if rows.next().is_some() {
        bail!("PostgreSQL ownership query returned more than one row");
    }
    Ok(first)
}

fn bounded_diagnostic(bytes: &[u8]) -> String {
    let truncated = bytes.len() > MAX_DIAGNOSTIC_BYTES;
    let value = String::from_utf8_lossy(&bytes[..bytes.len().min(MAX_DIAGNOSTIC_BYTES)]);
    let mut value = value
        .chars()
        .map(|character| {
            if character.is_control() && !matches!(character, '\n' | '\t') {
                ' '
            } else {
                character
            }
        })
        .collect::<String>()
        .split_whitespace()
        .collect::<Vec<_>>()
        .join(" ");
    if truncated {
        value.push_str(" [truncated]");
    }
    value
}

fn diagnostic_suffix(detail: &str) -> String {
    if detail.is_empty() {
        String::new()
    } else {
        format!(": {detail}")
    }
}

/// Validates a CentralD-managed `PostgreSQL` object name.
///
/// # Errors
///
/// Returns an error when the name does not match the generated managed-name
/// shape.
pub fn validate_managed_name(value: &str) -> Result<()> {
    if value.len() < 10
        || value.len() > 63
        || !value.starts_with("centrald_")
        || !value.chars().all(|character| {
            character.is_ascii_lowercase() || character.is_ascii_digit() || character == '_'
        })
    {
        bail!("invalid CentralD-managed PostgreSQL object name");
    }
    Ok(())
}

fn quote_identifier(value: &str) -> String {
    format!("\"{}\"", value.replace('"', "\"\""))
}

fn quote_literal(value: &str) -> String {
    format!("'{}'", value.replace('\\', "\\\\").replace('\'', "''"))
}

#[cfg(test)]
#[allow(clippy::expect_used)]
mod tests {
    use super::*;

    #[test]
    fn managed_url_requires_exact_generated_role_and_database() {
        let role = "centrald_0123456789abcdef";
        let good = SecretString::from(format!("postgresql://{role}:secret@127.0.0.1:5432/{role}"));
        assert_eq!(
            managed_database_name(role, &good).expect("managed URL should validate"),
            role
        );
        let wrong_database = SecretString::from(format!(
            "postgresql://{role}:secret@127.0.0.1:5432/centrald_other123"
        ));
        assert!(managed_database_name(role, &wrong_database).is_err());
    }

    #[test]
    fn role_marker_is_instance_bound() {
        assert_eq!(
            role_comment(Uuid::nil()),
            "centrald-instance:00000000-0000-0000-0000-000000000000"
        );
    }

    #[test]
    fn diagnostics_are_bounded_and_single_line() {
        let input = vec![b'x'; MAX_DIAGNOSTIC_BYTES + 10];
        let value = bounded_diagnostic(&input);
        assert!(value.ends_with("[truncated]"));
        assert!(value.len() <= MAX_DIAGNOSTIC_BYTES + 12);
        assert_eq!(
            bounded_diagnostic(b"line one\nline two"),
            "line one line two"
        );
    }
}
