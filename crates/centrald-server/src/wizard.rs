use std::path::{Path, PathBuf};

use anyhow::{Context, Result, bail};
use centrald_common::host::canonical_host;
use console::{Term, style};
use dialoguer::{Confirm, Input, Password, Select, theme::ColorfulTheme};
use rand::RngCore;
use secrecy::{ExposeSecret, SecretString};

use crate::cli::SetupArgs;
use crate::db::validate_database_url_policy;
use crate::manage::CreatedEnrollmentKey;
use crate::setup::{SetupOptions, SetupSummary};
use centrald_common::config::{SERVER_DATA_DIR, SERVER_DATABASE_ENV_FILE, SERVER_DATABASE_URL_ENV};

const DATABASE_ENV: &str = SERVER_DATABASE_URL_ENV;

/// Collects validated setup options through guided or non-interactive flow.
///
/// # Errors
///
/// Returns an error when required automation input is missing, prompt input is
/// invalid, terminal interaction fails, or the operator cancels.
pub fn collect(config_path: &Path, args: SetupArgs) -> Result<SetupOptions> {
    if args.non_interactive {
        return collect_non_interactive(config_path, args);
    }
    collect_interactive(config_path, args)
}

/// Prints post-setup paths, the one-time Admin access key, and next commands.
pub fn print_completion(
    summary: &SetupSummary,
    admin: &CreatedEnrollmentKey,
    service_status: &str,
) {
    let service_ready = service_status.starts_with("READY:");
    let service_incomplete = service_status.starts_with("INCOMPLETE:");
    println!();
    if service_ready {
        println!("{}", style("✓ CentralD server initialized").green().bold());
    } else if service_incomplete {
        println!(
            "{}",
            style("CentralD setup committed — service not ready yet")
                .yellow()
                .bold()
        );
    } else {
        println!(
            "{}",
            style("✓ CentralD setup committed (start the service next)")
                .green()
                .bold()
        );
    }
    println!("  Config: {}", summary.config_path.display());
    println!(
        "  Trust certificate: {}",
        summary.trust_certificate_path.display()
    );
    println!(
        "  Trust fingerprint: sha256:{}",
        summary.root_fingerprint_sha256
    );
    println!(
        "  Offline recovery bundle: {}",
        summary.recovery_key_output.display()
    );
    println!();
    println!(
        "{}",
        style("Initial Admin access key (shown once)")
            .yellow()
            .bold()
    );
    println!("{}", admin.key.expose_secret());
    println!("Expires: {}", admin.expires_at);
    println!(
        "Paste this single key into CentralD Admin. It contains the public bootstrap metadata; no CA file or separate endpoint is required."
    );
    println!();
    println!("{}", style("Service").cyan().bold());
    println!("  {service_status}");
    println!();
    println!("{}", style("Next steps").cyan().bold());
    if service_incomplete {
        println!("  1. Fix service startup using the recovery command above.");
        println!("  2. Confirm health with: sudo centrald-server config");
        println!("  3. Move the root recovery bundle offline.");
        println!("  4. Enroll CentralD Admin with the access key above.");
    } else if service_ready {
        println!("  1. Move the root recovery bundle offline.");
        println!("  2. Enroll CentralD Admin with the access key above.");
        println!("  3. Open guided management any time: centrald-server config");
    } else {
        println!("  1. Start CentralD using the service guidance above.");
        println!("  2. Move the root recovery bundle offline.");
        println!("  3. Enroll CentralD Admin with the access key above.");
        println!("  4. Open guided management any time: centrald-server config");
    }
}

fn collect_interactive(config_path: &Path, args: SetupArgs) -> Result<SetupOptions> {
    let theme = ColorfulTheme::default();
    let term = Term::stdout();
    term.write_line("")?;
    term.write_line(&style("CentralD Initial Setup").cyan().bold().to_string())?;
    term.write_line("Guided secure setup for Ubuntu Server 24.04 and newer.")?;
    term.write_line("No existing config, key, database, or recovery file will be overwritten.")?;
    term.write_line("")?;

    let instance_id = uuid::Uuid::now_v7();
    let public_host = Input::<String>::with_theme(&theme)
        .with_prompt("TLS name clients should verify (DNS name or IP)")
        .with_initial_text(args.public_host.unwrap_or_default())
        .validate_with(|value: &String| validate_host(value))
        .interact_text()?;
    let public_host = canonical_host(&public_host).context("canonicalize public TLS host")?;
    let database_url_env = args
        .database_url_env
        .unwrap_or_else(|| DATABASE_ENV.to_owned());
    let (database_url, managed_local_role) =
        database_setup(&theme, &database_url_env, instance_id)?;
    let requested_data_dir = args.data_dir.unwrap_or_else(default_data_dir);
    if requested_data_dir != *SERVER_DATA_DIR {
        bail!("packaged CentralD uses fixed server data directory {SERVER_DATA_DIR}");
    }
    let data_dir = PathBuf::from(SERVER_DATA_DIR);
    println!("  Package-managed data directory: {}", data_dir.display());
    let recovery_key_output = path_prompt(
        &theme,
        "Offline root recovery bundle path",
        &args
            .recovery_key_output
            .unwrap_or_else(default_recovery_path),
    )?;
    let admin_name = Input::<String>::with_theme(&theme)
        .with_prompt("Name for the first Admin")
        .with_initial_text(args.admin_name.unwrap_or_else(|| "Home Lab Admin".into()))
        .validate_with(|value: &String| validate_name(value))
        .interact_text()?;
    let environment_file = PathBuf::from(SERVER_DATABASE_ENV_FILE);

    println!();
    println!("{}", style("Review").cyan().bold());
    println!("  TLS name: {public_host}");
    println!("  Config: {}", config_path.display());
    println!("  Data: {}", data_dir.display());
    println!("  Database secret file: {}", environment_file.display());
    println!(
        "  PostgreSQL: {}",
        if managed_local_role.is_some() {
            "CentralD-managed local role/database"
        } else {
            "operator-managed PostgreSQL URL"
        }
    );
    println!("  Recovery bundle: {}", recovery_key_output.display());
    println!("  First Admin: {admin_name}");
    println!("  Ports: 7443 enrollment, 7444 client mTLS, 7445 Admin mTLS");
    println!("  PostgreSQL database is created when absent and then migrated.");
    if !Confirm::with_theme(&theme)
        .with_prompt("Create this CentralD server?")
        .default(true)
        .interact()?
    {
        bail!("setup canceled; no files written");
    }

    Ok(SetupOptions {
        instance_id,
        config_path: config_path.to_path_buf(),
        public_host,
        database_url_env,
        database_url,
        managed_local_role,
        environment_file,
        data_dir,
        recovery_key_output,
        admin_name,
    })
}

fn collect_non_interactive(config_path: &Path, args: SetupArgs) -> Result<SetupOptions> {
    let instance_id = uuid::Uuid::now_v7();
    let public_host = args
        .public_host
        .filter(|value| !value.trim().is_empty())
        .context("--public-host is required with --non-interactive")?;
    validate_host(&public_host).map_err(anyhow::Error::msg)?;
    let public_host = canonical_host(&public_host).context("canonicalize public TLS host")?;
    let database_url_env = args.database_url_env.unwrap_or_else(|| DATABASE_ENV.into());
    let database_url = std::env::var(&database_url_env)
        .with_context(|| format!("{database_url_env} must be set for non-interactive setup"))?;
    validate_database_url(&database_url).map_err(anyhow::Error::msg)?;
    let data_dir = args.data_dir.unwrap_or_else(default_data_dir);
    if data_dir != *SERVER_DATA_DIR {
        bail!("packaged CentralD uses fixed server data directory {SERVER_DATA_DIR}");
    }
    let recovery_key_output = args
        .recovery_key_output
        .context("--recovery-key-output is required with --non-interactive")?;
    let admin_name = args
        .admin_name
        .context("--admin-name is required with --non-interactive")?;
    validate_name(&admin_name).map_err(anyhow::Error::msg)?;
    let environment_file = PathBuf::from(SERVER_DATABASE_ENV_FILE);
    Ok(SetupOptions {
        instance_id,
        config_path: config_path.to_path_buf(),
        public_host,
        database_url_env,
        database_url: SecretString::from(database_url),
        managed_local_role: None,
        environment_file,
        data_dir,
        recovery_key_output,
        admin_name,
    })
}

fn database_setup(
    theme: &ColorfulTheme,
    variable: &str,
    instance_id: uuid::Uuid,
) -> Result<(SecretString, Option<String>)> {
    let choices = [
        "Recommended: configure local PostgreSQL automatically",
        "Advanced: use an existing or remote PostgreSQL URL",
    ];
    let selected = Select::with_theme(theme)
        .with_prompt("PostgreSQL setup")
        .items(choices)
        .default(0)
        .interact()?;
    if selected == 0 {
        let role = format!("centrald_{}", instance_id.simple());
        let mut secret = [0_u8; 32];
        rand::rng().fill_bytes(&mut secret);
        let password = SecretString::from(hex::encode(secret));
        secret.fill(0);
        let database = role.clone();
        let url = format!(
            "postgresql://{role}:{}@127.0.0.1:5432/{database}",
            password.expose_secret()
        );
        println!("  CentralD will create one dedicated local PostgreSQL role and database.");
        println!(
            "  The generated password is stored only in the root-protected server environment file."
        );
        Ok((SecretString::from(url), Some(role)))
    } else {
        Ok((advanced_database_secret(theme, variable)?, None))
    }
}

fn advanced_database_secret(theme: &ColorfulTheme, variable: &str) -> Result<SecretString> {
    if let Ok(value) = std::env::var(variable) {
        let use_existing = validate_database_url(&value).is_ok()
            && Confirm::with_theme(theme)
                .with_prompt(format!("Use PostgreSQL URL already set in {variable}?"))
                .default(true)
                .interact()?;
        if use_existing {
            return Ok(SecretString::from(value));
        }
    }
    let value = Password::with_theme(theme)
        .with_prompt("PostgreSQL URL (advanced; input hidden)")
        .validate_with(|value: &String| validate_database_url(value))
        .interact()?;
    Ok(SecretString::from(value))
}

fn path_prompt(theme: &ColorfulTheme, prompt: &str, default: &Path) -> Result<PathBuf> {
    let value = Input::<String>::with_theme(theme)
        .with_prompt(prompt)
        .default(default.to_string_lossy().into_owned())
        .validate_with(|value: &String| {
            if value.trim().is_empty() {
                Err("path must not be empty")
            } else {
                Ok(())
            }
        })
        .interact_text()?;
    Ok(PathBuf::from(value))
}

fn validate_host(value: &str) -> Result<(), &'static str> {
    canonical_host(value).map(|_| ()).map_err(
        |_| "enter a canonical ASCII DNS name or IP without scheme, port, path, or whitespace",
    )
}

fn validate_name(value: &str) -> Result<(), &'static str> {
    if value.trim().is_empty() || value.len() > 128 || value.chars().any(char::is_control) {
        Err("enter 1-128 printable characters")
    } else {
        Ok(())
    }
}

fn validate_database_url(value: &str) -> Result<(), String> {
    validate_database_url_policy(value).map_err(|error| format!(
        "{error}; use postgresql://user:password@host:5432/database and require sslmode=verify-full for non-loopback hosts"
    ))
}

fn default_data_dir() -> PathBuf {
    PathBuf::from(SERVER_DATA_DIR)
}

fn default_recovery_path() -> PathBuf {
    PathBuf::from("/root/centrald-root-recovery.pem")
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn validators_reject_urls_in_host_and_non_postgres_database() {
        assert!(validate_host("https://centrald.example").is_err());
        assert!(validate_host("centrald.example").is_ok());
        assert!(validate_database_url("https://centrald.example").is_err());
        assert!(
            validate_database_url("postgresql://centrald:secret@127.0.0.1:5432/centrald").is_ok()
        );
        assert!(validate_name("").is_err());
    }
}
