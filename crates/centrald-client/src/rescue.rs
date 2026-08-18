use std::path::{Path, PathBuf};
use std::process::{Command, Output};

use anyhow::{Context, Result, bail};
use centrald_common::config::ClientConfig;
#[cfg(windows)]
use centrald_common::config::windows_system_executable;
use centrald_common::secure_fs::write_new_file;
use chrono::Utc;
use serde::Serialize;

use crate::cli::RescueArgs;

#[derive(Debug, Serialize)]
#[serde(rename_all = "camelCase")]
struct RescueReport {
    generated_at: String,
    client_version: &'static str,
    operating_system: &'static str,
    architecture: &'static str,
    config_path: Option<PathBuf>,
    identity_id: Option<String>,
    server_name: Option<String>,
    endpoint: Option<String>,
    certificate_expires_at: Option<String>,
    checks: Vec<RescueCheck>,
    repair_performed: bool,
}

#[derive(Debug, Serialize)]
#[serde(rename_all = "camelCase")]
struct RescueCheck {
    name: &'static str,
    ok: bool,
    detail: String,
}

/// Runs bounded, redacted client diagnostics and optional local repair.
///
/// # Errors
///
/// Returns an error when no enrolled configuration exists, a requested repair
/// fails, a diagnostic bundle cannot be created safely, or one or more checks
/// fail after any requested repair.
#[allow(clippy::too_many_lines)]
pub async fn run(args: RescueArgs) -> Result<()> {
    let mut report = RescueReport {
        generated_at: Utc::now().to_rfc3339(),
        client_version: env!("CARGO_PKG_VERSION"),
        operating_system: std::env::consts::OS,
        architecture: std::env::consts::ARCH,
        config_path: None,
        identity_id: None,
        server_name: None,
        endpoint: None,
        certificate_expires_at: None,
        checks: Vec::new(),
        repair_performed: false,
    };

    let loaded = crate::enrollment::load_latest_config();
    #[allow(unused_mut)]
    let (mut config_path, mut config) = match loaded {
        Ok(value) => {
            report
                .checks
                .push(ok("configuration", "active configuration loaded"));
            value
        }
        Err(error) => {
            report
                .checks
                .push(failed("configuration", format!("{error:#}")));
            write_bundle_if_requested(args.bundle.as_deref(), &report)?;
            print_report(&report);
            return Err(error.context("no usable CentralD client configuration"));
        }
    };
    populate_identity_summary(&mut report, &config_path, &config);

    if args.repair || args.restart_service {
        require_repair_privilege()?;
    }
    if args.repair {
        #[cfg(windows)]
        {
            bail!(
                "Windows client ACL repair is installer-owned; rerun the signed CentralD installer as Administrator instead of rescue --repair"
            );
        }
        #[cfg(not(windows))]
        {
            let was_running = client_service_running();
            stop_client_service()
                .context("stop CentralD client service before permission repair")?;
            let repair_result = crate::enrollment::repair_active_state_permissions()
                .context("repair client state ownership and permissions");
            let restore_result = if was_running {
                start_client_service().context("restore previously running CentralD client service")
            } else {
                Ok(())
            };
            let repaired = match (repair_result, restore_result) {
                (Ok(value), Ok(())) => value,
                (Err(repair), Ok(())) => return Err(repair),
                (Ok(_), Err(restore)) => return Err(restore),
                (Err(repair), Err(restore)) => {
                    return Err(
                        repair.context(format!("service restoration also failed: {restore:#}"))
                    );
                }
            };
            config_path = repaired.0;
            config = repaired.1;
            populate_identity_summary(&mut report, &config_path, &config);
            report.repair_performed = true;
            report.checks.push(ok(
                "repair",
                if was_running {
                    "state permissions were reapplied and the previously running client service was restored"
                } else {
                    "state permissions were reapplied while the client service remained stopped"
                },
            ));
        }
    }
    if args.restart_service {
        restart_client_service().context("restart CentralD client service")?;
        report
            .checks
            .push(ok("service restart", "client service restarted"));
    }

    report.checks.push(match config.validate() {
        Ok(()) => ok("configuration schema", "configuration values are valid"),
        Err(error) => failed("configuration schema", format!("{error:#}")),
    });
    for (name, path, private) in [
        (
            "identity certificate",
            config.identity_cert.as_path(),
            false,
        ),
        ("identity private key", config.identity_key.as_path(), true),
        ("root trust certificate", config.root_ca.as_path(), false),
        (
            "grant verification key",
            config.grant_signing_public_key.as_path(),
            false,
        ),
        ("active configuration file", config_path.as_path(), true),
    ] {
        report.checks.push(check_file(name, path, private));
    }
    report
        .checks
        .push(if config.certificate_expires_at > Utc::now() {
            ok(
                "certificate lifetime",
                format!("valid until {}", config.certificate_expires_at.to_rfc3339()),
            )
        } else {
            failed(
                "certificate lifetime",
                format!("expired at {}", config.certificate_expires_at.to_rfc3339()),
            )
        });

    if args.repair && !args.restart_service {
        report.checks.push(ok(
            "client service",
            "stopped after permission repair; run rescue --restart-service when ready",
        ));
    } else {
        report.checks.push(service_status());
    }
    report
        .checks
        .push(match crate::daemon::probe_connection(&config).await {
            Ok(()) => ok("server mTLS", "pinned TLS connection succeeded"),
            Err(error) => failed("server mTLS", format!("{error:#}")),
        });

    write_bundle_if_requested(args.bundle.as_deref(), &report)?;
    print_report(&report);
    if report.checks.iter().any(|check| !check.ok) {
        bail!("one or more CentralD client rescue checks failed");
    }
    Ok(())
}

#[allow(clippy::unnecessary_wraps)]
fn require_repair_privilege() -> Result<()> {
    #[cfg(target_os = "linux")]
    {
        let status =
            std::fs::read_to_string("/proc/self/status").context("read process identity")?;
        let effective_uid = status
            .lines()
            .find(|line| line.starts_with("Uid:"))
            .and_then(|line| line.split_whitespace().nth(2))
            .and_then(|value| value.parse::<u32>().ok())
            .context("determine effective UID")?;
        if effective_uid != 0 {
            bail!("centrald-client rescue --repair must run as root");
        }
    }
    Ok(())
}

#[allow(dead_code)]
fn client_service_running() -> bool {
    #[cfg(target_os = "linux")]
    {
        return Command::new("/usr/bin/systemctl")
            .args(["is-active", "--quiet", "centrald-client.service"])
            .status()
            .is_ok_and(|status| status.success());
    }
    #[cfg(not(target_os = "linux"))]
    false
}

#[allow(dead_code, clippy::unnecessary_wraps)]
fn start_client_service() -> Result<()> {
    #[cfg(target_os = "linux")]
    {
        run_checked(Command::new("/usr/bin/systemctl").args(["start", "centrald-client.service"]))?;
        Ok(())
    }
    #[cfg(not(target_os = "linux"))]
    Ok(())
}

#[allow(dead_code)]
fn stop_client_service() -> Result<()> {
    #[cfg(target_os = "linux")]
    {
        let output = Command::new("/usr/bin/systemctl")
            .args(["stop", "centrald-client.service"])
            .output()
            .context("stop centrald-client.service")?;
        if !output.status.success() {
            bail!(
                "could not stop centrald-client.service: {}",
                command_detail(&output)
            );
        }
        Ok(())
    }
    #[cfg(windows)]
    {
        let sc = windows_system_executable("sc.exe")
            .context("Windows did not return its trusted system directory")?;
        let query = Command::new(&sc)
            .args(["query", "CentralDClient"])
            .output()
            .context("query CentralDClient service")?;
        if !query.status.success() {
            bail!("CentralDClient service is not installed");
        }
        if !String::from_utf8_lossy(&query.stdout).contains("RUNNING") {
            return Ok(());
        }
        run_checked(Command::new(&sc).args(["stop", "CentralDClient"]))?;
        for _ in 0..120 {
            std::thread::sleep(std::time::Duration::from_millis(250));
            let current = Command::new(&sc)
                .args(["query", "CentralDClient"])
                .output()
                .context("wait for CentralDClient service to stop")?;
            if String::from_utf8_lossy(&current.stdout).contains("STOPPED") {
                return Ok(());
            }
        }
        bail!("timed out waiting for CentralDClient to stop");
    }
    #[cfg(not(any(target_os = "linux", windows)))]
    {
        bail!("client service control is unsupported on this operating system")
    }
}

/// Restarts the installed client service using a fixed platform command.
///
/// # Errors
///
/// Returns an error when the service manager is unavailable or rejects the
/// restart request.
pub fn restart_client_service() -> Result<()> {
    #[cfg(target_os = "linux")]
    {
        run_checked(
            Command::new("/usr/bin/systemctl").args(["restart", "centrald-client.service"]),
        )?;
        Ok(())
    }
    #[cfg(windows)]
    {
        let sc = windows_system_executable("sc.exe")
            .context("Windows did not return its trusted system directory")?;
        let query = Command::new(&sc)
            .args(["query", "CentralDClient"])
            .output()
            .context("query CentralDClient service")?;
        if !query.status.success() {
            bail!("CentralDClient service is not installed");
        }
        let status = String::from_utf8_lossy(&query.stdout);
        if status.contains("RUNNING") {
            run_checked(Command::new(&sc).args(["stop", "CentralDClient"]))?;
            let mut stopped = false;
            for _ in 0..120 {
                std::thread::sleep(std::time::Duration::from_millis(250));
                let current = Command::new(&sc)
                    .args(["query", "CentralDClient"])
                    .output()
                    .context("wait for CentralDClient service to stop")?;
                if String::from_utf8_lossy(&current.stdout).contains("STOPPED") {
                    stopped = true;
                    break;
                }
            }
            if !stopped {
                bail!("timed out waiting for CentralDClient to stop");
            }
        }
        run_checked(Command::new(&sc).args(["start", "CentralDClient"]))?;
        Ok(())
    }
    #[cfg(not(any(target_os = "linux", windows)))]
    {
        bail!("client service control is unsupported on this operating system")
    }
}

fn populate_identity_summary(report: &mut RescueReport, path: &Path, config: &ClientConfig) {
    report.config_path = Some(path.to_path_buf());
    report.identity_id = Some(config.identity_id.to_string());
    report.server_name = Some(config.server_name.clone());
    report.endpoint = Some(config.endpoint.clone());
    report.certificate_expires_at = Some(config.certificate_expires_at.to_rfc3339());
}

fn check_file(name: &'static str, path: &Path, private: bool) -> RescueCheck {
    #[cfg(not(unix))]
    let _ = private;
    let metadata = match path.symlink_metadata() {
        Ok(metadata) => metadata,
        Err(error) => return failed(name, format!("{}: {error}", path.display())),
    };
    if metadata.file_type().is_symlink() || !metadata.is_file() {
        return failed(name, format!("{} is not a regular file", path.display()));
    }
    #[cfg(unix)]
    if private {
        use std::os::unix::fs::PermissionsExt;
        if metadata.permissions().mode() & 0o077 != 0 {
            return failed(
                name,
                format!("{} is accessible outside its owner", path.display()),
            );
        }
    }
    ok(name, path.display().to_string())
}

fn service_status() -> RescueCheck {
    #[cfg(target_os = "linux")]
    {
        return match Command::new("/usr/bin/systemctl")
            .args(["is-active", "centrald-client.service"])
            .output()
        {
            Ok(output) if output.status.success() => ok("client service", "active"),
            Ok(output) => failed("client service", command_detail(&output)),
            Err(error) => failed("client service", error.to_string()),
        };
    }
    #[cfg(windows)]
    {
        let Some(sc) = windows_system_executable("sc.exe") else {
            return failed("client service", "Windows system directory is unavailable");
        };
        let query = match Command::new(&sc).args(["query", "CentralDClient"]).output() {
            Ok(output) if output.status.success() => output,
            Ok(output) => return failed("client service", command_detail(&output)),
            Err(error) => return failed("client service", error.to_string()),
        };
        let account = match Command::new(&sc).args(["qc", "CentralDClient"]).output() {
            Ok(output) if output.status.success() => output,
            Ok(output) => return failed("client service identity", command_detail(&output)),
            Err(error) => return failed("client service identity", error.to_string()),
        };
        let account_text = String::from_utf8_lossy(&account.stdout).to_ascii_uppercase();
        if !account_text.contains(r"NT SERVICE\CENTRALDCLIENT") {
            return failed(
                "client service identity",
                "service is not configured for NT SERVICE\\CentralDClient",
            );
        }
        if String::from_utf8_lossy(&query.stdout).contains("RUNNING") {
            ok("client service", "running under NT SERVICE\\CentralDClient")
        } else {
            failed(
                "client service",
                "installed with the correct identity but not running",
            )
        }
    }
    #[cfg(not(any(target_os = "linux", windows)))]
    {
        failed("client service", "unsupported operating system")
    }
}

fn write_bundle_if_requested(path: Option<&Path>, report: &RescueReport) -> Result<()> {
    let Some(path) = path else {
        return Ok(());
    };
    let bytes = serde_json::to_vec_pretty(report).context("serialize rescue report")?;
    write_new_file(path, &bytes, true)
        .with_context(|| format!("write diagnostic bundle {}", path.display()))?;
    println!("redacted diagnostic bundle: {}", path.display());
    Ok(())
}

fn print_report(report: &RescueReport) {
    println!("CentralD client rescue report");
    for check in &report.checks {
        println!(
            "  [{}] {}: {}",
            if check.ok { "ok" } else { "failed" },
            check.name,
            check.detail
        );
    }
}

fn ok(name: &'static str, detail: impl Into<String>) -> RescueCheck {
    RescueCheck {
        name,
        ok: true,
        detail: detail.into(),
    }
}

fn failed(name: &'static str, detail: impl Into<String>) -> RescueCheck {
    RescueCheck {
        name,
        ok: false,
        detail: detail.into(),
    }
}

fn run_checked(command: &mut Command) -> Result<()> {
    let output = command.output().context("run service manager")?;
    if !output.status.success() {
        bail!("service manager failed: {}", command_detail(&output));
    }
    Ok(())
}

fn command_detail(output: &Output) -> String {
    let stderr = String::from_utf8_lossy(&output.stderr).trim().to_owned();
    let stdout = String::from_utf8_lossy(&output.stdout).trim().to_owned();
    if !stderr.is_empty() {
        stderr
    } else if !stdout.is_empty() {
        stdout
    } else {
        format!("exit status {}", output.status)
    }
}
