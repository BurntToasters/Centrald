//! Host firewall setup for packaged Ubuntu Server installs.
//!
//! Homelab first-run opens the unique non-loopback listener ports with UFW and
//! enables the firewall after SSH is allowed, using only fixed executable paths
//! and argument lists. PostgreSQL stays bound to localhost and is never opened.

use std::collections::BTreeSet;
use std::net::{IpAddr, SocketAddr};
#[cfg(unix)]
use std::path::Path;
#[cfg(unix)]
use std::process::Command;

use anyhow::{Context, Result, bail};
use centrald_common::config::ServerConfig;
use console::style;

const TIMEOUT: &str = "/usr/bin/timeout";
const UFW: &str = "/usr/sbin/ufw";
const SAFE_PATH: &str = "/usr/sbin:/usr/bin:/sbin:/bin";
const MAX_DIAGNOSTIC_BYTES: usize = 4096;
const SKIP_FIREWALL_ENV: &str = "CENTRALD_SKIP_FIREWALL";
const SKIP_ENABLE_ENV: &str = "CENTRALD_SKIP_FIREWALL_ENABLE";

/// One UFW allow rule derived from a persisted listener.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ListenRule {
    pub port: u16,
    pub comment: &'static str,
}

/// Outcome of applying or skipping host firewall rules.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum FirewallApplyReport {
    /// No host firewall mutation was attempted.
    Skipped { reason: String },
    /// Rules were installed. Enable may still have been skipped in automation.
    Applied {
        ports: Vec<u16>,
        ssh_ensured: bool,
        enabled: bool,
        already_active: bool,
        enable_skipped: bool,
    },
    /// Setup/config already committed; the operator must finish firewall work.
    Failed { detail: String },
}

impl FirewallApplyReport {
    /// Prints the firewall section used after setup, network changes, and refresh.
    pub fn print(&self) {
        println!("{}", style("Firewall:").cyan().bold());
        for line in self.operator_lines() {
            println!("  {line}");
        }
    }

    /// Operator-facing lines without a section header.
    #[must_use]
    pub fn operator_lines(&self) -> Vec<String> {
        match self {
            Self::Skipped { reason } => vec![reason.clone()],
            Self::Applied {
                ports,
                ssh_ensured,
                enabled,
                already_active,
                enable_skipped,
            } => {
                let mut lines = vec![format!(
                    "Allowed inbound TCP {}{}.",
                    format_ports(ports),
                    if *ssh_ensured { " and SSH" } else { "" }
                )];
                if *enabled {
                    if *already_active {
                        lines.push(
                            "UFW was already active; existing rules were kept and CentralD ports were refreshed."
                                .into(),
                        );
                    } else {
                        lines.push(
                            "UFW is now active with Ubuntu's default deny-incoming policy. Other host services need their own allow rules."
                                .into(),
                        );
                    }
                } else if *enable_skipped {
                    lines.push(
                        "UFW was left inactive because CI or CENTRALD_SKIP_FIREWALL_ENABLE is set."
                            .into(),
                    );
                    lines.push(
                        "Enable later with: sudo ufw --force enable (SSH is already allowed)."
                            .into(),
                    );
                }
                lines.push(
                    "Hypervisor or cloud security groups are separate and still need the same TCP ports."
                        .into(),
                );
                lines
            }
            Self::Failed { detail } => vec![
                format!("Could not configure UFW: {detail}"),
                "Allow inbound TCP for the enrollment, client, and Admin listeners plus SSH, then: sudo ufw --force enable".into(),
            ],
        }
    }
}

/// Derives unique non-loopback TCP allow rules from the persisted listeners.
#[must_use]
pub fn public_listen_rules(config: &ServerConfig) -> Vec<ListenRule> {
    unique_public_tcp_rules(&[
        (config.server.enrollment_listen, "CentralD-enrollment"),
        (config.server.client_listen, "CentralD-client"),
        (config.server.admin_listen, "CentralD-admin"),
    ])
}

/// Keeps the first comment for each unique non-loopback TCP port.
#[must_use]
pub fn unique_public_tcp_rules(listeners: &[(SocketAddr, &'static str)]) -> Vec<ListenRule> {
    let mut seen = BTreeSet::new();
    let mut rules = Vec::new();
    for (address, comment) in listeners {
        debug_assert!(
            is_safe_ufw_comment(comment),
            "UFW comments must be a single [A-Za-z0-9-] token"
        );
        if listen_is_loopback(*address) || address.port() == 0 {
            continue;
        }
        if seen.insert(address.port()) {
            rules.push(ListenRule {
                port: address.port(),
                comment,
            });
        }
    }
    rules
}

/// Opens the server's LAN listeners in UFW and enables the firewall when safe.
///
/// Never returns a hard error: setup and network saves have already committed.
/// Failures become an operator-facing report with the recovery command.
#[must_use]
pub fn apply_for_server(config: &ServerConfig) -> FirewallApplyReport {
    apply_rules(&public_listen_rules(config))
}

/// Read-only UFW status for Health.
#[must_use]
pub fn describe_status(config: &ServerConfig) -> String {
    let rules = public_listen_rules(config);
    if rules.is_empty() {
        return "Firewall: all CentralD listeners are loopback-only; no LAN UFW rules are required."
            .into();
    }
    #[cfg(not(unix))]
    {
        return "Firewall: host firewall setup is supported on Ubuntu Server.".into();
    }
    #[cfg(unix)]
    describe_status_unix(&rules)
}

fn apply_rules(rules: &[ListenRule]) -> FirewallApplyReport {
    if std::env::var_os(SKIP_FIREWALL_ENV).is_some() {
        let reason = if rules.is_empty() {
            format!("Host firewall unchanged ({SKIP_FIREWALL_ENV}).")
        } else {
            format!(
                "Host firewall unchanged ({SKIP_FIREWALL_ENV}). Allow inbound TCP {} and SSH before clients connect.",
                format_ports(&ports_only(rules))
            )
        };
        return FirewallApplyReport::Skipped { reason };
    }
    #[cfg(not(unix))]
    {
        let _ = rules;
        return FirewallApplyReport::Skipped {
            reason: "Host firewall setup is supported on Ubuntu Server.".into(),
        };
    }
    #[cfg(unix)]
    apply_unix(rules)
}

#[cfg(unix)]
fn apply_unix(rules: &[ListenRule]) -> FirewallApplyReport {
    if !is_effective_root() {
        return FirewallApplyReport::Skipped {
            reason: "Host firewall unchanged; UFW setup requires root.".into(),
        };
    }
    if let Err(error) = ensure_tools() {
        return FirewallApplyReport::Skipped {
            reason: error.to_string(),
        };
    }
    if rules.is_empty() {
        return FirewallApplyReport::Skipped {
            reason:
                "All CentralD listeners are loopback-only; UFW was not changed and was not enabled."
                    .into(),
        };
    }

    match apply_unix_inner(rules) {
        Ok(report) => report,
        Err(error) => FirewallApplyReport::Failed {
            detail: format!("{error:#}"),
        },
    }
}

#[cfg(unix)]
fn apply_unix_inner(rules: &[ListenRule]) -> Result<FirewallApplyReport> {
    let already_active = ufw_is_active()?;
    let ssh_ensured = ensure_ssh(already_active)?;
    for rule in rules {
        allow_tcp_port(rule.port, rule.comment)?;
    }
    let enable_skipped = !should_enable_ufw();
    let enabled = if already_active {
        run_ufw(&["reload"], 30).context("reload UFW after adding CentralD rules")?;
        true
    } else if enable_skipped {
        false
    } else {
        run_ufw(&["--force", "enable"], 45)
            .context("enable UFW after allowing SSH and CentralD")?;
        true
    };
    Ok(FirewallApplyReport::Applied {
        ports: ports_only(rules),
        ssh_ensured,
        enabled,
        already_active,
        enable_skipped: enable_skipped && !already_active,
    })
}

#[cfg(unix)]
fn describe_status_unix(rules: &[ListenRule]) -> String {
    if !is_effective_root() {
        return "Firewall: UFW status requires root.".into();
    }
    if ensure_tools().is_err() {
        return "Firewall: /usr/sbin/ufw is not installed; LAN clients need the enrollment, client, and Admin TCP ports reachable.".into();
    }
    match ufw_status_text() {
        Err(error) => format!("Firewall: could not read UFW status ({error:#})."),
        Ok(text) => match parse_ufw_active(&text) {
            None => "Firewall: could not parse UFW status.".into(),
            Some(false) => {
                "Firewall: ufw is installed but inactive. initial-setup normally enables it for the CentralD TCP ports and SSH. Hypervisor or cloud security groups are separate.".into()
            }
            Some(true) => {
                let missing: Vec<u16> = rules
                    .iter()
                    .map(|rule| rule.port)
                    .filter(|port| !status_allows_tcp(&text, *port))
                    .collect();
                if missing.is_empty() {
                    format!(
                        "Firewall: ufw is active and allows inbound TCP {}.",
                        format_ports(&ports_only(rules))
                    )
                } else {
                    format!(
                        "Firewall: ufw is active but missing TCP {}. Use Refresh host firewall (UFW).",
                        format_ports(&missing)
                    )
                }
            }
        },
    }
}

#[cfg(unix)]
fn ensure_ssh(already_active: bool) -> Result<bool> {
    if run_ufw(&["allow", "OpenSSH"], 30).is_ok() {
        return Ok(true);
    }
    match run_ufw(&["allow", "22/tcp", "comment", "CentralD-ssh"], 30) {
        Ok(()) => Ok(true),
        Err(error) if already_active => {
            tracing::warn!(
                %error,
                "could not add an explicit SSH UFW rule on an already-active firewall; continuing with CentralD ports"
            );
            Ok(false)
        }
        Err(error) => Err(error).context(
            "allow SSH before enabling UFW (tried the OpenSSH profile, then 22/tcp); enabling would risk dropping remote access",
        ),
    }
}

#[cfg(unix)]
fn allow_tcp_port(port: u16, comment: &str) -> Result<()> {
    if !is_safe_ufw_comment(comment) {
        bail!("refusing an unsafe UFW comment token");
    }
    let spec = format!("{port}/tcp");
    run_ufw(&["allow", spec.as_str(), "comment", comment], 30)
        .with_context(|| format!("allow inbound TCP {port}"))
}

#[cfg(unix)]
fn ufw_is_active() -> Result<bool> {
    let text = ufw_status_text()?;
    parse_ufw_active(&text).context("parse UFW status")
}

#[cfg(unix)]
fn ufw_status_text() -> Result<String> {
    let output = ufw_output(&["status"], 30).context("query UFW status")?;
    let combined = combined_output(&output);
    if !output.status.success() {
        bail!(
            "ufw status failed{}",
            diagnostic_suffix(&bounded_diagnostic(combined.as_bytes()))
        );
    }
    Ok(combined)
}

fn parse_ufw_active(status: &str) -> Option<bool> {
    for line in status.lines() {
        let line = line.trim();
        if let Some(rest) = line.strip_prefix("Status:") {
            let value = rest.trim();
            if value.eq_ignore_ascii_case("inactive") {
                return Some(false);
            }
            if value.to_ascii_lowercase().starts_with("active") {
                return Some(true);
            }
        }
    }
    None
}

fn status_allows_tcp(status: &str, port: u16) -> bool {
    let needle = format!("{port}/tcp");
    status.lines().any(|line| {
        let line = line.trim();
        line.starts_with(&needle)
            && line.to_ascii_uppercase().contains("ALLOW")
            && !line.to_ascii_lowercase().contains("deny")
    })
}

fn should_enable_ufw() -> bool {
    std::env::var_os(SKIP_ENABLE_ENV).is_none() && std::env::var_os("CI").is_none()
}

fn listen_is_loopback(address: SocketAddr) -> bool {
    match address.ip() {
        IpAddr::V4(v4) => v4.is_loopback(),
        IpAddr::V6(v6) => {
            v6.is_loopback() || v6.to_ipv4_mapped().is_some_and(|v4| v4.is_loopback())
        }
    }
}

fn is_safe_ufw_comment(comment: &str) -> bool {
    !comment.is_empty()
        && comment.len() <= 32
        && comment
            .chars()
            .all(|character| character.is_ascii_alphanumeric() || character == '-')
}

fn format_ports(ports: &[u16]) -> String {
    ports
        .iter()
        .map(ToString::to_string)
        .collect::<Vec<_>>()
        .join(", ")
}

fn ports_only(rules: &[ListenRule]) -> Vec<u16> {
    rules.iter().map(|rule| rule.port).collect()
}

#[cfg(unix)]
fn ensure_tools() -> Result<()> {
    if !Path::new(TIMEOUT).is_file() {
        bail!("Host firewall unchanged; {TIMEOUT} is missing.");
    }
    if !Path::new(UFW).is_file() {
        bail!(
            "Host firewall unchanged; UFW is not installed. Install it with: sudo apt install ufw"
        );
    }
    Ok(())
}

#[cfg(unix)]
fn is_effective_root() -> bool {
    let Ok(status) = std::fs::read_to_string("/proc/self/status") else {
        return false;
    };
    status
        .lines()
        .find_map(|line| line.strip_prefix("Uid:"))
        .and_then(|ids| ids.split_whitespace().nth(1))
        .and_then(|id| id.parse::<u32>().ok())
        == Some(0)
}

#[cfg(unix)]
fn run_ufw(args: &[&str], seconds: u8) -> Result<()> {
    let output = ufw_output(args, seconds)?;
    if output.status.success() {
        return Ok(());
    }
    let detail = bounded_diagnostic(combined_output(&output).as_bytes());
    bail!(
        "ufw {} failed{}",
        args.join(" "),
        diagnostic_suffix(&detail)
    )
}

#[cfg(unix)]
fn ufw_output(args: &[&str], seconds: u8) -> Result<std::process::Output> {
    let timeout = format!("{seconds}s");
    Command::new(TIMEOUT)
        .env_clear()
        .env("PATH", SAFE_PATH)
        .env("LANG", "C")
        .env("LC_ALL", "C")
        .args(["--signal=TERM", "--kill-after=5s", timeout.as_str(), UFW])
        .args(args)
        .output()
        .context("execute /usr/sbin/ufw")
}

fn combined_output(output: &std::process::Output) -> String {
    let mut text = String::from_utf8_lossy(&output.stdout).into_owned();
    if !output.stderr.is_empty() {
        if !text.is_empty() {
            text.push('\n');
        }
        text.push_str(&String::from_utf8_lossy(&output.stderr));
    }
    text
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

#[cfg(test)]
mod tests {
    use super::*;
    use std::net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr};

    fn addr(ip: IpAddr, port: u16) -> SocketAddr {
        SocketAddr::new(ip, port)
    }

    #[test]
    fn unique_rules_keep_non_loopback_ports_and_first_comment() {
        let rules = unique_public_tcp_rules(&[
            (
                addr(IpAddr::V4(Ipv4Addr::UNSPECIFIED), 7443),
                "CentralD-enrollment",
            ),
            (
                addr(IpAddr::V4(Ipv4Addr::UNSPECIFIED), 7444),
                "CentralD-client",
            ),
            (
                addr(IpAddr::V4(Ipv4Addr::UNSPECIFIED), 7445),
                "CentralD-admin",
            ),
            (addr(IpAddr::V4(Ipv4Addr::LOCALHOST), 7443), "ignored"),
        ]);
        assert_eq!(
            rules
                .iter()
                .map(|rule| (rule.port, rule.comment))
                .collect::<Vec<_>>(),
            vec![
                (7443, "CentralD-enrollment"),
                (7444, "CentralD-client"),
                (7445, "CentralD-admin"),
            ]
        );
    }

    #[test]
    fn loopback_v4_v6_and_mapped_addresses_are_skipped() {
        let mapped = match "::ffff:127.0.0.1".parse::<IpAddr>() {
            Ok(ip) => ip,
            Err(error) => {
                panic!("IPv4-mapped loopback should parse: {error}");
            }
        };
        assert!(listen_is_loopback(addr(mapped, 7445)));
        let listeners = [
            (
                addr(IpAddr::V4(Ipv4Addr::LOCALHOST), 7443),
                "CentralD-enrollment",
            ),
            (
                addr(IpAddr::V6(Ipv6Addr::LOCALHOST), 7444),
                "CentralD-client",
            ),
            (addr(mapped, 7445), "CentralD-admin"),
        ];
        assert!(unique_public_tcp_rules(&listeners).is_empty());
    }

    #[test]
    fn ipv6_unspecified_is_treated_as_lan_reachable() {
        let rules = unique_public_tcp_rules(&[(
            addr(IpAddr::V6(Ipv6Addr::UNSPECIFIED), 7443),
            "CentralD-enrollment",
        )]);
        assert_eq!(rules.first().map(|rule| rule.port), Some(7443));
    }

    #[test]
    fn status_parser_reads_active_and_inactive() {
        assert_eq!(parse_ufw_active("Status: inactive\n"), Some(false));
        assert_eq!(parse_ufw_active("Status: active\n"), Some(true));
        assert_eq!(
            parse_ufw_active("WARN\nStatus: active (disabled on system startup)\n"),
            Some(true)
        );
        assert_eq!(parse_ufw_active("garbage"), None);
    }

    #[test]
    fn status_allows_tcp_matches_ufw_listing() {
        let status = "\
Status: active

To                         Action      From
--                         ------      ----
22/tcp                     ALLOW       Anywhere
7443/tcp                   ALLOW       Anywhere                   # CentralD-enrollment
7444/tcp                   DENY        Anywhere
";
        assert!(status_allows_tcp(status, 7443));
        assert!(status_allows_tcp(status, 22));
        assert!(!status_allows_tcp(status, 7444));
        assert!(!status_allows_tcp(status, 7445));
    }

    #[test]
    fn ufw_comments_reject_spaces_and_shell_metacharacters() {
        assert!(is_safe_ufw_comment("CentralD-enrollment"));
        assert!(!is_safe_ufw_comment("CentralD enrollment"));
        assert!(!is_safe_ufw_comment("CentralD;rm"));
        assert!(!is_safe_ufw_comment(""));
    }

    #[test]
    fn skip_firewall_env_name_is_stable() {
        assert_eq!(SKIP_FIREWALL_ENV, "CENTRALD_SKIP_FIREWALL");
        assert_eq!(SKIP_ENABLE_ENV, "CENTRALD_SKIP_FIREWALL_ENABLE");
    }
}
