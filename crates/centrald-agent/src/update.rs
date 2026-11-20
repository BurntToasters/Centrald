//! `centrald-agent update`: replace this binary with the build the enrolled
//! server offers, fetched over the pinned connection and checked by SHA-256.

use std::io::Write;
use std::path::{Path, PathBuf};
use std::process::Command;

use anyhow::{Context, Result, anyhow, bail};
use sha2::{Digest, Sha256};

use crate::config::AgentConfig;
use crate::net;

/// Larger than any real agent build; bounds memory if a server misbehaves.
const MAX_BINARY_BYTES: usize = 64 * 1024 * 1024;

pub fn run() -> Result<()> {
    let config = AgentConfig::load()?
        .ok_or_else(|| anyhow!("not enrolled; run `centrald-agent enroll` first"))?;
    let exe = std::env::current_exe().context("cannot find this program's path")?;
    if exe.starts_with("/usr/bin") {
        bail!(
            "this agent was installed by your package manager; update it with apt, dnf, or pacman instead"
        );
    }
    let fingerprint = config.fingerprint()?;
    let path = format!(
        "/download/agent/{}/{}",
        std::env::consts::OS,
        std::env::consts::ARCH
    );

    let binary = crate::runtime()?.block_on(async {
        let mut last_error = anyhow!("no server address is configured");
        for server in &config.servers {
            match download(server, fingerprint, &path).await {
                Ok(binary) => return Ok(binary),
                Err(error) => last_error = error.context(format!("from {server}")),
            }
        }
        Err(last_error)
    })?;

    let current = std::fs::read(&exe).with_context(|| format!("cannot read {}", exe.display()))?;
    if Sha256::digest(&current) == Sha256::digest(&binary) {
        println!("Already up to date (version {}).", centrald_proto::VERSION);
        return Ok(());
    }

    let staged = stage(&exe, &binary)?;
    let version = match check_version(&staged) {
        Ok(version) => version,
        Err(error) => {
            let _ = std::fs::remove_file(&staged);
            return Err(error);
        }
    };
    install(&exe, &staged)?;
    println!(
        "Updated the agent from {} to {}.",
        centrald_proto::VERSION,
        version
    );
    restart();
    Ok(())
}

/// Fetches the build and its published checksum; both must agree.
async fn download(server: &str, fingerprint: [u8; 32], path: &str) -> Result<Vec<u8>> {
    let (status, binary) = net::get(server, fingerprint, path, MAX_BINARY_BYTES).await?;
    if status == 404 {
        bail!(
            "the server has no {} {} agent build",
            std::env::consts::OS,
            std::env::consts::ARCH
        );
    }
    if status != 200 {
        bail!("download failed: {}", net::error_message(&binary));
    }
    let (status, expected) = net::get(server, fingerprint, &format!("{path}.sha256"), 128).await?;
    if status != 200 {
        bail!(
            "cannot fetch the checksum: {}",
            net::error_message(&expected)
        );
    }
    let expected = String::from_utf8_lossy(&expected)
        .trim()
        .to_ascii_lowercase();
    if hex::encode(Sha256::digest(&binary)) != expected {
        bail!("the downloaded agent does not match its checksum; nothing was changed");
    }
    Ok(binary)
}

/// Writes the new build next to the current one so the final rename is atomic.
fn stage(exe: &Path, binary: &[u8]) -> Result<PathBuf> {
    let dir = exe
        .parent()
        .ok_or_else(|| anyhow!("unexpected program path"))?;
    let staged = dir.join(format!(
        ".centrald-agent-update-{}{}",
        std::process::id(),
        std::env::consts::EXE_SUFFIX
    ));
    let write = || -> Result<()> {
        let mut options = std::fs::OpenOptions::new();
        options.write(true).create_new(true);
        #[cfg(unix)]
        std::os::unix::fs::OpenOptionsExt::mode(&mut options, 0o755);
        let mut file = options
            .open(&staged)
            .with_context(|| format!("cannot write {}", staged.display()))?;
        file.write_all(binary)?;
        file.sync_all()?;
        Ok(())
    };
    if let Err(error) = write() {
        let _ = std::fs::remove_file(&staged);
        return Err(error);
    }
    Ok(staged)
}

/// Runs the new build once; it must identify itself as `centrald-agent`.
fn check_version(staged: &Path) -> Result<String> {
    let output = Command::new(staged)
        .arg("--version")
        .output()
        .context("the downloaded agent does not run on this machine; nothing was changed")?;
    let text = String::from_utf8_lossy(&output.stdout);
    match text.trim().strip_prefix("centrald-agent ") {
        Some(version) if output.status.success() && !version.is_empty() => Ok(version.to_owned()),
        _ => bail!("the downloaded file is not a CentralD agent; nothing was changed"),
    }
}

#[cfg(unix)]
fn install(exe: &Path, staged: &Path) -> Result<()> {
    std::fs::rename(staged, exe).map_err(|error| {
        let _ = std::fs::remove_file(staged);
        anyhow!("cannot replace {}: {error}", exe.display())
    })
}

/// Windows cannot overwrite a running program, but it can rename it.
#[cfg(windows)]
fn install(exe: &Path, staged: &Path) -> Result<()> {
    let old = exe.with_extension("old.exe");
    let _ = std::fs::remove_file(&old);
    std::fs::rename(exe, &old)
        .with_context(|| format!("cannot move the running agent aside ({})", exe.display()))?;
    if let Err(error) = std::fs::rename(staged, exe) {
        let _ = std::fs::rename(&old, exe);
        let _ = std::fs::remove_file(staged);
        bail!("cannot install the new agent: {error}");
    }
    Ok(())
}

#[cfg(unix)]
fn restart() {
    if std::env::var_os("CENTRALD_SKIP_SERVICE").is_some() || !crate::service::is_running() {
        println!("Restart the agent to start using the new version.");
        return;
    }
    // Delay the restart so a command running this update can report back.
    let delayed = ["/usr/bin/systemd-run", "/bin/systemd-run"]
        .into_iter()
        .find(|path| Path::new(path).exists())
        .and_then(|systemd_run| {
            let systemctl = crate::service::systemctl()?;
            Command::new(systemd_run)
                .args([
                    "--quiet",
                    "--on-active=5",
                    "--timer-property=AccuracySec=1s",
                ])
                .arg(systemctl)
                .args(["restart", "centrald-agent.service"])
                .status()
                .ok()
                .filter(std::process::ExitStatus::success)
        });
    if delayed.is_some() {
        println!("The agent service restarts in 5 seconds.");
    } else if crate::service::restart_now().is_ok() {
        println!("Restarted the agent service.");
    } else {
        println!(
            "Restart the agent to start using the new version: sudo systemctl restart centrald-agent"
        );
    }
}

#[cfg(windows)]
fn restart() {
    println!(
        "Restart the agent to start using the new version: Restart-Service CentralDAgent (or reboot)."
    );
}
