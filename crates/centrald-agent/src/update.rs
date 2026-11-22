//! `centrald-agent update`: replace this binary with the build the enrolled
//! server offers, fetched over the pinned connection.
//!
//! The server is not trusted to choose the code: the build must carry a
//! Minisign signature from the release key, signed for this platform and a
//! newer version, before it is written to disk. Nothing downloaded is run.

use std::io::Write;
use std::path::{Path, PathBuf};
#[cfg(unix)]
use std::process::Command;

use anyhow::{Context, Result, anyhow, bail};
use sha2::{Digest, Sha256};

use crate::config::AgentConfig;
use crate::net;

/// Larger than any real agent build; bounds memory if a server misbehaves.
const MAX_BINARY_BYTES: usize = 64 * 1024 * 1024;
const MAX_SIGNATURE_BYTES: usize = 4096;
/// The release signing key, the one `SHA256SUMS` is signed with.
const RELEASE_KEY_JSON: &str = include_str!("../../../packaging/minisign.json");
/// Development builds (E2E) may trust another key; release builds never set
/// this.
const DEV_KEY: Option<&str> = option_env!("CENTRALD_UPDATE_PUBKEY");

/// What a valid signature says about the build.
#[derive(Debug, PartialEq, Eq)]
struct Signed {
    version: semver::Version,
    target: String,
}

/// `linux-x86_64`, `windows-aarch64`, ...: the name in the trusted comment.
fn this_target() -> String {
    format!("{}-{}", std::env::consts::OS, std::env::consts::ARCH)
}

fn public_key() -> Result<minisign_verify::PublicKey> {
    let encoded = if let Some(key) = DEV_KEY.filter(|key| !key.is_empty()) {
        key.to_owned()
    } else {
        let json: serde_json::Value = serde_json::from_str(RELEASE_KEY_JSON)?;
        json.get("publicKey")
            .and_then(serde_json::Value::as_str)
            .ok_or_else(|| anyhow!("the built-in release key is missing"))?
            .to_owned()
    };
    minisign_verify::PublicKey::from_base64(&encoded)
        .map_err(|e| anyhow!("the built-in update key is invalid: {e}"))
}

/// Verifies the signature over `binary` and reads its trusted comment,
/// `centrald-agent <version> <target>`.
fn verify(binary: &[u8], signature: &str) -> Result<Signed> {
    let signature = minisign_verify::Signature::decode(signature)
        .map_err(|_| anyhow!("the build's signature is malformed; nothing was changed"))?;
    public_key()?
        .verify(binary, &signature, false)
        .map_err(|_| {
            anyhow!(
                "the build's signature is not from the CentralD release key; nothing was changed"
            )
        })?;
    let comment = signature.trusted_comment();
    let mut words = comment.split(' ');
    let (Some("centrald-agent"), Some(version), Some(target), None) =
        (words.next(), words.next(), words.next(), words.next())
    else {
        bail!("the build's signature does not describe an agent build; nothing was changed");
    };
    let version = semver::Version::parse(version)
        .map_err(|_| anyhow!("the build's signature has no valid version; nothing was changed"))?;
    Ok(Signed {
        version,
        target: target.to_owned(),
    })
}

pub fn run(allow_downgrade: bool) -> Result<()> {
    let config = AgentConfig::load()?
        .ok_or_else(|| anyhow!("not enrolled; run `centrald-agent enroll` first"))?;
    let exe = std::env::current_exe().context("cannot find this program's path")?;
    if exe.starts_with("/usr/bin") {
        bail!(
            "this agent was installed by your package manager; update it with apt, dnf, or pacman instead"
        );
    }
    if DEV_KEY.is_some_and(|key| !key.is_empty()) {
        println!("Note: this is a development build that trusts a development update key.");
    }
    let fingerprint = config.fingerprint()?;
    let path = format!(
        "/download/agent/{}/{}",
        std::env::consts::OS,
        std::env::consts::ARCH
    );

    let (binary, signature) = crate::runtime()?.block_on(async {
        let mut last_error = anyhow!("no server address is configured");
        for server in &config.servers {
            match download(server, fingerprint, &path).await {
                Ok(found) => return Ok(found),
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

    // Everything is checked before a single byte is written.
    let signed = verify(&binary, &signature)?;
    let target = this_target();
    if signed.target != target {
        bail!(
            "the build is signed for {}, not {target}; nothing was changed",
            signed.target
        );
    }
    let running = semver::Version::parse(centrald_proto::VERSION)?;
    if signed.version <= running && !allow_downgrade {
        bail!(
            "the server offers version {}, which is not newer than {running}; nothing was changed (pass --allow-downgrade to install it anyway)",
            signed.version
        );
    }

    let staged = stage(&exe, &binary)?;
    install(&exe, &staged)?;
    println!(
        "Updated the agent from {} to {}.",
        centrald_proto::VERSION,
        signed.version
    );
    restart();
    Ok(())
}

/// Fetches the build and its detached signature.
async fn download(server: &str, fingerprint: [u8; 32], path: &str) -> Result<(Vec<u8>, String)> {
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
    let (status, signature) = net::get(
        server,
        fingerprint,
        &format!("{path}.minisig"),
        MAX_SIGNATURE_BYTES,
    )
    .await?;
    if status != 200 {
        bail!(
            "the server offers no signature for its agent build; nothing was changed ({})",
            net::error_message(&signature)
        );
    }
    let signature = String::from_utf8(signature)
        .map_err(|_| anyhow!("the build's signature is malformed; nothing was changed"))?;
    Ok((binary, signature))
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
