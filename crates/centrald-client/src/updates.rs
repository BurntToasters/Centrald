//! Broker-side release verification and installation for `UpdateClient` jobs.
//!
//! The broker downloads the server-approved release manifest, verifies the
//! channel, pinned version, protocol, artifact digest, and Minisign
//! signature, and then installs the package with the platform installer
//! (dpkg on Linux, the signed installer script on Windows). Downloads are
//! bounded; staging files live only under the root-owned broker state
//! directory and are removed after installation.

use std::io::{Read, Write};
use std::path::{Path, PathBuf};
#[cfg(windows)]
use std::time::Instant;

use anyhow::{Context, Result, bail};
use centrald_common::release::{
    Architecture, Component, OperatingSystem, PackageKind, ReleaseManifestV1,
};
use serde::Deserialize;
use sha2::{Digest, Sha256};
use url::Url;

use crate::broker::broker_state_dir;

const MAX_MANIFEST_BYTES: u64 = 1024 * 1024;
const MAX_SIGNATURE_BYTES: u64 = 4096;
/// Hard cap for a single artifact download regardless of manifest size.
const MAX_ARTIFACT_BYTES: u64 = 512 * 1024 * 1024;
const MANIFEST_TIMEOUT_SECONDS: u64 = 30;
const ARTIFACT_TIMEOUT_SECONDS: u64 = 600;
/// Bounds for ZIP extraction: entry count, per-entry size, and total wall time.
#[cfg(windows)]
const MAX_ZIP_ENTRIES: usize = 512;
#[cfg(windows)]
const MAX_ZIP_ENTRY_BYTES: u64 = 512 * 1024 * 1024;
#[cfg(windows)]
const EXTRACTION_TIMEOUT: std::time::Duration = std::time::Duration::from_secs(600);

/// Job parameters for an `UpdateClient` operation.
#[derive(Debug, Clone, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct UpdateParameters {
    pub manifest_url: String,
    pub channel: String,
    pub allow_prerelease: bool,
    pub expected_version: String,
}

impl UpdateParameters {
    /// Validates every parameter against the updater's invariants.
    ///
    /// # Errors
    ///
    /// Returns an error when a parameter is missing or malformed.
    pub fn validate(&self) -> Result<()> {
        let parsed = Url::parse(&self.manifest_url).context("manifest URL is invalid")?;
        if parsed.scheme() != "https"
            || parsed.host_str().is_none()
            || !parsed.username().is_empty()
            || parsed.password().is_some()
            || parsed.query().is_some()
            || parsed.fragment().is_some()
        {
            bail!("manifest URL must be HTTPS without credentials, a query, or a fragment");
        }
        if !valid_channel(&self.channel) {
            bail!("update channel is invalid");
        }
        if self.channel != centrald_common::build_info::RELEASE_CHANNEL {
            bail!(
                "this build follows the {} channel, not {}",
                centrald_common::build_info::RELEASE_CHANNEL,
                self.channel
            );
        }
        let _: semver::Version = self
            .expected_version
            .parse()
            .context("expected_version is not a valid semantic version")?;
        Ok(())
    }
}

/// Executes the operator-approved client update and returns a bounded text
/// summary.
///
/// # Errors
///
/// Returns an error at the first failed integrity or installation step.
pub fn update_client(parameters_json: &[u8], installed_version: &str) -> Result<Vec<u8>> {
    let parameters: UpdateParameters =
        serde_json::from_slice(parameters_json).context("decode update parameters")?;
    parameters.validate()?;
    let client = http_client()?;
    let manifest = fetch_verified_manifest(&client, &parameters, installed_version)?;
    let artifact = select_artifact(&manifest)?;

    let staging = staging_dir()?;
    let artifact_path = staging.join(&artifact.filename);
    let result = (|| -> Result<()> {
        download_exact(
            &client,
            &artifact.url,
            artifact.size,
            MAX_ARTIFACT_BYTES,
            &artifact_path,
            "release artifact",
        )?;
        verify_sha256(&artifact_path, &artifact.sha256)?;
        if let Some(signature_url) = &artifact.signature_url {
            let signature_bytes = download_bounded(
                &client,
                signature_url,
                MAX_SIGNATURE_BYTES,
                ARTIFACT_TIMEOUT_SECONDS,
                "release signature",
            )?;
            centrald_common::secure_fs::write_new_file(
                &staging.join(format!("{}.minisig", artifact.filename)),
                &signature_bytes,
                false,
            )
            .context("stage the release signature")?;
            verify_minisign(
                &artifact_path,
                &staging.join(format!("{}.minisig", artifact.filename)),
            )?;
        } else {
            bail!("release artifact has no Minisign signature");
        }
        install_artifact(&artifact_path, artifact.package)?;
        Ok(())
    })();
    let _ = std::fs::remove_dir_all(&staging);
    result?;
    let current_os = artifact.os;
    let current_arch = artifact.architecture;
    let summary = format!(
        "installed CentralD {} ({}) on {}/{}\nartifact: {}\nsha256: {}",
        manifest.version,
        manifest.channel,
        os_name(current_os),
        arch_name(current_arch),
        artifact.filename,
        artifact.sha256,
    );
    Ok(summary.into_bytes())
}

fn http_client() -> Result<reqwest::blocking::Client> {
    reqwest::blocking::Client::builder()
        .redirect(reqwest::redirect::Policy::custom(|attempt| {
            let next = attempt.url();
            if attempt.previous().len() >= 3 {
                return attempt.stop();
            }
            if next.scheme() != "https" {
                return attempt.stop();
            }
            attempt.follow()
        }))
        .build()
        .context("build the update HTTP client")
}

fn download_bounded(
    client: &reqwest::blocking::Client,
    url: &str,
    limit: u64,
    timeout_seconds: u64,
    label: &str,
) -> Result<Vec<u8>> {
    let response = client
        .get(url)
        .header(reqwest::header::ACCEPT_ENCODING, "identity")
        .timeout(std::time::Duration::from_secs(timeout_seconds))
        .send()
        .with_context(|| format!("download {label}"))?
        .error_for_status()
        .with_context(|| format!("download {label}"))?;
    if response
        .content_length()
        .is_some_and(|length| length > limit)
    {
        bail!("{label} exceeds the size limit");
    }
    if response
        .headers()
        .get(reqwest::header::CONTENT_ENCODING)
        .and_then(|value| value.to_str().ok())
        .is_some_and(|value| !value.eq_ignore_ascii_case("identity"))
    {
        bail!("{label} must not use content encoding");
    }
    let mut body = Vec::new();
    response
        .take(limit + 1)
        .read_to_end(&mut body)
        .with_context(|| format!("read {label}"))?;
    if u64::try_from(body.len()).unwrap_or(u64::MAX) > limit {
        bail!("{label} exceeds the size limit");
    }
    Ok(body)
}

/// Downloads and validates the release manifest against the approved update
/// parameters and the installed version. The manifest itself must carry a
/// Minisign signature (`<url>.minisig`) so a feed compromise cannot spoof
/// channel/version fields; artifact signatures remain the second gate.
#[allow(clippy::items_after_statements)]
fn fetch_verified_manifest(
    client: &reqwest::blocking::Client,
    parameters: &UpdateParameters,
    installed_version: &str,
) -> Result<ReleaseManifestV1> {
    let expected: semver::Version = parameters.expected_version.parse()?;
    let installed: semver::Version = installed_version.parse()?;
    let manifest_bytes = download_bounded(
        client,
        &parameters.manifest_url,
        MAX_MANIFEST_BYTES,
        MANIFEST_TIMEOUT_SECONDS,
        "release manifest",
    )?;
    let signature_url = format!("{}.minisig", parameters.manifest_url);
    let signature_bytes = download_bounded(
        client,
        &signature_url,
        MAX_SIGNATURE_BYTES,
        MANIFEST_TIMEOUT_SECONDS,
        "release manifest signature",
    )?;
    verify_minisign_bytes(&manifest_bytes, &signature_bytes)?;
    let manifest: ReleaseManifestV1 =
        serde_json::from_slice(&manifest_bytes).context("decode release manifest")?;
    manifest
        .validate()
        .map_err(|error| anyhow::anyhow!("{error}"))?;
    if manifest.channel != parameters.channel {
        bail!(
            "release feed channel {} does not match the approved channel {}",
            manifest.channel,
            parameters.channel
        );
    }
    if manifest.version != expected {
        bail!(
            "release feed version {} does not match the approved version {}",
            manifest.version,
            parameters.expected_version
        );
    }
    // Monotonicity uses semver precedence so build-metadata variants of the
    // same version cannot be relabeled as newer (or newer builds as older).
    use std::cmp::Ordering as CmpOrdering;
    if manifest.version.cmp_precedence(&installed) != CmpOrdering::Greater {
        bail!(
            "same-version byte replacement is forbidden; the installed version is {installed_version}"
        );
    }
    if manifest.protocol_major != centrald_protocol::PROTOCOL_MAJOR {
        bail!("release feed protocol major is incompatible with this client");
    }
    if !parameters.allow_prerelease && !manifest.version.pre.is_empty() {
        bail!("release feed returned a prerelease while prereleases are disabled");
    }
    Ok(manifest)
}

/// Selects the client package for the current platform from the manifest.
fn select_artifact(
    manifest: &ReleaseManifestV1,
) -> Result<&centrald_common::release::ReleaseArtifact> {
    let current_os = current_os();
    let current_arch = current_architecture();
    let package_kind = match current_os {
        OperatingSystem::Linux => PackageKind::Deb,
        OperatingSystem::Windows => PackageKind::Zip,
    };
    manifest
        .artifacts
        .iter()
        .find(|artifact| {
            artifact.component == Component::Client
                && artifact.os == current_os
                && artifact.architecture == current_arch
                && artifact.package == package_kind
        })
        .ok_or_else(|| {
            anyhow::anyhow!(
                "release manifest has no client package for {} {}",
                os_name(current_os),
                arch_name(current_arch)
            )
        })
}

fn download_exact(
    client: &reqwest::blocking::Client,
    url: &str,
    expected_size: u64,
    hard_limit: u64,
    destination: &Path,
    label: &str,
) -> Result<()> {
    if expected_size > hard_limit {
        bail!("{label} size exceeds the hard limit");
    }
    let mut response = client
        .get(url)
        .header(reqwest::header::ACCEPT_ENCODING, "identity")
        .timeout(std::time::Duration::from_secs(ARTIFACT_TIMEOUT_SECONDS))
        .send()
        .with_context(|| format!("download {label}"))?
        .error_for_status()
        .with_context(|| format!("download {label}"))?;
    if response
        .content_length()
        .is_some_and(|length| length > expected_size)
    {
        bail!("{label} is larger than the manifest size");
    }
    if response
        .headers()
        .get(reqwest::header::CONTENT_ENCODING)
        .and_then(|value| value.to_str().ok())
        .is_some_and(|value| !value.eq_ignore_ascii_case("identity"))
    {
        bail!("{label} must not use content encoding");
    }
    let mut file = open_staged_file(destination)
        .with_context(|| format!("stage {label} at {}", destination.display()))?;
    let mut written = 0_u64;
    let mut buffer = vec![0_u8; 64 * 1024];
    loop {
        let read = response
            .read(&mut buffer)
            .with_context(|| format!("read {label}"))?;
        if read == 0 {
            break;
        }
        written = written.saturating_add(u64::try_from(read).unwrap_or(u64::MAX));
        if written > expected_size {
            bail!("{label} exceeds the manifest size");
        }
        file.write_all(&buffer[..read])
            .with_context(|| format!("write {label}"))?;
    }
    if written != expected_size {
        bail!("{label} is {written} bytes but the manifest declares {expected_size}");
    }
    file.sync_all().with_context(|| format!("sync {label}"))?;
    Ok(())
}

/// Opens a new staging file with no-follow validation and owner-only access.
fn open_staged_file(path: &Path) -> Result<std::fs::File> {
    use std::fs::OpenOptions;

    centrald_common::secure_fs::validate_no_symlink_ancestors(path)
        .map_err(|error| anyhow::anyhow!("{error}"))?;
    let mut options = OpenOptions::new();
    options.write(true).create_new(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        options.mode(0o600);
    }
    options
        .open(path)
        .with_context(|| format!("create staging file {}", path.display()))
}

fn verify_sha256(path: &Path, expected: &str) -> Result<()> {
    let mut file = std::fs::File::open(path).with_context(|| format!("open {}", path.display()))?;
    let mut hasher = Sha256::new();
    let mut buffer = vec![0_u8; 64 * 1024];
    loop {
        let read = file.read(&mut buffer).context("read artifact for digest")?;
        if read == 0 {
            break;
        }
        hasher.update(&buffer[..read]);
    }
    let actual = hex::encode(hasher.finalize());
    if actual != expected {
        bail!("artifact SHA-256 mismatch: expected {expected}, got {actual}");
    }
    Ok(())
}

fn verify_minisign(artifact: &Path, signature: &Path) -> Result<()> {
    let artifact_bytes =
        std::fs::read(artifact).with_context(|| format!("read artifact {}", artifact.display()))?;
    let signature_text = std::fs::read_to_string(signature)
        .with_context(|| format!("read Minisign signature {}", signature.display()))?;
    verify_minisign_bytes(&artifact_bytes, signature_text.as_bytes())
}

/// Verifies in-memory bytes against a Minisign signature file using the
/// build-time public key.
fn verify_minisign_bytes(data: &[u8], signature_text: &[u8]) -> Result<()> {
    let key = centrald_common::build_info::MINISIGN_PUBLIC_KEY;
    if key.is_empty() {
        bail!("this client build has no Minisign public key; update verification is disabled");
    }
    let public_key =
        minisign::PublicKey::from_base64(key).context("parse the Minisign public key")?;
    let signature_text = String::from_utf8(signature_text.to_vec())
        .context("Minisign signature is not valid text")?;
    let signature_box = minisign::SignatureBox::from_string(&signature_text)
        .context("decode the Minisign signature")?;
    let mut cursor = std::io::Cursor::new(data);
    minisign::verify(&public_key, &signature_box, &mut cursor, true, false, false)
        .context("Minisign verification failed")?;
    Ok(())
}

fn install_artifact(artifact: &Path, package_kind: PackageKind) -> Result<()> {
    match package_kind {
        PackageKind::Deb => {
            #[cfg(target_os = "linux")]
            {
                let mut command = std::process::Command::new("/usr/bin/dpkg");
                command.args(["-i"]);
                command.arg(artifact);
                let output = crate::runners::run_bounded(&mut command)?;
                if !output.success {
                    bail!(
                        "dpkg rejected the package: {}",
                        String::from_utf8_lossy(&output.output)
                    );
                }
                return Ok(());
            }
            #[cfg(not(target_os = "linux"))]
            {
                let _ = artifact;
                bail!("deb packages are only installable on Linux")
            }
        }
        PackageKind::Zip => {
            #[cfg(windows)]
            {
                install_windows_zip(artifact)
            }
            #[cfg(not(windows))]
            {
                let _ = artifact;
                bail!("zip packages are only installable on Windows")
            }
        }
        _ => bail!("unsupported client package kind"),
    }
}

#[cfg(windows)]
fn install_windows_zip(artifact: &Path) -> Result<()> {
    use std::io::Read;

    let staging = staging_dir()?;
    let extract_dir = staging.join("extract");
    std::fs::create_dir_all(&extract_dir).context("create extract directory")?;
    let file =
        std::fs::File::open(artifact).with_context(|| format!("open {}", artifact.display()))?;
    let mut archive = zip::ZipArchive::new(file).context("open the client ZIP")?;
    if archive.len() > MAX_ZIP_ENTRIES {
        bail!("the client ZIP contains more than {MAX_ZIP_ENTRIES} entries");
    }
    let mut extracted_total = 0_u64;
    let extraction_started = Instant::now();
    for index in 0..archive.len() {
        if extraction_started.elapsed() > EXTRACTION_TIMEOUT {
            bail!("the client ZIP extraction exceeded the time bound");
        }
        let mut entry = archive
            .by_index(index)
            .with_context(|| format!("read ZIP entry {index}"))?;
        let name = entry.name().to_owned();
        let is_directory = entry.is_dir();
        let name = name.strip_suffix('/').unwrap_or(&name).to_owned();
        if !is_simple_entry_name(&name) {
            bail!("ZIP entry name is unsafe: {name}");
        }
        if is_directory {
            std::fs::create_dir_all(extract_dir.join(&name))
                .with_context(|| format!("create directory {name}"))?;
            continue;
        }
        if entry.size() > MAX_ZIP_ENTRY_BYTES {
            bail!("ZIP entry {name} exceeds the per-entry limit");
        }
        let target = extract_dir.join(&name);
        if !target.starts_with(&extract_dir) {
            bail!("ZIP entry {name} escapes the extract directory");
        }
        if let Some(parent) = target.parent() {
            std::fs::create_dir_all(parent)
                .with_context(|| format!("create directory for {name}"))?;
        }
        let mut output = open_staged_file(&target).with_context(|| format!("extract {name}"))?;
        let mut buffer = vec![0_u8; 64 * 1024];
        loop {
            let read = entry
                .read(&mut buffer)
                .with_context(|| format!("read {name}"))?;
            if read == 0 {
                break;
            }
            extracted_total =
                extracted_total.saturating_add(u64::try_from(read).unwrap_or(u64::MAX));
            if extracted_total > MAX_ARTIFACT_BYTES {
                bail!("the client ZIP expands beyond the hard limit");
            }
            output
                .write_all(&buffer[..read])
                .with_context(|| format!("write {name}"))?;
        }
    }
    let installer = extract_dir.join("install-client.ps1");
    if !installer.is_file() {
        bail!("the client ZIP does not contain install-client.ps1");
    }
    let powershell = centrald_common::config::windows_powershell_executable()
        .context("Windows did not return its trusted system directory")?;
    let mut command = std::process::Command::new(powershell);
    command
        .args([
            "-NoLogo",
            "-NoProfile",
            "-NonInteractive",
            "-ExecutionPolicy",
            "Bypass",
            "-File",
        ])
        .arg(&installer)
        .arg("-StartAfterInstall")
        .current_dir(&extract_dir);
    let output = crate::runners::run_bounded(&mut command)?;
    if !output.success {
        bail!(
            "the CentralD installer failed: {}",
            String::from_utf8_lossy(&output.output)
        );
    }
    Ok(())
}

#[cfg(any(windows, test))]
fn is_simple_entry_name(name: &str) -> bool {
    !name.is_empty()
        && name.len() <= 255
        && name != "."
        && name != ".."
        && !name.starts_with('/')
        && !name.starts_with('\\')
        && !name.contains('\0')
        && !name.contains(':')
        && !name.ends_with('.')
        && !name.ends_with(' ')
        && !name
            .split(['/', '\\'])
            .any(|part| matches!(part, "" | "." | ".."))
        && !is_windows_device_name(name)
}

/// Windows reserves these device names even with an extension; a file named
/// `CON` or `CON.txt` cannot be created normally and would resolve to a device.
#[cfg(any(windows, test))]
fn is_windows_device_name(name: &str) -> bool {
    let stem = name.split('.').next().unwrap_or("");
    let stem = stem.to_ascii_uppercase();
    stem == "CON"
        || stem == "PRN"
        || stem == "AUX"
        || stem == "NUL"
        || stem == "COM1"
        || stem == "COM2"
        || stem == "COM3"
        || stem == "COM4"
        || stem == "COM5"
        || stem == "COM6"
        || stem == "COM7"
        || stem == "COM8"
        || stem == "COM9"
        || stem == "LPT1"
        || stem == "LPT2"
        || stem == "LPT3"
        || stem == "LPT4"
        || stem == "LPT5"
        || stem == "LPT6"
        || stem == "LPT7"
        || stem == "LPT8"
        || stem == "LPT9"
}

fn staging_dir() -> Result<PathBuf> {
    let base = broker_state_dir()?;
    let staging = base.join("updates");
    if let Ok(metadata) = staging.symlink_metadata() {
        if metadata.file_type().is_symlink() || !metadata.is_dir() {
            bail!("update staging path is not a real directory");
        }
    } else {
        std::fs::create_dir_all(&staging).context("create update staging directory")?;
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            std::fs::set_permissions(&staging, std::fs::Permissions::from_mode(0o700))?;
        }
    }
    Ok(staging)
}

fn current_os() -> OperatingSystem {
    if cfg!(windows) {
        OperatingSystem::Windows
    } else {
        OperatingSystem::Linux
    }
}

fn current_architecture() -> Architecture {
    match std::env::consts::ARCH {
        "aarch64" => Architecture::Aarch64,
        _ => Architecture::X86_64,
    }
}

fn os_name(os: OperatingSystem) -> &'static str {
    match os {
        OperatingSystem::Linux => "linux",
        OperatingSystem::Windows => "windows",
    }
}

fn arch_name(arch: Architecture) -> &'static str {
    match arch {
        Architecture::X86_64 => "x86_64",
        Architecture::Aarch64 => "aarch64",
    }
}

fn valid_channel(value: &str) -> bool {
    centrald_common::build_info::is_supported_channel(value)
}

#[cfg(test)]
#[allow(clippy::unwrap_used)]
mod tests {
    use super::*;

    fn parameters() -> UpdateParameters {
        UpdateParameters {
            manifest_url: "https://example.test/centrald/centrald-release.yml".into(),
            channel: centrald_common::build_info::RELEASE_CHANNEL.into(),
            allow_prerelease: true,
            expected_version: "0.2.0".into(),
        }
    }

    #[test]
    fn parameters_validate_strictly() {
        assert!(parameters().validate().is_ok());
        let mut insecure = parameters();
        insecure.manifest_url = "http://example.test/manifest.yml".into();
        assert!(insecure.validate().is_err());
        let mut bad_channel = parameters();
        bad_channel.channel = "Not A Channel".into();
        assert!(bad_channel.validate().is_err());
        let wrong_channel = {
            let mut params = parameters();
            let other = centrald_common::build_info::SUPPORTED_CHANNELS
                .iter()
                .copied()
                .find(|candidate| *candidate != centrald_common::build_info::RELEASE_CHANNEL)
                .unwrap_or("stable");
            params.channel = other.into();
            params
        };
        assert!(
            wrong_channel.validate().is_err(),
            "a build must refuse a channel other than its own"
        );
        let mut bad_version = parameters();
        bad_version.expected_version = "banana".into();
        assert!(bad_version.validate().is_err());
    }

    #[test]
    fn zip_entry_names_reject_traversal() {
        for safe in [
            "centrald-client.exe",
            "install-client.ps1",
            "sub/dir/file.txt",
        ] {
            assert!(is_simple_entry_name(safe), "{safe} should be safe");
        }
        for unsafe_name in [
            "../evil.exe",
            "/absolute.exe",
            "a/../../b.exe",
            "\\evil.exe",
            "a\\..\\b",
            "C:/evil.exe",
            "C:\\evil.exe",
            "C:evil.exe",
            "file.txt:$DATA",
            "",
        ] {
            assert!(
                !is_simple_entry_name(unsafe_name),
                "{unsafe_name} must be rejected"
            );
        }
    }

    #[test]
    fn platform_identity_maps_to_manifest_names() {
        assert!(matches!(
            current_os(),
            OperatingSystem::Linux | OperatingSystem::Windows
        ));
        assert!(matches!(
            current_architecture(),
            Architecture::X86_64 | Architecture::Aarch64
        ));
    }
}
