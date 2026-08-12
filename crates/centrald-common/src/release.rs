use std::collections::HashSet;

use chrono::{DateTime, Utc};
use semver::Version;
use serde::{Deserialize, Serialize};
use thiserror::Error;
use url::Url;

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ReleaseManifestV1 {
    pub schema_version: u32,
    pub version: Version,
    pub channel: String,
    pub protocol_major: u32,
    pub generated_at: DateTime<Utc>,
    pub repository: String,
    pub artifacts: Vec<ReleaseArtifact>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ReleaseArtifact {
    pub component: Component,
    pub os: OperatingSystem,
    pub architecture: Architecture,
    pub package: PackageKind,
    pub filename: String,
    pub url: String,
    pub size: u64,
    pub sha256: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub signature_url: Option<String>,
}

#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq, Hash)]
#[serde(rename_all = "snake_case")]
pub enum Component {
    Server,
    Client,
    Admin,
}

#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq, Hash)]
#[serde(rename_all = "snake_case")]
pub enum OperatingSystem {
    Linux,
    Windows,
}

#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq, Hash)]
#[serde(rename_all = "snake_case")]
pub enum Architecture {
    X86_64,
    Aarch64,
}

#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq, Hash)]
pub enum PackageKind {
    #[serde(rename = "deb")]
    Deb,
    #[serde(rename = "msi")]
    Msi,
    #[serde(rename = "nsis")]
    Nsis,
    #[serde(rename = "appimage")]
    AppImage,
    #[serde(rename = "tar_gz")]
    TarGz,
    #[serde(rename = "zip")]
    Zip,
}

#[derive(Debug, Error, PartialEq, Eq)]
pub enum ManifestError {
    #[error("unsupported release manifest schema")]
    Schema,
    #[error("release channel and semantic version do not agree")]
    ChannelVersion,
    #[error("release protocol major must be non-zero")]
    Protocol,
    #[error("release manifest repository is not a safe HTTPS URL")]
    Repository,
    #[error("release manifest contains no artifacts")]
    Empty,
    #[error("release manifest contains duplicate artifacts")]
    Duplicate,
    #[error("artifact URL is not an immutable HTTPS URL")]
    Url,
    #[error("artifact signature URL is invalid")]
    SignatureUrl,
    #[error("artifact digest must be a lowercase SHA-256 hex string")]
    Digest,
    #[error("artifact filename is invalid or does not match its URL")]
    Filename,
    #[error("artifact size must be non-zero")]
    Size,
}

impl ReleaseManifestV1 {
    /// Validates the release-feed schema, semantic channel, and every artifact.
    ///
    /// Artifact hosts may be GitHub Releases or static object storage. The
    /// manifest itself is the signed/approved index, while each artifact URL
    /// must still be HTTPS, immutable-looking (never `/latest/`), credential
    /// free, and bound to the declared filename and digest.
    ///
    /// # Errors
    ///
    /// Returns an error when the manifest or an artifact violates a release
    /// integrity invariant.
    pub fn validate(&self) -> Result<(), ManifestError> {
        if self.schema_version != 1 {
            return Err(ManifestError::Schema);
        }
        if !valid_channel(&self.channel) {
            return Err(ManifestError::ChannelVersion);
        }
        if (self.channel == "stable") != self.version.pre.is_empty() {
            return Err(ManifestError::ChannelVersion);
        }
        if self.protocol_major == 0 {
            return Err(ManifestError::Protocol);
        }
        validate_https_base(&self.repository).map_err(|_| ManifestError::Repository)?;
        if self.artifacts.is_empty() {
            return Err(ManifestError::Empty);
        }

        let mut identities = HashSet::with_capacity(self.artifacts.len());
        let mut filenames = HashSet::with_capacity(self.artifacts.len());
        let mut urls = HashSet::with_capacity(self.artifacts.len());
        for artifact in &self.artifacts {
            validate_artifact(artifact)?;
            if !identities.insert((
                artifact.component,
                artifact.os,
                artifact.architecture,
                artifact.package,
            )) || !filenames.insert(artifact.filename.as_str())
                || !urls.insert(artifact.url.as_str())
            {
                return Err(ManifestError::Duplicate);
            }
        }
        Ok(())
    }
}

fn validate_artifact(artifact: &ReleaseArtifact) -> Result<(), ManifestError> {
    if !is_simple_filename(&artifact.filename) {
        return Err(ManifestError::Filename);
    }
    if artifact.size == 0 {
        return Err(ManifestError::Size);
    }
    if artifact.sha256.len() != 64
        || !artifact
            .sha256
            .bytes()
            .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
    {
        return Err(ManifestError::Digest);
    }

    let artifact_url = validate_immutable_url(&artifact.url).map_err(|_| ManifestError::Url)?;
    if artifact_url
        .path_segments()
        .and_then(|segments| segments.last())
        != Some(artifact.filename.as_str())
    {
        return Err(ManifestError::Filename);
    }

    let signature_url = artifact
        .signature_url
        .as_ref()
        .ok_or(ManifestError::SignatureUrl)?;
    let signature =
        validate_immutable_url(signature_url).map_err(|_| ManifestError::SignatureUrl)?;
    let expected = format!("{}.minisig", artifact.filename);
    if signature.path_segments().and_then(|segments| segments.last()) != Some(expected.as_str()) {
        return Err(ManifestError::SignatureUrl);
    }
    Ok(())
}

fn valid_channel(value: &str) -> bool {
    let mut characters = value.chars();
    let Some(first) = characters.next() else {
        return false;
    };
    value.len() <= 32
        && first.is_ascii_lowercase()
        && characters.all(|character| {
            character.is_ascii_lowercase()
                || character.is_ascii_digit()
                || matches!(character, '.' | '_' | '-')
        })
}

fn validate_https_base(value: &str) -> Result<Url, ()> {
    let parsed = Url::parse(value).map_err(|_| ())?;
    if parsed.scheme() != "https"
        || parsed.host_str().is_none()
        || !parsed.username().is_empty()
        || parsed.password().is_some()
        || parsed.query().is_some()
        || parsed.fragment().is_some()
    {
        return Err(());
    }
    Ok(parsed)
}

fn validate_immutable_url(value: &str) -> Result<Url, ()> {
    let parsed = validate_https_base(value)?;
    let normalized_path = parsed.path().to_ascii_lowercase();
    if normalized_path == "/latest" || normalized_path.contains("/latest/") {
        return Err(());
    }
    Ok(parsed)
}

fn is_simple_filename(value: &str) -> bool {
    !value.is_empty()
        && value.len() <= 255
        && value != "."
        && value != ".."
        && !value.starts_with('.')
        && !value.contains('/')
        && !value.contains('\\')
        && !value.contains('\0')
        && !value.chars().any(char::is_control)
}

#[cfg(test)]
#[allow(clippy::expect_used)]
mod tests {
    use chrono::TimeZone as _;

    use super::*;

    fn manifest() -> ReleaseManifestV1 {
        ReleaseManifestV1 {
            schema_version: 1,
            version: Version::parse("0.1.0-alpha.1").expect("test version should parse"),
            channel: "prerelease".into(),
            protocol_major: 1,
            generated_at: Utc
                .with_ymd_and_hms(2026, 8, 6, 12, 0, 0)
                .single()
                .expect("test timestamp should be valid"),
            repository: "https://github.com/BurntToasters/centrald".into(),
            artifacts: vec![ReleaseArtifact {
                component: Component::Client,
                os: OperatingSystem::Linux,
                architecture: Architecture::X86_64,
                package: PackageKind::Deb,
                filename: "centrald-client_0.1.0-alpha.1_linux_x86_64.deb".into(),
                url: "https://downloads.example.test/centrald/releases/0.1.0-alpha.1/centrald-client_0.1.0-alpha.1_linux_x86_64.deb".into(),
                size: 1,
                sha256: "a".repeat(64),
                signature_url: Some("https://downloads.example.test/centrald/releases/0.1.0-alpha.1/centrald-client_0.1.0-alpha.1_linux_x86_64.deb.minisig".into()),
            }],
        }
    }

    #[test]
    fn accepts_generic_immutable_https_artifact_urls() {
        assert_eq!(manifest().validate(), Ok(()));
    }

    #[test]
    fn rejects_latest_asset_url_and_channel_mismatch() {
        let mut release = manifest();
        release.artifacts[0].url =
            "https://example.test/centrald/latest/centrald-client.deb".into();
        assert_eq!(release.validate(), Err(ManifestError::Url));

        let mut release = manifest();
        release.channel = "stable".into();
        assert_eq!(release.validate(), Err(ManifestError::ChannelVersion));
    }

    #[test]
    fn rejects_duplicate_platform_package_entries() {
        let mut release = manifest();
        let mut duplicate = release.artifacts[0].clone();
        duplicate.filename = "other.deb".into();
        duplicate.url = "https://example.test/releases/1/other.deb".into();
        duplicate.signature_url = Some("https://example.test/releases/1/other.deb.minisig".into());
        release.artifacts.push(duplicate);
        assert_eq!(release.validate(), Err(ManifestError::Duplicate));
    }
}
