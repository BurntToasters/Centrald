//! Non-secret build and update settings sourced from tracked `centrald.config`.

pub const REPO_URL: &str = env!("CENTRALD_REPO_URL");
pub const UPDATE_BASE_URL: &str = env!("CENTRALD_UPDATE_BASE_URL");
pub const CDN_BASE_URL: &str = env!("CENTRALD_CDN_BASE_URL");
pub const ARTIFACT_BASE_URL_TEMPLATE: &str = env!("CENTRALD_ARTIFACT_BASE_URL_TEMPLATE");
pub const RELEASE_CHANNEL: &str = env!("CENTRALD_RELEASE_CHANNEL");
pub const RELEASE_MANIFEST: &str = env!("CENTRALD_RELEASE_MANIFEST");
pub const TAURI_UPDATE_MANIFEST: &str = env!("CENTRALD_TAURI_UPDATE_MANIFEST");
pub const TAURI_UPDATER_PUBKEY: &str = env!("CENTRALD_TAURI_UPDATER_PUBKEY");
pub const MINISIGN_PUBLIC_KEY: &str = env!("CENTRALD_MINISIGN_PUBLIC_KEY");

/// The only release channels `CentralD` serves. Version auto-detection, the
/// operator-facing tools, the server update feed, and manifest validation all
/// restrict updates to exactly these three.
pub const SUPPORTED_CHANNELS: [&str; 3] = ["stable", "alpha", "beta"];

#[must_use]
pub fn is_supported_channel(value: &str) -> bool {
    SUPPORTED_CHANNELS.contains(&value)
}

#[must_use]
pub fn release_manifest_url() -> String {
    format!(
        "{}/{}",
        UPDATE_BASE_URL.trim_end_matches('/'),
        RELEASE_MANIFEST
    )
}

#[must_use]
pub fn tauri_update_manifest_url() -> String {
    format!(
        "{}/{}",
        UPDATE_BASE_URL.trim_end_matches('/'),
        TAURI_UPDATE_MANIFEST
    )
}

/// Resolves the mutable release-manifest URL for a specific channel, mirroring
/// the JS release tooling: a configured CDN serves every channel at
/// `<cdn>/<channel>/<manifest>`; otherwise GitHub serves stable from
/// `/releases/latest/download` and other channels from the
/// `centrald-channels` branch; generic origins use `<repo>/<channel>/latest`.
#[must_use]
pub fn manifest_url_for_channel(channel: &str) -> String {
    let cdn = CDN_BASE_URL.trim_end_matches('/');
    if !cdn.is_empty() {
        return format!("{cdn}/{channel}/{RELEASE_MANIFEST}");
    }
    let repo = REPO_URL.trim_end_matches('/');
    if let Some(rest) = repo.strip_prefix("https://github.com/") {
        if channel == "stable" {
            return format!("{repo}/releases/latest/download/{RELEASE_MANIFEST}");
        }
        let (owner, repository) = rest.split_once('/').unwrap_or(("", rest));
        return format!(
            "https://raw.githubusercontent.com/{owner}/{repository}/centrald-channels/channels/{channel}/latest/{RELEASE_MANIFEST}"
        );
    }
    if channel == "stable" {
        format!("{repo}/latest/{RELEASE_MANIFEST}")
    } else {
        format!("{repo}/{channel}/latest/{RELEASE_MANIFEST}")
    }
}
