//! Non-secret build and update settings sourced from tracked `centrald.config`.

pub const REPO_URL: &str = env!("CENTRALD_REPO_URL");
pub const UPDATE_BASE_URL: &str = env!("CENTRALD_UPDATE_BASE_URL");
pub const ARTIFACT_BASE_URL_TEMPLATE: &str = env!("CENTRALD_ARTIFACT_BASE_URL_TEMPLATE");
pub const RELEASE_CHANNEL: &str = env!("CENTRALD_RELEASE_CHANNEL");
pub const RELEASE_MANIFEST: &str = env!("CENTRALD_RELEASE_MANIFEST");
pub const TAURI_UPDATE_MANIFEST: &str = env!("CENTRALD_TAURI_UPDATE_MANIFEST");
pub const TAURI_UPDATER_PUBKEY: &str = env!("CENTRALD_TAURI_UPDATER_PUBKEY");
pub const MINISIGN_PUBLIC_KEY: &str = env!("CENTRALD_MINISIGN_PUBLIC_KEY");

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
