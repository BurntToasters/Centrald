//! Admin updater feed verification and installation.
//!
//! The Tauri updater plugin verifies its own `.sig` with `TAURI_UPDATER_PUBKEY`.
//! That is not a `CentralD` release signature. This module fetches the updater
//! JSON plus its Minisign `.minisig`, verifies with the baked Minisign public
//! key, and refuses a channel other than this build's `RELEASE_CHANNEL`.
//! Availability is decided from that single verified body. Install still uses
//! the Tauri plugin for artifact download, but only after the plugin's feed
//! JSON matches the Minisign-verified bytes (closes feed TOCTOU).
//! Install runs only through these Rust commands; the `WebView` has no updater
//! plugin ACL.

use std::cmp::Ordering;
use std::io::Cursor;
use std::time::Duration;

use anyhow::{Context, Result, bail};
use centrald_common::build_info::{
    MINISIGN_PUBLIC_KEY, RELEASE_CHANNEL, tauri_update_manifest_url,
};
use serde::Serialize;
use tauri::AppHandle;
use tauri_plugin_updater::UpdaterExt;

const MAX_TAURI_MANIFEST_BYTES: usize = 256 * 1024;
const MAX_SIGNATURE_BYTES: usize = 4096;

#[derive(Debug, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct AdminUpdateStatus {
    available: bool,
    version: Option<String>,
}

struct VerifiedAdminFeed {
    version: String,
    parsed: serde_json::Value,
}

/// Minisign-verifies the Admin updater feed once and reports whether a newer
/// version exists for this platform.
///
/// # Errors
///
/// Returns an error when the feed cannot be fetched, Minisign fails, or the
/// signed channel does not match this build.
#[tauri::command]
pub async fn check_admin_update(app: AppHandle) -> Result<AdminUpdateStatus, String> {
    let _ = app;
    check_admin_update_inner()
        .await
        .map_err(|error| error.to_string())
}

/// Minisign-verifies the feed, then installs only if the plugin's second fetch
/// returns JSON identical to the verified body and the same version.
///
/// # Errors
///
/// Returns an error when verification fails, no update is available, the plugin
/// feed disagrees with the signed body, or installation fails.
#[tauri::command]
pub async fn install_admin_update(app: AppHandle) -> Result<(), String> {
    install_admin_update_inner(app)
        .await
        .map_err(|error| error.to_string())
}

async fn check_admin_update_inner() -> Result<AdminUpdateStatus> {
    let feed = verify_admin_update_feed_inner().await?;
    let current = semver::Version::parse(env!("CARGO_PKG_VERSION"))
        .context("parse this Admin build version")?;
    let remote =
        semver::Version::parse(&feed.version).context("parse the signed Admin updater version")?;
    if !platform_present_in_feed(&feed.parsed) {
        return Ok(AdminUpdateStatus {
            available: false,
            version: None,
        });
    }
    let available = remote.cmp_precedence(&current) == Ordering::Greater;
    Ok(AdminUpdateStatus {
        available,
        version: available.then_some(feed.version),
    })
}

async fn install_admin_update_inner(app: AppHandle) -> Result<()> {
    let feed = verify_admin_update_feed_inner().await?;
    let current = semver::Version::parse(env!("CARGO_PKG_VERSION"))
        .context("parse this Admin build version")?;
    let remote =
        semver::Version::parse(&feed.version).context("parse the signed Admin updater version")?;
    if remote.cmp_precedence(&current) != Ordering::Greater {
        bail!("no Admin update is available");
    }
    if !platform_present_in_feed(&feed.parsed) {
        bail!("the signed Admin updater feed has no artifact for this platform");
    }
    let Some(update) = app.updater()?.check().await? else {
        bail!("no Admin update is available");
    };
    if update.version != feed.version {
        bail!(
            "updater plugin version {} does not match the Minisign-verified feed {}",
            update.version,
            feed.version
        );
    }
    if update.raw_json != feed.parsed {
        bail!(
            "updater plugin feed JSON does not match the Minisign-verified body; refusing install"
        );
    }
    update
        .download_and_install(|_, _| {}, || {})
        .await
        .context("download and install the signed Admin update")?;
    Ok(())
}

async fn verify_admin_update_feed_inner() -> Result<VerifiedAdminFeed> {
    let manifest_url = tauri_update_manifest_url();
    if manifest_url.is_empty() {
        bail!("this Admin build has no updater manifest URL");
    }
    let client = reqwest::Client::builder()
        .timeout(Duration::from_secs(20))
        .redirect(reqwest::redirect::Policy::custom(|attempt| {
            if attempt.previous().len() >= 3 {
                return attempt.stop();
            }
            match centrald_common::https::https_redirect_is_allowed(attempt.url()) {
                Ok(()) => attempt.follow(),
                Err(reason) => attempt.error(reason),
            }
        }))
        .build()?;
    let manifest_bytes = fetch_bounded(&client, &manifest_url, MAX_TAURI_MANIFEST_BYTES).await?;
    let signature_bytes = fetch_bounded(
        &client,
        &format!("{manifest_url}.minisig"),
        MAX_SIGNATURE_BYTES,
    )
    .await?;
    verify_minisign_bytes(&manifest_bytes, &signature_bytes)?;
    let parsed: serde_json::Value =
        serde_json::from_slice(&manifest_bytes).context("decode the Admin updater JSON")?;
    let channel = parsed
        .get("channel")
        .and_then(serde_json::Value::as_str)
        .unwrap_or("");
    if channel != RELEASE_CHANNEL {
        bail!(
            "Admin updater channel {channel:?} does not match this build's {RELEASE_CHANNEL} channel"
        );
    }
    let version = parsed
        .get("version")
        .and_then(serde_json::Value::as_str)
        .filter(|value| !value.is_empty())
        .context("Admin updater JSON is missing version")?
        .to_owned();
    Ok(VerifiedAdminFeed { version, parsed })
}

fn platform_present_in_feed(parsed: &serde_json::Value) -> bool {
    let Some(platforms) = parsed
        .get("platforms")
        .and_then(serde_json::Value::as_object)
    else {
        return false;
    };
    platforms.contains_key(current_updater_platform())
}

fn current_updater_platform() -> &'static str {
    #[cfg(all(target_os = "linux", target_arch = "x86_64"))]
    {
        "linux-x86_64"
    }
    #[cfg(all(target_os = "windows", target_arch = "x86_64"))]
    {
        "windows-x86_64"
    }
    #[cfg(all(target_os = "windows", target_arch = "aarch64"))]
    {
        "windows-aarch64"
    }
    #[cfg(not(any(
        all(target_os = "linux", target_arch = "x86_64"),
        all(target_os = "windows", target_arch = "x86_64"),
        all(target_os = "windows", target_arch = "aarch64"),
    )))]
    {
        "unsupported"
    }
}

async fn fetch_bounded(client: &reqwest::Client, url: &str, max_bytes: usize) -> Result<Vec<u8>> {
    let mut response = client
        .get(url)
        .header(reqwest::header::ACCEPT_ENCODING, "identity")
        .send()
        .await?
        .error_for_status()?;
    if response
        .headers()
        .get(reqwest::header::CONTENT_ENCODING)
        .and_then(|value| value.to_str().ok())
        .is_some_and(|value| !value.eq_ignore_ascii_case("identity"))
    {
        bail!("updater feed must not use content encoding");
    }
    if response
        .content_length()
        .is_some_and(|length| length > u64::try_from(max_bytes).unwrap_or(u64::MAX))
    {
        bail!("updater feed exceeds the size limit");
    }
    let mut body = Vec::new();
    while let Some(chunk) = response.chunk().await? {
        body.extend_from_slice(&chunk);
        if body.len() > max_bytes {
            bail!("updater feed exceeds the size limit");
        }
    }
    Ok(body)
}

fn verify_minisign_bytes(data: &[u8], signature_text: &[u8]) -> Result<()> {
    if MINISIGN_PUBLIC_KEY.is_empty() {
        bail!("this Admin build has no Minisign public key; update verification is disabled");
    }
    let public_key = minisign::PublicKey::from_base64(MINISIGN_PUBLIC_KEY)
        .context("parse the Minisign public key")?;
    let signature_text = String::from_utf8(signature_text.to_vec())
        .context("Minisign signature is not valid text")?;
    let signature_box = minisign::SignatureBox::from_string(&signature_text)
        .context("decode the Minisign signature")?;
    let mut cursor = Cursor::new(data);
    minisign::verify(&public_key, &signature_box, &mut cursor, true, false, false)
        .context("Minisign verification failed")?;
    Ok(())
}
