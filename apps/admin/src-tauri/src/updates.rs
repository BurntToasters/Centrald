//! Admin updater feed verification.
//!
//! The Tauri updater plugin verifies its own `.sig` with `TAURI_UPDATER_PUBKEY`.
//! That is not a `CentralD` release signature. This module fetches the updater
//! JSON plus its Minisign `.minisig`, verifies with the baked Minisign public
//! key, and refuses a channel other than this build's `RELEASE_CHANNEL` before
//! the plugin is allowed to `check()` / `downloadAndInstall()`.

use std::io::Cursor;
use std::time::Duration;

use anyhow::{Context, Result, bail};
use centrald_common::build_info::{
    MINISIGN_PUBLIC_KEY, RELEASE_CHANNEL, tauri_update_manifest_url,
};

const MAX_TAURI_MANIFEST_BYTES: usize = 256 * 1024;
const MAX_SIGNATURE_BYTES: usize = 4096;

/// Fetches and Minisign-verifies the Admin updater JSON, then checks that the
/// signed channel matches this build.
///
/// # Errors
///
/// Returns an error when the feed cannot be fetched, the Minisign signature
/// fails, or the signed channel does not match this Admin build.
#[tauri::command]
pub async fn verify_admin_update_feed() -> Result<(), String> {
    verify_admin_update_feed_inner()
        .await
        .map_err(|error| error.to_string())
}

async fn verify_admin_update_feed_inner() -> Result<()> {
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
            if attempt.url().scheme() != "https" {
                return attempt.stop();
            }
            attempt.follow()
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
    Ok(())
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
