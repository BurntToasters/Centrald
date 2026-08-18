//! Operating-system vault for saved OS-account credentials.
//!
//! Saved passwords are stored only in the machine vault: DPAPI-encrypted file
//! on Windows, the freedesktop Secret Service on Linux. If the vault is
//! unavailable the store fails closed; sessions never fall back to plaintext
//! credential persistence.

#[cfg(windows)]
use std::collections::HashMap;
#[cfg(windows)]
use std::path::PathBuf;

use anyhow::{Context, Result};
use secrecy::{ExposeSecret, SecretString};
#[cfg(windows)]
use serde::{Deserialize, Serialize};

#[cfg(windows)]
use crate::broker::broker_state_dir;

#[cfg(windows)]
const VAULT_FILE: &str = "vault.json";

/// Reads a saved credential from the operating system vault.
///
/// # Errors
///
/// Returns an error when the vault is unavailable or corrupt; `Ok(None)` when
/// the account has no saved credential.
pub fn load_account_credential(user: &str) -> Result<Option<SecretString>> {
    #[cfg(windows)]
    {
        windows_load(user)
    }
    #[cfg(target_os = "linux")]
    {
        linux_load(user)
    }
    #[cfg(not(any(windows, target_os = "linux")))]
    {
        let _ = user;
        anyhow::bail!("the operating-system credential vault is unsupported on this platform")
    }
}

/// Stores a validated credential in the operating system vault.
///
/// # Errors
///
/// Returns an error when the vault is unavailable or rejects the write.
pub fn store_account_credential(user: &str, password: &SecretString) -> Result<()> {
    #[cfg(windows)]
    {
        windows_store(user, password)
    }
    #[cfg(target_os = "linux")]
    {
        linux_store(user, password)
    }
    #[cfg(not(any(windows, target_os = "linux")))]
    {
        let _ = (user, password);
        anyhow::bail!("the operating-system credential vault is unsupported on this platform")
    }
}

/// Removes a saved credential from the operating system vault.
///
/// # Errors
///
/// Returns an error when the vault is unavailable.
pub fn delete_account_credential(user: &str) -> Result<()> {
    #[cfg(windows)]
    {
        windows_delete(user)
    }
    #[cfg(target_os = "linux")]
    {
        linux_delete(user)
    }
    #[cfg(not(any(windows, target_os = "linux")))]
    {
        let _ = user;
        anyhow::bail!("the operating-system credential vault is unsupported on this platform")
    }
}

#[cfg(windows)]
#[derive(Debug, Default, Serialize, Deserialize)]
struct VaultFile {
    entries: HashMap<String, Vec<u8>>,
}

#[cfg(windows)]
fn vault_file_path() -> Result<PathBuf> {
    Ok(broker_state_dir()?.join(VAULT_FILE))
}

/// The vault file holds a handful of DPAPI blobs; an oversized file is a
/// tampering or exhaustion signal, not a legitimate vault.
#[cfg(windows)]
const MAX_VAULT_FILE_BYTES: u64 = 256 * 1024;

#[cfg(windows)]
fn read_vault_file(path: &PathBuf) -> Result<zeroize::Zeroizing<Vec<u8>>> {
    let metadata = std::fs::metadata(path)
        .with_context(|| format!("inspect credential vault {}", path.display()))?;
    if metadata.len() > MAX_VAULT_FILE_BYTES {
        anyhow::bail!("credential vault exceeds the {MAX_VAULT_FILE_BYTES}-byte limit");
    }
    let raw = zeroize::Zeroizing::new(
        std::fs::read(path).with_context(|| format!("read credential vault {}", path.display()))?,
    );
    if raw.is_empty() {
        anyhow::bail!("credential vault is empty: {}", path.display());
    }
    Ok(raw)
}

#[cfg(windows)]
fn windows_load(user: &str) -> Result<Option<SecretString>> {
    let path = vault_file_path()?;
    if !path.exists() {
        return Ok(None);
    }
    let raw = read_vault_file(&path)?;
    let vault: VaultFile = serde_json::from_slice(&raw).context("decode credential vault")?;
    let Some(encrypted) = vault.entries.get(user) else {
        return Ok(None);
    };
    let plaintext = crate::windows_ffi::dpapi_unprotect(encrypted)?;
    let password = String::from_utf8(plaintext).context("credential vault holds invalid text")?;
    Ok(Some(SecretString::from(password)))
}

#[cfg(windows)]
fn windows_store(user: &str, password: &SecretString) -> Result<()> {
    let path = vault_file_path()?;
    let mut vault = if path.exists() {
        let raw = read_vault_file(&path)?;
        serde_json::from_slice::<VaultFile>(&raw).context("decode credential vault")?
    } else {
        VaultFile::default()
    };
    let encrypted = crate::windows_ffi::dpapi_protect(password.expose_secret().as_bytes())?;
    vault.entries.insert(user.to_owned(), encrypted);
    let raw = serde_json::to_vec(&vault)?;
    crate::windows_ffi::write_vault_file(&path, &raw)?;
    Ok(())
}

#[cfg(windows)]
fn windows_delete(user: &str) -> Result<()> {
    let path = vault_file_path()?;
    if !path.exists() {
        return Ok(());
    }
    let raw = read_vault_file(&path)?;
    let mut vault: VaultFile = serde_json::from_slice(&raw).context("decode credential vault")?;
    vault.entries.remove(user);
    let raw = serde_json::to_vec(&vault)?;
    crate::windows_ffi::write_vault_file(&path, &raw)?;
    Ok(())
}

#[cfg(target_os = "linux")]
fn linux_load(user: &str) -> Result<Option<SecretString>> {
    let Some(secret) = linux_search(user)? else {
        return Ok(None);
    };
    Ok(Some(SecretString::from(secret)))
}

#[cfg(target_os = "linux")]
fn linux_store(user: &str, password: &SecretString) -> Result<()> {
    linux_secret_service(|connection, service, session| {
        let item_path = linux_search_inner(&connection, &service, user)?;
        let collection = zbus::zvariant::OwnedObjectPath::try_from(
            "/org/freedesktop/secrets/collection/default",
        )
        .context("default Secret Service collection path")?;
        let secret = secret_tuple(&session, password.expose_secret().as_bytes())?;
        let properties = std::collections::HashMap::from([
            (
                "org.freedesktop.Secret.Item.Label".to_owned(),
                zbus::zvariant::OwnedValue::from(zbus::zvariant::Str::from(
                    "CentralD OS account credential",
                )),
            ),
            (
                "org.freedesktop.Secret.Item.Attributes".to_owned(),
                zbus::zvariant::OwnedValue::from(attributes(user)),
            ),
        ]);
        if let Some(existing) = item_path {
            let _: zbus::Message = connection
                .call_method(
                    Some("org.freedesktop.secrets"),
                    &existing,
                    Some("org.freedesktop.Secret.Item"),
                    "SetSecret",
                    &(secret,),
                )
                .context("set Secret Service item secret")?;
        } else {
            let _: zbus::Message = connection
                .call_method(
                    Some("org.freedesktop.secrets"),
                    &collection,
                    Some("org.freedesktop.Secret.Collection"),
                    "CreateItem",
                    &(properties, &secret, true),
                )
                .context("create Secret Service item")?;
        }
        let _ = service;
        Ok(())
    })
}

#[cfg(target_os = "linux")]
fn linux_delete(user: &str) -> Result<()> {
    linux_secret_service(|connection, service, _session| {
        let Some(item_path) = linux_search_inner(&connection, &service, user)? else {
            return Ok(());
        };
        let _: zbus::Message = connection
            .call_method(
                Some("org.freedesktop.secrets"),
                &item_path,
                Some("org.freedesktop.Secret.Item"),
                "Delete",
                &(),
            )
            .context("delete Secret Service item")?;
        Ok(())
    })
}

#[cfg(target_os = "linux")]
fn linux_search(user: &str) -> Result<Option<String>> {
    let mut found = None;
    linux_secret_service(|connection, service, session| {
        found = linux_search_inner(&connection, &service, user)?.map(|item_path| {
            let secret: (zbus::zvariant::OwnedObjectPath, Vec<u8>, Vec<u8>, String) = connection
                .call_method(
                    Some("org.freedesktop.secrets"),
                    &item_path,
                    Some("org.freedesktop.Secret.Item"),
                    "GetSecret",
                    &(&session,),
                )
                .context("get Secret Service item secret")?
                .body()
                .deserialize()
                .context("decode Secret Service item secret")?;
            Ok(String::from_utf8(secret.2)
                .context("Secret Service credential is not valid text")?)
        });
        Ok(())
    })?;
    found.transpose()
}

#[cfg(target_os = "linux")]
fn linux_search_inner(
    connection: &zbus::blocking::Connection,
    service: &zbus::zvariant::OwnedObjectPath,
    user: &str,
) -> Result<Option<zbus::zvariant::OwnedObjectPath>> {
    let attributes = attributes(user);
    let (unlocked, locked): (
        Vec<zbus::zvariant::OwnedObjectPath>,
        Vec<zbus::zvariant::OwnedObjectPath>,
    ) = connection
        .call_method(
            Some("org.freedesktop.secrets"),
            service,
            Some("org.freedesktop.secrets.Service"),
            "SearchItems",
            &(attributes,),
        )
        .context("search Secret Service")?
        .body()
        .deserialize()
        .context("decode Secret Service search")?;
    Ok(unlocked.into_iter().chain(locked).next())
}

#[cfg(target_os = "linux")]
fn attributes(user: &str) -> std::collections::HashMap<String, String> {
    std::collections::HashMap::from([
        ("application".to_owned(), "centrald".to_owned()),
        ("account".to_owned(), user.to_owned()),
    ])
}

#[cfg(target_os = "linux")]
fn secret_tuple(
    session: &zbus::zvariant::OwnedObjectPath,
    value: &[u8],
) -> Result<(zbus::zvariant::OwnedObjectPath, Vec<u8>, Vec<u8>, String)> {
    Ok((
        session.clone(),
        Vec::new(),
        value.to_vec(),
        "text/plain".to_owned(),
    ))
}

#[cfg(target_os = "linux")]
fn linux_secret_service(
    operation: impl FnOnce(
        &zbus::blocking::Connection,
        &zbus::zvariant::OwnedObjectPath,
        zbus::zvariant::OwnedObjectPath,
    ) -> Result<()>,
) -> Result<()> {
    let connection = zbus::blocking::Connection::session().context(
        "the freedesktop Secret Service is not available on this machine (is a secret service daemon running?)",
    )?;
    let service = zbus::zvariant::OwnedObjectPath::try_from("/org/freedesktop/secrets")
        .context("Secret Service object path")?;
    let input = zbus::zvariant::Value::from("");
    let (_output, session): (zbus::zvariant::OwnedValue, zbus::zvariant::OwnedObjectPath) =
        connection
            .call_method(
                Some("org.freedesktop.secrets"),
                &service,
                Some("org.freedesktop.secrets.Service"),
                "OpenSession",
                &("plain", &input),
            )
            .context("open a Secret Service session")?
            .body()
            .deserialize()
            .context("decode Secret Service session")?;
    operation(&connection, &service, session)
}

#[cfg(all(test, target_os = "linux"))]
#[allow(clippy::unwrap_used)]
mod tests {
    use super::*;

    #[test]
    fn secret_tuple_shape_is_stable() {
        // The tuple type must match org.freedesktop.Secret.Secret:
        // (o: session, ay: parameters, ay: value, s: content-type)
        let session =
            zbus::zvariant::OwnedObjectPath::try_from("/org/freedesktop/secrets/session/test")
                .unwrap();
        let tuple = secret_tuple(&session, b"hunter2");
        assert_eq!(tuple.unwrap().2, b"hunter2");
    }
}
