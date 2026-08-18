//! OS-account credential validation for shell sessions.
//!
//! The broker validates a requested OS account's password against the machine
//! itself (PAM on Linux, `LogonUserW` on Windows) before opening a shell for
//! that account. Validation never persists the password; callers must pass a
//! zeroizing wrapper and drop it immediately.

use secrecy::{ExposeSecret, SecretString};

/// Validates an OS account password against the local machine.
///
/// # Errors
///
/// Returns an error when the platform authenticator rejects the account or
/// password, or the authenticator itself is unavailable.
pub fn validate_account_credentials(user: &str, password: &SecretString) -> Result<(), String> {
    if user.trim().is_empty() {
        return Err("an OS account is required".to_owned());
    }
    if password.expose_secret().is_empty() {
        return Err("a password is required for this account".to_owned());
    }
    #[cfg(target_os = "linux")]
    {
        linux_pam_validate(user, password.expose_secret())
    }
    #[cfg(windows)]
    {
        crate::windows_ffi::validate_account_credentials(user, password.expose_secret())
    }
    #[cfg(not(any(target_os = "linux", windows)))]
    {
        let _ = user;
        Err("OS-account authentication is unsupported on this platform".to_owned())
    }
}

#[cfg(target_os = "linux")]
fn linux_pam_validate(user: &str, password: &str) -> Result<(), String> {
    // The `login` PAM service performs password authentication through
    // common-auth (pam_unix) and account management checks without granting
    // any session.
    let mut client = pam_unix::Client::with_password("login")
        .map_err(|error| format!("PAM initialization failed: {error}"))?;
    client.conversation_mut().set_credentials(user, password);
    client
        .authenticate()
        .map_err(|error| format!("the OS account password was rejected: {error}"))?;
    Ok(())
}

#[cfg(test)]
#[allow(clippy::unwrap_used)]
mod tests {
    use super::*;

    #[test]
    fn rejects_empty_account_and_password() {
        assert!(validate_account_credentials("", &SecretString::from("x")).is_err());
        assert!(validate_account_credentials("root", &SecretString::from("")).is_err());
        assert!(validate_account_credentials(" ", &SecretString::from("x")).is_err());
    }
}
