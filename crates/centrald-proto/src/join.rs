//! Join codes: the single string an operator pastes to enroll a device.
//!
//! A join code carries where the server is, the SHA-256 fingerprint of the
//! server's certificate authority, and a one-time secret. The fingerprint is
//! what makes enrollment safe on an untrusted network: the agent refuses any
//! server whose CA does not match it.
//!
//! Layout before base64url: `fingerprint(32) || secret(20) || servers || check(4)`
//! where `servers` is newline-separated `host:port` text and `check` is the
//! first four bytes of SHA-256 over everything before it. The check only
//! catches truncated or mistyped pastes; it is not a security boundary.

use base64::Engine;
use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use rand::RngCore;

use crate::sha256;

const PREFIX: &str = "cdj1.";
const FINGERPRINT_BYTES: usize = 32;
pub const SECRET_BYTES: usize = 20;
const CHECK_BYTES: usize = 4;
const MAX_SERVERS: usize = 4;
const MAX_SERVER_BYTES: usize = 260;
const MAX_CODE_BYTES: usize = 2048;

#[derive(Debug, thiserror::Error, PartialEq, Eq)]
pub enum JoinCodeError {
    #[error("this is not a CentralD join code (it should start with `cdj1.`)")]
    NotAJoinCode,
    #[error("the join code is incomplete or was changed while copying; copy it again")]
    Corrupt,
    #[error("the join code does not name a server address")]
    NoServer,
    #[error("invalid server address `{0}`; expected host:port")]
    InvalidServer(String),
}

/// A parsed join code.
#[derive(Clone, PartialEq, Eq)]
pub struct JoinCode {
    /// `host:port` candidates, tried in order.
    pub servers: Vec<String>,
    pub ca_fingerprint: [u8; FINGERPRINT_BYTES],
    pub secret: [u8; SECRET_BYTES],
}

impl std::fmt::Debug for JoinCode {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        // The secret never reaches logs.
        formatter
            .debug_struct("JoinCode")
            .field("servers", &self.servers)
            .field("secret", &"<redacted>")
            .finish_non_exhaustive()
    }
}

impl JoinCode {
    /// Creates a join code with a fresh random secret.
    pub fn generate(
        servers: Vec<String>,
        ca_fingerprint: [u8; FINGERPRINT_BYTES],
    ) -> Result<Self, JoinCodeError> {
        let mut secret = [0_u8; SECRET_BYTES];
        rand::rng().fill_bytes(&mut secret);
        let code = Self {
            servers,
            ca_fingerprint,
            secret,
        };
        code.validate()?;
        Ok(code)
    }

    fn validate(&self) -> Result<(), JoinCodeError> {
        if self.servers.is_empty() {
            return Err(JoinCodeError::NoServer);
        }
        if self.servers.len() > MAX_SERVERS {
            return Err(JoinCodeError::Corrupt);
        }
        for server in &self.servers {
            validate_server_address(server)?;
        }
        Ok(())
    }

    pub fn encode(&self) -> String {
        let mut bytes = Vec::with_capacity(128);
        bytes.extend_from_slice(&self.ca_fingerprint);
        bytes.extend_from_slice(&self.secret);
        bytes.extend_from_slice(self.servers.join("\n").as_bytes());
        let check = sha256(&bytes);
        bytes.extend_from_slice(&check[..CHECK_BYTES]);
        format!("{PREFIX}{}", URL_SAFE_NO_PAD.encode(bytes))
    }

    pub fn parse(text: &str) -> Result<Self, JoinCodeError> {
        let text = text.trim();
        if text.len() > MAX_CODE_BYTES {
            return Err(JoinCodeError::Corrupt);
        }
        let body = text
            .strip_prefix(PREFIX)
            .ok_or(JoinCodeError::NotAJoinCode)?;
        let bytes = URL_SAFE_NO_PAD
            .decode(body)
            .map_err(|_| JoinCodeError::Corrupt)?;
        let minimum = FINGERPRINT_BYTES + SECRET_BYTES + CHECK_BYTES;
        if bytes.len() <= minimum {
            return Err(JoinCodeError::Corrupt);
        }
        let (payload, check) = bytes.split_at(bytes.len() - CHECK_BYTES);
        if sha256(payload)[..CHECK_BYTES] != *check {
            return Err(JoinCodeError::Corrupt);
        }
        let (fingerprint, rest) = payload.split_at(FINGERPRINT_BYTES);
        let (secret, servers) = rest.split_at(SECRET_BYTES);
        let servers = std::str::from_utf8(servers).map_err(|_| JoinCodeError::Corrupt)?;
        let code = Self {
            servers: servers.split('\n').map(str::to_owned).collect(),
            ca_fingerprint: fingerprint.try_into().map_err(|_| JoinCodeError::Corrupt)?,
            secret: secret.try_into().map_err(|_| JoinCodeError::Corrupt)?,
        };
        code.validate()?;
        Ok(code)
    }

    /// The value the server stores and looks up; never the secret itself.
    pub fn secret_hash(&self) -> [u8; 32] {
        sha256(&self.secret)
    }
}

/// Accepts `host:port` and `[ipv6]:port` with a conservative character set.
///
/// The address is embedded in generated shell commands, so anything outside
/// hostname, IPv4, and bracketed IPv6 characters is rejected.
pub fn validate_server_address(address: &str) -> Result<(), JoinCodeError> {
    let invalid = || JoinCodeError::InvalidServer(address.to_owned());
    if address.is_empty() || address.len() > MAX_SERVER_BYTES {
        return Err(invalid());
    }
    let (host, port) = address.rsplit_once(':').ok_or_else(invalid)?;
    if port.is_empty() || port.len() > 5 || !port.bytes().all(|b| b.is_ascii_digit()) {
        return Err(invalid());
    }
    match port.parse::<u16>() {
        Ok(port) if port != 0 => {}
        _ => return Err(invalid()),
    }
    let host_ok = if let Some(inner) = host.strip_prefix('[').and_then(|h| h.strip_suffix(']')) {
        !inner.is_empty()
            && inner
                .bytes()
                .all(|b| b.is_ascii_hexdigit() || b == b':' || b == b'.')
    } else {
        !host.is_empty()
            && !host.starts_with(['-', '.'])
            && host
                .bytes()
                .all(|b| b.is_ascii_alphanumeric() || b == b'-' || b == b'.')
    };
    if host_ok { Ok(()) } else { Err(invalid()) }
}
