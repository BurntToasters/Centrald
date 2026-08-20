use argon2::password_hash::{PasswordHash, PasswordHasher, PasswordVerifier, SaltString};
use argon2::{Algorithm, Argon2, Params, Version};
use base64::Engine as _;
use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use chrono::{DateTime, Utc};
use rand::RngCore;
use secrecy::{ExposeSecret, SecretString};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use thiserror::Error;
use uuid::Uuid;

const INVITATION_SECRET_BYTES: usize = 32;
const SALT_BYTES: usize = 16;
const HMAC_BLOCK_BYTES: usize = 64;
const INVITATION_PREFIX: &str = "centrald-invite1";
const INVITATION_SCHEMA_VERSION: u32 = 1;
const MAX_INVITATION_BYTES: usize = 128 * 1024;
const MAX_ROOT_CA_BYTES: usize = 64 * 1024;

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum EnrollmentRole {
    Client,
    Admin,
}

impl EnrollmentRole {
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Client => "client",
            Self::Admin => "admin",
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct EnrollmentInvitationClaims {
    pub schema_version: u32,
    pub id: Uuid,
    pub server_instance_id: Uuid,
    pub role: EnrollmentRole,
    pub name: String,
    pub server_name: String,
    pub enrollment_port: u16,
    pub client_port: u16,
    pub admin_port: u16,
    pub root_ca_pem: String,
    pub expires_at: DateTime<Utc>,
}

impl EnrollmentInvitationClaims {
    #[must_use]
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        id: Uuid,
        server_instance_id: Uuid,
        role: EnrollmentRole,
        name: String,
        server_name: String,
        enrollment_port: u16,
        client_port: u16,
        admin_port: u16,
        root_ca_pem: String,
        expires_at: DateTime<Utc>,
    ) -> Self {
        Self {
            schema_version: INVITATION_SCHEMA_VERSION,
            id,
            server_instance_id,
            role,
            name,
            server_name,
            enrollment_port,
            client_port,
            admin_port,
            root_ca_pem,
            expires_at,
        }
    }

    /// Validates the public bootstrap metadata carried by an invitation.
    ///
    /// # Errors
    ///
    /// Returns an error for malformed identity, endpoint, role, or trust data.
    pub fn validate(&self) -> Result<(), EnrollmentSecretError> {
        if self.schema_version != INVITATION_SCHEMA_VERSION
            || self.id.is_nil()
            || self.server_instance_id.is_nil()
        {
            return Err(EnrollmentSecretError::InvalidClaims);
        }
        if self.name.trim().is_empty()
            || self.name.len() > 128
            || self.name.chars().any(char::is_control)
        {
            return Err(EnrollmentSecretError::InvalidClaims);
        }
        let server_name = self.server_name.trim();
        if server_name.is_empty()
            || server_name.len() > 253
            || server_name.contains("//")
            || server_name.contains('/')
            || server_name.contains(char::is_whitespace)
            || server_name.chars().any(char::is_control)
        {
            return Err(EnrollmentSecretError::InvalidClaims);
        }
        let ports = [self.enrollment_port, self.client_port, self.admin_port];
        if ports.iter().any(|port| *port < 1024)
            || ports[0] == ports[1]
            || ports[0] == ports[2]
            || ports[1] == ports[2]
        {
            return Err(EnrollmentSecretError::InvalidClaims);
        }
        if self.root_ca_pem.len() > MAX_ROOT_CA_BYTES
            || !self.root_ca_pem.contains("-----BEGIN CERTIFICATE-----")
            || !self.root_ca_pem.contains("-----END CERTIFICATE-----")
        {
            return Err(EnrollmentSecretError::InvalidClaims);
        }
        Ok(())
    }
}

#[derive(Debug, Error)]
pub enum EnrollmentSecretError {
    #[error("could not encode enrollment-invitation salt")]
    Salt,
    #[error("could not hash enrollment invitation")]
    Hash,
    #[error("stored enrollment-invitation hash is invalid")]
    InvalidHash,
    #[error("enrollment invitation has an invalid format")]
    InvalidFormat,
    #[error("enrollment invitation contains invalid bootstrap metadata")]
    InvalidClaims,
    #[error("enrollment invitation integrity check failed")]
    Integrity,
    #[error("could not serialize enrollment invitation")]
    Serialization,
}

/// Creates a self-contained, one-time invitation.
///
/// The invitation carries only public bootstrap information plus the bearer
/// secret. The full serialized invitation is Argon2id-hashed by the server.
///
/// # Errors
///
/// Returns an error when claims are invalid or cannot be serialized.
#[allow(clippy::missing_panics_doc)]
pub fn generate_enrollment_invitation(
    claims: &EnrollmentInvitationClaims,
) -> Result<SecretString, EnrollmentSecretError> {
    claims.validate()?;
    let payload = serde_json::to_vec(claims).map_err(|_| EnrollmentSecretError::Serialization)?;
    let payload = URL_SAFE_NO_PAD.encode(payload);
    let mut secret = [0_u8; INVITATION_SECRET_BYTES];
    rand::rng().fill_bytes(&mut secret);
    let encoded_secret = URL_SAFE_NO_PAD.encode(secret);
    let signed = format!("{INVITATION_PREFIX}.{payload}.{encoded_secret}");
    let mac = hmac_sha256(&secret, signed.as_bytes());
    Ok(SecretString::from(format!(
        "{signed}.{}",
        URL_SAFE_NO_PAD.encode(mac)
    )))
}

/// Parses and validates the only supported invitation format.
///
/// # Errors
///
/// Returns an error for malformed, oversized, corrupt, or unsupported tokens.
pub fn parse_enrollment_invitation(
    secret: &SecretString,
) -> Result<EnrollmentInvitationClaims, EnrollmentSecretError> {
    let token = secret.expose_secret();
    if token.len() > MAX_INVITATION_BYTES {
        return Err(EnrollmentSecretError::InvalidFormat);
    }
    let mut parts = token.split('.');
    let prefix = parts.next();
    let payload = parts.next();
    let encoded_secret = parts.next();
    let encoded_mac = parts.next();
    if prefix != Some(INVITATION_PREFIX) || parts.next().is_some() {
        return Err(EnrollmentSecretError::InvalidFormat);
    }
    let payload = payload.ok_or(EnrollmentSecretError::InvalidFormat)?;
    let encoded_secret = encoded_secret.ok_or(EnrollmentSecretError::InvalidFormat)?;
    let encoded_mac = encoded_mac.ok_or(EnrollmentSecretError::InvalidFormat)?;
    let random = URL_SAFE_NO_PAD
        .decode(encoded_secret)
        .map_err(|_| EnrollmentSecretError::InvalidFormat)?;
    if random.len() != INVITATION_SECRET_BYTES {
        return Err(EnrollmentSecretError::InvalidFormat);
    }
    let mac = URL_SAFE_NO_PAD
        .decode(encoded_mac)
        .map_err(|_| EnrollmentSecretError::InvalidFormat)?;
    if mac.len() != 32 {
        return Err(EnrollmentSecretError::InvalidFormat);
    }
    let signed = format!("{INVITATION_PREFIX}.{payload}.{encoded_secret}");
    let expected = hmac_sha256(&random, signed.as_bytes());
    if !constant_time_equal(&expected, &mac) {
        return Err(EnrollmentSecretError::Integrity);
    }
    let payload = URL_SAFE_NO_PAD
        .decode(payload)
        .map_err(|_| EnrollmentSecretError::InvalidFormat)?;
    let claims: EnrollmentInvitationClaims =
        serde_json::from_slice(&payload).map_err(|_| EnrollmentSecretError::InvalidFormat)?;
    claims.validate()?;
    Ok(claims)
}

/// Extracts the non-secret lookup identifier embedded in an invitation.
///
/// # Errors
///
/// Returns an error when the invitation is malformed or corrupt.
pub fn enrollment_key_id(secret: &SecretString) -> Result<Uuid, EnrollmentSecretError> {
    Ok(parse_enrollment_invitation(secret)?.id)
}

/// Hashes an enrollment invitation using hardened Argon2id parameters.
///
/// # Errors
///
/// Returns an error if the random salt cannot be encoded or Argon2id rejects
/// the hashing parameters.
pub fn hash_enrollment_key(secret: &SecretString) -> Result<String, EnrollmentSecretError> {
    let mut salt_bytes = [0_u8; SALT_BYTES];
    rand::rng().fill_bytes(&mut salt_bytes);
    let salt = SaltString::encode_b64(&salt_bytes).map_err(|_| EnrollmentSecretError::Salt)?;
    argon2()
        .hash_password(secret.expose_secret().as_bytes(), &salt)
        .map(|hash| hash.to_string())
        .map_err(|_| EnrollmentSecretError::Hash)
}

/// Verifies a candidate invitation against a stored Argon2id hash.
///
/// # Errors
///
/// Returns an error when the stored hash is malformed.
pub fn verify_enrollment_key(
    secret: &SecretString,
    encoded_hash: &str,
) -> Result<bool, EnrollmentSecretError> {
    let parsed = PasswordHash::new(encoded_hash).map_err(|_| EnrollmentSecretError::InvalidHash)?;
    Ok(argon2()
        .verify_password(secret.expose_secret().as_bytes(), &parsed)
        .is_ok())
}

fn hmac_sha256(key: &[u8], message: &[u8]) -> [u8; 32] {
    let mut key_block = [0_u8; HMAC_BLOCK_BYTES];
    if key.len() > HMAC_BLOCK_BYTES {
        key_block[..32].copy_from_slice(&Sha256::digest(key));
    } else {
        key_block[..key.len()].copy_from_slice(key);
    }
    let mut inner_pad = [0x36_u8; HMAC_BLOCK_BYTES];
    let mut outer_pad = [0x5c_u8; HMAC_BLOCK_BYTES];
    for index in 0..HMAC_BLOCK_BYTES {
        inner_pad[index] ^= key_block[index];
        outer_pad[index] ^= key_block[index];
    }
    let mut inner = Sha256::new();
    inner.update(inner_pad);
    inner.update(message);
    let inner_hash = inner.finalize();
    let mut outer = Sha256::new();
    outer.update(outer_pad);
    outer.update(inner_hash);
    outer.finalize().into()
}

fn constant_time_equal(left: &[u8], right: &[u8]) -> bool {
    if left.len() != right.len() {
        return false;
    }
    left.iter()
        .zip(right)
        .fold(0_u8, |difference, (left, right)| {
            difference | (left ^ right)
        })
        == 0
}

#[allow(clippy::expect_used)]
fn argon2() -> Argon2<'static> {
    // These parameters are fixed CentralD policy, not runtime input. Invalid
    // constants are a programming error and must not fall back to weaker
    // crate defaults.
    let params = Params::new(64 * 1024, 3, 1, Some(32))
        .expect("CentralD Argon2id parameters (64 MiB, t=3, p=1, 32-byte tag) must be valid");
    Argon2::new(Algorithm::Argon2id, Version::V0x13, params)
}

#[cfg(test)]
#[allow(clippy::unwrap_used)]
mod tests {
    use super::*;

    fn claims() -> EnrollmentInvitationClaims {
        EnrollmentInvitationClaims::new(
            Uuid::now_v7(),
            Uuid::now_v7(),
            EnrollmentRole::Client,
            "workstation".into(),
            "centrald.home.arpa".into(),
            7443,
            7444,
            7445,
            "-----BEGIN CERTIFICATE-----\nZmFrZQ==\n-----END CERTIFICATE-----\n".into(),
            Utc::now() + chrono::Duration::minutes(15),
        )
    }

    #[test]
    fn generated_invitation_round_trips_and_wrong_key_fails() {
        let key = generate_enrollment_invitation(&claims()).unwrap();
        let parsed = parse_enrollment_invitation(&key).unwrap();
        assert_eq!(parsed.role, EnrollmentRole::Client);
        assert_eq!(enrollment_key_id(&key).unwrap(), parsed.id);
        let hash = hash_enrollment_key(&key).unwrap();
        assert!(verify_enrollment_key(&key, &hash).unwrap());
        assert!(!verify_enrollment_key(&SecretString::from("wrong".to_owned()), &hash).unwrap());
        assert!(!hash.contains(key.expose_secret()));
    }

    #[test]
    fn invitation_rejects_privileged_listener_ports() {
        let mut claims = claims();
        claims.enrollment_port = 443;
        assert!(generate_enrollment_invitation(&claims).is_err());
    }

    #[test]
    fn tampered_invitation_is_rejected() {
        let key = generate_enrollment_invitation(&claims()).unwrap();
        let mut token = key.expose_secret().to_owned();
        let last = token.pop().unwrap();
        token.push(if last == 'A' { 'B' } else { 'A' });
        assert!(parse_enrollment_invitation(&SecretString::from(token)).is_err());
    }
}
