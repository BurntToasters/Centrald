use base64::Engine as _;
use base64::engine::general_purpose::STANDARD;
use chrono::{DateTime, Utc};
use ed25519_dalek::{Signature, Signer, SigningKey, Verifier, VerifyingKey};
use serde::{Deserialize, Serialize};
use thiserror::Error;
use uuid::Uuid;

const GRANT_DOMAIN: &[u8] = b"centrald-grant-v1\0";

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum GrantOperation {
    RestartClientService,
    RestartMachine,
    CheckOsUpdates,
    ApplyOsUpdates,
    UpdateClient,
    OpenLowShell,
    OpenElevatedShell,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct PrivilegedGrant {
    pub id: Uuid,
    pub device_id: Uuid,
    pub job_or_session_id: Uuid,
    pub admin_id: Uuid,
    pub operation: GrantOperation,
    pub parameters_sha256: String,
    pub issued_at: DateTime<Utc>,
    pub expires_at: DateTime<Utc>,
    pub nonce: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct SignedGrant {
    pub grant: PrivilegedGrant,
    pub signature_base64: String,
}

#[derive(Debug, Error)]
pub enum GrantError {
    #[error("grant serialization failed")]
    Serialization,
    #[error("grant signature has invalid encoding")]
    SignatureEncoding,
    #[error("grant signature verification failed")]
    InvalidSignature,
    #[error("grant is not for this device")]
    WrongDevice,
    #[error("grant is expired or not yet valid")]
    OutsideValidity,
}

impl PrivilegedGrant {
    /// Signs this grant using the broker-grant domain separator.
    ///
    /// # Errors
    ///
    /// Returns an error if the grant cannot be serialized canonically.
    pub fn sign(&self, key: &SigningKey) -> Result<SignedGrant, GrantError> {
        let payload = signing_payload(self)?;
        let signature = key.sign(&payload);
        Ok(SignedGrant {
            grant: self.clone(),
            signature_base64: STANDARD.encode(signature.to_bytes()),
        })
    }
}

impl SignedGrant {
    /// Verifies signature, device binding, and the validity window.
    ///
    /// # Errors
    ///
    /// Returns an error for malformed or invalid signatures, a device
    /// mismatch, an invalid validity window, or serialization failure.
    pub fn verify(
        &self,
        key: &VerifyingKey,
        expected_device: Uuid,
        now: DateTime<Utc>,
    ) -> Result<(), GrantError> {
        if self.grant.device_id != expected_device {
            return Err(GrantError::WrongDevice);
        }
        if now < self.grant.issued_at || now > self.grant.expires_at {
            return Err(GrantError::OutsideValidity);
        }
        let raw = STANDARD
            .decode(&self.signature_base64)
            .map_err(|_| GrantError::SignatureEncoding)?;
        let signature = Signature::from_slice(&raw).map_err(|_| GrantError::SignatureEncoding)?;
        let payload = signing_payload(&self.grant)?;
        key.verify(&payload, &signature)
            .map_err(|_| GrantError::InvalidSignature)
    }
}

fn signing_payload(grant: &PrivilegedGrant) -> Result<Vec<u8>, GrantError> {
    let encoded = serde_json::to_vec(grant).map_err(|_| GrantError::Serialization)?;
    let mut payload = Vec::with_capacity(GRANT_DOMAIN.len() + encoded.len());
    payload.extend_from_slice(GRANT_DOMAIN);
    payload.extend_from_slice(&encoded);
    Ok(payload)
}

#[cfg(test)]
#[allow(clippy::unwrap_used)]
mod tests {
    use chrono::Duration;

    use super::*;

    fn grant(device_id: Uuid) -> PrivilegedGrant {
        let now = Utc::now();
        PrivilegedGrant {
            id: Uuid::now_v7(),
            device_id,
            job_or_session_id: Uuid::now_v7(),
            admin_id: Uuid::now_v7(),
            operation: GrantOperation::RestartMachine,
            parameters_sha256: "00".repeat(32),
            issued_at: now - Duration::seconds(1),
            expires_at: now + Duration::seconds(30),
            nonce: "nonce".into(),
        }
    }

    #[test]
    fn grant_is_bound_to_device_and_signature() {
        let key = SigningKey::from_bytes(&[7_u8; 32]);
        let device = Uuid::now_v7();
        let signed = grant(device).sign(&key).unwrap();
        assert!(
            signed
                .verify(&key.verifying_key(), device, Utc::now())
                .is_ok()
        );
        assert!(matches!(
            signed.verify(&key.verifying_key(), Uuid::now_v7(), Utc::now()),
            Err(GrantError::WrongDevice)
        ));
    }
}
