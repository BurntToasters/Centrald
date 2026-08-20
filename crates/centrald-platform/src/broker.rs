use std::collections::{HashSet, VecDeque};

use centrald_common::grant::{GrantError, GrantOperation, SignedGrant};
use chrono::{DateTime, Utc};
use ed25519_dalek::VerifyingKey;
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use thiserror::Error;
use uuid::Uuid;

const MAX_REPLAY_ENTRIES: usize = 4096;
const MAX_PARAMETERS_BYTES: usize = 64 * 1024;
const MAX_OUTPUT_BYTES: usize = 256 * 1024;

/// Hard bound for a single broker-wire request (the signed grant plus exact
/// parameter bytes).
pub const MAX_WIRE_REQUEST_BYTES: usize = 16 * 1024;
/// Hard bound for a single broker-wire response. Operation output is capped at
/// 64 KiB but JSON encoding of raw bytes expands roughly 4x, so the encoded
/// response bound is sized to fit the maximum legal encoded output.
pub const MAX_WIRE_RESPONSE_BYTES: usize = 384 * 1024;

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct BrokerRequest {
    pub signed_grant: SignedGrant,
    pub parameters_json: Vec<u8>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct BrokerResponse {
    pub success: bool,
    pub output: Vec<u8>,
    pub exit_code: i32,
}

pub trait OperationRunner {
    type Error: std::error::Error + Send + Sync + 'static;

    /// Executes one allowlisted typed operation.
    ///
    /// # Errors
    ///
    /// Returns the platform runner's bounded operation error.
    fn run(
        &mut self,
        operation: &GrantOperation,
        parameters_json: &[u8],
    ) -> Result<BrokerResponse, Self::Error>;
}

#[derive(Debug)]
pub struct GrantVerifier {
    device_id: Uuid,
    signing_key: VerifyingKey,
    consumed: HashSet<Uuid>,
    order: VecDeque<(Uuid, DateTime<Utc>)>,
}

#[derive(Debug, Error)]
pub enum BrokerError {
    #[error(transparent)]
    InvalidGrant(#[from] GrantError),
    #[error("grant was already consumed")]
    Replay,
    #[error("operation parameters exceed the broker limit")]
    ParametersTooLarge,
    #[error("operation parameters do not match the signed grant")]
    ParametersMismatch,
    #[error("privileged operation failed: {0}")]
    Operation(String),
    #[error("privileged operation output exceeded the broker limit")]
    OutputTooLarge,
    #[error("grant replay set is full of still-valid grants")]
    ReplaySetFull,
}

impl GrantVerifier {
    #[must_use]
    pub fn new(device_id: Uuid, signing_key: VerifyingKey) -> Self {
        Self {
            device_id,
            signing_key,
            consumed: HashSet::new(),
            order: VecDeque::new(),
        }
    }

    /// Restores a previously persisted consumed grant into the in-memory set.
    pub fn restore(&mut self, grant_id: Uuid, expires_at: DateTime<Utc>, now: DateTime<Utc>) {
        if expires_at <= now {
            return;
        }
        if self.consumed.insert(grant_id) {
            self.order.push_back((grant_id, expires_at));
        }
    }

    /// Verifies a broker grant and records its identifier against replay.
    ///
    /// # Errors
    ///
    /// Returns an error when grant verification fails or the grant identifier
    /// has already been consumed.
    pub fn verify_and_consume(
        &mut self,
        grant: &SignedGrant,
        now: DateTime<Utc>,
    ) -> Result<(), BrokerError> {
        grant.verify(&self.signing_key, self.device_id, now)?;
        self.prune_expired(now);
        if !self.consumed.insert(grant.grant.id) {
            return Err(BrokerError::Replay);
        }
        self.order
            .push_back((grant.grant.id, grant.grant.expires_at));
        if self.order.len() > MAX_REPLAY_ENTRIES {
            self.consumed.remove(&grant.grant.id);
            self.order.pop_back();
            return Err(BrokerError::ReplaySetFull);
        }
        Ok(())
    }

    fn prune_expired(&mut self, now: DateTime<Utc>) {
        while let Some((id, expires_at)) = self.order.front().copied() {
            if expires_at > now {
                break;
            }
            self.order.pop_front();
            self.consumed.remove(&id);
        }
    }

    /// Verifies and consumes a grant, validates its exact parameter bytes, and
    /// dispatches only the typed operation carried by the signed grant.
    ///
    /// # Errors
    ///
    /// Returns an error for invalid/replayed grants, oversized or mismatched
    /// parameters, runner failure, or oversized command output.
    pub fn execute<R: OperationRunner>(
        &mut self,
        request: &BrokerRequest,
        now: DateTime<Utc>,
        runner: &mut R,
    ) -> Result<BrokerResponse, BrokerError> {
        self.verify_and_consume(&request.signed_grant, now)?;
        if request.parameters_json.len() > MAX_PARAMETERS_BYTES {
            return Err(BrokerError::ParametersTooLarge);
        }
        let digest = hex::encode(Sha256::digest(&request.parameters_json));
        if digest != request.signed_grant.grant.parameters_sha256 {
            return Err(BrokerError::ParametersMismatch);
        }
        let response = runner
            .run(
                &request.signed_grant.grant.operation,
                &request.parameters_json,
            )
            .map_err(|error| BrokerError::Operation(error.to_string()))?;
        if response.output.len() > MAX_OUTPUT_BYTES {
            return Err(BrokerError::OutputTooLarge);
        }
        Ok(response)
    }
}

#[cfg(test)]
#[allow(clippy::unwrap_used)]
mod tests {
    use centrald_common::grant::{GrantOperation, PrivilegedGrant};
    use chrono::Duration;
    use ed25519_dalek::SigningKey;
    use uuid::Uuid;

    use super::*;

    #[derive(Debug, thiserror::Error)]
    #[error("fake runner failed")]
    struct FakeError;

    #[derive(Debug, Default)]
    struct FakeRunner {
        calls: usize,
    }

    impl OperationRunner for FakeRunner {
        type Error = FakeError;

        fn run(
            &mut self,
            _operation: &GrantOperation,
            _parameters_json: &[u8],
        ) -> Result<BrokerResponse, Self::Error> {
            self.calls += 1;
            Ok(BrokerResponse {
                success: true,
                output: b"ok".to_vec(),
                exit_code: 0,
            })
        }
    }

    fn request(device_id: Uuid, key: &SigningKey, parameters: &[u8]) -> BrokerRequest {
        request_at(device_id, key, parameters, Utc::now())
    }

    fn request_at(
        device_id: Uuid,
        key: &SigningKey,
        parameters: &[u8],
        now: DateTime<Utc>,
    ) -> BrokerRequest {
        let grant = PrivilegedGrant {
            id: Uuid::now_v7(),
            device_id,
            job_or_session_id: Uuid::now_v7(),
            admin_id: Uuid::now_v7(),
            operation: GrantOperation::RestartMachine,
            parameters_sha256: hex::encode(Sha256::digest(parameters)),
            issued_at: now - Duration::seconds(1),
            expires_at: now + Duration::hours(1),
            nonce: Uuid::now_v7().to_string(),
        };
        BrokerRequest {
            signed_grant: grant.sign(key).unwrap(),
            parameters_json: parameters.to_vec(),
        }
    }

    #[test]
    fn executes_once_and_burns_mismatched_grants() {
        let key = SigningKey::from_bytes(&[9_u8; 32]);
        let device = Uuid::now_v7();
        let mut verifier = GrantVerifier::new(device, key.verifying_key());
        let mut runner = FakeRunner::default();
        let valid = request(device, &key, b"{}");
        assert!(verifier.execute(&valid, Utc::now(), &mut runner).is_ok());
        assert_eq!(runner.calls, 1);
        assert!(matches!(
            verifier.execute(&valid, Utc::now(), &mut runner),
            Err(BrokerError::Replay)
        ));

        let mut tampered = request(device, &key, b"{}");
        tampered.parameters_json = b"{\"delay\":999}".to_vec();
        assert!(matches!(
            verifier.execute(&tampered, Utc::now(), &mut runner),
            Err(BrokerError::ParametersMismatch)
        ));
        assert!(matches!(
            verifier.execute(&tampered, Utc::now(), &mut runner),
            Err(BrokerError::Replay)
        ));
        assert_eq!(runner.calls, 1);
    }

    #[test]
    fn refuses_to_evict_unexpired_grants() {
        let key = SigningKey::from_bytes(&[9_u8; 32]);
        let device = Uuid::now_v7();
        let mut verifier = GrantVerifier::new(device, key.verifying_key());
        let now = Utc::now();
        let first = request_at(device, &key, b"{}", now);
        assert!(
            verifier
                .verify_and_consume(&first.signed_grant, now)
                .is_ok()
        );
        for _ in 1..4096 {
            let extra = request_at(device, &key, b"{}", now);
            verifier
                .verify_and_consume(&extra.signed_grant, now)
                .unwrap();
        }
        let overflow = request_at(device, &key, b"{}", now);
        assert!(matches!(
            verifier.verify_and_consume(&overflow.signed_grant, now),
            Err(BrokerError::ReplaySetFull)
        ));
        assert!(matches!(
            verifier.verify_and_consume(&first.signed_grant, now),
            Err(BrokerError::Replay)
        ));
    }
}
