#![forbid(unsafe_code)]

use std::fmt;

use rand::RngCore;
use rcgen::{
    BasicConstraints, CertificateParams, CertificateSigningRequestParams, CertifiedIssuer,
    DistinguishedName, DnType, DnValue, ExtendedKeyUsagePurpose, IsCa, Issuer, KeyPair,
    KeyUsagePurpose, SerialNumber,
};
use sha2::{Digest, Sha256};
use thiserror::Error;
use time::{Duration, OffsetDateTime};
use uuid::Uuid;
use x509_parser::{parse_x509_certificate, pem::parse_x509_pem};

const ROOT_VALIDITY_DAYS: i64 = 15 * 365;
const ISSUER_VALIDITY_DAYS: i64 = 3 * 365;
const SERVER_VALIDITY_DAYS: i64 = 90;
const IDENTITY_VALIDITY_DAYS: i64 = 90;
const SIGNING_CHAIN_SAFETY_MARGIN_DAYS: i64 = 1;
const MINIMUM_LEAF_VALIDITY_DAYS: i64 = 31;
const MINIMUM_ISSUER_VALIDITY_DAYS: i64 = 120;

pub struct CertificateAuthority {
    issuer: CertifiedIssuer<'static, KeyPair>,
}

#[derive(Debug)]
pub struct PkiHierarchy {
    pub root: CertificateAuthority,
    pub server_issuer: CertificateAuthority,
    pub client_issuer: CertificateAuthority,
    pub admin_issuer: CertificateAuthority,
}

#[derive(Clone)]
pub struct OnlineIssuerRotation {
    pub server_certificate_pem: String,
    pub server_private_key_pem: String,
    pub client_certificate_pem: String,
    pub client_private_key_pem: String,
    pub admin_certificate_pem: String,
    pub admin_private_key_pem: String,
}

#[derive(Clone)]
pub struct PemIdentity {
    pub certificate_chain_pem: String,
    pub private_key_pem: String,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum IdentityCertificateKind {
    Client,
    Admin,
}

#[derive(Debug, Clone)]
pub struct IssuedCertificate {
    pub certificate_chain_pem: String,
    pub fingerprint_sha256: String,
    pub serial_hex: String,
    pub expires_at: OffsetDateTime,
}

#[derive(Debug, Error)]
pub enum PkiError {
    #[error("certificate generation failed: {0}")]
    Rcgen(#[from] rcgen::Error),
    #[error("public host must not be empty")]
    EmptyPublicHost,
    #[error("identity name must not be empty")]
    EmptyIdentityName,
    #[error("certificate request common name does not match the requested identity")]
    CommonNameMismatch,
    #[error("certificate request common name uses an unsupported string encoding")]
    UnsupportedCommonName,
    #[error("certificate parsing failed: {0}")]
    CertificateParse(String),
    #[error("{kind} cannot be issued because its signing chain expires too soon ({available_until})")]
    InsufficientSigningValidity {
        kind: &'static str,
        available_until: OffsetDateTime,
    },
}

impl CertificateAuthority {
    #[must_use]
    pub fn certificate_pem(&self) -> String {
        self.issuer.pem()
    }

    #[must_use]
    pub fn private_key_pem(&self) -> String {
        self.issuer.key().serialize_pem()
    }

    #[must_use]
    pub fn certificate_sha256(&self) -> String {
        certificate_sha256(self.issuer.der())
    }
}

impl fmt::Debug for CertificateAuthority {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("CertificateAuthority")
            .field("certificate_sha256", &self.certificate_sha256())
            .field("private_key", &"[REDACTED]")
            .finish()
    }
}

impl fmt::Debug for OnlineIssuerRotation {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("OnlineIssuerRotation")
            .field("server_certificate_pem", &"[CERTIFICATE PEM]")
            .field("server_private_key_pem", &"[REDACTED]")
            .field("client_certificate_pem", &"[CERTIFICATE PEM]")
            .field("client_private_key_pem", &"[REDACTED]")
            .field("admin_certificate_pem", &"[CERTIFICATE PEM]")
            .field("admin_private_key_pem", &"[REDACTED]")
            .finish()
    }
}

impl fmt::Debug for PemIdentity {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("PemIdentity")
            .field("certificate_chain_pem", &"[CERTIFICATE CHAIN PEM]")
            .field("private_key_pem", &"[REDACTED]")
            .finish()
    }
}

impl PkiHierarchy {
    /// Generates an offline root and separate server, client, and admin issuers.
    ///
    /// # Errors
    ///
    /// Returns an error if secure key or certificate generation fails.
    pub fn generate() -> Result<Self, PkiError> {
        let root = self_signed_ca("CentralD Offline Root CA", true)?;
        let server_issuer = signed_ca("CentralD Server Issuing CA", &root)?;
        let client_issuer = signed_ca("CentralD Client Issuing CA", &root)?;
        let admin_issuer = signed_ca("CentralD Admin Issuing CA", &root)?;
        Ok(Self {
            root,
            server_issuer,
            client_issuer,
            admin_issuer,
        })
    }

    /// Issues a server identity for the configured public DNS name or IP.
    ///
    /// # Errors
    ///
    /// Returns an error when the public host is empty or certificate/key
    /// generation fails.
    pub fn issue_server(&self, public_host: &str) -> Result<PemIdentity, PkiError> {
        if public_host.trim().is_empty() {
            return Err(PkiError::EmptyPublicHost);
        }
        let mut params = CertificateParams::new(vec![public_host.to_owned()])?;
        params.distinguished_name = common_name("CentralD Server");
        params.extended_key_usages = vec![ExtendedKeyUsagePurpose::ServerAuth];
        params.key_usages = vec![
            KeyUsagePurpose::DigitalSignature,
            KeyUsagePurpose::KeyEncipherment,
        ];
        apply_leaf_validity(
            &mut params,
            SERVER_VALIDITY_DAYS,
            "server TLS certificate",
            &[
                certificate_not_after(&self.server_issuer.certificate_pem())?,
                certificate_not_after(&self.root.certificate_pem())?,
            ],
        )?;
        params.serial_number = Some(SerialNumber::from_slice(&fresh_certificate_serial()));
        let key = KeyPair::generate()?;
        let certificate = params.signed_by(&key, &self.server_issuer.issuer)?;
        Ok(PemIdentity {
            certificate_chain_pem: format!(
                "{}{}{}",
                certificate.pem(),
                self.server_issuer.issuer.pem(),
                self.root.issuer.pem()
            ),
            private_key_pem: key.serialize_pem(),
        })
    }
}

/// Generates replacement online server/client/Admin issuers from the offline
/// root recovery certificate and private key. The root itself is not replaced.
///
/// # Errors
///
/// Returns an error when the recovery certificate/key are malformed, do not
/// belong together, or a replacement issuer cannot be generated.
pub fn rotate_online_issuers(
    root_certificate_pem: &str,
    root_private_key_pem: &str,
) -> Result<OnlineIssuerRotation, PkiError> {
    let (_, root_pem) = parse_x509_pem(root_certificate_pem.as_bytes())
        .map_err(|error| PkiError::CertificateParse(error.to_string()))?;
    let (_, root_certificate) = parse_x509_certificate(&root_pem.contents)
        .map_err(|error| PkiError::CertificateParse(error.to_string()))?;
    let root_key = KeyPair::from_pem(root_private_key_pem)?;
    if root_certificate.public_key().subject_public_key.data.as_ref() != root_key.public_key_raw() {
        return Err(PkiError::CertificateParse(
            "offline root recovery private key does not match the root certificate".into(),
        ));
    }
    let root_not_after = root_certificate.validity().not_after.to_datetime();
    let root_issuer = Issuer::from_ca_cert_pem(root_certificate_pem, root_key)?;
    let server = signed_ca_with_issuer(
        "CentralD Server Issuing CA",
        &root_issuer,
        root_not_after,
    )?;
    let client = signed_ca_with_issuer(
        "CentralD Client Issuing CA",
        &root_issuer,
        root_not_after,
    )?;
    let admin = signed_ca_with_issuer(
        "CentralD Admin Issuing CA",
        &root_issuer,
        root_not_after,
    )?;
    Ok(OnlineIssuerRotation {
        server_certificate_pem: server.certificate_pem(),
        server_private_key_pem: server.private_key_pem(),
        client_certificate_pem: client.certificate_pem(),
        client_private_key_pem: client.private_key_pem(),
        admin_certificate_pem: admin.certificate_pem(),
        admin_private_key_pem: admin.private_key_pem(),
    })
}

/// Issues a server identity from persisted online issuer material.
///
/// This is used when a local administrator changes the public TLS name. The
/// offline root key is not required because the online server issuer is
/// retained by the server.
///
/// # Errors
///
/// Returns an error for an empty host, malformed issuer material, or signing
/// failure.
pub fn issue_server_identity(
    public_host: &str,
    issuer_certificate_pem: &str,
    issuer_private_key_pem: &str,
    root_certificate_pem: &str,
) -> Result<PemIdentity, PkiError> {
    if public_host.trim().is_empty() {
        return Err(PkiError::EmptyPublicHost);
    }
    let mut params = CertificateParams::new(vec![public_host.to_owned()])?;
    params.distinguished_name = common_name("CentralD Server");
    params.extended_key_usages = vec![ExtendedKeyUsagePurpose::ServerAuth];
    params.key_usages = vec![
        KeyUsagePurpose::DigitalSignature,
        KeyUsagePurpose::KeyEncipherment,
    ];
    apply_leaf_validity(
        &mut params,
        SERVER_VALIDITY_DAYS,
        "server TLS certificate",
        &[
            certificate_not_after(issuer_certificate_pem)?,
            certificate_not_after(root_certificate_pem)?,
        ],
    )?;
    params.serial_number = Some(SerialNumber::from_slice(&fresh_certificate_serial()));
    let key = KeyPair::generate()?;
    let issuer_key = KeyPair::from_pem(issuer_private_key_pem)?;
    let issuer = Issuer::from_ca_cert_pem(issuer_certificate_pem, issuer_key)?;
    let certificate = params.signed_by(&key, &issuer)?;
    Ok(PemIdentity {
        certificate_chain_pem: format!(
            "{}{}{}",
            certificate.pem(),
            issuer_certificate_pem,
            root_certificate_pem
        ),
        private_key_pem: key.serialize_pem(),
    })
}

/// Generates an ephemeral client-auth identity for server-local TLS health
/// probing. The private key is returned only to the caller and is never stored.
///
/// # Errors
///
/// Returns an error when key generation, CSR creation, or issuer signing fails.
pub fn issue_ephemeral_identity(
    name: &str,
    kind: IdentityCertificateKind,
    issuer_certificate_pem: &str,
    issuer_private_key_pem: &str,
    root_certificate_pem: &str,
) -> Result<PemIdentity, PkiError> {
    let key = KeyPair::generate()?;
    let mut params = CertificateParams::default();
    params.distinguished_name = common_name(name);
    params.key_usages = vec![KeyUsagePurpose::DigitalSignature];
    params.extended_key_usages = vec![ExtendedKeyUsagePurpose::ClientAuth];
    let csr = params.serialize_request(&key)?.pem()?;
    let issued = issue_identity_csr(
        &csr,
        name,
        Uuid::now_v7(),
        kind,
        issuer_certificate_pem,
        issuer_private_key_pem,
        root_certificate_pem,
    )?;
    Ok(PemIdentity {
        certificate_chain_pem: issued.certificate_chain_pem,
        private_key_pem: key.serialize_pem(),
    })
}

/// Verifies and signs an identity CSR with a role-specific issuing CA.
///
/// The CSR signature and common name are verified before `CentralD` replaces all
/// caller-controlled certificate policy fields with its own end-entity policy.
///
/// # Errors
///
/// Returns an error for malformed or invalid CSRs, an identity mismatch, an
/// unsupported subject encoding, invalid issuer material, or signing failure.
pub fn issue_identity_csr(
    csr_pem: &str,
    expected_name: &str,
    _identity_id: Uuid,
    kind: IdentityCertificateKind,
    issuer_certificate_pem: &str,
    issuer_private_key_pem: &str,
    root_certificate_pem: &str,
) -> Result<IssuedCertificate, PkiError> {
    if expected_name.trim().is_empty() {
        return Err(PkiError::EmptyIdentityName);
    }

    let mut request = CertificateSigningRequestParams::from_pem(csr_pem)?;
    let requested_name = request
        .params
        .distinguished_name
        .get(&DnType::CommonName)
        .ok_or(PkiError::CommonNameMismatch)
        .and_then(dn_value_as_str)?;
    if requested_name != expected_name {
        return Err(PkiError::CommonNameMismatch);
    }

    let now = OffsetDateTime::now_utc();
    let expires_at = bounded_not_after(
        now,
        IDENTITY_VALIDITY_DAYS,
        "client/Admin identity certificate",
        &[
            certificate_not_after(issuer_certificate_pem)?,
            certificate_not_after(root_certificate_pem)?,
        ],
        MINIMUM_LEAF_VALIDITY_DAYS,
    )?;
    request.params.distinguished_name = common_name(expected_name);
    request.params.distinguished_name.push(
        DnType::OrganizationalUnitName,
        match kind {
            IdentityCertificateKind::Client => "client",
            IdentityCertificateKind::Admin => "admin",
        },
    );
    request.params.is_ca = IsCa::NoCa;
    request.params.subject_alt_names.clear();
    request.params.key_usages = vec![KeyUsagePurpose::DigitalSignature];
    request.params.extended_key_usages = vec![ExtendedKeyUsagePurpose::ClientAuth];
    request.params.not_before = now - Duration::minutes(5);
    request.params.not_after = expires_at;
    let serial = fresh_certificate_serial();
    request.params.serial_number = Some(SerialNumber::from_slice(&serial));

    let issuer_key = KeyPair::from_pem(issuer_private_key_pem)?;
    let issuer = Issuer::from_ca_cert_pem(issuer_certificate_pem, issuer_key)?;
    let certificate = request.signed_by(&issuer)?;
    Ok(IssuedCertificate {
        certificate_chain_pem: format!(
            "{}{}{}",
            certificate.pem(),
            issuer_certificate_pem,
            root_certificate_pem
        ),
        fingerprint_sha256: certificate_sha256(certificate.der()),
        serial_hex: hex::encode(serial),
        expires_at,
    })
}

fn apply_leaf_validity(
    params: &mut CertificateParams,
    validity_days: i64,
    kind: &'static str,
    parent_not_after: &[OffsetDateTime],
) -> Result<OffsetDateTime, PkiError> {
    let now = OffsetDateTime::now_utc();
    let expires_at = bounded_not_after(
        now,
        validity_days,
        kind,
        parent_not_after,
        MINIMUM_LEAF_VALIDITY_DAYS,
    )?;
    params.not_before = now - Duration::minutes(5);
    params.not_after = expires_at;
    Ok(expires_at)
}

fn apply_ca_validity(params: &mut CertificateParams, validity_days: i64) {
    let now = OffsetDateTime::now_utc();
    params.not_before = now - Duration::days(1);
    params.not_after = now + Duration::days(validity_days);
}

fn apply_signed_ca_validity(
    params: &mut CertificateParams,
    parent_not_after: OffsetDateTime,
) -> Result<(), PkiError> {
    let now = OffsetDateTime::now_utc();
    params.not_before = now - Duration::days(1);
    params.not_after = bounded_not_after(
        now,
        ISSUER_VALIDITY_DAYS,
        "online issuing CA",
        &[parent_not_after],
        MINIMUM_ISSUER_VALIDITY_DAYS,
    )?;
    Ok(())
}

fn bounded_not_after(
    now: OffsetDateTime,
    requested_days: i64,
    kind: &'static str,
    parent_not_after: &[OffsetDateTime],
    minimum_days: i64,
) -> Result<OffsetDateTime, PkiError> {
    let requested = now + Duration::days(requested_days);
    let parent_limit = parent_not_after
        .iter()
        .copied()
        .min()
        .map(|value| value - Duration::days(SIGNING_CHAIN_SAFETY_MARGIN_DAYS))
        .unwrap_or(requested);
    let expires_at = requested.min(parent_limit);
    if expires_at <= now + Duration::days(minimum_days) {
        return Err(PkiError::InsufficientSigningValidity {
            kind,
            available_until: parent_limit,
        });
    }
    Ok(expires_at)
}

/// Returns the expiration time of the first certificate in a PEM chain.
///
/// # Errors
///
/// Returns an error when the PEM or X.509 certificate cannot be parsed.
pub fn certificate_not_after(pem_text: &str) -> Result<OffsetDateTime, PkiError> {
    let (_, pem) = parse_x509_pem(pem_text.as_bytes())
        .map_err(|error| PkiError::CertificateParse(error.to_string()))?;
    let (_, certificate) = parse_x509_certificate(&pem.contents)
        .map_err(|error| PkiError::CertificateParse(error.to_string()))?;
    Ok(certificate.validity().not_after.to_datetime())
}

fn fresh_certificate_serial() -> [u8; 20] {
    let mut serial = [0_u8; 20];
    rand::rng().fill_bytes(&mut serial);
    // RFC 5280 serials are positive and non-zero. Clearing the sign bit also
    // keeps the DER INTEGER within the required 20-octet representation.
    serial[0] &= 0x7f;
    if serial.iter().all(|byte| *byte == 0) {
        serial[19] = 1;
    }
    serial
}

#[must_use]
pub fn certificate_sha256(der: &[u8]) -> String {
    hex::encode(Sha256::digest(der))
}

fn dn_value_as_str(value: &DnValue) -> Result<&str, PkiError> {
    match value {
        DnValue::Utf8String(value) => Ok(value),
        DnValue::Ia5String(value) => Ok(value.as_ref()),
        DnValue::PrintableString(value) => Ok(value.as_ref()),
        DnValue::TeletexString(value) => Ok(value.as_ref()),
        _ => Err(PkiError::UnsupportedCommonName),
    }
}

fn self_signed_ca(name: &str, unconstrained: bool) -> Result<CertificateAuthority, PkiError> {
    let mut params = CertificateParams::default();
    params.distinguished_name = common_name(name);
    params.is_ca = IsCa::Ca(if unconstrained {
        BasicConstraints::Unconstrained
    } else {
        BasicConstraints::Constrained(0)
    });
    params.key_usages = vec![
        KeyUsagePurpose::KeyCertSign,
        KeyUsagePurpose::CrlSign,
        KeyUsagePurpose::DigitalSignature,
    ];
    apply_ca_validity(&mut params, ROOT_VALIDITY_DAYS);
    params.serial_number = Some(SerialNumber::from_slice(&fresh_certificate_serial()));
    let key = KeyPair::generate()?;
    let issuer = CertifiedIssuer::self_signed(params, key)?;
    Ok(CertificateAuthority { issuer })
}

fn signed_ca(name: &str, issuer: &CertificateAuthority) -> Result<CertificateAuthority, PkiError> {
    signed_ca_with_issuer(
        name,
        &issuer.issuer,
        certificate_not_after(&issuer.certificate_pem())?,
    )
}

fn signed_ca_with_issuer(
    name: &str,
    issuer: &Issuer<'_, impl rcgen::SigningKey>,
    parent_not_after: OffsetDateTime,
) -> Result<CertificateAuthority, PkiError> {
    let mut params = CertificateParams::default();
    params.distinguished_name = common_name(name);
    params.is_ca = IsCa::Ca(BasicConstraints::Constrained(0));
    params.key_usages = vec![
        KeyUsagePurpose::KeyCertSign,
        KeyUsagePurpose::CrlSign,
        KeyUsagePurpose::DigitalSignature,
    ];
    apply_signed_ca_validity(&mut params, parent_not_after)?;
    params.serial_number = Some(SerialNumber::from_slice(&fresh_certificate_serial()));
    let key = KeyPair::generate()?;
    let signed = CertifiedIssuer::signed_by(params, key, issuer)?;
    Ok(CertificateAuthority { issuer: signed })
}

fn common_name(name: &str) -> DistinguishedName {
    let mut distinguished_name = DistinguishedName::new();
    distinguished_name.push(DnType::CommonName, name);
    distinguished_name
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used)]
mod tests {
    use super::*;

    #[test]
    fn secret_bearing_debug_output_is_redacted() {
        let hierarchy = PkiHierarchy::generate().expect("hierarchy");
        let identity = hierarchy
            .issue_server("centrald.home.arpa")
            .expect("server identity");
        let authority_debug = format!("{:?}", hierarchy.server_issuer);
        let identity_debug = format!("{identity:?}");
        assert!(!authority_debug.contains("PRIVATE KEY"));
        assert!(!identity_debug.contains("PRIVATE KEY"));
        assert!(authority_debug.contains("[REDACTED]"));
        assert!(identity_debug.contains("[REDACTED]"));
    }

    #[test]
    fn hierarchy_has_stable_root_fingerprint_and_server_chain() {
        let hierarchy = PkiHierarchy::generate().unwrap();
        assert_eq!(hierarchy.root.certificate_sha256().len(), 64);
        let server = hierarchy.issue_server("centrald.home.arpa").unwrap();
        assert!(
            server
                .certificate_chain_pem
                .matches("BEGIN CERTIFICATE")
                .count()
                >= 3
        );
        assert!(server.private_key_pem.contains("PRIVATE KEY"));
        let server_expiry = certificate_not_after(&server.certificate_chain_pem).unwrap();
        let now = OffsetDateTime::now_utc();
        assert!(server_expiry > now + Duration::days(80));
        assert!(server_expiry < now + Duration::days(100));
        let root_expiry = certificate_not_after(&hierarchy.root.certificate_pem()).unwrap();
        assert!(root_expiry < now + Duration::days(16 * 365));
        let issuer_expiry =
            certificate_not_after(&hierarchy.server_issuer.certificate_pem()).unwrap();
        assert!(issuer_expiry < now + Duration::days(4 * 365));

        let rotated = rotate_online_issuers(
            &hierarchy.root.certificate_pem(),
            &hierarchy.root.private_key_pem(),
        )
        .unwrap();
        assert!(rotated.server_certificate_pem.contains("BEGIN CERTIFICATE"));
        assert!(rotated.client_private_key_pem.contains("PRIVATE KEY"));
        assert!(rotated.admin_private_key_pem.contains("PRIVATE KEY"));
    }

    #[test]
    fn identity_csr_is_bound_to_claimed_name() {
        let hierarchy = PkiHierarchy::generate().unwrap();
        let key = KeyPair::generate().unwrap();
        let mut params = CertificateParams::default();
        params.distinguished_name = common_name("node-1");
        let csr = params.serialize_request(&key).unwrap().pem().unwrap();

        let issued = issue_identity_csr(
            &csr,
            "node-1",
            Uuid::now_v7(),
            IdentityCertificateKind::Client,
            &hierarchy.client_issuer.certificate_pem(),
            &hierarchy.client_issuer.private_key_pem(),
            &hierarchy.root.certificate_pem(),
        )
        .unwrap();
        assert_eq!(
            issued
                .certificate_chain_pem
                .matches("BEGIN CERTIFICATE")
                .count(),
            3
        );
        let renewed = issue_identity_csr(
            &csr,
            "node-1",
            Uuid::now_v7(),
            IdentityCertificateKind::Client,
            &hierarchy.client_issuer.certificate_pem(),
            &hierarchy.client_issuer.private_key_pem(),
            &hierarchy.root.certificate_pem(),
        )
        .unwrap();
        assert_ne!(issued.serial_hex, renewed.serial_hex);
        assert_eq!(issued.serial_hex.len(), 40);
        assert!(matches!(
            issue_identity_csr(
                &csr,
                "different-node",
                Uuid::now_v7(),
                IdentityCertificateKind::Client,
                &hierarchy.client_issuer.certificate_pem(),
                &hierarchy.client_issuer.private_key_pem(),
                &hierarchy.root.certificate_pem(),
            ),
            Err(PkiError::CommonNameMismatch)
        ));
    }
    #[test]
    fn child_validity_is_capped_by_the_signing_chain() {
        let now = OffsetDateTime::now_utc();
        let parent = now + Duration::days(45);
        let expiry = bounded_not_after(
            now,
            90,
            "test leaf",
            &[parent],
            31,
        )
        .expect("45-day parent should permit a bounded leaf");
        assert!(expiry <= parent - Duration::days(1));
        assert!(expiry > now + Duration::days(31));
    }

    #[test]
    fn issuance_fails_before_a_renewal_window_can_be_honored() {
        let now = OffsetDateTime::now_utc();
        let result = bounded_not_after(
            now,
            90,
            "test leaf",
            &[now + Duration::days(20)],
            31,
        );
        assert!(matches!(
            result,
            Err(PkiError::InsufficientSigningValidity { .. })
        ));
    }

}
