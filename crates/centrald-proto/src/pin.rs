//! TLS trust pinned to the server's certificate authority fingerprint.
//!
//! Agents never consult the system trust store and never trust on first use.
//! A connection is accepted only when the presented chain contains the CA
//! whose SHA-256 fingerprint was delivered in the join code, and the leaf
//! verifies under that CA for [`AGENT_TLS_NAME`](crate::AGENT_TLS_NAME).

use std::sync::Arc;

use rustls::client::WebPkiServerVerifier;
use rustls::client::danger::{HandshakeSignatureValid, ServerCertVerified, ServerCertVerifier};
use rustls::crypto::{CryptoProvider, verify_tls12_signature, verify_tls13_signature};
use rustls::pki_types::{CertificateDer, ServerName, UnixTime};
use rustls::{ClientConfig, DigitallySignedStruct, RootCertStore, SignatureScheme};

use crate::{AGENT_TLS_NAME, sha256};

#[derive(Debug)]
struct PinnedCaVerifier {
    fingerprint: [u8; 32],
    provider: Arc<CryptoProvider>,
}

impl ServerCertVerifier for PinnedCaVerifier {
    fn verify_server_cert(
        &self,
        end_entity: &CertificateDer<'_>,
        intermediates: &[CertificateDer<'_>],
        _server_name: &ServerName<'_>,
        ocsp_response: &[u8],
        now: UnixTime,
    ) -> Result<ServerCertVerified, rustls::Error> {
        let authority = intermediates
            .iter()
            .find(|certificate| sha256(certificate.as_ref()) == self.fingerprint)
            .ok_or_else(|| {
                rustls::Error::General(
                    "the server's certificate authority does not match the pinned fingerprint"
                        .to_owned(),
                )
            })?;
        let mut roots = RootCertStore::empty();
        roots.add(authority.clone().into_owned())?;
        let verifier =
            WebPkiServerVerifier::builder_with_provider(Arc::new(roots), self.provider.clone())
                .build()
                .map_err(|error| rustls::Error::General(error.to_string()))?;
        let name = ServerName::try_from(AGENT_TLS_NAME)
            .map_err(|error| rustls::Error::General(error.to_string()))?;
        verifier.verify_server_cert(end_entity, &[], &name, ocsp_response, now)
    }

    fn verify_tls12_signature(
        &self,
        message: &[u8],
        cert: &CertificateDer<'_>,
        dss: &DigitallySignedStruct,
    ) -> Result<HandshakeSignatureValid, rustls::Error> {
        verify_tls12_signature(
            message,
            cert,
            dss,
            &self.provider.signature_verification_algorithms,
        )
    }

    fn verify_tls13_signature(
        &self,
        message: &[u8],
        cert: &CertificateDer<'_>,
        dss: &DigitallySignedStruct,
    ) -> Result<HandshakeSignatureValid, rustls::Error> {
        verify_tls13_signature(
            message,
            cert,
            dss,
            &self.provider.signature_verification_algorithms,
        )
    }

    fn supported_verify_schemes(&self) -> Vec<SignatureScheme> {
        self.provider
            .signature_verification_algorithms
            .supported_schemes()
    }
}

/// Builds the only TLS client configuration agents use.
pub fn client_config(ca_fingerprint: [u8; 32]) -> Result<Arc<ClientConfig>, rustls::Error> {
    let provider = Arc::new(rustls::crypto::ring::default_provider());
    let mut config = ClientConfig::builder_with_provider(provider.clone())
        .with_protocol_versions(&[&rustls::version::TLS13])?
        .dangerous()
        .with_custom_certificate_verifier(Arc::new(PinnedCaVerifier {
            fingerprint: ca_fingerprint,
            provider,
        }))
        .with_no_client_auth();
    config.alpn_protocols = vec![b"http/1.1".to_vec()];
    Ok(Arc::new(config))
}

/// The server name agents send as SNI and verify.
pub fn server_name() -> Result<ServerName<'static>, rustls::Error> {
    ServerName::try_from(AGENT_TLS_NAME).map_err(|error| rustls::Error::General(error.to_string()))
}
