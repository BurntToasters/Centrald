//! Server TLS: a private certificate authority and a leaf it signs.
//!
//! The CA is created once and is what agents pin. The leaf lists every name
//! and address this host answers to (so browsers that trust the CA see a
//! matching certificate) and is re-issued automatically when addresses change
//! or expiry approaches. The leaf key stays the same across re-issues, which
//! keeps the public-key pin used by the install command stable.

use std::collections::BTreeSet;
use std::net::IpAddr;
use std::path::{Path, PathBuf};
use std::sync::{Arc, PoisonError, RwLock};

use anyhow::{Context, Result, anyhow, bail};
use base64::Engine;
use centrald_proto::{AGENT_TLS_NAME, sha256};
use rcgen::{
    BasicConstraints, CertificateParams, DistinguishedName, DnType, ExtendedKeyUsagePurpose, IsCa,
    Issuer, KeyPair, KeyUsagePurpose,
};
use rustls::crypto::ring::sign::any_supported_type;
use rustls::pki_types::pem::PemObject;
use rustls::pki_types::{CertificateDer, PrivateKeyDer};
use rustls::server::{ClientHello, ResolvesServerCert};
use rustls::sign::CertifiedKey;
use serde::{Deserialize, Serialize};
use time::{Duration, OffsetDateTime};

use crate::config::ServerConfig;

const CA_VALIDITY_DAYS: i64 = 20 * 365;
/// Stays under the 398-day limit some browsers apply to every certificate.
const LEAF_VALIDITY_DAYS: i64 = 397;
const LEAF_RENEW_BEFORE_DAYS: i64 = 30;

#[derive(Debug)]
pub struct TlsState {
    pub config: Arc<rustls::ServerConfig>,
    pub ca_pem: String,
    pub ca_fingerprint: [u8; 32],
    resolver: Arc<Resolver>,
    directory: PathBuf,
    extra_names: Vec<String>,
}

#[derive(Debug, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "camelCase")]
struct LeafMeta {
    names: BTreeSet<String>,
    not_after: i64,
}

#[derive(Debug)]
struct Resolver {
    internal: RwLock<Arc<CertifiedKey>>,
    custom: Option<Arc<CertifiedKey>>,
}

impl ResolvesServerCert for Resolver {
    fn resolve(&self, hello: ClientHello<'_>) -> Option<Arc<CertifiedKey>> {
        let is_agent = hello
            .server_name()
            .is_some_and(|name| name.eq_ignore_ascii_case(AGENT_TLS_NAME));
        // Agents always get the pinned internal chain, even when an
        // operator-supplied certificate serves browsers.
        match &self.custom {
            Some(custom) if !is_agent => Some(custom.clone()),
            _ => Some(
                self.internal
                    .read()
                    .unwrap_or_else(PoisonError::into_inner)
                    .clone(),
            ),
        }
    }
}

impl TlsState {
    /// Loads the CA and server key, creating them only when `fresh` (a
    /// brand-new data directory). An existing install with a missing or
    /// mismatched file refuses to start instead of minting a new CA.
    pub fn load_or_create(config: &ServerConfig, fresh: bool) -> Result<Self> {
        let directory = config.tls_dir();
        let ca_cert_path = directory.join("ca.crt");
        let ca_key_path = directory.join("ca.key");
        let leaf_key_path = directory.join("server.key");
        if fresh {
            create_private_dir(&directory)?;
            create_authority(&ca_cert_path, &ca_key_path)?;
            let key = KeyPair::generate().context("generate server key")?;
            write_private(&leaf_key_path, key.serialize_pem().as_bytes())?;
        } else {
            for path in [&ca_cert_path, &ca_key_path, &leaf_key_path] {
                if !path.is_file() {
                    bail!(
                        "{} is missing, so devices could no longer trust this server; restore it from backup (CentralD never replaces its certificate authority on its own)",
                        path.display()
                    );
                }
            }
        }
        let ca_pem = std::fs::read_to_string(&ca_cert_path)
            .with_context(|| format!("cannot read {}", ca_cert_path.display()))?;
        let ca_der = CertificateDer::from_pem_slice(ca_pem.as_bytes()).map_err(|error| {
            anyhow!(
                "invalid CA certificate in {}: {error}",
                ca_cert_path.display()
            )
        })?;
        let ca_fingerprint = sha256(ca_der.as_ref());
        let ca_key = PrivateKeyDer::from_pem_file(&ca_key_path)
            .map_err(|error| anyhow!("invalid CA key in {}: {error}", ca_key_path.display()))?;
        let ca_signer = any_supported_type(&ca_key)
            .with_context(|| format!("unsupported CA key in {}", ca_key_path.display()))?;
        if CertifiedKey::new(vec![ca_der.clone()], ca_signer)
            .keys_match()
            .is_err()
        {
            bail!(
                "{} does not belong to {}; restore the matching pair from backup",
                ca_key_path.display(),
                ca_cert_path.display()
            );
        }
        load_key(&leaf_key_path)?;

        let custom = match (&config.tls_cert, &config.tls_key) {
            (Some(cert), Some(key)) => Some(Arc::new(load_custom(cert, key)?)),
            _ => None,
        };

        let extra_names = config.hostnames.clone();
        ensure_leaf(&directory, &extra_names)?;
        let internal = load_internal(&directory, &ca_der)?;
        if internal.keys_match().is_err() {
            bail!(
                "{} does not match the certificate in {}; restore server.key from backup, or delete server.crt and server.json to issue a new certificate for this key (install commands then pin the new key)",
                leaf_key_path.display(),
                directory.join("server.crt").display()
            );
        }
        let resolver = Arc::new(Resolver {
            internal: RwLock::new(Arc::new(internal)),
            custom,
        });

        let provider = Arc::new(rustls::crypto::ring::default_provider());
        let mut server_config = rustls::ServerConfig::builder_with_provider(provider)
            .with_safe_default_protocol_versions()
            .context("select TLS versions")?
            .with_no_client_auth()
            .with_cert_resolver(resolver.clone());
        server_config.alpn_protocols = vec![b"h2".to_vec(), b"http/1.1".to_vec()];

        Ok(Self {
            config: Arc::new(server_config),
            ca_pem,
            ca_fingerprint,
            resolver,
            directory,
            extra_names,
        })
    }

    /// Re-issues the leaf when this host's addresses changed or it nears
    /// expiry. Returns whether a new certificate was installed.
    pub fn refresh(&self) -> Result<bool> {
        if !ensure_leaf(&self.directory, &self.extra_names)? {
            return Ok(false);
        }
        let ca_der = CertificateDer::from_pem_slice(self.ca_pem.as_bytes())
            .map_err(|error| anyhow!("invalid CA certificate: {error}"))?;
        let internal = load_internal(&self.directory, &ca_der)?;
        *self
            .resolver
            .internal
            .write()
            .unwrap_or_else(PoisonError::into_inner) = Arc::new(internal);
        Ok(true)
    }

    /// The certificate a browser (or `curl`) reaching this host by name sees.
    fn browser_key(&self) -> Arc<CertifiedKey> {
        match &self.resolver.custom {
            Some(custom) => custom.clone(),
            None => self
                .resolver
                .internal
                .read()
                .unwrap_or_else(PoisonError::into_inner)
                .clone(),
        }
    }

    /// Pins for install commands: the `sha256//…` public-key pin `curl
    /// --pinnedpubkey` takes, and the uppercase hex SHA-256 of the leaf
    /// certificate that `PowerShell` compares.
    pub fn browser_pins(&self) -> (String, String) {
        let key = self.browser_key();
        let spki = key
            .key
            .public_key()
            .map(|spki| sha256(spki.as_ref()))
            .unwrap_or_default();
        let leaf = key
            .cert
            .first()
            .map(|leaf| sha256(leaf.as_ref()))
            .unwrap_or_default();
        (
            format!(
                "sha256//{}",
                base64::engine::general_purpose::STANDARD.encode(spki)
            ),
            hex::encode_upper(leaf),
        )
    }

    /// Names and addresses in the built-in certificate, minus the internal
    /// agent name.
    pub fn certificate_names(&self) -> Vec<String> {
        std::fs::read_to_string(self.directory.join("server.json"))
            .ok()
            .and_then(|text| serde_json::from_str::<LeafMeta>(&text).ok())
            .map(|meta| {
                meta.names
                    .into_iter()
                    .filter(|name| name != AGENT_TLS_NAME)
                    .collect()
            })
            .unwrap_or_default()
    }

    pub fn has_custom_certificate(&self) -> bool {
        self.resolver.custom.is_some()
    }

    /// Whether a `Host` (or `:authority`) value names this server.
    ///
    /// IP literals always pass: DNS rebinding needs a name. Names must be
    /// `localhost`, the agent name, this host's name (also with `.local`),
    /// a configured hostname, or a name the custom certificate covers.
    pub fn allows_host(&self, host: &str) -> bool {
        let Some(name) = host_name_part(host) else {
            return false;
        };
        let name = name.trim_end_matches('.').to_ascii_lowercase();
        if name.parse::<IpAddr>().is_ok() {
            return true;
        }
        if name == "localhost"
            || name == AGENT_TLS_NAME
            || self.extra_names.iter().any(|extra| {
                extra
                    .trim()
                    .trim_end_matches('.')
                    .eq_ignore_ascii_case(&name)
            })
        {
            return true;
        }
        if let Some(local) = sysinfo::System::host_name().map(|h| h.to_ascii_lowercase())
            && (name == local || name.strip_suffix(".local") == Some(local.as_str()))
        {
            return true;
        }
        self.resolver.custom.as_ref().is_some_and(|custom| {
            let Ok(server_name) = rustls::pki_types::ServerName::try_from(name.as_str()) else {
                return false;
            };
            custom.end_entity_cert().is_ok_and(|leaf| {
                webpki::EndEntityCert::try_from(leaf)
                    .is_ok_and(|cert| cert.verify_is_valid_for_subject_name(&server_name).is_ok())
            })
        })
    }
}

/// The host part of `host`, `host:port`, `[v6]` or `[v6]:port`.
fn host_name_part(value: &str) -> Option<&str> {
    if let Some(rest) = value.strip_prefix('[') {
        let (inside, after) = rest.split_once(']')?;
        let port_ok = after.is_empty()
            || after
                .strip_prefix(':')
                .is_some_and(|p| !p.is_empty() && p.bytes().all(|b| b.is_ascii_digit()));
        return (port_ok && inside.parse::<std::net::Ipv6Addr>().is_ok()).then_some(inside);
    }
    let name = match value.rsplit_once(':') {
        Some((name, port)) if !port.is_empty() && port.bytes().all(|b| b.is_ascii_digit()) => name,
        Some(_) => return None,
        None => value,
    };
    (!name.is_empty() && !name.contains(':')).then_some(name)
}

fn create_authority(cert_path: &Path, key_path: &Path) -> Result<()> {
    let key = KeyPair::generate().context("generate CA key")?;
    let mut params = CertificateParams::default();
    let mut name = DistinguishedName::new();
    name.push(DnType::CommonName, "CentralD private CA");
    name.push(DnType::OrganizationName, "CentralD");
    params.distinguished_name = name;
    params.is_ca = IsCa::Ca(BasicConstraints::Constrained(0));
    params.key_usages = vec![KeyUsagePurpose::KeyCertSign, KeyUsagePurpose::CrlSign];
    let now = OffsetDateTime::now_utc();
    params.not_before = now - Duration::days(1);
    params.not_after = now + Duration::days(CA_VALIDITY_DAYS);
    let certificate = params.self_signed(&key).context("self-sign CA")?;
    write_private(key_path, key.serialize_pem().as_bytes())?;
    write_private(cert_path, certificate.pem().as_bytes())?;
    Ok(())
}

/// Every name and address a browser might use to reach this host.
fn desired_names(extra: &[String]) -> BTreeSet<String> {
    let mut names = BTreeSet::new();
    names.insert(AGENT_TLS_NAME.to_owned());
    names.insert("localhost".to_owned());
    names.insert("127.0.0.1".to_owned());
    names.insert("::1".to_owned());
    if let Some(host) = sysinfo::System::host_name() {
        names.insert(host.to_ascii_lowercase());
    }
    for name in extra {
        names.insert(name.trim().to_ascii_lowercase());
    }
    if let Ok(interfaces) = if_addrs::get_if_addrs() {
        for interface in interfaces {
            let address = interface.ip();
            let link_local = match address {
                IpAddr::V4(v4) => v4.is_link_local(),
                IpAddr::V6(v6) => (v6.segments()[0] & 0xffc0) == 0xfe80,
            };
            if !address.is_loopback() && !link_local {
                names.insert(address.to_string());
            }
        }
    }
    names.retain(|name| is_certificate_name(name));
    names
}

fn is_certificate_name(name: &str) -> bool {
    if name.parse::<IpAddr>().is_ok() {
        return true;
    }
    !name.is_empty()
        && name.len() <= 253
        && !name.starts_with(['-', '.'])
        && !name.ends_with(['-', '.'])
        && name
            .bytes()
            .all(|b| b.is_ascii_alphanumeric() || b == b'-' || b == b'.')
}

/// Issues a new leaf when needed. Returns whether one was written.
fn ensure_leaf(directory: &Path, extra_names: &[String]) -> Result<bool> {
    let meta_path = directory.join("server.json");
    let cert_path = directory.join("server.crt");
    let names = desired_names(extra_names);
    let now = OffsetDateTime::now_utc();

    if cert_path.exists()
        && let Ok(text) = std::fs::read_to_string(&meta_path)
        && let Ok(meta) = serde_json::from_str::<LeafMeta>(&text)
    {
        let renew_at = meta.not_after - LEAF_RENEW_BEFORE_DAYS * 86_400;
        if meta.names == names && now.unix_timestamp() < renew_at {
            return Ok(false);
        }
    }

    let ca_pem = std::fs::read_to_string(directory.join("ca.crt")).context("read CA")?;
    let issuer = Issuer::from_ca_cert_pem(&ca_pem, load_key(&directory.join("ca.key"))?)
        .context("load certificate authority")?;
    let key = load_key(&directory.join("server.key"))?;

    let mut params = CertificateParams::new(names.iter().cloned().collect::<Vec<_>>())
        .context("build certificate names")?;
    let mut name = DistinguishedName::new();
    name.push(DnType::CommonName, "CentralD server");
    params.distinguished_name = name;
    params.is_ca = IsCa::ExplicitNoCa;
    params.key_usages = vec![KeyUsagePurpose::DigitalSignature];
    params.extended_key_usages = vec![ExtendedKeyUsagePurpose::ServerAuth];
    params.use_authority_key_identifier_extension = true;
    params.not_before = now - Duration::days(1);
    let not_after = now + Duration::days(LEAF_VALIDITY_DAYS);
    params.not_after = not_after;
    let certificate = params
        .signed_by(&key, &issuer)
        .context("issue server certificate")?;

    let chain = format!("{}{}", certificate.pem(), ca_pem);
    write_private(&cert_path, chain.as_bytes())?;
    let meta = LeafMeta {
        names,
        not_after: not_after.unix_timestamp(),
    };
    write_private(&meta_path, serde_json::to_string_pretty(&meta)?.as_bytes())?;
    Ok(true)
}

fn load_internal(directory: &Path, ca: &CertificateDer<'static>) -> Result<CertifiedKey> {
    let chain_pem = std::fs::read(directory.join("server.crt")).context("read server.crt")?;
    let leaf = CertificateDer::from_pem_slice(&chain_pem)
        .map_err(|error| anyhow!("invalid server certificate: {error}"))?;
    let key = PrivateKeyDer::from_pem_file(directory.join("server.key"))
        .map_err(|error| anyhow!("invalid server key: {error}"))?;
    let signing_key = any_supported_type(&key).context("unsupported server key")?;
    // The CA travels in the chain so agents can match it to their pin.
    Ok(CertifiedKey::new(vec![leaf, ca.clone()], signing_key))
}

fn load_custom(cert_path: &Path, key_path: &Path) -> Result<CertifiedKey> {
    let chain = CertificateDer::pem_file_iter(cert_path)
        .map_err(|error| anyhow!("cannot read {}: {error}", cert_path.display()))?
        .collect::<Result<Vec<_>, _>>()
        .map_err(|error| anyhow!("invalid certificate in {}: {error}", cert_path.display()))?;
    if chain.is_empty() {
        bail!("{} contains no certificate", cert_path.display());
    }
    let key = PrivateKeyDer::from_pem_file(key_path)
        .map_err(|error| anyhow!("cannot read {}: {error}", key_path.display()))?;
    let signing_key = any_supported_type(&key)
        .with_context(|| format!("unsupported private key in {}", key_path.display()))?;
    let certified = CertifiedKey::new(chain, signing_key);
    if certified.keys_match().is_err() {
        bail!(
            "{} does not belong to the certificate in {}",
            key_path.display(),
            cert_path.display()
        );
    }
    Ok(certified)
}

fn load_key(path: &Path) -> Result<KeyPair> {
    let pem =
        std::fs::read_to_string(path).with_context(|| format!("cannot read {}", path.display()))?;
    KeyPair::from_pem(&pem).with_context(|| format!("invalid private key in {}", path.display()))
}

fn create_private_dir(path: &Path) -> Result<()> {
    std::fs::create_dir_all(path).with_context(|| format!("cannot create {}", path.display()))?;
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        std::fs::set_permissions(path, std::fs::Permissions::from_mode(0o700))
            .with_context(|| format!("cannot restrict {}", path.display()))?;
    }
    Ok(())
}

/// Writes `bytes` to a new owner-only file and renames it into place.
pub fn write_private(path: &Path, bytes: &[u8]) -> Result<()> {
    use std::io::Write;
    let mut temporary = path.as_os_str().to_owned();
    temporary.push(".tmp");
    let temporary = PathBuf::from(temporary);
    let mut options = std::fs::OpenOptions::new();
    options.write(true).create(true).truncate(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        options.mode(0o600);
    }
    let mut file = options
        .open(&temporary)
        .with_context(|| format!("cannot write {}", temporary.display()))?;
    file.write_all(bytes)?;
    file.sync_all()?;
    drop(file);
    std::fs::rename(&temporary, path)
        .with_context(|| format!("cannot replace {}", path.display()))?;
    Ok(())
}
