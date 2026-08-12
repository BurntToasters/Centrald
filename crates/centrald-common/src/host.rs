use std::net::IpAddr;
use std::str::FromStr;

use thiserror::Error;

#[derive(Debug, Error, Clone, PartialEq, Eq)]
pub enum HostError {
    #[error("host must be a DNS name or IP address without a scheme, port, path, or whitespace")]
    Invalid,
}

/// Parses one strict, ASCII DNS name or IP literal and returns its canonical
/// representation. Brackets around IPv6 input are accepted but are not
/// retained in the returned host value.
///
/// # Errors
///
/// Returns [`HostError::Invalid`] for embedded ports, malformed DNS labels,
/// Unicode/IDNA input, paths, credentials, zones, or invalid IP literals.
pub fn canonical_host(input: &str) -> Result<String, HostError> {
    let value = input.trim();
    if value.is_empty()
        || value != input
        || value.len() > 253
        || !value.is_ascii()
        || value.chars().any(char::is_whitespace)
        || value.chars().any(|character| matches!(character, '/' | '\\' | '@' | '%'))
    {
        return Err(HostError::Invalid);
    }

    let unbracketed = value
        .strip_prefix('[')
        .and_then(|value| value.strip_suffix(']'))
        .unwrap_or(value);
    if let Ok(address) = IpAddr::from_str(unbracketed) {
        if value.starts_with('[') != value.ends_with(']') {
            return Err(HostError::Invalid);
        }
        return Ok(address.to_string());
    }
    if value.chars().any(|character| matches!(character, '[' | ']' | ':')) {
        return Err(HostError::Invalid);
    }

    let domain = value.strip_suffix('.').unwrap_or(value);
    if domain.is_empty() || domain.len() > 253 {
        return Err(HostError::Invalid);
    }
    for label in domain.split('.') {
        if label.is_empty()
            || label.len() > 63
            || label.starts_with('-')
            || label.ends_with('-')
            || !label
                .bytes()
                .all(|byte| byte.is_ascii_alphanumeric() || byte == b'-')
        {
            return Err(HostError::Invalid);
        }
    }
    Ok(domain.to_ascii_lowercase())
}

/// Builds an HTTPS origin for a CentralD service, adding IPv6 brackets only
/// where URL syntax requires them.
///
/// # Errors
///
/// Returns an error when the host is invalid or the port is zero.
pub fn https_endpoint(input: &str, port: u16) -> Result<String, HostError> {
    if port == 0 {
        return Err(HostError::Invalid);
    }
    let host = canonical_host(input)?;
    if host.parse::<std::net::Ipv6Addr>().is_ok() {
        Ok(format!("https://[{host}]:{port}"))
    } else {
        Ok(format!("https://{host}:{port}"))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn canonicalizes_supported_hosts() {
        assert_eq!(canonical_host("CentralD.Home.Arpa"), Ok("centrald.home.arpa".into()));
        assert_eq!(canonical_host("192.0.2.10"), Ok("192.0.2.10".into()));
        assert_eq!(canonical_host("2001:db8::10"), Ok("2001:db8::10".into()));
        assert_eq!(canonical_host("[2001:db8::10]"), Ok("2001:db8::10".into()));
        assert_eq!(
            https_endpoint("2001:db8::10", 7443),
            Ok("https://[2001:db8::10]:7443".into())
        );
    }

    #[test]
    fn rejects_ambiguous_hosts() {
        for value in [
            "https://centrald.home.arpa",
            "centrald.home.arpa:7443",
            "user@centrald.home.arpa",
            "bad_label.home",
            "-bad.home",
            "centrald.例.test",
            "fe80::1%eth0",
        ] {
            assert!(canonical_host(value).is_err(), "{value}");
        }
    }
}
