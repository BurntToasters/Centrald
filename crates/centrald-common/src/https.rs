use url::{Host, Url};

/// Returns an error when `next` is not HTTPS or names a non-public IP literal.
///
/// Cross-origin HTTPS redirects to public hostnames stay allowed (GitHub
/// Releases uses them). Literal loopback, link-local, and RFC1918/ULA addresses
/// are refused so an open-redirecting feed cannot SSRF internal HTTPS.
///
/// # Errors
///
/// Returns a static reason when the scheme is not HTTPS or the host is a
/// non-public IP literal.
pub fn https_redirect_is_allowed(next: &Url) -> Result<(), &'static str> {
    if next.scheme() != "https" {
        return Err("refusing non-HTTPS redirect");
    }
    if host_is_non_public_literal(next) {
        return Err("refusing redirect to a private or local address");
    }
    Ok(())
}

fn host_is_non_public_literal(url: &Url) -> bool {
    match url.host() {
        Some(Host::Ipv4(ip)) => {
            ip.is_loopback()
                || ip.is_private()
                || ip.is_link_local()
                || ip.is_unspecified()
                || ip.is_broadcast()
                || ip.is_documentation()
        }
        Some(Host::Ipv6(ip)) => {
            ip.is_loopback()
                || ip.is_unique_local()
                || ip.is_unicast_link_local()
                || ip.is_unspecified()
        }
        Some(Host::Domain(domain)) => {
            let port = url.port_or_known_default().unwrap_or(443);
            if let Ok(mut addrs) = std::net::ToSocketAddrs::to_socket_addrs(&(domain, port)) {
                #[allow(clippy::collapsible_if)]
                if let Some(ip) = addrs.next().map(|addr| addr.ip()) {
                    if ip.is_loopback() || ip.is_unspecified() {
                        return true;
                    }
                    match ip {
                        std::net::IpAddr::V4(ipv4) => {
                            if ipv4.is_private()
                                || ipv4.is_link_local()
                                || ipv4.is_broadcast()
                                || ipv4.is_documentation()
                            {
                                return true;
                            }
                        }
                        std::net::IpAddr::V6(ipv6) => {
                            if ipv6.is_unique_local() || ipv6.is_unicast_link_local() {
                                return true;
                            }
                        }
                    }
                }
            }
            false
        }
        None => true,
    }
}

#[cfg(test)]
#[allow(clippy::unwrap_used)]
mod tests {
    use super::*;

    #[test]
    fn allows_public_https_hosts() {
        assert!(https_redirect_is_allowed(&Url::parse("https://github.com/x").unwrap()).is_ok());
        assert!(
            https_redirect_is_allowed(
                &Url::parse("https://objects.githubusercontent.com/releases/x").unwrap()
            )
            .is_ok()
        );
    }

    #[test]
    fn rejects_http_and_private_literals() {
        assert!(https_redirect_is_allowed(&Url::parse("http://example.test/x").unwrap()).is_err());
        assert!(https_redirect_is_allowed(&Url::parse("https://127.0.0.1/x").unwrap()).is_err());
        assert!(https_redirect_is_allowed(&Url::parse("https://10.0.0.1/x").unwrap()).is_err());
        assert!(https_redirect_is_allowed(&Url::parse("https://192.168.1.1/x").unwrap()).is_err());
        assert!(https_redirect_is_allowed(&Url::parse("https://[::1]/x").unwrap()).is_err());
        assert!(
            https_redirect_is_allowed(&Url::parse("https://[fd12:3456:789a::1]/x").unwrap())
                .is_err()
        );
        assert!(https_redirect_is_allowed(&Url::parse("https://192.0.2.1/x").unwrap()).is_err());
    }
}
