//! Shared wire protocol, join codes, and TLS pinning for `CentralD`.
//!
//! Both the server and the agent depend on this crate so the two binaries can
//! never disagree about message shapes, size limits, or how trust is pinned.

pub mod join;
pub mod limits;
pub mod pin;
pub mod text;
pub mod wire;

/// Version of the agent/server message protocol.
pub const PROTOCOL_VERSION: u32 = 1;

/// Fixed TLS name every server certificate carries. Agents verify this name
/// (never the address they dialled), so a server may move between IPs and
/// hostnames without breaking trust.
pub const AGENT_TLS_NAME: &str = "centrald-server.internal";

/// Default HTTPS port for the web UI, the API, and agent connections.
pub const DEFAULT_PORT: u16 = 7443;

/// Version of this build, shared by server and agent.
pub const VERSION: &str = env!("CARGO_PKG_VERSION");

/// Lowercase hexadecimal SHA-256 of `bytes`.
pub fn sha256(bytes: &[u8]) -> [u8; 32] {
    use sha2::Digest;
    sha2::Sha256::digest(bytes).into()
}

/// Renders a fingerprint the way browsers show it: `AB:CD:…`.
pub fn format_fingerprint(fingerprint: &[u8; 32]) -> String {
    use std::fmt::Write;
    let mut out = String::with_capacity(32 * 3);
    for (index, byte) in fingerprint.iter().enumerate() {
        if index > 0 {
            out.push(':');
        }
        let _ = write!(out, "{byte:02X}");
    }
    out
}
