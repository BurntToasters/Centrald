#![deny(unsafe_code)]

pub mod active_pointer;
pub mod build_info;
pub mod config;
pub mod enrollment;
pub mod grant;
pub mod host;
pub mod https;
pub mod release;
pub mod secure_fs;
#[cfg(windows)]
mod windows_paths;

pub const DEFAULT_ENROLLMENT_PORT: u16 = 7443;
pub const DEFAULT_CLIENT_PORT: u16 = 7444;
pub const DEFAULT_ADMIN_PORT: u16 = 7445;
pub const DEFAULT_ENROLLMENT_TTL_SECONDS: u64 = 15 * 60;

/// Remote restart, OS update, and client-package jobs stay fail-closed until
/// the complete broker path is a release gate. Flip only with the matching
/// Admin/client/broker checks and package enablement.
pub const PRIVILEGED_OPERATIONS_ENABLED: bool = false;
/// Interactive PTY/ConPTY stays fail-closed until vault + broker session
/// acceptance tests pass.
pub const TERMINAL_SESSIONS_ENABLED: bool = false;

/// Production binaries stay gated. Callers in this crate that need unit-test
/// coverage must also allow `cfg!(test)` locally; `cfg!(test)` in this crate
/// is true only when *this* crate is under test, not when dependents run tests.
#[must_use]
pub fn privileged_operations_enabled() -> bool {
    PRIVILEGED_OPERATIONS_ENABLED
}

/// Production binaries stay gated. See `privileged_operations_enabled`.
#[must_use]
pub fn terminal_sessions_enabled() -> bool {
    TERMINAL_SESSIONS_ENABLED
}
