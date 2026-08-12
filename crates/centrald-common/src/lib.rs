#![deny(unsafe_code)]

pub mod active_pointer;
pub mod build_info;
pub mod config;
pub mod enrollment;
pub mod grant;
pub mod host;
pub mod release;
pub mod secure_fs;
#[cfg(windows)]
mod windows_paths;

pub const DEFAULT_ENROLLMENT_PORT: u16 = 7443;
pub const DEFAULT_CLIENT_PORT: u16 = 7444;
pub const DEFAULT_ADMIN_PORT: u16 = 7445;
pub const DEFAULT_ENROLLMENT_TTL_SECONDS: u64 = 15 * 60;
