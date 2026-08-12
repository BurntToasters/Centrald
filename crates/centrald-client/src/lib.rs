#![deny(unsafe_code)]

pub mod cli;
pub mod daemon;
pub mod enrollment;
pub mod rescue;
#[cfg(windows)]
pub mod windows_service;

pub const DEFAULT_CONFIG_PATH: &str = "/etc/centrald/client.toml";

pub(crate) mod state_lock;
#[cfg(unix)]
pub(crate) mod unix_state;
