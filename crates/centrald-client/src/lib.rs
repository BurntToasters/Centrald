#![deny(unsafe_code)]

pub mod auth;
pub mod broker;
pub mod broker_session;
pub mod cli;
pub mod daemon;
pub mod enrollment;
pub mod ledger;
pub mod ptys;
pub mod rescue;
pub mod runners;
pub mod updates;
pub mod vault;
#[cfg(windows)]
pub mod windows_ffi;
#[cfg(windows)]
pub mod windows_service;

pub const DEFAULT_CONFIG_PATH: &str = "/etc/centrald/client.toml";

pub(crate) mod state_lock;
#[cfg(unix)]
pub(crate) mod unix_state;
