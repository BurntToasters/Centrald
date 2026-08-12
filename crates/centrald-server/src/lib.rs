#![forbid(unsafe_code)]

pub mod cli;
pub mod config_lock;
pub mod db;
pub mod file_security;
pub mod local_control;
pub mod local_postgres;
pub mod local_audit;
pub mod manage;
pub mod nuke;
pub mod services;
pub mod setup;
pub mod setup_recovery;
pub mod wizard;

pub const DEFAULT_CONFIG_PATH: &str = "/etc/centrald/server.toml";
pub const DEFAULT_LOCAL_SOCKET: &str = "/run/centrald/server.sock";
