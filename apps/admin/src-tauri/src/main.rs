#![cfg_attr(not(debug_assertions), windows_subsystem = "windows")]
#![forbid(unsafe_code)]

fn main() {
    if let Err(error) = centrald_admin::run() {
        eprintln!("CentralD Admin runtime failed: {error}");
        std::process::exit(1);
    }
}
