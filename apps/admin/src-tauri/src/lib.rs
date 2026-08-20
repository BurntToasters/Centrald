#![forbid(unsafe_code)]

use serde::Serialize;

mod profiles;
mod shell;
mod updates;

#[derive(Debug, Serialize)]
#[serde(rename_all = "camelCase")]
struct RuntimeInfo {
    version: &'static str,
    platform: &'static str,
    architecture: &'static str,
}

#[tauri::command]
fn runtime_info() -> RuntimeInfo {
    RuntimeInfo {
        version: env!("CARGO_PKG_VERSION"),
        platform: std::env::consts::OS,
        architecture: std::env::consts::ARCH,
    }
}

/// Starts the hardened Tauri desktop runtime.
///
/// # Errors
///
/// Returns a Tauri runtime error if application initialization or the window
/// event loop cannot start.
pub fn run() -> tauri::Result<()> {
    tauri::Builder::default()
        .manage(shell::ShellSessions::default())
        .setup(|app| {
            app.handle()
                .plugin(tauri_plugin_updater::Builder::new().build())?;
            Ok(())
        })
        .invoke_handler(tauri::generate_handler![
            runtime_info,
            profiles::list_profiles,
            profiles::enroll_admin,
            profiles::list_targets,
            profiles::create_client_invitation,
            profiles::list_client_invitations,
            profiles::revoke_client_invitation,
            profiles::revoke_client,
            profiles::start_job,
            profiles::get_server_settings,
            profiles::update_server_settings,
            shell::begin_elevation,
            shell::open_shell,
            shell::shell_input,
            shell::shell_resize,
            shell::shell_close,
            updates::check_admin_update,
            updates::install_admin_update
        ])
        .run(tauri::generate_context!())
}
