//! Windows Service Control Manager entry point for the managed client daemon.
//!
//! `windows-service` expands its dispatcher macro to the small Windows ABI
//! callback required by SCM. Unsafe code is allowed only in this module for
//! that audited macro expansion; CentralD itself contains no hand-written FFI.

#![cfg(windows)]
#![allow(unsafe_code)]

use std::ffi::OsString;
use std::fs::{self, OpenOptions};
use std::io::Write;
use std::sync::{Arc, Mutex};
use std::time::Duration;

use anyhow::{Context, Result};
use tokio::sync::watch;
use windows_service::define_windows_service;
use windows_service::service::{
    ServiceControl, ServiceControlAccept, ServiceExitCode, ServiceState, ServiceStatus, ServiceType,
};
use windows_service::service_control_handler::{
    self, ServiceControlHandlerResult, ServiceStatusHandle,
};
use windows_service::service_dispatcher;

const SERVICE_NAME: &str = "CentralDClient";

define_windows_service!(ffi_service_main, service_main);

/// Connects this process to the Windows Service Control Manager and blocks
/// until the service has stopped.
///
/// # Errors
///
/// Returns an error when the process was not launched by SCM or the dispatcher
/// could not be initialized.
pub fn run_dispatcher() -> Result<()> {
    service_dispatcher::start(SERVICE_NAME, ffi_service_main)
        .context("connect CentralD Client to the Windows Service Control Manager")
}

fn service_main(_arguments: Vec<OsString>) {
    if let Err(error) = service_main_inner() {
        tracing::error!(%error, "CentralD Windows service terminated with an error");
        write_service_failure(&error);
    }
}

fn service_main_inner() -> Result<()> {
    let (shutdown_sender, shutdown_receiver) = watch::channel(false);
    let status_slot = Arc::new(Mutex::new(None::<ServiceStatusHandle>));
    let handler_status = Arc::clone(&status_slot);
    let handler_shutdown = shutdown_sender.clone();

    let event_handler = move |control_event| match control_event {
        ServiceControl::Stop | ServiceControl::Shutdown => {
            if let Ok(guard) = handler_status.lock() {
                if let Some(handle) = guard.as_ref() {
                    let _ = handle.set_service_status(service_status(
                        ServiceState::StopPending,
                        ServiceControlAccept::empty(),
                        1,
                        Duration::from_secs(20),
                        ServiceExitCode::Win32(0),
                    ));
                }
            }
            let _ = handler_shutdown.send(true);
            ServiceControlHandlerResult::NoError
        }
        ServiceControl::Interrogate => ServiceControlHandlerResult::NoError,
        _ => ServiceControlHandlerResult::NotImplemented,
    };

    let status_handle = service_control_handler::register(SERVICE_NAME, event_handler)
        .context("register CentralD Windows service control handler")?;
    *status_slot
        .lock()
        .map_err(|_| anyhow::anyhow!("Windows service status lock was poisoned"))? =
        Some(status_handle.clone());

    status_handle
        .set_service_status(service_status(
            ServiceState::StartPending,
            ServiceControlAccept::empty(),
            1,
            Duration::from_secs(20),
            ServiceExitCode::Win32(0),
        ))
        .context("report CentralD Windows service initialization")?;

    let startup_result = (|| -> Result<tokio::runtime::Runtime> {
        let runtime = tokio::runtime::Builder::new_multi_thread()
            .enable_all()
            .build()
            .context("create CentralD Windows service async runtime")?;
        crate::daemon::validate_startup_state().context("validate CentralD client startup state")?;
        Ok(runtime)
    })();
    let runtime = match startup_result {
        Ok(runtime) => runtime,
        Err(error) => {
            let _ = status_handle.set_service_status(service_status(
                ServiceState::Stopped,
                ServiceControlAccept::empty(),
                0,
                Duration::ZERO,
                ServiceExitCode::ServiceSpecific(1),
            ));
            return Err(error);
        }
    };
    if *shutdown_receiver.borrow() {
        status_handle
            .set_service_status(service_status(
                ServiceState::Stopped,
                ServiceControlAccept::empty(),
                0,
                Duration::ZERO,
                ServiceExitCode::Win32(0),
            ))
            .context("report CentralD Windows service stopped during initialization")?;
        return Ok(());
    }
    status_handle
        .set_service_status(service_status(
            ServiceState::StartPending,
            ServiceControlAccept::empty(),
            2,
            Duration::from_secs(10),
            ServiceExitCode::Win32(0),
        ))
        .context("report CentralD Windows service startup checkpoint")?;
    status_handle
        .set_service_status(service_status(
            ServiceState::Running,
            ServiceControlAccept::STOP | ServiceControlAccept::SHUTDOWN,
            0,
            Duration::ZERO,
            ServiceExitCode::Win32(0),
        ))
        .context("report CentralD Windows service as running")?;
    let daemon_result = runtime.block_on(crate::daemon::run_with_shutdown(shutdown_receiver));

    let exit_code = if daemon_result.is_ok() {
        ServiceExitCode::Win32(0)
    } else {
        ServiceExitCode::ServiceSpecific(1)
    };
    status_handle
        .set_service_status(service_status(
            ServiceState::Stopped,
            ServiceControlAccept::empty(),
            0,
            Duration::ZERO,
            exit_code,
        ))
        .context("report CentralD Windows service as stopped")?;
    daemon_result
}

fn write_service_failure(error: &anyhow::Error) {
    let Ok(data_root) = centrald_common::config::client_data_dir() else {
        return;
    };
    if fs::create_dir_all(&data_root).is_err() {
        return;
    }
    let log = data_root.join("service.log");
    if fs::metadata(&log).is_ok_and(|metadata| metadata.len() > 1_048_576) {
        let previous = data_root.join("service.log.1");
        let _ = fs::remove_file(&previous);
        let _ = fs::rename(&log, &previous);
    }
    let Ok(mut file) = OpenOptions::new().create(true).append(true).open(log) else {
        return;
    };
    let _ = writeln!(file, "{} CentralDClient startup/runtime failure: {error:#}", chrono::Utc::now().to_rfc3339());
    let _ = file.sync_data();
}

fn service_status(
    state: ServiceState,
    accepted: ServiceControlAccept,
    checkpoint: u32,
    wait_hint: Duration,
    exit_code: ServiceExitCode,
) -> ServiceStatus {
    ServiceStatus {
        service_type: ServiceType::OWN_PROCESS,
        current_state: state,
        controls_accepted: accepted,
        exit_code,
        checkpoint,
        wait_hint,
        process_id: None,
    }
}
