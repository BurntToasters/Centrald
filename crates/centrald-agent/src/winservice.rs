//! Running under the Windows service control manager.

use std::sync::mpsc;
use std::time::Duration;

use anyhow::{Context, Result};
use windows_service::service::{
    ServiceControl, ServiceControlAccept, ServiceExitCode, ServiceState, ServiceStatus, ServiceType,
};
use windows_service::service_control_handler::{self, ServiceControlHandlerResult};
use windows_service::{define_windows_service, service_dispatcher};

use crate::config::AgentConfig;
use crate::service::WINDOWS_SERVICE_NAME;

define_windows_service!(ffi_service_main, service_main);

pub fn start() -> Result<()> {
    service_dispatcher::start(WINDOWS_SERVICE_NAME, ffi_service_main)
        .context("this command is only run by the Windows service manager")
}

fn service_main(_arguments: Vec<std::ffi::OsString>) {
    if let Err(error) = run_service() {
        tracing::error!(error = %format!("{error:#}"), "service failed");
    }
}

fn run_service() -> Result<()> {
    crate::init_logging();
    let (stop_tx, stop_rx) = mpsc::channel::<()>();
    let handler = move |control| match control {
        ServiceControl::Stop | ServiceControl::Shutdown => {
            let _ = stop_tx.send(());
            ServiceControlHandlerResult::NoError
        }
        ServiceControl::Interrogate => ServiceControlHandlerResult::NoError,
        _ => ServiceControlHandlerResult::NotImplemented,
    };
    let status = service_control_handler::register(WINDOWS_SERVICE_NAME, handler)?;
    let report = |state, accept| {
        let _ = status.set_service_status(ServiceStatus {
            service_type: ServiceType::OWN_PROCESS,
            current_state: state,
            controls_accepted: accept,
            exit_code: ServiceExitCode::Win32(0),
            checkpoint: 0,
            wait_hint: Duration::from_secs(10),
            process_id: None,
        });
    };
    report(
        ServiceState::Running,
        ServiceControlAccept::STOP | ServiceControlAccept::SHUTDOWN,
    );

    let config = AgentConfig::load()?.context("this machine is not enrolled")?;
    let runtime = crate::runtime()?;
    runtime.block_on(async move {
        let stop = tokio::task::spawn_blocking(move || {
            let _ = stop_rx.recv();
        });
        let stop = async {
            let _ = stop.await;
        };
        if let Err(error) = crate::connection::run(config, stop).await {
            tracing::error!(error = %format!("{error:#}"), "agent stopped");
        }
    });
    report(ServiceState::Stopped, ServiceControlAccept::empty());
    Ok(())
}
