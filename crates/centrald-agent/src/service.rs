//! Registering the agent with the system service manager.

use anyhow::Result;

pub enum Installed {
    /// The service is registered and (re)started.
    Started,
    /// No service manager we know; the operator must start `run` themselves.
    Manual(String),
}

/// `CENTRALD_SKIP_SERVICE=1` leaves service management alone (tests, images).
fn skipped() -> bool {
    std::env::var_os("CENTRALD_SKIP_SERVICE").is_some_and(|v| v == "1")
}

#[cfg(unix)]
mod platform {
    use std::path::Path;
    use std::process::Command;

    use anyhow::{Context, Result, bail};

    use super::Installed;

    const UNIT: &str = "centrald-agent.service";
    const LOCAL_UNIT: &str = "/etc/systemd/system/centrald-agent.service";
    const PACKAGED_UNITS: [&str; 2] = [
        "/usr/lib/systemd/system/centrald-agent.service",
        "/lib/systemd/system/centrald-agent.service",
    ];

    pub fn systemctl() -> Option<&'static str> {
        ["/usr/bin/systemctl", "/bin/systemctl"]
            .into_iter()
            .find(|p| Path::new(p).exists())
    }

    pub fn is_running() -> bool {
        systemctl().is_some_and(|program| {
            Command::new(program)
                .args(["is-active", "--quiet", UNIT])
                .status()
                .is_ok_and(|s| s.success())
        })
    }

    pub fn restart_now() -> Result<()> {
        run(&["restart", "--no-block", UNIT])
    }

    fn run(args: &[&str]) -> Result<()> {
        let program = systemctl().context("systemctl not found")?;
        let status = Command::new(program)
            .args(args)
            .status()
            .with_context(|| format!("run systemctl {}", args.join(" ")))?;
        if !status.success() {
            bail!("systemctl {} failed", args.join(" "));
        }
        Ok(())
    }

    fn unit_text(executable: &Path) -> String {
        format!(
            "[Unit]\n\
             Description=CentralD agent\n\
             Documentation=https://centrald.dev\n\
             Wants=network-online.target\n\
             After=network-online.target\n\
             \n\
             [Service]\n\
             Type=simple\n\
             ExecStart={} run\n\
             Restart=always\n\
             RestartSec=5\n\
             # Commands an operator started (such as package upgrades) keep\n\
             # running if the agent itself restarts.\n\
             KillMode=process\n\
             \n\
             [Install]\n\
             WantedBy=multi-user.target\n",
            executable.display()
        )
    }

    pub fn install_and_start() -> Result<Installed> {
        if !Path::new("/run/systemd/system").exists() || systemctl().is_none() {
            return Ok(Installed::Manual(
                "This system does not use systemd. Start `centrald-agent run` as root from your init system."
                    .to_owned(),
            ));
        }
        if !PACKAGED_UNITS.iter().any(|p| Path::new(p).exists()) {
            let executable = std::env::current_exe().context("locate the agent binary")?;
            let text = unit_text(&executable);
            if std::fs::read_to_string(LOCAL_UNIT).ok().as_deref() != Some(text.as_str()) {
                std::fs::write(LOCAL_UNIT, text)
                    .with_context(|| format!("cannot write {LOCAL_UNIT}"))?;
            }
            run(&["daemon-reload"])?;
        }
        run(&["enable", "--quiet", UNIT])?;
        run(&["restart", UNIT])?;
        Ok(Installed::Started)
    }

    pub fn stop_and_remove() -> Result<()> {
        if systemctl().is_none() {
            return Ok(());
        }
        let _ = run(&["disable", "--now", "--quiet", UNIT]);
        if Path::new(LOCAL_UNIT).exists() {
            std::fs::remove_file(LOCAL_UNIT)
                .with_context(|| format!("cannot remove {LOCAL_UNIT}"))?;
            let _ = run(&["daemon-reload"]);
        }
        Ok(())
    }

    pub fn state() -> String {
        let Some(program) = systemctl() else {
            return "not managed by systemd".to_owned();
        };
        Command::new(program)
            .args(["is-active", UNIT])
            .output()
            .map_or_else(
                |_| "unknown".to_owned(),
                |o| String::from_utf8_lossy(&o.stdout).trim().to_owned(),
            )
    }
}

#[cfg(windows)]
mod platform {
    use std::ffi::OsString;
    use std::time::Duration;

    use anyhow::{Context, Result};
    use windows_service::service::{
        ServiceAccess, ServiceErrorControl, ServiceInfo, ServiceStartType, ServiceState,
        ServiceType,
    };
    use windows_service::service_manager::{ServiceManager, ServiceManagerAccess};

    use super::Installed;

    pub const NAME: &str = "CentralDAgent";

    fn info() -> Result<ServiceInfo> {
        Ok(ServiceInfo {
            name: OsString::from(NAME),
            display_name: OsString::from("CentralD agent"),
            service_type: ServiceType::OWN_PROCESS,
            start_type: ServiceStartType::AutoStart,
            error_control: ServiceErrorControl::Normal,
            executable_path: std::env::current_exe().context("locate the agent binary")?,
            launch_arguments: vec![OsString::from("service")],
            dependencies: vec![],
            account_name: None, // LocalSystem
            account_password: None,
        })
    }

    pub fn install_and_start() -> Result<Installed> {
        let manager = ServiceManager::local_computer(
            None::<&str>,
            ServiceManagerAccess::CONNECT | ServiceManagerAccess::CREATE_SERVICE,
        )
        .context("open the service manager (run as Administrator)")?;
        let access = ServiceAccess::QUERY_STATUS
            | ServiceAccess::START
            | ServiceAccess::STOP
            | ServiceAccess::CHANGE_CONFIG;
        let service = match manager.open_service(NAME, access) {
            Ok(service) => {
                service.change_config(&info()?)?;
                service
            }
            Err(_) => manager
                .create_service(&info()?, access)
                .context("register the CentralD agent service")?,
        };
        let _ = service.set_description("Reports status to CentralD and runs operator commands.");
        if service.query_status()?.current_state != ServiceState::Stopped {
            let _ = service.stop();
            for _ in 0..30 {
                if service.query_status()?.current_state == ServiceState::Stopped {
                    break;
                }
                std::thread::sleep(Duration::from_millis(500));
            }
        }
        service
            .start::<&str>(&[])
            .context("start the CentralD agent service")?;
        Ok(Installed::Started)
    }

    pub fn stop_and_remove() -> Result<()> {
        let manager = ServiceManager::local_computer(None::<&str>, ServiceManagerAccess::CONNECT)?;
        if let Ok(service) = manager.open_service(
            NAME,
            ServiceAccess::QUERY_STATUS | ServiceAccess::STOP | ServiceAccess::DELETE,
        ) {
            let _ = service.stop();
            service
                .delete()
                .context("remove the CentralD agent service")?;
        }
        Ok(())
    }

    pub fn state() -> String {
        let Ok(manager) =
            ServiceManager::local_computer(None::<&str>, ServiceManagerAccess::CONNECT)
        else {
            return "unknown".to_owned();
        };
        match manager.open_service(NAME, ServiceAccess::QUERY_STATUS) {
            Ok(service) => service.query_status().map_or_else(
                |_| "unknown".to_owned(),
                |s| format!("{:?}", s.current_state).to_lowercase(),
            ),
            Err(_) => "not installed".to_owned(),
        }
    }
}

#[cfg(windows)]
pub use platform::NAME as WINDOWS_SERVICE_NAME;

pub fn install_and_start() -> Result<Installed> {
    if skipped() {
        return Ok(Installed::Manual(
            "Service setup skipped (CENTRALD_SKIP_SERVICE=1). Start `centrald-agent run` yourself."
                .to_owned(),
        ));
    }
    platform::install_and_start()
}

pub fn stop_and_remove() -> Result<()> {
    if skipped() {
        return Ok(());
    }
    platform::stop_and_remove()
}

pub fn state() -> String {
    platform::state()
}

#[cfg(unix)]
pub use platform::{is_running, restart_now, systemctl};
