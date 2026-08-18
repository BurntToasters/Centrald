//! Concrete privileged operation runners for the broker.
//!
//! Every operation uses fixed executable paths and fixed argument lists; no
//! shell is ever spawned. Output is merged from stdout/stderr and truncated at
//! the job-event bound so a single result always fits one bounded job event.

use std::io::Read;
use std::process::{Command, Stdio};
use std::time::{Duration, Instant};

use anyhow::Context;
use anyhow::{Result, bail};
use centrald_common::grant::GrantOperation;
use centrald_platform::broker::{BrokerResponse, OperationRunner};

/// Maximum operation output forwarded into one job event.
pub const MAX_OPERATION_OUTPUT_BYTES: usize = 64 * 1024;
const COMMAND_TIMEOUT: Duration = Duration::from_secs(900);
const GRACEFUL_TERMINATION_GRACE: Duration = Duration::from_secs(10);

#[derive(Debug)]
pub struct SystemOperationRunner;

#[derive(Debug)]
pub struct SystemRunnerError(pub String);

impl std::fmt::Display for SystemRunnerError {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter.write_str(&self.0)
    }
}

impl std::error::Error for SystemRunnerError {}

#[derive(Debug)]
pub(crate) struct BoundedOutput {
    pub(crate) success: bool,
    pub(crate) exit_code: i32,
    pub(crate) output: Vec<u8>,
}

impl OperationRunner for SystemOperationRunner {
    type Error = SystemRunnerError;

    fn run(
        &mut self,
        operation: &GrantOperation,
        parameters_json: &[u8],
    ) -> Result<BrokerResponse, Self::Error> {
        validate_parameters(parameters_json)?;
        match operation {
            GrantOperation::RestartClientService => {
                run_operation(restart_client_service).map(|_| BrokerResponse {
                    success: true,
                    output: b"client service restart requested".to_vec(),
                    exit_code: 0,
                })
            }
            GrantOperation::RestartMachine => {
                run_operation(restart_machine).map(|_| BrokerResponse {
                    success: true,
                    output: b"machine restart requested".to_vec(),
                    exit_code: 0,
                })
            }
            GrantOperation::CheckOsUpdates => run_operation(check_os_updates).map(response),
            GrantOperation::ApplyOsUpdates => run_operation(apply_os_updates).map(response),
            GrantOperation::UpdateClient => update_client_operation(parameters_json).map(response),
            GrantOperation::OpenLowShell | GrantOperation::OpenElevatedShell => {
                Err(SystemRunnerError(
                    "shell sessions are handled by the broker session channel, not the job runner"
                        .to_owned(),
                ))
            }
        }
    }
}

fn response(output: BoundedOutput) -> BrokerResponse {
    let mut body = output.output;
    body.truncate(MAX_OPERATION_OUTPUT_BYTES);
    BrokerResponse {
        success: output.success,
        output: body,
        exit_code: output.exit_code,
    }
}

fn run_operation(
    operation: fn() -> Result<BoundedOutput>,
) -> Result<BoundedOutput, SystemRunnerError> {
    operation().map_err(|error| SystemRunnerError(error.to_string()))
}

fn validate_parameters(parameters_json: &[u8]) -> Result<(), SystemRunnerError> {
    if parameters_json.is_empty() {
        return Err(SystemRunnerError(
            "job parameters must be a JSON object".to_owned(),
        ));
    }
    match serde_json::from_slice::<serde_json::Value>(parameters_json) {
        Ok(serde_json::Value::Object(_)) => Ok(()),
        _ => Err(SystemRunnerError(
            "job parameters must be a JSON object".to_owned(),
        )),
    }
}

fn restart_client_service() -> Result<BoundedOutput> {
    #[cfg(target_os = "linux")]
    {
        let mut command = Command::new("/usr/bin/systemctl");
        command.args(["restart", "centrald-client.service"]);
        run_bounded(&mut command)
    }
    #[cfg(windows)]
    {
        crate::rescue::restart_client_service()?;
        Ok(BoundedOutput {
            success: true,
            exit_code: 0,
            output: Vec::new(),
        })
    }
    #[cfg(not(any(target_os = "linux", windows)))]
    {
        bail!("client service control is unsupported on this operating system")
    }
}

fn restart_machine() -> Result<BoundedOutput> {
    #[cfg(target_os = "linux")]
    {
        let mut command = Command::new("/usr/bin/systemctl");
        command.args(["reboot"]);
        run_bounded(&mut command)
    }
    #[cfg(windows)]
    {
        crate::windows_ffi::request_system_reboot()?;
        Ok(BoundedOutput {
            success: true,
            exit_code: 0,
            output: Vec::new(),
        })
    }
    #[cfg(not(any(target_os = "linux", windows)))]
    {
        bail!("machine restart is unsupported on this operating system")
    }
}

fn check_os_updates() -> Result<BoundedOutput> {
    #[cfg(target_os = "linux")]
    {
        let mut command = Command::new("/usr/bin/apt-get");
        command.args(["-s", "upgrade"]);
        command.env("DEBIAN_FRONTEND", "noninteractive");
        return run_bounded(&mut command);
    }
    #[cfg(not(target_os = "linux"))]
    {
        bail!("OS update checks are supported only on Debian/Ubuntu hosts in this build")
    }
}

fn apply_os_updates() -> Result<BoundedOutput> {
    #[cfg(target_os = "linux")]
    {
        let mut command = Command::new("/usr/bin/apt-get");
        command.args(["-y", "upgrade"]);
        command.env("DEBIAN_FRONTEND", "noninteractive");
        return run_bounded(&mut command);
    }
    #[cfg(not(target_os = "linux"))]
    {
        bail!("OS update execution is supported only on Debian/Ubuntu hosts in this build")
    }
}

/// Downloads and installs the operator-approved `CentralD` client release.
fn update_client_operation(parameters_json: &[u8]) -> Result<BoundedOutput, SystemRunnerError> {
    let output = crate::updates::update_client(parameters_json, env!("CARGO_PKG_VERSION"))
        .map_err(|error| SystemRunnerError(error.to_string()))?;
    Ok(BoundedOutput {
        success: true,
        exit_code: 0,
        output,
    })
}

/// Runs a fixed command with bounded merged output and a hard timeout.
pub(crate) fn run_bounded(command: &mut Command) -> Result<BoundedOutput> {
    command
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .stdin(Stdio::null());
    // Put the child in its own process group so a timeout can terminate the
    // whole tree (apt-get's dpkg children, PowerShell's service installers).
    #[cfg(unix)]
    {
        use std::os::unix::process::CommandExt;
        command.process_group(0);
    }
    let mut child = command
        .spawn()
        .context("start privileged operation command")?;
    let stdout = child.stdout.take().context("capture command stdout")?;
    let stderr = child.stderr.take().context("capture command stderr")?;

    let reader = std::thread::spawn(move || {
        let mut merged = Vec::new();
        let mut stdout_remaining = MAX_OPERATION_OUTPUT_BYTES;
        let mut stderr_remaining = MAX_OPERATION_OUTPUT_BYTES;
        let mut stdout = stdout;
        let mut stderr = stderr;
        let mut capped = false;
        loop {
            let mut buffer = [0_u8; 4096];
            let stdout_read = stdout.read(&mut buffer).unwrap_or(0);
            if stdout_read > 0 {
                let take = if capped {
                    0
                } else {
                    stdout_read.min(stdout_remaining)
                };
                merged.extend_from_slice(&buffer[..take]);
                stdout_remaining -= take;
            }
            let stderr_read = stderr.read(&mut buffer).unwrap_or(0);
            if stderr_read > 0 {
                let take = if capped {
                    0
                } else {
                    stderr_read.min(stderr_remaining)
                };
                merged.extend_from_slice(&buffer[..take]);
                stderr_remaining -= take;
            }
            if stdout_read == 0 && stderr_read == 0 {
                break;
            }
            // Keep draining (discarding) after the cap so the child can exit
            // instead of blocking on a full pipe.
            if merged.len() >= MAX_OPERATION_OUTPUT_BYTES {
                capped = true;
            }
        }
        merged
    });

    let started = Instant::now();
    let status = loop {
        match child
            .try_wait()
            .context("poll privileged operation command")?
        {
            Some(status) => break status,
            None if started.elapsed() > COMMAND_TIMEOUT => {
                // Graceful first: dpkg/apt-get must not be SIGKILLed while
                // holding its package database. SIGTERM the whole tree, wait
                // briefly, then hard-kill anything still alive.
                let deadline = Instant::now() + GRACEFUL_TERMINATION_GRACE;
                terminate_command_tree(&mut child);
                loop {
                    match child
                        .try_wait()
                        .context("poll graceful privileged operation termination")?
                    {
                        Some(_) => break,
                        None if Instant::now() >= deadline => break,
                        None => std::thread::sleep(Duration::from_millis(100)),
                    }
                }
                if child
                    .try_wait()
                    .context("poll privileged operation command")?
                    .is_none()
                {
                    kill_command_tree(&mut child);
                    let _ = child.wait();
                }
                bail!(
                    "privileged operation command exceeded the {}s timeout",
                    COMMAND_TIMEOUT.as_secs()
                );
            }
            None => std::thread::sleep(Duration::from_millis(100)),
        }
    };
    let output = reader
        .join()
        .map_err(|_| anyhow::anyhow!("privileged operation output reader failed"))?;
    Ok(BoundedOutput {
        success: status.success(),
        exit_code: status.code().unwrap_or(1),
        output,
    })
}

/// Requests graceful termination of the whole child process tree (SIGTERM on
/// Unix; Windows first asks `taskkill` without `/F` so console apps get a
/// chance to close, then the hard killer below finishes the job).
fn terminate_command_tree(child: &mut std::process::Child) {
    #[cfg(unix)]
    {
        let _ = rustix::process::kill_process_group(
            rustix::process::Pid::from_child(child),
            rustix::process::Signal::TERM,
        );
    }
    #[cfg(windows)]
    {
        use std::process::Command;
        if let Some(taskkill) = centrald_common::config::windows_system_executable("taskkill.exe") {
            let _ = Command::new(taskkill)
                .args(["/T", "/PID"])
                .arg(child.id().to_string())
                .status();
        }
    }
}

/// Hard-terminates the whole child process tree after the graceful grace
/// expired.
fn kill_command_tree(child: &mut std::process::Child) {
    #[cfg(unix)]
    {
        let _ = rustix::process::kill_process_group(
            rustix::process::Pid::from_child(child),
            rustix::process::Signal::KILL,
        );
    }
    #[cfg(windows)]
    {
        use std::process::Command;
        if let Some(taskkill) = centrald_common::config::windows_system_executable("taskkill.exe") {
            let _ = Command::new(taskkill)
                .args(["/T", "/F", "/PID"])
                .arg(child.id().to_string())
                .status();
        }
    }
    let _ = child.kill();
}
