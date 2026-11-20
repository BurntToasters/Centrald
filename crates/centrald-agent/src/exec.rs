//! Operator commands and built-in actions, streamed back as they run.

use std::collections::HashMap;
use std::process::Stdio;
use std::sync::{Arc, Mutex, PoisonError};
use std::time::Duration;

use centrald_proto::limits::{MAX_CHUNK_BYTES, MAX_CONCURRENT_EXECS};
use centrald_proto::wire::{Action, AgentMessage, ExecOutcome, ExecSpec, ExecState};
use tokio::io::{AsyncRead, AsyncReadExt};
use tokio::process::{Child, Command};
use tokio::sync::{Semaphore, mpsc, oneshot};

use crate::process::{base_environment, work_directory};
use crate::status::{Manager, SharedUpdates, check_updates};

/// Output past this is not sent (the server keeps 1 MiB anyway).
const MAX_SENT_OUTPUT: usize = 2 * 1024 * 1024;
/// Grace between a polite stop and a forced kill.
const KILL_GRACE: Duration = Duration::from_secs(10);

#[derive(Debug, Clone)]
pub struct Executor {
    allow_commands: bool,
    permits: Arc<Semaphore>,
    running: Arc<Mutex<HashMap<String, oneshot::Sender<()>>>>,
    updates: SharedUpdates,
}

/// One step of an action: a fixed program and fixed arguments.
struct Step {
    program: std::path::PathBuf,
    args: Vec<String>,
    env: Vec<(String, String)>,
}

impl Executor {
    pub fn new(allow_commands: bool, updates: SharedUpdates) -> Self {
        Self {
            allow_commands,
            permits: Arc::new(Semaphore::new(MAX_CONCURRENT_EXECS)),
            running: Arc::new(Mutex::new(HashMap::new())),
            updates,
        }
    }

    pub fn cancel(&self, id: &str) {
        if let Some(cancel) = self
            .running
            .lock()
            .unwrap_or_else(PoisonError::into_inner)
            .remove(id)
        {
            let _ = cancel.send(());
        }
    }

    /// Starts work in the background; the result arrives as `ExecExit`.
    pub fn start(
        &self,
        id: String,
        spec: ExecSpec,
        timeout_seconds: u32,
        out: mpsc::Sender<AgentMessage>,
    ) {
        let executor = self.clone();
        tokio::spawn(async move {
            let outcome = executor.execute(&id, spec, timeout_seconds, &out).await;
            executor
                .running
                .lock()
                .unwrap_or_else(PoisonError::into_inner)
                .remove(&id);
            let _ = out.send(AgentMessage::ExecExit { id, outcome }).await;
        });
    }

    async fn execute(
        &self,
        id: &str,
        spec: ExecSpec,
        timeout_seconds: u32,
        out: &mpsc::Sender<AgentMessage>,
    ) -> ExecOutcome {
        if !self.allow_commands {
            return refused("This device is monitor-only and does not run commands.");
        }
        let Ok(_permit) = self.permits.clone().try_acquire_owned() else {
            return refused("The device is already running the maximum number of commands.");
        };
        let (cancel_tx, mut cancel_rx) = oneshot::channel();
        self.running
            .lock()
            .unwrap_or_else(PoisonError::into_inner)
            .insert(id.to_owned(), cancel_tx);

        let steps = match plan(&spec) {
            Ok(steps) => steps,
            Err(message) => return refused(message),
        };
        let deadline =
            tokio::time::Instant::now() + Duration::from_secs(u64::from(timeout_seconds));
        let mut sent = 0_usize;
        let mut last = ExecOutcome {
            state: ExecState::Succeeded,
            exit_code: Some(0),
            error: None,
        };
        for step in steps {
            last = run_step(id, &step, deadline, &mut cancel_rx, out, &mut sent).await;
            if last.state != ExecState::Succeeded {
                break;
            }
        }

        if last.state == ExecState::Succeeded {
            match spec {
                ExecSpec::Action {
                    action: Action::UpdatesCheck | Action::UpdatesApply,
                } => {
                    let summary = self.refresh_updates().await;
                    send_output(id, summary.as_bytes(), out, &mut sent).await;
                }
                ExecSpec::Action {
                    action: Action::Reboot,
                } => {
                    schedule_reboot();
                }
                ExecSpec::Shell { .. } => {}
            }
        }
        last
    }

    async fn refresh_updates(&self) -> String {
        let updates = tokio::task::spawn_blocking(check_updates)
            .await
            .ok()
            .flatten();
        let summary = match &updates {
            Some(u) if u.pending == 0 => "\nCentralD: no updates pending.\n".to_owned(),
            Some(u) => format!("\nCentralD: {} update(s) pending.\n", u.pending),
            None => "\nCentralD: could not count pending updates.\n".to_owned(),
        };
        let reboot = updates.as_ref().is_some_and(|u| u.reboot_required);
        *self.updates.lock().unwrap_or_else(PoisonError::into_inner) = updates;
        if reboot {
            format!("{summary}CentralD: a reboot is required to finish updating.\n")
        } else {
            summary
        }
    }
}

fn refused(message: &str) -> ExecOutcome {
    ExecOutcome {
        state: ExecState::Refused,
        exit_code: None,
        error: Some(message.to_owned()),
    }
}

fn step(program: &str, args: &[&str]) -> Step {
    Step {
        program: program.into(),
        args: args.iter().map(|a| (*a).to_owned()).collect(),
        env: Vec::new(),
    }
}

/// Turns a request into fixed steps. Shell commands are the only place an
/// operator string reaches a shell, and only as the single `-c` argument.
fn plan(spec: &ExecSpec) -> Result<Vec<Step>, &'static str> {
    match spec {
        ExecSpec::Shell { command } => {
            #[cfg(unix)]
            {
                Ok(vec![step("/bin/sh", &["-c", command])])
            }
            #[cfg(windows)]
            {
                let shell = crate::process::powershell().ok_or("SystemRoot is not set.")?;
                Ok(vec![Step {
                    program: shell,
                    args: vec![
                        "-NoLogo".into(),
                        "-NoProfile".into(),
                        "-NonInteractive".into(),
                        "-ExecutionPolicy".into(),
                        "Bypass".into(),
                        "-Command".into(),
                        command.clone(),
                    ],
                    env: Vec::new(),
                }])
            }
        }
        ExecSpec::Action { action } => plan_action(*action),
    }
}

fn plan_action(action: Action) -> Result<Vec<Step>, &'static str> {
    if cfg!(windows) {
        return match action {
            // The reboot itself is scheduled after the result is sent.
            Action::Reboot => Ok(Vec::new()),
            Action::UpdatesCheck | Action::UpdatesApply => {
                Err("Windows updates are managed by Windows Update; run them there for now.")
            }
        };
    }
    if action == Action::Reboot {
        return Ok(Vec::new());
    }
    let manager =
        Manager::detect().ok_or("No supported package manager (apt, dnf, pacman) was found.")?;
    let apply = action == Action::UpdatesApply;
    Ok(match manager {
        Manager::Apt => {
            let mut steps = vec![step("/usr/bin/apt-get", &["update"])];
            if apply {
                let mut upgrade = step(
                    "/usr/bin/apt-get",
                    &[
                        "-y",
                        "-o",
                        "Dpkg::Options::=--force-confdef",
                        "-o",
                        "Dpkg::Options::=--force-confold",
                        "upgrade",
                    ],
                );
                upgrade
                    .env
                    .push(("DEBIAN_FRONTEND".to_owned(), "noninteractive".to_owned()));
                steps.push(upgrade);
            }
            steps
        }
        Manager::Dnf => {
            if apply {
                vec![step("/usr/bin/dnf", &["-y", "upgrade"])]
            } else {
                // Exit 100 means "updates available", so refresh metadata
                // with a command that exits 0.
                vec![step("/usr/bin/dnf", &["-q", "makecache"])]
            }
        }
        Manager::Pacman => {
            if apply {
                vec![step("/usr/bin/pacman", &["-Syu", "--noconfirm"])]
            } else {
                vec![step("/usr/bin/pacman", &["-Sy"])]
            }
        }
    })
}

async fn send_output(id: &str, data: &[u8], out: &mpsc::Sender<AgentMessage>, sent: &mut usize) {
    for chunk in data.chunks(MAX_CHUNK_BYTES) {
        if *sent >= MAX_SENT_OUTPUT {
            return;
        }
        *sent += chunk.len();
        let _ = out
            .send(AgentMessage::ExecOutput {
                id: id.to_owned(),
                data: chunk.to_vec(),
            })
            .await;
    }
}

async fn run_step(
    id: &str,
    step: &Step,
    deadline: tokio::time::Instant,
    cancel: &mut oneshot::Receiver<()>,
    out: &mpsc::Sender<AgentMessage>,
    sent: &mut usize,
) -> ExecOutcome {
    let mut command = Command::new(&step.program);
    command
        .args(&step.args)
        .current_dir(work_directory())
        .stdin(Stdio::null())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .kill_on_drop(true);
    for (key, value) in base_environment().into_iter().chain(step.env.clone()) {
        command.env(key, value);
    }
    #[cfg(unix)]
    command.process_group(0);
    let mut child = match command.spawn() {
        Ok(child) => child,
        Err(error) => {
            return ExecOutcome {
                state: ExecState::Failed,
                exit_code: None,
                error: Some(format!(
                    "could not start {}: {error}",
                    step.program.display()
                )),
            };
        }
    };

    let (chunks_tx, mut chunks) = mpsc::channel::<Vec<u8>>(64);
    if let Some(stdout) = child.stdout.take() {
        tokio::spawn(pump(stdout, chunks_tx.clone()));
    }
    if let Some(stderr) = child.stderr.take() {
        tokio::spawn(pump(stderr, chunks_tx.clone()));
    }
    drop(chunks_tx);

    let mut stopped: Option<(ExecState, &'static str)> = None;
    let mut status = None;
    let mut output_open = true;
    loop {
        tokio::select! {
            chunk = chunks.recv(), if output_open => match chunk {
                Some(chunk) => send_output(id, &chunk, out, sent).await,
                None => output_open = false,
            },
            result = child.wait(), if status.is_none() => {
                status = Some(result);
            }
            () = tokio::time::sleep_until(deadline), if stopped.is_none() && status.is_none() => {
                stopped = Some((ExecState::TimedOut, "The command ran past its time limit and was stopped."));
                terminate(&mut child).await;
            }
            _ = &mut *cancel, if stopped.is_none() && status.is_none() => {
                stopped = Some((ExecState::Canceled, "Canceled by an operator."));
                terminate(&mut child).await;
            }
        }
        if status.is_some() && !output_open {
            break;
        }
        // A background grandchild may hold the pipes open; do not wait on
        // it forever once the main process is gone.
        if status.is_some() {
            match tokio::time::timeout(Duration::from_secs(2), chunks.recv()).await {
                Ok(Some(chunk)) => send_output(id, &chunk, out, sent).await,
                Ok(None) | Err(_) => break,
            }
        }
    }

    if let Some((state, message)) = stopped {
        return ExecOutcome {
            state,
            exit_code: None,
            error: Some(message.to_owned()),
        };
    }
    match status {
        Some(Ok(status)) if status.success() => ExecOutcome {
            state: ExecState::Succeeded,
            exit_code: Some(0),
            error: None,
        },
        Some(Ok(status)) => ExecOutcome {
            state: ExecState::Failed,
            exit_code: status.code(),
            error: signal_description(status),
        },
        Some(Err(error)) => ExecOutcome {
            state: ExecState::Failed,
            exit_code: None,
            error: Some(format!("lost track of the process: {error}")),
        },
        None => ExecOutcome {
            state: ExecState::Failed,
            exit_code: None,
            error: Some("the process ended without a status".to_owned()),
        },
    }
}

#[cfg(unix)]
fn signal_description(status: std::process::ExitStatus) -> Option<String> {
    use std::os::unix::process::ExitStatusExt;
    status
        .signal()
        .map(|signal| format!("terminated by signal {signal}"))
}

#[cfg(not(unix))]
fn signal_description(_status: std::process::ExitStatus) -> Option<String> {
    None
}

async fn pump(mut reader: impl AsyncRead + Unpin, chunks: mpsc::Sender<Vec<u8>>) {
    let mut buffer = vec![0_u8; MAX_CHUNK_BYTES];
    loop {
        match reader.read(&mut buffer).await {
            Ok(0) | Err(_) => return,
            Ok(count) => {
                if chunks.send(buffer[..count].to_vec()).await.is_err() {
                    return;
                }
            }
        }
    }
}

/// Stops the whole process tree: politely, then by force after a grace
/// period (package managers get a chance to release their locks).
async fn terminate(child: &mut Child) {
    let Some(pid) = child.id() else {
        return;
    };
    #[cfg(unix)]
    {
        use nix::sys::signal::{Signal, killpg};
        use nix::unistd::Pid;
        let Ok(raw) = i32::try_from(pid) else {
            return;
        };
        let group = Pid::from_raw(raw);
        let _ = killpg(group, Signal::SIGTERM);
        if tokio::time::timeout(KILL_GRACE, child.wait())
            .await
            .is_err()
        {
            let _ = killpg(group, Signal::SIGKILL);
        }
    }
    #[cfg(windows)]
    {
        if let Some(taskkill) = crate::process::system32("taskkill.exe") {
            let _ = Command::new(&taskkill)
                .args(["/T", "/PID", &pid.to_string()])
                .status()
                .await;
            if tokio::time::timeout(KILL_GRACE, child.wait())
                .await
                .is_err()
            {
                let _ = Command::new(&taskkill)
                    .args(["/T", "/F", "/PID", &pid.to_string()])
                    .status()
                    .await;
            }
        }
        let _ = child.start_kill();
    }
}

/// Reboots a few seconds from now so the result reaches the server first.
fn schedule_reboot() {
    tokio::spawn(async {
        tokio::time::sleep(Duration::from_secs(5)).await;
        tracing::warn!("rebooting at operator request");
        #[cfg(unix)]
        {
            for program in ["/usr/bin/systemctl", "/bin/systemctl"] {
                if std::path::Path::new(program).exists() {
                    let _ = Command::new(program).arg("reboot").status().await;
                    return;
                }
            }
            let _ = Command::new("/sbin/shutdown")
                .args(["-r", "now"])
                .status()
                .await;
        }
        #[cfg(windows)]
        {
            if let Some(shutdown) = crate::process::system32("shutdown.exe") {
                let _ = Command::new(shutdown)
                    .args([
                        "/r",
                        "/t",
                        "0",
                        "/c",
                        "CentralD: reboot requested by an operator",
                    ])
                    .status()
                    .await;
            }
        }
    });
}
