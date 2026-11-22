//! Operator commands and built-in actions, streamed back as they run.
//!
//! Each step runs in its own process group (Unix). A run is not over until
//! that group is gone: timeout and cancel send SIGTERM to the group, then
//! SIGKILL after a grace period whatever the direct child did, and
//! background processes left behind by a finished command are stopped too.
//! A process that calls `setsid` leaves the group and is out of reach.

use std::collections::HashMap;
use std::process::Stdio;
use std::sync::{Arc, Mutex, PoisonError};
use std::time::Duration;

use centrald_proto::limits::{MAX_CHUNK_BYTES, MAX_CONCURRENT_EXECS};
use centrald_proto::wire::{Action, AgentMessage, ExecOutcome, ExecSpec, ExecState, valid_id};
use tokio::io::{AsyncRead, AsyncReadExt};
use tokio::process::Command;
use tokio::sync::{mpsc, oneshot};
use tokio::time::Instant;

use crate::process::{clean_environment, work_directory};
use crate::status::{Manager, SharedUpdates, check_updates};

/// Output past this is not sent (the server keeps 1 MiB anyway).
const MAX_SENT_OUTPUT: usize = 2 * 1024 * 1024;
/// Grace between a polite stop and a forced kill.
const KILL_GRACE: Duration = Duration::from_secs(10);
/// Output still read after the main process exits.
const DRAIN: Duration = Duration::from_secs(2);
/// Grace for background processes a finished command left behind.
const LEFTOVER_GRACE: Duration = Duration::from_secs(2);
/// Grace for commands when the agent itself stops.
const SHUTDOWN_GRACE: Duration = Duration::from_secs(3);
/// How long a killed group may take to disappear.
const REAP_WAIT: Duration = Duration::from_secs(5);

/// Process group (Unix) or process id (Windows) of the step running now.
type GroupSlot = Arc<Mutex<Option<u32>>>;

#[derive(Debug)]
struct Running {
    cancel: Option<oneshot::Sender<()>>,
    group: GroupSlot,
    /// Operator shell commands stop with the agent; package actions finish.
    shell: bool,
}

#[derive(Debug, Clone)]
pub struct Executor {
    allow_commands: bool,
    running: Arc<Mutex<HashMap<String, Running>>>,
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
            running: Arc::new(Mutex::new(HashMap::new())),
            updates,
        }
    }

    fn lock(&self) -> std::sync::MutexGuard<'_, HashMap<String, Running>> {
        self.running.lock().unwrap_or_else(PoisonError::into_inner)
    }

    /// Ids of commands still running, reported in `Hello`.
    pub fn running_ids(&self) -> Vec<String> {
        self.lock().keys().cloned().collect()
    }

    pub fn cancel(&self, id: &str) {
        if let Some(cancel) = self.lock().get_mut(id).and_then(|r| r.cancel.take()) {
            let _ = cancel.send(());
        }
    }

    /// Checks the request, then starts it in the background; the result
    /// arrives as `ExecExit`. Refusals never spawn a task, and never wait on
    /// a full connection.
    pub fn start(
        &self,
        id: String,
        spec: ExecSpec,
        timeout_seconds: u32,
        out: &mpsc::Sender<AgentMessage>,
    ) {
        if !valid_id(&id) {
            tracing::warn!("ignoring a command with an invalid id");
            return;
        }
        let refuse = |message: &str| {
            let _ = out.try_send(AgentMessage::ExecExit {
                id: id.clone(),
                outcome: refused(message),
            });
        };
        if !self.allow_commands {
            refuse("This device is monitor-only and does not run commands.");
            return;
        }
        let group = GroupSlot::default();
        let (cancel_tx, cancel_rx) = oneshot::channel();
        {
            let mut running = self.lock();
            if running.contains_key(&id) {
                // Replacing it would orphan the first command.
                tracing::warn!(exec = %id, "ignoring a duplicate command id");
                return;
            }
            if running.len() >= MAX_CONCURRENT_EXECS {
                drop(running);
                refuse("The device is already running the maximum number of commands.");
                return;
            }
            running.insert(
                id.clone(),
                Running {
                    cancel: Some(cancel_tx),
                    group: group.clone(),
                    shell: matches!(spec, ExecSpec::Shell { .. }),
                },
            );
        }
        let executor = self.clone();
        let out = out.clone();
        tokio::spawn(async move {
            let outcome = executor
                .execute(&id, spec, timeout_seconds, cancel_rx, &group, &out)
                .await;
            executor.lock().remove(&id);
            let _ = out.send(AgentMessage::ExecExit { id, outcome }).await;
        });
    }

    /// Stops every operator shell command; used when the agent stops.
    /// Package actions are left to finish so a package manager is not cut
    /// off mid-transaction (for example while upgrading this agent).
    pub async fn shutdown(&self) {
        let groups: Vec<u32> = self
            .lock()
            .values()
            .filter(|r| r.shell)
            .filter_map(|r| *r.group.lock().unwrap_or_else(PoisonError::into_inner))
            .collect();
        if groups.is_empty() {
            return;
        }
        tracing::info!(count = groups.len(), "stopping running commands");
        for group in &groups {
            signal_group(*group, Stop::Polite).await;
        }
        let until = Instant::now() + SHUTDOWN_GRACE;
        while groups.iter().any(|g| group_alive(*g)) && Instant::now() < until {
            tokio::time::sleep(Duration::from_millis(100)).await;
        }
        for group in &groups {
            if group_alive(*group) {
                signal_group(*group, Stop::Force).await;
            }
        }
    }

    async fn execute(
        &self,
        id: &str,
        spec: ExecSpec,
        timeout_seconds: u32,
        mut cancel: oneshot::Receiver<()>,
        group: &GroupSlot,
        out: &mpsc::Sender<AgentMessage>,
    ) -> ExecOutcome {
        let steps = match plan(&spec) {
            Ok(steps) => steps,
            Err(message) => return refused(message),
        };
        let shell = matches!(spec, ExecSpec::Shell { .. });
        let deadline = Instant::now() + Duration::from_secs(u64::from(timeout_seconds));
        let mut cancel = Some(&mut cancel);
        let mut sent = 0_usize;
        let mut last = ExecOutcome {
            state: ExecState::Succeeded,
            exit_code: Some(0),
            error: None,
        };
        for step in steps {
            let context = StepContext {
                id,
                deadline,
                group,
                out,
                kill_on_drop: shell,
            };
            last = run_step(&context, &step, &mut cancel, &mut sent).await;
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

struct StepContext<'a> {
    id: &'a str,
    deadline: Instant,
    group: &'a GroupSlot,
    out: &'a mpsc::Sender<AgentMessage>,
    /// False for package actions, which outlive an agent restart.
    kill_on_drop: bool,
}

/// Resolves when an operator cancels; never resolves once it has fired.
async fn canceled(cancel: &mut Option<&mut oneshot::Receiver<()>>) -> bool {
    match cancel {
        Some(receiver) => (&mut **receiver).await.is_ok(),
        None => std::future::pending().await,
    }
}

#[allow(clippy::too_many_lines)]
async fn run_step(
    context: &StepContext<'_>,
    step: &Step,
    cancel: &mut Option<&mut oneshot::Receiver<()>>,
    sent: &mut usize,
) -> ExecOutcome {
    let (id, out) = (context.id, context.out);
    let mut command = Command::new(&step.program);
    command
        .args(&step.args)
        .current_dir(work_directory())
        .env_clear()
        .envs(clean_environment())
        .envs(step.env.iter().cloned())
        .stdin(Stdio::null())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .kill_on_drop(context.kill_on_drop);
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
    // The group id equals the child's pid (process_group(0)).
    let group = child.id();
    *context.group.lock().unwrap_or_else(PoisonError::into_inner) = group;

    let (chunks_tx, mut chunks) = mpsc::channel::<Vec<u8>>(64);
    if let Some(stdout) = child.stdout.take() {
        tokio::spawn(pump(stdout, chunks_tx.clone()));
    }
    if let Some(stderr) = child.stderr.take() {
        tokio::spawn(pump(stderr, chunks_tx.clone()));
    }
    drop(chunks_tx);

    let never = Instant::now() + Duration::from_secs(365 * 24 * 60 * 60);
    let mut stopped: Option<(ExecState, &'static str)> = None;
    let mut kill_at: Option<Instant> = None;
    let mut killed = false;
    let mut status = None;
    let mut drain_until: Option<Instant> = None;
    let mut output_open = true;
    while status.is_none() || output_open {
        tokio::select! {
            chunk = chunks.recv(), if output_open => match chunk {
                Some(chunk) => send_output(id, &chunk, out, sent).await,
                None => output_open = false,
            },
            result = child.wait(), if status.is_none() => {
                status = Some(result);
                // A background process may hold the pipes open; read what
                // is left for a moment, then stop the rest of the group.
                drain_until = Some(Instant::now() + DRAIN);
            }
            () = tokio::time::sleep_until(context.deadline), if stopped.is_none() && status.is_none() => {
                stopped = Some((ExecState::TimedOut, "The command ran past its time limit and was stopped."));
                kill_at = Some(Instant::now() + KILL_GRACE);
                signal_any(group, Stop::Polite).await;
            }
            fired = canceled(cancel), if stopped.is_none() && status.is_none() && cancel.is_some() => {
                *cancel = None;
                if fired {
                    stopped = Some((ExecState::Canceled, "Canceled by an operator."));
                    kill_at = Some(Instant::now() + KILL_GRACE);
                    signal_any(group, Stop::Polite).await;
                }
            }
            // Escalate whatever the direct child did.
            () = tokio::time::sleep_until(kill_at.unwrap_or(never)), if kill_at.is_some() && !killed => {
                killed = true;
                signal_any(group, Stop::Force).await;
            }
            () = tokio::time::sleep_until(drain_until.unwrap_or(never)), if drain_until.is_some() => break,
        }
    }

    let all_gone = finish_group(group, kill_at, killed).await;
    *context.group.lock().unwrap_or_else(PoisonError::into_inner) = None;
    let leftover = (!all_gone).then(|| "Some of its processes could not be stopped.".to_owned());

    if let Some((state, message)) = stopped {
        let message = match leftover {
            Some(note) => format!("{message} {note}"),
            None => message.to_owned(),
        };
        return ExecOutcome {
            state,
            exit_code: None,
            error: Some(message),
        };
    }
    match status {
        Some(Ok(status)) if status.success() => ExecOutcome {
            state: ExecState::Succeeded,
            exit_code: Some(0),
            error: leftover,
        },
        Some(Ok(status)) => ExecOutcome {
            state: ExecState::Failed,
            exit_code: status.code(),
            error: signal_description(status).or(leftover),
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

/// Waits for the group to disappear, stopping what is left: by the pending
/// forced kill after a timeout or cancel, or politely and then by force for
/// leftovers of a command that finished. Returns false if any survive.
async fn finish_group(group: Option<u32>, kill_at: Option<Instant>, killed: bool) -> bool {
    let Some(group) = group else {
        return true;
    };
    if !group_alive(group) {
        return true;
    }
    if !killed {
        let until = if let Some(at) = kill_at {
            at
        } else {
            signal_group(group, Stop::Polite).await;
            Instant::now() + LEFTOVER_GRACE
        };
        while group_alive(group) && Instant::now() < until {
            tokio::time::sleep(Duration::from_millis(100)).await;
        }
        if group_alive(group) {
            signal_group(group, Stop::Force).await;
        }
    }
    let until = Instant::now() + REAP_WAIT;
    while group_alive(group) && Instant::now() < until {
        tokio::time::sleep(Duration::from_millis(100)).await;
    }
    let gone = !group_alive(group);
    if !gone {
        tracing::warn!(group, "processes of a command survived SIGKILL");
    }
    gone
}

#[derive(Debug, Clone, Copy)]
enum Stop {
    Polite,
    Force,
}

async fn signal_any(group: Option<u32>, stop: Stop) {
    if let Some(group) = group {
        signal_group(group, stop).await;
    }
}

/// SIGTERM or SIGKILL to the whole process group.
#[cfg(unix)]
#[allow(clippy::unused_async)]
async fn signal_group(group: u32, stop: Stop) {
    use nix::sys::signal::{Signal, killpg};
    use nix::unistd::Pid;
    let Ok(raw) = i32::try_from(group) else {
        return;
    };
    let signal = match stop {
        Stop::Polite => Signal::SIGTERM,
        Stop::Force => Signal::SIGKILL,
    };
    let _ = killpg(Pid::from_raw(raw), signal);
}

/// `taskkill /T` stops the process tree, `/F` forces it.
#[cfg(windows)]
async fn signal_group(pid: u32, stop: Stop) {
    let Some(taskkill) = crate::process::system32("taskkill.exe") else {
        return;
    };
    let pid = pid.to_string();
    let mut args = vec!["/T"];
    if matches!(stop, Stop::Force) {
        args.push("/F");
    }
    args.extend(["/PID", &pid]);
    let _ = Command::new(&taskkill)
        .args(&args)
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .status()
        .await;
}

/// True while any process (including an unreaped zombie) is in the group.
#[cfg(unix)]
fn group_alive(group: u32) -> bool {
    use nix::errno::Errno;
    use nix::sys::signal::killpg;
    use nix::unistd::Pid;
    let Ok(raw) = i32::try_from(group) else {
        return false;
    };
    !matches!(killpg(Pid::from_raw(raw), None), Err(Errno::ESRCH))
}

/// Windows has no process groups here; `taskkill /T` already walked the
/// tree, and only the direct child can be tracked.
#[cfg(windows)]
fn group_alive(_pid: u32) -> bool {
    false
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
