//! Live state: connected agents, running commands, open terminals, browser
//! sockets tied to sessions, and the event stream browsers subscribe to.

use std::collections::{HashMap, HashSet};
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::sync::{Arc, Mutex, PoisonError, Weak};
use std::time::{Duration, Instant};

use anyhow::Result;
use base64::Engine;
use base64::engine::general_purpose::STANDARD;
use centrald_proto::limits::MAX_CONCURRENT_TERMINALS;
use centrald_proto::wire::{ExecOutcome, ExecSpec, ExecState, ServerMessage, Status};
use serde::Serialize;
use tokio::sync::{broadcast, mpsc, watch};

use crate::auth::SESSION_IDLE_SECONDS;
use crate::db::{Db, now};
use crate::model::{self, DeviceView, RunView};

/// Output kept per command per device; the rest is dropped and flagged.
pub const MAX_RUN_OUTPUT_BYTES: usize = 1024 * 1024;
/// Longest wait for a peer (agent or browser) to accept one frame before
/// its connection is dropped.
pub const SOCKET_SEND_TIMEOUT: Duration = Duration::from_secs(10);
/// Extra time a device gets to report after its own timeout fires.
const WATCHDOG_GRACE: Duration = Duration::from_secs(30);
/// How long terminal output may wait on a slow browser before the session
/// is closed rather than stalling the agent connection.
const TERMINAL_SEND_TIMEOUT: Duration = Duration::from_secs(5);
/// How long terminal input may wait on a device queue that is full.
const INPUT_SEND_TIMEOUT: Duration = Duration::from_secs(5);
/// Messages queued for one agent connection.
const AGENT_QUEUE: usize = 256;
/// Status reports closer together than this are ignored.
const STATUS_MIN_GAP: Duration = Duration::from_secs(5);
/// Live status is written to disk at most this often per device.
const STATUS_PERSIST_EVERY: Duration = Duration::from_secs(60);
/// How often open browser sockets are checked against stored sessions, so
/// sessions ended elsewhere (console reset, expiry) close them too.
const SESSION_POLL: Duration = Duration::from_secs(1);
/// How often command results that failed to save are retried.
const SAVE_RETRY: Duration = Duration::from_secs(5);
/// Untracked targets younger than this may still be starting.
const ORPHAN_MIN_AGE_SECONDS: i64 = 5;

/// Browser-facing live events.
#[derive(Debug, Serialize)]
#[serde(
    tag = "type",
    rename_all = "snake_case",
    rename_all_fields = "camelCase"
)]
pub enum Event {
    Device {
        device: Box<DeviceView>,
    },
    DeviceRemoved {
        id: String,
    },
    Run {
        run: RunView,
    },
    RunOutput {
        run_id: String,
        device_id: String,
        offset: usize,
        data: String,
    },
    JoinTokens,
}

#[derive(Debug)]
pub enum TermEvent {
    Output(Vec<u8>),
    Exit(String),
}

/// The latest status from a connected device, kept in memory and written
/// to disk at most every [`STATUS_PERSIST_EVERY`].
#[derive(Debug)]
struct LiveStatus {
    status: Status,
    at: i64,
    received: Instant,
    persisted: Option<Instant>,
}

#[derive(Debug)]
struct AgentHandle {
    connection: u64,
    sender: mpsc::Sender<ServerMessage>,
    allow_commands: bool,
    close: watch::Sender<bool>,
    status: Option<LiveStatus>,
}

#[derive(Debug)]
struct ExecTrack {
    run_id: String,
    device_id: String,
    output: Vec<u8>,
    truncated: bool,
}

#[derive(Debug)]
struct TermTrack {
    device_id: String,
    connection: u64,
    sender: mpsc::Sender<TermEvent>,
}

#[derive(Debug)]
struct SessionSocket {
    session: [u8; 32],
    user_id: String,
    ended: watch::Sender<bool>,
}

/// A command result kept in memory because writing it failed.
#[derive(Debug, Clone)]
struct Unsaved {
    run_id: String,
    device_id: String,
    state: &'static str,
    exit_code: Option<i32>,
    error: Option<String>,
    finished_at: i64,
    output: Vec<u8>,
    truncated: bool,
}

#[derive(Debug, Default)]
struct Inner {
    agents: HashMap<String, AgentHandle>,
    execs: HashMap<String, ExecTrack>,
    terminals: HashMap<String, TermTrack>,
    sockets: HashMap<u64, SessionSocket>,
    unsaved: Vec<Unsaved>,
}

#[derive(Debug)]
pub struct Hub {
    db: Db,
    events: broadcast::Sender<Arc<str>>,
    inner: Mutex<Inner>,
    next_connection: AtomicU64,
    session_poll: AtomicBool,
    save_retry: AtomicBool,
}

pub enum StartError {
    Offline,
    MonitorOnly,
}

/// One registered agent connection.
pub struct AgentLink {
    pub connection: u64,
    pub outgoing: mpsc::Receiver<ServerMessage>,
    /// Becomes true when the server drops this connection (device removed
    /// or replaced by a newer connection).
    pub closed: watch::Receiver<bool>,
}

/// Ties a browser socket to its session; dropping it unregisters.
pub struct SessionWatch {
    hub: Arc<Hub>,
    id: u64,
    ended: watch::Receiver<bool>,
}

impl SessionWatch {
    /// Resolves once the session has ended.
    pub async fn ended(&mut self) {
        let _ = self.ended.wait_for(|ended| *ended).await;
    }
}

impl Drop for SessionWatch {
    fn drop(&mut self) {
        self.hub.lock().sockets.remove(&self.id);
    }
}

/// Closes a terminal when dropped, whether or not its upgrade happened.
pub struct TerminalGuard {
    hub: Arc<Hub>,
    pub id: String,
}

impl Drop for TerminalGuard {
    fn drop(&mut self) {
        self.hub.close_terminal(&self.id);
    }
}

impl Hub {
    pub fn new(db: Db) -> Arc<Self> {
        let (events, _) = broadcast::channel(1024);
        Arc::new(Self {
            db,
            events,
            inner: Mutex::new(Inner::default()),
            next_connection: AtomicU64::new(1),
            session_poll: AtomicBool::new(false),
            save_retry: AtomicBool::new(false),
        })
    }

    fn lock(&self) -> std::sync::MutexGuard<'_, Inner> {
        self.inner.lock().unwrap_or_else(PoisonError::into_inner)
    }

    pub fn subscribe(&self) -> broadcast::Receiver<Arc<str>> {
        self.events.subscribe()
    }

    pub fn emit(&self, event: &Event) {
        match serde_json::to_string(event) {
            Ok(json) => {
                let _ = self.events.send(Arc::from(json));
            }
            Err(error) => tracing::error!(%error, "cannot encode event"),
        }
    }

    /// Fills in what the database cannot know: the `online` flag and the
    /// newest status, which is written to disk only now and then.
    pub fn decorate(&self, device: &mut DeviceView) {
        let inner = self.lock();
        let Some(agent) = inner.agents.get(&device.id) else {
            device.online = false;
            return;
        };
        device.online = true;
        if let Some(live) = &agent.status {
            device.status = Some(live.status.clone());
            device.status_at = Some(live.at);
            device.last_seen_at = Some(device.last_seen_at.unwrap_or(0).max(live.at));
        }
    }

    pub async fn emit_device(&self, device_id: &str) {
        let id = device_id.to_owned();
        match self.db.call(move |c| model::get_device(c, &id)).await {
            Ok(Some(mut device)) => {
                self.decorate(&mut device);
                self.emit(&Event::Device {
                    device: Box::new(device),
                });
            }
            Ok(None) => {}
            Err(error) => tracing::error!(%error, "cannot load device"),
        }
    }

    pub async fn emit_run(&self, run_id: &str) {
        let id = run_id.to_owned();
        match self.db.call(move |c| model::get_run(c, &id, false)).await {
            Ok(Some(mut run)) => {
                self.overlay_unsaved(&mut run);
                self.emit(&Event::Run { run });
            }
            Ok(None) => {}
            Err(error) => tracing::error!(%error, "cannot load run"),
        }
    }

    /// Registers a connected agent. An older connection for the same device
    /// is told to close.
    pub fn register_agent(&self, device_id: &str, allow_commands: bool) -> AgentLink {
        let connection = self.next_connection.fetch_add(1, Ordering::Relaxed);
        let (sender, outgoing) = mpsc::channel(AGENT_QUEUE);
        let (close, closed) = watch::channel(false);
        let old = self.lock().agents.insert(
            device_id.to_owned(),
            AgentHandle {
                connection,
                sender,
                allow_commands,
                close,
                status: None,
            },
        );
        if let Some(old) = old {
            let _ = old.close.send(true);
        }
        AgentLink {
            connection,
            outgoing,
            closed,
        }
    }

    /// Forgets an agent connection and fails whatever it was doing.
    pub async fn unregister_agent(self: &Arc<Self>, device_id: &str, connection: u64) {
        let (current, lost, terminals, flush) = {
            let mut inner = self.lock();
            let current = inner
                .agents
                .get(device_id)
                .is_some_and(|agent| agent.connection == connection);
            let mut flush = None;
            let mut lost = Vec::new();
            if current {
                if let Some(agent) = inner.agents.remove(device_id) {
                    flush = agent
                        .status
                        .filter(|live| live.persisted.is_none_or(|p| p < live.received));
                }
                lost = inner
                    .execs
                    .iter()
                    .filter(|(_, track)| track.device_id == device_id)
                    .map(|(id, _)| id.clone())
                    .collect();
            }
            let terminals: Vec<String> = inner
                .terminals
                .iter()
                .filter(|(_, track)| track.device_id == device_id && track.connection == connection)
                .map(|(id, _)| id.clone())
                .collect();
            (current, lost, terminals, flush)
        };
        for terminal in terminals {
            self.term_exit(device_id, &terminal, "The device disconnected.".to_owned())
                .await;
        }
        if !current {
            return;
        }
        if let Some(live) = flush {
            self.persist_status(device_id, &live.status, live.at).await;
        }
        for exec_id in lost {
            self.finish_exec(
                &exec_id,
                "lost",
                None,
                Some("The device disconnected before the command finished.".to_owned()),
            )
            .await;
        }
        self.emit_device(device_id).await;
    }

    /// Cuts a removed device off at once: asks it to stop its commands and
    /// terminals, closes its connection, and ends its runs and terminals.
    pub async fn disconnect(self: &Arc<Self>, device_id: &str) {
        let execs = {
            let mut inner = self.lock();
            let execs: Vec<String> = inner
                .execs
                .iter()
                .filter(|(_, track)| track.device_id == device_id)
                .map(|(id, _)| id.clone())
                .collect();
            let terminals: Vec<String> = inner
                .terminals
                .iter()
                .filter(|(_, track)| track.device_id == device_id)
                .map(|(id, _)| id.clone())
                .collect();
            if let Some(agent) = inner.agents.remove(device_id) {
                // Queued ahead of the close; the session flushes them.
                for id in &execs {
                    let _ = agent
                        .sender
                        .try_send(ServerMessage::ExecCancel { id: id.clone() });
                }
                for id in &terminals {
                    let _ = agent
                        .sender
                        .try_send(ServerMessage::TermClose { id: id.clone() });
                }
                let _ = agent.close.send(true);
            }
            let ended: Vec<TermTrack> = terminals
                .iter()
                .filter_map(|id| inner.terminals.remove(id))
                .collect();
            for track in ended {
                let _ = track
                    .sender
                    .try_send(TermEvent::Exit("The device was removed.".to_owned()));
            }
            execs
        };
        for exec_id in execs {
            self.finish_exec(
                &exec_id,
                "lost",
                None,
                Some("The device was removed; CentralD asked it to stop the command.".to_owned()),
            )
            .await;
        }
    }

    fn agent_sender(&self, device_id: &str) -> Option<(mpsc::Sender<ServerMessage>, bool)> {
        self.lock()
            .agents
            .get(device_id)
            .map(|agent| (agent.sender.clone(), agent.allow_commands))
    }

    /// Takes a status report from the current connection of `device_id`.
    /// Returns `None` when it is ignored (too soon, or a stale connection),
    /// else whether it is due to be written to disk.
    pub fn accept_status(&self, device_id: &str, connection: u64, status: Status) -> Option<bool> {
        let mut inner = self.lock();
        let agent = inner
            .agents
            .get_mut(device_id)
            .filter(|agent| agent.connection == connection)?;
        let received = Instant::now();
        let persisted = match &agent.status {
            Some(live) if received.duration_since(live.received) < STATUS_MIN_GAP => return None,
            Some(live) => live.persisted,
            None => None,
        };
        let due = persisted.is_none_or(|p| received.duration_since(p) >= STATUS_PERSIST_EVERY);
        agent.status = Some(LiveStatus {
            status,
            at: now(),
            received,
            persisted: if due { Some(received) } else { persisted },
        });
        Some(due)
    }

    /// Writes a device's status, its last-seen time, and a metrics sample.
    #[allow(clippy::cast_precision_loss)]
    pub async fn persist_status(&self, device_id: &str, status: &Status, time: i64) {
        let Ok(json) = serde_json::to_string(status) else {
            return;
        };
        let memory = if status.memory.total_bytes > 0 {
            status.memory.used_bytes as f64 * 100.0 / status.memory.total_bytes as f64
        } else {
            0.0
        };
        let cpu = f64::from(status.cpu_percent);
        let load = status.load.map(|l| f64::from(l[0]));
        let id = device_id.to_owned();
        let result = self
            .db
            .call(move |c| {
                c.execute(
                    "UPDATE devices SET status_json = ?2, status_at = ?3,
                         last_seen_at = MAX(COALESCE(last_seen_at, 0), ?3)
                     WHERE id = ?1",
                    rusqlite::params![id, json, time],
                )?;
                // One sample per minute keeps a week of history small.
                c.execute(
                    "INSERT INTO metrics (device_id, at, cpu, memory, load)
                     SELECT ?1, ?2, ?3, ?4, ?5 WHERE EXISTS (SELECT 1 FROM devices WHERE id = ?1)
                     ON CONFLICT (device_id, at) DO UPDATE
                     SET cpu = excluded.cpu, memory = excluded.memory, load = excluded.load",
                    rusqlite::params![id, time - time % 60, cpu, memory.clamp(0.0, 100.0), load],
                )?;
                Ok(())
            })
            .await;
        if let Err(error) = result {
            tracing::error!(%error, "cannot store status");
        }
    }

    /// Sends one command to one device and starts tracking it.
    pub fn start_exec(
        self: &Arc<Self>,
        run_id: &str,
        device_id: &str,
        spec: ExecSpec,
        timeout_seconds: u32,
    ) -> Result<(), StartError> {
        let (sender, allow_commands) = self.agent_sender(device_id).ok_or(StartError::Offline)?;
        if !allow_commands {
            return Err(StartError::MonitorOnly);
        }
        let exec_id = uuid::Uuid::new_v4().to_string();
        self.lock().execs.insert(
            exec_id.clone(),
            ExecTrack {
                run_id: run_id.to_owned(),
                device_id: device_id.to_owned(),
                output: Vec::new(),
                truncated: false,
            },
        );
        let message = ServerMessage::ExecStart {
            id: exec_id.clone(),
            spec,
            timeout_seconds,
        };
        if sender.try_send(message).is_err() {
            self.lock().execs.remove(&exec_id);
            return Err(StartError::Offline);
        }
        drop(sender);
        // Backstop for an agent that never answers.
        let hub = self.clone();
        tokio::spawn(async move {
            tokio::time::sleep(Duration::from_secs(u64::from(timeout_seconds)) + WATCHDOG_GRACE)
                .await;
            let device = hub
                .lock()
                .execs
                .get(&exec_id)
                .map(|track| track.device_id.clone());
            if let Some(device) = device {
                if let Some((sender, _)) = hub.agent_sender(&device) {
                    let _ = sender.try_send(ServerMessage::ExecCancel {
                        id: exec_id.clone(),
                    });
                }
                hub.finish_exec(
                    &exec_id,
                    "timed_out",
                    None,
                    Some("The device did not report a result in time.".to_owned()),
                )
                .await;
            }
        });
        Ok(())
    }

    /// Appends output reported by `device_id` for one of its own commands.
    pub fn exec_output(&self, device_id: &str, exec_id: &str, data: &[u8]) {
        let event = {
            let mut inner = self.lock();
            let Some(track) = inner.execs.get_mut(exec_id) else {
                return;
            };
            if track.device_id != device_id || data.is_empty() {
                return;
            }
            let offset = track.output.len();
            let room = MAX_RUN_OUTPUT_BYTES.saturating_sub(offset);
            if room == 0 {
                track.truncated = true;
                return;
            }
            let kept = &data[..data.len().min(room)];
            if kept.len() < data.len() {
                track.truncated = true;
            }
            track.output.extend_from_slice(kept);
            Event::RunOutput {
                run_id: track.run_id.clone(),
                device_id: device_id.to_owned(),
                offset,
                data: STANDARD.encode(kept),
            }
        };
        self.emit(&event);
    }

    /// Records the result `device_id` reported for one of its own commands.
    pub async fn exec_exit(self: &Arc<Self>, device_id: &str, exec_id: &str, outcome: ExecOutcome) {
        let owned = self
            .lock()
            .execs
            .get(exec_id)
            .is_some_and(|track| track.device_id == device_id);
        if !owned {
            return;
        }
        let state = match outcome.state {
            ExecState::Succeeded => "succeeded",
            ExecState::Failed => "failed",
            ExecState::TimedOut => "timed_out",
            ExecState::Canceled => "canceled",
            ExecState::Refused => "refused",
        };
        // No escapes, bell, or bidi tricks in text operators read.
        let error = outcome
            .error
            .map(|text| centrald_proto::text::clean(&text, 1024));
        self.finish_exec(exec_id, state, outcome.exit_code, error)
            .await;
    }

    async fn finish_exec(
        self: &Arc<Self>,
        exec_id: &str,
        state: &'static str,
        exit_code: Option<i32>,
        error: Option<String>,
    ) {
        let Some(track) = self.lock().execs.remove(exec_id) else {
            return;
        };
        let result = Unsaved {
            run_id: track.run_id,
            device_id: track.device_id,
            state,
            exit_code,
            error,
            finished_at: now(),
            output: track.output,
            truncated: track.truncated,
        };
        let run_id = result.run_id.clone();
        if let Err(error) = self.save_result(result.clone()).await {
            // Kept in memory and retried, so the run cannot stay "running".
            tracing::error!(%error, "cannot record command result; will retry");
            self.lock().unsaved.push(result);
            self.start_save_retry();
        }
        self.emit_run(&run_id).await;
    }

    async fn save_result(&self, result: Unsaved) -> Result<()> {
        self.db
            .call(move |c| {
                c.execute(
                    "UPDATE run_targets
                     SET state = ?3, exit_code = ?4, error = ?5, finished_at = ?6,
                         output = ?7, truncated = ?8
                     WHERE run_id = ?1 AND device_id = ?2 AND state = 'running'",
                    rusqlite::params![
                        result.run_id,
                        result.device_id,
                        result.state,
                        result.exit_code,
                        result.error,
                        result.finished_at,
                        result.output,
                        result.truncated
                    ],
                )?;
                Ok(())
            })
            .await
    }

    fn start_save_retry(self: &Arc<Self>) {
        if self.save_retry.swap(true, Ordering::SeqCst) {
            return;
        }
        let hub = Arc::downgrade(self);
        tokio::spawn(async move {
            loop {
                tokio::time::sleep(SAVE_RETRY).await;
                let Some(hub) = hub.upgrade() else { return };
                let pending = std::mem::take(&mut hub.lock().unsaved);
                let mut saved = Vec::new();
                for result in pending {
                    let run_id = result.run_id.clone();
                    if hub.save_result(result.clone()).await.is_ok() {
                        saved.push(run_id);
                    } else {
                        hub.lock().unsaved.push(result);
                    }
                }
                for run_id in saved {
                    hub.emit_run(&run_id).await;
                }
                let mut inner = hub.lock();
                if inner.unsaved.is_empty() {
                    hub.save_retry.store(false, Ordering::SeqCst);
                    drop(inner);
                    return;
                }
                inner.unsaved.shrink_to_fit();
            }
        });
    }

    /// Shows results that are finished but not yet saved.
    pub fn overlay_unsaved(&self, run: &mut RunView) {
        let inner = self.lock();
        for target in &mut run.targets {
            if target.state != "running" {
                continue;
            }
            if let Some(done) = inner
                .unsaved
                .iter()
                .find(|u| u.run_id == run.id && u.device_id == target.device_id)
            {
                target.state = done.state.to_owned();
                target.exit_code = done.exit_code.map(i64::from);
                target.error.clone_from(&done.error);
                target.finished_at = Some(done.finished_at);
                target.output_bytes = i64::try_from(done.output.len()).unwrap_or(i64::MAX);
                if target.output.is_some() {
                    target.output = Some(STANDARD.encode(&done.output));
                }
                target.truncated = done.truncated;
            }
        }
    }

    /// Output collected so far for a target that is still running.
    pub fn live_output(&self, run_id: &str, device_id: &str) -> Option<(Vec<u8>, bool)> {
        self.lock()
            .execs
            .values()
            .find(|track| track.run_id == run_id && track.device_id == device_id)
            .map(|track| (track.output.clone(), track.truncated))
    }

    /// Asks every device still working on `run_id` to stop, and closes
    /// targets nothing tracks any more. Returns how many it handled.
    pub async fn cancel_run(&self, run_id: &str) -> Result<usize> {
        let (mut handled, known) = {
            let inner = self.lock();
            let mut sent = 0;
            let mut known = HashSet::new();
            for (exec_id, track) in &inner.execs {
                if track.run_id != run_id {
                    continue;
                }
                known.insert(track.device_id.clone());
                if let Some(agent) = inner.agents.get(&track.device_id)
                    && agent
                        .sender
                        .try_send(ServerMessage::ExecCancel {
                            id: exec_id.clone(),
                        })
                        .is_ok()
                {
                    sent += 1;
                }
            }
            known.extend(
                inner
                    .unsaved
                    .iter()
                    .filter(|u| u.run_id == run_id)
                    .map(|u| u.device_id.clone()),
            );
            (sent, known)
        };
        let id = run_id.to_owned();
        let orphans = self
            .db
            .call(move |c| {
                let time = now();
                let mut statement = c.prepare(
                    "SELECT device_id FROM run_targets
                     WHERE run_id = ?1 AND state = 'running' AND started_at <= ?2",
                )?;
                let devices = statement
                    .query_map(rusqlite::params![id, time - ORPHAN_MIN_AGE_SECONDS], |r| {
                        r.get::<_, String>(0)
                    })?
                    .collect::<rusqlite::Result<Vec<_>>>()?;
                let mut closed = 0;
                for device in devices.iter().filter(|d| !known.contains(*d)) {
                    closed += c.execute(
                        "UPDATE run_targets SET state = 'canceled', finished_at = ?3,
                             error = 'Canceled. CentralD had lost track of this command.'
                         WHERE run_id = ?1 AND device_id = ?2 AND state = 'running'",
                        rusqlite::params![id, device, time],
                    )?;
                }
                Ok(closed)
            })
            .await?;
        handled += orphans;
        if orphans > 0 {
            self.emit_run(run_id).await;
        }
        Ok(handled)
    }

    /// Opens a terminal on a device. Returns a guard that closes it when
    /// dropped, and the stream of output.
    pub fn open_terminal(
        self: &Arc<Self>,
        device_id: &str,
        columns: u16,
        rows: u16,
    ) -> Result<(TerminalGuard, mpsc::Receiver<TermEvent>), &'static str> {
        let mut inner = self.lock();
        let agent = inner
            .agents
            .get(device_id)
            .ok_or("The device is offline.")?;
        if !agent.allow_commands {
            return Err("This device is monitor-only, so terminals are turned off.");
        }
        let connection = agent.connection;
        let open = inner
            .terminals
            .values()
            .filter(|track| track.device_id == device_id)
            .count();
        if open >= MAX_CONCURRENT_TERMINALS {
            return Err("Too many terminals are already open on this device.");
        }
        let id = uuid::Uuid::new_v4().to_string();
        let (events, receiver) = mpsc::channel(256);
        agent
            .sender
            .try_send(ServerMessage::TermOpen {
                id: id.clone(),
                columns,
                rows,
            })
            .map_err(|_| "The device is busy; try again.")?;
        inner.terminals.insert(
            id.clone(),
            TermTrack {
                device_id: device_id.to_owned(),
                connection,
                sender: events,
            },
        );
        Ok((
            TerminalGuard {
                hub: self.clone(),
                id,
            },
            receiver,
        ))
    }

    /// The live connection a terminal belongs to, looked up per message so
    /// a removed or replaced device gets nothing more.
    fn terminal_agent(&self, id: &str) -> Option<mpsc::Sender<ServerMessage>> {
        let inner = self.lock();
        let track = inner.terminals.get(id)?;
        inner
            .agents
            .get(&track.device_id)
            .filter(|agent| agent.connection == track.connection)
            .map(|agent| agent.sender.clone())
    }

    /// Forwards keyboard input. False when the device is gone or stuck.
    pub async fn term_input(&self, id: &str, data: Vec<u8>) -> bool {
        let Some(sender) = self.terminal_agent(id) else {
            return false;
        };
        let message = ServerMessage::TermInput {
            id: id.to_owned(),
            data,
        };
        sender
            .send_timeout(message, INPUT_SEND_TIMEOUT)
            .await
            .is_ok()
    }

    pub fn term_resize(&self, id: &str, columns: u16, rows: u16) {
        if let Some(sender) = self.terminal_agent(id) {
            let _ = sender.try_send(ServerMessage::TermResize {
                id: id.to_owned(),
                columns,
                rows,
            });
        }
    }

    pub async fn term_output(&self, device_id: &str, connection: u64, id: &str, data: Vec<u8>) {
        let sender = match self.lock().terminals.get(id) {
            Some(track) if track.device_id == device_id && track.connection == connection => {
                track.sender.clone()
            }
            _ => return,
        };
        let sent =
            tokio::time::timeout(TERMINAL_SEND_TIMEOUT, sender.send(TermEvent::Output(data))).await;
        if !matches!(sent, Ok(Ok(()))) {
            self.close_terminal(id);
        }
    }

    pub async fn term_exit(&self, device_id: &str, id: &str, message: String) {
        let track = {
            let mut inner = self.lock();
            match inner.terminals.get(id) {
                Some(track) if track.device_id == device_id => inner.terminals.remove(id),
                _ => None,
            }
        };
        if let Some(track) = track {
            let _ = tokio::time::timeout(
                TERMINAL_SEND_TIMEOUT,
                track.sender.send(TermEvent::Exit(message)),
            )
            .await;
        }
    }

    /// Closes a terminal from the server side and tells the agent.
    pub fn close_terminal(&self, id: &str) {
        let mut inner = self.lock();
        let Some(track) = inner.terminals.remove(id) else {
            return;
        };
        if let Some(agent) = inner
            .agents
            .get(&track.device_id)
            .filter(|agent| agent.connection == track.connection)
        {
            let _ = agent
                .sender
                .try_send(ServerMessage::TermClose { id: id.to_owned() });
        }
    }

    /// Registers a browser socket opened by `session`; it closes when the
    /// session ends here or anywhere else.
    pub fn watch_session(self: &Arc<Self>, session: [u8; 32], user_id: &str) -> SessionWatch {
        let id = self.next_connection.fetch_add(1, Ordering::Relaxed);
        let (ended, receiver) = watch::channel(false);
        self.lock().sockets.insert(
            id,
            SessionSocket {
                session,
                user_id: user_id.to_owned(),
                ended,
            },
        );
        if !self.session_poll.swap(true, Ordering::SeqCst) {
            tokio::spawn(poll_sessions(Arc::downgrade(self)));
        }
        SessionWatch {
            hub: self.clone(),
            id,
            ended: receiver,
        }
    }

    /// Closes the sockets of one session (sign-out).
    pub fn end_session(&self, session: &[u8; 32]) {
        for socket in self.lock().sockets.values() {
            if &socket.session == session {
                let _ = socket.ended.send(true);
            }
        }
    }

    /// Closes the sockets of every session of `user_id` except `keep`.
    pub fn end_user_sessions(&self, user_id: &str, keep: Option<&[u8; 32]>) {
        for socket in self.lock().sockets.values() {
            if socket.user_id == user_id && keep != Some(&socket.session) {
                let _ = socket.ended.send(true);
            }
        }
    }

    /// Marks work interrupted by a previous server run as lost.
    pub fn recover_on_start(db: &Db) -> Result<()> {
        db.call_blocking(|c| {
            c.execute(
                "UPDATE run_targets SET state = 'lost', finished_at = ?1,
                     error = 'The server restarted before the command finished.'
                 WHERE state = 'running'",
                [now()],
            )?;
            Ok(())
        })
    }
}

/// Closes browser sockets whose session no longer exists or has expired.
/// Read-only, so an open tab never keeps a session from going idle.
async fn poll_sessions(hub: Weak<Hub>) {
    let mut tick = tokio::time::interval(SESSION_POLL);
    loop {
        tick.tick().await;
        let Some(hub) = hub.upgrade() else { return };
        let watched: HashSet<[u8; 32]> = hub.lock().sockets.values().map(|s| s.session).collect();
        if watched.is_empty() {
            continue;
        }
        let valid = hub
            .db
            .call(|c| {
                let time = now();
                let mut statement = c.prepare_cached(
                    "SELECT token_hash FROM sessions
                     WHERE expires_at > ?1 AND last_seen_at > ?2",
                )?;
                let rows = statement
                    .query_map(rusqlite::params![time, time - SESSION_IDLE_SECONDS], |r| {
                        r.get::<_, Vec<u8>>(0)
                    })?
                    .collect::<rusqlite::Result<Vec<_>>>()?;
                Ok(rows)
            })
            .await;
        // A failed read closes nothing; the next tick tries again.
        let Ok(valid) = valid else { continue };
        let valid: HashSet<&[u8]> = valid.iter().map(Vec::as_slice).collect();
        for socket in hub.lock().sockets.values() {
            if !valid.contains(socket.session.as_slice()) {
                let _ = socket.ended.send(true);
            }
        }
    }
}
