//! Live state: connected agents, running commands, open terminals, and the
//! event stream browsers subscribe to.

use std::collections::HashMap;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{Arc, Mutex, PoisonError};
use std::time::Duration;

use anyhow::Result;
use base64::Engine;
use base64::engine::general_purpose::STANDARD;
use centrald_proto::limits::MAX_CONCURRENT_TERMINALS;
use centrald_proto::wire::{ExecOutcome, ExecSpec, ExecState, ServerMessage};
use serde::Serialize;
use tokio::sync::{broadcast, mpsc};

use crate::db::{Db, now};
use crate::model::{self, DeviceView, RunView};

/// Output kept per command per device; the rest is dropped and flagged.
pub const MAX_RUN_OUTPUT_BYTES: usize = 1024 * 1024;
/// Extra time a device gets to report after its own timeout fires.
const WATCHDOG_GRACE: Duration = Duration::from_secs(30);
/// How long terminal output may wait on a slow browser before the session
/// is closed rather than stalling the agent connection.
const TERMINAL_SEND_TIMEOUT: Duration = Duration::from_secs(5);

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

#[derive(Debug)]
struct AgentHandle {
    connection: u64,
    sender: mpsc::Sender<ServerMessage>,
    allow_commands: bool,
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
    sender: mpsc::Sender<TermEvent>,
}

#[derive(Debug, Default)]
struct Inner {
    agents: HashMap<String, AgentHandle>,
    execs: HashMap<String, ExecTrack>,
    terminals: HashMap<String, TermTrack>,
}

#[derive(Debug)]
pub struct Hub {
    db: Db,
    events: broadcast::Sender<Arc<str>>,
    inner: Mutex<Inner>,
    next_connection: AtomicU64,
}

pub enum StartError {
    Offline,
    MonitorOnly,
}

impl Hub {
    pub fn new(db: Db) -> Arc<Self> {
        let (events, _) = broadcast::channel(1024);
        Arc::new(Self {
            db,
            events,
            inner: Mutex::new(Inner::default()),
            next_connection: AtomicU64::new(1),
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

    pub fn is_online(&self, device_id: &str) -> bool {
        self.lock().agents.contains_key(device_id)
    }

    /// Fills in the `online` flag the database cannot know.
    pub fn decorate(&self, device: &mut DeviceView) {
        device.online = self.is_online(&device.id);
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
            Ok(Some(run)) => self.emit(&Event::Run { run }),
            Ok(None) => {}
            Err(error) => tracing::error!(%error, "cannot load run"),
        }
    }

    /// Registers a connected agent, replacing any older connection for the
    /// same device (whose loop then ends because its channel closes).
    pub fn register_agent(
        &self,
        device_id: &str,
        allow_commands: bool,
    ) -> (u64, mpsc::Receiver<ServerMessage>) {
        let connection = self.next_connection.fetch_add(1, Ordering::Relaxed);
        let (sender, receiver) = mpsc::channel(256);
        self.lock().agents.insert(
            device_id.to_owned(),
            AgentHandle {
                connection,
                sender,
                allow_commands,
            },
        );
        (connection, receiver)
    }

    /// Forgets an agent connection and fails whatever it was doing.
    pub async fn unregister_agent(&self, device_id: &str, connection: u64) {
        let (lost, terminals) = {
            let mut inner = self.lock();
            if inner
                .agents
                .get(device_id)
                .is_none_or(|agent| agent.connection != connection)
            {
                return;
            }
            inner.agents.remove(device_id);
            let lost: Vec<String> = inner
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
            (lost, terminals)
        };
        for exec_id in lost {
            self.finish_exec(
                &exec_id,
                "lost",
                None,
                Some("The device disconnected before the command finished.".to_owned()),
            )
            .await;
        }
        for terminal in terminals {
            self.term_exit(device_id, &terminal, "The device disconnected.".to_owned())
                .await;
        }
        self.emit_device(device_id).await;
    }

    /// Drops the live connection of a removed device.
    pub fn disconnect(&self, device_id: &str) {
        self.lock().agents.remove(device_id);
    }

    fn agent_sender(&self, device_id: &str) -> Option<(mpsc::Sender<ServerMessage>, bool)> {
        self.lock()
            .agents
            .get(device_id)
            .map(|agent| (agent.sender.clone(), agent.allow_commands))
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
    pub async fn exec_exit(&self, device_id: &str, exec_id: &str, outcome: ExecOutcome) {
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
        let error = outcome
            .error
            .map(|text| text.chars().take(1024).collect::<String>());
        self.finish_exec(exec_id, state, outcome.exit_code, error)
            .await;
    }

    async fn finish_exec(
        &self,
        exec_id: &str,
        state: &'static str,
        exit_code: Option<i32>,
        error: Option<String>,
    ) {
        let Some(track) = self.lock().execs.remove(exec_id) else {
            return;
        };
        let run_id = track.run_id.clone();
        let result = self
            .db
            .call(move |c| {
                c.execute(
                    "UPDATE run_targets
                     SET state = ?3, exit_code = ?4, error = ?5, finished_at = ?6,
                         output = ?7, truncated = ?8
                     WHERE run_id = ?1 AND device_id = ?2 AND state = 'running'",
                    rusqlite::params![
                        track.run_id,
                        track.device_id,
                        state,
                        exit_code,
                        error,
                        now(),
                        track.output,
                        track.truncated
                    ],
                )?;
                Ok(())
            })
            .await;
        if let Err(error) = result {
            tracing::error!(%error, "cannot record command result");
        }
        self.emit_run(&run_id).await;
    }

    /// Output collected so far for a target that is still running.
    pub fn live_output(&self, run_id: &str, device_id: &str) -> Option<(Vec<u8>, bool)> {
        self.lock()
            .execs
            .values()
            .find(|track| track.run_id == run_id && track.device_id == device_id)
            .map(|track| (track.output.clone(), track.truncated))
    }

    /// Asks every device still working on `run_id` to stop.
    pub fn cancel_run(&self, run_id: &str) -> usize {
        let inner = self.lock();
        let mut sent = 0;
        for (exec_id, track) in &inner.execs {
            if track.run_id != run_id {
                continue;
            }
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
        sent
    }

    /// Opens a terminal on a device. Returns its id, the stream of output,
    /// and the channel to the agent for input.
    pub fn open_terminal(
        &self,
        device_id: &str,
        columns: u16,
        rows: u16,
    ) -> Result<
        (
            String,
            mpsc::Receiver<TermEvent>,
            mpsc::Sender<ServerMessage>,
        ),
        &'static str,
    > {
        let mut inner = self.lock();
        let agent = inner
            .agents
            .get(device_id)
            .ok_or("The device is offline.")?;
        if !agent.allow_commands {
            return Err("This device is monitor-only, so terminals are turned off.");
        }
        let sender = agent.sender.clone();
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
        sender
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
                sender: events,
            },
        );
        Ok((id, receiver, sender))
    }

    pub async fn term_output(&self, device_id: &str, id: &str, data: Vec<u8>) {
        let sender = match self.lock().terminals.get(id) {
            Some(track) if track.device_id == device_id => track.sender.clone(),
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
        if let Some(agent) = inner.agents.get(&track.device_id) {
            let _ = agent
                .sender
                .try_send(ServerMessage::TermClose { id: id.to_owned() });
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
