//! Interactive terminals on a real pseudo-terminal (PTY or `ConPTY`).

use std::collections::HashMap;
use std::io::{Read, Write};
use std::sync::{Arc, Mutex, PoisonError};

use centrald_proto::limits::{
    MAX_CHUNK_BYTES, MAX_CONCURRENT_TERMINALS, MAX_TERMINAL_COLUMNS, MAX_TERMINAL_ROWS,
};
use centrald_proto::wire::{AgentMessage, valid_id};
use portable_pty::{ChildKiller, CommandBuilder, MasterPty, PtySize, native_pty_system};
use tokio::sync::mpsc;

use crate::process::{clean_environment, work_directory};

struct Session {
    input: std::sync::mpsc::SyncSender<Vec<u8>>,
    master: Box<dyn MasterPty + Send>,
    killer: Box<dyn ChildKiller + Send + Sync>,
}

#[derive(Clone)]
pub struct Terminals {
    allow_commands: bool,
    sessions: Arc<Mutex<HashMap<String, Session>>>,
}

impl std::fmt::Debug for Terminals {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter.debug_struct("Terminals").finish_non_exhaustive()
    }
}

fn size(columns: u16, rows: u16) -> PtySize {
    PtySize {
        rows: rows.clamp(4, MAX_TERMINAL_ROWS),
        cols: columns.clamp(10, MAX_TERMINAL_COLUMNS),
        pixel_width: 0,
        pixel_height: 0,
    }
}

fn shell() -> CommandBuilder {
    #[cfg(unix)]
    {
        let program = ["/bin/bash", "/usr/bin/bash", "/bin/sh"]
            .into_iter()
            .find(|p| std::path::Path::new(p).exists())
            .unwrap_or("/bin/sh");
        let mut command = CommandBuilder::new(program);
        command.arg("-l");
        command
    }
    #[cfg(windows)]
    {
        let program = crate::process::powershell().map_or_else(
            || "powershell.exe".into(),
            std::path::PathBuf::into_os_string,
        );
        let mut command = CommandBuilder::new(program);
        command.arg("-NoLogo");
        command
    }
}

impl Terminals {
    pub fn new(allow_commands: bool) -> Self {
        Self {
            allow_commands,
            sessions: Arc::new(Mutex::new(HashMap::new())),
        }
    }

    fn lock(&self) -> std::sync::MutexGuard<'_, HashMap<String, Session>> {
        self.sessions.lock().unwrap_or_else(PoisonError::into_inner)
    }

    pub fn open(&self, id: String, columns: u16, rows: u16, out: &mpsc::Sender<AgentMessage>) {
        let refuse = |message: &str| {
            let _ = out.try_send(AgentMessage::TermExit {
                id: id.clone(),
                message: message.to_owned(),
            });
        };
        if !valid_id(&id) {
            tracing::warn!("ignoring a terminal with an invalid id");
            return;
        }
        if !self.allow_commands {
            refuse("This device is monitor-only, so terminals are turned off.");
            return;
        }
        // Check and insert under one lock so neither the cap nor an
        // existing session can be bypassed.
        let mut sessions = self.lock();
        if sessions.contains_key(&id) {
            tracing::warn!(terminal = %id, "ignoring a duplicate terminal id");
            return;
        }
        if sessions.len() >= MAX_CONCURRENT_TERMINALS {
            drop(sessions);
            refuse("Too many terminals are open on this device.");
            return;
        }
        match self.spawn(&id, columns, rows, out.clone()) {
            Ok(session) => {
                sessions.insert(id, session);
            }
            Err(error) => {
                drop(sessions);
                refuse(&format!("Could not start a shell: {error}"));
            }
        }
    }

    fn spawn(
        &self,
        id: &str,
        columns: u16,
        rows: u16,
        out: mpsc::Sender<AgentMessage>,
    ) -> anyhow::Result<Session> {
        let pair = native_pty_system().openpty(size(columns, rows))?;
        let mut command = shell();
        command.cwd(work_directory());
        command.env_clear();
        for (key, value) in clean_environment() {
            command.env(key, value);
        }
        command.env("TERM", "xterm-256color");
        command.env("COLORTERM", "truecolor");
        let mut child = pair.slave.spawn_command(command)?;
        drop(pair.slave);
        let killer = child.clone_killer();
        let mut reader = pair.master.try_clone_reader()?;
        let mut writer = pair.master.take_writer()?;
        let (input, input_rx) = std::sync::mpsc::sync_channel::<Vec<u8>>(256);

        // Keyboard input: a blocking writer thread.
        std::thread::spawn(move || {
            while let Ok(bytes) = input_rx.recv() {
                if writer
                    .write_all(&bytes)
                    .and_then(|()| writer.flush())
                    .is_err()
                {
                    return;
                }
            }
        });

        // Screen output: a blocking reader thread feeding the connection.
        let output_id = id.to_owned();
        let output = out.clone();
        let reader_thread = std::thread::spawn(move || {
            let mut buffer = vec![0_u8; MAX_CHUNK_BYTES];
            loop {
                match reader.read(&mut buffer) {
                    Ok(0) | Err(_) => return,
                    Ok(count) => {
                        let message = AgentMessage::TermOutput {
                            id: output_id.clone(),
                            data: buffer[..count].to_vec(),
                        };
                        if output.blocking_send(message).is_err() {
                            return;
                        }
                    }
                }
            }
        });

        // Exit: report once the shell ends and its output is drained.
        let exit_id = id.to_owned();
        let sessions = self.sessions.clone();
        std::thread::spawn(move || {
            let status = child.wait();
            // The master closes when the session is dropped, ending the reader.
            sessions
                .lock()
                .unwrap_or_else(PoisonError::into_inner)
                .remove(&exit_id);
            // Let trailing output drain, but a background job holding the
            // PTY open must not block the exit notice.
            for _ in 0..20 {
                if reader_thread.is_finished() {
                    break;
                }
                std::thread::sleep(std::time::Duration::from_millis(50));
            }
            let message = match status {
                Ok(status) if status.success() => "The shell exited.".to_owned(),
                Ok(status) => format!("The shell exited with code {}.", status.exit_code()),
                Err(error) => format!("The shell ended: {error}"),
            };
            let _ = out.blocking_send(AgentMessage::TermExit {
                id: exit_id,
                message,
            });
        });

        Ok(Session {
            input,
            master: pair.master,
            killer,
        })
    }

    pub fn input(&self, id: &str, data: Vec<u8>) {
        let sender = self.lock().get(id).map(|s| s.input.clone());
        if let Some(sender) = sender {
            // A full queue means the shell stopped reading; drop keystrokes
            // rather than stall the connection.
            let _ = sender.try_send(data);
        }
    }

    pub fn resize(&self, id: &str, columns: u16, rows: u16) {
        if let Some(session) = self.lock().get(id) {
            let _ = session.master.resize(size(columns, rows));
        }
    }

    pub fn close(&self, id: &str) {
        if let Some(mut session) = self.lock().remove(id) {
            let _ = session.killer.kill();
        }
    }

    /// Kills every shell; used when the server connection drops.
    pub fn close_all(&self) {
        let sessions: Vec<Session> = self.lock().drain().map(|(_, s)| s).collect();
        for mut session in sessions {
            let _ = session.killer.kill();
        }
    }
}
