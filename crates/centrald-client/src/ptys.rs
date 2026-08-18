//! Real PTY/ConPTY session execution for the broker.
//!
//! Sessions use `portable-pty` so the same code path drives Unix PTYs and
//! Windows `ConPTY`. Command lines are fixed executable paths with fixed
//! argument lists; no shell interpolation happens on the broker side.

use std::sync::{Arc, Mutex};

use anyhow::{Context, Result, bail};
use portable_pty::{Child, CommandBuilder, MasterPty, PtySize, native_pty_system};

/// Shell programs the broker may start, by platform. Empty parameter selects
/// the first entry of the platform list.
const LINUX_ALLOWED_SHELLS: &[&str] = &["/bin/bash", "/bin/sh"];
const WINDOWS_ALLOWED_SHELLS: &[&str] = &["cmd.exe", "powershell.exe"];

/// Privilege requested for a shell session.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SessionPrivilege {
    Low,
    Elevated,
}

/// Everything the broker needs to start one PTY session.
#[derive(Debug, Clone)]
pub struct PtySessionSpec {
    pub privilege: SessionPrivilege,
    /// OS account the shell runs as. Empty selects the platform default.
    pub user: String,
    /// Shell program (fixed path). Empty selects the platform default.
    pub shell: String,
    pub columns: u32,
    pub rows: u32,
}

/// A running PTY session with bounded master I/O.
#[allow(dead_code)]
pub struct PtySession {
    master_reader: Box<dyn std::io::Read + Send>,
    master_writer: Box<dyn std::io::Write + Send>,
    controller: Arc<Mutex<Option<PtyController>>>,
}

/// Shared session controller: the child process and the PTY/ConPTY master.
/// Dropping it closes the master, which unblocks a pending master read
/// (`ConPTY` closes its output pipe only when the pseudoconsole is closed).
pub struct PtyController {
    child: Option<Box<dyn Child + Send + Sync>>,
    master: Box<dyn MasterPty + Send>,
}

impl std::fmt::Debug for PtyController {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter
            .debug_struct("PtyController")
            .field("child", &self.child.as_ref().map(|_| "<child>"))
            .finish_non_exhaustive()
    }
}

impl PtyController {
    /// Resizes the terminal.
    ///
    /// # Errors
    ///
    /// Returns an error when the resize fails or the session is closed.
    pub fn resize(&mut self, columns: u32, rows: u32) -> Result<()> {
        let size = PtySize {
            rows: u16::try_from(rows).unwrap_or(u16::MAX),
            cols: u16::try_from(columns).unwrap_or(u16::MAX),
            pixel_width: 0,
            pixel_height: 0,
        };
        self.master.resize(size).context("resize the PTY/ConPTY")
    }

    /// Terminates the session child and its whole process group, then closes
    /// the master so any blocked reader returns.
    pub fn kill(&mut self) {
        if let Some(child) = self.child.as_mut() {
            #[cfg(unix)]
            {
                if let Some(pid) = child.process_id() {
                    // portable-pty puts the child in its own session (setsid),
                    // so the child pid is its process-group leader; killing the
                    // group terminates grandchildren that keep the PTY slave
                    // open (e.g. `sleep 999 &`).
                    if let Some(process_group) = rustix::process::Pid::from_raw(pid as i32) {
                        let _ = rustix::process::kill_process_group(
                            process_group,
                            rustix::process::Signal::KILL,
                        );
                    }
                }
            }
            let _ = child.kill();
        }
    }
}

impl std::fmt::Debug for PtySession {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter.debug_struct("PtySession").finish_non_exhaustive()
    }
}

impl PtySession {
    /// Opens a PTY, spawns the requested shell, and splits the session into
    /// its reader, writer, and shared controller parts.
    ///
    /// # Errors
    ///
    /// Returns an error when the PTY cannot be created or the fixed shell
    /// command cannot start.
    pub fn open(spec: &PtySessionSpec) -> Result<PtyParts> {
        let (program, args) = shell_command(spec)?;
        let pty_system = native_pty_system();
        let mut size = PtySize {
            rows: u16::try_from(spec.rows).unwrap_or(u16::MAX),
            cols: u16::try_from(spec.columns).unwrap_or(u16::MAX),
            pixel_width: 0,
            pixel_height: 0,
        };
        size.rows = size.rows.clamp(2, 500);
        size.cols = size.cols.clamp(2, 500);
        let pair = pty_system
            .openpty(size)
            .context("open the PTY/ConPTY pair")?;
        let mut builder = CommandBuilder::new(program);
        for argument in args {
            builder.arg(argument);
        }
        let child = pair
            .slave
            .spawn_command(builder)
            .context("spawn the shell in the PTY/ConPTY")?;
        drop(pair.slave);
        let master_reader = pair
            .master
            .try_clone_reader()
            .context("clone the PTY/ConPTY reader")?;
        let master_writer = pair
            .master
            .take_writer()
            .context("take the PTY/ConPTY writer")?;
        let controller = Arc::new(Mutex::new(Some(PtyController {
            child: Some(child),
            master: pair.master,
        })));
        Ok(PtyParts {
            reader: master_reader,
            writer: master_writer,
            controller,
        })
    }
}

/// The split pieces of a PTY session: the input thread owns the writer, the
/// output thread owns the reader, and the watchdog shares the controller.
#[allow(missing_debug_implementations)]
pub struct PtyParts {
    pub reader: Box<dyn std::io::Read + Send>,
    pub writer: Box<dyn std::io::Write + Send>,
    pub controller: Arc<Mutex<Option<PtyController>>>,
}

fn shell_command(spec: &PtySessionSpec) -> Result<(String, Vec<String>)> {
    let allowed: &[&str] = if cfg!(windows) {
        WINDOWS_ALLOWED_SHELLS
    } else {
        LINUX_ALLOWED_SHELLS
    };
    let shell = if spec.shell.is_empty() {
        allowed[0]
    } else if allowed.contains(&spec.shell.as_str()) {
        spec.shell.as_str()
    } else {
        bail!(
            "requested shell {:?} is not in the broker allowlist",
            spec.shell
        );
    };
    match spec.privilege {
        SessionPrivilege::Elevated => Ok((shell.to_owned(), Vec::new())),
        SessionPrivilege::Low => {
            #[cfg(target_os = "linux")]
            {
                let user = if spec.user.is_empty() {
                    "centrald".to_owned()
                } else {
                    spec.user.clone()
                };
                if user == "root" {
                    bail!("a low shell must not run as root; request an elevated shell instead");
                }
                Ok((
                    "/usr/bin/runuser".to_owned(),
                    vec!["-u".to_owned(), user, "--".to_owned(), shell.to_owned()],
                ))
            }
            #[cfg(not(target_os = "linux"))]
            {
                let _ = shell;
                bail!(
                    "low-privilege shells are not supported on this platform in this build; request an elevated shell instead"
                )
            }
        }
    }
}

#[cfg(test)]
#[allow(clippy::unwrap_used)]
mod tests {
    use super::*;

    #[test]
    fn elevated_shell_must_be_allowlisted() {
        let spec = PtySessionSpec {
            privilege: SessionPrivilege::Elevated,
            user: String::new(),
            shell: "/usr/bin/python3".to_owned(),
            columns: 80,
            rows: 24,
        };
        assert!(shell_command(&spec).is_err());
    }

    #[test]
    fn empty_shell_selects_the_platform_default() {
        let spec = PtySessionSpec {
            privilege: SessionPrivilege::Elevated,
            user: String::new(),
            shell: String::new(),
            columns: 80,
            rows: 24,
        };
        let (program, args) = shell_command(&spec).unwrap();
        assert!(!program.is_empty());
        assert!(args.is_empty());
    }

    #[cfg(target_os = "linux")]
    #[test]
    fn low_shell_targets_the_service_account_and_rejects_root() {
        let spec = PtySessionSpec {
            privilege: SessionPrivilege::Low,
            user: String::new(),
            shell: "/bin/bash".to_owned(),
            columns: 80,
            rows: 24,
        };
        let (program, args) = shell_command(&spec).unwrap();
        assert_eq!(program, "/usr/bin/runuser");
        assert_eq!(args, ["-u", "centrald", "--", "/bin/bash"]);

        let root = PtySessionSpec {
            privilege: SessionPrivilege::Low,
            user: "root".to_owned(),
            shell: "/bin/bash".to_owned(),
            columns: 80,
            rows: 24,
        };
        assert!(shell_command(&root).is_err());
    }
}
