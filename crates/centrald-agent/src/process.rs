//! Child processes: short fixed-argument probes and streamed operator work.

use std::io::Read;
use std::process::{Command, Stdio};
use std::time::{Duration, Instant};

#[derive(Debug)]
pub struct Captured {
    pub code: Option<i32>,
    pub stdout: String,
}

/// Runs a fixed program with fixed arguments and captures stdout. Blocking.
/// Returns `None` if it cannot start or exceeds `timeout`.
pub fn run_capture(program: &str, args: &[&str], timeout: Duration) -> Option<Captured> {
    let mut child = Command::new(program)
        .args(args)
        .env("LANG", "C")
        .env("LC_ALL", "C")
        .stdin(Stdio::null())
        .stdout(Stdio::piped())
        .stderr(Stdio::null())
        .spawn()
        .ok()?;
    let mut stdout = child.stdout.take()?;
    let reader = std::thread::spawn(move || {
        let mut text = Vec::new();
        let _ = stdout.by_ref().take(4 * 1024 * 1024).read_to_end(&mut text);
        String::from_utf8_lossy(&text).into_owned()
    });
    let started = Instant::now();
    let status = loop {
        match child.try_wait() {
            Ok(Some(status)) => break status,
            Ok(None) if started.elapsed() < timeout => {
                std::thread::sleep(Duration::from_millis(50));
            }
            _ => {
                let _ = child.kill();
                let _ = child.wait();
                return None;
            }
        }
    };
    let stdout = reader.join().ok()?;
    Some(Captured {
        code: status.code(),
        stdout,
    })
}

/// The whole environment operator commands and terminals start from. Callers
/// clear the inherited environment first, so nothing from the agent's own
/// environment (service settings, credentials paths) leaks into commands.
pub fn clean_environment() -> Vec<(String, String)> {
    #[cfg_attr(not(unix), allow(unused_mut))]
    let mut env = Vec::new();
    #[cfg(unix)]
    {
        let home = if std::path::Path::new("/root").is_dir() {
            "/root"
        } else {
            "/"
        };
        env.push(("HOME".to_owned(), home.to_owned()));
        env.push(("USER".to_owned(), "root".to_owned()));
        env.push(("LOGNAME".to_owned(), "root".to_owned()));
        env.push(("SHELL".to_owned(), "/bin/sh".to_owned()));
        env.push((
            "PATH".to_owned(),
            "/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin".to_owned(),
        ));
        env.push(("LANG".to_owned(), "C.UTF-8".to_owned()));
    }
    #[cfg(windows)]
    {
        // Windows programs need these system locations to work at all.
        const KEEP: [&str; 22] = [
            "ALLUSERSPROFILE",
            "APPDATA",
            "COMPUTERNAME",
            "ComSpec",
            "CommonProgramFiles",
            "CommonProgramFiles(x86)",
            "CommonProgramW6432",
            "LOCALAPPDATA",
            "NUMBER_OF_PROCESSORS",
            "OS",
            "PATH",
            "PATHEXT",
            "PROCESSOR_ARCHITECTURE",
            "ProgramData",
            "ProgramFiles",
            "ProgramFiles(x86)",
            "ProgramW6432",
            "PSModulePath",
            "SystemDrive",
            "SystemRoot",
            "TEMP",
            "TMP",
        ];
        for key in KEEP.into_iter().chain(["USERPROFILE", "windir"]) {
            if let Some(value) = std::env::var_os(key) {
                env.push((key.to_owned(), value.to_string_lossy().into_owned()));
            }
        }
    }
    env
}

/// Working directory for operator work.
pub fn work_directory() -> std::path::PathBuf {
    #[cfg(unix)]
    {
        if std::path::Path::new("/root").is_dir() {
            return "/root".into();
        }
        "/".into()
    }
    #[cfg(windows)]
    {
        std::env::var_os("SystemDrive").map_or_else(std::env::temp_dir, |d| {
            std::path::PathBuf::from(format!("{}\\", d.to_string_lossy()))
        })
    }
}

/// `%SystemRoot%\System32\<program>`; `None` if the variable is unset.
#[cfg(windows)]
pub fn system32(program: &str) -> Option<std::path::PathBuf> {
    let root = std::env::var_os("SystemRoot").filter(|v| !v.is_empty())?;
    Some(
        std::path::PathBuf::from(root)
            .join("System32")
            .join(program),
    )
}

#[cfg(windows)]
pub fn powershell() -> Option<std::path::PathBuf> {
    Some(
        system32("WindowsPowerShell")?
            .join("v1.0")
            .join("powershell.exe"),
    )
}
