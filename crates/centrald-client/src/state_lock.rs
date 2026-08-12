use std::fs::{File, OpenOptions};
use std::path::PathBuf;

use anyhow::{Context, Result, bail};
#[cfg(not(unix))]
use centrald_common::config::client_data_dir;
use fs2::FileExt;

#[cfg(not(unix))]
const STATE_LOCK_FILE: &str = ".centrald-state.lock";

/// Exclusive coordination lock for client credential and active-pointer mutations.
///
/// The daemon holds this lock only while loading/finalizing/renewing a credential
/// generation. Enrollment and privileged repair hold it for their complete state
/// transition. The network control stream never holds it.
#[derive(Debug)]
pub(crate) struct ClientStateLock {
    file: File,
    path: PathBuf,
}

impl ClientStateLock {
    /// Acquires the fixed client-state lock, waiting for a current mutation to
    /// finish.
    pub(crate) fn acquire() -> Result<Self> {
        let (file, path) = open_lock_file()?;
        FileExt::lock_exclusive(&file)
            .with_context(|| format!("lock CentralD client state {}", path.display()))?;
        Ok(Self { file, path })
    }

    /// Attempts to acquire the fixed client-state lock without blocking the
    /// async daemon runtime. `None` means another CentralD process is currently
    /// publishing, repairing, or renewing client state.
    pub(crate) fn try_acquire() -> Result<Option<Self>> {
        let (file, path) = open_lock_file()?;
        match FileExt::try_lock_exclusive(&file) {
            Ok(()) => Ok(Some(Self { file, path })),
            Err(error) if error.kind() == std::io::ErrorKind::WouldBlock => Ok(None),
            Err(error) => Err(error)
                .with_context(|| format!("lock CentralD client state {}", path.display())),
        }
    }

    #[must_use]
    pub(crate) fn path(&self) -> &std::path::Path {
        &self.path
    }
}

impl Drop for ClientStateLock {
    fn drop(&mut self) {
        let _ = FileExt::unlock(&self.file);
    }
}

/// Returns the fixed cross-process client-state lock path.
///
/// On Unix the lock inode lives directly below root-owned `/var/lib`, outside
/// the service-writable client state tree.
#[cfg(unix)]
pub(crate) fn state_lock_path() -> Result<PathBuf> {
    Ok(PathBuf::from("/var/lib/centrald-client.lock"))
}

/// Returns the fixed cross-process client-state lock path.
#[cfg(not(unix))]
pub(crate) fn state_lock_path() -> Result<PathBuf> {
    Ok(client_data_dir()?.join(STATE_LOCK_FILE))
}

fn open_lock_file() -> Result<(File, PathBuf)> {
    let path = state_lock_path()?;
    let parent = path
        .parent()
        .context("CentralD client state lock has no parent")?;
    let parent_metadata = parent
        .symlink_metadata()
        .with_context(|| format!("inspect client state-lock directory {}", parent.display()))?;
    if parent_metadata.file_type().is_symlink() || !parent_metadata.is_dir() {
        bail!(
            "client state-lock directory is unsafe: {}",
            parent.display()
        );
    }
    if let Ok(metadata) = path.symlink_metadata() {
        if metadata.file_type().is_symlink() || !metadata.is_file() {
            bail!("client state lock is unsafe: {}", path.display());
        }
    }

    let mut options = OpenOptions::new();
    options.read(true).write(true).create(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        options.mode(0o600);
    }
    let file = options
        .open(&path)
        .with_context(|| format!("open CentralD client state lock {}", path.display()))?;
    let metadata = file
        .metadata()
        .with_context(|| format!("inspect CentralD client state lock {}", path.display()))?;
    if !metadata.is_file() {
        bail!("client state lock is not a regular file: {}", path.display());
    }
    Ok((file, path))
}
