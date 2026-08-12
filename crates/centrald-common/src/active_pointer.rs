use std::fs::{self, File, OpenOptions};
use std::path::{Path, PathBuf};

use fs2::FileExt;
use thiserror::Error;

const CURRENT_FILE: &str = "current.pointer";
const NEXT_FILE: &str = ".current.pointer.next";
const PREVIOUS_FILE: &str = ".current.pointer.previous";
const LOCK_FILE: &str = ".current.pointer.lock";

#[derive(Debug, Error)]
pub enum ActivePointerError {
    #[error("active-pointer directory is unsafe: {0}")]
    UnsafeDirectory(PathBuf),
    #[error("active-pointer file is unsafe: {0}")]
    UnsafeFile(PathBuf),
    #[error("active-pointer value must be one simple relative file name")]
    InvalidValue,
    #[error("no active credential generation has been published")]
    Missing,
    #[error("a previous credential publication still needs activation or rollback")]
    PendingPublication,
    #[error("active-pointer I/O failed for {path}: {source}")]
    Io {
        path: PathBuf,
        #[source]
        source: std::io::Error,
    },
}

/// A fixed, crash-recoverable pointer to the active credential metadata file.
///
/// Updates use sibling `next` and `previous` files under an exclusive lock. No
/// operation relies on directory ordering or timestamps. Each rename has a
/// non-existing destination, which keeps the protocol portable to Windows.
#[derive(Debug, Clone)]
pub struct ActivePointer {
    directory: PathBuf,
}

/// An active-pointer update that has been published but not finalized.
///
/// The previous pointer remains on disk until the caller proves the new
/// credential to the server. A crash is recoverable: the next process reads the
/// new current pointer, retries activation, and then calls `commit`.
#[derive(Debug)]
pub struct PointerPublication {
    pointer: ActivePointer,
}

impl ActivePointer {
    /// Opens a pointer rooted in an existing real directory.
    ///
    /// # Errors
    ///
    /// Returns an error when the directory is missing, is not a directory, or
    /// is a symbolic link/reparse-point-like filesystem object.
    pub fn new(directory: impl Into<PathBuf>) -> Result<Self, ActivePointerError> {
        let directory = directory.into();
        let metadata = directory
            .symlink_metadata()
            .map_err(|source| io_error(&directory, source))?;
        if metadata.file_type().is_symlink() || !metadata.is_dir() {
            return Err(ActivePointerError::UnsafeDirectory(directory));
        }
        Ok(Self { directory })
    }

    /// Returns the active simple file name after completing any interrupted
    /// pointer rename sequence.
    ///
    /// # Errors
    ///
    /// Returns an error for unsafe pointer files, malformed contents, lock or
    /// filesystem failures, or when no generation has been published.
    pub fn read(&self) -> Result<String, ActivePointerError> {
        let lock = self.lock()?;
        self.recover_locked()?;
        let value = read_value(&self.current())?.ok_or(ActivePointerError::Missing)?;
        drop(lock);
        Ok(value)
    }

    /// Returns the previous active file name while an activation transaction is
    /// pending. The current pointer is still authoritative.
    ///
    /// # Errors
    ///
    /// Returns an error for unsafe pointer files, malformed contents, or lock
    /// and filesystem failures.
    pub fn previous(&self) -> Result<Option<String>, ActivePointerError> {
        let lock = self.lock()?;
        self.recover_locked()?;
        let value = read_value(&self.previous_path())?;
        drop(lock);
        Ok(value)
    }

    /// Publishes a new active file name while retaining the previous pointer for
    /// activation rollback.
    ///
    /// # Errors
    ///
    /// Returns an error when another publication is pending, the value is not a
    /// simple file name, or a safe/durable update cannot be completed.
    pub fn publish(&self, value: &str) -> Result<PointerPublication, ActivePointerError> {
        validate_value(value)?;
        let lock = self.lock()?;
        self.recover_locked()?;
        if path_exists(&self.previous_path())? || path_exists(&self.next())? {
            return Err(ActivePointerError::PendingPublication);
        }

        let next = self.next();
        write_new_pointer(&next, value)?;
        let current = self.current();
        let previous = self.previous_path();
        let had_current = path_exists(&current)?;
        if had_current {
            ensure_regular_file(&current)?;
            fs::rename(&current, &previous).map_err(|source| io_error(&current, source))?;
        }

        if let Err(source) = fs::rename(&next, &current) {
            let _ = remove_regular_if_exists(&next);
            if had_current && !path_exists(&current).unwrap_or(false) {
                let _ = fs::rename(&previous, &current);
            }
            return Err(io_error(&current, source));
        }
        if let Err(error) = sync_directory(&self.directory) {
            let _ = remove_regular_if_exists(&current);
            if had_current {
                let _ = fs::rename(&previous, &current);
            }
            let _ = sync_directory(&self.directory);
            return Err(error);
        }
        drop(lock);
        Ok(PointerPublication {
            pointer: self.clone(),
        })
    }

    /// Finalizes a publication recovered after a process restart.
    ///
    /// This is idempotent and removes only the validated sibling rollback file.
    ///
    /// # Errors
    ///
    /// Returns an error when pointer recovery or cleanup fails.
    pub fn commit_recovered(&self) -> Result<(), ActivePointerError> {
        let lock = self.lock()?;
        self.recover_locked()?;
        remove_regular_if_exists(&self.previous_path())?;
        remove_regular_if_exists(&self.next())?;
        sync_directory(&self.directory)?;
        drop(lock);
        Ok(())
    }

    /// Rolls back a publication recovered after a process restart when a
    /// previous pointer exists. Returns `false` without changing the current
    /// pointer when this was the first credential generation.
    ///
    /// # Errors
    ///
    /// Returns an error when pointer recovery or file operations fail.
    pub fn rollback_recovered_if_previous(&self) -> Result<bool, ActivePointerError> {
        let lock = self.lock()?;
        self.recover_locked()?;
        if !path_exists(&self.previous_path())? {
            drop(lock);
            return Ok(false);
        }
        let current = self.current();
        let previous = self.previous_path();
        remove_regular_if_exists(&current)?;
        ensure_regular_file(&previous)?;
        fs::rename(&previous, &current).map_err(|source| io_error(&current, source))?;
        remove_regular_if_exists(&self.next())?;
        sync_directory(&self.directory)?;
        drop(lock);
        Ok(true)
    }

    fn commit(&self) -> Result<(), ActivePointerError> {
        self.commit_recovered()
    }

    fn rollback(&self) -> Result<(), ActivePointerError> {
        let lock = self.lock()?;
        self.recover_locked()?;
        let current = self.current();
        let previous = self.previous_path();
        remove_regular_if_exists(&current)?;
        if path_exists(&previous)? {
            ensure_regular_file(&previous)?;
            fs::rename(&previous, &current).map_err(|source| io_error(&current, source))?;
        }
        remove_regular_if_exists(&self.next())?;
        sync_directory(&self.directory)?;
        drop(lock);
        Ok(())
    }

    fn recover_locked(&self) -> Result<(), ActivePointerError> {
        let current = self.current();
        let next = self.next();
        let previous = self.previous_path();
        let has_current = path_exists(&current)?;
        let has_next = path_exists(&next)?;
        let has_previous = path_exists(&previous)?;

        if has_current {
            ensure_regular_file(&current)?;
            // A crash before moving the old current pointer left only `next`.
            // The old generation is still authoritative, so discard the staged
            // value. When `previous` also exists, current is the new generation
            // and activation must be retried before cleanup.
            if has_next {
                remove_regular_if_exists(&next)?;
                sync_directory(&self.directory)?;
            }
            if has_previous {
                ensure_regular_file(&previous)?;
            }
            return Ok(());
        }

        if has_next {
            ensure_regular_file(&next)?;
            if has_previous {
                ensure_regular_file(&previous)?;
            }
            fs::rename(&next, &current).map_err(|source| io_error(&current, source))?;
            sync_directory(&self.directory)?;
            return Ok(());
        }

        if has_previous {
            ensure_regular_file(&previous)?;
            fs::rename(&previous, &current).map_err(|source| io_error(&current, source))?;
            sync_directory(&self.directory)?;
        }
        Ok(())
    }

    fn lock(&self) -> Result<File, ActivePointerError> {
        let path = self.directory.join(LOCK_FILE);
        if path_exists(&path)? {
            ensure_regular_file(&path)?;
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
            .map_err(|source| io_error(&path, source))?;
        let metadata = file.metadata().map_err(|source| io_error(&path, source))?;
        if !metadata.is_file() {
            return Err(ActivePointerError::UnsafeFile(path));
        }
        FileExt::lock_exclusive(&file).map_err(|source| io_error(&path, source))?;
        Ok(file)
    }

    /// Returns the fixed files managed by this pointer for platform ACL handoff.
    #[must_use]
    pub fn managed_paths(&self) -> [PathBuf; 4] {
        [
            self.current(),
            self.next(),
            self.previous_path(),
            self.directory.join(LOCK_FILE),
        ]
    }

    fn current(&self) -> PathBuf {
        self.directory.join(CURRENT_FILE)
    }

    fn next(&self) -> PathBuf {
        self.directory.join(NEXT_FILE)
    }

    fn previous_path(&self) -> PathBuf {
        self.directory.join(PREVIOUS_FILE)
    }
}

impl PointerPublication {
    /// Permanently accepts the new pointer and removes the rollback pointer.
    ///
    /// # Errors
    ///
    /// Returns an error when durable cleanup fails.
    pub fn commit(self) -> Result<(), ActivePointerError> {
        self.pointer.commit()
    }

    /// Restores the previous pointer, or removes the current pointer when the
    /// failed publication was the first generation.
    ///
    /// # Errors
    ///
    /// Returns an error when safe restoration fails.
    pub fn rollback(self) -> Result<(), ActivePointerError> {
        self.pointer.rollback()
    }
}

fn validate_value(value: &str) -> Result<(), ActivePointerError> {
    let path = Path::new(value);
    if value.is_empty()
        || value.len() > 255
        || value.contains('\0')
        || value.contains('/')
        || value.contains('\\')
        || path.is_absolute()
        || path.components().count() != 1
        || matches!(value, "." | "..")
    {
        return Err(ActivePointerError::InvalidValue);
    }
    Ok(())
}

fn read_value(path: &Path) -> Result<Option<String>, ActivePointerError> {
    if !path_exists(path)? {
        return Ok(None);
    }
    ensure_regular_file(path)?;
    let value = fs::read_to_string(path).map_err(|source| io_error(path, source))?;
    let value = value.trim();
    validate_value(value)?;
    Ok(Some(value.to_owned()))
}

fn write_new_pointer(path: &Path, value: &str) -> Result<(), ActivePointerError> {
    use std::io::Write as _;
    remove_regular_if_exists(path)?;
    let mut options = OpenOptions::new();
    options.write(true).create_new(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        options.mode(0o600);
    }
    let mut file = options
        .open(path)
        .map_err(|source| io_error(path, source))?;
    file.write_all(value.as_bytes())
        .and_then(|()| file.write_all(b"\n"))
        .and_then(|()| file.sync_all())
        .map_err(|source| io_error(path, source))
}

fn path_exists(path: &Path) -> Result<bool, ActivePointerError> {
    match path.symlink_metadata() {
        Ok(_) => Ok(true),
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => Ok(false),
        Err(source) => Err(io_error(path, source)),
    }
}

fn ensure_regular_file(path: &Path) -> Result<(), ActivePointerError> {
    let metadata = path
        .symlink_metadata()
        .map_err(|source| io_error(path, source))?;
    if metadata.file_type().is_symlink() || !metadata.is_file() {
        return Err(ActivePointerError::UnsafeFile(path.to_path_buf()));
    }
    Ok(())
}

fn remove_regular_if_exists(path: &Path) -> Result<(), ActivePointerError> {
    if !path_exists(path)? {
        return Ok(());
    }
    ensure_regular_file(path)?;
    fs::remove_file(path).map_err(|source| io_error(path, source))
}

#[cfg(unix)]
fn sync_directory(path: &Path) -> Result<(), ActivePointerError> {
    File::open(path)
        .and_then(|directory| directory.sync_all())
        .map_err(|source| io_error(path, source))
}

#[cfg(not(unix))]
#[allow(clippy::unnecessary_wraps)]
fn sync_directory(_path: &Path) -> Result<(), ActivePointerError> {
    Ok(())
}

fn io_error(path: &Path, source: std::io::Error) -> ActivePointerError {
    ActivePointerError::Io {
        path: path.to_path_buf(),
        source,
    }
}

#[cfg(test)]
#[allow(clippy::expect_used)]
mod tests {
    use super::*;

    fn fixture() -> PathBuf {
        let root = std::env::temp_dir().join(format!("centrald-pointer-{}", uuid::Uuid::now_v7()));
        fs::create_dir(&root).expect("create fixture");
        root
    }

    #[test]
    fn publication_can_commit_and_rollback_without_ordering() {
        let directory = fixture();
        let pointer = ActivePointer::new(&directory).expect("pointer");
        pointer
            .publish("generation-one.toml")
            .expect("publish")
            .commit()
            .expect("commit");
        assert_eq!(pointer.read().expect("read"), "generation-one.toml");

        let pending = pointer
            .publish("generation-two.toml")
            .expect("publish second");
        assert_eq!(pointer.read().expect("read new"), "generation-two.toml");
        assert_eq!(
            pointer.previous().expect("read previous").as_deref(),
            Some("generation-one.toml")
        );
        pending.rollback().expect("rollback");
        assert_eq!(
            pointer.read().expect("read restored"),
            "generation-one.toml"
        );
        fs::remove_dir_all(directory).expect("remove fixture");
    }
}
