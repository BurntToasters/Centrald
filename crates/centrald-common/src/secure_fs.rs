use std::fs::{self, OpenOptions};
use std::io::Write;
use std::path::{Path, PathBuf};

use thiserror::Error;
use uuid::Uuid;

#[derive(Debug, Error)]
pub enum SecureFileError {
    #[error("target path has no parent: {0}")]
    MissingParent(PathBuf),
    #[error("refusing to overwrite existing path: {0}")]
    Exists(PathBuf),
    #[error("refusing to write through a symbolic-link target: {0}")]
    Symlink(PathBuf),
    #[error("replacement target is not a regular file: {0}")]
    NotRegular(PathBuf),
    #[error("refusing path with a symbolic-link or reparse-point ancestor: {0}")]
    UnsafeAncestor(PathBuf),
    #[error("safe file replacement is supported only on Unix")]
    ReplacementUnsupported,
    #[error("filesystem operation failed for {path}: {source}")]
    Io {
        path: PathBuf,
        source: std::io::Error,
    },
}

/// Atomically replaces an existing regular file and preserves a private,
/// uniquely named sibling backup. This is intentionally Unix-only because
/// portable `rename` does not provide the same atomic replace contract.
///
/// # Errors
///
/// Returns an error if the target is missing, is a symbolic link, is not a
/// regular file, or a backup/write/sync/rename operation fails.
pub fn replace_file_with_backup(
    path: &Path,
    contents: &[u8],
    private: bool,
) -> Result<PathBuf, SecureFileError> {
    #[cfg(not(unix))]
    {
        let _ = (path, contents, private);
        Err(SecureFileError::ReplacementUnsupported)
    }

    #[cfg(unix)]
    {
        validate_no_symlink_ancestors(path)?;
        let metadata = path
            .symlink_metadata()
            .map_err(|source| io_error(path, source))?;
        if metadata.file_type().is_symlink() {
            return Err(SecureFileError::Symlink(path.to_path_buf()));
        }
        if !metadata.is_file() {
            return Err(SecureFileError::NotRegular(path.to_path_buf()));
        }

        let parent = path
            .parent()
            .filter(|parent| !parent.as_os_str().is_empty())
            .ok_or_else(|| SecureFileError::MissingParent(path.to_path_buf()))?;
        let filename = path
            .file_name()
            .ok_or_else(|| SecureFileError::MissingParent(path.to_path_buf()))?
            .to_string_lossy();
        let nonce = Uuid::now_v7();
        let backup = parent.join(format!("{filename}.centrald-backup-{nonce}"));
        let temporary = parent.join(format!(".{filename}.centrald-replacement-{nonce}"));

        let original = fs::read(path).map_err(|source| io_error(path, source))?;
        write_new_file(&backup, &original, true)?;
        write_new_file(&temporary, contents, private)?;
        if let Err(source) = fs::rename(&temporary, path) {
            let _ = fs::remove_file(&temporary);
            return Err(io_error(path, source));
        }
        fs::File::open(parent)
            .and_then(|directory| directory.sync_all())
            .map_err(|source| io_error(parent, source))?;
        Ok(backup)
    }
}

/// Atomically replaces an existing regular file without creating a backup.
///
/// This is intended for callers that already maintain a crash-recovery
/// transaction containing the original bytes. It is Unix-only for the same
/// reason as [`replace_file_with_backup`].
///
/// # Errors
///
/// Returns an error if the target is missing, unsafe, not a regular file, or
/// the write, rename, or directory synchronization fails.
pub fn replace_file_atomically(
    path: &Path,
    contents: &[u8],
    private: bool,
) -> Result<(), SecureFileError> {
    #[cfg(not(unix))]
    {
        let _ = (path, contents, private);
        Err(SecureFileError::ReplacementUnsupported)
    }

    #[cfg(unix)]
    {
        validate_no_symlink_ancestors(path)?;
        let metadata = path
            .symlink_metadata()
            .map_err(|source| io_error(path, source))?;
        if metadata.file_type().is_symlink() {
            return Err(SecureFileError::Symlink(path.to_path_buf()));
        }
        if !metadata.is_file() {
            return Err(SecureFileError::NotRegular(path.to_path_buf()));
        }

        let parent = path
            .parent()
            .filter(|parent| !parent.as_os_str().is_empty())
            .ok_or_else(|| SecureFileError::MissingParent(path.to_path_buf()))?;
        let filename = path
            .file_name()
            .ok_or_else(|| SecureFileError::MissingParent(path.to_path_buf()))?
            .to_string_lossy();
        let temporary = parent.join(format!(
            ".{filename}.centrald-replacement-{}",
            Uuid::now_v7()
        ));

        write_new_file(&temporary, contents, private)?;
        if let Err(source) = fs::rename(&temporary, path) {
            let _ = fs::remove_file(&temporary);
            return Err(io_error(path, source));
        }
        fs::File::open(parent)
            .and_then(|directory| directory.sync_all())
            .map_err(|source| io_error(parent, source))?;
        Ok(())
    }
}

/// Removes the oldest CentralD sibling backups while retaining the newest
/// `retain` files.
///
/// Backup names contain UUIDv7 values, so lexical filename ordering is also
/// chronological ordering for backups produced by this module.
///
/// # Errors
///
/// Returns an error for unsafe matching entries or failed directory reads,
/// removals, and synchronization.
pub fn prune_file_backups(path: &Path, retain: usize) -> Result<usize, SecureFileError> {
    #[cfg(not(unix))]
    {
        let _ = (path, retain);
        Err(SecureFileError::ReplacementUnsupported)
    }

    #[cfg(unix)]
    {
        validate_no_symlink_ancestors(path)?;
        let parent = path
            .parent()
            .filter(|parent| !parent.as_os_str().is_empty())
            .ok_or_else(|| SecureFileError::MissingParent(path.to_path_buf()))?;
        let filename = path
            .file_name()
            .and_then(|value| value.to_str())
            .ok_or_else(|| SecureFileError::MissingParent(path.to_path_buf()))?;
        let prefix = format!("{filename}.centrald-backup-");
        let mut backups = Vec::new();

        for entry in fs::read_dir(parent).map_err(|source| io_error(parent, source))? {
            let entry = entry.map_err(|source| io_error(parent, source))?;
            let Some(name) = entry.file_name().to_str().map(ToOwned::to_owned) else {
                continue;
            };
            let Some(suffix) = name.strip_prefix(&prefix) else {
                continue;
            };
            if Uuid::parse_str(suffix).is_err() {
                continue;
            }
            let backup = entry.path();
            let metadata = backup
                .symlink_metadata()
                .map_err(|source| io_error(&backup, source))?;
            if metadata.file_type().is_symlink() {
                return Err(SecureFileError::Symlink(backup));
            }
            if !metadata.is_file() {
                return Err(SecureFileError::NotRegular(backup));
            }
            backups.push(backup);
        }

        backups.sort_by(|left, right| left.file_name().cmp(&right.file_name()));
        let remove_count = backups.len().saturating_sub(retain);
        for backup in backups.into_iter().take(remove_count) {
            fs::remove_file(&backup).map_err(|source| io_error(&backup, source))?;
        }
        if remove_count > 0 {
            fs::File::open(parent)
                .and_then(|directory| directory.sync_all())
                .map_err(|source| io_error(parent, source))?;
        }
        Ok(remove_count)
    }
}

/// Atomically creates a new file without replacing any existing target.
///
/// Private files are mode `0600` and public files are mode `0644` on Unix.
/// A uniquely named sibling is fully written and synced before the final
/// no-overwrite rename.
///
/// # Errors
///
/// Returns an error if the target exists, is a symbolic link, has no parent,
/// or any directory, write, permission, sync, or rename operation fails.
pub fn write_new_file(path: &Path, contents: &[u8], private: bool) -> Result<(), SecureFileError> {
    #[cfg(not(unix))]
    let _ = private;
    validate_no_symlink_ancestors(path)?;
    if path
        .symlink_metadata()
        .is_ok_and(|metadata| metadata.file_type().is_symlink())
    {
        return Err(SecureFileError::Symlink(path.to_path_buf()));
    }
    if path.exists() {
        return Err(SecureFileError::Exists(path.to_path_buf()));
    }

    let parent = path
        .parent()
        .filter(|parent| !parent.as_os_str().is_empty())
        .ok_or_else(|| SecureFileError::MissingParent(path.to_path_buf()))?;
    fs::create_dir_all(parent).map_err(|source| io_error(parent, source))?;
    let filename = path
        .file_name()
        .ok_or_else(|| SecureFileError::MissingParent(path.to_path_buf()))?
        .to_string_lossy();
    let temporary = parent.join(format!(".{filename}.centrald-tmp-{}", Uuid::now_v7()));

    let mut options = OpenOptions::new();
    options.write(true).create_new(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        options.mode(if private { 0o600 } else { 0o644 });
    }
    let mut file = options
        .open(&temporary)
        .map_err(|source| io_error(&temporary, source))?;
    file.write_all(contents)
        .map_err(|source| io_error(&temporary, source))?;
    file.sync_all()
        .map_err(|source| io_error(&temporary, source))?;
    drop(file);

    // Linking the completed sibling into place gives create-new semantics at
    // the final pathname. A plain rename would replace a target created during
    // the write window on Unix, violating this function's security contract.
    if let Err(source) = fs::hard_link(&temporary, path) {
        let _ = fs::remove_file(&temporary);
        return if source.kind() == std::io::ErrorKind::AlreadyExists {
            Err(SecureFileError::Exists(path.to_path_buf()))
        } else {
            Err(io_error(path, source))
        };
    }
    if let Err(source) = fs::remove_file(&temporary) {
        let _ = fs::remove_file(path);
        return Err(io_error(&temporary, source));
    }
    #[cfg(unix)]
    fs::File::open(parent)
        .and_then(|directory| directory.sync_all())
        .map_err(|source| io_error(parent, source))?;
    Ok(())
}

/// Rejects any existing parent component that is a symbolic link or, on
/// Windows, any reparse point. Missing parents are permitted so the caller may
/// create them only after the nearest existing ancestor has been validated.
pub fn validate_no_symlink_ancestors(path: &Path) -> Result<(), SecureFileError> {
    let mut current = path.parent();
    while let Some(ancestor) = current {
        if ancestor.as_os_str().is_empty() {
            break;
        }
        match fs::symlink_metadata(ancestor) {
            Ok(metadata) => {
                if metadata.file_type().is_symlink() || metadata_is_reparse_point(&metadata) {
                    return Err(SecureFileError::UnsafeAncestor(ancestor.to_path_buf()));
                }
                if !metadata.is_dir() {
                    return Err(SecureFileError::NotRegular(ancestor.to_path_buf()));
                }
            }
            Err(source) if source.kind() == std::io::ErrorKind::NotFound => {}
            Err(source) => return Err(io_error(ancestor, source)),
        }
        current = ancestor.parent();
    }
    Ok(())
}

#[cfg(windows)]
fn metadata_is_reparse_point(metadata: &fs::Metadata) -> bool {
    use std::os::windows::fs::MetadataExt;
    const FILE_ATTRIBUTE_REPARSE_POINT: u32 = 0x400;
    metadata.file_attributes() & FILE_ATTRIBUTE_REPARSE_POINT != 0
}

#[cfg(not(windows))]
const fn metadata_is_reparse_point(_metadata: &fs::Metadata) -> bool {
    false
}

fn io_error(path: &Path, source: std::io::Error) -> SecureFileError {
    SecureFileError::Io {
        path: path.to_path_buf(),
        source,
    }
}

#[cfg(test)]
#[allow(clippy::expect_used)]
mod tests {
    use std::fs;

    use super::*;

    #[test]
    fn refuses_to_replace_existing_file() {
        let root = std::env::temp_dir().join(format!("centrald-secure-fs-{}", Uuid::now_v7()));
        fs::create_dir(&root).expect("test directory should be creatable");
        let path = root.join("secret");
        write_new_file(&path, b"first", true).expect("initial write should succeed");
        assert!(matches!(
            write_new_file(&path, b"replacement", true),
            Err(SecureFileError::Exists(_))
        ));
        assert_eq!(
            fs::read(&path).expect("test file should be readable"),
            b"first"
        );
        fs::remove_file(path).expect("test file cleanup should succeed");
        fs::remove_dir(root).expect("test directory cleanup should succeed");
    }

    #[cfg(unix)]
    #[test]
    fn replacement_preserves_backup_and_rejects_symlink() {
        use std::os::unix::fs::symlink;

        let root = std::env::temp_dir().join(format!("centrald-replace-{}", Uuid::now_v7()));
        fs::create_dir(&root).expect("test directory should be creatable");
        let path = root.join("server.toml");
        write_new_file(&path, b"old", true).expect("initial file should be creatable");
        let backup = replace_file_with_backup(&path, b"new", true)
            .expect("regular file replacement should succeed");
        assert_eq!(
            fs::read(&path).expect("replacement should be readable"),
            b"new"
        );
        assert_eq!(
            fs::read(&backup).expect("backup should be readable"),
            b"old"
        );

        let symlink_path = root.join("linked.toml");
        symlink(&path, &symlink_path).expect("test symlink should be creatable");
        assert!(matches!(
            replace_file_with_backup(&symlink_path, b"bad", true),
            Err(SecureFileError::Symlink(_))
        ));

        fs::remove_file(symlink_path).expect("test symlink cleanup should succeed");
        fs::remove_file(backup).expect("test backup cleanup should succeed");
        fs::remove_file(path).expect("test file cleanup should succeed");
        fs::remove_dir(root).expect("test directory cleanup should succeed");
    }

    #[cfg(unix)]
    #[test]
    fn atomic_replacement_does_not_create_a_backup() {
        let root = std::env::temp_dir().join(format!("centrald-atomic-{}", Uuid::now_v7()));
        fs::create_dir(&root).expect("root should be creatable");
        let path = root.join("server.toml");
        write_new_file(&path, b"old", true).expect("initial file should be creatable");
        replace_file_atomically(&path, b"new", true).expect("replacement should succeed");
        assert_eq!(fs::read(&path).expect("replacement should be readable"), b"new");
        assert_eq!(
            fs::read_dir(&root)
                .expect("root should be readable")
                .filter_map(Result::ok)
                .filter(|entry| entry.file_name().to_string_lossy().contains("centrald-backup"))
                .count(),
            0
        );
        fs::remove_file(path).expect("file cleanup");
        fs::remove_dir(root).expect("root cleanup");
    }

    #[cfg(unix)]
    #[test]
    fn backup_pruning_keeps_only_the_newest_entries() {
        let root = std::env::temp_dir().join(format!("centrald-prune-{}", Uuid::now_v7()));
        fs::create_dir(&root).expect("root should be creatable");
        let path = root.join("server.toml");
        write_new_file(&path, b"zero", true).expect("initial file should be creatable");
        for value in [b"one".as_slice(), b"two".as_slice(), b"three".as_slice()] {
            replace_file_with_backup(&path, value, true).expect("replacement should succeed");
        }
        assert_eq!(prune_file_backups(&path, 2).expect("pruning should succeed"), 1);
        let remaining = fs::read_dir(&root)
            .expect("root should be readable")
            .filter_map(Result::ok)
            .filter(|entry| entry.file_name().to_string_lossy().contains("centrald-backup"))
            .count();
        assert_eq!(remaining, 2);
        fs::remove_dir_all(root).expect("root cleanup");
    }

    #[cfg(unix)]
    #[test]
    fn rejects_symlinked_parent_directory() {
        use std::os::unix::fs::symlink;
        let root = std::env::temp_dir().join(format!("centrald-parent-{}", Uuid::now_v7()));
        let outside = std::env::temp_dir().join(format!("centrald-outside-{}", Uuid::now_v7()));
        fs::create_dir(&root).expect("root should be creatable");
        fs::create_dir(&outside).expect("outside should be creatable");
        symlink(&outside, root.join("linked")).expect("symlink should be creatable");
        assert!(matches!(
            write_new_file(&root.join("linked/secret"), b"nope", true),
            Err(SecureFileError::UnsafeAncestor(_))
        ));
        assert!(!outside.join("secret").exists());
        fs::remove_file(root.join("linked")).expect("symlink cleanup");
        fs::remove_dir(root).expect("root cleanup");
        fs::remove_dir(outside).expect("outside cleanup");
    }

    #[cfg(not(unix))]
    #[test]
    fn replacement_is_disabled_without_atomic_unix_rename() {
        assert!(matches!(
            replace_file_with_backup(Path::new("unused"), b"new", true),
            Err(SecureFileError::ReplacementUnsupported)
        ));
        assert!(matches!(
            replace_file_atomically(Path::new("unused"), b"new", true),
            Err(SecureFileError::ReplacementUnsupported)
        ));
    }
}
