use std::fs::{self, File, OpenOptions};
use std::path::{Path, PathBuf};

use anyhow::{Context, Result, bail};
use centrald_common::secure_fs::{replace_file_atomically, write_new_file};
use fs2::FileExt;
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};

const SETTINGS_JOURNAL_NAME: &str = ".centrald-settings-update.json";
const SETTINGS_ORIGINAL_NAME: &str = ".centrald-settings-update.original";
const SETTINGS_PUBLISHED_NAME: &str = ".centrald-settings-update.published";
const DATABASE_JOURNAL_NAME: &str = ".centrald-database-update.json";
const DATABASE_ENV_STAGE_NAME: &str = ".centrald-database-update.env.next";
const DATABASE_CONFIG_STAGE_NAME: &str = ".centrald-database-update.config.next";

/// Held exclusive lock shared by the local configuration TUI and remote Admin
/// settings RPCs. The file descriptor owns the advisory lock until drop.
#[derive(Debug)]
pub struct ConfigFileLock {
    file: File,
    path: PathBuf,
}

impl ConfigFileLock {
    /// Acquires the cross-process configuration writer lock.
    ///
    /// Local TUI callers may block until the lock is free. Async RPC handlers
    /// must use [`Self::try_acquire`] from `spawn_blocking` so a held lock
    /// cannot park Tokio worker threads indefinitely.
    ///
    /// # Errors
    ///
    /// Returns an error when the lock file cannot be opened or the exclusive
    /// lock cannot be acquired.
    pub fn acquire(config_path: &Path) -> Result<Self> {
        let (file, path) = open_lock_file(config_path)?;
        FileExt::lock_exclusive(&file)
            .with_context(|| format!("lock configuration writer {}", path.display()))?;
        Ok(Self { file, path })
    }

    /// Attempts a non-blocking exclusive configuration lock.
    ///
    /// Returns `Ok(None)` when another writer already holds the lock.
    ///
    /// # Errors
    ///
    /// Returns an error when the lock file cannot be opened or the lock
    /// attempt fails for a reason other than the lock being held.
    pub fn try_acquire(config_path: &Path) -> Result<Option<Self>> {
        let (file, path) = open_lock_file(config_path)?;
        match FileExt::try_lock_exclusive(&file) {
            Ok(()) => Ok(Some(Self { file, path })),
            Err(error) if error.kind() == std::io::ErrorKind::WouldBlock => Ok(None),
            Err(error) => {
                Err(error).with_context(|| format!("lock configuration writer {}", path.display()))
            }
        }
    }

    #[must_use]
    pub fn path(&self) -> &Path {
        &self.path
    }
}

impl Drop for ConfigFileLock {
    fn drop(&mut self) {
        let _ = FileExt::unlock(&self.file);
    }
}

fn open_lock_file(config_path: &Path) -> Result<(File, PathBuf)> {
    let path = lock_path(config_path)?;
    if let Ok(metadata) = path.symlink_metadata()
        && (metadata.file_type().is_symlink() || !metadata.is_file())
    {
        bail!("refusing unsafe configuration lock path {}", path.display());
    }
    let mut options = OpenOptions::new();
    options.read(true).write(true).create(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        options.mode(0o600);
        const O_NOFOLLOW: i32 = 0o400000;
        const O_CLOEXEC: i32 = 0o2000000;
        options.custom_flags(O_NOFOLLOW | O_CLOEXEC);
    }
    let file = options
        .open(&path)
        .with_context(|| format!("open configuration lock {}", path.display()))?;
    let metadata = file
        .metadata()
        .with_context(|| format!("inspect configuration lock {}", path.display()))?;
    if !metadata.is_file() {
        bail!(
            "configuration lock is not a regular file: {}",
            path.display()
        );
    }
    Ok((file, path))
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct DatabaseUpdateJournal {
    version: u32,
    config_path: PathBuf,
    environment_path: PathBuf,
    intended_revision: String,
}

/// Crash-recoverable two-file publication for the `PostgreSQL` environment file
/// and the non-secret server configuration that refers to it.
#[derive(Debug)]
pub struct DatabaseUpdateTransaction {
    config_path: PathBuf,
    environment_path: PathBuf,
    journal_path: PathBuf,
    environment_stage: PathBuf,
    config_stage: PathBuf,
}

impl DatabaseUpdateTransaction {
    /// Stages both files while the caller holds [`ConfigFileLock`]. The secret
    /// environment bytes are never copied to a backup file.
    ///
    /// # Errors
    ///
    /// Returns an error when an interrupted update cannot be recovered, an
    /// unfinished artifact already exists, or a stage or journal file cannot
    /// be written.
    pub fn begin_locked(
        config_path: &Path,
        environment_path: &Path,
        environment_contents: &[u8],
        config_contents: &[u8],
    ) -> Result<Self> {
        recover_interrupted_database_update_locked(config_path)?;
        let paths = database_paths(config_path)?;
        for path in [
            &paths.journal,
            &paths.environment_stage,
            &paths.config_stage,
        ] {
            reject_unsafe_existing(path)?;
            if path.exists() {
                bail!(
                    "unfinished database update artifact exists: {}",
                    path.display()
                );
            }
        }
        reject_unsafe_existing(environment_path)?;
        if !environment_path.exists() {
            bail!(
                "database environment file is missing: {}",
                environment_path.display()
            );
        }
        write_new_file(&paths.environment_stage, environment_contents, true)?;
        if let Err(error) = write_new_file(&paths.config_stage, config_contents, true) {
            let _ = fs::remove_file(&paths.environment_stage);
            return Err(error.into());
        }
        let journal = DatabaseUpdateJournal {
            version: 1,
            config_path: config_path.to_path_buf(),
            environment_path: environment_path.to_path_buf(),
            intended_revision: revision(config_contents),
        };
        if let Err(error) =
            write_new_file(&paths.journal, &serde_json::to_vec_pretty(&journal)?, true)
        {
            let _ = fs::remove_file(&paths.environment_stage);
            let _ = fs::remove_file(&paths.config_stage);
            return Err(error.into());
        }
        sync_parent(config_path)?;
        Ok(Self {
            config_path: config_path.to_path_buf(),
            environment_path: environment_path.to_path_buf(),
            journal_path: paths.journal,
            environment_stage: paths.environment_stage,
            config_stage: paths.config_stage,
        })
    }

    /// Publishes the environment file first and the matching configuration
    /// second. Any interruption is completed by startup recovery.
    ///
    /// # Errors
    ///
    /// Returns an error when a staged file cannot be published or a journal
    /// file cannot be removed.
    pub fn commit(self) -> Result<()> {
        publish_database_stage(&self.environment_stage, &self.environment_path)?;
        sync_parent(&self.environment_path)?;
        publish_database_stage(&self.config_stage, &self.config_path)?;
        sync_parent(&self.config_path)?;
        fs::remove_file(&self.journal_path).with_context(|| {
            format!(
                "remove database update journal {}",
                self.journal_path.display()
            )
        })?;
        sync_parent(&self.config_path)
    }
}

/// Completes an interrupted database/config publication before configuration
/// is loaded by the daemon or local TUI.
///
/// # Errors
///
/// Returns an error when an interrupted publication cannot be recovered.
pub fn recover_interrupted_database_update(config_path: &Path) -> Result<()> {
    let paths = database_paths(config_path)?;
    if !paths.journal.exists() && !paths.environment_stage.exists() && !paths.config_stage.exists()
    {
        return Ok(());
    }
    let _lock = ConfigFileLock::acquire(config_path)?;
    recover_interrupted_database_update_locked(config_path)
}

/// Completes an interrupted database/config publication while the caller holds
/// [`ConfigFileLock`].
///
/// # Errors
///
/// Returns an error when an interrupted publication cannot be recovered or
/// the journal does not belong to this configuration.
pub fn recover_interrupted_database_update_locked(config_path: &Path) -> Result<()> {
    let paths = database_paths(config_path)?;
    for path in [
        &paths.journal,
        &paths.environment_stage,
        &paths.config_stage,
    ] {
        reject_unsafe_existing(path)?;
    }
    if !paths.journal.exists() {
        for orphan in [&paths.environment_stage, &paths.config_stage] {
            if orphan.exists() {
                fs::remove_file(orphan).with_context(|| {
                    format!("remove orphan database stage {}", orphan.display())
                })?;
            }
        }
        sync_parent(config_path)?;
        return Ok(());
    }
    let journal: DatabaseUpdateJournal =
        serde_json::from_slice(&fs::read(&paths.journal).with_context(|| {
            format!("read database update journal {}", paths.journal.display())
        })?)
        .context("parse database update journal")?;
    if journal.version != 1 || journal.config_path != config_path {
        bail!("database update journal does not belong to this server configuration");
    }
    validate_revision(&journal.intended_revision)?;
    reject_unsafe_existing(&journal.environment_path)?;

    if paths.environment_stage.exists() {
        publish_database_stage(&paths.environment_stage, &journal.environment_path)?;
        sync_parent(&journal.environment_path)?;
    } else if !journal.environment_path.exists() {
        bail!("database update lost both its staged and published environment file");
    }

    if paths.config_stage.exists() {
        publish_database_stage(&paths.config_stage, config_path)?;
        sync_parent(config_path)?;
    } else {
        let current = fs::read(config_path)
            .with_context(|| format!("read recovered configuration {}", config_path.display()))?;
        if revision(&current) != journal.intended_revision {
            bail!("database update lost its staged configuration before publication completed");
        }
    }

    fs::remove_file(&paths.journal)
        .with_context(|| format!("remove database update journal {}", paths.journal.display()))?;
    sync_parent(config_path)
}

#[cfg(unix)]
fn publish_database_stage(stage: &Path, destination: &Path) -> Result<()> {
    reject_unsafe_existing(stage)?;
    reject_unsafe_existing(destination)?;
    fs::rename(stage, destination).with_context(|| {
        format!(
            "publish database update {} from {}",
            destination.display(),
            stage.display()
        )
    })
}

#[cfg(not(unix))]
fn publish_database_stage(_stage: &Path, _destination: &Path) -> Result<()> {
    bail!("server database settings publication is supported only on Ubuntu Server")
}

#[derive(Debug)]
struct DatabasePaths {
    journal: PathBuf,
    environment_stage: PathBuf,
    config_stage: PathBuf,
}

fn database_paths(config_path: &Path) -> Result<DatabasePaths> {
    let parent = config_path
        .parent()
        .filter(|parent| !parent.as_os_str().is_empty())
        .context("server configuration path has no parent")?;
    Ok(DatabasePaths {
        journal: parent.join(DATABASE_JOURNAL_NAME),
        environment_stage: parent.join(DATABASE_ENV_STAGE_NAME),
        config_stage: parent.join(DATABASE_CONFIG_STAGE_NAME),
    })
}

/// Crash-recovery record for a remotely audited settings update.
///
/// The original bytes are stored in a separate private sibling. The published
/// marker is created only after the replacement configuration has reached its
/// final pathname. A durable `server_settings.update.prepare` audit entry is
/// committed before this transaction begins, so a published change always has
/// at least one database audit record even if the process stops before the
/// final success entry is appended.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct SettingsUpdateJournal {
    version: u32,
    config_path: PathBuf,
    intended_revision: String,
}

#[derive(Debug)]
#[allow(clippy::struct_field_names)]
pub struct SettingsUpdateTransaction {
    config_path: PathBuf,
    journal_path: PathBuf,
    original_path: PathBuf,
    published_path: PathBuf,
}

impl SettingsUpdateTransaction {
    /// Starts a crash-recoverable settings update while the caller holds the
    /// shared [`ConfigFileLock`]. No configuration bytes are changed here.
    ///
    /// # Errors
    ///
    /// Returns an error when an interrupted transaction cannot be recovered,
    /// an unfinished artifact already exists, or a recovery file cannot be
    /// written.
    pub fn begin_locked(
        config_path: &Path,
        original: &[u8],
        intended_revision: &str,
    ) -> Result<Self> {
        recover_interrupted_settings_update_locked(config_path)?;
        validate_revision(intended_revision)?;
        let paths = settings_paths(config_path)?;
        for path in [&paths.journal, &paths.original, &paths.published] {
            reject_unsafe_existing(path)?;
            if path.exists() {
                bail!(
                    "unfinished settings update artifact exists: {}",
                    path.display()
                );
            }
        }
        write_new_file(&paths.original, original, true).with_context(|| {
            format!("write settings recovery copy {}", paths.original.display())
        })?;
        let journal = SettingsUpdateJournal {
            version: 1,
            config_path: config_path.to_path_buf(),
            intended_revision: intended_revision.to_owned(),
        };
        if let Err(error) =
            write_new_file(&paths.journal, &serde_json::to_vec_pretty(&journal)?, true)
        {
            let _ = fs::remove_file(&paths.original);
            return Err(error).with_context(|| {
                format!("write settings update journal {}", paths.journal.display())
            });
        }
        sync_parent(config_path)?;
        Ok(Self {
            config_path: config_path.to_path_buf(),
            journal_path: paths.journal,
            original_path: paths.original,
            published_path: paths.published,
        })
    }

    /// Marks that the intended configuration bytes reached the final pathname.
    ///
    /// # Errors
    ///
    /// Returns an error when the current configuration does not match the
    /// journal revision or the publication marker cannot be written.
    pub fn mark_published(&self) -> Result<()> {
        let current = fs::read(&self.config_path)
            .with_context(|| format!("read published settings {}", self.config_path.display()))?;
        let revision = revision(&current);
        let journal = read_journal(&self.journal_path)?;
        if revision != journal.intended_revision {
            bail!("published settings revision does not match the update journal");
        }
        write_new_file(&self.published_path, revision.as_bytes(), true).with_context(|| {
            format!(
                "write settings publication marker {}",
                self.published_path.display()
            )
        })?;
        sync_parent(&self.config_path)
    }

    /// Removes the recovery transaction after the final audit append succeeds.
    ///
    /// # Errors
    ///
    /// Returns an error when a recovery artifact cannot be removed.
    pub fn complete(self) -> Result<()> {
        // Removing the journal is the durable transition into
        // "committed cleanup". Recovery treats a remaining publication
        // marker without a journal as a committed transaction and only
        // retires its recovery artifacts; it never restores the old bytes.
        remove_if_exists(&self.journal_path)?;
        sync_parent(&self.config_path)?;
        remove_if_exists(&self.original_path)?;
        remove_if_exists(&self.published_path)?;
        sync_parent(&self.config_path)
    }

    /// Restores the original configuration and removes the transaction files.
    ///
    /// # Errors
    ///
    /// Returns an error when the original configuration cannot be restored or
    /// the transaction files cannot be removed.
    pub fn rollback(self) -> Result<()> {
        rollback_settings_update_locked(&self.config_path)
    }
}

/// Recovers a settings transaction before any process reads the configuration.
///
/// # Errors
///
/// Returns an error when an interrupted settings transaction cannot be
/// recovered.
pub fn recover_interrupted_settings_update(config_path: &Path) -> Result<()> {
    let paths = settings_paths(config_path)?;
    if !paths.journal.exists() && !paths.original.exists() && !paths.published.exists() {
        return Ok(());
    }
    let _lock = ConfigFileLock::acquire(config_path)?;
    recover_interrupted_settings_update_locked(config_path)
}

/// Recovers a settings transaction while the caller holds [`ConfigFileLock`].
///
/// # Errors
///
/// Returns an error when an interrupted settings transaction cannot be
/// recovered or the journal does not belong to this configuration.
pub fn recover_interrupted_settings_update_locked(config_path: &Path) -> Result<()> {
    let paths = settings_paths(config_path)?;
    for path in [&paths.journal, &paths.original, &paths.published] {
        reject_unsafe_existing(path)?;
    }

    if !paths.journal.exists() {
        if paths.published.exists() {
            let marker = fs::read_to_string(&paths.published).with_context(|| {
                format!(
                    "read committed settings publication marker {}",
                    paths.published.display()
                )
            })?;
            validate_revision(&marker)?;
            let current = fs::read(config_path)
                .with_context(|| format!("read current settings {}", config_path.display()))?;
            if revision(&current) != marker {
                bail!("committed settings cleanup marker does not match the current configuration");
            }
            remove_if_exists(&paths.original)?;
            remove_if_exists(&paths.published)?;
            sync_parent(config_path)?;
            return Ok(());
        }
        // The original copy is written before the journal and before any
        // configuration mutation. A crash in that small window is safe to
        // clean up here.
        if paths.original.exists() {
            fs::remove_file(&paths.original).with_context(|| {
                format!(
                    "remove orphan settings recovery copy {}",
                    paths.original.display()
                )
            })?;
            sync_parent(config_path)?;
        }
        return Ok(());
    }

    let journal = read_journal(&paths.journal)?;
    if journal.version != 1 || journal.config_path != config_path {
        bail!("settings update journal does not belong to this server configuration");
    }
    validate_revision(&journal.intended_revision)?;
    if !paths.original.exists() {
        bail!("settings update journal is missing its original configuration copy");
    }

    let published = if paths.published.exists() {
        let marker = fs::read_to_string(&paths.published).with_context(|| {
            format!(
                "read settings publication marker {}",
                paths.published.display()
            )
        })?;
        let current = fs::read(config_path)
            .with_context(|| format!("read current settings {}", config_path.display()))?;
        marker == journal.intended_revision && revision(&current) == journal.intended_revision
    } else {
        false
    };

    if !published {
        restore_original(config_path, &paths.original)?;
    }
    cleanup_transaction_files(&paths.journal, &paths.original, &paths.published)?;
    sync_parent(config_path)
}

fn rollback_settings_update_locked(config_path: &Path) -> Result<()> {
    let paths = settings_paths(config_path)?;
    if !paths.journal.exists() {
        bail!("settings update rollback journal is missing");
    }
    restore_original(config_path, &paths.original)?;
    cleanup_transaction_files(&paths.journal, &paths.original, &paths.published)?;
    sync_parent(config_path)
}

fn restore_original(config_path: &Path, original_path: &Path) -> Result<()> {
    reject_unsafe_existing(original_path)?;
    let original = fs::read(original_path)
        .with_context(|| format!("read settings recovery copy {}", original_path.display()))?;
    replace_file_atomically(config_path, &original, true)
        .with_context(|| format!("restore server settings {}", config_path.display()))?;
    Ok(())
}

fn read_journal(path: &Path) -> Result<SettingsUpdateJournal> {
    reject_unsafe_existing(path)?;
    serde_json::from_slice(
        &fs::read(path)
            .with_context(|| format!("read settings update journal {}", path.display()))?,
    )
    .context("parse settings update recovery journal")
}

fn cleanup_transaction_files(journal: &Path, original: &Path, published: &Path) -> Result<()> {
    for path in [published, journal, original] {
        remove_if_exists(path)?;
    }
    Ok(())
}

fn remove_if_exists(path: &Path) -> Result<()> {
    match fs::remove_file(path) {
        Ok(()) => Ok(()),
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => Ok(()),
        Err(error) => Err(error).with_context(|| format!("remove {}", path.display())),
    }
}

fn reject_unsafe_existing(path: &Path) -> Result<()> {
    match path.symlink_metadata() {
        Ok(metadata) if metadata.file_type().is_symlink() || !metadata.is_file() => {
            bail!(
                "refusing unsafe settings update artifact {}",
                path.display()
            )
        }
        Ok(_) => Ok(()),
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => Ok(()),
        Err(error) => Err(error).with_context(|| format!("inspect {}", path.display())),
    }
}

#[derive(Debug)]
struct SettingsPaths {
    journal: PathBuf,
    original: PathBuf,
    published: PathBuf,
}

fn settings_paths(config_path: &Path) -> Result<SettingsPaths> {
    let parent = config_path
        .parent()
        .filter(|parent| !parent.as_os_str().is_empty())
        .context("server configuration path has no parent")?;
    Ok(SettingsPaths {
        journal: parent.join(SETTINGS_JOURNAL_NAME),
        original: parent.join(SETTINGS_ORIGINAL_NAME),
        published: parent.join(SETTINGS_PUBLISHED_NAME),
    })
}

fn lock_path(config_path: &Path) -> Result<PathBuf> {
    let parent = config_path
        .parent()
        .filter(|parent| !parent.as_os_str().is_empty())
        .context("server configuration path has no parent")?;
    Ok(parent.join(".centrald-config.lock"))
}

fn revision(bytes: &[u8]) -> String {
    hex::encode(Sha256::digest(bytes))
}

fn validate_revision(value: &str) -> Result<()> {
    if value.len() != 64 || !value.bytes().all(|byte| byte.is_ascii_hexdigit()) {
        bail!("settings update revision is not a SHA-256 digest");
    }
    Ok(())
}

#[allow(clippy::unnecessary_wraps)]
fn sync_parent(path: &Path) -> Result<()> {
    #[cfg(unix)]
    {
        let parent = path
            .parent()
            .filter(|parent| !parent.as_os_str().is_empty())
            .context("settings path has no parent")?;
        File::open(parent)
            .and_then(|directory| directory.sync_all())
            .with_context(|| format!("sync settings directory {}", parent.display()))?;
    }
    #[cfg(not(unix))]
    let _ = path;
    Ok(())
}

#[cfg(test)]
#[allow(clippy::expect_used)]
mod tests {
    #[cfg(unix)]
    #[test]
    fn unmarked_transaction_restores_original() {
        let root = std::env::temp_dir().join(format!("centrald-settings-{}", uuid::Uuid::now_v7()));
        fs::create_dir(&root).expect("test directory");
        let config = root.join("server.toml");
        write_new_file(&config, b"old", true).expect("initial config");
        let transaction =
            SettingsUpdateTransaction::begin_locked(&config, b"old", &revision(b"new"))
                .expect("transaction");
        replace_file_atomically(&config, b"new", true).expect("publish replacement");
        drop(transaction);
        recover_interrupted_settings_update_locked(&config).expect("recovery");
        assert_eq!(fs::read(&config).expect("read config"), b"old");
        fs::remove_dir_all(root).expect("cleanup");
    }

    #[cfg(unix)]
    #[test]
    fn published_transaction_keeps_replacement() {
        let root = std::env::temp_dir().join(format!("centrald-settings-{}", uuid::Uuid::now_v7()));
        fs::create_dir(&root).expect("test directory");
        let config = root.join("server.toml");
        write_new_file(&config, b"old", true).expect("initial config");
        let transaction =
            SettingsUpdateTransaction::begin_locked(&config, b"old", &revision(b"new"))
                .expect("transaction");
        replace_file_atomically(&config, b"new", true).expect("publish replacement");
        transaction.mark_published().expect("mark published");
        drop(transaction);
        recover_interrupted_settings_update_locked(&config).expect("recovery");
        assert_eq!(fs::read(&config).expect("read config"), b"new");
        fs::remove_dir_all(root).expect("cleanup");
    }

    #[cfg(unix)]
    #[test]
    fn committed_cleanup_without_journal_keeps_replacement() {
        let root = std::env::temp_dir().join(format!("centrald-settings-{}", uuid::Uuid::now_v7()));
        fs::create_dir(&root).expect("test directory");
        let config = root.join("server.toml");
        write_new_file(&config, b"old", true).expect("initial config");
        let transaction =
            SettingsUpdateTransaction::begin_locked(&config, b"old", &revision(b"new"))
                .expect("transaction");
        replace_file_atomically(&config, b"new", true).expect("publish replacement");
        transaction.mark_published().expect("mark published");
        let paths = settings_paths(&config).expect("settings paths");
        fs::remove_file(&paths.journal).expect("simulate committed cleanup transition");
        recover_interrupted_settings_update_locked(&config).expect("recovery");
        assert_eq!(fs::read(&config).expect("read config"), b"new");
        assert!(!paths.original.exists());
        assert!(!paths.published.exists());
        fs::remove_dir_all(root).expect("cleanup");
    }
}
