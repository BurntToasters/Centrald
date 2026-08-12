use std::fs;
#[cfg(unix)]
use std::fs::{File, OpenOptions};
use std::path::{Path, PathBuf};

use anyhow::{Context, Result, bail};
use centrald_common::config::SERVER_DATA_DIR;
use centrald_common::secure_fs::{
    replace_file_atomically, validate_no_symlink_ancestors, write_new_file,
};
use secrecy::ExposeSecret;
use serde::{Deserialize, Serialize};

#[cfg(unix)]
use fs2::FileExt;

use crate::db::{DatabaseAdminError, database_name_from_url, rollback_setup_database};
use crate::local_postgres;
use crate::setup::{
    SetupOptions, remove_empty_setup_directories, rollback_interrupted_setup_files,
};

const JOURNAL_VERSION: u32 = 3;
const JOURNAL_NAME: &str = ".centrald-initial-setup-recovery.json";
const MAX_JOURNAL_BYTES: u64 = 64 * 1024;
#[allow(dead_code)]
const SETUP_MUTATION_LOCK: &str = "/var/lib/centrald-initial-setup.lock";

/// Serializes first-run provisioning, interrupted-setup recovery, and a
/// destructive reset of an uncommitted setup.
#[derive(Debug)]
#[cfg(unix)]
pub struct SetupMutationLock {
    file: File,
}

#[derive(Debug)]
#[cfg(not(unix))]
pub struct SetupMutationLock;

#[cfg(unix)]
impl Drop for SetupMutationLock {
    fn drop(&mut self) {
        let _ = FileExt::unlock(&self.file);
    }
}

/// Acquires the fixed root-owned setup/reset lock without waiting indefinitely.
///
/// # Errors
///
/// Returns an error when another setup/reset owns the lock or when the fixed
/// lock path is unsafe.
pub fn acquire_setup_mutation_lock() -> Result<SetupMutationLock> {
    #[cfg(not(unix))]
    {
        bail!("CentralD server setup locking is supported only on Ubuntu Server hosts");
    }
    #[cfg(unix)]
    {
        use std::os::unix::fs::{MetadataExt, OpenOptionsExt};

        let path = Path::new(SETUP_MUTATION_LOCK);
        let parent = path.parent().context("setup mutation lock has no parent")?;
        let parent_metadata = parent
            .symlink_metadata()
            .with_context(|| format!("inspect setup lock directory {}", parent.display()))?;
        if parent_metadata.file_type().is_symlink()
            || !parent_metadata.is_dir()
            || parent_metadata.uid() != 0
            || parent_metadata.mode() & 0o022 != 0
        {
            bail!(
                "setup lock directory must be root-owned and not group/world-writable: {}",
                parent.display()
            );
        }
        if let Ok(metadata) = path.symlink_metadata() {
            if metadata.file_type().is_symlink() || !metadata.is_file() {
                bail!(
                    "setup mutation lock is not a regular file: {}",
                    path.display()
                );
            }
        }
        let file = OpenOptions::new()
            .read(true)
            .write(true)
            .create(true)
            .mode(0o600)
            .open(path)
            .with_context(|| format!("open setup mutation lock {}", path.display()))?;
        let metadata = file
            .metadata()
            .with_context(|| format!("inspect setup mutation lock {}", path.display()))?;
        if !metadata.is_file()
            || metadata.uid() != 0
            || metadata.mode() & 0o077 != 0
            || metadata.nlink() != 1
        {
            bail!(
                "setup mutation lock must be root-owned, private, and single-linked: {}",
                path.display()
            );
        }
        match FileExt::try_lock_exclusive(&file) {
            Ok(()) => Ok(SetupMutationLock { file }),
            Err(error) if error.kind() == std::io::ErrorKind::WouldBlock => bail!(
                "another CentralD initial setup or destructive setup reset is already running"
            ),
            Err(error) => Err(error).context("lock CentralD initial setup state"),
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
enum SetupPhase {
    Provisioning,
    Committed,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
enum SetupDatabaseMode {
    ManagedLocal,
    External,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct ProcessOwner {
    boot_id: String,
    pid: u32,
    start_ticks: u64,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct SetupRecoveryJournal {
    version: u32,
    phase: SetupPhase,
    config_path: PathBuf,
    recovery_key_output: PathBuf,
    environment_file: PathBuf,
    data_dir: PathBuf,
    instance_id: uuid::Uuid,
    database_mode: SetupDatabaseMode,
    managed_role: Option<String>,
    database_name: String,
    database_url_env: String,
    owner: ProcessOwner,
}

/// Writes durable, non-secret recovery state before the first `PostgreSQL`
/// mutation for either the recommended managed-local flow or the advanced
/// external flow. Credentials are never copied into this journal.
///
/// # Errors
///
/// Returns an error when the URL/role is inconsistent, process identity cannot
/// be determined, or the journal cannot be safely created and synced.
pub fn begin_setup(options: &SetupOptions) -> Result<()> {
    let path = journal_path();
    if path.symlink_metadata().is_ok() {
        bail!(
            "initial-setup recovery state already exists; rerun initial-setup so CentralD can recover it first"
        );
    }
    let (database_mode, managed_role, database_name) =
        if let Some(role) = options.managed_local_role.as_deref() {
            (
                SetupDatabaseMode::ManagedLocal,
                Some(role.to_owned()),
                local_postgres::managed_database_name(role, &options.database_url)?,
            )
        } else {
            (
                SetupDatabaseMode::External,
                None,
                database_name_from_url(options.database_url.expose_secret())?,
            )
        };
    let journal = SetupRecoveryJournal {
        version: JOURNAL_VERSION,
        phase: SetupPhase::Provisioning,
        config_path: options.config_path.clone(),
        recovery_key_output: options.recovery_key_output.clone(),
        environment_file: options.environment_file.clone(),
        data_dir: options.data_dir.clone(),
        instance_id: options.instance_id,
        database_mode,
        managed_role,
        database_name,
        database_url_env: options.database_url_env.clone(),
        owner: current_process_owner()?,
    };
    validate_journal_parent()?;
    write_new_file(&path, &serde_json::to_vec_pretty(&journal)?, true)
        .with_context(|| format!("write PostgreSQL setup recovery journal {}", path.display()))?;
    Ok(())
}

/// Recovers a dead recommended local-`PostgreSQL` setup before starting another
/// setup attempt. A live owner is never treated as abandoned.
///
/// Returns `true` when a committed journal was retired. The caller should then
/// report that setup already completed rather than starting a second install.
///
/// # Errors
///
/// Returns an error when the journal is unsafe, does not belong to this
/// configuration, a live setup owner is detected, or cleanup of an abandoned
/// setup fails.
pub async fn recover_before_initial_setup(config_path: &Path) -> Result<bool> {
    let Some(journal) = read_journal_if_present()? else {
        return Ok(false);
    };
    validate_journal_for_config(&journal, config_path)?;
    match journal.phase {
        SetupPhase::Committed => {
            if !config_path.is_file() {
                bail!(
                    "a committed initial-setup journal exists but {} is missing; refusing automatic PostgreSQL cleanup",
                    config_path.display()
                );
            }
            remove_journal()?;
            Ok(true)
        }
        SetupPhase::Provisioning => {
            if process_owner_is_live(&journal.owner)? {
                bail!(
                    "another centrald-server initial-setup process is still provisioning this installation (pid {})",
                    journal.owner.pid
                );
            }
            println!("Recovering an interrupted CentralD PostgreSQL setup...");
            cleanup_abandoned_setup(&journal).await?;
            println!("Interrupted setup recovery completed. Starting a fresh setup.");
            Ok(false)
        }
    }
}

/// Prevents normal server commands from using an installation while its
/// recommended local `PostgreSQL` setup is incomplete. A committed leftover
/// journal is safely retired.
///
/// # Errors
///
/// Returns an error when the journal is unsafe or does not belong to this
/// configuration, or when the installation's setup is incomplete.
#[allow(clippy::unused_async)]
pub async fn prepare_for_normal_command(config_path: &Path) -> Result<()> {
    let Some(journal) = read_journal_if_present()? else {
        return Ok(());
    };
    validate_journal_for_config(&journal, config_path)?;
    match journal.phase {
        SetupPhase::Committed => {
            if !config_path.is_file() {
                bail!(
                    "a committed initial-setup journal exists but {} is missing",
                    config_path.display()
                );
            }
            remove_journal()
        }
        SetupPhase::Provisioning => bail!(
            "CentralD initial setup was interrupted before commit; rerun `sudo centrald-server initial-setup` to recover it safely"
        ),
    }
}

/// Permanently removes an interrupted, uncommitted initial setup when the
/// operator invokes the explicit destructive-reset command.
///
/// A live setup owner is never interrupted. A committed setup journal is only
/// retired; the normal nuke path must then validate and remove the published
/// installation. Returns `true` only when an uncommitted setup was completely
/// removed and there is no published installation left to reset.
///
/// # Errors
///
/// Returns an error when the journal is unsafe or does not belong to this
/// configuration, a live setup owner is detected, or destructive cleanup fails.
pub async fn reset_interrupted_setup_for_nuke(config_path: &Path) -> Result<bool> {
    let Some(journal) = read_journal_if_present()? else {
        return Ok(false);
    };
    validate_journal_for_config(&journal, config_path)?;
    match journal.phase {
        SetupPhase::Committed => {
            if !config_path.is_file() {
                bail!(
                    "a committed initial-setup journal exists but {} is missing; refusing destructive recovery without the published configuration",
                    config_path.display()
                );
            }
            remove_journal()?;
            Ok(false)
        }
        SetupPhase::Provisioning => {
            if process_owner_is_live(&journal.owner)? {
                bail!(
                    "another centrald-server initial-setup process is still provisioning this installation (pid {}); stop it before destructive reset",
                    journal.owner.pid
                );
            }
            cleanup_abandoned_setup(&journal).await?;
            Ok(true)
        }
    }
}

/// Rolls back the setup attempt owned by the current process after an ordinary
/// error. This uses the same idempotent cleanup as crash recovery, without
/// treating the current live PID as a competing setup process.
///
/// # Errors
///
/// Returns an error when the journal is missing, does not belong to this
/// configuration, is committed, or cleanup fails.
pub async fn rollback_current_setup(config_path: &Path) -> Result<()> {
    let journal = read_journal_required()?;
    validate_journal_for_config(&journal, config_path)?;
    if journal.phase != SetupPhase::Provisioning {
        bail!("refusing to roll back a committed setup journal");
    }
    cleanup_abandoned_setup(&journal).await
}

/// Marks the installation durable after database hardening and initial Admin
/// creation, before the one-time Admin key is printed.
///
/// # Errors
///
/// Returns an error when the journal is missing, does not belong to this
/// configuration, is not in provisioning state, or cannot be rewritten.
pub fn mark_committed(config_path: &Path) -> Result<()> {
    let mut journal = read_journal_required()?;
    validate_journal_for_config(&journal, config_path)?;
    if journal.phase != SetupPhase::Provisioning {
        bail!("initial-setup recovery journal is not in provisioning state");
    }
    journal.phase = SetupPhase::Committed;
    let path = journal_path();
    replace_file_atomically(&path, &serde_json::to_vec_pretty(&journal)?, true)
        .with_context(|| format!("commit initial-setup recovery journal {}", path.display()))?;
    Ok(())
}

/// Removes the recovery journal after a committed installation is known to be
/// recoverable through its normal configuration and local management console.
///
/// # Errors
///
/// Returns an error when the journal is missing, does not belong to this
/// configuration, is not committed, or cannot be removed.
pub fn retire_committed(config_path: &Path) -> Result<()> {
    let journal = read_journal_required()?;
    validate_journal_for_config(&journal, config_path)?;
    if journal.phase != SetupPhase::Committed {
        bail!("refusing to retire an uncommitted initial-setup recovery journal");
    }
    remove_journal()
}

/// Removes the recovery journal only after the caller has successfully cleaned
/// every managed `PostgreSQL` and filesystem output from a failed setup.
///
/// # Errors
///
/// Returns an error when the journal is missing, does not belong to this
/// configuration, is committed, or cannot be removed.
pub fn retire_after_rollback(config_path: &Path) -> Result<()> {
    let journal = read_journal_required()?;
    validate_journal_for_config(&journal, config_path)?;
    if journal.phase != SetupPhase::Provisioning {
        bail!("refusing to retire a committed setup journal as rollback state");
    }
    remove_journal()?;
    remove_empty_setup_directories(&journal.data_dir)
}

async fn cleanup_abandoned_setup(journal: &SetupRecoveryJournal) -> Result<()> {
    let mut failures = Vec::new();
    let database_result = match journal.database_mode {
        SetupDatabaseMode::ManagedLocal => {
            let role = journal
                .managed_role
                .as_deref()
                .context("managed setup journal is missing its PostgreSQL role")?;
            local_postgres::cleanup_managed_resources(
                role,
                &journal.database_name,
                journal.instance_id,
            )
        }
        SetupDatabaseMode::External => cleanup_external_database(journal).await,
    };
    if let Err(error) = database_result {
        failures.push(format!("clean PostgreSQL resources: {error:#}"));
    }
    if let Err(error) = rollback_interrupted_setup_files(
        &journal.config_path,
        &journal.recovery_key_output,
        &journal.environment_file,
        &journal.data_dir,
    ) {
        failures.push(format!("clean generated setup files: {error:#}"));
    }
    if failures.is_empty() {
        remove_journal()?;
        remove_empty_setup_directories(&journal.data_dir)
            .context("remove empty directories left by interrupted initial setup")
    } else {
        bail!(
            "interrupted setup recovery is incomplete; the recovery journal was kept for the next retry: {}",
            failures.join("; ")
        )
    }
}

async fn cleanup_external_database(journal: &SetupRecoveryJournal) -> Result<()> {
    let raw = match fs::read_to_string(&journal.environment_file) {
        Ok(raw) => raw,
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => return Ok(()),
        Err(error) => {
            return Err(error).with_context(|| {
                format!(
                    "read {} for external setup recovery",
                    journal.environment_file.display()
                )
            });
        }
    };
    if raw.len() > 128 * 1024 || raw.contains('\r') {
        bail!("external setup database environment file is malformed");
    }
    let mut lines = raw.lines();
    let marker = lines
        .next()
        .context("external setup database environment marker is missing")?;
    let assignment = lines
        .next()
        .context("external setup database URL is missing")?;
    if lines.next().is_some() || marker != format!("# centrald-instance:{}", journal.instance_id) {
        bail!("external setup database environment file is not bound to this server instance");
    }
    let (name, url) = assignment
        .split_once('=')
        .context("external setup database environment assignment is malformed")?;
    if name != journal.database_url_env || url.is_empty() || url.contains(char::is_whitespace) {
        bail!("external setup database environment assignment is invalid");
    }
    if database_name_from_url(url)? != journal.database_name {
        bail!("external setup database URL no longer matches the recovery journal");
    }
    match rollback_setup_database(url, journal.instance_id).await {
        Ok(_) | Err(DatabaseAdminError::MissingDatabase(_)) => Ok(()),
        Err(error) => Err(error).context(
            "recover external setup database (if CREATE DATABASE was interrupted before the ownership comment was written, inspect that dedicated database manually before retrying)",
        ),
    }
}

fn validate_journal_for_config(journal: &SetupRecoveryJournal, config_path: &Path) -> Result<()> {
    if journal.version != JOURNAL_VERSION {
        bail!("unsupported initial-setup recovery journal version");
    }
    if journal.config_path != config_path {
        bail!(
            "initial-setup recovery journal belongs to {}; rerun initial-setup with that exact --config path",
            journal.config_path.display()
        );
    }
    if journal.instance_id.is_nil() {
        bail!("initial-setup recovery journal contains a nil server instance ID");
    }
    if journal.data_dir != *SERVER_DATA_DIR {
        bail!("initial-setup recovery journal contains an unexpected server data directory");
    }
    if journal.database_url_env.is_empty()
        || !journal
            .database_url_env
            .chars()
            .all(|character| character.is_ascii_alphanumeric() || character == '_')
    {
        bail!("initial-setup recovery journal has an invalid database environment variable name");
    }
    match journal.database_mode {
        SetupDatabaseMode::ManagedLocal => {
            let role = journal
                .managed_role
                .as_deref()
                .context("managed setup recovery journal is missing its PostgreSQL role")?;
            local_postgres::validate_managed_name(role)?;
            local_postgres::validate_managed_name(&journal.database_name)?;
            if role != journal.database_name {
                bail!("initial-setup recovery journal role/database pair is inconsistent");
            }
        }
        SetupDatabaseMode::External => {
            if journal.managed_role.is_some() {
                bail!("external setup recovery journal unexpectedly contains a managed role");
            }
            if journal.database_name.is_empty() || journal.database_name.len() > 63 {
                bail!("external setup recovery journal has an invalid database name");
            }
        }
    }
    Ok(())
}

fn read_journal_if_present() -> Result<Option<SetupRecoveryJournal>> {
    let path = journal_path();
    match path.symlink_metadata() {
        Ok(metadata) => {
            validate_journal_metadata(&path, &metadata)?;
            if metadata.len() > MAX_JOURNAL_BYTES {
                bail!(
                    "initial-setup recovery journal exceeds the maximum supported size: {}",
                    path.display()
                );
            }
            let value = serde_json::from_slice(
                &fs::read(&path).with_context(|| format!("read {}", path.display()))?,
            )
            .context("parse initial-setup recovery journal")?;
            Ok(Some(value))
        }
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => Ok(None),
        Err(error) => Err(error).with_context(|| format!("inspect {}", path.display())),
    }
}

fn read_journal_required() -> Result<SetupRecoveryJournal> {
    read_journal_if_present()?.context("initial-setup recovery journal is missing")
}

fn remove_journal() -> Result<()> {
    let path = journal_path();
    let metadata = path
        .symlink_metadata()
        .with_context(|| format!("inspect {}", path.display()))?;
    validate_journal_metadata(&path, &metadata)?;
    fs::remove_file(&path).with_context(|| format!("remove {}", path.display()))?;
    if let Some(parent) = path.parent() {
        fs::File::open(parent)
            .and_then(|directory| directory.sync_all())
            .with_context(|| format!("sync {}", parent.display()))?;
    }
    Ok(())
}

fn journal_path() -> PathBuf {
    Path::new(SERVER_DATA_DIR).join(JOURNAL_NAME)
}

fn validate_journal_parent() -> Result<()> {
    let path = journal_path();
    validate_no_symlink_ancestors(&path)
        .with_context(|| format!("validate recovery journal ancestors for {}", path.display()))?;
    #[cfg(unix)]
    {
        use std::os::unix::fs::MetadataExt;
        for parent in [Path::new("/var/lib"), Path::new(SERVER_DATA_DIR)] {
            let metadata = match parent.symlink_metadata() {
                Ok(metadata) => metadata,
                Err(error) if error.kind() == std::io::ErrorKind::NotFound => continue,
                Err(error) => {
                    return Err(error).with_context(|| format!("inspect {}", parent.display()));
                }
            };
            if metadata.file_type().is_symlink()
                || !metadata.is_dir()
                || metadata.uid() != 0
                || metadata.mode() & 0o022 != 0
            {
                bail!(
                    "setup recovery ancestor must be root-owned and not group/world-writable: {}",
                    parent.display()
                );
            }
        }
    }
    Ok(())
}

fn validate_journal_metadata(path: &Path, metadata: &fs::Metadata) -> Result<()> {
    if metadata.file_type().is_symlink() || !metadata.is_file() {
        bail!(
            "initial-setup recovery journal is not a regular file: {}",
            path.display()
        );
    }
    #[cfg(unix)]
    {
        use std::os::unix::fs::MetadataExt;
        if metadata.uid() != 0 || metadata.mode() & 0o077 != 0 || metadata.nlink() != 1 {
            bail!(
                "initial-setup recovery journal must be root-owned, mode 0600-compatible, and single-linked: {}",
                path.display()
            );
        }
    }
    Ok(())
}

fn current_process_owner() -> Result<ProcessOwner> {
    #[cfg(not(target_os = "linux"))]
    {
        bail!("managed local PostgreSQL setup recovery requires Linux /proc");
    }
    #[cfg(target_os = "linux")]
    {
        let pid = std::process::id();
        Ok(ProcessOwner {
            boot_id: read_boot_id()?,
            pid,
            start_ticks: read_process_start_ticks(pid)?,
        })
    }
}

fn process_owner_is_live(owner: &ProcessOwner) -> Result<bool> {
    #[cfg(not(target_os = "linux"))]
    {
        let _ = owner;
        bail!("managed local PostgreSQL setup recovery requires Linux /proc");
    }
    #[cfg(target_os = "linux")]
    {
        if read_boot_id()? != owner.boot_id {
            return Ok(false);
        }
        match read_process_start_ticks_if_present(owner.pid)? {
            Some(start_ticks) => Ok(start_ticks == owner.start_ticks),
            None => Ok(false),
        }
    }
}

#[cfg(target_os = "linux")]
fn read_boot_id() -> Result<String> {
    let value = fs::read_to_string("/proc/sys/kernel/random/boot_id")
        .context("read Linux boot ID for setup recovery")?;
    let value = value.trim();
    if value.len() != 36
        || !value
            .chars()
            .all(|character| character.is_ascii_hexdigit() || character == '-')
    {
        bail!("Linux boot ID has an unexpected format");
    }
    Ok(value.to_owned())
}

#[cfg(target_os = "linux")]
fn read_process_start_ticks(pid: u32) -> Result<u64> {
    read_process_start_ticks_if_present(pid)?.with_context(|| {
        format!("process {pid} disappeared while setup recovery state was created")
    })
}

#[cfg(target_os = "linux")]
fn read_process_start_ticks_if_present(pid: u32) -> Result<Option<u64>> {
    let path = PathBuf::from(format!("/proc/{pid}/stat"));
    let stat = match fs::read_to_string(&path) {
        Ok(stat) => stat,
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => return Ok(None),
        Err(error) => return Err(error).with_context(|| format!("read {}", path.display())),
    };
    parse_process_start_ticks(&stat).map(Some)
}

#[cfg(target_os = "linux")]
fn parse_process_start_ticks(stat: &str) -> Result<u64> {
    let close = stat
        .rfind(')')
        .context("Linux process stat is missing command terminator")?;
    let remainder = stat
        .get(close + 1..)
        .context("Linux process stat command boundary is invalid")?
        .trim_start();
    let start = remainder
        .split_whitespace()
        .nth(19)
        .context("Linux process stat is missing start time")?;
    start
        .parse::<u64>()
        .context("parse Linux process start time")
}

#[cfg(test)]
#[allow(clippy::expect_used)]
mod tests {
    #[cfg(target_os = "linux")]
    #[test]
    fn parses_proc_start_ticks_after_parenthesized_command() {
        let mut fields = vec!["S".to_owned()];
        fields.extend((4..=21).map(|value| value.to_string()));
        fields.push("424242".to_owned());
        fields.push("23".to_owned());
        let stat = format!("123 (centrald worker) {}", fields.join(" "));
        assert_eq!(
            parse_process_start_ticks(&stat).expect("parse start ticks"),
            424242
        );
    }
}
