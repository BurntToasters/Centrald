use std::ffi::OsString;
use std::path::{Component, Path, PathBuf};

use anyhow::{Context, Result, bail};
use centrald_common::config::ServerConfig;
use centrald_common::secure_fs::{
    replace_file_atomically, validate_no_symlink_ancestors, write_new_file,
};
use secrecy::ExposeSecret;
use serde::{Deserialize, Serialize};

use crate::db::{
    DatabaseAdminError, database_name_from_url, drop_owned_database,
    resolve_database_url_from_file, verify_owned_database,
};
use crate::local_audit;
use crate::local_control::acquire_server_lock;
use crate::local_postgres;
use crate::manage::require_root;
use crate::setup::{DATA_ROOT_MARKER, data_root_marker_contents};

const NUKE_JOURNAL_VERSION: u32 = 1;
const MAX_NUKE_JOURNAL_BYTES: u64 = 64 * 1024;

#[derive(Debug)]
pub struct NukeSummary {
    pub database_name: String,
    pub data_dir: PathBuf,
    pub config_path: PathBuf,
    pub environment_file: PathBuf,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
enum NukePhase {
    Authorized,
    DatabaseDropped,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct NukeRecoveryJournal {
    version: u32,
    phase: NukePhase,
    instance_id: uuid::Uuid,
    database_name: String,
    managed_local_role: Option<String>,
    plan: NukePlan,
}

/// Permanently removes one marked CentralD installation and drops its database.
///
/// Every filesystem target and both database ownership markers are validated
/// before a durable reset journal is written. The journal makes the destructive
/// operation retryable after a crash, PostgreSQL role-removal failure, or partial
/// filesystem cleanup. The same exclusive runtime lock used by the daemon is
/// held for the entire attempt.
///
/// # Errors
///
/// Returns an error unless the caller is root, the daemon lock can be acquired,
/// all filesystem and ownership markers match, and PostgreSQL accepts the owned
/// database/role removal. On a partial failure, the reset journal is retained and
/// rerunning the exact nuke command resumes rather than attempting a new reset.
pub async fn nuke(config_path: &Path) -> Result<NukeSummary> {
    require_root()?;
    let journal_path = nuke_journal_path(config_path)?;
    if journal_path.symlink_metadata().is_ok() {
        let journal = read_nuke_journal(config_path)?;
        return resume_nuke(journal, &journal_path).await;
    }

    validate_regular_file(config_path, "server configuration", true)?;
    let config = ServerConfig::load(config_path)?;
    let plan = NukePlan::validate(config_path, &config)?;
    let database_url = resolve_database_url_from_file(&config)?;

    let _server_lock = acquire_server_lock(&config.server.local_socket)
        .context("acquire exclusive CentralD server lock; stop centrald-server before --nuke")?;
    ensure_socket_inactive(&config.server.local_socket).await?;

    let database_name = verify_owned_database(
        database_url.expose_secret(),
        config.server.instance_id,
    )
    .await
    .context("verify CentralD PostgreSQL ownership before authorizing destructive reset")?;
    let journal = NukeRecoveryJournal {
        version: NUKE_JOURNAL_VERSION,
        phase: NukePhase::Authorized,
        instance_id: config.server.instance_id,
        database_name,
        managed_local_role: config.database.managed_local_role.clone(),
        plan,
    };
    write_nuke_journal(&journal_path, &journal)?;

    continue_authorized_nuke(journal, &journal_path, Some(database_url.expose_secret())).await
}

async fn resume_nuke(
    journal: NukeRecoveryJournal,
    journal_path: &Path,
) -> Result<NukeSummary> {
    validate_journal_plan(&journal)?;
    let _server_lock = acquire_server_lock(&journal.plan.runtime_socket)
        .context("acquire exclusive CentralD server lock; stop centrald-server before --nuke")?;
    ensure_socket_inactive(&journal.plan.runtime_socket).await?;

    match journal.phase {
        NukePhase::Authorized => {
            validate_regular_file(&journal.plan.config_path, "server configuration", true)?;
            let config = ServerConfig::load(&journal.plan.config_path)?;
            validate_config_matches_journal(&config, &journal)?;
            let database_url = resolve_database_url_from_file(&config)?;
            continue_authorized_nuke(
                journal,
                journal_path,
                Some(database_url.expose_secret()),
            )
            .await
        }
        NukePhase::DatabaseDropped => finish_nuke(journal, journal_path),
    }
}

async fn continue_authorized_nuke(
    mut journal: NukeRecoveryJournal,
    journal_path: &Path,
    database_url: Option<&str>,
) -> Result<NukeSummary> {
    let database_url = database_url.context(
        "authorized destructive reset still needs the root-protected database environment file",
    )?;
    let parsed_name = database_name_from_url(database_url)?;
    if parsed_name != journal.database_name {
        bail!("destructive-reset journal database does not match the configured database URL");
    }
    if let Some(role) = journal.managed_local_role.as_deref() {
        // Authorize both managed PostgreSQL objects before dropping either one.
        // A changed or colliding role marker must stop the reset while the
        // still-running database and server files are intact.
        local_postgres::require_owned_role(role, journal.instance_id).with_context(|| {
            format!(
                "verify CentralD-managed PostgreSQL role before dropping database {}; reset journal remains at {}",
                journal.database_name,
                journal_path.display()
            )
        })?;
    }

    match drop_owned_database(database_url, journal.instance_id).await {
        Ok(database_name) => {
            if database_name != journal.database_name {
                bail!("PostgreSQL dropped an unexpected database name");
            }
        }
        Err(DatabaseAdminError::MissingDatabase(database_name))
            if database_name == journal.database_name =>
        {
            // The journal is written only after both ownership markers have
            // been verified. A missing database here means the preceding nuke
            // process completed the drop but stopped before advancing the
            // durable phase.
        }
        Err(error) => {
            return Err(anyhow::Error::new(error).context(
                "drop owned CentralD PostgreSQL database; FORCE may still be blocked by prepared transactions, logical replication slots, or subscriptions; the reset journal was retained for an exact retry",
            ));
        }
    }

    journal.phase = NukePhase::DatabaseDropped;
    replace_file_atomically(
        journal_path,
        &serde_json::to_vec_pretty(&journal)?,
        true,
    )
    .with_context(|| {
        format!(
            "record completed PostgreSQL drop in {}",
            journal_path.display()
        )
    })?;
    finish_nuke(journal, journal_path)
}

fn finish_nuke(
    journal: NukeRecoveryJournal,
    journal_path: &Path,
) -> Result<NukeSummary> {
    validate_journal_plan(&journal)?;
    if let Some(role) = journal.managed_local_role.as_deref() {
        local_postgres::drop_owned_role(role, journal.instance_id).with_context(|| {
            format!(
                "remove CentralD-managed local PostgreSQL role; reset state remains at {} and the server files were preserved for retry",
                journal_path.display()
            )
        })?;
    }

    let mut cleanup_failures = Vec::new();
    collect_cleanup(
        remove_regular_file_if_present(&journal.plan.environment_file, "database environment file"),
        &mut cleanup_failures,
    );
    collect_cleanup(
        remove_regular_file_if_present(&journal.plan.local_audit_journal, "server-local audit journal"),
        &mut cleanup_failures,
    );
    collect_cleanup(
        remove_regular_file_if_present(&journal.plan.config_path, "server configuration"),
        &mut cleanup_failures,
    );
    collect_cleanup(
        remove_runtime_socket_if_present(&journal.plan.runtime_socket),
        &mut cleanup_failures,
    );
    collect_cleanup(
        remove_data_dir_if_present(&journal.plan.data_dir, journal.instance_id),
        &mut cleanup_failures,
    );

    if !cleanup_failures.is_empty() {
        bail!(
            "CentralD database {} was dropped, but cleanup was incomplete; rerun the exact --nuke command to resume from {}: {}",
            journal.database_name,
            journal_path.display(),
            cleanup_failures.join("; ")
        );
    }

    remove_nuke_journal(journal_path)?;
    Ok(NukeSummary {
        database_name: journal.database_name,
        data_dir: journal.plan.data_dir,
        config_path: journal.plan.config_path,
        environment_file: journal.plan.environment_file,
    })
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct NukePlan {
    data_dir: PathBuf,
    config_path: PathBuf,
    environment_file: PathBuf,
    runtime_socket: PathBuf,
    local_audit_journal: PathBuf,
}

impl NukePlan {
    fn validate(config_path: &Path, config: &ServerConfig) -> Result<Self> {
        validate_data_root(&config.server.data_dir, config.server.instance_id)?;
        validate_regular_file(
            &config.database.environment_file,
            "database environment file",
            false,
        )?;
        validate_runtime_socket(&config.server.local_socket)?;
        let local_audit_journal = local_audit::journal_path(config_path)?;
        validate_regular_file(&local_audit_journal, "server-local audit journal", false)?;
        let lock_path = config
            .server
            .local_socket
            .parent()
            .context("runtime socket has no parent")?
            .join("server.lock");
        validate_regular_file(&lock_path, "server lock", false)?;

        let canonical_data = std::fs::canonicalize(&config.server.data_dir)
            .context("canonicalize CentralD data root")?;
        let canonical_config = std::fs::canonicalize(config_path)
            .context("canonicalize CentralD server configuration")?;
        if canonical_config.starts_with(&canonical_data) {
            bail!(
                "server configuration must remain outside the disposable CentralD data root"
            );
        }
        for (label, path) in [
            ("server configuration", config_path),
            (
                "database environment file",
                config.database.environment_file.as_path(),
            ),
            ("runtime socket", config.server.local_socket.as_path()),
            ("server-local audit journal", local_audit_journal.as_path()),
        ] {
            if path == canonical_data || path.starts_with(&canonical_data) {
                bail!(
                    "{label} must be outside the CentralD data directory so destructive-reset recovery state cannot delete itself"
                );
            }
        }

        Ok(Self {
            data_dir: config.server.data_dir.clone(),
            config_path: config_path.to_path_buf(),
            environment_file: config.database.environment_file.clone(),
            runtime_socket: config.server.local_socket.clone(),
            local_audit_journal,
        })
    }
}

fn validate_config_matches_journal(
    config: &ServerConfig,
    journal: &NukeRecoveryJournal,
) -> Result<()> {
    let expected_plan = NukePlan::validate(&journal.plan.config_path, config)?;
    if config.server.instance_id != journal.instance_id
        || config.database.managed_local_role != journal.managed_local_role
        || expected_plan.data_dir != journal.plan.data_dir
        || expected_plan.environment_file != journal.plan.environment_file
        || expected_plan.runtime_socket != journal.plan.runtime_socket
        || expected_plan.local_audit_journal != journal.plan.local_audit_journal
    {
        bail!("destructive-reset journal does not match the current CentralD configuration");
    }
    Ok(())
}

fn validate_journal_plan(journal: &NukeRecoveryJournal) -> Result<()> {
    if journal.version != NUKE_JOURNAL_VERSION || journal.instance_id.is_nil() {
        bail!("invalid or unsupported CentralD destructive-reset journal");
    }
    for (label, path) in [
        ("configuration", journal.plan.config_path.as_path()),
        ("data root", journal.plan.data_dir.as_path()),
        ("database environment", journal.plan.environment_file.as_path()),
        ("runtime socket", journal.plan.runtime_socket.as_path()),
        ("local audit journal", journal.plan.local_audit_journal.as_path()),
    ] {
        if path.as_os_str().is_empty() || !path.is_absolute() {
            bail!("destructive-reset journal contains an unsafe {label} path");
        }
    }
    if let Some(role) = journal.managed_local_role.as_deref() {
        local_postgres::validate_managed_name(role)?;
        if role != journal.database_name {
            bail!("managed local reset journal role/database pair is inconsistent");
        }
    }
    if journal.plan.data_dir.symlink_metadata().is_ok() {
        let marker = journal.plan.data_dir.join(DATA_ROOT_MARKER);
        if marker.symlink_metadata().is_ok() {
            validate_data_root(&journal.plan.data_dir, journal.instance_id)?;
        } else if journal.phase == NukePhase::DatabaseDropped {
            validate_empty_data_root_after_marker_retirement(&journal.plan.data_dir)?;
        } else {
            bail!("destructive-reset data-root marker disappeared before the database was dropped");
        }
    } else if journal.phase != NukePhase::DatabaseDropped {
        bail!("CentralD data root disappeared before the database drop was recorded");
    }
    Ok(())
}

fn write_nuke_journal(path: &Path, journal: &NukeRecoveryJournal) -> Result<()> {
    validate_nuke_journal_parent(path)?;
    write_new_file(path, &serde_json::to_vec_pretty(journal)?, true)
        .with_context(|| format!("write destructive-reset journal {}", path.display()))
}

fn read_nuke_journal(config_path: &Path) -> Result<NukeRecoveryJournal> {
    let path = nuke_journal_path(config_path)?;
    let metadata = path
        .symlink_metadata()
        .with_context(|| format!("inspect destructive-reset journal {}", path.display()))?;
    validate_nuke_journal_metadata(&path, &metadata)?;
    validate_nuke_journal_parent(&path)?;
    if metadata.len() > MAX_NUKE_JOURNAL_BYTES {
        bail!(
            "destructive-reset journal exceeds the maximum supported size: {}",
            path.display()
        );
    }
    let journal: NukeRecoveryJournal = serde_json::from_slice(
        &std::fs::read(&path)
            .with_context(|| format!("read destructive-reset journal {}", path.display()))?,
    )
    .context("parse destructive-reset journal")?;
    if journal.plan.config_path != config_path {
        bail!("destructive-reset journal belongs to another configuration path");
    }
    validate_journal_plan(&journal)?;
    Ok(journal)
}

fn remove_nuke_journal(path: &Path) -> Result<()> {
    let metadata = path
        .symlink_metadata()
        .with_context(|| format!("inspect destructive-reset journal {}", path.display()))?;
    validate_nuke_journal_metadata(path, &metadata)?;
    std::fs::remove_file(path)
        .with_context(|| format!("remove destructive-reset journal {}", path.display()))?;
    if let Some(parent) = path.parent() {
        std::fs::File::open(parent)
            .and_then(|directory| directory.sync_all())
            .with_context(|| format!("sync destructive-reset journal directory {}", parent.display()))?;
    }
    Ok(())
}

fn validate_nuke_journal_metadata(path: &Path, metadata: &std::fs::Metadata) -> Result<()> {
    if metadata.file_type().is_symlink() || !metadata.is_file() {
        bail!("destructive-reset journal is not a regular file: {}", path.display());
    }
    #[cfg(unix)]
    {
        use std::os::unix::fs::MetadataExt;
        if metadata.uid() != 0 || metadata.mode() & 0o077 != 0 || metadata.nlink() != 1 {
            bail!(
                "destructive-reset journal must be root-owned, private, and single-linked: {}",
                path.display()
            );
        }
    }
    Ok(())
}

fn validate_nuke_journal_parent(path: &Path) -> Result<()> {
    validate_no_symlink_ancestors(path)
        .with_context(|| format!("validate destructive-reset journal path {}", path.display()))?;
    #[cfg(unix)]
    {
        use std::os::unix::fs::MetadataExt;

        let mut current = path.parent();
        let mut found_existing = false;
        while let Some(ancestor) = current {
            if ancestor.as_os_str().is_empty() {
                break;
            }
            match ancestor.symlink_metadata() {
                Ok(metadata) => {
                    found_existing = true;
                    if metadata.file_type().is_symlink()
                        || !metadata.is_dir()
                        || metadata.uid() != 0
                        || metadata.mode() & 0o022 != 0
                    {
                        bail!(
                            "every destructive-reset journal ancestor must be root-owned and not group/world-writable: {}",
                            ancestor.display()
                        );
                    }
                }
                Err(error) if error.kind() == std::io::ErrorKind::NotFound => {}
                Err(error) => {
                    return Err(error)
                        .with_context(|| format!("inspect {}", ancestor.display()));
                }
            }
            current = ancestor.parent();
        }
        if !found_existing {
            bail!(
                "destructive-reset journal has no existing trusted ancestor: {}",
                path.display()
            );
        }
    }
    Ok(())
}

fn nuke_journal_path(config_path: &Path) -> Result<PathBuf> {
    let parent = config_path
        .parent()
        .context("server configuration has no parent directory")?;
    let filename = config_path
        .file_name()
        .context("server configuration has no filename")?;
    let mut journal_name = OsString::from(".");
    journal_name.push(filename);
    journal_name.push(".centrald-nuke-recovery.json");
    Ok(parent.join(journal_name))
}

fn validate_data_root(data_dir: &Path, instance_id: uuid::Uuid) -> Result<()> {
    validate_data_root_directory(data_dir)?;
    let marker = data_dir.join(DATA_ROOT_MARKER);
    validate_data_root_marker(&marker, instance_id)
}

fn validate_data_root_directory(data_dir: &Path) -> Result<()> {
    if !data_dir.is_absolute()
        || data_dir == Path::new("/")
        || data_dir
            .components()
            .filter(|part| !matches!(part, Component::RootDir))
            .count()
            < 3
    {
        bail!(
            "refusing unsafe data directory {}; expected a dedicated absolute path",
            data_dir.display()
        );
    }
    let metadata = data_dir
        .symlink_metadata()
        .with_context(|| format!("inspect data directory {}", data_dir.display()))?;
    if metadata.file_type().is_symlink() || !metadata.is_dir() {
        bail!("refusing non-directory or symbolic-link data root");
    }
    #[cfg(unix)]
    {
        use std::os::unix::fs::MetadataExt;
        if metadata.uid() != 0 || metadata.mode() & 0o022 != 0 {
            bail!(
                "CentralD data root must be root-owned and not group/world-writable: {}",
                data_dir.display()
            );
        }
    }
    Ok(())
}

fn validate_data_root_marker(marker: &Path, instance_id: uuid::Uuid) -> Result<()> {
    let metadata = marker
        .symlink_metadata()
        .with_context(|| format!("inspect data-root marker {}", marker.display()))?;
    if metadata.file_type().is_symlink() || !metadata.is_file() {
        bail!("data-root marker is not a regular file: {}", marker.display());
    }
    #[cfg(unix)]
    {
        use std::os::unix::fs::MetadataExt;
        if metadata.uid() != 0 || metadata.mode() & 0o077 != 0 || metadata.nlink() != 1 {
            bail!(
                "data-root marker must be root-owned, private, and single-linked: {}",
                marker.display()
            );
        }
    }
    let marker_contents = std::fs::read_to_string(marker)
        .with_context(|| format!("read destructive-reset marker {}", marker.display()))?;
    if marker_contents != data_root_marker_contents(instance_id) {
        bail!("data-root marker does not belong to this CentralD server instance");
    }
    Ok(())
}

fn validate_empty_data_root_after_marker_retirement(data_dir: &Path) -> Result<()> {
    validate_data_root_directory(data_dir)?;
    let mut entries = std::fs::read_dir(data_dir)
        .with_context(|| format!("inspect partially removed data root {}", data_dir.display()))?;
    if entries.next().transpose()?.is_some() {
        bail!(
            "CentralD data-root marker is missing but the directory is not empty; refusing ambiguous destructive-reset recovery: {}",
            data_dir.display()
        );
    }
    Ok(())
}

fn remove_data_dir_if_present(data_dir: &Path, instance_id: uuid::Uuid) -> Result<()> {
    let metadata = match data_dir.symlink_metadata() {
        Ok(metadata) => metadata,
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => return Ok(()),
        Err(error) => {
            return Err(error)
                .with_context(|| format!("inspect data directory {}", data_dir.display()));
        }
    };
    if metadata.file_type().is_symlink() || !metadata.is_dir() {
        bail!("refusing non-directory or symbolic-link data root");
    }

    let marker = data_dir.join(DATA_ROOT_MARKER);
    match marker.symlink_metadata() {
        Ok(_) => {
            validate_data_root(data_dir, instance_id)?;
            // Keep the instance-bound marker until every other child has been
            // removed. An interruption therefore leaves enough durable proof
            // for an exact retry instead of stranding a half-removed tree.
            for entry in std::fs::read_dir(data_dir)
                .with_context(|| format!("list data directory {}", data_dir.display()))?
            {
                let entry = entry.with_context(|| {
                    format!("read data-directory entry under {}", data_dir.display())
                })?;
                if entry.file_name() == OsString::from(DATA_ROOT_MARKER) {
                    continue;
                }
                remove_data_root_entry(&entry.path())?;
            }
            std::fs::File::open(data_dir)
                .and_then(|directory| directory.sync_all())
                .with_context(|| format!("sync cleaned data directory {}", data_dir.display()))?;
            std::fs::remove_file(&marker)
                .with_context(|| format!("retire data-root marker {}", marker.display()))?;
            std::fs::File::open(data_dir)
                .and_then(|directory| directory.sync_all())
                .with_context(|| {
                    format!("sync retired data-root marker in {}", data_dir.display())
                })?;
        }
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => {
            // The only valid marker-free state is the empty final directory
            // left by a process stop between marker retirement and rmdir.
            validate_empty_data_root_after_marker_retirement(data_dir)?;
        }
        Err(error) => {
            return Err(error)
                .with_context(|| format!("inspect data-root marker {}", marker.display()));
        }
    }

    std::fs::remove_dir(data_dir)
        .with_context(|| format!("remove empty CentralD data directory {}", data_dir.display()))
}

fn remove_data_root_entry(path: &Path) -> Result<()> {
    let metadata = path
        .symlink_metadata()
        .with_context(|| format!("inspect CentralD data entry {}", path.display()))?;
    if metadata.file_type().is_symlink() || metadata.is_file() {
        return std::fs::remove_file(path)
            .with_context(|| format!("remove CentralD data file {}", path.display()));
    }
    if metadata.is_dir() {
        return std::fs::remove_dir_all(path)
            .with_context(|| format!("remove CentralD data directory {}", path.display()));
    }
    bail!(
        "refusing to remove unsupported CentralD data entry type: {}",
        path.display()
    )
}

#[cfg(unix)]
async fn ensure_socket_inactive(socket: &Path) -> Result<()> {
    use tokio::net::UnixStream;

    if UnixStream::connect(socket).await.is_ok() {
        bail!(
            "a process is still accepting CentralD local-control connections at {}; stop it before --nuke",
            socket.display()
        );
    }
    Ok(())
}

#[cfg(not(unix))]
async fn ensure_socket_inactive(_socket: &Path) -> Result<()> {
    bail!("destructive server reset is supported only on Ubuntu Server hosts")
}

fn validate_regular_file(path: &Path, label: &str, required: bool) -> Result<()> {
    let metadata = match path.symlink_metadata() {
        Ok(metadata) => metadata,
        Err(error) if error.kind() == std::io::ErrorKind::NotFound && !required => return Ok(()),
        Err(error) => {
            return Err(error).with_context(|| format!("inspect {label} {}", path.display()));
        }
    };
    if metadata.file_type().is_symlink() || !metadata.is_file() {
        bail!("refusing non-regular or symbolic-link {label}: {}", path.display());
    }
    Ok(())
}

#[cfg(unix)]
fn validate_runtime_socket(path: &Path) -> Result<()> {
    use std::os::unix::fs::FileTypeExt;

    match path.symlink_metadata() {
        Ok(metadata) if metadata.file_type().is_socket() => Ok(()),
        Ok(_) => bail!("refusing non-socket runtime path {}", path.display()),
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => Ok(()),
        Err(error) => Err(error).with_context(|| format!("inspect runtime socket {}", path.display())),
    }
}

#[cfg(not(unix))]
fn validate_runtime_socket(_path: &Path) -> Result<()> {
    bail!("destructive server reset is supported only on Ubuntu Server hosts")
}

fn remove_regular_file_if_present(path: &Path, label: &str) -> Result<()> {
    let metadata = match path.symlink_metadata() {
        Ok(metadata) => metadata,
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => return Ok(()),
        Err(error) => {
            return Err(error).with_context(|| format!("inspect {label} {}", path.display()));
        }
    };
    if metadata.file_type().is_symlink() || !metadata.is_file() {
        bail!("refusing to remove non-regular {label}: {}", path.display());
    }
    std::fs::remove_file(path).with_context(|| format!("remove {label} {}", path.display()))?;
    Ok(())
}

#[cfg(unix)]
fn remove_runtime_socket_if_present(path: &Path) -> Result<()> {
    use std::os::unix::fs::FileTypeExt;

    match path.symlink_metadata() {
        Ok(metadata) => {
            if !metadata.file_type().is_socket() {
                bail!("refusing to remove non-socket runtime path {}", path.display());
            }
            std::fs::remove_file(path)
                .with_context(|| format!("remove runtime socket {}", path.display()))?;
        }
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => {}
        Err(error) => {
            return Err(error)
                .with_context(|| format!("inspect runtime socket {}", path.display()));
        }
    }
    // The locked server.lock is intentionally left in the root-owned runtime
    // directory. Removing an open lock file would permit a racing process to
    // create a new inode and evade the lock. systemd RuntimeDirectory cleanup
    // or the next daemon start may safely reuse it.
    Ok(())
}

#[cfg(not(unix))]
fn remove_runtime_socket_if_present(_path: &Path) -> Result<()> {
    Ok(())
}

fn collect_cleanup(result: Result<()>, failures: &mut Vec<String>) {
    if let Err(error) = result {
        failures.push(format!("{error:#}"));
    }
}

#[cfg(test)]
#[allow(clippy::unwrap_used)]
mod tests {
    use super::*;

    #[test]
    fn refuses_shallow_or_relative_data_roots() {
        assert!(validate_data_root(Path::new("centrald"), uuid::Uuid::nil()).is_err());
        assert!(validate_data_root(Path::new("/"), uuid::Uuid::nil()).is_err());
        assert!(validate_data_root(Path::new("/var/lib"), uuid::Uuid::nil()).is_err());
    }

    #[test]
    fn optional_missing_file_is_safe_but_required_missing_file_is_not() {
        let path = Path::new("/definitely-not-a-centrald-file");
        assert!(validate_regular_file(path, "test", false).is_ok());
        assert!(validate_regular_file(path, "test", true).is_err());
    }

    #[test]
    fn nuke_journal_is_adjacent_to_config() {
        assert_eq!(
            nuke_journal_path(Path::new("/etc/centrald/server.toml")).unwrap(),
            PathBuf::from("/etc/centrald/.server.toml.centrald-nuke-recovery.json")
        );
    }
}
