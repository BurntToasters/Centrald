use std::fs::{self, OpenOptions};
use std::io::Write;
use std::path::{Path, PathBuf};

use anyhow::{Context, Result, bail};
use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use sqlx::{PgPool, Postgres, Transaction};
use uuid::Uuid;

use centrald_common::secure_fs::{validate_no_symlink_ancestors, write_new_file};

use crate::config_lock::ConfigFileLock;

const AUDIT_LOCK_ID: i64 = 1_129_601_348;
const LOCAL_AUDIT_JOURNAL_NAME: &str = ".centrald-local-audit.jsonl";

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct LocalAuditRecord {
    id: Uuid,
    created_at: DateTime<Utc>,
    action: String,
    outcome: String,
    metadata: serde_json::Value,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct LocalAuditEnvelope {
    version: u32,
    record: LocalAuditRecord,
    checksum_sha256: String,
}

/// Returns the fixed journal pathname derived from the server configuration.
///
/// # Errors
///
/// Returns an error when the configuration path has no usable parent
/// directory.
pub fn journal_path(config_path: &Path) -> Result<PathBuf> {
    let parent = config_path
        .parent()
        .filter(|parent| !parent.as_os_str().is_empty())
        .context("server configuration path has no parent")?;
    Ok(parent.join(LOCAL_AUDIT_JOURNAL_NAME))
}

/// Appends a non-secret, durable server-local audit record. The journal is
/// intentionally usable while `PostgreSQL` is unavailable and is reconciled at
/// daemon startup.
///
/// # Errors
///
/// Returns an error when the journal path is unsafe or the record cannot be
/// serialized, appended, or synced.
pub fn record(
    config_path: &Path,
    action: &str,
    outcome: &str,
    metadata: serde_json::Value,
) -> Result<()> {
    let path = journal_path(config_path)?;
    validate_no_symlink_ancestors(&path)
        .with_context(|| format!("validate local audit journal path {}", path.display()))?;
    if let Ok(metadata) = path.symlink_metadata() {
        if metadata.file_type().is_symlink() || !metadata.is_file() {
            bail!("refusing unsafe local audit journal {}", path.display());
        }
        let _ = recover_torn_final_record(&path)?;
    }
    let record = LocalAuditRecord {
        id: Uuid::now_v7(),
        created_at: Utc::now(),
        action: action.to_owned(),
        outcome: outcome.to_owned(),
        metadata,
    };
    let envelope = LocalAuditEnvelope {
        version: 1,
        checksum_sha256: record_checksum(&record)?,
        record,
    };
    let mut line = serde_json::to_vec(&envelope)?;
    line.push(b'\n');
    let mut options = OpenOptions::new();
    options.create(true).append(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        const O_NOFOLLOW: i32 = 0o400000;
        const O_CLOEXEC: i32 = 0o2000000;
        options.mode(0o600).custom_flags(O_NOFOLLOW | O_CLOEXEC);
    }
    let mut file = options
        .open(&path)
        .with_context(|| format!("open local audit journal {}", path.display()))?;
    #[cfg(unix)]
    {
        use std::os::unix::fs::MetadataExt;
        let metadata = file.metadata().context("stat local audit journal")?;
        if !metadata.is_file() || metadata.nlink() != 1 {
            bail!(
                "local audit journal must be a single-linked regular file: {}",
                path.display()
            );
        }
        if metadata.mode() & 0o077 != 0 {
            bail!(
                "local audit journal must not be group/world accessible: {}",
                path.display()
            );
        }
    }
    file.write_all(&line)
        .with_context(|| format!("append local audit journal {}", path.display()))?;
    file.sync_data()
        .with_context(|| format!("sync local audit journal {}", path.display()))?;
    Ok(())
}

/// Reconciles the offline/local journal into the `PostgreSQL` hash chain. A
/// record ID is checked before insertion so a crash after database commit but
/// before journal deletion is idempotent.
///
/// # Errors
///
/// Returns an error when the journal is unsafe, a record fails validation, or
/// the database reconciliation fails.
pub async fn reconcile(pool: &PgPool, config_path: &Path) -> Result<usize> {
    let path = journal_path(config_path)?;
    if !path.exists() {
        return Ok(0);
    }
    let _lock = ConfigFileLock::acquire(config_path)?;
    let metadata = path
        .symlink_metadata()
        .with_context(|| format!("inspect local audit journal {}", path.display()))?;
    if metadata.file_type().is_symlink() || !metadata.is_file() {
        bail!("refusing unsafe local audit journal {}", path.display());
    }
    let raw = recover_torn_final_record(&path)?;
    let mut records = Vec::new();
    for (index, line) in raw.split(|byte| *byte == b'\n').enumerate() {
        if line.iter().all(u8::is_ascii_whitespace) {
            continue;
        }
        let envelope: LocalAuditEnvelope = serde_json::from_slice(line)
            .with_context(|| format!("parse committed local audit journal record {}", index + 1))?;
        if envelope.version != 1 {
            bail!(
                "unsupported local audit journal record version on line {}",
                index + 1
            );
        }
        let expected = record_checksum(&envelope.record)?;
        if envelope.checksum_sha256 != expected {
            bail!(
                "local audit journal checksum mismatch on committed record {}",
                index + 1
            );
        }
        records.push(envelope.record);
    }
    if records.is_empty() {
        fs::remove_file(&path)?;
        return Ok(0);
    }

    let mut transaction = pool.begin().await?;
    sqlx::query("SELECT pg_advisory_xact_lock($1)")
        .bind(AUDIT_LOCK_ID)
        .execute(&mut *transaction)
        .await?;
    let mut inserted = 0_usize;
    for record in records {
        let exists: bool =
            sqlx::query_scalar("SELECT EXISTS(SELECT 1 FROM audit_entries WHERE id = $1)")
                .bind(record.id)
                .fetch_one(&mut *transaction)
                .await?;
        if exists {
            continue;
        }
        append_record(&mut transaction, &record).await?;
        inserted += 1;
    }
    transaction.commit().await?;
    fs::remove_file(&path)
        .with_context(|| format!("remove reconciled local audit journal {}", path.display()))?;
    if let Some(parent) = path.parent() {
        fs::File::open(parent)?.sync_all()?;
    }
    Ok(inserted)
}

fn record_checksum(record: &LocalAuditRecord) -> Result<String> {
    Ok(hex::encode(Sha256::digest(serde_json::to_vec(record)?)))
}

fn recover_torn_final_record(path: &Path) -> Result<Vec<u8>> {
    let raw =
        fs::read(path).with_context(|| format!("read local audit journal {}", path.display()))?;
    if raw.is_empty() || raw.last() == Some(&b'\n') {
        return Ok(raw);
    }

    let complete_len = raw
        .iter()
        .rposition(|byte| *byte == b'\n')
        .map_or(0, |index| index + 1);
    let tail = &raw[complete_len..];
    let parent = path.parent().context("local audit journal has no parent")?;
    let quarantine = parent.join(format!(".centrald-local-audit-torn-{}.bin", Uuid::now_v7()));
    write_new_file(&quarantine, tail, true).with_context(|| {
        format!(
            "preserve torn final local audit record at {}",
            quarantine.display()
        )
    })?;

    let mut options = OpenOptions::new();
    options.write(true).truncate(true);
    let mut file = options
        .open(path)
        .with_context(|| format!("truncate torn local audit tail in {}", path.display()))?;
    file.write_all(&raw[..complete_len])?;
    file.sync_all()?;
    fs::File::open(parent)?.sync_all()?;
    tracing::warn!(
        path = %path.display(),
        quarantine = %quarantine.display(),
        bytes = tail.len(),
        "preserved a torn final local-audit record and continued with committed records"
    );
    Ok(raw[..complete_len].to_vec())
}

async fn append_record(
    transaction: &mut Transaction<'_, Postgres>,
    record: &LocalAuditRecord,
) -> Result<()> {
    let previous_hash: Option<Vec<u8>> =
        sqlx::query_scalar("SELECT entry_hash FROM audit_entries ORDER BY sequence DESC LIMIT 1")
            .fetch_optional(&mut **transaction)
            .await?;
    // Normalize to Postgres microsecond precision so read-back rows reproduce
    // the canonical bytes during verified audit export.
    let created_at = DateTime::from_timestamp(
        record.created_at.timestamp(),
        record.created_at.timestamp_subsec_micros() * 1000,
    )
    .unwrap_or(record.created_at);
    let canonical = serde_json::to_vec(&serde_json::json!({
        "id": record.id,
        "actorId": null,
        "actorLabel": "server-local-root",
        "action": &record.action,
        "targetId": null,
        "outcome": &record.outcome,
        "metadata": &record.metadata,
        "previousHash": previous_hash.as_ref().map(hex::encode),
        "createdAt": created_at,
    }))?;
    let entry_hash = Sha256::digest(&canonical).to_vec();
    sqlx::query(
        "INSERT INTO audit_entries \
         (id, actor_id, actor_label, action, target_id, outcome, metadata, previous_hash, \
          entry_hash, created_at) VALUES ($1, NULL, $2, $3, NULL, $4, $5, $6, $7, $8)",
    )
    .bind(record.id)
    .bind("server-local-root")
    .bind(&record.action)
    .bind(&record.outcome)
    .bind(&record.metadata)
    .bind(previous_hash)
    .bind(entry_hash)
    .bind(created_at)
    .execute(&mut **transaction)
    .await?;
    Ok(())
}
