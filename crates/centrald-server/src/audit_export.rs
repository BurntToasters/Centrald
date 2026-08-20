//! Verified, append-only export of the `PostgreSQL` audit hash chain.
//!
//! Each export batch reads the next contiguous window of `audit_entries` in
//! sequence order, verifies the `previous_hash`/`entry_hash` chaining against
//! the previous exported window, and writes one canonical record per line to
//! `centrald-audit-<from>-<to>.jsonl` under a root-owned directory. Files are
//! created exclusively and never rewritten, so the exported chain is
//! append-only and can be collected by an external system.

use std::path::{Path, PathBuf};

use anyhow::{Context, Result, bail};
use chrono::{DateTime, Utc};
use sha2::{Digest, Sha256};
use sqlx::PgPool;
use uuid::Uuid;

const EXPORT_FILE_PREFIX: &str = "centrald-audit-";
const EXPORT_FILE_SUFFIX: &str = ".jsonl";
const MAX_EXPORT_DIRECTORY_ENTRIES: usize = 4096;
const MAX_BATCH_ENTRIES: usize = 50_000;

#[derive(Debug)]
pub struct AuditExportSummary {
    pub exported_from: i64,
    pub exported_to: i64,
    pub exported_count: usize,
    pub tail_hash: String,
}

struct AuditRow {
    sequence: i64,
    id: Uuid,
    actor_id: Option<Uuid>,
    actor_label: String,
    action: String,
    target_id: Option<Uuid>,
    outcome: String,
    metadata: serde_json::Value,
    previous_hash: Option<Vec<u8>>,
    entry_hash: Vec<u8>,
    created_at: DateTime<Utc>,
}

/// Exports the next unexported window of the audit chain into `directory`.
///
/// # Errors
///
/// Returns an error when the directory is unsafe, the chain verification
/// fails, or the batch cannot be written durably.
pub async fn export_audit_chain(
    pool: &PgPool,
    directory: &Path,
    max_entries: usize,
) -> Result<AuditExportSummary> {
    let max_entries = max_entries.clamp(1, MAX_BATCH_ENTRIES);
    prepare_export_directory(directory)?;
    let (from_sequence, tail_hash) = existing_export_tail(directory)?;
    let rows = fetch_window(pool, from_sequence, max_entries).await?;
    if rows.is_empty() {
        return Ok(AuditExportSummary {
            exported_from: from_sequence,
            exported_to: from_sequence,
            exported_count: 0,
            tail_hash: tail_hash.unwrap_or_default(),
        });
    }
    verify_chain(&rows, from_sequence, tail_hash.as_deref())?;
    let first_sequence = rows.first().context("empty audit batch")?.sequence;
    let to_sequence = rows.last().context("empty audit batch")?.sequence;
    let last_hash = rows.last().context("empty audit batch")?.entry_hash.clone();
    let filename =
        format!("{EXPORT_FILE_PREFIX}{first_sequence}-{to_sequence}{EXPORT_FILE_SUFFIX}");
    let path = directory.join(&filename);
    let mut lines = Vec::with_capacity(rows.len() * 512);
    for row in &rows {
        // The exported line carries the canonical record plus the stored
        // entry hash as an additional, non-canonical field.
        let mut record = canonical_record(row);
        record
            .as_object_mut()
            .context("canonical audit record is not an object")?
            .insert(
                "entryHash".to_owned(),
                serde_json::Value::String(hex::encode(&row.entry_hash)),
            );
        lines.extend_from_slice(&serde_json::to_vec(&record)?);
        lines.push(b'\n');
    }
    centrald_common::secure_fs::write_new_file(&path, &lines, true)
        .with_context(|| format!("write audit export {}", path.display()))?;
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o600))?;
    }
    let _ = std::fs::File::open(directory)?.sync_all();
    Ok(AuditExportSummary {
        exported_from: from_sequence,
        exported_to: to_sequence,
        exported_count: rows.len(),
        tail_hash: hex::encode(last_hash),
    })
}

/// Returns the next sequence to export and the tail `entry_hash` of the newest
/// exported file (the chain link the next window must continue from).
fn existing_export_tail(directory: &Path) -> Result<(i64, Option<String>)> {
    let mut newest_to: Option<i64> = None;
    let mut newest_path: Option<PathBuf> = None;
    let mut entries = 0_usize;
    for entry in std::fs::read_dir(directory)
        .with_context(|| format!("read audit export directory {}", directory.display()))?
    {
        entries += 1;
        if entries > MAX_EXPORT_DIRECTORY_ENTRIES {
            bail!(
                "audit export directory contains more than {MAX_EXPORT_DIRECTORY_ENTRIES} entries"
            );
        }
        let entry = entry?;
        let name = entry.file_name().to_string_lossy().into_owned();
        if !name.starts_with(EXPORT_FILE_PREFIX) || !name.ends_with(EXPORT_FILE_SUFFIX) {
            continue;
        }
        let range = &name[EXPORT_FILE_PREFIX.len()..name.len() - EXPORT_FILE_SUFFIX.len()];
        let (_from, to) = parse_export_range(range)
            .with_context(|| format!("invalid audit export filename {name}"))?;
        if newest_to.is_none_or(|best| to > best) {
            newest_to = Some(to);
            newest_path = Some(entry.path());
        }
    }
    let Some(to) = newest_to else {
        return Ok((0, None));
    };
    let path = newest_path.context("newest audit export file is missing")?;
    let raw = std::fs::read(&path).with_context(|| format!("read {}", path.display()))?;
    let last_line = raw
        .split(|byte| *byte == b'\n')
        .rfind(|line| !line.iter().all(u8::is_ascii_whitespace))
        .context("newest audit export file is empty")?;
    let record: serde_json::Value =
        serde_json::from_slice(last_line).context("parse newest audit export tail record")?;
    let tail_hash = record
        .get("entryHash")
        .and_then(serde_json::Value::as_str)
        .context("newest audit export tail record has no entryHash")?
        .to_owned();
    Ok((to, Some(tail_hash)))
}

async fn fetch_window(pool: &PgPool, from_sequence: i64, limit: usize) -> Result<Vec<AuditRow>> {
    let rows = sqlx::query_as::<_, AuditRow>(
        "SELECT sequence, id, actor_id, actor_label, action, target_id, outcome, metadata, \
                previous_hash, entry_hash, created_at \
         FROM audit_entries WHERE sequence > $1 ORDER BY sequence LIMIT $2",
    )
    .bind(from_sequence)
    .bind(i64::try_from(limit).unwrap_or(i64::MAX))
    .fetch_all(pool)
    .await
    .context("read audit chain window")?;
    Ok(rows)
}

fn verify_chain(rows: &[AuditRow], from_sequence: i64, previous_tail: Option<&str>) -> Result<()> {
    if rows.first().context("empty audit window")?.sequence <= from_sequence {
        bail!("audit export window is not strictly after the previous export");
    }
    if let Some(previous_tail) = previous_tail {
        let link = rows
            .first()
            .context("empty audit window")?
            .previous_hash
            .as_ref()
            .map(hex::encode);
        if link.as_deref() != Some(previous_tail) {
            bail!(
                "audit chain gap or tampering: first record links to {}, previous export tail is {previous_tail}",
                link.as_deref().unwrap_or("<none>")
            );
        }
    }
    // Seed the chaining expectation from the previous export's tail hash so a
    // continuation window verifies against it inside the loop.
    let mut expected_previous: Option<Vec<u8>> = previous_tail
        .map(|tail| hex::decode(tail).context("previous export tail hash is not valid hex"))
        .transpose()?;
    for row in rows {
        let actual_previous = row.previous_hash.as_deref();
        if actual_previous != expected_previous.as_deref() {
            bail!(
                "audit chain broken at sequence {}: previous_hash does not chain to the prior entry",
                row.sequence
            );
        }
        let canonical = serde_json::to_vec(&canonical_record(row))
            .context("serialize canonical audit record")?;
        if Sha256::digest(&canonical).as_slice() != row.entry_hash {
            bail!(
                "audit entry {} fails hash verification: stored entry_hash does not match its canonical record",
                row.sequence
            );
        }
        expected_previous = Some(row.entry_hash.clone());
    }
    Ok(())
}

/// Rebuilds the exact canonical record object that was hashed at append time.
/// Timestamps are normalized to Postgres microsecond precision so read-back
/// rows reproduce the original canonical serialization.
fn canonical_record(row: &AuditRow) -> serde_json::Value {
    let created_at = normalized_micros(row.created_at);
    serde_json::json!({
        "id": row.id,
        "actorId": row.actor_id,
        "actorLabel": row.actor_label,
        "action": row.action,
        "targetId": row.target_id,
        "outcome": row.outcome,
        "metadata": row.metadata,
        "previousHash": row.previous_hash.as_ref().map(hex::encode),
        "createdAt": created_at,
    })
}

/// Truncates a timestamp to microsecond precision, matching `PostgreSQL`
/// `timestamptz` storage.
fn normalized_micros(value: DateTime<Utc>) -> DateTime<Utc> {
    DateTime::from_timestamp(value.timestamp(), value.timestamp_subsec_micros() * 1000)
        .unwrap_or(value)
}

fn prepare_export_directory(directory: &Path) -> Result<()> {
    if !directory.is_absolute() {
        bail!("audit export directory must be absolute");
    }
    centrald_common::secure_fs::validate_no_symlink_ancestors(directory)
        .map_err(|error| anyhow::anyhow!("{error}"))?;
    if let Ok(metadata) = directory.symlink_metadata() {
        if metadata.file_type().is_symlink() || !metadata.is_dir() {
            bail!("audit export directory is not a real directory");
        }
    } else {
        std::fs::create_dir(directory)
            .with_context(|| format!("create audit export directory {}", directory.display()))?;
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            std::fs::set_permissions(directory, std::fs::Permissions::from_mode(0o700))?;
        }
    }
    #[cfg(unix)]
    {
        use std::os::unix::fs::MetadataExt;
        use std::os::unix::fs::PermissionsExt;
        let metadata = directory.symlink_metadata()?;
        if metadata.uid() != 0 || metadata.permissions().mode() & 0o022 != 0 {
            bail!(
                "audit export directory must be root-owned and not group/world writable: {}",
                directory.display()
            );
        }
    }
    Ok(())
}

fn parse_export_range(range: &str) -> Result<(i64, i64)> {
    let (from, to) = range
        .split_once('-')
        .context("invalid audit export filename")?;
    let from: i64 = from.parse().context("invalid audit export from sequence")?;
    let to: i64 = to.parse().context("invalid audit export to sequence")?;
    if from > to || from <= 0 || to <= 0 {
        bail!("invalid audit export sequence range {from}-{to}");
    }
    Ok((from, to))
}

/// Serializes `AuditRow` for sqlx query-as.
impl sqlx::FromRow<'_, sqlx::postgres::PgRow> for AuditRow {
    fn from_row(row: &sqlx::postgres::PgRow) -> sqlx::Result<Self> {
        use sqlx::Row;
        Ok(Self {
            sequence: row.try_get("sequence")?,
            id: row.try_get("id")?,
            actor_id: row.try_get("actor_id")?,
            actor_label: row.try_get("actor_label")?,
            action: row.try_get("action")?,
            target_id: row.try_get("target_id")?,
            outcome: row.try_get("outcome")?,
            metadata: row.try_get("metadata")?,
            previous_hash: row.try_get("previous_hash")?,
            entry_hash: row.try_get("entry_hash")?,
            created_at: row.try_get("created_at")?,
        })
    }
}

#[cfg(test)]
#[allow(clippy::unwrap_used)]
mod tests {
    use super::*;

    fn row(sequence: i64, previous: Option<Vec<u8>>) -> AuditRow {
        AuditRow {
            sequence,
            id: Uuid::now_v7(),
            actor_id: None,
            actor_label: "server-local-root".into(),
            action: "test".into(),
            target_id: None,
            outcome: "succeeded".into(),
            metadata: serde_json::json!({}),
            previous_hash: previous,
            entry_hash: vec![0_u8; 32],
            created_at: Utc::now(),
        }
    }

    #[test]
    fn microsecond_normalization_is_stable() {
        let now = Utc::now();
        let normalized = normalized_micros(now);
        assert_eq!(normalized.timestamp_subsec_nanos() % 1000, 0);
        assert_eq!(normalized_micros(normalized), normalized);
    }

    #[test]
    fn chain_verification_accepts_a_valid_continuation_window() {
        let mut rows = vec![row(1, None), row(2, None)];
        for index in 0..rows.len() {
            if index > 0 {
                rows[index].previous_hash = Some(rows[index - 1].entry_hash.clone());
            }
            let hash = Sha256::digest(serde_json::to_vec(&canonical_record(&rows[index])).unwrap());
            rows[index].entry_hash = hash.to_vec();
        }
        // A second window chained to the first export's tail must verify.
        let tail = hex::encode(&rows[1].entry_hash);
        let mut continuation = vec![row(3, Some(rows[1].entry_hash.clone()))];
        continuation[0].entry_hash =
            Sha256::digest(serde_json::to_vec(&canonical_record(&continuation[0])).unwrap())
                .to_vec();
        assert!(verify_chain(&rows, 0, None).is_ok());
        assert!(verify_chain(&continuation, 2, Some(&tail)).is_ok());
    }

    #[test]
    fn chain_verification_rejects_a_broken_link() {
        let mut rows = vec![row(1, None), row(2, None)];
        rows[0].entry_hash =
            Sha256::digest(serde_json::to_vec(&canonical_record(&rows[0])).unwrap()).to_vec();
        rows[1].previous_hash = Some(vec![7_u8; 32]);
        rows[1].entry_hash =
            Sha256::digest(serde_json::to_vec(&canonical_record(&rows[1])).unwrap()).to_vec();
        assert!(verify_chain(&rows, 0, None).is_err());
        rows[1].previous_hash = Some(rows[0].entry_hash.clone());
        rows[1].entry_hash =
            Sha256::digest(serde_json::to_vec(&canonical_record(&rows[1])).unwrap()).to_vec();
        assert!(verify_chain(&rows, 0, None).is_ok());
        assert!(verify_chain(&rows, 0, Some("00".repeat(32).as_str())).is_err());
        // Tampering with a record after the chain was built must fail.
        rows[1].outcome = "tampered".into();
        assert!(verify_chain(&rows, 0, None).is_err());
    }

    #[test]
    fn export_filenames_start_at_sequence_one() {
        assert_eq!(parse_export_range("1-10").unwrap(), (1, 10));
        assert!(parse_export_range("0-10").is_err());
        assert!(parse_export_range("10-1").is_err());
        assert!(parse_export_range("abc-1").is_err());
    }
}
