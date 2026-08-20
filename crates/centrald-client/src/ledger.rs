//! Durable exactly-once ledger for privileged broker operations.
//!
//! The broker records each job before executing it and appends the result
//! after execution. When the client daemon is destroyed mid-operation (client
//! service restart) or reconnects after a crash, the server re-dispatches the
//! same job and the broker replays the recorded result instead of executing
//! twice. An `Executing` record left by a crashed broker fails closed: the
//! outcome is unknown and the job must be retried as a new job by the
//! operator.
//!
//! The ledger is a root-owned, checksummed JSONL journal with the same
//! torn-tail recovery contract as the server's local audit journal. Records
//! older than the bounded retention window are pruned so the file cannot grow
//! without bound.

use std::fs::{self, OpenOptions};
use std::io::Write;
use std::path::{Path, PathBuf};

use anyhow::{Context, Result, bail};
use centrald_common::grant::GrantOperation;
use centrald_common::secure_fs::{validate_no_symlink_ancestors, write_new_file};
use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use uuid::Uuid;

use centrald_platform::broker::BrokerResponse;

const LEDGER_VERSION: u32 = 1;
const LEDGER_FILE_NAME: &str = "completed-jobs.jsonl";
/// Records are retained long enough to cover the maximum job TTL (7 days).
const RECORD_RETENTION: chrono::Duration = chrono::Duration::days(7);
/// An interrupted execution marker expires after this window; a later request
/// for the same job is then rejected as interrupted rather than re-executed.
/// The window exceeds the 900s command timeout so a legitimately running
/// command is never mislabeled as interrupted.
const EXECUTING_MARKER_TTL: chrono::Duration = chrono::Duration::minutes(30);
const MAX_LEDGER_BYTES: u64 = 4 * 1024 * 1024;
/// Interrupted markers are retained for fail-closed semantics; compaction
/// keeps at most this many of the newest markers so the file stays bounded.
const MAX_RETAINED_INTERRUPTED_MARKERS: usize = 32;
/// A replayed response is forwarded into a single bounded job event, so the
/// recorded output must respect the job-event limit.
const MAX_RECORDED_OUTPUT_BYTES: usize = 64 * 1024;

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
enum LedgerState {
    Executing,
    Completed,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct LedgerRecord {
    job_id: Uuid,
    operation: GrantOperation,
    state: LedgerState,
    response: Option<BrokerResponse>,
    expires_at: DateTime<Utc>,
    recorded_at: DateTime<Utc>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct LedgerEnvelope {
    version: u32,
    record: LedgerRecord,
    checksum_sha256: String,
}

#[derive(Debug, Clone)]
pub(crate) enum LedgerLookup {
    /// The job was recorded but never completed. `interrupted` is true when
    /// the executing marker has expired, meaning the previous broker process
    /// could not have finished and its outcome is unknown.
    Executing {
        interrupted: bool,
    },
    Completed(BrokerResponse),
}

/// The root-owned durable broker ledger for one machine.
#[derive(Debug)]
pub struct BrokerLedger {
    path: PathBuf,
}

impl BrokerLedger {
    /// Opens the ledger at the fixed broker state path.
    ///
    /// # Errors
    ///
    /// Returns an error when the state root is unsafe.
    pub fn open(state_dir: &Path) -> Result<Self> {
        validate_no_symlink_ancestors(state_dir)
            .with_context(|| format!("validate broker ledger directory {}", state_dir.display()))?;
        if let Ok(metadata) = state_dir.symlink_metadata() {
            if metadata.file_type().is_symlink() || !metadata.is_dir() {
                bail!("broker ledger directory is not a real directory");
            }
        } else {
            fs::create_dir(state_dir).with_context(|| {
                format!("create broker ledger directory {}", state_dir.display())
            })?;
            #[cfg(unix)]
            {
                use std::os::unix::fs::PermissionsExt;
                fs::set_permissions(state_dir, fs::Permissions::from_mode(0o700))?;
            }
        }
        let path = state_dir.join(LEDGER_FILE_NAME);
        validate_no_symlink_ancestors(&path)
            .with_context(|| format!("validate broker ledger path {}", path.display()))?;
        Ok(Self { path })
    }

    fn consumed_grants_path(&self) -> PathBuf {
        self.path.with_file_name("consumed-grants.jsonl")
    }

    /// Returns whether this grant identifier was already recorded as consumed.
    ///
    /// # Errors
    ///
    /// Returns an error when the consumed-grant journal is corrupt.
    pub fn grant_was_consumed(&self, grant_id: Uuid, now: DateTime<Utc>) -> Result<bool> {
        Ok(self
            .load_consumed_grants(now)?
            .iter()
            .any(|(id, _)| *id == grant_id))
    }

    /// Records a consumed grant identifier until its signed expiry.
    ///
    /// # Errors
    ///
    /// Returns an error when the journal cannot be written.
    pub fn record_consumed_grant(&self, grant_id: Uuid, expires_at: DateTime<Utc>) -> Result<()> {
        let path = self.consumed_grants_path();
        validate_no_symlink_ancestors(&path)
            .with_context(|| format!("validate consumed-grant journal {}", path.display()))?;
        let payload = serde_json::json!({
            "grant_id": grant_id,
            "expires_at": expires_at,
        });
        let encoded = serde_json::to_vec(&payload)?;
        let checksum = hex::encode(Sha256::digest(&encoded));
        let mut line = serde_json::to_vec(&serde_json::json!({
            "record": payload,
            "checksum_sha256": checksum,
        }))?;
        line.push(b'\n');
        let mut options = OpenOptions::new();
        options.create(true).append(true);
        #[cfg(unix)]
        {
            use std::os::unix::fs::OpenOptionsExt;
            options.mode(0o600);
        }
        let mut file = options
            .open(&path)
            .with_context(|| format!("open consumed-grant journal {}", path.display()))?;
        file.write_all(&line)
            .with_context(|| format!("append consumed-grant journal {}", path.display()))?;
        file.sync_data()
            .with_context(|| format!("sync consumed-grant journal {}", path.display()))?;
        Ok(())
    }

    /// Loads unexpired consumed grant identifiers.
    ///
    /// # Errors
    ///
    /// Returns an error when the journal is corrupt.
    pub fn load_consumed_grants(&self, now: DateTime<Utc>) -> Result<Vec<(Uuid, DateTime<Utc>)>> {
        let path = self.consumed_grants_path();
        if !path.exists() {
            return Ok(Vec::new());
        }
        let raw = fs::read(&path)
            .with_context(|| format!("read consumed-grant journal {}", path.display()))?;
        let mut grants = Vec::new();
        for (index, line) in raw.split(|byte| *byte == b'\n').enumerate() {
            if line.iter().all(u8::is_ascii_whitespace) {
                continue;
            }
            let envelope: serde_json::Value = serde_json::from_slice(line)
                .with_context(|| format!("parse consumed-grant journal record {}", index + 1))?;
            let record = envelope
                .get("record")
                .context("consumed-grant journal record missing payload")?;
            let checksum = envelope
                .get("checksum_sha256")
                .and_then(serde_json::Value::as_str)
                .context("consumed-grant journal record missing checksum")?;
            let encoded = serde_json::to_vec(record)?;
            if checksum != hex::encode(Sha256::digest(&encoded)) {
                bail!(
                    "consumed-grant journal checksum mismatch on record {}",
                    index + 1
                );
            }
            let grant_id: Uuid = serde_json::from_value(
                record
                    .get("grant_id")
                    .cloned()
                    .context("consumed-grant journal record missing grant_id")?,
            )?;
            let expires_at: DateTime<Utc> = serde_json::from_value(
                record
                    .get("expires_at")
                    .cloned()
                    .context("consumed-grant journal record missing expires_at")?,
            )?;
            if expires_at > now {
                grants.push((grant_id, expires_at));
            }
        }
        Ok(grants)
    }

    /// Appends a durable `Executing` marker for a job. Fails when a record for
    /// the job already exists (a duplicate dispatch, or an interrupted
    /// execution whose outcome is unknown).
    ///
    /// # Errors
    ///
    /// Returns an error when the ledger cannot be written durably or the job
    /// already has a record.
    pub fn mark_executing(
        &self,
        job_id: Uuid,
        operation: GrantOperation,
        now: DateTime<Utc>,
    ) -> Result<()> {
        if self.lookup(job_id, now)?.is_some() {
            bail!("job already has a broker ledger record");
        }
        self.append(LedgerRecord {
            job_id,
            operation,
            state: LedgerState::Executing,
            response: None,
            expires_at: now + EXECUTING_MARKER_TTL,
            recorded_at: now,
        })
    }

    /// Replaces an `Executing` marker with the durable completion record.
    ///
    /// # Errors
    ///
    /// Returns an error when the ledger cannot be written durably.
    pub fn record_completed(
        &self,
        job_id: Uuid,
        response: &BrokerResponse,
        now: DateTime<Utc>,
    ) -> Result<()> {
        if response.output.len() > MAX_RECORDED_OUTPUT_BYTES {
            bail!("broker response output exceeds the recorded bound");
        }
        let operation = match self.lookup(job_id, now)? {
            Some(LedgerLookup::Executing { .. } | LedgerLookup::Completed(_)) => {
                self.latest_operation(job_id, now)?
            }
            None => bail!("cannot complete a job without an executing marker"),
        };
        self.append(LedgerRecord {
            job_id,
            operation,
            state: LedgerState::Completed,
            response: Some(response.clone()),
            expires_at: now + RECORD_RETENTION,
            recorded_at: now,
        })
    }

    /// Returns the current ledger record for a job, pruning expired records.
    ///
    /// # Errors
    ///
    /// Returns an error when the ledger file is corrupt or unreadable.
    pub(crate) fn lookup(&self, job_id: Uuid, now: DateTime<Utc>) -> Result<Option<LedgerLookup>> {
        if !self.path.exists() {
            return Ok(None);
        }
        let records = self.read_committed(now)?;
        let mut found = None;
        for record in records.iter().rev() {
            if record.job_id != job_id {
                continue;
            }
            found = Some(match &record.state {
                LedgerState::Executing => LedgerLookup::Executing {
                    interrupted: record.expires_at <= now,
                },
                LedgerState::Completed => LedgerLookup::Completed(
                    record
                        .response
                        .clone()
                        .context("completed ledger record is missing its response")?,
                ),
            });
            break;
        }
        Ok(found)
    }

    fn latest_operation(&self, job_id: Uuid, now: DateTime<Utc>) -> Result<GrantOperation> {
        let records = self.read_committed(now)?;
        records
            .iter()
            .rfind(|record| record.job_id == job_id)
            .map(|record| record.operation.clone())
            .context("ledger record for job is missing")
    }

    fn append(&self, record: LedgerRecord) -> Result<()> {
        self.compact_if_needed()?;
        let envelope = LedgerEnvelope {
            version: LEDGER_VERSION,
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
            options.mode(0o600);
        }
        let mut file = options
            .open(&self.path)
            .with_context(|| format!("open broker ledger {}", self.path.display()))?;
        let metadata = file
            .metadata()
            .with_context(|| format!("inspect broker ledger {}", self.path.display()))?;
        if metadata.file_type().is_symlink() || !metadata.is_file() {
            bail!(
                "broker ledger is not a regular file: {}",
                self.path.display()
            );
        }
        #[cfg(unix)]
        {
            use std::os::unix::fs::MetadataExt;
            if metadata.uid() != 0 {
                bail!("broker ledger must be root-owned");
            }
        }
        file.write_all(&line)
            .with_context(|| format!("append broker ledger {}", self.path.display()))?;
        file.sync_data()
            .with_context(|| format!("sync broker ledger {}", self.path.display()))?;
        if metadata.len() == 0 {
            // First-ever record: sync the directory entry so the ledger cannot
            // vanish on power loss immediately after creation.
            if let Some(_parent) = self.path.parent() {
                #[cfg(unix)]
                std::fs::File::open(_parent)?.sync_all()?;
            }
        }
        Ok(())
    }

    /// Reads committed records, quarantining a torn final record exactly like
    /// the local audit journal. Expired `Executing` markers are retained so a
    /// later request reports them as interrupted (fail closed); only completed
    /// records are pruned by their retention window.
    fn read_committed(&self, now: DateTime<Utc>) -> Result<Vec<LedgerRecord>> {
        let raw = recover_torn_final_record(&self.path)?;
        let mut records = Vec::new();
        for (index, line) in raw.split(|byte| *byte == b'\n').enumerate() {
            if line.iter().all(u8::is_ascii_whitespace) {
                continue;
            }
            let envelope: LedgerEnvelope = serde_json::from_slice(line)
                .with_context(|| format!("parse broker ledger record {}", index + 1))?;
            if envelope.version != LEDGER_VERSION {
                bail!("unsupported broker ledger version on line {}", index + 1);
            }
            if envelope.checksum_sha256 != record_checksum(&envelope.record)? {
                bail!("broker ledger checksum mismatch on record {}", index + 1);
            }
            if envelope.record.expires_at > now
                || matches!(envelope.record.state, LedgerState::Executing)
            {
                records.push(envelope.record);
            }
        }
        Ok(records)
    }

    /// Rewrites the ledger when it exceeds the hard size bound, retaining only
    /// the latest committed record per job within the retention window.
    fn compact_if_needed(&self) -> Result<()> {
        let Ok(metadata) = self.path.symlink_metadata() else {
            return Ok(());
        };
        if metadata.file_type().is_symlink() || !metadata.is_file() {
            bail!(
                "broker ledger is not a regular file: {}",
                self.path.display()
            );
        }
        if metadata.len() <= MAX_LEDGER_BYTES {
            return Ok(());
        }
        let now = Utc::now();
        let records = self.read_committed(now)?;
        let mut latest: std::collections::HashMap<Uuid, LedgerRecord> =
            std::collections::HashMap::new();
        for record in records {
            latest.insert(record.job_id, record);
        }
        // Interrupted markers are retained for fail-closed semantics but are
        // bounded to the newest few so a crash storm cannot grow the ledger.
        let mut interrupted: Vec<LedgerRecord> = latest
            .values()
            .filter(|record| record.state == LedgerState::Executing)
            .cloned()
            .collect();
        interrupted.sort_by_key(|record| record.recorded_at);
        interrupted.reverse();
        interrupted.truncate(MAX_RETAINED_INTERRUPTED_MARKERS);
        let interrupted_ids: std::collections::HashSet<Uuid> =
            interrupted.iter().map(|record| record.job_id).collect();
        latest.retain(|_, record| {
            record.state != LedgerState::Executing || interrupted_ids.contains(&record.job_id)
        });
        let mut lines = Vec::new();
        for record in latest.into_values() {
            let envelope = LedgerEnvelope {
                version: LEDGER_VERSION,
                checksum_sha256: record_checksum(&record)?,
                record,
            };
            let mut line = serde_json::to_vec(&envelope)?;
            line.push(b'\n');
            lines.push(line);
        }
        let parent = self.path.parent().context("broker ledger has no parent")?;
        let staged = parent.join(format!(
            ".centrald-broker-ledger.compact-{}",
            Uuid::now_v7()
        ));
        write_new_file(&staged, &lines.concat(), true)
            .with_context(|| format!("stage compacted broker ledger at {}", staged.display()))?;
        fs::rename(&staged, &self.path)
            .with_context(|| format!("replace compacted broker ledger {}", self.path.display()))?;
        #[cfg(unix)]
        fs::File::open(parent)?.sync_all()?;
        Ok(())
    }
}

fn record_checksum(record: &LedgerRecord) -> Result<String> {
    Ok(hex::encode(Sha256::digest(serde_json::to_vec(record)?)))
}

fn recover_torn_final_record(path: &Path) -> Result<Vec<u8>> {
    let raw = fs::read(path).with_context(|| format!("read broker ledger {}", path.display()))?;
    if raw.is_empty() || raw.last() == Some(&b'\n') {
        return Ok(raw);
    }
    let complete_len = raw
        .iter()
        .rposition(|byte| *byte == b'\n')
        .map_or(0, |index| index + 1);
    let tail = &raw[complete_len..];
    let parent = path.parent().context("broker ledger has no parent")?;
    let quarantine = parent.join(format!(
        ".centrald-broker-ledger-torn-{}.bin",
        Uuid::now_v7()
    ));
    write_new_file(&quarantine, tail, true).with_context(|| {
        format!(
            "preserve torn final broker ledger record at {}",
            quarantine.display()
        )
    })?;
    let mut options = OpenOptions::new();
    options.write(true).truncate(true);
    let mut file = options
        .open(path)
        .with_context(|| format!("truncate torn broker ledger tail in {}", path.display()))?;
    file.write_all(&raw[..complete_len])?;
    file.sync_all()?;
    #[cfg(unix)]
    fs::File::open(parent)?.sync_all()?;
    tracing::warn!(
        path = %path.display(),
        quarantine = %quarantine.display(),
        bytes = tail.len(),
        "preserved a torn final broker-ledger record and continued with committed records"
    );
    Ok(raw[..complete_len].to_vec())
}

#[cfg(test)]
#[allow(clippy::unwrap_used)]
mod tests {
    use std::fs;

    use centrald_platform::broker::MAX_WIRE_RESPONSE_BYTES;

    use super::*;

    fn temp_ledger() -> (std::path::PathBuf, BrokerLedger) {
        let root = std::env::temp_dir().join(format!("centrald-ledger-{}", Uuid::now_v7()));
        let ledger = BrokerLedger::open(&root).unwrap();
        (root, ledger)
    }

    fn response(output: &[u8]) -> BrokerResponse {
        BrokerResponse {
            success: true,
            output: output.to_vec(),
            exit_code: 0,
        }
    }

    #[test]
    fn records_execution_then_completion() {
        let (_root, ledger) = temp_ledger();
        let now = Utc::now();
        let job = Uuid::now_v7();
        ledger
            .mark_executing(job, GrantOperation::RestartClientService, now)
            .unwrap();
        assert!(matches!(
            ledger.lookup(job, now).unwrap().unwrap(),
            LedgerLookup::Executing { interrupted: false }
        ));
        ledger.record_completed(job, &response(b"ok"), now).unwrap();
        assert!(matches!(
            ledger.lookup(job, now).unwrap().unwrap(),
            LedgerLookup::Completed(_)
        ));
    }

    #[test]
    fn replays_the_recorded_result_after_reopen() {
        let (root, ledger) = temp_ledger();
        let now = Utc::now();
        let job = Uuid::now_v7();
        ledger
            .mark_executing(job, GrantOperation::RestartClientService, now)
            .unwrap();
        ledger
            .record_completed(job, &response(b"restarted"), now)
            .unwrap();
        let reopened = BrokerLedger::open(&root).unwrap();
        let LedgerLookup::Completed(recorded) = reopened.lookup(job, now).unwrap().unwrap() else {
            panic!("expected completed record");
        };
        assert_eq!(recorded.output, b"restarted");
    }

    #[test]
    fn rejects_duplicate_executing_markers() {
        let (_root, ledger) = temp_ledger();
        let now = Utc::now();
        let job = Uuid::now_v7();
        ledger
            .mark_executing(job, GrantOperation::RestartClientService, now)
            .unwrap();
        assert!(
            ledger
                .mark_executing(job, GrantOperation::RestartClientService, now)
                .is_err()
        );
    }

    #[test]
    fn expired_interrupted_marker_fails_closed() {
        let (_root, ledger) = temp_ledger();
        let now = Utc::now();
        let job = Uuid::now_v7();
        ledger
            .mark_executing(job, GrantOperation::RestartMachine, now)
            .unwrap();
        let later = now + chrono::Duration::hours(1);
        assert!(matches!(
            ledger.lookup(job, later).unwrap().unwrap(),
            LedgerLookup::Executing { interrupted: true }
        ));
    }

    #[test]
    fn torn_final_record_is_quarantined() {
        let (root, ledger) = temp_ledger();
        let now = Utc::now();
        let job = Uuid::now_v7();
        ledger
            .mark_executing(job, GrantOperation::RestartClientService, now)
            .unwrap();
        let mut raw = fs::read(&ledger.path).unwrap();
        raw.extend_from_slice(b"{\"torn");
        fs::write(&ledger.path, raw).unwrap();
        assert!(matches!(
            ledger.lookup(job, now).unwrap().unwrap(),
            LedgerLookup::Executing { interrupted: false }
        ));
        let quarantined: Vec<_> = fs::read_dir(&root)
            .unwrap()
            .filter_map(Result::ok)
            .filter(|entry| {
                entry
                    .file_name()
                    .to_string_lossy()
                    .starts_with(".centrald-broker-ledger-torn-")
            })
            .collect();
        assert_eq!(quarantined.len(), 1);
        let _ = fs::remove_dir_all(&root);
    }

    #[test]
    fn record_output_respects_the_job_event_bound() {
        let (_root, ledger) = temp_ledger();
        let now = Utc::now();
        let job = Uuid::now_v7();
        ledger
            .mark_executing(job, GrantOperation::CheckOsUpdates, now)
            .unwrap();
        let oversized = vec![b'x'; MAX_RECORDED_OUTPUT_BYTES + 1];
        assert!(
            ledger
                .record_completed(job, &response(&oversized), now)
                .is_err()
        );
        assert!(ledger.record_completed(job, &response(b"ok"), now).is_ok());
    }

    #[test]
    fn recorded_response_cannot_exceed_the_wire_bound() {
        let (_root, ledger) = temp_ledger();
        let now = Utc::now();
        let job = Uuid::now_v7();
        ledger
            .mark_executing(job, GrantOperation::CheckOsUpdates, now)
            .unwrap();
        let oversized = vec![b'x'; MAX_WIRE_RESPONSE_BYTES + 1];
        assert!(
            ledger
                .record_completed(job, &response(&oversized), now)
                .is_err()
        );
    }
}
