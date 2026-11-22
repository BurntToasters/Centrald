//! Embedded `SQLite` storage.
//!
//! One connection guarded by a mutex is plenty for a homelab-sized fleet and
//! keeps every write trivially serialized. Async callers go through
//! [`Db::call`], which runs the closure on the blocking pool.

use std::path::Path;
use std::sync::{Arc, Mutex, PoisonError};
use std::time::{SystemTime, UNIX_EPOCH};

use anyhow::{Context, Result, bail};
use rusqlite::Connection;

/// Bumped with every schema change; each step lives in [`MIGRATIONS`].
const SCHEMA_VERSION: i64 = 1;

#[allow(clippy::cast_possible_truncation, clippy::cast_sign_loss)]
const MIGRATIONS: [&str; SCHEMA_VERSION as usize] = [
    // 1: initial schema.
    "
    CREATE TABLE settings (
        key TEXT PRIMARY KEY,
        value TEXT NOT NULL
    ) STRICT;

    CREATE TABLE users (
        id TEXT PRIMARY KEY,
        username TEXT NOT NULL UNIQUE COLLATE NOCASE,
        password_hash TEXT NOT NULL,
        totp_secret TEXT,
        totp_enabled INTEGER NOT NULL DEFAULT 0,
        totp_last_step INTEGER NOT NULL DEFAULT 0,
        created_at INTEGER NOT NULL
    ) STRICT;

    CREATE TABLE sessions (
        token_hash BLOB PRIMARY KEY,
        user_id TEXT NOT NULL REFERENCES users(id) ON DELETE CASCADE,
        created_at INTEGER NOT NULL,
        last_seen_at INTEGER NOT NULL,
        expires_at INTEGER NOT NULL,
        address TEXT NOT NULL,
        user_agent TEXT NOT NULL
    ) STRICT;

    CREATE TABLE join_tokens (
        id TEXT PRIMARY KEY,
        name TEXT NOT NULL,
        secret_hash BLOB NOT NULL UNIQUE,
        created_by TEXT NOT NULL,
        created_at INTEGER NOT NULL,
        expires_at INTEGER NOT NULL,
        used_at INTEGER,
        device_id TEXT
    ) STRICT;

    CREATE TABLE devices (
        id TEXT PRIMARY KEY,
        name TEXT NOT NULL,
        token_hash BLOB NOT NULL,
        hostname TEXT NOT NULL,
        os_json TEXT NOT NULL,
        agent_version TEXT NOT NULL,
        allow_commands INTEGER NOT NULL,
        package_managed INTEGER NOT NULL DEFAULT 0,
        enrolled_at INTEGER NOT NULL,
        last_seen_at INTEGER,
        last_address TEXT,
        status_json TEXT,
        status_at INTEGER
    ) STRICT;

    CREATE TABLE metrics (
        device_id TEXT NOT NULL REFERENCES devices(id) ON DELETE CASCADE,
        at INTEGER NOT NULL,
        cpu REAL NOT NULL,
        memory REAL NOT NULL,
        load REAL,
        PRIMARY KEY (device_id, at)
    ) STRICT, WITHOUT ROWID;

    CREATE TABLE runs (
        id TEXT PRIMARY KEY,
        kind TEXT NOT NULL CHECK (kind IN ('command', 'action')),
        command TEXT NOT NULL,
        created_by TEXT NOT NULL,
        created_at INTEGER NOT NULL,
        timeout_seconds INTEGER NOT NULL
    ) STRICT;
    CREATE INDEX runs_created_idx ON runs (created_at DESC);

    CREATE TABLE run_targets (
        run_id TEXT NOT NULL REFERENCES runs(id) ON DELETE CASCADE,
        device_id TEXT NOT NULL,
        device_name TEXT NOT NULL,
        state TEXT NOT NULL,
        exit_code INTEGER,
        error TEXT,
        started_at INTEGER NOT NULL,
        finished_at INTEGER,
        output BLOB NOT NULL DEFAULT x'',
        truncated INTEGER NOT NULL DEFAULT 0,
        PRIMARY KEY (run_id, device_id)
    ) STRICT;
    CREATE INDEX run_targets_device_idx ON run_targets (device_id, started_at DESC);

    CREATE TABLE audit (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        at INTEGER NOT NULL,
        actor TEXT NOT NULL,
        action TEXT NOT NULL,
        target TEXT NOT NULL DEFAULT '',
        detail TEXT NOT NULL DEFAULT '',
        address TEXT NOT NULL DEFAULT ''
    ) STRICT;
    ",
];

#[derive(Clone)]
pub struct Db {
    connection: Arc<Mutex<Connection>>,
}

impl std::fmt::Debug for Db {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter.debug_struct("Db").finish_non_exhaustive()
    }
}

/// How a process may open the database.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum OpenMode {
    /// First start in an empty data directory: create and migrate.
    Create,
    /// The server on an existing install: must hold a schema; migrates
    /// forward and checks integrity.
    Server,
    /// Local tools next to a running server: never create or migrate.
    Tool,
    /// Like `Tool`, but read-only.
    ReadOnly,
}

impl Db {
    /// Opens the database as `mode` allows.
    pub fn open(path: &Path, mode: OpenMode) -> Result<Self> {
        use rusqlite::OpenFlags;
        let exists = path.exists();
        if mode == OpenMode::Create && exists {
            bail!(
                "{} already exists; refusing to create a new database",
                path.display()
            );
        }
        if mode != OpenMode::Create {
            let size = std::fs::metadata(path)
                .with_context(|| format!("the database {} is missing", path.display()))?
                .len();
            if size == 0 {
                bail!(
                    "the database {} is empty (damaged or truncated); restore it from backup",
                    path.display()
                );
            }
        }
        let flags = match mode {
            OpenMode::Create => OpenFlags::SQLITE_OPEN_READ_WRITE | OpenFlags::SQLITE_OPEN_CREATE,
            OpenMode::Server | OpenMode::Tool => OpenFlags::SQLITE_OPEN_READ_WRITE,
            OpenMode::ReadOnly => OpenFlags::SQLITE_OPEN_READ_ONLY,
        } | OpenFlags::SQLITE_OPEN_NO_MUTEX
            | OpenFlags::SQLITE_OPEN_URI;
        let mut connection = Connection::open_with_flags(path, flags)
            .with_context(|| format!("cannot open database {}", path.display()))?;
        connection.busy_timeout(std::time::Duration::from_secs(10))?;
        if mode != OpenMode::ReadOnly {
            connection.pragma_update(None, "journal_mode", "WAL")?;
            connection.pragma_update(None, "synchronous", "NORMAL")?;
        }
        connection.pragma_update(None, "foreign_keys", "ON")?;
        let current: i64 = connection
            .pragma_query_value(None, "user_version", |row| row.get(0))
            .with_context(|| format!("cannot read {}", path.display()))?;
        match mode {
            OpenMode::Create => migrate(&mut connection)?,
            OpenMode::Server => {
                if current == 0 {
                    bail!(
                        "the database {} holds no CentralD data (damaged, or its WAL file was lost); restore it from backup",
                        path.display()
                    );
                }
                let check: String =
                    connection.query_row("PRAGMA quick_check", [], |row| row.get(0))?;
                if check != "ok" {
                    bail!(
                        "the database {} is damaged ({check}); restore it from backup",
                        path.display()
                    );
                }
                migrate(&mut connection)?;
            }
            OpenMode::Tool | OpenMode::ReadOnly => {
                if current != SCHEMA_VERSION {
                    bail!(
                        "the database {} has schema {current} but this build uses {SCHEMA_VERSION}; restart the server (sudo systemctl restart centrald-server) so it can upgrade the database first",
                        path.display()
                    );
                }
            }
        }
        Ok(Self {
            connection: Arc::new(Mutex::new(connection)),
        })
    }

    /// Runs `work` against the connection on the blocking pool.
    pub async fn call<T, F>(&self, work: F) -> Result<T>
    where
        T: Send + 'static,
        F: FnOnce(&mut Connection) -> Result<T> + Send + 'static,
    {
        let connection = self.connection.clone();
        tokio::task::spawn_blocking(move || {
            let mut guard = connection.lock().unwrap_or_else(PoisonError::into_inner);
            work(&mut guard)
        })
        .await
        .context("database task failed")?
    }

    /// Synchronous variant for the local command-line tools.
    pub fn call_blocking<T>(&self, work: impl FnOnce(&mut Connection) -> Result<T>) -> Result<T> {
        let mut guard = self
            .connection
            .lock()
            .unwrap_or_else(PoisonError::into_inner);
        work(&mut guard)
    }
}

fn migrate(connection: &mut Connection) -> Result<()> {
    let current: i64 = connection.pragma_query_value(None, "user_version", |row| row.get(0))?;
    if current > SCHEMA_VERSION {
        bail!(
            "this database was created by a newer CentralD (schema {current}, this build understands {SCHEMA_VERSION}); upgrade the server"
        );
    }
    for version in current..SCHEMA_VERSION {
        let step = usize::try_from(version).context("schema version out of range")?;
        let transaction = connection.transaction()?;
        transaction.execute_batch(MIGRATIONS[step])?;
        transaction.pragma_update(None, "user_version", version + 1)?;
        transaction.commit()?;
    }
    Ok(())
}

/// Current time as Unix seconds.
pub fn now() -> i64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map_or(0, |elapsed| {
            i64::try_from(elapsed.as_secs()).unwrap_or(i64::MAX)
        })
}

pub fn get_setting(connection: &Connection, key: &str) -> Result<Option<String>> {
    use rusqlite::OptionalExtension;
    Ok(connection
        .query_row("SELECT value FROM settings WHERE key = ?1", [key], |row| {
            row.get(0)
        })
        .optional()?)
}

pub fn set_setting(connection: &Connection, key: &str, value: &str) -> Result<()> {
    connection.execute(
        "INSERT INTO settings (key, value) VALUES (?1, ?2)
         ON CONFLICT (key) DO UPDATE SET value = excluded.value",
        [key, value],
    )?;
    Ok(())
}

pub fn delete_setting(connection: &Connection, key: &str) -> Result<()> {
    connection.execute("DELETE FROM settings WHERE key = ?1", [key])?;
    Ok(())
}

/// Appends one audit record.
pub fn audit(
    connection: &Connection,
    actor: &str,
    action: &str,
    target: &str,
    detail: &str,
    address: &str,
) -> Result<()> {
    connection.execute(
        "INSERT INTO audit (at, actor, action, target, detail, address)
         VALUES (?1, ?2, ?3, ?4, ?5, ?6)",
        rusqlite::params![now(), actor, action, target, detail, address],
    )?;
    Ok(())
}
