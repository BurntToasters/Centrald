//! `PostgreSQL` migrate smoke for CI.
//!
//! Requires `CENTRALD_TEST_DATABASE_URL` pointing at a privileged maintenance
//! URL whose path is replaced with a unique database name (for example
//! `postgres://postgres:postgres@127.0.0.1:5432/postgres`). When unset, the
//! test returns immediately so ordinary `cargo test` stays offline-friendly.

use anyhow::{Context, Result, bail};
use centrald_server::db::{
    drop_owned_database, ensure_database_and_migrate, validate_database_url_policy,
};
use uuid::Uuid;

#[tokio::test]
async fn ensure_database_and_migrate_smoke() -> Result<()> {
    let Some(base_url) = std::env::var_os("CENTRALD_TEST_DATABASE_URL") else {
        eprintln!("skipping: CENTRALD_TEST_DATABASE_URL is unset");
        return Ok(());
    };
    let base_url = base_url
        .into_string()
        .map_err(|_| anyhow::anyhow!("CENTRALD_TEST_DATABASE_URL must be UTF-8"))?;
    validate_database_url_policy(&base_url).map_err(|error| anyhow::anyhow!("{error}"))?;
    let instance_id = Uuid::now_v7();
    let url = unique_database_url(&base_url, instance_id)?;
    let initialized = ensure_database_and_migrate(&url, 2, instance_id)
        .await
        .map_err(|error| anyhow::anyhow!("{error}"))
        .context("ensure_database_and_migrate")?;
    let count: i64 = sqlx::query_scalar(
        "SELECT COUNT(*) FROM information_schema.tables \
         WHERE table_schema = 'public' AND table_name = 'centrald_installation'",
    )
    .fetch_one(&initialized.pool)
    .await
    .context("query installation table")?;
    if count != 1 {
        bail!("expected centrald_installation table after migrate");
    }
    initialized.pool.close().await;
    drop_owned_database(&url, instance_id)
        .await
        .map_err(|error| anyhow::anyhow!("{error}"))
        .context("drop owned database")?;
    Ok(())
}

fn unique_database_url(base_url: &str, instance_id: Uuid) -> Result<String> {
    let mut parsed = url::Url::parse(base_url).context("parse test database URL")?;
    let name = format!("centrald_ci_{}", instance_id.as_simple());
    parsed.set_path(&format!("/{name}"));
    Ok(parsed.to_string())
}
