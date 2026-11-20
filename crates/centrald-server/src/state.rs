//! Process-wide state shared by every request handler.

use std::sync::Arc;

use tokio::sync::Semaphore;

use crate::auth::RateLimiter;
use crate::config::ServerConfig;
use crate::db::Db;
use crate::downloads::AgentBuilds;
use crate::hub::Hub;
use crate::tls::TlsState;

#[derive(Debug)]
pub struct AppState {
    pub config: ServerConfig,
    pub db: Db,
    pub tls: TlsState,
    pub hub: Arc<Hub>,
    pub builds: AgentBuilds,
    /// Login and first-run setup failures, keyed by address and username.
    pub login_limiter: RateLimiter,
    /// Enrollment and agent authentication failures, keyed by address.
    pub agent_limiter: RateLimiter,
    /// Argon2 is memory hard; cap how many hashes run at once.
    pub hash_permits: Semaphore,
}

pub type Shared = Arc<AppState>;

impl AppState {
    /// Runs a password hash or verification on the blocking pool under the
    /// shared concurrency cap.
    pub async fn hashing<T: Send + 'static>(
        &self,
        work: impl FnOnce() -> T + Send + 'static,
    ) -> anyhow::Result<T> {
        let _permit = self.hash_permits.acquire().await?;
        Ok(tokio::task::spawn_blocking(work).await?)
    }
}
