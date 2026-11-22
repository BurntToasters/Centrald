//! Process-wide state shared by every request handler.

use std::sync::Arc;

use axum::http::StatusCode;
use tokio::sync::Semaphore;

use crate::auth::RateLimiter;
use crate::config::ServerConfig;
use crate::db::Db;
use crate::downloads::AgentBuilds;
use crate::error::{ApiError, ApiResult};
use crate::hub::Hub;
use crate::tls::TlsState;

/// Argon2 is memory hard (19 MiB each); this many run at once.
pub const HASH_PARALLEL: usize = 2;
/// Hashes running plus waiting; beyond this, sign-ins get 503 at once.
pub const HASH_QUEUE: usize = 32;

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
    /// Caps how many hashes run at once.
    pub hash_permits: Arc<Semaphore>,
    /// Caps how many hashes may be running or waiting.
    pub hash_queue: Arc<Semaphore>,
}

impl AppState {
    pub fn new_hash_limits() -> (Arc<Semaphore>, Arc<Semaphore>) {
        (
            Arc::new(Semaphore::new(HASH_PARALLEL)),
            Arc::new(Semaphore::new(HASH_QUEUE)),
        )
    }
}

pub type Shared = Arc<AppState>;

impl AppState {
    /// Runs a password hash or verification on the blocking pool under the
    /// shared concurrency cap.
    ///
    /// The work runs on its own task and holds its permits until it ends,
    /// so a client that hangs up neither cancels it nor frees a permit while
    /// the hash still runs.
    pub async fn hashing<T: Send + 'static>(
        &self,
        work: impl FnOnce() -> T + Send + 'static,
    ) -> ApiResult<T> {
        let queued = self.hash_queue.clone().try_acquire_owned().map_err(|_| {
            ApiError::new(
                StatusCode::SERVICE_UNAVAILABLE,
                "The server is busy checking passwords. Try again in a moment.",
            )
        })?;
        let permits = self.hash_permits.clone();
        let task = tokio::spawn(async move {
            let permit = permits.acquire_owned().await?;
            let result = tokio::task::spawn_blocking(move || {
                let _held = (permit, queued);
                work()
            })
            .await?;
            anyhow::Ok(result)
        });
        Ok(task.await.map_err(anyhow::Error::from)??)
    }
}
