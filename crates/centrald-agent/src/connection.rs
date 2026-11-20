//! The long-lived connection to the server, with reconnects.

use std::sync::{Arc, Mutex, PoisonError};
use std::time::Duration;

use anyhow::{Context, Result, anyhow, bail};
use centrald_proto::PROTOCOL_VERSION;
use centrald_proto::limits::MAX_MESSAGE_BYTES;
use centrald_proto::wire::{AgentMessage, Hello, ServerMessage};
use futures_util::{SinkExt, StreamExt};
use tokio::sync::mpsc;
use tokio_tungstenite::tungstenite::client::IntoClientRequest;
use tokio_tungstenite::tungstenite::protocol::WebSocketConfig;
use tokio_tungstenite::tungstenite::{self, Message};

use crate::config::AgentConfig;
use crate::exec::Executor;
use crate::status::{Collector, SharedUpdates, check_updates, hostname, os_info};
use crate::terminal::Terminals;

/// A server that sends nothing (it pings every 30 s) for this long is gone.
const SILENCE_LIMIT: Duration = Duration::from_secs(90);
const MAX_BACKOFF: Duration = Duration::from_secs(60);
/// Retry delay after the server rejects this device's credential.
const REJECTED_BACKOFF: Duration = Duration::from_secs(10 * 60);
const UPDATE_CHECK_INTERVAL: Duration = Duration::from_secs(6 * 60 * 60);

enum Ended {
    /// The session ran and then closed; reconnect soon.
    Closed { lasted: Duration },
    /// The server does not know this device any more.
    Rejected,
}

/// Runs forever, keeping one connection to the first reachable server.
pub async fn run(config: AgentConfig) -> Result<()> {
    let fingerprint = config.fingerprint()?;
    let updates: SharedUpdates = Arc::new(Mutex::new(None));
    tokio::spawn(update_checker(updates.clone()));
    let executor = Executor::new(config.allow_commands, updates.clone());
    let terminals = Terminals::new(config.allow_commands);
    let collector = Arc::new(Mutex::new(Collector::new(updates.clone())));

    tracing::info!(
        servers = ?config.servers,
        monitor_only = !config.allow_commands,
        "CentralD agent {} starting",
        centrald_proto::VERSION
    );
    let mut backoff = Duration::from_secs(1);
    // Start with whichever address worked last time.
    let mut preferred = 0_usize;
    loop {
        let mut rejected = false;
        let count = config.servers.len();
        for index in (0..count).map(|offset| (preferred + offset) % count) {
            let server = &config.servers[index];
            let result = session(
                server,
                fingerprint,
                &config,
                &executor,
                &terminals,
                &collector,
            )
            .await;
            terminals.close_all();
            match result {
                Ok(Ended::Closed { lasted }) => {
                    tracing::warn!(%server, "connection closed");
                    preferred = index;
                    if lasted > Duration::from_secs(60) {
                        backoff = Duration::from_secs(1);
                    }
                    break;
                }
                Ok(Ended::Rejected) => {
                    tracing::error!(
                        %server,
                        "the server rejected this device's credential; it was removed or the server was reset. Enroll again with `centrald-agent enroll`."
                    );
                    rejected = true;
                    break;
                }
                Err(error) => {
                    tracing::warn!(%server, error = %format!("{error:#}"), "cannot connect");
                }
            }
        }
        let delay = if rejected {
            REJECTED_BACKOFF
        } else {
            jitter(backoff)
        };
        tokio::time::sleep(delay).await;
        backoff = (backoff * 2).min(MAX_BACKOFF);
    }
}

fn jitter(base: Duration) -> Duration {
    let millis = u64::try_from(base.as_millis()).unwrap_or(u64::MAX);
    Duration::from_millis(millis / 2 + rand::random_range(0..=millis / 2 + 1))
}

async fn update_checker(updates: SharedUpdates) {
    tokio::time::sleep(Duration::from_secs(20)).await;
    loop {
        if let Ok(Some(found)) = tokio::task::spawn_blocking(check_updates).await {
            *updates.lock().unwrap_or_else(PoisonError::into_inner) = Some(found);
        }
        tokio::time::sleep(UPDATE_CHECK_INTERVAL).await;
    }
}

fn package_managed() -> bool {
    std::env::current_exe().is_ok_and(|path| path.starts_with("/usr/bin"))
}

async fn session(
    server: &str,
    fingerprint: [u8; 32],
    config: &AgentConfig,
    executor: &Executor,
    terminals: &Terminals,
    collector: &Arc<Mutex<Collector>>,
) -> Result<Ended> {
    let stream = crate::net::connect(server, fingerprint).await?;
    let url = format!("wss://{}/api/agent/connect", centrald_proto::AGENT_TLS_NAME);
    let mut request = url.into_client_request()?;
    request.headers_mut().insert(
        "Authorization",
        format!("Bearer {}.{}", config.device_id, config.token)
            .parse()
            .context("credential is not a valid header")?,
    );
    let ws_config = WebSocketConfig::default()
        .max_message_size(Some(MAX_MESSAGE_BYTES))
        .max_frame_size(Some(MAX_MESSAGE_BYTES));
    let socket =
        match tokio_tungstenite::client_async_with_config(request, stream, Some(ws_config)).await {
            Ok((socket, _)) => socket,
            Err(tungstenite::Error::Http(response)) if response.status() == 401 => {
                return Ok(Ended::Rejected);
            }
            Err(error) => return Err(anyhow!("WebSocket handshake failed: {error}")),
        };
    let started = tokio::time::Instant::now();
    let (mut sink, mut source) = socket.split();

    let hello = AgentMessage::Hello(Hello {
        protocol: PROTOCOL_VERSION,
        agent_version: centrald_proto::VERSION.to_owned(),
        hostname: hostname(),
        os: os_info(),
        allow_commands: config.allow_commands,
        package_managed: package_managed(),
    });
    sink.send(Message::text(serde_json::to_string(&hello)?))
        .await?;
    let welcome = tokio::time::timeout(Duration::from_secs(10), source.next())
        .await
        .map_err(|_| anyhow!("the server did not answer"))?;
    let interval = match welcome {
        Some(Ok(Message::Text(text))) => match serde_json::from_str::<ServerMessage>(&text) {
            Ok(ServerMessage::Welcome(welcome)) => welcome.status_interval_seconds.clamp(5, 300),
            _ => bail!("unexpected first message from the server"),
        },
        _ => bail!("the server closed the connection during the handshake"),
    };
    tracing::info!(%server, "connected");

    let (out, mut outgoing) = mpsc::channel::<AgentMessage>(256);
    let writer = tokio::spawn(async move {
        while let Some(message) = outgoing.recv().await {
            let Ok(text) = serde_json::to_string(&message) else {
                continue;
            };
            if sink.send(Message::text(text)).await.is_err() {
                return;
            }
        }
    });
    let reporter = tokio::spawn(report_status(
        collector.clone(),
        out.clone(),
        Duration::from_secs(u64::from(interval)),
    ));

    let result = loop {
        let Ok(next) = tokio::time::timeout(SILENCE_LIMIT, source.next()).await else {
            break Err(anyhow!("the server stopped responding"));
        };
        match next {
            Some(Ok(Message::Text(text))) => match serde_json::from_str::<ServerMessage>(&text) {
                Ok(message) => dispatch(message, executor, terminals, &out),
                Err(error) => tracing::warn!(%error, "ignoring an unknown server message"),
            },
            Some(Ok(Message::Close(_))) | None => {
                break Ok(Ended::Closed {
                    lasted: started.elapsed(),
                });
            }
            Some(Ok(_)) => {}
            Some(Err(error)) => break Err(anyhow!("connection error: {error}")),
        }
    };
    reporter.abort();
    drop(out);
    writer.abort();
    result
}

async fn report_status(
    collector: Arc<Mutex<Collector>>,
    out: mpsc::Sender<AgentMessage>,
    interval: Duration,
) {
    let mut tick = tokio::time::interval(interval);
    loop {
        tick.tick().await;
        let collector = collector.clone();
        let Ok(status) = tokio::task::spawn_blocking(move || {
            collector
                .lock()
                .unwrap_or_else(PoisonError::into_inner)
                .sample()
        })
        .await
        else {
            continue;
        };
        if out
            .send(AgentMessage::Status(Box::new(status)))
            .await
            .is_err()
        {
            return;
        }
    }
}

fn dispatch(
    message: ServerMessage,
    executor: &Executor,
    terminals: &Terminals,
    out: &mpsc::Sender<AgentMessage>,
) {
    match message {
        ServerMessage::Welcome(_) => {}
        ServerMessage::ExecStart {
            id,
            spec,
            timeout_seconds,
        } => executor.start(id, spec, timeout_seconds, out.clone()),
        ServerMessage::ExecCancel { id } => executor.cancel(&id),
        ServerMessage::TermOpen { id, columns, rows } => {
            terminals.open(id, columns, rows, out);
        }
        ServerMessage::TermInput { id, data } => terminals.input(&id, data),
        ServerMessage::TermResize { id, columns, rows } => terminals.resize(&id, columns, rows),
        ServerMessage::TermClose { id } => terminals.close(&id),
    }
}
