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
/// TCP, TLS, upgrade, `Hello`, and `Welcome` together must finish in this.
const HANDSHAKE_TIMEOUT: Duration = Duration::from_secs(30);
/// A server that does not take one message for this long is stuck.
const SEND_TIMEOUT: Duration = Duration::from_secs(60);
/// Messages waiting for the server; senders wait when it is full.
const OUTGOING_QUEUE: usize = 256;

type Socket =
    tokio_tungstenite::WebSocketStream<tokio_rustls::client::TlsStream<tokio::net::TcpStream>>;

enum Ended {
    /// The session ran and then closed; reconnect soon.
    Closed { lasted: Duration },
    /// The server does not know this device any more.
    Rejected,
}

/// Keeps one connection to the first reachable server until `shutdown`
/// resolves, then stops running commands and terminals.
pub async fn run(config: AgentConfig, shutdown: impl Future<Output = ()>) -> Result<()> {
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
    let connect = connect_forever(&config, fingerprint, &executor, &terminals, &collector);
    tokio::select! {
        () = connect => Ok(()),
        () = shutdown => {
            tracing::info!("stopping");
            terminals.close_all();
            executor.shutdown().await;
            Ok(())
        }
    }
}

async fn connect_forever(
    config: &AgentConfig,
    fingerprint: [u8; 32],
    executor: &Executor,
    terminals: &Terminals,
    collector: &Arc<Mutex<Collector>>,
) {
    let mut backoff = Duration::from_secs(1);
    // Start with whichever address worked last time.
    let mut preferred = 0_usize;
    loop {
        let mut rejected = false;
        let count = config.servers.len();
        for index in (0..count).map(|offset| (preferred + offset) % count) {
            let server = &config.servers[index];
            let result = session(server, fingerprint, config, executor, terminals, collector).await;
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

/// Connects, upgrades, and trades `Hello` for `Welcome`. `None` means the
/// server rejected this device's credential.
async fn handshake(
    server: &str,
    fingerprint: [u8; 32],
    config: &AgentConfig,
    executor: &Executor,
) -> Result<Option<(Socket, u32)>> {
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
    let mut socket =
        match tokio_tungstenite::client_async_with_config(request, stream, Some(ws_config)).await {
            Ok((socket, _)) => socket,
            Err(tungstenite::Error::Http(response)) if response.status() == 401 => {
                return Ok(None);
            }
            Err(error) => return Err(anyhow!("WebSocket handshake failed: {error}")),
        };

    let hello = AgentMessage::Hello(Hello {
        protocol: PROTOCOL_VERSION,
        agent_version: centrald_proto::VERSION.to_owned(),
        hostname: hostname(),
        os: os_info(),
        allow_commands: config.allow_commands,
        package_managed: package_managed(),
        running_execs: executor.running_ids(),
    });
    socket
        .send(Message::text(serde_json::to_string(&hello)?))
        .await?;
    let interval = match socket.next().await {
        Some(Ok(Message::Text(text))) => match serde_json::from_str::<ServerMessage>(&text) {
            Ok(ServerMessage::Welcome(welcome)) => welcome.status_interval_seconds.clamp(5, 300),
            _ => bail!("unexpected first message from the server"),
        },
        _ => bail!("the server closed the connection during the handshake"),
    };
    Ok(Some((socket, interval)))
}

async fn session(
    server: &str,
    fingerprint: [u8; 32],
    config: &AgentConfig,
    executor: &Executor,
    terminals: &Terminals,
    collector: &Arc<Mutex<Collector>>,
) -> Result<Ended> {
    let handshake = tokio::time::timeout(
        HANDSHAKE_TIMEOUT,
        handshake(server, fingerprint, config, executor),
    )
    .await
    .map_err(|_| anyhow!("the server did not complete the connection in time"))??;
    let Some((socket, interval)) = handshake else {
        return Ok(Ended::Rejected);
    };
    tracing::info!(%server, "connected");
    let started = tokio::time::Instant::now();
    let (mut sink, mut source) = socket.split();

    let (out, mut outgoing) = mpsc::channel::<AgentMessage>(OUTGOING_QUEUE);
    let mut writer = tokio::spawn(async move {
        while let Some(message) = outgoing.recv().await {
            let Ok(text) = serde_json::to_string(&message) else {
                continue;
            };
            tracing::trace!(kind = sent_kind(&message), bytes = text.len(), "to server");
            match tokio::time::timeout(SEND_TIMEOUT, sink.send(Message::text(text))).await {
                Ok(Ok(())) => {}
                _ => return,
            }
        }
    });
    let reporter = tokio::spawn(report_status(
        collector.clone(),
        out.clone(),
        Duration::from_secs(u64::from(interval)),
    ));

    let result = loop {
        let next = tokio::select! {
            next = tokio::time::timeout(SILENCE_LIMIT, source.next()) => next,
            _ = &mut writer => break Err(anyhow!("the server stopped accepting messages")),
        };
        let Ok(next) = next else {
            break Err(anyhow!("the server stopped responding"));
        };
        match next {
            Some(Ok(Message::Text(text))) => match serde_json::from_str::<ServerMessage>(&text) {
                Ok(message) => {
                    tracing::trace!(kind = received_kind(&message), "from server");
                    dispatch(message, executor, terminals, &out);
                }
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
        } => executor.start(id, spec, timeout_seconds, out),
        ServerMessage::ExecCancel { id } => executor.cancel(&id),
        ServerMessage::TermOpen { id, columns, rows } => {
            terminals.open(id, columns, rows, out);
        }
        ServerMessage::TermInput { id, data } => terminals.input(&id, data),
        ServerMessage::TermResize { id, columns, rows } => terminals.resize(&id, columns, rows),
        ServerMessage::TermClose { id } => terminals.close(&id),
    }
}

/// Message names for trace logs; payloads are never logged.
fn sent_kind(message: &AgentMessage) -> &'static str {
    match message {
        AgentMessage::Hello(_) => "hello",
        AgentMessage::Status(_) => "status",
        AgentMessage::ExecOutput { .. } => "exec_output",
        AgentMessage::ExecExit { .. } => "exec_exit",
        AgentMessage::TermOutput { .. } => "term_output",
        AgentMessage::TermExit { .. } => "term_exit",
    }
}

fn received_kind(message: &ServerMessage) -> &'static str {
    match message {
        ServerMessage::Welcome(_) => "welcome",
        ServerMessage::ExecStart { .. } => "exec_start",
        ServerMessage::ExecCancel { .. } => "exec_cancel",
        ServerMessage::TermOpen { .. } => "term_open",
        ServerMessage::TermInput { .. } => "term_input",
        ServerMessage::TermResize { .. } => "term_resize",
        ServerMessage::TermClose { .. } => "term_close",
    }
}
