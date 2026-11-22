//! The single listener: TLS for everything, plus a tiny plaintext responder
//! that redirects browsers which typed `http://`.
//!
//! Connections are capped globally and per source address (IPv6 by /64),
//! and both HTTP versions close idle connections, so idle sockets cannot
//! starve the server.

use std::collections::HashMap;
use std::future::Future;
use std::net::{IpAddr, SocketAddr};
use std::pin::Pin;
use std::sync::atomic::{AtomicU64, AtomicUsize, Ordering};
use std::sync::{Arc, Mutex, PoisonError};
use std::task::{Context as TaskContext, Poll};
use std::time::{Duration, Instant};

use anyhow::{Context, Result};
use axum::Router;
use axum::extract::ConnectInfo;
use hyper::body::Incoming;
use hyper::server::conn::{http1, http2};
use hyper_util::rt::{TokioExecutor, TokioIo, TokioTimer};
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt, ReadBuf};
use tokio::net::{TcpListener, TcpStream};
use tokio::sync::{OwnedSemaphorePermit, Semaphore, watch};
use tokio_rustls::TlsAcceptor;
use tokio_rustls::server::TlsStream;
use tower::ServiceExt;

const HANDSHAKE_TIMEOUT: Duration = Duration::from_secs(10);
/// Stays under the common 1,024 open-file limit, with room for the rest.
pub const MAX_CONNECTIONS: usize = 900;
/// One address (or IPv6 /64) may hold this many connections.
pub const MAX_CONNECTIONS_PER_SOURCE: u32 = 128;
/// HTTP/1.1: time allowed for a request head, which also bounds keep-alive
/// idle time.
const HEADER_TIMEOUT: Duration = Duration::from_secs(20);
/// A connection with no request in progress for this long is closed
/// gracefully (HTTP/2 needs this; HTTP/1.1 hits `HEADER_TIMEOUT` first).
const IDLE_TIMEOUT: Duration = Duration::from_secs(120);
const IDLE_CHECK: Duration = Duration::from_secs(15);
const H2_PING_INTERVAL: Duration = Duration::from_secs(30);
const H2_PING_TIMEOUT: Duration = Duration::from_secs(20);
const SHUTDOWN_GRACE: Duration = Duration::from_secs(3);
const MAX_REDIRECT_HEAD: usize = 8 * 1024;

/// Remote address of the peer, for audit records and rate limiting.
#[derive(Debug, Clone, Copy)]
pub struct ClientAddr(pub SocketAddr);

/// Binds the listening socket. Called before any state is touched, so a
/// second instance fails here (after the data-directory lock) harmlessly.
pub fn bind(address: SocketAddr) -> Result<std::net::TcpListener> {
    let listener = std::net::TcpListener::bind(address)
        .with_context(|| format!("cannot listen on {address}"))?;
    listener
        .set_nonblocking(true)
        .context("configure listener")?;
    Ok(listener)
}

/// Serves `app` until `shutdown` resolves, then lets open requests finish
/// for a few seconds.
pub async fn serve(
    listener: std::net::TcpListener,
    tls: Arc<rustls::ServerConfig>,
    app: Router,
    shutdown: impl Future<Output = ()>,
) -> Result<()> {
    let listener = TcpListener::from_std(listener).context("register listener")?;
    let acceptor = TlsAcceptor::from(tls);
    let permits = Arc::new(Semaphore::new(MAX_CONNECTIONS));
    let sources = Arc::new(Sources::default());
    let (stop, stopping) = watch::channel(false);
    // Each connection task holds a receiver; `closed()` waits for them all.
    let (live, _) = watch::channel(());
    tokio::pin!(shutdown);
    loop {
        let permit = tokio::select! {
            permit = permits.clone().acquire_owned() => permit.context("connection limit")?,
            () = &mut shutdown => break,
        };
        let (stream, peer) = tokio::select! {
            accepted = listener.accept() => match accepted {
                Ok(accepted) => accepted,
                Err(error) => {
                    tracing::debug!(%error, "accept failed");
                    tokio::time::sleep(Duration::from_millis(50)).await;
                    continue;
                }
            },
            () = &mut shutdown => break,
        };
        let Some(source) = sources.admit(peer.ip()) else {
            tracing::debug!(%peer, "too many connections from this address");
            continue;
        };
        let held = Held {
            _permit: permit,
            _source: source,
        };
        tokio::spawn(connection(
            stream,
            peer,
            acceptor.clone(),
            app.clone(),
            held,
            stopping.clone(),
            live.subscribe(),
        ));
    }
    drop(listener);
    let _ = stop.send(true);
    let _ = tokio::time::timeout(SHUTDOWN_GRACE, live.closed()).await;
    Ok(())
}

/// Per-source connection counts.
#[derive(Debug, Default)]
struct Sources {
    counts: Mutex<HashMap<IpAddr, u32>>,
}

impl Sources {
    fn admit(self: &Arc<Self>, ip: IpAddr) -> Option<SourceGuard> {
        let group = crate::auth::source_group(ip);
        let mut counts = self.counts.lock().unwrap_or_else(PoisonError::into_inner);
        let count = counts.entry(group).or_insert(0);
        if *count >= MAX_CONNECTIONS_PER_SOURCE {
            return None;
        }
        *count += 1;
        Some(SourceGuard {
            sources: self.clone(),
            group,
        })
    }
}

struct SourceGuard {
    sources: Arc<Sources>,
    group: IpAddr,
}

impl Drop for SourceGuard {
    fn drop(&mut self) {
        let mut counts = self
            .sources
            .counts
            .lock()
            .unwrap_or_else(PoisonError::into_inner);
        if let Some(count) = counts.get_mut(&self.group) {
            *count = count.saturating_sub(1);
            if *count == 0 {
                counts.remove(&self.group);
            }
        }
    }
}

/// Slots a connection holds for as long as its socket lives, including
/// after a WebSocket upgrade.
struct Held {
    _permit: OwnedSemaphorePermit,
    _source: SourceGuard,
}

struct Counted {
    inner: TlsStream<TcpStream>,
    _held: Held,
}

impl AsyncRead for Counted {
    fn poll_read(
        self: Pin<&mut Self>,
        cx: &mut TaskContext<'_>,
        buf: &mut ReadBuf<'_>,
    ) -> Poll<std::io::Result<()>> {
        Pin::new(&mut self.get_mut().inner).poll_read(cx, buf)
    }
}

impl AsyncWrite for Counted {
    fn poll_write(
        self: Pin<&mut Self>,
        cx: &mut TaskContext<'_>,
        buf: &[u8],
    ) -> Poll<std::io::Result<usize>> {
        Pin::new(&mut self.get_mut().inner).poll_write(cx, buf)
    }

    fn poll_write_vectored(
        self: Pin<&mut Self>,
        cx: &mut TaskContext<'_>,
        bufs: &[std::io::IoSlice<'_>],
    ) -> Poll<std::io::Result<usize>> {
        Pin::new(&mut self.get_mut().inner).poll_write_vectored(cx, bufs)
    }

    fn is_write_vectored(&self) -> bool {
        self.inner.is_write_vectored()
    }

    fn poll_flush(self: Pin<&mut Self>, cx: &mut TaskContext<'_>) -> Poll<std::io::Result<()>> {
        Pin::new(&mut self.get_mut().inner).poll_flush(cx)
    }

    fn poll_shutdown(self: Pin<&mut Self>, cx: &mut TaskContext<'_>) -> Poll<std::io::Result<()>> {
        Pin::new(&mut self.get_mut().inner).poll_shutdown(cx)
    }
}

/// Requests in progress on one connection and when the last one ended.
struct Activity {
    start: Instant,
    busy: AtomicUsize,
    last_ms: AtomicU64,
}

struct Busy(Arc<Activity>);

impl Activity {
    fn new() -> Arc<Self> {
        Arc::new(Self {
            start: Instant::now(),
            busy: AtomicUsize::new(0),
            last_ms: AtomicU64::new(0),
        })
    }

    fn elapsed_ms(&self) -> u64 {
        u64::try_from(self.start.elapsed().as_millis()).unwrap_or(u64::MAX)
    }

    fn begin(self: &Arc<Self>) -> Busy {
        self.busy.fetch_add(1, Ordering::SeqCst);
        Busy(self.clone())
    }

    fn idle_for(&self) -> Duration {
        if self.busy.load(Ordering::SeqCst) > 0 {
            return Duration::ZERO;
        }
        let idle = self
            .elapsed_ms()
            .saturating_sub(self.last_ms.load(Ordering::SeqCst));
        Duration::from_millis(idle)
    }
}

impl Drop for Busy {
    fn drop(&mut self) {
        self.0.last_ms.store(self.0.elapsed_ms(), Ordering::SeqCst);
        self.0.busy.fetch_sub(1, Ordering::SeqCst);
    }
}

/// Runs a hyper connection until it ends, closing it gracefully on server
/// shutdown or when it has been idle too long.
macro_rules! drive {
    ($conn:expr, $stopping:expr, $activity:expr) => {{
        let conn = $conn;
        tokio::pin!(conn);
        let mut tick = tokio::time::interval(IDLE_CHECK);
        let mut closing = false;
        loop {
            tokio::select! {
                result = conn.as_mut() => {
                    if let Err(error) = result {
                        tracing::debug!(%error, "connection ended");
                    }
                    break;
                }
                _ = $stopping.changed(), if !closing => {
                    closing = true;
                    conn.as_mut().graceful_shutdown();
                }
                _ = tick.tick(), if !closing => {
                    if $activity.idle_for() >= IDLE_TIMEOUT {
                        closing = true;
                        conn.as_mut().graceful_shutdown();
                    }
                }
            }
        }
    }};
}

async fn connection(
    stream: TcpStream,
    peer: SocketAddr,
    acceptor: TlsAcceptor,
    app: Router,
    held: Held,
    mut stopping: watch::Receiver<bool>,
    _live: watch::Receiver<()>,
) {
    let _ = stream.set_nodelay(true);
    let mut first = [0_u8; 1];
    match tokio::time::timeout(HANDSHAKE_TIMEOUT, stream.peek(&mut first)).await {
        Ok(Ok(1)) if first[0] == 0x16 => {}
        Ok(Ok(1)) => {
            redirect_plaintext(stream).await;
            return;
        }
        _ => return,
    }
    let tls = match tokio::time::timeout(HANDSHAKE_TIMEOUT, acceptor.accept(stream)).await {
        Ok(Ok(tls)) => tls,
        Ok(Err(error)) => {
            tracing::debug!(%peer, %error, "TLS handshake failed");
            return;
        }
        Err(_) => {
            tracing::debug!(%peer, "TLS handshake timed out");
            return;
        }
    };
    let h2 = tls.get_ref().1.alpn_protocol() == Some(b"h2".as_slice());
    let io = TokioIo::new(Counted {
        inner: tls,
        _held: held,
    });
    let activity = Activity::new();
    let service = {
        let activity = activity.clone();
        hyper::service::service_fn(move |mut request: hyper::Request<Incoming>| {
            request
                .extensions_mut()
                .insert(ConnectInfo(ClientAddr(peer)));
            let busy = activity.begin();
            let app = app.clone();
            async move {
                let _busy = busy;
                app.oneshot(request.map(axum::body::Body::new)).await
            }
        })
    };
    if h2 {
        let mut builder = http2::Builder::new(TokioExecutor::new());
        builder
            .timer(TokioTimer::new())
            // Browsers run WebSockets over HTTP/2 extended CONNECT.
            .enable_connect_protocol()
            .keep_alive_interval(H2_PING_INTERVAL)
            .keep_alive_timeout(H2_PING_TIMEOUT)
            .max_concurrent_streams(100);
        drive!(builder.serve_connection(io, service), stopping, activity);
    } else {
        let mut builder = http1::Builder::new();
        builder
            .timer(TokioTimer::new())
            .header_read_timeout(HEADER_TIMEOUT);
        drive!(
            builder.serve_connection(io, service).with_upgrades(),
            stopping,
            activity
        );
    }
}

/// Answers a plaintext HTTP request with a redirect to the same URL on HTTPS.
async fn redirect_plaintext(mut stream: TcpStream) {
    let mut head = Vec::with_capacity(1024);
    let mut buffer = [0_u8; 1024];
    let read = tokio::time::timeout(Duration::from_secs(5), async {
        while head.len() < MAX_REDIRECT_HEAD && !head.windows(4).any(|w| w == b"\r\n\r\n") {
            match stream.read(&mut buffer).await {
                Ok(0) | Err(_) => break,
                Ok(count) => head.extend_from_slice(&buffer[..count]),
            }
        }
    })
    .await;
    if read.is_err() {
        return;
    }
    let local_port = stream.local_addr().map(|a| a.port()).unwrap_or_default();
    let response = if let Some(location) = redirect_target(&head, local_port) {
        format!(
            "HTTP/1.1 301 Moved Permanently\r\nLocation: {location}\r\nContent-Length: 0\r\nConnection: close\r\n\r\n"
        )
    } else {
        let body = "This server only speaks HTTPS.\n";
        format!(
            "HTTP/1.1 400 Bad Request\r\nContent-Type: text/plain\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{body}",
            body.len()
        )
    };
    let _ = stream.write_all(response.as_bytes()).await;
    let _ = stream.shutdown().await;
}

fn redirect_target(head: &[u8], local_port: u16) -> Option<String> {
    let text = std::str::from_utf8(head).ok()?;
    let mut lines = text.split("\r\n");
    let request_line = lines.next()?;
    let mut parts = request_line.split(' ');
    let _method = parts.next()?;
    let target = parts.next().filter(|t| t.starts_with('/'))?;
    if target.bytes().any(|b| b.is_ascii_control() || b == b' ') {
        return None;
    }
    let host = lines.take_while(|line| !line.is_empty()).find_map(|line| {
        let (name, value) = line.split_once(':')?;
        name.trim()
            .eq_ignore_ascii_case("host")
            .then(|| value.trim())
    })?;
    // Reuse the join-code address rules so nothing odd lands in a header.
    let host = if host.contains(':') && !host.ends_with(']') {
        host.to_owned()
    } else {
        format!("{host}:{local_port}")
    };
    centrald_proto::join::validate_server_address(&host).ok()?;
    Some(format!("https://{host}{target}"))
}
