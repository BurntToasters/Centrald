//! The single listener: TLS for everything, plus a tiny plaintext responder
//! that redirects browsers which typed `http://`.

use std::net::SocketAddr;
use std::sync::Arc;
use std::time::Duration;

use anyhow::{Context, Result};
use axum::extract::connect_info::Connected;
use axum::serve::IncomingStream;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpListener, TcpStream};
use tokio::sync::{Semaphore, mpsc};
use tokio_rustls::TlsAcceptor;
use tokio_rustls::server::TlsStream;

const HANDSHAKE_TIMEOUT: Duration = Duration::from_secs(10);
const MAX_CONNECTIONS: usize = 2048;
const MAX_REDIRECT_HEAD: usize = 8 * 1024;

/// Accepts TCP connections and hands finished TLS sessions to axum.
///
/// Handshakes run on their own tasks so one slow client never stalls the
/// accept loop.
#[derive(Debug)]
pub struct TlsListener {
    ready: mpsc::Receiver<(TlsStream<TcpStream>, SocketAddr)>,
}

/// Remote address of the peer, for audit records and rate limiting.
#[derive(Debug, Clone, Copy)]
pub struct ClientAddr(pub SocketAddr);

impl Connected<IncomingStream<'_, TlsListener>> for ClientAddr {
    fn connect_info(stream: IncomingStream<'_, TlsListener>) -> Self {
        Self(*stream.remote_addr())
    }
}

impl TlsListener {
    pub async fn bind(address: SocketAddr, config: Arc<rustls::ServerConfig>) -> Result<Self> {
        let listener = TcpListener::bind(address)
            .await
            .with_context(|| format!("cannot listen on {address}"))?;
        let (sender, ready) = mpsc::channel(64);
        let acceptor = TlsAcceptor::from(config);
        let permits = Arc::new(Semaphore::new(MAX_CONNECTIONS));
        tokio::spawn(async move {
            loop {
                let Ok(permit) = permits.clone().acquire_owned().await else {
                    return;
                };
                let (stream, peer) = match listener.accept().await {
                    Ok(accepted) => accepted,
                    Err(error) => {
                        tracing::debug!(%error, "accept failed");
                        tokio::time::sleep(Duration::from_millis(50)).await;
                        continue;
                    }
                };
                let acceptor = acceptor.clone();
                let sender = sender.clone();
                tokio::spawn(async move {
                    // The permit lives as long as the handshake; afterwards
                    // hyper's own limits apply.
                    let _permit = permit;
                    let _ = stream.set_nodelay(true);
                    let mut first = [0_u8; 1];
                    let peeked =
                        tokio::time::timeout(HANDSHAKE_TIMEOUT, stream.peek(&mut first)).await;
                    match peeked {
                        Ok(Ok(1)) if first[0] == 0x16 => {}
                        Ok(Ok(1)) => {
                            redirect_plaintext(stream).await;
                            return;
                        }
                        _ => return,
                    }
                    match tokio::time::timeout(HANDSHAKE_TIMEOUT, acceptor.accept(stream)).await {
                        Ok(Ok(tls)) => {
                            let _ = sender.send((tls, peer)).await;
                        }
                        Ok(Err(error)) => tracing::debug!(%peer, %error, "TLS handshake failed"),
                        Err(_) => tracing::debug!(%peer, "TLS handshake timed out"),
                    }
                });
            }
        });
        Ok(Self { ready })
    }
}

impl axum::serve::Listener for TlsListener {
    type Io = TlsStream<TcpStream>;
    type Addr = SocketAddr;

    async fn accept(&mut self) -> (Self::Io, Self::Addr) {
        match self.ready.recv().await {
            Some(accepted) => accepted,
            // The accept task only ends if the semaphore closes, which never
            // happens; park forever rather than spin.
            None => std::future::pending().await,
        }
    }

    fn local_addr(&self) -> std::io::Result<Self::Addr> {
        Err(std::io::Error::other("not tracked"))
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
