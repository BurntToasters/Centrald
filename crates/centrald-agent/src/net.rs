//! Pinned TLS connections to the server.

use std::time::Duration;

use anyhow::{Context, Result, anyhow};
use http_body_util::{BodyExt, Full, Limited};
use hyper::body::Bytes;
use tokio::net::TcpStream;
use tokio_rustls::TlsConnector;
use tokio_rustls::client::TlsStream;

const CONNECT_TIMEOUT: Duration = Duration::from_secs(10);
const MAX_RESPONSE_BYTES: usize = 64 * 1024;

/// Opens TCP to `address` and completes TLS, accepting only a server whose
/// CA matches `fingerprint`.
pub async fn connect(address: &str, fingerprint: [u8; 32]) -> Result<TlsStream<TcpStream>> {
    let config = centrald_proto::pin::client_config(fingerprint)?;
    let tcp = tokio::time::timeout(CONNECT_TIMEOUT, TcpStream::connect(address))
        .await
        .map_err(|_| anyhow!("timed out connecting to {address}"))?
        .with_context(|| format!("cannot reach {address}"))?;
    let _ = tcp.set_nodelay(true);
    let name = centrald_proto::pin::server_name()?;
    let tls = tokio::time::timeout(
        CONNECT_TIMEOUT,
        TlsConnector::from(config).connect(name, tcp),
    )
    .await
    .map_err(|_| anyhow!("TLS handshake with {address} timed out"))?
    .with_context(|| format!("secure connection to {address} failed"))?;
    Ok(tls)
}

/// POSTs JSON over a fresh pinned connection and returns status and body.
pub async fn post_json(
    address: &str,
    fingerprint: [u8; 32],
    path: &str,
    body: Vec<u8>,
) -> Result<(u16, Vec<u8>)> {
    let request = hyper::Request::post(path)
        .header(hyper::header::HOST, centrald_proto::AGENT_TLS_NAME)
        .header(hyper::header::CONTENT_TYPE, "application/json")
        .body(Full::new(Bytes::from(body)))?;
    send(
        address,
        fingerprint,
        request,
        MAX_RESPONSE_BYTES,
        Duration::from_secs(30),
    )
    .await
}

/// GETs `path` over a fresh pinned connection, reading at most `limit` bytes.
pub async fn get(
    address: &str,
    fingerprint: [u8; 32],
    path: &str,
    limit: usize,
) -> Result<(u16, Vec<u8>)> {
    let request = hyper::Request::get(path)
        .header(hyper::header::HOST, centrald_proto::AGENT_TLS_NAME)
        .body(Full::new(Bytes::new()))?;
    send(
        address,
        fingerprint,
        request,
        limit,
        Duration::from_secs(300),
    )
    .await
}

async fn send(
    address: &str,
    fingerprint: [u8; 32],
    request: hyper::Request<Full<Bytes>>,
    limit: usize,
    deadline: Duration,
) -> Result<(u16, Vec<u8>)> {
    let stream = connect(address, fingerprint).await?;
    let io = hyper_util::rt::TokioIo::new(stream);
    let (mut sender, connection) = hyper::client::conn::http1::handshake(io)
        .await
        .context("HTTP handshake failed")?;
    tokio::spawn(async move {
        let _ = connection.await;
    });
    let exchange = async {
        let response = sender.send_request(request).await?;
        let status = response.status().as_u16();
        let bytes = Limited::new(response.into_body(), limit)
            .collect()
            .await
            .map_err(|e| anyhow!("reading the response failed: {e}"))?
            .to_bytes();
        Ok::<_, anyhow::Error>((status, bytes.to_vec()))
    };
    tokio::time::timeout(deadline, exchange)
        .await
        .map_err(|_| anyhow!("the server did not answer in time"))?
}

/// Pulls `{"error": "..."}` out of an API error body.
pub fn error_message(body: &[u8]) -> String {
    serde_json::from_slice::<serde_json::Value>(body)
        .ok()
        .and_then(|v| v.get("error").and_then(|e| e.as_str()).map(str::to_owned))
        .unwrap_or_else(|| String::from_utf8_lossy(body).chars().take(200).collect())
}
