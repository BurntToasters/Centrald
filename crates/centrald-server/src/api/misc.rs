//! Live events, the activity log, and server details.

use axum::Json;
use axum::extract::ws::{Message, WebSocket, WebSocketUpgrade};
use axum::extract::{Query, State};
use axum::http::header::{CONTENT_DISPOSITION, CONTENT_TYPE};
use axum::response::{IntoResponse, Response};
use serde::{Deserialize, Serialize};
use serde_json::json;
use tokio::sync::broadcast::error::RecvError;

use crate::downloads::AgentBuild;
use crate::error::ApiResult;
use crate::hub::SOCKET_SEND_TIMEOUT;
use crate::model::{self, AuditView};
use crate::session::CurrentUser;
use crate::state::Shared;

/// Pushes [`crate::hub::Event`]s to the browser. A slow client that falls
/// behind gets `resync` and reloads its data instead of stalling the hub.
pub async fn events(
    State(state): State<Shared>,
    user: CurrentUser,
    upgrade: WebSocketUpgrade,
) -> Response {
    upgrade
        .max_message_size(4096)
        .on_upgrade(move |socket| stream_events(state, user, socket))
}

async fn stream_events(state: Shared, user: CurrentUser, mut socket: WebSocket) {
    let mut events = state.hub.subscribe();
    let mut session = state.hub.watch_session(user.session_hash, &user.id);
    loop {
        tokio::select! {
            event = events.recv() => {
                let text = match event {
                    Ok(text) => text.to_string(),
                    Err(RecvError::Lagged(_)) => json!({ "type": "resync" }).to_string(),
                    Err(RecvError::Closed) => return,
                };
                // A tab that stops reading is dropped rather than parked.
                let sent = tokio::time::timeout(
                    SOCKET_SEND_TIMEOUT,
                    socket.send(Message::Text(text.into())),
                )
                .await;
                if !matches!(sent, Ok(Ok(()))) {
                    return;
                }
            }
            incoming = socket.recv() => match incoming {
                Some(Ok(Message::Close(_)) | Err(_)) | None => return,
                Some(Ok(_)) => {}
            },
            () = session.ended() => {
                let _ = tokio::time::timeout(SOCKET_SEND_TIMEOUT, socket.send(Message::Close(None))).await;
                return;
            }
        }
    }
}

#[derive(Debug, Deserialize)]
pub struct AuditQuery {
    limit: Option<u32>,
    before: Option<i64>,
}

pub async fn audit(
    State(state): State<Shared>,
    _user: CurrentUser,
    Query(query): Query<AuditQuery>,
) -> ApiResult<Json<Vec<AuditView>>> {
    let limit = query.limit.unwrap_or(100).clamp(1, 500);
    Ok(Json(
        state
            .db
            .call(move |c| model::list_audit(c, limit, query.before))
            .await?,
    ))
}

#[derive(Debug, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct ServerView {
    version: &'static str,
    ca_fingerprint: String,
    certificate_names: Vec<String>,
    custom_certificate: bool,
    port: u16,
    agent_builds: Vec<AgentBuild>,
}

pub async fn server(State(state): State<Shared>, _user: CurrentUser) -> Json<ServerView> {
    let builds_state = state.clone();
    let agent_builds = tokio::task::spawn_blocking(move || builds_state.builds.list())
        .await
        .unwrap_or_default();
    Json(ServerView {
        version: centrald_proto::VERSION,
        ca_fingerprint: centrald_proto::format_fingerprint(&state.tls.ca_fingerprint),
        certificate_names: state.tls.certificate_names(),
        custom_certificate: state.tls.has_custom_certificate(),
        port: state.config.listen.port(),
        agent_builds,
    })
}

/// The private CA, for operators who want browsers to trust this server.
pub async fn ca_certificate(State(state): State<Shared>, _user: CurrentUser) -> Response {
    (
        [
            (CONTENT_TYPE, "application/x-pem-file"),
            (
                CONTENT_DISPOSITION,
                "attachment; filename=\"centrald-ca.crt\"",
            ),
        ],
        state.tls.ca_pem.clone(),
    )
        .into_response()
}
