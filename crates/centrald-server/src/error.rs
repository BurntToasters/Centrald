//! API errors rendered as `{ "error": "…" }` with a plain-language message.

use axum::Json;
use axum::http::StatusCode;
use axum::response::{IntoResponse, Response};
use serde_json::{Value, json};

#[derive(Debug)]
pub struct ApiError {
    status: StatusCode,
    message: String,
    extra: Option<(&'static str, Value)>,
}

pub type ApiResult<T> = Result<T, ApiError>;

impl ApiError {
    pub fn new(status: StatusCode, message: impl Into<String>) -> Self {
        Self {
            status,
            message: message.into(),
            extra: None,
        }
    }

    pub fn bad_request(message: impl Into<String>) -> Self {
        Self::new(StatusCode::BAD_REQUEST, message)
    }

    pub fn unauthorized(message: impl Into<String>) -> Self {
        Self::new(StatusCode::UNAUTHORIZED, message)
    }

    pub fn forbidden(message: impl Into<String>) -> Self {
        Self::new(StatusCode::FORBIDDEN, message)
    }

    pub fn not_found(message: impl Into<String>) -> Self {
        Self::new(StatusCode::NOT_FOUND, message)
    }

    pub fn conflict(message: impl Into<String>) -> Self {
        Self::new(StatusCode::CONFLICT, message)
    }

    pub fn too_many(retry_after_seconds: i64) -> Self {
        let minutes = (retry_after_seconds + 59) / 60;
        let wait = if minutes <= 1 {
            "a minute".to_owned()
        } else {
            format!("{minutes} minutes")
        };
        Self::new(
            StatusCode::TOO_MANY_REQUESTS,
            format!("Too many failed attempts. Try again in {wait}."),
        )
    }

    /// Adds one machine-readable field next to `error`.
    pub fn with(mut self, key: &'static str, value: Value) -> Self {
        self.extra = Some((key, value));
        self
    }
}

impl From<anyhow::Error> for ApiError {
    fn from(error: anyhow::Error) -> Self {
        tracing::error!(error = %format!("{error:#}"), "request failed");
        Self::new(
            StatusCode::INTERNAL_SERVER_ERROR,
            "Something went wrong on the server. Check the server log for details.",
        )
    }
}

impl From<rusqlite::Error> for ApiError {
    fn from(error: rusqlite::Error) -> Self {
        anyhow::Error::from(error).into()
    }
}

impl IntoResponse for ApiError {
    fn into_response(self) -> Response {
        let mut body = json!({ "error": self.message });
        if let (Some((key, value)), Some(object)) = (self.extra, body.as_object_mut()) {
            object.insert(key.to_owned(), value);
        }
        (self.status, Json(body)).into_response()
    }
}
