//! The web app, compiled into the binary.

use axum::http::header::{ALLOW, CACHE_CONTROL, CONTENT_TYPE};
use axum::http::{Method, StatusCode, Uri};
use axum::response::{IntoResponse, Response};

use crate::error::ApiError;

#[derive(rust_embed::RustEmbed)]
#[folder = "$OUT_DIR/ui"]
struct Assets;

/// Fallback for every path no route claimed. Only GET and HEAD of a
/// non-API path reach the web app; anything else (including a CONNECT to
/// some other host) is refused.
pub async fn serve(method: Method, uri: Uri) -> Response {
    let path = uri.path().trim_start_matches('/');
    if path == "api" || path.starts_with("api/") {
        return ApiError::not_found("No such API endpoint.").into_response();
    }
    if method != Method::GET && method != Method::HEAD {
        return (
            StatusCode::METHOD_NOT_ALLOWED,
            [(ALLOW, "GET, HEAD")],
            "Method not allowed",
        )
            .into_response();
    }
    if let Some(file) = Assets::get(path).filter(|_| !path.is_empty()) {
        // Vite fingerprints everything under assets/, so it never changes.
        let cache = if path.starts_with("assets/") {
            "public, max-age=31536000, immutable"
        } else {
            "no-cache"
        };
        let mime = mime_guess::from_path(path).first_or_octet_stream();
        return (
            [
                (CONTENT_TYPE, mime.as_ref().to_owned()),
                (CACHE_CONTROL, cache.to_owned()),
            ],
            file.data,
        )
            .into_response();
    }
    // Missing static files are real 404s; everything else is an app route.
    if path.starts_with("assets/") || path.contains('.') {
        return (StatusCode::NOT_FOUND, "Not found").into_response();
    }
    match Assets::get("index.html") {
        Some(index) => (
            [
                (CONTENT_TYPE, "text/html; charset=utf-8"),
                (CACHE_CONTROL, "no-cache"),
            ],
            index.data,
        )
            .into_response(),
        None => (
            StatusCode::NOT_FOUND,
            "The web app is missing from this build.",
        )
            .into_response(),
    }
}
