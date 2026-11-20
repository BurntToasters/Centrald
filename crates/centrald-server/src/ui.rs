//! The web app, compiled into the binary.

use axum::http::header::{CACHE_CONTROL, CONTENT_TYPE};
use axum::http::{StatusCode, Uri};
use axum::response::{IntoResponse, Response};

#[derive(rust_embed::RustEmbed)]
#[folder = "$OUT_DIR/ui"]
struct Assets;

pub async fn serve(uri: Uri) -> Response {
    let path = uri.path().trim_start_matches('/');
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
