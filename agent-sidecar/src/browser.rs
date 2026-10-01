//! HUP-S5.1 + S5.6: the browser's control routes (bearer-gated, loopback, for citrate-core only).
//!
//! These are the member's controls behind the Browser pop-out: read the status and the latest
//! screencast frame, Stop and resume, attach to the member's Chrome (with the member's consent
//! for this session) or detach, consent to or revoke an origin, and decide on a browser action
//! that is waiting for the member. The agent loop cannot reach any of these: its tools only ask.
//! With the browser off (`CITRATE_HERMES_BROWSER` unset) status says `enabled: false` and every
//! other route answers 404.

use std::sync::Arc;

use axum::{
    extract::{Query, State},
    http::{HeaderMap, StatusCode},
    response::{IntoResponse, Response},
    Json,
};
use citrate_agent_browser::{BrowserConfig, BrowserService};
use serde::Deserialize;
use serde_json::json;

use crate::AppState;

/// The browser worker when `CITRATE_HERMES_BROWSER=1` (default off → `None`). What it will use is
/// logged to stderr for the operator.
pub fn from_env() -> Option<Arc<BrowserService>> {
    let cfg = BrowserConfig::from_env()?;
    let svc = BrowserService::new(cfg);
    match svc.chromium() {
        citrate_agent_browser::chromium::ChromiumStatus::NotInstalled { searched } => eprintln!(
            "citrate-agent-sidecar: browser tools on, but no Chromium is installed ({} places checked)",
            searched.len()
        ),
        s => eprintln!("citrate-agent-sidecar: browser tools on: {s:?}"),
    }
    Some(Arc::new(svc))
}

fn err(code: StatusCode, msg: impl Into<String>) -> Response {
    (code, Json(json!({ "error": msg.into() }))).into_response()
}

/// Why a route refused before reaching the browser.
pub struct Refusal(StatusCode, &'static str);

impl IntoResponse for Refusal {
    fn into_response(self) -> Response {
        if self.0 == StatusCode::UNAUTHORIZED {
            return self.0.into_response();
        }
        err(self.0, self.1)
    }
}

/// The worker, or why not (401 / 404).
fn worker(headers: &HeaderMap, st: &AppState) -> Result<Arc<BrowserService>, Refusal> {
    if !crate::authorized(headers, &st.bearer) {
        return Err(Refusal(StatusCode::UNAUTHORIZED, "unauthorized"));
    }
    st.sessions
        .browser()
        .cloned()
        .ok_or(Refusal(StatusCode::NOT_FOUND, "the browser is off"))
}

async fn blocking<T: Send + 'static>(f: impl FnOnce() -> T + Send + 'static) -> Result<T, Refusal> {
    tokio::task::spawn_blocking(f).await.map_err(|_| {
        Refusal(
            StatusCode::INTERNAL_SERVER_ERROR,
            "internal: the browser task failed",
        )
    })
}

/// `GET /browser/status`
pub async fn status(headers: HeaderMap, State(st): State<Arc<AppState>>) -> Response {
    if !crate::authorized(&headers, &st.bearer) {
        return StatusCode::UNAUTHORIZED.into_response();
    }
    match st.sessions.browser().cloned() {
        None => Json(json!({ "enabled": false })).into_response(),
        Some(b) => match blocking(move || b.status()).await {
            Ok(s) => Json(s).into_response(),
            Err(r) => r.into_response(),
        },
    }
}

#[derive(Deserialize)]
pub struct FrameQuery {
    #[serde(default)]
    after: u64,
}

/// `GET /browser/frame?after=N` — the screencast view when newer than N, else 204.
pub async fn frame(
    headers: HeaderMap,
    State(st): State<Arc<AppState>>,
    Query(q): Query<FrameQuery>,
) -> Response {
    let b = match worker(&headers, &st) {
        Ok(b) => b,
        Err(r) => return r.into_response(),
    };
    match b.frame(q.after) {
        Some(v) => Json(v).into_response(),
        None => StatusCode::NO_CONTENT.into_response(),
    }
}

/// `POST /browser/stop` — the member's Stop (latches until resume).
pub async fn stop(headers: HeaderMap, State(st): State<Arc<AppState>>) -> Response {
    let b = match worker(&headers, &st) {
        Ok(b) => b,
        Err(r) => return r.into_response(),
    };
    match blocking(move || b.stop()).await {
        Ok(()) => Json(json!({ "ok": true })).into_response(),
        Err(r) => r.into_response(),
    }
}

/// `POST /browser/resume`
pub async fn resume(headers: HeaderMap, State(st): State<Arc<AppState>>) -> Response {
    let b = match worker(&headers, &st) {
        Ok(b) => b,
        Err(r) => return r.into_response(),
    };
    b.resume();
    Json(json!({ "ok": true })).into_response()
}

#[derive(Deserialize)]
pub struct AttachReq {
    port: u16,
    #[serde(default)]
    consent: bool,
}

/// `POST /browser/attach {port, consent}` — consent is the member's, for this session.
pub async fn attach(
    headers: HeaderMap,
    State(st): State<Arc<AppState>>,
    body: axum::body::Bytes,
) -> Response {
    let b = match worker(&headers, &st) {
        Ok(b) => b,
        Err(r) => return r.into_response(),
    };
    let Ok(req) = serde_json::from_slice::<AttachReq>(&body) else {
        return err(StatusCode::BAD_REQUEST, "expected {port, consent}");
    };
    if !req.consent {
        return err(
            StatusCode::BAD_REQUEST,
            "attaching to Chrome needs the member's explicit consent for this session",
        );
    }
    if req.port < 1024 {
        return err(
            StatusCode::BAD_REQUEST,
            "the remote debugging port must be 1024 or higher",
        );
    }
    match blocking(move || b.attach(req.port, true)).await {
        Ok(Ok(_)) => Json(json!({ "ok": true })).into_response(),
        Ok(Err(e)) => err(StatusCode::BAD_GATEWAY, e.to_string()),
        Err(r) => r.into_response(),
    }
}

/// `POST /browser/detach` — close Hermes's tab in the member's Chrome, forget every consent.
pub async fn detach(headers: HeaderMap, State(st): State<Arc<AppState>>) -> Response {
    let b = match worker(&headers, &st) {
        Ok(b) => b,
        Err(r) => return r.into_response(),
    };
    match blocking(move || b.detach()).await {
        Ok(()) => Json(json!({ "ok": true })).into_response(),
        Err(r) => r.into_response(),
    }
}

#[derive(Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct OriginReq {
    origin: String,
    allow: bool,
    #[serde(default)]
    include_sensitive: bool,
}

/// `POST /browser/origins {origin, allow, includeSensitive}` — consent to or revoke one origin.
pub async fn origins(
    headers: HeaderMap,
    State(st): State<Arc<AppState>>,
    body: axum::body::Bytes,
) -> Response {
    let b = match worker(&headers, &st) {
        Ok(b) => b,
        Err(r) => return r.into_response(),
    };
    let Ok(req) = serde_json::from_slice::<OriginReq>(&body) else {
        return err(
            StatusCode::BAD_REQUEST,
            "expected {origin, allow, includeSensitive}",
        );
    };
    if req.origin.len() > 2048 {
        return err(StatusCode::BAD_REQUEST, "origin is too long");
    }
    let r = if req.allow {
        b.allow_origin(&req.origin, req.include_sensitive)
    } else {
        b.revoke_origin(&req.origin)
    };
    match r {
        Ok(origin) => Json(json!({ "ok": true, "origin": origin })).into_response(),
        Err(e) => err(StatusCode::BAD_REQUEST, e),
    }
}

#[derive(Deserialize)]
pub struct DecideReq {
    id: String,
    allow: bool,
}

/// `POST /browser/actions/decide {id, allow}` — the member's decision on a waiting action.
pub async fn decide(
    headers: HeaderMap,
    State(st): State<Arc<AppState>>,
    body: axum::body::Bytes,
) -> Response {
    let b = match worker(&headers, &st) {
        Ok(b) => b,
        Err(r) => return r.into_response(),
    };
    let Ok(req) = serde_json::from_slice::<DecideReq>(&body) else {
        return err(StatusCode::BAD_REQUEST, "expected {id, allow}");
    };
    match b.decide(&req.id, req.allow) {
        Ok(()) => Json(json!({ "ok": true })).into_response(),
        Err(e) => err(StatusCode::CONFLICT, e),
    }
}
