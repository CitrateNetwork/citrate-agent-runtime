//! HUP-S2.9 — the undo routes over the checkpoint store. Bearer-gated like every control route;
//! citrate-core calls them when the member presses Undo. Undo is a member action, never a tool.
//!
//! - `GET  /checkpoints/:session`                 the session's steps, newest first
//! - `POST /checkpoints/:session/steps/:seq/undo` undo one step
//! - `POST /checkpoints/:session/undo`            undo every step not undone yet (all or nothing)
//! - `GET  /checkpoints/:session/steps/:seq/diff` HUP-S5.4: what one step changed, path by path,
//!   for the Code and diff pop-out (read-only; text up to 256 KiB per side, binary and larger
//!   files described, the after side only while the file still holds the step's result)
//!
//! A refusal is a JSON body `{error, kind, conflicts?}`: `kind` is `disabled` (503, no store
//! configured), `invalid` (400), `not_found` (404), `pruned` (410), `conflict`, `busy` or
//! `already_undone` (409), or `failed` (500). `error` is the reason in words, shown as is.
//! A conflict lists every path that changed since the step, and nothing was restored.

use std::sync::Arc;

use axum::{
    extract::{Path, State},
    http::{HeaderMap, StatusCode},
    Json,
};
use citrate_agent_checkpoints::{
    CheckpointStore, Error, SessionId, StepSummary, UndoReport, DEFAULT_MAX_SIDE_BYTES,
};

use crate::{authorized, AppState};

type Reply = (StatusCode, Json<serde_json::Value>);

fn refusal(code: StatusCode, kind: &str, error: &str) -> Reply {
    (
        code,
        Json(serde_json::json!({ "error": error, "kind": kind })),
    )
}

fn from_error(e: Error) -> Reply {
    let msg = e.to_string();
    match e {
        Error::Conflict(list) => {
            let conflicts: Vec<serde_json::Value> = list
                .iter()
                .map(|c| serde_json::json!({ "seq": c.seq, "path": c.path, "found": c.found }))
                .collect();
            (
                StatusCode::CONFLICT,
                Json(
                    serde_json::json!({ "error": msg, "kind": "conflict", "conflicts": conflicts }),
                ),
            )
        }
        Error::Busy { .. } => refusal(StatusCode::CONFLICT, "busy", &msg),
        Error::AlreadyUndone { .. } => refusal(StatusCode::CONFLICT, "already_undone", &msg),
        Error::NotFound { .. } => refusal(StatusCode::NOT_FOUND, "not_found", &msg),
        Error::Pruned { .. } => refusal(StatusCode::GONE, "pruned", &msg),
        Error::InvalidSession(_) => refusal(StatusCode::BAD_REQUEST, "invalid", &msg),
        _ => refusal(StatusCode::INTERNAL_SERVER_ERROR, "failed", &msg),
    }
}

fn step_json(s: &StepSummary) -> serde_json::Value {
    serde_json::json!({
        "seq": s.seq,
        "status": s.status,
        "paths": s.paths,
        "root": s.root.to_string_lossy(),
    })
}

fn report_json(r: &UndoReport) -> serde_json::Value {
    serde_json::json!({
        "undone": r.steps,
        "restored": r.restored,
        "prunedThrough": r.pruned_through,
    })
}

/// Auth, the store, and a valid session id, or the refusal to send.
fn prepare(
    headers: &HeaderMap,
    st: &AppState,
    session: &str,
) -> Result<(Arc<CheckpointStore>, SessionId), Reply> {
    if !authorized(headers, &st.bearer) {
        return Err(refusal(
            StatusCode::UNAUTHORIZED,
            "unauthorized",
            "unauthorized",
        ));
    }
    let store = st.sessions.checkpoints().ok_or_else(|| {
        refusal(
            StatusCode::SERVICE_UNAVAILABLE,
            "disabled",
            "undo checkpoints are not enabled in this agent sidecar",
        )
    })?;
    let sid = SessionId::new(session).map_err(from_error)?;
    Ok((store, sid))
}

/// Run a store operation off the async runtime (it does file I/O).
async fn blocking<T: Send + 'static>(
    f: impl FnOnce() -> Result<T, Error> + Send + 'static,
) -> Result<T, Reply> {
    match tokio::task::spawn_blocking(f).await {
        Ok(r) => r.map_err(from_error),
        Err(_) => Err(refusal(
            StatusCode::INTERNAL_SERVER_ERROR,
            "failed",
            "the undo task did not finish",
        )),
    }
}

pub(crate) async fn list_steps(
    headers: HeaderMap,
    State(st): State<Arc<AppState>>,
    Path(session): Path<String>,
) -> Result<Json<serde_json::Value>, Reply> {
    let (store, sid) = prepare(&headers, &st, &session)?;
    let name = sid.as_str().to_string();
    let mut steps = blocking(move || store.steps(&sid)).await?;
    steps.reverse();
    Ok(Json(serde_json::json!({
        "session": name,
        "steps": steps.iter().map(step_json).collect::<Vec<_>>(),
    })))
}

fn positive_seq(seq: &str) -> Result<u64, Reply> {
    seq.parse().ok().filter(|n| *n > 0).ok_or_else(|| {
        refusal(
            StatusCode::BAD_REQUEST,
            "invalid",
            "the step must be a positive whole number",
        )
    })
}

/// HUP-S5.4: `GET /checkpoints/:session/steps/:seq/diff`.
pub(crate) async fn step_diff(
    headers: HeaderMap,
    State(st): State<Arc<AppState>>,
    Path((session, seq)): Path<(String, String)>,
) -> Result<Json<serde_json::Value>, Reply> {
    let (store, sid) = prepare(&headers, &st, &session)?;
    let seq = positive_seq(&seq)?;
    let d = blocking(move || store.step_diff(&sid, seq, DEFAULT_MAX_SIDE_BYTES)).await?;
    serde_json::to_value(&d).map(Json).map_err(|_| {
        refusal(
            StatusCode::INTERNAL_SERVER_ERROR,
            "failed",
            "the diff could not be encoded",
        )
    })
}

pub(crate) async fn undo_step(
    headers: HeaderMap,
    State(st): State<Arc<AppState>>,
    Path((session, seq)): Path<(String, String)>,
) -> Result<Json<serde_json::Value>, Reply> {
    let (store, sid) = prepare(&headers, &st, &session)?;
    let seq = positive_seq(&seq)?;
    let report = blocking(move || store.undo_step(&sid, seq)).await?;
    Ok(Json(report_json(&report)))
}

pub(crate) async fn undo_session(
    headers: HeaderMap,
    State(st): State<Arc<AppState>>,
    Path(session): Path<String>,
) -> Result<Json<serde_json::Value>, Reply> {
    let (store, sid) = prepare(&headers, &st, &session)?;
    let report = blocking(move || store.undo_session(&sid)).await?;
    Ok(Json(report_json(&report)))
}
