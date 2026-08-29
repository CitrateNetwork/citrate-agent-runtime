//! The citrate-core agent sidecar — a bearer-authed loopback HTTP control plane over the
//! `citrate-agent-core` harness.
//!
//! citrate-core (`src-tauri/src/hermes.rs`) spawns this binary, hands it a control bind
//! (`CITRATE_HERMES_ADDR`) + a 0600 bearer-token file (`CITRATE_HERMES_TOKEN_FILE`), and drives it
//! over the frozen `AgentHarnessDomain` shape: `status`, `skills`, `runSkill`, `pendingApprovals`,
//! `stop` — plus an open `GET /health` for the supervisor. This crate is that control surface; the
//! capabilities beneath it (capsule/WASM skills, the ceremony-grade [`ApprovalQueue`], emergency
//! stop) already live in the workspace.
//!
//! Keyless by construction: nothing here signs. Every chain effect a skill wants becomes a **pending
//! approval** that citrate-core presents through its SignatureCeremony (origin `agent:hermes`). S6.2
//! (this) is the control plane + read surface; the capsule-run + ceremony bridge is S6.3, so
//! `runSkill` honestly refuses until then rather than run an effect no human has gated (Rule 1).
//!
//! NB — this is NOT `hermes/` (the Discord command-plane bot). Different program, distinct binary.

use std::sync::Arc;

use axum::{
    extract::State,
    http::{HeaderMap, StatusCode},
    routing::{get, post},
    Json, Router,
};
use serde::Serialize;

use citrate_agent_core::hitl::ApprovalQueue;
use citrate_agent_legacy::estop::EmergencyStop;

/// One installed skill (a capsule), surfaced to the `AgentHarnessDomain::skills` shape.
#[derive(Debug, Clone, Serialize)]
pub struct SkillView {
    pub name: String,
    pub description: String,
}

/// The sidecar's shared state: the emergency stop, the approval queue (the ceremony surface), the
/// loaded skill catalog, and the session bearer the control calls must present.
pub struct AppState {
    pub estop: EmergencyStop,
    pub queue: Arc<ApprovalQueue>,
    pub skills: Vec<SkillView>,
    pub bearer: String,
}

/// Load the capsule catalog (a skill per `<dir>/<name>/manifest.toml`). A missing dir is an honest
/// empty catalog, not an error — a fresh install simply has no skills yet.
pub fn load_skills(capsule_dir: &std::path::Path) -> Vec<SkillView> {
    let mut out = Vec::new();
    let Ok(entries) = std::fs::read_dir(capsule_dir) else {
        return out;
    };
    for e in entries.flatten() {
        let manifest = e.path().join("manifest.toml");
        if let Ok(text) = std::fs::read_to_string(&manifest) {
            if let Some(name) = toml_str(&text, "name") {
                let description = toml_str(&text, "description").unwrap_or_default();
                out.push(SkillView { name, description });
            }
        }
    }
    out.sort_by(|a, b| a.name.cmp(&b.name));
    out
}

/// Extract a `key = "value"` string from a manifest without a TOML dep (the fields we read are flat
/// quoted scalars). Robust to comments + section headers.
fn toml_str(text: &str, key: &str) -> Option<String> {
    for line in text.lines() {
        let line = line.trim();
        if line.starts_with('#') {
            continue;
        }
        if let Some(rest) = line.strip_prefix(key) {
            let rest = rest.trim_start();
            if let Some(rest) = rest.strip_prefix('=') {
                let v = rest.trim().trim_matches('"');
                if !v.is_empty() {
                    return Some(v.to_string());
                }
            }
        }
    }
    None
}

// ── the wire shapes (mirror AgentHarnessDomain) ───────────────────────────

#[derive(Serialize)]
struct StatusBody {
    running: bool,
    skills: usize,
    #[serde(rename = "pendingApprovals")]
    pending_approvals: usize,
}

#[derive(Serialize)]
struct ApprovalBody {
    id: String,
    kind: String,
    summary: String,
}

/// Build the control-plane router. `/health` is open (the supervisor probes it with no bearer);
/// every other route is bearer-gated.
pub fn app(state: Arc<AppState>) -> Router {
    Router::new()
        .route("/health", get(health))
        .route("/status", get(status))
        .route("/skills", get(skills))
        .route("/approvals", get(approvals))
        .route("/run_skill", post(run_skill))
        .route("/stop", post(stop))
        .with_state(state)
}

/// Constant-time-ish bearer check. Returns the guard result; `/health` skips it.
fn authorized(headers: &HeaderMap, bearer: &str) -> bool {
    headers
        .get("authorization")
        .and_then(|v| v.to_str().ok())
        .and_then(|v| v.strip_prefix("Bearer "))
        .map(|t| t.len() == bearer.len() && t.as_bytes().ct_eq(bearer.as_bytes()))
        .unwrap_or(false)
}

async fn health(State(st): State<Arc<AppState>>) -> Json<serde_json::Value> {
    Json(serde_json::json!({ "status": "ok", "stopped": st.estop.is_stopped() }))
}

async fn status(
    headers: HeaderMap,
    State(st): State<Arc<AppState>>,
) -> Result<Json<StatusBody>, StatusCode> {
    if !authorized(&headers, &st.bearer) {
        return Err(StatusCode::UNAUTHORIZED);
    }
    Ok(Json(StatusBody {
        running: !st.estop.is_stopped(),
        skills: st.skills.len(),
        pending_approvals: st.queue.depth(),
    }))
}

async fn skills(
    headers: HeaderMap,
    State(st): State<Arc<AppState>>,
) -> Result<Json<Vec<SkillView>>, StatusCode> {
    if !authorized(&headers, &st.bearer) {
        return Err(StatusCode::UNAUTHORIZED);
    }
    Ok(Json(st.skills.clone()))
}

async fn approvals(
    headers: HeaderMap,
    State(st): State<Arc<AppState>>,
) -> Result<Json<Vec<ApprovalBody>>, StatusCode> {
    if !authorized(&headers, &st.bearer) {
        return Err(StatusCode::UNAUTHORIZED);
    }
    // S6.2: the queue is empty until runSkill (S6.3) submits an effect; surface the head honestly.
    let mut out = Vec::new();
    if let Some(p) = st.queue.peek() {
        out.push(ApprovalBody {
            id: p.name.clone(),
            kind: p.risk_level.clone(),
            summary: p.description,
        });
    }
    Ok(Json(out))
}

async fn run_skill(
    headers: HeaderMap,
    State(st): State<Arc<AppState>>,
) -> Result<Json<serde_json::Value>, StatusCode> {
    if !authorized(&headers, &st.bearer) {
        return Err(StatusCode::UNAUTHORIZED);
    }
    // Rule 1: do NOT run an effect no human has gated. The capsule-run + ceremony bridge is S6.3.
    Err(StatusCode::NOT_IMPLEMENTED)
}

async fn stop(
    headers: HeaderMap,
    State(st): State<Arc<AppState>>,
) -> Result<Json<serde_json::Value>, StatusCode> {
    if !authorized(&headers, &st.bearer) {
        return Err(StatusCode::UNAUTHORIZED);
    }
    st.estop.trigger();
    Ok(Json(serde_json::json!({ "ok": true })))
}

// A tiny constant-time compare so the bearer isn't `==`'d.
trait CtEq {
    fn ct_eq(&self, other: &[u8]) -> bool;
}
impl CtEq for [u8] {
    fn ct_eq(&self, other: &[u8]) -> bool {
        if self.len() != other.len() {
            return false;
        }
        let mut diff = 0u8;
        for (a, b) in self.iter().zip(other.iter()) {
            diff |= a ^ b;
        }
        diff == 0
    }
}

#[cfg(test)]
mod tests;
