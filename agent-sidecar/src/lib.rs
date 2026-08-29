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
//! approval** that citrate-core presents through its SignatureCeremony (origin `agent:hermes`).
//! `runSkill` (S6.3 slice-2) runs the named capsule via `CapsuleDispatch::call_json` on a background
//! task and returns `{ok}` = accepted; any chain effect the skill attempts parks on the
//! [`QueuedApprovalGate`] and surfaces on the approval queue (`/approvals`) for a human — the sidecar
//! itself never signs or broadcasts (no eth-send dispatcher). Rule 1: it runs real capsules, gates
//! real effects; it does not fake a result.
//!
//! NB — this is NOT `hermes/` (the Discord command-plane bot). Different program, distinct binary.

use std::sync::Arc;

use axum::{
    extract::State,
    http::{HeaderMap, StatusCode},
    routing::{get, post},
    Json, Router,
};
use serde::{Deserialize, Serialize};

use citrate_agent_core::capsule::dispatch::CapsuleDispatch;
use citrate_agent_core::capsule::dispatcher::ApprovalGate;
use citrate_agent_core::capsule::prod_impls::QueuedApprovalGate;
use citrate_agent_core::hitl::ApprovalQueue;
use citrate_agent_legacy::estop::EmergencyStop;

/// One installed skill (a capsule), surfaced to the `AgentHarnessDomain::skills` shape.
#[derive(Debug, Clone, Serialize)]
pub struct SkillView {
    pub name: String,
    pub description: String,
}

/// The `runSkill(name, argsJson)` request body. `args` is a JSON object keyed by the capsule
/// function's WIT param names; `call_json` maps it to the typed `Val`s. Absent `args` = no-arg skill.
#[derive(Debug, Clone, Deserialize)]
pub struct RunSkillReq {
    pub name: String,
    #[serde(default)]
    pub args: serde_json::Value,
}

/// The sidecar's shared state: the emergency stop, the approval queue (the ceremony surface), the
/// loaded skill catalog, the capsule dispatch that actually runs a skill, and the session bearer the
/// control calls must present.
pub struct AppState {
    pub estop: EmergencyStop,
    pub queue: Arc<ApprovalQueue>,
    pub skills: Vec<SkillView>,
    /// The capsule execution fleet, loaded with the [`QueuedApprovalGate`] so EVERY chain effect a
    /// skill attempts parks on `queue` for human approval (the gD-hermes safety property). `None`
    /// when no capsule dir loaded (a fresh install, or an unreadable dir) — `runSkill` then refuses
    /// with 503 rather than pretend a skill ran.
    pub dispatch: Option<Arc<CapsuleDispatch>>,
    pub bearer: String,
}

/// Build the capsule dispatch for `capsule_dir`, wired with the [`QueuedApprovalGate`] over `queue`.
///
/// The sidecar is KEYLESS (Rule 3): it passes NO eth-call / eth-send dispatcher, so a skill's chain
/// reads/writes fail closed at the host boundary — the actual signing + broadcast is citrate-core's
/// SignatureCeremony, never the sidecar. What the sidecar DOES provide is the approval gate, so a
/// skill's chain effect surfaces on `queue` (via `/approvals`) exactly as the ceremony bridge expects.
/// A missing or unreadable capsule dir is an honest `None`, not a panic.
pub fn load_dispatch(
    capsule_dir: &std::path::Path,
    queue: Arc<ApprovalQueue>,
) -> Option<Arc<CapsuleDispatch>> {
    let gate: Arc<dyn ApprovalGate> = Arc::new(QueuedApprovalGate::new(queue));
    match CapsuleDispatch::load_from_dir(capsule_dir, None, None, Some(gate)) {
        Ok(d) => Some(Arc::new(d)),
        Err(e) => {
            eprintln!("[citrate-agent-sidecar] no capsule dispatch ({capsule_dir:?}): {e}");
            None
        }
    }
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
    /// The raw chain-call target + calldata for a chain effect, so citrate-core's ceremony can build
    /// the `SignatureIntent` and sign+broadcast it (the keyless bridge). `None` for non-chain effects
    /// (code/shell). Parsed from the pending call's args (`{to, data_hex}`).
    #[serde(skip_serializing_if = "Option::is_none")]
    to: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    data: Option<String>,
}

/// Build the control-plane router. `/health` is open (the supervisor probes it with no bearer);
/// every other route is bearer-gated.
pub fn app(state: Arc<AppState>) -> Router {
    Router::new()
        .route("/health", get(health))
        .route("/status", get(status))
        .route("/skills", get(skills))
        .route("/approvals", get(approvals))
        .route("/approvals/approve", post(approve_head))
        .route("/approvals/reject", post(reject_head))
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
        // A chain effect's args carry the raw target + calldata ({to, data_hex}); expose them so
        // citrate-core's ceremony can build the SignatureIntent. Non-chain effects have neither.
        let args: serde_json::Value = serde_json::from_str(&p.args_pretty).unwrap_or_default();
        let to = args.get("to").and_then(|v| v.as_str()).map(str::to_string);
        let data = args
            .get("data_hex")
            .and_then(|v| v.as_str())
            .map(str::to_string);
        out.push(ApprovalBody {
            id: p.name.clone(),
            kind: p.risk_level.clone(),
            summary: p.description,
            to,
            data,
        });
    }
    Ok(Json(out))
}

/// S6.3 — the CEREMONY BRIDGE (approve half). citrate-core's SignatureCeremony, once the human
/// approves the head pending approval, calls this to resolve it. The queue is a FIFO; approving the
/// head unblocks the capsule host-fn that submitted it, which then performs the eth-send. Honest:
/// approving an empty queue is a no-op (nothing was pending), reported as such.
async fn approve_head(
    headers: HeaderMap,
    State(st): State<Arc<AppState>>,
) -> Result<Json<serde_json::Value>, StatusCode> {
    if !authorized(&headers, &st.bearer) {
        return Err(StatusCode::UNAUTHORIZED);
    }
    let had = st.queue.depth() > 0;
    st.queue.approve();
    Ok(Json(serde_json::json!({ "ok": true, "resolved": had })))
}

/// S6.3 — the ceremony bridge (reject half). The human declined the head approval; the submitting
/// host-fn gets `Err`, so the chain effect is NOT performed.
async fn reject_head(
    headers: HeaderMap,
    State(st): State<Arc<AppState>>,
) -> Result<Json<serde_json::Value>, StatusCode> {
    if !authorized(&headers, &st.bearer) {
        return Err(StatusCode::UNAUTHORIZED);
    }
    let had = st.queue.depth() > 0;
    st.queue.reject();
    Ok(Json(serde_json::json!({ "ok": true, "resolved": had })))
}

async fn run_skill(
    headers: HeaderMap,
    State(st): State<Arc<AppState>>,
    body: axum::body::Bytes,
) -> Result<Json<serde_json::Value>, StatusCode> {
    if !authorized(&headers, &st.bearer) {
        return Err(StatusCode::UNAUTHORIZED);
    }
    // Body is `{ "name": "<skill>", "args": { <wit-param>: <json> , ... } }` — the frozen
    // AgentHarnessDomain runSkill(name, argsJson) shape. Parse AFTER auth (Bytes never rejects) so a
    // missing bearer is a clean 401, not a 400.
    let req: RunSkillReq = serde_json::from_slice(&body).map_err(|_| StatusCode::BAD_REQUEST)?;

    // Fail closed while stopped: the estop is the operator's kill switch; do not start new skills.
    if st.estop.is_stopped() {
        return Err(StatusCode::SERVICE_UNAVAILABLE);
    }
    // A skill must be an installed capsule, and the dispatch must have loaded (Rule 1: no pretending).
    let Some(dispatch) = st.dispatch.clone() else {
        return Err(StatusCode::SERVICE_UNAVAILABLE);
    };
    if !st.skills.iter().any(|s| s.name == req.name) {
        return Err(StatusCode::NOT_FOUND);
    }

    // Run the capsule on a background task and return {ok} = ACCEPTED, not the result. This is
    // required, not a shortcut: any chain effect the skill attempts blocks inside the ApprovalGate
    // (`block_in_place`) until a human resolves it via /approvals, so it CANNOT run inline in the
    // handler. Its result / error is logged; a chain effect surfaces on the queue meanwhile.
    // `block_in_place` also releases this worker during the (epoch-bounded) wasm compute — needs the
    // multi-thread runtime `#[tokio::main]` gives us.
    let name = req.name.clone();
    let args = req.args.clone();
    tokio::spawn(async move {
        let outcome = tokio::task::block_in_place(|| dispatch.call_json(&name, &args));
        match outcome {
            Ok(v) => eprintln!("[citrate-agent-sidecar] skill {name:?} finished: {v}"),
            Err(e) => eprintln!("[citrate-agent-sidecar] skill {name:?} failed: {e}"),
        }
    });

    Ok(Json(serde_json::json!({
        "ok": true,
        "submitted": true,
        "skill": req.name,
    })))
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
