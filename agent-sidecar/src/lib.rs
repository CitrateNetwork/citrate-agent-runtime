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

pub mod grants;
pub mod llm_http;
pub mod sessions;
pub mod toolchain;

use std::sync::Arc;

use axum::{
    extract::{Path, Query, State},
    http::{HeaderMap, StatusCode},
    routing::{delete, get, post},
    Json, Router,
};
use serde::{Deserialize, Serialize};

use citrate_agent_core::capsule::allowlist::FleetAllowlist;
use citrate_agent_core::capsule::dispatch::CapsuleDispatch;
use citrate_agent_core::capsule::dispatcher::ApprovalGate;
use citrate_agent_core::capsule::prod_impls::QueuedApprovalGate;
use citrate_agent_core::hitl::ApprovalQueue;
use citrate_agent_legacy::estop::EmergencyStop;
use citrate_agent_loop::interview;

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
    /// PBA-L6b-032: bounds concurrently running skills. Each `run_skill` holds one permit for the
    /// life of its background task; when none is free the request is refused with 429 instead of
    /// piling up blocked workers.
    pub run_slots: Arc<tokio::sync::Semaphore>,
    /// HUP-S1.1b: Hermes's agent sessions (the turn loop runs here; core hosts the gated tools).
    pub sessions: Arc<sessions::SessionManager>,
}

/// PBA-L6b-032: at most this many skills run at once.
pub const MAX_CONCURRENT_SKILLS: usize = 4;

/// Build the capsule dispatch for `capsule_dir`, wired with the [`QueuedApprovalGate`] over `queue`.
///
/// The sidecar is KEYLESS (Rule 3): it passes NO eth-call / eth-send dispatcher, so a skill's chain
/// reads/writes fail closed at the host boundary — the actual signing + broadcast is citrate-core's
/// SignatureCeremony, never the sidecar. What the sidecar DOES provide is the approval gate, so a
/// skill's tier-low chain effect surfaces on `queue` (via `/approvals`) exactly as the ceremony bridge
/// expects. PBA-L6b-012 / PBA-L6b-032: the gate binds no invoking human and the sidecar exposes no
/// quorum-signature route, so a tier>=medium effect is refused at once rather than parked where
/// nobody can approve it.
/// A missing or unreadable capsule dir is an honest `None`, not a panic.
pub fn load_dispatch(
    capsule_dir: &std::path::Path,
    queue: Arc<ApprovalQueue>,
) -> Option<Arc<CapsuleDispatch>> {
    load_dispatch_with_allowlist(capsule_dir, &FleetAllowlist::bundled(), queue)
}

/// [`load_dispatch`] against an explicit fleet allowlist (PBA-L6b-015 test fixtures). Production
/// uses the compiled-in [`FleetAllowlist::bundled`] via `load_dispatch`.
pub(crate) fn load_dispatch_with_allowlist(
    capsule_dir: &std::path::Path,
    allowlist: &FleetAllowlist,
    queue: Arc<ApprovalQueue>,
) -> Option<Arc<CapsuleDispatch>> {
    let gate: Arc<dyn ApprovalGate> = Arc::new(QueuedApprovalGate::new(queue));
    match CapsuleDispatch::load_from_dir_with_allowlist(
        capsule_dir,
        allowlist,
        None,
        None,
        Some(gate),
    ) {
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
    /// PBA-L6b-032: role-track (quorum) actions pending, which `/approvals` does not list.
    #[serde(rename = "rolePendingApprovals")]
    role_pending_approvals: usize,
    /// PBA-L6b-032: skills currently running.
    #[serde(rename = "runningSkills")]
    running_skills: usize,
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

/// AR-B-024 — refuse a non-loopback control bind unless explicitly opted in.
/// The sidecar's control plane is a bearer-authed LOOPBACK plane by contract; a
/// stray `0.0.0.0` bind would put only the bearer between an attacker and
/// `run_skill`/`approve`. Requires the host of `addr` to be a loopback IP
/// literal; a routable IP or a hostname is rejected. `allow_nonloopback`
/// (wired to `CITRATE_HERMES_ALLOW_NONLOOPBACK=1`) is the deliberate override.
pub fn enforce_loopback_bind(addr: &str, allow_nonloopback: bool) -> Result<(), String> {
    if allow_nonloopback {
        return Ok(());
    }
    // Split host:port from the right so IPv6 literals ([::1]:port) work.
    let host = match addr.rsplit_once(':') {
        Some((h, _)) => h.trim_matches(|c| c == '[' || c == ']'),
        None => addr,
    };
    match host.parse::<std::net::IpAddr>() {
        Ok(ip) if ip.is_loopback() => Ok(()),
        Ok(ip) => Err(format!(
            "refusing to bind non-loopback control address {ip} (CITRATE_HERMES_ADDR={addr}); \
             the sidecar control plane is loopback-only. Set \
             CITRATE_HERMES_ALLOW_NONLOOPBACK=1 to override deliberately."
        )),
        Err(_) => Err(format!(
            "CITRATE_HERMES_ADDR host {host:?} is not an IP literal; bind an explicit loopback \
             address (127.0.0.1 / [::1]) so the bind cannot silently resolve off-loopback."
        )),
    }
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
        // HUP-S1.1b — agent sessions (ADR loop-in-sidecar).
        .route("/sessions", post(create_session))
        .route("/sessions/:id", delete(close_session))
        .route("/sessions/:id/messages", post(send_message))
        .route("/sessions/:id/events", get(session_events))
        .route("/sessions/:id/tool_results", post(tool_results))
        .route("/sessions/:id/stop", post(stop_session))
        .route("/sessions/:id/grants", post(replace_grants))
        // HUP-S1.4 — tracks + briefs (the interview every client shares).
        .route("/tracks", get(tracks))
        .route("/briefs", post(create_brief))
        .route("/briefs/check", post(check_brief))
        // HUP-S4.1: the configured MCP servers (read-only status).
        .route("/mcp/servers", get(mcp_servers))
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

async fn health(State(_st): State<Arc<AppState>>) -> Json<serde_json::Value> {
    // AR-B-024: `/health` is unauthenticated (the supervisor probes it with no
    // bearer). It reports liveness only — the emergency-stop state is
    // operational information and is exposed on the bearer-gated `/status`
    // route (`running`), never here.
    Json(serde_json::json!({ "status": "ok" }))
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
        role_pending_approvals: st.queue.role_pending_depth(),
        running_skills: MAX_CONCURRENT_SKILLS.saturating_sub(st.run_slots.available_permits()),
    }))
}

/// HUP-S4.1: `{configured, servers}`. Never the URL, env, or the servers' instructions text.
async fn mcp_servers(
    headers: HeaderMap,
    State(st): State<Arc<AppState>>,
) -> Result<Json<serde_json::Value>, StatusCode> {
    if !authorized(&headers, &st.bearer) {
        return Err(StatusCode::UNAUTHORIZED);
    }
    let body = match st.sessions.mcp_status() {
        Some(list) => serde_json::json!({ "configured": true, "servers": list }),
        None => serde_json::json!({ "configured": false, "servers": [] }),
    };
    Ok(Json(body))
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
    // PBA-L6b-010: the approval surface is closed while the e-stop is engaged.
    if st.estop.is_stopped() {
        return Err(StatusCode::SERVICE_UNAVAILABLE);
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
            // AR-B-023: expose the stable call-id (not the tool name) so the
            // ceremony can assert "I am approving *this* call" when it posts
            // back to /approvals/approve.
            id: p.id.clone(),
            kind: p.risk_level.clone(),
            summary: p.description,
            to,
            data,
        });
    }
    Ok(Json(out))
}

/// S6.3 — the CEREMONY BRIDGE (approve half). citrate-core's SignatureCeremony, once the human
/// approves a pending approval, calls this with `{"id": "<call_id>"}` to resolve it. Approving
/// unblocks the capsule host-fn that submitted it.
///
/// AR-B-023 / PBA-L6b-009: the approval is BOUND to the call-id the human reviewed.
/// * No `id` (empty body, `{}`, non-string id, malformed JSON) → 400; nothing is resolved. The
///   legacy "approve whatever is at the FIFO head" path is gone.
/// * The id is not the current head (a timeout eviction or a second queued effect changed the
///   head), or its submitter already stopped waiting → 409 CONFLICT; nothing runs.
async fn approve_head(
    headers: HeaderMap,
    State(st): State<Arc<AppState>>,
    body: axum::body::Bytes,
) -> Result<Json<serde_json::Value>, StatusCode> {
    if !authorized(&headers, &st.bearer) {
        return Err(StatusCode::UNAUTHORIZED);
    }
    resolve_body(&st, &body, true)
}

/// S6.3 — the ceremony bridge (reject half). The human declined the head approval; the submitting
/// host-fn gets `Err`, so the chain effect is NOT performed. See [`approve_head`] for the call-id
/// binding (AR-B-023).
async fn reject_head(
    headers: HeaderMap,
    State(st): State<Arc<AppState>>,
    body: axum::body::Bytes,
) -> Result<Json<serde_json::Value>, StatusCode> {
    if !authorized(&headers, &st.bearer) {
        return Err(StatusCode::UNAUTHORIZED);
    }
    resolve_body(&st, &body, false)
}

/// Extract the call-id the human reviewed from an approve/reject body. `None` for anything that is
/// not a JSON object carrying a non-empty string `id` (PBA-L6b-009).
fn requested_call_id(body: &[u8]) -> Option<String> {
    let v: serde_json::Value = serde_json::from_slice(body).ok()?;
    let id = v.get("id")?.as_str()?;
    (!id.is_empty()).then(|| id.to_string())
}

/// Shared approve/reject resolution, always bound to a call-id (AR-B-023 / PBA-L6b-009).
fn resolve_body(
    st: &Arc<AppState>,
    body: &[u8],
    approve: bool,
) -> Result<Json<serde_json::Value>, StatusCode> {
    // PBA-L6b-010: no approval can be resolved after the operator pulled the kill switch.
    if st.estop.is_stopped() {
        return Err(StatusCode::SERVICE_UNAVAILABLE);
    }
    let id = requested_call_id(body).ok_or(StatusCode::BAD_REQUEST)?;
    let res = if approve {
        st.queue.approve_by_id(&id)
    } else {
        st.queue.reject_by_id(&id)
    };
    match res {
        Ok(()) => Ok(Json(serde_json::json!({ "ok": true, "resolved": true }))),
        // The head is not the call the operator reviewed, or its submitter is gone — refuse.
        Err(_) => Err(StatusCode::CONFLICT),
    }
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
    // PBA-L6b-032: bounded concurrency. The permit moves into the task and is released when the
    // skill finishes (or is refused), so a burst of run_skill cannot pin every worker.
    let permit = st
        .run_slots
        .clone()
        .try_acquire_owned()
        .map_err(|_| StatusCode::TOO_MANY_REQUESTS)?;

    // Run the capsule on a background task and return {ok} = ACCEPTED, not the result. This is
    // required, not a shortcut: any chain effect the skill attempts blocks inside the ApprovalGate
    // (`block_in_place`) until a human resolves it via /approvals, so it CANNOT run inline in the
    // handler. Its result / error is logged; a chain effect surfaces on the queue meanwhile.
    // `block_in_place` also releases this worker during the (epoch-bounded) wasm compute — needs the
    // multi-thread runtime `#[tokio::main]` gives us.
    let name = req.name.clone();
    let args = req.args.clone();
    // AR-B-030: re-check the e-stop inside the task, immediately before running
    // the capsule. The check above races a /stop that lands between accept and
    // execution start; without this re-check an in-flight skill would begin
    // executing after the kill switch was engaged. (Interrupting a call already
    // in progress needs host-fn-level hooks — tracked separately.)
    let estop = st.estop.clone();
    tokio::spawn(async move {
        let _permit = permit;
        if estop.is_stopped() {
            eprintln!(
                "[citrate-agent-sidecar] skill {name:?} aborted: e-stop engaged before start"
            );
            return;
        }
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
    // HUP-S1.1b: the kill switch halts every agent session too.
    st.sessions.stop_all();
    // PBA-L6b-010: freeze + drain the approval queue so nothing parked before the stop can be
    // released after it, and running skills cannot queue new effects.
    let drained = st.queue.freeze_and_drain();
    Ok(Json(serde_json::json!({ "ok": true, "drained": drained })))
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

// ── HUP-S1.1b: agent session routes ─────────────────────────────────────

fn session_status(e: &sessions::SessionError) -> StatusCode {
    match e {
        sessions::SessionError::NotFound => StatusCode::NOT_FOUND,
        sessions::SessionError::Busy => StatusCode::CONFLICT,
        sessions::SessionError::TooMany => StatusCode::TOO_MANY_REQUESTS,
        sessions::SessionError::Invalid(_) => StatusCode::BAD_REQUEST,
        sessions::SessionError::NoGrants => StatusCode::CONFLICT,
    }
}

async fn create_session(
    headers: HeaderMap,
    State(st): State<Arc<AppState>>,
    body: axum::body::Bytes,
) -> Result<(StatusCode, Json<serde_json::Value>), (StatusCode, Json<serde_json::Value>)> {
    let err = |c: StatusCode, m: &str| (c, Json(serde_json::json!({ "error": m })));
    if !authorized(&headers, &st.bearer) {
        return Err(err(StatusCode::UNAUTHORIZED, "unauthorized"));
    }
    if st.estop.is_stopped() {
        return Err(err(
            StatusCode::SERVICE_UNAVAILABLE,
            "emergency stop engaged",
        ));
    }
    let req: sessions::CreateSessionReq = serde_json::from_slice(&body).map_err(|e| {
        err(
            StatusCode::BAD_REQUEST,
            &format!("bad session request: {e}"),
        )
    })?;
    match st.sessions.create(req) {
        Ok(id) => Ok((StatusCode::CREATED, Json(serde_json::json!({ "id": id })))),
        Err(e) => {
            let msg = match &e {
                sessions::SessionError::Invalid(m) => m.clone(),
                sessions::SessionError::TooMany => {
                    format!("at most {} sessions", sessions::MAX_SESSIONS)
                }
                _ => "refused".into(),
            };
            Err(err(session_status(&e), &msg))
        }
    }
}

#[derive(Deserialize)]
struct MessageReq {
    text: String,
}

async fn send_message(
    headers: HeaderMap,
    State(st): State<Arc<AppState>>,
    Path(id): Path<String>,
    body: axum::body::Bytes,
) -> Result<(StatusCode, Json<serde_json::Value>), StatusCode> {
    if !authorized(&headers, &st.bearer) {
        return Err(StatusCode::UNAUTHORIZED);
    }
    if st.estop.is_stopped() {
        return Err(StatusCode::SERVICE_UNAVAILABLE);
    }
    let req: MessageReq = serde_json::from_slice(&body).map_err(|_| StatusCode::BAD_REQUEST)?;
    st.sessions
        .send(&id, req.text, st.dispatch.clone())
        .map_err(|e| session_status(&e))?;
    Ok((
        StatusCode::ACCEPTED,
        Json(serde_json::json!({ "ok": true, "accepted": true })),
    ))
}

#[derive(Deserialize)]
struct EventsQuery {
    #[serde(default)]
    after: u64,
    #[serde(default)]
    wait_ms: u64,
}

async fn session_events(
    headers: HeaderMap,
    State(st): State<Arc<AppState>>,
    Path(id): Path<String>,
    Query(q): Query<EventsQuery>,
) -> Result<Json<sessions::EventsPage>, StatusCode> {
    if !authorized(&headers, &st.bearer) {
        return Err(StatusCode::UNAUTHORIZED);
    }
    let session = st.sessions.get(&id).ok_or(StatusCode::NOT_FOUND)?;
    let wait = std::time::Duration::from_millis(q.wait_ms.min(sessions::MAX_WAIT_MS));
    Ok(Json(session.wait_events(q.after, wait).await))
}

async fn tool_results(
    headers: HeaderMap,
    State(st): State<Arc<AppState>>,
    Path(id): Path<String>,
    body: axum::body::Bytes,
) -> Result<Json<serde_json::Value>, StatusCode> {
    if !authorized(&headers, &st.bearer) {
        return Err(StatusCode::UNAUTHORIZED);
    }
    let session = st.sessions.get(&id).ok_or(StatusCode::NOT_FOUND)?;
    let req: sessions::ToolResultReq =
        serde_json::from_slice(&body).map_err(|_| StatusCode::BAD_REQUEST)?;
    let call_id = req.call_id.clone();
    let outcome = sessions::outcome_from(req).map_err(|e| session_status(&e))?;
    if session.deliver(&call_id, outcome) {
        Ok(Json(serde_json::json!({ "ok": true, "delivered": true })))
    } else {
        // Nothing is waiting for that call (already answered, timed out, or never asked).
        Err(StatusCode::CONFLICT)
    }
}

async fn stop_session(
    headers: HeaderMap,
    State(st): State<Arc<AppState>>,
    Path(id): Path<String>,
) -> Result<Json<serde_json::Value>, StatusCode> {
    if !authorized(&headers, &st.bearer) {
        return Err(StatusCode::UNAUTHORIZED);
    }
    st.sessions.stop(&id).map_err(|e| session_status(&e))?;
    Ok(Json(serde_json::json!({ "ok": true, "stopped": true })))
}

/// HUP-S2.1: replace a session's folder grants with the member's current grant document (sent by
/// citrate-core whenever the member grants, revokes, or a full-access window is turned on). A
/// refused document answers 400 and leaves the session with no grants; a session opened without a
/// document answers 409.
async fn replace_grants(
    headers: HeaderMap,
    State(st): State<Arc<AppState>>,
    Path(id): Path<String>,
    body: axum::body::Bytes,
) -> Result<Json<serde_json::Value>, JsonErr> {
    if !authorized(&headers, &st.bearer) {
        return Err(json_err(StatusCode::UNAUTHORIZED, "unauthorized"));
    }
    let session = st
        .sessions
        .get(&id)
        .ok_or_else(|| json_err(StatusCode::NOT_FOUND, "no such session"))?;
    let doc: serde_json::Value = serde_json::from_slice(&body)
        .map_err(|_| json_err(StatusCode::BAD_REQUEST, "the body must be a grant document"))?;
    match session.replace_grants(&doc) {
        Ok(summary) => Ok(Json(serde_json::json!({ "ok": true, "grants": summary }))),
        Err(e) => {
            let msg = match &e {
                sessions::SessionError::Invalid(m) => m.clone(),
                sessions::SessionError::NoGrants => {
                    "this session was opened without folder grants".into()
                }
                _ => "refused".into(),
            };
            Err(json_err(session_status(&e), &msg))
        }
    }
}

async fn close_session(
    headers: HeaderMap,
    State(st): State<Arc<AppState>>,
    Path(id): Path<String>,
) -> Result<Json<serde_json::Value>, StatusCode> {
    if !authorized(&headers, &st.bearer) {
        return Err(StatusCode::UNAUTHORIZED);
    }
    st.sessions.close(&id).map_err(|e| session_status(&e))?;
    Ok(Json(serde_json::json!({ "ok": true, "closed": true })))
}

/// HUP-S3.2: parse `CITRATE_HERMES_SKILLS` — a platform path list (`:` on unix, `;` on windows)
/// of skill directories in precedence order (first wins). Empty entries are skipped.
pub fn skill_sources_from_env(value: &str) -> Vec<citrate_agent_loop::skills::SkillSource> {
    if value.trim().is_empty() {
        return Vec::new();
    }
    std::env::split_paths(value)
        .filter(|p| !p.as_os_str().is_empty())
        .enumerate()
        .map(|(i, p)| {
            let tail = p
                .file_name()
                .map(|n| n.to_string_lossy().into_owned())
                .unwrap_or_default();
            citrate_agent_loop::skills::SkillSource::new(format!("{}:{tail}", i + 1), p)
        })
        .collect()
}

/// HUP-S3.2: load the skills library named by `CITRATE_HERMES_SKILLS` (default off → `None`).
/// What was refused or shadowed is logged to stderr for the operator, never sent to the model.
pub fn skills_from_env() -> Option<Arc<citrate_agent_loop::skills::SkillLibrary>> {
    let value = std::env::var("CITRATE_HERMES_SKILLS").ok()?;
    let sources = skill_sources_from_env(&value);
    if sources.is_empty() {
        return None;
    }
    let lib = citrate_agent_loop::skills::SkillLibrary::load(&sources);
    for r in &lib.report().rejected {
        eprintln!(
            "citrate-agent-sidecar: skill refused: {}: {}",
            r.path.display(),
            r.reason
        );
    }
    for s in &lib.report().shadowed {
        eprintln!(
            "citrate-agent-sidecar: skill '{}' from {} is shadowed by {}",
            s.name, s.dropped_source, s.kept_source
        );
    }
    eprintln!(
        "citrate-agent-sidecar: {} instruction skills loaded",
        lib.len()
    );
    Some(Arc::new(lib))
}

/// HUP-S4.1: read and validate an MCP allowlist file and connect to its servers. `Ok(None)` for
/// an allowlist with no servers. Blocking (spawns processes, runs handshakes): call it off the
/// async runtime. A server that fails to start is reported in its status, not here.
pub fn mcp_from_path(
    path: &std::path::Path,
) -> Result<Option<Arc<citrate_agent_mcp_host::McpHost>>, String> {
    let cfg = citrate_agent_mcp_host::config::McpConfig::load(path)?;
    if cfg.servers.is_empty() {
        return Ok(None);
    }
    Ok(Some(Arc::new(citrate_agent_mcp_host::McpHost::connect(
        &cfg,
    ))))
}

/// HUP-S4.1: the MCP host named by `CITRATE_HERMES_MCP` (default unset → `None`, no MCP). An
/// invalid file is logged to stderr and yields no MCP (fail closed); the sidecar still runs.
pub fn mcp_from_env() -> Option<Arc<citrate_agent_mcp_host::McpHost>> {
    let value = std::env::var(citrate_agent_mcp_host::config::MCP_CONFIG_ENV).ok()?;
    if value.trim().is_empty() {
        return None;
    }
    match mcp_from_path(std::path::Path::new(&value)) {
        Ok(Some(host)) => {
            for s in host.status() {
                eprintln!(
                    "citrate-agent-sidecar: MCP server '{}' ({}): {:?}, {} tools{}",
                    s.name,
                    s.transport,
                    s.state,
                    s.tools,
                    s.error.map(|e| format!(", {e}")).unwrap_or_default()
                );
            }
            Some(host)
        }
        Ok(None) => None,
        Err(e) => {
            eprintln!("citrate-agent-sidecar: MCP disabled: {e}");
            None
        }
    }
}

/// Production session manager: OpenAI-compatible HTTP model client, 5-minute model and core-tool
/// deadlines (matching citrate-core's AI request bound), plus the skills library when
/// `CITRATE_HERMES_SKILLS` is set and the toolchain tools when `CITRATE_HERMES_TOOLCHAIN=1`.
pub fn production_sessions() -> Arc<sessions::SessionManager> {
    production_sessions_with(None)
}

/// [`production_sessions`] plus the MCP host when one is configured (HUP-S4.1).
pub fn production_sessions_with(
    mcp: Option<Arc<citrate_agent_mcp_host::McpHost>>,
) -> Arc<sessions::SessionManager> {
    let timeout = std::time::Duration::from_secs(300);
    let mgr = sessions::SessionManager::new(
        Arc::new(move |ep: &sessions::LlmEndpoint| {
            Arc::new(llm_http::OpenAiCompatClient::new(
                &ep.base_url,
                &ep.bearer,
                timeout,
            )) as Arc<dyn citrate_agent_loop::LlmClient>
        }),
        timeout,
    );
    // HUP-S2.1: grants are resolved against the member's home (the sidecar runs as the member).
    let mgr = match std::env::var_os("HOME").filter(|h| !h.is_empty()) {
        Some(home) => mgr.with_grants_home(std::path::PathBuf::from(home)),
        None => mgr,
    };
    let mgr = match skills_from_env() {
        Some(lib) => mgr.with_skills(lib),
        None => mgr,
    };
    let mgr = match toolchain_from_env() {
        Some(host) => mgr.with_toolchain(host),
        None => mgr,
    };
    Arc::new(match mcp {
        Some(host) => mgr.with_mcp(host),
        None => mgr,
    })
}

/// HUP-S6.3: the toolchain host when `CITRATE_HERMES_TOOLCHAIN=1` (default off → `None`). What it
/// will use is logged to stderr for the operator.
pub fn toolchain_from_env() -> Option<Arc<toolchain::ToolchainHost>> {
    let cfg = toolchain::ToolchainConfig::from_env()?;
    eprintln!(
        "citrate-agent-sidecar: toolchain tools on: {} granted folder(s), solc {}",
        cfg.roots.len(),
        if cfg.solc.is_some() {
            "configured"
        } else {
            "not found (builds will fail offline)"
        }
    );
    match toolchain::ToolchainHost::new(cfg) {
        Ok(h) => Some(Arc::new(h)),
        Err(e) => {
            eprintln!("citrate-agent-sidecar: toolchain tools off: {e}");
            None
        }
    }
}

// ---- HUP-S1.4: tracks + briefs ----

type JsonErr = (StatusCode, Json<serde_json::Value>);

fn json_err(c: StatusCode, m: &str) -> JsonErr {
    (c, Json(serde_json::json!({ "error": m })))
}

fn bundled_tracks_or_500() -> Result<Vec<interview::Track>, JsonErr> {
    interview::bundled_tracks().map_err(|e| json_err(StatusCode::INTERNAL_SERVER_ERROR, &e))
}

fn find_track(tracks: Vec<interview::Track>, id: &str) -> Result<interview::Track, JsonErr> {
    tracks.into_iter().find(|t| t.id == id).ok_or_else(|| {
        json_err(
            StatusCode::UNPROCESSABLE_ENTITY,
            &format!("no track {id:?}"),
        )
    })
}

async fn tracks(
    headers: HeaderMap,
    State(st): State<Arc<AppState>>,
) -> Result<Json<Vec<interview::Track>>, JsonErr> {
    if !authorized(&headers, &st.bearer) {
        return Err(json_err(StatusCode::UNAUTHORIZED, "unauthorized"));
    }
    Ok(Json(bundled_tracks_or_500()?))
}

#[derive(Deserialize)]
struct BriefReq {
    #[serde(default)]
    track: Option<String>,
    goal: String,
    #[serde(default)]
    answers: std::collections::BTreeMap<String, String>,
}

/// Answers → brief. Unanswered questions take their defaults; with no `track`, one is suggested
/// from the goal (422 when nothing fits, so the client asks the member to pick).
async fn create_brief(
    headers: HeaderMap,
    State(st): State<Arc<AppState>>,
    body: axum::body::Bytes,
) -> Result<Json<serde_json::Value>, JsonErr> {
    if !authorized(&headers, &st.bearer) {
        return Err(json_err(StatusCode::UNAUTHORIZED, "unauthorized"));
    }
    let req: BriefReq = serde_json::from_slice(&body)
        .map_err(|e| json_err(StatusCode::BAD_REQUEST, &format!("bad brief request: {e}")))?;
    let id = match req.track.as_deref() {
        Some(t) => t.to_string(),
        None => interview::suggest_track(&req.goal)
            .ok_or_else(|| {
                json_err(
                    StatusCode::UNPROCESSABLE_ENTITY,
                    "no track fits that goal; pick one from /tracks",
                )
            })?
            .to_string(),
    };
    let track = find_track(bundled_tracks_or_500()?, &id)?;
    let brief = interview::Brief::from_answers(&track, &req.goal, &req.answers)
        .map_err(|e| json_err(StatusCode::UNPROCESSABLE_ENTITY, &e))?;
    let markdown = brief.to_markdown();
    Ok(Json(
        serde_json::json!({ "brief": brief, "markdown": markdown }),
    ))
}

#[derive(Deserialize)]
struct CheckBriefReq {
    brief: interview::Brief,
}

/// Validate a member-edited brief against its track (gates and workflow are not editable away).
async fn check_brief(
    headers: HeaderMap,
    State(st): State<Arc<AppState>>,
    body: axum::body::Bytes,
) -> Result<Json<serde_json::Value>, JsonErr> {
    if !authorized(&headers, &st.bearer) {
        return Err(json_err(StatusCode::UNAUTHORIZED, "unauthorized"));
    }
    let req: CheckBriefReq = serde_json::from_slice(&body)
        .map_err(|e| json_err(StatusCode::BAD_REQUEST, &format!("bad brief: {e}")))?;
    let track = find_track(bundled_tracks_or_500()?, &req.brief.track)?;
    req.brief
        .validate_edit(&track)
        .map_err(|e| json_err(StatusCode::UNPROCESSABLE_ENTITY, &e))?;
    Ok(Json(
        serde_json::json!({ "ok": true, "markdown": req.brief.to_markdown() }),
    ))
}

#[cfg(test)]
mod grants_session_tests;
#[cfg(test)]
mod mcp_session_tests;
#[cfg(test)]
mod sessions_tests;
#[cfg(test)]
mod skills_session_tests;
#[cfg(test)]
mod tests;
#[cfg(test)]
mod toolchain_tests;
