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

pub mod anchor;
pub mod browser;
pub mod capsule_sandbox;
mod chain_routes;
mod checkpoint_routes;
pub mod decide;
pub mod escalation;
pub mod files;
pub mod grants;
pub mod hic_records;
pub mod learn;
pub mod llm_http;
pub mod mcp_approvals;
pub mod mcp_probe;
pub mod metering;
pub mod retrieval_http;
pub mod search;
pub mod sessions;
pub mod sheets;
pub mod shell_run;
pub mod signin_routes;
pub mod toolchain;
mod toolchain_config;
pub mod toolchain_reports;
pub mod trajectory;
pub mod verify_probes;
pub mod web_signing_records;
pub mod workers;
pub mod workflow_spec;

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
use citrate_agent_loop::{personas, workflows};

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

/// HUP-S2.5: the skills to list, out of `skills` (every capsule dir with a manifest): only the
/// ones `dispatch` will actually run. A capsule refused at load (bad signature, content hash or
/// manifest, or not allowlisted) or loaded unsigned for listing only is not a skill, and with no
/// dispatch nothing can run, so nothing is listed.
pub fn runnable_skills(
    skills: Vec<SkillView>,
    dispatch: Option<&CapsuleDispatch>,
) -> Vec<SkillView> {
    match dispatch {
        Some(d) => skills
            .into_iter()
            .filter(|s| d.is_runnable(&s.name))
            .collect(),
        None => Vec::new(),
    }
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
        // HUP-S3.2: the SKILL.md instruction skills sessions are offered, and a reload after the
        // member saves one.
        .route("/instruction-skills", get(instruction_skills))
        .route(
            "/instruction-skills/reload",
            post(reload_instruction_skills),
        )
        .route("/approvals", get(approvals))
        .route("/approvals/approve", post(approve_head))
        .route("/approvals/reject", post(reject_head))
        .route("/run_skill", post(run_skill))
        .route("/stop", post(stop))
        // HUP-S1.1b — agent sessions (ADR loop-in-sidecar).
        .route("/sessions", post(create_session).get(list_sessions))
        .route("/sessions/:id", delete(close_session))
        .route("/sessions/:id/messages", post(send_message))
        .route("/sessions/:id/events", get(session_events))
        .route("/sessions/:id/tool_results", post(tool_results))
        .route("/sessions/:id/stop", post(stop_session))
        .route("/sessions/:id/grants", post(replace_grants))
        .route("/sessions/:id/retrieval", get(session_retrieval))
        .route("/sessions/:id/shell/pending", get(shell_pending))
        .route("/sessions/:id/toolchain/reports", get(toolchain_reports))
        .route("/sessions/:id/shell/decide", post(shell_decide))
        .route("/sessions/:id/mcp/pending", get(mcp_pending))
        .route("/sessions/:id/mcp/decide", post(mcp_decide))
        // HUP-S1.4 — tracks + briefs (the interview every client shares).
        .route("/tracks", get(tracks))
        .route("/briefs", post(create_brief))
        .route("/briefs/check", post(check_brief))
        // HUP-S3.3 + S3.7 — personas (voice) and each track's workflow family.
        .route("/personas", get(list_personas))
        .route("/personas/check", post(check_persona))
        .route("/workflows", get(list_workflows))
        // HUP-S4.1: the configured MCP servers (read-only status).
        .route("/mcp/servers", get(mcp_servers))
        // HUP-S5.1 + S5.6: the browser (member controls for the Browser pop-out).
        .route("/browser/status", get(browser::status))
        .route("/browser/frame", get(browser::frame))
        .route("/browser/stop", post(browser::stop))
        .route("/browser/resume", post(browser::resume))
        .route("/browser/attach", post(browser::attach))
        .route("/browser/detach", post(browser::detach))
        .route("/browser/origins", post(browser::origins))
        .route("/browser/actions/decide", post(browser::decide))
        // HUP-S2.3: the managed browser's sign-in bridge, and web-signing decisions into the
        // decision records the nightly anchor covers (both for citrate-core only).
        .route("/browser/sign-in", get(signin_routes::list))
        .route("/browser/sign-in/answer", post(signin_routes::answer))
        .route("/records/web-signing", post(web_signing_records::write))
        // HUP-S2.6: core's other HIC events (grants, full access, escalation spend, approval
        // cards) into the same decision records.
        .route("/records/core", post(hic_records::write_core))
        // HUP-S5.2: search status (read-only). HUP-S5.3: the decide() slot + its metering.
        .route("/search/status", get(search_status))
        .route("/decide", post(decide))
        .route("/decide/stats", get(decide_stats))
        .route("/decide/outcomes", post(decide_outcome))
        // HUP-S3.4: verified workflow runs and verified self-learning.
        .route("/sessions/:id/workflows", post(start_workflow))
        .route("/sessions/:id/track_workflows", post(start_track_workflow))
        .route("/sessions/:id/workflows/:run", get(workflow_run))
        .route("/learn/status", get(learn_status))
        .route("/learn/proposals", post(learn_propose).get(learn_list))
        .route("/learn/proposals/:pid", get(learn_get))
        .route("/learn/proposals/:pid/accept", post(learn_accept))
        .route("/learn/proposals/:pid/reject", post(learn_reject))
        .route("/learn/proposals/:pid/publish", post(learn_publish))
        .route("/learn/memories/resolve", post(learn_resolve))
        // HUP-S2.9: undo checkpoints for agent file changes (member actions, never tools).
        .route("/checkpoints/:session", get(checkpoint_routes::list_steps))
        .route(
            "/checkpoints/:session/steps/:seq/undo",
            post(checkpoint_routes::undo_step),
        )
        .route(
            "/checkpoints/:session/undo",
            post(checkpoint_routes::undo_session),
        )
        // HUP-S5.4: one step's diff for the Code and diff pop-out (read-only).
        .route(
            "/checkpoints/:session/steps/:seq/diff",
            get(checkpoint_routes::step_diff),
        )
        // HUP-S1.9: the worker processes (toolchain, browser) and their health
        .route("/workers", get(workers_status))
        // HUP-S7.5: the daily metering report + opt-in BenchmarkRegistry calldata (built, never sent)
        .route("/metering/daily", get(chain_routes::metering_daily))
        .route(
            "/metering/benchmark",
            post(chain_routes::metering_benchmark),
        )
        // HUP-S7.3: nightly anchor batch (core signs with the anchor key; nothing is sent here)
        .route("/anchor/status", get(chain_routes::anchor_status))
        .route("/anchor/plan", post(chain_routes::anchor_plan))
        .route("/anchor/confirm", post(chain_routes::anchor_confirm))
        .route("/anchor/proof", get(chain_routes::anchor_proof))
        // HUP-S1.5: one escalation to a member endpoint (core checked the budget and passes the
        // key per request), and the registry route's status (disabled in this build).
        .route("/escalations", post(escalation::escalate))
        .route("/escalations/registry", get(escalation::registry_status))
        // HUP-S4.4: dry-run probe of a user-added server (validates, lists tools, registers nothing).
        .route("/mcp/probe", post(mcp_probe_route))
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

/// `GET /workers` — one entry per worker kind: state, health, pid, restarts, last exit. Bearer.
async fn workers_status(
    State(st): State<Arc<AppState>>,
    headers: HeaderMap,
) -> Result<Json<serde_json::Value>, StatusCode> {
    if !authorized(&headers, &st.bearer) {
        return Err(StatusCode::UNAUTHORIZED);
    }
    Ok(Json(
        serde_json::json!({ "workers": st.sessions.workers_report() }),
    ))
}

/// HUP-S4.4: `POST /mcp/probe` with one server entry (the allowlist's `[[servers]]` shape, JSON).
/// 422 `{errors: [{field, message}]}` for an invalid entry; 503 when the sidecar was not given
/// core's saved server list; 403 when the entry is not saved there exactly as sent (nothing is
/// started); 429 while another probe runs; else 200 with the probe report (`ok: false` + `error`
/// when the server could not be reached).
async fn mcp_probe_route(
    headers: HeaderMap,
    State(st): State<Arc<AppState>>,
    Json(entry): Json<serde_json::Value>,
) -> Result<Json<serde_json::Value>, (StatusCode, Json<serde_json::Value>)> {
    if !authorized(&headers, &st.bearer) {
        return Err((
            StatusCode::UNAUTHORIZED,
            Json(serde_json::json!({ "error": "unauthorized" })),
        ));
    }
    mcp_probe::handle(entry, st.sessions.mcp_registry()).await
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

/// HUP-S3.2: the instruction skills new sessions are offered (before any persona allowlist), with
/// provenance for reviewed third-party ones, the ranking method and how many surface per turn.
async fn instruction_skills(
    headers: HeaderMap,
    State(st): State<Arc<AppState>>,
) -> Result<Json<serde_json::Value>, StatusCode> {
    if !authorized(&headers, &st.bearer) {
        return Err(StatusCode::UNAUTHORIZED);
    }
    let lib = st.sessions.skills();
    let mut skills = Vec::new();
    let mut refused = 0usize;
    if let Some(lib) = &lib {
        refused = lib.report().rejected.len();
        for name in lib.names() {
            let Some(s) = lib.get(name) else { continue };
            let provenance = s.provenance.as_ref().map(|p| {
                serde_json::json!({
                    "source": p.source,
                    "upstream": p.upstream,
                    "commit": p.commit,
                    "license": p.license,
                    "path": p.path,
                    "verdict": p.verdict,
                    "skill_md_sha256": p.skill_md_sha256,
                    "intake_rewrite": p.intake_rewrite,
                })
            });
            skills.push(serde_json::json!({
                "name": s.name,
                "description": s.description,
                "source": s.source,
                "provenance": provenance,
            }));
        }
    }
    Ok(Json(serde_json::json!({
        "ranker": citrate_agent_loop::skills::SkillRanker::method(&citrate_agent_loop::skills::Bm25Ranker),
        "per_turn": citrate_agent_loop::skills::SKILLS_PER_TURN,
        "skills": skills,
        "refused": refused,
    })))
}

/// HUP-S3.2: read the skill sources again (the member saved or removed a skill). Sessions already
/// open keep their skills; the next session gets the new library.
async fn reload_instruction_skills(
    headers: HeaderMap,
    State(st): State<Arc<AppState>>,
) -> Result<Json<serde_json::Value>, StatusCode> {
    if !authorized(&headers, &st.bearer) {
        return Err(StatusCode::UNAUTHORIZED);
    }
    let sessions = st.sessions.clone();
    let reloaded = tokio::task::spawn_blocking(move || sessions.reload_skills())
        .await
        .map_err(|_| StatusCode::INTERNAL_SERVER_ERROR)?;
    let mut body = serde_json::json!({ "ok": true, "reloaded": reloaded.is_some() });
    if let Some(n) = reloaded {
        body["skills_offered"] = serde_json::json!(n);
    }
    Ok(Json(body))
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
    // HUP-S2.6: the member's decision on the reviewed head is recorded (write-ahead for an
    // approval; fail closed when the record cannot be written). A resolve that does not match
    // the head records nothing.
    let head = st.queue.peek().filter(|p| p.id == id);
    let log = st.sessions.records();
    let pending_record = match (&log, &head) {
        (Some(log), Some(p)) if approve => Some(
            record_ceremony_decision(log, p, true).map_err(|_| StatusCode::SERVICE_UNAVAILABLE)?,
        ),
        _ => None,
    };
    let res = if approve {
        st.queue.approve_by_id(&id)
    } else {
        st.queue.reject_by_id(&id)
    };
    match res {
        Ok(()) => {
            if let (Some(log), Some(p)) = (&log, &head) {
                match pending_record {
                    Some(seq) => hic_records::record_outcome(
                        log,
                        seq,
                        citrate_agent_records::Outcome::Completed,
                        "released to the capsule; a chain effect was signed and broadcast in core's ceremony first",
                    ),
                    None => {
                        if let Err(e) = record_ceremony_decision(log, p, false) {
                            eprintln!("citrate-agent-sidecar: {e}");
                        }
                    }
                }
            }
            Ok(Json(serde_json::json!({ "ok": true, "resolved": true })))
        }
        // The head is not the call the operator reviewed, or its submitter is gone — refuse.
        Err(_) => {
            if let (Some(log), Some(seq)) = (&log, pending_record) {
                hic_records::record_outcome(
                    log,
                    seq,
                    citrate_agent_records::Outcome::Failed,
                    "the call was no longer waiting, so nothing was released",
                );
            }
            Err(StatusCode::CONFLICT)
        }
    }
}

/// HUP-S2.6: one ceremony-bridge decision on the reviewed call `p`.
fn record_ceremony_decision(
    log: &citrate_agent_records::DecisionLog,
    p: &citrate_agent_core::hitl::PendingView,
    allow: bool,
) -> Result<u64, String> {
    hic_records::record_member_decision(
        log,
        "ceremony.capsule_effect",
        &format!("{}: {}", p.name, p.description),
        allow,
        if allow {
            "the member approved this effect in core's ceremony"
        } else {
            "the member declined this effect"
        },
        vec![citrate_agent_records::EvidenceRef {
            kind: "approval_call".to_string(),
            uri: format!("sidecar:approval/{}", p.id),
            digest: None,
        }],
    )
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
    // HUP-S5.1: and the browser (closes it, denies any waiting browser action, latches).
    if let Some(b) = st.sessions.browser().cloned() {
        let _ = tokio::task::spawn_blocking(move || b.stop()).await;
    }
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
        Ok(id) => {
            let session = st.sessions.get(&id);
            // HUP-S3.3: say what the persona did (offered skills, missing ones, pinned tools).
            let persona = session.as_ref().and_then(|s| s.persona().cloned());
            // HUP-S1.2: say how tokens are counted and tools ranked (probed once, off the
            // async runtime: the probes are blocking HTTP calls to the session's own endpoints).
            let retrieval = match session {
                Some(s) => tokio::task::spawn_blocking(move || s.probe_retrieval())
                    .await
                    .ok(),
                None => None,
            };
            let mut body = serde_json::json!({ "id": id });
            if let Some(p) = persona {
                body["persona"] = serde_json::json!(p);
            }
            if let Some(r) = retrieval {
                body["tokenCounting"] = serde_json::json!(r.token_counting);
                body["retrieval"] = serde_json::json!(r.retrieval);
                body["maxToolSchemas"] = serde_json::json!(r.max_tool_schemas);
            }
            Ok((StatusCode::CREATED, Json(body)))
        }
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

/// HUP-S1.2: `GET /sessions/:id/retrieval` — how the session counts tokens and ranks tools and
/// skills right now (a fallback after creation shows here).
async fn session_retrieval(
    headers: HeaderMap,
    State(st): State<Arc<AppState>>,
    Path(id): Path<String>,
) -> Result<Json<sessions::RetrievalReport>, StatusCode> {
    if !authorized(&headers, &st.bearer) {
        return Err(StatusCode::UNAUTHORIZED);
    }
    st.sessions
        .get(&id)
        .map(|s| Json(s.retrieval_report()))
        .ok_or(StatusCode::NOT_FOUND)
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

/// US-2.2 AC2: `GET /sessions/:id/shell/pending` — the commands waiting for the member, with
/// everything the approval card shows. A session without `shell_run` has none.
async fn shell_pending(
    headers: HeaderMap,
    State(st): State<Arc<AppState>>,
    Path(id): Path<String>,
) -> Result<Json<serde_json::Value>, JsonErr> {
    if !authorized(&headers, &st.bearer) {
        return Err(json_err(StatusCode::UNAUTHORIZED, "unauthorized"));
    }
    let session = st
        .sessions
        .get(&id)
        .ok_or_else(|| json_err(StatusCode::NOT_FOUND, "no such session"))?;
    let pending = session.shell_pending().unwrap_or_default();
    Ok(Json(serde_json::json!({ "pending": pending })))
}

/// HUP-S4.1: `GET /sessions/:id/mcp/pending`: the MCP approval cards waiting for the member
/// (effectful MCP calls after taint, and URL-mode elicitations). A session without them has none.
async fn mcp_pending(
    headers: HeaderMap,
    State(st): State<Arc<AppState>>,
    Path(id): Path<String>,
) -> Result<Json<serde_json::Value>, JsonErr> {
    if !authorized(&headers, &st.bearer) {
        return Err(json_err(StatusCode::UNAUTHORIZED, "unauthorized"));
    }
    let session = st
        .sessions
        .get(&id)
        .ok_or_else(|| json_err(StatusCode::NOT_FOUND, "no such session"))?;
    let pending = session.mcp_pending().unwrap_or_default();
    Ok(Json(serde_json::json!({ "pending": pending })))
}

#[derive(Deserialize)]
struct McpDecideReq {
    id: String,
    allow: bool,
    subject: String,
}

/// HUP-S4.1: `POST /sessions/:id/mcp/decide {id, allow, subject}`: the member's decision on one
/// MCP card. `subject` must be the arguments (or URL) that were shown; otherwise 409 and nothing
/// is decided. Recorded like the other HIC decisions (write-ahead for an allow).
async fn mcp_decide(
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
    let req: McpDecideReq = serde_json::from_slice(&body)
        .map_err(|_| json_err(StatusCode::BAD_REQUEST, "expected {id, allow, subject}"))?;
    let card = session
        .mcp_waiting(&req.id)
        .filter(|c| c.subject == req.subject)
        .ok_or_else(|| {
            json_err(
                StatusCode::CONFLICT,
                "that request is no longer waiting, or the decision does not match what is waiting; nothing was decided",
            )
        })?;
    let (kind, subject) = if card.kind == "open_url" {
        (
            "mcp.open_url",
            format!("open {} for MCP server '{}'", card.subject, card.server),
        )
    } else {
        (
            "mcp.tool_call",
            format!(
                "{} on MCP server '{}' with {}",
                card.remote_tool, card.server, card.subject
            ),
        )
    };
    let log = st.sessions.records();
    let record = |allow: bool, log: &citrate_agent_records::DecisionLog| {
        hic_records::record_member_decision(
            log,
            kind,
            &subject,
            allow,
            "the member decided on the exact request shown",
            vec![citrate_agent_records::EvidenceRef {
                kind: kind.replace('.', "_"),
                uri: format!("sidecar:sessions/{id}/mcp/{}", req.id),
                digest: None,
            }],
        )
    };
    let allow_seq = match &log {
        Some(log) if req.allow => match record(true, log) {
            Ok(seq) => Some(seq),
            Err(e) => return Err(json_err(StatusCode::SERVICE_UNAVAILABLE, &e)),
        },
        _ => None,
    };
    match session.mcp_decide(&req.id, req.allow, &req.subject) {
        Ok(()) => {
            if let Some(log) = &log {
                match allow_seq {
                    Some(seq) => hic_records::record_outcome(
                        log,
                        seq,
                        citrate_agent_records::Outcome::Completed,
                        "released; the call's own result is in the session",
                    ),
                    None => {
                        if let Err(e) = record(false, log) {
                            eprintln!("citrate-agent-sidecar: {e}");
                        }
                    }
                }
            }
            Ok(Json(serde_json::json!({ "ok": true })))
        }
        Err(e) => {
            if let (Some(log), Some(seq)) = (&log, allow_seq) {
                hic_records::record_outcome(
                    log,
                    seq,
                    citrate_agent_records::Outcome::Failed,
                    "not released (no longer waiting, or the subject differed)",
                );
            }
            let msg = match e {
                sessions::SessionError::Invalid(m) => m,
                _ => "that request is no longer waiting for a decision".to_string(),
            };
            Err(json_err(StatusCode::CONFLICT, &msg))
        }
    }
}

#[derive(Deserialize)]
struct ToolchainReportsQuery {
    #[serde(default)]
    project: Option<String>,
}

/// HUP-S6.3 → S6.4: `GET /sessions/:id/toolchain/reports[?project=<abs path>]` — the latest raw
/// report per (project, tool) of this session's toolchain runs, for core's deploy gate. 404 when
/// the session is unknown or was opened without the toolchain.
async fn toolchain_reports(
    headers: HeaderMap,
    State(st): State<Arc<AppState>>,
    Path(id): Path<String>,
    axum::extract::Query(q): axum::extract::Query<ToolchainReportsQuery>,
) -> Result<Json<serde_json::Value>, JsonErr> {
    if !authorized(&headers, &st.bearer) {
        return Err(json_err(StatusCode::UNAUTHORIZED, "unauthorized"));
    }
    let session = st
        .sessions
        .get(&id)
        .ok_or_else(|| json_err(StatusCode::NOT_FOUND, "no such session"))?;
    let reports = session
        .toolchain_reports(q.project.as_deref())
        .ok_or_else(|| json_err(StatusCode::NOT_FOUND, "this session has no toolchain"))?;
    Ok(Json(serde_json::json!({ "reports": reports })))
}

#[derive(Deserialize)]
struct ShellDecideReq {
    id: String,
    allow: bool,
    argv: Vec<String>,
    cwd: String,
}

/// US-2.2 AC2: `POST /sessions/:id/shell/decide {id, allow, argv, cwd}` — the member's decision.
/// The argv and cwd must be the ones that were shown; otherwise 409 and nothing is decided.
async fn shell_decide(
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
    let req: ShellDecideReq = serde_json::from_slice(&body)
        .map_err(|_| json_err(StatusCode::BAD_REQUEST, "expected {id, allow, argv, cwd}"))?;
    // HUP-S2.6: the member's decision on the exact command is recorded in the log the nightly
    // anchor batches (write-ahead for an allow, which is refused when it cannot be recorded; a
    // deny always takes effect and is recorded after).
    let log = st.sessions.records();
    let subject = format!("{} (in {})", req.argv.join(" "), req.cwd);
    let record = |allow: bool, log: &citrate_agent_records::DecisionLog| {
        hic_records::record_member_decision(
            log,
            "shell.run",
            &subject,
            allow,
            "the member decided on the exact command and folder shown",
            vec![citrate_agent_records::EvidenceRef {
                kind: "shell_run".to_string(),
                uri: format!("sidecar:sessions/{id}/shell/{}", req.id),
                digest: None,
            }],
        )
    };
    let allow_seq = match &log {
        Some(log) if req.allow => match record(true, log) {
            Ok(seq) => Some(seq),
            Err(e) => return Err(json_err(StatusCode::SERVICE_UNAVAILABLE, &e)),
        },
        _ => None,
    };
    match session.shell_decide(&req.id, req.allow, &req.argv, &req.cwd) {
        Ok(()) => {
            if let Some(log) = &log {
                match allow_seq {
                    Some(seq) => hic_records::record_outcome(
                        log,
                        seq,
                        citrate_agent_records::Outcome::Completed,
                        "released to the sandboxed runner; the run's own result is in the session",
                    ),
                    None => {
                        if let Err(e) = record(false, log) {
                            eprintln!("citrate-agent-sidecar: {e}");
                        }
                    }
                }
            }
            Ok(Json(serde_json::json!({ "ok": true })))
        }
        Err(e) => {
            if let (Some(log), Some(seq)) = (&log, allow_seq) {
                hic_records::record_outcome(
                    log,
                    seq,
                    citrate_agent_records::Outcome::Failed,
                    "the command was not released (no longer waiting, or argv/folder differed)",
                );
            }
            match e {
                sessions::SessionError::Invalid(m) => Err(json_err(StatusCode::CONFLICT, &m)),
                _ => Err(json_err(
                    StatusCode::CONFLICT,
                    "this session does not run commands",
                )),
            }
        }
    }
}

/// HUP-S1.1: `GET /sessions` — the open sessions (id, model, busy, last sequence number, persona,
/// waiting core calls), so every client (app, CLI, MCP) can find and attach to the same session.
async fn list_sessions(
    headers: HeaderMap,
    State(st): State<Arc<AppState>>,
) -> Result<Json<serde_json::Value>, StatusCode> {
    if !authorized(&headers, &st.bearer) {
        return Err(StatusCode::UNAUTHORIZED);
    }
    Ok(Json(serde_json::json!({ "sessions": st.sessions.list() })))
}

async fn close_session(
    headers: HeaderMap,
    State(st): State<Arc<AppState>>,
    Path(id): Path<String>,
) -> Result<Json<serde_json::Value>, StatusCode> {
    if !authorized(&headers, &st.bearer) {
        return Err(StatusCode::UNAUTHORIZED);
    }
    // A trajectory export at close writes files: keep it off the async workers.
    let sessions = st.sessions.clone();
    let exported = tokio::task::spawn_blocking(move || sessions.close(&id))
        .await
        .map_err(|_| StatusCode::INTERNAL_SERVER_ERROR)?
        .map_err(|e| session_status(&e))?;
    let mut body = serde_json::json!({ "ok": true, "closed": true });
    if let Some(summary) = exported {
        body["trajectory"] = serde_json::to_value(summary).unwrap_or(serde_json::Value::Null);
    }
    Ok(Json(body))
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

/// HUP-S3.2: the path of the `skills.lock` citrate-core ships beside the staged reviewed skills.
pub const SKILLS_LOCK_ENV: &str = "CITRATE_HERMES_SKILLS_LOCK";
/// HUP-S3.2: the staged tree of reviewed third-party skills (`<root>/<source>/<path>/`).
pub const SKILLS_THIRD_PARTY_ENV: &str = "CITRATE_HERMES_SKILLS_THIRD_PARTY";
/// The source label reviewed third-party skills load under.
pub const THIRD_PARTY_SKILLS_LABEL: &str = "reviewed";
/// Largest `skills.lock` read.
const MAX_SKILLS_LOCK_BYTES: u64 = 4 * 1024 * 1024;

/// HUP-S3.2: the reviewed third-party skills as a locked source: `lock` is `skills.lock`, `root`
/// the staged tree. Every file is checked against the lock when the library loads.
pub fn third_party_skill_source(
    lock: &std::path::Path,
    root: &std::path::Path,
) -> Result<citrate_agent_loop::skills::SkillSource, String> {
    let meta = std::fs::metadata(lock)
        .map_err(|e| format!("skills.lock at {}: {}", lock.display(), e.kind()))?;
    if meta.len() > MAX_SKILLS_LOCK_BYTES {
        return Err(format!(
            "skills.lock at {} is larger than {MAX_SKILLS_LOCK_BYTES} bytes",
            lock.display()
        ));
    }
    let text = std::fs::read_to_string(lock)
        .map_err(|e| format!("skills.lock at {}: {}", lock.display(), e.kind()))?;
    let parsed = citrate_agent_loop::skills::SkillLock::from_toml(&text)?;
    Ok(citrate_agent_loop::skills::SkillSource::locked(
        THIRD_PARTY_SKILLS_LABEL,
        root,
        Arc::new(parsed),
    ))
}

/// HUP-S3.2: every skill source in precedence order: the member's own folders
/// (`CITRATE_HERMES_SKILLS`, first wins) and then, when both paths are given, the reviewed
/// third-party skills. A lock that cannot be read is logged and left out (fail closed); the
/// member's own skills still load.
pub fn all_skill_sources(
    member: &str,
    third_party: Option<(&std::path::Path, &std::path::Path)>,
) -> Vec<citrate_agent_loop::skills::SkillSource> {
    let mut sources = skill_sources_from_env(member);
    if let Some((lock, root)) = third_party {
        match third_party_skill_source(lock, root) {
            Ok(src) => sources.push(src),
            Err(e) => eprintln!("citrate-agent-sidecar: reviewed third-party skills off: {e}"),
        }
    }
    sources
}

/// [`all_skill_sources`] from the environment.
fn skill_sources_from_process_env() -> Vec<citrate_agent_loop::skills::SkillSource> {
    let member = std::env::var("CITRATE_HERMES_SKILLS").unwrap_or_default();
    let lock = std::env::var_os(SKILLS_LOCK_ENV).filter(|v| !v.is_empty());
    let root = std::env::var_os(SKILLS_THIRD_PARTY_ENV).filter(|v| !v.is_empty());
    match (lock, root) {
        (Some(lock), Some(root)) => all_skill_sources(
            &member,
            Some((std::path::Path::new(&lock), std::path::Path::new(&root))),
        ),
        _ => all_skill_sources(&member, None),
    }
}

/// HUP-S3.2: load the skills library named by `CITRATE_HERMES_SKILLS` plus the reviewed
/// third-party skills (default off → `None`). What was refused or shadowed is logged to stderr
/// for the operator, never sent to the model.
pub fn skills_from_env() -> Option<Arc<citrate_agent_loop::skills::SkillLibrary>> {
    let sources = skill_sources_from_process_env();
    if sources.is_empty() {
        return None;
    }
    let lib = citrate_agent_loop::skills::SkillLibrary::load(&sources);
    log_skill_report(&lib);
    Some(Arc::new(lib))
}

/// What the skills loader refused or shadowed, for the operator (stderr), never the model.
fn log_skill_report(lib: &citrate_agent_loop::skills::SkillLibrary) {
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
}

/// How often the MCP host checks for servers to reconnect and tool lists to re-read.
pub const MCP_MAINTENANCE_EVERY: std::time::Duration = std::time::Duration::from_secs(2);

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
            // HUP-S4.1: reconnect servers that drop (with backoff) and re-list on list_changed.
            citrate_agent_mcp_host::McpHost::start_maintenance(&host, MCP_MAINTENANCE_EVERY);
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
/// `CITRATE_HERMES_SKILLS` is set, the toolchain tools when `CITRATE_HERMES_TOOLCHAIN=1` (run in
/// the supervised toolchain worker process, HUP-S1.9), verified self-learning when
/// `CITRATE_HERMES_LEARN_DIR` and `CITRATE_HERMES_LEARN_SKILLS_DIR` are both set (HUP-S3.4), the
/// search tools when `CITRATE_HERMES_SEARCH=1`, and the decide() slot (Jev only when opted in).
pub fn production_sessions() -> Arc<sessions::SessionManager> {
    production_sessions_with(None)
}

/// HUP-S1.2: llama-server `/tokenize` for a loopback chat endpoint; any other endpoint (an https
/// gateway) has no tokenizer the sidecar can reach, so its sessions estimate.
pub fn production_tokenizer() -> sessions::TokenizerFactory {
    Arc::new(|ep: &sessions::LlmEndpoint| {
        if retrieval_http::is_loopback_http(&ep.base_url) {
            Ok(Arc::new(retrieval_http::LlamaTokenizer::new(
                &ep.base_url,
                &ep.bearer,
            ))
                as Arc<dyn citrate_agent_loop::retrieval::Tokenizer>)
        } else {
            Err("the model endpoint is not the local llama-server, so tokens are estimated".into())
        }
    })
}

/// HUP-S1.2: the embedding endpoint named by `CITRATE_HERMES_EMBED_URL` (loopback http or https,
/// no bearer), else the session's own loopback chat server (which answers only when it was
/// started with `--embeddings`). An https chat endpoint is never sent tool or skill text for
/// embedding unless it is named here.
pub fn production_embedder(embed_url: Option<String>) -> sessions::EmbedderFactory {
    let embed_url = embed_url.filter(|u| !u.trim().is_empty());
    Arc::new(move |ep: &sessions::LlmEndpoint| match &embed_url {
        Some(url) => {
            sessions::validate_endpoint(url)
                .map_err(|e| format!("{} was refused: {e}", retrieval_http::EMBED_URL_ENV))?;
            Ok(Arc::new(retrieval_http::HttpEmbedder::new(url, ""))
                as Arc<dyn citrate_agent_loop::retrieval::Embedder>)
        }
        None if retrieval_http::is_loopback_http(&ep.base_url) => Ok(Arc::new(
            retrieval_http::HttpEmbedder::new(&ep.base_url, &ep.bearer),
        )
            as Arc<dyn citrate_agent_loop::retrieval::Embedder>),
        None => Err(format!(
            "no embedding endpoint: {} is not set and the model endpoint is not local",
            retrieval_http::EMBED_URL_ENV
        )),
    })
}

/// [`production_sessions`] plus the MCP host when one is configured (HUP-S4.1).
pub fn production_sessions_with(
    mcp: Option<Arc<citrate_agent_mcp_host::McpHost>>,
) -> Arc<sessions::SessionManager> {
    let timeout = std::time::Duration::from_secs(300);
    // HUP-S1.1 (g1-render): answers stream to the session events unless switched off.
    let streaming =
        llm_http::streaming_from_value(std::env::var(llm_http::LLM_STREAM_ENV).ok().as_deref());
    let mgr = sessions::SessionManager::new(
        Arc::new(move |ep: &sessions::LlmEndpoint| {
            Arc::new(
                llm_http::OpenAiCompatClient::new(&ep.base_url, &ep.bearer, timeout)
                    .with_streaming(streaming),
            ) as Arc<dyn citrate_agent_loop::LlmClient>
        }),
        timeout,
    );
    // HUP-S1.2 (US-1.4 AC1): token counts from the model's tokenizer, and tools and skills ranked
    // by embeddings plus keywords, each with an honest fallback the session reports.
    let mgr = mgr
        .with_tokenizer(production_tokenizer())
        .with_embedder(production_embedder(
            std::env::var(retrieval_http::EMBED_URL_ENV).ok(),
        ));
    // HUP-S2.1: grants are resolved against the member's home (the sidecar runs as the member).
    let mgr = match std::env::var_os("HOME").filter(|h| !h.is_empty()) {
        Some(home) => mgr.with_grants_home(std::path::PathBuf::from(home)),
        None => mgr,
    };
    // HUP-S4.4: the MCP probe starts only entries core saved in this list.
    let mgr = match std::env::var_os(mcp_probe::MCP_REGISTRY_ENV).filter(|p| !p.is_empty()) {
        Some(p) => mgr.with_mcp_registry(std::path::PathBuf::from(p)),
        None => mgr,
    };
    // HUP-S3.2: the skills library. HUP-S3.4: kept with its sources, so a learned skill the
    // member accepts is offered to the next session without a restart.
    let sources = skill_sources_from_process_env();
    let mgr = if sources.is_empty() {
        mgr
    } else {
        let mgr = mgr.with_skill_sources(sources);
        match mgr.skills() {
            Some(lib) => log_skill_report(&lib),
            None => eprintln!("citrate-agent-sidecar: 0 instruction skills loaded"),
        }
        mgr
    };
    // HUP-S1.9: the toolchain runs in its own supervised worker process (this binary started
    // with `--worker toolchain`), so a crash there never takes the loop down.
    let mgr = match std::env::current_exe() {
        Ok(exe) => match workers::toolchain_worker_from_env(exe) {
            Some(worker) => mgr
                .with_toolchain(Arc::new(workers::RemoteToolHost::new(
                    worker.clone(),
                    workers::TOOLCHAIN_CALL_TIMEOUT,
                )))
                .with_workers(Arc::new(workers::WorkerSet::with_toolchain(worker))),
            None => mgr,
        },
        Err(e) => {
            if toolchain::ToolchainConfig::from_env().is_some() {
                eprintln!(
                    "citrate-agent-sidecar: toolchain tools off: cannot locate this binary to start the worker: {e}"
                );
            }
            mgr
        }
    };
    let mgr = mgr.with_metering(metering::metering_from_env());
    let mgr = match trajectory::TrajectoryConfig::from_env() {
        Some(cfg) => {
            eprintln!(
                "citrate-agent-sidecar: trajectory recording on (verified turns only, redacted) into {}",
                cfg.dir().display()
            );
            mgr.with_trajectories(cfg)
        }
        None => mgr,
    };
    let mgr = match browser::from_env() {
        Some(b) => mgr.with_browser(b),
        None => mgr,
    };
    let mgr = match search::search_from_env() {
        Some(host) => mgr.with_search(host),
        None => mgr,
    };
    let mgr = mgr.with_decide(decide::DecideService::from_env());
    // HUP-S2.6: one writer for the records directory the anchor batches, shared by every HIC
    // event the sidecar records (and by learn, which then writes there instead of its own folder).
    let records = web_signing_records::records_dir_from_env().and_then(|dir| {
        match web_signing_records::shared_log(&dir) {
            Ok(log) => Some(log),
            Err(e) => {
                eprintln!("citrate-agent-sidecar: decision records off: {e}");
                None
            }
        }
    });
    let mgr = match &records {
        Some(log) => mgr.with_records(log.clone()),
        None => mgr,
    };
    let mgr = match learn::LearnService::from_env_with_records(records) {
        Some(svc) => mgr.with_learn(svc),
        None => mgr,
    };
    let mgr = match anchor::AnchorPaths::from_env() {
        Some(paths) => match anchor::AnchorService::from_paths(&paths) {
            Ok(svc) => mgr.with_anchor(Arc::new(svc)),
            Err(e) => {
                eprintln!("citrate-agent-sidecar: anchor store unavailable: {e}");
                mgr
            }
        },
        None => mgr,
    };
    let mgr = with_files_from_env(mgr);
    // US-1.3 AC2: record the model's self-review of each workflow step attempt as an opinion
    // (on unless CITRATE_HERMES_SELF_REVIEW=0).
    let mgr = mgr.with_self_review(self_review_from_env_var(
        std::env::var("CITRATE_HERMES_SELF_REVIEW").ok().as_deref(),
    ));
    // US-2.2 AC2: shell_run (off by default; always inside the OS sandbox).
    let mgr = match shell_run::ShellRunConfig::from_env() {
        Some(cfg) => {
            match cfg.sandbox.backend() {
                Ok(b) => eprintln!(
                    "citrate-agent-sidecar: shell_run on for sessions with folder grants; every command needs the member's approval and runs in the {} sandbox",
                    b.name()
                ),
                Err(why) => eprintln!(
                    "citrate-agent-sidecar: shell_run on, but every command will be refused: no OS sandbox ({why})"
                ),
            }
            mgr.with_shell_run(Arc::new(cfg))
        }
        None => mgr,
    };
    Arc::new(match mcp {
        Some(host) => mgr.with_mcp(host),
        None => mgr,
    })
}

/// US-1.3 AC2: workflow runs record the model's self-review unless the variable is exactly `0`.
pub fn self_review_from_env_var(v: Option<&str>) -> bool {
    v.map(str::trim) != Some("0")
}

/// HUP-S2.9: open the checkpoint store when `CITRATE_HERMES_CHECKPOINTS` names one (the undo
/// routes then serve it), and offer the file tools when `CITRATE_HERMES_FILES=1` with a grants
/// file. The file tools never run without a store: no change the member could not undo. What is
/// on is logged to stderr for the operator.
pub fn with_files_from_env(mgr: sessions::SessionManager) -> sessions::SessionManager {
    let get = |k: &str| std::env::var(k).ok();
    let files_cfg = files::FilesConfig::from_env_vars(get);
    let Some(dir) = files::checkpoints_dir_from_env_vars(get) else {
        if files_cfg.is_some() {
            eprintln!(
                "citrate-agent-sidecar: file tools off: no checkpoint store ({} is not set), so changes could not be undone",
                files::CHECKPOINTS_ENV
            );
        }
        return mgr;
    };
    let store = match citrate_agent_checkpoints::CheckpointStore::open(
        &dir,
        citrate_agent_checkpoints::Config::default(),
    ) {
        Ok(s) => Arc::new(s),
        Err(e) => {
            eprintln!("citrate-agent-sidecar: undo checkpoints off: {e}");
            return mgr;
        }
    };
    let mgr = mgr.with_checkpoints(store.clone());
    match files_cfg {
        Some(cfg) => {
            eprintln!("citrate-agent-sidecar: file tools on (fs_write, fs_edit, fs_delete, fs_rename), with undo checkpoints");
            mgr.with_files(Arc::new(files::FileTools::new(
                store,
                files::GrantSource::File(cfg.grants_file),
                cfg.home,
            )))
        }
        None => mgr,
    }
}

// ---- HUP-S1.4: tracks + briefs ----

type JsonErr = (StatusCode, Json<serde_json::Value>);

// ── HUP-S5.2 / S5.3: search status + the decide() slot ──────────────────

/// `{enabled, searxng, reader}`. Never a key, a path, or a query.
async fn search_status(
    headers: HeaderMap,
    State(st): State<Arc<AppState>>,
) -> Result<Json<serde_json::Value>, StatusCode> {
    if !authorized(&headers, &st.bearer) {
        return Err(StatusCode::UNAUTHORIZED);
    }
    let Some(host) = st.sessions.search() else {
        return Ok(Json(serde_json::json!({
            "enabled": false, "searxng": "off", "reader": "local"
        })));
    };
    let reader = if host.third_party_reader() {
        "jina"
    } else {
        "local"
    };
    let searxng = tokio::task::spawn_blocking(move || match host.searxng().state() {
        citrate_agent_search::SearxngState::NotInstalled(_) => "not_installed",
        citrate_agent_search::SearxngState::Idle => "idle",
        citrate_agent_search::SearxngState::Running { .. } => "running",
        citrate_agent_search::SearxngState::GaveUp(_) => "failed",
    })
    .await
    .unwrap_or("failed");
    Ok(Json(serde_json::json!({
        "enabled": true, "searxng": searxng, "reader": reader
    })))
}

fn decide_status_code(e: &citrate_agent_loop::decide::DecideError) -> StatusCode {
    use citrate_agent_loop::decide::DecideError as E;
    match e {
        E::Invalid(_) => StatusCode::BAD_REQUEST,
        E::NotPermitted(_) => StatusCode::FORBIDDEN,
        E::NotConfigured(_) => StatusCode::SERVICE_UNAVAILABLE,
        E::Backend(_) | E::BadAnswer(_) => StatusCode::BAD_GATEWAY,
    }
}

/// `POST /decide`: one typed decision. The work runs on the blocking pool.
async fn decide(
    headers: HeaderMap,
    State(st): State<Arc<AppState>>,
    body: axum::body::Bytes,
) -> Result<Json<serde_json::Value>, JsonErr> {
    if !authorized(&headers, &st.bearer) {
        return Err(json_err(StatusCode::UNAUTHORIZED, "unauthorized"));
    }
    if st.estop.is_stopped() {
        return Err(json_err(
            StatusCode::SERVICE_UNAVAILABLE,
            "emergency stop engaged",
        ));
    }
    let req: decide::DecideHttpReq = serde_json::from_slice(&body)
        .map_err(|e| json_err(StatusCode::BAD_REQUEST, &format!("bad decide request: {e}")))?;
    let svc = st.sessions.decide_service();
    let out = tokio::task::spawn_blocking(move || svc.decide(&req))
        .await
        .map_err(|_| json_err(StatusCode::INTERNAL_SERVER_ERROR, "decide task failed"))?;
    match out {
        Ok(d) => Ok(Json(serde_json::to_value(d).unwrap_or_default())),
        Err(e) => Err(json_err(decide_status_code(&e), &e.to_string())),
    }
}

/// `GET /decide/stats`: per-backend decision metering (no content).
async fn decide_stats(
    headers: HeaderMap,
    State(st): State<Arc<AppState>>,
) -> Result<Json<decide::DecideStatus>, StatusCode> {
    if !authorized(&headers, &st.bearer) {
        return Err(StatusCode::UNAUTHORIZED);
    }
    Ok(Json(st.sessions.decide_service().status()))
}

/// `POST /decide/outcomes`: record one task's success for a backend.
async fn decide_outcome(
    headers: HeaderMap,
    State(st): State<Arc<AppState>>,
    body: axum::body::Bytes,
) -> Result<StatusCode, JsonErr> {
    if !authorized(&headers, &st.bearer) {
        return Err(json_err(StatusCode::UNAUTHORIZED, "unauthorized"));
    }
    let o: decide::OutcomeReq = serde_json::from_slice(&body)
        .map_err(|e| json_err(StatusCode::BAD_REQUEST, &format!("bad outcome: {e}")))?;
    st.sessions
        .decide_service()
        .record_outcome(&o)
        .map_err(|e| json_err(StatusCode::BAD_REQUEST, &e))?;
    Ok(StatusCode::NO_CONTENT)
}

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

// ---- HUP-S3.3 + S3.7: personas + track workflows ----

/// A shipped persona as `GET /personas` serves it: the view plus which of its allowlisted skills
/// this sidecar has installed.
#[derive(Serialize)]
struct PersonaListing {
    #[serde(flatten)]
    view: personas::PersonaView,
    /// Allowlisted skills in this sidecar's library (what a session with this persona offers).
    skills_installed: Vec<String>,
}

/// The shipped personas, each with the prompt fragment a client appends when it is active.
async fn list_personas(
    headers: HeaderMap,
    State(st): State<Arc<AppState>>,
) -> Result<Json<Vec<PersonaListing>>, JsonErr> {
    if !authorized(&headers, &st.bearer) {
        return Err(json_err(StatusCode::UNAUTHORIZED, "unauthorized"));
    }
    let views =
        personas::persona_views().map_err(|e| json_err(StatusCode::INTERNAL_SERVER_ERROR, &e))?;
    let lib = st.sessions.skills_library();
    Ok(Json(
        views
            .into_iter()
            .map(|view| PersonaListing {
                skills_installed: view
                    .persona
                    .skills
                    .iter()
                    .filter(|k| lib.as_ref().is_some_and(|l| l.get(k).is_some()))
                    .cloned()
                    .collect(),
                view,
            })
            .collect(),
    ))
}

#[derive(Deserialize)]
struct CheckPersonaReq {
    persona: personas::CustomPersona,
}

/// Validate a member-defined persona and render its fragment (422 with the reason when refused).
async fn check_persona(
    headers: HeaderMap,
    State(st): State<Arc<AppState>>,
    body: axum::body::Bytes,
) -> Result<Json<personas::PersonaView>, JsonErr> {
    if !authorized(&headers, &st.bearer) {
        return Err(json_err(StatusCode::UNAUTHORIZED, "unauthorized"));
    }
    let req: CheckPersonaReq = serde_json::from_slice(&body)
        .map_err(|e| json_err(StatusCode::BAD_REQUEST, &format!("bad persona: {e}")))?;
    req.persona
        .check()
        .map(Json)
        .map_err(|e| json_err(StatusCode::UNPROCESSABLE_ENTITY, &e))
}

/// A workflow as `GET /workflows` serves it: the view plus, when this sidecar cannot host a tool
/// the workflow needs, why it cannot run here.
#[derive(Serialize)]
struct WorkflowListing {
    #[serde(flatten)]
    view: workflows::WorkflowView,
    /// `None` = this sidecar hosts every sidecar tool the workflow needs. Core-hosted tools
    /// (journal_read, ...) depend on the session's own tool list and are checked at start.
    unavailable: Option<String>,
}

/// Why this sidecar cannot run a workflow needing `needs`, if it cannot.
fn sidecar_unavailable(st: &AppState, needs: &[String]) -> Option<String> {
    if st.sessions.toolchain_enabled() {
        return None;
    }
    let missing: Vec<&str> = needs
        .iter()
        .map(String::as_str)
        .filter(|t| toolchain::ToolchainHost::handles(t))
        .collect();
    if missing.is_empty() {
        None
    } else {
        Some(format!(
            "needs the contract toolchain ({}), which is off in this app",
            missing.join(", ")
        ))
    }
}

/// Every track's workflow family (definitions; the verifiers are named, not run). A session runs
/// one with `POST /sessions/:id/track_workflows`.
async fn list_workflows(
    headers: HeaderMap,
    State(st): State<Arc<AppState>>,
) -> Result<Json<Vec<WorkflowListing>>, JsonErr> {
    if !authorized(&headers, &st.bearer) {
        return Err(json_err(StatusCode::UNAUTHORIZED, "unauthorized"));
    }
    let views =
        workflows::workflow_views().map_err(|e| json_err(StatusCode::INTERNAL_SERVER_ERROR, &e))?;
    Ok(Json(
        views
            .into_iter()
            .map(|view| WorkflowListing {
                unavailable: sidecar_unavailable(&st, &view.needs_tools),
                view,
            })
            .collect(),
    ))
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct TrackWorkflowReq {
    workflow: String,
}

/// HUP-S3.3 (US-3.3 AC2): run a track's catalog workflow in a session, by id. The steps and
/// verifiers are the bundled catalog's, never the client's. Refused (422, naming the tools) when
/// the session does not offer a tool a pass needs, so a workflow never starts that cannot finish.
async fn start_track_workflow(
    headers: HeaderMap,
    State(st): State<Arc<AppState>>,
    Path(id): Path<String>,
    body: axum::body::Bytes,
) -> Result<(StatusCode, Json<serde_json::Value>), JsonErr> {
    if !authorized(&headers, &st.bearer) {
        return Err(json_err(StatusCode::UNAUTHORIZED, "unauthorized"));
    }
    if st.estop.is_stopped() {
        return Err(json_err(
            StatusCode::SERVICE_UNAVAILABLE,
            "emergency stop engaged",
        ));
    }
    let Some(session) = st.sessions.get(&id) else {
        return Err(json_err(StatusCode::NOT_FOUND, "no such session"));
    };
    let req: TrackWorkflowReq = serde_json::from_slice(&body).map_err(|e| {
        json_err(
            StatusCode::BAD_REQUEST,
            &format!("bad track workflow request: {e}"),
        )
    })?;
    let spec = workflows::find_workflow(&req.workflow)
        .map_err(|e| json_err(StatusCode::INTERNAL_SERVER_ERROR, &e))?
        .ok_or_else(|| {
            json_err(
                StatusCode::NOT_FOUND,
                "no such track workflow; see GET /workflows",
            )
        })?;
    let offered = session.tool_names();
    let missing: Vec<String> = spec
        .required_tools()
        .into_iter()
        .filter(|t| !offered.contains(t))
        .collect();
    if !missing.is_empty() {
        let mut reason = format!(
            "this workflow needs {}, which this conversation does not offer",
            missing.join(", ")
        );
        if let Some(why) = sidecar_unavailable(&st, &missing) {
            reason = format!("this workflow {why}");
        }
        return Err((
            StatusCode::UNPROCESSABLE_ENTITY,
            Json(serde_json::json!({ "error": reason, "missing_tools": missing })),
        ));
    }
    let wf = spec
        .build()
        .map_err(|e| json_err(StatusCode::INTERNAL_SERVER_ERROR, &e))?;
    let run_id = st
        .sessions
        .run_workflow(&id, wf, st.dispatch.clone())
        .map_err(|e| json_err(session_status(&e), "the session refused the workflow"))?;
    Ok((
        StatusCode::ACCEPTED,
        Json(serde_json::json!({
            "run_id": run_id,
            "workflow_id": spec.id,
            "track": spec.track,
            "evidence": spec.evidence(),
        })),
    ))
}

#[cfg(test)]
mod anchor_route_tests;
#[cfg(test)]
mod capsule_sandbox_tests;
#[cfg(test)]
mod grants_session_tests;
#[cfg(test)]
mod instruction_skills_route_tests;
#[cfg(test)]
mod learn_more_session_tests;
#[cfg(test)]
mod learn_session_tests;
#[cfg(test)]
mod mcp_session_tests;
#[cfg(test)]
mod metering_session_tests;
#[cfg(test)]
mod retrieval_http_tests;
#[cfg(test)]
mod session_reattach_tests;
#[cfg(test)]
mod sessions_tests;
#[cfg(test)]
mod sheets_session_tests;
#[cfg(test)]
mod skills_lock_env_tests;
#[cfg(test)]
mod skills_session_tests;
#[cfg(test)]
mod tests;
#[cfg(test)]
mod verify_probes_tests;

#[cfg(test)]
mod browser_session_tests;
#[cfg(test)]
mod decide_route_tests;
#[cfg(test)]
mod search_session_tests;
#[cfg(test)]
mod shell_run_tests;
#[cfg(test)]
mod signin_route_tests;
#[cfg(test)]
mod toolchain_reports_tests;
#[cfg(test)]
mod toolchain_tests;

// ---- HUP-S3.4: verified workflow runs + verified self-learning ----

async fn start_workflow(
    headers: HeaderMap,
    State(st): State<Arc<AppState>>,
    Path(id): Path<String>,
    body: axum::body::Bytes,
) -> Result<(StatusCode, Json<serde_json::Value>), JsonErr> {
    if !authorized(&headers, &st.bearer) {
        return Err(json_err(StatusCode::UNAUTHORIZED, "unauthorized"));
    }
    if st.estop.is_stopped() {
        return Err(json_err(
            StatusCode::SERVICE_UNAVAILABLE,
            "emergency stop engaged",
        ));
    }
    if st.sessions.get(&id).is_none() {
        return Err(json_err(StatusCode::NOT_FOUND, "no such session"));
    }
    let spec: workflow_spec::WorkflowSpec = serde_json::from_slice(&body)
        .map_err(|e| json_err(StatusCode::BAD_REQUEST, &format!("bad workflow: {e}")))?;
    // HUP-S1.3: HTTP checks reach loopback or consented origins only; hash checks read only
    // inside this session's folder grants (none: refused).
    let env = verify_probes::env_for(
        st.sessions.browser().cloned(),
        st.sessions.get(&id).and_then(|s| s.grants().cloned()),
    );
    let wf = spec
        .build_in(&env)
        .map_err(|e| json_err(StatusCode::BAD_REQUEST, &e))?;
    let run_id = st
        .sessions
        .run_workflow(&id, wf, st.dispatch.clone())
        .map_err(|e| json_err(session_status(&e), "the session refused the workflow"))?;
    Ok((
        StatusCode::ACCEPTED,
        Json(serde_json::json!({ "run_id": run_id })),
    ))
}

async fn workflow_run(
    headers: HeaderMap,
    State(st): State<Arc<AppState>>,
    Path((id, run)): Path<(String, String)>,
) -> Result<Json<sessions::RunView>, JsonErr> {
    if !authorized(&headers, &st.bearer) {
        return Err(json_err(StatusCode::UNAUTHORIZED, "unauthorized"));
    }
    st.sessions
        .run_view(&id, &run)
        .map(Json)
        .map_err(|e| json_err(session_status(&e), "no such session or run"))
}

fn refusal(r: learn::LearnRefusal) -> JsonErr {
    match r {
        learn::LearnRefusal::NotFound(m) => json_err(StatusCode::NOT_FOUND, &m),
        learn::LearnRefusal::Invalid(m) => json_err(StatusCode::BAD_REQUEST, &m),
        learn::LearnRefusal::Failed(m) => json_err(StatusCode::INTERNAL_SERVER_ERROR, &m),
        learn::LearnRefusal::Conflict { message, conflicts } => (
            StatusCode::CONFLICT,
            Json(serde_json::json!({ "error": message, "conflicts": conflicts })),
        ),
    }
}

/// The learn service, after the bearer check. With `write`, also refused while the e-stop is
/// engaged.
fn learn_guard(
    headers: &HeaderMap,
    st: &Arc<AppState>,
    write: bool,
) -> Result<Arc<learn::LearnService>, JsonErr> {
    if !authorized(headers, &st.bearer) {
        return Err(json_err(StatusCode::UNAUTHORIZED, "unauthorized"));
    }
    if write && st.estop.is_stopped() {
        return Err(json_err(
            StatusCode::SERVICE_UNAVAILABLE,
            "emergency stop engaged",
        ));
    }
    st.sessions.learn().cloned().ok_or_else(|| {
        json_err(
            StatusCode::SERVICE_UNAVAILABLE,
            "learning is off (no learn folder configured)",
        )
    })
}

async fn learn_status(
    headers: HeaderMap,
    State(st): State<Arc<AppState>>,
) -> Result<Json<serde_json::Value>, JsonErr> {
    if !authorized(&headers, &st.bearer) {
        return Err(json_err(StatusCode::UNAUTHORIZED, "unauthorized"));
    }
    Ok(Json(match st.sessions.learn() {
        Some(svc) => svc.status(),
        None => serde_json::json!({ "enabled": false }),
    }))
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct ProposeReq {
    session_id: String,
    run_id: String,
    content: citrate_agent_learn::ProposalContent,
    #[serde(default)]
    known_memories: Vec<citrate_agent_learn::KnownMemory>,
}

async fn learn_propose(
    headers: HeaderMap,
    State(st): State<Arc<AppState>>,
    body: axum::body::Bytes,
) -> Result<(StatusCode, Json<citrate_agent_learn::Proposal>), JsonErr> {
    let svc = learn_guard(&headers, &st, true)?;
    let req: ProposeReq = serde_json::from_slice(&body)
        .map_err(|e| json_err(StatusCode::BAD_REQUEST, &format!("bad proposal: {e}")))?;
    let session = st
        .sessions
        .get(&req.session_id)
        .ok_or_else(|| json_err(StatusCode::NOT_FOUND, "no such session"))?;
    let p = svc
        .propose(&session, &req.run_id, req.content, &req.known_memories)
        .map_err(refusal)?;
    Ok((StatusCode::CREATED, Json(p)))
}

#[derive(Deserialize)]
struct ListQuery {
    #[serde(default)]
    all: bool,
}

async fn learn_list(
    headers: HeaderMap,
    State(st): State<Arc<AppState>>,
    Query(q): Query<ListQuery>,
) -> Result<Json<serde_json::Value>, JsonErr> {
    let svc = learn_guard(&headers, &st, false)?;
    Ok(Json(serde_json::json!({ "proposals": svc.list(q.all) })))
}

async fn learn_get(
    headers: HeaderMap,
    State(st): State<Arc<AppState>>,
    Path(pid): Path<String>,
) -> Result<Json<citrate_agent_learn::Proposal>, JsonErr> {
    let svc = learn_guard(&headers, &st, false)?;
    svc.get(&pid)
        .map(Json)
        .ok_or_else(|| json_err(StatusCode::NOT_FOUND, "no such proposal"))
}

async fn learn_accept(
    headers: HeaderMap,
    State(st): State<Arc<AppState>>,
    Path(pid): Path<String>,
    body: axum::body::Bytes,
) -> Result<Json<serde_json::Value>, JsonErr> {
    let svc = learn_guard(&headers, &st, true)?;
    let decision: citrate_agent_learn::MemberAccept = serde_json::from_slice(&body)
        .map_err(|e| json_err(StatusCode::BAD_REQUEST, &format!("bad accept: {e}")))?;
    let out = svc.accept(&pid, decision).map_err(refusal)?;
    let mut body = serde_json::json!({ "ok": true, "persisted": out });
    if matches!(out, learn::AcceptedView::Skill { .. }) {
        // HUP-S3.4: offer the saved skill to the next session without a restart.
        let reloaded = st.sessions.reload_skills();
        body["skills_reloaded"] = serde_json::Value::Bool(reloaded.is_some());
        if let Some(n) = reloaded {
            body["skills_offered"] = serde_json::json!(n);
        }
    }
    Ok(Json(body))
}

/// The member resolves a contradiction between two learned memories (HIC-1, recorded first):
/// keep one, retract the other. Returns the resolution for core's ledger and memory graph.
async fn learn_resolve(
    headers: HeaderMap,
    State(st): State<Arc<AppState>>,
    body: axum::body::Bytes,
) -> Result<Json<serde_json::Value>, JsonErr> {
    let svc = learn_guard(&headers, &st, true)?;
    let req: citrate_agent_learn::MemberResolve = serde_json::from_slice(&body)
        .map_err(|e| json_err(StatusCode::BAD_REQUEST, &format!("bad resolve: {e}")))?;
    let r = svc.resolve(req).map_err(refusal)?;
    Ok(Json(serde_json::json!({ "ok": true, "resolution": r })))
}

#[derive(Deserialize)]
struct RejectReq {
    member: String,
    #[serde(default)]
    reason: String,
}

async fn learn_reject(
    headers: HeaderMap,
    State(st): State<Arc<AppState>>,
    Path(pid): Path<String>,
    body: axum::body::Bytes,
) -> Result<Json<serde_json::Value>, JsonErr> {
    let svc = learn_guard(&headers, &st, true)?;
    let req: RejectReq = serde_json::from_slice(&body)
        .map_err(|e| json_err(StatusCode::BAD_REQUEST, &format!("bad reject: {e}")))?;
    svc.reject(&pid, &req.member, &req.reason)
        .map_err(refusal)?;
    Ok(Json(serde_json::json!({ "ok": true, "rejected": true })))
}

#[derive(Deserialize)]
struct PublishReq {
    approval: citrate_agent_learn::PublishApproval,
    params: citrate_agent_learn::PublishParams,
}

/// Build the SkillRegistry call for an accepted skill (HIC-1, recorded). Calldata only: core's
/// SignatureCeremony signs, the member sends.
async fn learn_publish(
    headers: HeaderMap,
    State(st): State<Arc<AppState>>,
    Path(pid): Path<String>,
    body: axum::body::Bytes,
) -> Result<Json<citrate_agent_learn::SkillPublishPayload>, JsonErr> {
    let svc = learn_guard(&headers, &st, true)?;
    let req: PublishReq = serde_json::from_slice(&body)
        .map_err(|e| json_err(StatusCode::BAD_REQUEST, &format!("bad publish: {e}")))?;
    svc.publish(&pid, req.approval, req.params)
        .map(Json)
        .map_err(refusal)
}
#[cfg(test)]
mod daemon_session_tests;
#[cfg(test)]
mod escalation_tests;
#[cfg(test)]
mod files_tests;
#[cfg(test)]
mod hic_records_tests;
#[cfg(test)]
mod mcp_probe_tests;
#[cfg(test)]
mod personas_route_tests;
#[cfg(test)]
mod track_workflow_route_tests;
#[cfg(test)]
mod undo_writes_tests;
