//! citrate-agent-sidecar — the binary citrate-core spawns as the keyless agent (installed as the
//! `hermes` sidecar). Config is via ENV; the bearer comes as a FILE PATH, never inline:
//!
//!   CITRATE_HERMES_ADDR         loopback control bind, e.g. 127.0.0.1:19700 (required)
//!   CITRATE_HERMES_TOKEN_FILE   path to the 0600 bearer-token file citrate-core wrote (required)
//!   CITRATE_HERMES_CAPSULES     capsule (skill) directory to load; default ./capsules (optional)

use std::sync::Arc;

use agent_sidecar::{app, load_dispatch, load_skills, AppState};
use citrate_agent_core::hitl::ApprovalQueue;
use citrate_agent_legacy::estop::EmergencyStop;

fn required(key: &str) -> Result<String, String> {
    std::env::var(key).map_err(|_| format!("{key} is required"))
}

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    let addr = required("CITRATE_HERMES_ADDR")?;
    let token_file = required("CITRATE_HERMES_TOKEN_FILE")?;
    let bearer = std::fs::read_to_string(&token_file)
        .map_err(|e| format!("reading bearer file {token_file}: {e}"))?
        .trim()
        .to_string();
    if bearer.is_empty() {
        return Err("bearer file is empty (fail closed)".into());
    }
    let capsule_dir =
        std::env::var("CITRATE_HERMES_CAPSULES").unwrap_or_else(|_| "capsules".to_string());
    let capsule_path = std::path::Path::new(&capsule_dir);
    let skills = load_skills(capsule_path);
    let queue = Arc::new(ApprovalQueue::new());
    // The dispatch carries the QueuedApprovalGate over `queue`, so a skill's chain effect surfaces on
    // the same queue /approvals + /status read.
    let dispatch = load_dispatch(capsule_path, queue.clone());
    // PBA-L6b-015: list only skills the dispatch will actually run (a refused or unverified
    // capsule is not a skill).
    let skills: Vec<_> = match &dispatch {
        Some(d) => skills.into_iter().filter(|s| d.has(&s.name)).collect(),
        None => skills,
    };

    let state = Arc::new(AppState {
        estop: EmergencyStop::new(),
        queue,
        skills,
        dispatch,
        bearer,
        run_slots: Arc::new(tokio::sync::Semaphore::new(agent_sidecar::MAX_CONCURRENT_SKILLS)),
    });

    // AR-B-024: the control plane is a bearer-authed LOOPBACK plane by contract.
    // Refuse to bind a non-loopback address (e.g. 0.0.0.0) unless the operator
    // explicitly opts in via CITRATE_HERMES_ALLOW_NONLOOPBACK=1, so a
    // misconfiguration cannot silently expose run_skill/approve to the network.
    let allow_nonloopback =
        std::env::var("CITRATE_HERMES_ALLOW_NONLOOPBACK").as_deref() == Ok("1");
    agent_sidecar::enforce_loopback_bind(&addr, allow_nonloopback)?;

    eprintln!(
        "citrate-agent-sidecar: {} skills, control on {}",
        state.skills.len(),
        addr
    );
    let listener = tokio::net::TcpListener::bind(&addr).await?;
    axum::serve(listener, app(state)).await?;
    Ok(())
}
