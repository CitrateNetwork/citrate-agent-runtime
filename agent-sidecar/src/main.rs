//! citrate-agent-sidecar — the binary citrate-core spawns as the keyless agent (installed as the
//! `hermes` sidecar). Config is via ENV; the bearer comes as a FILE PATH, never inline:
//!
//!   CITRATE_HERMES_ADDR         loopback control bind, e.g. 127.0.0.1:19700 (required)
//!   CITRATE_HERMES_TOKEN_FILE   path to the 0600 bearer-token file citrate-core wrote (required)
//!   CITRATE_HERMES_CAPSULES     capsule (skill) directory to load; default ./capsules (optional)

use std::sync::Arc;

use agent_sidecar::{app, load_skills, AppState};
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
    let skills = load_skills(std::path::Path::new(&capsule_dir));

    let state = Arc::new(AppState {
        estop: EmergencyStop::new(),
        queue: Arc::new(ApprovalQueue::new()),
        skills,
        bearer,
    });

    eprintln!(
        "citrate-agent-sidecar: {} skills, control on {}",
        state.skills.len(),
        addr
    );
    let listener = tokio::net::TcpListener::bind(&addr).await?;
    axum::serve(listener, app(state)).await?;
    Ok(())
}
