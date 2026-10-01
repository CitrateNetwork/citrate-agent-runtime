//! HUP-S1.9 — sidecar parity: every scenario in agent-loop's `parity-v1.json` (the same bytes that
//! drive citrate-core's TypeScript loop) run through the sidecar's real wire parser
//! (`llm_http::parse_turn`) feeding `run_turn`. Scope: the wire parser and the loop only. The
//! session layer (`sessions.rs` config such as its default `max_steps`, and the core-host
//! `tool_results` round trip) and citrate-core's `sidecarProvider.ts` are not exercised here, so a
//! pass is loop parity, not end-to-end parity of the live core + sidecar path.
#[path = "../../agent-loop/tests/parity_common/mod.rs"]
mod parity_common;

use agent_sidecar::llm_http::parse_turn;
use citrate_agent_loop::{AssistantTurn, LlmError};
use parity_common::*;
use serde_json::{json, Value};
use std::sync::Arc;

fn wire_to_turn(entry: &Value) -> Result<AssistantTurn, LlmError> {
    if let Some(raw) = entry.get("raw").and_then(Value::as_str) {
        return parse_turn(raw);
    }
    let body = json!({"choices": [{"index": 0, "message": entry["message"]}]});
    parse_turn(&body.to_string())
}

#[test]
fn parity_fixture_is_pinned_for_the_sidecar() {
    assert_eq!(sha256_hex(FIXTURE_BYTES), PARITY_V1_SHA256);
}

#[test]
fn parity_sidecar_matches_every_scenario() {
    let fx = fixture();
    let to_turn: Arc<TurnFn> = Arc::new(wire_to_turn);
    let mut ran = 0;
    let mut failures = Vec::new();
    for scn in fx["scenarios"].as_array().unwrap() {
        ran += 1;
        failures.extend(run_scenario(&fx, scn, "sidecar", to_turn.clone()));
    }
    assert!(ran >= 21, "ran {ran} scenarios");
    assert!(
        failures.is_empty(),
        "parity failures:\n{}",
        failures.join("\n")
    );
}
