//! HUP-S1.9 — loop parity: the sidecar's agent loop (`run_turn`) against every `layer: "loop"`
//! scenario in `fixtures/parity-v1.json`, the same bytes that drive citrate-core's TypeScript loop
//! (`src/agent/harness.ts`). `layer: "wire"` scenarios (malformed model bodies, missing ids, object
//! arguments) are about parsing the model's wire message, which is the client's job, not the loop's;
//! they run through the sidecar's real parser in `agent-sidecar/tests/parity_wire_tests.rs`.
mod parity_common;

use citrate_agent_loop::{AssistantTurn, LlmError, ToolCall};
use parity_common::*;
use serde_json::Value;
use std::sync::Arc;

/// A well-formed OpenAI `choices[0].message` as an [`AssistantTurn`] (loop-layer scenarios only).
fn message_to_turn(entry: &Value) -> Result<AssistantTurn, LlmError> {
    let m = entry
        .get("message")
        .ok_or_else(|| LlmError::BadResponse("loop layer scenarios carry a message".into()))?;
    let tool_calls = m["tool_calls"]
        .as_array()
        .map(|a| {
            a.iter()
                .map(|tc| ToolCall {
                    id: tc["id"].as_str().unwrap_or_default().into(),
                    name: tc["function"]["name"].as_str().unwrap_or_default().into(),
                    arguments: tc["function"]["arguments"].as_str().unwrap_or("{}").into(),
                })
                .collect()
        })
        .unwrap_or_default();
    Ok(AssistantTurn {
        content: m["content"].as_str().unwrap_or_default().into(),
        tool_calls,
    })
}

#[test]
fn parity_fixture_is_pinned() {
    assert_eq!(sha256_hex(FIXTURE_BYTES), PARITY_V1_SHA256);
}

#[test]
fn parity_fixture_is_well_formed() {
    let fx = fixture();
    assert_eq!(fx["version"], 1);
    let scns = fx["scenarios"].as_array().expect("scenarios");
    let mut ids: Vec<&str> = scns.iter().map(|s| s["id"].as_str().unwrap()).collect();
    let n = ids.len();
    ids.sort_unstable();
    ids.dedup();
    assert_eq!(ids.len(), n, "scenario ids are unique");
    for s in scns {
        assert!(matches!(s["layer"].as_str(), Some("loop" | "wire")));
        if let Some(d) = s.get("known_divergence") {
            assert!(!d["reason"].as_str().unwrap_or("").is_empty());
            assert!(matches!(
                d["verdict"].as_str(),
                Some("rust_correct" | "owner_decision")
            ));
        }
    }
}

#[test]
fn parity_loop_matches_every_loop_scenario() {
    let fx = fixture();
    let to_turn: Arc<TurnFn> = Arc::new(message_to_turn);
    let mut ran = 0;
    let mut failures = Vec::new();
    for scn in fx["scenarios"].as_array().unwrap() {
        if scn["layer"] != "loop" {
            continue;
        }
        ran += 1;
        failures.extend(run_scenario(&fx, scn, "loop", to_turn.clone()));
    }
    assert!(ran >= 16, "ran {ran} loop scenarios");
    assert!(
        failures.is_empty(),
        "parity failures:\n{}",
        failures.join("\n")
    );
}
