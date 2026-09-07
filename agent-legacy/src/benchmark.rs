//! Benchmark export — opt-in trace packaging for research and evaluation.
//!
//! BenchmarkTrace is the research truth projection of the trail layer.
//! Traces can be exported as JSON for replay, scoring, and model comparison.
//!
//! Export requires explicit consent — no traces leave the device without
//! the user choosing to export them.

use crate::canonical::{BenchmarkTrace, TrailEvent};
use serde::{Deserialize, Serialize};

/// A benchmark pack — a collection of traces for export.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct BenchmarkPack {
    /// Pack metadata
    pub name: String,
    pub version: String,
    pub created_at: String,
    /// Network the traces were recorded on
    pub network: String,
    /// Model used for inference
    pub model: String,
    /// Number of traces in this pack
    pub trace_count: usize,
    /// Traces
    pub traces: Vec<BenchmarkTrace>,
    /// Aggregate statistics
    pub stats: PackStats,
}

/// Aggregate statistics for a benchmark pack.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PackStats {
    pub total_tasks: usize,
    pub successful_tasks: usize,
    pub total_tool_calls: u32,
    pub total_approvals: u32,
    pub avg_duration_ms: u64,
    pub avg_tool_calls_per_task: f32,
}

/// Build a benchmark pack from a set of traces.
pub fn build_pack(
    name: &str,
    network: &str,
    model: &str,
    traces: Vec<BenchmarkTrace>,
) -> BenchmarkPack {
    let total = traces.len();
    let successful = traces.iter().filter(|t| t.success).count();
    let total_tools: u32 = traces.iter().map(|t| t.tool_call_count).sum();
    let total_approvals: u32 = traces.iter().map(|t| t.approval_count).sum();
    let total_duration: u64 = traces.iter().map(|t| t.total_duration_ms).sum();
    let avg_duration = if total > 0 {
        total_duration / total as u64
    } else {
        0
    };
    let avg_tools = if total > 0 {
        total_tools as f32 / total as f32
    } else {
        0.0
    };

    BenchmarkPack {
        name: name.to_string(),
        version: "1.0".to_string(),
        created_at: chrono::Utc::now().to_rfc3339(),
        network: network.to_string(),
        model: model.to_string(),
        trace_count: total,
        traces,
        stats: PackStats {
            total_tasks: total,
            successful_tasks: successful,
            total_tool_calls: total_tools,
            total_approvals,
            avg_duration_ms: avg_duration,
            avg_tool_calls_per_task: avg_tools,
        },
    }
}

/// Export a benchmark pack as JSON string.
pub fn export_json(pack: &BenchmarkPack) -> Result<String, serde_json::Error> {
    serde_json::to_string_pretty(pack)
}

/// Sensitive JSON keys redacted from exported trail events, at ANY nesting depth.
///
/// AR-B-031: the producer nests everything under `data.params` / `data.result`
/// (see `mcp_server` tool_call_to_trail_event), but the old redactor scanned
/// only the TOP-LEVEL keys of `data`, so it never fired on the shape the crate
/// actually emits — `data.params.private_key` was exported verbatim. The key
/// set was also missing `key`, `seed`, `password`, `secret`, `signature`,
/// `token`.
const SENSITIVE_KEYS: &[&str] = &[
    "address",
    "from",
    "to",
    "wallet_address",
    "private_key",
    "privatekey",
    "mnemonic",
    "key",
    "seed",
    "password",
    "secret",
    "signature",
    "token",
];

/// Recursively replace the value of any [`SENSITIVE_KEYS`] key with
/// `"[REDACTED]"`, walking nested objects and arrays.
fn redact_json_in_place(value: &mut serde_json::Value) {
    match value {
        serde_json::Value::Object(map) => {
            for (k, v) in map.iter_mut() {
                if SENSITIVE_KEYS.contains(&k.to_ascii_lowercase().as_str()) {
                    *v = serde_json::json!("[REDACTED]");
                } else {
                    redact_json_in_place(v);
                }
            }
        }
        serde_json::Value::Array(items) => {
            for v in items.iter_mut() {
                redact_json_in_place(v);
            }
        }
        _ => {}
    }
}

/// Redact sensitive data from trail events before export.
/// Removes wallet addresses, private keys, and other PII at any nesting depth.
pub fn redact_event(event: &TrailEvent) -> TrailEvent {
    let mut redacted = event.clone();
    redact_json_in_place(&mut redacted.data);
    redacted
}

/// Redact all events in a trace before export.
pub fn redact_trace(trace: &BenchmarkTrace) -> BenchmarkTrace {
    let mut redacted = trace.clone();
    redacted.events = redacted.events.iter().map(redact_event).collect();
    redacted
}

#[cfg(test)]
mod tests {
    use super::*;

    fn sample_trace(success: bool) -> BenchmarkTrace {
        BenchmarkTrace {
            id: "t1".to_string(),
            session_id: "s1".to_string(),
            task: "Test task".to_string(),
            model: "qwen2.5:72b".to_string(),
            events: vec![],
            total_duration_ms: 1000,
            tool_call_count: 3,
            approval_count: 1,
            success,
            human_rating: None,
        }
    }

    #[test]
    fn test_build_pack() {
        let traces = vec![sample_trace(true), sample_trace(false)];
        let pack = build_pack("test-pack", "testnet", "qwen2.5:72b", traces);
        assert_eq!(pack.trace_count, 2);
        assert_eq!(pack.stats.successful_tasks, 1);
        assert_eq!(pack.stats.total_tool_calls, 6);
        assert_eq!(pack.stats.avg_duration_ms, 1000);
    }

    #[test]
    fn test_export_json() {
        let pack = build_pack("test", "testnet", "qwen", vec![sample_trace(true)]);
        let json = export_json(&pack).expect("serializes");
        assert!(json.contains("test-pack") || json.contains("test"));
        assert!(json.contains("testnet"));
    }

    #[test]
    fn test_redact_event() {
        let event = TrailEvent {
            id: "e1".to_string(),
            session_id: "s1".to_string(),
            timestamp: "2026-03-31".to_string(),
            event_type: "tool_call".to_string(),
            tool_name: Some("send_tx".to_string()),
            data: serde_json::json!({"address": "0x1234", "amount": "100"}),
            risk_level: Some("high".to_string()),
            approved: Some(true),
            duration_ms: Some(500),
        };
        let redacted = redact_event(&event);
        assert_eq!(redacted.data["address"], "[REDACTED]");
        assert_eq!(redacted.data["amount"], "100"); // Not redacted
    }

    #[test]
    fn redact_event_redacts_nested_secrets() {
        // AR-B-031: the producer nests under data.params/data.result, so the
        // redactor must reach a secret at any depth — not only top-level keys.
        let event = TrailEvent {
            id: "e2".to_string(),
            session_id: "s1".to_string(),
            timestamp: "2026-03-31".to_string(),
            event_type: "tool_call".to_string(),
            tool_name: Some("send_tx".to_string()),
            data: serde_json::json!({
                "params": { "private_key": "0xdeadbeef", "to": "0xabc", "amount": "5" },
                "result": { "signature": "0xsig", "ok": true }
            }),
            risk_level: Some("high".to_string()),
            approved: Some(true),
            duration_ms: Some(500),
        };
        let r = redact_event(&event);
        assert_eq!(r.data["params"]["private_key"], "[REDACTED]");
        assert_eq!(r.data["params"]["to"], "[REDACTED]");
        assert_eq!(r.data["result"]["signature"], "[REDACTED]");
        // Non-sensitive fields survive.
        assert_eq!(r.data["params"]["amount"], "5");
        assert_eq!(r.data["result"]["ok"], true);
    }

    #[test]
    fn test_empty_pack() {
        let pack = build_pack("empty", "devnet", "none", vec![]);
        assert_eq!(pack.stats.total_tasks, 0);
        assert_eq!(pack.stats.avg_duration_ms, 0);
    }
}
