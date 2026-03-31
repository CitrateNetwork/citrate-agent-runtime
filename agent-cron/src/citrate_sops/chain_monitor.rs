//! Chain monitor SOP — watches block height and alerts on missed blocks.
//!
//! This SOP is designed to run on a cron schedule (e.g., every 30 seconds).
//! It queries the current block height and compares it against the previous
//! reading. If no new blocks have been produced within the expected interval,
//! it fires an alert step.
//!
//! Required tools in the `ToolRegistry`:
//! - `get_block_height` — returns `{"block_height": u64}` via `eth_blockNumber`
//! - `send_alert` — sends an alert notification

use crate::sop::{SOPDefinition, SOPStep, SOPTrigger};

/// Create a chain-monitor SOP that runs every 30 seconds.
///
/// Steps:
/// 1. `get_block_height` — queries the node for the latest block number
/// 2. `send_alert` — fires an alert if new blocks stopped (conditioned on `has_data`)
///
/// The `send_alert` step uses the `"has_data"` condition, meaning it only fires
/// when the height-check tool returns structured data. In practice, the alert
/// tool itself decides whether to alert based on the delta between readings.
pub fn chain_monitor_sop() -> SOPDefinition {
    SOPDefinition {
        id: "citrate.chain_monitor".to_string(),
        name: "Chain Block Height Monitor".to_string(),
        trigger: SOPTrigger::Cron("0 */30 * * * *".to_string()),
        steps: vec![
            SOPStep {
                tool_name: "get_block_height".to_string(),
                params: serde_json::json!({
                    "rpc_url": "http://127.0.0.1:8545",
                    "method": "eth_blockNumber"
                }),
                condition: None,
            },
            SOPStep {
                tool_name: "send_alert".to_string(),
                params: serde_json::json!({
                    "alert_type": "missed_blocks",
                    "severity": "warning",
                    "message": "No new blocks detected in the last monitoring interval"
                }),
                // Only fire alert if the previous step returned data
                condition: Some("has_data".to_string()),
            },
        ],
        enabled: true,
    }
}

/// Create a chain-monitor SOP with a custom cron schedule.
///
/// # Arguments
/// * `schedule` — A 6-field cron expression (e.g., `"0 */15 * * * *"` for every 15 seconds)
/// * `rpc_url` — The JSON-RPC endpoint URL to query
pub fn chain_monitor_sop_custom(schedule: &str, rpc_url: &str) -> SOPDefinition {
    let mut sop = chain_monitor_sop();
    sop.trigger = SOPTrigger::Cron(schedule.to_string());
    sop.steps[0].params = serde_json::json!({
        "rpc_url": rpc_url,
        "method": "eth_blockNumber"
    });
    sop
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_chain_monitor_sop_structure() {
        let sop = chain_monitor_sop();
        assert_eq!(sop.id, "citrate.chain_monitor");
        assert!(sop.enabled);
        assert_eq!(sop.steps.len(), 2);
        assert_eq!(sop.steps[0].tool_name, "get_block_height");
        assert_eq!(sop.steps[1].tool_name, "send_alert");
        assert!(sop.steps[0].condition.is_none());
        assert_eq!(
            sop.steps[1].condition.as_deref(),
            Some("has_data")
        );
    }

    #[test]
    fn test_chain_monitor_sop_trigger() {
        let sop = chain_monitor_sop();
        match &sop.trigger {
            SOPTrigger::Cron(expr) => assert_eq!(expr, "0 */30 * * * *"),
            other => panic!("Expected Cron trigger, got {:?}", other),
        }
    }

    #[test]
    fn test_chain_monitor_sop_custom() {
        let sop = chain_monitor_sop_custom("0 */10 * * * *", "http://rpc.citrate.ai:8545");
        match &sop.trigger {
            SOPTrigger::Cron(expr) => assert_eq!(expr, "0 */10 * * * *"),
            other => panic!("Expected Cron trigger, got {:?}", other),
        }
        assert_eq!(sop.steps[0].params["rpc_url"], "http://rpc.citrate.ai:8545");
    }

    #[test]
    fn test_chain_monitor_serializable() {
        let sop = chain_monitor_sop();
        let json = serde_json::to_string(&sop).expect("serialize chain_monitor SOP");
        let deserialized: SOPDefinition =
            serde_json::from_str(&json).expect("deserialize chain_monitor SOP");
        assert_eq!(deserialized.id, sop.id);
        assert_eq!(deserialized.steps.len(), sop.steps.len());
    }
}
