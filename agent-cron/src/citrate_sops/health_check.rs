//! Health check SOP — periodic node connectivity and liveness probe.
//!
//! This SOP is designed to run on a cron schedule (e.g., every 60 seconds).
//! It verifies that the local node is reachable, responding to RPC calls,
//! and has peers connected.
//!
//! Required tools in the `ToolRegistry`:
//! - `node_health` — calls `net_peerCount` and `eth_syncing` to verify node health
//! - `send_alert` — sends an alert notification if the node is unhealthy

use crate::sop::{SOPDefinition, SOPStep, SOPTrigger};

/// Create a health-check SOP that runs every 60 seconds.
///
/// Steps:
/// 1. `node_health` — probes the node for peer count and sync status
/// 2. `send_alert` — fires if the health check returned data indicating issues
///
/// The health tool returns structured data with fields like `peer_count`,
/// `is_syncing`, and `is_healthy`. The alert step fires only when data is
/// present (condition: `"has_data"`), letting the alert tool evaluate severity.
pub fn health_check_sop() -> SOPDefinition {
    SOPDefinition {
        id: "citrate.health_check".to_string(),
        name: "Node Health Check".to_string(),
        trigger: SOPTrigger::Cron("0 * * * * *".to_string()),
        steps: vec![
            SOPStep {
                tool_name: "node_health".to_string(),
                params: serde_json::json!({
                    "rpc_url": "http://127.0.0.1:8545",
                    "checks": ["peer_count", "sync_status", "block_production"]
                }),
                condition: None,
            },
            SOPStep {
                tool_name: "send_alert".to_string(),
                params: serde_json::json!({
                    "alert_type": "node_unhealthy",
                    "severity": "critical",
                    "message": "Node health check failed — verify node connectivity and sync status"
                }),
                condition: Some("has_data".to_string()),
            },
        ],
        enabled: true,
    }
}

/// Create a health-check SOP with a custom cron schedule and RPC endpoint.
///
/// # Arguments
/// * `schedule` — A 6-field cron expression (e.g., `"0 */2 * * * *"` for every 2 minutes)
/// * `rpc_url` — The JSON-RPC endpoint URL to probe
pub fn health_check_sop_custom(schedule: &str, rpc_url: &str) -> SOPDefinition {
    let mut sop = health_check_sop();
    sop.trigger = SOPTrigger::Cron(schedule.to_string());
    sop.steps[0].params = serde_json::json!({
        "rpc_url": rpc_url,
        "checks": ["peer_count", "sync_status", "block_production"]
    });
    sop
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_health_check_sop_structure() {
        let sop = health_check_sop();
        assert_eq!(sop.id, "citrate.health_check");
        assert_eq!(sop.name, "Node Health Check");
        assert!(sop.enabled);
        assert_eq!(sop.steps.len(), 2);
        assert_eq!(sop.steps[0].tool_name, "node_health");
        assert_eq!(sop.steps[1].tool_name, "send_alert");
    }

    #[test]
    fn test_health_check_sop_trigger() {
        let sop = health_check_sop();
        match &sop.trigger {
            SOPTrigger::Cron(expr) => assert_eq!(expr, "0 * * * * *"),
            other => panic!("Expected Cron trigger, got {:?}", other),
        }
    }

    #[test]
    fn test_health_check_sop_custom() {
        let sop = health_check_sop_custom("0 */2 * * * *", "https://rpc.citrate.ai");
        match &sop.trigger {
            SOPTrigger::Cron(expr) => assert_eq!(expr, "0 */2 * * * *"),
            other => panic!("Expected Cron trigger, got {:?}", other),
        }
        assert_eq!(sop.steps[0].params["rpc_url"], "https://rpc.citrate.ai");
    }

    #[test]
    fn test_health_check_alert_params() {
        let sop = health_check_sop();
        assert_eq!(sop.steps[1].params["severity"], "critical");
        assert_eq!(sop.steps[1].params["alert_type"], "node_unhealthy");
    }

    #[test]
    fn test_health_check_serializable() {
        let sop = health_check_sop();
        let json = serde_json::to_string(&sop).expect("serialize health_check SOP");
        let deserialized: SOPDefinition =
            serde_json::from_str(&json).expect("deserialize health_check SOP");
        assert_eq!(deserialized.id, sop.id);
        assert_eq!(deserialized.steps.len(), sop.steps.len());
    }
}
