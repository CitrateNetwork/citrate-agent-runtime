//! `get_peer_count` — return the number of P2P peers + mempool + DAG-tip stats.
//!
//! Data source: `NodeService::get_status()`. GUI closure executes.

use citrate_agent_core::error::AgentError;
use citrate_agent_core::tool::{AgentTool, RiskLevel, ToolContext, ToolResult};

pub struct GetPeerCount;

#[async_trait::async_trait]
impl AgentTool for GetPeerCount {
    fn name(&self) -> &str { "get_peer_count" }
    fn description(&self) -> &str {
        "Get the count of connected P2P peers, mempool transaction count, and DAG tip count. Use this when the user asks about network connectivity, peers, or node health."
    }
    fn parameters_schema(&self) -> serde_json::Value {
        serde_json::json!({
            "type": "object",
            "properties": {},
            "required": []
        })
    }
    fn risk_level(&self) -> RiskLevel { RiskLevel::Low }

    async fn execute(&self, _params: serde_json::Value, _ctx: &ToolContext) -> Result<ToolResult, AgentError> {
        Ok(ToolResult::ok("dispatched to GUI executor"))
    }
}
