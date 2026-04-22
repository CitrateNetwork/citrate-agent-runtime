//! `get_recent_blocks` — return the N most recent blocks (newest first).
//!
//! Data source: `NodeService::get_recent_blocks(count)` which pulls from
//! local storage index. GUI closure executes.

use citrate_agent_core::error::AgentError;
use citrate_agent_core::tool::{AgentTool, RiskLevel, ToolContext, ToolResult};

pub struct GetRecentBlocks;

#[async_trait::async_trait]
impl AgentTool for GetRecentBlocks {
    fn name(&self) -> &str { "get_recent_blocks" }
    fn description(&self) -> &str {
        "Return the most recent blocks in the chain (newest first), with height, hash, tx count, timestamp, and blue score. Use this when the user wants a block list, chain activity, or recent history. Default count = 10, max = 50."
    }
    fn parameters_schema(&self) -> serde_json::Value {
        serde_json::json!({
            "type": "object",
            "properties": {
                "count": {
                    "type": "integer",
                    "minimum": 1,
                    "maximum": 50,
                    "description": "Number of blocks to fetch (default 10)"
                }
            },
            "required": []
        })
    }
    fn risk_level(&self) -> RiskLevel { RiskLevel::Low }

    async fn execute(&self, _params: serde_json::Value, _ctx: &ToolContext) -> Result<ToolResult, AgentError> {
        Ok(ToolResult::ok("dispatched to GUI executor"))
    }
}
