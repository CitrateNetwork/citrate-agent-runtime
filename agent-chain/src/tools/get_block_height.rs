//! `get_block_height` — return the current chain head height + chain ID.
//!
//! Data source: `NodeService::get_status()` which wraps `eth_blockNumber`
//! against the embedded node's RPC. The GUI closure in
//! `citrate_gui_native/src/main.rs` provides the real execution; this
//! trait impl exists so the LLM gets the tool schema via
//! `ToolRegistry::tool_definitions()`.

use citrate_agent_core::error::AgentError;
use citrate_agent_core::tool::{AgentTool, RiskLevel, ToolContext, ToolResult};

pub struct GetBlockHeight;

#[async_trait::async_trait]
impl AgentTool for GetBlockHeight {
    fn name(&self) -> &str { "get_block_height" }
    fn description(&self) -> &str {
        "Get the current Citrate chain height (latest block number) and chain ID. Use this when the user asks how tall the chain is, what block we're on, or if the node is syncing."
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
        // Actual execution happens in the GUI's tool-executor closure
        // (see citrate_gui_native/src/main.rs). This impl exists so the
        // tool gets a schema that the LLM can consume.
        Ok(ToolResult::ok("dispatched to GUI executor"))
    }
}
