//! `get_tx_history` — return recent transactions for an address.
//!
//! Data source: `NodeService::get_transactions_for_address(addr, limit)`.
//! Falls back to the primary wallet account when no address is given.
//! GUI closure executes.

use citrate_agent_core::error::AgentError;
use citrate_agent_core::tool::{AgentTool, RiskLevel, ToolContext, ToolResult};

pub struct GetTxHistory;

#[async_trait::async_trait]
impl AgentTool for GetTxHistory {
    fn name(&self) -> &str { "get_tx_history" }
    fn description(&self) -> &str {
        "Return recent transactions for an address (send, receive, reward, etc.) with hash, type, amount, counterparty, status, and timestamp. If no address is provided, uses the primary wallet account. Default count = 20, max = 100."
    }
    fn parameters_schema(&self) -> serde_json::Value {
        serde_json::json!({
            "type": "object",
            "properties": {
                "address": {
                    "type": "string",
                    "description": "Wallet address to query (0x…). Defaults to the primary wallet account."
                },
                "count": {
                    "type": "integer",
                    "minimum": 1,
                    "maximum": 100,
                    "description": "Number of transactions to fetch (default 20)"
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
