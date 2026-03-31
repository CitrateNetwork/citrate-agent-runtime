use citrate_agent_core::error::AgentError;
use citrate_agent_core::tool::{AgentTool, RiskLevel, ToolContext, ToolResult};

pub struct CheckBalance;

#[async_trait::async_trait]
impl AgentTool for CheckBalance {
    fn name(&self) -> &str { "check_balance" }
    fn description(&self) -> &str { "Check the SALT balance of a wallet address on the Citrate chain" }
    fn parameters_schema(&self) -> serde_json::Value {
        serde_json::json!({
            "type": "object",
            "properties": {
                "address": { "type": "string", "description": "Wallet address (0x...)" }
            },
            "required": ["address"]
        })
    }
    fn risk_level(&self) -> RiskLevel { RiskLevel::Low }

    async fn execute(&self, params: serde_json::Value, ctx: &ToolContext) -> Result<ToolResult, AgentError> {
        let address = params.get("address")
            .and_then(|a| a.as_str())
            .or(ctx.wallet_address.as_deref())
            .ok_or_else(|| AgentError::InvalidParams("address required".into()))?;

        // The actual balance query would go through NodeService or RPC
        // For now, return a structured result that the chat agent can display
        Ok(ToolResult::ok_with_data(
            format!("Balance for {}: checking...", address),
            serde_json::json!({ "address": address, "action": "check_balance" }),
        ))
    }
}
