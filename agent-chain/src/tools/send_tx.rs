use citrate_agent_core::error::AgentError;
use citrate_agent_core::tool::{AgentTool, RiskLevel, ToolContext, ToolResult};

pub struct SendTransaction;

#[async_trait::async_trait]
impl AgentTool for SendTransaction {
    fn name(&self) -> &str { "send_tx" }
    fn description(&self) -> &str { "Send SALT tokens to another address. Requires user approval." }
    fn parameters_schema(&self) -> serde_json::Value {
        serde_json::json!({
            "type": "object",
            "properties": {
                "to": { "type": "string", "description": "Recipient address (0x...)" },
                "amount": { "type": "string", "description": "Amount in SALT (e.g., '1.5')" }
            },
            "required": ["to", "amount"]
        })
    }
    fn risk_level(&self) -> RiskLevel { RiskLevel::High }

    async fn execute(&self, params: serde_json::Value, _ctx: &ToolContext) -> Result<ToolResult, AgentError> {
        let to = params.get("to").and_then(|t| t.as_str())
            .ok_or_else(|| AgentError::InvalidParams("'to' address required".into()))?;
        let amount = params.get("amount").and_then(|a| a.as_str())
            .ok_or_else(|| AgentError::InvalidParams("'amount' required".into()))?;

        Ok(ToolResult::ok_with_data(
            format!("Transaction prepared: send {} SALT to {}", amount, to),
            serde_json::json!({ "to": to, "amount": amount, "action": "send_tx" }),
        ))
    }
}
