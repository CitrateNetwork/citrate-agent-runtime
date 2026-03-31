use citrate_agent_core::error::AgentError;
use citrate_agent_core::tool::{AgentTool, RiskLevel, ToolContext, ToolResult};

pub struct ExplainTransaction;

#[async_trait::async_trait]
impl AgentTool for ExplainTransaction {
    fn name(&self) -> &str { "explain_tx" }
    fn description(&self) -> &str { "Decode and explain a transaction by its hash — shows sender, recipient, value, gas, status" }
    fn parameters_schema(&self) -> serde_json::Value {
        serde_json::json!({
            "type": "object",
            "properties": {
                "tx_hash": { "type": "string", "description": "Transaction hash (0x...)" }
            },
            "required": ["tx_hash"]
        })
    }
    fn risk_level(&self) -> RiskLevel { RiskLevel::Low }

    async fn execute(&self, params: serde_json::Value, _ctx: &ToolContext) -> Result<ToolResult, AgentError> {
        let tx_hash = params.get("tx_hash").and_then(|h| h.as_str())
            .ok_or_else(|| AgentError::InvalidParams("'tx_hash' required".into()))?;

        Ok(ToolResult::ok_with_data(
            format!("Looking up transaction {}", tx_hash),
            serde_json::json!({ "tx_hash": tx_hash, "action": "explain_tx" }),
        ))
    }
}
