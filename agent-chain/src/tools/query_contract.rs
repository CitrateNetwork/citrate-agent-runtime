use citrate_agent_core::error::AgentError;
use citrate_agent_core::tool::{AgentTool, RiskLevel, ToolContext, ToolResult};

pub struct QueryContract;

#[async_trait::async_trait]
impl AgentTool for QueryContract {
    fn name(&self) -> &str { "query_contract" }
    fn description(&self) -> &str { "Call a read-only function on a deployed smart contract (no gas, no approval needed)" }
    fn parameters_schema(&self) -> serde_json::Value {
        serde_json::json!({
            "type": "object",
            "properties": {
                "contract_address": { "type": "string", "description": "Contract address (0x...)" },
                "function_signature": { "type": "string", "description": "Function signature (e.g., 'balanceOf(address)')" },
                "args": { "type": "array", "items": { "type": "string" }, "description": "Function arguments" }
            },
            "required": ["contract_address", "function_signature"]
        })
    }
    fn risk_level(&self) -> RiskLevel { RiskLevel::Low }

    async fn execute(&self, params: serde_json::Value, _ctx: &ToolContext) -> Result<ToolResult, AgentError> {
        let address = params.get("contract_address").and_then(|a| a.as_str())
            .ok_or_else(|| AgentError::InvalidParams("'contract_address' required".into()))?;
        let func = params.get("function_signature").and_then(|f| f.as_str())
            .ok_or_else(|| AgentError::InvalidParams("'function_signature' required".into()))?;

        Ok(ToolResult::ok_with_data(
            format!("Querying {}({}) on {}", func, "", address),
            serde_json::json!({ "contract": address, "function": func, "action": "query_contract" }),
        ))
    }
}
