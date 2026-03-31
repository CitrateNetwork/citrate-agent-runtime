use citrate_agent_core::error::AgentError;
use citrate_agent_core::tool::{AgentTool, RiskLevel, ToolContext, ToolResult};

pub struct DeployContract;

#[async_trait::async_trait]
impl AgentTool for DeployContract {
    fn name(&self) -> &str { "deploy_contract" }
    fn description(&self) -> &str { "Deploy a compiled Solidity smart contract to the Citrate chain. Requires user approval." }
    fn parameters_schema(&self) -> serde_json::Value {
        serde_json::json!({
            "type": "object",
            "properties": {
                "bytecode": { "type": "string", "description": "Contract bytecode (hex)" },
                "constructor_args": { "type": "string", "description": "ABI-encoded constructor arguments (hex, optional)" }
            },
            "required": ["bytecode"]
        })
    }
    fn risk_level(&self) -> RiskLevel { RiskLevel::High }

    async fn execute(&self, params: serde_json::Value, _ctx: &ToolContext) -> Result<ToolResult, AgentError> {
        let bytecode = params.get("bytecode").and_then(|b| b.as_str())
            .ok_or_else(|| AgentError::InvalidParams("'bytecode' required".into()))?;

        Ok(ToolResult::ok_with_data(
            format!("Contract deployment prepared ({} bytes)", bytecode.len() / 2),
            serde_json::json!({ "bytecode_length": bytecode.len() / 2, "action": "deploy_contract" }),
        ))
    }
}
