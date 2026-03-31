use citrate_agent_core::error::AgentError;
use citrate_agent_core::tool::{AgentTool, RiskLevel, ToolContext, ToolResult};

pub struct ListModels;

#[async_trait::async_trait]
impl AgentTool for ListModels {
    fn name(&self) -> &str { "list_models" }
    fn description(&self) -> &str { "List available AI models on the Citrate network (local and on-chain)" }
    fn parameters_schema(&self) -> serde_json::Value {
        serde_json::json!({
            "type": "object",
            "properties": {
                "filter": { "type": "string", "description": "Optional filter: 'local', 'onchain', or 'all'" }
            }
        })
    }
    fn risk_level(&self) -> RiskLevel { RiskLevel::Low }

    async fn execute(&self, params: serde_json::Value, _ctx: &ToolContext) -> Result<ToolResult, AgentError> {
        let filter = params.get("filter").and_then(|f| f.as_str()).unwrap_or("all");
        Ok(ToolResult::ok_with_data(
            format!("Listing {} models", filter),
            serde_json::json!({ "filter": filter, "action": "list_models" }),
        ))
    }
}
