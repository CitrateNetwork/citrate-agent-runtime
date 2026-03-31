use citrate_agent_core::error::AgentError;
use citrate_agent_core::tool::{AgentTool, RiskLevel, ToolContext, ToolResult};

pub struct RunInference;

#[async_trait::async_trait]
impl AgentTool for RunInference {
    fn name(&self) -> &str { "run_inference" }
    fn description(&self) -> &str { "Run AI inference on a model (local GGUF or on-chain via citrate_chatCompletion)" }
    fn parameters_schema(&self) -> serde_json::Value {
        serde_json::json!({
            "type": "object",
            "properties": {
                "model": { "type": "string", "description": "Model name or ID" },
                "prompt": { "type": "string", "description": "Input text for the model" },
                "max_tokens": { "type": "integer", "description": "Maximum output tokens (default: 256)" }
            },
            "required": ["prompt"]
        })
    }
    fn risk_level(&self) -> RiskLevel { RiskLevel::Low }

    async fn execute(&self, params: serde_json::Value, _ctx: &ToolContext) -> Result<ToolResult, AgentError> {
        let prompt = params.get("prompt").and_then(|p| p.as_str())
            .ok_or_else(|| AgentError::InvalidParams("'prompt' required".into()))?;
        let model = params.get("model").and_then(|m| m.as_str()).unwrap_or("default");

        Ok(ToolResult::ok_with_data(
            format!("Running inference on '{}' with model '{}'", &prompt[..prompt.len().min(50)], model),
            serde_json::json!({ "model": model, "prompt_length": prompt.len(), "action": "run_inference" }),
        ))
    }
}
