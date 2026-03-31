//! Standard Operating Procedures (SOPs) — multi-step automated workflows.
//!
//! An SOP is a named sequence of tool invocations that fires on a trigger.
//! Triggers can be cron-based (scheduled), webhook-based (external event),
//! event-based (blockchain event), or manual (user-initiated).
//!
//! The `SOPEngine` registers SOP definitions and executes their steps
//! sequentially, passing context between steps and aborting on failure.

use citrate_agent_core::approval::ApprovalFlow;
use citrate_agent_core::error::AgentError;
use citrate_agent_core::tool::{ToolContext, ToolRegistry, ToolResult};
use std::collections::HashMap;
use std::sync::Arc;
use tokio::sync::RwLock;

/// When an SOP should fire.
#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub enum SOPTrigger {
    /// Fires on a cron schedule (expression in the scheduler format).
    Cron(String),
    /// Fires when a webhook is received at the given path.
    Webhook(String),
    /// Fires on a blockchain event (event signature).
    Event(String),
    /// Fires only when explicitly invoked by the user.
    Manual,
}

/// A single step in an SOP.
#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub struct SOPStep {
    /// The agent tool to invoke for this step.
    pub tool_name: String,
    /// Parameters to pass to the tool.
    pub params: serde_json::Value,
    /// Optional condition: a JSONPath expression evaluated against the
    /// previous step's output. If present and the condition evaluates to
    /// false, the step is skipped.
    pub condition: Option<String>,
}

/// An SOP definition — a reusable multi-step procedure.
#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub struct SOPDefinition {
    /// Unique SOP identifier.
    pub id: String,
    /// Human-readable name.
    pub name: String,
    /// What triggers this SOP.
    pub trigger: SOPTrigger,
    /// Ordered list of steps to execute.
    pub steps: Vec<SOPStep>,
    /// Whether this SOP is active.
    pub enabled: bool,
}

/// Result of executing a single SOP step.
#[derive(Debug, Clone)]
pub struct StepOutcome {
    /// Zero-based step index.
    pub step_index: usize,
    /// The tool that was called.
    pub tool_name: String,
    /// Whether the step was skipped due to a condition.
    pub skipped: bool,
    /// The tool result (None if skipped).
    pub result: Option<ToolResult>,
}

/// Result of executing an entire SOP.
#[derive(Debug, Clone)]
pub struct SOPOutcome {
    /// The SOP that was executed.
    pub sop_id: String,
    /// Per-step outcomes.
    pub steps: Vec<StepOutcome>,
    /// Whether all steps succeeded (or were skipped).
    pub success: bool,
    /// Error message if any step failed.
    pub error: Option<String>,
}

/// Engine for registering and executing SOPs.
pub struct SOPEngine {
    sops: RwLock<HashMap<String, SOPDefinition>>,
}

impl SOPEngine {
    /// Create a new empty SOP engine.
    pub fn new() -> Self {
        Self {
            sops: RwLock::new(HashMap::new()),
        }
    }

    /// Register an SOP definition. Overwrites if the ID already exists.
    pub async fn register(&self, sop: SOPDefinition) {
        tracing::info!("SOP registered: id={} name={}", sop.id, sop.name);
        self.sops.write().await.insert(sop.id.clone(), sop);
    }

    /// Unregister an SOP by ID. Returns the removed definition, or None.
    pub async fn unregister(&self, id: &str) -> Option<SOPDefinition> {
        let removed = self.sops.write().await.remove(id);
        if removed.is_some() {
            tracing::info!("SOP unregistered: id={}", id);
        }
        removed
    }

    /// Get an SOP definition by ID.
    pub async fn get(&self, id: &str) -> Option<SOPDefinition> {
        self.sops.read().await.get(id).cloned()
    }

    /// List all registered SOPs.
    pub async fn list(&self) -> Vec<SOPDefinition> {
        self.sops.read().await.values().cloned().collect()
    }

    /// Number of registered SOPs.
    pub async fn count(&self) -> usize {
        self.sops.read().await.len()
    }

    /// Execute an SOP by ID using the given tool registry and context.
    ///
    /// S-03 FIX: Accepts an optional `ApprovalFlow` that is checked BEFORE
    /// each tool execution. If the approval flow denies a tool, the SOP
    /// aborts with an error. When `approval` is None, the SOP executes
    /// without approval checks (suitable only for internal/cron triggers
    /// where the SOP was pre-approved at registration time).
    ///
    /// Steps are executed sequentially. If a step has a `condition` and the
    /// previous step's result does not satisfy it, the step is skipped.
    /// Execution aborts on the first tool error.
    pub async fn execute(
        &self,
        sop_id: &str,
        registry: &ToolRegistry,
        ctx: &ToolContext,
        approval: Option<&Arc<ApprovalFlow>>,
    ) -> Result<SOPOutcome, SOPError> {
        let sop = {
            let sops = self.sops.read().await;
            sops.get(sop_id)
                .cloned()
                .ok_or_else(|| SOPError::NotFound(sop_id.to_string()))?
        };

        if !sop.enabled {
            return Err(SOPError::Disabled(sop_id.to_string()));
        }

        tracing::info!("Executing SOP: id={} name={} steps={}", sop.id, sop.name, sop.steps.len());

        let mut step_outcomes = Vec::new();
        let mut last_result: Option<ToolResult> = None;

        for (index, step) in sop.steps.iter().enumerate() {
            // Evaluate condition against previous result
            if let Some(ref condition) = step.condition {
                if !evaluate_condition(condition, last_result.as_ref()) {
                    tracing::info!(
                        "SOP step {} skipped (condition '{}' not met)",
                        index,
                        condition
                    );
                    step_outcomes.push(StepOutcome {
                        step_index: index,
                        tool_name: step.tool_name.clone(),
                        skipped: true,
                        result: None,
                    });
                    continue;
                }
            }

            // Look up the tool
            let tool = registry.get(&step.tool_name).await.ok_or_else(|| {
                SOPError::ToolNotFound {
                    sop_id: sop.id.clone(),
                    step_index: index,
                    tool_name: step.tool_name.clone(),
                }
            })?;

            // S-03 FIX: Check approval before execution when an approval flow is provided
            if let Some(approval_flow) = approval {
                approval_flow.check(
                    tool.name(),
                    tool.description(),
                    &step.params,
                    tool.risk_level(),
                ).await.map_err(|e| SOPError::StepFailed {
                    sop_id: sop.id.clone(),
                    step_index: index,
                    error: format!("approval denied: {}", e),
                })?;
                tracing::info!(
                    sop_id = %sop.id, step = index, tool = %step.tool_name,
                    risk = ?tool.risk_level(), "SOP tool approved — executing"
                );
            } else {
                tracing::info!(
                    sop_id = %sop.id, step = index, tool = %step.tool_name,
                    risk = ?tool.risk_level(), "SOP executing tool (no approval flow)"
                );
            }

            // Execute
            let result = tool
                .execute(step.params.clone(), ctx)
                .await
                .map_err(|e| SOPError::StepFailed {
                    sop_id: sop.id.clone(),
                    step_index: index,
                    error: e.to_string(),
                })?;

            let step_success = result.success;
            step_outcomes.push(StepOutcome {
                step_index: index,
                tool_name: step.tool_name.clone(),
                skipped: false,
                result: Some(result.clone()),
            });

            if !step_success {
                let err_msg = result
                    .error
                    .clone()
                    .unwrap_or_else(|| "tool returned failure".to_string());
                tracing::warn!(
                    "SOP step {} failed: tool={} error={}",
                    index,
                    step.tool_name,
                    err_msg
                );
                return Ok(SOPOutcome {
                    sop_id: sop.id,
                    steps: step_outcomes,
                    success: false,
                    error: Some(err_msg),
                });
            }

            last_result = Some(result);
        }

        tracing::info!("SOP completed successfully: id={}", sop.id);
        Ok(SOPOutcome {
            sop_id: sop.id,
            steps: step_outcomes,
            success: true,
            error: None,
        })
    }
}

impl Default for SOPEngine {
    fn default() -> Self {
        Self::new()
    }
}

/// Evaluate a simple condition against the previous step's result.
///
/// Supported condition expressions:
/// - `"success"` — true if the previous step succeeded
/// - `"has_data"` — true if the previous step returned structured data
/// - Any other string — treated as a key to look up in the result data
fn evaluate_condition(condition: &str, prev_result: Option<&ToolResult>) -> bool {
    let Some(result) = prev_result else {
        // No previous result — skip steps with conditions
        return false;
    };

    match condition {
        "success" => result.success,
        "has_data" => result.data.is_some(),
        key => {
            // Check if the key exists in the result data
            if let Some(ref data) = result.data {
                data.get(key).is_some()
            } else {
                false
            }
        }
    }
}

/// Errors from the SOP engine.
#[derive(Debug, thiserror::Error)]
pub enum SOPError {
    #[error("SOP '{0}' not found")]
    NotFound(String),

    #[error("SOP '{0}' is disabled")]
    Disabled(String),

    #[error("SOP '{sop_id}' step {step_index}: tool '{tool_name}' not found")]
    ToolNotFound {
        sop_id: String,
        step_index: usize,
        tool_name: String,
    },

    #[error("SOP '{sop_id}' step {step_index} failed: {error}")]
    StepFailed {
        sop_id: String,
        step_index: usize,
        error: String,
    },

    #[error("Agent error: {0}")]
    Agent(#[from] AgentError),
}

#[cfg(test)]
mod tests {
    use super::*;
    use citrate_agent_core::tool::{AgentTool, RiskLevel};
    use std::sync::Arc;

    /// A test tool that always succeeds with configurable output.
    struct SuccessTool {
        tool_name: String,
    }

    impl SuccessTool {
        fn new(name: &str) -> Self {
            Self {
                tool_name: name.to_string(),
            }
        }
    }

    #[async_trait::async_trait]
    impl AgentTool for SuccessTool {
        fn name(&self) -> &str {
            &self.tool_name
        }
        fn description(&self) -> &str {
            "A test tool that succeeds"
        }
        fn parameters_schema(&self) -> serde_json::Value {
            serde_json::json!({"type": "object", "properties": {}})
        }
        fn risk_level(&self) -> RiskLevel {
            RiskLevel::Low
        }
        async fn execute(
            &self,
            _params: serde_json::Value,
            _ctx: &ToolContext,
        ) -> Result<ToolResult, AgentError> {
            Ok(ToolResult::ok_with_data(
                "success",
                serde_json::json!({"status": "ok"}),
            ))
        }
    }

    /// A test tool that always fails.
    struct FailTool;

    #[async_trait::async_trait]
    impl AgentTool for FailTool {
        fn name(&self) -> &str {
            "fail_tool"
        }
        fn description(&self) -> &str {
            "A test tool that fails"
        }
        fn parameters_schema(&self) -> serde_json::Value {
            serde_json::json!({"type": "object", "properties": {}})
        }
        fn risk_level(&self) -> RiskLevel {
            RiskLevel::Low
        }
        async fn execute(
            &self,
            _params: serde_json::Value,
            _ctx: &ToolContext,
        ) -> Result<ToolResult, AgentError> {
            Ok(ToolResult::err("intentional failure"))
        }
    }

    fn test_ctx() -> ToolContext {
        ToolContext {
            session_id: "test-session".to_string(),
            wallet_address: None,
            chain_id: 40204,
            workspace_dir: "/tmp".to_string(),
        }
    }

    fn make_sop(id: &str, steps: Vec<SOPStep>) -> SOPDefinition {
        SOPDefinition {
            id: id.to_string(),
            name: format!("Test SOP {}", id),
            trigger: SOPTrigger::Manual,
            steps,
            enabled: true,
        }
    }

    #[tokio::test]
    async fn test_register_and_list() {
        let engine = SOPEngine::new();
        engine.register(make_sop("sop1", vec![])).await;
        engine.register(make_sop("sop2", vec![])).await;
        assert_eq!(engine.count().await, 2);

        let sop = engine.get("sop1").await;
        assert!(sop.is_some());
        assert_eq!(sop.expect("sop exists").name, "Test SOP sop1");
    }

    #[tokio::test]
    async fn test_unregister() {
        let engine = SOPEngine::new();
        engine.register(make_sop("sop1", vec![])).await;
        assert_eq!(engine.count().await, 1);

        let removed = engine.unregister("sop1").await;
        assert!(removed.is_some());
        assert_eq!(engine.count().await, 0);

        let not_found = engine.unregister("nonexistent").await;
        assert!(not_found.is_none());
    }

    #[tokio::test]
    async fn test_execute_simple_sop() {
        let engine = SOPEngine::new();
        let registry = ToolRegistry::new();
        registry.register(Arc::new(SuccessTool::new("step_a"))).await;
        registry.register(Arc::new(SuccessTool::new("step_b"))).await;

        let sop = make_sop(
            "two_step",
            vec![
                SOPStep {
                    tool_name: "step_a".to_string(),
                    params: serde_json::json!({}),
                    condition: None,
                },
                SOPStep {
                    tool_name: "step_b".to_string(),
                    params: serde_json::json!({}),
                    condition: None,
                },
            ],
        );
        engine.register(sop).await;

        let outcome = engine
            .execute("two_step", &registry, &test_ctx(), None)
            .await
            .expect("SOP execution should succeed");

        assert!(outcome.success);
        assert_eq!(outcome.steps.len(), 2);
        assert!(!outcome.steps[0].skipped);
        assert!(!outcome.steps[1].skipped);
    }

    #[tokio::test]
    async fn test_execute_aborts_on_failure() {
        let engine = SOPEngine::new();
        let registry = ToolRegistry::new();
        registry.register(Arc::new(FailTool)).await;
        registry.register(Arc::new(SuccessTool::new("step_b"))).await;

        let sop = make_sop(
            "fail_first",
            vec![
                SOPStep {
                    tool_name: "fail_tool".to_string(),
                    params: serde_json::json!({}),
                    condition: None,
                },
                SOPStep {
                    tool_name: "step_b".to_string(),
                    params: serde_json::json!({}),
                    condition: None,
                },
            ],
        );
        engine.register(sop).await;

        let outcome = engine
            .execute("fail_first", &registry, &test_ctx(), None)
            .await
            .expect("execute returns outcome even on step failure");

        assert!(!outcome.success);
        assert_eq!(outcome.steps.len(), 1, "second step should not have executed");
    }

    #[tokio::test]
    async fn test_execute_disabled_sop_fails() {
        let engine = SOPEngine::new();
        let registry = ToolRegistry::new();

        let mut sop = make_sop("disabled_sop", vec![]);
        sop.enabled = false;
        engine.register(sop).await;

        let result = engine.execute("disabled_sop", &registry, &test_ctx(), None).await;
        assert!(result.is_err());
        match result.expect_err("should be disabled error") {
            SOPError::Disabled(id) => assert_eq!(id, "disabled_sop"),
            other => panic!("Expected Disabled error, got {:?}", other),
        }
    }

    #[tokio::test]
    async fn test_execute_not_found() {
        let engine = SOPEngine::new();
        let registry = ToolRegistry::new();

        let result = engine.execute("nonexistent", &registry, &test_ctx(), None).await;
        assert!(result.is_err());
        match result.expect_err("should be not found error") {
            SOPError::NotFound(id) => assert_eq!(id, "nonexistent"),
            other => panic!("Expected NotFound error, got {:?}", other),
        }
    }

    #[tokio::test]
    async fn test_execute_with_condition_skip() {
        let engine = SOPEngine::new();
        let registry = ToolRegistry::new();
        registry.register(Arc::new(SuccessTool::new("step_a"))).await;
        registry.register(Arc::new(SuccessTool::new("step_b"))).await;

        let sop = make_sop(
            "conditional",
            vec![
                SOPStep {
                    tool_name: "step_a".to_string(),
                    params: serde_json::json!({}),
                    condition: None,
                },
                SOPStep {
                    tool_name: "step_b".to_string(),
                    params: serde_json::json!({}),
                    // Condition looks for key "missing_key" in previous result data
                    condition: Some("missing_key".to_string()),
                },
            ],
        );
        engine.register(sop).await;

        let outcome = engine
            .execute("conditional", &registry, &test_ctx(), None)
            .await
            .expect("SOP execution should succeed");

        assert!(outcome.success);
        assert_eq!(outcome.steps.len(), 2);
        assert!(!outcome.steps[0].skipped);
        assert!(outcome.steps[1].skipped, "step_b should be skipped — condition not met");
    }

    #[tokio::test]
    async fn test_execute_with_condition_passes() {
        let engine = SOPEngine::new();
        let registry = ToolRegistry::new();
        registry.register(Arc::new(SuccessTool::new("step_a"))).await;
        registry.register(Arc::new(SuccessTool::new("step_b"))).await;

        let sop = make_sop(
            "cond_passes",
            vec![
                SOPStep {
                    tool_name: "step_a".to_string(),
                    params: serde_json::json!({}),
                    condition: None,
                },
                SOPStep {
                    tool_name: "step_b".to_string(),
                    params: serde_json::json!({}),
                    // SuccessTool returns data with "status" key
                    condition: Some("status".to_string()),
                },
            ],
        );
        engine.register(sop).await;

        let outcome = engine
            .execute("cond_passes", &registry, &test_ctx(), None)
            .await
            .expect("SOP execution should succeed");

        assert!(outcome.success);
        assert!(!outcome.steps[1].skipped, "step_b should NOT be skipped — condition met");
    }

    #[test]
    fn test_evaluate_condition_success() {
        let result = ToolResult::ok("done");
        assert!(evaluate_condition("success", Some(&result)));
    }

    #[test]
    fn test_evaluate_condition_has_data() {
        let with_data = ToolResult::ok_with_data("done", serde_json::json!({"x": 1}));
        assert!(evaluate_condition("has_data", Some(&with_data)));

        let without_data = ToolResult::ok("done");
        assert!(!evaluate_condition("has_data", Some(&without_data)));
    }

    #[test]
    fn test_evaluate_condition_no_previous() {
        assert!(!evaluate_condition("success", None));
    }

    #[test]
    fn test_sop_trigger_serialization() {
        let trigger = SOPTrigger::Cron("0 */5 * * * *".to_string());
        let json = serde_json::to_string(&trigger).expect("serialize trigger");
        assert!(json.contains("Cron"));

        let manual = SOPTrigger::Manual;
        let json2 = serde_json::to_string(&manual).expect("serialize manual trigger");
        assert!(json2.contains("Manual"));
    }
}
