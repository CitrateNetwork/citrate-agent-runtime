//! Agent error types.

#[derive(Debug, thiserror::Error)]
pub enum AgentError {
    #[error("Tool not found: {0}")]
    ToolNotFound(String),

    #[error("Tool execution denied by user")]
    Denied,

    #[error("Tool execution timed out after {0}ms")]
    Timeout(u64),

    #[error("Budget exceeded: {0}")]
    BudgetExceeded(String),

    #[error("Emergency stop activated")]
    EmergencyStop,

    #[error("Tool execution failed: {0}")]
    ExecutionFailed(String),

    #[error("Invalid parameters: {0}")]
    InvalidParams(String),

    #[error("Approval timeout — no response within {0}s")]
    ApprovalTimeout(u64),
}
