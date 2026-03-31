//! GitOps tool — git operations (status, diff, commit, push).
//!
//! Data source: local git repository via `tokio::process::Command`.
//! Runs git commands in the workspace directory.
//! Risk varies by operation: status/diff are Low, commit/push are Medium.

use citrate_agent_core::error::AgentError;
use citrate_agent_core::tool::{AgentTool, RiskLevel, ToolContext, ToolResult};
use std::time::Duration;

pub struct GitOps;

/// Allowed git operations.
const ALLOWED_OPS: &[&str] = &["status", "diff", "commit", "push"];

/// Timeout for git operations: 60 seconds.
const GIT_TIMEOUT_MS: u64 = 60_000;

/// Execute a git command in the given directory and return (stdout, stderr, exit_code).
async fn run_git(
    workspace: &str,
    args: &[&str],
) -> Result<(String, String, i32), AgentError> {
    let output = tokio::time::timeout(
        Duration::from_millis(GIT_TIMEOUT_MS),
        tokio::process::Command::new("git")
            .args(args)
            .current_dir(workspace)
            .output(),
    )
    .await
    .map_err(|_| AgentError::Timeout(GIT_TIMEOUT_MS))?
    .map_err(|e| AgentError::ExecutionFailed(format!("failed to run git: {e}")))?;

    let stdout = String::from_utf8_lossy(&output.stdout).to_string();
    let stderr = String::from_utf8_lossy(&output.stderr).to_string();
    let code = output.status.code().unwrap_or(-1);

    Ok((stdout, stderr, code))
}

#[async_trait::async_trait]
impl AgentTool for GitOps {
    fn name(&self) -> &str {
        "git_ops"
    }

    fn description(&self) -> &str {
        "Git operations: status, diff, commit, push"
    }

    fn parameters_schema(&self) -> serde_json::Value {
        serde_json::json!({
            "type": "object",
            "properties": {
                "operation": {
                    "type": "string",
                    "enum": ["status", "diff", "commit", "push"],
                    "description": "Git operation to perform"
                },
                "message": {
                    "type": "string",
                    "description": "Commit message (required for 'commit' operation)"
                }
            },
            "required": ["operation"]
        })
    }

    fn risk_level(&self) -> RiskLevel {
        // The actual risk depends on the operation, but we report Medium
        // since commit/push are Medium. The approval flow checks before execute.
        RiskLevel::Medium
    }

    async fn execute(
        &self,
        params: serde_json::Value,
        ctx: &ToolContext,
    ) -> Result<ToolResult, AgentError> {
        let operation = params
            .get("operation")
            .and_then(|o| o.as_str())
            .ok_or_else(|| AgentError::InvalidParams("'operation' is required".into()))?;

        if !ALLOWED_OPS.contains(&operation) {
            return Err(AgentError::InvalidParams(format!(
                "unknown operation '{}' — allowed: {}",
                operation,
                ALLOWED_OPS.join(", ")
            )));
        }

        match operation {
            "status" => {
                let (stdout, stderr, code) =
                    run_git(&ctx.workspace_dir, &["status", "--porcelain"]).await?;
                if code != 0 {
                    return Ok(ToolResult::err(format!("git status failed: {stderr}")));
                }
                let changed_count = stdout.lines().count();
                Ok(ToolResult::ok_with_data(
                    if stdout.is_empty() {
                        "Working tree clean".to_string()
                    } else {
                        stdout.clone()
                    },
                    serde_json::json!({
                        "operation": "status",
                        "changed_files": changed_count,
                        "raw": stdout.trim(),
                    }),
                ))
            }
            "diff" => {
                let (stdout, stderr, code) =
                    run_git(&ctx.workspace_dir, &["diff", "--stat"]).await?;
                if code != 0 {
                    return Ok(ToolResult::err(format!("git diff failed: {stderr}")));
                }
                Ok(ToolResult::ok_with_data(
                    if stdout.is_empty() {
                        "No changes".to_string()
                    } else {
                        stdout.clone()
                    },
                    serde_json::json!({
                        "operation": "diff",
                        "raw": stdout.trim(),
                    }),
                ))
            }
            "commit" => {
                let message = params
                    .get("message")
                    .and_then(|m| m.as_str())
                    .ok_or_else(|| {
                        AgentError::InvalidParams(
                            "'message' is required for commit operation".into(),
                        )
                    })?;

                if message.trim().is_empty() {
                    return Err(AgentError::InvalidParams(
                        "commit message cannot be empty".into(),
                    ));
                }

                // Stage all changes first
                let (_, stderr, code) =
                    run_git(&ctx.workspace_dir, &["add", "-A"]).await?;
                if code != 0 {
                    return Ok(ToolResult::err(format!("git add failed: {stderr}")));
                }

                let (stdout, stderr, code) =
                    run_git(&ctx.workspace_dir, &["commit", "-m", message]).await?;
                if code != 0 {
                    return Ok(ToolResult::err(format!("git commit failed: {stderr}")));
                }

                Ok(ToolResult::ok_with_data(
                    stdout.clone(),
                    serde_json::json!({
                        "operation": "commit",
                        "message": message,
                        "raw": stdout.trim(),
                    }),
                ))
            }
            "push" => {
                let (stdout, stderr, code) =
                    run_git(&ctx.workspace_dir, &["push"]).await?;
                if code != 0 {
                    return Ok(ToolResult::err(format!("git push failed: {stderr}")));
                }
                let combined = if stdout.is_empty() {
                    stderr.clone()
                } else {
                    stdout.clone()
                };
                Ok(ToolResult::ok_with_data(
                    combined.clone(),
                    serde_json::json!({
                        "operation": "push",
                        "raw": combined.trim(),
                    }),
                ))
            }
            _ => Err(AgentError::InvalidParams(format!(
                "unhandled operation: {operation}"
            ))),
        }
    }
}
