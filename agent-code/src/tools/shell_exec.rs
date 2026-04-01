//! ShellExec tool — execute a shell command in the workspace directory.
//!
//! Data source: local OS process via `tokio::process::Command`.
//! Runs with the workspace directory as cwd and enforces a timeout.

use citrate_agent_core::error::AgentError;
use citrate_agent_core::tool::{AgentTool, RiskLevel, ToolContext, ToolResult};
use std::time::Duration;

pub struct ShellExec;

/// Commands that are always denied (destructive or privilege escalation).
const DENIED_COMMANDS: &[&str] = &[
    "sudo", "su ", "chmod 777", "rm -rf /", "rm -rf ~",
    "mkfs", "dd if=", ":(){ :|:& };:",
    "curl | sh", "wget | sh", "curl | bash", "wget | bash",
];

/// Default timeout for shell commands: 30 seconds.
const DEFAULT_TIMEOUT_MS: u64 = 30_000;

/// Maximum allowed timeout: 5 minutes.
const MAX_TIMEOUT_MS: u64 = 300_000;

/// Maximum output size we return: 64 KiB.
const MAX_OUTPUT_BYTES: usize = 65_536;

#[async_trait::async_trait]
impl AgentTool for ShellExec {
    fn name(&self) -> &str {
        "shell_exec"
    }

    fn description(&self) -> &str {
        "Execute a shell command in the workspace directory"
    }

    fn parameters_schema(&self) -> serde_json::Value {
        serde_json::json!({
            "type": "object",
            "properties": {
                "command": {
                    "type": "string",
                    "description": "Shell command to execute"
                },
                "timeout_ms": {
                    "type": "integer",
                    "description": "Timeout in milliseconds (default: 30000, max: 300000)"
                }
            },
            "required": ["command"]
        })
    }

    fn risk_level(&self) -> RiskLevel {
        RiskLevel::Medium
    }

    async fn execute(
        &self,
        params: serde_json::Value,
        ctx: &ToolContext,
    ) -> Result<ToolResult, AgentError> {
        let command = params
            .get("command")
            .and_then(|c| c.as_str())
            .ok_or_else(|| AgentError::InvalidParams("'command' is required".into()))?;

        // Check for denied commands (destructive or privilege escalation)
        let cmd_lower = command.to_lowercase();
        for denied in DENIED_COMMANDS {
            if cmd_lower.contains(denied) {
                return Err(AgentError::ExecutionFailed(
                    format!("command denied: contains '{}' (security policy)", denied),
                ));
            }
        }

        let timeout_ms = params
            .get("timeout_ms")
            .and_then(|t| t.as_u64())
            .unwrap_or(DEFAULT_TIMEOUT_MS)
            .min(MAX_TIMEOUT_MS);

        let result = tokio::time::timeout(
            Duration::from_millis(timeout_ms),
            tokio::process::Command::new("sh")
                .arg("-c")
                .arg(command)
                .current_dir(&ctx.workspace_dir)
                .output(),
        )
        .await;

        match result {
            Err(_) => Err(AgentError::Timeout(timeout_ms)),
            Ok(Err(e)) => Err(AgentError::ExecutionFailed(format!(
                "failed to execute command: {e}"
            ))),
            Ok(Ok(output)) => {
                let exit_code = output.status.code().unwrap_or(-1);
                let mut stdout = String::from_utf8_lossy(&output.stdout).to_string();
                let mut stderr = String::from_utf8_lossy(&output.stderr).to_string();

                // Truncate large outputs
                if stdout.len() > MAX_OUTPUT_BYTES {
                    stdout.truncate(MAX_OUTPUT_BYTES);
                    stdout.push_str("\n... (truncated)");
                }
                if stderr.len() > MAX_OUTPUT_BYTES {
                    stderr.truncate(MAX_OUTPUT_BYTES);
                    stderr.push_str("\n... (truncated)");
                }

                let combined = if stderr.is_empty() {
                    stdout.clone()
                } else if stdout.is_empty() {
                    stderr.clone()
                } else {
                    format!("{stdout}\n--- stderr ---\n{stderr}")
                };

                let success = output.status.success();

                Ok(ToolResult {
                    success,
                    output: combined,
                    data: Some(serde_json::json!({
                        "exit_code": exit_code,
                        "stdout_len": output.stdout.len(),
                        "stderr_len": output.stderr.len(),
                    })),
                    error: if success {
                        None
                    } else {
                        Some(format!("command exited with code {exit_code}"))
                    },
                })
            }
        }
    }
}
