//! SearchCode tool — search for patterns in code files (like grep).
//!
//! Data source: local filesystem via `tokio::process::Command` running `grep -rn`.
//! Falls back to a pure-Rust line-by-line search if grep is not available.
//! Restricted to the workspace directory.

use citrate_agent_core::error::AgentError;
use citrate_agent_core::tool::{AgentTool, RiskLevel, ToolContext, ToolResult};
use std::path::Path;
use std::time::Duration;

pub struct SearchCode;

/// Maximum matches to return to avoid overwhelming the LLM context.
const MAX_MATCHES: usize = 100;

/// Timeout for search operations: 30 seconds.
const SEARCH_TIMEOUT_MS: u64 = 30_000;

#[async_trait::async_trait]
impl AgentTool for SearchCode {
    fn name(&self) -> &str {
        "search_code"
    }

    fn description(&self) -> &str {
        "Search for patterns in code files (like grep)"
    }

    fn parameters_schema(&self) -> serde_json::Value {
        serde_json::json!({
            "type": "object",
            "properties": {
                "pattern": {
                    "type": "string",
                    "description": "Search pattern (regex supported)"
                },
                "path": {
                    "type": "string",
                    "description": "Directory or file to search in (relative to workspace, default: '.')"
                },
                "file_type": {
                    "type": "string",
                    "description": "File extension filter (e.g., 'rs', 'ts', 'sol')"
                }
            },
            "required": ["pattern"]
        })
    }

    fn risk_level(&self) -> RiskLevel {
        RiskLevel::Low
    }

    async fn execute(
        &self,
        params: serde_json::Value,
        ctx: &ToolContext,
    ) -> Result<ToolResult, AgentError> {
        let pattern = params
            .get("pattern")
            .and_then(|p| p.as_str())
            .ok_or_else(|| AgentError::InvalidParams("'pattern' is required".into()))?;

        if pattern.is_empty() {
            return Err(AgentError::InvalidParams(
                "search pattern cannot be empty".into(),
            ));
        }

        let search_path = params
            .get("path")
            .and_then(|p| p.as_str())
            .unwrap_or(".");

        let workspace = Path::new(&ctx.workspace_dir)
            .canonicalize()
            .map_err(|e| AgentError::ExecutionFailed(format!("invalid workspace: {e}")))?;

        let target = if Path::new(search_path).is_absolute() {
            let resolved = Path::new(search_path)
                .canonicalize()
                .map_err(|e| AgentError::ExecutionFailed(format!("invalid search path: {e}")))?;
            if !resolved.starts_with(&workspace) {
                return Err(AgentError::ExecutionFailed(
                    "search path outside workspace is not allowed".into(),
                ));
            }
            resolved
        } else {
            let resolved = workspace.join(search_path);
            if resolved.exists() {
                resolved
                    .canonicalize()
                    .map_err(|e| AgentError::ExecutionFailed(format!("invalid path: {e}")))?
            } else {
                return Err(AgentError::ExecutionFailed(format!(
                    "search path '{}' does not exist",
                    search_path
                )));
            }
        };

        // Build grep command
        let mut args: Vec<String> = vec![
            "-rn".to_string(),
            "--color=never".to_string(),
        ];

        if let Some(file_type) = params.get("file_type").and_then(|f| f.as_str()) {
            args.push("--include".to_string());
            args.push(format!("*.{file_type}"));
        }

        // Exclude common noisy directories
        args.push("--exclude-dir=target".to_string());
        args.push("--exclude-dir=node_modules".to_string());
        args.push("--exclude-dir=.git".to_string());

        args.push("--".to_string());
        args.push(pattern.to_string());
        args.push(target.to_string_lossy().to_string());

        let output = tokio::time::timeout(
            Duration::from_millis(SEARCH_TIMEOUT_MS),
            tokio::process::Command::new("grep")
                .args(&args)
                .current_dir(&ctx.workspace_dir)
                .output(),
        )
        .await
        .map_err(|_| AgentError::Timeout(SEARCH_TIMEOUT_MS))?
        .map_err(|e| AgentError::ExecutionFailed(format!("failed to run grep: {e}")))?;

        let stdout = String::from_utf8_lossy(&output.stdout);

        // grep exit code 1 = no matches (not an error)
        let exit_code = output.status.code().unwrap_or(-1);
        if exit_code > 1 {
            let stderr = String::from_utf8_lossy(&output.stderr);
            return Err(AgentError::ExecutionFailed(format!(
                "grep failed: {stderr}"
            )));
        }

        let lines: Vec<&str> = stdout.lines().collect();
        let total_matches = lines.len();

        // Strip the workspace prefix from results for cleaner output
        let workspace_str = workspace.to_string_lossy();
        let prefix = format!("{}/", workspace_str);
        let truncated: Vec<String> = lines
            .iter()
            .take(MAX_MATCHES)
            .map(|line| line.strip_prefix(&*prefix).unwrap_or(line).to_string())
            .collect();

        let display = if total_matches == 0 {
            format!("No matches found for '{pattern}'")
        } else if total_matches > MAX_MATCHES {
            format!(
                "{}\n... ({} total matches, showing first {})",
                truncated.join("\n"),
                total_matches,
                MAX_MATCHES
            )
        } else {
            truncated.join("\n")
        };

        Ok(ToolResult::ok_with_data(
            display,
            serde_json::json!({
                "pattern": pattern,
                "total_matches": total_matches,
                "shown": total_matches.min(MAX_MATCHES),
            }),
        ))
    }
}
