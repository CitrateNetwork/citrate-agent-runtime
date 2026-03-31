//! FileRead tool — read contents of a file in the workspace.
//!
//! Data source: local filesystem via `tokio::fs::read_to_string`.
//! Restricted to the workspace directory to prevent path traversal.

use citrate_agent_core::error::AgentError;
use citrate_agent_core::tool::{AgentTool, RiskLevel, ToolContext, ToolResult};
use std::path::{Path, PathBuf};

pub struct FileRead;

/// Resolve a path relative to the workspace, blocking traversal outside it.
fn resolve_workspace_path(workspace: &str, path: &str) -> Result<PathBuf, AgentError> {
    let workspace = Path::new(workspace)
        .canonicalize()
        .map_err(|e| AgentError::ExecutionFailed(format!("invalid workspace dir: {e}")))?;

    let candidate = if Path::new(path).is_absolute() {
        PathBuf::from(path)
    } else {
        workspace.join(path)
    };

    // Canonicalize may fail if the file doesn't exist yet — for reads we require it.
    let resolved = candidate
        .canonicalize()
        .map_err(|e| AgentError::ExecutionFailed(format!("cannot resolve path '{}': {e}", path)))?;

    if !resolved.starts_with(&workspace) {
        return Err(AgentError::ExecutionFailed(
            "path traversal outside workspace is not allowed".into(),
        ));
    }

    Ok(resolved)
}

#[async_trait::async_trait]
impl AgentTool for FileRead {
    fn name(&self) -> &str {
        "file_read"
    }

    fn description(&self) -> &str {
        "Read contents of a file in the workspace"
    }

    fn parameters_schema(&self) -> serde_json::Value {
        serde_json::json!({
            "type": "object",
            "properties": {
                "path": {
                    "type": "string",
                    "description": "File path relative to workspace root"
                },
                "start_line": {
                    "type": "integer",
                    "description": "First line to read (1-based, optional)"
                },
                "end_line": {
                    "type": "integer",
                    "description": "Last line to read (1-based, inclusive, optional)"
                }
            },
            "required": ["path"]
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
        let path = params
            .get("path")
            .and_then(|p| p.as_str())
            .ok_or_else(|| AgentError::InvalidParams("'path' is required".into()))?;

        let resolved = resolve_workspace_path(&ctx.workspace_dir, path)?;
        let content = tokio::fs::read_to_string(&resolved)
            .await
            .map_err(|e| AgentError::ExecutionFailed(format!("failed to read '{}': {e}", path)))?;

        let start_line = params
            .get("start_line")
            .and_then(|v| v.as_i64())
            .map(|v| v.max(1) as usize);
        let end_line = params
            .get("end_line")
            .and_then(|v| v.as_i64())
            .map(|v| v.max(1) as usize);

        let lines: Vec<&str> = content.lines().collect();
        let total_lines = lines.len();

        let (start, end) = match (start_line, end_line) {
            (Some(s), Some(e)) => (s.saturating_sub(1), e.min(total_lines)),
            (Some(s), None) => (s.saturating_sub(1), total_lines),
            (None, Some(e)) => (0, e.min(total_lines)),
            (None, None) => (0, total_lines),
        };

        let selected: Vec<String> = lines
            .get(start..end)
            .unwrap_or(&[])
            .iter()
            .enumerate()
            .map(|(i, line)| format!("{:>4}\t{}", start + i + 1, line))
            .collect();

        let output = selected.join("\n");

        Ok(ToolResult::ok_with_data(
            output,
            serde_json::json!({
                "path": path,
                "total_lines": total_lines,
                "range": [start + 1, end],
            }),
        ))
    }
}
