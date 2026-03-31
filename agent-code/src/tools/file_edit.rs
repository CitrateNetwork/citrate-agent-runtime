//! FileEdit tool — replace an exact string occurrence in a file.
//!
//! Data source: local filesystem via `tokio::fs::read_to_string` + `tokio::fs::write`.
//! The old_string must appear exactly once in the file to avoid ambiguous edits.

use citrate_agent_core::error::AgentError;
use citrate_agent_core::tool::{AgentTool, RiskLevel, ToolContext, ToolResult};
use std::path::{Path, PathBuf};

pub struct FileEdit;

/// Resolve a path relative to the workspace, requiring it to exist.
fn resolve_existing_path(workspace: &str, path: &str) -> Result<PathBuf, AgentError> {
    let workspace = Path::new(workspace)
        .canonicalize()
        .map_err(|e| AgentError::ExecutionFailed(format!("invalid workspace dir: {e}")))?;

    let candidate = if Path::new(path).is_absolute() {
        PathBuf::from(path)
    } else {
        workspace.join(path)
    };

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
impl AgentTool for FileEdit {
    fn name(&self) -> &str {
        "file_edit"
    }

    fn description(&self) -> &str {
        "Replace exact string in a file"
    }

    fn parameters_schema(&self) -> serde_json::Value {
        serde_json::json!({
            "type": "object",
            "properties": {
                "path": {
                    "type": "string",
                    "description": "File path relative to workspace root"
                },
                "old_string": {
                    "type": "string",
                    "description": "Exact string to find and replace (must occur exactly once)"
                },
                "new_string": {
                    "type": "string",
                    "description": "Replacement string"
                }
            },
            "required": ["path", "old_string", "new_string"]
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
        let path = params
            .get("path")
            .and_then(|p| p.as_str())
            .ok_or_else(|| AgentError::InvalidParams("'path' is required".into()))?;
        let old_string = params
            .get("old_string")
            .and_then(|s| s.as_str())
            .ok_or_else(|| AgentError::InvalidParams("'old_string' is required".into()))?;
        let new_string = params
            .get("new_string")
            .and_then(|s| s.as_str())
            .ok_or_else(|| AgentError::InvalidParams("'new_string' is required".into()))?;

        if old_string == new_string {
            return Err(AgentError::InvalidParams(
                "old_string and new_string must differ".into(),
            ));
        }

        let resolved = resolve_existing_path(&ctx.workspace_dir, path)?;
        let content = tokio::fs::read_to_string(&resolved)
            .await
            .map_err(|e| AgentError::ExecutionFailed(format!("failed to read '{}': {e}", path)))?;

        let match_count = content.matches(old_string).count();
        if match_count == 0 {
            return Err(AgentError::ExecutionFailed(format!(
                "old_string not found in '{}'",
                path
            )));
        }
        if match_count > 1 {
            return Err(AgentError::ExecutionFailed(format!(
                "old_string found {} times in '{}' — must be unique",
                match_count, path
            )));
        }

        let new_content = content.replacen(old_string, new_string, 1);
        tokio::fs::write(&resolved, &new_content)
            .await
            .map_err(|e| AgentError::ExecutionFailed(format!("failed to write '{}': {e}", path)))?;

        Ok(ToolResult::ok_with_data(
            format!("Edited {}: replaced 1 occurrence", path),
            serde_json::json!({
                "path": path,
                "replacements": 1,
            }),
        ))
    }
}
