//! FileWrite tool — write content to a file in the workspace.
//!
//! Data source: local filesystem via `tokio::fs::write`.
//! Restricted to the workspace directory to prevent path traversal.
//! Creates parent directories if they do not exist.

use citrate_agent_core::error::AgentError;
use citrate_agent_core::tool::{AgentTool, RiskLevel, ToolContext, ToolResult};
use std::path::{Path, PathBuf};

pub struct FileWrite;

/// Resolve a path relative to the workspace for write operations.
/// Unlike reads, the file need not exist yet — we validate the parent directory.
fn resolve_write_path(workspace: &str, path: &str) -> Result<PathBuf, AgentError> {
    let workspace = Path::new(workspace)
        .canonicalize()
        .map_err(|e| AgentError::ExecutionFailed(format!("invalid workspace dir: {e}")))?;

    let candidate = if Path::new(path).is_absolute() {
        PathBuf::from(path)
    } else {
        workspace.join(path)
    };

    // Normalize the path manually since the file may not exist yet.
    // We check that the parent resolves inside the workspace.
    let parent = candidate
        .parent()
        .ok_or_else(|| AgentError::ExecutionFailed("invalid file path".into()))?;

    // The parent may not exist yet either — walk up until we find an existing ancestor.
    let mut check = parent.to_path_buf();
    loop {
        if check.exists() {
            let resolved_ancestor = check
                .canonicalize()
                .map_err(|e| AgentError::ExecutionFailed(format!("cannot resolve path: {e}")))?;
            if !resolved_ancestor.starts_with(&workspace) {
                return Err(AgentError::ExecutionFailed(
                    "path traversal outside workspace is not allowed".into(),
                ));
            }
            break;
        }
        if !check.pop() {
            return Err(AgentError::ExecutionFailed(
                "cannot find existing ancestor directory".into(),
            ));
        }
    }

    Ok(candidate)
}

#[async_trait::async_trait]
impl AgentTool for FileWrite {
    fn name(&self) -> &str {
        "file_write"
    }

    fn description(&self) -> &str {
        "Write content to a file in the workspace"
    }

    fn parameters_schema(&self) -> serde_json::Value {
        serde_json::json!({
            "type": "object",
            "properties": {
                "path": {
                    "type": "string",
                    "description": "File path relative to workspace root"
                },
                "content": {
                    "type": "string",
                    "description": "Content to write to the file"
                }
            },
            "required": ["path", "content"]
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
        let content = params
            .get("content")
            .and_then(|c| c.as_str())
            .ok_or_else(|| AgentError::InvalidParams("'content' is required".into()))?;

        let resolved = resolve_write_path(&ctx.workspace_dir, path)?;

        // Create parent directories if needed
        if let Some(parent) = resolved.parent() {
            tokio::fs::create_dir_all(parent)
                .await
                .map_err(|e| AgentError::ExecutionFailed(format!("failed to create dirs: {e}")))?;
        }

        let bytes_written = content.len();
        tokio::fs::write(&resolved, content)
            .await
            .map_err(|e| AgentError::ExecutionFailed(format!("failed to write '{}': {e}", path)))?;

        Ok(ToolResult::ok_with_data(
            format!("Wrote {} bytes to {}", bytes_written, path),
            serde_json::json!({
                "path": path,
                "bytes_written": bytes_written,
            }),
        ))
    }
}
