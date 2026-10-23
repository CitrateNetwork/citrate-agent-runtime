//! FileWrite tool — write content to a file in the workspace.
//!
//! Data source: local filesystem, opened through [`super::safe_write`]
//! (`openat` + `O_NOFOLLOW` from the workspace root).
//! Restricted to the workspace directory to prevent path traversal; refuses
//! symbolic links in any component and files with more than one hard link.
//! Creates parent directories if they do not exist.

use citrate_agent_core::error::AgentError;
use citrate_agent_core::tool::{AgentTool, RiskLevel, ToolContext, ToolResult};
use super::safe_write::{self, WorkspacePath};
use std::io::Write;
use std::path::Path;

pub struct FileWrite;

/// Paths that are always denied for write operations (security-sensitive).
const DENIED_PATTERNS: &[&str] = &[
    ".ssh", ".gnupg", ".aws", ".config/gcloud", ".kube", ".env",
];

/// File extensions that are always denied for write operations.
const DENIED_EXTENSIONS: &[&str] = &["pem", "key", "p12", "pfx", "jks"];

/// Resolve a path relative to the workspace for write operations.
/// Checks denied patterns and extensions per SandboxPolicy rules, then
/// resolves the path lexically ([`safe_write::resolve`]): no `..` survives and
/// nothing outside the workspace is accepted. Symlinks and hard links are
/// handled when the file is opened ([`safe_write::open_for_write`]).
fn resolve_write_path(workspace: &str, path: &str) -> Result<WorkspacePath, AgentError> {
    // Check denied patterns
    for pattern in DENIED_PATTERNS {
        if path.contains(pattern) {
            return Err(AgentError::ExecutionFailed(
                format!("access denied: path contains '{}' (security-sensitive)", pattern),
            ));
        }
    }
    // Check denied extensions
    if let Some(ext) = Path::new(path).extension().and_then(|e| e.to_str()) {
        if DENIED_EXTENSIONS.contains(&ext) {
            return Err(AgentError::ExecutionFailed(
                format!("write denied: '{}' files are security-sensitive", ext),
            ));
        }
    }
    safe_write::resolve(workspace, path)
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

        let target = resolve_write_path(&ctx.workspace_dir, path)?;

        let bytes_written = content.len();
        let body = content.to_owned();
        let shown = path.to_owned();
        tokio::task::spawn_blocking(move || -> Result<(), AgentError> {
            let mut file = safe_write::open_for_write(&target)?;
            file.write_all(body.as_bytes())
                .map_err(|e| AgentError::ExecutionFailed(format!("failed to write '{shown}': {e}")))
        })
        .await
        .map_err(|e| AgentError::ExecutionFailed(format!("write task failed: {e}")))??;

        Ok(ToolResult::ok_with_data(
            format!("Wrote {} bytes to {}", bytes_written, path),
            serde_json::json!({
                "path": path,
                "bytes_written": bytes_written,
            }),
        ))
    }
}
