//! FileWrite tool — write content to a file in the workspace.
//!
//! Data source: local filesystem via `tokio::fs::write`.
//! Restricted to the workspace directory to prevent path traversal.
//! Creates parent directories if they do not exist.

use citrate_agent_core::error::AgentError;
use citrate_agent_core::tool::{AgentTool, RiskLevel, ToolContext, ToolResult};
use std::path::{Path, PathBuf};

pub struct FileWrite;

/// Paths that are always denied for write operations (security-sensitive).
const DENIED_PATTERNS: &[&str] = &[
    ".ssh", ".gnupg", ".aws", ".config/gcloud", ".kube", ".env",
];

/// File extensions that are always denied for write operations.
const DENIED_EXTENSIONS: &[&str] = &["pem", "key", "p12", "pfx", "jks"];

/// Lexically normalize a path — resolve `.` and `..` components without
/// touching the filesystem. Returns `None` if the path escapes above its
/// root via `..` (a traversal attempt). This is what closes AR-B-006: the
/// previous ancestor-walk stripped `..` with `PathBuf::pop()` for the
/// existence check but returned the *un-normalised* candidate, so the kernel
/// resolved the surviving `..` chain at write time and the write landed
/// outside the workspace.
fn lexical_normalize(path: &Path) -> Option<PathBuf> {
    use std::path::Component;
    let mut out = PathBuf::new();
    for comp in path.components() {
        match comp {
            Component::ParentDir => {
                // Refuse to pop past the root / an empty accumulator.
                if !out.pop() {
                    return None;
                }
            }
            Component::CurDir => {}
            other => out.push(other.as_os_str()),
        }
    }
    Some(out)
}

/// Resolve a path relative to the workspace for write operations.
/// Unlike reads, the file need not exist yet — we validate the parent directory.
/// Also checks denied patterns and extensions per SandboxPolicy rules.
fn resolve_write_path(workspace: &str, path: &str) -> Result<PathBuf, AgentError> {
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
    let workspace = Path::new(workspace)
        .canonicalize()
        .map_err(|e| AgentError::ExecutionFailed(format!("invalid workspace dir: {e}")))?;

    let candidate = if Path::new(path).is_absolute() {
        PathBuf::from(path)
    } else {
        workspace.join(path)
    };

    // Lexically normalize FIRST so any `..` chain is collapsed before we
    // reason about containment. The old code returned the raw `candidate`
    // with `..` intact, which the kernel later resolved through the
    // filesystem — escaping the workspace (AR-B-006).
    let candidate = lexical_normalize(&candidate).ok_or_else(|| {
        AgentError::ExecutionFailed("path traversal outside workspace is not allowed".into())
    })?;
    if !candidate.starts_with(&workspace) {
        return Err(AgentError::ExecutionFailed(
            "path traversal outside workspace is not allowed".into(),
        ));
    }

    // Defence in depth against a symlinked *existing* ancestor: walk up until
    // we find an ancestor that exists, canonicalize it (following symlinks),
    // and confirm it too is inside the workspace.
    let parent = candidate
        .parent()
        .ok_or_else(|| AgentError::ExecutionFailed("invalid file path".into()))?;
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

    // Return the NORMALISED path (no surviving `..`), so the eventual write
    // cannot be redirected by the kernel resolving traversal components.
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

            // Re-canonicalize the (now-materialised) parent and confirm it is
            // still inside the workspace. This closes the symlink-in-the-final
            // component variant: an allow-listed operation could have planted a
            // symlink at `parent`, which only resolves once it exists on disk.
            let workspace = Path::new(&ctx.workspace_dir).canonicalize().map_err(|e| {
                AgentError::ExecutionFailed(format!("invalid workspace dir: {e}"))
            })?;
            let real_parent = parent.canonicalize().map_err(|e| {
                AgentError::ExecutionFailed(format!("cannot resolve parent dir: {e}"))
            })?;
            if !real_parent.starts_with(&workspace) {
                return Err(AgentError::ExecutionFailed(
                    "path traversal outside workspace is not allowed".into(),
                ));
            }
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
