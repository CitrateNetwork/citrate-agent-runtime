//! FileEdit tool — replace an exact string occurrence in a file.
//!
//! Data source: local filesystem; the file is opened once through
//! [`super::safe_write`] (`openat` + `O_NOFOLLOW` from the workspace root), read
//! and rewritten through that one descriptor. Symbolic links in any component
//! and files with more than one hard link are refused.
//! The old_string must appear exactly once in the file to avoid ambiguous edits.

use citrate_agent_core::error::AgentError;
use citrate_agent_core::tool::{AgentTool, RiskLevel, ToolContext, ToolResult};
use super::safe_write;
use std::io::{Read, Seek, SeekFrom, Write};

pub struct FileEdit;

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

        let target = safe_write::resolve(&ctx.workspace_dir, path)?;
        let (shown, old, new) = (path.to_owned(), old_string.to_owned(), new_string.to_owned());
        tokio::task::spawn_blocking(move || -> Result<(), AgentError> {
            let fail = AgentError::ExecutionFailed;
            let mut file = safe_write::open_for_edit(&target)?;
            let mut content = String::new();
            file.read_to_string(&mut content)
                .map_err(|e| fail(format!("failed to read '{shown}': {e}")))?;

            let match_count = content.matches(old.as_str()).count();
            if match_count == 0 {
                return Err(fail(format!("old_string not found in '{shown}'")));
            }
            if match_count > 1 {
                return Err(fail(format!(
                    "old_string found {match_count} times in '{shown}' — must be unique"
                )));
            }

            let new_content = content.replacen(old.as_str(), new.as_str(), 1);
            file.set_len(0)
                .and_then(|()| file.seek(SeekFrom::Start(0)).map(|_| ()))
                .and_then(|()| file.write_all(new_content.as_bytes()))
                .map_err(|e| fail(format!("failed to write '{shown}': {e}")))
        })
        .await
        .map_err(|e| AgentError::ExecutionFailed(format!("edit task failed: {e}")))??;

        Ok(ToolResult::ok_with_data(
            format!("Edited {}: replaced 1 occurrence", path),
            serde_json::json!({
                "path": path,
                "replacements": 1,
            }),
        ))
    }
}
