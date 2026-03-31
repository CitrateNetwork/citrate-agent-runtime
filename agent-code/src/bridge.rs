//! CodeAgentBridge — routing layer between user prompts and coding tools.
//!
//! The bridge holds a reference to the ToolRegistry and provides higher-level
//! methods for the IDE/Studio tab: processing natural-language requests and
//! gathering workspace context.

use citrate_agent_core::approval::ApprovalFlow;
use citrate_agent_core::error::AgentError;
use citrate_agent_core::tool::{ToolContext, ToolRegistry, ToolResult};
use std::path::Path;
use std::sync::Arc;

/// Bridge between the Studio/IDE UI and the coding agent tools.
///
/// S-03 FIX: ApprovalFlow is MANDATORY in all live paths. The only way to
/// construct a bridge is via `with_approval()`. An ungated constructor is
/// available for tests only behind `#[cfg(test)]`.
pub struct CodeAgentBridge {
    registry: Arc<ToolRegistry>,
    approval_flow: Option<Arc<ApprovalFlow>>,
}

impl CodeAgentBridge {
    /// Create a bridge with mandatory approval flow enforcement.
    /// This is the ONLY public constructor for production code.
    pub fn with_approval(registry: Arc<ToolRegistry>, approval: Arc<ApprovalFlow>) -> Self {
        Self { registry, approval_flow: Some(approval) }
    }

    /// Create an ungated bridge for testing ONLY.
    /// This constructor is not available in production builds.
    #[cfg(test)]
    pub fn new_ungated_for_testing(registry: Arc<ToolRegistry>) -> Self {
        Self { registry, approval_flow: None }
    }

    /// Get a reference to the underlying tool registry.
    pub fn registry(&self) -> &ToolRegistry {
        &self.registry
    }

    /// Process a user request by dispatching to the named tool.
    ///
    /// The `tool_name` and `params` are typically extracted by the LLM
    /// from the user's natural-language prompt. This method validates
    /// the tool exists and delegates execution.
    /// Execute a tool with approval flow enforcement.
    /// H-01 FIX: All tool execution goes through ApprovalFlow when one is configured.
    pub async fn execute_tool(
        &self,
        tool_name: &str,
        params: serde_json::Value,
        ctx: &ToolContext,
    ) -> Result<ToolResult, AgentError> {
        let tool = self
            .registry
            .get(tool_name)
            .await
            .ok_or_else(|| AgentError::ToolNotFound(tool_name.to_string()))?;

        // H-01 FIX: Check approval before execution
        if let Some(ref approval) = self.approval_flow {
            approval.check(
                tool.name(),
                tool.description(),
                &params,
                tool.risk_level(),
            ).await?;
            tracing::info!(tool = tool_name, risk = ?tool.risk_level(), "approved — executing");
        } else {
            tracing::info!(tool = tool_name, "executing (no approval flow configured)");
        }

        tool.execute(params, ctx).await
    }

    /// Return a summary of the workspace file tree.
    ///
    /// This provides context to the LLM about what files exist in the
    /// project, enabling it to make better tool-call decisions.
    ///
    /// Data source: local filesystem via `tokio::process::Command` running
    /// `find` with depth limits and exclusions for build artifacts.
    pub async fn get_workspace_context(
        &self,
        workspace_dir: &str,
    ) -> Result<WorkspaceContext, AgentError> {
        let workspace = Path::new(workspace_dir);
        if !workspace.is_dir() {
            return Err(AgentError::ExecutionFailed(format!(
                "workspace '{}' is not a directory",
                workspace_dir
            )));
        }

        // Use `find` to list files, excluding build artifacts and version control
        let output = tokio::process::Command::new("find")
            .args([
                ".",
                "-maxdepth", "4",
                "-type", "f",
                "-not", "-path", "*/target/*",
                "-not", "-path", "*/.git/*",
                "-not", "-path", "*/node_modules/*",
                "-not", "-path", "*/__pycache__/*",
            ])
            .current_dir(workspace_dir)
            .output()
            .await
            .map_err(|e| AgentError::ExecutionFailed(format!("failed to list workspace: {e}")))?;

        if !output.status.success() {
            return Err(AgentError::ExecutionFailed(
                "failed to scan workspace directory".into(),
            ));
        }

        let stdout = String::from_utf8_lossy(&output.stdout);
        let mut files: Vec<String> = stdout
            .lines()
            .filter(|l| !l.is_empty())
            .map(|l| l.strip_prefix("./").unwrap_or(l).to_string())
            .collect();
        files.sort();

        let file_count = files.len();

        // Group by top-level directory for a summary
        let mut directories: Vec<String> = files
            .iter()
            .filter_map(|f| f.split('/').next())
            .filter(|d| !d.contains('.')) // skip root-level files for dir list
            .collect::<std::collections::BTreeSet<&str>>()
            .into_iter()
            .map(String::from)
            .collect();
        directories.sort();

        Ok(WorkspaceContext {
            workspace_dir: workspace_dir.to_string(),
            file_count,
            top_level_dirs: directories,
            files,
        })
    }

    /// List all available tool names in the registry.
    pub async fn available_tools(&self) -> Vec<String> {
        self.registry.list().await
    }

    /// Get tool definitions formatted for LLM function calling.
    pub async fn tool_definitions(&self) -> Vec<serde_json::Value> {
        self.registry.tool_definitions().await
    }
}

/// Summary of the workspace for LLM context.
#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub struct WorkspaceContext {
    /// Root directory path
    pub workspace_dir: String,
    /// Total number of files found
    pub file_count: usize,
    /// Top-level subdirectories
    pub top_level_dirs: Vec<String>,
    /// All files (relative paths, sorted)
    pub files: Vec<String>,
}
