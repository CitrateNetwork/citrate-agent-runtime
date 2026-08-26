//! First-class agent tools over the memory adapter: `memory_recall` and
//! `memory_assert`.
//!
//! These wrap [`MemoryAdapter`](super::memory::MemoryAdapter) in the crate's
//! [`AgentTool`](crate::tool::AgentTool) contract so the model can recall a
//! repo's storyline and write signed assertions mid-run, alongside file/shell/
//! chain tools. They are transport-agnostic (generic over `MemoryTransport`), so
//! they unit-test with a mock and run in production over the reqwest transport.
//!
//! Register with [`register_memory_tools`], or — with the `reqwest-transport`
//! feature — [`register_memory_tools_from_env`], which is a no-op when the
//! `MEM_GATEWAY_*` environment is unset (memory is optional for an agent).

use std::sync::Arc;

use async_trait::async_trait;
use serde_json::{json, Value};

use super::memory::{MemoryAdapter, MemoryError, MemoryTransport};
use crate::error::AgentError;
use crate::tool::{AgentTool, RiskLevel, ToolContext, ToolResult};

/// Pull the human-readable text out of an MCP `tools/call` result
/// (`{content:[{text:...}]}`), falling back to the compact JSON.
fn tool_text(v: &Value) -> String {
    v.get("content")
        .and_then(Value::as_array)
        .and_then(|a| a.first())
        .and_then(|c| c.get("text"))
        .and_then(Value::as_str)
        .map(str::to_string)
        .unwrap_or_else(|| v.to_string())
}

/// Map an adapter error to a failed (but non-fatal) tool result, so a memory
/// hiccup surfaces to the model as data and never crashes the agent loop.
fn memory_err(op: &str, e: MemoryError) -> ToolResult {
    ToolResult::err(format!("{op}: {e}"))
}

/// `memory_recall` — recall a repo's storyline from the memory DAG (read-only).
pub struct MemoryRecallTool<T: MemoryTransport> {
    adapter: Arc<MemoryAdapter<T>>,
}

#[async_trait]
impl<T: MemoryTransport + 'static> AgentTool for MemoryRecallTool<T> {
    fn name(&self) -> &str {
        "memory_recall"
    }

    fn description(&self) -> &str {
        "Recall the storyline and code-shape of a repo from the Citrate memory DAG \
         (\"git for agents\") without reading the code. Returns budgeted, \
         provenance-carrying nodes. Read-only."
    }

    fn parameters_schema(&self) -> Value {
        json!({
            "type": "object",
            "properties": {
                "repo": { "type": "string", "description": "Repo/tenant to recall, e.g. \"citrate-chain\"." },
                "budget": { "type": "integer", "description": "Max nodes to return (optional).", "minimum": 1, "maximum": 500 }
            },
            "required": ["repo"],
            "additionalProperties": false
        })
    }

    fn risk_level(&self) -> RiskLevel {
        RiskLevel::Low
    }

    async fn execute(
        &self,
        params: Value,
        _ctx: &ToolContext,
    ) -> Result<ToolResult, AgentError> {
        let repo = params.get("repo").and_then(Value::as_str);
        if repo.is_none_or(str::is_empty) {
            return Ok(ToolResult::err("memory_recall: 'repo' is required"));
        }
        match self.adapter.recall(params).await {
            Ok(v) => Ok(ToolResult::ok_with_data(tool_text(&v), v)),
            Err(e) => Ok(memory_err("memory_recall", e)),
        }
    }
}

/// `memory_assert` — write a signed, append-only assertion to the memory DAG.
pub struct MemoryAssertTool<T: MemoryTransport> {
    adapter: Arc<MemoryAdapter<T>>,
}

#[async_trait]
impl<T: MemoryTransport + 'static> AgentTool for MemoryAssertTool<T> {
    fn name(&self) -> &str {
        "memory_assert"
    }

    fn description(&self) -> &str {
        "Record a signed, append-only assertion (a rationale, finding, or note) \
         about a repo into the Citrate memory DAG, so future agents recall it. \
         Assertions are non-destructive and attributed to the caller."
    }

    fn parameters_schema(&self) -> Value {
        json!({
            "type": "object",
            "properties": {
                "repo": { "type": "string", "description": "Repo/tenant the assertion is about." },
                "content": { "type": "string", "description": "The claim to record." },
                "kind": { "type": "string", "description": "Node kind: rationale (default), finding, or doc.", "enum": ["rationale", "finding", "doc"] },
                "valid_from": { "type": "integer", "description": "Real-world ms-since-epoch this became true (optional; defaults to now)." }
            },
            "required": ["repo", "content"],
            "additionalProperties": false
        })
    }

    fn risk_level(&self) -> RiskLevel {
        // A write to shared memory — ask once per session, like a file write.
        RiskLevel::Medium
    }

    async fn execute(
        &self,
        params: Value,
        _ctx: &ToolContext,
    ) -> Result<ToolResult, AgentError> {
        let repo = params.get("repo").and_then(Value::as_str);
        let content = params.get("content").and_then(Value::as_str);
        if repo.is_none_or(str::is_empty) {
            return Ok(ToolResult::err("memory_assert: 'repo' is required"));
        }
        if content.is_none_or(str::is_empty) {
            return Ok(ToolResult::err("memory_assert: 'content' is required"));
        }
        match self.adapter.assert_node(params).await {
            Ok(v) => Ok(ToolResult::ok_with_data(tool_text(&v), v)),
            Err(e) => Ok(memory_err("memory_assert", e)),
        }
    }
}

/// Register both memory tools against a shared adapter. Any agent's
/// `register_tools` can call this to make `memory_recall` / `memory_assert`
/// first-class alongside its own tools.
pub async fn register_memory_tools<T: MemoryTransport + 'static>(
    registry: &crate::tool::ToolRegistry,
    adapter: Arc<MemoryAdapter<T>>,
) {
    registry
        .register(Arc::new(MemoryRecallTool { adapter: adapter.clone() }))
        .await;
    registry
        .register(Arc::new(MemoryAssertTool { adapter }))
        .await;
}

/// Register the memory tools from **resolved** credentials — a session/config
/// file written by the host app after login, then env as a fallback (see
/// [`MemoryAdapterConfig::resolve`](super::memory::MemoryAdapterConfig::resolve)).
/// This is the path user-facing agents should use: an in-app agent is
/// credentialed by the login the user already did, with no environment variables.
/// Returns whether the tools were registered — unconfigured is a quiet no-op
/// (memory is optional), a client-build failure is logged, never fatal.
#[cfg(feature = "reqwest-transport")]
pub async fn register_memory_tools_auto(registry: &crate::tool::ToolRegistry) -> bool {
    register_from(registry, MemoryAdapter::resolved()).await
}

/// Register the memory tools from environment variables only. Prefer
/// [`register_memory_tools_auto`] for user-facing surfaces; use this for CI or
/// self-hosting where env is the intended configuration channel.
#[cfg(feature = "reqwest-transport")]
pub async fn register_memory_tools_from_env(registry: &crate::tool::ToolRegistry) -> bool {
    register_from(registry, MemoryAdapter::from_env()).await
}

#[cfg(feature = "reqwest-transport")]
async fn register_from(
    registry: &crate::tool::ToolRegistry,
    built: Result<Option<MemoryAdapter<super::memory::ReqwestMemoryTransport>>, MemoryError>,
) -> bool {
    match built {
        Ok(Some(adapter)) => {
            register_memory_tools(registry, Arc::new(adapter)).await;
            true
        }
        Ok(None) => false,
        Err(e) => {
            tracing::warn!("memory tools not registered: {e}");
            false
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::tool::ToolRegistry;
    use std::sync::Mutex;

    use crate::adapters::memory::{MemoryAdapterConfig, MemoryTransport};

    struct MockTransport {
        response: (u16, String),
        seen: Mutex<Option<String>>,
    }

    #[async_trait]
    impl MemoryTransport for MockTransport {
        async fn post(&self, _url: &str, _bearer: &str, body: &str) -> Result<(u16, String), String> {
            *self.seen.lock().unwrap() = Some(body.to_string());
            Ok(self.response.clone())
        }
    }

    fn adapter_with(resp: &str) -> Arc<MemoryAdapter<MockTransport>> {
        let cfg = MemoryAdapterConfig {
            origin: "https://mem-gateway.example.com".into(),
            sub: "user-1".into(),
            connect_token: "tok".into(),
        };
        let t = MockTransport { response: (200, resp.to_string()), seen: Mutex::new(None) };
        Arc::new(MemoryAdapter::new(cfg, t).unwrap())
    }

    fn ctx() -> ToolContext {
        ToolContext {
            session_id: "s".into(),
            wallet_address: None,
            chain_id: 40204,
            workspace_dir: ".".into(),
        }
    }

    #[tokio::test]
    async fn registers_both_memory_tools() {
        let registry = ToolRegistry::new();
        register_memory_tools(&registry, adapter_with("{}")).await;
        let mut names = registry.list().await;
        names.sort();
        assert_eq!(names, vec!["memory_assert".to_string(), "memory_recall".to_string()]);
    }

    #[tokio::test]
    async fn recall_requires_repo() {
        let tool = MemoryRecallTool { adapter: adapter_with("{}") };
        let res = tool.execute(json!({}), &ctx()).await.unwrap();
        assert!(!res.success);
        assert!(res.error.unwrap().contains("'repo' is required"));
    }

    #[tokio::test]
    async fn recall_forwards_tools_call_and_surfaces_text() {
        let resp = r#"{"jsonrpc":"2.0","id":1,"result":{"content":[{"type":"text","text":"tenant citrate-chain — 935 nodes"}]}}"#;
        let tool = MemoryRecallTool { adapter: adapter_with(resp) };
        let res = tool.execute(json!({ "repo": "citrate-chain", "budget": 3 }), &ctx()).await.unwrap();
        assert!(res.success);
        assert!(res.output.contains("935 nodes"));
        assert!(res.data.is_some());
        // (the memory.recall tools/call wire format is covered in adapters::memory tests)
    }

    #[tokio::test]
    async fn assert_requires_repo_and_content() {
        let tool = MemoryAssertTool { adapter: adapter_with("{}") };
        let missing_content = tool.execute(json!({ "repo": "r" }), &ctx()).await.unwrap();
        assert!(!missing_content.success);
        assert!(missing_content.error.unwrap().contains("'content' is required"));
    }
}
