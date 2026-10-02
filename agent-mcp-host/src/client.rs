//! One MCP client per server (HUP-S4.1): `initialize` (version negotiation, capabilities
//! recorded), `notifications/initialized`, paginated `tools/list`, and `tools/call`.

use crate::config::ServerConfig;
use crate::error::McpError;
use crate::mapping::render_content;
use crate::transport::{self, Transport};
use citrate_agent_loop::StopFlag;
use serde_json::{json, Value};

/// The version this host asks for.
pub const PROTOCOL_VERSION: &str = "2025-06-18";
/// Versions this host accepts in the server's answer. Each uses the `initialize` handshake and
/// the tool shapes implemented here; later revisions are refused until implemented.
pub const SUPPORTED_VERSIONS: &[&str] = &["2025-06-18", "2025-03-26", "2024-11-05"];

/// Bounds on `tools/list`.
pub const MAX_TOOL_PAGES: usize = 32;
pub const MAX_TOOLS_PER_SERVER: usize = 256;

/// What `initialize` told us. `instructions` is untrusted server text: it is recorded for the
/// status view and never placed in the model's prompt.
#[derive(Debug, Clone, PartialEq)]
pub struct ServerInfo {
    pub protocol_version: String,
    pub capabilities: Value,
    pub server_name: String,
    pub server_version: String,
    pub instructions: Option<String>,
}

/// A tool as the server described it.
#[derive(Debug, Clone, PartialEq)]
pub struct RemoteTool {
    pub name: String,
    pub description: String,
    pub input_schema: Value,
    /// The raw `annotations` object (hints only).
    pub annotations: Value,
}

/// A `tools/call` result: the rendered text (no binary payloads) and the server's error flag.
#[derive(Debug, Clone, PartialEq)]
pub struct CallResult {
    pub text: String,
    pub is_error: bool,
}

pub struct McpClient {
    name: String,
    cfg: ServerConfig,
    transport: Box<dyn Transport>,
    info: ServerInfo,
}

impl std::fmt::Debug for McpClient {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("McpClient")
            .field("name", &self.name)
            .field("protocol_version", &self.info.protocol_version)
            .finish_non_exhaustive()
    }
}

fn short(s: &str, n: usize) -> String {
    s.chars().take(n).collect()
}

impl McpClient {
    /// Start or reach the server and run the handshake. A server that answers with a protocol
    /// version this host does not speak is refused (and a stdio child is stopped).
    pub fn connect(cfg: &ServerConfig) -> Result<Self, McpError> {
        let transport = transport::connect(cfg)?;
        let result = transport.request(
            "initialize",
            json!({
                "protocolVersion": PROTOCOL_VERSION,
                "capabilities": {},
                "clientInfo": {"name": "citrate-hermes", "version": env!("CARGO_PKG_VERSION")},
            }),
            cfg.init_timeout,
            None,
        )?;
        let version = result
            .get("protocolVersion")
            .and_then(Value::as_str)
            .ok_or_else(|| McpError::BadResponse("initialize had no protocolVersion".into()))?;
        if !SUPPORTED_VERSIONS.contains(&version) {
            return Err(McpError::Unsupported(format!(
                "protocol version {:?}",
                short(version, 40)
            )));
        }
        let capabilities = match result.get("capabilities") {
            Some(c) if c.is_object() => c.clone(),
            _ => json!({}),
        };
        let field = |k: &str| {
            result
                .pointer(&format!("/serverInfo/{k}"))
                .and_then(Value::as_str)
                .map(|s| short(s, 120))
                .unwrap_or_default()
        };
        let info = ServerInfo {
            protocol_version: version.to_string(),
            capabilities,
            server_name: field("name"),
            server_version: field("version"),
            instructions: result
                .get("instructions")
                .and_then(Value::as_str)
                .map(|s| short(s, 2000)),
        };
        transport.set_protocol_version(version);
        transport.notify("notifications/initialized", Value::Null)?;
        Ok(McpClient {
            name: cfg.name.clone(),
            cfg: cfg.clone(),
            transport,
            info,
        })
    }

    pub fn name(&self) -> &str {
        &self.name
    }

    pub fn info(&self) -> &ServerInfo {
        &self.info
    }

    /// Every tool the server lists (all pages, bounded). A server that did not declare the
    /// `tools` capability has none.
    pub fn list_tools(&self) -> Result<Vec<RemoteTool>, McpError> {
        if self.info.capabilities.get("tools").is_none() {
            return Ok(Vec::new());
        }
        let mut out = Vec::new();
        let mut cursor: Option<String> = None;
        for _ in 0..MAX_TOOL_PAGES {
            let params = match &cursor {
                Some(c) => json!({"cursor": c}),
                None => json!({}),
            };
            let page = self
                .transport
                .request("tools/list", params, self.cfg.init_timeout, None)?;
            let tools = page
                .get("tools")
                .and_then(Value::as_array)
                .ok_or_else(|| McpError::BadResponse("tools/list had no tools array".into()))?;
            for t in tools {
                if out.len() >= MAX_TOOLS_PER_SERVER {
                    return Ok(out);
                }
                let Some(name) = t.get("name").and_then(Value::as_str) else {
                    continue;
                };
                out.push(RemoteTool {
                    name: name.to_string(),
                    description: t
                        .get("description")
                        .and_then(Value::as_str)
                        .unwrap_or("")
                        .to_string(),
                    input_schema: t.get("inputSchema").cloned().unwrap_or(Value::Null),
                    annotations: t.get("annotations").cloned().unwrap_or(json!({})),
                });
            }
            cursor = page
                .get("nextCursor")
                .and_then(Value::as_str)
                .map(str::to_string);
            if cursor.is_none() {
                return Ok(out);
            }
        }
        Ok(out)
    }

    /// Call one tool. `args` must be a JSON object. The stop flag cancels the call.
    pub fn call_tool(
        &self,
        name: &str,
        args: Value,
        stop: &StopFlag,
    ) -> Result<CallResult, McpError> {
        let result = self.transport.request(
            "tools/call",
            json!({"name": name, "arguments": args}),
            self.cfg.timeout,
            Some(stop),
        )?;
        if !result.is_object() {
            return Err(McpError::BadResponse(
                "tools/call result was not an object".into(),
            ));
        }
        Ok(CallResult {
            text: render_content(&result),
            is_error: result.get("isError").and_then(Value::as_bool) == Some(true),
        })
    }

    /// Messages from the server that were not valid JSON-RPC and were skipped.
    pub fn bad_messages(&self) -> u64 {
        self.transport.bad_messages()
    }

    /// The server process exited (stdio).
    pub fn exited(&self) -> bool {
        self.transport.exited()
    }

    /// The server announced a changed tool list. Recorded only: the offered tools are fixed when
    /// the sidecar starts, so a server cannot add tools to a running session.
    /// Stop the server now (a stdio child is killed). Idempotent.
    pub fn close(&self) {
        self.transport.close();
    }

    pub fn tools_changed(&self) -> bool {
        self.transport.tools_changed()
    }
}
