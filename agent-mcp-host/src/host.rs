//! The MCP host (HUP-S4.1): every allowlisted server, its offered tools, and the
//! [`ToolHost`] the sidecar registers for them.

use crate::client::McpClient;
use crate::config::{McpConfig, ServerConfig};
use crate::error::McpError;
use crate::mapping::{fence, to_spec, TOOL_PREFIX};
use citrate_agent_loop::{Effect, StopFlag, ToolCall, ToolHost, ToolOutcome, ToolSpec};
use serde::Serialize;
use serde_json::Value;
use std::collections::HashMap;
use std::sync::Arc;

/// Whether `t` from server `sc` is offered to the model, and as which spec. `taken` says whether
/// an exposed name is already used. The same decision drives the session host and the dry-run
/// probe (HUP-S4.4), so the review screen shows exactly what a session would get.
pub(crate) fn offer(
    sc: &ServerConfig,
    t: &crate::client::RemoteTool,
    taken: impl Fn(&str) -> bool,
) -> Result<ToolSpec, String> {
    let spec = to_spec(&sc.name, t)?;
    if !sc.allow_write_tools && spec.annotations.effect != Some(Effect::None) {
        return Err(
            "not annotated read-only, and this server does not allow write tools".to_string(),
        );
    }
    if taken(&spec.name) {
        return Err("its name collides after mapping".to_string());
    }
    Ok(spec)
}

/// A server's state as shown to the operator.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum ServerState {
    /// Connected and initialized.
    Ready,
    /// Could not be started, reached or initialized.
    Failed,
    /// Was ready; its process has since exited (stdio). Not restarted automatically.
    Exited,
}

/// One server in the status view. Never carries the URL, env, or server instructions text.
#[derive(Debug, Clone, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct ServerStatus {
    pub name: String,
    pub transport: &'static str,
    pub state: ServerState,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub protocol_version: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub server_name: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub capabilities: Option<Value>,
    /// Tools offered to the model.
    pub tools: usize,
    /// Tools listed by the server but not offered, with the reason.
    pub skipped: Vec<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub error: Option<String>,
    pub tools_changed: bool,
    pub bad_messages: u64,
    pub allow_write_tools: bool,
}

struct Entry {
    cfg: ServerConfig,
    client: Option<McpClient>,
    error: Option<String>,
    specs: Vec<ToolSpec>,
    skipped: Vec<String>,
}

/// All configured servers. Tool lists are fixed at connect time.
pub struct McpHost {
    entries: Vec<Entry>,
    /// exposed name → (entry index, the server's own tool name)
    routes: HashMap<String, (usize, String)>,
}

impl McpHost {
    /// Connect to every server. Handshakes run in parallel (one thread per server), so a server
    /// that never answers costs its own init deadline once, not once per server; tools are then
    /// mapped in allowlist order. A server that fails is reported in [`McpHost::status`] and
    /// offers no tools; the others are unaffected.
    pub fn connect(cfg: &McpConfig) -> Self {
        type Connected = Result<(McpClient, Vec<crate::client::RemoteTool>), McpError>;
        let results: Vec<Connected> = std::thread::scope(|scope| {
            let handles: Vec<_> = cfg
                .servers
                .iter()
                .map(|sc| {
                    scope.spawn(move || {
                        McpClient::connect(sc).and_then(|c| c.list_tools().map(|t| (c, t)))
                    })
                })
                .collect();
            handles
                .into_iter()
                .map(|h| {
                    h.join().unwrap_or_else(|_| {
                        Err(McpError::Spawn("the connect thread panicked".into()))
                    })
                })
                .collect()
        });
        let mut entries = Vec::with_capacity(cfg.servers.len());
        let mut routes = HashMap::new();
        for ((idx, sc), connected) in cfg.servers.iter().enumerate().zip(results) {
            let mut e = Entry {
                cfg: sc.clone(),
                client: None,
                error: None,
                specs: Vec::new(),
                skipped: Vec::new(),
            };
            match connected {
                Ok((client, tools)) => {
                    for t in tools {
                        match offer(sc, &t, |n| routes.contains_key(n)) {
                            Err(why) => e.skipped.push(format!("{}: {why}", t.name)),
                            Ok(spec) => {
                                routes.insert(spec.name.clone(), (idx, t.name.clone()));
                                e.specs.push(spec);
                            }
                        }
                    }
                    e.client = Some(client);
                }
                Err(err) => e.error = Some(err.to_string()),
            }
            entries.push(e);
        }
        McpHost { entries, routes }
    }

    /// No server is configured.
    pub fn is_empty(&self) -> bool {
        self.entries.is_empty()
    }

    /// The tool specs offered to the model (host: sidecar; trust: untrusted).
    pub fn specs(&self) -> Vec<ToolSpec> {
        self.entries.iter().flat_map(|e| e.specs.clone()).collect()
    }

    /// Whether `name` is an MCP tool this host offers.
    pub fn handles(&self, name: &str) -> bool {
        self.routes.contains_key(name)
    }

    /// Whether `name` is in the reserved MCP tool namespace.
    pub fn reserved(name: &str) -> bool {
        name.starts_with(TOOL_PREFIX)
    }

    pub fn status(&self) -> Vec<ServerStatus> {
        self.entries
            .iter()
            .map(|e| {
                let state = match &e.client {
                    None => ServerState::Failed,
                    Some(c) if c.exited() => ServerState::Exited,
                    Some(_) => ServerState::Ready,
                };
                ServerStatus {
                    name: e.cfg.name.clone(),
                    transport: e.cfg.transport_kind(),
                    state,
                    protocol_version: e.client.as_ref().map(|c| c.info().protocol_version.clone()),
                    server_name: e.client.as_ref().map(|c| c.info().server_name.clone()),
                    capabilities: e.client.as_ref().map(|c| c.info().capabilities.clone()),
                    tools: e.specs.len(),
                    skipped: e.skipped.clone(),
                    error: e.error.clone(),
                    tools_changed: e.client.as_ref().is_some_and(|c| c.tools_changed()),
                    bad_messages: e.client.as_ref().map(|c| c.bad_messages()).unwrap_or(0),
                    allow_write_tools: e.cfg.allow_write_tools,
                }
            })
            .collect()
    }

    /// Run one MCP tool call. Output is always untrusted: a result is
    /// [`ToolOutcome::Untrusted`], a tool-level error is [`ToolOutcome::Error`] (both taint the
    /// session through the spec's annotation).
    pub fn call(&self, call: &ToolCall, stop: &StopFlag) -> ToolOutcome {
        let Some((idx, remote)) = self.routes.get(&call.name) else {
            return ToolOutcome::Error(format!(
                "'{}' is not an MCP tool offered in this session",
                call.name
            ));
        };
        let Some(entry) = self.entries.get(*idx) else {
            return ToolOutcome::Error("internal: MCP route without a server".into());
        };
        let server = &entry.cfg.name;
        let Some(client) = &entry.client else {
            return ToolOutcome::Error(format!("MCP server '{server}' is not connected"));
        };
        if stop.is_stopped() {
            return ToolOutcome::Error("stopped before the call was sent".into());
        }
        if client.exited() {
            return ToolOutcome::Error(format!(
                "MCP server '{server}' exited and is not running; restart the agent to reconnect"
            ));
        }
        let raw = if call.arguments.trim().is_empty() {
            "{}"
        } else {
            call.arguments.as_str()
        };
        let args: Value = match serde_json::from_str(raw) {
            Ok(v @ Value::Object(_)) => v,
            _ => return ToolOutcome::Error("MCP tool arguments must be a JSON object".to_string()),
        };
        let cap = entry.cfg.max_output_chars;
        match client.call_tool(remote, args, stop) {
            Ok(r) if r.is_error => ToolOutcome::Error(fence(server, remote, &r.text, cap, true)),
            Ok(r) => ToolOutcome::Untrusted(fence(server, remote, &r.text, cap, false)),
            Err(e) => {
                let msg: String = e.to_string().chars().take(cap).collect();
                ToolOutcome::Error(format!("MCP server '{server}': {msg}"))
            }
        }
    }

    /// The [`ToolHost`] for one turn, bound to the session's stop flag (a raised flag cancels an
    /// in-flight call). It cannot put a call in front of a person, so once a session is tainted
    /// the loop declines effectful MCP calls instead of dispatching them.
    pub fn tool_host(host: Arc<McpHost>, stop: StopFlag) -> Arc<dyn ToolHost> {
        Arc::new(McpToolHost { host, stop })
    }
}

/// See [`McpHost::tool_host`].
pub struct McpToolHost {
    host: Arc<McpHost>,
    stop: StopFlag,
}

impl McpToolHost {
    pub fn new(host: Arc<McpHost>, stop: StopFlag) -> Self {
        McpToolHost { host, stop }
    }

    pub fn handles(&self, name: &str) -> bool {
        self.host.handles(name)
    }
}

impl ToolHost for McpToolHost {
    fn execute(&self, call: &ToolCall) -> ToolOutcome {
        self.host.call(call, &self.stop)
    }
}
