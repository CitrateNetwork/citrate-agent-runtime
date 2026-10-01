//! The dry-run probe (HUP-S4.4): start or reach one server, run the handshake, list its tools,
//! and stop it. Nothing is registered: the probe feeds the review screen a person sees before a
//! user-added server is enabled.
//!
//! The report carries what the review needs (negotiated version, server name and version,
//! recorded capabilities, and every listed tool with the server's annotation hints, the effective
//! annotations after the spec defaults, the trust level, and whether a session would be offered
//! the tool) and nothing else: never the URL, the environment, or the server's `instructions`
//! text. Tool names and descriptions are server text, cleaned and capped, for display only.

use crate::client::{McpClient, RemoteTool};
use crate::config::ServerConfig;
use crate::host::offer;
use crate::mapping::{annotations_from, exposed_name, MAX_DESCRIPTION_CHARS};
use serde::Serialize;
use serde_json::Value;
use std::collections::HashSet;
use std::time::Duration;

/// The whole probe's deadline (handshake and every `tools/list` page together).
pub const PROBE_TIMEOUT: Duration = Duration::from_secs(20);

/// The annotation hints exactly as the server sent them (absent = not sent).
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct Hints {
    pub read_only_hint: Option<bool>,
    pub destructive_hint: Option<bool>,
    pub idempotent_hint: Option<bool>,
    pub open_world_hint: Option<bool>,
    pub title: Option<String>,
}

/// The annotations Hermes applies after the spec defaults.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct Effective {
    pub read_only: bool,
    pub destructive: bool,
    pub idempotent: bool,
    pub open_world: bool,
}

/// One tool as the review screen shows it.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct ProbedTool {
    /// The server's tool name (cleaned, at most 128 chars).
    pub name: String,
    /// The name the model would see, when it can be expressed.
    pub exposed_name: Option<String>,
    pub description: String,
    pub annotations: Hints,
    pub effective: Effective,
    /// Always `"untrusted"`: MCP output taints the session, whatever the server says.
    pub trust: &'static str,
    /// Whether a session would be offered this tool with the entry as it stands.
    pub offered: bool,
    pub skip_reason: Option<String>,
}

/// The probe's result. `ok = false` carries the reason in `error` and no tools.
#[derive(Debug, Clone, PartialEq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct ProbeReport {
    pub name: String,
    pub transport: &'static str,
    pub ok: bool,
    pub error: Option<String>,
    pub protocol_version: Option<String>,
    pub server_name: Option<String>,
    pub server_version: Option<String>,
    pub capabilities: Option<Value>,
    pub tools: Vec<ProbedTool>,
    /// The server listed more tools than the host reads (the rest are not shown or offered).
    pub tools_truncated: bool,
    pub allow_write_tools: bool,
}

fn clean(s: &str, max: usize) -> String {
    s.chars()
        .filter(|c| !c.is_control() || *c == '\n' || *c == '\t')
        .take(max)
        .collect()
}

fn hints(a: &Value) -> Hints {
    let b = |k: &str| a.get(k).and_then(Value::as_bool);
    Hints {
        read_only_hint: b("readOnlyHint"),
        destructive_hint: b("destructiveHint"),
        idempotent_hint: b("idempotentHint"),
        open_world_hint: b("openWorldHint"),
        title: a
            .get("title")
            .and_then(Value::as_str)
            .map(|t| clean(t, 120)),
    }
}

fn probed(sc: &ServerConfig, t: &RemoteTool, seen: &mut HashSet<String>) -> ProbedTool {
    let ann = annotations_from(&t.annotations);
    let decision = offer(sc, t, |n| seen.contains(n));
    let (offered, skip_reason) = match &decision {
        Ok(spec) => {
            seen.insert(spec.name.clone());
            (true, None)
        }
        Err(why) => (false, Some(why.clone())),
    };
    ProbedTool {
        name: clean(&t.name, 128),
        exposed_name: exposed_name(&sc.name, &t.name),
        description: clean(&t.description, MAX_DESCRIPTION_CHARS),
        annotations: hints(&t.annotations),
        effective: Effective {
            read_only: ann.read_only,
            destructive: ann.destructive,
            idempotent: ann.idempotent,
            open_world: ann.open_world,
        },
        trust: "untrusted",
        offered,
        skip_reason,
    }
}

fn run(sc: &ServerConfig) -> ProbeReport {
    let mut report = ProbeReport {
        name: sc.name.clone(),
        transport: sc.transport_kind(),
        ok: false,
        error: None,
        protocol_version: None,
        server_name: None,
        server_version: None,
        capabilities: None,
        tools: Vec::new(),
        tools_truncated: false,
        allow_write_tools: sc.allow_write_tools,
    };
    let client = match McpClient::connect(sc) {
        Ok(c) => c,
        Err(e) => {
            report.error = Some(e.to_string());
            return report;
        }
    };
    let info = client.info();
    report.protocol_version = Some(info.protocol_version.clone());
    report.server_name = Some(info.server_name.clone());
    report.server_version = Some(info.server_version.clone());
    report.capabilities = Some(info.capabilities.clone());
    match client.list_tools() {
        Ok(tools) => {
            report.tools_truncated = tools.len() >= crate::client::MAX_TOOLS_PER_SERVER;
            let mut seen = HashSet::new();
            report.tools = tools.iter().map(|t| probed(sc, t, &mut seen)).collect();
            report.ok = true;
        }
        Err(e) => report.error = Some(format!("listing tools: {e}")),
    }
    // Dropping the client stops a stdio server.
    drop(client);
    report
}

/// Probe with [`PROBE_TIMEOUT`]. Blocking: call it off the async runtime.
pub fn probe(sc: &ServerConfig) -> ProbeReport {
    probe_with_deadline(sc, PROBE_TIMEOUT)
}

/// Probe with an explicit overall deadline. Each request's own deadline is also capped at it, so
/// a server that never answers is abandoned (and a stdio child stopped) soon after.
pub fn probe_with_deadline(sc: &ServerConfig, deadline: Duration) -> ProbeReport {
    let mut cfg = sc.clone();
    cfg.init_timeout = cfg.init_timeout.min(deadline);
    let name = cfg.name.clone();
    let transport = cfg.transport_kind();
    let allow_write_tools = cfg.allow_write_tools;
    let (tx, rx) = std::sync::mpsc::channel();
    let spawned = std::thread::Builder::new()
        .name("mcp-probe".into())
        .spawn(move || {
            let _ = tx.send(run(&cfg));
        });
    let failed = |error: String| ProbeReport {
        name: name.clone(),
        transport,
        ok: false,
        error: Some(error),
        protocol_version: None,
        server_name: None,
        server_version: None,
        capabilities: None,
        tools: Vec::new(),
        tools_truncated: false,
        allow_write_tools,
    };
    if let Err(e) = spawned {
        return failed(format!("could not start the probe: {e}"));
    }
    match rx.recv_timeout(deadline) {
        Ok(r) => r,
        Err(_) => failed(format!(
            "no complete answer within {} ms; the server was not added",
            deadline.as_millis()
        )),
    }
}
