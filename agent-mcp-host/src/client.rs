//! One MCP client per server (HUP-S4.1), dual-era:
//!
//! - **Modern (2026-07-28, stateless).** `server/discover` first; every request then carries the
//!   protocol version, client info and client capabilities in `_meta`. Results carry
//!   `resultType`: `complete`, `input_required` (multi round-trip requests: URL-mode elicitation
//!   is put to the member through an [`Elicitor`], never opened automatically) or `task` (the
//!   Tasks extension: `tasks/get` polled within bounds, `tasks/update` for input, `tasks/cancel`
//!   on stop or timeout).
//! - **Legacy (2025-11-25 and earlier).** `initialize` (version negotiation, capabilities
//!   recorded), `notifications/initialized`, paginated `tools/list`, and `tools/call`.
//!
//! On stdio the era is found by probing with `server/discover` (a modern answer or a recognized
//! modern error means modern; any other error or no answer within [`DISCOVER_PROBE_TIMEOUT`]
//! means legacy). On HTTP a 4xx without a recognized modern error body means legacy. The
//! server's `init_timeout` bounds the whole connect (probe plus handshake). Spec text:
//! <https://modelcontextprotocol.io/specification/2026-07-28/basic/versioning>.

use crate::config::{ServerConfig, TransportConfig};
use crate::error::McpError;
use crate::mapping::render_content;
use crate::transport::{self, encode_header_value, Transport};
use citrate_agent_loop::StopFlag;
use serde_json::{json, Map, Value};
use std::collections::HashSet;
use std::time::{Duration, Instant};

/// The legacy version this host asks for in `initialize`.
pub const PROTOCOL_VERSION: &str = "2025-06-18";
/// The stateless revision this host speaks to modern servers.
pub const MODERN_VERSION: &str = "2026-07-28";
/// Legacy (handshake) versions accepted in an `initialize` answer. The tool shapes used here are
/// the same in all of them.
pub const LEGACY_VERSIONS: &[&str] = &["2025-11-25", "2025-06-18", "2025-03-26", "2024-11-05"];
/// Every version this host speaks.
pub const SUPPORTED_VERSIONS: &[&str] = &[
    "2026-07-28",
    "2025-11-25",
    "2025-06-18",
    "2025-03-26",
    "2024-11-05",
];
/// The Tasks extension identifier.
pub const TASKS_EXTENSION: &str = "io.modelcontextprotocol/tasks";

/// Bounds on `tools/list`.
pub const MAX_TOOL_PAGES: usize = 32;
pub const MAX_TOOLS_PER_SERVER: usize = 256;
/// Most multi round-trip retries of one call.
pub const MAX_INPUT_ROUNDS: usize = 3;
/// Most input requests answered in one round.
pub const MAX_INPUT_REQUESTS: usize = 4;
/// How long a stdio server has to answer the `server/discover` probe before it is treated as a
/// legacy server.
pub const DISCOVER_PROBE_TIMEOUT: Duration = Duration::from_secs(3);
/// Task polling interval bounds (the server's `pollIntervalMs` is clamped into these).
pub const MIN_POLL_INTERVAL: Duration = Duration::from_millis(100);
pub const MAX_POLL_INTERVAL: Duration = Duration::from_secs(10);
const DEFAULT_POLL_INTERVAL: Duration = Duration::from_secs(1);
/// Longest URL put in front of the member.
pub const MAX_ELICIT_URL: usize = 2048;

/// Which protocol family the server speaks.
#[derive(Debug, Clone, Copy, PartialEq, Eq, serde::Serialize)]
#[serde(rename_all = "snake_case")]
pub enum Era {
    /// 2026-07-28 and later: stateless, `_meta` on every request.
    Modern,
    /// 2025-11-25 and earlier: the `initialize` handshake.
    Legacy,
}

/// What `server/discover` or `initialize` told us. `instructions` is untrusted server text: it
/// is recorded for the status view and never placed in the model's prompt.
#[derive(Debug, Clone, PartialEq)]
pub struct ServerInfo {
    pub protocol_version: String,
    pub era: Era,
    pub capabilities: Value,
    pub server_name: String,
    pub server_version: String,
    pub instructions: Option<String>,
}

impl ServerInfo {
    /// The server advertised the Tasks extension.
    pub fn tasks(&self) -> bool {
        self.capabilities
            .pointer("/extensions")
            .and_then(Value::as_object)
            .is_some_and(|e| e.contains_key(TASKS_EXTENSION))
    }
}

/// One `x-mcp-header` parameter: where its value is in the arguments, and the header it goes in.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct HeaderParam {
    /// The chain of `properties` keys from the schema root.
    pub path: Vec<String>,
    /// The full header name, `Mcp-Param-<name>`.
    pub header: String,
}

/// A tool as the server described it.
#[derive(Debug, Clone, PartialEq)]
pub struct RemoteTool {
    pub name: String,
    pub description: String,
    pub input_schema: Value,
    /// The raw `annotations` object (hints only).
    pub annotations: Value,
    /// Its `x-mcp-header` parameters (streamable HTTP, 2026-07-28), or why the definition is
    /// invalid (an invalid tool is never offered).
    pub header_params: Result<Vec<HeaderParam>, String>,
}

/// A `tools/call` result: the rendered text (no binary payloads) and the server's error flag.
#[derive(Debug, Clone, PartialEq)]
pub struct CallResult {
    pub text: String,
    pub is_error: bool,
}

/// The member's answer to a URL-mode elicitation.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ElicitAction {
    /// The member consented; the app opened the URL in the system browser.
    Accept,
    Decline,
    Cancel,
}

impl ElicitAction {
    fn wire(self) -> &'static str {
        match self {
            ElicitAction::Accept => "accept",
            ElicitAction::Decline => "decline",
            ElicitAction::Cancel => "cancel",
        }
    }
}

/// A URL-mode elicitation as the member is shown it.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct UrlElicitation {
    pub server: String,
    /// The server's own tool name.
    pub tool: String,
    /// The server's message (untrusted text, control characters removed, capped).
    pub message: String,
    /// The full URL, exactly as the server sent it.
    pub url: String,
    /// The URL's host, for highlighting.
    pub host: String,
    /// Reasons to look twice (plain http, punycode, an IP address).
    pub warnings: Vec<String>,
}

/// Puts a URL-mode elicitation in front of a person. The host never opens a URL itself: only an
/// [`ElicitAction::Accept`] from the member (after which the app opens it) continues the call.
pub trait Elicitor: Send + Sync {
    fn open_url(&self, req: &UrlElicitation) -> ElicitAction;
}

/// Per-call options.
#[derive(Default)]
pub struct CallOpts<'a> {
    /// Present only when a person can be asked; then (and only then) URL-mode elicitation is
    /// declared in the request's client capabilities.
    pub elicitor: Option<&'a dyn Elicitor>,
    /// The tool as listed (for its `x-mcp-header` parameters).
    pub tool: Option<&'a RemoteTool>,
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

fn clean(s: &str, n: usize) -> String {
    s.chars().filter(|c| !c.is_control()).take(n).collect()
}

fn client_info() -> Value {
    json!({"name": "citrate-hermes", "version": env!("CARGO_PKG_VERSION")})
}

/// The `_meta` every modern request carries.
fn modern_meta(elicit: bool) -> Value {
    let mut caps = json!({"extensions": {TASKS_EXTENSION: {}}});
    if elicit {
        caps["elicitation"] = json!({"url": {}});
    }
    json!({
        "io.modelcontextprotocol/protocolVersion": MODERN_VERSION,
        "io.modelcontextprotocol/clientInfo": client_info(),
        "io.modelcontextprotocol/clientCapabilities": caps,
    })
}

/// What a result is, by its `resultType` (absent = complete, for earlier-protocol servers).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Kind {
    Complete,
    InputRequired,
    Task,
}

fn kind_of(result: &Value, allow_mrtr: bool, allow_task: bool) -> Result<Kind, McpError> {
    match result.get("resultType") {
        None => Ok(Kind::Complete),
        Some(Value::String(s)) if s == "complete" => Ok(Kind::Complete),
        Some(Value::String(s)) if s == "input_required" && allow_mrtr => Ok(Kind::InputRequired),
        Some(Value::String(s)) if s == "task" && allow_task => Ok(Kind::Task),
        Some(other) => Err(McpError::BadResponse(format!(
            "unexpected resultType {}",
            short(&other.to_string(), 40)
        ))),
    }
}

/// RFC 9110 `tchar`.
fn is_tchar(c: char) -> bool {
    c.is_ascii_alphanumeric() || "!#$%&'*+-.^_`|~".contains(c)
}

/// The `x-mcp-header` parameters of a tool's input schema (2026-07-28 streamable HTTP), or why
/// the definition is invalid. An annotation is valid only on a primitive (string, integer,
/// boolean) property reached from the root through `properties` keys alone.
pub fn header_params(schema: &Value) -> Result<Vec<HeaderParam>, String> {
    fn walk(
        v: &Value,
        path: &mut Vec<String>,
        out: &mut Vec<(Vec<String>, Value, Value)>,
        depth: usize,
    ) -> Result<(), String> {
        if depth > 32 {
            return Err("its input schema is nested too deeply".into());
        }
        match v {
            Value::Object(o) => {
                if let Some(h) = o.get("x-mcp-header") {
                    out.push((
                        path.clone(),
                        h.clone(),
                        o.get("type").cloned().unwrap_or(Value::Null),
                    ));
                }
                for (k, child) in o {
                    path.push(k.clone());
                    walk(child, path, out, depth + 1)?;
                    path.pop();
                }
            }
            Value::Array(a) => {
                for (i, child) in a.iter().enumerate() {
                    path.push(format!("[{i}]"));
                    walk(child, path, out, depth + 1)?;
                    path.pop();
                }
            }
            _ => {}
        }
        Ok(())
    }
    let mut found = Vec::new();
    walk(schema, &mut Vec::new(), &mut found, 0)?;
    let mut out: Vec<HeaderParam> = Vec::new();
    let mut seen: HashSet<String> = HashSet::new();
    for (path, header, ty) in found {
        // Statically reachable: properties, <key>, properties, <key>, ...
        let reachable = !path.is_empty()
            && path.len() % 2 == 0
            && path
                .chunks(2)
                .all(|c| c[0] == "properties" && !c[1].starts_with('['));
        if !reachable {
            return Err(
                "an x-mcp-header annotation is not on a property reachable through 'properties' alone"
                    .into(),
            );
        }
        let Some(name) = header.as_str() else {
            return Err("an x-mcp-header value is not a string".into());
        };
        if name.is_empty() || !name.chars().all(is_tchar) {
            return Err("an x-mcp-header value is not a valid header name".into());
        }
        if !seen.insert(name.to_ascii_lowercase()) {
            return Err("two x-mcp-header values are the same".into());
        }
        if !matches!(ty.as_str(), Some("string" | "integer" | "boolean")) {
            return Err(
                "an x-mcp-header annotation is on a property that is not a string, integer or boolean"
                    .into(),
            );
        }
        out.push(HeaderParam {
            path: path.chunks(2).map(|c| c[1].clone()).collect(),
            header: format!("Mcp-Param-{name}"),
        });
    }
    Ok(out)
}

/// The `Mcp-Param-*` headers for one call's arguments. A missing or null value omits the header.
pub fn param_headers(
    params: &[HeaderParam],
    args: &Value,
) -> Result<Vec<(String, String)>, McpError> {
    const SAFE: i64 = (1 << 53) - 1;
    let mut out = Vec::new();
    for p in params {
        let mut v = args;
        let mut present = true;
        for k in &p.path {
            match v.get(k) {
                Some(next) => v = next,
                None => {
                    present = false;
                    break;
                }
            }
        }
        if !present {
            continue;
        }
        let text = match v {
            Value::Null => continue,
            Value::String(s) => s.clone(),
            Value::Bool(b) => b.to_string(),
            Value::Number(n) => match n.as_i64() {
                Some(i) if (-SAFE..=SAFE).contains(&i) => i.to_string(),
                _ => {
                    return Err(McpError::BadResponse(format!(
                        "the argument for {} is not an integer in the header-safe range",
                        p.header
                    )))
                }
            },
            _ => {
                return Err(McpError::BadResponse(format!(
                    "the argument for {} is not a string, integer or boolean",
                    p.header
                )))
            }
        };
        out.push((p.header.clone(), encode_header_value(&text)));
    }
    Ok(out)
}

/// A URL-mode elicitation request, checked before it can reach the member.
pub fn parse_url_elicitation(
    server: &str,
    tool: &str,
    params: &Value,
) -> Result<UrlElicitation, String> {
    if params.get("mode").and_then(Value::as_str) != Some("url") {
        return Err("a form elicitation (this host only supports URL mode)".into());
    }
    let url = params
        .get("url")
        .and_then(Value::as_str)
        .ok_or("a URL elicitation without a url")?;
    if url.len() > MAX_ELICIT_URL || url.chars().any(char::is_control) {
        return Err("a URL elicitation whose url is too long or has control characters".into());
    }
    let parsed = reqwest::Url::parse(url).map_err(|_| "a URL elicitation with an invalid url")?;
    if !matches!(parsed.scheme(), "https" | "http") {
        return Err("a URL elicitation that is not an http(s) address".into());
    }
    if !parsed.username().is_empty() || parsed.password().is_some() {
        return Err("a URL elicitation with credentials in the address".into());
    }
    let host = parsed
        .host_str()
        .ok_or("a URL elicitation without a host")?
        .to_string();
    let mut warnings = Vec::new();
    let ip = host
        .trim_start_matches('[')
        .trim_end_matches(']')
        .parse::<std::net::IpAddr>()
        .ok();
    let loopback = host == "localhost" || ip.is_some_and(|ip| ip.is_loopback());
    if parsed.scheme() == "http" && !loopback {
        warnings.push("this address is not encrypted (http)".to_string());
    }
    if host.split('.').any(|l| l.starts_with("xn--")) {
        warnings.push(
            "this host uses international characters (punycode); check it carefully".to_string(),
        );
    }
    if ip.is_some() && !loopback {
        warnings.push("this address is a raw IP address".to_string());
    }
    Ok(UrlElicitation {
        server: server.to_string(),
        tool: tool.to_string(),
        message: clean(
            params.get("message").and_then(Value::as_str).unwrap_or(""),
            500,
        ),
        url: url.to_string(),
        host,
        warnings,
    })
}

fn valid_task_id(s: &str) -> bool {
    !s.is_empty() && s.len() <= 256 && s.bytes().all(|b| (0x21..=0x7e).contains(&b))
}

impl McpClient {
    /// Start or reach the server and find its era (see the module docs). A server that speaks
    /// no version this host does is refused (and a stdio child is stopped).
    pub fn connect(cfg: &ServerConfig) -> Result<Self, McpError> {
        let started = Instant::now();
        let transport = transport::connect(cfg)?;
        let is_stdio = matches!(cfg.transport, TransportConfig::Stdio { .. });
        let probe_timeout = if is_stdio {
            cfg.init_timeout.min(DISCOVER_PROBE_TIMEOUT)
        } else {
            cfg.init_timeout
        };
        transport.set_modern(MODERN_VERSION);
        let discovered = transport.request(
            "server/discover",
            json!({"_meta": modern_meta(false)}),
            probe_timeout,
            None,
        );
        // `init_timeout` is the whole connect budget: the handshake gets what the probe left.
        let legacy = |transport: Box<dyn Transport>| {
            let left = cfg
                .init_timeout
                .saturating_sub(started.elapsed())
                .max(Duration::from_millis(100));
            Self::initialize(cfg, transport, left)
        };
        match discovered {
            Ok(result) => {
                kind_of(&result, false, false)?;
                let versions: Vec<String> = result
                    .get("supportedVersions")
                    .and_then(Value::as_array)
                    .map(|a| {
                        a.iter()
                            .filter_map(Value::as_str)
                            .map(str::to_string)
                            .collect()
                    })
                    .unwrap_or_default();
                if versions.iter().any(|v| v == MODERN_VERSION) {
                    Ok(Self::modern(cfg, transport, &result))
                } else if versions
                    .iter()
                    .any(|v| LEGACY_VERSIONS.contains(&v.as_str()))
                {
                    // A dual-era server that offers us only handshake versions.
                    legacy(Self::reopen(cfg, transport)?)
                } else {
                    Err(McpError::Unsupported(format!(
                        "protocol versions {:?}",
                        short(&versions.join(", "), 80)
                    )))
                }
            }
            Err(e @ McpError::UnsupportedVersion { .. }) => Err(e),
            Err(e) if e.is_modern_protocol_error() => Err(e),
            // Legacy indicators. stdio: any other error, or no answer in time. HTTP: a 4xx
            // without a modern error body, or a JSON-RPC error that is not a modern one.
            Err(McpError::Rpc { .. }) | Err(McpError::HttpStatus(_)) => {
                legacy(Self::reopen(cfg, transport)?)
            }
            Err(McpError::Timeout(_)) | Err(McpError::BadResponse(_)) if is_stdio => {
                legacy(Self::reopen(cfg, transport)?)
            }
            Err(e) => Err(e),
        }
    }

    /// The legacy handshake needs legacy wire rules: an HTTP transport is rebuilt (stdio keeps
    /// its process; its framing is the same in both eras).
    fn reopen(
        cfg: &ServerConfig,
        transport: Box<dyn Transport>,
    ) -> Result<Box<dyn Transport>, McpError> {
        match cfg.transport {
            TransportConfig::Stdio { .. } => Ok(transport),
            TransportConfig::Http { .. } => {
                drop(transport);
                transport::connect(cfg)
            }
        }
    }

    fn modern(cfg: &ServerConfig, transport: Box<dyn Transport>, result: &Value) -> Self {
        let capabilities = match result.get("capabilities") {
            Some(c) if c.is_object() => c.clone(),
            _ => json!({}),
        };
        let field = |k: &str| {
            result
                .get("_meta")
                .and_then(|m| m.get("io.modelcontextprotocol/serverInfo"))
                .and_then(|i| i.get(k))
                .and_then(Value::as_str)
                .map(|s| short(s, 120))
                .unwrap_or_default()
        };
        let info = ServerInfo {
            protocol_version: MODERN_VERSION.to_string(),
            era: Era::Modern,
            capabilities,
            server_name: field("name"),
            server_version: field("version"),
            instructions: result
                .get("instructions")
                .and_then(Value::as_str)
                .map(|s| short(s, 2000)),
        };
        let client = McpClient {
            name: cfg.name.clone(),
            cfg: cfg.clone(),
            transport,
            info,
        };
        if client
            .info
            .capabilities
            .pointer("/tools/listChanged")
            .and_then(Value::as_bool)
            == Some(true)
        {
            client.transport.listen(json!({
                "_meta": modern_meta(false),
                "notifications": {"toolsListChanged": true},
            }));
        }
        client
    }

    fn initialize(
        cfg: &ServerConfig,
        transport: Box<dyn Transport>,
        timeout: Duration,
    ) -> Result<Self, McpError> {
        let result = transport.request(
            "initialize",
            json!({
                "protocolVersion": PROTOCOL_VERSION,
                "capabilities": {},
                "clientInfo": client_info(),
            }),
            timeout,
            None,
        )?;
        let version = result
            .get("protocolVersion")
            .and_then(Value::as_str)
            .ok_or_else(|| McpError::BadResponse("initialize had no protocolVersion".into()))?;
        if !LEGACY_VERSIONS.contains(&version) {
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
            era: Era::Legacy,
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

    fn modern_era(&self) -> bool {
        self.info.era == Era::Modern
    }

    fn is_http(&self) -> bool {
        matches!(self.cfg.transport, TransportConfig::Http { .. })
    }

    /// `params` with the modern `_meta` added (unchanged for a legacy server).
    fn with_meta(&self, mut params: Value, elicit: bool) -> Value {
        if self.modern_era() {
            if let Value::Object(o) = &mut params {
                o.insert("_meta".into(), modern_meta(elicit));
            }
        }
        params
    }

    /// Every tool the server lists (all pages, bounded). A server that did not declare the
    /// `tools` capability has none.
    pub fn list_tools(&self) -> Result<Vec<RemoteTool>, McpError> {
        if self.info.capabilities.get("tools").is_none() {
            return Ok(Vec::new());
        }
        let check_headers = self.modern_era() && self.is_http();
        let mut out = Vec::new();
        let mut cursor: Option<String> = None;
        for _ in 0..MAX_TOOL_PAGES {
            let params = match &cursor {
                Some(c) => json!({"cursor": c}),
                None => json!({}),
            };
            let page = self.transport.request(
                "tools/list",
                self.with_meta(params, false),
                self.cfg.init_timeout,
                None,
            )?;
            kind_of(&page, false, false)?;
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
                let input_schema = t.get("inputSchema").cloned().unwrap_or(Value::Null);
                let header_params = if check_headers {
                    header_params(&input_schema)
                } else {
                    Ok(Vec::new())
                };
                out.push(RemoteTool {
                    name: name.to_string(),
                    description: t
                        .get("description")
                        .and_then(Value::as_str)
                        .unwrap_or("")
                        .to_string(),
                    input_schema,
                    annotations: t.get("annotations").cloned().unwrap_or(json!({})),
                    header_params,
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
        self.call_tool_with(name, args, stop, &CallOpts::default())
    }

    /// [`McpClient::call_tool`] with an elicitor and the listed tool (for `x-mcp-header`).
    pub fn call_tool_with(
        &self,
        name: &str,
        args: Value,
        stop: &StopFlag,
        opts: &CallOpts<'_>,
    ) -> Result<CallResult, McpError> {
        let modern = self.modern_era();
        let headers = match opts.tool {
            Some(t) if modern && self.is_http() => match &t.header_params {
                Ok(p) => param_headers(p, &args)?,
                Err(e) => return Err(McpError::BadResponse(e.clone())),
            },
            _ => Vec::new(),
        };
        let elicit = opts.elicitor.is_some();
        let mut retry: Option<(Option<Value>, Option<Value>)> = None;
        for _ in 0..=MAX_INPUT_ROUNDS {
            let mut params = json!({"name": name, "arguments": args});
            if let Some((responses, state)) = retry.take() {
                if let Some(r) = responses {
                    params["inputResponses"] = r;
                }
                if let Some(s) = state {
                    params["requestState"] = s;
                }
            }
            let result = self.transport.request_with_headers(
                "tools/call",
                self.with_meta(params, elicit),
                self.cfg.timeout,
                Some(stop),
                &headers,
            )?;
            if !result.is_object() {
                return Err(McpError::BadResponse(
                    "tools/call result was not an object".into(),
                ));
            }
            match kind_of(&result, modern, modern)? {
                Kind::Complete => return Ok(Self::call_result(&result)),
                Kind::Task => return self.drive_task(name, &result, stop, opts.elicitor),
                Kind::InputRequired => {
                    let state = result.get("requestState").cloned();
                    let responses = match result.get("inputRequests") {
                        None => None,
                        Some(Value::Object(reqs)) => Some(Value::Object(self.answer_inputs(
                            name,
                            reqs,
                            opts.elicitor,
                            &mut HashSet::new(),
                        )?)),
                        Some(_) => {
                            return Err(McpError::BadResponse(
                                "inputRequests was not an object".into(),
                            ))
                        }
                    };
                    if responses.is_none() && state.is_none() {
                        return Err(McpError::BadResponse(
                            "input_required with neither inputRequests nor requestState".into(),
                        ));
                    }
                    if stop.is_stopped() {
                        return Err(McpError::Cancelled);
                    }
                    retry = Some((responses, state));
                }
            }
        }
        Err(McpError::InputRequired(format!(
            "the server kept asking for input after {MAX_INPUT_ROUNDS} rounds"
        )))
    }

    fn call_result(result: &Value) -> CallResult {
        CallResult {
            text: render_content(result),
            is_error: result.get("isError").and_then(Value::as_bool) == Some(true),
        }
    }

    /// Answer a round of input requests. Only URL-mode elicitation is supported, and only with
    /// an elicitor (a person); anything else ends the call. Keys in `answered` are skipped.
    fn answer_inputs(
        &self,
        tool: &str,
        reqs: &Map<String, Value>,
        elicitor: Option<&dyn Elicitor>,
        answered: &mut HashSet<String>,
    ) -> Result<Map<String, Value>, McpError> {
        let fresh: Vec<(&String, &Value)> = reqs
            .iter()
            .filter(|(k, _)| !answered.contains(*k))
            .collect();
        if fresh.len() > MAX_INPUT_REQUESTS {
            return Err(McpError::InputRequired(format!(
                "the server asked for more than {MAX_INPUT_REQUESTS} inputs at once"
            )));
        }
        let mut out = Map::new();
        for (key, req) in fresh {
            let method = req.get("method").and_then(Value::as_str).unwrap_or("");
            if method != "elicitation/create" {
                return Err(McpError::InputRequired(format!(
                    "a {} request, which this host does not provide",
                    short(method, 40)
                )));
            }
            let Some(e) = elicitor else {
                return Err(McpError::InputRequired(
                    "an elicitation, and no one can be asked in this context".into(),
                ));
            };
            let params = req.get("params").cloned().unwrap_or(json!({}));
            let ask = parse_url_elicitation(&self.name, tool, &params)
                .map_err(McpError::InputRequired)?;
            let action = e.open_url(&ask);
            out.insert(key.clone(), json!({"action": action.wire()}));
            answered.insert(key.clone());
        }
        Ok(out)
    }

    /// Drive a task to a terminal state: poll `tasks/get` at the server's interval (clamped),
    /// answer input through `tasks/update`, and cancel with `tasks/cancel` on stop or after the
    /// server's task timeout.
    fn drive_task(
        &self,
        tool: &str,
        created: &Value,
        stop: &StopFlag,
        elicitor: Option<&dyn Elicitor>,
    ) -> Result<CallResult, McpError> {
        let task_id = created
            .get("taskId")
            .and_then(Value::as_str)
            .filter(|s| valid_task_id(s))
            .ok_or_else(|| McpError::BadResponse("a task without a usable taskId".into()))?
            .to_string();
        let deadline = Instant::now() + self.cfg.task_timeout;
        let mut answered: HashSet<String> = HashSet::new();
        let mut state = created.clone();
        let cancel = |why: McpError| {
            let _ = self.transport.request(
                "tasks/cancel",
                self.with_meta(json!({"taskId": task_id}), false),
                self.cfg.init_timeout.min(Duration::from_secs(5)),
                None,
            );
            Err(why)
        };
        loop {
            match state.get("status").and_then(Value::as_str).unwrap_or("") {
                "completed" => {
                    let result =
                        state
                            .get("result")
                            .filter(|r| r.is_object())
                            .ok_or_else(|| {
                                McpError::BadResponse("a completed task without a result".into())
                            })?;
                    return Ok(Self::call_result(result));
                }
                "failed" => {
                    let err = state.get("error").cloned().unwrap_or(json!({}));
                    return Err(McpError::Rpc {
                        code: err.get("code").and_then(Value::as_i64).unwrap_or(0),
                        message: short(
                            err.get("message").and_then(Value::as_str).unwrap_or(""),
                            500,
                        ),
                    });
                }
                "cancelled" => return Err(McpError::TaskCancelled),
                "input_required" => {
                    if let Some(Value::Object(reqs)) = state.get("inputRequests") {
                        let responses =
                            match self.answer_inputs(tool, reqs, elicitor, &mut answered) {
                                Ok(r) => r,
                                Err(e) => return cancel(e),
                            };
                        if !responses.is_empty() {
                            self.transport.request(
                                "tasks/update",
                                self.with_meta(
                                    json!({"taskId": task_id, "inputResponses": responses}),
                                    elicitor.is_some(),
                                ),
                                self.cfg.timeout,
                                Some(stop),
                            )?;
                        }
                    }
                }
                "working" => {}
                other => {
                    return Err(McpError::BadResponse(format!(
                        "a task with status {:?}",
                        short(other, 30)
                    )))
                }
            }
            let interval = state
                .get("pollIntervalMs")
                .and_then(Value::as_u64)
                .map(Duration::from_millis)
                .unwrap_or(DEFAULT_POLL_INTERVAL)
                .clamp(MIN_POLL_INTERVAL, MAX_POLL_INTERVAL);
            let wake = Instant::now() + interval;
            while Instant::now() < wake {
                if stop.is_stopped() {
                    return cancel(McpError::Cancelled);
                }
                if Instant::now() >= deadline {
                    return cancel(McpError::Timeout(self.cfg.task_timeout));
                }
                std::thread::sleep(Duration::from_millis(20).min(interval));
            }
            if stop.is_stopped() {
                return cancel(McpError::Cancelled);
            }
            if Instant::now() >= deadline {
                return cancel(McpError::Timeout(self.cfg.task_timeout));
            }
            state = self.transport.request(
                "tasks/get",
                self.with_meta(json!({"taskId": task_id}), elicitor.is_some()),
                self.cfg.timeout,
                Some(stop),
            )?;
            kind_of(&state, false, false)?;
            if state.get("taskId").and_then(Value::as_str) != Some(task_id.as_str()) {
                return Err(McpError::BadResponse(
                    "tasks/get answered for a different task".into(),
                ));
            }
        }
    }

    /// Messages from the server that were not valid JSON-RPC and were skipped.
    pub fn bad_messages(&self) -> u64 {
        self.transport.bad_messages()
    }

    /// The server process exited (stdio).
    pub fn exited(&self) -> bool {
        self.transport.exited()
    }

    /// The connection can carry no more requests (the host reconnects).
    pub fn broken(&self) -> bool {
        self.transport.broken()
    }

    /// The server announced a changed tool list (not yet acted on).
    pub fn tools_changed(&self) -> bool {
        self.transport.tools_changed()
    }

    /// Whether the tool list changed since the last call; clears the flag.
    pub fn take_tools_changed(&self) -> bool {
        self.transport.take_tools_changed()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn header_params_accepts_reachable_primitives_only() {
        let ok = json!({"type": "object", "properties": {
            "region": {"type": "string", "x-mcp-header": "Region"},
            "opts": {"type": "object", "properties": {"n": {"type": "integer", "x-mcp-header": "N"}}}
        }});
        let p = header_params(&ok).expect("valid");
        assert_eq!(p.len(), 2);
        assert!(p
            .iter()
            .any(|h| h.path == vec!["region"] && h.header == "Mcp-Param-Region"));
        assert!(p.iter().any(|h| h.path == vec!["opts", "n"]));
        for bad in [
            json!({"properties": {"x": {"type": "number", "x-mcp-header": "X"}}}),
            json!({"properties": {"x": {"type": "array", "items": {"type": "string", "x-mcp-header": "X"}}}}),
            json!({"anyOf": [{"properties": {"x": {"type": "string", "x-mcp-header": "X"}}}]}),
            json!({"properties": {"x": {"type": "string", "x-mcp-header": "bad name"}}}),
            json!({"properties": {"a": {"type": "string", "x-mcp-header": "Dup"}, "b": {"type": "string", "x-mcp-header": "dup"}}}),
            json!({"properties": {"x": {"type": "string", "x-mcp-header": ""}}}),
        ] {
            assert!(header_params(&bad).is_err(), "accepted {bad}");
        }
    }

    #[test]
    fn param_headers_encode_values_and_skip_missing_ones() {
        let p = vec![
            HeaderParam {
                path: vec!["region".into()],
                header: "Mcp-Param-Region".into(),
            },
            HeaderParam {
                path: vec!["greeting".into()],
                header: "Mcp-Param-Greeting".into(),
            },
            HeaderParam {
                path: vec!["missing".into()],
                header: "Mcp-Param-Missing".into(),
            },
        ];
        let h = param_headers(
            &p,
            &json!({"region": "us-west1", "greeting": "Hello, 世界"}),
        )
        .expect("headers");
        assert_eq!(
            h,
            vec![
                ("Mcp-Param-Region".to_string(), "us-west1".to_string()),
                (
                    "Mcp-Param-Greeting".to_string(),
                    "=?base64?SGVsbG8sIOS4lueVjA==?=".to_string()
                ),
            ]
        );
        assert!(param_headers(&p[..1], &json!({"region": 1.5})).is_err());
    }

    #[test]
    fn url_elicitations_are_checked_and_flagged() {
        let ok = parse_url_elicitation(
            "s",
            "t",
            &json!({"mode": "url", "message": "Connect\u{7}", "url": "https://xn--pple-43d.example/connect"}),
        )
        .expect("ok");
        assert_eq!(ok.host, "xn--pple-43d.example");
        assert_eq!(ok.message, "Connect");
        assert!(ok.warnings.iter().any(|w| w.contains("punycode")));
        let plain = parse_url_elicitation(
            "s",
            "t",
            &json!({"mode": "url", "message": "m", "url": "http://10.0.0.1/x"}),
        )
        .expect("ok");
        assert_eq!(plain.warnings.len(), 2, "{:?}", plain.warnings);
        for bad in [
            json!({"mode": "form", "message": "m", "requestedSchema": {}}),
            json!({"message": "m", "requestedSchema": {}}),
            json!({"mode": "url", "message": "m", "url": "javascript:alert(1)"}),
            json!({"mode": "url", "message": "m", "url": "file:///etc/passwd"}),
            json!({"mode": "url", "message": "m", "url": "https://user:pw@example.com/"}),
            json!({"mode": "url", "message": "m"}),
        ] {
            assert!(
                parse_url_elicitation("s", "t", &bad).is_err(),
                "accepted {bad}"
            );
        }
    }

    #[test]
    fn result_types_are_checked() {
        assert_eq!(kind_of(&json!({}), false, false), Ok(Kind::Complete));
        assert_eq!(
            kind_of(&json!({"resultType": "complete"}), false, false),
            Ok(Kind::Complete)
        );
        assert_eq!(
            kind_of(&json!({"resultType": "task"}), true, true),
            Ok(Kind::Task)
        );
        assert!(kind_of(&json!({"resultType": "task"}), true, false).is_err());
        assert!(kind_of(&json!({"resultType": "input_required"}), false, true).is_err());
        assert!(kind_of(&json!({"resultType": "mystery"}), true, true).is_err());
    }
}
