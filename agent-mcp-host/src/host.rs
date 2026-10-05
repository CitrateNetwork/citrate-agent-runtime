//! The MCP host (HUP-S4.1): every allowlisted server, its offered tools, and the
//! [`ToolHost`] the sidecar registers for them.
//!
//! - **Reconnect.** A server that failed to start, whose process exited, or whose HTTP endpoint
//!   stopped answering is reconnected by [`McpHost::maintain_now`] with exponential backoff
//!   ([`RECONNECT_BACKOFF_START`] doubling to [`RECONNECT_BACKOFF_CAP`]).
//! - **Tool list changes.** A `notifications/tools/list_changed` makes the next maintenance pass
//!   re-list that server and apply the write-tool policy again. New and changed tools reach new
//!   sessions only: a running session keeps the specs it was offered, and a call to a tool whose
//!   spec has since changed or been withdrawn is refused (so a server can never widen what a
//!   running session can do).
//! - **Approvals after taint.** With an [`McpApprover`] (the sidecar's per-session approval
//!   queue), an effectful MCP call after taint is put in front of the member instead of being
//!   declined, and URL-mode elicitation is asked the same way. Without one, both fail closed.

use crate::client::{CallOpts, ElicitAction, Elicitor, Era, McpClient, RemoteTool, UrlElicitation};
use crate::config::{McpConfig, ServerConfig};
use crate::error::McpError;
use crate::mapping::{fence, to_spec, TOOL_PREFIX};
use citrate_agent_loop::{Effect, StopFlag, ToolCall, ToolHost, ToolOutcome, ToolSpec};
use serde::Serialize;
use serde_json::Value;
use std::collections::HashMap;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Mutex, RwLock, Weak};
use std::time::{Duration, Instant};

/// First wait before reconnecting a server; doubles per failure up to the cap.
pub const RECONNECT_BACKOFF_START: Duration = Duration::from_secs(1);
pub const RECONNECT_BACKOFF_CAP: Duration = Duration::from_secs(60);
/// Largest argument object put on an approval card (bytes of canonical JSON).
pub const MAX_REVIEW_ARGS: usize = 8 * 1024;

/// Whether `t` from server `sc` is offered to the model, and as which spec. `taken` says whether
/// an exposed name is already used. The same decision drives the session host and the dry-run
/// probe (HUP-S4.4), so the review screen shows exactly what a session would get.
pub(crate) fn offer(
    sc: &ServerConfig,
    t: &RemoteTool,
    taken: impl Fn(&str) -> bool,
) -> Result<ToolSpec, String> {
    let spec = to_spec(&sc.name, t)?;
    if let Err(why) = &t.header_params {
        return Err(format!("its definition is invalid: {why}"));
    }
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
    /// Connected.
    Ready,
    /// Could not be started, reached or initialized; retried with backoff.
    Failed,
    /// Was ready; its process has since exited or its endpoint stopped answering. Reconnected
    /// with backoff.
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
    /// `modern` (2026-07-28, stateless) or `legacy` (handshake).
    #[serde(skip_serializing_if = "Option::is_none")]
    pub era: Option<Era>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub server_name: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub capabilities: Option<Value>,
    /// The server advertised the Tasks extension.
    pub tasks: bool,
    /// Tools offered to the model.
    pub tools: usize,
    /// Tools listed by the server but not offered, with the reason.
    pub skipped: Vec<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub error: Option<String>,
    pub tools_changed: bool,
    pub bad_messages: u64,
    pub allow_write_tools: bool,
    /// Successful reconnects since the sidecar started.
    pub reconnects: u64,
    /// Times the tool list was re-read after the server said it changed.
    pub relists: u64,
    /// Milliseconds until the next reconnect attempt, while not connected.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub next_retry_ms: Option<u64>,
}

/// One effectful call put in front of the member after taint.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CallApproval {
    /// The loop's tool call id.
    pub call_id: String,
    /// The exposed name (`mcp__<server>__<tool>`).
    pub tool: String,
    pub server: String,
    /// The server's own tool name.
    pub remote_tool: String,
    /// The arguments exactly as they will be sent (canonical JSON).
    pub arguments: String,
    /// The server's hints, after the spec defaults (hints, never trusted).
    pub read_only: bool,
    pub destructive: bool,
    pub idempotent: bool,
    pub open_world: bool,
    /// Why the member is asked.
    pub reason: String,
}

/// Puts MCP calls and URL elicitations in front of the member (the sidecar's per-session
/// approval queue). Implementations must have no automatic path: only an explicit member
/// decision allows anything.
pub trait McpApprover: Send + Sync {
    /// `Ok(())` only for an explicit allow.
    fn approve_call(&self, req: &CallApproval, stop: &StopFlag) -> Result<(), String>;
    /// The member's answer to opening `req.url` (opened by the app, never by the sidecar).
    fn open_url(&self, call_id: &str, req: &UrlElicitation, stop: &StopFlag) -> ElicitAction;
}

/// Per-call context for [`McpHost::call_with`].
#[derive(Default)]
pub struct CallCtx<'a> {
    pub elicitor: Option<&'a dyn Elicitor>,
    /// The spec the session was offered for this tool; the call is refused when the server's
    /// current spec differs (changed or withdrawn since the session started).
    pub offered: Option<&'a ToolSpec>,
}

#[derive(Default)]
struct EntryState {
    client: Option<Arc<McpClient>>,
    error: Option<String>,
    /// Everything the server listed, before the offer policy.
    listed: Vec<RemoteTool>,
    specs: Vec<ToolSpec>,
    skipped: Vec<String>,
    failures: u32,
    next_retry: Option<Instant>,
    was_ready: bool,
    reconnects: u64,
    relists: u64,
}

struct Entry {
    cfg: ServerConfig,
    state: Mutex<EntryState>,
}

impl Entry {
    fn lock(&self) -> std::sync::MutexGuard<'_, EntryState> {
        self.state.lock().unwrap_or_else(|p| p.into_inner())
    }
}

#[derive(Clone)]
struct Route {
    entry: usize,
    tool: RemoteTool,
    spec: ToolSpec,
}

/// All configured servers.
pub struct McpHost {
    entries: Vec<Entry>,
    /// exposed name → route. Lock order: `routes`, then an entry's state.
    routes: RwLock<HashMap<String, Route>>,
    maintaining: Mutex<()>,
    /// Set by [`McpHost::shutdown`]: no server is reconnected afterwards.
    stopped: AtomicBool,
}

fn backoff(failures: u32) -> Duration {
    let shift = failures.saturating_sub(1).min(16);
    RECONNECT_BACKOFF_START
        .saturating_mul(1u32 << shift)
        .min(RECONNECT_BACKOFF_CAP)
}

type Connected = Result<(McpClient, Vec<RemoteTool>), McpError>;

fn connect_and_list(sc: &ServerConfig) -> Connected {
    McpClient::connect(sc).and_then(|c| c.list_tools().map(|t| (c, t)))
}

impl McpHost {
    /// Connect to every server. Handshakes run in parallel (one thread per server), so a server
    /// that never answers costs its own init deadline once, not once per server; tools are then
    /// mapped in allowlist order. A server that fails is reported in [`McpHost::status`], offers
    /// no tools, and is retried by [`McpHost::maintain_now`]; the others are unaffected.
    pub fn connect(cfg: &McpConfig) -> Self {
        let results: Vec<Connected> = std::thread::scope(|scope| {
            let handles: Vec<_> = cfg
                .servers
                .iter()
                .map(|sc| scope.spawn(move || connect_and_list(sc)))
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
        let now = Instant::now();
        let entries = cfg
            .servers
            .iter()
            .zip(results)
            .map(|(sc, connected)| {
                let mut st = EntryState::default();
                match connected {
                    Ok((client, tools)) => {
                        st.client = Some(Arc::new(client));
                        st.listed = tools;
                        st.was_ready = true;
                    }
                    Err(err) => {
                        st.error = Some(err.to_string());
                        st.failures = 1;
                        st.next_retry = Some(now + backoff(1));
                    }
                }
                Entry {
                    cfg: sc.clone(),
                    state: Mutex::new(st),
                }
            })
            .collect();
        let host = McpHost {
            entries,
            routes: RwLock::new(HashMap::new()),
            maintaining: Mutex::new(()),
            stopped: AtomicBool::new(false),
        };
        host.rebuild();
        host
    }

    /// Re-derive every server's offered specs and the route table from what each listed, in
    /// allowlist order (the write-tool policy and collision rule applied afresh).
    fn rebuild(&self) {
        let mut routes = self.routes.write().unwrap_or_else(|p| p.into_inner());
        let mut next: HashMap<String, Route> = HashMap::new();
        for (idx, e) in self.entries.iter().enumerate() {
            let mut st = e.lock();
            let mut specs = Vec::new();
            let mut skipped = Vec::new();
            let connected = st.client.as_ref().is_some_and(|c| !c.broken());
            if connected {
                for t in &st.listed {
                    match offer(&e.cfg, t, |n| next.contains_key(n)) {
                        Err(why) => skipped.push(format!("{}: {why}", t.name)),
                        Ok(spec) => {
                            next.insert(
                                spec.name.clone(),
                                Route {
                                    entry: idx,
                                    tool: t.clone(),
                                    spec: spec.clone(),
                                },
                            );
                            specs.push(spec);
                        }
                    }
                }
            }
            st.specs = specs;
            st.skipped = skipped;
        }
        *routes = next;
    }

    /// One maintenance pass: reconnect servers that are down (when their backoff has elapsed) and
    /// re-list servers whose tool list changed. Blocking (handshakes); the sidecar runs it on a
    /// background thread ([`McpHost::start_maintenance`]). Concurrent passes are serialised.
    pub fn maintain_now(&self) {
        let _guard = self.maintaining.lock().unwrap_or_else(|p| p.into_inner());
        if self.stopped.load(Ordering::SeqCst) {
            return;
        }
        let mut changed = false;
        for e in &self.entries {
            let (client, due) = {
                let st = e.lock();
                let due = st.next_retry.is_none_or(|t| Instant::now() >= t);
                (st.client.clone(), due)
            };
            match client {
                Some(c) if !c.broken() => {
                    if c.take_tools_changed() {
                        let listed = c.list_tools();
                        let mut st = e.lock();
                        match listed {
                            Ok(tools) => {
                                st.listed = tools;
                                st.relists += 1;
                                st.error = None;
                            }
                            Err(err) => {
                                st.error = Some(format!("re-reading its tools failed: {err}"));
                            }
                        }
                        changed = true;
                    }
                }
                down => {
                    if down.is_some() {
                        // Its tools go away at once; the dead connection is dropped.
                        let mut st = e.lock();
                        if st.client.take().is_some() {
                            st.failures = st.failures.max(1);
                            st.next_retry = Some(Instant::now() + backoff(st.failures));
                            st.error = Some("the server stopped; reconnecting".into());
                            changed = true;
                            continue;
                        }
                    }
                    if !due {
                        continue;
                    }
                    let connected = connect_and_list(&e.cfg);
                    let mut st = e.lock();
                    match connected {
                        Ok((client, tools)) => {
                            if st.was_ready {
                                st.reconnects += 1;
                            }
                            st.client = Some(Arc::new(client));
                            st.listed = tools;
                            st.error = None;
                            st.failures = 0;
                            st.next_retry = None;
                            st.was_ready = true;
                        }
                        Err(err) => {
                            st.failures = st.failures.saturating_add(1);
                            st.next_retry = Some(Instant::now() + backoff(st.failures));
                            st.error = Some(err.to_string());
                        }
                    }
                    changed = true;
                }
            }
        }
        if changed {
            self.rebuild();
        }
    }

    /// Run [`McpHost::maintain_now`] every `every` on a background thread for as long as the host
    /// is alive.
    pub fn start_maintenance(host: &Arc<McpHost>, every: Duration) {
        let weak: Weak<McpHost> = Arc::downgrade(host);
        std::thread::spawn(move || loop {
            std::thread::sleep(every);
            match weak.upgrade() {
                Some(h) => h.maintain_now(),
                None => break,
            }
        });
    }

    /// No server is configured.
    pub fn is_empty(&self) -> bool {
        self.entries.is_empty()
    }

    /// The tool specs offered to new sessions (host: sidecar; trust: untrusted).
    pub fn specs(&self) -> Vec<ToolSpec> {
        let _routes = self.routes.read().unwrap_or_else(|p| p.into_inner());
        self.entries
            .iter()
            .flat_map(|e| e.lock().specs.clone())
            .collect()
    }

    /// Whether `name` is an MCP tool this host offers now.
    pub fn handles(&self, name: &str) -> bool {
        self.routes
            .read()
            .unwrap_or_else(|p| p.into_inner())
            .contains_key(name)
    }

    /// Whether `name` is in the reserved MCP tool namespace.
    pub fn reserved(name: &str) -> bool {
        name.starts_with(TOOL_PREFIX)
    }

    /// Stop every server now (sidecar shutdown): stdio children are killed rather than left to
    /// the host being dropped. Idempotent; later calls report the server as gone.
    pub fn shutdown(&self) {
        self.stopped.store(true, Ordering::SeqCst);
        // Wait out a maintenance pass in progress, so it cannot reconnect a server after this.
        let _guard = self.maintaining.lock().unwrap_or_else(|p| p.into_inner());
        for e in &self.entries {
            let client = e.lock().client.clone();
            if let Some(c) = client {
                c.close();
            }
        }
    }

    pub fn status(&self) -> Vec<ServerStatus> {
        let now = Instant::now();
        self.entries
            .iter()
            .map(|e| {
                let st = e.lock();
                let client = st.client.as_ref();
                let state = match client {
                    None if st.was_ready => ServerState::Exited,
                    None => ServerState::Failed,
                    Some(c) if c.broken() => ServerState::Exited,
                    Some(_) => ServerState::Ready,
                };
                let info = client.map(|c| c.info());
                ServerStatus {
                    name: e.cfg.name.clone(),
                    transport: e.cfg.transport_kind(),
                    state,
                    protocol_version: info.map(|i| i.protocol_version.clone()),
                    era: info.map(|i| i.era),
                    server_name: info.map(|i| i.server_name.clone()),
                    capabilities: info.map(|i| i.capabilities.clone()),
                    tasks: info.is_some_and(|i| i.tasks()),
                    tools: st.specs.len(),
                    skipped: st.skipped.clone(),
                    error: st.error.clone(),
                    tools_changed: client.is_some_and(|c| c.tools_changed()),
                    bad_messages: client.map(|c| c.bad_messages()).unwrap_or(0),
                    allow_write_tools: e.cfg.allow_write_tools,
                    reconnects: st.reconnects,
                    relists: st.relists,
                    next_retry_ms: match (state, st.next_retry) {
                        (ServerState::Ready, _) => None,
                        (_, Some(t)) => Some(t.saturating_duration_since(now).as_millis() as u64),
                        (_, None) => Some(0),
                    },
                }
            })
            .collect()
    }

    /// Run one MCP tool call. Output is always untrusted: a result is
    /// [`ToolOutcome::Untrusted`], a tool-level error is [`ToolOutcome::Error`] (both taint the
    /// session through the spec's annotation).
    pub fn call(&self, call: &ToolCall, stop: &StopFlag) -> ToolOutcome {
        self.call_with(call, stop, &CallCtx::default())
    }

    /// [`McpHost::call`] with an elicitor and the session's offered spec.
    pub fn call_with(&self, call: &ToolCall, stop: &StopFlag, ctx: &CallCtx<'_>) -> ToolOutcome {
        let route = self
            .routes
            .read()
            .unwrap_or_else(|p| p.into_inner())
            .get(&call.name)
            .cloned();
        let Some(route) = route else {
            return match ctx.offered {
                Some(_) => ToolOutcome::Error(format!(
                    "'{}' is no longer offered by its MCP server (it was withdrawn or the server is reconnecting); start a new chat once it is back",
                    call.name
                )),
                None => ToolOutcome::Error(format!(
                    "'{}' is not an MCP tool offered in this session",
                    call.name
                )),
            };
        };
        if let Some(o) = ctx.offered {
            if *o != route.spec {
                return ToolOutcome::Error(format!(
                    "the MCP server changed '{}' since this chat started, so it is not run; start a new chat to use the new version",
                    call.name
                ));
            }
        }
        let Some(entry) = self.entries.get(route.entry) else {
            return ToolOutcome::Error("internal: MCP route without a server".into());
        };
        let server = &entry.cfg.name;
        let client = entry.lock().client.clone();
        let Some(client) = client else {
            return ToolOutcome::Error(format!(
                "MCP server '{server}' is not connected; it is reconnecting"
            ));
        };
        if stop.is_stopped() {
            return ToolOutcome::Error("stopped before the call was sent".into());
        }
        if client.broken() {
            return ToolOutcome::Error(format!(
                "MCP server '{server}' stopped answering and is reconnecting; try again shortly"
            ));
        }
        let args = match parse_args(&call.arguments) {
            Ok(v) => v,
            Err(e) => return ToolOutcome::Error(e),
        };
        let cap = entry.cfg.max_output_chars;
        let remote = &route.tool.name;
        let opts = CallOpts {
            elicitor: ctx.elicitor,
            tool: Some(&route.tool),
        };
        match client.call_tool_with(remote, args, stop, &opts) {
            Ok(r) if r.is_error => ToolOutcome::Error(fence(server, remote, &r.text, cap, true)),
            Ok(r) => ToolOutcome::Untrusted(fence(server, remote, &r.text, cap, false)),
            Err(e) => {
                let msg: String = e.to_string().chars().take(cap).collect();
                ToolOutcome::Error(format!("MCP server '{server}': {msg}"))
            }
        }
    }

    /// What the member is shown for `call`, or why it cannot be put in front of them.
    fn approval_for(&self, call: &ToolCall, reason: &str) -> Result<CallApproval, ToolOutcome> {
        let route = self
            .routes
            .read()
            .unwrap_or_else(|p| p.into_inner())
            .get(&call.name)
            .cloned()
            .ok_or_else(|| {
                ToolOutcome::Error(format!(
                    "'{}' is not an MCP tool offered in this session",
                    call.name
                ))
            })?;
        let args = parse_args(&call.arguments).map_err(ToolOutcome::Error)?;
        let arguments = serde_json::to_string(&args).unwrap_or_default();
        if arguments.len() > MAX_REVIEW_ARGS {
            return Err(ToolOutcome::Denied(format!(
                "the arguments are larger than {MAX_REVIEW_ARGS} bytes, too large to review on an approval card"
            )));
        }
        let server = self
            .entries
            .get(route.entry)
            .map(|e| e.cfg.name.clone())
            .unwrap_or_default();
        let a = &route.spec.annotations;
        Ok(CallApproval {
            call_id: call.id.clone(),
            tool: call.name.clone(),
            server,
            remote_tool: route.tool.name.clone(),
            arguments,
            read_only: a.read_only,
            destructive: a.destructive,
            idempotent: a.idempotent,
            open_world: a.open_world,
            reason: reason.to_string(),
        })
    }

    /// The [`ToolHost`] for one turn, bound to the session's stop flag (a raised flag cancels an
    /// in-flight call). Without an approver it cannot put a call in front of a person, so once a
    /// session is tainted the loop declines effectful MCP calls instead of dispatching them.
    pub fn tool_host(host: Arc<McpHost>, stop: StopFlag) -> Arc<dyn ToolHost> {
        Arc::new(McpToolHost::new(host, stop))
    }
}

fn parse_args(raw: &str) -> Result<Value, String> {
    let raw = if raw.trim().is_empty() { "{}" } else { raw };
    match serde_json::from_str(raw) {
        Ok(v @ Value::Object(_)) => Ok(v),
        _ => Err("MCP tool arguments must be a JSON object".to_string()),
    }
}

/// Bridges URL elicitation for one call to the session's approver.
struct AskMember<'a> {
    approver: &'a dyn McpApprover,
    call_id: &'a str,
    stop: &'a StopFlag,
}

impl Elicitor for AskMember<'_> {
    fn open_url(&self, req: &UrlElicitation) -> ElicitAction {
        if self.stop.is_stopped() {
            return ElicitAction::Cancel;
        }
        self.approver.open_url(self.call_id, req, self.stop)
    }
}

/// See [`McpHost::tool_host`].
pub struct McpToolHost {
    host: Arc<McpHost>,
    stop: StopFlag,
    /// The specs this session was offered (by exposed name).
    offered: Option<Arc<HashMap<String, ToolSpec>>>,
    approver: Option<Arc<dyn McpApprover>>,
}

impl McpToolHost {
    pub fn new(host: Arc<McpHost>, stop: StopFlag) -> Self {
        McpToolHost {
            host,
            stop,
            offered: None,
            approver: None,
        }
    }

    /// Bind to the specs the session was offered (calls to changed or withdrawn tools are
    /// refused).
    pub fn with_offered(mut self, offered: Arc<HashMap<String, ToolSpec>>) -> Self {
        self.offered = Some(offered);
        self
    }

    /// Put effectful calls after taint, and URL elicitations, in front of the member.
    pub fn with_approver(mut self, approver: Arc<dyn McpApprover>) -> Self {
        self.approver = Some(approver);
        self
    }

    pub fn handles(&self, name: &str) -> bool {
        match &self.offered {
            Some(o) => o.contains_key(name),
            None => self.host.handles(name),
        }
    }

    fn run(&self, call: &ToolCall) -> ToolOutcome {
        let ask = self.approver.as_deref().map(|approver| AskMember {
            approver,
            call_id: &call.id,
            stop: &self.stop,
        });
        let ctx = CallCtx {
            elicitor: ask.as_ref().map(|a| a as &dyn Elicitor),
            offered: self.offered.as_ref().and_then(|o| o.get(&call.name)),
        };
        self.host.call_with(call, &self.stop, &ctx)
    }
}

impl ToolHost for McpToolHost {
    fn execute(&self, call: &ToolCall) -> ToolOutcome {
        self.run(call)
    }

    fn honors_explicit_approval(&self) -> bool {
        self.approver.is_some()
    }

    /// After taint: the exact call (server, tool, canonical arguments, hints, reason) goes on an
    /// approval card; it runs only on the member's explicit allow, with the arguments shown.
    fn execute_with_explicit_approval(&self, call: &ToolCall, reason: &str) -> ToolOutcome {
        let Some(approver) = &self.approver else {
            return ToolOutcome::Denied("this action needs a member's explicit approval".into());
        };
        if !self.handles(&call.name) {
            return ToolOutcome::Denied("this action needs a member's explicit approval".into());
        }
        if let Some(o) = self.offered.as_ref().and_then(|o| o.get(&call.name)) {
            // Never ask about a tool whose current definition differs from the one offered.
            let current = self
                .host
                .routes
                .read()
                .unwrap_or_else(|p| p.into_inner())
                .get(&call.name)
                .map(|r| r.spec.clone());
            if current.as_ref() != Some(o) {
                return self.run(call);
            }
        }
        let req = match self.host.approval_for(call, reason) {
            Ok(r) => r,
            Err(outcome) => return outcome,
        };
        if let Err(why) = approver.approve_call(&req, &self.stop) {
            return ToolOutcome::Denied(why);
        }
        if self.stop.is_stopped() {
            return ToolOutcome::Denied("the session was stopped; nothing was sent".into());
        }
        let exact = ToolCall {
            id: call.id.clone(),
            name: call.name.clone(),
            arguments: req.arguments.clone(),
        };
        self.run(&exact)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn backoff_doubles_to_the_cap() {
        assert_eq!(backoff(1), Duration::from_secs(1));
        assert_eq!(backoff(2), Duration::from_secs(2));
        assert_eq!(backoff(4), Duration::from_secs(8));
        assert_eq!(backoff(9), RECONNECT_BACKOFF_CAP);
        assert_eq!(backoff(u32::MAX), RECONNECT_BACKOFF_CAP);
    }
}
