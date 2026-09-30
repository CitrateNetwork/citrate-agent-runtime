//! # citrate-agent-loop — Hermes's turn loop (HUP-S1.1a)
//!
//! "Brain in the sidecar, hands in core" (citrate-core ADR-2026-09-30-hermes-loop-in-sidecar):
//! this crate owns the loop — messages, bounded steps, tool dispatch, stop, and a typed event
//! stream — and nothing else. The model and every tool are injected ([`LlmClient`],
//! [`ToolHost`]), so the loop's properties are tested offline:
//!
//! - **Bounded:** at most `max_steps` model calls per turn, `max_tool_calls_per_step` tool runs.
//! - **Stoppable:** the [`StopFlag`] is checked before every model call and every tool run.
//! - **Honest outcome:** [`RunOutcome::Answered`] means the model produced a final message — NOT
//!   that the task succeeded. Success is a verifier's call (S1.3), never the model's.
//! - **Hands stay where the gates are:** a tool's [`HostKind`] routes it to the host that owns its
//!   capability. Core-hosted tools run through citrate-core's approval gates; this crate never
//!   signs, never holds a key, and never decides an approval.
//! - **Robust to small models:** unknown tools, malformed argument JSON, missing hosts and
//!   over-long tool batches become tool *results* the model can recover from, never panics.

use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;

// ---------------------------------------------------------------------------------------------
// Messages and tools
// ---------------------------------------------------------------------------------------------

/// A chat role (OpenAI-compatible).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum Role {
    System,
    User,
    Assistant,
    Tool,
}

/// One tool invocation proposed by the model. `arguments` is the raw JSON string it emitted.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ToolCall {
    pub id: String,
    pub name: String,
    pub arguments: String,
}

/// One message in the transcript.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Message {
    pub role: Role,
    pub content: String,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub tool_calls: Vec<ToolCall>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub tool_call_id: Option<String>,
}

impl Message {
    pub fn system(content: impl Into<String>) -> Self {
        Message {
            role: Role::System,
            content: content.into(),
            tool_calls: vec![],
            tool_call_id: None,
        }
    }
    pub fn user(content: impl Into<String>) -> Self {
        Message {
            role: Role::User,
            content: content.into(),
            tool_calls: vec![],
            tool_call_id: None,
        }
    }
    pub fn tool_result(call_id: &str, content: impl Into<String>) -> Self {
        Message {
            role: Role::Tool,
            content: content.into(),
            tool_calls: vec![],
            tool_call_id: Some(call_id.to_string()),
        }
    }
}

/// Where a tool's capability lives (ADR: brain in the sidecar, hands where the capability is).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum HostKind {
    /// Executed by citrate-core through its existing approval gates (memory, node, wallet, groups…).
    Core,
    /// Executed inside the sidecar under its own grants and ApprovalQueue (capsules; fs/shell/browser later).
    Sidecar,
}

/// MCP-style tool annotations. Hints for the approval UI and for HIC routing; never enforcement
/// on their own (the host enforces).
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(default)]
pub struct ToolAnnotations {
    pub read_only: bool,
    pub destructive: bool,
    pub idempotent: bool,
    pub open_world: bool,
}

/// A tool offered to the model.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct ToolSpec {
    pub name: String,
    pub description: String,
    /// JSON schema of the arguments.
    pub parameters: serde_json::Value,
    pub host: HostKind,
    #[serde(default)]
    pub annotations: ToolAnnotations,
}

/// What a host returns for one tool call. Every variant becomes a tool message the model sees.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ToolOutcome {
    /// The tool ran; its (possibly fenced) output.
    Ok(String),
    /// A human (or policy) declined the effect — nothing happened.
    Denied(String),
    /// The tool failed.
    Error(String),
}

impl ToolOutcome {
    fn to_content(&self) -> String {
        match self {
            ToolOutcome::Ok(s) => s.clone(),
            ToolOutcome::Denied(why) => format!("declined: {why}. Nothing was done."),
            ToolOutcome::Error(e) => format!("tool error: {e}"),
        }
    }
    fn status(&self) -> &'static str {
        match self {
            ToolOutcome::Ok(_) => "ok",
            ToolOutcome::Denied(_) => "denied",
            ToolOutcome::Error(_) => "error",
        }
    }
}

/// Executes tool calls for one [`HostKind`]. A core host typically suspends until citrate-core
/// posts the result back (S1.1b); that is invisible to the loop.
pub trait ToolHost: Send + Sync {
    fn execute(&self, call: &ToolCall) -> ToolOutcome;
}

/// The tools on offer plus the host that runs each kind.
pub struct ToolRegistry {
    specs: Vec<ToolSpec>,
    hosts: HashMap<HostKind, Arc<dyn ToolHost>>,
}

impl ToolRegistry {
    pub fn new(specs: Vec<ToolSpec>) -> Self {
        ToolRegistry {
            specs,
            hosts: HashMap::new(),
        }
    }
    /// Register the host for a kind (builder).
    pub fn with_host(mut self, kind: HostKind, host: Arc<dyn ToolHost>) -> Self {
        self.hosts.insert(kind, host);
        self
    }
    pub fn specs(&self) -> &[ToolSpec] {
        &self.specs
    }
    fn spec(&self, name: &str) -> Option<&ToolSpec> {
        self.specs.iter().find(|s| s.name == name)
    }
    fn host(&self, kind: HostKind) -> Option<&Arc<dyn ToolHost>> {
        self.hosts.get(&kind)
    }
}

// ---------------------------------------------------------------------------------------------
// The model
// ---------------------------------------------------------------------------------------------

/// One chat-completions request (OpenAI-compatible shape; the client maps it to the wire).
#[derive(Debug, Clone, PartialEq, Serialize)]
pub struct CompletionRequest {
    pub model: String,
    pub messages: Vec<Message>,
    pub tools: Vec<ToolSpec>,
    pub max_tokens: u32,
}

/// The assistant's reply: final text and/or tool calls.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AssistantTurn {
    pub content: String,
    pub tool_calls: Vec<ToolCall>,
}

impl AssistantTurn {
    pub fn text(s: impl Into<String>) -> Self {
        AssistantTurn {
            content: s.into(),
            tool_calls: vec![],
        }
    }
    pub fn tools(calls: Vec<ToolCall>) -> Self {
        AssistantTurn {
            content: String::new(),
            tool_calls: calls,
        }
    }
}

/// A model failure. Coarse on purpose: never carries the endpoint, key or request body.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum LlmError {
    Transport(String),
    Provider(String),
    BadResponse(String),
}

impl std::fmt::Display for LlmError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            LlmError::Transport(m) => write!(f, "model transport error: {m}"),
            LlmError::Provider(m) => write!(f, "model provider error: {m}"),
            LlmError::BadResponse(m) => write!(f, "model returned an unusable response: {m}"),
        }
    }
}

/// The model seam (production: an OpenAI-compatible client over loopback llama-server or the
/// configured gateway; tests: a script).
pub trait LlmClient: Send + Sync {
    fn complete(&self, req: &CompletionRequest) -> Result<AssistantTurn, LlmError>;
}

// ---------------------------------------------------------------------------------------------
// Events, stop, config, outcome
// ---------------------------------------------------------------------------------------------

/// The typed event stream every client (webview, CLI, MCP) renders.
#[derive(Debug, Clone, PartialEq, Serialize)]
#[serde(tag = "type", rename_all = "snake_case")]
pub enum Event {
    StepStart {
        step: u32,
    },
    ToolCall {
        step: u32,
        call: ToolCall,
        host: Option<HostKind>,
    },
    ToolResult {
        step: u32,
        call_id: String,
        status: &'static str,
        content: String,
    },
    StepEnd {
        step: u32,
    },
    Final {
        content: String,
    },
    Error {
        message: String,
    },
    Done {
        outcome: String,
    },
}

impl Event {
    /// The wire tag (also used by tests and the SSE `event:` field).
    pub fn kind(&self) -> &'static str {
        match self {
            Event::StepStart { .. } => "step_start",
            Event::ToolCall { .. } => "tool_call",
            Event::ToolResult { .. } => "tool_result",
            Event::StepEnd { .. } => "step_end",
            Event::Final { .. } => "final",
            Event::Error { .. } => "error",
            Event::Done { .. } => "done",
        }
    }
}

/// Where events go (SSE broadcaster in the sidecar; a Vec in tests).
pub trait EventSink: Send + Sync {
    fn emit(&self, ev: Event);
}

/// A shared, one-way stop switch.
#[derive(Debug, Clone, Default)]
pub struct StopFlag(Arc<AtomicBool>);

impl StopFlag {
    pub fn stop(&self) {
        self.0.store(true, Ordering::SeqCst);
    }
    pub fn is_stopped(&self) -> bool {
        self.0.load(Ordering::SeqCst)
    }
}

/// Per-session loop configuration.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct LoopConfig {
    pub model: String,
    pub system_prompt: String,
    pub max_steps: u32,
    pub max_tool_calls_per_step: u32,
    pub max_tokens: u32,
}

/// How a turn ended. `Answered` is "the model produced a final message", not "the task succeeded".
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum RunOutcome {
    Answered(String),
    Stopped,
    StepLimit,
    Failed(String),
}

impl RunOutcome {
    fn label(&self) -> String {
        match self {
            RunOutcome::Answered(_) => "answered".into(),
            RunOutcome::Stopped => "stopped".into(),
            RunOutcome::StepLimit => "step_limit".into(),
            RunOutcome::Failed(_) => "failed".into(),
        }
    }
}

// ---------------------------------------------------------------------------------------------
// The loop
// ---------------------------------------------------------------------------------------------

fn finish(sink: &dyn EventSink, outcome: RunOutcome) -> RunOutcome {
    sink.emit(Event::Done {
        outcome: outcome.label(),
    });
    outcome
}

/// Run one user turn with the defaults (every tool offered, no context budget).
pub fn run_turn(
    cfg: &LoopConfig,
    llm: &dyn LlmClient,
    tools: &ToolRegistry,
    sink: &dyn EventSink,
    stop: &StopFlag,
    history: &mut Vec<Message>,
    user: &str,
) -> RunOutcome {
    run_turn_with(
        cfg,
        &TurnOptions::default(),
        llm,
        tools,
        sink,
        stop,
        history,
        user,
    )
}

/// Run one user turn to completion (answer, stop, step limit, or failure), appending the user
/// message, assistant messages and tool results to `history`. `opts` bounds how many tool schemas
/// are offered per request (HUP-S1.2 tool retrieval) and keeps the prompt within the model's
/// context (compaction that must shrink, or an honest failure — never an overflow).
#[allow(clippy::too_many_arguments)]
pub fn run_turn_with(
    cfg: &LoopConfig,
    opts: &TurnOptions,
    llm: &dyn LlmClient,
    tools: &ToolRegistry,
    sink: &dyn EventSink,
    stop: &StopFlag,
    history: &mut Vec<Message>,
    user: &str,
) -> RunOutcome {
    history.push(Message::user(user));
    for step in 1..=cfg.max_steps {
        if stop.is_stopped() {
            return finish(sink, RunOutcome::Stopped);
        }
        sink.emit(Event::StepStart { step });
        let mut messages = Vec::with_capacity(history.len() + 1);
        messages.push(Message::system(cfg.system_prompt.clone()));
        messages.extend(history.iter().cloned());
        let offered = offered_tools(tools.specs(), history, user, opts.max_tools_per_request);
        if let Some((budget, counter)) = &opts.budget {
            let tool_tokens = counter.count(&serde_json::to_string(&offered).unwrap_or_default());
            let inner = ContextBudget {
                max_context_tokens: budget.max_context_tokens.saturating_sub(tool_tokens),
                reserve_for_output: budget.reserve_for_output,
            };
            match compact_to_budget(&messages, &inner, counter.as_ref()) {
                Ok(m) => messages = m,
                Err(e) => {
                    sink.emit(Event::Error { message: e.clone() });
                    return finish(sink, RunOutcome::Failed(e));
                }
            }
        }
        let req = CompletionRequest {
            model: cfg.model.clone(),
            messages,
            tools: offered,
            max_tokens: cfg.max_tokens,
        };
        let turn = match llm.complete(&req) {
            Ok(t) => t,
            Err(e) => {
                let msg = e.to_string();
                sink.emit(Event::Error {
                    message: msg.clone(),
                });
                return finish(sink, RunOutcome::Failed(msg));
            }
        };
        history.push(Message {
            role: Role::Assistant,
            content: turn.content.clone(),
            tool_calls: turn.tool_calls.clone(),
            tool_call_id: None,
        });
        if turn.tool_calls.is_empty() {
            sink.emit(Event::Final {
                content: turn.content.clone(),
            });
            return finish(sink, RunOutcome::Answered(turn.content));
        }
        for (i, call) in turn.tool_calls.iter().enumerate() {
            if stop.is_stopped() {
                return finish(sink, RunOutcome::Stopped);
            }
            let spec = tools.spec(&call.name);
            sink.emit(Event::ToolCall {
                step,
                call: call.clone(),
                host: spec.map(|s| s.host),
            });
            let outcome = if i as u32 >= cfg.max_tool_calls_per_step {
                ToolOutcome::Error(format!(
                    "skipped: at most {} tool calls per step — call it again next step if still needed",
                    cfg.max_tool_calls_per_step
                ))
            } else {
                match spec {
                    None => ToolOutcome::Error(format!("unknown tool '{}'", call.name)),
                    Some(s) => {
                        if serde_json::from_str::<serde_json::Value>(
                            if call.arguments.trim().is_empty() {
                                "{}"
                            } else {
                                &call.arguments
                            },
                        )
                        .is_err()
                        {
                            ToolOutcome::Error(
                                "the arguments were not valid JSON; retry with a JSON object"
                                    .into(),
                            )
                        } else {
                            match tools.host(s.host) {
                                Some(h) => h.execute(call),
                                None => ToolOutcome::Error(format!(
                                    "'{}' is not available in this session",
                                    call.name
                                )),
                            }
                        }
                    }
                }
            };
            let content = outcome.to_content();
            sink.emit(Event::ToolResult {
                step,
                call_id: call.id.clone(),
                status: outcome.status(),
                content: content.clone(),
            });
            history.push(Message::tool_result(&call.id, content));
        }
        sink.emit(Event::StepEnd { step });
    }
    sink.emit(Event::Error {
        message: format!("step budget of {} exhausted", cfg.max_steps),
    });
    finish(sink, RunOutcome::StepLimit)
}

// ---------------------------------------------------------------------------------------------
// HUP-S1.2 — tool retrieval and the context budget
// ---------------------------------------------------------------------------------------------

/// Per-turn options beyond [`LoopConfig`].
#[derive(Clone, Default)]
pub struct TurnOptions {
    /// Offer at most this many tool schemas per model request (plus any tool already used this
    /// conversation). `None` offers every tool.
    pub max_tools_per_request: Option<usize>,
    /// Keep each request within this budget, counted with this counter.
    pub budget: Option<(ContextBudget, Arc<dyn TokenCounter>)>,
}

/// Chooses which tool schemas to offer for a query. Tool schemas are the largest fixed cost in a
/// small model's context, so only the relevant ones go in each request.
pub trait ToolSelector: Send + Sync {
    fn select(&self, query: &str, specs: &[ToolSpec], k: usize) -> Vec<ToolSpec>;
}

/// Deterministic keyword scorer over tool names (weighted) and descriptions. Snake_case names are
/// split into words. With no signal at all it falls back to the first `k` tools in catalog order.
/// (An embedding selector can implement the same trait once the knowledge graph is bundled.)
#[derive(Debug, Clone, Copy, Default)]
pub struct KeywordSelector;

const STOPWORDS: &[&str] = &[
    "a", "an", "the", "and", "or", "to", "of", "in", "on", "for", "my", "me", "i", "is", "are",
    "it", "its", "this", "that", "what", "whats", "how", "many", "much", "do", "does", "can",
    "you", "please", "with", "from", "at", "by", "be",
];

fn words(s: &str) -> Vec<String> {
    s.to_lowercase()
        .split(|c: char| !c.is_ascii_alphanumeric())
        .filter(|w| w.len() >= 2 && !STOPWORDS.contains(w))
        .map(|w| {
            if w.len() > 3 && w.ends_with('s') && !w.ends_with("ss") {
                w[..w.len() - 1].to_string()
            } else {
                w.to_string()
            }
        })
        .collect()
}

impl ToolSelector for KeywordSelector {
    fn select(&self, query: &str, specs: &[ToolSpec], k: usize) -> Vec<ToolSpec> {
        let q = words(query);
        let mut scored: Vec<(usize, usize)> = specs
            .iter()
            .enumerate()
            .map(|(i, s)| {
                let name = words(&s.name);
                let desc = words(&s.description);
                let score = q
                    .iter()
                    .map(|w| {
                        3 * name.iter().filter(|n| *n == w).count()
                            + desc.iter().filter(|d| *d == w).count()
                    })
                    .sum();
                (i, score)
            })
            .collect();
        if scored.iter().all(|(_, sc)| *sc == 0) {
            return specs.iter().take(k).cloned().collect();
        }
        scored.sort_by(|a, b| b.1.cmp(&a.1).then(a.0.cmp(&b.0)));
        scored
            .into_iter()
            .filter(|(_, sc)| *sc > 0)
            .take(k)
            .map(|(i, _)| specs[i].clone())
            .collect()
    }
}

fn offered_tools(
    specs: &[ToolSpec],
    history: &[Message],
    user: &str,
    k: Option<usize>,
) -> Vec<ToolSpec> {
    let Some(k) = k else { return specs.to_vec() };
    let in_use: Vec<&str> = history
        .iter()
        .flat_map(|m| m.tool_calls.iter().map(|c| c.name.as_str()))
        .collect();
    let mut out: Vec<ToolSpec> = specs
        .iter()
        .filter(|s| in_use.contains(&s.name.as_str()))
        .cloned()
        .collect();
    for s in KeywordSelector.select(user, specs, k) {
        if out.len() >= k.max(in_use.len()) {
            break;
        }
        if !out.iter().any(|o| o.name == s.name) {
            out.push(s);
        }
    }
    out
}

/// Counts tokens. Production should use the model's own tokenizer (llama-server `/tokenize`); the
/// character heuristic is a conservative default.
pub trait TokenCounter: Send + Sync {
    fn count(&self, s: &str) -> usize;
    fn count_messages(&self, msgs: &[Message]) -> usize {
        msgs.iter()
            .map(|m| {
                4 + self.count(&m.content)
                    + m.tool_calls
                        .iter()
                        .map(|c| self.count(&c.name) + self.count(&c.arguments))
                        .sum::<usize>()
            })
            .sum()
    }
}

/// About four characters per token, rounded up.
#[derive(Debug, Clone, Copy, Default)]
pub struct CharTokenCounter;

impl TokenCounter for CharTokenCounter {
    fn count(&self, s: &str) -> usize {
        s.chars().count().div_ceil(4)
    }
}

/// The model's context window and the room reserved for its reply.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ContextBudget {
    pub max_context_tokens: usize,
    pub reserve_for_output: usize,
}

/// Fit `msgs` into `budget`: first elide old tool output (oldest first), then drop the oldest
/// exchanges — never the system prompt or the latest user message, and never leaving an orphaned
/// tool result. Compaction must shrink the prompt; if it still cannot fit, that is an error.
pub fn compact_to_budget(
    msgs: &[Message],
    budget: &ContextBudget,
    counter: &dyn TokenCounter,
) -> Result<Vec<Message>, String> {
    let limit = budget
        .max_context_tokens
        .saturating_sub(budget.reserve_for_output);
    let fits = |m: &[Message]| counter.count_messages(m) <= limit;
    if fits(msgs) {
        return Ok(msgs.to_vec());
    }
    let before = counter.count_messages(msgs);
    let mut out = msgs.to_vec();
    let last_user = out
        .iter()
        .rposition(|m| m.role == Role::User)
        .unwrap_or(out.len().saturating_sub(1));
    for i in 0..last_user {
        if out[i].role == Role::Tool && !out[i].content.starts_with("[elided") {
            let n = out[i].content.chars().count();
            out[i].content = format!("[elided: {n} characters of earlier tool output]");
            if fits(&out) {
                break;
            }
        }
    }
    while !fits(&out) {
        let last_user = out.iter().rposition(|m| m.role == Role::User).unwrap_or(0);
        if last_user <= 1 || out.len() <= 2 {
            break;
        }
        out.remove(1);
        while out.len() > 2 && out[1].role == Role::Tool {
            out.remove(1);
        }
    }
    if !fits(&out) || counter.count_messages(&out) >= before {
        return Err(format!(
            "the prompt exceeds the model's context budget ({} tokens available) even after compaction",
            limit
        ));
    }
    Ok(out)
}
