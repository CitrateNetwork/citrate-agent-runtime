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

/// Run one user turn to completion (answer, stop, step limit, or failure), appending the user
/// message, assistant messages and tool results to `history`.
pub fn run_turn(
    cfg: &LoopConfig,
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
        let req = CompletionRequest {
            model: cfg.model.clone(),
            messages,
            tools: tools.specs().to_vec(),
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
