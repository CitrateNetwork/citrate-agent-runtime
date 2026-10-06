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
//! - **Taint downgrade (HUP-S2.7):** once the session has ingested untrusted content, every
//!   effectful tool call needs an explicit member decision (no auto-approval, no budget path) for
//!   the rest of the session, unless a member clears it ([`TaintState`]; TLA+
//!   `formal/TaintDowngrade.tla`).
//! - **System-1 slot (HUP-S5.3):** [`decide`] makes one typed choice from a fixed option set, on
//!   the local model by default (grammar-constrained), with the TypeSafe Jev backend only on the
//!   member's per-origin opt-in (TLA+ `formal/DecideEgress.tla`).

use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Mutex};

pub mod decide;
pub mod deploy_guard;
pub mod interview;
pub mod personas;
pub mod planner;
pub mod retrieval;
pub mod skills;
pub mod verifiers_tooling;
pub mod workflows;

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

/// What running a tool can change (HUP-S2.7). An unannotated tool is treated as effectful.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum Effect {
    /// Reads only; changes nothing anywhere.
    None,
    /// Changes local or remote state (files, memory, messages, config…).
    Write,
    /// Moves value (SALT, gas, x402, faucet…).
    Spend,
    /// Asks for a signature (always through core's SignatureCeremony, never here).
    Sign,
}

/// Whether a tool's output can be trusted as instructions-free context (HUP-S2.7). Web pages, MCP
/// output, third-party skill bodies and files outside granted folders are untrusted. An
/// unannotated tool's output is treated as untrusted.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum Trust {
    Trusted,
    Untrusted,
}

/// MCP-style tool annotations. The first four are hints for the approval UI; `effect` and `trust`
/// drive the taint downgrade, and both default to the safe side when absent (effectful,
/// untrusted). The host still enforces its own gates.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(default)]
pub struct ToolAnnotations {
    pub read_only: bool,
    pub destructive: bool,
    pub idempotent: bool,
    pub open_world: bool,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub effect: Option<Effect>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub trust: Option<Trust>,
}

impl ToolAnnotations {
    /// True unless the tool is explicitly annotated `effect: none`.
    pub fn is_effectful(&self) -> bool {
        self.effect != Some(Effect::None)
    }
    /// True unless the tool is explicitly annotated `trust: trusted`.
    pub fn output_untrusted(&self) -> bool {
        self.trust != Some(Trust::Trusted)
    }
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
    /// The tool ran, but this particular output is untrusted whatever the tool's annotation says
    /// (e.g. a file read that resolved outside the granted folders). Taints the session.
    Untrusted(String),
    /// A human (or policy) declined the effect — nothing happened.
    Denied(String),
    /// The tool failed.
    Error(String),
}

impl ToolOutcome {
    fn to_content(&self) -> String {
        match self {
            ToolOutcome::Ok(s) | ToolOutcome::Untrusted(s) => s.clone(),
            ToolOutcome::Denied(why) => format!("declined: {why}. Nothing was done."),
            ToolOutcome::Error(e) => format!("tool error: {e}"),
        }
    }
    fn status(&self) -> &'static str {
        match self {
            ToolOutcome::Ok(_) | ToolOutcome::Untrusted(_) => "ok",
            ToolOutcome::Denied(_) => "denied",
            ToolOutcome::Error(_) => "error",
        }
    }
}

/// Executes tool calls for one [`HostKind`]. A core host typically suspends until citrate-core
/// posts the result back (S1.1b); that is invisible to the loop.
///
/// After taint (HUP-S2.7) an effectful call needs an explicit member decision. A host that can
/// guarantee that — every such call goes to a person, with no auto-approval and no budget path —
/// says so with [`ToolHost::honors_explicit_approval`] and receives the call through
/// [`ToolHost::execute_with_explicit_approval`]. Hosts that cannot are never handed such a call:
/// the loop declines it instead (fail closed).
pub trait ToolHost: Send + Sync {
    fn execute(&self, call: &ToolCall) -> ToolOutcome;
    /// Called once for a call the loop is about to dispatch to this host, before the `tool_call`
    /// event announces it; [`ToolHost::execute`] (or [`ToolHost::execute_with_explicit_approval`])
    /// follows immediately after the event. A host that is answered from outside (core reads the
    /// event and posts the result) registers the call here, so an answer sent the moment the event
    /// is visible always finds it waiting. The default does nothing.
    fn before_announce(&self, call: &ToolCall) {
        let _ = call;
    }
    /// Whether this host routes explicit-approval calls to a person with no automatic path.
    fn honors_explicit_approval(&self) -> bool {
        false
    }
    /// Run a call that must be decided by a person. Only called when
    /// [`ToolHost::honors_explicit_approval`] is true; the default declines.
    fn execute_with_explicit_approval(&self, call: &ToolCall, reason: &str) -> ToolOutcome {
        let _ = (call, reason);
        ToolOutcome::Denied("this action needs a member's explicit approval".into())
    }
}

/// The record of what tainted a session.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct TaintRecord {
    /// The tool whose output brought untrusted content in.
    pub source: String,
    pub reason: String,
}

/// A member's explicit decision to clear a session's taint. It carries the member's note so the
/// decision is never empty; only a member-facing surface should construct one.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct MemberClear {
    note: String,
}

impl MemberClear {
    /// `None` for an empty note.
    pub fn new(note: impl Into<String>) -> Option<Self> {
        let note = note.into();
        if note.trim().is_empty() {
            None
        } else {
            Some(MemberClear { note })
        }
    }
    pub fn note(&self) -> &str {
        &self.note
    }
}

/// The inside of a [`TaintState`]: the first source (what the member is shown) and every source
/// since (HUP-S2.3: the budgeted sign-in path must see all of them, not only the first).
#[derive(Debug, Default)]
struct TaintInner {
    record: Option<TaintRecord>,
    sources: std::collections::BTreeSet<String>,
}

/// A session's taint (HUP-S2.7). Clones share one state, so it survives across steps, turns and
/// rebuilt registries. Monotone: once set it stays set until [`TaintState::clear_by_member`].
/// A poisoned lock reads as tainted (fail closed).
#[derive(Debug, Clone, Default)]
pub struct TaintState(Arc<Mutex<TaintInner>>);

impl TaintState {
    pub fn is_tainted(&self) -> bool {
        self.0.lock().map(|g| g.record.is_some()).unwrap_or(true)
    }
    /// The taint record. Agrees with [`TaintState::is_tainted`]: a poisoned lock yields a record
    /// even if none was written (fail closed), since `run_turn_with` gates on this.
    pub fn record(&self) -> Option<TaintRecord> {
        match self.0.lock() {
            Ok(g) => g.record.clone(),
            Err(p) => Some(
                p.into_inner()
                    .record
                    .clone()
                    .unwrap_or_else(|| TaintRecord {
                        source: "an unknown source".to_string(),
                        reason: "the session's taint state could not be read".to_string(),
                    }),
            ),
        }
    }
    /// Every tool that has brought untrusted content into this session since it was last clean,
    /// sorted and without repeats. `None` when the state cannot be read (callers treat that as
    /// "unknown", which is tainted).
    pub fn sources(&self) -> Option<Vec<String>> {
        self.0
            .lock()
            .ok()
            .map(|g| g.sources.iter().cloned().collect())
    }
    /// Mark the session tainted by `source`. Every source is remembered; returns true only when
    /// this call flipped the session to tainted (the first source is kept as the record).
    pub fn taint(&self, source: &str, reason: &str) -> bool {
        let mut g = match self.0.lock() {
            Ok(g) => g,
            Err(p) => p.into_inner(),
        };
        g.sources.insert(source.to_string());
        if g.record.is_some() {
            return false;
        }
        g.record = Some(TaintRecord {
            source: source.to_string(),
            reason: reason.to_string(),
        });
        true
    }
    /// The only way a taint is cleared: an explicit member action. Returns what was cleared.
    pub fn clear_by_member(&self, ack: MemberClear) -> Option<TaintRecord> {
        let _ = ack;
        let mut g = match self.0.lock() {
            Ok(g) => g,
            Err(p) => p.into_inner(),
        };
        g.sources.clear();
        g.record.take()
    }
}

/// The tools on offer plus the host that runs each kind.
pub struct ToolRegistry {
    specs: Vec<ToolSpec>,
    hosts: HashMap<HostKind, Arc<dyn ToolHost>>,
    taint: TaintState,
    policies: Vec<Arc<dyn CallPolicy>>,
}

/// A policy that may decline a call before the loop announces or dispatches it (HUP-S6 US-6.2:
/// the sidecar's deploy guard). A declined call reaches no host: its `tool_call` event names no
/// host, so a remote host acting on those events (core) never runs it, and the model reads the
/// reason as a declined result. A policy only ever takes calls away; it never runs one.
pub trait CallPolicy: Send + Sync {
    /// `Some(reason)` declines `call`.
    fn decline(&self, call: &ToolCall) -> Option<String>;
}

impl ToolRegistry {
    pub fn new(specs: Vec<ToolSpec>) -> Self {
        ToolRegistry {
            specs,
            hosts: HashMap::new(),
            taint: TaintState::default(),
            policies: Vec::new(),
        }
    }
    /// Add a call policy (builder). Every policy is asked; the first decline wins.
    pub fn with_policy(mut self, policy: Arc<dyn CallPolicy>) -> Self {
        self.policies.push(policy);
        self
    }
    /// The first policy's reason to decline `call`, if any.
    pub fn declined(&self, call: &ToolCall) -> Option<String> {
        self.policies.iter().find_map(|p| p.decline(call))
    }
    /// Share a session's taint state (builder). A fresh registry starts untainted.
    pub fn with_taint(mut self, taint: TaintState) -> Self {
        self.taint = taint;
        self
    }
    /// This session's taint state.
    pub fn taint(&self) -> &TaintState {
        &self.taint
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

    /// HUP-S7.5: [`LlmClient::complete`] plus the token usage the provider reported for this
    /// call. The default reports none: a client that cannot see usage says "unknown", never zero.
    fn complete_with_usage(
        &self,
        req: &CompletionRequest,
    ) -> Result<(AssistantTurn, Option<TokenUsage>), LlmError> {
        self.complete(req).map(|t| (t, None))
    }

    /// HUP-S1.1 (g1-render): [`LlmClient::complete_with_usage`] that also hands each piece of
    /// assistant text to `on_delta` as the provider produces it. The returned turn is the whole
    /// answer, exactly as the non-streaming call would return it. The default produces no deltas:
    /// a client that cannot stream behaves as before.
    fn complete_streaming(
        &self,
        req: &CompletionRequest,
        on_delta: &mut dyn FnMut(&str),
    ) -> Result<(AssistantTurn, Option<TokenUsage>), LlmError> {
        let _ = on_delta;
        self.complete_with_usage(req)
    }
}

/// HUP-S1.1 (g1-render): batches streamed assistant text into `assistant_delta` events, so a long
/// answer becomes tens of events, not one per token (the session event log is bounded).
pub struct DeltaCoalescer {
    step: u32,
    buf: String,
    last: std::time::Instant,
}

impl DeltaCoalescer {
    /// Bytes buffered before an event is emitted.
    pub const MAX_BYTES: usize = 64;
    /// Longest a piece of text waits before it is emitted.
    pub const MAX_WAIT: std::time::Duration = std::time::Duration::from_millis(50);

    pub fn new(step: u32) -> Self {
        DeltaCoalescer {
            step,
            buf: String::new(),
            last: std::time::Instant::now(),
        }
    }

    /// Add streamed text; emits when enough text is waiting or it has waited long enough.
    pub fn push(&mut self, sink: &dyn EventSink, text: &str) {
        if text.is_empty() {
            return;
        }
        self.buf.push_str(text);
        if self.buf.len() >= Self::MAX_BYTES || self.last.elapsed() >= Self::MAX_WAIT {
            self.flush(sink);
        }
    }

    /// Emit whatever is waiting.
    pub fn flush(&mut self, sink: &dyn EventSink) {
        if self.buf.is_empty() {
            return;
        }
        sink.emit(Event::AssistantDelta {
            step: self.step,
            text: std::mem::take(&mut self.buf),
        });
        self.last = std::time::Instant::now();
    }
}

/// Token usage one model call reported (HUP-S7.5 metering). Taken from the provider's own
/// response; nothing here is estimated.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
pub struct TokenUsage {
    pub prompt_tokens: u64,
    pub completion_tokens: u64,
    /// HUP-S7.6: how long the provider spent generating the completion, in milliseconds, when it
    /// reports that (llama-server's `timings.predicted_ms`). `None` when it does not: tokens per
    /// second is then unknown, never guessed.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub generation_ms: Option<u64>,
    /// HUP-S7.5 (D-27): how long the provider spent reading the prompt before it wrote the first
    /// token, in milliseconds, when it reports that (llama-server's `timings.prompt_ms`). This is
    /// the server's time to first token. `None` when it does not report it: unknown, never guessed.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub prompt_ms: Option<u64>,
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
    /// `host` is `None` when the call is not dispatched to any host (no such tool, or a call that
    /// needs explicit approval its host cannot ask for). `hic: "required"` marks a call that needs
    /// a member's explicit decision because the session is tainted; absent otherwise.
    ToolCall {
        step: u32,
        call: ToolCall,
        host: Option<HostKind>,
        #[serde(skip_serializing_if = "Option::is_none")]
        hic: Option<&'static str>,
        #[serde(skip_serializing_if = "Option::is_none")]
        hic_reason: Option<String>,
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
    /// HUP-S2.7: the session just became tainted by `source`'s output. Emitted once per flip.
    Tainted {
        step: u32,
        source: String,
        reason: String,
    },
    /// HUP-S1.1 (g1-render): a piece of the assistant's text while the model is still writing.
    /// Informational only: the step's `final` event (when the step answers) carries the whole
    /// answer, and a step that ends in tool calls has no `final`.
    AssistantDelta {
        step: u32,
        text: String,
    },
    Final {
        content: String,
    },
    /// HUP-S7.6 (US-7.4 AC1): the token usage the provider reported for the model call of `step`.
    /// Emitted only when the provider reported usage; a call without it emits nothing (unknown,
    /// never zero).
    Usage {
        step: u32,
        prompt_tokens: u64,
        completion_tokens: u64,
        #[serde(skip_serializing_if = "Option::is_none")]
        generation_ms: Option<u64>,
        /// HUP-S7.5 (D-27): the server's time to first token (llama-server `timings.prompt_ms`).
        #[serde(skip_serializing_if = "Option::is_none")]
        prompt_ms: Option<u64>,
    },
    /// HUP-S7.6 (US-7.4 AC1): a workflow run's plan, emitted once before its first step: the step
    /// ids in the order they run. Verifier events then report each step's verdicts.
    Plan {
        steps: Vec<String>,
    },
    /// HUP-S1.3: one verifier's verdict on a workflow step attempt.
    Verifier {
        step: String,
        name: String,
        passed: bool,
        detail: String,
    },
    /// US-1.3 AC2: the model's own assessment of one workflow step attempt. Always labelled
    /// [`SELF_REVIEW_LABEL`] ("opinion"); it is recorded next to the verdicts and never decides a
    /// [`WorkflowOutcome`].
    SelfReview {
        step: String,
        attempt: u32,
        text: String,
        label: &'static str,
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
            Event::Tainted { .. } => "tainted",
            Event::AssistantDelta { .. } => "assistant_delta",
            Event::Final { .. } => "final",
            Event::Usage { .. } => "usage",
            Event::Plan { .. } => "plan",
            Event::Verifier { .. } => "verifier",
            Event::SelfReview { .. } => "self_review",
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
    let system_prompt = turn_system_prompt(cfg, opts, user, history);
    history.push(Message::user(user));
    for step in 1..=cfg.max_steps {
        if stop.is_stopped() {
            return finish(sink, RunOutcome::Stopped);
        }
        sink.emit(Event::StepStart { step });
        let mut messages = Vec::with_capacity(history.len() + 1);
        messages.push(Message::system(system_prompt.clone()));
        messages.extend(history.iter().cloned());
        let offered = offered_tools(
            tools.specs(),
            history,
            user,
            opts.max_tools_per_request,
            &opts.pinned_tools,
            opts.selector
                .as_deref()
                .unwrap_or(&KeywordSelector as &dyn ToolSelector),
            opts.max_tools_total,
        );
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
        let mut deltas = DeltaCoalescer::new(step);
        let streamed = llm.complete_streaming(&req, &mut |d| deltas.push(sink, d));
        deltas.flush(sink);
        let turn = match streamed {
            Ok((t, usage)) => {
                if let Some(u) = usage {
                    sink.emit(Event::Usage {
                        step,
                        prompt_tokens: u.prompt_tokens,
                        completion_tokens: u.completion_tokens,
                        generation_ms: u.generation_ms,
                        prompt_ms: u.prompt_ms,
                    });
                }
                t
            }
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
            let over_cap = i as u32 >= cfg.max_tool_calls_per_step;
            let host = spec.and_then(|s| tools.host(s.host));
            // Decide refusal BEFORE announcing the call: a `tool_call` event names a host only when
            // this loop will dispatch it, so a remote host acting on those events (core) never runs
            // a call the loop refused.
            let refusal: Option<String> = if over_cap {
                Some(format!(
                    "skipped: at most {} tool calls per step — call it again next step if still needed",
                    cfg.max_tool_calls_per_step
                ))
            } else {
                match spec {
                    None => Some(format!("unknown tool '{}'", call.name)),
                    Some(_) => {
                        let args = if call.arguments.trim().is_empty() {
                            "{}"
                        } else {
                            call.arguments.as_str()
                        };
                        if serde_json::from_str::<serde_json::Value>(args).is_err() {
                            Some(
                                "the arguments were not valid JSON; retry with a JSON object"
                                    .into(),
                            )
                        } else if host.is_none() {
                            Some(format!("'{}' is not available in this session", call.name))
                        } else {
                            None
                        }
                    }
                }
            };
            // US-6.2: a call policy (the deploy guard) may decline the call outright, before it
            // is announced, so no host (and no core gate behind it) ever sees it.
            let declined = if refusal.is_none() {
                tools.declined(call)
            } else {
                None
            };
            // HUP-S2.7: after taint, an effectful call needs a member's explicit decision.
            let hic_reason = match spec {
                Some(s)
                    if refusal.is_none() && declined.is_none() && s.annotations.is_effectful() =>
                {
                    tools.taint().record().map(|r| {
                        format!(
                            "this session read untrusted content (from {}), so this action needs your explicit approval",
                            r.source
                        )
                    })
                }
                _ => None,
            };
            // Fail closed: a host that cannot put the call in front of a person never gets it.
            let refused_hic =
                hic_reason.is_some() && host.is_some_and(|h| !h.honors_explicit_approval());
            let dispatch = match (&refusal, spec, host) {
                (None, Some(s), Some(h)) if !refused_hic && declined.is_none() => Some((s.host, h)),
                _ => None,
            };
            // A host answered from outside (core) must be ready for the answer before the event
            // that asks for it is visible: register first, then announce.
            if let Some((_, h)) = &dispatch {
                h.before_announce(call);
            }
            sink.emit(Event::ToolCall {
                step,
                call: call.clone(),
                host: dispatch.as_ref().map(|(k, _)| *k),
                hic: hic_reason.as_ref().map(|_| "required"),
                hic_reason: hic_reason.clone(),
            });
            let mut ran = false;
            let outcome = match (dispatch, refusal) {
                (Some((_, h)), _) => {
                    ran = true;
                    match &hic_reason {
                        Some(reason) => h.execute_with_explicit_approval(call, reason),
                        None => h.execute(call),
                    }
                }
                (None, Some(why)) => ToolOutcome::Error(why),
                (None, None) if declined.is_some() => {
                    ToolOutcome::Denied(declined.clone().unwrap_or_default())
                }
                (None, None) if refused_hic => ToolOutcome::Denied(
                    "this session read untrusted content and this action needs a member's explicit approval, which this tool's host cannot ask for"
                        .into(),
                ),
                (None, None) => {
                    ToolOutcome::Error(format!("'{}' is not available in this session", call.name))
                }
            };
            let content = outcome.to_content();
            sink.emit(Event::ToolResult {
                step,
                call_id: call.id.clone(),
                status: outcome.status(),
                content: content.clone(),
            });
            // Taint when outside content entered the context: a result the host marked untrusted,
            // or any output (incl. an error body) from a tool not annotated as trusted. Declined
            // calls and loop-generated errors ingest nothing.
            let ingested_untrusted = ran
                && match &outcome {
                    ToolOutcome::Untrusted(_) => true,
                    ToolOutcome::Ok(_) | ToolOutcome::Error(_) => {
                        spec.is_some_and(|s| s.annotations.output_untrusted())
                    }
                    ToolOutcome::Denied(_) => false,
                };
            if ingested_untrusted {
                let reason = format!("{} returned untrusted content", call.name);
                if tools.taint().taint(&call.name, &reason) {
                    sink.emit(Event::Tainted {
                        step,
                        source: call.name.clone(),
                        reason,
                    });
                }
            }
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
    /// HUP-S3.2: tools offered on every request regardless of retrieval and outside
    /// `max_tools_per_request` (e.g. `skill_load`, which only works if the model can always see it).
    /// Names that are not in the registry are ignored.
    pub pinned_tools: Vec<String>,
    /// HUP-S3.2: sections appended to the system prompt for each turn, built from that turn's
    /// request (e.g. the five skills that match it). Computed once per turn, never stored in
    /// the history.
    pub turn_context: Vec<Arc<dyn TurnContext>>,
    /// HUP-S1.2: ranks the tools offered on each request. `None` uses [`KeywordSelector`]; the
    /// sidecar passes a [`retrieval::HybridRetriever`] (embedding plus keywords, which falls back
    /// to keywords by itself when no embedding endpoint answers).
    pub selector: Option<Arc<dyn ToolSelector>>,
    /// US-1.4 AC1: a hard ceiling on the tool schemas in one request, pinned and in-use tools
    /// included. When it binds, pinned tools come first, then the tools used most recently, then
    /// retrieval. `None` keeps the plain `max_tools_per_request` rule (pinned tools and tools in
    /// use ride outside it).
    pub max_tools_total: Option<usize>,
}

/// HUP-S3.2: per-turn context for the system prompt. `section` sees the turn's user message and
/// the history before it, and returns the text to append (or `None` for nothing).
pub trait TurnContext: Send + Sync {
    fn section(&self, user: &str, history: &[Message]) -> Option<String>;
}

/// The system prompt for one turn: the configured prompt plus every turn-context section.
fn turn_system_prompt(
    cfg: &LoopConfig,
    opts: &TurnOptions,
    user: &str,
    history: &[Message],
) -> String {
    let mut out = cfg.system_prompt.clone();
    for ctx in &opts.turn_context {
        if let Some(section) = ctx.section(user, history) {
            if !section.is_empty() {
                out.push_str("\n\n");
                out.push_str(&section);
            }
        }
    }
    out
}

/// Chooses which tool schemas to offer for a query. Tool schemas are the largest fixed cost in a
/// small model's context, so only the relevant ones go in each request.
pub trait ToolSelector: Send + Sync {
    fn select(&self, query: &str, specs: &[ToolSpec], k: usize) -> Vec<ToolSpec>;
}

/// Deterministic keyword scorer over tool names (weighted) and descriptions. Snake_case names are
/// split into words. With no signal at all it falls back to the first `k` tools in catalog order.
/// [`retrieval::HybridRetriever`] adds embedding similarity on top of this score.
#[derive(Debug, Clone, Copy, Default)]
pub struct KeywordSelector;

const STOPWORDS: &[&str] = &[
    "a", "an", "the", "and", "or", "to", "of", "in", "on", "for", "my", "me", "i", "is", "are",
    "it", "its", "this", "that", "what", "whats", "how", "many", "much", "do", "does", "can",
    "you", "please", "with", "from", "at", "by", "be",
];

pub(crate) fn words(s: &str) -> Vec<String> {
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

/// The keyword score of every spec for `query` (same order as `specs`): three points for each
/// query word in the tool's name, one for each in its description.
pub fn keyword_scores(query: &str, specs: &[ToolSpec]) -> Vec<usize> {
    let q = words(query);
    specs
        .iter()
        .map(|s| {
            let name = words(&s.name);
            let desc = words(&s.description);
            q.iter()
                .map(|w| {
                    3 * name.iter().filter(|n| *n == w).count()
                        + desc.iter().filter(|d| *d == w).count()
                })
                .sum()
        })
        .collect()
}

impl ToolSelector for KeywordSelector {
    fn select(&self, query: &str, specs: &[ToolSpec], k: usize) -> Vec<ToolSpec> {
        let mut scored: Vec<(usize, usize)> = keyword_scores(query, specs)
            .into_iter()
            .enumerate()
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

/// The tool schemas for one request. Pinned tools first, then tools already used in this
/// conversation (most recent first), then `selector`'s picks over the rest, up to `k` retrieved
/// tools (or as many as are in use, if more). `total` caps the whole list (US-1.4 AC1).
#[allow(clippy::too_many_arguments)]
fn offered_tools(
    specs: &[ToolSpec],
    history: &[Message],
    user: &str,
    k: Option<usize>,
    pinned: &[String],
    selector: &dyn ToolSelector,
    total: Option<usize>,
) -> Vec<ToolSpec> {
    let cap = total.unwrap_or(usize::MAX);
    let k = match (k, total) {
        (Some(k), _) => k,
        (None, Some(t)) => t,
        (None, None) => return specs.to_vec(),
    };
    let is_pinned = |s: &ToolSpec| pinned.iter().any(|p| p == &s.name);
    // Pinned tools first, then retrieval over the rest (so pinning never costs a retrieval slot).
    let mut out: Vec<ToolSpec> = specs
        .iter()
        .filter(|s| is_pinned(s))
        .take(cap)
        .cloned()
        .collect();
    let rest: Vec<ToolSpec> = specs.iter().filter(|s| !is_pinned(s)).cloned().collect();
    let base = out.len();
    let mut in_use: Vec<&str> = Vec::new();
    for name in history
        .iter()
        .rev()
        .flat_map(|m| m.tool_calls.iter().rev().map(|c| c.name.as_str()))
    {
        if !in_use.contains(&name) && rest.iter().any(|s| s.name == name) {
            in_use.push(name);
        }
    }
    for name in &in_use {
        if out.len() >= cap {
            break;
        }
        if let Some(s) = rest.iter().find(|s| s.name == *name) {
            out.push(s.clone());
        }
    }
    for s in selector.select(user, &rest, k) {
        if out.len() - base >= k.max(in_use.len()) || out.len() >= cap {
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

// ---------------------------------------------------------------------------------------------
// HUP-S1.3 — workflows judged by verifiers ("only verifiers say done")
// ---------------------------------------------------------------------------------------------

/// One tool call made during a step attempt, with how it ended.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ToolRecord {
    pub name: String,
    pub arguments: String,
    pub content: String,
    /// "ok" | "denied" | "error"
    pub status: &'static str,
}

/// What a verifier sees: the step's final answer and every tool call made in the attempt.
#[derive(Debug, Clone)]
pub struct VerifyContext<'a> {
    pub step: &'a str,
    pub answer: &'a str,
    pub tools: &'a [ToolRecord],
}

/// A verifier's verdict.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Verdict {
    Pass,
    Fail(String),
}

/// A deterministic external check. Verifiers decide outcomes; the model's opinion never does.
/// The toolchain verifiers (forge test report, SARIF, medusa summary; HUP-S6.3) implement this
/// same trait in [`verifiers_tooling`].
pub trait Verifier: Send + Sync {
    fn name(&self) -> String;
    fn verify(&self, ctx: &VerifyContext) -> Verdict;
}

/// Passes when the named tool ran and returned `ok` at least once in the attempt.
pub struct ToolSucceeded(pub String);
impl Verifier for ToolSucceeded {
    fn name(&self) -> String {
        format!("{} succeeded", self.0)
    }
    fn verify(&self, ctx: &VerifyContext) -> Verdict {
        if ctx
            .tools
            .iter()
            .any(|t| t.name == self.0 && t.status == "ok")
        {
            Verdict::Pass
        } else if ctx.tools.iter().any(|t| t.name == self.0) {
            Verdict::Fail(format!("{} was called but did not succeed", self.0))
        } else {
            Verdict::Fail(format!("{} was never called", self.0))
        }
    }
}

/// Passes when the named tool was NOT called in the attempt (a guard, e.g. "no deploy yet").
pub struct ToolNotCalled(pub String);
impl Verifier for ToolNotCalled {
    fn name(&self) -> String {
        format!("{} not called", self.0)
    }
    fn verify(&self, ctx: &VerifyContext) -> Verdict {
        if ctx.tools.iter().any(|t| t.name == self.0) {
            Verdict::Fail(format!("{} must not be called in this step", self.0))
        } else {
            Verdict::Pass
        }
    }
}

/// Passes when the final answer contains the text (case-insensitive).
pub struct AnswerContains(pub String);
impl Verifier for AnswerContains {
    fn name(&self) -> String {
        format!("answer mentions {:?}", self.0)
    }
    fn verify(&self, ctx: &VerifyContext) -> Verdict {
        if ctx.answer.to_lowercase().contains(&self.0.to_lowercase()) {
            Verdict::Pass
        } else {
            Verdict::Fail(format!("the answer does not mention {:?}", self.0))
        }
    }
}

/// Passes when the named tool's latest `ok` result is JSON whose value at `pointer` (RFC 6901)
/// equals `value` — e.g. a test report's `/failed == 0`.
pub struct JsonFieldEquals {
    pub tool: String,
    pub pointer: String,
    pub value: serde_json::Value,
}
impl Verifier for JsonFieldEquals {
    fn name(&self) -> String {
        format!("{}{} == {}", self.tool, self.pointer, self.value)
    }
    fn verify(&self, ctx: &VerifyContext) -> Verdict {
        let Some(rec) = ctx
            .tools
            .iter()
            .rev()
            .find(|t| t.name == self.tool && t.status == "ok")
        else {
            return Verdict::Fail(format!("{} produced no successful result", self.tool));
        };
        match serde_json::from_str::<serde_json::Value>(&rec.content) {
            Ok(v) => match v.pointer(&self.pointer) {
                Some(got) if *got == self.value => Verdict::Pass,
                Some(got) => Verdict::Fail(format!(
                    "{}{} is {got}, expected {}",
                    self.tool, self.pointer, self.value
                )),
                None => Verdict::Fail(format!("{} result has no {}", self.tool, self.pointer)),
            },
            Err(_) => Verdict::Fail(format!("{} result is not JSON", self.tool)),
        }
    }
}

/// HUP-S1.3: how an [`HttpStatusIs`] verifier reaches a URL. The sidecar's probe allows only
/// loopback and origins the member consented to, follows no redirects and bounds the wait; this
/// crate does no I/O itself.
pub trait HttpProbe: Send + Sync {
    /// The status code of one `GET url`, or why the URL could not be checked.
    fn status(&self, url: &str, timeout: std::time::Duration) -> Result<u16, String>;
}

/// The longest an [`HttpStatusIs`] check waits.
pub const HTTP_VERIFIER_MAX_TIMEOUT: std::time::Duration = std::time::Duration::from_secs(10);
/// How long an [`HttpStatusIs`] check waits unless told otherwise.
pub const HTTP_VERIFIER_DEFAULT_TIMEOUT: std::time::Duration = std::time::Duration::from_secs(5);

/// Passes when `GET url` answers with exactly `status` (e.g. a dev server's health route is 200).
/// The verdict comes from the probe, never from the model.
pub struct HttpStatusIs {
    pub url: String,
    pub status: u16,
    timeout: std::time::Duration,
    probe: Arc<dyn HttpProbe>,
}

impl HttpStatusIs {
    pub fn new(url: impl Into<String>, status: u16, probe: Arc<dyn HttpProbe>) -> Self {
        HttpStatusIs {
            url: url.into(),
            status,
            timeout: HTTP_VERIFIER_DEFAULT_TIMEOUT,
            probe,
        }
    }

    /// Wait at most `timeout`, capped at [`HTTP_VERIFIER_MAX_TIMEOUT`].
    pub fn with_timeout(mut self, timeout: std::time::Duration) -> Self {
        self.timeout = timeout.min(HTTP_VERIFIER_MAX_TIMEOUT);
        self
    }
}

impl Verifier for HttpStatusIs {
    fn name(&self) -> String {
        format!("GET {} is {}", self.url, self.status)
    }
    fn verify(&self, _ctx: &VerifyContext) -> Verdict {
        match self.probe.status(&self.url, self.timeout) {
            Ok(got) if got == self.status => Verdict::Pass,
            Ok(got) => Verdict::Fail(format!(
                "GET {} answered {got}, expected {}",
                self.url, self.status
            )),
            Err(why) => Verdict::Fail(format!("GET {} could not be checked: {why}", self.url)),
        }
    }
}

/// HUP-S1.3: how a [`Sha256Equals`] verifier reads a file. The sidecar's host reads only paths
/// inside the session's live folder grants; this crate does no I/O itself.
pub trait FileDigest: Send + Sync {
    /// The lowercase hex SHA-256 of the file's bytes, or why it could not be read.
    fn sha256_hex(&self, path: &str) -> Result<String, String>;
}

/// Passes when the file's SHA-256 equals `hex` (case-insensitive).
pub struct Sha256Equals {
    pub path: String,
    pub hex: String,
    files: Arc<dyn FileDigest>,
}

impl Sha256Equals {
    pub fn new(path: impl Into<String>, hex: &str, files: Arc<dyn FileDigest>) -> Self {
        Sha256Equals {
            path: path.into(),
            hex: hex.to_ascii_lowercase(),
            files,
        }
    }
}

impl Verifier for Sha256Equals {
    fn name(&self) -> String {
        format!("sha256 of {} is {}", self.path, self.hex)
    }
    fn verify(&self, _ctx: &VerifyContext) -> Verdict {
        match self.files.sha256_hex(&self.path) {
            Ok(got) if got.eq_ignore_ascii_case(&self.hex) => Verdict::Pass,
            Ok(got) => Verdict::Fail(format!(
                "the sha256 of {} is {}, which does not match {}",
                self.path,
                got.to_ascii_lowercase(),
                self.hex
            )),
            Err(why) => Verdict::Fail(format!("{} could not be hashed: {why}", self.path)),
        }
    }
}

// ---------------------------------------------------------------------------------------------
// US-1.3 AC2 — the model's self-review, recorded as an opinion
// ---------------------------------------------------------------------------------------------

/// The label every [`Event::SelfReview`] carries.
pub const SELF_REVIEW_LABEL: &str = "opinion";
/// The most characters of one recorded opinion.
pub const SELF_REVIEW_MAX_CHARS: usize = 600;

/// One step attempt, as the self-reviewer sees it. It never includes a verifier's verdict.
#[derive(Debug, Clone)]
pub struct ReviewRequest<'a> {
    pub step: &'a str,
    pub attempt: u32,
    pub instruction: &'a str,
    pub answer: &'a str,
}

/// Produces the model's self-assessment of a step attempt. The text is recorded as an opinion
/// and nothing reads it to decide an outcome.
pub trait SelfReviewer: Send + Sync {
    fn review(&self, req: &ReviewRequest, history: &[Message]) -> Result<String, String>;
}

/// The self-reviewer that asks the session's own model, with no tools offered and without adding
/// anything to the conversation.
pub struct LlmSelfReviewer<'a> {
    llm: &'a dyn LlmClient,
    model: String,
    max_tokens: u32,
}

impl<'a> LlmSelfReviewer<'a> {
    pub fn new(llm: &'a dyn LlmClient, model: impl Into<String>, max_tokens: u32) -> Self {
        LlmSelfReviewer {
            llm,
            model: model.into(),
            max_tokens,
        }
    }
}

impl SelfReviewer for LlmSelfReviewer<'_> {
    fn review(&self, req: &ReviewRequest, history: &[Message]) -> Result<String, String> {
        let mut messages = history.to_vec();
        messages.push(Message::user(format!(
            "Before any check runs, give a short self-assessment of your last answer to step \"{}\" \
             (attempt {}). Start with PASS or FAIL, then one or two sentences. This is recorded as \
             your opinion only; it does not decide whether the step passed.\n\nStep: {}\nYour answer: {}",
            req.step, req.attempt, req.instruction, req.answer
        )));
        let turn = self
            .llm
            .complete(&CompletionRequest {
                model: self.model.clone(),
                messages,
                tools: vec![],
                max_tokens: self.max_tokens,
            })
            .map_err(|e| e.to_string())?;
        Ok(turn.content)
    }
}

fn bounded_opinion(text: &str) -> String {
    let t = text.trim();
    if t.chars().count() <= SELF_REVIEW_MAX_CHARS {
        return t.to_string();
    }
    let mut out: String = t.chars().take(SELF_REVIEW_MAX_CHARS - 1).collect();
    out.push('\u{2026}');
    out
}

/// One workflow step: an instruction, the verifiers that judge it, and a retry budget.
#[derive(Clone)]
pub struct Step {
    pub id: String,
    pub instruction: String,
    pub verifiers: Vec<Arc<dyn Verifier>>,
    pub max_attempts: u32,
}

/// An ordered set of verifier-judged steps.
#[derive(Clone)]
pub struct Workflow {
    pub id: String,
    pub steps: Vec<Step>,
}

impl Workflow {
    /// Valid only when every step can be judged: ≥1 step, ≥1 verifier per step, 1–5 attempts.
    pub fn new(id: impl Into<String>, steps: Vec<Step>) -> Result<Self, String> {
        let id = id.into();
        if steps.is_empty() {
            return Err(format!("workflow {id} has no steps"));
        }
        for st in &steps {
            if st.verifiers.is_empty() {
                return Err(format!(
                    "step {} has no verifier, so it could never be judged",
                    st.id
                ));
            }
            if !(1..=5).contains(&st.max_attempts) {
                return Err(format!("step {} needs 1–5 attempts", st.id));
            }
        }
        Ok(Workflow { id, steps })
    }
}

/// How a workflow ended. `Succeeded` is only reachable when every verifier of every step passed.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum WorkflowOutcome {
    Succeeded { answers: Vec<String> },
    Failed { step: String, reason: String },
    Stopped,
}

fn records_since(history: &[Message]) -> Vec<ToolRecord> {
    let mut calls: HashMap<String, (String, String)> = HashMap::new();
    let mut out = Vec::new();
    for m in history {
        for c in &m.tool_calls {
            calls.insert(c.id.clone(), (c.name.clone(), c.arguments.clone()));
        }
        if m.role == Role::Tool {
            if let Some((name, arguments)) = m.tool_call_id.as_ref().and_then(|id| calls.get(id)) {
                let status = if m.content.starts_with("declined:") {
                    "denied"
                } else if m.content.starts_with("tool error:") {
                    "error"
                } else {
                    "ok"
                };
                out.push(ToolRecord {
                    name: name.clone(),
                    arguments: arguments.clone(),
                    content: m.content.clone(),
                    status,
                });
            }
        }
    }
    out
}

/// Run a workflow: each step is one or more turns; after each attempt every verifier judges it; a
/// failed attempt is retried with the failures spelled out; the workflow succeeds only when every
/// step passed every verifier.
#[allow(clippy::too_many_arguments)]
pub fn run_workflow(
    cfg: &LoopConfig,
    opts: &TurnOptions,
    llm: &dyn LlmClient,
    tools: &ToolRegistry,
    sink: &dyn EventSink,
    stop: &StopFlag,
    history: &mut Vec<Message>,
    wf: &Workflow,
) -> WorkflowOutcome {
    run_workflow_reviewed(cfg, opts, llm, tools, sink, stop, history, wf, None)
}

/// [`run_workflow`], plus (US-1.3 AC2) the model's self-review of every step attempt, asked
/// before the verifiers judge it and emitted as [`Event::SelfReview`] labelled "opinion". The
/// opinion is never added to `history` and never read by the outcome: a "PASS" opinion with a
/// failing verifier still fails the step. A failed review call is recorded as "no opinion".
#[allow(clippy::too_many_arguments)]
pub fn run_workflow_reviewed(
    cfg: &LoopConfig,
    opts: &TurnOptions,
    llm: &dyn LlmClient,
    tools: &ToolRegistry,
    sink: &dyn EventSink,
    stop: &StopFlag,
    history: &mut Vec<Message>,
    wf: &Workflow,
    reviewer: Option<&dyn SelfReviewer>,
) -> WorkflowOutcome {
    let mut answers = Vec::new();
    sink.emit(Event::Plan {
        steps: wf.steps.iter().map(|st| st.id.clone()).collect(),
    });
    for st in &wf.steps {
        let mut feedback: Vec<String> = Vec::new();
        let mut passed = false;
        for attempt in 1..=st.max_attempts {
            if stop.is_stopped() {
                return WorkflowOutcome::Stopped;
            }
            let prompt = if feedback.is_empty() {
                st.instruction.clone()
            } else {
                format!(
                    "{}\n\nThe previous attempt did not pass these checks:\n{}\nFix that, then answer again.",
                    st.instruction,
                    feedback.iter().map(|f| format!("- {f}")).collect::<Vec<_>>().join("\n")
                )
            };
            let start = history.len();
            let answer = match run_turn_with(cfg, opts, llm, tools, sink, stop, history, &prompt) {
                RunOutcome::Stopped => return WorkflowOutcome::Stopped,
                RunOutcome::Answered(a) => a,
                RunOutcome::StepLimit => {
                    feedback = vec!["the step ran out of tool steps before finishing".into()];
                    continue;
                }
                RunOutcome::Failed(m) => {
                    feedback = vec![format!("the attempt failed: {m}")];
                    continue;
                }
            };
            if let Some(r) = reviewer {
                if !stop.is_stopped() {
                    let req = ReviewRequest {
                        step: &st.id,
                        attempt,
                        instruction: &st.instruction,
                        answer: &answer,
                    };
                    let text = match r.review(&req, history) {
                        Ok(t) => bounded_opinion(&t),
                        Err(why) => bounded_opinion(&format!("no opinion: {why}")),
                    };
                    sink.emit(Event::SelfReview {
                        step: st.id.clone(),
                        attempt,
                        text,
                        label: SELF_REVIEW_LABEL,
                    });
                }
            }
            let records = records_since(&history[start..]);
            let ctx = VerifyContext {
                step: &st.id,
                answer: &answer,
                tools: &records,
            };
            feedback.clear();
            for v in &st.verifiers {
                let (ok, detail) = match v.verify(&ctx) {
                    Verdict::Pass => (true, String::new()),
                    Verdict::Fail(why) => (false, why),
                };
                sink.emit(Event::Verifier {
                    step: st.id.clone(),
                    name: v.name(),
                    passed: ok,
                    detail: detail.clone(),
                });
                if !ok {
                    feedback.push(format!("{}: {detail}", v.name()));
                }
            }
            if feedback.is_empty() {
                answers.push(answer);
                passed = true;
                break;
            }
        }
        if !passed {
            return WorkflowOutcome::Failed {
                step: st.id.clone(),
                reason: feedback.join("; "),
            };
        }
    }
    WorkflowOutcome::Succeeded { answers }
}

/// Chooses a registered workflow for a goal (the planner half of planner/executor). The
/// model-driven planner, which writes a new workflow instead of choosing one, is
/// [`planner::ModelPlanner`]; both hand the same executor ([`run_workflow`]) a workflow whose
/// every step carries a verifier.
pub trait Planner: Send + Sync {
    fn plan(&self, goal: &str) -> Option<&Workflow>;
}

/// Keyword-triggered registry of workflows (deterministic; the default until S1.4).
pub struct StaticPlanner {
    entries: Vec<(Vec<String>, Workflow)>,
}

impl StaticPlanner {
    pub fn new(entries: Vec<(Vec<String>, Workflow)>) -> Self {
        StaticPlanner { entries }
    }
}

impl Planner for StaticPlanner {
    fn plan(&self, goal: &str) -> Option<&Workflow> {
        let g = goal.to_lowercase();
        self.entries
            .iter()
            .find(|(keys, _)| keys.iter().any(|k| g.contains(&k.to_lowercase())))
            .map(|(_, w)| w)
    }
}

#[cfg(test)]
mod taint_state_tests {
    use super::*;

    fn poison(t: &TaintState) {
        let inner = t.0.clone();
        let _ = std::thread::spawn(move || {
            let _g = inner.lock().unwrap();
            panic!("poison the taint lock");
        })
        .join();
    }

    #[test]
    fn a_poisoned_untainted_state_reads_as_tainted_everywhere() {
        let t = TaintState::default();
        poison(&t);
        assert!(t.is_tainted());
        // run_turn_with gates on `record()`, so it must agree with `is_tainted()`.
        assert!(t.record().is_some());
    }

    #[test]
    fn a_poisoned_tainted_state_keeps_its_first_source() {
        let t = TaintState::default();
        assert!(t.taint("web_fetch", "untrusted"));
        poison(&t);
        assert_eq!(t.record().map(|r| r.source), Some("web_fetch".to_string()));
    }
}
