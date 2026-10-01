//! HUP-S1.1b — agent sessions: the sidecar hosts Hermes's turn loop (`citrate-agent-loop`).
//!
//! "Brain in the sidecar, hands in core" (citrate-core ADR-2026-09-30-hermes-loop-in-sidecar):
//! - citrate-core opens a session with the inference endpoint + bearer it owns (loopback
//!   llama-server or the configured https gateway) and the tool specs it offers.
//! - A user message runs one turn on the blocking pool. Events are appended to a bounded,
//!   sequence-numbered log that clients read with a long-poll (`GET …/events?after=N&wait_ms=M`).
//! - A **core-hosted** tool call parks the loop until citrate-core posts its result
//!   (`POST …/tool_results`) after running it through its own approval gates — or until a deadline
//!   or a stop. The sidecar never executes a core tool, never signs, and never decides an approval.
//! - A **sidecar-hosted** tool is an installed capsule run through the capsule dispatch, whose chain
//!   effects still park on the ceremony-grade approval queue.
//! - The global e-stop halts every session.
//! - HUP-S3.2: when a skills library is configured (`CITRATE_HERMES_SKILLS`, default off), every
//!   session gets the skill description index in its system prompt and a pinned, sidecar-hosted
//!   `skill_load` tool. Skills are instructions only; `skill_load` reads text and runs nothing.
//! - HUP-S2.7 taint downgrade: tool specs carry `effect` / `trust` annotations (absent = effectful,
//!   untrusted). Once a session has ingested untrusted content it stays tainted, and every
//!   effectful call needs a member's explicit decision. A core-hosted call is only dispatched to
//!   core in that state when the session was opened with `hicAware: true` (core's promise that a
//!   `hic: "required"` call always goes to a person, with no auto or budget path); otherwise, and
//!   for capsules, the sidecar declines the call itself.
//! - HUP-S6.3: when the toolchain is enabled (`CITRATE_HERMES_TOOLCHAIN=1`, default off), every
//!   session also offers the sidecar-hosted `forge_test`, `slither_scan`, `aderyn_scan` and
//!   `medusa_fuzz` tools ([`crate::toolchain`]), whose results the toolchain verifiers judge.
//! - HUP-S4.1: when an MCP allowlist is configured (`CITRATE_HERMES_MCP`, default off), every
//!   session is offered the allowlisted servers' tools as sidecar-hosted `mcp__<server>__<tool>`
//!   specs (trust: untrusted, so an MCP result taints the session), and the `mcp__` namespace is
//!   reserved. Unset, nothing here changes.
//! - HUP-S3.4: a session can run a declarative workflow (`POST …/workflows`,
//!   [`crate::workflow_spec`]) through `citrate_agent_learn::run_verified_workflow`; a run whose
//!   verifiers all passed is kept (the last [`MAX_RUNS_KEPT`]) as the evidence a learn proposal
//!   needs. When learning is configured (`CITRATE_HERMES_LEARN_DIR`, default off), every session is
//!   also offered the sidecar-hosted `learn_propose` tool ([`crate::learn`]), which proposes from
//!   the session's last verified run and never persists anything itself.

use std::collections::{HashMap, VecDeque};
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::sync::mpsc;
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

use citrate_agent_core::capsule::dispatch::CapsuleDispatch;
use citrate_agent_learn::{run_verified_workflow, Evidence, VerifiedRun};
use citrate_agent_loop::skills::{skill_load_spec, SkillHost, SkillLibrary, SKILL_LOAD_TOOL};
use citrate_agent_loop::{
    run_turn_with, CharTokenCounter, ContextBudget, Event, EventSink, HostKind, LlmClient,
    LoopConfig, Message, StopFlag, TaintState, ToolCall, ToolHost, ToolOutcome, ToolRegistry,
    ToolSpec, TurnOptions, Workflow,
};
use citrate_agent_mcp_host::{McpHost, McpToolHost, ServerStatus};
use serde::{Deserialize, Serialize};

use crate::toolchain::ToolchainHost;

/// At most this many open sessions (a session is a conversation, not a request).
pub const MAX_SESSIONS: usize = 8;
/// Events kept per session for replay; older ones are dropped (clients read by sequence).
pub const EVENT_LOG_CAP: usize = 2000;
/// Upper bounds a client may request.
pub const MAX_STEPS_CAP: u32 = 32;
pub const MAX_TOKENS_CAP: u32 = 8192;
/// Longest a long-poll may wait.
pub const MAX_WAIT_MS: u64 = 25_000;
/// Token budget for the skill description index in a session's system prompt.
pub const SKILL_INDEX_TOKENS: usize = 1500;
/// Workflow runs remembered per session (oldest dropped first).
pub const MAX_RUNS_KEPT: usize = 16;

/// Where a workflow run is.
#[derive(Clone)]
pub enum RunState {
    Running {
        workflow_id: String,
    },
    /// Every verifier of every step passed.
    Verified(Box<VerifiedRun>),
    /// It failed, was stopped, or its verdicts did not add up.
    Unverified {
        workflow_id: String,
        reason: String,
    },
}

/// `GET /sessions/:id/workflows/:run`.
#[derive(Debug, Serialize)]
pub struct RunView {
    pub run_id: String,
    pub workflow_id: String,
    /// "running" | "verified" | "unverified"
    pub state: &'static str,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub evidence: Option<Evidence>,
    /// The model's final answers per step (shown to the member, never evidence).
    #[serde(skip_serializing_if = "Vec::is_empty")]
    pub answers: Vec<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub reason: Option<String>,
}

impl RunView {
    fn of(run_id: &str, st: &RunState) -> Self {
        match st {
            RunState::Running { workflow_id } => RunView {
                run_id: run_id.into(),
                workflow_id: workflow_id.clone(),
                state: "running",
                evidence: None,
                answers: vec![],
                reason: None,
            },
            RunState::Verified(run) => RunView {
                run_id: run_id.into(),
                workflow_id: run.evidence().workflow_id.clone(),
                state: "verified",
                evidence: Some(run.evidence().clone()),
                answers: run.answers().to_vec(),
                reason: None,
            },
            RunState::Unverified {
                workflow_id,
                reason,
            } => RunView {
                run_id: run_id.into(),
                workflow_id: workflow_id.clone(),
                state: "unverified",
                evidence: None,
                answers: vec![],
                reason: Some(reason.clone()),
            },
        }
    }
}

/// Where the model lives and how to authenticate. Supplied by citrate-core, never by a webview.
#[derive(Clone, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct LlmEndpoint {
    pub base_url: String,
    #[serde(default)]
    pub bearer: String,
}

impl std::fmt::Debug for LlmEndpoint {
    // Never print the bearer.
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("LlmEndpoint")
            .field("base_url", &self.base_url)
            .finish_non_exhaustive()
    }
}

/// Only a loopback http endpoint (the bundled llama-server) or an https endpoint is accepted.
pub fn validate_endpoint(url: &str) -> Result<(), String> {
    if let Some(rest) = url.strip_prefix("https://") {
        return if rest.is_empty() || rest.starts_with('/') {
            Err("https endpoint has no host".into())
        } else {
            Ok(())
        };
    }
    if let Some(rest) = url.strip_prefix("http://") {
        let host_port = rest.split('/').next().unwrap_or("");
        let host = if let Some(h) = host_port.strip_prefix('[') {
            h.split(']').next().unwrap_or("")
        } else {
            host_port
                .rsplit_once(':')
                .map(|(h, _)| h)
                .unwrap_or(host_port)
        };
        let loopback = host == "localhost"
            || host
                .parse::<std::net::IpAddr>()
                .map(|ip| ip.is_loopback())
                .unwrap_or(false);
        return if loopback {
            Ok(())
        } else {
            Err(format!(
                "plain http is only allowed to a loopback host, not {host:?}"
            ))
        };
    }
    Err("the model endpoint must be http://<loopback> or https://".into())
}

/// Builds the model client for an endpoint (production: [`crate::llm_http::OpenAiCompatClient`];
/// tests: a script).
pub type LlmFactory = Arc<dyn Fn(&LlmEndpoint) -> Arc<dyn LlmClient> + Send + Sync>;

/// `POST /sessions` body.
#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct CreateSessionReq {
    pub model: String,
    pub system_prompt: String,
    pub llm: LlmEndpoint,
    #[serde(default)]
    pub tools: Vec<ToolSpec>,
    pub max_steps: Option<u32>,
    pub max_tokens: Option<u32>,
    pub max_tool_calls_per_step: Option<u32>,
    /// HUP-S1.2: offer at most this many tool schemas per request (default 8).
    pub max_tools_per_request: Option<usize>,
    /// HUP-S1.2: the model's context window in tokens; when given, every request is compacted to
    /// fit (or the turn fails honestly).
    pub context_tokens: Option<usize>,
    /// HUP-S2.7: core confirms that a tool call marked `hic: "required"` always goes to a person
    /// for an explicit decision (no auto-approval, no budget path). Absent = false: the sidecar then
    /// declines tainted effectful core calls itself.
    #[serde(default)]
    pub hic_aware: bool,
}

/// `POST /sessions/:id/tool_results` body.
#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct ToolResultReq {
    pub call_id: String,
    /// "ok" | "denied" | "error"
    pub status: String,
    pub content: String,
    /// HUP-S2.7: "untrusted" marks this one result as untrusted content (e.g. a file outside the
    /// granted folders), which taints the session; "trusted" or absent defers to the tool's
    /// annotation.
    #[serde(default)]
    pub trust: Option<String>,
}

/// One event with its sequence number, as served by `GET …/events`.
#[derive(Debug, Clone, Serialize)]
pub struct Envelope {
    pub seq: u64,
    pub event: Event,
}

/// The `GET …/events` response.
#[derive(Debug, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct EventsPage {
    pub events: Vec<Envelope>,
    /// The highest sequence number assigned so far (pass it back as `after`).
    pub last_seq: u64,
    pub busy: bool,
}

struct EventLog {
    next_seq: u64,
    events: VecDeque<Envelope>,
}

/// One conversation.
pub struct Session {
    pub id: String,
    cfg: LoopConfig,
    opts: TurnOptions,
    specs: Vec<ToolSpec>,
    hic_aware: bool,
    taint: TaintState,
    llm: Arc<dyn LlmClient>,
    history: Mutex<Vec<Message>>,
    log: Mutex<EventLog>,
    notify: tokio::sync::Notify,
    pub stop: StopFlag,
    busy: AtomicBool,
    pending: Arc<Mutex<HashMap<String, mpsc::Sender<ToolOutcome>>>>,
    /// HUP-S3.2: present when this session was opened with skills (it then offers `skill_load`).
    skills: Option<Arc<SkillLibrary>>,
    /// HUP-S6.3: present when this session was opened with the toolchain enabled.
    toolchain: Option<Arc<ToolchainHost>>,
    /// HUP-S3.4: workflow runs, oldest first (at most [`MAX_RUNS_KEPT`]).
    runs: Mutex<VecDeque<(String, RunState)>>,
}

impl Session {
    fn push(&self, event: Event) {
        if let Ok(mut log) = self.log.lock() {
            log.next_seq += 1;
            let seq = log.next_seq;
            log.events.push_back(Envelope { seq, event });
            while log.events.len() > EVENT_LOG_CAP {
                log.events.pop_front();
            }
        }
        self.notify.notify_waiters();
    }

    /// Events with `seq > after`.
    pub fn events_after(&self, after: u64) -> EventsPage {
        let (events, last_seq) = match self.log.lock() {
            Ok(log) => (
                log.events
                    .iter()
                    .filter(|e| e.seq > after)
                    .cloned()
                    .collect(),
                log.next_seq,
            ),
            Err(_) => (Vec::new(), 0),
        };
        EventsPage {
            events,
            last_seq,
            busy: self.busy.load(Ordering::SeqCst),
        }
    }

    /// Long-poll: return new events as soon as there are any, or after `wait` with none.
    pub async fn wait_events(&self, after: u64, wait: Duration) -> EventsPage {
        let deadline = tokio::time::Instant::now() + wait;
        loop {
            let notified = self.notify.notified();
            tokio::pin!(notified);
            notified.as_mut().enable();
            let page = self.events_after(after);
            if !page.events.is_empty() || tokio::time::Instant::now() >= deadline {
                return page;
            }
            if tokio::time::timeout_at(deadline, notified).await.is_err() {
                return self.events_after(after);
            }
        }
    }

    /// Deliver a core-hosted tool's result. `false` when nothing is waiting for that call id.
    pub fn deliver(&self, call_id: &str, outcome: ToolOutcome) -> bool {
        let tx = self.pending.lock().ok().and_then(|mut p| p.remove(call_id));
        match tx {
            Some(tx) => tx.send(outcome).is_ok(),
            None => false,
        }
    }

    /// This session's taint (HUP-S2.7).
    pub fn taint(&self) -> &TaintState {
        &self.taint
    }

    pub fn is_busy(&self) -> bool {
        self.busy.load(Ordering::SeqCst)
    }

    /// The model this session runs (recorded in a learn proposal's provenance).
    pub fn model(&self) -> &str {
        &self.cfg.model
    }

    fn set_run(&self, run_id: &str, state: RunState) {
        if let Ok(mut runs) = self.runs.lock() {
            if let Some(slot) = runs.iter_mut().find(|(id, _)| id == run_id) {
                slot.1 = state;
                return;
            }
            runs.push_back((run_id.to_string(), state));
            while runs.len() > MAX_RUNS_KEPT {
                runs.pop_front();
            }
        }
    }

    /// One workflow run, if this session still remembers it.
    pub fn run(&self, run_id: &str) -> Option<RunState> {
        self.runs.lock().ok().and_then(|r| {
            r.iter()
                .find(|(id, _)| id == run_id)
                .map(|(_, st)| st.clone())
        })
    }

    /// The session's most recent verified run, with its id.
    pub fn last_verified(&self) -> Option<(String, VerifiedRun)> {
        self.runs.lock().ok().and_then(|r| {
            r.iter().rev().find_map(|(id, st)| match st {
                RunState::Verified(v) => Some((id.clone(), (**v).clone())),
                _ => None,
            })
        })
    }
}

struct SessionSink(Arc<Session>);
impl EventSink for SessionSink {
    fn emit(&self, ev: Event) {
        self.0.push(ev);
    }
}

/// Executes core-hosted tools by waiting for citrate-core to post the result.
struct CoreHost {
    pending: Arc<Mutex<HashMap<String, mpsc::Sender<ToolOutcome>>>>,
    deadline: Duration,
    stop: StopFlag,
    /// Core promised to route `hic: "required"` calls to a person (see `CreateSessionReq`).
    hic_aware: bool,
}

impl ToolHost for CoreHost {
    fn execute(&self, call: &ToolCall) -> ToolOutcome {
        let (tx, rx) = mpsc::channel();
        if let Ok(mut p) = self.pending.lock() {
            p.insert(call.id.clone(), tx);
        } else {
            return ToolOutcome::Error("internal: tool registry unavailable".into());
        }
        let started = Instant::now();
        let outcome = loop {
            match rx.recv_timeout(Duration::from_millis(100)) {
                Ok(o) => break o,
                Err(mpsc::RecvTimeoutError::Disconnected) => {
                    break ToolOutcome::Error("the app closed this tool call".into())
                }
                Err(mpsc::RecvTimeoutError::Timeout) => {
                    if self.stop.is_stopped() {
                        break ToolOutcome::Error("stopped before the app answered".into());
                    }
                    if started.elapsed() >= self.deadline {
                        break ToolOutcome::Error(format!(
                            "the app did not answer within {}s",
                            self.deadline.as_secs()
                        ));
                    }
                }
            }
        };
        if let Ok(mut p) = self.pending.lock() {
            p.remove(&call.id);
        }
        outcome
    }

    fn honors_explicit_approval(&self) -> bool {
        self.hic_aware
    }

    /// The requirement reaches core in the `tool_call` event (`hic: "required"` + reason); core
    /// asks the member and posts the decision back like any other result.
    fn execute_with_explicit_approval(&self, call: &ToolCall, _reason: &str) -> ToolOutcome {
        self.execute(call)
    }
}

/// Executes sidecar-hosted tools: installed capsules through the capsule dispatch (whose chain
/// effects still park on the approval queue for a human).
struct CapsuleHost {
    dispatch: Arc<CapsuleDispatch>,
}

impl ToolHost for CapsuleHost {
    fn execute(&self, call: &ToolCall) -> ToolOutcome {
        let args: serde_json::Value = serde_json::from_str(if call.arguments.trim().is_empty() {
            "{}"
        } else {
            &call.arguments
        })
        .unwrap_or(serde_json::Value::Object(Default::default()));
        match self.dispatch.call_json(&call.name, &args) {
            Ok(v) => ToolOutcome::Ok(v.to_string()),
            Err(e) => ToolOutcome::Error(e.to_string()),
        }
    }
}

/// The one host for [`HostKind::Sidecar`] tools: `skill_load` goes to the skill library, the
/// toolchain tools to the toolchain host (when enabled), an offered `mcp__…` tool to its MCP
/// server (HUP-S4.1), anything else to the capsule dispatch (when capsules are loaded).
struct SidecarHost {
    skills: Option<SkillHost>,
    toolchain: Option<Arc<ToolchainHost>>,
    mcp: Option<McpToolHost>,
    capsules: Option<CapsuleHost>,
    learn: Option<crate::learn::LearnToolHost>,
}

impl ToolHost for SidecarHost {
    fn execute(&self, call: &ToolCall) -> ToolOutcome {
        if call.name == crate::learn::LEARN_PROPOSE_TOOL {
            if let Some(l) = &self.learn {
                return l.execute(call);
            }
        }
        if call.name == SKILL_LOAD_TOOL {
            if let Some(h) = &self.skills {
                return h.execute(call);
            }
        }
        if ToolchainHost::handles(&call.name) {
            if let Some(t) = &self.toolchain {
                return t.execute(call);
            }
        }
        if let Some(m) = &self.mcp {
            if m.handles(&call.name) {
                return m.execute(call);
            }
        }
        match &self.capsules {
            Some(c) => c.execute(call),
            None => ToolOutcome::Error(format!("'{}' is not available in this session", call.name)),
        }
    }
}

/// Why a session operation was refused (mapped to HTTP status by the routes).
#[derive(Debug, PartialEq, Eq)]
pub enum SessionError {
    NotFound,
    Busy,
    TooMany,
    Invalid(String),
}

/// All sessions.
pub struct SessionManager {
    sessions: Mutex<HashMap<String, Arc<Session>>>,
    llm_factory: LlmFactory,
    core_tool_deadline: Duration,
    ids: AtomicU64,
    skills: Option<Arc<SkillLibrary>>,
    toolchain: Option<Arc<ToolchainHost>>,
    mcp: Option<Arc<McpHost>>,
    learn: Option<Arc<crate::learn::LearnService>>,
    run_ids: AtomicU64,
}

impl SessionManager {
    pub fn new(llm_factory: LlmFactory, core_tool_deadline: Duration) -> Self {
        SessionManager {
            sessions: Mutex::new(HashMap::new()),
            llm_factory,
            core_tool_deadline,
            ids: AtomicU64::new(0),
            skills: None,
            toolchain: None,
            mcp: None,
            learn: None,
            run_ids: AtomicU64::new(0),
        }
    }

    /// HUP-S3.4: verified self-learning (the learn routes and the `learn_propose` tool).
    pub fn with_learn(mut self, learn: Arc<crate::learn::LearnService>) -> Self {
        self.learn = Some(learn);
        self
    }

    /// HUP-S3.4: the learn service, when learning is configured.
    pub fn learn(&self) -> Option<&Arc<crate::learn::LearnService>> {
        self.learn.as_ref()
    }

    /// HUP-S6.3: offer the toolchain tools to every new session.
    pub fn with_toolchain(mut self, host: Arc<ToolchainHost>) -> Self {
        self.toolchain = Some(host);
        self
    }

    /// HUP-S4.1: offer this MCP host's tools to every new session. A host with no servers offers
    /// nothing and reserves nothing.
    pub fn with_mcp(mut self, host: Arc<McpHost>) -> Self {
        self.mcp = if host.is_empty() { None } else { Some(host) };
        self
    }

    /// HUP-S4.1: the configured MCP servers (`None` when MCP is not configured).
    pub fn mcp_status(&self) -> Option<Vec<ServerStatus>> {
        self.mcp.as_ref().map(|h| h.status())
    }

    /// HUP-S3.2: offer this skills library to every new session. An empty library offers nothing.
    pub fn with_skills(mut self, lib: Arc<SkillLibrary>) -> Self {
        self.skills = if lib.is_empty() { None } else { Some(lib) };
        self
    }

    pub fn create(&self, req: CreateSessionReq) -> Result<String, SessionError> {
        validate_endpoint(&req.llm.base_url).map_err(SessionError::Invalid)?;
        if req.model.trim().is_empty() {
            return Err(SessionError::Invalid("model is required".into()));
        }
        let mut specs = req.tools;
        let mut system_prompt = req.system_prompt;
        let mut pinned_tools = Vec::new();
        if let Some(lib) = &self.skills {
            if specs.iter().any(|t| t.name == SKILL_LOAD_TOOL) {
                return Err(SessionError::Invalid(format!(
                    "the tool name '{SKILL_LOAD_TOOL}' is reserved by the sidecar while skills are enabled"
                )));
            }
            if let Some(section) = lib.prompt_section(SKILL_INDEX_TOKENS, &CharTokenCounter) {
                system_prompt = format!("{system_prompt}\n\n{section}");
            }
            specs.push(skill_load_spec());
            pinned_tools.push(SKILL_LOAD_TOOL.to_string());
        }
        if self.toolchain.is_some() {
            if let Some(t) = specs.iter().find(|t| ToolchainHost::handles(&t.name)) {
                return Err(SessionError::Invalid(format!(
                    "the tool name '{}' is reserved by the sidecar while the toolchain is enabled",
                    t.name
                )));
            }
            specs.extend(ToolchainHost::specs());
        }
        if let Some(mcp) = &self.mcp {
            if let Some(t) = specs.iter().find(|t| McpHost::reserved(&t.name)) {
                return Err(SessionError::Invalid(format!(
                    "the tool name '{}' is in the 'mcp__' namespace, which is reserved while MCP servers are configured",
                    t.name
                )));
            }
            specs.extend(mcp.specs());
        }
        if self.learn.is_some() {
            if specs
                .iter()
                .any(|t| t.name == crate::learn::LEARN_PROPOSE_TOOL)
            {
                return Err(SessionError::Invalid(format!(
                    "the tool name '{}' is reserved by the sidecar while learning is on",
                    crate::learn::LEARN_PROPOSE_TOOL
                )));
            }
            specs.push(crate::learn::learn_propose_spec());
        }
        let mut sessions = self
            .sessions
            .lock()
            .map_err(|_| SessionError::Invalid("internal".into()))?;
        if sessions.len() >= MAX_SESSIONS {
            return Err(SessionError::TooMany);
        }
        let n = self.ids.fetch_add(1, Ordering::SeqCst) + 1;
        let id = format!(
            "s{}-{:x}",
            n,
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .map(|d| d.as_nanos())
                .unwrap_or(0)
        );
        let cfg = LoopConfig {
            model: req.model,
            system_prompt,
            max_steps: req.max_steps.unwrap_or(8).clamp(1, MAX_STEPS_CAP),
            max_tool_calls_per_step: req.max_tool_calls_per_step.unwrap_or(4).clamp(1, 16),
            max_tokens: req.max_tokens.unwrap_or(2048).clamp(64, MAX_TOKENS_CAP),
        };
        let opts = TurnOptions {
            max_tools_per_request: Some(req.max_tools_per_request.unwrap_or(8).clamp(1, 64)),
            budget: req.context_tokens.map(|ctx| {
                (
                    ContextBudget {
                        max_context_tokens: ctx.clamp(512, 1 << 20),
                        reserve_for_output: cfg.max_tokens as usize,
                    },
                    Arc::new(CharTokenCounter) as Arc<dyn citrate_agent_loop::TokenCounter>,
                )
            }),
            pinned_tools,
        };
        let session = Arc::new(Session {
            id: id.clone(),
            cfg,
            opts,
            specs,
            hic_aware: req.hic_aware,
            taint: TaintState::default(),
            llm: (self.llm_factory)(&req.llm),
            history: Mutex::new(Vec::new()),
            log: Mutex::new(EventLog {
                next_seq: 0,
                events: VecDeque::new(),
            }),
            notify: tokio::sync::Notify::new(),
            stop: StopFlag::default(),
            busy: AtomicBool::new(false),
            pending: Arc::new(Mutex::new(HashMap::new())),
            skills: self.skills.clone(),
            toolchain: self.toolchain.clone(),
            runs: Mutex::new(VecDeque::new()),
        });
        sessions.insert(id.clone(), session);
        Ok(id)
    }

    pub fn get(&self, id: &str) -> Option<Arc<Session>> {
        self.sessions.lock().ok().and_then(|s| s.get(id).cloned())
    }

    /// The tools a turn or workflow in this session can call: core-hosted ones park on core, and
    /// the sidecar-hosted ones (skills, toolchain, MCP, learn, capsules) run here.
    fn registry_for(
        &self,
        session: &Arc<Session>,
        capsules: Option<Arc<CapsuleDispatch>>,
    ) -> ToolRegistry {
        let core = Arc::new(CoreHost {
            pending: session.pending.clone(),
            deadline: self.core_tool_deadline,
            stop: session.stop.clone(),
            hic_aware: session.hic_aware,
        });
        let mut registry = ToolRegistry::new(session.specs.clone())
            .with_host(HostKind::Core, core)
            .with_taint(session.taint.clone());
        let skill_host = session.skills.clone().map(SkillHost::new);
        let capsule_host = capsules.map(|d| CapsuleHost { dispatch: d });
        let toolchain = session.toolchain.clone();
        let mcp_host = self
            .mcp
            .clone()
            .map(|h| McpToolHost::new(h, session.stop.clone()));
        let learn_host = self
            .learn
            .clone()
            .map(|svc| crate::learn::LearnToolHost::new(svc, session.clone()));
        if skill_host.is_some()
            || capsule_host.is_some()
            || toolchain.is_some()
            || mcp_host.is_some()
            || learn_host.is_some()
        {
            registry = registry.with_host(
                HostKind::Sidecar,
                Arc::new(SidecarHost {
                    skills: skill_host,
                    toolchain,
                    mcp: mcp_host,
                    capsules: capsule_host,
                    learn: learn_host,
                }),
            );
        }
        registry
    }

    /// HUP-S3.4: run a workflow in this session on the blocking pool. Refuses while a turn or
    /// another workflow is running. Returns the run id; read it with [`SessionManager::run_view`].
    pub fn run_workflow(
        &self,
        id: &str,
        wf: Workflow,
        capsules: Option<Arc<CapsuleDispatch>>,
    ) -> Result<String, SessionError> {
        let session = self.get(id).ok_or(SessionError::NotFound)?;
        if session
            .busy
            .compare_exchange(false, true, Ordering::SeqCst, Ordering::SeqCst)
            .is_err()
        {
            return Err(SessionError::Busy);
        }
        let n = self.run_ids.fetch_add(1, Ordering::SeqCst) + 1;
        let run_id = format!("wr-{n}");
        session.set_run(
            &run_id,
            RunState::Running {
                workflow_id: wf.id.clone(),
            },
        );
        let registry = self.registry_for(&session, capsules);
        let s = session.clone();
        let rid = run_id.clone();
        tokio::task::spawn_blocking(move || {
            let sink = SessionSink(s.clone());
            let mut history = s.history.lock().map(|h| h.clone()).unwrap_or_default();
            let out = run_verified_workflow(
                &s.id,
                &s.cfg,
                &s.opts,
                s.llm.as_ref(),
                &registry,
                &sink,
                &s.stop,
                &mut history,
                &wf,
            );
            if let Ok(mut h) = s.history.lock() {
                *h = history;
            }
            s.set_run(
                &rid,
                match out {
                    Ok(run) => RunState::Verified(Box::new(run)),
                    Err(e) => RunState::Unverified {
                        workflow_id: wf.id.clone(),
                        reason: e.to_string(),
                    },
                },
            );
            s.busy.store(false, Ordering::SeqCst);
            s.notify.notify_waiters();
        });
        Ok(run_id)
    }

    /// HUP-S3.4: one workflow run of this session.
    pub fn run_view(&self, id: &str, run_id: &str) -> Result<RunView, SessionError> {
        let session = self.get(id).ok_or(SessionError::NotFound)?;
        let st = session.run(run_id).ok_or(SessionError::NotFound)?;
        Ok(RunView::of(run_id, &st))
    }

    /// Start one user turn on the blocking pool. Refuses a second concurrent turn.
    pub fn send(
        &self,
        id: &str,
        text: String,
        capsules: Option<Arc<CapsuleDispatch>>,
    ) -> Result<(), SessionError> {
        let session = self.get(id).ok_or(SessionError::NotFound)?;
        if text.trim().is_empty() {
            return Err(SessionError::Invalid("message text is empty".into()));
        }
        if session
            .busy
            .compare_exchange(false, true, Ordering::SeqCst, Ordering::SeqCst)
            .is_err()
        {
            return Err(SessionError::Busy);
        }
        let registry = self.registry_for(&session, capsules);
        let s = session.clone();
        tokio::task::spawn_blocking(move || {
            let sink = SessionSink(s.clone());
            let mut history = s.history.lock().map(|h| h.clone()).unwrap_or_default();
            run_turn_with(
                &s.cfg,
                &s.opts,
                s.llm.as_ref(),
                &registry,
                &sink,
                &s.stop,
                &mut history,
                &text,
            );
            if let Ok(mut h) = s.history.lock() {
                *h = history;
            }
            s.busy.store(false, Ordering::SeqCst);
            s.notify.notify_waiters();
        });
        Ok(())
    }

    pub fn stop(&self, id: &str) -> Result<(), SessionError> {
        let s = self.get(id).ok_or(SessionError::NotFound)?;
        s.stop.stop();
        Ok(())
    }

    pub fn stop_all(&self) -> usize {
        let list: Vec<Arc<Session>> = self
            .sessions
            .lock()
            .map(|s| s.values().cloned().collect())
            .unwrap_or_default();
        for s in &list {
            s.stop.stop();
        }
        list.len()
    }

    pub fn close(&self, id: &str) -> Result<(), SessionError> {
        let s = self
            .sessions
            .lock()
            .ok()
            .and_then(|mut m| m.remove(id))
            .ok_or(SessionError::NotFound)?;
        s.stop.stop();
        Ok(())
    }

    pub fn count(&self) -> usize {
        self.sessions.lock().map(|s| s.len()).unwrap_or(0)
    }
}

/// Parse a `tool_results` status into an outcome.
pub fn outcome_from(req: ToolResultReq) -> Result<ToolOutcome, SessionError> {
    let untrusted = match req.trust.as_deref() {
        None | Some("trusted") => false,
        Some("untrusted") => true,
        Some(other) => {
            return Err(SessionError::Invalid(format!(
                "unknown trust {other:?} (trusted | untrusted)"
            )))
        }
    };
    match req.status.as_str() {
        "ok" if untrusted => Ok(ToolOutcome::Untrusted(req.content)),
        "ok" => Ok(ToolOutcome::Ok(req.content)),
        "denied" => Ok(ToolOutcome::Denied(req.content)),
        "error" => Ok(ToolOutcome::Error(req.content)),
        other => Err(SessionError::Invalid(format!(
            "unknown status {other:?} (ok | denied | error)"
        ))),
    }
}
