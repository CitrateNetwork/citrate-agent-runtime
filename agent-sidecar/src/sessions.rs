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
//!   turn's system prompt carries the at most five skills that match that turn's request (US-3.2
//!   AC1) and the session gets a pinned, sidecar-hosted `skill_load` tool. Skills are instructions only; `skill_load` reads text and runs nothing.
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
//! - HUP-S5.1: when the browser is enabled (`CITRATE_HERMES_BROWSER=1`, default off), every
//!   session is offered the sidecar-hosted `browser_*` tools (names reserved). Page content is
//!   untrusted; after taint each effectful browser action waits for the member's decision on the
//!   browser control routes, so the sidecar host can honor explicit approval for those calls (and
//!   still declines every other effectful sidecar call, as before). Unset, nothing here changes.
//! - HUP-S5.2: when search is enabled (`CITRATE_HERMES_SEARCH=1`, default off), every session also
//!   offers the sidecar-hosted `web_search` and `read_url` tools ([`crate::search`]). Their output is
//!   untrusted, so a call taints the session. The two names are reserved while search is on.
//! - HUP-S3.4: a session can run a declarative workflow (`POST …/workflows`,
//!   [`crate::workflow_spec`]) through `citrate_agent_learn::run_verified_workflow`; a run whose
//!   verifiers all passed is kept (the last [`MAX_RUNS_KEPT`]) as the evidence a learn proposal
//!   needs. When learning is configured (`CITRATE_HERMES_LEARN_DIR`, default off), every session is
//!   also offered the sidecar-hosted `learn_propose` tool ([`crate::learn`]), which proposes from
//!   the session's last verified run and never persists anything itself.
//! - HUP-S2.1: a session opened with the member's grant document (`grants`, sent by citrate-core)
//!   is offered the sidecar-hosted file tools (`file_list`, `file_read`, `file_write`), each path
//!   checked against those grants at use, and its toolchain project folder is checked against them
//!   instead of `CITRATE_HERMES_TOOLCHAIN_ROOTS`. `POST /sessions/:id/grants` replaces the set. A
//!   session opened without a document is unchanged (no file tools).
//! - HUP-S10.3: a session opened with `unattended: true` (a daemon run) starts tainted, so every
//!   effectful call needs a member's explicit decision from its first step. Absent, nothing changes.
//! - HUP-S7.5: every session meters its turns ([`crate::metering`]): a `MeteringSink` observes the
//!   event stream and the model client reports provider token usage onto the open turn. Finished
//!   records go to the manager's `MeteringStore` (no conversation content).
//! - HUP-S9.3: when trajectory recording is configured (`CITRATE_HERMES_TRAJECTORIES`, default
//!   off), a session also carries a `TrajectoryRecorder`, exported (verified turns only, redacted)
//!   when the session closes ([`crate::trajectory`]).
//! - HUP-S2.9: a session opened with a grant document, when a checkpoint store is configured, also
//!   offers the sidecar-hosted `fs_write`, `fs_edit`, `fs_delete` and `fs_rename` tools
//!   ([`crate::files`]) on that document, and its `file_write` and `sheet_write` are checkpointed
//!   too (without a store they write nothing). A session without a grant document gets the `fs_*`
//!   tools only with `CITRATE_HERMES_FILES=1` and a grants file. Each change is checked against
//!   the folder grants and the default-deny list, then checkpointed under the session id, so the
//!   member can undo it through the `/checkpoints` routes.
//! - US-2.2 AC2: when `shell_run` is enabled (`CITRATE_HERMES_SHELL_RUN=1`, default off), every
//!   session opened with folder grants also offers the sidecar-hosted `shell_run` tool
//!   ([`crate::shell_run`]): each command waits for the member's decision on the session's
//!   `/shell` routes and runs only in the OS sandbox. The name is reserved while it is on.

use std::collections::{HashMap, VecDeque};
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::sync::mpsc;
use std::sync::{Arc, Mutex, RwLock};
use std::time::{Duration, Instant};

use citrate_agent_browser::tools::{self as browser_tools, BrowserToolHost};
use citrate_agent_browser::BrowserService;
use citrate_agent_core::capsule::dispatch::CapsuleDispatch;
use citrate_agent_learn::{run_verified_workflow_reviewed, Evidence, VerifiedRun};
use citrate_agent_loop::retrieval::{
    Embedder, HybridRetriever, ModelTokenCounter, RetrievalMode, TokenCounting, Tokenizer,
};
use citrate_agent_loop::skills::{
    skill_load_spec, SkillHost, SkillLibrary, SkillSource, SkillTurnIndex, SKILL_LOAD_TOOL,
};
use citrate_agent_loop::{
    run_turn_with, ContextBudget, Event, EventSink, HostKind, LlmClient, LlmSelfReviewer,
    LoopConfig, Message, SelfReviewer, StopFlag, TaintState, ToolCall, ToolHost, ToolOutcome,
    ToolRegistry, ToolSpec, TurnContext, TurnOptions, Workflow,
};

/// US-1.3 AC2: the most tokens one recorded self-review may use.
pub const SELF_REVIEW_MAX_TOKENS: u32 = 160;
use citrate_agent_mcp_host::{McpHost, McpToolHost, ServerStatus};
use citrate_agent_metering::{MeteringSink, SystemClock};
use citrate_agent_trajectory::TrajectoryRecorder;
use serde::{Deserialize, Serialize};

use crate::anchor::AnchorService;
use crate::decide::DecideService;
use crate::files::{FileTools, FileToolsHost};
use crate::grants::{FileToolHost, GrantSummary, SessionGrants};
use crate::metering::{MeteredLlm, MeteringStore, TeeSink};
use crate::sheets::SheetToolHost;
use crate::shell_run::{
    shell_run_spec, ShellPending, ShellRunConfig, ShellRunHost, ShellRunSession, SHELL_RUN_TOOL,
};
use crate::toolchain::ToolchainHost;
use crate::trajectory::{export_session, ExportSummary, TrajectoryConfig};
use crate::workers::WorkerSet;
use citrate_agent_checkpoints::CheckpointStore;
use citrate_agent_search::SearchHost;

/// The toolchain as the session manager holds it: in process ([`ToolchainHost`], tests) or in
/// its worker process ([`crate::workers::RemoteToolHost`], HUP-S1.9). A session opened with
/// folder grants (HUP-S2.1) gets a host scoped to them: its project folder must be covered by live
/// read and write folder grants, checked again at every call, and `CITRATE_HERMES_TOOLCHAIN_ROOTS`
/// does not apply.
pub trait ToolchainBackend: ToolHost {
    /// This toolchain, checked against `grants` instead of its env roots.
    fn scoped_to(&self, grants: Arc<SessionGrants>) -> Result<Arc<dyn ToolHost>, String>;
}

impl ToolchainBackend for ToolchainHost {
    fn scoped_to(&self, grants: Arc<SessionGrants>) -> Result<Arc<dyn ToolHost>, String> {
        Ok(Arc::new(self.for_grants(grants)?))
    }
}

/// At most this many open sessions (a session is a conversation, not a request).
pub const MAX_SESSIONS: usize = 8;
// When the table is full, a new session replaces the idle session the app used least recently
// (sessions mid-turn are never replaced). Sessions the app opened and never closed (a Stop, a
// reload) therefore cannot fill the table for good.
/// Events kept per session for replay; older ones are dropped (clients read by sequence).
pub const EVENT_LOG_CAP: usize = 2000;
/// Upper bounds a client may request.
pub const MAX_STEPS_CAP: u32 = 32;
pub const MAX_TOKENS_CAP: u32 = 8192;
/// Longest a long-poll may wait.
pub const MAX_WAIT_MS: u64 = 25_000;
/// US-3.2 AC1: the most skills surfaced in one turn's system prompt.
pub use citrate_agent_loop::skills::SKILLS_PER_TURN;
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
/// HUP-S10.3: the taint source an unattended (daemon) session starts with. It appears in the
/// `hic_reason` of every effectful call such a session makes.
pub const UNATTENDED_TAINT_SOURCE: &str = "a scheduled daemon run nobody is watching";

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

/// HUP-S1.2: the model's tokenizer for an endpoint (production: llama-server `/tokenize` on a
/// loopback endpoint). `Err` says why there is none; the session then estimates and reports it.
pub type TokenizerFactory =
    Arc<dyn Fn(&LlmEndpoint) -> Result<Arc<dyn Tokenizer>, String> + Send + Sync>;

/// HUP-S1.2: the embedding model for a session's endpoint (production: `CITRATE_HERMES_EMBED_URL`,
/// else the loopback chat server's `/v1/embeddings`). `Err` says why there is none; the session
/// then ranks lexically and reports it.
pub type EmbedderFactory =
    Arc<dyn Fn(&LlmEndpoint) -> Result<Arc<dyn Embedder>, String> + Send + Sync>;

/// US-1.4 AC1: the most tool schemas in one request by default, pinned tools (`skill_load`, a
/// persona's emphasis) and tools already in use included. `maxToolsPerRequest` is the retrieval
/// budget inside it; a session that asks for a larger budget gets that as its ceiling instead.
pub const TOOL_SCHEMA_CEILING: usize = 8;

/// Why a session estimates tokens when the sidecar was built without a tokenizer.
pub const NO_TOKENIZER_REASON: &str = "this sidecar has no tokenizer configured";
/// Why a session ranks lexically when the sidecar was built without an embedder.
pub const NO_EMBEDDER_REASON: &str = "this sidecar has no embedding endpoint configured";

/// HUP-S1.2 (US-1.4 AC1): how a session counts tokens and ranks tools and skills, as `POST
/// /sessions` and `GET /sessions/:id/retrieval` report it. `token_counting` is absent when the
/// session has no context budget (nothing is counted).
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct RetrievalReport {
    #[serde(skip_serializing_if = "Option::is_none")]
    pub token_counting: Option<TokenCounting>,
    pub retrieval: RetrievalMode,
    /// The most tool schemas in one request, pinned and in-use tools included.
    pub max_tool_schemas: usize,
}

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
    /// HUP-S1.2: retrieve at most this many tool schemas per request (default 8). Every request
    /// stays within [`TOOL_SCHEMA_CEILING`] (or this, if larger), pinned and in-use tools included.
    pub max_tools_per_request: Option<usize>,
    /// HUP-S1.2: the model's context window in tokens; when given, every request is compacted to
    /// fit (or the turn fails honestly).
    pub context_tokens: Option<usize>,
    /// HUP-S2.7: core confirms that a tool call marked `hic: "required"` always goes to a person
    /// for an explicit decision (no auto-approval, no budget path). Absent = false: the sidecar then
    /// declines tainted effectful core calls itself.
    #[serde(default)]
    pub hic_aware: bool,
    /// HUP-S2.1: the member's grant document (`citrate-agent-grants` `GrantState` JSON). Absent =
    /// no file tools, and the toolchain keeps its env roots.
    #[serde(default)]
    pub grants: Option<serde_json::Value>,
    /// HUP-S2.5: capsule folder mounts (resolved against `grants` at every call) and the member's
    /// egress consent. Absent = capsules get no folder and no address.
    #[serde(default)]
    pub capsule_sandbox: Option<crate::capsule_sandbox::CapsuleSandboxDoc>,
    /// HUP-S10.3: a scheduled daemon run nobody is watching. The session starts tainted (source
    /// [`UNATTENDED_TAINT_SOURCE`]), so every effectful call needs a member's explicit decision
    /// from the first step, or is declined here when core is not `hic_aware`. Read-only calls run
    /// as usual. Absent = false: nothing changes. The taint is never cleared for such a session.
    #[serde(default)]
    pub unattended: bool,
    /// HUP-S3.3: a shipped persona id. Its skill allowlist decides which skills the session
    /// offers, and its tool emphasis pins up to four of the session's own tools into every request.
    /// The persona's prompt fragment is composed by the client. Absent = no persona: nothing
    /// changes.
    #[serde(default)]
    pub persona: Option<String>,
    /// HUP-S3.3 (US-3.3 AC3): a member-defined persona instead of `persona` (checked here with
    /// the same rules as `POST /personas/check`). Never both.
    #[serde(default)]
    pub custom_persona: Option<citrate_agent_loop::personas::CustomPersona>,
}

/// HUP-S3.3: what a session did with its persona (`POST /sessions` answers it as `persona`).
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct PersonaReport {
    pub id: String,
    /// Allowlisted skills this session offers (empty when the sidecar has no skills library).
    pub skills_offered: Vec<String>,
    /// Allowlisted skills that are not installed, so not offered.
    pub skills_missing: Vec<String>,
    /// False when the persona names no skills (a custom persona): the skills are then unchanged.
    pub skills_restricted: bool,
    /// The session's own tools pinned into every request, in emphasis order.
    pub pinned_tools: Vec<String>,
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
    /// HUP-S1.1: core-hosted tool calls this session is waiting on (no result posted yet). A view
    /// that comes back after a reload uses it to finish or honestly close calls it lost track of.
    pub pending_core_calls: Vec<String>,
}

/// HUP-S1.1: one open session, as listed by `GET /sessions` (no history, no prompt, no keys).
#[derive(Debug, Clone, Serialize, PartialEq, Eq)]
#[serde(rename_all = "camelCase")]
pub struct SessionSummary {
    pub id: String,
    pub model: String,
    pub busy: bool,
    pub last_seq: u64,
    /// The persona the session applies, if any.
    pub persona: Option<String>,
    pub pending_core_calls: Vec<String>,
}

struct EventLog {
    next_seq: u64,
    events: VecDeque<Envelope>,
}

/// HUP-S10.3: a session's starting taint. An unattended (daemon) session starts in the HIC
/// downgrade, as if it had already read untrusted content.
fn initial_taint(unattended: bool) -> TaintState {
    let taint = TaintState::default();
    if unattended {
        taint.taint(
            UNATTENDED_TAINT_SOURCE,
            "a scheduled run has no member watching, so every change it proposes needs an explicit decision",
        );
    }
    taint
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
    /// HUP-S6.3: present when this session was opened with the toolchain enabled. HUP-S1.9: in
    /// production this is a [`crate::workers::RemoteToolHost`] over the toolchain worker process.
    toolchain: Option<Arc<dyn ToolHost>>,
    /// HUP-S6.3 → S6.4: the raw reports of this session's toolchain runs, for core's deploy gate
    /// (present with the toolchain).
    toolchain_reports: Option<Arc<crate::toolchain_reports::ToolchainReports>>,
    /// HUP-S7.5: derives one metering record per turn from the event stream.
    metering: Arc<MeteringSink>,
    /// Where this session's finished metering records go.
    metering_store: Arc<MeteringStore>,
    /// HUP-S9.3: present only when trajectory recording is configured.
    trajectory: Option<(Arc<TrajectoryRecorder>, Arc<TrajectoryConfig>)>,
    /// HUP-S2.1: present when this session was opened with a grant document.
    grants: Option<Arc<SessionGrants>>,
    /// HUP-S2.5: what this session's capsule calls may mount and reach.
    capsule_sandbox: Arc<crate::capsule_sandbox::SessionSandbox>,
    /// HUP-S2.9: present when this session was opened with the file tools enabled.
    files: Option<Arc<FileTools>>,
    /// HUP-S3.4: workflow runs, oldest first (at most [`MAX_RUNS_KEPT`]).
    runs: Mutex<VecDeque<(String, RunState)>>,
    /// When the app last used this session (the manager's use counter): a full table replaces
    /// the idle session used least recently.
    last_used: AtomicU64,
    /// HUP-S3.3: present when this session was opened with a persona.
    persona: Option<PersonaReport>,
    /// HUP-S1.2: the session's token counter (present when it has a context budget).
    token_counter: Option<Arc<ModelTokenCounter>>,
    /// HUP-S1.2: ranks the session's tools and skills.
    retriever: Arc<HybridRetriever>,
    /// US-2.2 AC2: present when `shell_run` is on and the session has folder grants.
    shell: Option<Arc<ShellRunSession>>,
    /// HUP-S5.3: the session's own model endpoint, which `browser_pick` asks through the metered
    /// `decide()` slot (local grammar backend unless the member opted into Jev for the origin).
    decide_llm: LlmEndpoint,
    /// HUP-S4.1: the MCP specs this session was offered (calls to tools that changed since are
    /// refused), and its MCP approval cards (present only for an HIC-aware client).
    mcp_offered: Option<Arc<HashMap<String, ToolSpec>>>,
    mcp_approvals: Option<Arc<crate::mcp_approvals::McpApprovals>>,
}

impl Session {
    /// The conversation so far (what the model is sent next turn, after the system prompt).
    pub fn history_snapshot(&self) -> Vec<Message> {
        self.history.lock().map(|h| h.clone()).unwrap_or_default()
    }

    /// HUP-S6 US-6.2: the deploy guard over this session's toolchain reports (`None` without
    /// the toolchain).
    pub fn deploy_guard(&self) -> Option<crate::deploy_guard::DeployGuard> {
        self.toolchain_reports
            .clone()
            .map(crate::deploy_guard::DeployGuard::new)
    }

    /// HUP-S6.3 → S6.4: the latest toolchain report per (project, tool), only `project`'s when
    /// given. `None` when this session has no toolchain.
    pub fn toolchain_reports(
        &self,
        project: Option<&str>,
    ) -> Option<Vec<crate::toolchain_reports::StoredReport>> {
        self.toolchain_reports.as_ref().map(|r| r.list(project))
    }

    /// HUP-S4.1: the MCP cards waiting for the member (`None` when the session has none).
    pub fn mcp_pending(&self) -> Option<Vec<crate::mcp_approvals::McpPending>> {
        self.mcp_approvals.as_ref().map(|a| a.pending())
    }

    /// HUP-S4.1: the waiting card `id` (for its decision record).
    pub fn mcp_waiting(&self, id: &str) -> Option<crate::mcp_approvals::McpPending> {
        self.mcp_approvals.as_ref().and_then(|a| a.waiting(id))
    }

    /// HUP-S4.1: the member's decision on a waiting MCP card; it must carry the subject shown.
    pub fn mcp_decide(&self, id: &str, allow: bool, subject: &str) -> Result<(), SessionError> {
        let a = self.mcp_approvals.as_ref().ok_or(SessionError::NotFound)?;
        a.decide(id, allow, subject).map_err(SessionError::Invalid)
    }

    /// HUP-S1.2: how this session counts tokens and ranks tools and skills right now.
    pub fn retrieval_report(&self) -> RetrievalReport {
        RetrievalReport {
            token_counting: self.token_counter.as_ref().map(|c| c.mode()),
            retrieval: self.retriever.mode(),
            max_tool_schemas: self.opts.max_tools_total.unwrap_or(self.specs.len()),
        }
    }

    /// HUP-S1.2: count one probe and embed one probe, so the report is known before the first
    /// turn. Blocking (HTTP): call it on the blocking pool.
    pub fn probe_retrieval(&self) -> RetrievalReport {
        if let Some(c) = &self.token_counter {
            c.probe();
        }
        self.retriever.probe();
        self.retrieval_report()
    }

    /// US-2.2 AC2: the commands waiting for the member (`None` when the session has no
    /// `shell_run`).
    pub fn shell_pending(&self) -> Option<Vec<ShellPending>> {
        self.shell.as_ref().map(|s| s.approvals().pending())
    }

    /// US-2.2 AC2: the member's decision on a waiting command; it must carry the argv and cwd
    /// that were shown.
    pub fn shell_decide(
        &self,
        id: &str,
        allow: bool,
        argv: &[String],
        cwd: &str,
    ) -> Result<(), SessionError> {
        let s = self.shell.as_ref().ok_or(SessionError::NotFound)?;
        s.approvals()
            .decide(id, allow, argv, cwd)
            .map_err(SessionError::Invalid)
    }

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
            pending_core_calls: self.pending_core_calls(),
        }
    }

    /// HUP-S1.1: the core-hosted call ids waiting for a result, sorted.
    pub fn pending_core_calls(&self) -> Vec<String> {
        let mut ids: Vec<String> = self
            .pending
            .lock()
            .map(|p| p.keys().cloned().collect())
            .unwrap_or_default();
        ids.sort();
        ids
    }

    /// HUP-S1.1: this session as `GET /sessions` lists it.
    pub fn summary(&self) -> SessionSummary {
        let last_seq = self.log.lock().map(|l| l.next_seq).unwrap_or(0);
        SessionSummary {
            id: self.id.clone(),
            model: self.cfg.model.clone(),
            busy: self.is_busy(),
            last_seq,
            persona: self.persona.as_ref().map(|p| p.id.clone()),
            pending_core_calls: self.pending_core_calls(),
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

    /// HUP-S2.1: this session's folder grants (`None` when it was opened without a document).
    /// HUP-S3.3: what this session did with its persona, if it has one.
    pub fn persona(&self) -> Option<&PersonaReport> {
        self.persona.as_ref()
    }

    /// The names of every tool this session offers (core-hosted and sidecar-hosted).
    pub fn tool_names(&self) -> Vec<String> {
        self.specs.iter().map(|t| t.name.clone()).collect()
    }

    pub fn grants(&self) -> Option<&Arc<SessionGrants>> {
        self.grants.as_ref()
    }

    /// HUP-S2.1: replace the grant set. A refused document leaves the session with no grants.
    pub fn replace_grants(&self, doc: &serde_json::Value) -> Result<GrantSummary, SessionError> {
        let g = self.grants.as_ref().ok_or(SessionError::NoGrants)?;
        g.replace(doc).map_err(SessionError::Invalid)
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
pub(crate) struct CapsuleHost {
    dispatch: Arc<CapsuleDispatch>,
    /// HUP-S2.5: the session's sandbox, resolved at every call.
    sandbox: Arc<crate::capsule_sandbox::SessionSandbox>,
}

impl ToolHost for CapsuleHost {
    fn execute(&self, call: &ToolCall) -> ToolOutcome {
        let args: serde_json::Value = serde_json::from_str(if call.arguments.trim().is_empty() {
            "{}"
        } else {
            &call.arguments
        })
        .unwrap_or(serde_json::Value::Object(Default::default()));
        match self
            .dispatch
            .call_json_sandboxed(&call.name, &args, self.sandbox.as_ref())
        {
            Ok(v) => ToolOutcome::Ok(v.to_string()),
            Err(e) => ToolOutcome::Error(e.to_string()),
        }
    }
}

/// The one host for [`HostKind::Sidecar`] tools: `skill_load` goes to the skill library, the
/// toolchain tools to the toolchain host (when enabled), an offered `mcp__…` tool to its MCP
/// server (HUP-S4.1), a `browser_*` tool to the browser (HUP-S5.1, when enabled), anything else
/// to the capsule dispatch (when capsules are loaded).
#[derive(Default)]
pub(crate) struct SidecarHost {
    pub(crate) files: Option<FileToolHost>,
    /// HUP-S10.2: the sheet tools, present with the file tools.
    pub(crate) sheets: Option<SheetToolHost>,
    pub(crate) skills: Option<SkillHost>,
    pub(crate) toolchain: Option<Arc<dyn ToolHost>>,
    /// HUP-S2.9: the checkpointed file tools (`fs_write`, `fs_edit`, `fs_delete`, `fs_rename`).
    pub(crate) fs_tools: Option<FileToolsHost>,
    /// HUP-S5.2: `web_search` and `read_url`, when search is enabled.
    pub(crate) search: Option<Arc<SearchHost>>,
    pub(crate) mcp: Option<McpToolHost>,
    pub(crate) capsules: Option<CapsuleHost>,
    pub(crate) learn: Option<crate::learn::LearnToolHost>,
    pub(crate) browser: Option<BrowserToolHost>,
    /// US-2.2 AC2: `shell_run`, when on and the session has grants.
    pub(crate) shell: Option<ShellRunHost>,
}

impl ToolHost for SidecarHost {
    fn execute(&self, call: &ToolCall) -> ToolOutcome {
        if call.name == SHELL_RUN_TOOL {
            if let Some(s) = &self.shell {
                return s.execute(call);
            }
        }
        if browser_tools::handles(&call.name) {
            if let Some(b) = &self.browser {
                return b.execute(call);
            }
        }
        if call.name == crate::learn::LEARN_PROPOSE_TOOL {
            if let Some(l) = &self.learn {
                return l.execute(call);
            }
        }
        if crate::grants::handles(&call.name) {
            if let Some(f) = &self.files {
                return f.execute(call);
            }
        }
        if crate::sheets::handles(&call.name) {
            if let Some(s) = &self.sheets {
                return s.execute(call);
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
        if SearchHost::handles(&call.name) {
            if let Some(s) = &self.search {
                return s.execute(call);
            }
        }
        if FileTools::handles(&call.name) {
            if let Some(f) = &self.fs_tools {
                return f.execute(call);
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

    /// HUP-S5.1: the browser can put an action in front of the member (its decision routes);
    /// HUP-S4.1: so can MCP, through the session's MCP approval cards (HIC-aware clients only).
    /// Without either this stays false, so the loop declines as before.
    fn honors_explicit_approval(&self) -> bool {
        self.browser.is_some()
            || self
                .mcp
                .as_ref()
                .is_some_and(|m| m.honors_explicit_approval())
    }

    fn execute_with_explicit_approval(&self, call: &ToolCall, reason: &str) -> ToolOutcome {
        if let Some(m) = &self.mcp {
            if m.handles(&call.name) && m.honors_explicit_approval() {
                return m.execute_with_explicit_approval(call, reason);
            }
        }
        match &self.browser {
            Some(b) if browser_tools::handles(&call.name) => {
                b.execute_with_explicit_approval(call, reason)
            }
            _ => ToolOutcome::Denied(
                "this session read untrusted content and this action needs a member's explicit approval, which this tool's host cannot ask for"
                    .into(),
            ),
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
    /// HUP-S2.1: the session was opened without a grant document, so it has no grants to replace.
    NoGrants,
}

/// All sessions.
pub struct SessionManager {
    sessions: Mutex<HashMap<String, Arc<Session>>>,
    llm_factory: LlmFactory,
    tokenizer_factory: Option<TokenizerFactory>,
    embedder_factory: Option<EmbedderFactory>,
    core_tool_deadline: Duration,
    ids: AtomicU64,
    /// HUP-S3.2: the skills library offered to new sessions. HUP-S3.4: reloaded from
    /// `skill_sources` after the member accepts a learned skill, so it joins the next session
    /// without a sidecar restart (sessions already open keep the library they started with).
    skills: RwLock<Option<Arc<SkillLibrary>>>,
    skill_sources: Vec<SkillSource>,
    toolchain: Option<Arc<dyn ToolchainBackend>>,
    mcp: Option<Arc<McpHost>>,
    browser: Option<Arc<BrowserService>>,
    search: Option<Arc<SearchHost>>,
    decide: Arc<DecideService>,
    learn: Option<Arc<crate::learn::LearnService>>,
    run_ids: AtomicU64,
    files: Option<Arc<FileTools>>,
    checkpoints: Option<Arc<CheckpointStore>>,
    /// HUP-S2.1: the member's home, for resolving grants (`~`, the deny list). `None` = sessions
    /// with a grant document are refused.
    grants_home: Option<std::path::PathBuf>,
    /// HUP-S1.9: the worker processes behind sidecar-hosted tools (reported on `/workers`).
    workers: Arc<WorkerSet>,
    metering: Arc<MeteringStore>,
    trajectories: Option<Arc<TrajectoryConfig>>,
    anchor: Option<Arc<AnchorService>>,
    /// HUP-S4.4: core's saved MCP server list; the probe starts only entries saved there.
    mcp_registry: Option<std::path::PathBuf>,
    /// Use counter for [`Session::last_used`].
    uses: AtomicU64,
    /// US-2.2 AC2: `shell_run` for sessions opened with folder grants (default off).
    shell_run: Option<Arc<ShellRunConfig>>,
    /// HUP-S2.6: the one writer of the decision records the nightly anchor batches.
    records: Option<Arc<citrate_agent_records::DecisionLog>>,
    /// US-1.3 AC2: ask the model for a self-review of every workflow step attempt and record it
    /// in the session's event log as an opinion (never part of the verdict).
    self_review: bool,
}

impl SessionManager {
    pub fn new(llm_factory: LlmFactory, core_tool_deadline: Duration) -> Self {
        SessionManager {
            sessions: Mutex::new(HashMap::new()),
            llm_factory,
            tokenizer_factory: None,
            embedder_factory: None,
            core_tool_deadline,
            ids: AtomicU64::new(0),
            skills: RwLock::new(None),
            skill_sources: Vec::new(),
            toolchain: None,
            mcp: None,
            browser: None,
            search: None,
            decide: Arc::new(DecideService::default()),
            learn: None,
            run_ids: AtomicU64::new(0),
            files: None,
            checkpoints: None,
            grants_home: None,
            workers: Arc::new(WorkerSet::default()),
            metering: Arc::new(MeteringStore::in_memory()),
            trajectories: None,
            anchor: None,
            mcp_registry: None,
            uses: AtomicU64::new(0),
            shell_run: None,
            records: None,
            self_review: false,
        }
    }

    /// HUP-S4.4: core's saved MCP server list (`mcp_probe::MCP_REGISTRY_ENV`).
    pub fn with_mcp_registry(mut self, path: impl Into<std::path::PathBuf>) -> Self {
        self.mcp_registry = Some(path.into());
        self
    }

    /// HUP-S4.4: the saved MCP server list the probe checks against, if configured.
    pub fn mcp_registry(&self) -> Option<&std::path::Path> {
        self.mcp_registry.as_deref()
    }

    /// US-1.3 AC2: record the model's self-review of every workflow step attempt as an opinion.
    pub fn with_self_review(mut self, on: bool) -> Self {
        self.self_review = on;
        self
    }

    /// Whether workflow runs record the model's self-review.
    pub fn self_review_enabled(&self) -> bool {
        self.self_review
    }

    /// HUP-S1.2: count each session's tokens with the model's tokenizer (default: none, so
    /// sessions estimate and say so).
    pub fn with_tokenizer(mut self, f: TokenizerFactory) -> Self {
        self.tokenizer_factory = Some(f);
        self
    }

    /// HUP-S1.2: rank each session's tools and skills with embeddings plus keywords (default:
    /// none, so sessions rank lexically and say so).
    pub fn with_embedder(mut self, f: EmbedderFactory) -> Self {
        self.embedder_factory = Some(f);
        self
    }

    /// US-2.2 AC2: offer `shell_run` to every new session opened with folder grants.
    pub fn with_shell_run(mut self, cfg: Arc<ShellRunConfig>) -> Self {
        self.shell_run = Some(cfg);
        self
    }

    /// Whether `shell_run` is on.
    pub fn shell_run_enabled(&self) -> bool {
        self.shell_run.is_some()
    }

    /// HUP-S2.6: record HIC decisions (ceremony bridge, browser actions, core's events) into this
    /// log, the one in the records directory the anchor batches (default none: nothing recorded).
    pub fn with_records(mut self, log: Arc<citrate_agent_records::DecisionLog>) -> Self {
        self.records = Some(log);
        self
    }

    /// HUP-S2.6: the decision records writer, when configured.
    pub fn records(&self) -> Option<Arc<citrate_agent_records::DecisionLog>> {
        self.records.clone()
    }

    /// HUP-S7.5: where finished metering records go (default: in memory for this process).
    pub fn with_metering(mut self, store: Arc<MeteringStore>) -> Self {
        self.metering = store;
        self
    }

    pub fn metering(&self) -> &Arc<MeteringStore> {
        &self.metering
    }

    /// HUP-S9.3: record trajectories in every new session (default off).
    pub fn with_trajectories(mut self, cfg: TrajectoryConfig) -> Self {
        self.trajectories = Some(Arc::new(cfg));
        self
    }

    pub fn trajectories(&self) -> Option<&Arc<TrajectoryConfig>> {
        self.trajectories.as_ref()
    }

    /// HUP-S7.3: the nightly anchor store served by the `/anchor/*` routes (default none).
    pub fn with_anchor(mut self, svc: Arc<AnchorService>) -> Self {
        self.anchor = Some(svc);
        self
    }

    pub fn anchor(&self) -> Option<&Arc<AnchorService>> {
        self.anchor.as_ref()
    }

    /// HUP-S2.1: resolve session grants against this home directory.
    pub fn with_grants_home(mut self, home: impl Into<std::path::PathBuf>) -> Self {
        self.grants_home = Some(home.into());
        self
    }

    /// HUP-S2.9: serve the `/checkpoints` routes (list, undo a step, undo a session) from this
    /// store. Independent of the file tools, so changes stay undoable after the tools are off.
    pub fn with_checkpoints(mut self, store: Arc<CheckpointStore>) -> Self {
        self.checkpoints = Some(store);
        self
    }

    /// HUP-S2.9: offer the file tools to every new session. Their store also serves the
    /// `/checkpoints` routes unless one was set with [`SessionManager::with_checkpoints`].
    pub fn with_files(mut self, tools: Arc<FileTools>) -> Self {
        if self.checkpoints.is_none() {
            self.checkpoints = Some(tools.store().clone());
        }
        self.files = Some(tools);
        self
    }

    /// HUP-S2.9: the undo checkpoint store (`None` when undo is not configured).
    pub fn checkpoints(&self) -> Option<Arc<CheckpointStore>> {
        self.checkpoints.clone()
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

    /// HUP-S5.2: offer `web_search` and `read_url` to every new session.
    pub fn with_search(mut self, host: Arc<SearchHost>) -> Self {
        self.search = Some(host);
        self
    }

    /// HUP-S5.2: the search host, when search is enabled.
    pub fn search(&self) -> Option<Arc<SearchHost>> {
        self.search.clone()
    }

    /// HUP-S5.3: the `decide()` slot and its metering (the default has Jev off).
    pub fn with_decide(mut self, svc: Arc<DecideService>) -> Self {
        self.decide = svc;
        self
    }

    /// HUP-S5.3: the `decide()` service.
    pub fn decide_service(&self) -> Arc<DecideService> {
        self.decide.clone()
    }

    /// HUP-S5.1: offer the browser tools to every new session.
    pub fn with_browser(mut self, browser: Arc<BrowserService>) -> Self {
        self.browser = Some(browser);
        self
    }

    /// HUP-S5.1: the browser worker (`None` when the browser is off).
    pub fn browser(&self) -> Option<&Arc<BrowserService>> {
        self.browser.as_ref()
    }

    /// HUP-S6.3: offer the toolchain tools to every new session, executed by `host` (in
    /// production the toolchain worker process, HUP-S1.9). A session opened with folder grants
    /// (HUP-S2.1) gets the host scoped to its grants ([`ToolchainBackend::scoped_to`]).
    pub fn with_toolchain(mut self, host: Arc<dyn ToolchainBackend>) -> Self {
        self.toolchain = Some(host);
        self
    }

    /// HUP-S1.9: the worker processes this manager's tools run in.
    pub fn with_workers(mut self, workers: Arc<WorkerSet>) -> Self {
        self.workers = workers;
        self
    }

    /// HUP-S1.9: one status entry per worker kind (see [`WorkerSet::report`]).
    pub fn workers_report(&self) -> Vec<serde_json::Value> {
        self.workers.report()
    }

    /// HUP-S1.9: stop every worker process cleanly (sidecar shutdown).
    pub fn shutdown_workers(&self) {
        self.workers.shutdown();
    }

    /// Sidecar shutdown: stop every child process explicitly, not only by drop at exit (core
    /// kills the sidecar after its grace period, and a killed process runs no destructors): the
    /// workers, the browser (stopped and latched), SearXNG and the MCP servers. Idempotent.
    pub fn shutdown_children(&self) {
        self.stop_all();
        self.workers.shutdown();
        if let Some(b) = &self.browser {
            b.stop();
        }
        if let Some(s) = &self.search {
            s.shutdown();
        }
        if let Some(m) = &self.mcp {
            m.shutdown();
        }
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

    /// HUP-S3.3: the skills library new sessions start from (before a persona's allowlist).
    /// A snapshot: HUP-S3.4 reloads the library when the member accepts a learned skill.
    pub fn skills_library(&self) -> Option<Arc<SkillLibrary>> {
        self.skills()
    }

    /// HUP-S3.3: whether the toolchain tools (forge, slither, aderyn, medusa) are offered.
    pub fn toolchain_enabled(&self) -> bool {
        self.toolchain.is_some()
    }

    /// HUP-S3.2: offer this skills library to every new session. An empty library offers nothing.
    /// A library given this way is fixed: [`SessionManager::reload_skills`] has no sources to
    /// read again.
    pub fn with_skills(mut self, lib: Arc<SkillLibrary>) -> Self {
        self.skills = RwLock::new(if lib.is_empty() { None } else { Some(lib) });
        self
    }

    /// HUP-S3.2 + S3.4: load the skills library from these sources (in precedence order) and
    /// keep the sources, so [`SessionManager::reload_skills`] can read them again after the
    /// member accepts a learned skill. Sources that hold no skills yet offer nothing until then.
    pub fn with_skill_sources(mut self, sources: Vec<SkillSource>) -> Self {
        let lib = SkillLibrary::load(&sources);
        self.skills = RwLock::new(if lib.is_empty() {
            None
        } else {
            Some(Arc::new(lib))
        });
        self.skill_sources = sources;
        self
    }

    /// The library new sessions are offered now (a snapshot).
    pub fn skills(&self) -> Option<Arc<SkillLibrary>> {
        match self.skills.read() {
            Ok(g) => g.clone(),
            Err(p) => p.into_inner().clone(),
        }
    }

    /// HUP-S3.4: read the skill sources again so a newly saved skill is offered to the next
    /// session. Returns how many skills new sessions are offered, or `None` when the library was
    /// not configured from sources (nothing to reload). Sessions already open are unchanged.
    pub fn reload_skills(&self) -> Option<usize> {
        if self.skill_sources.is_empty() {
            return None;
        }
        let lib = SkillLibrary::load(&self.skill_sources);
        let n = lib.len();
        let next = if lib.is_empty() {
            None
        } else {
            Some(Arc::new(lib))
        };
        match self.skills.write() {
            Ok(mut g) => *g = next,
            Err(p) => *p.into_inner() = next,
        }
        Some(n)
    }

    pub fn create(&self, req: CreateSessionReq) -> Result<String, SessionError> {
        validate_endpoint(&req.llm.base_url).map_err(SessionError::Invalid)?;
        if req.model.trim().is_empty() {
            return Err(SessionError::Invalid("model is required".into()));
        }
        let persona = citrate_agent_loop::personas::session_persona(
            req.persona.as_deref(),
            req.custom_persona.as_ref(),
        )
        .map_err(SessionError::Invalid)?;
        // HUP-S3.3: the persona's skill allowlist decides which skills this session offers. An
        // allowlist with nothing installed offers no skills (and no `skill_load`), never others.
        // One snapshot of the (reloadable) library for the allowlist, the prompt section and
        // the session's `skill_load` host.
        let base_skills = self.skills();
        let (skills, persona_skills) = match (&persona, &base_skills) {
            (Some(p), Some(lib)) if p.restricts_skills() => {
                let (only, missing) = lib.restricted_to(&p.skills);
                let offered: Vec<String> = only.names().into_iter().map(String::from).collect();
                let lib = if only.is_empty() {
                    None
                } else {
                    Some(Arc::new(only))
                };
                (lib, Some((offered, missing, true)))
            }
            (Some(p), None) if p.restricts_skills() => {
                (None, Some((Vec::new(), p.skills.clone(), true)))
            }
            (Some(_), lib) => (
                lib.clone(),
                Some((
                    lib.as_ref()
                        .map(|l| l.names().into_iter().map(String::from).collect())
                        .unwrap_or_default(),
                    Vec::new(),
                    false,
                )),
            ),
            (None, lib) => (lib.clone(), None),
        };
        // HUP-S1.2: one retriever ranks this session's tools and its per-turn skills.
        let retriever = Arc::new(match &self.embedder_factory {
            None => HybridRetriever::lexical(NO_EMBEDDER_REASON),
            Some(f) => match f(&req.llm) {
                Ok(e) => HybridRetriever::new(e),
                Err(reason) => HybridRetriever::lexical(reason),
            },
        });
        let mut specs = req.tools;
        let mut system_prompt = req.system_prompt;
        // L-23: the persona's prompt fragment is rendered here from the checked persona (a shipped
        // id or a custom persona that passed `CustomPersona::check`), never taken from app state.
        if let Some(fragment) = citrate_agent_loop::personas::session_persona_fragment(
            req.persona.as_deref(),
            req.custom_persona.as_ref(),
        )
        .map_err(SessionError::Invalid)?
        {
            system_prompt = format!("{system_prompt}\n\n{fragment}");
        }
        let mut pinned_tools = Vec::new();
        let mut turn_context: Vec<Arc<dyn TurnContext>> = Vec::new();
        if let Some(lib) = &skills {
            if specs.iter().any(|t| t.name == SKILL_LOAD_TOOL) {
                return Err(SessionError::Invalid(format!(
                    "the tool name '{SKILL_LOAD_TOOL}' is reserved by the sidecar while skills are enabled"
                )));
            }
            // US-3.2 AC1: each turn carries the at most SKILLS_PER_TURN skills that match it,
            // ranked over the (persona-restricted) library; never the whole index.
            turn_context.push(Arc::new(
                SkillTurnIndex::new(lib.clone(), SKILLS_PER_TURN).with_ranker(retriever.clone()),
            ));
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
        if self.search.is_some() {
            if let Some(t) = specs.iter().find(|t| SearchHost::handles(&t.name)) {
                return Err(SessionError::Invalid(format!(
                    "the tool name '{}' is reserved by the sidecar while search is enabled",
                    t.name
                )));
            }
            specs.extend(SearchHost::specs());
        }
        if self.files.is_some() {
            if let Some(t) = specs.iter().find(|t| FileTools::handles(&t.name)) {
                return Err(SessionError::Invalid(format!(
                    "the tool name '{}' is reserved by the sidecar while the file tools are enabled",
                    t.name
                )));
            }
            specs.extend(FileTools::specs());
        }
        let mut mcp_offered = None;
        if let Some(mcp) = &self.mcp {
            if let Some(t) = specs.iter().find(|t| McpHost::reserved(&t.name)) {
                return Err(SessionError::Invalid(format!(
                    "the tool name '{}' is in the 'mcp__' namespace, which is reserved while MCP servers are configured",
                    t.name
                )));
            }
            let offered = mcp.specs();
            mcp_offered = Some(Arc::new(
                offered
                    .iter()
                    .map(|t| (t.name.clone(), t.clone()))
                    .collect::<HashMap<_, _>>(),
            ));
            specs.extend(offered);
        }
        // HUP-S4.1: MCP approval cards only for a client that shows `hic: required` to a person.
        let mcp_approvals = (self.mcp.is_some() && req.hic_aware)
            .then(|| Arc::new(crate::mcp_approvals::McpApprovals::default()));
        if self.browser.is_some() {
            if let Some(t) = specs.iter().find(|t| browser_tools::handles(&t.name)) {
                return Err(SessionError::Invalid(format!(
                    "the tool name '{}' is reserved by the sidecar while the browser is enabled",
                    t.name
                )));
            }
            specs.extend(browser_tools::specs());
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
        if self.shell_run.is_some() && specs.iter().any(|t| t.name == SHELL_RUN_TOOL) {
            return Err(SessionError::Invalid(format!(
                "the tool name '{SHELL_RUN_TOOL}' is reserved by the sidecar while shell_run is on"
            )));
        }
        let grants = match req.grants {
            None => None,
            Some(doc) => {
                let home = self.grants_home.as_ref().ok_or_else(|| {
                    SessionError::Invalid(
                        "folder grants need the member's home directory, which the sidecar does not know".into(),
                    )
                })?;
                if let Some(t) = specs
                    .iter()
                    .find(|t| crate::grants::handles(&t.name) || crate::sheets::handles(&t.name))
                {
                    return Err(SessionError::Invalid(format!(
                        "the tool name '{}' is reserved by the sidecar while folder grants are given",
                        t.name
                    )));
                }
                // HUP-S2.9: with an undo store, a grant session also gets the checkpointed fs_*
                // tools, checked against this same grant document.
                let fs_on_grants = self.checkpoints.is_some() && self.files.is_none();
                if fs_on_grants {
                    if let Some(t) = specs.iter().find(|t| FileTools::handles(&t.name)) {
                        return Err(SessionError::Invalid(format!(
                            "the tool name '{}' is reserved by the sidecar while folder grants are given",
                            t.name
                        )));
                    }
                }
                let g = SessionGrants::empty(home);
                g.replace(&doc).map_err(|e| {
                    SessionError::Invalid(format!("the grant document was refused: {e}"))
                })?;
                specs.extend(crate::grants::file_tool_specs());
                specs.extend(crate::sheets::sheet_tool_specs());
                if fs_on_grants {
                    specs.extend(FileTools::specs());
                }
                Some(Arc::new(g))
            }
        };
        let shell = match (&self.shell_run, &grants) {
            (Some(cfg), Some(g)) => {
                specs.push(shell_run_spec());
                Some(Arc::new(
                    ShellRunSession::new(cfg, g.clone()).map_err(SessionError::Invalid)?,
                ))
            }
            _ => None,
        };
        let capsule_sandbox = Arc::new(
            crate::capsule_sandbox::SessionSandbox::new(req.capsule_sandbox, grants.clone())
                .map_err(|e| SessionError::Invalid(format!("capsuleSandbox was refused: {e}")))?,
        );
        // HUP-S3.3: the persona's tool emphasis pins the session's own tools (never adds one).
        let persona = persona.map(|p| {
            let offered: Vec<String> = specs.iter().map(|t| t.name.clone()).collect();
            let pinned = p.pinned_tools(&offered);
            for t in &pinned {
                if !pinned_tools.contains(t) {
                    pinned_tools.push(t.clone());
                }
            }
            let (skills_offered, skills_missing, skills_restricted) =
                persona_skills.clone().unwrap_or_default();
            PersonaReport {
                id: p.id,
                skills_offered,
                skills_missing,
                skills_restricted,
                pinned_tools: pinned,
            }
        });
        let toolchain: Option<Arc<dyn ToolHost>> = match (&self.toolchain, &grants) {
            (Some(t), Some(g)) => Some(t.scoped_to(g.clone()).map_err(SessionError::Invalid)?),
            (Some(t), None) => Some(t.clone() as Arc<dyn ToolHost>),
            (None, _) => None,
        };
        // HUP-S6.3 → S6.4: keep each run's raw report for core's deploy gate; the model sees the
        // result without it.
        let toolchain_reports = toolchain
            .as_ref()
            .map(|_| Arc::new(crate::toolchain_reports::ToolchainReports::default()));
        let toolchain: Option<Arc<dyn ToolHost>> = match (toolchain, &toolchain_reports) {
            (Some(t), Some(r)) => Some(Arc::new(
                crate::toolchain_reports::CapturingToolchain::new(t, r.clone()),
            )),
            (t, _) => t,
        };
        // HUP-S2.9: a grant session's fs_* tools check the session's grant document (core's
        // grant store), not a grants file.
        let files = match (&grants, &self.checkpoints) {
            (Some(g), Some(store)) => Some(Arc::new(FileTools::new(
                store.clone(),
                crate::files::GrantSource::Session(g.clone()),
                g.home(),
            ))),
            _ => self.files.clone(),
        };
        let mut sessions = self
            .sessions
            .lock()
            .map_err(|_| SessionError::Invalid("internal".into()))?;
        let mut replaced = None;
        if sessions.len() >= MAX_SESSIONS {
            let victim = sessions
                .values()
                .filter(|s| !s.is_busy())
                .min_by_key(|s| s.last_used.load(Ordering::SeqCst))
                .map(|s| s.id.clone())
                .ok_or(SessionError::TooMany)?;
            replaced = sessions.remove(&victim);
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
        // US-1.4 AC1: token counts come from the model's tokenizer when it answers.
        let token_counter = req.context_tokens.map(|_| {
            Arc::new(match &self.tokenizer_factory {
                None => ModelTokenCounter::estimated(NO_TOKENIZER_REASON),
                Some(f) => match f(&req.llm) {
                    Ok(t) => ModelTokenCounter::new(t),
                    Err(reason) => ModelTokenCounter::estimated(reason),
                },
            })
        });
        let max_tools = req.max_tools_per_request.unwrap_or(8).clamp(1, 64);
        let opts = TurnOptions {
            max_tools_per_request: Some(max_tools),
            budget: req
                .context_tokens
                .zip(token_counter.clone())
                .map(|(ctx, c)| {
                    (
                        ContextBudget {
                            max_context_tokens: ctx.clamp(512, 1 << 20),
                            reserve_for_output: cfg.max_tokens as usize,
                        },
                        c as Arc<dyn citrate_agent_loop::TokenCounter>,
                    )
                }),
            pinned_tools,
            turn_context,
            selector: Some(retriever.clone() as Arc<dyn citrate_agent_loop::ToolSelector>),
            // US-1.4 AC1: at most TOOL_SCHEMA_CEILING schemas per request, pinned and in-use
            // tools included (or the session's own `maxToolsPerRequest`, if it asked for more).
            max_tools_total: Some(max_tools.max(TOOL_SCHEMA_CEILING)),
        };
        let metering = Arc::new(MeteringSink::new(
            id.clone(),
            cfg.model.clone(),
            specs.iter().map(|t| t.name.clone()).collect::<Vec<_>>(),
            Arc::new(SystemClock::new()),
        ));
        // HUP-S10.3: a daemon run (`unattended`) starts tainted.
        let taint = initial_taint(req.unattended);
        let trajectory = self.trajectories.as_ref().map(|c| {
            (
                Arc::new(TrajectoryRecorder::new(
                    id.clone(),
                    cfg.model.clone(),
                    taint.clone(),
                )),
                c.clone(),
            )
        });
        let decide_llm = req.llm.clone();
        let llm: Arc<dyn LlmClient> = Arc::new(MeteredLlm::new(
            (self.llm_factory)(&req.llm),
            metering.clone(),
        ));
        let session = Arc::new(Session {
            id: id.clone(),
            cfg,
            opts,
            specs,
            hic_aware: req.hic_aware,
            taint,
            llm,
            history: Mutex::new(Vec::new()),
            log: Mutex::new(EventLog {
                next_seq: 0,
                events: VecDeque::new(),
            }),
            notify: tokio::sync::Notify::new(),
            stop: StopFlag::default(),
            busy: AtomicBool::new(false),
            pending: Arc::new(Mutex::new(HashMap::new())),
            skills,
            toolchain,
            toolchain_reports,
            grants,
            capsule_sandbox,
            metering,
            metering_store: self.metering.clone(),
            trajectory,
            files,
            runs: Mutex::new(VecDeque::new()),
            last_used: AtomicU64::new(self.uses.fetch_add(1, Ordering::SeqCst) + 1),
            persona,
            token_counter,
            retriever,
            shell,
            decide_llm,
            mcp_offered,
            mcp_approvals,
        });
        sessions.insert(id.clone(), session);
        drop(sessions);
        if let Some(old) = replaced {
            Self::finish(&old);
        }
        Ok(id)
    }

    /// A session (marking it used now).
    pub fn get(&self, id: &str) -> Option<Arc<Session>> {
        let s = self.sessions.lock().ok().and_then(|s| s.get(id).cloned())?;
        s.last_used.store(
            self.uses.fetch_add(1, Ordering::SeqCst) + 1,
            Ordering::SeqCst,
        );
        Some(s)
    }

    /// Wind down a session removed from the table: stop it and, with trajectory recording on,
    /// export its verified turns.
    fn finish(s: &Arc<Session>) -> Option<ExportSummary> {
        s.stop.stop();
        s.trajectory.as_ref().map(|(rec, cfg)| {
            let history = s.history.lock().map(|h| h.clone()).unwrap_or_default();
            let now_ms = std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .map(|d| u64::try_from(d.as_millis()).unwrap_or(u64::MAX))
                .unwrap_or(0);
            export_session(cfg, rec, &history, &s.id, now_ms)
        })
    }

    /// HUP-S1.1: every open session, oldest id first.
    pub fn list(&self) -> Vec<SessionSummary> {
        let sessions: Vec<Arc<Session>> = self
            .sessions
            .lock()
            .map(|s| s.values().cloned().collect())
            .unwrap_or_default();
        let mut out: Vec<SessionSummary> = sessions.iter().map(|s| s.summary()).collect();
        out.sort_by(|a, b| a.id.cmp(&b.id));
        out
    }

    /// HUP-S2.3: the taint sources of every live session that is tainted (one list per session).
    /// `None` when the session table or any session's taint cannot be read, which callers treat
    /// as "unknown" (tainted).
    pub fn tainted_session_sources(&self) -> Option<Vec<Vec<String>>> {
        let sessions: Vec<Arc<Session>> = self.sessions.lock().ok()?.values().cloned().collect();
        let mut out = Vec::new();
        for s in sessions {
            if s.taint().is_tainted() {
                out.push(s.taint().sources()?);
            }
        }
        Some(out)
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
        // US-6.2: while the session's latest toolchain reports block a deploy, `contract_deploy`
        // is declined before it is announced, so core never opens a SignatureCeremony for it.
        if let Some(guard) = session.deploy_guard() {
            registry = registry.with_policy(Arc::new(guard));
        }
        let skill_host = session.skills.clone().map(SkillHost::new);
        let capsule_host = capsules.map(|d| CapsuleHost {
            dispatch: d,
            sandbox: session.capsule_sandbox.clone(),
        });
        let toolchain = session.toolchain.clone();
        let files = session
            .files
            .clone()
            .and_then(|t| FileToolsHost::new(t, &session.id));
        // HUP-S2.9: file_write and sheet_write checkpoint under the session id; without an undo
        // store they write nothing.
        let undo = self
            .checkpoints
            .clone()
            .and_then(|st| crate::files::UndoScope::new(st, &session.id));
        let file_host = session.grants.clone().map(|g| {
            let h = FileToolHost::new(g);
            match &undo {
                Some(u) => h.with_undo(u.clone()),
                None => h,
            }
        });
        let sheet_host = session.grants.clone().map(|g| {
            let h = SheetToolHost::new(g);
            match &undo {
                Some(u) => h.with_undo(u.clone()),
                None => h,
            }
        });
        let search = self.search.clone();
        let mcp_host = self.mcp.clone().map(|h| {
            let mut t = McpToolHost::new(h, session.stop.clone());
            if let Some(o) = &session.mcp_offered {
                t = t.with_offered(o.clone());
            }
            if let Some(a) = &session.mcp_approvals {
                t = t.with_approver(a.clone());
            }
            t
        });
        let learn_host = self
            .learn
            .clone()
            .map(|svc| crate::learn::LearnToolHost::new(svc, session.clone()));
        let browser_host = self.browser.clone().map(|b| {
            BrowserToolHost::new(b, session.stop.clone()).with_picker(Arc::new(
                crate::decide::SessionPicker::new(
                    self.decide.clone(),
                    session.decide_llm.clone(),
                    &session.cfg.model,
                ),
            ))
        });
        let shell_host = session
            .shell
            .as_ref()
            .map(|s| s.host(session.taint.clone(), session.stop.clone()));
        if file_host.is_some()
            || shell_host.is_some()
            || skill_host.is_some()
            || capsule_host.is_some()
            || toolchain.is_some()
            || files.is_some()
            || search.is_some()
            || mcp_host.is_some()
            || learn_host.is_some()
            || browser_host.is_some()
        {
            registry = registry.with_host(
                HostKind::Sidecar,
                Arc::new(SidecarHost {
                    files: file_host,
                    sheets: sheet_host,
                    skills: skill_host,
                    toolchain,
                    fs_tools: files,
                    search,
                    mcp: mcp_host,
                    capsules: capsule_host,
                    learn: learn_host,
                    browser: browser_host,
                    shell: shell_host,
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
        let self_review = self.self_review;
        tokio::task::spawn_blocking(move || {
            let sink = SessionSink(s.clone());
            let mut history = s.history.lock().map(|h| h.clone()).unwrap_or_default();
            let reviewer =
                LlmSelfReviewer::new(s.llm.as_ref(), s.cfg.model.clone(), SELF_REVIEW_MAX_TOKENS);
            let out = run_verified_workflow_reviewed(
                &s.id,
                &s.cfg,
                &s.opts,
                s.llm.as_ref(),
                &registry,
                &sink,
                &s.stop,
                &mut history,
                &wf,
                if self_review {
                    Some(&reviewer as &dyn SelfReviewer)
                } else {
                    None
                },
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
            let session_sink = SessionSink(s.clone());
            let mut observers: Vec<&dyn EventSink> = vec![s.metering.as_ref()];
            if let Some((rec, _)) = &s.trajectory {
                observers.push(rec.as_ref());
            }
            let sink = TeeSink {
                observers,
                last: &session_sink,
            };
            let mut history = s.history.lock().map(|h| h.clone()).unwrap_or_default();
            // US-6.1 AC2 / US-6.2: a deploy request while the gate blocks is answered with the
            // refusal, the findings and the proposed fix, without a model call or any tool call.
            match s.deploy_guard().and_then(|g| g.answer_to(&text)) {
                Some(refusal) => answer_without_model(&sink, &mut history, &text, refusal),
                None => {
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
                }
            }
            if let Ok(mut h) = s.history.lock() {
                *h = history;
            }
            // Workflow verdicts arrive after `done`, so drain only once the turn has returned.
            s.metering_store.append(s.metering.take_records());
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

    /// Close a session. With trajectory recording on, its verified turns are exported now (a
    /// session still mid-turn is exported with the turns it finished) and the summary returned.
    pub fn close(&self, id: &str) -> Result<Option<ExportSummary>, SessionError> {
        let s = self
            .sessions
            .lock()
            .ok()
            .and_then(|mut m| m.remove(id))
            .ok_or(SessionError::NotFound)?;
        Ok(Self::finish(&s))
    }

    pub fn count(&self) -> usize {
        self.sessions.lock().map(|s| s.len()).unwrap_or(0)
    }
}

/// A turn the sidecar answers itself (the deploy guard's refusal): the same events a model turn
/// that answers in one step emits, and the same history.
fn answer_without_model(
    sink: &dyn EventSink,
    history: &mut Vec<Message>,
    user: &str,
    answer: String,
) {
    history.push(Message::user(user));
    sink.emit(Event::StepStart { step: 1 });
    history.push(Message {
        role: citrate_agent_loop::Role::Assistant,
        content: answer.clone(),
        tool_calls: vec![],
        tool_call_id: None,
    });
    sink.emit(Event::Final { content: answer });
    sink.emit(Event::Done {
        outcome: "answered".into(),
    });
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
