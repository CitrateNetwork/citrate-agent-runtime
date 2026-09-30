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

use std::collections::{HashMap, VecDeque};
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::sync::mpsc;
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

use citrate_agent_core::capsule::dispatch::CapsuleDispatch;
use citrate_agent_loop::{
    run_turn_with, CharTokenCounter, ContextBudget, Event, EventSink, HostKind, LlmClient,
    LoopConfig, Message, StopFlag, ToolCall, ToolHost, ToolOutcome, ToolRegistry, ToolSpec,
    TurnOptions,
};
use serde::{Deserialize, Serialize};

/// At most this many open sessions (a session is a conversation, not a request).
pub const MAX_SESSIONS: usize = 8;
/// Events kept per session for replay; older ones are dropped (clients read by sequence).
pub const EVENT_LOG_CAP: usize = 2000;
/// Upper bounds a client may request.
pub const MAX_STEPS_CAP: u32 = 32;
pub const MAX_TOKENS_CAP: u32 = 8192;
/// Longest a long-poll may wait.
pub const MAX_WAIT_MS: u64 = 25_000;

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
}

/// `POST /sessions/:id/tool_results` body.
#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct ToolResultReq {
    pub call_id: String,
    /// "ok" | "denied" | "error"
    pub status: String,
    pub content: String,
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
    llm: Arc<dyn LlmClient>,
    history: Mutex<Vec<Message>>,
    log: Mutex<EventLog>,
    notify: tokio::sync::Notify,
    pub stop: StopFlag,
    busy: AtomicBool,
    pending: Arc<Mutex<HashMap<String, mpsc::Sender<ToolOutcome>>>>,
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

    pub fn is_busy(&self) -> bool {
        self.busy.load(Ordering::SeqCst)
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
}

impl SessionManager {
    pub fn new(llm_factory: LlmFactory, core_tool_deadline: Duration) -> Self {
        SessionManager {
            sessions: Mutex::new(HashMap::new()),
            llm_factory,
            core_tool_deadline,
            ids: AtomicU64::new(0),
        }
    }

    pub fn create(&self, req: CreateSessionReq) -> Result<String, SessionError> {
        validate_endpoint(&req.llm.base_url).map_err(SessionError::Invalid)?;
        if req.model.trim().is_empty() {
            return Err(SessionError::Invalid("model is required".into()));
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
            system_prompt: req.system_prompt,
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
        };
        let session = Arc::new(Session {
            id: id.clone(),
            cfg,
            opts,
            specs: req.tools,
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
        });
        sessions.insert(id.clone(), session);
        Ok(id)
    }

    pub fn get(&self, id: &str) -> Option<Arc<Session>> {
        self.sessions.lock().ok().and_then(|s| s.get(id).cloned())
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
        let core = Arc::new(CoreHost {
            pending: session.pending.clone(),
            deadline: self.core_tool_deadline,
            stop: session.stop.clone(),
        });
        let mut registry = ToolRegistry::new(session.specs.clone()).with_host(HostKind::Core, core);
        if let Some(d) = capsules {
            registry = registry.with_host(HostKind::Sidecar, Arc::new(CapsuleHost { dispatch: d }));
        }
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
    match req.status.as_str() {
        "ok" => Ok(ToolOutcome::Ok(req.content)),
        "denied" => Ok(ToolOutcome::Denied(req.content)),
        "error" => Ok(ToolOutcome::Error(req.content)),
        other => Err(SessionError::Invalid(format!(
            "unknown status {other:?} (ok | denied | error)"
        ))),
    }
}
