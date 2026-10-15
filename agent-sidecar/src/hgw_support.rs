//! Test support for the HGW ("Hermes gets to work") session tests: a scratch home with a granted
//! project folder, a scripted model, a session manager with `shell_run` and the checkpointed file
//! tools on, the HTTP app, and a "member" that answers approval cards through the routes.

#![cfg(all(test, unix))]
// Shared by several HGW test modules; each uses a different subset.
#![allow(dead_code)]

use super::*;
use axum::body::Body;
use axum::http::{Request, StatusCode};
use citrate_agent_checkpoints::{CheckpointStore, Config};
use citrate_agent_grants::{Access, FolderGrants, GrantRequest};
use citrate_agent_loop::{AssistantTurn, CompletionRequest, LlmClient, LlmError, ToolCall};
use citrate_agent_shell::sandbox::{SandboxMode, SandboxPolicy};
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::Mutex;
use std::time::Duration;
use tower::ServiceExt;

pub(crate) const BEARER: &str = "test-bearer-token-0123456789";
pub(crate) const MEMBER: &str = "0x00000000000000000000000000000000000000aa";
static N: AtomicUsize = AtomicUsize::new(0);

pub(crate) fn now() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0)
}

/// `base/home/proj` (granted read + write), `base/home/other` (not granted); undo stores go in
/// `base/ckpt-<n>` (outside the home).
pub(crate) struct Fx {
    pub base: PathBuf,
}

impl Fx {
    pub fn new(tag: &str) -> Self {
        let base = std::env::temp_dir().join(format!(
            "citrate-hgw-{tag}-{}-{}",
            std::process::id(),
            N.fetch_add(1, Ordering::SeqCst)
        ));
        let _ = std::fs::remove_dir_all(&base);
        for d in ["home/proj/src", "home/other"] {
            std::fs::create_dir_all(base.join(d)).expect("fixture dirs");
        }
        Fx {
            base: base.canonicalize().expect("canonical base"),
        }
    }
    pub fn home(&self) -> PathBuf {
        self.base.join("home")
    }
    pub fn proj(&self) -> PathBuf {
        self.base.join("home/proj")
    }
    pub fn other(&self) -> PathBuf {
        self.base.join("home/other")
    }
    /// A grant document over `roots` (read and write each).
    pub fn rw_doc_for(&self, roots: &[PathBuf]) -> serde_json::Value {
        let mut g = FolderGrants::new(self.home(), self.home());
        for r in roots {
            for a in [Access::Read, Access::Write] {
                g.grant(GrantRequest::folder(r, a, MEMBER, "build it"), now())
                    .expect("grant");
            }
        }
        serde_json::to_value(g.state()).expect("grant doc")
    }
    pub fn rw_doc(&self) -> serde_json::Value {
        self.rw_doc_for(&[self.proj()])
    }
}

impl Drop for Fx {
    fn drop(&mut self) {
        let _ = std::fs::remove_dir_all(&self.base);
    }
}

/// `shell_run` with the sandbox off: for tests of the approval flow itself, which must pass on
/// machines without a backend. Production always requires the sandbox.
pub(crate) fn shell_open() -> shell_run::ShellRunConfig {
    shell_run::ShellRunConfig {
        search_path: vec![PathBuf::from("/bin"), PathBuf::from("/usr/bin")],
        sandbox: SandboxPolicy::new(SandboxMode::Off),
        approval_timeout: Duration::from_secs(20),
    }
}

/// The model: replays `turns`, then answers "(done)".
pub(crate) struct Script(pub Mutex<Vec<AssistantTurn>>);
impl LlmClient for Script {
    fn complete(&self, _req: &CompletionRequest) -> Result<AssistantTurn, LlmError> {
        let mut t = self.0.lock().unwrap_or_else(|p| p.into_inner());
        Ok(if t.is_empty() {
            AssistantTurn::text("(done)")
        } else {
            t.remove(0)
        })
    }
}

/// A session manager with grants, the undo store and `shell` (when given).
pub(crate) fn manager_with(
    fx: &Fx,
    turns: Vec<AssistantTurn>,
    shell: Option<shell_run::ShellRunConfig>,
) -> sessions::SessionManager {
    let script = Arc::new(Script(Mutex::new(turns)));
    // One store per manager: a store is locked while it is open.
    let dir = fx
        .base
        .join(format!("ckpt-{}", N.fetch_add(1, Ordering::SeqCst)));
    let store = Arc::new(CheckpointStore::open(&dir, Config::default()).expect("store"));
    let mut mgr = sessions::SessionManager::new(
        Arc::new(move |_ep: &sessions::LlmEndpoint| script.clone() as Arc<dyn LlmClient>),
        Duration::from_secs(5),
    )
    .with_grants_home(fx.home())
    .with_checkpoints(store);
    if let Some(c) = shell {
        mgr = mgr.with_shell_run(Arc::new(c));
    }
    mgr
}

/// `POST /sessions` body with `grants` and `hicAware`.
pub(crate) fn create_req(grants: serde_json::Value, hic_aware: bool) -> sessions::CreateSessionReq {
    serde_json::from_value(serde_json::json!({
        "model": "gemma-4",
        "systemPrompt": "You are Hermes.",
        "llm": {"baseUrl": "http://127.0.0.1:18080/v1", "bearer": "k"},
        "tools": [],
        "maxToolsPerRequest": 8,
        "hicAware": hic_aware,
        "grants": grants,
    }))
    .expect("create req")
}

pub(crate) fn app_for(mgr: Arc<sessions::SessionManager>) -> axum::Router {
    app(Arc::new(AppState {
        estop: EmergencyStop::new(),
        queue: Arc::new(ApprovalQueue::new()),
        skills: vec![],
        dispatch: None,
        bearer: BEARER.to_string(),
        run_slots: Arc::new(tokio::sync::Semaphore::new(MAX_CONCURRENT_SKILLS)),
        sessions: mgr,
    }))
}

pub(crate) async fn send(
    app: &axum::Router,
    method: &str,
    path: &str,
    body: Option<serde_json::Value>,
) -> (StatusCode, serde_json::Value) {
    let req = Request::builder()
        .method(method)
        .uri(path)
        .header("authorization", format!("Bearer {BEARER}"))
        .header("content-type", "application/json")
        .body(match body {
            Some(b) => Body::from(b.to_string()),
            None => Body::empty(),
        })
        .expect("request");
    let resp = app.clone().oneshot(req).await.expect("response");
    let status = resp.status();
    let bytes = axum::body::to_bytes(resp.into_body(), 1 << 20)
        .await
        .unwrap_or_default();
    (
        status,
        serde_json::from_slice(&bytes).unwrap_or(serde_json::Value::Null),
    )
}

pub(crate) fn tool_call(id: &str, name: &str, args: serde_json::Value) -> ToolCall {
    ToolCall {
        id: id.into(),
        name: name.into(),
        arguments: args.to_string(),
    }
}

pub(crate) fn shell(id: &str, argv: &[&str], cwd: &Path) -> ToolCall {
    tool_call(
        id,
        shell_run::SHELL_RUN_TOOL,
        serde_json::json!({ "argv": argv, "cwd": cwd }),
    )
}

pub(crate) fn fs_write(id: &str, path: &Path, content: &str) -> ToolCall {
    tool_call(
        id,
        "fs_write",
        serde_json::json!({ "path": path, "content": content }),
    )
}

/// Every event of the session, as JSON.
pub(crate) fn events(s: &sessions::Session) -> Vec<serde_json::Value> {
    s.events_after(0)
        .events
        .iter()
        .map(|e| serde_json::to_value(&e.event).unwrap_or(serde_json::Value::Null))
        .collect()
}

/// The `tool_result` event for `call_id`, once it exists.
pub(crate) async fn result_of(s: &sessions::Session, call_id: &str) -> serde_json::Value {
    for _ in 0..1500 {
        if let Some(e) = events(s)
            .into_iter()
            .find(|e| e["type"] == "tool_result" && e["call_id"] == call_id)
        {
            return e;
        }
        tokio::time::sleep(Duration::from_millis(10)).await;
    }
    panic!("no tool_result for {call_id}");
}

/// Wait until the session's turn is over.
pub(crate) async fn wait_done(s: &sessions::Session) {
    for _ in 0..3000 {
        if !s.is_busy() && events(s).iter().any(|e| e["type"] == "done") {
            return;
        }
        tokio::time::sleep(Duration::from_millis(10)).await;
    }
    panic!("the turn never finished");
}

/// One card the member answered, and on which route.
#[derive(Debug, Clone)]
pub(crate) struct Answered {
    pub route: &'static str,
    pub card: serde_json::Value,
    pub allow: bool,
}

/// Plays the member: answers every shell and action card of session `id` with `decide(card)`
/// (true = allow), until the turn is over. Returns the cards in the order they were answered.
pub(crate) async fn member_answers(
    app: &axum::Router,
    s: &sessions::Session,
    id: &str,
    mut decide: impl FnMut(&'static str, &serde_json::Value) -> bool,
) -> Vec<Answered> {
    let mut out = Vec::new();
    for _ in 0..3000 {
        for route in ["shell", "actions"] {
            // Labels: `shell` = the shell_run cards, `actions` = the session's approval cards.
            let base = if route == "shell" {
                "shell"
            } else {
                "approvals"
            };
            let (st, body) =
                send(app, "GET", &format!("/sessions/{id}/{base}/pending"), None).await;
            assert_eq!(st, StatusCode::OK, "{route}: {body}");
            for card in body["pending"].as_array().cloned().unwrap_or_default() {
                let allow = decide(route, &card);
                let (url, decision) = if route == "shell" {
                    (
                        format!("/sessions/{id}/shell/decide"),
                        serde_json::json!({"id": card["id"], "allow": allow, "argv": card["argv"], "cwd": card["cwd"]}),
                    )
                } else {
                    (
                        format!(
                            "/sessions/{id}/approvals/{}/decide",
                            card["id"].as_str().unwrap_or_default()
                        ),
                        serde_json::json!({"allow": allow, "subject": card["subject"]}),
                    )
                };
                let (st, b) = send(app, "POST", &url, Some(decision)).await;
                assert_eq!(st, StatusCode::OK, "{route} decide: {b}");
                out.push(Answered { route, card, allow });
            }
        }
        if !s.is_busy() && events(s).iter().any(|e| e["type"] == "done") {
            return out;
        }
        tokio::time::sleep(Duration::from_millis(10)).await;
    }
    panic!("the turn never finished; answered so far: {out:?}");
}
