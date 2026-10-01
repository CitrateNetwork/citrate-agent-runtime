//! HUP-S3.2 — `skill_load` as a sidecar-hosted session tool, registered only when a skills
//! directory is configured (`CITRATE_HERMES_SKILLS`, default off).

use super::*;
use axum::body::Body;
use axum::http::{Request, StatusCode};
use citrate_agent_loop::skills::{SkillLibrary, SkillSource, SKILL_LOAD_TOOL};
use citrate_agent_loop::{AssistantTurn, CompletionRequest, LlmClient, LlmError, ToolCall};
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::Mutex;
use std::time::Duration;
use tower::ServiceExt;

const BEARER: &str = "test-bearer-token-0123456789";
static N: AtomicUsize = AtomicUsize::new(0);

struct Scratch(PathBuf);
impl Scratch {
    fn new() -> Self {
        let p = std::env::temp_dir().join(format!(
            "citrate-sidecar-skills-{}-{}",
            std::process::id(),
            N.fetch_add(1, Ordering::SeqCst)
        ));
        let _ = std::fs::remove_dir_all(&p);
        std::fs::create_dir_all(&p).unwrap();
        Scratch(p)
    }
}
impl Drop for Scratch {
    fn drop(&mut self) {
        let _ = std::fs::remove_dir_all(&self.0);
    }
}

fn skill(root: &Path, name: &str, description: &str, body: &str) {
    let dir = root.join(name);
    std::fs::create_dir_all(&dir).unwrap();
    std::fs::write(
        dir.join("SKILL.md"),
        format!("---\nname: {name}\ndescription: {description}\n---\n{body}"),
    )
    .unwrap();
}

/// A scripted model that also records every request it was sent.
struct Recorder {
    turns: Mutex<Vec<AssistantTurn>>,
    seen: Mutex<Vec<CompletionRequest>>,
}
impl LlmClient for Recorder {
    fn complete(&self, req: &CompletionRequest) -> Result<AssistantTurn, LlmError> {
        self.seen.lock().unwrap().push(req.clone());
        let mut t = self.turns.lock().unwrap();
        Ok(if t.is_empty() {
            AssistantTurn::text("(done)")
        } else {
            t.remove(0)
        })
    }
}

fn state(
    turns: Vec<AssistantTurn>,
    skills: Option<Arc<SkillLibrary>>,
) -> (Arc<AppState>, Arc<Recorder>) {
    let rec = Arc::new(Recorder {
        turns: Mutex::new(turns),
        seen: Mutex::new(vec![]),
    });
    let r2 = rec.clone();
    let mut mgr = sessions::SessionManager::new(
        Arc::new(move |_ep: &sessions::LlmEndpoint| r2.clone() as Arc<dyn LlmClient>),
        Duration::from_secs(5),
    );
    if let Some(lib) = skills {
        mgr = mgr.with_skills(lib);
    }
    let st = Arc::new(AppState {
        estop: EmergencyStop::new(),
        queue: Arc::new(ApprovalQueue::new()),
        skills: vec![],
        dispatch: None,
        bearer: BEARER.to_string(),
        run_slots: Arc::new(tokio::sync::Semaphore::new(MAX_CONCURRENT_SKILLS)),
        sessions: Arc::new(mgr),
    });
    (st, rec)
}

fn req(method: &str, path: &str, body: serde_json::Value) -> Request<Body> {
    Request::builder()
        .method(method)
        .uri(path)
        .header("content-type", "application/json")
        .header("authorization", format!("Bearer {BEARER}"))
        .body(Body::from(body.to_string()))
        .unwrap()
}

async fn json(resp: axum::response::Response) -> serde_json::Value {
    let bytes = axum::body::to_bytes(resp.into_body(), 1 << 20)
        .await
        .unwrap();
    serde_json::from_slice(&bytes).unwrap_or(serde_json::Value::Null)
}

fn create_body(tools: serde_json::Value) -> serde_json::Value {
    serde_json::json!({
        "model": "gemma-4",
        "systemPrompt": "You are Hermes.",
        "llm": {"baseUrl": "http://127.0.0.1:18080/v1", "bearer": "k"},
        "tools": tools,
        "maxToolsPerRequest": 1
    })
}

fn core_tools() -> serde_json::Value {
    serde_json::json!([
        {"name": "node_status", "description": "node height peers", "parameters": {"type": "object"}, "host": "core"},
        {"name": "wallet_balance", "description": "wallet balance", "parameters": {"type": "object"}, "host": "core"}
    ])
}

async fn run_one(
    st: &Arc<AppState>,
    body: serde_json::Value,
    text: &str,
) -> Vec<serde_json::Value> {
    let r = app(st.clone())
        .oneshot(req("POST", "/sessions", body))
        .await
        .unwrap();
    assert_eq!(r.status(), StatusCode::CREATED);
    let id = json(r).await["id"].as_str().unwrap().to_string();
    let r = app(st.clone())
        .oneshot(req(
            "POST",
            &format!("/sessions/{id}/messages"),
            serde_json::json!({ "text": text }),
        ))
        .await
        .unwrap();
    assert_eq!(r.status(), StatusCode::ACCEPTED);
    let mut all = vec![];
    let mut after = 0u64;
    for _ in 0..50 {
        let r = app(st.clone())
            .oneshot(req(
                "GET",
                &format!("/sessions/{id}/events?after={after}&wait_ms=100"),
                serde_json::Value::Null,
            ))
            .await
            .unwrap();
        let page = json(r).await;
        for e in page["events"].as_array().unwrap() {
            after = after.max(e["seq"].as_u64().unwrap());
            all.push(e["event"].clone());
        }
        if all.iter().any(|e| e["type"] == "done") {
            return all;
        }
    }
    panic!("no done event; got {all:?}");
}

fn library(root: &Path) -> Arc<SkillLibrary> {
    Arc::new(SkillLibrary::load(&[SkillSource::new("user", root)]))
}

#[tokio::test(flavor = "multi_thread")]
async fn without_skills_configured_sessions_offer_no_skill_load() {
    let (st, rec) = state(vec![], None);
    run_one(&st, create_body(core_tools()), "what is the node height").await;
    let seen = rec.seen.lock().unwrap();
    assert!(seen[0].tools.iter().all(|t| t.name != SKILL_LOAD_TOOL));
    assert_eq!(seen[0].messages[0].content, "You are Hermes.");
}

#[tokio::test(flavor = "multi_thread")]
async fn with_skills_the_index_is_in_the_prompt_and_skill_load_is_always_offered() {
    let s = Scratch::new();
    skill(
        &s.0,
        "staking-report",
        "Write the weekly staking report.",
        "BODY",
    );
    let (st, rec) = state(vec![], Some(library(&s.0)));
    run_one(&st, create_body(core_tools()), "what is the node height").await;
    let seen = rec.seen.lock().unwrap();
    let names: Vec<&str> = seen[0].tools.iter().map(|t| t.name.as_str()).collect();
    // Pinned outside the per-request retrieval budget of 1.
    assert_eq!(names, vec![SKILL_LOAD_TOOL, "node_status"]);
    let sys = &seen[0].messages[0].content;
    assert!(sys.starts_with("You are Hermes."));
    assert!(sys.contains("- staking-report: Write the weekly staking report."));
    assert!(
        !sys.contains("BODY"),
        "bodies load on demand, not in the prompt"
    );
}

#[tokio::test(flavor = "multi_thread")]
async fn skill_load_runs_in_the_sidecar_and_returns_the_body() {
    let s = Scratch::new();
    skill(
        &s.0,
        "staking-report",
        "Write the weekly staking report.",
        "STEP 1: read stake.",
    );
    let call = ToolCall {
        id: "k1".into(),
        name: SKILL_LOAD_TOOL.into(),
        arguments: r#"{"name":"staking-report"}"#.into(),
    };
    let (st, rec) = state(
        vec![
            AssistantTurn::tools(vec![call]),
            AssistantTurn::text("Done."),
        ],
        Some(library(&s.0)),
    );
    let evs = run_one(&st, create_body(core_tools()), "write my staking report").await;
    let tc = evs.iter().find(|e| e["type"] == "tool_call").unwrap();
    assert_eq!(tc["host"], "sidecar");
    let tr = evs.iter().find(|e| e["type"] == "tool_result").unwrap();
    assert_eq!(tr["status"], "ok");
    assert!(tr["content"]
        .as_str()
        .unwrap()
        .contains("STEP 1: read stake."));
    // The body reached the model as a tool message on the next request.
    let seen = rec.seen.lock().unwrap();
    assert!(seen[1]
        .messages
        .iter()
        .any(|m| m.content.contains("STEP 1: read stake.")));
}

#[tokio::test(flavor = "multi_thread")]
async fn a_core_tool_may_not_claim_the_skill_load_name_when_skills_are_on() {
    let s = Scratch::new();
    skill(&s.0, "a", "A.", "a");
    let (st, _) = state(vec![], Some(library(&s.0)));
    let tools = serde_json::json!([
        {"name": SKILL_LOAD_TOOL, "description": "x", "parameters": {"type": "object"}, "host": "core"}
    ]);
    let r = app(st)
        .oneshot(req("POST", "/sessions", create_body(tools)))
        .await
        .unwrap();
    assert_eq!(r.status(), StatusCode::BAD_REQUEST);
}

#[tokio::test(flavor = "multi_thread")]
async fn an_empty_skills_library_registers_nothing() {
    let s = Scratch::new();
    let (st, rec) = state(vec![], Some(library(&s.0)));
    run_one(&st, create_body(core_tools()), "hello").await;
    let seen = rec.seen.lock().unwrap();
    assert!(seen[0].tools.iter().all(|t| t.name != SKILL_LOAD_TOOL));
    assert_eq!(seen[0].messages[0].content, "You are Hermes.");
}

#[test]
fn skill_sources_parse_from_the_env_value_in_precedence_order() {
    let sep = if cfg!(windows) { ";" } else { ":" };
    let v = format!("/a/user-skills{sep}{sep}/b/bundled");
    let sources = skill_sources_from_env(&v);
    assert_eq!(sources.len(), 2);
    assert_eq!(sources[0].root, PathBuf::from("/a/user-skills"));
    assert_eq!(sources[1].root, PathBuf::from("/b/bundled"));
    assert_ne!(sources[0].label, sources[1].label);
    assert!(skill_sources_from_env("").is_empty());
    assert!(skill_sources_from_env("   ").is_empty());
}
