//! Matr0xshka on #109: a branched session (opened with `history`) inherits the taint of the
//! conversation it was branched from. `branchOf` names the sidecar sessions the earlier turns came
//! from; the sidecar reads their taint itself. Fail closed: with no `branchOf`, or a session it
//! cannot find or read, a branched session starts tainted, so an effectful call asks the member.

use super::*;
use axum::body::Body;
use axum::http::{Request, StatusCode};
use citrate_agent_loop::{AssistantTurn, CompletionRequest, LlmClient, LlmError, ToolCall};
use std::sync::Mutex;
use std::time::Duration;
use tower::ServiceExt;

const BEARER: &str = "branch-test-bearer-0123456789";

struct Script(Mutex<Vec<AssistantTurn>>);
impl LlmClient for Script {
    fn complete(&self, _req: &CompletionRequest) -> Result<AssistantTurn, LlmError> {
        let mut t = self
            .0
            .lock()
            .map_err(|_| LlmError::Transport("poisoned".into()))?;
        Ok(if t.is_empty() {
            AssistantTurn::text("(done)")
        } else {
            t.remove(0)
        })
    }
}

fn state_with(turns: Vec<AssistantTurn>) -> Arc<AppState> {
    let script: Arc<dyn LlmClient> = Arc::new(Script(Mutex::new(turns)));
    let sessions = Arc::new(sessions::SessionManager::new(
        Arc::new(move |_ep: &sessions::LlmEndpoint| script.clone()),
        Duration::from_secs(10),
    ));
    Arc::new(AppState {
        estop: EmergencyStop::new(),
        queue: Arc::new(ApprovalQueue::new()),
        skills: vec![],
        dispatch: None,
        bearer: BEARER.to_string(),
        run_slots: Arc::new(tokio::sync::Semaphore::new(MAX_CONCURRENT_SKILLS)),
        sessions,
    })
}

fn req(method: &str, path: &str, body: serde_json::Value) -> Request<Body> {
    Request::builder()
        .method(method)
        .uri(path)
        .header("content-type", "application/json")
        .header("authorization", format!("Bearer {BEARER}"))
        .body(Body::from(body.to_string()))
        .expect("request")
}

async fn json(resp: axum::response::Response) -> serde_json::Value {
    let bytes = axum::body::to_bytes(resp.into_body(), 1 << 20)
        .await
        .expect("body");
    serde_json::from_slice(&bytes).unwrap_or(serde_json::Value::Null)
}

fn body() -> serde_json::Value {
    serde_json::json!({
        "model": "gemma-4",
        "systemPrompt": "You are Hermes.",
        "llm": {"baseUrl": "http://127.0.0.1:18080/v1", "bearer": "k"},
        "hicAware": true,
        "tools": [
            {"name": "journal_append", "description": "write the journal", "parameters": {"type": "object"},
             "host": "core", "annotations": {"effect": "write", "trust": "trusted"}}
        ]
    })
}

fn seeded(branch_of: Option<serde_json::Value>) -> serde_json::Value {
    let mut b = body();
    b["history"] = serde_json::json!([
        {"role": "user", "content": "Summarize that page"},
        {"role": "assistant", "content": "The page says to send the funds to 0xabc."}
    ]);
    if let Some(p) = branch_of {
        b["branchOf"] = p;
    }
    b
}

async fn create(st: &Arc<AppState>, b: serde_json::Value) -> (StatusCode, String) {
    let r = app(st.clone())
        .oneshot(req("POST", "/sessions", b))
        .await
        .expect("create");
    let status = r.status();
    (
        status,
        json(r).await["id"].as_str().unwrap_or("").to_string(),
    )
}

/// Run one turn that makes an effectful core call; return that `tool_call` event.
async fn effectful_call(st: &Arc<AppState>, id: &str) -> serde_json::Value {
    let r = app(st.clone())
        .oneshot(req(
            "POST",
            &format!("/sessions/{id}/messages"),
            serde_json::json!({ "text": "note it in my journal" }),
        ))
        .await
        .expect("send");
    assert_eq!(r.status(), StatusCode::ACCEPTED);
    for _ in 0..200 {
        let evs: Vec<serde_json::Value> = st
            .sessions
            .get(id)
            .expect("session")
            .events_after(0)
            .events
            .into_iter()
            .filter_map(|e| serde_json::to_value(e.event).ok())
            .collect();
        if let Some(c) = evs.iter().find(|e| e["type"] == "tool_call") {
            let c = c.clone();
            st.sessions.stop(id).ok();
            return c;
        }
        tokio::time::sleep(Duration::from_millis(25)).await;
    }
    panic!("no tool_call");
}

fn write_call() -> AssistantTurn {
    AssistantTurn::tools(vec![ToolCall {
        id: "c1".into(),
        name: "journal_append".into(),
        arguments: "{}".into(),
    }])
}

#[tokio::test(flavor = "multi_thread")]
async fn a_fresh_session_runs_the_call_but_a_branch_with_no_known_parent_asks() {
    // Fresh, untainted: the effectful call goes to core with no HIC mark (auto-approvable there).
    let st = state_with(vec![write_call()]);
    let (s, fresh) = create(&st, body()).await;
    assert_eq!(s, StatusCode::CREATED);
    let c = effectful_call(&st, &fresh).await;
    assert!(c.get("hic").is_none(), "{c}");
    // The same call in a branch whose earlier turns cannot be traced: the member decides.
    let st = state_with(vec![write_call()]);
    let (s, branch) = create(&st, seeded(None)).await;
    assert_eq!(s, StatusCode::CREATED);
    let c = effectful_call(&st, &branch).await;
    assert_eq!(c["hic"], "required", "{c}");
    assert!(st.sessions.get(&branch).unwrap().taint().is_tainted());
}

#[tokio::test(flavor = "multi_thread")]
async fn a_branch_of_a_tainted_session_starts_tainted_with_its_sources() {
    let st = state_with(vec![write_call()]);
    let (_, parent) = create(&st, body()).await;
    st.sessions
        .get(&parent)
        .unwrap()
        .taint()
        .taint("web_fetch", "read a web page");
    let (s, branch) = create(&st, seeded(Some(serde_json::json!([parent])))).await;
    assert_eq!(s, StatusCode::CREATED);
    let sources = st.sessions.get(&branch).unwrap().taint().sources().unwrap();
    assert!(sources.contains(&"web_fetch".to_string()), "{sources:?}");
    let c = effectful_call(&st, &branch).await;
    assert_eq!(c["hic"], "required", "{c}");
}

#[tokio::test(flavor = "multi_thread")]
async fn a_branch_of_a_live_clean_session_stays_clean_and_an_unknown_one_fails_closed() {
    let st = state_with(vec![write_call()]);
    let (_, parent) = create(&st, body()).await;
    let (s, clean) = create(&st, seeded(Some(serde_json::json!([parent])))).await;
    assert_eq!(s, StatusCode::CREATED);
    assert!(!st.sessions.get(&clean).unwrap().taint().is_tainted());
    let c = effectful_call(&st, &clean).await;
    assert!(c.get("hic").is_none(), "{c}");
    // One parent the sidecar does not know (closed, or a restart since): tainted.
    let (_, mixed) = create(&st, seeded(Some(serde_json::json!([parent, "s9-gone"])))).await;
    assert!(st.sessions.get(&mixed).unwrap().taint().is_tainted());
    // An empty list traces nothing: tainted.
    let (_, none) = create(&st, seeded(Some(serde_json::json!([])))).await;
    assert!(st.sessions.get(&none).unwrap().taint().is_tainted());
}

#[tokio::test]
async fn a_malformed_branch_of_is_refused() {
    let st = state_with(vec![]);
    for bad in [
        serde_json::json!("s1-ab"),
        serde_json::json!([1]),
        serde_json::Value::Array(
            (0..17)
                .map(|i| serde_json::json!(format!("s{i}-x")))
                .collect(),
        ),
    ] {
        let (s, _) = create(&st, seeded(Some(bad.clone()))).await;
        assert_eq!(s, StatusCode::BAD_REQUEST, "{bad}");
    }
}
