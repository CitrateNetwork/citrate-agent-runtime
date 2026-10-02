//! HUP-S10.3 — unattended (daemon) sessions over the real control-plane routes.
//!
//! A daemon run is a scheduled Hermes turn nobody is watching. Core opens its session with
//! `unattended: true`; the session then starts in the HIC-downgraded state, so every effectful call
//! needs a member's explicit decision from the first step (or is declined by the sidecar itself when
//! core did not promise to ask). Read-only calls still run. Absent the flag nothing changes.

use super::*;
use axum::body::Body;
use axum::http::{Request, StatusCode};
use citrate_agent_loop::{AssistantTurn, CompletionRequest, LlmClient, LlmError, ToolCall};
use std::sync::Mutex;
use std::time::Duration;
use tower::ServiceExt;

const BEARER: &str = "daemon-test-bearer-0123456789";

struct Script(Mutex<Vec<AssistantTurn>>);
impl LlmClient for Script {
    fn complete(&self, _req: &CompletionRequest) -> Result<AssistantTurn, LlmError> {
        let mut t = self
            .0
            .lock()
            .map_err(|_| LlmError::Transport("poisoned".into()))?;
        if t.is_empty() {
            Ok(AssistantTurn::text("(done)"))
        } else {
            Ok(t.remove(0))
        }
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

fn body(hic_aware: bool, unattended: Option<serde_json::Value>) -> serde_json::Value {
    let mut b = serde_json::json!({
        "model": "gemma-4",
        "systemPrompt": "You are Hermes, running a scheduled task.",
        "llm": {"baseUrl": "http://127.0.0.1:18080/v1", "bearer": "k"},
        "hicAware": hic_aware,
        "tools": [
            {"name": "node_status", "description": "node", "parameters": {"type": "object"},
             "host": "core", "annotations": {"effect": "none", "trust": "trusted"}},
            {"name": "journal_append", "description": "write the journal", "parameters": {"type": "object"},
             "host": "core", "annotations": {"effect": "write", "trust": "trusted"}},
            {"name": "contract_deploy", "description": "deploy", "parameters": {"type": "object"},
             "host": "core", "annotations": {"effect": "sign", "trust": "trusted"}}
        ]
    });
    if let Some(u) = unattended {
        b["unattended"] = u;
    }
    b
}

fn tc(id: &str, name: &str) -> AssistantTurn {
    AssistantTurn::tools(vec![ToolCall {
        id: id.into(),
        name: name.into(),
        arguments: "{}".into(),
    }])
}

async fn create(st: &Arc<AppState>, b: serde_json::Value) -> (StatusCode, serde_json::Value) {
    let r = app(st.clone())
        .oneshot(req("POST", "/sessions", b))
        .await
        .expect("create");
    let status = r.status();
    (status, json(r).await)
}

async fn say(st: &Arc<AppState>, id: &str) {
    let r = app(st.clone())
        .oneshot(req(
            "POST",
            &format!("/sessions/{id}/messages"),
            serde_json::json!({ "text": "run the scheduled task" }),
        ))
        .await
        .expect("send");
    assert_eq!(r.status(), StatusCode::ACCEPTED);
}

/// Every event so far, as JSON (polled until `done` or ~5 s).
async fn events_until_done_answering(st: &Arc<AppState>, id: &str) -> Vec<serde_json::Value> {
    let mut answered = std::collections::HashSet::new();
    let mut all = vec![];
    for _ in 0..200 {
        all = st
            .sessions
            .get(id)
            .expect("session")
            .events_after(0)
            .events
            .into_iter()
            .filter_map(|e| serde_json::to_value(e.event).ok())
            .collect::<Vec<_>>();
        // Play core: answer every call dispatched to core exactly once.
        for e in all.iter().filter(|e| e["type"] == "tool_call") {
            let call_id = e["call"]["id"].as_str().unwrap_or("").to_string();
            if e["host"] == "core" && answered.insert(call_id.clone()) {
                let r = app(st.clone())
                    .oneshot(req(
                        "POST",
                        &format!("/sessions/{id}/tool_results"),
                        serde_json::json!({"callId": call_id, "status": "ok", "content": "done"}),
                    ))
                    .await
                    .expect("result");
                // 409 = the loop has not parked on it yet; retry on the next poll.
                if r.status() == StatusCode::CONFLICT {
                    answered.remove(&call_id);
                }
            }
        }
        if all.iter().any(|e| e["type"] == "done") {
            return all;
        }
        tokio::time::sleep(Duration::from_millis(25)).await;
    }
    panic!("no done event; got {all:?}");
}

fn call<'a>(evs: &'a [serde_json::Value], id: &str) -> &'a serde_json::Value {
    evs.iter()
        .find(|e| e["type"] == "tool_call" && e["call"]["id"] == id)
        .unwrap_or_else(|| panic!("no tool_call {id} in {evs:?}"))
}

fn result<'a>(evs: &'a [serde_json::Value], id: &str) -> &'a serde_json::Value {
    evs.iter()
        .find(|e| e["type"] == "tool_result" && e["call_id"] == id)
        .unwrap_or_else(|| panic!("no tool_result {id} in {evs:?}"))
}

#[tokio::test(flavor = "multi_thread")]
async fn an_unattended_session_asks_before_its_first_effectful_call() {
    let st = state_with(vec![
        tc("c1", "node_status"),
        tc("c2", "journal_append"),
        tc("c3", "contract_deploy"),
        AssistantTurn::text("ok"),
    ]);
    let (status, b) = create(&st, body(true, Some(serde_json::json!(true)))).await;
    assert_eq!(status, StatusCode::CREATED, "{b}");
    let id = b["id"].as_str().expect("id").to_string();
    say(&st, &id).await;
    let evs = events_until_done_answering(&st, &id).await;
    // The read runs as usual, with no HIC mark.
    let c1 = call(&evs, "c1");
    assert_eq!(c1["host"], "core");
    assert!(c1.get("hic").is_none(), "{c1}");
    // The write and the signature both go to core marked for an explicit decision, from step one.
    for id in ["c2", "c3"] {
        let c = call(&evs, id);
        assert_eq!(c["host"], "core", "{c}");
        assert_eq!(c["hic"], "required", "{c}");
        let reason = c["hic_reason"].as_str().unwrap_or("");
        assert!(
            reason.contains(sessions::UNATTENDED_TAINT_SOURCE),
            "{reason}"
        );
    }
}

#[tokio::test(flavor = "multi_thread")]
async fn an_unattended_session_without_a_hic_aware_core_declines_effects_itself() {
    let st = state_with(vec![
        tc("c1", "node_status"),
        tc("c2", "journal_append"),
        AssistantTurn::text("ok"),
    ]);
    let (status, b) = create(&st, body(false, Some(serde_json::json!(true)))).await;
    assert_eq!(status, StatusCode::CREATED);
    let id = b["id"].as_str().expect("id").to_string();
    say(&st, &id).await;
    let evs = events_until_done_answering(&st, &id).await;
    assert_eq!(call(&evs, "c1")["host"], "core");
    let c2 = call(&evs, "c2");
    assert!(c2["host"].is_null(), "never dispatched: {c2}");
    assert_eq!(c2["hic"], "required");
    assert_eq!(result(&evs, "c2")["status"], "denied");
}

#[tokio::test(flavor = "multi_thread")]
async fn without_the_flag_an_effectful_call_is_unchanged() {
    for flag in [None, Some(serde_json::json!(false))] {
        let st = state_with(vec![tc("c2", "journal_append"), AssistantTurn::text("ok")]);
        let (status, b) = create(&st, body(true, flag)).await;
        assert_eq!(status, StatusCode::CREATED);
        let id = b["id"].as_str().expect("id").to_string();
        say(&st, &id).await;
        let evs = events_until_done_answering(&st, &id).await;
        let c2 = call(&evs, "c2");
        assert_eq!(c2["host"], "core");
        assert!(c2.get("hic").is_none(), "{c2}");
    }
}

#[tokio::test(flavor = "multi_thread")]
async fn a_non_boolean_unattended_flag_is_refused() {
    let st = state_with(vec![]);
    for bad in [
        serde_json::json!("yes"),
        serde_json::json!(1),
        serde_json::json!(null),
    ] {
        let (status, _) = create(&st, body(true, Some(bad.clone()))).await;
        assert_eq!(status, StatusCode::BAD_REQUEST, "{bad}");
    }
}
