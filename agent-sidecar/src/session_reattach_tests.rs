//! HUP-S1.1 — one session reachable from every client: `GET /sessions`, the waiting core calls a
//! returning view needs, and streamed assistant text on the same event log.

use super::*;
use axum::body::Body;
use axum::http::{Request, StatusCode};
use citrate_agent_loop::{
    AssistantTurn, CompletionRequest, LlmClient, LlmError, TokenUsage, ToolCall,
};
use std::sync::Mutex;
use std::time::Duration;
use tower::ServiceExt;

const BEARER: &str = "test-bearer-token-reattach-0001";

/// Scripted model; `stream` sends each answer's words as deltas first.
struct Script {
    turns: Mutex<Vec<AssistantTurn>>,
    stream: bool,
}
impl LlmClient for Script {
    fn complete(&self, _req: &CompletionRequest) -> Result<AssistantTurn, LlmError> {
        let mut t = self.turns.lock().unwrap();
        Ok(if t.is_empty() {
            AssistantTurn::text("(done)")
        } else {
            t.remove(0)
        })
    }
    fn complete_streaming(
        &self,
        req: &CompletionRequest,
        on_delta: &mut dyn FnMut(&str),
    ) -> Result<(AssistantTurn, Option<TokenUsage>), LlmError> {
        let turn = self.complete(req)?;
        if self.stream {
            for w in turn.content.split_inclusive(' ') {
                on_delta(w);
            }
        }
        Ok((turn, None))
    }
}

fn state_with(turns: Vec<AssistantTurn>, stream: bool) -> Arc<AppState> {
    let script: Arc<dyn LlmClient> = Arc::new(Script {
        turns: Mutex::new(turns),
        stream,
    });
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

fn req(method: &str, path: &str, body: serde_json::Value, auth: bool) -> Request<Body> {
    let mut b = Request::builder()
        .method(method)
        .uri(path)
        .header("content-type", "application/json");
    if auth {
        b = b.header("authorization", format!("Bearer {BEARER}"));
    }
    b.body(Body::from(body.to_string())).unwrap()
}

async fn call(
    st: &Arc<AppState>,
    method: &str,
    path: &str,
    body: serde_json::Value,
) -> (StatusCode, serde_json::Value) {
    let r = app(st.clone())
        .oneshot(req(method, path, body, true))
        .await
        .unwrap();
    let status = r.status();
    let bytes = axum::body::to_bytes(r.into_body(), 1 << 20).await.unwrap();
    (
        status,
        serde_json::from_slice(&bytes).unwrap_or(serde_json::Value::Null),
    )
}

async fn create(st: &Arc<AppState>) -> String {
    let (s, v) = call(
        st,
        "POST",
        "/sessions",
        serde_json::json!({
            "model": "gemma-4",
            "systemPrompt": "You are Hermes.",
            "llm": {"baseUrl": "http://127.0.0.1:18080/v1", "bearer": "k"},
            "tools": [{"name": "node_status", "description": "node", "parameters": {"type": "object"}, "host": "core"}]
        }),
    )
    .await;
    assert_eq!(s, StatusCode::CREATED);
    v["id"].as_str().unwrap().to_string()
}

async fn events_until(
    st: &Arc<AppState>,
    id: &str,
    kind: &str,
) -> (Vec<serde_json::Value>, serde_json::Value) {
    let mut all = vec![];
    let mut after = 0u64;
    for _ in 0..50 {
        let (_, page) = call(
            st,
            "GET",
            &format!("/sessions/{id}/events?after={after}&wait_ms=100"),
            serde_json::Value::Null,
        )
        .await;
        for e in page["events"].as_array().unwrap() {
            after = after.max(e["seq"].as_u64().unwrap());
            all.push(e["event"].clone());
        }
        if all.iter().any(|e| e["type"] == kind) {
            return (all, page);
        }
    }
    panic!("no {kind} event; got {all:?}");
}

#[tokio::test]
async fn the_session_list_needs_the_bearer() {
    let st = state_with(vec![], false);
    let r = app(st)
        .oneshot(req("GET", "/sessions", serde_json::Value::Null, false))
        .await
        .unwrap();
    assert_eq!(r.status(), StatusCode::UNAUTHORIZED);
}

#[tokio::test]
async fn every_open_session_is_listed_without_history_or_keys() {
    let st = state_with(vec![], false);
    let (_, empty) = call(&st, "GET", "/sessions", serde_json::Value::Null).await;
    assert_eq!(empty["sessions"], serde_json::json!([]));
    let a = create(&st).await;
    let b = create(&st).await;
    let (s, v) = call(&st, "GET", "/sessions", serde_json::Value::Null).await;
    assert_eq!(s, StatusCode::OK);
    let list = v["sessions"].as_array().unwrap();
    let ids: Vec<&str> = list.iter().map(|x| x["id"].as_str().unwrap()).collect();
    assert!(
        ids.contains(&a.as_str()) && ids.contains(&b.as_str()),
        "{ids:?}"
    );
    let one = &list[0];
    assert_eq!(one["model"], "gemma-4");
    assert_eq!(one["busy"], false);
    assert_eq!(one["lastSeq"], 0);
    assert_eq!(one["pendingCoreCalls"], serde_json::json!([]));
    let text = v.to_string();
    assert!(
        !text.contains("You are Hermes") && !text.contains("\"k\""),
        "no prompt or endpoint key: {text}"
    );
    // A closed session leaves the list.
    let (s, _) = call(
        &st,
        "DELETE",
        &format!("/sessions/{a}"),
        serde_json::Value::Null,
    )
    .await;
    assert_eq!(s, StatusCode::OK);
    let (_, v) = call(&st, "GET", "/sessions", serde_json::Value::Null).await;
    assert_eq!(v["sessions"].as_array().unwrap().len(), 1);
}

#[tokio::test(flavor = "multi_thread")]
async fn a_waiting_core_call_is_reported_until_its_result_arrives() {
    let st = state_with(
        vec![
            AssistantTurn::tools(vec![ToolCall {
                id: "c1".into(),
                name: "node_status".into(),
                arguments: "{}".into(),
            }]),
            AssistantTurn::text("Height 6,310."),
        ],
        false,
    );
    let id = create(&st).await;
    call(
        &st,
        "POST",
        &format!("/sessions/{id}/messages"),
        serde_json::json!({"text": "height?"}),
    )
    .await;
    let (_, page) = events_until(&st, &id, "tool_call").await;
    // The call is registered as waiting just after its event; give the loop a moment.
    let mut waiting = page["pendingCoreCalls"].clone();
    for _ in 0..20 {
        if waiting == serde_json::json!(["c1"]) {
            break;
        }
        tokio::time::sleep(Duration::from_millis(25)).await;
        let (_, p) = call(
            &st,
            "GET",
            &format!("/sessions/{id}/events?after=0&wait_ms=0"),
            serde_json::Value::Null,
        )
        .await;
        waiting = p["pendingCoreCalls"].clone();
    }
    assert_eq!(waiting, serde_json::json!(["c1"]));
    let (_, v) = call(&st, "GET", "/sessions", serde_json::Value::Null).await;
    assert_eq!(
        v["sessions"][0]["pendingCoreCalls"],
        serde_json::json!(["c1"])
    );
    assert_eq!(v["sessions"][0]["busy"], true);
    let (s, _) = call(
        &st,
        "POST",
        &format!("/sessions/{id}/tool_results"),
        serde_json::json!({"callId": "c1", "status": "ok", "content": "{\"height\":6310}"}),
    )
    .await;
    assert_eq!(s, StatusCode::OK);
    let (_, page) = events_until(&st, &id, "done").await;
    assert_eq!(page["pendingCoreCalls"], serde_json::json!([]));
}

#[tokio::test(flavor = "multi_thread")]
async fn a_streaming_model_adds_delta_events_and_keeps_the_final_event() {
    let st = state_with(vec![AssistantTurn::text("Your node is validating.")], true);
    let id = create(&st).await;
    call(
        &st,
        "POST",
        &format!("/sessions/{id}/messages"),
        serde_json::json!({"text": "status?"}),
    )
    .await;
    let (evs, _) = events_until(&st, &id, "done").await;
    let kinds: Vec<&str> = evs.iter().map(|e| e["type"].as_str().unwrap()).collect();
    assert_eq!(kinds.first(), Some(&"step_start"));
    assert_eq!(&kinds[kinds.len() - 2..], &["final", "done"]);
    let streamed: String = evs
        .iter()
        .filter(|e| e["type"] == "assistant_delta")
        .map(|e| e["text"].as_str().unwrap())
        .collect();
    assert_eq!(streamed, "Your node is validating.");
    let fin = evs.iter().find(|e| e["type"] == "final").unwrap();
    assert_eq!(
        fin["content"], "Your node is validating.",
        "the final event is unchanged for existing clients"
    );
}
