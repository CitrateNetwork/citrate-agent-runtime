//! HUP-S1.1b — agent sessions over the real control-plane routes (tower::oneshot, no socket),
//! with a scripted model injected through the session manager's LLM factory.

use super::*;
use axum::body::Body;
use axum::http::{Request, StatusCode};
use citrate_agent_loop::{AssistantTurn, CompletionRequest, LlmClient, LlmError, ToolCall};
use std::sync::Mutex;
use std::time::Duration;
use tower::ServiceExt;

const BEARER: &str = "test-bearer-token-0123456789";

struct Script(Mutex<Vec<AssistantTurn>>);
impl LlmClient for Script {
    fn complete(&self, _req: &CompletionRequest) -> Result<AssistantTurn, LlmError> {
        let mut t = self.0.lock().unwrap();
        if t.is_empty() {
            Ok(AssistantTurn::text("(done)"))
        } else {
            Ok(t.remove(0))
        }
    }
}

fn state_with(turns: Vec<AssistantTurn>, core_deadline: Duration) -> Arc<AppState> {
    let script: Arc<dyn LlmClient> = Arc::new(Script(Mutex::new(turns)));
    let sessions = Arc::new(sessions::SessionManager::new(
        Arc::new(move |_ep: &sessions::LlmEndpoint| script.clone()),
        core_deadline,
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

async fn json(resp: axum::response::Response) -> serde_json::Value {
    let bytes = axum::body::to_bytes(resp.into_body(), 1 << 20)
        .await
        .unwrap();
    serde_json::from_slice(&bytes).unwrap_or(serde_json::Value::Null)
}

fn create_body(base_url: &str) -> serde_json::Value {
    serde_json::json!({
        "model": "gemma-4",
        "systemPrompt": "You are Hermes.",
        "llm": {"baseUrl": base_url, "bearer": "k"},
        "tools": [{"name": "node_status", "description": "node", "parameters": {"type": "object"}, "host": "core"}]
    })
}

async fn create(st: &Arc<AppState>) -> String {
    let r = app(st.clone())
        .oneshot(req(
            "POST",
            "/sessions",
            create_body("http://127.0.0.1:18080/v1"),
            true,
        ))
        .await
        .unwrap();
    assert_eq!(r.status(), StatusCode::CREATED);
    json(r).await["id"].as_str().unwrap().to_string()
}

/// Poll events until one of `kind` appears (or panic after ~5 s).
async fn wait_for(st: &Arc<AppState>, id: &str, kind: &str) -> Vec<serde_json::Value> {
    let mut all = vec![];
    let mut after = 0u64;
    for _ in 0..50 {
        let r = app(st.clone())
            .oneshot(req(
                "GET",
                &format!("/sessions/{id}/events?after={after}&wait_ms=100"),
                serde_json::Value::Null,
                true,
            ))
            .await
            .unwrap();
        let page = json(r).await;
        for e in page["events"].as_array().unwrap() {
            after = after.max(e["seq"].as_u64().unwrap());
            all.push(e["event"].clone());
        }
        if all.iter().any(|e| e["type"] == kind) {
            return all;
        }
    }
    panic!("no {kind} event; got {all:?}");
}

#[tokio::test]
async fn sessions_require_the_bearer() {
    let st = state_with(vec![], Duration::from_secs(5));
    let r = app(st)
        .oneshot(req(
            "POST",
            "/sessions",
            create_body("http://127.0.0.1:1/v1"),
            false,
        ))
        .await
        .unwrap();
    assert_eq!(r.status(), StatusCode::UNAUTHORIZED);
}

#[tokio::test]
async fn only_loopback_http_or_https_model_endpoints_are_accepted() {
    let st = state_with(vec![], Duration::from_secs(5));
    for bad in [
        "http://10.0.0.5:8080/v1",
        "http://evil.example/v1",
        "ftp://x",
        "file:///etc/passwd",
    ] {
        let r = app(st.clone())
            .oneshot(req("POST", "/sessions", create_body(bad), true))
            .await
            .unwrap();
        assert_eq!(r.status(), StatusCode::BAD_REQUEST, "{bad} must be refused");
    }
    for good in [
        "http://127.0.0.1:18080/v1",
        "http://localhost:18080/v1",
        "http://[::1]:18080/v1",
        "https://infer.citrate.ai/v1",
    ] {
        let r = app(st.clone())
            .oneshot(req("POST", "/sessions", create_body(good), true))
            .await
            .unwrap();
        assert_eq!(r.status(), StatusCode::CREATED, "{good} must be accepted");
    }
}

#[tokio::test(flavor = "multi_thread")]
async fn a_message_runs_a_turn_and_streams_events() {
    let st = state_with(
        vec![AssistantTurn::text("Your node is validating.")],
        Duration::from_secs(5),
    );
    let id = create(&st).await;
    let r = app(st.clone())
        .oneshot(req(
            "POST",
            &format!("/sessions/{id}/messages"),
            serde_json::json!({"text": "status?"}),
            true,
        ))
        .await
        .unwrap();
    assert_eq!(r.status(), StatusCode::ACCEPTED);
    let evs = wait_for(&st, &id, "done").await;
    let kinds: Vec<&str> = evs.iter().map(|e| e["type"].as_str().unwrap()).collect();
    assert_eq!(kinds, vec!["step_start", "final", "done"]);
    assert_eq!(evs[1]["content"], "Your node is validating.");
}

#[tokio::test(flavor = "multi_thread")]
async fn a_core_tool_waits_for_the_app_and_its_result_continues_the_turn() {
    let call = ToolCall {
        id: "c1".into(),
        name: "node_status".into(),
        arguments: "{}".into(),
    };
    let st = state_with(
        vec![
            AssistantTurn::tools(vec![call]),
            AssistantTurn::text("Height 6,310."),
        ],
        Duration::from_secs(10),
    );
    let id = create(&st).await;
    app(st.clone())
        .oneshot(req(
            "POST",
            &format!("/sessions/{id}/messages"),
            serde_json::json!({"text": "height?"}),
            true,
        ))
        .await
        .unwrap();
    let evs = wait_for(&st, &id, "tool_call").await;
    let tc = evs.iter().find(|e| e["type"] == "tool_call").unwrap();
    assert_eq!(tc["host"], "core");
    assert_eq!(tc["call"]["id"], "c1");
    // The app runs the tool through its own gates, then posts the result.
    let mut delivered = StatusCode::CONFLICT;
    for _ in 0..40 {
        let r = app(st.clone())
            .oneshot(req(
                "POST",
                &format!("/sessions/{id}/tool_results"),
                serde_json::json!({"callId": "c1", "status": "ok", "content": "{\"height\":6310}"}),
                true,
            ))
            .await
            .unwrap();
        delivered = r.status();
        if delivered == StatusCode::OK {
            break;
        }
        tokio::time::sleep(Duration::from_millis(25)).await;
    }
    assert_eq!(delivered, StatusCode::OK);
    let evs = wait_for(&st, &id, "done").await;
    assert!(evs
        .iter()
        .any(|e| e["type"] == "final" && e["content"] == "Height 6,310."));
    // A second result for the same call has nobody waiting.
    let r = app(st.clone())
        .oneshot(req(
            "POST",
            &format!("/sessions/{id}/tool_results"),
            serde_json::json!({"callId": "c1", "status": "ok", "content": "again"}),
            true,
        ))
        .await
        .unwrap();
    assert_eq!(r.status(), StatusCode::CONFLICT);
}

#[tokio::test(flavor = "multi_thread")]
async fn a_core_tool_the_app_never_answers_times_out_as_a_tool_error() {
    let call = ToolCall {
        id: "c1".into(),
        name: "node_status".into(),
        arguments: "{}".into(),
    };
    let st = state_with(
        vec![AssistantTurn::tools(vec![call]), AssistantTurn::text("ok")],
        Duration::from_millis(300),
    );
    let id = create(&st).await;
    app(st.clone())
        .oneshot(req(
            "POST",
            &format!("/sessions/{id}/messages"),
            serde_json::json!({"text": "x"}),
            true,
        ))
        .await
        .unwrap();
    let evs = wait_for(&st, &id, "done").await;
    let tr = evs.iter().find(|e| e["type"] == "tool_result").unwrap();
    assert_eq!(tr["status"], "error");
    assert!(tr["content"].as_str().unwrap().contains("did not answer"));
}

#[tokio::test(flavor = "multi_thread")]
async fn stopping_a_session_releases_a_waiting_tool_and_ends_the_turn() {
    let call = ToolCall {
        id: "c1".into(),
        name: "node_status".into(),
        arguments: "{}".into(),
    };
    let st = state_with(
        vec![
            AssistantTurn::tools(vec![call]),
            AssistantTurn::text("never"),
        ],
        Duration::from_secs(30),
    );
    let id = create(&st).await;
    app(st.clone())
        .oneshot(req(
            "POST",
            &format!("/sessions/{id}/messages"),
            serde_json::json!({"text": "x"}),
            true,
        ))
        .await
        .unwrap();
    wait_for(&st, &id, "tool_call").await;
    let r = app(st.clone())
        .oneshot(req(
            "POST",
            &format!("/sessions/{id}/stop"),
            serde_json::Value::Null,
            true,
        ))
        .await
        .unwrap();
    assert_eq!(r.status(), StatusCode::OK);
    let evs = wait_for(&st, &id, "done").await;
    assert_eq!(evs.last().unwrap()["outcome"], "stopped");
    assert!(
        !evs.iter().any(|e| e["type"] == "final"),
        "no model call after the stop"
    );
}

#[tokio::test(flavor = "multi_thread")]
async fn a_second_message_while_busy_is_refused() {
    let call = ToolCall {
        id: "c1".into(),
        name: "node_status".into(),
        arguments: "{}".into(),
    };
    let st = state_with(
        vec![AssistantTurn::tools(vec![call])],
        Duration::from_secs(30),
    );
    let id = create(&st).await;
    app(st.clone())
        .oneshot(req(
            "POST",
            &format!("/sessions/{id}/messages"),
            serde_json::json!({"text": "one"}),
            true,
        ))
        .await
        .unwrap();
    wait_for(&st, &id, "tool_call").await;
    let r = app(st.clone())
        .oneshot(req(
            "POST",
            &format!("/sessions/{id}/messages"),
            serde_json::json!({"text": "two"}),
            true,
        ))
        .await
        .unwrap();
    assert_eq!(r.status(), StatusCode::CONFLICT);
    st.sessions.stop_all();
}

#[tokio::test(flavor = "multi_thread")]
async fn the_global_estop_halts_sessions_and_refuses_new_work() {
    let call = ToolCall {
        id: "c1".into(),
        name: "node_status".into(),
        arguments: "{}".into(),
    };
    let st = state_with(
        vec![AssistantTurn::tools(vec![call])],
        Duration::from_secs(30),
    );
    let id = create(&st).await;
    app(st.clone())
        .oneshot(req(
            "POST",
            &format!("/sessions/{id}/messages"),
            serde_json::json!({"text": "x"}),
            true,
        ))
        .await
        .unwrap();
    wait_for(&st, &id, "tool_call").await;
    let r = app(st.clone())
        .oneshot(req("POST", "/stop", serde_json::Value::Null, true))
        .await
        .unwrap();
    assert_eq!(r.status(), StatusCode::OK);
    let evs = wait_for(&st, &id, "done").await;
    assert_eq!(evs.last().unwrap()["outcome"], "stopped");
    let r = app(st.clone())
        .oneshot(req(
            "POST",
            &format!("/sessions/{id}/messages"),
            serde_json::json!({"text": "again"}),
            true,
        ))
        .await
        .unwrap();
    assert_eq!(r.status(), StatusCode::SERVICE_UNAVAILABLE);
    let r = app(st.clone())
        .oneshot(req(
            "POST",
            "/sessions",
            create_body("http://127.0.0.1:1/v1"),
            true,
        ))
        .await
        .unwrap();
    assert_eq!(r.status(), StatusCode::SERVICE_UNAVAILABLE);
}

#[tokio::test]
async fn events_after_a_sequence_only_return_newer_events_and_unknown_sessions_404() {
    let st = state_with(vec![], Duration::from_secs(5));
    let r = app(st.clone())
        .oneshot(req(
            "GET",
            "/sessions/nope/events",
            serde_json::Value::Null,
            true,
        ))
        .await
        .unwrap();
    assert_eq!(r.status(), StatusCode::NOT_FOUND);
    let id = create(&st).await;
    let r = app(st.clone())
        .oneshot(req(
            "GET",
            &format!("/sessions/{id}/events?after=0"),
            serde_json::Value::Null,
            true,
        ))
        .await
        .unwrap();
    let page = json(r).await;
    assert_eq!(page["events"].as_array().unwrap().len(), 0);
    assert_eq!(page["lastSeq"], 0);
}

#[test]
fn the_wire_mapping_round_trips_tool_calls() {
    use citrate_agent_loop::{HostKind, Message, Role, ToolAnnotations, ToolSpec};
    let req = CompletionRequest {
        model: "m".into(),
        messages: vec![
            Message::system("sys"),
            Message {
                role: Role::Assistant,
                content: String::new(),
                tool_calls: vec![ToolCall {
                    id: "c1".into(),
                    name: "a".into(),
                    arguments: "{}".into(),
                }],
                tool_call_id: None,
            },
            Message::tool_result("c1", "r"),
        ],
        tools: vec![ToolSpec {
            name: "a".into(),
            description: "d".into(),
            parameters: serde_json::json!({"type":"object"}),
            host: HostKind::Core,
            annotations: ToolAnnotations::default(),
        }],
        max_tokens: 99,
    };
    let body = llm_http::to_wire_body(&req);
    assert_eq!(
        body["messages"][1]["tool_calls"][0]["function"]["name"],
        "a"
    );
    assert_eq!(body["messages"][2]["tool_call_id"], "c1");
    assert_eq!(body["tools"][0]["function"]["name"], "a");
    assert_eq!(body["max_tokens"], 99);
    assert_eq!(body["stream"], false);

    let resp = r#"{"choices":[{"message":{"content":null,"tool_calls":[{"id":"x","function":{"name":"node_status","arguments":{"a":1}}}]}}]}"#;
    let turn = llm_http::parse_turn(resp).unwrap();
    assert_eq!(turn.tool_calls[0].name, "node_status");
    assert_eq!(
        turn.tool_calls[0].arguments, "{\"a\":1}",
        "object arguments are stringified"
    );
    assert!(llm_http::parse_turn(r#"{"choices":[{"message":{"content":""}}]}"#).is_err());
    assert!(llm_http::parse_turn("not json").is_err());
}
