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

/// Regression (found by the S1.8 end-to-end smoke): the production model client must be safe to
/// create and drop inside the async runtime. reqwest's blocking client owns an internal runtime;
/// building or dropping it in an async handler panicked and poisoned the session lock.
#[tokio::test(flavor = "multi_thread")]
async fn the_production_client_survives_create_and_close_inside_the_runtime() {
    let st = Arc::new(AppState {
        estop: EmergencyStop::new(),
        queue: Arc::new(ApprovalQueue::new()),
        skills: vec![],
        dispatch: None,
        bearer: BEARER.to_string(),
        run_slots: Arc::new(tokio::sync::Semaphore::new(MAX_CONCURRENT_SKILLS)),
        sessions: production_sessions(),
    });
    let r = app(st.clone())
        .oneshot(req(
            "POST",
            "/sessions",
            create_body("http://127.0.0.1:9/v1"),
            true,
        ))
        .await
        .unwrap();
    assert_eq!(r.status(), StatusCode::CREATED);
    let id = json(r).await["id"].as_str().unwrap().to_string();
    // A turn against a closed port fails honestly (no panic), and the session keeps working.
    app(st.clone())
        .oneshot(req(
            "POST",
            &format!("/sessions/{id}/messages"),
            serde_json::json!({"text": "hi"}),
            true,
        ))
        .await
        .unwrap();
    let evs = wait_for(&st, &id, "done").await;
    assert!(evs.iter().any(|e| e["type"] == "error"), "{evs:?}");
    let r = app(st.clone())
        .oneshot(req(
            "DELETE",
            &format!("/sessions/{id}"),
            serde_json::Value::Null,
            true,
        ))
        .await
        .unwrap();
    assert_eq!(r.status(), StatusCode::OK);
    let r = app(st.clone())
        .oneshot(req(
            "POST",
            "/sessions",
            create_body("http://127.0.0.1:9/v1"),
            true,
        ))
        .await
        .unwrap();
    assert_eq!(
        r.status(),
        StatusCode::CREATED,
        "the session lock is not poisoned"
    );
}

// ---- HUP-S1.4: tracks + briefs (the interview every client shares) ----

#[tokio::test]
async fn tracks_and_briefs_are_bearer_gated() {
    let st = state_with(vec![], Duration::from_secs(1));
    for (m, p) in [
        ("GET", "/tracks"),
        ("POST", "/briefs"),
        ("POST", "/briefs/check"),
    ] {
        let r = app(st.clone())
            .oneshot(req(m, p, serde_json::json!({}), false))
            .await
            .unwrap();
        assert_eq!(r.status(), StatusCode::UNAUTHORIZED, "{m} {p}");
    }
}

#[tokio::test]
async fn get_tracks_lists_the_five_launch_tracks_with_their_questions() {
    let st = state_with(vec![], Duration::from_secs(1));
    let r = app(st)
        .oneshot(req("GET", "/tracks", serde_json::Value::Null, true))
        .await
        .unwrap();
    assert_eq!(r.status(), StatusCode::OK);
    let v = json(r).await;
    let tracks = v.as_array().expect("array");
    assert_eq!(tracks.len(), 5);
    assert!(tracks.iter().all(|t| t["questions"]
        .as_array()
        .map(|q| q.len() >= 3)
        .unwrap_or(false)));
}

#[tokio::test]
async fn post_briefs_uses_defaults_suggests_a_track_and_refuses_bad_answers() {
    let st = state_with(vec![], Duration::from_secs(1));
    // no track given: suggested from the goal; no answers: defaults
    let r = app(st.clone())
        .oneshot(req(
            "POST",
            "/briefs",
            serde_json::json!({"goal": "help me make an NFT project called Lemon Drops"}),
            true,
        ))
        .await
        .unwrap();
    assert_eq!(r.status(), StatusCode::OK);
    let v = json(r).await;
    assert_eq!(v["brief"]["track"], "full-project");
    assert_eq!(v["brief"]["workflow"], "hello-mint");
    assert!(v["markdown"].as_str().unwrap_or("").contains("## Gates"));

    let r = app(st.clone())
        .oneshot(req(
            "POST",
            "/briefs",
            serde_json::json!({"goal": "what's the weather"}),
            true,
        ))
        .await
        .unwrap();
    assert_eq!(
        r.status(),
        StatusCode::UNPROCESSABLE_ENTITY,
        "no track and none suggested"
    );

    let r = app(st)
        .oneshot(req(
            "POST",
            "/briefs",
            serde_json::json!({"track": "full-project", "goal": "x", "answers": {"standard": "ERC-20"}}),
            true,
        ))
        .await
        .unwrap();
    assert_eq!(r.status(), StatusCode::UNPROCESSABLE_ENTITY);
    assert!(json(r).await["error"]
        .as_str()
        .unwrap_or("")
        .contains("one of"));
}

#[tokio::test]
async fn briefs_check_accepts_wording_edits_and_refuses_a_dropped_gate() {
    let st = state_with(vec![], Duration::from_secs(1));
    let r = app(st.clone())
        .oneshot(req(
            "POST",
            "/briefs",
            serde_json::json!({"track": "smart-contract", "goal": "a capped token"}),
            true,
        ))
        .await
        .unwrap();
    let mut brief = json(r).await["brief"].clone();
    brief["goal"] = serde_json::json!("a capped token, 1M supply");
    let r = app(st.clone())
        .oneshot(req(
            "POST",
            "/briefs/check",
            serde_json::json!({"brief": brief}),
            true,
        ))
        .await
        .unwrap();
    assert_eq!(r.status(), StatusCode::OK);
    assert!(json(r).await["markdown"]
        .as_str()
        .unwrap_or("")
        .contains("1M supply"));

    let gates = brief["gates"].as_array().cloned().unwrap_or_default();
    brief["gates"] = serde_json::json!(gates.into_iter().skip(1).collect::<Vec<_>>());
    let r = app(st)
        .oneshot(req(
            "POST",
            "/briefs/check",
            serde_json::json!({"brief": brief}),
            true,
        ))
        .await
        .unwrap();
    assert_eq!(r.status(), StatusCode::UNPROCESSABLE_ENTITY);
}

// ---------------------------------------------------------------------------------------------
// HUP-S2.7 — taint annotations through session tool specs, and the HIC downgrade over the wire
// ---------------------------------------------------------------------------------------------

fn taint_body(hic_aware: Option<bool>) -> serde_json::Value {
    let mut b = serde_json::json!({
        "model": "gemma-4",
        "systemPrompt": "You are Hermes.",
        "llm": {"baseUrl": "http://127.0.0.1:18080/v1", "bearer": "k"},
        "tools": [
            {"name": "web_fetch", "description": "fetch a page", "parameters": {"type": "object"},
             "host": "core", "annotations": {"effect": "none", "trust": "untrusted"}},
            {"name": "write_note", "description": "write a note", "parameters": {"type": "object"},
             "host": "core", "annotations": {"effect": "write", "trust": "trusted"}},
            {"name": "node_status", "description": "node", "parameters": {"type": "object"},
             "host": "core", "annotations": {"effect": "none", "trust": "trusted"}}
        ]
    });
    if let Some(h) = hic_aware {
        b["hicAware"] = serde_json::json!(h);
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

async fn create_with(st: &Arc<AppState>, body: serde_json::Value) -> String {
    let r = app(st.clone())
        .oneshot(req("POST", "/sessions", body, true))
        .await
        .unwrap();
    assert_eq!(r.status(), StatusCode::CREATED);
    json(r).await["id"].as_str().unwrap().to_string()
}

async fn post_result(st: &Arc<AppState>, id: &str, body: serde_json::Value) -> StatusCode {
    let mut status = StatusCode::CONFLICT;
    for _ in 0..40 {
        let r = app(st.clone())
            .oneshot(req(
                "POST",
                &format!("/sessions/{id}/tool_results"),
                body.clone(),
                true,
            ))
            .await
            .unwrap();
        status = r.status();
        if status != StatusCode::CONFLICT {
            break;
        }
        tokio::time::sleep(Duration::from_millis(25)).await;
    }
    status
}

async fn say(st: &Arc<AppState>, id: &str, text: &str) {
    let r = app(st.clone())
        .oneshot(req(
            "POST",
            &format!("/sessions/{id}/messages"),
            serde_json::json!({ "text": text }),
            true,
        ))
        .await
        .unwrap();
    assert_eq!(r.status(), StatusCode::ACCEPTED);
}

#[tokio::test(flavor = "multi_thread")]
async fn without_hic_aware_core_a_tainted_write_is_refused_in_the_sidecar() {
    let st = state_with(
        vec![
            tc("c1", "web_fetch"),
            tc("c2", "write_note"),
            AssistantTurn::text("ok"),
        ],
        Duration::from_secs(10),
    );
    // The existing core client sends no hicAware: it defaults to false.
    let id = create_with(&st, taint_body(None)).await;
    say(&st, &id, "read then write").await;
    wait_for(&st, &id, "tool_call").await;
    let s = post_result(
        &st,
        &id,
        serde_json::json!({"callId": "c1", "status": "ok", "content": "<html>page</html>"}),
    )
    .await;
    assert_eq!(s, StatusCode::OK);
    let evs = wait_for(&st, &id, "done").await;
    let tainted = evs
        .iter()
        .find(|e| e["type"] == "tainted")
        .expect("tainted event");
    assert_eq!(tainted["source"], "web_fetch");
    let c2 = evs
        .iter()
        .find(|e| e["type"] == "tool_call" && e["call"]["id"] == "c2")
        .unwrap();
    assert_eq!(c2["hic"], "required");
    assert!(c2["host"].is_null(), "not dispatched to core: {c2}");
    let r2 = evs
        .iter()
        .find(|e| e["type"] == "tool_result" && e["call_id"] == "c2")
        .unwrap();
    assert_eq!(r2["status"], "denied");
    // The untainted first call kept today's wire shape.
    let c1 = evs
        .iter()
        .find(|e| e["type"] == "tool_call" && e["call"]["id"] == "c1")
        .unwrap();
    assert_eq!(c1["host"], "core");
    assert!(c1.get("hic").is_none());
}

#[tokio::test(flavor = "multi_thread")]
async fn a_hic_aware_core_receives_the_tainted_write_marked_required() {
    let st = state_with(
        vec![
            tc("c1", "web_fetch"),
            tc("c2", "write_note"),
            AssistantTurn::text("ok"),
        ],
        Duration::from_secs(10),
    );
    let id = create_with(&st, taint_body(Some(true))).await;
    say(&st, &id, "read then write").await;
    wait_for(&st, &id, "tool_call").await;
    post_result(
        &st,
        &id,
        serde_json::json!({"callId": "c1", "status": "ok", "content": "page"}),
    )
    .await;
    let s = post_result(
        &st,
        &id,
        serde_json::json!({"callId": "c2", "status": "ok", "content": "written after the member approved"}),
    )
    .await;
    assert_eq!(s, StatusCode::OK, "core is asked, and answers");
    let evs = wait_for(&st, &id, "done").await;
    let c2 = evs
        .iter()
        .find(|e| e["type"] == "tool_call" && e["call"]["id"] == "c2")
        .unwrap();
    assert_eq!(c2["host"], "core");
    assert_eq!(c2["hic"], "required");
    assert!(c2["hic_reason"].as_str().unwrap().contains("web_fetch"));
}

#[tokio::test(flavor = "multi_thread")]
async fn the_taint_outlives_the_turn_that_caused_it() {
    let st = state_with(
        vec![
            tc("c1", "web_fetch"),
            AssistantTurn::text("read it"),
            tc("c2", "write_note"),
            AssistantTurn::text("ok"),
        ],
        Duration::from_secs(10),
    );
    let id = create_with(&st, taint_body(None)).await;
    say(&st, &id, "read").await;
    wait_for(&st, &id, "tool_call").await;
    post_result(
        &st,
        &id,
        serde_json::json!({"callId": "c1", "status": "ok", "content": "page"}),
    )
    .await;
    wait_for(&st, &id, "done").await;
    // wait until the session is idle again, then send the second turn
    for _ in 0..40 {
        if !st.sessions.get(&id).unwrap().is_busy() {
            break;
        }
        tokio::time::sleep(Duration::from_millis(25)).await;
    }
    say(&st, &id, "now write").await;
    let mut evs = vec![];
    for _ in 0..40 {
        evs = st
            .sessions
            .get(&id)
            .unwrap()
            .events_after(0)
            .events
            .into_iter()
            .map(|e| serde_json::to_value(e.event).unwrap())
            .collect::<Vec<_>>();
        if evs.iter().filter(|e| e["type"] == "done").count() == 2 {
            break;
        }
        tokio::time::sleep(Duration::from_millis(25)).await;
    }
    let c2 = evs
        .iter()
        .find(|e| e["type"] == "tool_call" && e["call"]["id"] == "c2")
        .expect("second turn's call");
    assert_eq!(c2["hic"], "required");
    assert_eq!(evs.iter().filter(|e| e["type"] == "tainted").count(), 1);
}

#[tokio::test(flavor = "multi_thread")]
async fn core_can_mark_one_result_untrusted() {
    let st = state_with(
        vec![
            tc("c1", "node_status"),
            tc("c2", "write_note"),
            AssistantTurn::text("ok"),
        ],
        Duration::from_secs(10),
    );
    let id = create_with(&st, taint_body(None)).await;
    say(&st, &id, "x").await;
    wait_for(&st, &id, "tool_call").await;
    // An unknown trust value is refused, not guessed.
    let bad = post_result(
        &st,
        &id,
        serde_json::json!({"callId": "c1", "status": "ok", "content": "x", "trust": "maybe"}),
    )
    .await;
    assert_eq!(bad, StatusCode::BAD_REQUEST);
    let s = post_result(
        &st,
        &id,
        serde_json::json!({"callId": "c1", "status": "ok", "content": "outside text", "trust": "untrusted"}),
    )
    .await;
    assert_eq!(s, StatusCode::OK);
    let evs = wait_for(&st, &id, "done").await;
    assert!(evs
        .iter()
        .any(|e| e["type"] == "tainted" && e["source"] == "node_status"));
    let c2 = evs
        .iter()
        .find(|e| e["type"] == "tool_call" && e["call"]["id"] == "c2")
        .unwrap();
    assert_eq!(c2["hic"], "required");
}

#[test]
fn tool_result_trust_maps_to_the_outcome() {
    let mk = |status: &str, trust: Option<&str>| sessions::ToolResultReq {
        call_id: "c".into(),
        status: status.into(),
        content: "body".into(),
        trust: trust.map(String::from),
    };
    use citrate_agent_loop::ToolOutcome;
    assert_eq!(
        sessions::outcome_from(mk("ok", None)),
        Ok(ToolOutcome::Ok("body".into()))
    );
    assert_eq!(
        sessions::outcome_from(mk("ok", Some("trusted"))),
        Ok(ToolOutcome::Ok("body".into()))
    );
    assert_eq!(
        sessions::outcome_from(mk("ok", Some("untrusted"))),
        Ok(ToolOutcome::Untrusted("body".into()))
    );
    assert!(sessions::outcome_from(mk("ok", Some("maybe"))).is_err());
    // denied/error keep their meaning; a denied call ran nothing so trust is irrelevant.
    assert_eq!(
        sessions::outcome_from(mk("denied", Some("untrusted"))),
        Ok(ToolOutcome::Denied("body".into()))
    );
}

async fn events_status(st: &Arc<AppState>, id: &str) -> StatusCode {
    app(st.clone())
        .oneshot(req(
            "GET",
            &format!("/sessions/{id}/events?after=0"),
            serde_json::Value::Null,
            true,
        ))
        .await
        .unwrap()
        .status()
}

/// Sessions the app never closed (a Stop, a reload) do not fill the table for good: when it is
/// full, a new session replaces the idle session used least recently.
#[tokio::test(flavor = "multi_thread")]
async fn a_full_table_replaces_the_least_recently_used_idle_session() {
    let st = state_with(vec![], Duration::from_secs(5));
    let mut ids = Vec::new();
    for _ in 0..sessions::MAX_SESSIONS {
        ids.push(create(&st).await);
    }
    // The first session is used again, so the second is now the least recently used.
    assert_eq!(events_status(&st, &ids[0]).await, StatusCode::OK);
    let newest = create(&st).await;
    assert_eq!(st.sessions.count(), sessions::MAX_SESSIONS);
    assert_eq!(events_status(&st, &ids[0]).await, StatusCode::OK);
    assert_eq!(events_status(&st, &ids[1]).await, StatusCode::NOT_FOUND);
    assert_eq!(events_status(&st, &newest).await, StatusCode::OK);
}

/// A session in the middle of a turn is never replaced; with every session busy the table is
/// full as before.
#[tokio::test(flavor = "multi_thread")]
async fn busy_sessions_are_never_replaced() {
    let turns = (0..sessions::MAX_SESSIONS)
        .map(|i| {
            AssistantTurn::tools(vec![ToolCall {
                id: format!("c{i}"),
                name: "node_status".into(),
                arguments: "{}".into(),
            }])
        })
        .collect();
    let st = state_with(turns, Duration::from_secs(30));
    let mut ids = Vec::new();
    for _ in 0..sessions::MAX_SESSIONS {
        let id = create(&st).await;
        app(st.clone())
            .oneshot(req(
                "POST",
                &format!("/sessions/{id}/messages"),
                serde_json::json!({"text": "status?"}),
                true,
            ))
            .await
            .unwrap();
        wait_for(&st, &id, "tool_call").await;
        ids.push(id);
    }
    let r = app(st.clone())
        .oneshot(req(
            "POST",
            "/sessions",
            create_body("http://127.0.0.1:18080/v1"),
            true,
        ))
        .await
        .unwrap();
    assert_eq!(r.status(), StatusCode::TOO_MANY_REQUESTS);
    for id in &ids {
        assert_eq!(events_status(&st, id).await, StatusCode::OK);
    }
    st.sessions.stop_all();
}
