//! HUP-S5.1 + S5.6: the browser in the sidecar. Off unless `CITRATE_HERMES_BROWSER=1`; when on,
//! sessions are offered the `browser_*` tools (names reserved), the control plane serves the
//! Browser pop-out (status, screencast frames, Stop/resume, attach with consent, per-origin
//! consent, decisions on waiting actions), and the global e-stop stops the browser too. These
//! tests use a browser config with no Chromium, so they run anywhere; the real-Chromium paths are
//! covered in agent-browser's live tests.

use super::*;
use axum::body::Body;
use axum::http::{Request, StatusCode};
use citrate_agent_browser::{BrowserConfig, BrowserService};
use citrate_agent_loop::{AssistantTurn, CompletionRequest, LlmClient, LlmError, ToolCall};
use std::path::PathBuf;
use std::sync::Mutex;
use std::time::Duration;
use tower::ServiceExt;

const BEARER: &str = "test-bearer-token-0123456789";

struct Recorder {
    turns: Mutex<Vec<AssistantTurn>>,
    seen: Mutex<Vec<CompletionRequest>>,
}
impl LlmClient for Recorder {
    fn complete(&self, req: &CompletionRequest) -> Result<AssistantTurn, LlmError> {
        if let Ok(mut s) = self.seen.lock() {
            s.push(req.clone());
        }
        let mut t = self
            .turns
            .lock()
            .map_err(|_| LlmError::Transport("lock".into()))?;
        Ok(if t.is_empty() {
            AssistantTurn::text("(done)")
        } else {
            t.remove(0)
        })
    }
}

fn no_chromium() -> Arc<BrowserService> {
    Arc::new(BrowserService::new(BrowserConfig {
        managed_path: Some(PathBuf::from("/nonexistent/citrate/chromium")),
        candidates: Vec::new(),
        approval_timeout: Duration::from_secs(10),
        ..BrowserConfig::default()
    }))
}

fn state(
    turns: Vec<AssistantTurn>,
    browser: Option<Arc<BrowserService>>,
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
    if let Some(b) = browser {
        mgr = mgr.with_browser(b);
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
        .expect("request")
}

async fn call(
    st: &Arc<AppState>,
    method: &str,
    path: &str,
    body: serde_json::Value,
) -> (StatusCode, serde_json::Value) {
    let r = app(st.clone())
        .oneshot(req(method, path, body))
        .await
        .expect("response");
    let status = r.status();
    let bytes = axum::body::to_bytes(r.into_body(), 1 << 20)
        .await
        .unwrap_or_default();
    (
        status,
        serde_json::from_slice(&bytes).unwrap_or(serde_json::Value::Null),
    )
}

fn create_body(tools: serde_json::Value) -> serde_json::Value {
    serde_json::json!({
        "model": "gemma-4",
        "systemPrompt": "You are Hermes.",
        "llm": {"baseUrl": "http://127.0.0.1:18080/v1", "bearer": "k"},
        "tools": tools,
        "maxToolsPerRequest": 32
    })
}

fn tool_call(id: &str, name: &str, args: serde_json::Value) -> AssistantTurn {
    AssistantTurn::tools(vec![ToolCall {
        id: id.into(),
        name: name.into(),
        arguments: args.to_string(),
    }])
}

async fn open(st: &Arc<AppState>) -> String {
    let (s, v) = call(st, "POST", "/sessions", create_body(serde_json::json!([]))).await;
    assert_eq!(s, StatusCode::CREATED, "{v}");
    v["id"].as_str().unwrap_or_default().to_string()
}

async fn events_until_done(st: &Arc<AppState>, id: &str) -> Vec<serde_json::Value> {
    let mut all = vec![];
    let mut after = 0u64;
    for _ in 0..200 {
        let (_, page) = call(
            st,
            "GET",
            &format!("/sessions/{id}/events?after={after}&wait_ms=100"),
            serde_json::Value::Null,
        )
        .await;
        for e in page["events"].as_array().cloned().unwrap_or_default() {
            after = after.max(e["seq"].as_u64().unwrap_or(0));
            all.push(e["event"].clone());
        }
        if all.iter().any(|e| e["type"] == "done") {
            return all;
        }
    }
    panic!("no done event; got {all:?}");
}

#[tokio::test(flavor = "multi_thread")]
async fn without_the_browser_nothing_changes() {
    let (st, rec) = state(vec![], None);
    let tools = serde_json::json!([
        {"name": "browser_snapshot", "description": "a core tool that happens to use this name", "parameters": {"type": "object"}, "host": "core"}
    ]);
    let (s, v) = call(&st, "POST", "/sessions", create_body(tools)).await;
    assert_eq!(s, StatusCode::CREATED, "{v}");
    let id = v["id"].as_str().unwrap_or_default().to_string();
    call(
        &st,
        "POST",
        &format!("/sessions/{id}/messages"),
        serde_json::json!({"text": "hi"}),
    )
    .await;
    events_until_done(&st, &id).await;
    let names: Vec<String> = rec
        .seen
        .lock()
        .map(|s| s[0].tools.iter().map(|t| t.name.clone()).collect())
        .unwrap_or_default();
    assert_eq!(names, vec!["browser_snapshot".to_string()]);
    let (s, v) = call(&st, "GET", "/browser/status", serde_json::Value::Null).await;
    assert_eq!(s, StatusCode::OK);
    assert_eq!(v["enabled"], serde_json::json!(false));
    for (m, p) in [
        ("POST", "/browser/stop"),
        ("POST", "/browser/resume"),
        ("GET", "/browser/frame?after=0"),
        ("POST", "/browser/detach"),
    ] {
        let (s, _) = call(&st, m, p, serde_json::json!({})).await;
        assert_eq!(s, StatusCode::NOT_FOUND, "{p}");
    }
}

#[tokio::test(flavor = "multi_thread")]
async fn the_browser_routes_need_the_bearer() {
    let (st, _) = state(vec![], Some(no_chromium()));
    let r = app(st.clone())
        .oneshot(
            Request::builder()
                .method("GET")
                .uri("/browser/status")
                .body(Body::empty())
                .expect("request"),
        )
        .await
        .expect("response");
    assert_eq!(r.status(), StatusCode::UNAUTHORIZED);
}

#[tokio::test(flavor = "multi_thread")]
async fn with_the_browser_the_tools_are_offered_and_their_names_reserved() {
    let (st, rec) = state(vec![], Some(no_chromium()));
    let id = open(&st).await;
    call(
        &st,
        "POST",
        &format!("/sessions/{id}/messages"),
        serde_json::json!({"text": "hi"}),
    )
    .await;
    events_until_done(&st, &id).await;
    let names: Vec<String> = rec
        .seen
        .lock()
        .map(|s| s[0].tools.iter().map(|t| t.name.clone()).collect())
        .unwrap_or_default();
    for t in citrate_agent_browser::tools::TOOL_NAMES {
        assert!(names.contains(&t.to_string()), "{t} offered: {names:?}");
    }
    let clash = serde_json::json!([
        {"name": "browser_act", "description": "x", "parameters": {"type": "object"}, "host": "core"}
    ]);
    let (s, v) = call(&st, "POST", "/sessions", create_body(clash)).await;
    assert_eq!(s, StatusCode::BAD_REQUEST);
    assert!(
        v["error"].as_str().unwrap_or_default().contains("reserved"),
        "{v}"
    );
}

#[tokio::test(flavor = "multi_thread")]
async fn status_says_not_installed_honestly_and_a_tool_call_reports_it() {
    let (st, _) = state(
        vec![tool_call(
            "c1",
            "browser_navigate",
            serde_json::json!({"url": "https://example.com"}),
        )],
        Some(no_chromium()),
    );
    let (s, v) = call(&st, "GET", "/browser/status", serde_json::Value::Null).await;
    assert_eq!(s, StatusCode::OK);
    assert_eq!(v["enabled"], serde_json::json!(true));
    assert_eq!(v["chromium"]["state"], "not_installed");
    assert_eq!(v["mode"], "off");
    assert_eq!(v["stopped"], serde_json::json!(false));
    let cats: Vec<String> = v["excludedCategories"]
        .as_array()
        .map(|a| {
            a.iter()
                .filter_map(|c| c["id"].as_str().map(str::to_string))
                .collect()
        })
        .unwrap_or_default();
    assert_eq!(cats, vec!["banking", "email", "health"]);

    let id = open(&st).await;
    call(
        &st,
        "POST",
        &format!("/sessions/{id}/messages"),
        serde_json::json!({"text": "open it"}),
    )
    .await;
    let events = events_until_done(&st, &id).await;
    let result = events
        .iter()
        .find(|e| e["type"] == "tool_result")
        .expect("a tool result");
    assert_eq!(result["status"], "error");
    assert!(
        result["content"]
            .as_str()
            .unwrap_or_default()
            .contains("no Chromium is installed"),
        "{result}"
    );
}

#[tokio::test(flavor = "multi_thread")]
async fn the_read_only_tools_and_the_picker_are_wired_into_sessions() {
    // HUP-S5.1 (02 §5 console/network) and HUP-S5.3 (browser_pick over the session's decide()).
    let (st, rec) = state(
        vec![
            tool_call("c1", "browser_console_messages", serde_json::json!({})),
            tool_call(
                "c2",
                "browser_pick",
                serde_json::json!({"goal": "open the docs"}),
            ),
        ],
        Some(no_chromium()),
    );
    let id = open(&st).await;
    call(
        &st,
        "POST",
        &format!("/sessions/{id}/messages"),
        serde_json::json!({"text": "look at the page"}),
    )
    .await;
    let events = events_until_done(&st, &id).await;
    let results: Vec<&serde_json::Value> = events
        .iter()
        .filter(|e| e["type"] == "tool_result")
        .collect();
    assert_eq!(results.len(), 2, "{events:?}");
    let console = results[0]["content"].as_str().unwrap_or_default();
    assert!(
        console.contains("no page open"),
        "launches nothing: {console}"
    );
    let pick = results[1]["content"].as_str().unwrap_or_default();
    assert!(
        pick.contains("no Chromium is installed"),
        "the session has a picker, so it went on to read the page: {pick}"
    );
    assert!(!pick.contains("not configured"), "{pick}");
    let offered: Vec<String> = rec
        .seen
        .lock()
        .map(|s| s[0].tools.iter().map(|t| t.name.clone()).collect())
        .unwrap_or_default();
    for t in [
        "browser_console_messages",
        "browser_network_requests",
        "browser_pick",
    ] {
        assert!(
            offered.contains(&t.to_string()),
            "{t} not offered: {offered:?}"
        );
    }
}

#[tokio::test(flavor = "multi_thread")]
async fn after_taint_a_browser_action_waits_for_the_members_decision() {
    // The first call's output (even an error body) is untrusted, so the session is tainted;
    // the navigate after it must wait for the member, who declines here.
    let (st, _) = state(
        vec![
            tool_call("c1", "browser_snapshot", serde_json::json!({})),
            tool_call(
                "c2",
                "browser_navigate",
                serde_json::json!({"url": "https://example.com/x"}),
            ),
        ],
        Some(no_chromium()),
    );
    let id = open(&st).await;
    call(
        &st,
        "POST",
        &format!("/sessions/{id}/messages"),
        serde_json::json!({"text": "go"}),
    )
    .await;
    let mut pending = serde_json::Value::Null;
    for _ in 0..100 {
        let (_, v) = call(&st, "GET", "/browser/status", serde_json::Value::Null).await;
        if !v["pendingAction"].is_null() {
            pending = v["pendingAction"].clone();
            break;
        }
        tokio::time::sleep(Duration::from_millis(50)).await;
    }
    assert_eq!(
        pending["summary"], "Open https://example.com/x",
        "{pending}"
    );
    assert!(
        pending["reason"]
            .as_str()
            .unwrap_or_default()
            .contains("untrusted"),
        "{pending}"
    );
    let (s, _) = call(
        &st,
        "POST",
        "/browser/actions/decide",
        serde_json::json!({"id": "b999", "allow": true}),
    )
    .await;
    assert_eq!(s, StatusCode::CONFLICT);
    let (s, v) = call(
        &st,
        "POST",
        "/browser/actions/decide",
        serde_json::json!({"id": pending["id"], "allow": false}),
    )
    .await;
    assert_eq!(s, StatusCode::OK, "{v}");
    let events = events_until_done(&st, &id).await;
    let nav_call = events
        .iter()
        .find(|e| e["type"] == "tool_call" && e["call"]["name"] == "browser_navigate")
        .expect("the navigate call");
    assert_eq!(nav_call["hic"], "required");
    let last = events
        .iter()
        .rfind(|e| e["type"] == "tool_result")
        .expect("a result");
    assert_eq!(last["status"], "denied", "{last}");
}

#[tokio::test(flavor = "multi_thread")]
async fn attach_and_origin_consent_are_member_controls() {
    let (st, _) = state(vec![], Some(no_chromium()));
    let (s, v) = call(
        &st,
        "POST",
        "/browser/attach",
        serde_json::json!({"port": 9222, "consent": false}),
    )
    .await;
    assert_eq!(s, StatusCode::BAD_REQUEST);
    assert!(
        v["error"].as_str().unwrap_or_default().contains("consent"),
        "{v}"
    );
    let (s, _) = call(
        &st,
        "POST",
        "/browser/attach",
        serde_json::json!({"port": 80, "consent": true}),
    )
    .await;
    assert_eq!(s, StatusCode::BAD_REQUEST, "a privileged port is refused");

    let (s, v) = call(
        &st,
        "POST",
        "/browser/origins",
        serde_json::json!({"origin": "https://www.chase.com", "allow": true}),
    )
    .await;
    assert_eq!(s, StatusCode::BAD_REQUEST, "{v}");
    let (s, v) = call(
        &st,
        "POST",
        "/browser/origins",
        serde_json::json!({"origin": "https://docs.example.org/page", "allow": true}),
    )
    .await;
    assert_eq!(s, StatusCode::OK, "{v}");
    assert_eq!(v["origin"], "https://docs.example.org");
    let (_, v) = call(&st, "GET", "/browser/status", serde_json::Value::Null).await;
    assert_eq!(
        v["consentedOrigins"],
        serde_json::json!(["https://docs.example.org"])
    );
    let (s, _) = call(
        &st,
        "POST",
        "/browser/origins",
        serde_json::json!({"origin": "https://docs.example.org", "allow": false}),
    )
    .await;
    assert_eq!(s, StatusCode::OK);
    let (_, v) = call(&st, "GET", "/browser/status", serde_json::Value::Null).await;
    assert_eq!(v["consentedOrigins"], serde_json::json!([]));
    let (s, _) = call(
        &st,
        "POST",
        "/browser/origins",
        serde_json::json!({"origin": "file:///", "allow": true}),
    )
    .await;
    assert_eq!(s, StatusCode::BAD_REQUEST);
}

#[tokio::test(flavor = "multi_thread")]
async fn stop_latches_resume_clears_and_the_global_estop_stops_the_browser() {
    let (st, _) = state(vec![], Some(no_chromium()));
    let (s, _) = call(
        &st,
        "GET",
        "/browser/frame?after=0",
        serde_json::Value::Null,
    )
    .await;
    assert_eq!(s, StatusCode::NO_CONTENT, "no frame yet");
    let (s, _) = call(&st, "POST", "/browser/stop", serde_json::json!({})).await;
    assert_eq!(s, StatusCode::OK);
    let (_, v) = call(&st, "GET", "/browser/status", serde_json::Value::Null).await;
    assert_eq!(v["stopped"], serde_json::json!(true));
    let (s, _) = call(&st, "POST", "/browser/resume", serde_json::json!({})).await;
    assert_eq!(s, StatusCode::OK);
    let (_, v) = call(&st, "GET", "/browser/status", serde_json::Value::Null).await;
    assert_eq!(v["stopped"], serde_json::json!(false));
    let (s, _) = call(&st, "POST", "/stop", serde_json::json!({})).await;
    assert_eq!(s, StatusCode::OK);
    let (_, v) = call(&st, "GET", "/browser/status", serde_json::Value::Null).await;
    assert_eq!(
        v["stopped"],
        serde_json::json!(true),
        "the e-stop stops the browser too"
    );
}

#[test]
fn a_non_browser_sidecar_call_after_taint_is_still_declined() {
    let host = sessions::SidecarHost {
        skills: None,
        toolchain: None,
        mcp: None,
        capsules: None,
        browser: Some(citrate_agent_browser::tools::BrowserToolHost::new(
            no_chromium(),
            citrate_agent_loop::StopFlag::default(),
        )),
        ..Default::default()
    };
    use citrate_agent_loop::{ToolHost, ToolOutcome};
    assert!(host.honors_explicit_approval());
    let out = host.execute_with_explicit_approval(
        &ToolCall {
            id: "c".into(),
            name: "some_capsule".into(),
            arguments: "{}".into(),
        },
        "tainted",
    );
    assert!(matches!(out, ToolOutcome::Denied(_)), "{out:?}");
    let without = sessions::SidecarHost {
        skills: None,
        toolchain: None,
        mcp: None,
        capsules: None,
        browser: None,
        ..Default::default()
    };
    assert!(
        !without.honors_explicit_approval(),
        "unchanged without the browser"
    );
}

/// Sidecar shutdown stops the browser (and the other child processes) explicitly and latches it,
/// so nothing starts a new Chromium while the sidecar exits.
#[test]
fn shutdown_stops_and_latches_the_browser() {
    let browser = no_chromium();
    let mgr = sessions::SessionManager::new(
        Arc::new(|_ep: &sessions::LlmEndpoint| -> Arc<dyn LlmClient> {
            Arc::new(llm_http::OpenAiCompatClient::new(
                "http://127.0.0.1:9/v1",
                "k",
                Duration::from_secs(1),
            ))
        }),
        Duration::from_secs(5),
    )
    .with_browser(browser.clone());
    mgr.shutdown_children();
    assert!(browser.is_stopped());
    assert_eq!(browser.status().mode, "off");
    mgr.shutdown_children(); // idempotent
}
