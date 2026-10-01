//! HUP-S4.4: `POST /mcp/probe`, the dry-run probe for a user-added MCP server. It validates the
//! entry, initializes the server and lists its tools for the review screen, and registers nothing.

use super::mcp_session_tests::start_mcp_server;
use super::*;
use axum::body::Body;
use axum::http::{Request, StatusCode};
use std::time::Duration;
use tower::ServiceExt;

const BEARER: &str = "test-bearer-token-0123456789";

/// The sidecar allows one probe at a time (a second gets 429), so tests that run a probe take
/// turns.
static SERIAL: tokio::sync::Mutex<()> = tokio::sync::Mutex::const_new(());

fn state() -> Arc<AppState> {
    let mgr = sessions::SessionManager::new(
        Arc::new(
            |_ep: &sessions::LlmEndpoint| -> Arc<dyn citrate_agent_loop::LlmClient> {
                Arc::new(llm_http::OpenAiCompatClient::new(
                    "http://127.0.0.1:9/v1",
                    "k",
                    Duration::from_secs(1),
                ))
            },
        ),
        Duration::from_secs(5),
    );
    Arc::new(AppState {
        estop: EmergencyStop::new(),
        queue: Arc::new(ApprovalQueue::new()),
        skills: vec![],
        dispatch: None,
        bearer: BEARER.to_string(),
        run_slots: Arc::new(tokio::sync::Semaphore::new(MAX_CONCURRENT_SKILLS)),
        sessions: Arc::new(mgr),
    })
}

fn post(body: serde_json::Value, bearer: Option<&str>) -> Request<Body> {
    let mut b = Request::builder()
        .method("POST")
        .uri("/mcp/probe")
        .header("content-type", "application/json");
    if let Some(t) = bearer {
        b = b.header("authorization", format!("Bearer {t}"));
    }
    b.body(Body::from(body.to_string())).expect("request")
}

async fn json(resp: axum::response::Response) -> serde_json::Value {
    let bytes = axum::body::to_bytes(resp.into_body(), 1 << 20)
        .await
        .unwrap_or_default();
    serde_json::from_slice(&bytes).unwrap_or(serde_json::Value::Null)
}

#[tokio::test(flavor = "multi_thread")]
async fn the_probe_needs_the_bearer() {
    let st = state();
    let r = app(st)
        .oneshot(post(serde_json::json!({"name": "a"}), None))
        .await
        .expect("resp");
    assert_eq!(r.status(), StatusCode::UNAUTHORIZED);
}

#[tokio::test(flavor = "multi_thread")]
async fn an_invalid_entry_is_refused_with_field_errors_and_nothing_starts() {
    let st = state();
    let r = app(st)
        .oneshot(post(
            serde_json::json!({
                "name": "Bad",
                "transport": "stdio",
                "command": "relative-cmd",
                "env": {"LD_PRELOAD": "/tmp/x.so", "TOKEN": "${HF_TOKEN}"}
            }),
            Some(BEARER),
        ))
        .await
        .expect("resp");
    assert_eq!(r.status(), StatusCode::UNPROCESSABLE_ENTITY);
    let v = json(r).await;
    let fields: Vec<String> = v["errors"]
        .as_array()
        .map(|a| {
            a.iter()
                .filter_map(|e| e["field"].as_str().map(str::to_string))
                .collect()
        })
        .unwrap_or_default();
    for f in ["name", "command", "env.LD_PRELOAD", "env.TOKEN"] {
        assert!(fields.iter().any(|x| x == f), "{f} in {v}");
    }
}

#[tokio::test(flavor = "multi_thread")]
async fn a_valid_entry_is_probed_and_nothing_is_registered() {
    let _turn = SERIAL.lock().await;
    let url = start_mcp_server();
    let st = state();
    let r = app(st.clone())
        .oneshot(post(
            serde_json::json!({"name": "web2", "transport": "http", "url": url}),
            Some(BEARER),
        ))
        .await
        .expect("resp");
    assert_eq!(r.status(), StatusCode::OK);
    let v = json(r).await;
    assert_eq!(v["ok"], serde_json::json!(true), "{v}");
    assert_eq!(v["protocolVersion"], serde_json::json!("2025-06-18"));
    let tools = v["tools"].as_array().cloned().unwrap_or_default();
    let by = |n: &str| {
        tools
            .iter()
            .find(|t| t["name"] == serde_json::json!(n))
            .cloned()
            .unwrap_or(serde_json::Value::Null)
    };
    assert_eq!(by("echo")["offered"], serde_json::json!(true));
    assert_eq!(
        by("echo")["annotations"]["readOnlyHint"],
        serde_json::json!(true)
    );
    assert_eq!(by("write_note")["offered"], serde_json::json!(false));
    assert_eq!(
        by("write_note")["effective"]["destructive"],
        serde_json::json!(true)
    );
    assert!(tools
        .iter()
        .all(|t| t["trust"] == serde_json::json!("untrusted")));
    // Never the URL, never the server's instructions text.
    assert!(!v.to_string().contains("127.0.0.1"), "{v}");
    assert!(!v.to_string().contains("transfer funds"), "{v}");
    // Nothing was registered: MCP is still not configured for sessions.
    assert!(st.sessions.mcp_status().is_none());
    let r = app(st)
        .oneshot(
            Request::builder()
                .method("GET")
                .uri("/mcp/servers")
                .header("authorization", format!("Bearer {BEARER}"))
                .body(Body::empty())
                .expect("request"),
        )
        .await
        .expect("resp");
    assert_eq!(json(r).await["configured"], serde_json::json!(false));
}

#[tokio::test(flavor = "multi_thread")]
async fn an_unreachable_server_is_a_report_not_an_error_status() {
    let _turn = SERIAL.lock().await;
    let st = state();
    // A loopback port with nothing listening.
    let port = {
        let l = std::net::TcpListener::bind("127.0.0.1:0").expect("bind");
        l.local_addr().expect("addr").port()
    };
    let r = app(st)
        .oneshot(post(
            serde_json::json!({"name": "gone", "transport": "http", "url": format!("http://127.0.0.1:{port}/mcp")}),
            Some(BEARER),
        ))
        .await
        .expect("resp");
    assert_eq!(r.status(), StatusCode::OK);
    let v = json(r).await;
    assert_eq!(v["ok"], serde_json::json!(false));
    assert!(v["error"].as_str().is_some(), "{v}");
}

#[test]
fn only_one_probe_runs_at_a_time() {
    // Its own flag, so the probe tests running in parallel do not see this slot taken.
    static FLAG: std::sync::atomic::AtomicBool = std::sync::atomic::AtomicBool::new(false);
    let first = mcp_probe::ProbeSlot::try_take_from(&FLAG).expect("free");
    assert!(mcp_probe::ProbeSlot::try_take_from(&FLAG).is_none());
    drop(first);
    assert!(mcp_probe::ProbeSlot::try_take_from(&FLAG).is_some());
}
