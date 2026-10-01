//! HUP-S4.1: MCP tools in agent sessions, registered only when an MCP allowlist is configured
//! (`CITRATE_HERMES_MCP`, default off). The server here is a real streamable-HTTP MCP server
//! (axum) driven by the agent-mcp-host test fixture.

#[path = "../../agent-mcp-host/fixtures/logic.rs"]
mod fixture_logic;

use super::*;
use axum::body::{Body, Bytes};
use axum::http::{Request, StatusCode};
use axum::response::IntoResponse;
use citrate_agent_loop::{AssistantTurn, CompletionRequest, LlmClient, LlmError, ToolCall};
use citrate_agent_mcp_host::config::{McpConfig, ServerConfig, TransportConfig};
use citrate_agent_mcp_host::McpHost;
use fixture_logic::{Fixture, Out};
use std::sync::Mutex;
use std::time::{Duration, Instant};
use tower::ServiceExt;

const BEARER: &str = "test-bearer-token-0123456789";
const SESSION: &str = "fx-session";

async fn mcp_endpoint(
    axum::extract::State(fx): axum::extract::State<Arc<Mutex<Fixture>>>,
    body: Bytes,
) -> axum::response::Response {
    let Ok(msg) = serde_json::from_slice::<serde_json::Value>(&body) else {
        return StatusCode::BAD_REQUEST.into_response();
    };
    let is_init = msg["method"] == "initialize";
    let outs = match fx.lock() {
        Ok(mut f) => f.handle(&msg),
        Err(_) => return StatusCode::INTERNAL_SERVER_ERROR.into_response(),
    };
    if let Some(o) = outs.into_iter().next() {
        let mut resp = match o {
            Out::Msg(v) => ([("content-type", "application/json")], v.to_string()).into_response(),
            Out::Delayed { ms, msg, .. } => {
                tokio::time::sleep(Duration::from_millis(ms)).await;
                ([("content-type", "application/json")], msg.to_string()).into_response()
            }
            _ => StatusCode::INTERNAL_SERVER_ERROR.into_response(),
        };
        if is_init {
            if let Ok(v) = SESSION.parse() {
                resp.headers_mut().insert("mcp-session-id", v);
            }
        }
        return resp;
    }
    StatusCode::ACCEPTED.into_response()
}

/// A real MCP server on a background runtime; returns its URL.
fn start_mcp_server() -> String {
    let fx = Arc::new(Mutex::new(Fixture::new(None, false)));
    let (tx, rx) = std::sync::mpsc::channel();
    std::thread::spawn(move || {
        let rt = tokio::runtime::Builder::new_multi_thread()
            .worker_threads(2)
            .enable_all()
            .build()
            .expect("runtime");
        rt.block_on(async move {
            let listener = tokio::net::TcpListener::bind("127.0.0.1:0")
                .await
                .expect("bind");
            let _ = tx.send(listener.local_addr().expect("addr"));
            let app = axum::Router::new()
                .route("/mcp", axum::routing::post(mcp_endpoint))
                .with_state(fx);
            let _ = axum::serve(listener, app).await;
        });
    });
    format!("http://{}/mcp", rx.recv().expect("addr"))
}

async fn connect_host(allow_write_tools: bool) -> Arc<McpHost> {
    let url = start_mcp_server();
    let mut cfg = ServerConfig::new("web", TransportConfig::Http { url });
    cfg.timeout = Duration::from_secs(10);
    cfg.allow_write_tools = allow_write_tools;
    let host =
        tokio::task::spawn_blocking(move || McpHost::connect(&McpConfig { servers: vec![cfg] }))
            .await
            .expect("connect");
    Arc::new(host)
}

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

fn state(turns: Vec<AssistantTurn>, mcp: Option<Arc<McpHost>>) -> (Arc<AppState>, Arc<Recorder>) {
    let rec = Arc::new(Recorder {
        turns: Mutex::new(turns),
        seen: Mutex::new(vec![]),
    });
    let r2 = rec.clone();
    let mut mgr = sessions::SessionManager::new(
        Arc::new(move |_ep: &sessions::LlmEndpoint| r2.clone() as Arc<dyn LlmClient>),
        Duration::from_secs(5),
    );
    if let Some(h) = mcp {
        mgr = mgr.with_mcp(h);
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

async fn json(resp: axum::response::Response) -> serde_json::Value {
    let bytes = axum::body::to_bytes(resp.into_body(), 1 << 20)
        .await
        .unwrap_or_default();
    serde_json::from_slice(&bytes).unwrap_or(serde_json::Value::Null)
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

fn core_tools() -> serde_json::Value {
    serde_json::json!([
        {"name": "node_status", "description": "node height peers", "parameters": {"type": "object"}, "host": "core"}
    ])
}

fn tool_call(id: &str, name: &str, args: serde_json::Value) -> AssistantTurn {
    AssistantTurn::tools(vec![ToolCall {
        id: id.into(),
        name: name.into(),
        arguments: args.to_string(),
    }])
}

async fn open(st: &Arc<AppState>, body: serde_json::Value) -> String {
    let r = app(st.clone())
        .oneshot(req("POST", "/sessions", body))
        .await
        .expect("create");
    assert_eq!(r.status(), StatusCode::CREATED);
    json(r).await["id"].as_str().unwrap_or_default().to_string()
}

async fn send(st: &Arc<AppState>, id: &str, text: &str) {
    let r = app(st.clone())
        .oneshot(req(
            "POST",
            &format!("/sessions/{id}/messages"),
            serde_json::json!({ "text": text }),
        ))
        .await
        .expect("send");
    assert_eq!(r.status(), StatusCode::ACCEPTED);
}

async fn until_done(st: &Arc<AppState>, id: &str) -> Vec<serde_json::Value> {
    let mut all = vec![];
    let mut after = 0u64;
    for _ in 0..100 {
        let r = app(st.clone())
            .oneshot(req(
                "GET",
                &format!("/sessions/{id}/events?after={after}&wait_ms=100"),
                serde_json::Value::Null,
            ))
            .await
            .expect("events");
        let page = json(r).await;
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
async fn without_mcp_nothing_changes_and_the_namespace_is_not_reserved() {
    let (st, rec) = state(vec![], None);
    let tools = serde_json::json!([
        {"name": "mcp__x__y", "description": "a core tool that happens to use this prefix", "parameters": {"type": "object"}, "host": "core"}
    ]);
    let id = open(&st, create_body(tools)).await;
    send(&st, &id, "hello").await;
    until_done(&st, &id).await;
    let names: Vec<String> = rec
        .seen
        .lock()
        .map(|s| s[0].tools.iter().map(|t| t.name.clone()).collect())
        .unwrap_or_default();
    assert_eq!(names, vec!["mcp__x__y".to_string()]);
    let r = app(st.clone())
        .oneshot(req("GET", "/mcp/servers", serde_json::Value::Null))
        .await
        .expect("status");
    assert_eq!(r.status(), StatusCode::OK);
    let v = json(r).await;
    assert_eq!(v["configured"], serde_json::json!(false));
    assert_eq!(v["servers"], serde_json::json!([]));
}

#[tokio::test(flavor = "multi_thread")]
async fn with_mcp_tools_are_offered_and_a_call_runs_untrusted_and_taints() {
    let host = connect_host(false).await;
    let (st, rec) = state(
        vec![tool_call(
            "c1",
            "mcp__web__echo",
            serde_json::json!({"text": "hi"}),
        )],
        Some(host),
    );
    let id = open(&st, create_body(core_tools())).await;
    send(&st, &id, "echo hi via the web tool").await;
    let events = until_done(&st, &id).await;
    let offered: Vec<String> = rec
        .seen
        .lock()
        .map(|s| s[0].tools.iter().map(|t| t.name.clone()).collect())
        .unwrap_or_default();
    assert!(
        offered.contains(&"mcp__web__echo".to_string()),
        "{offered:?}"
    );
    // Write tools stay hidden by default.
    assert!(
        !offered.contains(&"mcp__web__write_note".to_string()),
        "{offered:?}"
    );
    let call = events
        .iter()
        .find(|e| e["type"] == "tool_call")
        .cloned()
        .unwrap_or_default();
    assert_eq!(call["host"], serde_json::json!("sidecar"));
    let result = events
        .iter()
        .find(|e| e["type"] == "tool_result")
        .cloned()
        .unwrap_or_default();
    assert_eq!(result["status"], serde_json::json!("ok"));
    let content = result["content"].as_str().unwrap_or_default();
    assert!(content.contains("echo: hi"), "{content}");
    assert!(content.contains("untrusted"), "{content}");
    let tainted = events
        .iter()
        .find(|e| e["type"] == "tainted")
        .cloned()
        .unwrap_or_default();
    assert_eq!(tainted["source"], serde_json::json!("mcp__web__echo"));
}

#[tokio::test(flavor = "multi_thread")]
async fn with_mcp_a_client_tool_in_the_mcp_namespace_is_refused() {
    let host = connect_host(false).await;
    let (st, _) = state(vec![], Some(host));
    let tools = serde_json::json!([
        {"name": "mcp__web__echo", "description": "shadow", "parameters": {"type": "object"}, "host": "core"}
    ]);
    let r = app(st.clone())
        .oneshot(req("POST", "/sessions", create_body(tools)))
        .await
        .expect("create");
    assert_eq!(r.status(), StatusCode::BAD_REQUEST);
}

#[tokio::test(flavor = "multi_thread")]
async fn after_taint_an_effectful_mcp_tool_is_declined_not_run() {
    let host = connect_host(true).await;
    let (st, _) = state(
        vec![
            tool_call("c1", "mcp__web__echo", serde_json::json!({"text": "x"})),
            tool_call(
                "c2",
                "mcp__web__write_note",
                serde_json::json!({"text": "y"}),
            ),
        ],
        Some(host),
    );
    let id = open(&st, create_body(core_tools())).await;
    send(&st, &id, "echo then write a note").await;
    let events = until_done(&st, &id).await;
    let calls: Vec<&serde_json::Value> =
        events.iter().filter(|e| e["type"] == "tool_call").collect();
    assert_eq!(calls.len(), 2);
    assert_eq!(calls[1]["hic"], serde_json::json!("required"));
    assert_eq!(
        calls[1]["host"],
        serde_json::Value::Null,
        "must not be dispatched"
    );
    let results: Vec<&serde_json::Value> = events
        .iter()
        .filter(|e| e["type"] == "tool_result")
        .collect();
    assert_eq!(results[1]["status"], serde_json::json!("denied"));
}

#[tokio::test(flavor = "multi_thread")]
async fn stopping_a_session_cancels_an_in_flight_mcp_call() {
    let host = connect_host(false).await;
    let (st, _) = state(
        vec![tool_call(
            "c1",
            "mcp__web__sleep",
            serde_json::json!({"ms": 8000}),
        )],
        Some(host),
    );
    let id = open(&st, create_body(core_tools())).await;
    send(&st, &id, "sleep").await;
    tokio::time::sleep(Duration::from_millis(300)).await;
    let started = Instant::now();
    let r = app(st.clone())
        .oneshot(req(
            "POST",
            &format!("/sessions/{id}/stop"),
            serde_json::Value::Null,
        ))
        .await
        .expect("stop");
    assert!(r.status().is_success());
    let events = until_done(&st, &id).await;
    assert!(
        started.elapsed() < Duration::from_secs(4),
        "stop took {:?}",
        started.elapsed()
    );
    let done = events
        .iter()
        .find(|e| e["type"] == "done")
        .cloned()
        .unwrap_or_default();
    assert_eq!(done["outcome"], serde_json::json!("stopped"));
}

#[tokio::test(flavor = "multi_thread")]
async fn mcp_status_lists_servers_and_needs_the_bearer() {
    let host = connect_host(false).await;
    let (st, _) = state(vec![], Some(host));
    let r = app(st.clone())
        .oneshot(
            Request::builder()
                .method("GET")
                .uri("/mcp/servers")
                .body(Body::empty())
                .expect("request"),
        )
        .await
        .expect("status");
    assert_eq!(r.status(), StatusCode::UNAUTHORIZED);
    let r = app(st.clone())
        .oneshot(req("GET", "/mcp/servers", serde_json::Value::Null))
        .await
        .expect("status");
    let v = json(r).await;
    assert_eq!(v["configured"], serde_json::json!(true));
    let s = &v["servers"][0];
    assert_eq!(s["name"], serde_json::json!("web"));
    assert_eq!(s["state"], serde_json::json!("ready"));
    assert_eq!(s["protocolVersion"], serde_json::json!("2025-06-18"));
    assert!(s["tools"].as_u64().unwrap_or(0) > 0);
    // Never the URL.
    assert!(!v.to_string().contains("127.0.0.1"), "{v}");
}

#[test]
fn mcp_config_from_a_path_is_validated() {
    let dir = std::env::temp_dir().join(format!("citrate-sidecar-mcp-{}", std::process::id()));
    let _ = std::fs::create_dir_all(&dir);
    let bad = dir.join("bad.toml");
    let _ = std::fs::write(
        &bad,
        "[[servers]]\nname='x'\ntransport='stdio'\ncommand='relative'\n",
    );
    assert!(mcp_from_path(&bad).is_err());
    let empty = dir.join("empty.json");
    let _ = std::fs::write(&empty, "{\"servers\": []}");
    let host = mcp_from_path(&empty).expect("valid");
    assert!(host.is_none(), "an empty allowlist means no MCP");
    assert!(mcp_from_path(&dir.join("missing.toml")).is_err());
    let _ = std::fs::remove_dir_all(&dir);
}
