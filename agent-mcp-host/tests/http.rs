//! HUP-S4.1: the MCP host against a real streamable-HTTP MCP server (axum, in-test).

#[path = "../fixtures/logic.rs"]
mod logic;

use axum::body::Bytes;
use axum::extract::State;
use axum::http::{HeaderMap, StatusCode};
use axum::response::{IntoResponse, Response};
use axum::routing::post;
use axum::Router;
use citrate_agent_loop::{StopFlag, ToolCall, ToolOutcome};
use citrate_agent_mcp_host::config::{McpConfig, ServerConfig, TransportConfig};
use citrate_agent_mcp_host::{McpClient, McpError, McpHost};
use logic::{Fixture, Out};
use serde_json::{json, Value};
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

const SESSION: &str = "fixture-session-1";

#[derive(Default)]
struct Seen {
    /// (method, protocol-version header, session header) for every POST after initialize.
    headers: Vec<(String, Option<String>, Option<String>)>,
}

#[derive(Clone)]
struct Srv {
    fx: Arc<Mutex<Fixture>>,
    seen: Arc<Mutex<Seen>>,
    /// Answer every request with this raw body (bad JSON / oversize tests).
    raw_override: Option<&'static str>,
}

async fn mcp(State(s): State<Srv>, headers: HeaderMap, body: Bytes) -> Response {
    let Ok(msg) = serde_json::from_slice::<Value>(&body) else {
        return (StatusCode::BAD_REQUEST, "bad json").into_response();
    };
    let method = msg
        .get("method")
        .and_then(Value::as_str)
        .unwrap_or("")
        .to_string();
    let accept = headers
        .get("accept")
        .and_then(|v| v.to_str().ok())
        .unwrap_or("");
    if !(accept.contains("application/json") && accept.contains("text/event-stream")) {
        return (StatusCode::NOT_ACCEPTABLE, "accept both").into_response();
    }
    let hv = |k: &str| {
        headers
            .get(k)
            .and_then(|v| v.to_str().ok())
            .map(str::to_string)
    };
    if method != "initialize" {
        if let Ok(mut seen) = s.seen.lock() {
            seen.headers.push((
                method.clone(),
                hv("mcp-protocol-version"),
                hv("mcp-session-id"),
            ));
        }
        if hv("mcp-session-id").as_deref() != Some(SESSION) {
            return (StatusCode::BAD_REQUEST, "missing session").into_response();
        }
    }
    if let (Some(raw), true) = (s.raw_override, method == "tools/call") {
        return ([("content-type", "application/json")], raw.to_string()).into_response();
    }
    let outs = match s.fx.lock() {
        Ok(mut f) => f.handle(&msg),
        Err(_) => return StatusCode::INTERNAL_SERVER_ERROR.into_response(),
    };
    let is_init = method == "initialize";
    if let Some(o) = outs.into_iter().next() {
        let mut resp = match o {
            Out::Msg(v) => ([("content-type", "application/json")], v.to_string()).into_response(),
            Out::Raw(r) => ([("content-type", "application/json")], r).into_response(),
            Out::Exit(_) => StatusCode::INTERNAL_SERVER_ERROR.into_response(),
            Out::Sse(vs) => {
                let body: String = vs
                    .iter()
                    .map(|v| format!("event: message\ndata: {v}\n\n"))
                    .collect();
                ([("content-type", "text/event-stream")], body).into_response()
            }
            Out::Delayed { ms, msg, .. } => {
                tokio::time::sleep(Duration::from_millis(ms)).await;
                ([("content-type", "application/json")], msg.to_string()).into_response()
            }
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

/// Always answers with a redirect to the real endpoint (the host must not follow it).
async fn moved() -> Response {
    (StatusCode::TEMPORARY_REDIRECT, [("location", "/mcp")]).into_response()
}

/// Start the server on a background runtime; returns its URL.
fn start(raw_override: Option<&'static str>) -> (String, Arc<Mutex<Seen>>, Arc<Mutex<Fixture>>) {
    let fx = Arc::new(Mutex::new(Fixture::new(None, false)));
    let seen = Arc::new(Mutex::new(Seen::default()));
    let srv = Srv {
        fx: fx.clone(),
        seen: seen.clone(),
        raw_override,
    };
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
            let addr = listener.local_addr().expect("addr");
            let _ = tx.send(addr);
            let app = Router::new()
                .route("/mcp", post(mcp))
                .route("/moved", post(moved))
                .with_state(srv);
            let _ = axum::serve(listener, app).await;
        });
    });
    let addr = rx.recv().expect("addr");
    (format!("http://{addr}/mcp"), seen, fx)
}

fn http_server(name: &str, url: &str) -> ServerConfig {
    let mut c = ServerConfig::new(name, TransportConfig::Http { url: url.into() });
    c.timeout = Duration::from_secs(5);
    c
}

#[test]
fn http_handshake_list_and_call_carry_session_and_version_headers() {
    let (url, seen, fx) = start(None);
    let client = McpClient::connect(&http_server("web", &url)).expect("connect");
    assert_eq!(client.info().protocol_version, "2025-06-18");
    let tools = client.list_tools().expect("list");
    assert!(tools.iter().any(|t| t.name == "echo"));
    let r = client
        .call_tool("echo", json!({"text": "over http"}), &StopFlag::default())
        .expect("call");
    assert!(r.text.contains("echo: over http"));
    assert!(fx.lock().map(|f| f.initialized).unwrap_or(false));
    let seen = seen.lock().expect("seen");
    assert!(!seen.headers.is_empty());
    for (m, v, sid) in &seen.headers {
        assert_eq!(v.as_deref(), Some("2025-06-18"), "{m}");
        assert_eq!(sid.as_deref(), Some(SESSION), "{m}");
    }
}

#[test]
fn an_sse_response_is_parsed_past_notifications() {
    let (url, _, _) = start(None);
    let client = McpClient::connect(&http_server("web", &url)).expect("connect");
    let r = client
        .call_tool(
            "sse_echo",
            json!({"text": "streamed"}),
            &StopFlag::default(),
        )
        .expect("sse call");
    assert!(r.text.contains("sse: streamed"), "{}", r.text);
}

#[test]
fn http_timeout_and_cancel_notification() {
    let (url, seen, _) = start(None);
    let mut cfg = http_server("web", &url);
    cfg.timeout = Duration::from_millis(300);
    let client = McpClient::connect(&cfg).expect("connect");
    let started = Instant::now();
    let err = client
        .call_tool("sleep", json!({"ms": 3000}), &StopFlag::default())
        .expect_err("timeout");
    assert!(matches!(err, McpError::Timeout(_)), "{err:?}");
    assert!(started.elapsed() < Duration::from_secs(2));
    // The cancellation notification is posted (best effort, asynchronously).
    let deadline = Instant::now() + Duration::from_secs(3);
    loop {
        let n = seen
            .lock()
            .map(|s| {
                s.headers
                    .iter()
                    .filter(|(m, _, _)| m == "notifications/cancelled")
                    .count()
            })
            .unwrap_or(0);
        if n == 1 {
            break;
        }
        assert!(Instant::now() < deadline, "no cancellation was posted");
        std::thread::sleep(Duration::from_millis(20));
    }
}

#[test]
fn http_bad_json_is_a_bad_response() {
    let (url, _, _) = start(Some("this is not json"));
    let client = McpClient::connect(&http_server("web", &url)).expect("connect");
    let err = client
        .call_tool("echo", json!({}), &StopFlag::default())
        .expect_err("bad json");
    assert!(matches!(err, McpError::BadResponse(_)), "{err:?}");
}

#[test]
fn http_oversize_is_refused() {
    let (url, _, _) = start(None);
    let mut cfg = http_server("web", &url);
    cfg.max_response_bytes = 2048;
    let client = McpClient::connect(&cfg).expect("connect");
    let err = client
        .call_tool("big", json!({"bytes": 50_000}), &StopFlag::default())
        .expect_err("oversize");
    assert!(matches!(err, McpError::Oversize(_)), "{err:?}");
}

#[test]
fn http_server_error_is_a_transport_error_through_the_host() {
    let (url, _, _) = start(None);
    let host = McpHost::connect(&McpConfig {
        servers: vec![http_server("web", &url)],
    });
    let out = host.call(
        &ToolCall {
            id: "c".into(),
            name: "mcp__web__crash".into(),
            arguments: "{}".into(),
        },
        &StopFlag::default(),
    );
    assert!(matches!(out, ToolOutcome::Error(_)), "{out:?}");
    // A 500 does not take the server down for later calls.
    let out = host.call(
        &ToolCall {
            id: "c2".into(),
            name: "mcp__web__echo".into(),
            arguments: r#"{"text":"ok"}"#.into(),
        },
        &StopFlag::default(),
    );
    assert!(matches!(out, ToolOutcome::Untrusted(_)), "{out:?}");
}

#[test]
fn a_non_loopback_plain_http_url_is_refused_at_config_time() {
    let cfg = r#"
[[servers]]
name = "web"
transport = "http"
url = "http://203.0.113.9/mcp"
"#;
    assert!(McpConfig::parse_toml(cfg).is_err());
}

#[test]
fn an_oversized_sse_stream_is_refused_as_oversize() {
    let (url, _, _) = start(None);
    let mut cfg = http_server("web", &url);
    cfg.max_response_bytes = 2048;
    let client = McpClient::connect(&cfg).expect("connect");
    let err = client
        .call_tool(
            "sse_echo",
            json!({"text": "y".repeat(50_000)}),
            &StopFlag::default(),
        )
        .expect_err("oversize");
    assert!(matches!(err, McpError::Oversize(2048)), "{err:?}");
}

#[test]
fn redirects_are_not_followed() {
    let (url, _, _) = start(None);
    let moved = url.replace("/mcp", "/moved");
    let err = McpClient::connect(&http_server("web", &moved)).expect_err("redirect");
    assert!(
        matches!(&err, McpError::Transport(m) if m.contains("307")),
        "{err:?}"
    );
}
