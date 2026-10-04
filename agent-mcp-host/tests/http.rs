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
use logic::{Fixture, FxEra, Out};
use serde_json::{json, Value};
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

const SESSION: &str = "fixture-session-1";
const SESSION_2: &str = "fixture-session-2";

/// (method, mcp-method, mcp-name, mcp-param-region) of one modern request.
type ModernSeen = (String, Option<String>, Option<String>, Option<String>);

#[derive(Default)]
struct Seen {
    /// (method, protocol-version header, session header) for every POST after initialize.
    headers: Vec<(String, Option<String>, Option<String>)>,
    /// Modern requests: (method, mcp-method, mcp-name, mcp-param-region).
    modern: Vec<ModernSeen>,
    /// Legacy initialize count.
    inits: usize,
}

#[derive(Clone)]
struct Srv {
    fx: Arc<Mutex<Fixture>>,
    seen: Arc<Mutex<Seen>>,
    /// Answer every request with this raw body (bad JSON / oversize tests).
    raw_override: Option<&'static str>,
    /// The legacy session the server currently accepts.
    session: Arc<Mutex<String>>,
}

fn json_resp(status: StatusCode, v: Value) -> Response {
    (
        status,
        [("content-type", "application/json")],
        v.to_string(),
    )
        .into_response()
}

fn out_response(o: Out) -> Option<Response> {
    Some(match o {
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
        Out::Delayed { .. } => return None,
    })
}

/// The 2026-07-28 rules: headers mirror the body, no session.
async fn modern(s: Srv, headers: HeaderMap, msg: Value) -> Response {
    let hv = |k: &str| {
        headers
            .get(k)
            .and_then(|v| v.to_str().ok())
            .map(str::to_string)
    };
    let method = msg["method"].as_str().unwrap_or("").to_string();
    let id = msg.get("id").cloned().unwrap_or(Value::Null);
    if let Ok(mut seen) = s.seen.lock() {
        seen.modern.push((
            method.clone(),
            hv("mcp-method"),
            hv("mcp-name"),
            hv("mcp-param-region"),
        ));
    }
    let mismatch = |why: &str| {
        json_resp(
            StatusCode::BAD_REQUEST,
            json!({"jsonrpc": "2.0", "id": id, "error": {"code": -32020, "message": format!("Header mismatch: {why}")}}),
        )
    };
    let body_version = msg
        .pointer("/params/_meta/io.modelcontextprotocol~1protocolVersion")
        .and_then(Value::as_str)
        .map(str::to_string);
    if hv("mcp-protocol-version") != body_version {
        return mismatch("MCP-Protocol-Version");
    }
    if hv("mcp-method").as_deref() != Some(method.as_str()) {
        return mismatch("Mcp-Method");
    }
    let name_src = match method.as_str() {
        "tools/call" => msg.pointer("/params/name"),
        m if m.starts_with("tasks/") => msg.pointer("/params/taskId"),
        _ => None,
    }
    .and_then(Value::as_str)
    .map(str::to_string);
    if name_src.is_some() && hv("mcp-name") != name_src {
        return mismatch("Mcp-Name");
    }
    if msg.pointer("/params/name") == Some(&json!("regional")) {
        let want = msg
            .pointer("/params/arguments/region")
            .and_then(Value::as_str)
            .map(str::to_string);
        if hv("mcp-param-region") != want {
            return mismatch("Mcp-Param-Region");
        }
    }
    if hv("mcp-session-id").is_some() {
        return mismatch("a modern request carried a session id");
    }
    if method == "subscriptions/listen" {
        // Wait (bounded) for a change, deliver it, then end the subscription gracefully.
        let ack = match s.fx.lock() {
            Ok(mut f) => f.handle(&msg),
            Err(_) => return StatusCode::INTERNAL_SERVER_ERROR.into_response(),
        };
        let mut events: Vec<Value> = ack
            .into_iter()
            .filter_map(|o| match o {
                Out::Msg(v) => Some(v),
                _ => None,
            })
            .collect();
        let until = Instant::now() + Duration::from_secs(2);
        loop {
            let pending =
                s.fx.lock()
                    .map(|mut f| std::mem::take(&mut f.pending_list_changed))
                    .unwrap_or(false);
            if pending {
                events.push(json!({"jsonrpc": "2.0", "method": "notifications/tools/list_changed", "params": {"_meta": {"io.modelcontextprotocol/subscriptionId": id}}}));
                break;
            }
            if Instant::now() >= until {
                break;
            }
            tokio::time::sleep(Duration::from_millis(25)).await;
        }
        events.push(json!({"jsonrpc": "2.0", "id": id, "result": {"resultType": "complete"}}));
        let body: String = events
            .iter()
            .map(|v| format!(": keep-alive\nevent: message\ndata: {v}\n\n"))
            .collect();
        return ([("content-type", "text/event-stream")], body).into_response();
    }
    let outs = match s.fx.lock() {
        Ok(mut f) => f.handle(&msg),
        Err(_) => return StatusCode::INTERNAL_SERVER_ERROR.into_response(),
    };
    let Some(first) = outs.into_iter().next() else {
        return StatusCode::ACCEPTED.into_response();
    };
    if let Out::Delayed { ms, msg, .. } = first {
        tokio::time::sleep(Duration::from_millis(ms)).await;
        return ([("content-type", "application/json")], msg.to_string()).into_response();
    }
    // Modern errors carry their HTTP status (400 for the protocol errors).
    if let Out::Msg(v) = &first {
        if let Some(code) = v.pointer("/error/code").and_then(Value::as_i64) {
            let status = match code {
                -32020 | -32021 | -32022 | -32602 => StatusCode::BAD_REQUEST,
                -32601 => StatusCode::NOT_FOUND,
                _ => StatusCode::OK,
            };
            return json_resp(status, v.clone());
        }
    }
    out_response(first).unwrap_or_else(|| StatusCode::INTERNAL_SERVER_ERROR.into_response())
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
    let era = s.fx.lock().map(|f| f.era).unwrap_or(FxEra::Legacy);
    let modern_req = msg
        .pointer("/params/_meta/io.modelcontextprotocol~1protocolVersion")
        .is_some();
    if era == FxEra::Modern || (era == FxEra::Dual && modern_req) {
        return modern(s, headers, msg).await;
    }
    let hv = |k: &str| {
        headers
            .get(k)
            .and_then(|v| v.to_str().ok())
            .map(str::to_string)
    };
    let current = s.session.lock().map(|c| c.clone()).unwrap_or_default();
    if method == "initialize" {
        if let Ok(mut seen) = s.seen.lock() {
            seen.inits += 1;
        }
    } else {
        if let Ok(mut seen) = s.seen.lock() {
            seen.headers.push((
                method.clone(),
                hv("mcp-protocol-version"),
                hv("mcp-session-id"),
            ));
        }
        match hv("mcp-session-id") {
            None => return (StatusCode::BAD_REQUEST, "missing session").into_response(),
            Some(sid) if sid != current => {
                return (StatusCode::NOT_FOUND, "session ended").into_response()
            }
            Some(_) => {}
        }
    }
    if let (Some(raw), true) = (s.raw_override, method == "tools/call") {
        return ([("content-type", "application/json")], raw.to_string()).into_response();
    }
    if msg.pointer("/params/name") == Some(&json!("forget_session")) {
        if let Ok(mut c) = s.session.lock() {
            *c = SESSION_2.to_string();
        }
    }
    let outs = match s.fx.lock() {
        Ok(mut f) => f.handle(&msg),
        Err(_) => return StatusCode::INTERNAL_SERVER_ERROR.into_response(),
    };
    let is_init = method == "initialize";
    if let Some(o) = outs.into_iter().next() {
        let mut resp = match o {
            Out::Delayed { ms, msg, .. } => {
                tokio::time::sleep(Duration::from_millis(ms)).await;
                ([("content-type", "application/json")], msg.to_string()).into_response()
            }
            other => out_response(other)
                .unwrap_or_else(|| StatusCode::INTERNAL_SERVER_ERROR.into_response()),
        };
        if is_init {
            if let Ok(v) = current.parse() {
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
    start_era(FxEra::Legacy, raw_override)
}

fn start_era(
    era: FxEra,
    raw_override: Option<&'static str>,
) -> (String, Arc<Mutex<Seen>>, Arc<Mutex<Fixture>>) {
    let fx = Arc::new(Mutex::new(Fixture::new(None, false).with_era(era)));
    let seen = Arc::new(Mutex::new(Seen::default()));
    let srv = Srv {
        fx: fx.clone(),
        seen: seen.clone(),
        raw_override,
        session: Arc::new(Mutex::new(SESSION.to_string())),
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
    // The dual-era probe comes first, with the modern version and no session; the legacy
    // server's 400 (no modern error body) sends the host to `initialize`.
    let (m0, v0, sid0) = &seen.headers[0];
    assert_eq!(m0, "server/discover");
    assert_eq!(v0.as_deref(), Some("2026-07-28"));
    assert_eq!(sid0.as_deref(), None);
    assert_eq!(seen.inits, 1);
    for (m, v, sid) in &seen.headers[1..] {
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

// ---------------------------------------------------------------------------------------------
// Revision 2026-07-28 over streamable HTTP
// ---------------------------------------------------------------------------------------------

fn call_of(name: &str, args: Value) -> ToolCall {
    ToolCall {
        id: "c".into(),
        name: name.into(),
        arguments: args.to_string(),
    }
}

#[test]
fn modern_http_mirrors_the_body_into_the_standard_and_param_headers() {
    let (url, seen, _) = start_era(FxEra::Modern, None);
    let host = McpHost::connect(&McpConfig {
        servers: vec![http_server("web", &url)],
    });
    let st = &host.status()[0];
    assert_eq!(st.protocol_version.as_deref(), Some("2026-07-28"));
    assert!(st.tasks);
    let out = host.call(
        &call_of("mcp__web__echo", json!({"text": "hi"})),
        &StopFlag::default(),
    );
    assert!(matches!(out, ToolOutcome::Untrusted(_)), "{out:?}");
    // The server refuses (-32020) unless Mcp-Param-Region matches the body.
    let out = host.call(
        &call_of("mcp__web__regional", json!({"region": "us-west1"})),
        &StopFlag::default(),
    );
    match &out {
        ToolOutcome::Untrusted(t) => assert!(t.contains("region: us-west1"), "{t}"),
        other => panic!("{other:?}"),
    }
    // A non-ASCII value goes base64 and still matches after decoding on a real server; here the
    // fixture compares raw text, so it refuses: the host reports the header mismatch.
    let out = host.call(
        &call_of("mcp__web__regional", json!({"region": "Zürich"})),
        &StopFlag::default(),
    );
    assert!(matches!(out, ToolOutcome::Error(_)), "{out:?}");
    let seen = seen.lock().expect("seen");
    assert!(
        seen.inits == 0 && seen.headers.is_empty(),
        "no legacy traffic"
    );
    for (method, mm, name, _) in &seen.modern {
        assert_eq!(mm.as_deref(), Some(method.as_str()));
        if method == "tools/call" {
            assert!(name.is_some());
        }
    }
    assert!(seen
        .modern
        .iter()
        .any(|(_, _, n, r)| n.as_deref() == Some("regional")
            && r.as_deref() == Some("=?base64?WsO8cmljaA==?=")));
}

#[test]
fn modern_http_withholds_a_tool_with_an_invalid_header_annotation() {
    let (url, _, _) = start_era(FxEra::Modern, None);
    let host = McpHost::connect(&McpConfig {
        servers: vec![http_server("web", &url)],
    });
    assert!(!host.handles("mcp__web__bad_header"));
    assert!(host.status()[0]
        .skipped
        .iter()
        .any(|s| s.starts_with("bad_header:") && s.contains("invalid")));
}

#[test]
fn modern_http_tasks_route_by_task_id() {
    let (url, seen, _) = start_era(FxEra::Modern, None);
    let client = McpClient::connect(&http_server("web", &url)).expect("connect");
    let r = client
        .call_tool("long_job", json!({"polls": 2}), &StopFlag::default())
        .expect("task");
    assert_eq!(r.text, "long_job finished after 2 polls");
    let seen = seen.lock().expect("seen");
    assert!(seen
        .modern
        .iter()
        .any(|(m, _, n, _)| m == "tasks/get" && n.as_deref() == Some("task-1")));
}

#[test]
fn modern_http_unsupported_version_is_reported_not_retried_as_legacy() {
    let (url, seen, fx) = start_era(FxEra::Modern, None);
    if let Ok(mut f) = fx.lock() {
        f.version_override = Some("2027-01-01".into());
    }
    let err = McpClient::connect(&http_server("web", &url)).expect_err("refused");
    assert!(
        matches!(&err, McpError::UnsupportedVersion { supported } if supported == &vec!["2027-01-01".to_string()]),
        "{err:?}"
    );
    assert_eq!(seen.lock().map(|s| s.inits).unwrap_or(9), 0);
}

#[test]
fn modern_http_tool_list_changes_arrive_on_the_listen_stream() {
    let (url, _, _) = start_era(FxEra::Modern, None);
    let host = McpHost::connect(&McpConfig {
        servers: vec![http_server("web", &url)],
    });
    assert!(!host.handles("mcp__web__added_later"));
    host.call(
        &call_of("mcp__web__change_tools", json!({})),
        &StopFlag::default(),
    );
    let deadline = Instant::now() + Duration::from_secs(6);
    while !host.handles("mcp__web__added_later") {
        assert!(Instant::now() < deadline, "the change never arrived");
        std::thread::sleep(Duration::from_millis(50));
        host.maintain_now();
    }
    assert_eq!(host.status()[0].relists, 1);
}

#[test]
fn a_legacy_http_session_the_server_ended_is_reconnected() {
    let (url, seen, _) = start(None);
    let host = McpHost::connect(&McpConfig {
        servers: vec![http_server("web", &url)],
    });
    host.call(
        &call_of("mcp__web__forget_session", json!({})),
        &StopFlag::default(),
    );
    let out = host.call(
        &call_of("mcp__web__echo", json!({"text": "x"})),
        &StopFlag::default(),
    );
    assert!(matches!(out, ToolOutcome::Error(_)), "{out:?}");
    host.maintain_now();
    assert_eq!(
        host.status()[0].state,
        citrate_agent_mcp_host::ServerState::Exited
    );
    std::thread::sleep(Duration::from_millis(1100));
    host.maintain_now();
    let st = &host.status()[0];
    assert_eq!(
        st.state,
        citrate_agent_mcp_host::ServerState::Ready,
        "{st:?}"
    );
    assert_eq!(st.reconnects, 1);
    let out = host.call(
        &call_of("mcp__web__echo", json!({"text": "again"})),
        &StopFlag::default(),
    );
    match &out {
        ToolOutcome::Untrusted(t) => assert!(t.contains("echo: again")),
        other => panic!("{other:?}"),
    }
    assert_eq!(seen.lock().map(|s| s.inits).unwrap_or(0), 2);
}

#[test]
fn modern_http_cancels_by_closing_the_stream_not_by_a_notification() {
    let (url, seen, _) = start_era(FxEra::Modern, None);
    let mut cfg = http_server("web", &url);
    cfg.timeout = Duration::from_millis(300);
    let client = McpClient::connect(&cfg).expect("connect");
    let err = client
        .call_tool("sleep", json!({"ms": 2000}), &StopFlag::default())
        .expect_err("timeout");
    assert!(matches!(err, McpError::Timeout(_)), "{err:?}");
    std::thread::sleep(Duration::from_millis(300));
    let seen = seen.lock().expect("seen");
    assert!(
        !seen
            .modern
            .iter()
            .any(|(m, _, _, _)| m == "notifications/cancelled"),
        "{:?}",
        seen.modern
    );
}
