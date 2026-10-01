//! HUP-S4.1: the MCP host against a real stdio MCP server (the crate's fixture binary).

use citrate_agent_loop::{Effect, HostKind, StopFlag, ToolCall, ToolOutcome, Trust};
use citrate_agent_mcp_host::config::{McpConfig, ServerConfig, TransportConfig};
use citrate_agent_mcp_host::{McpClient, McpError, McpHost, ServerState};
use serde_json::{json, Value};
use std::collections::BTreeMap;
use std::sync::Arc;
use std::time::{Duration, Instant};

const FIXTURE: &str = env!("CARGO_BIN_EXE_citrate-mcp-fixture-server");

fn server(name: &str, args: &[&str]) -> ServerConfig {
    let mut cfg = ServerConfig::new(
        name,
        TransportConfig::Stdio {
            command: FIXTURE.into(),
            args: args.iter().map(|s| s.to_string()).collect(),
            env: BTreeMap::new(),
            cwd: None,
        },
    );
    cfg.timeout = Duration::from_secs(5);
    cfg
}

fn call(name: &str, args: Value) -> ToolCall {
    ToolCall {
        id: "c1".into(),
        name: name.into(),
        arguments: args.to_string(),
    }
}

fn text_of(o: &ToolOutcome) -> String {
    match o {
        ToolOutcome::Ok(s)
        | ToolOutcome::Untrusted(s)
        | ToolOutcome::Denied(s)
        | ToolOutcome::Error(s) => s.clone(),
    }
}

#[test]
fn initialize_negotiates_the_version_and_records_capabilities() {
    let client = McpClient::connect(&server("fx", &[])).expect("connect");
    let info = client.info();
    assert_eq!(info.protocol_version, "2025-06-18");
    assert_eq!(info.capabilities["tools"]["listChanged"], json!(true));
    assert_eq!(info.server_name, "citrate-mcp-fixture");
    // The server saw `notifications/initialized` after the handshake.
    let state = client
        .call_tool("state", json!({}), &StopFlag::default())
        .expect("state");
    let state: Value = serde_json::from_str(&state.text).expect("state json");
    assert_eq!(state["initialized"], json!(true));
    assert_eq!(state["requestedVersion"], json!("2025-06-18"));
}

#[test]
fn an_older_supported_version_is_accepted() {
    let client = McpClient::connect(&server("fx", &["--version", "2024-11-05"])).expect("connect");
    assert_eq!(client.info().protocol_version, "2024-11-05");
}

#[test]
fn an_unsupported_version_is_refused() {
    let err =
        McpClient::connect(&server("fx", &["--version", "1999-01-01"])).expect_err("must refuse");
    assert!(matches!(err, McpError::Unsupported(_)), "{err:?}");
}

#[test]
fn tools_map_to_untrusted_sidecar_specs_with_prefixed_names() {
    let host = McpHost::connect(&McpConfig {
        servers: vec![{
            let mut s = server("fx", &["--paged"]);
            s.allow_write_tools = true;
            s
        }],
    });
    let specs = host.specs();
    let names: Vec<&str> = specs.iter().map(|s| s.name.as_str()).collect();
    // Pagination: tools from both pages are present.
    assert!(names.contains(&"mcp__fx__echo"), "{names:?}");
    assert!(names.contains(&"mcp__fx__state"), "{names:?}");
    // Dots are not valid in model tool names; they are mapped and the call still reaches the tool.
    assert!(names.contains(&"mcp__fx__dotted_name"), "{names:?}");
    for s in &specs {
        assert_eq!(s.host, HostKind::Sidecar);
        assert_eq!(s.annotations.trust, Some(Trust::Untrusted), "{}", s.name);
        assert!(
            s.description.contains("MCP server 'fx'"),
            "{}",
            s.description
        );
    }
    let by = |n: &str| specs.iter().find(|s| s.name == n).cloned().expect(n);
    assert_eq!(by("mcp__fx__echo").annotations.effect, Some(Effect::None));
    assert!(by("mcp__fx__echo").annotations.read_only);
    assert!(!by("mcp__fx__echo").annotations.open_world);
    assert_eq!(
        by("mcp__fx__write_note").annotations.effect,
        Some(Effect::Write)
    );
    assert!(by("mcp__fx__write_note").annotations.destructive);
    // No annotations: the spec's defaults (not read-only, destructive, open world) apply.
    let plain = by("mcp__fx__plain");
    assert_eq!(plain.annotations.effect, Some(Effect::Write));
    assert!(plain.annotations.destructive);
    assert!(plain.annotations.open_world);
    let out = host.call(
        &call("mcp__fx__dotted_name", json!({"text": "d"})),
        &StopFlag::default(),
    );
    assert!(text_of(&out).contains("echo: d"), "{out:?}");
}

#[test]
fn write_tools_are_not_offered_unless_the_server_allows_them() {
    let host = McpHost::connect(&McpConfig {
        servers: vec![server("fx", &[])],
    });
    let names: Vec<String> = host.specs().iter().map(|s| s.name.clone()).collect();
    assert!(names.contains(&"mcp__fx__echo".to_string()));
    assert!(
        !names.contains(&"mcp__fx__write_note".to_string()),
        "{names:?}"
    );
    assert!(!names.contains(&"mcp__fx__plain".to_string()), "{names:?}");
    // And a call to a hidden write tool is refused by the host, not forwarded.
    let out = host.call(
        &call("mcp__fx__write_note", json!({})),
        &StopFlag::default(),
    );
    assert!(matches!(out, ToolOutcome::Error(_)), "{out:?}");
}

#[test]
fn a_call_returns_fenced_untrusted_output() {
    let host = McpHost::connect(&McpConfig {
        servers: vec![server("fx", &[])],
    });
    let out = host.call(
        &call("mcp__fx__echo", json!({"text": "hi"})),
        &StopFlag::default(),
    );
    match &out {
        ToolOutcome::Untrusted(s) => {
            assert!(s.contains("echo: hi"), "{s}");
            assert!(s.contains("untrusted"), "{s}");
        }
        other => panic!("expected untrusted output, got {other:?}"),
    }
}

#[test]
fn a_tool_level_error_is_an_error_outcome_with_the_text() {
    let host = McpHost::connect(&McpConfig {
        servers: vec![server("fx", &[])],
    });
    let out = host.call(&call("mcp__fx__fail", json!({})), &StopFlag::default());
    assert!(matches!(out, ToolOutcome::Error(_)), "{out:?}");
    assert!(text_of(&out).contains("it failed"));
}

#[test]
fn mixed_content_is_rendered_without_binary_payloads() {
    let host = McpHost::connect(&McpConfig {
        servers: vec![server("fx", &[])],
    });
    let s = text_of(&host.call(&call("mcp__fx__media", json!({})), &StopFlag::default()));
    assert!(s.contains("caption"), "{s}");
    assert!(s.contains("image/png"), "{s}");
    assert!(
        !s.contains("aGVsbG8="),
        "binary data must not reach the model: {s}"
    );
    assert!(s.contains("file:///tmp/x.txt"), "{s}");
    assert!(s.contains("embedded text"), "{s}");
}

#[test]
fn a_slow_call_times_out_and_the_server_is_told_to_cancel() {
    let mut cfg = server("fx", &[]);
    cfg.timeout = Duration::from_millis(300);
    let client = McpClient::connect(&cfg).expect("connect");
    let started = Instant::now();
    let err = client
        .call_tool("sleep", json!({"ms": 5000}), &StopFlag::default())
        .expect_err("must time out");
    assert!(matches!(err, McpError::Timeout(_)), "{err:?}");
    assert!(started.elapsed() < Duration::from_secs(3));
    // The connection is still usable, and the server saw a cancellation for that request.
    let state = client
        .call_tool("state", json!({}), &StopFlag::default())
        .expect("state");
    let state: Value = serde_json::from_str(&state.text).expect("json");
    assert_eq!(
        state["cancelled"].as_array().map(|a| a.len()),
        Some(1),
        "{state}"
    );
}

#[test]
fn stop_cancels_an_in_flight_call() {
    let client = Arc::new(McpClient::connect(&server("fx", &[])).expect("connect"));
    let stop = StopFlag::default();
    let s2 = stop.clone();
    let t = std::thread::spawn(move || {
        std::thread::sleep(Duration::from_millis(150));
        s2.stop();
    });
    let started = Instant::now();
    let err = client
        .call_tool("sleep", json!({"ms": 5000}), &stop)
        .expect_err("must be cancelled");
    let _ = t.join();
    assert!(matches!(err, McpError::Cancelled), "{err:?}");
    assert!(started.elapsed() < Duration::from_secs(2));
}

#[test]
fn an_oversized_response_is_refused_and_the_connection_survives() {
    let mut cfg = server("fx", &[]);
    cfg.max_response_bytes = 4096;
    let client = McpClient::connect(&cfg).expect("connect");
    let err = client
        .call_tool("big", json!({"bytes": 100_000}), &StopFlag::default())
        .expect_err("must refuse");
    assert!(matches!(err, McpError::Oversize(_)), "{err:?}");
    let ok = client
        .call_tool("echo", json!({"text": "still here"}), &StopFlag::default())
        .expect("echo after oversize");
    assert!(ok.text.contains("still here"));
}

#[test]
fn long_output_is_truncated_for_the_model() {
    let mut cfg = server("fx", &[]);
    cfg.max_output_chars = 500;
    let host = McpHost::connect(&McpConfig { servers: vec![cfg] });
    let s = text_of(&host.call(
        &call("mcp__fx__big", json!({"bytes": 20_000})),
        &StopFlag::default(),
    ));
    assert!(s.len() < 1200, "len {}", s.len());
    assert!(s.contains("truncated"), "{s}");
}

#[test]
fn a_bad_json_line_is_skipped_and_counted() {
    let client = McpClient::connect(&server("fx", &[])).expect("connect");
    let r = client
        .call_tool("garbage_then_echo", json!({}), &StopFlag::default())
        .expect("answer after garbage");
    assert!(r.text.contains("after garbage"));
    assert_eq!(client.bad_messages(), 1);
}

#[test]
fn a_bad_json_answer_never_matches_and_times_out() {
    let mut cfg = server("fx", &[]);
    cfg.timeout = Duration::from_millis(300);
    let client = McpClient::connect(&cfg).expect("connect");
    let err = client
        .call_tool("garbage_only", json!({}), &StopFlag::default())
        .expect_err("no answer");
    assert!(matches!(err, McpError::Timeout(_)), "{err:?}");
}

#[test]
fn a_server_crash_fails_the_call_and_marks_the_server_down() {
    let host = McpHost::connect(&McpConfig {
        servers: vec![server("fx", &[])],
    });
    let started = Instant::now();
    let out = host.call(&call("mcp__fx__crash", json!({})), &StopFlag::default());
    assert!(matches!(out, ToolOutcome::Error(_)), "{out:?}");
    assert!(text_of(&out).contains("exited"), "{out:?}");
    assert!(
        started.elapsed() < Duration::from_secs(3),
        "must not wait for the timeout"
    );
    let st = host.status();
    assert_eq!(st[0].state, ServerState::Exited);
    let again = host.call(
        &call("mcp__fx__echo", json!({"text": "x"})),
        &StopFlag::default(),
    );
    assert!(matches!(again, ToolOutcome::Error(_)), "{again:?}");
}

#[test]
fn server_to_client_requests_are_answered_method_not_found() {
    let client = McpClient::connect(&server("fx", &[])).expect("connect");
    let r = client
        .call_tool("ask_client", json!({}), &StopFlag::default())
        .expect("answer");
    assert!(r.text.contains("-32601"), "{}", r.text);
}

#[test]
fn the_child_gets_only_allowlisted_and_explicit_env() {
    // A secret in the host's environment must not reach the server.
    std::env::set_var("CITRATE_MCP_TEST_SECRET", "hunter2");
    let mut cfg = server("fx", &[]);
    if let TransportConfig::Stdio { env, .. } = &mut cfg.transport {
        env.insert("FX_EXPLICIT".into(), "yes".into());
    }
    let client = McpClient::connect(&cfg).expect("connect");
    let r = client
        .call_tool("env", json!({}), &StopFlag::default())
        .expect("env");
    let env: Value = serde_json::from_str(&r.text).expect("env json");
    let obj = env.as_object().expect("object");
    assert_eq!(obj.get("FX_EXPLICIT"), Some(&json!("yes")));
    assert!(obj.get("CITRATE_MCP_TEST_SECRET").is_none(), "{env}");
    for k in obj.keys() {
        assert!(
            k == "FX_EXPLICIT"
                || citrate_agent_mcp_host::config::BASE_ENV_ALLOWLIST.contains(&k.as_str()),
            "unexpected env var {k} reached the server"
        );
    }
}

#[test]
fn stderr_noise_does_not_stall_the_server() {
    let client = McpClient::connect(&server("fx", &["--noisy"])).expect("connect");
    for i in 0..50 {
        let r = client
            .call_tool(
                "echo",
                json!({"text": format!("n{i}")}),
                &StopFlag::default(),
            )
            .expect("echo");
        assert!(r.text.contains(&format!("n{i}")));
    }
}

#[test]
fn a_server_that_fails_to_start_is_reported_and_others_still_work() {
    let bad = ServerConfig::new(
        "bad",
        TransportConfig::Stdio {
            command: "/nonexistent/citrate-mcp-server".into(),
            args: vec![],
            env: BTreeMap::new(),
            cwd: None,
        },
    );
    let host = McpHost::connect(&McpConfig {
        servers: vec![bad, server("fx", &[])],
    });
    let st = host.status();
    assert_eq!(st[0].name, "bad");
    assert_eq!(st[0].state, ServerState::Failed);
    assert_eq!(st[1].state, ServerState::Ready);
    assert!(host.specs().iter().all(|s| s.name.starts_with("mcp__fx__")));
}

#[test]
fn the_tool_host_binds_a_stop_flag_and_refuses_unknown_names() {
    let host = Arc::new(McpHost::connect(&McpConfig {
        servers: vec![server("fx", &[])],
    }));
    let stop = StopFlag::default();
    let th = McpHost::tool_host(host.clone(), stop.clone());
    assert!(host.handles("mcp__fx__echo"));
    assert!(!host.handles("mcp__fx__nope"));
    let out = th.execute(&call("mcp__fx__nope", json!({})));
    assert!(matches!(out, ToolOutcome::Error(_)));
    // The host cannot put a call in front of a person, so after taint the loop declines effectful
    // MCP calls instead of dispatching them (fail closed).
    assert!(!th.honors_explicit_approval());
    stop.stop();
    let out = th.execute(&call("mcp__fx__sleep", json!({"ms": 3000})));
    assert!(matches!(out, ToolOutcome::Error(_)), "{out:?}");
}

#[test]
fn non_object_arguments_are_refused_before_reaching_the_server() {
    let host = McpHost::connect(&McpConfig {
        servers: vec![server("fx", &[])],
    });
    let out = host.call(
        &ToolCall {
            id: "c".into(),
            name: "mcp__fx__echo".into(),
            arguments: "[1,2]".into(),
        },
        &StopFlag::default(),
    );
    assert!(matches!(out, ToolOutcome::Error(_)), "{out:?}");
}
