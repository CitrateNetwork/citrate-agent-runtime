//! HUP-S4.1 (revision 2026-07-28): the dual-era host against the real stdio fixture server in its
//! modern and dual modes: `server/discover`, per-request `_meta`, the Tasks extension, URL-mode
//! elicitation through an elicitor, tool-list changes and reconnect with backoff.

use citrate_agent_loop::{StopFlag, ToolCall, ToolOutcome};
use citrate_agent_mcp_host::config::{McpConfig, ServerConfig, TransportConfig};
use citrate_agent_mcp_host::host::CallCtx;
use citrate_agent_mcp_host::{
    CallOpts, ElicitAction, Elicitor, Era, McpClient, McpError, McpHost, ServerState,
    UrlElicitation,
};
use serde_json::{json, Value};
use std::collections::BTreeMap;
use std::sync::Mutex;
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

fn state(client: &McpClient) -> Value {
    let r = client
        .call_tool("state", json!({}), &StopFlag::default())
        .expect("state");
    serde_json::from_str(&r.text).expect("state json")
}

/// Answers every URL elicitation with a fixed action and records what it was shown.
struct Member {
    answer: ElicitAction,
    seen: Mutex<Vec<UrlElicitation>>,
}

impl Member {
    fn new(answer: ElicitAction) -> Self {
        Member {
            answer,
            seen: Mutex::new(Vec::new()),
        }
    }
    fn asked(&self) -> Vec<UrlElicitation> {
        self.seen.lock().map(|s| s.clone()).unwrap_or_default()
    }
}

impl Elicitor for Member {
    fn open_url(&self, req: &UrlElicitation) -> ElicitAction {
        if let Ok(mut s) = self.seen.lock() {
            s.push(req.clone());
        }
        self.answer
    }
}

#[test]
fn a_modern_server_is_found_by_discover_and_spoken_to_statelessly() {
    let client = McpClient::connect(&server("fx", &["--modern"])).expect("connect");
    let info = client.info();
    assert_eq!(info.era, Era::Modern);
    assert_eq!(info.protocol_version, "2026-07-28");
    assert_eq!(info.server_name, "citrate-mcp-fixture-modern");
    assert!(info.tasks(), "the server advertised the Tasks extension");
    let tools = client.list_tools().expect("list");
    assert!(tools.iter().any(|t| t.name == "long_job"));
    let r = client
        .call_tool("echo", json!({"text": "stateless"}), &StopFlag::default())
        .expect("echo");
    assert!(r.text.contains("echo: stateless"));
    let st = state(&client);
    let methods: Vec<&str> = st["modernMethods"]
        .as_array()
        .expect("methods")
        .iter()
        .filter_map(Value::as_str)
        .collect();
    assert_eq!(methods.first(), Some(&"server/discover"));
    assert!(methods.contains(&"tools/list") && methods.contains(&"tools/call"));
    assert!(!methods.contains(&"initialize"));
    // Every call declares the Tasks extension; URL elicitation only when someone can be asked.
    let caps = &st["callCaps"][0];
    assert!(caps
        .pointer("/extensions/io.modelcontextprotocol~1tasks")
        .is_some());
    assert!(caps.get("elicitation").is_none(), "{caps}");
    // The server's listChanged capability opened a subscription.
    assert!(!st["listening"].is_null(), "{st}");
}

#[test]
fn a_dual_era_server_is_spoken_to_in_the_modern_era() {
    let client = McpClient::connect(&server("fx", &["--dual"])).expect("connect");
    assert_eq!(client.info().era, Era::Modern);
    let st = state(&client);
    assert_eq!(st["initialized"], json!(false));
}

#[test]
fn a_legacy_server_is_reached_through_the_handshake_after_the_probe() {
    let client = McpClient::connect(&server("fx", &[])).expect("connect");
    assert_eq!(client.info().era, Era::Legacy);
    let st = state(&client);
    assert_eq!(st["initialized"], json!(true));
    assert_eq!(st["modernMethods"], json!([]));
}

#[test]
fn a_modern_server_without_our_version_is_refused_without_falling_back() {
    let err = McpClient::connect(&server("fx", &["--modern", "--version", "2027-01-01"]))
        .expect_err("refused");
    match err {
        McpError::UnsupportedVersion { supported } => {
            assert_eq!(supported, vec!["2027-01-01".to_string()])
        }
        other => panic!("expected UnsupportedVersion, got {other:?}"),
    }
}

#[test]
fn a_task_is_polled_until_it_completes() {
    let client = McpClient::connect(&server("fx", &["--modern"])).expect("connect");
    let started = Instant::now();
    let r = client
        .call_tool("long_job", json!({"polls": 3}), &StopFlag::default())
        .expect("task result");
    assert_eq!(r.text, "long_job finished after 3 polls");
    assert!(!r.is_error);
    // pollIntervalMs 50 is clamped up to the 100 ms floor: three polls take at least 300 ms.
    assert!(started.elapsed() >= Duration::from_millis(300));
}

#[test]
fn a_stopped_task_is_cancelled_with_tasks_cancel() {
    let client = McpClient::connect(&server("fx", &["--modern"])).expect("connect");
    let stop = StopFlag::default();
    let s2 = stop.clone();
    let t = std::thread::spawn(move || {
        std::thread::sleep(Duration::from_millis(300));
        s2.stop();
    });
    let err = client
        .call_tool("forever_job", json!({}), &stop)
        .expect_err("stopped");
    let _ = t.join();
    assert!(matches!(err, McpError::Cancelled), "{err:?}");
    assert_eq!(state(&client)["cancelledTasks"], json!(["task-1"]));
}

#[test]
fn a_task_past_its_deadline_is_cancelled() {
    let mut cfg = server("fx", &["--modern"]);
    cfg.task_timeout = Duration::from_millis(400);
    let client = McpClient::connect(&cfg).expect("connect");
    let started = Instant::now();
    let err = client
        .call_tool("forever_job", json!({}), &StopFlag::default())
        .expect_err("timeout");
    assert!(matches!(err, McpError::Timeout(_)), "{err:?}");
    assert!(started.elapsed() < Duration::from_secs(3));
    assert_eq!(state(&client)["cancelledTasks"], json!(["task-1"]));
}

#[test]
fn a_url_elicitation_inside_a_task_is_asked_once_and_answered_through_tasks_update() {
    let client = McpClient::connect(&server("fx", &["--modern"])).expect("connect");
    let member = Member::new(ElicitAction::Accept);
    let opts = CallOpts {
        elicitor: Some(&member),
        tool: None,
    };
    let r = client
        .call_tool_with("job_needs_url", json!({}), &StopFlag::default(), &opts)
        .expect("task result");
    assert_eq!(r.text, "job finished after the member said accept");
    let asked = member.asked();
    assert_eq!(asked.len(), 1, "asked {asked:?}");
    assert_eq!(asked[0].url, "https://jobs.example.com/connect?job=1");
    assert_eq!(asked[0].host, "jobs.example.com");
    assert_eq!(asked[0].server, "fx");
    let st = state(&client);
    assert_eq!(
        st["taskUpdates"][0]["inputResponses"]["login"]["action"],
        json!("accept")
    );
    assert!(st["callCaps"][0].pointer("/elicitation/url").is_some());
}

#[test]
fn a_task_that_needs_input_with_no_one_to_ask_is_cancelled() {
    let client = McpClient::connect(&server("fx", &["--modern"])).expect("connect");
    let err = client
        .call_tool("job_needs_url", json!({}), &StopFlag::default())
        .expect_err("no elicitor");
    assert!(matches!(err, McpError::InputRequired(_)), "{err:?}");
    assert_eq!(state(&client)["cancelledTasks"], json!(["task-1"]));
}

#[test]
fn a_multi_round_trip_url_elicitation_retries_with_the_answer_and_request_state() {
    let client = McpClient::connect(&server("fx", &["--modern"])).expect("connect");
    for (answer, want) in [
        (ElicitAction::Accept, "account connected"),
        (ElicitAction::Decline, "not connected: decline"),
    ] {
        let member = Member::new(answer);
        let opts = CallOpts {
            elicitor: Some(&member),
            tool: None,
        };
        let r = client
            .call_tool_with("connect_account", json!({}), &StopFlag::default(), &opts)
            .expect("result");
        assert_eq!(r.text, want);
        let asked = member.asked();
        assert_eq!(asked.len(), 1);
        assert_eq!(asked[0].url, "https://auth.example.com/connect?state=abc");
        assert_eq!(asked[0].message, "Connect your GitHub account.");
    }
    // Without an elicitor URL mode is not declared, so the server reports the missing capability.
    let err = client
        .call_tool("connect_account", json!({}), &StopFlag::default())
        .expect_err("not declared");
    assert!(matches!(err, McpError::Rpc { code: -32021, .. }), "{err:?}");
}

#[test]
fn a_form_elicitation_is_refused() {
    let client = McpClient::connect(&server("fx", &["--modern"])).expect("connect");
    let member = Member::new(ElicitAction::Accept);
    let opts = CallOpts {
        elicitor: Some(&member),
        tool: None,
    };
    let err = client
        .call_tool_with("ask_form", json!({}), &StopFlag::default(), &opts)
        .expect_err("form");
    assert!(matches!(err, McpError::InputRequired(_)), "{err:?}");
    assert!(
        member.asked().is_empty(),
        "a form is never put to the member"
    );
}

fn tool_list_changes_are_relisted(args: &[&str]) {
    let host = McpHost::connect(&McpConfig {
        servers: vec![server("fx", args)],
    });
    assert!(!host.handles("mcp__fx__added_later"));
    let echo_before = host
        .specs()
        .into_iter()
        .find(|s| s.name == "mcp__fx__echo")
        .expect("echo offered");
    let out = host.call(
        &call("mcp__fx__change_tools", json!({})),
        &StopFlag::default(),
    );
    assert!(matches!(out, ToolOutcome::Untrusted(_)), "{out:?}");
    // The notification arrives on the channel; the next maintenance pass re-lists.
    let deadline = Instant::now() + Duration::from_secs(3);
    while !host.handles("mcp__fx__added_later") {
        assert!(Instant::now() < deadline, "the new tool never appeared");
        std::thread::sleep(Duration::from_millis(20));
        host.maintain_now();
    }
    assert_eq!(host.status()[0].relists, 1);
    // Now echo turns destructive: the policy (no write tools) is applied again and it is withdrawn.
    host.call(&call("mcp__fx__flip_echo", json!({})), &StopFlag::default());
    let deadline = Instant::now() + Duration::from_secs(3);
    while host.handles("mcp__fx__echo") {
        assert!(Instant::now() < deadline, "echo was never withdrawn");
        std::thread::sleep(Duration::from_millis(20));
        host.maintain_now();
    }
    let st = &host.status()[0];
    assert!(
        st.skipped.iter().any(|s| s.starts_with("echo:")),
        "{:?}",
        st.skipped
    );
    // A session that was offered the old echo cannot call it any more.
    let out = host.call_with(
        &call("mcp__fx__echo", json!({"text": "x"})),
        &StopFlag::default(),
        &CallCtx {
            elicitor: None,
            offered: Some(&echo_before),
        },
    );
    assert!(matches!(out, ToolOutcome::Error(_)), "{out:?}");
    assert!(text_of(&out).contains("no longer offered"), "{out:?}");
}

#[test]
fn a_legacy_tool_list_change_is_relisted_with_the_policy_applied_again() {
    tool_list_changes_are_relisted(&[]);
}

#[test]
fn a_modern_tool_list_change_arrives_on_the_subscription_and_is_relisted() {
    tool_list_changes_are_relisted(&["--modern"]);
}

#[test]
fn a_changed_tool_is_refused_to_a_session_that_was_offered_the_old_version() {
    let mut cfg = server("fx", &[]);
    cfg.allow_write_tools = true;
    let host = McpHost::connect(&McpConfig { servers: vec![cfg] });
    let echo_before = host
        .specs()
        .into_iter()
        .find(|s| s.name == "mcp__fx__echo")
        .expect("echo offered");
    host.call(&call("mcp__fx__flip_echo", json!({})), &StopFlag::default());
    let deadline = Instant::now() + Duration::from_secs(3);
    loop {
        host.maintain_now();
        let now = host.specs().into_iter().find(|s| s.name == "mcp__fx__echo");
        if now.as_ref().is_some_and(|s| *s != echo_before) {
            break;
        }
        assert!(Instant::now() < deadline, "echo never changed");
        std::thread::sleep(Duration::from_millis(20));
    }
    let out = host.call_with(
        &call("mcp__fx__echo", json!({"text": "x"})),
        &StopFlag::default(),
        &CallCtx {
            elicitor: None,
            offered: Some(&echo_before),
        },
    );
    assert!(text_of(&out).contains("changed"), "{out:?}");
    // A new session (offered the new spec) can call it.
    let echo_now = host
        .specs()
        .into_iter()
        .find(|s| s.name == "mcp__fx__echo")
        .expect("echo");
    let out = host.call_with(
        &call("mcp__fx__echo", json!({"text": "y"})),
        &StopFlag::default(),
        &CallCtx {
            elicitor: None,
            offered: Some(&echo_now),
        },
    );
    assert!(matches!(out, ToolOutcome::Untrusted(_)), "{out:?}");
}

#[test]
fn an_exited_server_is_reconnected_after_its_backoff() {
    for args in [&[][..], &["--modern"][..]] {
        let host = McpHost::connect(&McpConfig {
            servers: vec![server("fx", args)],
        });
        let out = host.call(&call("mcp__fx__crash", json!({})), &StopFlag::default());
        assert!(matches!(out, ToolOutcome::Error(_)), "{out:?}");
        host.maintain_now();
        let st = &host.status()[0];
        assert_eq!(st.state, ServerState::Exited);
        assert_eq!(st.tools, 0, "an exited server offers nothing");
        assert!(st.next_retry_ms.is_some());
        let refused = host.call(
            &call("mcp__fx__echo", json!({"text": "x"})),
            &StopFlag::default(),
        );
        assert!(
            text_of(&refused).contains("reconnecting")
                || text_of(&refused).contains("not an MCP tool"),
            "{refused:?}"
        );
        std::thread::sleep(Duration::from_millis(1100));
        host.maintain_now();
        let st = &host.status()[0];
        assert_eq!(st.state, ServerState::Ready, "{st:?}");
        assert_eq!(st.reconnects, 1);
        let out = host.call(
            &call("mcp__fx__echo", json!({"text": "back"})),
            &StopFlag::default(),
        );
        assert!(text_of(&out).contains("echo: back"), "{out:?}");
    }
}

#[test]
fn a_server_that_keeps_failing_backs_off_exponentially() {
    let bad = ServerConfig::new(
        "bad",
        TransportConfig::Stdio {
            command: "/nonexistent/citrate-mcp-server".into(),
            args: vec![],
            env: BTreeMap::new(),
            cwd: None,
        },
    );
    let host = McpHost::connect(&McpConfig { servers: vec![bad] });
    let first = host.status()[0].next_retry_ms.expect("retry scheduled");
    assert!(first <= 1000, "{first}");
    // Not due yet: nothing is attempted.
    host.maintain_now();
    assert!(host.status()[0].next_retry_ms.expect("retry") <= 1000);
    std::thread::sleep(Duration::from_millis(1050));
    host.maintain_now();
    let st = &host.status()[0];
    assert_eq!(st.state, ServerState::Failed);
    let second = st.next_retry_ms.expect("retry");
    assert!((1500..=2000).contains(&second), "{second}");
}

#[test]
fn background_maintenance_reconnects_without_a_call() {
    let host = std::sync::Arc::new(McpHost::connect(&McpConfig {
        servers: vec![server("fx", &[])],
    }));
    McpHost::start_maintenance(&host, Duration::from_millis(50));
    host.call(&call("mcp__fx__crash", json!({})), &StopFlag::default());
    let deadline = Instant::now() + Duration::from_secs(5);
    loop {
        let st = &host.status()[0];
        if st.reconnects == 1 && st.state == ServerState::Ready {
            break;
        }
        assert!(Instant::now() < deadline, "never reconnected: {st:?}");
        std::thread::sleep(Duration::from_millis(50));
    }
}
