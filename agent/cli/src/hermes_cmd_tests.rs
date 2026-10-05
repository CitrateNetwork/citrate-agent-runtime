// HUP-S1.8 — `citrate-agent hermes …`: the terminal drives the same sidecar-owned agent.
use super::*;

#[test]
fn the_default_bearer_path_matches_where_the_app_writes_it() {
    assert_eq!(
        default_token_path("macos", "/Users/a"),
        std::path::PathBuf::from("/Users/a/Library/Application Support/ai.citrate.core/hermes/bearer.token")
    );
    assert_eq!(
        default_token_path("linux", "/home/a"),
        std::path::PathBuf::from("/home/a/.local/share/ai.citrate.core/hermes/bearer.token")
    );
}

#[test]
fn only_a_loopback_control_address_is_accepted() {
    for ok in ["127.0.0.1:19700", "[::1]:19700", "localhost:19700"] {
        assert!(check_loopback_addr(ok).is_ok(), "{ok}");
    }
    for bad in ["10.0.0.2:19700", "example.com:19700", "0.0.0.0:19700"] {
        assert!(check_loopback_addr(bad).is_err(), "{bad}");
    }
}

#[test]
fn a_cli_session_offers_only_sidecar_capsules_and_reads_the_key_from_the_environment() {
    let skills = vec![("hello".to_string(), "Say hello".to_string())];
    let body = build_open_body("qwen", "You are Hermes.", "http://127.0.0.1:18080/v1", "secret-k", &skills);
    assert_eq!(body["llm"]["bearer"], "secret-k");
    assert_eq!(body["tools"][0]["name"], "hello");
    assert_eq!(body["tools"][0]["host"], "sidecar", "core-hosted (gated) tools only exist inside the app");
    assert_eq!(body["maxToolsPerRequest"], 8);
}

#[test]
fn events_render_as_readable_lines() {
    let ev = |v: serde_json::Value| render_event(&v);
    assert_eq!(ev(serde_json::json!({"type":"final","content":"Height 6,310."})).as_deref(), Some("Height 6,310."));
    assert!(ev(serde_json::json!({"type":"tool_call","host":"core","call":{"name":"node_status"}})).unwrap().contains("node_status"));
    assert!(ev(serde_json::json!({"type":"verifier","name":"forge_test succeeded","passed":false,"detail":"never called"})).unwrap().contains("✗"));
    assert!(ev(serde_json::json!({"type":"error","message":"boom"})).unwrap().contains("boom"));
    assert_eq!(ev(serde_json::json!({"type":"step_end","step":1})), None, "noise is suppressed");
}

#[test]
fn session_ids_are_checked_before_they_reach_a_url() {
    assert!(check_session_id("s1-abc").is_ok());
    assert!(check_session_id("../stop").is_err());
    assert!(check_session_id("").is_err());
}

// HUP-S1.4 — the terminal runs the same interview the app does.
fn sample_track() -> Value {
    json!({"id": "full-project", "questions": [
        {"id": "name", "ask": "Project name?", "default": "Hello Mint", "choices": []},
        {"id": "standard", "ask": "Which token standard?", "default": "ERC-721", "choices": ["ERC-721", "ERC-1155"]},
        {"id": "supply", "ask": "Maximum supply?", "default": "500", "choices": []}
    ]})
}

#[test]
fn enter_takes_the_default_and_typed_answers_are_kept() {
    let mut input = std::io::Cursor::new("Lemon Drops\n\n1000\n");
    let mut prompts = Vec::new();
    let a = ask_questions(&sample_track(), &mut input, &mut prompts).unwrap();
    assert_eq!(a.get("name").map(String::as_str), Some("Lemon Drops"));
    assert!(!a.contains_key("standard"), "blank line = default, left for the sidecar to fill");
    assert_eq!(a.get("supply").map(String::as_str), Some("1000"));
    let shown = String::from_utf8(prompts).unwrap();
    assert!(shown.contains("[ERC-721]") && shown.contains("ERC-1155"), "{shown}");
}

#[test]
fn a_choice_can_be_picked_by_number_and_a_bad_pick_is_asked_again() {
    let mut input = std::io::Cursor::new("\n9\n2\n\n");
    let mut prompts = Vec::new();
    let a = ask_questions(&sample_track(), &mut input, &mut prompts).unwrap();
    assert_eq!(a.get("standard").map(String::as_str), Some("ERC-1155"));
    assert!(String::from_utf8(prompts).unwrap().contains("pick 1-2"));
}

#[test]
fn the_brief_body_omits_the_track_when_none_is_given() {
    let b = build_brief_body(None, "an NFT project", &BTreeMap::new());
    assert!(b.get("track").is_none());
    assert_eq!(b["goal"], "an NFT project");
    let b = build_brief_body(Some("code"), "fix a test", &BTreeMap::new());
    assert_eq!(b["track"], "code");
}

// HUP-S1.8 — `citrate-agent hermes run <workflow>` and `hermes sessions`.

#[test]
fn run_needs_exactly_one_of_session_or_model() {
    assert_eq!(run_target(Some("s1-ab"), None), Ok(RunTarget::Session("s1-ab".into())));
    assert_eq!(run_target(None, Some("qwen")), Ok(RunTarget::Model("qwen".into())));
    assert!(run_target(Some("s1-ab"), Some("qwen")).is_err());
    assert!(run_target(None, None).is_err());
    assert!(run_target(None, Some("  ")).is_err());
    assert!(run_target(Some("../x"), None).is_err(), "a session id is checked before it reaches a URL");
}

#[test]
fn a_catalog_id_starts_a_track_workflow_and_a_file_starts_its_spec() {
    let (route, body) = workflow_request("hello-mint", None).unwrap();
    assert_eq!(route, "track_workflows");
    assert_eq!(body, json!({"workflow": "hello-mint"}));
    let (route, body) = workflow_request("wf.json", Some(r#"{"id":"w","steps":[]}"#)).unwrap();
    assert_eq!(route, "workflows");
    assert_eq!(body["id"], "w");
    assert!(workflow_request("wf.json", Some("[1]")).is_err());
    assert!(workflow_request("wf.json", Some("not json")).is_err());
    assert!(workflow_request("../../etc", None).is_err());
    assert!(workflow_request("", None).is_err());
}

#[test]
fn a_finished_run_renders_its_verdict_and_a_running_one_does_not() {
    assert_eq!(render_run(&json!({"state": "running", "workflow_id": "w"})), None);
    assert_eq!(render_run(&json!({"state": "verified", "workflow_id": "hello-mint"})).as_deref(), Some("[hello-mint: verified]"));
    let u = render_run(&json!({"state": "unverified", "workflow_id": "w", "reason": "forge_test failed"})).unwrap();
    assert!(u.contains("unverified") && u.contains("forge_test failed"), "{u}");
}

#[test]
fn sessions_render_one_line_each() {
    let lines = render_sessions(&json!({"sessions": [
        {"id": "s1-a", "model": "gemma", "busy": true, "lastSeq": 12, "persona": "operator", "pendingCoreCalls": ["c1"]},
        {"id": "s2-b", "model": "qwen", "busy": false, "lastSeq": 0, "persona": null, "pendingCoreCalls": []}
    ]}));
    assert_eq!(lines.len(), 2);
    assert!(lines[0].contains("s1-a") && lines[0].contains("busy") && lines[0].contains("persona operator") && lines[0].contains("1 app tool call"), "{}", lines[0]);
    assert!(lines[1].contains("idle") && !lines[1].contains("persona"), "{}", lines[1]);
    assert!(render_sessions(&json!({"sessions": []})).is_empty());
}

#[test]
fn streamed_text_prints_once_even_with_the_final_event() {
    let mut p = EventPrinter::default();
    let mut out = Vec::new();
    for ev in [
        json!({"type": "step_start", "step": 1}),
        json!({"type": "assistant_delta", "step": 1, "text": "Height "}),
        json!({"type": "assistant_delta", "step": 1, "text": "6,310."}),
        json!({"type": "final", "content": "Height 6,310."}),
        json!({"type": "done", "outcome": "answered"}),
    ] {
        p.print(&ev, &mut out);
    }
    assert_eq!(String::from_utf8(out).unwrap(), "Height 6,310.\n[answered]\n");
}

#[test]
fn text_that_led_into_a_tool_call_ends_its_line() {
    let mut p = EventPrinter::default();
    let mut out = Vec::new();
    p.print(&json!({"type": "assistant_delta", "step": 1, "text": "Let me check."}), &mut out);
    p.print(&json!({"type": "tool_call", "host": "core", "call": {"name": "node_status"}}), &mut out);
    p.print(&json!({"type": "final", "content": "Done."}), &mut out);
    let s = String::from_utf8(out).unwrap();
    assert!(s.starts_with("Let me check.\n  → node_status"), "{s}");
    assert!(s.ends_with("Done.\n"), "{s}");
}

/// A loopback sidecar stand-in: answers each request by the first route prefix that matches.
fn fake_sidecar(routes: Vec<(&'static str, &'static str, String)>) -> (String, std::sync::mpsc::Receiver<String>) {
    use std::io::{Read as _, Write as _};
    let listener = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
    let addr = listener.local_addr().unwrap().to_string();
    let (tx, rx) = std::sync::mpsc::channel();
    std::thread::spawn(move || {
        for sock in listener.incoming().flatten() {
            let mut sock = sock;
            let mut reader = std::io::BufReader::new(sock.try_clone().unwrap());
            let mut first = String::new();
            if reader.read_line(&mut first).unwrap_or(0) == 0 {
                continue;
            }
            let mut len = 0usize;
            loop {
                let mut line = String::new();
                if reader.read_line(&mut line).unwrap_or(0) == 0 || line == "\r\n" {
                    break;
                }
                if let Some(v) = line.to_ascii_lowercase().strip_prefix("content-length:") {
                    len = v.trim().parse().unwrap_or(0);
                }
            }
            let mut body = vec![0u8; len];
            let _ = reader.read_exact(&mut body);
            let mut parts = first.split_whitespace();
            let method = parts.next().unwrap_or("").to_string();
            let path = parts.next().unwrap_or("").to_string();
            let _ = tx.send(format!("{method} {path} {}", String::from_utf8_lossy(&body)));
            let reply = routes
                .iter()
                .find(|(m, p, _)| *m == method && path.starts_with(p))
                .map(|(_, _, r)| r.clone())
                .unwrap_or_else(|| "{}".into());
            let resp = format!(
                "HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{reply}",
                reply.len()
            );
            let _ = sock.write_all(resp.as_bytes());
        }
    });
    (addr, rx)
}

fn client_for(addr: &str) -> Client {
    let dir = std::env::temp_dir().join(format!("n6-hermes-cli-{}", std::process::id()));
    let _ = std::fs::create_dir_all(&dir);
    let token = dir.join(format!("bearer-{}.token", addr.replace([':', '.'], "-")));
    std::fs::write(&token, "cli-test-bearer").unwrap();
    let args = HermesArgs { addr: addr.to_string(), token_file: Some(token), cmd: HermesCmd::Status };
    Client::new(&args).unwrap()
}

#[test]
fn run_follow_starts_the_catalog_workflow_and_prints_events_until_the_verdict() {
    let (addr, seen) = fake_sidecar(vec![
        ("GET", "/sessions/s1-ab/events?after=0&", json!({"events": [{"seq": 4, "event": {"type": "done", "outcome": "answered"}}], "lastSeq": 4, "busy": false}).to_string()),
        ("POST", "/sessions/s1-ab/track_workflows", json!({"run_id": "r1"}).to_string()),
        ("GET", "/sessions/s1-ab/events?after=4&", json!({"events": [
            {"seq": 5, "event": {"type": "step_start", "step": 1}},
            {"seq": 6, "event": {"type": "assistant_delta", "step": 1, "text": "Deployed."}},
            {"seq": 7, "event": {"type": "final", "content": "Deployed."}},
            {"seq": 8, "event": {"type": "verifier", "step": "deploy", "name": "forge_test succeeded", "passed": true, "detail": ""}},
            {"seq": 9, "event": {"type": "done", "outcome": "answered"}}
        ], "lastSeq": 9, "busy": false}).to_string()),
        ("GET", "/sessions/s1-ab/workflows/r1", json!({"run_id": "r1", "workflow_id": "hello-mint", "state": "verified"}).to_string()),
    ]);
    let c = client_for(&addr);
    let mut out = Vec::new();
    let view = c.run_workflow("s1-ab", "hello-mint", true, &mut out).unwrap();
    assert_eq!(view["state"], "verified");
    let printed = String::from_utf8(out).unwrap();
    assert_eq!(printed.matches("Deployed.").count(), 1, "{printed}");
    assert!(printed.contains("✓ forge_test succeeded"), "{printed}");
    assert!(printed.ends_with("[hello-mint: verified]\n"), "{printed}");
    assert!(!printed.contains("[answered]\n[answered]"), "the earlier turn's events are not replayed: {printed}");
    let reqs: Vec<String> = seen.try_iter().collect();
    let start = reqs.iter().find(|r| r.starts_with("POST /sessions/s1-ab/track_workflows")).unwrap();
    assert!(start.contains("\"workflow\":\"hello-mint\""), "{start}");
}

#[test]
fn run_without_follow_returns_the_run_id_at_once() {
    let (addr, _seen) = fake_sidecar(vec![
        ("GET", "/sessions/s1-ab/events", json!({"events": [], "lastSeq": 0, "busy": false}).to_string()),
        ("POST", "/sessions/s1-ab/track_workflows", json!({"run_id": "r7"}).to_string()),
    ]);
    let c = client_for(&addr);
    let mut out = Vec::new();
    let v = c.run_workflow("s1-ab", "hello-mint", false, &mut out).unwrap();
    assert_eq!(v["run_id"], "r7");
    assert!(out.is_empty());
}

#[test]
fn a_malformed_run_id_is_refused_before_it_reaches_a_url() {
    let (addr, _seen) = fake_sidecar(vec![
        ("GET", "/sessions/s1-ab/events", json!({"events": [], "lastSeq": 0, "busy": false}).to_string()),
        ("POST", "/sessions/s1-ab/track_workflows", json!({"run_id": "../stop"}).to_string()),
    ]);
    let c = client_for(&addr);
    let mut out = Vec::new();
    assert!(c.run_workflow("s1-ab", "hello-mint", true, &mut out).is_err());
}
