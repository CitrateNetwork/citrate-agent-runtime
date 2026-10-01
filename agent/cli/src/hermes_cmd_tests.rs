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
