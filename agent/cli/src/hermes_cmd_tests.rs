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
