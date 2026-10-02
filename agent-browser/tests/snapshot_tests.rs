//! HUP-S5.1: ref-indexed accessibility snapshots. The snapshot is built from the CDP
//! `Accessibility.getFullAXTree` result: interactive elements get refs (`e1`, `e2`, ...) that map
//! back to DOM nodes, structure-only nodes are flattened away, and page text is sanitised and
//! bounded so a page costs a few hundred tokens, not thousands.

use citrate_agent_browser::snapshot::{build_snapshot, SnapshotLimits};
use serde_json::{json, Value};

fn node(id: &str, role: &str, name: &str, children: &[&str], backend: Option<i64>) -> Value {
    let mut n = json!({
        "nodeId": id,
        "ignored": false,
        "role": {"type": "role", "value": role},
        "name": {"type": "computedString", "value": name},
        "childIds": children,
    });
    if let Some(b) = backend {
        n["backendDOMNodeId"] = json!(b);
    }
    n
}

fn small_page() -> Vec<Value> {
    let mut textbox = node("6", "textbox", "Email", &[], Some(106));
    textbox["value"] = json!({"type": "string", "value": "me@example.com"});
    let mut ignored = node("9", "generic", "", &["10"], Some(109));
    ignored["ignored"] = json!(true);
    let mut disabled = node("10", "button", "Later", &[], Some(110));
    disabled["properties"] =
        json!([{"name": "disabled", "value": {"type": "boolean", "value": true}}]);
    let mut heading = node("3", "heading", "Sign in", &["4"], Some(103));
    heading["properties"] = json!([{"name": "level", "value": {"type": "integer", "value": 1}}]);
    vec![
        node("1", "RootWebArea", "Example login", &["2"], Some(101)),
        node(
            "2",
            "generic",
            "",
            &["3", "5", "6", "7", "9", "11"],
            Some(102),
        ),
        heading,
        node("4", "StaticText", "Sign in", &[], None),
        node("5", "StaticText", "Use your account.\u{1b}[31m", &[], None),
        textbox,
        node("7", "button", "Continue", &["8"], Some(107)),
        node("8", "StaticText", "Continue", &[], None),
        ignored,
        disabled,
        node("11", "link", "Forgot password?", &[], Some(111)),
    ]
}

#[test]
fn interactive_elements_get_refs_in_document_order() {
    let snap = build_snapshot(&small_page(), SnapshotLimits::default());
    let refs: Vec<_> = snap
        .refs
        .iter()
        .map(|r| (r.r#ref.as_str(), r.role.as_str(), r.backend_node_id))
        .collect();
    assert_eq!(
        refs,
        vec![
            ("e1", "textbox", 106),
            ("e2", "button", 107),
            ("e3", "button", 110),
            ("e4", "link", 111),
        ]
    );
    assert_eq!(snap.refs[0].name, "Email");
}

#[test]
fn the_text_is_compact_and_readable() {
    let snap = build_snapshot(&small_page(), SnapshotLimits::default());
    let text = &snap.text;
    assert!(text.contains("page \"Example login\""), "{text}");
    assert!(text.contains("heading[1] \"Sign in\""), "{text}");
    assert!(
        text.contains("[e1] textbox \"Email\" value=\"me@example.com\""),
        "{text}"
    );
    assert!(text.contains("[e2] button \"Continue\""), "{text}");
    assert!(text.contains("[e3] button \"Later\" (disabled)"), "{text}");
    assert!(text.contains("[e4] link \"Forgot password?\""), "{text}");
    // Text that repeats its parent's name is not printed twice.
    assert_eq!(text.matches("Continue").count(), 1, "{text}");
    assert_eq!(text.matches("Sign in").count(), 1, "{text}");
    // Structure-only nodes are flattened away.
    assert!(!text.contains("generic"), "{text}");
    assert!(!snap.truncated);
}

#[test]
fn control_characters_from_the_page_are_stripped() {
    let snap = build_snapshot(&small_page(), SnapshotLimits::default());
    assert!(
        snap.text.contains("text \"Use your account.[31m\""),
        "{}",
        snap.text
    );
    assert!(!snap.text.contains('\u{1b}'));
}

#[test]
fn long_names_and_large_pages_are_bounded() {
    let long = "x".repeat(500);
    let mut nodes = vec![node("1", "RootWebArea", "Big", &[], Some(1))];
    let ids: Vec<String> = (2..2000).map(|i| i.to_string()).collect();
    nodes[0]["childIds"] = json!(ids);
    for i in 2..2000 {
        nodes.push(node(&i.to_string(), "link", &long, &[], Some(i)));
    }
    let limits = SnapshotLimits {
        max_refs: 50,
        max_chars: 4000,
        max_name_chars: 80,
    };
    let snap = build_snapshot(&nodes, limits);
    assert!(snap.truncated);
    assert!(snap.refs.len() <= 50);
    assert!(
        snap.text.chars().count() <= 4000 + 200,
        "{}",
        snap.text.len()
    );
    assert!(!snap.text.contains(&"x".repeat(81)));
    assert!(snap.text.contains("snapshot truncated"));
}

#[test]
fn hostile_trees_do_not_loop_or_panic() {
    // A cycle, a dangling child, a node with no role, an empty input.
    let nodes = vec![
        node("1", "RootWebArea", "Loop", &["2", "404"], Some(1)),
        node("2", "group", "g", &["1"], Some(2)),
        json!({"nodeId": "3"}),
    ];
    let snap = build_snapshot(&nodes, SnapshotLimits::default());
    assert!(snap.text.contains("Loop"));
    let empty = build_snapshot(&[], SnapshotLimits::default());
    assert!(empty.refs.is_empty());
    assert!(empty.text.contains("empty"), "{}", empty.text);
}

#[test]
fn nodes_without_a_dom_node_get_no_ref() {
    let nodes = vec![
        node("1", "RootWebArea", "P", &["2"], Some(1)),
        node("2", "button", "Ghost", &[], None),
    ];
    let snap = build_snapshot(&nodes, SnapshotLimits::default());
    assert!(snap.refs.is_empty());
    assert!(snap.text.contains("button \"Ghost\""), "{}", snap.text);
}

/// A tree recorded from a real headless Chrome (see tests/fixtures/README.md).
#[test]
fn a_recorded_chrome_tree_snapshots_to_its_form_controls() {
    let raw = include_str!("fixtures/ax-login-form.json");
    let v: Value = serde_json::from_str(raw).expect("fixture parses");
    let nodes = v["nodes"].as_array().expect("nodes").clone();
    let snap = build_snapshot(&nodes, SnapshotLimits::default());
    let roles: Vec<_> = snap
        .refs
        .iter()
        .map(|r| (r.role.as_str(), r.name.as_str()))
        .collect();
    assert!(
        roles.contains(&("textbox", "Email")),
        "{roles:?}\n{}",
        snap.text
    );
    assert!(roles.contains(&("button", "Continue")), "{roles:?}");
    assert!(roles.contains(&("link", "Forgot password?")), "{roles:?}");
    assert!(snap.text.chars().count() < 2000, "{}", snap.text);
}
