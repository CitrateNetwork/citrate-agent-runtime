//! HUP-S4.4: validation of a user-added MCP server entry (the shape citrate-core's Settings writes
//! into the allowlist file and sends to the dry-run probe).

use citrate_agent_mcp_host::config::{TransportConfig, BASE_ENV_ALLOWLIST};
use citrate_agent_mcp_host::user::{validate_user_entry, FieldError, RESERVED_SERVER_NAMES};
use serde_json::json;

fn fields(errs: &[FieldError]) -> Vec<&str> {
    errs.iter().map(|e| e.field.as_str()).collect()
}

#[test]
fn a_valid_stdio_entry_becomes_a_server_config() {
    let cfg = validate_user_entry(&json!({
        "name": "notes",
        "transport": "stdio",
        "command": "/opt/notes/bin/notes-mcp",
        "args": ["--root", "/Users/me/notes"],
        "env": {"NOTES_TOKEN": "abc123"},
    }))
    .expect("valid");
    assert_eq!(cfg.name, "notes");
    assert!(
        !cfg.allow_write_tools,
        "write tools are off unless asked for"
    );
    match cfg.transport {
        TransportConfig::Stdio {
            command,
            args,
            env,
            cwd,
        } => {
            assert_eq!(command.to_string_lossy(), "/opt/notes/bin/notes-mcp");
            assert_eq!(args.len(), 2);
            assert_eq!(env.get("NOTES_TOKEN").map(String::as_str), Some("abc123"));
            assert!(cwd.is_none());
        }
        other => panic!("expected stdio, got {other:?}"),
    }
}

#[test]
fn a_valid_http_entry_becomes_a_server_config() {
    let cfg = validate_user_entry(&json!({
        "name": "scan2",
        "transport": "http",
        "url": "https://scan.example/api/mcp",
        "allow_write_tools": true,
    }))
    .expect("valid");
    assert!(cfg.allow_write_tools);
    assert!(matches!(cfg.transport, TransportConfig::Http { .. }));
}

#[test]
fn every_problem_is_reported_against_its_field() {
    let errs = validate_user_entry(&json!({
        "name": "Bad Name",
        "transport": "stdio",
        "command": "notes-mcp",
        "env": {"1BAD": "x", "OK": "${HOME}/x"},
    }))
    .expect_err("invalid");
    let f = fields(&errs);
    assert!(f.contains(&"name"), "{errs:?}");
    assert!(f.contains(&"command"), "{errs:?}");
    assert!(f.contains(&"env.1BAD"), "{errs:?}");
    assert!(f.contains(&"env.OK"), "{errs:?}");
}

#[test]
fn env_values_must_be_explicit_not_references_to_the_sidecar_environment() {
    for v in [
        "$HF_TOKEN",
        "${AWS_SECRET_ACCESS_KEY}",
        "%APPDATA%",
        "prefix-${X}",
    ] {
        let errs = validate_user_entry(&json!({
            "name": "a", "transport": "stdio", "command": "/bin/a", "env": {"TOKEN": v},
        }))
        .expect_err(v);
        assert_eq!(fields(&errs), vec!["env.TOKEN"], "{v}: {errs:?}");
        assert!(errs[0].message.contains("literally"), "{}", errs[0].message);
    }
    // A plain value that merely contains a dollar sign later on is fine (passwords do).
    assert!(validate_user_entry(&json!({
        "name": "a", "transport": "stdio", "command": "/bin/a", "env": {"PASS": "pa$$word"},
    }))
    .is_ok());
}

#[test]
fn env_keys_that_change_which_code_runs_are_refused() {
    for k in [
        "LD_PRELOAD",
        "LD_LIBRARY_PATH",
        "DYLD_INSERT_LIBRARIES",
        "NODE_OPTIONS",
        "BASH_ENV",
        "PYTHONSTARTUP",
    ] {
        let errs = validate_user_entry(&json!({
            "name": "a", "transport": "stdio", "command": "/bin/a", "env": {k: "x"},
        }))
        .expect_err(k);
        assert_eq!(fields(&errs), vec![format!("env.{k}").as_str()], "{errs:?}");
    }
}

#[test]
fn reserved_names_are_refused_for_user_servers() {
    assert!(!RESERVED_SERVER_NAMES.is_empty());
    for n in RESERVED_SERVER_NAMES {
        let errs =
            validate_user_entry(&json!({"name": n, "transport": "http", "url": "https://x/mcp"}))
                .expect_err(n);
        assert_eq!(fields(&errs), vec!["name"], "{errs:?}");
    }
}

#[test]
fn transport_fields_are_checked() {
    let cases = [
        (
            json!({"name": "a", "transport": "http", "url": "http://10.0.0.1/mcp"}),
            "url",
        ),
        (json!({"name": "a", "transport": "http"}), "url"),
        (
            json!({"name": "a", "transport": "http", "url": "https://x", "command": "/bin/a"}),
            "command",
        ),
        (
            json!({"name": "a", "transport": "stdio", "command": "/bin/a", "url": "https://x"}),
            "url",
        ),
        (json!({"name": "a", "transport": "stdio"}), "command"),
        (
            json!({"name": "a", "transport": "stdio", "command": "/bin/a", "cwd": "rel"}),
            "cwd",
        ),
        (
            json!({"name": "a", "transport": "sse", "url": "https://x"}),
            "transport",
        ),
        (
            json!({"name": "a", "transport": "stdio", "command": "/bin/a", "args": ["ok", "nul\u{0}"]}),
            "args",
        ),
        (
            json!({"name": "a", "transport": "http", "url": "https://x", "typo_field": 1}),
            "entry",
        ),
        (json!("not an object"), "entry"),
    ];
    for (entry, field) in cases {
        let errs = validate_user_entry(&entry).expect_err(&entry.to_string());
        assert!(fields(&errs).contains(&field), "{entry}: {errs:?}");
    }
}

#[test]
fn limits_are_enforced() {
    let many_args: Vec<String> = (0..65).map(|i| i.to_string()).collect();
    let errs = validate_user_entry(
        &json!({"name": "a", "transport": "stdio", "command": "/bin/a", "args": many_args}),
    )
    .expect_err("too many args");
    assert!(fields(&errs).contains(&"args"), "{errs:?}");
    let long = "x".repeat(8193);
    let errs = validate_user_entry(
        &json!({"name": "a", "transport": "stdio", "command": "/bin/a", "env": {"K": long}}),
    )
    .expect_err("long value");
    assert!(fields(&errs).contains(&"env.K"), "{errs:?}");
}

#[test]
fn field_errors_never_echo_env_values() {
    let errs = validate_user_entry(&json!({
        "name": "a", "transport": "stdio", "command": "/bin/a", "env": {"TOKEN": "${sekrit-value}"},
    }))
    .expect_err("invalid");
    let all = format!("{errs:?}");
    assert!(!all.contains("sekrit"), "{all}");
}

#[test]
fn base_env_inheritance_is_unchanged_and_carries_no_secrets() {
    // Inherited variables are only the process basics; a user server's credentials come from its
    // explicit env table, never from the sidecar's environment.
    for k in BASE_ENV_ALLOWLIST {
        let up = k.to_ascii_uppercase();
        assert!(
            !up.contains("TOKEN") && !up.contains("KEY") && !up.contains("SECRET"),
            "{k}"
        );
    }
}
