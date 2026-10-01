//! HUP-S4.4: the dry-run probe initializes a server and lists its tools for the review screen
//! without registering anything, then stops the server.

use citrate_agent_mcp_host::config::{ServerConfig, TransportConfig};
use citrate_agent_mcp_host::probe::{probe, probe_with_deadline, ProbeReport, PROBE_TIMEOUT};
use std::collections::BTreeMap;
use std::time::{Duration, Instant};

const FIXTURE: &str = env!("CARGO_BIN_EXE_citrate-mcp-fixture-server");

fn server(args: &[&str], allow_write: bool) -> ServerConfig {
    let mut cfg = ServerConfig::new(
        "fx",
        TransportConfig::Stdio {
            command: FIXTURE.into(),
            args: args.iter().map(|s| s.to_string()).collect(),
            env: BTreeMap::new(),
            cwd: None,
        },
    );
    cfg.allow_write_tools = allow_write;
    cfg
}

fn tool<'a>(r: &'a ProbeReport, name: &str) -> &'a citrate_agent_mcp_host::probe::ProbedTool {
    r.tools
        .iter()
        .find(|t| t.name == name)
        .unwrap_or_else(|| panic!("{name} in {:?}", r.tools))
}

#[test]
fn probe_lists_every_tool_with_annotations_and_offer_decision() {
    let r = probe(&server(&["--paged"], false));
    assert!(r.ok, "{:?}", r.error);
    assert_eq!(r.protocol_version.as_deref(), Some("2025-06-18"));
    assert_eq!(r.server_name.as_deref(), Some("citrate-mcp-fixture"));
    // Both pages are listed.
    assert!(r.tools.len() >= 10, "{}", r.tools.len());
    let echo = tool(&r, "echo");
    assert_eq!(echo.annotations.read_only_hint, Some(true));
    assert_eq!(echo.annotations.open_world_hint, Some(false));
    assert!(echo.effective.read_only && !echo.effective.open_world);
    assert!(echo.offered);
    assert_eq!(echo.exposed_name.as_deref(), Some("mcp__fx__echo"));
    // A write tool is listed but not offered while write tools are off, with the reason.
    let w = tool(&r, "write_note");
    assert_eq!(w.annotations.destructive_hint, Some(true));
    assert!(w.effective.destructive);
    assert!(!w.offered);
    assert!(
        w.skip_reason.as_deref().unwrap_or("").contains("read-only"),
        "{:?}",
        w.skip_reason
    );
    // No annotations: the hints are absent and the spec defaults apply.
    let plain = tool(&r, "plain");
    assert_eq!(plain.annotations.read_only_hint, None);
    assert!(plain.effective.destructive && plain.effective.open_world);
    // Every MCP tool is untrusted, whatever it claims.
    assert!(r.tools.iter().all(|t| t.trust == "untrusted"));
}

#[test]
fn probe_with_write_tools_allowed_offers_them() {
    let r = probe(&server(&[], true));
    assert!(r.ok, "{:?}", r.error);
    assert!(tool(&r, "write_note").offered);
}

#[test]
fn probe_reports_a_failure_instead_of_erroring() {
    let mut cfg = server(&[], false);
    cfg.transport = TransportConfig::Stdio {
        command: "/nonexistent/citrate/mcp-server".into(),
        args: vec![],
        env: BTreeMap::new(),
        cwd: None,
    };
    let r = probe(&cfg);
    assert!(!r.ok);
    assert!(r.error.is_some());
    assert!(r.tools.is_empty());
    let r = probe(&server(&["--version", "1999-01-01"], false));
    assert!(!r.ok);
    assert!(
        r.error.as_deref().unwrap_or("").contains("unsupported"),
        "{:?}",
        r.error
    );
}

#[test]
fn probe_is_bounded_by_its_own_deadline_not_the_entry_s() {
    // A loopback HTTP endpoint that accepts and never answers.
    let listener = std::net::TcpListener::bind("127.0.0.1:0").expect("bind");
    let addr = listener.local_addr().expect("addr");
    let _hold = std::thread::spawn(move || {
        let mut held = Vec::new();
        for s in listener.incoming().flatten() {
            held.push(s);
        }
    });
    let mut cfg = ServerConfig::new(
        "stall",
        TransportConfig::Http {
            url: format!("http://{addr}/mcp"),
        },
    );
    cfg.init_timeout = Duration::from_secs(600);
    let started = Instant::now();
    let r = probe_with_deadline(&cfg, Duration::from_millis(500));
    assert!(!r.ok);
    assert!(
        started.elapsed() < Duration::from_secs(5),
        "{:?}",
        started.elapsed()
    );
    assert!(PROBE_TIMEOUT <= Duration::from_secs(30));
}

#[test]
fn the_report_serializes_camel_case_and_never_carries_env_or_instructions() {
    let mut cfg = server(&[], false);
    if let TransportConfig::Stdio { env, .. } = &mut cfg.transport {
        env.insert("SEKRIT_TOKEN".into(), "sekrit-value".into());
    }
    let r = probe(&cfg);
    let s = serde_json::to_string(&r).expect("json");
    assert!(s.contains("\"protocolVersion\""), "{s}");
    assert!(s.contains("\"readOnlyHint\""), "{s}");
    assert!(s.contains("\"exposedName\""), "{s}");
    assert!(!s.contains("sekrit"), "{s}");
    assert!(!s.contains("instructions"), "{s}");
}
