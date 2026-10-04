//! HUP-S4.1 manual demo (ignored by default): Hermes's MCP host loads the allowlist citrate-core
//! writes for its built-in `node` entry and talks to the real citrate-node MCP server through the
//! stdio shim. Run citrate-core's `hermes_node_entry_demo` first (it writes the allowlist and
//! serves), then:
//!
//! ```sh
//! CITRATE_HERMES_MCP=<allowlist> cargo test -p citrate-agent-mcp-host --test node_demo -- --ignored --nocapture
//! ```

use citrate_agent_loop::{StopFlag, ToolCall, ToolOutcome};
use citrate_agent_mcp_host::config::{McpConfig, MCP_CONFIG_ENV};
use citrate_agent_mcp_host::McpHost;

fn show(o: &ToolOutcome) -> String {
    match o {
        ToolOutcome::Ok(s) => format!("ok: {s}"),
        ToolOutcome::Untrusted(s) => format!("untrusted: {s}"),
        ToolOutcome::Denied(s) => format!("denied: {s}"),
        ToolOutcome::Error(s) => format!("error: {s}"),
    }
}

#[test]
#[ignore = "manual demo: needs citrate-core's hermes_node_entry_demo serving"]
fn hermes_lists_node_tools_and_a_tx_propose_lands_as_a_pending_approval() {
    let path = std::env::var(MCP_CONFIG_ENV).expect("CITRATE_HERMES_MCP");
    let cfg = McpConfig::load(std::path::Path::new(&path)).expect("allowlist");
    let host = McpHost::connect(&cfg);
    for s in host.status() {
        println!(
            "server {} ({}): {:?}, protocol {:?}, era {:?}, {} tools offered, skipped {:?}, error {:?}",
            s.name, s.transport, s.state, s.protocol_version, s.era, s.tools, s.skipped, s.error
        );
    }
    let names: Vec<String> = host.specs().into_iter().map(|s| s.name).collect();
    println!("tools Hermes is offered: {names:?}");
    assert!(names.contains(&"mcp__node__chain_head".to_string()));
    assert!(names.contains(&"mcp__node__tx_propose".to_string()));
    let call = |id: &str, name: &str, args: &str| {
        let out = host.call(
            &ToolCall {
                id: id.into(),
                name: name.into(),
                arguments: args.into(),
            },
            &StopFlag::default(),
        );
        println!(">>> {name} {args}\n<<< {}\n", show(&out));
        out
    };
    let head = call("c1", "mcp__node__chain_head", "{}");
    assert!(matches!(head, ToolOutcome::Untrusted(_)));
    let tx = call(
        "c2",
        "mcp__node__tx_propose",
        r#"{"to":"0x52908400098527886E0F7030069857D2E4169EE7","value_wei":"1"}"#,
    );
    match &tx {
        ToolOutcome::Untrusted(t) => assert!(t.contains("pending"), "{t}"),
        other => panic!("{other:?}"),
    }
}
