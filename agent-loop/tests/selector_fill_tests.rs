//! HUP-S1.9 (live parity finding): retrieval offers the top K tools, not only the lexical matches.
//!
//! The live parity run on a real local model found that "Please remember that my validator is
//! named alpha." reached the model with two tools on offer (`skill_write`, `journal_read`), so it
//! could only describe the memory write instead of proposing it; the TypeScript loop offers every
//! tool. With `max_tools_per_request = K`, the request now carries the K best-scoring tools: the
//! matches first, then the rest of the catalog in its order, so a query that matches few tools still
//! sees K of them.
use citrate_agent_loop::*;
use std::sync::{Arc, Mutex};

fn spec(name: &str, desc: &str) -> ToolSpec {
    ToolSpec {
        name: name.into(),
        description: desc.into(),
        parameters: serde_json::json!({"type":"object"}),
        host: HostKind::Core,
        annotations: Default::default(),
    }
}

/// The head of citrate-core's chat tool catalog, in its order, with its descriptions shortened.
fn app_catalog() -> Vec<ToolSpec> {
    vec![
        spec("memory_search", "Semantic search over the member's memory graph, including preloaded Citrate documentation."),
        spec("memory_recall", "Recall the most recent nodes from a memory tenant (no query)."),
        spec("app_navigate", "Move the member to an app surface when it helps them act."),
        spec("memory_assert", "Propose remembering a fact in the member's personal memory. This is a WRITE."),
        spec("journal_append", "Propose appending an entry to the member's local daily journal. A WRITE."),
        spec("journal_read", "Read the member's local journal (daily notes + named pages)."),
        spec("node_status", "Read the member's node: sync state, block height, peer count, and whether it is validating."),
        spec("staking_status", "Read the member's real position: staked SALT, liquid balance, claimable rewards."),
        spec("groups_list", "List the groups the member belongs to (id + name)."),
        spec("group_roster", "Read a group's roster (member addresses + roles)."),
        spec("skills_list", "List available skills."),
        spec("skill_write", "Author (or update) a reusable local instruction-skill on this device: a named markdown playbook."),
    ]
}

#[test]
fn a_query_that_matches_few_tools_still_gets_k_matches_first_then_catalog_order() {
    let picked = KeywordSelector.select("how many peers", &app_catalog(), 4);
    let names: Vec<&str> = picked.iter().map(|t| t.name.as_str()).collect();
    assert_eq!(names.len(), 4, "K slots are filled: {names:?}");
    assert_eq!(names[0], "node_status", "the match comes first");
    assert_eq!(
        &names[1..],
        &["memory_search", "memory_recall", "app_navigate"],
        "then the catalog in its order"
    );
}

#[test]
fn selection_never_exceeds_k_or_the_catalog() {
    let cat = app_catalog();
    assert_eq!(KeywordSelector.select("staking status", &cat, 3).len(), 3);
    assert_eq!(KeywordSelector.select("staking status", &cat, 50).len(), cat.len());
    let picked = KeywordSelector.select("staking status", &cat, 50);
    let mut names: Vec<&str> = picked.iter().map(|t| t.name.as_str()).collect();
    names.sort_unstable();
    names.dedup();
    assert_eq!(names.len(), cat.len(), "no tool is offered twice");
}

struct Recorder(Mutex<Vec<CompletionRequest>>);
impl LlmClient for Recorder {
    fn complete(&self, req: &CompletionRequest) -> Result<AssistantTurn, LlmError> {
        self.0.lock().map_err(|_| LlmError::Provider("poisoned".into()))?.push(req.clone());
        Ok(AssistantTurn::text("ok"))
    }
}
struct Null;
impl EventSink for Null {
    fn emit(&self, _e: Event) {}
}
struct Ok1;
impl ToolHost for Ok1 {
    fn execute(&self, _c: &ToolCall) -> ToolOutcome {
        ToolOutcome::Ok("ok".into())
    }
}

#[test]
fn the_remember_ask_from_the_live_run_is_offered_the_memory_write() {
    let llm = Recorder(Mutex::new(vec![]));
    let tools = ToolRegistry::new(app_catalog()).with_host(HostKind::Core, Arc::new(Ok1));
    let cfg = LoopConfig {
        model: "m".into(),
        system_prompt: "s".into(),
        max_steps: 2,
        max_tool_calls_per_step: 4,
        max_tokens: 64,
    };
    let opts = TurnOptions {
        max_tools_per_request: Some(8),
        budget: None,
        ..Default::default()
    };
    run_turn_with(
        &cfg,
        &opts,
        &llm,
        &tools,
        &Null,
        &StopFlag::default(),
        &mut vec![],
        "Please remember that my validator is named alpha.",
    );
    let seen = llm.0.lock().unwrap();
    let offered: Vec<&str> = seen[0].tools.iter().map(|t| t.name.as_str()).collect();
    assert_eq!(offered.len(), 8, "{offered:?}");
    assert!(offered.contains(&"memory_assert"), "{offered:?}");
}
