//! HUP-S1.2 — only relevant tools are offered, and the prompt stays within the model's context.
use citrate_agent_loop::*;
use std::sync::Mutex;

fn spec(name: &str, desc: &str) -> ToolSpec {
    ToolSpec {
        name: name.into(),
        description: desc.into(),
        parameters: serde_json::json!({"type":"object"}),
        host: HostKind::Core,
        annotations: Default::default(),
    }
}

fn catalog() -> Vec<ToolSpec> {
    vec![
        spec(
            "node_status",
            "Read the local node's block height, peers and sync state.",
        ),
        spec(
            "staking_status",
            "Read staked SALT, validator bond and claimable rewards.",
        ),
        spec(
            "memory_search",
            "Semantic search over the member's memory graph and Citrate docs.",
        ),
        spec(
            "group_invite",
            "Mint a one-click invite link for an encrypted group.",
        ),
        spec("group_create", "Create an encrypted group or channel."),
        spec(
            "contract_deploy",
            "Propose deploying compiled contract bytecode through the signing ceremony.",
        ),
        spec("journal_append", "Append an entry to today's journal page."),
        spec("models_list", "List local and registry models."),
        spec("skills_list", "List installed and on-chain skills."),
        spec(
            "directory_find",
            "Find a member by their X or Discord handle.",
        ),
    ]
}

#[test]
fn keyword_selection_picks_the_relevant_tools() {
    let sel = KeywordSelector;
    let picked = sel.select("what's my block height and how many peers?", &catalog(), 3);
    assert!(picked.len() <= 3);
    assert_eq!(picked[0].name, "node_status");
    let picked = sel.select("invite alice to my group", &catalog(), 3);
    assert!(picked.iter().any(|t| t.name == "group_invite"));
    let picked = sel.select("deploy my NFT contract", &catalog(), 2);
    assert_eq!(picked[0].name, "contract_deploy");
}

#[test]
fn selection_matches_snake_case_parts_and_is_deterministic() {
    let sel = KeywordSelector;
    let a = sel.select("staking status", &catalog(), 3);
    let b = sel.select("staking status", &catalog(), 3);
    assert_eq!(a, b);
    assert_eq!(a[0].name, "staking_status");
}

#[test]
fn a_query_with_no_signal_still_gets_a_bounded_fallback() {
    let sel = KeywordSelector;
    let picked = sel.select("hi", &catalog(), 4);
    assert_eq!(
        picked.len(),
        4,
        "falls back to the first k in catalog order"
    );
}

struct Recorder(Mutex<Vec<CompletionRequest>>);
impl LlmClient for Recorder {
    fn complete(&self, req: &CompletionRequest) -> Result<AssistantTurn, LlmError> {
        let mut seen = self.0.lock().unwrap();
        seen.push(req.clone());
        if seen.len() == 1 {
            Ok(AssistantTurn::tools(vec![ToolCall {
                id: "c1".into(),
                name: "journal_append".into(),
                arguments: "{}".into(),
            }]))
        } else {
            Ok(AssistantTurn::text("done"))
        }
    }
}
struct Ok1;
impl ToolHost for Ok1 {
    fn execute(&self, _c: &ToolCall) -> ToolOutcome {
        ToolOutcome::Ok("ok".into())
    }
}
struct Null;
impl EventSink for Null {
    fn emit(&self, _e: Event) {}
}

#[test]
fn the_loop_offers_at_most_k_tools_and_keeps_tools_already_in_use() {
    let llm = Recorder(Mutex::new(vec![]));
    let tools = ToolRegistry::new(catalog()).with_host(HostKind::Core, std::sync::Arc::new(Ok1));
    let mut cfg = LoopConfig {
        model: "m".into(),
        system_prompt: "s".into(),
        max_steps: 4,
        max_tool_calls_per_step: 4,
        max_tokens: 64,
    };
    let opts = TurnOptions {
        max_tools_per_request: Some(3),
        budget: None,
    };
    let _ = &mut cfg;
    run_turn_with(
        &cfg,
        &opts,
        &llm,
        &tools,
        &Null,
        &StopFlag::default(),
        &mut vec![],
        "write in my journal that the node synced",
    );
    let seen = llm.0.lock().unwrap();
    assert!(seen[0].tools.len() <= 3);
    assert!(seen[0].tools.iter().any(|t| t.name == "journal_append"));
    assert!(
        seen[1].tools.iter().any(|t| t.name == "journal_append"),
        "a tool used earlier in the turn stays on offer"
    );
}

#[test]
fn compaction_elides_old_tool_output_first_and_keeps_system_and_latest_user() {
    let mut msgs = vec![Message::system("SYSTEM"), Message::user("old question")];
    msgs.push(Message {
        role: Role::Assistant,
        content: String::new(),
        tool_calls: vec![ToolCall {
            id: "c1".into(),
            name: "x".into(),
            arguments: "{}".into(),
        }],
        tool_call_id: None,
    });
    msgs.push(Message::tool_result("c1", "X".repeat(4000)));
    msgs.push(Message::user("latest question"));
    let budget = ContextBudget {
        max_context_tokens: 400,
        reserve_for_output: 100,
    };
    let counter = CharTokenCounter;
    let before = counter.count_messages(&msgs);
    let out = compact_to_budget(&msgs, &budget, &counter).expect("fits after compaction");
    assert!(
        counter.count_messages(&out) < before,
        "compaction must shrink"
    );
    assert!(counter.count_messages(&out) + budget.reserve_for_output <= budget.max_context_tokens);
    assert_eq!(out[0].content, "SYSTEM");
    assert_eq!(out.last().unwrap().content, "latest question");
    let tool = out
        .iter()
        .find(|m| m.role == Role::Tool)
        .expect("tool message kept for transcript validity");
    assert!(
        tool.content.starts_with("[elided"),
        "old tool output is elided, not dropped"
    );
}

#[test]
fn compaction_that_cannot_fit_fails_honestly() {
    let msgs = vec![
        Message::system("S".repeat(2000)),
        Message::user("U".repeat(2000)),
    ];
    let budget = ContextBudget {
        max_context_tokens: 300,
        reserve_for_output: 100,
    };
    let err = compact_to_budget(&msgs, &budget, &CharTokenCounter).unwrap_err();
    assert!(err.contains("context"), "{err}");
}

#[test]
fn a_turn_whose_prompt_cannot_fit_fails_instead_of_overflowing() {
    let llm = Recorder(Mutex::new(vec![]));
    let cfg = LoopConfig {
        model: "m".into(),
        system_prompt: "S".repeat(4000),
        max_steps: 2,
        max_tool_calls_per_step: 1,
        max_tokens: 64,
    };
    let opts = TurnOptions {
        max_tools_per_request: None,
        budget: Some((
            ContextBudget {
                max_context_tokens: 200,
                reserve_for_output: 64,
            },
            std::sync::Arc::new(CharTokenCounter),
        )),
    };
    let out = run_turn_with(
        &cfg,
        &opts,
        &llm,
        &ToolRegistry::new(vec![]),
        &Null,
        &StopFlag::default(),
        &mut vec![],
        "hi",
    );
    assert!(matches!(out, RunOutcome::Failed(ref m) if m.contains("context")));
    assert!(
        llm.0.lock().unwrap().is_empty(),
        "the model is never called with an over-budget prompt"
    );
}
