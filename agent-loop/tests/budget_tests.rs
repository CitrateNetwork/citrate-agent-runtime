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
        ..Default::default()
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
        ..Default::default()
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

// ---------------------------------------------------------------------------------------------
// US-1.4 AC1: budgets counted with the model's tokenizer (HUP-S1.2)
// ---------------------------------------------------------------------------------------------

use citrate_agent_loop::retrieval::{ModelTokenCounter, TokenCounting, Tokenizer};

/// `/tokenize` answers recorded from the bundled llama-server with the T0 model
/// (`tests/fixtures/tokenize_gemma4_e4b_t0.json`).
const RECORDED: &str = include_str!("fixtures/tokenize_gemma4_e4b_t0.json");

/// The recorded tokenizer: answers exactly what llama-server answered for the recorded texts and
/// refuses any other text (so a test can never pass on a made-up count).
struct Recorded(Vec<(String, usize)>);
impl Recorded {
    fn load() -> Self {
        let v: serde_json::Value = serde_json::from_str(RECORDED).unwrap();
        Recorded(
            v["cases"]
                .as_array()
                .unwrap()
                .iter()
                .map(|c| {
                    (
                        c["content"].as_str().unwrap().to_string(),
                        c["response"]["tokens"].as_array().unwrap().len(),
                    )
                })
                .collect(),
        )
    }
    fn text(&self, i: usize) -> &str {
        &self.0[i].0
    }
}
impl Tokenizer for Recorded {
    fn token_count(&self, text: &str) -> Result<usize, String> {
        self.0
            .iter()
            .find(|(t, _)| t == text)
            .map(|(_, n)| *n)
            .ok_or_else(|| "not a recorded text".into())
    }
}

#[test]
fn the_model_counter_reports_the_recorded_tokenize_counts() {
    let rec = Recorded::load();
    let expected: Vec<usize> = rec.0.iter().map(|(_, n)| *n).collect();
    let texts: Vec<String> = rec.0.iter().map(|(t, _)| t.clone()).collect();
    let counter = ModelTokenCounter::new(std::sync::Arc::new(rec));
    assert_eq!(counter.mode(), TokenCounting::Unprobed);
    let got: Vec<usize> = texts.iter().map(|t| counter.count(t)).collect();
    assert_eq!(got, expected);
    assert_eq!(counter.mode(), TokenCounting::Model);
    // The recorded texts show why the estimate is not enough: non-ASCII text runs over it.
    let est = CharTokenCounter.count(&texts[5]);
    assert!(
        expected[5] > est,
        "{} tokens vs {est} estimated",
        expected[5]
    );
}

#[test]
fn compaction_measured_by_the_model_tokenizer_catches_what_the_estimate_misses() {
    let rec = Recorded::load();
    let msgs = vec![
        Message::system(rec.text(1)),
        Message::user(rec.text(0)),
        Message::user(rec.text(5)),
    ];
    let model_total: usize = [1usize, 0, 5].iter().map(|i| rec.0[*i].1 + 4).sum();
    let est_total = CharTokenCounter.count_messages(&msgs);
    assert!(est_total < model_total, "{est_total} vs {model_total}");
    // A limit between the two: the estimate says it fits, the tokenizer says it does not.
    let budget = ContextBudget {
        max_context_tokens: est_total + 10,
        reserve_for_output: 10,
    };
    let by_estimate = compact_to_budget(&msgs, &budget, &CharTokenCounter).unwrap();
    assert_eq!(by_estimate.len(), 3, "the estimate sees no need to compact");
    let counter = ModelTokenCounter::new(std::sync::Arc::new(rec));
    let by_model = compact_to_budget(&msgs, &budget, &counter).expect("fits after compaction");
    assert_eq!(counter.count_messages(&msgs), model_total);
    assert_eq!(by_model.len(), 2, "the oldest exchange is dropped");
    assert_eq!(by_model[0].role, Role::System);
    assert_eq!(by_model[1].content, msgs[2].content);
    assert!(counter.count_messages(&by_model) <= est_total);
    assert_eq!(counter.mode(), TokenCounting::Model);
}

#[test]
fn a_turn_counts_its_prompt_with_the_model_tokenizer_and_reports_an_estimate_when_it_cannot() {
    // The loop also counts the offered tool schemas; this tokenizer only knows the recorded
    // texts, so the turn falls back to the estimate and the counter says why.
    let rec = Recorded::load();
    let counter = std::sync::Arc::new(ModelTokenCounter::new(std::sync::Arc::new(rec)));
    let llm = Recorder(Mutex::new(vec![]));
    let cfg = LoopConfig {
        model: "m".into(),
        system_prompt: "s".into(),
        max_steps: 1,
        max_tool_calls_per_step: 1,
        max_tokens: 64,
    };
    let opts = TurnOptions {
        budget: Some((
            ContextBudget {
                max_context_tokens: 4096,
                reserve_for_output: 64,
            },
            counter.clone(),
        )),
        ..Default::default()
    };
    run_turn_with(
        &cfg,
        &opts,
        &llm,
        &ToolRegistry::new(vec![]),
        &Null,
        &StopFlag::default(),
        &mut vec![],
        "hi",
    );
    assert!(
        matches!(counter.mode(), TokenCounting::Estimated { ref reason } if reason.contains("recorded")),
        "{:?}",
        counter.mode()
    );
}

/// Live check against a local llama-server (the bundled one with the T0 model):
/// `CITRATE_TEST_LLAMA_URL=http://127.0.0.1:18391 cargo test -p citrate-agent-loop --test
/// budget_tests -- --ignored`. It must count every recorded text exactly as recorded.
#[test]
#[ignore = "needs a local llama-server; set CITRATE_TEST_LLAMA_URL"]
fn live_llama_server_tokenize_matches_the_recording() {
    use std::io::{Read, Write};
    struct Live(String);
    impl Tokenizer for Live {
        fn token_count(&self, text: &str) -> Result<usize, String> {
            let addr = self.0.trim_start_matches("http://").trim_end_matches('/');
            let body = serde_json::json!({"content": text, "add_special": false}).to_string();
            let mut s = std::net::TcpStream::connect(addr).map_err(|e| e.to_string())?;
            write!(
                s,
                "POST /tokenize HTTP/1.1\r\nHost: {addr}\r\nContent-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{body}",
                body.len()
            )
            .map_err(|e| e.to_string())?;
            let mut out = String::new();
            s.read_to_string(&mut out).map_err(|e| e.to_string())?;
            let status = out.lines().next().unwrap_or("");
            if !status.contains(" 200 ") {
                return Err(format!("llama-server answered {status}"));
            }
            let json = out.split("\r\n\r\n").nth(1).ok_or("no body")?;
            let v: serde_json::Value = serde_json::from_str(json).map_err(|e| e.to_string())?;
            Ok(v["tokens"].as_array().ok_or("no tokens")?.len())
        }
    }
    let url = std::env::var("CITRATE_TEST_LLAMA_URL").expect("CITRATE_TEST_LLAMA_URL");
    let rec = Recorded::load();
    let counter = ModelTokenCounter::new(std::sync::Arc::new(Live(url)));
    for (text, n) in &rec.0 {
        let got = counter.count(text);
        assert_eq!(
            counter.mode(),
            TokenCounting::Model,
            "the live tokenizer answered"
        );
        assert_eq!(got, *n, "{text}");
    }
    assert_eq!(counter.mode(), TokenCounting::Model);
}
