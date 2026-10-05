//! HUP-S1.2 / US-1.4 AC1 / US-3.2 AC1 — the model-tokenizer counter, the hybrid (embedding plus
//! lexical) retriever for tools and skills, and the per-request tool ceiling.
use citrate_agent_loop::retrieval::*;
use citrate_agent_loop::skills::{Bm25Ranker, SkillRanker, SkillTurnIndex};
use citrate_agent_loop::*;
use std::sync::atomic::{AtomicUsize, Ordering};
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

// ---- Token counting ---------------------------------------------------------------------------

/// Counts words as tokens and records how often it was asked.
struct Words(AtomicUsize);
impl Tokenizer for Words {
    fn token_count(&self, text: &str) -> Result<usize, String> {
        self.0.fetch_add(1, Ordering::SeqCst);
        Ok(text.split_whitespace().count())
    }
}

/// Fails the first `n` calls, then answers like [`Words`].
struct FailsFirst(AtomicUsize, usize);
impl Tokenizer for FailsFirst {
    fn token_count(&self, text: &str) -> Result<usize, String> {
        let i = self.0.fetch_add(1, Ordering::SeqCst);
        if i < self.1 {
            Err("the model's tokenizer did not answer (could not connect)".into())
        } else {
            Ok(text.split_whitespace().count())
        }
    }
}

#[test]
fn counts_are_cached_so_the_tokenizer_is_asked_once_per_text() {
    let backend = Arc::new(Words(AtomicUsize::new(0)));
    let c = ModelTokenCounter::new(backend.clone());
    assert_eq!(c.count("one two three"), 3);
    assert_eq!(c.count("one two three"), 3);
    assert_eq!(c.count(""), 0, "empty text costs nothing and asks nobody");
    assert_eq!(backend.0.load(Ordering::SeqCst), 1);
    assert_eq!(c.mode(), TokenCounting::Model);
}

#[test]
fn a_failed_tokenizer_falls_back_to_the_estimate_for_the_rest_of_the_session() {
    let backend = Arc::new(FailsFirst(AtomicUsize::new(0), 1));
    let c = ModelTokenCounter::new(backend.clone());
    let text = "a sentence of seven words right here";
    assert_eq!(c.count(text), CharTokenCounter.count(text));
    match c.mode() {
        TokenCounting::Estimated { reason } => assert!(reason.contains("could not connect")),
        other => panic!("expected an estimate, got {other:?}"),
    }
    // The tokenizer would answer now, but counts within one session never mix methods.
    assert_eq!(
        c.count("another text"),
        CharTokenCounter.count("another text")
    );
    assert_eq!(backend.0.load(Ordering::SeqCst), 1, "never asked again");
}

#[test]
fn a_counter_without_a_tokenizer_says_it_estimates_and_why() {
    let c = ModelTokenCounter::estimated("the model endpoint is not the local llama-server");
    assert_eq!(c.count("abcdefgh"), 2);
    assert_eq!(
        serde_json::to_value(c.mode()).unwrap(),
        serde_json::json!({"mode": "estimated", "reason": "the model endpoint is not the local llama-server"})
    );
    assert_eq!(
        serde_json::to_value(TokenCounting::Model).unwrap(),
        serde_json::json!({"mode": "model"})
    );
}

#[test]
fn probing_settles_the_mode_before_any_turn() {
    let c = ModelTokenCounter::new(Arc::new(Words(AtomicUsize::new(0))));
    assert_eq!(c.probe(), TokenCounting::Model);
    let c = ModelTokenCounter::new(Arc::new(FailsFirst(AtomicUsize::new(0), 99)));
    assert!(matches!(c.probe(), TokenCounting::Estimated { .. }));
}

// ---- Hybrid retrieval -------------------------------------------------------------------------

/// A deterministic concept embedder: each text becomes a vector over a few concepts, counted from
/// the words that express them (synonyms included). It stands in for BGE so the ranking math is
/// testable offline; the HTTP embedder is tested in the sidecar.
struct Concepts {
    calls: AtomicUsize,
    texts: Mutex<usize>,
}
const CONCEPTS: &[&[&str]] = &[
    &[
        "height", "tall", "block", "sync", "synced", "peers", "node", "behind",
    ],
    &[
        "staked",
        "stake",
        "validator",
        "bond",
        "rewards",
        "earning",
        "salt",
    ],
    &["memory", "remember", "recall", "search", "docs", "notes"],
    &["invite", "group", "friend", "channel", "encrypted", "join"],
    &[
        "contract", "deploy", "bytecode", "ship", "launch", "solidity",
    ],
    &["journal", "diary", "entry", "today", "log"],
    &["audit", "security", "review", "vulnerability", "reentrancy"],
    &[
        "paraconsensus",
        "belnap",
        "four",
        "truth",
        "orders",
        "aggregate",
    ],
];
impl Concepts {
    fn new() -> Self {
        Concepts {
            calls: AtomicUsize::new(0),
            texts: Mutex::new(0),
        }
    }
}
impl Embedder for Concepts {
    fn embed(&self, texts: &[String]) -> Result<Vec<Vec<f32>>, String> {
        self.calls.fetch_add(1, Ordering::SeqCst);
        *self.texts.lock().unwrap() += texts.len();
        Ok(texts
            .iter()
            .map(|t| {
                let lower = t.to_lowercase();
                let words: Vec<&str> = lower
                    .split(|c: char| !c.is_ascii_alphanumeric())
                    .filter(|w| !w.is_empty())
                    .collect();
                let mut v: Vec<f32> = CONCEPTS
                    .iter()
                    .map(|c| words.iter().filter(|w| c.contains(w)).count() as f32)
                    .collect();
                v.push(0.01); // never the zero vector
                v
            })
            .collect())
    }
}

struct Broken;
impl Embedder for Broken {
    fn embed(&self, _: &[String]) -> Result<Vec<Vec<f32>>, String> {
        Err("the embedding endpoint did not answer (HTTP 501)".into())
    }
}

/// Answers one vector too few.
struct Short;
impl Embedder for Short {
    fn embed(&self, texts: &[String]) -> Result<Vec<Vec<f32>>, String> {
        Ok(vec![vec![1.0, 0.0]; texts.len().saturating_sub(1)])
    }
}

#[test]
fn embeddings_find_the_tool_a_paraphrase_means_when_no_keyword_matches() {
    let q = "how tall is everything, am I behind on the list?";
    let kw = KeywordSelector.select(q, &catalog(), 3);
    assert_ne!(
        kw[0].name, "node_status",
        "keywords alone miss the paraphrase"
    );
    let r = HybridRetriever::new(Arc::new(Concepts::new()));
    let picked = r.select(q, &catalog(), 3);
    assert_eq!(picked[0].name, "node_status");
    assert_eq!(r.mode(), RetrievalMode::Embedding);
}

#[test]
fn keywords_still_count_in_the_blend() {
    // "group" is a concept word for two tools; the keyword "invite" separates them.
    let r = HybridRetriever::new(Arc::new(Concepts::new()));
    let picked = r.select("invite bob to my group", &catalog(), 2);
    assert_eq!(picked[0].name, "group_invite");
}

#[test]
fn tool_embeddings_are_cached_and_only_the_query_is_embedded_again() {
    let e = Arc::new(Concepts::new());
    let r = HybridRetriever::new(e.clone());
    r.select("node height", &catalog(), 3);
    assert_eq!(*e.texts.lock().unwrap(), 1 + catalog().len());
    r.select("staking rewards", &catalog(), 3);
    assert_eq!(*e.texts.lock().unwrap(), 2 + catalog().len());
    assert_eq!(e.calls.load(Ordering::SeqCst), 2);
}

#[test]
fn a_failed_embedder_falls_back_to_exactly_the_keyword_selector() {
    let r = HybridRetriever::new(Arc::new(Broken));
    for q in ["what's my block height", "deploy my NFT contract", "hi"] {
        assert_eq!(
            r.select(q, &catalog(), 3),
            KeywordSelector.select(q, &catalog(), 3)
        );
    }
    assert_eq!(
        serde_json::to_value(r.mode()).unwrap(),
        serde_json::json!({"mode": "lexical", "reason": "the embedding endpoint did not answer (HTTP 501)"})
    );
}

#[test]
fn a_wrongly_shaped_embedding_answer_falls_back_too() {
    let r = HybridRetriever::new(Arc::new(Short));
    let q = "deploy my contract";
    assert_eq!(
        r.select(q, &catalog(), 2),
        KeywordSelector.select(q, &catalog(), 2)
    );
    assert!(matches!(r.mode(), RetrievalMode::Lexical { .. }));
}

#[test]
fn the_probe_settles_the_retrieval_mode() {
    assert_eq!(
        HybridRetriever::new(Arc::new(Concepts::new())).probe(),
        RetrievalMode::Embedding
    );
    assert!(matches!(
        HybridRetriever::new(Arc::new(Broken)).probe(),
        RetrievalMode::Lexical { .. }
    ));
    assert!(matches!(
        HybridRetriever::lexical("no embedding endpoint is configured").probe(),
        RetrievalMode::Lexical { ref reason } if reason.contains("configured")
    ));
}

#[test]
fn the_selection_never_exceeds_k() {
    let r = HybridRetriever::new(Arc::new(Concepts::new()));
    for k in 0..12 {
        assert!(r.select("node height and staking", &catalog(), k).len() <= k);
    }
}

// ---- Skills (US-3.2 AC1) ----------------------------------------------------------------------

fn skill_docs() -> Vec<(&'static str, &'static str)> {
    vec![
        (
            "citrate-paraconsensus",
            "Explain FOUR, the knowledge and truth orders, and how claims are classified.",
        ),
        (
            "citrate-belnap-aggregate",
            "Prepare 0x0110 inputs and read the states it returns.",
        ),
        (
            "solidity-audit",
            "Audit a Solidity contract for reentrancy and other vulnerabilities.",
        ),
        (
            "journal-digest",
            "Summarize the member's journal into a weekly digest.",
        ),
        ("staking-report", "Write the weekly staking report."),
        ("frontend-design", "Design a web page."),
    ]
}

#[test]
fn the_hybrid_skill_ranker_surfaces_a_paraphrase_and_drops_unrelated_skills() {
    let r = HybridRetriever::new(Arc::new(Concepts::new()));
    let docs = skill_docs();
    let q = "is the security of my code ok? check for vulnerability issues";
    assert!(
        Bm25Ranker.rank("is my code safe", &docs, 5).is_empty(),
        "BM25 needs a shared term"
    );
    let picked = r.rank(q, &docs, 5);
    assert_eq!(picked.first(), Some(&2), "solidity-audit first: {picked:?}");
    assert!(
        picked.len() < docs.len(),
        "unrelated skills stay out: {picked:?}"
    );
    assert_eq!(r.method(), "hybrid-embedding-bm25");
}

#[test]
fn the_skill_ranker_falls_back_to_bm25_when_embeddings_fail() {
    let r = HybridRetriever::new(Arc::new(Broken));
    let docs = skill_docs();
    for q in ["audit my solidity contract", "weekly report", "hello"] {
        assert_eq!(r.rank(q, &docs, 5), Bm25Ranker.rank(q, &docs, 5));
    }
    assert_eq!(r.method(), "bm25-lexical");
}

#[test]
fn the_turn_index_with_the_hybrid_ranker_still_surfaces_at_most_five() {
    let root =
        std::env::temp_dir().join(format!("citrate-retrieval-skills-{}", std::process::id()));
    let _ = std::fs::remove_dir_all(&root);
    for i in 0..12 {
        let dir = root.join(format!("node-skill-{i}"));
        std::fs::create_dir_all(&dir).unwrap();
        std::fs::write(
            dir.join("SKILL.md"),
            format!("---\nname: node-skill-{i}\ndescription: Check the node block height and peers, variant {i}.\n---\nBODY"),
        )
        .unwrap();
    }
    let lib = Arc::new(citrate_agent_loop::skills::SkillLibrary::load(&[
        citrate_agent_loop::skills::SkillSource::new("user", &root),
    ]));
    assert_eq!(lib.len(), 12);
    let idx = SkillTurnIndex::new(lib, 5)
        .with_ranker(Arc::new(HybridRetriever::new(Arc::new(Concepts::new()))));
    assert_eq!(idx.method(), "hybrid-embedding-bm25");
    let section = idx.section("is my node synced?", &[]).unwrap();
    let lines = section
        .lines()
        .filter(|l| l.starts_with("- node-skill-"))
        .count();
    assert_eq!(lines, 5, "{section}");
    let _ = std::fs::remove_dir_all(&root);
}

// ---- The per-request tool ceiling (US-1.4 AC1) ------------------------------------------------

struct Capture(Mutex<Vec<Vec<String>>>, Vec<AssistantTurn>);
impl LlmClient for Capture {
    fn complete(&self, req: &CompletionRequest) -> Result<AssistantTurn, LlmError> {
        let mut seen = self.0.lock().unwrap();
        seen.push(req.tools.iter().map(|t| t.name.clone()).collect());
        Ok(self
            .1
            .get(seen.len() - 1)
            .cloned()
            .unwrap_or_else(|| AssistantTurn::text("done")))
    }
}
struct OkHost;
impl ToolHost for OkHost {
    fn execute(&self, _c: &ToolCall) -> ToolOutcome {
        ToolOutcome::Ok("ok".into())
    }
}
struct Null;
impl EventSink for Null {
    fn emit(&self, _e: Event) {}
}

fn call(id: &str, name: &str) -> ToolCall {
    ToolCall {
        id: id.into(),
        name: name.into(),
        arguments: "{}".into(),
    }
}

fn run(opts: &TurnOptions, script: Vec<AssistantTurn>, user: &str) -> Vec<Vec<String>> {
    let llm = Capture(Mutex::new(vec![]), script);
    let tools = ToolRegistry::new(catalog()).with_host(HostKind::Core, Arc::new(OkHost));
    let cfg = LoopConfig {
        model: "m".into(),
        system_prompt: "s".into(),
        max_steps: 8,
        max_tool_calls_per_step: 8,
        max_tokens: 64,
    };
    run_turn_with(
        &cfg,
        opts,
        &llm,
        &tools,
        &Null,
        &StopFlag::default(),
        &mut vec![],
        user,
    );
    llm.0.into_inner().unwrap()
}

#[test]
fn with_a_ceiling_no_request_ever_offers_more_tools_pinned_and_in_use_included() {
    let pinned: Vec<String> = ["skills_list", "memory_search", "journal_append"]
        .iter()
        .map(|s| s.to_string())
        .collect();
    // The model uses five different tools across steps, so in-use tools alone would exceed it.
    let script = vec![
        AssistantTurn::tools(vec![call("a", "node_status"), call("b", "staking_status")]),
        AssistantTurn::tools(vec![call("c", "group_invite"), call("d", "group_create")]),
        AssistantTurn::tools(vec![call("e", "contract_deploy")]),
        AssistantTurn::text("done"),
    ];
    for total in 1..=8 {
        for k in 1..=8 {
            let opts = TurnOptions {
                max_tools_per_request: Some(k),
                max_tools_total: Some(total),
                pinned_tools: pinned.clone(),
                ..Default::default()
            };
            for (i, offered) in run(&opts, script.clone(), "node height and staking")
                .iter()
                .enumerate()
            {
                assert!(
                    offered.len() <= total,
                    "total {total}, k {k}, request {i}: {offered:?}"
                );
                // Pinned tools come first (catalog order) and are never pushed out by others.
                let want: Vec<String> = catalog()
                    .into_iter()
                    .filter(|s| pinned.contains(&s.name))
                    .map(|s| s.name)
                    .take(total)
                    .collect();
                assert_eq!(offered[..want.len()], want[..]);
            }
        }
    }
}

#[test]
fn under_the_ceiling_the_most_recently_used_tool_is_kept_first() {
    let script = vec![
        AssistantTurn::tools(vec![call("a", "node_status")]),
        AssistantTurn::tools(vec![call("b", "contract_deploy")]),
        AssistantTurn::text("done"),
    ];
    let opts = TurnOptions {
        max_tools_per_request: Some(1),
        max_tools_total: Some(1),
        ..Default::default()
    };
    let seen = run(&opts, script, "node height");
    assert_eq!(seen[0], vec!["node_status".to_string()]);
    assert_eq!(seen[2], vec!["contract_deploy".to_string()], "{seen:?}");
}

#[test]
fn without_a_ceiling_pinned_tools_ride_outside_k_as_documented() {
    let opts = TurnOptions {
        max_tools_per_request: Some(2),
        pinned_tools: vec!["skills_list".into(), "models_list".into()],
        ..Default::default()
    };
    let seen = run(&opts, vec![], "node height and staking status");
    assert_eq!(seen[0].len(), 4, "two pinned plus k=2: {:?}", seen[0]);
}

#[test]
fn the_loop_ranks_with_the_selector_it_is_given() {
    let opts = TurnOptions {
        max_tools_per_request: Some(1),
        selector: Some(Arc::new(HybridRetriever::new(Arc::new(Concepts::new())))),
        ..Default::default()
    };
    let seen = run(
        &opts,
        vec![],
        "how tall is everything, am I behind on the list?",
    );
    assert_eq!(seen[0], vec!["node_status".to_string()]);
}
