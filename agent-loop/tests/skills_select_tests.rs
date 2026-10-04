//! HUP-S3.2 US-3.2 AC1: at most five skills are surfaced per turn. The description index is ranked
//! against the turn's request (BM25 over each skill's name and description; the sidecar has no
//! embedding model in process, so lexical ranking is what runs) and only the best matches ride in
//! the system prompt. Bodies still load on demand through `skill_load`.

use citrate_agent_loop::skills::{
    Bm25Ranker, SkillLibrary, SkillRanker, SkillSource, SkillTurnIndex, SKILLS_PER_TURN,
    SKILL_LOAD_TOOL,
};
use citrate_agent_loop::{
    run_turn_with, AssistantTurn, CompletionRequest, EventSink, LlmClient, LlmError, LoopConfig,
    Message, StopFlag, ToolRegistry, TurnContext, TurnOptions,
};
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::{Arc, Mutex};

static N: AtomicUsize = AtomicUsize::new(0);

struct Scratch(PathBuf);
impl Scratch {
    fn new(tag: &str) -> Self {
        let p = std::env::temp_dir().join(format!(
            "citrate-skills-select-{tag}-{}-{}",
            std::process::id(),
            N.fetch_add(1, Ordering::SeqCst)
        ));
        let _ = std::fs::remove_dir_all(&p);
        std::fs::create_dir_all(&p).unwrap();
        Scratch(p)
    }
}
impl Drop for Scratch {
    fn drop(&mut self) {
        let _ = std::fs::remove_dir_all(&self.0);
    }
}

fn skill(root: &Path, name: &str, description: &str) {
    let dir = root.join(name);
    std::fs::create_dir_all(&dir).unwrap();
    std::fs::write(
        dir.join("SKILL.md"),
        format!("---\nname: {name}\ndescription: {description}\n---\nBODY OF {name}\n"),
    )
    .unwrap();
}

/// Twelve skills on distinct topics plus a few that share common words.
fn catalog(root: &Path) -> Arc<SkillLibrary> {
    skill(
        root,
        "staking-report",
        "Write the weekly staking report for a validator.",
    );
    skill(
        root,
        "solidity-audit",
        "Audit a Solidity contract for reentrancy and access control bugs.",
    );
    skill(
        root,
        "foundry-tests",
        "Write Foundry forge tests and fuzz tests for a contract.",
    );
    skill(
        root,
        "deploy-contract",
        "Deploy a contract to the Citrate chain and verify it.",
    );
    skill(
        root,
        "nft-mint",
        "Mint an NFT collection and pin its metadata to IPFS.",
    );
    skill(
        root,
        "frontend-polish",
        "Polish a web frontend: typography, spacing and colour.",
    );
    skill(
        root,
        "journal-digest",
        "Summarize the member's journal into a daily digest.",
    );
    skill(
        root,
        "wallet-hygiene",
        "Review wallet approvals and revoke stale allowances.",
    );
    skill(
        root,
        "lora-train",
        "Plan a LoRA fine-tuning round on the compute pool.",
    );
    skill(
        root,
        "precompile-guide",
        "Explain the model and LoRA precompiles on Citrate.",
    );
    skill(
        root,
        "semgrep-rules",
        "Write Semgrep rules for a code pattern.",
    );
    skill(
        root,
        "release-notes",
        "Draft release notes from a list of merged changes.",
    );
    Arc::new(SkillLibrary::load(&[SkillSource::new("user", root)]))
}

fn names(v: &[&citrate_agent_loop::skills::Skill]) -> Vec<String> {
    v.iter().map(|s| s.name.clone()).collect()
}

#[test]
fn at_most_five_skills_are_selected_and_the_best_match_is_first() {
    let s = Scratch::new("top");
    let lib = catalog(&s.0);
    assert_eq!(SKILLS_PER_TURN, 5);
    let got = lib.select("audit my solidity contract for reentrancy", SKILLS_PER_TURN);
    assert!(got.len() <= 5, "{:?}", names(&got));
    assert_eq!(got[0].name, "solidity-audit");
    // A query that names many contract skills still stops at five.
    let broad = lib.select(
        "contract solidity foundry deploy mint nft wallet lora precompile semgrep release journal staking frontend",
        SKILLS_PER_TURN,
    );
    assert_eq!(broad.len(), 5);
}

#[test]
fn a_request_with_no_lexical_signal_surfaces_no_skill() {
    let s = Scratch::new("none");
    let lib = catalog(&s.0);
    assert!(lib.select("hello there", SKILLS_PER_TURN).is_empty());
    assert!(lib.select("", SKILLS_PER_TURN).is_empty());
}

#[test]
fn ranking_is_deterministic_and_ties_break_by_name() {
    let s = Scratch::new("tie");
    skill(&s.0, "beta-skill", "Handle the widget.");
    skill(&s.0, "alpha-skill", "Handle the widget.");
    let lib = SkillLibrary::load(&[SkillSource::new("user", &s.0)]);
    for _ in 0..3 {
        assert_eq!(
            names(&lib.select("widget", 5)),
            vec!["alpha-skill".to_string(), "beta-skill".to_string()]
        );
    }
}

#[test]
fn a_rare_matching_term_outranks_a_common_one() {
    let s = Scratch::new("idf");
    // "contract" appears in many descriptions, "reentrancy" in one.
    let lib = catalog(&s.0);
    let got = lib.select("contract reentrancy", 5);
    assert_eq!(got[0].name, "solidity-audit");
}

#[test]
fn the_name_counts_more_than_the_description() {
    let s = Scratch::new("name");
    skill(&s.0, "ipfs-pin", "Keep files available.");
    skill(&s.0, "file-keeper", "Keep files available with ipfs.");
    let lib = SkillLibrary::load(&[SkillSource::new("user", &s.0)]);
    assert_eq!(lib.select("ipfs", 5)[0].name, "ipfs-pin");
}

#[test]
fn the_ranker_says_which_method_ran() {
    assert_eq!(Bm25Ranker.method(), "bm25-lexical");
}

#[test]
fn the_turn_section_lists_only_the_selected_skills_and_the_installed_count() {
    let s = Scratch::new("section");
    let lib = catalog(&s.0);
    let section = lib
        .turn_section("audit my solidity contract for reentrancy", SKILLS_PER_TURN)
        .unwrap();
    assert!(section.starts_with("## Skills"));
    assert!(section.contains("- solidity-audit: Audit a Solidity contract"));
    let listed = section.lines().filter(|l| l.starts_with("- ")).count();
    assert!((1..=5).contains(&listed), "{section}");
    assert!(!section.contains("- journal-digest:"), "{section}");
    assert!(section.contains("12 skills are installed"), "{section}");
    assert!(section.contains(SKILL_LOAD_TOOL));
    assert!(!section.contains("BODY OF"), "bodies load on demand");
}

#[test]
fn with_no_match_the_section_is_one_short_note() {
    let s = Scratch::new("nomatch");
    let lib = catalog(&s.0);
    let section = lib.turn_section("hello there", SKILLS_PER_TURN).unwrap();
    assert_eq!(section.lines().filter(|l| l.starts_with("- ")).count(), 0);
    assert!(section.contains("12 skills are installed"));
    assert!(section.len() < 400, "{section}");
    assert!(SkillLibrary::empty().turn_section("anything", 5).is_none());
}

#[test]
fn a_follow_up_without_signal_reuses_the_previous_request() {
    let s = Scratch::new("follow");
    let lib = catalog(&s.0);
    let idx = SkillTurnIndex::new(lib, SKILLS_PER_TURN);
    let history = vec![
        Message::user("write foundry fuzz tests for my token"),
        Message {
            role: citrate_agent_loop::Role::Assistant,
            content: "Sure.".into(),
            tool_calls: vec![],
            tool_call_id: None,
        },
    ];
    let section = idx.section("ok go ahead", &history).unwrap();
    assert!(section.contains("- foundry-tests:"), "{section}");
}

struct Capture(Mutex<Vec<CompletionRequest>>);
impl LlmClient for Capture {
    fn complete(&self, req: &CompletionRequest) -> Result<AssistantTurn, LlmError> {
        self.0.lock().unwrap().push(req.clone());
        Ok(AssistantTurn::text("ok"))
    }
}
struct NullSink;
impl EventSink for NullSink {
    fn emit(&self, _ev: citrate_agent_loop::Event) {}
}

#[test]
fn each_turn_carries_its_own_top_five_in_the_system_prompt() {
    let s = Scratch::new("turns");
    let lib = catalog(&s.0);
    let cfg = LoopConfig {
        model: "m".into(),
        system_prompt: "You are Hermes.".into(),
        max_steps: 2,
        max_tool_calls_per_step: 2,
        max_tokens: 256,
    };
    let opts = TurnOptions {
        turn_context: vec![
            Arc::new(SkillTurnIndex::new(lib, SKILLS_PER_TURN)) as Arc<dyn TurnContext>
        ],
        ..Default::default()
    };
    let llm = Capture(Mutex::new(vec![]));
    let mut history = vec![];
    for q in [
        "audit my solidity contract for reentrancy",
        "summarize my journal into a digest",
    ] {
        run_turn_with(
            &cfg,
            &opts,
            &llm,
            &ToolRegistry::new(vec![]),
            &NullSink,
            &StopFlag::default(),
            &mut history,
            q,
        );
    }
    let seen = llm.0.lock().unwrap();
    let sys0 = &seen[0].messages[0].content;
    let sys1 = &seen[1].messages[0].content;
    assert!(sys0.starts_with("You are Hermes.\n\n## Skills"), "{sys0}");
    assert!(sys0.contains("- solidity-audit:") && !sys0.contains("- journal-digest:"));
    assert!(sys1.contains("- journal-digest:") && !sys1.contains("- solidity-audit:"));
    for sys in [sys0, sys1] {
        assert!(sys.lines().filter(|l| l.starts_with("- ")).count() <= 5);
    }
    // History keeps no system message: the section is rebuilt for each turn.
    assert!(history
        .iter()
        .all(|m| m.role != citrate_agent_loop::Role::System));
}

#[test]
fn without_turn_context_the_system_prompt_is_unchanged() {
    let cfg = LoopConfig {
        model: "m".into(),
        system_prompt: "You are Hermes.".into(),
        max_steps: 1,
        max_tool_calls_per_step: 1,
        max_tokens: 64,
    };
    let llm = Capture(Mutex::new(vec![]));
    let mut history = vec![];
    run_turn_with(
        &cfg,
        &TurnOptions::default(),
        &llm,
        &ToolRegistry::new(vec![]),
        &NullSink,
        &StopFlag::default(),
        &mut history,
        "hi",
    );
    assert_eq!(
        llm.0.lock().unwrap()[0].messages[0].content,
        "You are Hermes."
    );
}

/// A ranker the library can be given instead of BM25 (an embedding ranker plugs in here).
struct Reverse;
impl SkillRanker for Reverse {
    fn method(&self) -> &'static str {
        "reverse-test"
    }
    fn rank(&self, _query: &str, docs: &[(&str, &str)], k: usize) -> Vec<usize> {
        (0..docs.len()).rev().take(k).collect()
    }
}

#[test]
fn a_different_ranker_can_be_plugged_in_and_k_still_caps_it() {
    let s = Scratch::new("plug");
    let lib = catalog(&s.0);
    let got = lib.select_with(&Reverse, "anything", 3);
    assert_eq!(
        names(&got),
        vec![
            "wallet-hygiene".to_string(),
            "staking-report".to_string(),
            "solidity-audit".to_string()
        ]
    );
}
