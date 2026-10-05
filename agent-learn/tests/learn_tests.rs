//! HUP-S3.4 (US-3.4): Hermes learns only what is proven.
//! - A proposal can only come from a workflow whose verifiers passed; the model's claim never counts.
//! - Nothing persists without the member's accept; a reject is recorded.
//! - Contradictions with existing items are surfaced and never silently merged.
//! - Publishing to SkillRegistry is HIC-1: build only, after persist, with an explicit approval.
use citrate_agent_learn::registry::encode_register_skill;
use citrate_agent_learn::*;
use citrate_agent_loop::skills::{SkillLibrary, SkillSource};
use citrate_agent_loop::*;
use citrate_agent_records::{
    read, verify_dir, Clock, Decision, DecisionLog, Entry, HicTier, LogConfig, Outcome,
    StoredRecord,
};
use std::path::Path;
use std::sync::{Arc, Mutex};

// ------------------------------------------------------------------------------------------------
// harness: a scripted model, a tool host, an event sink
// ------------------------------------------------------------------------------------------------

struct Script(Mutex<Vec<AssistantTurn>>);
impl Script {
    fn new(t: Vec<AssistantTurn>) -> Self {
        Script(Mutex::new(t))
    }
}
impl LlmClient for Script {
    fn complete(&self, _req: &CompletionRequest) -> Result<AssistantTurn, LlmError> {
        let mut t = self.0.lock().unwrap();
        Ok(if t.is_empty() {
            AssistantTurn::text("done")
        } else {
            t.remove(0)
        })
    }
}
struct Host(ToolOutcome, Option<StopFlag>);
impl ToolHost for Host {
    fn execute(&self, _c: &ToolCall) -> ToolOutcome {
        if let Some(s) = &self.1 {
            s.stop();
        }
        self.0.clone()
    }
}
#[derive(Default)]
struct Sink(Mutex<Vec<Event>>);
impl EventSink for Sink {
    fn emit(&self, e: Event) {
        self.0.lock().unwrap().push(e);
    }
}
struct FixedClock(u64);
impl Clock for FixedClock {
    fn now_ms(&self) -> u64 {
        self.0
    }
}

fn spec(n: &str) -> ToolSpec {
    ToolSpec {
        name: n.into(),
        description: n.into(),
        parameters: serde_json::json!({"type":"object"}),
        host: HostKind::Core,
        annotations: ToolAnnotations {
            trust: Some(Trust::Trusted),
            ..Default::default()
        },
    }
}
fn call(id: &str, n: &str) -> AssistantTurn {
    AssistantTurn::tools(vec![ToolCall {
        id: id.into(),
        name: n.into(),
        arguments: "{}".into(),
    }])
}
fn cfg() -> LoopConfig {
    LoopConfig {
        model: "m".into(),
        system_prompt: "s".into(),
        max_steps: 4,
        max_tool_calls_per_step: 4,
        max_tokens: 64,
    }
}
fn tools(stop: Option<StopFlag>) -> ToolRegistry {
    ToolRegistry::new(vec![spec("run_tests")]).with_host(
        HostKind::Core,
        Arc::new(Host(ToolOutcome::Ok(r#"{"failed":0}"#.into()), stop)),
    )
}
fn workflow(attempts: u32) -> Workflow {
    Workflow::new(
        "audit",
        vec![Step {
            id: "test".into(),
            instruction: "run the tests".into(),
            verifiers: vec![
                Arc::new(ToolSucceeded("run_tests".into())),
                Arc::new(JsonFieldEquals {
                    tool: "run_tests".into(),
                    pointer: "/failed".into(),
                    value: serde_json::json!(0),
                }),
            ],
            max_attempts: attempts,
        }],
    )
    .unwrap()
}

/// A run in which the model calls the test tool and the verifiers pass.
fn verified_run() -> VerifiedRun {
    let llm = Script::new(vec![
        call("c1", "run_tests"),
        AssistantTurn::text("tests pass"),
    ]);
    let sink = Sink::default();
    run_verified_workflow(
        "sess-1",
        &cfg(),
        &TurnOptions::default(),
        &llm,
        &tools(None),
        &sink,
        &StopFlag::default(),
        &mut vec![],
        &workflow(2),
    )
    .expect("verifiers passed")
}

const SKILL: &str = "---\nname: solidity-audit-checklist\ndescription: Checks a contract before deploy\n---\n\n# Audit checklist\n\n1. Run slither.\n";

fn skill_content() -> ProposalContent {
    ProposalContent::Skill {
        skill_md: SKILL.into(),
    }
}
fn provenance() -> Provenance {
    Provenance {
        session_id: "sess-1".into(),
        agent: "hermes".into(),
        model: "m".into(),
    }
}

struct Env {
    _root: tempfile::TempDir,
    user: std::path::PathBuf,
    bundled: std::path::PathBuf,
    logdir: std::path::PathBuf,
    learner: Learner,
}

fn env() -> Env {
    let root = tempfile::tempdir().unwrap();
    let user = root.path().join("user-skills");
    let bundled = root.path().join("bundled");
    std::fs::create_dir_all(&bundled).unwrap();
    let logdir = root.path().join("records");
    let log = Arc::new(DecisionLog::open(&logdir, LogConfig::default()).unwrap().0);
    let learner = Learner::with_clock(
        LearnConfig {
            user_skills_dir: user.clone(),
            other_skill_sources: vec![SkillSource::new("bundled", &bundled)],
        },
        log,
        Arc::new(FixedClock(1_700_000_000_000)),
    );
    Env {
        _root: root,
        user,
        bundled,
        logdir,
        learner,
    }
}

fn records(dir: &Path) -> Vec<StoredRecord> {
    let mut v = read::page(dir, None, 1000).unwrap();
    v.sort_by_key(|r| r.record.seq);
    v
}

fn accept(member: &str) -> MemberAccept {
    MemberAccept {
        member: member.into(),
        acknowledged_conflicts: vec![],
    }
}

fn write_skill(dir: &Path, name: &str, desc: &str) {
    let d = dir.join(name);
    std::fs::create_dir_all(&d).unwrap();
    std::fs::write(
        d.join("SKILL.md"),
        format!("---\nname: {name}\ndescription: {desc}\n---\n\nbody\n"),
    )
    .unwrap();
}

// ------------------------------------------------------------------------------------------------
// evidence: only verifiers make a run learnable
// ------------------------------------------------------------------------------------------------

#[test]
fn the_models_claim_of_success_never_yields_a_verified_run() {
    // The model says it ran the tests and they passed, but it never called the tool.
    let llm = Script::new(vec![
        AssistantTurn::text("All tests pass, learned it."),
        AssistantTurn::text("Really, they pass."),
    ]);
    let sink = Sink::default();
    let out = run_verified_workflow(
        "s",
        &cfg(),
        &TurnOptions::default(),
        &llm,
        &tools(None),
        &sink,
        &StopFlag::default(),
        &mut vec![],
        &workflow(2),
    );
    assert!(
        matches!(out, Err(Unverified::Failed { ref step, .. }) if step == "test"),
        "{:?}",
        out.err()
    );
}

#[test]
fn a_stopped_workflow_is_not_learnable() {
    let stop = StopFlag::default();
    let llm = Script::new(vec![call("c1", "run_tests"), AssistantTurn::text("ok")]);
    let out = run_verified_workflow(
        "s",
        &cfg(),
        &TurnOptions::default(),
        &llm,
        &tools(Some(stop.clone())),
        &Sink::default(),
        &stop,
        &mut vec![],
        &workflow(2),
    );
    assert!(matches!(out, Err(Unverified::Stopped)), "{:?}", out.err());
}

#[test]
fn evidence_carries_the_final_passing_verdicts_and_a_trajectory_digest() {
    // Attempt 1: no tool call (fails both verifiers). Attempt 2: passes.
    let llm = Script::new(vec![
        AssistantTurn::text("done already"),
        call("c1", "run_tests"),
        AssistantTurn::text("tests pass"),
    ]);
    let sink = Sink::default();
    let mut history = vec![Message::user("earlier context")];
    let run = run_verified_workflow(
        "sess-9",
        &cfg(),
        &TurnOptions::default(),
        &llm,
        &tools(None),
        &sink,
        &StopFlag::default(),
        &mut history,
        &workflow(2),
    )
    .expect("second attempt passes");
    let ev = run.evidence();
    assert_eq!(ev.workflow_id, "audit");
    assert_eq!(ev.steps, vec!["test".to_string()]);
    assert_eq!(ev.attempts, 2, "both judged attempts are counted");
    assert_eq!(
        ev.verdicts.len(),
        2,
        "one verdict per verifier of the final attempt"
    );
    assert!(ev.verdicts.iter().all(|v| v.passed && v.step == "test"));
    assert_eq!(ev.trajectory.session_id, "sess-9");
    assert_eq!(ev.trajectory.workflow_id, "audit");
    assert_eq!(
        ev.trajectory.messages,
        history.len() - 1,
        "the trajectory is what the workflow appended, not the earlier context"
    );
    assert_eq!(ev.trajectory.sha256.len(), 64);
    assert_eq!(
        ev.trajectory.sha256,
        trajectory_digest(&history[1..]),
        "the digest is recomputable from the appended messages"
    );
    assert_eq!(run.answers(), &["tests pass".to_string()]);
    // The caller's sink still saw every verifier event (the recorder tees).
    let seen = sink
        .0
        .lock()
        .unwrap()
        .iter()
        .filter(|e| e.kind() == "verifier")
        .count();
    assert_eq!(seen, 4);
}

#[test]
fn the_trajectory_digest_changes_with_any_message() {
    let a = vec![Message::user("x"), Message::system("y")];
    let mut b = a.clone();
    b[1].content.push('!');
    assert_ne!(trajectory_digest(&a), trajectory_digest(&b));
}

// ------------------------------------------------------------------------------------------------
// skills: propose, accept, reject
// ------------------------------------------------------------------------------------------------

#[test]
fn a_proposal_carries_evidence_and_nothing_is_written_until_accept() {
    let mut e = env();
    let run = verified_run();
    let p = e
        .learner
        .propose(&run, skill_content(), provenance(), &[])
        .unwrap();
    assert_eq!(p.kind, ProposalKind::Skill);
    assert_eq!(p.state, ProposalState::Proposed);
    assert_eq!(&p.evidence, run.evidence());
    assert_eq!(p.created_at_ms, 1_700_000_000_000);
    assert_eq!(p.content_sha256, sha256_hex(SKILL.as_bytes()));
    assert!(p.conflicts.is_empty());
    assert!(!e.user.join("solidity-audit-checklist").exists());
    assert!(
        records(&e.logdir).is_empty(),
        "a proposal is not a decision"
    );
    assert_eq!(e.learner.pending().len(), 1);
}

#[test]
fn an_invalid_skill_is_refused_at_proposal_time() {
    let mut e = env();
    let run = verified_run();
    for bad in [
        "no frontmatter",
        "---\nname: Bad_Name\ndescription: x\n---\nbody",
        "---\nname: ok\n---\nbody",
        "---\nname: ok\ndescription: x\nweird: 1\n---\nbody",
    ] {
        let r = e.learner.propose(
            &run,
            ProposalContent::Skill {
                skill_md: bad.into(),
            },
            provenance(),
            &[],
        );
        assert!(
            matches!(r, Err(LearnError::InvalidSkill(_))),
            "{bad:?}: {r:?}"
        );
    }
    let huge = format!(
        "---\nname: big\ndescription: x\n---\n{}",
        "a".repeat(citrate_agent_loop::skills::MAX_SKILL_FILE_BYTES)
    );
    assert!(matches!(
        e.learner.propose(
            &run,
            ProposalContent::Skill { skill_md: huge },
            provenance(),
            &[]
        ),
        Err(LearnError::InvalidSkill(_))
    ));
}

#[test]
fn accept_writes_a_loadable_skill_and_records_the_hic1_decision() {
    let mut e = env();
    let run = verified_run();
    let p = e
        .learner
        .propose(&run, skill_content(), provenance(), &[])
        .unwrap();
    let out = e.learner.accept(&p.id, accept("member-1")).unwrap();
    let Persisted::Skill {
        name,
        path,
        content_sha256,
    } = out
    else {
        panic!("expected a skill")
    };
    assert_eq!(name, "solidity-audit-checklist");
    assert_eq!(content_sha256, p.content_sha256);
    assert_eq!(std::fs::read_to_string(&path).unwrap(), SKILL);
    // The agent-loop loader accepts it from the user dir.
    let lib = SkillLibrary::load(&[SkillSource::new("user", &e.user)]);
    assert!(lib.report().rejected.is_empty(), "{:?}", lib.report());
    assert!(lib.get("solidity-audit-checklist").is_some());
    // No temp leftovers next to it.
    let entries: Vec<_> = std::fs::read_dir(&e.user).unwrap().collect();
    assert_eq!(entries.len(), 1);
    assert_eq!(
        e.learner.get(&p.id).unwrap().state,
        ProposalState::Persisted
    );
    // Write-ahead decision then its outcome, by the member, at HIC-1.
    let recs = records(&e.logdir);
    assert_eq!(recs.len(), 2);
    match &recs[0].record.entry {
        Entry::Decision(d) => {
            assert_eq!(d.tier, HicTier::Hic1);
            assert_eq!(d.decision, Decision::Approved);
            assert_eq!(d.kind, "learn.skill");
            assert!(d.subject.contains("solidity-audit-checklist"));
            assert!(d.evidence.iter().any(|r| r.kind == "trajectory"
                && r.digest.as_deref() == Some(run.evidence().trajectory.sha256.as_str())));
            assert!(d.evidence.iter().any(|r| r.kind == "verifier"));
            assert!(d
                .evidence
                .iter()
                .any(|r| r.kind == "proposal"
                    && r.digest.as_deref() == Some(p.content_sha256.as_str())));
        }
        other => panic!("{other:?}"),
    }
    assert_eq!(recs[0].record.actor.id, "member-1");
    match &recs[1].record.entry {
        Entry::Outcome(o) => assert_eq!(o.outcome, Outcome::Completed),
        other => panic!("{other:?}"),
    }
    assert!(verify_dir(&e.logdir).is_ok());
}

#[test]
fn the_user_skills_dir_is_created_on_first_accept() {
    let mut e = env();
    assert!(!e.user.exists());
    let run = verified_run();
    let p = e
        .learner
        .propose(&run, skill_content(), provenance(), &[])
        .unwrap();
    e.learner.accept(&p.id, accept("m")).unwrap();
    assert!(e.user.join("solidity-audit-checklist/SKILL.md").is_file());
}

#[test]
fn reject_is_recorded_and_nothing_persists() {
    let mut e = env();
    let run = verified_run();
    let p = e
        .learner
        .propose(&run, skill_content(), provenance(), &[])
        .unwrap();
    e.learner.reject(&p.id, "member-1", "not useful").unwrap();
    assert!(!e.user.exists() || std::fs::read_dir(&e.user).unwrap().next().is_none());
    let st = &e.learner.get(&p.id).unwrap().state;
    assert!(
        matches!(st, ProposalState::Rejected { by, reason } if by == "member-1" && reason == "not useful")
    );
    let recs = records(&e.logdir);
    assert_eq!(recs.len(), 1);
    match &recs[0].record.entry {
        Entry::Decision(d) => {
            assert_eq!(d.decision, Decision::Denied);
            assert_eq!(d.kind, "learn.skill");
            assert_eq!(d.reason, "not useful");
        }
        other => panic!("{other:?}"),
    }
    // A rejected proposal can never be accepted afterwards.
    assert!(matches!(
        e.learner.accept(&p.id, accept("member-1")),
        Err(LearnError::WrongState { .. })
    ));
    assert!(e.learner.pending().is_empty());
}

#[test]
fn accept_and_reject_need_a_member_and_a_known_proposal() {
    let mut e = env();
    let run = verified_run();
    let p = e
        .learner
        .propose(&run, skill_content(), provenance(), &[])
        .unwrap();
    assert!(matches!(
        e.learner.accept("nope", accept("m")),
        Err(LearnError::UnknownProposal(_))
    ));
    assert!(matches!(
        e.learner.accept(&p.id, accept("  ")),
        Err(LearnError::MemberRequired)
    ));
    assert!(matches!(
        e.learner.reject(&p.id, "", "x"),
        Err(LearnError::MemberRequired)
    ));
    assert!(records(&e.logdir).is_empty());
}

#[test]
fn a_persisted_proposal_cannot_be_accepted_twice() {
    let mut e = env();
    let run = verified_run();
    let p = e
        .learner
        .propose(&run, skill_content(), provenance(), &[])
        .unwrap();
    e.learner.accept(&p.id, accept("m")).unwrap();
    assert!(matches!(
        e.learner.accept(&p.id, accept("m")),
        Err(LearnError::WrongState { .. })
    ));
    assert!(matches!(
        e.learner.reject(&p.id, "m", "x"),
        Err(LearnError::WrongState { .. })
    ));
}

// ------------------------------------------------------------------------------------------------
// conflicts: surfaced, never silently merged
// ------------------------------------------------------------------------------------------------

#[test]
fn the_same_skill_already_saved_is_not_proposed_again() {
    let mut e = env();
    std::fs::create_dir_all(e.user.join("solidity-audit-checklist")).unwrap();
    std::fs::write(e.user.join("solidity-audit-checklist/SKILL.md"), SKILL).unwrap();
    let r = e
        .learner
        .propose(&verified_run(), skill_content(), provenance(), &[]);
    assert!(matches!(r, Err(LearnError::AlreadyKnown { .. })), "{r:?}");
}

#[test]
fn a_different_user_skill_with_the_same_name_blocks_and_is_never_overwritten() {
    let mut e = env();
    write_skill(&e.user, "solidity-audit-checklist", "mine, hand written");
    let before = std::fs::read_to_string(e.user.join("solidity-audit-checklist/SKILL.md")).unwrap();
    let p = e
        .learner
        .propose(&verified_run(), skill_content(), provenance(), &[])
        .unwrap();
    assert_eq!(p.conflicts.len(), 1);
    let c = &p.conflicts[0];
    assert_eq!(c.kind, ConflictKind::SameNameSkill);
    assert!(c.blocking);
    assert_eq!(c.existing_id, "skill:user/solidity-audit-checklist");
    // Even an acknowledged blocking conflict cannot be accepted.
    let r = e.learner.accept(
        &p.id,
        MemberAccept {
            member: "m".into(),
            acknowledged_conflicts: vec![c.existing_id.clone()],
        },
    );
    assert!(matches!(r, Err(LearnError::Blocked(_))), "{r:?}");
    assert_eq!(
        std::fs::read_to_string(e.user.join("solidity-audit-checklist/SKILL.md")).unwrap(),
        before
    );
    // The member can still reject it.
    e.learner.reject(&p.id, "m", "keep mine").unwrap();
}

#[test]
fn shadowing_a_bundled_skill_needs_an_explicit_acknowledgement() {
    let mut e = env();
    write_skill(&e.bundled, "solidity-audit-checklist", "the bundled one");
    let p = e
        .learner
        .propose(&verified_run(), skill_content(), provenance(), &[])
        .unwrap();
    assert_eq!(p.conflicts.len(), 1);
    assert_eq!(p.conflicts[0].kind, ConflictKind::ShadowsSkill);
    assert!(!p.conflicts[0].blocking);
    let id = p.conflicts[0].existing_id.clone();
    assert_eq!(id, "skill:bundled/solidity-audit-checklist");
    let r = e.learner.accept(&p.id, accept("m"));
    assert!(
        matches!(r, Err(LearnError::UnacknowledgedConflicts(ref v)) if v.len() == 1),
        "{r:?}"
    );
    assert!(!e.user.join("solidity-audit-checklist").exists());
    assert!(
        records(&e.logdir).is_empty(),
        "a refused accept records nothing"
    );
    // A wrong acknowledgement does not count either.
    assert!(matches!(
        e.learner.accept(
            &p.id,
            MemberAccept {
                member: "m".into(),
                acknowledged_conflicts: vec!["skill:bundled/other".into()],
            }
        ),
        Err(LearnError::UnacknowledgedConflicts(_))
    ));
    e.learner
        .accept(
            &p.id,
            MemberAccept {
                member: "m".into(),
                acknowledged_conflicts: vec![id],
            },
        )
        .unwrap();
    assert!(e.user.join("solidity-audit-checklist/SKILL.md").is_file());
}

#[test]
fn conflicts_are_rechecked_at_accept_time() {
    let mut e = env();
    let run = verified_run();
    let a = e
        .learner
        .propose(&run, skill_content(), provenance(), &[])
        .unwrap();
    let other = SKILL.replace("Run slither.", "Run slither and forge test.");
    let b = e
        .learner
        .propose(
            &run,
            ProposalContent::Skill { skill_md: other },
            provenance(),
            &[],
        )
        .unwrap();
    // b sees a as a pending same-name proposal.
    assert_eq!(b.conflicts.len(), 1);
    assert_eq!(b.conflicts[0].kind, ConflictKind::PendingProposal);
    assert_eq!(b.conflicts[0].existing_id, format!("proposal:{}", a.id));
    // a now sees b the same way, so accepting a needs that acknowledged.
    assert!(matches!(
        e.learner.accept(&a.id, accept("m")),
        Err(LearnError::UnacknowledgedConflicts(_))
    ));
    e.learner
        .accept(
            &a.id,
            MemberAccept {
                member: "m".into(),
                acknowledged_conflicts: vec![format!("proposal:{}", b.id)],
            },
        )
        .unwrap();
    // Now a is on disk: b is blocked even if the member acknowledges the old conflict.
    let r = e.learner.accept(
        &b.id,
        MemberAccept {
            member: "m".into(),
            acknowledged_conflicts: vec![format!("proposal:{}", a.id)],
        },
    );
    assert!(matches!(r, Err(LearnError::Blocked(_))), "{r:?}");
    assert_eq!(
        std::fs::read_to_string(e.user.join("solidity-audit-checklist/SKILL.md")).unwrap(),
        SKILL
    );
    let refreshed = e.learner.get(&b.id).unwrap();
    assert!(refreshed
        .conflicts
        .iter()
        .any(|c| c.kind == ConflictKind::SameNameSkill && c.blocking));
}

// ------------------------------------------------------------------------------------------------
// memories
// ------------------------------------------------------------------------------------------------

fn memory(key: &str, value: &str) -> ProposalContent {
    ProposalContent::Memory {
        key: key.into(),
        value: value.into(),
    }
}

#[test]
fn an_accepted_memory_is_emitted_as_a_typed_record_for_core() {
    let mut e = env();
    let run = verified_run();
    let p = e
        .learner
        .propose(
            &run,
            memory("project.test-command", "forge test -vvv"),
            provenance(),
            &[],
        )
        .unwrap();
    assert_eq!(p.kind, ProposalKind::Memory);
    let out = e.learner.accept(&p.id, accept("m")).unwrap();
    let Persisted::Memory(rec) = out else {
        panic!("expected a memory")
    };
    assert_eq!(rec.key, "project.test-command");
    assert_eq!(rec.value, "forge test -vvv");
    assert_eq!(rec.belnap, Belnap::True);
    assert!(rec.contradicts.is_empty());
    assert_eq!(rec.proposal_id, p.id);
    assert_eq!(rec.accepted_by, "m");
    assert_eq!(&rec.evidence, run.evidence());
    assert_eq!(rec.provenance, provenance());
    assert_eq!(rec.decision_seq, 0);
    assert!(!e.user.exists(), "a memory never touches the skills dir");
    let recs = records(&e.logdir);
    assert!(matches!(&recs[0].record.entry, Entry::Decision(d) if d.kind == "learn.memory"));
    // Wire shape is stable for core.
    let j = serde_json::to_value(&rec).unwrap();
    assert_eq!(j["belnap"], "true");
    assert_eq!(j["schema"], "citrate.learn.memory.v1");
}

#[test]
fn a_contradicting_memory_is_surfaced_and_stored_as_both_never_merged() {
    let mut e = env();
    let known = vec![KnownMemory {
        id: "mem-7".into(),
        key: "Project.Test-Command".into(),
        value: "npm test".into(),
    }];
    let p = e
        .learner
        .propose(
            &verified_run(),
            memory("project.test-command", "forge test -vvv"),
            provenance(),
            &known,
        )
        .unwrap();
    assert_eq!(p.conflicts.len(), 1);
    assert_eq!(p.conflicts[0].kind, ConflictKind::Contradiction);
    assert_eq!(p.conflicts[0].existing_id, "memory:mem-7");
    assert!(!p.conflicts[0].blocking);
    assert!(matches!(
        e.learner.accept(&p.id, accept("m")),
        Err(LearnError::UnacknowledgedConflicts(_))
    ));
    let Persisted::Memory(rec) = e
        .learner
        .accept(
            &p.id,
            MemberAccept {
                member: "m".into(),
                acknowledged_conflicts: vec!["memory:mem-7".into()],
            },
        )
        .unwrap()
    else {
        panic!()
    };
    assert_eq!(rec.belnap, Belnap::Both, "a contradiction halts reliance");
    assert_eq!(rec.contradicts, vec!["mem-7".to_string()]);
    assert_eq!(
        rec.value, "forge test -vvv",
        "the new value is kept as is, not merged"
    );
}

#[test]
fn a_memory_already_known_is_not_proposed_again() {
    let mut e = env();
    let known = vec![KnownMemory {
        id: "mem-1".into(),
        key: "project.test-command".into(),
        value: "forge  test   -vvv".into(),
    }];
    let r = e.learner.propose(
        &verified_run(),
        memory("Project.Test-Command", "forge test -vvv"),
        provenance(),
        &known,
    );
    assert!(
        matches!(r, Err(LearnError::AlreadyKnown { ref existing_id }) if existing_id == "memory:mem-1"),
        "{r:?}"
    );
}

#[test]
fn memory_fields_are_bounded() {
    let mut e = env();
    let run = verified_run();
    for (k, v) in [
        ("", "x"),
        ("k", ""),
        (&*"k".repeat(MAX_MEMORY_KEY_LEN + 1), "x"),
        ("k", &*"v".repeat(MAX_MEMORY_VALUE_LEN + 1)),
    ] {
        assert!(matches!(
            e.learner.propose(&run, memory(k, v), provenance(), &[]),
            Err(LearnError::InvalidMemory(_))
        ));
    }
}

// ------------------------------------------------------------------------------------------------
// publish: HIC-1, build only, after persist, with an explicit approval
// ------------------------------------------------------------------------------------------------

const REGISTRY: &str = "0x2B687899EF4aF05A18F4f36cE1fE9d51c017A97c";
const OWNER: &str = "0x00000000000000000000000000000000000000aa";

fn params() -> PublishParams {
    PublishParams {
        chain_id: 40204,
        registry: REGISTRY.into(),
        owner: OWNER.into(),
        version: "1.0.0".into(),
        manifest_cid: None,
        tags: vec!["solidity".into()],
    }
}
fn approval(p: &Proposal) -> PublishApproval {
    PublishApproval {
        member: "m".into(),
        proposal_id: p.id.clone(),
        content_sha256: p.content_sha256.clone(),
    }
}

#[test]
fn publish_is_refused_before_persist() {
    let mut e = env();
    let p = e
        .learner
        .propose(&verified_run(), skill_content(), provenance(), &[])
        .unwrap();
    let r = e.learner.prepare_publish(&p.id, approval(&p), params());
    assert!(matches!(r, Err(LearnError::WrongState { .. })), "{r:?}");
    e.learner.reject(&p.id, "m", "no").unwrap();
    assert!(matches!(
        e.learner.prepare_publish(&p.id, approval(&p), params()),
        Err(LearnError::WrongState { .. })
    ));
}

#[test]
fn publish_needs_an_approval_for_this_exact_proposal_and_content() {
    let mut e = env();
    let p = e
        .learner
        .propose(&verified_run(), skill_content(), provenance(), &[])
        .unwrap();
    e.learner.accept(&p.id, accept("m")).unwrap();
    let n = records(&e.logdir).len();
    let mut wrong_hash = approval(&p);
    wrong_hash.content_sha256 = "00".repeat(32);
    let mut wrong_id = approval(&p);
    wrong_id.proposal_id = "other".into();
    let mut no_member = approval(&p);
    no_member.member = " ".into();
    for a in [wrong_hash, wrong_id] {
        assert!(matches!(
            e.learner.prepare_publish(&p.id, a, params()),
            Err(LearnError::ApprovalMismatch)
        ));
    }
    assert!(matches!(
        e.learner.prepare_publish(&p.id, no_member, params()),
        Err(LearnError::MemberRequired)
    ));
    assert_eq!(records(&e.logdir).len(), n, "refusals record nothing");
}

#[test]
fn a_memory_is_never_published() {
    let mut e = env();
    let p = e
        .learner
        .propose(&verified_run(), memory("k", "v"), provenance(), &[])
        .unwrap();
    e.learner.accept(&p.id, accept("m")).unwrap();
    assert!(matches!(
        e.learner.prepare_publish(&p.id, approval(&p), params()),
        Err(LearnError::NotASkill)
    ));
}

#[test]
fn publish_builds_the_registry_calldata_and_records_hic1_without_sending() {
    let mut e = env();
    let p = e
        .learner
        .propose(&verified_run(), skill_content(), provenance(), &[])
        .unwrap();
    e.learner.accept(&p.id, accept("m")).unwrap();
    let pay = e
        .learner
        .prepare_publish(&p.id, approval(&p), params())
        .unwrap();
    assert_eq!(pay.chain_id, 40204);
    assert_eq!(pay.to, REGISTRY.to_lowercase());
    assert_eq!(pay.value, "0x0");
    assert_eq!(pay.hic, "hic-1");
    assert!(!pay.broadcast, "the runtime never sends");
    assert_eq!(
        pay.function,
        "registerSkill(string,string,string,string,string[])"
    );
    assert_eq!(pay.name, "solidity-audit-checklist");
    assert_eq!(pay.version, "1.0.0");
    assert_eq!(pay.manifest_cid, "");
    assert_eq!(pay.description, "Checks a contract before deploy");
    let hash_tag = format!("sha256:{}", p.content_sha256);
    assert_eq!(
        pay.tags,
        vec!["solidity".to_string(), "hermes-learned".into(), hash_tag]
    );
    let expect = encode_register_skill(
        &pay.name,
        &pay.version,
        &pay.manifest_cid,
        &pay.description,
        &pay.tags,
    );
    assert_eq!(pay.data, format!("0x{}", hex::encode(expect)));
    assert_eq!(pay.content_sha256, p.content_sha256);
    assert_eq!(pay.expected_skill_hash.len(), 66);
    assert_eq!(
        e.learner.get(&p.id).unwrap().state,
        ProposalState::PublishPrepared
    );
    let recs = records(&e.logdir);
    let last_decision = recs
        .iter()
        .rev()
        .find_map(|r| match &r.record.entry {
            Entry::Decision(d) => Some(d.clone()),
            _ => None,
        })
        .unwrap();
    assert_eq!(last_decision.kind, "skill.publish");
    assert_eq!(last_decision.tier, HicTier::Hic1);
    assert_eq!(last_decision.decision, Decision::Approved);
    assert!(
        matches!(&recs.last().unwrap().record.entry, Entry::Outcome(o) if o.outcome == Outcome::Completed)
    );
    assert!(verify_dir(&e.logdir).is_ok());
}

#[test]
fn publish_is_refused_when_the_saved_skill_changed_since_accept() {
    let mut e = env();
    let p = e
        .learner
        .propose(&verified_run(), skill_content(), provenance(), &[])
        .unwrap();
    let Persisted::Skill { path, .. } = e.learner.accept(&p.id, accept("m")).unwrap() else {
        panic!()
    };
    std::fs::write(&path, SKILL.replace("slither", "nothing")).unwrap();
    assert!(matches!(
        e.learner.prepare_publish(&p.id, approval(&p), params()),
        Err(LearnError::ContentChanged)
    ));
    std::fs::remove_file(&path).unwrap();
    assert!(matches!(
        e.learner.prepare_publish(&p.id, approval(&p), params()),
        Err(LearnError::ContentChanged)
    ));
}

#[test]
fn publish_params_are_validated() {
    let mut e = env();
    let p = e
        .learner
        .propose(&verified_run(), skill_content(), provenance(), &[])
        .unwrap();
    e.learner.accept(&p.id, accept("m")).unwrap();
    let mut bad = Vec::new();
    let mut x = params();
    x.version = "1.0".into();
    bad.push(x);
    let mut x = params();
    x.registry = "0x1234".into();
    bad.push(x);
    let mut x = params();
    x.owner = "nope".into();
    bad.push(x);
    let mut x = params();
    x.chain_id = 0;
    bad.push(x);
    let mut x = params();
    x.manifest_cid = Some("ipfs://x".into());
    bad.push(x);
    let mut x = params();
    x.tags = vec!["Bad Tag".into()];
    bad.push(x);
    let mut x = params();
    x.tags = (0..=MAX_USER_TAGS).map(|i| format!("t{i}")).collect();
    bad.push(x);
    for b in bad {
        let r = e.learner.prepare_publish(&p.id, approval(&p), b.clone());
        assert!(
            matches!(r, Err(LearnError::InvalidPublish(_))),
            "{b:?}: {r:?}"
        );
    }
}

// ------------------------------------------------------------------------------------------------
// edges
// ------------------------------------------------------------------------------------------------

#[test]
fn provenance_must_name_the_verified_runs_session() {
    let mut e = env();
    let mut prov = provenance();
    prov.session_id = "another-session".into();
    assert!(matches!(
        e.learner
            .propose(&verified_run(), skill_content(), prov, &[]),
        Err(LearnError::ProvenanceMismatch { .. })
    ));
}

#[test]
fn a_same_name_skill_nested_deeper_in_the_user_folder_also_blocks() {
    // The loader scans the user folder recursively, so writing a second copy at the top level
    // would make both ambiguous and neither would load.
    let mut e = env();
    write_skill(&e.user.join("team"), "solidity-audit-checklist", "nested");
    let p = e
        .learner
        .propose(&verified_run(), skill_content(), provenance(), &[])
        .unwrap();
    assert!(p
        .conflicts
        .iter()
        .any(|c| c.kind == ConflictKind::SameNameSkill && c.blocking));
}

#[test]
fn a_failed_write_is_recorded_as_failed_and_can_be_retried() {
    let mut e = env();
    // The skills "folder" is a file, so nothing can be written under it.
    std::fs::write(&e.user, b"not a folder").unwrap();
    let p = e
        .learner
        .propose(&verified_run(), skill_content(), provenance(), &[])
        .unwrap();
    let r = e.learner.accept(&p.id, accept("m"));
    assert!(matches!(r, Err(LearnError::Persist(_))), "{r:?}");
    assert!(matches!(
        e.learner.get(&p.id).unwrap().state,
        ProposalState::PersistFailed { .. }
    ));
    let recs = records(&e.logdir);
    assert_eq!(recs.len(), 2);
    assert!(matches!(&recs[1].record.entry, Entry::Outcome(o) if o.outcome == Outcome::Failed));
    // Still pending: the member can retry once the folder is fixed.
    assert_eq!(e.learner.pending().len(), 1);
    std::fs::remove_file(&e.user).unwrap();
    e.learner.accept(&p.id, accept("m")).unwrap();
    assert_eq!(
        e.learner.get(&p.id).unwrap().state,
        ProposalState::Persisted
    );
    assert!(verify_dir(&e.logdir).is_ok());
}

#[test]
fn pending_proposals_are_bounded() {
    let mut e = env();
    let run = verified_run();
    for i in 0..MAX_PENDING {
        e.learner
            .propose(&run, memory(&format!("k{i}"), "v"), provenance(), &[])
            .unwrap();
    }
    assert!(matches!(
        e.learner
            .propose(&run, memory("one-more", "v"), provenance(), &[]),
        Err(LearnError::TooManyPending)
    ));
}

#[test]
fn the_same_pending_proposal_is_not_made_twice() {
    let mut e = env();
    let run = verified_run();
    let a = e
        .learner
        .propose(&run, skill_content(), provenance(), &[])
        .unwrap();
    assert!(matches!(
        e.learner.propose(&run, skill_content(), provenance(), &[]),
        Err(LearnError::AlreadyKnown { ref existing_id }) if *existing_id == format!("proposal:{}", a.id)
    ));
}

#[test]
fn a_written_skill_the_loader_would_not_load_is_rolled_back() {
    // A full user folder: the loader takes at most MAX_SKILLS_PER_SOURCE per source, so a new
    // skill that sorts last would be written but never loaded. That is a failed persist.
    let mut e = env();
    for i in 0..citrate_agent_loop::skills::MAX_SKILLS_PER_SOURCE {
        write_skill(&e.user, &format!("a-{i:04}"), "filler");
    }
    let p = e
        .learner
        .propose(&verified_run(), skill_content(), provenance(), &[])
        .unwrap();
    let r = e.learner.accept(&p.id, accept("m"));
    assert!(matches!(r, Err(LearnError::Persist(_))), "{r:?}");
    assert!(
        !e.user.join("solidity-audit-checklist").exists(),
        "rolled back"
    );
    assert!(matches!(
        e.learner.get(&p.id).unwrap().state,
        ProposalState::PersistFailed { .. }
    ));
}

#[test]
fn two_contradicting_memories_accepted_one_after_the_other_end_as_both() {
    // Two pending proposals give the same key different values. Accepting the first (with the
    // other acknowledged) must not let the second be stored later as plain `true`: once the
    // first is persisted it is a contradiction for the second, surfaced and stored as `both`.
    let mut e = env();
    let a = e
        .learner
        .propose(
            &verified_run(),
            memory("project.test-command", "forge test -vvv"),
            provenance(),
            &[],
        )
        .unwrap();
    let b = e
        .learner
        .propose(
            &verified_run(),
            memory("project.test-command", "npm test"),
            provenance(),
            &[],
        )
        .unwrap();
    let a_ref = format!("proposal:{}", a.id);
    let b_ref = format!("proposal:{}", b.id);
    let Persisted::Memory(ra) = e
        .learner
        .accept(
            &a.id,
            MemberAccept {
                member: "m".into(),
                acknowledged_conflicts: vec![b_ref.clone()],
            },
        )
        .unwrap()
    else {
        panic!()
    };
    assert_eq!(ra.belnap, Belnap::True);
    // The second accept must surface the now-persisted first memory as a contradiction.
    match e.learner.accept(&b.id, accept("m")) {
        Err(LearnError::UnacknowledgedConflicts(c)) => {
            assert_eq!(c.len(), 1, "{c:?}");
            assert_eq!(c[0].kind, ConflictKind::Contradiction);
            assert_eq!(c[0].existing_id, a_ref);
        }
        other => panic!("expected the contradiction to be surfaced, got {other:?}"),
    }
    let Persisted::Memory(rb) = e
        .learner
        .accept(
            &b.id,
            MemberAccept {
                member: "m".into(),
                acknowledged_conflicts: vec![a_ref.clone()],
            },
        )
        .unwrap()
    else {
        panic!()
    };
    assert_eq!(rb.belnap, Belnap::Both);
    assert_eq!(rb.contradicts, vec![a_ref.clone()]);
    // And the same value as an accepted memory is not proposed again.
    let r = e.learner.propose(
        &verified_run(),
        memory("Project.Test-Command", "forge  test -vvv"),
        provenance(),
        &[],
    );
    assert!(
        matches!(r, Err(LearnError::AlreadyKnown { ref existing_id }) if *existing_id == a_ref),
        "{r:?}"
    );
}

#[test]
fn a_reject_reason_is_bounded_in_the_proposal_as_in_the_log() {
    let mut e = env();
    let p = e
        .learner
        .propose(&verified_run(), skill_content(), provenance(), &[])
        .unwrap();
    let long = "x".repeat(5000);
    e.learner.reject(&p.id, "m", &long).unwrap();
    let ProposalState::Rejected { reason, .. } = &e.learner.get(&p.id).unwrap().state else {
        panic!("expected rejected")
    };
    assert_eq!(reason.chars().count(), 1000);
    let Entry::Decision(d) = &records(&e.logdir)[0].record.entry else {
        panic!("expected a decision")
    };
    assert_eq!(
        &d.reason, reason,
        "the proposal keeps what the log recorded"
    );
}

// ------------------------------------------------------------------------------------------------
// Resolving a contradiction (US-3.4 AC4, the member's way out of Belnap `both`)
// ------------------------------------------------------------------------------------------------

/// Two learned memories that disagree on one key, both accepted (the second as `both`).
fn two_contradicting(e: &mut Env) -> (Proposal, Proposal) {
    let a = e
        .learner
        .propose(
            &verified_run(),
            memory("project.test-command", "forge test -vvv"),
            provenance(),
            &[],
        )
        .unwrap();
    e.learner.accept(&a.id, accept("m")).unwrap();
    let b = e
        .learner
        .propose(
            &verified_run(),
            memory("Project.Test-Command", "npm test"),
            provenance(),
            &[],
        )
        .unwrap();
    e.learner
        .accept(
            &b.id,
            MemberAccept {
                member: "m".into(),
                acknowledged_conflicts: vec![format!("proposal:{}", a.id)],
            },
        )
        .unwrap();
    (a, b)
}

fn resolve(member: &str, keep: &str, retract: &str) -> MemberResolve {
    MemberResolve {
        member: member.into(),
        keep: keep.into(),
        retract: retract.into(),
    }
}

#[test]
fn resolving_a_contradiction_keeps_one_retracts_the_other_and_records_hic1() {
    let mut e = env();
    let (a, b) = two_contradicting(&mut e);
    let before = records(&e.logdir).len();
    let r = e.learner.resolve(resolve("m", &b.id, &a.id)).unwrap();
    assert_eq!(r.schema, RESOLUTION_SCHEMA);
    assert_eq!(r.kept, b.id);
    assert_eq!(r.retracted, a.id);
    assert_eq!(r.kept_value, "npm test");
    assert_eq!(r.retracted_value, "forge test -vvv");
    assert_eq!(r.decided_by, "m");
    // The kept memory stays persisted; the other is retracted, never deleted.
    assert!(matches!(
        e.learner.get(&b.id).unwrap().state,
        ProposalState::Persisted
    ));
    match &e.learner.get(&a.id).unwrap().state {
        ProposalState::Retracted { by, kept } => {
            assert_eq!(by, "m");
            assert_eq!(kept, &b.id);
        }
        other => panic!("expected retracted, got {other:?}"),
    }
    // The decision was recorded (write-ahead) as HIC-1 with both proposals as evidence, then
    // closed as completed.
    let recs = records(&e.logdir);
    assert_eq!(recs.len(), before + 2);
    let Entry::Decision(d) = &recs[before].record.entry else {
        panic!("expected a decision")
    };
    assert_eq!(d.kind, "learn.memory.resolve");
    assert_eq!(d.tier, HicTier::Hic1);
    assert_eq!(d.decision, Decision::Approved);
    assert_eq!(recs[before].record.seq, r.decision_seq);
    assert_eq!(
        d.evidence[0].uri,
        format!("learn:proposal/{}", a.id),
        "the retracted proposal is the subject"
    );
    assert!(
        d.evidence
            .iter()
            .any(|x| x.uri == format!("learn:kept/{}", b.id)),
        "{:?}",
        d.evidence
    );
    assert!(matches!(
        &recs[before + 1].record.entry,
        Entry::Outcome(o) if o.outcome == Outcome::Completed
    ));
    assert!(verify_dir(&e.logdir).is_ok());
    // The wire shape core reads.
    let j = serde_json::to_value(&r).unwrap();
    assert_eq!(j["schema"], "citrate.learn.resolve.v1");
    assert_eq!(j["kept"], b.id.as_str());
}

#[test]
fn only_two_accepted_memories_that_disagree_on_one_key_can_be_resolved() {
    let mut e = env();
    let (a, b) = two_contradicting(&mut e);
    // A member is required; the ids must be known.
    assert!(matches!(
        e.learner.resolve(resolve(" ", &b.id, &a.id)),
        Err(LearnError::MemberRequired)
    ));
    assert!(matches!(
        e.learner.resolve(resolve("m", "lp-nope", &a.id)),
        Err(LearnError::UnknownProposal(_))
    ));
    assert!(matches!(
        e.learner.resolve(resolve("m", &b.id, &b.id)),
        Err(LearnError::NotAContradiction(_))
    ));
    // A memory on another key is not a contradiction.
    let other = e
        .learner
        .propose(
            &verified_run(),
            memory("deploy chain", "40204"),
            provenance(),
            &[],
        )
        .unwrap();
    // ...and while it is undecided it cannot take part at all.
    assert!(matches!(
        e.learner.resolve(resolve("m", &other.id, &a.id)),
        Err(LearnError::WrongState { .. })
    ));
    e.learner.accept(&other.id, accept("m")).unwrap();
    assert!(matches!(
        e.learner.resolve(resolve("m", &other.id, &a.id)),
        Err(LearnError::NotAContradiction(_))
    ));
    // A skill is never part of a memory resolution.
    let s = e
        .learner
        .propose(&verified_run(), skill_content(), provenance(), &[])
        .unwrap();
    e.learner.accept(&s.id, accept("m")).unwrap();
    assert!(matches!(
        e.learner.resolve(resolve("m", &s.id, &a.id)),
        Err(LearnError::NotAContradiction(_))
    ));
    // Nothing was recorded for any refusal, and nothing changed state.
    let resolves = records(&e.logdir)
        .into_iter()
        .filter(
            |r| matches!(&r.record.entry, Entry::Decision(d) if d.kind == "learn.memory.resolve"),
        )
        .count();
    assert_eq!(resolves, 0);
    // Once resolved, the retracted one cannot be kept or retracted again.
    e.learner.resolve(resolve("m", &b.id, &a.id)).unwrap();
    assert!(matches!(
        e.learner.resolve(resolve("m", &a.id, &b.id)),
        Err(LearnError::WrongState { .. })
    ));
    assert!(matches!(
        e.learner.resolve(resolve("m", &b.id, &a.id)),
        Err(LearnError::WrongState { .. })
    ));
}

#[test]
fn a_retracted_memory_no_longer_counts_as_known() {
    let mut e = env();
    let (a, b) = two_contradicting(&mut e);
    e.learner.resolve(resolve("m", &b.id, &a.id)).unwrap();
    // Proposing the retracted value again is a new proposal that contradicts the kept memory,
    // not "already known".
    let again = e
        .learner
        .propose(
            &verified_run(),
            memory("project.test-command", "forge test -vvv"),
            provenance(),
            &[],
        )
        .unwrap();
    assert_eq!(again.conflicts.len(), 1, "{:?}", again.conflicts);
    assert_eq!(again.conflicts[0].kind, ConflictKind::Contradiction);
    assert_eq!(again.conflicts[0].existing_id, format!("proposal:{}", b.id));
    // The kept value is still known.
    let r = e.learner.propose(
        &verified_run(),
        memory("project.test-command", "npm test"),
        provenance(),
        &[],
    );
    assert!(matches!(r, Err(LearnError::AlreadyKnown { .. })), "{r:?}");
}

// ---- resolving a contradiction with a memory that was not learned here (fan-out 7, L02) -------

/// A learned memory accepted against a known memory core passed in (`memory:mem-7`).
fn contradicting_known(e: &mut Env) -> Proposal {
    let known = vec![KnownMemory {
        id: "mem-7".into(),
        key: "project.test-command".into(),
        value: "npm test".into(),
    }];
    let p = e
        .learner
        .propose(
            &verified_run(),
            memory("project.test-command", "forge test -vvv"),
            provenance(),
            &known,
        )
        .unwrap();
    e.learner
        .accept(
            &p.id,
            MemberAccept {
                member: "m".into(),
                acknowledged_conflicts: vec!["memory:mem-7".into()],
            },
        )
        .unwrap();
    p
}

#[test]
fn keeping_the_learned_memory_sets_the_known_one_aside_and_records_hic1() {
    let mut e = env();
    let p = contradicting_known(&mut e);
    let before = records(&e.logdir).len();
    let r = e
        .learner
        .resolve(resolve("m", &p.id, "memory:mem-7"))
        .unwrap();
    assert_eq!(r.kept, p.id);
    assert_eq!(r.retracted, "memory:mem-7");
    assert_eq!(r.kept_value, "forge test -vvv");
    assert_eq!(
        r.retracted_value, "",
        "the learner never held the known memory's value"
    );
    let kept = e.learner.get(&p.id).unwrap();
    assert!(matches!(kept.state, ProposalState::Persisted));
    assert_eq!(kept.set_aside, vec!["memory:mem-7".to_string()]);
    let recs = records(&e.logdir);
    assert_eq!(recs.len(), before + 2);
    let Entry::Decision(d) = &recs[before].record.entry else {
        panic!("expected a decision")
    };
    assert_eq!(d.kind, "learn.memory.resolve");
    assert_eq!(d.tier, HicTier::Hic1);
    assert!(d
        .evidence
        .iter()
        .any(|x| x.uri == "learn:set-aside/memory:mem-7"));
    assert!(d
        .evidence
        .iter()
        .any(|x| x.uri == format!("learn:kept/{}", p.id)));
    assert!(
        !d.evidence
            .iter()
            .any(|x| x.uri.starts_with("learn:proposal/")),
        "the kept memory is not the subject of a retraction: {:?}",
        d.evidence
    );
    // Resolved once: the same pair cannot be resolved again, either way.
    assert!(matches!(
        e.learner.resolve(resolve("m", &p.id, "memory:mem-7")),
        Err(LearnError::NotAContradiction(_))
    ));
    assert!(matches!(
        e.learner.resolve(resolve("m", "memory:mem-7", &p.id)),
        Err(LearnError::NotAContradiction(_))
    ));
}

#[test]
fn keeping_the_known_memory_retracts_the_learned_one() {
    let mut e = env();
    let p = contradicting_known(&mut e);
    let r = e
        .learner
        .resolve(resolve("m", "memory:mem-7", &p.id))
        .unwrap();
    assert_eq!(r.kept, "memory:mem-7");
    assert_eq!(r.retracted, p.id);
    assert_eq!(r.kept_value, "");
    assert_eq!(r.retracted_value, "forge test -vvv");
    match &e.learner.get(&p.id).unwrap().state {
        ProposalState::Retracted { by, kept } => {
            assert_eq!(by, "m");
            assert_eq!(kept, "memory:mem-7");
        }
        other => panic!("expected retracted, got {other:?}"),
    }
}

#[test]
fn a_known_memory_resolution_needs_the_contradiction_the_member_acknowledged() {
    let mut e = env();
    let p = contradicting_known(&mut e);
    for (keep, retract) in [
        (p.id.as_str(), "memory:mem-8"),
        ("memory:mem-8", p.id.as_str()),
        ("memory:mem-7", "memory:mem-7"),
        ("memory:mem-7", "memory:mem-9"),
        (p.id.as_str(), "memory:"),
        (p.id.as_str(), "memory:mem 7"),
    ] {
        assert!(
            matches!(
                e.learner.resolve(resolve("m", keep, retract)),
                Err(LearnError::NotAContradiction(_))
            ),
            "{keep} / {retract}"
        );
    }
    // A memory with no contradiction against a known one cannot set one aside.
    let other = e
        .learner
        .propose(
            &verified_run(),
            memory("deploy chain", "40204"),
            provenance(),
            &[],
        )
        .unwrap();
    assert!(matches!(
        e.learner.resolve(resolve("m", &other.id, "memory:mem-7")),
        Err(LearnError::WrongState { .. })
    ));
    e.learner.accept(&other.id, accept("m")).unwrap();
    assert!(matches!(
        e.learner.resolve(resolve("m", &other.id, "memory:mem-7")),
        Err(LearnError::NotAContradiction(_))
    ));
    let resolves = records(&e.logdir)
        .into_iter()
        .filter(
            |r| matches!(&r.record.entry, Entry::Decision(d) if d.kind == "learn.memory.resolve"),
        )
        .count();
    assert_eq!(resolves, 0, "no refusal is recorded");
}
