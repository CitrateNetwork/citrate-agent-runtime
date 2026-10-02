//! HUP-S3.4 wiring: proposals survive a sidecar restart.
//! - Undecided proposals are saved to a file after every change and restored on open.
//! - Decided states survive too, so a restart cannot reopen a decision.
//! - What is loaded is re-checked: tampered content is dropped, an unreadable file is moved aside.
use citrate_agent_learn::*;
use citrate_agent_loop::skills::SkillSource;
use citrate_agent_loop::*;
use citrate_agent_records::{Clock, DecisionLog, LogConfig};
use std::path::{Path, PathBuf};
use std::sync::{Arc, Mutex};

struct Script(Mutex<Vec<AssistantTurn>>);
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
struct Host;
impl ToolHost for Host {
    fn execute(&self, _c: &ToolCall) -> ToolOutcome {
        ToolOutcome::Ok(r#"{"failed":0}"#.into())
    }
}
struct NullSink;
impl EventSink for NullSink {
    fn emit(&self, _e: Event) {}
}
struct TickClock(Mutex<u64>);
impl Clock for TickClock {
    fn now_ms(&self) -> u64 {
        let mut t = self.0.lock().unwrap();
        *t += 1;
        *t
    }
}

fn verified_run(session: &str) -> VerifiedRun {
    let llm = Script(Mutex::new(vec![
        AssistantTurn::tools(vec![ToolCall {
            id: "c1".into(),
            name: "run_tests".into(),
            arguments: "{}".into(),
        }]),
        AssistantTurn::text("tests pass"),
    ]));
    let tools = ToolRegistry::new(vec![ToolSpec {
        name: "run_tests".into(),
        description: "run".into(),
        parameters: serde_json::json!({"type":"object"}),
        host: HostKind::Core,
        annotations: ToolAnnotations {
            trust: Some(Trust::Trusted),
            ..Default::default()
        },
    }])
    .with_host(HostKind::Core, Arc::new(Host));
    let wf = Workflow::new(
        "audit",
        vec![Step {
            id: "test".into(),
            instruction: "run the tests".into(),
            verifiers: vec![Arc::new(ToolSucceeded("run_tests".into()))],
            max_attempts: 2,
        }],
    )
    .unwrap();
    run_verified_workflow(
        session,
        &LoopConfig {
            model: "m".into(),
            system_prompt: "s".into(),
            max_steps: 4,
            max_tool_calls_per_step: 4,
            max_tokens: 64,
        },
        &TurnOptions::default(),
        &llm,
        &tools,
        &NullSink,
        &StopFlag::default(),
        &mut vec![],
        &wf,
    )
    .expect("verified")
}

const SKILL: &str = "---\nname: deploy-checklist\ndescription: Checks a contract before deploy\n---\n\n1. Run the tests.\n";

fn prov(session: &str) -> Provenance {
    Provenance {
        session_id: session.into(),
        agent: "hermes".into(),
        model: "m".into(),
    }
}
fn skill() -> ProposalContent {
    ProposalContent::Skill {
        skill_md: SKILL.into(),
    }
}
fn memory(key: &str, value: &str) -> ProposalContent {
    ProposalContent::Memory {
        key: key.into(),
        value: value.into(),
    }
}
fn accept() -> MemberAccept {
    MemberAccept {
        member: "member-1".into(),
        acknowledged_conflicts: vec![],
    }
}

struct Env {
    root: tempfile::TempDir,
}
impl Env {
    fn new() -> Self {
        Env {
            root: tempfile::tempdir().unwrap(),
        }
    }
    fn user(&self) -> PathBuf {
        self.root.path().join("skills")
    }
    fn store(&self) -> PathBuf {
        self.root.path().join("learn").join("proposals.json")
    }
    /// Open a learner over the same folders, as a restarted sidecar would.
    fn open(&self) -> (Learner, LoadReport) {
        let log = Arc::new(
            DecisionLog::open(&self.root.path().join("records"), LogConfig::default())
                .unwrap()
                .0,
        );
        Learner::open(
            LearnConfig {
                user_skills_dir: self.user(),
                other_skill_sources: vec![SkillSource::new("bundled", self.root.path().join("b"))],
            },
            log,
            Arc::new(TickClock(Mutex::new(1_700_000_000_000))),
            &self.store(),
        )
    }
}

fn edit_store(path: &Path, f: impl FnOnce(&mut serde_json::Value)) {
    let mut v: serde_json::Value = serde_json::from_slice(&std::fs::read(path).unwrap()).unwrap();
    f(&mut v);
    std::fs::write(path, serde_json::to_vec(&v).unwrap()).unwrap();
}

#[test]
fn undecided_proposals_survive_a_restart_and_can_still_be_accepted() {
    let env = Env::new();
    let run = verified_run("s1");
    let (sid, mid) = {
        let (mut l, report) = env.open();
        assert_eq!(report, LoadReport::default(), "a fresh store is empty");
        let s = l.propose(&run, skill(), prov("s1"), &[]).unwrap();
        let m = l
            .propose(&run, memory("deploy chain", "40204"), prov("s1"), &[])
            .unwrap();
        (s, m)
    };
    assert!(env.store().is_file(), "the proposals file was written");

    let (mut l, report) = env.open();
    assert_eq!(report.loaded, 2);
    assert!(report.dropped.is_empty(), "{:?}", report.dropped);
    let pending: Vec<&Proposal> = l.pending();
    assert_eq!(pending.len(), 2);
    assert_eq!(l.get(&sid.id), Some(&sid), "restored byte for byte");
    assert_eq!(l.get(&mid.id), Some(&mid));

    let out = l.accept(&sid.id, accept()).unwrap();
    match out {
        Persisted::Skill { path, .. } => assert!(path.is_file()),
        other => panic!("{other:?}"),
    }
}

#[test]
fn decisions_survive_a_restart_and_are_never_reopened() {
    let env = Env::new();
    let run = verified_run("s1");
    let (rejected, accepted) = {
        let (mut l, _) = env.open();
        let a = l
            .propose(&run, memory("k1", "v1"), prov("s1"), &[])
            .unwrap();
        let b = l
            .propose(&run, memory("k2", "v2"), prov("s1"), &[])
            .unwrap();
        l.reject(&a.id, "member-1", "not true").unwrap();
        l.accept(&b.id, accept()).unwrap();
        (a.id, b.id)
    };
    let (mut l, report) = env.open();
    assert_eq!(report.loaded, 2);
    assert!(l.pending().is_empty());
    assert!(matches!(
        l.get(&rejected).map(|p| &p.state),
        Some(ProposalState::Rejected { .. })
    ));
    assert!(matches!(
        l.reject(&accepted, "member-1", "again"),
        Err(LearnError::WrongState { .. })
    ));
    // The memory accepted before the restart still counts as known: a disagreeing proposal is a
    // contradiction against it, and accepting it stores Belnap `both`.
    let p = l
        .propose(&run, memory("K2", "something else"), prov("s1"), &[])
        .unwrap();
    assert_eq!(p.conflicts.len(), 1, "{:?}", p.conflicts);
    assert_eq!(p.conflicts[0].kind, ConflictKind::Contradiction);
    assert_eq!(p.conflicts[0].existing_id, format!("proposal:{accepted}"));
    let rec = l
        .accept(
            &p.id,
            MemberAccept {
                member: "member-1".into(),
                acknowledged_conflicts: vec![format!("proposal:{accepted}")],
            },
        )
        .unwrap();
    match rec {
        Persisted::Memory(m) => {
            assert_eq!(m.belnap, Belnap::Both);
            assert_eq!(m.contradicts, vec![format!("proposal:{accepted}")]);
        }
        other => panic!("{other:?}"),
    }
}

#[test]
fn a_skill_accepted_before_a_restart_can_be_published_after_it() {
    let env = Env::new();
    let run = verified_run("s1");
    let p = {
        let (mut l, _) = env.open();
        let p = l.propose(&run, skill(), prov("s1"), &[]).unwrap();
        l.accept(&p.id, accept()).unwrap();
        p
    };
    let (mut l, _) = env.open();
    let payload = l
        .prepare_publish(
            &p.id,
            PublishApproval {
                member: "member-1".into(),
                proposal_id: p.id.clone(),
                content_sha256: p.content_sha256.clone(),
            },
            PublishParams {
                chain_id: 40204,
                registry: format!("0x{}", "11".repeat(20)),
                owner: format!("0x{}", "22".repeat(20)),
                version: "1.0.0".into(),
                manifest_cid: None,
                tags: vec![],
            },
        )
        .unwrap();
    assert!(!payload.broadcast);
    assert!(matches!(
        l.get(&p.id).map(|p| &p.state),
        Some(ProposalState::PublishPrepared)
    ));
    drop(l);
    let (l, _) = env.open();
    assert!(matches!(
        l.get(&p.id).map(|p| &p.state),
        Some(ProposalState::PublishPrepared)
    ));
}

#[test]
fn ids_stay_unique_across_restarts() {
    let env = Env::new();
    let run = verified_run("s1");
    let first = {
        let (mut l, _) = env.open();
        l.propose(&run, memory("a", "1"), prov("s1"), &[])
            .unwrap()
            .id
    };
    let (mut l, _) = env.open();
    let second = l
        .propose(&run, memory("b", "2"), prov("s1"), &[])
        .unwrap()
        .id;
    assert_ne!(first, second);
    assert_eq!(l.pending().len(), 2);
}

#[test]
fn tampered_or_inconsistent_proposals_are_dropped_on_load() {
    let env = Env::new();
    let run = verified_run("s1");
    let ids = {
        let (mut l, _) = env.open();
        let a = l.propose(&run, skill(), prov("s1"), &[]).unwrap().id;
        let b = l
            .propose(&run, memory("k", "v"), prov("s1"), &[])
            .unwrap()
            .id;
        let c = l
            .propose(&run, memory("k3", "v3"), prov("s1"), &[])
            .unwrap()
            .id;
        let d = l
            .propose(&run, memory("k4", "v4"), prov("s1"), &[])
            .unwrap()
            .id;
        [a, b, c, d]
    };
    edit_store(&env.store(), |v| {
        let ps = v["proposals"].as_array_mut().unwrap();
        for p in ps.iter_mut() {
            let id = p["id"].as_str().unwrap().to_string();
            if id == ids[0] {
                // The skill text changed after the hash was taken.
                p["content"]["skill_md"] = serde_json::json!(SKILL.replace("tests", "nothing"));
            } else if id == ids[1] {
                // Evidence from another session.
                p["evidence"]["trajectory"]["session_id"] = serde_json::json!("other");
            } else if id == ids[2] {
                // A verdict that did not pass is not evidence.
                p["evidence"]["verdicts"][0]["passed"] = serde_json::json!(false);
            }
        }
        // A duplicate of the last one.
        let dup = ps.last().unwrap().clone();
        ps.push(dup);
    });
    let (l, report) = env.open();
    assert_eq!(report.loaded, 1, "{report:?}");
    let dropped: Vec<&str> = report.dropped.iter().map(|(id, _)| id.as_str()).collect();
    assert!(dropped.contains(&ids[0].as_str()));
    assert!(dropped.contains(&ids[1].as_str()));
    assert!(dropped.contains(&ids[2].as_str()));
    assert!(dropped.contains(&ids[3].as_str()), "the duplicate is named");
    assert!(l.get(&ids[0]).is_none());
    assert!(l.get(&ids[3]).is_some(), "the first copy is kept");
}

#[test]
fn an_unreadable_file_is_moved_aside_and_the_learner_starts_empty() {
    let env = Env::new();
    std::fs::create_dir_all(env.store().parent().unwrap()).unwrap();
    std::fs::write(env.store(), b"{ not json").unwrap();
    let (mut l, report) = env.open();
    assert_eq!(report.loaded, 0);
    let aside = report.moved_aside.expect("moved aside");
    assert_eq!(
        std::fs::read(&aside).unwrap(),
        b"{ not json",
        "kept, never deleted"
    );
    assert!(l.pending().is_empty());
    let run = verified_run("s1");
    l.propose(&run, memory("k", "v"), prov("s1"), &[]).unwrap();
    drop(l);
    let (_, report) = env.open();
    assert_eq!(report.loaded, 1, "a fresh file replaced it");
}

#[test]
fn a_file_with_an_unknown_schema_is_moved_aside() {
    let env = Env::new();
    std::fs::create_dir_all(env.store().parent().unwrap()).unwrap();
    std::fs::write(
        env.store(),
        br#"{"schema":"citrate.learn.proposals.v9","counter":0,"proposals":[]}"#,
    )
    .unwrap();
    let (_, report) = env.open();
    assert!(report.moved_aside.is_some());
}

#[test]
fn a_proposal_that_cannot_be_saved_is_not_kept() {
    let env = Env::new();
    // The store's folder is a file, so nothing can be written there.
    std::fs::write(env.root.path().join("learn"), b"").unwrap();
    let (mut l, _) = env.open();
    let run = verified_run("s1");
    let err = l
        .propose(&run, memory("k", "v"), prov("s1"), &[])
        .unwrap_err();
    assert!(matches!(err, LearnError::Store(_)), "{err:?}");
    assert!(
        l.pending().is_empty(),
        "rolled back: nothing a restart would lose"
    );
}

#[test]
fn the_file_is_written_atomically_and_privately() {
    let env = Env::new();
    let (mut l, _) = env.open();
    let run = verified_run("s1");
    l.propose(&run, memory("k", "v"), prov("s1"), &[]).unwrap();
    let dir = env.store().parent().unwrap().to_path_buf();
    let names: Vec<String> = std::fs::read_dir(&dir)
        .unwrap()
        .map(|e| e.unwrap().file_name().to_string_lossy().into_owned())
        .collect();
    assert_eq!(
        names,
        vec!["proposals.json".to_string()],
        "no temp file left"
    );
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        let mode = std::fs::metadata(env.store()).unwrap().permissions().mode() & 0o777;
        assert_eq!(mode, 0o600);
    }
    assert!(l.store_error().is_none());
}

#[test]
fn a_learner_without_a_store_writes_no_file() {
    let env = Env::new();
    let log = Arc::new(
        DecisionLog::open(&env.root.path().join("records"), LogConfig::default())
            .unwrap()
            .0,
    );
    let mut l = Learner::new(
        LearnConfig {
            user_skills_dir: env.user(),
            other_skill_sources: vec![],
        },
        log,
    );
    let run = verified_run("s1");
    l.propose(&run, memory("k", "v"), prov("s1"), &[]).unwrap();
    assert!(!env.store().exists());
    assert!(l.store_error().is_none());
}

// ---- the decision log wins over a stale proposals file ----------------------------------------

/// Simulate a save that was lost: put back the file as it was before the decision.
fn restore_file(path: &Path, bytes: &[u8]) {
    std::fs::write(path, bytes).unwrap();
}

#[test]
fn a_reject_whose_save_was_lost_is_still_final_after_a_restart() {
    let env = Env::new();
    let run = verified_run("s1");
    let id = {
        let (mut l, _) = env.open();
        let p = l.propose(&run, skill(), prov("s1"), &[]).unwrap();
        let before = std::fs::read(env.store()).unwrap();
        l.reject(&p.id, "member-1", "no").unwrap();
        drop(l);
        restore_file(&env.store(), &before);
        p.id
    };
    let (mut l, report) = env.open();
    assert_eq!(report.reconciled, 1, "{report:?}");
    assert!(
        matches!(l.get(&id).map(|p| &p.state), Some(ProposalState::Rejected { by, .. }) if by == "member-1"),
        "{:?}",
        l.get(&id)
    );
    assert!(matches!(
        l.accept(&id, accept()),
        Err(LearnError::WrongState { .. })
    ));
    assert!(!env.user().join("deploy-checklist").exists());
}

#[test]
fn a_skill_accept_whose_save_was_lost_is_persisted_after_a_restart() {
    let env = Env::new();
    let run = verified_run("s1");
    let p = {
        let (mut l, _) = env.open();
        let p = l.propose(&run, skill(), prov("s1"), &[]).unwrap();
        let before = std::fs::read(env.store()).unwrap();
        l.accept(&p.id, accept()).unwrap();
        drop(l);
        restore_file(&env.store(), &before);
        p
    };
    let (mut l, report) = env.open();
    assert_eq!(report.reconciled, 1);
    assert!(matches!(
        l.get(&p.id).map(|p| &p.state),
        Some(ProposalState::Persisted)
    ));
    // Publishing still works from the reconciled state.
    l.prepare_publish(
        &p.id,
        PublishApproval {
            member: "member-1".into(),
            proposal_id: p.id.clone(),
            content_sha256: p.content_sha256.clone(),
        },
        PublishParams {
            chain_id: 40204,
            registry: format!("0x{}", "11".repeat(20)),
            owner: format!("0x{}", "22".repeat(20)),
            version: "1.0.0".into(),
            manifest_cid: None,
            tags: vec![],
        },
    )
    .unwrap();
}

#[test]
fn a_memory_accept_whose_save_was_lost_can_be_accepted_again() {
    // The memory record may never have reached core, so the learner offers it again rather than
    // calling it done. Core stores records by proposal id, so a second accept is not a duplicate.
    let env = Env::new();
    let run = verified_run("s1");
    let id = {
        let (mut l, _) = env.open();
        let p = l.propose(&run, memory("k", "v"), prov("s1"), &[]).unwrap();
        let before = std::fs::read(env.store()).unwrap();
        l.accept(&p.id, accept()).unwrap();
        drop(l);
        restore_file(&env.store(), &before);
        p.id
    };
    let (mut l, report) = env.open();
    assert_eq!(report.reconciled, 1);
    match l.get(&id).map(|p| &p.state) {
        Some(ProposalState::PersistFailed { reason }) => {
            assert!(reason.contains("accept again"), "{reason}");
            // The reason is shown to the member: no stray source-indentation runs.
            assert!(!reason.contains("  "), "{reason:?}")
        }
        other => panic!("{other:?}"),
    }
    let rec = l.accept(&id, accept()).unwrap();
    assert!(matches!(rec, Persisted::Memory(m) if m.proposal_id == id));
}

#[test]
fn a_consistent_file_needs_no_reconciling() {
    let env = Env::new();
    let run = verified_run("s1");
    {
        let (mut l, _) = env.open();
        let a = l.propose(&run, skill(), prov("s1"), &[]).unwrap();
        let b = l.propose(&run, memory("k", "v"), prov("s1"), &[]).unwrap();
        l.accept(&a.id, accept()).unwrap();
        l.reject(&b.id, "member-1", "no").unwrap();
    }
    let (_, report) = env.open();
    assert_eq!(report.reconciled, 0);
}

#[test]
fn a_resolution_whose_save_was_lost_is_still_applied_after_a_restart() {
    let env = Env::new();
    let run = verified_run("s1");
    let (a, b) = {
        let (mut l, _) = env.open();
        let a = l
            .propose(&run, memory("k", "one"), prov("s1"), &[])
            .unwrap();
        l.accept(&a.id, accept()).unwrap();
        let b = l
            .propose(&run, memory("k", "two"), prov("s1"), &[])
            .unwrap();
        l.accept(
            &b.id,
            MemberAccept {
                member: "member-1".into(),
                acknowledged_conflicts: vec![format!("proposal:{}", a.id)],
            },
        )
        .unwrap();
        let before = std::fs::read(env.store()).unwrap();
        l.resolve(MemberResolve {
            member: "member-1".into(),
            keep: a.id.clone(),
            retract: b.id.clone(),
        })
        .unwrap();
        drop(l);
        restore_file(&env.store(), &before);
        (a, b)
    };
    let (l, report) = env.open();
    assert_eq!(report.reconciled, 1, "{report:?}");
    match l.get(&b.id).map(|p| &p.state) {
        Some(ProposalState::Retracted { by, kept }) => {
            assert_eq!(by, "member-1");
            assert_eq!(kept, &a.id);
        }
        other => panic!("{other:?}"),
    }
    assert!(matches!(
        l.get(&a.id).map(|p| &p.state),
        Some(ProposalState::Persisted)
    ));
}

#[test]
fn a_retracted_proposal_is_restored_from_the_file() {
    let env = Env::new();
    let run = verified_run("s1");
    let b = {
        let (mut l, _) = env.open();
        let a = l
            .propose(&run, memory("k", "one"), prov("s1"), &[])
            .unwrap();
        l.accept(&a.id, accept()).unwrap();
        let b = l
            .propose(&run, memory("k", "two"), prov("s1"), &[])
            .unwrap();
        l.accept(
            &b.id,
            MemberAccept {
                member: "member-1".into(),
                acknowledged_conflicts: vec![format!("proposal:{}", a.id)],
            },
        )
        .unwrap();
        l.resolve(MemberResolve {
            member: "member-1".into(),
            keep: a.id.clone(),
            retract: b.id.clone(),
        })
        .unwrap();
        b
    };
    let (l, report) = env.open();
    assert_eq!(report.reconciled, 0, "{report:?}");
    assert!(report.dropped.is_empty(), "{report:?}");
    assert!(matches!(
        l.get(&b.id).map(|p| &p.state),
        Some(ProposalState::Retracted { .. })
    ));
}

#[test]
fn a_resolution_is_applied_even_when_the_accept_before_it_was_lost_too() {
    // Found by formal/ContradictionResolve.tla: the file lost both the accept and the resolve of
    // the retracted memory. The log has both; the memory must come back retracted, not offered
    // for accepting again (which would bring back what the member set aside).
    let env = Env::new();
    let run = verified_run("s1");
    let (a, b) = {
        let (mut l, _) = env.open();
        let a = l
            .propose(&run, memory("k", "one"), prov("s1"), &[])
            .unwrap();
        l.accept(&a.id, accept()).unwrap();
        let b = l
            .propose(&run, memory("k", "two"), prov("s1"), &[])
            .unwrap();
        let before = std::fs::read(env.store()).unwrap();
        l.accept(
            &b.id,
            MemberAccept {
                member: "member-1".into(),
                acknowledged_conflicts: vec![format!("proposal:{}", a.id)],
            },
        )
        .unwrap();
        l.resolve(MemberResolve {
            member: "member-1".into(),
            keep: a.id.clone(),
            retract: b.id.clone(),
        })
        .unwrap();
        drop(l);
        restore_file(&env.store(), &before);
        (a, b)
    };
    let (mut l, report) = env.open();
    assert_eq!(report.reconciled, 1, "{report:?}");
    match l.get(&b.id).map(|p| &p.state) {
        Some(ProposalState::Retracted { kept, .. }) => assert_eq!(kept, &a.id),
        other => panic!("{other:?}"),
    }
    assert!(matches!(
        l.accept(&b.id, accept()),
        Err(LearnError::WrongState { .. })
    ));
}

#[test]
fn a_memory_offered_again_after_a_lost_save_still_counts_as_accepted_for_contradictions() {
    // Found by formal/ContradictionResolve.tla: the accept of `a` was recorded and core may hold
    // its record, but the file lost it, so `a` is offered again. A later memory that disagrees
    // must be a contradiction (stored as `both`), not a plain pending clash stored as `true`.
    let env = Env::new();
    let run = verified_run("s1");
    let a = {
        let (mut l, _) = env.open();
        let a = l
            .propose(&run, memory("k", "one"), prov("s1"), &[])
            .unwrap();
        let before = std::fs::read(env.store()).unwrap();
        l.accept(&a.id, accept()).unwrap();
        drop(l);
        restore_file(&env.store(), &before);
        a
    };
    let (mut l, _) = env.open();
    assert!(matches!(
        l.get(&a.id).map(|p| &p.state),
        Some(ProposalState::PersistFailed { .. })
    ));
    let b = l
        .propose(&run, memory("k", "two"), prov("s1"), &[])
        .unwrap();
    let a_ref = format!("proposal:{}", a.id);
    assert_eq!(b.conflicts.len(), 1, "{:?}", b.conflicts);
    assert_eq!(b.conflicts[0].kind, ConflictKind::Contradiction);
    assert_eq!(b.conflicts[0].existing_id, a_ref);
    let rec = l
        .accept(
            &b.id,
            MemberAccept {
                member: "member-1".into(),
                acknowledged_conflicts: vec![a_ref.clone()],
            },
        )
        .unwrap();
    match rec {
        Persisted::Memory(m) => {
            assert_eq!(m.belnap, Belnap::Both);
            assert_eq!(m.contradicts, vec![a_ref]);
        }
        other => panic!("{other:?}"),
    }
}
