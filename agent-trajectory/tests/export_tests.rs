//! HUP-S9.3: only verified turns are exported, tainted sessions never are (unless explicitly
//! allowed), and every exported line is redacted.
use citrate_agent_loop::*;
use citrate_agent_trajectory::*;
use std::sync::{Arc, Mutex};

struct Script(Mutex<Vec<AssistantTurn>>);
impl LlmClient for Script {
    fn complete(&self, _r: &CompletionRequest) -> Result<AssistantTurn, LlmError> {
        let mut t = self.0.lock().unwrap();
        Ok(if t.is_empty() {
            AssistantTurn::text("done")
        } else {
            t.remove(0)
        })
    }
}
struct Host(ToolOutcome);
impl ToolHost for Host {
    fn execute(&self, _c: &ToolCall) -> ToolOutcome {
        self.0.clone()
    }
}
#[derive(Default)]
struct Capture(Mutex<Vec<Event>>);
impl EventSink for Capture {
    fn emit(&self, e: Event) {
        self.0.lock().unwrap().push(e);
    }
}

fn spec(n: &str, trust: Trust) -> ToolSpec {
    ToolSpec {
        name: n.into(),
        description: n.into(),
        parameters: serde_json::json!({"type":"object"}),
        host: HostKind::Core,
        annotations: ToolAnnotations {
            effect: Some(Effect::None),
            trust: Some(trust),
            ..Default::default()
        },
    }
}
fn call(id: &str, n: &str, args: &str) -> AssistantTurn {
    AssistantTurn::tools(vec![ToolCall {
        id: id.into(),
        name: n.into(),
        arguments: args.into(),
    }])
}
fn cfg() -> LoopConfig {
    LoopConfig {
        model: "gemma-4-e4b".into(),
        system_prompt: "SYSTEM-PROMPT-CANARY".into(),
        max_steps: 4,
        max_tool_calls_per_step: 4,
        max_tokens: 64,
    }
}
fn deploy_workflow() -> Workflow {
    Workflow::new(
        "hello-mint",
        vec![Step {
            id: "test".into(),
            instruction: "run the tests in /Users/member/work/app and mail me@example.com".into(),
            verifiers: vec![Arc::new(ToolSucceeded("forge_test".into()))],
            max_attempts: 2,
        }],
    )
    .unwrap()
}
fn policy() -> ExportPolicy {
    ExportPolicy::new()
        .with_granted_root("/Users/member/work/app")
        .with_home("/Users/member")
}

/// Runs the hello-mint test step: attempt 1 claims success without testing (fails its
/// verifier), attempt 2 runs forge_test (passes). Optionally reads a web page first (taint).
fn run(read_web_first: bool, taint: TaintState) -> (TrajectoryRecorder, Vec<Message>) {
    let mut turns = vec![];
    if read_web_first {
        turns.push(call("w", "web_fetch", "{}"));
        turns.push(AssistantTurn::text("read it"));
    }
    turns.extend([
        AssistantTurn::text("All tests pass!"),
        call(
            "t",
            "forge_test",
            r#"{"root":"/Users/member/work/app","rpc":"https://x.example/?token=abcd1234"}"#,
        ),
        AssistantTurn::text("2 passed. Deployer 0x9D5d16FD1c2bF9a1E9C1b1f0C3d5B6b7a8e9F0a1."),
    ]);
    let llm = Script(Mutex::new(turns));
    let tools = ToolRegistry::new(vec![
        spec("forge_test", Trust::Trusted),
        spec("web_fetch", Trust::Untrusted),
    ])
    .with_host(
        HostKind::Core,
        Arc::new(Host(ToolOutcome::Ok(
            "{\"passed\":2,\"log\":\"/Users/member/.cache/forge/log.txt\"}".into(),
        ))),
    )
    .with_taint(taint.clone());
    let inner = Arc::new(Capture::default());
    let rec = TrajectoryRecorder::new("sess-1", "gemma-4-e4b", taint)
        .with_workflow("hello-mint")
        .forwarding_to(inner.clone());
    let mut history = vec![];
    if read_web_first {
        run_turn(
            &cfg(),
            &llm,
            &tools,
            &rec,
            &StopFlag::default(),
            &mut history,
            "read the docs",
        );
    }
    let out = run_workflow(
        &cfg(),
        &TurnOptions::default(),
        &llm,
        &tools,
        &rec,
        &StopFlag::default(),
        &mut history,
        &deploy_workflow(),
    );
    assert!(matches!(out, WorkflowOutcome::Succeeded { .. }), "{out:?}");
    assert!(!inner.0.lock().unwrap().is_empty(), "events are forwarded");
    (rec, history)
}

#[test]
fn only_the_verified_attempt_is_exported_and_it_is_redacted() {
    let (rec, history) = run(false, TaintState::default());
    let trajs = rec.trajectories(&history).unwrap();
    assert_eq!(trajs.len(), 2);
    assert_eq!(trajs[0].eligibility(), Eligibility::VerifierFailed);
    assert_eq!(trajs[1].eligibility(), Eligibility::Verified);
    assert_eq!(trajs[1].step.as_deref(), Some("test"));
    assert_eq!(trajs[1].workflow.as_deref(), Some("hello-mint"));

    let ex = export_verified(&trajs, &policy()).unwrap();
    assert_eq!(ex.examples.len(), 1);
    let r = &ex.report;
    assert_eq!((r.considered, r.exported), (2, 1));
    assert_eq!(r.excluded.verifier_failed, 1);

    let jsonl = ex.to_jsonl().unwrap();
    assert_eq!(jsonl.lines().count(), 1);
    let line: serde_json::Value = serde_json::from_str(jsonl.lines().next().unwrap()).unwrap();
    let msgs = line["messages"].as_array().unwrap();
    assert_eq!(msgs[0]["role"], "user");
    assert!(msgs[0]["content"]
        .as_str()
        .unwrap()
        .starts_with("run the tests in [root:0] and mail [REDACTED:email]"));
    assert_eq!(msgs[1]["tool_calls"][0]["function"]["name"], "forge_test");
    let args = msgs[1]["tool_calls"][0]["function"]["arguments"]
        .as_str()
        .unwrap();
    assert!(args.contains(r#""root":"[root:0]""#), "{args}");
    assert!(args.contains("token=[REDACTED:secret]"), "{args}");
    assert_eq!(msgs[2]["role"], "tool");
    assert!(msgs[2]["content"]
        .as_str()
        .unwrap()
        .contains("[REDACTED:path]"));
    assert!(msgs[3]["content"]
        .as_str()
        .unwrap()
        .contains("Deployer [REDACTED:address]."));
    assert_eq!(line["metadata"]["verifiers"][0], "forge_test succeeded");

    for leaked in [
        "/Users/member",
        "me@example.com",
        "abcd1234",
        "0x9D5d16FD1c2bF9a1E9C1b1f0C3d5B6b7a8e9F0a1",
        "All tests pass!",
        "SYSTEM-PROMPT-CANARY",
    ] {
        assert!(!jsonl.contains(leaked), "{leaked} in {jsonl}");
    }
    assert_eq!(r.totals.get(Category::Email), 1);
    assert_eq!(r.totals.get(Category::Address), 1);
    assert_eq!(r.totals.get(Category::Secret), 1);
    assert_eq!(r.totals.get(Category::Path), 1);
    assert_eq!(r.totals.relativised, 2);
    assert_eq!(r.per_example.len(), 1);
    assert_eq!(r.per_example[0].total(), 4);
}

#[test]
fn the_report_never_contains_a_redacted_value() {
    let (rec, history) = run(false, TaintState::default());
    let ex = export_verified(&rec.trajectories(&history).unwrap(), &policy()).unwrap();
    let report = serde_json::to_string(&ex.report).unwrap();
    for leaked in ["/Users/member", "me@example.com", "abcd1234", "9D5d16FD"] {
        assert!(!report.contains(leaked), "{leaked} in report");
    }
}

#[test]
fn an_allowed_address_survives_the_export() {
    let (rec, history) = run(false, TaintState::default());
    let p = policy().allow_address("0x9d5d16fd1c2bf9a1e9c1b1f0c3d5b6b7a8e9f0a1");
    let jsonl = export_verified(&rec.trajectories(&history).unwrap(), &p)
        .unwrap()
        .to_jsonl()
        .unwrap();
    assert!(jsonl.contains("0x9D5d16FD1c2bF9a1E9C1b1f0C3d5B6b7a8e9F0a1"));
}

#[test]
fn a_tainted_session_exports_nothing_by_default() {
    let (rec, history) = run(true, TaintState::default());
    let trajs = rec.trajectories(&history).unwrap();
    assert_eq!(trajs.len(), 3);
    assert!(
        trajs.iter().all(|t| t.session_tainted),
        "taint is session-wide"
    );
    let ex = export_verified(&trajs, &policy()).unwrap();
    assert!(ex.examples.is_empty());
    assert_eq!(ex.report.excluded.tainted_session, 3);
    assert_eq!(ex.report.tainted_sessions_allowed, None);
    assert_eq!(ex.to_jsonl().unwrap(), "");
}

#[test]
fn tainted_sessions_need_an_explicit_reasoned_allowance() {
    assert!(matches!(
        policy().allow_tainted_sessions("  "),
        Err(TrajectoryError::EmptyReason)
    ));
    let (rec, history) = run(true, TaintState::default());
    let p = policy()
        .allow_tainted_sessions("member reviewed this session")
        .unwrap();
    let ex = export_verified(&rec.trajectories(&history).unwrap(), &p).unwrap();
    assert_eq!(ex.examples.len(), 1, "still only the verified attempt");
    assert_eq!(
        ex.report.tainted_sessions_allowed.as_deref(),
        Some("member reviewed this session")
    );
}

#[test]
fn taint_from_before_the_recorder_or_cleared_since_still_excludes() {
    // Tainted before the recorder was attached.
    let pre = TaintState::default();
    pre.taint("web_fetch", "earlier");
    let (rec, history) = run(false, pre);
    let ex = export_verified(&rec.trajectories(&history).unwrap(), &policy()).unwrap();
    assert!(ex.examples.is_empty());

    // Tainted during the session, then cleared by a member: the content is still in the turns.
    let t = TaintState::default();
    let (rec, history) = run(true, t.clone());
    t.clear_by_member(MemberClear::new("looked fine").unwrap());
    let ex = export_verified(&rec.trajectories(&history).unwrap(), &policy()).unwrap();
    assert!(ex.examples.is_empty());
}

#[test]
fn a_history_that_does_not_line_up_with_the_recorded_turns_is_refused() {
    let (rec, mut history) = run(false, TaintState::default());
    assert!(matches!(
        rec.trajectories(&history[1..]),
        Err(TrajectoryError::Misaligned { .. })
    ));
    history.push(Message::user("an extra turn the recorder never saw"));
    assert!(matches!(
        rec.trajectories(&history),
        Err(TrajectoryError::Misaligned { .. })
    ));
}

fn manual(outcome: &str, verdicts: &[bool]) -> TurnTrajectory {
    TurnTrajectory {
        session_id: "s".into(),
        model: "m".into(),
        workflow: None,
        step: Some("x".into()),
        outcome: outcome.into(),
        messages: vec![Message::user("hi")],
        verifiers: verdicts
            .iter()
            .map(|p| VerifierVerdict {
                name: "v".into(),
                passed: *p,
            })
            .collect(),
        session_tainted: false,
    }
}

#[test]
fn eligibility_needs_an_answer_and_every_verifier_passing() {
    assert_eq!(
        manual("answered", &[true, true]).eligibility(),
        Eligibility::Verified
    );
    assert_eq!(
        manual("answered", &[]).eligibility(),
        Eligibility::Unverified
    );
    assert_eq!(
        manual("answered", &[true, false]).eligibility(),
        Eligibility::VerifierFailed
    );
    assert_eq!(
        manual("stopped", &[true]).eligibility(),
        Eligibility::NotAnswered
    );
    let mut t = manual("answered", &[true]);
    t.session_tainted = true;
    assert_eq!(
        t.eligibility(),
        Eligibility::Verified,
        "taint is policy, not verification"
    );
    let ex = export_verified(
        &[
            manual("answered", &[]),
            manual("stopped", &[true]),
            manual("answered", &[true]),
        ],
        &ExportPolicy::new(),
    )
    .unwrap();
    assert_eq!(ex.report.excluded.unverified, 1);
    assert_eq!(ex.report.excluded.not_answered, 1);
    assert_eq!(ex.report.exported, 1);
}

#[test]
fn plain_turns_without_a_workflow_are_unverified() {
    let llm = Script(Mutex::new(vec![AssistantTurn::text("hello")]));
    let tools = ToolRegistry::new(vec![]);
    let rec = TrajectoryRecorder::new("s", "m", TaintState::default());
    let mut h = vec![];
    run_turn(
        &cfg(),
        &llm,
        &tools,
        &rec,
        &StopFlag::default(),
        &mut h,
        "hi",
    );
    let trajs = rec.trajectories(&h).unwrap();
    assert_eq!(trajs[0].eligibility(), Eligibility::Unverified);
    assert!(export_verified(&trajs, &ExportPolicy::new())
        .unwrap()
        .examples
        .is_empty());
}

#[test]
fn writing_never_overwrites_an_existing_file() {
    let (rec, history) = run(false, TaintState::default());
    let ex = export_verified(&rec.trajectories(&history).unwrap(), &policy()).unwrap();
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("train.jsonl");
    ex.write_jsonl(&path).unwrap();
    let body = std::fs::read_to_string(&path).unwrap();
    assert_eq!(body, ex.to_jsonl().unwrap());
    assert!(matches!(ex.write_jsonl(&path), Err(TrajectoryError::Io(_))));
}

#[cfg(unix)]
#[test]
fn the_written_training_set_is_readable_only_by_the_member() {
    use std::os::unix::fs::PermissionsExt;
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("perm.jsonl");
    let ex = export_verified(&[], &ExportPolicy::new()).unwrap();
    ex.write_jsonl(&path).unwrap();
    let mode = std::fs::metadata(&path).unwrap().permissions().mode() & 0o777;
    assert_eq!(mode, 0o600);
}

/// US-1.3 AC2: the model's self-review arrives after an attempt's `done`, like a verdict. It is
/// an opinion: it must not open a turn of its own, or every later verdict would be filed under
/// the next attempt and a failed attempt could be exported as verified.
#[test]
fn a_self_review_opinion_does_not_shift_verdicts_onto_the_next_attempt() {
    struct AlwaysPass;
    impl SelfReviewer for AlwaysPass {
        fn review(&self, _r: &ReviewRequest, _h: &[Message]) -> Result<String, String> {
            Ok("PASS: looks done to me.".into())
        }
    }
    let llm = Script(Mutex::new(vec![
        AssistantTurn::text("All tests pass!"),
        call("t", "forge_test", "{}"),
        AssistantTurn::text("2 passed."),
    ]));
    let tools = ToolRegistry::new(vec![spec("forge_test", Trust::Trusted)]).with_host(
        HostKind::Core,
        Arc::new(Host(ToolOutcome::Ok("{\"passed\":2}".into()))),
    );
    let inner = Arc::new(Capture::default());
    let rec = TrajectoryRecorder::new("sess-1", "gemma-4-e4b", TaintState::default())
        .with_workflow("hello-mint")
        .forwarding_to(inner.clone());
    let mut history = vec![];
    let out = run_workflow_reviewed(
        &cfg(),
        &TurnOptions::default(),
        &llm,
        &tools,
        &rec,
        &StopFlag::default(),
        &mut history,
        &deploy_workflow(),
        Some(&AlwaysPass),
    );
    assert!(matches!(out, WorkflowOutcome::Succeeded { .. }), "{out:?}");
    let opinions = inner
        .0
        .lock()
        .unwrap()
        .iter()
        .filter(|e| matches!(e, Event::SelfReview { .. }))
        .count();
    assert_eq!(opinions, 2, "the opinions are still forwarded");
    let trajs = rec.trajectories(&history).unwrap();
    assert_eq!(trajs.len(), 2);
    assert_eq!(trajs[0].eligibility(), Eligibility::VerifierFailed);
    assert_eq!(trajs[1].eligibility(), Eligibility::Verified);
}
