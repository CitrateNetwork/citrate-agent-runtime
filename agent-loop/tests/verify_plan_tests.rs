//! HUP-S1.3 / US-1.3 AC2: the HTTP-status and content-hash verifiers, the model's self-review
//! recorded as a labelled opinion that never decides an outcome, and the model-driven planner
//! whose every proposed step must carry a verifier.
//!
//! The probes here are test hosts with fixed answers; the sidecar's real probes (loopback or
//! consented origins only, folder grants only) are tested in agent-sidecar.
use citrate_agent_loop::planner::{ModelPlanner, PlanError};
use citrate_agent_loop::workflows::{VerifierEnv, VerifierSpec};
use citrate_agent_loop::*;
use std::collections::HashMap;
use std::sync::{Arc, Mutex};
use std::time::Duration;

struct Script {
    turns: Mutex<Vec<AssistantTurn>>,
    seen: Mutex<Vec<CompletionRequest>>,
}
impl Script {
    fn new(t: Vec<AssistantTurn>) -> Self {
        Script {
            turns: Mutex::new(t),
            seen: Mutex::new(vec![]),
        }
    }
    fn seen(&self) -> Vec<CompletionRequest> {
        self.seen.lock().unwrap().clone()
    }
}
impl LlmClient for Script {
    fn complete(&self, req: &CompletionRequest) -> Result<AssistantTurn, LlmError> {
        self.seen.lock().unwrap().push(req.clone());
        let mut t = self.turns.lock().unwrap();
        if t.is_empty() {
            return Err(LlmError::Provider("script exhausted".into()));
        }
        Ok(t.remove(0))
    }
}

#[derive(Default)]
struct Sink(Mutex<Vec<Event>>);
impl EventSink for Sink {
    fn emit(&self, e: Event) {
        self.0.lock().unwrap().push(e);
    }
}
impl Sink {
    fn events(&self) -> Vec<Event> {
        self.0.lock().unwrap().clone()
    }
}

/// Fixed answers per URL; an absent URL is "unreachable".
struct Statuses(HashMap<String, Result<u16, String>>, Mutex<Vec<Duration>>);
impl HttpProbe for Statuses {
    fn status(&self, url: &str, timeout: Duration) -> Result<u16, String> {
        self.1.lock().unwrap().push(timeout);
        self.0
            .get(url)
            .cloned()
            .unwrap_or_else(|| Err(format!("{url} is unreachable")))
    }
}
fn statuses(pairs: &[(&str, Result<u16, String>)]) -> Arc<Statuses> {
    Arc::new(Statuses(
        pairs
            .iter()
            .map(|(u, r)| (u.to_string(), r.clone()))
            .collect(),
        Mutex::new(vec![]),
    ))
}

/// Fixed digests per path; a path outside the grant is refused by the host.
struct Digests(HashMap<String, Result<String, String>>);
impl FileDigest for Digests {
    fn sha256_hex(&self, path: &str) -> Result<String, String> {
        self.0
            .get(path)
            .cloned()
            .unwrap_or_else(|| Err(format!("{path} is outside every folder grant")))
    }
}

const HELLO_SHA: &str = "2cf24dba5fb0a30e26e83b2ac5b9e29e1b161e5c1fa7425e73043362938b9824";

fn ctx<'a>(answer: &'a str) -> VerifyContext<'a> {
    VerifyContext {
        step: "s",
        answer,
        tools: &[],
    }
}

// ---- HttpStatusIs ---------------------------------------------------------------------------

#[test]
fn http_status_passes_on_the_expected_status() {
    let p = statuses(&[("http://127.0.0.1:8080/health", Ok(200))]);
    let v = HttpStatusIs::new("http://127.0.0.1:8080/health", 200, p.clone());
    assert_eq!(v.verify(&ctx("")), Verdict::Pass);
    assert_eq!(v.name(), "GET http://127.0.0.1:8080/health is 200");
}

#[test]
fn http_status_fails_on_another_status() {
    let p = statuses(&[("http://127.0.0.1:8080/health", Ok(503))]);
    let v = HttpStatusIs::new("http://127.0.0.1:8080/health", 200, p);
    match v.verify(&ctx("it is up")) {
        Verdict::Fail(why) => assert!(why.contains("503"), "{why}"),
        Verdict::Pass => panic!("a 503 must not pass a 200 check"),
    }
}

#[test]
fn http_status_fails_when_the_url_is_unreachable() {
    let p = statuses(&[]);
    let v = HttpStatusIs::new("http://127.0.0.1:9/none", 200, p);
    match v.verify(&ctx("")) {
        Verdict::Fail(why) => assert!(why.contains("unreachable"), "{why}"),
        Verdict::Pass => panic!("an unreachable URL must fail"),
    }
}

#[test]
fn http_status_uses_a_bounded_timeout() {
    let p = statuses(&[("http://127.0.0.1:1/", Ok(200))]);
    let v = HttpStatusIs::new("http://127.0.0.1:1/", 200, p.clone())
        .with_timeout(Duration::from_secs(600));
    assert_eq!(v.verify(&ctx("")), Verdict::Pass);
    let seen = p.1.lock().unwrap().clone();
    assert_eq!(seen, vec![HTTP_VERIFIER_MAX_TIMEOUT]);
    assert!(HTTP_VERIFIER_MAX_TIMEOUT <= Duration::from_secs(10));
}

// ---- Sha256Equals ---------------------------------------------------------------------------

#[test]
fn sha256_passes_on_a_matching_digest_in_any_case() {
    let d = Arc::new(Digests(
        [("/work/out.txt".to_string(), Ok(HELLO_SHA.to_string()))].into(),
    ));
    let v = Sha256Equals::new("/work/out.txt", &HELLO_SHA.to_uppercase(), d);
    assert_eq!(v.verify(&ctx("")), Verdict::Pass);
}

#[test]
fn sha256_fails_on_another_digest() {
    let d = Arc::new(Digests(
        [("/work/out.txt".to_string(), Ok("00".repeat(32)))].into(),
    ));
    let v = Sha256Equals::new("/work/out.txt", HELLO_SHA, d);
    match v.verify(&ctx("the file is right")) {
        Verdict::Fail(why) => assert!(why.contains("does not match"), "{why}"),
        Verdict::Pass => panic!("a different digest must fail"),
    }
}

#[test]
fn sha256_fails_for_a_path_outside_the_grant() {
    let d = Arc::new(Digests(HashMap::new()));
    let v = Sha256Equals::new("/etc/passwd", HELLO_SHA, d);
    match v.verify(&ctx("")) {
        Verdict::Fail(why) => assert!(why.contains("outside"), "{why}"),
        Verdict::Pass => panic!("a path outside the grant must fail"),
    }
}

// ---- VerifierSpec kinds ---------------------------------------------------------------------

fn parse(v: serde_json::Value) -> VerifierSpec {
    serde_json::from_value(v).unwrap()
}

#[test]
fn the_new_kinds_parse_and_need_their_host() {
    let http = parse(
        serde_json::json!({"kind": "http_status_is", "url": "http://127.0.0.1:3000/", "status": 200}),
    );
    let sha =
        parse(serde_json::json!({"kind": "sha256_equals", "path": "/work/a", "hex": HELLO_SHA}));
    // The bundled catalog has no probes, so it cannot build either kind.
    assert!(http.build().is_err());
    assert!(sha.build().is_err());
    let env = VerifierEnv {
        http: Some(statuses(&[("http://127.0.0.1:3000/", Ok(200))])),
        files: Some(Arc::new(Digests(
            [("/work/a".to_string(), Ok(HELLO_SHA.to_string()))].into(),
        ))),
    };
    let h = http.build_in(&env).unwrap();
    let s = sha.build_in(&env).unwrap();
    assert_eq!(h.verify(&ctx("")), Verdict::Pass);
    assert_eq!(s.verify(&ctx("")), Verdict::Pass);
    assert_eq!(http.tool(), None);
    assert!(!http.requires_call());
    assert!(http.reads_a_tool_report() && sha.reads_a_tool_report());
}

#[test]
fn malformed_new_kinds_are_refused() {
    let env = VerifierEnv {
        http: Some(statuses(&[])),
        files: Some(Arc::new(Digests(HashMap::new()))),
    };
    for bad in [
        serde_json::json!({"kind": "http_status_is", "url": "", "status": 200}),
        serde_json::json!({"kind": "http_status_is", "url": "ftp://127.0.0.1/", "status": 200}),
        serde_json::json!({"kind": "http_status_is", "url": "http://127.0.0.1/", "status": 99}),
        serde_json::json!({"kind": "http_status_is", "url": "http://127.0.0.1/", "status": 600}),
        serde_json::json!({"kind": "sha256_equals", "path": "", "hex": HELLO_SHA}),
        serde_json::json!({"kind": "sha256_equals", "path": "/a", "hex": "abc"}),
        serde_json::json!({"kind": "sha256_equals", "path": "/a", "hex": "zz".repeat(32)}),
    ] {
        assert!(parse(bad.clone()).build_in(&env).is_err(), "{bad}");
    }
}

// ---- Self-review as an opinion --------------------------------------------------------------

fn cfg() -> LoopConfig {
    LoopConfig {
        model: "m".into(),
        system_prompt: "s".into(),
        max_steps: 4,
        max_tool_calls_per_step: 4,
        max_tokens: 64,
    }
}

fn http_step(probe: Arc<Statuses>, attempts: u32) -> Workflow {
    Workflow::new(
        "serve",
        vec![Step {
            id: "serve".into(),
            instruction: "start the dev server".into(),
            verifiers: vec![Arc::new(HttpStatusIs::new(
                "http://127.0.0.1:3000/",
                200,
                probe,
            ))],
            max_attempts: attempts,
        }],
    )
    .unwrap()
}

#[test]
fn a_pass_opinion_with_a_failing_verifier_still_fails_the_step_and_the_workflow() {
    let llm = Script::new(vec![
        AssistantTurn::text("The server is running."),
        AssistantTurn::text("PASS: I started it, it works."),
        AssistantTurn::text("Started again."),
        AssistantTurn::text("PASS: definitely working now."),
    ]);
    let wf = http_step(statuses(&[("http://127.0.0.1:3000/", Ok(502))]), 2);
    let sink = Sink::default();
    let reviewer = LlmSelfReviewer::new(&llm, "m", 64);
    let mut history = vec![];
    let out = run_workflow_reviewed(
        &cfg(),
        &TurnOptions::default(),
        &llm,
        &ToolRegistry::new(vec![]),
        &sink,
        &StopFlag::default(),
        &mut history,
        &wf,
        Some(&reviewer),
    );
    match out {
        WorkflowOutcome::Failed { step, reason } => {
            assert_eq!(step, "serve");
            assert!(reason.contains("502"), "{reason}");
        }
        other => panic!("a passing opinion must not rescue a failing verifier: {other:?}"),
    }
    let evs = sink.events();
    let reviews: Vec<_> = evs
        .iter()
        .filter_map(|e| match e {
            Event::SelfReview {
                step,
                attempt,
                text,
                label,
            } => Some((step.clone(), *attempt, text.clone(), *label)),
            _ => None,
        })
        .collect();
    assert_eq!(reviews.len(), 2, "one opinion per attempt");
    assert_eq!(reviews[0].0, "serve");
    assert_eq!((reviews[0].1, reviews[1].1), (1, 2));
    assert!(reviews[0].2.starts_with("PASS"));
    assert!(reviews.iter().all(|r| r.3 == "opinion"));
    assert_eq!(SELF_REVIEW_LABEL, "opinion");
    // Wire shape: its own event type, labelled.
    let wire =
        serde_json::to_value(&evs[evs.iter().position(|e| e.kind() == "self_review").unwrap()])
            .unwrap();
    assert_eq!(wire["type"], "self_review");
    assert_eq!(wire["label"], "opinion");
    // The opinion is asked before the verdict, so the model never sees the verifier's answer.
    let first_review = evs.iter().position(|e| e.kind() == "self_review").unwrap();
    let first_verdict = evs.iter().position(|e| e.kind() == "verifier").unwrap();
    assert!(first_review < first_verdict);
    // The opinion never enters the conversation the next attempt or step sees.
    assert!(history.iter().all(|m| !m.content.contains("PASS")));
    let reqs = llm.seen();
    assert_eq!(reqs.len(), 4);
    assert!(reqs[1].tools.is_empty(), "the review call offers no tools");
    assert!(reqs[2].messages.iter().all(|m| !m.content.contains("PASS")));
}

#[test]
fn a_fail_opinion_with_passing_verifiers_still_succeeds() {
    let llm = Script::new(vec![
        AssistantTurn::text("I think it is up."),
        AssistantTurn::text("FAIL: not sure it started."),
    ]);
    let wf = http_step(statuses(&[("http://127.0.0.1:3000/", Ok(200))]), 1);
    let reviewer = LlmSelfReviewer::new(&llm, "m", 64);
    let out = run_workflow_reviewed(
        &cfg(),
        &TurnOptions::default(),
        &llm,
        &ToolRegistry::new(vec![]),
        &Sink::default(),
        &StopFlag::default(),
        &mut vec![],
        &wf,
        Some(&reviewer),
    );
    assert!(matches!(out, WorkflowOutcome::Succeeded { .. }), "{out:?}");
}

#[test]
fn a_failed_review_call_is_recorded_as_no_opinion_and_changes_nothing() {
    // Only one scripted turn: the review call fails.
    let llm = Script::new(vec![AssistantTurn::text("up")]);
    let wf = http_step(statuses(&[("http://127.0.0.1:3000/", Ok(200))]), 1);
    let sink = Sink::default();
    let reviewer = LlmSelfReviewer::new(&llm, "m", 64);
    let out = run_workflow_reviewed(
        &cfg(),
        &TurnOptions::default(),
        &llm,
        &ToolRegistry::new(vec![]),
        &sink,
        &StopFlag::default(),
        &mut vec![],
        &wf,
        Some(&reviewer),
    );
    assert!(matches!(out, WorkflowOutcome::Succeeded { .. }), "{out:?}");
    let texts: Vec<String> = sink
        .events()
        .into_iter()
        .filter_map(|e| match e {
            Event::SelfReview { text, .. } => Some(text),
            _ => None,
        })
        .collect();
    assert_eq!(texts.len(), 1);
    assert!(texts[0].starts_with("no opinion"), "{}", texts[0]);
}

#[test]
fn without_a_reviewer_no_review_call_is_made() {
    let llm = Script::new(vec![AssistantTurn::text("up")]);
    let wf = http_step(statuses(&[("http://127.0.0.1:3000/", Ok(200))]), 1);
    let sink = Sink::default();
    let out = run_workflow(
        &cfg(),
        &TurnOptions::default(),
        &llm,
        &ToolRegistry::new(vec![]),
        &sink,
        &StopFlag::default(),
        &mut vec![],
        &wf,
    );
    assert!(matches!(out, WorkflowOutcome::Succeeded { .. }));
    assert_eq!(llm.seen().len(), 1);
    assert!(sink.events().iter().all(|e| e.kind() != "self_review"));
}

#[test]
fn an_overlong_opinion_is_bounded() {
    let long = format!("PASS {}", "x".repeat(5000));
    let llm = Script::new(vec![AssistantTurn::text("up"), AssistantTurn::text(long)]);
    let wf = http_step(statuses(&[("http://127.0.0.1:3000/", Ok(200))]), 1);
    let sink = Sink::default();
    let reviewer = LlmSelfReviewer::new(&llm, "m", 64);
    run_workflow_reviewed(
        &cfg(),
        &TurnOptions::default(),
        &llm,
        &ToolRegistry::new(vec![]),
        &sink,
        &StopFlag::default(),
        &mut vec![],
        &wf,
        Some(&reviewer),
    );
    let text = sink
        .events()
        .into_iter()
        .find_map(|e| match e {
            Event::SelfReview { text, .. } => Some(text),
            _ => None,
        })
        .unwrap();
    assert!(text.chars().count() <= SELF_REVIEW_MAX_CHARS);
}

// ---- Model-driven planner -------------------------------------------------------------------

fn planner(turns: Vec<AssistantTurn>) -> (Arc<Script>, ModelPlanner) {
    let llm = Arc::new(Script::new(turns));
    let p = ModelPlanner::new(llm.clone(), "m")
        .with_tools(vec!["forge_test".into(), "contract_deploy".into()]);
    (llm, p)
}

#[test]
fn the_model_planner_proposes_a_workflow_whose_steps_all_carry_verifiers() {
    let plan = serde_json::json!({
        "id": "token-tests",
        "steps": [
            {"id": "write", "instruction": "write the tests", "verifiers": [
                {"kind": "tool_succeeded", "tool": "forge_test"}
            ]},
            {"id": "check", "instruction": "summarise", "max_attempts": 3, "verifiers": [
                {"kind": "tool_not_called", "tool": "contract_deploy"},
                {"kind": "answer_contains", "text": "passed"}
            ]}
        ]
    });
    let (llm, p) = planner(vec![AssistantTurn::text(format!(
        "Here is the plan:\n```json\n{plan}\n```"
    ))]);
    let wf = p.propose("add tests to my token").unwrap();
    assert_eq!(wf.id, "token-tests");
    assert_eq!(wf.steps.len(), 2);
    assert_eq!(wf.steps[0].max_attempts, 2, "default attempts");
    assert_eq!(wf.steps[1].max_attempts, 3);
    assert!(wf.steps.iter().all(|s| !s.verifiers.is_empty()));
    let req = &llm.seen()[0];
    assert!(req.tools.is_empty(), "planning offers no tools");
    assert!(req
        .messages
        .iter()
        .any(|m| m.content.contains("add tests to my token")));
    assert!(req
        .messages
        .iter()
        .any(|m| m.content.contains("forge_test")));
}

#[test]
fn a_proposed_step_without_a_verifier_is_refused() {
    let plan = serde_json::json!({"id": "p", "steps": [
        {"id": "a", "instruction": "do it", "verifiers": []}
    ]});
    let (_, p) = planner(vec![AssistantTurn::text(plan.to_string())]);
    match p.propose("anything") {
        Err(PlanError::Refused(why)) => assert!(why.contains("no verifier"), "{why}"),
        other => panic!(
            "a step with no verifier must be refused: {:?}",
            other.map(|w| w.id)
        ),
    }
}

#[test]
fn a_proposed_verifier_on_a_tool_the_session_lacks_is_refused() {
    let plan = serde_json::json!({"id": "p", "steps": [
        {"id": "a", "instruction": "do it", "verifiers": [{"kind": "tool_succeeded", "tool": "rm_rf"}]}
    ]});
    let (_, p) = planner(vec![AssistantTurn::text(plan.to_string())]);
    assert!(matches!(p.propose("x"), Err(PlanError::Refused(_))));
}

#[test]
fn a_proposed_http_or_hash_check_needs_the_sessions_probes() {
    let plan = serde_json::json!({"id": "p", "steps": [
        {"id": "a", "instruction": "serve", "verifiers": [
            {"kind": "http_status_is", "url": "http://127.0.0.1:3000/", "status": 200}
        ]}
    ]});
    let (_, p) = planner(vec![AssistantTurn::text(plan.to_string())]);
    assert!(matches!(p.propose("x"), Err(PlanError::Refused(_))));
    let llm = Arc::new(Script::new(vec![AssistantTurn::text(plan.to_string())]));
    let p = ModelPlanner::new(llm, "m").with_env(VerifierEnv {
        http: Some(statuses(&[])),
        files: None,
    });
    assert!(p.propose("x").is_ok());
}

#[test]
fn an_unusable_plan_is_refused_not_guessed() {
    for text in [
        "I would start by writing tests.".to_string(),
        "{\"id\": \"p\", \"steps\": []}".to_string(),
        "{\"id\": \"p\", \"steps\": [{\"id\": \"a\", \"instruction\": \"x\", \"verifiers\": [{\"kind\": \"model_says_done\"}]}]}".to_string(),
        format!(
            "{{\"id\": \"p\", \"steps\": [{}]}}",
            (0..20)
                .map(|i| format!("{{\"id\": \"s{i}\", \"instruction\": \"x\", \"verifiers\": [{{\"kind\": \"answer_contains\", \"text\": \"y\"}}]}}"))
                .collect::<Vec<_>>()
                .join(",")
        ),
    ] {
        let (_, p) = planner(vec![AssistantTurn::text(text.clone())]);
        assert!(p.propose("x").is_err(), "{text}");
    }
    let (_, p) = planner(vec![]);
    assert!(matches!(p.propose("x"), Err(PlanError::Model(_))));
}

#[test]
fn the_executor_runs_a_planned_workflow_and_only_verifiers_decide() {
    let plan = serde_json::json!({"id": "p", "steps": [
        {"id": "a", "instruction": "say ok", "max_attempts": 1, "verifiers": [
            {"kind": "answer_contains", "text": "ok"}
        ]}
    ]});
    let (_, p) = planner(vec![AssistantTurn::text(plan.to_string())]);
    let wf = p.propose("x").unwrap();
    let exec = Script::new(vec![AssistantTurn::text("nope, PASS anyway")]);
    let out = run_workflow(
        &cfg(),
        &TurnOptions::default(),
        &exec,
        &ToolRegistry::new(vec![]),
        &Sink::default(),
        &StopFlag::default(),
        &mut vec![],
        &wf,
    );
    assert!(matches!(out, WorkflowOutcome::Failed { .. }), "{out:?}");
}
