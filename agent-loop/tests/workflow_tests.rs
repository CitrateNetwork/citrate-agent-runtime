//! HUP-S1.3 — only verifiers say "done". A workflow's outcome is the verifiers' verdict; the
//! model's own claim of success never counts (the upstream agent's #1 complaint).
use citrate_agent_loop::*;
use std::sync::{Arc, Mutex};

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
}
impl LlmClient for Script {
    fn complete(&self, req: &CompletionRequest) -> Result<AssistantTurn, LlmError> {
        self.seen.lock().unwrap().push(req.clone());
        let mut t = self.turns.lock().unwrap();
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

fn spec(n: &str) -> ToolSpec {
    ToolSpec {
        name: n.into(),
        description: n.into(),
        parameters: serde_json::json!({"type":"object"}),
        host: HostKind::Core,
        annotations: Default::default(),
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
fn step(id: &str, verifiers: Vec<Arc<dyn Verifier>>, attempts: u32) -> Step {
    Step {
        id: id.into(),
        instruction: format!("do {id}"),
        verifiers,
        max_attempts: attempts,
    }
}

#[test]
fn a_workflow_needs_at_least_one_step_and_a_verifier_on_every_step() {
    assert!(Workflow::new("w", vec![]).is_err());
    assert!(
        Workflow::new("w", vec![step("a", vec![], 1)]).is_err(),
        "a step with no verifier can never be judged"
    );
    assert!(Workflow::new(
        "w",
        vec![step("a", vec![Arc::new(AnswerContains("x".into()))], 0)]
    )
    .is_err());
    assert!(Workflow::new(
        "w",
        vec![step("a", vec![Arc::new(AnswerContains("x".into()))], 1)]
    )
    .is_ok());
}

#[test]
fn the_models_claim_of_success_is_not_success() {
    // The model says "Deployed!" but never ran the deploy tool: the verifier fails, the workflow fails.
    let llm = Script::new(vec![
        AssistantTurn::text("Deployed! All done."),
        AssistantTurn::text("Deployed, really."),
    ]);
    let tools = ToolRegistry::new(vec![spec("contract_deploy")]).with_host(
        HostKind::Core,
        Arc::new(Host(ToolOutcome::Ok("{}".into()), None)),
    );
    let wf = Workflow::new(
        "deploy",
        vec![step(
            "deploy",
            vec![Arc::new(ToolSucceeded("contract_deploy".into()))],
            2,
        )],
    )
    .unwrap();
    let sink = Sink::default();
    let out = run_workflow(
        &cfg(),
        &TurnOptions::default(),
        &llm,
        &tools,
        &sink,
        &StopFlag::default(),
        &mut vec![],
        &wf,
    );
    assert!(
        matches!(out, WorkflowOutcome::Failed { ref step, .. } if step == "deploy"),
        "{out:?}"
    );
    let verdicts: Vec<bool> = sink
        .0
        .lock()
        .unwrap()
        .iter()
        .filter_map(|e| {
            if let Event::Verifier { passed, .. } = e {
                Some(*passed)
            } else {
                None
            }
        })
        .collect();
    assert_eq!(
        verdicts,
        vec![false, false],
        "each attempt is judged, and judged honestly"
    );
}

#[test]
fn a_failed_check_is_retried_with_its_reason_and_passes_on_the_second_attempt() {
    let llm = Script::new(vec![
        AssistantTurn::text("I think it's fine"),
        call("c1", "forge_test"),
        AssistantTurn::text("tests pass"),
    ]);
    let tools = ToolRegistry::new(vec![spec("forge_test")]).with_host(
        HostKind::Core,
        Arc::new(Host(
            ToolOutcome::Ok("{\"passed\":12,\"failed\":0}".into()),
            None,
        )),
    );
    let wf = Workflow::new(
        "test",
        vec![step(
            "tests",
            vec![Arc::new(JsonFieldEquals {
                tool: "forge_test".into(),
                pointer: "/failed".into(),
                value: serde_json::json!(0),
            })],
            3,
        )],
    )
    .unwrap();
    let out = run_workflow(
        &cfg(),
        &TurnOptions::default(),
        &llm,
        &tools,
        &Sink::default(),
        &StopFlag::default(),
        &mut vec![],
        &wf,
    );
    assert!(matches!(out, WorkflowOutcome::Succeeded { .. }), "{out:?}");
    let seen = llm.seen.lock().unwrap();
    let retry_prompt = &seen[1]
        .messages
        .iter()
        .rev()
        .find(|m| m.role == Role::User)
        .unwrap()
        .content;
    assert!(
        retry_prompt.contains("did not pass"),
        "the retry tells the model what failed: {retry_prompt}"
    );
}

#[test]
fn a_declined_tool_does_not_count_as_succeeded() {
    let llm = Script::new(vec![
        call("c1", "group_invite"),
        AssistantTurn::text("invited!"),
    ]);
    let tools = ToolRegistry::new(vec![spec("group_invite")]).with_host(
        HostKind::Core,
        Arc::new(Host(
            ToolOutcome::Denied("the member declined".into()),
            None,
        )),
    );
    let wf = Workflow::new(
        "invite",
        vec![step(
            "invite",
            vec![Arc::new(ToolSucceeded("group_invite".into()))],
            1,
        )],
    )
    .unwrap();
    let out = run_workflow(
        &cfg(),
        &TurnOptions::default(),
        &llm,
        &tools,
        &Sink::default(),
        &StopFlag::default(),
        &mut vec![],
        &wf,
    );
    assert!(matches!(out, WorkflowOutcome::Failed { .. }));
}

#[test]
fn steps_run_in_order_and_all_must_pass() {
    let llm = Script::new(vec![
        call("c1", "a"),
        AssistantTurn::text("a done"),
        call("c2", "b"),
        AssistantTurn::text("b done"),
    ]);
    let tools = ToolRegistry::new(vec![spec("a"), spec("b")]).with_host(
        HostKind::Core,
        Arc::new(Host(ToolOutcome::Ok("ok".into()), None)),
    );
    let wf = Workflow::new(
        "two",
        vec![
            step("first", vec![Arc::new(ToolSucceeded("a".into()))], 1),
            step(
                "second",
                vec![
                    Arc::new(ToolSucceeded("b".into())),
                    Arc::new(ToolNotCalled("a".into())),
                ],
                1,
            ),
        ],
    )
    .unwrap();
    let out = run_workflow(
        &cfg(),
        &TurnOptions::default(),
        &llm,
        &tools,
        &Sink::default(),
        &StopFlag::default(),
        &mut vec![],
        &wf,
    );
    match out {
        WorkflowOutcome::Succeeded { answers } => {
            assert_eq!(answers, vec!["a done".to_string(), "b done".to_string()])
        }
        other => panic!("{other:?}"),
    }
}

#[test]
fn stop_during_a_workflow_stops_it() {
    let stop = StopFlag::default();
    let llm = Script::new(vec![call("c1", "a"), AssistantTurn::text("x")]);
    let tools = ToolRegistry::new(vec![spec("a")]).with_host(
        HostKind::Core,
        Arc::new(Host(ToolOutcome::Ok("ok".into()), Some(stop.clone()))),
    );
    let wf = Workflow::new(
        "w",
        vec![step("s", vec![Arc::new(ToolSucceeded("a".into()))], 3)],
    )
    .unwrap();
    let out = run_workflow(
        &cfg(),
        &TurnOptions::default(),
        &llm,
        &tools,
        &Sink::default(),
        &stop,
        &mut vec![],
        &wf,
    );
    assert_eq!(out, WorkflowOutcome::Stopped);
}

#[test]
fn a_static_planner_picks_a_registered_workflow_or_none() {
    let wf = Workflow::new(
        "hello-mint",
        vec![step("s", vec![Arc::new(AnswerContains("ok".into()))], 1)],
    )
    .unwrap();
    let planner = StaticPlanner::new(vec![(vec!["nft".into(), "mint".into()], wf)]);
    assert_eq!(
        planner
            .plan("help me make an NFT project")
            .map(|w| w.id.clone()),
        Some("hello-mint".into())
    );
    assert!(planner.plan("what's the weather").is_none());
}
