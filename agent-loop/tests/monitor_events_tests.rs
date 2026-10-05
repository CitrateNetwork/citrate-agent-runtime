//! HUP-S7.6 (US-7.4 AC1): the events the Activity monitor needs from the loop.
//!
//! - `usage`: every model call whose provider reported token usage emits it on that call's step,
//!   with the generation time when the provider reports one. A call without usage emits nothing.
//! - `plan`: a workflow run announces its step ids once, before its first step.
use citrate_agent_loop::*;
use std::sync::{Arc, Mutex};

struct Script {
    turns: Mutex<Vec<(AssistantTurn, Option<TokenUsage>)>>,
}
impl Script {
    fn new(t: Vec<(AssistantTurn, Option<TokenUsage>)>) -> Self {
        Script {
            turns: Mutex::new(t),
        }
    }
}
impl LlmClient for Script {
    fn complete(&self, req: &CompletionRequest) -> Result<AssistantTurn, LlmError> {
        self.complete_with_usage(req).map(|(t, _)| t)
    }
    fn complete_with_usage(
        &self,
        _req: &CompletionRequest,
    ) -> Result<(AssistantTurn, Option<TokenUsage>), LlmError> {
        let mut t = self.turns.lock().unwrap();
        Ok(if t.is_empty() {
            (AssistantTurn::text("done"), None)
        } else {
            t.remove(0)
        })
    }
}
struct Host;
impl ToolHost for Host {
    fn execute(&self, _c: &ToolCall) -> ToolOutcome {
        ToolOutcome::Ok("{}".into())
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
fn cfg() -> LoopConfig {
    LoopConfig {
        model: "m".into(),
        system_prompt: "s".into(),
        max_steps: 4,
        max_tool_calls_per_step: 4,
        max_tokens: 64,
    }
}
fn usage(p: u64, c: u64, ms: Option<u64>) -> Option<TokenUsage> {
    Some(TokenUsage {
        prompt_tokens: p,
        completion_tokens: c,
        generation_ms: ms,
    })
}
fn tools() -> ToolRegistry {
    ToolRegistry::new(vec![spec("node_status")]).with_host(HostKind::Core, Arc::new(Host))
}

#[test]
fn each_reported_model_call_emits_its_usage_on_its_own_step() {
    let llm = Script::new(vec![
        (
            AssistantTurn::tools(vec![ToolCall {
                id: "c1".into(),
                name: "node_status".into(),
                arguments: "{}".into(),
            }]),
            usage(120, 9, Some(300)),
        ),
        (AssistantTurn::text("height 7"), usage(140, 4, None)),
    ]);
    let sink = Sink::default();
    let mut history = vec![];
    let out = run_turn(
        &cfg(),
        &llm,
        &tools(),
        &sink,
        &StopFlag::default(),
        &mut history,
        "status?",
    );
    assert_eq!(out, RunOutcome::Answered("height 7".into()));
    let usages: Vec<Event> = sink
        .events()
        .into_iter()
        .filter(|e| e.kind() == "usage")
        .collect();
    assert_eq!(
        usages,
        vec![
            Event::Usage {
                step: 1,
                prompt_tokens: 120,
                completion_tokens: 9,
                generation_ms: Some(300),
            },
            Event::Usage {
                step: 2,
                prompt_tokens: 140,
                completion_tokens: 4,
                generation_ms: None,
            },
        ]
    );
    // The usage of a step follows its step_start and precedes its tool call.
    let kinds: Vec<&str> = sink.events().iter().map(Event::kind).collect();
    assert_eq!(&kinds[..3], &["step_start", "usage", "tool_call"]);
}

#[test]
fn a_call_without_usage_emits_no_usage_event() {
    let llm = Script::new(vec![(AssistantTurn::text("hi"), None)]);
    let sink = Sink::default();
    let mut history = vec![];
    run_turn(
        &cfg(),
        &llm,
        &tools(),
        &sink,
        &StopFlag::default(),
        &mut history,
        "hi",
    );
    assert!(sink.events().iter().all(|e| e.kind() != "usage"));
}

#[test]
fn usage_serializes_with_the_wire_tag_and_omits_an_unknown_generation_time() {
    let v = serde_json::to_value(Event::Usage {
        step: 2,
        prompt_tokens: 10,
        completion_tokens: 3,
        generation_ms: None,
    })
    .unwrap();
    assert_eq!(
        v,
        serde_json::json!({"type":"usage","step":2,"prompt_tokens":10,"completion_tokens":3})
    );
    let v = serde_json::to_value(Event::Plan {
        steps: vec!["a".into(), "b".into()],
    })
    .unwrap();
    assert_eq!(v, serde_json::json!({"type":"plan","steps":["a","b"]}));
}

#[test]
fn a_workflow_announces_its_plan_once_before_its_first_step() {
    let llm = Script::new(vec![
        (AssistantTurn::text("alpha"), None),
        (AssistantTurn::text("nope"), None),
        (AssistantTurn::text("beta"), None),
    ]);
    let wf = Workflow::new(
        "w",
        vec![
            Step {
                id: "first".into(),
                instruction: "say alpha".into(),
                verifiers: vec![Arc::new(AnswerContains("alpha".into()))],
                max_attempts: 1,
            },
            Step {
                id: "second".into(),
                instruction: "say beta".into(),
                verifiers: vec![Arc::new(AnswerContains("beta".into()))],
                max_attempts: 2,
            },
        ],
    )
    .unwrap();
    let sink = Sink::default();
    let mut history = vec![];
    let out = run_workflow(
        &cfg(),
        &TurnOptions::default(),
        &llm,
        &tools(),
        &sink,
        &StopFlag::default(),
        &mut history,
        &wf,
    );
    assert!(matches!(out, WorkflowOutcome::Succeeded { .. }));
    let ev = sink.events();
    assert_eq!(
        ev[0],
        Event::Plan {
            steps: vec!["first".into(), "second".into()]
        }
    );
    assert_eq!(ev.iter().filter(|e| e.kind() == "plan").count(), 1);
}
