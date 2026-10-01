//! HUP-S1.1a — the agent loop's contract, driven offline with scripted LLM turns and mock hosts.
use citrate_agent_loop::*;
use std::sync::{Arc, Mutex};

/// Scripted LLM: returns the queued turns in order; records every request it saw.
struct ScriptLlm {
    turns: Mutex<Vec<Result<AssistantTurn, LlmError>>>,
    seen: Mutex<Vec<CompletionRequest>>,
}
impl ScriptLlm {
    fn new(turns: Vec<Result<AssistantTurn, LlmError>>) -> Self {
        let mut t = turns;
        t.reverse();
        ScriptLlm {
            turns: Mutex::new(t),
            seen: Mutex::new(vec![]),
        }
    }
    fn calls(&self) -> usize {
        self.seen.lock().unwrap().len()
    }
}
impl LlmClient for ScriptLlm {
    fn complete(&self, req: &CompletionRequest) -> Result<AssistantTurn, LlmError> {
        self.seen.lock().unwrap().push(req.clone());
        self.turns
            .lock()
            .unwrap()
            .pop()
            .unwrap_or_else(|| Ok(AssistantTurn::text("(script exhausted)")))
    }
}

/// Records calls; returns a fixed result; can trip the stop flag while running.
struct MockHost {
    name: &'static str,
    calls: Mutex<Vec<ToolCall>>,
    result: ToolOutcome,
    stop_on_call: Option<StopFlag>,
}
impl MockHost {
    fn new(name: &'static str, result: ToolOutcome) -> Self {
        MockHost {
            name,
            calls: Mutex::new(vec![]),
            result,
            stop_on_call: None,
        }
    }
}
impl ToolHost for MockHost {
    fn execute(&self, call: &ToolCall) -> ToolOutcome {
        self.calls.lock().unwrap().push(call.clone());
        if let Some(s) = &self.stop_on_call {
            s.stop();
        }
        let _ = self.name;
        self.result.clone()
    }
}

#[derive(Default)]
struct Sink(Mutex<Vec<Event>>);
impl EventSink for Sink {
    fn emit(&self, ev: Event) {
        self.0.lock().unwrap().push(ev);
    }
}
impl Sink {
    fn kinds(&self) -> Vec<&'static str> {
        self.0.lock().unwrap().iter().map(Event::kind).collect()
    }
}

fn spec(name: &str, host: HostKind) -> ToolSpec {
    ToolSpec {
        name: name.into(),
        description: format!("{name} tool"),
        parameters: serde_json::json!({"type": "object"}),
        host,
        annotations: ToolAnnotations {
            read_only: true,
            ..Default::default()
        },
    }
}

fn call(id: &str, name: &str, args: &str) -> ToolCall {
    ToolCall {
        id: id.into(),
        name: name.into(),
        arguments: args.into(),
    }
}

fn cfg(max_steps: u32) -> LoopConfig {
    LoopConfig {
        model: "m".into(),
        system_prompt: "You are Hermes.".into(),
        max_steps,
        max_tool_calls_per_step: 4,
        max_tokens: 512,
    }
}

#[test]
fn a_plain_answer_finishes_in_one_step() {
    let llm = ScriptLlm::new(vec![Ok(AssistantTurn::text("Your node is validating."))]);
    let tools = ToolRegistry::new(vec![]);
    let sink = Sink::default();
    let mut history = vec![];
    let out = run_turn(
        &cfg(6),
        &llm,
        &tools,
        &sink,
        &StopFlag::default(),
        &mut history,
        "how is my node?",
    );
    assert_eq!(out, RunOutcome::Answered("Your node is validating.".into()));
    assert_eq!(sink.kinds(), vec!["step_start", "final", "done"]);
    assert_eq!(history.len(), 2, "user + assistant");
    let req = &llm.seen.lock().unwrap()[0];
    assert_eq!(req.messages[0].role, Role::System, "system prompt first");
    assert_eq!(req.max_tokens, 512);
}

#[test]
fn a_tool_call_runs_on_its_host_and_its_result_feeds_the_next_step() {
    let llm = ScriptLlm::new(vec![
        Ok(AssistantTurn::tools(vec![call("c1", "node_status", "{}")])),
        Ok(AssistantTurn::text("Height 6,310.")),
    ]);
    let core = Arc::new(MockHost::new(
        "core",
        ToolOutcome::Ok("{\"height\":6310}".into()),
    ));
    let sidecar = Arc::new(MockHost::new("sidecar", ToolOutcome::Ok("unused".into())));
    let tools = ToolRegistry::new(vec![spec("node_status", HostKind::Core)])
        .with_host(HostKind::Core, core.clone())
        .with_host(HostKind::Sidecar, sidecar.clone());
    let sink = Sink::default();
    let mut history = vec![];
    let out = run_turn(
        &cfg(6),
        &llm,
        &tools,
        &sink,
        &StopFlag::default(),
        &mut history,
        "height?",
    );
    assert_eq!(out, RunOutcome::Answered("Height 6,310.".into()));
    assert_eq!(
        core.calls.lock().unwrap().len(),
        1,
        "routed to the core host"
    );
    assert!(sidecar.calls.lock().unwrap().is_empty());
    let second = &llm.seen.lock().unwrap()[1];
    let tool_msg = second
        .messages
        .iter()
        .find(|m| m.role == Role::Tool)
        .expect("tool result sent back");
    assert_eq!(tool_msg.tool_call_id.as_deref(), Some("c1"));
    assert_eq!(tool_msg.content, "{\"height\":6310}");
    assert_eq!(
        sink.kinds(),
        vec![
            "step_start",
            "tool_call",
            "tool_result",
            "step_end",
            "step_start",
            "final",
            "done"
        ]
    );
    assert!(
        second.tools.iter().any(|t| t.name == "node_status"),
        "tool specs are offered"
    );
}

#[test]
fn the_loop_is_bounded_by_max_steps() {
    let turns = (0..20)
        .map(|i| {
            Ok(AssistantTurn::tools(vec![call(
                &format!("c{i}"),
                "node_status",
                "{}",
            )]))
        })
        .collect();
    let llm = ScriptLlm::new(turns);
    let core = Arc::new(MockHost::new("core", ToolOutcome::Ok("ok".into())));
    let tools = ToolRegistry::new(vec![spec("node_status", HostKind::Core)])
        .with_host(HostKind::Core, core);
    let sink = Sink::default();
    let out = run_turn(
        &cfg(3),
        &llm,
        &tools,
        &sink,
        &StopFlag::default(),
        &mut vec![],
        "loop forever",
    );
    assert_eq!(out, RunOutcome::StepLimit);
    assert_eq!(llm.calls(), 3);
    assert_eq!(sink.kinds().last(), Some(&"done"));
}

#[test]
fn stop_before_start_makes_no_model_call() {
    let llm = ScriptLlm::new(vec![Ok(AssistantTurn::text("never"))]);
    let stop = StopFlag::default();
    stop.stop();
    let out = run_turn(
        &cfg(6),
        &llm,
        &ToolRegistry::new(vec![]),
        &Sink::default(),
        &stop,
        &mut vec![],
        "hi",
    );
    assert_eq!(out, RunOutcome::Stopped);
    assert_eq!(llm.calls(), 0);
}

#[test]
fn stop_during_a_tool_halts_before_the_next_model_call() {
    let llm = ScriptLlm::new(vec![
        Ok(AssistantTurn::tools(vec![
            call("c1", "a", "{}"),
            call("c2", "a", "{}"),
        ])),
        Ok(AssistantTurn::text("never")),
    ]);
    let stop = StopFlag::default();
    let mut host = MockHost::new("core", ToolOutcome::Ok("ok".into()));
    host.stop_on_call = Some(stop.clone());
    let host = Arc::new(host);
    let tools =
        ToolRegistry::new(vec![spec("a", HostKind::Core)]).with_host(HostKind::Core, host.clone());
    let out = run_turn(
        &cfg(6),
        &llm,
        &tools,
        &Sink::default(),
        &stop,
        &mut vec![],
        "go",
    );
    assert_eq!(out, RunOutcome::Stopped);
    assert_eq!(
        host.calls.lock().unwrap().len(),
        1,
        "the second call in the same step does not run"
    );
    assert_eq!(llm.calls(), 1);
}

#[test]
fn unknown_tools_and_bad_arguments_become_tool_errors_not_crashes() {
    let llm = ScriptLlm::new(vec![
        Ok(AssistantTurn::tools(vec![
            call("c1", "no_such_tool", "{}"),
            call("c2", "node_status", "{not json"),
        ])),
        Ok(AssistantTurn::text("sorry")),
    ]);
    let core = Arc::new(MockHost::new("core", ToolOutcome::Ok("ok".into())));
    let tools = ToolRegistry::new(vec![spec("node_status", HostKind::Core)])
        .with_host(HostKind::Core, core.clone());
    let out = run_turn(
        &cfg(6),
        &llm,
        &tools,
        &Sink::default(),
        &StopFlag::default(),
        &mut vec![],
        "x",
    );
    assert_eq!(out, RunOutcome::Answered("sorry".into()));
    assert!(
        core.calls.lock().unwrap().is_empty(),
        "malformed arguments never reach the host"
    );
    let second = &llm.seen.lock().unwrap()[1];
    let results: Vec<&str> = second
        .messages
        .iter()
        .filter(|m| m.role == Role::Tool)
        .map(|m| m.content.as_str())
        .collect();
    assert!(results[0].contains("unknown tool"));
    assert!(results[1].contains("not valid JSON"));
}

#[test]
fn a_denied_tool_is_reported_to_the_model_as_declined() {
    let llm = ScriptLlm::new(vec![
        Ok(AssistantTurn::tools(vec![call("c1", "group_invite", "{}")])),
        Ok(AssistantTurn::text("ok, I won't")),
    ]);
    let core = Arc::new(MockHost::new(
        "core",
        ToolOutcome::Denied("the member declined".into()),
    ));
    let tools = ToolRegistry::new(vec![spec("group_invite", HostKind::Core)])
        .with_host(HostKind::Core, core);
    let sink = Sink::default();
    run_turn(
        &cfg(6),
        &llm,
        &tools,
        &sink,
        &StopFlag::default(),
        &mut vec![],
        "invite",
    );
    let second = &llm.seen.lock().unwrap()[1];
    let r = second
        .messages
        .iter()
        .find(|m| m.role == Role::Tool)
        .unwrap();
    assert!(r.content.contains("declined"));
}

#[test]
fn a_model_error_fails_the_turn_with_an_error_event() {
    let llm = ScriptLlm::new(vec![Err(LlmError::Transport("connection refused".into()))]);
    let sink = Sink::default();
    let out = run_turn(
        &cfg(6),
        &llm,
        &ToolRegistry::new(vec![]),
        &sink,
        &StopFlag::default(),
        &mut vec![],
        "x",
    );
    assert!(matches!(out, RunOutcome::Failed(ref m) if m.contains("connection refused")));
    assert_eq!(sink.kinds(), vec!["step_start", "error", "done"]);
}

#[test]
fn tool_calls_per_step_are_capped() {
    let many = (0..10).map(|i| call(&format!("c{i}"), "a", "{}")).collect();
    let llm = ScriptLlm::new(vec![
        Ok(AssistantTurn::tools(many)),
        Ok(AssistantTurn::text("done")),
    ]);
    let host = Arc::new(MockHost::new("core", ToolOutcome::Ok("ok".into())));
    let tools =
        ToolRegistry::new(vec![spec("a", HostKind::Core)]).with_host(HostKind::Core, host.clone());
    run_turn(
        &cfg(6),
        &llm,
        &tools,
        &Sink::default(),
        &StopFlag::default(),
        &mut vec![],
        "x",
    );
    assert_eq!(host.calls.lock().unwrap().len(), 4);
    let second = &llm.seen.lock().unwrap()[1];
    let skipped = second
        .messages
        .iter()
        .filter(|m| m.role == Role::Tool && m.content.contains("skipped"))
        .count();
    assert_eq!(
        skipped, 6,
        "every call still gets a result so the transcript stays valid"
    );
}

#[test]
fn a_tool_without_a_registered_host_is_an_error_not_a_panic() {
    let llm = ScriptLlm::new(vec![
        Ok(AssistantTurn::tools(vec![call("c1", "browse", "{}")])),
        Ok(AssistantTurn::text("k")),
    ]);
    let tools = ToolRegistry::new(vec![spec("browse", HostKind::Sidecar)]);
    let out = run_turn(
        &cfg(6),
        &llm,
        &tools,
        &Sink::default(),
        &StopFlag::default(),
        &mut vec![],
        "x",
    );
    assert_eq!(out, RunOutcome::Answered("k".into()));
}

/// A `tool_call` event names a host only when the loop will actually dispatch that call; calls it
/// refuses (over the per-step cap, unparseable arguments, unknown tool) carry no host, so a remote
/// host that acts on `host == core` events never runs a call the loop refused.
#[test]
fn only_dispatched_calls_announce_a_host() {
    let mut calls = vec![
        call("c0", "a", "{}"),
        call("c1", "a", "{not json"),
        call("c2", "nope", "{}"),
        call("c3", "a", "{}"),
    ];
    calls.extend((4..7).map(|i| call(&format!("c{i}"), "a", "{}")));
    let llm = ScriptLlm::new(vec![
        Ok(AssistantTurn::tools(calls)),
        Ok(AssistantTurn::text("done")),
    ]);
    let host = Arc::new(MockHost::new("core", ToolOutcome::Ok("ok".into())));
    let tools =
        ToolRegistry::new(vec![spec("a", HostKind::Core)]).with_host(HostKind::Core, host.clone());
    let sink = Sink::default();
    run_turn(
        &cfg(6),
        &llm,
        &tools,
        &sink,
        &StopFlag::default(),
        &mut vec![],
        "x",
    );
    let announced: Vec<String> = sink
        .0
        .lock()
        .unwrap()
        .iter()
        .filter_map(|e| match e {
            Event::ToolCall {
                call,
                host: Some(_),
                ..
            } => Some(call.id.clone()),
            _ => None,
        })
        .collect();
    let dispatched: Vec<String> = host
        .calls
        .lock()
        .unwrap()
        .iter()
        .map(|c| c.id.clone())
        .collect();
    assert_eq!(
        dispatched,
        ["c0", "c3"],
        "cap 4: c4..c6 skipped; c1 bad args; c2 unknown"
    );
    assert_eq!(
        announced, dispatched,
        "every host-named event is a real dispatch, and only those"
    );
    let all_calls = sink.kinds().iter().filter(|k| **k == "tool_call").count();
    assert_eq!(
        all_calls, 7,
        "refused calls are still reported, just without a host"
    );
}
