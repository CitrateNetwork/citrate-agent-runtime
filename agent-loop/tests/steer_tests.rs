//! #691: a member message sent while a chat turn runs joins the conversation at the next step
//! boundary, never lost to an answer, and is refused when no turn can take it.
use citrate_agent_loop::*;
use std::sync::{Arc, Mutex};

/// Scripted LLM that can push a steering message while a given model call is "running".
struct ScriptLlm {
    turns: Mutex<Vec<AssistantTurn>>,
    seen: Mutex<Vec<CompletionRequest>>,
    steer_during: Mutex<Vec<(usize, &'static str)>>,
    inbox: SteerInbox,
}
impl ScriptLlm {
    fn new(
        turns: Vec<AssistantTurn>,
        inbox: SteerInbox,
        steer_during: Vec<(usize, &'static str)>,
    ) -> Self {
        let mut t = turns;
        t.reverse();
        ScriptLlm {
            turns: Mutex::new(t),
            seen: Mutex::new(vec![]),
            steer_during: Mutex::new(steer_during),
            inbox,
        }
    }
}
impl LlmClient for ScriptLlm {
    fn complete(&self, req: &CompletionRequest) -> Result<AssistantTurn, LlmError> {
        let n = {
            let mut seen = self.seen.lock().unwrap();
            seen.push(req.clone());
            seen.len()
        };
        for (at, text) in self.steer_during.lock().unwrap().iter() {
            if *at == n {
                self.inbox
                    .push("t1", text)
                    .expect("the running turn takes it");
            }
        }
        Ok(self
            .turns
            .lock()
            .unwrap()
            .pop()
            .unwrap_or_else(|| AssistantTurn::text("(script exhausted)")))
    }
}

struct Host;
impl ToolHost for Host {
    fn execute(&self, _call: &ToolCall) -> ToolOutcome {
        ToolOutcome::Ok("{\"height\":6310}".into())
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

fn tools() -> ToolRegistry {
    ToolRegistry::new(vec![ToolSpec {
        name: "node_status".into(),
        description: "node".into(),
        parameters: serde_json::json!({"type": "object"}),
        host: HostKind::Core,
        annotations: ToolAnnotations {
            read_only: true,
            effect: Some(Effect::None),
            trust: Some(Trust::Trusted),
            ..Default::default()
        },
    }])
    .with_host(HostKind::Core, Arc::new(Host))
}

fn cfg(max_steps: u32) -> LoopConfig {
    LoopConfig {
        model: "m".into(),
        system_prompt: "s".into(),
        max_steps,
        max_tool_calls_per_step: 4,
        max_tokens: 64,
    }
}

fn opts(inbox: &SteerInbox) -> TurnOptions {
    // The run every steer in these tests is written for.
    inbox.begin("t1");
    TurnOptions {
        steer: Some(inbox.clone()),
        ..Default::default()
    }
}

fn tool_turn() -> AssistantTurn {
    AssistantTurn::tools(vec![ToolCall {
        id: "c1".into(),
        name: "node_status".into(),
        arguments: "{}".into(),
    }])
}

#[test]
fn a_steer_during_a_tool_step_joins_before_the_next_model_call() {
    let inbox = SteerInbox::default();
    let llm = ScriptLlm::new(
        vec![tool_turn(), AssistantTurn::text("Weeknights only, then.")],
        inbox.clone(),
        vec![(1, "also skip Fridays")],
    );
    let sink = Sink::default();
    let mut history = vec![];
    let out = run_turn_with(
        &cfg(6),
        &opts(&inbox),
        &llm,
        &tools(),
        &sink,
        &StopFlag::default(),
        &mut history,
        "Put my GPU to work at night",
    );
    assert_eq!(out, RunOutcome::Answered("Weeknights only, then.".into()));
    assert_eq!(
        sink.kinds(),
        vec![
            "step_start",
            "tool_call",
            "tool_result",
            "step_end",
            "steered",
            "step_start",
            "final",
            "done"
        ]
    );
    assert!(
        matches!(&sink.0.lock().unwrap()[4], Event::Steered { step: 2, text } if text == "also skip Fridays")
    );
    // The second model call sees the steer after the tool result.
    let second = &llm.seen.lock().unwrap()[1];
    let last = second.messages.last().unwrap();
    assert_eq!(last.role, Role::User);
    assert_eq!(last.content, "also skip Fridays");
    assert!(!inbox.is_open(), "closed with the answer");
}

#[test]
fn a_steer_during_the_answering_call_takes_one_more_step_instead_of_being_lost() {
    let inbox = SteerInbox::default();
    let llm = ScriptLlm::new(
        vec![
            AssistantTurn::text("Every night."),
            AssistantTurn::text("Weeknights only."),
        ],
        inbox.clone(),
        vec![(1, "weeknights only")],
    );
    let sink = Sink::default();
    let mut history = vec![];
    let out = run_turn_with(
        &cfg(6),
        &opts(&inbox),
        &llm,
        &tools(),
        &sink,
        &StopFlag::default(),
        &mut history,
        "nights?",
    );
    assert_eq!(out, RunOutcome::Answered("Weeknights only.".into()));
    assert_eq!(
        sink.kinds(),
        vec!["step_start", "steered", "step_start", "final", "done"]
    );
    assert_eq!(llm.seen.lock().unwrap().len(), 2);
    // user, assistant (first answer), steer, assistant
    assert_eq!(
        history.iter().map(|m| m.role).collect::<Vec<_>>(),
        vec![Role::User, Role::Assistant, Role::User, Role::Assistant]
    );
}

#[test]
fn the_inbox_refuses_when_idle_after_the_turn_and_when_full_empty_or_too_long() {
    let inbox = SteerInbox::default();
    assert_eq!(inbox.push("t1", "hi"), Err(SteerError::NotRunning));
    let llm = ScriptLlm::new(vec![AssistantTurn::text("ok")], inbox.clone(), vec![]);
    run_turn_with(
        &cfg(2),
        &opts(&inbox),
        &llm,
        &tools(),
        &Sink::default(),
        &StopFlag::default(),
        &mut vec![],
        "x",
    );
    assert_eq!(
        inbox.push("t1", "late"),
        Err(SteerError::NotRunning),
        "after the answer"
    );

    // Bounds, checked while a turn is running.
    let inbox = SteerInbox::default();
    let probe = Arc::new(Mutex::new(Vec::<Result<usize, SteerError>>::new()));
    struct Probe(SteerInbox, Arc<Mutex<Vec<Result<usize, SteerError>>>>);
    impl LlmClient for Probe {
        fn complete(&self, _req: &CompletionRequest) -> Result<AssistantTurn, LlmError> {
            let mut r = self.1.lock().unwrap();
            if r.is_empty() {
                r.push(self.0.push("t1", "   "));
                r.push(self.0.push("t1", &"x".repeat(MAX_STEER_CHARS + 1)));
                for i in 0..=MAX_STEER_QUEUE {
                    r.push(self.0.push("t1", &format!("m{i}")));
                }
            }
            Ok(AssistantTurn::text("done"))
        }
    }
    let llm = Probe(inbox.clone(), probe.clone());
    run_turn_with(
        &cfg(3),
        &opts(&inbox),
        &llm,
        &tools(),
        &Sink::default(),
        &StopFlag::default(),
        &mut vec![],
        "x",
    );
    let r = probe.lock().unwrap().clone();
    assert_eq!(r[0], Err(SteerError::Empty));
    assert_eq!(r[1], Err(SteerError::TooLong));
    assert_eq!(r[2], Ok(1));
    assert_eq!(r[2 + MAX_STEER_QUEUE], Err(SteerError::Full));
}

#[test]
fn a_turn_without_an_inbox_never_steers_and_a_stopped_turn_closes_it() {
    let inbox = SteerInbox::default();
    let stop = StopFlag::default();
    stop.stop();
    let llm = ScriptLlm::new(vec![AssistantTurn::text("x")], inbox.clone(), vec![]);
    let out = run_turn_with(
        &cfg(2),
        &opts(&inbox),
        &llm,
        &tools(),
        &Sink::default(),
        &stop,
        &mut vec![],
        "x",
    );
    assert_eq!(out, RunOutcome::Stopped);
    assert!(!inbox.is_open());
    let sink = Sink::default();
    run_turn(
        &cfg(2),
        &ScriptLlm::new(vec![AssistantTurn::text("y")], inbox.clone(), vec![]),
        &tools(),
        &sink,
        &StopFlag::default(),
        &mut vec![],
        "y",
    );
    assert!(!sink.kinds().contains(&"steered"));
}

#[test]
fn a_steer_for_another_run_is_refused_and_never_reaches_the_model() {
    let inbox = SteerInbox::default();
    struct Stale(SteerInbox, Mutex<Option<Result<usize, SteerError>>>);
    impl LlmClient for Stale {
        fn complete(&self, req: &CompletionRequest) -> Result<AssistantTurn, LlmError> {
            let mut r = self.1.lock().unwrap();
            if r.is_none() {
                *r = Some(self.0.push("t0", "for the run before"));
            }
            assert!(!req
                .messages
                .iter()
                .any(|m| m.content == "for the run before"));
            Ok(AssistantTurn::text("ok"))
        }
    }
    let llm = Stale(inbox.clone(), Mutex::new(None));
    let sink = Sink::default();
    run_turn_with(
        &cfg(3),
        &opts(&inbox),
        &llm,
        &tools(),
        &sink,
        &StopFlag::default(),
        &mut vec![],
        "x",
    );
    assert_eq!(*llm.1.lock().unwrap(), Some(Err(SteerError::WrongRun)));
    assert!(!sink.kinds().contains(&"steered"));
}
