//! HUP-S1.1 (g1-render) — the loop turns a streaming model's text into `assistant_delta` events,
//! batched, and leaves `final` exactly as before. A model that cannot stream changes nothing.
use citrate_agent_loop::*;
use std::sync::Mutex;

/// Streams `pieces` (with an optional pause between them), then answers with their join.
struct Streaming {
    pieces: Vec<String>,
    pause: std::time::Duration,
    tool_first: Mutex<bool>,
}
impl LlmClient for Streaming {
    fn complete(&self, _req: &CompletionRequest) -> Result<AssistantTurn, LlmError> {
        Ok(AssistantTurn::text(self.pieces.concat()))
    }
    fn complete_streaming(
        &self,
        _req: &CompletionRequest,
        on_delta: &mut dyn FnMut(&str),
    ) -> Result<(AssistantTurn, Option<TokenUsage>), LlmError> {
        let mut first = self.tool_first.lock().unwrap();
        if *first {
            *first = false;
            on_delta("Let me check. ");
            return Ok((
                AssistantTurn {
                    content: "Let me check. ".into(),
                    tool_calls: vec![ToolCall {
                        id: "c1".into(),
                        name: "node_status".into(),
                        arguments: "{}".into(),
                    }],
                },
                None,
            ));
        }
        for p in &self.pieces {
            on_delta(p);
            if !self.pause.is_zero() {
                std::thread::sleep(self.pause);
            }
        }
        Ok((AssistantTurn::text(self.pieces.concat()), None))
    }
}

struct Plain;
impl LlmClient for Plain {
    fn complete(&self, _req: &CompletionRequest) -> Result<AssistantTurn, LlmError> {
        Ok(AssistantTurn::text("whole answer"))
    }
}

struct Ok1;
impl ToolHost for Ok1 {
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

fn cfg() -> LoopConfig {
    LoopConfig {
        model: "m".into(),
        system_prompt: "s".into(),
        max_steps: 4,
        max_tool_calls_per_step: 4,
        max_tokens: 64,
    }
}

fn deltas(events: &[Event]) -> Vec<(u32, String)> {
    events
        .iter()
        .filter_map(|e| match e {
            Event::AssistantDelta { step, text } => Some((*step, text.clone())),
            _ => None,
        })
        .collect()
}

fn registry() -> ToolRegistry {
    ToolRegistry::new(vec![ToolSpec {
        name: "node_status".into(),
        description: "d".into(),
        parameters: serde_json::json!({"type": "object"}),
        host: HostKind::Core,
        annotations: Default::default(),
    }])
    .with_host(HostKind::Core, std::sync::Arc::new(Ok1))
}

#[test]
fn small_pieces_are_batched_and_the_final_event_is_unchanged() {
    let pieces: Vec<String> = (0..200).map(|i| format!("w{i} ")).collect();
    let whole = pieces.concat();
    let llm = Streaming {
        pieces,
        pause: std::time::Duration::ZERO,
        tool_first: Mutex::new(false),
    };
    let sink = Sink::default();
    let mut history = vec![];
    let out = run_turn(
        &cfg(),
        &llm,
        &ToolRegistry::new(vec![]),
        &sink,
        &StopFlag::default(),
        &mut history,
        "hi",
    );
    assert_eq!(out, RunOutcome::Answered(whole.clone()));
    let ev = sink.0.lock().unwrap().clone();
    let d = deltas(&ev);
    assert!(
        !d.is_empty() && d.len() < 200,
        "200 pieces become far fewer events ({})",
        d.len()
    );
    assert_eq!(
        d.iter().map(|(_, t)| t.as_str()).collect::<String>(),
        whole,
        "no text lost or repeated"
    );
    assert!(d.iter().all(|(s, _)| *s == 1));
    let kinds: Vec<&str> = ev.iter().map(Event::kind).collect();
    let last_delta = kinds.iter().rposition(|k| *k == "assistant_delta").unwrap();
    let fin = kinds.iter().position(|k| *k == "final").unwrap();
    assert!(
        last_delta < fin,
        "every delta comes before the final event: {kinds:?}"
    );
    assert_eq!(ev[fin], Event::Final { content: whole });
}

#[test]
fn slow_pieces_are_not_held_back() {
    let llm = Streaming {
        pieces: vec!["a".into(), "b".into(), "c".into()],
        pause: DeltaCoalescer::MAX_WAIT + std::time::Duration::from_millis(10),
        tool_first: Mutex::new(false),
    };
    let sink = Sink::default();
    let mut history = vec![];
    run_turn(
        &cfg(),
        &llm,
        &ToolRegistry::new(vec![]),
        &sink,
        &StopFlag::default(),
        &mut history,
        "hi",
    );
    let d = deltas(&sink.0.lock().unwrap());
    assert!(
        d.len() >= 2,
        "a slow model's text is emitted as it comes, not only at the end: {d:?}"
    );
}

#[test]
fn text_before_a_tool_call_streams_with_its_own_step_and_no_final() {
    let llm = Streaming {
        pieces: vec!["Height 6,310.".into()],
        pause: std::time::Duration::ZERO,
        tool_first: Mutex::new(true),
    };
    let sink = Sink::default();
    let mut history = vec![];
    let out = run_turn(
        &cfg(),
        &llm,
        &registry(),
        &sink,
        &StopFlag::default(),
        &mut history,
        "height?",
    );
    assert_eq!(out, RunOutcome::Answered("Height 6,310.".into()));
    let ev = sink.0.lock().unwrap().clone();
    assert_eq!(
        deltas(&ev),
        vec![
            (1, "Let me check. ".to_string()),
            (2, "Height 6,310.".to_string())
        ]
    );
    let finals: Vec<&Event> = ev.iter().filter(|e| e.kind() == "final").collect();
    assert_eq!(
        finals,
        vec![&Event::Final {
            content: "Height 6,310.".into()
        }],
        "only the answering step has a final"
    );
}

#[test]
fn a_model_that_cannot_stream_emits_no_deltas() {
    let sink = Sink::default();
    let mut history = vec![];
    let out = run_turn(
        &cfg(),
        &Plain,
        &ToolRegistry::new(vec![]),
        &sink,
        &StopFlag::default(),
        &mut history,
        "hi",
    );
    assert_eq!(out, RunOutcome::Answered("whole answer".into()));
    let kinds: Vec<&str> = sink.0.lock().unwrap().iter().map(Event::kind).collect();
    assert_eq!(
        kinds,
        vec!["step_start", "final", "done"],
        "the event stream is exactly as before"
    );
}

#[test]
fn the_delta_wire_shape_is_stable() {
    let v = serde_json::to_value(Event::AssistantDelta {
        step: 2,
        text: "Hi".into(),
    })
    .unwrap();
    assert_eq!(
        v,
        serde_json::json!({"type": "assistant_delta", "step": 2, "text": "Hi"})
    );
}

/// A streamed answer with usage.
struct StreamingWithUsage;
impl LlmClient for StreamingWithUsage {
    fn complete(&self, _req: &CompletionRequest) -> Result<AssistantTurn, LlmError> {
        Ok(AssistantTurn::text("streamed"))
    }
    fn complete_streaming(
        &self,
        _req: &CompletionRequest,
        on_delta: &mut dyn FnMut(&str),
    ) -> Result<(AssistantTurn, Option<TokenUsage>), LlmError> {
        on_delta("streamed");
        Ok((
            AssistantTurn::text("streamed"),
            Some(TokenUsage {
                prompt_tokens: 40,
                completion_tokens: 8,
                generation_ms: Some(200),
                prompt_ms: None,
            }),
        ))
    }
}

/// HUP-S7.6 with HUP-S1.1: a streamed answer still reports the provider's usage to the monitor.
#[test]
fn a_streamed_answer_still_emits_its_usage() {
    let sink = Sink::default();
    let mut history = vec![];
    let out = run_turn(
        &cfg(),
        &StreamingWithUsage,
        &ToolRegistry::new(vec![]),
        &sink,
        &StopFlag::default(),
        &mut history,
        "hi",
    );
    assert_eq!(out, RunOutcome::Answered("streamed".into()));
    let ev = sink.0.lock().unwrap().clone();
    let usage: Vec<_> = ev
        .iter()
        .filter_map(|e| match e {
            Event::Usage {
                prompt_tokens,
                completion_tokens,
                generation_ms,
                ..
            } => Some((*prompt_tokens, *completion_tokens, *generation_ms)),
            _ => None,
        })
        .collect();
    assert_eq!(usage, vec![(40, 8, Some(200))]);
}
