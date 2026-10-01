//! HUP-S2.7 — taint tracking and the HIC downgrade (TLA+ `agent-loop/formal/TaintDowngrade.tla`).
//!
//! Once a session has ingested untrusted content, every effectful tool call needs an explicit
//! member decision: no auto-approval and no budget path, for the rest of the session, unless a
//! member clears the taint. Untainted sessions behave exactly as before.
use citrate_agent_loop::*;
use std::sync::{Arc, Mutex};

struct ScriptLlm(Mutex<Vec<AssistantTurn>>);
impl ScriptLlm {
    fn new(t: Vec<AssistantTurn>) -> Self {
        ScriptLlm(Mutex::new(t))
    }
}
impl LlmClient for ScriptLlm {
    fn complete(&self, _req: &CompletionRequest) -> Result<AssistantTurn, LlmError> {
        let mut t = self.0.lock().unwrap();
        Ok(if t.is_empty() {
            AssistantTurn::text("done")
        } else {
            t.remove(0)
        })
    }
}

/// Records how each call reached it: through the ordinary path or the explicit-approval path.
struct RecHost {
    honors_hic: bool,
    result: ToolOutcome,
    plain: Mutex<Vec<String>>,
    explicit: Mutex<Vec<(String, String)>>,
}
impl RecHost {
    fn new(honors_hic: bool, result: ToolOutcome) -> Self {
        RecHost {
            honors_hic,
            result,
            plain: Mutex::new(vec![]),
            explicit: Mutex::new(vec![]),
        }
    }
    fn plain(&self) -> Vec<String> {
        self.plain.lock().unwrap().clone()
    }
    fn explicit(&self) -> Vec<(String, String)> {
        self.explicit.lock().unwrap().clone()
    }
}
impl ToolHost for RecHost {
    fn execute(&self, call: &ToolCall) -> ToolOutcome {
        self.plain.lock().unwrap().push(call.name.clone());
        self.result.clone()
    }
    fn honors_explicit_approval(&self) -> bool {
        self.honors_hic
    }
    fn execute_with_explicit_approval(&self, call: &ToolCall, reason: &str) -> ToolOutcome {
        self.explicit
            .lock()
            .unwrap()
            .push((call.name.clone(), reason.to_string()));
        self.result.clone()
    }
}

/// Returns a different outcome per tool name (default: ok).
struct PerTool {
    inner: RecHost,
    by_name: Vec<(&'static str, ToolOutcome)>,
}
impl ToolHost for PerTool {
    fn execute(&self, call: &ToolCall) -> ToolOutcome {
        self.inner.execute(call);
        self.pick(call)
    }
    fn honors_explicit_approval(&self) -> bool {
        self.inner.honors_hic
    }
    fn execute_with_explicit_approval(&self, call: &ToolCall, reason: &str) -> ToolOutcome {
        self.inner.execute_with_explicit_approval(call, reason);
        self.pick(call)
    }
}
impl PerTool {
    fn pick(&self, call: &ToolCall) -> ToolOutcome {
        self.by_name
            .iter()
            .find(|(n, _)| *n == call.name)
            .map(|(_, o)| o.clone())
            .unwrap_or_else(|| ToolOutcome::Ok("ok".into()))
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
    fn events(&self) -> Vec<Event> {
        self.0.lock().unwrap().clone()
    }
    fn kinds(&self) -> Vec<&'static str> {
        self.0.lock().unwrap().iter().map(Event::kind).collect()
    }
    fn tool_call(&self, id: &str) -> Event {
        self.events()
            .into_iter()
            .find(|e| matches!(e, Event::ToolCall { call, .. } if call.id == id))
            .unwrap_or_else(|| panic!("no tool_call event for {id}"))
    }
}

fn spec(name: &str, effect: Option<Effect>, trust: Option<Trust>) -> ToolSpec {
    ToolSpec {
        name: name.into(),
        description: format!("{name} tool"),
        parameters: serde_json::json!({"type": "object"}),
        host: HostKind::Core,
        annotations: ToolAnnotations {
            effect,
            trust,
            ..Default::default()
        },
    }
}

fn call(id: &str, name: &str) -> ToolCall {
    ToolCall {
        id: id.into(),
        name: name.into(),
        arguments: "{}".into(),
    }
}

fn cfg() -> LoopConfig {
    LoopConfig {
        model: "m".into(),
        system_prompt: "You are Hermes.".into(),
        max_steps: 6,
        max_tool_calls_per_step: 4,
        max_tokens: 256,
    }
}

/// The trusted, read-only catalog plus one untrusted reader and some effectful tools.
fn catalog() -> Vec<ToolSpec> {
    vec![
        spec("node_status", Some(Effect::None), Some(Trust::Trusted)),
        spec("web_fetch", Some(Effect::None), Some(Trust::Untrusted)),
        spec("write_file", Some(Effect::Write), Some(Trust::Trusted)),
        spec("send_salt", Some(Effect::Spend), Some(Trust::Trusted)),
        spec("sign_message", Some(Effect::Sign), Some(Trust::Trusted)),
    ]
}

fn hic_of(ev: &Event) -> (Option<&'static str>, Option<String>, Option<HostKind>) {
    match ev {
        Event::ToolCall {
            hic,
            hic_reason,
            host,
            ..
        } => (*hic, hic_reason.clone(), *host),
        other => panic!("not a tool_call: {other:?}"),
    }
}

#[test]
fn an_untainted_session_keeps_the_ordinary_path_for_every_tool() {
    let llm = ScriptLlm::new(vec![
        AssistantTurn::tools(vec![call("c1", "node_status"), call("c2", "write_file")]),
        AssistantTurn::tools(vec![call("c3", "send_salt")]),
        AssistantTurn::text("done"),
    ]);
    let host = Arc::new(RecHost::new(true, ToolOutcome::Ok("ok".into())));
    let tools = ToolRegistry::new(catalog()).with_host(HostKind::Core, host.clone());
    let sink = Sink::default();
    let out = run_turn(
        &cfg(),
        &llm,
        &tools,
        &sink,
        &StopFlag::default(),
        &mut vec![],
        "go",
    );
    assert_eq!(out, RunOutcome::Answered("done".into()));
    assert_eq!(host.plain(), vec!["node_status", "write_file", "send_salt"]);
    assert!(
        host.explicit().is_empty(),
        "no explicit-approval path while untainted"
    );
    for id in ["c1", "c2", "c3"] {
        assert_eq!(
            hic_of(&sink.tool_call(id)),
            (None, None, Some(HostKind::Core))
        );
    }
    assert!(!sink.kinds().contains(&"tainted"));
    assert!(!tools.taint().is_tainted());
    // Untainted, an untainted tool_call serializes exactly as before (no hic fields).
    let v = serde_json::to_value(sink.tool_call("c2")).unwrap();
    assert!(
        v.get("hic").is_none() && v.get("hic_reason").is_none(),
        "{v}"
    );
}

#[test]
fn an_untrusted_result_flips_the_taint_once_and_says_so() {
    let llm = ScriptLlm::new(vec![
        AssistantTurn::tools(vec![call("c1", "web_fetch")]),
        AssistantTurn::tools(vec![call("c2", "web_fetch")]),
        AssistantTurn::text("read it"),
    ]);
    let host = Arc::new(RecHost::new(
        false,
        ToolOutcome::Ok("<html>…</html>".into()),
    ));
    let tools = ToolRegistry::new(catalog()).with_host(HostKind::Core, host.clone());
    let sink = Sink::default();
    run_turn(
        &cfg(),
        &llm,
        &tools,
        &sink,
        &StopFlag::default(),
        &mut vec![],
        "read the page",
    );
    assert!(tools.taint().is_tainted());
    let rec = tools.taint().record().expect("a taint record");
    assert_eq!(rec.source, "web_fetch");
    let tainted: Vec<Event> = sink
        .events()
        .into_iter()
        .filter(|e| e.kind() == "tainted")
        .collect();
    assert_eq!(tainted.len(), 1, "the flip is announced exactly once");
    match &tainted[0] {
        Event::Tainted { step, source, .. } => {
            assert_eq!(*step, 1);
            assert_eq!(source, "web_fetch");
        }
        other => panic!("{other:?}"),
    }
    // A read-only (effect: none) tool stays on the ordinary path even when tainted.
    assert_eq!(hic_of(&sink.tool_call("c2")).0, None);
    assert_eq!(host.plain(), vec!["web_fetch", "web_fetch"]);
    // The flip comes right after the result that caused it.
    let kinds = sink.kinds();
    let i = kinds.iter().position(|k| *k == "tainted").unwrap();
    assert_eq!(kinds[i - 1], "tool_result");
}

#[test]
fn an_effectful_call_after_taint_needs_explicit_approval() {
    let llm = ScriptLlm::new(vec![
        AssistantTurn::tools(vec![call("c1", "web_fetch")]),
        AssistantTurn::tools(vec![
            call("c2", "write_file"),
            call("c3", "send_salt"),
            call("c4", "sign_message"),
            call("c5", "node_status"),
        ]),
        AssistantTurn::text("done"),
    ]);
    let host = Arc::new(RecHost::new(true, ToolOutcome::Ok("ok".into())));
    let tools = ToolRegistry::new(catalog()).with_host(HostKind::Core, host.clone());
    let sink = Sink::default();
    run_turn(
        &cfg(),
        &llm,
        &tools,
        &sink,
        &StopFlag::default(),
        &mut vec![],
        "go",
    );
    for id in ["c2", "c3", "c4"] {
        let (hic, reason, host_kind) = hic_of(&sink.tool_call(id));
        assert_eq!(hic, Some("required"), "{id}");
        assert!(
            reason.unwrap().contains("web_fetch"),
            "{id}: the reason names the source"
        );
        assert_eq!(host_kind, Some(HostKind::Core));
    }
    assert_eq!(hic_of(&sink.tool_call("c5")).0, None, "reads stay ordinary");
    let explicit: Vec<String> = host.explicit().into_iter().map(|(n, _)| n).collect();
    assert_eq!(explicit, vec!["write_file", "send_salt", "sign_message"]);
    assert_eq!(host.plain(), vec!["web_fetch", "node_status"]);
    // The wire shape carries the requirement.
    let v = serde_json::to_value(sink.tool_call("c3")).unwrap();
    assert_eq!(v["hic"], "required");
    assert!(v["hic_reason"]
        .as_str()
        .unwrap()
        .contains("explicit approval"));
}

#[test]
fn a_host_that_cannot_ask_a_member_refuses_instead_of_running() {
    let llm = ScriptLlm::new(vec![
        AssistantTurn::tools(vec![call("c1", "web_fetch"), call("c2", "write_file")]),
        AssistantTurn::text("done"),
    ]);
    let host = Arc::new(RecHost::new(false, ToolOutcome::Ok("ok".into())));
    let tools = ToolRegistry::new(catalog()).with_host(HostKind::Core, host.clone());
    let sink = Sink::default();
    let mut history = vec![];
    run_turn(
        &cfg(),
        &llm,
        &tools,
        &sink,
        &StopFlag::default(),
        &mut history,
        "go",
    );
    assert_eq!(
        host.plain(),
        vec!["web_fetch"],
        "the write never reached the host"
    );
    assert!(host.explicit().is_empty());
    let (hic, _, host_kind) = hic_of(&sink.tool_call("c2"));
    assert_eq!(hic, Some("required"));
    assert_eq!(
        host_kind, None,
        "a refused call is not dispatched to any host"
    );
    let denied = sink.events().into_iter().any(|e| {
        matches!(e, Event::ToolResult { call_id, status, .. } if call_id == "c2" && status == "denied")
    });
    assert!(denied, "the model is told the action was declined");
    let msg = history
        .iter()
        .find(|m| m.tool_call_id.as_deref() == Some("c2"))
        .unwrap();
    assert!(msg.content.starts_with("declined:"), "{}", msg.content);
}

#[test]
fn the_taint_persists_across_steps_and_turns() {
    let llm = ScriptLlm::new(vec![
        AssistantTurn::tools(vec![call("c1", "web_fetch")]),
        AssistantTurn::tools(vec![call("c2", "node_status")]),
        AssistantTurn::tools(vec![call("c3", "write_file")]),
        AssistantTurn::text("first turn done"),
        // second turn on the same registry (= same session)
        AssistantTurn::tools(vec![call("c4", "send_salt")]),
        AssistantTurn::text("second turn done"),
    ]);
    let host = Arc::new(RecHost::new(true, ToolOutcome::Ok("ok".into())));
    let tools = ToolRegistry::new(catalog()).with_host(HostKind::Core, host.clone());
    let sink = Sink::default();
    let mut history = vec![];
    run_turn(
        &cfg(),
        &llm,
        &tools,
        &sink,
        &StopFlag::default(),
        &mut history,
        "one",
    );
    // A trusted read in step 2 does not wash the taint out.
    assert_eq!(hic_of(&sink.tool_call("c3")).0, Some("required"));
    run_turn(
        &cfg(),
        &llm,
        &tools,
        &sink,
        &StopFlag::default(),
        &mut history,
        "two",
    );
    assert_eq!(hic_of(&sink.tool_call("c4")).0, Some("required"));
    assert_eq!(
        sink.kinds().iter().filter(|k| **k == "tainted").count(),
        1,
        "already tainted: no second flip"
    );
    // A session's registry is rebuilt per turn in the sidecar; the shared state carries over.
    let rebuilt = ToolRegistry::new(catalog())
        .with_host(HostKind::Core, host.clone())
        .with_taint(tools.taint().clone());
    assert!(rebuilt.taint().is_tainted());
}

#[test]
fn a_call_later_in_the_same_batch_sees_the_taint() {
    let llm = ScriptLlm::new(vec![
        AssistantTurn::tools(vec![
            call("c1", "write_file"),
            call("c2", "web_fetch"),
            call("c3", "write_file"),
        ]),
        AssistantTurn::text("done"),
    ]);
    let host = Arc::new(RecHost::new(true, ToolOutcome::Ok("ok".into())));
    let tools = ToolRegistry::new(catalog()).with_host(HostKind::Core, host.clone());
    let sink = Sink::default();
    run_turn(
        &cfg(),
        &llm,
        &tools,
        &sink,
        &StopFlag::default(),
        &mut vec![],
        "go",
    );
    assert_eq!(hic_of(&sink.tool_call("c1")).0, None, "before the taint");
    assert_eq!(
        hic_of(&sink.tool_call("c3")).0,
        Some("required"),
        "after it"
    );
}

#[test]
fn unannotated_tools_default_to_effectful_and_untrusted() {
    let a = ToolAnnotations::default();
    assert!(a.is_effectful(), "unknown effect is treated as effectful");
    assert!(
        a.output_untrusted(),
        "unknown source is treated as untrusted"
    );
    // The wire form without the new fields parses to the same safe defaults.
    let s: ToolSpec = serde_json::from_value(serde_json::json!({
        "name": "mystery", "description": "?", "parameters": {"type": "object"}, "host": "core"
    }))
    .unwrap();
    assert_eq!(s.annotations.effect, None);
    assert_eq!(s.annotations.trust, None);
    assert!(s.annotations.is_effectful() && s.annotations.output_untrusted());
    // Explicit annotations parse from lowercase names.
    let s: ToolSpec = serde_json::from_value(serde_json::json!({
        "name": "r", "description": "", "parameters": {}, "host": "core",
        "annotations": {"effect": "none", "trust": "trusted"}
    }))
    .unwrap();
    assert!(!s.annotations.is_effectful() && !s.annotations.output_untrusted());
    for (e, effectful) in [
        (Effect::None, false),
        (Effect::Write, true),
        (Effect::Spend, true),
        (Effect::Sign, true),
    ] {
        let a = ToolAnnotations {
            effect: Some(e),
            ..Default::default()
        };
        assert_eq!(a.is_effectful(), effectful, "{e:?}");
    }

    // In a loop: the first unannotated call runs normally (untainted), its output taints, and the
    // second unannotated call needs explicit approval.
    let llm = ScriptLlm::new(vec![
        AssistantTurn::tools(vec![call("c1", "mystery")]),
        AssistantTurn::tools(vec![call("c2", "mystery")]),
        AssistantTurn::text("done"),
    ]);
    let host = Arc::new(RecHost::new(true, ToolOutcome::Ok("ok".into())));
    let tools = ToolRegistry::new(vec![spec("mystery", None, None)])
        .with_host(HostKind::Core, host.clone());
    let sink = Sink::default();
    run_turn(
        &cfg(),
        &llm,
        &tools,
        &sink,
        &StopFlag::default(),
        &mut vec![],
        "go",
    );
    assert_eq!(hic_of(&sink.tool_call("c1")).0, None);
    assert_eq!(hic_of(&sink.tool_call("c2")).0, Some("required"));
}

#[test]
fn a_host_can_mark_one_result_untrusted_even_from_a_trusted_tool() {
    // e.g. a file read that resolved outside the granted folders.
    let llm = ScriptLlm::new(vec![
        AssistantTurn::tools(vec![call("c1", "read_file"), call("c2", "write_file")]),
        AssistantTurn::text("done"),
    ]);
    let host = Arc::new(PerTool {
        inner: RecHost::new(true, ToolOutcome::Ok("ok".into())),
        by_name: vec![("read_file", ToolOutcome::Untrusted("outside text".into()))],
    });
    let mut specs = catalog();
    specs.push(spec("read_file", Some(Effect::None), Some(Trust::Trusted)));
    let tools = ToolRegistry::new(specs).with_host(HostKind::Core, host.clone());
    let sink = Sink::default();
    let mut history = vec![];
    run_turn(
        &cfg(),
        &llm,
        &tools,
        &sink,
        &StopFlag::default(),
        &mut history,
        "go",
    );
    assert!(tools.taint().is_tainted());
    assert_eq!(hic_of(&sink.tool_call("c2")).0, Some("required"));
    let r = sink.events().into_iter().find_map(|e| match e {
        Event::ToolResult {
            call_id,
            status,
            content,
            ..
        } if call_id == "c1" => Some((status, content)),
        _ => None,
    });
    assert_eq!(
        r,
        Some(("ok", "outside text".to_string())),
        "it is still an ok result"
    );
}

#[test]
fn results_that_ingested_nothing_do_not_taint() {
    // Declined calls ran nothing; loop-generated errors (unknown tool, bad JSON, no host) carry
    // no outside content.
    let llm = ScriptLlm::new(vec![
        AssistantTurn::tools(vec![
            call("c1", "web_fetch"),
            call("c2", "nope"),
            ToolCall {
                id: "c3".into(),
                name: "web_fetch".into(),
                arguments: "{not json".into(),
            },
        ]),
        AssistantTurn::tools(vec![call("c4", "write_file")]),
        AssistantTurn::text("done"),
    ]);
    let host = Arc::new(RecHost::new(
        true,
        ToolOutcome::Denied("member said no".into()),
    ));
    let tools = ToolRegistry::new(catalog()).with_host(HostKind::Core, host.clone());
    let sink = Sink::default();
    run_turn(
        &cfg(),
        &llm,
        &tools,
        &sink,
        &StopFlag::default(),
        &mut vec![],
        "go",
    );
    assert!(!tools.taint().is_tainted());
    assert_eq!(hic_of(&sink.tool_call("c4")).0, None);

    // A tool missing its host taints nothing either.
    let llm = ScriptLlm::new(vec![
        AssistantTurn::tools(vec![call("c1", "web_fetch")]),
        AssistantTurn::text("done"),
    ]);
    let tools = ToolRegistry::new(catalog());
    run_turn(
        &cfg(),
        &llm,
        &tools,
        &Sink::default(),
        &StopFlag::default(),
        &mut vec![],
        "go",
    );
    assert!(!tools.taint().is_tainted());
}

#[test]
fn an_error_from_an_untrusted_tool_taints() {
    // An error body from an untrusted source is still outside text in the context.
    let llm = ScriptLlm::new(vec![
        AssistantTurn::tools(vec![call("c1", "web_fetch")]),
        AssistantTurn::text("done"),
    ]);
    let host = Arc::new(RecHost::new(
        true,
        ToolOutcome::Error("502 from the page: …".into()),
    ));
    let tools = ToolRegistry::new(catalog()).with_host(HostKind::Core, host);
    run_turn(
        &cfg(),
        &llm,
        &tools,
        &Sink::default(),
        &StopFlag::default(),
        &mut vec![],
        "go",
    );
    assert!(tools.taint().is_tainted());
}

#[test]
fn only_an_explicit_member_action_clears_the_taint() {
    let t = TaintState::default();
    assert!(!t.is_tainted());
    assert!(
        t.clear_by_member(MemberClear::new("ok").unwrap()).is_none(),
        "nothing to clear"
    );
    assert!(
        MemberClear::new("   ").is_none(),
        "a clear must carry the member's note"
    );
    assert!(t.taint("web_fetch", "untrusted output"));
    assert!(!t.taint("mcp_tool", "second"), "already tainted: no flip");
    assert_eq!(
        t.record().unwrap().source,
        "web_fetch",
        "the first source is kept"
    );
    let shared = t.clone();
    assert!(shared.is_tainted(), "clones share one session state");
    let ack = MemberClear::new("I checked that page").unwrap();
    let was = t.clear_by_member(ack).unwrap();
    assert_eq!(was.source, "web_fetch");
    assert!(!shared.is_tainted());
}

#[test]
fn a_workflow_shares_the_session_taint_across_its_steps() {
    let llm = ScriptLlm::new(vec![
        AssistantTurn::tools(vec![call("c1", "web_fetch")]),
        AssistantTurn::text("read"),
        AssistantTurn::tools(vec![call("c2", "write_file")]),
        AssistantTurn::text("wrote"),
    ]);
    let host = Arc::new(RecHost::new(true, ToolOutcome::Ok("ok".into())));
    let tools = ToolRegistry::new(catalog()).with_host(HostKind::Core, host.clone());
    let sink = Sink::default();
    let wf = Workflow::new(
        "w",
        vec![
            Step {
                id: "read".into(),
                instruction: "read".into(),
                verifiers: vec![Arc::new(ToolSucceeded("web_fetch".into()))],
                max_attempts: 1,
            },
            Step {
                id: "write".into(),
                instruction: "write".into(),
                verifiers: vec![Arc::new(ToolSucceeded("write_file".into()))],
                max_attempts: 1,
            },
        ],
    )
    .unwrap();
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
    assert!(matches!(out, WorkflowOutcome::Succeeded { .. }), "{out:?}");
    assert_eq!(hic_of(&sink.tool_call("c2")).0, Some("required"));
    assert_eq!(host.explicit().len(), 1);
}
