//! HUP-S1.9 — shared parity runner. Used by `agent-loop/tests/parity_tests.rs` (implementation
//! `loop`) and, via `#[path]`, by `agent-sidecar/tests/parity_wire_tests.rs` (implementation
//! `sidecar`). The fixture is byte-identical to citrate-core `src/agent/parity/parity-v1.json`,
//! which drives the TypeScript loop (`harness.ts`); the sha256 pin below matches the one there.
#![allow(dead_code)]

use citrate_agent_loop::*;
use serde_json::Value;
use sha2::{Digest, Sha256};
use std::sync::{Arc, Mutex};

/// sha256 of `fixtures/parity-v1.json`. Changing the fixture means bumping this here AND in
/// citrate-core `src/agent/parity/parity.test.ts`.
pub const PARITY_V1_SHA256: &str =
    "2ecdbe41b965df2493f272323b8f901345bb16515bd1114896a91a34e3a2f1fc";

pub const FIXTURE_BYTES: &[u8] = include_bytes!("../fixtures/parity-v1.json");

pub fn sha256_hex(bytes: &[u8]) -> String {
    Sha256::digest(bytes)
        .iter()
        .map(|b| format!("{b:02x}"))
        .collect()
}

pub fn fixture() -> Value {
    serde_json::from_slice(FIXTURE_BYTES).expect("parity fixture is JSON")
}

/// Turns one fixture `model[]` entry that is not an `{error}` into the loop's [`AssistantTurn`].
pub type TurnFn = dyn Fn(&Value) -> Result<AssistantTurn, LlmError> + Send + Sync;

struct ScriptLlm {
    entries: Vec<Value>,
    repeat_last: bool,
    idx: Mutex<usize>,
    seen: Mutex<Vec<CompletionRequest>>,
    to_turn: Arc<TurnFn>,
}

impl LlmClient for ScriptLlm {
    fn complete(&self, req: &CompletionRequest) -> Result<AssistantTurn, LlmError> {
        self.seen.lock().unwrap().push(req.clone());
        let mut idx = self.idx.lock().unwrap();
        if self.entries.is_empty() || (*idx >= self.entries.len() && !self.repeat_last) {
            return Err(LlmError::Provider("parity script exhausted".into()));
        }
        let entry = self.entries[(*idx).min(self.entries.len() - 1)].clone();
        *idx += 1;
        if let Some(e) = entry.get("error").and_then(Value::as_str) {
            return Err(LlmError::Transport(e.to_string()));
        }
        (self.to_turn)(&entry)
    }
}

struct ScriptHost {
    results: Vec<Value>,
    default: Option<Value>,
    calls: Mutex<Vec<ToolCall>>,
    stop: StopFlag,
    stop_after: Option<usize>,
}

impl ToolHost for ScriptHost {
    fn execute(&self, call: &ToolCall) -> ToolOutcome {
        let mut calls = self.calls.lock().unwrap();
        let r = self
            .results
            .get(calls.len())
            .cloned()
            .or_else(|| self.default.clone());
        calls.push(call.clone());
        if self.stop_after == Some(calls.len()) {
            self.stop.stop();
        }
        let Some(r) = r else {
            return ToolOutcome::Error("parity script: no tool result scripted".into());
        };
        if let Some(s) = r.get("ok").and_then(Value::as_str) {
            ToolOutcome::Ok(s.into())
        } else if let Some(s) = r.get("denied").and_then(Value::as_str) {
            ToolOutcome::Denied(s.into())
        } else if let Some(s) = r.get("error").and_then(Value::as_str) {
            ToolOutcome::Error(s.into())
        } else {
            ToolOutcome::Error("parity script: unrecognised tool result".into())
        }
    }
}

#[derive(Default)]
struct Sink(Mutex<Vec<Event>>);
impl EventSink for Sink {
    fn emit(&self, ev: Event) {
        self.0.lock().unwrap().push(ev);
    }
}

/// `expect` merged with this implementation's `known_divergence` override (shallow, like the TS side).
pub fn effective(scn: &Value, implementation: &str) -> serde_json::Map<String, Value> {
    let mut ex = scn["expect"].as_object().cloned().unwrap_or_default();
    if let Some(over) = scn
        .get("known_divergence")
        .and_then(|d| d.get(implementation))
        .and_then(Value::as_object)
    {
        for (k, v) in over {
            ex.insert(k.clone(), v.clone());
        }
    }
    ex
}

fn role_str(r: Role) -> &'static str {
    match r {
        Role::System => "system",
        Role::User => "user",
        Role::Assistant => "assistant",
        Role::Tool => "tool",
    }
}

/// Run one scenario through `run_turn` and return every mismatch against the effective expectation.
pub fn run_scenario(
    fx: &Value,
    scn: &Value,
    implementation: &str,
    to_turn: Arc<TurnFn>,
) -> Vec<String> {
    let id = scn["id"].as_str().unwrap_or("?").to_string();
    let ex = effective(scn, implementation);
    let mut bad = Vec::new();
    let mut check = |what: &str, ok: bool, detail: String| {
        if !ok {
            bad.push(format!("[{implementation}] {id}: {what}: {detail}"));
        }
    };

    let limits = &fx["limits"];
    let cfg = LoopConfig {
        model: "parity".into(),
        system_prompt: "parity system prompt".into(),
        max_steps: limits["rust_max_steps"].as_u64().unwrap() as u32,
        max_tool_calls_per_step: limits["rust_max_tool_calls_per_step"].as_u64().unwrap() as u32,
        max_tokens: 512,
    };
    let llm = ScriptLlm {
        entries: scn["model"].as_array().cloned().unwrap_or_default(),
        repeat_last: scn["model_repeat_last"].as_bool().unwrap_or(false),
        idx: Mutex::new(0),
        seen: Mutex::new(vec![]),
        to_turn,
    };
    let stop = StopFlag::default();
    let host = Arc::new(ScriptHost {
        results: scn["tool_results"].as_array().cloned().unwrap_or_default(),
        default: scn.get("tool_result_default").cloned(),
        calls: Mutex::new(vec![]),
        stop: stop.clone(),
        stop_after: scn["stop_after_host_calls"].as_u64().map(|n| n as usize),
    });
    // The fixture's roster mirrors harness.ts AGENT_TOOLS + READ_ONLY_AGENT_TOOLS; all core-hosted.
    let specs = fx["tools"]
        .as_array()
        .cloned()
        .unwrap_or_default()
        .iter()
        .map(|t| {
            let n = t["name"].as_str().unwrap_or_default();
            ToolSpec {
                name: n.into(),
                description: format!("{n} (parity)"),
                parameters: serde_json::json!({"type": "object"}),
                host: HostKind::Core,
                // Annotated the way the app annotates its own tools (HUP-A8): reads are
                // `effect: none`, the rest `write`, and results from the app's gated handlers are
                // trusted. Parity covers the untainted loop; the taint downgrade (HUP-S2.7) has its
                // own suite (taint_tests.rs), and harness.ts has no taint concept to compare with.
                annotations: {
                    let read_only = t["read_only"].as_bool().unwrap_or(false);
                    ToolAnnotations {
                        read_only,
                        effect: Some(if read_only {
                            citrate_agent_loop::Effect::None
                        } else {
                            citrate_agent_loop::Effect::Write
                        }),
                        trust: Some(citrate_agent_loop::Trust::Trusted),
                        ..ToolAnnotations::default()
                    }
                },
            }
        })
        .collect();
    let tools = ToolRegistry::new(specs).with_host(HostKind::Core, host.clone());
    let sink = Sink::default();
    let mut history: Vec<Message> = scn["history"]
        .as_array()
        .cloned()
        .unwrap_or_default()
        .iter()
        .map(|m| Message {
            role: if m["role"] == "assistant" {
                Role::Assistant
            } else {
                Role::User
            },
            content: m["content"].as_str().unwrap_or("").into(),
            tool_calls: vec![],
            tool_call_id: None,
        })
        .collect();

    let outcome = run_turn(
        &cfg,
        &llm,
        &tools,
        &sink,
        &stop,
        &mut history,
        scn["user"].as_str().unwrap_or(""),
    );

    let events = sink.0.lock().unwrap().clone();
    let seen = llm.seen.lock().unwrap().clone();
    let host_calls = host.calls.lock().unwrap().clone();
    let (label, final_text, failure) = match &outcome {
        RunOutcome::Answered(s) => ("answered", Some(s.clone()), String::new()),
        RunOutcome::Stopped => ("stopped", None, String::new()),
        RunOutcome::StepLimit => ("step_limit", None, String::new()),
        RunOutcome::Failed(m) => ("failed", None, m.clone()),
    };
    let error_events: Vec<String> = events
        .iter()
        .filter_map(|e| match e {
            Event::Error { message } => Some(message.clone()),
            _ => None,
        })
        .collect();

    if let Some(o) = ex.get("outcome").and_then(Value::as_str) {
        check("outcome", label == o, format!("got {label}, want {o}"));
    }
    if let Some(f) = ex.get("final").and_then(Value::as_str) {
        check(
            "final",
            final_text.as_deref() == Some(f),
            format!("got {final_text:?}, want {f:?}"),
        );
        let final_ev = events.iter().find_map(|e| match e {
            Event::Final { content } => Some(content.clone()),
            _ => None,
        });
        check(
            "final event",
            final_ev.as_deref() == Some(f),
            format!("got {final_ev:?}"),
        );
    }
    if let Some(t) = ex.get("terminal").and_then(Value::as_str) {
        // core's sidecar provider: answered|stopped -> done, anything else -> error.
        let terminal = if matches!(label, "answered" | "stopped") {
            "done"
        } else {
            "error"
        };
        check(
            "terminal",
            terminal == t,
            format!("got {terminal}, want {t}"),
        );
        if t == "error" {
            check(
                "error event",
                !error_events.is_empty(),
                "no error event emitted".into(),
            );
        }
    }
    match events.last() {
        Some(Event::Done { outcome }) => {
            check("done event", outcome == label, format!("done={outcome}"))
        }
        other => check("done event", false, format!("last event {other:?}")),
    }
    if !seen.is_empty() {
        check(
            "first event",
            matches!(events.first(), Some(Event::StepStart { .. })),
            format!("{:?}", events.first()),
        );
    }
    if let Some(n) = ex.get("model_calls").and_then(Value::as_u64) {
        check(
            "model_calls",
            seen.len() as u64 == n,
            format!("got {}, want {n}", seen.len()),
        );
    }
    if let Some(want) = ex.get("host_calls").and_then(Value::as_array) {
        let got: Vec<Value> = host_calls
            .iter()
            .map(|c| Value::String(c.name.clone()))
            .collect();
        check(
            "host_calls",
            &got == want,
            format!("got {got:?}, want {want:?}"),
        );
    }
    if let Some(want) = ex.get("host_arguments").and_then(Value::as_array) {
        let got: Vec<Value> = host_calls
            .iter()
            .map(|c| Value::String(c.arguments.clone()))
            .collect();
        check(
            "host_arguments",
            &got == want,
            format!("got {got:?}, want {want:?}"),
        );
    }
    if let Some(n) = ex.get("tool_events").and_then(Value::as_u64) {
        let got = events.iter().filter(|e| e.kind() == "tool_call").count() as u64;
        check("tool_events", got == n, format!("got {got}, want {n}"));
    }

    let last: Vec<Message> = seen
        .last()
        .map(|r| {
            r.messages
                .iter()
                .filter(|m| m.role != Role::System)
                .cloned()
                .collect()
        })
        .unwrap_or_default();
    if let Some(want) = ex.get("last_request_roles").and_then(Value::as_array) {
        let got: Vec<Value> = last
            .iter()
            .map(|m| Value::String(role_str(m.role).into()))
            .collect();
        check(
            "last_request_roles",
            &got == want,
            format!("got {got:?}, want {want:?}"),
        );
    }
    if let Some(want) = ex
        .get("last_request_assistant_content")
        .and_then(Value::as_str)
    {
        let got = last
            .iter()
            .rev()
            .find(|m| m.role == Role::Assistant)
            .map(|m| m.content.clone());
        check(
            "last_request_assistant_content",
            got.as_deref() == Some(want),
            format!("got {got:?}"),
        );
    }
    if let Some(want) = ex.get("tool_messages").and_then(Value::as_array) {
        let got: Vec<&Message> = last.iter().filter(|m| m.role == Role::Tool).collect();
        check(
            "tool_messages count",
            got.len() == want.len(),
            format!("got {}, want {}", got.len(), want.len()),
        );
        for (i, (g, w)) in got.iter().zip(want.iter()).enumerate() {
            if let Some(idw) = w.get("tool_call_id").and_then(Value::as_str) {
                check(
                    &format!("tool_messages[{i}].tool_call_id"),
                    g.tool_call_id.as_deref() == Some(idw),
                    format!("got {:?}", g.tool_call_id),
                );
            }
            if let Some(c) = w.get("content").and_then(Value::as_str) {
                check(
                    &format!("tool_messages[{i}].content"),
                    g.content == c,
                    format!("got {:?}, want {c:?}", g.content),
                );
            }
            if let Some(c) = w.get("content_contains").and_then(Value::as_str) {
                check(
                    &format!("tool_messages[{i}].content_contains"),
                    g.content.contains(c),
                    format!("got {:?}, want ⊇ {c:?}", g.content),
                );
            }
            if w.get("id_synthesized").and_then(Value::as_bool) == Some(true) {
                let gid = g.tool_call_id.clone().unwrap_or_default();
                let host_id = host_calls.get(i).map(|c| c.id.clone()).unwrap_or_default();
                check(
                    &format!("tool_messages[{i}].id_synthesized"),
                    !gid.is_empty() && gid == host_id,
                    format!("tool msg id {gid:?}, host id {host_id:?}"),
                );
            }
        }
    }
    if let Some(want) = ex.get("first_request_messages").and_then(Value::as_array) {
        let got: Vec<Value> = seen
            .first()
            .map(|r| {
                r.messages
                    .iter()
                    .filter(|m| m.role != Role::System)
                    .map(|m| serde_json::json!({"role": role_str(m.role), "content": m.content}))
                    .collect()
            })
            .unwrap_or_default();
        check(
            "first_request_messages",
            &got == want,
            format!("got {got:?}, want {want:?}"),
        );
    }
    if matches!(label, "failed" | "step_limit") {
        let needle = match ex.get("error_contains") {
            Some(Value::String(s)) => Some(s.clone()),
            Some(Value::Object(m)) => m
                .get(implementation)
                .and_then(Value::as_str)
                .map(str::to_string),
            _ => None,
        };
        if let Some(n) = needle {
            let text = if failure.is_empty() {
                error_events.join(" | ")
            } else {
                failure.clone()
            };
            check(
                "error_contains",
                text.contains(&n),
                format!("got {text:?}, want ⊇ {n:?}"),
            );
        }
    }
    bad
}
