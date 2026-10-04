//! HUP-S7.5 (runtime half): metering records derived from the real agent-loop event stream, the
//! daily report, the JSONL log and the opt-in BenchmarkRegistry calldata builder.
use citrate_agent_loop::*;
use citrate_agent_metering::*;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{Arc, Mutex};

// ---------------------------------------------------------------------------------------------
// Harness: a scripted model that advances a fake clock, real tool hosts, a capturing sink.
// ---------------------------------------------------------------------------------------------

#[derive(Default)]
struct FakeClock {
    unix: AtomicU64,
    mono: AtomicU64,
}
impl FakeClock {
    fn at(unix_ms: u64) -> Arc<Self> {
        let c = FakeClock::default();
        c.unix.store(unix_ms, Ordering::SeqCst);
        Arc::new(c)
    }
    fn advance(&self, ms: u64) {
        self.unix.fetch_add(ms, Ordering::SeqCst);
        self.mono.fetch_add(ms, Ordering::SeqCst);
    }
}
impl Clock for FakeClock {
    fn unix_ms(&self) -> u64 {
        self.unix.load(Ordering::SeqCst)
    }
    fn monotonic_ms(&self) -> u64 {
        self.mono.load(Ordering::SeqCst)
    }
}

struct Script {
    turns: Mutex<Vec<Result<AssistantTurn, LlmError>>>,
    clock: Arc<FakeClock>,
    per_call_ms: u64,
    usage: Option<(Arc<MeteringSink>, u64, u64)>,
}
impl Script {
    fn new(clock: Arc<FakeClock>, turns: Vec<AssistantTurn>) -> Self {
        Script {
            turns: Mutex::new(turns.into_iter().map(Ok).collect()),
            clock,
            per_call_ms: 100,
            usage: None,
        }
    }
}
impl LlmClient for Script {
    fn complete(&self, _req: &CompletionRequest) -> Result<AssistantTurn, LlmError> {
        self.clock.advance(self.per_call_ms);
        if let Some((m, i, o)) = &self.usage {
            m.record_usage(*i, *o);
        }
        let mut t = self.turns.lock().unwrap();
        if t.is_empty() {
            Ok(AssistantTurn::text("done"))
        } else {
            t.remove(0)
        }
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
            trust: Some(trust),
            ..Default::default()
        },
    }
}
fn call(id: &str, n: &str, args: &str) -> ToolCall {
    ToolCall {
        id: id.into(),
        name: n.into(),
        arguments: args.into(),
    }
}
fn cfg(max_steps: u32) -> LoopConfig {
    LoopConfig {
        model: "gemma-4-e4b".into(),
        system_prompt: "s".into(),
        max_steps,
        max_tool_calls_per_step: 4,
        max_tokens: 64,
    }
}
fn registry(outcome: ToolOutcome, names: &[(&str, Trust)]) -> ToolRegistry {
    ToolRegistry::new(names.iter().map(|(n, t)| spec(n, *t)).collect())
        .with_host(HostKind::Core, Arc::new(Host(outcome)))
}
fn sink(clock: Arc<FakeClock>, tools: &[&str]) -> Arc<MeteringSink> {
    Arc::new(MeteringSink::new(
        "sess-1",
        "gemma-4-e4b",
        tools.iter().map(|s| s.to_string()),
        clock,
    ))
}

const T0: u64 = 1_790_812_800_000; // 2026-10-01T00:00:00Z

// ---------------------------------------------------------------------------------------------
// Records from the event stream
// ---------------------------------------------------------------------------------------------

#[test]
fn a_record_is_derived_from_a_real_turn() {
    let clock = FakeClock::at(T0 + 5_000);
    let llm = Script::new(
        clock.clone(),
        vec![
            AssistantTurn::tools(vec![
                call("a", "balance_read", "{}"),
                call("b", "no_such_tool", "{}"),
            ]),
            AssistantTurn::tools(vec![call("c", "balance_read", "not json")]),
            AssistantTurn::text("you have 3 SALT"),
        ],
    );
    let tools = registry(
        ToolOutcome::Ok("{\"salt\":3}".into()),
        &[("balance_read", Trust::Trusted)],
    );
    let m = sink(clock.clone(), &["balance_read"]);
    let out = run_turn(
        &cfg(6),
        &llm,
        &tools,
        m.as_ref(),
        &StopFlag::default(),
        &mut vec![],
        "how much SALT do I have",
    );
    assert!(matches!(out, RunOutcome::Answered(_)));
    let recs = m.records();
    assert_eq!(recs.len(), 1);
    let r = &recs[0];
    assert_eq!(r.session_id, "sess-1");
    assert_eq!(r.turn, 1);
    assert_eq!(r.model, "gemma-4-e4b");
    assert_eq!(r.started_unix_ms, T0 + 5_000);
    assert_eq!(r.latency_ms, 300, "three model calls of 100 ms each");
    assert_eq!(r.steps, 3);
    assert_eq!(r.outcome, TurnOutcome::Answered);
    assert_eq!(
        r.tokens_in, None,
        "no usage reported means unknown, not zero"
    );
    assert_eq!(r.tokens_out, None);
    let bal = &r.tool_calls["balance_read"];
    assert_eq!((bal.calls, bal.ok, bal.error, bal.denied), (2, 1, 1, 0));
    let unk = &r.tool_calls[UNKNOWN_TOOL];
    assert_eq!((unk.calls, unk.error), (1, 1));
    assert_eq!(r.tool_call_total(), 3);
    assert!(r.verifiers.is_empty());
    assert_eq!(r.verification(), Verification::Unverified);
    assert!(!r.tainted);
}

#[test]
fn turns_are_numbered_and_timed_separately() {
    let clock = FakeClock::at(T0);
    let llm = Script::new(clock.clone(), vec![]);
    let tools = registry(ToolOutcome::Ok("x".into()), &[]);
    let m = sink(clock.clone(), &[]);
    let mut h = vec![];
    for _ in 0..3 {
        clock.advance(1_000); // idle time between turns is not latency
        run_turn(
            &cfg(2),
            &llm,
            &tools,
            m.as_ref(),
            &StopFlag::default(),
            &mut h,
            "hi",
        );
    }
    let recs = m.records();
    assert_eq!(
        recs.iter().map(|r| r.turn).collect::<Vec<_>>(),
        vec![1, 2, 3]
    );
    assert!(recs.iter().all(|r| r.latency_ms == 100));
    assert_eq!(recs[2].started_unix_ms, T0 + 3_000 + 200);
}

#[test]
fn reported_usage_is_summed_over_the_turns_model_calls() {
    let clock = FakeClock::at(T0);
    let m = sink(clock.clone(), &["balance_read"]);
    let mut llm = Script::new(
        clock.clone(),
        vec![
            AssistantTurn::tools(vec![call("a", "balance_read", "{}")]),
            AssistantTurn::text("ok"),
        ],
    );
    llm.usage = Some((m.clone(), 120, 30));
    let tools = registry(
        ToolOutcome::Ok("1".into()),
        &[("balance_read", Trust::Trusted)],
    );
    run_turn(
        &cfg(4),
        &llm,
        &tools,
        m.as_ref(),
        &StopFlag::default(),
        &mut vec![],
        "q",
    );
    let r = &m.records()[0];
    assert_eq!(r.tokens_in, Some(240));
    assert_eq!(r.tokens_out, Some(60));
}

#[test]
fn usage_outside_an_open_turn_is_refused_not_misattributed() {
    let clock = FakeClock::at(T0);
    let m = sink(clock, &[]);
    assert!(!m.record_usage(10, 10));
    assert!(m.records().is_empty());
}

#[test]
fn every_event_is_forwarded_unchanged_to_the_wrapped_sink() {
    let clock = FakeClock::at(T0);
    let inner = Arc::new(Capture::default());
    let m = MeteringSink::new("s", "m", ["balance_read".to_string()], clock.clone())
        .forwarding_to(inner.clone());
    let direct = Capture::default();
    let llm1 = Script::new(
        clock.clone(),
        vec![
            AssistantTurn::tools(vec![call("a", "balance_read", "{}")]),
            AssistantTurn::text("ok"),
        ],
    );
    let llm2 = Script::new(
        clock.clone(),
        vec![
            AssistantTurn::tools(vec![call("a", "balance_read", "{}")]),
            AssistantTurn::text("ok"),
        ],
    );
    let tools = registry(
        ToolOutcome::Ok("1".into()),
        &[("balance_read", Trust::Trusted)],
    );
    run_turn(
        &cfg(4),
        &llm1,
        &tools,
        &m,
        &StopFlag::default(),
        &mut vec![],
        "q",
    );
    run_turn(
        &cfg(4),
        &llm2,
        &tools,
        &direct,
        &StopFlag::default(),
        &mut vec![],
        "q",
    );
    assert_eq!(*inner.0.lock().unwrap(), *direct.0.lock().unwrap());
    assert_eq!(m.records().len(), 1);
}

#[test]
fn outcomes_map_from_the_loops_done_event() {
    let clock = FakeClock::at(T0);
    let tools = registry(ToolOutcome::Ok("1".into()), &[("t", Trust::Trusted)]);

    // stopped before the first model call
    let m = sink(clock.clone(), &["t"]);
    let stop = StopFlag::default();
    stop.stop();
    run_turn(
        &cfg(4),
        &Script::new(clock.clone(), vec![]),
        &tools,
        m.as_ref(),
        &stop,
        &mut vec![],
        "q",
    );
    let r = &m.records()[0];
    assert_eq!((r.outcome.clone(), r.steps), (TurnOutcome::Stopped, 0));

    // step limit
    let m = sink(clock.clone(), &["t"]);
    let llm = Script::new(
        clock.clone(),
        vec![
            AssistantTurn::tools(vec![call("a", "t", "{}")]),
            AssistantTurn::tools(vec![call("b", "t", "{}")]),
        ],
    );
    run_turn(
        &cfg(2),
        &llm,
        &tools,
        m.as_ref(),
        &StopFlag::default(),
        &mut vec![],
        "q",
    );
    assert_eq!(m.records()[0].outcome, TurnOutcome::StepLimit);

    // model failure
    let m = sink(clock.clone(), &["t"]);
    let llm = Script {
        turns: Mutex::new(vec![Err(LlmError::Transport("down".into()))]),
        clock: clock.clone(),
        per_call_ms: 7,
        usage: None,
    };
    run_turn(
        &cfg(2),
        &llm,
        &tools,
        m.as_ref(),
        &StopFlag::default(),
        &mut vec![],
        "q",
    );
    let r = &m.records()[0];
    assert_eq!((r.outcome.clone(), r.latency_ms), (TurnOutcome::Failed, 7));
}

#[test]
fn verifier_verdicts_attach_to_the_attempt_they_judge() {
    let clock = FakeClock::at(T0);
    let m = sink(clock.clone(), &["contract_deploy"]);
    let llm = Script::new(
        clock.clone(),
        vec![
            AssistantTurn::text("Deployed!"), // attempt 1: the model claims success, never deployed
            AssistantTurn::tools(vec![call("d", "contract_deploy", "{}")]),
            AssistantTurn::text("deployed for real"),
        ],
    );
    let tools = registry(
        ToolOutcome::Ok("{}".into()),
        &[("contract_deploy", Trust::Trusted)],
    );
    let wf = Workflow::new(
        "deploy",
        vec![Step {
            id: "deploy".into(),
            instruction: "deploy it".into(),
            verifiers: vec![Arc::new(ToolSucceeded("contract_deploy".into()))],
            max_attempts: 2,
        }],
    )
    .unwrap();
    let out = run_workflow(
        &cfg(4),
        &TurnOptions::default(),
        &llm,
        &tools,
        m.as_ref(),
        &StopFlag::default(),
        &mut vec![],
        &wf,
    );
    assert!(matches!(out, WorkflowOutcome::Succeeded { .. }));
    let recs = m.records();
    assert_eq!(recs.len(), 2);
    assert_eq!(recs[0].outcome, TurnOutcome::Answered);
    assert_eq!(
        recs[0].verification(),
        Verification::Failed,
        "an answered turn is not a success"
    );
    assert_eq!(recs[0].verifiers.len(), 1);
    assert_eq!(recs[0].verifiers[0].step, "deploy");
    assert!(!recs[0].verifiers[0].passed);
    assert_eq!(recs[1].verification(), Verification::Passed);
}

#[test]
fn a_self_review_opinion_opens_no_turn_and_never_marks_an_attempt_passed() {
    // US-1.3 AC2: the opinion arrives after the attempt's `done`, like a verdict. It must not
    // open a phantom turn, and a "PASS" opinion must not turn a failed attempt into a pass.
    let clock = FakeClock::at(T0);
    let m = sink(clock.clone(), &["contract_deploy"]);
    let llm = Script::new(
        clock.clone(),
        vec![
            AssistantTurn::text("Deployed!"),
            AssistantTurn::text("PASS: it is deployed."),
            AssistantTurn::tools(vec![call("d", "contract_deploy", "{}")]),
            AssistantTurn::text("deployed for real"),
            AssistantTurn::text("PASS: deployed."),
        ],
    );
    let tools = registry(
        ToolOutcome::Ok("{}".into()),
        &[("contract_deploy", Trust::Trusted)],
    );
    let wf = Workflow::new(
        "deploy",
        vec![Step {
            id: "deploy".into(),
            instruction: "deploy it".into(),
            verifiers: vec![Arc::new(ToolSucceeded("contract_deploy".into()))],
            max_attempts: 2,
        }],
    )
    .unwrap();
    let reviewer = LlmSelfReviewer::new(&llm, "m", 32);
    let out = run_workflow_reviewed(
        &cfg(4),
        &TurnOptions::default(),
        &llm,
        &tools,
        m.as_ref(),
        &StopFlag::default(),
        &mut vec![],
        &wf,
        Some(&reviewer),
    );
    assert!(matches!(out, WorkflowOutcome::Succeeded { .. }));
    let recs = m.records();
    assert_eq!(recs.len(), 2, "an opinion is not a turn");
    assert_eq!(recs[0].verification(), Verification::Failed);
    assert_eq!(recs[1].verification(), Verification::Passed);
}

#[test]
fn taint_and_explicit_approval_calls_are_counted() {
    let clock = FakeClock::at(T0);
    let m = sink(clock.clone(), &["web_fetch"]);
    let llm = Script::new(
        clock.clone(),
        vec![
            AssistantTurn::tools(vec![call("a", "web_fetch", "{}")]),
            AssistantTurn::tools(vec![call("b", "web_fetch", "{}")]),
            AssistantTurn::text("ok"),
        ],
    );
    let tools = registry(
        ToolOutcome::Ok("page".into()),
        &[("web_fetch", Trust::Untrusted)],
    );
    run_turn(
        &cfg(4),
        &llm,
        &tools,
        m.as_ref(),
        &StopFlag::default(),
        &mut vec![],
        "q",
    );
    let r = &m.records()[0];
    assert!(r.tainted);
    let t = &r.tool_calls["web_fetch"];
    assert_eq!(t.calls, 2);
    assert_eq!(t.hic_required, 1, "the second call came after taint");
    assert_eq!(
        t.denied, 1,
        "a host that cannot ask a person is never handed the call"
    );
}

#[test]
fn records_carry_no_conversation_content() {
    let clock = FakeClock::at(T0);
    let m = sink(clock.clone(), &["note_write"]);
    let llm = Script::new(
        clock.clone(),
        vec![
            AssistantTurn::tools(vec![
                call("a", "note_write", "{\"text\":\"ARG-CANARY\"}"),
                call("b", "HALLUCINATED-CANARY", "{}"),
            ]),
            AssistantTurn::text("ANSWER-CANARY"),
        ],
    );
    let tools = registry(
        ToolOutcome::Ok("RESULT-CANARY".into()),
        &[("note_write", Trust::Trusted)],
    );
    run_turn(
        &cfg(4),
        &llm,
        &tools,
        m.as_ref(),
        &StopFlag::default(),
        &mut vec![],
        "PROMPT-CANARY",
    );
    let llm = Script {
        turns: Mutex::new(vec![Err(LlmError::Provider("ERROR-CANARY".into()))]),
        clock: clock.clone(),
        per_call_ms: 1,
        usage: None,
    };
    run_turn(
        &cfg(4),
        &llm,
        &tools,
        m.as_ref(),
        &StopFlag::default(),
        &mut vec![],
        "q",
    );
    let json = serde_json::to_string(&m.records()).unwrap();
    for canary in [
        "ARG-CANARY",
        "HALLUCINATED-CANARY",
        "ANSWER-CANARY",
        "RESULT-CANARY",
        "PROMPT-CANARY",
        "ERROR-CANARY",
    ] {
        assert!(!json.contains(canary), "{canary} leaked into {json}");
    }
}

#[test]
fn take_records_drains() {
    let clock = FakeClock::at(T0);
    let m = sink(clock.clone(), &[]);
    let tools = registry(ToolOutcome::Ok("x".into()), &[]);
    run_turn(
        &cfg(2),
        &Script::new(clock, vec![]),
        &tools,
        m.as_ref(),
        &StopFlag::default(),
        &mut vec![],
        "q",
    );
    assert_eq!(m.take_records().len(), 1);
    assert!(m.records().is_empty());
}

// ---------------------------------------------------------------------------------------------
// The JSONL log
// ---------------------------------------------------------------------------------------------

fn rec(turn: u32, at: u64, latency: u64, outcome: TurnOutcome, verifiers: &[bool]) -> TurnRecord {
    let mut r = TurnRecord::new("sess", turn, "gemma-4-e4b", at);
    r.latency_ms = latency;
    r.steps = 2;
    r.outcome = outcome;
    r.verifiers = verifiers
        .iter()
        .map(|p| VerifierOutcome {
            step: "build".into(),
            name: "forge test".into(),
            passed: *p,
        })
        .collect();
    r
}

#[test]
fn the_log_round_trips_and_names_a_corrupt_line() {
    let dir = tempfile::tempdir().unwrap();
    let log = MeteringLog::new(dir.path().join("metering").join("turns.jsonl"));
    assert!(log.read_all().unwrap().is_empty(), "a missing log is empty");
    let a = rec(1, T0, 10, TurnOutcome::Answered, &[true]);
    let b = rec(2, T0 + 1, 20, TurnOutcome::Stopped, &[]);
    log.append(&a).unwrap();
    log.append(&b).unwrap();
    assert_eq!(log.read_all().unwrap(), vec![a, b]);

    std::fs::OpenOptions::new()
        .append(true)
        .open(log.path())
        .and_then(|mut f| std::io::Write::write_all(&mut f, b"{not json\n"))
        .unwrap();
    match log.read_all() {
        Err(MeteringError::Parse { line, .. }) => assert_eq!(line, 3),
        other => panic!("expected a parse error, got {other:?}"),
    }
}

// ---------------------------------------------------------------------------------------------
// The daily report
// ---------------------------------------------------------------------------------------------

fn sample_day() -> Vec<TurnRecord> {
    let mut v = vec![
        rec(1, T0 + 1_000, 100, TurnOutcome::Answered, &[true, true]),
        rec(2, T0 + 2_000, 200, TurnOutcome::Answered, &[true, false]),
        rec(3, T0 + 3_000, 300, TurnOutcome::Answered, &[]),
        rec(4, T0 + 4_000, 400, TurnOutcome::StepLimit, &[]),
        rec(5, T0 + 5_000, 1_000, TurnOutcome::Failed, &[false]),
        // the day before and the day after: excluded
        rec(6, T0 - 1, 9_999, TurnOutcome::Answered, &[true]),
        rec(7, T0 + 86_400_000, 9_999, TurnOutcome::Answered, &[true]),
    ];
    v[0].tokens_in = Some(1_000);
    v[0].tokens_out = Some(200);
    v[1].tokens_in = Some(500);
    v[1].tokens_out = Some(50);
    v[0].tool_calls.insert(
        "forge_test".into(),
        ToolTally {
            calls: 3,
            ok: 2,
            error: 1,
            ..Default::default()
        },
    );
    v[1].tool_calls.insert(
        "forge_test".into(),
        ToolTally {
            calls: 1,
            ok: 1,
            ..Default::default()
        },
    );
    v[2].session_id = "sess-2".into();
    v[2].tainted = true;
    v
}

#[test]
fn the_daily_report_aggregates_one_utc_day() {
    let r = DailyReport::build("2026-10-01", &sample_day()).unwrap();
    assert_eq!(r.day, "2026-10-01");
    assert_eq!(r.turns, 5);
    assert_eq!(r.sessions, 2);
    assert_eq!(r.outcomes.answered, 3);
    assert_eq!(r.outcomes.step_limit, 1);
    assert_eq!(r.outcomes.failed, 1);
    assert_eq!(r.verification.passed, 1);
    assert_eq!(r.verification.failed, 2);
    assert_eq!(r.verification.unverified, 2);
    assert_eq!(
        r.verified_success_bps,
        Some(3_333),
        "unverified turns are neither successes nor failures"
    );
    let l = r.latency_ms.clone().unwrap();
    assert_eq!((l.p50, l.p95, l.max), (300, 1_000, 1_000));
    assert_eq!(r.tokens.tokens_in, 1_500);
    assert_eq!(r.tokens.tokens_out, 250);
    assert_eq!(r.tokens.turns_reporting, 2);
    assert_eq!(r.tool_calls["forge_test"].calls, 4);
    assert_eq!(r.tool_calls["forge_test"].error, 1);
    assert_eq!(r.verifiers["build / forge test"].passed, 3);
    assert_eq!(r.verifiers["build / forge test"].failed, 2);
    assert_eq!(r.models["gemma-4-e4b"], 5);
    assert_eq!(r.tainted_turns, 1);
    assert_eq!(r.steps_total, 10);

    let json = r.to_json().unwrap();
    let back: DailyReport = serde_json::from_str(&json).unwrap();
    assert_eq!(back, r);
}

#[test]
fn the_markdown_report_is_honest_about_what_was_measured() {
    let md = DailyReport::build("2026-10-01", &sample_day())
        .unwrap()
        .to_markdown();
    assert!(md.starts_with("# Hermes daily report: 2026-10-01"));
    assert!(md.contains("| Turns | 5 |"));
    assert!(md.contains("33.33%"));
    assert!(md.contains("tokens reported for 2 of 5 turns"));
    assert!(md.contains("not a success"), "answered is not success");
    assert!(md.contains("`forge_test`"));
    assert!(
        !md.contains('\u{2014}'),
        "no em-dashes in member-facing text"
    );
}

#[test]
fn an_empty_day_reports_nothing_measured() {
    let r = DailyReport::build("2026-09-01", &sample_day()).unwrap();
    assert_eq!(r.turns, 0);
    assert_eq!(r.verified_success_bps, None);
    assert_eq!(r.latency_ms, None);
    let md = r.to_markdown();
    assert!(md.contains("No turns were recorded"));
}

#[test]
fn a_malformed_day_is_rejected() {
    for bad in [
        "2026-13-01",
        "2026-02-30",
        "26-10-01",
        "2026/10/01",
        "",
        "2026-10-1",
    ] {
        assert!(
            matches!(
                DailyReport::build(bad, &[]),
                Err(MeteringError::InvalidDay(_))
            ),
            "{bad}"
        );
    }
    assert!(DailyReport::build("2024-02-29", &[]).is_ok());
}

#[test]
fn utc_day_bounds_are_exact() {
    assert_eq!(
        utc_day_bounds_ms("2026-10-01").unwrap(),
        (T0, T0 + 86_400_000)
    );
    assert_eq!(utc_day_bounds_ms("1970-01-01").unwrap(), (0, 86_400_000));
    assert_eq!(utc_day_of_ms(T0 - 1), "2026-09-30");
    assert_eq!(utc_day_of_ms(T0), "2026-10-01");
}

// ---------------------------------------------------------------------------------------------
// BenchmarkRegistry payload (opt-in, aggregates only, build only)
// ---------------------------------------------------------------------------------------------

const REGISTRY: &str = "0x00000000000000000000000000000000000000b1";

#[test]
fn no_opt_in_means_no_payload() {
    let r = DailyReport::build("2026-10-01", &sample_day()).unwrap();
    assert!(matches!(
        build_benchmark_payload(&r, None),
        Err(MeteringError::NotOptedIn)
    ));
}

#[test]
fn the_selector_matches_the_deployed_abi() {
    // `cast sig "record(uint256,bytes32,bytes32,uint256)"` (foundry 1.5.1)
    assert_eq!(
        BENCHMARK_RECORD_SIGNATURE,
        "record(uint256,bytes32,bytes32,uint256)"
    );
    assert_eq!(hex::encode(record_selector()), "fce25138");
    // `cast keccak "citrate.hermes.agent-loop.v1"`
    assert_eq!(
        hex::encode(hermes_capsule_id()),
        "9bf1a6295bf6cad36e6ad3a5defce3c880372fa75b99e42b64ad8c530c2f8850"
    );
}

#[test]
fn calldata_matches_cast_for_a_known_vector() {
    // Five turns on 2026-10-01 for AgentSBT id 7. Expected from:
    // cast calldata "record(uint256,bytes32,bytes32,uint256)" 7 \
    //   $(cast keccak citrate.hermes.agent-loop.v1) $(cast keccak hermes.daily.turns) 5
    let expected = "0xfce25138\
        0000000000000000000000000000000000000000000000000000000000000007\
        9bf1a6295bf6cad36e6ad3a5defce3c880372fa75b99e42b64ad8c530c2f8850\
        4093d29569bc2cbd51dd1b64d6801e979f1bd9caa8c952ff42bbd80567ed2864\
        0000000000000000000000000000000000000000000000000000000000000005";
    let r = DailyReport::build("2026-10-01", &sample_day()).unwrap();
    let opt = BenchmarkOptIn::new(7, REGISTRY).unwrap();
    let p = build_benchmark_payload(&r, Some(&opt)).unwrap();
    assert_eq!(p.chain_id, 40_204);
    assert_eq!(p.to, REGISTRY);
    assert_eq!(p.value, "0");
    assert!(!p.sent, "the builder never sends");
    let turns = p
        .calls
        .iter()
        .find(|c| c.metric == "hermes.daily.turns")
        .unwrap();
    assert_eq!(turns.value, "5");
    assert_eq!(turns.data, expected);
    let pass = p
        .calls
        .iter()
        .find(|c| c.metric == "hermes.daily.verified_pass")
        .unwrap();
    assert_eq!(
        pass.metric_name,
        "0xa47f309bf4a1562538f67cd3b3bc3070ec93c5c835fa1445839e375ebaf158ca"
    );
    assert_eq!(pass.value, "1");
    let bps = p
        .calls
        .iter()
        .find(|c| c.metric == "hermes.daily.verified_success_bps")
        .unwrap();
    assert_eq!(bps.value, "3333");
    for c in &p.calls {
        assert_eq!(c.data.len(), 2 + 8 + 4 * 64, "{}", c.metric);
        assert!(c.data.starts_with("0xfce25138"));
    }
}

#[test]
fn the_payload_holds_aggregates_only() {
    let mut day = sample_day();
    day[0].model = "MODEL-CANARY".into();
    day[0].session_id = "SESSION-CANARY".into();
    day[0]
        .tool_calls
        .insert("TOOL-CANARY".into(), ToolTally::default());
    day[0].verifiers[0].name = "VERIFIER-CANARY".into();
    let r = DailyReport::build("2026-10-01", &day).unwrap();
    let p = build_benchmark_payload(&r, Some(&BenchmarkOptIn::new(7, REGISTRY).unwrap())).unwrap();
    let json = serde_json::to_string(&p).unwrap();
    for canary in [
        "MODEL-CANARY",
        "SESSION-CANARY",
        "TOOL-CANARY",
        "VERIFIER-CANARY",
    ] {
        assert!(!json.contains(canary), "{canary} in payload");
    }
    let names: Vec<&str> = p.calls.iter().map(|c| c.metric.as_str()).collect();
    assert!(names.iter().all(|n| METRICS.contains(n)), "{names:?}");
}

#[test]
fn undefined_metrics_are_omitted_not_zeroed() {
    let day = vec![rec(1, T0 + 1, 50, TurnOutcome::Answered, &[])];
    let r = DailyReport::build("2026-10-01", &day).unwrap();
    let p = build_benchmark_payload(&r, Some(&BenchmarkOptIn::new(7, REGISTRY).unwrap())).unwrap();
    let names: Vec<&str> = p.calls.iter().map(|c| c.metric.as_str()).collect();
    assert!(!names.contains(&"hermes.daily.verified_success_bps"));
    assert!(!names.contains(&"hermes.daily.tokens_in"));
    assert!(names.contains(&"hermes.daily.unverified"));
}

#[test]
fn an_empty_day_or_a_bad_address_builds_nothing() {
    let r = DailyReport::build("2026-09-01", &sample_day()).unwrap();
    let opt = BenchmarkOptIn::new(7, REGISTRY).unwrap();
    assert!(matches!(
        build_benchmark_payload(&r, Some(&opt)),
        Err(MeteringError::EmptyReport)
    ));
    for bad in [
        "",
        "0x",
        "00000000000000000000000000000000000000b1",
        "0x00000000000000000000000000000000000000b",
        "0x00000000000000000000000000000000000000zz",
        "0x0000000000000000000000000000000000000000",
    ] {
        assert!(
            matches!(
                BenchmarkOptIn::new(7, bad),
                Err(MeteringError::InvalidAddress(_))
            ),
            "{bad}"
        );
    }
}

// ---------------------------------------------------------------------------------------------
// HUP-S7.5 / US-7.3 AC1 (D-27): time to first token, tokens per second, resource peaks, the
// energy estimate, the self-review opinion, SALT and gas, and the schema bump.
// ---------------------------------------------------------------------------------------------

fn timed(prompt: u64, completion: u64, gen_ms: Option<u64>, prompt_ms: Option<u64>) -> TokenUsage {
    TokenUsage {
        prompt_tokens: prompt,
        completion_tokens: completion,
        generation_ms: gen_ms,
        prompt_ms,
    }
}

/// A model that reports llama-server-style timings for each call through the metered sink.
struct TimedScript {
    inner: Script,
    sink: Arc<MeteringSink>,
    usages: Mutex<Vec<TokenUsage>>,
}
impl LlmClient for TimedScript {
    fn complete(&self, req: &CompletionRequest) -> Result<AssistantTurn, LlmError> {
        let out = self.inner.complete(req);
        let mut u = self.usages.lock().unwrap();
        if !u.is_empty() {
            self.sink.record_model_call(&u.remove(0));
        }
        out
    }
}

fn two_step_turn(m: &Arc<MeteringSink>, clock: Arc<FakeClock>, usages: Vec<TokenUsage>) {
    let llm = TimedScript {
        inner: Script::new(
            clock,
            vec![
                AssistantTurn::tools(vec![call("a", "balance_read", "{}")]),
                AssistantTurn::text("ok"),
            ],
        ),
        sink: m.clone(),
        usages: Mutex::new(usages),
    };
    let tools = registry(
        ToolOutcome::Ok("{}".into()),
        &[("balance_read", Trust::Trusted)],
    );
    run_turn(
        &cfg(4),
        &llm,
        &tools,
        m.as_ref(),
        &StopFlag::default(),
        &mut vec![],
        "hi",
    );
}

#[test]
fn ttft_is_the_first_model_calls_prompt_time_from_the_server() {
    let clock = FakeClock::at(T0);
    let m = sink(clock.clone(), &["balance_read"]);
    two_step_turn(
        &m,
        clock,
        vec![
            timed(300, 12, Some(400), Some(180)),
            timed(340, 20, Some(600), Some(35)),
        ],
    );
    let recs = m.records();
    assert_eq!(recs.len(), 1);
    assert_eq!(
        recs[0].ttft_ms,
        Some(180),
        "the turn's first token waits on its first call"
    );
    assert_eq!(recs[0].tokens_in, Some(640));
}

#[test]
fn ttft_is_unknown_when_the_first_call_did_not_report_it() {
    let clock = FakeClock::at(T0);
    let m = sink(clock.clone(), &["balance_read"]);
    two_step_turn(
        &m,
        clock,
        vec![
            timed(300, 12, Some(400), None),
            timed(340, 20, Some(600), Some(35)),
        ],
    );
    assert_eq!(
        m.records()[0].ttft_ms,
        None,
        "a later call's time is not substituted"
    );
}

#[test]
fn tokens_per_second_uses_only_calls_with_a_server_generation_time() {
    let clock = FakeClock::at(T0);
    let m = sink(clock.clone(), &["balance_read"]);
    two_step_turn(
        &m,
        clock,
        vec![
            timed(300, 30, Some(1_000), None),
            timed(340, 99, None, None),
        ],
    );
    let r = &m.records()[0];
    assert_eq!(
        r.generation,
        Some(Generation {
            tokens: 30,
            ms: 1_000
        })
    );
    assert_eq!(r.generation.unwrap().tokens_per_s_milli(), Some(30_000));
    assert_eq!(
        r.tokens_out,
        Some(129),
        "token totals still count every reporting call"
    );
    assert_eq!(tokens_per_s_milli(7, 0), None);
    assert_eq!(tokens_per_s_milli(7, 234), Some(29_914));
}

#[test]
fn no_timings_leave_ttft_and_speed_unknown() {
    let clock = FakeClock::at(T0);
    let m = sink(clock.clone(), &["balance_read"]);
    two_step_turn(
        &m,
        clock,
        vec![timed(1, 1, None, None), timed(1, 1, None, None)],
    );
    let r = &m.records()[0];
    assert_eq!((r.ttft_ms, r.generation), (None, None));
}

/// A test sampler: hands out fixed readings and records that sampling began and finished.
struct FixedSampler {
    samples: Vec<ResourceSample>,
    begun: AtomicU64,
    finished: Arc<AtomicU64>,
}
struct FixedSampling(Vec<ResourceSample>, Arc<AtomicU64>);
impl TurnSampling for FixedSampling {
    fn finish(self: Box<Self>) -> Option<ResourcePeaks> {
        self.1.fetch_add(1, Ordering::SeqCst);
        ResourcePeaks::from_samples(&self.0)
    }
}
impl ResourceSampler for FixedSampler {
    fn begin(&self) -> Box<dyn TurnSampling> {
        self.begun.fetch_add(1, Ordering::SeqCst);
        Box::new(FixedSampling(self.samples.clone(), self.finished.clone()))
    }
}

fn sample(cpu: u32, ram_mib: u64, gpu: Option<u32>) -> ResourceSample {
    ResourceSample {
        cpu_bps: cpu,
        ram_used_bytes: ram_mib * 1024 * 1024,
        ram_total_bytes: 16 * 1024 * 1024 * 1024,
        gpu_bps: gpu,
    }
}

#[test]
fn resource_peaks_are_sampled_for_each_turn() {
    let clock = FakeClock::at(T0);
    let sampler = Arc::new(FixedSampler {
        samples: vec![
            sample(2_000, 6_000, Some(9_000)),
            sample(6_000, 7_000, Some(5_000)),
        ],
        begun: AtomicU64::new(0),
        finished: Arc::new(AtomicU64::new(0)),
    });
    let m = Arc::new(
        MeteringSink::new(
            "s",
            "gemma-4-e4b",
            ["balance_read".to_string()],
            clock.clone(),
        )
        .sampling_with(sampler.clone()),
    );
    two_step_turn(&m, clock.clone(), vec![]);
    two_step_turn(&m, clock, vec![]);
    assert_eq!(
        sampler.begun.load(Ordering::SeqCst),
        2,
        "one sampling per turn"
    );
    assert_eq!(sampler.finished.load(Ordering::SeqCst), 2);
    let r = m.records()[0].resources.unwrap();
    assert_eq!(r.samples, 2);
    assert_eq!((r.cpu_peak_bps, r.cpu_mean_bps), (6_000, 4_000));
    assert_eq!(r.ram_used_peak_bytes, 7_000 * 1024 * 1024);
    assert_eq!((r.gpu_peak_bps, r.gpu_mean_bps), (Some(9_000), Some(7_000)));
}

#[test]
fn peaks_clamp_bad_readings_and_keep_an_unread_gpu_unknown() {
    assert_eq!(ResourcePeaks::from_samples(&[]), None);
    let p = ResourcePeaks::from_samples(&[sample(25_000, 1, None), sample(0, 2, None)]).unwrap();
    assert_eq!(p.cpu_peak_bps, BPS_WHOLE);
    assert_eq!(p.cpu_mean_bps, 5_000);
    assert_eq!(
        (p.gpu_peak_bps, p.gpu_mean_bps),
        (None, None),
        "unknown, never zero"
    );
}

#[test]
fn the_energy_estimate_is_labelled_and_computed_from_mean_load() {
    let peaks = ResourcePeaks::from_samples(&[sample(5_000, 1, Some(10_000))]).unwrap();
    let e = EnergyModel {
        cpu_watts: 30,
        gpu_watts: 20,
    }
    .estimate(&peaks, 3_600_000);
    // 50% x 30 W + 100% x 20 W = 35 W for one hour = 35 Wh.
    assert_eq!(e.microwatt_hours, 35_000_000);
    assert_eq!(e.label, ENERGY_ESTIMATE_LABEL);
    assert_eq!(e.label, "estimate");
    assert!(e.gpu_included);
    assert!(e.method.starts_with("estimate:"), "{}", e.method);
    let cpu_only = ResourcePeaks::from_samples(&[sample(5_000, 1, None)]).unwrap();
    let e = DEFAULT_ENERGY_MODEL.estimate(&cpu_only, 3_600_000);
    assert!(!e.gpu_included);
    assert_eq!(
        e.microwatt_hours, 15_000_000,
        "only the CPU's share is counted"
    );
}

#[test]
fn a_turn_without_a_sampler_has_no_peaks_and_no_energy_estimate() {
    let clock = FakeClock::at(T0);
    let m = sink(clock.clone(), &["balance_read"]);
    two_step_turn(&m, clock, vec![]);
    let r = &m.records()[0];
    assert_eq!((r.resources, r.energy_estimate.clone()), (None, None));
}

#[test]
fn a_sampled_turn_carries_an_energy_estimate() {
    let clock = FakeClock::at(T0);
    let sampler = Arc::new(FixedSampler {
        samples: vec![sample(10_000, 1, None)],
        begun: AtomicU64::new(0),
        finished: Arc::new(AtomicU64::new(0)),
    });
    let m = Arc::new(
        MeteringSink::new("s", "m", ["balance_read".to_string()], clock.clone())
            .sampling_with(sampler)
            .with_energy_model(EnergyModel {
                cpu_watts: 36,
                gpu_watts: 0,
            }),
    );
    two_step_turn(&m, clock, vec![]);
    let r = &m.records()[0];
    // Two model calls at 100 ms each: 36 W for 200 ms = 2 mWh.
    assert_eq!(r.latency_ms, 200);
    assert_eq!(r.energy_estimate.as_ref().unwrap().microwatt_hours, 2_000);
}

#[test]
fn the_self_review_claim_is_kept_as_a_labelled_opinion_without_its_text() {
    let clock = FakeClock::at(T0);
    let m = sink(clock.clone(), &["contract_deploy"]);
    let llm = Script::new(
        clock.clone(),
        vec![
            AssistantTurn::text("Deployed!"),
            AssistantTurn::text("PASS: OPINION-CANARY it is deployed."),
            AssistantTurn::tools(vec![call("d", "contract_deploy", "{}")]),
            AssistantTurn::text("deployed for real"),
            AssistantTurn::text("fail, OPINION-CANARY unsure"),
        ],
    );
    let tools = registry(
        ToolOutcome::Ok("{}".into()),
        &[("contract_deploy", Trust::Trusted)],
    );
    let wf = Workflow::new(
        "deploy",
        vec![Step {
            id: "deploy".into(),
            instruction: "deploy it".into(),
            verifiers: vec![Arc::new(ToolSucceeded("contract_deploy".into()))],
            max_attempts: 2,
        }],
    )
    .unwrap();
    let reviewer = LlmSelfReviewer::new(&llm, "m", 32);
    run_workflow_reviewed(
        &cfg(4),
        &TurnOptions::default(),
        &llm,
        &tools,
        m.as_ref(),
        &StopFlag::default(),
        &mut vec![],
        &wf,
        Some(&reviewer),
    );
    let recs = m.records();
    assert_eq!(recs.len(), 2);
    let first = recs[0].self_review.clone().unwrap();
    assert_eq!(first.label, "opinion");
    assert_eq!(first.claim, SelfReviewClaim::Pass);
    assert_eq!(
        recs[0].verification(),
        Verification::Failed,
        "the opinion decides nothing"
    );
    assert_eq!(
        recs[1].self_review.as_ref().unwrap().claim,
        SelfReviewClaim::Fail
    );
    let json = serde_json::to_string(&recs).unwrap();
    assert!(
        !json.contains("OPINION-CANARY"),
        "no opinion text in records"
    );

    let r = DailyReport::build("2026-10-01", &recs).unwrap();
    assert_eq!(r.self_review.label, "opinion");
    assert_eq!((r.self_review.pass, r.self_review.fail), (1, 1));
    assert_eq!(r.self_review.disagreed_with_verifiers, 2);
    assert_eq!(
        SelfReviewClaim::parse("  no opinion: timeout"),
        SelfReviewClaim::Unclear
    );
    assert_eq!(SelfReviewClaim::parse("Passable"), SelfReviewClaim::Unclear);
    assert_eq!(SelfReviewClaim::parse("PASS."), SelfReviewClaim::Pass);
    assert_eq!(
        SelfReviewClaim::parse("**PASS** it is."),
        SelfReviewClaim::Pass
    );
    assert_eq!(SelfReviewClaim::parse("- Fail: no."), SelfReviewClaim::Fail);
    assert_eq!(SelfReviewClaim::parse("\"FAIL\""), SelfReviewClaim::Fail);
    assert_eq!(SelfReviewClaim::parse("2 PASS"), SelfReviewClaim::Unclear);
    assert_eq!(SelfReviewClaim::parse(""), SelfReviewClaim::Unclear);
}

#[test]
fn version_1_records_still_read_and_new_records_are_version_2() {
    let v1 = r#"{"schema":1,"session_id":"s","turn":1,"model":"m","started_unix_ms":1790812800001,"latency_ms":5,"tokens_in":null,"tokens_out":null,"steps":1,"tool_calls":{},"tainted":false,"verifiers":[],"outcome":"answered"}"#;
    let r: TurnRecord = serde_json::from_str(v1).unwrap();
    assert_eq!(r.schema, 1);
    assert_eq!(
        (
            r.ttft_ms,
            r.generation,
            r.resources,
            r.energy_estimate,
            r.self_review
        ),
        (None, None, None, None, None)
    );
    assert_eq!(RECORD_SCHEMA, 2);
    assert_eq!(TurnRecord::new("s", 1, "m", T0).schema, 2);
    // An unknown measure is left out of the line, so a version 1 reader is not handed new nulls.
    let line = serde_json::to_string(&TurnRecord::new("s", 1, "m", T0)).unwrap();
    assert!(
        !line.contains("ttft_ms") && !line.contains("energy_estimate"),
        "{line}"
    );
    // A log mixing both versions reads, and the report counts both.
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("metering.jsonl");
    let mut v2 = TurnRecord::new("s", 2, "m", T0 + 2);
    v2.ttft_ms = Some(90);
    std::fs::write(
        &path,
        format!("{v1}\n{}\n", serde_json::to_string(&v2).unwrap()),
    )
    .unwrap();
    let all = MeteringLog::new(&path).read_all().unwrap();
    let rep = DailyReport::build("2026-10-01", &all).unwrap();
    assert_eq!(rep.turns, 2);
    assert_eq!(rep.schema, REPORT_SCHEMA);
    assert_eq!(rep.ttft_ms.as_ref().map(|t| t.p50), Some(90));
    // A version 1 report (no D-27 fields) still reads.
    let mut old = serde_json::to_value(&rep).unwrap();
    for k in [
        "ttft_ms",
        "speed",
        "resources",
        "energy_estimate",
        "self_review",
    ] {
        old.as_object_mut().unwrap().remove(k);
    }
    let back: DailyReport = serde_json::from_value(old).unwrap();
    assert_eq!(back.ttft_ms, None);
    assert_eq!(back.self_review.label, "opinion");
}

fn d27_day() -> Vec<TurnRecord> {
    let mut v = sample_day();
    v[0].ttft_ms = Some(100);
    v[1].ttft_ms = Some(300);
    v[2].ttft_ms = Some(200);
    v[0].generation = Some(Generation {
        tokens: 60,
        ms: 2_000,
    });
    v[1].generation = Some(Generation {
        tokens: 30,
        ms: 1_000,
    });
    let p1 = ResourcePeaks::from_samples(&[sample(7_000, 9_000, Some(8_000))]).unwrap();
    let p2 = ResourcePeaks::from_samples(&[sample(9_000, 8_000, None)]).unwrap();
    v[0].resources = Some(p1);
    v[1].resources = Some(p2);
    v[0].energy_estimate = Some(DEFAULT_ENERGY_MODEL.estimate(&p1, 100));
    v[1].energy_estimate = Some(DEFAULT_ENERGY_MODEL.estimate(&p2, 200));
    v[0].self_review = Some(SelfReview::from_text("PASS"));
    v
}

#[test]
fn the_daily_report_carries_the_d27_measures() {
    let r = DailyReport::build("2026-10-01", &d27_day()).unwrap();
    let t = r.ttft_ms.as_ref().unwrap();
    assert_eq!((t.p50, t.p95, t.max), (200, 300, 300));
    let sp = r.speed.as_ref().unwrap();
    assert_eq!(
        (sp.tokens, sp.generation_ms, sp.turns_reporting),
        (90, 3_000, 2)
    );
    assert_eq!(sp.tokens_per_s_milli, 30_000);
    let rs = r.resources.as_ref().unwrap();
    assert_eq!(rs.turns_sampled, 2);
    assert_eq!(rs.cpu_peak_bps, 9_000);
    assert_eq!(rs.gpu_peak_bps, Some(8_000));
    assert_eq!(rs.ram_used_peak_bytes, 9_000 * 1024 * 1024);
    let e = r.energy_estimate.as_ref().unwrap();
    assert_eq!(e.label, "estimate");
    assert_eq!(e.turns_estimated, 2);
    assert_eq!(e.turns_without_gpu, 1);
    // (0.7 x 30 + 0.8 x 30) W x 100 ms + 0.9 x 30 W x 200 ms = 4500 + 5400 mW-ms... in uWh:
    assert_eq!(
        e.microwatt_hours,
        45_000 * 100 / 3_600 + 27_000 * 200 / 3_600
    );
    assert_eq!(r.self_review.pass, 1);
    assert_eq!(r.self_review.agreed_with_verifiers, 1);
    let md = r.to_markdown();
    for needle in [
        "Time to first token p50 / p95 | 200 ms / 300 ms",
        "Tokens per second | 30.0",
        "Peak CPU / GPU / RAM (whole machine) | 90.00% / 80.00% / 9000 MiB",
        "Energy (estimate, not measured)",
        "Self-review (opinion, not a verdict)",
    ] {
        assert!(md.contains(needle), "missing {needle:?} in\n{md}");
    }
    let unknown = DailyReport::build("2026-10-01", &sample_day())
        .unwrap()
        .to_markdown();
    assert!(
        unknown.contains("| Time to first token | unknown"),
        "{unknown}"
    );
    assert!(
        unknown.contains("| Energy (estimate) | unknown"),
        "{unknown}"
    );
}

const TX_A: &str = "0x00000000000000000000000000000000000000000000000000000000000000aa";
const TX_B: &str = "0x00000000000000000000000000000000000000000000000000000000000000bb";
const TX_C: &str = "0x00000000000000000000000000000000000000000000000000000000000000cc";

fn receipt(
    hash: &str,
    purpose: ChainPurpose,
    at: u64,
    status: u8,
    gas: u64,
    value: &str,
) -> ChainReceipt {
    ChainReceipt {
        schema: CHAIN_RECEIPT_SCHEMA,
        tx_hash: hash.into(),
        purpose,
        mined_unix_ms: at,
        status,
        gas_used: gas,
        effective_gas_price_wei: "1000000000".into(),
        value_wei: value.into(),
    }
}

#[test]
fn salt_spent_and_gas_come_from_the_ceremony_receipts() {
    let rs = vec![
        // A registry escalation: 0.5 SALT sent plus 100k gas at 1 gwei.
        receipt(
            TX_A,
            ChainPurpose::RegistryEscalation,
            T0 + 1,
            1,
            100_000,
            "500000000000000000",
        ),
        // Reported twice: counted once.
        receipt(
            TX_A,
            ChainPurpose::RegistryEscalation,
            T0 + 2,
            1,
            100_000,
            "500000000000000000",
        ),
        // Reverted: pays gas, moves no value.
        receipt(TX_B, ChainPurpose::Benchmark, T0 + 3, 0, 50_000, "7"),
        // Another day.
        receipt(TX_C, ChainPurpose::Anchor, T0 + 86_400_000, 1, 1, "0"),
    ];
    let s = ChainSpendSummary::build("2026-10-01", &rs).unwrap();
    assert_eq!(s.transactions, 2);
    assert_eq!(s.reverted, 1);
    assert_eq!(s.gas_used, 150_000);
    assert_eq!(s.fee_wei, "150000000000000");
    assert_eq!(s.value_wei, "500000000000000000");
    assert_eq!(s.salt_spent_wei, "500150000000000000");
    assert_eq!(s.salt_spent(), 500_150_000_000_000_000);
    assert_eq!(s.by_purpose.get("registry_escalation"), Some(&1));
    assert!(
        s.to_markdown().contains("SALT spent: 0.50015 SALT"),
        "{}",
        s.to_markdown()
    );
    assert_eq!(format_salt(2_000_000_000_000_000_000), "2 SALT");
    let empty = ChainSpendSummary::build("2026-09-01", &rs).unwrap();
    assert_eq!(
        (empty.transactions, empty.salt_spent_wei.as_str()),
        (0, "0")
    );
}

#[test]
fn a_malformed_chain_receipt_is_refused_by_the_log() {
    let dir = tempfile::tempdir().unwrap();
    let log = ChainReceiptLog::new(dir.path().join("chain.jsonl"));
    let good = receipt(TX_A, ChainPurpose::Agent, T0, 1, 21_000, "0");
    log.append(&good).unwrap();
    let mut bad = vec![];
    for (h, st, price, val) in [
        ("0xaa", 1, "1", "0"),
        (TX_B, 2, "1", "0"),
        (TX_B, 1, "-1", "0"),
        (TX_B, 1, "1", "1e18"),
        (TX_B, 1, "1", "0x10"),
        (TX_B, 1, "1", ""),
    ] {
        let mut r = receipt(h, ChainPurpose::Agent, T0, st, 1, val);
        r.effective_gas_price_wei = price.into();
        bad.push(r);
    }
    for r in &bad {
        assert!(
            matches!(log.append(r), Err(MeteringError::InvalidReceipt(_))),
            "{r:?}"
        );
    }
    assert_eq!(log.read_all().unwrap(), vec![good]);
}

#[test]
fn the_benchmark_payload_picks_up_the_d27_metrics() {
    let r = DailyReport::build("2026-10-01", &d27_day()).unwrap();
    let chain = ChainSpendSummary::build(
        "2026-10-01",
        &[receipt(
            TX_A,
            ChainPurpose::RegistryEscalation,
            T0 + 1,
            1,
            100_000,
            "5",
        )],
    )
    .unwrap();
    let opt = BenchmarkOptIn::new(7, REGISTRY).unwrap();
    let p = build_benchmark_payload_with(&r, Some(&chain), Some(&opt)).unwrap();
    let get = |m: &str| {
        p.calls
            .iter()
            .find(|c| c.metric == m)
            .map(|c| c.value.clone())
    };
    assert_eq!(get("hermes.daily.ttft_p50_ms").as_deref(), Some("200"));
    assert_eq!(get("hermes.daily.ttft_p95_ms").as_deref(), Some("300"));
    assert_eq!(
        get("hermes.daily.tokens_per_s_milli").as_deref(),
        Some("30000")
    );
    assert_eq!(get("hermes.daily.cpu_peak_bps").as_deref(), Some("9000"));
    assert_eq!(get("hermes.daily.gpu_peak_bps").as_deref(), Some("8000"));
    assert_eq!(get("hermes.daily.ram_peak_mib").as_deref(), Some("9000"));
    assert!(get("hermes.daily.energy_estimate_uwh").is_some());
    assert_eq!(
        get("hermes.daily.self_review_opinion_pass").as_deref(),
        Some("1")
    );
    assert_eq!(get("hermes.daily.gas_used").as_deref(), Some("100000"));
    assert_eq!(
        get("hermes.daily.salt_spent_wei").as_deref(),
        Some("100000000000005")
    );
    assert!(p.calls.len() <= 32, "core accepts at most 32 calls a day");
    for c in &p.calls {
        assert!(METRICS.contains(&c.metric.as_str()), "{}", c.metric);
        assert!(c.metric.len() <= 64);
        assert_eq!(c.data.len(), 2 + 8 + 4 * 64, "{}", c.metric);
    }
    // The plain builder (no chain summary) still works and leaves gas and SALT out.
    let plain = build_benchmark_payload(&r, Some(&opt)).unwrap();
    assert!(plain
        .calls
        .iter()
        .all(|c| c.metric != "hermes.daily.gas_used"));
}

#[test]
fn a_day_without_the_d27_measures_omits_their_metrics() {
    let r = DailyReport::build("2026-10-01", &sample_day()).unwrap();
    let opt = BenchmarkOptIn::new(7, REGISTRY).unwrap();
    let empty_chain = ChainSpendSummary::build("2026-10-01", &[]).unwrap();
    let p = build_benchmark_payload_with(&r, Some(&empty_chain), Some(&opt)).unwrap();
    for m in &METRICS[15..] {
        assert!(
            p.calls.iter().all(|c| c.metric != *m),
            "{m} sent without a measurement"
        );
    }
}
