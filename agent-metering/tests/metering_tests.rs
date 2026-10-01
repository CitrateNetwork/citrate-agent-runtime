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
