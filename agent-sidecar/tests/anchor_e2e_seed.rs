//! HUP-S7.3 + S7.5: the seed step of citrate-core's anvil anchor rehearsal
//! (`scripts/anvil-anchor-e2e.sh` in citrate-core).
//!
//! Writes real decision records (through `citrate-agent-records`' own writer) and real metering
//! turn records (through `citrate-agent-metering`'s log) into a Hermes data folder laid out the
//! way citrate-core hands it to the sidecar (`records/`, `metering/`, `anchor/`). The rehearsal
//! then starts the real sidecar binary over that folder, so every hash, batch and proof in it
//! comes from the production code paths, not from a fixture.
//!
//! Opt-in: it only runs with `--ignored` and `CITRATE_ANCHOR_E2E_HERMES_DIR` set to an absolute,
//! empty or missing folder. It never touches the member's real Hermes folder by default.

use std::path::PathBuf;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::Arc;

use citrate_agent_metering::{MeteringLog, ToolTally, TurnOutcome, TurnRecord, VerifierOutcome};
use citrate_agent_records::{
    Actor, Clock, Decision, DecisionEvent, DecisionLog, EvidenceRef, HicTier, LogConfig, Outcome,
    OutcomeEvent,
};

const DAY_MS: u64 = 86_400_000;
const SEED_DIR_ENV: &str = "CITRATE_ANCHOR_E2E_HERMES_DIR";

struct StepClock(AtomicU64);
impl Clock for StepClock {
    fn now_ms(&self) -> u64 {
        self.0.fetch_add(1_000, Ordering::SeqCst)
    }
}

fn now_ms() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_millis() as u64)
        .unwrap_or(0)
}

#[test]
#[ignore = "seed step of citrate-core scripts/anvil-anchor-e2e.sh; needs CITRATE_ANCHOR_E2E_HERMES_DIR"]
fn seed_a_closed_day_of_decisions_and_metering() {
    let base = PathBuf::from(
        std::env::var(SEED_DIR_ENV)
            .unwrap_or_else(|_| panic!("set {SEED_DIR_ENV} to an absolute, empty folder")),
    );
    assert!(base.is_absolute(), "{SEED_DIR_ENV} must be absolute");
    if base.exists() {
        let empty = std::fs::read_dir(&base)
            .map(|mut d| d.next().is_none())
            .unwrap_or(false);
        assert!(empty, "{} must be empty or missing", base.display());
    }
    let records = base.join("records");
    let metering = base.join("metering");
    std::fs::create_dir_all(base.join("anchor")).expect("anchor dir");

    let today = now_ms() / DAY_MS;
    let yesterday = today - 1;
    // Yesterday, 12:00 UTC: the decisions of a closed day.
    let clock = Arc::new(StepClock(AtomicU64::new(
        yesterday * DAY_MS + 12 * 3_600_000,
    )));
    let (log, _) =
        DecisionLog::open_with_clock(&records, LogConfig::default(), clock.clone()).expect("log");
    let tx = log
        .record_decision(
            Actor::member("member"),
            DecisionEvent {
                tier: HicTier::Hic1,
                kind: "tx".into(),
                subject: "send 1 SALT to 0x00000000000000000000000000000000000000b2".into(),
                decision: Decision::Approved,
                reason: "approved on the card".into(),
                evidence: vec![EvidenceRef {
                    kind: "ceremony".into(),
                    uri: "ceremony:1".into(),
                    digest: None,
                }],
            },
        )
        .expect("decision");
    log.record_outcome(
        Actor::agent("hermes"),
        OutcomeEvent {
            decision_seq: tx.seq,
            outcome: Outcome::Completed,
            detail: "mined".into(),
        },
    )
    .expect("outcome");
    let siwe = log
        .record_decision(
            Actor::agent("hermes"),
            DecisionEvent {
                tier: HicTier::Hic2,
                kind: "siwe".into(),
                subject: "https://app.example sign-in".into(),
                decision: Decision::AutoWithinBudget,
                reason: "inside the member's sign-in budget".into(),
                evidence: vec![],
            },
        )
        .expect("decision");
    log.record_outcome(
        Actor::agent("hermes"),
        OutcomeEvent {
            decision_seq: siwe.seq,
            outcome: Outcome::Completed,
            detail: "signed".into(),
        },
    )
    .expect("outcome");
    log.record_decision(
        Actor::member("member"),
        DecisionEvent {
            tier: HicTier::Hic1,
            kind: "deploy".into(),
            subject: "deploy HelloMint".into(),
            decision: Decision::Denied,
            reason: "rejected on the card".into(),
            evidence: vec![],
        },
    )
    .expect("decision");
    // Today (still open, so never batched): one more decision.
    clock.0.store(now_ms(), Ordering::SeqCst);
    let open = log
        .record_decision(
            Actor::member("member"),
            DecisionEvent {
                tier: HicTier::Hic1,
                kind: "tx".into(),
                subject: "today".into(),
                decision: Decision::Denied,
                reason: "rejected on the card".into(),
                evidence: vec![],
            },
        )
        .expect("decision");
    let verify = log.verify().expect("verify");
    drop(log);

    // Yesterday's metering: two verified turns and one unverified, with provider token counts.
    let mlog = MeteringLog::new(metering.join("metering.jsonl"));
    std::fs::create_dir_all(&metering).expect("metering dir");
    for (i, (passed, verifiers)) in [(true, 1usize), (false, 1), (true, 0)].iter().enumerate() {
        let start = yesterday * DAY_MS + 13 * 3_600_000 + (i as u64) * 60_000;
        let mut r = TurnRecord::new("seed-session", i as u32 + 1, "gemma-4-e4b", start);
        r.latency_ms = 1_200 + 300 * i as u64;
        r.tokens_in = Some(400 + 10 * i as u64);
        r.tokens_out = Some(120 + i as u64);
        r.steps = 2;
        r.tool_calls.insert(
            "read_file".into(),
            ToolTally {
                calls: 1,
                ok: 1,
                ..ToolTally::default()
            },
        );
        r.verifiers = (0..*verifiers)
            .map(|_| VerifierOutcome {
                step: "s1".into(),
                name: "hash".into(),
                passed: *passed,
            })
            .collect();
        r.outcome = TurnOutcome::Answered;
        mlog.append(&r).expect("metering append");
    }

    println!(
        "E2E_SEED {}",
        serde_json::json!({
            "day": yesterday,
            "today": today,
            "closedDaySeqs": [0, 1, 2, 3, 4],
            "openDaySeq": open.seq,
            "verifiedRecords": verify.count,
            "meteringTurns": 3,
        })
    );
}
