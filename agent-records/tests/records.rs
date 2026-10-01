//! HUP-S2.6 decision records: behaviour tests (chain, tamper detection, rotation, concurrency,
//! crash recovery, read API, daily Merkle root).

use std::fs;
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::Arc;

use citrate_agent_records::{
    merkle, read, verify_dir, Actor, ActorKind, Clock, Decision, DecisionEvent, DecisionLog, Entry,
    Error, EvidenceRef, HicTier, IntegrityError, LogConfig, Outcome, OutcomeEvent, GENESIS_PREV,
};

const DAY: u64 = 86_400_000;

struct TestClock(AtomicU64);
impl Clock for TestClock {
    fn now_ms(&self) -> u64 {
        self.0.load(Ordering::SeqCst)
    }
}
fn clock(at: u64) -> Arc<TestClock> {
    Arc::new(TestClock(AtomicU64::new(at)))
}

fn open(dir: &Path) -> DecisionLog {
    DecisionLog::open(dir, LogConfig::default()).unwrap().0
}
fn open_cfg(dir: &Path, cfg: LogConfig, c: Arc<TestClock>) -> DecisionLog {
    DecisionLog::open_with_clock(dir, cfg, c).unwrap().0
}

fn ev(tier: HicTier, decision: Decision, subject: &str) -> DecisionEvent {
    DecisionEvent {
        tier,
        kind: "tx".into(),
        subject: subject.into(),
        decision,
        reason: "test".into(),
        evidence: vec![EvidenceRef {
            kind: "approval_card".into(),
            uri: "card:1".into(),
            digest: None,
        }],
    }
}
fn approve(log: &DecisionLog, subject: &str) -> u64 {
    log.record_decision(
        Actor::member("m1"),
        ev(HicTier::Hic1, Decision::Approved, subject),
    )
    .unwrap()
    .seq
}
fn done(log: &DecisionLog, seq: u64) -> u64 {
    log.record_outcome(
        Actor::agent("hermes"),
        OutcomeEvent {
            decision_seq: seq,
            outcome: Outcome::Completed,
            detail: String::new(),
        },
    )
    .unwrap()
    .seq
}

fn segments(dir: &Path) -> Vec<PathBuf> {
    let mut v: Vec<PathBuf> = fs::read_dir(dir)
        .unwrap()
        .map(|e| e.unwrap().path())
        .filter(|p| {
            p.file_name()
                .and_then(|n| n.to_str())
                .is_some_and(|n| n.starts_with("seg-") && n.ends_with(".jsonl"))
        })
        .collect();
    v.sort();
    v
}
fn lines(p: &Path) -> Vec<String> {
    fs::read_to_string(p)
        .unwrap()
        .lines()
        .map(str::to_string)
        .collect()
}
fn write_lines(p: &Path, l: &[String]) {
    let mut s = l.join("\n");
    s.push('\n');
    fs::write(p, s).unwrap();
}
fn integrity(r: Result<citrate_agent_records::VerifyReport, Error>) -> IntegrityError {
    match r {
        Err(Error::Integrity(e)) => e,
        other => panic!("expected an integrity error, got {other:?}"),
    }
}

// ── chain basics ──────────────────────────────────────────────────────────────────────────

#[test]
fn append_and_verify_roundtrip() {
    let d = tempfile::tempdir().unwrap();
    let log = open(d.path());
    let a = approve(&log, "send 1 SALT");
    let b = log
        .record_decision(
            Actor::member("m1"),
            ev(HicTier::Hic1, Decision::Denied, "deploy x"),
        )
        .unwrap();
    assert!(!b.awaiting_outcome);
    let c = log
        .record_decision(
            Actor::agent("hermes"),
            ev(
                HicTier::Hic2,
                Decision::AutoWithinBudget,
                "siwe example.org",
            ),
        )
        .unwrap();
    assert!(c.awaiting_outcome);
    done(&log, a);
    let rep = verify_dir(d.path()).unwrap();
    assert_eq!(rep.count, 4);
    assert_eq!(rep.first_seq, Some(0));
    assert_eq!(rep.tip.as_ref().map(|t| t.0), Some(3));
    assert_eq!(rep.open_decisions, vec![c.seq]);
    assert_eq!(log.open_decisions().unwrap(), vec![c.seq]);
    let first = read::get(d.path(), 0).unwrap().unwrap();
    assert_eq!(first.record.prev, GENESIS_PREV);
    let second = read::get(d.path(), 1).unwrap().unwrap();
    assert_eq!(second.record.prev, first.hash);
}

#[test]
fn reopen_continues_the_chain() {
    let d = tempfile::tempdir().unwrap();
    {
        let log = open(d.path());
        let s = approve(&log, "a");
        done(&log, s);
    }
    let log = open(d.path());
    let s = approve(&log, "b");
    assert_eq!(s, 2);
    assert_eq!(verify_dir(d.path()).unwrap().count, 3);
}

#[test]
fn record_json_shape_is_stable_for_the_ui() {
    let d = tempfile::tempdir().unwrap();
    let log = open(d.path());
    log.record_decision(
        Actor::agent("hermes"),
        ev(HicTier::Hic2, Decision::AutoWithinBudget, "siwe"),
    )
    .unwrap();
    let line = &lines(&segments(d.path())[0])[0];
    let v: serde_json::Value = serde_json::from_str(line).unwrap();
    assert_eq!(v["record"]["v"], 1);
    assert_eq!(v["record"]["actor"]["kind"], "agent");
    assert_eq!(v["record"]["entry"]["decision"]["tier"], "hic-2");
    assert_eq!(
        v["record"]["entry"]["decision"]["decision"],
        "auto_within_budget"
    );
    assert_eq!(v["hash"].as_str().unwrap().len(), 64);
}

// ── policy on append ─────────────────────────────────────────────────────────────────────

#[test]
fn hic1_auto_within_budget_is_refused() {
    let d = tempfile::tempdir().unwrap();
    let log = open(d.path());
    let r = log.record_decision(
        Actor::agent("hermes"),
        ev(HicTier::Hic1, Decision::AutoWithinBudget, "tx"),
    );
    assert!(matches!(r, Err(Error::Invalid(_))), "{r:?}");
    assert_eq!(verify_dir(d.path()).unwrap().count, 0);
}

#[test]
fn outcome_must_close_an_open_allowing_decision() {
    let d = tempfile::tempdir().unwrap();
    let log = open(d.path());
    let denied = log
        .record_decision(
            Actor::member("m1"),
            ev(HicTier::Hic1, Decision::Denied, "x"),
        )
        .unwrap()
        .seq;
    let ok = approve(&log, "y");
    let out = |seq| {
        log.record_outcome(
            Actor::agent("hermes"),
            OutcomeEvent {
                decision_seq: seq,
                outcome: Outcome::Failed,
                detail: "boom".into(),
            },
        )
    };
    assert!(matches!(out(denied), Err(Error::Invalid(_))));
    assert!(matches!(out(99), Err(Error::Invalid(_))));
    assert!(out(ok).is_ok());
    assert!(matches!(out(ok), Err(Error::Invalid(_))), "double outcome");
    assert_eq!(verify_dir(d.path()).unwrap().count, 3);
}

#[test]
fn field_bounds_are_enforced() {
    let d = tempfile::tempdir().unwrap();
    let log = open(d.path());
    let mut e = ev(HicTier::Hic1, Decision::Approved, " ");
    assert!(matches!(
        log.record_decision(Actor::member("m1"), e.clone()),
        Err(Error::Invalid(_))
    ));
    e.subject = "s".repeat(5000);
    assert!(log.record_decision(Actor::member("m1"), e.clone()).is_err());
    e.subject = "ok".into();
    assert!(log.record_decision(Actor::member(""), e.clone()).is_err());
    e.evidence = vec![
        EvidenceRef {
            kind: "k".into(),
            uri: "u".into(),
            digest: None
        };
        33
    ];
    assert!(log.record_decision(Actor::member("m1"), e).is_err());
}

// ── tamper detection ─────────────────────────────────────────────────────────────────────

fn five(d: &Path) {
    let log = open(d);
    for i in 0..5 {
        approve(&log, &format!("op {i}"));
    }
}

#[test]
fn edited_field_is_detected() {
    let d = tempfile::tempdir().unwrap();
    five(d.path());
    let seg = &segments(d.path())[0];
    let mut l = lines(seg);
    l[2] = l[2].replace("op 2", "op 9");
    write_lines(seg, &l);
    assert_eq!(
        integrity(verify_dir(d.path())),
        IntegrityError::HashMismatch { seq: 2 }
    );
}

#[test]
fn edited_and_rehashed_record_breaks_the_next_link() {
    let d = tempfile::tempdir().unwrap();
    five(d.path());
    let seg = &segments(d.path())[0];
    let mut l = lines(seg);
    let mut r: citrate_agent_records::StoredRecord = serde_json::from_str(&l[2]).unwrap();
    if let Entry::Decision(ref mut e) = r.record.entry {
        e.subject = "op 9".into();
    }
    let r = citrate_agent_records::StoredRecord::seal(r.record).unwrap();
    l[2] = serde_json::to_string(&r).unwrap();
    write_lines(seg, &l);
    assert_eq!(
        integrity(verify_dir(d.path())),
        IntegrityError::PrevMismatch { seq: 3 }
    );
}

#[test]
fn reordered_records_are_detected() {
    let d = tempfile::tempdir().unwrap();
    five(d.path());
    let seg = &segments(d.path())[0];
    let mut l = lines(seg);
    l.swap(1, 2);
    write_lines(seg, &l);
    assert_eq!(
        integrity(verify_dir(d.path())),
        IntegrityError::SeqGap {
            expected: 1,
            found: 2
        }
    );
}

#[test]
fn deleted_middle_record_is_detected() {
    let d = tempfile::tempdir().unwrap();
    five(d.path());
    let seg = &segments(d.path())[0];
    let mut l = lines(seg);
    l.remove(3);
    write_lines(seg, &l);
    assert_eq!(
        integrity(verify_dir(d.path())),
        IntegrityError::SeqGap {
            expected: 3,
            found: 4
        }
    );
}

#[test]
fn tail_truncation_is_detected() {
    let d = tempfile::tempdir().unwrap();
    five(d.path());
    let seg = &segments(d.path())[0];
    let mut l = lines(seg);
    l.truncate(3);
    write_lines(seg, &l);
    assert_eq!(
        integrity(verify_dir(d.path())),
        IntegrityError::Truncated {
            head_seq: 4,
            tip: Some(2)
        }
    );
    // and the writer refuses to open on it
    assert!(matches!(
        DecisionLog::open(d.path(), LogConfig::default()),
        Err(Error::Integrity(IntegrityError::Truncated { .. }))
    ));
}

#[test]
fn whole_log_truncation_is_detected() {
    let d = tempfile::tempdir().unwrap();
    five(d.path());
    fs::remove_file(&segments(d.path())[0]).unwrap();
    assert_eq!(
        integrity(verify_dir(d.path())),
        IntegrityError::Truncated {
            head_seq: 4,
            tip: None
        }
    );
}

#[test]
fn missing_head_is_detected() {
    let d = tempfile::tempdir().unwrap();
    five(d.path());
    fs::remove_file(d.path().join("HEAD")).unwrap();
    assert_eq!(integrity(verify_dir(d.path())), IntegrityError::HeadMissing);
}

#[test]
fn injected_unknown_field_is_detected() {
    let d = tempfile::tempdir().unwrap();
    five(d.path());
    let seg = &segments(d.path())[0];
    let mut l = lines(seg);
    l[1] = l[1].replacen("\"v\":1,", "\"v\":1,\"note\":\"x\",", 1);
    write_lines(seg, &l);
    assert!(matches!(
        integrity(verify_dir(d.path())),
        IntegrityError::Malformed { line: 2, .. }
    ));
}

#[test]
fn forged_policy_violation_is_detected_even_with_valid_hashes() {
    // Rewrite the whole chain consistently with an HIC-1 auto approval: hashes line up, the
    // verifier's policy check still refuses it.
    let d = tempfile::tempdir().unwrap();
    five(d.path());
    let seg = &segments(d.path())[0];
    let l = lines(seg);
    let mut prev = GENESIS_PREV.to_string();
    let mut out = Vec::new();
    let mut last = String::new();
    for (i, line) in l.iter().enumerate() {
        let mut r: citrate_agent_records::StoredRecord = serde_json::from_str(line).unwrap();
        r.record.prev = prev.clone();
        if i == 1 {
            if let Entry::Decision(ref mut e) = r.record.entry {
                e.decision = Decision::AutoWithinBudget;
            }
        }
        let r = citrate_agent_records::StoredRecord::seal(r.record).unwrap();
        prev = r.hash.clone();
        last = r.hash.clone();
        out.push(serde_json::to_string(&r).unwrap());
    }
    write_lines(seg, &out);
    fs::write(
        d.path().join("HEAD"),
        serde_json::json!({"seq": 4, "hash": last}).to_string(),
    )
    .unwrap();
    assert!(matches!(
        integrity(verify_dir(d.path())),
        IntegrityError::Policy { seq: 1, .. }
    ));
}

// ── rotation ─────────────────────────────────────────────────────────────────────────────

#[test]
fn rotation_keeps_the_chain_verifiable_across_files() {
    let d = tempfile::tempdir().unwrap();
    let cfg = LogConfig {
        max_segment_bytes: 1500,
        max_segments: None,
    };
    let log = open_cfg(d.path(), cfg, clock(DAY));
    for i in 0..30 {
        let s = approve(&log, &format!("op {i}"));
        done(&log, s);
    }
    let segs = segments(d.path());
    assert!(
        segs.len() > 3,
        "expected rotation, got {} segments",
        segs.len()
    );
    for s in &segs {
        assert!(fs::metadata(s).unwrap().len() <= 1500);
    }
    let rep = verify_dir(d.path()).unwrap();
    assert_eq!(rep.count, 60);
    assert_eq!(rep.segments, segs.len());
    // the first record of segment 2 links to the last record of segment 1
    let last1: citrate_agent_records::StoredRecord =
        serde_json::from_str(lines(&segs[0]).last().unwrap()).unwrap();
    let first2: citrate_agent_records::StoredRecord =
        serde_json::from_str(&lines(&segs[1])[0]).unwrap();
    assert_eq!(first2.record.prev, last1.hash);
    drop(log);
    // removing a middle segment is a gap
    fs::remove_file(&segs[1]).unwrap();
    assert!(matches!(
        integrity(verify_dir(d.path())),
        IntegrityError::SeqGap { .. }
    ));
}

#[test]
fn pruning_bounds_total_size_and_keeps_a_verifiable_checkpoint() {
    let d = tempfile::tempdir().unwrap();
    let cfg = LogConfig {
        max_segment_bytes: 1500,
        max_segments: Some(2),
    };
    let log = open_cfg(d.path(), cfg.clone(), clock(DAY));
    for i in 0..30 {
        let s = approve(&log, &format!("op {i}"));
        done(&log, s);
    }
    assert!(segments(d.path()).len() <= 2);
    let rep = verify_dir(d.path()).unwrap();
    assert!(rep.count < 60);
    assert!(rep.first_seq.unwrap() > 0);
    assert_eq!(rep.tip.as_ref().map(|t| t.0), Some(59));
    drop(log);
    // reopen + append still fine
    let log = open_cfg(d.path(), cfg, clock(DAY));
    approve(&log, "after");
    drop(log);
    assert!(verify_dir(d.path()).is_ok());
    // a forged checkpoint is caught
    let cp = d.path().join("CHECKPOINT");
    let mut v: serde_json::Value = serde_json::from_str(&fs::read_to_string(&cp).unwrap()).unwrap();
    v["prev"] = serde_json::Value::String("11".repeat(32));
    fs::write(&cp, v.to_string()).unwrap();
    assert_eq!(
        integrity(verify_dir(d.path())),
        IntegrityError::CheckpointMismatch
    );
}

// ── concurrency ──────────────────────────────────────────────────────────────────────────

#[test]
fn concurrent_appends_produce_one_valid_chain() {
    let d = tempfile::tempdir().unwrap();
    let cfg = LogConfig {
        max_segment_bytes: 4096,
        max_segments: None,
    };
    let log = Arc::new(DecisionLog::open(d.path(), cfg).unwrap().0);
    let mut hs = Vec::new();
    for t in 0..8 {
        let log = Arc::clone(&log);
        hs.push(std::thread::spawn(move || {
            let mut seqs = Vec::new();
            for i in 0..25 {
                let s = approve(&log, &format!("t{t} op{i}"));
                seqs.push(s);
                seqs.push(done(&log, s));
            }
            seqs
        }));
    }
    let mut all: Vec<u64> = hs.into_iter().flat_map(|h| h.join().unwrap()).collect();
    all.sort();
    assert_eq!(all, (0..400).collect::<Vec<_>>());
    let rep = verify_dir(d.path()).unwrap();
    assert_eq!(rep.count, 400);
    assert!(rep.open_decisions.is_empty());
}

#[test]
fn a_second_writer_is_refused() {
    let d = tempfile::tempdir().unwrap();
    let _a = open(d.path());
    assert!(matches!(
        DecisionLog::open(d.path(), LogConfig::default()),
        Err(Error::Locked(_))
    ));
}

// ── crash recovery ───────────────────────────────────────────────────────────────────────

#[test]
fn crash_after_an_allowing_decision_marks_outcome_unknown() {
    let d = tempfile::tempdir().unwrap();
    let (allowed, denied);
    {
        let log = open(d.path());
        allowed = approve(&log, "send");
        denied = log
            .record_decision(
                Actor::member("m1"),
                ev(HicTier::Hic1, Decision::Denied, "x"),
            )
            .unwrap()
            .seq;
        // process dies here: no outcome for `allowed`
    }
    let (log, rep) = DecisionLog::open(d.path(), LogConfig::default()).unwrap();
    assert_eq!(rep.marked_unknown, vec![allowed]);
    assert!(log.open_decisions().unwrap().is_empty());
    let view = read::decision_view(d.path(), allowed).unwrap().unwrap();
    let out = view.outcome.unwrap();
    assert_eq!(out.record.actor.kind, ActorKind::Daemon);
    match out.record.entry {
        Entry::Outcome(o) => assert_eq!(o.outcome, Outcome::OutcomeUnknown),
        e => panic!("{e:?}"),
    }
    assert!(read::decision_view(d.path(), denied)
        .unwrap()
        .unwrap()
        .outcome
        .is_none());
    assert!(verify_dir(d.path()).is_ok());
    // a second reopen has nothing more to mark
    drop(log);
    let (_log, rep) = DecisionLog::open(d.path(), LogConfig::default()).unwrap();
    assert!(rep.marked_unknown.is_empty());
}

#[test]
fn torn_tail_write_is_quarantined_on_open() {
    let d = tempfile::tempdir().unwrap();
    five(d.path());
    let seg = segments(d.path())[0].clone();
    let mut f = fs::OpenOptions::new().append(true).open(&seg).unwrap();
    std::io::Write::write_all(&mut f, b"{\"hash\":\"abc\",\"rec").unwrap();
    drop(f);
    assert!(matches!(
        integrity(verify_dir(d.path())),
        IntegrityError::TornTail { .. }
    ));
    let (log, rep) = DecisionLog::open(d.path(), LogConfig::default()).unwrap();
    assert!(rep.torn_tail_bytes > 0);
    let quarantined = fs::read_dir(d.path())
        .unwrap()
        .filter_map(|e| e.ok())
        .any(|e| e.file_name().to_string_lossy().starts_with("torn-"));
    assert!(quarantined);
    // the five decisions were allowing ones with no outcome: all marked unknown
    assert_eq!(rep.marked_unknown, vec![0, 1, 2, 3, 4]);
    approve(&log, "after");
    drop(log);
    assert_eq!(verify_dir(d.path()).unwrap().count, 11);
}

#[test]
fn crash_between_append_and_head_update_is_repaired() {
    let d = tempfile::tempdir().unwrap();
    {
        let log = open(d.path());
        let s = approve(&log, "a");
        done(&log, s);
    }
    let first = read::get(d.path(), 0).unwrap().unwrap();
    fs::write(
        d.path().join("HEAD"),
        serde_json::json!({"seq": 0, "hash": first.hash}).to_string(),
    )
    .unwrap();
    let rep = verify_dir(d.path()).unwrap();
    assert!(rep.head_lag);
    let (_log, rec) = DecisionLog::open(d.path(), LogConfig::default()).unwrap();
    assert!(rec.head_repaired);
    assert!(!verify_dir(d.path()).unwrap().head_lag);
}

#[test]
fn head_more_than_one_behind_is_refused() {
    let d = tempfile::tempdir().unwrap();
    five(d.path());
    let first = read::get(d.path(), 0).unwrap().unwrap();
    fs::write(
        d.path().join("HEAD"),
        serde_json::json!({"seq": 0, "hash": first.hash}).to_string(),
    )
    .unwrap();
    assert_eq!(
        integrity(verify_dir(d.path())),
        IntegrityError::HeadBehind {
            head_seq: 0,
            tip: 4
        }
    );
}

#[test]
fn timestamps_never_go_backwards() {
    let d = tempfile::tempdir().unwrap();
    let c = clock(10 * DAY);
    let log = open_cfg(d.path(), LogConfig::default(), c.clone());
    approve(&log, "a");
    c.0.store(5 * DAY, Ordering::SeqCst);
    approve(&log, "b");
    let a = read::get(d.path(), 0).unwrap().unwrap();
    let b = read::get(d.path(), 1).unwrap().unwrap();
    assert_eq!(b.record.ts_ms, a.record.ts_ms);
}

// ── read API ─────────────────────────────────────────────────────────────────────────────

#[test]
fn page_reads_newest_first_with_a_cursor_across_segments() {
    let d = tempfile::tempdir().unwrap();
    let cfg = LogConfig {
        max_segment_bytes: 1200,
        max_segments: None,
    };
    let log = open_cfg(d.path(), cfg, clock(DAY));
    for i in 0..20 {
        approve(&log, &format!("op {i}"));
    }
    let p1 = read::page(d.path(), None, 7).unwrap();
    assert_eq!(
        p1.iter().map(|r| r.record.seq).collect::<Vec<_>>(),
        vec![19, 18, 17, 16, 15, 14, 13]
    );
    let p2 = read::page(d.path(), Some(13), 7).unwrap();
    assert_eq!(p2.first().map(|r| r.record.seq), Some(12));
    let tail = read::page(d.path(), Some(3), 10).unwrap();
    assert_eq!(
        tail.iter().map(|r| r.record.seq).collect::<Vec<_>>(),
        vec![2, 1, 0]
    );
    assert!(read::page(d.path(), None, 0).unwrap().is_empty());
}

#[test]
fn decision_view_joins_the_outcome() {
    let d = tempfile::tempdir().unwrap();
    let log = open(d.path());
    let s = approve(&log, "a");
    approve(&log, "b");
    let o = done(&log, s);
    let v = read::decision_view(d.path(), s).unwrap().unwrap();
    assert_eq!(v.decision.record.seq, s);
    assert_eq!(v.outcome.map(|r| r.record.seq), Some(o));
    // an outcome seq is not a decision
    assert!(read::decision_view(d.path(), o).unwrap().is_none());
    assert!(read::decision_view(d.path(), 99).unwrap().is_none());
}

// ── daily Merkle root + inclusion proofs ─────────────────────────────────────────────────

#[test]
fn daily_root_covers_exactly_one_utc_day() {
    let d = tempfile::tempdir().unwrap();
    let c = clock(20 * DAY + 1000);
    let log = open_cfg(d.path(), LogConfig::default(), c.clone());
    for i in 0..3 {
        approve(&log, &format!("d20 {i}"));
    }
    c.0.store(21 * DAY + 5, Ordering::SeqCst);
    for i in 0..4 {
        approve(&log, &format!("d21 {i}"));
    }
    let r20 = merkle::daily_root(d.path(), 20).unwrap().unwrap();
    assert_eq!((r20.first_seq, r20.last_seq, r20.count), (0, 2, 3));
    let r21 = merkle::daily_root(d.path(), 21).unwrap().unwrap();
    assert_eq!((r21.first_seq, r21.last_seq, r21.count), (3, 6, 4));
    assert!(merkle::daily_root(d.path(), 22).unwrap().is_none());
    let leaves: Vec<[u8; 32]> = (3..=6)
        .map(|s| read::get(d.path(), s).unwrap().unwrap().hash_raw().unwrap())
        .collect();
    assert_eq!(r21.root, hex::encode(merkle::merkle_root(&leaves).unwrap()));
    assert_eq!(merkle::utc_day(21 * DAY + 5), 21);
}

#[test]
fn inclusion_proofs_verify_and_reject_tampering() {
    let d = tempfile::tempdir().unwrap();
    let log = open_cfg(d.path(), LogConfig::default(), clock(30 * DAY));
    for i in 0..7 {
        approve(&log, &format!("op {i}"));
    }
    let root = merkle::daily_root(d.path(), 30).unwrap().unwrap();
    for seq in 0..7 {
        let p = merkle::inclusion_proof(d.path(), seq).unwrap().unwrap();
        assert_eq!(p.root, root.root);
        assert!(merkle::verify_inclusion(&p), "seq {seq}");
        let mut bad = p.clone();
        bad.leaf = "22".repeat(32);
        assert!(!merkle::verify_inclusion(&bad));
        let mut bad = p.clone();
        bad.leaf_index = (bad.leaf_index + 1) % bad.tree_size;
        assert!(!merkle::verify_inclusion(&bad));
    }
    assert!(merkle::inclusion_proof(d.path(), 99).unwrap().is_none());
}

#[test]
fn daily_root_refuses_a_tampered_log() {
    let d = tempfile::tempdir().unwrap();
    five(d.path());
    let seg = &segments(d.path())[0];
    let mut l = lines(seg);
    l[2] = l[2].replace("op 2", "op 9");
    write_lines(seg, &l);
    let day = merkle::utc_day(read::get(d.path(), 0).unwrap().unwrap().record.ts_ms);
    assert!(matches!(
        merkle::daily_root(d.path(), day),
        Err(Error::Integrity(_))
    ));
}

#[test]
fn rfc6962_tree_shape_for_every_size_up_to_40() {
    use sha2::{Digest, Sha256};
    let leaf = |i: u8| -> [u8; 32] { Sha256::digest([i]).into() };
    let lh = |d: &[u8; 32]| -> [u8; 32] {
        let mut h = Sha256::new();
        h.update([0u8]);
        h.update(d);
        h.finalize().into()
    };
    let nh = |l: &[u8; 32], r: &[u8; 32]| -> [u8; 32] {
        let mut h = Sha256::new();
        h.update([1u8]);
        h.update(l);
        h.update(r);
        h.finalize().into()
    };
    let a = leaf(0);
    let b = leaf(1);
    let c = leaf(2);
    assert!(merkle::merkle_root(&[]).is_none());
    assert_eq!(merkle::merkle_root(&[a]), Some(lh(&a)));
    assert_eq!(merkle::merkle_root(&[a, b]), Some(nh(&lh(&a), &lh(&b))));
    // RFC 6962: split at the largest power of two below n (2 | 1), not a duplicated last leaf
    assert_eq!(
        merkle::merkle_root(&[a, b, c]),
        Some(nh(&nh(&lh(&a), &lh(&b)), &lh(&c)))
    );
    for n in 1..=40u8 {
        let leaves: Vec<[u8; 32]> = (0..n).map(leaf).collect();
        let root = merkle::merkle_root(&leaves).unwrap();
        for i in 0..n as usize {
            let path = merkle::audit_path(&leaves, i);
            assert!(
                merkle::verify_path(&leaves[i], i as u64, n as u64, &path, &root),
                "n={n} i={i}"
            );
            if n > 1 {
                let mut bad = path.clone();
                bad[0][0] ^= 1;
                assert!(!merkle::verify_path(
                    &leaves[i], i as u64, n as u64, &bad, &root
                ));
            }
        }
    }
}

// ── verifier branches reached only by a consistent rewrite ───────────────────────────────

/// Rewrite every record of a one-segment log through `edit`, re-seal the whole chain and HEAD,
/// so only the semantic checks can catch the change.
fn rechain(d: &Path, mut edit: impl FnMut(usize, &mut citrate_agent_records::RecordBody)) {
    let seg = &segments(d)[0];
    let mut prev = GENESIS_PREV.to_string();
    let mut out = Vec::new();
    let mut tip = (0u64, String::new());
    for (i, line) in lines(seg).iter().enumerate() {
        let mut r: citrate_agent_records::StoredRecord = serde_json::from_str(line).unwrap();
        r.record.prev = prev.clone();
        edit(i, &mut r.record);
        let r = citrate_agent_records::StoredRecord::seal(r.record).unwrap();
        prev = r.hash.clone();
        tip = (r.record.seq, r.hash.clone());
        out.push(serde_json::to_string(&r).unwrap());
    }
    write_lines(seg, &out);
    fs::write(
        d.join("HEAD"),
        serde_json::json!({"seq": tip.0, "hash": tip.1}).to_string(),
    )
    .unwrap();
}

#[test]
fn rechain_without_edits_still_verifies() {
    let d = tempfile::tempdir().unwrap();
    five(d.path());
    rechain(d.path(), |_, _| {});
    assert_eq!(verify_dir(d.path()).unwrap().count, 5);
}

#[test]
fn forged_outcome_for_a_denied_decision_is_detected() {
    let d = tempfile::tempdir().unwrap();
    {
        let log = open(d.path());
        log.record_decision(
            Actor::member("m1"),
            ev(HicTier::Hic1, Decision::Denied, "x"),
        )
        .unwrap();
        let s = approve(&log, "y");
        done(&log, s);
    }
    rechain(d.path(), |i, b| {
        if i == 2 {
            if let Entry::Outcome(ref mut o) = b.entry {
                o.decision_seq = 0;
            }
        }
    });
    assert_eq!(
        integrity(verify_dir(d.path())),
        IntegrityError::BadOutcomeRef {
            seq: 2,
            decision_seq: 0
        }
    );
}

#[test]
fn backdated_record_is_detected() {
    let d = tempfile::tempdir().unwrap();
    let log = open_cfg(d.path(), LogConfig::default(), clock(5 * DAY));
    for i in 0..3 {
        approve(&log, &format!("op {i}"));
    }
    drop(log);
    rechain(d.path(), |i, b| {
        if i == 2 {
            b.ts_ms = DAY;
        }
    });
    assert_eq!(
        integrity(verify_dir(d.path())),
        IntegrityError::TimeReversed { seq: 2 }
    );
}

#[test]
fn unknown_schema_version_is_detected() {
    let d = tempfile::tempdir().unwrap();
    five(d.path());
    rechain(d.path(), |i, b| {
        if i == 1 {
            b.v = 2;
        }
    });
    assert_eq!(
        integrity(verify_dir(d.path())),
        IntegrityError::UnknownVersion { seq: 1, v: 2 }
    );
}

#[test]
fn head_with_the_wrong_hash_is_detected() {
    let d = tempfile::tempdir().unwrap();
    five(d.path());
    fs::write(
        d.path().join("HEAD"),
        serde_json::json!({"seq": 4, "hash": "33".repeat(32)}).to_string(),
    )
    .unwrap();
    assert_eq!(
        integrity(verify_dir(d.path())),
        IntegrityError::HeadHashMismatch { seq: 4 }
    );
}

#[test]
fn verify_through_the_open_writer() {
    let d = tempfile::tempdir().unwrap();
    let log = open(d.path());
    approve(&log, "a");
    let rep = log.verify().unwrap();
    assert_eq!(rep.count, 1);
    assert!(!rep.head_lag);
}

// ── pruning edge cases ───────────────────────────────────────────────────────────────────

#[test]
fn a_crash_mid_prune_leaves_a_stale_segment_that_open_removes() {
    let d = tempfile::tempdir().unwrap();
    let cfg = LogConfig {
        max_segment_bytes: 1500,
        max_segments: Some(2),
    };
    let saved = d.path().join("saved-first-segment");
    {
        let log = open_cfg(d.path(), cfg.clone(), clock(DAY));
        let mut i = 0;
        // fill until the first segment exists alone and is full, copy it, then force a prune
        while segments(d.path()).len() < 2 {
            assert!(i < 200, "rotation never happened");
            let s = approve(&log, &format!("op {i}"));
            done(&log, s);
            i += 1;
        }
        fs::copy(&segments(d.path())[0], &saved).unwrap();
        while segments(d.path()).len() < 3 && !d.path().join("CHECKPOINT").exists() {
            assert!(i < 400, "pruning never happened");
            let s = approve(&log, &format!("op {i}"));
            done(&log, s);
            i += 1;
        }
    }
    assert!(d.path().join("CHECKPOINT").exists());
    // put the pruned segment back, as if the delete after the checkpoint write never happened
    fs::copy(&saved, d.path().join("seg-00000001.jsonl")).unwrap();
    fs::remove_file(&saved).unwrap();
    assert!(verify_dir(d.path()).is_ok(), "stale segment is skipped");
    let (_log, rep) = DecisionLog::open_with_clock(d.path(), cfg, clock(DAY)).unwrap();
    assert_eq!(rep.stale_segments_removed, 1);
    assert!(!d.path().join("seg-00000001.jsonl").exists());
}

#[test]
fn an_open_decision_survives_pruning_and_is_marked_unknown_on_recovery() {
    let d = tempfile::tempdir().unwrap();
    let cfg = LogConfig {
        max_segment_bytes: 1500,
        max_segments: Some(2),
    };
    let pending;
    {
        let log = open_cfg(d.path(), cfg.clone(), clock(DAY));
        pending = approve(&log, "never closed");
        for i in 0..30 {
            let s = approve(&log, &format!("op {i}"));
            done(&log, s);
        }
        assert!(verify_dir(d.path()).unwrap().first_seq.unwrap() > pending);
        assert_eq!(log.open_decisions().unwrap(), vec![pending]);
    }
    assert_eq!(verify_dir(d.path()).unwrap().open_decisions, vec![pending]);
    let (log, rep) = DecisionLog::open_with_clock(d.path(), cfg, clock(DAY)).unwrap();
    assert_eq!(rep.marked_unknown, vec![pending]);
    assert!(log.open_decisions().unwrap().is_empty());
    drop(log);
    assert!(verify_dir(d.path()).unwrap().open_decisions.is_empty());
}

// ── live readers ─────────────────────────────────────────────────────────────────────────

#[test]
fn readers_tolerate_an_append_in_flight() {
    let d = tempfile::tempdir().unwrap();
    let log = open_cfg(d.path(), LogConfig::default(), clock(40 * DAY));
    for i in 0..3 {
        approve(&log, &format!("op {i}"));
    }
    // simulate a concurrent half-written line as an outside reader would see it
    let seg = segments(d.path())[0].clone();
    let mut f = fs::OpenOptions::new().append(true).open(&seg).unwrap();
    std::io::Write::write_all(&mut f, b"{\"hash\":\"").unwrap();
    drop(f);
    assert!(verify_dir(d.path()).is_err(), "strict verify flags it");
    assert_eq!(merkle::daily_root(d.path(), 40).unwrap().unwrap().count, 3);
    assert_eq!(read::page(d.path(), None, 10).unwrap().len(), 3);
}

#[test]
fn a_stale_segment_that_disagrees_with_the_checkpoint_is_detected() {
    let d = tempfile::tempdir().unwrap();
    let cfg = LogConfig {
        max_segment_bytes: 1500,
        max_segments: Some(1),
    };
    let saved = d.path().join("saved-first-segment");
    {
        let log = open_cfg(d.path(), cfg, clock(DAY));
        let mut i = 0;
        while !d.path().join("CHECKPOINT").exists() {
            assert!(i < 200, "pruning never happened");
            if segments(d.path())
                .first()
                .is_some_and(|p| p.ends_with("seg-00000001.jsonl"))
            {
                fs::copy(&segments(d.path())[0], &saved).unwrap();
            }
            let s = approve(&log, &format!("op {i}"));
            done(&log, s);
            i += 1;
        }
    }
    // restore segment 1 as a stale leftover, but with its last record's hash altered
    let mut l = lines(&saved);
    let last = l.len() - 1;
    let mut r: citrate_agent_records::StoredRecord = serde_json::from_str(&l[last]).unwrap();
    r.hash = "44".repeat(32);
    l[last] = serde_json::to_string(&r).unwrap();
    write_lines(&d.path().join("seg-00000001.jsonl"), &l);
    fs::remove_file(&saved).unwrap();
    assert_eq!(
        integrity(verify_dir(d.path())),
        IntegrityError::CheckpointMismatch
    );
}

#[test]
fn record_hash_is_domain_separated_sha256_of_the_canonical_body() {
    use sha2::{Digest, Sha256};
    let d = tempfile::tempdir().unwrap();
    let log = open(d.path());
    approve(&log, "a");
    let r = read::get(d.path(), 0).unwrap().unwrap();
    let mut h = Sha256::new();
    h.update(b"citrate.agent-records.v1\n");
    h.update(serde_json::to_vec(&r.record).unwrap());
    assert_eq!(r.hash, hex::encode(h.finalize()));
}

#[test]
fn a_proof_that_stops_at_a_subtree_root_is_rejected() {
    use sha2::{Digest, Sha256};
    let leaves: Vec<[u8; 32]> = (0..4u8).map(|i| Sha256::digest([i]).into()).collect();
    let path = merkle::audit_path(&leaves, 0);
    assert_eq!(path.len(), 2);
    // the root of the left half, presented as the root of the 4-leaf tree with a cut path
    let subtree = merkle::merkle_root(&leaves[..2]).unwrap();
    assert!(!merkle::verify_path(&leaves[0], 0, 4, &path[..1], &subtree));
}

// ── pruning edge cases found in review ──────────────────────────────────────────────────

/// Fill a pruning log until the first CHECKPOINT exists. Returns the config and the first line
/// ever written (record 0), which by then is pruned.
fn fill_until_pruned(d: &Path, max_segments: usize) -> (LogConfig, String) {
    let cfg = LogConfig {
        max_segment_bytes: 1500,
        max_segments: Some(max_segments),
    };
    let log = open_cfg(d, cfg.clone(), clock(DAY));
    let first = approve(&log, "op 0");
    let first_line = lines(&segments(d)[0])[0].clone();
    done(&log, first);
    let mut i = 1;
    while !d.join("CHECKPOINT").exists() {
        assert!(i < 300, "pruning never happened");
        let s = approve(&log, &format!("op {i}"));
        done(&log, s);
        i += 1;
    }
    (cfg, first_line)
}

#[test]
fn a_crash_after_pruning_every_record_and_before_the_next_append_reopens() {
    // max_segments = 1: a rotation prunes every record. A crash before the record that caused
    // the rotation lands leaves an empty retained chain with HEAD on the checkpoint's record.
    let d = tempfile::tempdir().unwrap();
    let (cfg, _) = fill_until_pruned(d.path(), 1);
    let cp: serde_json::Value =
        serde_json::from_str(&fs::read_to_string(d.path().join("CHECKPOINT")).unwrap()).unwrap();
    let next_seq = cp["next_seq"].as_u64().unwrap();
    let last = segments(d.path()).pop().unwrap();
    fs::write(&last, b"").unwrap();
    let head = serde_json::json!({ "seq": next_seq - 1, "hash": cp["prev"] });
    fs::write(d.path().join("HEAD"), head.to_string()).unwrap();

    let rep = verify_dir(d.path()).unwrap();
    assert_eq!((rep.count, rep.tip), (0, None));
    let log = open_cfg(d.path(), cfg.clone(), clock(DAY));
    assert_eq!(approve(&log, "after the crash"), next_seq);
    drop(log);
    assert!(verify_dir(d.path()).is_ok());

    // a HEAD that does not name the checkpoint's record is still truncation
    fs::write(&last, b"").unwrap();
    let head = serde_json::json!({ "seq": next_seq + 5, "hash": cp["prev"] });
    fs::write(d.path().join("HEAD"), head.to_string()).unwrap();
    assert!(matches!(
        integrity(verify_dir(d.path())),
        IntegrityError::Truncated { .. }
    ));
}

#[test]
fn a_pre_checkpoint_record_inside_the_retained_chain_is_detected() {
    let d = tempfile::tempdir().unwrap();
    let (_cfg, first_line) = fill_until_pruned(d.path(), 2);
    let last = segments(d.path()).pop().unwrap();
    let original = lines(&last);

    // a pruned record put back at the start of a retained segment
    let mut l = original.clone();
    l.insert(0, first_line.clone());
    write_lines(&last, &l);
    assert!(matches!(
        integrity(verify_dir(d.path())),
        IntegrityError::SeqGap { .. }
    ));

    // or appended after the tip
    let mut l = original.clone();
    l.push(first_line.clone());
    write_lines(&last, &l);
    assert!(matches!(
        integrity(verify_dir(d.path())),
        IntegrityError::SeqGap { .. }
    ));

    // or as a whole stale-looking segment after the retained chain
    write_lines(&last, &original);
    let after = d.path().join("seg-99999999.jsonl");
    write_lines(&after, &[first_line]);
    assert!(matches!(
        integrity(verify_dir(d.path())),
        IntegrityError::SeqGap { .. }
    ));
    fs::remove_file(&after).unwrap();
    assert!(verify_dir(d.path()).is_ok());
}
