//! HUP-S5.3 AC3: decide() decisions and task outcomes recorded per backend.

use citrate_agent_loop::decide::{
    BackendKind, DecideError, DecisionPurpose, DecisionRecord, ProbSource,
};
use citrate_agent_metering::{
    DecisionLine, DecisionLog, DecisionReport, MeteringError, TaskRecord,
};

fn ok(backend: BackendKind, latency: u64, conf: f64, egress: Option<usize>) -> DecisionLine {
    DecisionLine::Decision(DecisionRecord {
        at_unix_ms: 1_700_000_000_000,
        backend,
        purpose: DecisionPurpose::PickElement,
        n_options: 5,
        ok: true,
        error: None,
        latency_ms: latency,
        confidence: Some(conf),
        probs_source: Some(ProbSource::Model),
        egress_bytes: egress,
    })
}

fn task(backend: BackendKind, id: &str, success: bool) -> DecisionLine {
    DecisionLine::Task(
        TaskRecord::new(1_700_000_000_000, backend, "web-subset-v1", id, success).unwrap(),
    )
}

#[test]
fn the_report_splits_decisions_and_task_success_by_backend() {
    let lines = vec![
        ok(BackendKind::Local, 100, 0.9, None),
        ok(BackendKind::Local, 300, 0.7, None),
        DecisionLine::Decision(DecisionRecord::failure(
            1,
            BackendKind::Local,
            DecisionPurpose::Route,
            3,
            50,
            &DecideError::Backend("down".into()),
        )),
        ok(BackendKind::Jev, 800, 0.95, Some(1200)),
        task(BackendKind::Local, "a", true),
        task(BackendKind::Local, "b", false),
        task(BackendKind::Local, "c", true),
        task(BackendKind::Jev, "a", true),
    ];
    let r = DecisionReport::build(&lines);
    let local = &r.backends["local"];
    assert_eq!(local.decisions, 3);
    assert_eq!(local.errors, 1);
    assert_eq!(local.errors_by_kind["backend"], 1);
    assert_eq!(local.latency_ms.as_ref().unwrap().p50, 100);
    assert_eq!(local.latency_ms.as_ref().unwrap().max, 300);
    assert!((local.mean_confidence.unwrap() - 0.8).abs() < 1e-9);
    assert_eq!(local.egress_bytes, 0);
    assert_eq!(local.tasks_attempted, 3);
    assert_eq!(local.tasks_succeeded, 2);
    assert_eq!(local.task_success_bps, Some(6_666));
    let jev = &r.backends["jev"];
    assert_eq!(jev.egress_bytes, 1200);
    assert_eq!(jev.task_success_bps, Some(10_000));
    let md = r.to_markdown();
    assert!(md.contains("| local |"), "{md}");
    assert!(md.contains("66.66%"), "{md}");
}

#[test]
fn an_empty_report_has_no_rates() {
    let r = DecisionReport::build(&[]);
    assert!(r.backends.is_empty());
    assert!(r.to_markdown().contains("No decisions"));
}

#[test]
fn task_ids_are_slugs_not_content() {
    for bad in ["", "has space", "x".repeat(65).as_str(), "a/b", "Ünïcode"] {
        assert!(
            TaskRecord::new(0, BackendKind::Local, "suite", bad, true).is_err(),
            "{bad:?}"
        );
        assert!(TaskRecord::new(0, BackendKind::Local, bad, "task", true).is_err());
    }
    assert!(TaskRecord::new(
        0,
        BackendKind::Local,
        "web-subset-v1",
        "repo-star_2.x",
        true
    )
    .is_ok());
}

#[test]
fn the_log_round_trips_and_names_a_bad_line() {
    let dir = tempfile::tempdir().unwrap();
    let log = DecisionLog::new(dir.path().join("nested/decisions.jsonl"));
    assert!(log.read_all().unwrap().is_empty());
    let a = ok(BackendKind::Local, 10, 0.5, None);
    let b = task(BackendKind::Jev, "t1", false);
    log.append(&a).unwrap();
    log.append(&b).unwrap();
    assert_eq!(log.read_all().unwrap(), vec![a, b]);
    std::fs::write(log.path(), "{\"kind\":\"decision\"}\n").unwrap();
    assert!(matches!(
        log.read_all(),
        Err(MeteringError::Parse { line: 1, .. })
    ));
}
