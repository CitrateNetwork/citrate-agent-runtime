//! HUP-S1.5 / US-1.5 AC3: escalation records in metering (a JSONL log and a daily report), with
//! the registry route's x402 receipt kept as the provider sent it.

use citrate_agent_metering::{
    utc_day_bounds_ms, ChargeUnit, EscalationLog, EscalationOutcomeKind, EscalationRecord,
    EscalationReport, EscalationRoute, MeteringError, ReceiptRecord, ESCALATION_RECORD_SCHEMA,
};

fn day_start(day: &str) -> u64 {
    utc_day_bounds_ms(day).expect("day").0
}

fn endpoint_rec(id: &str, at: u64, micros: u64, outcome: EscalationOutcomeKind) -> EscalationRecord {
    EscalationRecord {
        schema: ESCALATION_RECORD_SCHEMA,
        escalation_id: id.into(),
        route: EscalationRoute::Endpoint,
        model: "planner-large".into(),
        started_unix_ms: at,
        latency_ms: 900,
        tokens_in: Some(40),
        tokens_out: Some(12),
        charged: micros.to_string(),
        unit: ChargeUnit::MicroUsd,
        payee: None,
        receipt: None,
        outcome,
    }
}

fn registry_rec(id: &str, at: u64, base: &str, receipt: Option<ReceiptRecord>) -> EscalationRecord {
    EscalationRecord {
        schema: ESCALATION_RECORD_SCHEMA,
        escalation_id: id.into(),
        route: EscalationRoute::Registry,
        model: format!("0x{}", "cd".repeat(32)),
        started_unix_ms: at,
        latency_ms: 1500,
        tokens_in: None,
        tokens_out: None,
        charged: base.into(),
        unit: ChargeUnit::BaseUnits {
            asset: "0xaa918302b94a4b0e75e01e019cc6b819b4f7c906".into(),
            network: "eip155:40204".into(),
        },
        payee: Some("0x70997970c51812dc3a010c7d01b50e0d17dc79c8".into()),
        receipt,
        outcome: EscalationOutcomeKind::Answered,
    }
}

fn receipt(tx_byte: &str) -> ReceiptRecord {
    ReceiptRecord {
        success: true,
        transaction: Some(format!("0x{}", tx_byte.repeat(32))),
        network: Some("eip155:40204".into()),
        payer: Some("0x9858effd232b4033e47d90003d41ec34ecaeda94".into()),
    }
}

#[test]
fn the_log_round_trips_and_a_missing_file_is_empty() {
    let dir = tempfile::tempdir().expect("tmp");
    let log = EscalationLog::new(dir.path().join("m").join("escalations.jsonl"));
    assert_eq!(log.read_all().expect("empty"), vec![]);
    let t = day_start("2026-10-01");
    let a = endpoint_rec("esc-1", t + 1, 1234, EscalationOutcomeKind::Answered);
    let b = registry_rec("esc-2", t + 2, "10000000000000000", Some(receipt("12")));
    log.append(&a).expect("append a");
    log.append(&b).expect("append b");
    assert_eq!(log.read_all().expect("read"), vec![a, b]);
}

#[test]
fn a_bad_line_is_named_not_skipped() {
    let dir = tempfile::tempdir().expect("tmp");
    let path = dir.path().join("escalations.jsonl");
    let log = EscalationLog::new(&path);
    log.append(&endpoint_rec("esc-1", 1, 1, EscalationOutcomeKind::Answered))
        .expect("append");
    std::fs::write(
        &path,
        format!("{}not json\n", std::fs::read_to_string(&path).expect("read")),
    )
    .expect("write");
    assert!(matches!(log.read_all(), Err(MeteringError::Parse { line: 2, .. })));
}

#[test]
fn records_hold_no_content_fields() {
    let v = serde_json::to_value(registry_rec("esc-2", 5, "1", Some(receipt("12")))).expect("json");
    let mut keys: Vec<String> = v.as_object().expect("obj").keys().cloned().collect();
    keys.sort();
    assert_eq!(
        keys,
        [
            "charged", "escalation_id", "latency_ms", "model", "outcome", "payee", "receipt",
            "route", "schema", "started_unix_ms", "tokens_in", "tokens_out", "unit"
        ]
    );
}

#[test]
fn the_daily_report_counts_spend_per_unit_and_keeps_receipts() {
    let t = day_start("2026-10-01");
    let recs = vec![
        endpoint_rec("esc-1", t + 10, 1_500, EscalationOutcomeKind::Answered),
        endpoint_rec("esc-2", t + 20, 700, EscalationOutcomeKind::FailedMaybeSent),
        endpoint_rec("esc-3", t + 30, 0, EscalationOutcomeKind::FailedNotSent),
        registry_rec("esc-4", t + 40, "10000000000000000", Some(receipt("12"))),
        registry_rec("esc-5", t + 50, "5000000000000000", Some(receipt("34"))),
        registry_rec("esc-6", t + 60, "5000000000000000", None),
        // The next day: not counted.
        endpoint_rec("esc-7", t + 86_400_000, 9_999, EscalationOutcomeKind::Answered),
    ];
    let r = EscalationReport::build("2026-10-01", &recs).expect("report");
    assert_eq!(r.total, 6);
    assert_eq!((r.answered, r.failed_maybe_sent, r.failed_not_sent), (4, 1, 1));
    assert_eq!((r.endpoint, r.registry), (3, 3));
    assert_eq!(r.micro_usd_charged, 2_200);
    assert_eq!(
        r.base_units_charged
            .get("eip155:40204/0xaa918302b94a4b0e75e01e019cc6b819b4f7c906")
            .map(String::as_str),
        Some("20000000000000000")
    );
    assert_eq!(r.registry_without_receipt, 1);
    let ids: Vec<&str> = r.receipts.iter().map(|(id, _)| id.as_str()).collect();
    assert_eq!(ids, ["esc-4", "esc-5"]);
}

#[test]
fn an_unsuccessful_receipt_is_not_counted_as_one() {
    let t = day_start("2026-10-01");
    let mut bad = receipt("12");
    bad.success = false;
    let r = EscalationReport::build("2026-10-01", &[registry_rec("esc-1", t, "1", Some(bad))])
        .expect("report");
    assert!(r.receipts.is_empty());
    assert_eq!(r.registry_without_receipt, 1);
}

#[test]
fn a_bad_day_is_refused() {
    assert!(matches!(
        EscalationReport::build("2026-13-01", &[]),
        Err(MeteringError::InvalidDay(_))
    ));
}
