//! HUP-S1.5 / US-1.5 AC3: escalation receipts in metering (content-free, joined by escalation id).

use citrate_agent_metering::{
    utc_day_bounds_ms, EscalationLog, EscalationReceipt, EscalationRoute, EscalationSettlement,
    EscalationSummary, MeteringError, ESCALATION_RECEIPT_SCHEMA,
};

fn day_start(day: &str) -> u64 {
    utc_day_bounds_ms(day).map(|b| b.0).unwrap_or(0)
}

#[test]
fn a_settled_receipt_carries_usage_and_never_charges_above_the_reservation() {
    let r = EscalationReceipt::settled(
        "esc-1",
        "big-model",
        10,
        1200,
        Some((900, 300)),
        5_000,
        7_000,
        true,
    );
    assert_eq!(r.schema, ESCALATION_RECEIPT_SCHEMA);
    assert_eq!(r.route, EscalationRoute::MemberEndpoint);
    assert_eq!(r.settlement, EscalationSettlement::Settled);
    assert_eq!((r.tokens_in, r.tokens_out), (Some(900), Some(300)));
    assert_eq!(r.charged_micros, 5_000, "capped at the reservation");
    assert!(r.usage_reported && r.exceeded_quote);
    let r = EscalationReceipt::settled("esc-2", "m", 10, 5, None, 5_000, 5_000, false);
    assert_eq!(
        (r.tokens_in, r.tokens_out, r.usage_reported),
        (None, None, false)
    );
}

#[test]
fn a_failure_after_sending_charges_the_whole_reservation() {
    let r = EscalationReceipt::failed_after_send("esc-3", "m", 10, 30_000, 4_200);
    assert_eq!(r.settlement, EscalationSettlement::FailedAfterSend);
    assert_eq!(r.charged_micros, 4_200);
    assert!(!r.usage_reported);
}

#[test]
fn receipts_hold_no_content_fields() {
    let r = EscalationReceipt::settled("esc-1", "m", 1, 1, Some((1, 1)), 10, 5, false);
    let v = serde_json::to_value(&r).unwrap_or_default();
    let keys: Vec<&str> = v
        .as_object()
        .map(|o| o.keys().map(String::as_str).collect())
        .unwrap_or_default();
    for banned in [
        "prompt", "content", "answer", "url", "base_url", "api_key", "key", "system",
    ] {
        assert!(
            !keys.contains(&banned),
            "receipt must not carry {banned}: {keys:?}"
        );
    }
}

#[test]
fn the_log_round_trips_and_names_a_bad_line() {
    let dir = tempfile::tempdir().unwrap_or_else(|e| panic!("{e}"));
    let log = EscalationLog::new(dir.path().join("nested").join("escalations.jsonl"));
    assert_eq!(log.read_all(), Ok(vec![]), "a missing file is an empty log");
    let a = EscalationReceipt::settled("esc-a", "m", 1, 2, Some((3, 4)), 10, 9, false);
    let b = EscalationReceipt::failed_after_send("esc-b", "m", 5, 6, 7);
    log.append(&a).unwrap_or_else(|e| panic!("{e}"));
    log.append(&b).unwrap_or_else(|e| panic!("{e}"));
    assert_eq!(log.read_all(), Ok(vec![a, b]));
    std::fs::write(log.path(), "{\"schema\":1}\n").unwrap_or_else(|e| panic!("{e}"));
    assert!(matches!(
        log.read_all(),
        Err(MeteringError::Parse { line: 1, .. })
    ));
}

#[test]
fn the_daily_summary_sums_only_that_day() {
    let d = day_start("2026-10-04");
    let rs = vec![
        EscalationReceipt::settled("a", "m", d + 1, 1, Some((100, 50)), 1_000, 600, false),
        EscalationReceipt::settled("b", "m", d + 2, 1, None, 2_000, 2_000, false),
        EscalationReceipt::failed_after_send("c", "m", d + 3, 1, 500),
        EscalationReceipt::settled("d", "m", d + 4, 1, Some((10, 10)), 100, 100, true),
        // The next day and the previous day are excluded.
        EscalationReceipt::settled("e", "m", d + 86_400_000, 1, Some((1, 1)), 9, 9, false),
        EscalationReceipt::settled("f", "m", d - 1, 1, Some((1, 1)), 9, 9, false),
    ];
    let s = EscalationSummary::build("2026-10-04", &rs).unwrap_or_else(|e| panic!("{e}"));
    assert_eq!((s.count, s.settled, s.failed_after_send), (4, 3, 1));
    assert_eq!(s.charged_micros, 600 + 2_000 + 500 + 100);
    assert_eq!(s.reserved_micros, 1_000 + 2_000 + 500 + 100);
    assert_eq!((s.tokens_in, s.tokens_out), (110, 60));
    assert_eq!(s.without_usage, 2);
    assert_eq!(s.exceeded_quote, 1);
    let md = s.to_markdown();
    assert!(
        md.contains("Escalations: 4 (3 settled, 1 failed after sending)"),
        "{md}"
    );
    assert!(md.contains("$0.003200 of $0.003600 reserved"), "{md}");
    assert!(md.contains("Above the quote"), "{md}");
    assert!(EscalationSummary::build("2026-13-01", &rs).is_err());
    let empty = EscalationSummary::build("2026-10-05", &[]).unwrap_or_else(|e| panic!("{e}"));
    assert_eq!(empty.count, 0);
    assert!(empty.to_markdown().contains("No escalations."));
}
