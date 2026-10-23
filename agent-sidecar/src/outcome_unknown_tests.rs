//! C1-V3-R — the ceremony bridge's approve route carries the payment outcome.
//!
//! citrate-core (C1-V3, `hermes_resolve_outcome_unknown`) releases a payment the member approved
//! whose broadcast had no known outcome through `POST /approvals/approve` with
//! `{id, outcome: "submitted_outcome_unknown", txHash, message}`. The capsule must be told exactly
//! that message (not success), the decision record must say "Submitted · outcome unknown (tx …)",
//! and an identical re-proposal must reference the earlier transaction and never auto-approve.
//! A body with only `{id}` keeps today's behaviour.

use super::*;
use axum::body::Body;
use axum::http::{Request, StatusCode};
use citrate_agent_core::hitl::{ApprovalOutcomePublic, ToolCall};
use citrate_agent_loop::{AssistantTurn, CompletionRequest, LlmClient, LlmError};
use citrate_agent_records::{DecisionLog, Entry, LogConfig, Outcome};
use std::time::Duration;
use tower::ServiceExt;

const BEARER: &str = "test-bearer-token-outcome-0001";
const HASH: &str = "0x8f3c2a1b9d4e5f60718293a4b5c6d7e8f90a1b2c3d4e5f60718293a4b5c6d7e8";

struct Quiet;
impl LlmClient for Quiet {
    fn complete(&self, _req: &CompletionRequest) -> Result<AssistantTurn, LlmError> {
        Ok(AssistantTurn::text("(done)"))
    }
}

struct Fx {
    root: tempfile::TempDir,
    st: Arc<AppState>,
}

impl Fx {
    fn new() -> Self {
        Self::new_with(LogConfig::default())
    }

    fn new_with(cfg: LogConfig) -> Self {
        let root = tempfile::tempdir().unwrap();
        let (log, _) = DecisionLog::open(&root.path().join("records"), cfg).unwrap();
        let log = Arc::new(log);
        let client: Arc<dyn LlmClient> = Arc::new(Quiet);
        let mgr = sessions::SessionManager::new(
            Arc::new(move |_ep: &sessions::LlmEndpoint| client.clone()),
            Duration::from_secs(5),
        )
        .with_records(log.clone());
        let st = Arc::new(AppState {
            estop: EmergencyStop::new(),
            queue: Arc::new(ApprovalQueue::new()),
            skills: vec![],
            dispatch: None,
            bearer: BEARER.to_string(),
            run_slots: Arc::new(tokio::sync::Semaphore::new(MAX_CONCURRENT_SKILLS)),
            sessions: Arc::new(mgr),
        });
        Fx { root, st }
    }

    fn records(&self) -> Vec<citrate_agent_records::StoredRecord> {
        let dir = self.root.path().join("records");
        let mut r = citrate_agent_records::read::page(&dir, None, 10_000).unwrap();
        r.sort_by_key(|x| x.record.seq);
        r
    }

    /// The (outcome, detail) closing each ceremony decision, oldest first.
    fn ceremony_outcomes(&self) -> Vec<(Decision, Option<(Outcome, String)>)> {
        let recs = self.records();
        recs.iter()
            .filter_map(|r| match &r.record.entry {
                Entry::Decision(d) if d.kind == "ceremony.capsule_effect" => {
                    let seq = r.record.seq;
                    let out = recs.iter().find_map(|o| match &o.record.entry {
                        Entry::Outcome(o) if o.decision_seq == seq => {
                            Some((o.outcome, o.detail.clone()))
                        }
                        _ => None,
                    });
                    Some((d.decision, out))
                }
                _ => None,
            })
            .collect()
    }

    async fn post(&self, path: &str, body: serde_json::Value) -> (StatusCode, serde_json::Value) {
        let r = app(self.st.clone())
            .oneshot(
                Request::builder()
                    .method("POST")
                    .uri(path)
                    .header("content-type", "application/json")
                    .header("authorization", format!("Bearer {BEARER}"))
                    .body(Body::from(body.to_string()))
                    .unwrap(),
            )
            .await
            .unwrap();
        let s = r.status();
        let bytes = axum::body::to_bytes(r.into_body(), 1 << 20).await.unwrap();
        (
            s,
            serde_json::from_slice(&bytes).unwrap_or(serde_json::Value::Null),
        )
    }

    async fn get(&self, path: &str) -> serde_json::Value {
        let r = app(self.st.clone())
            .oneshot(
                Request::builder()
                    .method("GET")
                    .uri(path)
                    .header("authorization", format!("Bearer {BEARER}"))
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(r.status(), StatusCode::OK);
        let bytes = axum::body::to_bytes(r.into_body(), 1 << 20).await.unwrap();
        serde_json::from_slice(&bytes).unwrap()
    }

    async fn wait_depth(&self, want: usize) {
        for _ in 0..400 {
            if self.st.queue.depth() == want {
                return;
            }
            tokio::time::sleep(Duration::from_millis(5)).await;
        }
        panic!("queue never reached depth {want}");
    }
}

use citrate_agent_records::Decision;

fn payment(id: &str) -> ToolCall {
    ToolCall {
        call_id: id.to_string(),
        name: "pay::eth-send".to_string(),
        args: serde_json::json!({
            "to": "0x4a86659BDab24dc444C72fbbaD4cd83491820E40",
            "data_hex": "0xa9059cbb",
            "data_len": 4
        }),
    }
}

fn core_message(hash: &str) -> String {
    format!("submitted, outcome unknown, tx {hash}, check before retrying")
}

fn unknown_body(id: &str) -> serde_json::Value {
    serde_json::json!({
        "id": id,
        "outcome": "submitted_outcome_unknown",
        "txHash": HASH,
        "message": core_message(HASH),
    })
}

#[tokio::test(flavor = "multi_thread")]
async fn an_unknown_outcome_reaches_the_capsule_as_that_message_not_success() {
    let fx = Fx::new();
    let q = fx.st.queue.clone();
    let waiter = tokio::spawn(async move { q.submit_with_resolution(payment("p1")).await });
    fx.wait_depth(1).await;

    let (s, v) = fx.post("/approvals/approve", unknown_body("p1")).await;
    assert_eq!(s, StatusCode::OK, "{v}");
    assert_eq!(v["resolved"], true);
    assert_eq!(v["outcome"], "submitted_outcome_unknown");

    match waiter.await.unwrap() {
        citrate_agent_core::hitl::Resolution::SubmittedOutcomeUnknown(u) => {
            assert_eq!(u.message(), core_message(HASH), "exactly core's words");
            assert!(u.message().contains(HASH), "the message names the tx");
            assert_eq!(u.tx_hash(), Some(HASH));
        }
        other => panic!("an unknown outcome is not a plain decision: {other:?}"),
    }
}

#[tokio::test(flavor = "multi_thread")]
async fn the_plain_submit_never_reads_an_unknown_outcome_as_approved() {
    let fx = Fx::new();
    let q = fx.st.queue.clone();
    let waiter = tokio::spawn(async move { q.submit_with_outcome(payment("p2")).await });
    fx.wait_depth(1).await;
    let (s, _) = fx.post("/approvals/approve", unknown_body("p2")).await;
    assert_eq!(s, StatusCode::OK);
    let out = waiter.await.unwrap();
    assert_eq!(out, ApprovalOutcomePublic::SubmittedOutcomeUnknown);
    assert_ne!(out, ApprovalOutcomePublic::Approved);
}

#[tokio::test(flavor = "multi_thread")]
async fn the_decision_record_says_submitted_outcome_unknown_not_completed() {
    let fx = Fx::new();
    let q = fx.st.queue.clone();
    let waiter = tokio::spawn(async move { q.submit_with_outcome(payment("p3")).await });
    fx.wait_depth(1).await;
    let (s, _) = fx.post("/approvals/approve", unknown_body("p3")).await;
    assert_eq!(s, StatusCode::OK);
    let _ = waiter.await;

    let rows = fx.ceremony_outcomes();
    assert_eq!(rows.len(), 1, "{rows:?}");
    assert_eq!(rows[0].0, Decision::Approved, "the member approved it");
    let (outcome, detail) = rows[0].1.clone().expect("the decision is closed");
    assert_eq!(outcome, Outcome::OutcomeUnknown, "never Completed");
    assert_eq!(detail, format!("Submitted · outcome unknown (tx {HASH})"));
}

#[tokio::test(flavor = "multi_thread")]
async fn an_unknown_outcome_without_a_hash_says_so() {
    let fx = Fx::new();
    let q = fx.st.queue.clone();
    let waiter = tokio::spawn(async move { q.submit_with_resolution(payment("p4")).await });
    fx.wait_depth(1).await;
    // What core sends when the ceremony had no hash: txHash null, its own words.
    let msg = "submitted, outcome unknown, check recent transactions before retrying";
    let (s, v) = fx
        .post(
            "/approvals/approve",
            serde_json::json!({"id": "p4", "outcome": "submitted_outcome_unknown",
                               "txHash": null, "message": msg}),
        )
        .await;
    assert_eq!(s, StatusCode::OK, "{v}");
    match waiter.await.unwrap() {
        citrate_agent_core::hitl::Resolution::SubmittedOutcomeUnknown(u) => {
            assert_eq!(u.message(), msg);
            assert_eq!(u.tx_hash(), None);
        }
        other => panic!("{other:?}"),
    }
    let rows = fx.ceremony_outcomes();
    let (outcome, detail) = rows[0].1.clone().unwrap();
    assert_eq!(outcome, Outcome::OutcomeUnknown);
    assert_eq!(detail, "Submitted · outcome unknown (tx not known)");
}

#[tokio::test(flavor = "multi_thread")]
async fn an_id_only_approve_keeps_todays_behaviour() {
    let fx = Fx::new();
    let q = fx.st.queue.clone();
    let waiter = tokio::spawn(async move { q.submit_with_outcome(payment("p5")).await });
    fx.wait_depth(1).await;
    let (s, v) = fx
        .post("/approvals/approve", serde_json::json!({"id": "p5"}))
        .await;
    assert_eq!(s, StatusCode::OK);
    assert!(v.get("outcome").is_none(), "{v}");
    assert_eq!(waiter.await.unwrap(), ApprovalOutcomePublic::Approved);
    let rows = fx.ceremony_outcomes();
    assert_eq!(rows[0].1.as_ref().unwrap().0, Outcome::Completed);
}

/// Every malformed outcome body is refused with 400 before anything is resolved or recorded.
#[tokio::test(flavor = "multi_thread")]
async fn malformed_outcome_fields_are_refused_and_resolve_nothing() {
    let fx = Fx::new();
    let q = fx.st.queue.clone();
    let waiter = tokio::spawn(async move { q.submit_with_outcome(payment("p6")).await });
    fx.wait_depth(1).await;

    let long = format!("{} {}", core_message(HASH), "x".repeat(400));
    let bad: Vec<(&str, serde_json::Value)> = vec![
        (
            "short hash",
            serde_json::json!({"id":"p6","outcome":"submitted_outcome_unknown","txHash":"0x1234","message":core_message("0x1234")}),
        ),
        (
            "no 0x",
            serde_json::json!({"id":"p6","outcome":"submitted_outcome_unknown","txHash":&HASH[2..],"message":core_message(&HASH[2..])}),
        ),
        (
            "non-hex",
            serde_json::json!({"id":"p6","outcome":"submitted_outcome_unknown","txHash":HASH.replace('a',"g"),"message":core_message(&HASH.replace('a',"g"))}),
        ),
        (
            "hash not a string",
            serde_json::json!({"id":"p6","outcome":"submitted_outcome_unknown","txHash":5,"message":"m"}),
        ),
        (
            "message too long",
            serde_json::json!({"id":"p6","outcome":"submitted_outcome_unknown","txHash":HASH,"message":long}),
        ),
        (
            "empty message",
            serde_json::json!({"id":"p6","outcome":"submitted_outcome_unknown","txHash":HASH,"message":""}),
        ),
        (
            "control chars",
            serde_json::json!({"id":"p6","outcome":"submitted_outcome_unknown","txHash":HASH,"message":format!("{}\n\u{7}", core_message(HASH))}),
        ),
        (
            "message omits the hash",
            serde_json::json!({"id":"p6","outcome":"submitted_outcome_unknown","txHash":HASH,"message":"submitted, outcome unknown, check before retrying"}),
        ),
        (
            "unknown outcome",
            serde_json::json!({"id":"p6","outcome":"completed","txHash":HASH,"message":core_message(HASH)}),
        ),
        (
            "outcome not a string",
            serde_json::json!({"id":"p6","outcome":true}),
        ),
        (
            "hash without outcome",
            serde_json::json!({"id":"p6","txHash":HASH}),
        ),
        (
            "message without outcome",
            serde_json::json!({"id":"p6","message":"anything"}),
        ),
    ];
    for (why, body) in bad {
        let (s, _) = fx.post("/approvals/approve", body).await;
        assert_eq!(s, StatusCode::BAD_REQUEST, "{why} must be refused");
        assert_eq!(fx.st.queue.depth(), 1, "{why} must not resolve the head");
    }
    // An unknown outcome is never a rejection.
    let (s, _) = fx.post("/approvals/reject", unknown_body("p6")).await;
    assert_eq!(s, StatusCode::BAD_REQUEST, "reject carries no outcome");
    assert_eq!(fx.st.queue.depth(), 1);
    assert!(fx.ceremony_outcomes().is_empty(), "nothing was recorded");
    assert!(!waiter.is_finished());

    let (s, _) = fx.post("/approvals/approve", unknown_body("p6")).await;
    assert_eq!(s, StatusCode::OK, "the well-formed body still resolves it");
    let _ = waiter.await;
}

/// No auto-retry: an identical payment proposed again after an unknown outcome parks for the
/// member (even under an auto-grant) and the approval card names the earlier transaction.
#[tokio::test(flavor = "multi_thread")]
async fn a_reproposal_references_the_earlier_tx_and_never_auto_approves() {
    let fx = Fx::new();
    let q = fx.st.queue.clone();
    let first = tokio::spawn(async move { q.submit_with_outcome(payment("p7")).await });
    fx.wait_depth(1).await;
    let (s, _) = fx.post("/approvals/approve", unknown_body("p7")).await;
    assert_eq!(s, StatusCode::OK);
    let _ = first.await;

    // A different payment (same tool, other call) carries no such reference.
    let q = fx.st.queue.clone();
    let other = tokio::spawn(async move { q.submit_with_outcome(payment("p8")).await });
    fx.wait_depth(1).await;
    let cards = fx.get("/approvals").await;
    assert!(
        cards[0].get("priorOutcomeUnknown").is_none(),
        "{}",
        cards[0]
    );
    let (s, _) = fx
        .post("/approvals/reject", serde_json::json!({"id": "p8"}))
        .await;
    assert_eq!(s, StatusCode::OK);
    let _ = other.await;

    // Even a live grant for the tool does not let the identical effect through unattended.
    fx.st.queue.add_grant("pay::eth-send");
    let q = fx.st.queue.clone();
    let again = tokio::spawn(async move { q.submit_with_outcome(payment("p7")).await });
    fx.wait_depth(1).await;
    assert!(!again.is_finished(), "the re-proposal waits for the member");

    let cards = fx.get("/approvals").await;
    let card = &cards[0];
    assert_eq!(card["id"], "p7");
    assert_eq!(card["priorOutcomeUnknown"]["txHash"], HASH, "{card}");
    assert_eq!(card["priorOutcomeUnknown"]["message"], core_message(HASH));
    let summary = card["summary"].as_str().unwrap();
    assert!(
        summary.contains(HASH),
        "the card names the earlier tx: {summary}"
    );
    assert!(summary.contains("outcome unknown"), "{summary}");

    let (s, _) = fx
        .post("/approvals/reject", serde_json::json!({"id": "p7"}))
        .await;
    assert_eq!(s, StatusCode::OK);
    assert_eq!(again.await.unwrap(), ApprovalOutcomePublic::Rejected);
}

// ── Round 2: the outcome survives a failing record and a late callback ────────────────────────

impl Fx {
    /// A records log that refuses every write after the first: each record needs a new segment,
    /// and the directory is made read-only, so creating it fails. `heal` restores the directory.
    fn with_failing_log() -> Self {
        let fx = Fx::new_with(LogConfig {
            max_segment_bytes: 1,
            max_segments: None,
        });
        let log = fx.st.sessions.records().expect("a records log");
        hic_records::record_member_decision(&log, "test.seed", "seed", false, "seed", vec![])
            .expect("the first record fits the open segment");
        fx.set_records_writable(false);
        fx
    }

    fn set_records_writable(&self, writable: bool) {
        use std::os::unix::fs::PermissionsExt;
        let mode = if writable { 0o700 } else { 0o500 };
        std::fs::set_permissions(
            self.root.path().join("records"),
            std::fs::Permissions::from_mode(mode),
        )
        .unwrap();
    }

    /// The ceremony decisions bound to `call_id` (by their evidence), with their closing outcome.
    fn records_for(&self, call_id: &str) -> Vec<(Decision, Option<(Outcome, String)>)> {
        let recs = self.records();
        let uri = format!("sidecar:approval/{call_id}");
        recs.iter()
            .filter_map(|r| match &r.record.entry {
                Entry::Decision(d)
                    if d.kind == "ceremony.capsule_effect"
                        && d.evidence.iter().any(|e| e.uri == uri) =>
                {
                    let seq = r.record.seq;
                    let out = recs.iter().find_map(|o| match &o.record.entry {
                        Entry::Outcome(o) if o.decision_seq == seq => {
                            Some((o.outcome, o.detail.clone()))
                        }
                        _ => None,
                    });
                    Some((d.decision, out))
                }
                _ => None,
            })
            .collect()
    }
}

/// Codex P2 (round 1): the transaction already went out, so a decision record that cannot be
/// written must not hide the outcome. The capsule is told, the tx is remembered, and the route
/// says the record is missing instead of refusing.
#[tokio::test(flavor = "multi_thread")]
async fn an_unknown_outcome_is_delivered_even_when_the_record_cannot_be_written() {
    let fx = Fx::with_failing_log();
    let q = fx.st.queue.clone();
    let waiter = tokio::spawn(async move { q.submit_with_resolution(payment("f1")).await });
    fx.wait_depth(1).await;

    let (s, v) = fx.post("/approvals/approve", unknown_body("f1")).await;
    fx.set_records_writable(true);
    assert_eq!(s, StatusCode::OK, "the outcome is not refused: {v}");
    assert_eq!(v["outcome"], "submitted_outcome_unknown");
    assert_eq!(v["recorded"], false, "the route says the record is missing");
    match tokio::time::timeout(Duration::from_secs(5), waiter)
        .await
        .expect("the waiter is told")
        .unwrap()
    {
        citrate_agent_core::hitl::Resolution::SubmittedOutcomeUnknown(u) => {
            assert_eq!(u.message(), core_message(HASH))
        }
        other => panic!("{other:?}"),
    }
    assert_eq!(
        fx.st
            .queue
            .prior_unknown_outcome("f1")
            .and_then(|u| u.tx_hash().map(str::to_string)),
        Some(HASH.to_string()),
        "an identical re-proposal still names the tx"
    );
}

/// The write-ahead refusal stays for an ordinary approval: nothing is released unrecorded.
#[tokio::test(flavor = "multi_thread")]
async fn an_ordinary_approval_is_still_refused_when_the_record_cannot_be_written() {
    let fx = Fx::with_failing_log();
    let q = fx.st.queue.clone();
    let waiter = tokio::spawn(async move { q.submit_with_outcome(payment("f2")).await });
    fx.wait_depth(1).await;
    let (s, _) = fx
        .post("/approvals/approve", serde_json::json!({"id": "f2"}))
        .await;
    fx.set_records_writable(true);
    assert_eq!(s, StatusCode::SERVICE_UNAVAILABLE);
    assert_eq!(fx.st.queue.depth(), 1, "nothing was released");
    assert!(!waiter.is_finished());
    fx.st.queue.reject_by_id("f2").unwrap();
    let _ = waiter.await;
}

/// Codex P2 (round 1): a callback that arrives after the waiter went away still writes the
/// transaction into the decision log, bound to its call id.
#[tokio::test(flavor = "multi_thread")]
async fn a_late_unknown_outcome_is_recorded_after_the_waiter_is_gone() {
    let fx = Fx::new();
    let q = fx.st.queue.clone();
    let waiter = tokio::spawn(async move { q.submit_with_resolution(payment("l1")).await });
    fx.wait_depth(1).await;
    waiter.abort();
    let _ = waiter.await;
    fx.wait_depth(0).await;

    let (s, _) = fx.post("/approvals/approve", unknown_body("l1")).await;
    assert_eq!(s, StatusCode::CONFLICT, "the capsule was not told");
    let rows = fx.records_for("l1");
    assert_eq!(rows.len(), 1, "one receipt for the submitted tx: {rows:?}");
    assert_eq!(rows[0].0, Decision::Approved);
    let (outcome, detail) = rows[0].1.clone().expect("closed");
    assert_eq!(outcome, Outcome::OutcomeUnknown);
    assert!(detail.contains(HASH), "{detail}");
    assert!(detail.contains("not told"), "{detail}");
    assert!(fx.st.queue.prior_unknown_outcome("l1").is_some());
}

/// A late callback for a call that is no longer pending, while another call is at the head, is
/// recorded for its own id and resolves nothing else.
#[tokio::test(flavor = "multi_thread")]
async fn a_late_unknown_outcome_never_touches_the_current_head() {
    let fx = Fx::new();
    let q = fx.st.queue.clone();
    let other = tokio::spawn(async move { q.submit_with_outcome(payment("h1")).await });
    fx.wait_depth(1).await;

    let (s, _) = fx.post("/approvals/approve", unknown_body("gone")).await;
    assert_eq!(s, StatusCode::CONFLICT);
    assert_eq!(fx.st.queue.depth(), 1, "the head is untouched");
    assert!(!other.is_finished());
    assert!(
        fx.records_for("h1").is_empty(),
        "nothing recorded for the head"
    );
    let rows = fx.records_for("gone");
    assert_eq!(rows.len(), 1, "{rows:?}");
    assert_eq!(
        rows[0].1.as_ref().map(|o| o.0),
        Some(Outcome::OutcomeUnknown)
    );

    let (s, _) = fx
        .post("/approvals/reject", serde_json::json!({"id": "h1"}))
        .await;
    assert_eq!(s, StatusCode::OK);
    assert_eq!(other.await.unwrap(), ApprovalOutcomePublic::Rejected);
}

/// Tripwire: for every state the queue and the log can be in when core's well-formed
/// unknown-outcome callback arrives, the sidecar never refuses it with 503, always remembers the
/// tx, never resolves a different call, and writes a receipt naming the tx whenever the log can
/// be written. A new early return on that path fails one of these rows.
#[tokio::test(flavor = "multi_thread")]
async fn every_unknown_outcome_callback_keeps_the_transaction() {
    #[derive(Debug, Clone, Copy)]
    enum Head {
        Waiting,
        Gone,
        Other,
    }
    #[derive(Debug, Clone, Copy)]
    enum Log {
        Writable,
        Failing,
    }
    for head in [Head::Waiting, Head::Gone, Head::Other] {
        for log in [Log::Writable, Log::Failing] {
            let why = format!("{head:?}/{log:?}");
            let fx = match log {
                Log::Writable => Fx::new(),
                Log::Failing => Fx::with_failing_log(),
            };
            let q = fx.st.queue.clone();
            let id = match head {
                Head::Other => "x-other",
                _ => "x-pay",
            };
            let waiter = tokio::spawn(async move { q.submit_with_resolution(payment(id)).await });
            fx.wait_depth(1).await;
            if let Head::Gone = head {
                waiter.abort();
                fx.wait_depth(0).await;
            }
            let (s, v) = fx.post("/approvals/approve", unknown_body("x-pay")).await;
            fx.set_records_writable(true);
            assert_ne!(s, StatusCode::SERVICE_UNAVAILABLE, "{why}: {v}");
            assert!(
                fx.st.queue.prior_unknown_outcome("x-pay").is_some(),
                "{why}: the tx is remembered"
            );
            match head {
                Head::Waiting => {
                    assert_eq!(s, StatusCode::OK, "{why}");
                    assert!(matches!(
                        waiter.await.unwrap(),
                        citrate_agent_core::hitl::Resolution::SubmittedOutcomeUnknown(_)
                    ));
                }
                Head::Gone => assert_eq!(s, StatusCode::CONFLICT, "{why}"),
                Head::Other => {
                    assert_eq!(s, StatusCode::CONFLICT, "{why}");
                    assert_eq!(fx.st.queue.depth(), 1, "{why}: the other call still waits");
                    fx.st.queue.reject_by_id("x-other").unwrap();
                    let _ = waiter.await;
                }
            }
            let rows = fx.records_for("x-pay");
            match log {
                Log::Writable => {
                    assert_eq!(rows.len(), 1, "{why}: {rows:?}");
                    let (o, d) = rows[0].1.clone().expect("closed");
                    assert_eq!(o, Outcome::OutcomeUnknown, "{why}");
                    assert!(d.contains(HASH), "{why}: {d}");
                }
                Log::Failing => assert!(rows.is_empty(), "{why}: nothing could be written"),
            }
        }
    }
}
