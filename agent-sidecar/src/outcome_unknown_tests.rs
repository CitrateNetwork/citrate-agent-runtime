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
        let root = tempfile::tempdir().unwrap();
        let (log, _) =
            DecisionLog::open(&root.path().join("records"), LogConfig::default()).unwrap();
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
