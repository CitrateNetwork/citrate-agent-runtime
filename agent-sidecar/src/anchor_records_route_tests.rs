//! HUP-S7.3 (US-7.2 AC3): the decision list the member picks a record from to prove, and the
//! proof route's check that the retained record really is the proven leaf. Read-only routes; the
//! sidecar still never signs or sends.

use super::*;
use axum::body::Body;
use axum::http::{Request, StatusCode};
use citrate_agent_records::{
    Actor, Clock, Decision, DecisionEvent, DecisionLog, HicTier, LogConfig, Outcome, OutcomeEvent,
};
use std::sync::atomic::{AtomicU64, Ordering};
use std::time::Duration;
use tower::ServiceExt;

const DAY: u64 = 86_400_000;

fn bearer() -> String {
    // Built at runtime so no credential-looking literal sits in the source.
    ["anchor", "records", "route", "tests"].join("-")
}

struct TestClock(AtomicU64);
impl Clock for TestClock {
    fn now_ms(&self) -> u64 {
        self.0.load(Ordering::SeqCst)
    }
}

fn today() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_millis() as u64)
        .unwrap_or(0)
        / DAY
}

/// Day `d0`: one approved decision closed by its outcome, then one denied decision.
/// Day `d0 + 1`: one denied decision. Seqs 0..=3.
fn write_records(dir: &std::path::Path, d0: u64) {
    let c = Arc::new(TestClock(AtomicU64::new(d0 * DAY + 10)));
    let (log, _) = DecisionLog::open_with_clock(dir, LogConfig::default(), c.clone()).unwrap();
    let ev = |subject: &str, decision: Decision| DecisionEvent {
        tier: HicTier::Hic1,
        kind: "tx".into(),
        subject: subject.into(),
        decision,
        reason: "test".into(),
        evidence: vec![],
    };
    let r = log
        .record_decision(Actor::member("m1"), ev("send 1 SALT", Decision::Approved))
        .unwrap();
    log.record_outcome(
        Actor::agent("hermes"),
        OutcomeEvent {
            decision_seq: r.seq,
            outcome: Outcome::Completed,
            detail: "mined".into(),
        },
    )
    .unwrap();
    log.record_decision(Actor::member("m1"), ev("deploy", Decision::Denied))
        .unwrap();
    c.0.store((d0 + 1) * DAY + 10, Ordering::SeqCst);
    log.record_decision(Actor::member("m1"), ev("next day", Decision::Denied))
        .unwrap();
}

fn state(anchor: Option<anchor::AnchorService>) -> Arc<AppState> {
    let mut mgr = sessions::SessionManager::new(
        Arc::new(
            |_ep: &sessions::LlmEndpoint| -> Arc<dyn citrate_agent_loop::LlmClient> {
                unreachable!("no session in these tests")
            },
        ),
        Duration::from_secs(5),
    );
    if let Some(a) = anchor {
        mgr = mgr.with_anchor(Arc::new(a));
    }
    Arc::new(AppState {
        estop: EmergencyStop::new(),
        queue: Arc::new(ApprovalQueue::new()),
        skills: vec![],
        dispatch: None,
        bearer: bearer(),
        run_slots: Arc::new(tokio::sync::Semaphore::new(MAX_CONCURRENT_SKILLS)),
        sessions: Arc::new(mgr),
    })
}

fn req(method: &str, path: &str, body: serde_json::Value, auth: bool) -> Request<Body> {
    let mut b = Request::builder()
        .method(method)
        .uri(path)
        .header("content-type", "application/json");
    if auth {
        b = b.header("authorization", format!("Bearer {}", bearer()));
    }
    b.body(Body::from(body.to_string())).unwrap()
}

async fn call(
    st: &Arc<AppState>,
    method: &str,
    path: &str,
    body: serde_json::Value,
) -> (StatusCode, serde_json::Value) {
    let r = app(st.clone())
        .oneshot(req(method, path, body, true))
        .await
        .unwrap();
    let s = r.status();
    let bytes = axum::body::to_bytes(r.into_body(), 1 << 20).await.unwrap();
    (
        s,
        serde_json::from_slice(&bytes).unwrap_or(serde_json::Value::Null),
    )
}

struct Fixture {
    _records: tempfile::TempDir,
    _ledger: tempfile::TempDir,
    st: Arc<AppState>,
}

fn fixture(d0: u64) -> Fixture {
    let records = tempfile::tempdir().unwrap();
    let ledger = tempfile::tempdir().unwrap();
    write_records(records.path(), d0);
    let svc = anchor::AnchorService::open(records.path(), ledger.path()).unwrap();
    Fixture {
        st: state(Some(svc)),
        _records: records,
        _ledger: ledger,
    }
}

fn seqs(v: &serde_json::Value) -> Vec<u64> {
    v["records"]
        .as_array()
        .unwrap()
        .iter()
        .map(|r| r["seq"].as_u64().unwrap())
        .collect()
}

#[tokio::test]
async fn the_record_list_is_newest_first_with_each_days_anchor_state() {
    let d0 = today() - 3;
    let f = fixture(d0);
    let (_, p) = call(
        &f.st,
        "POST",
        "/anchor/plan",
        serde_json::json!({ "day": d0 }),
    )
    .await;
    assert_eq!(p["plan"], "ready", "{p}");
    let tx = format!("0x{}", "cd".repeat(32));
    let (s, _) = call(
        &f.st,
        "POST",
        "/anchor/confirm",
        serde_json::json!({ "day": d0, "commitment": p["commitment"], "txHash": tx, "blockNumber": 9 }),
    )
    .await;
    assert_eq!(s, StatusCode::OK);

    let (s, v) = call(&f.st, "GET", "/anchor/records", serde_json::Value::Null).await;
    assert_eq!(s, StatusCode::OK, "{v}");
    assert_eq!(v["configured"], true);
    assert_eq!(seqs(&v), vec![3, 2, 1, 0]);
    let r3 = &v["records"][0];
    assert_eq!(r3["day"], d0 + 1);
    assert_eq!(r3["date"].as_str().unwrap().len(), 10);
    assert_eq!(r3["batched"], false);
    assert_eq!(r3["anchored"], false);
    assert!(r3["anchorTx"].is_null());
    assert_eq!(r3["record"]["entry"]["decision"]["subject"], "next day");
    let r0 = &v["records"][3];
    assert_eq!(r0["day"], d0);
    assert_eq!(r0["batched"], true);
    assert_eq!(r0["anchored"], true);
    assert_eq!(r0["anchorTx"], tx);
    assert_eq!(r0["anchorBlock"], 9);
    assert_eq!(r0["hash"].as_str().unwrap().len(), 64);
    // An outcome is listed as its own record, naming the decision it closes.
    let r1 = &v["records"][2];
    assert_eq!(r1["record"]["entry"]["outcome"]["decision_seq"], 0);
}

#[tokio::test]
async fn the_record_list_pages_with_before_and_a_capped_limit() {
    let f = fixture(today() - 3);
    let (_, v) = call(
        &f.st,
        "GET",
        "/anchor/records?before=3&limit=2",
        serde_json::Value::Null,
    )
    .await;
    assert_eq!(seqs(&v), vec![2, 1]);
    assert_eq!(v["nextBefore"], 1);
    let (_, v) = call(
        &f.st,
        "GET",
        "/anchor/records?before=1&limit=5",
        serde_json::Value::Null,
    )
    .await;
    assert_eq!(seqs(&v), vec![0]);
    assert!(v["nextBefore"].is_null(), "the last page has no next page");
    let (s, v) = call(
        &f.st,
        "GET",
        "/anchor/records?limit=100000",
        serde_json::Value::Null,
    )
    .await;
    assert_eq!(s, StatusCode::OK);
    assert_eq!(v["limit"], anchor::MAX_RECORDS_PAGE);
}

#[tokio::test]
async fn the_record_list_needs_the_bearer_and_an_anchor_store() {
    let f = fixture(today() - 3);
    let r = app(f.st.clone())
        .oneshot(req("GET", "/anchor/records", serde_json::json!({}), false))
        .await
        .unwrap();
    assert_eq!(r.status(), StatusCode::UNAUTHORIZED);
    let (s, _) = call(
        &state(None),
        "GET",
        "/anchor/records",
        serde_json::Value::Null,
    )
    .await;
    assert_eq!(s, StatusCode::SERVICE_UNAVAILABLE);
    // No records folder yet: an empty list, said honestly.
    let records = tempfile::tempdir().unwrap();
    let ledger = tempfile::tempdir().unwrap();
    let svc = anchor::AnchorService::open(&records.path().join("none"), ledger.path()).unwrap();
    let (s, v) = call(
        &state(Some(svc)),
        "GET",
        "/anchor/records",
        serde_json::Value::Null,
    )
    .await;
    assert_eq!(s, StatusCode::OK, "{v}");
    assert_eq!(v["recordsPresent"], false);
    assert_eq!(v["records"].as_array().unwrap().len(), 0);
}

#[tokio::test]
async fn a_proof_checks_the_retained_record_against_its_leaf() {
    let d0 = today() - 3;
    let f = fixture(d0);
    let (_, p) = call(
        &f.st,
        "POST",
        "/anchor/plan",
        serde_json::json!({ "day": d0 }),
    )
    .await;
    assert_eq!(p["plan"], "ready");
    let (s, pr) = call(&f.st, "GET", "/anchor/proof?seq=2", serde_json::Value::Null).await;
    assert_eq!(s, StatusCode::OK, "{pr}");
    assert_eq!(pr["verifies"], true);
    assert_eq!(pr["recordMatches"], true);
    assert_eq!(pr["record"]["seq"], 2);
    assert_eq!(pr["record"]["entry"]["decision"]["subject"], "deploy");
    // The proof's leaf is the record's own hash.
    assert_eq!(pr["proof"]["record_hash"], pr["recordHash"]);
    // The exact hashed bytes travel too, so core can bind the content to the leaf itself:
    // SHA-256("citrate.agent-records.v1\n" || canonical) is the leaf.
    let canonical = pr["recordCanonical"].as_str().unwrap();
    use sha2::{Digest, Sha256};
    let mut h = Sha256::new();
    h.update(b"citrate.agent-records.v1\n");
    h.update(canonical.as_bytes());
    assert_eq!(
        hex::encode(h.finalize()),
        pr["recordHash"].as_str().unwrap()
    );
    let parsed: serde_json::Value = serde_json::from_str(canonical).unwrap();
    assert_eq!(parsed, pr["record"]);
}

#[tokio::test]
async fn a_batched_day_is_not_anchored_until_core_confirms_it() {
    let d0 = today() - 3;
    let f = fixture(d0);
    let (_, p) = call(
        &f.st,
        "POST",
        "/anchor/plan",
        serde_json::json!({ "day": d0 }),
    )
    .await;
    assert_eq!(p["plan"], "ready");
    let (_, v) = call(&f.st, "GET", "/anchor/records", serde_json::Value::Null).await;
    let r0 = &v["records"][3];
    assert_eq!(r0["seq"], 0);
    assert_eq!(r0["batched"], true);
    assert_eq!(r0["anchored"], false);
    assert!(r0["anchorTx"].is_null());
    assert!(r0["anchorBlock"].is_null());
}
