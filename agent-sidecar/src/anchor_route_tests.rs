//! HUP-S7.3 sidecar routes over `citrate-agent-anchor`: status, plan (unsigned calldata only),
//! confirm (written back only with the batched commitment), and inclusion proofs. The sidecar
//! never signs or sends; core's ceremony does, with the anchor key.

use super::*;
use axum::body::Body;
use axum::http::{Request, StatusCode};
use citrate_agent_records::{
    Actor, Clock, Decision, DecisionEvent, DecisionLog, HicTier, LogConfig,
};
use std::sync::atomic::{AtomicU64, Ordering};
use std::time::Duration;
use tower::ServiceExt;

const BEARER: &str = "test-bearer-token-anchor-0001";
const DAY: u64 = 86_400_000;
const REGISTRY: &str = "0x00000000000000000000000000000000000000a1";

struct TestClock(AtomicU64);
impl Clock for TestClock {
    fn now_ms(&self) -> u64 {
        self.0.load(Ordering::SeqCst)
    }
}

fn now_ms() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap()
        .as_millis() as u64
}

fn today() -> u64 {
    now_ms() / DAY
}

/// `per_day[i]` decision records on day `first_day + i`.
fn write_records(dir: &std::path::Path, first_day: u64, per_day: &[u64]) {
    let c = Arc::new(TestClock(AtomicU64::new(first_day * DAY)));
    let (log, _) = DecisionLog::open_with_clock(dir, LogConfig::default(), c.clone()).unwrap();
    for (i, n) in per_day.iter().enumerate() {
        c.0.store((first_day + i as u64) * DAY + 5, Ordering::SeqCst);
        for k in 0..*n {
            log.record_decision(
                Actor::member("m1"),
                DecisionEvent {
                    tier: HicTier::Hic1,
                    kind: "tx".into(),
                    subject: format!("d{i}-r{k}"),
                    decision: Decision::Denied,
                    reason: "test".into(),
                    evidence: vec![],
                },
            )
            .unwrap();
        }
    }
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
        bearer: BEARER.to_string(),
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
        b = b.header("authorization", format!("Bearer {BEARER}"));
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

fn fixture(first_day: u64, per_day: &[u64]) -> Fixture {
    let records = tempfile::tempdir().unwrap();
    let ledger = tempfile::tempdir().unwrap();
    write_records(records.path(), first_day, per_day);
    let svc = anchor::AnchorService::open(records.path(), ledger.path()).unwrap();
    Fixture {
        st: state(Some(svc)),
        _records: records,
        _ledger: ledger,
    }
}

#[tokio::test]
async fn status_without_an_anchor_store_says_so() {
    let st = state(None);
    let (s, v) = call(&st, "GET", "/anchor/status", serde_json::Value::Null).await;
    assert_eq!(s, StatusCode::OK);
    assert_eq!(v["configured"], false);
    assert!(v["reason"].as_str().unwrap().contains("not configured"));
    let (s, _) = call(
        &st,
        "POST",
        "/anchor/plan",
        serde_json::json!({ "day": today() - 1 }),
    )
    .await;
    assert_eq!(s, StatusCode::SERVICE_UNAVAILABLE);
}

#[tokio::test]
async fn anchor_routes_need_the_bearer() {
    let f = fixture(today() - 2, &[1]);
    for (m, p) in [
        ("GET", "/anchor/status"),
        ("POST", "/anchor/plan"),
        ("POST", "/anchor/confirm"),
        ("GET", "/anchor/proof?seq=1"),
    ] {
        let r = app(f.st.clone())
            .oneshot(req(m, p, serde_json::json!({}), false))
            .await
            .unwrap();
        assert_eq!(r.status(), StatusCode::UNAUTHORIZED, "{m} {p}");
    }
}

#[tokio::test]
async fn an_empty_records_directory_has_nothing_pending() {
    let records = tempfile::tempdir().unwrap();
    let ledger = tempfile::tempdir().unwrap();
    let missing = records.path().join("not-created-yet");
    let svc = anchor::AnchorService::open(&missing, ledger.path()).unwrap();
    let st = state(Some(svc));
    let (s, v) = call(&st, "GET", "/anchor/status", serde_json::Value::Null).await;
    assert_eq!(s, StatusCode::OK, "{v}");
    assert_eq!(v["configured"], true);
    assert_eq!(v["recordsPresent"], false);
    assert_eq!(v["pendingDays"].as_array().unwrap().len(), 0);
}

#[tokio::test]
async fn plan_then_confirm_marks_a_day_anchored_only_with_its_own_commitment() {
    let d0 = today() - 3;
    let f = fixture(d0, &[3, 2]);
    let (_, v) = call(&f.st, "GET", "/anchor/status", serde_json::Value::Null).await;
    let pending: Vec<u64> = v["pendingDays"]
        .as_array()
        .unwrap()
        .iter()
        .map(|d| d["day"].as_u64().unwrap())
        .collect();
    assert_eq!(pending, vec![d0, d0 + 1]);
    assert_eq!(v["pendingDays"][0]["date"].as_str().unwrap().len(), 10);

    // plan day d0: unsigned calldata for anchor(NightlyMerkle, commitment), nothing sent
    let (s, p) = call(
        &f.st,
        "POST",
        "/anchor/plan",
        serde_json::json!({ "day": d0, "registry": REGISTRY }),
    )
    .await;
    assert_eq!(s, StatusCode::OK, "{p}");
    assert_eq!(p["plan"], "ready");
    assert_eq!(p["header"]["count"], 3);
    let commitment = p["commitment"].as_str().unwrap().to_string();
    assert_eq!(p["call"]["to"], REGISTRY);
    assert_eq!(p["call"]["chain_id"], 40204);
    assert_eq!(p["call"]["value"], 0);
    assert_eq!(p["call"]["kind"], "nightly_merkle");
    let data = p["call"]["data"].as_str().unwrap();
    assert!(data.starts_with("0x9e621f4c"), "{data}");
    assert!(data.ends_with(commitment.trim_start_matches("0x")));
    assert_eq!(p["sent"], false);

    // the day is now awaiting confirmation, not anchored
    let (_, v) = call(&f.st, "GET", "/anchor/status", serde_json::Value::Null).await;
    assert_eq!(v["awaitingConfirmation"][0]["day"], d0);
    assert_eq!(v["anchored"].as_array().unwrap().len(), 0);

    // a confirmation that names another commitment is refused and changes nothing
    let tx = format!("0x{}", "ab".repeat(32));
    let wrong = format!("0x{}", "00".repeat(32));
    let (s, _) = call(
        &f.st,
        "POST",
        "/anchor/confirm",
        serde_json::json!({ "day": d0, "commitment": wrong, "txHash": tx, "blockNumber": 77 }),
    )
    .await;
    assert_eq!(s, StatusCode::CONFLICT);
    // a malformed tx hash is refused
    let (s, _) = call(
        &f.st,
        "POST",
        "/anchor/confirm",
        serde_json::json!({ "day": d0, "commitment": commitment, "txHash": "0x12", "blockNumber": 77 }),
    )
    .await;
    assert_eq!(s, StatusCode::BAD_REQUEST);

    let (s, c) = call(
        &f.st,
        "POST",
        "/anchor/confirm",
        serde_json::json!({ "day": d0, "commitment": commitment, "txHash": tx, "blockNumber": 77 }),
    )
    .await;
    assert_eq!(s, StatusCode::OK, "{c}");
    assert_eq!(c["recorded"], "new");
    let (_, v) = call(&f.st, "GET", "/anchor/status", serde_json::Value::Null).await;
    assert_eq!(v["anchored"][0]["day"], d0);
    assert_eq!(v["anchored"][0]["txHash"], tx);
    assert_eq!(v["anchored"][0]["blockNumber"], 77);

    // planning an anchored day again reports it, never a second call
    let (_, p2) = call(
        &f.st,
        "POST",
        "/anchor/plan",
        serde_json::json!({ "day": d0, "registry": REGISTRY }),
    )
    .await;
    assert_eq!(p2["plan"], "already_anchored");
    assert!(p2.get("call").is_none() || p2["call"].is_null());
}

#[tokio::test]
async fn confirming_a_day_that_was_never_batched_is_refused() {
    let d0 = today() - 2;
    let f = fixture(d0, &[1]);
    let (s, _) = call(
        &f.st,
        "POST",
        "/anchor/confirm",
        serde_json::json!({
            "day": d0,
            "commitment": format!("0x{}", "11".repeat(32)),
            "txHash": format!("0x{}", "ab".repeat(32)),
            "blockNumber": 1
        }),
    )
    .await;
    assert_eq!(s, StatusCode::CONFLICT);
}

#[tokio::test]
async fn the_open_day_is_never_planned_and_a_bad_registry_is_refused() {
    let f = fixture(today() - 1, &[1]);
    let (s, _) = call(
        &f.st,
        "POST",
        "/anchor/plan",
        serde_json::json!({ "day": today() }),
    )
    .await;
    assert_eq!(s, StatusCode::UNPROCESSABLE_ENTITY);
    let (s, _) = call(
        &f.st,
        "POST",
        "/anchor/plan",
        serde_json::json!({ "day": today() - 1, "registry": "0xnot-an-address" }),
    )
    .await;
    assert_eq!(s, StatusCode::BAD_REQUEST);
}

#[tokio::test]
async fn a_day_with_no_records_plans_as_empty() {
    let f = fixture(today() - 3, &[1]);
    let (s, p) = call(
        &f.st,
        "POST",
        "/anchor/plan",
        serde_json::json!({ "day": today() - 2 }),
    )
    .await;
    assert_eq!(s, StatusCode::OK);
    assert_eq!(p["plan"], "empty");
}

#[tokio::test]
async fn a_proof_verifies_against_the_planned_commitment() {
    let d0 = today() - 2;
    let f = fixture(d0, &[4]);
    // before the day is batched there is no proof
    let (s, _) = call(&f.st, "GET", "/anchor/proof?seq=2", serde_json::Value::Null).await;
    assert_eq!(s, StatusCode::CONFLICT);
    let (_, p) = call(
        &f.st,
        "POST",
        "/anchor/plan",
        serde_json::json!({ "day": d0 }),
    )
    .await;
    assert_eq!(p["plan"], "ready");
    assert!(p["call"]["to"].is_null(), "no registry was given");
    let (s, pr) = call(&f.st, "GET", "/anchor/proof?seq=2", serde_json::Value::Null).await;
    assert_eq!(s, StatusCode::OK, "{pr}");
    assert_eq!(pr["verifies"], true);
    assert_eq!(pr["commitment"], p["commitment"]);
    let proof: citrate_agent_anchor::AnchorProof =
        serde_json::from_value(pr["proof"].clone()).unwrap();
    let mut root = [0u8; 32];
    hex::decode_to_slice(
        p["commitment"].as_str().unwrap().trim_start_matches("0x"),
        &mut root,
    )
    .unwrap();
    assert!(citrate_agent_anchor::verify_proof(&proof, &root));
    // an unknown seq has no proof
    let (s, _) = call(
        &f.st,
        "GET",
        "/anchor/proof?seq=999",
        serde_json::Value::Null,
    )
    .await;
    assert_eq!(s, StatusCode::NOT_FOUND);
}

#[test]
fn the_anchor_store_reads_only_explicit_absolute_directories() {
    assert!(anchor::AnchorPaths::from_values(None, None).is_none());
    assert!(anchor::AnchorPaths::from_values(Some("/tmp/r"), None).is_none());
    assert!(anchor::AnchorPaths::from_values(Some("rel"), Some("/tmp/a")).is_none());
    assert!(anchor::AnchorPaths::from_values(Some(""), Some("/tmp/a")).is_none());
    let p = anchor::AnchorPaths::from_values(Some("/tmp/r"), Some("/tmp/a")).unwrap();
    assert_eq!(p.records_dir, std::path::PathBuf::from("/tmp/r"));
    assert_eq!(p.anchor_dir, std::path::PathBuf::from("/tmp/a"));
}
