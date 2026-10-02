//! HUP-S2.3: the sign-in bridge routes and the web-signing decision records route. The browser
//! here has no Chromium, so these run anywhere; the real-Chromium bridge is covered in
//! agent-browser's live tests.

use super::*;
use axum::body::Body;
use axum::http::{Request, StatusCode};
use citrate_agent_browser::{BrowserConfig, BrowserService};
use citrate_agent_loop::{AssistantTurn, CompletionRequest, LlmClient, LlmError};
use citrate_agent_records::{DecisionLog, LogConfig};
use signin_routes::{fold_taint, TaintView};
use std::path::PathBuf;
use std::time::Duration;
use tower::ServiceExt;
use web_signing_records::{to_events, write_records, CoreRecord};

fn bearer() -> String {
    format!("signin-route-test-{}", "b".repeat(16))
}

struct Idle;
impl LlmClient for Idle {
    fn complete(&self, _req: &CompletionRequest) -> Result<AssistantTurn, LlmError> {
        Ok(AssistantTurn::text("(done)"))
    }
}

fn state(browser: bool) -> Arc<AppState> {
    let mut mgr = sessions::SessionManager::new(
        Arc::new(|_ep: &sessions::LlmEndpoint| Arc::new(Idle) as Arc<dyn LlmClient>),
        Duration::from_secs(5),
    );
    if browser {
        mgr = mgr.with_browser(Arc::new(BrowserService::new(BrowserConfig {
            managed_path: Some(PathBuf::from("/nonexistent/citrate/chromium")),
            candidates: Vec::new(),
            ..BrowserConfig::default()
        })));
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

async fn call(
    st: &Arc<AppState>,
    method: &str,
    path: &str,
    body: serde_json::Value,
    auth: bool,
) -> (StatusCode, serde_json::Value) {
    let mut b = Request::builder()
        .method(method)
        .uri(path)
        .header("content-type", "application/json");
    if auth {
        b = b.header("authorization", format!("Bearer {}", bearer()));
    }
    let r = app(st.clone())
        .oneshot(b.body(Body::from(body.to_string())).expect("request"))
        .await
        .expect("response");
    let status = r.status();
    let bytes = axum::body::to_bytes(r.into_body(), 1 << 20)
        .await
        .unwrap_or_default();
    (
        status,
        serde_json::from_slice(&bytes).unwrap_or(serde_json::Value::Null),
    )
}

// ---- taint (ADR D2 #19, computed from the sessions, never from the caller) ----

#[test]
fn taint_folds_sessions_and_the_pages_the_model_read() {
    assert_eq!(fold_taint(None, &[]), TaintView::Unknown);
    assert_eq!(
        fold_taint(Some(vec![]), &["https://a.example".into()]),
        TaintView::Clean
    );
    assert_eq!(
        fold_taint(
            Some(vec![vec!["browser_snapshot".into()]]),
            &["https://a.example".into()]
        ),
        TaintView::Sources {
            sources: vec!["https://a.example".into()]
        }
    );
    assert_eq!(
        fold_taint(Some(vec![vec!["browser_navigate".into()]]), &[]),
        TaintView::Sources {
            sources: vec!["ext:browser".into()]
        },
        "a browser source with no recorded page is never read as clean"
    );
    assert_eq!(
        fold_taint(
            Some(vec![
                vec!["browser_snapshot".into()],
                vec!["mcp__notes__read".into()]
            ]),
            &["https://a.example".into()]
        ),
        TaintView::Sources {
            sources: vec!["ext:mcp__notes__read".into(), "https://a.example".into()]
        },
        "another session's MCP output counts too"
    );
    assert_eq!(
        fold_taint(Some(vec![vec![]]), &[]),
        TaintView::Unknown,
        "a tainted session that names no source is unknown"
    );
}

#[tokio::test(flavor = "multi_thread")]
async fn sign_in_routes_need_the_bearer_and_the_browser() {
    let st = state(true);
    let (s, _) = call(
        &st,
        "GET",
        "/browser/sign-in",
        serde_json::Value::Null,
        false,
    )
    .await;
    assert_eq!(s, StatusCode::UNAUTHORIZED);
    let (s, _) = call(
        &st,
        "POST",
        "/browser/sign-in/answer",
        serde_json::json!({}),
        false,
    )
    .await;
    assert_eq!(s, StatusCode::UNAUTHORIZED);
    let off = state(false);
    let (s, _) = call(
        &off,
        "GET",
        "/browser/sign-in",
        serde_json::Value::Null,
        true,
    )
    .await;
    assert_eq!(s, StatusCode::NOT_FOUND, "the browser is off by default");
    let (s, _) = call(
        &off,
        "POST",
        "/browser/sign-in/answer",
        serde_json::json!({"id": "x", "refused": {"code": 4001, "message": "no"}}),
        true,
    )
    .await;
    assert_eq!(s, StatusCode::NOT_FOUND);
}

#[tokio::test(flavor = "multi_thread")]
async fn the_sign_in_list_reports_taint_from_live_sessions() {
    let st = state(true);
    let (s, v) = call(
        &st,
        "GET",
        "/browser/sign-in",
        serde_json::Value::Null,
        true,
    )
    .await;
    assert_eq!(s, StatusCode::OK, "{v}");
    assert_eq!(v["requests"], serde_json::json!([]));
    assert_eq!(v["taint"]["state"], "clean");
    assert_eq!(
        v["devtoolsPort"],
        serde_json::Value::Null,
        "no browser running"
    );

    let (s, created) = call(
        &st,
        "POST",
        "/sessions",
        serde_json::json!({
            "model": "m", "systemPrompt": "x", "tools": [],
            "llm": {"baseUrl": "http://127.0.0.1:18080/v1", "bearer": "k"},
        }),
        true,
    )
    .await;
    assert_eq!(s, StatusCode::CREATED, "{created}");
    let id = created["id"].as_str().unwrap_or_default().to_string();
    let sess = st.sessions.get(&id).expect("session");
    sess.taint().taint("browser_snapshot", "a page");
    let (_, v) = call(
        &st,
        "GET",
        "/browser/sign-in",
        serde_json::Value::Null,
        true,
    )
    .await;
    assert_eq!(v["taint"]["state"], "sources");
    assert_eq!(v["taint"]["sources"], serde_json::json!(["ext:browser"]));
    sess.taint().taint("mcp__x__y", "mcp");
    let (_, v) = call(
        &st,
        "GET",
        "/browser/sign-in",
        serde_json::Value::Null,
        true,
    )
    .await;
    assert_eq!(
        v["taint"]["sources"],
        serde_json::json!(["ext:browser", "ext:mcp__x__y"])
    );
}

#[tokio::test(flavor = "multi_thread")]
async fn an_answer_is_exactly_one_kind_and_for_a_waiting_request() {
    let st = state(true);
    for body in [
        serde_json::json!({"id": "signin-1"}),
        serde_json::json!({"id": "signin-1", "signature": "0x00", "refused": {"code": 4001, "message": "x"}}),
        serde_json::json!({"id": "", "refused": {"code": 4001, "message": "x"}}),
        serde_json::json!({"id": "signin-1", "extra": true, "refused": {"code": 4001, "message": "x"}}),
    ] {
        let (s, v) = call(&st, "POST", "/browser/sign-in/answer", body.clone(), true).await;
        assert_eq!(s, StatusCode::BAD_REQUEST, "{body} -> {v}");
    }
    let (s, v) = call(
        &st,
        "POST",
        "/browser/sign-in/answer",
        serde_json::json!({"id": "signin-1", "refused": {"code": 4001, "message": "no"}}),
        true,
    )
    .await;
    assert_eq!(s, StatusCode::CONFLICT, "nothing is waiting: {v}");
}

// ---- web-signing decision records (US-2.3 AC3) ----

fn h(c: char) -> String {
    format!("0x{}", c.to_string().repeat(64))
}

fn signed(id: u64) -> CoreRecord {
    CoreRecord {
        record_id: id,
        kind: "auto_sign".into(),
        status: "signed".into(),
        origin: "https://app.example.org".into(),
        budget_id: Some(3),
        payload_digest: Some(h('a')),
        nonce: Some("abcdefgh12345678".into()),
        statement: Some("Sign in to Example".into()),
        signer_address: Some("0x00000000000000000000000000000000000000a1".into()),
        at_ms: 1_790_000_000_000,
        hash: h('b'),
    }
}

#[test]
fn a_budgeted_sign_in_becomes_an_hic2_decision_with_its_outcome() {
    let (actor, d, outcome, _) = to_events(&signed(12)).expect("valid");
    assert_eq!(actor.kind, citrate_agent_records::ActorKind::Agent);
    assert_eq!(d.tier, citrate_agent_records::HicTier::Hic2);
    assert_eq!(d.kind, "siwe");
    assert_eq!(
        d.decision,
        citrate_agent_records::Decision::AutoWithinBudget
    );
    assert_eq!(outcome, citrate_agent_records::Outcome::Completed);
    assert_eq!(d.subject, "https://app.example.org");
    let rec = d
        .evidence
        .iter()
        .find(|e| e.kind == "web_budget_record")
        .expect("core's record");
    assert_eq!(rec.uri, "citrate-core:web-budget/record/12");
    assert_eq!(rec.digest.as_deref(), Some(h('b').as_str()));
    assert!(d.evidence.iter().any(
        |e| e.kind == "siwe_payload_keccak256" && e.digest.as_deref() == Some(h('a').as_str())
    ));
    assert!(d.reason.contains("Sign in to Example"));

    let mut unknown = signed(13);
    unknown.status = "outcome_unknown".into();
    assert_eq!(
        to_events(&unknown).expect("valid").2,
        citrate_agent_records::Outcome::OutcomeUnknown,
        "never reported as not signed"
    );
    let mut grant = signed(14);
    grant.kind = "budget_granted".into();
    grant.status = "final".into();
    grant.payload_digest = None;
    let (actor, d, _, _) = to_events(&grant).expect("valid");
    assert_eq!(actor.kind, citrate_agent_records::ActorKind::Member);
    assert_eq!(d.tier, citrate_agent_records::HicTier::Hic1);
    assert_eq!(d.decision, citrate_agent_records::Decision::Approved);
}

#[test]
fn malformed_or_still_reserved_records_are_refused() {
    let mut r = signed(1);
    r.status = "reserved".into();
    assert!(
        to_events(&r).is_err(),
        "an open reservation is not exported"
    );
    let mut r = signed(1);
    r.payload_digest = None;
    assert!(to_events(&r).is_err());
    let mut r = signed(1);
    r.hash = "0x12".into();
    assert!(to_events(&r).is_err());
    let mut r = signed(1);
    r.kind = "transaction".into();
    assert!(to_events(&r).is_err(), "only the closed list");
    let mut r = signed(1);
    r.kind = "budget_revoked".into();
    assert!(to_events(&r).is_err(), "a member decision must be final");
}

#[test]
fn records_are_written_all_or_nothing_and_verify() {
    let dir = tempfile::tempdir().expect("tempdir");
    let (log, _) = DecisionLog::open(dir.path(), LogConfig::default()).expect("log");
    let mut bad = signed(2);
    bad.hash = "nope".into();
    assert!(write_records(&log, &[signed(1), bad]).is_err());
    assert_eq!(log.verify().expect("verifies").count, 0, "nothing written");

    let last = write_records(&log, &[signed(1), signed(2)]).expect("written");
    assert_eq!(last, Some(3), "two decisions and two outcomes: seq 0..=3");
    let rep = log.verify().expect("verifies");
    assert_eq!(rep.count, 4);
    assert!(
        rep.open_decisions.is_empty(),
        "every decision has its outcome"
    );
    let too_many: Vec<CoreRecord> = (0..101).map(signed).collect();
    assert!(write_records(&log, &too_many).is_err());
}

#[tokio::test(flavor = "multi_thread")]
async fn the_records_route_needs_the_bearer_and_a_configured_folder() {
    let st = state(false);
    let (s, _) = call(
        &st,
        "POST",
        "/records/web-signing",
        serde_json::json!({"records": []}),
        false,
    )
    .await;
    assert_eq!(s, StatusCode::UNAUTHORIZED);
    if std::env::var(anchor::RECORDS_DIR_ENV).is_err() {
        let (s, v) = call(
            &st,
            "POST",
            "/records/web-signing",
            serde_json::json!({"records": []}),
            true,
        )
        .await;
        assert_eq!(s, StatusCode::NOT_FOUND, "{v}");
    }
}
