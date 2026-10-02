//! HUP-S2.6 (US-7.2 AC1): local decision records for every HIC-1/2 event, in the one records
//! directory the nightly anchor (HUP-S7.3) batches.
//!
//! BDD map:
//! - Ceremony bridge (`/approvals/approve`, `/approvals/reject`, the sidecar's resolve path):
//!   `ceremony_bridge_resolves_are_recorded_and_anchored`.
//! - A browser action decided by the member: `browser_action_decisions_are_recorded`.
//! - Core's events (folder-grant changes, full-access confirmations, escalation spend, ceremony
//!   and session tool approvals) over `POST /records/core`:
//!   `core_events_become_records_the_anchor_batches_and_proves`,
//!   `a_malformed_core_batch_writes_nothing`, `core_records_need_the_bearer_and_a_records_dir`.
//! - Learn accept and reject go to the same directory: `learn_decisions_land_in_the_records_dir`.
//! - Budgeted SIWE keeps its own route (`/records/web-signing`) into the same log:
//!   `web_signing_and_core_records_share_one_chain`.

use super::*;
use axum::body::Body;
use axum::http::{Request, StatusCode};
use citrate_agent_browser::{BrowserConfig, BrowserService};
use citrate_agent_loop::{AssistantTurn, CompletionRequest, LlmClient, LlmError};
use citrate_agent_records::{Decision, DecisionLog, Entry, HicTier, LogConfig, Outcome};
use std::path::{Path, PathBuf};
use std::sync::Mutex;
use std::time::Duration;
use tower::ServiceExt;

const BEARER: &str = "test-bearer-token-records-0001";
const DAY: u64 = 86_400_000;
const REGISTRY: &str = "0x00000000000000000000000000000000000000a1";

fn now_ms() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap()
        .as_millis() as u64
}

fn h(c: char) -> String {
    format!("0x{}", c.to_string().repeat(64))
}

struct Script(Mutex<Vec<AssistantTurn>>);
impl LlmClient for Script {
    fn complete(&self, _req: &CompletionRequest) -> Result<AssistantTurn, LlmError> {
        let mut t = self.0.lock().unwrap();
        Ok(if t.is_empty() {
            AssistantTurn::text("(done)")
        } else {
            t.remove(0)
        })
    }
}

struct Fx {
    root: tempfile::TempDir,
    log: Arc<DecisionLog>,
}
impl Fx {
    fn new() -> Self {
        let root = tempfile::tempdir().unwrap();
        let (log, _) =
            DecisionLog::open(&root.path().join("records"), LogConfig::default()).unwrap();
        Fx {
            root,
            log: Arc::new(log),
        }
    }
    fn records_dir(&self) -> PathBuf {
        self.root.path().join("records")
    }
    fn state(
        &self,
        turns: Vec<AssistantTurn>,
        browser: Option<Arc<BrowserService>>,
        learn: Option<Arc<learn::LearnService>>,
        with_records: bool,
    ) -> Arc<AppState> {
        let script: Arc<dyn LlmClient> = Arc::new(Script(Mutex::new(turns)));
        let mut mgr = sessions::SessionManager::new(
            Arc::new(move |_ep: &sessions::LlmEndpoint| script.clone()),
            Duration::from_secs(5),
        );
        if with_records {
            mgr = mgr.with_records(self.log.clone());
        }
        if let Some(b) = browser {
            mgr = mgr.with_browser(b);
        }
        if let Some(l) = learn {
            mgr = mgr.with_learn(l);
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
    /// Every record in the directory, oldest first.
    fn records(&self) -> Vec<citrate_agent_records::StoredRecord> {
        let mut r = citrate_agent_records::read::page(&self.records_dir(), None, 10_000).unwrap();
        r.sort_by_key(|x| x.record.seq);
        r
    }
    /// The anchor over the same directory: today's batch (planned as if the day were over) and a
    /// verified inclusion proof for every record in it.
    fn anchor_covers_all(&self) {
        let ledger = self.root.path().join("anchor");
        let svc = anchor::AnchorService::open(&self.records_dir(), &ledger).unwrap();
        let today = now_ms() / DAY;
        let plan = svc
            .plan(today, (today + 1) * DAY + 1, Some(REGISTRY))
            .unwrap();
        let plan = serde_json::to_value(plan).unwrap();
        assert_eq!(plan["plan"], "ready", "{plan}");
        let records = self.records();
        assert!(!records.is_empty());
        for r in &records {
            let p = svc.proof(r.record.seq).unwrap();
            assert_eq!(p["verifies"], true, "{p}");
        }
    }
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

async fn call_auth(
    st: &Arc<AppState>,
    method: &str,
    path: &str,
    body: serde_json::Value,
    auth: bool,
) -> (StatusCode, serde_json::Value) {
    let r = app(st.clone())
        .oneshot(req(method, path, body, auth))
        .await
        .unwrap();
    let s = r.status();
    let bytes = axum::body::to_bytes(r.into_body(), 1 << 20).await.unwrap();
    (
        s,
        serde_json::from_slice(&bytes).unwrap_or(serde_json::Value::Null),
    )
}

async fn call(
    st: &Arc<AppState>,
    method: &str,
    path: &str,
    body: serde_json::Value,
) -> (StatusCode, serde_json::Value) {
    call_auth(st, method, path, body, true).await
}

fn decisions(fx: &Fx) -> Vec<(u64, citrate_agent_records::DecisionEvent)> {
    fx.records()
        .into_iter()
        .filter_map(|r| match r.record.entry {
            Entry::Decision(d) => Some((r.record.seq, d)),
            _ => None,
        })
        .collect()
}

fn outcome_of(fx: &Fx, seq: u64) -> Option<Outcome> {
    fx.records().into_iter().find_map(|r| match r.record.entry {
        Entry::Outcome(o) if o.decision_seq == seq => Some(o.outcome),
        _ => None,
    })
}

fn effect_call(id: &str) -> citrate_agent_core::hitl::ToolCall {
    citrate_agent_core::hitl::ToolCall {
        call_id: id.to_string(),
        name: "eth-send".to_string(),
        args: serde_json::json!({ "to": "0x1111111111111111111111111111111111111111", "data_hex": "0x01" }),
    }
}

async fn wait_depth(q: &ApprovalQueue, want: usize) {
    for _ in 0..400 {
        if q.depth() == want {
            return;
        }
        tokio::time::sleep(Duration::from_millis(5)).await;
    }
    panic!("queue never reached depth {want}");
}

#[tokio::test(flavor = "multi_thread")]
async fn ceremony_bridge_resolves_are_recorded_and_anchored() {
    let fx = Fx::new();
    let st = fx.state(vec![], None, None, true);
    let q = st.queue.clone();
    let a = tokio::spawn(async move { q.submit_with_outcome(effect_call("c1")).await });
    wait_depth(&st.queue, 1).await;
    let (s, _) = call(
        &st,
        "POST",
        "/approvals/approve",
        serde_json::json!({"id": "c1"}),
    )
    .await;
    assert_eq!(s, StatusCode::OK);
    a.await.unwrap();

    let q = st.queue.clone();
    let b = tokio::spawn(async move { q.submit_with_outcome(effect_call("c2")).await });
    wait_depth(&st.queue, 1).await;
    let (s, _) = call(
        &st,
        "POST",
        "/approvals/reject",
        serde_json::json!({"id": "c2"}),
    )
    .await;
    assert_eq!(s, StatusCode::OK);
    b.await.unwrap();

    // A resolve that does not match the head records nothing new.
    let before = fx.records().len();
    let (s, _) = call(
        &st,
        "POST",
        "/approvals/approve",
        serde_json::json!({"id": "gone"}),
    )
    .await;
    assert_eq!(s, StatusCode::CONFLICT);

    let d = decisions(&fx);
    let ceremony: Vec<_> = d
        .iter()
        .filter(|(_, e)| e.kind == "ceremony.capsule_effect")
        .collect();
    assert_eq!(ceremony.len(), 2, "{d:?}");
    let (s1, e1) = ceremony[0];
    assert_eq!(e1.tier, HicTier::Hic1);
    assert_eq!(e1.decision, Decision::Approved);
    assert!(e1.evidence.iter().any(|e| e.uri == "sidecar:approval/c1"));
    assert_eq!(outcome_of(&fx, *s1), Some(Outcome::Completed));
    let (s2, e2) = ceremony[1];
    assert_eq!(e2.decision, Decision::Denied);
    assert_eq!(outcome_of(&fx, *s2), None);
    // The failed resolve added an outcome-free refusal record or nothing at all, never an approval.
    assert!(fx.records()[before..].iter().all(|r| !matches!(
        &r.record.entry,
        Entry::Decision(d) if d.decision == Decision::Approved
    )));
    fx.anchor_covers_all();
}

#[tokio::test(flavor = "multi_thread")]
async fn browser_action_decisions_are_recorded() {
    let fx = Fx::new();
    let browser = Arc::new(BrowserService::new(BrowserConfig {
        managed_path: Some(PathBuf::from("/nonexistent/citrate/chromium")),
        candidates: Vec::new(),
        approval_timeout: Duration::from_secs(10),
        ..BrowserConfig::default()
    }));
    let st = fx.state(vec![], Some(browser.clone()), None, true);
    for allow in [true, false] {
        let b = browser.clone();
        let waiter = std::thread::spawn(move || {
            b.request_approval(
                "browser_click",
                "click Pay",
                "the page is untrusted",
                &|| false,
            )
        });
        let id = loop {
            if let Some(p) = browser.pending_action() {
                break p.id;
            }
            tokio::time::sleep(Duration::from_millis(5)).await;
        };
        let (s, v) = call(
            &st,
            "POST",
            "/browser/actions/decide",
            serde_json::json!({"id": id, "allow": allow}),
        )
        .await;
        assert_eq!(s, StatusCode::OK, "{v}");
        waiter.join().unwrap();
    }
    let d: Vec<_> = decisions(&fx)
        .into_iter()
        .filter(|(_, e)| e.kind == "browser.action")
        .collect();
    assert_eq!(d.len(), 2);
    assert_eq!(d[0].1.decision, Decision::Approved);
    assert!(d[0].1.subject.contains("browser_click"));
    assert_eq!(outcome_of(&fx, d[0].0), Some(Outcome::Completed));
    assert_eq!(d[1].1.decision, Decision::Denied);
    fx.anchor_covers_all();
}

fn core_record(id: u64, kind: &str, decision: &str, outcome: Option<&str>) -> serde_json::Value {
    serde_json::json!({
        "recordId": id,
        "kind": kind,
        "decision": decision,
        "subject": format!("subject {id}"),
        "reason": "the member's decision in Settings",
        "outcome": outcome,
        "outcomeDetail": outcome.map(|_| "saved"),
        "evidence": [],
        "atMs": 1_700_000_000_000u64 + id,
        "hash": h(char::from_digit((id % 10) as u32, 10).unwrap()),
    })
}

#[tokio::test(flavor = "multi_thread")]
async fn core_events_become_records_the_anchor_batches_and_proves() {
    let fx = Fx::new();
    let st = fx.state(vec![], None, None, true);
    let batch = serde_json::json!({ "records": [
        core_record(1, "grant.folder_added", "approved", Some("completed")),
        core_record(2, "grant.revoked", "approved", Some("completed")),
        core_record(3, "grant.full_access_confirmed", "approved", Some("completed")),
        core_record(4, "grant.reset", "approved", Some("completed")),
        core_record(5, "escalation.spend", "auto_within_budget", Some("completed")),
        core_record(6, "escalation.spend", "approved", Some("failed")),
        core_record(7, "agent.tool_approval", "denied", None),
        core_record(8, "ceremony.approval", "approved", None),
    ]});
    let (s, v) = call(&st, "POST", "/records/core", batch).await;
    assert_eq!(s, StatusCode::OK, "{v}");
    assert_eq!(v["written"], 8);

    let d = decisions(&fx);
    assert_eq!(d.len(), 8);
    let by_kind = |k: &str| d.iter().filter(|(_, e)| e.kind == k).collect::<Vec<_>>();
    let spend = by_kind("escalation.spend");
    assert_eq!(spend[0].1.tier, HicTier::Hic2);
    assert_eq!(spend[0].1.decision, Decision::AutoWithinBudget);
    assert_eq!(outcome_of(&fx, spend[0].0), Some(Outcome::Completed));
    assert_eq!(spend[1].1.tier, HicTier::Hic1);
    assert_eq!(outcome_of(&fx, spend[1].0), Some(Outcome::Failed));
    let full = by_kind("grant.full_access_confirmed");
    assert_eq!(full[0].1.tier, HicTier::Hic1);
    assert!(full[0]
        .1
        .evidence
        .iter()
        .any(|e| e.uri == "citrate-core:hic/record/3"
            && e.digest.as_deref() == Some(h('3').as_str())));
    let tool = by_kind("agent.tool_approval");
    assert_eq!(tool[0].1.decision, Decision::Denied);
    assert_eq!(outcome_of(&fx, tool[0].0), None);
    // An allowing decision without a reported result is closed as outcome_unknown, never guessed.
    let cer = by_kind("ceremony.approval");
    assert_eq!(outcome_of(&fx, cer[0].0), Some(Outcome::OutcomeUnknown));
    fx.anchor_covers_all();
}

#[tokio::test(flavor = "multi_thread")]
async fn a_malformed_core_batch_writes_nothing() {
    let fx = Fx::new();
    let st = fx.state(vec![], None, None, true);
    for bad in [
        // HIC-2 is only an escalation within its budget.
        core_record(
            1,
            "grant.folder_added",
            "auto_within_budget",
            Some("completed"),
        ),
        // A denial has no outcome.
        core_record(2, "agent.tool_approval", "denied", Some("completed")),
        // Unknown kinds and decisions.
        core_record(3, "wallet.drain", "approved", Some("completed")),
        core_record(4, "grant.revoked", "maybe", None),
        // A grant change is a member approval, not a denial.
        core_record(5, "grant.revoked", "denied", None),
        {
            let mut r = core_record(6, "grant.revoked", "approved", Some("completed"));
            r["hash"] = serde_json::json!("0x12");
            r
        },
    ] {
        let batch = serde_json::json!({ "records": [
            core_record(9, "grant.folder_added", "approved", Some("completed")),
            bad.clone(),
        ]});
        let (s, v) = call(&st, "POST", "/records/core", batch).await;
        assert_eq!(s, StatusCode::BAD_REQUEST, "{bad}: {v}");
    }
    let (s, _) = call(
        &st,
        "POST",
        "/records/core",
        serde_json::json!({"records": [], "extra": 1}),
    )
    .await;
    assert_eq!(s, StatusCode::BAD_REQUEST);
    assert!(fx.records().is_empty());
}

#[tokio::test(flavor = "multi_thread")]
async fn core_records_need_the_bearer_and_a_records_dir() {
    let fx = Fx::new();
    let st = fx.state(vec![], None, None, true);
    let one = serde_json::json!({"records": [core_record(1, "grant.reset", "approved", Some("completed"))]});
    let (s, _) = call_auth(&st, "POST", "/records/core", one.clone(), false).await;
    assert_eq!(s, StatusCode::UNAUTHORIZED);
    let off = fx.state(vec![], None, None, false);
    let (s, _) = call(&off, "POST", "/records/core", one).await;
    assert_eq!(s, StatusCode::NOT_FOUND);
    assert!(fx.records().is_empty());
}

#[tokio::test(flavor = "multi_thread")]
async fn web_signing_and_core_records_share_one_chain() {
    let fx = Fx::new();
    let st = fx.state(vec![], None, None, true);
    let (s, v) = call(
        &st,
        "POST",
        "/records/web-signing",
        serde_json::json!({"records": [{
            "recordId": 1, "kind": "budget_granted", "status": "final",
            "origin": "https://app.example", "atMs": 1, "hash": h('a')
        }]}),
    )
    .await;
    assert_eq!(s, StatusCode::OK, "{v}");
    let (s, _) = call(
        &st,
        "POST",
        "/records/core",
        serde_json::json!({"records": [core_record(1, "grant.reset", "approved", Some("completed"))]}),
    )
    .await;
    assert_eq!(s, StatusCode::OK);
    let kinds: Vec<_> = decisions(&fx).into_iter().map(|(_, e)| e.kind).collect();
    assert_eq!(
        kinds,
        vec!["siwe_budget".to_string(), "grant.reset".to_string()]
    );
    assert!(fx.log.verify().unwrap().open_decisions.is_empty());
    fx.anchor_covers_all();
}

// ---- learn -------------------------------------------------------------------------------------

const SKILL: &str = "---\nname: deploy-checklist\ndescription: Checks a contract before deploy\n---\n\n1. Run the tests.\n";

async fn run_verified(st: &Arc<AppState>) -> (String, String) {
    let (s, v) = call(
        st,
        "POST",
        "/sessions",
        serde_json::json!({
            "model": "gemma-4",
            "systemPrompt": "You are Hermes.",
            "llm": {"baseUrl": "http://127.0.0.1:18080/v1", "bearer": "k"},
            "tools": []
        }),
    )
    .await;
    assert_eq!(s, StatusCode::CREATED, "{v}");
    let sid = v["id"].as_str().unwrap().to_string();
    let wf = serde_json::json!({
        "id": "check",
        "steps": [{
            "id": "answer",
            "instruction": "Say whether the checks pass.",
            "max_attempts": 1,
            "verifiers": [{"kind": "answer_contains", "text": "checks pass"}]
        }]
    });
    let (s, v) = call(st, "POST", &format!("/sessions/{sid}/workflows"), wf).await;
    assert_eq!(s, StatusCode::ACCEPTED, "{v}");
    let run = v["run_id"].as_str().unwrap().to_string();
    for _ in 0..100 {
        let (_, v) = call(
            st,
            "GET",
            &format!("/sessions/{sid}/workflows/{run}"),
            serde_json::Value::Null,
        )
        .await;
        if v["state"] != "running" {
            return (sid, run);
        }
        tokio::time::sleep(Duration::from_millis(20)).await;
    }
    panic!("the workflow did not finish");
}

fn learn_service(fx: &Fx) -> Arc<learn::LearnService> {
    let dir = fx.root.path();
    Arc::new(
        learn::LearnService::open_with_log(
            &dir.join("learn"),
            &dir.join("skills"),
            vec![],
            fx.log.clone(),
        )
        .unwrap(),
    )
}

#[tokio::test(flavor = "multi_thread")]
async fn learn_decisions_land_in_the_records_dir() {
    let fx = Fx::new();
    let svc = learn_service(&fx);
    let st = fx.state(
        vec![AssistantTurn::text("All checks pass.")],
        None,
        Some(svc),
        true,
    );
    let (sid, run) = run_verified(&st).await;
    let mut ids = vec![];
    for content in [
        serde_json::json!({"kind": "skill", "skill_md": SKILL}),
        serde_json::json!({"kind": "memory", "key": "k", "value": "v"}),
    ] {
        let (s, v) = call(
            &st,
            "POST",
            "/learn/proposals",
            serde_json::json!({"session_id": sid, "run_id": run, "content": content, "known_memories": []}),
        )
        .await;
        assert_eq!(s, StatusCode::CREATED, "{v}");
        ids.push(v["id"].as_str().unwrap().to_string());
    }
    let (s, v) = call(
        &st,
        "POST",
        &format!("/learn/proposals/{}/accept", ids[0]),
        serde_json::json!({"member": "0xmember"}),
    )
    .await;
    assert_eq!(s, StatusCode::OK, "{v}");
    let (s, _) = call(
        &st,
        "POST",
        &format!("/learn/proposals/{}/reject", ids[1]),
        serde_json::json!({"member": "0xmember", "reason": "not right"}),
    )
    .await;
    assert_eq!(s, StatusCode::OK);
    let kinds: Vec<_> = decisions(&fx)
        .into_iter()
        .map(|(_, e)| (e.kind, e.decision))
        .collect();
    assert!(
        kinds.contains(&("learn.skill".to_string(), Decision::Approved)),
        "{kinds:?}"
    );
    assert!(
        kinds.contains(&("learn.memory".to_string(), Decision::Denied)),
        "{kinds:?}"
    );
    // Nothing went to the learn folder's old private log.
    assert!(!fx.root.path().join("learn/decisions").exists());
    fx.anchor_covers_all();
}

#[test]
fn learn_uses_the_records_dir_when_one_is_configured() {
    let fx = Fx::new();
    let dir = fx.root.path();
    let svc = learn::LearnService::from_values_with_records(
        Some(dir.join("learn").to_str().unwrap()),
        Some(dir.join("skills").to_str().unwrap()),
        "",
        Some(fx.log.clone()),
    )
    .expect("on");
    assert_eq!(svc.decision_log_dir(), fx.records_dir().as_path());
    let alone = learn::LearnService::from_values(
        Some(dir.join("learn2").to_str().unwrap()),
        Some(dir.join("skills2").to_str().unwrap()),
        "",
    )
    .expect("on");
    assert_eq!(
        alone.decision_log_dir(),
        dir.join("learn2/decisions").as_path()
    );
    let _ = Path::new("");
}
