//! Control-plane tests — the bearer gate, /health (open), status/skills/approvals shapes, stop flips
//! the emergency stop, and runSkill honestly refuses (S6.3). In-process via tower::oneshot; no socket.

use super::*;
use axum::body::Body;
use axum::http::{Request, StatusCode};
use tower::ServiceExt;

const BEARER: &str = "test-bearer-token-0123456789";

fn state() -> Arc<AppState> {
    Arc::new(AppState {
        estop: EmergencyStop::new(),
        queue: Arc::new(ApprovalQueue::new()),
        skills: vec![
            SkillView {
                name: "list-compliance-posture".into(),
                description: "".into(),
            },
            SkillView {
                name: "eth-sender-test".into(),
                description: "".into(),
            },
        ],
        dispatch: None,
        bearer: BEARER.to_string(),
    })
}

async fn body_json(resp: axum::response::Response) -> serde_json::Value {
    let bytes = axum::body::to_bytes(resp.into_body(), 1 << 20)
        .await
        .unwrap();
    serde_json::from_slice(&bytes).unwrap_or(serde_json::Value::Null)
}

fn authed(method: &str, path: &str) -> Request<Body> {
    Request::builder()
        .method(method)
        .uri(path)
        .header("authorization", format!("Bearer {BEARER}"))
        .body(Body::empty())
        .unwrap()
}

#[tokio::test]
async fn health_is_open_and_reports_stop_state() {
    let st = state();
    let resp = app(st.clone())
        .oneshot(
            Request::builder()
                .uri("/health")
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(resp.status(), StatusCode::OK);
    let j = body_json(resp).await;
    assert_eq!(j["status"], "ok");
    assert_eq!(j["stopped"], false);
}

#[tokio::test]
async fn control_routes_require_the_bearer() {
    for (m, p) in [
        ("GET", "/status"),
        ("GET", "/skills"),
        ("GET", "/approvals"),
        ("POST", "/stop"),
        ("POST", "/run_skill"),
    ] {
        let resp = app(state())
            .oneshot(
                Request::builder()
                    .method(m)
                    .uri(p)
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(
            resp.status(),
            StatusCode::UNAUTHORIZED,
            "{m} {p} must require the bearer"
        );
    }
}

#[tokio::test]
async fn status_reports_running_skills_and_pending() {
    let resp = app(state())
        .oneshot(authed("GET", "/status"))
        .await
        .unwrap();
    assert_eq!(resp.status(), StatusCode::OK);
    let j = body_json(resp).await;
    assert_eq!(j["running"], true);
    assert_eq!(j["skills"], 2);
    assert_eq!(j["pendingApprovals"], 0);
}

#[tokio::test]
async fn skills_lists_the_catalog() {
    let resp = app(state())
        .oneshot(authed("GET", "/skills"))
        .await
        .unwrap();
    let j = body_json(resp).await;
    let arr = j.as_array().unwrap();
    assert_eq!(arr.len(), 2);
    assert_eq!(arr[0]["name"], "list-compliance-posture");
}

#[tokio::test]
async fn approvals_is_empty_until_a_skill_runs() {
    let resp = app(state())
        .oneshot(authed("GET", "/approvals"))
        .await
        .unwrap();
    let j = body_json(resp).await;
    assert_eq!(j.as_array().unwrap().len(), 0);
}

// runSkill now RUNS a skill (S6.3 slice-2) via CapsuleDispatch::call_json, spawning it so a chain
// effect can park on the ApprovalGate. The unit tests below pin the guard rails (auth, bad body,
// unknown skill, no-dispatch, estop); the real gate-path e2e (a skill's effect surfaces on the queue)
// is `run_skill_surfaces_a_chain_effect_on_the_queue` further down, driven from the real capsule dir.

// The built capsule fixtures live at the repo root, but tests run from the crate dir.
fn capsules_dir() -> std::path::PathBuf {
    std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join("../capsules")
}

fn run_body(name: &str, args: serde_json::Value) -> Request<Body> {
    Request::builder()
        .method("POST")
        .uri("/run_skill")
        .header("authorization", format!("Bearer {BEARER}"))
        .header("content-type", "application/json")
        .body(Body::from(
            serde_json::json!({ "name": name, "args": args }).to_string(),
        ))
        .unwrap()
}

#[tokio::test]
async fn run_skill_rejects_a_malformed_body_after_auth() {
    // Authed but empty body → 400 (auth still runs first; Bytes never rejects).
    let resp = app(state())
        .oneshot(authed("POST", "/run_skill"))
        .await
        .unwrap();
    assert_eq!(resp.status(), StatusCode::BAD_REQUEST);
}

#[tokio::test]
async fn run_skill_503s_when_no_dispatch_loaded() {
    // state() has dispatch: None — a valid request must NOT pretend to run (Rule 1).
    let resp = app(state())
        .oneshot(run_body("list-compliance-posture", serde_json::json!({})))
        .await
        .unwrap();
    assert_eq!(resp.status(), StatusCode::SERVICE_UNAVAILABLE);
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn run_skill_surfaces_a_chain_effect_on_the_queue() {
    // AR-B-003 (RC-8): the eth-sender-test capsule declares tier = "high",
    // required_roles = [Reviewer, ComplianceOfficer]. This test previously
    // proved the VULNERABILITY: the tier-high eth-send parked on the anonymous
    // FIFO queue and a single anonymous `queue.approve()` released it. Post-fix
    // the effect is routed to the role-bound quorum track and the anonymous
    // FIFO approve CANNOT release it.
    //
    // (Follow-up: the sidecar's HTTP /approvals + /approvals/approve ceremony
    // is still FIFO-only; to approve a privileged effect an operator surface
    // must adopt the role-aware submit_for_action/add_signature track.)
    let queue = Arc::new(ApprovalQueue::new());
    let dispatch = crate::load_dispatch(&capsules_dir(), queue.clone());
    assert!(dispatch.is_some(), "the repo capsules/ dir must load");
    let st = Arc::new(AppState {
        estop: EmergencyStop::new(),
        queue: queue.clone(),
        skills: vec![SkillView {
            name: "eth-sender-test".into(),
            description: String::new(),
        }],
        dispatch,
        bearer: BEARER.to_string(),
    });

    // `to` must be the capsule's allow-listed address so the effect reaches the gate (not rejected at
    // the allow-list). `data` is a 1-byte payload. call_json maps both hex strings → list<u8>.
    let resp = app(st.clone())
        .oneshot(run_body(
            "eth-sender-test",
            serde_json::json!({
                "to": "0x4a86659BDab24dc444C72fbbaD4cd83491820E40",
                "data": "0x01",
            }),
        ))
        .await
        .unwrap();
    assert_eq!(resp.status(), StatusCode::OK, "skill accepted");
    let j = body_json(resp).await;
    assert_eq!(j["ok"], true);
    assert_eq!(j["submitted"], true);

    // The spawned tier-high eth-send parks on the ROLE-BOUND quorum track…
    wait_role_depth(&queue, 1).await;
    // …and NOT on the anonymous FIFO queue.
    assert_eq!(
        queue.depth(),
        0,
        "tier-high effect must not surface on the anonymous FIFO queue"
    );

    // The anonymous single-click FIFO approve MUST NOT release it (the exploit).
    queue.approve();
    tokio::time::sleep(std::time::Duration::from_millis(50)).await;
    assert_eq!(
        queue.role_pending_depth(),
        1,
        "anonymous FIFO approve must not release a tier-high privileged effect"
    );
    assert_eq!(queue.depth(), 0);
}

#[tokio::test]
async fn run_skill_404s_for_an_unknown_skill() {
    // A loaded dispatch, but the name isn't in the catalog.
    let queue = Arc::new(ApprovalQueue::new());
    let dispatch = crate::load_dispatch(&capsules_dir(), queue.clone());
    assert!(dispatch.is_some(), "the repo capsules/ dir must load");
    let st = Arc::new(AppState {
        estop: EmergencyStop::new(),
        queue,
        skills: vec![SkillView {
            name: "eth-sender-test".into(),
            description: String::new(),
        }],
        dispatch,
        bearer: BEARER.to_string(),
    });
    let resp = app(st)
        .oneshot(run_body("no-such-skill", serde_json::json!({})))
        .await
        .unwrap();
    assert_eq!(resp.status(), StatusCode::NOT_FOUND);
}

#[tokio::test]
async fn stop_triggers_the_emergency_stop() {
    let st = state();
    assert!(!st.estop.is_stopped());
    let resp = app(st.clone())
        .oneshot(authed("POST", "/stop"))
        .await
        .unwrap();
    assert_eq!(resp.status(), StatusCode::OK);
    assert!(st.estop.is_stopped(), "stop flips the emergency stop");
    // /health then reflects it.
    let h = app(st.clone())
        .oneshot(
            Request::builder()
                .uri("/health")
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(body_json(h).await["stopped"], true);
}

#[test]
fn load_skills_parses_manifests_and_is_empty_on_a_missing_dir() {
    assert!(load_skills(std::path::Path::new("/no/such/capsule/dir")).is_empty());
    // A temp capsule dir with one manifest.
    let d = std::env::temp_dir().join(format!("agentsidecar-skills-{}", std::process::id()));
    let cap = d.join("demo-skill");
    std::fs::create_dir_all(&cap).unwrap();
    std::fs::write(
        cap.join("manifest.toml"),
        "[capsule]\nname = \"demo-skill\"\ndescription = \"a demo\"\n",
    )
    .unwrap();
    let skills = load_skills(&d);
    assert_eq!(skills.len(), 1);
    assert_eq!(skills[0].name, "demo-skill");
    assert_eq!(skills[0].description, "a demo");
    let _ = std::fs::remove_dir_all(&d);
}

// ── S6.3 — the ceremony-resolution bridge (approve/reject the head) ──

#[tokio::test]
async fn approve_reject_require_the_bearer() {
    for p in ["/approvals/approve", "/approvals/reject"] {
        let resp = app(state())
            .oneshot(
                Request::builder()
                    .method("POST")
                    .uri(p)
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(
            resp.status(),
            StatusCode::UNAUTHORIZED,
            "{p} must require the bearer"
        );
    }
}

#[tokio::test]
async fn approve_on_an_empty_queue_is_an_honest_noop() {
    // Nothing pending yet (no capsule has run) → resolved:false, but the endpoint is live so the
    // ceremony can resolve the head the moment a chain effect enqueues.
    let resp = app(state())
        .oneshot(authed("POST", "/approvals/approve"))
        .await
        .unwrap();
    assert_eq!(resp.status(), StatusCode::OK);
    let j = body_json(resp).await;
    assert_eq!(j["ok"], true);
    assert_eq!(j["resolved"], false);
}

#[tokio::test]
async fn reject_on_an_empty_queue_is_an_honest_noop() {
    let resp = app(state())
        .oneshot(authed("POST", "/approvals/reject"))
        .await
        .unwrap();
    assert_eq!(resp.status(), StatusCode::OK);
    assert_eq!(body_json(resp).await["resolved"], false);
}

// ── S6.3 — end-to-end ceremony bridge: an effect submitted (as a capsule's ApprovalGate does)
// surfaces on the queue and is resolved by the same approve/reject the HTTP endpoints call. This is
// the safety property of gD-hermes proven through the real ApprovalQueue submit→resolve path.

use citrate_agent_core::hitl::{ApprovalOutcomePublic, ToolCall};

fn effect_call(id: &str) -> ToolCall {
    ToolCall {
        call_id: id.to_string(),
        name: "eth-send".to_string(), // not trusted → must pend for human approval
        args: serde_json::json!({ "to": "0x1111111111111111111111111111111111111111", "data": "0x01" }),
    }
}

async fn wait_depth(q: &ApprovalQueue, want: usize) {
    for _ in 0..400 {
        if q.depth() == want {
            return;
        }
        tokio::time::sleep(std::time::Duration::from_millis(5)).await;
    }
    panic!("queue never reached depth {want} (was {})", q.depth());
}

/// AR-B-003: wait for the role-bound (quorum) pending track to reach `want`.
async fn wait_role_depth(q: &ApprovalQueue, want: usize) {
    for _ in 0..400 {
        if q.role_pending_depth() == want {
            return;
        }
        tokio::time::sleep(std::time::Duration::from_millis(5)).await;
    }
    panic!(
        "role-pending never reached depth {want} (was {})",
        q.role_pending_depth()
    );
}

#[tokio::test]
async fn a_chain_effect_surfaces_and_approve_lets_it_proceed() {
    let queue = Arc::new(ApprovalQueue::new());
    let q = queue.clone();
    // A capsule's eth-send submits + blocks on the outcome (here, directly via the queue's async API).
    let submitter = tokio::spawn(async move { q.submit_with_outcome(effect_call("c1")).await });
    wait_depth(&queue, 1).await; // the effect is now a pending approval (what /approvals shows)
    queue.approve(); // exactly what POST /approvals/approve calls
    let outcome = submitter.await.unwrap();
    assert!(
        matches!(outcome, ApprovalOutcomePublic::Approved),
        "approved → the effect proceeds"
    );
}

#[tokio::test]
async fn a_chain_effect_that_is_rejected_does_not_proceed() {
    let queue = Arc::new(ApprovalQueue::new());
    let q = queue.clone();
    let submitter = tokio::spawn(async move { q.submit_with_outcome(effect_call("c2")).await });
    wait_depth(&queue, 1).await;
    queue.reject(); // POST /approvals/reject
    let outcome = submitter.await.unwrap();
    assert!(
        matches!(outcome, ApprovalOutcomePublic::Rejected),
        "rejected → the effect is refused"
    );
}

/// A ToolCall shaped exactly as the QueuedApprovalGate submits a chain effect ({to, data_hex}).
fn chain_effect_call(id: &str) -> ToolCall {
    ToolCall {
        call_id: id.to_string(),
        name: "cap::eth-send".to_string(), // not trusted → pends
        args: serde_json::json!({
            "to": "0x4a86659BDab24dc444C72fbbaD4cd83491820E40",
            "data_hex": "0xdeadbeef",
            "data_len": 4
        }),
    }
}

#[tokio::test]
async fn approvals_exposes_the_raw_calldata_for_the_ceremony_bridge() {
    // S6.3: citrate-core's ceremony needs the raw (to, data) to build the SignatureIntent. /approvals
    // must surface them from the pending chain effect, not just a human summary.
    let queue = Arc::new(ApprovalQueue::new());
    let q = queue.clone();
    let submitter = tokio::spawn(async move { q.submit_with_outcome(chain_effect_call("cd1")).await });
    wait_depth(&queue, 1).await;

    let st = Arc::new(AppState {
        estop: EmergencyStop::new(),
        queue: queue.clone(),
        skills: vec![],
        dispatch: None,
        bearer: BEARER.to_string(),
    });
    let resp = app(st).oneshot(authed("GET", "/approvals")).await.unwrap();
    assert_eq!(resp.status(), StatusCode::OK);
    let j = body_json(resp).await;
    assert_eq!(
        j[0]["to"], "0x4a86659BDab24dc444C72fbbaD4cd83491820E40",
        "the chain target is exposed"
    );
    assert_eq!(j[0]["data"], "0xdeadbeef", "the calldata is exposed");

    queue.approve();
    let _ = submitter.await;
}
