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

#[tokio::test]
async fn run_skill_refuses_until_s6_3() {
    let resp = app(state())
        .oneshot(authed("POST", "/run_skill"))
        .await
        .unwrap();
    assert_eq!(
        resp.status(),
        StatusCode::NOT_IMPLEMENTED,
        "no effect runs without the ceremony bridge"
    );
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
