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
