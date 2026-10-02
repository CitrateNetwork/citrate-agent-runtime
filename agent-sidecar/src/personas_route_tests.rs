//! HUP-S3.3 + S3.7: personas and track workflows over the real control-plane routes
//! (tower::oneshot, no socket). Every client (app, CLI, MCP) reads the same data.

use super::*;
use axum::body::Body;
use axum::http::{Request, StatusCode};
use std::time::Duration;
use tower::ServiceExt;

const BEARER: &str = "test-bearer-token-personas-0123";

struct Idle;
impl citrate_agent_loop::LlmClient for Idle {
    fn complete(
        &self,
        _r: &citrate_agent_loop::CompletionRequest,
    ) -> Result<citrate_agent_loop::AssistantTurn, citrate_agent_loop::LlmError> {
        Ok(citrate_agent_loop::AssistantTurn::text("(idle)"))
    }
}

fn state() -> Arc<AppState> {
    let llm: Arc<dyn citrate_agent_loop::LlmClient> = Arc::new(Idle);
    let sessions = Arc::new(sessions::SessionManager::new(
        Arc::new(move |_ep: &sessions::LlmEndpoint| llm.clone()),
        Duration::from_secs(1),
    ));
    Arc::new(AppState {
        estop: EmergencyStop::new(),
        queue: Arc::new(ApprovalQueue::new()),
        skills: vec![],
        dispatch: None,
        bearer: BEARER.to_string(),
        run_slots: Arc::new(tokio::sync::Semaphore::new(MAX_CONCURRENT_SKILLS)),
        sessions,
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

async fn json(resp: axum::response::Response) -> serde_json::Value {
    let bytes = axum::body::to_bytes(resp.into_body(), 1 << 20)
        .await
        .unwrap();
    serde_json::from_slice(&bytes).unwrap_or(serde_json::Value::Null)
}

fn custom() -> serde_json::Value {
    serde_json::json!({
        "id": "custom-night-owl",
        "name": "Night Owl",
        "summary": "Late-night pair programmer.",
        "voice": "Quiet and focused.",
        "tone": "Dry.",
        "style_rules": ["Lead with the answer."],
        "default_track": "code"
    })
}

#[tokio::test]
async fn persona_and_workflow_routes_are_bearer_gated() {
    for (m, p) in [
        ("GET", "/personas"),
        ("POST", "/personas/check"),
        ("GET", "/workflows"),
    ] {
        let r = app(state())
            .oneshot(req(m, p, serde_json::json!({}), false))
            .await
            .unwrap();
        assert_eq!(r.status(), StatusCode::UNAUTHORIZED, "{m} {p}");
    }
}

#[tokio::test]
async fn get_personas_lists_the_shipped_personas_with_fragments_and_approved_names() {
    let r = app(state())
        .oneshot(req("GET", "/personas", serde_json::Value::Null, true))
        .await
        .unwrap();
    assert_eq!(r.status(), StatusCode::OK);
    let v = json(r).await;
    let ps = v.as_array().expect("array");
    assert!(ps.len() >= 5);
    for p in ps {
        assert_eq!(p["name_pending_sign_off"], false, "{p}");
        assert_eq!(p["custom"], false);
        let frag = p["prompt_fragment"].as_str().expect("fragment");
        assert!(frag.contains(p["name"].as_str().expect("name")));
        assert!(p["default_track"].is_string() && p["default_workflow"].is_string());
    }
}

#[tokio::test]
async fn post_personas_check_renders_a_custom_persona_or_refuses_it() {
    let r = app(state())
        .oneshot(req(
            "POST",
            "/personas/check",
            serde_json::json!({ "persona": custom() }),
            true,
        ))
        .await
        .unwrap();
    assert_eq!(r.status(), StatusCode::OK);
    let v = json(r).await;
    assert_eq!(v["custom"], true);
    assert_eq!(v["default_workflow"], "code-change");
    assert!(v["prompt_fragment"]
        .as_str()
        .unwrap_or("")
        .contains("Night Owl"));

    let mut bad = custom();
    bad["name"] = serde_json::json!("graft");
    let r = app(state())
        .oneshot(req(
            "POST",
            "/personas/check",
            serde_json::json!({ "persona": bad }),
            true,
        ))
        .await
        .unwrap();
    assert_eq!(r.status(), StatusCode::UNPROCESSABLE_ENTITY);
    assert!(json(r).await["error"]
        .as_str()
        .unwrap_or("")
        .contains("shipped"));

    let r = app(state())
        .oneshot(req(
            "POST",
            "/personas/check",
            serde_json::json!({ "persona": { "id": "custom-x" } }),
            true,
        ))
        .await
        .unwrap();
    assert_eq!(r.status(), StatusCode::BAD_REQUEST, "malformed body");
}

#[tokio::test]
async fn get_workflows_lists_every_track_family_with_verifier_names() {
    let r = app(state())
        .oneshot(req("GET", "/workflows", serde_json::Value::Null, true))
        .await
        .unwrap();
    assert_eq!(r.status(), StatusCode::OK);
    let v = json(r).await;
    let ws = v.as_array().expect("array");
    let tracks: std::collections::BTreeSet<&str> =
        ws.iter().filter_map(|w| w["track"].as_str()).collect();
    assert_eq!(tracks.len(), 5);
    assert_eq!(ws.iter().filter(|w| w["is_default"] == true).count(), 5);
    let cb = ws
        .iter()
        .find(|w| w["id"] == "contract-build")
        .expect("contract-build");
    assert_eq!(cb["evidence"], "tool-report");
    assert!(cb["verifier_names"]
        .as_array()
        .map(|n| n
            .iter()
            .any(|x| x.as_str().unwrap_or("").contains("forge_test")))
        .unwrap_or(false));
}
