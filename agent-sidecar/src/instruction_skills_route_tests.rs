//! HUP-S3.2: core reads which instruction skills the sidecar offers (with provenance and the
//! ranking method that runs) and asks for a reload after the member saves a skill, so it joins the
//! next session without a restart.

use super::*;
use axum::body::Body;
use axum::http::{Request, StatusCode};
use citrate_agent_loop::skills::SkillSource;
use std::path::PathBuf;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::time::Duration;
use tower::ServiceExt;

const BEARER: &str = "test-bearer-token-0123456789";
static N: AtomicUsize = AtomicUsize::new(0);

struct Scratch(PathBuf);
impl Scratch {
    fn new() -> Self {
        let p = std::env::temp_dir().join(format!(
            "citrate-sidecar-iskills-{}-{}",
            std::process::id(),
            N.fetch_add(1, Ordering::SeqCst)
        ));
        let _ = std::fs::remove_dir_all(&p);
        std::fs::create_dir_all(&p).unwrap();
        Scratch(p)
    }
}
impl Drop for Scratch {
    fn drop(&mut self) {
        let _ = std::fs::remove_dir_all(&self.0);
    }
}

fn skill(root: &std::path::Path, name: &str, description: &str) {
    let dir = root.join(name);
    std::fs::create_dir_all(&dir).unwrap();
    std::fs::write(
        dir.join("SKILL.md"),
        format!("---\nname: {name}\ndescription: {description}\n---\nBody.\n"),
    )
    .unwrap();
}

struct Quiet;
impl citrate_agent_loop::LlmClient for Quiet {
    fn complete(
        &self,
        _req: &citrate_agent_loop::CompletionRequest,
    ) -> Result<citrate_agent_loop::AssistantTurn, citrate_agent_loop::LlmError> {
        Ok(citrate_agent_loop::AssistantTurn::text("ok"))
    }
}

fn state(sources: Vec<SkillSource>) -> Arc<AppState> {
    let mut mgr = sessions::SessionManager::new(
        Arc::new(
            |_ep: &sessions::LlmEndpoint| -> Arc<dyn citrate_agent_loop::LlmClient> {
                Arc::new(Quiet)
            },
        ),
        Duration::from_secs(5),
    );
    if !sources.is_empty() {
        mgr = mgr.with_skill_sources(sources);
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

fn req(method: &str, path: &str, bearer: &str) -> Request<Body> {
    Request::builder()
        .method(method)
        .uri(path)
        .header("authorization", format!("Bearer {bearer}"))
        .body(Body::empty())
        .unwrap()
}

async fn json(resp: axum::response::Response) -> serde_json::Value {
    let bytes = axum::body::to_bytes(resp.into_body(), 1 << 20)
        .await
        .unwrap();
    serde_json::from_slice(&bytes).unwrap_or(serde_json::Value::Null)
}

#[tokio::test(flavor = "multi_thread")]
async fn the_offered_instruction_skills_are_listed_with_the_ranking_method() {
    let s = Scratch::new();
    skill(&s.0, "staking-report", "Write the weekly staking report.");
    let st = state(vec![SkillSource::new("1:member", &s.0)]);
    let r = app(st)
        .oneshot(req("GET", "/instruction-skills", BEARER))
        .await
        .unwrap();
    assert_eq!(r.status(), StatusCode::OK);
    let v = json(r).await;
    assert_eq!(v["ranker"], "bm25-lexical");
    assert_eq!(v["per_turn"], 5);
    assert_eq!(v["skills"][0]["name"], "staking-report");
    assert_eq!(v["skills"][0]["source"], "1:member");
    assert!(v["skills"][0]["provenance"].is_null());
}

#[tokio::test(flavor = "multi_thread")]
async fn a_saved_skill_is_offered_after_a_reload() {
    let s = Scratch::new();
    let st = state(vec![SkillSource::new("1:member", &s.0)]);
    let r = app(st.clone())
        .oneshot(req("GET", "/instruction-skills", BEARER))
        .await
        .unwrap();
    assert_eq!(json(r).await["skills"], serde_json::json!([]));
    skill(
        &s.0,
        "morning-check",
        "Read node status then staking status.",
    );
    let r = app(st.clone())
        .oneshot(req("POST", "/instruction-skills/reload", BEARER))
        .await
        .unwrap();
    assert_eq!(r.status(), StatusCode::OK);
    let v = json(r).await;
    assert_eq!(v["reloaded"], true);
    assert_eq!(v["skills_offered"], 1);
    let r = app(st)
        .oneshot(req("GET", "/instruction-skills", BEARER))
        .await
        .unwrap();
    assert_eq!(json(r).await["skills"][0]["name"], "morning-check");
}

#[tokio::test(flavor = "multi_thread")]
async fn without_skill_sources_a_reload_says_so() {
    let st = state(vec![]);
    let r = app(st)
        .oneshot(req("POST", "/instruction-skills/reload", BEARER))
        .await
        .unwrap();
    assert_eq!(r.status(), StatusCode::OK);
    assert_eq!(json(r).await["reloaded"], false);
}

#[tokio::test(flavor = "multi_thread")]
async fn the_routes_need_the_bearer() {
    let st = state(vec![]);
    for (m, p) in [
        ("GET", "/instruction-skills"),
        ("POST", "/instruction-skills/reload"),
    ] {
        let r = app(st.clone()).oneshot(req(m, p, "wrong")).await.unwrap();
        assert_eq!(r.status(), StatusCode::UNAUTHORIZED, "{p}");
    }
}
