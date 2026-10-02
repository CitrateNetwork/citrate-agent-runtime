//! HUP-S3.4 wiring: verified workflow runs in a session, and the learn routes over agent-learn.
//! - A workflow run is judged only by its verifiers; only a verified run can back a proposal.
//! - Proposals are listed, accepted (skill to the skills folder, memory record back to core),
//!   or rejected; contradictions must be acknowledged and come back as Belnap `both`.
//! - Proposals survive a sidecar restart (the proposals file under the learn folder).
//! - Hermes itself can propose through the `learn_propose` tool, bound to its last verified run.

use super::*;
use axum::body::Body;
use axum::http::{Request, StatusCode};
use citrate_agent_loop::{AssistantTurn, CompletionRequest, LlmClient, LlmError, ToolCall};
use std::sync::Mutex;
use std::time::Duration;
use tower::ServiceExt;

const BEARER: &str = "test-bearer-token-0123456789";
const SKILL: &str = "---\nname: deploy-checklist\ndescription: Checks a contract before deploy\n---\n\n1. Run the tests.\n";

struct Script(Mutex<Vec<AssistantTurn>>);
impl LlmClient for Script {
    fn complete(&self, _req: &CompletionRequest) -> Result<AssistantTurn, LlmError> {
        let mut t = self.0.lock().unwrap();
        if t.is_empty() {
            Ok(AssistantTurn::text("(done)"))
        } else {
            Ok(t.remove(0))
        }
    }
}

struct Fx {
    root: tempfile::TempDir,
}
impl Fx {
    fn new() -> Self {
        Fx {
            root: tempfile::tempdir().unwrap(),
        }
    }
    fn learn_dir(&self) -> std::path::PathBuf {
        self.root.path().join("learn")
    }
    fn skills_dir(&self) -> std::path::PathBuf {
        self.root.path().join("skills")
    }
    fn service(&self) -> Arc<learn::LearnService> {
        Arc::new(learn::LearnService::open(&self.learn_dir(), &self.skills_dir(), vec![]).unwrap())
    }
}

fn state(turns: Vec<AssistantTurn>, learn: Option<Arc<learn::LearnService>>) -> Arc<AppState> {
    let script: Arc<dyn LlmClient> = Arc::new(Script(Mutex::new(turns)));
    let mgr = sessions::SessionManager::new(
        Arc::new(move |_ep: &sessions::LlmEndpoint| script.clone()),
        Duration::from_secs(5),
    );
    let mgr = match learn {
        Some(l) => mgr.with_learn(l),
        None => mgr,
    };
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
    let status = r.status();
    let bytes = axum::body::to_bytes(r.into_body(), 1 << 20).await.unwrap();
    (
        status,
        serde_json::from_slice(&bytes).unwrap_or(serde_json::Value::Null),
    )
}

async fn open_session(st: &Arc<AppState>) -> String {
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
    v["id"].as_str().unwrap().to_string()
}

fn workflow(needle: &str) -> serde_json::Value {
    serde_json::json!({
        "id": "check",
        "steps": [{
            "id": "answer",
            "instruction": "Say whether the checks pass.",
            "max_attempts": 1,
            "verifiers": [{"kind": "answer_contains", "text": needle}]
        }]
    })
}

/// Start a workflow and poll until it leaves `running`.
async fn run_workflow(st: &Arc<AppState>, sid: &str, wf: serde_json::Value) -> serde_json::Value {
    let (s, v) = call(st, "POST", &format!("/sessions/{sid}/workflows"), wf).await;
    assert_eq!(s, StatusCode::ACCEPTED, "{v}");
    let run = v["run_id"].as_str().unwrap().to_string();
    for _ in 0..100 {
        let (s, v) = call(
            st,
            "GET",
            &format!("/sessions/{sid}/workflows/{run}"),
            serde_json::Value::Null,
        )
        .await;
        assert_eq!(s, StatusCode::OK, "{v}");
        if v["state"] != "running" {
            return v;
        }
        tokio::time::sleep(Duration::from_millis(20)).await;
    }
    panic!("the workflow did not finish");
}

async fn propose(
    st: &Arc<AppState>,
    sid: &str,
    run: &str,
    content: serde_json::Value,
    known: serde_json::Value,
) -> (StatusCode, serde_json::Value) {
    call(
        st,
        "POST",
        "/learn/proposals",
        serde_json::json!({"session_id": sid, "run_id": run, "content": content, "known_memories": known}),
    )
    .await
}

// ---- workflows -----------------------------------------------------------------------------

#[tokio::test]
async fn workflow_routes_require_the_bearer() {
    let st = state(vec![], None);
    let r = app(st)
        .oneshot(req("POST", "/sessions/x/workflows", workflow("ok"), false))
        .await
        .unwrap();
    assert_eq!(r.status(), StatusCode::UNAUTHORIZED);
}

#[tokio::test]
async fn a_workflow_that_cannot_be_judged_is_refused() {
    let st = state(vec![], None);
    let sid = open_session(&st).await;
    let bad = [
        serde_json::json!({"id": "w", "steps": []}),
        serde_json::json!({"id": "w", "steps": [{"id": "a", "instruction": "x", "verifiers": []}]}),
        serde_json::json!({"id": "w", "steps": [{"id": "a", "instruction": "x", "max_attempts": 9, "verifiers": [{"kind": "answer_contains", "text": "y"}]}]}),
        serde_json::json!({"id": "w", "steps": [{"id": "a", "instruction": "x", "verifiers": [{"kind": "model_says_ok"}]}]}),
        serde_json::json!({"id": "w", "steps": [{"id": "a", "instruction": "x", "verifiers": [{"kind": "sarif_below", "tool": "slither_scan", "threshold": "catastrophic"}]}]}),
    ];
    for b in bad {
        let (s, v) = call(
            &st,
            "POST",
            &format!("/sessions/{sid}/workflows"),
            b.clone(),
        )
        .await;
        assert_eq!(s, StatusCode::BAD_REQUEST, "{b} -> {v}");
    }
    let (s, _) = call(&st, "POST", "/sessions/nope/workflows", workflow("x")).await;
    assert_eq!(s, StatusCode::NOT_FOUND);
}

#[tokio::test]
async fn a_passing_workflow_is_verified_with_its_evidence() {
    let st = state(vec![AssistantTurn::text("All checks pass.")], None);
    let sid = open_session(&st).await;
    let v = run_workflow(&st, &sid, workflow("checks pass")).await;
    assert_eq!(v["state"], "verified", "{v}");
    assert_eq!(v["evidence"]["workflow_id"], "check");
    assert_eq!(v["evidence"]["trajectory"]["session_id"], sid.as_str());
    let verdicts = v["evidence"]["verdicts"].as_array().unwrap();
    assert_eq!(verdicts.len(), 1);
    assert_eq!(verdicts[0]["passed"], true);
    assert_eq!(v["answers"][0], "All checks pass.");
}

#[tokio::test]
async fn the_models_claim_alone_leaves_a_workflow_unverified() {
    let st = state(vec![AssistantTurn::text("Trust me, it is done.")], None);
    let sid = open_session(&st).await;
    let v = run_workflow(&st, &sid, workflow("checks pass")).await;
    assert_eq!(v["state"], "unverified", "{v}");
    assert!(
        v["reason"].as_str().unwrap().contains("did not pass"),
        "{v}"
    );
    assert!(v.get("evidence").is_none() || v["evidence"].is_null());
    let (s, _) = call(
        &st,
        "GET",
        &format!("/sessions/{sid}/workflows/wr-999"),
        serde_json::Value::Null,
    )
    .await;
    assert_eq!(s, StatusCode::NOT_FOUND);
}

// ---- learn routes --------------------------------------------------------------------------

#[tokio::test]
async fn learn_routes_say_so_when_learning_is_off() {
    let st = state(vec![], None);
    let (s, v) = call(&st, "GET", "/learn/status", serde_json::Value::Null).await;
    assert_eq!(s, StatusCode::OK);
    assert_eq!(v["enabled"], false);
    let (s, v) = call(&st, "GET", "/learn/proposals", serde_json::Value::Null).await;
    assert_eq!(s, StatusCode::SERVICE_UNAVAILABLE);
    assert!(v["error"].as_str().unwrap().contains("off"), "{v}");
}

#[tokio::test]
async fn only_a_verified_run_of_that_session_can_back_a_proposal() {
    let fx = Fx::new();
    let st = state(
        vec![
            AssistantTurn::text("All checks pass."),
            AssistantTurn::text("not sure"),
        ],
        Some(fx.service()),
    );
    let sid = open_session(&st).await;
    let other = open_session(&st).await;
    let ok = run_workflow(&st, &sid, workflow("checks pass")).await;
    let bad = run_workflow(&st, &sid, workflow("checks pass")).await;
    assert_eq!(bad["state"], "unverified");
    let mem = serde_json::json!({"kind": "memory", "key": "deploy chain", "value": "40204"});

    let (s, v) = propose(
        &st,
        &sid,
        bad["run_id"].as_str().unwrap(),
        mem.clone(),
        serde_json::json!([]),
    )
    .await;
    assert_eq!(
        s,
        StatusCode::CONFLICT,
        "an unverified run is not evidence: {v}"
    );
    let (s, _) = propose(
        &st,
        &other,
        ok["run_id"].as_str().unwrap(),
        mem.clone(),
        serde_json::json!([]),
    )
    .await;
    assert_eq!(
        s,
        StatusCode::NOT_FOUND,
        "another session's run is not found"
    );
    let (s, _) = propose(&st, &sid, "wr-404", mem.clone(), serde_json::json!([])).await;
    assert_eq!(s, StatusCode::NOT_FOUND);

    let (s, p) = propose(
        &st,
        &sid,
        ok["run_id"].as_str().unwrap(),
        mem,
        serde_json::json!([]),
    )
    .await;
    assert_eq!(s, StatusCode::CREATED, "{p}");
    assert_eq!(p["kind"], "memory");
    assert_eq!(p["state"]["state"], "proposed");
    assert_eq!(p["provenance"]["session_id"], sid.as_str());
    assert_eq!(p["provenance"]["model"], "gemma-4");
    assert_eq!(p["evidence"]["verdicts"][0]["passed"], true);

    let (s, list) = call(&st, "GET", "/learn/proposals", serde_json::Value::Null).await;
    assert_eq!(s, StatusCode::OK);
    assert_eq!(list["proposals"].as_array().unwrap().len(), 1);
    let (s, one) = call(
        &st,
        "GET",
        &format!("/learn/proposals/{}", p["id"].as_str().unwrap()),
        serde_json::Value::Null,
    )
    .await;
    assert_eq!(s, StatusCode::OK);
    assert_eq!(one["id"], p["id"]);
}

#[tokio::test]
async fn a_session_that_read_untrusted_content_cannot_propose() {
    let fx = Fx::new();
    let st = state(
        vec![AssistantTurn::text("All checks pass.")],
        Some(fx.service()),
    );
    let sid = open_session(&st).await;
    let ok = run_workflow(&st, &sid, workflow("checks pass")).await;
    st.sessions
        .get(&sid)
        .unwrap()
        .taint()
        .taint("web_fetch", "untrusted page");
    let (s, v) = propose(
        &st,
        &sid,
        ok["run_id"].as_str().unwrap(),
        serde_json::json!({"kind": "memory", "key": "k", "value": "v"}),
        serde_json::json!([]),
    )
    .await;
    assert_eq!(s, StatusCode::CONFLICT, "{v}");
    assert!(v["error"].as_str().unwrap().contains("untrusted"), "{v}");
}

#[tokio::test]
async fn accepting_a_skill_writes_it_and_a_reject_is_final() {
    let fx = Fx::new();
    let st = state(
        vec![AssistantTurn::text("All checks pass.")],
        Some(fx.service()),
    );
    let sid = open_session(&st).await;
    let run = run_workflow(&st, &sid, workflow("checks pass")).await;
    let run = run["run_id"].as_str().unwrap();
    let (_, sk) = propose(
        &st,
        &sid,
        run,
        serde_json::json!({"kind": "skill", "skill_md": SKILL}),
        serde_json::json!([]),
    )
    .await;
    let (_, mem) = propose(
        &st,
        &sid,
        run,
        serde_json::json!({"kind": "memory", "key": "k", "value": "v"}),
        serde_json::json!([]),
    )
    .await;
    let sk_id = sk["id"].as_str().unwrap();
    let mem_id = mem["id"].as_str().unwrap();

    let (s, v) = call(
        &st,
        "POST",
        &format!("/learn/proposals/{sk_id}/accept"),
        serde_json::json!({"member": ""}),
    )
    .await;
    assert_eq!(s, StatusCode::BAD_REQUEST, "a member is required: {v}");
    let (s, v) = call(
        &st,
        "POST",
        &format!("/learn/proposals/{sk_id}/accept"),
        serde_json::json!({"member": "0xmember"}),
    )
    .await;
    assert_eq!(s, StatusCode::OK, "{v}");
    assert_eq!(v["persisted"]["kind"], "skill");
    let path = fx.skills_dir().join("deploy-checklist").join("SKILL.md");
    assert_eq!(std::fs::read_to_string(path).unwrap(), SKILL);
    assert!(
        v["persisted"].get("path").is_none(),
        "the route does not echo local paths: {v}"
    );

    let (s, _) = call(
        &st,
        "POST",
        &format!("/learn/proposals/{mem_id}/reject"),
        serde_json::json!({"member": "0xmember", "reason": "not right"}),
    )
    .await;
    assert_eq!(s, StatusCode::OK);
    let (s, v) = call(
        &st,
        "POST",
        &format!("/learn/proposals/{mem_id}/accept"),
        serde_json::json!({"member": "0xmember"}),
    )
    .await;
    assert_eq!(s, StatusCode::CONFLICT, "{v}");
    let (_, list) = call(&st, "GET", "/learn/proposals", serde_json::Value::Null).await;
    assert!(list["proposals"].as_array().unwrap().is_empty());
    let (_, all) = call(
        &st,
        "GET",
        "/learn/proposals?all=true",
        serde_json::Value::Null,
    )
    .await;
    assert_eq!(all["proposals"].as_array().unwrap().len(), 2);
    let (s, _) = call(
        &st,
        "POST",
        "/learn/proposals/lp-000000000000000000000000/accept",
        serde_json::json!({"member": "m"}),
    )
    .await;
    assert_eq!(s, StatusCode::NOT_FOUND);
}

#[tokio::test]
async fn a_contradicting_memory_needs_acknowledgement_and_is_stored_as_both() {
    let fx = Fx::new();
    let st = state(
        vec![AssistantTurn::text("All checks pass.")],
        Some(fx.service()),
    );
    let sid = open_session(&st).await;
    let run = run_workflow(&st, &sid, workflow("checks pass")).await;
    let known = serde_json::json!([{"id": "lm-1", "key": "Deploy chain", "value": "1"}]);
    let (s, p) = propose(
        &st,
        &sid,
        run["run_id"].as_str().unwrap(),
        serde_json::json!({"kind": "memory", "key": "deploy chain", "value": "40204"}),
        known,
    )
    .await;
    assert_eq!(s, StatusCode::CREATED, "{p}");
    assert_eq!(p["conflicts"][0]["kind"], "contradiction");
    let id = p["id"].as_str().unwrap();
    let (s, v) = call(
        &st,
        "POST",
        &format!("/learn/proposals/{id}/accept"),
        serde_json::json!({"member": "0xm"}),
    )
    .await;
    assert_eq!(s, StatusCode::CONFLICT, "{v}");
    assert_eq!(v["conflicts"][0]["existing_id"], "memory:lm-1", "{v}");
    let (s, v) = call(
        &st,
        "POST",
        &format!("/learn/proposals/{id}/accept"),
        serde_json::json!({"member": "0xm", "acknowledged_conflicts": ["memory:lm-1"]}),
    )
    .await;
    assert_eq!(s, StatusCode::OK, "{v}");
    assert_eq!(v["persisted"]["kind"], "memory");
    assert_eq!(v["persisted"]["belnap"], "both");
    assert_eq!(v["persisted"]["contradicts"][0], "lm-1");
    assert_eq!(v["persisted"]["schema"], "citrate.learn.memory.v1");
}

#[tokio::test]
async fn proposals_survive_a_sidecar_restart() {
    let fx = Fx::new();
    let id = {
        let st = state(
            vec![AssistantTurn::text("All checks pass.")],
            Some(fx.service()),
        );
        let sid = open_session(&st).await;
        let run = run_workflow(&st, &sid, workflow("checks pass")).await;
        let (_, p) = propose(
            &st,
            &sid,
            run["run_id"].as_str().unwrap(),
            serde_json::json!({"kind": "skill", "skill_md": SKILL}),
            serde_json::json!([]),
        )
        .await;
        p["id"].as_str().unwrap().to_string()
    };
    // A new process: a fresh service over the same folders.
    let st = state(vec![], Some(fx.service()));
    let (_, list) = call(&st, "GET", "/learn/proposals", serde_json::Value::Null).await;
    let ids: Vec<&str> = list["proposals"]
        .as_array()
        .unwrap()
        .iter()
        .map(|p| p["id"].as_str().unwrap())
        .collect();
    assert_eq!(ids, vec![id.as_str()]);
    let (s, v) = call(
        &st,
        "POST",
        &format!("/learn/proposals/{id}/accept"),
        serde_json::json!({"member": "0xm"}),
    )
    .await;
    assert_eq!(s, StatusCode::OK, "{v}");
    let (_, status) = call(&st, "GET", "/learn/status", serde_json::Value::Null).await;
    assert_eq!(status["enabled"], true);
    assert_eq!(status["restored"], 1);
    assert!(status["store_error"].is_null());
}

#[tokio::test]
async fn the_emergency_stop_closes_the_learn_decisions() {
    let fx = Fx::new();
    let st = state(
        vec![AssistantTurn::text("All checks pass.")],
        Some(fx.service()),
    );
    let sid = open_session(&st).await;
    let run = run_workflow(&st, &sid, workflow("checks pass")).await;
    let (_, p) = propose(
        &st,
        &sid,
        run["run_id"].as_str().unwrap(),
        serde_json::json!({"kind": "memory", "key": "k", "value": "v"}),
        serde_json::json!([]),
    )
    .await;
    let id = p["id"].as_str().unwrap();
    st.estop.trigger();
    let (s, _) = call(
        &st,
        "POST",
        &format!("/learn/proposals/{id}/accept"),
        serde_json::json!({"member": "0xm"}),
    )
    .await;
    assert_eq!(s, StatusCode::SERVICE_UNAVAILABLE);
    let (s, _) = propose(
        &st,
        &sid,
        run["run_id"].as_str().unwrap(),
        serde_json::json!({"kind": "memory", "key": "k2", "value": "v"}),
        serde_json::json!([]),
    )
    .await;
    assert_eq!(s, StatusCode::SERVICE_UNAVAILABLE);
    let (s, _) = call(
        &st,
        "POST",
        &format!("/sessions/{sid}/workflows"),
        workflow("x"),
    )
    .await;
    assert_eq!(s, StatusCode::SERVICE_UNAVAILABLE);
}

#[tokio::test]
async fn publishing_builds_calldata_only_after_accept() {
    let fx = Fx::new();
    let st = state(
        vec![AssistantTurn::text("All checks pass.")],
        Some(fx.service()),
    );
    let sid = open_session(&st).await;
    let run = run_workflow(&st, &sid, workflow("checks pass")).await;
    let (_, p) = propose(
        &st,
        &sid,
        run["run_id"].as_str().unwrap(),
        serde_json::json!({"kind": "skill", "skill_md": SKILL}),
        serde_json::json!([]),
    )
    .await;
    let id = p["id"].as_str().unwrap();
    let body = serde_json::json!({
        "approval": {"member": "0xm", "proposal_id": id, "content_sha256": p["content_sha256"]},
        "params": {"chain_id": 40204, "registry": format!("0x{}", "11".repeat(20)), "owner": format!("0x{}", "22".repeat(20)), "version": "1.0.0", "manifest_cid": null, "tags": []}
    });
    let (s, v) = call(
        &st,
        "POST",
        &format!("/learn/proposals/{id}/publish"),
        body.clone(),
    )
    .await;
    assert_eq!(s, StatusCode::CONFLICT, "not persisted yet: {v}");
    call(
        &st,
        "POST",
        &format!("/learn/proposals/{id}/accept"),
        serde_json::json!({"member": "0xm"}),
    )
    .await;
    let (s, v) = call(&st, "POST", &format!("/learn/proposals/{id}/publish"), body).await;
    assert_eq!(s, StatusCode::OK, "{v}");
    assert_eq!(v["broadcast"], false);
    assert_eq!(v["hic"], "hic-1");
    assert!(
        v["data"].as_str().unwrap().starts_with("0x2a996145"),
        "registerSkill selector: {v}"
    );
}

// ---- the learn_propose tool ----------------------------------------------------------------

#[tokio::test]
async fn hermes_can_propose_through_its_tool_after_a_verified_run() {
    let fx = Fx::new();
    let tool_call = |id: &str| {
        AssistantTurn::tools(vec![ToolCall {
            id: id.into(),
            name: "learn_propose".into(),
            arguments:
                serde_json::json!({"kind": "memory", "key": "deploy chain", "value": "40204"})
                    .to_string(),
        }])
    };
    let st = state(
        vec![
            // A turn before any verified run: the tool refuses.
            tool_call("c0"),
            AssistantTurn::text("nothing to learn yet"),
            // The workflow.
            AssistantTurn::text("All checks pass."),
            // A turn after it: the tool proposes.
            tool_call("c1"),
            AssistantTurn::text("proposed"),
        ],
        Some(fx.service()),
    );
    let sid = open_session(&st).await;
    let (s, _) = call(
        &st,
        "POST",
        &format!("/sessions/{sid}/messages"),
        serde_json::json!({"text": "learn what you did"}),
    )
    .await;
    assert_eq!(s, StatusCode::ACCEPTED);
    wait_idle(&st, &sid).await;
    let (_, list) = call(&st, "GET", "/learn/proposals", serde_json::Value::Null).await;
    assert!(
        list["proposals"].as_array().unwrap().is_empty(),
        "no verified run, no proposal"
    );

    run_workflow(&st, &sid, workflow("checks pass")).await;
    let (s, _) = call(
        &st,
        "POST",
        &format!("/sessions/{sid}/messages"),
        serde_json::json!({"text": "learn what you did"}),
    )
    .await;
    assert_eq!(s, StatusCode::ACCEPTED);
    wait_idle(&st, &sid).await;
    let (_, list) = call(&st, "GET", "/learn/proposals", serde_json::Value::Null).await;
    let ps = list["proposals"].as_array().unwrap();
    assert_eq!(ps.len(), 1, "{list}");
    assert_eq!(ps[0]["content"]["key"], "deploy chain");
    assert_eq!(ps[0]["evidence"]["workflow_id"], "check");
}

#[tokio::test]
async fn the_learn_tool_name_is_reserved_while_learning_is_on() {
    let fx = Fx::new();
    let st = state(vec![], Some(fx.service()));
    let (s, v) = call(
        &st,
        "POST",
        "/sessions",
        serde_json::json!({
            "model": "m",
            "systemPrompt": "s",
            "llm": {"baseUrl": "http://127.0.0.1:1/v1"},
            "tools": [{"name": "learn_propose", "description": "x", "parameters": {"type": "object"}, "host": "core"}]
        }),
    )
    .await;
    assert_eq!(s, StatusCode::BAD_REQUEST, "{v}");
}

async fn wait_idle(st: &Arc<AppState>, sid: &str) {
    for _ in 0..200 {
        if !st.sessions.get(sid).unwrap().is_busy() {
            return;
        }
        tokio::time::sleep(Duration::from_millis(10)).await;
    }
    panic!("the turn did not finish");
}

// ---- configuration --------------------------------------------------------------------------

#[test]
fn learning_is_on_only_with_both_folders() {
    let fx = Fx::new();
    let d = fx.learn_dir().to_string_lossy().into_owned();
    let k = fx.skills_dir().to_string_lossy().into_owned();
    assert!(learn::LearnService::from_values(None, None, "").is_none());
    assert!(learn::LearnService::from_values(Some(&d), None, "").is_none());
    assert!(learn::LearnService::from_values(Some(""), Some(&k), "").is_none());
    let svc = learn::LearnService::from_values(Some(&d), Some(&k), "").expect("on");
    assert!(svc.status()["enabled"].as_bool().unwrap());
}
