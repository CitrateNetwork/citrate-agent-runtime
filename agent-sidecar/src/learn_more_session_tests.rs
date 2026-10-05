//! HUP-S3.4 (fan-out 5): the rest of verified self-learning in the sidecar.
//! - An accepted skill is offered to the next session without a sidecar restart.
//! - The member resolves a contradiction between two accepted memories: keep one, retract the
//!   other. The decision is HIC-1, recorded first, and closed by the e-stop like every learn write.

use super::*;
use axum::body::Body;
use axum::http::{Request, StatusCode};
use citrate_agent_loop::skills::{SkillSource, SKILL_LOAD_TOOL};
use citrate_agent_loop::{AssistantTurn, CompletionRequest, LlmClient, LlmError, ToolCall};
use std::sync::Mutex;
use std::time::Duration;
use tower::ServiceExt;

const BEARER: &str = "test-bearer-token-0123456789";
const SKILL: &str = "---\nname: deploy-checklist\ndescription: Checks a contract before deploy\n---\n\n1. Run the tests.\n";

/// A scripted model that records every request it was sent.
struct Recorder {
    turns: Mutex<Vec<AssistantTurn>>,
    seen: Mutex<Vec<CompletionRequest>>,
}
impl LlmClient for Recorder {
    fn complete(&self, req: &CompletionRequest) -> Result<AssistantTurn, LlmError> {
        self.seen.lock().unwrap().push(req.clone());
        let mut t = self.turns.lock().unwrap();
        Ok(if t.is_empty() {
            AssistantTurn::text("(done)")
        } else {
            t.remove(0)
        })
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
    fn skills_dir(&self) -> std::path::PathBuf {
        self.root.path().join("skills")
    }
    fn service(&self) -> Arc<learn::LearnService> {
        Arc::new(
            learn::LearnService::open(&self.root.path().join("learn"), &self.skills_dir(), vec![])
                .unwrap(),
        )
    }
}

fn state(
    turns: Vec<AssistantTurn>,
    learn: Option<Arc<learn::LearnService>>,
    sources: Vec<SkillSource>,
) -> (Arc<AppState>, Arc<Recorder>) {
    let rec = Arc::new(Recorder {
        turns: Mutex::new(turns),
        seen: Mutex::new(vec![]),
    });
    let r2 = rec.clone();
    let mut mgr = sessions::SessionManager::new(
        Arc::new(move |_ep: &sessions::LlmEndpoint| r2.clone() as Arc<dyn LlmClient>),
        Duration::from_secs(5),
    );
    if let Some(l) = learn {
        mgr = mgr.with_learn(l);
    }
    if !sources.is_empty() {
        mgr = mgr.with_skill_sources(sources);
    }
    let st = Arc::new(AppState {
        estop: EmergencyStop::new(),
        queue: Arc::new(ApprovalQueue::new()),
        skills: vec![],
        dispatch: None,
        bearer: BEARER.to_string(),
        run_slots: Arc::new(tokio::sync::Semaphore::new(MAX_CONCURRENT_SKILLS)),
        sessions: Arc::new(mgr),
    });
    (st, rec)
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

/// Send one message and wait for the turn to finish.
async fn send(st: &Arc<AppState>, sid: &str, text: &str) {
    let (s, v) = call(
        st,
        "POST",
        &format!("/sessions/{sid}/messages"),
        serde_json::json!({ "text": text }),
    )
    .await;
    assert_eq!(s, StatusCode::ACCEPTED, "{v}");
    let mut after = 0u64;
    for _ in 0..100 {
        let (_, page) = call(
            st,
            "GET",
            &format!("/sessions/{sid}/events?after={after}&wait_ms=100"),
            serde_json::Value::Null,
        )
        .await;
        for e in page["events"].as_array().cloned().unwrap_or_default() {
            after = after.max(e["seq"].as_u64().unwrap_or(0));
            if e["event"]["type"] == "done" {
                return;
            }
        }
    }
    panic!("the turn did not finish");
}

/// Run a one-step workflow that passes when the answer mentions `needle`; returns the run id.
async fn verified_run(st: &Arc<AppState>, sid: &str, needle: &str) -> String {
    let wf = serde_json::json!({
        "id": "check",
        "steps": [{
            "id": "answer",
            "instruction": "Say whether the checks pass.",
            "max_attempts": 1,
            "verifiers": [{"kind": "answer_contains", "text": needle}]
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
        if v["state"] == "verified" {
            return run;
        }
        assert_ne!(v["state"], "unverified", "{v}");
        tokio::time::sleep(Duration::from_millis(20)).await;
    }
    panic!("the workflow did not finish");
}

async fn propose(
    st: &Arc<AppState>,
    sid: &str,
    run: &str,
    content: serde_json::Value,
) -> serde_json::Value {
    let (s, p) = call(
        st,
        "POST",
        "/learn/proposals",
        serde_json::json!({"session_id": sid, "run_id": run, "content": content}),
    )
    .await;
    assert_eq!(s, StatusCode::CREATED, "{p}");
    p
}

fn system_prompt(req: &CompletionRequest) -> String {
    req.messages
        .first()
        .map(|m| m.content.clone())
        .unwrap_or_default()
}

// ---- an accepted skill joins the next session ------------------------------------------------

#[tokio::test(flavor = "multi_thread")]
async fn an_accepted_skill_is_offered_to_the_next_session_without_a_restart() {
    let fx = Fx::new();
    let (st, rec) = state(
        vec![AssistantTurn::text("All checks pass.")],
        Some(fx.service()),
        vec![SkillSource::new("user", fx.skills_dir())],
    );
    let sid = open_session(&st).await;
    let run = verified_run(&st, &sid, "checks pass").await;
    let p = propose(
        &st,
        &sid,
        &run,
        serde_json::json!({"kind": "skill", "skill_md": SKILL}),
    )
    .await;

    // Before the accept a new session is offered no skills at all.
    let before = open_session(&st).await;
    send(&st, &before, "hello").await;
    {
        let seen = rec.seen.lock().unwrap();
        let last = seen.last().unwrap();
        assert!(!system_prompt(last).contains("deploy-checklist"));
        assert!(last.tools.iter().all(|t| t.name != SKILL_LOAD_TOOL));
    }

    let (s, v) = call(
        &st,
        "POST",
        &format!("/learn/proposals/{}/accept", p["id"].as_str().unwrap()),
        serde_json::json!({"member": "0xmember"}),
    )
    .await;
    assert_eq!(s, StatusCode::OK, "{v}");
    assert_eq!(v["skills_reloaded"], true, "{v}");
    assert_eq!(v["skills_offered"], 1, "{v}");

    // The next session sees the skill in its index and can load it.
    let after = open_session(&st).await;
    send(&st, &after, "check my contract before deploy").await;
    let seen = rec.seen.lock().unwrap();
    let last = seen.last().unwrap();
    assert!(
        system_prompt(last).contains("- deploy-checklist: Checks a contract before deploy"),
        "{}",
        system_prompt(last)
    );
    assert!(last.tools.iter().any(|t| t.name == SKILL_LOAD_TOOL));
}

/// Fan-out 7 (L02): the session the member is already in sees an accepted skill on its next
/// turn, in its per-turn index and through `skill_load`, without a sidecar restart.
#[tokio::test(flavor = "multi_thread")]
async fn an_accepted_skill_reaches_an_open_session_on_its_next_turn() {
    let fx = Fx::new();
    // A session opened with a skills library: another source already holds one skill.
    let team = fx.root.path().join("team");
    let other = team.join("release-notes");
    std::fs::create_dir_all(&other).unwrap();
    std::fs::write(
        other.join("SKILL.md"),
        "---\nname: release-notes\ndescription: Drafts release notes\n---\n\nList the changes.\n",
    )
    .unwrap();
    let load = ToolCall {
        id: "k1".into(),
        name: SKILL_LOAD_TOOL.into(),
        arguments: r#"{"name":"deploy-checklist"}"#.into(),
    };
    let (st, rec) = state(
        vec![
            AssistantTurn::text("All checks pass."),
            AssistantTurn::text("Nothing to check yet."),
            AssistantTurn::tools(vec![load]),
            AssistantTurn::text("Done."),
        ],
        Some(fx.service()),
        vec![
            SkillSource::new("user", fx.skills_dir()),
            SkillSource::new("team", &team),
        ],
    );
    let sid = open_session(&st).await;
    let run = verified_run(&st, &sid, "checks pass").await;
    let p = propose(
        &st,
        &sid,
        &run,
        serde_json::json!({"kind": "skill", "skill_md": SKILL}),
    )
    .await;

    // Before the accept, this session's turn does not offer the proposed skill.
    send(&st, &sid, "check my contract before deploy").await;
    {
        let seen = rec.seen.lock().unwrap();
        let last = seen.last().unwrap();
        assert!(
            !system_prompt(last).contains("deploy-checklist"),
            "{}",
            system_prompt(last)
        );
        assert!(last.tools.iter().any(|t| t.name == SKILL_LOAD_TOOL));
    }

    let (s, v) = call(
        &st,
        "POST",
        &format!("/learn/proposals/{}/accept", p["id"].as_str().unwrap()),
        serde_json::json!({"member": "0xmember"}),
    )
    .await;
    assert_eq!(s, StatusCode::OK, "{v}");
    assert_eq!(v["skills_reloaded"], true, "{v}");
    assert_eq!(v["skills_offered"], 2, "{v}");

    // The same session's next turn ranks the skill into its prompt and can load its body.
    let n = rec.seen.lock().unwrap().len();
    send(&st, &sid, "check my contract before deploy").await;
    let seen = rec.seen.lock().unwrap();
    let first = seen.get(n).unwrap();
    assert!(
        system_prompt(first).contains("- deploy-checklist: Checks a contract before deploy"),
        "{}",
        system_prompt(first)
    );
    let after_load = seen.get(n + 1).unwrap();
    assert!(
        after_load
            .messages
            .iter()
            .any(|m| m.content.contains("1. Run the tests.")),
        "skill_load returned the accepted skill's body"
    );
}

/// A refresh never widens a persona's allowlist, and a reload that leaves no skills empties the
/// open session's view.
#[test]
fn a_live_refresh_keeps_the_persona_allowlist() {
    let fx = Fx::new();
    for (name, desc) in [
        ("deploy-checklist", "Checks a contract"),
        ("release-notes", "Drafts notes"),
    ] {
        let d = fx.skills_dir().join(name);
        std::fs::create_dir_all(&d).unwrap();
        std::fs::write(
            d.join("SKILL.md"),
            format!("---\nname: {name}\ndescription: {desc}\n---\n\nBody.\n"),
        )
        .unwrap();
    }
    let lib = Arc::new(citrate_agent_loop::skills::SkillLibrary::load(&[
        SkillSource::new("user", fx.skills_dir()),
    ]));
    let live = sessions::LiveSkills::new(
        Arc::new(citrate_agent_loop::skills::SkillLibrary::empty()),
        Some(vec!["release-notes".to_string()]),
    );
    live.refresh(Some(&lib));
    assert_eq!(live.current().names(), vec!["release-notes"]);
    let open = sessions::LiveSkills::new(
        Arc::new(citrate_agent_loop::skills::SkillLibrary::empty()),
        None,
    );
    open.refresh(Some(&lib));
    assert_eq!(open.current().len(), 2);
    open.refresh(None);
    assert!(open.current().is_empty());
}

#[tokio::test(flavor = "multi_thread")]
async fn without_skill_sources_the_accept_says_the_skill_waits_for_a_restart() {
    let fx = Fx::new();
    let (st, _) = state(
        vec![AssistantTurn::text("All checks pass.")],
        Some(fx.service()),
        vec![],
    );
    let sid = open_session(&st).await;
    let run = verified_run(&st, &sid, "checks pass").await;
    let p = propose(
        &st,
        &sid,
        &run,
        serde_json::json!({"kind": "skill", "skill_md": SKILL}),
    )
    .await;
    let (s, v) = call(
        &st,
        "POST",
        &format!("/learn/proposals/{}/accept", p["id"].as_str().unwrap()),
        serde_json::json!({"member": "0xmember"}),
    )
    .await;
    assert_eq!(s, StatusCode::OK, "{v}");
    assert_eq!(v["skills_reloaded"], false, "{v}");
    assert!(v.get("skills_offered").is_none(), "{v}");
}

#[test]
fn a_reload_reads_the_sources_again_and_a_fixed_library_is_not_reloaded() {
    let fx = Fx::new();
    let mk = || {
        sessions::SessionManager::new(
            Arc::new(|_ep: &sessions::LlmEndpoint| {
                Arc::new(Recorder {
                    turns: Mutex::new(vec![]),
                    seen: Mutex::new(vec![]),
                }) as Arc<dyn LlmClient>
            }),
            Duration::from_secs(5),
        )
    };
    let mgr = mk().with_skill_sources(vec![SkillSource::new("user", fx.skills_dir())]);
    assert!(mgr.skills().is_none(), "an empty folder offers nothing");
    let dir = fx.skills_dir().join("deploy-checklist");
    std::fs::create_dir_all(&dir).unwrap();
    std::fs::write(dir.join("SKILL.md"), SKILL).unwrap();
    assert!(
        mgr.skills().is_none(),
        "nothing changes until a reload is asked for"
    );
    assert_eq!(mgr.reload_skills(), Some(1));
    assert!(mgr.skills().unwrap().get("deploy-checklist").is_some());
    std::fs::remove_dir_all(&dir).unwrap();
    assert_eq!(mgr.reload_skills(), Some(0));
    assert!(mgr.skills().is_none());

    let fixed = mk().with_skills(Arc::new(citrate_agent_loop::skills::SkillLibrary::load(&[
        SkillSource::new("user", fx.skills_dir()),
    ])));
    assert_eq!(fixed.reload_skills(), None);
}

// ---- resolving a contradiction -----------------------------------------------------------------

/// Two accepted memories that disagree; returns (first, second) proposal ids.
async fn two_contradicting(st: &Arc<AppState>) -> (String, String) {
    let sid = open_session(st).await;
    let run = verified_run(st, &sid, "checks pass").await;
    let a = propose(
        st,
        &sid,
        &run,
        serde_json::json!({"kind": "memory", "key": "test command", "value": "forge test"}),
    )
    .await;
    let a = a["id"].as_str().unwrap().to_string();
    let (s, v) = call(
        st,
        "POST",
        &format!("/learn/proposals/{a}/accept"),
        serde_json::json!({"member": "0xmember"}),
    )
    .await;
    assert_eq!(s, StatusCode::OK, "{v}");
    let b = propose(
        st,
        &sid,
        &run,
        serde_json::json!({"kind": "memory", "key": "test command", "value": "npm test"}),
    )
    .await;
    let b = b["id"].as_str().unwrap().to_string();
    let (s, v) = call(
        st,
        "POST",
        &format!("/learn/proposals/{b}/accept"),
        serde_json::json!({"member": "0xmember", "acknowledged_conflicts": [format!("proposal:{a}")]}),
    )
    .await;
    assert_eq!(s, StatusCode::OK, "{v}");
    assert_eq!(v["persisted"]["belnap"], "both");
    (a, b)
}

#[tokio::test(flavor = "multi_thread")]
async fn the_member_resolves_a_contradiction_through_the_route() {
    let fx = Fx::new();
    let (st, _) = state(
        vec![AssistantTurn::text("All checks pass.")],
        Some(fx.service()),
        vec![],
    );
    let (a, b) = two_contradicting(&st).await;
    let (s, v) = call(
        &st,
        "POST",
        "/learn/memories/resolve",
        serde_json::json!({"member": "", "keep": b, "retract": a}),
    )
    .await;
    assert_eq!(s, StatusCode::BAD_REQUEST, "a member is required: {v}");
    let (s, v) = call(
        &st,
        "POST",
        "/learn/memories/resolve",
        serde_json::json!({"member": "0xmember", "keep": b, "retract": a, "merge": true}),
    )
    .await;
    assert_eq!(
        s,
        StatusCode::BAD_REQUEST,
        "unknown fields are refused: {v}"
    );

    let (s, v) = call(
        &st,
        "POST",
        "/learn/memories/resolve",
        serde_json::json!({"member": "0xmember", "keep": b, "retract": a}),
    )
    .await;
    assert_eq!(s, StatusCode::OK, "{v}");
    let r = &v["resolution"];
    assert_eq!(r["schema"], "citrate.learn.resolve.v1");
    assert_eq!(r["kept"], b.as_str());
    assert_eq!(r["retracted"], a.as_str());
    assert_eq!(r["kept_value"], "npm test");
    assert_eq!(r["decided_by"], "0xmember");

    let (_, one) = call(
        &st,
        "GET",
        &format!("/learn/proposals/{a}"),
        serde_json::Value::Null,
    )
    .await;
    assert_eq!(one["state"]["state"], "retracted", "{one}");
    assert_eq!(one["state"]["kept"], b.as_str());

    // A second resolve of the same pair is a conflict, not a second decision.
    let (s, v) = call(
        &st,
        "POST",
        "/learn/memories/resolve",
        serde_json::json!({"member": "0xmember", "keep": b, "retract": a}),
    )
    .await;
    assert_eq!(s, StatusCode::CONFLICT, "{v}");
    let (s, _) = call(
        &st,
        "POST",
        "/learn/memories/resolve",
        serde_json::json!({"member": "0xmember", "keep": "lp-000000000000000000000000", "retract": a}),
    )
    .await;
    assert_eq!(s, StatusCode::NOT_FOUND);
}

#[tokio::test(flavor = "multi_thread")]
async fn resolving_needs_the_bearer_learning_on_and_no_emergency_stop() {
    let (off, _) = state(vec![], None, vec![]);
    let (s, _) = call(
        &off,
        "POST",
        "/learn/memories/resolve",
        serde_json::json!({"member": "m", "keep": "a", "retract": "b"}),
    )
    .await;
    assert_eq!(s, StatusCode::SERVICE_UNAVAILABLE);

    let fx = Fx::new();
    let (st, _) = state(
        vec![AssistantTurn::text("All checks pass.")],
        Some(fx.service()),
        vec![],
    );
    let r = app(st.clone())
        .oneshot(req(
            "POST",
            "/learn/memories/resolve",
            serde_json::json!({"member": "m", "keep": "a", "retract": "b"}),
            false,
        ))
        .await
        .unwrap();
    assert_eq!(r.status(), StatusCode::UNAUTHORIZED);

    let (a, b) = two_contradicting(&st).await;
    st.estop.trigger();
    let (s, v) = call(
        &st,
        "POST",
        "/learn/memories/resolve",
        serde_json::json!({"member": "0xmember", "keep": b, "retract": a}),
    )
    .await;
    assert_eq!(s, StatusCode::SERVICE_UNAVAILABLE, "{v}");
    let (_, one) = call(
        &st,
        "GET",
        &format!("/learn/proposals/{a}"),
        serde_json::Value::Null,
    )
    .await;
    assert_eq!(one["state"]["state"], "persisted", "nothing changed: {one}");
}

/// Fan-out 7 (L02): a contradiction with a memory core holds (not learned here) is resolved
/// through the same route: keeping the learned memory sets the known one aside.
#[tokio::test(flavor = "multi_thread")]
async fn a_contradiction_with_a_known_memory_is_resolved_through_the_route() {
    let fx = Fx::new();
    let (st, _) = state(
        vec![AssistantTurn::text("All checks pass.")],
        Some(fx.service()),
        vec![],
    );
    let sid = open_session(&st).await;
    let run = verified_run(&st, &sid, "checks pass").await;
    let (s, p) = call(
        &st,
        "POST",
        "/learn/proposals",
        serde_json::json!({
            "session_id": sid,
            "run_id": run,
            "content": {"kind": "memory", "key": "deploy chain", "value": "40204"},
            "known_memories": [{"id": "mem-7", "key": "Deploy Chain", "value": "1"}]
        }),
    )
    .await;
    assert_eq!(s, StatusCode::CREATED, "{p}");
    let id = p["id"].as_str().unwrap().to_string();
    let (s, v) = call(
        &st,
        "POST",
        &format!("/learn/proposals/{id}/accept"),
        serde_json::json!({"member": "0xmember", "acknowledged_conflicts": ["memory:mem-7"]}),
    )
    .await;
    assert_eq!(s, StatusCode::OK, "{v}");
    assert_eq!(v["persisted"]["belnap"], "both", "{v}");

    let (s, v) = call(
        &st,
        "POST",
        "/learn/memories/resolve",
        serde_json::json!({"member": "0xmember", "keep": id, "retract": "memory:mem-7"}),
    )
    .await;
    assert_eq!(s, StatusCode::OK, "{v}");
    assert_eq!(v["resolution"]["kept"], id.as_str());
    assert_eq!(v["resolution"]["retracted"], "memory:mem-7");

    let (_, one) = call(
        &st,
        "GET",
        &format!("/learn/proposals/{id}"),
        serde_json::Value::Null,
    )
    .await;
    assert_eq!(one["state"]["state"], "persisted", "{one}");
    assert_eq!(one["set_aside"], serde_json::json!(["memory:mem-7"]));

    // A known memory the learned one never contradicted is refused.
    let (s, v) = call(
        &st,
        "POST",
        "/learn/memories/resolve",
        serde_json::json!({"member": "0xmember", "keep": id, "retract": "memory:mem-8"}),
    )
    .await;
    assert_eq!(s, StatusCode::CONFLICT, "{v}");
}
