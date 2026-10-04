//! HUP-S3.3 + S3.7, the rest of US-3.3, over the real control-plane routes (tower::oneshot).
//!
//! - `POST /sessions/:id/track_workflows {"workflow": id}` runs a track's catalog workflow in a
//!   session. One BDD scenario group per track (the Gherkin is in agent-loop `PERSONAS.md`): a
//!   model that satisfies the verifiers finishes; a model that only claims success does not.
//! - A workflow that needs a tool the session does not offer is refused before it starts.
//! - `POST /sessions` with a persona: the skill allowlist decides the skills offered, the tool
//!   emphasis pins the session's own tools. Nothing is granted.

use super::*;
use axum::body::Body;
use axum::http::{Request, StatusCode};
use citrate_agent_loop::skills::{SkillLibrary, SkillSource, SKILL_LOAD_TOOL};
use citrate_agent_loop::verifiers_tooling::{
    verify_forge_test_output, verify_medusa_output, verify_sarif_output, SarifProfile, Severity,
    ToolchainEnvelope, ADERYN_SCAN_TOOL, FORGE_TEST_TOOL, MEDUSA_FUZZ_TOOL, SLITHER_SCAN_TOOL,
};
use citrate_agent_loop::workflows::{find_workflow, VerifierSpec, WorkflowSpec};
use citrate_agent_loop::{
    AssistantTurn, CompletionRequest, LlmClient, LlmError, ToolCall, ToolHost, ToolOutcome,
};
use std::collections::BTreeSet;
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::Mutex;
use std::time::Duration;
use tower::ServiceExt;

const BEARER: &str = "test-bearer-token-trackwf-0123";
static N: AtomicUsize = AtomicUsize::new(0);

// ---- harness ---------------------------------------------------------------------------------

struct Scratch(PathBuf);
impl Scratch {
    fn new() -> Self {
        let p = std::env::temp_dir().join(format!(
            "citrate-sidecar-trackwf-{}-{}",
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

fn skill(root: &Path, name: &str) {
    let dir = root.join(name);
    std::fs::create_dir_all(&dir).unwrap();
    std::fs::write(
        dir.join("SKILL.md"),
        format!("---\nname: {name}\ndescription: The {name} skill\n---\nBody of {name}.\n"),
    )
    .unwrap();
}

fn fixture(name: &str) -> String {
    let p = Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("../agent-loop/tests/fixtures/toolchain")
        .join(name);
    std::fs::read_to_string(&p).unwrap_or_else(|e| panic!("{}: {e}", p.display()))
}

/// A toolchain that answers with real reports judged by the real parsers (no binaries run).
/// `slither` picks the slither report, so a High finding can be injected.
#[derive(Clone)]
struct CannedToolchain {
    slither: &'static str,
}
impl ToolHost for CannedToolchain {
    fn execute(&self, c: &ToolCall) -> ToolOutcome {
        let verdict = match c.name.as_str() {
            FORGE_TEST_TOOL => verify_forge_test_output(&fixture("forge-test-pass.json")),
            SLITHER_SCAN_TOOL => verify_sarif_output(
                &fixture(self.slither),
                SarifProfile::Slither,
                Severity::High,
            ),
            ADERYN_SCAN_TOOL => verify_sarif_output(
                &fixture("aderyn-lows-only.sarif"),
                SarifProfile::Aderyn,
                Severity::High,
            ),
            MEDUSA_FUZZ_TOOL => verify_medusa_output(&fixture("medusa-pass.txt")),
            other => return ToolOutcome::Error(format!("{other} is not a toolchain tool")),
        };
        ToolOutcome::Ok(ToolchainEnvelope::completed(&c.name, verdict).to_content())
    }
}
impl sessions::ToolchainBackend for CannedToolchain {
    fn scoped_to(&self, _grants: Arc<grants::SessionGrants>) -> Result<Arc<dyn ToolHost>, String> {
        Ok(Arc::new(self.clone()))
    }
}

struct Recorder {
    turns: Mutex<Vec<AssistantTurn>>,
    seen: Mutex<Vec<CompletionRequest>>,
}
impl LlmClient for Recorder {
    fn complete(&self, req: &CompletionRequest) -> Result<AssistantTurn, LlmError> {
        self.seen.lock().unwrap().push(req.clone());
        let mut t = self.turns.lock().unwrap();
        Ok(if t.is_empty() {
            AssistantTurn::text("All done, everything passed.")
        } else {
            t.remove(0)
        })
    }
}

struct Opts {
    toolchain: Option<CannedToolchain>,
    skills: Option<Arc<SkillLibrary>>,
}

fn state(turns: Vec<AssistantTurn>, o: Opts) -> (Arc<AppState>, Arc<Recorder>) {
    let rec = Arc::new(Recorder {
        turns: Mutex::new(turns),
        seen: Mutex::new(vec![]),
    });
    let r2 = rec.clone();
    let mut mgr = sessions::SessionManager::new(
        Arc::new(move |_ep: &sessions::LlmEndpoint| r2.clone() as Arc<dyn LlmClient>),
        Duration::from_secs(5),
    );
    if let Some(t) = o.toolchain {
        mgr = mgr.with_toolchain(Arc::new(t));
    }
    if let Some(lib) = o.skills {
        mgr = mgr.with_skills(lib);
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

fn plain() -> Opts {
    Opts {
        toolchain: None,
        skills: None,
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

/// A core-hosted tool, as core declares it (read-only, trusted).
fn core_tool(name: &str) -> serde_json::Value {
    serde_json::json!({
        "name": name,
        "description": format!("the {name} tool"),
        "parameters": {"type": "object"},
        "host": "core",
        "annotations": {"effect": "none", "trust": "trusted"}
    })
}

/// The tools core offers every chat session that a track workflow reads or guards.
fn core_tools() -> serde_json::Value {
    serde_json::json!([
        core_tool("journal_read"),
        core_tool("journal_append"),
        core_tool("contract_deploy"),
        core_tool("memory_search"),
    ])
}

async fn open(st: &Arc<AppState>, extra: serde_json::Value) -> (StatusCode, serde_json::Value) {
    let mut body = serde_json::json!({
        "model": "gemma-4",
        "systemPrompt": "You are Hermes.",
        "llm": {"baseUrl": "http://127.0.0.1:18080/v1", "bearer": "k"},
        "tools": core_tools(),
        "maxToolsPerRequest": 8
    });
    if let (Some(b), Some(e)) = (body.as_object_mut(), extra.as_object()) {
        for (k, v) in e {
            b.insert(k.clone(), v.clone());
        }
    }
    call(st, "POST", "/sessions", body).await
}

async fn open_id(st: &Arc<AppState>) -> String {
    let (s, v) = open(st, serde_json::json!({})).await;
    assert_eq!(s, StatusCode::CREATED, "{v}");
    v["id"].as_str().unwrap().to_string()
}

/// Start a track workflow, answer every core tool call it makes (as core would), and poll until
/// the run leaves `running`. Returns the run view and every core call's tool name.
async fn run_track(
    st: &Arc<AppState>,
    sid: &str,
    workflow: &str,
) -> (serde_json::Value, Vec<String>) {
    let (s, v) = call(
        st,
        "POST",
        &format!("/sessions/{sid}/track_workflows"),
        serde_json::json!({ "workflow": workflow }),
    )
    .await;
    assert_eq!(s, StatusCode::ACCEPTED, "{v}");
    assert_eq!(v["workflow_id"], workflow);
    let run = v["run_id"].as_str().unwrap().to_string();
    let session = st.sessions.get(sid).unwrap();
    let mut after = 0;
    let mut core_calls = Vec::new();
    for _ in 0..400 {
        let page = session.wait_events(after, Duration::from_millis(25)).await;
        for e in page.events {
            after = after.max(e.seq);
            let ev = serde_json::to_value(&e.event).unwrap();
            if ev["type"] == "tool_call" && ev["host"] == "core" {
                let name = ev["call"]["name"].as_str().unwrap_or("").to_string();
                let id = ev["call"]["id"].as_str().unwrap_or("").to_string();
                let content = if name == "journal_read" {
                    "2026-09-30: shipped the brief screen".to_string()
                } else {
                    "ok".to_string()
                };
                session.deliver(&id, ToolOutcome::Ok(content));
                core_calls.push(name);
            }
        }
        let (s, view) = call(
            st,
            "GET",
            &format!("/sessions/{sid}/workflows/{run}"),
            serde_json::Value::Null,
        )
        .await;
        assert_eq!(s, StatusCode::OK, "{view}");
        if view["state"] != "running" {
            return (view, core_calls);
        }
    }
    panic!("workflow {workflow} did not finish");
}

/// The turns of a model that does exactly what each step's verifiers ask for.
fn satisfying_turns(wf: &WorkflowSpec) -> Vec<AssistantTurn> {
    let mut turns = Vec::new();
    for (i, st) in wf.steps.iter().enumerate() {
        let calls: Vec<ToolCall> = st
            .verifiers
            .iter()
            .filter(|v| v.requires_call())
            .filter_map(|v| v.tool())
            .collect::<BTreeSet<_>>()
            .into_iter()
            .enumerate()
            .map(|(j, t)| ToolCall {
                id: format!("c{i}-{j}"),
                name: t.to_string(),
                arguments: r#"{"project":"/p"}"#.into(),
            })
            .collect();
        if !calls.is_empty() {
            turns.push(AssistantTurn::tools(calls));
        }
        let mut answer = format!("Step {} finished.", st.id);
        for v in &st.verifiers {
            if let VerifierSpec::AnswerContains { text } = v {
                answer.push('\n');
                answer.push_str(text);
            }
        }
        turns.push(AssistantTurn::text(answer));
    }
    turns
}

fn wf(id: &str) -> WorkflowSpec {
    find_workflow(id).unwrap().unwrap_or_else(|| panic!("{id}"))
}

fn canned() -> Opts {
    Opts {
        toolchain: Some(CannedToolchain {
            slither: "slither-info-only.sarif",
        }),
        skills: None,
    }
}

/// Given a track's workflow, a satisfying model finishes it through the route and a model that
/// only claims success does not.
async fn track_scenario(workflow: &str, opts: impl Fn() -> Opts) -> Vec<String> {
    let spec = wf(workflow);
    let (st, _) = state(satisfying_turns(&spec), opts());
    let sid = open_id(&st).await;
    let (view, core_calls) = run_track(&st, &sid, workflow).await;
    assert_eq!(view["state"], "verified", "{workflow}: {view}");
    assert_eq!(
        view["evidence"]["steps"].as_array().map(|a| a.len()),
        Some(spec.steps.len()),
        "{view}"
    );
    let (st, _) = state(vec![], opts());
    let sid = open_id(&st).await;
    let (view, _) = run_track(&st, &sid, workflow).await;
    assert_eq!(
        view["state"], "unverified",
        "{workflow}: a claim of success is not success"
    );
    core_calls
}

// ---- the route -------------------------------------------------------------------------------

#[tokio::test]
async fn the_track_workflow_route_is_bearer_gated() {
    let (st, _) = state(vec![], plain());
    let r = app(st)
        .oneshot(req(
            "POST",
            "/sessions/s1/track_workflows",
            serde_json::json!({"workflow": "creative-project"}),
            false,
        ))
        .await
        .unwrap();
    assert_eq!(r.status(), StatusCode::UNAUTHORIZED);
}

#[tokio::test(flavor = "multi_thread")]
async fn an_unknown_session_workflow_or_a_bad_body_is_refused() {
    let (st, _) = state(vec![], plain());
    let (s, _) = call(
        &st,
        "POST",
        "/sessions/nope/track_workflows",
        serde_json::json!({"workflow": "creative-project"}),
    )
    .await;
    assert_eq!(s, StatusCode::NOT_FOUND);
    let sid = open_id(&st).await;
    let path = format!("/sessions/{sid}/track_workflows");
    let (s, v) = call(&st, "POST", &path, serde_json::json!({"workflow": "nope"})).await;
    assert_eq!(s, StatusCode::NOT_FOUND, "{v}");
    // The client names a catalog workflow; it cannot send its own steps through this route.
    let (s, _) = call(
        &st,
        "POST",
        &path,
        serde_json::json!({"workflow": "creative-project", "steps": []}),
    )
    .await;
    assert_eq!(s, StatusCode::BAD_REQUEST);
}

#[tokio::test(flavor = "multi_thread")]
async fn a_workflow_needing_the_toolchain_is_refused_when_it_is_off_and_names_the_tools() {
    let (st, rec) = state(vec![], plain());
    let sid = open_id(&st).await;
    let (s, v) = call(
        &st,
        "POST",
        &format!("/sessions/{sid}/track_workflows"),
        serde_json::json!({"workflow": "contract-build"}),
    )
    .await;
    assert_eq!(s, StatusCode::UNPROCESSABLE_ENTITY, "{v}");
    let err = v["error"].as_str().unwrap();
    assert!(err.contains("toolchain") && err.contains("off"), "{err}");
    let missing: Vec<&str> = v["missing_tools"]
        .as_array()
        .unwrap()
        .iter()
        .filter_map(|t| t.as_str())
        .collect();
    for t in [
        FORGE_TEST_TOOL,
        SLITHER_SCAN_TOOL,
        ADERYN_SCAN_TOOL,
        MEDUSA_FUZZ_TOOL,
    ] {
        assert!(missing.contains(&t), "{t} in {missing:?}");
    }
    assert!(rec.seen.lock().unwrap().is_empty(), "nothing started");
}

#[tokio::test(flavor = "multi_thread")]
async fn a_workflow_needing_a_core_tool_the_session_lacks_is_refused() {
    let (st, _) = state(vec![], plain());
    let (s, v) = open(&st, serde_json::json!({"tools": []})).await;
    assert_eq!(s, StatusCode::CREATED, "{v}");
    let sid = v["id"].as_str().unwrap();
    let (s, v) = call(
        &st,
        "POST",
        &format!("/sessions/{sid}/track_workflows"),
        serde_json::json!({"workflow": "status-note"}),
    )
    .await;
    assert_eq!(s, StatusCode::UNPROCESSABLE_ENTITY, "{v}");
    assert_eq!(v["missing_tools"], serde_json::json!(["journal_read"]));
    assert!(v["error"].as_str().unwrap().contains("journal_read"), "{v}");
}

#[tokio::test(flavor = "multi_thread")]
async fn the_workflow_listing_says_which_workflows_this_sidecar_cannot_run() {
    let (st, _) = state(vec![], plain());
    let (s, v) = call(&st, "GET", "/workflows", serde_json::Value::Null).await;
    assert_eq!(s, StatusCode::OK);
    let by_id = |id: &str| {
        v.as_array()
            .unwrap()
            .iter()
            .find(|w| w["id"] == id)
            .cloned()
            .unwrap()
    };
    let hello = by_id("hello-mint");
    assert!(hello["unavailable"].as_str().unwrap().contains("toolchain"));
    assert!(hello["needs_tools"]
        .as_array()
        .unwrap()
        .contains(&serde_json::json!(FORGE_TEST_TOOL)));
    assert!(by_id("creative-project")["unavailable"].is_null());
    // With the toolchain on, nothing is unavailable here.
    let (st, _) = state(vec![], canned());
    let (_, v) = call(&st, "GET", "/workflows", serde_json::Value::Null).await;
    assert!(v
        .as_array()
        .unwrap()
        .iter()
        .all(|w| w["unavailable"].is_null()));
}

// ---- BDD, one scenario group per track -------------------------------------------------------

#[tokio::test(flavor = "multi_thread")]
async fn track_creative_runs_through_the_route_and_never_deploys() {
    let calls = track_scenario("creative-project", plain).await;
    assert!(!calls.iter().any(|c| c == "contract_deploy"));
    track_scenario("copy-pass", plain).await;
}

#[tokio::test(flavor = "multi_thread")]
async fn track_code_runs_through_the_route() {
    track_scenario("code-change", plain).await;
    track_scenario("solidity-red-green", canned).await;
}

#[tokio::test(flavor = "multi_thread")]
async fn track_smart_contract_is_judged_by_the_toolchain_reports() {
    track_scenario("contract-build", canned).await;
    track_scenario("audit-a-contract", canned).await;
    // A High slither finding fails the workflow whatever the model says.
    let spec = wf("contract-build");
    let (st, _) = state(
        satisfying_turns(&spec),
        Opts {
            toolchain: Some(CannedToolchain {
                slither: "slither-high.sarif",
            }),
            skills: None,
        },
    );
    let sid = open_id(&st).await;
    let (view, _) = run_track(&st, &sid, "contract-build").await;
    assert_eq!(view["state"], "unverified", "{view}");
}

#[tokio::test(flavor = "multi_thread")]
async fn track_project_management_reads_the_journal_and_never_appends_before_approval() {
    let calls = track_scenario("status-note", plain).await;
    assert!(calls.iter().any(|c| c == "journal_read"), "{calls:?}");
    assert!(!calls.iter().any(|c| c == "journal_append"));
    track_scenario("project-plan", plain).await;
    // A model that appends to the journal before approval fails the plan step.
    let spec = wf("project-plan");
    let mut turns = vec![AssistantTurn::tools(vec![ToolCall {
        id: "j1".into(),
        name: "journal_append".into(),
        arguments: r#"{"text":"plan"}"#.into(),
    }])];
    turns.extend(satisfying_turns(&spec));
    let (st, _) = state(turns, plain());
    let sid = open_id(&st).await;
    let (view, _) = run_track(&st, &sid, "project-plan").await;
    assert_ne!(view["state"], "verified", "{view}");
}

#[tokio::test(flavor = "multi_thread")]
async fn track_full_project_hello_mint_ends_at_the_ceremony_and_never_deploys() {
    let calls = track_scenario("hello-mint", canned).await;
    assert!(!calls.iter().any(|c| c == "contract_deploy"));
    track_scenario("launch-checklist", plain).await;
    // A model that calls contract_deploy inside the workflow does not pass.
    let spec = wf("hello-mint");
    let mut turns = vec![AssistantTurn::tools(vec![ToolCall {
        id: "d1".into(),
        name: "contract_deploy".into(),
        arguments: "{}".into(),
    }])];
    turns.extend(satisfying_turns(&spec));
    let (st, _) = state(turns, canned());
    let sid = open_id(&st).await;
    let (view, _) = run_track(&st, &sid, "hello-mint").await;
    assert_ne!(view["state"], "verified", "{view}");
}

// ---- personas in sessions --------------------------------------------------------------------

fn library(names: &[&str]) -> (Scratch, Arc<SkillLibrary>) {
    let s = Scratch::new();
    for n in names {
        skill(&s.0, n);
    }
    let lib = SkillLibrary::load(&[SkillSource::new("bundled", &s.0)]);
    (s, Arc::new(lib))
}

#[tokio::test(flavor = "multi_thread")]
async fn a_persona_session_offers_only_allowlisted_skills_and_pins_its_tools() {
    // Maker: allowlist includes frontend-design and copywriting; planset is not on it.
    let (_s, lib) = library(&["frontend-design", "copywriting", "planset"]);
    let (st, rec) = state(
        vec![AssistantTurn::text("Three directions.")],
        Opts {
            toolchain: None,
            skills: Some(lib),
        },
    );
    // One retrieval slot per request, so only pinned tools are sure to be offered.
    let mut tools: Vec<serde_json::Value> = (0..10)
        .map(|i| core_tool(&format!("hello_tool_{i}")))
        .collect();
    tools.push(core_tool("memory_search"));
    let (s, v) = open(
        &st,
        serde_json::json!({"persona": "maker", "tools": tools, "maxToolsPerRequest": 1}),
    )
    .await;
    assert_eq!(s, StatusCode::CREATED, "{v}");
    let p = &v["persona"];
    assert_eq!(p["id"], "maker");
    assert_eq!(p["skills_restricted"], true);
    assert_eq!(
        p["skills_offered"],
        serde_json::json!(["copywriting", "frontend-design"])
    );
    assert!(p["skills_missing"]
        .as_array()
        .unwrap()
        .contains(&serde_json::json!("impeccable")));
    // Maker's emphasis is skill_load then memory_search; both are offered, so both are pinned.
    assert_eq!(
        p["pinned_tools"],
        serde_json::json!([SKILL_LOAD_TOOL, "memory_search"])
    );
    let sid = v["id"].as_str().unwrap().to_string();
    st.sessions.send(&sid, "hello".into(), None).unwrap();
    let session = st.sessions.get(&sid).unwrap();
    let mut after = 0;
    for _ in 0..200 {
        let page = session.wait_events(after, Duration::from_millis(25)).await;
        let done = page.events.iter().any(|e| e.event.kind() == "done");
        after = page.events.iter().map(|e| e.seq).max().unwrap_or(after);
        if done {
            break;
        }
    }
    let seen = rec.seen.lock().unwrap();
    let first = &seen[0];
    let system = &first.messages[0].content;
    assert!(system.contains("frontend-design"), "{system}");
    assert!(
        !system.contains("planset"),
        "not on the allowlist: {system}"
    );
    let names: Vec<&str> = first.tools.iter().map(|t| t.name.as_str()).collect();
    assert!(names.contains(&"memory_search"), "{names:?}");
    assert!(names.contains(&SKILL_LOAD_TOOL), "{names:?}");
}

#[tokio::test(flavor = "multi_thread")]
async fn skill_load_refuses_a_skill_outside_the_persona_allowlist() {
    let (_s, lib) = library(&["frontend-design", "planset"]);
    let load = |name: &str, id: &str| ToolCall {
        id: id.into(),
        name: SKILL_LOAD_TOOL.into(),
        arguments: serde_json::json!({ "name": name }).to_string(),
    };
    let (st, _) = state(
        vec![
            AssistantTurn::tools(vec![load("planset", "k1"), load("frontend-design", "k2")]),
            AssistantTurn::text("ok"),
        ],
        Opts {
            toolchain: None,
            skills: Some(lib),
        },
    );
    let (s, v) = open(&st, serde_json::json!({"persona": "maker"})).await;
    assert_eq!(s, StatusCode::CREATED, "{v}");
    let sid = v["id"].as_str().unwrap().to_string();
    st.sessions.send(&sid, "load skills".into(), None).unwrap();
    let session = st.sessions.get(&sid).unwrap();
    let mut after = 0;
    let mut results = std::collections::BTreeMap::new();
    for _ in 0..200 {
        let page = session.wait_events(after, Duration::from_millis(25)).await;
        let mut done = false;
        for e in page.events {
            after = after.max(e.seq);
            let ev = serde_json::to_value(&e.event).unwrap();
            if ev["type"] == "tool_result" {
                results.insert(
                    ev["call_id"].as_str().unwrap().to_string(),
                    (ev["status"].clone(), ev["content"].clone()),
                );
            }
            done |= ev["type"] == "done";
        }
        if done {
            break;
        }
    }
    let (planset_status, _) = &results["k1"];
    assert_ne!(planset_status, "ok", "planset is not on Maker's allowlist");
    let (fd_status, fd_body) = &results["k2"];
    assert_eq!(fd_status, "ok");
    assert!(fd_body
        .as_str()
        .unwrap()
        .contains("Body of frontend-design"));
}

#[tokio::test(flavor = "multi_thread")]
async fn an_allowlist_with_nothing_installed_offers_no_skills_at_all() {
    let (_s, lib) = library(&["planset"]);
    let (st, _) = state(
        vec![],
        Opts {
            toolchain: None,
            skills: Some(lib),
        },
    );
    let (s, v) = open(&st, serde_json::json!({"persona": "auditor"})).await;
    assert_eq!(s, StatusCode::CREATED, "{v}");
    assert_eq!(v["persona"]["skills_offered"], serde_json::json!([]));
    let sid = v["id"].as_str().unwrap();
    let tools = st.sessions.get(sid).unwrap().tool_names();
    assert!(!tools.iter().any(|t| t == SKILL_LOAD_TOOL), "{tools:?}");
    // Auditor's emphasised toolchain tools are not offered here, so none is pinned (never granted).
    assert_eq!(v["persona"]["pinned_tools"], serde_json::json!([]));
}

#[tokio::test(flavor = "multi_thread")]
async fn a_custom_persona_without_skills_leaves_the_skills_unchanged() {
    let (_s, lib) = library(&["planset", "red-green"]);
    let (st, _) = state(
        vec![],
        Opts {
            toolchain: None,
            skills: Some(lib),
        },
    );
    let (s, v) = open(
        &st,
        serde_json::json!({"customPersona": {
            "id": "custom-night-owl",
            "name": "Night Owl",
            "summary": "Late-night pair programmer.",
            "voice": "Quiet.",
            "tone": "Dry.",
            "style_rules": ["Lead with the answer."],
            "default_track": "code",
            "tool_emphasis": ["journal_read"]
        }}),
    )
    .await;
    assert_eq!(s, StatusCode::CREATED, "{v}");
    let p = &v["persona"];
    assert_eq!(p["skills_restricted"], false);
    assert_eq!(
        p["skills_offered"],
        serde_json::json!(["planset", "red-green"])
    );
    assert_eq!(p["pinned_tools"], serde_json::json!(["journal_read"]));
}

#[tokio::test(flavor = "multi_thread")]
async fn an_unknown_persona_or_two_at_once_is_refused_and_no_persona_changes_nothing() {
    let (st, _) = state(vec![], plain());
    let (s, v) = open(&st, serde_json::json!({"persona": "nobody"})).await;
    assert_eq!(s, StatusCode::BAD_REQUEST, "{v}");
    let (s, _) = open(
        &st,
        serde_json::json!({"persona": "maker", "customPersona": {
            "id": "custom-x", "name": "X", "summary": "s", "voice": "v", "tone": "t",
            "style_rules": ["r"], "default_track": "code"
        }}),
    )
    .await;
    assert_eq!(s, StatusCode::BAD_REQUEST);
    let (s, v) = open(&st, serde_json::json!({})).await;
    assert_eq!(s, StatusCode::CREATED);
    assert!(v.get("persona").is_none(), "{v}");
}

#[tokio::test(flavor = "multi_thread")]
async fn the_persona_listing_says_which_allowlisted_skills_are_installed() {
    let (_s, lib) = library(&["frontend-design", "planset"]);
    let (st, _) = state(
        vec![],
        Opts {
            toolchain: None,
            skills: Some(lib),
        },
    );
    let (s, v) = call(&st, "GET", "/personas", serde_json::Value::Null).await;
    assert_eq!(s, StatusCode::OK);
    let by_id = |id: &str| {
        v.as_array()
            .unwrap()
            .iter()
            .find(|p| p["id"] == id)
            .cloned()
            .unwrap()
    };
    assert_eq!(
        by_id("maker")["skills_installed"],
        serde_json::json!(["frontend-design"])
    );
    assert_eq!(
        by_id("steward")["skills_installed"],
        serde_json::json!(["planset"])
    );
    assert!(by_id("maker")["prompt_fragment"].is_string());
}
