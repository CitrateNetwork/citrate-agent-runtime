//! Per-session host tool-set allowlist (`toolSets`, `promptSnapshot`) for Store daemons
//! (citrate-core #356). The manager runs with search, skills, the toolchain, learning and folder
//! grants all on, and core passes one sidecar-hosted (capsule) spec, so every case shows what an
//! allowlist removes from a session that would otherwise get all of them.

use super::host_sets::set_names;
use super::toolchain::{ToolchainConfig, ToolchainHost};
use super::*;
use axum::body::Body;
use axum::http::{Request, StatusCode};
use citrate_agent_grants::FolderGrants;
use citrate_agent_loop::skills::{SkillLibrary, SkillSource, SKILL_LOAD_TOOL};
use citrate_agent_loop::{AssistantTurn, CompletionRequest, LlmClient, LlmError, ToolCall};
use citrate_agent_search::{ReadUrlConfig, SearchConfig, SearchHost};
use citrate_agent_shell::sandbox::SandboxMode;
use std::sync::Mutex;
use std::time::Duration;
use tower::ServiceExt;

const BEARER: &str = "test-bearer-token-0123456789";
const PROMPT: &str = "You are Hermes.";

struct Recorder {
    turns: Mutex<Vec<AssistantTurn>>,
    seen: Mutex<Vec<CompletionRequest>>,
}
impl LlmClient for Recorder {
    fn complete(&self, req: &CompletionRequest) -> Result<AssistantTurn, LlmError> {
        if let Ok(mut s) = self.seen.lock() {
            s.push(req.clone());
        }
        let mut t = self
            .turns
            .lock()
            .map_err(|_| LlmError::Transport("lock".into()))?;
        Ok(if t.is_empty() {
            AssistantTurn::text("(done)")
        } else {
            t.remove(0)
        })
    }
}

/// A scratch tree: `home/` (grants home), `skills/deploy-checklist/SKILL.md`, `learn/`,
/// `tc/root` (toolchain root) and `tc/bin` (an empty toolchain search path).
struct Fx {
    dir: tempfile::TempDir,
}
impl Fx {
    fn new() -> Self {
        let dir = tempfile::tempdir().expect("tempdir");
        for d in [
            "home",
            "skills/deploy-checklist",
            "learn",
            "tc/root",
            "tc/bin",
            "tc/home",
        ] {
            std::fs::create_dir_all(dir.path().join(d)).expect("mkdir");
        }
        std::fs::write(
            dir.path().join("skills/deploy-checklist/SKILL.md"),
            "---\nname: deploy-checklist\ndescription: Checks a contract before deploy\n---\n1. Run the tests.\n",
        )
        .expect("skill");
        Fx { dir }
    }
    fn p(&self, rel: &str) -> std::path::PathBuf {
        self.dir.path().join(rel)
    }
    /// A valid grant document with no folders granted (enough for the file tools to be offered).
    fn grants_doc(&self) -> serde_json::Value {
        let home = self.p("home");
        serde_json::to_value(FolderGrants::new(home.clone(), home).state()).expect("doc")
    }
}

fn state(fx: &Fx, turns: Vec<AssistantTurn>) -> (Arc<AppState>, Arc<Recorder>) {
    let rec = Arc::new(Recorder {
        turns: Mutex::new(turns),
        seen: Mutex::new(vec![]),
    });
    let r2 = rec.clone();
    let search = SearchConfig {
        read: ReadUrlConfig {
            allow_private: vec!["127.0.0.1".parse().expect("ip")],
            ..ReadUrlConfig::default()
        },
        ..SearchConfig::default()
    };
    let toolchain = ToolchainHost::new(ToolchainConfig {
        roots: vec![fx.p("tc/root")],
        search_path: vec![fx.p("tc/bin")],
        solc: None,
        home: fx.p("tc/home"),
        sandbox: SandboxMode::Off,
    })
    .expect("toolchain");
    let learn =
        crate::learn::LearnService::open(&fx.p("learn"), &fx.p("skills"), vec![]).expect("learn");
    let mgr = sessions::SessionManager::new(
        Arc::new(move |_ep: &sessions::LlmEndpoint| r2.clone() as Arc<dyn LlmClient>),
        Duration::from_secs(5),
    )
    .with_search(Arc::new(SearchHost::new(search)))
    .with_skills(Arc::new(SkillLibrary::load(&[SkillSource::new(
        "user",
        fx.p("skills"),
    )])))
    .with_toolchain(Arc::new(toolchain))
    .with_learn(Arc::new(learn))
    .with_grants_home(fx.p("home"));
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

fn req(method: &str, path: &str, body: serde_json::Value) -> Request<Body> {
    Request::builder()
        .method(method)
        .uri(path)
        .header("content-type", "application/json")
        .header("authorization", format!("Bearer {BEARER}"))
        .body(Body::from(body.to_string()))
        .expect("request")
}

async fn json(resp: axum::response::Response) -> serde_json::Value {
    let bytes = axum::body::to_bytes(resp.into_body(), 1 << 20)
        .await
        .unwrap_or_default();
    serde_json::from_slice(&bytes).unwrap_or(serde_json::Value::Null)
}

/// A session body with one core tool, one core-passed capsule spec (`host: sidecar`) and a grant
/// document; `extra` is merged in (`toolSets`, `promptSnapshot`, `persona`).
fn body(fx: &Fx, extra: serde_json::Value) -> serde_json::Value {
    let mut b = serde_json::json!({
        "model": "gemma-4",
        "systemPrompt": PROMPT,
        "llm": {"baseUrl": "http://127.0.0.1:18080/v1", "bearer": "k"},
        "tools": [
            {"name": "node_status", "description": "Read the node status", "parameters": {"type": "object"}, "host": "core"},
            {"name": "hello_capsule", "description": "An installed capsule", "parameters": {"type": "object"}, "host": "sidecar"}
        ],
        "grants": fx.grants_doc(),
        "maxToolsPerRequest": 64
    });
    if let (Some(o), Some(e)) = (b.as_object_mut(), extra.as_object()) {
        for (k, v) in e {
            o.insert(k.clone(), v.clone());
        }
    }
    b
}

async fn open(st: &Arc<AppState>, b: serde_json::Value) -> (StatusCode, serde_json::Value) {
    let r = app(st.clone())
        .oneshot(req("POST", "/sessions", b))
        .await
        .expect("create");
    let status = r.status();
    (status, json(r).await)
}

async fn run(st: &Arc<AppState>, id: &str, text: &str) -> Vec<serde_json::Value> {
    let r = app(st.clone())
        .oneshot(req(
            "POST",
            &format!("/sessions/{id}/messages"),
            serde_json::json!({ "text": text }),
        ))
        .await
        .expect("send");
    assert_eq!(r.status(), StatusCode::ACCEPTED);
    let mut all = vec![];
    let mut after = 0u64;
    for _ in 0..200 {
        let r = app(st.clone())
            .oneshot(req(
                "GET",
                &format!("/sessions/{id}/events?after={after}&wait_ms=100"),
                serde_json::Value::Null,
            ))
            .await
            .expect("events");
        let page = json(r).await;
        for e in page["events"].as_array().cloned().unwrap_or_default() {
            after = after.max(e["seq"].as_u64().unwrap_or(0));
            all.push(e["event"].clone());
        }
        if all.iter().any(|e| e["type"] == "done") {
            return all;
        }
    }
    panic!("no done event; got {all:?}");
}

fn offered(rec: &Recorder) -> Vec<String> {
    let mut v: Vec<String> = rec
        .seen
        .lock()
        .map(|s| s[0].tools.iter().map(|t| t.name.clone()).collect())
        .unwrap_or_default();
    v.sort();
    v
}

fn call(name: &str) -> ToolCall {
    ToolCall {
        id: format!("c-{name}"),
        name: name.into(),
        arguments: "{}".into(),
    }
}

/// The tool results by call name.
fn results(events: &[serde_json::Value]) -> Vec<(String, String, String)> {
    let names: std::collections::HashMap<String, String> = events
        .iter()
        .filter(|e| e["type"] == "tool_call")
        .map(|e| {
            (
                e["call"]["id"].as_str().unwrap_or_default().to_string(),
                e["call"]["name"].as_str().unwrap_or_default().to_string(),
            )
        })
        .collect();
    events
        .iter()
        .filter(|e| e["type"] == "tool_result")
        .map(|e| {
            let id = e["callId"]
                .as_str()
                .or_else(|| e["call_id"].as_str())
                .unwrap_or_default()
                .to_string();
            (
                names.get(&id).cloned().unwrap_or(id),
                e["status"].as_str().unwrap_or_default().to_string(),
                e["content"].as_str().unwrap_or_default().to_string(),
            )
        })
        .collect()
}

/// Every host tool this fixture's sidecar runs with.
const HOST_TOOLS: &[&str] = &[
    "web_search",
    "read_url",
    SKILL_LOAD_TOOL,
    "forge_test",
    "slither_scan",
    "aderyn_scan",
    "medusa_fuzz",
    "learn_propose",
    "file_list",
    "file_read",
    "hello_capsule",
];

#[tokio::test(flavor = "multi_thread")]
async fn absent_allowlist_keeps_every_host_set() {
    let fx = Fx::new();
    let (st, rec) = state(&fx, vec![]);
    let (status, v) = open(&st, body(&fx, serde_json::json!({}))).await;
    assert_eq!(status, StatusCode::CREATED, "{v}");
    assert!(v.get("toolSets").is_none(), "{v}");
    let id = v["id"].as_str().unwrap_or_default().to_string();
    run(&st, &id, "the deploy checklist for a contract").await;
    let names = offered(&rec);
    for t in HOST_TOOLS {
        assert!(names.contains(&t.to_string()), "{t} missing from {names:?}");
    }
    assert!(names.contains(&"node_status".to_string()));
    // The per-turn skill index is in the prompt, as before.
    let prompt = rec
        .seen
        .lock()
        .map(|s| s[0].messages[0].content.clone())
        .unwrap_or_default();
    assert!(prompt.contains("deploy-checklist"), "{prompt}");
}

#[tokio::test(flavor = "multi_thread")]
async fn empty_allowlist_offers_no_host_tool_and_refuses_every_host_call() {
    let fx = Fx::new();
    let calls = HOST_TOOLS.iter().map(|t| call(t)).collect::<Vec<_>>();
    let (st, rec) = state(&fx, vec![AssistantTurn::tools(calls)]);
    let (status, v) = open(
        &st,
        body(
            &fx,
            serde_json::json!({ "toolSets": [], "maxToolCallsPerStep": 16 }),
        ),
    )
    .await;
    assert_eq!(status, StatusCode::CREATED, "{v}");
    assert_eq!(v["toolSets"], serde_json::json!([]));
    let id = v["id"].as_str().unwrap_or_default().to_string();
    let events = run(&st, &id, "use every tool you have").await;
    assert_eq!(offered(&rec), vec!["node_status".to_string()]);
    let res = results(&events);
    assert_eq!(res.len(), HOST_TOOLS.len(), "{res:?}");
    for (name, status, content) in &res {
        assert_ne!(status, "ok", "{name} ran: {content}");
        assert!(content.contains("unknown tool"), "{name}: {content}");
    }
    // Nothing ran in the sidecar: no host-side tool_call was announced.
    assert!(
        events
            .iter()
            .filter(|e| e["type"] == "tool_call")
            .all(|e| e["host"].is_null()),
        "{events:?}"
    );
}

#[tokio::test(flavor = "multi_thread")]
async fn web_search_allowlist_offers_only_the_search_set() {
    let fx = Fx::new();
    let (st, rec) = state(
        &fx,
        vec![AssistantTurn::tools(vec![
            call(SKILL_LOAD_TOOL),
            call("forge_test"),
            call("file_list"),
        ])],
    );
    let (status, v) = open(
        &st,
        body(&fx, serde_json::json!({ "toolSets": ["web_search"] })),
    )
    .await;
    assert_eq!(status, StatusCode::CREATED, "{v}");
    assert_eq!(v["toolSets"], serde_json::json!(["web_search"]));
    let id = v["id"].as_str().unwrap_or_default().to_string();
    let events = run(&st, &id, "search the web").await;
    // Retrieval may leave out core tools that do not match the request; of the host tools,
    // exactly the search set is offered.
    let host_offered: Vec<String> = offered(&rec)
        .into_iter()
        .filter(|t| HOST_TOOLS.contains(&t.as_str()))
        .collect();
    assert_eq!(
        host_offered,
        vec!["read_url".to_string(), "web_search".to_string()]
    );
    for (name, status, content) in results(&events) {
        assert_ne!(status, "ok", "{name} ran: {content}");
        assert!(content.contains("unknown tool"), "{name}: {content}");
    }
}

#[tokio::test(flavor = "multi_thread")]
async fn each_allowed_set_brings_only_its_own_tools() {
    let fx = Fx::new();
    let (st, rec) = state(&fx, vec![]);
    let (status, v) = open(
        &st,
        body(
            &fx,
            serde_json::json!({ "toolSets": ["toolchain", "skills_read", "learn_propose", "capsules_run", "files"] }),
        ),
    )
    .await;
    assert_eq!(status, StatusCode::CREATED, "{v}");
    let id = v["id"].as_str().unwrap_or_default().to_string();
    run(&st, &id, "hi").await;
    let names = offered(&rec);
    for t in ["web_search", "read_url"] {
        assert!(!names.contains(&t.to_string()), "{t} offered: {names:?}");
    }
    for t in [
        SKILL_LOAD_TOOL,
        "forge_test",
        "learn_propose",
        "hello_capsule",
        "file_list",
    ] {
        assert!(names.contains(&t.to_string()), "{t} missing: {names:?}");
    }
}

#[tokio::test(flavor = "multi_thread")]
async fn an_unknown_set_name_refuses_the_session() {
    let fx = Fx::new();
    let (st, _rec) = state(&fx, vec![]);
    let (status, v) = open(
        &st,
        body(&fx, serde_json::json!({ "toolSets": ["search"] })),
    )
    .await;
    assert_eq!(status, StatusCode::BAD_REQUEST);
    assert!(
        v["error"]
            .as_str()
            .unwrap_or_default()
            .contains("unknown tool set 'search'"),
        "{v}"
    );
}

#[tokio::test(flavor = "multi_thread")]
async fn prompt_snapshot_false_keeps_the_prompt_exactly_as_sent() {
    let fx = Fx::new();
    let (st, rec) = state(&fx, vec![]);
    let (status, v) = open(
        &st,
        body(
            &fx,
            serde_json::json!({ "toolSets": ["skills_read"], "promptSnapshot": false }),
        ),
    )
    .await;
    assert_eq!(status, StatusCode::CREATED, "{v}");
    assert_eq!(v["promptSnapshot"], serde_json::json!(false));
    let id = v["id"].as_str().unwrap_or_default().to_string();
    run(&st, &id, "the deploy checklist for a contract").await;
    let seen = rec.seen.lock().map(|s| s.clone()).unwrap_or_default();
    assert_eq!(seen[0].messages[0].content, PROMPT);
    assert!(seen[0].tools.iter().any(|t| t.name == SKILL_LOAD_TOOL));
}

#[tokio::test(flavor = "multi_thread")]
async fn prompt_snapshot_false_refuses_a_persona() {
    let fx = Fx::new();
    let (st, _rec) = state(&fx, vec![]);
    let (status, v) = open(
        &st,
        body(
            &fx,
            serde_json::json!({ "promptSnapshot": false, "persona": "builder" }),
        ),
    )
    .await;
    assert_eq!(status, StatusCode::BAD_REQUEST, "{v}");
    assert!(
        v["error"]
            .as_str()
            .unwrap_or_default()
            .contains("promptSnapshot"),
        "{v}"
    );
}

#[tokio::test(flavor = "multi_thread")]
async fn status_reports_the_capability() {
    let fx = Fx::new();
    let (st, _rec) = state(&fx, vec![]);
    let r = app(st.clone())
        .oneshot(req("GET", "/status", serde_json::Value::Null))
        .await
        .expect("status");
    assert_eq!(r.status(), StatusCode::OK);
    let v = json(r).await;
    assert_eq!(
        v["capabilities"]["sessionToolSets"],
        serde_json::json!(set_names())
    );
    assert_eq!(
        v["capabilities"]["sessionPromptSnapshot"],
        serde_json::json!(true)
    );
}

/// What a sidecar-hosted call that no set host takes answers (no capsule dispatch here).
const CAPSULE_FALLTHROUGH: &str = "is not available in this session";

/// The second, execute-time check (DGX non-blocking, fed#331). With `capsules_run` allowed, core
/// can pass a sidecar-hosted spec under a host tool's name (`web_search`, `read_url`,
/// `learn_propose`, `file_list`, `file_read`, `sheet_read`): it is kept as a capsule spec, so it passes the
/// offer-time filter. At execute time the session's registry must not hold the hosts of the sets
/// it was not allowed, so these calls never reach search, learning, the folder-grant file tools
/// or the sheet tools.
#[tokio::test(flavor = "multi_thread")]
async fn a_capsule_spec_named_like_a_host_tool_never_reaches_a_disallowed_set() {
    // One session per name, so one call's taint (web_search marks the session) never decides
    // another call's result.
    for name in [
        "web_search",
        "read_url",
        "learn_propose",
        "file_list",
        "file_read",
        "sheet_read",
    ] {
        let fx = Fx::new();
        let (st, _rec) = state(&fx, vec![AssistantTurn::tools(vec![call(name)])]);
        let mut b = body(&fx, serde_json::json!({ "toolSets": ["capsules_run"] }));
        b["tools"].as_array_mut().expect("tools").push(serde_json::json!({
            "name": name, "description": "a capsule", "parameters": {"type": "object"}, "host": "sidecar"
        }));
        let (status, v) = open(&st, b).await;
        assert_eq!(status, StatusCode::CREATED, "{name}: {v}");
        assert_eq!(v["toolSets"], serde_json::json!(["capsules_run"]));
        let id = v["id"].as_str().unwrap_or_default().to_string();
        let events = run(&st, &id, "use it").await;
        let res = results(&events);
        assert_eq!(res.len(), 1, "{name}: {res:?}");
        let (_, status, content) = &res[0];
        assert_ne!(status, "ok", "{name} ran in a disallowed set: {content}");
        assert!(
            content.contains(CAPSULE_FALLTHROUGH),
            "{name} reached a set host: {content}"
        );
    }
}

// ---- The write and exec sets: shell_run, the checkpointed fs_* tools, project_create ----------

/// The manager of [`state`] plus `shell_run` (sandbox off: only the offer and refusal paths run
/// here), a checkpoint store (the grant session's fs_* tools) and projects.
fn write_state(fx: &Fx, turns: Vec<AssistantTurn>) -> (Arc<AppState>, Arc<Recorder>) {
    std::fs::create_dir_all(fx.p("home/projects")).expect("projects root");
    let rec = Arc::new(Recorder {
        turns: Mutex::new(turns),
        seen: Mutex::new(vec![]),
    });
    let r2 = rec.clone();
    let store = Arc::new(
        citrate_agent_checkpoints::CheckpointStore::open(
            &fx.p("ckpt"),
            citrate_agent_checkpoints::Config::default(),
        )
        .expect("checkpoint store"),
    );
    let shell = crate::shell_run::ShellRunConfig {
        search_path: vec!["/bin".into(), "/usr/bin".into()],
        sandbox: citrate_agent_shell::sandbox::SandboxPolicy::new(SandboxMode::Off),
        approval_timeout: Duration::from_secs(5),
        auto_approve: None,
        commit_identity: crate::shell_run::GitIdentity::hermes(),
    };
    let mgr = sessions::SessionManager::new(
        Arc::new(move |_ep: &sessions::LlmEndpoint| r2.clone() as Arc<dyn LlmClient>),
        Duration::from_secs(5),
    )
    .with_grants_home(fx.p("home"))
    .with_checkpoints(store)
    .with_shell_run(Arc::new(shell))
    .with_projects(Arc::new(crate::projects::ProjectsConfig {
        root: fx.p("home/projects"),
        renderer: None,
    }));
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

const SHELL: &str = "shell_run";
const FS_TOOLS: &[&str] = &["fs_write", "fs_edit", "fs_delete", "fs_rename"];
const PROJECT: &str = "project_create";

/// What a session with `toolSets` (`None` = absent) offers of the write and exec tools, and what
/// a call to each one returns.
async fn write_tools_for(
    sets: Option<serde_json::Value>,
) -> (Vec<String>, Vec<(String, String, String)>) {
    let fx = Fx::new();
    let mut names = vec![SHELL, PROJECT];
    names.extend_from_slice(FS_TOOLS);
    let (st, rec) = write_state(
        &fx,
        vec![AssistantTurn::tools(
            names.iter().map(|n| call(n)).collect(),
        )],
    );
    let extra = match sets {
        Some(s) => {
            serde_json::json!({ "toolSets": s, "maxToolCallsPerStep": 16, "maxToolsPerRequest": 64 })
        }
        None => serde_json::json!({ "maxToolCallsPerStep": 16, "maxToolsPerRequest": 64 }),
    };
    let (status, v) = open(&st, body(&fx, extra)).await;
    assert_eq!(status, StatusCode::CREATED, "{v}");
    let id = v["id"].as_str().unwrap_or_default().to_string();
    let events = run(&st, &id, "write a file, make a project and run a command").await;
    (offered(&rec), results(&events))
}

fn refused(res: &[(String, String, String)], name: &str) -> bool {
    res.iter()
        .any(|(n, status, content)| n == name && status != "ok" && content.contains("unknown tool"))
}

#[tokio::test(flavor = "multi_thread")]
async fn without_an_allowlist_the_fixture_offers_every_write_and_exec_tool() {
    let (offered, _) = write_tools_for(None).await;
    for t in [SHELL, PROJECT].iter().chain(FS_TOOLS) {
        assert!(
            offered.contains(&t.to_string()),
            "{t} missing from {offered:?}"
        );
    }
}

#[tokio::test(flavor = "multi_thread")]
async fn an_empty_allowlist_offers_no_write_or_exec_tool() {
    let (offered, res) = write_tools_for(Some(serde_json::json!([]))).await;
    for t in [SHELL, PROJECT].iter().chain(FS_TOOLS) {
        assert!(
            !offered.contains(&t.to_string()),
            "{t} offered: {offered:?}"
        );
        assert!(refused(&res, t), "{t} not refused: {res:?}");
    }
}

#[tokio::test(flavor = "multi_thread")]
async fn files_allows_fs_tools_and_project_create_but_not_shell_run() {
    let (offered, res) = write_tools_for(Some(serde_json::json!(["files"]))).await;
    for t in [PROJECT].iter().chain(FS_TOOLS) {
        assert!(
            offered.contains(&t.to_string()),
            "{t} missing from {offered:?}"
        );
    }
    assert!(
        !offered.contains(&SHELL.to_string()),
        "shell_run offered: {offered:?}"
    );
    assert!(refused(&res, SHELL), "shell_run not refused: {res:?}");
}

#[tokio::test(flavor = "multi_thread")]
async fn web_search_leaves_out_fs_tools_project_create_and_shell_run() {
    let (offered, res) = write_tools_for(Some(serde_json::json!(["web_search"]))).await;
    for t in [SHELL, PROJECT].iter().chain(FS_TOOLS) {
        assert!(
            !offered.contains(&t.to_string()),
            "{t} offered: {offered:?}"
        );
        assert!(refused(&res, t), "{t} not refused: {res:?}");
    }
}

#[tokio::test(flavor = "multi_thread")]
async fn shell_run_allows_shell_run_but_not_fs_tools_or_project_create() {
    let (offered, res) = write_tools_for(Some(serde_json::json!(["shell_run"]))).await;
    assert!(
        offered.contains(&SHELL.to_string()),
        "shell_run missing from {offered:?}"
    );
    for t in [PROJECT].iter().chain(FS_TOOLS) {
        assert!(
            !offered.contains(&t.to_string()),
            "{t} offered: {offered:?}"
        );
        assert!(refused(&res, t), "{t} not refused: {res:?}");
    }
}

/// The execution layer for the write sets: with only `capsules_run`, core-passed capsule specs
/// named like the fs_* tools and `project_create` reach no file or project host.
#[tokio::test(flavor = "multi_thread")]
async fn capsule_specs_named_like_write_tools_reach_no_write_host() {
    for name in ["fs_write", "fs_delete", PROJECT] {
        let fx = Fx::new();
        let (st, _rec) = write_state(&fx, vec![AssistantTurn::tools(vec![call(name)])]);
        let mut b = body(&fx, serde_json::json!({ "toolSets": ["capsules_run"] }));
        b["tools"].as_array_mut().expect("tools").push(serde_json::json!({
            "name": name, "description": "a capsule", "parameters": {"type": "object"}, "host": "sidecar"
        }));
        let (status, v) = open(&st, b).await;
        assert_eq!(status, StatusCode::CREATED, "{name}: {v}");
        let id = v["id"].as_str().unwrap_or_default().to_string();
        let res = results(&run(&st, &id, "use it").await);
        assert_eq!(res.len(), 1, "{name}: {res:?}");
        assert_ne!(res[0].1, "ok", "{name} ran: {}", res[0].2);
        assert!(
            res[0].2.contains(CAPSULE_FALLTHROUGH),
            "{name} reached a write host: {}",
            res[0].2
        );
    }
}

// ---- The session body fails closed --------------------------------------------------------------

/// An explicit `toolSets: null` is no tool sets, never all of them.
#[tokio::test(flavor = "multi_thread")]
async fn a_null_allowlist_is_no_tool_sets() {
    let fx = Fx::new();
    let (st, rec) = state(
        &fx,
        vec![AssistantTurn::tools(
            HOST_TOOLS.iter().map(|t| call(t)).collect(),
        )],
    );
    let (status, v) = open(
        &st,
        body(
            &fx,
            serde_json::json!({ "toolSets": null, "maxToolCallsPerStep": 16 }),
        ),
    )
    .await;
    assert_eq!(status, StatusCode::CREATED, "{v}");
    assert_eq!(
        v["toolSets"],
        serde_json::json!([]),
        "the applied allowlist is echoed: none"
    );
    let id = v["id"].as_str().unwrap_or_default().to_string();
    let events = run(&st, &id, "use every tool you have").await;
    assert_eq!(offered(&rec), vec!["node_status".to_string()]);
    for (name, status, content) in results(&events) {
        assert_ne!(status, "ok", "{name} ran: {content}");
    }
}

/// A key the sidecar does not know (a misspelled `toolSets`, say) refuses the session: it is
/// never opened with the sets the misspelling meant to restrict.
#[tokio::test(flavor = "multi_thread")]
async fn an_unknown_key_refuses_the_session() {
    for extra in [
        serde_json::json!({ "toolsets": [] }),
        serde_json::json!({ "tool_sets": [] }),
        serde_json::json!({ "toolSet": ["web_search"] }),
        serde_json::json!({ "promptsnapshot": false }),
    ] {
        let fx = Fx::new();
        let (st, _rec) = state(&fx, vec![]);
        let (status, v) = open(&st, body(&fx, extra.clone())).await;
        assert_ne!(status, StatusCode::CREATED, "{extra}: {v}");
        assert!(status.is_client_error(), "{extra}: {status}");
        assert_eq!(st.sessions.count(), 0, "{extra}: no session was opened");
    }
}

/// Every key core and the other clients send is still accepted.
#[tokio::test(flavor = "multi_thread")]
async fn every_known_key_is_accepted() {
    let fx = Fx::new();
    let (st, _rec) = state(&fx, vec![]);
    let b = body(
        &fx,
        serde_json::json!({
            "maxSteps": 8, "maxTokens": 512, "maxToolCallsPerStep": 4, "maxToolsPerRequest": 16,
            "contextTokens": 8192, "hicAware": true, "unattended": true, "projectRoots": [],
            "toolSets": ["web_search"], "promptSnapshot": false
        }),
    );
    let (status, v) = open(&st, b).await;
    assert_eq!(status, StatusCode::CREATED, "{v}");
}
