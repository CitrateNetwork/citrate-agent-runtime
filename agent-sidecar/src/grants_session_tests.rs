//! HUP-S2.1 (wiring) — folder grants in agent sessions: the grant document core sends, the
//! grant-checked file tools, the replace route, and the toolchain project check driven by grants
//! instead of `CITRATE_HERMES_TOOLCHAIN_ROOTS`.
//!
//! BDD map (US-2.1):
//! - AC1 descendants only, symlinks resolved first, read and write separate:
//!   `a_read_grant_reads_inside_and_nothing_outside`, `read_and_write_are_separate`,
//!   `a_symlink_out_of_the_grant_is_denied`, `parent_traversal_is_denied`.
//! - AC2 secrets denied even under full access: `full_access_never_reaches_credentials_or_env`.
//! - AC3 full access is read-only, expires, and its reads are untrusted:
//!   `full_access_reads_are_untrusted_and_never_write`, `an_expired_full_access_grant_allows_nothing`.
//! - Revocation reaches a live session at once: `a_replace_revokes_immediately`,
//!   `a_refused_document_leaves_the_session_with_nothing`.

#![cfg(unix)]

use super::grants::*;
use super::toolchain::*;
use super::*;
use axum::body::Body;
use axum::http::{Request, StatusCode};
use citrate_agent_grants::{Access, FolderGrants, GrantRequest};
use citrate_agent_loop::verifiers_tooling::{RunStatus, ToolchainEnvelope, FORGE_TEST_TOOL};
use citrate_agent_loop::{
    AssistantTurn, CompletionRequest, LlmClient, LlmError, ToolCall, ToolHost, ToolOutcome,
};
use std::os::unix::fs::{symlink, PermissionsExt};
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::Mutex;
use std::time::Duration;
use tower::ServiceExt;

const BEARER: &str = "test-bearer-token-0123456789";
const MEMBER: &str = "0x00000000000000000000000000000000000000aa";
static N: AtomicUsize = AtomicUsize::new(0);

fn now() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap()
        .as_secs()
}

/// `base/home` (the member's home, with `.ssh` and a `.env`), `base/home/proj` (a project),
/// `base/home/other` (not granted), `base/bin` (a toolchain search path).
struct Fx {
    base: PathBuf,
}
impl Fx {
    fn new() -> Self {
        let base = std::env::temp_dir().join(format!(
            "citrate-sidecar-grants-{}-{}",
            std::process::id(),
            N.fetch_add(1, Ordering::SeqCst)
        ));
        let _ = std::fs::remove_dir_all(&base);
        for d in ["home/proj/src", "home/other", "home/.ssh", "bin"] {
            std::fs::create_dir_all(base.join(d)).unwrap();
        }
        let base = base.canonicalize().unwrap();
        std::fs::write(base.join("home/proj/src/main.sol"), "contract A {}").unwrap();
        std::fs::write(base.join("home/proj/.env"), "K=project").unwrap();
        std::fs::write(base.join("home/other/notes.txt"), "not granted").unwrap();
        std::fs::write(base.join("home/other/.env"), "K=other").unwrap();
        std::fs::write(base.join("home/.ssh/id_ed25519"), "secret").unwrap();
        Fx { base }
    }
    fn home(&self) -> PathBuf {
        self.base.join("home")
    }
    fn proj(&self) -> PathBuf {
        self.base.join("home/proj")
    }
    fn other(&self) -> PathBuf {
        self.base.join("home/other")
    }
    fn fg(&self) -> FolderGrants {
        FolderGrants::new(self.home(), self.home())
    }
    fn doc(&self, f: impl FnOnce(&mut FolderGrants)) -> serde_json::Value {
        let mut g = self.fg();
        f(&mut g);
        serde_json::to_value(g.state()).unwrap()
    }
    fn grants(&self, doc: &serde_json::Value) -> Arc<SessionGrants> {
        let g = SessionGrants::empty(self.home());
        g.replace(doc).unwrap();
        Arc::new(g)
    }
}
impl Drop for Fx {
    fn drop(&mut self) {
        let _ = std::fs::remove_dir_all(&self.base);
    }
}

fn folder(root: &Path, access: Access) -> GrantRequest {
    GrantRequest::folder(root, access, MEMBER, "work on the project")
}

fn call(tool: &str, args: serde_json::Value) -> ToolCall {
    ToolCall {
        id: "f1".into(),
        name: tool.into(),
        arguments: args.to_string(),
    }
}

fn read(host: &FileToolHost, p: &Path) -> ToolOutcome {
    host.execute(&call(FILE_READ_TOOL, serde_json::json!({ "path": p })))
}

fn write(host: &FileToolHost, p: &Path, content: &str) -> ToolOutcome {
    host.execute(&call(
        FILE_WRITE_TOOL,
        serde_json::json!({ "path": p, "content": content }),
    ))
}

fn is_denied(o: &ToolOutcome) -> bool {
    matches!(o, ToolOutcome::Denied(_))
}

// ---------------------------------------------------------------------------------------------
// The file tools against a grant set
// ---------------------------------------------------------------------------------------------

#[test]
fn a_read_grant_reads_inside_and_nothing_outside() {
    let fx = Fx::new();
    let doc = fx.doc(|g| {
        g.grant(folder(&fx.proj(), Access::Read), now()).unwrap();
    });
    let host = FileToolHost::new(fx.grants(&doc));
    match read(&host, &fx.proj().join("src/main.sol")) {
        ToolOutcome::Ok(body) => {
            let v: serde_json::Value = serde_json::from_str(&body).unwrap();
            assert_eq!(v["content"], "contract A {}");
        }
        other => panic!("expected a trusted read, got {other:?}"),
    }
    assert!(is_denied(&read(&host, &fx.other().join("notes.txt"))));
    // A sibling whose name starts with the granted folder's name is not inside it.
    std::fs::create_dir_all(fx.home().join("proj-old")).unwrap();
    std::fs::write(fx.home().join("proj-old/x.txt"), "x").unwrap();
    assert!(is_denied(&read(&host, &fx.home().join("proj-old/x.txt"))));
}

#[test]
fn read_and_write_are_separate() {
    let fx = Fx::new();
    let read_only = fx.doc(|g| {
        g.grant(folder(&fx.proj(), Access::Read), now()).unwrap();
    });
    let host = FileToolHost::new(fx.grants(&read_only));
    assert!(is_denied(&write(
        &host,
        &fx.proj().join("src/new.sol"),
        "x"
    )));
    assert!(!fx.proj().join("src/new.sol").exists());

    let write_only = fx.doc(|g| {
        g.grant(folder(&fx.proj(), Access::Write), now()).unwrap();
    });
    let host = FileToolHost::new(fx.grants(&write_only));
    match write(&host, &fx.proj().join("src/new.sol"), "contract B {}") {
        ToolOutcome::Ok(_) => {}
        other => panic!("a write grant must write: {other:?}"),
    }
    assert_eq!(
        std::fs::read_to_string(fx.proj().join("src/new.sol")).unwrap(),
        "contract B {}"
    );
    // A write grant does not read.
    assert!(is_denied(&read(&host, &fx.proj().join("src/new.sol"))));
}

#[test]
fn a_symlink_out_of_the_grant_is_denied() {
    let fx = Fx::new();
    symlink(fx.other(), fx.proj().join("escape")).unwrap();
    symlink(fx.home().join(".ssh"), fx.proj().join("keys")).unwrap();
    let doc = fx.doc(|g| {
        g.grant(folder(&fx.proj(), Access::Read), now()).unwrap();
        g.grant(folder(&fx.proj(), Access::Write), now()).unwrap();
    });
    let host = FileToolHost::new(fx.grants(&doc));
    assert!(is_denied(&read(&host, &fx.proj().join("escape/notes.txt"))));
    assert!(is_denied(&read(&host, &fx.proj().join("keys/id_ed25519"))));
    assert!(is_denied(&write(
        &host,
        &fx.proj().join("escape/planted.txt"),
        "x"
    )));
    assert!(!fx.other().join("planted.txt").exists());
}

#[test]
fn parent_traversal_is_denied() {
    let fx = Fx::new();
    let doc = fx.doc(|g| {
        g.grant(folder(&fx.proj(), Access::Read), now()).unwrap();
    });
    let host = FileToolHost::new(fx.grants(&doc));
    let sneaky = fx.proj().join("src/../../other/notes.txt");
    assert!(is_denied(&read(&host, &sneaky)));
    let rel = host.execute(&call(
        FILE_READ_TOOL,
        serde_json::json!({ "path": "proj/src/main.sol" }),
    ));
    assert!(matches!(rel, ToolOutcome::Error(_)), "{rel:?}");
}

#[test]
fn a_write_never_follows_a_symlink_or_a_hard_link_out() {
    let fx = Fx::new();
    std::fs::write(fx.other().join("target.txt"), "keep").unwrap();
    symlink(fx.other().join("target.txt"), fx.proj().join("link.txt")).unwrap();
    std::fs::hard_link(fx.other().join("target.txt"), fx.proj().join("hard.txt")).unwrap();
    let doc = fx.doc(|g| {
        g.grant(folder(&fx.proj(), Access::Write), now()).unwrap();
    });
    let host = FileToolHost::new(fx.grants(&doc));
    assert!(is_denied(&write(&host, &fx.proj().join("link.txt"), "x")));
    assert!(is_denied(&write(&host, &fx.proj().join("hard.txt"), "x")));
    assert_eq!(
        std::fs::read_to_string(fx.other().join("target.txt")).unwrap(),
        "keep"
    );
}

#[test]
fn full_access_never_reaches_credentials_or_env() {
    let fx = Fx::new();
    let doc = fx.doc(|g| {
        g.grant(
            GrantRequest::full_access(fx.home(), 3600, MEMBER, "look around"),
            now(),
        )
        .unwrap();
    });
    let host = FileToolHost::new(fx.grants(&doc));
    assert!(is_denied(&read(&host, &fx.home().join(".ssh/id_ed25519"))));
    assert!(is_denied(&read(&host, &fx.other().join(".env"))));
    // A listing never names what the agent may not read.
    match host.execute(&call(
        FILE_LIST_TOOL,
        serde_json::json!({ "path": fx.home() }),
    )) {
        ToolOutcome::Untrusted(body) => {
            let v: serde_json::Value = serde_json::from_str(&body).unwrap();
            let names: Vec<&str> = v["entries"]
                .as_array()
                .unwrap()
                .iter()
                .map(|e| e["name"].as_str().unwrap())
                .collect();
            assert!(names.contains(&"proj"));
            assert!(!names.contains(&".ssh"), "{names:?}");
            assert!(v["hidden"].as_u64().unwrap() >= 1);
        }
        other => panic!("expected an untrusted listing, got {other:?}"),
    }
    // A folder grant does unlock the project's own .env.
    let doc = fx.doc(|g| {
        g.grant(folder(&fx.proj(), Access::Read), now()).unwrap();
    });
    let host = FileToolHost::new(fx.grants(&doc));
    assert!(matches!(
        read(&host, &fx.proj().join(".env")),
        ToolOutcome::Ok(_)
    ));
}

#[test]
fn full_access_reads_are_untrusted_and_never_write() {
    let fx = Fx::new();
    let doc = fx.doc(|g| {
        g.grant(
            GrantRequest::full_access(fx.home(), 3600, MEMBER, "look around"),
            now(),
        )
        .unwrap();
    });
    let host = FileToolHost::new(fx.grants(&doc));
    assert!(matches!(
        read(&host, &fx.other().join("notes.txt")),
        ToolOutcome::Untrusted(_)
    ));
    assert!(is_denied(&write(&host, &fx.other().join("notes.txt"), "x")));
    assert_eq!(
        std::fs::read_to_string(fx.other().join("notes.txt")).unwrap(),
        "not granted"
    );
}

#[test]
fn an_expired_full_access_grant_allows_nothing() {
    let fx = Fx::new();
    let doc = fx.doc(|g| {
        // Granted two hours ago for one hour.
        g.grant(
            GrantRequest::full_access(fx.home(), 3600, MEMBER, "look around"),
            now() - 7200,
        )
        .unwrap();
    });
    let grants = fx.grants(&doc);
    assert_eq!(grants.summary().active, 0);
    let host = FileToolHost::new(grants);
    assert!(is_denied(&read(&host, &fx.other().join("notes.txt"))));
}

#[test]
fn a_replace_revokes_immediately() {
    let fx = Fx::new();
    let mut g = fx.fg();
    let id = g.grant(folder(&fx.proj(), Access::Read), now()).unwrap();
    let grants = fx.grants(&serde_json::to_value(g.state()).unwrap());
    let host = FileToolHost::new(grants.clone());
    assert!(matches!(
        read(&host, &fx.proj().join("src/main.sol")),
        ToolOutcome::Ok(_)
    ));
    g.revoke(&id, now()).unwrap();
    let s = grants
        .replace(&serde_json::to_value(g.state()).unwrap())
        .unwrap();
    assert_eq!((s.total, s.active), (1, 0));
    assert!(is_denied(&read(&host, &fx.proj().join("src/main.sol"))));
}

#[test]
fn a_refused_document_leaves_the_session_with_nothing() {
    let fx = Fx::new();
    let doc = fx.doc(|g| {
        g.grant(folder(&fx.proj(), Access::Read), now()).unwrap();
    });
    let grants = fx.grants(&doc);
    let host = FileToolHost::new(grants.clone());
    // A tampered document: full access made writable.
    let mut bad = fx.doc(|g| {
        g.grant(
            GrantRequest::full_access(fx.home(), 3600, MEMBER, "look"),
            now(),
        )
        .unwrap();
    });
    bad["grants"][0]["access"] = serde_json::json!("write");
    assert!(grants.replace(&bad).is_err());
    assert!(is_denied(&read(&host, &fx.proj().join("src/main.sol"))));
    assert!(grants.replace(&serde_json::json!({"version": 99})).is_err());
    assert_eq!(grants.summary().total, 0);
}

#[test]
fn oversized_and_binary_reads_are_reported_not_returned() {
    let fx = Fx::new();
    std::fs::write(
        fx.proj().join("big.txt"),
        vec![b'a'; MAX_READ_BYTES as usize + 1],
    )
    .unwrap();
    std::fs::write(fx.proj().join("bin.dat"), [0xffu8, 0xfe, 0x00]).unwrap();
    let doc = fx.doc(|g| {
        g.grant(folder(&fx.proj(), Access::Read), now()).unwrap();
        g.grant(folder(&fx.proj(), Access::Write), now()).unwrap();
    });
    let host = FileToolHost::new(fx.grants(&doc));
    assert!(matches!(
        read(&host, &fx.proj().join("big.txt")),
        ToolOutcome::Error(_)
    ));
    assert!(matches!(
        read(&host, &fx.proj().join("bin.dat")),
        ToolOutcome::Error(_)
    ));
    let huge = "a".repeat(MAX_WRITE_BYTES + 1);
    assert!(matches!(
        write(&host, &fx.proj().join("huge.txt"), &huge),
        ToolOutcome::Error(_)
    ));
    assert!(!fx.proj().join("huge.txt").exists());
}

// ---------------------------------------------------------------------------------------------
// Sessions and the replace route
// ---------------------------------------------------------------------------------------------

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

fn manager(
    fx: &Fx,
    turns: Vec<AssistantTurn>,
    toolchain: Option<ToolchainHost>,
) -> (Arc<sessions::SessionManager>, Arc<Recorder>) {
    let rec = Arc::new(Recorder {
        turns: Mutex::new(turns),
        seen: Mutex::new(vec![]),
    });
    let r2 = rec.clone();
    let mut mgr = sessions::SessionManager::new(
        Arc::new(move |_ep: &sessions::LlmEndpoint| r2.clone() as Arc<dyn LlmClient>),
        Duration::from_secs(5),
    )
    .with_grants_home(fx.home());
    if let Some(t) = toolchain {
        mgr = mgr.with_toolchain(Arc::new(t));
    }
    (Arc::new(mgr), rec)
}

fn create_body(grants: Option<serde_json::Value>) -> serde_json::Value {
    let mut b = serde_json::json!({
        "model": "gemma-4",
        "systemPrompt": "You are Hermes.",
        "llm": {"baseUrl": "http://127.0.0.1:18080/v1", "bearer": "k"},
        "tools": [],
        "maxToolsPerRequest": 16
    });
    if let Some(g) = grants {
        b["grants"] = g;
    }
    b
}

fn create_req(grants: Option<serde_json::Value>) -> sessions::CreateSessionReq {
    serde_json::from_value(create_body(grants)).unwrap()
}

async fn run_turn_events(
    mgr: &sessions::SessionManager,
    id: &str,
    text: &str,
) -> Vec<serde_json::Value> {
    mgr.send(id, text.into(), None).unwrap();
    let s = mgr.get(id).unwrap();
    let mut after = 0;
    let mut all = vec![];
    for _ in 0..100 {
        let page = s.wait_events(after, Duration::from_millis(200)).await;
        for e in page.events {
            after = after.max(e.seq);
            all.push(serde_json::to_value(&e.event).unwrap());
        }
        if all.iter().any(|e| e["type"] == "done") {
            return all;
        }
    }
    panic!("no done event: {all:?}");
}

fn state(mgr: Arc<sessions::SessionManager>) -> Arc<AppState> {
    Arc::new(AppState {
        estop: EmergencyStop::new(),
        queue: Arc::new(ApprovalQueue::new()),
        skills: vec![],
        dispatch: None,
        bearer: BEARER.to_string(),
        run_slots: Arc::new(tokio::sync::Semaphore::new(MAX_CONCURRENT_SKILLS)),
        sessions: mgr,
    })
}

fn http(method: &str, path: &str, body: serde_json::Value, auth: bool) -> Request<Body> {
    let mut b = Request::builder()
        .method(method)
        .uri(path)
        .header("content-type", "application/json");
    if auth {
        b = b.header("authorization", format!("Bearer {BEARER}"));
    }
    b.body(Body::from(body.to_string())).unwrap()
}

async fn body_json(resp: axum::response::Response) -> serde_json::Value {
    let bytes = axum::body::to_bytes(resp.into_body(), 1 << 20)
        .await
        .unwrap();
    serde_json::from_slice(&bytes).unwrap_or(serde_json::Value::Null)
}

#[tokio::test(flavor = "multi_thread")]
async fn without_a_grant_document_no_file_tools_are_offered() {
    let fx = Fx::new();
    let (mgr, rec) = manager(&fx, vec![], None);
    let id = mgr.create(create_req(None)).unwrap();
    run_turn_events(&mgr, &id, "read my file").await;
    let seen = rec.seen.lock().unwrap();
    assert!(seen[0].tools.iter().all(|t| !handles(&t.name)));
}

#[tokio::test(flavor = "multi_thread")]
async fn a_session_with_grants_reads_a_granted_file_through_the_sidecar() {
    let fx = Fx::new();
    let doc = fx.doc(|g| {
        g.grant(folder(&fx.proj(), Access::Read), now()).unwrap();
    });
    let c = call(
        FILE_READ_TOOL,
        serde_json::json!({ "path": fx.proj().join("src/main.sol") }),
    );
    let (mgr, rec) = manager(
        &fx,
        vec![AssistantTurn::tools(vec![c]), AssistantTurn::text("Read.")],
        None,
    );
    let id = mgr.create(create_req(Some(doc))).unwrap();
    let evs = run_turn_events(&mgr, &id, "open main.sol").await;
    let tc = evs.iter().find(|e| e["type"] == "tool_call").unwrap();
    assert_eq!(tc["host"], "sidecar");
    let tr = evs.iter().find(|e| e["type"] == "tool_result").unwrap();
    assert_eq!(tr["status"], "ok");
    assert!(tr["content"].as_str().unwrap().contains("contract A {}"));
    assert!(!mgr.get(&id).unwrap().taint().is_tainted());
    let seen = rec.seen.lock().unwrap();
    for name in FILE_TOOL_NAMES {
        assert!(seen[0].tools.iter().any(|t| t.name == name), "{name}");
    }
}

#[tokio::test(flavor = "multi_thread")]
async fn a_full_access_read_taints_the_session() {
    let fx = Fx::new();
    let doc = fx.doc(|g| {
        g.grant(
            GrantRequest::full_access(fx.home(), 3600, MEMBER, "look around"),
            now(),
        )
        .unwrap();
    });
    let c = call(
        FILE_READ_TOOL,
        serde_json::json!({ "path": fx.other().join("notes.txt") }),
    );
    let (mgr, _) = manager(
        &fx,
        vec![AssistantTurn::tools(vec![c]), AssistantTurn::text("ok")],
        None,
    );
    let id = mgr.create(create_req(Some(doc))).unwrap();
    run_turn_events(&mgr, &id, "what is in other").await;
    assert!(mgr.get(&id).unwrap().taint().is_tainted());
}

#[test]
fn a_session_tool_may_not_claim_a_file_tool_name_when_grants_are_given() {
    let fx = Fx::new();
    let (mgr, _) = manager(&fx, vec![], None);
    let mut body = create_body(Some(fx.doc(|_| {})));
    body["tools"] = serde_json::json!([
        {"name": FILE_WRITE_TOOL, "description": "x", "parameters": {"type": "object"}, "host": "core"}
    ]);
    let r = mgr.create(serde_json::from_value(body).unwrap());
    assert!(matches!(r, Err(sessions::SessionError::Invalid(_))));
}

#[test]
fn an_invalid_grant_document_refuses_the_session() {
    let fx = Fx::new();
    let (mgr, _) = manager(&fx, vec![], None);
    let r = mgr.create(create_req(Some(serde_json::json!({"version": 7}))));
    assert!(matches!(r, Err(sessions::SessionError::Invalid(_))));
    assert_eq!(mgr.count(), 0);
}

#[tokio::test]
async fn the_grants_route_replaces_a_sessions_grant_set() {
    let fx = Fx::new();
    let (mgr, _) = manager(&fx, vec![], None);
    let st = state(mgr.clone());
    let id = mgr.create(create_req(Some(fx.doc(|_| {})))).unwrap();
    let doc = fx.doc(|g| {
        g.grant(folder(&fx.proj(), Access::Read), now()).unwrap();
    });
    let path = format!("/sessions/{id}/grants");

    let r = app(st.clone())
        .oneshot(http("POST", &path, doc.clone(), false))
        .await
        .unwrap();
    assert_eq!(r.status(), StatusCode::UNAUTHORIZED);

    let r = app(st.clone())
        .oneshot(http("POST", &path, doc.clone(), true))
        .await
        .unwrap();
    assert_eq!(r.status(), StatusCode::OK);
    let v = body_json(r).await;
    assert_eq!(v["grants"]["active"], 1);
    let s = mgr.get(&id).unwrap();
    assert!(s
        .grants()
        .unwrap()
        .check(
            &fx.proj().join("src/main.sol"),
            citrate_agent_grants::Op::Read
        )
        .is_ok());

    let r = app(st.clone())
        .oneshot(http("POST", &path, serde_json::json!({"version": 9}), true))
        .await
        .unwrap();
    assert_eq!(r.status(), StatusCode::BAD_REQUEST);
    assert!(s
        .grants()
        .unwrap()
        .check(
            &fx.proj().join("src/main.sol"),
            citrate_agent_grants::Op::Read
        )
        .is_err());

    let r = app(st.clone())
        .oneshot(http("POST", "/sessions/s99-0/grants", doc.clone(), true))
        .await
        .unwrap();
    assert_eq!(r.status(), StatusCode::NOT_FOUND);
}

#[tokio::test]
async fn the_grants_route_refuses_a_session_opened_without_grants() {
    let fx = Fx::new();
    let (mgr, _) = manager(&fx, vec![], None);
    let st = state(mgr.clone());
    let id = mgr.create(create_req(None)).unwrap();
    let r = app(st)
        .oneshot(http(
            "POST",
            &format!("/sessions/{id}/grants"),
            fx.doc(|_| {}),
            true,
        ))
        .await
        .unwrap();
    assert_eq!(r.status(), StatusCode::CONFLICT);
}

// ---------------------------------------------------------------------------------------------
// The toolchain project check, driven by grants
// ---------------------------------------------------------------------------------------------

fn fake_forge(fx: &Fx) {
    let fixture = Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("../agent-loop/tests/fixtures/toolchain/forge-test-pass.json");
    let p = fx.base.join("bin/forge");
    std::fs::write(
        &p,
        format!(
            "#!/bin/sh\npwd > '{}'\n/bin/cat '{}'\n",
            fx.base.join("forge.cwd").display(),
            fixture.display()
        ),
    )
    .unwrap();
    std::fs::set_permissions(&p, std::fs::Permissions::from_mode(0o755)).unwrap();
}

/// A toolchain host whose env roots cover the whole home (the interim seam), so a test can show
/// that grants, when present, replace them.
fn env_rooted_host(fx: &Fx) -> ToolchainHost {
    ToolchainHost::new(ToolchainConfig {
        roots: vec![fx.home()],
        search_path: vec![fx.base.join("bin")],
        solc: None,
        home: fx.home(),
    })
    .unwrap()
}

async fn forge_in_session(fx: &Fx, doc: Option<serde_json::Value>) -> ToolchainEnvelope {
    fake_forge(fx);
    // The fixture project holds a .env (for the file tool tests); the toolchain does not run
    // beside env files, so these runs use the project without it.
    let _ = std::fs::remove_file(fx.proj().join(".env"));
    let c = call(FORGE_TEST_TOOL, serde_json::json!({ "project": fx.proj() }));
    let (mgr, _) = manager(
        fx,
        vec![AssistantTurn::tools(vec![c]), AssistantTurn::text("ok")],
        Some(env_rooted_host(fx)),
    );
    let id = mgr.create(create_req(doc)).unwrap();
    let evs = run_turn_events(&mgr, &id, "run the tests").await;
    let tr = evs.iter().find(|e| e["type"] == "tool_result").unwrap();
    ToolchainEnvelope::from_content(tr["content"].as_str().unwrap()).unwrap()
}

#[tokio::test(flavor = "multi_thread")]
async fn without_grants_the_toolchain_keeps_its_env_roots() {
    let fx = Fx::new();
    let env = forge_in_session(&fx, None).await;
    assert_eq!(env.status, RunStatus::Completed, "{}", env.summary);
}

#[tokio::test(flavor = "multi_thread")]
async fn with_grants_the_toolchain_needs_read_and_write_folder_grants() {
    let fx = Fx::new();
    // Read only: refused even though the env roots cover the project.
    let read_only = fx.doc(|g| {
        g.grant(folder(&fx.proj(), Access::Read), now()).unwrap();
    });
    let env = forge_in_session(&fx, Some(read_only)).await;
    assert_eq!(env.status, RunStatus::Refused, "{}", env.summary);

    // Full access (read-only) is not enough either.
    let full = fx.doc(|g| {
        g.grant(
            GrantRequest::full_access(fx.home(), 3600, MEMBER, "look"),
            now(),
        )
        .unwrap();
    });
    let env = forge_in_session(&fx, Some(full)).await;
    assert_eq!(env.status, RunStatus::Refused, "{}", env.summary);

    // A write folder grant with only full access for reading: the read must be a folder grant.
    let write_and_full = fx.doc(|g| {
        g.grant(folder(&fx.proj(), Access::Write), now()).unwrap();
        g.grant(
            GrantRequest::full_access(fx.home(), 3600, MEMBER, "look"),
            now(),
        )
        .unwrap();
    });
    let env = forge_in_session(&fx, Some(write_and_full)).await;
    assert_eq!(env.status, RunStatus::Refused, "{}", env.summary);

    let rw = fx.doc(|g| {
        g.grant(folder(&fx.proj(), Access::Read), now()).unwrap();
        g.grant(folder(&fx.proj(), Access::Write), now()).unwrap();
    });
    let env = forge_in_session(&fx, Some(rw)).await;
    assert_eq!(env.status, RunStatus::Completed, "{}", env.summary);
    let cwd = std::fs::read_to_string(fx.base.join("forge.cwd")).unwrap();
    assert_eq!(cwd.trim(), fx.proj().display().to_string());
}

/// Core's early refusal list is shorter than the sidecar's deny list, so core can store a grant
/// rooted in a deny location (a browser profile folder, say), and that row stays in the document
/// after it is revoked. Such a row can never allow anything (the deny list wins under every
/// grant), so it must not make the sidecar refuse the member's whole document: that would refuse
/// every new session and strip the grants from every open one.
#[tokio::test]
async fn a_grant_rooted_in_a_deny_location_grants_nothing_and_does_not_refuse_the_rest() {
    let fx = Fx::new();
    for d in [".mozilla/profile", ".password-store"] {
        std::fs::create_dir_all(fx.home().join(d)).unwrap();
    }
    std::fs::write(fx.home().join(".mozilla/profile/cookies.sqlite"), "c").unwrap();
    let mut doc = fx.doc(|g| {
        g.grant(folder(&fx.proj(), Access::Read), now()).unwrap();
    });
    let row = |id: &str, root: PathBuf, revoked: Option<u64>| {
        serde_json::json!({
            "id": id, "kind": "folder", "root": root, "access": "read", "scope": "subtree",
            "granted_at": now() - 10, "expires_at": null, "granted_by": "member",
            "reason": "Granted in Settings", "revoked_at": revoked,
        })
    };
    let rows = doc["grants"].as_array_mut().unwrap();
    rows.push(row("g-2", fx.home().join(".mozilla"), None));
    rows.push(row(
        "g-3",
        fx.home().join(".password-store"),
        Some(now() - 5),
    ));
    doc["next_id"] = serde_json::json!(4);

    let grants = SessionGrants::empty(fx.home());
    let s = grants.replace(&doc).expect("the usable grants still load");
    assert_eq!((s.total, s.active, s.ignored), (1, 1, 2));
    let host = FileToolHost::new(Arc::new(grants));
    assert!(matches!(
        read(&host, &fx.proj().join("src/main.sol")),
        ToolOutcome::Ok(_)
    ));
    assert!(is_denied(&read(
        &host,
        &fx.home().join(".mozilla/profile/cookies.sqlite")
    )));

    // A session opens with it, and the replace route takes it.
    let (mgr, _) = manager(&fx, vec![], None);
    let id = mgr
        .create(create_req(Some(doc.clone())))
        .expect("session opens");
    let r = app(state(mgr.clone()))
        .oneshot(http("POST", &format!("/sessions/{id}/grants"), doc, true))
        .await
        .unwrap();
    assert_eq!(r.status(), StatusCode::OK);
    assert_eq!(body_json(r).await["grants"]["ignored"], 2);
}
