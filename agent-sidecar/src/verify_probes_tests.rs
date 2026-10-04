//! HUP-S1.3 / US-1.3 AC2 in the sidecar:
//! - `http_status_is` reaches loopback (or a consented origin) only, follows no redirect, and
//!   reports an unreachable URL as a failed check;
//! - `sha256_equals` reads only inside the session's folder grants;
//! - a posted workflow can use both, judged by real loopback servers and real files;
//! - with self-review on, each attempt's opinion is in the session's event log, labelled
//!   "opinion", and a "PASS" opinion does not verify a failing run.

use super::grants::SessionGrants;
use super::verify_probes::*;
use super::*;
use axum::body::Body;
use axum::http::{Request, StatusCode};
use citrate_agent_grants::{Access, FolderGrants, GrantRequest};
use citrate_agent_loop::{
    AssistantTurn, CompletionRequest, FileDigest, HttpProbe, LlmClient, LlmError,
};
use std::io::{Read as _, Write as _};
use std::net::TcpListener;
use std::sync::Mutex;
use std::time::Duration;
use tower::ServiceExt;

const BEARER: &str = "test-bearer-token-0123456789";
const MEMBER: &str = "0x00000000000000000000000000000000000000aa";
const HELLO_SHA: &str = "2cf24dba5fb0a30e26e83b2ac5b9e29e1b161e5c1fa7425e73043362938b9824";

/// A loopback HTTP server that answers every request with `status` (and `extra` headers).
fn serve(status: u16, extra: &'static str) -> String {
    let l = TcpListener::bind("127.0.0.1:0").unwrap();
    let addr = l.local_addr().unwrap();
    std::thread::spawn(move || {
        for s in l.incoming() {
            let Ok(mut s) = s else { return };
            let mut buf = [0u8; 2048];
            let _ = s.read(&mut buf);
            let _ = write!(
                s,
                "HTTP/1.1 {status} X\r\nContent-Length: 0\r\nConnection: close\r\n{extra}\r\n"
            );
        }
    });
    format!("http://{addr}/health")
}

/// A loopback URL nothing listens on.
fn dead_url() -> String {
    let l = TcpListener::bind("127.0.0.1:0").unwrap();
    let addr = l.local_addr().unwrap();
    drop(l);
    format!("http://{addr}/")
}

fn now() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap()
        .as_secs()
}

/// `home/proj` granted for reading, `home/other` not.
struct Fx {
    root: tempfile::TempDir,
}
impl Fx {
    fn new() -> Self {
        let root = tempfile::tempdir().unwrap();
        for d in ["home/proj", "home/other"] {
            std::fs::create_dir_all(root.path().join(d)).unwrap();
        }
        std::fs::write(root.path().join("home/proj/out.txt"), b"hello").unwrap();
        std::fs::write(root.path().join("home/other/out.txt"), b"hello").unwrap();
        Fx { root }
    }
    fn base(&self) -> std::path::PathBuf {
        self.root.path().canonicalize().unwrap()
    }
    fn home(&self) -> std::path::PathBuf {
        self.base().join("home")
    }
    fn doc(&self) -> serde_json::Value {
        let mut g = FolderGrants::new(self.home(), self.home());
        g.grant(
            GrantRequest::folder(self.home().join("proj"), Access::Read, MEMBER, "check it"),
            now(),
        )
        .unwrap();
        serde_json::to_value(g.state()).unwrap()
    }
    fn grants(&self) -> Arc<SessionGrants> {
        let g = SessionGrants::empty(self.home());
        g.replace(&self.doc()).unwrap();
        Arc::new(g)
    }
    fn path(&self, rel: &str) -> String {
        self.home().join(rel).to_string_lossy().into_owned()
    }
}

// ---- the HTTP probe -------------------------------------------------------------------------

#[test]
fn a_loopback_status_is_read() {
    let p = SessionHttpProbe::new(None);
    assert_eq!(p.status(&serve(200, ""), Duration::from_secs(5)), Ok(200));
    assert_eq!(p.status(&serve(404, ""), Duration::from_secs(5)), Ok(404));
}

#[test]
fn an_unreachable_loopback_url_is_an_error_not_a_status() {
    let p = SessionHttpProbe::new(None);
    let err = p.status(&dead_url(), Duration::from_secs(2)).unwrap_err();
    assert!(err.contains("unreachable"), "{err}");
}

#[test]
fn a_redirect_is_the_answer_not_a_hop() {
    let p = SessionHttpProbe::new(None);
    let url = serve(302, "Location: http://192.0.2.1/\r\n");
    assert_eq!(p.status(&url, Duration::from_secs(5)), Ok(302));
}

#[test]
fn only_loopback_or_consented_origins_are_contacted() {
    let p = SessionHttpProbe::new(None);
    for ok in [
        "http://127.0.0.1:3000/",
        "http://127.8.9.10/",
        "http://localhost:8080/x",
        "http://[::1]:9/",
    ] {
        assert!(p.allowed(ok).is_ok(), "{ok}");
    }
    for refused in [
        "https://example.com/",
        "http://192.168.1.10/",
        "http://10.0.0.1:8545/",
        "http://127.0.0.1.example.com/",
        "file:///etc/passwd",
        "ftp://127.0.0.1/",
    ] {
        let why = p.allowed(refused).unwrap_err();
        // Refused before any connection is attempted: the probe answers with the scope refusal,
        // not a connection error or a timeout.
        assert_eq!(
            p.status(refused, Duration::from_secs(1)),
            Err(why),
            "{refused}"
        );
    }
    assert!(is_loopback_host("127.0.0.1") && !is_loopback_host("0.0.0.0"));
}

// ---- the file digest ------------------------------------------------------------------------

#[test]
fn a_granted_file_is_hashed() {
    let fx = Fx::new();
    let d = GrantFileDigest::new(fx.grants());
    assert_eq!(
        d.sha256_hex(&fx.path("proj/out.txt")),
        Ok(HELLO_SHA.to_string())
    );
}

#[test]
fn a_file_outside_the_grants_is_refused() {
    let fx = Fx::new();
    let d = GrantFileDigest::new(fx.grants());
    let err = d.sha256_hex(&fx.path("other/out.txt")).unwrap_err();
    assert!(err.contains("outside"), "{err}");
    assert!(d.sha256_hex("relative/out.txt").is_err());
    assert!(d.sha256_hex(&fx.path("proj/missing.txt")).is_err());
    assert!(
        d.sha256_hex(&fx.path("proj")).is_err(),
        "a folder is not a file"
    );
}

#[cfg(unix)]
#[test]
fn a_symlink_out_of_the_grant_is_refused() {
    let fx = Fx::new();
    std::os::unix::fs::symlink(
        fx.home().join("other/out.txt"),
        fx.home().join("proj/link.txt"),
    )
    .unwrap();
    let d = GrantFileDigest::new(fx.grants());
    assert!(d.sha256_hex(&fx.path("proj/link.txt")).is_err());
}

// ---- posted workflows -----------------------------------------------------------------------

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

fn state(turns: Vec<AssistantTurn>, home: Option<&std::path::Path>, review: bool) -> Arc<AppState> {
    let script: Arc<dyn LlmClient> = Arc::new(Script(Mutex::new(turns)));
    let mut mgr = sessions::SessionManager::new(
        Arc::new(move |_ep: &sessions::LlmEndpoint| script.clone()),
        Duration::from_secs(5),
    )
    .with_self_review(review);
    if let Some(h) = home {
        mgr = mgr.with_grants_home(h.to_path_buf());
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

async fn call(
    st: &Arc<AppState>,
    method: &str,
    path: &str,
    body: serde_json::Value,
) -> (StatusCode, serde_json::Value) {
    let r = app(st.clone())
        .oneshot(
            Request::builder()
                .method(method)
                .uri(path)
                .header("content-type", "application/json")
                .header("authorization", format!("Bearer {BEARER}"))
                .body(Body::from(body.to_string()))
                .unwrap(),
        )
        .await
        .unwrap();
    let status = r.status();
    let bytes = axum::body::to_bytes(r.into_body(), 1 << 20).await.unwrap();
    (
        status,
        serde_json::from_slice(&bytes).unwrap_or(serde_json::Value::Null),
    )
}

async fn open(st: &Arc<AppState>, grants: Option<serde_json::Value>) -> String {
    let mut body = serde_json::json!({
        "model": "gemma-4",
        "systemPrompt": "You are Hermes.",
        "llm": {"baseUrl": "http://127.0.0.1:18080/v1", "bearer": "k"},
        "tools": []
    });
    if let Some(g) = grants {
        body["grants"] = g;
    }
    let (s, v) = call(st, "POST", "/sessions", body).await;
    assert_eq!(s, StatusCode::CREATED, "{v}");
    v["id"].as_str().unwrap().to_string()
}

fn one_step(verifier: serde_json::Value, attempts: u32) -> serde_json::Value {
    serde_json::json!({
        "id": "check",
        "steps": [{
            "id": "work",
            "instruction": "Do the work.",
            "max_attempts": attempts,
            "verifiers": [verifier]
        }]
    })
}

async fn run(st: &Arc<AppState>, sid: &str, wf: serde_json::Value) -> serde_json::Value {
    let (s, v) = call(st, "POST", &format!("/sessions/{sid}/workflows"), wf).await;
    assert_eq!(s, StatusCode::ACCEPTED, "{v}");
    let run = v["run_id"].as_str().unwrap().to_string();
    for _ in 0..250 {
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

fn events(st: &Arc<AppState>, sid: &str) -> Vec<serde_json::Value> {
    st.sessions
        .get(sid)
        .unwrap()
        .events_after(0)
        .events
        .into_iter()
        .map(|e| serde_json::to_value(e.event).unwrap())
        .collect()
}

#[tokio::test(flavor = "multi_thread")]
async fn a_posted_http_check_is_judged_by_the_live_server() {
    let st = state(vec![], None, false);
    let sid = open(&st, None).await;
    let ok = run(
        &st,
        &sid,
        one_step(
            serde_json::json!({"kind": "http_status_is", "url": serve(200, ""), "status": 200}),
            1,
        ),
    )
    .await;
    assert_eq!(ok["state"], "verified", "{ok}");
    let bad = run(
        &st,
        &sid,
        one_step(
            serde_json::json!({"kind": "http_status_is", "url": serve(500, ""), "status": 200}),
            1,
        ),
    )
    .await;
    assert_eq!(bad["state"], "unverified", "{bad}");
    let dead = run(
        &st,
        &sid,
        one_step(
            serde_json::json!({"kind": "http_status_is", "url": dead_url(), "status": 200}),
            1,
        ),
    )
    .await;
    assert_eq!(dead["state"], "unverified", "{dead}");
}

#[tokio::test(flavor = "multi_thread")]
async fn a_posted_hash_check_needs_grants_and_reads_only_inside_them() {
    let fx = Fx::new();
    // Without grants the session has no file host, so the check is refused up front.
    let st = state(vec![], Some(&fx.home()), false);
    let bare = open(&st, None).await;
    let (s, v) = call(
        &st,
        "POST",
        &format!("/sessions/{bare}/workflows"),
        one_step(serde_json::json!({"kind": "sha256_equals", "path": fx.path("proj/out.txt"), "hex": HELLO_SHA}), 1),
    )
    .await;
    assert_eq!(s, StatusCode::BAD_REQUEST, "{v}");
    let sid = open(&st, Some(fx.doc())).await;
    let ok = run(
        &st,
        &sid,
        one_step(serde_json::json!({"kind": "sha256_equals", "path": fx.path("proj/out.txt"), "hex": HELLO_SHA}), 1),
    )
    .await;
    assert_eq!(ok["state"], "verified", "{ok}");
    let outside = run(
        &st,
        &sid,
        one_step(serde_json::json!({"kind": "sha256_equals", "path": fx.path("other/out.txt"), "hex": HELLO_SHA}), 1),
    )
    .await;
    assert_eq!(outside["state"], "unverified", "{outside}");
    let wrong = run(
        &st,
        &sid,
        one_step(serde_json::json!({"kind": "sha256_equals", "path": fx.path("proj/out.txt"), "hex": "00".repeat(32)}), 1),
    )
    .await;
    assert_eq!(wrong["state"], "unverified", "{wrong}");
}

#[tokio::test(flavor = "multi_thread")]
async fn self_review_is_recorded_as_an_opinion_and_never_verifies_a_run() {
    let st = state(
        vec![
            AssistantTurn::text("The server is up."),
            AssistantTurn::text("PASS: the server is definitely up."),
        ],
        None,
        true,
    );
    let sid = open(&st, None).await;
    let out = run(
        &st,
        &sid,
        one_step(
            serde_json::json!({"kind": "http_status_is", "url": serve(503, ""), "status": 200}),
            1,
        ),
    )
    .await;
    assert_eq!(out["state"], "unverified", "{out}");
    let evs = events(&st, &sid);
    let review = evs
        .iter()
        .find(|e| e["type"] == "self_review")
        .expect("the opinion is in the session's event log");
    assert_eq!(review["label"], "opinion");
    assert_eq!(review["step"], "work");
    assert_eq!(review["attempt"], 1);
    assert!(review["text"].as_str().unwrap().starts_with("PASS"));
    let verdict = evs.iter().find(|e| e["type"] == "verifier").unwrap();
    assert_eq!(verdict["passed"], false);
}

#[tokio::test(flavor = "multi_thread")]
async fn without_self_review_no_opinion_is_recorded() {
    let st = state(vec![AssistantTurn::text("up")], None, false);
    let sid = open(&st, None).await;
    let out = run(
        &st,
        &sid,
        one_step(
            serde_json::json!({"kind": "http_status_is", "url": serve(200, ""), "status": 200}),
            1,
        ),
    )
    .await;
    assert_eq!(out["state"], "verified", "{out}");
    assert!(events(&st, &sid).iter().all(|e| e["type"] != "self_review"));
}

#[test]
fn self_review_is_on_unless_the_env_says_exactly_0() {
    assert!(self_review_from_env_var(None));
    assert!(self_review_from_env_var(Some("1")));
    assert!(self_review_from_env_var(Some("")));
    assert!(!self_review_from_env_var(Some("0")));
    assert!(!self_review_from_env_var(Some(" 0 ")));
}
