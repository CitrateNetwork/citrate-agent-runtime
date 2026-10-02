//! HUP-S2.5 (wiring): each session's capsule calls run under that session's own sandbox, built
//! from the member's live folder grants, the session's mount bindings and its egress consent.
//!
//! BDD map (US-2.5 AC1, "enforced via WASI preopens scoped to live grants and a socket
//! allowlist"):
//! - a binding backed by a live grant mounts; revoking the grant stops it at the next call:
//!   `a_bound_mount_follows_the_sessions_live_grants`.
//! - a binding never widens the manifest, and with no grant there is no mount:
//!   `a_binding_for_an_undeclared_mount_is_refused`, `mounts_need_a_grant_document`.
//! - egress only to addresses the member consented to, inside the signed list (M-6):
//!   `egress_consent_is_per_capsule_and_never_widens_the_manifest`,
//!   `consent_to_a_private_address_is_refused`.
//! - the session's capsule tool calls go through it:
//!   `a_session_capsule_call_runs_under_the_session_sandbox`.
//! - only runnable capsules are listed as skills:
//!   `only_runnable_capsules_are_listed_as_skills`.

#![cfg(unix)]

use super::capsule_sandbox::*;
use super::grants::SessionGrants;
use super::*;
use citrate_agent_core::capsule::manifest::Manifest;
use citrate_agent_core::capsule::sandbox::{NetworkPlan, SandboxProvider};
use citrate_agent_grants::{Access, FolderGrants, GrantRequest};
use citrate_agent_loop::{AssistantTurn, CompletionRequest, LlmClient, LlmError, ToolCall};
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::Mutex;
use std::time::Duration;

const MEMBER: &str = "0x00000000000000000000000000000000000000aa";
static N: AtomicUsize = AtomicUsize::new(0);

fn now() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0)
}

/// `base/home` with a project folder holding one file.
struct Fx {
    base: PathBuf,
}

impl Fx {
    fn new() -> Self {
        let base = std::env::temp_dir().join(format!(
            "citrate-sidecar-capsule-sandbox-{}-{}",
            std::process::id(),
            N.fetch_add(1, Ordering::SeqCst)
        ));
        let _ = std::fs::remove_dir_all(&base);
        std::fs::create_dir_all(base.join("home/proj")).expect("mkdir");
        let base = base.canonicalize().expect("canonical");
        std::fs::write(base.join("home/proj/notes.txt"), "granted").expect("write");
        Fx { base }
    }
    fn home(&self) -> PathBuf {
        self.base.join("home")
    }
    fn proj(&self) -> PathBuf {
        self.base.join("home/proj")
    }
    fn read_grant_doc(&self) -> serde_json::Value {
        let mut g = FolderGrants::new(self.home(), self.home());
        g.grant(
            GrantRequest::folder(self.proj(), Access::Read, MEMBER, "capsule work"),
            now(),
        )
        .expect("grant");
        serde_json::to_value(g.state()).expect("doc")
    }
    fn grants(&self, doc: &serde_json::Value) -> Arc<SessionGrants> {
        let g = SessionGrants::empty(self.home());
        g.replace(doc).expect("doc accepted");
        Arc::new(g)
    }
}

impl Drop for Fx {
    fn drop(&mut self) {
        let _ = std::fs::remove_dir_all(&self.base);
    }
}

fn manifest(name: &str, network: &str, filesystem: &[&str]) -> Manifest {
    let fs = filesystem
        .iter()
        .map(|s| format!("{s:?}"))
        .collect::<Vec<_>>()
        .join(", ");
    Manifest::parse(&format!(
        r#"
[capsule]
name = "{name}"
version = "0.1.0"
content_hash = "sha256:{zeros}"

[capability]
{network}
filesystem = [{fs}]
chain_calls = []
subagent_spawn = false

[data_class]
reads = ["PUBLIC"]
writes = []
emits = []

[risk]
tier = "low"
required_roles = ["Operator"]
break_glass_eligible = false

[overlay]
certified = []
not_certified = []

[provenance]
publisher = "did:citrate:agent:0xab12"
build_reproducible = true
agentile_sprint = "hup-s2.5"
tla_spec = ""

[signing]
tier = "bundled"
"#,
        zeros = "0".repeat(64),
    ))
    .expect("test manifest parses")
}

fn doc(v: serde_json::Value) -> CapsuleSandboxDoc {
    serde_json::from_value(v).expect("doc parses")
}

#[test]
fn a_bound_mount_follows_the_sessions_live_grants() {
    let fx = Fx::new();
    let grants = fx.grants(&fx.read_grant_doc());
    let sandbox = SessionSandbox::new(
        Some(doc(serde_json::json!({
            "mounts": [{ "capsule": "reader", "guest": "/work", "host": fx.proj() }]
        }))),
        Some(grants.clone()),
    )
    .expect("sandbox");
    let m = manifest("reader", r#"network = "none""#, &["read:/work"]);
    let plan = sandbox.plan_for(&m).expect("granted");
    assert_eq!(plan.preopens().len(), 1);
    assert_eq!(plan.preopens()[0].host, fx.proj());
    assert_eq!(plan.preopens()[0].guest, "/work");

    // The member revokes everything (core replaces the session's document).
    let empty = serde_json::to_value(FolderGrants::new(fx.home(), fx.home()).state()).expect("doc");
    grants.replace(&empty).expect("replace");
    let err = sandbox.plan_for(&m).expect_err("revoked at the next call");
    assert!(err.to_string().contains("not granted"), "{err}");

    // Another capsule gets nothing from this binding.
    let other = manifest("other", r#"network = "none""#, &["read:/work"]);
    assert!(sandbox
        .plan_for(&other)
        .expect("plan")
        .preopens()
        .is_empty());
}

#[test]
fn a_binding_for_an_undeclared_mount_is_refused() {
    let fx = Fx::new();
    let sandbox = SessionSandbox::new(
        Some(doc(serde_json::json!({
            "mounts": [{ "capsule": "reader", "guest": "/elsewhere", "host": fx.proj() }]
        }))),
        Some(fx.grants(&fx.read_grant_doc())),
    )
    .expect("sandbox");
    let m = manifest("reader", r#"network = "none""#, &["read:/work"]);
    let err = sandbox
        .plan_for(&m)
        .expect_err("the manifest is the ceiling");
    assert!(err.to_string().contains("declares no"), "{err}");
}

#[test]
fn mounts_need_a_grant_document() {
    let fx = Fx::new();
    let err = SessionSandbox::new(
        Some(doc(serde_json::json!({
            "mounts": [{ "capsule": "reader", "guest": "/work", "host": fx.proj() }]
        }))),
        None,
    )
    .expect_err("no grants, no mounts");
    assert!(err.contains("grant"), "{err}");
}

#[test]
fn bindings_are_validated() {
    let fx = Fx::new();
    let grants = Some(fx.grants(&fx.read_grant_doc()));
    for (bad, why) in [
        (
            serde_json::json!({ "mounts": [{ "capsule": "", "guest": "/work", "host": fx.proj() }] }),
            "capsule",
        ),
        (
            serde_json::json!({ "mounts": [{ "capsule": "r", "guest": "work", "host": fx.proj() }] }),
            "guest",
        ),
        (
            serde_json::json!({ "mounts": [{ "capsule": "r", "guest": "/work", "host": "proj" }] }),
            "absolute",
        ),
        (
            serde_json::json!({ "egress": [{ "capsule": "r", "allow": [] }] }),
            "address",
        ),
        (
            serde_json::json!({ "egress": [{ "capsule": "r", "allow": ["example.com:443"] }] }),
            "ip:port",
        ),
    ] {
        let err = SessionSandbox::new(Some(doc(bad.clone())), grants.clone())
            .err()
            .unwrap_or_else(|| panic!("{bad} must be refused"));
        assert!(err.contains(why), "{bad}: {err}");
    }
    let many: Vec<serde_json::Value> = (0..=MAX_CAPSULE_BINDINGS)
        .map(|i| serde_json::json!({ "capsule": format!("c{i}"), "guest": "/work", "host": fx.proj() }))
        .collect();
    let err = SessionSandbox::new(
        Some(doc(serde_json::json!({ "mounts": many }))),
        grants.clone(),
    )
    .expect_err("too many bindings");
    assert!(err.contains("at most"), "{err}");
    let unknown = serde_json::from_value::<CapsuleSandboxDoc>(
        serde_json::json!({ "mounts": [], "shell": true }),
    );
    assert!(unknown.is_err(), "unknown fields are refused");
}

#[test]
fn egress_consent_is_per_capsule_and_never_widens_the_manifest() {
    let sandbox = SessionSandbox::new(
        Some(doc(serde_json::json!({
            "egress": [{ "capsule": "fetcher", "allow": ["1.1.1.1:443", "8.8.8.8:53"] }]
        }))),
        None,
    )
    .expect("sandbox");
    let fetcher = manifest(
        "fetcher",
        "network = \"egress-allowed\"\nnetwork_allow = [\"1.1.1.1:443\", \"9.9.9.9:443\"]",
        &[],
    );
    let ok: std::net::SocketAddr = "1.1.1.1:443".parse().expect("addr");
    assert_eq!(
        sandbox.plan_for(&fetcher).expect("plan").network(),
        &NetworkPlan::Allow(vec![ok])
    );
    let other = manifest(
        "other",
        "network = \"egress-allowed\"\nnetwork_allow = [\"1.1.1.1:443\"]",
        &[],
    );
    assert_eq!(
        sandbox.plan_for(&other).expect("plan").network(),
        &NetworkPlan::DenyAll
    );
    let none = SessionSandbox::new(None, None).expect("default");
    assert_eq!(
        none.plan_for(&fetcher).expect("plan").network(),
        &NetworkPlan::DenyAll,
        "no consent, no address"
    );
}

#[test]
fn consent_to_a_private_address_is_refused() {
    for addr in [
        "127.0.0.1:8545",
        "169.254.169.254:80",
        "192.168.1.10:443",
        "[::1]:443",
    ] {
        let err = SessionSandbox::new(
            Some(doc(
                serde_json::json!({ "egress": [{ "capsule": "c", "allow": [addr] }] }),
            )),
            None,
        )
        .err()
        .unwrap_or_else(|| panic!("{addr} must be refused"));
        assert!(err.contains("not a public address"), "{addr}: {err}");
    }
}

// ---------------------------------------------------------------------------------------------
// End to end through a session
// ---------------------------------------------------------------------------------------------

fn shipped_capsules_dir() -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR")).join("../capsules")
}

struct Scripted {
    turns: Mutex<Vec<AssistantTurn>>,
}

impl LlmClient for Scripted {
    fn complete(&self, _req: &CompletionRequest) -> Result<AssistantTurn, LlmError> {
        let mut t = self
            .turns
            .lock()
            .map_err(|_| LlmError::Transport("poisoned".into()))?;
        Ok(if t.is_empty() {
            AssistantTurn::text("done")
        } else {
            t.remove(0)
        })
    }
}

fn manager(fx: &Fx, turns: Vec<AssistantTurn>) -> Arc<sessions::SessionManager> {
    let llm = Arc::new(Scripted {
        turns: Mutex::new(turns),
    });
    Arc::new(
        sessions::SessionManager::new(
            Arc::new(move |_ep: &sessions::LlmEndpoint| llm.clone() as Arc<dyn LlmClient>),
            Duration::from_secs(5),
        )
        .with_grants_home(fx.home()),
    )
}

fn hello_session_body(fx: &Fx, sandbox: Option<serde_json::Value>) -> sessions::CreateSessionReq {
    let mut b = serde_json::json!({
        "model": "gemma-4",
        "systemPrompt": "You are Hermes.",
        "llm": {"baseUrl": "http://127.0.0.1:18080/v1", "bearer": "k"},
        "tools": [{
            "name": "hello",
            "description": "greet",
            "parameters": {"type": "object", "properties": {"name": {"type": "string"}}},
            "host": "sidecar"
        }],
        "maxToolsPerRequest": 16,
        "grants": fx.read_grant_doc(),
    });
    if let Some(s) = sandbox {
        b["capsuleSandbox"] = s;
    }
    serde_json::from_value(b).expect("body")
}

async fn hello_result(fx: &Fx, sandbox: Option<serde_json::Value>) -> serde_json::Value {
    let call = ToolCall {
        id: "c1".into(),
        name: "hello".into(),
        arguments: serde_json::json!({ "name": "member" }).to_string(),
    };
    let mgr = manager(fx, vec![AssistantTurn::tools(vec![call])]);
    let id = mgr
        .create(hello_session_body(fx, sandbox))
        .expect("session");
    let dispatch = load_dispatch(&shipped_capsules_dir(), Arc::new(ApprovalQueue::new()));
    assert!(dispatch.as_ref().is_some_and(|d| d.is_runnable("hello")));
    mgr.send(&id, "say hello".into(), dispatch).expect("send");
    let s = mgr.get(&id).expect("session");
    let mut after = 0;
    for _ in 0..100 {
        let page = s.wait_events(after, Duration::from_millis(200)).await;
        for e in page.events {
            after = after.max(e.seq);
            let v = serde_json::to_value(&e.event).expect("event");
            if v["type"] == "tool_result" {
                return v;
            }
        }
    }
    panic!("no tool_result");
}

#[tokio::test(flavor = "multi_thread")]
async fn a_session_capsule_call_runs_under_the_session_sandbox() {
    let fx = Fx::new();
    // No bindings: hello (pure compute) runs, with nothing mounted.
    let ok = hello_result(&fx, None).await;
    assert_eq!(ok["status"], "ok", "{ok}");
    assert!(
        ok["content"]
            .as_str()
            .unwrap_or("")
            .contains("Hello, member"),
        "{ok}"
    );
    // A binding the manifest does not declare: the session's sandbox refuses the call before any
    // capsule code runs (the dispatch default would have run it).
    let refused = hello_result(
        &fx,
        Some(serde_json::json!({
            "mounts": [{ "capsule": "hello", "guest": "/work", "host": fx.proj() }]
        })),
    )
    .await;
    assert_eq!(refused["status"], "error", "{refused}");
    assert!(
        refused["content"]
            .as_str()
            .unwrap_or("")
            .contains("declares no"),
        "{refused}"
    );
}

#[test]
fn a_session_with_mounts_but_no_grants_is_refused() {
    let fx = Fx::new();
    let mgr = manager(&fx, vec![]);
    let b = serde_json::json!({
        "model": "gemma-4",
        "systemPrompt": "You are Hermes.",
        "llm": {"baseUrl": "http://127.0.0.1:18080/v1", "bearer": "k"},
        "tools": [],
        "capsuleSandbox": { "mounts": [{ "capsule": "hello", "guest": "/work", "host": fx.proj() }] }
    });
    let req: sessions::CreateSessionReq = serde_json::from_value(b).expect("request parses");
    match mgr.create(req) {
        Err(sessions::SessionError::Invalid(why)) => assert!(why.contains("grant"), "{why}"),
        other => panic!("expected a refusal, got {other:?}"),
    }
}

#[test]
fn only_runnable_capsules_are_listed_as_skills() {
    let tmp = std::env::temp_dir().join(format!(
        "citrate-sidecar-skills-{}-{}",
        std::process::id(),
        N.fetch_add(1, Ordering::SeqCst)
    ));
    let _ = std::fs::remove_dir_all(&tmp);
    let src = shipped_capsules_dir();
    for name in ["hello", "echo-chain"] {
        let dst = tmp.join(name);
        std::fs::create_dir_all(&dst).expect("mkdir");
        for f in std::fs::read_dir(src.join(name)).expect("list").flatten() {
            if f.path().is_file() {
                std::fs::copy(f.path(), dst.join(f.file_name())).expect("copy");
            }
        }
    }
    // echo-chain's signed archive is corrupted: refused at load.
    std::fs::write(tmp.join("echo-chain/echo-chain.cps"), b"corrupt").expect("write");
    // A loose (unsigned) capsule: loaded for listing only, never runnable.
    let loose = tmp.join("loose");
    std::fs::create_dir_all(&loose).expect("mkdir");
    std::fs::copy(src.join("hello/manifest.toml"), loose.join("manifest.toml")).expect("copy");
    let text = std::fs::read_to_string(loose.join("manifest.toml"))
        .expect("read")
        .replace("name = \"hello\"", "name = \"loose\"");
    std::fs::write(loose.join("manifest.toml"), text).expect("write");
    std::fs::copy(src.join("hello/capsule.wasm"), loose.join("capsule.wasm")).expect("copy");

    let dispatch = load_dispatch(&tmp, Arc::new(ApprovalQueue::new()));
    let listed: Vec<String> = runnable_skills(load_skills(&tmp), dispatch.as_deref())
        .into_iter()
        .map(|s| s.name)
        .collect();
    assert_eq!(listed, vec!["hello".to_string()]);
    // With no dispatch at all, nothing can run, so nothing is listed.
    assert!(runnable_skills(load_skills(&tmp), None).is_empty());
    let _ = std::fs::remove_dir_all(&tmp);
}
