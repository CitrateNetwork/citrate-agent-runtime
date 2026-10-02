//! US-2.2 AC2 — the general `shell_run` tool: the agent proposes an exact argv and cwd, the member
//! sees exactly that (plus the program it resolves to and the sandbox) and decides, and only an
//! approved command runs, inside the OS sandbox, in a live folder grant, with a timeout and
//! capped output. Off by default; refused in a tainted session; fails closed without a sandbox.
//!
//! BDD map:
//! - "Anything else shows the exact command + cwd for approval":
//!   `a_call_waits_for_the_member_and_shows_exactly_what_will_run`,
//!   `an_approved_command_runs_and_reports`, `a_declined_command_never_runs`,
//!   `a_decision_must_carry_the_argv_and_cwd_that_were_shown`.
//! - Grants: `a_cwd_outside_the_grants_is_refused_before_asking`,
//!   `a_read_only_or_shallow_grant_is_not_enough`, `a_revoked_grant_stops_an_approved_run`.
//! - Taint: `a_tainted_session_is_refused_and_nothing_is_asked`,
//!   `an_unattended_session_never_offers_a_run`.
//! - Sandbox: `no_sandbox_means_no_run_and_no_question`, `the_approved_run_is_sandboxed` (macOS).
//! - Timeout + capture: `a_command_past_its_timeout_is_killed_and_reported`,
//!   `output_is_capped`.
//! - Off by default: `shell_run_is_off_unless_the_env_flag_is_exactly_1`,
//!   `sessions_without_grants_are_not_offered_shell_run`.

#![cfg(unix)]

use super::grants::SessionGrants;
use super::shell_run::*;
use super::*;
use axum::body::Body;
use axum::http::{Request, StatusCode};
use citrate_agent_grants::{Access, FolderGrants, GrantRequest, GrantScope};
use citrate_agent_loop::verifiers_tooling::{RunStatus, ToolchainEnvelope};
use citrate_agent_loop::{
    AssistantTurn, CompletionRequest, Effect, HostKind, LlmClient, LlmError, StopFlag, TaintState,
    ToolCall, ToolHost, ToolOutcome, Trust,
};
use citrate_agent_shell::sandbox::{Backend, SandboxMode, SandboxPolicy};
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

/// `base/home/proj` (granted read + write) and `base/home/other` (not granted).
struct Fx {
    base: PathBuf,
}
impl Fx {
    fn new() -> Self {
        let base = std::env::temp_dir().join(format!(
            "citrate-sidecar-shell-{}-{}",
            std::process::id(),
            N.fetch_add(1, Ordering::SeqCst)
        ));
        let _ = std::fs::remove_dir_all(&base);
        for d in ["home/proj/src", "home/other"] {
            std::fs::create_dir_all(base.join(d)).unwrap();
        }
        Fx {
            base: base.canonicalize().unwrap(),
        }
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
    fn doc_with(&self, reqs: Vec<GrantRequest>) -> serde_json::Value {
        let mut g = FolderGrants::new(self.home(), self.home());
        for r in reqs {
            g.grant(r, now()).unwrap();
        }
        serde_json::to_value(g.state()).unwrap()
    }
    fn rw_doc(&self) -> serde_json::Value {
        self.doc_with(vec![
            GrantRequest::folder(self.proj(), Access::Read, MEMBER, "build it"),
            GrantRequest::folder(self.proj(), Access::Write, MEMBER, "build it"),
        ])
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

/// The real sandbox on this machine when there is one; otherwise a stated test backend answer is
/// not available, so tests that need a run use [`cfg_open`] (sandbox off) explicitly.
fn cfg_with(sandbox: SandboxPolicy) -> ShellRunConfig {
    ShellRunConfig {
        search_path: vec![PathBuf::from("/bin"), PathBuf::from("/usr/bin")],
        sandbox,
        approval_timeout: Duration::from_secs(10),
    }
}

/// Runs without an OS sandbox (only for tests of the approval flow itself, which must pass on
/// machines with no backend too). Production always requires the sandbox.
fn cfg_open() -> ShellRunConfig {
    cfg_with(SandboxPolicy::new(SandboxMode::Off))
}

fn call(id: &str, argv: &[&str], cwd: &Path) -> ToolCall {
    ToolCall {
        id: id.into(),
        name: SHELL_RUN_TOOL.into(),
        arguments: serde_json::json!({ "argv": argv, "cwd": cwd }).to_string(),
    }
}

/// Run `c` on a thread; return its outcome handle.
fn spawn(host: ShellRunHost, c: ToolCall) -> std::thread::JoinHandle<ToolOutcome> {
    std::thread::spawn(move || host.execute(&c))
}

fn wait_pending(approvals: &ShellApprovals) -> ShellPending {
    for _ in 0..500 {
        if let Some(p) = approvals.pending().into_iter().next() {
            return p;
        }
        std::thread::sleep(Duration::from_millis(10));
    }
    panic!("nothing became pending");
}

fn envelope(o: &ToolOutcome) -> ToolchainEnvelope {
    let s = match o {
        ToolOutcome::Ok(s) | ToolOutcome::Untrusted(s) | ToolOutcome::Error(s) => s,
        ToolOutcome::Denied(s) => panic!("unexpected denial: {s}"),
    };
    ToolchainEnvelope::from_content(s).unwrap()
}

fn session(fx: &Fx, cfg: &ShellRunConfig) -> ShellRunSession {
    ShellRunSession::new(cfg, fx.grants(&fx.rw_doc())).unwrap()
}

// ------------------------------------------------------------------------------------------
// Config + spec
// ------------------------------------------------------------------------------------------

fn vars(pairs: &[(&str, &str)]) -> impl Fn(&str) -> Option<String> {
    let m: std::collections::HashMap<String, String> = pairs
        .iter()
        .map(|(k, v)| (k.to_string(), v.to_string()))
        .collect();
    move |k| m.get(k).cloned()
}

#[test]
fn shell_run_is_off_unless_the_env_flag_is_exactly_1() {
    assert!(ShellRunConfig::from_env_vars(vars(&[("HOME", "/h")])).is_none());
    assert!(
        ShellRunConfig::from_env_vars(vars(&[(SHELL_RUN_ENV, "true"), ("HOME", "/h")])).is_none()
    );
    let c = ShellRunConfig::from_env_vars(vars(&[(SHELL_RUN_ENV, "1"), ("HOME", "/h")])).unwrap();
    // Always the OS sandbox, whatever the toolchain's sandbox setting says.
    assert_eq!(c.sandbox.mode(), SandboxMode::Required);
    let c = ShellRunConfig::from_env_vars(vars(&[
        (SHELL_RUN_ENV, "1"),
        ("HOME", "/h"),
        (crate::toolchain::SANDBOX_ENV, "off"),
        (SHELL_PATH_ENV, "/opt/x/bin:rel/bin"),
    ]))
    .unwrap();
    assert_eq!(c.sandbox.mode(), SandboxMode::Required);
    assert_eq!(c.search_path, vec![PathBuf::from("/opt/x/bin")]);
    assert_eq!(c.approval_timeout, APPROVAL_TIMEOUT);
}

#[test]
fn the_spec_is_a_sidecar_write_tool_whose_output_is_untrusted() {
    let s = shell_run_spec();
    assert_eq!(s.name, SHELL_RUN_TOOL);
    assert_eq!(s.host, HostKind::Sidecar);
    assert_eq!(s.annotations.effect, Some(Effect::Write));
    assert_eq!(s.annotations.trust, Some(Trust::Untrusted));
    assert_eq!(s.parameters["required"], serde_json::json!(["argv", "cwd"]));
    assert!(s.description.contains("approve"));
}

// ------------------------------------------------------------------------------------------
// The approval flow
// ------------------------------------------------------------------------------------------

#[test]
fn a_call_waits_for_the_member_and_shows_exactly_what_will_run() {
    let fx = Fx::new();
    let s = session(&fx, &cfg_open());
    let approvals = s.approvals().clone();
    let h = spawn(
        s.host(TaintState::default(), StopFlag::default()),
        call("c1", &["echo", "hello $(id)"], &fx.proj().join("src")),
    );
    let p = wait_pending(&approvals);
    assert!(p.id.starts_with("sh-"), "{}", p.id);
    assert_eq!(p.call_id, "c1");
    assert_eq!(p.tool, SHELL_RUN_TOOL);
    assert_eq!(p.hic, "required");
    assert_eq!(p.argv, vec!["echo", "hello $(id)"]);
    assert_eq!(p.resolved_program, "/bin/echo");
    assert_eq!(p.cwd, fx.proj().join("src").display().to_string());
    assert_eq!(p.timeout_secs, 120);
    assert!(p.expires_in_secs <= 10);
    assert!(!p.sandbox.summary.is_empty());
    let v = serde_json::to_value(&p).unwrap();
    for k in ["callId", "resolvedProgram", "timeoutSecs", "expiresInSecs"] {
        assert!(v.get(k).is_some(), "camelCase field {k} missing: {v}");
    }
    approvals
        .decide(&p.id, false, &p.argv, &p.cwd)
        .expect("decide");
    assert!(matches!(h.join().unwrap(), ToolOutcome::Denied(_)));
    assert!(approvals.pending().is_empty());
}

#[test]
fn an_approved_command_runs_and_reports() {
    let fx = Fx::new();
    let s = session(&fx, &cfg_open());
    let approvals = s.approvals().clone();
    let marker = fx.proj().join("built.txt");
    let h = spawn(
        s.host(TaintState::default(), StopFlag::default()),
        call(
            "c1",
            &[
                "sh",
                "-c",
                &format!("echo out; echo err >&2; echo done > '{}'", marker.display()),
            ],
            &fx.proj(),
        ),
    );
    let p = wait_pending(&approvals);
    assert!(!marker.exists(), "nothing runs before the member decides");
    approvals.decide(&p.id, true, &p.argv, &p.cwd).unwrap();
    let out = h.join().unwrap();
    assert!(matches!(out, ToolOutcome::Ok(_)), "{out:?}");
    let env = envelope(&out);
    assert_eq!(env.tool, SHELL_RUN_TOOL);
    assert_eq!(env.status, RunStatus::Completed);
    let run = env.run.unwrap();
    assert_eq!(run["exit_code"], 0);
    assert_eq!(run["stdout"], "out\n");
    assert_eq!(run["stderr"], "err\n");
    assert_eq!(run["argv"][0], "sh");
    assert_eq!(run["cwd"], fx.proj().display().to_string());
    assert!(run["sandbox"].is_object());
    assert!(marker.exists());
}

#[test]
fn a_declined_command_never_runs() {
    let fx = Fx::new();
    let s = session(&fx, &cfg_open());
    let approvals = s.approvals().clone();
    let marker = fx.proj().join("never.txt");
    let h = spawn(
        s.host(TaintState::default(), StopFlag::default()),
        call(
            "c1",
            &["sh", "-c", &format!("echo x > '{}'", marker.display())],
            &fx.proj(),
        ),
    );
    let p = wait_pending(&approvals);
    approvals.decide(&p.id, false, &p.argv, &p.cwd).unwrap();
    match h.join().unwrap() {
        ToolOutcome::Denied(why) => assert!(why.contains("declined"), "{why}"),
        other => panic!("{other:?}"),
    }
    assert!(!marker.exists());
}

#[test]
fn a_decision_must_carry_the_argv_and_cwd_that_were_shown() {
    let fx = Fx::new();
    let s = session(&fx, &cfg_open());
    let approvals = s.approvals().clone();
    let h = spawn(
        s.host(TaintState::default(), StopFlag::default()),
        call("c1", &["echo", "a"], &fx.proj()),
    );
    let p = wait_pending(&approvals);
    let other_argv = vec!["echo".to_string(), "b".to_string()];
    assert!(approvals.decide(&p.id, true, &other_argv, &p.cwd).is_err());
    let other_cwd = fx.proj().join("src").display().to_string();
    assert!(approvals.decide(&p.id, true, &p.argv, &other_cwd).is_err());
    assert!(approvals
        .decide("sh-999999", true, &p.argv, &p.cwd)
        .is_err());
    // Still waiting after the refused decisions; a matching one goes through.
    assert_eq!(approvals.pending().len(), 1);
    approvals.decide(&p.id, true, &p.argv, &p.cwd).unwrap();
    assert!(matches!(h.join().unwrap(), ToolOutcome::Ok(_)));
    // A decided approval cannot be decided again.
    assert!(approvals.decide(&p.id, true, &p.argv, &p.cwd).is_err());
}

#[test]
fn an_unanswered_approval_expires_as_declined() {
    let fx = Fx::new();
    let mut cfg = cfg_open();
    cfg.approval_timeout = Duration::from_millis(200);
    let s = session(&fx, &cfg);
    let out = s
        .host(TaintState::default(), StopFlag::default())
        .execute(&call("c1", &["echo", "a"], &fx.proj()));
    match out {
        ToolOutcome::Denied(why) => assert!(why.contains("no decision"), "{why}"),
        other => panic!("{other:?}"),
    }
    assert!(s.approvals().pending().is_empty());
}

#[test]
fn a_session_stop_declines_a_waiting_command() {
    let fx = Fx::new();
    let s = session(&fx, &cfg_open());
    let approvals = s.approvals().clone();
    let stop = StopFlag::default();
    let h = spawn(
        s.host(TaintState::default(), stop.clone()),
        call("c1", &["echo", "a"], &fx.proj()),
    );
    wait_pending(&approvals);
    stop.stop();
    assert!(matches!(h.join().unwrap(), ToolOutcome::Denied(_)));
    assert!(approvals.pending().is_empty());
}

// ------------------------------------------------------------------------------------------
// Refused before anything is asked
// ------------------------------------------------------------------------------------------

fn refused(out: ToolOutcome, needle: &str) {
    let env = envelope(&out);
    assert!(matches!(out, ToolOutcome::Error(_)), "{out:?}");
    assert!(
        matches!(env.status, RunStatus::Refused | RunStatus::NotInstalled),
        "{env:?}"
    );
    assert!(env.summary.contains(needle), "{} !~ {needle}", env.summary);
}

#[test]
fn bad_arguments_are_refused_before_asking() {
    let fx = Fx::new();
    let s = session(&fx, &cfg_open());
    let host = s.host(TaintState::default(), StopFlag::default());
    let raw = |args: serde_json::Value| {
        host.execute(&ToolCall {
            id: "c".into(),
            name: SHELL_RUN_TOOL.into(),
            arguments: args.to_string(),
        })
    };
    refused(raw(serde_json::json!({"cwd": fx.proj()})), "argv");
    refused(
        raw(serde_json::json!({"argv": [], "cwd": fx.proj()})),
        "argv",
    );
    refused(
        raw(serde_json::json!({"argv": ["echo", 3], "cwd": fx.proj()})),
        "argv",
    );
    refused(raw(serde_json::json!({"argv": ["echo"]})), "cwd");
    refused(
        raw(serde_json::json!({"argv": ["echo"], "cwd": "rel"})),
        "absolute",
    );
    refused(
        raw(serde_json::json!({"argv": ["echo"], "cwd": fx.proj(), "timeout_secs": 0})),
        "timeout_secs",
    );
    refused(
        raw(serde_json::json!({"argv": ["echo"], "cwd": fx.proj(), "timeout_secs": 100000})),
        "timeout_secs",
    );
    refused(
        raw(serde_json::json!({"argv": ["/bin/echo"], "cwd": fx.proj()})),
        "bare name",
    );
    let many: Vec<String> = (0..(MAX_ARGV + 1)).map(|i| i.to_string()).collect();
    refused(
        raw(serde_json::json!({"argv": many, "cwd": fx.proj()})),
        "argv",
    );
    refused(
        raw(serde_json::json!({"argv": ["definitely-not-installed-xyz"], "cwd": fx.proj()})),
        "not installed",
    );
    assert!(s.approvals().pending().is_empty());
}

#[test]
fn a_cwd_outside_the_grants_is_refused_before_asking() {
    let fx = Fx::new();
    let s = session(&fx, &cfg_open());
    let host = s.host(TaintState::default(), StopFlag::default());
    refused(host.execute(&call("c", &["echo"], &fx.other())), "refused");
    refused(host.execute(&call("c", &["echo"], &fx.home())), "refused");
    assert!(s.approvals().pending().is_empty());
}

#[test]
fn a_read_only_or_shallow_grant_is_not_enough() {
    let fx = Fx::new();
    let read_only = fx.doc_with(vec![GrantRequest::folder(
        fx.proj(),
        Access::Read,
        MEMBER,
        "look",
    )]);
    let s = ShellRunSession::new(&cfg_open(), fx.grants(&read_only)).unwrap();
    refused(
        s.host(TaintState::default(), StopFlag::default())
            .execute(&call("c", &["echo"], &fx.proj())),
        "refused",
    );
    let shallow = fx.doc_with(vec![
        GrantRequest::folder(fx.proj(), Access::Read, MEMBER, "x").with_scope(GrantScope::Shallow),
        GrantRequest::folder(fx.proj(), Access::Write, MEMBER, "x").with_scope(GrantScope::Shallow),
    ]);
    let s = ShellRunSession::new(&cfg_open(), fx.grants(&shallow)).unwrap();
    refused(
        s.host(TaintState::default(), StopFlag::default())
            .execute(&call("c", &["echo"], &fx.proj())),
        "everything below",
    );
}

#[test]
fn a_revoked_grant_stops_an_approved_run() {
    let fx = Fx::new();
    let grants = fx.grants(&fx.rw_doc());
    let s = ShellRunSession::new(&cfg_open(), grants.clone()).unwrap();
    let approvals = s.approvals().clone();
    let marker = fx.proj().join("late.txt");
    let h = spawn(
        s.host(TaintState::default(), StopFlag::default()),
        call(
            "c1",
            &["sh", "-c", &format!("echo x > '{}'", marker.display())],
            &fx.proj(),
        ),
    );
    let p = wait_pending(&approvals);
    // The member revokes every grant while the card is open, then (by mistake) approves.
    grants.replace(&fx.doc_with(vec![])).unwrap();
    approvals.decide(&p.id, true, &p.argv, &p.cwd).unwrap();
    let out = h.join().unwrap();
    assert!(matches!(out, ToolOutcome::Error(_)), "{out:?}");
    assert!(!marker.exists());
}

#[test]
fn a_tainted_session_is_refused_and_nothing_is_asked() {
    let fx = Fx::new();
    let s = session(&fx, &cfg_open());
    let taint = TaintState::default();
    taint.taint("read_url", "a web page");
    let out = s
        .host(taint, StopFlag::default())
        .execute(&call("c1", &["echo", "a"], &fx.proj()));
    match out {
        ToolOutcome::Denied(why) => assert!(why.contains("untrusted"), "{why}"),
        other => panic!("{other:?}"),
    }
    assert!(s.approvals().pending().is_empty());
}

#[test]
fn no_sandbox_means_no_run_and_no_question() {
    let fx = Fx::new();
    let cfg = cfg_with(
        SandboxPolicy::new(SandboxMode::Required)
            .with_backend(Err("no sandbox program here".into())),
    );
    let s = session(&fx, &cfg);
    let out = s
        .host(TaintState::default(), StopFlag::default())
        .execute(&call("c1", &["echo", "a"], &fx.proj()));
    refused(out, "sandbox");
    assert!(s.approvals().pending().is_empty());
}

// ------------------------------------------------------------------------------------------
// Timeout + capture
// ------------------------------------------------------------------------------------------

fn approve_next(approvals: Arc<ShellApprovals>) -> std::thread::JoinHandle<()> {
    std::thread::spawn(move || {
        let p = wait_pending(&approvals);
        approvals.decide(&p.id, true, &p.argv, &p.cwd).unwrap();
    })
}

#[test]
fn a_command_past_its_timeout_is_killed_and_reported() {
    let fx = Fx::new();
    let s = session(&fx, &cfg_open());
    let a = approve_next(s.approvals().clone());
    let c = ToolCall {
        id: "c1".into(),
        name: SHELL_RUN_TOOL.into(),
        arguments:
            serde_json::json!({"argv": ["sleep", "30"], "cwd": fx.proj(), "timeout_secs": 1})
                .to_string(),
    };
    let started = std::time::Instant::now();
    let out = s
        .host(TaintState::default(), StopFlag::default())
        .execute(&c);
    a.join().unwrap();
    assert!(started.elapsed() < Duration::from_secs(10));
    let env = envelope(&out);
    assert!(matches!(out, ToolOutcome::Error(_)));
    assert_eq!(env.status, RunStatus::TimedOut);
    assert_eq!(env.run.unwrap()["timed_out"], true);
}

#[test]
fn output_is_capped() {
    let fx = Fx::new();
    let s = session(&fx, &cfg_open());
    let a = approve_next(s.approvals().clone());
    let out = s
        .host(TaintState::default(), StopFlag::default())
        .execute(&call(
            "c1",
            &["sh", "-c", "yes x | head -c 200000"],
            &fx.proj(),
        ));
    a.join().unwrap();
    let run = envelope(&out).run.unwrap();
    assert_eq!(run["stdout_truncated"], true);
    assert_eq!(run["stdout_bytes"], 200000);
    assert!(run["stdout"].as_str().unwrap().len() < OUTPUT_CAP + 100);
}

// ------------------------------------------------------------------------------------------
// macOS: the approved run is sandboxed (Seatbelt)
// ------------------------------------------------------------------------------------------

#[cfg(target_os = "macos")]
#[test]
fn the_approved_run_is_sandboxed() {
    let fx = Fx::new();
    let s = session(&fx, &cfg_with(SandboxPolicy::new(SandboxMode::Required)));
    let approvals = s.approvals().clone();
    let inside = fx.proj().join("src/ok.txt");
    let outside = fx.other().join("escape.txt");
    let h = spawn(
        s.host(TaintState::default(), StopFlag::default()),
        call(
            "c1",
            &[
                "sh",
                "-c",
                &format!(
                    "echo ok > '{}'; echo x > '{}'; exit 0",
                    inside.display(),
                    outside.display()
                ),
            ],
            &fx.proj(),
        ),
    );
    let p = wait_pending(&approvals);
    assert!(p.sandbox.enforced);
    assert_eq!(p.sandbox.backend, "seatbelt");
    assert_eq!(p.sandbox.network, "denied");
    assert!(p
        .sandbox
        .writable
        .contains(&fx.proj().display().to_string()));
    approvals.decide(&p.id, true, &p.argv, &p.cwd).unwrap();
    let run = envelope(&h.join().unwrap()).run.unwrap();
    assert_eq!(run["sandbox"]["enforced"], true);
    assert!(inside.exists(), "a write in the grant is allowed");
    assert!(!outside.exists(), "a write outside the grant is denied");
    assert!(
        run["stderr"]
            .as_str()
            .unwrap()
            .contains("Operation not permitted"),
        "{run}"
    );
}

#[test]
fn backend_override_reaches_the_card() {
    // A machine whose backend is bubblewrap shows that on the card (the argv is built, not run).
    let fx = Fx::new();
    let cfg = cfg_with(SandboxPolicy::new(SandboxMode::Required).with_backend(Ok(
        Backend::Bwrap {
            exe: PathBuf::from("/usr/bin/bwrap"),
        },
    )));
    let s = session(&fx, &cfg);
    let approvals = s.approvals().clone();
    let stop = StopFlag::default();
    let h = spawn(
        s.host(TaintState::default(), stop.clone()),
        call("c1", &["echo", "a"], &fx.proj()),
    );
    let p = wait_pending(&approvals);
    assert_eq!(p.sandbox.backend, "bwrap");
    assert!(p.sandbox.summary.contains("Linux bubblewrap"));
    stop.stop();
    assert!(matches!(h.join().unwrap(), ToolOutcome::Denied(_)));
}

// ------------------------------------------------------------------------------------------
// Sessions + routes
// ------------------------------------------------------------------------------------------

struct Script(Mutex<Vec<AssistantTurn>>);
impl LlmClient for Script {
    fn complete(&self, _req: &CompletionRequest) -> Result<AssistantTurn, LlmError> {
        let mut t = self.0.lock().unwrap();
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
    cfg: Option<ShellRunConfig>,
) -> Arc<sessions::SessionManager> {
    let script = Arc::new(Script(Mutex::new(turns)));
    let mut mgr = sessions::SessionManager::new(
        Arc::new(move |_ep: &sessions::LlmEndpoint| script.clone() as Arc<dyn LlmClient>),
        Duration::from_secs(5),
    )
    .with_grants_home(fx.home());
    if let Some(c) = cfg {
        mgr = mgr.with_shell_run(Arc::new(c));
    }
    Arc::new(mgr)
}

fn create_req(grants: Option<serde_json::Value>, unattended: bool) -> sessions::CreateSessionReq {
    let mut b = serde_json::json!({
        "model": "gemma-4",
        "systemPrompt": "You are Hermes.",
        "llm": {"baseUrl": "http://127.0.0.1:18080/v1", "bearer": "k"},
        "tools": [],
        "maxToolsPerRequest": 8,
        "unattended": unattended,
    });
    if let Some(g) = grants {
        b["grants"] = g;
    }
    serde_json::from_value(b).unwrap()
}

fn app_for(mgr: Arc<sessions::SessionManager>) -> axum::Router {
    app(Arc::new(AppState {
        estop: EmergencyStop::new(),
        queue: Arc::new(ApprovalQueue::new()),
        skills: vec![],
        dispatch: None,
        bearer: BEARER.to_string(),
        run_slots: Arc::new(tokio::sync::Semaphore::new(MAX_CONCURRENT_SKILLS)),
        sessions: mgr,
    }))
}

async fn send(
    app: &axum::Router,
    method: &str,
    path: &str,
    body: Option<serde_json::Value>,
) -> (StatusCode, serde_json::Value) {
    let req = Request::builder()
        .method(method)
        .uri(path)
        .header("authorization", format!("Bearer {BEARER}"))
        .header("content-type", "application/json")
        .body(match body {
            Some(b) => Body::from(b.to_string()),
            None => Body::empty(),
        })
        .unwrap();
    let resp = app.clone().oneshot(req).await.unwrap();
    let status = resp.status();
    let bytes = axum::body::to_bytes(resp.into_body(), 1 << 20)
        .await
        .unwrap();
    (
        status,
        serde_json::from_slice(&bytes).unwrap_or(serde_json::Value::Null),
    )
}

#[test]
fn sessions_without_grants_are_not_offered_shell_run() {
    let fx = Fx::new();
    let mgr = manager(&fx, vec![], Some(cfg_open()));
    let id = mgr.create(create_req(None, false)).unwrap();
    assert!(!mgr
        .get(&id)
        .unwrap()
        .tool_names()
        .contains(&SHELL_RUN_TOOL.to_string()));
    let id = mgr.create(create_req(Some(fx.rw_doc()), false)).unwrap();
    assert!(mgr
        .get(&id)
        .unwrap()
        .tool_names()
        .contains(&SHELL_RUN_TOOL.to_string()));
    // Off: never offered, even with grants.
    let off = manager(&fx, vec![], None);
    let id = off.create(create_req(Some(fx.rw_doc()), false)).unwrap();
    assert!(!off
        .get(&id)
        .unwrap()
        .tool_names()
        .contains(&SHELL_RUN_TOOL.to_string()));
}

#[test]
fn a_session_tool_may_not_claim_the_shell_run_name() {
    let fx = Fx::new();
    let mgr = manager(&fx, vec![], Some(cfg_open()));
    let mut req = create_req(Some(fx.rw_doc()), false);
    req.tools = vec![serde_json::from_value(serde_json::json!({
        "name": SHELL_RUN_TOOL, "description": "x", "parameters": {"type": "object"}, "host": "core"
    }))
    .unwrap()];
    assert!(matches!(
        mgr.create(req),
        Err(sessions::SessionError::Invalid(_))
    ));
}

#[tokio::test(flavor = "multi_thread")]
async fn the_member_decides_through_the_routes_and_the_result_reaches_the_event_log() {
    let fx = Fx::new();
    let marker = fx.proj().join("routed.txt");
    let c = call(
        "call_0",
        &[
            "sh",
            "-c",
            &format!("echo routed > '{}'; echo hi", marker.display()),
        ],
        &fx.proj(),
    );
    let mgr = manager(
        &fx,
        vec![AssistantTurn::tools(vec![c]), AssistantTurn::text("Done.")],
        Some(cfg_open()),
    );
    let id = mgr.create(create_req(Some(fx.rw_doc()), false)).unwrap();
    let app = app_for(mgr.clone());
    mgr.send(&id, "build it".into(), None).unwrap();
    // The card's data appears on the pending route.
    let mut pending = serde_json::Value::Null;
    for _ in 0..300 {
        let (st, body) = send(&app, "GET", &format!("/sessions/{id}/shell/pending"), None).await;
        assert_eq!(st, StatusCode::OK);
        if body["pending"].as_array().is_some_and(|a| !a.is_empty()) {
            pending = body["pending"][0].clone();
            break;
        }
        tokio::time::sleep(Duration::from_millis(10)).await;
    }
    assert_eq!(pending["callId"], "call_0", "{pending}");
    assert_eq!(pending["hic"], "required");
    // A decision with a different argv is refused (409) and nothing runs.
    let (st, _) = send(
        &app,
        "POST",
        &format!("/sessions/{id}/shell/decide"),
        Some(serde_json::json!({"id": pending["id"], "allow": true, "argv": ["sh"], "cwd": pending["cwd"]})),
    )
    .await;
    assert_eq!(st, StatusCode::CONFLICT);
    assert!(!marker.exists());
    let (st, body) = send(
        &app,
        "POST",
        &format!("/sessions/{id}/shell/decide"),
        Some(serde_json::json!({"id": pending["id"], "allow": true, "argv": pending["argv"], "cwd": pending["cwd"]})),
    )
    .await;
    assert_eq!(st, StatusCode::OK, "{body}");
    // The run report is in the session's event log as the tool result.
    let s = mgr.get(&id).unwrap();
    let mut result = serde_json::Value::Null;
    for _ in 0..300 {
        let page = s.events_after(0);
        if let Some(e) = page
            .events
            .iter()
            .map(|e| serde_json::to_value(&e.event).unwrap())
            .find(|e| e["type"] == "tool_result")
        {
            result = e;
            break;
        }
        tokio::time::sleep(Duration::from_millis(10)).await;
    }
    assert_eq!(result["status"], "ok", "{result}");
    let env = ToolchainEnvelope::from_content(result["content"].as_str().unwrap()).unwrap();
    assert_eq!(env.run.unwrap()["stdout"], "hi\n");
    assert!(marker.exists());
    // Bad bodies and unknown sessions.
    let (st, _) = send(
        &app,
        "POST",
        &format!("/sessions/{id}/shell/decide"),
        Some(serde_json::json!({"id": 1})),
    )
    .await;
    assert_eq!(st, StatusCode::BAD_REQUEST);
    let (st, _) = send(&app, "GET", "/sessions/nope/shell/pending", None).await;
    assert_eq!(st, StatusCode::NOT_FOUND);
}

#[tokio::test(flavor = "multi_thread")]
async fn the_shell_routes_need_the_bearer() {
    let fx = Fx::new();
    let mgr = manager(&fx, vec![], Some(cfg_open()));
    let id = mgr.create(create_req(Some(fx.rw_doc()), false)).unwrap();
    let app = app_for(mgr);
    let resp = app
        .oneshot(
            Request::builder()
                .uri(format!("/sessions/{id}/shell/pending"))
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(resp.status(), StatusCode::UNAUTHORIZED);
}

#[tokio::test(flavor = "multi_thread")]
async fn an_unattended_session_never_offers_a_run() {
    let fx = Fx::new();
    let marker = fx.proj().join("daemon.txt");
    let c = call(
        "call_0",
        &["sh", "-c", &format!("echo x > '{}'", marker.display())],
        &fx.proj(),
    );
    let mgr = manager(
        &fx,
        vec![AssistantTurn::tools(vec![c]), AssistantTurn::text("ok")],
        Some(cfg_open()),
    );
    let id = mgr.create(create_req(Some(fx.rw_doc()), true)).unwrap();
    mgr.send(&id, "build it".into(), None).unwrap();
    let s = mgr.get(&id).unwrap();
    let mut result = serde_json::Value::Null;
    for _ in 0..300 {
        if let Some(e) = s
            .events_after(0)
            .events
            .iter()
            .map(|e| serde_json::to_value(&e.event).unwrap())
            .find(|e| e["type"] == "tool_result")
        {
            result = e;
            break;
        }
        tokio::time::sleep(Duration::from_millis(10)).await;
    }
    assert_eq!(result["status"], "denied", "{result}");
    assert!(s.shell_pending().unwrap_or_default().is_empty());
    assert!(!marker.exists());
}
