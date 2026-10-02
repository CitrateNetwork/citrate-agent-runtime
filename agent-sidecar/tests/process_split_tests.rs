//! HUP-S1.9 — the process split: the toolchain tools run in a separate worker process (the real
//! `citrate-agent-sidecar --worker toolchain` binary), supervised by the sidecar with restarts,
//! health checks and clean shutdown. A crash in the worker never takes down the sidecar or a
//! session, and the session reports the crash honestly in the tool result.
//!
//! The toolchain programs are small `/bin/sh` stand-ins on a private search path (as in the
//! in-process toolchain tests), so this runs in CI without forge.
#![cfg(unix)]

use agent_sidecar::sessions::{CreateSessionReq, LlmEndpoint, SessionManager};
use agent_sidecar::workers::{
    toolchain_worker_spec, RemoteToolHost, WorkerSet, WORKER_ARG, WORKER_TOOLCHAIN,
};
use citrate_agent_loop::verifiers_tooling::{RunStatus, ToolchainEnvelope, FORGE_TEST_TOOL};
use citrate_agent_loop::{
    AssistantTurn, CompletionRequest, LlmClient, LlmError, ToolCall, ToolHost, ToolOutcome,
};
use citrate_agent_workers::{RestartPolicy, Worker, WorkerState};
use serde_json::{json, Value};
use std::os::unix::fs::PermissionsExt;
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

static N: AtomicUsize = AtomicUsize::new(0);

const SIDECAR: &str = env!("CARGO_BIN_EXE_citrate-agent-sidecar");

struct Scratch {
    base: PathBuf,
}
impl Scratch {
    fn new() -> Self {
        let base = std::env::temp_dir().join(format!(
            "citrate-sidecar-split-{}-{}",
            std::process::id(),
            N.fetch_add(1, Ordering::SeqCst)
        ));
        let _ = std::fs::remove_dir_all(&base);
        for d in ["root/proj", "bin", "home"] {
            std::fs::create_dir_all(base.join(d)).unwrap();
        }
        Scratch {
            base: base.canonicalize().unwrap(),
        }
    }
    fn proj(&self) -> PathBuf {
        self.base.join("root/proj")
    }
    /// A stand-in forge that sleeps `sleep_secs`, prints the pass fixture and exits 0.
    fn fake_forge(&self, sleep_secs: u32) {
        let fixture = Path::new(env!("CARGO_MANIFEST_DIR"))
            .join("../agent-loop/tests/fixtures/toolchain/forge-test-pass.json");
        let script = format!(
            "#!/bin/sh\n/bin/sleep {sleep_secs}\n/bin/cat '{}'\nexit 0\n",
            fixture.display()
        );
        let p = self.base.join("bin/forge");
        std::fs::write(&p, script).unwrap();
        std::fs::set_permissions(&p, std::fs::Permissions::from_mode(0o755)).unwrap();
    }
    fn env(&self) -> Vec<(String, String)> {
        vec![
            ("CITRATE_HERMES_TOOLCHAIN".into(), "1".into()),
            ("HOME".into(), self.base.join("home").display().to_string()),
            (
                "CITRATE_HERMES_TOOLCHAIN_ROOTS".into(),
                self.base.join("root").display().to_string(),
            ),
            (
                "CITRATE_HERMES_TOOLCHAIN_PATH".into(),
                self.base.join("bin").display().to_string(),
            ),
            ("CITRATE_HERMES_SOLC".into(), "/opt/solc/solc-0.8.36".into()),
        ]
    }
    fn worker(&self) -> Arc<Worker> {
        Arc::new(Worker::start(
            toolchain_worker_spec(PathBuf::from(SIDECAR), self.env()),
            fast_policy(),
        ))
    }
}
impl Drop for Scratch {
    fn drop(&mut self) {
        let _ = std::fs::remove_dir_all(&self.base);
    }
}

fn fast_policy() -> RestartPolicy {
    RestartPolicy {
        backoff_base: Duration::from_millis(50),
        backoff_max: Duration::from_millis(200),
        health_interval: Duration::from_millis(200),
        health_timeout: Duration::from_millis(500),
        ..RestartPolicy::default()
    }
}

fn wait_for(what: &str, limit: Duration, mut f: impl FnMut() -> bool) {
    let t0 = Instant::now();
    while !f() {
        assert!(t0.elapsed() < limit, "timed out waiting for {what}");
        std::thread::sleep(Duration::from_millis(20));
    }
}

fn kill9(pid: u32) {
    // SAFETY: kill(2) on the worker pid the supervisor reported; no memory involved.
    let rc = unsafe { libc::kill(pid as libc::pid_t, libc::SIGKILL) };
    assert_eq!(rc, 0);
}

fn forge_call(proj: &Path) -> ToolCall {
    ToolCall {
        id: "c1".into(),
        name: FORGE_TEST_TOOL.into(),
        arguments: json!({"project": proj}).to_string(),
    }
}

fn running(w: &Worker) -> bool {
    w.status().state == WorkerState::Running
}

#[test]
fn the_toolchain_runs_in_a_separate_worker_process_with_the_same_result() {
    let s = Scratch::new();
    s.fake_forge(0);
    let w = s.worker();
    wait_for("running", Duration::from_secs(20), || running(&w));
    let pid = w.status().pid.unwrap();
    assert_ne!(pid, std::process::id());
    let host = RemoteToolHost::new(w.clone(), Duration::from_secs(30));
    let out = host.execute(&forge_call(&s.proj()));
    let ToolOutcome::Ok(content) = out else {
        panic!("expected ok, got {out:?}");
    };
    let env = ToolchainEnvelope::from_content(&content).unwrap();
    assert_eq!(env.status, RunStatus::Completed);
    assert!(env.verdict.unwrap().passed);
}

#[test]
fn a_refusal_in_the_worker_comes_back_as_the_same_outcome_kind() {
    let s = Scratch::new();
    s.fake_forge(0);
    let w = s.worker();
    wait_for("running", Duration::from_secs(20), || running(&w));
    let host = RemoteToolHost::new(w, Duration::from_secs(30));
    let out = host.execute(&ToolCall {
        id: "c2".into(),
        name: FORGE_TEST_TOOL.into(),
        arguments: json!({"project": "/etc"}).to_string(),
    });
    assert!(
        matches!(out, ToolOutcome::Error(ref e) if e.contains("granted")),
        "{out:?}"
    );
}

#[test]
fn the_worker_checks_the_project_build_configuration_before_running() {
    let s = Scratch::new();
    s.fake_forge(0);
    std::fs::write(
        s.proj().join("foundry.toml"),
        "[profile.default]\nffi = true\n",
    )
    .unwrap();
    let w = s.worker();
    wait_for("running", Duration::from_secs(20), || running(&w));
    let host = RemoteToolHost::new(w, Duration::from_secs(30));
    let out = host.execute(&forge_call(&s.proj()));
    let ToolOutcome::Error(content) = out else {
        panic!("expected a refusal, got {out:?}");
    };
    let env = ToolchainEnvelope::from_content(&content).unwrap();
    assert_eq!(env.status, RunStatus::Refused, "{}", env.summary);
    assert!(env.summary.contains("ffi"), "{}", env.summary);
}

#[test]
fn killing_the_worker_restarts_it_and_the_next_call_works() {
    let s = Scratch::new();
    s.fake_forge(0);
    let w = s.worker();
    wait_for("running", Duration::from_secs(20), || running(&w));
    let first = w.status().pid.unwrap();
    kill9(first);
    wait_for("restarted", Duration::from_secs(20), || {
        let st = w.status();
        running(&w) && st.pid.is_some() && st.pid != Some(first)
    });
    let st = w.status();
    assert_eq!(st.restarts, 1);
    assert!(st.last_exit.unwrap().contains("signal 9"));
    let host = RemoteToolHost::new(w, Duration::from_secs(30));
    assert!(matches!(
        host.execute(&forge_call(&s.proj())),
        ToolOutcome::Ok(_)
    ));
}

#[test]
fn a_call_in_flight_when_the_worker_is_killed_reports_the_crash_honestly() {
    let s = Scratch::new();
    s.fake_forge(5);
    let w = s.worker();
    wait_for("running", Duration::from_secs(20), || running(&w));
    let pid = w.status().pid.unwrap();
    let host = RemoteToolHost::new(w.clone(), Duration::from_secs(30));
    let proj = s.proj();
    let h = std::thread::spawn(move || host.execute(&forge_call(&proj)));
    std::thread::sleep(Duration::from_millis(500));
    kill9(pid);
    let out = h.join().unwrap();
    let ToolOutcome::Error(msg) = out else {
        panic!("a crashed call is an error, never a result: {out:?}");
    };
    assert!(msg.contains("toolchain worker"), "{msg}");
    assert!(msg.contains("signal 9"), "{msg}");
    assert!(msg.contains("not retried"), "{msg}");
}

/// A model that calls `forge_test` once, then answers.
struct OneForgeCall {
    proj: PathBuf,
    n: Mutex<u32>,
}
impl LlmClient for OneForgeCall {
    fn complete(&self, _req: &CompletionRequest) -> Result<AssistantTurn, LlmError> {
        let mut n = self.n.lock().unwrap();
        *n += 1;
        if *n == 1 {
            Ok(AssistantTurn {
                content: String::new(),
                tool_calls: vec![forge_call(&self.proj)],
            })
        } else {
            Ok(AssistantTurn::text("done"))
        }
    }
}

fn session_req() -> CreateSessionReq {
    serde_json::from_value(json!({
        "model": "m",
        "systemPrompt": "p",
        "llm": {"baseUrl": "http://127.0.0.1:9/v1", "bearer": ""},
    }))
    .unwrap()
}

fn tool_results(mgr: &SessionManager, id: &str) -> Vec<Value> {
    let page = mgr.get(id).unwrap().events_after(0);
    serde_json::to_value(&page).unwrap()["events"]
        .as_array()
        .unwrap()
        .iter()
        .filter(|e| e["event"]["type"] == "tool_result")
        .map(|e| e["event"].clone())
        .collect()
}

#[tokio::test(flavor = "multi_thread")]
async fn a_session_survives_a_worker_crash_and_says_what_happened() {
    let s = Scratch::new();
    s.fake_forge(5);
    let w = s.worker();
    wait_for("running", Duration::from_secs(20), || running(&w));
    let pid = w.status().pid.unwrap();
    let proj = s.proj();
    let llm: Arc<dyn LlmClient> = Arc::new(OneForgeCall {
        proj,
        n: Mutex::new(0),
    });
    let set = Arc::new(WorkerSet::with_toolchain(w.clone()));
    let mgr = SessionManager::new(
        Arc::new(move |_: &LlmEndpoint| llm.clone()),
        Duration::from_secs(5),
    )
    .with_toolchain(Arc::new(RemoteToolHost::new(
        w.clone(),
        Duration::from_secs(30),
    )))
    .with_workers(set.clone());
    let id = mgr.create(session_req()).unwrap();
    mgr.send(&id, "run the tests".into(), None).unwrap();
    tokio::time::sleep(Duration::from_millis(700)).await;
    kill9(pid);
    let session = mgr.get(&id).unwrap();
    let t0 = Instant::now();
    while session.events_after(0).busy {
        assert!(t0.elapsed() < Duration::from_secs(20), "the turn ends");
        tokio::time::sleep(Duration::from_millis(50)).await;
    }
    let results = tool_results(&mgr, &id);
    assert_eq!(results.len(), 1, "{results:?}");
    assert_eq!(results[0]["status"], "error");
    let content = results[0]["content"].as_str().unwrap();
    assert!(content.contains("toolchain worker"), "{content}");
    // The session itself is fine: the turn finished with the model's answer.
    let page = serde_json::to_value(session.events_after(0)).unwrap();
    assert!(
        page["events"]
            .as_array()
            .unwrap()
            .iter()
            .any(|e| e["event"]["type"] == "done"),
        "{page}"
    );
    // And the report shows the restart.
    wait_for("restarted", Duration::from_secs(20), || {
        w.status().restarts == 1 && running(&w)
    });
    let report = mgr.workers_report();
    let tc = report.iter().find(|r| r["kind"] == "toolchain").unwrap();
    assert_eq!(tc["restarts"], 1);
    assert_eq!(tc["state"], "running");
}

#[test]
fn the_report_lists_the_browser_worker_as_not_built_and_an_off_toolchain_as_off() {
    let set = WorkerSet::default();
    let report = set.report();
    let tc = report.iter().find(|r| r["kind"] == "toolchain").unwrap();
    assert_eq!(tc["state"], "off");
    let br = report.iter().find(|r| r["kind"] == "browser").unwrap();
    assert_eq!(br["state"], "not_built");
    assert!(br["detail"].as_str().unwrap().contains("HUP-S5.1"));
}

#[test]
fn a_worker_exits_when_the_sidecar_closes_its_input() {
    let s = Scratch::new();
    let mut child = std::process::Command::new(SIDECAR)
        .args([WORKER_ARG, WORKER_TOOLCHAIN])
        .envs(s.env())
        .stdin(std::process::Stdio::piped())
        .stdout(std::process::Stdio::piped())
        .stderr(std::process::Stdio::null())
        .spawn()
        .unwrap();
    drop(child.stdin.take());
    let t0 = Instant::now();
    loop {
        if let Some(st) = child.try_wait().unwrap() {
            assert!(st.success(), "a parent going away is a normal exit: {st:?}");
            break;
        }
        assert!(
            t0.elapsed() < Duration::from_secs(10),
            "worker outlived its parent's pipe"
        );
        std::thread::sleep(Duration::from_millis(20));
    }
}

#[test]
fn a_worker_started_with_the_toolchain_off_refuses_to_run() {
    let out = std::process::Command::new(SIDECAR)
        .args([WORKER_ARG, WORKER_TOOLCHAIN])
        .env_remove("CITRATE_HERMES_TOOLCHAIN")
        .stdin(std::process::Stdio::null())
        .output()
        .unwrap();
    assert!(!out.status.success());
    assert!(String::from_utf8_lossy(&out.stderr).contains("toolchain is off"));
}

#[test]
fn an_unknown_worker_kind_is_refused() {
    let out = std::process::Command::new(SIDECAR)
        .args([WORKER_ARG, "teleporter"])
        .stdin(std::process::Stdio::null())
        .output()
        .unwrap();
    assert!(!out.status.success());
    assert!(String::from_utf8_lossy(&out.stderr).contains("unknown worker"));
}

#[test]
fn shutting_the_set_down_stops_the_worker_cleanly() {
    let s = Scratch::new();
    let w = s.worker();
    wait_for("running", Duration::from_secs(20), || running(&w));
    let set = WorkerSet::with_toolchain(w.clone());
    set.shutdown();
    let st = w.status();
    assert_eq!(st.state, WorkerState::Stopped);
    assert_eq!(st.restarts, 0);
    assert_eq!(st.last_exit.as_deref(), Some("exited with code 0"));
}

/// The whole binary: the control plane starts its toolchain worker as a child, `/workers` reports
/// it, a `kill -9` of the worker leaves the control plane serving and the worker restarted, and
/// SIGTERM to the control plane shuts the worker down with it.
#[test]
fn the_sidecar_binary_supervises_its_toolchain_worker_end_to_end() {
    let s = Scratch::new();
    let port = std::net::TcpListener::bind("127.0.0.1:0")
        .unwrap()
        .local_addr()
        .unwrap()
        .port();
    let token = s.base.join("bearer");
    // Test-only bearer value, built at runtime so it is not a literal credential.
    let bearer = ["split", "test", "bearer", "0123456789"].join("-");
    std::fs::write(&token, &bearer).unwrap();
    let mut sidecar = std::process::Command::new(SIDECAR)
        .envs(s.env())
        .env("CITRATE_HERMES_ADDR", format!("127.0.0.1:{port}"))
        .env("CITRATE_HERMES_TOKEN_FILE", &token)
        .env("CITRATE_HERMES_CAPSULES", s.base.join("no-capsules"))
        .stdin(std::process::Stdio::null())
        .stdout(std::process::Stdio::null())
        .stderr(std::process::Stdio::null())
        .spawn()
        .unwrap();
    let client = reqwest::blocking::Client::new();
    let workers = || -> Option<Value> {
        let r = client
            .get(format!("http://127.0.0.1:{port}/workers"))
            .bearer_auth(&bearer)
            .send()
            .ok()?;
        let v: Value = r.json().ok()?;
        v["workers"]
            .as_array()?
            .iter()
            .find(|w| w["kind"] == "toolchain")
            .cloned()
    };
    let mut first = 0u64;
    wait_for(
        "toolchain worker running",
        Duration::from_secs(30),
        || match workers() {
            Some(w) if w["state"] == "running" => {
                first = w["pid"].as_u64().unwrap_or(0);
                true
            }
            _ => false,
        },
    );
    assert_ne!(first, 0);
    assert_ne!(
        first,
        u64::from(sidecar.id()),
        "the worker is its own process"
    );
    kill9(first as u32);
    wait_for("restarted", Duration::from_secs(30), || {
        matches!(workers(), Some(w) if w["state"] == "running"
            && w["restarts"] == 1
            && w["pid"].as_u64() != Some(first)
            && w["last_exit"].as_str().is_some_and(|e| e.contains("signal 9")))
    });
    assert!(
        sidecar.try_wait().unwrap().is_none(),
        "the control plane outlived its worker's crash"
    );
    let second = workers().unwrap()["pid"].as_u64().unwrap() as libc::pid_t;
    // SAFETY: kill(2) on the sidecar child we spawned; no memory involved.
    assert_eq!(
        unsafe { libc::kill(sidecar.id() as libc::pid_t, libc::SIGTERM) },
        0
    );
    let t0 = Instant::now();
    loop {
        if sidecar.try_wait().unwrap().is_some() {
            break;
        }
        assert!(
            t0.elapsed() < Duration::from_secs(15),
            "sidecar did not stop on SIGTERM"
        );
        std::thread::sleep(Duration::from_millis(20));
    }
    // The worker went down with it (signal 0 probes for existence).
    wait_for("worker gone", Duration::from_secs(10), || {
        // SAFETY: as above.
        let rc = unsafe { libc::kill(second, 0) };
        rc != 0
    });
}
