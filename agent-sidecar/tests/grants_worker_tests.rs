//! HUP-S2.1 x HUP-S1.9 (stack integration): a session opened with folder grants keeps the S2.1
//! toolchain rule when the toolchain runs in its worker process. The session's grant set travels
//! with every call, the worker checks the project against it (live read and write folder grants)
//! instead of `CITRATE_HERMES_TOOLCHAIN_ROOTS`, and a replaced set applies to the next call.
//!
//! The worker is the real `citrate-agent-sidecar --worker toolchain` binary; forge is a `/bin/sh`
//! stand-in on a private search path, so this runs in CI without forge.
#![cfg(unix)]

use agent_sidecar::grants::SessionGrants;
use agent_sidecar::sessions::ToolchainBackend;
use agent_sidecar::workers::{toolchain_worker_spec, RemoteToolHost};
use citrate_agent_grants::{Access, FolderGrants, GrantRequest};
use citrate_agent_loop::verifiers_tooling::{RunStatus, ToolchainEnvelope, FORGE_TEST_TOOL};
use citrate_agent_loop::{ToolCall, ToolOutcome};
use citrate_agent_workers::{RestartPolicy, Worker, WorkerState};
use serde_json::json;
use std::os::unix::fs::PermissionsExt;
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::Arc;
use std::time::{Duration, Instant};

static N: AtomicUsize = AtomicUsize::new(0);

const SIDECAR: &str = env!("CARGO_BIN_EXE_citrate-agent-sidecar");
const MEMBER: &str = "0x00000000000000000000000000000000000000aa";

/// `base/home` (the member's home), `base/home/gproj` (a project only grants can reach),
/// `base/root/proj` (a project the worker's env roots cover), `base/bin` (the search path).
struct Fx {
    base: PathBuf,
}

impl Fx {
    fn new() -> Self {
        let base = std::env::temp_dir().join(format!(
            "citrate-sidecar-grants-worker-{}-{}",
            std::process::id(),
            N.fetch_add(1, Ordering::SeqCst)
        ));
        let _ = std::fs::remove_dir_all(&base);
        for d in ["home/gproj", "root/proj", "bin"] {
            std::fs::create_dir_all(base.join(d)).unwrap();
        }
        let base = base.canonicalize().unwrap();
        let fixture = Path::new(env!("CARGO_MANIFEST_DIR"))
            .join("../agent-loop/tests/fixtures/toolchain/forge-test-pass.json");
        let forge = base.join("bin/forge");
        std::fs::write(
            &forge,
            format!(
                "#!/bin/sh\n/bin/pwd > '{}'\n/bin/cat '{}'\nexit 0\n",
                base.join("forge.cwd").display(),
                fixture.display()
            ),
        )
        .unwrap();
        std::fs::set_permissions(&forge, std::fs::Permissions::from_mode(0o755)).unwrap();
        Fx { base }
    }
    fn home(&self) -> PathBuf {
        self.base.join("home")
    }
    fn gproj(&self) -> PathBuf {
        self.base.join("home/gproj")
    }
    fn env_proj(&self) -> PathBuf {
        self.base.join("root/proj")
    }
    fn worker(&self) -> Arc<Worker> {
        let env = vec![
            ("CITRATE_HERMES_TOOLCHAIN".into(), "1".into()),
            ("HOME".into(), self.home().display().to_string()),
            (
                "CITRATE_HERMES_TOOLCHAIN_ROOTS".into(),
                self.base.join("root").display().to_string(),
            ),
            (
                "CITRATE_HERMES_TOOLCHAIN_PATH".into(),
                self.base.join("bin").display().to_string(),
            ),
            ("CITRATE_HERMES_SOLC".into(), "/opt/solc/solc-0.8.36".into()),
        ];
        let w = Arc::new(Worker::start(
            toolchain_worker_spec(PathBuf::from(SIDECAR), env),
            RestartPolicy {
                backoff_base: Duration::from_millis(50),
                backoff_max: Duration::from_millis(200),
                ..RestartPolicy::default()
            },
        ));
        let t0 = Instant::now();
        while w.status().state != WorkerState::Running {
            assert!(t0.elapsed() < Duration::from_secs(20), "worker starts");
            std::thread::sleep(Duration::from_millis(20));
        }
        w
    }
    fn grants(&self, f: impl FnOnce(&mut FolderGrants, u64)) -> Arc<SessionGrants> {
        let mut g = FolderGrants::new(self.home(), self.home());
        f(&mut g, now());
        let set = SessionGrants::empty(self.home());
        set.replace(&serde_json::to_value(g.state()).unwrap())
            .unwrap();
        Arc::new(set)
    }
}

impl Drop for Fx {
    fn drop(&mut self) {
        let _ = std::fs::remove_dir_all(&self.base);
    }
}

fn now() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap()
        .as_secs()
}

fn folder(root: &Path, access: Access) -> GrantRequest {
    GrantRequest::folder(root, access, MEMBER, "work on the project")
}

fn forge(proj: &Path) -> ToolCall {
    ToolCall {
        id: "c1".into(),
        name: FORGE_TEST_TOOL.into(),
        arguments: json!({ "project": proj }).to_string(),
    }
}

/// The run status, or `None` when the call did not produce a toolchain envelope.
fn status(out: &ToolOutcome) -> Option<RunStatus> {
    let content = match out {
        ToolOutcome::Ok(c) | ToolOutcome::Error(c) => c,
        _ => return None,
    };
    ToolchainEnvelope::from_content(content)
        .ok()
        .map(|e| e.status)
}

fn ran(out: &ToolOutcome) -> bool {
    status(out) == Some(RunStatus::Completed)
}

#[test]
fn with_grants_the_worker_runs_a_project_its_env_roots_do_not_cover() {
    let fx = Fx::new();
    let remote = RemoteToolHost::new(fx.worker(), Duration::from_secs(30));
    // Without grants the env roots apply, and they do not cover gproj.
    let out = citrate_agent_loop::ToolHost::execute(&remote, &forge(&fx.gproj()));
    assert!(!ran(&out), "env roots must refuse gproj: {out:?}");

    let g = fx.grants(|g, t| {
        g.grant(folder(&fx.gproj(), Access::Read), t).unwrap();
        g.grant(folder(&fx.gproj(), Access::Write), t).unwrap();
    });
    let scoped = remote.scoped_to(g).unwrap();
    let out = scoped.execute(&forge(&fx.gproj()));
    assert!(
        ran(&out),
        "read and write folder grants run the project: {out:?}"
    );
    let cwd = std::fs::read_to_string(fx.base.join("forge.cwd")).unwrap();
    assert_eq!(cwd.trim(), fx.gproj().display().to_string());
}

#[test]
fn with_grants_the_env_roots_no_longer_apply_in_the_worker() {
    let fx = Fx::new();
    let remote = RemoteToolHost::new(fx.worker(), Duration::from_secs(30));
    assert!(ran(&citrate_agent_loop::ToolHost::execute(
        &remote,
        &forge(&fx.env_proj())
    )));
    // A session whose grants cover nothing may not use the worker's env roots.
    let none = fx.grants(|_, _| {});
    let out = none.clone();
    let scoped = remote.scoped_to(out).unwrap();
    assert!(!ran(&scoped.execute(&forge(&fx.env_proj()))));
    // A read-only grant is not enough either.
    let read_only = fx.grants(|g, t| {
        g.grant(folder(&fx.gproj(), Access::Read), t).unwrap();
    });
    let scoped = remote.scoped_to(read_only).unwrap();
    assert!(!ran(&scoped.execute(&forge(&fx.gproj()))));
}

#[test]
fn a_replaced_grant_set_applies_to_the_next_worker_call() {
    let fx = Fx::new();
    let remote = RemoteToolHost::new(fx.worker(), Duration::from_secs(30));
    let g = fx.grants(|g, t| {
        g.grant(folder(&fx.gproj(), Access::Read), t).unwrap();
        g.grant(folder(&fx.gproj(), Access::Write), t).unwrap();
    });
    let scoped = remote.scoped_to(g.clone()).unwrap();
    assert!(ran(&scoped.execute(&forge(&fx.gproj()))));
    let empty = serde_json::to_value(FolderGrants::new(fx.home(), fx.home()).state()).unwrap();
    g.replace(&empty).unwrap();
    assert!(!ran(&scoped.execute(&forge(&fx.gproj()))));
}
