//! HUP-S1.9 — the sidecar's worker processes.
//!
//! The agent loop stays in the sidecar process (citrate-core supervises and restarts that). The
//! tools that run other programs move out of it, each into a child process of the sidecar
//! supervised by `citrate-agent-workers` (restart policy, health checks, clean shutdown):
//!
//! - **toolchain**: `forge_test`, `slither_scan`, `aderyn_scan`, `medusa_fuzz` (HUP-S6.3). The
//!   worker is this same binary started as `citrate-agent-sidecar --worker toolchain`; it builds
//!   its [`ToolchainHost`] from the same `CITRATE_HERMES_TOOLCHAIN*` environment it inherits and
//!   serves calls over stdio. Sessions reach it through [`RemoteToolHost`].
//! - **browser**: reserved. The browser tools (HUP-S5.1) run in the sidecar process and drive the
//!   managed Chromium, which is its own process; a separate browser worker is not built, so the
//!   report says `not_built` and no worker is started.
//!
//! A worker crash fails only the calls that were in flight in that worker. Each such call
//! returns a tool error that says the worker ended, how, that it is being restarted, and that the
//! run was not retried, so the model and the member see what happened instead of a silent gap.
//! Nothing here holds a key or signs (Rule 3).

use std::path::PathBuf;
use std::sync::Arc;
use std::time::Duration;

use citrate_agent_loop::{ToolCall, ToolHost, ToolOutcome};
use citrate_agent_workers::protocol::{serve, Handler, ServeEnd};
use citrate_agent_workers::{RestartPolicy, Worker, WorkerError, WorkerKind, WorkerSpec};
use serde::{Deserialize, Serialize};
use serde_json::Value;

use crate::grants::SessionGrants;
use crate::toolchain::{ToolchainConfig, ToolchainHost};

/// The argument that starts the binary as a worker instead of the control plane.
pub const WORKER_ARG: &str = "--worker";
/// `--worker toolchain`.
pub const WORKER_TOOLCHAIN: &str = "toolchain";

/// What a toolchain call may take in the worker: the longest run the toolchain allows (its
/// wall-clock cap plus medusa's summary grace) and a minute of margin for start-up and transfer.
pub const TOOLCHAIN_CALL_TIMEOUT: Duration =
    Duration::from_secs(crate::toolchain::LONGEST_RUN_SECS + 60);

/// A [`ToolOutcome`] on the wire between the sidecar and a worker.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "status", content = "content", rename_all = "lowercase")]
pub enum WireOutcome {
    Ok(String),
    Untrusted(String),
    Denied(String),
    Error(String),
}

impl From<ToolOutcome> for WireOutcome {
    fn from(o: ToolOutcome) -> Self {
        match o {
            ToolOutcome::Ok(s) => WireOutcome::Ok(s),
            ToolOutcome::Untrusted(s) => WireOutcome::Untrusted(s),
            ToolOutcome::Denied(s) => WireOutcome::Denied(s),
            ToolOutcome::Error(s) => WireOutcome::Error(s),
        }
    }
}

impl From<WireOutcome> for ToolOutcome {
    fn from(o: WireOutcome) -> Self {
        match o {
            WireOutcome::Ok(s) => ToolOutcome::Ok(s),
            WireOutcome::Untrusted(s) => ToolOutcome::Untrusted(s),
            WireOutcome::Denied(s) => ToolOutcome::Denied(s),
            WireOutcome::Error(s) => ToolOutcome::Error(s),
        }
    }
}

/// The spec for a toolchain worker: `program --worker toolchain`, with `env` added to the
/// inherited environment (production passes none).
pub fn toolchain_worker_spec(program: PathBuf, env: Vec<(String, String)>) -> WorkerSpec {
    WorkerSpec {
        kind: WorkerKind::Toolchain,
        program,
        args: vec![WORKER_ARG.to_string(), WORKER_TOOLCHAIN.to_string()],
        env,
        // The worker needs none of the control plane's own settings.
        env_remove: [
            "CITRATE_HERMES_TOKEN_FILE",
            "CITRATE_HERMES_ADDR",
            "CITRATE_HERMES_ALLOW_NONLOOPBACK",
        ]
        .iter()
        .map(|s| s.to_string())
        .collect(),
    }
}

/// The sidecar-side host for tools that run in a worker process.
pub struct RemoteToolHost {
    worker: Arc<Worker>,
    call_timeout: Duration,
}

impl RemoteToolHost {
    pub fn new(worker: Arc<Worker>, call_timeout: Duration) -> Self {
        RemoteToolHost {
            worker,
            call_timeout,
        }
    }
}

impl RemoteToolHost {
    /// Send one call to the worker and map every failure to an honest tool error.
    fn send(&self, params: Value) -> ToolOutcome {
        let kind = self.worker.kind().as_str();
        match self.worker.call(params, self.call_timeout) {
            Ok(v) => match serde_json::from_value::<WireOutcome>(v) {
                Ok(o) => o.into(),
                Err(e) => ToolOutcome::Error(format!(
                    "the {kind} worker sent an answer the sidecar could not read ({e})"
                )),
            },
            Err(WorkerError::Crashed(why)) => ToolOutcome::Error(format!(
                "the {kind} worker process ended during this call ({why}). The sidecar is \
                 restarting it. The result of this run is unknown and it was not retried."
            )),
            Err(WorkerError::NotRunning(why)) => ToolOutcome::Error(format!(
                "the {kind} worker is not available ({why}). Nothing was run."
            )),
            Err(WorkerError::Timeout) => ToolOutcome::Error(format!(
                "the {kind} worker did not answer within {}s. The run may still be finishing \
                 in the worker; it was not retried.",
                self.call_timeout.as_secs()
            )),
            Err(WorkerError::Remote(e)) => {
                ToolOutcome::Error(format!("the {kind} worker could not run the call: {e}"))
            }
        }
    }
}

impl ToolHost for RemoteToolHost {
    fn execute(&self, call: &ToolCall) -> ToolOutcome {
        match serde_json::to_value(call) {
            Ok(v) => self.send(serde_json::json!({ "call": v })),
            Err(e) => ToolOutcome::Error(format!("could not encode the call: {e}")),
        }
    }
}

impl crate::sessions::ToolchainBackend for RemoteToolHost {
    fn scoped_to(&self, grants: Arc<SessionGrants>) -> Result<Arc<dyn ToolHost>, String> {
        Ok(Arc::new(GrantScopedRemote {
            remote: RemoteToolHost::new(self.worker.clone(), self.call_timeout),
            grants,
        }))
    }
}

/// HUP-S2.1 in the worker process: a session opened with folder grants sends its grant set as it
/// is at the moment of each call (so a revocation applies to the next call), and the worker
/// checks the project against it instead of `CITRATE_HERMES_TOOLCHAIN_ROOTS`.
struct GrantScopedRemote {
    remote: RemoteToolHost,
    grants: Arc<SessionGrants>,
}

impl ToolHost for GrantScopedRemote {
    fn execute(&self, call: &ToolCall) -> ToolOutcome {
        match serde_json::to_value(call) {
            Ok(v) => self.remote.send(serde_json::json!({
                "call": v,
                "grants": {
                    "home": self.grants.home(),
                    "document": self.grants.document(),
                },
            })),
            Err(e) => ToolOutcome::Error(format!("could not encode the call: {e}")),
        }
    }
}

/// The sidecar's workers, for the `/workers` report and shutdown.
#[derive(Default)]
pub struct WorkerSet {
    toolchain: Option<Arc<Worker>>,
}

impl WorkerSet {
    pub fn with_toolchain(worker: Arc<Worker>) -> Self {
        WorkerSet {
            toolchain: Some(worker),
        }
    }

    /// One entry per worker kind, always both kinds, so a client never has to guess what an
    /// absent entry means.
    pub fn report(&self) -> Vec<Value> {
        let toolchain = match &self.toolchain {
            Some(w) => serde_json::to_value(w.status()).unwrap_or_else(|e| {
                serde_json::json!({"kind": "toolchain", "state": "unknown", "detail": e.to_string()})
            }),
            None => serde_json::json!({
                "kind": "toolchain",
                "state": "off",
                "detail": "the toolchain tools are off (CITRATE_HERMES_TOOLCHAIN is not 1)",
            }),
        };
        let browser = serde_json::json!({
            "kind": "browser",
            "state": "not_built",
            "detail": "the browser tools (HUP-S5.1) run in the sidecar and drive the managed Chromium as its own process; a separate browser worker is not built",
        });
        vec![toolchain, browser]
    }

    /// Stop every worker cleanly (each gets its shutdown request and grace period).
    pub fn shutdown(&self) {
        if let Some(w) = &self.toolchain {
            w.shutdown();
        }
    }
}

/// Start the toolchain worker when the toolchain is on (`None` otherwise). The parent reads the
/// same environment first so a misconfiguration is logged once, here, and no worker is started
/// for tools that are off.
pub fn toolchain_worker_from_env(program: PathBuf) -> Option<Arc<Worker>> {
    let cfg = ToolchainConfig::from_env()?;
    eprintln!(
        "citrate-agent-sidecar: toolchain tools on (worker process): {} granted folder(s), solc {}",
        cfg.roots.len(),
        if cfg.solc.is_some() {
            "configured"
        } else {
            "not found (builds will fail offline)"
        }
    );
    Some(Arc::new(Worker::start(
        toolchain_worker_spec(program, Vec::new()),
        RestartPolicy::default(),
    )))
}

struct ToolchainHandler(ToolchainHost);

#[derive(Deserialize)]
struct CallParams {
    call: ToolCall,
    /// HUP-S2.1: present when the session was opened with folder grants.
    #[serde(default)]
    grants: Option<CallGrants>,
}

#[derive(Deserialize)]
struct CallGrants {
    home: PathBuf,
    document: Value,
}

impl Handler for ToolchainHandler {
    fn call(&self, params: Value) -> Result<Value, String> {
        let p: CallParams =
            serde_json::from_value(params).map_err(|e| format!("bad call parameters: {e}"))?;
        if !ToolchainHost::handles(&p.call.name) {
            return Err(format!(
                "'{}' is not a toolchain tool",
                p.call.name.chars().take(64).collect::<String>()
            ));
        }
        let out: WireOutcome = match p.grants {
            None => self.0.execute(&p.call).into(),
            Some(g) => {
                if !g.home.is_absolute() {
                    return Err("the grants home must be an absolute path".into());
                }
                let set = SessionGrants::empty(&g.home);
                set.replace(&g.document)
                    .map_err(|e| format!("the session's grant set was refused: {e}"))?;
                self.0.for_grants(Arc::new(set))?.execute(&p.call).into()
            }
        };
        serde_json::to_value(out).map_err(|e| format!("could not encode the outcome: {e}"))
    }
}

/// Run as a worker (`--worker <kind>`): serve stdio until shutdown or until the sidecar closes
/// the pipe. Returns the process exit code.
pub fn run_worker(kind: &str) -> i32 {
    match kind {
        WORKER_TOOLCHAIN => {
            let Some(cfg) = ToolchainConfig::from_env() else {
                eprintln!("citrate-agent-sidecar worker: the toolchain is off; not starting");
                return 2;
            };
            let host = match ToolchainHost::new(cfg) {
                Ok(h) => h,
                Err(e) => {
                    eprintln!("citrate-agent-sidecar worker: toolchain unavailable: {e}");
                    return 2;
                }
            };
            let stdin = std::io::stdin();
            match serve(
                stdin.lock(),
                std::io::stdout(),
                Arc::new(ToolchainHandler(host)),
            ) {
                ServeEnd::Shutdown | ServeEnd::Eof => 0,
            }
        }
        other => {
            eprintln!(
                "citrate-agent-sidecar: unknown worker '{}'",
                other.chars().take(32).collect::<String>()
            );
            2
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn wire_outcome_round_trips_every_kind() {
        for o in [
            ToolOutcome::Ok("a".into()),
            ToolOutcome::Untrusted("b".into()),
            ToolOutcome::Denied("c".into()),
            ToolOutcome::Error("d".into()),
        ] {
            let w: WireOutcome = o.clone().into();
            let v = serde_json::to_value(&w).unwrap();
            let back: ToolOutcome = serde_json::from_value::<WireOutcome>(v).unwrap().into();
            assert_eq!(format!("{back:?}"), format!("{o:?}"));
        }
        assert_eq!(
            serde_json::to_value(WireOutcome::Untrusted("x".into())).unwrap(),
            serde_json::json!({"status": "untrusted", "content": "x"})
        );
    }

    #[test]
    fn the_handler_refuses_a_non_toolchain_tool() {
        let cfg = ToolchainConfig {
            roots: vec![],
            search_path: vec![PathBuf::from("/usr/bin")],
            solc: None,
            home: std::env::temp_dir(),
            sandbox: citrate_agent_shell::sandbox::SandboxMode::Off,
        };
        let h = ToolchainHandler(ToolchainHost::new(cfg).unwrap());
        let err = h
            .call(
                serde_json::json!({"call": {"id": "1", "name": "wallet_send", "arguments": "{}"}}),
            )
            .unwrap_err();
        assert!(err.contains("not a toolchain tool"), "{err}");
        assert!(h.call(serde_json::json!({"nope": 1})).is_err());
    }

    #[test]
    fn the_call_timeout_outlasts_the_longest_toolchain_run() {
        assert!(TOOLCHAIN_CALL_TIMEOUT.as_secs() > crate::toolchain::LONGEST_RUN_SECS);
    }

    #[test]
    fn the_worker_spec_starts_the_toolchain_worker_mode() {
        let s = toolchain_worker_spec(PathBuf::from("/x/sidecar"), vec![]);
        assert_eq!(s.kind, WorkerKind::Toolchain);
        assert_eq!(s.args, vec!["--worker", "toolchain"]);
        assert!(s
            .env_remove
            .iter()
            .any(|k| k == "CITRATE_HERMES_TOKEN_FILE"));
    }
}
