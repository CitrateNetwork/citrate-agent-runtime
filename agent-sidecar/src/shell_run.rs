//! US-2.2 AC2 — `shell_run`: a general command, run only after the member approves exactly it.
//!
//! The four toolchain tools ([`crate::toolchain`]) are fixed argv templates. Anything else the
//! agent wants to run goes through this tool, which is **off by default**
//! (`CITRATE_HERMES_SHELL_RUN=1` turns it on, pending owner sign-off) and offered only to a
//! session opened with the member's folder grants.
//!
//! One call:
//!
//! 1. **Refused in a tainted session.** Once a session has read untrusted content it never runs a
//!    command (the loop declines the call; this host checks again).
//! 2. **Validated before anything is asked.** The model gives `argv` (program first, as a bare
//!    name resolved from a fixed search path, never a path; argv only, no shell expansion) and an
//!    absolute `cwd`. The cwd must be covered by live read and write folder grants that reach
//!    their whole subtree ([`crate::grants::SessionGrants::shell_scope`]); that grant's folder is
//!    the only one the command may write. The OS sandbox is **required**: with no working backend
//!    the call is refused and nothing is asked.
//! 3. **HIC required, always.** The call parks as a [`ShellPending`] (the exact argv, the program
//!    it resolves to, the canonical cwd, the timeout, the sandbox) that citrate-core shows as an
//!    approval card (`GET /sessions/:id/shell/pending`). The member's decision
//!    (`POST /sessions/:id/shell/decide`) must carry the argv and cwd that were shown; anything
//!    else is refused. No decision within [`APPROVAL_TIMEOUT`], or a session stop, declines it.
//! 4. **Runs in the OS sandbox**, after the grant check is repeated: no network, writes only in
//!    the grant's folder and a scratch HOME, a wall-clock timeout that kills the process group,
//!    and stdout/stderr captured up to [`OUTPUT_CAP`] bytes each.
//! 5. **Reports** a toolchain envelope (`tool: "shell_run"`) with the run facts, the captured
//!    output and the sandbox; citrate-core adds it to the Activity monitor. The output is
//!    untrusted, so it taints the session (and the next `shell_run` is then refused).
//!
//! Keyless: nothing here holds a key or signs (Rule 3).

use std::path::{Path, PathBuf};
use std::sync::{Arc, Condvar, Mutex};
use std::time::{Duration, Instant};

use serde::Serialize;

use crate::grants::SessionGrants;
use citrate_agent_loop::verifiers_tooling::{RunStatus, ToolchainEnvelope};
use citrate_agent_loop::{
    Effect, HostKind, StopFlag, TaintState, ToolAnnotations, ToolCall, ToolHost, ToolOutcome,
    ToolSpec, Trust,
};
use citrate_agent_shell::sandbox::{SandboxMode, SandboxPolicy, SandboxSummary};
use citrate_agent_shell::{
    Allowlist, RunPlan, RunReport, RunRequest, ShellError, ShellPolicy, ShellRunner,
};

pub const SHELL_RUN_TOOL: &str = "shell_run";
/// `1` offers `shell_run` to sessions opened with folder grants; anything else leaves it off.
pub const SHELL_RUN_ENV: &str = "CITRATE_HERMES_SHELL_RUN";
/// The search path programs are resolved from (absolute dirs, a platform path list). Unset = the
/// system dirs plus the per-user Foundry, pipx, cargo and Go bin dirs (as the toolchain).
pub const SHELL_PATH_ENV: &str = "CITRATE_HERMES_SHELL_PATH";
/// How long a command waits for the member's decision.
pub const APPROVAL_TIMEOUT: Duration = Duration::from_secs(300);
/// Wall-clock limits for one command, in seconds.
pub const DEFAULT_TIMEOUT_SECS: u64 = 120;
pub const MAX_TIMEOUT_SECS: u64 = 600;
/// Bytes of stdout and of stderr kept from one command.
pub const OUTPUT_CAP: usize = 32 * 1024;
/// Most argv entries, longest entry, and most argv bytes a call may propose.
pub const MAX_ARGV: usize = 64;
pub const MAX_ARG_BYTES: usize = 4096;
pub const MAX_ARGV_BYTES: usize = 32 * 1024;

/// How `shell_run` runs.
#[derive(Debug, Clone)]
pub struct ShellRunConfig {
    pub search_path: Vec<PathBuf>,
    /// Production is always [`SandboxMode::Required`].
    pub sandbox: SandboxPolicy,
    pub approval_timeout: Duration,
}

impl ShellRunConfig {
    /// `None` unless `CITRATE_HERMES_SHELL_RUN` is exactly `1` and a home directory is known.
    /// The OS sandbox is always required here, whatever `CITRATE_HERMES_SHELL_SANDBOX` says.
    pub fn from_env_vars(get: impl Fn(&str) -> Option<String>) -> Option<Self> {
        if get(SHELL_RUN_ENV).as_deref() != Some("1") {
            return None;
        }
        let home = PathBuf::from(get("HOME").filter(|h| !h.is_empty())?);
        let search_path = match get(SHELL_PATH_ENV).map(|v| {
            std::env::split_paths(&v)
                .filter(|p| p.is_absolute())
                .collect::<Vec<_>>()
        }) {
            Some(p) if !p.is_empty() => p,
            _ => {
                let mut p = ShellPolicy::default_search_path();
                for d in [".foundry/bin", ".local/bin", ".cargo/bin", "go/bin"] {
                    p.push(home.join(d));
                }
                p
            }
        };
        Some(ShellRunConfig {
            search_path,
            sandbox: SandboxPolicy::new(SandboxMode::Required),
            approval_timeout: APPROVAL_TIMEOUT,
        })
    }

    pub fn from_env() -> Option<Self> {
        Self::from_env_vars(|k| std::env::var(k).ok())
    }
}

/// The tool offered to the model.
pub fn shell_run_spec() -> ToolSpec {
    ToolSpec {
        name: SHELL_RUN_TOOL.into(),
        description: "Run one command in a folder the member granted. The member sees the exact command and folder and must approve it before it runs. It runs in an OS sandbox with no network, may write only in that granted folder, and is stopped at its time limit. Use the forge_test, slither_scan, aderyn_scan and medusa_fuzz tools for those programs instead.".into(),
        parameters: serde_json::json!({
            "type": "object",
            "properties": {
                "argv": {
                    "type": "array", "minItems": 1, "maxItems": MAX_ARGV,
                    "items": {"type": "string"},
                    "description": "The program (a bare name such as npm or make, never a path) followed by its arguments, one per entry. No shell runs it, so quotes, $(...), pipes and globs are passed literally."
                },
                "cwd": {
                    "type": "string",
                    "description": "Absolute path of the folder to run in (inside a folder the member granted for reading and writing)."
                },
                "timeout_secs": {
                    "type": "integer", "minimum": 1, "maximum": MAX_TIMEOUT_SECS,
                    "description": format!("Wall-clock limit in seconds (default {DEFAULT_TIMEOUT_SECS}).")
                }
            },
            "required": ["argv", "cwd"],
        }),
        host: HostKind::Sidecar,
        annotations: ToolAnnotations {
            read_only: false,
            destructive: true,
            idempotent: false,
            open_world: false,
            effect: Some(Effect::Write),
            // Any command's output can carry instructions; it taints the session.
            trust: Some(Trust::Untrusted),
        },
    }
}

// ------------------------------------------------------------------------------------------
// Approvals
// ------------------------------------------------------------------------------------------

/// A command waiting for the member's decision: everything the approval card shows.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct ShellPending {
    /// The approval id (`sh-<n>`), which the decision names.
    pub id: String,
    /// The loop's tool call id.
    pub call_id: String,
    pub tool: String,
    /// Always `required`: every command needs the member's explicit decision.
    pub hic: String,
    /// Exactly as proposed, program first.
    pub argv: Vec<String>,
    /// The executable the program name resolves to.
    pub resolved_program: String,
    /// The canonical folder it runs in.
    pub cwd: String,
    pub timeout_secs: u64,
    pub sandbox: SandboxSummary,
    /// Seconds left before it is declined for want of a decision.
    pub expires_in_secs: u64,
}

struct Waiting {
    view: ShellPending,
    deadline: Instant,
    answer: Option<bool>,
}

#[derive(Default)]
struct ApprovalsInner {
    next: u64,
    waiting: Vec<Waiting>,
}

/// One session's commands waiting for the member.
#[derive(Default)]
pub struct ShellApprovals {
    inner: Mutex<ApprovalsInner>,
    cv: Condvar,
}

impl ShellApprovals {
    fn lock(&self) -> std::sync::MutexGuard<'_, ApprovalsInner> {
        self.inner.lock().unwrap_or_else(|p| p.into_inner())
    }

    /// The commands waiting now, oldest first.
    pub fn pending(&self) -> Vec<ShellPending> {
        let now = Instant::now();
        self.lock()
            .waiting
            .iter()
            .filter(|w| w.answer.is_none())
            .map(|w| {
                let mut v = w.view.clone();
                v.expires_in_secs = w.deadline.saturating_duration_since(now).as_secs();
                v
            })
            .collect()
    }

    /// The member's decision on approval `id`. It must carry the argv and cwd that were shown;
    /// otherwise (or when nothing with that id is waiting) it is refused and changes nothing.
    pub fn decide(&self, id: &str, allow: bool, argv: &[String], cwd: &str) -> Result<(), String> {
        let mut g = self.lock();
        let w = g
            .waiting
            .iter_mut()
            .find(|w| w.view.id == id && w.answer.is_none())
            .ok_or_else(|| "that command is no longer waiting for a decision".to_string())?;
        if w.view.argv != argv || w.view.cwd != cwd {
            return Err(
                "the decision does not match the command and folder that are waiting; nothing was decided"
                    .to_string(),
            );
        }
        w.answer = Some(allow);
        drop(g);
        self.cv.notify_all();
        Ok(())
    }

    /// Park `view` until the member decides, it expires, or `stopped()` turns true. `Ok(())`
    /// only for an explicit allow.
    fn request(
        &self,
        mut view: ShellPending,
        timeout: Duration,
        stopped: &dyn Fn() -> bool,
    ) -> Result<(), String> {
        let deadline = Instant::now() + timeout;
        let mut g = self.lock();
        g.next += 1;
        let id = format!("sh-{}", g.next);
        view.id = id.clone();
        view.expires_in_secs = timeout.as_secs();
        g.waiting.push(Waiting {
            view,
            deadline,
            answer: None,
        });
        let outcome = loop {
            let answer = g
                .waiting
                .iter()
                .find(|w| w.view.id == id)
                .and_then(|w| w.answer);
            if let Some(a) = answer {
                break if a {
                    Ok(())
                } else {
                    Err("the member declined this command".to_string())
                };
            }
            if stopped() {
                break Err("the session was stopped before the member decided".to_string());
            }
            let now = Instant::now();
            if now >= deadline {
                break Err(format!(
                    "no decision within {}s, so the command was declined",
                    timeout.as_secs()
                ));
            }
            let wait = (deadline - now).min(Duration::from_millis(100));
            g = match self.cv.wait_timeout(g, wait) {
                Ok((guard, _)) => guard,
                Err(p) => p.into_inner().0,
            };
        };
        g.waiting.retain(|w| w.view.id != id);
        outcome
    }
}

// ------------------------------------------------------------------------------------------
// Per session
// ------------------------------------------------------------------------------------------

/// `shell_run` for one session: a runner scoped to the session's live folder grants, and the
/// session's waiting commands.
pub struct ShellRunSession {
    runner: Arc<ShellRunner>,
    approvals: Arc<ShellApprovals>,
    approval_timeout: Duration,
}

impl ShellRunSession {
    /// Fails only on a malformed search path.
    pub fn new(cfg: &ShellRunConfig, grants: Arc<SessionGrants>) -> Result<Self, String> {
        let policy = ShellPolicy::new(Allowlist::any_program(), cfg.search_path.clone())
            .map_err(|e| e.to_string())?
            .with_default_timeout(Duration::from_secs(DEFAULT_TIMEOUT_SECS))
            .with_max_timeout(Duration::from_secs(MAX_TIMEOUT_SECS))
            .with_output_caps(OUTPUT_CAP, OUTPUT_CAP)
            .with_sandbox(cfg.sandbox.clone());
        let runner = ShellRunner::with_scope(policy, move |cwd: &Path| {
            grants.shell_scope(cwd).map(|(_, root)| vec![root])
        });
        Ok(ShellRunSession {
            runner: Arc::new(runner),
            approvals: Arc::new(ShellApprovals::default()),
            approval_timeout: cfg.approval_timeout,
        })
    }

    pub fn approvals(&self) -> &Arc<ShellApprovals> {
        &self.approvals
    }

    /// The host for one turn of the session.
    pub fn host(&self, taint: TaintState, stop: StopFlag) -> ShellRunHost {
        ShellRunHost {
            runner: self.runner.clone(),
            approvals: self.approvals.clone(),
            approval_timeout: self.approval_timeout,
            taint,
            stop,
        }
    }
}

/// Executes `shell_run` calls.
pub struct ShellRunHost {
    runner: Arc<ShellRunner>,
    approvals: Arc<ShellApprovals>,
    approval_timeout: Duration,
    taint: TaintState,
    stop: StopFlag,
}

/// The model's proposal.
struct Proposal {
    argv: Vec<String>,
    cwd: PathBuf,
    timeout_secs: u64,
}

fn parse(raw: &str) -> Result<Proposal, String> {
    let raw = if raw.trim().is_empty() { "{}" } else { raw };
    let args: serde_json::Map<String, serde_json::Value> = match serde_json::from_str(raw) {
        Ok(serde_json::Value::Object(m)) => m,
        _ => return Err("the arguments must be a JSON object".into()),
    };
    let argv_err = || {
        format!(
            "argv must be a list of 1 to {MAX_ARGV} strings (each at most {MAX_ARG_BYTES} bytes), program first"
        )
    };
    let argv: Vec<String> = match args.get("argv") {
        Some(serde_json::Value::Array(items)) if (1..=MAX_ARGV).contains(&items.len()) => items
            .iter()
            .map(|v| v.as_str().map(str::to_string))
            .collect::<Option<Vec<_>>>()
            .ok_or_else(argv_err)?,
        _ => return Err(argv_err()),
    };
    if argv.iter().any(|a| a.len() > MAX_ARG_BYTES)
        || argv.iter().map(String::len).sum::<usize>() > MAX_ARGV_BYTES
    {
        return Err(argv_err());
    }
    let cwd = match args.get("cwd") {
        Some(serde_json::Value::String(c)) if !c.trim().is_empty() => PathBuf::from(c),
        _ => return Err("cwd (the absolute path of the folder to run in) is required".into()),
    };
    if !cwd.is_absolute() {
        return Err("cwd must be an absolute path inside a granted folder".into());
    }
    let timeout_secs = match args.get("timeout_secs") {
        None | Some(serde_json::Value::Null) => DEFAULT_TIMEOUT_SECS,
        Some(v) => match v.as_u64() {
            Some(n) if (1..=MAX_TIMEOUT_SECS).contains(&n) => n,
            _ => {
                return Err(format!(
                    "timeout_secs must be a whole number from 1 to {MAX_TIMEOUT_SECS}"
                ))
            }
        },
    };
    Ok(Proposal {
        argv,
        cwd,
        timeout_secs,
    })
}

fn refuse(status: RunStatus, why: impl Into<String>) -> ToolOutcome {
    ToolOutcome::Error(ToolchainEnvelope::not_run(SHELL_RUN_TOOL, status, why).to_content())
}

fn refusal_for(e: &ShellError) -> ToolOutcome {
    match e {
        ShellError::ProgramNotFound { program, .. } => refuse(
            RunStatus::NotInstalled,
            format!("{program} is not installed on this machine's search path"),
        ),
        ShellError::InvalidProgramName { .. } => refuse(
            RunStatus::Refused,
            format!("{e}; the program must be a bare name such as npm, never a path"),
        ),
        ShellError::Spawn { .. } => refuse(RunStatus::Failed, e.to_string()),
        _ => refuse(RunStatus::Refused, e.to_string()),
    }
}

fn request_of(p: &Proposal) -> Option<RunRequest> {
    let (program, rest) = p.argv.split_first()?;
    Some(
        RunRequest::new(program, rest.to_vec(), &p.cwd)
            .timeout(Duration::from_secs(p.timeout_secs)),
    )
}

/// The same program, argv and folder as approved.
fn same_command(a: &RunPlan, b: &RunPlan) -> bool {
    a.resolved_path == b.resolved_path && a.args == b.args && a.cwd == b.cwd
}

fn report(argv: &[String], r: &RunReport) -> ToolOutcome {
    let facts = serde_json::json!({
        "program": r.program,
        "args": r.args,
        "argv": argv,
        "cwd": r.cwd,
        "exit_code": r.exit_code,
        "signal": r.signal,
        "timed_out": r.timed_out,
        "timeout_ms": r.timeout_ms,
        "duration_ms": r.duration_ms,
        "stdout": r.stdout,
        "stderr": r.stderr,
        "stdout_bytes": r.stdout_bytes,
        "stderr_bytes": r.stderr_bytes,
        "stdout_truncated": r.stdout_truncated,
        "stderr_truncated": r.stderr_truncated,
        "output_incomplete": r.output_incomplete,
        "sandbox": r.sandbox,
    });
    let isolation = if r.sandbox.enforced {
        format!("in the {} sandbox, no network", r.sandbox.backend)
    } else {
        "without an OS sandbox".to_string()
    };
    if r.timed_out {
        return ToolOutcome::Error(
            ToolchainEnvelope::not_run(
                SHELL_RUN_TOOL,
                RunStatus::TimedOut,
                format!(
                    "{} did not finish within {}s and was stopped ({isolation})",
                    r.program,
                    r.timeout_ms / 1000
                ),
            )
            .with_run(facts)
            .to_content(),
        );
    }
    let ended = match (r.exit_code, r.signal) {
        (Some(c), _) => format!("exited with code {c}"),
        (None, Some(s)) => format!("was ended by signal {s}"),
        (None, None) => "ended without a status".to_string(),
    };
    ToolOutcome::Ok(
        ToolchainEnvelope::not_run(
            SHELL_RUN_TOOL,
            RunStatus::Completed,
            format!(
                "{} {ended} after {} ms ({isolation})",
                r.program, r.duration_ms
            ),
        )
        .with_run(facts)
        .to_content(),
    )
}

impl ToolHost for ShellRunHost {
    fn execute(&self, call: &ToolCall) -> ToolOutcome {
        if call.name != SHELL_RUN_TOOL {
            return ToolOutcome::Error(format!("'{}' is not shell_run", call.name));
        }
        if self.taint.is_tainted() {
            return ToolOutcome::Denied(
                "this session read untrusted content, so it does not run commands".into(),
            );
        }
        let proposal = match parse(&call.arguments) {
            Ok(p) => p,
            Err(e) => return refuse(RunStatus::Refused, e),
        };
        let Some(req) = request_of(&proposal) else {
            return refuse(RunStatus::Refused, "argv is empty");
        };
        // Everything is checked (grants, program, sandbox) before the member is asked.
        let plan = match self.runner.plan(&req) {
            Ok(p) => p,
            Err(e) => return refusal_for(&e),
        };
        let view = ShellPending {
            id: String::new(),
            call_id: call.id.clone(),
            tool: SHELL_RUN_TOOL.into(),
            hic: "required".into(),
            argv: proposal.argv.clone(),
            resolved_program: plan.resolved_path.display().to_string(),
            cwd: plan.cwd.display().to_string(),
            timeout_secs: plan.timeout.as_secs(),
            sandbox: plan.sandbox.clone(),
            expires_in_secs: 0,
        };
        let stop = self.stop.clone();
        if let Err(why) = self
            .approvals
            .request(view, self.approval_timeout, &move || stop.is_stopped())
        {
            return ToolOutcome::Denied(why);
        }
        if self.stop.is_stopped() {
            return ToolOutcome::Denied("the session was stopped; nothing ran".into());
        }
        // The grants are checked again now: a grant revoked while the card was open stops it.
        let again = match self.runner.plan(&req) {
            Ok(p) => p,
            Err(e) => return refusal_for(&e),
        };
        if !same_command(&plan, &again) {
            return refuse(
                RunStatus::Refused,
                "what would run changed after the member approved it, so nothing ran",
            );
        }
        match self.runner.run(&req) {
            Ok(r) => report(&proposal.argv, &r),
            Err(e) => refusal_for(&e),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parse_keeps_argv_exactly() {
        let p = parse(r#"{"argv":["npm","run","build -- --x"],"cwd":"/p"}"#).expect("parse");
        assert_eq!(p.argv, vec!["npm", "run", "build -- --x"]);
        assert_eq!(p.timeout_secs, DEFAULT_TIMEOUT_SECS);
    }

    #[test]
    fn parse_refuses_oversized_argv() {
        let big = "x".repeat(MAX_ARG_BYTES + 1);
        let raw = serde_json::json!({"argv": ["echo", big], "cwd": "/p"}).to_string();
        assert!(parse(&raw).is_err());
        let many: Vec<String> = (0..MAX_ARGV).map(|_| "y".repeat(MAX_ARG_BYTES)).collect();
        let raw = serde_json::json!({"argv": many, "cwd": "/p"}).to_string();
        assert!(parse(&raw).is_err(), "total argv bytes are bounded too");
    }
}
