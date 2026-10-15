//! US-2.2 AC2 — `shell_run`: a general command, run only after the member approves exactly it.
//!
//! The four toolchain tools ([`crate::toolchain`]) are fixed argv templates. Anything else the
//! agent wants to run goes through this tool, which is **off by default**
//! (`CITRATE_HERMES_SHELL_RUN=1` turns it on, pending owner sign-off) and offered only to a
//! session opened with the member's folder grants.
//!
//! One call:
//!
//! 1. **After taint, still asked, never automatic (HGW-1).** Once a session has read untrusted
//!    content, a command is still put in front of the member, with the card saying why it is
//!    gated (`hicReason`, `taintSources`), but only in a session opened by an HIC-aware app
//!    (`hicAware: true`). Without one nobody can be asked, so the call is declined with
//!    [`citrate_agent_loop::cannot_ask_reason`]. An approval releases that one command; the
//!    session stays tainted.
//! 2. **Validated before anything is asked.** The model gives `argv` (program first, as a bare
//!    name resolved from a fixed search path, never a path; argv only, no shell expansion) and an
//!    absolute `cwd`. The cwd must be covered by live read and write folder grants that reach
//!    their whole subtree ([`crate::grants::SessionGrants::shell_scope`]); that grant's folder is
//!    the only one the command may write. The OS sandbox is **required**: with no working backend
//!    the call is refused and nothing is asked.
//! 3. **HIC required, except the auto-approve list (HGW-5, D-16 as amended).** A command that
//!    matches a rule of [`crate::auto_approve`] runs without a card only when the session is
//!    untainted, the OS sandbox is enforced, and its folder is inside one of the session's project
//!    roots; that run may write only the project (not the wider grant), it is recorded
//!    (`shell.run.auto`), and its result says so (`run.approval = {mode: "auto", rule, project}`).
//!    Everything else parks as a [`ShellPending`] (the exact argv, the program
//!    it resolves to, the canonical cwd, the timeout, the sandbox) that citrate-core shows as an
//!    approval card (`GET /sessions/:id/shell/pending`). The member's decision
//!    (`POST /sessions/:id/shell/decide`) must carry the argv and cwd that were shown; anything
//!    else is refused. No decision within [`APPROVAL_TIMEOUT`], or a session stop, declines it.
//! 4. **Runs in the OS sandbox**, after the grant check is repeated: no network, writes only in
//!    the grant's folder and a scratch HOME, a wall-clock timeout that kills the process group,
//!    and stdout/stderr captured up to [`OUTPUT_CAP`] bytes each.
//! 5. **Reports** a toolchain envelope (`tool: "shell_run"`) with the run facts, the captured
//!    output and the sandbox; citrate-core adds it to the Activity monitor. The output is
//!    untrusted, so it taints the session (and every later effectful call then needs a card).
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
/// HGW-4: bytes of a failing command's stderr (or stdout, when stderr is empty) handed to the
/// model in the result's summary, from the end of the stream, where npm, cargo and tsc print the
/// cause. The full capture (head and tail) stays in the run facts.
pub const FAILURE_TAIL_BYTES: usize = 2048;
/// HGW-5: the author and committer of commits made through `shell_run` (`git` runs only). The
/// run's scratch HOME has no git identity, so without these git refuses to commit; and a commit
/// Hermes makes is Hermes's, whoever's machine it is. These outrank the repository's own
/// `user.name`/`user.email` for that run (pending owner sign-off on the wording).
pub const GIT_AGENT_NAME: &str = "Hermes";
pub const GIT_AGENT_EMAIL: &str = "hermes@citrate.invalid";
const GIT_IDENTITY_ENV: [&str; 4] = [
    "GIT_AUTHOR_NAME",
    "GIT_AUTHOR_EMAIL",
    "GIT_COMMITTER_NAME",
    "GIT_COMMITTER_EMAIL",
];
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
    /// HGW-5: commands that may run without a card (see the module docs). `None` = every command
    /// asks.
    pub auto_approve: Option<Arc<crate::auto_approve::AutoApproveList>>,
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
        // HGW-5: the shipped list unless CITRATE_HERMES_AUTO_APPROVE says otherwise; a list that
        // does not load turns auto-approval off (every command asks) and says why.
        let auto_approve = match crate::auto_approve::AutoApproveList::from_env_value(
            get(crate::auto_approve::AUTO_APPROVE_ENV).as_deref(),
        ) {
            Ok(l) => l.map(Arc::new),
            Err(e) => {
                eprintln!("citrate-agent-sidecar: auto-approval is off: {e}");
                None
            }
        };
        Some(ShellRunConfig {
            search_path,
            sandbox: SandboxPolicy::new(SandboxMode::Required),
            approval_timeout: APPROVAL_TIMEOUT,
            auto_approve,
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
        description: "Run one command in a folder the member granted. It runs in an OS sandbox with no network, may write only in that folder, and is stopped at its time limit. Inside a project, listed read and build commands (ls, cat, head, node <file>, npm run <script>, npm test, forge build/test, cargo build/test --offline, git init/status/diff/add/commit) run without asking; for anything else the member sees the exact command and folder and must approve it first. If a command is declined, ask the member; do not retry it. Use the forge_test, slither_scan, aderyn_scan and medusa_fuzz tools for those programs instead.".into(),
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
    /// HGW-1: why this command is gated beyond the usual card, when the session is tainted.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub hic_reason: Option<String>,
    /// HGW-1: every tool that brought untrusted content into the session (empty when clean).
    #[serde(skip_serializing_if = "Vec::is_empty")]
    pub taint_sources: Vec<String>,
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
                    Err("the member declined this command; ask the member what to do instead of retrying it".to_string())
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
    /// HGW-5: the runner for auto-approved commands: same policy, but a run may write only the
    /// project root that holds its folder (and is refused outside a project).
    auto_runner: Arc<ShellRunner>,
    auto_approve: Option<Arc<crate::auto_approve::AutoApproveList>>,
    records: Option<Arc<citrate_agent_records::DecisionLog>>,
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
            .with_request_env_allow(&GIT_IDENTITY_ENV)
            .with_sandbox(cfg.sandbox.clone());
        let g = grants.clone();
        let auto_runner = ShellRunner::with_scope(policy.clone(), move |cwd: &Path| {
            let (dir, _) = g.shell_scope(cwd)?;
            g.project_root_of(&dir)
                .map(|root| vec![root])
                .ok_or_else(|| "the folder is not inside a project".to_string())
        });
        let runner = ShellRunner::with_scope(policy, move |cwd: &Path| {
            grants.shell_scope(cwd).map(|(_, root)| vec![root])
        });
        Ok(ShellRunSession {
            runner: Arc::new(runner),
            auto_runner: Arc::new(auto_runner),
            auto_approve: cfg.auto_approve.clone(),
            records: None,
            approvals: Arc::new(ShellApprovals::default()),
            approval_timeout: cfg.approval_timeout,
        })
    }

    /// HUP-S2.6: record auto-approved runs in this decision log (when configured).
    pub fn with_records(mut self, log: Option<Arc<citrate_agent_records::DecisionLog>>) -> Self {
        self.records = log;
        self
    }

    pub fn approvals(&self) -> &Arc<ShellApprovals> {
        &self.approvals
    }

    /// The host for one turn of the session. `hic_aware`: the session was opened by an app that
    /// always puts a `hic: "required"` card in front of a person, so a tainted session may still
    /// ask; without it a tainted session's commands are declined.
    pub fn host(&self, taint: TaintState, stop: StopFlag, hic_aware: bool) -> ShellRunHost {
        ShellRunHost {
            runner: self.runner.clone(),
            auto_runner: self.auto_runner.clone(),
            auto_approve: self.auto_approve.clone(),
            records: self.records.clone(),
            approvals: self.approvals.clone(),
            approval_timeout: self.approval_timeout,
            taint,
            stop,
            hic_aware,
        }
    }
}

/// Executes `shell_run` calls.
pub struct ShellRunHost {
    runner: Arc<ShellRunner>,
    auto_runner: Arc<ShellRunner>,
    auto_approve: Option<Arc<crate::auto_approve::AutoApproveList>>,
    records: Option<Arc<citrate_agent_records::DecisionLog>>,
    approvals: Arc<ShellApprovals>,
    approval_timeout: Duration,
    taint: TaintState,
    stop: StopFlag,
    hic_aware: bool,
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
    let mut req = RunRequest::new(program, rest.to_vec(), &p.cwd)
        .timeout(Duration::from_secs(p.timeout_secs));
    if program == "git" {
        for (i, name) in GIT_IDENTITY_ENV.iter().enumerate() {
            req = req.env(
                name,
                if i % 2 == 0 {
                    GIT_AGENT_NAME
                } else {
                    GIT_AGENT_EMAIL
                },
            );
        }
    }
    Some(req)
}

/// The same program, argv and folder as approved.
fn same_command(a: &RunPlan, b: &RunPlan) -> bool {
    a.resolved_path == b.resolved_path && a.args == b.args && a.cwd == b.cwd
}

/// The last `max` bytes of `s` (on a character boundary).
pub(crate) fn tail_of(s: &str, max: usize) -> String {
    if s.len() <= max {
        return s.to_string();
    }
    let mut start = s.len() - max;
    while !s.is_char_boundary(start) {
        start += 1;
    }
    s[start..].to_string()
}

/// How a run was released (HGW-5): by the member's card, or by an auto-approve rule.
enum Released<'a> {
    Member,
    Auto { rule: &'a str, project: &'a Path },
}

fn report(argv: &[String], r: &RunReport, released: &Released<'_>) -> ToolOutcome {
    let mut facts = serde_json::json!({
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
        "cleanup_error": r.cleanup_error,
        "sandbox": r.sandbox,
        "git_warnings": r.git_warnings,
        "approval": match released {
            Released::Member => serde_json::json!({ "mode": "member" }),
            Released::Auto { rule, project } => serde_json::json!({
                "mode": "auto",
                "rule": rule,
                "project": project,
            }),
        },
    });
    let auto_note = match released {
        Released::Member => String::new(),
        Released::Auto { rule, project } => format!(
            "Ran without a card under the auto-approve rule {rule} (sandboxed, no network, writing only the project {}). ",
            project.display()
        ),
    };
    // HGW-2: git state the command left that would run a program outside the sandbox later.
    let git_note = if r.git_warnings.is_empty() {
        String::new()
    } else {
        format!(
            ". Warning: the command left git set up to run a program outside the sandbox the next time git is used ({}); the member should review it",
            r.git_warnings.join("; ")
        )
    };
    let isolation = if r.sandbox.enforced {
        format!("in the {} sandbox, no network", r.sandbox.backend)
    } else {
        "without an OS sandbox".to_string()
    };
    if let Some(cleanup_error) = &r.cleanup_error {
        return ToolOutcome::Error(
            ToolchainEnvelope::not_run(
                SHELL_RUN_TOOL,
                RunStatus::Failed,
                format!("{} ran but cleanup failed: {cleanup_error}", r.program),
            )
            .with_run(facts)
            .to_content(),
        );
    }
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
    // HGW-4: a failing command hands the model the end of its output, so it can fix the cause.
    let failure_note = if r.exit_code == Some(0) {
        String::new()
    } else {
        let (stream, text) = if r.stderr.trim().is_empty() {
            ("stdout", r.stdout.as_str())
        } else {
            ("stderr", r.stderr.as_str())
        };
        let tail = tail_of(text, FAILURE_TAIL_BYTES);
        if let Some(o) = facts.as_object_mut() {
            o.insert(format!("{stream}_tail"), serde_json::json!(tail));
        }
        if tail.trim().is_empty() {
            ". It printed nothing".to_string()
        } else {
            format!(". The end of its {stream}:\n{tail}")
        }
    };
    ToolOutcome::Ok(
        ToolchainEnvelope::not_run(
            SHELL_RUN_TOOL,
            RunStatus::Completed,
            format!(
                "{auto_note}{} {ended} after {} ms ({isolation}){git_note}{failure_note}",
                r.program, r.duration_ms
            ),
        )
        .with_run(facts)
        .to_content(),
    )
}

impl ShellRunHost {
    /// Validate, ask the member (with the taint reason when there is one), re-check, run.
    fn ask_and_run(&self, call: &ToolCall, hic_reason: Option<&str>) -> ToolOutcome {
        if call.name != SHELL_RUN_TOOL {
            return ToolOutcome::Error(format!("'{}' is not shell_run", call.name));
        }
        let proposal = match parse(&call.arguments) {
            Ok(p) => p,
            Err(e) => return refuse(RunStatus::Refused, e),
        };
        let Some(req) = request_of(&proposal) else {
            return refuse(RunStatus::Refused, "argv is empty");
        };
        // HGW-5: a listed command inside a project runs without a card (never after taint).
        if hic_reason.is_none() {
            if let Some(out) = self.try_auto(call, &proposal.argv, &req) {
                return out;
            }
        }
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
            hic_reason: hic_reason.map(str::to_string),
            taint_sources: if hic_reason.is_some() {
                self.taint.sources().unwrap_or_default()
            } else {
                Vec::new()
            },
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
            Ok(r) => report(&proposal.argv, &r, &Released::Member),
            Err(e) => refusal_for(&e),
        }
    }

    /// HGW-5: run `req` without a card when every condition holds (untainted, listed, OS sandbox
    /// enforced, inside a project, recorded when records are on). `None` = ask as usual.
    fn try_auto(&self, call: &ToolCall, argv: &[String], req: &RunRequest) -> Option<ToolOutcome> {
        if self.taint.is_tainted() {
            return None;
        }
        let rule = self.auto_approve.as_ref()?.matching(argv)?.to_string();
        let plan = self.auto_runner.plan(req).ok()?;
        if !plan.sandbox.enforced {
            return None;
        }
        let project = plan.write_roots.first()?.clone();
        let seq = match &self.records {
            Some(log) => match crate::hic_records::record_auto_decision(
                log,
                "shell.run.auto",
                &format!("{} (in {})", argv.join(" "), plan.cwd.display()),
                &format!(
                    "auto-approve rule {rule}: {} runs in the OS sandbox with no network, writing only the project {}",
                    argv.join(" "),
                    project.display()
                ),
                vec![citrate_agent_records::EvidenceRef {
                    kind: "shell_run".to_string(),
                    uri: format!("sidecar:shell_run/{}", call.id),
                    digest: None,
                }],
            ) {
                Ok(seq) => Some(seq),
                // Not recorded = not released without a card: ask instead.
                Err(_) => return None,
            },
            None => None,
        };
        let out = match self.auto_runner.run(req) {
            // The output of a listed command run this way derives from the project's own files
            // (no network, writes only in the project, an untainted session), like a folder-grant
            // file read: it is vouched for and does not taint. Errors keep the tool's annotation.
            Ok(r) => match report(
                argv,
                &r,
                &Released::Auto {
                    rule: &rule,
                    project: &project,
                },
            ) {
                ToolOutcome::Ok(s) => ToolOutcome::Vouched(s),
                other => other,
            },
            Err(e) => refusal_for(&e),
        };
        if let (Some(log), Some(seq)) = (&self.records, seq) {
            let (outcome, detail) = match &out {
                ToolOutcome::Ok(_) | ToolOutcome::Vouched(_) => {
                    (citrate_agent_records::Outcome::Completed, "ran")
                }
                _ => (citrate_agent_records::Outcome::Failed, "did not complete"),
            };
            crate::hic_records::record_outcome(log, seq, outcome, detail);
        }
        Some(out)
    }

    /// The reason a tainted session's command is gated (the loop's wording, naming the source).
    fn taint_reason(&self) -> Option<String> {
        self.taint.record().map(|r| {
            format!(
                "this session read untrusted content (from {}), so this action needs your explicit approval",
                r.source
            )
        })
    }
}

impl ToolHost for ShellRunHost {
    fn execute(&self, call: &ToolCall) -> ToolOutcome {
        // The loop routes tainted calls through `execute_with_explicit_approval`; a session that
        // became tainted in between is checked again here and never runs a command unasked.
        match self.taint_reason() {
            Some(reason) => self.execute_with_explicit_approval(call, &reason),
            None => self.ask_and_run(call, None),
        }
    }

    fn honors_explicit_approval(&self) -> bool {
        self.hic_aware
    }

    /// HGW-1: the command's own card is the explicit approval; it carries the reason. Without an
    /// HIC-aware app nobody can be asked, so nothing is asked or run.
    fn execute_with_explicit_approval(&self, call: &ToolCall, reason: &str) -> ToolOutcome {
        if !self.hic_aware {
            return ToolOutcome::Denied(citrate_agent_loop::cannot_ask_reason(
                self.taint.record().as_ref().map(|r| r.source.as_str()),
            ));
        }
        self.ask_and_run(call, Some(reason))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn cleanup_failed_report() -> RunReport {
        RunReport {
            program: "echo".into(),
            resolved_path: PathBuf::from("echo"),
            args: vec!["ok".into()],
            cwd: PathBuf::from("."),
            exit_code: Some(0),
            signal: None,
            timed_out: false,
            timeout_ms: 1_000,
            duration_ms: 10,
            stdout: "ok\n".into(),
            stderr: String::new(),
            stdout_bytes: 3,
            stderr_bytes: 0,
            stdout_truncated: false,
            stderr_truncated: false,
            output_incomplete: false,
            cleanup_error: Some("scratch removal failed".into()),
            sandbox: SandboxSummary {
                backend: "none".into(),
                enforced: false,
                network: "allowed".into(),
                writable: Vec::new(),
                readable_extra: Vec::new(),
                summary: "test".into(),
            },
            git_warnings: Vec::new(),
        }
    }

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

    #[test]
    fn cleanup_failure_is_failed_with_run_facts() {
        let out = report(
            &["echo".into(), "ok".into()],
            &cleanup_failed_report(),
            &Released::Member,
        );
        let ToolOutcome::Error(content) = out else {
            panic!("cleanup failure must be a tool error");
        };
        let env = ToolchainEnvelope::from_content(&content).expect("envelope");

        assert_eq!(env.status, RunStatus::Failed);
        assert!(env.verdict.is_none());
        let facts = env.run.expect("run facts");
        assert_eq!(facts["exit_code"], 0);
        assert_eq!(facts["cleanup_error"], "scratch removal failed");
    }
}
