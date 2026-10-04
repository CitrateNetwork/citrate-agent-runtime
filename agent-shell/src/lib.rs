//! # citrate-agent-shell — Hermes's shell allowlist runner (HUP-S2.2)
//!
//! "Brain in the sidecar, hands in core": the sidecar hosts the agent loop, and this crate is
//! the piece of it that runs a toolchain program (forge, anvil, slither, npm, read-only git, ...)
//! on the agent's behalf. It is a synchronous library: call [`ShellRunner::run`] from a blocking
//! thread (`tokio::task::spawn_blocking` in the sidecar).
//!
//! What one run guarantees:
//!
//! - **Allowlist by bare name.** The program must be a bare name (`forge`, not `/x/forge`,
//!   `./forge`, or `forge;rm`) that appears on the [`Allowlist`]. Names are restricted to
//!   `[A-Za-z0-9._+-]` and may not start with `-` or `.`.
//! - **Argv only.** No shell is ever involved. Arguments are passed to `execve` literally, so
//!   `$(...)`, `;`, `|` and globs in an argument are plain bytes. Per-program [`ArgPolicy`]
//!   can narrow arguments further (git is limited to read-only subcommands).
//! - **Fixed resolution.** The program is resolved to an absolute path from the policy's fixed
//!   search path (absolute directories only), never from the caller's `PATH` or the cwd.
//! - **Scrubbed environment.** The child sees only `PATH` (the search path), a fresh per-run
//!   scratch `HOME`/`TMPDIR` that is deleted afterwards, `NO_COLOR=1`, a small locale
//!   pass-through set, per-program fixed variables, and request variables whose names the
//!   policy explicitly allows.
//! - **Caller-checked cwd.** The cwd must be absolute and exist; its canonical form is handed to
//!   the caller's check closure, which is where S2.1 folder grants and the S2.8 default-deny
//!   list plug in.
//! - **Wall-clock timeout.** The child leads its own process group; on timeout the whole group
//!   is killed with `SIGKILL`. Leftover group members are also killed when the leader exits.
//! - **Capped capture.** stdout and stderr are captured separately up to per-stream byte caps,
//!   with a truncation marker and the true byte count, and drained to EOF so a chatty child
//!   never blocks on a full pipe.
//! - **A [`RunReport`]** with exit code / signal / timeout / duration that serializes to JSON
//!   for the S1.3 verifiers (`JsonFieldEquals` on `exit_code`, `passed`, ...).
//!
//! - **An OS sandbox when the policy asks for one** ([`sandbox`], US-2.2 AC1): macOS Seatbelt
//!   or Linux bubblewrap with no network, writes only in the caller's write roots (the granted
//!   folder) and the scratch HOME, and reads limited to those, the system and the toolchain
//!   directories. [`sandbox::SandboxMode::Required`] fails closed when no backend works here;
//!   every report says whether the run was isolated ([`RunReport::sandbox`]).
//!
//! Honest scope: the allowlist alone is not a sandbox. Several allowlisted programs execute
//! project code by design (forge scripts and FFI, npm lifecycle scripts, node), so the
//! allowlist bounds *which entry points* the agent can reach; the OS sandbox bounds what they
//! can touch (no network, writes only in the grant), and HIC approval (US-2.2 AC2) and folder
//! grants on the cwd decide whether they run at all. A policy with the sandbox off (the
//! default of [`ShellPolicy::new`]) runs exactly as before and reports `enforced: false`.
//! This crate never holds a key and never signs (Rule 3).
//!
//! Lifted from `citrate-agent-code` (`agent-code/src/tools/shell_exec.rs`,
//! `git_operations.rs`): the bare-name/relative-path refusal, the cleared environment with a
//! fixed PATH, the isolated scratch HOME, and git's global/system config pinned to `/dev/null`.
//! That crate is async and tied to the legacy tool trait, so the logic is re-homed here as a
//! synchronous, dependency-light library.

pub mod sandbox;

use sandbox::{Backend, SandboxMode, SandboxPolicy, SandboxSpec, SandboxSummary};
use serde::Serialize;
use std::collections::BTreeMap;
use std::fmt;
use std::io::Read;
use std::os::unix::fs::{DirBuilderExt, PermissionsExt};
use std::os::unix::process::{CommandExt, ExitStatusExt};
use std::path::{Path, PathBuf};
use std::process::{Child, Command, Stdio};
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{mpsc, Arc, Mutex};
use std::time::{Duration, Instant};

// ------------------------------------------------------------------------------------------
// Errors
// ------------------------------------------------------------------------------------------

/// Why a run was refused or could not start. A run that starts always yields a [`RunReport`]
/// (non-zero exit and timeout are reported, not errors).
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ShellError {
    /// The program string is not a bare, plain name (path separators, shell metacharacters,
    /// whitespace, NUL, leading `-`/`.`, or empty).
    InvalidProgramName { program: String, reason: String },
    /// The program is a valid name but is not on the allowlist.
    ProgramNotAllowed { program: String },
    /// An argument is refused by the program's [`ArgPolicy`] (or contains NUL).
    ArgumentRefused {
        program: String,
        arg: String,
        reason: String,
    },
    /// A request environment variable is not on the policy's request allowlist.
    EnvRefused { name: String, reason: String },
    /// The cwd is not absolute, does not exist, is not a directory, or the caller's check
    /// refused it.
    CwdRefused { cwd: PathBuf, reason: String },
    /// The program is allowlisted but no executable file of that name is on the search path.
    ProgramNotFound {
        program: String,
        search_path: Vec<PathBuf>,
    },
    /// The policy itself is malformed (for example a relative search-path entry).
    InvalidPolicy { reason: String },
    /// The OS refused to start the process (or the scratch HOME could not be created).
    Spawn { program: String, reason: String },
    /// The policy requires the OS sandbox and no backend works on this machine; nothing ran.
    SandboxUnavailable { reason: String },
}

impl fmt::Display for ShellError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            ShellError::InvalidProgramName { program, reason } => {
                write!(f, "invalid program name {program:?}: {reason}")
            }
            ShellError::ProgramNotAllowed { program } => {
                write!(f, "program {program:?} is not on the shell allowlist")
            }
            ShellError::ArgumentRefused {
                program,
                arg,
                reason,
            } => write!(f, "{program}: argument {arg:?} refused: {reason}"),
            ShellError::EnvRefused { name, reason } => {
                write!(f, "environment variable {name:?} refused: {reason}")
            }
            ShellError::CwdRefused { cwd, reason } => {
                write!(f, "working directory {} refused: {reason}", cwd.display())
            }
            ShellError::ProgramNotFound {
                program,
                search_path,
            } => {
                let dirs: Vec<String> = search_path
                    .iter()
                    .map(|p| p.display().to_string())
                    .collect();
                write!(
                    f,
                    "program {program:?} is allowlisted but not installed on the search path ({})",
                    dirs.join(":")
                )
            }
            ShellError::InvalidPolicy { reason } => write!(f, "invalid shell policy: {reason}"),
            ShellError::Spawn { program, reason } => {
                write!(f, "could not start {program:?}: {reason}")
            }
            ShellError::SandboxUnavailable { reason } => write!(
                f,
                "the OS sandbox is required but not available on this machine ({reason}); nothing ran"
            ),
        }
    }
}

impl std::error::Error for ShellError {}

impl ShellError {
    /// A short stable tag for logs and tool results.
    pub fn kind(&self) -> &'static str {
        match self {
            ShellError::InvalidProgramName { .. } => "invalid_program_name",
            ShellError::ProgramNotAllowed { .. } => "program_not_allowed",
            ShellError::ArgumentRefused { .. } => "argument_refused",
            ShellError::EnvRefused { .. } => "env_refused",
            ShellError::CwdRefused { .. } => "cwd_refused",
            ShellError::ProgramNotFound { .. } => "program_not_found",
            ShellError::InvalidPolicy { .. } => "invalid_policy",
            ShellError::Spawn { .. } => "spawn_failed",
            ShellError::SandboxUnavailable { .. } => "sandbox_unavailable",
        }
    }
}

// ------------------------------------------------------------------------------------------
// Allowlist
// ------------------------------------------------------------------------------------------

/// Read-only git subcommands the agent may run.
pub const GIT_READ_ONLY_SUBCOMMANDS: &[&str] = &[
    "status",
    "diff",
    "log",
    "show",
    "rev-parse",
    "ls-files",
    "ls-tree",
    "blame",
    "describe",
    "shortlog",
    "merge-base",
];

/// Argument prefixes refused on every git invocation, even under a read-only subcommand:
/// options that write files, select another repository, or hand work to an external program.
pub const GIT_DENIED_ARG_PREFIXES: &[&str] = &[
    "--output",
    "--ext-diff",
    "--textconv",
    "--no-index",
    "--exec",
    "--upload-pack",
    "--receive-pack",
    "--git-dir",
    "--work-tree",
    "--namespace",
    "--super-prefix",
    "--config-env",
    "--contents",
    "--ignore-revs-file",
];

/// Exact git option names that are also leading fragments of a denied option, so the
/// abbreviation check in [`denied_git_option`] must not treat them as abbreviations.
const GIT_EXACT_OPTIONS_NOT_ABBREVIATIONS: &[&str] = &["--text"];

/// Git subcommands that render diffs; the runner adds `--no-ext-diff --no-textconv` to them so
/// diff rendering stays inside git itself.
const GIT_DIFF_RENDERING: &[&str] = &["diff", "log", "show"];

/// `git blame` applies textconv drivers by default and does not take `--no-ext-diff`; the
/// runner adds `--no-textconv` to it.
const GIT_TEXTCONV_ONLY: &[&str] = &["blame"];

/// The denied option an argument names, if any. git's option parser accepts unambiguous
/// abbreviations of long options, so a strict leading fragment of a denied option (other than
/// the bare `--` separator and the exact options in [`GIT_EXACT_OPTIONS_NOT_ABBREVIATIONS`])
/// is refused as well.
fn denied_git_option(sub: &str, arg: &str) -> Option<&'static str> {
    if let Some(p) = GIT_DENIED_ARG_PREFIXES
        .iter()
        .find(|p| arg.starts_with(**p))
    {
        return Some(p);
    }
    if arg.starts_with("--") {
        let name = arg.split_once('=').map_or(arg, |(n, _)| n);
        if name.len() > 2 && !GIT_EXACT_OPTIONS_NOT_ABBREVIATIONS.contains(&name) {
            if let Some(p) = GIT_DENIED_ARG_PREFIXES.iter().find(|p| p.starts_with(name)) {
                return Some(p);
            }
        }
    }
    // `git blame -S <file>` reads revisions from an arbitrary file; refuse it, including
    // inside a cluster of short options.
    if sub == "blame" && arg.starts_with('-') && !arg.starts_with("--") && arg.contains('S') {
        return Some("-S");
    }
    None
}

/// How a program's arguments are constrained.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ArgPolicy {
    /// Any argv (still argv-only, never shell-expanded; NUL is always refused).
    Any,
    /// git restricted to [`GIT_READ_ONLY_SUBCOMMANDS`] as the first argument (so no global
    /// options such as `-c` or `--git-dir`), with [`GIT_DENIED_ARG_PREFIXES`] refused anywhere,
    /// and a fixed environment that ignores user/system config and pins repository-local
    /// settings that would otherwise start helper processes.
    GitReadOnly,
}

/// The set of programs the runner will start, by bare name.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct Allowlist {
    programs: BTreeMap<String, ArgPolicy>,
    /// Every validated bare name is allowed with [`ArgPolicy::Any`] (names listed explicitly
    /// keep their own policy). For runs a member approves command by command.
    any_program: bool,
}

static ANY_ARGS: ArgPolicy = ArgPolicy::Any;

impl Allowlist {
    /// Nothing allowed.
    pub fn empty() -> Self {
        Self::default()
    }

    /// The hello-mint toolchain (HUP-S2.2): Foundry, the Solidity analyzers and compiler, the
    /// JS toolchain, and read-only git. Deliberately no shells, no generic file tools (cat, ls,
    /// cp, rm), no network clients, and no interpreters beyond node.
    pub fn hello_mint() -> Self {
        let mut a = Self::empty();
        for p in [
            "forge", "anvil", "cast", "slither", "aderyn", "medusa", "solc", "node", "npm", "npx",
            "pnpm",
        ] {
            a = a.allow(p, ArgPolicy::Any);
        }
        a.allow("git", ArgPolicy::GitReadOnly)
    }

    /// Add (or replace) a program. The name is validated at run time like any request, so an
    /// invalid name here can never match.
    pub fn allow(mut self, program: &str, policy: ArgPolicy) -> Self {
        self.programs.insert(program.to_string(), policy);
        self
    }

    /// Remove a program.
    pub fn deny(mut self, program: &str) -> Self {
        self.programs.remove(program);
        self
    }

    /// Any bare program name on the search path, with any argv (still argv-only, resolved from
    /// the fixed search path, never a path). Only for runs a member approves one by one.
    pub fn any_program() -> Self {
        Self {
            programs: BTreeMap::new(),
            any_program: true,
        }
    }

    /// Whether every bare name is allowed.
    pub fn allows_any_program(&self) -> bool {
        self.any_program
    }

    pub fn contains(&self, program: &str) -> bool {
        self.any_program || self.programs.contains_key(program)
    }

    pub fn policy_for(&self, program: &str) -> Option<&ArgPolicy> {
        match self.programs.get(program) {
            Some(p) => Some(p),
            None if self.any_program => Some(&ANY_ARGS),
            None => None,
        }
    }

    /// Allowlisted program names, sorted.
    pub fn programs(&self) -> Vec<String> {
        self.programs.keys().cloned().collect()
    }
}

/// Validate a program name: a bare, plain file name. Everything that could be interpreted by a
/// shell or as a path is refused before the allowlist is even consulted.
pub fn validate_program_name(program: &str) -> Result<(), ShellError> {
    let refuse = |reason: &str| ShellError::InvalidProgramName {
        program: program.to_string(),
        reason: reason.to_string(),
    };
    if program.is_empty() {
        return Err(refuse("empty program name"));
    }
    if program.len() > 64 {
        return Err(refuse("program name longer than 64 bytes"));
    }
    if program.contains('/') || program.contains('\\') {
        return Err(refuse(
            "program must be a bare name resolved from the fixed search path, not a path",
        ));
    }
    if program.starts_with('-') || program.starts_with('.') {
        return Err(refuse("program name may not start with '-' or '.'"));
    }
    if let Some(c) = program
        .chars()
        .find(|c| !(c.is_ascii_alphanumeric() || matches!(c, '.' | '_' | '+' | '-')))
    {
        return Err(refuse(&format!(
            "character {c:?} is not permitted in a program name (argv-only, no shell)"
        )));
    }
    Ok(())
}

fn check_args(program: &str, policy: &ArgPolicy, args: &[String]) -> Result<(), ShellError> {
    let refuse = |arg: &str, reason: &str| ShellError::ArgumentRefused {
        program: program.to_string(),
        arg: arg.to_string(),
        reason: reason.to_string(),
    };
    if let Some(a) = args.iter().find(|a| a.contains('\0')) {
        return Err(refuse(a, "NUL byte in argument"));
    }
    match policy {
        ArgPolicy::Any => Ok(()),
        ArgPolicy::GitReadOnly => {
            let sub = args
                .first()
                .ok_or_else(|| refuse("", "git needs a read-only subcommand"))?;
            if !GIT_READ_ONLY_SUBCOMMANDS.contains(&sub.as_str()) {
                return Err(refuse(
                    sub,
                    &format!(
                        "only read-only git subcommands are allowed ({}); global options are not",
                        GIT_READ_ONLY_SUBCOMMANDS.join(", ")
                    ),
                ));
            }
            for a in args {
                if let Some(p) = denied_git_option(sub, a) {
                    return Err(refuse(
                        a,
                        &format!("git option {p} is not permitted for the agent"),
                    ));
                }
            }
            Ok(())
        }
    }
}

/// The argv actually executed for `program`: the request args plus any policy-added flags.
fn effective_args(policy: &ArgPolicy, args: &[String]) -> Vec<String> {
    match policy {
        ArgPolicy::Any => args.to_vec(),
        ArgPolicy::GitReadOnly => {
            let mut out = Vec::with_capacity(args.len() + 2);
            if let Some((sub, rest)) = args.split_first() {
                out.push(sub.clone());
                if GIT_DIFF_RENDERING.contains(&sub.as_str()) {
                    out.push("--no-ext-diff".to_string());
                    out.push("--no-textconv".to_string());
                } else if GIT_TEXTCONV_ONLY.contains(&sub.as_str()) {
                    out.push("--no-textconv".to_string());
                }
                out.extend(rest.iter().cloned());
            }
            out
        }
    }
}

/// Environment fixed by a program's policy (applied after the generic fixed set).
fn policy_env(policy: &ArgPolicy) -> Vec<(&'static str, &'static str)> {
    match policy {
        ArgPolicy::Any => Vec::new(),
        ArgPolicy::GitReadOnly => vec![
            ("GIT_CONFIG_NOSYSTEM", "1"),
            ("GIT_CONFIG_GLOBAL", "/dev/null"),
            ("GIT_TERMINAL_PROMPT", "0"),
            ("GIT_OPTIONAL_LOCKS", "0"),
            ("GIT_PAGER", "cat"),
            // Command-scope config outranks repository-local config.
            ("GIT_CONFIG_COUNT", "2"),
            ("GIT_CONFIG_KEY_0", "core.fsmonitor"),
            ("GIT_CONFIG_VALUE_0", "false"),
            ("GIT_CONFIG_KEY_1", "core.hooksPath"),
            ("GIT_CONFIG_VALUE_1", "/dev/null"),
        ],
    }
}

// ------------------------------------------------------------------------------------------
// Policy
// ------------------------------------------------------------------------------------------

/// Variables the runner always sets itself; a request can never supply them.
const RESERVED_ENV: &[&str] = &["PATH", "HOME", "TMPDIR", "NO_COLOR"];

/// Locale/time variables copied from the host when present.
pub const DEFAULT_PASSTHROUGH_ENV: &[&str] = &["LANG", "LC_ALL", "LC_CTYPE", "TZ"];

pub const DEFAULT_TIMEOUT: Duration = Duration::from_secs(120);
pub const DEFAULT_MAX_TIMEOUT: Duration = Duration::from_secs(900);
pub const DEFAULT_OUTPUT_CAP: usize = 64 * 1024;

/// After the leader exits (or is killed), how long to wait for the output pipes to reach EOF.
/// A process that left the group can hold a pipe open; past this grace the capture so far is
/// reported and `output_incomplete` is set.
const DRAIN_GRACE: Duration = Duration::from_secs(2);

/// Everything that is fixed about how programs run, independent of a single request.
#[derive(Debug, Clone)]
pub struct ShellPolicy {
    allowlist: Allowlist,
    search_path: Vec<PathBuf>,
    passthrough_env: Vec<String>,
    request_env_allow: Vec<String>,
    default_timeout: Duration,
    max_timeout: Duration,
    stdout_cap: usize,
    stderr_cap: usize,
    sandbox: SandboxPolicy,
}

impl ShellPolicy {
    /// A policy with the given allowlist and search path. Every search-path entry must be
    /// absolute; programs are only ever resolved from these directories, in order.
    pub fn new(allowlist: Allowlist, search_path: Vec<PathBuf>) -> Result<Self, ShellError> {
        if search_path.is_empty() {
            return Err(ShellError::InvalidPolicy {
                reason: "search path is empty".to_string(),
            });
        }
        for d in &search_path {
            if !d.is_absolute() {
                return Err(ShellError::InvalidPolicy {
                    reason: format!("search path entry {} is not absolute", d.display()),
                });
            }
            if d.to_string_lossy().contains(':') {
                return Err(ShellError::InvalidPolicy {
                    reason: format!("search path entry {} contains ':'", d.display()),
                });
            }
        }
        Ok(Self {
            allowlist,
            search_path,
            passthrough_env: DEFAULT_PASSTHROUGH_ENV
                .iter()
                .map(|s| s.to_string())
                .collect(),
            request_env_allow: Vec::new(),
            default_timeout: DEFAULT_TIMEOUT,
            max_timeout: DEFAULT_MAX_TIMEOUT,
            stdout_cap: DEFAULT_OUTPUT_CAP,
            stderr_cap: DEFAULT_OUTPUT_CAP,
            sandbox: SandboxPolicy::off(),
        })
    }

    /// Wrap runs in the OS sandbox ([`sandbox`]). Default: off.
    pub fn with_sandbox(mut self, sandbox: SandboxPolicy) -> Self {
        self.sandbox = sandbox;
        self
    }

    pub fn sandbox(&self) -> &SandboxPolicy {
        &self.sandbox
    }

    /// The system directories, in lookup order. User-local toolchain directories (for example
    /// Foundry's `~/.foundry/bin`) are not included; a host that wants them adds them
    /// explicitly, which keeps the decision visible.
    pub fn default_search_path() -> Vec<PathBuf> {
        ["/opt/homebrew/bin", "/usr/local/bin", "/usr/bin", "/bin"]
            .iter()
            .map(PathBuf::from)
            .collect()
    }

    /// Replace the host variables copied through when present (default: locale + TZ).
    pub fn with_passthrough_env(mut self, names: &[&str]) -> Self {
        self.passthrough_env = names
            .iter()
            .filter(|n| !RESERVED_ENV.contains(n))
            .map(|s| s.to_string())
            .collect();
        self
    }

    /// Variable names a request may set (for example `FOUNDRY_PROFILE`). Reserved names
    /// (`PATH`, `HOME`, `TMPDIR`, `NO_COLOR`) are ignored.
    pub fn with_request_env_allow(mut self, names: &[&str]) -> Self {
        self.request_env_allow = names
            .iter()
            .filter(|n| !RESERVED_ENV.contains(n))
            .map(|s| s.to_string())
            .collect();
        self
    }

    pub fn with_default_timeout(mut self, t: Duration) -> Self {
        self.default_timeout = t;
        self
    }

    pub fn with_max_timeout(mut self, t: Duration) -> Self {
        self.max_timeout = t;
        self
    }

    /// Per-stream capture caps in bytes.
    pub fn with_output_caps(mut self, stdout_cap: usize, stderr_cap: usize) -> Self {
        self.stdout_cap = stdout_cap;
        self.stderr_cap = stderr_cap;
        self
    }

    pub fn allowlist(&self) -> &Allowlist {
        &self.allowlist
    }

    pub fn search_path(&self) -> &[PathBuf] {
        &self.search_path
    }

    /// Resolve a validated, allowlisted name to an absolute executable path on the search path.
    pub fn resolve(&self, program: &str) -> Result<PathBuf, ShellError> {
        for dir in &self.search_path {
            let candidate = dir.join(program);
            if let Ok(meta) = std::fs::metadata(&candidate) {
                if meta.is_file() && meta.permissions().mode() & 0o111 != 0 {
                    return Ok(candidate);
                }
            }
        }
        Err(ShellError::ProgramNotFound {
            program: program.to_string(),
            search_path: self.search_path.clone(),
        })
    }

    fn effective_timeout(&self, requested: Option<Duration>) -> Duration {
        requested
            .unwrap_or(self.default_timeout)
            .min(self.max_timeout)
    }
}

// ------------------------------------------------------------------------------------------
// Request + report
// ------------------------------------------------------------------------------------------

/// One program invocation.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RunRequest {
    pub program: String,
    pub args: Vec<String>,
    pub cwd: PathBuf,
    pub timeout: Option<Duration>,
    pub env: Vec<(String, String)>,
}

impl RunRequest {
    pub fn new(program: &str, args: Vec<String>, cwd: &Path) -> Self {
        Self {
            program: program.to_string(),
            args,
            cwd: cwd.to_path_buf(),
            timeout: None,
            env: Vec::new(),
        }
    }

    /// Requested timeout; clamped to the policy maximum.
    pub fn timeout(mut self, t: Duration) -> Self {
        self.timeout = Some(t);
        self
    }

    /// Request an environment variable; its name must be on the policy's request allowlist.
    pub fn env(mut self, name: &str, value: &str) -> Self {
        self.env.push((name.to_string(), value.to_string()));
        self
    }
}

/// The outcome of a run that started. Serializes to JSON as a verifier input.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct RunReport {
    /// The program name as requested.
    pub program: String,
    /// The absolute path that was executed.
    pub resolved_path: PathBuf,
    /// The argv after the program, exactly as executed (including policy-added flags).
    pub args: Vec<String>,
    /// The canonical working directory.
    pub cwd: PathBuf,
    /// Exit code, when the process exited normally.
    pub exit_code: Option<i32>,
    /// Terminating signal, when the process was killed by one.
    pub signal: Option<i32>,
    /// The wall-clock timeout fired and the process group was killed.
    pub timed_out: bool,
    /// The effective timeout, after clamping.
    pub timeout_ms: u64,
    pub duration_ms: u64,
    /// Captured stdout (lossy UTF-8), capped, with a truncation marker when cut.
    pub stdout: String,
    pub stderr: String,
    /// True byte counts the process wrote, before capping.
    pub stdout_bytes: u64,
    pub stderr_bytes: u64,
    pub stdout_truncated: bool,
    pub stderr_truncated: bool,
    /// An output pipe was still open after the drain grace (a process outside the group held
    /// it); the capture is what had arrived by then.
    pub output_incomplete: bool,
    /// Whether (and how) the run was wrapped in the OS sandbox.
    pub sandbox: SandboxSummary,
}

impl RunReport {
    /// Exited normally with code 0 and did not time out.
    pub fn passed(&self) -> bool {
        self.exit_code == Some(0) && !self.timed_out
    }

    /// The report as a JSON object, plus a derived `passed` field.
    pub fn to_json(&self) -> serde_json::Value {
        match serde_json::to_value(self) {
            Ok(mut v) => {
                if let Some(o) = v.as_object_mut() {
                    o.insert("passed".to_string(), serde_json::Value::Bool(self.passed()));
                }
                v
            }
            Err(e) => serde_json::json!({ "error": format!("report serialization failed: {e}") }),
        }
    }
}

// ------------------------------------------------------------------------------------------
// Runner
// ------------------------------------------------------------------------------------------

type CwdScope = dyn Fn(&Path) -> Result<Vec<PathBuf>, String> + Send + Sync;

/// Runs allowlisted programs under a [`ShellPolicy`]. `Send + Sync`; share it behind an `Arc`.
pub struct ShellRunner {
    policy: ShellPolicy,
    cwd_scope: Box<CwdScope>,
}

impl fmt::Debug for ShellRunner {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("ShellRunner")
            .field("policy", &self.policy)
            .finish_non_exhaustive()
    }
}

static SCRATCH_SEQ: AtomicU64 = AtomicU64::new(0);

impl ShellRunner {
    /// `cwd_check` receives the canonical cwd and returns `Err(reason)` to refuse the run. It is
    /// the seam for S2.1 folder grants and the S2.8 default-deny list.
    /// The cwd itself is the only folder a sandboxed run may write (besides the scratch HOME).
    pub fn new<F>(policy: ShellPolicy, cwd_check: F) -> Self
    where
        F: Fn(&Path) -> Result<(), String> + Send + Sync + 'static,
    {
        Self::with_scope(policy, move |cwd: &Path| {
            cwd_check(cwd).map(|()| vec![cwd.to_path_buf()])
        })
    }

    /// `cwd_scope` receives the canonical cwd and returns the folders a sandboxed run may write
    /// (for example the folder grant that covers the cwd), or `Err(reason)` to refuse. Every
    /// root must be absolute and one of them must contain the cwd.
    pub fn with_scope<F>(policy: ShellPolicy, cwd_scope: F) -> Self
    where
        F: Fn(&Path) -> Result<Vec<PathBuf>, String> + Send + Sync + 'static,
    {
        Self {
            policy,
            cwd_scope: Box::new(cwd_scope),
        }
    }

    pub fn policy(&self) -> &ShellPolicy {
        &self.policy
    }

    /// Validate everything about a request without running it (useful for an approval card).
    pub fn plan(&self, req: &RunRequest) -> Result<RunPlan, ShellError> {
        validate_program_name(&req.program)?;
        let arg_policy = self
            .policy
            .allowlist
            .policy_for(&req.program)
            .ok_or_else(|| ShellError::ProgramNotAllowed {
                program: req.program.clone(),
            })?;
        check_args(&req.program, arg_policy, &req.args)?;
        for (name, value) in &req.env {
            if !self.policy.request_env_allow.iter().any(|n| n == name) {
                return Err(ShellError::EnvRefused {
                    name: name.clone(),
                    reason: "not on the policy's request environment allowlist".to_string(),
                });
            }
            if value.contains('\0') {
                return Err(ShellError::EnvRefused {
                    name: name.clone(),
                    reason: "NUL byte in value".to_string(),
                });
            }
        }
        let (cwd, write_roots) = self.check_cwd(&req.cwd)?;
        let resolved_path = self.policy.resolve(&req.program)?;
        let read_roots = self.read_roots(&resolved_path);
        let (backend, sandbox) = match self.policy.sandbox.backend() {
            Ok(b) => {
                let summary = SandboxSummary::enforced(&b, &write_roots, &read_roots);
                (Some(b), summary)
            }
            Err(reason) => match self.policy.sandbox.mode() {
                SandboxMode::Required => return Err(ShellError::SandboxUnavailable { reason }),
                SandboxMode::Preferred | SandboxMode::Off => {
                    (None, SandboxSummary::not_enforced(&reason, &write_roots))
                }
            },
        };
        Ok(RunPlan {
            resolved_path,
            cwd,
            args: effective_args(arg_policy, &req.args),
            arg_policy: arg_policy.clone(),
            timeout: self.policy.effective_timeout(req.timeout),
            write_roots,
            read_roots,
            backend,
            sandbox,
        })
    }

    /// Directories a sandboxed run may read beyond the system set: the search path, the
    /// policy's extra roots, the program's own directory (symlinks resolved), and, for a Python
    /// virtual environment's entry point, that environment. Canonical, without repeats.
    fn read_roots(&self, program: &Path) -> Vec<PathBuf> {
        let mut out: Vec<PathBuf> = Vec::new();
        let mut add = |p: &Path| {
            if let Ok(c) = std::fs::canonicalize(p) {
                if !out.contains(&c) {
                    out.push(c);
                }
            }
        };
        for d in &self.policy.search_path {
            add(d);
        }
        for d in self.policy.sandbox.extra_read_roots() {
            add(d);
        }
        if let Ok(real) = std::fs::canonicalize(program) {
            if let Some(dir) = real.parent() {
                add(dir);
                if let Some(env) = dir.parent() {
                    if env.join("pyvenv.cfg").is_file() {
                        add(env);
                    }
                }
            }
        }
        out
    }

    fn check_cwd(&self, cwd: &Path) -> Result<(PathBuf, Vec<PathBuf>), ShellError> {
        let refuse = |reason: String| ShellError::CwdRefused {
            cwd: cwd.to_path_buf(),
            reason,
        };
        if !cwd.is_absolute() {
            return Err(refuse(
                "working directory must be an absolute path".to_string(),
            ));
        }
        let canonical =
            std::fs::canonicalize(cwd).map_err(|e| refuse(format!("cannot resolve: {e}")))?;
        if !canonical.is_dir() {
            return Err(refuse("not a directory".to_string()));
        }
        let roots = (self.cwd_scope)(&canonical).map_err(|reason| ShellError::CwdRefused {
            cwd: canonical.clone(),
            reason,
        })?;
        let mut write_roots = Vec::with_capacity(roots.len());
        for r in roots {
            if !r.is_absolute() {
                return Err(ShellError::CwdRefused {
                    cwd: canonical,
                    reason: format!("write root {} is not absolute", r.display()),
                });
            }
            let c = std::fs::canonicalize(&r).map_err(|e| ShellError::CwdRefused {
                cwd: canonical.clone(),
                reason: format!("write root {} cannot be resolved: {e}", r.display()),
            })?;
            if !write_roots.contains(&c) {
                write_roots.push(c);
            }
        }
        if !write_roots.iter().any(|r| canonical.starts_with(r)) {
            return Err(ShellError::CwdRefused {
                cwd: canonical,
                reason: "the working directory is not inside the folders this run may write"
                    .to_string(),
            });
        }
        Ok((canonical, write_roots))
    }

    /// Run one request to completion (or timeout). Blocking.
    pub fn run(&self, req: &RunRequest) -> Result<RunReport, ShellError> {
        let plan = self.plan(req)?;

        let scratch = ScratchDir::create().map_err(|e| ShellError::Spawn {
            program: req.program.clone(),
            reason: format!("cannot create scratch HOME: {e}"),
        })?;

        let mut cmd = match &plan.backend {
            Some(backend) => {
                // Seatbelt matches real paths (`/var` is `/private/var` on macOS).
                let scratch_real =
                    std::fs::canonicalize(scratch.path()).map_err(|e| ShellError::Spawn {
                        program: req.program.clone(),
                        reason: format!("cannot resolve the scratch HOME: {e}"),
                    })?;
                let spec = SandboxSpec {
                    write_roots: plan.write_roots.clone(),
                    read_roots: plan.read_roots.clone(),
                    scratch: scratch_real,
                    cwd: plan.cwd.clone(),
                    masked_files: sandbox::env_files(&plan.write_roots),
                };
                sandbox::wrap(backend, &spec, &plan.resolved_path, &plan.args)
            }
            None => {
                let mut c = Command::new(&plan.resolved_path);
                c.args(&plan.args);
                c
            }
        };
        cmd.current_dir(&plan.cwd)
            .env_clear()
            .env("PATH", join_search_path(&self.policy.search_path))
            .env("HOME", scratch.path())
            .env("TMPDIR", scratch.path())
            .env("NO_COLOR", "1")
            .stdin(Stdio::null())
            .stdout(Stdio::piped())
            .stderr(Stdio::piped())
            // Leader of a new process group, so a timeout can kill everything it started.
            .process_group(0);
        for name in &self.policy.passthrough_env {
            if let Some(v) = std::env::var_os(name) {
                cmd.env(name, v);
            }
        }
        for (k, v) in policy_env(&plan.arg_policy) {
            cmd.env(k, v);
        }
        for (k, v) in &req.env {
            cmd.env(k, v);
        }

        let started = Instant::now();
        let mut child = cmd.spawn().map_err(|e| ShellError::Spawn {
            program: req.program.clone(),
            reason: e.to_string(),
        })?;
        let pgid = libc::pid_t::try_from(child.id()).unwrap_or(0);

        let out = Capture::spawn_reader(child.stdout.take(), self.policy.stdout_cap);
        let err = Capture::spawn_reader(child.stderr.take(), self.policy.stderr_cap);

        let (status, timed_out) = wait_with_deadline(&mut child, pgid, started + plan.timeout);
        // Reap anything the leader left behind in its group. (A group id is not reused while
        // any member is alive; when none is left this is a no-op.)
        kill_group(pgid);
        let duration = started.elapsed();

        let drain_deadline = Instant::now() + DRAIN_GRACE;
        let out = out.finish(drain_deadline);
        let err = err.finish(drain_deadline);

        let (exit_code, signal) = match status {
            Some(s) => (s.code(), s.signal()),
            None => (None, None),
        };

        Ok(RunReport {
            program: req.program.clone(),
            resolved_path: plan.resolved_path,
            args: plan.args,
            cwd: plan.cwd,
            exit_code,
            signal,
            timed_out,
            timeout_ms: duration_ms(plan.timeout),
            duration_ms: duration_ms(duration),
            stdout: out.text,
            stderr: err.text,
            stdout_bytes: out.total,
            stderr_bytes: err.total,
            stdout_truncated: out.truncated,
            stderr_truncated: err.truncated,
            output_incomplete: !(out.reached_eof && err.reached_eof),
            sandbox: plan.sandbox,
        })
    }
}

/// A fully validated request: what would run, where, and for how long.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RunPlan {
    pub resolved_path: PathBuf,
    pub cwd: PathBuf,
    /// The argv after the program, including policy-added flags.
    pub args: Vec<String>,
    pub arg_policy: ArgPolicy,
    pub timeout: Duration,
    /// Folders a sandboxed run may write (canonical; one of them holds the cwd).
    pub write_roots: Vec<PathBuf>,
    /// Directories beyond the system set a sandboxed run may read (canonical).
    pub read_roots: Vec<PathBuf>,
    /// The sandbox backend the run will use; `None` when it runs without one.
    pub backend: Option<Backend>,
    /// What the member is shown about the sandbox.
    pub sandbox: SandboxSummary,
}

fn duration_ms(d: Duration) -> u64 {
    u64::try_from(d.as_millis()).unwrap_or(u64::MAX)
}

fn join_search_path(dirs: &[PathBuf]) -> String {
    dirs.iter()
        .map(|d| d.to_string_lossy().into_owned())
        .collect::<Vec<_>>()
        .join(":")
}

fn kill_group(pgid: libc::pid_t) {
    if pgid > 0 {
        // SAFETY: kill(2) with a negative pid signals a process group; it has no memory
        // effects on this process. An error (no such group) is expected and ignored.
        unsafe {
            libc::kill(-pgid, libc::SIGKILL);
        }
    }
}

/// Poll the child until it exits or the deadline passes; on deadline kill the whole group and
/// reap the leader. Returns `(status, timed_out)`; status is `None` only if waiting failed.
fn wait_with_deadline(
    child: &mut Child,
    pgid: libc::pid_t,
    deadline: Instant,
) -> (Option<std::process::ExitStatus>, bool) {
    let mut sleep = Duration::from_millis(2);
    loop {
        match child.try_wait() {
            Ok(Some(s)) => return (Some(s), false),
            Ok(None) => {}
            Err(_) => {
                kill_group(pgid);
                return (child.wait().ok(), false);
            }
        }
        let now = Instant::now();
        if now >= deadline {
            kill_group(pgid);
            return (child.wait().ok(), true);
        }
        std::thread::sleep(sleep.min(deadline - now));
        sleep = (sleep * 2).min(Duration::from_millis(25));
    }
}

// ------------------------------------------------------------------------------------------
// Output capture
// ------------------------------------------------------------------------------------------

#[derive(Default)]
struct CaptureState {
    kept: Vec<u8>,
    total: u64,
}

struct Capture {
    state: Arc<Mutex<CaptureState>>,
    done: Option<mpsc::Receiver<()>>,
}

struct Captured {
    text: String,
    total: u64,
    truncated: bool,
    reached_eof: bool,
}

impl Capture {
    fn spawn_reader<R: Read + Send + 'static>(pipe: Option<R>, cap: usize) -> Self {
        let state = Arc::new(Mutex::new(CaptureState::default()));
        let Some(mut pipe) = pipe else {
            return Self { state, done: None };
        };
        let (tx, rx) = mpsc::channel();
        let shared = Arc::clone(&state);
        std::thread::spawn(move || {
            let mut buf = [0u8; 8192];
            loop {
                match pipe.read(&mut buf) {
                    Ok(0) => break,
                    Ok(n) => {
                        let mut s = shared.lock().unwrap_or_else(|p| p.into_inner());
                        s.total += n as u64;
                        let room = cap.saturating_sub(s.kept.len());
                        let take = room.min(n);
                        s.kept.extend_from_slice(&buf[..take]);
                    }
                    Err(e) if e.kind() == std::io::ErrorKind::Interrupted => continue,
                    Err(_) => break,
                }
            }
            let _ = tx.send(());
        });
        Self {
            state,
            done: Some(rx),
        }
    }

    /// Wait (until `deadline`) for EOF, then render what was kept.
    fn finish(self, deadline: Instant) -> Captured {
        let reached_eof = match &self.done {
            None => true,
            Some(rx) => rx
                .recv_timeout(deadline.saturating_duration_since(Instant::now()))
                .is_ok(),
        };
        let s = self.state.lock().unwrap_or_else(|p| p.into_inner());
        let truncated = s.total > s.kept.len() as u64;
        let text = if truncated {
            let omitted = s.total.saturating_sub(s.kept.len() as u64);
            format!(
                "{}\n[truncated: {omitted} bytes omitted]",
                lossy_prefix(&s.kept)
            )
        } else {
            String::from_utf8_lossy(&s.kept).into_owned()
        };
        Captured {
            text,
            total: s.total,
            truncated,
            reached_eof,
        }
    }
}

/// Lossy UTF-8 of a capped prefix: a multi-byte character cut in half by the cap is dropped
/// rather than rendered as a replacement character.
fn lossy_prefix(bytes: &[u8]) -> String {
    let end = bytes.len();
    let mut start = end;
    while start > 0 && end - start < 3 && (bytes[start - 1] & 0xC0) == 0x80 {
        start -= 1;
    }
    let mut keep = end;
    if start > 0 {
        let need = match bytes[start - 1] {
            0xF0..=0xFF => 4,
            0xE0..=0xEF => 3,
            0xC0..=0xDF => 2,
            _ => 1,
        };
        if need > 1 && end - (start - 1) < need {
            keep = start - 1;
        }
    }
    String::from_utf8_lossy(&bytes[..keep]).into_owned()
}

// ------------------------------------------------------------------------------------------
// Scratch HOME
// ------------------------------------------------------------------------------------------

/// A fresh, private (0700) directory per run, removed on drop.
struct ScratchDir(PathBuf);

impl ScratchDir {
    fn create() -> std::io::Result<Self> {
        let nanos = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map(|d| d.subsec_nanos())
            .unwrap_or(0);
        let p = std::env::temp_dir().join(format!(
            "citrate-shell-{}-{}-{nanos}",
            std::process::id(),
            SCRATCH_SEQ.fetch_add(1, Ordering::Relaxed)
        ));
        std::fs::DirBuilder::new().mode(0o700).create(&p)?;
        Ok(Self(p))
    }

    fn path(&self) -> &Path {
        &self.0
    }
}

impl Drop for ScratchDir {
    fn drop(&mut self) {
        let _ = std::fs::remove_dir_all(&self.0);
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn lossy_prefix_drops_a_split_trailing_char() {
        let s = "héllo".as_bytes();
        // Cut inside the two-byte 'é'.
        assert_eq!(lossy_prefix(&s[..2]), "h");
        assert_eq!(lossy_prefix(s), "héllo");
        let e = "a€".as_bytes(); // '€' is three bytes
        assert_eq!(lossy_prefix(&e[..3]), "a");
        assert_eq!(lossy_prefix(e), "a€");
    }

    #[test]
    fn git_diff_family_gets_no_external_helpers() {
        let args = vec!["diff".to_string(), "HEAD~1".to_string()];
        assert_eq!(
            effective_args(&ArgPolicy::GitReadOnly, &args),
            vec!["diff", "--no-ext-diff", "--no-textconv", "HEAD~1"]
        );
        let args = vec!["status".to_string()];
        assert_eq!(
            effective_args(&ArgPolicy::GitReadOnly, &args),
            vec!["status"]
        );
        assert_eq!(effective_args(&ArgPolicy::Any, &args), vec!["status"]);
    }

    #[test]
    fn reserved_env_names_cannot_be_allowed_for_requests() {
        let p = ShellPolicy::new(Allowlist::empty(), ShellPolicy::default_search_path())
            .expect("policy")
            .with_request_env_allow(&["PATH", "HOME", "FOUNDRY_PROFILE"]);
        assert_eq!(p.request_env_allow, vec!["FOUNDRY_PROFILE".to_string()]);
    }

    #[test]
    fn error_kinds_are_stable() {
        let e = ShellError::ProgramNotAllowed {
            program: "rm".into(),
        };
        assert_eq!(e.kind(), "program_not_allowed");
        assert!(e.to_string().contains("not on the shell allowlist"));
    }

    #[test]
    fn plan_reports_without_running() {
        let d = std::env::temp_dir();
        let r = ShellRunner::new(
            ShellPolicy::new(Allowlist::hello_mint(), vec![PathBuf::from("/usr/bin")])
                .expect("policy")
                .with_max_timeout(Duration::from_secs(5)),
            |_p: &Path| Ok(()),
        );
        let plan = r
            .plan(&RunRequest::new("git", vec!["log".into()], &d).timeout(Duration::from_secs(60)))
            .expect("plan");
        assert_eq!(plan.resolved_path, PathBuf::from("/usr/bin/git"));
        assert_eq!(plan.args, vec!["log", "--no-ext-diff", "--no-textconv"]);
        assert_eq!(plan.timeout, Duration::from_secs(5));
    }
}
