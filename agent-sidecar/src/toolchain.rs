//! HUP-S6.3 — the dApp-forge toolchain as sidecar-hosted session tools.
//!
//! Four tools, registered in every session only when `CITRATE_HERMES_TOOLCHAIN=1` (default off):
//!
//! | tool           | program | fixed argv                                                       | verdict                    |
//! |----------------|---------|------------------------------------------------------------------|----------------------------|
//! | `forge_test`   | forge   | `test --json [--match-test T] [--match-contract C]`              | all tests pass             |
//! | `slither_scan` | slither | `. --sarif - --exclude-dependencies --disable-color --compile-force-framework foundry` | no finding ≥ `fail_on` |
//! | `aderyn_scan`  | aderyn  | `. --output aderyn-report.sarif --stdout --skip-update-check`    | no finding ≥ `fail_on`     |
//! | `medusa_fuzz`  | medusa  | `fuzz --no-color --test-limit N --timeout S`                     | no failed property/assert  |
//!
//! Each call runs through `citrate-agent-shell` (allowlisted bare names resolved from a fixed
//! search path, argv only, scrubbed env with a scratch HOME, process-group timeout, capped
//! capture), and its output is judged by the `citrate-agent-loop` toolchain verifiers
//! (`verifiers_tooling`). The tool result is a `ToolchainEnvelope`: status, a one-line summary,
//! the verdict with its evidence counts, run facts, and (for a build that produced no report)
//! sanitized compiler error headers. The model chooses only the project folder and a few
//! validated options; it never supplies argv, env, or a program name.
//!
//! **Where it may run.** The project must resolve (symlinks followed) inside one of the granted
//! folders in `CITRATE_HERMES_TOOLCHAIN_ROOTS`, and pass the agent-guard default-deny list.
//! With no granted folder every call is refused. This env list is the interim seam for a session
//! opened without a grant document. HUP-S2.1: a session opened with the member's grants (sent by
//! citrate-core) ignores the env list; its project must be covered by live read **and** write
//! folder grants (see [`crate::grants`]), checked again at every call.
//!
//! **Network.** Every run gets `FOUNDRY_OFFLINE=true`, so forge (and the forge build slither
//! starts) never downloads a compiler. The compiler comes from `CITRATE_HERMES_SOLC`, else the
//! pinned solc 0.8.36 in the per-user svm directory when it is there; without either a build
//! fails with forge's own "can't install missing solc in offline mode" error.
//!
//! **Project configuration.** Before a run, the project's build configuration is checked
//! ([`crate::toolchain_config`]): a project that turns on `ffi`, sets `fs_permissions` beyond
//! reading inside the project, names a compiler by path, or holds env files or other build
//! front-end configs is refused with the reason, and nothing runs.
//!
//! **OS sandbox (US-2.2 AC1).** When the machine has a working OS sandbox (macOS Seatbelt, Linux
//! bubblewrap) every run goes through it: no network, writes only in the project folder and the
//! scratch HOME, reads limited to those, the system and the toolchain directories. Without one
//! the runs behave as before and the run facts say `sandbox.enforced: false`.
//! `CITRATE_HERMES_SHELL_SANDBOX` = `preferred` (default), `required` (refuse when no sandbox
//! works here) or `off`; any other value is treated as `required`.
//!
//! **Honest scope.** These are fixed argv templates, but the programs execute project code by
//! design (forge tests in the EVM, compilation); the OS sandbox bounds what that code can reach.
//! A session stop or the e-stop does not interrupt a run in progress; the wall-clock timeout
//! bounds it. aderyn and medusa are
//! often not installed: the tools then say so and their verifiers fail, never pass. This module
//! never holds a key and never signs (Rule 3).
//!
//! **Deploy gate hand-over (retro A27).** The verdict in each envelope drives workflow steps only.
//! A completed run also carries its raw report ([`GateReport`]: stdout, the project's source
//! digest before and after, forge's built bytecode digests, medusa's call budget and lcov). The
//! session takes it out of the result before the model sees it
//! ([`crate::toolchain_reports::CapturingToolchain`]); core reads it back and its deploy gate,
//! the one source of truth for a deploy verdict, parses the raw report itself. Without an
//! explicit `test_limit`, `medusa_fuzz` uses the tier budget the template renderer recorded in
//! the project's `citrate-template.lock.json` (HUP-S6.9).

use std::path::{Path, PathBuf};
use std::sync::Arc;
use std::time::Duration;

use crate::grants::SessionGrants;
use citrate_agent_guard::{check_path, GuardContext};
use citrate_agent_loop::verifiers_tooling::{
    compiler_diagnostics, verify_forge_test_output, verify_medusa_output, verify_sarif_output,
    GateReport, RunStatus, SarifProfile, Severity, ToolchainEnvelope, ADERYN_SCAN_TOOL,
    FORGE_TEST_TOOL, MEDUSA_FUZZ_TOOL, SLITHER_SCAN_TOOL,
};
use citrate_agent_loop::{
    Effect, HostKind, ToolAnnotations, ToolCall, ToolHost, ToolOutcome, ToolSpec, Trust,
};
use citrate_agent_shell::sandbox::{SandboxMode, SandboxPolicy};
use citrate_agent_shell::{
    Allowlist, ArgPolicy, RunReport, RunRequest, ShellError, ShellPolicy, ShellRunner,
};

/// `1` turns the toolchain tools on; anything else (or unset) leaves them off.
pub const TOOLCHAIN_ENV: &str = "CITRATE_HERMES_TOOLCHAIN";
/// Granted project folders, a platform path list. Unset = nothing granted.
pub const TOOLCHAIN_ROOTS_ENV: &str = "CITRATE_HERMES_TOOLCHAIN_ROOTS";
/// The toolchain search path (absolute dirs, a platform path list). Unset = the system dirs
/// plus the per-user Foundry, pipx, cargo and Go bin dirs.
pub const TOOLCHAIN_PATH_ENV: &str = "CITRATE_HERMES_TOOLCHAIN_PATH";
/// Absolute path of the solc binary forge should use (`FOUNDRY_SOLC`).
pub const SOLC_ENV: &str = "CITRATE_HERMES_SOLC";
/// The OS sandbox mode for the toolchain (and any other agent-shell run the sidecar makes):
/// `preferred` (default), `required`, or `off`. Anything else is `required` (fail closed).
pub const SANDBOX_ENV: &str = "CITRATE_HERMES_SHELL_SANDBOX";
/// The chain's pinned compiler version (looked up in the per-user svm dir by default).
pub const PINNED_SOLC: &str = "0.8.36";

/// The tool names this module owns (reserved in sessions while it is on).
pub const TOOL_NAMES: [&str; 4] = [
    FORGE_TEST_TOOL,
    SLITHER_SCAN_TOOL,
    ADERYN_SCAN_TOOL,
    MEDUSA_FUZZ_TOOL,
];

const DEFAULT_TIMEOUT_SECS: u64 = 300;
const MAX_TIMEOUT_SECS: u64 = 900;
const DEFAULT_MEDUSA_TIMEOUT_SECS: u64 = 600;
/// Extra wall-clock time a medusa run gets past its own `--timeout` to print its summary.
const MEDUSA_GRACE_SECS: u64 = 60;
/// HUP-S1.9: the longest a single toolchain run may take (the wall-clock cap plus medusa's grace);
/// the worker call timeout is set above it.
pub const LONGEST_RUN_SECS: u64 = MAX_TIMEOUT_SECS + MEDUSA_GRACE_SECS;
/// Planset item 10: a call budget, not wall-clock minutes.
const DEFAULT_MEDUSA_TEST_LIMIT: u64 = 50_000;
const MAX_MEDUSA_TEST_LIMIT: u64 = 1_000_000;
/// SARIF from a real project easily exceeds the shell's 64 KiB default.
const OUTPUT_CAP: usize = 4 * 1024 * 1024;
const STDERR_CAP: usize = 256 * 1024;
const MAX_DIAGNOSTICS: usize = 12;

/// Where and with what the toolchain runs.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ToolchainConfig {
    /// Granted project folders (canonical).
    pub roots: Vec<PathBuf>,
    /// Absolute directories programs are resolved from, in order.
    pub search_path: Vec<PathBuf>,
    /// The solc binary handed to forge as `FOUNDRY_SOLC`.
    pub solc: Option<PathBuf>,
    /// The member's home (for the default-deny list).
    pub home: PathBuf,
    /// Whether runs go through the OS sandbox.
    pub sandbox: SandboxMode,
}

/// [`SANDBOX_ENV`] read with `get`: unset or empty is `default`, junk is `Required`.
pub fn sandbox_mode_from(
    get: &impl Fn(&str) -> Option<String>,
    default: SandboxMode,
) -> SandboxMode {
    match get(SANDBOX_ENV) {
        Some(v) if !v.trim().is_empty() => SandboxMode::parse(&v).unwrap_or(SandboxMode::Required),
        _ => default,
    }
}

fn split_abs(value: &str) -> Vec<PathBuf> {
    std::env::split_paths(value)
        .filter(|p| !p.as_os_str().is_empty() && p.is_absolute())
        .collect()
}

impl ToolchainConfig {
    /// `None` unless `CITRATE_HERMES_TOOLCHAIN` is exactly `1` and a home directory is known.
    /// Relative or missing roots are dropped (never resolved against the sidecar's cwd).
    pub fn from_env_vars(get: impl Fn(&str) -> Option<String>) -> Option<Self> {
        if get(TOOLCHAIN_ENV).as_deref() != Some("1") {
            return None;
        }
        let home = PathBuf::from(get("HOME").filter(|h| !h.is_empty())?);
        let roots = get(TOOLCHAIN_ROOTS_ENV)
            .map(|v| {
                split_abs(&v)
                    .into_iter()
                    .filter_map(|p| p.canonicalize().ok())
                    .filter(|p| p.is_dir())
                    .collect()
            })
            .unwrap_or_default();
        let search_path = match get(TOOLCHAIN_PATH_ENV).map(|v| split_abs(&v)) {
            Some(p) if !p.is_empty() => p,
            _ => {
                let mut p = ShellPolicy::default_search_path();
                for d in [".foundry/bin", ".local/bin", ".cargo/bin", "go/bin"] {
                    p.push(home.join(d));
                }
                p
            }
        };
        let solc = match get(SOLC_ENV) {
            Some(v) if !v.is_empty() => Some(PathBuf::from(v)).filter(|p| p.is_absolute()),
            _ => [
                home.join("Library/Application Support/svm"),
                home.join(".svm"),
                home.join(".local/share/svm"),
            ]
            .into_iter()
            .map(|d| d.join(PINNED_SOLC).join(format!("solc-{PINNED_SOLC}")))
            .find(|p| p.is_file()),
        };
        let sandbox = sandbox_mode_from(&get, SandboxMode::Preferred);
        Some(ToolchainConfig {
            roots,
            search_path,
            solc,
            home,
            sandbox,
        })
    }

    /// [`ToolchainConfig::from_env_vars`] over the process environment.
    pub fn from_env() -> Option<Self> {
        Self::from_env_vars(|k| std::env::var(k).ok())
    }
}

/// Runs the toolchain tools for a session's sidecar host.
pub struct ToolchainHost {
    runner: ShellRunner,
    cfg: ToolchainConfig,
    /// HUP-S2.1: the session's folder grants. When present they replace `cfg.roots`.
    grants: Option<Arc<SessionGrants>>,
    stdout_cap: usize,
}

impl std::fmt::Debug for ToolchainHost {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("ToolchainHost")
            .field("cfg", &self.cfg)
            .finish_non_exhaustive()
    }
}

/// The cwd check: inside a granted root, and not on the default-deny list.
fn check_project(roots: &[PathBuf], home: &Path, cwd: &Path) -> Result<(), String> {
    if roots.is_empty() {
        return Err("no project folder is granted to the toolchain".into());
    }
    let Some(root) = roots.iter().find(|r| cwd.starts_with(r)) else {
        return Err("the project is not inside a folder granted to the toolchain".into());
    };
    let ctx = GuardContext::new(home, cwd).with_project_root(root);
    check_path(cwd, &ctx).map(|_| ()).map_err(|d| d.to_string())
}

fn build_runner(
    cfg: &ToolchainConfig,
    grants: Option<Arc<SessionGrants>>,
    stdout_cap: usize,
) -> Result<ShellRunner, String> {
    let allow = Allowlist::empty()
        .allow("forge", ArgPolicy::Any)
        .allow("slither", ArgPolicy::Any)
        .allow("aderyn", ArgPolicy::Any)
        .allow("medusa", ArgPolicy::Any);
    let policy = ShellPolicy::new(allow, cfg.search_path.clone())
        .map_err(|e| e.to_string())?
        .with_request_env_allow(&["FOUNDRY_OFFLINE", "FOUNDRY_SOLC"])
        .with_default_timeout(Duration::from_secs(DEFAULT_TIMEOUT_SECS))
        .with_max_timeout(Duration::from_secs(MAX_TIMEOUT_SECS + MEDUSA_GRACE_SECS))
        .with_output_caps(stdout_cap, STDERR_CAP)
        .with_sandbox(
            SandboxPolicy::new(cfg.sandbox).with_extra_read_roots(
                cfg.solc
                    .iter()
                    .filter_map(|p| p.parent().map(Path::to_path_buf))
                    .collect(),
            ),
        );
    if let Some(g) = grants {
        return Ok(ShellRunner::new(policy, move |cwd: &Path| {
            g.check_project(cwd).map(|_| ())
        }));
    }
    let roots = cfg.roots.clone();
    let home = cfg.home.clone();
    Ok(ShellRunner::new(policy, move |cwd: &Path| {
        check_project(&roots, &home, cwd)
    }))
}

impl ToolchainHost {
    /// Fails only on a malformed search path (for example a relative entry).
    pub fn new(cfg: ToolchainConfig) -> Result<Self, String> {
        Ok(ToolchainHost {
            runner: build_runner(&cfg, None, OUTPUT_CAP)?,
            cfg,
            grants: None,
            stdout_cap: OUTPUT_CAP,
        })
    }

    /// The same host with a different stdout capture cap in bytes.
    pub fn with_output_cap(self, bytes: usize) -> Result<Self, String> {
        Ok(ToolchainHost {
            runner: build_runner(&self.cfg, self.grants.clone(), bytes)?,
            cfg: self.cfg,
            grants: self.grants,
            stdout_cap: bytes,
        })
    }

    /// HUP-S2.1: a host for one session whose project folder is checked against that session's
    /// folder grants (read and write) instead of `CITRATE_HERMES_TOOLCHAIN_ROOTS`.
    pub fn for_grants(&self, grants: Arc<SessionGrants>) -> Result<Self, String> {
        Ok(ToolchainHost {
            runner: build_runner(&self.cfg, Some(grants.clone()), self.stdout_cap)?,
            cfg: self.cfg.clone(),
            grants: Some(grants),
            stdout_cap: self.stdout_cap,
        })
    }

    /// Whether `name` is one of the toolchain tools.
    pub fn handles(name: &str) -> bool {
        TOOL_NAMES.contains(&name)
    }

    /// The tool specs offered to the model.
    pub fn specs() -> Vec<ToolSpec> {
        let project = serde_json::json!({
            "type": "string",
            "description": "Absolute path of the Foundry project folder (inside a folder the member granted)."
        });
        let timeout = |default: u64| {
            serde_json::json!({
                "type": "integer", "minimum": 1, "maximum": MAX_TIMEOUT_SECS,
                "description": format!("Wall-clock limit in seconds (default {default}).")
            })
        };
        let fail_on = serde_json::json!({
            "type": "string", "enum": ["critical", "high", "medium", "low", "info"],
            "description": "Fail when any finding is at or above this severity (default high)."
        });
        let filter = |what: &str| {
            serde_json::json!({
                "type": "string", "pattern": "^[A-Za-z0-9_]{1,64}$",
                "description": format!("Only run {what} whose name matches (letters, digits, underscore).")
            })
        };
        let annotations = ToolAnnotations {
            read_only: false,
            destructive: false,
            idempotent: true,
            open_world: false,
            // Builds write out/ and cache/ under the project.
            effect: Some(Effect::Write),
            // The result is a structured report built here; tool free text is not passed on.
            trust: Some(Trust::Trusted),
        };
        let spec = |name: &str, description: &str, props: serde_json::Value| ToolSpec {
            name: name.into(),
            description: description.into(),
            parameters: serde_json::json!({
                "type": "object",
                "properties": props,
                "required": ["project"],
            }),
            host: HostKind::Sidecar,
            annotations: annotations.clone(),
        };
        vec![
            spec(
                FORGE_TEST_TOOL,
                "Run forge test on a Foundry project and report how many tests passed and failed. The result comes from forge's JSON report, not from reading the code.",
                serde_json::json!({
                    "project": project,
                    "match_test": filter("tests"),
                    "match_contract": filter("test contracts"),
                    "timeout_secs": timeout(DEFAULT_TIMEOUT_SECS),
                }),
            ),
            spec(
                SLITHER_SCAN_TOOL,
                "Run the slither static analyzer on a Foundry project and report findings by severity (SARIF). Fails when a finding is at or above fail_on.",
                serde_json::json!({
                    "project": project,
                    "fail_on": fail_on,
                    "timeout_secs": timeout(DEFAULT_TIMEOUT_SECS),
                }),
            ),
            spec(
                ADERYN_SCAN_TOOL,
                "Run the aderyn static analyzer on a Foundry project and report findings by severity (SARIF). Reports 'not installed' when aderyn is absent.",
                serde_json::json!({
                    "project": project,
                    "fail_on": fail_on,
                    "timeout_secs": timeout(DEFAULT_TIMEOUT_SECS),
                }),
            ),
            spec(
                MEDUSA_FUZZ_TOOL,
                "Fuzz a Foundry project's property and assertion tests with medusa within a call budget and report passed and failed tests. Reports 'not installed' when medusa is absent.",
                serde_json::json!({
                    "project": project,
                    "test_limit": {
                        "type": "integer", "minimum": 1, "maximum": MAX_MEDUSA_TEST_LIMIT,
                        "description": format!("Call budget (default: the tier budget recorded in the project's {}, else {DEFAULT_MEDUSA_TEST_LIMIT}).", crate::toolchain_reports::TEMPLATE_LOCK_FILE)
                    },
                    "timeout_secs": timeout(DEFAULT_MEDUSA_TIMEOUT_SECS),
                }),
            ),
        ]
    }

    fn run_call(&self, call: &ToolCall) -> ToolOutcome {
        let tool = call.name.as_str();
        let refuse = |why: String| {
            ToolOutcome::Error(
                ToolchainEnvelope::not_run(tool, RunStatus::Refused, why).to_content(),
            )
        };
        let args = match parse_args(&call.arguments) {
            Ok(a) => a,
            Err(e) => return refuse(e),
        };
        let project = match args.get("project") {
            Some(serde_json::Value::String(p)) if !p.trim().is_empty() => PathBuf::from(p),
            Some(_) | None => {
                return refuse(
                    "project (the absolute path of the project folder) is required".into(),
                )
            }
        };
        if !project.is_absolute() {
            return refuse("project must be an absolute path inside a granted folder".into());
        }
        let project = match &self.grants {
            // Run in the canonical folder the grants resolved; the runner checks it again.
            Some(g) => match g.check_project(&project) {
                Ok(canonical) => canonical,
                Err(e) => return refuse(e),
            },
            None if self.cfg.roots.is_empty() => {
                return refuse("no project folder is granted to the toolchain".into())
            }
            None => project,
        };
        if let Err(e) = crate::toolchain_config::check_project_config(&project) {
            return refuse(e);
        }
        let plan = match plan_call(tool, &args, &project) {
            Ok(p) => p,
            Err(e) => return refuse(e),
        };
        let mut req = RunRequest::new(plan.program, plan.argv.clone(), &project)
            .timeout(Duration::from_secs(plan.wall_secs))
            .env("FOUNDRY_OFFLINE", "true");
        if let Some(solc) = &self.cfg.solc {
            req = req.env("FOUNDRY_SOLC", &solc.to_string_lossy());
        }
        // HUP-S6.3 → S6.4: bind the run to the project's sources, taken before and after.
        let started = std::time::SystemTime::now();
        let sources_before = crate::toolchain_reports::sources_sha256(&project);
        match self.runner.run(&req) {
            Ok(report) => {
                let sources_after = crate::toolchain_reports::sources_sha256(&project);
                let ctx = RunContext {
                    project: &project,
                    started,
                    sources: sources_before.filter(|b| Some(b) == sources_after.as_ref()),
                };
                judge_run(tool, &plan, &report, &ctx)
            }
            Err(e) => {
                let (status, summary) = match &e {
                    ShellError::ProgramNotFound { program, search_path } => (
                        RunStatus::NotInstalled,
                        format!(
                            "{program} is not installed on this machine (looked in {} toolchain directories)",
                            search_path.len()
                        ),
                    ),
                    ShellError::Spawn { .. } => (RunStatus::Failed, e.to_string()),
                    _ => (RunStatus::Refused, e.to_string()),
                };
                ToolOutcome::Error(ToolchainEnvelope::not_run(tool, status, summary).to_content())
            }
        }
    }
}

impl ToolHost for ToolchainHost {
    fn execute(&self, call: &ToolCall) -> ToolOutcome {
        if !Self::handles(&call.name) {
            return ToolOutcome::Error(format!("'{}' is not a toolchain tool", call.name));
        }
        self.run_call(call)
    }
}

type Args = serde_json::Map<String, serde_json::Value>;

fn parse_args(raw: &str) -> Result<Args, String> {
    let raw = if raw.trim().is_empty() { "{}" } else { raw };
    match serde_json::from_str::<serde_json::Value>(raw) {
        Ok(serde_json::Value::Object(m)) => Ok(m),
        Ok(_) => Err("the arguments must be a JSON object".into()),
        Err(_) => Err("the arguments are not valid JSON".into()),
    }
}

/// An optional bounded integer argument.
fn int_arg(args: &Args, key: &str, default: u64, max: u64) -> Result<u64, String> {
    match args.get(key) {
        None | Some(serde_json::Value::Null) => Ok(default),
        Some(v) => match v.as_u64() {
            Some(n) if (1..=max).contains(&n) => Ok(n),
            _ => Err(format!("{key} must be a whole number from 1 to {max}")),
        },
    }
}

/// An optional forge name filter: `[A-Za-z0-9_]{1,64}` only (it is a regex to forge).
fn filter_arg(args: &Args, key: &str) -> Result<Option<String>, String> {
    match args.get(key) {
        None | Some(serde_json::Value::Null) => Ok(None),
        Some(serde_json::Value::String(s))
            if (1..=64).contains(&s.len())
                && s.chars().all(|c| c.is_ascii_alphanumeric() || c == '_') =>
        {
            Ok(Some(s.clone()))
        }
        Some(_) => Err(format!(
            "{key} may only contain letters, digits and underscores (1 to 64 characters)"
        )),
    }
}

fn severity_arg(args: &Args) -> Result<Severity, String> {
    match args.get("fail_on") {
        None | Some(serde_json::Value::Null) => Ok(Severity::High),
        Some(serde_json::Value::String(s)) => Severity::parse(s)
            .ok_or_else(|| "fail_on must be one of critical, high, medium, low, info".to_string()),
        Some(_) => Err("fail_on must be one of critical, high, medium, low, info".into()),
    }
}

/// What to run for one call.
#[derive(Debug, Clone)]
struct CallPlan {
    program: &'static str,
    argv: Vec<String>,
    wall_secs: u64,
    threshold: Severity,
    /// medusa: the call budget passed as `--test-limit`.
    test_limit: Option<u64>,
}

/// Where a finished run happened, for its gate report.
struct RunContext<'a> {
    project: &'a Path,
    started: std::time::SystemTime,
    /// The project's source digest when it was the same before and after the run.
    sources: Option<String>,
}

fn plan_call(tool: &str, args: &Args, project: &Path) -> Result<CallPlan, String> {
    let s = |v: &[&str]| v.iter().map(|x| x.to_string()).collect::<Vec<_>>();
    match tool {
        FORGE_TEST_TOOL => {
            let mut argv = s(&["test", "--json"]);
            if let Some(t) = filter_arg(args, "match_test")? {
                argv.extend(["--match-test".to_string(), t]);
            }
            if let Some(c) = filter_arg(args, "match_contract")? {
                argv.extend(["--match-contract".to_string(), c]);
            }
            Ok(CallPlan {
                program: "forge",
                argv,
                wall_secs: int_arg(args, "timeout_secs", DEFAULT_TIMEOUT_SECS, MAX_TIMEOUT_SECS)?,
                threshold: Severity::High,
                test_limit: None,
            })
        }
        SLITHER_SCAN_TOOL => Ok(CallPlan {
            program: "slither",
            argv: s(&[
                ".",
                "--sarif",
                "-",
                "--exclude-dependencies",
                "--disable-color",
                "--compile-force-framework",
                "foundry",
            ]),
            threshold: severity_arg(args)?,
            wall_secs: int_arg(args, "timeout_secs", DEFAULT_TIMEOUT_SECS, MAX_TIMEOUT_SECS)?,
            test_limit: None,
        }),
        ADERYN_SCAN_TOOL => Ok(CallPlan {
            program: "aderyn",
            argv: s(&[
                ".",
                "--output",
                "aderyn-report.sarif",
                "--stdout",
                "--skip-update-check",
            ]),
            threshold: severity_arg(args)?,
            wall_secs: int_arg(args, "timeout_secs", DEFAULT_TIMEOUT_SECS, MAX_TIMEOUT_SECS)?,
            test_limit: None,
        }),
        MEDUSA_FUZZ_TOOL => {
            // HUP-S6.9: without an explicit test_limit, the tier budget the template renderer
            // recorded for this project; the deploy gate in core enforces the tier budget itself.
            let default_limit = crate::toolchain_reports::lock_test_limit(project)
                .filter(|l| (1..=MAX_MEDUSA_TEST_LIMIT).contains(l))
                .unwrap_or(DEFAULT_MEDUSA_TEST_LIMIT);
            let limit = int_arg(args, "test_limit", default_limit, MAX_MEDUSA_TEST_LIMIT)?;
            let secs = int_arg(
                args,
                "timeout_secs",
                DEFAULT_MEDUSA_TIMEOUT_SECS,
                MAX_TIMEOUT_SECS,
            )?;
            Ok(CallPlan {
                program: "medusa",
                argv: vec![
                    "fuzz".into(),
                    "--no-color".into(),
                    "--test-limit".into(),
                    limit.to_string(),
                    "--timeout".into(),
                    secs.to_string(),
                ],
                wall_secs: secs + MEDUSA_GRACE_SECS,
                threshold: Severity::High,
                test_limit: Some(limit),
            })
        }
        other => Err(format!("'{other}' is not a toolchain tool")),
    }
}

fn run_facts(r: &RunReport) -> serde_json::Value {
    serde_json::json!({
        "program": r.program,
        "args": r.args,
        "exit_code": r.exit_code,
        "signal": r.signal,
        "timed_out": r.timed_out,
        "timeout_ms": r.timeout_ms,
        "duration_ms": r.duration_ms,
        "stdout_bytes": r.stdout_bytes,
        "stderr_bytes": r.stderr_bytes,
        "stdout_truncated": r.stdout_truncated,
        "output_incomplete": r.output_incomplete,
        "sandbox": r.sandbox,
    })
}

/// Turn a finished run into the tool result.
fn judge_run(tool: &str, plan: &CallPlan, r: &RunReport, ctx: &RunContext<'_>) -> ToolOutcome {
    let facts = run_facts(r);
    if r.timed_out {
        return ToolOutcome::Error(
            ToolchainEnvelope::not_run(
                tool,
                RunStatus::TimedOut,
                format!(
                    "{} did not finish within {}s and was stopped",
                    plan.program,
                    r.timeout_ms / 1000
                ),
            )
            .with_run(facts)
            .to_content(),
        );
    }
    if r.stdout_truncated || r.output_incomplete {
        return ToolOutcome::Error(
            ToolchainEnvelope::not_run(
                tool,
                RunStatus::Failed,
                format!(
                    "{}'s report exceeded the capture limit ({} bytes), so it was not judged",
                    plan.program, r.stdout_bytes
                ),
            )
            .with_run(facts)
            .to_content(),
        );
    }
    let verdict = match tool {
        FORGE_TEST_TOOL => verify_forge_test_output(&r.stdout),
        SLITHER_SCAN_TOOL => verify_sarif_output(&r.stdout, SarifProfile::Slither, plan.threshold),
        ADERYN_SCAN_TOOL => verify_sarif_output(&r.stdout, SarifProfile::Aderyn, plan.threshold),
        _ => verify_medusa_output(&r.stdout),
    };
    let unparsed = verdict.evidence.get("error").is_some();
    let gate = GateReport {
        project: ctx.project.to_string_lossy().into_owned(),
        output: r.stdout.clone(),
        duration_ms: r.duration_ms,
        sources_sha256: ctx.sources.clone(),
        test_limit: plan.test_limit,
        coverage_lcov: if tool == MEDUSA_FUZZ_TOOL {
            crate::toolchain_reports::medusa_lcov(ctx.project, ctx.started)
        } else {
            None
        },
        artifacts: if tool == FORGE_TEST_TOOL {
            crate::toolchain_reports::forge_artifacts(ctx.project)
        } else {
            Default::default()
        },
    };
    let mut env = ToolchainEnvelope::completed(tool, verdict)
        .with_run(facts)
        .with_gate(gate);
    if unparsed {
        env = env.with_diagnostics(compiler_diagnostics(
            &format!("{}\n{}", r.stderr, r.stdout),
            MAX_DIAGNOSTICS,
        ));
    }
    ToolOutcome::Ok(env.to_content())
}
