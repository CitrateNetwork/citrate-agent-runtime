//! ShellExec tool — execute an allowlisted binary in the workspace directory.
//!
//! ## SECREM-01 SVC-3: the allowlist is a SPEED BUMP, not a security boundary
//!
//! Several allowlisted binaries execute arbitrary code BY DESIGN:
//! `cargo` (build.rs / proc macros), `make` (recipes), `npm`/`npx`/
//! `pnpm` (lifecycle scripts), `node`, `python`/`python3`, `pip`,
//! `git` (hooks, `core.fsmonitor`), and `forge` (ffi / solc plugins).
//! Combined with the `file_write` tool, an agent that can run any of
//! these can stage and execute arbitrary code in the workspace. The
//! allowlist therefore only filters out *obviously* hostile direct
//! invocations (`sudo`, `nc`, `dd`, ...) and the metachar reject only
//! rules out shell chaining — neither is the enforced control.
//!
//! The ENFORCED control is HIC (Human In Control) re-authorization:
//! `ShellExec::risk_level()` is `RiskLevel::Critical`, and every tool
//! call is gated by `ApprovalFlow::check` in
//! `agent-legacy/src/approval.rs` (invoked from
//! `CodeAgentBridge::execute_tool` in `agent-code/src/bridge.rs`,
//! mandatory in all live paths per S-03/H-01). For Critical risk that
//! means: explicit per-call user approval PLUS password
//! re-authentication (`ApprovalHandler::request_reauth`) on EVERY
//! call — session grants and auto-approve never bypass it.
//!
//! As part of SVC-3 we also tightened the one allowlisted binary whose
//! danger was *not* by-design-obvious: `find` is kept for read-only
//! use, but its exec/write primitives (`-exec`, `-execdir`, `-ok`,
//! `-okdir`, `-delete`, `-fprint`, `-fprint0`, `-fprintf`, `-fls`)
//! are rejected — see `FORBIDDEN_FIND_FLAGS`.
//!
//! RM-B1 / WP-E4.4 (audit AGT-04): allowlist replaces the previous
//! denylist. Pre-fix `DENIED_COMMANDS` checked for ~10 substrings;
//! the audit's variant analysis enumerated 16 bypasses (`s\udo`,
//! `base64 -d <<< ... | bash`, chmod chains, redirected sudo,
//! POSIX expansions, etc.) all of which slipped through. Post-fix
//! we no longer go through `sh -c` at all — we tokenize the
//! command, reject shell metacharacters, and exec the binary
//! directly with `tokio::process::Command` against a vetted
//! ALLOWED_BINARIES list.
//!
//! RM-B1 / WP-E4.5 (audit AGT-03): risk_level is now Critical.
//! With the allowlist + meta-reject, the surface is bounded enough
//! for re-auth-on-every-call to be operationally tolerable.
//!
//! RM-B1 / WP-E4.6 (audit AGT-05): cwd validation + PATH cleansing.
//! `ctx.workspace_dir` must exist and resolve to an allowed
//! workspace; PATH is cleared to a known-safe set of directories
//! so an attacker-controlled binary in PATH can't be invoked.

use citrate_agent_core::error::AgentError;
use citrate_agent_core::tool::{AgentTool, RiskLevel, ToolContext, ToolResult};
use std::time::Duration;

pub struct ShellExec;

/// Allowlisted binaries by basename. Anything else is rejected.
/// RM-B1 / WP-E4.4 (audit AGT-04).
pub const ALLOWED_BINARIES: &[&str] = &[
    // Rust toolchain
    "cargo", "rustc", "rustup", "rustfmt", "clippy",
    // Source control
    "git",
    // Solidity toolchain
    "forge", "cast", "anvil",
    // POSIX read-only utilities
    "ls", "cat", "head", "tail", "wc", "echo", "pwd", "tree",
    // Search
    "grep", "find", "rg", "fd",
    // JS toolchain
    "node", "npm", "npx", "pnpm",
    // Python toolchain
    "python", "python3", "pip", "pip3",
    // Build tools
    "make",
    // Hashing
    "sha256sum",
];

/// Shell metacharacters that allow chaining, redirection, or
/// substitution. Banning these rules out the entire class of
/// "agent-controlled binary path through pipes/`$()`" bypasses
/// the audit found.
const FORBIDDEN_METACHARS: &[char] = &[
    '|', ';', '&', '>', '<', '`', '$', '(', ')', '\n', '\r',
];

/// SECREM-01 SVC-3: `find` flags that execute arbitrary binaries
/// (`-exec`/`-execdir`/`-ok`/`-okdir`) or write to the filesystem
/// (`-delete`, `-fprint`, `-fprint0`, `-fprintf`, `-fls`). `find`
/// stays allowlisted for read-only traversal; any of these flags
/// rejects the whole command. Matching is exact-token: find's CLI
/// grammar requires each primary as its own argv token (no
/// `--exec=`/combined forms), and whitespace tokenization plus the
/// metachar reject above means no token can smuggle one in.
const FORBIDDEN_FIND_FLAGS: &[&str] = &[
    "-exec", "-execdir", "-ok", "-okdir",
    "-delete", "-fprint", "-fprint0", "-fprintf", "-fls",
];

/// PATH the spawned process sees. Constrained to system binary
/// directories so an attacker can't pre-stage a binary named
/// `cargo` earlier in PATH.
/// RM-B1 / WP-E4.6 (audit AGT-05).
const SAFE_PATH: &str = "/usr/local/bin:/usr/bin:/bin";

/// Default timeout for shell commands: 30 seconds.
const DEFAULT_TIMEOUT_MS: u64 = 30_000;

/// PBA-L6b-034: cap `s` at [`MAX_OUTPUT_BYTES`] on a UTF-8 char boundary and
/// mark it truncated. Never panics.
fn truncate_output(s: &mut String) {
    if s.len() > MAX_OUTPUT_BYTES {
        let cut = s.floor_char_boundary(MAX_OUTPUT_BYTES);
        s.truncate(cut);
        s.push_str("\n... (truncated)");
    }
}

/// Maximum allowed timeout: 5 minutes.
const MAX_TIMEOUT_MS: u64 = 300_000;

/// Maximum output size we return: 64 KiB.
const MAX_OUTPUT_BYTES: usize = 65_536;

/// AR-B-022: per-exec counter for the isolated scratch HOME directory name, so
/// concurrent invocations get distinct empty homes.
static SCRATCH_HOME_SEQ: std::sync::atomic::AtomicU64 = std::sync::atomic::AtomicU64::new(0);

/// Tokenize a command string into (binary, args). Rejects:
///   - shell metacharacters anywhere in the string
///   - empty commands
///   - binaries whose basename is not in `ALLOWED_BINARIES`
///   - binaries with absolute paths whose basename IS allowlisted
///     but whose path is not in SAFE_PATH (defense in depth)
pub fn parse_and_validate_command(
    command: &str,
) -> Result<(String, Vec<String>), String> {
    for ch in command.chars() {
        if FORBIDDEN_METACHARS.contains(&ch) {
            return Err(format!(
                "shell metacharacter '{}' is not permitted; only single-binary invocations are accepted",
                ch
            ));
        }
    }
    let mut tokens = command.split_whitespace();
    let binary_raw = tokens
        .next()
        .ok_or_else(|| "empty command".to_string())?
        .to_string();
    let args: Vec<String> = tokens.map(|s| s.to_string()).collect();

    let basename = std::path::Path::new(&binary_raw)
        .file_name()
        .and_then(|s| s.to_str())
        .unwrap_or(&binary_raw);

    if !ALLOWED_BINARIES.contains(&basename) {
        return Err(format!(
            "binary '{}' is not in the allowlist; see ALLOWED_BINARIES in shell_exec.rs",
            basename
        ));
    }

    // AR-B-022: a RELATIVE path that carries a separator (`./cargo`,
    // `target/debug/make`) passed the basename allowlist but was never checked
    // against SAFE_PATH, so it executed a workspace-local — attacker-writable —
    // binary. Only a bare name (resolved via the cleansed PATH) or an absolute
    // path inside SAFE_PATH is permitted; reject any other form.
    if !std::path::Path::new(&binary_raw).is_absolute() && binary_raw.contains('/') {
        return Err(format!(
            "relative binary path '{}' is not permitted; use a bare binary name (resolved via the \
             cleansed PATH) or an absolute path inside the safe PATH directories ({})",
            binary_raw, SAFE_PATH
        ));
    }

    // Defense in depth: if the caller passes an absolute path,
    // it must live in one of the SAFE_PATH directories. This stops
    // `/tmp/cargo` (an attacker-staged binary) even though `cargo`
    // is allowlisted by basename.
    if std::path::Path::new(&binary_raw).is_absolute() {
        let allowed_dirs: Vec<&str> = SAFE_PATH.split(':').collect();
        let parent = std::path::Path::new(&binary_raw)
            .parent()
            .and_then(|p| p.to_str())
            .unwrap_or("");
        if !allowed_dirs.iter().any(|d| *d == parent) {
            return Err(format!(
                "absolute binary path '{}' is outside the safe PATH directories ({})",
                binary_raw, SAFE_PATH
            ));
        }
    }

    // SECREM-01 SVC-3: per-binary argument validation. `find` is
    // allowlisted for read-only traversal only; its exec/write
    // primitives turn it into an arbitrary-code-execution vector
    // for non-allowlisted binaries.
    if basename == "find" {
        for arg in &args {
            if FORBIDDEN_FIND_FLAGS.contains(&arg.as_str()) {
                return Err(format!(
                    "find flag '{}' is not permitted; find is allowlisted for read-only use only (SECREM-01 SVC-3)",
                    arg
                ));
            }
        }
    }

    Ok((binary_raw, args))
}

#[async_trait::async_trait]
impl AgentTool for ShellExec {
    fn name(&self) -> &str {
        "shell_exec"
    }

    fn description(&self) -> &str {
        "Execute a shell command in the workspace directory"
    }

    fn parameters_schema(&self) -> serde_json::Value {
        serde_json::json!({
            "type": "object",
            "properties": {
                "command": {
                    "type": "string",
                    "description": "Shell command to execute"
                },
                "timeout_ms": {
                    "type": "integer",
                    "description": "Timeout in milliseconds (default: 30000, max: 300000)"
                }
            },
            "required": ["command"]
        })
    }

    fn risk_level(&self) -> RiskLevel {
        // RM-B1 / WP-E4.5 (audit AGT-03): re-auth on every call.
        RiskLevel::Critical
    }

    async fn execute(
        &self,
        params: serde_json::Value,
        ctx: &ToolContext,
    ) -> Result<ToolResult, AgentError> {
        let command = params
            .get("command")
            .and_then(|c| c.as_str())
            .ok_or_else(|| AgentError::InvalidParams("'command' is required".into()))?;

        // RM-B1 / WP-E4.4 (audit AGT-04): allowlist + meta-reject.
        let (binary, args) = parse_and_validate_command(command)
            .map_err(AgentError::ExecutionFailed)?;

        // RM-B1 / WP-E4.6 (audit AGT-05): cwd must be a real
        // directory. Empty / absent / file-shaped values reject.
        let workspace_path = std::path::Path::new(&ctx.workspace_dir);
        if !workspace_path.is_dir() {
            return Err(AgentError::ExecutionFailed(format!(
                "workspace_dir '{}' is not a valid directory",
                ctx.workspace_dir
            )));
        }

        let timeout_ms = params
            .get("timeout_ms")
            .and_then(|t| t.as_u64())
            .unwrap_or(DEFAULT_TIMEOUT_MS)
            .min(MAX_TIMEOUT_MS);

        // Build a minimal-environment Command. PATH is hard-coded
        // to SAFE_PATH so an attacker can't pre-stage a binary
        // earlier in PATH; no other env is inherited.
        //
        // AR-B-022: HOME is NOT inherited from the real user. The old code
        // re-added the real $HOME, so an allow-listed `git`/`cargo` read
        // `~/.gitconfig` (core.sshCommand / core.pager) or `~/.cargo/config.toml`
        // ([target.*].runner) — a code-exec sink that never touches the Critical
        // shell_exec re-auth gate. Point HOME at a fresh, isolated, empty scratch
        // dir so no attacker-plantable home config is on the search path. Also
        // pin git's global/system config to /dev/null as belt-and-braces.
        let scratch_home = std::env::temp_dir().join(format!(
            "citrate-shell-home-{}-{}",
            std::process::id(),
            SCRATCH_HOME_SEQ.fetch_add(1, std::sync::atomic::Ordering::Relaxed)
        ));
        let _ = std::fs::create_dir_all(&scratch_home);
        let mut cmd = tokio::process::Command::new(&binary);
        cmd.args(&args)
            .current_dir(&ctx.workspace_dir)
            .env_clear()
            .env("PATH", SAFE_PATH)
            .env("HOME", &scratch_home)
            .env("GIT_CONFIG_GLOBAL", "/dev/null")
            .env("GIT_CONFIG_SYSTEM", "/dev/null");

        let result = tokio::time::timeout(
            Duration::from_millis(timeout_ms),
            cmd.output(),
        )
        .await;

        // AR-B-022: best-effort cleanup of the isolated scratch HOME.
        let _ = std::fs::remove_dir_all(&scratch_home);

        match result {
            Err(_) => Err(AgentError::Timeout(timeout_ms)),
            Ok(Err(e)) => Err(AgentError::ExecutionFailed(format!(
                "failed to execute command: {e}"
            ))),
            Ok(Ok(output)) => {
                let exit_code = output.status.code().unwrap_or(-1);
                let mut stdout = String::from_utf8_lossy(&output.stdout).to_string();
                let mut stderr = String::from_utf8_lossy(&output.stderr).to_string();

                // Truncate large outputs.
                // PBA-L6b-034: cut at the last char boundary at or below the
                // cap; `truncate(MAX_OUTPUT_BYTES)` panicked when that byte
                // fell inside a multi-byte character.
                truncate_output(&mut stdout);
                truncate_output(&mut stderr);

                let combined = if stderr.is_empty() {
                    stdout.clone()
                } else if stdout.is_empty() {
                    stderr.clone()
                } else {
                    format!("{stdout}\n--- stderr ---\n{stderr}")
                };

                let success = output.status.success();

                Ok(ToolResult {
                    success,
                    output: combined,
                    data: Some(serde_json::json!({
                        "exit_code": exit_code,
                        "stdout_len": output.stdout.len(),
                        "stderr_len": output.stderr.len(),
                    })),
                    error: if success {
                        None
                    } else {
                        Some(format!("command exited with code {exit_code}"))
                    },
                })
            }
        }
    }
}
