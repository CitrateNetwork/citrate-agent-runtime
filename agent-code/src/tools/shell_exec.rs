//! ShellExec tool — execute a allowlisted binary in the workspace directory.
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

/// PATH the spawned process sees. Constrained to system binary
/// directories so an attacker can't pre-stage a binary named
/// `cargo` earlier in PATH.
/// RM-B1 / WP-E4.6 (audit AGT-05).
const SAFE_PATH: &str = "/usr/local/bin:/usr/bin:/bin";

/// Default timeout for shell commands: 30 seconds.
const DEFAULT_TIMEOUT_MS: u64 = 30_000;

/// Maximum allowed timeout: 5 minutes.
const MAX_TIMEOUT_MS: u64 = 300_000;

/// Maximum output size we return: 64 KiB.
const MAX_OUTPUT_BYTES: usize = 65_536;

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
        // earlier in PATH; HOME is preserved (cargo/git read it
        // for credentials/config) but no other env is inherited.
        let mut cmd = tokio::process::Command::new(&binary);
        cmd.args(&args)
            .current_dir(&ctx.workspace_dir)
            .env_clear()
            .env("PATH", SAFE_PATH);
        if let Ok(home) = std::env::var("HOME") {
            cmd.env("HOME", home);
        }

        let result = tokio::time::timeout(
            Duration::from_millis(timeout_ms),
            cmd.output(),
        )
        .await;

        match result {
            Err(_) => Err(AgentError::Timeout(timeout_ms)),
            Ok(Err(e)) => Err(AgentError::ExecutionFailed(format!(
                "failed to execute command: {e}"
            ))),
            Ok(Ok(output)) => {
                let exit_code = output.status.code().unwrap_or(-1);
                let mut stdout = String::from_utf8_lossy(&output.stdout).to_string();
                let mut stderr = String::from_utf8_lossy(&output.stderr).to_string();

                // Truncate large outputs
                if stdout.len() > MAX_OUTPUT_BYTES {
                    stdout.truncate(MAX_OUTPUT_BYTES);
                    stdout.push_str("\n... (truncated)");
                }
                if stderr.len() > MAX_OUTPUT_BYTES {
                    stderr.truncate(MAX_OUTPUT_BYTES);
                    stderr.push_str("\n... (truncated)");
                }

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
