//! Citrate Agent Code — coding agent tools for the IDE/Studio tab.
//!
//! These 6 tools provide an OpenCode-style coding agent bridge:
//! - file_read: read file contents with optional line ranges
//! - file_write: write content to a file (creates dirs as needed)
//! - file_edit: replace an exact string occurrence in a file
//! - shell_exec: execute a shell command with timeout
//! - git_ops: git status, diff, commit, push
//! - search_code: search for patterns in code files (grep-like)
//!
//! The `CodeAgentBridge` provides a higher-level interface for the
//! Studio/IDE tab, routing LLM tool calls to the appropriate tool
//! and gathering workspace context.

pub mod tools;
pub mod bridge;

use citrate_agent_core::tool::ToolRegistry;
use std::sync::Arc;

/// Register all coding tools with the given registry.
pub async fn register_tools(registry: &ToolRegistry) {
    registry.register(Arc::new(tools::FileRead)).await;
    registry.register(Arc::new(tools::FileWrite)).await;
    registry.register(Arc::new(tools::FileEdit)).await;
    registry.register(Arc::new(tools::ShellExec)).await;
    registry.register(Arc::new(tools::GitOps)).await;
    registry.register(Arc::new(tools::SearchCode)).await;

    // Memory tools (memory_recall / memory_assert) over the citrate-memories
    // gateway. Credentials resolve from the host app's session/config file first
    // (written after the user logs in), then env — so an in-app agent needs no
    // environment setup. A quiet no-op when unconfigured; memory stays optional.
    if citrate_agent_core::adapters::memory_tools::register_memory_tools_auto(registry).await {
        tracing::info!("registered memory tools: memory_recall, memory_assert");
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use citrate_agent_core::tool::{AgentTool, RiskLevel, ToolContext};

    fn test_ctx_with_dir(dir: &str) -> ToolContext {
        ToolContext {
            session_id: "test-session".to_string(),
            wallet_address: None,
            chain_id: 40204,
            workspace_dir: dir.to_string(),
        }
    }

    // ── Registration tests ──────────────────────────────────────────────

    #[tokio::test]
    async fn test_register_all_tools() {
        let registry = ToolRegistry::new();
        register_tools(&registry).await;
        assert_eq!(registry.count().await, 6);
    }

    #[tokio::test]
    async fn test_tool_names_present() {
        let registry = ToolRegistry::new();
        register_tools(&registry).await;
        let names = registry.list().await;
        assert!(names.contains(&"file_read".to_string()));
        assert!(names.contains(&"file_write".to_string()));
        assert!(names.contains(&"file_edit".to_string()));
        assert!(names.contains(&"shell_exec".to_string()));
        assert!(names.contains(&"git_ops".to_string()));
        assert!(names.contains(&"search_code".to_string()));
    }

    #[tokio::test]
    async fn test_tool_definitions_format() {
        let registry = ToolRegistry::new();
        register_tools(&registry).await;
        let defs = registry.tool_definitions().await;
        assert_eq!(defs.len(), 6);
        for def in &defs {
            assert!(def["function"]["name"].as_str().is_some());
            assert!(def["function"]["description"].as_str().is_some());
            assert!(def["function"]["parameters"].is_object());
        }
    }

    // ── Risk level tests ────────────────────────────────────────────────

    #[tokio::test]
    async fn test_risk_levels() {
        assert_eq!(tools::FileRead.risk_level(), RiskLevel::Low);
        assert_eq!(tools::FileWrite.risk_level(), RiskLevel::Medium);
        assert_eq!(tools::FileEdit.risk_level(), RiskLevel::Medium);
        // RM-B1 / WP-E4.5 (audit AGT-03): Critical, not Medium.
        assert_eq!(tools::ShellExec.risk_level(), RiskLevel::Critical);
        assert_eq!(tools::GitOps.risk_level(), RiskLevel::Medium);
        assert_eq!(tools::SearchCode.risk_level(), RiskLevel::Low);
    }

    // ── FileRead tests ──────────────────────────────────────────────────

    #[tokio::test]
    async fn test_file_read_success() {
        let dir = tempfile::tempdir().expect("failed to create temp dir");
        let file_path = dir.path().join("hello.txt");
        std::fs::write(&file_path, "line1\nline2\nline3\n")
            .expect("failed to write test file");

        let ctx = test_ctx_with_dir(dir.path().to_str().expect("valid path"));
        let result = tools::FileRead
            .execute(serde_json::json!({ "path": "hello.txt" }), &ctx)
            .await
            .expect("file_read should succeed");

        assert!(result.success);
        assert!(result.output.contains("line1"));
        assert!(result.output.contains("line2"));
        assert!(result.output.contains("line3"));
        let data = result.data.expect("should have data");
        assert_eq!(data["total_lines"], 3);
    }

    #[tokio::test]
    async fn test_file_read_with_line_range() {
        let dir = tempfile::tempdir().expect("failed to create temp dir");
        let file_path = dir.path().join("lines.txt");
        std::fs::write(&file_path, "a\nb\nc\nd\ne\n")
            .expect("failed to write test file");

        let ctx = test_ctx_with_dir(dir.path().to_str().expect("valid path"));
        let result = tools::FileRead
            .execute(
                serde_json::json!({ "path": "lines.txt", "start_line": 2, "end_line": 4 }),
                &ctx,
            )
            .await
            .expect("file_read should succeed");

        assert!(result.success);
        assert!(result.output.contains("b"));
        assert!(result.output.contains("c"));
        assert!(result.output.contains("d"));
        // Should not contain line 1 or line 5
        assert!(!result.output.contains("\ta\n"));
        assert!(!result.output.contains("\te\n"));
    }

    #[tokio::test]
    async fn test_file_read_missing_file() {
        let dir = tempfile::tempdir().expect("failed to create temp dir");
        let ctx = test_ctx_with_dir(dir.path().to_str().expect("valid path"));
        let result = tools::FileRead
            .execute(serde_json::json!({ "path": "nonexistent.txt" }), &ctx)
            .await;

        assert!(result.is_err());
    }

    #[tokio::test]
    async fn test_file_read_missing_param() {
        let dir = tempfile::tempdir().expect("failed to create temp dir");
        let ctx = test_ctx_with_dir(dir.path().to_str().expect("valid path"));
        let result = tools::FileRead
            .execute(serde_json::json!({}), &ctx)
            .await;

        assert!(result.is_err());
        let err = result.expect_err("should fail without path");
        assert!(err.to_string().contains("'path' is required"));
    }

    // ── FileWrite tests ─────────────────────────────────────────────────

    #[tokio::test]
    async fn test_file_write_creates_file() {
        let dir = tempfile::tempdir().expect("failed to create temp dir");
        let ctx = test_ctx_with_dir(dir.path().to_str().expect("valid path"));
        let result = tools::FileWrite
            .execute(
                serde_json::json!({ "path": "new_file.txt", "content": "hello world" }),
                &ctx,
            )
            .await
            .expect("file_write should succeed");

        assert!(result.success);
        let written = std::fs::read_to_string(dir.path().join("new_file.txt"))
            .expect("file should exist");
        assert_eq!(written, "hello world");
    }

    #[tokio::test]
    async fn test_file_write_creates_dirs() {
        let dir = tempfile::tempdir().expect("failed to create temp dir");
        let ctx = test_ctx_with_dir(dir.path().to_str().expect("valid path"));
        let result = tools::FileWrite
            .execute(
                serde_json::json!({
                    "path": "sub/dir/file.txt",
                    "content": "nested content"
                }),
                &ctx,
            )
            .await
            .expect("file_write should succeed");

        assert!(result.success);
        let written = std::fs::read_to_string(dir.path().join("sub/dir/file.txt"))
            .expect("nested file should exist");
        assert_eq!(written, "nested content");
    }

    #[tokio::test]
    async fn test_file_write_missing_content() {
        let dir = tempfile::tempdir().expect("failed to create temp dir");
        let ctx = test_ctx_with_dir(dir.path().to_str().expect("valid path"));
        let result = tools::FileWrite
            .execute(serde_json::json!({ "path": "file.txt" }), &ctx)
            .await;

        assert!(result.is_err());
        let err = result.expect_err("should fail without content");
        assert!(err.to_string().contains("'content' is required"));
    }

    // ── FileEdit tests ──────────────────────────────────────────────────

    #[tokio::test]
    async fn test_file_edit_replaces_string() {
        let dir = tempfile::tempdir().expect("failed to create temp dir");
        let file_path = dir.path().join("edit_me.txt");
        std::fs::write(&file_path, "hello world, hello rust")
            .expect("failed to write test file");

        let ctx = test_ctx_with_dir(dir.path().to_str().expect("valid path"));
        let result = tools::FileEdit
            .execute(
                serde_json::json!({
                    "path": "edit_me.txt",
                    "old_string": "hello world",
                    "new_string": "goodbye world"
                }),
                &ctx,
            )
            .await
            .expect("file_edit should succeed");

        assert!(result.success);
        let content = std::fs::read_to_string(&file_path).expect("file should exist");
        assert_eq!(content, "goodbye world, hello rust");
    }

    #[tokio::test]
    async fn test_file_edit_rejects_ambiguous() {
        let dir = tempfile::tempdir().expect("failed to create temp dir");
        let file_path = dir.path().join("dup.txt");
        std::fs::write(&file_path, "aaa bbb aaa").expect("failed to write test file");

        let ctx = test_ctx_with_dir(dir.path().to_str().expect("valid path"));
        let result = tools::FileEdit
            .execute(
                serde_json::json!({
                    "path": "dup.txt",
                    "old_string": "aaa",
                    "new_string": "zzz"
                }),
                &ctx,
            )
            .await;

        assert!(result.is_err());
        let err = result.expect_err("should reject ambiguous edit");
        assert!(err.to_string().contains("2 times"));
    }

    #[tokio::test]
    async fn test_file_edit_not_found() {
        let dir = tempfile::tempdir().expect("failed to create temp dir");
        let file_path = dir.path().join("edit_me.txt");
        std::fs::write(&file_path, "hello world").expect("failed to write test file");

        let ctx = test_ctx_with_dir(dir.path().to_str().expect("valid path"));
        let result = tools::FileEdit
            .execute(
                serde_json::json!({
                    "path": "edit_me.txt",
                    "old_string": "xyz",
                    "new_string": "abc"
                }),
                &ctx,
            )
            .await;

        assert!(result.is_err());
        let err = result.expect_err("should fail when old_string not found");
        assert!(err.to_string().contains("not found"));
    }

    #[tokio::test]
    async fn test_file_edit_same_strings_rejected() {
        let dir = tempfile::tempdir().expect("failed to create temp dir");
        let file_path = dir.path().join("same.txt");
        std::fs::write(&file_path, "hello").expect("failed to write test file");

        let ctx = test_ctx_with_dir(dir.path().to_str().expect("valid path"));
        let result = tools::FileEdit
            .execute(
                serde_json::json!({
                    "path": "same.txt",
                    "old_string": "hello",
                    "new_string": "hello"
                }),
                &ctx,
            )
            .await;

        assert!(result.is_err());
        let err = result.expect_err("should reject identical strings");
        assert!(err.to_string().contains("must differ"));
    }

    // ── ShellExec tests ─────────────────────────────────────────────────

    #[tokio::test]
    async fn test_shell_exec_echo() {
        let dir = tempfile::tempdir().expect("failed to create temp dir");
        let ctx = test_ctx_with_dir(dir.path().to_str().expect("valid path"));
        let result = tools::ShellExec
            .execute(serde_json::json!({ "command": "echo hello" }), &ctx)
            .await
            .expect("shell_exec should succeed");

        assert!(result.success);
        assert!(result.output.contains("hello"));
    }

    #[tokio::test]
    async fn test_shell_exec_failing_command() {
        // Post RM-E4: shell builtins like `exit 42` no longer apply
        // because we don't go through `sh -c`. Use an allowlisted
        // binary (`cat`) on a missing file to produce a non-zero
        // exit. This proves the failure-path plumbing still works
        // even though shell builtins are gone.
        let dir = tempfile::tempdir().expect("failed to create temp dir");
        let ctx = test_ctx_with_dir(dir.path().to_str().expect("valid path"));
        let result = tools::ShellExec
            .execute(
                serde_json::json!({ "command": "cat /nonexistent-citrate-test-file" }),
                &ctx,
            )
            .await
            .expect("shell_exec should return result, not error");

        assert!(!result.success);
        let data = result.data.expect("should have data");
        // `cat` returns 1 on missing file across coreutils/BSD.
        assert!(
            data["exit_code"].as_i64().expect("exit_code int") != 0,
            "expected non-zero exit, got {:?}",
            data["exit_code"]
        );
    }

    #[tokio::test]
    async fn test_shell_exec_missing_command() {
        let dir = tempfile::tempdir().expect("failed to create temp dir");
        let ctx = test_ctx_with_dir(dir.path().to_str().expect("valid path"));
        let result = tools::ShellExec.execute(serde_json::json!({}), &ctx).await;

        assert!(result.is_err());
        let err = result.expect_err("should fail without command");
        assert!(err.to_string().contains("'command' is required"));
    }

    // ── RM-E4 / WP-E4.4 bypass attempts (audit AGT-04) ──────────────

    /// Helper: assert the parser rejects a command. Any rejection
    /// reason is acceptable — the contract is "this string must
    /// not run a process."
    fn assert_rejected(command: &str) {
        use crate::tools::shell_exec::parse_and_validate_command;
        let r = parse_and_validate_command(command);
        assert!(
            r.is_err(),
            "AGT-04: bypass attempt {:?} must be rejected",
            command
        );
    }

    #[tokio::test]
    async fn test_agt04_rejects_pipe_chain() {
        assert_rejected("ls | rm -rf /");
        assert_rejected("cat /etc/passwd | base64");
    }

    #[tokio::test]
    async fn test_agt04_rejects_semicolon_chain() {
        assert_rejected("ls; rm -rf /");
        assert_rejected("cargo build ; sudo apt install evil");
    }

    #[tokio::test]
    async fn test_agt04_rejects_ampersand_background() {
        assert_rejected("cargo build &");
        assert_rejected("ls && rm -rf /");
    }

    #[tokio::test]
    async fn test_agt04_rejects_redirect() {
        assert_rejected("echo evil > /etc/passwd");
        assert_rejected("cat < /etc/shadow");
    }

    #[tokio::test]
    async fn test_agt04_rejects_command_substitution() {
        assert_rejected("echo $(rm -rf /)");
        assert_rejected("echo `whoami`");
    }

    #[tokio::test]
    async fn test_agt04_rejects_variable_expansion() {
        assert_rejected("echo $HOME");
    }

    #[tokio::test]
    async fn test_agt04_rejects_non_allowlisted_binary() {
        assert_rejected("sudo cargo build");
        assert_rejected("dd if=/dev/zero of=/etc/passwd");
        assert_rejected("nc -l 9000");
        assert_rejected("/bin/su -");
    }

    #[tokio::test]
    async fn test_agt04_rejects_attacker_staged_absolute_path() {
        // `cargo` IS allowlisted, but only at SAFE_PATH locations.
        // /tmp/cargo (an attacker-staged binary) is rejected.
        assert_rejected("/tmp/cargo build");
        assert_rejected("/home/user/.local/bin/cargo build");
    }

    #[tokio::test]
    async fn test_arb022_rejects_workspace_relative_binary() {
        // AR-B-022: a relative path with a separator passed the basename
        // allowlist but escaped the SAFE_PATH check, executing a
        // workspace-local (attacker-writable) binary. It must be rejected.
        assert_rejected("./cargo build");
        assert_rejected("target/debug/make");
        assert_rejected("./git status");
        assert_rejected("subdir/cargo build");
    }

    #[tokio::test]
    async fn test_agt04_accepts_allowlisted_binaries() {
        use crate::tools::shell_exec::parse_and_validate_command;
        let cases = &[
            "cargo build --release",
            "git status",
            "forge test",
            "ls -la src",
            "rg pattern src",
            "/usr/bin/python3 --version",
        ];
        for c in cases {
            assert!(
                parse_and_validate_command(c).is_ok(),
                "must accept allowlisted: {}",
                c
            );
        }
    }

    #[tokio::test]
    async fn test_agt04_rejects_empty_command() {
        assert_rejected("");
        assert_rejected("   ");
    }

    #[tokio::test]
    async fn test_agt04_rejects_newline_smuggling() {
        // Some shell parsers treat `\n` like `;`.
        assert_rejected("cargo build\nrm -rf /");
        assert_rejected("ls\rrm -rf /");
    }

    // ── SECREM-01 SVC-3: find exec/write primitives rejected ────────

    #[tokio::test]
    async fn test_svc3_rejects_find_exec_variants() {
        // -exec and friends invoke arbitrary non-allowlisted binaries.
        assert_rejected("find . -name x -exec rm -rf {} +");
        assert_rejected("find . -execdir touch pwned {} +");
        assert_rejected("find . -name x -ok rm {} +");
        assert_rejected("find . -okdir mv {} /tmp +");
    }

    #[tokio::test]
    async fn test_svc3_rejects_find_write_primitives() {
        assert_rejected("find . -name x -delete");
        assert_rejected("find . -fprintf /etc/cron.d/evil %p");
        assert_rejected("find . -fprint /tmp/out");
        assert_rejected("find . -fprint0 /tmp/out");
        assert_rejected("find . -fls /tmp/out");
    }

    #[tokio::test]
    async fn test_svc3_allows_readonly_find() {
        use crate::tools::shell_exec::parse_and_validate_command;
        let cases = &[
            "find . -name x",
            "find src -type f -name *.rs",
            "find . -maxdepth 2 -name Cargo.toml -print",
        ];
        for c in cases {
            assert!(
                parse_and_validate_command(c).is_ok(),
                "SVC-3: read-only find must stay allowed: {}",
                c
            );
        }
    }

    #[tokio::test]
    async fn test_svc3_find_flags_only_constrain_find() {
        use crate::tools::shell_exec::parse_and_validate_command;
        // `-exec` as an argument to another allowlisted binary is a
        // plain string, not an execution primitive.
        assert!(parse_and_validate_command("grep -r -exec src").is_ok());
        assert!(parse_and_validate_command("rg -- -delete src").is_ok());
    }

    /// AGT-05: invalid workspace_dir rejects.
    #[tokio::test]
    async fn test_agt05_invalid_workspace_dir_rejects() {
        let mut ctx = test_ctx_with_dir("/nonexistent-citrate-cwd-test");
        ctx.workspace_dir = "/nonexistent-citrate-cwd-test".to_string();
        let result = tools::ShellExec
            .execute(serde_json::json!({ "command": "echo hi" }), &ctx)
            .await;
        assert!(
            result.is_err(),
            "AGT-05: nonexistent workspace_dir must reject"
        );
    }

    // ── GitOps tests ────────────────────────────────────────────────────

    #[tokio::test]
    async fn test_git_ops_status_in_git_repo() {
        let dir = tempfile::tempdir().expect("failed to create temp dir");
        // Initialize a git repo
        std::process::Command::new("git")
            .args(["init"])
            .current_dir(dir.path())
            .output()
            .expect("git init should work");

        let ctx = test_ctx_with_dir(dir.path().to_str().expect("valid path"));
        let result = tools::GitOps
            .execute(serde_json::json!({ "operation": "status" }), &ctx)
            .await
            .expect("git status should succeed");

        assert!(result.success);
    }

    #[tokio::test]
    async fn test_git_ops_invalid_operation() {
        let dir = tempfile::tempdir().expect("failed to create temp dir");
        let ctx = test_ctx_with_dir(dir.path().to_str().expect("valid path"));
        let result = tools::GitOps
            .execute(serde_json::json!({ "operation": "rebase" }), &ctx)
            .await;

        assert!(result.is_err());
        let err = result.expect_err("should reject unknown op");
        assert!(err.to_string().contains("unknown operation"));
    }

    #[tokio::test]
    async fn test_git_ops_commit_requires_message() {
        let dir = tempfile::tempdir().expect("failed to create temp dir");
        std::process::Command::new("git")
            .args(["init"])
            .current_dir(dir.path())
            .output()
            .expect("git init should work");

        let ctx = test_ctx_with_dir(dir.path().to_str().expect("valid path"));
        let result = tools::GitOps
            .execute(serde_json::json!({ "operation": "commit" }), &ctx)
            .await;

        assert!(result.is_err());
        let err = result.expect_err("should require message");
        assert!(err.to_string().contains("'message' is required"));
    }

    #[tokio::test]
    async fn test_git_ops_commit_empty_message_rejected() {
        let dir = tempfile::tempdir().expect("failed to create temp dir");
        std::process::Command::new("git")
            .args(["init"])
            .current_dir(dir.path())
            .output()
            .expect("git init should work");

        let ctx = test_ctx_with_dir(dir.path().to_str().expect("valid path"));
        let result = tools::GitOps
            .execute(
                serde_json::json!({ "operation": "commit", "message": "  " }),
                &ctx,
            )
            .await;

        assert!(result.is_err());
        let err = result.expect_err("should reject empty message");
        assert!(err.to_string().contains("cannot be empty"));
    }

    #[tokio::test]
    async fn test_git_ops_diff_in_repo() {
        let dir = tempfile::tempdir().expect("failed to create temp dir");
        std::process::Command::new("git")
            .args(["init"])
            .current_dir(dir.path())
            .output()
            .expect("git init should work");

        let ctx = test_ctx_with_dir(dir.path().to_str().expect("valid path"));
        let result = tools::GitOps
            .execute(serde_json::json!({ "operation": "diff" }), &ctx)
            .await
            .expect("git diff should succeed");

        assert!(result.success);
    }

    #[tokio::test]
    async fn test_git_ops_missing_operation() {
        let dir = tempfile::tempdir().expect("failed to create temp dir");
        let ctx = test_ctx_with_dir(dir.path().to_str().expect("valid path"));
        let result = tools::GitOps.execute(serde_json::json!({}), &ctx).await;

        assert!(result.is_err());
    }

    // ── SearchCode tests ────────────────────────────────────────────────

    #[tokio::test]
    async fn test_search_code_finds_pattern() {
        let dir = tempfile::tempdir().expect("failed to create temp dir");
        std::fs::write(dir.path().join("main.rs"), "fn main() {\n    println!(\"hello\");\n}\n")
            .expect("write test file");
        std::fs::write(dir.path().join("lib.rs"), "pub fn add(a: i32, b: i32) -> i32 { a + b }\n")
            .expect("write test file");

        let ctx = test_ctx_with_dir(dir.path().to_str().expect("valid path"));
        let result = tools::SearchCode
            .execute(serde_json::json!({ "pattern": "fn " }), &ctx)
            .await
            .expect("search should succeed");

        assert!(result.success);
        let data = result.data.expect("should have data");
        assert!(data["total_matches"].as_u64().expect("has count") >= 2);
    }

    #[tokio::test]
    async fn test_search_code_no_matches() {
        let dir = tempfile::tempdir().expect("failed to create temp dir");
        std::fs::write(dir.path().join("a.txt"), "nothing here\n")
            .expect("write test file");

        let ctx = test_ctx_with_dir(dir.path().to_str().expect("valid path"));
        let result = tools::SearchCode
            .execute(serde_json::json!({ "pattern": "zzzzzzz_no_match" }), &ctx)
            .await
            .expect("search should succeed even with no matches");

        assert!(result.success);
        let data = result.data.expect("should have data");
        assert_eq!(data["total_matches"], 0);
    }

    #[tokio::test]
    async fn test_search_code_with_file_type() {
        let dir = tempfile::tempdir().expect("failed to create temp dir");
        std::fs::write(dir.path().join("code.rs"), "fn hello() {}\n")
            .expect("write test file");
        std::fs::write(dir.path().join("data.txt"), "fn hello() {}\n")
            .expect("write test file");

        let ctx = test_ctx_with_dir(dir.path().to_str().expect("valid path"));
        let result = tools::SearchCode
            .execute(
                serde_json::json!({ "pattern": "fn hello", "file_type": "rs" }),
                &ctx,
            )
            .await
            .expect("search should succeed");

        assert!(result.success);
        let data = result.data.expect("should have data");
        assert_eq!(data["total_matches"], 1);
    }

    #[tokio::test]
    async fn test_search_code_empty_pattern_rejected() {
        let dir = tempfile::tempdir().expect("failed to create temp dir");
        let ctx = test_ctx_with_dir(dir.path().to_str().expect("valid path"));
        let result = tools::SearchCode
            .execute(serde_json::json!({ "pattern": "" }), &ctx)
            .await;

        assert!(result.is_err());
        let err = result.expect_err("should reject empty pattern");
        assert!(err.to_string().contains("cannot be empty"));
    }

    // ── Bridge tests ────────────────────────────────────────────────────

    #[tokio::test]
    async fn test_bridge_execute_tool() {
        let registry = Arc::new(ToolRegistry::new());
        register_tools(&registry).await;

        let bridge = bridge::CodeAgentBridge::new_ungated_for_testing(registry);
        let dir = tempfile::tempdir().expect("failed to create temp dir");
        std::fs::write(dir.path().join("test.txt"), "content here\n")
            .expect("write test file");

        let ctx = test_ctx_with_dir(dir.path().to_str().expect("valid path"));
        let result = bridge
            .execute_tool("file_read", serde_json::json!({ "path": "test.txt" }), &ctx)
            .await
            .expect("bridge execute should succeed");

        assert!(result.success);
        assert!(result.output.contains("content here"));
    }

    #[tokio::test]
    async fn test_bridge_tool_not_found() {
        let registry = Arc::new(ToolRegistry::new());
        register_tools(&registry).await;

        let bridge = bridge::CodeAgentBridge::new_ungated_for_testing(registry);
        let dir = tempfile::tempdir().expect("failed to create temp dir");
        let ctx = test_ctx_with_dir(dir.path().to_str().expect("valid path"));

        let result = bridge
            .execute_tool("nonexistent_tool", serde_json::json!({}), &ctx)
            .await;

        assert!(result.is_err());
        let err = result.expect_err("should fail for missing tool");
        assert!(err.to_string().contains("nonexistent_tool"));
    }

    #[tokio::test]
    async fn test_bridge_available_tools() {
        let registry = Arc::new(ToolRegistry::new());
        register_tools(&registry).await;

        let bridge = bridge::CodeAgentBridge::new_ungated_for_testing(registry);
        let tools = bridge.available_tools().await;
        assert_eq!(tools.len(), 6);
    }

    #[tokio::test]
    async fn test_bridge_workspace_context() {
        let dir = tempfile::tempdir().expect("failed to create temp dir");
        std::fs::create_dir_all(dir.path().join("src")).expect("create src dir");
        std::fs::write(dir.path().join("src/main.rs"), "fn main() {}")
            .expect("write test file");
        std::fs::write(dir.path().join("Cargo.toml"), "[package]")
            .expect("write test file");

        let registry = Arc::new(ToolRegistry::new());
        let bridge = bridge::CodeAgentBridge::new_ungated_for_testing(registry);

        let context = bridge
            .get_workspace_context(dir.path().to_str().expect("valid path"))
            .await
            .expect("should get context");

        assert!(context.file_count >= 2);
        assert!(context.top_level_dirs.contains(&"src".to_string()));
    }

    // ── Path traversal prevention ───────────────────────────────────────

    #[tokio::test]
    async fn test_file_read_blocks_path_traversal() {
        let dir = tempfile::tempdir().expect("failed to create temp dir");
        let ctx = test_ctx_with_dir(dir.path().to_str().expect("valid path"));
        let result = tools::FileRead
            .execute(serde_json::json!({ "path": "../../../etc/passwd" }), &ctx)
            .await;

        assert!(result.is_err());
    }

    #[tokio::test]
    async fn test_search_code_blocks_path_traversal() {
        let dir = tempfile::tempdir().expect("failed to create temp dir");
        let ctx = test_ctx_with_dir(dir.path().to_str().expect("valid path"));
        // The path /etc is outside workspace — should be rejected
        let result = tools::SearchCode
            .execute(
                serde_json::json!({ "pattern": "root", "path": "/etc" }),
                &ctx,
            )
            .await;

        assert!(result.is_err());
    }

    // ── AR-B-007 tripwire: relative-branch traversal must be rejected ───────
    // Before the fix the relative branch canonicalized `../../..` and ran grep
    // over it WITHOUT a containment check. Red on the vulnerable code.
    #[tokio::test]
    async fn test_search_code_blocks_relative_traversal_ar_b_007() {
        // Workspace two levels deep so `../..` escapes into an existing dir.
        let root = tempfile::tempdir().expect("failed to create temp dir");
        let ws = root.path().join("a").join("b");
        std::fs::create_dir_all(&ws).expect("mkdir");
        // Plant a canary two levels above the workspace.
        std::fs::write(root.path().join("CANARY.txt"), "TOP-SECRET-agentb")
            .expect("write canary");
        let ctx = test_ctx_with_dir(ws.to_str().expect("valid path"));

        let result = tools::SearchCode
            .execute(
                serde_json::json!({ "pattern": "TOP-SECRET-agentb", "path": "../.." }),
                &ctx,
            )
            .await;

        assert!(
            result.is_err(),
            "relative traversal `../..` must be rejected, got: {result:?}"
        );
    }

    // ── AR-B-006 tripwire: file_write must not escape via a non-existent ─────
    // ancestor `..` chain. Red on the vulnerable code, which materialised the
    // `a/` dir then let the kernel resolve `../../..` outside the workspace.
    #[tokio::test]
    async fn test_file_write_blocks_nonexistent_ancestor_traversal_ar_b_006() {
        // Keep the workspace deep inside the tempdir so any escape lands INSIDE
        // `root` (cleaned up on drop) rather than in shared /tmp.
        let root = tempfile::tempdir().expect("failed to create temp dir");
        let ws = root.path().join("d1").join("d2").join("d3").join("ws");
        std::fs::create_dir_all(&ws).expect("mkdir");
        let ctx = test_ctx_with_dir(ws.to_str().expect("valid path"));

        // `a` does not exist; `a/../../../evil.txt` normalises to
        // root/d1/d2/evil.txt — above the workspace, still inside `root`.
        let escape_target = root.path().join("d1").join("d2").join("evil.txt");
        assert!(!escape_target.exists(), "precondition: escape target absent");

        let result = tools::FileWrite
            .execute(
                serde_json::json!({
                    "path": "a/../../../evil.txt",
                    "content": "OWNED-BY-AGENTB"
                }),
                &ctx,
            )
            .await;

        assert!(
            result.is_err(),
            "traversal write via non-existent ancestor must be rejected, got: {result:?}"
        );
        assert!(
            !escape_target.exists(),
            "file escaped the workspace to {escape_target:?}"
        );
    }
}
