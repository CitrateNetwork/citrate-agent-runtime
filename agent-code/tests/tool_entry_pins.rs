//! Pins at the tool `execute` entry points of `file_write`, `shell_exec` and
//! `git_ops`.
//!
//! * `file_write` must refuse an escaping path BEFORE it creates anything:
//!   the post-`create_dir_all` re-check also refuses, but only after the
//!   directories already exist outside the workspace.
//! * `shell_exec` and `git_ops` must not hand the caller's environment or home
//!   directory to the spawned process.
//!
//! This binary sets `HOME` (and git's env-config variables) to fixtures under
//! a temp dir once, before any test runs, so nothing here reads or writes the
//! real home directory.

use std::path::{Path, PathBuf};
use std::sync::OnceLock;

use citrate_agent_code::tools::{FileWrite, GitOps, ShellExec};
use citrate_agent_core::tool::{AgentTool, ToolContext};

/// The fake home every test in this binary runs under, with a `.gitconfig`
/// naming an identity no isolated process should ever see.
fn fake_home() -> &'static Path {
    static HOME: OnceLock<tempfile::TempDir> = OnceLock::new();
    HOME.get_or_init(|| {
        let dir = tempfile::tempdir().expect("fake home");
        std::fs::write(
            dir.path().join(".gitconfig"),
            "[user]\n\tname = HOME-LEAK\n\temail = home-leak@example.invalid\n",
        )
        .expect("write fake .gitconfig");
        // Edition 2021: set_var is safe. Done once, before any spawn below.
        std::env::set_var("HOME", dir.path());
        // git also reads config from the environment; a process that inherits
        // the caller's environment sees this identity.
        std::env::set_var("GIT_CONFIG_COUNT", "2");
        std::env::set_var("GIT_CONFIG_KEY_0", "user.name");
        std::env::set_var("GIT_CONFIG_VALUE_0", "ENV-LEAK");
        std::env::set_var("GIT_CONFIG_KEY_1", "user.email");
        std::env::set_var("GIT_CONFIG_VALUE_1", "env-leak@example.invalid");
        dir
    })
    .path()
}

fn ctx(dir: &Path) -> ToolContext {
    ToolContext {
        session_id: "pin".to_string(),
        wallet_address: None,
        chain_id: 0,
        workspace_dir: dir.to_str().expect("utf8 path").to_string(),
    }
}

/// `<root>/ws` as the workspace, so anything that escapes lands inside
/// `<root>` (a temp dir) and is visible to the assertions.
fn workspace() -> (tempfile::TempDir, PathBuf) {
    let root = tempfile::tempdir().expect("tempdir");
    let ws = root.path().join("ws");
    std::fs::create_dir_all(&ws).expect("mkdir ws");
    (root, ws)
}

// ── file_write ────────────────────────────────────────────────────────────

/// A `..` chain through directories that do not exist yet is refused, and no
/// directory is created outside the workspace on the way.
#[tokio::test]
async fn file_write_traversal_is_refused_before_any_directory_is_created() {
    fake_home();
    let (root, ws) = workspace();
    let res = FileWrite
        .execute(
            serde_json::json!({"path": "a/b/../../../outside/x/f.txt", "content": "x"}),
            &ctx(&ws),
        )
        .await;
    assert!(res.is_err(), "escaping write must be refused: {res:?}");
    assert!(
        !root.path().join("outside").exists(),
        "a directory was created outside the workspace before the refusal"
    );
    assert!(
        !ws.join("a").exists(),
        "nothing is created for a refused write"
    );
}

/// A symlinked directory inside the workspace that points outside it: a
/// write under it is refused before `create_dir_all` materialises anything
/// in the link's target.
#[cfg(unix)]
#[tokio::test]
async fn file_write_through_an_escaping_dir_symlink_creates_nothing_outside() {
    fake_home();
    let (root, ws) = workspace();
    let outside = root.path().join("outside_dir");
    std::fs::create_dir_all(&outside).expect("mkdir outside");
    std::os::unix::fs::symlink(&outside, ws.join("link")).expect("symlink");
    let res = FileWrite
        .execute(
            serde_json::json!({"path": "link/new/f.txt", "content": "x"}),
            &ctx(&ws),
        )
        .await;
    assert!(
        res.is_err(),
        "write through an escaping symlink must be refused: {res:?}"
    );
    assert!(
        !outside.join("new").exists(),
        "a directory was created in the symlink target outside the workspace"
    );
}

/// Control: an ordinary nested write inside the workspace still works.
#[tokio::test]
async fn file_write_inside_the_workspace_still_works() {
    fake_home();
    let (_root, ws) = workspace();
    FileWrite
        .execute(
            serde_json::json!({"path": "src/new/f.txt", "content": "ok"}),
            &ctx(&ws),
        )
        .await
        .expect("in-workspace write");
    assert_eq!(
        std::fs::read_to_string(ws.join("src/new/f.txt")).unwrap(),
        "ok"
    );
}

// ── shell_exec ────────────────────────────────────────────────────────────

/// The spawned process gets an isolated HOME, never the caller's. Python
/// reports its user base from `HOME`.
#[tokio::test]
async fn shell_exec_does_not_pass_the_callers_home() {
    let home = fake_home().to_str().expect("utf8").to_string();
    let (_root, ws) = workspace();
    let out = ShellExec
        .execute(
            serde_json::json!({"command": "python3 -m site --user-base"}),
            &ctx(&ws),
        )
        .await
        .expect("python3 runs");
    assert!(out.success, "python3 -m site failed: {}", out.output);
    assert!(
        !out.output.contains(&home),
        "the spawned process saw the caller's HOME ({home}): {}",
        out.output
    );
}

/// The spawned process starts from a cleared environment: neither the
/// caller's git env-config nor the caller's `~/.gitconfig` is visible.
#[tokio::test]
async fn shell_exec_does_not_pass_the_callers_environment_or_git_config() {
    fake_home();
    let (_root, ws) = workspace();
    let out = ShellExec
        .execute(
            serde_json::json!({"command": "git config --get user.name"}),
            &ctx(&ws),
        )
        .await
        .expect("git runs");
    assert!(
        !out.output.contains("ENV-LEAK"),
        "the caller's environment reached the spawned process: {}",
        out.output
    );
    assert!(
        !out.output.contains("HOME-LEAK"),
        "the caller's ~/.gitconfig reached the spawned process: {}",
        out.output
    );
}

// ── git_ops ───────────────────────────────────────────────────────────────

/// `git_ops commit` runs git with an isolated HOME and pinned config, so the
/// commit can never take the caller's configured identity.
#[tokio::test]
async fn git_ops_commit_does_not_use_the_callers_git_identity() {
    fake_home();
    let (root, ws) = workspace();
    let scratch_home = root.path().join("init-home");
    std::fs::create_dir_all(&scratch_home).expect("mkdir");
    let git = |args: &[&str]| {
        std::process::Command::new("git")
            .args(args)
            .current_dir(&ws)
            .env_clear()
            .env("PATH", "/usr/bin:/bin")
            .env("HOME", &scratch_home)
            .env("GIT_CONFIG_GLOBAL", "/dev/null")
            .env("GIT_CONFIG_SYSTEM", "/dev/null")
            .output()
            .expect("git")
    };
    assert!(git(&["init", "-q"]).status.success());
    std::fs::write(ws.join("f.txt"), "x").expect("write");

    // Whatever the outcome (git may refuse with no identity, or fall back to
    // an auto-detected one), the caller's identity is never used.
    let _ = GitOps
        .execute(
            serde_json::json!({"operation": "commit", "message": "pin"}),
            &ctx(&ws),
        )
        .await;
    let log = git(&["log", "--format=%an <%ae>"]);
    let authors = String::from_utf8_lossy(&log.stdout);
    assert!(
        !authors.contains("HOME-LEAK") && !authors.contains("ENV-LEAK"),
        "git_ops committed as the caller's configured identity: {authors}"
    );
}
