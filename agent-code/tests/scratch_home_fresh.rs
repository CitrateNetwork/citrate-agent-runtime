//! `git_ops` and `shell_exec` run their subprocess with HOME pointed at a scratch directory.
//! That directory must be created fresh: a directory or symlink already sitting at the name the
//! tool would pick is never used.
//!
//! Each test drives the real tool entry point (`AgentTool::execute`). The process temp
//! directory is pointed (via `TMPDIR`) at a private tree created with a unique `dgx-shf-`
//! prefix, so every planted path lives inside that tree and is removed with it. The tests hold
//! one lock while `TMPDIR` is overridden, so they never see each other's value.
//!
//! How "HOME was used" is observed: with the environment cleared, git reads its default
//! exclude file from `$HOME/.config/git/ignore`. The planted HOME carries an ignore file that
//! hides `marker.txt`; the workspace has `marker.txt` untracked. If `git status --porcelain`
//! leaves the marker out, the planted HOME was used.
#![cfg(unix)]

use citrate_agent_code::tools::{GitOps, ShellExec};
use citrate_agent_core::tool::{AgentTool, ToolContext};
use std::os::unix::fs::symlink;
use std::path::{Path, PathBuf};
static TMPDIR_LOCK: tokio::sync::Mutex<()> = tokio::sync::Mutex::const_new(());

/// Counter values the old naming scheme could reach in this test process.
const PLANTED: u64 = 256;

struct Env {
    root: tempfile::TempDir,
    tmp: PathBuf,
    ws: PathBuf,
    old_tmpdir: Option<std::ffi::OsString>,
}

impl Env {
    fn new() -> Self {
        let root = tempfile::Builder::new()
            .prefix("dgx-shf-")
            .tempdir()
            .expect("create private test root");
        let tmp = root.path().join("tmp");
        let ws = root.path().join("ws");
        std::fs::create_dir(&tmp).expect("mkdir tmp");
        std::fs::create_dir(&ws).expect("mkdir ws");
        let st = std::process::Command::new("git")
            .args(["init", "-q"])
            .current_dir(&ws)
            .env_clear()
            .env("PATH", "/usr/local/bin:/usr/bin:/bin")
            .env("HOME", root.path())
            .env("GIT_CONFIG_GLOBAL", "/dev/null")
            .env("GIT_CONFIG_SYSTEM", "/dev/null")
            .status()
            .expect("run git init");
        assert!(st.success(), "git init failed");
        std::fs::write(ws.join("marker.txt"), b"x").expect("write marker");
        let old_tmpdir = std::env::var_os("TMPDIR");
        std::env::set_var("TMPDIR", &tmp);
        assert_eq!(std::env::temp_dir(), tmp, "TMPDIR override did not take");
        Env {
            root,
            tmp,
            ws,
            old_tmpdir,
        }
    }

    fn ctx(&self) -> ToolContext {
        ToolContext {
            session_id: "scratch-home-fresh-test".to_string(),
            wallet_address: None,
            chain_id: 40204,
            workspace_dir: self.ws.to_str().expect("utf-8 temp path").to_string(),
        }
    }

    /// A HOME whose git exclude file hides `marker.txt`.
    fn planted_home(&self, name: &str) -> PathBuf {
        let h = self.root.path().join(name);
        std::fs::create_dir_all(h.join(".config").join("git")).expect("mkdir planted config");
        std::fs::write(h.join(".config").join("git").join("ignore"), b"marker.txt\n")
            .expect("write planted ignore");
        h
    }

    fn predictable(&self, prefix: &str, seq: u64) -> PathBuf {
        self.tmp.join(format!("{prefix}{}-{seq}", std::process::id()))
    }
}

impl Drop for Env {
    fn drop(&mut self) {
        match &self.old_tmpdir {
            Some(v) => std::env::set_var("TMPDIR", v),
            None => std::env::remove_var("TMPDIR"),
        }
    }
}

fn copy_tree(from: &Path, to: &Path) {
    std::fs::create_dir(to).expect("mkdir copy");
    for e in std::fs::read_dir(from).expect("read_dir") {
        let e = e.expect("entry");
        let dst = to.join(e.file_name());
        if e.file_type().expect("file type").is_dir() {
            copy_tree(&e.path(), &dst);
        } else {
            std::fs::copy(e.path(), &dst).expect("copy file");
        }
    }
}

/// Plant a real directory (a copy of the planted HOME) at every predictable name.
fn plant_dirs(env: &Env, prefix: &str, home: &Path) {
    for seq in 0..PLANTED {
        copy_tree(home, &env.predictable(prefix, seq));
    }
}

/// Plant a symlink to the planted HOME at every predictable name.
fn plant_links(env: &Env, prefix: &str, home: &Path) {
    for seq in 0..PLANTED {
        symlink(home, env.predictable(prefix, seq)).expect("plant symlink");
    }
}

fn assert_planted_dirs_intact(env: &Env, prefix: &str) {
    for seq in 0..PLANTED {
        let p = env.predictable(prefix, seq);
        assert!(
            p.join(".config/git/ignore").is_file(),
            "planted directory {} was used and removed by the tool",
            p.display()
        );
    }
}

fn assert_planted_links_intact(env: &Env, prefix: &str, home: &Path) {
    for seq in 0..PLANTED {
        let p = env.predictable(prefix, seq);
        let m = std::fs::symlink_metadata(&p).expect("planted link still there");
        assert!(m.file_type().is_symlink(), "planted link {} replaced", p.display());
    }
    assert!(home.join(".config/git/ignore").is_file(), "link target was touched");
}

async fn git_ops_status(env: &Env) -> String {
    let r = GitOps
        .execute(serde_json::json!({"operation": "status"}), &env.ctx())
        .await
        .expect("git_ops status runs");
    assert!(r.success, "git_ops status failed: {}", r.output);
    r.output
}

async fn shell_git_status(env: &Env) -> String {
    let r = ShellExec
        .execute(
            serde_json::json!({"command": "git status --porcelain"}),
            &env.ctx(),
        )
        .await
        .expect("shell_exec runs");
    r.output
}

/// Negative control: with HOME pointed straight at the planted directory, git hides the marker.
/// This proves the observation method detects a used HOME.
#[tokio::test]
async fn control_planted_home_hides_marker() {
    let _g = TMPDIR_LOCK.lock().await;
    let env = Env::new();
    let home = env.planted_home("control-home");
    let out = std::process::Command::new("git")
        .args(["status", "--porcelain"])
        .current_dir(&env.ws)
        .env_clear()
        .env("PATH", "/usr/local/bin:/usr/bin:/bin")
        .env("HOME", &home)
        .env("GIT_CONFIG_GLOBAL", "/dev/null")
        .env("GIT_CONFIG_SYSTEM", "/dev/null")
        .output()
        .expect("run git status");
    let s = String::from_utf8_lossy(&out.stdout);
    assert!(!s.contains("marker.txt"), "control: planted ignore not honoured: {s}");
}

#[tokio::test]
async fn git_ops_ignores_pre_created_home_dir() {
    let _g = TMPDIR_LOCK.lock().await;
    let env = Env::new();
    let home = env.planted_home("planted-home");
    plant_dirs(&env, "citrate-gitops-home-", &home);
    let out = git_ops_status(&env).await;
    assert!(
        out.contains("marker.txt"),
        "git_ops ran with a pre-existing directory as HOME (marker hidden): {out}"
    );
    assert_planted_dirs_intact(&env, "citrate-gitops-home-");
}

#[tokio::test]
async fn git_ops_does_not_follow_planted_home_link() {
    let _g = TMPDIR_LOCK.lock().await;
    let env = Env::new();
    let home = env.planted_home("planted-home");
    plant_links(&env, "citrate-gitops-home-", &home);
    let out = git_ops_status(&env).await;
    assert!(
        out.contains("marker.txt"),
        "git_ops followed a planted link as HOME (marker hidden): {out}"
    );
    assert_planted_links_intact(&env, "citrate-gitops-home-", &home);
}

#[tokio::test]
async fn shell_exec_ignores_pre_created_home_dir() {
    let _g = TMPDIR_LOCK.lock().await;
    let env = Env::new();
    let home = env.planted_home("planted-home");
    plant_dirs(&env, "citrate-shell-home-", &home);
    let out = shell_git_status(&env).await;
    assert!(
        out.contains("marker.txt"),
        "shell_exec ran with a pre-existing directory as HOME (marker hidden): {out}"
    );
    assert_planted_dirs_intact(&env, "citrate-shell-home-");
}

#[tokio::test]
async fn shell_exec_does_not_follow_planted_home_link() {
    let _g = TMPDIR_LOCK.lock().await;
    let env = Env::new();
    let home = env.planted_home("planted-home");
    plant_links(&env, "citrate-shell-home-", &home);
    let out = shell_git_status(&env).await;
    assert!(
        out.contains("marker.txt"),
        "shell_exec followed a planted link as HOME (marker hidden): {out}"
    );
    assert_planted_links_intact(&env, "citrate-shell-home-", &home);
}

/// The scratch HOME is gone once the call returns: nothing new is left under the temp dir.
#[tokio::test]
async fn scratch_homes_are_removed_after_each_call() {
    let _g = TMPDIR_LOCK.lock().await;
    let env = Env::new();
    git_ops_status(&env).await;
    shell_git_status(&env).await;
    let left: Vec<_> = std::fs::read_dir(&env.tmp)
        .expect("read tmp")
        .map(|e| e.expect("entry").file_name())
        .collect();
    assert!(left.is_empty(), "scratch HOME left behind: {left:?}");
}
