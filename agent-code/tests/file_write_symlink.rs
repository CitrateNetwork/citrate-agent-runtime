//! `file_write` / `file_edit` must not write through a symbolic link, and must
//! not write to a file that is also reachable from outside the workspace.
//!
//! Every test drives the real tool entry point (`AgentTool::execute`) against a
//! private temporary tree created with a unique `dgx-fw-` prefix. The "outside"
//! file each test protects lives in that same tree (a sibling of the
//! workspace), never at a real host path, and is removed with the tree when the
//! `TempDir` drops.
//!
//! Policy pinned here (documented in `agent-code/src/tools/safe_write.rs`):
//! * a symlink as the final path component is refused, wherever it points
//!   (outside file, outside directory, dangling, or another file inside the
//!   workspace);
//! * a symlink as an intermediate directory component is refused, wherever it
//!   points;
//! * a regular file with more than one hard link is refused, since the other
//!   name may be outside the workspace;
//! * swapping the target between a regular file and a symlink while writes are
//!   running never lets a write land outside.
#![cfg(unix)]

use citrate_agent_code::tools::{FileEdit, FileWrite};
use citrate_agent_core::error::AgentError;
use citrate_agent_core::tool::{AgentTool, ToolContext, ToolResult};
use std::os::unix::fs::symlink;
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;

const ORIGINAL: &str = "ORIGINAL-CONTENT";
const PAYLOAD: &str = "WRITTEN-BY-TOOL";

/// A private tree: `<root>/ws` is the workspace, `<root>/outside` is a sibling
/// directory holding `victim.txt` (the file no write may change).
struct Tree {
    _root: tempfile::TempDir,
    ws: PathBuf,
    outside: PathBuf,
    victim: PathBuf,
}

fn tree() -> Tree {
    let root = tempfile::Builder::new()
        .prefix("dgx-fw-")
        .tempdir()
        .expect("create temp tree");
    let ws = root.path().join("ws");
    let outside = root.path().join("outside");
    std::fs::create_dir(&ws).expect("mkdir ws");
    std::fs::create_dir(&outside).expect("mkdir outside");
    let victim = outside.join("victim.txt");
    std::fs::write(&victim, ORIGINAL).expect("write victim");
    Tree {
        _root: root,
        ws,
        outside,
        victim,
    }
}

fn ctx(ws: &Path) -> ToolContext {
    ToolContext {
        session_id: "file-write-symlink-test".to_string(),
        wallet_address: None,
        chain_id: 40204,
        workspace_dir: ws.to_str().expect("utf-8 temp path").to_string(),
    }
}

fn refused(r: &Result<ToolResult, AgentError>) -> bool {
    match r {
        Err(_) => true,
        Ok(res) => !res.success,
    }
}

async fn write(ws: &Path, path: &str) -> Result<ToolResult, AgentError> {
    FileWrite
        .execute(
            serde_json::json!({ "path": path, "content": PAYLOAD }),
            &ctx(ws),
        )
        .await
}

fn read(p: &Path) -> String {
    std::fs::read_to_string(p).expect("read file")
}

fn outside_entries(t: &Tree) -> Vec<String> {
    let mut v: Vec<String> = std::fs::read_dir(&t.outside)
        .expect("read outside dir")
        .map(|e| {
            e.expect("dir entry")
                .file_name()
                .to_string_lossy()
                .into_owned()
        })
        .collect();
    v.sort();
    v
}

// ── final component ────────────────────────────────────────────────────────

#[tokio::test]
async fn refuses_final_symlink_to_outside_file() {
    let t = tree();
    symlink(&t.victim, t.ws.join("target.txt")).expect("plant symlink");

    let r = write(&t.ws, "target.txt").await;

    assert!(
        refused(&r),
        "write through a final symlink must be refused, got {r:?}"
    );
    assert_eq!(read(&t.victim), ORIGINAL, "the outside file changed");
}

#[tokio::test]
async fn refuses_final_symlink_to_outside_file_by_absolute_path() {
    let t = tree();
    let link = t.ws.join("target.txt");
    symlink(&t.victim, &link).expect("plant symlink");
    let abs = t.ws.canonicalize().expect("canon ws").join("target.txt");

    let r = write(&t.ws, abs.to_str().expect("utf-8")).await;

    assert!(
        refused(&r),
        "absolute-path write through a symlink must be refused, got {r:?}"
    );
    assert_eq!(read(&t.victim), ORIGINAL, "the outside file changed");
}

#[tokio::test]
async fn refuses_final_symlink_to_outside_directory() {
    let t = tree();
    symlink(&t.outside, t.ws.join("out")).expect("plant dir symlink");
    let before = outside_entries(&t);

    let r_link = write(&t.ws, "out").await;
    let r_into = write(&t.ws, "out/new.txt").await;

    assert!(
        refused(&r_link),
        "write to a directory symlink must be refused, got {r_link:?}"
    );
    assert!(
        refused(&r_into),
        "write through a directory symlink must be refused, got {r_into:?}"
    );
    assert_eq!(
        outside_entries(&t),
        before,
        "a file appeared outside the workspace"
    );
    assert_eq!(read(&t.victim), ORIGINAL);
}

#[tokio::test]
async fn refuses_dangling_final_symlink() {
    let t = tree();
    let would_be = t.outside.join("created.txt");
    symlink(&would_be, t.ws.join("dangling.txt")).expect("plant dangling symlink");

    let r = write(&t.ws, "dangling.txt").await;

    assert!(
        refused(&r),
        "write through a dangling symlink must be refused, got {r:?}"
    );
    assert!(
        !would_be.exists(),
        "the dangling symlink's target was created outside"
    );
}

#[tokio::test]
async fn refuses_final_symlink_pointing_inside_workspace() {
    // Policy: refused. A link inside the workspace can be retargeted at any
    // time, so the tool writes only to the name it was given.
    let t = tree();
    let real = t.ws.join("real.txt");
    std::fs::write(&real, ORIGINAL).expect("write real");
    symlink(&real, t.ws.join("alias.txt")).expect("plant inside symlink");

    let r = write(&t.ws, "alias.txt").await;

    assert!(
        refused(&r),
        "write through an inside symlink must be refused, got {r:?}"
    );
    assert_eq!(read(&real), ORIGINAL, "the link target changed");
}

#[tokio::test]
async fn refuses_hardlinked_target() {
    // Policy: a regular file with more than one link is refused, because the
    // other name can be outside the workspace and the write would change it.
    let t = tree();
    let hl = t.ws.join("hl.txt");
    std::fs::hard_link(&t.victim, &hl).expect("plant hard link");

    let r = write(&t.ws, "hl.txt").await;

    assert!(
        refused(&r),
        "write to a multiply-linked file must be refused, got {r:?}"
    );
    assert_eq!(
        read(&t.victim),
        ORIGINAL,
        "the outside file changed via its hard link"
    );
}

// ── intermediate components ────────────────────────────────────────────────

#[tokio::test]
async fn refuses_intermediate_symlink_inside_workspace() {
    // Policy: refused, same reasoning as the final component.
    let t = tree();
    let real_dir = t.ws.join("real_dir");
    std::fs::create_dir(&real_dir).expect("mkdir real_dir");
    symlink(&real_dir, t.ws.join("alias_dir")).expect("plant dir symlink");

    let r = write(&t.ws, "alias_dir/f.txt").await;

    assert!(
        refused(&r),
        "write through an intermediate symlink must be refused, got {r:?}"
    );
    assert!(
        !real_dir.join("f.txt").exists(),
        "the write went through the link"
    );
}

#[tokio::test]
async fn refuses_deep_intermediate_symlink_to_outside() {
    let t = tree();
    std::fs::create_dir_all(t.ws.join("a/b")).expect("mkdir a/b");
    symlink(&t.outside, t.ws.join("a/b/c")).expect("plant deep dir symlink");
    let before = outside_entries(&t);

    let r = write(&t.ws, "a/b/c/new_dir/f.txt").await;

    assert!(
        refused(&r),
        "write through a deep intermediate symlink must be refused, got {r:?}"
    );
    assert_eq!(
        outside_entries(&t),
        before,
        "a directory or file appeared outside"
    );
}

// ── ordinary behaviour is kept ─────────────────────────────────────────────

#[tokio::test]
async fn ordinary_writes_still_work() {
    let t = tree();
    let r_new = write(&t.ws, "deep/nested/new.txt").await;
    assert!(
        !refused(&r_new),
        "creating a nested file must work, got {r_new:?}"
    );
    assert_eq!(read(&t.ws.join("deep/nested/new.txt")), PAYLOAD);

    std::fs::write(t.ws.join("exists.txt"), "a much longer original body").expect("seed");
    let r_over = write(&t.ws, "exists.txt").await;
    assert!(
        !refused(&r_over),
        "overwriting a regular file must work, got {r_over:?}"
    );
    assert_eq!(
        read(&t.ws.join("exists.txt")),
        PAYLOAD,
        "overwrite must truncate"
    );

    let abs = t.ws.canonicalize().expect("canon ws").join("abs.txt");
    let r_abs = write(&t.ws, abs.to_str().expect("utf-8")).await;
    assert!(
        !refused(&r_abs),
        "absolute path inside the workspace must work, got {r_abs:?}"
    );
    assert_eq!(read(&abs), PAYLOAD);
}

#[tokio::test]
async fn workspace_reached_through_a_symlink_still_works() {
    // The workspace root itself may be a symlinked path (e.g. /tmp -> /private/tmp
    // on macOS). That is resolved once, up front, and is not a refusal.
    let t = tree();
    let ws_link = t.outside.join("ws_link");
    symlink(&t.ws, &ws_link).expect("symlink to workspace");

    let r = write(&ws_link, "via_link.txt").await;

    assert!(
        !refused(&r),
        "a symlinked workspace root must be usable, got {r:?}"
    );
    assert_eq!(read(&t.ws.join("via_link.txt")), PAYLOAD);
}

// ── races ──────────────────────────────────────────────────────────────────

/// Repeatedly swap `ws/<name>` between a regular file (or directory) and a
/// symlink to `link_to`, using atomic renames, until `stop` is set.
fn spawn_swapper(
    ws: PathBuf,
    name: &'static str,
    link_to: PathBuf,
    as_dir: bool,
    stop: Arc<AtomicBool>,
) -> std::thread::JoinHandle<u64> {
    std::thread::spawn(move || {
        let target = ws.join(name);
        let tmp_link = ws.join(format!(".swap-link-{name}"));
        let tmp_real = ws.join(format!(".swap-real-{name}"));
        let mut swaps = 0u64;
        while !stop.load(Ordering::Relaxed) {
            let _ = std::fs::remove_file(&tmp_link);
            if symlink(&link_to, &tmp_link).is_ok() && std::fs::rename(&tmp_link, &target).is_ok() {
                swaps += 1;
            }
            if as_dir {
                // rename(dir, path) cannot replace a symlink with a directory on
                // every platform; remove the link first, then move a dir in.
                let _ = std::fs::create_dir(&tmp_real);
                let _ = std::fs::remove_file(&target);
                if std::fs::rename(&tmp_real, &target).is_ok() {
                    swaps += 1;
                }
                // Clear out anything the tool wrote so the next rename works.
                let _ = std::fs::remove_file(target.join("f.txt"));
                let _ = std::fs::remove_dir(&target);
            } else {
                let _ = std::fs::write(&tmp_real, "regular");
                if std::fs::rename(&tmp_real, &target).is_ok() {
                    swaps += 1;
                }
            }
        }
        swaps
    })
}

const RACE_WRITES: usize = 3_000;

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn race_final_component_swap_never_writes_outside() {
    let t = tree();
    std::fs::write(t.ws.join("target.txt"), "regular").expect("seed target");
    let stop = Arc::new(AtomicBool::new(false));
    let h = spawn_swapper(
        t.ws.clone(),
        "target.txt",
        t.victim.clone(),
        false,
        stop.clone(),
    );

    let mut escaped_at = None;
    for i in 0..RACE_WRITES {
        let _ = write(&t.ws, "target.txt").await;
        if read(&t.victim) != ORIGINAL {
            escaped_at = Some(i);
            break;
        }
    }
    stop.store(true, Ordering::Relaxed);
    let swaps = h.join().expect("swapper thread");

    assert!(
        swaps > 0,
        "the swapper never ran; the race was not exercised"
    );
    assert_eq!(
        escaped_at, None,
        "a write landed outside the workspace (after {swaps} swaps)"
    );
    assert_eq!(read(&t.victim), ORIGINAL);
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn race_intermediate_component_swap_never_writes_outside() {
    let t = tree();
    let stop = Arc::new(AtomicBool::new(false));
    let h = spawn_swapper(t.ws.clone(), "d", t.outside.clone(), true, stop.clone());
    let escaped = t.outside.join("f.txt");

    let mut escaped_at = None;
    for i in 0..RACE_WRITES {
        let _ = write(&t.ws, "d/f.txt").await;
        if escaped.exists() {
            escaped_at = Some(i);
            break;
        }
    }
    stop.store(true, Ordering::Relaxed);
    let swaps = h.join().expect("swapper thread");

    assert!(
        swaps > 0,
        "the swapper never ran; the race was not exercised"
    );
    assert_eq!(
        escaped_at, None,
        "a write landed outside the workspace (after {swaps} swaps)"
    );
}

// ── file_edit (same write path) ────────────────────────────────────────────

async fn edit(ws: &Path, path: &str) -> Result<ToolResult, AgentError> {
    FileEdit
        .execute(
            serde_json::json!({ "path": path, "old_string": "CONTENT", "new_string": "EDITED" }),
            &ctx(ws),
        )
        .await
}

#[tokio::test]
async fn file_edit_refuses_symlink_pointing_inside_workspace() {
    let t = tree();
    let real = t.ws.join("real.txt");
    std::fs::write(&real, ORIGINAL).expect("write real");
    symlink(&real, t.ws.join("alias.txt")).expect("plant inside symlink");

    let r = edit(&t.ws, "alias.txt").await;

    assert!(
        refused(&r),
        "edit through a symlink must be refused, got {r:?}"
    );
    assert_eq!(read(&real), ORIGINAL, "the link target changed");
}

#[tokio::test]
async fn file_edit_refuses_hardlinked_target() {
    let t = tree();
    std::fs::hard_link(&t.victim, t.ws.join("hl.txt")).expect("plant hard link");

    let r = edit(&t.ws, "hl.txt").await;

    assert!(
        refused(&r),
        "edit of a multiply-linked file must be refused, got {r:?}"
    );
    assert_eq!(
        read(&t.victim),
        ORIGINAL,
        "the outside file changed via its hard link"
    );
}

#[tokio::test]
async fn file_edit_still_edits_regular_files() {
    let t = tree();
    let f = t.ws.join("plain.txt");
    std::fs::write(&f, ORIGINAL).expect("seed");

    let r = edit(&t.ws, "plain.txt").await;

    assert!(!refused(&r), "editing a regular file must work, got {r:?}");
    assert_eq!(read(&f), "ORIGINAL-EDITED");
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn race_file_edit_swap_never_writes_outside() {
    let t = tree();
    std::fs::write(t.ws.join("target.txt"), "regular CONTENT").expect("seed target");
    let stop = Arc::new(AtomicBool::new(false));
    // Swap to a symlink pointing at the victim; the swapper's regular file has
    // no "CONTENT" match, so edits succeed only when they open the victim.
    let h = spawn_swapper(
        t.ws.clone(),
        "target.txt",
        t.victim.clone(),
        false,
        stop.clone(),
    );

    let mut escaped_at = None;
    for i in 0..RACE_WRITES {
        let _ = edit(&t.ws, "target.txt").await;
        if read(&t.victim) != ORIGINAL {
            escaped_at = Some(i);
            break;
        }
    }
    stop.store(true, Ordering::Relaxed);
    let swaps = h.join().expect("swapper thread");

    assert!(
        swaps > 0,
        "the swapper never ran; the race was not exercised"
    );
    assert_eq!(
        escaped_at, None,
        "an edit landed outside the workspace (after {swaps} swaps)"
    );
}
