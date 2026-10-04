//! HUP-S2.9 — every agent write a member can trigger is undoable.
//!
//! BDD map (US-2.9 / WP S2.9 "undo checkpoints for agent file writes"):
//! - `file_write` (the grant-session write tool) goes through the checkpoint store:
//!   `file_write_is_checkpointed_and_undoable`, `file_write_without_an_undo_store_writes_nothing`.
//! - `sheet_write` likewise: `sheet_write_is_checkpointed_and_undoable`,
//!   `sheet_write_without_an_undo_store_writes_nothing`.
//! - The deny list, symlink leaves and multiply-linked files are refused before anything is
//!   snapshotted: `refused_writes_leave_no_snapshot`.
//! - The checkpointed `fs_*` tools run on the session's grant document (core's grant store), with
//!   no `CITRATE_HERMES_FILES` or grants file: `a_grant_session_with_undo_offers_the_fs_tools_on_its_grants`.
//! - Without an undo store, a grant session offers no `fs_*` tool:
//!   `a_grant_session_without_undo_offers_no_fs_tools`.

#![cfg(unix)]

use super::files::{GrantSource, UndoScope, TOOL_NAMES as FS_TOOL_NAMES};
use super::grants::*;
use super::sheets::*;
use super::*;
use citrate_agent_checkpoints::{CheckpointStore, Config, SessionId};
use citrate_agent_grants::{Access, FolderGrants, GrantRequest};
use citrate_agent_loop::{
    AssistantTurn, CompletionRequest, LlmClient, LlmError, ToolCall, ToolHost, ToolOutcome,
};
use std::os::unix::fs::symlink;
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::Mutex;
use std::time::Duration;

const MEMBER: &str = "0x00000000000000000000000000000000000000cc";
const SESSION: &str = "s1-undo";
static N: AtomicUsize = AtomicUsize::new(0);

fn now() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap()
        .as_secs()
}

/// `base/home/proj` (granted read + write), `base/home/.ssh`, `base/home/other`, and the
/// checkpoint store at `base/ckpt` (outside the home, as core's app data is).
struct Fx {
    base: PathBuf,
    store: Arc<CheckpointStore>,
}
impl Fx {
    fn new() -> Self {
        let base = std::env::temp_dir().join(format!(
            "citrate-sidecar-undo-writes-{}-{}",
            std::process::id(),
            N.fetch_add(1, Ordering::SeqCst)
        ));
        let _ = std::fs::remove_dir_all(&base);
        for d in ["home/proj/src", "home/other", "home/.ssh", "ckpt"] {
            std::fs::create_dir_all(base.join(d)).unwrap();
        }
        let base = base.canonicalize().unwrap();
        std::fs::write(base.join("home/proj/src/main.sol"), "contract A {}").unwrap();
        std::fs::write(base.join("home/proj/q3.csv"), "item,cost\npaper,4.5\n").unwrap();
        std::fs::write(base.join("home/other/notes.txt"), "not granted").unwrap();
        std::fs::write(base.join("home/.ssh/id_ed25519"), "do-not-snapshot").unwrap();
        let store = Arc::new(CheckpointStore::open(&base.join("ckpt"), Config::default()).unwrap());
        Fx { base, store }
    }
    fn home(&self) -> PathBuf {
        self.base.join("home")
    }
    fn proj(&self) -> PathBuf {
        self.base.join("home/proj")
    }
    fn doc(&self, f: impl FnOnce(&mut FolderGrants)) -> serde_json::Value {
        let mut g = FolderGrants::new(self.home(), self.home());
        f(&mut g);
        serde_json::to_value(g.state()).unwrap()
    }
    fn rw(&self) -> serde_json::Value {
        self.doc(|g| {
            g.grant(folder(&self.proj(), Access::Read), now()).unwrap();
            g.grant(folder(&self.proj(), Access::Write), now()).unwrap();
        })
    }
    fn grants(&self, doc: &serde_json::Value) -> Arc<SessionGrants> {
        let g = SessionGrants::empty(self.home());
        g.replace(doc).unwrap();
        Arc::new(g)
    }
    fn undo(&self) -> UndoScope {
        UndoScope::new(self.store.clone(), SESSION).unwrap()
    }
    fn steps(&self) -> usize {
        self.store
            .steps(&SessionId::new(SESSION).unwrap())
            .map(|s| s.len())
            .unwrap_or(0)
    }
    /// Every byte the checkpoint store holds, concatenated.
    fn store_bytes(&self) -> Vec<u8> {
        let mut out = Vec::new();
        let mut stack = vec![self.base.join("ckpt")];
        while let Some(d) = stack.pop() {
            for e in std::fs::read_dir(&d).unwrap().flatten() {
                let p = e.path();
                if p.is_dir() {
                    stack.push(p);
                } else if let Ok(b) = std::fs::read(&p) {
                    out.extend(b);
                }
            }
        }
        out
    }
}
impl Drop for Fx {
    fn drop(&mut self) {
        let _ = std::fs::remove_dir_all(&self.base);
    }
}

fn folder(root: &Path, access: Access) -> GrantRequest {
    GrantRequest::folder(root, access, MEMBER, "work on the project")
}

fn call(tool: &str, args: serde_json::Value) -> ToolCall {
    ToolCall {
        id: "u1".into(),
        name: tool.into(),
        arguments: args.to_string(),
    }
}

fn ok_json(o: &ToolOutcome) -> serde_json::Value {
    match o {
        ToolOutcome::Ok(b) => serde_json::from_str(b).unwrap(),
        other => panic!("expected ok, got {other:?}"),
    }
}

fn contains(hay: &[u8], needle: &[u8]) -> bool {
    hay.windows(needle.len()).any(|w| w == needle)
}

#[test]
fn file_write_is_checkpointed_and_undoable() {
    let fx = Fx::new();
    let host = FileToolHost::new(fx.grants(&fx.rw())).with_undo(fx.undo());
    let main = fx.proj().join("src/main.sol");
    let v = ok_json(&host.execute(&call(
        FILE_WRITE_TOOL,
        serde_json::json!({ "path": main, "content": "contract B {}" }),
    )));
    assert_eq!(v["written"], true);
    assert_eq!(v["checkpoint"]["session"], SESSION);
    let seq = v["checkpoint"]["seq"].as_u64().unwrap();
    assert_eq!(v["paths"][0], main.to_string_lossy().as_ref());
    assert_eq!(std::fs::read_to_string(&main).unwrap(), "contract B {}");
    // A new file is checkpointed too (undo removes it).
    let fresh = fx.proj().join("src/New.sol");
    let v2 = ok_json(&host.execute(&call(
        FILE_WRITE_TOOL,
        serde_json::json!({ "path": fresh, "content": "contract N {}" }),
    )));
    let seq2 = v2["checkpoint"]["seq"].as_u64().unwrap();
    assert_eq!(fx.steps(), 2);

    let sid = SessionId::new(SESSION).unwrap();
    fx.store.undo_step(&sid, seq2).unwrap();
    assert!(!fresh.exists());
    fx.store.undo_step(&sid, seq).unwrap();
    assert_eq!(std::fs::read_to_string(&main).unwrap(), "contract A {}");
}

#[test]
fn file_write_without_an_undo_store_writes_nothing() {
    let fx = Fx::new();
    let host = FileToolHost::new(fx.grants(&fx.rw()));
    let p = fx.proj().join("src/New.sol");
    let out = host.execute(&call(
        FILE_WRITE_TOOL,
        serde_json::json!({ "path": p, "content": "x" }),
    ));
    match out {
        ToolOutcome::Denied(why) => assert!(why.contains("undo"), "{why}"),
        other => panic!("expected a refusal, got {other:?}"),
    }
    assert!(!p.exists());
}

#[test]
fn sheet_write_is_checkpointed_and_undoable() {
    let fx = Fx::new();
    let host = SheetToolHost::new(fx.grants(&fx.rw())).with_undo(fx.undo());
    let csv = fx.proj().join("q3.csv");
    let v = ok_json(&host.execute(&call(
        SHEET_WRITE_TOOL,
        serde_json::json!({ "path": csv, "rows": [["item", "cost"], ["ink", 9]] }),
    )));
    assert_eq!(v["written"], true);
    assert_eq!(v["checkpoint"]["session"], SESSION);
    let seq = v["checkpoint"]["seq"].as_u64().unwrap();
    assert!(std::fs::read_to_string(&csv).unwrap().contains("ink"));
    fx.store
        .undo_step(&SessionId::new(SESSION).unwrap(), seq)
        .unwrap();
    assert_eq!(
        std::fs::read_to_string(&csv).unwrap(),
        "item,cost\npaper,4.5\n"
    );
}

#[test]
fn sheet_write_without_an_undo_store_writes_nothing() {
    let fx = Fx::new();
    let host = SheetToolHost::new(fx.grants(&fx.rw()));
    let csv = fx.proj().join("q3.csv");
    let out = host.execute(&call(
        SHEET_WRITE_TOOL,
        serde_json::json!({ "path": csv, "rows": [["a"]] }),
    ));
    assert!(matches!(out, ToolOutcome::Denied(_)), "{out:?}");
    assert_eq!(
        std::fs::read_to_string(&csv).unwrap(),
        "item,cost\npaper,4.5\n"
    );
}

#[test]
fn refused_writes_leave_no_snapshot() {
    let fx = Fx::new();
    // A write grant on the whole home: the deny list still wins for `.ssh`.
    let doc = fx.doc(|g| {
        g.grant(folder(&fx.home(), Access::Write), now()).unwrap();
    });
    std::fs::write(fx.base.join("home/other/target.txt"), "outside-bytes").unwrap();
    symlink(
        fx.base.join("home/other/target.txt"),
        fx.proj().join("link.txt"),
    )
    .unwrap();
    std::fs::write(fx.proj().join("a.txt"), "linked-bytes").unwrap();
    std::fs::hard_link(fx.proj().join("a.txt"), fx.proj().join("b.txt")).unwrap();
    let file_host = FileToolHost::new(fx.grants(&doc)).with_undo(fx.undo());
    let sheet_host = SheetToolHost::new(fx.grants(&doc)).with_undo(fx.undo());
    for p in [
        fx.home().join(".ssh/id_ed25519"),
        fx.proj().join("link.txt"),
        fx.proj().join("b.txt"),
        fx.proj().join("foundry.toml"),
    ] {
        let out = file_host.execute(&call(
            FILE_WRITE_TOOL,
            serde_json::json!({ "path": p, "content": "x" }),
        ));
        assert!(matches!(out, ToolOutcome::Denied(_)), "{p:?}: {out:?}");
    }
    for p in [fx.home().join(".ssh/keys.csv"), fx.proj().join("hard.csv")] {
        if p.ends_with("hard.csv") {
            std::fs::hard_link(fx.proj().join("a.txt"), &p).unwrap();
        }
        let out = sheet_host.execute(&call(
            SHEET_WRITE_TOOL,
            serde_json::json!({ "path": p, "rows": [["x"]] }),
        ));
        assert!(matches!(out, ToolOutcome::Denied(_)), "{p:?}: {out:?}");
    }
    assert_eq!(fx.steps(), 0);
    let held = fx.store_bytes();
    for secret in [
        &b"do-not-snapshot"[..],
        &b"outside-bytes"[..],
        &b"linked-bytes"[..],
    ] {
        assert!(!contains(&held, secret));
    }
    assert_eq!(
        std::fs::read_to_string(fx.home().join(".ssh/id_ed25519")).unwrap(),
        "do-not-snapshot"
    );
}

// ---------------------------------------------------------------------------------------------
// Sessions: the checkpointed fs_* tools on the session's grant document
// ---------------------------------------------------------------------------------------------

struct Recorder {
    turns: Mutex<Vec<AssistantTurn>>,
    seen: Mutex<Vec<CompletionRequest>>,
}
impl LlmClient for Recorder {
    fn complete(&self, req: &CompletionRequest) -> Result<AssistantTurn, LlmError> {
        self.seen.lock().unwrap().push(req.clone());
        let mut t = self.turns.lock().unwrap();
        Ok(if t.is_empty() {
            AssistantTurn::text("(done)")
        } else {
            t.remove(0)
        })
    }
}

fn manager(
    fx: &Fx,
    turns: Vec<AssistantTurn>,
    undo: bool,
) -> (Arc<sessions::SessionManager>, Arc<Recorder>) {
    let rec = Arc::new(Recorder {
        turns: Mutex::new(turns),
        seen: Mutex::new(vec![]),
    });
    let r2 = rec.clone();
    let mut mgr = sessions::SessionManager::new(
        Arc::new(move |_ep: &sessions::LlmEndpoint| r2.clone() as Arc<dyn LlmClient>),
        Duration::from_secs(5),
    )
    .with_grants_home(fx.home());
    if undo {
        mgr = mgr.with_checkpoints(fx.store.clone());
    }
    (Arc::new(mgr), rec)
}

fn create_req(grants: serde_json::Value) -> sessions::CreateSessionReq {
    serde_json::from_value(serde_json::json!({
        "model": "gemma-4",
        "systemPrompt": "You are Hermes.",
        "llm": {"baseUrl": "http://127.0.0.1:18080/v1", "bearer": "k"},
        "tools": [],
        "maxToolsPerRequest": 32,
        "grants": grants
    }))
    .unwrap()
}

async fn run_turn_events(
    mgr: &sessions::SessionManager,
    id: &str,
    text: &str,
) -> Vec<serde_json::Value> {
    mgr.send(id, text.into(), None).unwrap();
    let s = mgr.get(id).unwrap();
    let mut after = 0;
    let mut all = vec![];
    for _ in 0..100 {
        let page = s.wait_events(after, Duration::from_millis(200)).await;
        for e in page.events {
            after = after.max(e.seq);
            all.push(serde_json::to_value(&e.event).unwrap());
        }
        if all.iter().any(|e| e["type"] == "done") {
            return all;
        }
    }
    panic!("no done event: {all:?}");
}

#[tokio::test(flavor = "multi_thread")]
async fn a_grant_session_with_undo_offers_the_fs_tools_on_its_grants() {
    let fx = Fx::new();
    let main = fx.proj().join("src/main.sol");
    let edit = call(
        files::FS_EDIT_TOOL,
        serde_json::json!({ "path": main, "old_text": "A", "new_text": "Z" }),
    );
    let write = call(
        FILE_WRITE_TOOL,
        serde_json::json!({ "path": fx.proj().join("src/W.sol"), "content": "contract W {}" }),
    );
    let (mgr, rec) = manager(
        &fx,
        vec![
            AssistantTurn::tools(vec![edit]),
            AssistantTurn::tools(vec![write]),
            AssistantTurn::text("Edited."),
        ],
        true,
    );
    let id = mgr.create(create_req(fx.rw())).unwrap();
    let evs = run_turn_events(&mgr, &id, "rename the contract").await;
    let results: Vec<_> = evs.iter().filter(|e| e["type"] == "tool_result").collect();
    assert_eq!(results.len(), 2, "{evs:?}");
    for r in &results {
        assert_eq!(r["status"], "ok", "{r:?}");
    }
    assert_eq!(std::fs::read_to_string(&main).unwrap(), "contract Z {}");
    let offered = mgr.get(&id).unwrap().tool_names();
    for name in FS_TOOL_NAMES.iter().chain(FILE_TOOL_NAMES.iter()) {
        assert!(offered.iter().any(|t| t == name), "{name}");
    }
    assert!(!rec.seen.lock().unwrap().is_empty());
    // Both changes are checkpointed under the session id, and undo restores the original.
    let sid = SessionId::new(&id).unwrap();
    let steps = fx.store.steps(&sid).unwrap();
    assert_eq!(steps.len(), 2);
    fx.store.undo_session(&sid).unwrap();
    assert_eq!(std::fs::read_to_string(&main).unwrap(), "contract A {}");
    assert!(!fx.proj().join("src/W.sol").exists());

    // The session's grants are the source: after a replace without write, nothing writes.
    let read_only = fx.doc(|g| {
        g.grant(folder(&fx.proj(), Access::Read), now()).unwrap();
    });
    mgr.get(&id)
        .unwrap()
        .grants()
        .unwrap()
        .replace(&read_only)
        .unwrap();
    let tools = files::FileTools::new(
        fx.store.clone(),
        GrantSource::Session(mgr.get(&id).unwrap().grants().unwrap().clone()),
        fx.home(),
    );
    let host = files::FileToolsHost::new(Arc::new(tools), &id).unwrap();
    let out = host.execute(&call(
        files::FS_WRITE_TOOL,
        serde_json::json!({ "path": main, "content": "x" }),
    ));
    assert!(matches!(out, ToolOutcome::Denied(_)), "{out:?}");
    assert_eq!(std::fs::read_to_string(&main).unwrap(), "contract A {}");
}

#[tokio::test(flavor = "multi_thread")]
async fn a_grant_session_without_undo_offers_no_fs_tools() {
    let fx = Fx::new();
    let (mgr, _rec) = manager(&fx, vec![], false);
    let id = mgr.create(create_req(fx.rw())).unwrap();
    let offered = mgr.get(&id).unwrap().tool_names();
    assert!(offered.iter().any(|t| t == FILE_WRITE_TOOL));
    assert!(offered.iter().all(|t| !files::FileTools::handles(t)));
}
