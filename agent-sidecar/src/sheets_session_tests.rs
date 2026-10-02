//! HUP-S10.2 — the grant-checked sheet tools (`sheet_read`, `sheet_write`).
//!
//! BDD map (US-10.2 AC1, "read/write xlsx/csv in grants"):
//! - reads and writes CSV and XLSX inside a granted folder:
//!   `csv_and_xlsx_round_trip_inside_a_write_and_read_grant`;
//! - nothing outside the grant, read and write separate, deny list wins:
//!   `a_read_grant_never_writes_and_nothing_outside_is_reached`,
//!   `a_symlinked_or_hard_linked_target_is_never_written`;
//! - full access reads are untrusted and never write: `full_access_reads_are_untrusted`;
//! - sessions only get the tools with a grant document:
//!   `sheet_tools_are_offered_only_with_grants`, `a_session_tool_may_not_claim_a_sheet_tool_name`;
//! - limits are reported, not ignored: `an_oversized_write_is_refused_and_the_file_is_untouched`.

#![cfg(unix)]

use super::grants::SessionGrants;
use super::sheets::*;
use super::*;
use citrate_agent_grants::{Access, FolderGrants, GrantRequest};
use citrate_agent_loop::{
    AssistantTurn, CompletionRequest, LlmClient, LlmError, ToolCall, ToolHost, ToolOutcome,
};
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::Mutex;
use std::time::Duration;

const MEMBER: &str = "0x00000000000000000000000000000000000000bb";
static N: AtomicUsize = AtomicUsize::new(0);

fn now() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap()
        .as_secs()
}

/// `base/home/books` (granted), `base/home/other` (not granted), `base/home/.ssh`.
struct Fx {
    base: PathBuf,
    /// HUP-S2.9: the undo store (one open per directory).
    store: std::sync::OnceLock<Arc<citrate_agent_checkpoints::CheckpointStore>>,
}
impl Fx {
    fn new() -> Self {
        let base = std::env::temp_dir().join(format!(
            "citrate-sidecar-sheets-{}-{}",
            std::process::id(),
            N.fetch_add(1, Ordering::SeqCst)
        ));
        let _ = std::fs::remove_dir_all(&base);
        for d in ["home/books", "home/other", "home/.ssh"] {
            std::fs::create_dir_all(base.join(d)).unwrap();
        }
        let base = base.canonicalize().unwrap();
        std::fs::write(base.join("home/books/q3.csv"), "item,cost\npaper,4.5\n").unwrap();
        std::fs::write(base.join("home/other/secret.csv"), "a,b\n1,2\n").unwrap();
        std::fs::write(base.join("home/.ssh/keys.csv"), "k\nv\n").unwrap();
        Fx {
            base,
            store: std::sync::OnceLock::new(),
        }
    }
    fn home(&self) -> PathBuf {
        self.base.join("home")
    }
    fn books(&self) -> PathBuf {
        self.base.join("home/books")
    }
    fn other(&self) -> PathBuf {
        self.base.join("home/other")
    }
    fn doc(&self, f: impl FnOnce(&mut FolderGrants)) -> serde_json::Value {
        let mut g = FolderGrants::new(self.home(), self.home());
        f(&mut g);
        serde_json::to_value(g.state()).unwrap()
    }
    fn host(&self, doc: &serde_json::Value) -> SheetToolHost {
        let g = SessionGrants::empty(self.home());
        g.replace(doc).unwrap();
        // HUP-S2.9: writes are checkpointed (at `base/ckpt`, outside the home).
        SheetToolHost::new(Arc::new(g))
            .with_undo(crate::files::UndoScope::new(self.store(), "s1-sheets").unwrap())
    }
    fn store(&self) -> Arc<citrate_agent_checkpoints::CheckpointStore> {
        self.store
            .get_or_init(|| {
                Arc::new(
                    citrate_agent_checkpoints::CheckpointStore::open(
                        &self.base.join("ckpt"),
                        citrate_agent_checkpoints::Config::default(),
                    )
                    .unwrap(),
                )
            })
            .clone()
    }
}
impl Drop for Fx {
    fn drop(&mut self) {
        let _ = std::fs::remove_dir_all(&self.base);
    }
}

fn folder(root: &Path, access: Access) -> GrantRequest {
    GrantRequest::folder(root, access, MEMBER, "bookkeeping")
}

fn call(tool: &str, args: serde_json::Value) -> ToolCall {
    ToolCall {
        id: "s1".into(),
        name: tool.into(),
        arguments: args.to_string(),
    }
}

fn read(host: &SheetToolHost, p: &Path) -> ToolOutcome {
    host.execute(&call(SHEET_READ_TOOL, serde_json::json!({ "path": p })))
}

fn write(host: &SheetToolHost, p: &Path, rows: serde_json::Value) -> ToolOutcome {
    host.execute(&call(
        SHEET_WRITE_TOOL,
        serde_json::json!({ "path": p, "rows": rows }),
    ))
}

fn ok_json(o: &ToolOutcome) -> serde_json::Value {
    match o {
        ToolOutcome::Ok(b) => serde_json::from_str(b).unwrap(),
        other => panic!("expected ok, got {other:?}"),
    }
}

fn both(fx: &Fx) -> serde_json::Value {
    fx.doc(|g| {
        g.grant(folder(&fx.books(), Access::Read), now()).unwrap();
        g.grant(folder(&fx.books(), Access::Write), now()).unwrap();
    })
}

#[test]
fn csv_and_xlsx_round_trip_inside_a_write_and_read_grant() {
    let fx = Fx::new();
    let host = fx.host(&both(&fx));
    let v = ok_json(&read(&host, &fx.books().join("q3.csv")));
    assert_eq!(v["format"], "csv");
    assert_eq!(
        v["rows"],
        serde_json::json!([["item", "cost"], ["paper", 4.5]])
    );
    assert_eq!(v["truncated"], false);

    let rows = serde_json::json!([["name", "paid"], ["Ada", true], ["Bo", null]]);
    let out = fx.books().join("Ledger.XLSX");
    let w = ok_json(&write(&host, &out, rows.clone()));
    assert_eq!(w["written"], true);
    assert_eq!(w["format"], "xlsx");
    assert!(w["bytes"].as_u64().unwrap() > 0);
    let back = ok_json(&read(&host, &out));
    assert_eq!(back["sheetNames"], serde_json::json!(["Sheet1"]));
    assert_eq!(
        back["rows"],
        serde_json::json!([["name", "paid"], ["Ada", true], ["Bo"]])
    );

    // A named sheet.
    let named = fx.books().join("named.xlsx");
    let o = host.execute(&call(
        SHEET_WRITE_TOOL,
        serde_json::json!({ "path": named, "rows": [[1, 2]], "sheet": "Q3" }),
    ));
    ok_json(&o);
    let o = host.execute(&call(
        SHEET_READ_TOOL,
        serde_json::json!({ "path": named, "sheet": "Q3" }),
    ));
    assert_eq!(ok_json(&o)["rows"], serde_json::json!([[1.0, 2.0]]));
}

#[test]
fn a_read_grant_never_writes_and_nothing_outside_is_reached() {
    let fx = Fx::new();
    let doc = fx.doc(|g| {
        g.grant(folder(&fx.books(), Access::Read), now()).unwrap();
    });
    let host = fx.host(&doc);
    assert!(matches!(
        write(
            &host,
            &fx.books().join("new.csv"),
            serde_json::json!([["x"]])
        ),
        ToolOutcome::Denied(_)
    ));
    assert!(!fx.books().join("new.csv").exists());
    assert!(matches!(
        read(&host, &fx.other().join("secret.csv")),
        ToolOutcome::Denied(_)
    ));
    assert!(matches!(
        read(&host, &fx.books().join("../other/secret.csv")),
        ToolOutcome::Denied(_)
    ));
    // The deny list wins even with a grant over home.
    let doc = fx.doc(|g| {
        g.grant(folder(&fx.home(), Access::Read), now()).unwrap();
    });
    let host = fx.host(&doc);
    assert!(matches!(
        read(&host, &fx.home().join(".ssh/keys.csv")),
        ToolOutcome::Denied(_)
    ));
}

#[test]
fn a_symlinked_or_hard_linked_target_is_never_written() {
    let fx = Fx::new();
    let host = fx.host(&both(&fx));
    let outside = fx.other().join("secret.csv");
    std::os::unix::fs::symlink(&outside, fx.books().join("link.csv")).unwrap();
    let r = write(
        &host,
        &fx.books().join("link.csv"),
        serde_json::json!([["x"]]),
    );
    assert!(matches!(r, ToolOutcome::Denied(_)), "{r:?}");
    std::fs::hard_link(&outside, fx.books().join("hard.csv")).unwrap();
    let r = write(
        &host,
        &fx.books().join("hard.csv"),
        serde_json::json!([["x"]]),
    );
    assert!(matches!(r, ToolOutcome::Denied(_)), "{r:?}");
    assert_eq!(std::fs::read_to_string(&outside).unwrap(), "a,b\n1,2\n");
}

#[test]
fn a_hard_linked_or_leaf_symlinked_sheet_is_never_read() {
    let fx = Fx::new();
    let host = fx.host(&both(&fx));
    std::fs::hard_link(fx.other().join("secret.csv"), fx.books().join("hard.csv")).unwrap();
    let r = read(&host, &fx.books().join("hard.csv"));
    assert!(matches!(r, ToolOutcome::Denied(_)), "{r:?}");
    std::os::unix::fs::symlink(fx.books().join("q3.csv"), fx.books().join("alias.csv")).unwrap();
    let r = read(&host, &fx.books().join("alias.csv"));
    assert!(matches!(r, ToolOutcome::Denied(_)), "{r:?}");
    // The plain file still reads.
    assert!(matches!(
        read(&host, &fx.books().join("q3.csv")),
        ToolOutcome::Ok(_)
    ));
}

#[test]
fn full_access_reads_are_untrusted() {
    let fx = Fx::new();
    let doc = fx.doc(|g| {
        g.grant(
            GrantRequest::full_access(fx.home(), 3600, MEMBER, "look around"),
            now(),
        )
        .unwrap();
    });
    let host = fx.host(&doc);
    assert!(matches!(
        read(&host, &fx.other().join("secret.csv")),
        ToolOutcome::Untrusted(_)
    ));
    assert!(matches!(
        write(&host, &fx.other().join("x.csv"), serde_json::json!([["x"]])),
        ToolOutcome::Denied(_)
    ));
}

#[test]
fn an_oversized_write_is_refused_and_the_file_is_untouched() {
    let fx = Fx::new();
    let host = fx.host(&both(&fx));
    let big: Vec<serde_json::Value> = (0..(SHEET_LIMITS.max_rows + 1))
        .map(|i| serde_json::json!([i]))
        .collect();
    let target = fx.books().join("q3.csv");
    let r = write(&host, &target, serde_json::Value::Array(big));
    assert!(matches!(r, ToolOutcome::Error(_)), "{r:?}");
    assert_eq!(
        std::fs::read_to_string(&target).unwrap(),
        "item,cost\npaper,4.5\n"
    );
}

#[test]
fn bad_arguments_and_formats_are_errors() {
    let fx = Fx::new();
    let host = fx.host(&both(&fx));
    let r = read(&host, &fx.books().join("notes.txt"));
    assert!(matches!(r, ToolOutcome::Error(_)), "{r:?}");
    let r = host.execute(&call(
        SHEET_READ_TOOL,
        serde_json::json!({ "path": "rel.csv" }),
    ));
    assert!(matches!(r, ToolOutcome::Error(_)), "{r:?}");
    let r = host.execute(&call(
        SHEET_WRITE_TOOL,
        serde_json::json!({ "path": fx.books().join("a.csv"), "rows": "nope" }),
    ));
    assert!(matches!(r, ToolOutcome::Error(_)), "{r:?}");
    let r = host.execute(&call(
        SHEET_WRITE_TOOL,
        serde_json::json!({ "path": fx.books().join("a.csv"), "rows": [[{"x": 1}]] }),
    ));
    assert!(matches!(r, ToolOutcome::Error(_)), "{r:?}");
    // The parent folder must exist (the tool never creates folders).
    let r = write(
        &host,
        &fx.books().join("missing/a.csv"),
        serde_json::json!([["x"]]),
    );
    assert!(!matches!(r, ToolOutcome::Ok(_)), "{r:?}");
}

#[test]
fn the_specs_mark_read_as_read_only_and_write_as_destructive() {
    let specs = sheet_tool_specs();
    let r = specs.iter().find(|s| s.name == SHEET_READ_TOOL).unwrap();
    assert!(r.annotations.read_only);
    let w = specs.iter().find(|s| s.name == SHEET_WRITE_TOOL).unwrap();
    assert!(w.annotations.destructive && !w.annotations.read_only);
    assert_eq!(w.host, citrate_agent_loop::HostKind::Sidecar);
}

// ---------------------------------------------------------------------------------------------
// Sessions
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

fn manager(fx: &Fx, turns: Vec<AssistantTurn>) -> (Arc<sessions::SessionManager>, Arc<Recorder>) {
    let rec = Arc::new(Recorder {
        turns: Mutex::new(turns),
        seen: Mutex::new(vec![]),
    });
    let r2 = rec.clone();
    let mgr = sessions::SessionManager::new(
        Arc::new(move |_ep: &sessions::LlmEndpoint| r2.clone() as Arc<dyn LlmClient>),
        Duration::from_secs(5),
    )
    .with_grants_home(fx.home())
    .with_checkpoints(fx.store());
    (Arc::new(mgr), rec)
}

fn create_body(grants: Option<serde_json::Value>) -> serde_json::Value {
    let mut b = serde_json::json!({
        "model": "gemma-4",
        "systemPrompt": "You are Hermes.",
        "llm": {"baseUrl": "http://127.0.0.1:18080/v1", "bearer": "k"},
        "tools": [],
        "maxToolsPerRequest": 16
    });
    if let Some(g) = grants {
        b["grants"] = g;
    }
    b
}

async fn run_turn(mgr: &sessions::SessionManager, id: &str) -> Vec<serde_json::Value> {
    mgr.send(id, "update the ledger".into(), None).unwrap();
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
async fn sheet_tools_are_offered_only_with_grants() {
    let fx = Fx::new();
    let (mgr, rec) = manager(&fx, vec![]);
    let id = mgr
        .create(serde_json::from_value(create_body(None)).unwrap())
        .unwrap();
    run_turn(&mgr, &id).await;
    assert!(rec.seen.lock().unwrap()[0]
        .tools
        .iter()
        .all(|t| !handles(&t.name)));

    let c = call(
        SHEET_WRITE_TOOL,
        serde_json::json!({ "path": fx.books().join("out.csv"), "rows": [["a", 1]] }),
    );
    let (mgr, rec) = manager(
        &fx,
        vec![AssistantTurn::tools(vec![c]), AssistantTurn::text("Saved.")],
    );
    let id = mgr
        .create(serde_json::from_value(create_body(Some(both(&fx)))).unwrap())
        .unwrap();
    let evs = run_turn(&mgr, &id).await;
    let tc = evs.iter().find(|e| e["type"] == "tool_call").unwrap();
    assert_eq!(tc["host"], "sidecar");
    let tr = evs.iter().find(|e| e["type"] == "tool_result").unwrap();
    assert_eq!(tr["status"], "ok", "{tr}");
    assert_eq!(
        std::fs::read_to_string(fx.books().join("out.csv")).unwrap(),
        "a,1\n"
    );
    let seen = rec.seen.lock().unwrap();
    for name in SHEET_TOOL_NAMES {
        assert!(seen[0].tools.iter().any(|t| t.name == name), "{name}");
    }
}

#[test]
fn a_session_tool_may_not_claim_a_sheet_tool_name() {
    let fx = Fx::new();
    let (mgr, _) = manager(&fx, vec![]);
    let mut body = create_body(Some(fx.doc(|_| {})));
    body["tools"] = serde_json::json!([
        {"name": SHEET_READ_TOOL, "description": "x", "parameters": {"type": "object"}, "host": "core"}
    ]);
    let r = mgr.create(serde_json::from_value(body).unwrap());
    assert!(matches!(r, Err(sessions::SessionError::Invalid(_))));
}
