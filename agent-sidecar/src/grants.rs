//! HUP-S2.1 — folder grants in agent sessions, and the grant-checked file tools.
//!
//! citrate-core owns the member's grant document (`citrate-agent-grants`' [`GrantState`], stored
//! in core's app data) and sends it to the sidecar when it opens a session (`grants` in
//! `POST /sessions`) and again whenever the member changes it (`POST /sessions/:id/grants`,
//! replace). The sidecar never creates, extends or stores a grant; it only checks against the
//! document it was last given.
//!
//! What a session's grants control:
//!
//! * **File tools** (`file_list`, `file_read`, `file_write`, sidecar-hosted). Offered only to a
//!   session that was opened with a grant document. Every path goes through
//!   [`FolderGrants::check`] at the moment of use, so an expired or revoked grant allows nothing
//!   from that instant. Reads covered by a folder grant are trusted context; reads that only full
//!   access covers come back untrusted and taint the session (HUP-S2.7). Writes need a live
//!   write grant; full access never writes.
//! * **Toolchain project folder** (HUP-S6.3). When the session has a grant document it replaces
//!   `CITRATE_HERMES_TOOLCHAIN_ROOTS`: the project must be covered by live read **and** write
//!   folder grants (forge reads the sources and writes `out/` and `cache/`).
//!
//! A document that fails validation is refused with an error **and** leaves the session with an
//! empty grant set (it grants nothing), so a refused update can never keep an older, broader set
//! alive. The deny list (`citrate-agent-guard`) always wins, under every grant.
//!
//! Keyless: nothing here holds a key or signs (Rule 3).

use std::io::{Read, Write};
use std::path::{Path, PathBuf};
use std::sync::RwLock;

use citrate_agent_grants::{Decision, FolderGrants, GrantKind, GrantState, GrantStatus, Op};
use citrate_agent_guard::{check_path, GuardContext};
use citrate_agent_loop::{
    Effect, HostKind, ToolAnnotations, ToolCall, ToolHost, ToolOutcome, ToolSpec, Trust,
};

pub const FILE_LIST_TOOL: &str = "file_list";
pub const FILE_READ_TOOL: &str = "file_read";
pub const FILE_WRITE_TOOL: &str = "file_write";
/// The tool names this module owns (reserved in sessions opened with grants).
pub const FILE_TOOL_NAMES: [&str; 3] = [FILE_LIST_TOOL, FILE_READ_TOOL, FILE_WRITE_TOOL];

// Size caps: conservative defaults, pending owner sign-off.
/// Largest file `file_read` returns.
pub const MAX_READ_BYTES: u64 = 256 * 1024;
/// Largest content `file_write` accepts.
pub const MAX_WRITE_BYTES: usize = 1024 * 1024;
/// Most entries `file_list` returns.
pub const MAX_LIST_ENTRIES: usize = 500;

fn now_secs() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0)
}

/// Counts for `GET`-style reporting after a replace.
#[derive(Debug, Clone, Copy, PartialEq, Eq, serde::Serialize)]
#[serde(rename_all = "camelCase")]
pub struct GrantSummary {
    pub total: usize,
    pub active: usize,
    /// Rows of the last document set aside because their folder is in a deny location (they could
    /// never allow anything).
    pub ignored: usize,
}

/// One session's grant set. Clones of the `Arc` share it, so a replace reaches every tool host of
/// the session immediately, including a turn already in progress.
pub struct SessionGrants {
    home: PathBuf,
    clock: fn() -> u64,
    inner: RwLock<FolderGrants>,
    ignored: std::sync::atomic::AtomicUsize,
}

impl std::fmt::Debug for SessionGrants {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("SessionGrants")
            .field("home", &self.home)
            .field("summary", &self.summary())
            .finish_non_exhaustive()
    }
}

impl SessionGrants {
    /// An empty set (grants nothing) resolved against `home`. Relative paths are never accepted
    /// by the file tools, so the resolution cwd is `home` too.
    pub fn empty(home: impl AsRef<Path>) -> Self {
        let home = home.as_ref().to_path_buf();
        SessionGrants {
            inner: RwLock::new(FolderGrants::new(&home, &home)),
            home,
            clock: now_secs,
            ignored: std::sync::atomic::AtomicUsize::new(0),
        }
    }

    /// Use a different clock (tests).
    pub fn with_clock(mut self, clock: fn() -> u64) -> Self {
        self.clock = clock;
        self
    }

    /// Parse and validate `doc` (a [`GrantState`] JSON value). On success the session uses it; on
    /// failure the session is left with an empty set and the reason is returned.
    ///
    /// A row whose folder is in a deny location is set aside (counted in
    /// [`GrantSummary::ignored`]) instead of refusing the whole document: the deny list wins under
    /// every grant, so such a row could never allow anything, and core's own early refusal list is
    /// shorter than the deny list. Every other rule still refuses the whole document.
    pub fn replace(&self, doc: &serde_json::Value) -> Result<GrantSummary, String> {
        let mut ignored = 0usize;
        let parsed = serde_json::from_value::<GrantState>(doc.clone())
            .map_err(|e| format!("not a grant document: {e}"))
            .and_then(|mut st| {
                let ctx = GuardContext::new(&self.home, &self.home);
                let before = st.grants.len();
                st.grants.retain(|g| check_path(&g.root, &ctx).is_ok());
                ignored = before - st.grants.len();
                FolderGrants::from_state(st, &self.home, &self.home).map_err(|e| e.to_string())
            });
        self.ignored.store(
            if parsed.is_ok() { ignored } else { 0 },
            std::sync::atomic::Ordering::SeqCst,
        );
        let mut slot = self
            .inner
            .write()
            .unwrap_or_else(|poisoned| poisoned.into_inner());
        match parsed {
            Ok(g) => {
                *slot = g;
                drop(slot);
                Ok(self.summary())
            }
            Err(e) => {
                *slot = FolderGrants::new(&self.home, &self.home);
                Err(e)
            }
        }
    }

    /// May the agent perform `op` on `path` now? A poisoned lock denies.
    pub fn check(&self, path: &Path, op: Op) -> Result<(PathBuf, GrantKind), String> {
        let g = self
            .inner
            .read()
            .map_err(|_| "the grant set could not be read, so nothing is allowed".to_string())?;
        match g.check(path, op, (self.clock)()) {
            Decision::Allowed {
                canonical,
                grant_id,
            } => {
                let kind = g
                    .state()
                    .grants
                    .iter()
                    .find(|x| x.id == grant_id)
                    .map(|x| x.kind)
                    .unwrap_or(GrantKind::FullAccess);
                Ok((canonical.into_path_buf(), kind))
            }
            Decision::Denied { reason } => Err(reason.to_string()),
        }
    }

    /// The toolchain project check: live read and write folder grants must both cover `dir`.
    pub fn check_project(&self, dir: &Path) -> Result<PathBuf, String> {
        let (read, rk) = self.check(dir, Op::Read)?;
        let (write, wk) = self.check(dir, Op::Write)?;
        if rk != GrantKind::Folder || wk != GrantKind::Folder || read != write {
            return Err("the project needs read and write folder grants".into());
        }
        Ok(read)
    }

    /// The member's home these grants resolve against.
    pub fn home(&self) -> &Path {
        &self.home
    }

    /// The grant set in use now, as a [`GrantState`] document (deny-location rows already set
    /// aside). HUP-S1.9: sent with every toolchain call so the worker process checks the same set
    /// again. A poisoned lock or an encoding failure yields `null`, which the worker refuses.
    pub fn document(&self) -> serde_json::Value {
        match self.inner.read() {
            Ok(g) => serde_json::to_value(g.state()).unwrap_or(serde_json::Value::Null),
            Err(_) => serde_json::Value::Null,
        }
    }

    /// How many grants the session holds, and how many are live now.
    pub fn summary(&self) -> GrantSummary {
        match self.inner.read() {
            Ok(g) => {
                let views = g.list((self.clock)());
                GrantSummary {
                    total: views.len(),
                    active: views
                        .iter()
                        .filter(|v| v.status == GrantStatus::Active)
                        .count(),
                    ignored: self.ignored.load(std::sync::atomic::Ordering::SeqCst),
                }
            }
            Err(_) => GrantSummary {
                total: 0,
                active: 0,
                ignored: 0,
            },
        }
    }
}

/// Whether `name` is one of the file tools.
pub fn handles(name: &str) -> bool {
    FILE_TOOL_NAMES.contains(&name)
}

/// The file tool specs offered to the model.
pub fn file_tool_specs() -> Vec<ToolSpec> {
    let path = serde_json::json!({
        "type": "string",
        "description": "Absolute path inside a folder the member granted."
    });
    let ann = |effect: Effect| ToolAnnotations {
        read_only: effect == Effect::None,
        destructive: effect == Effect::Write,
        idempotent: true,
        open_world: false,
        effect: Some(effect),
        // A folder-grant read is the member's own file: trusted. A read only full access covers
        // returns ToolOutcome::Untrusted, which taints the session whatever this says. (This
        // trust split is a conservative default, pending owner sign-off.)
        trust: Some(Trust::Trusted),
    };
    let spec =
        |name: &str, description: &str, props: serde_json::Value, req: &[&str], e| ToolSpec {
            name: name.into(),
            description: description.into(),
            parameters: serde_json::json!({
                "type": "object",
                "properties": props,
                "required": req,
            }),
            host: HostKind::Sidecar,
            annotations: ann(e),
        };
    vec![
        spec(
            FILE_LIST_TOOL,
            "List the entries of a folder the member granted read access to. Entries Hermes may not read are left out.",
            serde_json::json!({ "path": path }),
            &["path"],
            Effect::None,
        ),
        spec(
            FILE_READ_TOOL,
            "Read a UTF-8 text file (at most 256 KiB) from a folder the member granted read access to.",
            serde_json::json!({ "path": path }),
            &["path"],
            Effect::None,
        ),
        spec(
            FILE_WRITE_TOOL,
            "Create or replace a UTF-8 text file (at most 1 MiB) in a folder the member granted write access to. The parent folder must already exist.",
            serde_json::json!({
                "path": path,
                "content": {"type": "string", "description": "The full new file content."}
            }),
            &["path", "content"],
            Effect::Write,
        ),
    ]
}

/// Runs the file tools for one session.
pub struct FileToolHost {
    grants: std::sync::Arc<SessionGrants>,
}

impl FileToolHost {
    pub fn new(grants: std::sync::Arc<SessionGrants>) -> Self {
        FileToolHost { grants }
    }

    fn args(call: &ToolCall) -> Result<serde_json::Map<String, serde_json::Value>, String> {
        let raw = if call.arguments.trim().is_empty() {
            "{}"
        } else {
            call.arguments.as_str()
        };
        match serde_json::from_str::<serde_json::Value>(raw) {
            Ok(serde_json::Value::Object(m)) => Ok(m),
            _ => Err("the arguments must be a JSON object".into()),
        }
    }

    fn path_arg(args: &serde_json::Map<String, serde_json::Value>) -> Result<PathBuf, String> {
        match args.get("path") {
            Some(serde_json::Value::String(p)) if !p.trim().is_empty() => {
                let p = PathBuf::from(p);
                if p.is_absolute() {
                    Ok(p)
                } else {
                    Err("path must be absolute".into())
                }
            }
            _ => Err("path is required".into()),
        }
    }

    fn list(&self, path: &Path) -> ToolOutcome {
        let (dir, kind) = match self.grants.check(path, Op::Read) {
            Ok(x) => x,
            Err(e) => return ToolOutcome::Denied(e),
        };
        let rd = match std::fs::read_dir(&dir) {
            Ok(r) => r,
            Err(e) => return ToolOutcome::Error(format!("cannot list {}: {e}", dir.display())),
        };
        let mut names: Vec<(String, std::fs::FileType)> = rd
            .filter_map(|e| e.ok())
            .filter_map(|e| {
                let ft = e.file_type().ok()?;
                Some((e.file_name().to_string_lossy().into_owned(), ft))
            })
            .collect();
        names.sort_by(|a, b| a.0.cmp(&b.0));
        let mut entries = Vec::new();
        let mut hidden = 0usize;
        let mut truncated = false;
        for (name, ft) in names {
            // Show only what the agent could read itself (the deny list wins here too).
            if self.grants.check(&dir.join(&name), Op::Read).is_err() {
                hidden += 1;
                continue;
            }
            if entries.len() >= MAX_LIST_ENTRIES {
                truncated = true;
                break;
            }
            let kind = if ft.is_dir() {
                "dir"
            } else if ft.is_symlink() {
                "symlink"
            } else {
                "file"
            };
            entries.push(serde_json::json!({ "name": name, "kind": kind }));
        }
        let body = serde_json::json!({
            "path": dir,
            "entries": entries,
            "hidden": hidden,
            "truncated": truncated,
        })
        .to_string();
        Self::by_kind(kind, body)
    }

    fn by_kind(kind: GrantKind, body: String) -> ToolOutcome {
        match kind {
            GrantKind::Folder => ToolOutcome::Ok(body),
            GrantKind::FullAccess => ToolOutcome::Untrusted(body),
        }
    }

    fn read(&self, path: &Path) -> ToolOutcome {
        let (file, kind) = match self.grants.check(path, Op::Read) {
            Ok(x) => x,
            Err(e) => return ToolOutcome::Denied(e),
        };
        let mut f = match open_nofollow(&file, false) {
            Ok(f) => f,
            Err(e) => return ToolOutcome::Error(format!("cannot open {}: {e}", file.display())),
        };
        let meta = match f.metadata() {
            Ok(m) => m,
            Err(e) => return ToolOutcome::Error(format!("cannot inspect {}: {e}", file.display())),
        };
        if !meta.is_file() {
            return ToolOutcome::Error(format!("{} is not a regular file", file.display()));
        }
        if meta.len() > MAX_READ_BYTES {
            return ToolOutcome::Error(format!(
                "{} is {} bytes; file_read returns at most {MAX_READ_BYTES}",
                file.display(),
                meta.len()
            ));
        }
        let mut buf = Vec::new();
        if let Err(e) = (&mut f).take(MAX_READ_BYTES + 1).read_to_end(&mut buf) {
            return ToolOutcome::Error(format!("cannot read {}: {e}", file.display()));
        }
        if buf.len() as u64 > MAX_READ_BYTES {
            return ToolOutcome::Error(format!(
                "{} grew past {MAX_READ_BYTES} bytes while it was read",
                file.display()
            ));
        }
        match String::from_utf8(buf) {
            Ok(text) => Self::by_kind(
                kind,
                serde_json::json!({ "path": file, "content": text }).to_string(),
            ),
            Err(_) => ToolOutcome::Error(format!(
                "{} is not UTF-8 text ({} bytes)",
                file.display(),
                meta.len()
            )),
        }
    }

    fn write(&self, path: &Path, content: &str) -> ToolOutcome {
        if content.len() > MAX_WRITE_BYTES {
            return ToolOutcome::Error(format!(
                "content is {} bytes; file_write accepts at most {MAX_WRITE_BYTES}",
                content.len()
            ));
        }
        let (file, _) = match self.grants.check(path, Op::Write) {
            Ok(x) => x,
            Err(e) => return ToolOutcome::Denied(e),
        };
        match std::fs::symlink_metadata(&file) {
            Ok(m) if m.file_type().is_symlink() => {
                return ToolOutcome::Denied(format!("{} is a symbolic link", file.display()))
            }
            Ok(m) if !m.is_file() => {
                return ToolOutcome::Error(format!("{} is not a regular file", file.display()))
            }
            Ok(m) if hard_linked(&m) => {
                return ToolOutcome::Denied(format!(
                    "{} has other hard links, so writing it could change a file outside the grant",
                    file.display()
                ))
            }
            _ => {}
        }
        let mut f = match open_nofollow(&file, true) {
            Ok(f) => f,
            Err(e) => return ToolOutcome::Error(format!("cannot open {}: {e}", file.display())),
        };
        if let Err(e) = f.write_all(content.as_bytes()).and_then(|_| f.flush()) {
            return ToolOutcome::Error(format!("cannot write {}: {e}", file.display()));
        }
        ToolOutcome::Ok(
            serde_json::json!({ "path": file, "bytes": content.len(), "written": true })
                .to_string(),
        )
    }
}

impl ToolHost for FileToolHost {
    fn execute(&self, call: &ToolCall) -> ToolOutcome {
        let args = match Self::args(call) {
            Ok(a) => a,
            Err(e) => return ToolOutcome::Error(e),
        };
        let path = match Self::path_arg(&args) {
            Ok(p) => p,
            Err(e) => return ToolOutcome::Error(e),
        };
        match call.name.as_str() {
            FILE_LIST_TOOL => self.list(&path),
            FILE_READ_TOOL => self.read(&path),
            FILE_WRITE_TOOL => match args.get("content") {
                Some(serde_json::Value::String(c)) => self.write(&path, c),
                _ => ToolOutcome::Error("content (a string) is required".into()),
            },
            other => ToolOutcome::Error(format!("'{other}' is not a file tool")),
        }
    }
}

#[cfg(unix)]
fn hard_linked(m: &std::fs::Metadata) -> bool {
    use std::os::unix::fs::MetadataExt;
    m.nlink() > 1
}

#[cfg(not(unix))]
fn hard_linked(_m: &std::fs::Metadata) -> bool {
    false
}

/// Open without following a symlink at the leaf (where the OS allows), so a link swapped in after
/// the check is refused instead of followed.
fn open_nofollow(path: &Path, write: bool) -> std::io::Result<std::fs::File> {
    let mut o = std::fs::OpenOptions::new();
    if write {
        o.write(true).create(true).truncate(true);
    } else {
        o.read(true);
    }
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        o.custom_flags(libc::O_NOFOLLOW);
    }
    o.open(path)
}
