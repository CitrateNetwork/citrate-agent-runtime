//! HUP-S2.9 — sidecar file tools with undo checkpoints.
//!
//! Four sidecar-hosted session tools change files inside the folders a member granted for
//! writing (HUP-S2.1 grants):
//!
//! | tool        | arguments                                          | change                       |
//! |-------------|----------------------------------------------------|------------------------------|
//! | `fs_write`  | `path`, `content`                                  | create or overwrite a file   |
//! | `fs_edit`   | `path`, `old_text`, `new_text`, `replace_all?`     | exact text replacement       |
//! | `fs_delete` | `path`                                             | delete a file or a link      |
//! | `fs_rename` | `from`, `to`                                       | rename inside one grant      |
//!
//! Every call runs in this order:
//!
//! 1. **Grant and deny list.** Build configuration (`foundry.toml`, env files and the rest of
//!    `toolchain_config::build_config_file`) is refused first: the member edits it. Each path
//!    then goes through [`FolderGrants::check`] for a write, which
//!    asks the agent-guard default-deny list first (credentials, keychains, browser profiles,
//!    wallet storage, app data, shell history) and then needs a live write grant covering the
//!    resolved path. A refusal here happens before anything is read or snapshotted, so the bytes
//!    of a denied file never enter the checkpoint store.
//! 2. **Checkpoint.** [`CheckpointStore::begin_step`] snapshots the prior state of every path
//!    and makes the step durable.
//! 3. **Change.** The tool writes (temp sibling, then rename), deletes or renames.
//! 4. **Commit.** The step records the post-change state ([`citrate_agent_checkpoints::Step::commit`]); a failed
//!    change aborts the step (undo still accepts either state).
//!
//! The tool result names the checkpoint (`session`, `seq`) so the app can offer Undo on the
//! change. Undo itself is a member action through the `/checkpoints` routes, never a tool.
//!
//! **Configuration.** A session citrate-core opens with the member's grant document (HUP-S2.1)
//! gets these tools whenever a checkpoint store is configured (`CITRATE_HERMES_CHECKPOINTS`, which
//! core always sets): they check that session's document ([`GrantSource::Session`], core's grant
//! store), read at every call, so a revoke or an expiry applies to the next call. Without a grant
//! document, they are on only with `CITRATE_HERMES_FILES=1`, a grants file (`CITRATE_HERMES_GRANTS`)
//! and a checkpoint store. Either way: no write without a grant, and no write that could not be
//! undone. Paths must be absolute (or start with `~/`).
//!
//! **One write path.** The grant-session write tools (`file_write` in [`crate::grants`],
//! `sheet_write` in [`crate::sheets`]) write through [`checked_whole_file_write`]: the same grant
//! and deny-list check, then a refusal of build configuration, a symbolic link at the leaf (as
//! given or as resolved) and a file with other hard links, all before any snapshot; then a
//! checkpoint under the session id. Without a checkpoint store they write nothing. So every agent
//! write a member can trigger can be undone through the `/checkpoints` routes.
//!
//! **Honest scope.** A file changed between the grant check and the write is caught by the
//! checkpoint's own path checks (no write through a symbolic link, no path through a symlinked
//! directory), not by an OS sandbox. Taint (HUP-S2.7) is enforced by the loop: these tools are
//! effectful, so after the session reads untrusted content they are declined. This module never
//! holds a key and never signs (Rule 3).

use std::fs;
use std::io::{ErrorKind, Read, Write};
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::Arc;

use citrate_agent_checkpoints::{Change, CheckpointStore, SessionId, Step};
use citrate_agent_grants::{Decision, FolderGrants, Op};
use citrate_agent_loop::{
    Effect, HostKind, ToolAnnotations, ToolCall, ToolHost, ToolOutcome, ToolSpec, Trust,
};

/// `1` turns the file tools on; anything else (or unset) leaves them off.
pub const FILES_ENV: &str = "CITRATE_HERMES_FILES";
/// Absolute path of the grants file (the `GrantState` JSON core stores).
pub const GRANTS_ENV: &str = "CITRATE_HERMES_GRANTS";
/// Absolute directory of the undo checkpoint store (inside the app's data dir).
pub const CHECKPOINTS_ENV: &str = "CITRATE_HERMES_CHECKPOINTS";

pub const FS_WRITE_TOOL: &str = "fs_write";
pub const FS_EDIT_TOOL: &str = "fs_edit";
pub const FS_DELETE_TOOL: &str = "fs_delete";
pub const FS_RENAME_TOOL: &str = "fs_rename";
/// The tool names this module owns (reserved in sessions while it is on).
pub const TOOL_NAMES: [&str; 4] = [FS_WRITE_TOOL, FS_EDIT_TOOL, FS_DELETE_TOOL, FS_RENAME_TOOL];

/// Largest content `fs_write` accepts, and largest file `fs_edit` opens (4 MiB).
pub const MAX_CONTENT_BYTES: usize = 4 * 1024 * 1024;

/// What the env asks for (the store directory is configured separately).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct FilesConfig {
    pub grants_file: PathBuf,
    /// The member's home (`~` and the deny list).
    pub home: PathBuf,
}

impl FilesConfig {
    /// `None` unless `CITRATE_HERMES_FILES` is exactly `1`, a home is known and an absolute
    /// grants file is given (never resolved against the sidecar's cwd).
    pub fn from_env_vars(get: impl Fn(&str) -> Option<String>) -> Option<Self> {
        if get(FILES_ENV).as_deref() != Some("1") {
            return None;
        }
        let home = PathBuf::from(get("HOME").filter(|h| !h.is_empty())?);
        let grants_file = PathBuf::from(get(GRANTS_ENV).filter(|g| !g.is_empty())?);
        if !grants_file.is_absolute() {
            return None;
        }
        Some(FilesConfig { grants_file, home })
    }

    pub fn from_env() -> Option<Self> {
        Self::from_env_vars(|k| std::env::var(k).ok())
    }
}

/// The checkpoint store directory from `CITRATE_HERMES_CHECKPOINTS`; relative paths are ignored.
pub fn checkpoints_dir_from_env_vars(get: impl Fn(&str) -> Option<String>) -> Option<PathBuf> {
    get(CHECKPOINTS_ENV)
        .filter(|v| !v.is_empty())
        .map(PathBuf::from)
        .filter(|p| p.is_absolute())
}

/// Where the grants come from.
#[derive(Debug, Clone)]
pub enum GrantSource {
    /// Read and validated on every call (`CITRATE_HERMES_GRANTS`). Missing or invalid = nothing
    /// granted.
    File(PathBuf),
    /// A fixed set (tests and embedders that manage grants themselves).
    Fixed(FolderGrants),
    /// HUP-S2.9: the session's grant document, which citrate-core sends from its grant store when
    /// it opens the session and after every change (production). Read at every call, so a revoke
    /// reaches the next call.
    Session(Arc<crate::grants::SessionGrants>),
}

/// What the tool results tell the model about undo.
pub const UNDO_NOTE: &str = "The member can undo this change from the app.";

/// HUP-S2.9: where one session's agent writes are checkpointed (the store and the session id).
#[derive(Clone)]
pub struct UndoScope {
    store: Arc<CheckpointStore>,
    session: SessionId,
}

impl std::fmt::Debug for UndoScope {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("UndoScope")
            .field("session", &self.session.as_str())
            .finish_non_exhaustive()
    }
}

impl UndoScope {
    /// `None` when `session` is not a valid checkpoint session id.
    pub fn new(store: Arc<CheckpointStore>, session: &str) -> Option<Self> {
        Some(UndoScope {
            store,
            session: SessionId::new(session).ok()?,
        })
    }

    pub fn session(&self) -> &SessionId {
        &self.session
    }

    /// Checkpoint, then replace `file` (under the grant `root`) with `bytes`. Returns the step.
    fn replace(&self, root: &Path, file: &Path, bytes: &[u8]) -> Result<u64, Refusal> {
        let step = self
            .store
            .begin_step(&self.session, root, &[Change::write(file, bytes)])?;
        let r = write_file(file, bytes);
        finish(step, r)
    }
}

/// A whole-file write that was made and checkpointed.
#[derive(Debug, Clone)]
pub(crate) struct CheckedWrite {
    pub path: PathBuf,
    pub session: String,
    pub seq: u64,
}

/// HUP-S2.9: the one checkpointed whole-file write for the grant-session write tools
/// (`file_write`, `sheet_write`). In order, and before anything is read or snapshotted:
/// build configuration is refused (as given and as resolved), the path must pass the session's
/// grants for a write (the agent-guard deny list first), the leaf must not be a symbolic link, a
/// non-file, or a file with other hard links, and the parent folder must exist unless
/// `create_parent`. Only then is the prior state snapshotted and the file replaced (temp sibling
/// and rename). Without an undo store nothing is written: no agent write the member could not undo.
pub(crate) fn checked_whole_file_write(
    grants: &crate::grants::SessionGrants,
    undo: Option<&UndoScope>,
    path: &Path,
    bytes: &[u8],
    create_parent: bool,
) -> Result<CheckedWrite, Refusal> {
    if !path.is_absolute() {
        return Err(Refusal::Failed("path must be absolute".into()));
    }
    if let Some(name) = crate::toolchain_config::build_config_file(path) {
        return Err(Refusal::Policy(
            crate::toolchain_config::build_config_refusal(&name),
        ));
    }
    let (file, root) = grants.check_write(path).map_err(Refusal::Policy)?;
    if let Some(name) = crate::toolchain_config::build_config_file(&file) {
        return Err(Refusal::Policy(
            crate::toolchain_config::build_config_refusal(&name),
        ));
    }
    if let Some(r) = leaf_refusal(&[path, &file]) {
        return Err(r);
    }
    if !create_parent && !file.parent().is_some_and(Path::is_dir) {
        return Err(Refusal::Failed(format!(
            "the folder of {} does not exist",
            file.display()
        )));
    }
    let Some(undo) = undo else {
        return Err(Refusal::Policy(
            "undo checkpoints are not configured, so no agent write is made (every agent write must be undoable)"
                .into(),
        ));
    };
    let seq = undo.replace(&root, &file, bytes)?;
    Ok(CheckedWrite {
        path: file,
        session: undo.session.as_str().to_string(),
        seq,
    })
}

/// A refusal when a leaf in `paths` is a symbolic link, is not a regular file, or has other hard
/// links (writing it could change a file outside the grant). A missing leaf is fine (a new file).
/// The grant-session write tools pass the path as given and as resolved (they never follow a
/// link at the leaf); `fs_write` and `fs_edit` resolve links before the grant check, so they pass
/// the resolved path only.
fn leaf_refusal(paths: &[&Path]) -> Option<Refusal> {
    for p in paths.iter().copied() {
        match fs::symlink_metadata(p) {
            Ok(m) if m.file_type().is_symlink() => {
                return Some(Refusal::Policy(format!(
                    "{} is a symbolic link",
                    p.display()
                )))
            }
            Ok(m) if !m.is_file() => {
                return Some(Refusal::Failed(format!(
                    "{} is not a regular file",
                    p.display()
                )))
            }
            Ok(m) if crate::grants::hard_linked(&m) => {
                return Some(Refusal::Policy(format!(
                    "{} has other hard links, so writing it could change a file outside the grant",
                    p.display()
                )))
            }
            _ => {}
        }
    }
    None
}

/// The file tools shared by every session (one checkpoint store per process).
pub struct FileTools {
    store: Arc<CheckpointStore>,
    grants: GrantSource,
    home: PathBuf,
    clock: fn() -> u64,
}

impl std::fmt::Debug for FileTools {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("FileTools")
            .field("grants", &self.grants)
            .field("home", &self.home)
            .finish_non_exhaustive()
    }
}

fn unix_now() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0)
}

/// A path that passed the grant check: where to do the I/O and the grant root it is under.
struct Allowed {
    canonical: PathBuf,
    root: PathBuf,
}

type Args = serde_json::Map<String, serde_json::Value>;

/// Why a call did not change anything. `Policy` is a grant or deny-list refusal (the model sees
/// "declined"); `Failed` is anything else.
pub(crate) enum Refusal {
    Policy(String),
    Failed(String),
}

impl Refusal {
    pub(crate) fn into_outcome(self) -> ToolOutcome {
        match self {
            Refusal::Policy(m) => ToolOutcome::Denied(m),
            Refusal::Failed(m) => ToolOutcome::Error(m),
        }
    }
}

impl From<citrate_agent_checkpoints::Error> for Refusal {
    fn from(e: citrate_agent_checkpoints::Error) -> Self {
        Refusal::Failed(format!("no change was made: {e}"))
    }
}

impl FileTools {
    pub fn new(store: Arc<CheckpointStore>, grants: GrantSource, home: impl AsRef<Path>) -> Self {
        FileTools {
            store,
            grants,
            home: home.as_ref().to_path_buf(),
            clock: unix_now,
        }
    }

    /// Use a fixed clock (grant expiry is checked against it).
    pub fn with_clock(mut self, clock: fn() -> u64) -> Self {
        self.clock = clock;
        self
    }

    pub fn store(&self) -> &Arc<CheckpointStore> {
        &self.store
    }

    /// Whether `name` is one of the file tools.
    pub fn handles(name: &str) -> bool {
        TOOL_NAMES.contains(&name)
    }

    /// The tool specs offered to the model.
    pub fn specs() -> Vec<ToolSpec> {
        let path = |what: &str| {
            serde_json::json!({
                "type": "string",
                "description": format!("Absolute path of the {what} (inside a folder the member granted for writing).")
            })
        };
        let ann = |destructive: bool, idempotent: bool| ToolAnnotations {
            read_only: false,
            destructive,
            idempotent,
            open_world: false,
            effect: Some(Effect::Write),
            trust: Some(Trust::Trusted),
        };
        let spec = |name: &str, description: &str, parameters: serde_json::Value, a| ToolSpec {
            name: name.into(),
            description: description.into(),
            parameters,
            host: HostKind::Sidecar,
            annotations: a,
        };
        vec![
            spec(
                FS_WRITE_TOOL,
                "Create or overwrite a text file in a folder the member granted for writing. The member can undo the change.",
                serde_json::json!({
                    "type": "object",
                    "properties": {
                        "path": path("file"),
                        "content": {"type": "string", "description": "The complete new file content."}
                    },
                    "required": ["path", "content"]
                }),
                ann(true, true),
            ),
            spec(
                FS_EDIT_TOOL,
                "Replace exact text in a file in a granted folder. old_text must appear exactly once unless replace_all is true. The member can undo the change.",
                serde_json::json!({
                    "type": "object",
                    "properties": {
                        "path": path("file"),
                        "old_text": {"type": "string", "description": "The exact text to replace."},
                        "new_text": {"type": "string", "description": "The replacement text."},
                        "replace_all": {"type": "boolean", "description": "Replace every occurrence (default false)."}
                    },
                    "required": ["path", "old_text", "new_text"]
                }),
                ann(true, false),
            ),
            spec(
                FS_DELETE_TOOL,
                "Delete a file (or a symbolic link) in a granted folder. The member can undo the change.",
                serde_json::json!({
                    "type": "object",
                    "properties": {"path": path("file")},
                    "required": ["path"]
                }),
                ann(true, true),
            ),
            spec(
                FS_RENAME_TOOL,
                "Rename or move a file inside one granted folder, replacing anything at the destination. The member can undo the change.",
                serde_json::json!({
                    "type": "object",
                    "properties": {"from": path("file to move"), "to": path("destination")},
                    "required": ["from", "to"]
                }),
                ann(true, false),
            ),
        ]
    }

    /// The grant set to check against now, and the time to check it at.
    fn load_grants(&self) -> Result<(FolderGrants, u64), Refusal> {
        match &self.grants {
            GrantSource::Session(g) => g
                .with_folder_grants(|fg, now| (fg.clone(), now))
                .map_err(Refusal::Policy),
            GrantSource::Fixed(g) => Ok((g.clone(), (self.clock)())),
            GrantSource::File(p) => {
                let json = fs::read_to_string(p).map_err(|e| {
                    Refusal::Policy(format!(
                        "no folder grants are readable ({e}); ask the member to grant a folder"
                    ))
                })?;
                FolderGrants::from_json(&json, &self.home, &self.home)
                    .map(|g| (g, (self.clock)()))
                    .map_err(|e| {
                        Refusal::Policy(format!("the folder grants could not be loaded: {e}"))
                    })
            }
        }
    }

    /// Grant + deny-list check for a write to `raw`. Nothing is read or snapshotted before this.
    fn allow(&self, grants: &FolderGrants, now: u64, raw: &str) -> Result<Allowed, Refusal> {
        let p = Path::new(raw);
        if !(p.is_absolute() || raw.starts_with("~/")) {
            return Err(Refusal::Failed(format!(
                "{raw:?} is not an absolute path; use an absolute path inside a folder the member granted"
            )));
        }
        // Build configuration is the member's to edit: no fs tool creates, changes, moves or
        // removes it (checked on the path as given and as resolved).
        if let Some(name) = crate::toolchain_config::build_config_file(p) {
            return Err(Refusal::Policy(
                crate::toolchain_config::build_config_refusal(&name),
            ));
        }
        match grants.check(p, Op::Write, now) {
            Decision::Allowed {
                canonical,
                grant_id,
            } => {
                if let Some(name) = crate::toolchain_config::build_config_file(canonical.as_path())
                {
                    return Err(Refusal::Policy(
                        crate::toolchain_config::build_config_refusal(&name),
                    ));
                }
                // A hard link can name a file kept outside the grant (the deny list is
                // path-based): no fs tool reads, snapshots, edits, moves or removes one.
                if let Ok(meta) = fs::symlink_metadata(canonical.as_path()) {
                    if meta.is_file() && crate::grants::hard_linked(&meta) {
                        return Err(Refusal::Policy(format!(
                            "{raw} has another hard link, so it may be a file kept elsewhere; the member handles it"
                        )));
                    }
                }
                let root = grants
                    .state()
                    .grants
                    .iter()
                    .find(|g| g.id == grant_id)
                    .map(|g| g.root.clone())
                    .ok_or_else(|| Refusal::Failed("internal: the grant disappeared".into()))?;
                Ok(Allowed {
                    canonical: canonical.into_path_buf(),
                    root,
                })
            }
            Decision::Denied { reason } => Err(Refusal::Policy(format!("{raw}: {reason}"))),
        }
    }

    fn run(&self, session: &SessionId, call: &ToolCall) -> Result<serde_json::Value, Refusal> {
        let args = parse_args(&call.arguments).map_err(Refusal::Failed)?;
        let (grants, now) = self.load_grants()?;
        let (paths, step) = match call.name.as_str() {
            FS_WRITE_TOOL => {
                let path = str_arg(&args, "path")?;
                let content = str_arg(&args, "content")?;
                if content.len() > MAX_CONTENT_BYTES {
                    return Err(Refusal::Failed(format!(
                        "the content is {} bytes, over the {MAX_CONTENT_BYTES}-byte limit",
                        content.len()
                    )));
                }
                let a = self.allow(&grants, now, path)?;
                if let Some(r) = leaf_refusal(&[&a.canonical]) {
                    return Err(r);
                }
                let bytes = content.as_bytes();
                let step = self.store.begin_step(
                    session,
                    &a.root,
                    &[Change::write(&a.canonical, bytes)],
                )?;
                let r = write_file(&a.canonical, bytes);
                (vec![a.canonical], finish(step, r)?)
            }
            FS_EDIT_TOOL => {
                let path = str_arg(&args, "path")?;
                let old_text = str_arg(&args, "old_text")?;
                let new_text = str_arg(&args, "new_text")?;
                let replace_all = match args.get("replace_all") {
                    None | Some(serde_json::Value::Null) => false,
                    Some(serde_json::Value::Bool(b)) => *b,
                    Some(_) => {
                        return Err(Refusal::Failed("replace_all must be true or false".into()))
                    }
                };
                if old_text.is_empty() {
                    return Err(Refusal::Failed("old_text is empty".into()));
                }
                let a = self.allow(&grants, now, path)?;
                if let Some(r) = leaf_refusal(&[&a.canonical]) {
                    return Err(r);
                }
                let before = read_text(&a.canonical)?;
                let n = before.matches(old_text).count();
                if n == 0 {
                    return Err(Refusal::Failed(format!(
                        "old_text was not found in {path}; nothing was changed"
                    )));
                }
                if n > 1 && !replace_all {
                    return Err(Refusal::Failed(format!(
                        "old_text appears {n} times in {path}; give more context or set replace_all"
                    )));
                }
                let after = if replace_all {
                    before.replace(old_text, new_text)
                } else {
                    before.replacen(old_text, new_text, 1)
                };
                if after.len() > MAX_CONTENT_BYTES {
                    return Err(Refusal::Failed(format!(
                        "the edited file would be {} bytes, over the {MAX_CONTENT_BYTES}-byte limit",
                        after.len()
                    )));
                }
                let step = self.store.begin_step(
                    session,
                    &a.root,
                    &[Change::write(&a.canonical, after.as_bytes())],
                )?;
                // The snapshot is of what is on disk now; refuse if that is not what was edited.
                let r = write_if_unchanged(&a.canonical, &before, after.as_bytes());
                (vec![a.canonical], finish(step, r)?)
            }
            FS_DELETE_TOOL => {
                let path = str_arg(&args, "path")?;
                let a = self.allow(&grants, now, path)?;
                let step =
                    self.store
                        .begin_step(session, &a.root, &[Change::delete(&a.canonical)])?;
                let r = remove_checked(&a.canonical).map_err(|e| format!("delete failed: {e}"));
                (vec![a.canonical], finish(step, r)?)
            }
            FS_RENAME_TOOL => {
                let from_raw = str_arg(&args, "from")?;
                let to_raw = str_arg(&args, "to")?;
                let from = self.allow(&grants, now, from_raw)?;
                let to = self.allow(&grants, now, to_raw)?;
                if from.root != to.root {
                    return Err(Refusal::Failed(
                        "from and to must be inside the same granted folder".into(),
                    ));
                }
                let step = self.store.begin_step(
                    session,
                    &from.root,
                    &[Change::rename(&from.canonical, &to.canonical)],
                )?;
                let r = to
                    .canonical
                    .parent()
                    .map_or(Ok(()), fs::create_dir_all)
                    .and_then(|()| rename_checked(&from.canonical, &to.canonical))
                    .map_err(|e| format!("rename failed: {e}"));
                (vec![from.canonical, to.canonical], finish(step, r)?)
            }
            other => {
                return Err(Refusal::Failed(format!("'{other}' is not a file tool")));
            }
        };
        Ok(serde_json::json!({
            "ok": true,
            "tool": call.name,
            "paths": paths.iter().map(|p| p.to_string_lossy()).collect::<Vec<_>>(),
            "checkpoint": {"session": session.as_str(), "seq": step},
            "undo": UNDO_NOTE
        }))
    }
}

/// Commit after a change that happened, abort after one that failed. Returns the step's seq.
pub(crate) fn finish(step: Step<'_>, change: Result<(), String>) -> Result<u64, Refusal> {
    let seq = step.seq();
    match change {
        Ok(()) => match step.commit() {
            Ok(_) => Ok(seq),
            Err(e) => Err(Refusal::Failed(format!(
                "the change was made, but its undo record could not be finished ({e}); undo of step {seq} still works"
            ))),
        },
        Err(m) => {
            let _ = step.abort();
            Err(Refusal::Failed(m))
        }
    }
}

fn parse_args(raw: &str) -> Result<Args, String> {
    let raw = if raw.trim().is_empty() { "{}" } else { raw };
    match serde_json::from_str::<serde_json::Value>(raw) {
        Ok(serde_json::Value::Object(m)) => Ok(m),
        Ok(_) => Err("the arguments must be a JSON object".into()),
        Err(_) => Err("the arguments are not valid JSON".into()),
    }
}

fn str_arg<'a>(args: &'a Args, key: &str) -> Result<&'a str, Refusal> {
    match args.get(key) {
        Some(serde_json::Value::String(s))
            if key == "content" || key == "new_text" || !s.is_empty() =>
        {
            Ok(s)
        }
        _ => Err(Refusal::Failed(format!("{key} is required (a string)"))),
    }
}

/// Read a regular file (never through a symbolic link) as UTF-8 text, within the size limit.
fn read_text(path: &Path) -> Result<String, Refusal> {
    let shown = path.display();
    let meta = match fs::symlink_metadata(path) {
        Ok(m) => m,
        Err(e) if e.kind() == ErrorKind::NotFound => {
            return Err(Refusal::Failed(format!("{shown} does not exist")))
        }
        Err(e) => return Err(Refusal::Failed(format!("{shown}: {e}"))),
    };
    if meta.file_type().is_symlink() {
        return Err(Refusal::Failed(format!(
            "{shown} is a symbolic link; edit its target instead"
        )));
    }
    if !meta.is_file() {
        return Err(Refusal::Failed(format!("{shown} is not a regular file")));
    }
    if meta.len() > MAX_CONTENT_BYTES as u64 {
        return Err(Refusal::Failed(format!(
            "{shown} is {} bytes, over the {MAX_CONTENT_BYTES}-byte edit limit",
            meta.len()
        )));
    }
    // Read through a confirmed open of the checked path (see `grants::open_checked`).
    let mut bytes = Vec::new();
    crate::grants::open_checked(path, false)
        .and_then(|f| {
            f.take(MAX_CONTENT_BYTES as u64 + 1)
                .read_to_end(&mut bytes)
                .map(|_| ())
        })
        .map_err(|e| Refusal::Failed(format!("{shown}: {e}")))?;
    if bytes.len() > MAX_CONTENT_BYTES {
        return Err(Refusal::Failed(format!(
            "{shown} grew past the {MAX_CONTENT_BYTES}-byte edit limit while it was read"
        )));
    }
    String::from_utf8(bytes).map_err(|_| Refusal::Failed(format!("{shown} is not UTF-8 text")))
}

/// Write `bytes` only if the file still holds `expected` (what the edit was computed from).
pub(crate) fn write_if_unchanged(path: &Path, expected: &str, bytes: &[u8]) -> Result<(), String> {
    match read_text(path) {
        Ok(now) if now == expected => write_file(path, bytes),
        Ok(_) => Err(format!(
            "{} changed while it was being edited; nothing was changed",
            path.display()
        )),
        Err(Refusal::Policy(m) | Refusal::Failed(m)) => Err(m),
    }
}

static TMP_N: AtomicU64 = AtomicU64::new(0);

/// Write through a temp sibling and a rename, keeping an existing file's permissions.
///
/// On Unix the write is anchored to the folder that was checked (L-21): the folder is opened once
/// without following a link and confirmed to be at the checked path, and the temp file's creation
/// and the final rename are both made relative to that open folder (`openat`, `renameat`), so a
/// folder on the way swapped for a link after the check cannot move the write elsewhere.
pub(crate) fn write_file(path: &Path, bytes: &[u8]) -> Result<(), String> {
    let parent = path
        .parent()
        .ok_or_else(|| "the path has no parent folder".to_string())?;
    let name = path
        .file_name()
        .ok_or_else(|| "the path has no file name".to_string())?;
    fs::create_dir_all(parent).map_err(|e| format!("could not create the folder: {e}"))?;
    #[cfg(unix)]
    {
        let dir = open_dir_checked(parent).map_err(|e| format!("write failed: {e}"))?;
        replace_in_dir(&dir, name, bytes).map_err(|e| format!("write failed: {e}"))
    }
    #[cfg(not(unix))]
    {
        let tmp = parent.join(temp_name(name));
        let res = (|| -> std::io::Result<()> {
            let mut f = crate::grants::open_checked(&tmp, true)?;
            f.write_all(bytes)?;
            f.sync_all()?;
            if let Ok(meta) = fs::metadata(path) {
                if meta.is_file() {
                    fs::set_permissions(&tmp, meta.permissions())?;
                }
            }
            fs::rename(&tmp, path)
        })();
        if res.is_err() {
            let _ = fs::remove_file(&tmp);
        }
        res.map_err(|e| format!("write failed: {e}"))
    }
}

fn temp_name(name: &std::ffi::OsStr) -> String {
    format!(
        ".{}.citrate-write-{}-{}",
        name.to_string_lossy(),
        std::process::id(),
        TMP_N.fetch_add(1, Ordering::SeqCst)
    )
}

/// Open the folder at `dir` (already resolved by the grant check) without following a link at
/// its last component, and confirm the open folder is at that path (a folder on the way swapped
/// for a link makes it land elsewhere, which is refused).
#[cfg(unix)]
pub(crate) fn open_dir_checked(dir: &Path) -> std::io::Result<fs::File> {
    use std::os::unix::fs::OpenOptionsExt;
    let f = fs::OpenOptions::new()
        .read(true)
        .custom_flags(libc::O_DIRECTORY | libc::O_NOFOLLOW | libc::O_CLOEXEC)
        .open(dir)?;
    if !crate::grants::opened_at(&f, dir) {
        return Err(std::io::Error::new(
            ErrorKind::PermissionDenied,
            "the folder changed while it was being opened",
        ));
    }
    Ok(f)
}

/// Replace `name` inside the open folder `dir` with `bytes`: a new temp file created there
/// (exclusive, never through a link), synced, given the replaced file's permissions, then renamed
/// over `name`, all relative to `dir`. The temp file is removed on failure.
#[cfg(unix)]
pub(crate) fn replace_in_dir(
    dir: &fs::File,
    name: &std::ffi::OsStr,
    bytes: &[u8],
) -> std::io::Result<()> {
    use std::ffi::CString;
    use std::os::unix::ffi::OsStrExt;
    use std::os::unix::io::{AsRawFd, FromRawFd};
    let cstr = |s: &[u8]| {
        CString::new(s)
            .map_err(|_| std::io::Error::new(ErrorKind::InvalidInput, "a NUL in the name"))
    };
    let target = cstr(name.as_bytes())?;
    let tmp_name = temp_name(name);
    let tmp = cstr(tmp_name.as_bytes())?;
    let dfd = dir.as_raw_fd();
    // SAFETY: openat on a valid directory fd with a NUL-terminated name; the returned fd is owned
    // by the File built from it (closed on drop).
    let fd = unsafe {
        libc::openat(
            dfd,
            tmp.as_ptr(),
            libc::O_WRONLY | libc::O_CREAT | libc::O_EXCL | libc::O_NOFOLLOW | libc::O_CLOEXEC,
            0o666 as libc::c_uint,
        )
    };
    if fd < 0 {
        return Err(std::io::Error::last_os_error());
    }
    // SAFETY: `fd` was just returned by openat and is owned by nothing else.
    let mut f = unsafe { fs::File::from_raw_fd(fd) };
    let unlink_tmp = || {
        // SAFETY: unlinkat on a valid directory fd with a NUL-terminated name.
        unsafe {
            libc::unlinkat(dfd, tmp.as_ptr(), 0);
        }
    };
    let res = (|| -> std::io::Result<()> {
        f.write_all(bytes)?;
        f.sync_all()?;
        // Keep a replaced regular file's permissions (looked up in the same folder, no link).
        // SAFETY: `stat` is a plain C struct of integers, valid when zeroed.
        let mut st: libc::stat = unsafe { std::mem::zeroed() };
        // SAFETY: fstatat writes one `stat` into `st`; the fd and name are valid.
        let rc = unsafe { libc::fstatat(dfd, target.as_ptr(), &mut st, libc::AT_SYMLINK_NOFOLLOW) };
        if rc == 0 && (st.st_mode & libc::S_IFMT) == libc::S_IFREG {
            // SAFETY: fchmod on the temp file's own fd.
            if unsafe { libc::fchmod(f.as_raw_fd(), st.st_mode & 0o7777) } != 0 {
                return Err(std::io::Error::last_os_error());
            }
        }
        // SAFETY: renameat within one valid directory fd, both names NUL-terminated.
        if unsafe { libc::renameat(dfd, tmp.as_ptr(), dfd, target.as_ptr()) } != 0 {
            return Err(std::io::Error::last_os_error());
        }
        Ok(())
    })();
    if res.is_err() {
        unlink_tmp();
    }
    res
}

fn parent_and_name(path: &Path) -> std::io::Result<(&Path, &std::ffi::OsStr)> {
    match (path.parent(), path.file_name()) {
        (Some(p), Some(n)) => Ok((p, n)),
        _ => Err(std::io::Error::new(
            ErrorKind::InvalidInput,
            "the path has no parent folder or file name",
        )),
    }
}

#[cfg(unix)]
fn c_name(name: &std::ffi::OsStr) -> std::io::Result<std::ffi::CString> {
    use std::os::unix::ffi::OsStrExt;
    std::ffi::CString::new(name.as_bytes())
        .map_err(|_| std::io::Error::new(ErrorKind::InvalidInput, "a NUL in the name"))
}

/// Delete the file at `path` (resolved by the grant check) inside its checked folder (L-21): the
/// folder is opened and confirmed ([`open_dir_checked`]) and the name removed relative to it.
pub(crate) fn remove_checked(path: &Path) -> std::io::Result<()> {
    let (parent, name) = parent_and_name(path)?;
    #[cfg(unix)]
    {
        let dir = open_dir_checked(parent)?;
        remove_in_dir(&dir, name)
    }
    #[cfg(not(unix))]
    {
        let _ = (parent, name);
        fs::remove_file(path)
    }
}

/// Rename `from` to `to` (both resolved by the grant check), relative to their checked folders.
pub(crate) fn rename_checked(from: &Path, to: &Path) -> std::io::Result<()> {
    let (fp, fname) = parent_and_name(from)?;
    let (tp, tname) = parent_and_name(to)?;
    #[cfg(unix)]
    {
        let fdir = open_dir_checked(fp)?;
        let tdir = open_dir_checked(tp)?;
        rename_between(&fdir, fname, &tdir, tname)
    }
    #[cfg(not(unix))]
    {
        let _ = (fp, fname, tp, tname);
        fs::rename(from, to)
    }
}

/// Remove `name` (a file, or a link itself, never a folder) inside the open folder `dir`.
#[cfg(unix)]
pub(crate) fn remove_in_dir(dir: &fs::File, name: &std::ffi::OsStr) -> std::io::Result<()> {
    use std::os::unix::io::AsRawFd;
    let n = c_name(name)?;
    // SAFETY: unlinkat on a valid directory fd with a NUL-terminated name.
    if unsafe { libc::unlinkat(dir.as_raw_fd(), n.as_ptr(), 0) } != 0 {
        return Err(std::io::Error::last_os_error());
    }
    Ok(())
}

/// Rename `from` in the open folder `fdir` to `to` in the open folder `tdir`.
#[cfg(unix)]
pub(crate) fn rename_between(
    fdir: &fs::File,
    from: &std::ffi::OsStr,
    tdir: &fs::File,
    to: &std::ffi::OsStr,
) -> std::io::Result<()> {
    use std::os::unix::io::AsRawFd;
    let f = c_name(from)?;
    let t = c_name(to)?;
    // SAFETY: renameat on two valid directory fds with NUL-terminated names.
    if unsafe { libc::renameat(fdir.as_raw_fd(), f.as_ptr(), tdir.as_raw_fd(), t.as_ptr()) } != 0 {
        return Err(std::io::Error::last_os_error());
    }
    Ok(())
}

/// The per-session host: the shared tools plus this session's checkpoint id.
pub struct FileToolsHost {
    tools: Arc<FileTools>,
    session: SessionId,
}

impl FileToolsHost {
    /// `None` when the session id is not a valid checkpoint session id.
    pub fn new(tools: Arc<FileTools>, session: &str) -> Option<Self> {
        Some(FileToolsHost {
            tools,
            session: SessionId::new(session).ok()?,
        })
    }
}

impl ToolHost for FileToolsHost {
    fn execute(&self, call: &ToolCall) -> ToolOutcome {
        if !FileTools::handles(&call.name) {
            return ToolOutcome::Error(format!("'{}' is not a file tool", call.name));
        }
        match self.tools.run(&self.session, call) {
            Ok(v) => ToolOutcome::Ok(v.to_string()),
            Err(r) => r.into_outcome(),
        }
    }
}
