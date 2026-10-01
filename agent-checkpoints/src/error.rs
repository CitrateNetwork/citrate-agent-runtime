//! Errors. Every refusal names the path and the reason, so the UI can show it as is.

use std::path::PathBuf;

/// One path that changed since the step it would be restored from.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Conflict {
    /// The step whose undo hit the conflict.
    pub seq: u64,
    /// The path, relative to the granted folder.
    pub path: String,
    /// What is on disk now (e.g. `file sha256:ab12..`, `absent`, `directory`).
    pub found: String,
}

#[derive(Debug, thiserror::Error)]
pub enum Error {
    #[error("io error at {path}: {source}")]
    Io {
        path: PathBuf,
        #[source]
        source: std::io::Error,
    },
    #[error("checkpoint manifest json: {0}")]
    Json(#[source] serde_json::Error),
    #[error(
        "invalid session id {0:?}: use 1 to 64 of A-Z a-z 0-9 _ -, starting with a letter or digit"
    )]
    InvalidSession(String),
    #[error("path {path:?} refused: {reason}")]
    Path { path: String, reason: String },
    #[error("{path:?} cannot be checkpointed: {reason}")]
    Unsupported { path: String, reason: String },
    #[error("{path:?} is {size} bytes, over the per-file checkpoint cap of {cap} bytes; the change is refused because it could not be undone")]
    TooLarge { path: String, size: u64, cap: u64 },
    #[error("this step needs {size} bytes of snapshots, over the whole checkpoint store cap of {cap} bytes; the change is refused because it could not be undone")]
    StepTooLarge { size: u64, cap: u64 },
    #[error("the checkpoint store cannot free {needed} bytes under its {cap}-byte cap: every remaining step is still in flight")]
    StoreFull { needed: u64, cap: u64 },
    #[error("{path:?} has a step in flight; try again when it finishes")]
    Busy { path: String },
    #[error("undo refused, nothing was changed: {} path(s) changed since the step ({})", .0.len(), describe(.0))]
    Conflict(Vec<Conflict>),
    #[error("session {session} has no step {seq}")]
    NotFound { session: String, seq: u64 },
    #[error("session {session} step {seq} was pruned to keep the checkpoint store under its size cap; it can no longer be undone")]
    Pruned { session: String, seq: u64 },
    #[error("session {session} step {seq} is already undone")]
    AlreadyUndone { session: String, seq: u64 },
    #[error("checkpoint data is corrupt: {what}")]
    Corrupt { what: String },
    #[error("the checkpoint store {0} is open in another process")]
    Locked(PathBuf),
    #[error("the checkpoint store's internal lock is poisoned; refusing to continue")]
    Poisoned,
    #[error("{0} is not inside a git work tree")]
    NotGitWorkTree(PathBuf),
    #[error("git is not available: {0}")]
    GitUnavailable(String),
    #[error("git {command} failed: {stderr}")]
    Git { command: String, stderr: String },
}

fn describe(c: &[Conflict]) -> String {
    c.iter()
        .map(|c| format!("step {} {}: now {}", c.seq, c.path, c.found))
        .collect::<Vec<_>>()
        .join("; ")
}

pub type Result<T> = std::result::Result<T, Error>;

pub(crate) fn io_err(path: impl Into<PathBuf>) -> impl FnOnce(std::io::Error) -> Error {
    let path = path.into();
    move |source| Error::Io { path, source }
}
