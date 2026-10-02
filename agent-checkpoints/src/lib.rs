//! Undo checkpoints for agent file writes (HUP-S2.9, runtime half).
//!
//! Before a tool writes, deletes, or renames a file inside a folder the member granted, the tool
//! calls [`CheckpointStore::begin_step`] with the changes it is about to make. The store
//! snapshots the prior state of every path, writes a per-step manifest, and only then returns;
//! the tool performs the change and calls [`Step::commit`]. Later the member can undo one step
//! ([`CheckpointStore::undo_step`]) or the whole session ([`CheckpointStore::undo_session`]).
//!
//! # What is recorded
//!
//! - Regular files: the bytes, in a content-addressed blob store (`blobs/<xx>/<sha256>`,
//!   identical content kept once), plus the permission bits on Unix.
//! - Symbolic links: the link and its target text. The target is never read or followed, and
//!   writing *through* a link is refused.
//! - Absent paths: recorded as absent, so undo removes a file the step created, and removes the
//!   directories the step created if they are still empty.
//! - Directories and special files are refused, as are paths that leave the folder (`..`,
//!   absolute paths elsewhere) or pass through a symlinked directory.
//!
//! # Exact undo, never a silent clobber
//!
//! Each manifest entry keeps the prior state and the post-change state (the intended one from
//! the start, the observed one from commit). Undo restores only when every path is in the
//! post-change state (or already back in the prior state); otherwise it is refused with
//! [`Error::Conflict`] and nothing is changed. A session undo is checked as a whole first.
//! Every restore writes a temp sibling and renames it over the path, and blob hashes are
//! verified before and while restoring.
//!
//! # Crashes
//!
//! The snapshot and the manifest are fsynced before `begin_step` returns, so a crash between the
//! snapshot and the write loses nothing. On the next open such a step is
//! [`StepStatus::Interrupted`]; undo accepts either the prior or the intended state, so it is
//! correct whether or not the write landed. A torn or foreign state is a conflict.
//!
//! # Size
//!
//! [`Config::max_file_bytes`] caps one snapshot; a bigger file is refused with
//! [`Error::TooLarge`] (the change should not proceed, because it could not be undone).
//! [`Config::max_store_bytes`] caps the store: older steps are pruned, least recently used
//! session first and oldest step first, and an undo of a pruned step says
//! [`Error::Pruned`]. Steps in flight are never pruned.
//!
//! # Concurrency
//!
//! One process per store directory (an OS file lock, [`LOCK_FILE`]). Within the process all
//! operations are serialized, and a path with a step in flight refuses a second step or an undo
//! with [`Error::Busy`].
//!
//! # Git mode
//!
//! When the folder is inside a git work tree, [`CheckpointStore::git_checkpoint`] also commits
//! its state to `refs/citrate/checkpoints/<session>` without touching HEAD, the index, or any
//! branch (see the `git` module docs for the plumbing used).
//!
//! # Not here
//!
//! Keyless: nothing signs (Rule 3). The sidecar file tools (`agent-sidecar` `files` module,
//! HUP-S2.9) take a step around every change and serve the undo routes; the app (citrate-core)
//! owns the app-data directory and the undo UI.

mod blobs;
mod error;
mod fsutil;
mod git;
mod manifest;
mod paths;
mod session;
mod state;
mod store;

pub use error::{Conflict, Error, Result};
pub use git::{checkpoint_ref, GitCheckpoint};
pub use manifest::StepStatus;
pub use session::SessionId;
pub use store::{Change, CheckpointStore, Config, Step, StepSummary, UndoReport, Usage, LOCK_FILE};
