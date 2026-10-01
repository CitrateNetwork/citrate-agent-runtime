//! Per-step manifests and per-session metadata, stored as JSON under `sessions/<id>/`.

use std::path::PathBuf;

use serde::{Deserialize, Serialize};

use crate::state::{Fingerprint, Prior};

pub(crate) const MANIFEST_VERSION: u32 = 1;

/// Where a step is in its life.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum StepStatus {
    /// Snapshotted; the tool's write is in flight.
    Prepared,
    /// The tool finished; the post-write state is recorded.
    Committed,
    /// The snapshot was taken but the step never committed (crash, abort, or a dropped step).
    /// The write may or may not have happened; undo accepts either and restores the prior state.
    Interrupted,
    /// Restored to the prior state.
    Undone,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub(crate) struct Entry {
    pub path: String,
    pub before: Prior,
    /// What the path should hold once the tool's change lands (known before the write).
    pub expected_after: Fingerprint,
    /// What it actually held at commit.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub after: Option<Fingerprint>,
}

impl Entry {
    /// The post-step state undo compares against: the recorded one, else the expected one.
    pub(crate) fn post(&self) -> &Fingerprint {
        self.after.as_ref().unwrap_or(&self.expected_after)
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub(crate) struct Manifest {
    pub version: u32,
    pub session: String,
    pub seq: u64,
    /// The canonical granted folder the paths are relative to.
    pub root: PathBuf,
    pub status: StepStatus,
    pub entries: Vec<Entry>,
    /// Directories (relative, shallowest first) that did not exist before the step.
    pub created_dirs: Vec<String>,
}

#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub(crate) struct SessionMeta {
    /// Logical clock value of the last begin, commit or undo (drives LRU pruning).
    pub last_used: u64,
    /// Highest step seq ever allocated in this session.
    pub last_seq: u64,
    /// Every step with seq at or below this was pruned (0 = none).
    pub pruned_through: u64,
}
