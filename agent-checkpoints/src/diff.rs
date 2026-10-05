//! HUP-S5.4 over HUP-S2.9: what one checkpointed step changed, for the Code and diff pop-out.
//!
//! The "before" side of each path is the snapshot the step took (a verified blob, a link target,
//! or absent). The store keeps no copy of the "after" side, so it is read from disk, and only when
//! the path still holds exactly what the step left there (its recorded post state). Otherwise the
//! after side says why it cannot be shown (the step was undone, the file changed since, or the
//! change is still being written). Text is returned whole up to a size cap; binary content and
//! larger files are described, never sent. Read-only: nothing here changes a file or the store.

use std::fs::File;
use std::io::Read;
use std::path::Path;

use serde::Serialize;

use crate::blobs;
use crate::manifest::{Entry, Manifest, StepStatus};
use crate::state::{fingerprint_now, sha256_hex, Fingerprint, Prior};

/// Largest side (bytes) returned as text by default.
pub const DEFAULT_MAX_SIDE_BYTES: u64 = 256 * 1024;

/// One side of a path's change.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
#[serde(tag = "kind", rename_all = "snake_case")]
pub enum Side {
    Absent,
    Text { text: String },
    Binary { size: u64 },
    TooLarge { size: u64 },
    Symlink { target: String },
    Unavailable { reason: String },
}

/// One path the step touched.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct FileDiff {
    /// Relative to the granted folder.
    pub path: String,
    pub before: Side,
    pub after: Side,
}

/// What a step changed.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct StepDiff {
    pub session: String,
    pub seq: u64,
    pub status: StepStatus,
    pub files: Vec<FileDiff>,
}

fn classify(bytes: Vec<u8>) -> Side {
    let size = bytes.len() as u64;
    if bytes.contains(&0) {
        return Side::Binary { size };
    }
    match String::from_utf8(bytes) {
        Ok(text) => Side::Text { text },
        Err(_) => Side::Binary { size },
    }
}

/// Read at most `max + 1` bytes of `path`.
fn read_capped(path: &Path, max: u64) -> std::io::Result<Vec<u8>> {
    let f = File::open(path)?;
    let mut out = Vec::new();
    f.take(max.saturating_add(1)).read_to_end(&mut out)?;
    Ok(out)
}

fn before_side(store: &Path, prior: &Prior, max: u64) -> Side {
    match prior {
        Prior::Absent => Side::Absent,
        Prior::Symlink { target } => Side::Symlink {
            target: target.clone(),
        },
        Prior::File { blob, size, .. } => {
            if *size > max {
                return Side::TooLarge { size: *size };
            }
            match read_capped(&blobs::blob_path(store, blob), max) {
                Ok(bytes) if sha256_hex(&bytes) == *blob => classify(bytes),
                Ok(_) => Side::Unavailable {
                    reason: "the saved copy does not match its checksum".into(),
                },
                Err(_) => Side::Unavailable {
                    reason: "the saved copy is missing".into(),
                },
            }
        }
    }
}

fn after_side(m: &Manifest, e: &Entry, max: u64) -> Side {
    match m.status {
        StepStatus::Undone => {
            return Side::Unavailable {
                reason: "this step was undone, so its result is no longer on disk".into(),
            }
        }
        StepStatus::Prepared => {
            return Side::Unavailable {
                reason: "the change is still being written".into(),
            }
        }
        StepStatus::Committed | StepStatus::Interrupted => {}
    }
    let path = m.root.join(&e.path);
    let now = match fingerprint_now(&path) {
        Ok(f) => f,
        Err(_) => {
            return Side::Unavailable {
                reason: "the file could not be read".into(),
            }
        }
    };
    if now != *e.post() {
        return Side::Unavailable {
            reason: format!("the file changed after this step (now {now})"),
        };
    }
    match now {
        Fingerprint::Absent => Side::Absent,
        Fingerprint::Symlink { target } => Side::Symlink { target },
        Fingerprint::Other { what } => Side::Unavailable { reason: what },
        Fingerprint::File { sha256 } => match read_capped(&path, max) {
            Ok(bytes) if bytes.len() as u64 > max => Side::TooLarge {
                size: std::fs::metadata(&path)
                    .map(|md| md.len())
                    .unwrap_or(bytes.len() as u64),
            },
            Ok(bytes) if sha256_hex(&bytes) == sha256 => classify(bytes),
            Ok(_) => Side::Unavailable {
                reason: "the file changed while it was being read".into(),
            },
            Err(_) => Side::Unavailable {
                reason: "the file could not be read".into(),
            },
        },
    }
}

pub(crate) fn diff_of(store: &Path, m: &Manifest, max: u64) -> StepDiff {
    StepDiff {
        session: m.session.clone(),
        seq: m.seq,
        status: m.status,
        files: m
            .entries
            .iter()
            .map(|e| FileDiff {
                path: e.path.clone(),
                before: before_side(store, &e.before, max),
                after: after_side(m, e, max),
            })
            .collect(),
    }
}
