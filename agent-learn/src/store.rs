//! The proposals file: undecided proposals (and recent decided ones) survive a restart.
//!
//! The learner keeps its proposals in memory and, when it was opened with a store path, rewrites
//! the whole set to one JSON file after every change: written to a temporary file next to it,
//! flushed, then renamed over it, so a crash leaves either the old file or the new one.
//!
//! Loading is defensive. The file lives in the member's own data folder, so it is not a security
//! boundary (anyone who can write it can also write a skill folder directly), but nothing loaded
//! from it skips a check the learner would have made: every proposal's content is re-validated and
//! its content hash recomputed, ids must be well formed and unique, and the evidence must be
//! internally consistent. A proposal that fails is dropped and named in the [`LoadReport`]. A file
//! that cannot be read as a proposals file at all is moved aside (never deleted) and the learner
//! starts empty; decisions already made are in the decision log either way.

use std::io::Write;
use std::path::{Path, PathBuf};

use serde::{Deserialize, Serialize};

use crate::learner::Proposal;

/// The schema tag of the proposals file.
pub const STORE_SCHEMA: &str = "citrate.learn.proposals.v1";
/// Decided proposals (rejected, persisted, publish prepared) kept in the file, newest first.
/// Undecided ones are always kept (they are bounded by `MAX_PENDING`).
pub const MAX_KEPT_DECIDED: usize = 512;
/// Most decision-log records read when reconciling on open (the learn log is its own folder).
pub const MAX_RECONCILE_RECORDS: usize = 200_000;
/// A proposals file larger than this is not read (it is moved aside).
pub const MAX_STORE_BYTES: u64 = 64 * 1024 * 1024;

#[derive(Serialize, Deserialize)]
pub(crate) struct StoreFile {
    pub schema: String,
    pub counter: u64,
    pub proposals: Vec<Proposal>,
}

/// What opening the store found.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct LoadReport {
    /// Proposals restored.
    pub loaded: usize,
    /// Proposals dropped, as `(id, reason)`.
    pub dropped: Vec<(String, String)>,
    /// Where an unreadable file was moved, if one was.
    pub moved_aside: Option<PathBuf>,
    /// Proposals whose state the decision log moved forward (a decision whose save was lost).
    pub reconciled: usize,
    /// Why the decision log could not be read for reconciling, if it could not.
    pub log_error: Option<String>,
}

/// Read the file. `Ok(None)` when it does not exist. `Err(reason)` when it exists but is not a
/// readable proposals file.
pub(crate) fn read_file(path: &Path) -> Result<Option<StoreFile>, String> {
    let meta = match std::fs::metadata(path) {
        Ok(m) => m,
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => return Ok(None),
        Err(e) => return Err(format!("cannot read: {}", e.kind())),
    };
    if !meta.is_file() {
        return Err("not a regular file".into());
    }
    if meta.len() > MAX_STORE_BYTES {
        return Err(format!("larger than {MAX_STORE_BYTES} bytes"));
    }
    let bytes = std::fs::read(path).map_err(|e| format!("cannot read: {}", e.kind()))?;
    let file: StoreFile =
        serde_json::from_slice(&bytes).map_err(|e| format!("not a proposals file: {e}"))?;
    if file.schema != STORE_SCHEMA {
        return Err(format!("unknown schema {:?}", file.schema));
    }
    Ok(Some(file))
}

/// Move an unreadable file aside so it can be inspected; returns where it went.
pub(crate) fn move_aside(path: &Path, now_ms: u64) -> Option<PathBuf> {
    let name = path.file_name()?.to_string_lossy().into_owned();
    let dest = path.with_file_name(format!("{name}.unreadable-{now_ms}"));
    std::fs::rename(path, &dest).ok().map(|_| dest)
}

/// Write the file atomically (temporary file, flush, rename, then sync the folder on unix).
pub(crate) fn write_file(path: &Path, file: &StoreFile) -> Result<(), String> {
    let bytes = serde_json::to_vec_pretty(file).map_err(|e| format!("encode: {e}"))?;
    let parent = path
        .parent()
        .filter(|p| !p.as_os_str().is_empty())
        .map(Path::to_path_buf)
        .unwrap_or_else(|| PathBuf::from("."));
    std::fs::create_dir_all(&parent).map_err(|e| format!("create folder: {}", e.kind()))?;
    let name = path
        .file_name()
        .map(|n| n.to_string_lossy().into_owned())
        .unwrap_or_else(|| "proposals.json".into());
    let tmp = parent.join(format!(".{name}.tmp"));
    let res = (|| -> std::io::Result<()> {
        let mut opts = std::fs::OpenOptions::new();
        opts.write(true).create(true).truncate(true);
        #[cfg(unix)]
        {
            use std::os::unix::fs::OpenOptionsExt;
            opts.mode(0o600);
        }
        let mut f = opts.open(&tmp)?;
        f.write_all(&bytes)?;
        f.sync_all()?;
        drop(f);
        std::fs::rename(&tmp, path)?;
        #[cfg(unix)]
        {
            if let Ok(d) = std::fs::File::open(&parent) {
                let _ = d.sync_all();
            }
        }
        Ok(())
    })();
    if let Err(e) = res {
        let _ = std::fs::remove_file(&tmp);
        return Err(format!("write {}: {}", path.display(), e.kind()));
    }
    Ok(())
}
