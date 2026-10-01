//! Small durable-write helpers: unique temp names, write-fsync-rename, directory fsync.

use std::fs::{self, File};
use std::io::Write;
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicU64, Ordering};

use crate::error::{io_err, Result};

static NONCE: AtomicU64 = AtomicU64::new(0);

/// A name unique within this process run (pid plus a counter plus the clock).
pub(crate) fn unique(prefix: &str, suffix: &str) -> String {
    let n = NONCE.fetch_add(1, Ordering::Relaxed);
    let t = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_nanos())
        .unwrap_or(0);
    format!("{prefix}{}-{n}-{t}{suffix}", std::process::id())
}

/// Write `bytes` to `dest` atomically: a temp file in `tmp_dir` (same filesystem), fsync, rename,
/// then fsync the destination directory.
pub(crate) fn atomic_write(tmp_dir: &Path, dest: &Path, bytes: &[u8]) -> Result<()> {
    let tmp = tmp_dir.join(unique("w-", ".part"));
    let res = (|| {
        let mut f = File::create(&tmp).map_err(io_err(&tmp))?;
        f.write_all(bytes).map_err(io_err(&tmp))?;
        f.sync_all().map_err(io_err(&tmp))?;
        drop(f);
        fs::rename(&tmp, dest).map_err(io_err(dest))?;
        if let Some(parent) = dest.parent() {
            sync_dir(parent)?;
        }
        Ok(())
    })();
    if res.is_err() {
        let _ = fs::remove_file(&tmp);
    }
    res
}

#[cfg(unix)]
pub(crate) fn sync_dir(dir: &Path) -> Result<()> {
    let d = File::open(dir).map_err(io_err(dir))?;
    d.sync_all().map_err(io_err(dir))
}

#[cfg(not(unix))]
pub(crate) fn sync_dir(_dir: &Path) -> Result<()> {
    // Directory handles cannot be fsynced through std on this platform; renames are still atomic.
    Ok(())
}

/// Remove a temp file when dropped unless disarmed.
pub(crate) struct TempGuard(pub Option<PathBuf>);

impl TempGuard {
    pub(crate) fn new(p: PathBuf) -> Self {
        Self(Some(p))
    }
    pub(crate) fn disarm(&mut self) {
        self.0 = None;
    }
}

impl Drop for TempGuard {
    fn drop(&mut self) {
        if let Some(p) = self.0.take() {
            let _ = fs::remove_file(p);
        }
    }
}
