//! What a path held before a step (`Prior`) and a comparable fingerprint of what it holds now.

use std::fmt;
use std::fs::{self, File};
use std::io::{ErrorKind, Read};
use std::path::Path;

use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};

use crate::error::{io_err, Result};

/// The prior state of a path, as recorded in a step manifest.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "kind", rename_all = "snake_case")]
pub(crate) enum Prior {
    Absent,
    /// A regular file whose bytes are the blob `blob` (lowercase hex SHA-256).
    File {
        blob: String,
        size: u64,
        /// Unix permission bits (`mode & 0o7777`); `None` where the platform has none.
        mode: Option<u32>,
    },
    /// A symbolic link, recorded by its target text. The target is never read or followed.
    Symlink {
        target: String,
    },
}

impl Prior {
    pub(crate) fn fingerprint(&self) -> Fingerprint {
        match self {
            Prior::Absent => Fingerprint::Absent,
            Prior::File { blob, .. } => Fingerprint::File {
                sha256: blob.clone(),
            },
            Prior::Symlink { target } => Fingerprint::Symlink {
                target: target.clone(),
            },
        }
    }
}

/// A comparable identity of a path's state: kind plus content hash or link target. File mode is
/// not part of it, so a mode-only change by the agent is not a conflict (undo restores the mode).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "kind", rename_all = "snake_case")]
pub(crate) enum Fingerprint {
    Absent,
    File {
        sha256: String,
    },
    Symlink {
        target: String,
    },
    /// A directory or special file; never an expected state.
    Other {
        what: String,
    },
}

impl fmt::Display for Fingerprint {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Fingerprint::Absent => f.write_str("absent"),
            Fingerprint::File { sha256 } => {
                write!(f, "file sha256:{}", sha256.get(..12).unwrap_or(sha256))
            }
            Fingerprint::Symlink { target } => write!(f, "symlink -> {target}"),
            Fingerprint::Other { what } => f.write_str(what),
        }
    }
}

pub(crate) fn sha256_hex(bytes: &[u8]) -> String {
    hex::encode(Sha256::digest(bytes))
}

/// Hash a file's bytes without loading it whole.
pub(crate) fn hash_file(path: &Path) -> Result<(String, u64)> {
    let mut f = File::open(path).map_err(io_err(path))?;
    let mut h = Sha256::new();
    let mut buf = vec![0u8; 64 * 1024];
    let mut n_total = 0u64;
    loop {
        let n = f.read(&mut buf).map_err(io_err(path))?;
        if n == 0 {
            break;
        }
        h.update(&buf[..n]);
        n_total += n as u64;
    }
    Ok((hex::encode(h.finalize()), n_total))
}

pub(crate) fn link_target_string(path: &Path) -> Result<Option<String>> {
    let t = fs::read_link(path).map_err(io_err(path))?;
    Ok(t.to_str().map(str::to_string))
}

/// Fingerprint what is at `path` now, without following a final symlink.
pub(crate) fn fingerprint_now(path: &Path) -> Result<Fingerprint> {
    let meta = match fs::symlink_metadata(path) {
        Ok(m) => m,
        Err(e) if e.kind() == ErrorKind::NotFound => return Ok(Fingerprint::Absent),
        Err(e) => return Err(io_err(path)(e)),
    };
    let ft = meta.file_type();
    if ft.is_symlink() {
        return Ok(match link_target_string(path)? {
            Some(target) => Fingerprint::Symlink { target },
            None => Fingerprint::Other {
                what: "symlink with a non-UTF-8 target".into(),
            },
        });
    }
    if ft.is_dir() {
        return Ok(Fingerprint::Other {
            what: "directory".into(),
        });
    }
    if !ft.is_file() {
        return Ok(Fingerprint::Other {
            what: "special file".into(),
        });
    }
    let (sha256, _) = hash_file(path)?;
    Ok(Fingerprint::File { sha256 })
}

#[cfg(unix)]
pub(crate) fn mode_of(meta: &fs::Metadata) -> Option<u32> {
    use std::os::unix::fs::PermissionsExt;
    Some(meta.permissions().mode() & 0o7777)
}

#[cfg(not(unix))]
pub(crate) fn mode_of(_meta: &fs::Metadata) -> Option<u32> {
    None
}

#[cfg(unix)]
pub(crate) fn set_mode(path: &Path, mode: Option<u32>) -> Result<()> {
    use std::os::unix::fs::PermissionsExt;
    if let Some(m) = mode {
        fs::set_permissions(path, fs::Permissions::from_mode(m)).map_err(io_err(path))?;
    }
    Ok(())
}

#[cfg(not(unix))]
pub(crate) fn set_mode(_path: &Path, _mode: Option<u32>) -> Result<()> {
    Ok(())
}
