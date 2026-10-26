//! Workspace-confined file opening for the writing tools (`file_write`, `file_edit`).
//!
//! Data source: the local filesystem, opened component by component with
//! `openat(2)` relative to a directory descriptor for the canonical workspace root.
//!
//! Policy (pinned by `agent-code/tests/file_write_symlink.rs`):
//! * The workspace root is canonicalized once (it may itself be reached through a
//!   symlink, e.g. `/tmp` on macOS). Everything below it is opened with
//!   `O_NOFOLLOW`, so no component of the requested path may be a symbolic link,
//!   wherever the link points (outside, inside, dangling). Because each component
//!   is opened relative to the descriptor of the one before it, there is no
//!   window between a check and the open in which a component can be swapped.
//! * Missing intermediate directories are created with `mkdirat(2)` relative to the
//!   parent descriptor (never `create_dir_all`, which follows symlinks).
//! * The final component must be a regular file with exactly one hard link. A
//!   file with more links is refused, since another name for it may be outside the
//!   workspace.
//! * On Linux the opened descriptor's path (`/proc/self/fd/N`) is re-checked to be
//!   inside the workspace before any byte is written; a file this call created is
//!   removed again if that check fails. The check fails closed if `/proc` is absent.
//! * On platforms without `O_NOFOLLOW` / `openat` (non-Unix) every write is refused.

use citrate_agent_core::error::AgentError;
use std::fs::File;
use std::path::{Component, Path, PathBuf};

fn fail(msg: impl Into<String>) -> AgentError {
    AgentError::ExecutionFailed(msg.into())
}

const OUTSIDE: &str = "path traversal outside workspace is not allowed";

/// Lexically normalize a path — resolve `.` and `..` components without
/// touching the filesystem. Returns `None` if the path escapes above its
/// root via `..`.
fn lexical_normalize(path: &Path) -> Option<PathBuf> {
    let mut out = PathBuf::new();
    for comp in path.components() {
        match comp {
            Component::ParentDir => {
                // Refuse to pop past the root / an empty accumulator.
                if !out.pop() {
                    return None;
                }
            }
            Component::CurDir => {}
            other => out.push(other.as_os_str()),
        }
    }
    Some(out)
}

/// A request resolved against the workspace: the canonical root plus the path
/// below it, made only of normal components.
pub(crate) struct WorkspacePath {
    pub(crate) root: PathBuf,
    pub(crate) rel: PathBuf,
}

/// Resolve `path` (relative to the workspace, or absolute inside it) lexically.
/// No `..` survives and nothing outside the workspace is accepted. The
/// filesystem is consulted only to canonicalize the workspace root itself.
pub(crate) fn resolve(workspace: &str, path: &str) -> Result<WorkspacePath, AgentError> {
    let root = Path::new(workspace)
        .canonicalize()
        .map_err(|e| fail(format!("invalid workspace dir: {e}")))?;
    let candidate = if Path::new(path).is_absolute() {
        PathBuf::from(path)
    } else {
        root.join(path)
    };
    let candidate = lexical_normalize(&candidate).ok_or_else(|| fail(OUTSIDE))?;
    let rel = candidate
        .strip_prefix(&root)
        .map_err(|_| fail(OUTSIDE))?
        .to_path_buf();
    if rel.as_os_str().is_empty() || !rel.components().all(|c| matches!(c, Component::Normal(_))) {
        return Err(fail("invalid file path"));
    }
    Ok(WorkspacePath { root, rel })
}

/// Open `wp` for writing: missing directories and the file are created, and the
/// file is truncated only after every check has passed.
pub(crate) fn open_for_write(wp: &WorkspacePath) -> Result<File, AgentError> {
    imp::open(wp, true)
}

/// Open the existing regular file `wp` for reading and writing (no creation, no
/// truncation).
pub(crate) fn open_for_edit(wp: &WorkspacePath) -> Result<File, AgentError> {
    imp::open(wp, false)
}

#[cfg(unix)]
mod imp {
    use super::{fail, WorkspacePath, OUTSIDE};
    use citrate_agent_core::error::AgentError;
    use rustix::fs::{fstat, mkdirat, openat, unlinkat, AtFlags, FileType, Mode, OFlags};
    use rustix::io::Errno;
    use std::ffi::OsStr;
    use std::fs::File;
    use std::os::fd::{AsFd, OwnedFd};

    const SYMLINK: &str = "refusing to write through a symbolic link";

    /// `O_NOFOLLOW` on a final symlink reports `ELOOP` on Linux/macOS and `EMLINK`
    /// on FreeBSD; an `O_DIRECTORY` open of a symlink or a file reports `ENOTDIR`.
    fn is_link_refusal(e: Errno) -> bool {
        e == Errno::LOOP || e == Errno::MLINK || e == Errno::NOTDIR
    }

    fn open_dir(parent: &OwnedFd, name: &OsStr, create: bool) -> Result<OwnedFd, AgentError> {
        let flags = OFlags::RDONLY | OFlags::DIRECTORY | OFlags::NOFOLLOW | OFlags::CLOEXEC;
        match openat(parent, name, flags, Mode::empty()) {
            Ok(fd) => Ok(fd),
            Err(e) if e == Errno::NOENT && create => {
                match mkdirat(parent, name, Mode::from_raw_mode(0o755)) {
                    Ok(()) => {}
                    Err(e) if e == Errno::EXIST => {}
                    Err(e) => return Err(fail(format!("failed to create dirs: {e}"))),
                }
                openat(parent, name, flags, Mode::empty()).map_err(|e| {
                    if is_link_refusal(e) {
                        fail(SYMLINK)
                    } else {
                        fail(format!("failed to open directory: {e}"))
                    }
                })
            }
            Err(e) if is_link_refusal(e) => Err(fail(SYMLINK)),
            Err(e) => Err(fail(format!("failed to open directory: {e}"))),
        }
    }

    /// Returns the opened file and whether this call created it.
    fn open_leaf(dir: &OwnedFd, name: &OsStr, create: bool) -> Result<(OwnedFd, bool), AgentError> {
        // NONBLOCK so a FIFO planted at the target cannot hang the call; it has no
        // effect on regular files.
        let access = if create { OFlags::WRONLY } else { OFlags::RDWR };
        let base = access | OFlags::NOFOLLOW | OFlags::CLOEXEC | OFlags::NONBLOCK;
        if create {
            // O_EXCL never follows a symlink, dangling or not: it reports EEXIST.
            match openat(
                dir,
                name,
                base | OFlags::CREATE | OFlags::EXCL,
                Mode::from_raw_mode(0o644),
            ) {
                Ok(fd) => return Ok((fd, true)),
                Err(e) if e == Errno::EXIST => {}
                Err(e) => return Err(fail(format!("failed to open file: {e}"))),
            }
        }
        match openat(dir, name, base, Mode::empty()) {
            Ok(fd) => Ok((fd, false)),
            Err(e) if e == Errno::LOOP || e == Errno::MLINK => Err(fail(SYMLINK)),
            Err(e) if e == Errno::NOENT && create => Err(fail(
                "the target changed while it was being opened; refusing",
            )),
            Err(e) => Err(fail(format!("failed to open file: {e}"))),
        }
    }

    /// Linux: confirm the opened descriptor really lives inside the workspace.
    #[cfg(any(target_os = "linux", target_os = "android"))]
    fn fd_inside(fd: &OwnedFd, root: &std::path::Path) -> Result<bool, AgentError> {
        use std::os::fd::AsRawFd;
        let real = std::fs::read_link(format!("/proc/self/fd/{}", fd.as_fd().as_raw_fd()))
            .map_err(|e| fail(format!("cannot confirm the opened file's location: {e}")))?;
        Ok(real.starts_with(root))
    }

    /// Elsewhere the descriptor chain from the workspace root is the guarantee.
    #[cfg(not(any(target_os = "linux", target_os = "android")))]
    fn fd_inside(_fd: &OwnedFd, _root: &std::path::Path) -> Result<bool, AgentError> {
        Ok(true)
    }

    pub(super) fn open(wp: &WorkspacePath, create: bool) -> Result<File, AgentError> {
        let root_flags = OFlags::RDONLY | OFlags::DIRECTORY | OFlags::CLOEXEC;
        let mut dir = openat(
            rustix::fs::CWD,
            wp.root.as_path(),
            root_flags,
            Mode::empty(),
        )
        .map_err(|e| fail(format!("invalid workspace dir: {e}")))?;

        let mut names: Vec<&OsStr> = wp.rel.iter().collect();
        let leaf = names.pop().ok_or_else(|| fail("invalid file path"))?;
        for name in names {
            dir = open_dir(&dir, name, create)?;
        }

        let (fd, created) = open_leaf(&dir, leaf, create)?;
        let undo = |msg: String| -> AgentError {
            if created {
                let _ = unlinkat(&dir, leaf, AtFlags::empty());
            }
            fail(msg)
        };

        let st = fstat(&fd).map_err(|e| undo(format!("cannot stat the opened file: {e}")))?;
        if FileType::from_raw_mode(st.st_mode) != FileType::RegularFile {
            return Err(undo(
                "refusing to write: the target is not a regular file".into(),
            ));
        }
        if st.st_nlink != 1 {
            return Err(undo(
                "refusing to write: the target has more than one hard link".into(),
            ));
        }
        if !fd_inside(&fd, &wp.root).map_err(|e| undo(e.to_string()))? {
            return Err(undo(OUTSIDE.into()));
        }

        let file = File::from(fd);
        if create && !created {
            file.set_len(0)
                .map_err(|e| fail(format!("failed to truncate: {e}")))?;
        }
        Ok(file)
    }
}

#[cfg(not(unix))]
mod imp {
    use super::{fail, WorkspacePath};
    use citrate_agent_core::error::AgentError;
    use std::fs::File;

    /// Fail closed: without `openat` + `O_NOFOLLOW` the symlink and swap
    /// guarantees above cannot be given, so nothing is written.
    pub(super) fn open(_wp: &WorkspacePath, _create: bool) -> Result<File, AgentError> {
        Err(fail(
            "file writes are not supported on this platform (no O_NOFOLLOW/openat)",
        ))
    }
}
