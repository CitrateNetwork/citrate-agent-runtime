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
//! * The opened descriptor's current path (`/proc/self/fd/N` on Linux,
//!   `fcntl(F_GETPATH)` on macOS) is re-checked to be inside the canonical
//!   workspace root before any byte is written; a file this call created is
//!   removed again if that check fails. The check fails closed when the path
//!   cannot be read, and on Unix targets with no way to read it.
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
    use std::os::fd::OwnedFd;

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
        use std::os::fd::{AsFd, AsRawFd};
        let real = std::fs::read_link(format!("/proc/self/fd/{}", fd.as_fd().as_raw_fd()))
            .map_err(|e| fail(format!("cannot confirm the opened file's location: {e}")))?;
        Ok(real.starts_with(root))
    }

    /// Apple platforms: `fcntl(F_GETPATH)` reports where the descriptor is now.
    #[cfg(any(target_os = "macos", target_os = "ios"))]
    fn fd_inside(fd: &OwnedFd, root: &std::path::Path) -> Result<bool, AgentError> {
        use std::os::unix::ffi::OsStrExt;
        let real = rustix::fs::getpath(fd)
            .map_err(|e| fail(format!("cannot confirm the opened file's location: {e}")))?;
        Ok(std::path::Path::new(OsStr::from_bytes(real.as_bytes())).starts_with(root))
    }

    /// Other Unix targets have no supported way to ask where a descriptor is,
    /// so the check fails closed.
    #[cfg(not(any(
        target_os = "linux",
        target_os = "android",
        target_os = "macos",
        target_os = "ios"
    )))]
    fn fd_inside(_fd: &OwnedFd, _root: &std::path::Path) -> Result<bool, AgentError> {
        Err(fail(
            "cannot confirm the opened file's location on this platform; refusing",
        ))
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
        #[cfg(test)]
        super::tests::after_leaf_open();
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

#[cfg(all(test, unix))]
mod tests {
    //! The opened descriptor must still be inside the workspace when the
    //! location check runs, on every Unix target the runtime ships for. A
    //! test-only seam runs a closure between opening the leaf and checking it.
    use super::{open_for_edit, open_for_write, resolve, OUTSIDE};
    use std::cell::RefCell;
    use std::io::Write;
    use std::path::Path;

    type Hook = Box<dyn FnOnce()>;

    thread_local! {
        static AFTER_LEAF_OPEN: RefCell<Option<Hook>> = RefCell::new(None);
    }

    pub(super) fn after_leaf_open() {
        if let Some(f) = AFTER_LEAF_OPEN.with(|h| h.borrow_mut().take()) {
            f();
        }
    }

    fn set_hook(f: impl FnOnce() + 'static) {
        AFTER_LEAF_OPEN.with(|h| *h.borrow_mut() = Some(Box::new(f)));
    }

    struct Tree {
        _root: tempfile::TempDir,
        ws: std::path::PathBuf,
        outside: std::path::PathBuf,
    }

    fn tree() -> Tree {
        let root = tempfile::Builder::new()
            .prefix("fxsec-sw-")
            .tempdir()
            .expect("temp tree");
        let ws = root.path().join("ws");
        let outside = root.path().join("outside");
        std::fs::create_dir(&ws).expect("mkdir ws");
        std::fs::create_dir(&outside).expect("mkdir outside");
        Tree {
            _root: root,
            ws,
            outside,
        }
    }

    fn err_text<T>(r: Result<T, citrate_agent_core::error::AgentError>) -> String {
        match r {
            Ok(_) => panic!("expected the open to be refused"),
            Err(e) => e.to_string(),
        }
    }

    /// The directory holding a new file is moved out of the workspace after the
    /// file is opened: the write is refused and the created file is removed.
    #[test]
    fn new_file_whose_directory_moves_out_is_refused_and_removed() {
        let t = tree();
        std::fs::create_dir(t.ws.join("sub")).expect("mkdir sub");
        let wp = resolve(t.ws.to_str().expect("utf8"), "sub/new.txt").expect("resolve");
        let (from, to) = (t.ws.join("sub"), t.outside.join("sub"));
        let to2 = to.clone();
        set_hook(move || std::fs::rename(&from, &to2).expect("move dir out"));
        let msg = err_text(open_for_write(&wp));
        assert!(msg.contains(OUTSIDE), "unexpected refusal: {msg}");
        assert!(
            !to.join("new.txt").exists(),
            "a file created by a refused write must be removed"
        );
    }

    /// Same, for an existing file opened for writing: refused, and its content
    /// is not truncated.
    #[test]
    fn existing_file_whose_directory_moves_out_is_refused_and_untouched() {
        let t = tree();
        std::fs::create_dir(t.ws.join("sub")).expect("mkdir sub");
        std::fs::write(t.ws.join("sub/keep.txt"), "KEEP").expect("seed");
        let wp = resolve(t.ws.to_str().expect("utf8"), "sub/keep.txt").expect("resolve");
        let (from, to) = (t.ws.join("sub"), t.outside.join("sub"));
        let to2 = to.clone();
        set_hook(move || std::fs::rename(&from, &to2).expect("move dir out"));
        let msg = err_text(open_for_write(&wp));
        assert!(msg.contains(OUTSIDE), "unexpected refusal: {msg}");
        assert_eq!(
            std::fs::read_to_string(to.join("keep.txt")).expect("read"),
            "KEEP"
        );
    }

    /// The edit path (no create, no truncate) gets the same check.
    #[test]
    fn edit_target_whose_directory_moves_out_is_refused() {
        let t = tree();
        std::fs::create_dir(t.ws.join("sub")).expect("mkdir sub");
        std::fs::write(t.ws.join("sub/e.txt"), "E").expect("seed");
        let wp = resolve(t.ws.to_str().expect("utf8"), "sub/e.txt").expect("resolve");
        let (from, to) = (t.ws.join("sub"), t.outside.join("sub"));
        set_hook(move || std::fs::rename(&from, &to).expect("move dir out"));
        let msg = err_text(open_for_edit(&wp));
        assert!(msg.contains(OUTSIDE), "unexpected refusal: {msg}");
    }

    /// A sibling whose name merely starts with the workspace name is outside
    /// (component-wise prefix, not string prefix).
    #[test]
    fn move_to_a_name_prefixed_sibling_is_refused() {
        let t = tree();
        std::fs::create_dir(t.ws.join("sub")).expect("mkdir sub");
        let evil = t.ws.with_file_name("ws-sibling");
        std::fs::create_dir(&evil).expect("mkdir sibling");
        let wp = resolve(t.ws.to_str().expect("utf8"), "sub/n.txt").expect("resolve");
        let (from, to) = (t.ws.join("sub"), evil.join("sub"));
        set_hook(move || std::fs::rename(&from, &to).expect("move dir out"));
        let msg = err_text(open_for_write(&wp));
        assert!(msg.contains(OUTSIDE), "unexpected refusal: {msg}");
    }

    /// A move that stays inside the workspace is still accepted.
    #[test]
    fn move_within_the_workspace_is_accepted() {
        let t = tree();
        std::fs::create_dir(t.ws.join("sub")).expect("mkdir sub");
        let wp = resolve(t.ws.to_str().expect("utf8"), "sub/in.txt").expect("resolve");
        let (from, to) = (t.ws.join("sub"), t.ws.join("moved"));
        set_hook(move || std::fs::rename(&from, &to).expect("move dir within"));
        let mut f = open_for_write(&wp).expect("inside the workspace is fine");
        f.write_all(b"ok").expect("write");
        assert_eq!(
            std::fs::read_to_string(t.ws.join("moved/in.txt")).expect("read"),
            "ok"
        );
    }

    /// A workspace reached through a symlinked path (e.g. /tmp on macOS) is
    /// compared in canonical form, so ordinary writes are not refused.
    #[test]
    fn workspace_reached_through_a_symlink_still_writes() {
        let t = tree();
        let link = t.ws.with_file_name("ws-link");
        std::os::unix::fs::symlink(&t.ws, &link).expect("symlink ws");
        let wp = resolve(link.to_str().expect("utf8"), "a/b.txt").expect("resolve");
        let mut f = open_for_write(&wp).expect("write through canonical root");
        f.write_all(b"x").expect("write");
        assert!(Path::new(&t.ws.join("a/b.txt")).exists());
    }

    /// Tripwire: no platform variant of the location check may accept
    /// unconditionally. A new target must read the descriptor's path or refuse.
    #[test]
    fn no_location_check_variant_accepts_unconditionally() {
        let src = include_str!("safe_write.rs");
        let accept_all = concat!("Ok(", "true)");
        let body_start = src.find("fn fd_inside").expect("location check present");
        let body_end = src.find("pub(super) fn open(").expect("open present");
        let checks = &src[body_start..body_end];
        assert!(
            !checks.contains(accept_all),
            "a location-check variant accepts every descriptor without looking"
        );
        assert!(checks.matches("fn fd_inside").count() >= 3);
    }
}
