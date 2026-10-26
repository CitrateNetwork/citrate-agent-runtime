//! Scratch HOME directories for the tools that spawn subprocesses (`git_ops`, `shell_exec`).
//!
//! Data source: the local filesystem under the process temp directory.
//!
//! Policy (pinned by the tests below and `agent-code/tests/scratch_home_fresh.rs`):
//! * The directory name carries a random suffix (`tempfile::Builder`), not the process id and a
//!   counter, so the name cannot be guessed in advance.
//! * It is created with a single `mkdir(2)`, which fails if anything (a directory, a file, a
//!   symlink, dangling or not) already sits at that name; nothing pre-existing is ever reused and
//!   no link is followed. On a collision `tempfile` retries with a fresh random name.
//! * The mode is 0700 on Unix (owner only).
//! * The directory and everything in it is removed when the value is dropped, including when the
//!   subprocess times out.
//! * Failure to create it is an error: the tool does not run the subprocess with an unprepared
//!   HOME.

use citrate_agent_core::error::AgentError;
use std::path::Path;

/// Random characters in the directory name (on top of the fixed prefix).
const RAND_CHARS: usize = 16;

/// A freshly created, owner-only scratch HOME directory, removed when dropped.
pub(crate) struct ScratchHome(tempfile::TempDir);

impl ScratchHome {
    /// Create a scratch HOME under the process temp directory.
    pub(crate) fn create(prefix: &str) -> Result<Self, AgentError> {
        Self::create_in(&std::env::temp_dir(), prefix)
    }

    /// Create a scratch HOME under `parent`.
    pub(crate) fn create_in(parent: &Path, prefix: &str) -> Result<Self, AgentError> {
        let mut b = tempfile::Builder::new();
        b.prefix(prefix).rand_bytes(RAND_CHARS);
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            b.permissions(std::fs::Permissions::from_mode(0o700));
        }
        b.tempdir_in(parent).map(ScratchHome).map_err(|e| {
            AgentError::ExecutionFailed(format!("could not create a scratch HOME directory: {e}"))
        })
    }

    pub(crate) fn path(&self) -> &Path {
        self.0.path()
    }
}

#[cfg(all(test, unix))]
mod tests {
    use super::*;
    use std::os::unix::fs::{symlink, MetadataExt};
    use std::path::PathBuf;

    const PREFIX: &str = "citrate-test-home-";
    /// How many predictable names each test plants (pid plus every counter value up to this).
    const PLANTED: u64 = 512;

    fn root() -> tempfile::TempDir {
        tempfile::Builder::new()
            .prefix("dgx-scratch-home-")
            .tempdir()
            .expect("create private test root")
    }

    fn predictable(parent: &Path, seq: u64) -> PathBuf {
        parent.join(format!("{PREFIX}{}-{seq}", std::process::id()))
    }

    #[test]
    fn pre_created_directory_is_not_used() {
        let root = root();
        let parent = root.path().join("tmp");
        std::fs::create_dir(&parent).expect("mkdir parent");
        for seq in 0..PLANTED {
            let d = predictable(&parent, seq);
            std::fs::create_dir(&d).expect("plant dir");
            std::fs::write(d.join("planted"), b"x").expect("plant file");
        }
        let home = ScratchHome::create_in(&parent, PREFIX).expect("create scratch home");
        assert!(
            !home.path().join("planted").exists(),
            "a pre-existing directory was reused as the scratch HOME: {}",
            home.path().display()
        );
        assert_eq!(
            std::fs::read_dir(home.path())
                .expect("read scratch home")
                .count(),
            0,
            "the scratch HOME must start empty"
        );
        drop(home);
        for seq in 0..PLANTED {
            assert!(
                predictable(&parent, seq).join("planted").exists(),
                "a planted directory was touched"
            );
        }
    }

    #[test]
    fn planted_symlink_is_not_followed() {
        let root = root();
        let parent = root.path().join("tmp");
        let elsewhere = root.path().join("elsewhere");
        std::fs::create_dir(&parent).expect("mkdir parent");
        std::fs::create_dir(&elsewhere).expect("mkdir elsewhere");
        std::fs::write(elsewhere.join("keep"), b"x").expect("plant file");
        for seq in 0..PLANTED {
            symlink(&elsewhere, predictable(&parent, seq)).expect("plant symlink");
        }
        let home = ScratchHome::create_in(&parent, PREFIX).expect("create scratch home");
        let meta = std::fs::symlink_metadata(home.path()).expect("stat scratch home");
        assert!(
            meta.file_type().is_dir() && !meta.file_type().is_symlink(),
            "the scratch HOME must be a real directory, not a link"
        );
        assert_ne!(
            std::fs::canonicalize(home.path()).expect("canonicalize"),
            std::fs::canonicalize(&elsewhere).expect("canonicalize"),
            "a planted symlink was followed"
        );
        drop(home);
        assert!(
            elsewhere.join("keep").exists(),
            "the link target was touched"
        );
        for seq in 0..PLANTED {
            let m = std::fs::symlink_metadata(predictable(&parent, seq)).expect("planted link");
            assert!(
                m.file_type().is_symlink(),
                "a planted link was removed or replaced"
            );
        }
    }

    #[test]
    fn created_directory_is_owner_only() {
        let root = root();
        let home = ScratchHome::create_in(root.path(), PREFIX).expect("create scratch home");
        let mode = std::fs::metadata(home.path()).expect("stat").mode() & 0o777;
        assert_eq!(mode, 0o700, "scratch HOME mode is {mode:o}, want 700");
    }

    #[test]
    fn directory_is_removed_on_drop() {
        let root = root();
        let home = ScratchHome::create_in(root.path(), PREFIX).expect("create scratch home");
        let p = home.path().to_path_buf();
        std::fs::create_dir(p.join(".config")).expect("child dir");
        std::fs::write(p.join(".config").join("f"), b"x").expect("child file");
        drop(home);
        assert!(!p.exists(), "scratch HOME left behind at {}", p.display());
    }

    #[test]
    fn concurrent_creates_get_distinct_directories() {
        let root = root();
        let parent = root.path().to_path_buf();
        let handles: Vec<_> = (0..8)
            .map(|_| {
                let parent = parent.clone();
                std::thread::spawn(move || {
                    (0..16)
                        .map(|_| ScratchHome::create_in(&parent, PREFIX).expect("create"))
                        .collect::<Vec<_>>()
                })
            })
            .collect();
        let homes: Vec<ScratchHome> = handles
            .into_iter()
            .flat_map(|h| h.join().expect("thread"))
            .collect();
        let mut paths: Vec<PathBuf> = homes.iter().map(|h| h.path().to_path_buf()).collect();
        paths.sort();
        paths.dedup();
        assert_eq!(paths.len(), homes.len(), "two creates shared one directory");
    }
}
