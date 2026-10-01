//! Git mode: when the granted folder is inside a git work tree, record a checkpoint commit on a
//! private ref, `refs/citrate/checkpoints/<session>`, without touching HEAD, the index, or any
//! branch.
//!
//! How: copy the repository's index to a temporary index in the store (read only; the real index
//! is never opened for writing), `git add -A -- .` from the granted folder into that temporary
//! index (honours `.gitignore`; paths outside the folder keep their indexed state), `write-tree`,
//! `commit-tree --no-gpg-sign` with a fixed identity, then `update-ref` with the previous value
//! as a compare-and-swap. `git add` does write blob objects into the repository's object store;
//! that is the only change, and it is invisible to `status`, `log`, and the branch. Every git
//! call runs with hooks and fsmonitor turned off.

use std::ffi::OsStr;
use std::fs;
use std::io::ErrorKind;
use std::path::{Path, PathBuf};
use std::process::{Command, Output};

use crate::error::{io_err, Error, Result};
use crate::fsutil::{unique, TempGuard};
use crate::session::SessionId;
use crate::store::{CheckpointStore, TMP_DIR};

/// The ref a session's checkpoints live on.
pub fn checkpoint_ref(session: &SessionId) -> String {
    format!("refs/citrate/checkpoints/{session}")
}

const AUTHOR_NAME: &str = "Citrate checkpoint";
const AUTHOR_EMAIL: &str = "checkpoint@citrate.invalid";
const DEFAULT_MESSAGE: &str = "citrate checkpoint";

/// The result of a git checkpoint.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct GitCheckpoint {
    pub reference: String,
    pub commit: String,
    /// The commit's first parent (the previous checkpoint, else HEAD; none on an unborn branch).
    pub parent: Option<String>,
    /// False when the tree matched the previous checkpoint and no commit was made.
    pub created: bool,
}

/// Environment that could redirect git somewhere other than the folder we name.
const SCRUB_ENV: [&str; 9] = [
    "GIT_DIR",
    "GIT_WORK_TREE",
    "GIT_INDEX_FILE",
    "GIT_OBJECT_DIRECTORY",
    "GIT_ALTERNATE_OBJECT_DIRECTORIES",
    "GIT_COMMON_DIR",
    "GIT_NAMESPACE",
    "GIT_PREFIX",
    "GIT_CEILING_DIRECTORIES",
];

fn git(dir: &Path, index: Option<&Path>, args: &[&OsStr]) -> Result<Output> {
    let mut cmd = Command::new("git");
    // Run no program the repository configures: no hooks (update-ref would run the
    // reference-transaction hook) and no fsmonitor (consulted by `add`).
    cmd.arg("-C")
        .arg(dir)
        .args([
            "-c",
            "core.hooksPath=/dev/null",
            "-c",
            "core.fsmonitor=false",
        ])
        .args(args);
    for k in SCRUB_ENV {
        cmd.env_remove(k);
    }
    cmd.env("GIT_TERMINAL_PROMPT", "0")
        .env("GIT_OPTIONAL_LOCKS", "0")
        .env("GIT_AUTHOR_NAME", AUTHOR_NAME)
        .env("GIT_AUTHOR_EMAIL", AUTHOR_EMAIL)
        .env("GIT_COMMITTER_NAME", AUTHOR_NAME)
        .env("GIT_COMMITTER_EMAIL", AUTHOR_EMAIL);
    if let Some(i) = index {
        cmd.env("GIT_INDEX_FILE", i);
    }
    cmd.output().map_err(|e| {
        if e.kind() == ErrorKind::NotFound {
            Error::GitUnavailable("the git executable was not found".into())
        } else {
            Error::GitUnavailable(e.to_string())
        }
    })
}

fn git_ok(dir: &Path, index: Option<&Path>, args: &[&str]) -> Result<String> {
    let os: Vec<&OsStr> = args.iter().map(OsStr::new).collect();
    let out = git(dir, index, &os)?;
    if !out.status.success() {
        return Err(Error::Git {
            command: args.first().copied().unwrap_or("").to_string(),
            stderr: String::from_utf8_lossy(&out.stderr).trim().to_string(),
        });
    }
    Ok(String::from_utf8_lossy(&out.stdout).trim().to_string())
}

/// `rev-parse --verify -q <rev>`, `None` when it does not resolve.
fn resolve_rev(dir: &Path, rev: &str) -> Result<Option<String>> {
    let os = [
        OsStr::new("rev-parse"),
        OsStr::new("--verify"),
        OsStr::new("-q"),
        OsStr::new(rev),
    ];
    let out = git(dir, None, &os)?;
    if out.status.success() {
        Ok(Some(
            String::from_utf8_lossy(&out.stdout).trim().to_string(),
        ))
    } else {
        Ok(None)
    }
}

pub(crate) fn is_work_tree(dir: &Path) -> Result<bool> {
    let os = [OsStr::new("rev-parse"), OsStr::new("--is-inside-work-tree")];
    let out = git(dir, None, &os)?;
    Ok(out.status.success() && String::from_utf8_lossy(&out.stdout).trim() == "true")
}

pub(crate) fn checkpoint(
    tmp_dir: &Path,
    session: &SessionId,
    root: &Path,
    message: &str,
) -> Result<GitCheckpoint> {
    let root = fs::canonicalize(root).map_err(io_err(root))?;
    if !is_work_tree(&root)? {
        return Err(Error::NotGitWorkTree(root));
    }
    let reference = checkpoint_ref(session);
    let real_index = {
        let p = PathBuf::from(git_ok(&root, None, &["rev-parse", "--git-path", "index"])?);
        if p.is_absolute() {
            p
        } else {
            root.join(p)
        }
    };
    let tmp_index = tmp_dir.join(unique(&format!("git-{session}-"), ".index"));
    let _index_guard = TempGuard::new(tmp_index.clone());
    let _lock_guard = TempGuard::new(tmp_index.with_extension("index.lock"));
    match fs::copy(&real_index, &tmp_index) {
        Ok(_) => {}
        Err(e) if e.kind() == ErrorKind::NotFound => {}
        Err(e) => return Err(io_err(&real_index)(e)),
    }
    git_ok(&root, Some(&tmp_index), &["add", "-A", "--", "."])?;
    let tree = git_ok(&root, Some(&tmp_index), &["write-tree"])?;

    let prev = resolve_rev(&root, &format!("{reference}^{{commit}}"))?;
    if let Some(prev) = &prev {
        let prev_tree = git_ok(&root, None, &["rev-parse", &format!("{prev}^{{tree}}")])?;
        if prev_tree == tree {
            return Ok(GitCheckpoint {
                reference,
                commit: prev.clone(),
                parent: resolve_rev(&root, &format!("{prev}^1"))?,
                created: false,
            });
        }
    }
    let parent = match &prev {
        Some(p) => Some(p.clone()),
        None => resolve_rev(&root, "HEAD^{commit}")?,
    };
    let message = if message.trim().is_empty() {
        DEFAULT_MESSAGE
    } else {
        message
    };
    let mut args: Vec<&str> = vec!["commit-tree", "--no-gpg-sign", &tree];
    if let Some(p) = &parent {
        args.extend(["-p", p.as_str()]);
    }
    args.extend(["-m", message]);
    let commit = git_ok(&root, None, &args)?;
    let zero = "0".repeat(tree.len());
    let old = prev.as_deref().unwrap_or(&zero);
    git_ok(
        &root,
        None,
        &[
            "update-ref",
            "-m",
            "citrate checkpoint",
            &reference,
            &commit,
            old,
        ],
    )?;
    Ok(GitCheckpoint {
        reference,
        commit,
        parent,
        created: true,
    })
}

impl CheckpointStore {
    /// Whether `root` is inside a git work tree (so git mode is available).
    pub fn is_git_work_tree(&self, root: &Path) -> Result<bool> {
        is_work_tree(root)
    }

    /// Commit the granted folder's current state to `refs/citrate/checkpoints/<session>`.
    /// HEAD, the index, and every branch are left as they were. A no-op (returns the previous
    /// checkpoint with `created: false`) when nothing changed since the last checkpoint.
    pub fn git_checkpoint(
        &self,
        session: &SessionId,
        root: &Path,
        message: &str,
    ) -> Result<GitCheckpoint> {
        checkpoint(&self.dir().join(TMP_DIR), session, root, message)
    }

    /// The session's latest checkpoint commit, if any.
    pub fn git_checkpoint_head(&self, session: &SessionId, root: &Path) -> Result<Option<String>> {
        let root = fs::canonicalize(root).map_err(io_err(root))?;
        if !is_work_tree(&root)? {
            return Err(Error::NotGitWorkTree(root));
        }
        resolve_rev(&root, &format!("{}^{{commit}}", checkpoint_ref(session)))
    }
}
