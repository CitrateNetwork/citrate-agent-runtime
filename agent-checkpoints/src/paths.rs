//! Resolving a tool's path against the granted folder. Only plain relative components are
//! accepted; `..`, other roots, and symlinked parent directories are refused, so a checkpointed
//! path can never resolve outside the folder.

use std::fs;
use std::io::ErrorKind;
use std::path::{Component, Path, PathBuf};

use crate::error::{io_err, Error, Result};

pub(crate) struct Resolved {
    /// `/`-joined path relative to the granted folder.
    pub rel: String,
    pub abs: PathBuf,
    /// Parent directories (relative, shallowest first) that do not exist yet.
    pub missing_dirs: Vec<String>,
}

fn refuse(p: &Path, reason: &str) -> Error {
    Error::Path {
        path: p.display().to_string(),
        reason: reason.to_string(),
    }
}

/// Canonicalize the granted folder; it must exist and be a directory.
pub(crate) fn canonical_root(root: &Path) -> Result<PathBuf> {
    let c =
        fs::canonicalize(root).map_err(|_| refuse(root, "the granted folder does not exist"))?;
    if !c.is_dir() {
        return Err(refuse(root, "the granted folder is not a directory"));
    }
    Ok(c)
}

pub(crate) fn resolve(root_canon: &Path, root_given: &Path, p: &Path) -> Result<Resolved> {
    let rel_path: &Path = if p.is_absolute() {
        p.strip_prefix(root_canon)
            .or_else(|_| p.strip_prefix(root_given))
            .map_err(|_| refuse(p, "outside the granted folder"))?
    } else {
        p
    };
    let mut parts: Vec<String> = Vec::new();
    for c in rel_path.components() {
        match c {
            Component::Normal(s) => match s.to_str() {
                Some(s) => parts.push(s.to_string()),
                None => return Err(refuse(p, "the path is not valid UTF-8")),
            },
            Component::CurDir => {}
            Component::ParentDir => return Err(refuse(p, "'..' is not allowed")),
            Component::RootDir | Component::Prefix(_) => {
                return Err(refuse(p, "outside the granted folder"))
            }
        }
    }
    if parts.is_empty() {
        return Err(refuse(p, "empty path (the granted folder itself)"));
    }
    let mut cur = root_canon.to_path_buf();
    let mut missing_dirs = Vec::new();
    let mut missing = false;
    for (i, part) in parts[..parts.len() - 1].iter().enumerate() {
        cur.push(part);
        if missing {
            missing_dirs.push(parts[..=i].join("/"));
            continue;
        }
        match fs::symlink_metadata(&cur) {
            Ok(m) if m.file_type().is_symlink() => {
                return Err(refuse(p, "a parent directory is a symbolic link"))
            }
            Ok(m) if !m.is_dir() => return Err(refuse(p, "a parent is not a directory")),
            Ok(_) => {}
            Err(e) if e.kind() == ErrorKind::NotFound => {
                missing = true;
                missing_dirs.push(parts[..=i].join("/"));
            }
            Err(e) => return Err(io_err(&cur)(e)),
        }
    }
    let rel = parts.join("/");
    let abs = root_canon.join(&rel);
    Ok(Resolved {
        rel,
        abs,
        missing_dirs,
    })
}
