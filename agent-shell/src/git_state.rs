//! HGW-2: git state that would run a program later, outside the sandbox.
//!
//! The sandbox lets a run write `.git/` inside its write roots, so `git init`, `git config` and
//! `git commit` work. A run can then leave git set up to start a program the next time the
//! member uses git in a terminal, where no sandbox applies: a hook, `core.hooksPath`,
//! `core.fsmonitor`, an alias that starts a shell, a diff or filter driver, an include. The
//! Seatbelt profile keeps hook files out of `.git/hooks`, but configuration cannot be filtered by
//! path. So the runner looks at the repositories a run could have touched before and after it,
//! and reports what is new ([`crate::RunReport::git_warnings`]) for the member to see. It reports,
//! it does not change anything.
//!
//! Honest scope: the repositories checked are the run's folder, its parents up to the write root
//! that holds it, and the folders directly inside the run's folder. A repository created deeper
//! than that is not checked.

use std::collections::BTreeSet;
use std::path::{Path, PathBuf};

/// Most entries of the run's folder looked at for nested repositories.
const MAX_CHILDREN: usize = 256;
/// Largest `.git/config` read.
const MAX_CONFIG_BYTES: u64 = 256 * 1024;

/// The repositories (their `.git` folders) a run in `cwd` with `write_roots` could touch.
pub(crate) fn repo_dirs(cwd: &Path, write_roots: &[PathBuf]) -> Vec<PathBuf> {
    let mut out: Vec<PathBuf> = Vec::new();
    let mut push = |p: PathBuf| {
        if !out.contains(&p) {
            out.push(p);
        }
    };
    if let Some(root) = write_roots
        .iter()
        .filter(|r| cwd.starts_with(r))
        .max_by_key(|r| r.components().count())
    {
        for dir in cwd.ancestors() {
            push(dir.join(".git"));
            if dir == root.as_path() {
                break;
            }
        }
    }
    if let Ok(rd) = std::fs::read_dir(cwd) {
        for e in rd.flatten().take(MAX_CHILDREN) {
            if e.file_type().map(|t| t.is_dir()).unwrap_or(false) {
                push(e.path().join(".git"));
            }
        }
    }
    out
}

/// One line per risky item across `git_dirs` (sorted, without repeats).
pub(crate) fn risks(git_dirs: &[PathBuf]) -> BTreeSet<String> {
    let mut out = BTreeSet::new();
    for g in git_dirs {
        let Ok(meta) = std::fs::symlink_metadata(g) else {
            continue;
        };
        if !meta.is_dir() {
            continue;
        }
        let hooks = g.join("hooks");
        match std::fs::symlink_metadata(&hooks) {
            Ok(m) if m.file_type().is_symlink() => {
                out.insert(format!("{} is a symbolic link", hooks.display()));
            }
            Ok(m) if m.is_dir() => {
                if let Ok(rd) = std::fs::read_dir(&hooks) {
                    for e in rd.flatten() {
                        let name = e.file_name().to_string_lossy().into_owned();
                        if !name.ends_with(".sample") {
                            out.insert(format!(
                                "git hook {name} in {} (git runs it outside the sandbox)",
                                hooks.display()
                            ));
                        }
                    }
                }
            }
            _ => {}
        }
        let config = g.join("config");
        if let Ok(m) = std::fs::symlink_metadata(&config) {
            if m.file_type().is_symlink() {
                out.insert(format!("{} is a symbolic link", config.display()));
            } else if m.len() <= MAX_CONFIG_BYTES {
                if let Ok(text) = std::fs::read_to_string(&config) {
                    for (key, value) in risky_config(&text) {
                        out.insert(format!(
                            "git config {key} = {value} in {} (git may run a program from it)",
                            config.display()
                        ));
                    }
                }
            } else {
                out.insert(format!("{} is too large to check", config.display()));
            }
        }
    }
    out
}

/// `(section.key, value)` pairs in a git config text that make git start a program. Keys are
/// lowercased (git's own rule for section and key names; a subsection keeps its case).
pub(crate) fn risky_config(text: &str) -> Vec<(String, String)> {
    let mut out = Vec::new();
    let mut section = String::new();
    for raw in text.lines() {
        let line = raw.trim();
        if line.is_empty() || line.starts_with('#') || line.starts_with(';') {
            continue;
        }
        if let Some(rest) = line.strip_prefix('[') {
            let inner = rest.split(']').next().unwrap_or("").trim();
            section = match inner.split_once(char::is_whitespace) {
                Some((name, sub)) => {
                    format!(
                        "{}.{}",
                        name.to_ascii_lowercase(),
                        sub.trim().trim_matches('"')
                    )
                }
                None => inner.to_ascii_lowercase(),
            };
            continue;
        }
        let (k, v) = match line.split_once('=') {
            Some((k, v)) => (k.trim(), v.trim().trim_matches('"')),
            None => (line, "true"),
        };
        let key = format!("{section}.{}", k.to_ascii_lowercase());
        if is_risky(&key, v) {
            out.push((key, v.to_string()));
        }
    }
    out
}

fn is_risky(key: &str, value: &str) -> bool {
    let lower = key.to_ascii_lowercase();
    let (first, rest) = lower.split_once('.').unwrap_or((lower.as_str(), ""));
    let last = rest.rsplit('.').next().unwrap_or(rest);
    let off = matches!(
        value.to_ascii_lowercase().as_str(),
        "" | "false" | "0" | "no" | "off"
    );
    match first {
        "core" => match last {
            "fsmonitor" => !off,
            "hookspath" | "sshcommand" | "gitproxy" | "editor" | "pager" | "askpass" => true,
            _ => false,
        },
        "alias" => value.trim_start().starts_with('!'),
        "sequence" => last == "editor",
        "credential" => last == "helper",
        "gpg" => last == "program",
        "diff" => matches!(last, "external" | "command" | "textconv"),
        "filter" => matches!(last, "clean" | "smudge" | "process"),
        "merge" => last == "driver",
        "include" | "includeif" => last == "path",
        "uploadpack" => last == "packobjectshook",
        "remote" => matches!(last, "uploadpack" | "receivepack"),
        "pager" | "browser" | "man" | "difftool" | "mergetool" => {
            matches!(last, "cmd" | "path") || first == "pager"
        }
        _ => false,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn risky_keys_are_found_and_harmless_ones_are_not() {
        let text = "[core]\n\trepositoryformatversion = 0\n\tfsmonitor = false\n\thooksPath = .h\n[alias]\n\tst = status\n\tx = !sh -c id\n[filter \"lfs\"]\n\tsmudge = git-lfs smudge %f\n[remote \"origin\"]\n\turl = https://example.invalid/r.git\n[includeIf \"gitdir:~/\"]\n\tpath = ~/.evil\n";
        let keys: Vec<String> = risky_config(text).into_iter().map(|(k, _)| k).collect();
        assert_eq!(
            keys,
            vec![
                "core.hookspath",
                "alias.x",
                "filter.lfs.smudge",
                "includeif.gitdir:~/.path"
            ]
        );
        assert!(risky_config("[core]\n\tfsmonitor = true\n")
            .iter()
            .any(|(k, _)| k == "core.fsmonitor"));
    }

    #[test]
    fn repo_dirs_cover_the_cwd_its_parents_to_the_root_and_its_children() {
        let d = tempfile::tempdir().expect("tmp");
        let root = d.path().join("root");
        std::fs::create_dir_all(root.join("a/b/c")).expect("dirs");
        let got = repo_dirs(&root.join("a/b"), std::slice::from_ref(&root));
        assert!(got.contains(&root.join("a/b/.git")));
        assert!(got.contains(&root.join("a/.git")));
        assert!(got.contains(&root.join(".git")));
        assert!(got.contains(&root.join("a/b/c/.git")));
        assert!(
            !got.contains(&d.path().join(".git")),
            "never above the write root"
        );
    }
}
