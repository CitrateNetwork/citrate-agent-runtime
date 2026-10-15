//! HGW-2: git state that would run a program later, outside the sandbox, and its revert.
//!
//! The sandbox lets a run write `.git/` inside its write roots, so `git init`, `git config` and
//! `git commit` work. A run could then leave git set up to start a program the next time the
//! member uses git in a terminal, where no sandbox applies: a hook, `core.hooksPath`,
//! `core.fsmonitor`, an alias, a filter or diff driver, an include, a `url.*.insteadOf` to a
//! non-https place. Configuration cannot be filtered by path, so the runner snapshots the
//! repositories a run could touch before it ([`snapshot`]) and, after it, **reverts** what the run
//! added ([`revert_new`], owner decision 2026-10-15): newly added risky config entries are removed
//! from the file (normal config such as `user.*`, `remote.*`, `branch.*`, `core.autocrlf` stays),
//! new hook files (other than git's `*.sample`) are deleted, a hooks folder or config swapped for
//! a symbolic link is put back. Each revert is a line in [`crate::RunReport::git_warnings`].
//! What was there before the run (the member's own setup) is never touched.
//!
//! Honest scope: the repositories checked are the run's folder, its parents up to the write root
//! that holds it, and the folders directly inside the run's folder. A repository created deeper
//! than that is not checked. An include file the run wrote is not deleted; the `include.path`
//! entry that would load it is. A `.git` the run turned into a pointer (a `gitdir:` file, as
//! `git worktree add` writes, or a symbolic link) to a git folder elsewhere is reported with the
//! risky state found where it points, but that folder is not changed: it may be the member's own.

use std::collections::BTreeSet;
use std::path::{Path, PathBuf};

/// Most entries of the run's folder looked at for nested repositories.
const MAX_CHILDREN: usize = 256;
/// Largest `.git/config` read.
const MAX_CONFIG_BYTES: u64 = 256 * 1024;
/// Largest `.git` file (`gitdir: <path>`) read.
const MAX_GITDIR_FILE_BYTES: u64 = 4096;

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

/// One config entry: its full key (section and key lowercased, subsection as written), its
/// value, and the lines it spans (`start..end`). `inline` = the key sits on its section header.
#[derive(Debug, Clone, PartialEq, Eq)]
struct ConfigEntry {
    key: String,
    value: String,
    start: usize,
    end: usize,
    inline: bool,
    /// The line of the section header this entry belongs to.
    header: Option<usize>,
}

fn section_name(inner: &str) -> String {
    match inner.split_once(char::is_whitespace) {
        Some((name, sub)) => format!(
            "{}.{}",
            name.to_ascii_lowercase(),
            sub.trim().trim_matches('"')
        ),
        None => match inner.split_once('.') {
            // Old-style `[section.sub]`.
            Some((name, sub)) => format!("{}.{}", name.to_ascii_lowercase(), sub),
            None => inner.to_ascii_lowercase(),
        },
    }
}

/// Parse a key line (`key = value`, or a bare `key`), stripping comments outside quotes.
fn key_value(line: &str) -> Option<(String, String)> {
    let line = line.trim();
    if line.is_empty() || line.starts_with('#') || line.starts_with(';') {
        return None;
    }
    let (k, v) = match line.split_once('=') {
        Some((k, v)) => (k.trim(), v.trim()),
        None => (line, "true"),
    };
    let mut value = String::new();
    let mut quoted = false;
    for c in v.chars() {
        match c {
            '"' => quoted = !quoted,
            '#' | ';' if !quoted => break,
            _ => value.push(c),
        }
    }
    Some((k.to_ascii_lowercase(), value.trim().to_string()))
}

/// Every entry of a git config text, with its line span. Continuation lines (a trailing `\`)
/// belong to the entry they continue.
fn parse_config(text: &str) -> Vec<ConfigEntry> {
    let lines: Vec<&str> = text.lines().collect();
    let mut out = Vec::new();
    let mut section = String::new();
    let mut header: Option<usize> = None;
    let mut i = 0;
    while i < lines.len() {
        let line = lines[i].trim();
        let start = i;
        let (body, inline) = if let Some(rest) = line.strip_prefix('[') {
            let Some(close) = rest.find(']') else {
                i += 1;
                continue;
            };
            section = section_name(rest[..close].trim());
            header = Some(i);
            (rest[close + 1..].trim().to_string(), true)
        } else {
            (line.to_string(), false)
        };
        let mut joined = body;
        while joined.ends_with('\\') && i + 1 < lines.len() {
            joined.pop();
            i += 1;
            joined.push_str(lines[i].trim());
        }
        i += 1;
        if let Some((k, v)) = key_value(&joined) {
            out.push(ConfigEntry {
                key: format!("{section}.{k}"),
                value: v,
                start,
                end: i,
                inline,
                header,
            });
        }
    }
    out
}

/// `(section.key, value)` pairs in a git config text that make git start a program or fetch from
/// an unexpected place (see [`is_risky`]).
pub(crate) fn risky_config(text: &str) -> Vec<(String, String)> {
    parse_config(text)
        .into_iter()
        .filter(|e| is_risky(&e.key, &e.value))
        .map(|e| (e.key, e.value))
        .collect()
}

/// The owner's list (2026-10-15): `core.hooksPath`, `core.fsmonitor`, `core.sshCommand`,
/// `core.pager`, `core.editor`, `alias.*`, `filter.*`, `diff.*.textconv` / `diff.external`,
/// `merge.*.driver`, `credential.*`, `include.path` / `includeIf.*.path`, `url.*.insteadOf` to a
/// non-https (or file) place, `protocol.*.allow = always`, `gpg.program`; plus other keys that
/// name a program (`core.askPass`, `core.gitProxy`, `sequence.editor`, `diff.*.command`,
/// `gpg.*.program`, `pager.*`, `*.cmd`/`*.path` of the tool sections, upload/receive-pack hooks).
fn is_risky(key: &str, value: &str) -> bool {
    let lower = key.to_ascii_lowercase();
    let (first, rest) = lower.split_once('.').unwrap_or((lower.as_str(), ""));
    let last = rest.rsplit('.').next().unwrap_or(rest);
    match first {
        "core" => matches!(
            last,
            "hookspath" | "fsmonitor" | "sshcommand" | "pager" | "editor" | "askpass" | "gitproxy"
        ),
        "alias" | "filter" | "credential" => true,
        "diff" => matches!(last, "external" | "textconv" | "command"),
        "merge" => last == "driver",
        "include" | "includeif" => last == "path",
        "url" => {
            if !matches!(last, "insteadof" | "pushinsteadof") {
                return false;
            }
            // The subsection (the replacement base) keeps its case in `key`.
            let base = key
                .split_once('.')
                .map(|(_, r)| r)
                .and_then(|r| r.rsplit_once('.'))
                .map(|(b, _)| b)
                .unwrap_or("");
            !base.to_ascii_lowercase().starts_with("https://")
        }
        "protocol" => last == "allow" && value.eq_ignore_ascii_case("always"),
        "gpg" => last == "program",
        "sequence" => last == "editor",
        "uploadpack" => last == "packobjectshook",
        "remote" => matches!(last, "uploadpack" | "receivepack"),
        "pager" => true,
        "browser" | "man" | "difftool" | "mergetool" => matches!(last, "cmd" | "path"),
        _ => false,
    }
}

/// One repository before a run.
#[derive(Debug, Clone)]
struct RepoSnap {
    git: PathBuf,
    /// The config text, when it was a regular, readable file of a checkable size.
    config_text: Option<String>,
    config_symlink: bool,
    risky: Vec<(String, String)>,
    hooks: BTreeSet<String>,
    hooks_symlink: bool,
    /// Where `.git` pointed (a `gitdir:` file or a symbolic link), resolved.
    pointer: Option<PathBuf>,
}

/// Where `git` (a `.git` path) points when it is a `gitdir:` file or a symbolic link to a
/// folder, resolved; `None` when it is a folder itself or absent.
fn pointer_of(git: &Path) -> Option<PathBuf> {
    let m = std::fs::symlink_metadata(git).ok()?;
    if m.file_type().is_symlink() {
        return std::fs::canonicalize(git).ok().filter(|p| p.is_dir());
    }
    if !m.is_file() || m.len() > MAX_GITDIR_FILE_BYTES {
        return None;
    }
    let text = std::fs::read_to_string(git).ok()?;
    let target = text.lines().next()?.strip_prefix("gitdir:")?.trim();
    let target = Path::new(target);
    let joined = if target.is_absolute() {
        target.to_path_buf()
    } else {
        git.parent()?.join(target)
    };
    std::fs::canonicalize(joined).ok().filter(|p| p.is_dir())
}

/// Risky state in a git folder the run newly pointed `.git` at: its risky config and its hooks
/// (other than samples). Reported, never changed.
fn report_pointer(git: &Path, target: &Path, out: &mut BTreeSet<String>) {
    let mut found: Vec<String> = Vec::new();
    let config = target.join("config");
    if let Ok(m) = std::fs::metadata(&config) {
        if m.is_file() && m.len() <= MAX_CONFIG_BYTES {
            if let Ok(text) = std::fs::read_to_string(&config) {
                for (k, v) in risky_config(&text) {
                    found.push(format!("{k} = {v}"));
                }
            }
        }
    }
    if let Ok(rd) = std::fs::read_dir(target.join("hooks")) {
        let mut hooks: Vec<String> = rd
            .flatten()
            .map(|e| e.file_name().to_string_lossy().into_owned())
            .filter(|n| !n.ends_with(".sample"))
            .collect();
        hooks.sort();
        for h in hooks {
            found.push(format!("hook {h}"));
        }
    }
    if !found.is_empty() {
        out.insert(format!(
            "{} now points git at {}, where git would run a program outside the sandbox ({}); not changed (it may be the member's own folder); the member should review it",
            git.display(),
            target.display(),
            found.join(", ")
        ));
    }
}

/// The repositories a run could touch, as they were before it.
#[derive(Debug, Clone, Default)]
pub(crate) struct Snapshot {
    repos: Vec<RepoSnap>,
}

fn snap_one(git: &Path) -> RepoSnap {
    let config = git.join("config");
    let (config_text, config_symlink) = match std::fs::symlink_metadata(&config) {
        Ok(m) if m.file_type().is_symlink() => (None, true),
        Ok(m) if m.is_file() && m.len() <= MAX_CONFIG_BYTES => {
            (std::fs::read_to_string(&config).ok(), false)
        }
        _ => (None, false),
    };
    let hooks_dir = git.join("hooks");
    let hooks_symlink = std::fs::symlink_metadata(&hooks_dir)
        .map(|m| m.file_type().is_symlink())
        .unwrap_or(false);
    let hooks = if hooks_symlink {
        BTreeSet::new()
    } else {
        std::fs::read_dir(&hooks_dir)
            .map(|rd| {
                rd.flatten()
                    .map(|e| e.file_name().to_string_lossy().into_owned())
                    .collect()
            })
            .unwrap_or_default()
    };
    RepoSnap {
        git: git.to_path_buf(),
        pointer: pointer_of(git),
        risky: config_text.as_deref().map(risky_config).unwrap_or_default(),
        config_text,
        config_symlink,
        hooks,
        hooks_symlink,
    }
}

/// Snapshot `git_dirs` before a run.
pub(crate) fn snapshot(git_dirs: &[PathBuf]) -> Snapshot {
    Snapshot {
        repos: git_dirs.iter().map(|g| snap_one(g)).collect(),
    }
}

/// After a run: revert what it added that would make git run a program later (see the module
/// docs). Returns one line per revert (or per item that could not be reverted), sorted.
pub(crate) fn revert_new(before: &Snapshot) -> Vec<String> {
    let mut out = BTreeSet::new();
    for b in &before.repos {
        let Ok(meta) = std::fs::symlink_metadata(&b.git) else {
            continue;
        };
        if !meta.is_dir() {
            if let Some(target) = pointer_of(&b.git) {
                if b.pointer.as_ref() != Some(&target) {
                    report_pointer(&b.git, &target, &mut out);
                }
            }
            continue;
        }
        revert_hooks(b, &mut out);
        revert_config(b, &mut out);
    }
    out.into_iter().collect()
}

fn revert_hooks(b: &RepoSnap, out: &mut BTreeSet<String>) {
    let hooks = b.git.join("hooks");
    let now_symlink = std::fs::symlink_metadata(&hooks)
        .map(|m| m.file_type().is_symlink())
        .unwrap_or(false);
    if now_symlink && !b.hooks_symlink {
        match std::fs::remove_file(&hooks) {
            Ok(()) => out.insert(format!(
                "reverted: {} had become a symbolic link (git would run hooks from elsewhere); removed",
                hooks.display()
            )),
            Err(e) => out.insert(format!(
                "could not revert {}, a new symbolic link: {e}; the member should remove it",
                hooks.display()
            )),
        };
        return;
    }
    if now_symlink {
        return;
    }
    let Ok(rd) = std::fs::read_dir(&hooks) else {
        return;
    };
    for e in rd.flatten() {
        let name = e.file_name().to_string_lossy().into_owned();
        if name.ends_with(".sample") || b.hooks.contains(&name) {
            continue;
        }
        let p = e.path();
        let removed = match std::fs::symlink_metadata(&p) {
            Ok(m) if m.is_dir() => std::fs::remove_dir_all(&p),
            _ => std::fs::remove_file(&p),
        };
        match removed {
            Ok(()) => out.insert(format!(
                "reverted: removed the new git hook {name} in {} (git would run it outside the sandbox)",
                hooks.display()
            )),
            Err(e) => out.insert(format!(
                "could not remove the new git hook {name} in {}: {e}; the member should remove it",
                hooks.display()
            )),
        };
    }
}

fn revert_config(b: &RepoSnap, out: &mut BTreeSet<String>) {
    let config = b.git.join("config");
    let Ok(m) = std::fs::symlink_metadata(&config) else {
        return;
    };
    if m.file_type().is_symlink() {
        if b.config_symlink {
            return;
        }
        let restored = std::fs::remove_file(&config).and_then(|()| match &b.config_text {
            Some(t) => std::fs::write(&config, t),
            None => Ok(()),
        });
        match restored {
            Ok(()) => out.insert(format!(
                "reverted: {} had become a symbolic link (git would read config from elsewhere); put back as it was",
                config.display()
            )),
            Err(e) => out.insert(format!(
                "could not revert {}, now a symbolic link: {e}; the member should check it",
                config.display()
            )),
        };
        return;
    }
    if !m.is_file() {
        return;
    }
    if m.len() > MAX_CONFIG_BYTES {
        out.insert(format!(
            "{} is too large to check after the run; the member should review it",
            config.display()
        ));
        return;
    }
    let Ok(text) = std::fs::read_to_string(&config) else {
        out.insert(format!(
            "{} could not be read after the run; the member should review it",
            config.display()
        ));
        return;
    };
    // What was risky before stays (once per occurrence); every other risky entry goes.
    let mut kept = b.risky.clone();
    let mut drop: Vec<ConfigEntry> = Vec::new();
    for e in parse_config(&text) {
        if !is_risky(&e.key, &e.value) {
            continue;
        }
        if let Some(i) = kept.iter().position(|(k, v)| *k == e.key && *v == e.value) {
            kept.remove(i);
            continue;
        }
        drop.push(e);
    }
    if drop.is_empty() {
        return;
    }
    let all = parse_config(&text);
    let mut lines: Vec<Option<String>> = text.lines().map(|l| Some(l.to_string())).collect();
    // A section header whose every entry is reverted goes too (it would be left empty).
    let headers: BTreeSet<usize> = drop.iter().filter_map(|e| e.header).collect();
    for h in headers {
        if all
            .iter()
            .filter(|e| e.header == Some(h))
            .all(|e| drop.contains(e))
        {
            if let Some(slot) = lines.get_mut(h) {
                *slot = None;
            }
        }
    }
    for e in &drop {
        for (i, slot) in lines.iter_mut().enumerate().take(e.end).skip(e.start) {
            if e.inline && i == e.start {
                // Keep the section header, drop the key written on the same line.
                *slot = slot.as_ref().map(|l| match l.find(']') {
                    Some(c) => l[..=c].to_string(),
                    None => l.clone(),
                });
            } else {
                *slot = None;
            }
        }
    }
    let mut rewritten: String = lines.into_iter().flatten().collect::<Vec<_>>().join("\n");
    if text.ends_with('\n') {
        rewritten.push('\n');
    }
    match std::fs::write(&config, rewritten) {
        Ok(()) => {
            for e in drop {
                out.insert(format!(
                    "reverted: removed git config {} = {} from {} (git could run a program or fetch from it outside the sandbox)",
                    e.key,
                    e.value,
                    config.display()
                ));
            }
        }
        Err(err) => {
            for e in drop {
                out.insert(format!(
                    "could not revert git config {} = {} in {}: {err}; the member should remove it",
                    e.key,
                    e.value,
                    config.display()
                ));
            }
        }
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
                "core.fsmonitor",
                "core.hookspath",
                "alias.st",
                "alias.x",
                "filter.lfs.smudge",
                "includeif.gitdir:~/.path"
            ]
        );
        let url = "[url \"file:///x\"]\n\tinsteadOf = https://a/\n[url \"https://m/\"]\n\tinsteadOf = https://a/\n[protocol \"ext\"]\n\tallow = always\n[protocol \"file\"]\n\tallow = user\n";
        let keys: Vec<String> = risky_config(url).into_iter().map(|(k, _)| k).collect();
        assert_eq!(keys, vec!["url.file:///x.insteadof", "protocol.ext.allow"]);
    }

    #[test]
    fn parsing_handles_inline_keys_continuations_comments_and_old_style_sections() {
        let text = "[core] hooksPath = .h\n[alias]\n\tx = \"!sh \\\n -c id\" # note\n[remote.origin]\n\turl = https://r\n";
        let e = parse_config(text);
        let keys: Vec<(&str, &str, bool)> = e
            .iter()
            .map(|e| (e.key.as_str(), e.value.as_str(), e.inline))
            .collect();
        assert_eq!(
            keys,
            vec![
                ("core.hookspath", ".h", true),
                ("alias.x", "!sh -c id", false),
                ("remote.origin.url", "https://r", false),
            ]
        );
        assert_eq!((e[1].start, e[1].end), (2, 4));
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
