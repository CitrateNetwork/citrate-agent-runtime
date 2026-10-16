//! HGW-2: git state that would run a program later, outside the sandbox, and its revert.
//!
//! The sandbox lets a run write `.git/` inside its write roots, so `git init`, `git config` and
//! `git commit` work. A run could then leave git set up to start a program the next time the
//! member uses git in a terminal, where no sandbox applies: a hook, `core.hooksPath`,
//! `core.fsmonitor`, an alias, a filter or diff driver, an include, a `url.*.insteadOf` to a
//! non-https place. Configuration cannot be filtered by path, so the runner snapshots every
//! repository in the run's write roots before it ([`snapshot`]) and, after it, **reverts** what
//! the run added ([`revert_new`], owner decision 2026-10-15): newly added risky config entries are
//! removed from the file (normal config such as `user.*`, `remote.*`, `branch.*`,
//! `core.autocrlf` stays), new hook files (other than git's `*.sample`) are deleted, a hooks
//! folder or config swapped for a symbolic link is put back. Each revert is a line in
//! [`crate::RunReport::git_warnings`]. What was there before the run (the member's own setup) is
//! never touched.
//!
//! Coverage: every write root is walked (symbolic links are not followed) for git folders: a
//! `.git` folder at any depth, a bare repository (a folder holding `HEAD`, `objects/` and
//! `refs/`), the linked worktrees under `.git/worktrees/` and the submodule git folders under
//! `.git/modules/`. In each, `config`, `config.worktree` and `hooks/` are checked. A repository
//! the run created is reverted against an empty baseline. A `.git` file or link (`gitdir:`) and a
//! worktree's `commondir` are followed when they point at a git folder inside the write roots;
//! one pointing outside them (where the sandbox cannot write) is reported with the risky state
//! found there and not changed.
//!
//! Bounds: one walk looks at no more than [`MAX_WALK_ENTRIES`] folder entries and goes no deeper
//! than [`MAX_WALK_DEPTH`] folders below a write root. When a walk stops early it says so in the
//! report (the member should review git state there before using git outside the sandbox), and a
//! repository the run-before walk did not reach is reported, not changed, since what was there
//! before is unknown. An include file the run wrote is not deleted; the `include.path` entry that
//! would load it is.

use std::collections::{BTreeMap, BTreeSet, VecDeque};
use std::path::{Path, PathBuf};

/// Most folder entries one walk of the write roots looks at.
pub(crate) const MAX_WALK_ENTRIES: usize = 300_000;
/// Deepest folder level below a write root one walk looks at.
pub(crate) const MAX_WALK_DEPTH: usize = 48;
/// Largest `config` read.
const MAX_CONFIG_BYTES: u64 = 256 * 1024;
/// Largest `.git` file (`gitdir: <path>`) or `commondir` read.
const MAX_GITDIR_FILE_BYTES: u64 = 4096;
/// The config files git reads from a git folder (`config.worktree` with
/// `extensions.worktreeConfig`).
const CONFIG_FILES: [&str; 2] = ["config", "config.worktree"];

#[derive(Debug, Clone, Copy)]
struct Limits {
    entries: usize,
    depth: usize,
}

const LIMITS: Limits = Limits {
    entries: MAX_WALK_ENTRIES,
    depth: MAX_WALK_DEPTH,
};

/// Whether `name` is what git looks for as a repository's git folder (the Mac's and Windows'
/// file systems ignore case, so `.GIT` is the same folder there).
fn is_dot_git(name: &str) -> bool {
    if cfg!(any(target_os = "macos", windows)) {
        name.eq_ignore_ascii_case(".git")
    } else {
        name == ".git"
    }
}

/// Whether `dir` is a git folder git would use: `HEAD` with `objects/` and `refs/`, or `HEAD`
/// with a `commondir` (a linked worktree's).
fn is_git_dir(dir: &Path) -> bool {
    let has = |n: &str, want_dir: bool| {
        std::fs::symlink_metadata(dir.join(n))
            .map(|m| if want_dir { m.is_dir() } else { !m.is_dir() })
            .unwrap_or(false)
    };
    has("HEAD", false) && ((has("objects", true) && has("refs", true)) || has("commondir", false))
}

/// What one walk of the write roots found.
#[derive(Debug, Default)]
struct Found {
    git_dirs: BTreeSet<PathBuf>,
    /// `.git` files or links and `commondir` files, with where they point (resolved).
    pointers: BTreeMap<PathBuf, PathBuf>,
    /// Why the walk did not see everything (empty when it did).
    incomplete: Vec<String>,
}

struct Walk<'a> {
    roots: &'a [PathBuf],
    limits: Limits,
    seen: usize,
    stopped: bool,
    too_deep: bool,
    found: Found,
}

impl Walk<'_> {
    /// Count one entry; `false` once the bound is reached.
    fn tick(&mut self) -> bool {
        if self.stopped {
            return false;
        }
        self.seen += 1;
        if self.seen > self.limits.entries {
            self.stopped = true;
            self.found.incomplete.push(format!(
                "the folders this command could write hold more than {} entries",
                self.limits.entries
            ));
            return false;
        }
        true
    }

    fn inside(&self, p: &Path) -> bool {
        self.roots.iter().any(|r| p.starts_with(r))
    }

    fn walk_root(&mut self, root: &Path) {
        let mut queue = VecDeque::from([(root.to_path_buf(), 0usize)]);
        while let Some((dir, depth)) = queue.pop_front() {
            if self.stopped {
                return;
            }
            if is_git_dir(&dir) {
                self.add_git_dir(&dir);
                continue;
            }
            let Ok(rd) = std::fs::read_dir(&dir) else {
                continue;
            };
            for e in rd.flatten() {
                if !self.tick() {
                    return;
                }
                let path = e.path();
                if is_dot_git(&e.file_name().to_string_lossy()) {
                    self.dot_git(&path);
                    continue;
                }
                // `file_type` does not follow a symbolic link.
                if !e.file_type().map(|t| t.is_dir()).unwrap_or(false) {
                    continue;
                }
                if depth + 1 > self.limits.depth {
                    if !self.too_deep {
                        self.too_deep = true;
                        self.found.incomplete.push(format!(
                            "{} is more than {} folders deep",
                            path.display(),
                            self.limits.depth
                        ));
                    }
                    continue;
                }
                queue.push_back((path, depth + 1));
            }
        }
    }

    fn dot_git(&mut self, p: &Path) {
        let Ok(m) = std::fs::symlink_metadata(p) else {
            return;
        };
        if m.is_dir() {
            self.add_git_dir(p);
            return;
        }
        if let Some(target) = pointer_of(p) {
            self.follow(p, target);
        }
    }

    /// A pointer (`.git` file or link, `commondir`) to `target`: recorded, and followed when
    /// `target` is a git folder inside the write roots.
    fn follow(&mut self, pointer: &Path, target: PathBuf) {
        self.found
            .pointers
            .insert(pointer.to_path_buf(), target.clone());
        if self.inside(&target) && is_git_dir(&target) {
            self.add_git_dir(&target);
        }
    }

    fn add_git_dir(&mut self, git: &Path) {
        if !self.found.git_dirs.insert(git.to_path_buf()) {
            return;
        }
        let common = git.join("commondir");
        if let Some(target) = read_pointer_file(&common, git, false) {
            self.follow(&common, target);
        }
        if let Ok(rd) = std::fs::read_dir(git.join("worktrees")) {
            for e in rd.flatten() {
                if !self.tick() {
                    return;
                }
                if e.file_type().map(|t| t.is_dir()).unwrap_or(false) {
                    self.add_git_dir(&e.path());
                }
            }
        }
        self.modules(&git.join("modules"), 0);
    }

    /// Submodule git folders under `modules/` (a submodule's name may hold `/`).
    fn modules(&mut self, dir: &Path, depth: usize) {
        let Ok(rd) = std::fs::read_dir(dir) else {
            return;
        };
        for e in rd.flatten() {
            if !self.tick() {
                return;
            }
            if !e.file_type().map(|t| t.is_dir()).unwrap_or(false) {
                continue;
            }
            let p = e.path();
            if is_git_dir(&p) {
                self.add_git_dir(&p);
            } else if depth < self.limits.depth {
                self.modules(&p, depth + 1);
            }
        }
    }
}

/// The write roots, resolved, without duplicates or roots inside another.
fn normalize_roots(write_roots: &[PathBuf]) -> Vec<PathBuf> {
    let mut roots: Vec<PathBuf> = write_roots
        .iter()
        .map(|r| std::fs::canonicalize(r).unwrap_or_else(|_| r.clone()))
        .collect();
    roots.sort();
    roots.dedup();
    let all = roots.clone();
    roots.retain(|r| !all.iter().any(|o| o != r && r.starts_with(o)));
    roots
}

fn discover(roots: &[PathBuf], limits: Limits) -> Found {
    let mut w = Walk {
        roots,
        limits,
        seen: 0,
        stopped: false,
        too_deep: false,
        found: Found::default(),
    };
    for root in roots {
        w.walk_root(root);
    }
    w.found
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
/// name a program (`core.askPass`, `core.gitProxy`, `core.alternateRefsCommand`,
/// `sequence.editor`, `diff.*.command`, `interactive.diffFilter`, `gpg.*.program`,
/// `gpg.ssh.defaultKeyCommand`, `pager.*`, `hook.*` (config-defined hooks), `tar.*.command`,
/// `submodule.*.update = !…`, the `sendemail` commands, `*.cmd`/`*.path` of the tool sections,
/// upload/receive-pack hooks); plus `core.worktree`, which moves where git works; plus what could
/// drop the `Co-authored-by: Hermes` trailer from later commits (`trailer.*`, `commit.cleanup`,
/// `core.commentChar`/`commentString`).
fn is_risky(key: &str, value: &str) -> bool {
    let lower = key.to_ascii_lowercase();
    let (first, rest) = lower.split_once('.').unwrap_or((lower.as_str(), ""));
    let last = rest.rsplit('.').next().unwrap_or(rest);
    match first {
        "core" => matches!(
            last,
            "hookspath"
                | "fsmonitor"
                | "sshcommand"
                | "pager"
                | "editor"
                | "askpass"
                | "gitproxy"
                | "commentchar"
                | "commentstring"
                | "alternaterefscommand"
                | "worktree"
        ),
        "alias" | "filter" | "credential" => true,
        "diff" => matches!(last, "external" | "textconv" | "command"),
        "interactive" => last == "difffilter",
        "hook" => true,
        "tar" => last == "command",
        "submodule" => last == "update" && value.trim_start().starts_with('!'),
        "sendemail" => matches!(
            last,
            "sendmailcmd" | "tocmd" | "cccmd" | "headercmd" | "smtpserver"
        ),
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
        "gpg" => matches!(last, "program" | "defaultkeycommand"),
        "sequence" => last == "editor",
        "uploadpack" => last == "packobjectshook",
        "remote" => matches!(last, "uploadpack" | "receivepack"),
        "pager" => true,
        "browser" | "man" | "difftool" | "mergetool" | "guitool" => matches!(last, "cmd" | "path"),
        // `trailer.<token>.cmd` / `.command` run a program; the rest can drop the
        // `Co-authored-by: Hermes` trailer from later commits (owner decision 2026-10-15).
        "trailer" => true,
        "commit" => last == "cleanup",
        _ => false,
    }
}

/// Where `git` (a `.git` path) points when it is a `gitdir:` file or a symbolic link to a
/// folder, resolved; `None` when it is a folder itself or absent.
fn pointer_of(git: &Path) -> Option<PathBuf> {
    let m = std::fs::symlink_metadata(git).ok()?;
    if m.file_type().is_symlink() {
        return std::fs::canonicalize(git).ok().filter(|p| p.is_dir());
    }
    read_pointer_file(git, git.parent()?, true)
}

/// The folder a small pointer file names (`gitdir: <path>` when `prefixed`, else the bare path,
/// as in `commondir`), resolved against `base`.
fn read_pointer_file(file: &Path, base: &Path, prefixed: bool) -> Option<PathBuf> {
    let m = std::fs::symlink_metadata(file).ok()?;
    if !m.is_file() || m.len() > MAX_GITDIR_FILE_BYTES {
        return None;
    }
    let text = std::fs::read_to_string(file).ok()?;
    let line = text.lines().next()?;
    let target = if prefixed {
        line.strip_prefix("gitdir:")?
    } else {
        line
    }
    .trim();
    if target.is_empty() {
        return None;
    }
    let target = Path::new(target);
    let joined = if target.is_absolute() {
        target.to_path_buf()
    } else {
        base.join(target)
    };
    std::fs::canonicalize(joined).ok().filter(|p| p.is_dir())
}

/// Risky state (config entries, hooks other than samples) in a git folder, as report items.
fn risky_state(git: &Path) -> Vec<String> {
    let mut found: Vec<String> = Vec::new();
    for name in CONFIG_FILES {
        let config = git.join(name);
        if let Ok(m) = std::fs::metadata(&config) {
            if m.is_file() && m.len() <= MAX_CONFIG_BYTES {
                if let Ok(text) = std::fs::read_to_string(&config) {
                    for (k, v) in risky_config(&text) {
                        found.push(format!("{k} = {v}"));
                    }
                }
            }
        }
    }
    if let Ok(rd) = std::fs::read_dir(git.join("hooks")) {
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
    found
}

/// A pointer the run made or changed: what git would still run where it points. Outside the
/// write roots that folder is the member's (the run could not write there); inside them, what
/// the run added was reverted above and what is left was there before.
fn report_pointer(pointer: &Path, target: &Path, inside: bool, out: &mut BTreeSet<String>) {
    let found = risky_state(target);
    if found.is_empty() {
        return;
    }
    let why = if inside {
        "it was there before this run; not changed"
    } else {
        "not changed (it may be the member's own folder)"
    };
    out.insert(format!(
        "{} now points git at {}, where git would run a program outside the sandbox ({}); {why}; the member should review it",
        pointer.display(),
        target.display(),
        found.join(", ")
    ));
}

/// One config file of a git folder before a run.
#[derive(Debug, Clone, Default)]
struct ConfigSnap {
    /// The text, when it was a regular, readable file of a checkable size.
    text: Option<String>,
    symlink: bool,
    risky: Vec<(String, String)>,
}

/// One git folder before a run (the default is the empty baseline of a new one).
#[derive(Debug, Clone, Default)]
struct RepoSnap {
    configs: BTreeMap<&'static str, ConfigSnap>,
    hooks: BTreeSet<String>,
    hooks_symlink: bool,
}

/// Every git folder in the write roots, as it was before a run.
#[derive(Debug, Clone, Default)]
pub(crate) struct Snapshot {
    roots: Vec<PathBuf>,
    repos: BTreeMap<PathBuf, RepoSnap>,
    pointers: BTreeMap<PathBuf, PathBuf>,
    /// Whether the walk saw every folder (so a git folder missing from `repos` is new).
    complete: bool,
}

fn snap_config(path: &Path) -> ConfigSnap {
    let (text, symlink) = match std::fs::symlink_metadata(path) {
        Ok(m) if m.file_type().is_symlink() => (None, true),
        Ok(m) if m.is_file() && m.len() <= MAX_CONFIG_BYTES => {
            (std::fs::read_to_string(path).ok(), false)
        }
        _ => (None, false),
    };
    ConfigSnap {
        risky: text.as_deref().map(risky_config).unwrap_or_default(),
        text,
        symlink,
    }
}

fn snap_repo(git: &Path) -> RepoSnap {
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
        configs: CONFIG_FILES
            .iter()
            .map(|n| (*n, snap_config(&git.join(n))))
            .collect(),
        hooks,
        hooks_symlink,
    }
}

/// Snapshot every git folder in `write_roots` before a run.
pub(crate) fn snapshot(write_roots: &[PathBuf]) -> Snapshot {
    snapshot_with(write_roots, LIMITS)
}

fn snapshot_with(write_roots: &[PathBuf], limits: Limits) -> Snapshot {
    let roots = normalize_roots(write_roots);
    let found = discover(&roots, limits);
    Snapshot {
        repos: found
            .git_dirs
            .iter()
            .map(|g| (g.clone(), snap_repo(g)))
            .collect(),
        pointers: found.pointers,
        complete: found.incomplete.is_empty(),
        roots,
    }
}

/// After a run: revert what it added that would make git run a program later (see the module
/// docs). Returns one line per revert (or per item that could not be reverted or checked),
/// sorted.
pub(crate) fn revert_new(before: &Snapshot) -> Vec<String> {
    revert_new_with(before, LIMITS)
}

fn revert_new_with(before: &Snapshot, limits: Limits) -> Vec<String> {
    let after = discover(&before.roots, limits);
    let mut out = BTreeSet::new();
    for why in &after.incomplete {
        out.insert(format!(
            "not every folder was checked for git changes after the command ({why}); the member should review git state there before using git outside the sandbox"
        ));
    }
    let empty = RepoSnap::default();
    for git in &after.git_dirs {
        let base = match before.repos.get(git) {
            Some(b) => b,
            None if before.complete => &empty,
            None => {
                let found = risky_state(git);
                if !found.is_empty() {
                    out.insert(format!(
                        "{} was not reached by the check before the command (too many folders), so what was there before is unknown; not changed ({}); the member should review it",
                        git.display(),
                        found.join(", ")
                    ));
                }
                continue;
            }
        };
        revert_hooks(git, base, &mut out);
        for name in CONFIG_FILES {
            let snap = base.configs.get(name).cloned().unwrap_or_default();
            revert_config(&git.join(name), &snap, &mut out);
        }
    }
    for (pointer, target) in &after.pointers {
        if before.pointers.get(pointer) != Some(target) {
            let inside = before.roots.iter().any(|r| target.starts_with(r));
            report_pointer(pointer, target, inside, &mut out);
        }
    }
    out.into_iter().collect()
}

fn revert_hooks(git: &Path, b: &RepoSnap, out: &mut BTreeSet<String>) {
    let hooks = git.join("hooks");
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

fn revert_config(config: &Path, b: &ConfigSnap, out: &mut BTreeSet<String>) {
    let Ok(m) = std::fs::symlink_metadata(config) else {
        return;
    };
    if m.file_type().is_symlink() {
        if b.symlink {
            return;
        }
        let restored = std::fs::remove_file(config).and_then(|()| match &b.text {
            Some(t) => std::fs::write(config, t),
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
    let Ok(text) = std::fs::read_to_string(config) else {
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
    match std::fs::write(config, rewritten) {
        Ok(()) => {
            for e in drop {
                out.insert(format!(
                    "reverted: removed git config {} = {} from {} (git could run a program or fetch from it outside the sandbox, or drop the Hermes trailer from commits)",
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
        let trailer = "[trailer \"x\"]\n\tcmd = evil\n\tkey = Co-authored-by\n[trailer]\n\tifmissing = doNothing\n[commit]\n\tcleanup = scissors\n\tgpgsign = false\n[core]\n\tcommentChar = C\n";
        let keys: Vec<String> = risky_config(trailer).into_iter().map(|(k, _)| k).collect();
        assert_eq!(
            keys,
            vec![
                "trailer.x.cmd",
                "trailer.x.key",
                "trailer.ifmissing",
                "commit.cleanup",
                "core.commentchar"
            ]
        );
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
    fn keys_that_run_a_program_or_move_the_worktree_are_risky() {
        let text = "[core]\n\tworktree = /elsewhere\n\talternateRefsCommand = evil\n[submodule \"a\"]\n\tupdate = !evil\n[submodule \"b\"]\n\tupdate = rebase\n[hook \"pre-commit\"]\n\tcommand = evil\n[interactive]\n\tdiffFilter = evil\n[sendemail]\n\tsendmailCmd = evil\n[gpg \"ssh\"]\n\tdefaultKeyCommand = evil\n[tar \"tgz\"]\n\tcommand = evil\n[guitool \"x\"]\n\tcmd = evil\n[extensions]\n\tworktreeConfig = true\n";
        let keys: Vec<String> = risky_config(text).into_iter().map(|(k, _)| k).collect();
        assert_eq!(
            keys,
            vec![
                "core.worktree",
                "core.alternaterefscommand",
                "submodule.a.update",
                "hook.pre-commit.command",
                "interactive.difffilter",
                "sendemail.sendmailcmd",
                "gpg.ssh.defaultkeycommand",
                "tar.tgz.command",
                "guitool.x.cmd",
            ]
        );
    }

    fn bare(dir: &Path) {
        std::fs::create_dir_all(dir.join("objects")).expect("objects");
        std::fs::create_dir_all(dir.join("refs")).expect("refs");
        std::fs::write(dir.join("HEAD"), "ref: refs/heads/main\n").expect("HEAD");
    }

    #[test]
    fn the_walk_finds_git_folders_at_any_depth_bare_ones_worktrees_modules_and_pointers() {
        let d = tempfile::tempdir().expect("tmp");
        let root = d.path().canonicalize().expect("canon").join("root");
        std::fs::create_dir_all(root.join("a/b/c/.git")).expect("deep");
        std::fs::create_dir_all(root.join("x/.git/worktrees/w")).expect("wt");
        bare(&root.join("x/.git/modules/lib/sub"));
        bare(&root.join("y/bare.git"));
        bare(&root.join("z/gd"));
        std::fs::create_dir_all(root.join("p")).expect("p");
        std::fs::write(root.join("p/.git"), "gitdir: ../z/gd\n").expect("ptr");
        // A pointer at a folder git would not use as a repository is recorded, not followed.
        std::fs::create_dir_all(root.join("q/hooks")).expect("q");
        std::fs::write(root.join("q/.git"), "gitdir: .\n").expect("ptr");
        let found = discover(std::slice::from_ref(&root), LIMITS);
        for g in [
            "a/b/c/.git",
            "x/.git",
            "x/.git/worktrees/w",
            "x/.git/modules/lib/sub",
            "y/bare.git",
            "z/gd",
        ] {
            assert!(
                found.git_dirs.contains(&root.join(g)),
                "{g}: {:?}",
                found.git_dirs
            );
        }
        assert!(!found.git_dirs.contains(&root.join("q")));
        assert_eq!(
            found.pointers.get(&root.join("p/.git")),
            Some(&root.join("z/gd"))
        );
        assert_eq!(
            found.pointers.get(&root.join("q/.git")),
            Some(&root.join("q"))
        );
        assert!(found.incomplete.is_empty(), "{:?}", found.incomplete);
    }

    #[test]
    fn a_pointer_at_a_folder_that_is_not_a_repository_changes_nothing_there() {
        let d = tempfile::tempdir().expect("tmp");
        let root = d.path().canonicalize().expect("canon");
        std::fs::create_dir_all(root.join("app/hooks")).expect("app");
        std::fs::write(root.join("app/hooks/useThing.ts"), "export {}\n").expect("src");
        std::fs::write(root.join("app/config"), "[alias]\n\tx = !id\n").expect("cfg");
        let before = snapshot(std::slice::from_ref(&root));
        std::fs::write(root.join("app/.git"), "gitdir: .\n").expect("ptr");
        let w = revert_new(&before);
        assert!(root.join("app/hooks/useThing.ts").exists(), "{w:?}");
        assert!(std::fs::read_to_string(root.join("app/config"))
            .expect("cfg")
            .contains("!id"));
        assert!(w.iter().all(|l| l.contains("not changed")), "{w:?}");
    }

    #[test]
    fn a_walk_that_reaches_its_bound_says_so_and_leaves_what_it_could_not_compare() {
        let d = tempfile::tempdir().expect("tmp");
        let root = d.path().canonicalize().expect("canon");
        for i in 0..20 {
            std::fs::write(root.join(format!("f{i}")), "x").expect("file");
        }
        let small = Limits {
            entries: 5,
            depth: 8,
        };
        let before = snapshot_with(std::slice::from_ref(&root), small);
        assert!(!before.complete);
        // A repository the before-run walk could not reach: what was there is unknown, so it
        // is reported, not changed.
        std::fs::create_dir_all(root.join("zz/.git")).expect("repo");
        std::fs::write(root.join("zz/.git/config"), "[core]\n\thooksPath = .h\n").expect("cfg");
        let w = revert_new_with(&before, LIMITS).join("\n");
        assert!(
            w.contains("not reached") && w.contains("core.hookspath"),
            "{w}"
        );
        assert!(std::fs::read_to_string(root.join("zz/.git/config"))
            .expect("cfg")
            .contains("hooksPath"));
        // An after-run walk that reaches its bound says so.
        let w = revert_new_with(&snapshot(std::slice::from_ref(&root)), small).join("\n");
        assert!(w.contains("not every folder was checked"), "{w}");
        // Too deep is reported as well.
        std::fs::create_dir_all(root.join("d1/d2/d3")).expect("deep");
        let shallow = Limits {
            entries: 1000,
            depth: 1,
        };
        let found = discover(std::slice::from_ref(&root), shallow);
        assert!(
            found.incomplete.iter().any(|m| m.contains("folders deep")),
            "{:?}",
            found.incomplete
        );
    }

    #[test]
    fn nested_and_duplicate_write_roots_are_walked_once() {
        let d = tempfile::tempdir().expect("tmp");
        let root = d.path().canonicalize().expect("canon");
        std::fs::create_dir_all(root.join("a/b")).expect("dirs");
        let roots =
            normalize_roots(&[root.join("a/b"), root.clone(), root.join("a"), root.clone()]);
        assert_eq!(roots, vec![root]);
    }
}
