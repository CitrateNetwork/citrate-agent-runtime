//! # citrate-agent-guard: the central default-deny list (HUP-S2.8)
//!
//! One function, [`check_path`], that every agent-facing filesystem surface
//! (file tools, shell argument checks, capsule preopens) asks before touching
//! a path. It denies, **regardless of any grant**, the locations where a
//! user's secrets live: credential directories, OS keychains, browser
//! profiles, wallet storage, Citrate Core app data (vault, Hermes bearer
//! token), shell histories, `.env` files outside granted project roots, and
//! system secret files. Grants are layered on top by the caller; this crate
//! never widens access, it only narrows it.
//!
//! ## Resolution model
//!
//! The input string is interpreted (`\` becomes `/`, `~` expands to the
//! context home, relative paths join the context cwd) and then resolved the
//! way the kernel would: component by component, following every symlink at
//! the point it is met, so `link/..` means the parent of the link *target*.
//! Every intermediate location, every symlink location, and the final
//! location are checked. Components that do not exist yet (write targets)
//! are appended lexically to their nearest existing ancestor; a dangling
//! symlink is resolved through its target. Any resolution error other than
//! "not found" fails closed.
//!
//! Matching is done on folded components: Unicode NFKD, lowercase, NFKC,
//! trailing dots and spaces trimmed, anything after a `:` dropped. Folding
//! can only over-deny (a case-sensitive Linux `~/.SSH` is denied too); it can
//! never let a denied spelling through.
//!
//! ## Caller contract
//!
//! * Do the I/O on the returned [`CanonicalPath`], not on the input string.
//! * This is a point-in-time check. A caller that opens the path later must
//!   still open without following a swapped-in symlink where the OS allows
//!   (`O_NOFOLLOW` on the leaf) or re-check after opening.
//! * Recursive operations (copy a tree, archive a directory, `grep -r`) must
//!   check each entry they visit; allowing `~` does not allow everything
//!   under it.
//! * Hard links cannot be detected from a path. Write grants must not let an
//!   agent create hard links into a granted folder.

use std::path::{Component, Path, PathBuf};
use unicode_normalization::UnicodeNormalization;

/// Why a path was denied. One variant per list in the crate README.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum DenyCategory {
    /// SSH, GPG, cloud CLI, registry and git credential stores.
    Credentials,
    /// OS keychains and secret services.
    Keychain,
    /// Browser profile directories (cookies, saved logins, history).
    BrowserProfile,
    /// Browser wallet-extension storage and desktop wallet keystores.
    WalletStorage,
    /// Citrate Core app data (vault, Hermes bearer token) and node keys.
    CitrateAppData,
    /// Shell and REPL histories.
    ShellHistory,
    /// A `.env`-style file outside every granted project root.
    DotEnv,
    /// System secret files and kernel interfaces.
    SystemPath,
    /// The input could not be interpreted (empty, NUL byte, `~user`, non-UTF-8).
    Malformed,
    /// The path could not be resolved safely (symlink loop, I/O error).
    Unresolvable,
}

/// A denial. `reason` is human-readable and names the matched rule.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Denied {
    pub category: DenyCategory,
    pub reason: String,
}

impl std::fmt::Display for Denied {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "denied ({:?}): {}", self.category, self.reason)
    }
}

impl std::error::Error for Denied {}

/// An absolute, symlink-resolved path that passed the deny list.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CanonicalPath(PathBuf);

impl CanonicalPath {
    pub fn as_path(&self) -> &Path {
        &self.0
    }

    pub fn into_path_buf(self) -> PathBuf {
        self.0
    }
}

impl AsRef<Path> for CanonicalPath {
    fn as_ref(&self) -> &Path {
        &self.0
    }
}

/// Where relative paths and `~` resolve, and which project roots may hold
/// `.env` files.
#[derive(Debug, Clone)]
pub struct GuardContext {
    home: PathBuf,
    cwd: PathBuf,
    project_roots: Vec<PathBuf>,
}

impl GuardContext {
    pub fn new(home: impl AsRef<Path>, cwd: impl AsRef<Path>) -> Self {
        Self {
            home: home.as_ref().to_path_buf(),
            cwd: cwd.as_ref().to_path_buf(),
            project_roots: Vec::new(),
        }
    }

    /// Context for the current process: `HOME` (or `USERPROFILE`) and the
    /// current directory. Fails closed when either is unavailable.
    pub fn from_process_env() -> Result<Self, Denied> {
        let home = std::env::var_os("HOME")
            .or_else(|| std::env::var_os("USERPROFILE"))
            .filter(|h| !h.is_empty())
            .ok_or_else(|| denied(DenyCategory::Unresolvable, "no home directory in env"))?;
        let cwd = std::env::current_dir()
            .map_err(|e| denied(DenyCategory::Unresolvable, format!("no cwd: {e}")))?;
        Ok(Self::new(PathBuf::from(home), cwd))
    }

    /// Mark a granted project root. `.env` files under it are allowed; the
    /// rest of the deny list still applies inside it.
    pub fn with_project_root(mut self, root: impl AsRef<Path>) -> Self {
        self.project_roots.push(root.as_ref().to_path_buf());
        self
    }

    pub fn home(&self) -> &Path {
        &self.home
    }

    pub fn cwd(&self) -> &Path {
        &self.cwd
    }

    pub fn project_roots(&self) -> &[PathBuf] {
        &self.project_roots
    }
}

/// Where in a path a rule's component run may appear.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Anchor {
    /// The run must start at the filesystem root (`/etc/shadow`).
    Root,
    /// The run may start at any depth (`~/.ssh`, `/root/.ssh`, `/home/x/.ssh`).
    Anywhere,
}

/// One deny rule: a run of folded path components.
#[derive(Debug, Clone, Copy)]
pub struct Rule {
    pub category: DenyCategory,
    pub anchor: Anchor,
    pub run: &'static [&'static str],
}

const fn any(category: DenyCategory, run: &'static [&'static str]) -> Rule {
    Rule {
        category,
        anchor: Anchor::Anywhere,
        run,
    }
}

const fn root(run: &'static [&'static str]) -> Rule {
    Rule {
        category: DenyCategory::SystemPath,
        anchor: Anchor::Root,
        run,
    }
}

use DenyCategory::{
    BrowserProfile as B, CitrateAppData as A, Credentials as C, Keychain as K, ShellHistory as H,
    SystemPath as S, WalletStorage as W,
};

const AS: &str = "application support";

/// The deny list. Every entry is lowercase, already folded. Documented
/// category by category in the crate README; keep the two in step.
pub static RULES: &[Rule] = &[
    // ---- Credentials
    any(C, &[".ssh"]),
    any(C, &[".gnupg"]),
    any(C, &[".aws"]),
    any(C, &[".azure"]),
    any(C, &[".kube"]),
    any(C, &[".config", "gcloud"]),
    any(C, &[".docker", "config.json"]),
    any(C, &[".netrc"]),
    any(C, &["_netrc"]),
    any(C, &[".npmrc"]),
    any(C, &[".pypirc"]),
    any(C, &[".git-credentials"]),
    any(C, &[".config", "gh"]),
    any(C, &[".config", "hub"]),
    any(C, &[".cargo", "credentials"]),
    any(C, &[".cargo", "credentials.toml"]),
    any(C, &[".terraform.d", "credentials.tfrc.json"]),
    any(C, &[".password-store"]),
    // ---- Keychains and secret services
    any(K, &["library", "keychains"]),
    any(K, &[".local", "share", "keyrings"]),
    any(K, &[".gnome2", "keyrings"]),
    any(K, &[".local", "share", "kwalletd"]),
    any(K, &[".kde", "share", "apps", "kwallet"]),
    any(K, &[".kde4", "share", "apps", "kwallet"]),
    any(K, &["appdata", "roaming", "microsoft", "credentials"]),
    any(K, &["appdata", "local", "microsoft", "credentials"]),
    any(K, &["appdata", "roaming", "microsoft", "protect"]),
    any(K, &["appdata", "roaming", "microsoft", "vault"]),
    any(K, &["appdata", "local", "microsoft", "vault"]),
    // ---- Browser profiles: macOS
    any(B, &["library", AS, "google", "chrome"]),
    any(B, &["library", AS, "google", "chrome beta"]),
    any(B, &["library", AS, "google", "chrome canary"]),
    any(B, &["library", AS, "chromium"]),
    any(B, &["library", AS, "bravesoftware"]),
    any(B, &["library", AS, "microsoft edge"]),
    any(B, &["library", AS, "firefox"]),
    any(B, &["library", AS, "arc"]),
    any(B, &["library", AS, "vivaldi"]),
    any(B, &["library", AS, "com.operasoftware.opera"]),
    any(B, &["library", "safari"]),
    any(B, &["library", "containers", "com.apple.safari"]),
    any(B, &["library", "cookies"]),
    // ---- Browser profiles: Linux
    any(B, &[".config", "google-chrome"]),
    any(B, &[".config", "google-chrome-beta"]),
    any(B, &[".config", "chromium"]),
    any(B, &[".config", "bravesoftware"]),
    any(B, &[".config", "microsoft-edge"]),
    any(B, &[".config", "vivaldi"]),
    any(B, &[".config", "opera"]),
    any(B, &[".mozilla"]),
    any(B, &["snap", "chromium"]),
    any(B, &["snap", "firefox"]),
    any(B, &[".var", "app", "org.mozilla.firefox"]),
    any(B, &[".var", "app", "com.google.chrome"]),
    any(B, &[".var", "app", "com.brave.browser"]),
    // ---- Browser profiles: Windows
    any(B, &["appdata", "local", "google", "chrome"]),
    any(B, &["appdata", "local", "chromium"]),
    any(B, &["appdata", "local", "bravesoftware"]),
    any(B, &["appdata", "local", "microsoft", "edge"]),
    any(B, &["appdata", "local", "vivaldi"]),
    any(B, &["appdata", "roaming", "opera software"]),
    any(B, &["appdata", "roaming", "mozilla"]),
    any(B, &["appdata", "local", "mozilla"]),
    // ---- Wallet storage: extension storage in any Chromium-family profile
    // (also caught by the component prefixes below), and desktop keystores.
    any(W, &["local extension settings"]),
    any(W, &["sync extension settings"]),
    any(W, &["managed extension settings"]),
    any(W, &[".ethereum", "keystore"]),
    any(W, &["library", "ethereum", "keystore"]),
    any(W, &[".foundry", "keystores"]),
    any(W, &[".citrate-wallet"]),
    any(W, &[".electrum"]),
    any(W, &["library", AS, "exodus"]),
    any(W, &[".bitcoin", "wallets"]),
    any(W, &["library", AS, "bitcoin", "wallets"]),
    // ---- Citrate app data (Tauri identifier dirs are matched by prefix
    // below; these are the CLI/node key locations under ~/.citrate).
    any(A, &[".citrate", "noise"]),
    any(A, &[".citrate", "proposer"]),
    any(A, &[".citrate", "keystore"]),
    any(A, &[".citrate", "node"]),
    // ---- Shell and REPL histories
    any(H, &[".zsh_history"]),
    any(H, &[".bash_history"]),
    any(H, &[".sh_history"]),
    any(H, &[".ksh_history"]),
    any(H, &[".history"]),
    any(H, &["fish_history"]),
    any(H, &[".zsh_sessions"]),
    any(H, &[".bash_sessions"]),
    any(H, &[".python_history"]),
    any(H, &[".node_repl_history"]),
    any(H, &[".psql_history"]),
    any(H, &[".mysql_history"]),
    any(H, &[".sqlite_history"]),
    any(H, &[".rediscli_history"]),
    any(H, &[".irb_history"]),
    any(H, &[".lesshst"]),
    any(H, &["consolehost_history.txt"]),
    // ---- System secrets (anchored at the root; `/etc` is `/private/etc`
    // on macOS, so both spellings are listed).
    root(&["etc", "shadow"]),
    root(&["etc", "shadow-"]),
    root(&["etc", "gshadow"]),
    root(&["etc", "gshadow-"]),
    root(&["etc", "master.passwd"]),
    root(&["etc", "sudoers"]),
    root(&["etc", "sudoers.d"]),
    root(&["etc", "ssh"]),
    root(&["etc", "ssl", "private"]),
    root(&["etc", "krb5.keytab"]),
    root(&["etc", "security", "opasswd"]),
    root(&["private", "etc", "master.passwd"]),
    root(&["private", "etc", "sudoers"]),
    root(&["private", "etc", "sudoers.d"]),
    root(&["private", "etc", "ssh"]),
    root(&["private", "etc", "krb5.keytab"]),
    root(&["private", "var", "db"]),
    root(&["var", "db"]),
    root(&["root"]),
    root(&["proc"]),
    root(&["dev", "mem"]),
    root(&["dev", "kmem"]),
    root(&["dev", "port"]),
    any(S, &["windows", "system32", "config"]),
];

/// Single-component prefix rules: any component whose folded form starts
/// with the prefix is denied.
pub static PREFIX_RULES: &[(DenyCategory, &str)] = &[
    // Chromium IndexedDB / storage for an extension origin.
    (W, "chrome-extension_"),
    // Firefox per-extension storage (`storage/default/moz-extension+++<uuid>`).
    (W, "moz-extension+++"),
    // Tauri app dirs for Citrate Core and its keyring-adjacent siblings
    // (`ai.citrate.core`, `ai.citrate.core.custody`): vault, Hermes bearer
    // token, sessions, caches, WebKit storage, preferences plist.
    (A, "ai.citrate.core"),
];

/// `.env` templates that are meant to be committed and hold no secrets.
const DOTENV_TEMPLATES: &[&str] = &[
    ".env.example",
    ".env.sample",
    ".env.template",
    ".env.dist",
    ".env.defaults",
];

/// macOS mounts the data volume a second time under `/System/Volumes/Data`
/// (firmlinks), so a root-anchored rule also matches after this prefix.
const DATA_VOLUME_ALIAS: &[&str] = &["system", "volumes", "data"];

/// Symlinks followed per check before failing closed (matches Linux ELOOP).
const MAX_SYMLINKS: usize = 40;

fn denied(category: DenyCategory, reason: impl Into<String>) -> Denied {
    Denied {
        category,
        reason: reason.into(),
    }
}

/// Fold one component for matching. See the module docs.
pub fn fold(component: &str) -> String {
    let lowered: String = component.nfkd().collect::<String>().to_lowercase();
    let mut key: String = lowered.nfkc().collect();
    if let Some(i) = key.find(':') {
        if i > 0 {
            key.truncate(i);
        }
    }
    let trimmed_len = key.trim_end_matches(['.', ' ']).len();
    if trimmed_len > 0 {
        key.truncate(trimmed_len);
    }
    key
}

fn folded_components(path: &Path) -> Vec<String> {
    path.components()
        .filter_map(|c| match c {
            Component::Normal(s) => Some(fold(&s.to_string_lossy())),
            _ => None,
        })
        .collect()
}

fn run_matches(keys: &[String], run: &[&str]) -> bool {
    keys.len() >= run.len() && keys.iter().zip(run).all(|(k, r)| k == r)
}

/// Check the static rule tables against one location.
fn match_rules(path: &Path) -> Result<(), Denied> {
    let keys = folded_components(path);
    for rule in RULES {
        let hit = match rule.anchor {
            Anchor::Root => {
                run_matches(&keys, rule.run)
                    || (run_matches(&keys, DATA_VOLUME_ALIAS)
                        && run_matches(&keys[DATA_VOLUME_ALIAS.len()..], rule.run))
            }
            Anchor::Anywhere => (0..keys.len()).any(|i| run_matches(&keys[i..], rule.run)),
        };
        if hit {
            return Err(denied(
                rule.category,
                format!(
                    "{} is inside the default-deny location `{}`",
                    path.display(),
                    rule.run.join("/")
                ),
            ));
        }
    }
    for (category, prefix) in PREFIX_RULES {
        if keys.iter().any(|k| k.starts_with(prefix)) {
            return Err(denied(
                *category,
                format!(
                    "{} is inside a default-deny location (`{prefix}*`)",
                    path.display()
                ),
            ));
        }
    }
    Ok(())
}

fn is_dotenv(key: &str) -> bool {
    let named = key == ".env" || key == ".envrc" || key.starts_with(".env.");
    named && !DOTENV_TEMPLATES.contains(&key)
}

/// `.env` files are allowed only under a granted project root. Decision
/// recorded in the README: a project's own `.env` is part of the work the
/// user granted; one anywhere else is somebody's secret.
fn match_dotenv(path: &Path, roots: &[PathBuf]) -> Result<(), Denied> {
    let Some(name) = path.file_name() else {
        return Ok(());
    };
    if !is_dotenv(&fold(&name.to_string_lossy())) {
        return Ok(());
    }
    let keys = folded_components(path);
    let inside = roots.iter().any(|r| {
        let rk = folded_components(r);
        // Strictly inside: the root itself can't be a `.env` file.
        keys.len() > rk.len() && keys[..rk.len()] == rk[..]
    });
    if inside {
        Ok(())
    } else {
        Err(denied(
            DenyCategory::DotEnv,
            format!(
                "{} is an environment file outside every granted project root",
                path.display()
            ),
        ))
    }
}

/// Turn the caller's string into an absolute (unresolved) path.
fn interpret(input: &str, ctx: &GuardContext) -> Result<PathBuf, Denied> {
    if input.is_empty() {
        return Err(denied(DenyCategory::Malformed, "empty path"));
    }
    if input.contains('\0') {
        return Err(denied(DenyCategory::Malformed, "path contains a NUL byte"));
    }
    let unified = input.replace('\\', "/");
    let expanded = if unified == "~" {
        ctx.home.clone()
    } else if let Some(rest) = unified.strip_prefix("~/") {
        ctx.home.join(rest.trim_start_matches('/'))
    } else if unified.starts_with('~') {
        return Err(denied(
            DenyCategory::Malformed,
            "`~user` paths are not supported; use an absolute path",
        ));
    } else {
        PathBuf::from(&unified)
    };
    if expanded.has_root() {
        Ok(expanded)
    } else {
        Ok(ctx.cwd.join(expanded))
    }
}

/// Resolve like the kernel: component by component, following symlinks
/// where they are met. `check` runs on every location visited.
fn walk(
    path: &Path,
    links: &mut usize,
    check: &dyn Fn(&Path) -> Result<(), Denied>,
) -> Result<PathBuf, Denied> {
    let mut cur = PathBuf::new();
    for comp in path.components() {
        match comp {
            Component::Prefix(p) => cur.push(p.as_os_str()),
            Component::RootDir => cur.push(Component::RootDir.as_os_str()),
            Component::CurDir => {}
            // `cur` never contains a symlink, so a lexical pop is exact.
            Component::ParentDir => {
                cur.pop();
            }
            Component::Normal(name) => {
                let next = cur.join(name);
                check(&next)?;
                match std::fs::symlink_metadata(&next) {
                    Ok(md) if md.file_type().is_symlink() => {
                        if *links == 0 {
                            return Err(denied(
                                DenyCategory::Unresolvable,
                                format!("too many symlinks resolving {}", path.display()),
                            ));
                        }
                        *links -= 1;
                        let target = std::fs::read_link(&next).map_err(|e| {
                            denied(
                                DenyCategory::Unresolvable,
                                format!("cannot read symlink {}: {e}", next.display()),
                            )
                        })?;
                        let joined = if target.has_root() {
                            target
                        } else {
                            cur.join(target)
                        };
                        cur = walk(&joined, links, check)?;
                    }
                    Ok(_) => cur = next,
                    Err(e) if is_absent(&e) => cur = next,
                    Err(e) => {
                        return Err(denied(
                            DenyCategory::Unresolvable,
                            format!("cannot inspect {}: {e}", next.display()),
                        ))
                    }
                }
            }
        }
        check(&cur)?;
    }
    Ok(cur)
}

fn is_absent(e: &std::io::Error) -> bool {
    matches!(
        e.kind(),
        std::io::ErrorKind::NotFound | std::io::ErrorKind::NotADirectory
    )
}

/// The default-deny check. Returns the resolved absolute path to use for
/// the actual I/O, or why it is denied. Grants do not override a denial.
pub fn check_path(path: impl AsRef<Path>, ctx: &GuardContext) -> Result<CanonicalPath, Denied> {
    let Some(input) = path.as_ref().to_str() else {
        return Err(denied(DenyCategory::Malformed, "path is not valid UTF-8"));
    };
    let abs = interpret(input, ctx)?;

    // Project roots are resolved the same way (without the deny check) so a
    // symlinked or relative root compares against resolved paths.
    let no_check = |_: &Path| Ok(());
    let roots: Vec<PathBuf> = ctx
        .project_roots
        .iter()
        .filter_map(|r| {
            let mut budget = MAX_SYMLINKS;
            let r = if r.has_root() {
                r.clone()
            } else {
                ctx.cwd.join(r)
            };
            walk(&r, &mut budget, &no_check).ok()
        })
        .collect();

    let check = |p: &Path| -> Result<(), Denied> {
        match_rules(p)?;
        match_dotenv(p, &roots)
    };

    // Lexical pass over the request as written, then the resolved pass.
    check(&lexical(&abs))?;
    let mut budget = MAX_SYMLINKS;
    let resolved = walk(&abs, &mut budget, &check)?;
    check(&resolved)?;
    Ok(CanonicalPath(resolved))
}

fn lexical(path: &Path) -> PathBuf {
    let mut out = PathBuf::new();
    for c in path.components() {
        match c {
            Component::ParentDir => {
                out.pop();
            }
            Component::CurDir => {}
            other => out.push(other.as_os_str()),
        }
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn fold_handles_case_compat_and_suffixes() {
        assert_eq!(fold(".SSH"), ".ssh");
        assert_eq!(fold(".\u{212A}ube"), ".kube");
        assert_eq!(fold("\u{FF0E}ssh"), ".ssh");
        assert_eq!(fold(".ssh."), ".ssh");
        assert_eq!(fold(".ssh .."), ".ssh");
        assert_eq!(fold(".netrc::$DATA"), ".netrc");
        assert_eq!(fold("..."), "...");
    }

    #[test]
    fn every_rule_is_already_folded() {
        for r in RULES {
            for part in r.run {
                assert_eq!(&fold(part), part, "rule part {part:?} is not folded");
            }
        }
        for (_, p) in PREFIX_RULES {
            assert_eq!(&fold(p), p);
        }
    }

    #[test]
    fn dotenv_names() {
        assert!(is_dotenv(".env"));
        assert!(is_dotenv(".env.local"));
        assert!(is_dotenv(".envrc"));
        assert!(!is_dotenv(".env.example"));
        assert!(!is_dotenv(".environment-notes"));
        assert!(!is_dotenv("env"));
    }
}
