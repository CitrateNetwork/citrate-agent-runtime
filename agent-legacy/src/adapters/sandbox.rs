//! Sandbox hardening — path policies and shell isolation.
//!
//! Inspired by ZeroClaw's safety patterns. Implemented natively in Rust.
//!
//! Rules:
//! - File tools may only touch the declared workspace root
//! - Deny ~/.ssh, keystores, config secrets, and home-directory escape
//! - Shell commands run with timeout and can be further isolated
//!
//! RM-B1 / WP-E4.1 (audit AGT-01): per-component path comparison.
//! Pre-fix the deny list was matched via `path_str.contains(denied)`,
//! so a workspace file named `~/.envrc-project` would be denied
//! purely because the substring `.env` appeared anywhere in the
//! string. Post-fix the comparison walks `Path::components()` and
//! checks whole component equality (case-insensitive on Apple/Win
//! by tradition; we keep it case-sensitive on Linux which matches
//! filesystem reality).
//!
//! RM-B1 / WP-E4.2 (audit AGT-02): symlink resolution. Pre-fix the
//! sandbox normalized paths LEXICALLY only — a symlink at
//! `<workspace>/link → /etc/passwd` resolved to itself and then
//! passed `starts_with(workspace_root)`. Post-fix we use
//! `std::fs::canonicalize` (which follows links) and reject if the
//! canonical path leaves the workspace.

use std::path::{Component, Path, PathBuf};

/// Path components that are always denied as exact matches at any
/// depth in the path. Each entry is matched against a SINGLE
/// component, never as a substring of one.
const DENIED_COMPONENTS: &[&str] = &[
    ".ssh",
    ".gnupg",
    ".aws",
    ".kube",
    ".env",
    ".gitconfig",
];

/// Multi-component denied paths. Each tuple is matched as an
/// adjacent run of components — `(".config", "gcloud")` denies
/// `~/.config/gcloud/...` but does NOT deny `~/myapp/.config/gcloud`
/// nested under a workspace `.config` (highly unusual but possible).
const DENIED_COMPONENT_RUNS: &[&[&str]] = &[
    &[".config", "gcloud"],
    &["node_modules", ".cache"],
];

/// File extensions that are always denied for write operations.
const DENIED_EXTENSIONS: &[&str] = &["pem", "key", "p12", "pfx", "jks"];

/// Sandbox policy — enforces path boundaries for tool execution.
pub struct SandboxPolicy {
    /// Workspace root — all file operations must stay within this directory
    workspace_root: PathBuf,
    /// Additional allowed paths (e.g., ~/.citrate/models/ for model ops)
    extra_allowed: Vec<PathBuf>,
}

impl SandboxPolicy {
    pub fn new(workspace_root: &Path) -> Self {
        Self {
            workspace_root: workspace_root.to_path_buf(),
            extra_allowed: Vec::new(),
        }
    }

    /// Add an additional allowed path outside the workspace.
    pub fn allow_path(&mut self, path: &Path) {
        self.extra_allowed.push(path.to_path_buf());
    }

    /// Check if a path is allowed for read operations.
    pub fn check_read(&self, path: &Path) -> Result<(), String> {
        let canonical = self.resolve(path)?;
        self.check_denied_patterns(&canonical)?;
        self.check_within_scope(&canonical)
    }

    /// Check if a path is allowed for write operations.
    /// Stricter than read — also checks file extensions.
    pub fn check_write(&self, path: &Path) -> Result<(), String> {
        let canonical = self.resolve(path)?;
        self.check_denied_patterns(&canonical)?;
        self.check_denied_extensions(&canonical)?;
        self.check_within_scope(&canonical)
    }

    /// Resolve a path relative to workspace root, then canonicalize.
    ///
    /// RM-B1 / WP-E4.2 (audit AGT-02): symlink resolution. We try
    /// `std::fs::canonicalize`, which follows links. If the path
    /// doesn't yet exist (e.g., `file_write` of a new file), we
    /// canonicalize the deepest existing ancestor and append the
    /// remaining components — this gates symlinked PARENTS while
    /// still permitting writes to non-existent targets within the
    /// workspace.
    fn resolve(&self, path: &Path) -> Result<PathBuf, String> {
        let initial = if path.is_relative() {
            self.workspace_root.join(path)
        } else {
            path.to_path_buf()
        };
        let lexical = normalize_path(&initial);

        // Fast path: if the path exists, canonicalize it directly.
        if lexical.exists() {
            return std::fs::canonicalize(&lexical).map_err(|e| {
                format!(
                    "Access denied: cannot canonicalize '{}': {}",
                    lexical.display(),
                    e
                )
            });
        }

        // The path doesn't exist. Walk up to the deepest ancestor
        // that DOES exist, canonicalize THAT, then re-append the
        // missing tail. Resolves symlinks anywhere in the parent
        // chain without requiring the leaf to exist.
        let mut existing = lexical.clone();
        let mut tail: Vec<PathBuf> = Vec::new();
        while !existing.exists() {
            match existing.file_name().map(|n| PathBuf::from(n)) {
                Some(name) => {
                    tail.push(name);
                    if !existing.pop() {
                        // Hit the root and still don't exist — give
                        // up and use the lexical form.
                        return Ok(lexical);
                    }
                }
                None => return Ok(lexical),
            }
        }
        let canon = std::fs::canonicalize(&existing).map_err(|e| {
            format!(
                "Access denied: cannot canonicalize parent '{}': {}",
                existing.display(),
                e
            )
        })?;
        let mut result = canon;
        for piece in tail.into_iter().rev() {
            result.push(piece);
        }
        Ok(result)
    }

    /// Check that a path doesn't match any denied patterns at the
    /// component level. RM-B1 / WP-E4.1 (audit AGT-01).
    fn check_denied_patterns(&self, path: &Path) -> Result<(), String> {
        let components: Vec<&str> = path
            .components()
            .filter_map(|c| match c {
                Component::Normal(s) => s.to_str(),
                _ => None,
            })
            .collect();

        for comp in &components {
            for denied in DENIED_COMPONENTS {
                if comp == denied {
                    return Err(format!(
                        "Access denied: path component '{}' is security-sensitive",
                        denied
                    ));
                }
            }
        }

        for run in DENIED_COMPONENT_RUNS {
            if components.windows(run.len()).any(|w| w == *run) {
                return Err(format!(
                    "Access denied: path matches denied component run {:?}",
                    run
                ));
            }
        }
        Ok(())
    }

    /// Check that a write target doesn't have a denied extension.
    fn check_denied_extensions(&self, path: &Path) -> Result<(), String> {
        if let Some(ext) = path.extension().and_then(|e| e.to_str()) {
            if DENIED_EXTENSIONS.contains(&ext) {
                return Err(format!(
                    "Write denied: '{}' files are security-sensitive",
                    ext
                ));
            }
        }
        Ok(())
    }

    /// Check that a path is within the workspace root or extra allowed paths.
    fn check_within_scope(&self, path: &Path) -> Result<(), String> {
        if path.starts_with(&self.workspace_root) {
            return Ok(());
        }
        for allowed in &self.extra_allowed {
            if path.starts_with(allowed) {
                return Ok(());
            }
        }
        Err(format!(
            "Access denied: path '{}' is outside workspace root '{}'",
            path.display(),
            self.workspace_root.display()
        ))
    }
}

/// Normalize a path without requiring it to exist on the filesystem.
/// Resolves `.` and `..` components lexically.
fn normalize_path(path: &Path) -> PathBuf {
    let mut result = PathBuf::new();
    for component in path.components() {
        match component {
            std::path::Component::ParentDir => {
                result.pop();
            }
            std::path::Component::CurDir => {}
            other => result.push(other),
        }
    }
    result
}

#[cfg(test)]
mod tests {
    use super::*;
    use tempfile::TempDir;

    /// Materialize a workspace on the real filesystem so the
    /// canonicalize-backed resolve path can run end-to-end.
    fn make_workspace() -> (TempDir, SandboxPolicy) {
        let tmp = TempDir::new().expect("tempdir");
        // The tempdir handle's path may itself have symlinks (e.g.
        // `/private/var/...` on macOS); canonicalize for stability.
        let root = std::fs::canonicalize(tmp.path()).expect("canonicalize workspace");
        let sandbox = SandboxPolicy::new(&root);
        // Pre-create a `src` subdirectory used by several tests.
        std::fs::create_dir_all(root.join("src")).expect("mkdir src");
        (tmp, sandbox)
    }

    #[test]
    fn test_read_within_workspace() {
        let (tmp, sandbox) = make_workspace();
        let target = tmp.path().join("src/main.rs");
        std::fs::write(&target, b"fn main() {}").expect("write");
        assert!(sandbox.check_read(&target).is_ok());
    }

    #[test]
    fn test_read_outside_workspace() {
        let (_tmp, sandbox) = make_workspace();
        assert!(sandbox.check_read(Path::new("/etc/passwd")).is_err());
    }

    #[test]
    fn test_read_traversal_blocked() {
        let (tmp, sandbox) = make_workspace();
        let traversal = tmp.path().join("../../etc/passwd");
        assert!(sandbox.check_read(&traversal).is_err());
    }

    #[test]
    fn test_write_key_extension_denied() {
        let (tmp, sandbox) = make_workspace();
        let path = tmp.path().join("secret.pem");
        assert!(sandbox.check_write(&path).is_err());
    }

    #[test]
    fn test_write_normal_file_ok() {
        let (tmp, sandbox) = make_workspace();
        let path = tmp.path().join("src/lib.rs");
        assert!(sandbox.check_write(&path).is_ok());
    }

    #[test]
    fn test_relative_path_resolves() {
        let (tmp, sandbox) = make_workspace();
        std::fs::write(tmp.path().join("src/main.rs"), b"fn main() {}").expect("write");
        assert!(sandbox.check_read(Path::new("src/main.rs")).is_ok());
    }

    #[test]
    fn test_relative_traversal_blocked() {
        let (_tmp, sandbox) = make_workspace();
        assert!(sandbox.check_read(Path::new("../../etc/passwd")).is_err());
    }

    #[test]
    fn test_env_file_denied_when_created() {
        let (tmp, sandbox) = make_workspace();
        let dotenv = tmp.path().join(".env");
        std::fs::write(&dotenv, b"SECRET=x").expect("write");
        assert!(
            sandbox.check_read(&dotenv).is_err(),
            "exact `.env` component should be denied"
        );
    }

    // ── RM-E4 / WP-E4.1 (audit AGT-01) ──────────────────────────────

    /// `~/.envrc-project` is NOT `.env` — pre-fix the substring
    /// match treated `.env` as a substring of `.envrc-project` and
    /// denied legitimate workspace files. Post-fix the per-component
    /// check accepts these.
    #[test]
    fn test_agt01_envrc_project_not_denied() {
        let (tmp, sandbox) = make_workspace();
        let path = tmp.path().join(".envrc-project");
        std::fs::write(&path, b"export FOO=bar").expect("write");
        assert!(
            sandbox.check_read(&path).is_ok(),
            "AGT-01: `.envrc-project` is a distinct component"
        );
    }

    /// A file literally named `.env` is still denied.
    #[test]
    fn test_agt01_dotenv_still_denied() {
        let (tmp, sandbox) = make_workspace();
        let path = tmp.path().join(".env");
        std::fs::write(&path, b"x").expect("write");
        assert!(sandbox.check_read(&path).is_err());
    }

    /// `~/.ssh/id_rsa` — when present anywhere in the path — is denied.
    #[test]
    fn test_agt01_ssh_component_denied() {
        let (_tmp, sandbox) = make_workspace();
        // Don't actually create `.ssh` in tmp — denied by component
        // even on a path that doesn't yet exist.
        assert!(sandbox
            .check_read(Path::new("/home/user/.ssh/id_rsa"))
            .is_err());
    }

    /// Workspace file with `.config` somewhere in the path is OK
    /// unless it's a `.config/gcloud` run.
    #[test]
    fn test_agt01_config_not_gcloud_allowed() {
        let (tmp, sandbox) = make_workspace();
        let cfg_dir = tmp.path().join(".config/cargo");
        std::fs::create_dir_all(&cfg_dir).expect("mkdir");
        let path = cfg_dir.join("config.toml");
        std::fs::write(&path, b"[build]").expect("write");
        assert!(
            sandbox.check_read(&path).is_ok(),
            "AGT-01: `.config/cargo` is not the denied `.config/gcloud` run"
        );
    }

    /// `.config/gcloud/credentials.json` — the multi-component run
    /// — is still denied.
    #[test]
    fn test_agt01_config_gcloud_run_denied() {
        let (_tmp, sandbox) = make_workspace();
        assert!(sandbox
            .check_read(Path::new("/home/user/.config/gcloud/credentials.json"))
            .is_err());
    }

    // ── RM-E4 / WP-E4.2 (audit AGT-02) ──────────────────────────────

    /// A symlink inside the workspace pointing to /etc/passwd is
    /// rejected: canonicalize follows the link and `starts_with`
    /// the workspace root fails.
    #[cfg(unix)]
    #[test]
    fn test_agt02_symlink_to_etc_passwd_rejected() {
        use std::os::unix::fs::symlink;
        let (tmp, sandbox) = make_workspace();
        let link = tmp.path().join("link-to-passwd");
        symlink("/etc/passwd", &link).expect("symlink");
        assert!(
            sandbox.check_read(&link).is_err(),
            "AGT-02: symlink escape must be rejected"
        );
    }

    /// A symlink that points within the workspace is fine.
    #[cfg(unix)]
    #[test]
    fn test_agt02_workspace_internal_symlink_ok() {
        use std::os::unix::fs::symlink;
        let (tmp, sandbox) = make_workspace();
        let target = tmp.path().join("src/main.rs");
        std::fs::write(&target, b"fn main() {}").expect("write");
        let link = tmp.path().join("link-to-main");
        symlink(&target, &link).expect("symlink");
        assert!(sandbox.check_read(&link).is_ok());
    }

    /// `file_write` to a non-existent file inside the workspace
    /// still works: we canonicalize the existing ancestor.
    #[test]
    fn test_agt02_write_to_new_file_in_workspace_ok() {
        let (tmp, sandbox) = make_workspace();
        let new_file = tmp.path().join("src/new_module.rs");
        assert!(
            sandbox.check_write(&new_file).is_ok(),
            "writes to new files inside workspace must succeed"
        );
    }

    /// `file_write` whose PARENT is a symlink escaping the workspace
    /// is rejected.
    #[cfg(unix)]
    #[test]
    fn test_agt02_write_through_escaping_parent_rejected() {
        use std::os::unix::fs::symlink;
        let (tmp, sandbox) = make_workspace();
        let escape = tmp.path().join("escape-parent");
        symlink("/tmp", &escape).expect("symlink");
        let new_file = escape.join("malicious.txt");
        assert!(
            sandbox.check_write(&new_file).is_err(),
            "AGT-02: writes through escaping parent must be rejected"
        );
    }

    // ── extra-allowed paths still work after AGT-02 ─────────────────

    #[test]
    fn test_extra_allowed_path() {
        let (_tmp, mut sandbox) = make_workspace();
        let extra_tmp = TempDir::new().expect("extra tempdir");
        let extra = std::fs::canonicalize(extra_tmp.path()).expect("canon extra");
        sandbox.allow_path(&extra);
        let target = extra.join("qwen.gguf");
        std::fs::write(&target, b"weights").expect("write");
        assert!(sandbox.check_read(&target).is_ok());
    }
}
