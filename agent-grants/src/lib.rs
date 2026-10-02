//! # citrate-agent-grants: folder grants (HUP-S2.1)
//!
//! A member grants Hermes access to a folder. This crate holds those grants
//! and answers one question for every agent file operation:
//! [`FolderGrants::check`]`(path, op, now)` is either
//! [`Decision::Allowed`] with the canonical path to do the I/O on, or
//! [`Decision::Denied`] with the reason.
//!
//! ## Model (decision D-15, amended 2026-09-30)
//!
//! A grant is `(root folder, access, scope, expiry, granted_by, reason)`.
//!
//! * **Descendants only.** A grant covers its root and what is below it
//!   ([`GrantScope::Subtree`]) or its root and the root's direct entries
//!   ([`GrantScope::Shallow`]). It never covers a parent or a sibling.
//! * **Read and write are separate.** A [`Access::Read`] grant allows
//!   [`Op::Read`] only; an [`Access::Write`] grant allows [`Op::Write`] only.
//!   A member who wants both grants both.
//! * **Full access** is a [`GrantKind::FullAccess`] grant over a root the
//!   member picks (often home). It is read-only and always expires, at most
//!   [`FULL_ACCESS_MAX_TTL_SECS`] (24 h) after it was granted. Writes only
//!   ever come from folder grants.
//! * **The deny list always wins.** Every check runs
//!   `citrate_agent_guard::check_path` first. No grant, including full
//!   access, reaches a credential store, keychain, browser profile, wallet
//!   storage, Citrate Core app data or shell history. A `.env` file is
//!   readable or writable only inside a live *folder* grant for that
//!   operation, never through full access.
//! * **Time is checked at use.** A grant with `expires_at = Some(t)` allows
//!   nothing at or after `t`. Revocation is immediate and final.
//!
//! ## Resolution
//!
//! Paths are resolved by agent-guard the way the kernel resolves them:
//! component by component, following each symlink where it is met, so
//! `link/..` is the parent of the link's *target*. No `..` is ever popped
//! lexically before resolution. The existing part of the result
//! is then passed through `std::fs::canonicalize` only to pick up the
//! on-disk spelling on case-insensitive volumes, and the guard is asked
//! again about that spelling; the two must agree exactly or the check fails
//! closed. Grant roots are stored in the same canonical form, so a root
//! later swapped for a symlink grants nothing new.
//!
//! ## Caller contract
//!
//! The guard's contract applies: do the I/O on the returned
//! [`CanonicalPath`], open the leaf without following a swapped-in symlink
//! where the OS allows, check every entry of a recursive operation, and do
//! not let an agent create hard links into a write grant.
//!
//! ## Status
//!
//! Implemented and tested in this crate. The agent sidecar's sessions use it
//! for the grant-checked file tools and the toolchain project folder
//! (`agent-sidecar/src/grants.rs`); citrate-core stores the persistence format
//! ([`GrantState`]) and sends it to each session. Capsule WASI preopens are
//! scoped to these grants (`citrate_agent_core::capsule::sandbox`, HUP-S2.5);
//! the sidecar does not pass session grants to capsules yet.

use citrate_agent_guard::{check_path, Denied, GuardContext};
use serde::{Deserialize, Serialize};
use std::collections::HashSet;
use std::path::{Component, Path, PathBuf};

pub use citrate_agent_guard::CanonicalPath;

/// Longest a full-access grant may live: 24 hours.
pub const FULL_ACCESS_MAX_TTL_SECS: u64 = 24 * 60 * 60;

/// Version of the [`GrantState`] persistence format.
pub const STATE_VERSION: u32 = 1;

/// What a grant allows. Separate on purpose: read never implies write and
/// write never implies read.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Access {
    Read,
    Write,
}

/// The operation an agent wants to perform.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum Op {
    Read,
    Write,
}

impl Op {
    fn access(self) -> Access {
        match self {
            Op::Read => Access::Read,
            Op::Write => Access::Write,
        }
    }
}

/// How far below its root a grant reaches.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum GrantScope {
    /// The root and everything below it.
    Subtree,
    /// The root and its direct entries only.
    Shallow,
}

/// A per-folder grant, or the time-boxed read-only full-access grant.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum GrantKind {
    Folder,
    FullAccess,
}

/// One stored grant. `root` is absolute and canonical (symlinks resolved,
/// on-disk spelling) as of when it was granted.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Grant {
    pub id: String,
    pub kind: GrantKind,
    pub root: PathBuf,
    pub access: Access,
    pub scope: GrantScope,
    /// Unix seconds.
    pub granted_at: u64,
    /// Unix seconds; the grant allows nothing at or after this instant.
    /// `None` only for folder grants, meaning "until revoked".
    pub expires_at: Option<u64>,
    /// The member who granted it (wallet address or member id).
    pub granted_by: String,
    /// Why, in the member's words; shown in the Grants list.
    pub reason: String,
    /// Unix seconds; set once, never cleared.
    pub revoked_at: Option<u64>,
}

impl Grant {
    /// Live at `now`: not revoked, already granted and not expired. The
    /// window is `[granted_at, expires_at)`, so a stored grant dated ahead of
    /// the clock is inert until then and full access stays bounded by its
    /// TTL from the instant it starts.
    pub fn is_active(&self, now: u64) -> bool {
        self.revoked_at.is_none()
            && self.granted_at <= now
            && self.expires_at.is_none_or(|t| now < t)
    }

    fn covers(&self, path: &Path) -> bool {
        match self.scope {
            GrantScope::Subtree => path.starts_with(&self.root),
            GrantScope::Shallow => {
                path == self.root || path.parent().is_some_and(|p| p == self.root)
            }
        }
    }
}

/// The persistence format core stores (JSON via serde). Loading validates
/// every rule a fresh grant must satisfy and refuses the whole document on
/// any violation.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct GrantState {
    pub version: u32,
    /// Next numeric id; every stored id is `g-<n>` with `n < next_id`.
    pub next_id: u64,
    pub grants: Vec<Grant>,
}

impl Default for GrantState {
    fn default() -> Self {
        Self {
            version: STATE_VERSION,
            next_id: 1,
            grants: Vec::new(),
        }
    }
}

/// A request to create a grant. Build with [`GrantRequest::folder`] or
/// [`GrantRequest::full_access`].
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct GrantRequest {
    pub kind: GrantKind,
    pub root: PathBuf,
    pub access: Access,
    pub scope: GrantScope,
    /// `None` = until revoked (folder grants only).
    pub ttl_secs: Option<u64>,
    pub granted_by: String,
    pub reason: String,
}

impl GrantRequest {
    /// A folder grant covering `root` and its descendants, until revoked.
    pub fn folder(
        root: impl AsRef<Path>,
        access: Access,
        granted_by: impl Into<String>,
        reason: impl Into<String>,
    ) -> Self {
        Self {
            kind: GrantKind::Folder,
            root: root.as_ref().to_path_buf(),
            access,
            scope: GrantScope::Subtree,
            ttl_secs: None,
            granted_by: granted_by.into(),
            reason: reason.into(),
        }
    }

    /// The read-only full-access grant over `root`, expiring after
    /// `ttl_secs` (at most [`FULL_ACCESS_MAX_TTL_SECS`]).
    pub fn full_access(
        root: impl AsRef<Path>,
        ttl_secs: u64,
        granted_by: impl Into<String>,
        reason: impl Into<String>,
    ) -> Self {
        Self {
            kind: GrantKind::FullAccess,
            root: root.as_ref().to_path_buf(),
            access: Access::Read,
            scope: GrantScope::Subtree,
            ttl_secs: Some(ttl_secs),
            granted_by: granted_by.into(),
            reason: reason.into(),
        }
    }

    pub fn with_scope(mut self, scope: GrantScope) -> Self {
        self.scope = scope;
        self
    }

    pub fn with_ttl_secs(mut self, ttl_secs: u64) -> Self {
        self.ttl_secs = Some(ttl_secs);
        self
    }

    pub fn without_ttl(mut self) -> Self {
        self.ttl_secs = None;
        self
    }

    pub fn with_access(mut self, access: Access) -> Self {
        self.access = access;
        self
    }
}

/// Why a grant could not be created, revoked or loaded.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum GrantError {
    #[error("grant root is in a default-deny location: {0}")]
    RootDenied(Denied),
    #[error("grant root is not an existing folder: {0}")]
    RootNotADirectory(PathBuf),
    #[error("could not resolve the grant root: {0}")]
    RootUnresolvable(String),
    #[error("write access to the filesystem root is not grantable")]
    WriteOnFilesystemRoot,
    #[error("full access is read-only; writes need a folder grant")]
    FullAccessIsReadOnly,
    #[error("bad time limit: {reason}")]
    BadTtl { reason: String },
    #[error("a grant needs the member who granted it")]
    MissingGrantedBy,
    #[error("a grant needs a reason")]
    MissingReason,
    #[error("no grant with id {0}")]
    UnknownGrant(String),
    #[error("grant {0} is already revoked")]
    AlreadyRevoked(String),
    #[error("stored grants are invalid: {0}")]
    InvalidState(String),
    #[error("could not serialize grants: {0}")]
    Serialize(String),
}

/// Why a check was denied.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum DenialReason {
    /// The default-deny list (agent-guard). No grant overrides this.
    #[error("{0}")]
    DenyList(Denied),
    /// The resolved path is outside every live grant for this operation.
    #[error("no live {op:?} grant covers {}", path.display())]
    NoGrant { op: Op, path: PathBuf },
    /// The path changed while it was being checked, or could not be read.
    #[error("path could not be resolved consistently: {0}")]
    Unresolvable(String),
}

/// The answer to [`FolderGrants::check`].
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Decision {
    Allowed {
        /// Absolute, symlink-resolved path. Do the I/O on this.
        canonical: CanonicalPath,
        /// The most specific live grant that covers it.
        grant_id: String,
    },
    Denied {
        reason: DenialReason,
    },
}

/// Lifecycle state for the Grants list.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum GrantStatus {
    /// Dated after `now` (`granted_at > now`): allows nothing yet.
    NotYetActive,
    Active,
    Expired,
    Revoked,
}

/// One row of [`FolderGrants::list`].
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct GrantView {
    pub grant: Grant,
    pub status: GrantStatus,
    /// Seconds until expiry (0 once expired); `None` for "until revoked".
    /// This is the full-access countdown.
    pub remaining_secs: Option<u64>,
}

/// The grant set plus the context paths are resolved in (home for `~`,
/// cwd for relative paths).
#[derive(Debug, Clone)]
pub struct FolderGrants {
    state: GrantState,
    home: PathBuf,
    cwd: PathBuf,
}

impl FolderGrants {
    /// An empty grant set.
    pub fn new(home: impl AsRef<Path>, cwd: impl AsRef<Path>) -> Self {
        Self {
            state: GrantState::default(),
            home: home.as_ref().to_path_buf(),
            cwd: cwd.as_ref().to_path_buf(),
        }
    }

    /// Load a stored state, refusing it as a whole if any rule is broken.
    pub fn from_state(
        state: GrantState,
        home: impl AsRef<Path>,
        cwd: impl AsRef<Path>,
    ) -> Result<Self, GrantError> {
        let me = Self {
            state,
            home: home.as_ref().to_path_buf(),
            cwd: cwd.as_ref().to_path_buf(),
        };
        me.validate_state()?;
        Ok(me)
    }

    /// Load the JSON written by [`FolderGrants::to_json`].
    pub fn from_json(
        json: &str,
        home: impl AsRef<Path>,
        cwd: impl AsRef<Path>,
    ) -> Result<Self, GrantError> {
        let state: GrantState = serde_json::from_str(json)
            .map_err(|e| GrantError::InvalidState(format!("not a grant document: {e}")))?;
        Self::from_state(state, home, cwd)
    }

    pub fn to_json(&self) -> Result<String, GrantError> {
        serde_json::to_string_pretty(&self.state).map_err(|e| GrantError::Serialize(e.to_string()))
    }

    pub fn state(&self) -> &GrantState {
        &self.state
    }

    fn guard_ctx(&self) -> GuardContext {
        GuardContext::new(&self.home, &self.cwd)
    }

    /// Create a grant at `now` and return its id.
    pub fn grant(&mut self, req: GrantRequest, now: u64) -> Result<String, GrantError> {
        if req.granted_by.trim().is_empty() {
            return Err(GrantError::MissingGrantedBy);
        }
        if req.reason.trim().is_empty() {
            return Err(GrantError::MissingReason);
        }
        if req.kind == GrantKind::FullAccess && req.access != Access::Read {
            return Err(GrantError::FullAccessIsReadOnly);
        }
        let expires_at = match (req.kind, req.ttl_secs) {
            (_, Some(0)) => {
                return Err(GrantError::BadTtl {
                    reason: "a time limit must be at least one second".into(),
                })
            }
            (GrantKind::FullAccess, None) => {
                return Err(GrantError::BadTtl {
                    reason: "full access always expires".into(),
                })
            }
            (GrantKind::FullAccess, Some(t)) if t > FULL_ACCESS_MAX_TTL_SECS => {
                return Err(GrantError::BadTtl {
                    reason: format!("full access lasts at most {FULL_ACCESS_MAX_TTL_SECS} s"),
                })
            }
            (_, Some(t)) => Some(now.checked_add(t).ok_or_else(|| GrantError::BadTtl {
                reason: "expiry overflows".into(),
            })?),
            (GrantKind::Folder, None) => None,
        };
        let root = self.canonical_root(&req.root)?;
        if req.access == Access::Write && root.parent().is_none() {
            return Err(GrantError::WriteOnFilesystemRoot);
        }
        let id = format!("g-{}", self.state.next_id);
        let next = self
            .state
            .next_id
            .checked_add(1)
            .ok_or_else(|| GrantError::InvalidState("grant ids exhausted".into()))?;
        self.state.grants.push(Grant {
            id: id.clone(),
            kind: req.kind,
            root,
            access: req.access,
            scope: req.scope,
            granted_at: now,
            expires_at,
            granted_by: req.granted_by,
            reason: req.reason,
            revoked_at: None,
        });
        self.state.next_id = next;
        Ok(id)
    }

    /// Revoke a grant. Takes effect for every check from now on.
    pub fn revoke(&mut self, id: &str, now: u64) -> Result<(), GrantError> {
        let g = self
            .state
            .grants
            .iter_mut()
            .find(|g| g.id == id)
            .ok_or_else(|| GrantError::UnknownGrant(id.to_string()))?;
        if g.revoked_at.is_some() {
            return Err(GrantError::AlreadyRevoked(id.to_string()));
        }
        g.revoked_at = Some(now);
        Ok(())
    }

    /// Every grant, with its status and countdown at `now`.
    pub fn list(&self, now: u64) -> Vec<GrantView> {
        self.state
            .grants
            .iter()
            .map(|g| GrantView {
                grant: g.clone(),
                status: if g.revoked_at.is_some() {
                    GrantStatus::Revoked
                } else if now < g.granted_at {
                    GrantStatus::NotYetActive
                } else if g.is_active(now) {
                    GrantStatus::Active
                } else {
                    GrantStatus::Expired
                },
                remaining_secs: g.expires_at.map(|t| t.saturating_sub(now)),
            })
            .collect()
    }

    /// May the agent perform `op` on `path` at `now`?
    pub fn check(&self, path: impl AsRef<Path>, op: Op, now: u64) -> Decision {
        match self.check_inner(path.as_ref(), op, now) {
            Ok((canonical, grant_id)) => Decision::Allowed {
                canonical,
                grant_id,
            },
            Err(reason) => Decision::Denied { reason },
        }
    }

    fn check_inner(
        &self,
        path: &Path,
        op: Op,
        now: u64,
    ) -> Result<(CanonicalPath, String), DenialReason> {
        let want = op.access();
        let live = |kind: GrantKind| -> Vec<&Grant> {
            self.state
                .grants
                .iter()
                .filter(|g| g.kind == kind && g.access == want && g.is_active(now))
                .collect()
        };

        // Phase 1: folder grants. Their roots are the guard's project roots,
        // so a `.env` inside one passes the guard. Only a folder grant that
        // actually covers the target may allow it: a shallow grant's root is
        // a project root for files it does not cover, which is why the
        // full-access phase below re-runs the guard without project roots.
        let folders = live(GrantKind::Folder);
        let ctx = folders
            .iter()
            .fold(self.guard_ctx(), |c, g| c.with_project_root(&g.root));
        let canonical = resolve_checked(path, &ctx)?;
        if let Some(g) = most_specific(&folders, canonical.as_path()) {
            return Ok((canonical, g.id.clone()));
        }

        // Phase 2: full access (read-only by construction). No project
        // roots: full access never unlocks a `.env` file.
        let full = live(GrantKind::FullAccess);
        if full.is_empty() {
            return Err(DenialReason::NoGrant {
                op,
                path: canonical.into_path_buf(),
            });
        }
        let canonical = resolve_checked(path, &self.guard_ctx())?;
        match most_specific(&full, canonical.as_path()) {
            Some(g) => Ok((canonical, g.id.clone())),
            None => Err(DenialReason::NoGrant {
                op,
                path: canonical.into_path_buf(),
            }),
        }
    }

    /// Resolve a requested root to the canonical folder a grant stores.
    fn canonical_root(&self, root: &Path) -> Result<PathBuf, GrantError> {
        let spelled = resolve_checked(root, &self.guard_ctx())
            .map_err(|r| match r {
                DenialReason::DenyList(d) => GrantError::RootDenied(d),
                other => GrantError::RootUnresolvable(other.to_string()),
            })?
            .into_path_buf();
        if !spelled.is_dir() {
            return Err(GrantError::RootNotADirectory(spelled));
        }
        Ok(spelled)
    }

    fn validate_state(&self) -> Result<(), GrantError> {
        let bad = |m: String| Err(GrantError::InvalidState(m));
        let st = &self.state;
        if st.version != STATE_VERSION {
            return bad(format!("unknown version {}", st.version));
        }
        let ctx = self.guard_ctx();
        let mut seen = HashSet::new();
        for g in &st.grants {
            let n =
                g.id.strip_prefix("g-")
                    .and_then(|n| n.parse::<u64>().ok())
                    .ok_or_else(|| GrantError::InvalidState(format!("bad id {:?}", g.id)))?;
            if n >= st.next_id {
                return bad(format!("id {} is not below next_id {}", g.id, st.next_id));
            }
            if !seen.insert(n) {
                return bad(format!("duplicate id {}", g.id));
            }
            let plain = g
                .root
                .components()
                .all(|c| matches!(c, Component::RootDir | Component::Normal(_)));
            if !g.root.has_root() || !plain {
                return bad(format!(
                    "{}: root {} is not absolute and normalized",
                    g.id,
                    g.root.display()
                ));
            }
            if let Err(d) = check_path(&g.root, &ctx) {
                return bad(format!("{}: root is in a deny location ({d})", g.id));
            }
            if g.access == Access::Write && g.root.parent().is_none() {
                return bad(format!("{}: write on the filesystem root", g.id));
            }
            if g.granted_by.trim().is_empty() {
                return bad(format!("{}: missing granted_by", g.id));
            }
            if g.reason.trim().is_empty() {
                return bad(format!("{}: missing reason", g.id));
            }
            if let Some(t) = g.expires_at {
                if t <= g.granted_at {
                    return bad(format!("{}: expires before it was granted", g.id));
                }
            }
            if g.kind == GrantKind::FullAccess {
                if g.access != Access::Read {
                    return bad(format!("{}: full access is read-only", g.id));
                }
                match g.expires_at {
                    Some(t) if t - g.granted_at <= FULL_ACCESS_MAX_TTL_SECS => {}
                    _ => return bad(format!("{}: full access must expire within 24 h", g.id)),
                }
            }
        }
        Ok(())
    }
}

/// The deny list on the kernel-style resolution of the request, then the
/// on-disk spelling, then the guard again on that exact spelling; the two
/// answers must agree.
fn resolve_checked(path: &Path, ctx: &GuardContext) -> Result<CanonicalPath, DenialReason> {
    let resolved = check_path(path, ctx).map_err(DenialReason::DenyList)?;
    let spelled = on_disk_spelling(resolved.as_path()).map_err(DenialReason::Unresolvable)?;
    let canonical = check_path(&spelled, ctx).map_err(DenialReason::DenyList)?;
    if canonical.as_path() != spelled {
        return Err(DenialReason::Unresolvable(format!(
            "{} resolved differently on a second look",
            path.display()
        )));
    }
    Ok(canonical)
}

/// The covering grant with the deepest root.
fn most_specific<'a>(grants: &[&'a Grant], path: &Path) -> Option<&'a Grant> {
    grants
        .iter()
        .copied()
        .filter(|g| g.covers(path))
        .max_by_key(|g| g.root.components().count())
}

/// The on-disk spelling of an already resolved, symlink-free path: the
/// deepest existing ancestor through `std::fs::canonicalize` (which reports
/// the stored case on case-insensitive volumes), plus the components that do
/// not exist yet, unchanged.
fn on_disk_spelling(path: &Path) -> Result<PathBuf, String> {
    let mut existing = path.to_path_buf();
    let mut tail = Vec::new();
    loop {
        match std::fs::symlink_metadata(&existing) {
            Ok(_) => break,
            Err(e)
                if matches!(
                    e.kind(),
                    std::io::ErrorKind::NotFound | std::io::ErrorKind::NotADirectory
                ) =>
            {
                match existing.file_name() {
                    Some(name) => tail.push(name.to_owned()),
                    None => return Ok(path.to_path_buf()),
                }
                if !existing.pop() {
                    return Ok(path.to_path_buf());
                }
            }
            Err(e) => return Err(format!("cannot inspect {}: {e}", existing.display())),
        }
    }
    let mut out = std::fs::canonicalize(&existing)
        .map_err(|e| format!("cannot resolve {}: {e}", existing.display()))?;
    for name in tail.into_iter().rev() {
        out.push(name);
    }
    Ok(out)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn grant(root: &str, scope: GrantScope) -> Grant {
        Grant {
            id: "g-1".into(),
            kind: GrantKind::Folder,
            root: PathBuf::from(root),
            access: Access::Read,
            scope,
            granted_at: 10,
            expires_at: Some(20),
            granted_by: "m".into(),
            reason: "r".into(),
            revoked_at: None,
        }
    }

    #[test]
    fn covers_is_component_wise() {
        let g = grant("/a/proj", GrantScope::Subtree);
        assert!(g.covers(Path::new("/a/proj")));
        assert!(g.covers(Path::new("/a/proj/x/y")));
        assert!(!g.covers(Path::new("/a/proj-old")));
        assert!(!g.covers(Path::new("/a")));
        let s = grant("/a/proj", GrantScope::Shallow);
        assert!(s.covers(Path::new("/a/proj/x")));
        assert!(!s.covers(Path::new("/a/proj/x/y")));
        assert!(!s.covers(Path::new("/a")));
    }

    #[test]
    fn active_window_is_half_open() {
        let mut g = grant("/a", GrantScope::Subtree);
        assert!(!g.is_active(9));
        assert!(g.is_active(10));
        assert!(g.is_active(19));
        assert!(!g.is_active(20));
        g.expires_at = None;
        assert!(g.is_active(u64::MAX));
        g.revoked_at = Some(11);
        assert!(!g.is_active(0));
    }
}
