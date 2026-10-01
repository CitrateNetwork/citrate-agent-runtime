//! What an export may keep. The default keeps the least.

use crate::TrajectoryError;
use std::collections::BTreeSet;
use std::path::{Path, PathBuf};

/// Export policy. [`ExportPolicy::new`] is the conservative default: no granted roots (every
/// absolute path is redacted), no allowed addresses, tainted sessions excluded.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct ExportPolicy {
    granted_roots: Vec<PathBuf>,
    home: Option<PathBuf>,
    allowed_addresses: BTreeSet<String>,
    tainted_allowed: Option<String>,
}

impl ExportPolicy {
    pub fn new() -> Self {
        ExportPolicy::default()
    }

    /// A folder the member granted Hermes. Paths inside it are kept, rewritten as `[root:N]/...`
    /// (N = the order roots were added) so the absolute prefix never leaves the machine.
    pub fn with_granted_root(mut self, root: impl Into<PathBuf>) -> Self {
        self.granted_roots.push(root.into());
        self
    }

    /// The member's home directory, so `~/...` paths can be matched against granted roots.
    /// Without it every `~/...` path is redacted.
    pub fn with_home(mut self, home: impl Into<PathBuf>) -> Self {
        self.home = Some(home.into());
        self
    }

    /// Keep this wallet address verbatim (e.g. a public contract the member wants in the data).
    pub fn allow_address(mut self, address: &str) -> Self {
        self.allowed_addresses.insert(address.trim().to_lowercase());
        self
    }

    /// Include sessions that read untrusted content. Needs a non-empty reason, which is written
    /// into the redaction report.
    pub fn allow_tainted_sessions(mut self, reason: &str) -> Result<Self, TrajectoryError> {
        let reason = reason.trim();
        if reason.is_empty() {
            return Err(TrajectoryError::EmptyReason);
        }
        self.tainted_allowed = Some(reason.to_string());
        Ok(self)
    }

    pub fn granted_roots(&self) -> &[PathBuf] {
        &self.granted_roots
    }
    pub fn home(&self) -> Option<&Path> {
        self.home.as_deref()
    }
    pub fn allowed_addresses(&self) -> &BTreeSet<String> {
        &self.allowed_addresses
    }
    pub fn tainted_allowed(&self) -> Option<&str> {
        self.tainted_allowed.as_deref()
    }
}
