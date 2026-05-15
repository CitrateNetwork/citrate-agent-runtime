//! Audit storage backends — RFC-CIT-AGENT-0001 §6.2 + planset
//! `05_AUDIT_CHAIN.md` "Storage backends".
//!
//! Planset lists 4 backends; CIT-AGENT-5a lands the filesystem one
//! (the always-required default). NFS/S3 + WORM + chain-anchor come
//! in 5b/c.

mod fs;
pub use fs::FilesystemSink;

use crate::audit::record::AuditRecord;
use crate::error::AgentError;

/// Persistence trait for audit records. Implementations:
///   * `FilesystemSink` (5a) — local-disk JSONL
///   * `ObjectSink` (5b) — NFS / S3-compatible
///   * `WormSink` (5b) — NetApp SnapLock, S3 Object Lock Compliance, etc.
///   * `ChainAnchorSink` (5c) — commits to AnchorRegistry per strategy
pub trait AuditSink: Send + Sync {
    /// Append a record to the sink. MUST be atomic against partial
    /// writes (filesystem uses `O_APPEND` + a single `write_all`;
    /// object stores use single-PUT operations).
    fn append(&self, record: &AuditRecord) -> Result<(), AgentError>;

    /// Iterate all records in sequence order. Used by chain
    /// integrity verification + audit export. Implementations
    /// returning a streaming iterator MUST yield records in
    /// sequence-number order.
    fn iter(
        &self,
    ) -> Result<Box<dyn Iterator<Item = Result<AuditRecord, AgentError>> + '_>, AgentError>;
}
