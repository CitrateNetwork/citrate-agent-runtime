//! Audit chain — RFC-CIT-AGENT-0001 §3.1 + §6.
//!
//! CIT-AGENT-5a lands the canonical record schema, hash-chained
//! `AuditChain`, and the default filesystem `AuditSink` backend.
//! Verified against `.agentile/formal/specs/agent/AuditChainIntegrity.tla`
//! (CIT-AGENT-2 PASS at 35,435 distinct states).
//!
//! Module organization:
//!   * `record` — `AuditRecord`, `EventType`, canonical CBOR
//!   * `chain` — `AuditChain` (hash-chained append + integrity verify)
//!   * `sink` — `AuditSink` trait + `FilesystemSink` impl
//!   * `recorder` — BFR-INT-12b on-chain decision-log writer
//!     (moved here from `audit/mod.rs` in 5a; will become a
//!     Boeing-overlay adapter once cit-agent's `AnchorRegistry`
//!     ships in CIT-AGENT-6)

pub mod chain;
pub mod record;
pub mod recorder;
pub mod sink;

// Re-exports for the v1.0 public API per RFC §3.2.
pub use chain::{AuditChain, GenesisInfo};
pub use record::{
    canonical_cbor, record_hash, AnchorKind, AnchorRef, AuditRecord, EventType, RoleSignature,
    SigningSurfaceTag,
};
pub use recorder::*;
pub use sink::{AuditSink, FilesystemSink};
