//! Citrate Agent Core — the cit-agent harness library.
//!
//! Reference: RFC-CIT-AGENT-0001 v0.1 §3 (architecture) + §9.1 (TLA+
//! normative specs).
//!
//! The library is organized as eight top-level modules, one per
//! RFC §3.1 subsystem. CIT-AGENT-1 lands the skeleton + the first
//! two populated modules (`hitl` carries `ApprovalQueue` from
//! BFR-INT-12b; `audit` carries `RecorderClient`). The other six
//! land in CIT-AGENT-2..7 per
//! [`.agentile/planset/2026-05-14-citrate-agent/08_SPRINT_SEQUENCE.md`].
//!
//! Public API surface (RFC §3.2 — frozen until v1.0):
//!   - Re-exports: `ApprovalQueue`, `RecorderClient` (today)
//!   - Future: `Agent`, `Capsule`, `PolicyBundle`, `AuditChain`
//!     (CIT-AGENT-3..5)
//!   - Traits: `Model`, `AuditSink` (CIT-AGENT-3, 5)

pub mod agent;
pub mod audit;
pub mod capsule;
pub mod chain;
pub mod doctor;
pub mod hitl;
pub mod model;
pub mod policy;

pub mod error;
pub mod types;

// Public re-exports — the BFR-INT-12b types that boeing-shell consumes
// directly. Per RFC §3.2 the v1.0 frozen surface lists these by name.
pub use audit::RecorderClient;
pub use hitl::{
    ApprovalOutcomePublic, ApprovalQueue, PendingView, ToolCall, ToolResult,
};
