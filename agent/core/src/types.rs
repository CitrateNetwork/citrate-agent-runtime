//! Shared cit-agent types.
//!
//! Reference: RFC-CIT-AGENT-0001 §3.2 paragraph 2. Lands the
//! identity-bearing newtypes the rest of the crate references. The
//! richer types (`PolicyBundle`, `Capsule`, etc.) live in their own
//! modules per the planset crate-structure doc.
//!
//! CIT-AGENT-1 keeps this minimal — only what `hitl` and `audit`
//! already need. Future sprints extend.
