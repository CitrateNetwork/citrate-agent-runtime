//! Agent loop — RFC-CIT-AGENT-0001 §3.1 "Agent Loop".
//!
//! Lands in CIT-AGENT-3 per planset
//! [`.agentile/planset/2026-05-14-citrate-agent/08_SPRINT_SEQUENCE.md`].
//!
//! Will contain: token-by-token streaming loop with checkpoint hooks,
//! state-managed interrupt (HIC pause/resume), and optional
//! trajectory export (feature-gated, RFC §12 Q3).
