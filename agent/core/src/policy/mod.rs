//! Policy engine — RFC-CIT-AGENT-0001 §3.1 "Policy Engine".
//!
//! Lands in CIT-AGENT-4 per planset
//! [`.agentile/planset/2026-05-14-citrate-agent/08_SPRINT_SEQUENCE.md`].
//!
//! Will contain: signed PolicyBundle (canonical CBOR), data-class
//! lattice (PUBLIC | CUI | PHI | FERPA | ITAR), risk-tier mapping
//! rules, overlay activation as a one-way ratchet (RFC §2.3). The
//! lattice operator semantics are verified by
//! `.agentile/formal/specs/agent/DataClassLattice.tla`.
