//! Doctor + continuous monitoring — RFC-CIT-AGENT-0001 §10.
//!
//! Lands in CIT-AGENT-7 per planset
//! [`.agentile/planset/2026-05-14-citrate-agent/08_SPRINT_SEQUENCE.md`].
//!
//! Will contain: `pub fn run() -> DoctorReport`, the 11 checks
//! enumerated in RFC §10.2, signed TOML report writer, BLOCKER vs
//! WARN classification, optional content-hash anchor on-chain. The
//! daily continuous-monitoring artifact satisfies NIST CA-7.
