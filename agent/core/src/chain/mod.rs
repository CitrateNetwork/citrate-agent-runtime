//! Chain client — RFC-CIT-AGENT-0001 §3.1 "Chain Client".
//!
//! Lands in CIT-AGENT-6 per planset
//! [`.agentile/planset/2026-05-14-citrate-agent/08_SPRINT_SEQUENCE.md`]
//! when the on-chain contract surface ships (5 contracts:
//! OrganizationSBT, AgentSBT, CapsuleRegistry, AnchorRegistry,
//! BenchmarkRegistry).
//!
//! Will contain: `pub trait ChainClient`, ethers-rs adapter for
//! chain 40204, AnchorRegistry write API (3 strategies — per-capsule,
//! per-approval, nightly Merkle root), OrganizationSBT + AgentSBT
//! read + watch.
//!
//! NOTE: BFR-INT-12b's `RecorderClient` lives in `audit/` today and
//! writes to the Boeing-specific `AgentDecisionRegistryV2`. When the
//! cit-agent contracts deploy (CIT-AGENT-6), the canonical write path
//! moves to `AnchorRegistry` and `RecorderClient` becomes a
//! Boeing-overlay adapter — see planset
//! `06_ON_CHAIN_SURFACE.md` row 21.
