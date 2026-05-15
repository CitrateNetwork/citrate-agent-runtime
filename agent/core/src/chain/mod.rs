//! Chain client — RFC-CIT-AGENT-0001 §3.1 "Chain Client" + planset
//! `06_ON_CHAIN_SURFACE.md`.
//!
//! CIT-AGENT-6d lands the first Rust adapter: `AnchorRegistryClient`
//! talks to the AnchorRegistry contract deployed by
//! `script/DeployCitAgent.s.sol`. The other 4 contract adapters
//! (OrganizationSBT, AgentSBT, CapsuleRegistry, BenchmarkRegistry)
//! land in per-contract slices.
//!
//! Architecture: each Rust adapter mirrors the BFR-INT-12b
//! `audit::recorder::RecorderClient` shape — `citrate-wallet-core`
//! provides the RPC client + transaction builder; the adapter
//! supplies the ABI encoding + the eth_call + send-tx ergonomics for
//! one contract.

pub mod anchor;

pub use anchor::{encode_anchor, encode_is_anchored, AnchorRegistryClient};
