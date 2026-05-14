//! Capsule loader — RFC-CIT-AGENT-0001 §3.1 + §4.
//!
//! Lands in CIT-AGENT-3 per planset
//! [`.agentile/planset/2026-05-14-citrate-agent/08_SPRINT_SEQUENCE.md`].
//!
//! Will contain: `.cps` archive read/write, manifest TOML schema +
//! canonical-form hash, signature chain + content-hash + WIT/WASM
//! cross-check, wasmtime engine per-capsule (capability-typed linker),
//! bundled / managed / workspace signing tiers (RFC §4.5). The
//! install state-machine is verified by
//! `.agentile/formal/specs/agent/CapsuleInstall.tla`.
