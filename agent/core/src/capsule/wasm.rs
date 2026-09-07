//! Wasmtime engine factory — RFC-CIT-AGENT-0001 §4.5 invariant 3.
//!
//! Each capsule load constructs a fresh wasmtime `Engine` configured
//! for the Component Model + deterministic settings appropriate for
//! a FedRAMP-audit workload (NaN canonicalization on, default fuel
//! disabled — fuel + epoch interruption land in CIT-AGENT-3d when
//! `Capsule::call(...)` becomes real).

use crate::capsule::dispatcher::{ApprovalGate, EthCallDispatcher, EthSendDispatcher};
use crate::error::AgentError;
use std::sync::Arc;
use wasmtime::component::ResourceTable;
use wasmtime::{Config, Engine, StoreLimits, StoreLimitsBuilder};
use wasmtime_wasi::{WasiCtx, WasiCtxBuilder, WasiCtxView, WasiView};

/// A 20-byte EVM address.
pub type Address = [u8; 20];

/// Per-capsule host context — RFC-CIT-AGENT-0001 §4.5 invariant 3
/// runtime side. Holds the `WasiCtx` (the WASI capability + state
/// container), the `ResourceTable` (the Component Model resource
/// pool), and the per-capsule chain-call allow-list (CIT-AGENT-9c-host).
/// Future sprints extend `HostCtx` with chain-client + audit-sink
/// handles as the call path needs them.
pub struct HostCtx {
    ctx: WasiCtx,
    table: ResourceTable,
    /// Manifest-parsed allow-list for `citrate:chain/eth-call`. The
    /// host fn at call time consults this list; a `to` arg outside
    /// the list returns `Err("ChainCallNotAuthorized: ...")` without
    /// dispatching the RPC. CIT-AGENT-9c-host.
    eth_call_allow_list: Vec<Address>,
    /// Queue of pre-canned eth_call responses — test-only fixture.
    /// When non-empty, the host fn pops the front entry on each
    /// authorized call. When empty, falls back to the stub
    /// `Ok(Vec::new())`. CIT-AGENT-9c-2 (extended from 9c-1's
    /// single-response shape to support multi-call capsules).
    eth_call_canned_queue: std::collections::VecDeque<Vec<u8>>,
    /// Per-call forensic record of every eth_call (to, data). Tests
    /// inspect this to verify the capsule produced the expected
    /// ABI encoding for each call in a multi-call sequence.
    /// CIT-AGENT-9c-2 (extended from 9c-1's "last only" shape).
    eth_call_history: Vec<(Address, Vec<u8>)>,
    /// Optional production dispatcher for `citrate:chain/eth-call`.
    /// When set AND the canned-queue is empty, the host fn calls
    /// the dispatcher's `eth_call` to obtain the real chain
    /// response. When `None`, the host fn falls back to
    /// `Ok(Vec::new())` (the 9c-host legacy stub).
    /// CIT-AGENT-9c-1-rpc.
    eth_call_dispatcher: Option<Arc<dyn EthCallDispatcher>>,
    /// Manifest-parsed allow-list for `citrate:chain/eth-send`.
    /// The send host fn rejects `to` addresses outside this list.
    /// CIT-AGENT-9c-write-host.
    eth_send_allow_list: Vec<Address>,
    /// Per-call forensic record of every eth_send (to, data).
    /// Parallel to `eth_call_history`; tests + audit consumers
    /// inspect both.
    eth_send_history: Vec<(Address, Vec<u8>)>,
    /// Test fixture for eth_send responses (tx hash). Same shape
    /// as `eth_call_canned_queue`.
    eth_send_canned_queue: std::collections::VecDeque<[u8; 32]>,
    /// Optional production dispatcher for `citrate:chain/eth-send`.
    /// When set AND the canned-queue is empty, the host fn calls
    /// the dispatcher's `eth_send` AFTER the approval gate clears.
    eth_send_dispatcher: Option<Arc<dyn EthSendDispatcher>>,
    /// Optional HITL approval gate. Every eth_send call traverses
    /// this gate BEFORE the dispatcher is invoked. When `None`,
    /// the host fn rejects all eth_send calls with
    /// `Err("ChainSendApprovalRejected: no approval gate configured")`
    /// — defense-in-depth: writes without a gate are write-disabled.
    /// CIT-AGENT-9c-write-host.
    approval_gate: Option<Arc<dyn ApprovalGate>>,
    /// Self-identifier passed to the approval gate in
    /// `ApprovalRequest.capsule_name`. Set by the instantiate path
    /// from the manifest's `[capsule].name`. Empty when not yet
    /// instantiated.
    capsule_name: String,
    /// Risk tier from the calling capsule's manifest. AR-B-003: the
    /// approval gate uses this to compute the role-bound quorum and
    /// surface the true risk — instead of defaulting a privileged
    /// write to "low". Defaults to `Low` for un-instantiated / test
    /// contexts.
    risk_tier: crate::capsule::manifest::RiskTier,
    /// Roles the manifest requires to approve this capsule's writes.
    required_roles: Vec<crate::capsule::manifest::Role>,
    /// REM-12b real binding — per-store resource caps. Lives ON
    /// `HostCtx` (not in the limiter closure) so the `Store::limiter`
    /// callback can return `&mut self.store_limits` without the
    /// borrow-escapes-closure problem the old wasmtime-26 OnceLock
    /// placeholder ran into. Configured before each capsule call in
    /// `dispatch.rs` per RFC §4.5 invariant 3 ("bounded resource
    /// appetite per call"). Default values are the per-call caps
    /// (64 MiB heap, 1 table, 1 instance) — `dispatch.rs` may
    /// override per workload.
    pub store_limits: StoreLimits,
}

impl HostCtx {
    /// Build an empty host context. Sockets, filesystem preopens,
    /// and stdin/stdout/stderr defaults all start un-configured —
    /// per-capability wiring is the linker's job, NOT the host
    /// context's. This keeps the "build from manifest" property
    /// intact at the runtime layer.
    pub fn empty() -> Self {
        Self {
            ctx: WasiCtxBuilder::new().build(),
            table: ResourceTable::new(),
            eth_call_allow_list: Vec::new(),
            eth_call_canned_queue: std::collections::VecDeque::new(),
            eth_call_history: Vec::new(),
            eth_call_dispatcher: None,
            eth_send_allow_list: Vec::new(),
            eth_send_history: Vec::new(),
            eth_send_canned_queue: std::collections::VecDeque::new(),
            eth_send_dispatcher: None,
            approval_gate: None,
            capsule_name: String::new(),
            risk_tier: crate::capsule::manifest::RiskTier::Low,
            required_roles: Vec::new(),
            // REM-12b — per-capsule call resource caps.
            // dispatch.rs may reconfigure before each call; this is
            // the conservative default that applies even if the
            // dispatcher forgets to set it.
            store_limits: StoreLimitsBuilder::new()
                .memory_size(64 * 1024 * 1024) // 64 MiB hard cap
                .tables(1)
                .table_elements(10_000)
                .instances(1)
                .build(),
        }
    }

    /// Build a host context with a read allow-list (eth-call only).
    /// Write path stays unconfigured — no eth_send calls will
    /// succeed because `approval_gate = None` rejects them all.
    pub fn with_eth_call_allow_list(allow_list: Vec<Address>) -> Self {
        let mut s = Self::empty();
        s.eth_call_allow_list = allow_list;
        s
    }

    /// Build a host context with a read allow-list AND a read
    /// dispatcher. CIT-AGENT-9c-1-rpc. Write path still
    /// unconfigured.
    pub fn with_dispatcher(
        allow_list: Vec<Address>,
        dispatcher: Arc<dyn EthCallDispatcher>,
    ) -> Self {
        let mut s = Self::empty();
        s.eth_call_allow_list = allow_list;
        s.eth_call_dispatcher = Some(dispatcher);
        s
    }

    /// Build a host context with the full write-path wiring: read +
    /// write allow-lists, both dispatchers (any can be None), and
    /// the approval gate. CIT-AGENT-9c-write-host.
    pub fn with_write_path(
        eth_call_allow_list: Vec<Address>,
        eth_send_allow_list: Vec<Address>,
        eth_call_dispatcher: Option<Arc<dyn EthCallDispatcher>>,
        eth_send_dispatcher: Option<Arc<dyn EthSendDispatcher>>,
        approval_gate: Option<Arc<dyn ApprovalGate>>,
        capsule_name: String,
        risk_tier: crate::capsule::manifest::RiskTier,
        required_roles: Vec<crate::capsule::manifest::Role>,
    ) -> Self {
        let mut s = Self::empty();
        s.eth_call_allow_list = eth_call_allow_list;
        s.eth_send_allow_list = eth_send_allow_list;
        s.eth_call_dispatcher = eth_call_dispatcher;
        s.eth_send_dispatcher = eth_send_dispatcher;
        s.approval_gate = approval_gate;
        s.capsule_name = capsule_name;
        s.risk_tier = risk_tier;
        s.required_roles = required_roles;
        s
    }

    /// Get a clone of the dispatcher, if any. Host fn uses this to
    /// route real eth_call invocations when the canned-queue is
    /// empty.
    pub fn eth_call_dispatcher(&self) -> Option<Arc<dyn EthCallDispatcher>> {
        self.eth_call_dispatcher.clone()
    }

    // ────────────────── eth_send accessors (9c-write-host) ──────

    pub fn is_eth_send_authorized(&self, to: &Address) -> bool {
        self.eth_send_allow_list.iter().any(|a| a == to)
    }

    pub fn eth_send_allow_list(&self) -> &[Address] {
        &self.eth_send_allow_list
    }

    pub fn record_eth_send(&mut self, to: Address, data: Vec<u8>) {
        self.eth_send_history.push((to, data));
    }

    pub fn eth_send_history(&self) -> &[(Address, Vec<u8>)] {
        &self.eth_send_history
    }

    /// Pop the next canned tx hash response (test fixture).
    pub fn take_eth_send_canned_response(&mut self) -> Option<[u8; 32]> {
        self.eth_send_canned_queue.pop_front()
    }

    pub fn enqueue_eth_send_canned_response(&mut self, tx_hash: [u8; 32]) {
        self.eth_send_canned_queue.push_back(tx_hash);
    }

    pub fn eth_send_dispatcher(&self) -> Option<Arc<dyn EthSendDispatcher>> {
        self.eth_send_dispatcher.clone()
    }

    pub fn approval_gate(&self) -> Option<Arc<dyn ApprovalGate>> {
        self.approval_gate.clone()
    }

    pub fn capsule_name(&self) -> &str {
        &self.capsule_name
    }

    /// Risk tier from the calling capsule's manifest (AR-B-003).
    pub fn risk_tier(&self) -> crate::capsule::manifest::RiskTier {
        self.risk_tier
    }

    /// Roles the manifest requires to approve this capsule's writes
    /// (AR-B-003).
    pub fn required_roles(&self) -> &[crate::capsule::manifest::Role] {
        &self.required_roles
    }

    /// Whether `to` is in the manifest-declared eth-call allow-list.
    pub fn is_eth_call_authorized(&self, to: &Address) -> bool {
        self.eth_call_allow_list.iter().any(|a| a == to)
    }

    /// Inspection accessor for the allow-list (audit + tests).
    pub fn eth_call_allow_list(&self) -> &[Address] {
        &self.eth_call_allow_list
    }

    /// Single-response convenience for tests that only expect one
    /// host fn invocation. Clears any queued responses + enqueues
    /// one entry. Preserves the CIT-AGENT-9c-1 API shape.
    pub fn inject_eth_call_canned_response(&mut self, bytes: Vec<u8>) {
        self.eth_call_canned_queue.clear();
        self.eth_call_canned_queue.push_back(bytes);
    }

    /// Enqueue a canned response for the next eth_call. Multi-call
    /// capsules push one per expected call; the host fn pops in
    /// order. CIT-AGENT-9c-2.
    pub fn enqueue_eth_call_canned_response(&mut self, bytes: Vec<u8>) {
        self.eth_call_canned_queue.push_back(bytes);
    }

    /// Pop the next canned response from the front of the queue.
    /// Returns `None` if the queue is empty (host fn falls back to
    /// the stub).
    pub fn take_eth_call_canned_response(&mut self) -> Option<Vec<u8>> {
        self.eth_call_canned_queue.pop_front()
    }

    /// Append a (to, data) record to the host fn's per-call history.
    /// Tests inspect this to verify calldata for each call in a
    /// multi-call sequence.
    pub fn record_eth_call(&mut self, to: Address, data: Vec<u8>) {
        self.eth_call_history.push((to, data));
    }

    /// Full call history (audit + tests).
    pub fn eth_call_history(&self) -> &[(Address, Vec<u8>)] {
        &self.eth_call_history
    }

    /// Last call's `to`, if any. Convenience accessor that
    /// preserves the CIT-AGENT-9c-1 test API.
    pub fn last_eth_call_to(&self) -> Option<&Address> {
        self.eth_call_history.last().map(|(to, _)| to)
    }

    /// Last call's `data`, if any. Convenience accessor that
    /// preserves the CIT-AGENT-9c-1 test API.
    pub fn last_eth_call_data(&self) -> Option<&Vec<u8>> {
        self.eth_call_history.last().map(|(_, d)| d)
    }
}

impl WasiView for HostCtx {
    // REM-12 (wasmtime 26 → 45): WasiView trait now returns a
    // `WasiCtxView` struct that bundles ctx + table together. The
    // separate `fn table()` method is gone — the new view exposes
    // both via field access. The auto-impl at
    // wasmtime_wasi::view::impl<T: WasiView> WasiCliView/etc. for T
    // picks up cli / clocks / random / filesystem / sockets for free
    // from this one `ctx()` method, so the per-subsystem View traits
    // we used to need to satisfy explicitly are now derived.
    fn ctx(&mut self) -> WasiCtxView<'_> {
        WasiCtxView {
            ctx: &mut self.ctx,
            table: &mut self.table,
        }
    }
}

/// Build a wasmtime engine configured for the cit-agent capsule
/// model. Per-capsule because the engine config is part of the
/// fail-closed property — a single shared engine would let
/// capabilities leak across capsules via wasmtime internal state.
pub struct EngineFactory;

impl EngineFactory {
    pub fn build() -> Result<Engine, AgentError> {
        let mut config = Config::new();
        config.wasm_component_model(true);
        // Determinism for FedRAMP audit reproducibility. NaN
        // canonicalization makes float results bit-identical across
        // hardware so audit replays don't drift on floating point.
        config.cranelift_nan_canonicalization(true);

        // REM-12a (2026-05-20): epoch interruption enabled.
        // The 2026-05-19 federation-split audit's F-04 verified that
        // citrate-agent-runtime can be DoS'd by a 3-instruction
        // capsule (`(loop br 0)`) because no fuel + no epoch
        // interruption are wired. Enabling epoch_interruption here
        // is the first half of the fix; the caller of `func.call`
        // must arm `store.set_epoch_deadline(N)` + a background
        // ticker that advances `engine.increment_epoch()` to
        // actually bound execution time. See REM-12a in the audit's
        // 06_REMEDIATION_PLAN.md and per-repo/citrate-agent-runtime/
        // F-04_FP_CHECK.md §8 for the interim hardening plan.
        config.epoch_interruption(true);

        // REM-12d (2026-05-20): explicitly disable SIMD.
        // F-04 / RUSTSEC-2026-0087 — Cranelift x86-64 miscompiles
        // `f64x2.splat` causing segfault or out-of-sandbox load.
        // No in-tree capsule needs SIMD today. Disabling defeats the
        // attack path entirely; revisit if a capsule legitimately
        // needs SIMD (requires upgrade to a patched wasmtime first).
        config.wasm_simd(false);
        config.wasm_relaxed_simd(false);

        Engine::new(&config).map_err(|e| {
            AgentError::Capsule(format!("wasmtime engine construction failed: {e}"))
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn engine_builds() {
        EngineFactory::build().expect("engine constructs");
    }

    #[test]
    fn engine_is_independent_per_call() {
        // Two engines should be distinct (no shared global state
        // leaking between capsules). We can't easily assert
        // "different memory address" so we just confirm both build
        // without conflict.
        let e1 = EngineFactory::build().unwrap();
        let e2 = EngineFactory::build().unwrap();
        // Smoke: both engines accept a no-op precompile via
        // `precompile_component(&[])` — actually that returns Err
        // on empty bytes; we just check neither panics.
        let _ = e1;
        let _ = e2;
    }
}
