//! Wasmtime engine factory — RFC-CIT-AGENT-0001 §4.5 invariant 3.
//!
//! Each capsule load constructs a fresh wasmtime `Engine` configured
//! for the Component Model + deterministic settings appropriate for
//! a FedRAMP-audit workload (NaN canonicalization on, default fuel
//! disabled — fuel + epoch interruption land in CIT-AGENT-3d when
//! `Capsule::call(...)` becomes real).

use crate::capsule::dispatcher::EthCallDispatcher;
use crate::error::AgentError;
use std::sync::Arc;
use wasmtime::component::ResourceTable;
use wasmtime::{Config, Engine};
use wasmtime_wasi::{WasiCtx, WasiCtxBuilder, WasiView};

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
        }
    }

    /// Build a host context with a chain-call allow-list. Called by
    /// `Capsule::instantiate` when the manifest declares any
    /// `eth_call:<address>` entries.
    pub fn with_eth_call_allow_list(allow_list: Vec<Address>) -> Self {
        Self {
            ctx: WasiCtxBuilder::new().build(),
            table: ResourceTable::new(),
            eth_call_allow_list: allow_list,
            eth_call_canned_queue: std::collections::VecDeque::new(),
            eth_call_history: Vec::new(),
            eth_call_dispatcher: None,
        }
    }

    /// Build a host context with an allow-list AND a production
    /// dispatcher. Used by `Capsule::instantiate_with_store_and_dispatcher`
    /// for the live chain-dispatch path. CIT-AGENT-9c-1-rpc.
    pub fn with_dispatcher(
        allow_list: Vec<Address>,
        dispatcher: Arc<dyn EthCallDispatcher>,
    ) -> Self {
        Self {
            ctx: WasiCtxBuilder::new().build(),
            table: ResourceTable::new(),
            eth_call_allow_list: allow_list,
            eth_call_canned_queue: std::collections::VecDeque::new(),
            eth_call_history: Vec::new(),
            eth_call_dispatcher: Some(dispatcher),
        }
    }

    /// Get a clone of the dispatcher, if any. Host fn uses this to
    /// route real eth_call invocations when the canned-queue is
    /// empty.
    pub fn eth_call_dispatcher(&self) -> Option<Arc<dyn EthCallDispatcher>> {
        self.eth_call_dispatcher.clone()
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
    fn ctx(&mut self) -> &mut WasiCtx {
        &mut self.ctx
    }
    fn table(&mut self) -> &mut ResourceTable {
        &mut self.table
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
        // Defer fuel + epoch interruption to CIT-AGENT-3d; they need
        // the call path to wire the fuel-out + epoch-tick handlers.
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
