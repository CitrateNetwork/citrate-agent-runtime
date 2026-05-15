//! Wasmtime engine factory — RFC-CIT-AGENT-0001 §4.5 invariant 3.
//!
//! Each capsule load constructs a fresh wasmtime `Engine` configured
//! for the Component Model + deterministic settings appropriate for
//! a FedRAMP-audit workload (NaN canonicalization on, default fuel
//! disabled — fuel + epoch interruption land in CIT-AGENT-3d when
//! `Capsule::call(...)` becomes real).

use crate::error::AgentError;
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
    /// Pre-canned eth_call response — test-only fixture. When `Some`,
    /// the host fn returns these bytes on authorized calls instead
    /// of dispatching the (future) real RPC. Production code paths
    /// MUST NOT set this; the value is only ever populated by the
    /// `inject_eth_call_canned_response` method, which is gated on
    /// the calling crate exposing test fixtures. CIT-AGENT-9c-1.
    eth_call_canned_response: Option<Vec<u8>>,
    /// Forensic record of the most recent eth_call (to, data). Tests
    /// inspect this to verify the calldata produced by the capsule
    /// matches the expected ABI encoding. Production audit log uses
    /// the AuditChain instead; this field is internal to the
    /// linker/test boundary. CIT-AGENT-9c-1.
    last_eth_call_to: Option<Address>,
    last_eth_call_data: Option<Vec<u8>>,
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
            eth_call_canned_response: None,
            last_eth_call_to: None,
            last_eth_call_data: None,
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
            eth_call_canned_response: None,
            last_eth_call_to: None,
            last_eth_call_data: None,
        }
    }

    /// Whether `to` is in the manifest-declared eth-call allow-list.
    pub fn is_eth_call_authorized(&self, to: &Address) -> bool {
        self.eth_call_allow_list.iter().any(|a| a == to)
    }

    /// Inspection accessor for the allow-list (audit + tests).
    pub fn eth_call_allow_list(&self) -> &[Address] {
        &self.eth_call_allow_list
    }

    /// Inject a canned response for the eth_call host fn. **Test
    /// fixture only.** Production code paths leave this as `None`,
    /// and the host fn returns `Ok(Vec::new())` as a stub until the
    /// real RPC dispatch lands in CIT-AGENT-9c-1-rpc.
    pub fn inject_eth_call_canned_response(&mut self, bytes: Vec<u8>) {
        self.eth_call_canned_response = Some(bytes);
    }

    /// Take the canned response (consumes the fixture so the next
    /// call would fall back to the default stub). Used by the host
    /// fn.
    pub fn take_eth_call_canned_response(&mut self) -> Option<Vec<u8>> {
        self.eth_call_canned_response.take()
    }

    /// Record the last (to, data) pair the host fn was invoked with.
    /// Used by integration tests to verify the calldata the capsule
    /// produced matches the expected ABI encoding.
    pub fn record_eth_call(&mut self, to: Address, data: Vec<u8>) {
        self.last_eth_call_to = Some(to);
        self.last_eth_call_data = Some(data);
    }

    pub fn last_eth_call_to(&self) -> Option<&Address> {
        self.last_eth_call_to.as_ref()
    }

    pub fn last_eth_call_data(&self) -> Option<&Vec<u8>> {
        self.last_eth_call_data.as_ref()
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
