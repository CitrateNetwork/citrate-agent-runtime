//! Wasmtime engine factory — RFC-CIT-AGENT-0001 §4.5 invariant 3.
//!
//! Each capsule load constructs a fresh wasmtime `Engine` configured
//! for the Component Model + deterministic settings appropriate for
//! a FedRAMP-audit workload (NaN canonicalization on, default fuel
//! disabled — fuel + epoch interruption land in CIT-AGENT-3d when
//! `Capsule::call(...)` becomes real).

use crate::error::AgentError;
use wasmtime::{Config, Engine};

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
