//! Per-capsule wasmtime linker — RFC-CIT-AGENT-0001 §4.5 invariant 3
//! ("build from manifest, NOT filter default").
//!
//! This is the load-bearing security module for the harness. From
//! the planset:
//!
//! > A "default table then filter" approach has two failure modes:
//! >   - A new wasmtime version adds a host function that the
//! >     harness's filter doesn't know about; the new function leaks.
//! >   - A bug in the filter logic silently passes a capability that
//! >     shouldn't be passable.
//! >
//! > A "build from manifest" approach has neither failure mode:
//! > every host function in the per-capsule linker is there because
//! > the manifest explicitly declared the capability that requires it.
//!
//! CIT-AGENT-3c lands the *construction pattern* — a `LinkerBuilder`
//! that records which capabilities were declared on the manifest and
//! adds them to the wasmtime `Linker`. The actual wasmtime-wasi host
//! function bodies are wired in CIT-AGENT-3d when `Capsule::call(...)`
//! becomes the runtime path. For now, the linker is constructed and
//! the *capability set* is recorded for inspection + test assertions.

use crate::capsule::filesystem;
use crate::capsule::manifest::{Manifest, NetworkPolicy};
use crate::capsule::wasm::HostCtx;
use crate::error::AgentError;
use std::collections::BTreeSet;
use wasmtime::component::Linker;
use wasmtime::Engine;

/// The capability tokens recorded by the linker builder. These name
/// the WASI interface families the capsule may import. Inspection of
/// this set is the audit-friendly witness: "this capsule's linker
/// admits exactly these WASI groups, nothing more."
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub enum CapabilityToken {
    /// `wasi:cli` (stdio). Always permitted.
    WasiCli,
    /// `wasi:clocks` (time of day). Always permitted.
    WasiClocks,
    /// `wasi:random` (RNG). Always permitted.
    WasiRandom,
    /// `wasi:sockets` (TCP/UDP). Permitted only when
    /// `[capability].network != "none"`.
    WasiSockets,
    /// `wasi:filesystem` (FS open/read/write). Permitted only when
    /// `[capability].filesystem` is non-empty.
    WasiFilesystem,
    /// `citrate:chain/eth-call@0.1.0` (read-only chain calls).
    /// Permitted only when `[capability].chain_calls` contains at
    /// least one `eth_call:<address>` entry. The host fn enforces
    /// the per-address allow-list at call time — the token here
    /// just gates whether the host fn is registered at all.
    /// CIT-AGENT-9c-host.
    CitrateChainEthCall,
}

/// LinkerBuilder for the per-capsule wasmtime Linker. Starts empty;
/// the manifest constructor adds only what's declared. CIT-AGENT-3d
/// promoted the `HostCtx` from a placeholder to the real
/// `wasmtime_wasi::WasiView` impl in `capsule::wasm`.
pub struct LinkerBuilder {
    linker: Linker<HostCtx>,
    permitted: BTreeSet<CapabilityToken>,
}

impl std::fmt::Debug for LinkerBuilder {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        // wasmtime::Linker doesn't implement Debug; expose what
        // matters for inspection.
        f.debug_struct("LinkerBuilder")
            .field("permitted", &self.permitted)
            .finish_non_exhaustive()
    }
}

impl LinkerBuilder {
    /// Empty linker — no host functions registered. Useful for
    /// tests of the fail-closed property.
    pub fn empty(engine: &Engine) -> Self {
        Self {
            linker: Linker::new(engine),
            permitted: BTreeSet::new(),
        }
    }

    /// Build a per-capsule linker from a manifest. The linker
    /// admits ONLY the WASI capabilities the manifest declares. New
    /// wasmtime versions may add host functions; this constructor
    /// will not register them unless the manifest schema is extended
    /// to recognize the new capability — the fail-closed property
    /// per planset §"Why 'build from manifest' not 'filter default'".
    pub fn from_manifest(engine: &Engine, manifest: &Manifest) -> Result<Self, AgentError> {
        let mut b = Self::empty(engine);
        // CLI / clocks / random — always permitted (no policy
        // implication; capsules typically need stdio).
        b.permitted.insert(CapabilityToken::WasiCli);
        b.permitted.insert(CapabilityToken::WasiClocks);
        b.permitted.insert(CapabilityToken::WasiRandom);
        // Sockets — only when network policy is non-`none`.
        if !matches!(manifest.capability.network, NetworkPolicy::None) {
            b.permitted.insert(CapabilityToken::WasiSockets);
        }
        // Filesystem — only when at least one entry is declared.
        // Per-path sandboxing happens when wasi:filesystem is
        // actually wired in CIT-AGENT-3d (the linker registers a
        // host fn that consults the allow-list at runtime).
        if !manifest.capability.filesystem.is_empty() {
            // Validate the entries now — fail-fast on a malformed
            // manifest rather than later at first filesystem call.
            filesystem::parse_all(&manifest.capability.filesystem)?;
            b.permitted.insert(CapabilityToken::WasiFilesystem);
        }
        // Citrate chain eth-call — token gates whether the host fn
        // gets registered at all; the host fn itself enforces the
        // per-address allow-list at call time. CIT-AGENT-9c-host.
        if manifest
            .capability
            .chain_calls
            .iter()
            .any(|s| s.starts_with("eth_call:"))
        {
            b.permitted.insert(CapabilityToken::CitrateChainEthCall);
        }
        Ok(b)
    }

    /// Inspection accessor: which capability tokens are registered.
    /// Audit + test assertions use this.
    pub fn permitted(&self) -> &BTreeSet<CapabilityToken> {
        &self.permitted
    }

    /// Wire real `wasmtime-wasi` host functions into the linker based
    /// on the permitted capability tokens. The selection mirrors
    /// `wasmtime_wasi::add_to_linker_sync` but only registers the
    /// subsystems whose token is permitted — i.e. "build from
    /// manifest, NOT filter default" at the linker level.
    ///
    /// Per RFC §4.5: a new wasmtime version adding a host fn under
    /// `wasi:sockets` can't leak through to a `network = "none"`
    /// capsule because the per-capsule linker never called the
    /// sockets add_to_linker family. CIT-AGENT-3d.
    pub fn wire_wasi_host_fns(mut self) -> Result<Self, AgentError> {
        use wasmtime_wasi::bindings as b;
        use wasmtime_wasi::{WasiImpl, WasiView};

        // The `closure` pattern + `type_annotate` workaround is
        // copied verbatim from wasmtime_wasi::add_to_linker_sync.
        fn type_annotate<T: WasiView, F>(val: F) -> F
        where
            F: Fn(&mut T) -> WasiImpl<&mut T>,
        {
            val
        }
        let closure = type_annotate::<HostCtx, _>(|t| WasiImpl(t));
        let l = &mut self.linker;

        if self.permitted.contains(&CapabilityToken::WasiCli) {
            b::cli::exit::add_to_linker_get_host(l, closure)
                .map_err(|e| linker_err("cli::exit", e))?;
            b::cli::environment::add_to_linker_get_host(l, closure)
                .map_err(|e| linker_err("cli::environment", e))?;
            b::cli::stdin::add_to_linker_get_host(l, closure)
                .map_err(|e| linker_err("cli::stdin", e))?;
            b::cli::stdout::add_to_linker_get_host(l, closure)
                .map_err(|e| linker_err("cli::stdout", e))?;
            b::cli::stderr::add_to_linker_get_host(l, closure)
                .map_err(|e| linker_err("cli::stderr", e))?;
            b::cli::terminal_input::add_to_linker_get_host(l, closure)
                .map_err(|e| linker_err("cli::terminal_input", e))?;
            b::cli::terminal_output::add_to_linker_get_host(l, closure)
                .map_err(|e| linker_err("cli::terminal_output", e))?;
            b::cli::terminal_stdin::add_to_linker_get_host(l, closure)
                .map_err(|e| linker_err("cli::terminal_stdin", e))?;
            b::cli::terminal_stdout::add_to_linker_get_host(l, closure)
                .map_err(|e| linker_err("cli::terminal_stdout", e))?;
            b::cli::terminal_stderr::add_to_linker_get_host(l, closure)
                .map_err(|e| linker_err("cli::terminal_stderr", e))?;
        }
        if self.permitted.contains(&CapabilityToken::WasiClocks) {
            b::clocks::wall_clock::add_to_linker_get_host(l, closure)
                .map_err(|e| linker_err("clocks::wall_clock", e))?;
            b::clocks::monotonic_clock::add_to_linker_get_host(l, closure)
                .map_err(|e| linker_err("clocks::monotonic_clock", e))?;
        }
        if self.permitted.contains(&CapabilityToken::WasiRandom) {
            b::random::random::add_to_linker_get_host(l, closure)
                .map_err(|e| linker_err("random::random", e))?;
            b::random::insecure::add_to_linker_get_host(l, closure)
                .map_err(|e| linker_err("random::insecure", e))?;
            b::random::insecure_seed::add_to_linker_get_host(l, closure)
                .map_err(|e| linker_err("random::insecure_seed", e))?;
        }
        // I/O streams + io::error are foundational for filesystem
        // AND sockets — register when either is permitted.
        let needs_io = self.permitted.contains(&CapabilityToken::WasiFilesystem)
            || self.permitted.contains(&CapabilityToken::WasiSockets)
            || self.permitted.contains(&CapabilityToken::WasiCli);
        if needs_io {
            b::io::error::add_to_linker_get_host(l, closure)
                .map_err(|e| linker_err("io::error", e))?;
            b::sync::io::poll::add_to_linker_get_host(l, closure)
                .map_err(|e| linker_err("io::poll", e))?;
            b::sync::io::streams::add_to_linker_get_host(l, closure)
                .map_err(|e| linker_err("io::streams", e))?;
        }
        if self.permitted.contains(&CapabilityToken::WasiFilesystem) {
            b::sync::filesystem::types::add_to_linker_get_host(l, closure)
                .map_err(|e| linker_err("filesystem::types", e))?;
            b::filesystem::preopens::add_to_linker_get_host(l, closure)
                .map_err(|e| linker_err("filesystem::preopens", e))?;
        }
        if self.permitted.contains(&CapabilityToken::WasiSockets) {
            b::sync::sockets::tcp::add_to_linker_get_host(l, closure)
                .map_err(|e| linker_err("sockets::tcp", e))?;
            b::sockets::tcp_create_socket::add_to_linker_get_host(l, closure)
                .map_err(|e| linker_err("sockets::tcp_create_socket", e))?;
            b::sync::sockets::udp::add_to_linker_get_host(l, closure)
                .map_err(|e| linker_err("sockets::udp", e))?;
            b::sockets::udp_create_socket::add_to_linker_get_host(l, closure)
                .map_err(|e| linker_err("sockets::udp_create_socket", e))?;
            b::sockets::instance_network::add_to_linker_get_host(l, closure)
                .map_err(|e| linker_err("sockets::instance_network", e))?;
            b::sockets::network::add_to_linker_get_host(l, closure)
                .map_err(|e| linker_err("sockets::network", e))?;
            b::sockets::ip_name_lookup::add_to_linker_get_host(l, closure)
                .map_err(|e| linker_err("sockets::ip_name_lookup", e))?;
        }
        // CIT-AGENT-9c-host: citrate:chain/eth-call. Two-layer
        // enforcement: the token in `permitted` means the host fn
        // is registered at all; the host fn closure consults the
        // per-call `to` address against the per-capsule allow-list
        // held by `HostCtx::eth_call_allow_list`. The allow-list
        // arrives via `Capsule::instantiate` populating the store
        // data — the linker itself doesn't see the addresses.
        if self.permitted.contains(&CapabilityToken::CitrateChainEthCall) {
            self.wire_citrate_chain_eth_call()?;
        }
        Ok(self)
    }

    /// Wire `citrate:chain/eth-call@0.1.0` into the linker. The host
    /// fn signature mirrors:
    /// ```wit
    /// interface eth-call {
    ///     call: func(to: list<u8>, data: list<u8>)
    ///         -> result<list<u8>, string>;
    /// }
    /// ```
    /// CIT-AGENT-9c-host.
    fn wire_citrate_chain_eth_call(&mut self) -> Result<(), AgentError> {
        let mut inst = self
            .linker
            .instance("citrate:chain/eth-call@0.1.0")
            .map_err(|e| linker_err("citrate:chain/eth-call@0.1.0 instance", e))?;
        inst.func_wrap(
            "call",
            |store: wasmtime::StoreContextMut<'_, HostCtx>,
             (to, _data): (Vec<u8>, Vec<u8>)|
             -> wasmtime::Result<(Result<Vec<u8>, String>,)> {
                if to.len() != 20 {
                    return Ok((Err(format!(
                        "ChainCallNotAuthorized: `to` must be 20 bytes, got {}",
                        to.len()
                    )),));
                }
                let mut addr: [u8; 20] = [0; 20];
                addr.copy_from_slice(&to);
                if !store.data().is_eth_call_authorized(&addr) {
                    return Ok((Err(format!(
                        "ChainCallNotAuthorized: 0x{}",
                        hex::encode(addr)
                    )),));
                }
                // CIT-AGENT-9c-host stub: deterministic empty response.
                // The first real RPC dispatch lands in CIT-AGENT-9c-1
                // when the first tool capsule needs live data.
                Ok((Ok(Vec::new()),))
            },
        )
        .map_err(|e| linker_err("citrate:chain/eth-call call func_wrap", e))?;
        Ok(())
    }

    /// Consume the builder, yielding the wasmtime `Linker` ready for
    /// instantiation.
    pub fn into_linker(self) -> Linker<HostCtx> {
        self.linker
    }
}

fn linker_err<E: std::fmt::Display>(family: &str, e: E) -> AgentError {
    AgentError::Capsule(format!("wasi {family} add_to_linker_get_host failed: {e}"))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::capsule::manifest::{
        CapabilitySet, CapsuleMetadata, DataClassDecl, OverlayDecl, ProcedureDecl,
        ProvenanceDecl, RiskDecl, RiskTier, SigningDecl, SigningTier,
    };
    use crate::capsule::wasm::EngineFactory;

    fn manifest_with(net: NetworkPolicy, fs: Vec<String>) -> Manifest {
        Manifest {
            capsule: CapsuleMetadata {
                name: "x".into(),
                version: "0.1.0".into(),
                content_hash: "sha256:".to_string() + &"0".repeat(64),
            },
            capability: CapabilitySet {
                network: net,
                filesystem: fs,
                chain_calls: vec![],
                subagent_spawn: false,
            },
            data_class: DataClassDecl {
                reads: vec![],
                writes: vec![],
                emits: vec![],
            },
            risk: RiskDecl {
                tier: RiskTier::Low,
                required_roles: vec![],
                break_glass_eligible: false,
            },
            overlay: OverlayDecl {
                certified: vec![],
                not_certified: vec![],
            },
            procedure: ProcedureDecl { gates: vec![] },
            provenance: ProvenanceDecl {
                publisher: "did:citrate:agent:0xab12".into(),
                build_reproducible: true,
                agentile_sprint: "test".into(),
                tla_spec: "".into(),
            },
            signing: SigningDecl {
                tier: SigningTier::Bundled,
            },
        }
    }

    #[test]
    fn empty_linker_permits_nothing() {
        let engine = EngineFactory::build().unwrap();
        let b = LinkerBuilder::empty(&engine);
        assert!(b.permitted().is_empty(), "empty linker has no permitted tokens");
    }

    #[test]
    fn network_none_omits_sockets() {
        let engine = EngineFactory::build().unwrap();
        let m = manifest_with(NetworkPolicy::None, vec![]);
        let b = LinkerBuilder::from_manifest(&engine, &m).expect("builds");
        assert!(!b.permitted().contains(&CapabilityToken::WasiSockets));
        assert!(!b.permitted().contains(&CapabilityToken::WasiFilesystem));
        // CLI/clocks/random always present.
        assert!(b.permitted().contains(&CapabilityToken::WasiCli));
        assert!(b.permitted().contains(&CapabilityToken::WasiClocks));
        assert!(b.permitted().contains(&CapabilityToken::WasiRandom));
    }

    #[test]
    fn network_egress_includes_sockets() {
        let engine = EngineFactory::build().unwrap();
        let m = manifest_with(NetworkPolicy::EgressAllowed, vec![]);
        let b = LinkerBuilder::from_manifest(&engine, &m).expect("builds");
        assert!(b.permitted().contains(&CapabilityToken::WasiSockets));
    }

    #[test]
    fn network_broker_only_includes_sockets() {
        let engine = EngineFactory::build().unwrap();
        let m = manifest_with(NetworkPolicy::BrokerOnly, vec![]);
        let b = LinkerBuilder::from_manifest(&engine, &m).expect("builds");
        assert!(b.permitted().contains(&CapabilityToken::WasiSockets));
    }

    #[test]
    fn filesystem_empty_omits_filesystem() {
        let engine = EngineFactory::build().unwrap();
        let m = manifest_with(NetworkPolicy::None, vec![]);
        let b = LinkerBuilder::from_manifest(&engine, &m).expect("builds");
        assert!(!b.permitted().contains(&CapabilityToken::WasiFilesystem));
    }

    #[test]
    fn filesystem_nonempty_includes_filesystem() {
        let engine = EngineFactory::build().unwrap();
        let m = manifest_with(NetworkPolicy::None, vec!["read:/data".into()]);
        let b = LinkerBuilder::from_manifest(&engine, &m).expect("builds");
        assert!(b.permitted().contains(&CapabilityToken::WasiFilesystem));
    }

    #[test]
    fn malformed_filesystem_entry_fails_construction() {
        let engine = EngineFactory::build().unwrap();
        let m = manifest_with(NetworkPolicy::None, vec!["exec:/bin/sh".into()]);
        let err =
            LinkerBuilder::from_manifest(&engine, &m).expect_err("bad fs entry fails");
        assert!(err.to_string().contains("exec"));
    }
}
