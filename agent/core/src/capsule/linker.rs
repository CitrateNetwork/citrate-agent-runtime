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
}

/// Placeholder for the per-capsule host context. CIT-AGENT-3d will
/// populate this with WasiCtx + ResourceTable + manifest-derived
/// filesystem allow-list. For 3c the linker is constructed against
/// an opaque host context so the type signature stabilizes.
pub struct HostCtx;

/// LinkerBuilder for the per-capsule wasmtime Linker. Starts empty;
/// the manifest constructor adds only what's declared.
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
        Ok(b)
    }

    /// Inspection accessor: which capability tokens are registered.
    /// Audit + test assertions use this.
    pub fn permitted(&self) -> &BTreeSet<CapabilityToken> {
        &self.permitted
    }

    /// Consume the builder, yielding the wasmtime `Linker` ready for
    /// instantiation. Real instantiation lands in CIT-AGENT-3d.
    pub fn into_linker(self) -> Linker<HostCtx> {
        self.linker
    }
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
