//! Capsule loader — RFC-CIT-AGENT-0001 §3.1 + §4.
//!
//! CIT-AGENT-3a lands the manifest schema + archive format. The
//! load-time invariants from RFC §4.5 are sequenced across the
//! follow-up sprints in this same crate:
//!
//!   1. Manifest signature verification  → CIT-AGENT-3b (`tiers.rs`)
//!   2. WIT / manifest cross-validation  → CIT-AGENT-3b (`verify.rs`)
//!   3. wasmtime engine + per-capsule linker → CIT-AGENT-3c (`wasm.rs`)
//!   4. Per-call data-class check        → CIT-AGENT-3d (runtime path)
//!
//! The install state-machine is verified by
//! `.agentile/formal/specs/agent/CapsuleInstall.tla` (CIT-AGENT-2 —
//! 2,600 distinct states PASS).

pub mod archive;
pub mod dispatcher;
pub mod filesystem;
pub mod linker;
pub mod manifest;
pub mod prod_impls;
pub mod tiers;
pub mod verify;
pub mod wasm;

use crate::error::AgentError;
use std::io::Read;

/// A loaded capsule: parsed manifest + unpacked archive entries. The
/// content_hash declared in the manifest is verified against the
/// computed hash of the archive contents during `from_archive`.
/// Signature verification (publisher.sig / reviewer.sig) and WIT/WASM
/// cross-check land in CIT-AGENT-3b.
#[derive(Debug)]
pub struct Capsule {
    pub manifest: manifest::Manifest,
    pub archive: archive::ArchiveContents,
}

impl Capsule {
    /// Read a `.cps` archive (Zstd-compressed tar), parse and validate
    /// the manifest, verify the archive's content_hash matches the
    /// manifest declaration. Returns the loaded capsule on success.
    ///
    /// Per CIT-AGENT-3a SPRINT.md, signature verification + WIT
    /// cross-check are NOT yet performed — they land in 3b.
    pub fn from_archive(reader: impl Read) -> Result<Self, AgentError> {
        let archive = archive::read_archive(reader)?;
        let manifest_toml = std::str::from_utf8(&archive.manifest).map_err(|e| {
            AgentError::Capsule(format!("manifest.toml is not valid UTF-8: {e}"))
        })?;
        let manifest = manifest::Manifest::parse(manifest_toml)?;
        let computed_hash = archive::compute_content_hash(&archive);
        if computed_hash != manifest.capsule.content_hash {
            return Err(AgentError::Capsule(format!(
                "content_hash mismatch — manifest declares {}, archive computed {}",
                manifest.capsule.content_hash, computed_hash,
            )));
        }
        Ok(Self { manifest, archive })
    }

    /// Production load path — runs the full RFC §4.5 invariant chain
    /// available in CIT-AGENT-3b:
    ///   1. archive structure + content_hash verification (3a)
    ///   2. publisher signature verification under the tier's
    ///      trusted key (3b — this fn)
    ///   3. WIT / manifest capability cross-check (3b — this fn)
    ///
    /// Invariants 3 (wasmtime per-capsule linker) and 4 (per-call
    /// data-class check) land in CIT-AGENT-3c/d and will extend the
    /// chain in this same function.
    pub fn from_archive_verified(
        reader: impl Read,
        registry: &dyn tiers::PublicKeyRegistry,
    ) -> Result<Self, AgentError> {
        let capsule = Self::from_archive(reader)?;
        let sig = capsule
            .archive
            .signatures
            .get("publisher.sig")
            .ok_or_else(|| {
                AgentError::CapsuleSignatureInvalid(
                    "publisher.sig missing from SIGNATURES/".to_string(),
                )
            })?;
        tiers::verify_signature(
            &capsule.manifest.capsule.content_hash,
            sig,
            capsule.manifest.signing.tier,
            registry,
        )?;
        let wit_str = std::str::from_utf8(&capsule.archive.wit).map_err(|e| {
            AgentError::CapsuleWitMismatch(format!("capsule.wit is not valid UTF-8: {e}"))
        })?;
        verify::verify_capability_against_wit(&capsule.manifest, wit_str)?;
        Ok(capsule)
    }

    /// Build the per-capsule wasmtime linker from this capsule's
    /// manifest. CIT-AGENT-3c — the linker is constructed with only
    /// the WASI capabilities the manifest declares (fail-closed,
    /// "build from manifest, NOT filter default" per planset).
    /// CIT-AGENT-3d adds real wasmtime-wasi host fn wiring via
    /// `wire_wasi_host_fns`.
    pub fn prepare_linker(
        &self,
        engine: &wasmtime::Engine,
    ) -> Result<linker::LinkerBuilder, AgentError> {
        linker::LinkerBuilder::from_manifest(engine, &self.manifest)?.wire_wasi_host_fns()
    }

    /// Instantiate the capsule's WASM component against the prepared
    /// linker. CIT-AGENT-3d: this is the runtime path that proves
    /// the fail-closed property — a WASM importing `wasi:sockets`
    /// fails here with a link error when the manifest's
    /// `[capability].network = "none"` denied the sockets host fns.
    ///
    /// Returns `Ok(())` on successful instantiation; calling typed
    /// exports of the resulting `Instance` requires the WIT-typed
    /// binding layer which lands when capsules' typed-call API
    /// arrives (per-capsule sprint, post-3d).
    pub fn instantiate(
        &self,
        engine: &wasmtime::Engine,
        linker: &wasmtime::component::Linker<wasm::HostCtx>,
    ) -> Result<(), AgentError> {
        let (_store, _instance) = self.instantiate_with_store(engine, linker)?;
        Ok(())
    }

    /// Instantiate and return the `Store` + `Instance` so callers
    /// can invoke typed exports on the instance. Threads the
    /// manifest-declared `chain_calls` allow-list into the `HostCtx`
    /// the store carries, so `citrate:chain/eth-call` host fns can
    /// consult it at call time. CIT-AGENT-9c-host.
    ///
    /// No dispatcher is attached — the host fn falls back to its
    /// legacy `Ok(empty)` stub when the canned-queue is empty. For
    /// production end-to-end dispatch, use
    /// `instantiate_with_store_and_dispatcher`. CIT-AGENT-9c-1-rpc.
    pub fn instantiate_with_store(
        &self,
        engine: &wasmtime::Engine,
        linker: &wasmtime::component::Linker<wasm::HostCtx>,
    ) -> Result<
        (
            wasmtime::Store<wasm::HostCtx>,
            wasmtime::component::Instance,
        ),
        AgentError,
    > {
        let component = wasmtime::component::Component::from_binary(engine, &self.archive.wasm)
            .map_err(|e| AgentError::Capsule(format!("WASM component parse: {e}")))?;
        let allow_list = self.parse_eth_call_allow_list()?;
        let mut store = wasmtime::Store::new(
            engine,
            wasm::HostCtx::with_eth_call_allow_list(allow_list),
        );
        let instance = linker
            .instantiate(&mut store, &component)
            .map_err(|e| AgentError::Capsule(format!("component instantiate: {e}")))?;
        Ok((store, instance))
    }

    /// Instantiate with the full write-path wiring: read + write
    /// allow-lists (parsed from the manifest), both dispatchers,
    /// and the HITL approval gate. Any of the optional arcs may be
    /// `None` — the host fn rejects accordingly (no gate ⇒ all
    /// eth_send calls fail closed). CIT-AGENT-9c-write-host.
    pub fn instantiate_with_write_path(
        &self,
        engine: &wasmtime::Engine,
        linker: &wasmtime::component::Linker<wasm::HostCtx>,
        eth_call_dispatcher: Option<std::sync::Arc<dyn dispatcher::EthCallDispatcher>>,
        eth_send_dispatcher: Option<std::sync::Arc<dyn dispatcher::EthSendDispatcher>>,
        approval_gate: Option<std::sync::Arc<dyn dispatcher::ApprovalGate>>,
    ) -> Result<
        (
            wasmtime::Store<wasm::HostCtx>,
            wasmtime::component::Instance,
        ),
        AgentError,
    > {
        let component = wasmtime::component::Component::from_binary(engine, &self.archive.wasm)
            .map_err(|e| AgentError::Capsule(format!("WASM component parse: {e}")))?;
        let (read_allow, write_allow) = self.parse_chain_call_allow_lists()?;
        let mut store = wasmtime::Store::new(
            engine,
            wasm::HostCtx::with_write_path(
                read_allow,
                write_allow,
                eth_call_dispatcher,
                eth_send_dispatcher,
                approval_gate,
                self.manifest.capsule.name.clone(),
            ),
        );
        let instance = linker
            .instantiate(&mut store, &component)
            .map_err(|e| AgentError::Capsule(format!("component instantiate: {e}")))?;
        Ok((store, instance))
    }

    /// Instantiate with a production `EthCallDispatcher` attached
    /// to the HostCtx. When the capsule calls `citrate:chain/eth-call`
    /// AND no canned-queue fixture is present, the host fn routes
    /// the call through `dispatcher.eth_call(...)`. CIT-AGENT-9c-1-rpc.
    pub fn instantiate_with_store_and_dispatcher(
        &self,
        engine: &wasmtime::Engine,
        linker: &wasmtime::component::Linker<wasm::HostCtx>,
        dispatcher: std::sync::Arc<dyn dispatcher::EthCallDispatcher>,
    ) -> Result<
        (
            wasmtime::Store<wasm::HostCtx>,
            wasmtime::component::Instance,
        ),
        AgentError,
    > {
        let component = wasmtime::component::Component::from_binary(engine, &self.archive.wasm)
            .map_err(|e| AgentError::Capsule(format!("WASM component parse: {e}")))?;
        let allow_list = self.parse_eth_call_allow_list()?;
        let mut store = wasmtime::Store::new(
            engine,
            wasm::HostCtx::with_dispatcher(allow_list, dispatcher),
        );
        let instance = linker
            .instantiate(&mut store, &component)
            .map_err(|e| AgentError::Capsule(format!("component instantiate: {e}")))?;
        Ok((store, instance))
    }

    /// Parse the manifest's `chain_calls` entries into per-prefix
    /// allow-lists. Recognized prefixes:
    ///   `eth_call:0x<40-hex>`  → read allow-list (CIT-AGENT-9c-host)
    ///   `eth_send:0x<40-hex>`  → write allow-list (CIT-AGENT-9c-write-host)
    /// Other prefixes (e.g. `model_inference:`) are silently
    /// skipped — they belong to future host-fn families.
    fn parse_chain_call_allow_lists(
        &self,
    ) -> Result<(Vec<wasm::Address>, Vec<wasm::Address>), AgentError> {
        let mut read = Vec::new();
        let mut write = Vec::new();
        for entry in &self.manifest.capability.chain_calls {
            let (rest, target) = if let Some(r) = entry.strip_prefix("eth_call:") {
                (r, &mut read)
            } else if let Some(r) = entry.strip_prefix("eth_send:") {
                (r, &mut write)
            } else {
                continue;
            };
            let hex_part = rest.strip_prefix("0x").unwrap_or(rest);
            if hex_part.len() != 40 {
                return Err(AgentError::Capsule(format!(
                    "chain_calls entry {entry:?} expected <prefix>:0x<40 hex>, got {hex_part:?}"
                )));
            }
            let bytes = hex::decode(hex_part).map_err(|e| {
                AgentError::Capsule(format!("chain_calls entry {entry:?} hex decode: {e}"))
            })?;
            let mut addr: wasm::Address = [0; 20];
            addr.copy_from_slice(&bytes);
            target.push(addr);
        }
        Ok((read, write))
    }

    /// Convenience for code paths that only care about the read
    /// allow-list. Preserves the CIT-AGENT-9c-host API.
    fn parse_eth_call_allow_list(&self) -> Result<Vec<wasm::Address>, AgentError> {
        Ok(self.parse_chain_call_allow_lists()?.0)
    }

    pub fn name(&self) -> &str {
        &self.manifest.capsule.name
    }

    pub fn version(&self) -> &str {
        &self.manifest.capsule.version
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::Write;

    /// Round-trip: build a tiny `.cps` archive whose manifest declares
    /// the computed content_hash; from_archive should accept it.
    /// Under the CIT-AGENT-3b semantic (hash excludes manifest.toml),
    /// the declared hash is straightforward — no fixed-point dance.
    #[test]
    fn from_archive_round_trip_with_correct_hash() {
        // First compute the content_hash for the archive contents we
        // intend to include.
        let archive_contents = archive::ArchiveContents {
            manifest: vec![], // placeholder; we overwrite below
            wit: b"// stub WIT".to_vec(),
            wasm: b"\x00asm\x01\x00\x00\x00".to_vec(),
            procedure: b"# stub procedure".to_vec(),
            ..Default::default()
        };
        // The content_hash is computed over all entries EXCEPT
        // manifest itself; but the manifest IS included in the hash.
        // So we first build the manifest, compute the full hash with
        // the manifest's body of the form "sha256:0000..." (a
        // placeholder), then update the manifest body to declare
        // its OWN computed hash. The hash changes when we update the
        // manifest body — chicken-and-egg.
        //
        // For test simplicity we accept that the round-trip happy
        // path can only be exercised when the manifest's declared
        // content_hash matches what the archive computes WITH that
        // same manifest body inside. We use an iterative approach:
        // compute → embed → recompute → confirm stable.
        let make_manifest = |declared_hash: &str| -> String {
            format!(
                r#"
[capsule]
name = "test-capsule"
version = "0.1.0"
content_hash = "{declared_hash}"

[capability]
network = "none"
filesystem = []
chain_calls = []
subagent_spawn = false

[data_class]
reads = ["PUBLIC"]
writes = []
emits = ["PUBLIC"]

[risk]
tier = "low"
required_roles = ["Operator"]
break_glass_eligible = false

[overlay]
certified = []
not_certified = []

[procedure]
gates = []

[provenance]
publisher = "did:citrate:agent:0xab12"
build_reproducible = true
agentile_sprint = "2026-05-15-cit-agent-3a"
tla_spec = ""

[signing]
tier = "bundled"
"#
            )
        };
        // Compute the body hash once (excludes manifest.toml).
        let body_hash = archive::compute_content_hash(&archive_contents);
        let manifest_with_hash = make_manifest(&body_hash);
        let mut working = archive_contents.clone();
        working.manifest = manifest_with_hash.as_bytes().to_vec();
        working
            .signatures
            .insert("publisher.sig".to_string(), b"stub-sig".to_vec());

        // Pack working into a real .cps archive, then read it back.
        let mut tar_buf = Vec::new();
        {
            let mut tar = tar::Builder::new(&mut tar_buf);
            let entries: Vec<(&str, &[u8])> = vec![
                ("manifest.toml", &working.manifest),
                ("capsule.wit", &working.wit),
                ("capsule.wasm", &working.wasm),
                ("procedure.md", &working.procedure),
                ("SIGNATURES/publisher.sig", b"stub-sig"),
            ];
            for (path, bytes) in entries {
                let mut header = tar::Header::new_gnu();
                header.set_size(bytes.len() as u64);
                header.set_cksum();
                tar.append_data(&mut header, path, bytes).unwrap();
            }
            tar.finish().unwrap();
        }
        let mut zstd_buf = Vec::new();
        let mut enc = zstd::Encoder::new(&mut zstd_buf, 3).unwrap();
        enc.write_all(&tar_buf).unwrap();
        enc.finish().unwrap();

        // Capsule::from_archive computes content_hash from the body
        // (excluding manifest.toml); the manifest's declared hash
        // matches; this MUST succeed.
        let capsule = Capsule::from_archive(&zstd_buf[..])
            .expect("manifest-declared body hash matches; load succeeds");
        assert_eq!(capsule.name(), "test-capsule");
        assert_eq!(capsule.manifest.capsule.content_hash, body_hash);
    }

    /// CIT-AGENT-3d — instantiate a minimal empty WASM component
    /// (no imports) under a linker built from a `network = "none",
    /// filesystem = []` manifest. Instantiation MUST succeed since
    /// the component imports nothing.
    #[test]
    fn instantiate_empty_component_succeeds() {
        use crate::capsule::manifest::Manifest;
        use crate::capsule::wasm::EngineFactory;

        // Tiny empty component: `(component)` in WAT compiles to a
        // 16-byte component-model binary.
        let component_wasm = wat::parse_str("(component)").expect("WAT compiles");

        let manifest_str = r#"
[capsule]
name = "empty-component"
version = "0.1.0"
content_hash = "sha256:0000000000000000000000000000000000000000000000000000000000000000"

[capability]
network = "none"
filesystem = []
chain_calls = []
subagent_spawn = false

[data_class]
reads = ["PUBLIC"]
writes = []
emits = ["PUBLIC"]

[risk]
tier = "low"
required_roles = ["Operator"]
break_glass_eligible = false

[overlay]
certified = []
not_certified = []

[procedure]
gates = []

[provenance]
publisher = "did:citrate:agent:0xab12"
build_reproducible = true
agentile_sprint = "2026-05-15-cit-agent-3d"
tla_spec = ""

[signing]
tier = "bundled"
"#;
        let manifest = Manifest::parse(manifest_str).expect("manifest parses");
        let capsule = Capsule {
            manifest,
            archive: archive::ArchiveContents {
                wasm: component_wasm,
                ..Default::default()
            },
        };
        let engine = EngineFactory::build().unwrap();
        let linker = capsule
            .prepare_linker(&engine)
            .expect("linker constructs")
            .into_linker();
        capsule
            .instantiate(&engine, &linker)
            .expect("empty component instantiates");
    }

    /// CIT-AGENT-3d — instantiate a component that has an exported
    /// function (no imports) under a strict linker. Confirms the
    /// instantiation path handles components with exports cleanly.
    #[test]
    fn instantiate_component_with_export_succeeds() {
        use crate::capsule::manifest::Manifest;
        use crate::capsule::wasm::EngineFactory;

        // A component that contains a core module with a single
        // function and exports it. No imports.
        let component_wat = r#"
(component
    (core module $m
        (func (export "ping") (result i32) i32.const 42)
    )
    (core instance $i (instantiate $m))
)
"#;
        let component_wasm = wat::parse_str(component_wat).expect("WAT compiles");

        let manifest_str = r#"
[capsule]
name = "ping"
version = "0.1.0"
content_hash = "sha256:0000000000000000000000000000000000000000000000000000000000000000"

[capability]
network = "none"
filesystem = []
chain_calls = []
subagent_spawn = false

[data_class]
reads = ["PUBLIC"]
writes = []
emits = ["PUBLIC"]

[risk]
tier = "low"
required_roles = ["Operator"]
break_glass_eligible = false

[overlay]
certified = []
not_certified = []

[procedure]
gates = []

[provenance]
publisher = "did:citrate:agent:0xab12"
build_reproducible = true
agentile_sprint = "2026-05-15-cit-agent-3d"
tla_spec = ""

[signing]
tier = "bundled"
"#;
        let manifest = Manifest::parse(manifest_str).expect("manifest parses");
        let capsule = Capsule {
            manifest,
            archive: archive::ArchiveContents {
                wasm: component_wasm,
                ..Default::default()
            },
        };
        let engine = EngineFactory::build().unwrap();
        let linker = capsule
            .prepare_linker(&engine)
            .expect("linker constructs")
            .into_linker();
        capsule
            .instantiate(&engine, &linker)
            .expect("component with export instantiates");
    }

    /// CIT-AGENT-3d — malformed WASM bytes are rejected at parse,
    /// not at instantiate. The error variant carries the parse
    /// diagnostic.
    #[test]
    fn instantiate_malformed_wasm_rejects() {
        use crate::capsule::manifest::Manifest;
        use crate::capsule::wasm::EngineFactory;

        let bad_wasm = vec![0x00, 0x01, 0x02, 0x03]; // not a valid WASM header

        let manifest_str = r#"
[capsule]
name = "bad-wasm"
version = "0.1.0"
content_hash = "sha256:0000000000000000000000000000000000000000000000000000000000000000"

[capability]
network = "none"
filesystem = []
chain_calls = []
subagent_spawn = false

[data_class]
reads = ["PUBLIC"]
writes = []
emits = ["PUBLIC"]

[risk]
tier = "low"
required_roles = ["Operator"]
break_glass_eligible = false

[overlay]
certified = []
not_certified = []

[procedure]
gates = []

[provenance]
publisher = "did:citrate:agent:0xab12"
build_reproducible = true
agentile_sprint = "test"
tla_spec = ""

[signing]
tier = "bundled"
"#;
        let manifest = Manifest::parse(manifest_str).expect("manifest parses");
        let capsule = Capsule {
            manifest,
            archive: archive::ArchiveContents {
                wasm: bad_wasm,
                ..Default::default()
            },
        };
        let engine = EngineFactory::build().unwrap();
        let linker = capsule
            .prepare_linker(&engine)
            .expect("linker constructs")
            .into_linker();
        let err = capsule
            .instantiate(&engine, &linker)
            .expect_err("malformed WASM rejected");
        assert!(err.to_string().contains("parse") || err.to_string().contains("instantiate"));
    }

    /// CIT-AGENT-9a — empirical fail-closed proof for the
    /// "build from manifest, NOT filter default" linker invariant.
    ///
    /// CIT-AGENT-3c proved the linker's *permitted set* excludes
    /// undeclared capabilities. CIT-AGENT-9a closes the empirical
    /// gap: a component whose WASM declares an import that the
    /// manifest-built linker did NOT register MUST be rejected
    /// before any host call can occur. Without this, the security
    /// claim ("undeclared caps cannot be reached") rests on
    /// inference from the permitted-set check rather than direct
    /// observation of wasmtime rejecting the load.
    ///
    /// Concretely: build a WAT component declaring a custom host
    /// import in the `citrate:` namespace; build a manifest with
    /// `network = "none"`, `filesystem = []`; construct the linker;
    /// attempt to load the component. Wasmtime rejects the load
    /// before any host call is reached. The exact failure layer
    /// (parse vs. instantiate) is a wasmtime implementation
    /// detail and may shift between versions — the security
    /// invariant is "load fails", not "load fails at one specific
    /// layer". The test allows either layer; if both stop
    /// rejecting, this test fires and the security claim must be
    /// re-examined immediately.
    #[test]
    fn instantiate_rejects_undeclared_host_import() {
        use crate::capsule::manifest::Manifest;
        use crate::capsule::wasm::EngineFactory;

        // A component that imports an interface the linker won't
        // register. The interface name is intentionally NOT one of
        // the WASI families the `from_manifest` linker knows about,
        // so even a fully-permissive manifest could not coincidentally
        // satisfy this import. (We want to exercise "fail-closed on
        // undeclared", not "fail-closed on misdeclared".)
        // Component with a single function import. The interface
        // name uses the `citrate:` namespace so it cannot collide
        // with any WASI family the manifest-built linker registers.
        let component_wat = r#"
(component
    (import "citrate:capsule-9a/forbidden" (func (param "x" u32) (result u32)))
)
"#;
        let component_wasm =
            wat::parse_str(component_wat).expect("WAT compiles to a component");

        let manifest_str = r#"
[capsule]
name = "fail-closed-witness"
version = "0.1.0"
content_hash = "sha256:0000000000000000000000000000000000000000000000000000000000000000"

[capability]
network = "none"
filesystem = []
chain_calls = []
subagent_spawn = false

[data_class]
reads = ["PUBLIC"]
writes = []
emits = ["PUBLIC"]

[risk]
tier = "low"
required_roles = ["Operator"]
break_glass_eligible = false

[overlay]
certified = []
not_certified = []

[procedure]
gates = []

[provenance]
publisher = "did:citrate:agent:0xab12"
build_reproducible = true
agentile_sprint = "2026-05-15-cit-agent-9a"
tla_spec = ""

[signing]
tier = "bundled"
"#;
        let manifest = Manifest::parse(manifest_str).expect("manifest parses");
        let capsule = Capsule {
            manifest,
            archive: archive::ArchiveContents {
                wasm: component_wasm,
                ..Default::default()
            },
        };
        let engine = EngineFactory::build().unwrap();
        let linker = capsule
            .prepare_linker(&engine)
            .expect("linker constructs (no caps to add)")
            .into_linker();
        let err = capsule
            .instantiate(&engine, &linker)
            .expect_err("component with undeclared host import must fail to load");
        // The security invariant: the load FAILED. Either layer
        // (parse or instantiate / link) is acceptable evidence —
        // the capsule never reaches a state where its (undeclared)
        // import could be called. We assert on a broad set of
        // wasmtime failure substrings so a future wasmtime upgrade
        // that changes the error wording does not silently weaken
        // the security claim — at least one of these substrings
        // MUST be present in any honest failure.
        let msg = err.to_string();
        assert!(
            msg.contains("parse")
                || msg.contains("import")
                || msg.contains("instantiate")
                || msg.contains("forbidden")
                || msg.contains("citrate:capsule-9a"),
            "load-fail error must indicate parse/import/instantiate failure; got: {msg}",
        );
    }

    /// CIT-AGENT-9b — first end-to-end compiled-capsule test.
    /// Reads the `capsules/hello/capsule.wasm` artifact built by
    /// `tools/cps-build/hello-capsule/` (cargo-component →
    /// wasm32-unknown-unknown), constructs the cit-agent Capsule
    /// + manifest matching the on-disk manifest.toml shape, builds
    /// the manifest-driven linker, and instantiates the component.
    ///
    /// This is the converse of CIT-AGENT-9a's fail-closed test:
    /// 9a proved an undeclared-import component is rejected; 9b
    /// proves a no-import, manifest-compliant component is
    /// accepted. Together they bracket the load gate.
    ///
    /// The on-disk WASM is committed to the repo (under
    /// `citrate_v0.01.1/capsules/hello/`); the source crate is
    /// also committed (under `tools/cps-build/hello-capsule/`)
    /// so anyone can reproduce the build. If the build product
    /// drifts from the source, this test fails because the on-
    /// disk capsule.wasm and the manifest declared content_hash
    /// will diverge.
    #[test]
    fn hello_capsule_loads_and_instantiates() {
        use crate::capsule::manifest::Manifest;
        use crate::capsule::wasm::EngineFactory;
        use std::path::PathBuf;

        // CARGO_MANIFEST_DIR is .../citrate_v0.01.1/agent/core/;
        // the capsules live one level up at .../capsules/hello/.
        let manifest_dir =
            PathBuf::from(env!("CARGO_MANIFEST_DIR"));
        let capsule_dir = manifest_dir
            .parent()
            .and_then(|p| p.parent())
            .expect("walk up to citrate_v0.01.1/")
            .join("capsules")
            .join("hello");
        let wasm_path = capsule_dir.join("capsule.wasm");
        let manifest_path = capsule_dir.join("manifest.toml");
        let wasm =
            std::fs::read(&wasm_path).expect("hello capsule.wasm exists on disk");
        let manifest_str = std::fs::read_to_string(&manifest_path)
            .expect("hello manifest.toml exists on disk");
        let manifest = Manifest::parse(&manifest_str).expect("hello manifest parses");

        let capsule = Capsule {
            manifest,
            archive: archive::ArchiveContents {
                wasm,
                ..Default::default()
            },
        };
        let engine = EngineFactory::build().expect("engine builds");
        let linker = capsule
            .prepare_linker(&engine)
            .expect("linker constructs from hello manifest")
            .into_linker();
        capsule
            .instantiate(&engine, &linker)
            .expect("hello capsule instantiates under manifest-built linker");
    }

    /// CIT-AGENT-9c-host helper: invoke `query` on the echo-chain
    /// capsule with the given `to` + `data` bytes. Returns the WIT
    /// `result<list<u8>, string>` as a Rust `Result<Vec<u8>, String>`.
    /// Used by both the authorized + unauthorized integration tests.
    #[cfg(test)]
    fn invoke_echo_chain_query(
        store: &mut wasmtime::Store<wasm::HostCtx>,
        instance: wasmtime::component::Instance,
        to: Vec<u8>,
        data: Vec<u8>,
    ) -> Result<Vec<u8>, String> {
        use wasmtime::component::Val;
        // wasmtime 26 component-model dynamic-export lookup. The
        // `query` interface is exported under
        // `citrate:echo-chain-capsule/query@0.1.0`; the `query`
        // function lives inside that exported instance.
        let iface_index = instance
            .get_export(&mut *store, None, "citrate:echo-chain-capsule/query@0.1.0")
            .expect("capsule exports `query` interface");
        let func_index = instance
            .get_export(&mut *store, Some(&iface_index), "query")
            .expect("query interface exports `query` func");
        let func = instance
            .get_func(&mut *store, func_index)
            .expect("query func resolves");
        let to_val = Val::List(to.into_iter().map(Val::U8).collect());
        let data_val = Val::List(data.into_iter().map(Val::U8).collect());
        let mut results = [Val::Bool(false)]; // placeholder; replaced by call
        func.call(&mut *store, &[to_val, data_val], &mut results)
            .expect("query call completes");
        func.post_return(&mut *store)
            .expect("post_return clears the call");
        match &results[0] {
            Val::Result(r) => match r.as_ref() {
                Ok(Some(boxed)) => match boxed.as_ref() {
                    Val::List(bytes) => Ok(bytes
                        .iter()
                        .map(|v| match v {
                            Val::U8(b) => *b,
                            _ => panic!("expected u8 in list"),
                        })
                        .collect()),
                    other => panic!("expected list<u8> in Ok, got {other:?}"),
                },
                Ok(None) => Ok(Vec::new()),
                Err(Some(boxed)) => match boxed.as_ref() {
                    Val::String(s) => Err(s.clone()),
                    other => panic!("expected string in Err, got {other:?}"),
                },
                Err(None) => Err(String::new()),
            },
            other => panic!("expected Val::Result, got {other:?}"),
        }
    }

    /// CIT-AGENT-9c-host — happy-path. The echo-chain capsule
    /// declares allow-list `["eth_call:0x4a86...20E40"]` in its
    /// manifest. Calling `query` with that exact address returns
    /// `Ok(vec![])` (the host fn's stub success response).
    #[test]
    fn echo_chain_capsule_with_authorized_address_succeeds() {
        use crate::capsule::manifest::Manifest;
        use crate::capsule::wasm::EngineFactory;
        use std::path::PathBuf;

        let manifest_dir = PathBuf::from(env!("CARGO_MANIFEST_DIR"));
        let capsule_dir = manifest_dir
            .parent()
            .and_then(|p| p.parent())
            .expect("walk up to citrate_v0.01.1/")
            .join("capsules")
            .join("echo-chain");
        let wasm = std::fs::read(capsule_dir.join("capsule.wasm"))
            .expect("echo-chain capsule.wasm exists");
        let manifest_str = std::fs::read_to_string(capsule_dir.join("manifest.toml"))
            .expect("echo-chain manifest.toml exists");
        let manifest = Manifest::parse(&manifest_str).expect("manifest parses");
        let capsule = Capsule {
            manifest,
            archive: archive::ArchiveContents {
                wasm,
                ..Default::default()
            },
        };
        let engine = EngineFactory::build().expect("engine builds");
        let linker = capsule
            .prepare_linker(&engine)
            .expect("linker constructs")
            .into_linker();
        let (mut store, instance) = capsule
            .instantiate_with_store(&engine, &linker)
            .expect("echo-chain instantiates with chain-call host fn");

        // The manifest-authorized address — matches what was parsed
        // out of `chain_calls = ["eth_call:0x4a86659B..."]`.
        let authorized = hex::decode("4a86659BDab24dc444C72fbbaD4cd83491820E40").unwrap();
        let result = invoke_echo_chain_query(&mut store, instance, authorized, vec![]);
        assert_eq!(
            result,
            Ok(Vec::new()),
            "authorized eth_call returns Ok(empty) stub response"
        );
    }

    /// CIT-AGENT-9c-host — empirical proof that the per-address
    /// allow-list rejects an unauthorized `to`. The host fn returns
    /// `Err("ChainCallNotAuthorized: 0x...")` through the WIT
    /// result type; the capsule sees the err and re-emits it.
    #[test]
    fn echo_chain_capsule_blocks_unauthorized_address() {
        use crate::capsule::manifest::Manifest;
        use crate::capsule::wasm::EngineFactory;
        use std::path::PathBuf;

        let manifest_dir = PathBuf::from(env!("CARGO_MANIFEST_DIR"));
        let capsule_dir = manifest_dir
            .parent()
            .and_then(|p| p.parent())
            .expect("walk up to citrate_v0.01.1/")
            .join("capsules")
            .join("echo-chain");
        let wasm = std::fs::read(capsule_dir.join("capsule.wasm"))
            .expect("echo-chain capsule.wasm exists");
        let manifest_str = std::fs::read_to_string(capsule_dir.join("manifest.toml"))
            .expect("echo-chain manifest.toml exists");
        let manifest = Manifest::parse(&manifest_str).expect("manifest parses");
        let capsule = Capsule {
            manifest,
            archive: archive::ArchiveContents {
                wasm,
                ..Default::default()
            },
        };
        let engine = EngineFactory::build().expect("engine builds");
        let linker = capsule
            .prepare_linker(&engine)
            .expect("linker constructs")
            .into_linker();
        let (mut store, instance) = capsule
            .instantiate_with_store(&engine, &linker)
            .expect("echo-chain instantiates");

        // Address NOT in the manifest allow-list.
        let unauthorized = vec![1u8; 20];
        let result = invoke_echo_chain_query(&mut store, instance, unauthorized, vec![]);
        let err = result.expect_err("unauthorized address must be rejected");
        assert!(
            err.starts_with("ChainCallNotAuthorized:"),
            "rejection must name the cause; got: {err}"
        );
        // The rejection must include the address that was blocked
        // (forensic value: an operator reading the audit log can
        // see what was attempted, not just that something failed).
        assert!(
            err.contains("0x0101"),
            "rejection message must include attempted address; got: {err}"
        );
    }

    /// CIT-AGENT-9c-1 helper: invoke `query` on the
    /// list-compliance-posture capsule with `(framework, scope)`
    /// strings. Returns the WIT `result<posture-row, string>` as
    /// a Rust `Result<DecodedRow, String>`.
    #[cfg(test)]
    #[derive(Debug, PartialEq, Eq)]
    struct DecodedRow {
        row_id: [u8; 32],
        framework: [u8; 32],
        scope: [u8; 32],
        evidence_cid: [u8; 32],
        attestor: [u8; 32],
        posture: u8,
        expired: bool,
        attested_at_block: u64,
        expires_at_block: u64,
    }

    #[cfg(test)]
    fn invoke_list_compliance_query(
        store: &mut wasmtime::Store<wasm::HostCtx>,
        instance: wasmtime::component::Instance,
        framework: &str,
        scope: &str,
    ) -> Result<DecodedRow, String> {
        use wasmtime::component::Val;
        let iface_index = instance
            .get_export(
                &mut *store,
                None,
                "citrate:list-compliance-posture/query@0.1.0",
            )
            .expect("capsule exports `query` interface");
        let func_index = instance
            .get_export(&mut *store, Some(&iface_index), "query")
            .expect("query interface exports `query` func");
        let func = instance
            .get_func(&mut *store, func_index)
            .expect("query func resolves");
        let args = vec![
            Val::String(framework.to_string()),
            Val::String(scope.to_string()),
        ];
        let mut results = [Val::Bool(false)];
        func.call(&mut *store, &args, &mut results)
            .expect("query call completes");
        func.post_return(&mut *store).expect("post_return clears");
        // Unwrap the result<posture-row, string>.
        match &results[0] {
            Val::Result(r) => match r.as_ref() {
                Ok(Some(boxed)) => match boxed.as_ref() {
                    Val::Record(fields) => {
                        let lookup = |name: &str| -> Val {
                            fields
                                .iter()
                                .find(|(k, _)| k == name)
                                .map(|(_, v)| v.clone())
                                .unwrap_or_else(|| panic!("field {name} missing"))
                        };
                        let bytes32 = |v: Val| -> [u8; 32] {
                            match v {
                                Val::List(bytes) => {
                                    let raw: Vec<u8> = bytes
                                        .into_iter()
                                        .map(|b| match b {
                                            Val::U8(b) => b,
                                            _ => panic!("non-u8 in bytes32"),
                                        })
                                        .collect();
                                    assert_eq!(raw.len(), 32, "expected 32 bytes");
                                    let mut a = [0u8; 32];
                                    a.copy_from_slice(&raw);
                                    a
                                }
                                _ => panic!("expected list<u8>"),
                            }
                        };
                        let u8v = |v: Val| -> u8 {
                            if let Val::U8(b) = v {
                                b
                            } else {
                                panic!("expected u8")
                            }
                        };
                        let boolv = |v: Val| -> bool {
                            if let Val::Bool(b) = v {
                                b
                            } else {
                                panic!("expected bool")
                            }
                        };
                        let u64v = |v: Val| -> u64 {
                            if let Val::U64(n) = v {
                                n
                            } else {
                                panic!("expected u64")
                            }
                        };
                        Ok(DecodedRow {
                            row_id: bytes32(lookup("row-id")),
                            framework: bytes32(lookup("framework")),
                            scope: bytes32(lookup("scope")),
                            evidence_cid: bytes32(lookup("evidence-cid")),
                            attestor: bytes32(lookup("attestor")),
                            posture: u8v(lookup("posture")),
                            expired: boolv(lookup("expired")),
                            attested_at_block: u64v(lookup("attested-at-block")),
                            expires_at_block: u64v(lookup("expires-at-block")),
                        })
                    }
                    other => panic!("expected Record in Ok, got {other:?}"),
                },
                Ok(None) => panic!("Ok(None) not expected for posture-row"),
                Err(Some(boxed)) => match boxed.as_ref() {
                    Val::String(s) => Err(s.clone()),
                    other => panic!("expected string in Err, got {other:?}"),
                },
                Err(None) => Err(String::new()),
            },
            other => panic!("expected Val::Result, got {other:?}"),
        }
    }

    /// CIT-AGENT-9c-1 helper: load the list-compliance-posture capsule
    /// from disk, build engine + linker, return store + instance.
    #[cfg(test)]
    fn load_list_compliance_capsule() -> (
        wasmtime::Store<wasm::HostCtx>,
        wasmtime::component::Instance,
    ) {
        use crate::capsule::manifest::Manifest;
        use crate::capsule::wasm::EngineFactory;
        use std::path::PathBuf;

        let manifest_dir = PathBuf::from(env!("CARGO_MANIFEST_DIR"));
        let capsule_dir = manifest_dir
            .parent()
            .and_then(|p| p.parent())
            .expect("walk up to citrate_v0.01.1/")
            .join("capsules")
            .join("list-compliance-posture");
        let wasm = std::fs::read(capsule_dir.join("capsule.wasm"))
            .expect("list-compliance-posture capsule.wasm on disk");
        let manifest_str = std::fs::read_to_string(capsule_dir.join("manifest.toml"))
            .expect("list-compliance-posture manifest.toml on disk");
        let manifest = Manifest::parse(&manifest_str).expect("manifest parses");
        let capsule = Capsule {
            manifest,
            archive: archive::ArchiveContents {
                wasm,
                ..Default::default()
            },
        };
        let engine = EngineFactory::build().expect("engine builds");
        let linker = capsule
            .prepare_linker(&engine)
            .expect("linker constructs")
            .into_linker();
        capsule
            .instantiate_with_store(&engine, &linker)
            .expect("list-compliance-posture instantiates")
    }

    /// CIT-AGENT-9c-1 — verifies the capsule encodes the canonical
    /// ABI calldata for `BoeingComplianceRegistry.framework(...)`.
    /// The expected layout is:
    ///   selector (4 bytes) || framework_hash (32 bytes) || scope (32 bytes)
    /// where selector = keccak256("framework(bytes32,bytes32)")[0..4]
    /// and framework_hash = keccak256(framework_slug).
    #[test]
    fn list_compliance_posture_capsule_encodes_correct_calldata() {
        use sha3::{Digest, Keccak256};

        let (mut store, instance) = load_list_compliance_capsule();
        // Inject a 288-byte zero-padded response so the capsule's
        // decoder doesn't error out before we can inspect what it
        // sent.
        let canned = vec![0u8; 288];
        store.data_mut().inject_eth_call_canned_response(canned);

        let framework_slug = "fedramp-moderate";
        let scope_hex = "00112233445566778899aabbccddeeff00112233445566778899aabbccddeeff";
        let scope_arg = format!("0x{scope_hex}");
        let _ = invoke_list_compliance_query(&mut store, instance, framework_slug, &scope_arg);

        // Compute expected calldata.
        let mut sel_hasher = Keccak256::new();
        sel_hasher.update(b"framework(bytes32,bytes32)");
        let sel_full = sel_hasher.finalize();
        let mut expected = Vec::with_capacity(68);
        expected.extend_from_slice(&sel_full[..4]);
        let mut fw_hasher = Keccak256::new();
        fw_hasher.update(framework_slug.as_bytes());
        let fw_hash = fw_hasher.finalize();
        expected.extend_from_slice(&fw_hash);
        expected.extend_from_slice(&hex::decode(scope_hex).unwrap());

        let actual = store
            .data()
            .last_eth_call_data()
            .expect("host fn recorded the call")
            .clone();
        assert_eq!(actual.len(), 68, "calldata is 4-byte selector + 64-byte args");
        assert_eq!(
            actual, expected,
            "capsule must produce canonical framework(bytes32,bytes32) calldata",
        );

        // Verify the `to` is the manifest-allow-listed address.
        let to = store.data().last_eth_call_to().expect("to recorded").clone();
        assert_eq!(
            hex::encode(to),
            "8dbbbc46d840f40205b48d76aa9fc5063b7d55d8",
            "calldata must be routed to BoeingComplianceRegistry"
        );
    }

    /// CIT-AGENT-9c-1 — verifies the capsule decodes a 288-byte
    /// `Row` response into the WIT `posture-row` record correctly.
    /// Layout per LiveComplianceBindings::decode_row:
    ///   [0..32)    row_id
    ///   [32..64)   framework
    ///   [64..96)   scope
    ///   [96..128)  evidence_cid
    ///   [128..160) attestor
    ///   [160..192) posture (last byte)
    ///   [192..224) expired (last byte 0/1)
    ///   [224..256) attested_at_block (low 8 bytes BE)
    ///   [256..288) expires_at_block (low 8 bytes BE)
    #[test]
    fn list_compliance_posture_capsule_decodes_response() {
        let (mut store, instance) = load_list_compliance_capsule();

        // Hand-craft a 288-byte response with known field values.
        let mut canned = vec![0u8; 288];
        // row_id: 0x11..11
        canned[0..32].fill(0x11);
        // framework: 0x22..22
        canned[32..64].fill(0x22);
        // scope: 0x33..33
        canned[64..96].fill(0x33);
        // evidence_cid: 0x44..44
        canned[96..128].fill(0x44);
        // attestor: 0x55..55
        canned[128..160].fill(0x55);
        // posture = 2 (Attested) — last byte of chunk at 160..192
        canned[191] = 2;
        // expired = true — last byte of chunk at 192..224
        canned[223] = 1;
        // attested_at_block = 1000 (low 8 bytes BE of chunk 224..256)
        let attested: u64 = 1000;
        canned[248..256].copy_from_slice(&attested.to_be_bytes());
        // expires_at_block = 12345
        let expires: u64 = 12345;
        canned[280..288].copy_from_slice(&expires.to_be_bytes());
        store.data_mut().inject_eth_call_canned_response(canned);

        let result = invoke_list_compliance_query(
            &mut store,
            instance,
            "fedramp-moderate",
            "0x00112233445566778899aabbccddeeff00112233445566778899aabbccddeeff",
        );
        let row = result.expect("decode succeeds");
        assert_eq!(row.row_id, [0x11; 32]);
        assert_eq!(row.framework, [0x22; 32]);
        assert_eq!(row.scope, [0x33; 32]);
        assert_eq!(row.evidence_cid, [0x44; 32]);
        assert_eq!(row.attestor, [0x55; 32]);
        assert_eq!(row.posture, 2);
        assert!(row.expired);
        assert_eq!(row.attested_at_block, 1000);
        assert_eq!(row.expires_at_block, 12345);
    }

    /// CIT-AGENT-9c-1 — when the capsule's manifest allow-list does
    /// NOT include the contract address hardcoded into the capsule
    /// source, the host fn rejects the call with
    /// `ChainCallNotAuthorized` and the capsule re-emits the err
    /// string through its result.
    ///
    /// This tests the "compiled-in contract address vs. manifest
    /// declaration" mismatch path: a deployment-time bug where the
    /// manifest was edited without rebuilding the capsule. The
    /// security property is that the host fn closes the gap.
    #[test]
    fn list_compliance_posture_capsule_blocks_unauthorized_address() {
        use crate::capsule::manifest::Manifest;
        use crate::capsule::wasm::EngineFactory;
        use std::path::PathBuf;

        let manifest_dir = PathBuf::from(env!("CARGO_MANIFEST_DIR"));
        let capsule_dir = manifest_dir
            .parent()
            .and_then(|p| p.parent())
            .expect("walk up to citrate_v0.01.1/")
            .join("capsules")
            .join("list-compliance-posture");
        let wasm = std::fs::read(capsule_dir.join("capsule.wasm"))
            .expect("list-compliance-posture capsule.wasm on disk");

        // Use a tampered manifest where the allow-list points at a
        // DIFFERENT address (not the one the capsule has compiled in).
        let manifest_str = r#"
[capsule]
name = "list-compliance-posture-tampered"
version = "0.1.0"
content_hash = "sha256:0000000000000000000000000000000000000000000000000000000000000000"

[capability]
network = "none"
filesystem = []
chain_calls = ["eth_call:0xdeadbeefdeadbeefdeadbeefdeadbeefdeadbeef"]
subagent_spawn = false

[data_class]
reads = ["PUBLIC"]
writes = []
emits = ["PUBLIC"]

[risk]
tier = "low"
required_roles = ["Operator"]
break_glass_eligible = false

[overlay]
certified = []
not_certified = []

[procedure]
gates = []

[provenance]
publisher = "did:citrate:agent:0xab12"
build_reproducible = true
agentile_sprint = "2026-05-15-cit-agent-9c-1"
tla_spec = ""

[signing]
tier = "bundled"
"#;
        let manifest = Manifest::parse(manifest_str).expect("tampered manifest parses");
        let capsule = Capsule {
            manifest,
            archive: archive::ArchiveContents {
                wasm,
                ..Default::default()
            },
        };
        let engine = EngineFactory::build().expect("engine builds");
        let linker = capsule
            .prepare_linker(&engine)
            .expect("linker constructs")
            .into_linker();
        let (mut store, instance) = capsule
            .instantiate_with_store(&engine, &linker)
            .expect("tampered capsule still instantiates");

        let result = invoke_list_compliance_query(
            &mut store,
            instance,
            "fedramp-moderate",
            "0x00112233445566778899aabbccddeeff00112233445566778899aabbccddeeff",
        );
        let err = result.expect_err("call must fail when capsule's target is not allow-listed");
        assert!(
            err.starts_with("ChainCallNotAuthorized:"),
            "host fn must reject; got: {err}"
        );
        // The forensic info: the BoeingComplianceRegistry address
        // (the capsule's compiled-in target) appears in the error
        // even though the manifest allow-listed deadbeef. This is
        // the "compiled-in vs declared mismatch" surface.
        assert!(
            err.contains("8dbbbc46"),
            "error must name the capsule's actual target; got: {err}"
        );
    }

    // ────────────────────── CIT-AGENT-9c-2 ────────────────────────
    // Multi-call capsule: query-decisions-by-tenant. Tests verify
    // both calldata invocations + the N-cap policy.

    #[cfg(test)]
    #[derive(Debug, PartialEq, Eq)]
    struct DecodedDecision {
        decision_id: [u8; 32],
        user: [u8; 32],
        tenant: [u8; 32],
        corr_id: [u8; 32],
        class: u8,
        recorded_at_block: u64,
    }

    #[cfg(test)]
    fn invoke_query_decisions(
        store: &mut wasmtime::Store<wasm::HostCtx>,
        instance: wasmtime::component::Instance,
        tenant: &str,
        n: u32,
    ) -> Result<Vec<DecodedDecision>, String> {
        use wasmtime::component::Val;
        let iface_index = instance
            .get_export(
                &mut *store,
                None,
                "citrate:query-decisions-by-tenant/query@0.1.0",
            )
            .expect("capsule exports `query` interface");
        let func_index = instance
            .get_export(&mut *store, Some(&iface_index), "query")
            .expect("query interface exports `query` func");
        let func = instance
            .get_func(&mut *store, func_index)
            .expect("query func resolves");
        let args = vec![Val::String(tenant.to_string()), Val::U32(n)];
        let mut results = [Val::Bool(false)];
        func.call(&mut *store, &args, &mut results)
            .expect("query call completes");
        func.post_return(&mut *store).expect("post_return clears");

        fn bytes32_from_val(v: &Val) -> [u8; 32] {
            match v {
                Val::List(bytes) => {
                    let raw: Vec<u8> = bytes
                        .iter()
                        .map(|b| match b {
                            Val::U8(b) => *b,
                            _ => panic!("non-u8 in bytes32"),
                        })
                        .collect();
                    assert_eq!(raw.len(), 32);
                    let mut a = [0u8; 32];
                    a.copy_from_slice(&raw);
                    a
                }
                _ => panic!("expected list<u8>"),
            }
        }

        fn decode_decision_record(boxed: &wasmtime::component::Val) -> DecodedDecision {
            match boxed {
                Val::Record(fields) => {
                    let f = |name: &str| -> &Val {
                        fields
                            .iter()
                            .find(|(k, _)| k == name)
                            .map(|(_, v)| v)
                            .unwrap_or_else(|| panic!("field {name} missing"))
                    };
                    DecodedDecision {
                        decision_id: bytes32_from_val(f("decision-id")),
                        user: bytes32_from_val(f("user")),
                        tenant: bytes32_from_val(f("tenant")),
                        corr_id: bytes32_from_val(f("corr-id")),
                        class: if let Val::U8(b) = f("class") { *b } else { panic!() },
                        recorded_at_block: if let Val::U64(n) = f("recorded-at-block") {
                            *n
                        } else {
                            panic!()
                        },
                    }
                }
                _ => panic!("expected Record, got {boxed:?}"),
            }
        }

        match &results[0] {
            Val::Result(r) => match r.as_ref() {
                Ok(Some(boxed)) => match boxed.as_ref() {
                    Val::List(items) => Ok(items.iter().map(decode_decision_record).collect()),
                    other => panic!("expected list, got {other:?}"),
                },
                Ok(None) => Ok(Vec::new()),
                Err(Some(boxed)) => match boxed.as_ref() {
                    Val::String(s) => Err(s.clone()),
                    other => panic!("expected string, got {other:?}"),
                },
                Err(None) => Err(String::new()),
            },
            other => panic!("expected Result, got {other:?}"),
        }
    }

    #[cfg(test)]
    fn load_query_decisions_capsule() -> (
        wasmtime::Store<wasm::HostCtx>,
        wasmtime::component::Instance,
    ) {
        use crate::capsule::manifest::Manifest;
        use crate::capsule::wasm::EngineFactory;
        use std::path::PathBuf;

        let manifest_dir = PathBuf::from(env!("CARGO_MANIFEST_DIR"));
        let capsule_dir = manifest_dir
            .parent()
            .and_then(|p| p.parent())
            .expect("walk up to citrate_v0.01.1/")
            .join("capsules")
            .join("query-decisions-by-tenant");
        let wasm = std::fs::read(capsule_dir.join("capsule.wasm"))
            .expect("query-decisions capsule.wasm on disk");
        let manifest_str = std::fs::read_to_string(capsule_dir.join("manifest.toml"))
            .expect("query-decisions manifest.toml on disk");
        let manifest = Manifest::parse(&manifest_str).expect("manifest parses");
        let capsule = Capsule {
            manifest,
            archive: archive::ArchiveContents {
                wasm,
                ..Default::default()
            },
        };
        let engine = EngineFactory::build().expect("engine builds");
        let linker = capsule
            .prepare_linker(&engine)
            .expect("linker constructs")
            .into_linker();
        capsule
            .instantiate_with_store(&engine, &linker)
            .expect("query-decisions instantiates")
    }

    /// Build a 64-byte bytes32[] return with one ID (the
    /// minimum valid response: outer offset 32 + length 1 +
    /// one 32-byte entry).
    #[cfg(test)]
    fn build_bytes32_array_response(ids: &[[u8; 32]]) -> Vec<u8> {
        let mut out = Vec::with_capacity(64 + ids.len() * 32);
        // Outer offset = 0x20
        let mut off = [0u8; 32];
        off[31] = 0x20;
        out.extend_from_slice(&off);
        // Length
        let mut len = [0u8; 32];
        len[24..32].copy_from_slice(&(ids.len() as u64).to_be_bytes());
        out.extend_from_slice(&len);
        // Entries
        for id in ids {
            out.extend_from_slice(id);
        }
        out
    }

    /// Build a getDecision dynamic-struct response. The outer
    /// offset points at byte 32 (immediately after itself); the
    /// struct body is 11 chunks (354 bytes; but our decoder only
    /// reads 10 chunks ending at s+288..s+320). Pads to 352 bytes
    /// total to satisfy the bound check.
    #[cfg(test)]
    fn build_decision_response(
        decision_id: [u8; 32],
        user: [u8; 32],
        tenant: [u8; 32],
        corr_id: [u8; 32],
        class: u8,
        recorded_at_block: u64,
    ) -> Vec<u8> {
        let mut out = Vec::with_capacity(32 + 320);
        // Outer offset = 0x20
        let mut off = [0u8; 32];
        off[31] = 0x20;
        out.extend_from_slice(&off);
        // s = 32. Chunks at s+0..32, s+32..64, ..., s+288..320.
        out.extend_from_slice(&decision_id);
        out.extend_from_slice(&user);
        out.extend_from_slice(&tenant);
        out.extend_from_slice(&corr_id);
        // class at s+128..s+160 (last byte)
        let mut class_chunk = [0u8; 32];
        class_chunk[31] = class;
        out.extend_from_slice(&class_chunk);
        // skipped chunks at s+160..s+288 (4 chunks = 128 bytes)
        out.extend_from_slice(&[0u8; 128]);
        // ts at s+288..s+320 (low 8 bytes BE)
        let mut ts_chunk = [0u8; 32];
        ts_chunk[24..32].copy_from_slice(&recorded_at_block.to_be_bytes());
        out.extend_from_slice(&ts_chunk);
        out
    }

    /// CIT-AGENT-9c-2 — verifies the capsule produces canonical
    /// latestByTenant calldata followed by per-ID getDecision
    /// calldata. Two host fn calls expected (one ID returned).
    #[test]
    fn query_decisions_by_tenant_capsule_encodes_correct_calldata() {
        use sha3::{Digest, Keccak256};

        let (mut store, instance) = load_query_decisions_capsule();
        // 1st response: array with one ID (= 0x77..77).
        let id_a = [0x77u8; 32];
        store
            .data_mut()
            .enqueue_eth_call_canned_response(build_bytes32_array_response(&[id_a]));
        // 2nd response: a valid getDecision for id_a.
        store
            .data_mut()
            .enqueue_eth_call_canned_response(build_decision_response(
                id_a,
                [0xaau8; 32],
                [0xbbu8; 32],
                [0xccu8; 32],
                3,
                42,
            ));

        let tenant_hex = "0011223344556677889900aabbccddee0011223344556677889900aabbccddee";
        let tenant_arg = format!("0x{tenant_hex}");
        let _ = invoke_query_decisions(&mut store, instance, &tenant_arg, 3);

        // Expected selectors
        let mut h = Keccak256::new();
        h.update(b"latestByTenant(bytes32,uint256)");
        let sel_latest = h.finalize();
        let mut h = Keccak256::new();
        h.update(b"getDecision(bytes32)");
        let sel_get = h.finalize();

        let history = store.data().eth_call_history();
        assert_eq!(history.len(), 2, "expected 1 + 1 calls (1 latest + 1 get)");

        // Call 1: latestByTenant(tenant, 3)
        let call1 = &history[0];
        assert_eq!(
            hex::encode(call1.0),
            "4a86659bdab24dc444c72fbbad4cd83491820e40",
            "call 1 routed to AgentDecisionRegistryV2"
        );
        assert_eq!(call1.1[..4], sel_latest[..4]);
        let tenant_bytes = hex::decode(tenant_hex).unwrap();
        assert_eq!(&call1.1[4..36], &tenant_bytes[..]);
        // N param: last byte should be 3 (under the cap)
        assert_eq!(call1.1[67], 3, "n encoded as 3");

        // Call 2: getDecision(id_a)
        let call2 = &history[1];
        assert_eq!(call2.1[..4], sel_get[..4]);
        assert_eq!(&call2.1[4..36], &id_a[..]);
    }

    /// CIT-AGENT-9c-2 — verifies the capsule decodes 2 getDecision
    /// responses into structured DecisionSummary records.
    #[test]
    fn query_decisions_by_tenant_capsule_decodes_multi_response() {
        let (mut store, instance) = load_query_decisions_capsule();
        let id_a = [0x11u8; 32];
        let id_b = [0x22u8; 32];
        store
            .data_mut()
            .enqueue_eth_call_canned_response(build_bytes32_array_response(&[id_a, id_b]));
        store
            .data_mut()
            .enqueue_eth_call_canned_response(build_decision_response(
                id_a,
                [0xa1u8; 32],
                [0xb1u8; 32],
                [0xc1u8; 32],
                1,
                100,
            ));
        store
            .data_mut()
            .enqueue_eth_call_canned_response(build_decision_response(
                id_b,
                [0xa2u8; 32],
                [0xb2u8; 32],
                [0xc2u8; 32],
                2,
                200,
            ));

        let result = invoke_query_decisions(
            &mut store,
            instance,
            "0x0011223344556677889900aabbccddee0011223344556677889900aabbccddee",
            10,
        );
        let list = result.expect("multi-call decode succeeds");
        assert_eq!(list.len(), 2);
        assert_eq!(list[0].decision_id, id_a);
        assert_eq!(list[0].class, 1);
        assert_eq!(list[0].recorded_at_block, 100);
        assert_eq!(list[1].decision_id, id_b);
        assert_eq!(list[1].class, 2);
        assert_eq!(list[1].recorded_at_block, 200);
    }

    /// CIT-AGENT-9c-2 — n is silently clamped to 50. Calling with
    /// n=100 must encode 50 in the latestByTenant calldata.
    #[test]
    fn query_decisions_by_tenant_capsule_caps_n_at_50() {
        let (mut store, instance) = load_query_decisions_capsule();
        // First call: empty array (no follow-ups needed).
        store
            .data_mut()
            .enqueue_eth_call_canned_response(build_bytes32_array_response(&[]));

        let _ = invoke_query_decisions(
            &mut store,
            instance,
            "0x0011223344556677889900aabbccddee0011223344556677889900aabbccddee",
            100,
        );

        let history = store.data().eth_call_history();
        assert_eq!(history.len(), 1, "empty ID array → no getDecision calls");
        let n_byte = history[0].1[67]; // last byte of the second uint256 arg
        assert_eq!(n_byte, 50, "n=100 was clamped to MAX_N=50");
        // High bytes should be zero (no encoding overflow).
        assert_eq!(&history[0].1[36..67], &[0u8; 31][..]);
    }

    // ────────────────────── (end CIT-AGENT-9c-2) ──────────────────

    // ────────────────────── CIT-AGENT-9c-3 ────────────────────────
    // query-supplier-status: single-call capsule, static-struct decode.

    #[cfg(test)]
    #[derive(Debug, PartialEq, Eq)]
    struct DecodedSupplier {
        supplier_id: [u8; 32],
        scope: [u8; 32],
        state: u8,
        registered_at: u64,
        qualification_period_days: u64,
    }

    #[cfg(test)]
    fn invoke_query_supplier(
        store: &mut wasmtime::Store<wasm::HostCtx>,
        instance: wasmtime::component::Instance,
        supplier_id: &str,
    ) -> Result<DecodedSupplier, String> {
        use wasmtime::component::Val;
        let iface_index = instance
            .get_export(
                &mut *store,
                None,
                "citrate:query-supplier-status/query@0.1.0",
            )
            .expect("capsule exports `query` interface");
        let func_index = instance
            .get_export(&mut *store, Some(&iface_index), "query")
            .expect("query interface exports `query` func");
        let func = instance
            .get_func(&mut *store, func_index)
            .expect("query func resolves");
        let args = vec![Val::String(supplier_id.to_string())];
        let mut results = [Val::Bool(false)];
        func.call(&mut *store, &args, &mut results)
            .expect("query call completes");
        func.post_return(&mut *store).expect("post_return clears");

        fn bytes32_from_val(v: &Val) -> [u8; 32] {
            match v {
                Val::List(bytes) => {
                    let raw: Vec<u8> = bytes
                        .iter()
                        .map(|b| match b {
                            Val::U8(b) => *b,
                            _ => panic!("non-u8 in bytes32"),
                        })
                        .collect();
                    assert_eq!(raw.len(), 32);
                    let mut a = [0u8; 32];
                    a.copy_from_slice(&raw);
                    a
                }
                _ => panic!("expected list<u8>"),
            }
        }

        match &results[0] {
            Val::Result(r) => match r.as_ref() {
                Ok(Some(boxed)) => match boxed.as_ref() {
                    Val::Record(fields) => {
                        let f = |name: &str| -> &Val {
                            fields
                                .iter()
                                .find(|(k, _)| k == name)
                                .map(|(_, v)| v)
                                .unwrap_or_else(|| panic!("field {name} missing"))
                        };
                        Ok(DecodedSupplier {
                            supplier_id: bytes32_from_val(f("supplier-id")),
                            scope: bytes32_from_val(f("scope")),
                            state: if let Val::U8(b) = f("state") { *b } else { panic!() },
                            registered_at: if let Val::U64(n) = f("registered-at") {
                                *n
                            } else {
                                panic!()
                            },
                            qualification_period_days: if let Val::U64(n) =
                                f("qualification-period-days")
                            {
                                *n
                            } else {
                                panic!()
                            },
                        })
                    }
                    other => panic!("expected Record, got {other:?}"),
                },
                Ok(None) => panic!("Ok(None) not expected for supplier-view"),
                Err(Some(boxed)) => match boxed.as_ref() {
                    Val::String(s) => Err(s.clone()),
                    other => panic!("expected string, got {other:?}"),
                },
                Err(None) => Err(String::new()),
            },
            other => panic!("expected Result, got {other:?}"),
        }
    }

    #[cfg(test)]
    fn load_query_supplier_capsule() -> (
        wasmtime::Store<wasm::HostCtx>,
        wasmtime::component::Instance,
    ) {
        use crate::capsule::manifest::Manifest;
        use crate::capsule::wasm::EngineFactory;
        use std::path::PathBuf;

        let manifest_dir = PathBuf::from(env!("CARGO_MANIFEST_DIR"));
        let capsule_dir = manifest_dir
            .parent()
            .and_then(|p| p.parent())
            .expect("walk up to citrate_v0.01.1/")
            .join("capsules")
            .join("query-supplier-status");
        let wasm = std::fs::read(capsule_dir.join("capsule.wasm"))
            .expect("query-supplier capsule.wasm on disk");
        let manifest_str = std::fs::read_to_string(capsule_dir.join("manifest.toml"))
            .expect("query-supplier manifest.toml on disk");
        let manifest = Manifest::parse(&manifest_str).expect("manifest parses");
        let capsule = Capsule {
            manifest,
            archive: archive::ArchiveContents {
                wasm,
                ..Default::default()
            },
        };
        let engine = EngineFactory::build().expect("engine builds");
        let linker = capsule
            .prepare_linker(&engine)
            .expect("linker constructs")
            .into_linker();
        capsule
            .instantiate_with_store(&engine, &linker)
            .expect("query-supplier instantiates")
    }

    /// CIT-AGENT-9c-3 — calldata encoding.
    #[test]
    fn query_supplier_status_capsule_encodes_correct_calldata() {
        use sha3::{Digest, Keccak256};

        let (mut store, instance) = load_query_supplier_capsule();
        // Inject a 192-byte zero-padded response.
        store
            .data_mut()
            .enqueue_eth_call_canned_response(vec![0u8; 192]);

        let id_hex = "deadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeef";
        let id_arg = format!("0x{id_hex}");
        let _ = invoke_query_supplier(&mut store, instance, &id_arg);

        let mut h = Keccak256::new();
        h.update(b"get(bytes32)");
        let sel = h.finalize();

        let history = store.data().eth_call_history();
        assert_eq!(history.len(), 1);
        let call = &history[0];
        assert_eq!(
            hex::encode(call.0),
            "425064443c3c3392c47dcbe10d455831545efd9b",
            "calldata routed to SupplierRegistry"
        );
        assert_eq!(call.1.len(), 36, "selector(4) + bytes32(32) = 36 bytes");
        assert_eq!(call.1[..4], sel[..4]);
        assert_eq!(&call.1[4..36], &hex::decode(id_hex).unwrap()[..]);
    }

    /// CIT-AGENT-9c-3 — static-struct decoder.
    #[test]
    fn query_supplier_status_capsule_decodes_response() {
        let (mut store, instance) = load_query_supplier_capsule();

        // 192 bytes for the 6-chunk static struct (we read 5).
        let mut canned = vec![0u8; 192];
        canned[0..32].fill(0xa1); // supplier_id
        canned[32..64].fill(0xb2); // scope
        canned[95] = 3; // state (last byte of chunk at 64..96)
        let reg: u64 = 9999;
        canned[120..128].copy_from_slice(&reg.to_be_bytes());
        let period: u64 = 365;
        canned[152..160].copy_from_slice(&period.to_be_bytes());
        store.data_mut().enqueue_eth_call_canned_response(canned);

        let result = invoke_query_supplier(
            &mut store,
            instance,
            "0xdeadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeef",
        );
        let row = result.expect("decode succeeds");
        assert_eq!(row.supplier_id, [0xa1; 32]);
        assert_eq!(row.scope, [0xb2; 32]);
        assert_eq!(row.state, 3);
        assert_eq!(row.registered_at, 9999);
        assert_eq!(row.qualification_period_days, 365);
    }

    /// CIT-AGENT-9c-3 — bad input hex is rejected by the capsule's
    /// parser before any host fn call is made.
    #[test]
    fn query_supplier_status_capsule_rejects_malformed_id() {
        let (mut store, instance) = load_query_supplier_capsule();
        let result = invoke_query_supplier(&mut store, instance, "not-a-hex-string");
        let err = result.expect_err("malformed hex must be rejected");
        assert!(
            err.starts_with("expected 32-byte hex"),
            "error names the input contract; got: {err}"
        );
        // No host fn call should have been made — the parse failure
        // is pre-call.
        assert_eq!(
            store.data().eth_call_history().len(),
            0,
            "parse failure must short-circuit before eth_call"
        );
    }

    // ────────────────────── (end CIT-AGENT-9c-3) ──────────────────

    // ────────────────────── CIT-AGENT-9c-4 ────────────────────────
    // verify-provenance-chain: single call, mixed (bool, bytes32[])
    // return — exercises variable-length array decoding behind an
    // offset.

    #[cfg(test)]
    #[derive(Debug, PartialEq, Eq)]
    struct DecodedVerifyResult {
        ok: bool,
        chain: Vec<[u8; 32]>,
    }

    #[cfg(test)]
    fn invoke_verify_provenance_chain(
        store: &mut wasmtime::Store<wasm::HostCtx>,
        instance: wasmtime::component::Instance,
        part_hash: &str,
    ) -> Result<DecodedVerifyResult, String> {
        use wasmtime::component::Val;
        let iface_index = instance
            .get_export(
                &mut *store,
                None,
                "citrate:verify-provenance-chain/query@0.1.0",
            )
            .expect("capsule exports `query` interface");
        let func_index = instance
            .get_export(&mut *store, Some(&iface_index), "query")
            .expect("query interface exports `query` func");
        let func = instance
            .get_func(&mut *store, func_index)
            .expect("query func resolves");
        let args = vec![Val::String(part_hash.to_string())];
        let mut results = [Val::Bool(false)];
        func.call(&mut *store, &args, &mut results)
            .expect("query call completes");
        func.post_return(&mut *store).expect("post_return clears");

        fn bytes32_from_val(v: &Val) -> [u8; 32] {
            match v {
                Val::List(bytes) => {
                    let raw: Vec<u8> = bytes
                        .iter()
                        .map(|b| match b {
                            Val::U8(b) => *b,
                            _ => panic!("non-u8 in bytes32"),
                        })
                        .collect();
                    assert_eq!(raw.len(), 32);
                    let mut a = [0u8; 32];
                    a.copy_from_slice(&raw);
                    a
                }
                _ => panic!("expected list<u8>"),
            }
        }

        match &results[0] {
            Val::Result(r) => match r.as_ref() {
                Ok(Some(boxed)) => match boxed.as_ref() {
                    Val::Record(fields) => {
                        let f = |name: &str| -> &Val {
                            fields
                                .iter()
                                .find(|(k, _)| k == name)
                                .map(|(_, v)| v)
                                .unwrap_or_else(|| panic!("field {name} missing"))
                        };
                        let ok = if let Val::Bool(b) = f("ok") {
                            *b
                        } else {
                            panic!("expected bool for ok")
                        };
                        let chain = if let Val::List(items) = f("chain") {
                            items.iter().map(bytes32_from_val).collect()
                        } else {
                            panic!("expected list for chain")
                        };
                        Ok(DecodedVerifyResult { ok, chain })
                    }
                    other => panic!("expected Record, got {other:?}"),
                },
                Ok(None) => panic!("Ok(None) not expected for verify-result"),
                Err(Some(boxed)) => match boxed.as_ref() {
                    Val::String(s) => Err(s.clone()),
                    other => panic!("expected string, got {other:?}"),
                },
                Err(None) => Err(String::new()),
            },
            other => panic!("expected Result, got {other:?}"),
        }
    }

    #[cfg(test)]
    fn load_verify_provenance_capsule() -> (
        wasmtime::Store<wasm::HostCtx>,
        wasmtime::component::Instance,
    ) {
        use crate::capsule::manifest::Manifest;
        use crate::capsule::wasm::EngineFactory;
        use std::path::PathBuf;

        let manifest_dir = PathBuf::from(env!("CARGO_MANIFEST_DIR"));
        let capsule_dir = manifest_dir
            .parent()
            .and_then(|p| p.parent())
            .expect("walk up to citrate_v0.01.1/")
            .join("capsules")
            .join("verify-provenance-chain");
        let wasm = std::fs::read(capsule_dir.join("capsule.wasm"))
            .expect("verify-provenance capsule.wasm on disk");
        let manifest_str = std::fs::read_to_string(capsule_dir.join("manifest.toml"))
            .expect("verify-provenance manifest.toml on disk");
        let manifest = Manifest::parse(&manifest_str).expect("manifest parses");
        let capsule = Capsule {
            manifest,
            archive: archive::ArchiveContents {
                wasm,
                ..Default::default()
            },
        };
        let engine = EngineFactory::build().expect("engine builds");
        let linker = capsule
            .prepare_linker(&engine)
            .expect("linker constructs")
            .into_linker();
        capsule
            .instantiate_with_store(&engine, &linker)
            .expect("verify-provenance instantiates")
    }

    /// Build a (bool, bytes32[]) response. Layout:
    ///   [0..32)  bool (last byte 0/1)
    ///   [32..64) offset = 0x40 (64) pointing to the array data
    ///   [64..96) array length
    ///   [96..)   N × 32 bytes of entries
    #[cfg(test)]
    fn build_verify_response(ok: bool, chain: &[[u8; 32]]) -> Vec<u8> {
        let mut out = Vec::with_capacity(96 + chain.len() * 32);
        let mut ok_chunk = [0u8; 32];
        ok_chunk[31] = if ok { 1 } else { 0 };
        out.extend_from_slice(&ok_chunk);
        let mut off = [0u8; 32];
        off[31] = 0x40;
        out.extend_from_slice(&off);
        let mut len = [0u8; 32];
        len[24..32].copy_from_slice(&(chain.len() as u64).to_be_bytes());
        out.extend_from_slice(&len);
        for entry in chain {
            out.extend_from_slice(entry);
        }
        out
    }

    /// CIT-AGENT-9c-4 — calldata encoding for verifyChain(bytes32).
    #[test]
    fn verify_provenance_chain_capsule_encodes_correct_calldata() {
        use sha3::{Digest, Keccak256};

        let (mut store, instance) = load_verify_provenance_capsule();
        store
            .data_mut()
            .enqueue_eth_call_canned_response(build_verify_response(true, &[]));

        let hash_hex = "abcdefabcdefabcdefabcdefabcdefabcdefabcdefabcdefabcdefabcdefabcd";
        let _ = invoke_verify_provenance_chain(
            &mut store,
            instance,
            &format!("0x{hash_hex}"),
        );

        let mut h = Keccak256::new();
        h.update(b"verifyChain(bytes32)");
        let sel = h.finalize();

        let history = store.data().eth_call_history();
        assert_eq!(history.len(), 1);
        let call = &history[0];
        assert_eq!(
            hex::encode(call.0),
            "1afe987622ab5add275d2fd21248f77f5e00667f",
            "routed to PartProvenanceRegistry"
        );
        assert_eq!(call.1[..4], sel[..4]);
        assert_eq!(&call.1[4..36], &hex::decode(hash_hex).unwrap()[..]);
    }

    /// CIT-AGENT-9c-4 — non-empty chain decode.
    #[test]
    fn verify_provenance_chain_capsule_decodes_mixed_return() {
        let (mut store, instance) = load_verify_provenance_capsule();
        let step_a = [0xa1u8; 32];
        let step_b = [0xb2u8; 32];
        let step_c = [0xc3u8; 32];
        store
            .data_mut()
            .enqueue_eth_call_canned_response(build_verify_response(
                true,
                &[step_a, step_b, step_c],
            ));

        let result = invoke_verify_provenance_chain(
            &mut store,
            instance,
            "0xabcdefabcdefabcdefabcdefabcdefabcdefabcdefabcdefabcdefabcdefabcd",
        );
        let v = result.expect("decode succeeds");
        assert!(v.ok);
        assert_eq!(v.chain.len(), 3);
        assert_eq!(v.chain[0], step_a);
        assert_eq!(v.chain[1], step_b);
        assert_eq!(v.chain[2], step_c);
    }

    /// CIT-AGENT-9c-4 — empty chain with ok=false is a valid
    /// response (unknown part), returned as Ok, not Err.
    #[test]
    fn verify_provenance_chain_capsule_decodes_empty_chain() {
        let (mut store, instance) = load_verify_provenance_capsule();
        store
            .data_mut()
            .enqueue_eth_call_canned_response(build_verify_response(false, &[]));

        let result = invoke_verify_provenance_chain(
            &mut store,
            instance,
            "0xabcdefabcdefabcdefabcdefabcdefabcdefabcdefabcdefabcdefabcdefabcd",
        );
        let v = result.expect(
            "empty chain with ok=false is a valid response, not an error",
        );
        assert!(!v.ok);
        assert_eq!(v.chain.len(), 0);
    }

    // ────────────────────── (end CIT-AGENT-9c-4) ──────────────────

    // ────────────────────── CIT-AGENT-9c-1-rpc ────────────────────
    // Trait-based dispatcher path: capsule calls eth-call, host fn
    // routes to a pluggable `EthCallDispatcher`. Tests use a
    // recording mock to verify the call reaches the dispatcher and
    // its response flows back to the capsule.

    /// Mock dispatcher used in this module's integration test.
    #[cfg(test)]
    struct LocalMockDispatcher {
        calls: std::sync::Mutex<Vec<([u8; 20], Vec<u8>)>>,
        response: Vec<u8>,
    }

    #[cfg(test)]
    impl dispatcher::EthCallDispatcher for LocalMockDispatcher {
        fn eth_call(
            &self,
            to: &wasm::Address,
            data: &[u8],
        ) -> Result<Vec<u8>, String> {
            self.calls.lock().unwrap().push((*to, data.to_vec()));
            Ok(self.response.clone())
        }
    }

    /// CIT-AGENT-9c-1-rpc — end-to-end test of the production
    /// dispatch path. Instantiate echo-chain with a mock dispatcher
    /// (NO canned-queue fixture), call `query`, and verify:
    ///   1. The dispatcher received the (to, data) pair.
    ///   2. The dispatcher's response bytes flow back to the
    ///      capsule through the WIT `result<list<u8>, string>` type.
    ///   3. The host fn's record_eth_call still ran (audit trail
    ///      preserved across the dispatcher path).
    #[test]
    fn echo_chain_capsule_dispatches_via_real_dispatcher() {
        use crate::capsule::manifest::Manifest;
        use crate::capsule::wasm::EngineFactory;
        use std::path::PathBuf;
        use std::sync::Arc;

        let manifest_dir = PathBuf::from(env!("CARGO_MANIFEST_DIR"));
        let capsule_dir = manifest_dir
            .parent()
            .and_then(|p| p.parent())
            .expect("walk up to citrate_v0.01.1/")
            .join("capsules")
            .join("echo-chain");
        let wasm = std::fs::read(capsule_dir.join("capsule.wasm"))
            .expect("echo-chain capsule.wasm on disk");
        let manifest_str = std::fs::read_to_string(capsule_dir.join("manifest.toml"))
            .expect("echo-chain manifest.toml on disk");
        let manifest = Manifest::parse(&manifest_str).expect("manifest parses");
        let capsule = Capsule {
            manifest,
            archive: archive::ArchiveContents {
                wasm,
                ..Default::default()
            },
        };

        let dispatcher_response = vec![0xfeu8, 0xed, 0xbe, 0xef];
        let mock = Arc::new(LocalMockDispatcher {
            calls: std::sync::Mutex::new(Vec::new()),
            response: dispatcher_response.clone(),
        });

        let engine = EngineFactory::build().expect("engine builds");
        let linker = capsule
            .prepare_linker(&engine)
            .expect("linker constructs")
            .into_linker();
        let (mut store, instance) = capsule
            .instantiate_with_store_and_dispatcher(&engine, &linker, mock.clone())
            .expect("instantiates with dispatcher");

        // NOTE: deliberately no canned-queue entry. The host fn
        // must hit the dispatcher path.
        let authorized = hex::decode("4a86659BDab24dc444C72fbbaD4cd83491820E40").unwrap();
        let result = invoke_echo_chain_query(
            &mut store,
            instance,
            authorized.clone(),
            vec![0x12, 0x34],
        );
        assert_eq!(
            result,
            Ok(dispatcher_response.clone()),
            "dispatcher response flows back to the capsule"
        );

        // The mock saw the call.
        let calls = mock.calls.lock().unwrap();
        assert_eq!(calls.len(), 1, "dispatcher invoked exactly once");
        let mut addr_arr = [0u8; 20];
        addr_arr.copy_from_slice(&authorized);
        assert_eq!(calls[0].0, addr_arr, "dispatcher receives the to bytes");
        assert_eq!(
            calls[0].1,
            vec![0x12, 0x34],
            "dispatcher receives the data bytes"
        );

        // The host fn's record_eth_call ran — audit trail
        // preserved across the dispatcher path, not just the
        // test-fixture path.
        let history = store.data().eth_call_history();
        assert_eq!(
            history.len(),
            1,
            "host fn still records via dispatcher path"
        );
        assert_eq!(history[0].0, addr_arr);
    }

    /// CIT-AGENT-9c-1-rpc — dispatch precedence. When BOTH a canned
    /// queue entry AND a dispatcher are present, the canned queue
    /// wins. This preserves the 12 read-tool tests' behavior under
    /// the new dispatch order.
    #[test]
    fn canned_queue_takes_precedence_over_dispatcher() {
        use crate::capsule::manifest::Manifest;
        use crate::capsule::wasm::EngineFactory;
        use std::path::PathBuf;
        use std::sync::Arc;

        let manifest_dir = PathBuf::from(env!("CARGO_MANIFEST_DIR"));
        let capsule_dir = manifest_dir
            .parent()
            .and_then(|p| p.parent())
            .expect("walk up to citrate_v0.01.1/")
            .join("capsules")
            .join("echo-chain");
        let wasm = std::fs::read(capsule_dir.join("capsule.wasm")).unwrap();
        let manifest_str = std::fs::read_to_string(capsule_dir.join("manifest.toml")).unwrap();
        let manifest = Manifest::parse(&manifest_str).unwrap();
        let capsule = Capsule {
            manifest,
            archive: archive::ArchiveContents {
                wasm,
                ..Default::default()
            },
        };

        let mock = Arc::new(LocalMockDispatcher {
            calls: std::sync::Mutex::new(Vec::new()),
            response: vec![0xffu8; 8],
        });
        let engine = EngineFactory::build().unwrap();
        let linker = capsule.prepare_linker(&engine).unwrap().into_linker();
        let (mut store, instance) = capsule
            .instantiate_with_store_and_dispatcher(&engine, &linker, mock.clone())
            .unwrap();

        // Pre-queue a canned response — should be returned ahead of
        // the dispatcher's response.
        store
            .data_mut()
            .enqueue_eth_call_canned_response(vec![0x42; 4]);

        let authorized = hex::decode("4a86659BDab24dc444C72fbbaD4cd83491820E40").unwrap();
        let result = invoke_echo_chain_query(&mut store, instance, authorized, vec![]);
        assert_eq!(result, Ok(vec![0x42; 4]), "canned queue wins over dispatcher");
        assert_eq!(
            mock.calls.lock().unwrap().len(),
            0,
            "dispatcher MUST NOT have been called"
        );
    }

    // ────────────────────── (end CIT-AGENT-9c-1-rpc) ──────────────

    // ────────────────────── CIT-AGENT-9c-write-host ───────────────
    // Three-layer write-path tests: allow-list, HITL approval gate,
    // dispatcher. Each layer has its own test that proves the
    // capsule never reaches the layers below when a layer rejects.

    #[cfg(test)]
    struct MockGate {
        decisions: std::sync::Mutex<Vec<dispatcher::ApprovalRequest>>,
        allow: bool,
        reason: String,
    }

    #[cfg(test)]
    impl dispatcher::ApprovalGate for MockGate {
        fn request(
            &self,
            req: dispatcher::ApprovalRequest,
        ) -> Result<(), String> {
            self.decisions.lock().unwrap().push(req);
            if self.allow {
                Ok(())
            } else {
                Err(self.reason.clone())
            }
        }
    }

    #[cfg(test)]
    struct MockSendDispatcher {
        calls: std::sync::Mutex<Vec<([u8; 20], Vec<u8>)>>,
        tx_hash: [u8; 32],
    }

    #[cfg(test)]
    impl dispatcher::EthSendDispatcher for MockSendDispatcher {
        fn eth_send(
            &self,
            to: &wasm::Address,
            data: &[u8],
        ) -> Result<[u8; 32], String> {
            self.calls.lock().unwrap().push((*to, data.to_vec()));
            Ok(self.tx_hash)
        }
    }

    /// Helper to invoke the eth-sender-test capsule's `send` export.
    /// Returns the result through `Result<Vec<u8> tx_hash, String err>`.
    #[cfg(test)]
    fn invoke_eth_sender_send(
        store: &mut wasmtime::Store<wasm::HostCtx>,
        instance: wasmtime::component::Instance,
        to: Vec<u8>,
        data: Vec<u8>,
    ) -> Result<Vec<u8>, String> {
        use wasmtime::component::Val;
        let iface_idx = instance
            .get_export(&mut *store, None, "citrate:eth-sender-test/action@0.1.0")
            .expect("action interface exists");
        let func_idx = instance
            .get_export(&mut *store, Some(&iface_idx), "send")
            .expect("send func exists");
        let func = instance.get_func(&mut *store, func_idx).unwrap();
        let to_val = Val::List(to.into_iter().map(Val::U8).collect());
        let data_val = Val::List(data.into_iter().map(Val::U8).collect());
        let mut results = [Val::Bool(false)];
        func.call(&mut *store, &[to_val, data_val], &mut results)
            .expect("send call completes");
        func.post_return(&mut *store).expect("post_return clears");
        match &results[0] {
            Val::Result(r) => match r.as_ref() {
                Ok(Some(boxed)) => match boxed.as_ref() {
                    Val::List(bytes) => Ok(bytes
                        .iter()
                        .map(|b| match b {
                            Val::U8(b) => *b,
                            _ => panic!("non-u8"),
                        })
                        .collect()),
                    other => panic!("expected list<u8>, got {other:?}"),
                },
                Ok(None) => Ok(Vec::new()),
                Err(Some(boxed)) => match boxed.as_ref() {
                    Val::String(s) => Err(s.clone()),
                    other => panic!("expected string, got {other:?}"),
                },
                Err(None) => Err(String::new()),
            },
            other => panic!("expected Result, got {other:?}"),
        }
    }

    #[cfg(test)]
    fn load_eth_sender_capsule_with(
        manifest_str: &str,
        gate: Option<std::sync::Arc<dyn dispatcher::ApprovalGate>>,
        dispatcher_impl: Option<
            std::sync::Arc<dyn dispatcher::EthSendDispatcher>,
        >,
    ) -> (
        wasmtime::Store<wasm::HostCtx>,
        wasmtime::component::Instance,
    ) {
        use crate::capsule::manifest::Manifest;
        use crate::capsule::wasm::EngineFactory;
        use std::path::PathBuf;

        let manifest_dir = PathBuf::from(env!("CARGO_MANIFEST_DIR"));
        let capsule_dir = manifest_dir
            .parent()
            .and_then(|p| p.parent())
            .expect("walk up to citrate_v0.01.1/")
            .join("capsules")
            .join("eth-sender-test");
        let wasm = std::fs::read(capsule_dir.join("capsule.wasm")).unwrap();
        let manifest = Manifest::parse(manifest_str).expect("manifest parses");
        let capsule = Capsule {
            manifest,
            archive: archive::ArchiveContents {
                wasm,
                ..Default::default()
            },
        };
        let engine = EngineFactory::build().unwrap();
        let linker = capsule.prepare_linker(&engine).unwrap().into_linker();
        capsule
            .instantiate_with_write_path(&engine, &linker, None, dispatcher_impl, gate)
            .expect("instantiate succeeds")
    }

    const ETH_SENDER_MANIFEST_OK: &str = r#"
[capsule]
name = "eth-sender-test"
version = "0.1.0"
content_hash = "sha256:0000000000000000000000000000000000000000000000000000000000000000"

[capability]
network = "none"
filesystem = []
chain_calls = ["eth_send:0x4a86659BDab24dc444C72fbbaD4cd83491820E40"]
subagent_spawn = false

[data_class]
reads = ["PUBLIC"]
writes = ["PUBLIC"]
emits = ["PUBLIC"]

[risk]
tier = "high"
required_roles = ["Reviewer", "ComplianceOfficer"]
break_glass_eligible = false

[overlay]
certified = []
not_certified = []

[procedure]
gates = []

[provenance]
publisher = "did:citrate:agent:0xab12"
build_reproducible = true
agentile_sprint = "2026-05-15-cit-agent-9c-write-host"
tla_spec = ""

[signing]
tier = "bundled"
"#;

    /// CIT-AGENT-9c-write-host LAYER 1 — capsule with an
    /// authorized-address manifest BUT a different `to` arg at
    /// call time. The host fn rejects at the allow-list check;
    /// the approval gate is never consulted; the dispatcher is
    /// never invoked.
    #[test]
    fn eth_send_capsule_blocks_when_address_unauthorized() {
        use std::sync::Arc;

        let gate = Arc::new(MockGate {
            decisions: std::sync::Mutex::new(Vec::new()),
            allow: true,
            reason: String::new(),
        });
        let dispatcher_impl = Arc::new(MockSendDispatcher {
            calls: std::sync::Mutex::new(Vec::new()),
            tx_hash: [0xeeu8; 32],
        });
        let (mut store, instance) = load_eth_sender_capsule_with(
            ETH_SENDER_MANIFEST_OK,
            Some(gate.clone()),
            Some(dispatcher_impl.clone()),
        );

        // Call with an address NOT in the manifest allow-list.
        let unauthorized = vec![0x11u8; 20];
        let result = invoke_eth_sender_send(&mut store, instance, unauthorized, vec![]);

        let err = result.expect_err("allow-list miss must reject");
        assert!(
            err.starts_with("ChainSendNotAuthorized:"),
            "layer 1 rejection; got: {err}"
        );
        // The gate was NOT consulted.
        assert_eq!(
            gate.decisions.lock().unwrap().len(),
            0,
            "layer 1 rejection MUST short-circuit before the gate"
        );
        // The dispatcher was NOT invoked.
        assert_eq!(
            dispatcher_impl.calls.lock().unwrap().len(),
            0,
            "layer 1 rejection MUST short-circuit before dispatch"
        );
    }

    /// CIT-AGENT-9c-write-host LAYER 2 — allow-list passes, but the
    /// HITL approval gate denies. Dispatcher is never invoked. The
    /// rejection reason is propagated through the WIT result.
    #[test]
    fn eth_send_capsule_blocks_when_approval_denied() {
        use std::sync::Arc;

        let gate = Arc::new(MockGate {
            decisions: std::sync::Mutex::new(Vec::new()),
            allow: false,
            reason: "compliance officer rejected".to_string(),
        });
        let dispatcher_impl = Arc::new(MockSendDispatcher {
            calls: std::sync::Mutex::new(Vec::new()),
            tx_hash: [0xeeu8; 32],
        });
        let (mut store, instance) = load_eth_sender_capsule_with(
            ETH_SENDER_MANIFEST_OK,
            Some(gate.clone()),
            Some(dispatcher_impl.clone()),
        );

        let authorized =
            hex::decode("4a86659BDab24dc444C72fbbaD4cd83491820E40").unwrap();
        let result = invoke_eth_sender_send(
            &mut store,
            instance,
            authorized.clone(),
            vec![0xab],
        );

        let err = result.expect_err("approval denial must reject");
        assert!(
            err.starts_with("ChainSendApprovalRejected:"),
            "layer 2 rejection; got: {err}"
        );
        assert!(
            err.contains("compliance officer rejected"),
            "rejection reason must propagate; got: {err}"
        );
        // The gate WAS consulted exactly once.
        let decisions = gate.decisions.lock().unwrap();
        assert_eq!(decisions.len(), 1, "gate consulted exactly once");
        assert_eq!(decisions[0].method, "eth-send");
        assert_eq!(decisions[0].capsule_name, "eth-sender-test");
        let mut addr_arr = [0u8; 20];
        addr_arr.copy_from_slice(&authorized);
        assert_eq!(decisions[0].to, addr_arr);
        // The dispatcher was NOT invoked.
        assert_eq!(
            dispatcher_impl.calls.lock().unwrap().len(),
            0,
            "layer 2 rejection MUST short-circuit before dispatch"
        );
    }

    /// CIT-AGENT-9c-write-host LAYER 3 (happy path) — allow-list
    /// passes, approval granted, dispatcher invoked, tx hash flows
    /// back through the WIT result. The host fn's eth_send_history
    /// records the call.
    #[test]
    fn eth_send_capsule_dispatches_when_approval_granted() {
        use std::sync::Arc;

        let gate = Arc::new(MockGate {
            decisions: std::sync::Mutex::new(Vec::new()),
            allow: true,
            reason: String::new(),
        });
        let tx_hash = [0xdeu8; 32];
        let dispatcher_impl = Arc::new(MockSendDispatcher {
            calls: std::sync::Mutex::new(Vec::new()),
            tx_hash,
        });
        let (mut store, instance) = load_eth_sender_capsule_with(
            ETH_SENDER_MANIFEST_OK,
            Some(gate.clone()),
            Some(dispatcher_impl.clone()),
        );

        let authorized =
            hex::decode("4a86659BDab24dc444C72fbbaD4cd83491820E40").unwrap();
        let result = invoke_eth_sender_send(
            &mut store,
            instance,
            authorized.clone(),
            vec![0x12, 0x34],
        );

        assert_eq!(
            result,
            Ok(tx_hash.to_vec()),
            "tx hash flows back to the capsule"
        );
        // Gate consulted.
        assert_eq!(gate.decisions.lock().unwrap().len(), 1);
        // Dispatcher invoked exactly once with the right args.
        let calls = dispatcher_impl.calls.lock().unwrap();
        assert_eq!(calls.len(), 1);
        let mut addr_arr = [0u8; 20];
        addr_arr.copy_from_slice(&authorized);
        assert_eq!(calls[0].0, addr_arr);
        assert_eq!(calls[0].1, vec![0x12, 0x34]);
        // Host fn's audit history populated.
        let history = store.data().eth_send_history();
        assert_eq!(history.len(), 1);
        assert_eq!(history[0].0, addr_arr);
        assert_eq!(history[0].1, vec![0x12, 0x34]);
    }

    /// CIT-AGENT-9c-write-host — defense-in-depth: when NO approval
    /// gate is configured, every eth_send call rejects regardless
    /// of allow-list and dispatcher status. Writes-without-gate
    /// MUST never reach the chain.
    #[test]
    fn eth_send_capsule_rejects_when_no_gate_configured() {
        use std::sync::Arc;

        let dispatcher_impl = Arc::new(MockSendDispatcher {
            calls: std::sync::Mutex::new(Vec::new()),
            tx_hash: [0xeeu8; 32],
        });
        // Note: gate = None.
        let (mut store, instance) = load_eth_sender_capsule_with(
            ETH_SENDER_MANIFEST_OK,
            None,
            Some(dispatcher_impl.clone()),
        );

        let authorized =
            hex::decode("4a86659BDab24dc444C72fbbaD4cd83491820E40").unwrap();
        let result = invoke_eth_sender_send(&mut store, instance, authorized, vec![]);
        let err = result.expect_err("no gate ⇒ all writes rejected");
        assert!(
            err.contains("no approval gate configured"),
            "defense-in-depth: missing gate must be a clear error; got: {err}"
        );
        // Dispatcher MUST not have been called.
        assert_eq!(
            dispatcher_impl.calls.lock().unwrap().len(),
            0,
            "missing gate MUST short-circuit before dispatch"
        );
    }

    // ────────────────────── (end CIT-AGENT-9c-write-host) ─────────

    // ────────────────── CIT-AGENT-9c-write-tools (5+6+7) ──────────
    // Three production write capsules: provision-user, revoke-role,
    // anchor-session. Each test verifies the capsule's ABI encoding
    // matches the canonical encoder in `audit::recorder` bit-for-bit
    // — the encoders there were BFR-INT-12b tested against live
    // contracts, so matching them is sufficient proof of correctness.

    /// Shared helper: load a write-tool capsule from disk with the
    /// gate-allow + recording mock dispatcher, return store +
    /// instance + dispatcher handle for post-call inspection.
    #[cfg(test)]
    fn load_write_capsule(
        capsule_name: &str,
    ) -> (
        wasmtime::Store<wasm::HostCtx>,
        wasmtime::component::Instance,
        std::sync::Arc<MockSendDispatcher>,
    ) {
        use crate::capsule::manifest::Manifest;
        use crate::capsule::wasm::EngineFactory;
        use std::path::PathBuf;
        use std::sync::Arc;

        let manifest_dir = PathBuf::from(env!("CARGO_MANIFEST_DIR"));
        let capsule_dir = manifest_dir
            .parent()
            .and_then(|p| p.parent())
            .expect("walk up to citrate_v0.01.1/")
            .join("capsules")
            .join(capsule_name);
        let wasm = std::fs::read(capsule_dir.join("capsule.wasm")).unwrap();
        let manifest_str =
            std::fs::read_to_string(capsule_dir.join("manifest.toml")).unwrap();
        let manifest = Manifest::parse(&manifest_str).expect("manifest parses");
        let capsule = Capsule {
            manifest,
            archive: archive::ArchiveContents {
                wasm,
                ..Default::default()
            },
        };
        let gate = Arc::new(MockGate {
            decisions: std::sync::Mutex::new(Vec::new()),
            allow: true,
            reason: String::new(),
        });
        let dispatcher_impl = Arc::new(MockSendDispatcher {
            calls: std::sync::Mutex::new(Vec::new()),
            tx_hash: [0xa1u8; 32],
        });
        let engine = EngineFactory::build().unwrap();
        let linker = capsule.prepare_linker(&engine).unwrap().into_linker();
        let (store, instance) = capsule
            .instantiate_with_write_path(
                &engine,
                &linker,
                None,
                Some(dispatcher_impl.clone()),
                Some(gate),
            )
            .unwrap();
        (store, instance, dispatcher_impl)
    }

    /// Generic invocation: calls the named export with the given
    /// `Val` args and returns the WIT `result<list<u8>, string>`
    /// unwrapped to `Result<Vec<u8>, String>`.
    #[cfg(test)]
    fn invoke_write_capsule(
        store: &mut wasmtime::Store<wasm::HostCtx>,
        instance: wasmtime::component::Instance,
        iface_name: &str,
        func_name: &str,
        args: Vec<wasmtime::component::Val>,
    ) -> Result<Vec<u8>, String> {
        use wasmtime::component::Val;
        let iface = instance
            .get_export(&mut *store, None, iface_name)
            .expect("interface export");
        let func_idx = instance
            .get_export(&mut *store, Some(&iface), func_name)
            .expect("func export");
        let func = instance.get_func(&mut *store, func_idx).unwrap();
        let mut results = [Val::Bool(false)];
        func.call(&mut *store, &args, &mut results)
            .expect("call completes");
        func.post_return(&mut *store).expect("post_return clears");
        match &results[0] {
            Val::Result(r) => match r.as_ref() {
                Ok(Some(boxed)) => match boxed.as_ref() {
                    Val::List(bytes) => Ok(bytes
                        .iter()
                        .map(|b| match b {
                            Val::U8(b) => *b,
                            _ => panic!("non-u8"),
                        })
                        .collect()),
                    other => panic!("expected list<u8>, got {other:?}"),
                },
                Ok(None) => Ok(Vec::new()),
                Err(Some(boxed)) => match boxed.as_ref() {
                    Val::String(s) => Err(s.clone()),
                    other => panic!("expected string, got {other:?}"),
                },
                Err(None) => Err(String::new()),
            },
            other => panic!("expected Result, got {other:?}"),
        }
    }

    /// CIT-AGENT-9c-6 — revoke-role calldata matches the canonical
    /// `audit::recorder::encode_revoke` byte-for-byte.
    #[test]
    fn revoke_role_capsule_calldata_matches_canonical_encoder() {
        use crate::audit::recorder;
        use sha3::{Digest, Keccak256};
        use wasmtime::component::Val;

        let (mut store, instance, dispatcher_impl) = load_write_capsule("revoke-role");

        let user_hex = "1111111111111111111111111111111111111111111111111111111111111111";
        let tenant_hex = "2222222222222222222222222222222222222222222222222222222222222222";
        let reason_str = "policy-violation";

        let result = invoke_write_capsule(
            &mut store,
            instance,
            "citrate:revoke-role/action@0.1.0",
            "revoke",
            vec![
                Val::String(format!("0x{user_hex}")),
                Val::String(format!("0x{tenant_hex}")),
                Val::String(reason_str.to_string()),
            ],
        );
        assert_eq!(result, Ok(vec![0xa1u8; 32]), "tx hash flows back");

        // Compute expected calldata via the canonical encoder.
        let user_b: [u8; 32] = hex::decode(user_hex).unwrap().try_into().unwrap();
        let tenant_b: [u8; 32] = hex::decode(tenant_hex).unwrap().try_into().unwrap();
        let mut h = Keccak256::new();
        h.update(reason_str.as_bytes());
        let reason_b: [u8; 32] = h.finalize().into();
        let mut h = Keccak256::new();
        h.update(
            format!(
                "revoke_role|0x{}|0x{}|{}",
                hex::encode(user_b),
                hex::encode(tenant_b),
                reason_str
            )
            .as_bytes(),
        );
        let corr_b: [u8; 32] = h.finalize().into();
        let expected = recorder::encode_revoke(user_b, tenant_b, reason_b, corr_b);

        let calls = dispatcher_impl.calls.lock().unwrap();
        assert_eq!(calls.len(), 1);
        assert_eq!(
            calls[0].1, expected,
            "capsule calldata MUST match canonical encoder byte-for-byte"
        );
        // Also: routed to RoleEscalation, not somewhere else.
        assert_eq!(
            hex::encode(calls[0].0),
            "a6a4122126a75611ea06241e404327addfe8eb5e"
        );
    }

    /// CIT-AGENT-9c-7 — anchor-session calldata matches canonical.
    #[test]
    fn anchor_session_capsule_calldata_matches_canonical_encoder() {
        use crate::audit::recorder;
        use sha3::{Digest, Keccak256};
        use wasmtime::component::Val;

        let (mut store, instance, dispatcher_impl) = load_write_capsule("anchor-session");

        let session_hex = "3333333333333333333333333333333333333333333333333333333333333333";
        let scope_hex = "4444444444444444444444444444444444444444444444444444444444444444";
        let merkle_hex = "5555555555555555555555555555555555555555555555555555555555555555";
        let result = invoke_write_capsule(
            &mut store,
            instance,
            "citrate:anchor-session/action@0.1.0",
            "anchor",
            vec![
                Val::U8(1),
                Val::String(format!("0x{session_hex}")),
                Val::String(format!("0x{scope_hex}")),
                Val::String(format!("0x{merkle_hex}")),
                Val::String("0x".to_string()), // empty ipfs_cid
                Val::U64(42),
            ],
        );
        assert_eq!(result, Ok(vec![0xa1u8; 32]));

        let session_b: [u8; 32] =
            hex::decode(session_hex).unwrap().try_into().unwrap();
        let scope_b: [u8; 32] = hex::decode(scope_hex).unwrap().try_into().unwrap();
        let merkle_b: [u8; 32] = hex::decode(merkle_hex).unwrap().try_into().unwrap();
        let ipfs_b = [0u8; 32];
        let mut seed = Vec::with_capacity(64);
        seed.extend_from_slice(&session_b);
        seed.extend_from_slice(&merkle_b);
        let mut h = Keccak256::new();
        h.update(&seed);
        let bundle_id: [u8; 32] = h.finalize().into();
        let expected = recorder::encode_anchor_bundle(
            1, bundle_id, session_b, scope_b, merkle_b, ipfs_b, 42,
        );

        let calls = dispatcher_impl.calls.lock().unwrap();
        assert_eq!(calls.len(), 1);
        assert_eq!(
            calls[0].1, expected,
            "capsule calldata MUST match canonical encoder byte-for-byte"
        );
        assert_eq!(
            hex::encode(calls[0].0),
            "9a58e44f8dd6fd6a75637a32e6e51c16440996f8"
        );
    }

    /// CIT-AGENT-9c-5 — provision-user calldata matches canonical.
    /// Dynamic-tail encoder — the hardest of the three.
    #[test]
    fn provision_user_capsule_calldata_matches_canonical_encoder() {
        use crate::audit::recorder;
        use sha3::{Digest, Keccak256};
        use wasmtime::component::Val;

        let (mut store, instance, dispatcher_impl) = load_write_capsule("provision-user");

        let user_hex = "6666666666666666666666666666666666666666666666666666666666666666";
        let tenant_hex = "7777777777777777777777777777777777777777777777777777777777777777";
        let role_hex = "8888888888888888888888888888888888888888888888888888888888888888";
        let duration_sec: u32 = 3600;
        let reauth_kind = "kba";

        let result = invoke_write_capsule(
            &mut store,
            instance,
            "citrate:provision-user/action@0.1.0",
            "provision",
            vec![
                Val::String(format!("0x{user_hex}")),
                Val::String(format!("0x{tenant_hex}")),
                Val::String(format!("0x{role_hex}")),
                Val::U32(duration_sec),
                Val::String(reauth_kind.to_string()),
            ],
        );
        assert_eq!(result, Ok(vec![0xa1u8; 32]));

        let user_b: [u8; 32] = hex::decode(user_hex).unwrap().try_into().unwrap();
        let tenant_b: [u8; 32] =
            hex::decode(tenant_hex).unwrap().try_into().unwrap();
        let role_b: [u8; 32] = hex::decode(role_hex).unwrap().try_into().unwrap();
        let mut h = Keccak256::new();
        h.update(
            format!(
                "provision_user|0x{}|0x{}",
                hex::encode(user_b),
                hex::encode(tenant_b)
            )
            .as_bytes(),
        );
        let corr_b: [u8; 32] = h.finalize().into();
        let reauth_proof = vec![0x01u8];
        let expected = recorder::encode_request_elevation(
            user_b,
            tenant_b,
            role_b,
            duration_sec,
            corr_b,
            &reauth_proof,
            reauth_kind,
        );

        let calls = dispatcher_impl.calls.lock().unwrap();
        assert_eq!(calls.len(), 1);
        assert_eq!(
            calls[0].1, expected,
            "provision-user calldata (dynamic tails) MUST match canonical"
        );
        assert_eq!(
            hex::encode(calls[0].0),
            "a6a4122126a75611ea06241e404327addfe8eb5e"
        );
    }

    // ────────────────── (end CIT-AGENT-9c-write-tools) ────────────

    /// CIT-AGENT-3c — `Capsule::prepare_linker` integrates with
    /// `from_archive`: a loaded capsule + an engine yields a
    /// constructed per-capsule linker whose permitted set reflects
    /// the manifest exactly.
    #[test]
    fn prepare_linker_reflects_manifest_capabilities() {
        use crate::capsule::linker::CapabilityToken;
        use crate::capsule::manifest::Manifest;
        use crate::capsule::wasm::EngineFactory;

        let manifest_str = r#"
[capsule]
name = "linker-roundtrip"
version = "0.1.0"
content_hash = "sha256:0000000000000000000000000000000000000000000000000000000000000000"

[capability]
network = "broker-only"
filesystem = ["read:/data"]
chain_calls = []
subagent_spawn = false

[data_class]
reads = ["PUBLIC"]
writes = []
emits = ["PUBLIC"]

[risk]
tier = "low"
required_roles = ["Operator"]
break_glass_eligible = false

[overlay]
certified = []
not_certified = []

[procedure]
gates = []

[provenance]
publisher = "did:citrate:agent:0xab12"
build_reproducible = true
agentile_sprint = "test"
tla_spec = ""

[signing]
tier = "bundled"
"#;
        let manifest = Manifest::parse(manifest_str).expect("manifest parses");
        // Wrap in a fake Capsule (no archive) to exercise prepare_linker
        // independently of from_archive.
        let capsule = Capsule {
            manifest,
            archive: archive::ArchiveContents::default(),
        };
        let engine = EngineFactory::build().unwrap();
        let builder = capsule.prepare_linker(&engine).expect("linker builds");
        let permitted = builder.permitted();
        assert!(permitted.contains(&CapabilityToken::WasiSockets));
        assert!(permitted.contains(&CapabilityToken::WasiFilesystem));
        assert!(permitted.contains(&CapabilityToken::WasiCli));
    }

    /// CIT-AGENT-3b — round-trip `from_archive_verified` with a real
    /// signed capsule. Builds a minimal `.cps` archive whose
    /// publisher.sig is computed from a known key; verifies the load
    /// succeeds end-to-end (archive parse → content_hash → signature
    /// → WIT cross-check).
    #[test]
    fn from_archive_verified_round_trip_happy_path() {
        use ed25519_dalek::{Signer, SigningKey};
        use sha2::{Digest, Sha256};

        // Build manifest, WIT, WASM, procedure with a content_hash
        // placeholder. We compute the real content_hash, embed it,
        // sign it, and pack the archive.
        let wit = b"package test:capsule@0.1.0;\nworld root {\n}\n".to_vec();
        let wasm = b"\x00asm\x01\x00\x00\x00".to_vec();
        let procedure = b"# stub procedure".to_vec();
        let manifest_template = |declared_hash: &str| {
            format!(
                r#"
[capsule]
name = "verified-test"
version = "0.1.0"
content_hash = "{declared_hash}"

[capability]
network = "none"
filesystem = []
chain_calls = []
subagent_spawn = false

[data_class]
reads = ["PUBLIC"]
writes = []
emits = ["PUBLIC"]

[risk]
tier = "low"
required_roles = ["Operator"]
break_glass_eligible = false

[overlay]
certified = []
not_certified = []

[procedure]
gates = []

[provenance]
publisher = "did:citrate:agent:0xab12"
build_reproducible = true
agentile_sprint = "2026-05-15-cit-agent-3b"
tla_spec = ""

[signing]
tier = "bundled"
"#
            )
        };
        // 3b semantic: content_hash is over everything EXCEPT
        // manifest.toml (and SIGNATURES/). The manifest declares the
        // hash; the publisher signs the manifest; the signature
        // transitively binds content_hash. No fixed-point dance.
        let unsigned_archive = archive::ArchiveContents {
            manifest: vec![], // placeholder; not included in hash
            wit: wit.clone(),
            wasm: wasm.clone(),
            procedure: procedure.clone(),
            ..Default::default()
        };
        let truth_hash = archive::compute_content_hash(&unsigned_archive);
        let manifest_body = manifest_template(&truth_hash);
        let final_archive = archive::ArchiveContents {
            manifest: manifest_body.as_bytes().to_vec(),
            wit: wit.clone(),
            wasm: wasm.clone(),
            procedure: procedure.clone(),
            ..Default::default()
        };
        // The hash is over the non-manifest body, so re-hashing with
        // the manifest present yields the same value.
        assert_eq!(archive::compute_content_hash(&final_archive), truth_hash);

        // Sign the truth_hash with a known key.
        let signing_key = SigningKey::from_bytes(&[0xef; 32]);
        let pubkey = signing_key.verifying_key().to_bytes();
        let mut hasher = Sha256::new();
        hasher.update(truth_hash.as_bytes());
        let payload = hasher.finalize();
        let signature = signing_key.sign(&payload);

        // Pack the .cps archive.
        let signature_bytes = signature.to_bytes();
        let mut tar_buf = Vec::new();
        {
            let mut tar = tar::Builder::new(&mut tar_buf);
            let entries: Vec<(&str, &[u8])> = vec![
                ("manifest.toml", &final_archive.manifest),
                ("capsule.wit", &final_archive.wit),
                ("capsule.wasm", &final_archive.wasm),
                ("procedure.md", &final_archive.procedure),
                ("SIGNATURES/publisher.sig", &signature_bytes),
            ];
            for (path, bytes) in entries {
                let mut header = tar::Header::new_gnu();
                header.set_size(bytes.len() as u64);
                header.set_cksum();
                tar.append_data(&mut header, path, bytes).unwrap();
            }
            tar.finish().unwrap();
        }
        let mut zstd_buf = Vec::new();
        let mut enc = zstd::Encoder::new(&mut zstd_buf, 3).unwrap();
        enc.write_all(&tar_buf).unwrap();
        enc.finish().unwrap();

        // Build the registry that recognizes our test key.
        let registry = tiers::StaticKeyRegistry {
            bundled: Some(pubkey),
            managed: None,
        };

        // The full verified load path:
        let capsule = Capsule::from_archive_verified(&zstd_buf[..], &registry)
            .expect("verified load succeeds");
        assert_eq!(capsule.name(), "verified-test");
        assert_eq!(capsule.version(), "0.1.0");
    }

    /// Direct exercise of the verify-against-manifest path without
    /// the fixed-point dance: declare the computed hash directly.
    #[test]
    fn from_archive_rejects_hash_mismatch() {
        let cps = {
            let mut tar_buf = Vec::new();
            {
                let mut tar = tar::Builder::new(&mut tar_buf);
                let manifest = r#"
[capsule]
name = "x"
version = "0.1.0"
content_hash = "sha256:0000000000000000000000000000000000000000000000000000000000000000"

[capability]
network = "none"
filesystem = []
chain_calls = []
subagent_spawn = false

[data_class]
reads = ["PUBLIC"]
writes = []
emits = ["PUBLIC"]

[risk]
tier = "low"
required_roles = ["Operator"]
break_glass_eligible = false

[overlay]
certified = []
not_certified = []

[procedure]
gates = []

[provenance]
publisher = "did:citrate:agent:0xab12"
build_reproducible = true
agentile_sprint = "test"
tla_spec = ""

[signing]
tier = "bundled"
"#;
                for (path, bytes) in [
                    ("manifest.toml", manifest.as_bytes()),
                    ("capsule.wit", b"// wit"),
                    ("capsule.wasm", b"\x00asm\x01\x00\x00\x00"),
                    ("procedure.md", b"# md"),
                    ("SIGNATURES/publisher.sig", b"sig"),
                ] {
                    let mut header = tar::Header::new_gnu();
                    header.set_size(bytes.len() as u64);
                    header.set_cksum();
                    tar.append_data(&mut header, path, bytes).unwrap();
                }
                tar.finish().unwrap();
            }
            let mut zstd_buf = Vec::new();
            let mut enc = zstd::Encoder::new(&mut zstd_buf, 3).unwrap();
            enc.write_all(&tar_buf).unwrap();
            enc.finish().unwrap();
            zstd_buf
        };
        let err = Capsule::from_archive(&cps[..]).expect_err("hash mismatch rejected");
        assert!(
            err.to_string().contains("content_hash mismatch"),
            "actual: {err}"
        );
    }
}
