//! CIT-AGENT-9c-shell-wire-prep — `CapsuleDispatch` helper.
//!
//! Encapsulates the production wire-up for a fleet of capsules:
//! load capsule archives from a directory at startup, build their
//! per-capsule linkers eagerly, and expose a single `call_raw`
//! method that invokes a named export on a named capsule.
//!
//! The boeing-shell consumes this through a per-tool adapter that
//! translates the chat tool's JSON args into the capsule's WIT
//! types + formats the returned `Val` into a chat-displayable
//! string. Adapter code stays in the consumer crate — this struct
//! is the library boundary.

use crate::capsule::dispatcher::{
    ApprovalGate, EthCallDispatcher, EthSendDispatcher,
};
use crate::capsule::manifest::Manifest;
use crate::capsule::wasm::EngineFactory;
use crate::capsule::{archive, Capsule};
use crate::error::AgentError;
use std::collections::{HashMap, HashSet};
use std::path::Path;
use std::sync::Arc;

/// All-zero placeholder `content_hash` means the capsule was never run through
/// the CIT-AGENT-3e packer (which computes + embeds the real hash and signs the
/// manifest). Such a capsule carries no integrity proof and cannot be verified.
fn is_placeholder_content_hash(h: &str) -> bool {
    h.strip_prefix("sha256:")
        .map(|hex| !hex.is_empty() && hex.bytes().all(|b| b == b'0'))
        .unwrap_or(false)
}

/// A loose-dir capsule is integrity-verified iff its manifest declares a real
/// (non-placeholder) `content_hash` AND that hash matches the hash recomputed
/// over the loaded executable body. This binds the wasm that actually runs to
/// the signed manifest the harness makes policy decisions from.
fn capsule_body_verified(manifest: &Manifest, wasm: &[u8]) -> bool {
    if is_placeholder_content_hash(&manifest.capsule.content_hash) {
        return false;
    }
    let recomputed = archive::compute_content_hash(&archive::ArchiveContents {
        wasm: wasm.to_vec(),
        ..Default::default()
    });
    recomputed == manifest.capsule.content_hash
}

/// Operator opt-in to run capsules that failed integrity verification — intended
/// ONLY for the pre-packer placeholder period. Default (unset) is fail-closed.
fn allow_unverified_capsules() -> bool {
    std::env::var("CITRATE_ALLOW_UNVERIFIED_CAPSULES")
        .map(|v| v == "1" || v.eq_ignore_ascii_case("true"))
        .unwrap_or(false)
}

/// Pre-loaded fleet of capsules sharing one engine + one set of
/// production dispatchers + one approval gate. Build once at
/// startup; call `call_raw(name, ...)` per tool invocation.
pub struct CapsuleDispatch {
    engine: wasmtime::Engine,
    capsules: HashMap<String, Capsule>,
    /// Names of loaded capsules that FAILED integrity verification at load
    /// (placeholder or mismatched content_hash). `call_raw` refuses to
    /// instantiate these unless `CITRATE_ALLOW_UNVERIFIED_CAPSULES` is set.
    unverified: HashSet<String>,
    eth_call_dispatcher: Option<Arc<dyn EthCallDispatcher>>,
    eth_send_dispatcher: Option<Arc<dyn EthSendDispatcher>>,
    approval_gate: Option<Arc<dyn ApprovalGate>>,
}

impl CapsuleDispatch {
    /// Scan `dir` for `<capsule-name>/{manifest.toml,capsule.wasm}`
    /// pairs and load each into the dispatch fleet. Subdirectories
    /// without both files are silently skipped (allows the
    /// directory to coexist with non-capsule scaffolding like the
    /// `wit/` and `gherkin/` companion dirs documented in
    /// planset 03).
    pub fn load_from_dir(
        dir: &Path,
        eth_call_dispatcher: Option<Arc<dyn EthCallDispatcher>>,
        eth_send_dispatcher: Option<Arc<dyn EthSendDispatcher>>,
        approval_gate: Option<Arc<dyn ApprovalGate>>,
    ) -> Result<Self, AgentError> {
        let engine = EngineFactory::build()?;
        let mut capsules = HashMap::new();
        let mut unverified = HashSet::new();
        let entries = std::fs::read_dir(dir).map_err(|e| {
            AgentError::Capsule(format!("read capsule dir {dir:?}: {e}"))
        })?;
        for entry in entries {
            let entry = entry
                .map_err(|e| AgentError::Capsule(format!("read_dir entry: {e}")))?;
            let path = entry.path();
            if !path.is_dir() {
                continue;
            }
            let manifest_path = path.join("manifest.toml");
            let wasm_path = path.join("capsule.wasm");
            if !manifest_path.exists() || !wasm_path.exists() {
                continue;
            }
            let manifest_str = std::fs::read_to_string(&manifest_path)
                .map_err(|e| AgentError::Capsule(format!("read manifest: {e}")))?;
            let manifest = Manifest::parse(&manifest_str)?;
            let wasm = std::fs::read(&wasm_path)
                .map_err(|e| AgentError::Capsule(format!("read wasm: {e}")))?;
            // RM-A WP-AGENT_RUNTIME-001: record integrity status at load.
            // Enforcement is deferred to `call_raw` so the doctor/inspection
            // paths can still enumerate the fleet without executing it.
            if !capsule_body_verified(&manifest, &wasm) {
                unverified.insert(manifest.capsule.name.clone());
            }
            let capsule = Capsule {
                manifest: manifest.clone(),
                archive: archive::ArchiveContents {
                    wasm,
                    ..Default::default()
                },
            };
            capsules.insert(manifest.capsule.name.clone(), capsule);
        }
        Ok(Self {
            engine,
            capsules,
            unverified,
            eth_call_dispatcher,
            eth_send_dispatcher,
            approval_gate,
        })
    }

    /// Names of every loaded capsule, alphabetized. Used by the
    /// boeing-shell startup smoke ("the fleet has all 7 capsules
    /// I expect") + by the doctor pre-flight check.
    pub fn capsule_names(&self) -> Vec<String> {
        let mut names: Vec<String> = self.capsules.keys().cloned().collect();
        names.sort();
        names
    }

    /// Whether `capsule_name` is in the fleet.
    pub fn has(&self, capsule_name: &str) -> bool {
        self.capsules.contains_key(capsule_name)
    }

    /// Low-level invocation: instantiate the named capsule, look
    /// up `iface.func`, call with the given Vals, return the
    /// single result Val. The boeing-shell adapter does the JSON
    /// → Val + Val → chat-string translation per-tool.
    pub fn call_raw(
        &self,
        capsule_name: &str,
        iface_name: &str,
        func_name: &str,
        args: &[wasmtime::component::Val],
    ) -> Result<wasmtime::component::Val, AgentError> {
        let capsule = self.capsules.get(capsule_name).ok_or_else(|| {
            AgentError::Capsule(format!("capsule {capsule_name:?} not loaded"))
        })?;

        // RM-A WP-AGENT_RUNTIME-2026-05-31-001 (CRITICAL): fail-closed integrity
        // gate. Refuse to instantiate a capsule whose executable wasm is not
        // bound to a valid manifest `content_hash` (no integrity proof). Until
        // the CIT-AGENT-3e packer embeds real hashes + signatures (today every
        // capsule carries the all-zero placeholder), running an unverified
        // capsule requires an explicit, loudly-logged operator opt-in — never
        // the silent default that this path used to be.
        if self.unverified.contains(capsule_name) {
            if allow_unverified_capsules() {
                tracing::warn!(
                    capsule = capsule_name,
                    "INSTANTIATING UNVERIFIED CAPSULE: wasm is not bound to a valid manifest \
                     content_hash. Permitted only because CITRATE_ALLOW_UNVERIFIED_CAPSULES is \
                     set — this MUST NOT be set in production once capsules are packed/signed."
                );
            } else {
                return Err(AgentError::Capsule(format!(
                    "refusing to instantiate unverified capsule {capsule_name:?}: its wasm is not \
                     bound to a valid manifest content_hash (no integrity proof). Pack and sign \
                     the capsule (CIT-AGENT-3e), or set CITRATE_ALLOW_UNVERIFIED_CAPSULES=1 for \
                     development only."
                )));
            }
        }

        let linker = capsule.prepare_linker(&self.engine)?.into_linker();
        let (mut store, instance) = capsule.instantiate_with_write_path(
            &self.engine,
            &linker,
            self.eth_call_dispatcher.clone(),
            self.eth_send_dispatcher.clone(),
            self.approval_gate.clone(),
        )?;
        // REM-12 (wasmtime 26 → 45): `Instance::get_export` now returns
        // `(ComponentItem, ComponentExportIndex)`. The second `get_export`
        // call (looking up a func within an iface) takes only the index,
        // not the tuple — so we pluck `.1` from the iface lookup before
        // passing it through. `Instance::get_func` likewise wants the
        // index alone now (the `InstanceExportLookup` trait is impl'd
        // for `ComponentExportIndex`, not the tuple).
        let iface = instance
            .get_export(&mut store, None, iface_name)
            .ok_or_else(|| {
                AgentError::Capsule(format!(
                    "capsule {capsule_name:?} missing interface {iface_name:?}"
                ))
            })?;
        let (_, iface_idx) = iface;
        let func_export = instance
            .get_export(&mut store, Some(&iface_idx), func_name)
            .ok_or_else(|| {
                AgentError::Capsule(format!(
                    "capsule {capsule_name:?} interface {iface_name:?} missing func {func_name:?}"
                ))
            })?;
        let (_, func_idx) = func_export;
        let func = instance.get_func(&mut store, func_idx).ok_or_else(|| {
            AgentError::Capsule(format!(
                "capsule {capsule_name:?} func {func_name:?} resolve failed"
            ))
        })?;

        // REM-12b (2026-05-20): arm the per-call epoch deadline.
        // EngineFactory::build set Config::epoch_interruption(true)
        // (REM-12a); this is the per-call deadline. After N epoch
        // ticks the call traps (caller sees Err). The background
        // ticker that advances the engine's epoch counter must be
        // wired separately (TODO: spawn a tokio task per Dispatch
        // that ticks the engine.increment_epoch() every 50ms).
        // Until the ticker is wired this deadline is inert; the
        // deadline is set here so wiring the ticker is a one-line
        // change. See REM-12a in 06_REMEDIATION_PLAN.md.
        store.set_epoch_deadline(/* ticks */ 600); // 600 * 50ms = 30s budget when ticker is on

        // REM-12b CLOSED (2026-05-23, wasmtime-45 bump): bound capsule
        // resource appetite per call. The previous (wasmtime-26)
        // OnceLock<StoreLimits> placeholder returned a `&StoreLimits`
        // where the `Store::limiter` API expects `&mut dyn
        // ResourceLimiter`; that was a documented "doc-only intent"
        // gap waiting for the wasmtime bump.
        //
        // The bump lands the real binding by hoisting StoreLimits to
        // a `HostCtx::store_limits` field. The limiter closure now
        // returns `&mut state.store_limits` where `state: &mut HostCtx`
        // is the closure's per-call argument — which lives as long as
        // the Store and is independently borrow-checkable. This is the
        // canonical wasmtime pattern (see wasmtime::Store::limiter
        // docs).
        //
        // Numbers chosen conservatively for the current capsule set
        // (largest in-tree capsule ~16 MiB heap, single table, single
        // instance per call). Revisit when capsule diversity grows.
        store.data_mut().store_limits = wasmtime::StoreLimitsBuilder::new()
            .memory_size(64 * 1024 * 1024) // 64 MiB hard cap
            .tables(1)
            .table_elements(10_000)
            .instances(1)
            .build();
        store.limiter(|state| &mut state.store_limits);

        let mut results = [wasmtime::component::Val::Bool(false)];

        // REM-12c (2026-05-20): catch_unwind around func.call.
        // F-04 RUSTSEC-2026-0085 + 2026-0092 panic during host-side
        // lift / transcode. Without catch_unwind, the panic propagates
        // through the dispatcher and aborts the entire agent-runtime
        // process. Wrapping degrades it to a per-call AgentError so
        // a single hostile capsule cannot kill the runtime. See
        // F-04_FP_CHECK.md §8 and REM-12c.
        //
        // NOTE: this catches host-Rust panics. WASM-level traps come
        // back as Err from func.call (already handled below) and
        // don't unwind, so catch_unwind is a no-op for them.
        let call_result = std::panic::catch_unwind(
            std::panic::AssertUnwindSafe(|| {
                func.call(&mut store, args, &mut results)
            }),
        );
        match call_result {
            Ok(Ok(())) => {}
            Ok(Err(e)) => return Err(AgentError::Capsule(format!("capsule call: {e}"))),
            Err(panic_payload) => {
                let msg = panic_payload
                    .downcast_ref::<&str>()
                    .map(|s| s.to_string())
                    .or_else(|| panic_payload.downcast_ref::<String>().cloned())
                    .unwrap_or_else(|| "<non-string panic payload>".to_string());
                return Err(AgentError::Capsule(format!(
                    "capsule call panicked (host-side lift/transcode panic; \
                     see RUSTSEC-2026-0085, 2026-0092 and F-04 in the audit): {msg}"
                )));
            }
        }
        // REM-12 (wasmtime 26 → 45): `Func::post_return` is now a
        // documented no-op (per the v45 deprecation notice on the
        // method: "no longer needs to be called; this function has
        // no effect"). The component-model runtime handles the
        // post-return state internally. Removing the call eliminates
        // the deprecation warning without behavior change.
        Ok(std::mem::replace(
            &mut results[0],
            wasmtime::component::Val::Bool(false),
        ))
    }

    /// Inspection accessor for the host context history (audit +
    /// tests). Note: each call to `call_raw` creates a fresh store,
    /// so the history is per-invocation; the boeing-shell adapter
    /// should drain the history via the linker's post-call inspection
    /// if it wants to retain it.
    pub fn engine(&self) -> &wasmtime::Engine {
        &self.engine
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::path::PathBuf;

    /// Loading the full BFR-INT-12 fleet from disk: all 7 capsules
    /// present + correctly named.
    #[test]
    fn load_full_fleet() {
        let manifest_dir = PathBuf::from(env!("CARGO_MANIFEST_DIR"));
        let capsules_root = manifest_dir
            .parent()
            .and_then(|p| p.parent())
            .expect("walk up to citrate_v0.01.1/")
            .join("capsules");
        let dispatch =
            CapsuleDispatch::load_from_dir(&capsules_root, None, None, None)
                .expect("loads cleanly");
        let names = dispatch.capsule_names();
        // 7 BFR-INT-12 tool capsules + 3 supporting/test capsules
        // (hello, echo-chain, eth-sender-test). The fleet has at
        // LEAST the 7 BFR tools; the supporting ones come along
        // as siblings in the same dir.
        for expected in &[
            "list-compliance-posture",
            "query-decisions-by-tenant",
            "query-supplier-status",
            "verify-provenance-chain",
            "provision-user",
            "revoke-role",
            "anchor-session",
        ] {
            assert!(
                dispatch.has(expected),
                "fleet must include {expected}; loaded: {names:?}"
            );
        }
    }

    // ── RM-A WP-AGENT_RUNTIME-001 tripwires (red on the unfixed dispatch) ──

    const PLACEHOLDER_HASH: &str =
        "sha256:0000000000000000000000000000000000000000000000000000000000000000";

    fn manifest_with_hash(content_hash: &str) -> Manifest {
        let toml = format!(
            r#"
[capsule]
name = "tripwire-cap"
version = "0.1.0"
content_hash = "{content_hash}"
[capability]
network = "none"
subagent_spawn = false
[data_class]
[risk]
tier = "low"
break_glass_eligible = false
[overlay]
[provenance]
publisher = "did:citrate:test"
build_reproducible = true
agentile_sprint = "rm-a-tripwire"
[signing]
tier = "bundled"
"#
        );
        Manifest::parse(&toml).expect("tripwire manifest parses")
    }

    #[test]
    fn tripwire_placeholder_content_hash_is_unverified() {
        assert!(is_placeholder_content_hash(PLACEHOLDER_HASH));
        assert!(!is_placeholder_content_hash(
            "sha256:deadbeef00000000000000000000000000000000000000000000000000000000"
        ));
        // A capsule shipped with the placeholder hash carries no integrity proof.
        let m = manifest_with_hash(PLACEHOLDER_HASH);
        assert!(!capsule_body_verified(&m, b"\x00asm\x01\x00\x00\x00"));
    }

    #[test]
    fn tripwire_matching_content_hash_is_verified_and_tamper_is_not() {
        let wasm = b"\x00asm\x01\x00\x00\x00".to_vec();
        let real = archive::compute_content_hash(&archive::ArchiveContents {
            wasm: wasm.clone(),
            ..Default::default()
        });
        let m = manifest_with_hash(&real);
        // Honest wasm bound to the declared hash → verified.
        assert!(capsule_body_verified(&m, &wasm));
        // Tampered wasm under the same manifest → not verified.
        assert!(!capsule_body_verified(&m, b"\x00asm\x01\x00\x00\xff"));
    }

    #[test]
    fn tripwire_unverified_capsule_refused_by_default() {
        let manifest_dir = PathBuf::from(env!("CARGO_MANIFEST_DIR"));
        let capsules_root = manifest_dir
            .parent()
            .and_then(|p| p.parent())
            .expect("walk up to repo root")
            .join("capsules");
        let dispatch = CapsuleDispatch::load_from_dir(&capsules_root, None, None, None)
            .expect("loads cleanly");
        // The shipped fleet carries placeholder hashes → all flagged unverified.
        assert!(
            !dispatch.unverified.is_empty(),
            "placeholder-hashed capsules must be flagged unverified"
        );
        // With the override unset (normal/CI default), call_raw refuses to
        // instantiate an unverified capsule BEFORE touching the linker.
        if !allow_unverified_capsules() {
            let name = dispatch
                .capsule_names()
                .into_iter()
                .next()
                .expect("fleet is non-empty");
            let err = dispatch
                .call_raw(&name, "iface", "func", &[])
                .expect_err("unverified capsule must be refused by default");
            assert!(
                err.to_string().to_lowercase().contains("unverified"),
                "refusal must cite the missing integrity proof, got: {err}"
            );
        }
    }
}
