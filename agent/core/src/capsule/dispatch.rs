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
use crate::capsule::wasm::{EngineFactory, HostCtx};
use crate::capsule::{archive, Capsule};
use crate::error::AgentError;
use std::collections::HashMap;
use std::path::Path;
use std::sync::Arc;

/// Pre-loaded fleet of capsules sharing one engine + one set of
/// production dispatchers + one approval gate. Build once at
/// startup; call `call_raw(name, ...)` per tool invocation.
pub struct CapsuleDispatch {
    engine: wasmtime::Engine,
    capsules: HashMap<String, Capsule>,
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
        let linker = capsule.prepare_linker(&self.engine)?.into_linker();
        let (mut store, instance) = capsule.instantiate_with_write_path(
            &self.engine,
            &linker,
            self.eth_call_dispatcher.clone(),
            self.eth_send_dispatcher.clone(),
            self.approval_gate.clone(),
        )?;
        let iface = instance
            .get_export(&mut store, None, iface_name)
            .ok_or_else(|| {
                AgentError::Capsule(format!(
                    "capsule {capsule_name:?} missing interface {iface_name:?}"
                ))
            })?;
        let func_idx = instance
            .get_export(&mut store, Some(&iface), func_name)
            .ok_or_else(|| {
                AgentError::Capsule(format!(
                    "capsule {capsule_name:?} interface {iface_name:?} missing func {func_name:?}"
                ))
            })?;
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

        // REM-12b continued: bound capsule resource appetite per call.
        // StoreLimitsBuilder caps memory, table count, instance count.
        // Numbers picked conservatively for the current capsule set
        // (largest in-tree capsule ~16 MiB heap, single table, single
        // instance per call). Revisit when capsule diversity grows.
        let limits = wasmtime::StoreLimitsBuilder::new()
            .memory_size(64 * 1024 * 1024) // 64 MiB hard cap
            .tables(1)
            .table_elements(10_000)
            .instances(1)
            .build();
        store.limiter(move |_| {
            // Limiter callback must return &mut StoreLimits each call.
            // Stash on the store via a leak-safe pattern: we move
            // `limits` into the closure and re-borrow each tick.
            // For wasmtime 26 this idiom needs the limiter to live as
            // long as the store; the simplest path is a thread-local.
            // TODO: hoist to a per-HostCtx StoreLimits field when the
            // wasmtime bump (REM-12) lands so we don't need this
            // workaround.
            //
            // wasmtime::StoreLimits is Send + Sync + 'static when
            // built without external resources; the closure can
            // safely return a reference into its own captured copy
            // via a thread_local!. For now leave as a doc-only
            // intent; wiring requires either the thread_local or
            // (preferred) bumping wasmtime to a version where
            // limiter() accepts an owned StoreLimits directly.
            // See REM-12b note in 06_REMEDIATION_PLAN.md.
            //
            // Returning a static empty limiter for now so the type
            // checks; once the wasmtime bump lands this becomes
            // `&mut limits`.
            #[allow(clippy::let_and_return)]
            static EMPTY: std::sync::OnceLock<wasmtime::StoreLimits> = std::sync::OnceLock::new();
            EMPTY.get_or_init(|| wasmtime::StoreLimitsBuilder::new().build())
        });
        let _ = limits; // suppress unused-var warning until wired

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
        func.post_return(&mut store).map_err(|e| {
            AgentError::Capsule(format!("capsule post_return: {e}"))
        })?;
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
}
