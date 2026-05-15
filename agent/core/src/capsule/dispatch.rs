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
        let mut results = [wasmtime::component::Val::Bool(false)];
        func.call(&mut store, args, &mut results)
            .map_err(|e| AgentError::Capsule(format!("capsule call: {e}")))?;
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
