//! Citrate Agent Core — the cit-agent harness library.
//!
//! Reference: RFC-CIT-AGENT-0001 v0.1 §3 (architecture) + §9.1 (TLA+
//! normative specs).
//!
//! The library is organized as eight top-level modules, one per
//! RFC §3.1 subsystem. CIT-AGENT-1 lands the skeleton + the first
//! two populated modules (`hitl` carries `ApprovalQueue` from
//! BFR-INT-12b; `audit` carries `RecorderClient`). The other six
//! land in CIT-AGENT-2..7 per
//! [`.agentile/planset/2026-05-14-citrate-agent/08_SPRINT_SEQUENCE.md`].
//!
//! Public API surface (RFC §3.2 — frozen until v1.0):
//!   - Re-exports: `ApprovalQueue`, `RecorderClient` (today)
//!   - Future: `Agent`, `Capsule`, `PolicyBundle`, `AuditChain`
//!     (CIT-AGENT-3..5)
//!   - Traits: `Model`, `AuditSink` (CIT-AGENT-3, 5)

// PBA-R2 tripwire: `insecure-dev-hitl` disables the authorized-signer roster
// (HITL quorum, break-glass, audit-chain role signatures). It must never reach
// an optimized build. See also `tests::insecure_dev_hitl_is_off_everywhere`.
#[cfg(all(feature = "insecure-dev-hitl", not(debug_assertions)))]
compile_error!(
    "the `insecure-dev-hitl` feature disables HITL signer-roster checks and must never be \
     enabled in a release build"
);

pub mod agent;
pub mod audit;
pub mod capsule;
pub mod chain;
pub mod doctor;
pub mod hitl;
pub mod model;
pub mod policy;

pub mod error;
pub mod types;

// Public re-exports — the BFR-INT-12b types that defense_prime-shell consumes
// directly. Per RFC §3.2 the v1.0 frozen surface lists these by name.
pub use audit::RecorderClient;
pub use hitl::{
    ApprovalOutcomePublic, ApprovalQueue, PendingView, ToolCall, ToolResult,
};

// CIT-AGENT-9c-shell-wire-cutover — re-export `wasmtime` so the
// capsule-dispatch consumer (defense_prime-shell + future agent shells)
// can pass typed `Val` args to `CapsuleDispatch::call_raw` without
// taking a direct wasmtime dep. The capsule library OWNS the
// wasmtime version pinning; consumers SHOULD NOT depend on
// wasmtime directly to avoid version skew.
pub use wasmtime;

#[cfg(test)]
mod insecure_feature_tripwire {
    /// PBA-R2 tripwire: `insecure-dev-hitl` stays OFF in every build. It is
    /// not enabled for this test build (so not by `default` or by a workspace
    /// dependent), no Cargo manifest in the workspace turns it on, and the
    /// only mention is its definition in agent/core/Cargo.toml.
    #[test]
    fn insecure_dev_hitl_is_off_everywhere() {
        const _: () = assert!(
            !cfg!(feature = "insecure-dev-hitl"),
            "insecure-dev-hitl is enabled in this build"
        );
        let root = std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
            .parent()
            .and_then(|p| p.parent())
            .expect("workspace root");
        let mut manifests = vec![root.join("Cargo.toml")];
        let mut stack = vec![root.to_path_buf()];
        while let Some(dir) = stack.pop() {
            let Ok(rd) = std::fs::read_dir(&dir) else { continue };
            for e in rd.flatten() {
                let p = e.path();
                let name = e.file_name().to_string_lossy().into_owned();
                if p.is_dir() {
                    if !name.starts_with('.') && name != "target" && name != "node_modules" {
                        stack.push(p);
                    }
                } else if name == "Cargo.toml" && p != root.join("Cargo.toml") {
                    manifests.push(p);
                }
            }
        }
        let core_manifest = root.join("agent").join("core").join("Cargo.toml");
        for m in &manifests {
            let text = std::fs::read_to_string(m).expect("read manifest");
            for line in text.lines() {
                let code = line.split('#').next().unwrap_or("");
                if !code.contains("insecure-dev-hitl") {
                    continue;
                }
                assert!(
                    m == &core_manifest && code.trim() == "insecure-dev-hitl = []",
                    "{}: `{}` enables or re-exports insecure-dev-hitl",
                    m.display(),
                    line.trim()
                );
            }
        }
    }
}
