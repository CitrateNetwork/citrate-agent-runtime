//! `hermes-anchor` — the optional on-chain decision sink (HERMES-L-S2.2b).
//!
//! Maps a [`hermes_core::decision::ApprovalDecision`] onto an
//! `AgentDecisionRegistryV2.record(...)` call via the runtime's
//! [`citrate_agent_core::RecorderClient`], so every owner approve/deny is anchored on
//! chain 40204 — the same registry the rest of the runtime's audit trail uses.
//!
//! This is **additive**: the daemon's always-on tracing sink already records every
//! decision locally. Anchoring fires-and-forgets on a tokio task so chain latency never
//! gates the owner's button click, and a failed anchor is a warning (the local record
//! stands), never a lost decision.
//!
//! Construction is owner-gated (the custody discipline from INFER-S1): no registry
//! address → no anchoring; no signer key → no anchoring. [`ChainDecisionSink::from_env`]
//! returns `None` in either case, and the daemon falls back to journald-only.

use std::sync::Arc;

use citrate_agent_core::audit::recorder::{DecisionParams, DecisionStatus};
use citrate_agent_core::RecorderClient;
use hermes_core::decision::{ApprovalDecision, DecisionSink};
use sha3::{Digest, Keccak256};

/// `EventClass::Audit` (u8 `9`) per the `AgentDecisionRegistryV2` enum — the class for
/// "this entry exists for after-the-fact audit, not to drive a workflow", which is exactly
/// what an owner-approval decision is.
const EVENT_CLASS_AUDIT: u8 = 9;

/// Cap the on-chain `description` so a long proposed message can't blow up calldata/gas.
/// The full effect is always in the local record; the chain commits to a bounded copy plus
/// the `artifact_root` hash of the *complete* effect (so the full text is provable).
const MAX_DESC_BYTES: usize = 400;

/// An on-chain decision sink. Holds a shared [`RecorderClient`] (cheap to clone) and the
/// decision-registry address it writes to.
pub struct ChainDecisionSink {
    recorder: Arc<RecorderClient>,
    registry_addr: String,
}

impl ChainDecisionSink {
    /// Build from explicit parts (for tests / callers that already have a recorder).
    pub fn new(recorder: Arc<RecorderClient>, registry_addr: impl Into<String>) -> Self {
        Self { recorder, registry_addr: registry_addr.into() }
    }

    /// Build from the environment. Returns `None` (anchoring disabled) unless **both**:
    ///   - `HERMES_DECISION_REGISTRY` is a non-empty registry address, and
    ///   - a signer is available (`DEPLOYER_PRIVATE_KEY` or `.env.testnet`).
    ///
    /// The RPC URL comes from `HERMES_RPC_URL` (defaults to the local node on 8545).
    pub fn from_env() -> Option<Self> {
        let registry = std::env::var("HERMES_DECISION_REGISTRY")
            .ok()
            .map(|s| s.trim().to_string())
            .filter(|s| !s.is_empty())?;
        let rpc_url = std::env::var("HERMES_RPC_URL")
            .unwrap_or_else(|_| "http://127.0.0.1:8545".to_string());
        let recorder = RecorderClient::from_env(rpc_url)?;
        Some(Self::new(Arc::new(recorder), registry))
    }

    /// The configured registry address (for diagnostics).
    pub fn registry_addr(&self) -> &str {
        &self.registry_addr
    }

    /// The signer's address (for diagnostics — confirms which key anchors).
    pub fn signer_address(&self) -> &str {
        self.recorder.from_address()
    }
}

impl DecisionSink for ChainDecisionSink {
    fn record(&self, d: ApprovalDecision) {
        let recorder = self.recorder.clone();
        let registry = self.registry_addr.clone();
        let params = decision_params(&d);
        let action_id = d.action_id;
        // Fire-and-forget: never block the owner's click on chain confirmation.
        tokio::spawn(async move {
            match recorder.record_decision(&registry, params).await {
                Ok(tx) => tracing::info!(action_id, tx, "decision anchored on-chain"),
                Err(e) => {
                    tracing::warn!(action_id, error = %e, "on-chain decision anchor failed (local record stands)")
                }
            }
        });
    }
}

/// Map an [`ApprovalDecision`] to the registry's `record(...)` params. Every bytes32 field
/// is derived deterministically so an off-chain reader can recompute and verify them, and
/// `artifact_root` commits to the **full** concrete effect even though `description` is
/// length-capped (T11/H-A12: the chain still pins exactly what was approved).
fn decision_params(d: &ApprovalDecision) -> DecisionParams {
    let status = match d.decision {
        hermes_core::Decision::Approve => DecisionStatus::Approved,
        hermes_core::Decision::Deny => DecisionStatus::Rejected,
    };
    // decision_id binds the action, the time, the effect kind, and the outcome — unique
    // per decision instance.
    let decision_id = keccak_parts(&[
        b"hermes:decision",
        &d.action_id.to_be_bytes(),
        &d.at_ms.to_be_bytes(),
        d.effect_kind.as_bytes(),
        d.status_str().as_bytes(),
    ]);
    let corr_id = match d.provenance.triggered_by_message {
        Some(m) => keccak_parts(&[b"hermes:msg", &m.to_be_bytes()]),
        None => [0u8; 32],
    };
    DecisionParams {
        decision_id,
        user: keccak_parts(&[b"hermes:owner"]),
        tenant: keccak_parts(&[b"citrate:hermes"]),
        corr_id,
        class: EVENT_CLASS_AUDIT,
        description: truncate_bytes(&d.effect_describe, MAX_DESC_BYTES),
        auth_mode: "owner-approval".to_string(),
        // Commit to the *complete* effect text, uncapped.
        artifact_root: keccak_parts(&[d.effect_describe.as_bytes()]),
        status,
    }
}

/// `keccak256(part0 || part1 || …)` → bytes32. Used for every derived id so they are
/// recomputable off-chain.
fn keccak_parts(parts: &[&[u8]]) -> [u8; 32] {
    let mut h = Keccak256::new();
    for p in parts {
        h.update(p);
    }
    let d = h.finalize();
    let mut out = [0u8; 32];
    out.copy_from_slice(&d);
    out
}

/// Truncate a string to at most `max` bytes without splitting a UTF-8 char.
fn truncate_bytes(s: &str, max: usize) -> String {
    if s.len() <= max {
        return s.to_string();
    }
    let mut end = max;
    while end > 0 && !s.is_char_boundary(end) {
        end -= 1;
    }
    s[..end].to_string()
}

#[cfg(test)]
mod tests {
    use super::*;
    use hermes_core::approval::{ActionEffect, PendingAction, Provenance};
    use hermes_core::Decision;

    fn decision(decision: Decision, content: &str) -> ApprovalDecision {
        let action = PendingAction {
            id: 7,
            effect: ActionEffect::PostMessage { channel: 12345, content: content.into() },
            provenance: Provenance {
                triggered_by_message: Some(900),
                triggered_in_channel: Some(12345),
            },
            created_at_ms: 1,
        };
        ApprovalDecision::from_resolved(&action, decision, 42)
    }

    #[test]
    fn params_map_status_and_class() {
        let p = decision_params(&decision(Decision::Approve, "hi"));
        assert_eq!(p.class, EVENT_CLASS_AUDIT);
        assert!(matches!(p.status, DecisionStatus::Approved));
        assert_eq!(p.auth_mode, "owner-approval");
        let denied = decision_params(&decision(Decision::Deny, "hi"));
        assert!(matches!(denied.status, DecisionStatus::Rejected));
    }

    #[test]
    fn derived_ids_are_deterministic_and_effect_bound() {
        let a = decision_params(&decision(Decision::Approve, "welcome"));
        let b = decision_params(&decision(Decision::Approve, "welcome"));
        // Same decision → same ids (recomputable / verifiable off-chain).
        assert_eq!(a.decision_id, b.decision_id);
        assert_eq!(a.artifact_root, b.artifact_root);
        // A different effect → a different artifact_root (it commits to the exact effect).
        let c = decision_params(&decision(Decision::Approve, "different"));
        assert_ne!(a.artifact_root, c.artifact_root);
        // Approve vs Deny → different decision_id (outcome is bound in).
        let d = decision_params(&decision(Decision::Deny, "welcome"));
        assert_ne!(a.decision_id, d.decision_id);
        // corr_id is non-zero when there is a triggering message.
        assert_ne!(a.corr_id, [0u8; 32]);
    }

    #[test]
    fn description_is_length_capped_but_artifact_root_commits_to_full() {
        let long = "x".repeat(5000);
        let p = decision_params(&decision(Decision::Approve, &long));
        assert!(p.description.len() <= MAX_DESC_BYTES);
        // The full effect (way over the cap) still produces a stable artifact_root.
        assert_ne!(p.artifact_root, [0u8; 32]);
    }

    #[test]
    fn truncate_respects_char_boundaries() {
        let s = "héllo wörld"; // multi-byte chars
        let t = truncate_bytes(s, 3);
        assert!(s.starts_with(&t));
        assert!(t.len() <= 3);
    }

    #[test]
    fn from_env_without_registry_is_none() {
        // No HERMES_DECISION_REGISTRY in the test env ⇒ anchoring disabled.
        std::env::remove_var("HERMES_DECISION_REGISTRY");
        assert!(ChainDecisionSink::from_env().is_none());
    }
}
