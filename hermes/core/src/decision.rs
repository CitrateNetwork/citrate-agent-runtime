//! The decision-anchoring seam (WP-S2.2b): how an owner approval/denial of a queued
//! action becomes a durable, auditable **decision record** — the thing worth anchoring
//! on-chain (unlike the per-message guard trail, which is too chatty for the chain).
//!
//! This module is pure (ADR-H11: no I/O, no supply-chain surface on the boundary). It
//! defines the record an approval produces and the [`DecisionSink`] seam concrete sinks
//! implement: a structured-logging sink is live in the adapter today, and an optional
//! on-chain sink (the runtime's `RecorderClient` → `AgentDecisionRegistryV2.record`)
//! lands behind the same trait, constructed only when the owner supplies a registry
//! address and a signer (the custody gate from INFER-S1).
//!
//! The record carries the **concrete effect** the owner approved against
//! ([`crate::approval::ActionEffect::describe`], H-A12), not a label — so an after-the-
//! fact reader (or a chain verifier) sees exactly what was authorized, never a summary an
//! injection could have shaped (T11).

use crate::approval::{Decision, PendingAction, Provenance};

/// A durable record of one owner decision on a queued action. Produced at the moment the
/// owner approves or denies (the only authority that can, T15) and handed to every
/// [`DecisionSink`]. This is the unit the on-chain anchor commits to.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ApprovalDecision {
    /// The queue id of the action this decision resolved.
    pub action_id: u64,
    /// The machine label of the effect (e.g. `"post-message"`), for indexing.
    pub effect_kind: &'static str,
    /// The **full, concrete** human description the owner approved against (H-A12) — the
    /// exact effect, never a summary. This is what gets anchored.
    pub effect_describe: String,
    /// Approve or Deny.
    pub decision: Decision,
    /// Where the action originated (the owner message/channel that triggered it, T11).
    pub provenance: Provenance,
    /// When the decision was made (monotonic ms).
    pub at_ms: u64,
}

impl ApprovalDecision {
    /// Build a decision record from the resolved [`PendingAction`] and the owner's choice.
    pub fn from_resolved(action: &PendingAction, decision: Decision, at_ms: u64) -> Self {
        Self {
            action_id: action.id,
            effect_kind: action.effect.kind(),
            effect_describe: action.effect.describe(),
            decision,
            provenance: action.provenance.clone(),
            at_ms,
        }
    }

    /// The decision as a stable status string, matching the on-chain decision registry's
    /// `status` field convention (`"Approved"` / `"Rejected"`). Kept here so the chain
    /// adapter and the log sink agree without duplicating the mapping.
    pub fn status_str(&self) -> &'static str {
        match self.decision {
            Decision::Approve => "Approved",
            Decision::Deny => "Rejected",
        }
    }
}

/// A sink for decision records. Like [`crate::trail::Trail`], it is **append-only**:
/// `record` is the sole operation, so a sink cannot rewrite a decision after the fact.
/// Implementations must not block the event path — an on-chain sink fires-and-forgets.
pub trait DecisionSink: Send + Sync {
    /// Append one decision record.
    fn record(&self, decision: ApprovalDecision);
}

/// A no-op decision sink (when no anchoring is configured, or for tests).
pub struct NullDecisionSink;

impl DecisionSink for NullDecisionSink {
    fn record(&self, _decision: ApprovalDecision) {}
}

/// An in-memory decision sink for tests: collects records so assertions can inspect them.
#[derive(Default)]
pub struct InMemoryDecisionSink {
    decisions: std::sync::Mutex<Vec<ApprovalDecision>>,
}

impl InMemoryDecisionSink {
    /// A new, empty sink.
    pub fn new() -> Self {
        Self::default()
    }
    /// A snapshot of recorded decisions.
    pub fn decisions(&self) -> Vec<ApprovalDecision> {
        self.decisions.lock().unwrap().clone()
    }
    /// How many decisions have been recorded.
    pub fn len(&self) -> usize {
        self.decisions.lock().unwrap().len()
    }
    /// Whether nothing has been recorded yet.
    pub fn is_empty(&self) -> bool {
        self.decisions.lock().unwrap().is_empty()
    }
}

impl DecisionSink for InMemoryDecisionSink {
    fn record(&self, decision: ApprovalDecision) {
        self.decisions.lock().unwrap().push(decision);
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::approval::{ActionEffect, PendingAction};

    fn action(id: u64, channel: u64, content: &str) -> PendingAction {
        PendingAction {
            id,
            effect: ActionEffect::PostMessage { channel, content: content.into() },
            provenance: Provenance {
                triggered_by_message: Some(500),
                triggered_in_channel: Some(channel),
            },
            created_at_ms: 10,
        }
    }

    #[test]
    fn decision_record_carries_the_concrete_effect_not_a_label() {
        let a = action(7, 12345, "Welcome!");
        let d = ApprovalDecision::from_resolved(&a, Decision::Approve, 99);
        assert_eq!(d.action_id, 7);
        assert_eq!(d.effect_kind, "post-message");
        // H-A12: the anchored description is the exact effect, including the target + body.
        assert!(d.effect_describe.contains("<#12345>"));
        assert!(d.effect_describe.contains("> Welcome!"));
        assert_eq!(d.status_str(), "Approved");
        assert_eq!(d.provenance.triggered_by_message, Some(500));
        assert_eq!(d.at_ms, 99);
    }

    #[test]
    fn deny_maps_to_rejected_status() {
        let a = action(1, 1, "x");
        let d = ApprovalDecision::from_resolved(&a, Decision::Deny, 0);
        assert_eq!(d.status_str(), "Rejected");
    }

    #[test]
    fn in_memory_sink_is_append_only_record() {
        let sink = InMemoryDecisionSink::new();
        assert!(sink.is_empty());
        sink.record(ApprovalDecision::from_resolved(&action(1, 9, "a"), Decision::Approve, 1));
        sink.record(ApprovalDecision::from_resolved(&action(2, 9, "b"), Decision::Deny, 2));
        let got = sink.decisions();
        assert_eq!(got.len(), 2);
        assert_eq!(got[0].decision, Decision::Approve);
        assert_eq!(got[1].decision, Decision::Deny);
    }
}
