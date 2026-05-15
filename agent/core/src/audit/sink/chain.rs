//! Chain-anchor AuditSink — RFC-CIT-AGENT-0001 §6.3 + planset
//! `05_AUDIT_CHAIN.md` "Anchor strategies".
//!
//! Commits audit-record hashes (or Merkle batch roots) to the
//! cit-agent `AnchorRegistry` contract via the
//! `chain::AnchorRegistryClient` adapter (CIT-AGENT-6d).
//!
//! Three strategies:
//!   * `PerCapsule` — anchor only `CapsuleInstall` / `CapsuleRevoke` events
//!   * `PerApproval` — anchor only `Approval` / `Rejection` / `Submission` events
//!   * `NightlyMerkle` — accumulator over the day's records;
//!     a single anchor per day (deferred to a 6d-tail; requires a
//!     clock + batch flush background task)
//!
//! `iter` returns an error — chain sinks are write-only. The audit
//! chain's offline-verifiable property comes from the filesystem
//! sink; the chain anchor is the tamper-evidence witness.

use crate::audit::record::{AnchorKind, AuditRecord, EventType};
use crate::audit::sink::AuditSink;
use crate::chain::AnchorRegistryClient;
use crate::error::AgentError;
use std::sync::Arc;
use tokio::runtime::Handle;

/// Anchor strategy per planset 05. The strategy determines (1)
/// which audit events trigger an anchor call and (2) what root
/// value is committed.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum AnchorStrategy {
    /// Anchor each capsule-install + capsule-revoke event. Root
    /// is the per-event record hash.
    PerCapsule,
    /// Anchor each approval-resolution event (Approval / Rejection /
    /// Submission). Root is the per-event record hash.
    PerApproval,
    /// Nightly Merkle root over the day's records. CIT-AGENT-6d-tail
    /// — needs accumulator + batch flush.
    NightlyMerkle,
}

impl AnchorStrategy {
    /// Return the corresponding `AnchorKind` for the on-chain enum.
    /// The mapping is identity — the strategy + the kind are the
    /// same concept on different sides of the wire.
    pub fn kind(self) -> AnchorKind {
        match self {
            AnchorStrategy::PerCapsule => AnchorKind::PerCapsule,
            AnchorStrategy::PerApproval => AnchorKind::PerApproval,
            AnchorStrategy::NightlyMerkle => AnchorKind::NightlyMerkle,
        }
    }

    /// Should this strategy anchor the given event? `PerCapsule`
    /// anchors install/revoke; `PerApproval` anchors approval-
    /// resolution events; `NightlyMerkle` anchors nothing in the
    /// per-event path (the accumulator handles all events; the
    /// daily flush is what calls `anchor`).
    pub fn should_anchor(&self, event: EventType) -> bool {
        match self {
            AnchorStrategy::PerCapsule => {
                matches!(event, EventType::CapsuleInstall | EventType::CapsuleRevoke)
            }
            AnchorStrategy::PerApproval => matches!(
                event,
                EventType::Approval | EventType::Rejection | EventType::Submission
            ),
            AnchorStrategy::NightlyMerkle => false,
        }
    }
}

/// AuditSink impl that commits record hashes to AnchorRegistry per
/// the configured strategy. Wraps an `AnchorRegistryClient` and a
/// strategy enum. The append path is fire-and-forget at the
/// chain-tx level — the doctor pre-flight (CIT-AGENT-7) verifies
/// anchors actually landed.
pub struct ChainAnchorSink {
    client: Arc<AnchorRegistryClient>,
    strategy: AnchorStrategy,
}

impl ChainAnchorSink {
    pub fn new(client: Arc<AnchorRegistryClient>, strategy: AnchorStrategy) -> Self {
        Self { client, strategy }
    }

    pub fn strategy(&self) -> AnchorStrategy {
        self.strategy
    }
}

impl AuditSink for ChainAnchorSink {
    fn append(&self, record: &AuditRecord) -> Result<(), AgentError> {
        if !self.strategy.should_anchor(record.event_type) {
            // Strategy doesn't anchor this event type — skip cleanly.
            return Ok(());
        }
        let root = crate::audit::record::record_hash(record)?;
        let kind = self.strategy.kind();
        // We need an async context. If we're in a tokio runtime,
        // spawn the anchor call; otherwise return an error so the
        // caller knows they need a runtime. Doctor's verifier
        // catches any anchor that failed to land.
        let client = Arc::clone(&self.client);
        match Handle::try_current() {
            Ok(handle) => {
                handle.spawn(async move {
                    match client.anchor(kind, root).await {
                        Ok(tx) => tracing::info!(
                            "ChainAnchorSink anchored {:?} root={:x?} tx={}",
                            kind,
                            &root[..4],
                            tx
                        ),
                        Err(e) => tracing::warn!(
                            "ChainAnchorSink anchor failed {:?} root={:x?}: {}",
                            kind,
                            &root[..4],
                            e
                        ),
                    }
                });
                Ok(())
            }
            Err(_) => Err(AgentError::Chain(
                "ChainAnchorSink::append requires a tokio runtime context".to_string(),
            )),
        }
    }

    fn iter(
        &self,
    ) -> Result<Box<dyn Iterator<Item = Result<AuditRecord, AgentError>> + '_>, AgentError>
    {
        Err(AgentError::Audit(
            "ChainAnchorSink is write-only; iterate via the off-chain log + reconcile via is_anchored() lookups"
                .to_string(),
        ))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn strategy_kind_mapping_matches_record_anchor_kind() {
        assert_eq!(AnchorStrategy::PerCapsule.kind(), AnchorKind::PerCapsule);
        assert_eq!(AnchorStrategy::PerApproval.kind(), AnchorKind::PerApproval);
        assert_eq!(AnchorStrategy::NightlyMerkle.kind(), AnchorKind::NightlyMerkle);
    }

    #[test]
    fn per_capsule_anchors_install_and_revoke() {
        let s = AnchorStrategy::PerCapsule;
        assert!(s.should_anchor(EventType::CapsuleInstall));
        assert!(s.should_anchor(EventType::CapsuleRevoke));
        assert!(!s.should_anchor(EventType::Approval));
        assert!(!s.should_anchor(EventType::Proposal));
    }

    #[test]
    fn per_approval_anchors_approval_rejection_submission() {
        let s = AnchorStrategy::PerApproval;
        assert!(s.should_anchor(EventType::Approval));
        assert!(s.should_anchor(EventType::Rejection));
        assert!(s.should_anchor(EventType::Submission));
        assert!(!s.should_anchor(EventType::CapsuleInstall));
        assert!(!s.should_anchor(EventType::Genesis));
    }

    #[test]
    fn nightly_merkle_anchors_nothing_per_event() {
        let s = AnchorStrategy::NightlyMerkle;
        for et in [
            EventType::Genesis,
            EventType::Proposal,
            EventType::Approval,
            EventType::CapsuleInstall,
            EventType::DoctorReport,
        ] {
            assert!(!s.should_anchor(et), "NightlyMerkle anchors via batch flush only, not per-event");
        }
    }
}
