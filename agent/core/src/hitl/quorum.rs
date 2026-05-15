//! Tier → quorum mapping — RFC-CIT-AGENT-0001 §5.2 + planset
//! `04_APPROVAL_MODEL.md` "Risk tiers".
//!
//! | Tier | Approval requirement |
//! |---|---|
//! | low | Auto-approve; log only |
//! | medium | 1 approver from required-role set |
//! | high | N-of-M (default 2) from required-role set |
//! | critical | Full quorum: SecurityOfficer + ComplianceOfficer + Reviewer |
//!
//! The TLA+ spec invariants verified by `ApprovalStateMachine.tla`
//! (CIT-AGENT-2 PASS at 336,292 distinct states) include:
//!   * `NoExecuteWithoutQuorum` — Executed implies signatures satisfy quorum
//!   * `AuditorNeverApproves` — Auditor never appears in `signatures[a]`
//!   * `NoSilentPromotion` — edit-on-medium doesn't sneak to higher tier
//!
//! This module is the runtime concretization of the spec's
//! `Quorum(t)` function.

use crate::capsule::manifest::{Role, RiskTier};
use crate::hitl::roles;
use std::collections::BTreeSet;

/// The signature requirement for an action at a given risk tier.
/// `for_tier(tier, manifest_required_roles)` produces the variant
/// the action must satisfy before resolving Approved.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Quorum {
    /// Tier-low: log only; no human signature.
    AutoApprove,
    /// Tier-medium: at least one signature from the manifest's
    /// required-role set.
    OneOf(BTreeSet<Role>),
    /// Tier-high: N signatures from the manifest's required-role
    /// set. Default N = 2 (planset §"Risk tiers").
    NofM { n: u8, m: BTreeSet<Role> },
    /// Tier-critical: every named role in the set must sign.
    /// Per planset, this is SecurityOfficer + ComplianceOfficer +
    /// Reviewer regardless of manifest declaration.
    Multiset(BTreeSet<Role>),
}

impl Quorum {
    /// Compute the quorum for an action of the given tier whose
    /// manifest declares `manifest_required` as the role set. For
    /// tier-critical, the manifest's set is ignored — the planset
    /// fixes the multiset.
    pub fn for_tier(tier: RiskTier, manifest_required: &[Role]) -> Quorum {
        match tier {
            RiskTier::Low => Quorum::AutoApprove,
            RiskTier::Medium => Quorum::OneOf(manifest_required.iter().copied().collect()),
            RiskTier::High => Quorum::NofM {
                n: 2,
                m: manifest_required.iter().copied().collect(),
            },
            RiskTier::Critical => Quorum::Multiset({
                let mut s = BTreeSet::new();
                s.insert(Role::SecurityOfficer);
                s.insert(Role::ComplianceOfficer);
                s.insert(Role::Reviewer);
                s
            }),
        }
    }

    /// Returns `true` when the accumulated signer-role multiset
    /// satisfies the quorum. Auditor signatures are filtered out
    /// here as a defense-in-depth — `add_signature` should reject
    /// Auditor before reaching this point, but the check is also
    /// present in `satisfied_by` to make the property structural.
    pub fn satisfied_by(&self, signed_roles: &[Role]) -> bool {
        let usable: Vec<Role> = signed_roles
            .iter()
            .copied()
            .filter(|r| roles::can_approve(*r))
            .collect();
        match self {
            Quorum::AutoApprove => true,
            Quorum::OneOf(set) => usable.iter().any(|r| set.contains(r)),
            Quorum::NofM { n, m } => {
                let hits = usable.iter().filter(|r| m.contains(r)).count();
                hits >= *n as usize
            }
            Quorum::Multiset(required) => {
                let signed: BTreeSet<Role> = usable.into_iter().collect();
                required.is_subset(&signed)
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn low_tier_auto_approves() {
        let q = Quorum::for_tier(RiskTier::Low, &[]);
        assert!(matches!(q, Quorum::AutoApprove));
        assert!(q.satisfied_by(&[]));
    }

    #[test]
    fn medium_tier_requires_one_from_set() {
        let q = Quorum::for_tier(RiskTier::Medium, &[Role::Reviewer, Role::ComplianceOfficer]);
        assert!(!q.satisfied_by(&[]));
        assert!(!q.satisfied_by(&[Role::Operator])); // not in required set
        assert!(q.satisfied_by(&[Role::Reviewer]));
        assert!(q.satisfied_by(&[Role::ComplianceOfficer]));
    }

    #[test]
    fn high_tier_requires_two_from_set() {
        let q = Quorum::for_tier(
            RiskTier::High,
            &[Role::Reviewer, Role::ComplianceOfficer, Role::SecurityOfficer],
        );
        assert!(!q.satisfied_by(&[Role::Reviewer]));
        assert!(q.satisfied_by(&[Role::Reviewer, Role::ComplianceOfficer]));
        assert!(q.satisfied_by(&[Role::Reviewer, Role::SecurityOfficer]));
        // Out-of-set signers don't count.
        assert!(!q.satisfied_by(&[Role::Reviewer, Role::Operator]));
    }

    #[test]
    fn critical_tier_requires_full_quorum() {
        let q = Quorum::for_tier(RiskTier::Critical, &[]);
        // Critical ignores manifest required — full quorum is fixed.
        assert!(!q.satisfied_by(&[Role::SecurityOfficer]));
        assert!(!q.satisfied_by(&[Role::SecurityOfficer, Role::ComplianceOfficer]));
        assert!(q.satisfied_by(&[
            Role::SecurityOfficer,
            Role::ComplianceOfficer,
            Role::Reviewer
        ]));
    }

    #[test]
    fn auditor_signatures_filtered_out() {
        // Even at low tier, Auditor doesn't count toward quorum
        // (defense-in-depth — should never reach satisfied_by).
        let q = Quorum::for_tier(RiskTier::Medium, &[Role::Auditor]);
        assert!(!q.satisfied_by(&[Role::Auditor]));
    }
}
