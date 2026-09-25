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
    /// Tier-high: signatures from N DISTINCT roles of the manifest's
    /// required-role set. Default N = 2 (planset §"Risk tiers").
    /// PBA-L6b-012: two signers holding the same role count once.
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
                // PBA-L6b-012: separation of duties is across roles — count
                // each required role at most once.
                let distinct: BTreeSet<Role> =
                    usable.into_iter().filter(|r| m.contains(r)).collect();
                distinct.len() >= usize::from(*n)
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

    /// PBA-L6b-012 regression: N-of-M counts DISTINCT roles. Pre-fix two
    /// Reviewer signatures satisfied `[Reviewer, ComplianceOfficer]`, so the
    /// ComplianceOfficer attestation the manifest demands was never required.
    #[test]
    fn nofm_requires_distinct_roles_pba_l6b_012() {
        let q = Quorum::for_tier(RiskTier::High, &[Role::Reviewer, Role::ComplianceOfficer]);
        assert!(!q.satisfied_by(&[Role::Reviewer, Role::Reviewer]));
        assert!(!q.satisfied_by(&[Role::ComplianceOfficer, Role::ComplianceOfficer]));
        assert!(!q.satisfied_by(&[Role::Reviewer, Role::Reviewer, Role::Reviewer]));
        assert!(q.satisfied_by(&[Role::Reviewer, Role::ComplianceOfficer]));
        assert!(q.satisfied_by(&[Role::Reviewer, Role::Reviewer, Role::ComplianceOfficer]));
    }

    /// PBA-L6b-012 tripwire (class: quorum counted by signature instead of
    /// by role). Exhaustive over every signer-role sequence of length <= 4:
    /// each quorum is satisfied exactly when the set of DISTINCT approving
    /// roles meets it, so repeating a role never helps.
    #[test]
    fn tripwire_quorum_depends_only_on_distinct_roles_pba_l6b_012() {
        let all = [
            Role::Operator,
            Role::Reviewer,
            Role::ComplianceOfficer,
            Role::SecurityOfficer,
            Role::Auditor,
        ];
        let quorums = [
            Quorum::for_tier(RiskTier::Medium, &[Role::Reviewer, Role::ComplianceOfficer]),
            Quorum::for_tier(RiskTier::High, &[Role::Reviewer, Role::ComplianceOfficer]),
            Quorum::for_tier(
                RiskTier::High,
                &[Role::Reviewer, Role::ComplianceOfficer, Role::SecurityOfficer],
            ),
            Quorum::for_tier(RiskTier::Critical, &[]),
        ];
        let oracle = |q: &Quorum, signed: &BTreeSet<Role>| -> bool {
            let usable: BTreeSet<Role> =
                signed.iter().copied().filter(|r| roles::can_approve(*r)).collect();
            match q {
                Quorum::AutoApprove => true,
                Quorum::OneOf(set) => !usable.is_disjoint(set),
                Quorum::NofM { n, m } => usable.intersection(m).count() >= usize::from(*n),
                Quorum::Multiset(req) => req.is_subset(&usable),
            }
        };
        let mut seqs: Vec<Vec<Role>> = vec![vec![]];
        for _ in 0..4 {
            let mut next = Vec::new();
            for s in &seqs {
                for r in all {
                    let mut t = s.clone();
                    t.push(r);
                    next.push(t);
                }
            }
            seqs.extend(next.clone());
            seqs.dedup();
            seqs = seqs.into_iter().filter(|s| s.len() <= 4).collect();
        }
        for seq in &seqs {
            let set: BTreeSet<Role> = seq.iter().copied().collect();
            for q in &quorums {
                assert_eq!(
                    q.satisfied_by(seq),
                    oracle(q, &set),
                    "quorum {q:?} on signer roles {seq:?}"
                );
            }
        }
    }

    #[test]
    fn auditor_signatures_filtered_out() {
        // Even at low tier, Auditor doesn't count toward quorum
        // (defense-in-depth — should never reach satisfied_by).
        let q = Quorum::for_tier(RiskTier::Medium, &[Role::Auditor]);
        assert!(!q.satisfied_by(&[Role::Auditor]));
    }
}
