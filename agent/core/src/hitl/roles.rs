//! Five-role lattice + separation-of-duties checker — RFC-CIT-AGENT-0001
//! §5.3 + planset `04_APPROVAL_MODEL.md` "The five-role lattice".
//!
//! The 5 roles:
//!
//! | Role | Primary responsibility |
//! |---|---|
//! | Operator | Run the agent; approve low-risk; propose actions for higher review |
//! | Reviewer | Second signature on medium/high; peer of Operator |
//! | ComplianceOfficer | Required signature on protected data classes (CUI/PHI/FERPA/ITAR) |
//! | SecurityOfficer | Required signature on capability changes, capsule installs, break-glass |
//! | Auditor | Read-only access to audit chain; export evidence; never approves |
//!
//! Role-conflict rules (separation of duties):
//!   * ComplianceOfficer ⊥ SecurityOfficer (same agent, conflicting)
//!   * Auditor cannot approve ANY action (enforced at signature time,
//!     not via SoD pair-table because Auditor's restriction is unary)

// Role enum re-exported from manifest for backward compatibility with
// the TOML schema. Manifest is still the canonical TOML deserialization
// home; this module is the canonical *semantic* home.
pub use crate::capsule::manifest::Role;

/// Returns `true` when the two roles MUST NOT be held by the same
/// person for the same agent action. The relation is symmetric.
///
/// Per planset §"Role-conflict enforcement": pairing
/// ComplianceOfficer with SecurityOfficer in the same signature
/// chain undermines the dual-attestation property — both roles
/// independently certify the action's safety from their angle.
pub fn is_conflict(a: Role, b: Role) -> bool {
    use Role::*;
    matches!(
        (a, b),
        (ComplianceOfficer, SecurityOfficer) | (SecurityOfficer, ComplianceOfficer)
    )
}

/// Returns `true` when the role is allowed to issue an approval
/// signature. Auditor is the only role that returns `false` — its
/// access is strictly read-only (RFC §5.3).
pub fn can_approve(role: Role) -> bool {
    !matches!(role, Role::Auditor)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn compliance_security_conflict_is_symmetric() {
        assert!(is_conflict(Role::ComplianceOfficer, Role::SecurityOfficer));
        assert!(is_conflict(Role::SecurityOfficer, Role::ComplianceOfficer));
    }

    #[test]
    fn no_self_conflict() {
        // A role doesn't conflict with itself — that's "same person
        // submits twice" which is a SoD concern handled at signer-id
        // dedup time, not at role-pair time.
        assert!(!is_conflict(Role::Operator, Role::Operator));
        assert!(!is_conflict(Role::Reviewer, Role::Reviewer));
    }

    #[test]
    fn operator_reviewer_not_inherently_conflicting() {
        // Operator + Reviewer is a SAME-PERSON conflict (the
        // Operator who proposed can't be the Reviewer), not a role
        // conflict. Distinct people holding Operator + Reviewer is
        // fine.
        assert!(!is_conflict(Role::Operator, Role::Reviewer));
    }

    #[test]
    fn auditor_cannot_approve() {
        assert!(!can_approve(Role::Auditor));
        for r in [
            Role::Operator,
            Role::Reviewer,
            Role::ComplianceOfficer,
            Role::SecurityOfficer,
        ] {
            assert!(can_approve(r));
        }
    }
}
