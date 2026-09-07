//! Doctor + continuous monitoring — RFC-CIT-AGENT-0001 §10.
//!
//! Per planset `08_SPRINT_SEQUENCE.md` CIT-AGENT-7: the doctor
//! framework runs a configurable set of health/integrity checks
//! against the cit-agent runtime, produces a TOML report, signs it
//! with an ed25519 surface, and optionally anchors the report's
//! content hash on chain (via the same `AnchorRegistry` adapter
//! `audit::sink::ChainAnchorSink` consumes from CIT-AGENT-6d).
//!
//! Daily continuous-monitoring artifact for NIST CA-7. The doctor
//! report is the structured evidence FedRAMP assessors review.
//!
//! CIT-AGENT-7a lands the framework + 5 of the 11 RFC §10.2 checks.
//! The remaining 6 checks land in 7b once dependencies (capsule
//! manifest re-verification, policy bundle, TLA-CI-status reader,
//! retention) are ready.

pub mod checks;
pub mod report;

pub use checks::{Check, DoctorContext};
pub use report::{CheckResult, DoctorReport, Severity, SignedDoctorReport};

/// Run a doctor pass against the supplied context and check set.
/// Returns the full report. Caller is responsible for serializing
/// + signing + persisting via `report::DoctorReport::to_toml()` +
/// `sign()`.
pub fn run(ctx: &DoctorContext, checks: &[Box<dyn Check>]) -> DoctorReport {
    let started_at_unix = ctx.now_unix;
    let results: Vec<CheckResult> = checks.iter().map(|c| c.run(ctx)).collect();
    let overall = compute_overall(&results);
    DoctorReport {
        agent_did: ctx.agent_did.clone(),
        started_at_unix,
        finished_at_unix: ctx.now_unix, // synchronous; no progression
        results,
        overall_status: overall,
    }
}

fn compute_overall(results: &[CheckResult]) -> Severity {
    if results.iter().any(|r| matches!(r.severity, Severity::Blocker)) {
        Severity::Blocker
    } else if results.iter().any(|r| matches!(r.severity, Severity::Warn)) {
        Severity::Warn
    } else if results.iter().any(|r| matches!(r.severity, Severity::Skipped)) {
        // AR-B-015: a report in which a required check did not run is NOT a
        // clean Pass. A skipped check drags the overall status to Warn so an
        // assessor never receives a signed all-green artifact whose green rows
        // include checks that ran nothing.
        Severity::Warn
    } else {
        Severity::Pass
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::doctor::checks::Check;

    struct FixedCheck {
        name: String,
        severity: Severity,
    }

    impl Check for FixedCheck {
        fn name(&self) -> &str {
            &self.name
        }
        fn run(&self, _: &DoctorContext) -> CheckResult {
            CheckResult {
                name: self.name.clone(),
                severity: self.severity,
                message: format!("fixed {:?}", self.severity),
                details: Default::default(),
            }
        }
    }

    fn ctx() -> DoctorContext {
        DoctorContext {
            agent_did: "did:citrate:agent:0xab12".to_string(),
            now_unix: 1_715_000_000,
            audit_chain_path: None,
            approval_queue: None,
            break_glass: None,
            expected_audit_head: None,
        }
    }

    #[test]
    fn overall_pass_when_all_checks_pass() {
        let checks: Vec<Box<dyn Check>> = vec![
            Box::new(FixedCheck {
                name: "c1".into(),
                severity: Severity::Pass,
            }),
            Box::new(FixedCheck {
                name: "c2".into(),
                severity: Severity::Pass,
            }),
        ];
        let report = run(&ctx(), &checks);
        assert!(matches!(report.overall_status, Severity::Pass));
    }

    #[test]
    fn overall_warn_when_any_warn_no_blocker() {
        let checks: Vec<Box<dyn Check>> = vec![
            Box::new(FixedCheck {
                name: "c1".into(),
                severity: Severity::Pass,
            }),
            Box::new(FixedCheck {
                name: "c2".into(),
                severity: Severity::Warn,
            }),
        ];
        let report = run(&ctx(), &checks);
        assert!(matches!(report.overall_status, Severity::Warn));
    }

    #[test]
    fn overall_blocker_when_any_blocker() {
        let checks: Vec<Box<dyn Check>> = vec![
            Box::new(FixedCheck {
                name: "c1".into(),
                severity: Severity::Warn,
            }),
            Box::new(FixedCheck {
                name: "c2".into(),
                severity: Severity::Blocker,
            }),
            Box::new(FixedCheck {
                name: "c3".into(),
                severity: Severity::Pass,
            }),
        ];
        let report = run(&ctx(), &checks);
        assert!(matches!(report.overall_status, Severity::Blocker));
    }

    #[test]
    fn report_includes_all_check_results_in_order() {
        let checks: Vec<Box<dyn Check>> = vec![
            Box::new(FixedCheck {
                name: "alpha".into(),
                severity: Severity::Pass,
            }),
            Box::new(FixedCheck {
                name: "beta".into(),
                severity: Severity::Warn,
            }),
        ];
        let report = run(&ctx(), &checks);
        assert_eq!(report.results.len(), 2);
        assert_eq!(report.results[0].name, "alpha");
        assert_eq!(report.results[1].name, "beta");
    }
}
