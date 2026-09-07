//! Doctor report types + canonical TOML serialization + ed25519
//! signed-report writer — RFC-CIT-AGENT-0001 §10.2.
//!
//! The report's `to_toml` output is the bytes a `SigningSurface`
//! (CIT-AGENT-4b) signs over. Verifying the signature against the
//! same TOML proves the report wasn't tampered with after the
//! doctor pass. The `SignedDoctorReport` bundles the canonical bytes
//! + the attestation for offline review by FedRAMP assessors.

use crate::error::AgentError;
use crate::hitl::signing::{AttestedSignature, SigningSurface};
use serde::{Deserialize, Serialize};
use std::collections::BTreeMap;

/// Triage classification per RFC §10.2 "BLOCKER vs WARN
/// classification". `Pass` means the check ran cleanly; `Warn`
/// surfaces a finding the operator should review but doesn't gate
/// continued operation; `Blocker` means the doctor explicitly
/// recommends halting the harness until remediation.
///
/// AR-B-015: `Skipped` means the check did NOT run (no config supplied,
/// unsupported platform, etc.). It was previously encoded as `Pass` with a
/// "skipped: …" message, so a report where four RFC §10.2 checks ran nothing —
/// including capsule signature re-verification, the *first* required check —
/// still rolled up to a signed all-green `Pass`. A skipped check is not a pass:
/// it is excluded from a clean `Pass` and drags the overall status to at least
/// `Warn` (see `doctor::compute_overall`).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum Severity {
    Pass,
    Skipped,
    Warn,
    Blocker,
}

impl Severity {
    pub fn as_str(self) -> &'static str {
        match self {
            Severity::Pass => "pass",
            Severity::Skipped => "skipped",
            Severity::Warn => "warn",
            Severity::Blocker => "blocker",
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CheckResult {
    pub name: String,
    pub severity: Severity,
    pub message: String,
    /// Per-check structured detail (e.g. {"records_verified": "1234"}
    /// for the audit chain integrity check). Stored as a stringly-
    /// typed map so the TOML output is human-readable + the schema
    /// extends across check versions without breaking parsers.
    #[serde(default)]
    pub details: BTreeMap<String, String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DoctorReport {
    pub agent_did: String,
    pub started_at_unix: i64,
    pub finished_at_unix: i64,
    pub results: Vec<CheckResult>,
    pub overall_status: Severity,
}

impl DoctorReport {
    /// Serialize the report to TOML. The output bytes are what
    /// `sign()` attests to — the signature covers the literal TOML
    /// emission, NOT a re-canonicalized form. Verifying signatures
    /// requires recovering the same bytes.
    pub fn to_toml(&self) -> Result<String, AgentError> {
        toml::to_string(self).map_err(|e| AgentError::Audit(format!("doctor TOML emit: {e}")))
    }

    /// Sign the report with the supplied surface. Returns the
    /// `SignedDoctorReport` envelope — TOML body + attestation
    /// over the body bytes. Offline verification:
    /// `signing::verify_attestation(&toml_bytes, &signed.attestation)`.
    pub fn sign(
        &self,
        surface: &dyn SigningSurface,
    ) -> Result<SignedDoctorReport, AgentError> {
        let toml_body = self.to_toml()?;
        let attestation = surface.sign(toml_body.as_bytes())?;
        Ok(SignedDoctorReport {
            toml_body,
            attestation,
        })
    }
}

/// The on-disk format: the raw TOML body + the ed25519 attestation
/// over those bytes. Field names match the planset's expectations
/// for offline assessor tooling.
#[derive(Debug, Clone)]
pub struct SignedDoctorReport {
    pub toml_body: String,
    pub attestation: AttestedSignature,
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::capsule::manifest::Role;
    use crate::hitl::signing::{verify_attestation, Ed25519FileSurface};

    fn sample_report() -> DoctorReport {
        DoctorReport {
            agent_did: "did:citrate:agent:0xab12".to_string(),
            started_at_unix: 1_715_000_000,
            finished_at_unix: 1_715_000_010,
            results: vec![
                CheckResult {
                    name: "audit-chain-integrity".to_string(),
                    severity: Severity::Pass,
                    message: "verified 1234 records".to_string(),
                    details: {
                        let mut m = BTreeMap::new();
                        m.insert("records_verified".to_string(), "1234".to_string());
                        m
                    },
                },
                CheckResult {
                    name: "approval-queue-depth".to_string(),
                    severity: Severity::Warn,
                    message: "queue depth 150 above threshold 100".to_string(),
                    details: BTreeMap::new(),
                },
            ],
            overall_status: Severity::Warn,
        }
    }

    #[test]
    fn serialize_to_toml() {
        let report = sample_report();
        let toml = report.to_toml().expect("emit toml");
        assert!(toml.contains("agent_did = \"did:citrate:agent:0xab12\""));
        assert!(toml.contains("overall_status = \"Warn\""));
        assert!(toml.contains("name = \"audit-chain-integrity\""));
        assert!(toml.contains("name = \"approval-queue-depth\""));
    }

    #[test]
    fn round_trip_toml() {
        let original = sample_report();
        let toml = original.to_toml().expect("emit");
        let decoded: DoctorReport = toml::from_str(&toml).expect("parse");
        assert_eq!(decoded.agent_did, original.agent_did);
        assert_eq!(decoded.results.len(), 2);
        assert_eq!(decoded.results[0].name, "audit-chain-integrity");
        assert!(matches!(decoded.overall_status, Severity::Warn));
    }

    #[test]
    fn sign_and_verify_round_trip() {
        let report = sample_report();
        let surface = Ed25519FileSurface::from_seed([0x42; 32], Role::SecurityOfficer);
        let signed = report.sign(&surface).expect("sign");
        verify_attestation(signed.toml_body.as_bytes(), &signed.attestation)
            .expect("attestation verifies");
    }

    #[test]
    fn tampered_body_fails_verify() {
        let report = sample_report();
        let surface = Ed25519FileSurface::from_seed([0x42; 32], Role::SecurityOfficer);
        let mut signed = report.sign(&surface).expect("sign");
        signed.toml_body.push_str("\n# tampered");
        verify_attestation(signed.toml_body.as_bytes(), &signed.attestation)
            .expect_err("tampered body fails");
    }

    #[test]
    fn severity_as_str_round_trip() {
        assert_eq!(Severity::Pass.as_str(), "pass");
        assert_eq!(Severity::Warn.as_str(), "warn");
        assert_eq!(Severity::Blocker.as_str(), "blocker");
    }
}
