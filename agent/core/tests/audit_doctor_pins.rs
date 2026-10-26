//! Pins on the audit-chain read path (`AuditChain::verify_integrity`) and the
//! doctor roll-up (`doctor::run`), through the public API.

use std::sync::Arc;

use citrate_agent_core::audit::{
    AuditChain, AuditRecord, AuditSink, EventType, FilesystemSink, GenesisInfo, RoleSignature,
    SigningSurfaceTag,
};
use citrate_agent_core::capsule::manifest::Role;
use citrate_agent_core::doctor::{self, Check, CheckResult, DoctorContext, Severity};

fn genesis() -> GenesisInfo {
    GenesisInfo {
        agent_did: "did:citrate:agent:0xab12".to_string(),
        harness_version: "0.4.0".to_string(),
        policy_bundle_hash: [0u8; 32],
        doctor_report_hash: [0u8; 32],
    }
}

/// `append` refuses a record with an unverifiable role signature. A record
/// written straight to the sink (bypassing `append`) with a correct sequence
/// and previous-hash link but a forged signature must still fail
/// `verify_integrity`, so a forged attestation cannot pass as intact.
#[test]
fn verify_integrity_rejects_a_forged_signature_written_past_append() {
    let dir = tempfile::tempdir().expect("tempdir");
    let sink: Arc<dyn AuditSink> =
        Arc::new(FilesystemSink::open(&dir.path().join("audit.jsonl")).expect("sink"));
    let chain = AuditChain::open_or_init(sink.clone(), genesis(), 1_715_000_000).expect("open");
    chain
        .verify_integrity()
        .expect("control: genesis-only chain verifies");

    let forged = AuditRecord {
        sequence: chain.next_sequence(),
        timestamp: 1_715_000_001,
        previous_hash: chain.last_hash(),
        event_type: EventType::Approval,
        payload: b"privileged write".to_vec(),
        actor: "did:citrate:agent:0xab12".to_string(),
        signatures: vec![RoleSignature {
            signer: "did:citrate:role:0xSECURITY_OFFICER".to_string(),
            role: Role::SecurityOfficer,
            signed_at: 0,
            signature: vec![0u8; 64],
            surface: SigningSurfaceTag::Slint,
            signer_pubkey: [0u8; 32],
        }],
        chain_anchor: None,
    };
    sink.append(&forged).expect("raw sink write");

    let reopened = AuditChain::open_or_init(sink, genesis(), 1_715_000_002).expect("reopen");
    assert!(
        reopened.verify_integrity().is_err(),
        "a forged role signature in the log must fail integrity verification"
    );
}

struct Fixed(&'static str, Severity);
impl Check for Fixed {
    fn name(&self) -> &str {
        self.0
    }
    fn run(&self, _: &DoctorContext) -> CheckResult {
        CheckResult {
            name: self.0.to_string(),
            severity: self.1,
            message: format!("{:?}", self.1),
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

/// A report in which a check did not run is not a clean pass: one Skipped
/// among Pass results rolls the overall status up to Warn.
#[test]
fn doctor_report_with_a_skipped_check_is_not_a_pass() {
    let checks: Vec<Box<dyn Check>> = vec![
        Box::new(Fixed("ran", Severity::Pass)),
        Box::new(Fixed("did-not-run", Severity::Skipped)),
        Box::new(Fixed("ran-too", Severity::Pass)),
    ];
    let report = doctor::run(&ctx(), &checks);
    assert_eq!(report.overall_status, Severity::Warn);

    // Control: all Pass is Pass.
    let checks: Vec<Box<dyn Check>> = vec![Box::new(Fixed("ran", Severity::Pass))];
    assert_eq!(doctor::run(&ctx(), &checks).overall_status, Severity::Pass);
}
