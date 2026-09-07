//! `citrate-agent doctor` subcommand — CIT-AGENT-7c.
//!
//! Loads the TOML config, builds the DoctorContext + check set,
//! runs the orchestrator, signs the TOML report with an ed25519
//! seed file, and writes the signed artifact. Exit code:
//!   * 0 — Pass or Warn
//!   * 1 — Blocker (any check produced Severity::Blocker)
//!   * 2 — Configuration / IO error before doctor could run

use crate::config::{parse_sha256_hex, AgentCliConfig};
use citrate_agent_core::capsule::manifest::Role;
use citrate_agent_core::doctor::{
    self,
    checks::{
        ApprovalQueueDepthCheck, AuditChainIntegrityCheck, AuditFilePermissionsCheck,
        CapsuleManifestReverifyCheck, Check, DoctorContext, PendingBreakGlassCheck,
        PolicyBundleHashCheck, RetentionAgeCheck, RuntimeCheck, TlaSpecCiStatusCheck,
        WasmLinkerRecheckCheck,
    },
    Severity,
};
use citrate_agent_core::hitl::signing::Ed25519FileSurface;
use std::path::PathBuf;

#[derive(clap::Args, Debug)]
pub struct DoctorArgs {
    /// Path to the doctor TOML config.
    #[arg(long)]
    pub config: PathBuf,
    /// Path to write the signed TOML report. When omitted, prints to stdout.
    #[arg(long)]
    pub output: Option<PathBuf>,
    /// Filter to a subset of checks by name (case-sensitive). Empty
    /// list = run all configured checks.
    #[arg(long)]
    pub check: Vec<String>,
    /// Path to a 32-byte ed25519 seed file for signing the report.
    /// When omitted, the report is emitted unsigned (warns on stderr).
    #[arg(long)]
    pub seed: Option<PathBuf>,
}

pub fn run(args: DoctorArgs) -> i32 {
    let cfg = match AgentCliConfig::load(&args.config) {
        Ok(c) => c,
        Err(e) => {
            eprintln!("config error: {e}");
            return 2;
        }
    };
    let now_unix = match std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
    {
        Ok(d) => d.as_secs() as i64,
        Err(_) => 0,
    };
    let ctx = DoctorContext {
        agent_did: cfg.doctor.agent_did.clone(),
        now_unix,
        audit_chain_path: cfg.doctor.audit_chain.as_ref().map(|a| a.path.clone()),
        approval_queue: None,
        break_glass: None,
        // AR-B-001: the CLI does not yet resolve the AgentSBT
        // `latest_audit_chain_head`; until it does, tail-truncation
        // cannot be detected here, though a deleted/empty log is still a
        // Blocker. Wiring the on-chain head is tracked as follow-up.
        expected_audit_head: None,
    };

    // Build the 11 checks per RFC §10.2. Each check pulls its
    // config from the TOML or skips with Pass when absent.
    let mut checks: Vec<Box<dyn Check>> = Vec::new();
    checks.push(Box::new(AuditChainIntegrityCheck));
    checks.push(Box::new(AuditFilePermissionsCheck));
    checks.push(Box::new(
        cfg.doctor
            .approval_queue_depth
            .as_ref()
            .map(|s| ApprovalQueueDepthCheck {
                warn_threshold: s.warn_threshold,
            })
            .unwrap_or_default(),
    ));
    checks.push(Box::new(PendingBreakGlassCheck { action_ids: vec![] }));
    checks.push(Box::new(RuntimeCheck));
    let capsule_paths = cfg
        .doctor
        .capsule_reverify
        .as_ref()
        .map(|c| c.capsule_paths.clone())
        .unwrap_or_default();
    checks.push(Box::new(CapsuleManifestReverifyCheck {
        capsule_paths,
        registry: None,
    }));
    checks.push(Box::new(WasmLinkerRecheckCheck { pairs: vec![] }));
    let policy_files = if let Some(p) = &cfg.doctor.policy_bundle {
        let mut out = Vec::with_capacity(p.files.len());
        for f in &p.files {
            let hash = match parse_sha256_hex(&f.sha256) {
                Ok(h) => h,
                Err(e) => {
                    eprintln!("config: policy_bundle.files entry {:?} has bad sha256: {e}", f.path);
                    return 2;
                }
            };
            out.push((f.path.clone(), hash));
        }
        out
    } else {
        Vec::new()
    };
    checks.push(Box::new(PolicyBundleHashCheck {
        files: policy_files,
    }));
    let (tla_path, tla_max_age) = cfg
        .doctor
        .tla_ci
        .as_ref()
        .map(|s| (Some(s.status_file.clone()), s.max_age_hours))
        .unwrap_or((None, 48));
    checks.push(Box::new(TlaSpecCiStatusCheck {
        status_file_path: tla_path,
        max_age_hours: tla_max_age,
    }));
    let max_age = cfg
        .doctor
        .retention
        .as_ref()
        .map(|s| s.max_age_days)
        .unwrap_or(90);
    checks.push(Box::new(RetentionAgeCheck {
        max_age_days: max_age,
    }));
    // AnchorReconciliationCheck — left unconfigured at the CLI level
    // for 7c; the chain client setup is the next CIT-AGENT-7c-tail.
    checks.push(Box::new(
        citrate_agent_core::doctor::checks::AnchorReconciliationCheck {
            client: None,
            expected_roots: vec![],
        },
    ));

    // Apply --check filter if any names were supplied.
    let checks: Vec<Box<dyn Check>> = if args.check.is_empty() {
        checks
    } else {
        checks
            .into_iter()
            .filter(|c| args.check.iter().any(|n| n == c.name()))
            .collect()
    };

    let report = doctor::run(&ctx, &checks);
    let toml_body = match report.to_toml() {
        Ok(s) => s,
        Err(e) => {
            eprintln!("emit toml: {e}");
            return 2;
        }
    };

    let body_to_write = if let Some(seed_path) = &args.seed {
        let surface = match Ed25519FileSurface::load(seed_path, Role::SecurityOfficer) {
            Ok(s) => s,
            Err(e) => {
                eprintln!("seed load: {e}");
                return 2;
            }
        };
        let signed = match report.sign(&surface) {
            Ok(s) => s,
            Err(e) => {
                eprintln!("sign: {e}");
                return 2;
            }
        };
        format!(
            "{}\n# signature.pubkey = \"{}\"\n# signature.signature = \"{}\"\n",
            signed.toml_body,
            hex::encode(signed.attestation.pubkey),
            hex::encode(&signed.attestation.signature_bytes)
        )
    } else {
        eprintln!("warning: report unsigned — supply --seed for SignedDoctorReport");
        toml_body
    };

    if let Some(out) = args.output {
        if let Err(e) = std::fs::write(&out, body_to_write.as_bytes()) {
            eprintln!("write {out:?}: {e}");
            return 2;
        }
    } else {
        print!("{body_to_write}");
    }

    match report.overall_status {
        Severity::Blocker => 1,
        Severity::Pass | Severity::Warn => 0,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn empty_config_produces_all_skip_passes() {
        let cfg_path = std::env::temp_dir().join("cit-agent-7c-empty.toml");
        std::fs::write(&cfg_path, b"[doctor]\nagent_did = \"did:test\"\n").unwrap();
        let out_path = std::env::temp_dir().join("cit-agent-7c-empty-report.toml");
        let _ = std::fs::remove_file(&out_path);
        let exit = run(DoctorArgs {
            config: cfg_path.clone(),
            output: Some(out_path.clone()),
            check: vec![],
            seed: None,
        });
        assert_eq!(exit, 0, "empty config produces Pass/Warn overall");
        let body = std::fs::read_to_string(&out_path).unwrap();
        assert!(body.contains("agent_did = \"did:test\""));
        // 11 checks should appear in the report.
        let appearances = body.matches("[[results]]").count();
        assert_eq!(appearances, 11);
        let _ = std::fs::remove_file(&cfg_path);
        let _ = std::fs::remove_file(&out_path);
    }

    #[test]
    fn missing_config_returns_exit_2() {
        let exit = run(DoctorArgs {
            config: PathBuf::from("/nonexistent/cit-agent-7c-no-config.toml"),
            output: None,
            check: vec![],
            seed: None,
        });
        assert_eq!(exit, 2);
    }

    #[test]
    fn filter_check_runs_subset() {
        let cfg_path = std::env::temp_dir().join("cit-agent-7c-filter.toml");
        std::fs::write(&cfg_path, b"[doctor]\nagent_did = \"did:test\"\n").unwrap();
        let out_path = std::env::temp_dir().join("cit-agent-7c-filter-report.toml");
        let _ = std::fs::remove_file(&out_path);
        let exit = run(DoctorArgs {
            config: cfg_path.clone(),
            output: Some(out_path.clone()),
            check: vec!["runtime-presence".into()],
            seed: None,
        });
        assert_eq!(exit, 0);
        let body = std::fs::read_to_string(&out_path).unwrap();
        let appearances = body.matches("[[results]]").count();
        assert_eq!(appearances, 1);
        assert!(body.contains("runtime-presence"));
        let _ = std::fs::remove_file(&cfg_path);
        let _ = std::fs::remove_file(&out_path);
    }
}
