//! Deterministic offline demonstration of the signed `hello` capsule.

use citrate_agent_core::audit::{AuditChain, EventType, FilesystemSink, GenesisInfo};
use citrate_agent_core::capsule::dispatch::CapsuleDispatch;
use citrate_agent_core::capsule::manifest::{Manifest, NetworkPolicy};
use serde::Serialize;
use std::fs::OpenOptions;
use std::io::Write;
use std::path::{Path, PathBuf};
use std::sync::Arc;

const CAPSULE_NAME: &str = "hello";
const INPUT_NAME: &str = "Tech Week";
const EXPECTED_OUTPUT: &str = "Hello, Tech Week";
const ACTOR: &str = "did:citrate:demo:tech-week";
// Logical times are part of the v1 evidence format. They are deliberately not wall-clock values.
const GENESIS_TIMESTAMP_NS: i64 = 1_767_225_600_000_000_000;
const EXECUTION_TIMESTAMP_NS: i64 = GENESIS_TIMESTAMP_NS + 1;

#[derive(clap::Args, Debug, Clone)]
pub struct DemoArgs {
    /// Existing directory containing the signed capsule fleet.
    #[arg(long, default_value = "capsules")]
    pub capsules_dir: PathBuf,
    /// Existing empty directory that will receive audit.jsonl and summary.json.
    #[arg(long)]
    pub evidence_dir: PathBuf,
}

#[derive(Serialize)]
struct DemoInput<'a> {
    name: &'a str,
}

#[derive(Serialize)]
struct CapsuleEvidence<'a> {
    name: &'a str,
    version: &'a str,
    content_hash: &'a str,
}

#[derive(Serialize)]
struct CapabilityEvidence {
    network: &'static str,
    filesystem: Vec<String>,
    chain_calls: Vec<String>,
    subagent_spawn: bool,
}

/// Versioned, typed payload stored inside the production audit record.
/// Struct field order gives serde_json a stable encoding without map-order dependence.
#[derive(Serialize)]
struct DemoAuditPayload<'a> {
    schema_version: &'static str,
    command: &'static str,
    capsule: CapsuleEvidence<'a>,
    capabilities: CapabilityEvidence,
    input: DemoInput<'a>,
    output: &'a str,
    capsule_signature_verified: bool,
    evidence_signed: bool,
    chain_anchored: bool,
    external_network_used: bool,
}

#[derive(Serialize)]
struct DemoSummary<'a> {
    schema_version: &'static str,
    command: &'static str,
    capsule: CapsuleEvidence<'a>,
    input: DemoInput<'a>,
    output: &'a str,
    capsule_signature_verified: bool,
    evidence_signed: bool,
    chain_anchored: bool,
    external_network_used: bool,
    audit_chain_verified: bool,
    audit_record_count: u64,
    audit_head_sha256: String,
}

pub fn run(args: DemoArgs) -> i32 {
    match execute(&args) {
        Ok(output) => {
            println!("{output}");
            0
        }
        Err(error) => {
            eprintln!("demo failed: {error}");
            1
        }
    }
}

fn execute(args: &DemoArgs) -> Result<String, String> {
    let evidence_dir = require_empty_evidence_dir(&args.evidence_dir)?;

    let dispatch = CapsuleDispatch::load_from_dir(&args.capsules_dir, None, None, None)
        .map_err(|error| format!("load signed capsule fleet: {error}"))?;
    let hello = dispatch
        .verified_manifest(CAPSULE_NAME)
        .map_err(|error| format!("load verified hello manifest: {error}"))?;
    confirm_offline_manifest(hello)?;

    let output_value = dispatch
        .call_json(CAPSULE_NAME, &serde_json::json!({ "name": INPUT_NAME }))
        .map_err(|error| format!("execute signed hello capsule: {error}"))?;
    let output = output_value
        .as_str()
        .ok_or_else(|| "signed hello capsule returned a non-string result".to_string())?;
    if output != EXPECTED_OUTPUT {
        return Err(format!(
            "signed hello capsule returned {output:?}, expected {EXPECTED_OUTPUT:?}"
        ));
    }

    let audit_path = evidence_dir.join("audit.jsonl");
    let audit_staging_path = evidence_dir.join(".audit.jsonl.tmp");
    let payload = encode_payload(hello, output)?;

    // The existing core audit implementation is intentionally the only persistence and
    // verification framework used here. This demo evidence is local, unsigned, and unanchored.
    let sink = Arc::new(
        FilesystemSink::create_new(&audit_staging_path)
            .map_err(|error| format!("open audit evidence: {error}"))?,
    );
    let audit_result = (|| {
        let mut chain = AuditChain::open_or_init(
            Arc::clone(&sink) as Arc<dyn citrate_agent_core::audit::AuditSink>,
            GenesisInfo {
                agent_did: ACTOR.to_string(),
                harness_version: env!("CARGO_PKG_VERSION").to_string(),
                // This local demo has no policy bundle or doctor report. Zero hashes are
                // explicit absent-value sentinels; capsule identity lives in the event payload.
                policy_bundle_hash: [0; 32],
                doctor_report_hash: [0; 32],
            },
            GENESIS_TIMESTAMP_NS,
        )
        .map_err(|error| format!("initialize audit chain: {error}"))?;
        chain
            .append(
                EventType::AuditExport,
                payload,
                ACTOR.to_string(),
                Vec::new(),
                None,
                EXECUTION_TIMESTAMP_NS,
            )
            .map_err(|error| format!("append demo audit record: {error}"))?;
        drop(chain);
        sink.sync_all()
            .map_err(|error| format!("synchronize audit evidence: {error}"))?;

        let reopened = AuditChain::open_existing(
            Arc::clone(&sink) as Arc<dyn citrate_agent_core::audit::AuditSink>
        )
        .map_err(|error| format!("reopen audit chain: {error}"))?
        .ok_or_else(|| "reopened audit chain is empty".to_string())?;
        let record_count = reopened
            .verify_integrity()
            .map_err(|error| format!("verify reopened audit chain: {error}"))?;
        if record_count != 2 {
            return Err(format!(
                "verified audit chain has {record_count} records; expected exactly 2"
            ));
        }
        Ok((record_count, hex::encode(reopened.last_hash())))
    })();
    let (record_count, audit_head_sha256) = match audit_result {
        Ok(result) => result,
        Err(error) => {
            drop(sink);
            return Err(cleanup_failure(error, &[&audit_staging_path]));
        }
    };
    drop(sink);
    publish_new(&audit_staging_path, &audit_path)
        .map_err(|error| cleanup_failure(error, &[&audit_staging_path]))?;

    let summary = DemoSummary {
        schema_version: "citrate-agent-demo-summary/v1",
        command: "citrate-agent demo",
        capsule: capsule_evidence(hello),
        input: DemoInput { name: INPUT_NAME },
        output,
        capsule_signature_verified: true,
        evidence_signed: false,
        chain_anchored: false,
        external_network_used: false,
        audit_chain_verified: true,
        audit_record_count: record_count,
        audit_head_sha256,
    };
    let mut summary_bytes = serde_json::to_vec_pretty(&summary)
        .map_err(|error| format!("encode summary evidence: {error}"))?;
    summary_bytes.push(b'\n');
    let summary_path = evidence_dir.join("summary.json");
    let summary_staging_path = evidence_dir.join(".summary.json.tmp");
    if let Err(error) = write_new_file(&summary_staging_path, &summary_bytes)
        .and_then(|()| publish_new(&summary_staging_path, &summary_path))
    {
        return Err(cleanup_failure(
            error,
            &[&summary_staging_path, &summary_path, &audit_path],
        ));
    }

    Ok(output.to_string())
}

fn require_empty_evidence_dir(path: &Path) -> Result<PathBuf, String> {
    let metadata = std::fs::symlink_metadata(path)
        .map_err(|error| format!("evidence directory must already exist at {path:?}: {error}"))?;
    if metadata.file_type().is_symlink() {
        return Err(format!(
            "evidence directory must not be a symlink: {path:?}"
        ));
    }
    #[cfg(windows)]
    {
        use std::os::windows::fs::MetadataExt;
        const FILE_ATTRIBUTE_REPARSE_POINT: u32 = 0x400;
        if metadata.file_attributes() & FILE_ATTRIBUTE_REPARSE_POINT != 0 {
            return Err(format!(
                "evidence directory must not be a reparse point: {path:?}"
            ));
        }
    }
    if !metadata.is_dir() {
        return Err(format!("evidence path is not a directory: {path:?}"));
    }
    let canonical = std::fs::canonicalize(path)
        .map_err(|error| format!("canonicalize evidence directory {path:?}: {error}"))?;
    let mut entries = std::fs::read_dir(&canonical)
        .map_err(|error| format!("read evidence directory {canonical:?}: {error}"))?;
    if entries
        .next()
        .transpose()
        .map_err(|error| format!("read evidence directory entry: {error}"))?
        .is_some()
    {
        return Err(format!(
            "evidence directory must be empty; refusing to overwrite anything in {canonical:?}"
        ));
    }
    Ok(canonical)
}

fn confirm_offline_manifest(manifest: &Manifest) -> Result<(), String> {
    let capability = &manifest.capability;
    if capability.network != NetworkPolicy::None
        || !capability.filesystem.is_empty()
        || !capability.chain_calls.is_empty()
        || capability.subagent_spawn
    {
        return Err(
            "hello manifest must declare network=none, no filesystem, no chain calls, and no subagent spawning"
                .to_string(),
        );
    }
    Ok(())
}

fn encode_payload(manifest: &Manifest, output: &str) -> Result<Vec<u8>, String> {
    serde_json::to_vec(&DemoAuditPayload {
        schema_version: "citrate-agent-demo-audit/v1",
        command: "citrate-agent demo",
        capsule: capsule_evidence(manifest),
        capabilities: CapabilityEvidence {
            network: "none",
            filesystem: Vec::new(),
            chain_calls: Vec::new(),
            subagent_spawn: false,
        },
        input: DemoInput { name: INPUT_NAME },
        output,
        capsule_signature_verified: true,
        evidence_signed: false,
        chain_anchored: false,
        external_network_used: false,
    })
    .map_err(|error| format!("encode typed audit payload: {error}"))
}

fn capsule_evidence(manifest: &Manifest) -> CapsuleEvidence<'_> {
    CapsuleEvidence {
        name: &manifest.capsule.name,
        version: &manifest.capsule.version,
        content_hash: &manifest.capsule.content_hash,
    }
}

fn write_new_file(path: &Path, bytes: &[u8]) -> Result<(), String> {
    let mut file = OpenOptions::new()
        .write(true)
        .create_new(true)
        .open(path)
        .map_err(|error| format!("create evidence file {path:?} without overwrite: {error}"))?;
    if let Err(error) = file.write_all(bytes).and_then(|()| file.sync_all()) {
        drop(file);
        let cleanup = std::fs::remove_file(path);
        return Err(match cleanup {
            Ok(()) => format!("write evidence file {path:?}: {error}"),
            Err(cleanup_error) => format!(
                "write evidence file {path:?}: {error}; cleanup also failed: {cleanup_error}"
            ),
        });
    }
    Ok(())
}

fn publish_new(staging: &Path, destination: &Path) -> Result<(), String> {
    std::fs::hard_link(staging, destination).map_err(|error| {
        format!("publish evidence {destination:?} without replacement: {error}")
    })?;
    if let Err(error) = std::fs::remove_file(staging) {
        let rollback = std::fs::remove_file(destination);
        return Err(match rollback {
            Ok(()) => format!("remove staging evidence {staging:?}: {error}"),
            Err(rollback_error) => format!(
                "remove staging evidence {staging:?}: {error}; rollback of {destination:?} also failed: {rollback_error}"
            ),
        });
    }
    Ok(())
}

fn cleanup_failure(error: String, paths: &[&Path]) -> String {
    let mut cleanup_errors = Vec::new();
    for path in paths {
        match std::fs::remove_file(path) {
            Ok(()) => {}
            Err(cleanup_error) if cleanup_error.kind() == std::io::ErrorKind::NotFound => {}
            Err(cleanup_error) => cleanup_errors.push(format!("{path:?}: {cleanup_error}")),
        }
    }
    if cleanup_errors.is_empty() {
        error
    } else {
        format!("{error}; cleanup failed for {}", cleanup_errors.join(", "))
    }
}

#[cfg(test)]
#[path = "demo_cmd_tests.rs"]
mod tests;
