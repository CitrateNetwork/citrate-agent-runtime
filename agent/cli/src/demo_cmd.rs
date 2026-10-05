//! Deterministic offline demonstration of the signed `hello` capsule.

use citrate_agent_core::audit::{AuditChain, EventType, FilesystemSink, GenesisInfo};
use citrate_agent_core::capsule::bundled_key;
use citrate_agent_core::capsule::dispatch::CapsuleDispatch;
use citrate_agent_core::capsule::manifest::{Manifest, NetworkPolicy};
use citrate_agent_core::capsule::Capsule;
use serde::Serialize;
use std::fs::{File, OpenOptions};
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
    require_empty_evidence_dir(&args.evidence_dir)?;

    let dispatch = CapsuleDispatch::load_from_dir(&args.capsules_dir, None, None, None)
        .map_err(|error| format!("load signed capsule fleet: {error}"))?;
    let hello = load_verified_hello(&args.capsules_dir)?;
    confirm_offline_manifest(&hello.manifest)?;

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

    let audit_path = args.evidence_dir.join("audit.jsonl");
    reserve_new_file(&audit_path, "audit evidence")?;
    let policy_bundle_hash = decode_content_hash(&hello.manifest.capsule.content_hash)?;
    let payload = encode_payload(&hello.manifest, output)?;

    // The existing core audit implementation is intentionally the only persistence and
    // verification framework used here. This demo evidence is local, unsigned, and unanchored.
    let sink = Arc::new(
        FilesystemSink::open(&audit_path)
            .map_err(|error| format!("open audit evidence: {error}"))?,
    );
    let mut chain = AuditChain::open_or_init(
        sink,
        GenesisInfo {
            agent_did: ACTOR.to_string(),
            harness_version: env!("CARGO_PKG_VERSION").to_string(),
            policy_bundle_hash,
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

    let reopened_sink = Arc::new(
        FilesystemSink::open(&audit_path)
            .map_err(|error| format!("reopen audit evidence: {error}"))?,
    );
    let reopened = AuditChain::open_existing(reopened_sink)
        .map_err(|error| format!("reopen audit chain: {error}"))?
        .ok_or_else(|| "reopened audit chain is empty".to_string())?;
    let record_count = reopened
        .verify_integrity()
        .map_err(|error| format!("verify reopened audit chain: {error}"))?;

    let summary = DemoSummary {
        schema_version: "citrate-agent-demo-summary/v1",
        command: "citrate-agent demo",
        capsule: capsule_evidence(&hello.manifest),
        input: DemoInput { name: INPUT_NAME },
        output,
        capsule_signature_verified: true,
        evidence_signed: false,
        chain_anchored: false,
        external_network_used: false,
        audit_chain_verified: true,
        audit_record_count: record_count,
        audit_head_sha256: hex::encode(reopened.last_hash()),
    };
    let mut summary_bytes = serde_json::to_vec_pretty(&summary)
        .map_err(|error| format!("encode summary evidence: {error}"))?;
    summary_bytes.push(b'\n');
    write_new_summary(&args.evidence_dir.join("summary.json"), &summary_bytes)?;

    Ok(output.to_string())
}

fn require_empty_evidence_dir(path: &Path) -> Result<(), String> {
    let metadata = std::fs::metadata(path)
        .map_err(|error| format!("evidence directory must already exist at {path:?}: {error}"))?;
    if !metadata.is_dir() {
        return Err(format!("evidence path is not a directory: {path:?}"));
    }
    let mut entries = std::fs::read_dir(path)
        .map_err(|error| format!("read evidence directory {path:?}: {error}"))?;
    if entries
        .next()
        .transpose()
        .map_err(|error| format!("read evidence directory entry: {error}"))?
        .is_some()
    {
        return Err(format!(
            "evidence directory must be empty; refusing to overwrite anything in {path:?}"
        ));
    }
    Ok(())
}

fn load_verified_hello(capsules_dir: &Path) -> Result<Capsule, String> {
    let path = capsules_dir.join(CAPSULE_NAME).join("hello.cps");
    let file = File::open(&path)
        .map_err(|error| format!("signed hello capsule is required at {path:?}: {error}"))?;
    Capsule::from_archive_verified(file, &bundled_key::registry())
        .map_err(|error| format!("verify signed hello capsule: {error}"))
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

fn decode_content_hash(value: &str) -> Result<[u8; 32], String> {
    let encoded = value
        .strip_prefix("sha256:")
        .ok_or_else(|| "hello content hash lacks sha256 prefix".to_string())?;
    let bytes =
        hex::decode(encoded).map_err(|error| format!("decode hello content hash: {error}"))?;
    bytes
        .try_into()
        .map_err(|_| "hello content hash is not 32 bytes".to_string())
}

fn reserve_new_file(path: &Path, label: &str) -> Result<(), String> {
    OpenOptions::new()
        .write(true)
        .create_new(true)
        .open(path)
        .map(|_| ())
        .map_err(|error| format!("reserve {label} {path:?} without overwrite: {error}"))
}

fn write_new_summary(path: &Path, bytes: &[u8]) -> Result<(), String> {
    let mut file = OpenOptions::new()
        .write(true)
        .create_new(true)
        .open(path)
        .map_err(|error| format!("create summary evidence {path:?} without overwrite: {error}"))?;
    if let Err(error) = file.write_all(bytes).and_then(|()| file.sync_all()) {
        drop(file);
        let _ = std::fs::remove_file(path);
        return Err(format!("write summary evidence {path:?}: {error}"));
    }
    Ok(())
}

#[cfg(test)]
#[path = "demo_cmd_tests.rs"]
mod tests;
