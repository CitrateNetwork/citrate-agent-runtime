//! TOML config schema for the cit-agent CLI — CIT-AGENT-7c.
//!
//! Pairs with the `doctor` subcommand: the config wires each of the
//! 11 RFC §10.2 checks. Sections are optional so operators stage
//! the configuration incrementally; missing sections produce
//! Skip-with-Pass results in the doctor report.

use serde::{Deserialize, Serialize};
use std::path::PathBuf;

#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct AgentCliConfig {
    #[serde(default)]
    pub doctor: DoctorConfig,
}

#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct DoctorConfig {
    /// AgentSBT DID. Hard-coded into every report.
    #[serde(default)]
    pub agent_did: String,
    #[serde(default)]
    pub audit_chain: Option<AuditChainSection>,
    #[serde(default)]
    pub approval_queue_depth: Option<ApprovalQueueDepthSection>,
    #[serde(default)]
    pub retention: Option<RetentionSection>,
    #[serde(default)]
    pub tla_ci: Option<TlaCiSection>,
    #[serde(default)]
    pub policy_bundle: Option<PolicyBundleSection>,
    #[serde(default)]
    pub capsule_reverify: Option<CapsuleReverifySection>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AuditChainSection {
    pub path: PathBuf,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ApprovalQueueDepthSection {
    pub warn_threshold: usize,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RetentionSection {
    pub max_age_days: u32,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TlaCiSection {
    pub status_file: PathBuf,
    #[serde(default = "default_tla_max_age_hours")]
    pub max_age_hours: u64,
}

fn default_tla_max_age_hours() -> u64 {
    48
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PolicyBundleSection {
    pub files: Vec<PolicyBundleFile>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PolicyBundleFile {
    pub path: PathBuf,
    /// Hex-encoded SHA-256 of the expected file contents.
    pub sha256: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CapsuleReverifySection {
    pub capsule_paths: Vec<PathBuf>,
}

impl AgentCliConfig {
    pub fn from_toml(s: &str) -> Result<Self, String> {
        toml::from_str(s).map_err(|e| format!("config parse: {e}"))
    }

    pub fn load(path: &std::path::Path) -> Result<Self, String> {
        let s = std::fs::read_to_string(path)
            .map_err(|e| format!("read config {path:?}: {e}"))?;
        Self::from_toml(&s)
    }
}

/// Decode a hex sha256 string to a fixed [u8; 32].
pub fn parse_sha256_hex(s: &str) -> Result<[u8; 32], String> {
    let stripped = s.trim().trim_start_matches("0x").trim_start_matches("sha256:");
    let bytes = hex::decode(stripped).map_err(|e| format!("hex decode: {e}"))?;
    if bytes.len() != 32 {
        return Err(format!("sha256 must be 32 bytes; got {}", bytes.len()));
    }
    let mut out = [0u8; 32];
    out.copy_from_slice(&bytes);
    Ok(out)
}

#[cfg(test)]
mod tests {
    use super::*;

    const EXAMPLE_TOML: &str = r#"
[doctor]
agent_did = "did:citrate:agent:0xab12"

[doctor.audit_chain]
path = "/var/lib/citrate-agent/audit.jsonl"

[doctor.retention]
max_age_days = 90

[doctor.tla_ci]
status_file = "/var/lib/citrate-agent/tla-ci-status.json"
max_age_hours = 48

[[doctor.policy_bundle.files]]
path = "/etc/citrate-agent/policy.toml"
sha256 = "0000000000000000000000000000000000000000000000000000000000000000"

[doctor.capsule_reverify]
capsule_paths = ["/var/lib/citrate-agent/capsules/example.cps"]
"#;

    #[test]
    fn round_trip_toml() {
        let cfg = AgentCliConfig::from_toml(EXAMPLE_TOML).expect("parse");
        assert_eq!(cfg.doctor.agent_did, "did:citrate:agent:0xab12");
        assert!(cfg.doctor.audit_chain.is_some());
        assert_eq!(cfg.doctor.retention.unwrap().max_age_days, 90);
        let tla = cfg.doctor.tla_ci.unwrap();
        assert_eq!(tla.max_age_hours, 48);
        let policy = cfg.doctor.policy_bundle.unwrap();
        assert_eq!(policy.files.len(), 1);
        let caps = cfg.doctor.capsule_reverify.unwrap();
        assert_eq!(caps.capsule_paths.len(), 1);
    }

    #[test]
    fn empty_toml_parses() {
        let cfg = AgentCliConfig::from_toml("").expect("empty parses");
        assert!(cfg.doctor.agent_did.is_empty());
        assert!(cfg.doctor.audit_chain.is_none());
    }

    #[test]
    fn parse_sha256_hex_round_trip() {
        let expected = [0xab; 32];
        let s = hex::encode(expected);
        assert_eq!(parse_sha256_hex(&s).unwrap(), expected);
        assert_eq!(parse_sha256_hex(&format!("0x{s}")).unwrap(), expected);
        assert_eq!(parse_sha256_hex(&format!("sha256:{s}")).unwrap(), expected);
    }

    #[test]
    fn parse_sha256_hex_rejects_wrong_length() {
        assert!(parse_sha256_hex("0xabcd").is_err());
    }
}
