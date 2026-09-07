//! Capsule manifest schema + parser — RFC-CIT-AGENT-0001 §4.3.
//!
//! The manifest is the source of truth for every runtime policy
//! decision. The harness MUST NOT make policy decisions based on the
//! WASM bytecode, the WIT interface, or `procedure.md` — only on the
//! signed manifest. This module is the typed representation +
//! validator.
//!
//! Field order in the source TOML is normative for the canonical-CBOR
//! hash used in signatures. See `CANONICAL_FIELD_ORDER` below.

use crate::error::AgentError;
use serde::{Deserialize, Serialize};

/// Field-order convention for canonical re-emission. The TOML on
/// disk SHOULD be ordered this way for the signature canonical form
/// to compute deterministically. Enforcement is in 3b
/// (`capsule/verify.rs`) when the signing-canonicalization lands.
pub const CANONICAL_FIELD_ORDER: &[&str] = &[
    "capsule",
    "capability",
    "data_class",
    "risk",
    "overlay",
    "procedure",
    "provenance",
    "signing",
];

/// The top-level manifest as parsed from `manifest.toml`. All fields
/// are required at the schema level; validation errors carry the
/// missing/invalid field name.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Manifest {
    pub capsule: CapsuleMetadata,
    pub capability: CapabilitySet,
    pub data_class: DataClassDecl,
    pub risk: RiskDecl,
    pub overlay: OverlayDecl,
    #[serde(default)]
    pub procedure: ProcedureDecl,
    pub provenance: ProvenanceDecl,
    pub signing: SigningDecl,
}

impl Manifest {
    /// Parse + validate a TOML manifest string. Returns the typed
    /// Manifest on success; `AgentError::Capsule(msg)` on schema or
    /// validation error.
    pub fn parse(toml: &str) -> Result<Self, AgentError> {
        let manifest: Self =
            toml::from_str(toml).map_err(|e| AgentError::Capsule(format!("manifest parse: {e}")))?;
        manifest.validate()?;
        Ok(manifest)
    }

    fn validate(&self) -> Result<(), AgentError> {
        validate_dns_label(&self.capsule.name)?;
        validate_semver(&self.capsule.version)?;
        validate_sha256_prefix(&self.capsule.content_hash)?;
        if self.capability.subagent_spawn {
            return Err(AgentError::Capsule(
                "[capability].subagent_spawn = false is required in v1 (RFC §1.3 N1)"
                    .to_string(),
            ));
        }
        if self.data_class.reads.contains(&DataClass::Itar) && self.risk.break_glass_eligible {
            return Err(AgentError::Capsule(
                "[risk].break_glass_eligible MUST be false for capsules that read ITAR data \
                 (RFC §2.3 + §5.5)"
                    .to_string(),
            ));
        }
        // AR-B-011: the `[capability].filesystem` allow-list and a
        // `network != "none"` policy are PARSED but NEVER enforced — `HostCtx`
        // builds an empty `WasiCtx` with no preopens and no `socket_addr_check`,
        // so the declaration reads as a working control while nothing consults
        // it. Rather than let a manifest advertise a capability the runtime
        // cannot physically enforce (RFC §4.5: "enforcement is physical, not
        // advisory"), refuse to load it until per-path/per-socket enforcement
        // exists. No shipped capsule declares either today, so this is
        // fail-closed with no behavioral loss.
        if !self.capability.filesystem.is_empty() {
            return Err(AgentError::Capsule(
                "[capability].filesystem is declared but per-path enforcement is not implemented \
                 (AR-B-011): the runtime builds an empty WASI preopen table, so the allow-list \
                 would be inert. Remove the declaration until filesystem sandboxing is wired."
                    .to_string(),
            ));
        }
        if self.capability.network != NetworkPolicy::None {
            return Err(AgentError::Capsule(
                "[capability].network != \"none\" is declared but network enforcement is not \
                 implemented (AR-B-011): the runtime installs no socket_addr_check, so the policy \
                 would be inert. Keep network = \"none\" until egress enforcement is wired."
                    .to_string(),
            ));
        }
        Ok(())
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CapsuleMetadata {
    pub name: String,
    pub version: String,
    pub content_hash: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CapabilitySet {
    pub network: NetworkPolicy,
    #[serde(default)]
    pub filesystem: Vec<String>,
    #[serde(default)]
    pub chain_calls: Vec<String>,
    pub subagent_spawn: bool,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum NetworkPolicy {
    None,
    BrokerOnly,
    EgressAllowed,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DataClassDecl {
    #[serde(default)]
    pub reads: Vec<DataClass>,
    #[serde(default)]
    pub writes: Vec<DataClass>,
    #[serde(default)]
    pub emits: Vec<DataClass>,
}

/// Per RFC §7.2 + planset `02_COMPLIANCE_MAP.md` lattice. The
/// `serde(rename)` strings match the manifest's literal labels.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum DataClass {
    #[serde(rename = "PUBLIC")]
    Public,
    #[serde(rename = "CUI")]
    Cui,
    #[serde(rename = "PHI")]
    Phi,
    #[serde(rename = "FERPA")]
    Ferpa,
    #[serde(rename = "FERPA-directory")]
    FerpaDirectory,
    #[serde(rename = "FERPA-restricted")]
    FerpaRestricted,
    #[serde(rename = "ITAR")]
    Itar,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RiskDecl {
    pub tier: RiskTier,
    #[serde(default)]
    pub required_roles: Vec<Role>,
    pub break_glass_eligible: bool,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum RiskTier {
    Low,
    Medium,
    High,
    Critical,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, PartialOrd, Ord, Serialize, Deserialize)]
pub enum Role {
    Operator,
    Reviewer,
    ComplianceOfficer,
    SecurityOfficer,
    Auditor,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct OverlayDecl {
    #[serde(default)]
    pub certified: Vec<String>,
    #[serde(default)]
    pub not_certified: Vec<String>,
}

#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct ProcedureDecl {
    #[serde(default)]
    pub gates: Vec<GateStep>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct GateStep {
    pub step: String,
    pub role: Role,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ProvenanceDecl {
    pub publisher: String,
    pub build_reproducible: bool,
    pub agentile_sprint: String,
    #[serde(default)]
    pub tla_spec: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SigningDecl {
    pub tier: SigningTier,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum SigningTier {
    Bundled,
    Managed,
    Workspace,
}

// ── Validation helpers ────────────────────────────────────────────

fn validate_dns_label(s: &str) -> Result<(), AgentError> {
    if s.is_empty() || s.len() > 63 {
        return Err(AgentError::Capsule(format!(
            "[capsule].name must be 1..=63 chars, got {}",
            s.len()
        )));
    }
    if !s
        .chars()
        .all(|c| c.is_ascii_lowercase() || c.is_ascii_digit() || c == '-')
    {
        return Err(AgentError::Capsule(format!(
            "[capsule].name '{s}' must be DNS-label charset (a-z 0-9 -)"
        )));
    }
    if s.starts_with('-') || s.ends_with('-') {
        return Err(AgentError::Capsule(format!(
            "[capsule].name '{s}' must not start or end with '-'"
        )));
    }
    Ok(())
}

fn validate_semver(s: &str) -> Result<(), AgentError> {
    let parts: Vec<&str> = s.split('.').collect();
    if parts.len() != 3 {
        return Err(AgentError::Capsule(format!(
            "[capsule].version '{s}' is not SemVer X.Y.Z"
        )));
    }
    for (i, p) in parts.iter().enumerate() {
        // Allow build-metadata suffix on the patch segment per SemVer.
        let core = if i == 2 {
            p.split(['-', '+']).next().unwrap_or(p)
        } else {
            p
        };
        if core.parse::<u64>().is_err() {
            return Err(AgentError::Capsule(format!(
                "[capsule].version '{s}' segment {i} is not a number"
            )));
        }
    }
    Ok(())
}

fn validate_sha256_prefix(s: &str) -> Result<(), AgentError> {
    let prefix = "sha256:";
    if !s.starts_with(prefix) {
        return Err(AgentError::Capsule(format!(
            "[capsule].content_hash '{s}' must begin with '{prefix}'"
        )));
    }
    let hex = &s[prefix.len()..];
    if hex.len() != 64 {
        return Err(AgentError::Capsule(format!(
            "[capsule].content_hash hex must be 64 chars, got {}",
            hex.len()
        )));
    }
    if !hex.chars().all(|c| c.is_ascii_hexdigit()) {
        return Err(AgentError::Capsule(format!(
            "[capsule].content_hash '{s}' must be lowercase hex"
        )));
    }
    Ok(())
}

// ── Tests ─────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;

    /// The BFR-INT-12 worked example from planset
    /// `03_CAPSULE_MODEL.md`. Content_hash is a synthetic 64-char
    /// hex value because 3a doesn't compute the real hash from
    /// archive contents (that's 3b).
    const WORKED_EXAMPLE: &str = r#"
[capsule]
name = "boeing-query-decisions-by-signer"
version = "0.1.0"
content_hash = "sha256:0000000000000000000000000000000000000000000000000000000000000000"

[capability]
network = "none"
filesystem = []
chain_calls = ["eth_call:0x4a86659BDab24dc444C72fbbaD4cd83491820E40"]
subagent_spawn = false

[data_class]
reads = ["PUBLIC"]
writes = []
emits = ["PUBLIC"]

[risk]
tier = "low"
required_roles = ["Operator"]
break_glass_eligible = false

[overlay]
certified = ["FERPA", "HIPAA", "FedRAMP-High", "CMMC-L3"]
not_certified = []

[procedure]
gates = []

[provenance]
publisher = "did:citrate:agent:0xab12"
build_reproducible = true
agentile_sprint = "2026-05-14-bfr-int-12-agent-harness"
tla_spec = ""

[signing]
tier = "bundled"
"#;

    #[test]
    fn parse_worked_example() {
        let m = Manifest::parse(WORKED_EXAMPLE).expect("worked example parses");
        assert_eq!(m.capsule.name, "boeing-query-decisions-by-signer");
        assert_eq!(m.risk.tier, RiskTier::Low);
        assert_eq!(m.signing.tier, SigningTier::Bundled);
        assert_eq!(m.capability.network, NetworkPolicy::None);
        assert_eq!(m.data_class.reads, vec![DataClass::Public]);
    }

    #[test]
    fn reject_subagent_spawn_true() {
        let bad = WORKED_EXAMPLE.replace("subagent_spawn = false", "subagent_spawn = true");
        let err = Manifest::parse(&bad).expect_err("v1 forbids subagent_spawn");
        let msg = err.to_string();
        assert!(msg.contains("subagent_spawn"), "actual: {msg}");
    }

    #[test]
    fn reject_itar_with_break_glass() {
        let bad = WORKED_EXAMPLE
            .replace(r#"reads = ["PUBLIC"]"#, r#"reads = ["ITAR"]"#)
            .replace(
                "break_glass_eligible = false",
                "break_glass_eligible = true",
            );
        let err = Manifest::parse(&bad).expect_err("ITAR + break-glass forbidden");
        let msg = err.to_string();
        assert!(msg.contains("ITAR"), "actual: {msg}");
        assert!(msg.contains("break_glass"), "actual: {msg}");
    }

    #[test]
    fn reject_declared_but_unenforced_filesystem_capability() {
        // AR-B-011: a filesystem allow-list is inert (no preopens are wired), so
        // a manifest declaring one must be refused rather than advertise a
        // control the runtime cannot enforce.
        let bad = WORKED_EXAMPLE.replace("filesystem = []", r#"filesystem = ["read:/data"]"#);
        let err = Manifest::parse(&bad).expect_err("unenforced filesystem capability refused");
        assert!(err.to_string().contains("filesystem"), "actual: {err}");
    }

    #[test]
    fn reject_declared_but_unenforced_network_capability() {
        // AR-B-011: network != "none" is inert (no socket_addr_check), so it
        // must be refused at load.
        let bad = WORKED_EXAMPLE.replace(r#"network = "none""#, r#"network = "egress-allowed""#);
        let err = Manifest::parse(&bad).expect_err("unenforced network capability refused");
        assert!(err.to_string().contains("network"), "actual: {err}");
    }

    #[test]
    fn reject_bad_dns_label() {
        let bad = WORKED_EXAMPLE.replace(
            r#"name = "boeing-query-decisions-by-signer""#,
            r#"name = "Boeing_Bad_Name""#,
        );
        let err = Manifest::parse(&bad).expect_err("uppercase + underscore forbidden");
        assert!(err.to_string().contains("DNS-label"));
    }

    #[test]
    fn reject_bad_semver() {
        let bad = WORKED_EXAMPLE.replace(r#"version = "0.1.0""#, r#"version = "v0.1""#);
        let err = Manifest::parse(&bad).expect_err("v-prefix + 2 segments rejected");
        assert!(err.to_string().contains("SemVer"));
    }

    #[test]
    fn reject_missing_content_hash_prefix() {
        let bad = WORKED_EXAMPLE.replace(
            r#"content_hash = "sha256:0000000000000000000000000000000000000000000000000000000000000000""#,
            r#"content_hash = "0000000000000000000000000000000000000000000000000000000000000000""#,
        );
        let err = Manifest::parse(&bad).expect_err("must begin with sha256:");
        assert!(err.to_string().contains("sha256:"));
    }

    #[test]
    fn reject_short_hash() {
        let bad = WORKED_EXAMPLE.replace(
            r#"content_hash = "sha256:0000000000000000000000000000000000000000000000000000000000000000""#,
            r#"content_hash = "sha256:0000""#,
        );
        let err = Manifest::parse(&bad).expect_err("hex must be 64 chars");
        assert!(err.to_string().contains("64"));
    }
}
