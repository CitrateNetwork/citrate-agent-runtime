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
        // HUP-S2.5: filesystem and network declarations are enforced by the
        // capsule sandbox (`capsule::sandbox`): WASI preopens scoped to live
        // folder grants, and a socket allowlist. A declaration is a ceiling;
        // the sandbox opens nothing the member has not granted. Malformed
        // declarations are refused here, at load.
        crate::capsule::filesystem::parse_all(&self.capability.filesystem)?;
        let allow = crate::capsule::sandbox::parse_network_allow(&self.capability.network_allow)?;
        match self.capability.network {
            NetworkPolicy::EgressAllowed if allow.is_empty() => {
                return Err(AgentError::Capsule(
                    "[capability].network = \"egress-allowed\" needs a non-empty \
                     [capability].network_allow list of exact ip:port addresses"
                        .to_string(),
                ));
            }
            NetworkPolicy::None | NetworkPolicy::BrokerOnly if !allow.is_empty() => {
                return Err(AgentError::Capsule(
                    "[capability].network_allow is only valid with network = \"egress-allowed\""
                        .to_string(),
                ));
            }
            _ => {}
        }
        // PBA-L6b-012: a tier-high action needs signatures from two DISTINCT
        // roles of `required_roles` (Quorum::NofM counts roles, not signers).
        // Fewer than two distinct approving roles would make every such action
        // permanently unapprovable, so refuse the manifest up front.
        if self.risk.tier == RiskTier::High {
            let distinct: std::collections::BTreeSet<Role> = self
                .risk
                .required_roles
                .iter()
                .copied()
                .filter(|r| *r != Role::Auditor)
                .collect();
            if distinct.len() < 2 {
                return Err(AgentError::Capsule(
                    "[risk].tier = \"high\" requires at least two distinct approving roles in \
                     required_roles (separation of duties, PBA-L6b-012)"
                        .to_string(),
                ));
            }
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
    /// HUP-S2.5: the exact remote socket addresses (`ip:port`, IPv6 as
    /// `[addr]:port`) an `egress-allowed` capsule may connect or send to.
    /// Enforced by the WASI socket check in `capsule::sandbox`; name lookup
    /// stays disabled, so entries are addresses, never host names. Must be
    /// empty unless `network = "egress-allowed"`, and non-empty when it is.
    #[serde(default)]
    pub network_allow: Vec<String>,
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
name = "defense-prime-query-decisions-by-signer"
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
        assert_eq!(m.capsule.name, "defense-prime-query-decisions-by-signer");
        assert_eq!(m.risk.tier, RiskTier::Low);
        assert_eq!(m.signing.tier, SigningTier::Bundled);
        assert_eq!(m.capability.network, NetworkPolicy::None);
        assert_eq!(m.data_class.reads, vec![DataClass::Public]);
    }

    /// PBA-L6b-012: tier high needs two distinct approving roles (NofM counts
    /// roles), otherwise every such action would be unapprovable.
    #[test]
    fn high_tier_requires_two_distinct_approving_roles_pba_l6b_012() {
        let high = |roles: &str| {
            WORKED_EXAMPLE
                .replace(r#"tier = "low""#, r#"tier = "high""#)
                .replace(r#"required_roles = ["Operator"]"#, &format!("required_roles = {roles}"))
        };
        for bad in [
            r#"["Reviewer"]"#,
            r#"["Reviewer", "Reviewer"]"#,
            r#"["Reviewer", "Auditor"]"#,
            "[]",
        ] {
            let err = Manifest::parse(&high(bad)).expect_err(bad);
            assert!(err.to_string().contains("distinct approving roles"), "{bad}: {err}");
        }
        Manifest::parse(&high(r#"["Reviewer", "ComplianceOfficer"]"#)).expect("two roles ok");
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

    /// HUP-S2.5: a filesystem declaration is now enforced by WASI preopens
    /// scoped to live folder grants (`capsule::sandbox`), so a well-formed
    /// one loads. It is a ceiling, not a grant: nothing is opened until a
    /// member's grant covers the mounted folder.
    #[test]
    fn filesystem_declaration_loads_now_that_preopens_enforce_it() {
        let ok = WORKED_EXAMPLE.replace("filesystem = []", r#"filesystem = ["read:/data"]"#);
        let m = Manifest::parse(&ok).expect("declared filesystem capability loads");
        assert_eq!(m.capability.filesystem, vec!["read:/data".to_string()]);
    }

    #[test]
    fn malformed_filesystem_entry_is_refused_at_parse() {
        for bad in [
            r#"["exec:/bin"]"#,
            r#"["read:relative"]"#,
            r#"["read:/data/../etc"]"#,
        ] {
            let m = WORKED_EXAMPLE.replace("filesystem = []", &format!("filesystem = {bad}"));
            let err = Manifest::parse(&m).expect_err(bad);
            assert!(err.to_string().contains("filesystem"), "{bad}: {err}");
        }
    }

    /// Egress is enforced by a socket allowlist: `egress-allowed` without
    /// `network_allow` would reach nothing, so it is refused as a mistake.
    #[test]
    fn egress_allowed_requires_a_network_allowlist() {
        let bad = WORKED_EXAMPLE.replace(r#"network = "none""#, r#"network = "egress-allowed""#);
        let err = Manifest::parse(&bad).expect_err("egress without an allowlist");
        assert!(err.to_string().contains("network_allow"), "actual: {err}");
    }

    #[test]
    fn egress_allowed_with_exact_socket_addresses_loads() {
        let ok = WORKED_EXAMPLE.replace(
            r#"network = "none""#,
            "network = \"egress-allowed\"\nnetwork_allow = [\"1.1.1.1:443\", \"[2606:4700::1111]:8443\"]",
        );
        let m = Manifest::parse(&ok).expect("egress with an allowlist loads");
        assert_eq!(m.capability.network, NetworkPolicy::EgressAllowed);
        assert_eq!(m.capability.network_allow.len(), 2);
    }

    #[test]
    fn network_allowlist_without_egress_is_refused() {
        for policy in ["none", "broker-only"] {
            let bad = WORKED_EXAMPLE.replace(
                r#"network = "none""#,
                &format!("network = \"{policy}\"\nnetwork_allow = [\"1.1.1.1:443\"]"),
            );
            let err = Manifest::parse(&bad).expect_err(policy);
            assert!(err.to_string().contains("network_allow"), "{policy}: {err}");
        }
    }

    #[test]
    fn network_allowlist_entries_must_be_exact_remote_addresses() {
        for bad in [
            "example.com:443",
            "0.0.0.0:443",
            "1.1.1.1:0",
            "1.1.1.1",
            "[::]:443",
        ] {
            let m = WORKED_EXAMPLE.replace(
                r#"network = "none""#,
                &format!("network = \"egress-allowed\"\nnetwork_allow = [\"{bad}\"]"),
            );
            let err = Manifest::parse(&m).expect_err(bad);
            assert!(err.to_string().contains("network_allow"), "{bad}: {err}");
        }
    }

    /// A signed manifest alone cannot point a capsule at this machine, the local network, or a
    /// cloud metadata service: only public addresses may be allowlisted.
    #[test]
    fn network_allowlist_entries_must_be_public_addresses() {
        for bad in [
            "127.0.0.1:8545",
            "169.254.169.254:80",
            "10.0.0.5:443",
            "172.16.1.1:443",
            "192.168.1.1:80",
            "100.64.0.1:443",
            "203.0.113.7:443",
            "[::1]:443",
            "[fd00::1]:443",
            "[fe80::1]:443",
            "[::ffff:127.0.0.1]:80",
            "[2002:7f00:1::1]:80",
        ] {
            let m = WORKED_EXAMPLE.replace(
                r#"network = "none""#,
                &format!("network = \"egress-allowed\"\nnetwork_allow = [\"{bad}\"]"),
            );
            let err = Manifest::parse(&m).expect_err(bad);
            assert!(err.to_string().contains("public"), "{bad}: {err}");
        }
    }

    /// `broker-only` loads: the capsule gets no direct socket at all (the
    /// sandbox denies every address); traffic goes through host brokers.
    #[test]
    fn broker_only_loads_and_has_no_allowlist() {
        let ok = WORKED_EXAMPLE.replace(r#"network = "none""#, r#"network = "broker-only""#);
        let m = Manifest::parse(&ok).expect("broker-only loads");
        assert!(m.capability.network_allow.is_empty());
    }

    #[test]
    fn reject_bad_dns_label() {
        let bad = WORKED_EXAMPLE.replace(
            r#"name = "defense-prime-query-decisions-by-signer""#,
            r#"name = "defense_prime_Bad_Name""#,
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
