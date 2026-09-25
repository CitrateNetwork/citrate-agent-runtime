//! Capsule fleet allowlist with a version floor — PBA-L6b-015.
//!
//! A valid bundled-tier publisher signature proves only that the capsule was
//! signed with the bundled key at SOME point. Without an allowlist, every
//! capsule ever signed with that key stays runnable: an older signed manifest
//! (lower tier, wider `chain_calls`) can be rolled back onto a host, and a test
//! capsule signed for CI (`eth-sender-test`) ran as part of the fleet.
//!
//! The runtime therefore admits a verified capsule only when its
//! `(name, version, content_hash)` is on the allowlist compiled into this
//! binary:
//!
//! * `name` must be listed (unknown names are refused);
//! * `version` must be at or above the entry's `min_version` (the floor —
//!   raise it to revoke every older release of a capsule);
//! * `content_hash` (the value the publisher signature covers) must be one of
//!   the entry's pinned hashes (removing a hash revokes that exact build).
//!
//! Trust root: the list ships inside the signed / notarized runtime binary,
//! next to the bundled publisher key it constrains, so it is exactly as
//! authentic as that key. Moving it to a separately signed file (so the fleet
//! can update without a binary release) needs the HSM-held publisher key and
//! is an OWNER step; see the PBA-L6b-015 notes in the PR.
//!
//! Updating: after re-packing a capsule with `cit-capsule-pack`, add the new
//! `content_hash` from its `.cps` manifest to the entry (and raise
//! `min_version` to retire older builds). The
//! `bundled_allowlist_matches_the_shipped_fleet` test fails until the list and
//! `capsules/` agree.

use crate::capsule::manifest::Manifest;

/// One allowlisted capsule.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AllowEntry {
    pub name: String,
    /// Lowest `major.minor.patch` that may run.
    pub min_version: String,
    /// The signed `content_hash` values (`sha256:<hex>`) that may run.
    pub content_hashes: Vec<String>,
}

/// The set of capsules this runtime will execute.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct FleetAllowlist {
    entries: Vec<AllowEntry>,
}

/// `(name, min_version, content_hashes)` of the bundled fleet. The shipped
/// `.cps` archives under `capsules/` are the source of these hashes.
const BUNDLED_FLEET: &[(&str, &str, &[&str])] = &[
    (
        "anchor-session",
        "0.1.0",
        &["sha256:48c02c8c268c9383eb5b61b1d1ac0d78ba207876727ba3dbbe09d698ff4e5109"],
    ),
    (
        "echo-chain",
        "0.1.0",
        &["sha256:008f8bcbc66a444a604998f54757588071f59a950abf975465cdd3ca2c7b7631"],
    ),
    (
        "hello",
        "0.1.0",
        &["sha256:88c703080488b4852035a4007351a6d4cd63a065771881385cd2d3e2ffaf34f9"],
    ),
    (
        "list-compliance-posture",
        "0.1.0",
        &["sha256:926b604a825c2b1276a5378105373f0708d3544cbb98de76e27e9f69740b7761"],
    ),
    (
        "provision-user",
        "0.1.0",
        &["sha256:480b3983b412fc70f08aa6c6454dd85394c25e5935cd41a98bd6d55276e6655e"],
    ),
    (
        "query-decisions-by-tenant",
        "0.1.0",
        &["sha256:d6ecc92f9885a09b4b82bce78752dc9de256367d3b1a4339b3ce84a5128e938f"],
    ),
    (
        "query-supplier-status",
        "0.1.0",
        &["sha256:588cc912b846d7bd2662c90b3308a7c636a57c20ec5ee7fe814ebade5940965f"],
    ),
    (
        "revoke-role",
        "0.1.0",
        &["sha256:5cc97b788f8662e00b9dc44ca0c7d21ce45f1146c1b7b81e0f7deea5fcc79ad6"],
    ),
    (
        "verify-provenance-chain",
        "0.1.0",
        &["sha256:9288ebc24783ba64eaae602ea0c1ecf017fd5f2c47c4b7d2d124f4b9b467e0db"],
    ),
];

/// Parse `major.minor.patch` (no pre-release / build suffix — a suffixed
/// version is not comparable against a floor, so it is refused).
fn parse_version(v: &str) -> Option<(u64, u64, u64)> {
    let mut it = v.split('.');
    let major = it.next()?.parse().ok()?;
    let minor = it.next()?.parse().ok()?;
    let patch = it.next()?.parse().ok()?;
    if it.next().is_some() {
        return None;
    }
    Some((major, minor, patch))
}

impl FleetAllowlist {
    /// The allowlist compiled into this runtime.
    pub fn bundled() -> Self {
        Self::from_entries(
            BUNDLED_FLEET
                .iter()
                .map(|(name, min, hashes)| AllowEntry {
                    name: (*name).to_string(),
                    min_version: (*min).to_string(),
                    content_hashes: hashes.iter().map(|h| (*h).to_string()).collect(),
                })
                .collect(),
        )
    }

    /// Build an allowlist from explicit entries (tests, fixtures).
    pub fn from_entries(entries: Vec<AllowEntry>) -> Self {
        Self { entries }
    }

    /// Names on the list.
    pub fn names(&self) -> Vec<&str> {
        self.entries.iter().map(|e| e.name.as_str()).collect()
    }

    /// Admit or refuse a signature-verified manifest. `Err` carries the
    /// reason, for the operator.
    pub fn check(&self, manifest: &Manifest) -> Result<(), String> {
        let name = &manifest.capsule.name;
        let entry = self
            .entries
            .iter()
            .find(|e| &e.name == name)
            .ok_or_else(|| format!("capsule {name:?} is not on the fleet allowlist"))?;
        let have = parse_version(&manifest.capsule.version).ok_or_else(|| {
            format!(
                "capsule {name:?} version {:?} is not a plain major.minor.patch",
                manifest.capsule.version
            )
        })?;
        let floor = parse_version(&entry.min_version)
            .ok_or_else(|| format!("allowlist floor for {name:?} is malformed"))?;
        if have < floor {
            return Err(format!(
                "capsule {name:?} version {} is below the allowlist floor {} (rollback refused)",
                manifest.capsule.version, entry.min_version
            ));
        }
        if !entry
            .content_hashes
            .iter()
            .any(|h| h == &manifest.capsule.content_hash)
        {
            return Err(format!(
                "capsule {name:?} content_hash {} is not an allowlisted build",
                manifest.capsule.content_hash
            ));
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn manifest(name: &str, version: &str, hash: &str) -> Manifest {
        Manifest::parse(&format!(
            r#"
[capsule]
name = "{name}"
version = "{version}"
content_hash = "{hash}"
[capability]
network = "none"
filesystem = []
chain_calls = []
subagent_spawn = false
[data_class]
[risk]
tier = "low"
required_roles = ["Operator"]
break_glass_eligible = false
[overlay]
[provenance]
publisher = "did:citrate:test"
build_reproducible = true
agentile_sprint = "test"
tla_spec = ""
[signing]
tier = "bundled"
"#
        ))
        .expect("manifest parses")
    }

    const H1: &str = "sha256:1111111111111111111111111111111111111111111111111111111111111111";
    const H2: &str = "sha256:2222222222222222222222222222222222222222222222222222222222222222";

    fn list() -> FleetAllowlist {
        FleetAllowlist::from_entries(vec![AllowEntry {
            name: "cap".into(),
            min_version: "1.2.0".into(),
            content_hashes: vec![H1.into(), H2.into()],
        }])
    }

    /// PBA-L6b-015: the version floor refuses a rollback to an older signed
    /// release; the floor itself and anything above it pass.
    #[test]
    fn version_floor_refuses_rollback_pba_l6b_015() {
        let l = list();
        for v in ["1.1.9", "0.9.0", "1.0.0"] {
            let err = l.check(&manifest("cap", v, H1)).expect_err(v);
            assert!(err.contains("below the allowlist floor"), "{v}: {err}");
        }
        for v in ["1.2.0", "1.2.1", "1.10.0", "2.0.0"] {
            l.check(&manifest("cap", v, H1)).expect(v);
        }
    }

    /// PBA-L6b-015: unknown names and unpinned builds are refused.
    #[test]
    fn unknown_name_and_unpinned_hash_are_refused_pba_l6b_015() {
        let l = list();
        assert!(l
            .check(&manifest("other", "1.2.0", H1))
            .expect_err("unknown")
            .contains("not on the fleet allowlist"));
        let h3 = "sha256:3333333333333333333333333333333333333333333333333333333333333333";
        assert!(l
            .check(&manifest("cap", "1.2.0", h3))
            .expect_err("unpinned")
            .contains("not an allowlisted build"));
        l.check(&manifest("cap", "1.3.0", H2))
            .expect("second pinned hash");
    }

    /// PBA-L6b-015 (R2 verifier): the name match is exact and
    /// case-sensitive. `Cap` / `CAP` are different capsules from `cap`.
    #[test]
    fn name_match_is_exact_and_case_sensitive_pba_l6b_015() {
        let l = list();
        for name in ["Cap", "CAP", "cap ", "ca"] {
            assert!(
                l.check(&manifest_unchecked(name, "1.2.0", H1)).is_err(),
                "{name:?} must not match the entry for \"cap\""
            );
        }
        l.check(&manifest("cap", "1.2.0", H1)).expect("exact name");
    }

    /// A manifest with a name `Manifest::parse` would reject (the name
    /// validator enforces DNS labels), built directly so the allowlist's own
    /// comparison is what is tested.
    fn manifest_unchecked(name: &str, version: &str, hash: &str) -> Manifest {
        let mut m = manifest("cap", version, hash);
        m.capsule.name = name.to_string();
        m
    }

    #[test]
    fn version_parse_is_strict() {
        assert_eq!(parse_version("1.2.3"), Some((1, 2, 3)));
        assert_eq!(parse_version("1.2"), None);
        assert_eq!(parse_version("1.2.3.4"), None);
        assert_eq!(parse_version("1.2.3-rc1"), None);
        assert_eq!(parse_version("a.b.c"), None);
    }

    /// PBA-L6b-015: the bundled list never names the test capsule.
    #[test]
    fn bundled_allowlist_excludes_test_capsules_pba_l6b_015() {
        let names = FleetAllowlist::bundled();
        assert!(!names.names().contains(&"eth-sender-test"));
        assert_eq!(names.names().len(), BUNDLED_FLEET.len());
    }
}
