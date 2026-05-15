//! WIT / manifest cross-check — RFC-CIT-AGENT-0001 §4.5 invariant 2.
//!
//! The WIT interface declares what host functions the WASM imports.
//! The manifest declares what capabilities the capsule is allowed to
//! use. The two MUST agree before the capsule can load.
//!
//! Concretely:
//!
//! | WIT import | Required manifest fact |
//! |---|---|
//! | `wasi:sockets/*` | `[capability].network != "none"` |
//! | `wasi:filesystem/*` | `[capability].filesystem` non-empty |
//! | `wasi:cli/*` | always OK (stdio-only, no policy implication) |
//! | `wasi:clocks/*` | always OK |
//! | `wasi:random/*` | always OK |
//! | (custom namespace) | OK for now; tighter check in CIT-AGENT-3c when the linker is built |
//!
//! Per-path filesystem matching (`wasi:filesystem` open of `/foo` vs
//! manifest `filesystem = ["read:/bar"]`) is deferred to CIT-AGENT-3c
//! where the typed `FilesystemEntry` parser lands alongside the
//! wasmtime linker.

use crate::capsule::manifest::{Manifest, NetworkPolicy};
use crate::error::AgentError;

/// Parse a WIT source and verify its imports are covered by the
/// manifest's declared capability set. Returns `Ok(())` on success;
/// `AgentError::CapsuleWitMismatch(reason)` when any import requires
/// a capability the manifest hasn't declared.
///
/// CIT-AGENT-3b uses a simple line-based scan because the
/// full `wit_parser::Resolve` typecheck requires the imported
/// packages (`wasi:sockets`, etc.) to be present on the
/// filesystem. Invariant 2's check is "what NAMESPACE is being
/// imported?", which is decidable purely from the import line —
/// no type resolution needed. The full `wit_parser` integration
/// lands in CIT-AGENT-3c where the wasmtime linker actually
/// resolves the imported types.
pub fn verify_capability_against_wit(manifest: &Manifest, wit: &str) -> Result<(), AgentError> {
    for line in wit.lines() {
        let trimmed = line.trim();
        // Strip optional trailing `;` and any inline comment.
        let stripped = trimmed
            .split("//")
            .next()
            .unwrap_or("")
            .trim_end_matches(';')
            .trim();
        // Match `import <ns>:<name>/...` form. The parser is
        // permissive — it accepts both `import wasi:sockets/tcp@0.2.0`
        // and `import wasi:sockets/tcp`.
        if let Some(rest) = stripped.strip_prefix("import ") {
            // Skip self-imports of `use` or function imports — those
            // begin with an identifier without `:`.
            let pkg_path = rest.split_whitespace().next().unwrap_or("");
            // pkg_path: "<ns>:<name>/<interface>[@version]"
            let Some(colon_pos) = pkg_path.find(':') else {
                continue;
            };
            let ns = &pkg_path[..colon_pos];
            let after_colon = &pkg_path[colon_pos + 1..];
            let name_end = after_colon
                .find(['/', '@'])
                .unwrap_or(after_colon.len());
            let name = &after_colon[..name_end];
            check_import(manifest, ns, name)?;
        }
    }
    Ok(())
}

fn check_import(manifest: &Manifest, ns: &str, name: &str) -> Result<(), AgentError> {
    match (ns, name) {
        ("wasi", "sockets") => {
            if manifest.capability.network == NetworkPolicy::None {
                return Err(AgentError::CapsuleWitMismatch(format!(
                    "WIT imports {ns}:{name} but manifest declares [capability].network = \"none\""
                )));
            }
            Ok(())
        }
        ("wasi", "filesystem") => {
            if manifest.capability.filesystem.is_empty() {
                return Err(AgentError::CapsuleWitMismatch(format!(
                    "WIT imports {ns}:{name} but manifest's [capability].filesystem is empty"
                )));
            }
            Ok(())
        }
        // Stdio / time / RNG — no policy implication.
        ("wasi", "cli") | ("wasi", "clocks") | ("wasi", "random") | ("wasi", "io") => Ok(()),
        // Citrate's own host functions — always OK; tighter check
        // when the linker lands in CIT-AGENT-3c.
        ("citrate", _) => Ok(()),
        // Unknown namespace — let pass for now; CIT-AGENT-3c's
        // built-from-manifest linker will reject anything the
        // manifest doesn't permit.
        _ => Ok(()),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::capsule::manifest::{
        CapabilitySet, CapsuleMetadata, DataClassDecl, Manifest, OverlayDecl, ProcedureDecl,
        ProvenanceDecl, RiskDecl, SigningDecl, SigningTier,
    };

    fn manifest_with(net: NetworkPolicy, fs: Vec<String>) -> Manifest {
        Manifest {
            capsule: CapsuleMetadata {
                name: "x".into(),
                version: "0.1.0".into(),
                content_hash: "sha256:".to_string() + &"0".repeat(64),
            },
            capability: CapabilitySet {
                network: net,
                filesystem: fs,
                chain_calls: vec![],
                subagent_spawn: false,
            },
            data_class: DataClassDecl {
                reads: vec![],
                writes: vec![],
                emits: vec![],
            },
            risk: RiskDecl {
                tier: crate::capsule::manifest::RiskTier::Low,
                required_roles: vec![],
                break_glass_eligible: false,
            },
            overlay: OverlayDecl {
                certified: vec![],
                not_certified: vec![],
            },
            procedure: ProcedureDecl { gates: vec![] },
            provenance: ProvenanceDecl {
                publisher: "did:citrate:agent:0xab12".into(),
                build_reproducible: true,
                agentile_sprint: "test".into(),
                tla_spec: "".into(),
            },
            signing: SigningDecl {
                tier: SigningTier::Bundled,
            },
        }
    }

    const WIT_NO_IMPORTS: &str = "package test:capsule@0.1.0;\nworld root {\n}\n";

    const WIT_SOCKETS: &str = r#"package test:capsule@0.1.0;
world root {
    import wasi:sockets/tcp@0.2.0;
}
"#;

    const WIT_FILESYSTEM: &str = r#"package test:capsule@0.1.0;
world root {
    import wasi:filesystem/types@0.2.0;
}
"#;

    const WIT_CLI_ONLY: &str = r#"package test:capsule@0.1.0;
world root {
    import wasi:cli/stdout@0.2.0;
}
"#;

    #[test]
    fn empty_wit_passes() {
        let m = manifest_with(NetworkPolicy::None, vec![]);
        verify_capability_against_wit(&m, WIT_NO_IMPORTS).expect("no imports = trivially OK");
    }

    #[test]
    fn sockets_import_requires_network_policy() {
        let m_none = manifest_with(NetworkPolicy::None, vec![]);
        let err = verify_capability_against_wit(&m_none, WIT_SOCKETS).expect_err("sockets vs none");
        assert!(matches!(err, AgentError::CapsuleWitMismatch(_)));
        assert!(err.to_string().contains("network"));

        let m_egress = manifest_with(NetworkPolicy::EgressAllowed, vec![]);
        verify_capability_against_wit(&m_egress, WIT_SOCKETS).expect("sockets + egress = OK");
    }

    #[test]
    fn filesystem_import_requires_non_empty_filesystem_decl() {
        let m_empty = manifest_with(NetworkPolicy::None, vec![]);
        let err = verify_capability_against_wit(&m_empty, WIT_FILESYSTEM)
            .expect_err("fs vs empty filesystem decl");
        assert!(matches!(err, AgentError::CapsuleWitMismatch(_)));
        assert!(err.to_string().contains("filesystem"));

        let m_some = manifest_with(NetworkPolicy::None, vec!["read:/data".into()]);
        verify_capability_against_wit(&m_some, WIT_FILESYSTEM)
            .expect("fs + non-empty filesystem decl = OK");
    }

    #[test]
    fn cli_only_passes_under_strict_policy() {
        let m_strict = manifest_with(NetworkPolicy::None, vec![]);
        verify_capability_against_wit(&m_strict, WIT_CLI_ONLY)
            .expect("cli/stdio has no policy implication");
    }
}
