//! Capsule loader — RFC-CIT-AGENT-0001 §3.1 + §4.
//!
//! CIT-AGENT-3a lands the manifest schema + archive format. The
//! load-time invariants from RFC §4.5 are sequenced across the
//! follow-up sprints in this same crate:
//!
//!   1. Manifest signature verification  → CIT-AGENT-3b (`tiers.rs`)
//!   2. WIT / manifest cross-validation  → CIT-AGENT-3b (`verify.rs`)
//!   3. wasmtime engine + per-capsule linker → CIT-AGENT-3c (`wasm.rs`)
//!   4. Per-call data-class check        → CIT-AGENT-3d (runtime path)
//!
//! The install state-machine is verified by
//! `.agentile/formal/specs/agent/CapsuleInstall.tla` (CIT-AGENT-2 —
//! 2,600 distinct states PASS).

pub mod archive;
pub mod filesystem;
pub mod linker;
pub mod manifest;
pub mod tiers;
pub mod verify;
pub mod wasm;

use crate::error::AgentError;
use std::io::Read;

/// A loaded capsule: parsed manifest + unpacked archive entries. The
/// content_hash declared in the manifest is verified against the
/// computed hash of the archive contents during `from_archive`.
/// Signature verification (publisher.sig / reviewer.sig) and WIT/WASM
/// cross-check land in CIT-AGENT-3b.
#[derive(Debug)]
pub struct Capsule {
    pub manifest: manifest::Manifest,
    pub archive: archive::ArchiveContents,
}

impl Capsule {
    /// Read a `.cps` archive (Zstd-compressed tar), parse and validate
    /// the manifest, verify the archive's content_hash matches the
    /// manifest declaration. Returns the loaded capsule on success.
    ///
    /// Per CIT-AGENT-3a SPRINT.md, signature verification + WIT
    /// cross-check are NOT yet performed — they land in 3b.
    pub fn from_archive(reader: impl Read) -> Result<Self, AgentError> {
        let archive = archive::read_archive(reader)?;
        let manifest_toml = std::str::from_utf8(&archive.manifest).map_err(|e| {
            AgentError::Capsule(format!("manifest.toml is not valid UTF-8: {e}"))
        })?;
        let manifest = manifest::Manifest::parse(manifest_toml)?;
        let computed_hash = archive::compute_content_hash(&archive);
        if computed_hash != manifest.capsule.content_hash {
            return Err(AgentError::Capsule(format!(
                "content_hash mismatch — manifest declares {}, archive computed {}",
                manifest.capsule.content_hash, computed_hash,
            )));
        }
        Ok(Self { manifest, archive })
    }

    /// Production load path — runs the full RFC §4.5 invariant chain
    /// available in CIT-AGENT-3b:
    ///   1. archive structure + content_hash verification (3a)
    ///   2. publisher signature verification under the tier's
    ///      trusted key (3b — this fn)
    ///   3. WIT / manifest capability cross-check (3b — this fn)
    ///
    /// Invariants 3 (wasmtime per-capsule linker) and 4 (per-call
    /// data-class check) land in CIT-AGENT-3c/d and will extend the
    /// chain in this same function.
    pub fn from_archive_verified(
        reader: impl Read,
        registry: &dyn tiers::PublicKeyRegistry,
    ) -> Result<Self, AgentError> {
        let capsule = Self::from_archive(reader)?;
        let sig = capsule
            .archive
            .signatures
            .get("publisher.sig")
            .ok_or_else(|| {
                AgentError::CapsuleSignatureInvalid(
                    "publisher.sig missing from SIGNATURES/".to_string(),
                )
            })?;
        tiers::verify_signature(
            &capsule.manifest.capsule.content_hash,
            sig,
            capsule.manifest.signing.tier,
            registry,
        )?;
        let wit_str = std::str::from_utf8(&capsule.archive.wit).map_err(|e| {
            AgentError::CapsuleWitMismatch(format!("capsule.wit is not valid UTF-8: {e}"))
        })?;
        verify::verify_capability_against_wit(&capsule.manifest, wit_str)?;
        Ok(capsule)
    }

    /// Build the per-capsule wasmtime linker from this capsule's
    /// manifest. CIT-AGENT-3c — the linker is constructed with only
    /// the WASI capabilities the manifest declares (fail-closed,
    /// "build from manifest, NOT filter default" per planset).
    /// Actual instantiation lands in CIT-AGENT-3d alongside
    /// `Capsule::call(...)`.
    pub fn prepare_linker(
        &self,
        engine: &wasmtime::Engine,
    ) -> Result<linker::LinkerBuilder, AgentError> {
        linker::LinkerBuilder::from_manifest(engine, &self.manifest)
    }

    pub fn name(&self) -> &str {
        &self.manifest.capsule.name
    }

    pub fn version(&self) -> &str {
        &self.manifest.capsule.version
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::Write;

    /// Round-trip: build a tiny `.cps` archive whose manifest declares
    /// the computed content_hash; from_archive should accept it.
    /// Under the CIT-AGENT-3b semantic (hash excludes manifest.toml),
    /// the declared hash is straightforward — no fixed-point dance.
    #[test]
    fn from_archive_round_trip_with_correct_hash() {
        // First compute the content_hash for the archive contents we
        // intend to include.
        let archive_contents = archive::ArchiveContents {
            manifest: vec![], // placeholder; we overwrite below
            wit: b"// stub WIT".to_vec(),
            wasm: b"\x00asm\x01\x00\x00\x00".to_vec(),
            procedure: b"# stub procedure".to_vec(),
            ..Default::default()
        };
        // The content_hash is computed over all entries EXCEPT
        // manifest itself; but the manifest IS included in the hash.
        // So we first build the manifest, compute the full hash with
        // the manifest's body of the form "sha256:0000..." (a
        // placeholder), then update the manifest body to declare
        // its OWN computed hash. The hash changes when we update the
        // manifest body — chicken-and-egg.
        //
        // For test simplicity we accept that the round-trip happy
        // path can only be exercised when the manifest's declared
        // content_hash matches what the archive computes WITH that
        // same manifest body inside. We use an iterative approach:
        // compute → embed → recompute → confirm stable.
        let make_manifest = |declared_hash: &str| -> String {
            format!(
                r#"
[capsule]
name = "test-capsule"
version = "0.1.0"
content_hash = "{declared_hash}"

[capability]
network = "none"
filesystem = []
chain_calls = []
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
certified = []
not_certified = []

[procedure]
gates = []

[provenance]
publisher = "did:citrate:agent:0xab12"
build_reproducible = true
agentile_sprint = "2026-05-15-cit-agent-3a"
tla_spec = ""

[signing]
tier = "bundled"
"#
            )
        };
        // Compute the body hash once (excludes manifest.toml).
        let body_hash = archive::compute_content_hash(&archive_contents);
        let manifest_with_hash = make_manifest(&body_hash);
        let mut working = archive_contents.clone();
        working.manifest = manifest_with_hash.as_bytes().to_vec();
        working
            .signatures
            .insert("publisher.sig".to_string(), b"stub-sig".to_vec());

        // Pack working into a real .cps archive, then read it back.
        let mut tar_buf = Vec::new();
        {
            let mut tar = tar::Builder::new(&mut tar_buf);
            let entries: Vec<(&str, &[u8])> = vec![
                ("manifest.toml", &working.manifest),
                ("capsule.wit", &working.wit),
                ("capsule.wasm", &working.wasm),
                ("procedure.md", &working.procedure),
                ("SIGNATURES/publisher.sig", b"stub-sig"),
            ];
            for (path, bytes) in entries {
                let mut header = tar::Header::new_gnu();
                header.set_size(bytes.len() as u64);
                header.set_cksum();
                tar.append_data(&mut header, path, bytes).unwrap();
            }
            tar.finish().unwrap();
        }
        let mut zstd_buf = Vec::new();
        let mut enc = zstd::Encoder::new(&mut zstd_buf, 3).unwrap();
        enc.write_all(&tar_buf).unwrap();
        enc.finish().unwrap();

        // Capsule::from_archive computes content_hash from the body
        // (excluding manifest.toml); the manifest's declared hash
        // matches; this MUST succeed.
        let capsule = Capsule::from_archive(&zstd_buf[..])
            .expect("manifest-declared body hash matches; load succeeds");
        assert_eq!(capsule.name(), "test-capsule");
        assert_eq!(capsule.manifest.capsule.content_hash, body_hash);
    }

    /// CIT-AGENT-3c — `Capsule::prepare_linker` integrates with
    /// `from_archive`: a loaded capsule + an engine yields a
    /// constructed per-capsule linker whose permitted set reflects
    /// the manifest exactly.
    #[test]
    fn prepare_linker_reflects_manifest_capabilities() {
        use crate::capsule::linker::CapabilityToken;
        use crate::capsule::manifest::Manifest;
        use crate::capsule::wasm::EngineFactory;

        let manifest_str = r#"
[capsule]
name = "linker-roundtrip"
version = "0.1.0"
content_hash = "sha256:0000000000000000000000000000000000000000000000000000000000000000"

[capability]
network = "broker-only"
filesystem = ["read:/data"]
chain_calls = []
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
certified = []
not_certified = []

[procedure]
gates = []

[provenance]
publisher = "did:citrate:agent:0xab12"
build_reproducible = true
agentile_sprint = "test"
tla_spec = ""

[signing]
tier = "bundled"
"#;
        let manifest = Manifest::parse(manifest_str).expect("manifest parses");
        // Wrap in a fake Capsule (no archive) to exercise prepare_linker
        // independently of from_archive.
        let capsule = Capsule {
            manifest,
            archive: archive::ArchiveContents::default(),
        };
        let engine = EngineFactory::build().unwrap();
        let builder = capsule.prepare_linker(&engine).expect("linker builds");
        let permitted = builder.permitted();
        assert!(permitted.contains(&CapabilityToken::WasiSockets));
        assert!(permitted.contains(&CapabilityToken::WasiFilesystem));
        assert!(permitted.contains(&CapabilityToken::WasiCli));
    }

    /// CIT-AGENT-3b — round-trip `from_archive_verified` with a real
    /// signed capsule. Builds a minimal `.cps` archive whose
    /// publisher.sig is computed from a known key; verifies the load
    /// succeeds end-to-end (archive parse → content_hash → signature
    /// → WIT cross-check).
    #[test]
    fn from_archive_verified_round_trip_happy_path() {
        use ed25519_dalek::{Signer, SigningKey};
        use sha2::{Digest, Sha256};

        // Build manifest, WIT, WASM, procedure with a content_hash
        // placeholder. We compute the real content_hash, embed it,
        // sign it, and pack the archive.
        let wit = b"package test:capsule@0.1.0;\nworld root {\n}\n".to_vec();
        let wasm = b"\x00asm\x01\x00\x00\x00".to_vec();
        let procedure = b"# stub procedure".to_vec();
        let manifest_template = |declared_hash: &str| {
            format!(
                r#"
[capsule]
name = "verified-test"
version = "0.1.0"
content_hash = "{declared_hash}"

[capability]
network = "none"
filesystem = []
chain_calls = []
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
certified = []
not_certified = []

[procedure]
gates = []

[provenance]
publisher = "did:citrate:agent:0xab12"
build_reproducible = true
agentile_sprint = "2026-05-15-cit-agent-3b"
tla_spec = ""

[signing]
tier = "bundled"
"#
            )
        };
        // 3b semantic: content_hash is over everything EXCEPT
        // manifest.toml (and SIGNATURES/). The manifest declares the
        // hash; the publisher signs the manifest; the signature
        // transitively binds content_hash. No fixed-point dance.
        let unsigned_archive = archive::ArchiveContents {
            manifest: vec![], // placeholder; not included in hash
            wit: wit.clone(),
            wasm: wasm.clone(),
            procedure: procedure.clone(),
            ..Default::default()
        };
        let truth_hash = archive::compute_content_hash(&unsigned_archive);
        let manifest_body = manifest_template(&truth_hash);
        let final_archive = archive::ArchiveContents {
            manifest: manifest_body.as_bytes().to_vec(),
            wit: wit.clone(),
            wasm: wasm.clone(),
            procedure: procedure.clone(),
            ..Default::default()
        };
        // The hash is over the non-manifest body, so re-hashing with
        // the manifest present yields the same value.
        assert_eq!(archive::compute_content_hash(&final_archive), truth_hash);

        // Sign the truth_hash with a known key.
        let signing_key = SigningKey::from_bytes(&[0xef; 32]);
        let pubkey = signing_key.verifying_key().to_bytes();
        let mut hasher = Sha256::new();
        hasher.update(truth_hash.as_bytes());
        let payload = hasher.finalize();
        let signature = signing_key.sign(&payload);

        // Pack the .cps archive.
        let signature_bytes = signature.to_bytes();
        let mut tar_buf = Vec::new();
        {
            let mut tar = tar::Builder::new(&mut tar_buf);
            let entries: Vec<(&str, &[u8])> = vec![
                ("manifest.toml", &final_archive.manifest),
                ("capsule.wit", &final_archive.wit),
                ("capsule.wasm", &final_archive.wasm),
                ("procedure.md", &final_archive.procedure),
                ("SIGNATURES/publisher.sig", &signature_bytes),
            ];
            for (path, bytes) in entries {
                let mut header = tar::Header::new_gnu();
                header.set_size(bytes.len() as u64);
                header.set_cksum();
                tar.append_data(&mut header, path, bytes).unwrap();
            }
            tar.finish().unwrap();
        }
        let mut zstd_buf = Vec::new();
        let mut enc = zstd::Encoder::new(&mut zstd_buf, 3).unwrap();
        enc.write_all(&tar_buf).unwrap();
        enc.finish().unwrap();

        // Build the registry that recognizes our test key.
        let registry = tiers::StaticKeyRegistry {
            bundled: Some(pubkey),
            managed: None,
        };

        // The full verified load path:
        let capsule = Capsule::from_archive_verified(&zstd_buf[..], &registry)
            .expect("verified load succeeds");
        assert_eq!(capsule.name(), "verified-test");
        assert_eq!(capsule.version(), "0.1.0");
    }

    /// Direct exercise of the verify-against-manifest path without
    /// the fixed-point dance: declare the computed hash directly.
    #[test]
    fn from_archive_rejects_hash_mismatch() {
        let cps = {
            let mut tar_buf = Vec::new();
            {
                let mut tar = tar::Builder::new(&mut tar_buf);
                let manifest = r#"
[capsule]
name = "x"
version = "0.1.0"
content_hash = "sha256:0000000000000000000000000000000000000000000000000000000000000000"

[capability]
network = "none"
filesystem = []
chain_calls = []
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
certified = []
not_certified = []

[procedure]
gates = []

[provenance]
publisher = "did:citrate:agent:0xab12"
build_reproducible = true
agentile_sprint = "test"
tla_spec = ""

[signing]
tier = "bundled"
"#;
                for (path, bytes) in [
                    ("manifest.toml", manifest.as_bytes()),
                    ("capsule.wit", b"// wit"),
                    ("capsule.wasm", b"\x00asm\x01\x00\x00\x00"),
                    ("procedure.md", b"# md"),
                    ("SIGNATURES/publisher.sig", b"sig"),
                ] {
                    let mut header = tar::Header::new_gnu();
                    header.set_size(bytes.len() as u64);
                    header.set_cksum();
                    tar.append_data(&mut header, path, bytes).unwrap();
                }
                tar.finish().unwrap();
            }
            let mut zstd_buf = Vec::new();
            let mut enc = zstd::Encoder::new(&mut zstd_buf, 3).unwrap();
            enc.write_all(&tar_buf).unwrap();
            enc.finish().unwrap();
            zstd_buf
        };
        let err = Capsule::from_archive(&cps[..]).expect_err("hash mismatch rejected");
        assert!(
            err.to_string().contains("content_hash mismatch"),
            "actual: {err}"
        );
    }
}
