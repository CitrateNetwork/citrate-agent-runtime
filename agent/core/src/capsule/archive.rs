//! `.cps` archive reader — RFC-CIT-AGENT-0001 §4 + planset
//! `03_CAPSULE_MODEL.md` "Archive format".
//!
//! The archive is a Zstandard-compressed POSIX tar with a fixed
//! structure:
//!
//! ```text
//! <capsule-name>-<version>.cps
//! +-- capsule.wit
//! +-- capsule.wasm
//! +-- procedure.md
//! +-- manifest.toml
//! +-- gherkin/                # optional
//! +-- specs/                  # optional (REQUIRED for tier-high+)
//! +-- SIGNATURES/
//!     +-- publisher.sig
//!     +-- reviewer.sig        # optional, REQUIRED for tier-high+
//! ```
//!
//! Mtimes are pinned to 1970-01-01T00:00:00Z for reproducible builds.
//! The bundle content_hash is
//! `sha256(sorted_concat(<file_hash> || <file_path>))` over every
//! entry except `SIGNATURES/`.

use crate::error::AgentError;
use sha2::{Digest, Sha256};
use std::collections::BTreeMap;
use std::io::Read;

/// Unpacked archive contents, ready for manifest parsing + content-
/// hash verification. The `signatures` map holds detached signatures
/// keyed by filename (e.g., `"publisher.sig"`, `"reviewer.sig"`).
#[derive(Debug, Clone, Default)]
pub struct ArchiveContents {
    /// Raw `manifest.toml` bytes (UTF-8 expected; parsing is in
    /// `manifest.rs`).
    pub manifest: Vec<u8>,
    /// Raw `capsule.wit` bytes.
    pub wit: Vec<u8>,
    /// Raw `capsule.wasm` bytes — a deterministic WASM component.
    pub wasm: Vec<u8>,
    /// Raw `procedure.md` bytes.
    pub procedure: Vec<u8>,
    /// `gherkin/*.feature` entries, keyed by relative path
    /// (e.g., `"gherkin/redaction_blocks_pii_emit.feature"`).
    pub gherkin: BTreeMap<String, Vec<u8>>,
    /// `specs/*.tla` entries, keyed by relative path.
    pub specs: BTreeMap<String, Vec<u8>>,
    /// `SIGNATURES/*.sig` entries, keyed by filename without prefix
    /// (e.g., `"publisher.sig"`).
    pub signatures: BTreeMap<String, Vec<u8>>,
}

/// Read a `.cps` archive (Zstd-compressed tar). Verifies the
/// structural requirements (required files present, no unexpected
/// top-level files) but does NOT verify signatures or the
/// content_hash against the manifest — those steps live in
/// `Capsule::from_archive` and `CIT-AGENT-3b::verify` respectively.
/// FUA-AGENT-RUNTIME-01: a `.cps` is read (and decompressed) BEFORE any
/// hash/signature check, so an unbounded read is a pre-auth OOM bomb (a tiny
/// zstd payload can expand to gigabytes). The total DECOMPRESSED bytes are
/// capped; tar hits EOF past the cap and the archive fails closed (and would
/// fail the downstream hash check anyway). 256 MiB is far above any real capsule.
pub const MAX_DECOMPRESSED_BYTES: u64 = 256 * 1024 * 1024;

pub fn read_archive(reader: impl Read) -> Result<ArchiveContents, AgentError> {
    read_archive_capped(reader, MAX_DECOMPRESSED_BYTES)
}

/// Like [`read_archive`] but with an explicit decompression cap (for tests).
pub fn read_archive_capped(
    reader: impl Read,
    max_decompressed: u64,
) -> Result<ArchiveContents, AgentError> {
    let decoder = zstd::Decoder::new(reader)
        .map_err(|e| AgentError::Capsule(format!("zstd init: {e}")))?;
    let mut archive = tar::Archive::new(decoder.take(max_decompressed));
    let mut out = ArchiveContents::default();

    for entry in archive
        .entries()
        .map_err(|e| AgentError::Capsule(format!("tar entries: {e}")))?
    {
        let mut entry = entry.map_err(|e| AgentError::Capsule(format!("tar entry: {e}")))?;
        let path = entry
            .path()
            .map_err(|e| AgentError::Capsule(format!("tar entry path: {e}")))?
            .to_string_lossy()
            .into_owned();
        // Skip directory entries.
        if path.ends_with('/') {
            continue;
        }
        let mut bytes = Vec::new();
        entry
            .read_to_end(&mut bytes)
            .map_err(|e| AgentError::Capsule(format!("read entry {path}: {e}")))?;
        match path.as_str() {
            "manifest.toml" => out.manifest = bytes,
            "capsule.wit" => out.wit = bytes,
            "capsule.wasm" => out.wasm = bytes,
            "procedure.md" => out.procedure = bytes,
            p if p.starts_with("gherkin/") => {
                out.gherkin.insert(p.to_string(), bytes);
            }
            p if p.starts_with("specs/") => {
                out.specs.insert(p.to_string(), bytes);
            }
            p if p.starts_with("SIGNATURES/") => {
                let fname = p.strip_prefix("SIGNATURES/").unwrap().to_string();
                out.signatures.insert(fname, bytes);
            }
            other => {
                return Err(AgentError::Capsule(format!(
                    "unexpected archive entry: {other}"
                )));
            }
        }
    }

    validate_structure(&out)?;
    Ok(out)
}

fn validate_structure(a: &ArchiveContents) -> Result<(), AgentError> {
    if a.manifest.is_empty() {
        return Err(AgentError::Capsule("missing manifest.toml".to_string()));
    }
    if a.wit.is_empty() {
        return Err(AgentError::Capsule("missing capsule.wit".to_string()));
    }
    if a.wasm.is_empty() {
        return Err(AgentError::Capsule("missing capsule.wasm".to_string()));
    }
    if a.procedure.is_empty() {
        return Err(AgentError::Capsule("missing procedure.md".to_string()));
    }
    if !a.signatures.contains_key("publisher.sig") {
        return Err(AgentError::Capsule(
            "missing SIGNATURES/publisher.sig".to_string(),
        ));
    }
    Ok(())
}

/// Compute the canonical bundle content_hash from the archive
/// contents. Hash is `sha256(sorted_concat(file_hash || file_path))`
/// over every entry EXCEPT `manifest.toml` and `SIGNATURES/`.
///
/// **Deviation from planset literal wording.** Planset
/// `03_CAPSULE_MODEL.md` says "every entry except SIGNATURES/", which
/// would include manifest.toml in the hash. That creates a self-
/// referential chicken-and-egg: the manifest's `content_hash` field
/// declares a hash that includes the manifest body that contains the
/// hash. CIT-AGENT-3b resolves this by hashing the non-manifest
/// body. The manifest's `content_hash` field is the canonical claim
/// about that body; the publisher.sig binds the manifest
/// authoritatively, which in turn binds content_hash.
///
/// The CIT-AGENT-3e capsule builder will compute this hash, embed it
/// in the manifest, sign the manifest (transitively binding the
/// content_hash), and pack the archive.
///
/// Returned as `"sha256:<64-char-lowercase-hex>"` to match the
/// manifest's `content_hash` field format.
pub fn compute_content_hash(a: &ArchiveContents) -> String {
    // BTreeMap iteration is sorted; we collect all non-SIGNATURES
    // and non-manifest entries with their canonical paths.
    let mut entries: Vec<(&str, &[u8])> = Vec::new();
    entries.push(("capsule.wit", &a.wit));
    entries.push(("capsule.wasm", &a.wasm));
    entries.push(("procedure.md", &a.procedure));
    for (p, b) in &a.gherkin {
        entries.push((p.as_str(), b.as_slice()));
    }
    for (p, b) in &a.specs {
        entries.push((p.as_str(), b.as_slice()));
    }
    // Sort by path so the order is deterministic regardless of tar
    // entry order in the archive.
    entries.sort_by(|a, b| a.0.cmp(b.0));

    let mut bundle = Sha256::new();
    for (path, bytes) in entries {
        let mut entry_hash = Sha256::new();
        entry_hash.update(bytes);
        let entry_digest = entry_hash.finalize();
        bundle.update(entry_digest);
        bundle.update(path.as_bytes());
    }
    let digest = bundle.finalize();
    let hex: String = digest.iter().map(|b| format!("{b:02x}")).collect();
    format!("sha256:{hex}")
}

// ── Tests ─────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::Write;

    /// Build a minimal in-memory `.cps` archive with the 5 required
    /// files (manifest.toml, capsule.wit, capsule.wasm, procedure.md,
    /// SIGNATURES/publisher.sig).
    fn build_minimal_cps(manifest_body: &str) -> Vec<u8> {
        let mut tar_buf = Vec::new();
        {
            let mut tar = tar::Builder::new(&mut tar_buf);
            // No mtime override — tar crate uses system time, but
            // tests don't verify reproducibility (that's CIT-AGENT-3c).
            for (path, bytes) in [
                ("manifest.toml", manifest_body.as_bytes()),
                ("capsule.wit", b"// stub WIT"),
                ("capsule.wasm", b"\x00asm\x01\x00\x00\x00"),
                ("procedure.md", b"# stub procedure"),
                ("SIGNATURES/publisher.sig", b"stub-sig"),
            ] {
                let mut header = tar::Header::new_gnu();
                header.set_size(bytes.len() as u64);
                header.set_cksum();
                tar.append_data(&mut header, path, bytes)
                    .expect("tar write");
            }
            tar.finish().expect("tar finish");
        }
        let mut out = Vec::new();
        let mut enc = zstd::Encoder::new(&mut out, 3).expect("zstd init");
        enc.write_all(&tar_buf).expect("zstd write");
        enc.finish().expect("zstd finish");
        out
    }

    #[test]
    fn read_minimal_archive_succeeds() {
        let cps = build_minimal_cps("[capsule]\nname = \"x\"\n");
        let archive = read_archive(&cps[..]).expect("minimal archive reads");
        assert!(!archive.manifest.is_empty());
        assert_eq!(archive.signatures.get("publisher.sig").map(|v| v.as_slice()), Some(&b"stub-sig"[..]));
    }

    #[test]
    fn read_archive_caps_decompression_bomb() {
        // FUA-AGENT-RUNTIME-01: an archive that decompresses past the cap fails
        // closed instead of reading unboundedly into memory. (A real bomb is a
        // tiny zstd payload that expands to GBs; here a small over-cap fixture +
        // a tiny test cap exercises the same guard cheaply.)
        let big_manifest = format!("[capsule]\nname = \"x\"\n# {}\n", "A".repeat(64 * 1024));
        let cps = build_minimal_cps(&big_manifest);
        // Under a tiny cap, the read fails (tar hits EOF past the cap).
        assert!(read_archive_capped(&cps[..], 1024).is_err());
        // Under the real cap it reads fine.
        assert!(read_archive(&cps[..]).is_ok());
    }

    #[test]
    fn reject_archive_missing_manifest() {
        // Build an archive without manifest.toml.
        let mut tar_buf = Vec::new();
        {
            let mut tar = tar::Builder::new(&mut tar_buf);
            for (path, bytes) in [
                ("capsule.wit", b"// wit".as_slice()),
                ("capsule.wasm", b"\x00asm\x01\x00\x00\x00".as_slice()),
                ("procedure.md", b"# md".as_slice()),
                ("SIGNATURES/publisher.sig", b"sig".as_slice()),
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
        std::io::Write::write_all(&mut enc, &tar_buf).unwrap();
        enc.finish().unwrap();

        let err = read_archive(&zstd_buf[..]).expect_err("missing manifest rejected");
        assert!(err.to_string().contains("manifest.toml"), "actual: {err}");
    }

    #[test]
    fn reject_archive_missing_publisher_sig() {
        let mut tar_buf = Vec::new();
        {
            let mut tar = tar::Builder::new(&mut tar_buf);
            for (path, bytes) in [
                ("manifest.toml", b"[capsule]".as_slice()),
                ("capsule.wit", b"// wit".as_slice()),
                ("capsule.wasm", b"\x00asm\x01\x00\x00\x00".as_slice()),
                ("procedure.md", b"# md".as_slice()),
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
        std::io::Write::write_all(&mut enc, &tar_buf).unwrap();
        enc.finish().unwrap();

        let err = read_archive(&zstd_buf[..]).expect_err("missing publisher.sig rejected");
        assert!(err.to_string().contains("publisher.sig"), "actual: {err}");
    }

    #[test]
    fn reject_unexpected_top_level_entry() {
        let mut tar_buf = Vec::new();
        {
            let mut tar = tar::Builder::new(&mut tar_buf);
            for (path, bytes) in [
                ("manifest.toml", b"[capsule]".as_slice()),
                ("capsule.wit", b"// wit".as_slice()),
                ("capsule.wasm", b"\x00asm\x01\x00\x00\x00".as_slice()),
                ("procedure.md", b"# md".as_slice()),
                ("SIGNATURES/publisher.sig", b"sig".as_slice()),
                ("README.md", b"unexpected".as_slice()),
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
        std::io::Write::write_all(&mut enc, &tar_buf).unwrap();
        enc.finish().unwrap();

        let err = read_archive(&zstd_buf[..]).expect_err("unexpected entry rejected");
        assert!(err.to_string().contains("README.md"), "actual: {err}");
    }

    #[test]
    fn compute_content_hash_is_deterministic() {
        let a = ArchiveContents {
            manifest: b"[capsule]".to_vec(),
            wit: b"// wit".to_vec(),
            wasm: b"\x00asm\x01\x00\x00\x00".to_vec(),
            procedure: b"# md".to_vec(),
            ..Default::default()
        };
        let h1 = compute_content_hash(&a);
        let h2 = compute_content_hash(&a);
        assert_eq!(h1, h2);
        assert!(h1.starts_with("sha256:"));
        assert_eq!(h1.len(), "sha256:".len() + 64);
    }

    #[test]
    fn compute_content_hash_excludes_signatures() {
        // Two archives that differ only in SIGNATURES/ content should
        // hash identically.
        let base = ArchiveContents {
            manifest: b"[capsule]".to_vec(),
            wit: b"// wit".to_vec(),
            wasm: b"\x00asm\x01\x00\x00\x00".to_vec(),
            procedure: b"# md".to_vec(),
            ..Default::default()
        };
        let mut with_sig_a = base.clone();
        with_sig_a
            .signatures
            .insert("publisher.sig".to_string(), b"sig-a".to_vec());
        let mut with_sig_b = base.clone();
        with_sig_b
            .signatures
            .insert("publisher.sig".to_string(), b"sig-b".to_vec());
        assert_eq!(
            compute_content_hash(&with_sig_a),
            compute_content_hash(&with_sig_b)
        );
    }
}
