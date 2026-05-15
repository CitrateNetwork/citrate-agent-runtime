//! Local filesystem audit sink — RFC-CIT-AGENT-0001 §6.2 + planset
//! `05_AUDIT_CHAIN.md` row "Local filesystem".
//!
//! The default storage backend. Records are appended as JSONL
//! envelopes:
//!
//! ```json
//! { "sequence": 0, "cbor_b64": "..." }
//! ```
//!
//! The envelope wraps the canonical-CBOR encoding in base64 so the
//! file is line-oriented and inspectable with `jq` / `grep` while
//! preserving the canonical bytes for offline signature verification.
//! `iter()` reads each line, base64-decodes the `cbor_b64` field, and
//! deserializes the CBOR back into an `AuditRecord`.
//!
//! Permissions: on Unix the file is `chmod 600` (owner-only). Non-
//! Posix platforms fall back to the default ACL; the installer is
//! responsible for tightening permissions out-of-band.

use crate::audit::record::AuditRecord;
use crate::audit::sink::AuditSink;
use crate::error::AgentError;
use base64::{engine::general_purpose::STANDARD as B64, Engine};
use std::fs::{File, OpenOptions};
use std::io::{BufRead, BufReader, Write};
use std::path::{Path, PathBuf};
use std::sync::Mutex;

/// Append-only audit log file. Concurrent writers MUST synchronize
/// through a single instance — the internal `Mutex` serializes
/// appends; the OS guarantees atomicity within a single `write_all`
/// up to PIPE_BUF / page size, which is sufficient for our typical
/// record size.
pub struct FilesystemSink {
    path: PathBuf,
    writer: Mutex<File>,
}

impl FilesystemSink {
    /// Open the audit log file. If it doesn't exist, creates it with
    /// owner-only permissions (Unix); on Windows it's the default
    /// ACL of the process owner.
    pub fn open(path: &Path) -> Result<Self, AgentError> {
        let mut options = OpenOptions::new();
        options.create(true).append(true).read(true);
        #[cfg(unix)]
        {
            use std::os::unix::fs::OpenOptionsExt;
            options.mode(0o600);
        }
        let file = options
            .open(path)
            .map_err(|e| AgentError::Audit(format!("open audit file {path:?}: {e}")))?;
        Ok(Self {
            path: path.to_path_buf(),
            writer: Mutex::new(file),
        })
    }

    pub fn path(&self) -> &Path {
        &self.path
    }
}

impl AuditSink for FilesystemSink {
    fn append(&self, record: &AuditRecord) -> Result<(), AgentError> {
        // Encode the FULL record (signatures + anchor included) as
        // CBOR for storage — we want to persist what was actually
        // produced. The chain-integrity check re-strips sigs/anchor
        // when computing `record_hash`.
        let mut cbor = Vec::new();
        ciborium::ser::into_writer(record, &mut cbor)
            .map_err(|e| AgentError::Audit(format!("encode record: {e}")))?;
        let envelope = serde_json::json!({
            "sequence": record.sequence,
            "cbor_b64": B64.encode(&cbor),
        });
        let line = envelope.to_string() + "\n";
        let mut writer = self
            .writer
            .lock()
            .map_err(|_| AgentError::Audit("mutex poisoned".to_string()))?;
        writer
            .write_all(line.as_bytes())
            .map_err(|e| AgentError::Audit(format!("append: {e}")))?;
        writer
            .flush()
            .map_err(|e| AgentError::Audit(format!("flush: {e}")))?;
        Ok(())
    }

    fn iter(
        &self,
    ) -> Result<Box<dyn Iterator<Item = Result<AuditRecord, AgentError>> + '_>, AgentError>
    {
        let file = File::open(&self.path)
            .map_err(|e| AgentError::Audit(format!("re-open for read: {e}")))?;
        let reader = BufReader::new(file);
        Ok(Box::new(reader.lines().map(|line_result| {
            let line = line_result
                .map_err(|e| AgentError::Audit(format!("read line: {e}")))?;
            let envelope: serde_json::Value = serde_json::from_str(&line)
                .map_err(|e| AgentError::Audit(format!("parse envelope: {e}")))?;
            let cbor_b64 = envelope
                .get("cbor_b64")
                .and_then(|v| v.as_str())
                .ok_or_else(|| AgentError::Audit("envelope missing cbor_b64".to_string()))?;
            let cbor = B64
                .decode(cbor_b64)
                .map_err(|e| AgentError::Audit(format!("b64 decode: {e}")))?;
            let record: AuditRecord = ciborium::de::from_reader(&cbor[..])
                .map_err(|e| AgentError::Audit(format!("CBOR decode: {e}")))?;
            Ok(record)
        })))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::audit::record::{EventType, RoleSignature, SigningSurfaceTag};
    use crate::capsule::manifest::Role;

    fn tmp_path(name: &str) -> PathBuf {
        std::env::temp_dir().join(format!("cit-agent-5a-{name}.jsonl"))
    }

    fn mkrecord(sequence: u64) -> AuditRecord {
        AuditRecord {
            sequence,
            timestamp: 1_715_000_000 + sequence as i64,
            previous_hash: [0u8; 32],
            event_type: EventType::Proposal,
            payload: format!("payload-{sequence}").into_bytes(),
            actor: "did:citrate:agent:0xab12".to_string(),
            signatures: vec![RoleSignature {
                signer: "did:citrate:role:0xrv".to_string(),
                role: Role::Reviewer,
                signed_at: 0,
                signature: vec![0xde, 0xad, 0xbe, 0xef],
                surface: SigningSurfaceTag::Cli,
            }],
            chain_anchor: None,
        }
    }

    #[test]
    fn round_trip_three_records() {
        let p = tmp_path("round-trip-three");
        let _ = std::fs::remove_file(&p);
        let sink = FilesystemSink::open(&p).expect("open");
        for i in 0..3 {
            sink.append(&mkrecord(i)).expect("append");
        }
        let records: Vec<AuditRecord> = sink
            .iter()
            .expect("iter")
            .collect::<Result<_, _>>()
            .expect("collect");
        assert_eq!(records.len(), 3);
        for (i, r) in records.iter().enumerate() {
            assert_eq!(r.sequence, i as u64);
            assert_eq!(r.payload, format!("payload-{i}").into_bytes());
            // Signature round-trips fully.
            assert_eq!(r.signatures.len(), 1);
            assert_eq!(r.signatures[0].signature, vec![0xde, 0xad, 0xbe, 0xef]);
        }
        let _ = std::fs::remove_file(&p);
    }

    #[cfg(unix)]
    #[test]
    fn open_creates_file_with_tight_permissions() {
        use std::os::unix::fs::PermissionsExt;
        let p = tmp_path("tight-perms");
        let _ = std::fs::remove_file(&p);
        let _sink = FilesystemSink::open(&p).expect("open");
        let meta = std::fs::metadata(&p).expect("metadata");
        let mode = meta.permissions().mode() & 0o777;
        assert_eq!(mode, 0o600, "audit file MUST be owner-only");
        let _ = std::fs::remove_file(&p);
    }

    #[test]
    fn iter_on_empty_file_yields_nothing() {
        let p = tmp_path("empty");
        let _ = std::fs::remove_file(&p);
        let sink = FilesystemSink::open(&p).expect("open");
        let count = sink.iter().expect("iter").count();
        assert_eq!(count, 0);
        let _ = std::fs::remove_file(&p);
    }

    #[test]
    fn iter_handles_malformed_line() {
        // Write a line that isn't valid JSON envelope; iter should
        // surface the error rather than panicking.
        let p = tmp_path("malformed");
        let _ = std::fs::remove_file(&p);
        std::fs::write(&p, b"not json\n").expect("write");
        let sink = FilesystemSink::open(&p).expect("open");
        let results: Vec<_> = sink.iter().expect("iter").collect();
        assert_eq!(results.len(), 1);
        assert!(results[0].is_err());
        let _ = std::fs::remove_file(&p);
    }
}
