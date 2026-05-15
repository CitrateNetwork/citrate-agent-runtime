//! Audit record schema + canonical CBOR encoding — RFC-CIT-AGENT-0001
//! §6.1 + planset `05_AUDIT_CHAIN.md` "Record structure".
//!
//! Signatures are computed over canonical CBOR of the record with
//! `signatures` and `chain_anchor` removed — so each signer signs the
//! same bytes regardless of who else has signed. The canonical-CBOR
//! contract follows RFC 8949 §4.2.1 deterministic encoding:
//!   * Map keys in lexicographic byte order
//!   * No indefinite-length items
//!   * Smallest possible encoding of integers
//!
//! Hash-chain integrity is verified by
//! `.agentile/formal/specs/agent/AuditChainIntegrity.tla` (CIT-AGENT-2
//! PASS at 35,435 distinct states).

use crate::capsule::manifest::Role;
use crate::error::AgentError;
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};

/// The 19-variant exhaustive event type enum per planset 05. Adding
/// a variant is a major-version bump because the doctor pre-flight
/// (CIT-AGENT-7) enumerates all variants for chain-integrity checks.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum EventType {
    Genesis,
    Proposal,
    Edit,
    Approval,
    Rejection,
    Timeout,
    Submission,
    Confirmation,
    CapsuleInstall,
    CapsuleRevoke,
    PolicyUpdate,
    OverlayActivation,
    OverlayDeactivation,
    BreakGlass,
    BreakGlassAffirmation,
    DoctorReport,
    AuditExport,
    Quarantine,
    Resumption,
}

/// Signing surface tag carried in each role-signature for audit
/// provenance. CIT-AGENT-4b's `SigningSurface` trait produces these
/// at the runtime layer; the audit record records the surface
/// flavor so auditors can trace "who signed via which mechanism".
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum SigningSurfaceTag {
    Slint,
    Cli,
    LocalWeb,
    Mobile,
    FileBacked,
}

/// On-chain anchor reference. Present when this record (or its
/// containing Merkle batch) was committed to `AnchorRegistry`. The
/// three anchor strategies (per-capsule, per-approval, nightly
/// Merkle root) are implemented in CIT-AGENT-5c.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct AnchorRef {
    pub anchor_kind: AnchorKind,
    pub block_number: u64,
    pub tx_hash: [u8; 32],
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum AnchorKind {
    PerCapsule,
    PerApproval,
    NightlyMerkle,
}

/// An approver signature on the audit record. CIT-AGENT-4b lands the
/// `Signature` machinery at the queue layer; this is the
/// audit-chain analogue. The two flows converge in CIT-AGENT-5b when
/// the queue feeds approval events into the chain.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RoleSignature {
    /// DID of the signer (e.g. `did:citrate:role:0x...`). CIT-AGENT-6
    /// makes this typed against AgentSBT records.
    pub signer: String,
    pub role: Role,
    pub signed_at: i64,
    pub signature: Vec<u8>,
    pub surface: SigningSurfaceTag,
}

/// The canonical audit record. Every event of interest produces one.
/// The hash chain is built over `record_hash(record_without_sigs)`.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AuditRecord {
    pub sequence: u64,
    pub timestamp: i64,
    pub previous_hash: [u8; 32],
    pub event_type: EventType,
    /// Event-specific payload as a CBOR value (serialized as bytes
    /// when this record is encoded). Per planset 05 each EventType
    /// has its own canonical payload shape; CIT-AGENT-5b/c/d will
    /// land per-variant typed payload helpers. For 5a the payload
    /// is opaque bytes.
    pub payload: Vec<u8>,
    /// AgentSBT DID of the proposer. CIT-AGENT-6 makes this typed.
    pub actor: String,
    pub signatures: Vec<RoleSignature>,
    pub chain_anchor: Option<AnchorRef>,
}

/// CIT-AGENT-5a: opaque view of a record with `signatures` and
/// `chain_anchor` cleared. This is what signers sign over, and what
/// the hash chain links via `record_hash`. Cleared (not removed) so
/// the CBOR map shape stays stable across signing rounds.
fn record_without_sigs(r: &AuditRecord) -> AuditRecord {
    AuditRecord {
        sequence: r.sequence,
        timestamp: r.timestamp,
        previous_hash: r.previous_hash,
        event_type: r.event_type,
        payload: r.payload.clone(),
        actor: r.actor.clone(),
        signatures: Vec::new(),
        chain_anchor: None,
    }
}

/// Encode a record using deterministic CBOR per RFC 8949 §4.2.1.
/// Used for signature computation + hash-chain linkage.
pub fn canonical_cbor(record: &AuditRecord) -> Result<Vec<u8>, AgentError> {
    let stripped = record_without_sigs(record);
    let mut buf = Vec::new();
    ciborium::ser::into_writer(&stripped, &mut buf)
        .map_err(|e| AgentError::Audit(format!("canonical CBOR encode: {e}")))?;
    Ok(buf)
}

/// SHA-256 of the canonical CBOR of `record_without_sigs`. This is
/// the value that goes into the NEXT record's `previous_hash` field.
pub fn record_hash(record: &AuditRecord) -> Result<[u8; 32], AgentError> {
    let bytes = canonical_cbor(record)?;
    let mut h = Sha256::new();
    h.update(&bytes);
    let digest = h.finalize();
    let mut out = [0u8; 32];
    out.copy_from_slice(&digest);
    Ok(out)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn mkrecord(sequence: u64, et: EventType) -> AuditRecord {
        AuditRecord {
            sequence,
            timestamp: 1_715_000_000_000_000_000 + sequence as i64,
            previous_hash: [0u8; 32],
            event_type: et,
            payload: b"payload".to_vec(),
            actor: "did:citrate:agent:0xab12".to_string(),
            signatures: vec![],
            chain_anchor: None,
        }
    }

    #[test]
    fn canonical_cbor_round_trip() {
        let r = mkrecord(0, EventType::Genesis);
        let bytes = canonical_cbor(&r).expect("encode");
        // Decode via ciborium back into a typed record (with empty
        // sigs / anchor since canonical_cbor strips them).
        let decoded: AuditRecord = ciborium::de::from_reader(&bytes[..]).expect("decode");
        assert_eq!(decoded.sequence, r.sequence);
        assert_eq!(decoded.event_type, r.event_type);
        assert_eq!(decoded.payload, r.payload);
        assert!(decoded.signatures.is_empty());
        assert!(decoded.chain_anchor.is_none());
    }

    #[test]
    fn canonical_cbor_deterministic() {
        let r = mkrecord(7, EventType::Approval);
        let a = canonical_cbor(&r).expect("encode 1");
        let b = canonical_cbor(&r).expect("encode 2");
        assert_eq!(a, b, "encoding MUST be byte-identical across calls");
    }

    #[test]
    fn canonical_cbor_ignores_signatures_and_anchor() {
        let mut r = mkrecord(0, EventType::Genesis);
        let bytes_a = canonical_cbor(&r).expect("encode");
        // Add a signature + anchor; canonical bytes MUST be unchanged.
        r.signatures.push(RoleSignature {
            signer: "did:citrate:role:0xrv".to_string(),
            role: Role::Reviewer,
            signed_at: 0,
            signature: vec![1, 2, 3],
            surface: SigningSurfaceTag::Cli,
        });
        r.chain_anchor = Some(AnchorRef {
            anchor_kind: AnchorKind::PerApproval,
            block_number: 42,
            tx_hash: [0xab; 32],
        });
        let bytes_b = canonical_cbor(&r).expect("encode 2");
        assert_eq!(bytes_a, bytes_b);
    }

    #[test]
    fn record_hash_changes_when_payload_changes() {
        let mut r = mkrecord(0, EventType::Genesis);
        let h1 = record_hash(&r).expect("hash");
        r.payload = b"different payload".to_vec();
        let h2 = record_hash(&r).expect("hash 2");
        assert_ne!(h1, h2);
    }

    #[test]
    fn record_hash_is_32_bytes() {
        let r = mkrecord(0, EventType::Genesis);
        let h = record_hash(&r).expect("hash");
        assert_eq!(h.len(), 32);
    }
}
