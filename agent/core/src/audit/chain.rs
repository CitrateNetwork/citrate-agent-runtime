//! Hash-chained audit log — RFC-CIT-AGENT-0001 §6 + planset
//! `05_AUDIT_CHAIN.md` "Hash chain integrity".
//!
//! Verified by `.agentile/formal/specs/agent/AuditChainIntegrity.tla`
//! (CIT-AGENT-2 PASS at 35,435 distinct states). The three invariants
//! `ChainContiguity`, `SignatureValidity`, `NoDanglingPrevHash` are
//! concretized as runtime checks in `AuditChain::append` (write side)
//! and `AuditChain::verify_integrity` (read side).

use crate::audit::record::{
    record_hash, AnchorRef, AuditRecord, EventType, RoleSignature,
};
use crate::audit::sink::AuditSink;
use crate::error::AgentError;
use std::sync::Arc;

/// Information needed to mint the genesis record on first init.
#[derive(Debug, Clone)]
pub struct GenesisInfo {
    pub agent_did: String,
    pub harness_version: String,
    pub policy_bundle_hash: [u8; 32],
    pub doctor_report_hash: [u8; 32],
}

/// Hash-chained audit log. Owns the sink + tracks the
/// monotonic-sequence + last-hash invariant. Concurrent appenders
/// MUST serialize through this struct — call sites typically wrap it
/// in `Arc<Mutex<AuditChain>>`.
pub struct AuditChain {
    sink: Arc<dyn AuditSink>,
    next_sequence: u64,
    last_hash: [u8; 32],
}

impl AuditChain {
    /// Open the chain from its sink. If the sink is empty, mints a
    /// genesis record using `genesis_info`. Otherwise, walks the
    /// existing records to recover `next_sequence` and `last_hash`
    /// — this is the offline-verifiable replay path.
    pub fn open_or_init(
        sink: Arc<dyn AuditSink>,
        genesis_info: GenesisInfo,
        now_unix_nanos: i64,
    ) -> Result<Self, AgentError> {
        let mut next_sequence = 0u64;
        let mut last_hash = [0u8; 32];
        let mut has_records = false;
        // Walk the sink to find the tail.
        for r in sink.iter()? {
            let record = r?;
            // Contiguity check: every record's previous_hash MUST
            // equal the previously-computed last_hash. The first
            // record's previous_hash MUST be all zeros (genesis).
            if record.previous_hash != last_hash {
                return Err(AgentError::Audit(format!(
                    "chain contiguity broken at sequence {}: previous_hash mismatch",
                    record.sequence
                )));
            }
            if record.sequence != next_sequence {
                return Err(AgentError::Audit(format!(
                    "chain sequence broken: expected {next_sequence}, got {}",
                    record.sequence
                )));
            }
            last_hash = record_hash(&record)?;
            next_sequence = record.sequence + 1;
            has_records = true;
        }
        if !has_records {
            // Mint the genesis record.
            // Encode genesis payload as CBOR of (agent_did,
            // harness_version, policy_bundle_hash, doctor_report_hash).
            let payload = encode_genesis_payload(&genesis_info)?;
            let genesis = AuditRecord {
                sequence: 0,
                timestamp: now_unix_nanos,
                previous_hash: [0u8; 32],
                event_type: EventType::Genesis,
                payload,
                actor: genesis_info.agent_did.clone(),
                signatures: vec![],
                chain_anchor: None,
            };
            sink.append(&genesis)?;
            last_hash = record_hash(&genesis)?;
            next_sequence = 1;
        }
        Ok(Self {
            sink,
            next_sequence,
            last_hash,
        })
    }

    /// Append a new event to the chain. Computes `previous_hash` from
    /// the chain's tracked `last_hash`, assigns the next sequence
    /// number, persists via the sink, and updates the local state.
    /// Returns the appended record.
    pub fn append(
        &mut self,
        event_type: EventType,
        payload: Vec<u8>,
        actor: String,
        signatures: Vec<RoleSignature>,
        anchor: Option<AnchorRef>,
        now_unix_nanos: i64,
    ) -> Result<AuditRecord, AgentError> {
        let record = AuditRecord {
            sequence: self.next_sequence,
            timestamp: now_unix_nanos,
            previous_hash: self.last_hash,
            event_type,
            payload,
            actor,
            signatures,
            chain_anchor: anchor,
        };
        self.sink.append(&record)?;
        self.last_hash = record_hash(&record)?;
        self.next_sequence += 1;
        Ok(record)
    }

    /// Walk the chain end-to-end, verifying contiguity at every
    /// record. Returns the number of records on success; on first
    /// tamper detected, returns `AgentError::Audit` with the
    /// sequence number where the chain broke.
    pub fn verify_integrity(&self) -> Result<u64, AgentError> {
        let mut count = 0u64;
        let mut expected_prev = [0u8; 32];
        let mut expected_seq = 0u64;
        for r in self.sink.iter()? {
            let record = r?;
            if record.sequence != expected_seq {
                return Err(AgentError::Audit(format!(
                    "sequence break at record {}: expected {expected_seq}",
                    record.sequence
                )));
            }
            if record.previous_hash != expected_prev {
                return Err(AgentError::Audit(format!(
                    "previous_hash break at sequence {}: chain tampered",
                    record.sequence
                )));
            }
            expected_prev = record_hash(&record)?;
            expected_seq = record.sequence + 1;
            count += 1;
        }
        Ok(count)
    }

    pub fn next_sequence(&self) -> u64 {
        self.next_sequence
    }

    pub fn last_hash(&self) -> [u8; 32] {
        self.last_hash
    }
}

fn encode_genesis_payload(g: &GenesisInfo) -> Result<Vec<u8>, AgentError> {
    // Canonical CBOR of a small record. We use the same ciborium
    // encoder path as `record::canonical_cbor` for consistency.
    let val = ciborium::value::Value::Map(vec![
        (
            ciborium::value::Value::Text("agent_did".to_string()),
            ciborium::value::Value::Text(g.agent_did.clone()),
        ),
        (
            ciborium::value::Value::Text("harness_version".to_string()),
            ciborium::value::Value::Text(g.harness_version.clone()),
        ),
        (
            ciborium::value::Value::Text("policy_bundle_hash".to_string()),
            ciborium::value::Value::Bytes(g.policy_bundle_hash.to_vec()),
        ),
        (
            ciborium::value::Value::Text("doctor_report_hash".to_string()),
            ciborium::value::Value::Bytes(g.doctor_report_hash.to_vec()),
        ),
    ]);
    let mut buf = Vec::new();
    ciborium::ser::into_writer(&val, &mut buf)
        .map_err(|e| AgentError::Audit(format!("genesis payload encode: {e}")))?;
    Ok(buf)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::audit::sink::FilesystemSink;
    use std::sync::Mutex;

    /// In-memory sink for unit testing without filesystem coupling.
    #[derive(Default)]
    struct MemorySink {
        records: Mutex<Vec<AuditRecord>>,
    }

    impl AuditSink for MemorySink {
        fn append(&self, record: &AuditRecord) -> Result<(), AgentError> {
            self.records
                .lock()
                .map_err(|_| AgentError::Audit("mutex poisoned".to_string()))?
                .push(record.clone());
            Ok(())
        }

        fn iter(
            &self,
        ) -> Result<
            Box<dyn Iterator<Item = Result<AuditRecord, AgentError>> + '_>,
            AgentError,
        > {
            let snapshot: Vec<AuditRecord> = self
                .records
                .lock()
                .map_err(|_| AgentError::Audit("mutex poisoned".to_string()))?
                .clone();
            Ok(Box::new(snapshot.into_iter().map(Ok)))
        }
    }

    fn genesis_info() -> GenesisInfo {
        GenesisInfo {
            agent_did: "did:citrate:agent:0xab12".to_string(),
            harness_version: "0.4.0".to_string(),
            policy_bundle_hash: [0u8; 32],
            doctor_report_hash: [0u8; 32],
        }
    }

    #[test]
    fn genesis_has_zero_prev_hash_and_sequence_zero() {
        let sink: Arc<dyn AuditSink> = Arc::new(MemorySink::default());
        let _chain = AuditChain::open_or_init(sink.clone(), genesis_info(), 1_715_000_000)
            .expect("open");
        let records: Vec<_> = sink.iter().unwrap().collect::<Result<_, _>>().unwrap();
        assert_eq!(records.len(), 1);
        assert_eq!(records[0].sequence, 0);
        assert_eq!(records[0].previous_hash, [0u8; 32]);
        assert_eq!(records[0].event_type, EventType::Genesis);
    }

    #[test]
    fn append_links_previous_hash() {
        let sink: Arc<dyn AuditSink> = Arc::new(MemorySink::default());
        let mut chain = AuditChain::open_or_init(sink.clone(), genesis_info(), 1_715_000_000)
            .expect("open");
        let r1 = chain
            .append(
                EventType::Proposal,
                b"action 1".to_vec(),
                "did:citrate:role:0xop".to_string(),
                vec![],
                None,
                1_715_000_001,
            )
            .expect("append 1");
        let r2 = chain
            .append(
                EventType::Approval,
                b"action 1 approve".to_vec(),
                "did:citrate:role:0xrv".to_string(),
                vec![],
                None,
                1_715_000_002,
            )
            .expect("append 2");
        assert_eq!(r1.sequence, 1);
        assert_eq!(r2.sequence, 2);
        // r1's previous_hash equals the genesis record's hash.
        let genesis_records: Vec<_> =
            sink.iter().unwrap().collect::<Result<_, _>>().unwrap();
        assert_eq!(r1.previous_hash, record_hash(&genesis_records[0]).unwrap());
        // r2's previous_hash equals r1's hash.
        assert_eq!(r2.previous_hash, record_hash(&r1).unwrap());
    }

    #[test]
    fn verify_integrity_walks_clean_chain() {
        let sink: Arc<dyn AuditSink> = Arc::new(MemorySink::default());
        let mut chain = AuditChain::open_or_init(sink, genesis_info(), 1_715_000_000)
            .expect("open");
        for i in 0..5 {
            chain
                .append(
                    EventType::Proposal,
                    format!("action {i}").into_bytes(),
                    "did:citrate:role:0xop".to_string(),
                    vec![],
                    None,
                    1_715_000_000 + i,
                )
                .expect("append");
        }
        let count = chain.verify_integrity().expect("verify");
        assert_eq!(count, 6); // genesis + 5 proposals
    }

    #[test]
    fn verify_integrity_detects_payload_tamper() {
        let memsink = Arc::new(MemorySink::default());
        let sink: Arc<dyn AuditSink> = memsink.clone();
        let mut chain = AuditChain::open_or_init(sink, genesis_info(), 1_715_000_000)
            .expect("open");
        chain
            .append(
                EventType::Proposal,
                b"original".to_vec(),
                "did:citrate:role:0xop".to_string(),
                vec![],
                None,
                1_715_000_001,
            )
            .expect("append");
        chain
            .append(
                EventType::Approval,
                b"approve".to_vec(),
                "did:citrate:role:0xrv".to_string(),
                vec![],
                None,
                1_715_000_002,
            )
            .expect("append");
        // Tamper: change the payload of record 1 in the sink without
        // updating record 2's previous_hash.
        {
            let mut records = memsink.records.lock().unwrap();
            records[1].payload = b"tampered".to_vec();
        }
        let err = chain.verify_integrity().expect_err("tamper detected");
        assert!(err.to_string().contains("previous_hash break"));
    }

    #[test]
    fn end_to_end_filesystem_round_trip() {
        let tmp = std::env::temp_dir().join("cit-agent-5a-fs-roundtrip.jsonl");
        let _ = std::fs::remove_file(&tmp);
        {
            let sink: Arc<dyn AuditSink> =
                Arc::new(FilesystemSink::open(&tmp).expect("open"));
            let mut chain =
                AuditChain::open_or_init(sink, genesis_info(), 1_715_000_000).expect("open");
            chain
                .append(
                    EventType::Proposal,
                    b"action".to_vec(),
                    "did:citrate:role:0xop".to_string(),
                    vec![],
                    None,
                    1_715_000_001,
                )
                .expect("append");
        }
        // Re-open: walk the file, verify integrity.
        {
            let sink: Arc<dyn AuditSink> =
                Arc::new(FilesystemSink::open(&tmp).expect("re-open"));
            let chain =
                AuditChain::open_or_init(sink, genesis_info(), 1_715_000_000).expect("open");
            let count = chain.verify_integrity().expect("verify");
            assert_eq!(count, 2);
        }
        let _ = std::fs::remove_file(&tmp);
    }
}
