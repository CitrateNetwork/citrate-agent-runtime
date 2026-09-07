//! Hash-chained audit log — RFC-CIT-AGENT-0001 §6 + planset
//! `05_AUDIT_CHAIN.md` "Hash chain integrity".
//!
//! Verified by `.agentile/formal/specs/agent/AuditChainIntegrity.tla`
//! (CIT-AGENT-2 PASS at 35,435 distinct states). The three invariants
//! `ChainContiguity`, `SignatureValidity`, `NoDanglingPrevHash` are
//! concretized as runtime checks in `AuditChain::append` (write side)
//! and `AuditChain::verify_integrity` (read side).

use crate::audit::record::{
    record_hash, verify_role_signature, AnchorRef, AuditRecord, EventType, RoleSignature,
};
use crate::audit::sink::AuditSink;
use crate::error::AgentError;
use crate::hitl::signing::{signer_is_authorized, SignerRoster};
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
    /// Optional roster of public keys authorized to sign under given
    /// roles. AR-B-002: when set, every `RoleSignature` on an appended
    /// or verified record must (a) verify cryptographically and (b)
    /// come from a key enrolled for the role it claims. When `None`,
    /// signature *authorization* falls back to `signer_is_authorized`'s
    /// dev/prod policy (fail-closed in release builds), but the
    /// cryptographic check always runs.
    roster: Option<Arc<dyn SignerRoster>>,
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
            roster: None,
        })
    }

    /// Open an EXISTING chain WITHOUT minting a genesis. Returns
    /// `Ok(None)` when the sink holds no records so the caller can
    /// decide what an empty sink means.
    ///
    /// AR-B-001: the doctor integrity check previously used
    /// `open_or_init`, which mints a fresh genesis on an empty sink —
    /// so a *wholesale-deleted* audit log was silently re-initialised
    /// and reported as an intact "verified 1 records" Pass. The doctor
    /// must treat an empty sink as a Blocker instead; this opener gives
    /// it the ability to distinguish "empty" from "one record".
    pub fn open_existing(sink: Arc<dyn AuditSink>) -> Result<Option<Self>, AgentError> {
        let mut next_sequence = 0u64;
        let mut last_hash = [0u8; 32];
        let mut has_records = false;
        for r in sink.iter()? {
            let record = r?;
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
            return Ok(None);
        }
        Ok(Some(Self {
            sink,
            next_sequence,
            last_hash,
            roster: None,
        }))
    }

    /// Attach a `SignerRoster` so appended / verified role-signatures
    /// are checked against enrolled keys (AR-B-002).
    pub fn with_roster(mut self, roster: Arc<dyn SignerRoster>) -> Self {
        self.roster = Some(roster);
        self
    }

    /// Verify the walked head matches an externally-anchored
    /// expectation (AgentSBT `latest_audit_chain_head` / the last
    /// `AnchorRegistry` Merkle root). This is the ONLY way to detect
    /// tail-truncation and rollback: internal contiguity from genesis
    /// stays intact after the tail is lopped off, so a truncated log
    /// walks clean. AR-B-001.
    pub fn verify_head(
        &self,
        expected_sequence: u64,
        expected_hash: [u8; 32],
    ) -> Result<(), AgentError> {
        if self.next_sequence == 0 {
            return Err(AgentError::Audit(
                "audit chain is empty — cannot match expected head".into(),
            ));
        }
        let head_sequence = self.next_sequence - 1;
        if head_sequence != expected_sequence || self.last_hash != expected_hash {
            return Err(AgentError::Audit(format!(
                "audit chain head mismatch: walked head is sequence {head_sequence}, \
                 expected {expected_sequence} — tail truncation or rollback detected"
            )));
        }
        Ok(())
    }

    /// Verify every `RoleSignature` on `record`: cryptographically bind
    /// it to the record, and (when configured / in release builds)
    /// require the key to be an authorized signer for the claimed role.
    /// AR-B-002.
    fn verify_signatures(&self, record: &AuditRecord) -> Result<(), AgentError> {
        // In debug / test builds with no roster we allow un-enrolled
        // keys through the AUTHORIZATION gate so local flows work, but
        // the cryptographic check below always runs. Release builds
        // fail closed: a signed record with no roster is rejected.
        let dev_allowed = cfg!(debug_assertions);
        for sig in &record.signatures {
            verify_role_signature(record, sig)?;
            if !signer_is_authorized(
                self.roster.as_deref(),
                &sig.signer_pubkey,
                sig.role,
                dev_allowed,
            ) {
                return Err(AgentError::Audit(format!(
                    "audit signature: signer '{}' is not authorized for role {:?}",
                    sig.signer, sig.role
                )));
            }
        }
        Ok(())
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
        // AR-B-002: refuse to persist a record carrying an unverifiable
        // or unauthorized role-signature. Signatures are computed over
        // `canonical_cbor(record_without_sigs)`, which is fully
        // determined here (sequence + previous_hash are assigned above),
        // so the binding is exact.
        self.verify_signatures(&record)?;
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
            // AR-B-002: re-verify every role-signature on the read path,
            // so a signature written directly into the JSONL (bypassing
            // `append`) cannot pass off as an attestation.
            self.verify_signatures(&record)?;
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

    // ── AR-B-002 tripwires ────────────────────────────────────────────
    use crate::audit::record::{canonical_cbor, SigningSurfaceTag};
    use crate::capsule::manifest::Role;
    use crate::hitl::signing::StaticSignerRoster;
    use ed25519_dalek::{Signer as _, SigningKey};

    /// A fabricated `RoleSignature` (64 zero bytes, claiming
    /// SecurityOfficer) must be REJECTED by `append` — it does not
    /// verify cryptographically. Red on the pre-fix code, which stored
    /// it verbatim and never checked it.
    #[test]
    fn append_rejects_forged_signature_ar_b_002() {
        let sink: Arc<dyn AuditSink> = Arc::new(MemorySink::default());
        let mut chain =
            AuditChain::open_or_init(sink, genesis_info(), 1_715_000_000).expect("open");
        let forged = RoleSignature {
            signer: "did:citrate:role:0xSECURITY_OFFICER".to_string(),
            role: Role::SecurityOfficer,
            signed_at: 0,
            signature: vec![0u8; 64],
            surface: SigningSurfaceTag::Slint,
            signer_pubkey: [0u8; 32],
        };
        let res = chain.append(
            EventType::Approval,
            b"privileged write".to_vec(),
            "did:citrate:agent:0xab12".to_string(),
            vec![forged],
            None,
            1_715_000_001,
        );
        assert!(res.is_err(), "forged signature must be rejected, got {res:?}");
    }

    /// A cryptographically-VALID signature from a key that is NOT on
    /// the roster (a self-minted key) must be rejected when a roster is
    /// configured, and the same key+sig must be ACCEPTED once enrolled.
    #[test]
    fn append_roster_gates_signature_ar_b_002() {
        let ts = 1_715_000_001i64;
        let key = SigningKey::from_bytes(&[7u8; 32]);
        let pubkey = key.verifying_key().to_bytes();
        let payload = b"privileged action".to_vec();
        let actor = "did:citrate:agent:0xab12".to_string();

        // Helper: sign the exact canonical preimage `append` will hash.
        let sign_for = |chain: &AuditChain| -> Vec<u8> {
            let unsigned = AuditRecord {
                sequence: chain.next_sequence(),
                timestamp: ts,
                previous_hash: chain.last_hash(),
                event_type: EventType::Approval,
                payload: payload.clone(),
                actor: actor.clone(),
                signatures: vec![],
                chain_anchor: None,
            };
            let preimage = canonical_cbor(&unsigned).expect("cbor");
            key.sign(&preimage).to_bytes().to_vec()
        };

        // (a) Roster present, key NOT enrolled → rejected even with a valid sig.
        {
            let sink: Arc<dyn AuditSink> = Arc::new(MemorySink::default());
            let roster = Arc::new(StaticSignerRoster::new()); // empty roster
            let mut chain = AuditChain::open_or_init(sink, genesis_info(), 1_715_000_000)
                .expect("open")
                .with_roster(roster);
            let sig = sign_for(&chain);
            let unauthorized = RoleSignature {
                signer: "did:citrate:role:0xSO".to_string(),
                role: Role::SecurityOfficer,
                signed_at: 0,
                signature: sig,
                surface: SigningSurfaceTag::Slint,
                signer_pubkey: pubkey,
            };
            let res = chain.append(
                EventType::Approval,
                payload.clone(),
                actor.clone(),
                vec![unauthorized],
                None,
                ts,
            );
            assert!(
                res.is_err(),
                "valid sig from un-enrolled key must be rejected by the roster, got {res:?}"
            );
        }

        // (b) Roster present, key enrolled for the role → accepted.
        {
            let sink: Arc<dyn AuditSink> = Arc::new(MemorySink::default());
            let roster =
                Arc::new(StaticSignerRoster::new().authorize(pubkey, Role::SecurityOfficer));
            let mut chain = AuditChain::open_or_init(sink, genesis_info(), 1_715_000_000)
                .expect("open")
                .with_roster(roster);
            let sig = sign_for(&chain);
            let authorized = RoleSignature {
                signer: "did:citrate:role:0xSO".to_string(),
                role: Role::SecurityOfficer,
                signed_at: 0,
                signature: sig,
                surface: SigningSurfaceTag::Slint,
                signer_pubkey: pubkey,
            };
            chain
                .append(
                    EventType::Approval,
                    payload.clone(),
                    actor.clone(),
                    vec![authorized],
                    None,
                    ts,
                )
                .expect("enrolled key + valid sig must be accepted");
        }
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
