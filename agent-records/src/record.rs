//! The record schema and its canonical hash.
//!
//! One line of a segment file is one [`StoredRecord`]: the record body plus the hex SHA-256 of the
//! body's canonical JSON. The body carries the previous record's hash (`prev`) and a strictly
//! increasing `seq`, which is what makes the log a chain.

use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};

use crate::error::{Error, Result};

/// Schema version written into every record body.
pub const SCHEMA_VERSION: u32 = 1;

/// The `prev` of the very first record: 32 zero bytes, hex encoded.
pub const GENESIS_PREV: &str = "0000000000000000000000000000000000000000000000000000000000000000";

/// Domain-separation prefix for record hashes, so a record hash can never collide with a Merkle
/// leaf or node hash (those use RFC 6962's 0x00 / 0x01 prefixes over 32-byte inputs).
const RECORD_DOMAIN: &[u8] = b"citrate.agent-records.v1\n";

/// Upper bounds on free-text fields, so one record cannot bloat a segment.
pub const MAX_ID_LEN: usize = 256;
pub const MAX_KIND_LEN: usize = 128;
pub const MAX_SUBJECT_LEN: usize = 1024;
pub const MAX_REASON_LEN: usize = 4096;
pub const MAX_EVIDENCE: usize = 32;
pub const MAX_URI_LEN: usize = 2048;

/// Who produced the record.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ActorKind {
    /// The human member (an explicit approve or deny).
    Member,
    /// The interactive agent (Hermes) acting inside a budget.
    Agent,
    /// A scheduled or triggered daemon run, or this crate's own crash recovery.
    Daemon,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Actor {
    pub kind: ActorKind,
    pub id: String,
}

impl Actor {
    pub fn member(id: impl Into<String>) -> Self {
        Self {
            kind: ActorKind::Member,
            id: id.into(),
        }
    }
    pub fn agent(id: impl Into<String>) -> Self {
        Self {
            kind: ActorKind::Agent,
            id: id.into(),
        }
    }
    pub fn daemon(id: impl Into<String>) -> Self {
        Self {
            kind: ActorKind::Daemon,
            id: id.into(),
        }
    }
}

/// The HIC tier the event was gated at. HIC-0 (reads) is not recorded.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum HicTier {
    /// Approve each: transactions, key operations, deploys, off-allowlist shell, and so on.
    #[serde(rename = "hic-1")]
    Hic1,
    /// Inside a budget granted earlier through the ceremony.
    #[serde(rename = "hic-2")]
    Hic2,
}

/// What was decided.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Decision {
    Approved,
    Denied,
    /// Allowed without a prompt because a live HIC-2 budget covered it. Never valid for HIC-1.
    AutoWithinBudget,
}

impl Decision {
    /// Whether an effect may follow this decision, so an outcome record is owed.
    pub fn expects_outcome(self) -> bool {
        matches!(self, Decision::Approved | Decision::AutoWithinBudget)
    }
}

/// What happened to the effect after an allowing decision.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Outcome {
    Completed,
    Failed,
    /// The effect may or may not have happened. Written by crash recovery for every allowing
    /// decision that has no outcome, because a write-ahead record cannot tell a crash before the
    /// effect from a crash after it. Callers may also write it (for example on a submit timeout).
    OutcomeUnknown,
}

/// A pointer to evidence held elsewhere (an approval card id, a tx hash, a file digest).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct EvidenceRef {
    pub kind: String,
    pub uri: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub digest: Option<String>,
}

/// An HIC decision. Written before any effect it allows (write-ahead).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct DecisionEvent {
    pub tier: HicTier,
    /// The event kind, for example `tx`, `deploy`, `siwe`, `x402`, `shell`, `fs_write`.
    pub kind: String,
    /// What the decision is about, for example the origin, the command, or the decoded call.
    pub subject: String,
    pub decision: Decision,
    pub reason: String,
    #[serde(default)]
    pub evidence: Vec<EvidenceRef>,
}

/// Closes an allowing decision.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct OutcomeEvent {
    /// The `seq` of the decision this outcome closes.
    pub decision_seq: u64,
    pub outcome: Outcome,
    pub detail: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Entry {
    Decision(DecisionEvent),
    Outcome(OutcomeEvent),
}

/// The hashed part of a record.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct RecordBody {
    pub v: u32,
    pub seq: u64,
    /// Unix milliseconds. Clamped to be non-decreasing along the chain, so a UTC day is always a
    /// contiguous run of `seq`.
    pub ts_ms: u64,
    /// Hex SHA-256 of the previous record, or [`GENESIS_PREV`].
    pub prev: String,
    pub actor: Actor,
    pub entry: Entry,
}

/// One line of a segment file.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct StoredRecord {
    /// Hex SHA-256 over the domain prefix and the body's canonical JSON.
    pub hash: String,
    pub record: RecordBody,
}

impl RecordBody {
    /// Canonical bytes: serde_json over a struct with a fixed field order and no maps, so the
    /// encoding is deterministic. Unknown fields are refused on parse, so nothing can hide outside
    /// the hash.
    pub fn canonical_json(&self) -> Result<Vec<u8>> {
        serde_json::to_vec(self).map_err(Error::Json)
    }

    pub fn hash_bytes(&self) -> Result<[u8; 32]> {
        let mut h = Sha256::new();
        h.update(RECORD_DOMAIN);
        h.update(self.canonical_json()?);
        Ok(h.finalize().into())
    }

    pub fn hash_hex(&self) -> Result<String> {
        Ok(hex::encode(self.hash_bytes()?))
    }
}

impl StoredRecord {
    /// Seal a body: compute its hash.
    pub fn seal(record: RecordBody) -> Result<Self> {
        let hash = record.hash_hex()?;
        Ok(Self { hash, record })
    }

    /// Whether the stored hash matches the body.
    pub fn hash_matches(&self) -> Result<bool> {
        Ok(self.record.hash_hex()? == self.hash)
    }

    /// The record hash as raw bytes (the Merkle leaf data).
    pub fn hash_raw(&self) -> Result<[u8; 32]> {
        decode_hash(&self.hash)
    }
}

pub(crate) fn decode_hash(s: &str) -> Result<[u8; 32]> {
    let mut out = [0u8; 32];
    hex::decode_to_slice(s, &mut out).map_err(|_| Error::Invalid(format!("bad hash hex: {s}")))?;
    Ok(out)
}

fn check_len(field: &str, s: &str, max: usize, allow_empty: bool) -> Result<()> {
    if !allow_empty && s.trim().is_empty() {
        return Err(Error::Invalid(format!("{field} must not be empty")));
    }
    if s.len() > max {
        return Err(Error::Invalid(format!("{field} longer than {max} bytes")));
    }
    Ok(())
}

pub(crate) fn validate_actor(a: &Actor) -> Result<()> {
    check_len("actor.id", &a.id, MAX_ID_LEN, false)
}

/// Field-level policy for a decision, applied on append and again by the verifier.
pub(crate) fn validate_decision(d: &DecisionEvent) -> Result<()> {
    check_len("kind", &d.kind, MAX_KIND_LEN, false)?;
    check_len("subject", &d.subject, MAX_SUBJECT_LEN, false)?;
    check_len("reason", &d.reason, MAX_REASON_LEN, true)?;
    if d.tier == HicTier::Hic1 && d.decision == Decision::AutoWithinBudget {
        return Err(Error::Invalid(
            "HIC-1 events are approved each time; auto_within_budget is only valid for HIC-2"
                .into(),
        ));
    }
    if d.evidence.len() > MAX_EVIDENCE {
        return Err(Error::Invalid(format!(
            "at most {MAX_EVIDENCE} evidence refs"
        )));
    }
    for e in &d.evidence {
        check_len("evidence.kind", &e.kind, MAX_KIND_LEN, false)?;
        check_len("evidence.uri", &e.uri, MAX_URI_LEN, false)?;
        if let Some(dg) = &e.digest {
            check_len("evidence.digest", dg, MAX_URI_LEN, false)?;
        }
    }
    Ok(())
}

pub(crate) fn validate_outcome(o: &OutcomeEvent) -> Result<()> {
    check_len("detail", &o.detail, MAX_REASON_LEN, true)
}
