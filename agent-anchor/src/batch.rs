//! One UTC day's records as a batch: header, day commitment, inclusion proofs, verification.
//!
//! # The anchored value (the day commitment)
//!
//! The value put on chain is not the bare tree root but a commitment over the batch header:
//!
//! ```text
//! commitment = SHA-256( "citrate.agent-anchor.nightly.v1\n"
//!                       || be32(v) || be64(day) || be64(first_seq) || be64(last_seq)
//!                       || be64(count) || tree_root )
//! ```
//!
//! Binding the day and the `seq` range means the anchored value says which records it covers:
//! a verifier holding the header can check that the batch is exactly records
//! `first_seq..=last_seq` of UTC day `day`, and an inclusion proof binds a record's `seq` to its
//! leaf position (`seq = first_seq + leaf_index`), so a valid proof for one record can never be
//! replayed as a proof for another. The domain prefix keeps the commitment distinct from record
//! hashes (`citrate.agent-records.v1\n`) and from tree leaves and nodes (0x00 / 0x01 prefixes over
//! 32 or 64 bytes). `AnchorRegistry` refuses a value it has already seen, and distinct days give
//! distinct commitments, so one day's anchor can never collide with another's.

use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};

use citrate_agent_records::merkle::{utc_day, verify_path, RetainedLeaf};
use citrate_agent_records::StoredRecord;

use crate::error::{Error, Result};
use crate::tree::Tree;

/// Domain prefix of the day commitment.
pub const COMMITMENT_DOMAIN: &[u8] = b"citrate.agent-anchor.nightly.v1\n";

/// Batch header version, part of the commitment.
pub const BATCH_VERSION: u32 = 1;

/// What one day's batch commits to.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct BatchHeader {
    pub v: u32,
    /// UTC day number (days since 1970-01-01).
    pub day: u64,
    pub first_seq: u64,
    pub last_seq: u64,
    pub count: u64,
    /// RFC 6962 root over the day's record hashes, in `seq` order.
    #[serde(with = "crate::hex32")]
    pub tree_root: [u8; 32],
}

impl BatchHeader {
    /// The anchored value (see the module docs for the exact bytes).
    pub fn commitment(&self) -> [u8; 32] {
        let mut h = Sha256::new();
        h.update(COMMITMENT_DOMAIN);
        h.update(self.v.to_be_bytes());
        h.update(self.day.to_be_bytes());
        h.update(self.first_seq.to_be_bytes());
        h.update(self.last_seq.to_be_bytes());
        h.update(self.count.to_be_bytes());
        h.update(self.tree_root);
        h.finalize().into()
    }

    /// Whether the header is internally consistent: a non-empty, contiguous `seq` range.
    pub fn well_formed(&self) -> bool {
        self.v == BATCH_VERSION
            && self.count > 0
            && self.last_seq >= self.first_seq
            && self.last_seq - self.first_seq == self.count - 1
    }
}

/// Proof that one record is in a day's batch.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct AnchorProof {
    pub header: BatchHeader,
    pub seq: u64,
    pub leaf_index: u64,
    /// The record hash (`StoredRecord::hash`), the leaf data.
    #[serde(with = "crate::hex32")]
    pub record_hash: [u8; 32],
    /// Sibling hashes, leaf to root.
    #[serde(with = "crate::hex32::vec")]
    pub path: Vec<[u8; 32]>,
}

/// One closed day's batch.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DayBatch {
    header: BatchHeader,
    leaf_data: Vec<[u8; 32]>,
    tree: Tree,
}

/// Build the batch of UTC day `day` from retained leaves (any days, in `seq` order). The day's
/// records must be a contiguous run of `seq` (the decision log guarantees it, since timestamps
/// never go backwards); anything else is refused. `None` when the day has no records.
/// Deterministic: the result depends only on the input.
pub fn build_day_batch(day: u64, leaves: &[RetainedLeaf]) -> Result<Option<DayBatch>> {
    let mut day_leaves = leaves.iter().filter(|l| utc_day(l.ts_ms) == day);
    let Some(first) = day_leaves.next() else {
        return Ok(None);
    };
    let mut leaf_data = vec![first.hash];
    let mut expected = first.seq;
    for l in day_leaves {
        expected = expected.checked_add(1).ok_or(Error::SeqGap {
            day,
            expected,
            found: l.seq,
        })?;
        if l.seq != expected {
            return Err(Error::SeqGap {
                day,
                expected,
                found: l.seq,
            });
        }
        leaf_data.push(l.hash);
    }
    let Some(tree) = Tree::build(&leaf_data) else {
        return Ok(None);
    };
    let header = BatchHeader {
        v: BATCH_VERSION,
        day,
        first_seq: first.seq,
        last_seq: expected,
        count: leaf_data.len() as u64,
        tree_root: tree.root(),
    };
    Ok(Some(DayBatch {
        header,
        leaf_data,
        tree,
    }))
}

impl DayBatch {
    pub fn header(&self) -> &BatchHeader {
        &self.header
    }

    /// The anchored value.
    pub fn commitment(&self) -> [u8; 32] {
        self.header.commitment()
    }

    /// The inclusion proof for record `seq`. `None` when `seq` is not in this batch.
    pub fn proof(&self, seq: u64) -> Option<AnchorProof> {
        let index = seq.checked_sub(self.header.first_seq)?;
        let i = usize::try_from(index).ok()?;
        let record_hash = *self.leaf_data.get(i)?;
        Some(AnchorProof {
            header: self.header.clone(),
            seq,
            leaf_index: index,
            record_hash,
            path: self.tree.path(i)?,
        })
    }

    /// Proofs for every record of the batch, in `seq` order.
    pub fn proofs(&self) -> Vec<AnchorProof> {
        (self.header.first_seq..=self.header.last_seq)
            .filter_map(|s| self.proof(s))
            .collect()
    }
}

/// Check a proof against an anchored value (read from `AnchorRegistry`): the header commits to
/// `anchored`, the header is well formed, the record's `seq` sits at its leaf position, and the
/// path leads from the record hash to the header's tree root.
pub fn verify_proof(p: &AnchorProof, anchored: &[u8; 32]) -> bool {
    let h = &p.header;
    h.well_formed()
        && h.commitment() == *anchored
        && p.leaf_index < h.count
        && h.first_seq.checked_add(p.leaf_index) == Some(p.seq)
        && verify_path(&p.record_hash, p.leaf_index, h.count, &p.path, &h.tree_root)
}

/// [`verify_proof`], plus: `record` is the leaf. Its body hashes to the stored hash, that hash is
/// the proof's leaf, its `seq` matches, and its timestamp falls on the batch's day.
pub fn verify_record_proof(
    record: &StoredRecord,
    p: &AnchorProof,
    anchored: &[u8; 32],
) -> Result<bool> {
    let body_hash = record.record.hash_bytes()?;
    Ok(record.hash_matches()?
        && body_hash == p.record_hash
        && record.record.seq == p.seq
        && utc_day(record.record.ts_ms) == p.header.day
        && verify_proof(p, anchored))
}
