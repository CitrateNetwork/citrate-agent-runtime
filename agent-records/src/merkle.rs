//! The daily Merkle root over record hashes, and inclusion proofs, for later anchoring.
//!
//! The tree is RFC 6962 / RFC 9162: leaf `SHA-256(0x00 || record_hash)`, node
//! `SHA-256(0x01 || left || right)`, split at the largest power of two below the size (no
//! duplicated last leaf). A day is a UTC calendar day of record timestamps; because timestamps
//! are clamped to be non-decreasing, a day is one contiguous run of `seq`.
//!
//! Nothing here anchors. HUP-S7.3 (`citrate-agent-anchor`) builds the nightly batch, its anchor
//! commitment, and the anchor calldata on top of [`retained_leaves`] and these hash functions.

use std::path::Path;

use sha2::{Digest, Sha256};

use crate::error::{Error, Result};
use crate::record::decode_hash;
use crate::seg::{walk, Mode};

pub const DAY_MS: u64 = 86_400_000;

/// The UTC day number (days since 1970-01-01) of a Unix-millisecond timestamp.
pub fn utc_day(ts_ms: u64) -> u64 {
    ts_ms / DAY_MS
}

/// The Merkle root of one UTC day's records.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DailyRoot {
    pub day: u64,
    pub first_seq: u64,
    pub last_seq: u64,
    pub count: u64,
    /// Hex root.
    pub root: String,
}

/// Proof that one record is a leaf of its day's tree.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct InclusionProof {
    pub day: u64,
    pub seq: u64,
    pub leaf_index: u64,
    pub tree_size: u64,
    /// Hex record hash (the leaf data).
    pub leaf: String,
    /// Hex sibling hashes, leaf to root.
    pub path: Vec<String>,
    /// Hex root.
    pub root: String,
}

/// RFC 6962 leaf hash: `SHA-256(0x00 || data)`.
pub fn leaf_hash(data: &[u8; 32]) -> [u8; 32] {
    let mut h = Sha256::new();
    h.update([0u8]);
    h.update(data);
    h.finalize().into()
}

/// RFC 6962 interior node hash: `SHA-256(0x01 || left || right)`.
pub fn node_hash(l: &[u8; 32], r: &[u8; 32]) -> [u8; 32] {
    let mut h = Sha256::new();
    h.update([1u8]);
    h.update(l);
    h.update(r);
    h.finalize().into()
}

/// Largest power of two strictly below `n` (`n >= 2`).
fn split(n: usize) -> usize {
    let mut k = 1;
    while k * 2 < n {
        k *= 2;
    }
    k
}

fn mth(leaves: &[[u8; 32]]) -> [u8; 32] {
    match leaves {
        [] => [0u8; 32], // unreachable through the public API: callers check emptiness
        [one] => leaf_hash(one),
        _ => {
            let k = split(leaves.len());
            node_hash(&mth(&leaves[..k]), &mth(&leaves[k..]))
        }
    }
}

/// The RFC 6962 root of `leaves` (record hashes). `None` for no leaves.
pub fn merkle_root(leaves: &[[u8; 32]]) -> Option<[u8; 32]> {
    if leaves.is_empty() {
        None
    } else {
        Some(mth(leaves))
    }
}

/// The audit path for leaf `index`, leaf to root. Empty when `index` is out of range or the
/// tree has one leaf.
pub fn audit_path(leaves: &[[u8; 32]], index: usize) -> Vec<[u8; 32]> {
    if index >= leaves.len() || leaves.len() < 2 {
        return Vec::new();
    }
    let k = split(leaves.len());
    let (mut p, sibling) = if index < k {
        (audit_path(&leaves[..k], index), mth(&leaves[k..]))
    } else {
        (audit_path(&leaves[k..], index - k), mth(&leaves[..k]))
    };
    p.push(sibling);
    p
}

/// RFC 9162 §2.1.3.2 inclusion verification.
pub fn verify_path(
    leaf: &[u8; 32],
    index: u64,
    size: u64,
    path: &[[u8; 32]],
    root: &[u8; 32],
) -> bool {
    if index >= size {
        return false;
    }
    let (mut fnode, mut snode) = (index, size - 1);
    let mut r = leaf_hash(leaf);
    for p in path {
        if snode == 0 {
            return false;
        }
        if fnode & 1 == 1 || fnode == snode {
            r = node_hash(p, &r);
            while fnode & 1 == 0 && fnode != 0 {
                fnode >>= 1;
                snode >>= 1;
            }
        } else {
            r = node_hash(&r, p);
        }
        fnode >>= 1;
        snode >>= 1;
    }
    snode == 0 && &r == root
}

/// Check a proof produced by [`inclusion_proof`]. Malformed hex is a failed proof.
pub fn verify_inclusion(p: &InclusionProof) -> bool {
    let (Ok(leaf), Ok(root)) = (decode_hash(&p.leaf), decode_hash(&p.root)) else {
        return false;
    };
    let path: std::result::Result<Vec<[u8; 32]>, Error> =
        p.path.iter().map(|h| decode_hash(h)).collect();
    let Ok(path) = path else {
        return false;
    };
    verify_path(&leaf, p.leaf_index, p.tree_size, &path, &root)
}

/// One retained record as a Merkle leaf.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct RetainedLeaf {
    pub seq: u64,
    pub ts_ms: u64,
    /// The record hash (the leaf data).
    pub hash: [u8; 32],
}

/// Every retained record as a leaf, in `seq` order, plus where pruning stopped.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RetainedLeaves {
    pub leaves: Vec<RetainedLeaf>,
    /// Timestamp of the last pruned record, when older segments were pruned. Records of any day
    /// at or before `utc_day(pruned_through_ms)` may be missing, so a root over that day would
    /// not cover the whole day.
    pub pruned_through_ms: Option<u64>,
}

/// Every retained record, after verifying the chain. A torn tail or a lagging `HEAD` from an
/// append in flight is tolerated; any real break is an error, because a root over a broken chain
/// must never be produced.
pub fn retained_leaves(dir: &Path) -> Result<RetainedLeaves> {
    let mut out = Vec::new();
    let mut bad: Option<Error> = None;
    let walked = walk(dir, Mode::Live, |r| {
        if bad.is_some() {
            return;
        }
        match r.hash_raw() {
            Ok(hash) => out.push(RetainedLeaf {
                seq: r.record.seq,
                ts_ms: r.record.ts_ms,
                hash,
            }),
            Err(e) => bad = Some(e),
        }
    })?;
    match bad {
        Some(e) => Err(e),
        None => Ok(RetainedLeaves {
            leaves: out,
            pruned_through_ms: walked.checkpoint.map(|cp| cp.ts_ms),
        }),
    }
}

/// `(seq, day, record hash)` for every retained record, after verifying the chain.
fn verified_leaves(dir: &Path) -> Result<Vec<(u64, u64, [u8; 32])>> {
    Ok(retained_leaves(dir)?
        .leaves
        .into_iter()
        .map(|l| (l.seq, utc_day(l.ts_ms), l.hash))
        .collect())
}

/// The Merkle root of every retained record whose timestamp falls on UTC day `day`. `None` when
/// the day has no records. Verifies the chain first and refuses a broken one.
pub fn daily_root(dir: &Path, day: u64) -> Result<Option<DailyRoot>> {
    let day_leaves: Vec<(u64, u64, [u8; 32])> = verified_leaves(dir)?
        .into_iter()
        .filter(|(_, d, _)| *d == day)
        .collect();
    let (Some(first), Some(last)) = (day_leaves.first(), day_leaves.last()) else {
        return Ok(None);
    };
    let hashes: Vec<[u8; 32]> = day_leaves.iter().map(|(_, _, h)| *h).collect();
    let Some(root) = merkle_root(&hashes) else {
        return Ok(None);
    };
    Ok(Some(DailyRoot {
        day,
        first_seq: first.0,
        last_seq: last.0,
        count: hashes.len() as u64,
        root: hex::encode(root),
    }))
}

/// An inclusion proof for record `seq` in its day's tree. `None` when `seq` is not retained.
pub fn inclusion_proof(dir: &Path, seq: u64) -> Result<Option<InclusionProof>> {
    let all = verified_leaves(dir)?;
    let Some(&(_, day, leaf)) = all.iter().find(|(s, _, _)| *s == seq) else {
        return Ok(None);
    };
    let day_leaves: Vec<(u64, [u8; 32])> = all
        .iter()
        .filter(|(_, d, _)| *d == day)
        .map(|(s, _, h)| (*s, *h))
        .collect();
    let hashes: Vec<[u8; 32]> = day_leaves.iter().map(|(_, h)| *h).collect();
    let Some(index) = day_leaves.iter().position(|(s, _)| *s == seq) else {
        return Ok(None);
    };
    let Some(root) = merkle_root(&hashes) else {
        return Ok(None);
    };
    Ok(Some(InclusionProof {
        day,
        seq,
        leaf_index: index as u64,
        tree_size: hashes.len() as u64,
        leaf: hex::encode(leaf),
        path: audit_path(&hashes, index).iter().map(hex::encode).collect(),
        root: hex::encode(root),
    }))
}
