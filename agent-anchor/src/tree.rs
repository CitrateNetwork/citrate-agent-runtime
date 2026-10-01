//! The batch's Merkle tree, with every level kept so all proofs are cheap.
//!
//! The tree is RFC 6962 / RFC 9162, the same tree as `citrate_agent_records::merkle` (and its
//! hash functions are used directly, so there is one definition of the hashing):
//!
//! - leaf: `SHA-256(0x00 || record_hash)`
//! - node: `SHA-256(0x01 || left || right)`
//!
//! The 0x00 / 0x01 prefixes keep a leaf from ever being read as a node (second-preimage
//! separation). For a size that is not a power of two, RFC 6962 splits at the largest power of
//! two below the size; built level by level, that is the same as pairing adjacent nodes and
//! carrying an unpaired last node up unchanged. The last node is never duplicated, so the tree of
//! `[a, b, c]` differs from the tree of `[a, b, c, c]`.
//!
//! Building keeps every level (2n hashes of memory), so each proof is O(log n) instead of the
//! O(n) recomputation of `citrate_agent_records::merkle::audit_path`.

use citrate_agent_records::merkle::{leaf_hash, node_hash};

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Tree {
    /// `levels[0]` are the leaf hashes; the last level has one node, the root.
    levels: Vec<Vec<[u8; 32]>>,
}

impl Tree {
    /// Build the tree over `leaf_data` (record hashes, in order). `None` for no leaves.
    pub fn build(leaf_data: &[[u8; 32]]) -> Option<Tree> {
        if leaf_data.is_empty() {
            return None;
        }
        let mut levels: Vec<Vec<[u8; 32]>> = vec![leaf_data.iter().map(leaf_hash).collect()];
        while let Some(top) = levels.last() {
            if top.len() <= 1 {
                break;
            }
            let next: Vec<[u8; 32]> = top
                .chunks(2)
                .map(|pair| match pair {
                    [l, r] => node_hash(l, r),
                    // An unpaired last node is promoted (chunks are never empty).
                    _ => pair[0],
                })
                .collect();
            levels.push(next);
        }
        Some(Tree { levels })
    }

    /// Number of leaves.
    pub fn size(&self) -> u64 {
        self.levels.first().map_or(0, |l| l.len() as u64)
    }

    /// The root (the RFC 6962 Merkle tree hash).
    pub fn root(&self) -> [u8; 32] {
        self.levels
            .last()
            .and_then(|l| l.first())
            .copied()
            .unwrap_or([0u8; 32])
    }

    /// The audit path for leaf `index`, leaf to root, in the RFC 9162 §2.1.3.1 form (promoted
    /// nodes contribute no sibling). `None` when `index` is out of range.
    pub fn path(&self, index: usize) -> Option<Vec<[u8; 32]>> {
        if index >= self.levels.first()?.len() {
            return None;
        }
        let mut out = Vec::new();
        let mut i = index;
        for level in &self.levels[..self.levels.len() - 1] {
            let sib = i ^ 1;
            if sib < level.len() {
                out.push(level[sib]);
            }
            i /= 2;
        }
        Some(out)
    }
}
