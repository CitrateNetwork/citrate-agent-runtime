//! Calldata for `AnchorRegistry` (citrate-chain `contracts/src/cit_agent/AnchorRegistry.sol`).
//!
//! ```solidity
//! enum AnchorKind { PerCapsule, PerApproval, NightlyMerkle }
//! function anchor(AnchorKind kind, bytes32 root) external;     // anchor(uint8,bytes32)
//! function isAnchored(bytes32 root) external view returns (bool);
//! ```
//!
//! A Solidity enum is `uint8` in the ABI signature and a left-padded 32-byte word in calldata.
//! The selectors below are pinned in tests against keccak-256 of the signature and against
//! `forge inspect AnchorRegistry methodIdentifiers` (forge 1.5.1, source sha256
//! `deabbc4cd5ecb6a4fddc950392540e9be6bc7b358aefdf2a8c55196e47c585f8` at citrate-chain `0aab474b`).
//!
//! This module builds bytes only. It never signs and never sends: under the accepted Rule-3 ADR
//! (ADR-2026-09-30-rule3-budgetable-signatures) the nightly anchor is signed by a separate
//! no-funds anchor key that lives in citrate-core's signature ceremony, which is a later core WP.

use serde::{Deserialize, Serialize};

use crate::error::{Error, Result};

/// The `AnchorRegistry.anchor` signature as it appears in the ABI.
pub const ANCHOR_SIGNATURE: &str = "anchor(uint8,bytes32)";
/// `keccak256("anchor(uint8,bytes32)")[..4]`.
pub const ANCHOR_SELECTOR: [u8; 4] = [0x9e, 0x62, 0x1f, 0x4c];
/// `keccak256("isAnchored(bytes32)")[..4]`, for a read-only `eth_call` check.
pub const IS_ANCHORED_SELECTOR: [u8; 4] = [0x4f, 0x0b, 0x58, 0x01];
/// Citrate mainnet / testnet chain id.
pub const CITRATE_CHAIN_ID: u64 = 40204;

/// `AnchorRegistry.AnchorKind`, in declaration order.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
#[repr(u8)]
pub enum AnchorKind {
    PerCapsule = 0,
    PerApproval = 1,
    NightlyMerkle = 2,
}

impl AnchorKind {
    pub fn from_u8(v: u8) -> Option<Self> {
        match v {
            0 => Some(Self::PerCapsule),
            1 => Some(Self::PerApproval),
            2 => Some(Self::NightlyMerkle),
            _ => None,
        }
    }
}

/// `anchor(kind, root)` calldata: selector, the kind as a uint8 word, the root (68 bytes).
pub fn anchor_calldata(kind: AnchorKind, root: &[u8; 32]) -> Vec<u8> {
    let mut out = Vec::with_capacity(68);
    out.extend_from_slice(&ANCHOR_SELECTOR);
    let mut word = [0u8; 32];
    word[31] = kind as u8;
    out.extend_from_slice(&word);
    out.extend_from_slice(root);
    out
}

/// `isAnchored(root)` calldata (36 bytes), for an `eth_call`.
pub fn is_anchored_calldata(root: &[u8; 32]) -> Vec<u8> {
    let mut out = Vec::with_capacity(36);
    out.extend_from_slice(&IS_ANCHORED_SELECTOR);
    out.extend_from_slice(root);
    out
}

/// Decode `anchor(kind, root)` calldata strictly (exact length, selector, a clean uint8 word in
/// enum range), so an approval card can show what a payload does.
pub fn decode_anchor_calldata(data: &[u8]) -> Result<(AnchorKind, [u8; 32])> {
    if data.len() != 68 {
        return Err(Error::BadCalldata(format!(
            "expected 68 bytes, got {}",
            data.len()
        )));
    }
    if data[..4] != ANCHOR_SELECTOR {
        return Err(Error::BadCalldata(
            "not an anchor(uint8,bytes32) call".into(),
        ));
    }
    let word = &data[4..36];
    if word[..31].iter().any(|b| *b != 0) {
        return Err(Error::BadCalldata("kind is not a uint8 word".into()));
    }
    let kind = AnchorKind::from_u8(word[31])
        .ok_or_else(|| Error::BadCalldata(format!("unknown anchor kind {}", word[31])))?;
    let mut root = [0u8; 32];
    root.copy_from_slice(&data[36..68]);
    Ok((kind, root))
}

/// An unsigned call for the core ceremony to review, sign with the anchor key, and send. Nothing
/// in this crate signs or sends it.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct UnsignedAnchorCall {
    pub chain_id: u64,
    /// The `AnchorRegistry` address, when the caller supplied one. The address comes from the
    /// deployed-address book that core reads; this crate does not hard-code it.
    pub to: Option<String>,
    /// Always 0: anchoring moves no value.
    pub value: u64,
    pub kind: AnchorKind,
    /// The anchored value (the day commitment).
    #[serde(with = "crate::hex32")]
    pub root: [u8; 32],
    #[serde(with = "hex_bytes")]
    pub data: Vec<u8>,
}

impl UnsignedAnchorCall {
    pub fn nightly(root: [u8; 32], to: Option<&str>) -> Self {
        Self {
            chain_id: CITRATE_CHAIN_ID,
            to: to.map(str::to_owned),
            value: 0,
            kind: AnchorKind::NightlyMerkle,
            root,
            data: anchor_calldata(AnchorKind::NightlyMerkle, &root),
        }
    }
}

mod hex_bytes {
    use serde::{Deserialize, Deserializer, Serializer};

    pub(crate) fn serialize<S: Serializer>(v: &[u8], s: S) -> Result<S::Ok, S::Error> {
        s.serialize_str(&format!("0x{}", hex::encode(v)))
    }

    pub(crate) fn deserialize<'de, D: Deserializer<'de>>(d: D) -> Result<Vec<u8>, D::Error> {
        let s = String::deserialize(d)?;
        hex::decode(s.strip_prefix("0x").unwrap_or(&s)).map_err(serde::de::Error::custom)
    }
}
