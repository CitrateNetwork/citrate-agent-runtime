//! SkillRegistry calldata (build only).
//!
//! The deployed contract is citrate-chain `contracts/src/SkillRegistry.sol` (chain 40204):
//!
//! ```solidity
//! function registerSkill(string name, string version, string manifestCID,
//!                        string description, string[] tags) returns (bytes32 skillHash);
//! // skillHash = keccak256(abi.encodePacked(msg.sender, name, version))
//! ```
//!
//! This module ABI-encodes that call and projects the `skillHash` the contract will assign. It
//! never signs, never sends, and holds no key (Rule 3): the member signs the transaction through
//! citrate-core's SignatureCeremony. The encoding is pinned against `cast calldata` output in
//! `tests/fixtures/register_skill_cast.json`.
//!
//! The contract stores no content hash, so the learner carries the SKILL.md SHA-256 as a
//! `sha256:<hex>` tag (see [`crate::Learner::prepare_publish`]). Names on the registry are not
//! unique or authoritative: readers resolve a skill by `skillHash` against an owner they trust.

use sha3::{Digest, Keccak256};

/// The canonical signature of the registry write this module encodes.
pub const REGISTER_SKILL_SIGNATURE: &str = "registerSkill(string,string,string,string,string[])";
/// Longest accepted tag, in bytes.
pub const MAX_TAG_LEN: usize = 80;
/// Longest accepted manifest CID, in bytes.
pub const MAX_CID_LEN: usize = 128;

/// The 4-byte function selector of [`REGISTER_SKILL_SIGNATURE`].
pub fn register_skill_selector() -> [u8; 4] {
    let h = Keccak256::digest(REGISTER_SKILL_SIGNATURE.as_bytes());
    [h[0], h[1], h[2], h[3]]
}

fn word_usize(n: usize) -> [u8; 32] {
    let mut w = [0u8; 32];
    w[24..].copy_from_slice(&(n as u64).to_be_bytes());
    w
}

/// ABI tail of a dynamic `string`: length word, then the bytes right-padded to 32.
fn encode_string(s: &str) -> Vec<u8> {
    let b = s.as_bytes();
    let mut out = Vec::with_capacity(32 + b.len().div_ceil(32) * 32);
    out.extend_from_slice(&word_usize(b.len()));
    out.extend_from_slice(b);
    let pad = (32 - b.len() % 32) % 32;
    out.extend(std::iter::repeat_n(0u8, pad));
    out
}

/// ABI tail of a `string[]`: length word, one offset per element (relative to the first offset
/// word), then each element's string tail.
fn encode_string_array(items: &[String]) -> Vec<u8> {
    let tails: Vec<Vec<u8>> = items.iter().map(|s| encode_string(s)).collect();
    let mut out = Vec::new();
    out.extend_from_slice(&word_usize(items.len()));
    let mut offset = 32 * items.len();
    for t in &tails {
        out.extend_from_slice(&word_usize(offset));
        offset += t.len();
    }
    for t in tails {
        out.extend_from_slice(&t);
    }
    out
}

/// Calldata for `registerSkill(name, version, manifestCID, description, tags)`.
pub fn encode_register_skill(
    name: &str,
    version: &str,
    manifest_cid: &str,
    description: &str,
    tags: &[String],
) -> Vec<u8> {
    let tails = [
        encode_string(name),
        encode_string(version),
        encode_string(manifest_cid),
        encode_string(description),
        encode_string_array(tags),
    ];
    let mut out = Vec::new();
    out.extend_from_slice(&register_skill_selector());
    let mut offset = 32 * tails.len();
    for t in &tails {
        out.extend_from_slice(&word_usize(offset));
        offset += t.len();
    }
    for t in &tails {
        out.extend_from_slice(t);
    }
    out
}

/// The id the contract assigns: `keccak256(abi.encodePacked(owner, name, version))`.
pub fn skill_hash(owner: &[u8; 20], name: &str, version: &str) -> [u8; 32] {
    let mut h = Keccak256::new();
    h.update(owner);
    h.update(name.as_bytes());
    h.update(version.as_bytes());
    h.finalize().into()
}

/// Parse a `0x`-prefixed 20-byte hex address (any case; no checksum enforcement).
pub fn parse_address(s: &str) -> Result<[u8; 20], String> {
    let hexpart = s
        .strip_prefix("0x")
        .or_else(|| s.strip_prefix("0X"))
        .ok_or_else(|| format!("address {s:?} must start with 0x"))?;
    if hexpart.len() != 40 {
        return Err(format!("address {s:?} must be 20 bytes (40 hex digits)"));
    }
    let mut out = [0u8; 20];
    hex::decode_to_slice(hexpart, &mut out).map_err(|_| format!("address {s:?} is not hex"))?;
    Ok(out)
}

/// `MAJOR.MINOR.PATCH`, digits only, no leading zeros (pre-release and build tags are refused).
pub fn valid_version(v: &str) -> bool {
    let parts: Vec<&str> = v.split('.').collect();
    parts.len() == 3
        && parts.iter().all(|p| {
            !p.is_empty()
                && p.len() <= 9
                && p.bytes().all(|b| b.is_ascii_digit())
                && !(p.len() > 1 && p.starts_with('0'))
        })
}

/// A tag: 1..=[`MAX_TAG_LEN`] bytes of `[a-z0-9-.:_]`.
pub fn valid_tag(t: &str) -> bool {
    !t.is_empty()
        && t.len() <= MAX_TAG_LEN
        && t.bytes().all(|b| {
            b.is_ascii_lowercase() || b.is_ascii_digit() || matches!(b, b'-' | b'.' | b':' | b'_')
        })
}

/// A bare CID (CIDv0 base58 or CIDv1 base32/base36): empty (pending pin) or
/// 1..=[`MAX_CID_LEN`] ASCII alphanumerics. URIs (`ipfs://`) are refused.
pub fn valid_manifest_cid(c: &str) -> bool {
    c.is_empty() || (c.len() <= MAX_CID_LEN && c.bytes().all(|b| b.is_ascii_alphanumeric()))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_string_tail_is_padded_to_a_word_boundary() {
        assert_eq!(encode_string("").len(), 32);
        assert_eq!(encode_string("a").len(), 64);
        assert_eq!(encode_string(&"a".repeat(32)).len(), 64);
        assert_eq!(encode_string(&"a".repeat(33)).len(), 96);
    }

    #[test]
    fn an_empty_array_is_just_its_length() {
        assert_eq!(encode_string_array(&[]), word_usize(0).to_vec());
    }
}
