//! AnchorRegistry Rust adapter — RFC-CIT-AGENT-0001 §6.3 + planset
//! `06_ON_CHAIN_SURFACE.md` "AnchorRegistry".
//!
//! Commits audit-chain roots to the cit-agent `AnchorRegistry`
//! contract (CIT-AGENT-6a). Mirrors the BFR-INT-12b
//! `RecorderClient` shape: ABI-encode → sign via
//! `TransactionBuilder` → submit via `RpcClient`.
//!
//! The Solidity `AnchorKind` enum (PerCapsule=0, PerApproval=1,
//! NightlyMerkle=2) maps directly to `audit::record::AnchorKind` —
//! the cross-layer enum alignment from CIT-AGENT-6a's REPORT.

use crate::audit::record::AnchorKind;
use crate::error::AgentError;
use citrate_wallet_core::chain::{RpcClient, TransactionBuilder};
use k256::ecdsa::SigningKey;
use sha3::{Digest, Keccak256};

/// 4-byte function selectors for the AnchorRegistry methods we
/// consume. Computed at first call via `keccak256(signature)[..4]`.
fn anchor_selector() -> [u8; 4] {
    let mut h = Keccak256::new();
    h.update(b"anchor(uint8,bytes32)");
    let digest = h.finalize();
    let mut out = [0u8; 4];
    out.copy_from_slice(&digest[..4]);
    out
}

fn is_anchored_selector() -> [u8; 4] {
    let mut h = Keccak256::new();
    h.update(b"isAnchored(bytes32)");
    let digest = h.finalize();
    let mut out = [0u8; 4];
    out.copy_from_slice(&digest[..4]);
    out
}

/// Solidity ABI encoding of the AnchorKind enum (uint8 in the
/// contract). The Solidity enum order MUST match this — verified
/// by the cross-layer alignment test in CIT-AGENT-6a.
fn anchor_kind_byte(kind: AnchorKind) -> u8 {
    match kind {
        AnchorKind::PerCapsule => 0,
        AnchorKind::PerApproval => 1,
        AnchorKind::NightlyMerkle => 2,
    }
}

/// Encode `AnchorRegistry.anchor(AnchorKind kind, bytes32 root)`.
/// Returns the 4-byte selector + 64-byte argument tail (uint8
/// right-padded to 32 bytes + bytes32 root).
pub fn encode_anchor(kind: AnchorKind, root: [u8; 32]) -> Vec<u8> {
    let mut out = Vec::with_capacity(4 + 64);
    out.extend_from_slice(&anchor_selector());
    // uint8 args are encoded as 32-byte big-endian words with the
    // value in the rightmost byte.
    let mut kind_word = [0u8; 32];
    kind_word[31] = anchor_kind_byte(kind);
    out.extend_from_slice(&kind_word);
    out.extend_from_slice(&root);
    out
}

/// Encode `AnchorRegistry.isAnchored(bytes32 root)`.
pub fn encode_is_anchored(root: [u8; 32]) -> Vec<u8> {
    let mut out = Vec::with_capacity(4 + 32);
    out.extend_from_slice(&is_anchored_selector());
    out.extend_from_slice(&root);
    out
}

/// Adapter for the cit-agent `AnchorRegistry` contract. Holds the
/// signing key (used by `anchor` writes), the RPC URL, and the
/// contract address. `is_anchored` reads work without a key.
pub struct AnchorRegistryClient {
    signing_key: SigningKey,
    from_address_hex: String,
    rpc_url: String,
    chain_id: u64,
    contract_address: String,
}

impl AnchorRegistryClient {
    /// Build from a hex-encoded private key + RPC URL + the
    /// deployed AnchorRegistry contract address.
    ///
    /// `chain_id` is 40204 (the cit-agent testnet beta). Future
    /// chains pass their id at construction.
    pub fn from_hex_key(
        hex_key: &str,
        rpc_url: impl Into<String>,
        contract_address: impl Into<String>,
        chain_id: u64,
    ) -> Option<Self> {
        let stripped = hex_key.trim().trim_start_matches("0x");
        let bytes = hex::decode(stripped).ok()?;
        if bytes.len() != 32 {
            tracing::warn!("AnchorRegistryClient key must be 32 bytes; got {}", bytes.len());
            return None;
        }
        let mut arr = [0u8; 32];
        arr.copy_from_slice(&bytes);
        let signing_key = SigningKey::from_bytes(&arr.into()).ok()?;
        let from_address_hex = crate::audit::recorder::derive_address(&signing_key);
        Some(Self {
            signing_key,
            from_address_hex,
            rpc_url: rpc_url.into(),
            chain_id,
            contract_address: contract_address.into(),
        })
    }

    /// Sender address (from `signer_key` ECDSA public key derivation).
    pub fn from_address(&self) -> &str {
        &self.from_address_hex
    }

    /// Submit an `anchor(kind, root)` transaction. Returns the tx
    /// hash on success. Caller is responsible for waiting for
    /// confirmation if needed (the audit chain doesn't require
    /// strict ordering with the off-chain log — the on-chain commit
    /// is a privacy-preserving witness).
    pub async fn anchor(
        &self,
        kind: AnchorKind,
        root: [u8; 32],
    ) -> Result<String, AgentError> {
        let calldata = encode_anchor(kind, root);
        let rpc = RpcClient::new(&self.rpc_url);
        let nonce = rpc
            .get_nonce(&self.from_address_hex)
            .await
            .map_err(|e| AgentError::Chain(format!("nonce read: {e}")))?;
        let signed = TransactionBuilder::new()
            .to(&self.contract_address)
            .data(calldata)
            .nonce(nonce)
            .gas_limit(200_000)
            .chain_id(self.chain_id)
            .sign_secp256k1(&self.signing_key, nonce)
            .map_err(|e| AgentError::Chain(format!("sign: {e}")))?;
        rpc.send_raw_transaction(&signed.raw)
            .await
            .map_err(|e| AgentError::Chain(format!("send_raw_transaction: {e}")))
    }

    /// `isAnchored(root)` eth_call. Returns `Ok(true)` if the
    /// AnchorRegistry has a record for `root`; `Ok(false)` otherwise.
    pub async fn is_anchored(&self, root: [u8; 32]) -> Result<bool, AgentError> {
        let calldata = encode_is_anchored(root);
        let rpc = RpcClient::new(&self.rpc_url);
        let result = rpc
            .eth_call(&self.contract_address, &calldata)
            .await
            .map_err(|e| AgentError::Chain(format!("eth_call: {e}")))?;
        // Solidity bool encodes as a 32-byte word; the last byte is 1 or 0.
        if result.is_empty() {
            return Err(AgentError::Chain(
                "isAnchored returned empty data — contract may be unset".to_string(),
            ));
        }
        Ok(*result.last().unwrap() == 1)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn anchor_selector_matches_keccak() {
        // Sanity: the selector is the first 4 bytes of
        // keccak256("anchor(uint8,bytes32)"). We compute it the
        // same way the helper does and compare.
        let mut h = Keccak256::new();
        h.update(b"anchor(uint8,bytes32)");
        let digest = h.finalize();
        let mut expected = [0u8; 4];
        expected.copy_from_slice(&digest[..4]);
        assert_eq!(anchor_selector(), expected);
        // Not all zeros.
        assert_ne!(anchor_selector(), [0u8; 4]);
    }

    #[test]
    fn is_anchored_selector_matches_keccak() {
        let mut h = Keccak256::new();
        h.update(b"isAnchored(bytes32)");
        let digest = h.finalize();
        let mut expected = [0u8; 4];
        expected.copy_from_slice(&digest[..4]);
        assert_eq!(is_anchored_selector(), expected);
    }

    #[test]
    fn encode_anchor_layout() {
        let root = [0xab; 32];
        let calldata = encode_anchor(AnchorKind::PerCapsule, root);
        // 4 selector + 32 kind word + 32 root word.
        assert_eq!(calldata.len(), 68);
        assert_eq!(&calldata[..4], &anchor_selector());
        // Kind word is 32 bytes of zero with last byte = kind.
        for &b in &calldata[4..35] {
            assert_eq!(b, 0);
        }
        assert_eq!(calldata[35], 0); // PerCapsule
        // Root follows.
        assert_eq!(&calldata[36..68], &root);
    }

    #[test]
    fn encode_anchor_kind_mapping() {
        let root = [0u8; 32];
        let cd_per_capsule = encode_anchor(AnchorKind::PerCapsule, root);
        assert_eq!(cd_per_capsule[35], 0);
        let cd_per_approval = encode_anchor(AnchorKind::PerApproval, root);
        assert_eq!(cd_per_approval[35], 1);
        let cd_nightly = encode_anchor(AnchorKind::NightlyMerkle, root);
        assert_eq!(cd_nightly[35], 2);
    }

    #[test]
    fn encode_is_anchored_layout() {
        let root = [0xcd; 32];
        let calldata = encode_is_anchored(root);
        assert_eq!(calldata.len(), 36);
        assert_eq!(&calldata[..4], &is_anchored_selector());
        assert_eq!(&calldata[4..], &root);
    }

    #[test]
    fn from_hex_key_round_trip_with_known_address() {
        // Same fixture used in recorder.rs::tests — the deployer
        // key from .env.testnet. Confirms `derive_address` is
        // wired correctly via the recorder module's helper.
        let hex = "0x1feffc85883856c384f497cf057d38da863eb9b89c545e72fbfd35631eaf4a58";
        let client = AnchorRegistryClient::from_hex_key(
            hex,
            "http://localhost:8545",
            "0x0000000000000000000000000000000000000000",
            40204,
        )
        .expect("valid key");
        assert_eq!(
            client.from_address().to_lowercase(),
            "0x4250675f9015e65fc866f3a373f82bb9dfc000c6"
        );
    }

    #[test]
    fn from_hex_key_rejects_wrong_length() {
        let url = "http://localhost:8545";
        let contract = "0x0000000000000000000000000000000000000000".to_string();
        assert!(AnchorRegistryClient::from_hex_key("0x1234", url, contract.clone(), 40204).is_none());
        assert!(AnchorRegistryClient::from_hex_key("", url, contract.clone(), 40204).is_none());
        assert!(AnchorRegistryClient::from_hex_key("not-hex", url, contract, 40204).is_none());
    }
}
