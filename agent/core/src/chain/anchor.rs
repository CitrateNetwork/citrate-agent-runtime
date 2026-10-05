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
//!
//! Confirming an anchor (HUP-S7.1): `isAnchored(root)` is true once *anyone* anchored `root`, so
//! it never confirms this client's own anchor. [`AnchorRegistryClient::is_anchored_by_self`] asks
//! for this key's record: `isAnchoredBy(self, root)` on the next registry version, and the first
//! committer (`getAnchor(root)`) on the deployed version, which has no per-committer record. The
//! read sequence is `citrate_agent_anchor::OwnAnchorCheck`.

use crate::audit::record::AnchorKind;
use crate::error::AgentError;
use citrate_agent_anchor::{decode_bool, CheckStep, OwnAnchorCheck, RegistryAnswer};
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

/// Gas limit of an `anchor` transaction. The next registry version (HUP-S7.1 redeploy) writes a
/// per-committer record as well as the first record of a root, about 335,000 gas for a new root
/// (citrate-core's estimate); 200,000 ran the next version out of gas in
/// `tests/anchor_registry_versions.rs`. Same ceiling as citrate-core's anchor ceremony (`PLACEHOLDER_MAX_GAS_LIMIT`).
pub const ANCHOR_GAS_LIMIT: u64 = 400_000;

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
            tracing::warn!(
                "AnchorRegistryClient key must be 32 bytes; got {}",
                bytes.len()
            );
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
    pub async fn anchor(&self, kind: AnchorKind, root: [u8; 32]) -> Result<String, AgentError> {
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
            .gas_limit(ANCHOR_GAS_LIMIT)
            .chain_id(self.chain_id)
            .sign_secp256k1(&self.signing_key, nonce)
            .map_err(|e| AgentError::Chain(format!("sign: {e}")))?;
        rpc.send_raw_transaction(&signed.raw)
            .await
            .map_err(|e| AgentError::Chain(format!("send_raw_transaction: {e}")))
    }

    /// `isAnchored(root)` eth_call: `Ok(true)` once ANY committer has anchored `root`. This is
    /// not a confirmation of this client's anchor (a stranger can send the same value); use
    /// [`Self::is_anchored_by_self`] for that.
    pub async fn is_anchored(&self, root: [u8; 32]) -> Result<bool, AgentError> {
        let calldata = encode_is_anchored(root);
        let rpc = RpcClient::new(&self.rpc_url);
        let result = rpc
            .eth_call(&self.contract_address, &calldata)
            .await
            .map_err(|e| AgentError::Chain(format!("eth_call: {e}")))?;
        decode_bool(&result)
            .map_err(|e| AgentError::Chain(format!("isAnchored: {e} (is the contract set?)")))
    }

    /// Did this client's own key anchor `root`? See the module docs: `isAnchoredBy(self, root)` on
    /// the next registry version, the first committer on the deployed one.
    pub async fn is_anchored_by_self(&self, root: [u8; 32]) -> Result<bool, AgentError> {
        let me = self.from_address_hex.clone();
        self.is_anchored_by(&me, root).await
    }

    /// Did `committer` (a `0x` address) anchor `root`? Read-only `eth_call`s; never signs.
    pub async fn is_anchored_by(
        &self,
        committer: &str,
        root: [u8; 32],
    ) -> Result<bool, AgentError> {
        let who = parse_address(committer)?;
        let rpc = RpcClient::new(&self.rpc_url);
        let (mut check, mut step) = OwnAnchorCheck::new(who, root);
        // At most three reads (isAnchored, isAnchoredBy, getAnchor); the bound is defensive.
        for _ in 0..4 {
            let data = match step {
                CheckStep::Done(v) => return Ok(v),
                CheckStep::Call(data) => data,
            };
            let answer = match rpc.eth_call(&self.contract_address, &data).await {
                Ok(bytes) => RegistryAnswer::Returned(bytes),
                Err(e) if is_revert(&e.to_string()) => RegistryAnswer::Reverted,
                Err(e) => return Err(AgentError::Chain(format!("eth_call: {e}"))),
            };
            step = check
                .answer(answer)
                .map_err(|e| AgentError::Chain(format!("AnchorRegistry: {e}")))?;
        }
        Err(AgentError::Chain(
            "AnchorRegistry: the own-anchor check did not finish".to_string(),
        ))
    }
}

/// A `0x` + 40-hex address as 20 bytes.
fn parse_address(s: &str) -> Result<[u8; 20], AgentError> {
    let h = s
        .strip_prefix("0x")
        .filter(|h| h.len() == 40)
        .ok_or_else(|| AgentError::Chain(format!("not a 0x address: {s:?}")))?;
    let mut out = [0u8; 20];
    hex::decode_to_slice(h, &mut out)
        .map_err(|_| AgentError::Chain(format!("not a 0x address: {s:?}")))?;
    Ok(out)
}

/// Whether an `eth_call` error is the call reverting (anvil and geth: "execution reverted"; the
/// Citrate node: "... Contract call reverted: 0x...") rather than a transport failure.
fn is_revert(msg: &str) -> bool {
    msg.to_ascii_lowercase().contains("revert")
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

    // ─── HUP-S7.1: own-anchor confirmation against both registry versions ───
    //
    // A JSON-RPC stand-in that answers eth_call the way each AnchorRegistry version does (the
    // anvil test `tests/anchor_registry_versions.rs` runs the real contracts).

    struct Registry {
        /// `true`: the next version (isAnchoredBy exists, one record per committer).
        next: bool,
        /// (committer, root) in anchoring order.
        anchors: Vec<([u8; 20], [u8; 32])>,
        /// Answer every call with a transport-level error instead.
        down: bool,
    }

    impl wiremock::Respond for Registry {
        fn respond(&self, req: &wiremock::Request) -> wiremock::ResponseTemplate {
            let body: serde_json::Value = serde_json::from_slice(&req.body).unwrap_or_default();
            let id = body["id"].clone();
            let ok = |hex_out: String| {
                wiremock::ResponseTemplate::new(200).set_body_json(
                    serde_json::json!({"jsonrpc": "2.0", "id": id, "result": hex_out}),
                )
            };
            let revert = || {
                wiremock::ResponseTemplate::new(200).set_body_json(serde_json::json!({
                    "jsonrpc": "2.0", "id": body["id"].clone(),
                    "error": {"code": 3, "message": "execution reverted"}
                }))
            };
            if self.down {
                return wiremock::ResponseTemplate::new(200).set_body_json(serde_json::json!({
                    "jsonrpc": "2.0", "id": body["id"].clone(),
                    "error": {"code": -32000, "message": "upstream unavailable"}
                }));
            }
            let data = body["params"][0]["data"].as_str().unwrap_or("0x");
            let data = hex::decode(data.trim_start_matches("0x")).unwrap_or_default();
            let sel = &data[..4.min(data.len())];
            let word = |b: bool| format!("0x{}{:02x}", "00".repeat(31), u8::from(b));
            let root_at = |i: usize| -> [u8; 32] {
                let mut r = [0u8; 32];
                r.copy_from_slice(&data[i..i + 32]);
                r
            };
            if sel == is_anchored_selector() {
                let root = root_at(4);
                return ok(word(self.anchors.iter().any(|(_, r)| *r == root)));
            }
            if sel == citrate_agent_anchor::IS_ANCHORED_BY_SELECTOR {
                if !self.next {
                    return revert();
                }
                let mut who = [0u8; 20];
                who.copy_from_slice(&data[16..36]);
                let root = root_at(36);
                return ok(word(self.anchors.contains(&(who, root))));
            }
            if sel == citrate_agent_anchor::GET_ANCHOR_SELECTOR {
                let root = root_at(4);
                return match self.anchors.iter().find(|(_, r)| *r == root) {
                    None => revert(),
                    Some((who, _)) => {
                        let mut out = vec![0u8; 160];
                        out[31] = 2;
                        out[32..64].copy_from_slice(&root);
                        out[76..96].copy_from_slice(who);
                        out[127] = 5;
                        ok(format!("0x{}", hex::encode(out)))
                    }
                };
            }
            revert()
        }
    }

    fn derived_client(label: &str, rpc: &str) -> AnchorRegistryClient {
        // A throwaway key derived at run time (no key material in the source).
        let key = hex::encode(Keccak256::digest(label.as_bytes()));
        AnchorRegistryClient::from_hex_key(&key, rpc, format!("0x{}", "a1".repeat(20)), 31337)
            .unwrap_or_else(|| panic!("derived key {label} is not a valid scalar"))
    }

    fn addr20(client: &AnchorRegistryClient) -> [u8; 20] {
        parse_address(client.from_address()).unwrap_or_else(|e| panic!("{e}"))
    }

    async fn serve(
        next: bool,
        anchors: Vec<([u8; 20], [u8; 32])>,
        down: bool,
    ) -> wiremock::MockServer {
        let server = wiremock::MockServer::start().await;
        wiremock::Mock::given(wiremock::matchers::method("POST"))
            .respond_with(Registry {
                next,
                anchors,
                down,
            })
            .mount(&server)
            .await;
        server
    }

    #[tokio::test]
    async fn own_anchor_on_both_registry_versions() {
        let root = [0x42u8; 32];
        let other_root = [0x43u8; 32];
        for next in [false, true] {
            let probe = derived_client("anchor-test-me", "http://127.0.0.1:1");
            let stranger = derived_client("anchor-test-stranger", "http://127.0.0.1:1");
            let (me, them) = (addr20(&probe), addr20(&stranger));
            // The stranger anchored `root` first; on the next version I anchored it too.
            let mut anchors = vec![(them, root)];
            if next {
                anchors.push((me, root));
            }
            let server = serve(next, anchors, false).await;
            let mine = derived_client("anchor-test-me", &server.uri());
            let theirs = derived_client("anchor-test-stranger", &server.uri());
            // isAnchored is true for both clients: someone anchored it.
            assert!(mine.is_anchored(root).await.unwrap_or(false));
            // The stranger's own anchor is confirmed on both versions.
            assert!(
                theirs.is_anchored_by_self(root).await.unwrap_or(false),
                "next={next}"
            );
            // Mine: only the next version keeps a record per committer. On the deployed version
            // my identical anchor reverted, so it is (truthfully) not mine.
            assert_eq!(
                mine.is_anchored_by_self(root).await.ok(),
                Some(next),
                "next={next}"
            );
            // A value nobody anchored.
            assert_eq!(mine.is_anchored_by_self(other_root).await.ok(), Some(false));
        }
    }

    #[tokio::test]
    async fn own_anchor_never_true_on_a_transport_error() {
        let server = serve(true, vec![], true).await;
        let c = derived_client("anchor-test-me", &server.uri());
        assert!(c.is_anchored_by_self([1u8; 32]).await.is_err());
        assert!(c.is_anchored([1u8; 32]).await.is_err());
    }

    #[test]
    fn parse_address_is_strict() {
        assert!(parse_address("0x1234").is_err());
        assert!(parse_address(&"a".repeat(42)).is_err());
        assert!(parse_address(&format!("0x{}", "zz".repeat(20))).is_err());
        assert_eq!(
            parse_address(&format!("0x{}", "Ab".repeat(20))).ok(),
            Some([0xab; 20])
        );
        assert!(is_revert("execution reverted"));
        assert!(is_revert(
            "Contract call reverted: 0x46716752 (gas used: 1)"
        ));
        assert!(!is_revert("Request failed: connection refused"));
    }

    #[test]
    fn from_hex_key_rejects_wrong_length() {
        let url = "http://localhost:8545";
        let contract = "0x0000000000000000000000000000000000000000".to_string();
        assert!(
            AnchorRegistryClient::from_hex_key("0x1234", url, contract.clone(), 40204).is_none()
        );
        assert!(AnchorRegistryClient::from_hex_key("", url, contract.clone(), 40204).is_none());
        assert!(AnchorRegistryClient::from_hex_key("not-hex", url, contract, 40204).is_none());
    }
}
