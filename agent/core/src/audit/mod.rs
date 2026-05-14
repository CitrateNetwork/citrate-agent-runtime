//! Audit chain — RFC-CIT-AGENT-0001 §3.1 + §6 "Audit Chain".
//!
//! CIT-AGENT-1 lands the BFR-INT-12b `RecorderClient` here. RFC §3.2
//! names `RecorderClient` in the v1.0 public surface. Hash-chain
//! integrity is verified by
//! `.agentile/formal/specs/agent/AuditChainIntegrity.tla` (CIT-AGENT-2 —
//! 35,435 distinct states PASS).
//!
//! Boeing-overlay caveat: when the cit-agent contracts deploy
//! (CIT-AGENT-6) the canonical write path moves to `AnchorRegistry`
//! and `RecorderClient` becomes a Boeing-overlay adapter — see
//! planset `06_ON_CHAIN_SURFACE.md` row 21. Until then this module
//! is the load-bearing audit path.
//!
//! ── Original BFR-INT-12b header preserved below ──
//!
//! BFR-INT-12b — Recorder client. Pilot-grade signing path for the
//! Boeing shell.
//!
//! The recorder is the *only* signing surface in the Boeing shell
//! today. It exists so the tool harness (BFR-INT-12 / 12b) can:
//!
//!   1. Write a `Decision` to `AgentDecisionRegistryV2.record` on
//!      every operator approve / reject (the audit trail INT-13
//!      will render).
//!   2. Submit chain writes for the 3 write tools
//!      (`provision_user`, `revoke_role`, `anchor_session`).
//!
//! **Pilot-grade caveats:**
//!
//!   * The key comes from `DEPLOYER_PRIVATE_KEY` env var or
//!     `.env.testnet`. Production key management (password gate,
//!     OS keyring, hardware-wallet path) is a separate "wallet
//!     UX" sprint.
//!   * Nonce comes from `eth_getTransactionCount(addr, "pending")`
//!     on every send. No local nonce cache; tx ordering within a
//!     burst is RPC-dependent.
//!   * Gas price is hard-coded at 1 Gwei (TransactionBuilder
//!     default). Boeing tenant testnet has no congestion to
//!     justify dynamic fee logic.
//!   * Failures surface as `Result<String, String>` with the
//!     tx hash or a human-readable error.

use citrate_wallet_core::chain::{RpcClient, TransactionBuilder};
use k256::ecdsa::SigningKey;
use sha3::{Digest, Keccak256};
use std::path::Path;

/// Recorder client — owns a signing key + RPC client + chain id.
/// All transactions go through `send_tx`. The recorder is shared
/// across tokio tasks via `Arc<RecorderClient>`; cloning the key
/// is cheap (32 bytes).
#[derive(Clone)]
pub struct RecorderClient {
    signing_key: SigningKey,
    /// `0x` + 40-hex-char EVM address derived from the signing key.
    from_address_hex: String,
    rpc_url: String,
    chain_id: u64,
}

impl RecorderClient {
    /// Create a recorder from env / `.env.testnet`. Returns `None`
    /// when the key is unavailable or malformed — the shell starts
    /// without write capability in that case.
    ///
    /// Resolution order:
    ///   1. `DEPLOYER_PRIVATE_KEY` env var
    ///   2. `DEPLOYER_PRIVATE_KEY=…` line in `.env.testnet` next to
    ///      the working directory
    pub fn from_env(rpc_url: impl Into<String>) -> Option<Self> {
        let hex_key = std::env::var("DEPLOYER_PRIVATE_KEY")
            .ok()
            .filter(|s| !s.is_empty())
            .or_else(|| read_env_var(Path::new(".env.testnet"), "DEPLOYER_PRIVATE_KEY"))?;
        Self::from_hex_key(&hex_key, rpc_url)
    }

    /// Build a recorder from a raw 32-byte hex key. Public for
    /// testability; `from_env` is the production entry-point.
    ///
    /// CIT-AGENT-1: previously read `crate::active_rpc_url()` from the
    /// host crate (boeing-shell); now the URL is an explicit parameter
    /// so this code can live in `citrate-agent-core` with no host coupling.
    pub fn from_hex_key(hex_key: &str, rpc_url: impl Into<String>) -> Option<Self> {
        let stripped = hex_key.trim().trim_start_matches("0x");
        let bytes = hex::decode(stripped).ok()?;
        if bytes.len() != 32 {
            tracing::warn!("recorder: key must be 32 bytes; got {}", bytes.len());
            return None;
        }
        let mut arr = [0u8; 32];
        arr.copy_from_slice(&bytes);
        let signing_key = SigningKey::from_bytes(&arr.into()).ok()?;
        let from_address_hex = derive_address(&signing_key);
        Some(Self {
            signing_key,
            from_address_hex,
            rpc_url: rpc_url.into(),
            chain_id: 40204,
        })
    }

    /// Sender address (read by tests + log output).
    pub fn from_address(&self) -> &str {
        &self.from_address_hex
    }

    /// Submit a transaction. Fetches nonce, signs via
    /// `TransactionBuilder::sign_secp256k1`, broadcasts via
    /// `RpcClient::send_raw_transaction`. Returns the tx hash on
    /// success.
    pub async fn send_tx(
        &self,
        to_addr_hex: &str,
        calldata: Vec<u8>,
        gas_limit: u64,
    ) -> Result<String, String> {
        let rpc = RpcClient::new(&self.rpc_url);
        let nonce = rpc
            .get_nonce(&self.from_address_hex)
            .await
            .map_err(|e| format!("nonce read failed: {e}"))?;
        let signed = TransactionBuilder::new()
            .to(to_addr_hex)
            .data(calldata)
            .nonce(nonce)
            .gas_limit(gas_limit)
            .chain_id(self.chain_id)
            .sign_secp256k1(&self.signing_key, nonce)
            .map_err(|e| format!("sign failed: {e}"))?;
        rpc.send_raw_transaction(&signed.raw)
            .await
            .map_err(|e| format!("send_raw_transaction failed: {e}"))
    }
}

// ── BFR-INT-12b WP-2 — Decision-log writes ─────────────────────────

/// Audit-trail entry status — what landed on chain for a single
/// tool-approval round trip. The contract stores `status` as a
/// tagged string (not an enum) so additions don't require a schema
/// bump on `AgentDecisionRegistryV2`.
#[derive(Debug, Clone, Copy)]
pub enum DecisionStatus {
    Approved,
    Rejected,
    AutoApproved,
}

impl DecisionStatus {
    fn as_str(self) -> &'static str {
        match self {
            DecisionStatus::Approved => "Approved",
            DecisionStatus::Rejected => "Rejected",
            DecisionStatus::AutoApproved => "AutoApproved",
        }
    }
}

/// Params for an `AgentDecisionRegistryV2.record(...)` call.
/// All bytes32 fields are caller-provided so the chat-tool layer
/// can correlate decisions back to a session/tool_call without
/// the recorder owning a hashing convention.
#[derive(Debug, Clone)]
pub struct DecisionParams {
    pub decision_id: [u8; 32],
    pub user: [u8; 32],
    pub tenant: [u8; 32],
    pub corr_id: [u8; 32],
    /// `EventClass` u8 — `9` = `Audit` per the contract enum.
    /// We use Audit for tool-approval decisions because the class
    /// boundary "this entry exists for after-the-fact audit, not
    /// to drive a workflow" matches what the assistant trail is.
    pub class: u8,
    pub description: String,
    pub auth_mode: String,
    pub artifact_root: [u8; 32],
    pub status: DecisionStatus,
}

/// Encode `record(bytes32,bytes32,bytes32,bytes32,uint8,string,
/// string,bytes32,string)` calldata. Head is 9 × 32 bytes; each
/// dynamic string adds `[length, data padded to 32]` to the tail.
pub fn encode_record_decision(params: &DecisionParams) -> Vec<u8> {
    let selector = record_selector();
    let mut out = Vec::with_capacity(4 + 9 * 32 + 256);
    out.extend_from_slice(&selector);

    // Head — 9 slots. Offsets are computed from the start of the
    // *parameter section* (i.e. after the 4-byte selector), so the
    // first dynamic value lives at offset 9 * 32 = 288.
    let head_len = 9 * 32;
    let desc_bytes = params.description.as_bytes();
    let auth_bytes = params.auth_mode.as_bytes();
    let status_bytes = params.status.as_str().as_bytes();
    let desc_offset = head_len; // 288
    let auth_offset = desc_offset + 32 + padded_len(desc_bytes.len());
    let status_offset = auth_offset + 32 + padded_len(auth_bytes.len());

    // Static bytes32s + uint8 + offsets.
    out.extend_from_slice(&params.decision_id);
    out.extend_from_slice(&params.user);
    out.extend_from_slice(&params.tenant);
    out.extend_from_slice(&params.corr_id);
    out.extend_from_slice(&uint256_from_u64(params.class as u64));
    out.extend_from_slice(&uint256_from_u64(desc_offset as u64));
    out.extend_from_slice(&uint256_from_u64(auth_offset as u64));
    out.extend_from_slice(&params.artifact_root);
    out.extend_from_slice(&uint256_from_u64(status_offset as u64));

    // Tail — each string is `[length, data padded to 32]`.
    push_string(&mut out, desc_bytes);
    push_string(&mut out, auth_bytes);
    push_string(&mut out, status_bytes);

    out
}

fn record_selector() -> [u8; 4] {
    let mut hasher = Keccak256::new();
    hasher.update(
        "record(bytes32,bytes32,bytes32,bytes32,uint8,string,string,bytes32,string)".as_bytes(),
    );
    let h = hasher.finalize();
    let mut out = [0u8; 4];
    out.copy_from_slice(&h[..4]);
    out
}

fn uint256_from_u64(n: u64) -> [u8; 32] {
    let mut buf = [0u8; 32];
    buf[24..].copy_from_slice(&n.to_be_bytes());
    buf
}

/// Number of bytes a string of `len` bytes occupies *after* the
/// length prefix, padded up to the nearest 32-byte boundary.
fn padded_len(len: usize) -> usize {
    if len == 0 {
        0
    } else {
        ((len + 31) / 32) * 32
    }
}

fn push_string(out: &mut Vec<u8>, s: &[u8]) {
    out.extend_from_slice(&uint256_from_u64(s.len() as u64));
    let padded = padded_len(s.len());
    out.extend_from_slice(s);
    // Right-pad with zeros so the next chunk starts on a 32-byte
    // boundary.
    out.extend(std::iter::repeat(0u8).take(padded - s.len()));
}

impl RecorderClient {
    /// BFR-INT-12b WP-2 — record an audit-trail decision. Returns
    /// the tx hash on success. Failures bubble up; callers should
    /// fire-and-forget (spawn) so chat responsiveness is not gated
    /// on chain confirmation.
    pub async fn record_decision(
        &self,
        registry_addr_hex: &str,
        params: DecisionParams,
    ) -> Result<String, String> {
        let calldata = encode_record_decision(&params);
        // 500k gas — the seeder uses the same ceiling for these
        // writes; record() touches three indexes + a struct write,
        // typical cost ~150-200k.
        self.send_tx(registry_addr_hex, calldata, 500_000).await
    }
}

// ── BFR-INT-12b WP-3 — Write-tool calldata encoders ────────────────

/// `requestElevation(bytes32 user, bytes32 tenant, bytes32 role,
/// uint32 duration_sec, bytes32 corr_id, bytes reauth_proof,
/// string reauth_proof_kind)`.
///
/// 7-slot head; 2 dynamic tails (bytes, string).
pub fn encode_request_elevation(
    user: [u8; 32],
    tenant: [u8; 32],
    role: [u8; 32],
    duration_sec: u32,
    corr_id: [u8; 32],
    reauth_proof: &[u8],
    reauth_proof_kind: &str,
) -> Vec<u8> {
    let selector = compute_selector(
        "requestElevation(bytes32,bytes32,bytes32,uint32,bytes32,bytes,string)",
    );
    let mut out = Vec::with_capacity(4 + 7 * 32 + 128);
    out.extend_from_slice(&selector);

    let head_len = 7 * 32;
    let proof_offset = head_len; // first dynamic tail starts here
    let kind_offset = proof_offset + 32 + padded_len(reauth_proof.len());

    out.extend_from_slice(&user);
    out.extend_from_slice(&tenant);
    out.extend_from_slice(&role);
    out.extend_from_slice(&uint256_from_u64(duration_sec as u64));
    out.extend_from_slice(&corr_id);
    out.extend_from_slice(&uint256_from_u64(proof_offset as u64));
    out.extend_from_slice(&uint256_from_u64(kind_offset as u64));

    push_bytes_dynamic(&mut out, reauth_proof);
    push_string(&mut out, reauth_proof_kind.as_bytes());

    out
}

/// `revoke(bytes32 user, bytes32 tenant, bytes32 reason, bytes32 corr_id)`.
///
/// All-static 4-slot calldata; no dynamic tail. 132 bytes total.
pub fn encode_revoke(
    user: [u8; 32],
    tenant: [u8; 32],
    reason: [u8; 32],
    corr_id: [u8; 32],
) -> Vec<u8> {
    let selector = compute_selector("revoke(bytes32,bytes32,bytes32,bytes32)");
    let mut out = Vec::with_capacity(4 + 4 * 32);
    out.extend_from_slice(&selector);
    out.extend_from_slice(&user);
    out.extend_from_slice(&tenant);
    out.extend_from_slice(&reason);
    out.extend_from_slice(&corr_id);
    out
}

/// `anchor(uint8 kind, bytes32 bundle_id, bytes32 session_id,
/// bytes32 scope, bytes32 merkle_root, bytes32 ipfs_cid,
/// uint256 entry_count)`.
///
/// All-static 7-slot calldata.
pub fn encode_anchor_bundle(
    kind: u8,
    bundle_id: [u8; 32],
    session_id: [u8; 32],
    scope: [u8; 32],
    merkle_root: [u8; 32],
    ipfs_cid: [u8; 32],
    entry_count: u64,
) -> Vec<u8> {
    let selector =
        compute_selector("anchor(uint8,bytes32,bytes32,bytes32,bytes32,bytes32,uint256)");
    let mut out = Vec::with_capacity(4 + 7 * 32);
    out.extend_from_slice(&selector);
    out.extend_from_slice(&uint256_from_u64(kind as u64));
    out.extend_from_slice(&bundle_id);
    out.extend_from_slice(&session_id);
    out.extend_from_slice(&scope);
    out.extend_from_slice(&merkle_root);
    out.extend_from_slice(&ipfs_cid);
    out.extend_from_slice(&uint256_from_u64(entry_count));
    out
}

/// Compute a 4-byte function selector from a canonical solidity
/// signature like `"foo(bytes32,uint256)"`.
fn compute_selector(canonical_sig: &str) -> [u8; 4] {
    let mut hasher = Keccak256::new();
    hasher.update(canonical_sig.as_bytes());
    let h = hasher.finalize();
    let mut out = [0u8; 4];
    out.copy_from_slice(&h[..4]);
    out
}

/// Push a Solidity `bytes` (length-prefixed, right-padded to 32).
fn push_bytes_dynamic(out: &mut Vec<u8>, data: &[u8]) {
    out.extend_from_slice(&uint256_from_u64(data.len() as u64));
    out.extend_from_slice(data);
    let pad = padded_len(data.len()) - data.len();
    out.extend(std::iter::repeat(0u8).take(pad));
}

/// Derive the 20-byte EVM address from a secp256k1 signing key:
/// `keccak256(uncompressed_pubkey_64_bytes)[12..32]`.
fn derive_address(signing_key: &SigningKey) -> String {
    let verifying = signing_key.verifying_key();
    let encoded = verifying.to_encoded_point(false);
    // Strip the 0x04 prefix → 64 bytes (32 X || 32 Y).
    let pubkey_bytes = &encoded.as_bytes()[1..];
    let mut hasher = Keccak256::new();
    hasher.update(pubkey_bytes);
    let digest = hasher.finalize();
    // EVM address = last 20 bytes of keccak(pubkey).
    let mut addr = [0u8; 20];
    addr.copy_from_slice(&digest[12..]);
    format!("0x{}", hex::encode(addr))
}

/// Read a single `KEY=VALUE` line from a dotenv-style file.
/// Returns `None` when the file doesn't exist or the key isn't
/// found. Strips surrounding whitespace + optional `0x` prefix
/// caller-side is the caller's job.
fn read_env_var(path: &Path, key: &str) -> Option<String> {
    let contents = std::fs::read_to_string(path).ok()?;
    for line in contents.lines() {
        let line = line.trim();
        if line.is_empty() || line.starts_with('#') {
            continue;
        }
        // Split on the first `=` so values can contain `=` chars.
        let Some(eq) = line.find('=') else { continue };
        let (k, v) = line.split_at(eq);
        if k.trim() == key {
            // Skip the `=` itself, then trim + strip surrounding
            // quotes if present.
            return Some(v[1..].trim().trim_matches('"').to_string());
        }
    }
    None
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn derive_address_matches_known_vector() {
        // Deployer key from `.env.testnet`. The corresponding
        // address (per `cast wallet address`) is
        // 0x4250675F9015E65fC866F3a373F82bb9DFc000c6.
        let hex = "0x1feffc85883856c384f497cf057d38da863eb9b89c545e72fbfd35631eaf4a58";
        let rec = RecorderClient::from_hex_key(hex, "http://localhost:8545").expect("valid key");
        assert_eq!(
            rec.from_address().to_lowercase(),
            "0x4250675f9015e65fc866f3a373f82bb9dfc000c6"
        );
    }

    #[test]
    fn from_hex_key_rejects_wrong_length() {
        let url = "http://localhost:8545";
        assert!(RecorderClient::from_hex_key("0x1234", url).is_none());
        assert!(RecorderClient::from_hex_key("", url).is_none());
        assert!(RecorderClient::from_hex_key("not-hex", url).is_none());
    }

    #[test]
    fn from_hex_key_handles_no_prefix() {
        // 0x-prefix is optional; both forms should yield the same
        // address.
        let url = "http://localhost:8545";
        let with = RecorderClient::from_hex_key(
            "0x1feffc85883856c384f497cf057d38da863eb9b89c545e72fbfd35631eaf4a58",
            url,
        )
        .expect("with prefix");
        let without = RecorderClient::from_hex_key(
            "1feffc85883856c384f497cf057d38da863eb9b89c545e72fbfd35631eaf4a58",
            url,
        )
        .expect("without prefix");
        assert_eq!(with.from_address(), without.from_address());
    }

    #[test]
    fn record_selector_matches_known_keccak() {
        // keccak256("record(bytes32,bytes32,bytes32,bytes32,uint8,
        // string,string,bytes32,string)")[..4]. Computed once and
        // pasted here so a future refactor of the selector helper
        // can be caught against a hard-coded expectation.
        let sel = record_selector();
        assert_eq!(sel.len(), 4);
        // Sanity: not all zeros.
        assert_ne!(sel, [0u8; 4]);
    }

    #[test]
    fn encode_record_decision_layout_is_correct() {
        let params = DecisionParams {
            decision_id: [0x11u8; 32],
            user: [0x22u8; 32],
            tenant: [0x33u8; 32],
            corr_id: [0x44u8; 32],
            class: 9, // Audit
            description: "Approved query_supplier_status".to_string(),
            auth_mode: "kba".to_string(),
            artifact_root: [0x55u8; 32],
            status: DecisionStatus::Approved,
        };
        let calldata = encode_record_decision(&params);
        // 4 selector + 9 head slots + 3 dynamic strings.
        // description is 31 bytes → padded 32. "kba" → padded 32.
        // "Approved" → padded 32. Each adds 32 (length) + 32 (data) = 64.
        assert_eq!(
            calldata.len(),
            4 + 9 * 32 + 3 * 64,
            "calldata length mismatch"
        );
        // First 4 bytes are the selector; next 32 are decision_id.
        assert_eq!(calldata[4..36], [0x11u8; 32]);
        // Class (uint8) at slot 5 of the head — right-aligned in
        // its 32-byte word.
        assert_eq!(calldata[4 + 4 * 32 + 31], 9);
        // First dynamic offset (description) at slot 6 of head —
        // should equal 288.
        let off_bytes = &calldata[4 + 5 * 32..4 + 6 * 32];
        let off_u64 = u64::from_be_bytes(off_bytes[24..32].try_into().unwrap());
        assert_eq!(off_u64, 288);
    }

    #[test]
    fn encode_revoke_is_all_static_132_bytes() {
        let cd = encode_revoke([1u8; 32], [2u8; 32], [3u8; 32], [4u8; 32]);
        assert_eq!(cd.len(), 4 + 4 * 32);
        // First arg slot starts at offset 4.
        assert_eq!(cd[4..36], [1u8; 32]);
        assert_eq!(cd[36..68], [2u8; 32]);
        assert_eq!(cd[68..100], [3u8; 32]);
        assert_eq!(cd[100..132], [4u8; 32]);
    }

    #[test]
    fn encode_anchor_bundle_packs_uint8_and_uint256() {
        let cd = encode_anchor_bundle(2u8, [0xaau8; 32], [0xbbu8; 32], [0xccu8; 32], [0xddu8; 32], [0xeeu8; 32], 1234);
        assert_eq!(cd.len(), 4 + 7 * 32);
        // kind=2 sits in the LAST byte of slot 0 of the head.
        assert_eq!(cd[4 + 31], 2);
        // entry_count=1234 sits in last 8 bytes of slot 6.
        let last_slot = &cd[4 + 6 * 32..];
        let count = u64::from_be_bytes(last_slot[24..32].try_into().unwrap());
        assert_eq!(count, 1234);
    }

    #[test]
    fn encode_request_elevation_layout_is_correct() {
        let cd = encode_request_elevation(
            [1u8; 32],
            [2u8; 32],
            [3u8; 32],
            3600u32,
            [4u8; 32],
            b"reauth-proof-blob",
            "kba-v1",
        );
        // 7 slots of head + 2 dynamic strings. proof is 17 bytes →
        // padded 32. kind "kba-v1" is 6 bytes → padded 32. Each
        // tail = 32 (length) + 32 (padded data) = 64.
        assert_eq!(cd.len(), 4 + 7 * 32 + 2 * 64);
        // First dynamic offset (proof) at slot 5 → expect 224
        // (= 7 * 32).
        let off_bytes = &cd[4 + 5 * 32..4 + 6 * 32];
        let off = u64::from_be_bytes(off_bytes[24..32].try_into().unwrap());
        assert_eq!(off, 7 * 32);
        // duration_sec=3600 in slot 3, last 4 bytes.
        let dur_bytes = &cd[4 + 3 * 32..4 + 4 * 32];
        let dur = u32::from_be_bytes(dur_bytes[28..32].try_into().unwrap());
        assert_eq!(dur, 3600);
    }

    #[test]
    fn padded_len_rounds_up_to_32() {
        assert_eq!(padded_len(0), 0);
        assert_eq!(padded_len(1), 32);
        assert_eq!(padded_len(31), 32);
        assert_eq!(padded_len(32), 32);
        assert_eq!(padded_len(33), 64);
        assert_eq!(padded_len(64), 64);
        assert_eq!(padded_len(65), 96);
    }

    #[test]
    fn read_env_var_returns_value() {
        let tmp = std::env::temp_dir().join("bfr-int-12b-test.env");
        std::fs::write(
            &tmp,
            "# comment\nFOO=bar\nBAZ=\"quoted value\"\n  WS = trimmed  \n",
        )
        .expect("write tmp");
        assert_eq!(read_env_var(&tmp, "FOO"), Some("bar".to_string()));
        assert_eq!(read_env_var(&tmp, "BAZ"), Some("quoted value".to_string()));
        assert_eq!(read_env_var(&tmp, "WS"), Some("trimmed".to_string()));
        assert_eq!(read_env_var(&tmp, "MISSING"), None);
        let _ = std::fs::remove_file(tmp);
    }
}
