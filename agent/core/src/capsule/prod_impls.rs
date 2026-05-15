//! CIT-AGENT-9c-prod-impls — production implementations of
//! `ApprovalGate` and `EthSendDispatcher`. Both bridge async APIs
//! (the in-tree ApprovalQueue + wallet-core's RpcClient) to the
//! sync host-fn surface via `tokio::task::block_in_place` +
//! `Handle::block_on` — same pattern as `RpcEthCallDispatcher`.
//!
//! Operational requirement: every host-fn invocation must occur
//! on a thread inside a multi-thread tokio runtime. The agent
//! harness's main loop satisfies this; the doctor CLI uses
//! `spawn_blocking` for the same reason.

use crate::audit::recorder::RecorderClient;
use crate::capsule::dispatcher::{
    ApprovalGate, ApprovalRequest, EthSendDispatcher,
};
use crate::capsule::wasm::Address;
use crate::hitl::{ApprovalOutcomePublic, ApprovalQueue, ToolCall};
use serde_json::json;
use std::sync::Arc;

/// Production `ApprovalGate` backed by the in-tree async
/// `ApprovalQueue`. Bridges the sync host fn to
/// `ApprovalQueue::submit_with_outcome` via `block_in_place`.
///
/// CIT-AGENT-9c-prod-impls.
pub struct QueuedApprovalGate {
    queue: Arc<ApprovalQueue>,
}

impl QueuedApprovalGate {
    pub fn new(queue: Arc<ApprovalQueue>) -> Self {
        Self { queue }
    }
}

impl ApprovalGate for QueuedApprovalGate {
    fn request(&self, req: ApprovalRequest) -> Result<(), String> {
        // Build the ToolCall the queue's UI surfaces will display.
        // call_id is derived from the (capsule, to, data) tuple via
        // SHA3 so retries with identical args collide on the same
        // queue entry — denying double-spends from rapid
        // re-invocation.
        let call_id = {
            use sha3::{Digest, Keccak256};
            let mut h = Keccak256::new();
            h.update(req.capsule_name.as_bytes());
            h.update(b"|");
            h.update(req.method.as_bytes());
            h.update(b"|");
            h.update(req.to);
            h.update(b"|");
            h.update(&req.data);
            let out = h.finalize();
            hex::encode(&out[..16])
        };
        let call = ToolCall {
            call_id,
            name: format!("{}::{}", req.capsule_name, req.method),
            args: json!({
                "to": format!("0x{}", hex::encode(req.to)),
                "data_hex": format!("0x{}", hex::encode(&req.data)),
                "data_len": req.data.len(),
            }),
        };
        // Bridge sync → async via block_in_place. Requires a
        // multi-thread runtime — see module docstring.
        let queue = self.queue.clone();
        let outcome = tokio::task::block_in_place(move || {
            let handle = tokio::runtime::Handle::current();
            handle.block_on(async move { queue.submit_with_outcome(call).await })
        });
        match outcome {
            ApprovalOutcomePublic::Approved => Ok(()),
            ApprovalOutcomePublic::AutoApproved => Ok(()),
            ApprovalOutcomePublic::Rejected => Err("rejected by operator".to_string()),
            ApprovalOutcomePublic::TimedOut => {
                Err("approval timed out (5min)".to_string())
            }
        }
    }
}

/// Production `EthSendDispatcher` backed by `RecorderClient`
/// (citrate-wallet-core signing + send_raw_transaction).
///
/// CIT-AGENT-9c-prod-impls.
pub struct RecorderEthSendDispatcher {
    recorder: Arc<RecorderClient>,
    gas_limit: u64,
}

impl RecorderEthSendDispatcher {
    /// Default gas limit (600,000) — calibrated against
    /// BFR-INT-12b production usage. Override via `with_gas_limit`
    /// when known.
    pub fn new(recorder: Arc<RecorderClient>) -> Self {
        Self {
            recorder,
            gas_limit: 600_000,
        }
    }

    pub fn with_gas_limit(mut self, gas_limit: u64) -> Self {
        self.gas_limit = gas_limit;
        self
    }
}

impl EthSendDispatcher for RecorderEthSendDispatcher {
    fn eth_send(&self, to: &Address, data: &[u8]) -> Result<[u8; 32], String> {
        let to_hex = format!("0x{}", hex::encode(to));
        let calldata = data.to_vec();
        let recorder = self.recorder.clone();
        let gas_limit = self.gas_limit;
        let tx_str = tokio::task::block_in_place(move || {
            let handle = tokio::runtime::Handle::current();
            handle.block_on(async move {
                recorder.send_tx(&to_hex, calldata, gas_limit).await
            })
        })?;
        // tx_str is `0x<64-hex>`; convert to [u8; 32].
        let stripped = tx_str.strip_prefix("0x").unwrap_or(&tx_str);
        if stripped.len() != 64 {
            return Err(format!(
                "send_tx returned malformed tx hash ({} chars): {tx_str}",
                stripped.len()
            ));
        }
        let bytes = hex::decode(stripped)
            .map_err(|e| format!("send_tx tx hash hex decode: {e}"))?;
        let mut out = [0u8; 32];
        out.copy_from_slice(&bytes);
        Ok(out)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Construction smoke — the production types build without
    /// panicking. Doesn't exercise the async bridge (that requires
    /// a tokio runtime + a real ApprovalQueue or RecorderClient
    /// behind it).
    #[test]
    fn types_construct() {
        let queue = Arc::new(ApprovalQueue::new());
        let _gate = QueuedApprovalGate::new(queue);
        // RecorderClient::from_hex_key returns Option<Self>; we
        // pass a 32-byte zero hex which decodes but isn't a valid
        // signing key. We accept either Some or None for this
        // construction smoke.
        let key = "0".repeat(64);
        if let Some(rec) = RecorderClient::from_hex_key(&key, "http://localhost") {
            let _disp = RecorderEthSendDispatcher::new(Arc::new(rec))
                .with_gas_limit(400_000);
        }
    }
}
