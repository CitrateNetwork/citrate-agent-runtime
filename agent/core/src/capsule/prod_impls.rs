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
use crate::hitl::quorum::Quorum;
use crate::hitl::{ApprovalOutcomePublic, ApprovalQueue, Signer, ToolCall};
use serde_json::json;
use std::sync::Arc;

/// Production `ApprovalGate` backed by the in-tree async
/// `ApprovalQueue`. Bridges the sync host fn to
/// `ApprovalQueue::submit_with_outcome` via `block_in_place`.
///
/// CIT-AGENT-9c-prod-impls.
pub struct QueuedApprovalGate {
    queue: Arc<ApprovalQueue>,
    /// PBA-L6b-012: the HUMAN who invoked the capsule. Recorded as the
    /// proposer of every tier>=medium effect so separation of duties
    /// ("the proposer cannot approve") is checked against a real signer id.
    /// `None` = no accountable human is bound, and privileged effects are
    /// refused at once (see `request`).
    proposer: Option<Signer>,
}

impl QueuedApprovalGate {
    /// A gate with no invoking human bound. Tier-low effects use the FIFO
    /// track; tier>=medium effects are refused immediately (PBA-L6b-012 /
    /// PBA-L6b-032) because nothing could ever approve them against SoD.
    pub fn new(queue: Arc<ApprovalQueue>) -> Self {
        Self {
            queue,
            proposer: None,
        }
    }

    /// Bind the human operator who invokes capsules through this gate, by
    /// their Ed25519 PUBLIC KEY. The proposer id is derived from the key
    /// (`signer_id_from_pubkey`, the same fingerprint `add_signature` checks),
    /// so it cannot be set to an arbitrary string that no signing key matches
    /// (PBA-L6b-012). That key can then never count toward the quorum of an
    /// effect it proposed.
    pub fn with_proposer(mut self, operator_pubkey: [u8; 32]) -> Self {
        self.proposer = Some(Signer {
            id: crate::hitl::signer_id_from_pubkey(&operator_pubkey),
            role: crate::capsule::manifest::Role::Operator,
        });
        self
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
            call_id: call_id.clone(),
            name: format!("{}::{}", req.capsule_name, req.method),
            args: json!({
                "to": format!("0x{}", hex::encode(req.to)),
                "data_hex": format!("0x{}", hex::encode(&req.data)),
                "data_len": req.data.len(),
                // AR-B-003: surface the TRUE risk tier from the manifest,
                // not a name-derived "low" default.
                "risk_tier": format!("{:?}", req.tier),
                "required_roles": req
                    .required_roles
                    .iter()
                    .map(|r| format!("{r:?}"))
                    .collect::<Vec<_>>(),
            }),
        };

        // AR-B-003: derive the role-bound quorum from the manifest tier.
        // Tier-low actions auto-approve (log only); every higher tier
        // MUST accumulate roster-authorized signatures satisfying the
        // quorum before resolving — the anonymous single-click FIFO
        // `approve()` path CANNOT release them.
        let quorum = Quorum::for_tier(req.tier, &req.required_roles);
        let queue = self.queue.clone();

        if matches!(quorum, Quorum::AutoApprove) {
            // Tier-low: the legacy FIFO fast path is acceptable.
            let outcome = tokio::task::block_in_place(move || {
                let handle = tokio::runtime::Handle::current();
                handle.block_on(async move { queue.submit_with_outcome(call).await })
            });
            return outcome_to_result(outcome);
        }

        // Tier medium/high/critical: route through the role-aware quorum.
        //
        // PBA-L6b-012: the proposer is the HUMAN who invoked the capsule, not
        // the capsule. With `capsule:<name>` as proposer the self-approval
        // check compared signer ids against a string no key fingerprint can
        // equal, so the invoking human could approve their own effect.
        // PBA-L6b-032: with no human bound there is nobody accountable to
        // propose, so refuse now rather than park the effect (and block this
        // worker) for the 5-minute timeout.
        let Some(proposer) = self.proposer.clone() else {
            return Err(format!(
                "{} effect from capsule {:?} refused: tier {:?} needs a role quorum and no \
                 invoking human is bound to this approval gate",
                req.method, req.capsule_name, req.tier
            ));
        };
        let payload = signing_payload(&req);
        let outcome = tokio::task::block_in_place(move || {
            let handle = tokio::runtime::Handle::current();
            handle.block_on(async move {
                queue
                    .submit_for_action(call, payload, quorum, proposer)
                    .await
            })
        });
        outcome_to_result(outcome)
    }
}

/// Canonical bytes the action's signers attest to. Fetched by the
/// operator ceremony via `ApprovalQueue::payload_for(call_id)` and
/// signed; `add_signature` verifies each signature against exactly
/// these bytes.
fn signing_payload(req: &ApprovalRequest) -> Vec<u8> {
    format!(
        "{}|{}|0x{}|0x{}",
        req.capsule_name,
        req.method,
        hex::encode(req.to),
        hex::encode(&req.data)
    )
    .into_bytes()
}

fn outcome_to_result(outcome: ApprovalOutcomePublic) -> Result<(), String> {
    match outcome {
        ApprovalOutcomePublic::Approved => Ok(()),
        ApprovalOutcomePublic::AutoApproved => Ok(()),
        ApprovalOutcomePublic::Rejected => Err("rejected by operator".to_string()),
        ApprovalOutcomePublic::TimedOut => Err("approval timed out (5min)".to_string()),
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

    use crate::capsule::manifest::{RiskTier, Role};
    use crate::hitl::signing::{Ed25519FileSurface, SigningSurface, StaticSignerRoster};
    use crate::hitl::Signature;
    use std::time::Duration;

    fn call_id_for(capsule: &str, method: &str, to: &[u8; 20], data: &[u8]) -> String {
        use sha3::{Digest, Keccak256};
        let mut h = Keccak256::new();
        h.update(capsule.as_bytes());
        h.update(b"|");
        h.update(method.as_bytes());
        h.update(b"|");
        h.update(to);
        h.update(b"|");
        h.update(data);
        hex::encode(&h.finalize()[..16])
    }

    /// AR-B-003 tripwire: a tier-`high` capsule effect routed through the
    /// production `QueuedApprovalGate` must NOT resolve on an anonymous
    /// FIFO `approve()`, and MUST require two roster-authorized signatures
    /// from `{Reviewer, ComplianceOfficer}`.
    #[tokio::test(flavor = "multi_thread", worker_threads = 4)]
    async fn queued_gate_tier_high_requires_role_quorum_ar_b_003() {
        let reviewer = Ed25519FileSurface::from_seed([0x11; 32], Role::Reviewer);
        let compliance = Ed25519FileSurface::from_seed([0x22; 32], Role::ComplianceOfficer);
        let roster = StaticSignerRoster::new()
            .authorize(reviewer.pubkey(), Role::Reviewer)
            .authorize(compliance.pubkey(), Role::ComplianceOfficer);
        let queue = Arc::new(ApprovalQueue::new().with_signer_roster(Arc::new(roster)));
        // PBA-L6b-012: the invoking human is the proposer.
        let operator = Ed25519FileSurface::from_seed([0x33; 32], Role::Operator);
        let gate =
            Arc::new(QueuedApprovalGate::new(queue.clone()).with_proposer(operator.pubkey()));

        let addr = [0xa6u8; 20];
        let data = vec![0xde, 0xad, 0xbe, 0xef];
        let call_id = call_id_for("provision-user", "eth-send", &addr, &data);

        let req = ApprovalRequest {
            capsule_name: "provision-user".to_string(),
            method: "eth-send".to_string(),
            to: addr,
            data: data.clone(),
            tier: RiskTier::High,
            required_roles: vec![Role::Reviewer, Role::ComplianceOfficer],
        };

        // Run the (blocking) gate on a worker; it parks until quorum.
        let g = gate.clone();
        let handle = tokio::spawn(async move { g.request(req) });

        // Wait for the role-aware entry to register.
        let payload = {
            let mut got = None;
            for _ in 0..200 {
                if let Some(p) = queue.payload_for(&call_id) {
                    got = Some(p);
                    break;
                }
                tokio::time::sleep(Duration::from_millis(5)).await;
            }
            got.expect("role-aware entry should register")
        };

        // (a) The FIFO approve surface MUST NOT release it (it is not on the
        // FIFO track, so an id-bound approve finds nothing to resolve).
        assert!(queue.approve_by_id(&call_id).is_err());
        tokio::time::sleep(Duration::from_millis(20)).await;
        assert!(
            !handle.is_finished(),
            "tier-high write was released by an anonymous FIFO approve"
        );

        // (b) One roster signature is not enough (NofM{n:2}).
        let s1: Signature = reviewer.sign(&payload).expect("reviewer sign").into();
        queue.add_signature(&call_id, s1).expect("reviewer sig accepted");
        assert_eq!(queue.signatures_on(&call_id).len(), 1);
        tokio::time::sleep(Duration::from_millis(20)).await;
        assert!(!handle.is_finished(), "resolved on a single signature");

        // Second roster signature satisfies the quorum → resolves Approved.
        let s2: Signature = compliance.sign(&payload).expect("compliance sign").into();
        queue.add_signature(&call_id, s2).expect("compliance sig accepted");

        let res = tokio::time::timeout(Duration::from_secs(5), handle)
            .await
            .expect("gate resolves after quorum")
            .expect("join");
        assert!(res.is_ok(), "gate should approve once quorum met: {res:?}");
    }

    /// PBA-L6b-012 / PBA-L6b-032 regression: with no invoking human bound to
    /// the gate, a tier>=medium effect is refused at once. Pre-fix the
    /// proposer was recorded as `capsule:<name>` (so the self-approval check
    /// compared against a name no human key can have) and the effect parked
    /// for 5 minutes on a track the sidecar exposes no way to approve.
    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn gate_without_a_bound_human_refuses_privileged_effects_pba_l6b_012() {
        let queue = Arc::new(ApprovalQueue::new());
        let gate = Arc::new(QueuedApprovalGate::new(queue.clone()));
        let req = ApprovalRequest {
            capsule_name: "provision-user".to_string(),
            method: "eth-send".to_string(),
            to: [0xa6u8; 20],
            data: vec![1, 2, 3],
            tier: RiskTier::High,
            required_roles: vec![Role::Reviewer, Role::ComplianceOfficer],
        };
        let g = gate.clone();
        let res = tokio::time::timeout(
            Duration::from_secs(2),
            tokio::spawn(async move { g.request(req) }),
        )
        .await
        .expect("an unapprovable effect must be refused at once, not parked")
        .expect("join");
        assert!(res.is_err(), "privileged effect without a bound human must be refused");
        assert_eq!(queue.role_pending_depth(), 0, "nothing parks on the role track");
    }

    /// PBA-L6b-012: with the invoking human bound as proposer, that human's
    /// key cannot sign toward its own effect's quorum, even when the roster
    /// also enrols it for an approving role.
    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn bound_proposer_cannot_approve_own_effect_pba_l6b_012() {
        let operator = Ed25519FileSurface::from_seed([0x44; 32], Role::Reviewer);
        let roster = StaticSignerRoster::new().authorize(operator.pubkey(), Role::Reviewer);
        let queue = Arc::new(ApprovalQueue::new().with_signer_roster(Arc::new(roster)));
        let gate =
            Arc::new(QueuedApprovalGate::new(queue.clone()).with_proposer(operator.pubkey()));
        let (addr, data) = ([0xa7u8; 20], vec![9u8]);
        let call_id = call_id_for("revoke-role", "eth-send", &addr, &data);
        let req = ApprovalRequest {
            capsule_name: "revoke-role".to_string(),
            method: "eth-send".to_string(),
            to: addr,
            data,
            tier: RiskTier::Medium,
            required_roles: vec![Role::Reviewer],
        };
        let g = gate.clone();
        let h = tokio::spawn(async move { g.request(req) });
        let payload = loop {
            if let Some(p) = queue.payload_for(&call_id) {
                break p;
            }
            tokio::time::sleep(Duration::from_millis(5)).await;
        };
        let own: Signature = operator.sign(&payload).expect("sign").into();
        assert_eq!(
            queue.add_signature(&call_id, own),
            Err(crate::hitl::SignatureError::ProposerCannotSelfApprove)
        );
        queue.reject_action(&call_id).expect("cleanup");
        assert!(h.await.expect("join").is_err());
    }

    /// PBA-L6b-012 tripwire: the production gate must never again record a
    /// non-human (capsule-derived) proposer for a role-track effect.
    #[test]
    fn tripwire_gate_proposer_is_not_the_capsule_pba_l6b_012() {
        let src = include_str!("prod_impls.rs");
        let prod = &src[..src.find("#[cfg(test)]").expect("test module")];
        assert!(
            !prod.contains("format!(\"capsule:"),
            "QueuedApprovalGate must not synthesize a capsule proposer"
        );
    }

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
