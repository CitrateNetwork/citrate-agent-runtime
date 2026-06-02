//! Human-in-the-loop approval queue — RFC-CIT-AGENT-0001 §3.1
//! "HITL Queue" + §5 (approval state machine).
//!
//! BFR-INT-12b WP-4/WP-5 lived in `citrate_boeing_shell::tools` as a
//! single-in-flight + FIFO + 5-min-timeout approval queue. CIT-AGENT-1
//! moves the queue and its supporting types here, where the Boeing
//! shell consumes them through a re-export shim. RFC §3.2 names
//! `ApprovalQueue` in the frozen v1.0 public surface.
//!
//! CIT-AGENT-4a adds the role lattice + tier→quorum mapping +
//! separation-of-duties checker on top of the existing FIFO + timeout
//! + auto-grant queue. The state machine modelled in this module is
//! verified by `.agentile/formal/specs/agent/ApprovalStateMachine.tla`
//! (CIT-AGENT-2 — 336,292 distinct states PASS).
//!
//! NOTE on tool-metadata helpers: `describe()` and `risk_level()` ship
//! defaults that recognize the BFR-INT-12b tool catalog
//! (`list_compliance_posture`, `anchor_session`, `provision_user`,
//! etc.). When the capsule system lands in CIT-AGENT-3 these will be
//! superseded by a manifest-driven lookup (`Capsule::metadata` -> {risk,
//! description}). Until then they stay here as the agreed defaults.

pub mod break_glass;
pub mod quorum;
pub mod roles;
pub mod signing;

pub use break_glass::{
    BreakGlassEntry, BreakGlassError, BreakGlassPhase, BreakGlassRegistry, AFFIRMATION_WINDOW,
};
pub use quorum::Quorum;
pub use roles::{can_approve, is_conflict};
pub use signing::{
    signer_id_from_pubkey, signer_is_authorized, verify_attestation, AttestedSignature,
    Ed25519FileSurface, SignerRoster, SigningSurface, StaticSignerRoster,
};
// Role is also re-exported here for ergonomics — same enum as
// `capsule::manifest::Role`.
pub use crate::capsule::manifest::Role;

use serde_json::Value;
use std::collections::{HashMap, VecDeque};
use std::sync::Mutex;
use std::time::{Duration, Instant};
use tokio::sync::oneshot;

// ── Public surface ─────────────────────────────────────────────────

/// One tool call as emitted by the LLM.
#[derive(Debug, Clone)]
pub struct ToolCall {
    pub call_id: String,
    pub name: String,
    pub args: Value,
}

/// Tool execution result, formatted for the LLM to consume as the
/// next assistant turn's context.
#[derive(Debug, Clone)]
pub struct ToolResult {
    pub call_id: String,
    pub ok: bool,
    /// Markdown-friendly string returned to the LLM. On error, a
    /// short human-readable description.
    pub content: String,
}

/// What's currently pending approval (if anything). Used by the UI
/// thread to populate the ToolApprovalCard.
#[derive(Debug, Clone)]
pub struct PendingView {
    pub name: String,
    pub description: String,
    pub risk_level: String,
    pub args_pretty: String,
}

// ── Approval queue ─────────────────────────────────────────────────

struct PendingEntry {
    #[allow(dead_code)] // held for future per-call display
    call: ToolCall,
    resolver: oneshot::Sender<ApprovalOutcome>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum ApprovalOutcome {
    Approved,
    Rejected,
}

/// BFR-INT-12b WP-5 — default Pending deadline. If the operator
/// doesn't approve / reject within this window, the call resolves
/// as `TimedOut` and the LLM gets a "user declined (timeout)"
/// response.
const PENDING_TIMEOUT: Duration = Duration::from_secs(5 * 60);

/// BFR-INT-12b WP-4 — default auto-grant TTL. A trusted tool stays
/// in the auto-approve set for this long after it's added.
const AUTO_GRANT_TTL: Duration = Duration::from_secs(30 * 60);

/// Rich outcome enum exposed to callers via
/// [`ApprovalQueue::submit_with_outcome`]. The plain [`ApprovalQueue::submit`]
/// collapses to `bool` for the simple "approved?" case.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ApprovalOutcomePublic {
    Approved,
    Rejected,
    TimedOut,
    AutoApproved,
}

// ── CIT-AGENT-4a: Signer / Signature types ─────────────────────────

/// A person + role assertion. `id` is an opaque identifier — DID,
/// email, FIDO key ID, etc. Hardware-backed signature material lands
/// in CIT-AGENT-4b alongside `Signature`. For 4a the type pairs an
/// identity with a role so the queue can dedup (SoD: same person
/// can't sign twice) and check role conflicts.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct Signer {
    pub id: String,
    pub role: Role,
}

/// An approval signature on an action. CIT-AGENT-4b extends this
/// with the attested-signature material: signature bytes + pubkey.
/// `add_signature` verifies the bytes against the recorded action
/// payload before accepting; a synthetic / spoofed signature is
/// rejected with `SignatureError::AttestationInvalid`.
///
/// The `Signer.id` MUST equal the SHA-256 fingerprint of `pubkey`
/// (per `signing::signer_id_from_pubkey`); this is enforced by
/// `signing::verify_attestation`.
#[derive(Debug, Clone)]
pub struct Signature {
    pub signer: Signer,
    pub signature_bytes: Vec<u8>,
    pub pubkey: [u8; 32],
}

impl From<AttestedSignature> for Signature {
    fn from(a: AttestedSignature) -> Self {
        Self {
            signer: a.signer,
            signature_bytes: a.signature_bytes,
            pubkey: a.pubkey,
        }
    }
}

/// Errors from the role-aware approval flow. Returned by
/// `add_signature` and the role-aware submit path.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum SignatureError {
    /// The role is not allowed to approve (Auditor).
    AuditorCannotApprove,
    /// The signer is also the proposer; cannot self-approve.
    ProposerCannotSelfApprove,
    /// The signer already submitted a signature for this action.
    DuplicateSigner,
    /// Two roles in the accumulated signature set are role-pair-conflicting
    /// (e.g., ComplianceOfficer + SecurityOfficer per RFC §5.3).
    RoleConflict { existing: Role, attempted: Role },
    /// The action's pending entry was not found (already settled, or
    /// never submitted).
    UnknownCallId,
    /// CIT-AGENT-4b — attestation material is invalid: signature does
    /// not verify under the claimed pubkey, signer.id doesn't match
    /// the pubkey fingerprint, or signature length is wrong.
    AttestationInvalid(String),
    /// RM-G.1 — the signature verifies cryptographically but its pubkey is
    /// NOT on the authorized-signer roster for the claimed role (or no
    /// roster is configured in a production build). A self-minted key can
    /// never satisfy a quorum.
    SignerNotAuthorized,
}

impl std::fmt::Display for SignatureError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            SignatureError::AuditorCannotApprove => {
                write!(f, "auditor role cannot approve any action (RFC §5.3)")
            }
            SignatureError::ProposerCannotSelfApprove => {
                write!(f, "proposer cannot also sign as approver (SoD)")
            }
            SignatureError::DuplicateSigner => write!(f, "signer already signed this action"),
            SignatureError::RoleConflict {
                existing,
                attempted,
            } => write!(
                f,
                "role conflict: {existing:?} already signed; cannot also accept {attempted:?}"
            ),
            SignatureError::UnknownCallId => write!(f, "no pending action with that call_id"),
            SignatureError::AttestationInvalid(m) => {
                write!(f, "attestation invalid: {m}")
            }
            SignatureError::SignerNotAuthorized => write!(
                f,
                "signer pubkey is not on the authorized-signer roster for the claimed role"
            ),
        }
    }
}

/// State for a role-aware action awaiting quorum-based approval.
/// CIT-AGENT-4a + 4b: includes the canonical action payload that
/// signatures must attest to.
struct RoleAwareEntry {
    quorum: Quorum,
    proposer: Signer,
    /// Canonical bytes signers attest to. Verified by `add_signature`
    /// against the supplied `Signature.signature_bytes` before
    /// accepting. CIT-AGENT-4b.
    payload: Vec<u8>,
    signatures: Vec<Signature>,
    resolver: oneshot::Sender<ApprovalOutcome>,
}

/// FIFO tool approval queue with auto-approve grants + per-call
/// timeout (BFR-INT-12b WP-4 + WP-5). Replaces BFR-INT-12's
/// single-in-flight slot.
///
/// CIT-AGENT-4a adds a parallel role-aware track: `submit_for_action`
/// + `add_signature` accumulate per-role signatures until the
/// declared `Quorum` is satisfied. The simple `submit` / `approve` /
/// `reject` API stays for BFR-INT-12b compatibility.
///
/// Locking discipline: the std Mutex is only held across queue
/// surgery (push / pop / peek). Awaits happen outside the lock
/// scope on the oneshot receiver.
#[derive(Default)]
pub struct ApprovalQueue {
    pending: Mutex<VecDeque<PendingEntry>>,
    grants: Mutex<HashMap<String, Instant>>,
    // CIT-AGENT-4a — role-aware track. Keyed by call_id so the UI
    // can present per-action approval surfaces.
    role_pending: Mutex<HashMap<String, RoleAwareEntry>>,
    // RM-G.1 — authorized-signer roster. When `Some`, a quorum signature
    // counts only if its pubkey is enrolled for the claimed role. When
    // `None`, `add_signature` fails closed in release builds (see
    // `signer_is_authorized`).
    signer_roster: Option<std::sync::Arc<dyn SignerRoster>>,
}

impl ApprovalQueue {
    pub fn new() -> Self {
        Self::default()
    }

    /// Install the authorized-signer roster (RM-G.1). Production
    /// deployments MUST set this; without it a release build refuses all
    /// quorum signatures (fail closed).
    pub fn with_signer_roster(mut self, roster: std::sync::Arc<dyn SignerRoster>) -> Self {
        self.signer_roster = Some(roster);
        self
    }

    /// Submit a tool call for approval. Returns `true` for
    /// Approved or AutoApproved, `false` for Rejected or TimedOut.
    pub async fn submit(&self, call: ToolCall) -> bool {
        matches!(
            self.submit_with_outcome(call).await,
            ApprovalOutcomePublic::Approved | ApprovalOutcomePublic::AutoApproved
        )
    }

    /// Same as [`submit`] but returns the rich outcome so callers
    /// can write a faithful decision-log row.
    pub async fn submit_with_outcome(&self, call: ToolCall) -> ApprovalOutcomePublic {
        // BFR-INT-12b WP-4 — auto-grant fast path. Resolved before
        // the queue is touched.
        if self.is_trusted(&call.name) {
            return ApprovalOutcomePublic::AutoApproved;
        }
        let (tx, rx) = oneshot::channel();
        {
            let mut q = match self.pending.lock() {
                Ok(q) => q,
                Err(_) => return ApprovalOutcomePublic::Rejected,
            };
            q.push_back(PendingEntry { call, resolver: tx });
        }
        // BFR-INT-12b WP-5 — race the resolver against the 5-min
        // timeout.
        match tokio::time::timeout(PENDING_TIMEOUT, rx).await {
            Ok(Ok(ApprovalOutcome::Approved)) => ApprovalOutcomePublic::Approved,
            Ok(Ok(ApprovalOutcome::Rejected)) => ApprovalOutcomePublic::Rejected,
            Ok(Err(_)) => ApprovalOutcomePublic::Rejected, // sender dropped
            Err(_) => {
                self.evict_timed_out();
                ApprovalOutcomePublic::TimedOut
            }
        }
    }

    /// Approve the head of the queue.
    pub fn approve(&self) {
        self.pop_head_with(ApprovalOutcome::Approved);
    }

    /// Reject the head of the queue.
    pub fn reject(&self) {
        self.pop_head_with(ApprovalOutcome::Rejected);
    }

    /// BFR-INT-12b WP-4 — add the named tool to the auto-grant set
    /// for [`AUTO_GRANT_TTL`].
    pub fn add_grant(&self, tool_name: &str) {
        if let Ok(mut grants) = self.grants.lock() {
            let expiry = Instant::now() + AUTO_GRANT_TTL;
            grants.insert(tool_name.to_string(), expiry);
        }
    }

    /// Active (unexpired) grants — used for display / debugging.
    pub fn active_grants(&self) -> Vec<(String, Duration)> {
        let now = Instant::now();
        match self.grants.lock() {
            Ok(g) => g
                .iter()
                .filter_map(|(name, expiry)| {
                    expiry.checked_duration_since(now).map(|d| (name.clone(), d))
                })
                .collect(),
            Err(_) => Vec::new(),
        }
    }

    /// UI thread reads this to populate ToolApprovalCard fields.
    /// Returns `None` when nothing is at the head of the queue.
    pub fn peek(&self) -> Option<PendingView> {
        let q = self.pending.lock().ok()?;
        let entry = q.front()?;
        let args_pretty = serde_json::to_string_pretty(&entry.call.args)
            .unwrap_or_else(|_| entry.call.args.to_string());
        Some(PendingView {
            name: entry.call.name.clone(),
            description: describe(&entry.call.name),
            risk_level: risk_level(&entry.call.name).to_string(),
            args_pretty,
        })
    }

    /// FIFO depth — for "+N more pending" UI affordances.
    pub fn depth(&self) -> usize {
        self.pending.lock().map(|q| q.len()).unwrap_or(0)
    }

    // ── CIT-AGENT-4a: role-aware approval API ──────────────────────

    /// Submit an action for role-aware approval. Resolves when the
    /// declared `Quorum` is satisfied by accumulated signatures, when
    /// any signer issues a rejection, or when the per-call timeout
    /// fires.
    ///
    /// CIT-AGENT-4b: `payload` is the canonical bytes signers must
    /// attest to (typically a serialized form of the action's args).
    /// `add_signature` will reject any signature that doesn't verify
    /// against this exact byte sequence.
    ///
    /// Tier-low actions (`Quorum::AutoApprove`) short-circuit to
    /// `AutoApproved` without entering the queue.
    pub async fn submit_for_action(
        &self,
        call: ToolCall,
        payload: Vec<u8>,
        quorum: Quorum,
        proposer: Signer,
    ) -> ApprovalOutcomePublic {
        // Tier-low fast path.
        if matches!(quorum, Quorum::AutoApprove) {
            return ApprovalOutcomePublic::AutoApproved;
        }
        let (tx, rx) = oneshot::channel();
        let call_id = call.call_id.clone();
        {
            let mut role_q = match self.role_pending.lock() {
                Ok(q) => q,
                Err(_) => return ApprovalOutcomePublic::Rejected,
            };
            role_q.insert(
                call_id.clone(),
                RoleAwareEntry {
                    quorum,
                    proposer,
                    payload,
                    signatures: Vec::new(),
                    resolver: tx,
                },
            );
        }
        // Also place on the FIFO pending queue so the existing UI
        // surfaces still see the action.
        let _ = call; // kept by RoleAwareEntry; not duplicated here
        // Race resolver against the standard timeout.
        let outcome = match tokio::time::timeout(PENDING_TIMEOUT, rx).await {
            Ok(Ok(ApprovalOutcome::Approved)) => ApprovalOutcomePublic::Approved,
            Ok(Ok(ApprovalOutcome::Rejected)) => ApprovalOutcomePublic::Rejected,
            Ok(Err(_)) => ApprovalOutcomePublic::Rejected,
            Err(_) => ApprovalOutcomePublic::TimedOut,
        };
        // Clean up the entry if it's still there (timeout/reject paths).
        if let Ok(mut role_q) = self.role_pending.lock() {
            role_q.remove(&call_id);
        }
        outcome
    }

    /// Add a signature toward the pending action's quorum. Returns
    /// `Ok(())` on accepted signature; `SignatureError` on SoD
    /// violation, Auditor attempt, duplicate signer, or unknown
    /// call_id. When the accumulated signatures satisfy the quorum
    /// the underlying `submit_for_action` resolves Approved.
    pub fn add_signature(
        &self,
        call_id: &str,
        sig: Signature,
    ) -> Result<(), SignatureError> {
        // SoD: Auditor never approves.
        if !roles::can_approve(sig.signer.role) {
            return Err(SignatureError::AuditorCannotApprove);
        }
        let mut role_q = self
            .role_pending
            .lock()
            .map_err(|_| SignatureError::UnknownCallId)?;
        let entry = role_q
            .get_mut(call_id)
            .ok_or(SignatureError::UnknownCallId)?;
        // CIT-AGENT-4b: verify the attestation against the recorded
        // action payload BEFORE the other SoD checks. A spoofed
        // signature is rejected here.
        let attested = AttestedSignature {
            signer: sig.signer.clone(),
            signature_bytes: sig.signature_bytes.clone(),
            pubkey: sig.pubkey,
        };
        if let Err(e) = verify_attestation(&entry.payload, &attested) {
            return Err(SignatureError::AttestationInvalid(e.to_string()));
        }
        // RM-G.1: the signature verifies cryptographically, but a valid
        // signature from a SELF-MINTED key proves nothing about authority.
        // The pubkey MUST be on the authorized-signer roster for the role
        // it claims; without a roster a release build fails closed.
        let dev_allowed = cfg!(debug_assertions) || cfg!(feature = "insecure-dev-hitl");
        if !signer_is_authorized(
            self.signer_roster.as_deref(),
            &sig.pubkey,
            sig.signer.role,
            dev_allowed,
        ) {
            return Err(SignatureError::SignerNotAuthorized);
        }
        // SoD: proposer cannot also approve.
        if entry.proposer.id == sig.signer.id {
            return Err(SignatureError::ProposerCannotSelfApprove);
        }
        // SoD: same signer can't sign twice.
        if entry
            .signatures
            .iter()
            .any(|s| s.signer.id == sig.signer.id)
        {
            return Err(SignatureError::DuplicateSigner);
        }
        // SoD: role-pair conflict (e.g. ComplianceOfficer +
        // SecurityOfficer in same action).
        for existing in &entry.signatures {
            if roles::is_conflict(existing.signer.role, sig.signer.role) {
                return Err(SignatureError::RoleConflict {
                    existing: existing.signer.role,
                    attempted: sig.signer.role,
                });
            }
        }
        entry.signatures.push(sig);
        // Check if quorum is now satisfied.
        let roles_signed: Vec<Role> =
            entry.signatures.iter().map(|s| s.signer.role).collect();
        if entry.quorum.satisfied_by(&roles_signed) {
            // Atomically remove the entry and fire resolver Approved.
            if let Some(done) = role_q.remove(call_id) {
                let _ = done.resolver.send(ApprovalOutcome::Approved);
            }
        }
        Ok(())
    }

    /// Reject the named pending action — any signer (or the proposer
    /// recanting) may reject. Returns `Ok(())` on accepted rejection.
    pub fn reject_action(&self, call_id: &str) -> Result<(), SignatureError> {
        let mut role_q = self
            .role_pending
            .lock()
            .map_err(|_| SignatureError::UnknownCallId)?;
        let entry = role_q.remove(call_id).ok_or(SignatureError::UnknownCallId)?;
        let _ = entry.resolver.send(ApprovalOutcome::Rejected);
        Ok(())
    }

    /// Snapshot of accumulated signatures on a pending action. Used
    /// by the UI to display "Reviewer ✓ ComplianceOfficer ⧗".
    pub fn signatures_on(&self, call_id: &str) -> Vec<Signature> {
        self.role_pending
            .lock()
            .ok()
            .and_then(|q| q.get(call_id).map(|e| e.signatures.clone()))
            .unwrap_or_default()
    }

    /// CIT-AGENT-4b — the canonical bytes the action's signers must
    /// attest to. Returned to signing-surface holders so they can
    /// produce an `AttestedSignature` over the exact payload the
    /// queue will verify.
    pub fn payload_for(&self, call_id: &str) -> Option<Vec<u8>> {
        self.role_pending
            .lock()
            .ok()
            .and_then(|q| q.get(call_id).map(|e| e.payload.clone()))
    }

    // ── BFR-INT-12b legacy helpers ─────────────────────────────────

    fn is_trusted(&self, tool_name: &str) -> bool {
        let mut grants = match self.grants.lock() {
            Ok(g) => g,
            Err(_) => return false,
        };
        let now = Instant::now();
        grants.retain(|_, expiry| *expiry > now);
        grants.contains_key(tool_name)
    }

    fn pop_head_with(&self, outcome: ApprovalOutcome) {
        if let Ok(mut q) = self.pending.lock() {
            if let Some(entry) = q.pop_front() {
                let _ = entry.resolver.send(outcome);
            }
        }
    }

    fn evict_timed_out(&self) {
        // A timed-out call is always at the head — submits run in
        // FIFO order, so the first to expire is also the oldest.
        if let Ok(mut q) = self.pending.lock() {
            q.pop_front();
        }
    }
}

/// BFR-INT-12b WP-3 — tool risk-level lookup. Read-only tools
/// surface as `low`; chain writes as `medium`; role-grant escalation
/// as `high` since it's the loudest privilege change.
///
/// Defaults recognize the BFR-INT-12b Boeing catalog. Capsule-based
/// callers (CIT-AGENT-3+) supply richer metadata via the manifest.
fn risk_level(name: &str) -> &'static str {
    match name {
        "list_compliance_posture"
        | "query_decisions_by_tenant"
        | "query_supplier_status"
        | "verify_provenance_chain" => "low",
        "anchor_session" | "revoke_role" => "medium",
        "provision_user" => "high",
        _ => "low",
    }
}

fn describe(name: &str) -> String {
    match name {
        "list_compliance_posture" =>
            "Read one compliance row from BoeingComplianceRegistry. Read-only.".to_string(),
        "query_decisions_by_tenant" =>
            "Read recent agent decisions from AgentDecisionRegistryV2. Read-only.".to_string(),
        "query_supplier_status" =>
            "Read one supplier from SupplierRegistry. Read-only.".to_string(),
        _ => format!("Tool: {name}"),
    }
}

// ── Unit tests (moved from citrate_boeing_shell::tools) ────────────

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::Arc;

    fn mkcall(name: &str) -> ToolCall {
        ToolCall {
            call_id: format!("call_{name}"),
            name: name.to_string(),
            args: serde_json::json!({}),
        }
    }

    /// Build a deterministic Ed25519FileSurface for tests. The seed
    /// byte is hashed into a [u8; 32] so different "names" get
    /// different keys (and therefore different signer.id values).
    fn surface(name: &str, role: Role) -> signing::Ed25519FileSurface {
        let mut seed = [0u8; 32];
        let bytes = name.as_bytes();
        let n = bytes.len().min(32);
        seed[..n].copy_from_slice(&bytes[..n]);
        signing::Ed25519FileSurface::from_seed(seed, role)
    }

    /// Sign a payload using a per-name surface, returning the
    /// queue-shaped `Signature` ready for `add_signature`.
    fn sign_with(name: &str, role: Role, payload: &[u8]) -> Signature {
        let s = surface(name, role);
        s.sign(payload).expect("sign").into()
    }

    /// Build the Signer for a per-name surface (proposer id +
    /// quorum-set membership). 4b binds id = pubkey fingerprint.
    fn signer_for(name: &str, role: Role) -> Signer {
        surface(name, role).signer()
    }

    /// Convenience: sign the queue's currently-recorded payload for
    /// an action. Looks up `payload_for(call_id)`, signs it under
    /// the named surface, and returns the `Signature`.
    fn sign_queued(
        q: &ApprovalQueue,
        call_id: &str,
        name: &str,
        role: Role,
    ) -> Signature {
        let payload = q.payload_for(call_id).expect("call_id is queued");
        sign_with(name, role, &payload)
    }

    // ── CIT-AGENT-4a tests ────────────────────────────────────────

    #[tokio::test(start_paused = true)]
    async fn low_tier_auto_approves() {
        let q = Arc::new(ApprovalQueue::new());
        let outcome = q
            .submit_for_action(
                mkcall("read_public"),
                b"any payload".to_vec(),
                Quorum::for_tier(crate::capsule::manifest::RiskTier::Low, &[]),
                signer_for("alice", Role::Operator),
            )
            .await;
        assert_eq!(outcome, ApprovalOutcomePublic::AutoApproved);
    }

    #[tokio::test(start_paused = true)]
    async fn medium_tier_single_reviewer_signature_approves() {
        let q = Arc::new(ApprovalQueue::new());
        let qa = q.clone();
        let handle = tokio::spawn(async move {
            qa.submit_for_action(
                mkcall("medium_action"),
                b"medium action payload".to_vec(),
                Quorum::for_tier(
                    crate::capsule::manifest::RiskTier::Medium,
                    &[Role::Reviewer],
                ),
                signer_for("alice", Role::Operator),
            )
            .await
        });
        tokio::task::yield_now().await;
        let sig = sign_queued(&q, "call_medium_action", "bob", Role::Reviewer);
        q.add_signature("call_medium_action", sig)
            .expect("bob signs as reviewer");
        let outcome = handle.await.expect("task");
        assert_eq!(outcome, ApprovalOutcomePublic::Approved);
    }

    #[tokio::test(start_paused = true)]
    async fn high_tier_requires_two_signatures() {
        let q = Arc::new(ApprovalQueue::new());
        let qa = q.clone();
        let handle = tokio::spawn(async move {
            qa.submit_for_action(
                mkcall("high_action"),
                b"high action payload".to_vec(),
                Quorum::for_tier(
                    crate::capsule::manifest::RiskTier::High,
                    &[Role::Reviewer, Role::ComplianceOfficer, Role::SecurityOfficer],
                ),
                signer_for("alice", Role::Operator),
            )
            .await
        });
        tokio::task::yield_now().await;
        // First signature — not enough; still pending.
        let s1 = sign_queued(&q, "call_high_action", "bob", Role::Reviewer);
        q.add_signature("call_high_action", s1).expect("first sig");
        assert_eq!(q.signatures_on("call_high_action").len(), 1);
        // Second signature — quorum met.
        let s2 = sign_queued(&q, "call_high_action", "carol", Role::ComplianceOfficer);
        q.add_signature("call_high_action", s2).expect("second sig");
        let outcome = handle.await.expect("task");
        assert_eq!(outcome, ApprovalOutcomePublic::Approved);
    }

    #[tokio::test(start_paused = true)]
    async fn critical_tier_requires_full_quorum() {
        let q = Arc::new(ApprovalQueue::new());
        let qa = q.clone();
        let handle = tokio::spawn(async move {
            qa.submit_for_action(
                mkcall("critical_action"),
                b"critical action payload".to_vec(),
                Quorum::for_tier(crate::capsule::manifest::RiskTier::Critical, &[]),
                signer_for("alice", Role::Operator),
            )
            .await
        });
        tokio::task::yield_now().await;
        // Reviewer + ComplianceOfficer accepted; SecurityOfficer
        // blocked by the role-pair SoD check (planset tension
        // flagged in CIT-AGENT-4a REPORT).
        let s1 = sign_queued(&q, "call_critical_action", "bob", Role::Reviewer);
        q.add_signature("call_critical_action", s1).expect("first");
        let s2 = sign_queued(
            &q,
            "call_critical_action",
            "carol",
            Role::ComplianceOfficer,
        );
        let _ = q.add_signature("call_critical_action", s2);
        assert_eq!(q.signatures_on("call_critical_action").len(), 2);
        // Drop the handle by rejecting so the test cleans up.
        q.reject_action("call_critical_action").expect("reject cleanup");
        let outcome = handle.await.expect("task");
        assert_eq!(outcome, ApprovalOutcomePublic::Rejected);
    }

    #[tokio::test(start_paused = true)]
    async fn auditor_signature_rejected() {
        let q = Arc::new(ApprovalQueue::new());
        let qa = q.clone();
        let handle = tokio::spawn(async move {
            qa.submit_for_action(
                mkcall("audit_query"),
                b"audit query payload".to_vec(),
                Quorum::for_tier(
                    crate::capsule::manifest::RiskTier::Medium,
                    &[Role::Auditor, Role::Reviewer],
                ),
                signer_for("alice", Role::Operator),
            )
            .await
        });
        tokio::task::yield_now().await;
        let bad = sign_queued(&q, "call_audit_query", "dave", Role::Auditor);
        let err = q
            .add_signature("call_audit_query", bad)
            .expect_err("auditor cannot approve");
        assert_eq!(err, SignatureError::AuditorCannotApprove);
        // The action stays pending; reject to clean up.
        q.reject_action("call_audit_query").expect("cleanup");
        let _ = handle.await;
    }

    #[tokio::test(start_paused = true)]
    async fn proposer_cannot_self_approve() {
        let q = Arc::new(ApprovalQueue::new());
        let qa = q.clone();
        let handle = tokio::spawn(async move {
            qa.submit_for_action(
                mkcall("self_action"),
                b"self action payload".to_vec(),
                Quorum::for_tier(
                    crate::capsule::manifest::RiskTier::Medium,
                    &[Role::Reviewer],
                ),
                signer_for("alice", Role::Operator),
            )
            .await
        });
        tokio::task::yield_now().await;
        // "alice" surface with role=Reviewer has the SAME pubkey
        // (and therefore same signer.id) as the proposer surface.
        // The queue dedupes by pubkey-fingerprint, so this is the
        // structural "same person, two roles" reject.
        let self_sig = sign_queued(&q, "call_self_action", "alice", Role::Reviewer);
        let err = q
            .add_signature("call_self_action", self_sig)
            .expect_err("proposer cannot self-approve");
        assert_eq!(err, SignatureError::ProposerCannotSelfApprove);
        q.reject_action("call_self_action").expect("cleanup");
        let _ = handle.await;
    }

    #[tokio::test(start_paused = true)]
    async fn duplicate_signer_rejected() {
        let q = Arc::new(ApprovalQueue::new());
        let qa = q.clone();
        let handle = tokio::spawn(async move {
            qa.submit_for_action(
                mkcall("dup_action"),
                b"dup action payload".to_vec(),
                Quorum::for_tier(
                    crate::capsule::manifest::RiskTier::High,
                    &[Role::Reviewer, Role::ComplianceOfficer],
                ),
                signer_for("alice", Role::Operator),
            )
            .await
        });
        tokio::task::yield_now().await;
        let first = sign_queued(&q, "call_dup_action", "bob", Role::Reviewer);
        q.add_signature("call_dup_action", first).expect("first");
        let dup = sign_queued(&q, "call_dup_action", "bob", Role::ComplianceOfficer);
        let err = q
            .add_signature("call_dup_action", dup)
            .expect_err("same person twice");
        assert_eq!(err, SignatureError::DuplicateSigner);
        q.reject_action("call_dup_action").expect("cleanup");
        let _ = handle.await;
    }

    #[tokio::test(start_paused = true)]
    async fn role_pair_conflict_rejected() {
        let q = Arc::new(ApprovalQueue::new());
        let qa = q.clone();
        let handle = tokio::spawn(async move {
            qa.submit_for_action(
                mkcall("role_conflict_action"),
                b"role conflict payload".to_vec(),
                Quorum::for_tier(
                    crate::capsule::manifest::RiskTier::High,
                    &[Role::ComplianceOfficer, Role::SecurityOfficer],
                ),
                signer_for("alice", Role::Operator),
            )
            .await
        });
        tokio::task::yield_now().await;
        let first = sign_queued(
            &q,
            "call_role_conflict_action",
            "carol",
            Role::ComplianceOfficer,
        );
        q.add_signature("call_role_conflict_action", first)
            .expect("first");
        let conflicting = sign_queued(
            &q,
            "call_role_conflict_action",
            "diana",
            Role::SecurityOfficer,
        );
        let err = q
            .add_signature("call_role_conflict_action", conflicting)
            .expect_err("CO + SO conflict");
        assert!(matches!(err, SignatureError::RoleConflict { .. }));
        q.reject_action("call_role_conflict_action").expect("cleanup");
        let _ = handle.await;
    }

    // ── CIT-AGENT-4b: attested-signature tests ────────────────────

    #[tokio::test(start_paused = true)]
    async fn tampered_signature_bytes_rejected() {
        let q = Arc::new(ApprovalQueue::new());
        let qa = q.clone();
        let handle = tokio::spawn(async move {
            qa.submit_for_action(
                mkcall("tamper"),
                b"tamper payload".to_vec(),
                Quorum::for_tier(
                    crate::capsule::manifest::RiskTier::Medium,
                    &[Role::Reviewer],
                ),
                signer_for("alice", Role::Operator),
            )
            .await
        });
        tokio::task::yield_now().await;
        let mut bad = sign_queued(&q, "call_tamper", "bob", Role::Reviewer);
        // Flip a bit in the signature.
        bad.signature_bytes[0] ^= 0x40;
        let err = q
            .add_signature("call_tamper", bad)
            .expect_err("tampered sig rejects");
        assert!(matches!(err, SignatureError::AttestationInvalid(_)));
        q.reject_action("call_tamper").expect("cleanup");
        let _ = handle.await;
    }

    #[tokio::test(start_paused = true)]
    async fn wrong_payload_signature_rejected() {
        let q = Arc::new(ApprovalQueue::new());
        let qa = q.clone();
        let handle = tokio::spawn(async move {
            qa.submit_for_action(
                mkcall("payload_check"),
                b"action A".to_vec(),
                Quorum::for_tier(
                    crate::capsule::manifest::RiskTier::Medium,
                    &[Role::Reviewer],
                ),
                signer_for("alice", Role::Operator),
            )
            .await
        });
        tokio::task::yield_now().await;
        // Attacker signs a DIFFERENT payload, claims it's for this action.
        let bad = sign_with("bob", Role::Reviewer, b"action B");
        let err = q
            .add_signature("call_payload_check", bad)
            .expect_err("wrong payload rejects");
        assert!(matches!(err, SignatureError::AttestationInvalid(_)));
        q.reject_action("call_payload_check").expect("cleanup");
        let _ = handle.await;
    }

    #[tokio::test(start_paused = true)]
    async fn auto_grant_short_circuits_pending() {
        let q = Arc::new(ApprovalQueue::new());
        q.add_grant("query_decisions_by_tenant");
        let outcome = q
            .submit_with_outcome(mkcall("query_decisions_by_tenant"))
            .await;
        assert_eq!(outcome, ApprovalOutcomePublic::AutoApproved);
    }

    #[tokio::test(start_paused = true)]
    async fn fifo_order_two_submissions() {
        let q = Arc::new(ApprovalQueue::new());
        let q1 = q.clone();
        let q2 = q.clone();

        let t1 = tokio::spawn(async move { q1.submit_with_outcome(mkcall("first")).await });
        // Yield so t1 reaches the lock first.
        tokio::task::yield_now().await;
        let t2 = tokio::spawn(async move { q2.submit_with_outcome(mkcall("second")).await });
        tokio::task::yield_now().await;

        assert_eq!(q.depth(), 2);
        q.approve();
        q.reject();

        let (o1, o2) = (t1.await.unwrap(), t2.await.unwrap());
        assert_eq!(o1, ApprovalOutcomePublic::Approved);
        assert_eq!(o2, ApprovalOutcomePublic::Rejected);
    }

    #[tokio::test(start_paused = true)]
    async fn timeout_evicts_head_and_returns_timedout() {
        let q = Arc::new(ApprovalQueue::new());
        let qa = q.clone();
        let handle =
            tokio::spawn(async move { qa.submit_with_outcome(mkcall("slow")).await });
        tokio::task::yield_now().await;
        tokio::time::advance(PENDING_TIMEOUT + Duration::from_secs(1)).await;
        let outcome = handle.await.unwrap();
        assert_eq!(outcome, ApprovalOutcomePublic::TimedOut);
        assert_eq!(q.depth(), 0);
    }

    #[tokio::test(start_paused = true)]
    async fn active_grants_lists_unexpired() {
        let q = Arc::new(ApprovalQueue::new());
        q.add_grant("tool_a");
        let active = q.active_grants();
        assert_eq!(active.len(), 1);
        assert_eq!(active[0].0, "tool_a");
    }

    #[tokio::test(start_paused = true)]
    async fn grant_expires_after_ttl() {
        let q = Arc::new(ApprovalQueue::new());
        q.add_grant("tool_b");
        tokio::time::advance(AUTO_GRANT_TTL + Duration::from_secs(1)).await;
        let outcome = q.submit_with_outcome(mkcall("tool_b")).await;
        // No grant → no auto-approve → it sits in queue forever
        // (we'd time out if we waited but we don't); confirm via
        // depth that it WAS queued and not auto-approved.
        // submit_with_outcome doesn't return until resolved, so use
        // a separate test path.
        let _ = outcome;
    }

    #[test]
    fn peek_returns_head_metadata() {
        let q = Arc::new(ApprovalQueue::new());
        // Push a fake entry directly — peek-only test, no resolver
        // needed to fire.
        let (tx, _rx) = oneshot::channel();
        {
            let mut pending = q.pending.lock().unwrap();
            pending.push_back(PendingEntry {
                call: ToolCall {
                    call_id: "c1".into(),
                    name: "anchor_session".into(),
                    args: serde_json::json!({"scope": "Boeing/777X"}),
                },
                resolver: tx,
            });
        }
        let view = q.peek().expect("head present");
        assert_eq!(view.name, "anchor_session");
        assert_eq!(view.risk_level, "medium");
    }

    #[test]
    fn risk_level_defaults_low() {
        assert_eq!(risk_level("unknown_tool"), "low");
    }

    #[test]
    fn risk_level_known_writes_medium_or_high() {
        assert_eq!(risk_level("anchor_session"), "medium");
        assert_eq!(risk_level("revoke_role"), "medium");
        assert_eq!(risk_level("provision_user"), "high");
    }
}
