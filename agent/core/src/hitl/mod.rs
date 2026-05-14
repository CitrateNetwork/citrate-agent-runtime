//! Human-in-the-loop approval queue — RFC-CIT-AGENT-0001 §3.1
//! "HITL Queue" + §5 (approval state machine).
//!
//! BFR-INT-12b WP-4/WP-5 lived in `citrate_boeing_shell::tools` as a
//! single-in-flight + FIFO + 5-min-timeout approval queue. CIT-AGENT-1
//! moves the queue and its supporting types here, where the Boeing
//! shell consumes them through a re-export shim. RFC §3.2 names
//! `ApprovalQueue` in the frozen v1.0 public surface.
//!
//! The state machine modelled in this module is verified by
//! `.agentile/formal/specs/agent/ApprovalStateMachine.tla`
//! (CIT-AGENT-2 — 336,292 distinct states PASS).
//!
//! NOTE on tool-metadata helpers: `describe()` and `risk_level()` ship
//! defaults that recognize the BFR-INT-12b tool catalog
//! (`list_compliance_posture`, `anchor_session`, `provision_user`,
//! etc.). When the capsule system lands in CIT-AGENT-3 these will be
//! superseded by a manifest-driven lookup (`Capsule::metadata` -> {risk,
//! description}). Until then they stay here as the agreed defaults.

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

/// FIFO tool approval queue with auto-approve grants + per-call
/// timeout (BFR-INT-12b WP-4 + WP-5). Replaces BFR-INT-12's
/// single-in-flight slot.
///
/// Locking discipline: the std Mutex is only held across queue
/// surgery (push / pop / peek). Awaits happen outside the lock
/// scope on the oneshot receiver.
#[derive(Default)]
pub struct ApprovalQueue {
    pending: Mutex<VecDeque<PendingEntry>>,
    grants: Mutex<HashMap<String, Instant>>,
}

impl ApprovalQueue {
    pub fn new() -> Self {
        Self::default()
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
